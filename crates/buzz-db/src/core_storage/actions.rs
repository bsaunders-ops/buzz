use buzz_core::{
    action_auth::{VerifiedActionDecision, VerifiedActionProposal, VerifiedActionReceipt},
    CommunityId,
};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use std::{collections::HashSet, time::Duration as StdDuration};
use uuid::Uuid;

use super::audit::append_audit_entry_tx;

use super::{
    action_member_hash, action_member_operation_hash, action_operation_hash,
    action_ordered_members_hash, bounded_lease, require_hash, require_pubkey,
    ActionDecisionRecordOutcome, ActionExecutionClaim, ActionExecutionItem, ActionMemberHashInput,
    ActionMemberOutcome, ActionProposalStatus, ActionReceiptPublication,
    ActionReceiptPublicationItem, ActionRemoteAttempt, AuditEntityType, AuditEnvelope,
    AuditEventType, AuditOutcome, ExternalConnector, ExternalOperation, NewActionMemberOutcome,
    NewExternalActionProposal,
};

async fn lock_current_private_pair(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    community_id: CommunityId,
    channel_id: Uuid,
    owner_pubkey: &[u8],
    broker_pubkey: &[u8],
) -> crate::Result<bool> {
    let channel_is_private = sqlx::query_scalar::<_, String>(
        "SELECT visibility::text FROM channels \
         WHERE community_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(community_id.as_uuid())
    .bind(channel_id)
    .fetch_optional(&mut **tx)
    .await?
    .is_some_and(|visibility| visibility == "private");
    if !channel_is_private {
        return Ok(false);
    }
    let pair_is_current = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM users \
         WHERE community_id=$1 AND pubkey=$2 AND agent_owner_pubkey=$3 FOR KEY SHARE",
    )
    .bind(community_id.as_uuid())
    .bind(broker_pubkey)
    .bind(owner_pubkey)
    .fetch_optional(&mut **tx)
    .await?
    .is_some();
    if !pair_is_current {
        return Ok(false);
    }
    let members = sqlx::query(
        "SELECT pubkey FROM channel_members \
         WHERE community_id=$1 AND channel_id=$2 AND removed_at IS NULL FOR KEY SHARE",
    )
    .bind(community_id.as_uuid())
    .bind(channel_id)
    .fetch_all(&mut **tx)
    .await?;
    if members.len() != 2 {
        return Ok(false);
    }
    let mut owner_present = false;
    let mut broker_present = false;
    for member in members {
        let pubkey: Vec<u8> = member.try_get("pubkey")?;
        owner_present |= pubkey == owner_pubkey;
        broker_present |= pubkey == broker_pubkey;
    }
    Ok(owner_present && broker_present)
}

/// Insert a proposed cross-provider action bundle and all members atomically.
///
/// Member indices and `member_count` are derived from the ordered input. Tenant,
/// owner, broker, current private-channel membership, connector-account ownership,
/// and approved-scope authority are revalidated before insertion.
pub async fn insert_action_proposal(
    pool: &PgPool,
    community_id: CommunityId,
    proposal: &NewExternalActionProposal,
    verified: &VerifiedActionProposal,
) -> crate::Result<()> {
    const MAX_MEMBERS: usize = 10;
    if proposal.items.is_empty() || proposal.items.len() > MAX_MEMBERS {
        return Err(crate::DbError::InvalidData(format!(
            "action bundle must contain between 1 and {MAX_MEMBERS} members"
        )));
    }
    require_pubkey("owner_pubkey", &proposal.owner_pubkey)?;
    require_pubkey("broker_pubkey", &proposal.broker_pubkey)?;
    require_hash("operation_hash", &proposal.operation_hash)?;
    require_hash("ordered_members_hash", &proposal.ordered_members_hash)?;
    if verified.proposal_id() != proposal.id
        || verified.nonce() != proposal.nonce
        || verified.operation_hash().as_slice() != proposal.operation_hash
        || verified.channel_id() != proposal.channel_id
        || verified.owner_pubkey().as_slice() != proposal.owner_pubkey
        || verified.broker_pubkey().as_slice() != proposal.broker_pubkey
        || verified.proposed_at() != proposal.proposed_at.timestamp()
        || verified.expires_at() != proposal.expires_at.timestamp()
    {
        return Err(crate::DbError::InvalidData(
            "signed proposal capability does not match the durable proposal".into(),
        ));
    }
    if proposal.canonical_proposal.is_empty() || proposal.canonical_proposal.len() > 65_535 {
        return Err(crate::DbError::InvalidData(
            "canonical_proposal must contain between 1 and 65535 bytes".into(),
        ));
    }
    if proposal.operation_hash.as_slice() != action_operation_hash(&proposal.canonical_proposal) {
        return Err(crate::DbError::InvalidData(
            "operation_hash does not match canonical_proposal".into(),
        ));
    }
    if proposal.nonce.get_version_num() != 4 {
        return Err(crate::DbError::InvalidData(
            "action proposal nonce must be UUIDv4".into(),
        ));
    }
    let proposal_lifetime = proposal
        .expires_at
        .signed_duration_since(proposal.proposed_at);
    if proposal_lifetime <= chrono::Duration::zero()
        || proposal_lifetime > chrono::Duration::minutes(15)
        || proposal.proposed_at > Utc::now()
        || proposal.expires_at <= Utc::now()
    {
        return Err(crate::DbError::InvalidData(
            "action proposal expiry must be in the future and within 15 minutes of proposed_at"
                .into(),
        ));
    }
    let mut member_hashes = Vec::with_capacity(proposal.items.len());
    let mut operation_ids = HashSet::with_capacity(proposal.items.len());
    for item in &proposal.items {
        if item.operation_id.get_version_num() != 4 || !operation_ids.insert(item.operation_id) {
            return Err(crate::DbError::InvalidData(
                "action member operation_id must be a unique UUIDv4 within the proposal".into(),
            ));
        }
        require_hash("target_hash", &item.target_hash)?;
        require_hash("canonical_operation_hash", &item.canonical_operation_hash)?;
        if let Some(before_hash) = &item.before_hash {
            require_hash("before_hash", before_hash)?;
        }
        require_hash("after_hash", &item.after_hash)?;
        require_hash("member_hash", &item.member_hash)?;
        if item.canonical_operation.is_empty() || item.canonical_operation.len() > 65_535 {
            return Err(crate::DbError::InvalidData(
                "canonical_operation must contain between 1 and 65535 bytes".into(),
            ));
        }
        if item.operation.connector() != item.connector {
            return Err(crate::DbError::InvalidData(
                "external action member operation does not match its connector".into(),
            ));
        }
        if item.idempotency_key.get_version_num() != 4 {
            return Err(crate::DbError::InvalidData(
                "action member idempotency_key must be UUIDv4".into(),
            ));
        }
        let expected_operation_hash = action_member_operation_hash(&item.canonical_operation);
        if item.canonical_operation_hash.as_slice() != expected_operation_hash {
            return Err(crate::DbError::InvalidData(
                "canonical_operation_hash does not match canonical_operation".into(),
            ));
        }
        if item.operation.is_create() {
            if item.before_hash.is_some() || item.expected_remote_version.is_some() {
                return Err(crate::DbError::InvalidData(
                    "create action members must not carry before state or a remote version".into(),
                ));
            }
        } else if item.before_hash.is_none()
            || item
                .expected_remote_version
                .as_ref()
                .is_none_or(|version| version.is_empty() || version.len() > 256)
        {
            return Err(crate::DbError::InvalidData(
                "non-create action members require before_hash and a 1-256 byte remote version"
                    .into(),
            ));
        }
        let expected_member_hash = action_member_hash(ActionMemberHashInput {
            account_id: item.account_id,
            scope_id: item.scope_id,
            operation_id: item.operation_id,
            owner_pubkey: &proposal.owner_pubkey,
            connector: item.connector,
            operation: item.operation,
            target_hash: &item.target_hash,
            before_hash: item.before_hash.as_deref(),
            after_hash: &item.after_hash,
            expected_remote_version: item.expected_remote_version.as_deref(),
            idempotency_key: item.idempotency_key,
            canonical_operation_hash: &item.canonical_operation_hash,
        });
        if item.member_hash.as_slice() != expected_member_hash {
            return Err(crate::DbError::InvalidData(
                "member_hash does not match immutable action member fields".into(),
            ));
        }
        member_hashes.push(expected_member_hash);
    }
    let expected_ordered_members_hash = action_ordered_members_hash(&member_hashes);
    if proposal.ordered_members_hash.as_slice() != expected_ordered_members_hash {
        return Err(crate::DbError::InvalidData(
            "ordered_members_hash does not match ordered member hashes".into(),
        ));
    }

    let member_count = i16::try_from(proposal.items.len()).map_err(|_| {
        crate::DbError::InvalidData("action bundle member count is out of range".into())
    })?;
    let mut tx = pool.begin().await?;
    if !lock_current_private_pair(
        &mut tx,
        community_id,
        proposal.channel_id,
        &proposal.owner_pubkey,
        &proposal.broker_pubkey,
    )
    .await?
    {
        return Err(crate::DbError::InvalidData(
            "action proposal requires the exact current private owner/broker pair".into(),
        ));
    }
    sqlx::query(
        "INSERT INTO external_action_proposals \
         (community_id, id, owner_pubkey, broker_pubkey, channel_id, channel_visibility, \
          canonical_proposal, operation_hash, ordered_members_hash, member_count, nonce, proposed_at, expires_at, \
          proposal_event_hash, proposal_event_created_at) \
         VALUES ($1, $2, $3, $4, $5, 'private', $6, $7, $8, $9, $10, $11, $12, $13, $11)",
    )
    .bind(community_id.as_uuid())
    .bind(proposal.id)
    .bind(&proposal.owner_pubkey)
    .bind(&proposal.broker_pubkey)
    .bind(proposal.channel_id)
    .bind(&proposal.canonical_proposal)
    .bind(&proposal.operation_hash)
    .bind(&proposal.ordered_members_hash)
    .bind(member_count)
    .bind(proposal.nonce)
    .bind(proposal.proposed_at)
    .bind(proposal.expires_at)
    .bind(verified.event_hash().as_slice())
    .execute(&mut *tx)
    .await?;

    for (index, item) in proposal.items.iter().enumerate() {
        let item_index = i16::try_from(index).map_err(|_| {
            crate::DbError::InvalidData("action bundle item index is out of range".into())
        })?;
        let authorized: bool = sqlx::query_scalar(
            "SELECT EXISTS ( \
                 SELECT 1 FROM connector_accounts ca \
                 JOIN approved_source_scopes scope \
                   ON scope.community_id=ca.community_id AND scope.account_id=ca.id \
                 WHERE ca.community_id=$1 AND ca.id=$2 AND ca.provider=$3 \
                   AND ca.owner_pubkey=$4 AND ca.status='active' \
                   AND scope.id=$5 AND scope.status='active' AND scope.can_write=true \
             )",
        )
        .bind(community_id.as_uuid())
        .bind(item.account_id)
        .bind(item.connector.as_str())
        .bind(&proposal.owner_pubkey)
        .bind(item.scope_id)
        .fetch_one(&mut *tx)
        .await?;
        if !authorized {
            return Err(crate::DbError::InvalidData(format!(
                "action bundle member {item_index} has no active writable connector scope"
            )));
        }
        sqlx::query(
            "INSERT INTO external_action_proposal_items \
             (community_id, proposal_id, item_index, operation_id, account_id, scope_id, owner_pubkey, \
              connector, operation, target_hash, canonical_operation, canonical_operation_hash, \
              before_hash, after_hash, expected_remote_version, idempotency_key, member_hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)",
        )
        .bind(community_id.as_uuid())
        .bind(proposal.id)
        .bind(item_index)
        .bind(item.operation_id)
        .bind(item.account_id)
        .bind(item.scope_id)
        .bind(&proposal.owner_pubkey)
        .bind(item.connector.as_str())
        .bind(item.operation.as_str())
        .bind(&item.target_hash)
        .bind(&item.canonical_operation)
        .bind(&item.canonical_operation_hash)
        .bind(&item.before_hash)
        .bind(&item.after_hash)
        .bind(&item.expected_remote_version)
        .bind(item.idempotency_key)
        .bind(&item.member_hash)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Apply one cryptographically verified Desktop decision with a tenant-scoped CAS.
///
/// The row lock, current owner/broker pairing, private-channel membership, exact
/// proposal binding, member transition, and content-free audit append all occur
/// in one transaction. Callers must construct `decision` only from a verified
/// kind `44311` event; conversational approval never enters this API.
pub async fn record_action_decision(
    pool: &PgPool,
    community_id: CommunityId,
    decision: &VerifiedActionDecision,
) -> crate::Result<ActionDecisionRecordOutcome> {
    if decision.decision_id().get_version_num() != 4
        || decision.proposal_id().get_version_num() != 4
        || decision.nonce().get_version_num() != 4
    {
        return Err(crate::DbError::InvalidData(
            "external action decision identifiers must be UUIDv4".into(),
        ));
    }
    let verified_owner_pubkey = decision.owner_pubkey();
    let verified_broker_pubkey = decision.broker_pubkey();
    let verified_operation_hash = decision.operation_hash();
    let decision_event_hash = decision.event_hash();
    let decided_at = DateTime::<Utc>::from_timestamp(decision.decided_at(), 0)
        .ok_or_else(|| crate::DbError::InvalidData("decision timestamp is out of range".into()))?;

    let mut tx = pool.begin().await?;
    let row = sqlx::query(
        "SELECT owner_pubkey, broker_pubkey, channel_id, nonce, operation_hash, proposal_event_hash, \
                member_count, proposed_at, expires_at, status \
         FROM external_action_proposals \
         WHERE community_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(community_id.as_uuid())
    .bind(decision.proposal_id())
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        tx.commit().await?;
        return Ok(ActionDecisionRecordOutcome::Rejected);
    };

    let owner_pubkey: Vec<u8> = row.try_get("owner_pubkey")?;
    let broker_pubkey: Vec<u8> = row.try_get("broker_pubkey")?;
    let channel_id: Uuid = row.try_get("channel_id")?;
    let nonce: Uuid = row.try_get("nonce")?;
    let operation_hash: Vec<u8> = row.try_get("operation_hash")?;
    let proposal_event_hash: Option<Vec<u8>> = row.try_get("proposal_event_hash")?;
    let proposed_at: DateTime<Utc> = row.try_get("proposed_at")?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at")?;
    let status: String = row.try_get("status")?;

    if status != ActionProposalStatus::Proposed.as_str()
        || owner_pubkey.as_slice() != decision.owner_pubkey()
        || broker_pubkey.as_slice() != decision.broker_pubkey()
        || channel_id != decision.channel_id()
        || nonce != decision.nonce()
        || operation_hash.as_slice() != decision.operation_hash()
        || proposal_event_hash
            .as_ref()
            .is_none_or(|hash| hash.len() != 32)
    {
        tx.commit().await?;
        return Ok(ActionDecisionRecordOutcome::Rejected);
    }

    let database_now: DateTime<Utc> = sqlx::query_scalar("SELECT NOW()")
        .fetch_one(&mut *tx)
        .await?;
    if decided_at < proposed_at
        || decided_at >= expires_at
        || expires_at <= database_now
        || decided_at > database_now + chrono::Duration::minutes(5)
    {
        sqlx::query(
            "UPDATE external_action_proposals SET status='expired', updated_at=$3 \
             WHERE community_id=$1 AND id=$2 AND status='proposed'",
        )
        .bind(community_id.as_uuid())
        .bind(decision.proposal_id())
        .bind(database_now)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(ActionDecisionRecordOutcome::Expired);
    }

    let pair_is_current = lock_current_private_pair(
        &mut tx,
        community_id,
        decision.channel_id(),
        verified_owner_pubkey.as_slice(),
        verified_broker_pubkey.as_slice(),
    )
    .await?;
    let decision_is_fresh = !sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS ( \
             SELECT 1 FROM external_action_proposals \
             WHERE community_id=$1 \
               AND (decision_id=$2 OR decision_event_hash=$3) \
         )",
    )
    .bind(community_id.as_uuid())
    .bind(decision.decision_id())
    .bind(decision_event_hash.as_slice())
    .fetch_one(&mut *tx)
    .await?;

    if !pair_is_current || !decision_is_fresh {
        tx.commit().await?;
        return Ok(ActionDecisionRecordOutcome::Rejected);
    }

    let status = if decision.approved() {
        ActionProposalStatus::Approved
    } else {
        ActionProposalStatus::Denied
    };
    let updated = sqlx::query(
        "UPDATE external_action_proposals \
         SET status=$3, decision_id=$4, signer_pubkey=$5, decision_broker_pubkey=$6, \
             decision_event_hash=$7, decided_at=$8, updated_at=$8 \
         WHERE community_id=$1 AND id=$2 AND status='proposed' \
           AND owner_pubkey=$5 AND broker_pubkey=$6 AND channel_id=$9 \
           AND nonce=$10 AND operation_hash=$11 AND expires_at > $8",
    )
    .bind(community_id.as_uuid())
    .bind(decision.proposal_id())
    .bind(status.as_str())
    .bind(decision.decision_id())
    .bind(verified_owner_pubkey.as_slice())
    .bind(verified_broker_pubkey.as_slice())
    .bind(decision_event_hash.as_slice())
    .bind(decided_at)
    .bind(decision.channel_id())
    .bind(decision.nonce())
    .bind(verified_operation_hash.as_slice())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if updated != 1 {
        tx.rollback().await?;
        return Ok(ActionDecisionRecordOutcome::Rejected);
    }
    let member_updates = sqlx::query(
        "UPDATE external_action_proposal_items SET status=$3 \
         WHERE community_id=$1 AND proposal_id=$2 AND status='proposed'",
    )
    .bind(community_id.as_uuid())
    .bind(decision.proposal_id())
    .bind(status.as_str())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    let member_count: i16 = row.try_get("member_count")?;
    let expected_member_updates = u64::try_from(member_count).map_err(|_| {
        crate::DbError::InvalidData("external action member count is out of range".into())
    })?;
    if member_updates != expected_member_updates {
        tx.rollback().await?;
        return Err(crate::DbError::InvalidData(
            "external action decision did not transition every bound member".into(),
        ));
    }
    append_audit_entry_tx(
        &mut tx,
        community_id,
        AuditEnvelope {
            event_type: AuditEventType::ActionProposalDecided,
            entity_type: AuditEntityType::ExternalActionProposal,
            entity_id: decision.proposal_id(),
            object_hash: verified_operation_hash.as_slice(),
            version: None,
            occurred_at: decided_at,
            outcome: AuditOutcome::Accepted,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(if decision.approved() {
        ActionDecisionRecordOutcome::Approved
    } else {
        ActionDecisionRecordOutcome::Denied
    })
}

/// Atomically claim an approved, unexpired external action exactly once.
///
/// The returned values are read from the proposal and its ordered normalized
/// members in the same transaction that changes them to `executing`, so the
/// executor cannot substitute, omit, duplicate, or reorder a member after
/// approval.
pub async fn claim_action_execution(
    pool: &PgPool,
    community_id: CommunityId,
    proposal_id: Uuid,
    worker_id: Uuid,
    now: DateTime<Utc>,
) -> crate::Result<Option<ActionExecutionClaim>> {
    let claim_id = Uuid::new_v4();
    let mut tx = pool.begin().await?;

    sqlx::query(
        "UPDATE external_action_proposals \
         SET status='expired', updated_at=$3 \
         WHERE community_id=$1 AND id=$2 AND status='approved' AND expires_at <= $3",
    )
    .bind(community_id.as_uuid())
    .bind(proposal_id)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    let row = sqlx::query(
        "UPDATE external_action_proposals \
         SET status='executing', execution_claim_id=$3, execution_claimed_by=$4, \
             execution_claimed_at=$5, updated_at=$5 \
         WHERE community_id=$1 AND id=$2 AND status=$6 AND expires_at > $5 \
           AND proposal_event_hash IS NOT NULL \
           AND execution_claim_id IS NULL \
         RETURNING owner_pubkey, broker_pubkey, channel_id, canonical_proposal, operation_hash, \
                   ordered_members_hash, member_count, nonce, \
                   proposed_at, expires_at, signer_pubkey, decision_broker_pubkey, \
                   decision_id, decision_event_hash",
    )
    .bind(community_id.as_uuid())
    .bind(proposal_id)
    .bind(claim_id)
    .bind(worker_id)
    .bind(now)
    .bind(ActionProposalStatus::Approved.as_str())
    .fetch_optional(&mut *tx)
    .await?;

    let Some(row) = row else {
        tx.commit().await?;
        return Ok(None);
    };
    let signer_pubkey: Option<Vec<u8>> = row.try_get("signer_pubkey")?;
    let signer_pubkey = signer_pubkey.ok_or_else(|| {
        crate::DbError::InvalidData("approved action proposal has no signer_pubkey".into())
    })?;
    let decision_event_hash: Option<Vec<u8>> = row.try_get("decision_event_hash")?;
    let decision_event_hash = decision_event_hash.ok_or_else(|| {
        crate::DbError::InvalidData("approved action proposal has no decision_event_hash".into())
    })?;
    let broker_pubkey: Vec<u8> = row.try_get("broker_pubkey")?;
    let owner_pubkey: Vec<u8> = row.try_get("owner_pubkey")?;
    let channel_id: Uuid = row.try_get("channel_id")?;
    let decision_id: Option<Uuid> = row.try_get("decision_id")?;
    let decision_id = decision_id.ok_or_else(|| {
        crate::DbError::InvalidData("approved action proposal has no decision_id".into())
    })?;
    let decision_broker_pubkey: Option<Vec<u8>> = row.try_get("decision_broker_pubkey")?;
    if decision_broker_pubkey.as_deref() != Some(broker_pubkey.as_slice()) {
        return Err(crate::DbError::InvalidData(
            "approved action decision is addressed to a different broker".into(),
        ));
    }
    if !lock_current_private_pair(
        &mut tx,
        community_id,
        channel_id,
        &owner_pubkey,
        &broker_pubkey,
    )
    .await?
    {
        return Err(crate::DbError::InvalidData(
            "approved action no longer has the exact current private owner/broker authorization"
                .into(),
        ));
    }
    let member_count: i16 = row.try_get("member_count")?;
    let member_rows = sqlx::query(
        "SELECT item.item_index, item.operation_id, item.account_id, item.scope_id, item.connector, item.operation, \
                item.target_hash, item.status, ca.status AS account_status, \
                scope.status AS scope_status, scope.can_write, \
                canonical_operation, canonical_operation_hash, before_hash, after_hash, \
                expected_remote_version, idempotency_key, member_hash \
         FROM external_action_proposal_items item \
         JOIN connector_accounts ca \
           ON ca.community_id=item.community_id AND ca.id=item.account_id \
          AND ca.provider=item.connector AND ca.owner_pubkey=item.owner_pubkey \
         JOIN approved_source_scopes scope \
           ON scope.community_id=item.community_id AND scope.account_id=item.account_id \
          AND scope.id=item.scope_id \
         WHERE item.community_id=$1 AND item.proposal_id=$2 \
         ORDER BY item.item_index",
    )
    .bind(community_id.as_uuid())
    .bind(proposal_id)
    .fetch_all(&mut *tx)
    .await?;
    let expected_count = usize::try_from(member_count).map_err(|_| {
        crate::DbError::InvalidData("action proposal has an invalid member_count".into())
    })?;
    if member_rows.len() != expected_count {
        return Err(crate::DbError::InvalidData(format!(
            "action proposal member_count is {member_count}, but {} members were stored",
            member_rows.len()
        )));
    }

    let mut items = Vec::with_capacity(expected_count);
    for (expected_index, member_row) in member_rows.into_iter().enumerate() {
        let item_index: i16 = member_row.try_get("item_index")?;
        if usize::try_from(item_index).ok() != Some(expected_index) {
            return Err(crate::DbError::InvalidData(
                "action proposal item indices are not contiguous from zero".into(),
            ));
        }
        let item_connector_text: String = member_row.try_get("connector")?;
        let item_connector = ExternalConnector::from_db(&item_connector_text)?;
        let item_account_id: Uuid = member_row.try_get("account_id")?;
        let item_status: String = member_row.try_get("status")?;
        if item_status != ActionProposalStatus::Approved.as_str() {
            return Err(crate::DbError::InvalidData(format!(
                "action proposal member {item_index} is not approved"
            )));
        }
        let account_status: String = member_row.try_get("account_status")?;
        let scope_status: String = member_row.try_get("scope_status")?;
        let can_write: bool = member_row.try_get("can_write")?;
        if account_status != "active" || scope_status != "active" || !can_write {
            return Err(crate::DbError::InvalidData(format!(
                "action proposal member {item_index} has no active writable connector scope"
            )));
        }
        let operation_text: String = member_row.try_get("operation")?;
        let operation = ExternalOperation::from_wire(&operation_text)
            .ok_or_else(|| crate::DbError::InvalidData("unknown external operation".into()))?;
        if operation.connector() != item_connector || item_connector.as_str() != item_connector_text
        {
            return Err(crate::DbError::InvalidData(
                "external action member does not match proposal connector".into(),
            ));
        }
        items.push(ActionExecutionItem {
            item_index,
            operation_id: member_row.try_get("operation_id")?,
            account_id: item_account_id,
            scope_id: member_row.try_get("scope_id")?,
            connector: item_connector,
            operation,
            target_hash: member_row.try_get("target_hash")?,
            canonical_operation: member_row.try_get("canonical_operation")?,
            canonical_operation_hash: member_row.try_get("canonical_operation_hash")?,
            before_hash: member_row.try_get("before_hash")?,
            after_hash: member_row.try_get("after_hash")?,
            expected_remote_version: member_row.try_get("expected_remote_version")?,
            idempotency_key: member_row.try_get("idempotency_key")?,
            member_hash: member_row.try_get("member_hash")?,
        });
    }
    sqlx::query(
        "UPDATE external_action_proposal_items SET status='executing' \
         WHERE community_id=$1 AND proposal_id=$2 AND status='approved'",
    )
    .bind(community_id.as_uuid())
    .bind(proposal_id)
    .execute(&mut *tx)
    .await?;
    let claim = ActionExecutionClaim {
        community_id,
        proposal_id,
        claim_id,
        decision_id,
        owner_pubkey,
        broker_pubkey,
        channel_id,
        canonical_proposal: row.try_get("canonical_proposal")?,
        operation_hash: row.try_get("operation_hash")?,
        ordered_members_hash: row.try_get("ordered_members_hash")?,
        member_count,
        items,
        nonce: row.try_get("nonce")?,
        proposed_at: row.try_get("proposed_at")?,
        expires_at: row.try_get("expires_at")?,
        signer_pubkey,
        decision_event_hash,
    };
    append_audit_entry_tx(
        &mut tx,
        community_id,
        AuditEnvelope {
            event_type: AuditEventType::ActionExecution,
            entity_type: AuditEntityType::ExternalActionProposal,
            entity_id: proposal_id,
            object_hash: &claim.operation_hash,
            version: None,
            occurred_at: now,
            outcome: AuditOutcome::Accepted,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(Some(claim))
}

/// Persist one member's actual remote-dispatch intent immediately before I/O.
///
/// A claim alone records bundle execution intent, but is deliberately not a
/// remote attempt. This function creates the sole attempt only after the
/// executor's fresh remote-version check has passed. A repeated call for the
/// same member returns `None` and can never authorize a blind retry.
pub async fn begin_action_remote_attempt(
    pool: &PgPool,
    community_id: CommunityId,
    proposal_id: Uuid,
    claim_id: Uuid,
    item_index: i16,
    now: DateTime<Utc>,
) -> crate::Result<Option<ActionRemoteAttempt>> {
    if proposal_id.get_version_num() != 4 || claim_id.get_version_num() != 4 {
        return Err(crate::DbError::InvalidData(
            "external action attempt identifiers must be UUIDv4".into(),
        ));
    }
    if !(0..=9).contains(&item_index) {
        return Err(crate::DbError::InvalidData(
            "external action item index is out of range".into(),
        ));
    }

    let mut tx = pool.begin().await?;
    let proposal = sqlx::query(
        "SELECT owner_pubkey, broker_pubkey, channel_id \
         FROM external_action_proposals \
         WHERE community_id=$1 AND id=$2 AND execution_claim_id=$3 \
           AND status='executing' AND expires_at > $4 FOR UPDATE",
    )
    .bind(community_id.as_uuid())
    .bind(proposal_id)
    .bind(claim_id)
    .bind(now)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(proposal) = proposal else {
        tx.commit().await?;
        return Ok(None);
    };
    let owner_pubkey: Vec<u8> = proposal.try_get("owner_pubkey")?;
    let broker_pubkey: Vec<u8> = proposal.try_get("broker_pubkey")?;
    let channel_id: Uuid = proposal.try_get("channel_id")?;
    if !lock_current_private_pair(
        &mut tx,
        community_id,
        channel_id,
        &owner_pubkey,
        &broker_pubkey,
    )
    .await?
    {
        tx.commit().await?;
        return Ok(None);
    }

    let member = sqlx::query(
        "SELECT item.operation, item.connector, ca.status AS account_status, \
                scope.status AS scope_status, scope.can_write \
         FROM external_action_proposal_items item \
         JOIN connector_accounts ca \
           ON ca.community_id=item.community_id AND ca.id=item.account_id \
          AND ca.provider=item.connector AND ca.owner_pubkey=item.owner_pubkey \
         JOIN approved_source_scopes scope \
           ON scope.community_id=item.community_id AND scope.account_id=item.account_id \
          AND scope.id=item.scope_id \
         WHERE item.community_id=$1 AND item.proposal_id=$2 AND item.item_index=$3 \
           AND item.status='executing' FOR UPDATE OF item, ca, scope",
    )
    .bind(community_id.as_uuid())
    .bind(proposal_id)
    .bind(item_index)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(member) = member else {
        tx.commit().await?;
        return Ok(None);
    };
    let connector_text: String = member.try_get("connector")?;
    let operation_text: String = member.try_get("operation")?;
    let connector = ExternalConnector::from_db(&connector_text)?;
    let operation = ExternalOperation::from_wire(&operation_text)
        .ok_or_else(|| crate::DbError::InvalidData("unknown external operation".into()))?;
    let account_status: String = member.try_get("account_status")?;
    let scope_status: String = member.try_get("scope_status")?;
    let can_write: bool = member.try_get("can_write")?;
    if operation.connector() != connector
        || account_status != "active"
        || scope_status != "active"
        || !can_write
    {
        tx.commit().await?;
        return Ok(None);
    }

    let attempt_id = Uuid::new_v4();
    let inserted = sqlx::query(
        "INSERT INTO external_action_attempts \
         (community_id, id, proposal_id, item_index, claim_id, attempt_number, started_at) \
         SELECT $1, $2, $3, $4, $5, 1, $6 \
         WHERE NOT EXISTS ( \
             SELECT 1 FROM external_action_attempts \
             WHERE community_id=$1 AND proposal_id=$3 AND item_index=$4 \
         ) \
         ON CONFLICT DO NOTHING",
    )
    .bind(community_id.as_uuid())
    .bind(attempt_id)
    .bind(proposal_id)
    .bind(item_index)
    .bind(claim_id)
    .bind(now)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    Ok((inserted == 1).then_some(ActionRemoteAttempt {
        attempt_id,
        item_index,
    }))
}

/// Record one pre-dispatch or provider outcome and queue a complete receipt.
///
/// The attempt outcome, immutable member receipt, aggregate proposal state,
/// content-free audit entry, and crash-safe publication marker commit together.
/// Replays return `false` and never reopen a member or create another outbox row.
pub async fn record_action_member_outcome(
    pool: &PgPool,
    community_id: CommunityId,
    outcome: &NewActionMemberOutcome,
) -> crate::Result<bool> {
    if outcome.proposal_id.get_version_num() != 4
        || outcome.claim_id.get_version_num() != 4
        || outcome.operation_id.get_version_num() != 4
        || outcome
            .attempt_id
            .is_some_and(|attempt_id| attempt_id.get_version_num() != 4)
        || !(0..=9).contains(&outcome.item_index)
    {
        return Err(crate::DbError::InvalidData(
            "external action outcome identifiers are invalid".into(),
        ));
    }
    require_hash("member_hash", &outcome.member_hash)?;
    if let Some(hash) = &outcome.remote_resource_id_hash {
        require_hash("remote_resource_id_hash", hash)?;
    }
    let valid = match outcome.outcome {
        ActionMemberOutcome::Succeeded => {
            outcome.attempt_id.is_some()
                && outcome
                    .remote_result_id
                    .as_ref()
                    .is_some_and(|value| !value.is_empty() && value.len() <= 256)
                && outcome
                    .remote_version
                    .as_ref()
                    .is_some_and(|value| !value.is_empty() && value.len() <= 256)
        }
        ActionMemberOutcome::Failed => {
            outcome.remote_result_id.is_none()
                && outcome.remote_version.is_none()
                && outcome.remote_resource_id_hash.is_none()
        }
        ActionMemberOutcome::ReconciliationRequired => {
            outcome.attempt_id.is_some()
                && outcome.remote_result_id.is_none()
                && outcome.remote_version.is_none()
                && outcome.remote_resource_id_hash.is_none()
        }
    };
    if !valid {
        return Err(crate::DbError::InvalidData(
            "external action outcome fields are inconsistent".into(),
        ));
    }

    let mut tx = pool.begin().await?;
    let proposal = sqlx::query(
        "SELECT member_count, operation_hash \
         FROM external_action_proposals \
         WHERE community_id=$1 AND id=$2 AND execution_claim_id=$3 \
           AND status='executing' FOR UPDATE",
    )
    .bind(community_id.as_uuid())
    .bind(outcome.proposal_id)
    .bind(outcome.claim_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(proposal) = proposal else {
        tx.commit().await?;
        return Ok(false);
    };
    let member = sqlx::query(
        "SELECT operation_id, member_hash FROM external_action_proposal_items \
         WHERE community_id=$1 AND proposal_id=$2 AND item_index=$3 \
           AND status='executing' FOR UPDATE",
    )
    .bind(community_id.as_uuid())
    .bind(outcome.proposal_id)
    .bind(outcome.item_index)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(member) = member else {
        tx.commit().await?;
        return Ok(false);
    };
    if member.try_get::<Uuid, _>("operation_id")? != outcome.operation_id
        || member.try_get::<Vec<u8>, _>("member_hash")? != outcome.member_hash
    {
        tx.commit().await?;
        return Ok(false);
    }

    if let Some(attempt_id) = outcome.attempt_id {
        let attempt_outcome = match outcome.outcome {
            ActionMemberOutcome::Succeeded => "succeeded",
            ActionMemberOutcome::Failed => "failed",
            ActionMemberOutcome::ReconciliationRequired => "remote_unknown",
        };
        let attempt_updated = sqlx::query(
            "UPDATE external_action_attempts \
             SET outcome=$6, finished_at=$7, remote_outcome_hash=$8 \
             WHERE community_id=$1 AND proposal_id=$2 AND item_index=$3 \
               AND claim_id=$4 AND id=$5 AND outcome='in_progress'",
        )
        .bind(community_id.as_uuid())
        .bind(outcome.proposal_id)
        .bind(outcome.item_index)
        .bind(outcome.claim_id)
        .bind(attempt_id)
        .bind(attempt_outcome)
        .bind(outcome.occurred_at)
        .bind(&outcome.remote_resource_id_hash)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if attempt_updated != 1 {
            tx.commit().await?;
            return Ok(false);
        }
    } else {
        let existing_attempt: bool = sqlx::query_scalar(
            "SELECT EXISTS ( \
                 SELECT 1 FROM external_action_attempts \
                 WHERE community_id=$1 AND proposal_id=$2 AND item_index=$3 \
             )",
        )
        .bind(community_id.as_uuid())
        .bind(outcome.proposal_id)
        .bind(outcome.item_index)
        .fetch_one(&mut *tx)
        .await?;
        if existing_attempt {
            tx.commit().await?;
            return Ok(false);
        }
    }

    let reconciliation_state = match outcome.outcome {
        ActionMemberOutcome::ReconciliationRequired => "pending",
        ActionMemberOutcome::Succeeded | ActionMemberOutcome::Failed => "not_required",
    };
    sqlx::query(
        "INSERT INTO external_action_receipts \
         (community_id, proposal_id, item_index, operation_id, member_hash, attempt_id, \
          remote_result_id, remote_resource_id_hash, remote_version, outcome, reconciliation_state, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(community_id.as_uuid())
    .bind(outcome.proposal_id)
    .bind(outcome.item_index)
    .bind(outcome.operation_id)
    .bind(&outcome.member_hash)
    .bind(outcome.attempt_id)
    .bind(&outcome.remote_result_id)
    .bind(&outcome.remote_resource_id_hash)
    .bind(&outcome.remote_version)
    .bind(outcome.outcome.as_str())
    .bind(reconciliation_state)
    .bind(outcome.occurred_at)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE external_action_proposal_items SET status=$4 \
         WHERE community_id=$1 AND proposal_id=$2 AND item_index=$3 AND status='executing'",
    )
    .bind(community_id.as_uuid())
    .bind(outcome.proposal_id)
    .bind(outcome.item_index)
    .bind(outcome.outcome.as_str())
    .execute(&mut *tx)
    .await?;
    append_audit_entry_tx(
        &mut tx,
        community_id,
        AuditEnvelope {
            event_type: AuditEventType::ActionExecution,
            entity_type: AuditEntityType::ExternalActionProposal,
            entity_id: outcome.proposal_id,
            object_hash: &outcome.member_hash,
            version: None,
            occurred_at: outcome.occurred_at,
            outcome: match outcome.outcome {
                ActionMemberOutcome::Succeeded => AuditOutcome::Succeeded,
                ActionMemberOutcome::Failed => AuditOutcome::Failed,
                ActionMemberOutcome::ReconciliationRequired => AuditOutcome::ReconciliationRequired,
            },
        },
    )
    .await?;

    let member_count: i16 = proposal.try_get("member_count")?;
    let receipt_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM external_action_receipts \
         WHERE community_id=$1 AND proposal_id=$2",
    )
    .bind(community_id.as_uuid())
    .bind(outcome.proposal_id)
    .fetch_one(&mut *tx)
    .await?;
    if receipt_count == i64::from(member_count) {
        let outcomes = sqlx::query(
            "SELECT outcome FROM external_action_receipts \
             WHERE community_id=$1 AND proposal_id=$2 ORDER BY item_index",
        )
        .bind(community_id.as_uuid())
        .bind(outcome.proposal_id)
        .fetch_all(&mut *tx)
        .await?;
        let mut aggregate = ActionProposalStatus::Succeeded;
        for row in outcomes {
            match ActionMemberOutcome::from_db(&row.try_get::<String, _>("outcome")?)? {
                ActionMemberOutcome::ReconciliationRequired => {
                    aggregate = ActionProposalStatus::ReconciliationRequired;
                    break;
                }
                ActionMemberOutcome::Failed => aggregate = ActionProposalStatus::Failed,
                ActionMemberOutcome::Succeeded => {}
            }
        }
        sqlx::query(
            "UPDATE external_action_proposals SET status=$3, updated_at=$4 \
             WHERE community_id=$1 AND id=$2 AND status='executing'",
        )
        .bind(community_id.as_uuid())
        .bind(outcome.proposal_id)
        .bind(aggregate.as_str())
        .bind(outcome.occurred_at)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO external_action_receipt_outbox \
             (community_id, proposal_id, receipt_id, occurred_at) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(community_id.as_uuid())
        .bind(outcome.proposal_id)
        .bind(Uuid::new_v4())
        .bind(outcome.occurred_at)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(true)
}

/// Claim one crash-safe receipt publication lease and rebuild it from durable rows.
pub async fn claim_action_receipt_publication(
    pool: &PgPool,
    community_id: CommunityId,
    worker_id: Uuid,
    now: DateTime<Utc>,
    lease_for: StdDuration,
) -> crate::Result<Option<ActionReceiptPublication>> {
    if worker_id.get_version_num() != 4 {
        return Err(crate::DbError::InvalidData(
            "receipt publisher worker must be UUIDv4".into(),
        ));
    }
    let claim_until = now
        .checked_add_signed(bounded_lease(lease_for)?)
        .ok_or_else(|| crate::DbError::InvalidData("receipt lease is out of range".into()))?;
    let publish_claim_id = Uuid::new_v4();
    let mut tx = pool.begin().await?;
    sqlx::query(
        "UPDATE external_action_receipt_outbox \
         SET publish_state='retry', publish_claim_id=NULL, publish_claimed_by=NULL, \
             publish_claimed_at=NULL, publish_claim_until=NULL, retry_count=retry_count+1, \
             next_retry_at=$2 \
         WHERE community_id=$1 AND publish_state='claimed' AND publish_claim_until <= $2",
    )
    .bind(community_id.as_uuid())
    .bind(now)
    .execute(&mut *tx)
    .await?;
    let outbox = sqlx::query(
        "SELECT proposal_id, receipt_id, occurred_at \
         FROM external_action_receipt_outbox \
         WHERE community_id=$1 AND publish_state IN ('pending', 'retry') \
           AND next_retry_at <= $2 \
         ORDER BY created_at, proposal_id LIMIT 1 FOR UPDATE SKIP LOCKED",
    )
    .bind(community_id.as_uuid())
    .bind(now)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(outbox) = outbox else {
        tx.commit().await?;
        return Ok(None);
    };
    let proposal_id: Uuid = outbox.try_get("proposal_id")?;
    let receipt_id: Uuid = outbox.try_get("receipt_id")?;
    let occurred_at: DateTime<Utc> = outbox.try_get("occurred_at")?;
    sqlx::query(
        "UPDATE external_action_receipt_outbox \
         SET publish_state='claimed', publish_claim_id=$3, publish_claimed_by=$4, \
             publish_claimed_at=$5, publish_claim_until=$6 \
         WHERE community_id=$1 AND proposal_id=$2",
    )
    .bind(community_id.as_uuid())
    .bind(proposal_id)
    .bind(publish_claim_id)
    .bind(worker_id)
    .bind(now)
    .bind(claim_until)
    .execute(&mut *tx)
    .await?;
    let proposal = sqlx::query(
        "SELECT decision_id, channel_id, owner_pubkey, broker_pubkey, operation_hash, member_count \
         FROM external_action_proposals \
         WHERE community_id=$1 AND id=$2 \
           AND status IN ('succeeded', 'failed', 'reconciliation_required')",
    )
    .bind(community_id.as_uuid())
    .bind(proposal_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| crate::DbError::InvalidData("receipt proposal is not terminal".into()))?;
    let decision_id: Option<Uuid> = proposal.try_get("decision_id")?;
    let decision_id = decision_id.ok_or_else(|| {
        crate::DbError::InvalidData("receipt proposal has no bound decision".into())
    })?;
    let operation_hash: Vec<u8> = proposal.try_get("operation_hash")?;
    let channel_id: Uuid = proposal.try_get("channel_id")?;
    let owner_pubkey: Vec<u8> = proposal.try_get("owner_pubkey")?;
    let broker_pubkey: Vec<u8> = proposal.try_get("broker_pubkey")?;
    let member_count: i16 = proposal.try_get("member_count")?;
    let rows = sqlx::query(
        "SELECT item.operation_id, item.member_hash, item.idempotency_key, \
                receipt.remote_result_id, receipt.remote_version, receipt.outcome, \
                receipt.reconciliation_state \
         FROM external_action_proposal_items item \
         JOIN external_action_receipts receipt \
           ON receipt.community_id=item.community_id \
          AND receipt.proposal_id=item.proposal_id \
          AND receipt.item_index=item.item_index \
          AND receipt.operation_id=item.operation_id \
          AND receipt.member_hash=item.member_hash \
         WHERE item.community_id=$1 AND item.proposal_id=$2 \
         ORDER BY item.item_index",
    )
    .bind(community_id.as_uuid())
    .bind(proposal_id)
    .fetch_all(&mut *tx)
    .await?;
    if rows.len() != usize::try_from(member_count).unwrap_or_default() {
        return Err(crate::DbError::InvalidData(
            "receipt results do not match the approved member count".into(),
        ));
    }
    let mut results = Vec::with_capacity(rows.len());
    for row in rows {
        results.push(ActionReceiptPublicationItem {
            operation_id: row.try_get("operation_id")?,
            operation_hash: row.try_get("member_hash")?,
            idempotency_key: row.try_get("idempotency_key")?,
            outcome: ActionMemberOutcome::from_db(&row.try_get::<String, _>("outcome")?)?,
            external_result_id: row.try_get("remote_result_id")?,
            external_result_version: row.try_get("remote_version")?,
            reconciliation_status: row.try_get("reconciliation_state")?,
        });
    }
    tx.commit().await?;
    Ok(Some(ActionReceiptPublication {
        publish_claim_id,
        receipt_id,
        proposal_id,
        decision_id,
        channel_id,
        owner_pubkey,
        broker_pubkey,
        operation_hash,
        results,
        occurred_at,
    }))
}

/// Mark a claimed receipt published only after its signed event is durable.
pub async fn complete_action_receipt_publication(
    pool: &PgPool,
    community_id: CommunityId,
    publish_claim_id: Uuid,
    verified: &VerifiedActionReceipt,
    published_at: DateTime<Utc>,
) -> crate::Result<bool> {
    let occurred_at = DateTime::<Utc>::from_timestamp(verified.occurred_at(), 0)
        .ok_or_else(|| crate::DbError::InvalidData("receipt timestamp is out of range".into()))?;
    let updated = sqlx::query(
        "UPDATE external_action_receipt_outbox \
         SET publish_state='published', published_event_hash=$4, published_at=$5, \
             publish_claim_id=NULL, publish_claimed_by=NULL, publish_claimed_at=NULL, \
             publish_claim_until=NULL \
         WHERE community_id=$1 AND proposal_id=$2 AND publish_claim_id=$3 \
           AND publish_state='claimed' AND receipt_id=$6 AND occurred_at=$7 \
           AND EXISTS ( \
               SELECT 1 FROM external_action_proposals proposal \
               WHERE proposal.community_id=external_action_receipt_outbox.community_id \
                 AND proposal.id=external_action_receipt_outbox.proposal_id \
                 AND proposal.decision_id=$8 AND proposal.operation_hash=$9 \
                 AND proposal.channel_id=$10 AND proposal.owner_pubkey=$11 \
                 AND proposal.broker_pubkey=$12 AND proposal.proposal_event_hash IS NOT NULL \
           )",
    )
    .bind(community_id.as_uuid())
    .bind(verified.proposal_id())
    .bind(publish_claim_id)
    .bind(verified.event_hash().as_slice())
    .bind(published_at)
    .bind(verified.receipt_id())
    .bind(occurred_at)
    .bind(verified.decision_id())
    .bind(verified.operation_hash().as_slice())
    .bind(verified.channel_id())
    .bind(verified.owner_pubkey().as_slice())
    .bind(verified.broker_pubkey().as_slice())
    .execute(pool)
    .await?
    .rows_affected();
    Ok(updated == 1)
}

/// Release a failed receipt publication lease for a bounded explicit retry.
pub async fn retry_action_receipt_publication(
    pool: &PgPool,
    community_id: CommunityId,
    proposal_id: Uuid,
    publish_claim_id: Uuid,
    retry_at: DateTime<Utc>,
) -> crate::Result<bool> {
    let updated = sqlx::query(
        "UPDATE external_action_receipt_outbox \
         SET publish_state='retry', publish_claim_id=NULL, publish_claimed_by=NULL, \
             publish_claimed_at=NULL, publish_claim_until=NULL, retry_count=retry_count+1, \
             next_retry_at=$4 \
         WHERE community_id=$1 AND proposal_id=$2 AND publish_claim_id=$3 \
           AND publish_state='claimed'",
    )
    .bind(community_id.as_uuid())
    .bind(proposal_id)
    .bind(publish_claim_id)
    .bind(retry_at)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(updated == 1)
}

/// Move an in-flight action timeout to reconciliation without reopening it.
pub async fn mark_action_timeout_for_reconciliation(
    pool: &PgPool,
    community_id: CommunityId,
    proposal_id: Uuid,
    claim_id: Uuid,
    now: DateTime<Utc>,
) -> crate::Result<bool> {
    let mut tx = pool.begin().await?;
    let updated = sqlx::query(
        "UPDATE external_action_proposals \
         SET status='reconciliation_required', updated_at=$4 \
         WHERE community_id=$1 AND id=$2 AND execution_claim_id=$3 AND status='executing'",
    )
    .bind(community_id.as_uuid())
    .bind(proposal_id)
    .bind(claim_id)
    .bind(now)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if updated == 1 {
        sqlx::query(
            "UPDATE external_action_proposal_items \
             SET status='reconciliation_required' \
             WHERE community_id=$1 AND proposal_id=$2 AND status='executing'",
        )
        .bind(community_id.as_uuid())
        .bind(proposal_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE external_action_attempts \
             SET outcome='timeout', finished_at=$4 \
             WHERE community_id=$1 AND proposal_id=$2 AND claim_id=$3 AND outcome='in_progress'",
        )
        .bind(community_id.as_uuid())
        .bind(proposal_id)
        .bind(claim_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(updated == 1)
}
