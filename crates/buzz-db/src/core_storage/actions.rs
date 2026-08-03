use buzz_core::CommunityId;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use std::collections::HashSet;
use uuid::Uuid;

use super::{
    action_member_hash, action_member_operation_hash, action_operation_hash,
    action_ordered_members_hash, require_hash, require_pubkey, ActionExecutionClaim,
    ActionExecutionItem, ActionMemberHashInput, ActionProposalStatus, ExternalConnector,
    ExternalOperation, NewExternalActionProposal,
};

/// Insert a proposed cross-provider action bundle and all members atomically.
///
/// Member indices and `member_count` are derived from the ordered input. Tenant,
/// owner, broker, current private-channel membership, connector-account ownership,
/// and approved-scope authority are revalidated before insertion.
pub async fn insert_action_proposal(
    pool: &PgPool,
    community_id: CommunityId,
    proposal: &NewExternalActionProposal,
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
    let current_channel_members: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT pubkey) FROM channel_members \
         WHERE community_id=$1 AND channel_id=$2 AND removed_at IS NULL \
           AND pubkey IN ($3, $4)",
    )
    .bind(community_id.as_uuid())
    .bind(proposal.channel_id)
    .bind(&proposal.owner_pubkey)
    .bind(&proposal.broker_pubkey)
    .fetch_one(&mut *tx)
    .await?;
    if current_channel_members != 2 {
        return Err(crate::DbError::InvalidData(
            "action proposal owner and broker must be current private-channel members".into(),
        ));
    }
    sqlx::query(
        "INSERT INTO external_action_proposals \
         (community_id, id, owner_pubkey, broker_pubkey, channel_id, channel_visibility, \
          canonical_proposal, operation_hash, ordered_members_hash, member_count, nonce, proposed_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, 'private', $6, $7, $8, $9, $10, $11, $12)",
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
           AND execution_claim_id IS NULL \
         RETURNING owner_pubkey, broker_pubkey, channel_id, canonical_proposal, operation_hash, \
                   ordered_members_hash, member_count, nonce, \
                   proposed_at, expires_at, signer_pubkey, decision_broker_pubkey, \
                   decision_event_hash",
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
    let decision_broker_pubkey: Option<Vec<u8>> = row.try_get("decision_broker_pubkey")?;
    if decision_broker_pubkey.as_deref() != Some(broker_pubkey.as_slice()) {
        return Err(crate::DbError::InvalidData(
            "approved action decision is addressed to a different broker".into(),
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
        let operation = ExternalOperation::from_wire(&operation_text).ok_or_else(|| {
            crate::DbError::InvalidData(format!("unknown external operation {operation_text:?}"))
        })?;
        if operation.connector() != item_connector || item_connector.as_str() != item_connector_text
        {
            return Err(crate::DbError::InvalidData(
                "external action member does not match proposal connector".into(),
            ));
        }
        sqlx::query(
            "INSERT INTO external_action_attempts \
             (community_id, id, proposal_id, item_index, claim_id, attempt_number, started_at) \
             VALUES ($1, $2, $3, $4, $5, 1, $6)",
        )
        .bind(community_id.as_uuid())
        .bind(Uuid::new_v4())
        .bind(proposal_id)
        .bind(item_index)
        .bind(claim_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
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
        owner_pubkey: row.try_get("owner_pubkey")?,
        broker_pubkey,
        channel_id: row.try_get("channel_id")?,
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
    tx.commit().await?;
    Ok(Some(claim))
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
