use std::time::Duration as StdDuration;

use buzz_core::{
    action_auth::{
        validate_signed_action_decision, validate_signed_action_proposal,
        validate_signed_action_receipt, DecisionExpectation, ProposalExpectation,
        ReceiptExpectation, VerifiedActionDecision, VerifiedActionProposal, VerifiedActionReceipt,
    },
    core_protocol::{ActionProposalPayload, ActionReceiptPayload},
    CommunityId,
};
use buzz_db::core_storage::{
    action_member_hash, action_member_operation_hash, action_operation_hash,
    action_ordered_members_hash, append_audit_entry, apply_source_change_page,
    begin_action_remote_attempt, claim_action_execution, claim_action_receipt_publication,
    claim_audit_export_batch, claim_delta_scope, claim_insight_slot,
    complete_action_receipt_publication, complete_audit_export_batch, complete_delta_scope,
    fail_delta_scope, insert_action_proposal, mark_action_timeout_for_reconciliation,
    recheck_source_chunk, record_action_decision, record_action_member_outcome,
    retry_action_receipt_publication, retry_audit_export_batch, search_source_chunks,
    search_source_chunks_by_embedding, source_chunk_hash, ActionClaimDecision,
    ActionDecisionRecordOutcome, ActionMemberHashInput, ActionMemberOutcome, ActionProposalStatus,
    ApprovedSourceScopeRecord, AuditEntityType, AuditEnvelope, AuditEventType, AuditObjectVersion,
    AuditOutcome, ConnectorAccountRecord, DeltaLeaseClaim, DeltaLeaseDecision, ExternalConnector,
    ExternalOperation, IndexedSourceKind, InsightClaimDecision, InsightClaimOutcome,
    InsightPriority, KeyVaultSecretName, NewActionMemberOutcome, NewAssistantInsight,
    NewExternalActionProposal, NewExternalActionProposalItem, NewIndexedSourceChunk,
    NewIndexedSourceItem, NewSourceAclPrincipal, NewSourceChangePage, NewSourceTombstone,
    SourceCandidateRecheckRequest, SourceItemAclRecord, SourcePageApplyOutcome,
    SourceSearchRequest, SourceVectorSearchRequest,
};
use chrono::{Duration, NaiveDate, Utc};
use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};
use serde_json::json;
use sqlx::{PgPool, Row};
use uuid::Uuid;

const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz";

fn verified_proposal(
    proposal: &NewExternalActionProposal,
    broker: &Keys,
) -> VerifiedActionProposal {
    let first = proposal.items.first().expect("proposal item");
    let payload: ActionProposalPayload = serde_json::from_value(json!({
        "schema_version": 1,
        "proposal_id": proposal.id.to_string(),
        "nonce": proposal.nonce.to_string(),
        "operation_hash": hex::encode(&proposal.operation_hash),
        "proposed_at": proposal.proposed_at.timestamp(),
        "expires_at": proposal.expires_at.timestamp(),
        "bundle_semantics": "independent_operations",
        "operations": [{
            "operation_id": first.operation_id.to_string(),
            "operation_hash": "11".repeat(32),
            "idempotency_key": first.idempotency_key.to_string(),
            "target": {
                "provider": "outlook",
                "account_id": first.account_id.to_string(),
                "scope_id": first.scope_id.to_string(),
                "object_id": null
            },
            "before": null,
            "after": {"canonical_value": "{}", "value_hash": "22".repeat(32)},
            "expected_remote_version": null,
            "side_effects": ["creates_draft"],
            "operation": {
                "provider": "outlook",
                "operation": {
                    "action": "create_draft",
                    "recipients": {"to": ["test@example.invalid"], "cc": [], "bcc": []},
                    "subject": "Contract test",
                    "body": "Contract test",
                    "attachments": []
                }
            }
        }],
        "evidence": [{
            "source": "crm",
            "source_id": "contract-test",
            "source_hash": "33".repeat(32),
            "citation": null
        }]
    }))
    .expect("valid signed proposal payload");
    let channel = proposal.channel_id.to_string();
    let owner = hex::encode(&proposal.owner_pubkey);
    let event = EventBuilder::new(
        Kind::Custom(44_310),
        serde_json::to_string(&payload).expect("serialize proposal payload"),
    )
    .tags(vec![
        Tag::parse(["h", channel.as_str()]).expect("proposal h tag"),
        Tag::parse(["p", owner.as_str()]).expect("proposal p tag"),
    ])
    .custom_created_at(Timestamp::from(proposal.proposed_at.timestamp() as u64))
    .sign_with_keys(broker)
    .expect("sign proposal event");
    validate_signed_action_proposal(
        &event,
        &ProposalExpectation {
            payload,
            channel_id: proposal.channel_id,
            owner_pubkey: proposal
                .owner_pubkey
                .as_slice()
                .try_into()
                .expect("proposal owner key"),
            broker_pubkey: proposal
                .broker_pubkey
                .as_slice()
                .try_into()
                .expect("proposal broker key"),
        },
        proposal.proposed_at.timestamp(),
    )
    .expect("verify signed proposal event")
}

fn verified_receipt(
    publication: &buzz_db::core_storage::ActionReceiptPublication,
    broker: &Keys,
) -> VerifiedActionReceipt {
    let results = publication
        .results
        .iter()
        .map(|result| {
            json!({
                "operation_id": result.operation_id.to_string(),
                "operation_hash": hex::encode(&result.operation_hash),
                "idempotency_key": result.idempotency_key.to_string(),
                "outcome": match result.outcome {
                    ActionMemberOutcome::Succeeded => "succeeded",
                    ActionMemberOutcome::Failed => "failed",
                    ActionMemberOutcome::ReconciliationRequired => "reconciliation_required",
                },
                "external_result_id": result.external_result_id,
                "external_result_version": result.external_result_version,
                "reconciliation_status": result.reconciliation_status,
            })
        })
        .collect::<Vec<_>>();
    let payload: ActionReceiptPayload = serde_json::from_value(json!({
        "schema_version": 1,
        "receipt_id": publication.receipt_id.to_string(),
        "proposal_id": publication.proposal_id.to_string(),
        "decision_id": publication.decision_id.to_string(),
        "operation_hash": hex::encode(&publication.operation_hash),
        "results": results,
        "occurred_at": publication.occurred_at.timestamp(),
    }))
    .expect("valid signed receipt payload");
    let channel = publication.channel_id.to_string();
    let owner = hex::encode(&publication.owner_pubkey);
    let event = EventBuilder::new(
        Kind::Custom(44_312),
        serde_json::to_string(&payload).expect("serialize receipt payload"),
    )
    .tags(vec![
        Tag::parse(["h", channel.as_str()]).expect("receipt h tag"),
        Tag::parse(["p", owner.as_str()]).expect("receipt p tag"),
    ])
    .custom_created_at(Timestamp::from(publication.occurred_at.timestamp() as u64))
    .sign_with_keys(broker)
    .expect("sign receipt event");
    validate_signed_action_receipt(
        &event,
        &ReceiptExpectation {
            payload,
            channel_id: publication.channel_id,
            owner_pubkey: publication
                .owner_pubkey
                .as_slice()
                .try_into()
                .expect("receipt owner key"),
            broker_pubkey: publication
                .broker_pubkey
                .as_slice()
                .try_into()
                .expect("receipt broker key"),
        },
        publication.occurred_at.timestamp(),
    )
    .expect("verify signed receipt event")
}

fn verified_approval(
    owner: &Keys,
    recipient: &Keys,
    expectation: &DecisionExpectation,
    decided_at: i64,
) -> VerifiedActionDecision {
    let payload = json!({
        "schema_version": 1,
        "decision_id": Uuid::new_v4().to_string(),
        "proposal_id": expectation.proposal_id.to_string(),
        "nonce": expectation.nonce.to_string(),
        "operation_hash": hex::encode(expectation.operation_hash),
        "decision": "approve",
        "signer": owner.public_key().to_hex(),
        "decided_at": decided_at,
    });
    let event = EventBuilder::new(
        Kind::Custom(44_311),
        serde_json::to_string(&payload).expect("serialize decision payload"),
    )
    .tags(vec![
        Tag::parse(["h", expectation.channel_id.to_string().as_str()]).expect("decision h tag"),
        Tag::parse(["p", recipient.public_key().to_hex().as_str()]).expect("decision p tag"),
    ])
    .custom_created_at(Timestamp::from(decided_at as u64))
    .sign_with_keys(owner)
    .expect("sign decision event");

    validate_signed_action_decision(&event, expectation, decided_at)
        .expect("decision fixture must be cryptographically valid")
}

#[test]
fn action_operation_hash_uses_the_frozen_domain_and_exact_canonical_bytes() {
    assert_eq!(
        hex::encode(action_operation_hash(br#"{"x":1}"#)),
        "4474c4c51bb8952e6934b2d708bf2102db763d56c4888250d880f3cb1ef9795c"
    );
    assert_ne!(
        action_operation_hash(br#"{"x":1}"#),
        action_operation_hash(b"{ \"x\": 1 }")
    );
}

fn test_db_url() -> String {
    std::env::var("BUZZ_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| TEST_DB_URL.to_owned())
}

async fn scratch_db() -> (PgPool, PgPool, String) {
    let admin = PgPool::connect(&test_db_url())
        .await
        .expect("connect to Postgres test instance");
    let name = format!("core_storage_{}", Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(&admin)
        .await
        .expect("create isolated scratch database");
    let base = test_db_url();
    let path = base.rfind('/').expect("database URL has a path");
    let pool = PgPool::connect(&format!("{}/{name}", &base[..path]))
        .await
        .expect("connect to scratch database");
    buzz_db::migration::run_migrations(&pool)
        .await
        .expect("apply migrations to scratch database");
    (admin, pool, name)
}

async fn drop_scratch_db(admin: &PgPool, pool: PgPool, name: &str) {
    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP DATABASE IF EXISTS {name} WITH (FORCE)"
    )))
    .execute(admin)
    .await
    .expect("drop isolated scratch database");
}

async fn seed_community(pool: &PgPool, marker: &str) -> (CommunityId, Uuid) {
    let community = Uuid::new_v4();
    let channel = Uuid::new_v4();
    sqlx::query("INSERT INTO communities (id, host) VALUES ($1, $2)")
        .bind(community)
        .bind(format!("{marker}-{}.example", community.simple()))
        .execute(pool)
        .await
        .expect("insert community");
    sqlx::query(
        "INSERT INTO channels (community_id, id, name, created_by) VALUES ($1, $2, $3, $4)",
    )
    .bind(community)
    .bind(channel)
    .bind(format!("{marker}-channel"))
    .bind(vec![7_u8; 32])
    .execute(pool)
    .await
    .expect("insert channel");
    for marker in [3_u8, 4_u8, 8_u8] {
        sqlx::query("INSERT INTO users (community_id, pubkey) VALUES ($1, $2)")
            .bind(community)
            .bind(vec![marker; 32])
            .execute(pool)
            .await
            .expect("insert connector or insight owner");
    }
    (CommunityId::from_uuid(community), channel)
}

async fn seed_source(
    pool: &PgPool,
    community: CommunityId,
    item_id: Uuid,
    acl_pubkey: &[u8],
) -> (Uuid, Uuid, Uuid) {
    let account_id = Uuid::new_v4();
    let scope_id = Uuid::new_v4();
    let chunk_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (community_id, pubkey) VALUES ($1, $2) ON CONFLICT DO NOTHING")
        .bind(community.as_uuid())
        .bind(acl_pubkey)
        .execute(pool)
        .await
        .expect("insert ACL user");
    sqlx::query(
        "INSERT INTO connector_accounts \
         (community_id, id, provider, owner_pubkey, external_account_id, credential_reference) \
         VALUES ($1, $2, 'microsoft_graph', $3, $4, $5)",
    )
    .bind(community.as_uuid())
    .bind(account_id)
    .bind(vec![3_u8; 32])
    .bind(format!("account-{account_id}"))
    .bind(format!("kv-account-{account_id}"))
    .execute(pool)
    .await
    .expect("insert connector account");
    sqlx::query(
        "INSERT INTO approved_source_scopes \
         (community_id, id, account_id, external_scope_id, scope_type, can_read, can_write) \
         VALUES ($1, $2, $3, $4, 'sharepoint_site', true, false)",
    )
    .bind(community.as_uuid())
    .bind(scope_id)
    .bind(account_id)
    .bind(format!("scope-{scope_id}"))
    .execute(pool)
    .await
    .expect("insert source scope");
    sqlx::query(
        "INSERT INTO source_items \
         (community_id, id, account_id, scope_id, external_item_id, remote_version, title, source_type, modified_at, resolvable_link, last_authorization_check_at) \
         VALUES ($1, $2, $3, $4, $5, 'v1', $6, 'document', NOW(), $7, NOW())",
    )
    .bind(community.as_uuid())
    .bind(item_id)
    .bind(account_id)
    .bind(scope_id)
    .bind(format!("external-{item_id}"))
    .bind(format!("Needle {item_id}"))
    .bind(format!("https://source.invalid/{item_id}"))
    .execute(pool)
    .await
    .expect("insert source item");
    sqlx::query(
        "INSERT INTO source_chunks \
         (community_id, id, item_id, chunk_index, start_char, end_char, content, content_hash) \
         VALUES ($1, $2, $3, 0, 0, 28, 'needle confidential evidence', $4)",
    )
    .bind(community.as_uuid())
    .bind(chunk_id)
    .bind(item_id)
    .bind(source_chunk_hash(0, 0, 28, "needle confidential evidence").to_vec())
    .execute(pool)
    .await
    .expect("insert source chunk");
    sqlx::query(
        "INSERT INTO source_item_acls \
         (community_id, id, item_id, principal_type, principal_pubkey) \
         VALUES ($1, $2, $3, 'user', $4)",
    )
    .bind(community.as_uuid())
    .bind(Uuid::new_v4())
    .bind(item_id)
    .bind(acl_pubkey)
    .execute(pool)
    .await
    .expect("insert source ACL");
    (account_id, scope_id, chunk_id)
}

#[allow(clippy::too_many_arguments)]
fn microsoft_resolver_page<'a>(
    community_id: CommunityId,
    account_id: Uuid,
    scope_id: Uuid,
    worker_id: Uuid,
    lease_generation: i64,
    upserts: &'a [NewIndexedSourceItem],
    page_digest: &'a [u8],
    now: chrono::DateTime<Utc>,
) -> NewSourceChangePage<'a> {
    NewSourceChangePage {
        community_id,
        account_id,
        scope_id,
        provider: ExternalConnector::MicrosoftGraph,
        stream: "changes",
        worker_id,
        lease_generation,
        expected_cursor_integrity_hash: &[4_u8; 32],
        next_encrypted_cursor: &[5_u8; 48],
        next_cursor_integrity_hash: &[5_u8; 32],
        next_cursor_key_version: 1,
        page_digest,
        upserts,
        tombstones: &[],
        now,
    }
}

#[tokio::test]
#[ignore = "requires Postgres with pgvector"]
async fn revoked_identity_history_allows_new_key_but_never_reuses_compromised_key() {
    let (admin, pool, name) = scratch_db().await;
    let (community, _) = seed_community(&pool, "identity").await;
    let old_key = vec![10_u8; 32];
    let new_key = vec![11_u8; 32];
    let revoker = vec![12_u8; 32];
    for pubkey in [&old_key, &new_key, &revoker] {
        sqlx::query("INSERT INTO users (community_id, pubkey) VALUES ($1, $2)")
            .bind(community.as_uuid())
            .bind(pubkey)
            .execute(&pool)
            .await
            .expect("insert identity user");
    }
    let active_without_verification = sqlx::query(
        "INSERT INTO core_identity_bindings \
         (community_id, entra_object_id, buzz_pubkey, lifecycle_state, challenge_hash, challenge_created_at, challenge_expires_at) \
         VALUES ($1, $2, $3, 'active', $4, NOW(), NOW()+INTERVAL '5 minutes')",
    )
    .bind(community.as_uuid())
    .bind(Uuid::new_v4())
    .bind(&old_key)
    .bind(vec![90_u8; 32])
    .execute(&pool)
    .await;
    assert!(active_without_verification.is_err());
    let challenged_with_verification = sqlx::query(
        "INSERT INTO core_identity_bindings \
         (community_id, entra_object_id, buzz_pubkey, lifecycle_state, challenge_hash, challenge_created_at, challenge_expires_at, challenge_verified_at) \
         VALUES ($1, $2, $3, 'challenged', $4, NOW(), NOW()+INTERVAL '5 minutes', NOW())",
    )
    .bind(community.as_uuid())
    .bind(Uuid::new_v4())
    .bind(&new_key)
    .bind(vec![91_u8; 32])
    .execute(&pool)
    .await;
    assert!(challenged_with_verification.is_err());
    let verification_before_challenge = sqlx::query(
        "INSERT INTO core_identity_bindings \
         (community_id, entra_object_id, buzz_pubkey, lifecycle_state, challenge_hash, challenge_created_at, challenge_expires_at, challenge_verified_at) \
         VALUES ($1, $2, $3, 'active', $4, NOW(), NOW()+INTERVAL '5 minutes', NOW()-INTERVAL '1 second')",
    )
    .bind(community.as_uuid())
    .bind(Uuid::new_v4())
    .bind(&revoker)
    .bind(vec![92_u8; 32])
    .execute(&pool)
    .await;
    assert!(
        verification_before_challenge.is_err(),
        "verification before challenge creation must be rejected"
    );
    let entra_object_id = Uuid::new_v4();
    let account_id = Uuid::new_v4();
    let old_binding_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO connector_accounts \
         (community_id, id, provider, owner_pubkey, external_account_id, credential_reference) \
         VALUES ($1, $2, 'microsoft_graph', $3, $4, $5)",
    )
    .bind(community.as_uuid())
    .bind(account_id)
    .bind(&old_key)
    .bind(format!("account-{account_id}"))
    .bind(format!("kv-account-{account_id}"))
    .execute(&pool)
    .await
    .expect("insert identity connector account");
    sqlx::query(
        "INSERT INTO core_identity_bindings \
         (community_id, id, entra_object_id, buzz_pubkey, lifecycle_state, challenge_hash, challenge_created_at, challenge_expires_at, challenge_verified_at, connector_account_id) \
         VALUES ($1, $2, $3, $4, 'active', $5, NOW(), NOW()+INTERVAL '5 minutes', NOW(), $6)",
    )
    .bind(community.as_uuid())
    .bind(old_binding_id)
    .bind(entra_object_id)
    .bind(&old_key)
    .bind(vec![13_u8; 32])
    .bind(account_id)
    .execute(&pool)
    .await
    .expect("insert old active identity binding");

    let simultaneous = sqlx::query(
        "INSERT INTO core_identity_bindings \
         (community_id, entra_object_id, buzz_pubkey, lifecycle_state, challenge_hash, challenge_created_at, challenge_expires_at) \
         VALUES ($1, $2, $3, 'challenged', $4, NOW(), NOW()+INTERVAL '5 minutes')",
    )
    .bind(community.as_uuid())
    .bind(entra_object_id)
    .bind(&new_key)
    .bind(vec![14_u8; 32])
    .execute(&pool)
    .await;
    assert!(
        simultaneous.is_err(),
        "two live Entra bindings must conflict"
    );

    let mut tx = pool.begin().await.expect("begin identity recovery");
    sqlx::query(
        "UPDATE core_identity_bindings \
         SET lifecycle_state='revoked', revoked_at=NOW(), revoked_by_pubkey=$3, connector_account_id=NULL \
         WHERE community_id=$1 AND id=$2",
    )
    .bind(community.as_uuid())
    .bind(old_binding_id)
    .bind(&revoker)
    .execute(&mut *tx)
    .await
    .expect("revoke and detach old binding");
    sqlx::query("UPDATE connector_accounts SET owner_pubkey=$3 WHERE community_id=$1 AND id=$2")
        .bind(community.as_uuid())
        .bind(account_id)
        .bind(&new_key)
        .execute(&mut *tx)
        .await
        .expect("reassign connector account owner");
    sqlx::query(
        "INSERT INTO core_identity_bindings \
         (community_id, entra_object_id, buzz_pubkey, lifecycle_state, challenge_hash, challenge_created_at, challenge_expires_at, challenge_verified_at, connector_account_id) \
         VALUES ($1, $2, $3, 'active', $4, NOW(), NOW()+INTERVAL '5 minutes', NOW(), $5)",
    )
    .bind(community.as_uuid())
    .bind(entra_object_id)
    .bind(&new_key)
    .bind(vec![15_u8; 32])
    .bind(account_id)
    .execute(&mut *tx)
    .await
    .expect("insert replacement identity binding");
    tx.commit().await.expect("commit identity recovery");

    let compromised_reuse = sqlx::query(
        "INSERT INTO core_identity_bindings \
         (community_id, entra_object_id, buzz_pubkey, lifecycle_state, challenge_hash, challenge_created_at, challenge_expires_at) \
         VALUES ($1, $2, $3, 'challenged', $4, NOW(), NOW()+INTERVAL '5 minutes')",
    )
    .bind(community.as_uuid())
    .bind(Uuid::new_v4())
    .bind(&old_key)
    .bind(vec![16_u8; 32])
    .execute(&pool)
    .await;
    assert!(
        compromised_reuse.is_err(),
        "revoked Buzz keys remain permanently unique"
    );

    drop_scratch_db(&admin, pool, &name).await;
}

#[tokio::test]
#[ignore = "requires vanilla PostgreSQL without pgvector"]
async fn vanilla_postgres_migrates_without_installing_vector_storage() {
    let (admin, pool, name) = scratch_db().await;
    let vector_installed: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname='vector')")
            .fetch_one(&pool)
            .await
            .expect("inspect installed extensions");
    let embedding_column: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
         WHERE table_schema='public' AND table_name='source_chunks' AND column_name='embedding')",
    )
    .fetch_one(&pool)
    .await
    .expect("inspect optional embedding column");
    assert!(!vector_installed);
    assert!(!embedding_column);
    drop_scratch_db(&admin, pool, &name).await;
}

#[tokio::test]
#[ignore = "requires Postgres role privileges"]
async fn connector_worker_can_delete_only_replaceable_source_children() {
    let (admin, pool, name) = scratch_db().await;

    for table in ["source_chunks", "source_item_acls"] {
        let allowed: bool =
            sqlx::query_scalar("SELECT has_table_privilege('core_connector_worker', $1, 'DELETE')")
                .bind(table)
                .fetch_one(&pool)
                .await
                .expect("check connector worker delete privilege");
        assert!(
            allowed,
            "connector worker must delete {table} during replacement"
        );
    }

    for table in [
        "source_items",
        "connector_accounts",
        "approved_source_scopes",
        "connector_delta_cursors",
        "core_audit_outbox",
    ] {
        let denied: bool =
            sqlx::query_scalar("SELECT has_table_privilege('core_connector_worker', $1, 'DELETE')")
                .bind(table)
                .fetch_one(&pool)
                .await
                .expect("check connector worker delete privilege");
        assert!(!denied, "connector worker must not delete from {table}");
    }

    drop_scratch_db(&admin, pool, &name).await;
}

#[test]
fn pure_claim_decisions_fail_closed_at_boundaries() {
    let now = Utc::now();
    let worker = Uuid::new_v4();

    assert_eq!(
        InsightClaimDecision::evaluate(true, 4),
        InsightClaimDecision::Duplicate
    );
    assert_eq!(
        InsightClaimDecision::evaluate(false, 10),
        InsightClaimDecision::BudgetExhausted
    );
    assert_eq!(
        ActionClaimDecision::evaluate(
            ActionProposalStatus::Approved,
            now + Duration::seconds(1),
            false,
            now,
        ),
        ActionClaimDecision::Claim
    );
    assert_eq!(
        ActionClaimDecision::evaluate(ActionProposalStatus::Approved, now, false, now),
        ActionClaimDecision::Expired
    );
    assert_eq!(
        DeltaLeaseDecision::evaluate(
            Some(Uuid::new_v4()),
            Some(now + Duration::seconds(1)),
            worker,
            now,
        ),
        DeltaLeaseDecision::Busy
    );
    assert_eq!(
        DeltaLeaseDecision::evaluate(None, Some(now - Duration::seconds(1)), worker, now),
        DeltaLeaseDecision::Claim
    );
}

#[test]
fn operation_and_audit_categories_reject_open_ended_values() {
    assert_eq!(
        ExternalOperation::from_wire("outlook/create_draft"),
        Some(ExternalOperation::OutlookCreateDraft)
    );
    assert_eq!(ExternalOperation::from_wire("outlook/send_mail"), None);
    assert!(AuditObjectVersion::new("v1:etag-2").is_ok());
    assert!(AuditObjectVersion::new("mailbox body with spaces").is_err());
}

#[test]
fn connector_storage_debug_output_redacts_cursors_and_authority_ids() {
    let sensitive_id =
        Uuid::parse_str("feedface-dead-beef-cafe-0123456789ab").expect("valid sentinel UUID");
    let claim = DeltaLeaseClaim {
        encrypted_cursor: b"MNPI-CURSOR-SENTINEL".to_vec(),
        cursor_integrity_hash: vec![77; 32],
        cursor_key_version: 1,
        generation: 2,
        lease_until: Utc::now(),
    };
    let acl = SourceItemAclRecord {
        community_id: CommunityId::from_uuid(sensitive_id),
        id: sensitive_id,
        item_id: sensitive_id,
        principal_type: "user".into(),
        principal_pubkey: Some(vec![77; 32]),
        channel_id: None,
    };
    let new_acl = NewSourceAclPrincipal::Channel(sensitive_id);
    let credential_reference =
        KeyVaultSecretName::new("MNPI-CREDENTIAL-SENTINEL").expect("valid secret name");
    let account = ConnectorAccountRecord {
        community_id: CommunityId::from_uuid(sensitive_id),
        id: sensitive_id,
        provider: "google_drive".into(),
        owner_pubkey: vec![77; 32],
        external_account_id: "MNPI-ACCOUNT-SENTINEL".into(),
        credential_reference: credential_reference.clone(),
        status: "active".into(),
    };
    let scope = ApprovedSourceScopeRecord {
        community_id: CommunityId::from_uuid(sensitive_id),
        id: sensitive_id,
        account_id: sensitive_id,
        external_scope_id: "MNPI-SCOPE-SENTINEL".into(),
        resolver_hosts: vec!["mnpi-host-sentinel.sharepoint.com".into()],
        scope_type: "google_shared_drive".into(),
        can_read: true,
        can_write: false,
        active_deal_pinned: false,
        status: "active".into(),
    };
    for debug in [
        format!("{claim:?}"),
        format!("{acl:?}"),
        format!("{new_acl:?}"),
        format!("{credential_reference:?}"),
        format!("{account:?}"),
        format!("{scope:?}"),
    ] {
        assert!(!debug.contains("MNPI-CURSOR-SENTINEL"));
        assert!(!debug.contains("MNPI-CREDENTIAL-SENTINEL"));
        assert!(!debug.contains("MNPI-ACCOUNT-SENTINEL"));
        assert!(!debug.contains("MNPI-SCOPE-SENTINEL"));
        assert!(!debug.contains("feedface"));
        assert!(!debug.contains("77, 77"));
    }
}

#[tokio::test]
#[ignore = "requires Postgres with pgvector"]
async fn cross_community_collisions_are_safe_and_acl_filtering_precedes_search() {
    let (admin, pool, name) = scratch_db().await;
    let (community_a, channel_a) = seed_community(&pool, "source-a").await;
    let (community_b, _) = seed_community(&pool, "source-b").await;
    let shared_item_id = Uuid::new_v4();
    let allowed_user = vec![1_u8; 32];
    let denied_user = vec![2_u8; 32];
    let (_, scope_a, chunk_a) =
        seed_source(&pool, community_a, shared_item_id, &allowed_user).await;
    seed_source(&pool, community_b, shared_item_id, &denied_user).await;
    sqlx::query(
        "INSERT INTO source_item_acls \
         (community_id, id, item_id, principal_type, channel_id) \
         VALUES ($1, $2, $3, 'channel', $4)",
    )
    .bind(community_a.as_uuid())
    .bind(Uuid::new_v4())
    .bind(shared_item_id)
    .bind(channel_a)
    .execute(&pool)
    .await
    .expect("insert channel source ACL");
    let embedding_version = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO embedding_versions \
         (community_id, id, model_name, dimensions, version, activated_at) \
         VALUES ($1, $2, 'acl-contract', 384, 1, NOW())",
    )
    .bind(community_a.as_uuid())
    .bind(embedding_version)
    .execute(&pool)
    .await
    .expect("insert embedding version");
    assert!(sqlx::query(
        "INSERT INTO embedding_versions \
         (community_id, id, model_name, dimensions, version, status, activated_at) \
         VALUES ($1, $2, 'acl-contract', 384, 2, 'active', NOW())",
    )
    .bind(community_a.as_uuid())
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .is_err());
    let embedding = vec![1.0_f32; 384];
    let embedding_literal = format!(
        "[{}]",
        embedding
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    sqlx::query(
        "UPDATE source_chunks SET embedding_version_id=$3, embedding=CAST($4 AS vector) \
         WHERE community_id=$1 AND id=$2",
    )
    .bind(community_a.as_uuid())
    .bind(chunk_a)
    .bind(embedding_version)
    .bind(embedding_literal)
    .execute(&pool)
    .await
    .expect("seed source embedding");

    let allowed = search_source_chunks(
        &pool,
        community_a,
        SourceSearchRequest {
            query: "needle",
            embedding_version_id: embedding_version,
            requester_pubkey: &allowed_user,
            authorized_channel_ids: &[channel_a],
            limit: 10,
        },
    )
    .await
    .expect("search allowed source chunks");
    assert_eq!(allowed.len(), 1);
    assert_eq!(allowed[0].item_id, shared_item_id);
    assert_eq!(allowed[0].title, format!("Needle {shared_item_id}"));
    let ranked = allowed[0].clone();
    let rechecked = recheck_source_chunk(
        &pool,
        community_a,
        SourceCandidateRecheckRequest {
            item_id: ranked.item_id,
            chunk_id: ranked.chunk_id,
            remote_version: &ranked.remote_version,
            remote_etag: ranked.remote_etag.as_deref(),
            chunk_hash: &ranked.chunk_hash,
            embedding_version_id: ranked.embedding_version_id,
            requester_pubkey: &allowed_user,
            authorized_channel_ids: &[],
        },
    )
    .await
    .expect("post-rank source recheck")
    .expect("unchanged user ACL remains authorized");
    assert_eq!(rechecked.content, "needle confidential evidence");
    assert_eq!((rechecked.start_char, rechecked.end_char), (0, 28));
    assert_eq!(rechecked.provider, "microsoft_graph");
    assert_eq!(rechecked.acl_revision.len(), 32);
    assert!(recheck_source_chunk(
        &pool,
        community_b,
        SourceCandidateRecheckRequest {
            item_id: ranked.item_id,
            chunk_id: ranked.chunk_id,
            remote_version: &ranked.remote_version,
            remote_etag: ranked.remote_etag.as_deref(),
            chunk_hash: &ranked.chunk_hash,
            embedding_version_id: ranked.embedding_version_id,
            requester_pubkey: &allowed_user,
            authorized_channel_ids: &[],
        },
    )
    .await
    .expect("cross-tenant post-rank recheck")
    .is_none());

    sqlx::query(
        "DELETE FROM source_item_acls \
         WHERE community_id=$1 AND item_id=$2 AND principal_type='user' AND principal_pubkey=$3",
    )
    .bind(community_a.as_uuid())
    .bind(shared_item_id)
    .bind(&allowed_user)
    .execute(&pool)
    .await
    .expect("revoke user ACL after ranking");
    assert!(recheck_source_chunk(
        &pool,
        community_a,
        SourceCandidateRecheckRequest {
            item_id: ranked.item_id,
            chunk_id: ranked.chunk_id,
            remote_version: &ranked.remote_version,
            remote_etag: ranked.remote_etag.as_deref(),
            chunk_hash: &ranked.chunk_hash,
            embedding_version_id: ranked.embedding_version_id,
            requester_pubkey: &allowed_user,
            authorized_channel_ids: &[],
        },
    )
    .await
    .expect("post-rank revocation recheck")
    .is_none());
    sqlx::query(
        "INSERT INTO source_item_acls \
         (community_id, id, item_id, principal_type, principal_pubkey) \
         VALUES ($1, $2, $3, 'user', $4)",
    )
    .bind(community_a.as_uuid())
    .bind(Uuid::new_v4())
    .bind(shared_item_id)
    .bind(&allowed_user)
    .execute(&pool)
    .await
    .expect("restore user ACL for remaining contract checks");

    sqlx::query("UPDATE source_items SET remote_version='v2' WHERE community_id=$1 AND id=$2")
        .bind(community_a.as_uuid())
        .bind(shared_item_id)
        .execute(&pool)
        .await
        .expect("change provider version after ranking");
    assert!(recheck_source_chunk(
        &pool,
        community_a,
        SourceCandidateRecheckRequest {
            item_id: ranked.item_id,
            chunk_id: ranked.chunk_id,
            remote_version: &ranked.remote_version,
            remote_etag: ranked.remote_etag.as_deref(),
            chunk_hash: &ranked.chunk_hash,
            embedding_version_id: ranked.embedding_version_id,
            requester_pubkey: &allowed_user,
            authorized_channel_ids: &[],
        },
    )
    .await
    .expect("changed-version recheck")
    .is_none());
    sqlx::query("UPDATE source_items SET remote_version='v1' WHERE community_id=$1 AND id=$2")
        .bind(community_a.as_uuid())
        .bind(shared_item_id)
        .execute(&pool)
        .await
        .expect("restore provider version");

    sqlx::query("UPDATE source_items SET remote_etag='etag-v1' WHERE community_id=$1 AND id=$2")
        .bind(community_a.as_uuid())
        .bind(shared_item_id)
        .execute(&pool)
        .await
        .expect("change provider etag after ranking");
    assert!(recheck_source_chunk(
        &pool,
        community_a,
        SourceCandidateRecheckRequest {
            item_id: ranked.item_id,
            chunk_id: ranked.chunk_id,
            remote_version: &ranked.remote_version,
            remote_etag: ranked.remote_etag.as_deref(),
            chunk_hash: &ranked.chunk_hash,
            embedding_version_id: ranked.embedding_version_id,
            requester_pubkey: &allowed_user,
            authorized_channel_ids: &[],
        },
    )
    .await
    .expect("changed-etag recheck")
    .is_none());
    sqlx::query("UPDATE source_items SET remote_etag=NULL WHERE community_id=$1 AND id=$2")
        .bind(community_a.as_uuid())
        .bind(shared_item_id)
        .execute(&pool)
        .await
        .expect("restore provider etag");

    sqlx::query("UPDATE source_chunks SET content_hash=$3 WHERE community_id=$1 AND id=$2")
        .bind(community_a.as_uuid())
        .bind(ranked.chunk_id)
        .bind(vec![10_u8; 32])
        .execute(&pool)
        .await
        .expect("replace chunk hash after ranking");
    assert!(recheck_source_chunk(
        &pool,
        community_a,
        SourceCandidateRecheckRequest {
            item_id: ranked.item_id,
            chunk_id: ranked.chunk_id,
            remote_version: &ranked.remote_version,
            remote_etag: ranked.remote_etag.as_deref(),
            chunk_hash: &ranked.chunk_hash,
            embedding_version_id: ranked.embedding_version_id,
            requester_pubkey: &allowed_user,
            authorized_channel_ids: &[],
        },
    )
    .await
    .expect("changed-chunk recheck")
    .is_none());
    sqlx::query("UPDATE source_chunks SET content_hash=$3 WHERE community_id=$1 AND id=$2")
        .bind(community_a.as_uuid())
        .bind(ranked.chunk_id)
        .bind(&ranked.chunk_hash)
        .execute(&pool)
        .await
        .expect("restore chunk hash");

    sqlx::query("UPDATE source_chunks SET content='needle corrupted evidence' WHERE community_id=$1 AND id=$2")
        .bind(community_a.as_uuid())
        .bind(ranked.chunk_id)
        .execute(&pool)
        .await
        .expect("corrupt source content without its hash");
    assert!(recheck_source_chunk(
        &pool,
        community_a,
        SourceCandidateRecheckRequest {
            item_id: ranked.item_id,
            chunk_id: ranked.chunk_id,
            remote_version: &ranked.remote_version,
            remote_etag: ranked.remote_etag.as_deref(),
            chunk_hash: &ranked.chunk_hash,
            embedding_version_id: ranked.embedding_version_id,
            requester_pubkey: &allowed_user,
            authorized_channel_ids: &[],
        },
    )
    .await
    .is_err());
    sqlx::query(
        "UPDATE source_chunks SET content='needle confidential evidence', start_char=1, end_char=29 \
         WHERE community_id=$1 AND id=$2",
    )
    .bind(community_a.as_uuid())
    .bind(ranked.chunk_id)
    .execute(&pool)
    .await
    .expect("corrupt Unicode-scalar source offsets");
    assert!(recheck_source_chunk(
        &pool,
        community_a,
        SourceCandidateRecheckRequest {
            item_id: ranked.item_id,
            chunk_id: ranked.chunk_id,
            remote_version: &ranked.remote_version,
            remote_etag: ranked.remote_etag.as_deref(),
            chunk_hash: &ranked.chunk_hash,
            embedding_version_id: ranked.embedding_version_id,
            requester_pubkey: &allowed_user,
            authorized_channel_ids: &[],
        },
    )
    .await
    .is_err());
    sqlx::query(
        "UPDATE source_chunks SET start_char=0, end_char=28 \
         WHERE community_id=$1 AND id=$2",
    )
    .bind(community_a.as_uuid())
    .bind(ranked.chunk_id)
    .execute(&pool)
    .await
    .expect("restore source chunk offsets");

    let denied = search_source_chunks(
        &pool,
        community_a,
        SourceSearchRequest {
            query: "needle",
            embedding_version_id: embedding_version,
            requester_pubkey: &denied_user,
            authorized_channel_ids: &[],
            limit: 10,
        },
    )
    .await
    .expect("search denied source chunks");
    assert!(
        denied.is_empty(),
        "positive ACLs must prevent search leakage"
    );
    let forged_channel = search_source_chunks(
        &pool,
        community_a,
        SourceSearchRequest {
            query: "needle",
            embedding_version_id: embedding_version,
            requester_pubkey: &denied_user,
            authorized_channel_ids: &[channel_a],
            limit: 10,
        },
    )
    .await
    .expect("search with forged authorized-channel UUID");
    assert!(
        forged_channel.is_empty(),
        "a supplied channel UUID cannot replace current tenant membership"
    );
    assert!(search_source_chunks_by_embedding(
        &pool,
        community_a,
        SourceVectorSearchRequest {
            embedding: &embedding,
            embedding_version_id: embedding_version,
            requester_pubkey: &denied_user,
            authorized_channel_ids: &[channel_a],
            limit: 10,
        },
    )
    .await
    .expect("vector search with forged channel UUID")
    .is_empty());
    sqlx::query("INSERT INTO users (community_id, pubkey) VALUES ($1, $2)")
        .bind(community_a.as_uuid())
        .bind(&denied_user)
        .execute(&pool)
        .await
        .expect("insert channel ACL requester");
    sqlx::query(
        "INSERT INTO channel_members (community_id, channel_id, pubkey, role) \
         VALUES ($1, $2, $3, 'member')",
    )
    .bind(community_a.as_uuid())
    .bind(channel_a)
    .bind(&denied_user)
    .execute(&pool)
    .await
    .expect("grant current channel membership");
    assert_eq!(
        search_source_chunks(
            &pool,
            community_a,
            SourceSearchRequest {
                query: "needle",
                embedding_version_id: embedding_version,
                requester_pubkey: &denied_user,
                authorized_channel_ids: &[channel_a],
                limit: 10,
            },
        )
        .await
        .expect("search current channel member")
        .len(),
        1
    );
    assert_eq!(
        search_source_chunks_by_embedding(
            &pool,
            community_a,
            SourceVectorSearchRequest {
                embedding: &embedding,
                embedding_version_id: embedding_version,
                requester_pubkey: &denied_user,
                authorized_channel_ids: &[channel_a],
                limit: 10,
            },
        )
        .await
        .expect("vector search current channel member")
        .len(),
        1
    );
    sqlx::query(
        "UPDATE embedding_versions SET status='retired', retired_at=NOW() \
         WHERE community_id=$1 AND id=$2",
    )
    .bind(community_a.as_uuid())
    .bind(embedding_version)
    .execute(&pool)
    .await
    .expect("retire embedding version");
    assert!(search_source_chunks_by_embedding(
        &pool,
        community_a,
        SourceVectorSearchRequest {
            embedding: &embedding,
            embedding_version_id: embedding_version,
            requester_pubkey: &denied_user,
            authorized_channel_ids: &[channel_a],
            limit: 10,
        },
    )
    .await
    .expect("vector search retired model version")
    .is_empty());
    assert!(search_source_chunks(
        &pool,
        community_a,
        SourceSearchRequest {
            query: "needle",
            embedding_version_id: embedding_version,
            requester_pubkey: &allowed_user,
            authorized_channel_ids: &[],
            limit: 10,
        },
    )
    .await
    .expect("full-text search retired model version")
    .is_empty());
    assert!(recheck_source_chunk(
        &pool,
        community_a,
        SourceCandidateRecheckRequest {
            item_id: ranked.item_id,
            chunk_id: ranked.chunk_id,
            remote_version: &ranked.remote_version,
            remote_etag: ranked.remote_etag.as_deref(),
            chunk_hash: &ranked.chunk_hash,
            embedding_version_id: ranked.embedding_version_id,
            requester_pubkey: &allowed_user,
            authorized_channel_ids: &[],
        },
    )
    .await
    .expect("post-rank retired model recheck")
    .is_none());
    sqlx::query(
        "UPDATE embedding_versions \
         SET status='building', activated_at=NULL, retired_at=NULL \
         WHERE community_id=$1 AND id=$2",
    )
    .bind(community_a.as_uuid())
    .bind(embedding_version)
    .execute(&pool)
    .await
    .expect("mark embedding version building");
    assert!(search_source_chunks(
        &pool,
        community_a,
        SourceSearchRequest {
            query: "needle",
            embedding_version_id: embedding_version,
            requester_pubkey: &allowed_user,
            authorized_channel_ids: &[],
            limit: 10,
        },
    )
    .await
    .expect("full-text search building model version")
    .is_empty());
    sqlx::query(
        "UPDATE embedding_versions SET status='active', activated_at=NOW(), retired_at=NULL \
         WHERE community_id=$1 AND id=$2",
    )
    .bind(community_a.as_uuid())
    .bind(embedding_version)
    .execute(&pool)
    .await
    .expect("restore active embedding version");
    assert!(
        search_source_chunks(
            &pool,
            community_a,
            SourceSearchRequest {
                query: "needle",
                embedding_version_id: embedding_version,
                requester_pubkey: &denied_user,
                authorized_channel_ids: &[],
                limit: 10,
            },
        )
        .await
        .expect("search member outside supplied audience")
        .is_empty(),
        "membership must not expand beyond the supplied audience subset"
    );
    sqlx::query(
        "UPDATE channel_members SET removed_at=NOW() \
         WHERE community_id=$1 AND channel_id=$2 AND pubkey=$3",
    )
    .bind(community_a.as_uuid())
    .bind(channel_a)
    .bind(&denied_user)
    .execute(&pool)
    .await
    .expect("remove channel ACL requester");
    assert!(
        search_source_chunks(
            &pool,
            community_a,
            SourceSearchRequest {
                query: "needle",
                embedding_version_id: embedding_version,
                requester_pubkey: &denied_user,
                authorized_channel_ids: &[channel_a],
                limit: 10,
            },
        )
        .await
        .expect("search removed channel member")
        .is_empty(),
        "retained removed membership must not authorize search"
    );
    assert!(search_source_chunks_by_embedding(
        &pool,
        community_a,
        SourceVectorSearchRequest {
            embedding: &embedding,
            embedding_version_id: embedding_version,
            requester_pubkey: &denied_user,
            authorized_channel_ids: &[channel_a],
            limit: 10,
        },
    )
    .await
    .expect("vector search removed channel member")
    .is_empty());
    assert!(recheck_source_chunk(
        &pool,
        community_a,
        SourceCandidateRecheckRequest {
            item_id: ranked.item_id,
            chunk_id: ranked.chunk_id,
            remote_version: &ranked.remote_version,
            remote_etag: ranked.remote_etag.as_deref(),
            chunk_hash: &ranked.chunk_hash,
            embedding_version_id: ranked.embedding_version_id,
            requester_pubkey: &denied_user,
            authorized_channel_ids: &[channel_a],
        },
    )
    .await
    .expect("removed channel member post-rank recheck")
    .is_none());

    sqlx::query("UPDATE source_items SET tombstoned_at=NOW() WHERE community_id=$1 AND id=$2")
        .bind(community_a.as_uuid())
        .bind(shared_item_id)
        .execute(&pool)
        .await
        .expect("tombstone source");
    assert!(search_source_chunks(
        &pool,
        community_a,
        SourceSearchRequest {
            query: "needle",
            embedding_version_id: embedding_version,
            requester_pubkey: &allowed_user,
            authorized_channel_ids: &[],
            limit: 10,
        },
    )
    .await
    .expect("search tombstoned source")
    .is_empty());
    assert!(recheck_source_chunk(
        &pool,
        community_a,
        SourceCandidateRecheckRequest {
            item_id: ranked.item_id,
            chunk_id: ranked.chunk_id,
            remote_version: &ranked.remote_version,
            remote_etag: ranked.remote_etag.as_deref(),
            chunk_hash: &ranked.chunk_hash,
            embedding_version_id: ranked.embedding_version_id,
            requester_pubkey: &allowed_user,
            authorized_channel_ids: &[],
        },
    )
    .await
    .expect("tombstoned post-rank recheck")
    .is_none());

    sqlx::query("UPDATE source_items SET tombstoned_at=NULL WHERE community_id=$1 AND id=$2")
        .bind(community_a.as_uuid())
        .bind(shared_item_id)
        .execute(&pool)
        .await
        .expect("restore source for revocation check");
    sqlx::query(
        "UPDATE approved_source_scopes SET status='revoked', revoked_at=NOW() WHERE community_id=$1 AND id=$2",
    )
        .bind(community_a.as_uuid())
        .bind(scope_a)
        .execute(&pool)
        .await
        .expect("revoke source scope");
    let purged_projection: (i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM source_chunks WHERE community_id=$1 AND item_id=$2), \
           (SELECT count(*) FROM source_item_acls WHERE community_id=$1 AND item_id=$2)",
    )
    .bind(community_a.as_uuid())
    .bind(shared_item_id)
    .fetch_one(&pool)
    .await
    .expect("inspect physical scope-revocation purge");
    assert_eq!(purged_projection, (0, 0));
    assert!(search_source_chunks(
        &pool,
        community_a,
        SourceSearchRequest {
            query: "needle",
            embedding_version_id: embedding_version,
            requester_pubkey: &allowed_user,
            authorized_channel_ids: &[],
            limit: 10,
        },
    )
    .await
    .expect("search revoked scope")
    .is_empty());
    assert!(recheck_source_chunk(
        &pool,
        community_a,
        SourceCandidateRecheckRequest {
            item_id: ranked.item_id,
            chunk_id: ranked.chunk_id,
            remote_version: &ranked.remote_version,
            remote_etag: ranked.remote_etag.as_deref(),
            chunk_hash: &ranked.chunk_hash,
            embedding_version_id: ranked.embedding_version_id,
            requester_pubkey: &allowed_user,
            authorized_channel_ids: &[],
        },
    )
    .await
    .expect("revoked-scope post-rank recheck")
    .is_none());
    sqlx::query(
        "UPDATE approved_source_scopes SET status='active', revoked_at=NULL \
         WHERE community_id=$1 AND id=$2",
    )
    .bind(community_a.as_uuid())
    .bind(scope_a)
    .execute(&pool)
    .await
    .expect("restore source scope");
    sqlx::query(
        "UPDATE source_items SET status='active', tombstoned_at=NULL \
         WHERE community_id=$1 AND id=$2",
    )
    .bind(community_a.as_uuid())
    .bind(shared_item_id)
    .execute(&pool)
    .await
    .expect("prepare account-revocation purge fixture");
    let account_purge_chunk = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO source_chunks \
         (community_id, id, item_id, chunk_index, start_char, end_char, content, content_hash) \
         VALUES ($1, $2, $3, 0, 0, 28, 'needle confidential evidence', $4)",
    )
    .bind(community_a.as_uuid())
    .bind(account_purge_chunk)
    .bind(shared_item_id)
    .bind(source_chunk_hash(0, 0, 28, "needle confidential evidence").to_vec())
    .execute(&pool)
    .await
    .expect("reindex source before account revocation");
    sqlx::query(
        "INSERT INTO source_item_acls \
         (community_id, id, item_id, principal_type, principal_pubkey) \
         VALUES ($1, $2, $3, 'user', $4)",
    )
    .bind(community_a.as_uuid())
    .bind(Uuid::new_v4())
    .bind(shared_item_id)
    .bind(&allowed_user)
    .execute(&pool)
    .await
    .expect("restore ACL before account revocation");
    let account_a = ranked.account_id;
    sqlx::query(
        "UPDATE connector_accounts SET status='revoked', revoked_at=NOW() \
         WHERE community_id=$1 AND id=$2",
    )
    .bind(community_a.as_uuid())
    .bind(account_a)
    .execute(&pool)
    .await
    .expect("revoke connector account after ranking");
    assert!(recheck_source_chunk(
        &pool,
        community_a,
        SourceCandidateRecheckRequest {
            item_id: ranked.item_id,
            chunk_id: ranked.chunk_id,
            remote_version: &ranked.remote_version,
            remote_etag: ranked.remote_etag.as_deref(),
            chunk_hash: &ranked.chunk_hash,
            embedding_version_id: ranked.embedding_version_id,
            requester_pubkey: &allowed_user,
            authorized_channel_ids: &[],
        },
    )
    .await
    .expect("revoked-account post-rank recheck")
    .is_none());
    let account_purged: (i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM source_chunks WHERE community_id=$1 AND item_id=$2), \
           (SELECT count(*) FROM source_item_acls WHERE community_id=$1 AND item_id=$2)",
    )
    .bind(community_a.as_uuid())
    .bind(shared_item_id)
    .fetch_one(&pool)
    .await
    .expect("inspect physical account-revocation purge");
    assert_eq!(account_purged, (0, 0));

    drop_scratch_db(&admin, pool, &name).await;
}

#[tokio::test]
#[ignore = "requires Postgres with pgvector"]
async fn concurrent_insight_claims_cap_at_ten_and_dedupe_without_visible_rejections() {
    let (admin, pool, name) = scratch_db().await;
    let (community, channel_id) = seed_community(&pool, "insights").await;
    let owner = vec![4_u8; 32];
    let local_date: NaiveDate = sqlx::query_scalar(
        "SELECT (transaction_timestamp() AT TIME ZONE 'America/New_York')::date",
    )
    .fetch_one(&pool)
    .await
    .expect("derive current New York budget date");
    let boundary_dates: (NaiveDate, NaiveDate) = sqlx::query_as(
        "SELECT (TIMESTAMPTZ '2026-03-08 04:59:59+00' AT TIME ZONE 'America/New_York')::date, \
                (TIMESTAMPTZ '2026-03-08 05:00:00+00' AT TIME ZONE 'America/New_York')::date",
    )
    .fetch_one(&pool)
    .await
    .expect("evaluate New York DST date boundary");
    assert_eq!(
        boundary_dates,
        (
            NaiveDate::from_ymd_opt(2026, 3, 7).expect("valid date"),
            NaiveDate::from_ymd_opt(2026, 3, 8).expect("valid date")
        )
    );
    let rejected_insight = NewAssistantInsight {
        owner_pubkey: &owner,
        channel_id,
        dedupe_key: &[250_u8; 32],
        priority: InsightPriority::Low,
        evidence_hash: &[251_u8; 32],
        evidence_count: 1,
        expires_at: None,
    };
    assert!(
        claim_insight_slot(&pool, community, rejected_insight)
            .await
            .is_err(),
        "an open channel must reject private insight projection"
    );
    sqlx::query("UPDATE channels SET visibility='private' WHERE community_id=$1 AND id=$2")
        .bind(community.as_uuid())
        .bind(channel_id)
        .execute(&pool)
        .await
        .expect("make insight channel private");
    assert!(
        claim_insight_slot(&pool, community, rejected_insight)
            .await
            .is_err(),
        "a nonmember owner must reject private insight projection"
    );
    sqlx::query(
        "INSERT INTO channel_members (community_id, channel_id, pubkey, role) \
         VALUES ($1, $2, $3, 'owner')",
    )
    .bind(community.as_uuid())
    .bind(channel_id)
    .bind(&owner)
    .execute(&pool)
    .await
    .expect("authorize private insight owner");
    sqlx::query(
        "UPDATE channel_members SET removed_at=NOW() \
         WHERE community_id=$1 AND channel_id=$2 AND pubkey=$3",
    )
    .bind(community.as_uuid())
    .bind(channel_id)
    .bind(&owner)
    .execute(&pool)
    .await
    .expect("remove private insight owner");
    assert!(
        claim_insight_slot(&pool, community, rejected_insight)
            .await
            .is_err(),
        "a retained removed membership must not authorize feed insertion"
    );
    sqlx::query(
        "UPDATE channel_members SET removed_at=NULL \
         WHERE community_id=$1 AND channel_id=$2 AND pubkey=$3",
    )
    .bind(community.as_uuid())
    .bind(channel_id)
    .bind(&owner)
    .execute(&pool)
    .await
    .expect("restore private insight owner");
    sqlx::query(
        "INSERT INTO insight_daily_budgets (community_id, owner_pubkey, new_york_date) \
         VALUES ($1, $2, $3)",
    )
    .bind(community.as_uuid())
    .bind(&owner)
    .bind(local_date)
    .execute(&pool)
    .await
    .expect("seed insight budget for priority rejection");
    let invalid_priority = sqlx::query(
        "INSERT INTO assistant_insights \
         (community_id, owner_pubkey, channel_id, new_york_date, dedupe_key, priority, evidence_hash, evidence_count) \
         VALUES ($1, $2, $3, $4, $5, 4, $6, 1)",
    )
    .bind(community.as_uuid())
    .bind(&owner)
    .bind(channel_id)
    .bind(local_date)
    .bind(vec![248_u8; 32])
    .bind(vec![249_u8; 32])
    .execute(&pool)
    .await;
    assert!(
        invalid_priority.is_err(),
        "priority tiers outside 0..3 persisted"
    );
    let mut tasks = Vec::new();
    for marker in 0_u8..20 {
        let pool = pool.clone();
        let owner = owner.clone();
        tasks.push(tokio::spawn(async move {
            let outcome = claim_insight_slot(
                &pool,
                community,
                NewAssistantInsight {
                    owner_pubkey: &owner,
                    channel_id,
                    dedupe_key: &[marker; 32],
                    priority: match marker % 4 {
                        0 => InsightPriority::Low,
                        1 => InsightPriority::Normal,
                        2 => InsightPriority::High,
                        _ => InsightPriority::Urgent,
                    },
                    evidence_hash: &[marker.saturating_add(32); 32],
                    evidence_count: 1,
                    expires_at: None,
                },
            )
            .await;
            (marker, outcome)
        }));
    }
    let mut claimed = 0;
    let mut claimed_marker = None;
    for task in tasks {
        let (marker, outcome) = task.await.expect("join claim task");
        if matches!(
            outcome.expect("claim slot"),
            InsightClaimOutcome::Claimed(_)
        ) {
            claimed += 1;
            claimed_marker.get_or_insert(marker);
        }
    }
    assert_eq!(claimed, 10);
    let claimed_marker = claimed_marker.expect("at least one insight was claimed");

    let duplicate = claim_insight_slot(
        &pool,
        community,
        NewAssistantInsight {
            owner_pubkey: &owner,
            channel_id,
            dedupe_key: &[claimed_marker; 32],
            priority: InsightPriority::Low,
            evidence_hash: &[claimed_marker.saturating_add(32); 32],
            evidence_count: 1,
            expires_at: None,
        },
    )
    .await
    .expect("duplicate claim");
    assert_eq!(duplicate, InsightClaimOutcome::Duplicate);
    let visible: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM assistant_insights WHERE community_id=$1 AND owner_pubkey=$2 AND new_york_date=$3",
    )
    .bind(community.as_uuid())
    .bind(&owner)
    .bind(local_date)
    .fetch_one(&pool)
    .await
    .expect("count visible insights");
    assert_eq!(visible, 10);

    drop_scratch_db(&admin, pool, &name).await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn learning_domains_reject_policy_and_unknown_values() {
    let (admin, pool, name) = scratch_db().await;
    let (community, _) = seed_community(&pool, "learning-domains").await;
    for (version, domain) in [(1_i32, "permissions"), (2_i32, "unknown")] {
        let result = sqlx::query(
            "INSERT INTO learning_revisions \
             (community_id, layer, domain, version, encrypted_bundle, bundle_integrity_hash, \
              encryption_key_version, base_policy_version) \
             VALUES ($1, 'sanitized_firm', $2, $3, $4, $5, 1, 'policy-v1')",
        )
        .bind(community.as_uuid())
        .bind(domain)
        .bind(version)
        .bind(vec![1_u8])
        .bind(vec![2_u8; 32])
        .execute(&pool)
        .await;
        assert!(
            result.is_err(),
            "forbidden learning domain {domain} persisted"
        );
    }
    drop_scratch_db(&admin, pool, &name).await;
}

#[tokio::test]
#[ignore = "requires Postgres with pgvector"]
async fn action_claims_execute_once_and_timeout_enters_reconciliation() {
    let (admin, pool, name) = scratch_db().await;
    let (community, channel_id) = seed_community(&pool, "actions").await;
    let account_id = Uuid::new_v4();
    let scope_id = Uuid::new_v4();
    let google_account_id = Uuid::new_v4();
    let google_scope_id = Uuid::new_v4();
    let proposal_id = Uuid::new_v4();
    let owner_keys = Keys::generate();
    let broker_keys = Keys::generate();
    let signer = owner_keys.public_key().to_bytes().to_vec();
    let broker = broker_keys.public_key().to_bytes().to_vec();
    let third_member = vec![9_u8; 32];
    for pubkey in [&signer, &broker] {
        sqlx::query("INSERT INTO users (community_id, pubkey) VALUES ($1, $2)")
            .bind(community.as_uuid())
            .bind(pubkey)
            .execute(&pool)
            .await
            .expect("insert signed action identity");
    }
    sqlx::query("INSERT INTO users (community_id, pubkey) VALUES ($1, $2)")
        .bind(community.as_uuid())
        .bind(&third_member)
        .execute(&pool)
        .await
        .expect("insert unauthorized third action-channel member");
    sqlx::query("UPDATE users SET agent_owner_pubkey=$3 WHERE community_id=$1 AND pubkey=$2")
        .bind(community.as_uuid())
        .bind(&broker)
        .bind(&signer)
        .execute(&pool)
        .await
        .expect("bind broker agent to owner");
    sqlx::query(
        "INSERT INTO connector_accounts \
         (community_id, id, provider, owner_pubkey, external_account_id, credential_reference) \
         VALUES ($1, $2, 'microsoft_graph', $3, $4, $5)",
    )
    .bind(community.as_uuid())
    .bind(account_id)
    .bind(&signer)
    .bind(format!("account-{account_id}"))
    .bind(format!("kv-account-{account_id}"))
    .execute(&pool)
    .await
    .expect("insert action account");
    sqlx::query(
        "INSERT INTO connector_accounts \
         (community_id, id, provider, owner_pubkey, external_account_id, credential_reference) \
         VALUES ($1, $2, 'google_drive', $3, $4, $5)",
    )
    .bind(community.as_uuid())
    .bind(google_account_id)
    .bind(&signer)
    .bind(format!("account-{google_account_id}"))
    .bind(format!("kv-account-{google_account_id}"))
    .execute(&pool)
    .await
    .expect("insert cross-provider action account");
    sqlx::query(
        "INSERT INTO approved_source_scopes \
         (community_id, id, account_id, external_scope_id, scope_type, can_read, can_write) \
         VALUES ($1, $2, $3, $4, 'mailbox', true, true)",
    )
    .bind(community.as_uuid())
    .bind(scope_id)
    .bind(account_id)
    .bind(format!("scope-{scope_id}"))
    .execute(&pool)
    .await
    .expect("insert approved action scope");
    sqlx::query(
        "INSERT INTO approved_source_scopes \
         (community_id, id, account_id, external_scope_id, scope_type, can_read, can_write) \
         VALUES ($1, $2, $3, $4, 'drive_folder', true, true)",
    )
    .bind(community.as_uuid())
    .bind(google_scope_id)
    .bind(google_account_id)
    .bind(format!("scope-{google_scope_id}"))
    .execute(&pool)
    .await
    .expect("insert cross-provider action scope");
    sqlx::query("UPDATE channels SET visibility='private' WHERE community_id=$1 AND id=$2")
        .bind(community.as_uuid())
        .bind(channel_id)
        .execute(&pool)
        .await
        .expect("make action channel private");
    sqlx::query(
        "INSERT INTO channel_members (community_id, channel_id, pubkey, role) \
         VALUES ($1, $2, $3, 'owner')",
    )
    .bind(community.as_uuid())
    .bind(channel_id)
    .bind(&signer)
    .execute(&pool)
    .await
    .expect("authorize action owner in private channel");
    sqlx::query(
        "INSERT INTO channel_members (community_id, channel_id, pubkey, role) \
         VALUES ($1, $2, $3, 'member')",
    )
    .bind(community.as_uuid())
    .bind(channel_id)
    .bind(&broker)
    .execute(&pool)
    .await
    .expect("authorize action broker in private channel");
    let member_idempotency_keys = [Uuid::new_v4(), Uuid::new_v4()];
    let operation_ids = [Uuid::new_v4(), Uuid::new_v4()];
    let proposed_at = Utc::now() - Duration::seconds(1);
    let mut new_proposal = NewExternalActionProposal {
        id: proposal_id,
        owner_pubkey: signer.clone(),
        broker_pubkey: broker.clone(),
        channel_id,
        canonical_proposal: br#"{"action":"cross-provider"}"#.to_vec(),
        operation_hash: vec![3_u8; 32],
        ordered_members_hash: vec![4_u8; 32],
        nonce: Uuid::new_v4(),
        proposed_at,
        expires_at: proposed_at + Duration::minutes(5),
        items: vec![
            NewExternalActionProposalItem {
                operation_id: operation_ids[0],
                account_id,
                scope_id,
                connector: ExternalConnector::MicrosoftGraph,
                operation: ExternalOperation::OutlookCreateDraft,
                target_hash: vec![15_u8; 32],
                canonical_operation: br#"{"to":"counterparty@example.invalid"}"#.to_vec(),
                canonical_operation_hash: vec![5_u8; 32],
                before_hash: None,
                after_hash: vec![35_u8; 32],
                expected_remote_version: None,
                idempotency_key: member_idempotency_keys[0],
                member_hash: vec![45_u8; 32],
            },
            NewExternalActionProposalItem {
                operation_id: operation_ids[1],
                account_id: google_account_id,
                scope_id: google_scope_id,
                connector: ExternalConnector::GoogleDrive,
                operation: ExternalOperation::GoogleEditDoc,
                target_hash: vec![16_u8; 32],
                canonical_operation: br#"{"document":"document-1"}"#.to_vec(),
                canonical_operation_hash: vec![6_u8; 32],
                before_hash: Some(vec![26_u8; 32]),
                after_hash: vec![36_u8; 32],
                expected_remote_version: Some("etag-1".into()),
                idempotency_key: member_idempotency_keys[1],
                member_hash: vec![46_u8; 32],
            },
        ],
    };
    new_proposal.operation_hash = action_operation_hash(&new_proposal.canonical_proposal).to_vec();
    let mut member_hashes = Vec::new();
    for item in &mut new_proposal.items {
        item.canonical_operation_hash =
            action_member_operation_hash(&item.canonical_operation).to_vec();
        let member_hash = action_member_hash(ActionMemberHashInput {
            account_id: item.account_id,
            scope_id: item.scope_id,
            operation_id: item.operation_id,
            owner_pubkey: &new_proposal.owner_pubkey,
            connector: item.connector,
            operation: item.operation,
            target_hash: &item.target_hash,
            before_hash: item.before_hash.as_deref(),
            after_hash: &item.after_hash,
            expected_remote_version: item.expected_remote_version.as_deref(),
            idempotency_key: item.idempotency_key,
            canonical_operation_hash: &item.canonical_operation_hash,
        });
        item.member_hash = member_hash.to_vec();
        member_hashes.push(member_hash);
    }
    new_proposal.ordered_members_hash = action_ordered_members_hash(&member_hashes).to_vec();
    sqlx::query(
        "INSERT INTO channel_members (community_id, channel_id, pubkey, role) \
         VALUES ($1, $2, $3, 'member')",
    )
    .bind(community.as_uuid())
    .bind(channel_id)
    .bind(&third_member)
    .execute(&pool)
    .await
    .expect("add unauthorized third action-channel member");
    let mut three_member_proposal = new_proposal.clone();
    three_member_proposal.id = Uuid::new_v4();
    three_member_proposal.nonce = Uuid::new_v4();
    assert!(
        insert_action_proposal(
            &pool,
            community,
            &three_member_proposal,
            &verified_proposal(&three_member_proposal, &broker_keys),
        )
        .await
        .is_err(),
        "a private action channel with a third current member must reject proposal insertion"
    );
    sqlx::query(
        "UPDATE channel_members SET removed_at=NOW() \
         WHERE community_id=$1 AND channel_id=$2 AND pubkey=$3",
    )
    .bind(community.as_uuid())
    .bind(channel_id)
    .bind(&third_member)
    .execute(&pool)
    .await
    .expect("remove unauthorized third action-channel member");
    let mut mutated_operation_id = new_proposal.clone();
    mutated_operation_id.id = Uuid::new_v4();
    mutated_operation_id.nonce = Uuid::new_v4();
    mutated_operation_id.items[0].operation_id = Uuid::new_v4();
    assert!(
        insert_action_proposal(
            &pool,
            community,
            &mutated_operation_id,
            &verified_proposal(&mutated_operation_id, &broker_keys),
        )
        .await
        .is_err(),
        "operation_id mutation without new member hashes must reject insertion"
    );
    let mut duplicate_operation_id = new_proposal.clone();
    duplicate_operation_id.id = Uuid::new_v4();
    duplicate_operation_id.nonce = Uuid::new_v4();
    duplicate_operation_id.items[1].operation_id = duplicate_operation_id.items[0].operation_id;
    assert!(
        insert_action_proposal(
            &pool,
            community,
            &duplicate_operation_id,
            &verified_proposal(&duplicate_operation_id, &broker_keys),
        )
        .await
        .is_err(),
        "duplicate operation_id must reject the whole proposal"
    );
    let mut wrong_proposal_hash = new_proposal.clone();
    wrong_proposal_hash.id = Uuid::new_v4();
    wrong_proposal_hash.nonce = Uuid::new_v4();
    wrong_proposal_hash.canonical_proposal.push(b' ');
    assert!(
        insert_action_proposal(
            &pool,
            community,
            &wrong_proposal_hash,
            &verified_proposal(&wrong_proposal_hash, &broker_keys),
        )
        .await
        .is_err(),
        "canonical proposal mutation without a new frozen hash must reject insertion"
    );
    let mut oversized_proposal = new_proposal.clone();
    oversized_proposal.id = Uuid::new_v4();
    oversized_proposal.nonce = Uuid::new_v4();
    oversized_proposal.canonical_proposal = vec![b'x'; 65_536];
    oversized_proposal.operation_hash =
        action_operation_hash(&oversized_proposal.canonical_proposal).to_vec();
    assert!(
        insert_action_proposal(
            &pool,
            community,
            &oversized_proposal,
            &verified_proposal(&oversized_proposal, &broker_keys),
        )
        .await
        .is_err(),
        "oversized canonical proposal must reject insertion"
    );
    let mut oversized_member = new_proposal.clone();
    oversized_member.id = Uuid::new_v4();
    oversized_member.nonce = Uuid::new_v4();
    oversized_member.items[0].canonical_operation = vec![b'x'; 65_536];
    oversized_member.items[0].canonical_operation_hash =
        action_member_operation_hash(&oversized_member.items[0].canonical_operation).to_vec();
    assert!(
        insert_action_proposal(
            &pool,
            community,
            &oversized_member,
            &verified_proposal(&oversized_member, &broker_keys),
        )
        .await
        .is_err(),
        "oversized member canonical operation must reject insertion"
    );
    sqlx::query(
        "UPDATE channel_members SET removed_at=NOW() \
         WHERE community_id=$1 AND channel_id=$2 AND pubkey=$3",
    )
    .bind(community.as_uuid())
    .bind(channel_id)
    .bind(&broker)
    .execute(&pool)
    .await
    .expect("remove action broker");
    let mut removed_broker = new_proposal.clone();
    removed_broker.id = Uuid::new_v4();
    removed_broker.nonce = Uuid::new_v4();
    assert!(
        insert_action_proposal(
            &pool,
            community,
            &removed_broker,
            &verified_proposal(&removed_broker, &broker_keys),
        )
        .await
        .is_err(),
        "removed broker membership must not authorize proposal insertion"
    );
    sqlx::query(
        "UPDATE channel_members SET removed_at=NULL \
         WHERE community_id=$1 AND channel_id=$2 AND pubkey=$3",
    )
    .bind(community.as_uuid())
    .bind(channel_id)
    .bind(&broker)
    .execute(&pool)
    .await
    .expect("restore action broker membership");
    let mut invalid_create = new_proposal.clone();
    invalid_create.id = Uuid::new_v4();
    invalid_create.nonce = Uuid::new_v4();
    invalid_create.items.truncate(1);
    invalid_create.items[0].before_hash = Some(vec![99_u8; 32]);
    assert!(
        insert_action_proposal(
            &pool,
            community,
            &invalid_create,
            &verified_proposal(&invalid_create, &broker_keys),
        )
        .await
        .is_err(),
        "create members must reject before-state preconditions"
    );
    let mut invalid_update = new_proposal.clone();
    invalid_update.id = Uuid::new_v4();
    invalid_update.nonce = Uuid::new_v4();
    invalid_update.items.remove(0);
    invalid_update.items[0].before_hash = None;
    invalid_update.items[0].expected_remote_version = None;
    assert!(
        insert_action_proposal(
            &pool,
            community,
            &invalid_update,
            &verified_proposal(&invalid_update, &broker_keys),
        )
        .await
        .is_err(),
        "non-create members must require before state and a remote version"
    );
    let mut replayed_proposal = new_proposal.clone();
    replayed_proposal.id = Uuid::new_v4();
    replayed_proposal.nonce = Uuid::new_v4();
    replayed_proposal.proposed_at = Utc::now() - Duration::minutes(20);
    replayed_proposal.expires_at = replayed_proposal.proposed_at + Duration::minutes(5);
    assert!(
        insert_action_proposal(
            &pool,
            community,
            &replayed_proposal,
            &verified_proposal(&replayed_proposal, &broker_keys),
        )
        .await
        .is_err(),
        "a replayed canonical proposal must not receive a fresh DB insertion window"
    );
    let mut extreme_timestamp = new_proposal.clone();
    extreme_timestamp.id = Uuid::new_v4();
    extreme_timestamp.nonce = Uuid::new_v4();
    extreme_timestamp.proposed_at = chrono::DateTime::<Utc>::MAX_UTC - Duration::minutes(1);
    extreme_timestamp.expires_at = chrono::DateTime::<Utc>::MAX_UTC;
    assert!(
        insert_action_proposal(
            &pool,
            community,
            &extreme_timestamp,
            &verified_proposal(&extreme_timestamp, &broker_keys),
        )
        .await
        .is_err(),
        "extreme timestamps must return an error rather than panic"
    );
    let mut wrong_operation_hash = new_proposal.clone();
    wrong_operation_hash.id = Uuid::new_v4();
    wrong_operation_hash.nonce = Uuid::new_v4();
    wrong_operation_hash.items[0].canonical_operation_hash[0] ^= 0xff;
    assert!(
        insert_action_proposal(
            &pool,
            community,
            &wrong_operation_hash,
            &verified_proposal(&wrong_operation_hash, &broker_keys),
        )
        .await
        .is_err(),
        "operation hash mismatch must reject the whole bundle"
    );
    let mut spliced_member = new_proposal.clone();
    spliced_member.id = Uuid::new_v4();
    spliced_member.nonce = Uuid::new_v4();
    spliced_member.items[1].target_hash[0] ^= 0xff;
    assert!(
        insert_action_proposal(
            &pool,
            community,
            &spliced_member,
            &verified_proposal(&spliced_member, &broker_keys),
        )
        .await
        .is_err(),
        "a field spliced into a member must reject the whole bundle"
    );
    let mut wrong_bundle_hash = new_proposal.clone();
    wrong_bundle_hash.id = Uuid::new_v4();
    wrong_bundle_hash.nonce = Uuid::new_v4();
    wrong_bundle_hash.ordered_members_hash[0] ^= 0xff;
    assert!(
        insert_action_proposal(
            &pool,
            community,
            &wrong_bundle_hash,
            &verified_proposal(&wrong_bundle_hash, &broker_keys),
        )
        .await
        .is_err(),
        "bundle hash mismatch must reject insertion"
    );
    let mut reordered_bundle = new_proposal.clone();
    reordered_bundle.id = Uuid::new_v4();
    reordered_bundle.nonce = Uuid::new_v4();
    reordered_bundle.items.swap(0, 1);
    assert!(
        insert_action_proposal(
            &pool,
            community,
            &reordered_bundle,
            &verified_proposal(&reordered_bundle, &broker_keys),
        )
        .await
        .is_err(),
        "reordering members without a new bundle hash must reject insertion"
    );
    insert_action_proposal(
        &pool,
        community,
        &new_proposal,
        &verified_proposal(&new_proposal, &broker_keys),
    )
    .await
    .expect("insert atomic cross-provider action bundle");
    let stored_count: i16 = sqlx::query_scalar(
        "SELECT member_count FROM external_action_proposals WHERE community_id=$1 AND id=$2",
    )
    .bind(community.as_uuid())
    .bind(proposal_id)
    .fetch_one(&pool)
    .await
    .expect("load derived member count");
    assert_eq!(stored_count, 2);
    let decided_at = Utc::now().timestamp();
    let wrong_broker_keys = Keys::generate();
    let wrong_broker_expectation = DecisionExpectation {
        proposal_id,
        channel_id,
        nonce: new_proposal.nonce,
        operation_hash: new_proposal
            .operation_hash
            .as_slice()
            .try_into()
            .expect("proposal hash"),
        owner_pubkey: owner_keys.public_key().to_bytes(),
        broker_pubkey: wrong_broker_keys.public_key().to_bytes(),
        proposed_at: new_proposal.proposed_at.timestamp(),
        expires_at: new_proposal.expires_at.timestamp(),
    };
    let wrong_broker_decision = verified_approval(
        &owner_keys,
        &wrong_broker_keys,
        &wrong_broker_expectation,
        decided_at,
    );
    assert_eq!(
        record_action_decision(&pool, community, &wrong_broker_decision)
            .await
            .expect("reject mismatched broker decision"),
        ActionDecisionRecordOutcome::Rejected
    );
    let decision_expectation = DecisionExpectation {
        broker_pubkey: broker_keys.public_key().to_bytes(),
        ..wrong_broker_expectation
    };
    let decision = verified_approval(&owner_keys, &broker_keys, &decision_expectation, decided_at);
    sqlx::query(
        "UPDATE channel_members SET removed_at=NULL \
         WHERE community_id=$1 AND channel_id=$2 AND pubkey=$3",
    )
    .bind(community.as_uuid())
    .bind(channel_id)
    .bind(&third_member)
    .execute(&pool)
    .await
    .expect("restore third member before decision authorization check");
    assert_eq!(
        record_action_decision(&pool, community, &decision)
            .await
            .expect("reject decision in a three-member action channel"),
        ActionDecisionRecordOutcome::Rejected
    );
    sqlx::query(
        "UPDATE channel_members SET removed_at=NOW() \
         WHERE community_id=$1 AND channel_id=$2 AND pubkey=$3",
    )
    .bind(community.as_uuid())
    .bind(channel_id)
    .bind(&third_member)
    .execute(&pool)
    .await
    .expect("remove third member before exact decision authorization");
    assert_eq!(
        record_action_decision(&pool, community, &decision)
            .await
            .expect("record exact owner decision"),
        ActionDecisionRecordOutcome::Approved
    );
    let decision_audits: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM core_audit_outbox \
         WHERE community_id=$1 AND entity_id=$2 AND event_type='action_proposal_decided'",
    )
    .bind(community.as_uuid())
    .bind(proposal_id)
    .fetch_one(&pool)
    .await
    .expect("count decision audit");
    assert_eq!(decision_audits, 1);
    sqlx::query(
        "UPDATE channel_members SET removed_at=NULL \
         WHERE community_id=$1 AND channel_id=$2 AND pubkey=$3",
    )
    .bind(community.as_uuid())
    .bind(channel_id)
    .bind(&third_member)
    .execute(&pool)
    .await
    .expect("restore third member after approval");
    assert!(
        claim_action_execution(&pool, community, proposal_id, Uuid::new_v4(), Utc::now())
            .await
            .is_err(),
        "approval must not authorize execution while a third channel member is current"
    );
    sqlx::query(
        "UPDATE channel_members SET removed_at=NOW() \
         WHERE community_id=$1 AND channel_id=$2 AND pubkey=$3",
    )
    .bind(community.as_uuid())
    .bind(channel_id)
    .bind(&third_member)
    .execute(&pool)
    .await
    .expect("remove third member after claim rejection");
    sqlx::query(
        "UPDATE channel_members SET removed_at=NOW() \
         WHERE community_id=$1 AND channel_id=$2 AND pubkey=$3",
    )
    .bind(community.as_uuid())
    .bind(channel_id)
    .bind(&broker)
    .execute(&pool)
    .await
    .expect("remove broker after approval");
    assert!(
        claim_action_execution(&pool, community, proposal_id, Uuid::new_v4(), Utc::now())
            .await
            .is_err(),
        "approval must not survive current private-channel revocation"
    );
    sqlx::query(
        "UPDATE channel_members SET removed_at=NULL \
         WHERE community_id=$1 AND channel_id=$2 AND pubkey=$3",
    )
    .bind(community.as_uuid())
    .bind(channel_id)
    .bind(&broker)
    .execute(&pool)
    .await
    .expect("restore broker after claim rejection");
    sqlx::query("UPDATE users SET agent_owner_pubkey=NULL WHERE community_id=$1 AND pubkey=$2")
        .bind(community.as_uuid())
        .bind(&broker)
        .execute(&pool)
        .await
        .expect("break owner/broker pair after approval");
    assert!(
        claim_action_execution(&pool, community, proposal_id, Uuid::new_v4(), Utc::now())
            .await
            .is_err(),
        "approval must not survive owner/broker pair revocation"
    );
    sqlx::query(
        "UPDATE users SET agent_owner_pubkey=$3 \
         WHERE community_id=$1 AND pubkey=$2",
    )
    .bind(community.as_uuid())
    .bind(&broker)
    .bind(&signer)
    .execute(&pool)
    .await
    .expect("restore owner/broker pair");
    sqlx::query(
        "UPDATE approved_source_scopes SET status='paused' \
         WHERE community_id=$1 AND id=$2",
    )
    .bind(community.as_uuid())
    .bind(google_scope_id)
    .execute(&pool)
    .await
    .expect("pause one member scope");
    assert!(
        claim_action_execution(&pool, community, proposal_id, Uuid::new_v4(), Utc::now())
            .await
            .is_err(),
        "a paused member scope must dispatch zero bundle operations"
    );
    sqlx::query(
        "UPDATE approved_source_scopes SET status='active', can_read=true, can_write=false \
         WHERE community_id=$1 AND id=$2",
    )
    .bind(community.as_uuid())
    .bind(google_scope_id)
    .execute(&pool)
    .await
    .expect("make one member scope read-only");
    assert!(
        claim_action_execution(&pool, community, proposal_id, Uuid::new_v4(), Utc::now())
            .await
            .is_err(),
        "a read-only member scope must dispatch zero bundle operations"
    );
    sqlx::query(
        "UPDATE approved_source_scopes \
         SET status='revoked', revoked_at=NOW(), can_write=true \
         WHERE community_id=$1 AND id=$2",
    )
    .bind(community.as_uuid())
    .bind(google_scope_id)
    .execute(&pool)
    .await
    .expect("revoke one member scope");
    assert!(
        claim_action_execution(&pool, community, proposal_id, Uuid::new_v4(), Utc::now())
            .await
            .is_err(),
        "a revoked member scope must dispatch zero bundle operations"
    );
    let attempts_before_authorization: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM external_action_attempts WHERE community_id=$1 AND proposal_id=$2",
    )
    .bind(community.as_uuid())
    .bind(proposal_id)
    .fetch_one(&pool)
    .await
    .expect("count attempts after authorization rejection");
    assert_eq!(attempts_before_authorization, 0);
    sqlx::query(
        "UPDATE approved_source_scopes SET status='active', revoked_at=NULL, can_write=true \
         WHERE community_id=$1 AND id=$2",
    )
    .bind(community.as_uuid())
    .bind(google_scope_id)
    .execute(&pool)
    .await
    .expect("restore writable member scope");
    sqlx::query("UPDATE connector_accounts SET status='paused' WHERE community_id=$1 AND id=$2")
        .bind(community.as_uuid())
        .bind(google_account_id)
        .execute(&pool)
        .await
        .expect("pause one member account");
    assert!(
        claim_action_execution(&pool, community, proposal_id, Uuid::new_v4(), Utc::now())
            .await
            .is_err(),
        "a paused connector account must dispatch zero bundle operations"
    );
    sqlx::query("UPDATE connector_accounts SET status='active' WHERE community_id=$1 AND id=$2")
        .bind(community.as_uuid())
        .bind(google_account_id)
        .execute(&pool)
        .await
        .expect("restore active member account");

    let now = Utc::now();
    let worker_a = Uuid::new_v4();
    let worker_b = Uuid::new_v4();
    assert!(
        claim_delta_scope(
            &pool,
            community,
            account_id,
            scope_id,
            "items",
            worker_a,
            chrono::DateTime::<Utc>::MAX_UTC,
            StdDuration::from_secs(30),
        )
        .await
        .is_err(),
        "extreme delta lease timestamp must return an error rather than panic"
    );
    let (a, b) = tokio::join!(
        claim_action_execution(&pool, community, proposal_id, worker_a, now),
        claim_action_execution(&pool, community, proposal_id, worker_b, now)
    );
    let claims = [
        a.expect("first action claim"),
        b.expect("second action claim"),
    ];
    assert_eq!(claims.iter().filter(|claim| claim.is_some()).count(), 1);
    let claim = claims.into_iter().flatten().next().expect("one claim");
    let execution_intent_audits: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM core_audit_outbox \
         WHERE community_id=$1 AND entity_id=$2 AND event_type='action_execution' \
           AND outcome='accepted'",
    )
    .bind(community.as_uuid())
    .bind(proposal_id)
    .fetch_one(&pool)
    .await
    .expect("count execution-intent audit");
    assert_eq!(execution_intent_audits, 1);
    assert_eq!(claim.canonical_proposal, new_proposal.canonical_proposal);
    assert_eq!(claim.operation_hash, new_proposal.operation_hash);
    assert_eq!(
        claim.ordered_members_hash,
        new_proposal.ordered_members_hash
    );
    assert_eq!(claim.broker_pubkey, broker);
    assert_eq!(
        claim.proposed_at.timestamp_micros(),
        proposed_at.timestamp_micros()
    );
    assert_eq!(claim.member_count, 2);
    assert_eq!(claim.items.len(), 2);
    assert_eq!(claim.items[0].item_index, 0);
    assert_eq!(claim.items[0].operation_id, operation_ids[0]);
    assert_eq!(claim.items[0].scope_id, scope_id);
    assert_eq!(claim.items[0].idempotency_key, member_idempotency_keys[0]);
    assert_eq!(
        claim.items[0].operation,
        ExternalOperation::OutlookCreateDraft
    );
    assert_eq!(
        claim.items[0].canonical_operation_hash,
        new_proposal.items[0].canonical_operation_hash
    );
    assert!(claim.items[0].expected_remote_version.is_none());
    assert_eq!(claim.items[1].item_index, 1);
    assert_eq!(claim.items[1].operation_id, operation_ids[1]);
    assert_eq!(claim.items[1].scope_id, google_scope_id);
    assert_eq!(claim.items[1].idempotency_key, member_idempotency_keys[1]);
    assert_eq!(claim.items[1].operation, ExternalOperation::GoogleEditDoc);
    assert_eq!(
        claim.items[1].canonical_operation_hash,
        new_proposal.items[1].canonical_operation_hash
    );
    assert_eq!(
        claim.items[1].expected_remote_version.as_deref(),
        Some("etag-1")
    );
    assert_eq!(claim.nonce.get_version_num(), 4);
    let attempts_after_claim: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM external_action_attempts WHERE community_id=$1 AND proposal_id=$2",
    )
    .bind(community.as_uuid())
    .bind(proposal_id)
    .fetch_one(&pool)
    .await
    .expect("count remote attempts after durable claim");
    assert_eq!(
        attempts_after_claim, 0,
        "claim intent must not be misreported as a provider dispatch"
    );
    sqlx::query(
        "UPDATE approved_source_scopes SET can_write=false \
         WHERE community_id=$1 AND id=$2",
    )
    .bind(community.as_uuid())
    .bind(scope_id)
    .execute(&pool)
    .await
    .expect("revoke first member write scope after claim");
    assert!(
        begin_action_remote_attempt(&pool, community, proposal_id, claim.claim_id, 0, Utc::now(),)
            .await
            .expect("fail closed after post-claim scope revocation")
            .is_none(),
        "a stale claim cannot authorize a provider dispatch after scope revocation"
    );
    sqlx::query(
        "UPDATE approved_source_scopes SET can_write=true \
         WHERE community_id=$1 AND id=$2",
    )
    .bind(community.as_uuid())
    .bind(scope_id)
    .execute(&pool)
    .await
    .expect("restore first member write scope");
    sqlx::query(
        "UPDATE channel_members SET removed_at=NULL \
         WHERE community_id=$1 AND channel_id=$2 AND pubkey=$3",
    )
    .bind(community.as_uuid())
    .bind(channel_id)
    .bind(&third_member)
    .execute(&pool)
    .await
    .expect("restore third member after durable claim");
    assert!(
        begin_action_remote_attempt(&pool, community, proposal_id, claim.claim_id, 0, Utc::now())
            .await
            .expect("fail closed when private-pair membership changes after claim")
            .is_none(),
        "a durable claim must not authorize dispatch while a third member is current"
    );
    sqlx::query(
        "UPDATE channel_members SET removed_at=NOW() \
         WHERE community_id=$1 AND channel_id=$2 AND pubkey=$3",
    )
    .bind(community.as_uuid())
    .bind(channel_id)
    .bind(&third_member)
    .execute(&pool)
    .await
    .expect("remove third member before provider dispatch");
    let remote_attempt_0 =
        begin_action_remote_attempt(&pool, community, proposal_id, claim.claim_id, 0, Utc::now())
            .await
            .expect("begin first provider attempt")
            .expect("first member is dispatchable");
    let remote_attempt_1 =
        begin_action_remote_attempt(&pool, community, proposal_id, claim.claim_id, 1, Utc::now())
            .await
            .expect("begin second provider attempt")
            .expect("second member is dispatchable");
    assert!(
        begin_action_remote_attempt(&pool, community, proposal_id, claim.claim_id, 0, Utc::now(),)
            .await
            .expect("reject duplicate provider attempt")
            .is_none(),
        "a provider member must never receive a blind second dispatch"
    );
    let unbound_attempt = sqlx::query(
        "INSERT INTO external_action_attempts \
         (community_id, proposal_id, item_index, claim_id, attempt_number, started_at) \
         VALUES ($1, $2, 0, $3, 2, NOW())",
    )
    .bind(community.as_uuid())
    .bind(proposal_id)
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await;
    assert!(
        unbound_attempt.is_err(),
        "attempt claim_id must match the proposal's one-time claim"
    );
    let missing_member_attempt = sqlx::query(
        "INSERT INTO external_action_attempts \
         (community_id, proposal_id, item_index, claim_id, attempt_number, started_at) \
         VALUES ($1, $2, 49, $3, 2, NOW())",
    )
    .bind(community.as_uuid())
    .bind(proposal_id)
    .bind(claim.claim_id)
    .execute(&pool)
    .await;
    assert!(
        missing_member_attempt.is_err(),
        "an attempt cannot splice in a member absent from the approved bundle"
    );
    let attempt_0 = remote_attempt_0.attempt_id;
    let attempt_1 = remote_attempt_1.attempt_id;
    let spliced_receipt = sqlx::query(
        "INSERT INTO external_action_receipts \
         (community_id, proposal_id, item_index, operation_id, member_hash, attempt_id, remote_result_id, remote_version, outcome) \
         VALUES ($1, $2, 0, $3, $4, $5, 'draft-123', 'etag-2', 'succeeded')",
    )
    .bind(community.as_uuid())
    .bind(proposal_id)
    .bind(claim.items[0].operation_id)
    .bind(&claim.items[0].member_hash)
    .bind(attempt_1)
    .execute(&pool)
    .await;
    assert!(
        spliced_receipt.is_err(),
        "a receipt for one member cannot cite another member's attempt"
    );
    let url_result_id = sqlx::query(
        "INSERT INTO external_action_receipts \
         (community_id, proposal_id, item_index, operation_id, member_hash, attempt_id, remote_result_id, remote_version, outcome) \
         VALUES ($1, $2, 0, $3, $4, $5, 'https://graph.invalid/draft/123', 'etag-2', 'succeeded')",
    )
    .bind(community.as_uuid())
    .bind(proposal_id)
    .bind(claim.items[0].operation_id)
    .bind(&claim.items[0].member_hash)
    .bind(attempt_0)
    .execute(&pool)
    .await;
    assert!(
        url_result_id.is_err(),
        "receipt result IDs must not store URLs"
    );
    assert!(sqlx::query(
        "INSERT INTO external_action_receipts \
         (community_id, proposal_id, item_index, operation_id, member_hash, attempt_id, outcome, reconciliation_state) \
         VALUES ($1, $2, 1, $3, $4, $5, 'failed', 'pending')",
    )
    .bind(community.as_uuid())
    .bind(proposal_id)
    .bind(claim.items[1].operation_id)
    .bind(&claim.items[1].member_hash)
    .bind(attempt_1)
    .execute(&pool)
    .await
    .is_err(), "ordinary outcomes cannot carry a reconciliation workflow state");
    assert!(sqlx::query(
        "INSERT INTO external_action_receipts \
         (community_id, proposal_id, item_index, operation_id, member_hash, attempt_id, outcome, reconciliation_state) \
         VALUES ($1, $2, 1, $3, $4, $5, 'reconciliation_required', 'reconciled')",
    )
    .bind(community.as_uuid())
    .bind(proposal_id)
    .bind(claim.items[1].operation_id)
    .bind(&claim.items[1].member_hash)
    .bind(attempt_1)
    .execute(&pool)
    .await
    .is_err(), "reconciliation_required cannot claim a reconciled protocol status");
    assert!(
        sqlx::query(
            "INSERT INTO external_action_receipts \
             (community_id, proposal_id, item_index, operation_id, member_hash, attempt_id, \
              remote_result_id, remote_version, outcome, reconciliation_state) \
             VALUES ($1, $2, 0, $3, $4, $5, 'draft-reconciled', 'etag-3', \
                     'succeeded', 'reconciled')",
        )
        .bind(community.as_uuid())
        .bind(proposal_id)
        .bind(claim.items[0].operation_id)
        .bind(&claim.items[0].member_hash)
        .bind(attempt_0)
        .execute(&pool)
        .await
        .is_err(),
        "reconciled receipt state must require reconciled_at"
    );
    assert!(
        sqlx::query(
            "INSERT INTO external_action_receipts \
             (community_id, proposal_id, item_index, operation_id, member_hash, attempt_id, \
              outcome, reconciliation_state, reconciled_at) \
             VALUES ($1, $2, 1, $3, $4, $5, 'reconciliation_required', 'pending', NOW())",
        )
        .bind(community.as_uuid())
        .bind(proposal_id)
        .bind(claim.items[1].operation_id)
        .bind(&claim.items[1].member_hash)
        .bind(attempt_1)
        .execute(&pool)
        .await
        .is_err(),
        "pending receipt state must reject reconciled_at"
    );
    sqlx::query(
        "INSERT INTO external_action_receipts \
         (community_id, proposal_id, item_index, operation_id, member_hash, attempt_id, remote_result_id, remote_version, outcome, reconciliation_state) \
         VALUES ($1, $2, 0, $3, $4, $5, 'draft-123', 'etag-2', 'succeeded', 'not_required'), \
                ($1, $2, 1, $6, $7, $8, NULL, NULL, 'reconciliation_required', 'pending')",
    )
    .bind(community.as_uuid())
    .bind(proposal_id)
    .bind(claim.items[0].operation_id)
    .bind(&claim.items[0].member_hash)
    .bind(attempt_0)
    .bind(claim.items[1].operation_id)
    .bind(&claim.items[1].member_hash)
    .bind(attempt_1)
    .execute(&pool)
    .await
    .expect("record honest partial bundle outcomes");
    sqlx::query(
        "UPDATE external_action_receipts \
         SET reconciliation_state='reconciled', reconciled_at=NOW() \
         WHERE community_id=$1 AND proposal_id=$2 AND item_index=0",
    )
    .bind(community.as_uuid())
    .bind(proposal_id)
    .execute(&pool)
    .await
    .expect("record valid succeeded and reconciled receipt");
    sqlx::query(
        "UPDATE external_action_receipts SET reconciliation_state='manual_review' \
         WHERE community_id=$1 AND proposal_id=$2 AND item_index=1",
    )
    .bind(community.as_uuid())
    .bind(proposal_id)
    .execute(&pool)
    .await
    .expect("record valid reconciliation-required manual-review receipt");
    sqlx::query(
        "UPDATE external_action_receipts \
         SET outcome='failed', reconciliation_state='not_required' \
         WHERE community_id=$1 AND proposal_id=$2 AND item_index=1",
    )
    .bind(community.as_uuid())
    .bind(proposal_id)
    .execute(&pool)
    .await
    .expect("record valid failed and not-required receipt");
    let partial_outcomes: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT outcome) FROM external_action_receipts \
         WHERE community_id=$1 AND proposal_id=$2",
    )
    .bind(community.as_uuid())
    .bind(proposal_id)
    .fetch_one(&pool)
    .await
    .expect("count distinct per-member outcomes");
    assert_eq!(partial_outcomes, 2);
    assert!(mark_action_timeout_for_reconciliation(
        &pool,
        community,
        proposal_id,
        claim.claim_id,
        Utc::now(),
    )
    .await
    .expect("mark timeout"));
    assert!(
        claim_action_execution(&pool, community, proposal_id, Uuid::new_v4(), Utc::now())
            .await
            .expect("claim after timeout")
            .is_none(),
        "a timeout must not reopen a blind retry"
    );

    let receipt_proposal_id = Uuid::new_v4();
    let mut receipt_proposal = new_proposal.clone();
    receipt_proposal.id = receipt_proposal_id;
    receipt_proposal.nonce = Uuid::new_v4();
    receipt_proposal.proposed_at = Utc::now() - Duration::seconds(1);
    receipt_proposal.expires_at = receipt_proposal.proposed_at + Duration::minutes(5);
    receipt_proposal.canonical_proposal = br#"{"action":"receipt-outbox"}"#.to_vec();
    receipt_proposal.operation_hash =
        action_operation_hash(&receipt_proposal.canonical_proposal).to_vec();
    receipt_proposal.items.truncate(1);
    receipt_proposal.items[0].operation_id = Uuid::new_v4();
    receipt_proposal.items[0].idempotency_key = Uuid::new_v4();
    receipt_proposal.items[0].canonical_operation = br#"{"draft":"exact"}"#.to_vec();
    receipt_proposal.items[0].canonical_operation_hash =
        action_member_operation_hash(&receipt_proposal.items[0].canonical_operation).to_vec();
    let receipt_member_hash = action_member_hash(ActionMemberHashInput {
        account_id: receipt_proposal.items[0].account_id,
        scope_id: receipt_proposal.items[0].scope_id,
        operation_id: receipt_proposal.items[0].operation_id,
        owner_pubkey: &receipt_proposal.owner_pubkey,
        connector: receipt_proposal.items[0].connector,
        operation: receipt_proposal.items[0].operation,
        target_hash: &receipt_proposal.items[0].target_hash,
        before_hash: receipt_proposal.items[0].before_hash.as_deref(),
        after_hash: &receipt_proposal.items[0].after_hash,
        expected_remote_version: receipt_proposal.items[0].expected_remote_version.as_deref(),
        idempotency_key: receipt_proposal.items[0].idempotency_key,
        canonical_operation_hash: &receipt_proposal.items[0].canonical_operation_hash,
    });
    receipt_proposal.items[0].member_hash = receipt_member_hash.to_vec();
    receipt_proposal.ordered_members_hash =
        action_ordered_members_hash(&[receipt_member_hash]).to_vec();
    insert_action_proposal(
        &pool,
        community,
        &receipt_proposal,
        &verified_proposal(&receipt_proposal, &broker_keys),
    )
    .await
    .expect("insert receipt-outbox proposal");
    let receipt_decided_at = Utc::now().timestamp();
    let receipt_expectation = DecisionExpectation {
        proposal_id: receipt_proposal_id,
        channel_id,
        nonce: receipt_proposal.nonce,
        operation_hash: receipt_proposal
            .operation_hash
            .as_slice()
            .try_into()
            .expect("receipt proposal hash"),
        owner_pubkey: owner_keys.public_key().to_bytes(),
        broker_pubkey: broker_keys.public_key().to_bytes(),
        proposed_at: receipt_proposal.proposed_at.timestamp(),
        expires_at: receipt_proposal.expires_at.timestamp(),
    };
    let receipt_decision = verified_approval(
        &owner_keys,
        &broker_keys,
        &receipt_expectation,
        receipt_decided_at,
    );
    assert_eq!(
        record_action_decision(&pool, community, &receipt_decision)
            .await
            .expect("approve receipt-outbox proposal"),
        ActionDecisionRecordOutcome::Approved
    );
    let receipt_claim = claim_action_execution(
        &pool,
        community,
        receipt_proposal_id,
        Uuid::new_v4(),
        Utc::now(),
    )
    .await
    .expect("claim receipt-outbox proposal")
    .expect("receipt-outbox claim");
    let durable_outcome = NewActionMemberOutcome {
        proposal_id: receipt_proposal_id,
        claim_id: receipt_claim.claim_id,
        item_index: 0,
        attempt_id: None,
        operation_id: receipt_claim.items[0].operation_id,
        member_hash: receipt_claim.items[0].member_hash.clone(),
        remote_result_id: None,
        remote_version: None,
        remote_resource_id_hash: None,
        outcome: ActionMemberOutcome::Failed,
        occurred_at: Utc::now(),
    };
    assert!(
        record_action_member_outcome(&pool, community, &durable_outcome)
            .await
            .expect("record durable member outcome")
    );
    assert!(
        !record_action_member_outcome(&pool, community, &durable_outcome)
            .await
            .expect("reject member outcome replay"),
        "a durable outcome must not replay"
    );
    let publish_now = Utc::now();
    let (publication_a, publication_b) = tokio::join!(
        claim_action_receipt_publication(
            &pool,
            community,
            Uuid::new_v4(),
            publish_now,
            StdDuration::from_secs(30),
        ),
        claim_action_receipt_publication(
            &pool,
            community,
            Uuid::new_v4(),
            publish_now,
            StdDuration::from_secs(30),
        )
    );
    let publications = [
        publication_a.expect("first concurrent receipt claim"),
        publication_b.expect("second concurrent receipt claim"),
    ];
    assert_eq!(
        publications.iter().filter(|value| value.is_some()).count(),
        1,
        "only one receipt publisher may hold the durable lease"
    );
    let publication = publications
        .into_iter()
        .flatten()
        .next()
        .expect("receipt publication");
    assert_eq!(publication.proposal_id, receipt_proposal_id);
    assert_eq!(publication.decision_id, receipt_decision.decision_id());
    assert_eq!(publication.results.len(), 1);
    assert_eq!(publication.results[0].outcome, ActionMemberOutcome::Failed);
    let receipt_remote_attempts: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM external_action_attempts \
         WHERE community_id=$1 AND proposal_id=$2",
    )
    .bind(community.as_uuid())
    .bind(receipt_proposal_id)
    .fetch_one(&pool)
    .await
    .expect("count pre-dispatch remote attempts");
    assert_eq!(
        receipt_remote_attempts, 0,
        "a deterministic pre-dispatch failure must record zero provider attempts"
    );
    assert!(retry_action_receipt_publication(
        &pool,
        community,
        receipt_proposal_id,
        publication.publish_claim_id,
        publish_now,
    )
    .await
    .expect("retry receipt publication"));
    let publication = claim_action_receipt_publication(
        &pool,
        community,
        Uuid::new_v4(),
        publish_now,
        StdDuration::from_secs(30),
    )
    .await
    .expect("reclaim receipt publication")
    .expect("retried receipt publication");
    let verified_receipt = verified_receipt(&publication, &broker_keys);
    assert!(complete_action_receipt_publication(
        &pool,
        community,
        publication.publish_claim_id,
        &verified_receipt,
        Utc::now(),
    )
    .await
    .expect("complete receipt publication"));
    assert!(
        claim_action_receipt_publication(
            &pool,
            community,
            Uuid::new_v4(),
            Utc::now(),
            StdDuration::from_secs(30),
        )
        .await
        .expect("receipt outbox drained")
        .is_none(),
        "published receipts must not replay"
    );

    drop_scratch_db(&admin, pool, &name).await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn change_pages_commit_index_acl_tombstone_and_cursor_once() {
    let (admin, pool, name) = scratch_db().await;
    let (community, _) = seed_community(&pool, "source-page").await;
    let account_id = Uuid::new_v4();
    let scope_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO connector_accounts \
         (community_id, id, provider, owner_pubkey, external_account_id, credential_reference) \
         VALUES ($1, $2, 'google_drive', $3, $4, $5)",
    )
    .bind(community.as_uuid())
    .bind(account_id)
    .bind(vec![3_u8; 32])
    .bind(format!("account-{account_id}"))
    .bind(format!("kv-account-{account_id}"))
    .execute(&pool)
    .await
    .expect("insert page connector account");
    sqlx::query(
        "INSERT INTO approved_source_scopes \
         (community_id, id, account_id, external_scope_id, scope_type, can_read, can_write) \
         VALUES ($1, $2, $3, $4, 'google_shared_drive', true, false)",
    )
    .bind(community.as_uuid())
    .bind(scope_id)
    .bind(account_id)
    .bind(format!("scope-{scope_id}"))
    .execute(&pool)
    .await
    .expect("insert page source scope");
    sqlx::query(
        "INSERT INTO connector_delta_cursors \
         (community_id, account_id, scope_id, stream, encrypted_cursor, \
          cursor_integrity_hash, cursor_key_version) \
         VALUES ($1, $2, $3, 'changes', $4, $5, 1)",
    )
    .bind(community.as_uuid())
    .bind(account_id)
    .bind(scope_id)
    .bind(vec![1_u8; 48])
    .bind(vec![1_u8; 32])
    .execute(&pool)
    .await
    .expect("insert page cursor");

    let worker = Uuid::new_v4();
    let now = Utc::now();
    let lease = claim_delta_scope(
        &pool,
        community,
        account_id,
        scope_id,
        "changes",
        worker,
        now,
        StdDuration::from_secs(60),
    )
    .await
    .expect("claim page cursor")
    .expect("page cursor lease");
    let upserts = vec![NewIndexedSourceItem {
        external_item_id: "drive-item-1".into(),
        remote_version: "v1".into(),
        remote_etag: Some("etag-v1".into()),
        title: "Project Atlas notes".into(),
        source_kind: IndexedSourceKind::Document,
        modified_at: now,
        resolvable_link: "https://drive.google.com/open?id=drive-item-1".into(),
        acls: vec![NewSourceAclPrincipal::User([3_u8; 32])],
        chunks: vec![NewIndexedSourceChunk {
            chunk_index: 0,
            start_char: 0,
            end_char: 29,
            content: "bounded untrusted source text".into(),
            content_hash: source_chunk_hash(0, 0, 29, "bounded untrusted source text"),
        }],
    }];
    let page = NewSourceChangePage {
        community_id: community,
        account_id,
        scope_id,
        provider: ExternalConnector::GoogleDrive,
        stream: "changes",
        worker_id: worker,
        lease_generation: lease.generation,
        expected_cursor_integrity_hash: &[1_u8; 32],
        next_encrypted_cursor: &[2_u8; 48],
        next_cursor_integrity_hash: &[2_u8; 32],
        next_cursor_key_version: 1,
        page_digest: &[4_u8; 32],
        upserts: &upserts,
        tombstones: &[],
        now: now + Duration::seconds(1),
    };
    let (other_community, _) = seed_community(&pool, "source-page-other").await;
    assert!(apply_source_change_page(&pool, other_community, page)
        .await
        .is_err());
    assert_eq!(
        apply_source_change_page(&pool, community, page)
            .await
            .expect("apply source page"),
        SourcePageApplyOutcome::Applied { changed_items: 1 }
    );
    assert_eq!(
        apply_source_change_page(&pool, community, page)
            .await
            .expect("replay source page"),
        SourcePageApplyOutcome::AlreadyApplied
    );
    let mismatched_replay = NewSourceChangePage {
        page_digest: &[99_u8; 32],
        ..page
    };
    assert!(
        apply_source_change_page(&pool, community, mismatched_replay)
            .await
            .is_err()
    );
    let projection: (i64, i64, Vec<u8>, Option<Uuid>, i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM source_chunks WHERE community_id=$1), \
           (SELECT count(*) FROM source_item_acls WHERE community_id=$1), \
           cursor_integrity_hash, lease_owner, \
           (SELECT start_char FROM source_chunks WHERE community_id=$1 LIMIT 1), \
           (SELECT end_char FROM source_chunks WHERE community_id=$1 LIMIT 1) \
         FROM connector_delta_cursors \
         WHERE community_id=$1 AND account_id=$2 AND scope_id=$3 AND stream='changes'",
    )
    .bind(community.as_uuid())
    .bind(account_id)
    .bind(scope_id)
    .fetch_one(&pool)
    .await
    .expect("inspect committed source page");
    assert_eq!((projection.0, projection.1), (1, 1));
    assert_eq!(projection.2, vec![2_u8; 32]);
    assert_eq!(projection.3, None);
    assert_eq!((projection.4, projection.5), (0, 29));

    let second_worker = Uuid::new_v4();
    let second_lease = claim_delta_scope(
        &pool,
        community,
        account_id,
        scope_id,
        "changes",
        second_worker,
        now + Duration::seconds(2),
        StdDuration::from_secs(60),
    )
    .await
    .expect("claim ACL replacement cursor")
    .expect("ACL replacement cursor lease");
    let replacement_upserts = vec![NewIndexedSourceItem {
        external_item_id: "drive-item-1".into(),
        remote_version: "v2".into(),
        remote_etag: Some("etag-v2".into()),
        title: "Project Atlas revised notes".into(),
        source_kind: IndexedSourceKind::Document,
        modified_at: now + Duration::seconds(2),
        resolvable_link: "https://drive.google.com/open?id=drive-item-1".into(),
        acls: vec![NewSourceAclPrincipal::User([4_u8; 32])],
        chunks: vec![NewIndexedSourceChunk {
            chunk_index: 0,
            start_char: 0,
            end_char: 11,
            content: "replacement".into(),
            content_hash: source_chunk_hash(0, 0, 11, "replacement"),
        }],
    }];
    let replacement_page = NewSourceChangePage {
        community_id: community,
        account_id,
        scope_id,
        provider: ExternalConnector::GoogleDrive,
        stream: "changes",
        worker_id: second_worker,
        lease_generation: second_lease.generation,
        expected_cursor_integrity_hash: &[2_u8; 32],
        next_encrypted_cursor: &[3_u8; 48],
        next_cursor_integrity_hash: &[3_u8; 32],
        next_cursor_key_version: 1,
        page_digest: &[5_u8; 32],
        upserts: &replacement_upserts,
        tombstones: &[],
        now: now + Duration::seconds(3),
    };
    assert_eq!(
        apply_source_change_page(&pool, community, replacement_page)
            .await
            .expect("replace item ACL and source version"),
        SourcePageApplyOutcome::Applied { changed_items: 1 }
    );
    assert_eq!(
        apply_source_change_page(&pool, community, replacement_page)
            .await
            .expect("replay ACL replacement"),
        SourcePageApplyOutcome::AlreadyApplied
    );
    let replacement: (i64, i64, String, String) = sqlx::query_as(
        "SELECT \
           count(*) FILTER (WHERE acl.principal_pubkey=$2), \
           count(*) FILTER (WHERE acl.principal_pubkey=$3), \
           min(item.remote_version), min(chunk.content) \
         FROM source_items item \
         JOIN source_item_acls acl ON acl.community_id=item.community_id AND acl.item_id=item.id \
         JOIN source_chunks chunk ON chunk.community_id=item.community_id AND chunk.item_id=item.id \
         WHERE item.community_id=$1 AND item.external_item_id='drive-item-1'",
    )
    .bind(community.as_uuid())
    .bind(vec![3_u8; 32])
    .bind(vec![4_u8; 32])
    .fetch_one(&pool)
    .await
    .expect("inspect complete ACL and source replacement");
    assert_eq!(replacement, (0, 1, "v2".into(), "replacement".into()));

    let third_worker = Uuid::new_v4();
    let third_lease = claim_delta_scope(
        &pool,
        community,
        account_id,
        scope_id,
        "changes",
        third_worker,
        now + Duration::seconds(4),
        StdDuration::from_secs(60),
    )
    .await
    .expect("claim tombstone cursor")
    .expect("tombstone cursor lease");
    let tombstones = vec![NewSourceTombstone {
        external_item_id: "drive-item-1".into(),
    }];
    let tombstone_page = NewSourceChangePage {
        community_id: community,
        account_id,
        scope_id,
        provider: ExternalConnector::GoogleDrive,
        stream: "changes",
        worker_id: third_worker,
        lease_generation: third_lease.generation,
        expected_cursor_integrity_hash: &[3_u8; 32],
        next_encrypted_cursor: &[4_u8; 48],
        next_cursor_integrity_hash: &[4_u8; 32],
        next_cursor_key_version: 1,
        page_digest: &[6_u8; 32],
        upserts: &[],
        tombstones: &tombstones,
        now: now + Duration::seconds(5),
    };
    assert_eq!(
        apply_source_change_page(&pool, community, tombstone_page)
            .await
            .expect("apply tombstone page"),
        SourcePageApplyOutcome::Applied { changed_items: 1 }
    );
    assert_eq!(
        apply_source_change_page(&pool, community, tombstone_page)
            .await
            .expect("replay tombstone page"),
        SourcePageApplyOutcome::AlreadyApplied
    );
    let removed: (i64, i64, bool) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM source_chunks WHERE community_id=$1), \
           (SELECT count(*) FROM source_item_acls WHERE community_id=$1), \
           EXISTS (SELECT 1 FROM source_items \
                   WHERE community_id=$1 AND external_item_id='drive-item-1' \
                     AND tombstoned_at IS NOT NULL AND status='unavailable')",
    )
    .bind(community.as_uuid())
    .fetch_one(&pool)
    .await
    .expect("inspect tombstoned source page");
    assert_eq!(removed, (0, 0, true));
    assert!(apply_source_change_page(&pool, community, page)
        .await
        .is_err());

    sqlx::query(
        "UPDATE connector_accounts SET provider='microsoft_graph' \
         WHERE community_id=$1 AND id=$2",
    )
    .bind(community.as_uuid())
    .bind(account_id)
    .execute(&pool)
    .await
    .expect("switch fixture to Microsoft provider");
    sqlx::query(
        "UPDATE approved_source_scopes SET resolver_hosts=ARRAY['coreadvs.sharepoint.com'] \
         WHERE community_id=$1 AND id=$2",
    )
    .bind(community.as_uuid())
    .bind(scope_id)
    .execute(&pool)
    .await
    .expect("configure exact SharePoint resolver host");
    let fourth_worker = Uuid::new_v4();
    let fourth_lease = claim_delta_scope(
        &pool,
        community,
        account_id,
        scope_id,
        "changes",
        fourth_worker,
        now + Duration::seconds(6),
        StdDuration::from_secs(60),
    )
    .await
    .expect("claim Microsoft authority cursor")
    .expect("Microsoft authority cursor lease");
    let sharepoint_item = |link: &str| NewIndexedSourceItem {
        external_item_id: "onedrive-item-1".into(),
        remote_version: "v1".into(),
        remote_etag: Some("etag-v1".into()),
        title: "Selected OneDrive source".into(),
        source_kind: IndexedSourceKind::Document,
        modified_at: now,
        resolvable_link: link.into(),
        acls: vec![NewSourceAclPrincipal::User([3_u8; 32])],
        chunks: vec![NewIndexedSourceChunk {
            chunk_index: 0,
            start_char: 0,
            end_char: 9,
            content: "authority".into(),
            content_hash: source_chunk_hash(0, 0, 9, "authority"),
        }],
    };
    let attacker_items = [sharepoint_item(
        "https://attacker.sharepoint.com/sites/deals/file",
    )];
    assert!(apply_source_change_page(
        &pool,
        community,
        microsoft_resolver_page(
            community,
            account_id,
            scope_id,
            fourth_worker,
            fourth_lease.generation,
            &attacker_items,
            &[7_u8; 32],
            now + Duration::seconds(7),
        ),
    )
    .await
    .is_err());
    let approved_items = [sharepoint_item(
        "https://coreadvs.sharepoint.com/sites/deals/file",
    )];
    assert_eq!(
        apply_source_change_page(
            &pool,
            community,
            microsoft_resolver_page(
                community,
                account_id,
                scope_id,
                fourth_worker,
                fourth_lease.generation,
                &approved_items,
                &[8_u8; 32],
                now + Duration::seconds(7),
            ),
        )
        .await
        .expect("apply exact configured SharePoint resolver authority"),
        SourcePageApplyOutcome::Applied { changed_items: 1 }
    );

    drop_scratch_db(&admin, pool, &name).await;
}

#[tokio::test]
#[ignore = "requires Postgres with pgvector"]
async fn cursor_leases_recover_by_generation_and_reject_stale_completion() {
    let (admin, pool, name) = scratch_db().await;
    let (community, _) = seed_community(&pool, "cursor").await;
    let account_id = Uuid::new_v4();
    let scope_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO connector_accounts \
         (community_id, id, provider, owner_pubkey, external_account_id, credential_reference) \
         VALUES ($1, $2, 'google_drive', $3, $4, $5)",
    )
    .bind(community.as_uuid())
    .bind(account_id)
    .bind(vec![3_u8; 32])
    .bind(format!("account-{account_id}"))
    .bind(format!("kv-account-{account_id}"))
    .execute(&pool)
    .await
    .expect("insert cursor account");
    sqlx::query(
        "INSERT INTO approved_source_scopes \
         (community_id, id, account_id, external_scope_id, scope_type, can_read, can_write) \
         VALUES ($1, $2, $3, $4, 'shared_drive', true, false)",
    )
    .bind(community.as_uuid())
    .bind(scope_id)
    .bind(account_id)
    .bind(format!("scope-{scope_id}"))
    .execute(&pool)
    .await
    .expect("insert cursor scope");
    sqlx::query(
        "INSERT INTO connector_delta_cursors \
         (community_id, account_id, scope_id, stream, encrypted_cursor, cursor_integrity_hash, cursor_key_version) \
         VALUES ($1, $2, $3, 'items', $4, $5, 1)",
    )
    .bind(community.as_uuid())
    .bind(account_id)
    .bind(scope_id)
    .bind(vec![1_u8; 24])
    .bind(vec![2_u8; 32])
    .execute(&pool)
    .await
    .expect("insert encrypted cursor");

    let now = Utc::now();
    let worker_a = Uuid::new_v4();
    let worker_b = Uuid::new_v4();
    for invalid_stream in [
        "https://graph.invalid/delta?token=secret".to_owned(),
        "items\nsecret".to_owned(),
        "x".repeat(129),
    ] {
        assert!(claim_delta_scope(
            &pool,
            community,
            account_id,
            scope_id,
            &invalid_stream,
            worker_a,
            now,
            StdDuration::from_secs(30),
        )
        .await
        .is_err());
    }
    assert!(
        sqlx::query(
            "UPDATE approved_source_scopes SET can_read=false, can_write=true \
         WHERE community_id=$1 AND id=$2",
        )
        .bind(community.as_uuid())
        .bind(scope_id)
        .execute(&pool)
        .await
        .is_err(),
        "write-only connector scopes must be rejected by the database"
    );
    sqlx::query(
        "UPDATE approved_source_scopes SET can_read=true, status='paused' \
         WHERE community_id=$1 AND id=$2",
    )
    .bind(community.as_uuid())
    .bind(scope_id)
    .execute(&pool)
    .await
    .expect("pause cursor scope");
    assert!(claim_delta_scope(
        &pool,
        community,
        account_id,
        scope_id,
        "items",
        worker_a,
        now,
        StdDuration::from_secs(30),
    )
    .await
    .expect("paused claim")
    .is_none());
    sqlx::query(
        "UPDATE approved_source_scopes SET status='revoked', revoked_at=NOW() \
         WHERE community_id=$1 AND id=$2",
    )
    .bind(community.as_uuid())
    .bind(scope_id)
    .execute(&pool)
    .await
    .expect("revoke cursor scope");
    assert!(claim_delta_scope(
        &pool,
        community,
        account_id,
        scope_id,
        "items",
        worker_a,
        now,
        StdDuration::from_secs(30),
    )
    .await
    .expect("revoked claim")
    .is_none());
    sqlx::query(
        "UPDATE approved_source_scopes SET status='active', revoked_at=NULL \
         WHERE community_id=$1 AND id=$2",
    )
    .bind(community.as_uuid())
    .bind(scope_id)
    .execute(&pool)
    .await
    .expect("restore cursor scope");
    let first = claim_delta_scope(
        &pool,
        community,
        account_id,
        scope_id,
        "items",
        worker_a,
        now,
        StdDuration::from_secs(30),
    )
    .await
    .expect("claim initial cursor")
    .expect("initial cursor lease");
    assert!(claim_delta_scope(
        &pool,
        community,
        account_id,
        scope_id,
        "items",
        worker_a,
        now,
        StdDuration::from_secs(30),
    )
    .await
    .expect("same-worker duplicate cursor claim")
    .is_none());
    assert!(claim_delta_scope(
        &pool,
        community,
        account_id,
        scope_id,
        "items",
        worker_b,
        now,
        StdDuration::from_secs(30),
    )
    .await
    .expect("contended cursor claim")
    .is_none());
    assert!(!fail_delta_scope(
        &pool,
        community,
        account_id,
        scope_id,
        "items",
        worker_b,
        first.generation,
        "provider.transient",
        now + Duration::seconds(1),
        StdDuration::from_secs(20),
    )
    .await
    .expect("reject stale-worker delta failure"));
    assert!(fail_delta_scope(
        &pool,
        community,
        account_id,
        scope_id,
        "items",
        worker_a,
        first.generation,
        "https://provider.invalid?secret=1",
        now + Duration::seconds(1),
        StdDuration::from_secs(20),
    )
    .await
    .is_err());
    assert!(fail_delta_scope(
        &pool,
        community,
        account_id,
        scope_id,
        "items",
        worker_a,
        first.generation,
        "provider.transient",
        now + Duration::seconds(1),
        StdDuration::from_secs(20),
    )
    .await
    .expect("fail current delta lease"));
    assert!(claim_delta_scope(
        &pool,
        community,
        account_id,
        scope_id,
        "items",
        worker_b,
        now + Duration::seconds(20),
        StdDuration::from_secs(30),
    )
    .await
    .expect("claim before retry delay")
    .is_none());
    let recovered = claim_delta_scope(
        &pool,
        community,
        account_id,
        scope_id,
        "items",
        worker_b,
        now + Duration::seconds(21),
        StdDuration::from_secs(30),
    )
    .await
    .expect("recover cursor lease")
    .expect("expired cursor lease can recover");
    assert_eq!(recovered.generation, first.generation + 1);
    assert!(!complete_delta_scope(
        &pool,
        community,
        account_id,
        scope_id,
        "items",
        worker_a,
        first.generation,
        &[3_u8; 24],
        &[4_u8; 32],
        2,
        now + Duration::seconds(22),
    )
    .await
    .expect("stale cursor completion"));
    assert!(complete_delta_scope(
        &pool,
        community,
        account_id,
        scope_id,
        "items",
        worker_b,
        recovered.generation,
        &[5_u8; 24],
        &[6_u8; 32],
        2,
        now + Duration::seconds(22),
    )
    .await
    .expect("current cursor completion"));

    drop_scratch_db(&admin, pool, &name).await;
}

#[tokio::test]
#[ignore = "requires Postgres with pgvector"]
async fn audit_export_retry_preserves_order_and_checkpoints_before_export() {
    let (admin, pool, name) = scratch_db().await;
    let (community, _) = seed_community(&pool, "audit").await;
    let version = AuditObjectVersion::new("v1").expect("valid version marker");
    for marker in 1_u8..=3 {
        append_audit_entry(
            &pool,
            community,
            AuditEnvelope {
                event_type: AuditEventType::SourceSync,
                entity_type: AuditEntityType::SourceItem,
                entity_id: Uuid::from_u128(u128::from(marker)),
                object_hash: &[marker; 32],
                version: Some(&version),
                occurred_at: Utc::now() + Duration::seconds(i64::from(marker)),
                outcome: AuditOutcome::Accepted,
            },
        )
        .await
        .expect("append audit entry");
    }
    assert!(
        sqlx::query(
            "INSERT INTO core_audit_outbox \
         (community_id, sequence, event_type, entity_type, entity_id, object_hash, object_version, \
          occurred_at, outcome, prior_entry_hash, entry_hash) \
         VALUES ($1, 5, 'source_sync', 'source_item', $2, $3, 'v1', NOW(), \
                 'accepted', $4, $5)",
        )
        .bind(community.as_uuid())
        .bind(Uuid::new_v4())
        .bind(vec![71_u8; 32])
        .bind(vec![72_u8; 32])
        .bind(vec![73_u8; 32])
        .execute(&pool)
        .await
        .is_err(),
        "database must reject an audit sequence/predecessor gap"
    );
    assert!(
        sqlx::query(
            "UPDATE core_audit_outbox SET object_hash=$2 \
         WHERE community_id=$1 AND sequence=1",
        )
        .bind(community.as_uuid())
        .bind(vec![74_u8; 32])
        .execute(&pool)
        .await
        .is_err(),
        "database must reject audit envelope mutation"
    );
    assert!(
        sqlx::query(
            "UPDATE core_audit_outbox SET export_state='exported', exported_at=NOW() \
         WHERE community_id=$1 AND sequence=3",
        )
        .bind(community.as_uuid())
        .execute(&pool)
        .await
        .is_err(),
        "database must reject a skipped audit export transition"
    );
    assert!(
        sqlx::query(
            "UPDATE core_audit_outbox \
         SET export_state='claimed', export_batch_id=$2, export_claimed_by=$3, \
             export_claimed_at=NOW(), export_claim_until=NOW() + INTERVAL '30 seconds' \
         WHERE community_id=$1 AND sequence=3",
        )
        .bind(community.as_uuid())
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .execute(&pool)
        .await
        .is_err(),
        "database must reject claiming an unsigned audit row"
    );
    assert!(
        sqlx::query("DELETE FROM core_audit_outbox WHERE community_id=$1 AND sequence=3",)
            .bind(community.as_uuid())
            .execute(&pool)
            .await
            .is_err(),
        "database must reject audit outbox deletion"
    );

    let worker = Uuid::new_v4();
    let now = Utc::now() + Duration::seconds(10);
    assert!(
        claim_audit_export_batch(
            &pool,
            community,
            worker,
            chrono::DateTime::<Utc>::MAX_UTC,
            StdDuration::from_secs(30),
            3,
        )
        .await
        .is_err(),
        "extreme audit lease timestamp must return an error rather than panic"
    );
    sqlx::query(
        "UPDATE core_audit_outbox SET signing_state='signed', signer_identifier='audit-signer-v1', \
         signature=$2 WHERE community_id=$1 AND sequence=2",
    )
    .bind(community.as_uuid())
    .bind(vec![22_u8; 64])
    .execute(&pool)
    .await
    .expect("sign later audit row");
    assert!(
        sqlx::query(
            "UPDATE core_audit_outbox SET signature=$2 \
         WHERE community_id=$1 AND sequence=2",
        )
        .bind(community.as_uuid())
        .bind(vec![99_u8; 64])
        .execute(&pool)
        .await
        .is_err(),
        "database must reject mutation of a signed audit signature"
    );
    assert!(
        claim_audit_export_batch(&pool, community, worker, now, StdDuration::from_secs(30), 3,)
            .await
            .expect("unsigned-head audit claim")
            .is_none(),
        "an unsigned chain head must block later signed rows"
    );
    sqlx::query(
        "UPDATE core_audit_outbox SET signing_state='signed', signer_identifier='audit-signer-v1', \
         signature=$2 WHERE community_id=$1 AND sequence=1",
    )
    .bind(community.as_uuid())
    .bind(vec![21_u8; 64])
    .execute(&pool)
    .await
    .expect("sign audit head");
    let first =
        claim_audit_export_batch(&pool, community, worker, now, StdDuration::from_secs(30), 3)
            .await
            .expect("claim audit batch")
            .expect("audit batch available");
    assert_eq!(
        first
            .entries
            .iter()
            .map(|entry| entry.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(first.entries.iter().all(|entry| {
        entry.signing_state == "signed"
            && entry.signer_identifier.as_deref() == Some("audit-signer-v1")
            && entry
                .signature
                .as_ref()
                .is_some_and(|value| value.len() == 64)
    }));
    assert!(retry_audit_export_batch(
        &pool,
        community,
        first.batch_id,
        now + Duration::seconds(31),
    )
    .await
    .expect("retry audit batch"));
    sqlx::query(
        "UPDATE core_audit_outbox SET signing_state='signed', signer_identifier='audit-signer-v1', \
         signature=$2 WHERE community_id=$1 AND sequence=3",
    )
    .bind(community.as_uuid())
    .bind(vec![23_u8; 64])
    .execute(&pool)
    .await
    .expect("sign final audit row");
    let retried = claim_audit_export_batch(
        &pool,
        community,
        worker,
        now + Duration::seconds(31),
        StdDuration::from_secs(30),
        2,
    )
    .await
    .expect("reclaim audit batch")
    .expect("retried audit batch available");
    assert_eq!(
        retried
            .entries
            .iter()
            .map(|entry| entry.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(complete_audit_export_batch(
        &pool,
        community,
        retried.batch_id,
        "https://vault.invalid/audit?sig=secret",
        &[43_u8; 32],
        "etag-secret",
        now + Duration::seconds(32),
    )
    .await
    .is_err());
    assert!(complete_audit_export_batch(
        &pool,
        community,
        retried.batch_id,
        "audit/2026-08-03/sequence-1-2.ndjson",
        &[44_u8; 32],
        "etag-immutable",
        now + Duration::seconds(32),
    )
    .await
    .expect("complete audit export"));
    let final_batch = claim_audit_export_batch(
        &pool,
        community,
        worker,
        now + Duration::seconds(33),
        StdDuration::from_secs(30),
        3,
    )
    .await
    .expect("claim second audit batch")
    .expect("final signed row available");
    assert_eq!(
        final_batch
            .entries
            .iter()
            .map(|entry| entry.sequence)
            .collect::<Vec<_>>(),
        vec![3]
    );
    assert!(complete_audit_export_batch(
        &pool,
        community,
        final_batch.batch_id,
        "audit/2026-08-03/sequence-3.ndjson",
        &[45_u8; 32],
        "etag-immutable-2",
        now + Duration::seconds(34),
    )
    .await
    .expect("complete second audit export"));
    let checkpoint: (i64, Vec<u8>) = sqlx::query_as(
        "SELECT last_exported_sequence, last_entry_hash FROM core_audit_checkpoints \
         WHERE community_id=$1 ORDER BY last_exported_sequence DESC LIMIT 1",
    )
    .bind(community.as_uuid())
    .fetch_one(&pool)
    .await
    .expect("read durable checkpoint");
    assert_eq!(checkpoint.0, 3);
    let checkpoint_history: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM core_audit_checkpoints WHERE community_id=$1")
            .bind(community.as_uuid())
            .fetch_one(&pool)
            .await
            .expect("count immutable checkpoint history");
    assert_eq!(checkpoint_history, 2);
    let sequence_one_hash: Vec<u8> = sqlx::query_scalar(
        "SELECT entry_hash FROM core_audit_outbox WHERE community_id=$1 AND sequence=1",
    )
    .bind(community.as_uuid())
    .fetch_one(&pool)
    .await
    .expect("read prior audit hash for checkpoint backfill test");
    assert!(
        sqlx::query(
            "INSERT INTO core_audit_checkpoints \
         (community_id, last_exported_sequence, last_entry_hash, blob_object_key, \
          blob_content_hash, blob_etag, checkpointed_at) \
         VALUES ($1, 1, $2, 'audit/backfill.ndjson', $3, 'backfill', NOW())",
        )
        .bind(community.as_uuid())
        .bind(sequence_one_hash)
        .bind(vec![98_u8; 32])
        .execute(&pool)
        .await
        .is_err(),
        "database must reject a backfilled audit checkpoint"
    );
    assert!(
        sqlx::query(
            "UPDATE core_audit_checkpoints SET blob_etag='mutated' \
         WHERE community_id=$1 AND last_exported_sequence=3",
        )
        .bind(community.as_uuid())
        .execute(&pool)
        .await
        .is_err(),
        "database must reject checkpoint mutation"
    );
    assert!(
        sqlx::query(
            "DELETE FROM core_audit_checkpoints \
         WHERE community_id=$1 AND last_exported_sequence=3",
        )
        .bind(community.as_uuid())
        .execute(&pool)
        .await
        .is_err(),
        "database must reject checkpoint deletion"
    );
    let exported_before_checkpoint: i64 = sqlx::query(
        "SELECT count(*) AS count FROM core_audit_outbox o \
         WHERE o.community_id=$1 AND o.export_state='exported' \
           AND NOT EXISTS (SELECT 1 FROM core_audit_checkpoints c \
                           WHERE c.community_id=o.community_id \
                             AND c.last_exported_sequence >= o.sequence)",
    )
    .bind(community.as_uuid())
    .fetch_one(&pool)
    .await
    .expect("check export/checkpoint ordering")
    .get("count");
    assert_eq!(exported_before_checkpoint, 0);

    drop_scratch_db(&admin, pool, &name).await;
}
