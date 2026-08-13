use std::{future::Future, pin::Pin, time::Duration as StdDuration};

use buzz_assistant_broker::{
    run_private_assistant_turn, AssistantAuthorityResolver, AssistantModel, AuthorizedFtsRetriever,
    BrokerVersionStamps, InsightCommandSink, ModelFailure, ModelRequest, PgAuthorizedFtsRetriever,
    PrivateAssistantRoute, PublishFailure, RetrievalFailure, ServerAuthenticatedTurn, TurnError,
};
use buzz_connector_core::{
    apply::ApplyOutcome,
    core_crm::{normalize_core_crm_response, CoreCrmReadOperation},
    core_crm_sync::{CoreCrmSyncCursorV1, CoreCrmSyncTarget, CoreCrmTrackedTarget},
    persistence::apply_postgres_change_page,
    retrieval::{AuthorizedExcerpt, FullTextRetrievalQuery},
    types::{AccountId, AclPrincipal, ConnectorProvider, EncryptedCursor, ScopeId},
};
use buzz_core::{
    core_protocol::{
        EvidenceResolveRequestPayload, EvidenceResolveResultPayload, EvidenceResolvedSourceType,
        EvidenceResolverId, InsightPayload,
    },
    CommunityId,
};
use buzz_core_worker::{
    connector_iteration::{PageProvider, ProviderPageError, TrustedConnectorClaim},
    core_crm_provider::{
        CoreCrmCursorCodec, CoreCrmPageProvider, CoreCrmReadOutcome, CoreCrmSnapshotReader,
    },
    postgres_core_crm::CoreCrmAesCursorCodec,
};
use buzz_db::core_storage::{
    claim_next_core_crm_delta_scope, resolve_source_evidence, CoreCrmDeltaScopeClaim,
    EvidenceResolution, EvidenceResolveRequest, ServerResolvedSourceAudience,
};
use chrono::{Duration, Utc};
use nostr::{EventBuilder, Keys, PublicKey};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz";
const CRM_FIXTURE: &[u8] =
    include_bytes!("../../buzz-connector-core/tests/fixtures/core-crm/get-contact.response.json");
const PRIVATE_CHANNEL: Uuid = Uuid::from_u128(0x400);
const OTHER_PRIVATE_CHANNEL: Uuid = Uuid::from_u128(0x401);
// One minute after the fixture's latest provider modification timestamp.
const CREATED_AT: i64 = 1_785_596_705;
const CREDENTIAL_REFERENCE: &str = "kv-synthetic-secret-sentinel";
const STREAM: &str = "known-records";
const CURSOR_KEY: [u8; 32] = [91; 32];

fn test_db_url() -> String {
    std::env::var("BUZZ_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| TEST_DB_URL.to_owned())
}

async fn scratch_db() -> (PgPool, PgPool, String) {
    let admin = PgPool::connect(&test_db_url())
        .await
        .expect("connect to Postgres test instance");
    let name = format!("assistant_slice_{}", Uuid::new_v4().simple());
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

async fn seed_community(pool: &PgPool, label: &str, users: &[PublicKey]) -> CommunityId {
    let community = Uuid::new_v4();
    sqlx::query("INSERT INTO communities (id, host) VALUES ($1, $2)")
        .bind(community)
        .bind(format!("{label}-{}.example", community.simple()))
        .execute(pool)
        .await
        .expect("insert community");
    for user in users {
        sqlx::query("INSERT INTO users (community_id, pubkey) VALUES ($1, $2)")
            .bind(community)
            .bind(user.to_bytes().as_slice())
            .execute(pool)
            .await
            .expect("insert community user");
    }
    CommunityId::from_uuid(community)
}

async fn seed_private_channel(
    pool: &PgPool,
    community: CommunityId,
    channel_id: Uuid,
    owner: PublicKey,
) {
    sqlx::query(
        "INSERT INTO channels \
         (community_id, id, name, channel_type, visibility, created_by) \
         VALUES ($1, $2, 'core-relationship-assistant', 'dm', 'private', $3)",
    )
    .bind(community.as_uuid())
    .bind(channel_id)
    .bind(owner.to_bytes().as_slice())
    .execute(pool)
    .await
    .expect("insert private assistant channel");
    sqlx::query(
        "INSERT INTO channel_members (community_id, channel_id, pubkey, role) \
         VALUES ($1, $2, $3, 'owner')",
    )
    .bind(community.as_uuid())
    .bind(channel_id)
    .bind(owner.to_bytes().as_slice())
    .execute(pool)
    .await
    .expect("insert private assistant owner membership");
}

async fn seed_core_crm_scope(
    pool: &PgPool,
    community: CommunityId,
    owner: PublicKey,
) -> (Uuid, Uuid) {
    let account_id = Uuid::new_v4();
    let scope_id = Uuid::new_v4();
    let logical_cursor = CoreCrmSyncCursorV1::new(vec![CoreCrmTrackedTarget::new(
        CoreCrmSyncTarget::contact(
            Uuid::parse_str("11111111-1111-4111-8111-111111111111").expect("fixture contact UUID"),
        ),
        Vec::new(),
    )
    .expect("tracked contact")])
    .expect("initial known-record cursor");
    let seed_claim = TrustedConnectorClaim::new(
        *community.as_uuid(),
        AccountId::new(account_id),
        ScopeId::new(scope_id),
        ConnectorProvider::CoreCrm,
        STREAM,
        1,
        EncryptedCursor::new(vec![1; 32], [1; 32], 1, 0).expect("seed cursor"),
        std::collections::BTreeSet::from([AclPrincipal::user(owner.to_bytes())]),
    )
    .expect("seed claim");
    let initial_cursor = CoreCrmAesCursorCodec::new(CURSOR_KEY, 1)
        .expect("synthetic cursor codec")
        .encode(&seed_claim, &logical_cursor)
        .expect("encrypt initial known-record cursor");
    sqlx::query(
        "INSERT INTO connector_accounts \
         (community_id, id, provider, owner_pubkey, external_account_id, credential_reference) \
         VALUES ($1, $2, 'core_crm', $3, $4, $5)",
    )
    .bind(community.as_uuid())
    .bind(account_id)
    .bind(owner.to_bytes().as_slice())
    .bind(format!("synthetic-account-{account_id}"))
    .bind(CREDENTIAL_REFERENCE)
    .execute(pool)
    .await
    .expect("insert Core CRM account");
    sqlx::query(
        "INSERT INTO approved_source_scopes \
         (community_id, id, account_id, external_scope_id, scope_type, can_read, can_write) \
         VALUES ($1, $2, $3, 'core-crm-read-corpus', 'core_crm_corpus', true, false)",
    )
    .bind(community.as_uuid())
    .bind(scope_id)
    .bind(account_id)
    .execute(pool)
    .await
    .expect("insert Core CRM read scope");
    sqlx::query(
        "INSERT INTO connector_delta_cursors \
         (community_id, account_id, scope_id, stream, encrypted_cursor, \
          cursor_integrity_hash, cursor_key_version) \
         VALUES ($1, $2, $3, $4, $5, $6, 1)",
    )
    .bind(community.as_uuid())
    .bind(account_id)
    .bind(scope_id)
    .bind(STREAM)
    .bind(initial_cursor.ciphertext())
    .bind(initial_cursor.integrity_hash().as_slice())
    .execute(pool)
    .await
    .expect("insert bounded snapshot cursor");
    (account_id, scope_id)
}

fn trusted_claim(claimed: CoreCrmDeltaScopeClaim) -> TrustedConnectorClaim {
    let owner: [u8; 32] = claimed.owner_pubkey.try_into().expect("owner pubkey");
    let integrity_hash: [u8; 32] = claimed
        .lease
        .cursor_integrity_hash
        .try_into()
        .expect("cursor hash");
    let generation = u64::try_from(claimed.lease.generation).expect("lease generation");
    TrustedConnectorClaim::new(
        *claimed.community_id.as_uuid(),
        AccountId::new(claimed.account_id),
        ScopeId::new(claimed.scope_id),
        ConnectorProvider::CoreCrm,
        claimed.stream,
        generation,
        EncryptedCursor::new(
            claimed.lease.encrypted_cursor,
            integrity_hash,
            u32::try_from(claimed.lease.cursor_key_version).expect("cursor key version"),
            generation - 1,
        )
        .expect("claimed cursor"),
        std::collections::BTreeSet::from([AclPrincipal::user(owner)]),
    )
    .expect("trusted claimed authority")
}

struct FixtureCoreCrmReader;

impl CoreCrmSnapshotReader for FixtureCoreCrmReader {
    async fn read(
        &mut self,
        operation: &CoreCrmReadOperation,
        acls: Vec<AclPrincipal>,
    ) -> Result<CoreCrmReadOutcome, ProviderPageError> {
        normalize_core_crm_response(operation, 1, CRM_FIXTURE, acls)
            .map(CoreCrmReadOutcome::Snapshot)
            .map_err(|_| ProviderPageError::InvalidResponse)
    }
}

struct Resolver {
    route: PrivateAssistantRoute,
}

impl AssistantAuthorityResolver for Resolver {
    fn resolve_private_assistant(
        &mut self,
        _community: CommunityId,
        _caller: &PublicKey,
    ) -> Result<PrivateAssistantRoute, TurnError> {
        Ok(self.route.clone())
    }

    fn resolve_accessible_channels(
        &mut self,
        _community: CommunityId,
        _caller: &PublicKey,
    ) -> Result<Vec<Uuid>, TurnError> {
        Ok(Vec::new())
    }
}

#[derive(Default)]
struct Model {
    inputs: Vec<String>,
}

impl AssistantModel for Model {
    fn complete(&mut self, request: ModelRequest<'_>) -> Result<String, ModelFailure> {
        self.inputs.push(format!(
            "{}{}{}",
            request.system_policy(),
            request.question(),
            request.excerpt_envelopes().join("")
        ));
        Ok(json!({
            "change": "A client follow-up needs attention.",
            "why_it_matters": "The relationship record shows an open commitment.",
            "recommendation": "Review the evidence and prepare a concise response.",
            "citations": [0]
        })
        .to_string())
    }
}

#[derive(Default)]
struct Sink(Vec<EventBuilder>);

impl InsightCommandSink for Sink {
    fn enqueue(&mut self, command: EventBuilder) -> Result<(), PublishFailure> {
        self.0.push(command);
        Ok(())
    }
}

fn resolver(
    community: CommunityId,
    owner: PublicKey,
    assistant: PublicKey,
    private_channel: Uuid,
) -> Resolver {
    Resolver {
        route: PrivateAssistantRoute::server_verified(community, owner, assistant, private_channel),
    }
}

fn versions() -> BrokerVersionStamps {
    BrokerVersionStamps::new(
        "safety-v1",
        "persona-v1",
        "firm-v1",
        "personal-v1",
        "model-v1",
    )
    .expect("valid synthetic versions")
}

struct RevokingPgRetriever<'a> {
    pool: &'a PgPool,
    community: CommunityId,
    account_id: Uuid,
    scope_id: Uuid,
    calls: usize,
}

impl AuthorizedFtsRetriever for RevokingPgRetriever<'_> {
    fn retrieve<'a>(
        &'a mut self,
        community: CommunityId,
        query: &'a FullTextRetrievalQuery,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<AuthorizedExcerpt>, RetrievalFailure>> + Send + 'a>>
    {
        self.calls += 1;
        let revoke = self.calls == 2;
        Box::pin(async move {
            if revoke {
                sqlx::query(
                    "UPDATE approved_source_scopes SET status='paused' \
                     WHERE community_id=$1 AND account_id=$2 AND id=$3",
                )
                .bind(self.community.as_uuid())
                .bind(self.account_id)
                .bind(self.scope_id)
                .execute(self.pool)
                .await
                .map_err(|_| RetrievalFailure::Unavailable)?;
            }
            let mut inner = PgAuthorizedFtsRetriever::new(self.pool);
            inner.retrieve(community, query).await
        })
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn synthetic_core_crm_read_reaches_only_the_authorized_private_assistant() {
    let (admin, pool, database_name) = scratch_db().await;
    let blake = Keys::generate();
    let denied_user = Keys::generate();
    let assistant = Keys::generate();
    let community = seed_community(
        &pool,
        "assistant-slice",
        &[blake.public_key(), denied_user.public_key()],
    )
    .await;
    let other_community = seed_community(
        &pool,
        "assistant-slice-other",
        &[blake.public_key(), denied_user.public_key()],
    )
    .await;
    seed_private_channel(&pool, community, PRIVATE_CHANNEL, blake.public_key()).await;
    let (account_id, scope_id) = seed_core_crm_scope(&pool, community, blake.public_key()).await;

    let now = Utc::now();
    let lost_worker = Uuid::new_v4();
    let lost_claim = claim_next_core_crm_delta_scope(
        &pool,
        lost_worker,
        now - Duration::minutes(2),
        StdDuration::from_secs(60),
    )
    .await
    .expect("claim expiring synthetic cursor")
    .expect("expiring synthetic cursor lease");
    let lost_generation = lost_claim.lease.generation;
    let lost_claim = trusted_claim(lost_claim);
    let mut lost_provider = CoreCrmPageProvider::new(
        FixtureCoreCrmReader,
        CoreCrmAesCursorCodec::new(CURSOR_KEY, 1).expect("cursor codec"),
    );
    let lost_page = lost_provider
        .fetch_one_page(&lost_claim)
        .await
        .expect("identity-bound lost-lease page");
    assert!(lost_page.reconciliation_complete());

    let worker_id = Uuid::new_v4();
    let claimed =
        claim_next_core_crm_delta_scope(&pool, worker_id, now, StdDuration::from_secs(60))
            .await
            .expect("reclaim expired synthetic cursor")
            .expect("current synthetic cursor lease");
    assert!(claimed.lease.generation > lost_generation);
    assert!(apply_postgres_change_page(
        &pool,
        community,
        &lost_page,
        lost_worker,
        lost_generation,
        now,
    )
    .await
    .is_err());

    let lease_generation = claimed.lease.generation;
    let claim = trusted_claim(claimed);
    let mut provider = CoreCrmPageProvider::new(
        FixtureCoreCrmReader,
        CoreCrmAesCursorCodec::new(CURSOR_KEY, 1).expect("cursor codec"),
    );
    let page = provider
        .fetch_one_page(&claim)
        .await
        .expect("exact identity-bound Core CRM page");
    assert_eq!(page.upserts().len(), 1);
    assert!(page.reconciliation_complete());
    assert_eq!(
        apply_postgres_change_page(&pool, community, &page, worker_id, lease_generation, now,)
            .await
            .expect("apply synthetic CRM page"),
        ApplyOutcome::Applied { changed_items: 1 }
    );
    assert_eq!(
        apply_postgres_change_page(&pool, community, &page, worker_id, lease_generation, now,)
            .await
            .expect("retry identical CRM page"),
        ApplyOutcome::AlreadyApplied
    );

    let denied_turn = ServerAuthenticatedTurn::from_server_facts(
        community,
        denied_user.public_key(),
        assistant.public_key(),
        OTHER_PRIVATE_CHANNEL,
        "synthetic follow-up",
    )
    .expect("denied-user turn");
    let mut denied_resolver = resolver(
        community,
        denied_user.public_key(),
        assistant.public_key(),
        OTHER_PRIVATE_CHANNEL,
    );
    let mut denied_retriever = PgAuthorizedFtsRetriever::new(&pool);
    let mut denied_model = Model::default();
    let mut denied_sink = Sink::default();
    assert_eq!(
        run_private_assistant_turn(
            &denied_turn,
            &versions(),
            &mut denied_resolver,
            &mut denied_retriever,
            &mut denied_model,
            &mut denied_sink,
            CREATED_AT,
        )
        .await,
        Err(TurnError::NoEvidence)
    );
    assert!(denied_model.inputs.is_empty());
    assert!(denied_sink.0.is_empty());

    let other_tenant_turn = ServerAuthenticatedTurn::from_server_facts(
        other_community,
        blake.public_key(),
        assistant.public_key(),
        OTHER_PRIVATE_CHANNEL,
        "synthetic follow-up",
    )
    .expect("other-tenant turn");
    let mut other_tenant_resolver = resolver(
        other_community,
        blake.public_key(),
        assistant.public_key(),
        OTHER_PRIVATE_CHANNEL,
    );
    let mut other_tenant_retriever = PgAuthorizedFtsRetriever::new(&pool);
    let mut other_tenant_model = Model::default();
    let mut other_tenant_sink = Sink::default();
    assert_eq!(
        run_private_assistant_turn(
            &other_tenant_turn,
            &versions(),
            &mut other_tenant_resolver,
            &mut other_tenant_retriever,
            &mut other_tenant_model,
            &mut other_tenant_sink,
            CREATED_AT,
        )
        .await,
        Err(TurnError::NoEvidence)
    );
    assert!(other_tenant_model.inputs.is_empty());
    assert!(other_tenant_sink.0.is_empty());

    let turn = ServerAuthenticatedTurn::from_server_facts(
        community,
        blake.public_key(),
        assistant.public_key(),
        PRIVATE_CHANNEL,
        "synthetic follow-up",
    )
    .expect("authorized Blake-like turn");
    let mut authorized_resolver = resolver(
        community,
        blake.public_key(),
        assistant.public_key(),
        PRIVATE_CHANNEL,
    );
    let mut authorized_retriever = PgAuthorizedFtsRetriever::new(&pool);
    let mut model = Model::default();
    let mut sink = Sink::default();
    run_private_assistant_turn(
        &turn,
        &versions(),
        &mut authorized_resolver,
        &mut authorized_retriever,
        &mut model,
        &mut sink,
        CREATED_AT,
    )
    .await
    .expect("authorized synthetic assistant turn");
    assert_eq!(model.inputs.len(), 1);
    assert_eq!(sink.0.len(), 1);

    let event = sink
        .0
        .pop()
        .expect("one publish command")
        .sign_with_keys(&assistant)
        .expect("sign synthetic command");
    assert_eq!(event.kind.as_u16(), 44_300);
    let tags: Vec<Vec<String>> = event
        .tags
        .iter()
        .map(|tag| tag.as_slice().iter().map(ToString::to_string).collect())
        .collect();
    assert_eq!(
        tags,
        vec![
            vec!["h".into(), PRIVATE_CHANNEL.to_string()],
            vec!["p".into(), blake.public_key().to_hex()],
        ]
    );
    let payload: InsightPayload = serde_json::from_str(&event.content).expect("kind-44300 payload");
    assert_eq!(payload.evidence.len(), 1);
    let payload_json: Value = serde_json::from_str(&event.content).expect("payload JSON");
    assert_eq!(payload_json["category"], "assistant_response");
    assert_eq!(payload_json["priority"], "normal");
    assert!(!event.content.contains("https://"));

    let cited = &payload.evidence[0];
    let citation = cited
        .citation
        .as_ref()
        .expect("private citation descriptor");
    let resolver_id = EvidenceResolverId::try_from(citation.resolver_id.as_str())
        .expect("opaque local resolver id");
    let chunk_hash = hex::decode(cited.source_hash.as_str()).expect("cited chunk hash");
    let current_channels = [PRIVATE_CHANNEL];
    let owner_bytes = blake.public_key().to_bytes();
    let resolution_request = EvidenceResolveRequest {
        item_id: resolver_id.source_item_id(),
        chunk_hash: &chunk_hash,
        channel_id: PRIVATE_CHANNEL,
        audience: ServerResolvedSourceAudience::new(&owner_bytes, &current_channels),
    };
    let relay = Keys::generate();
    let resolve_now = Utc::now().timestamp();
    let request_payload: EvidenceResolveRequestPayload = serde_json::from_value(json!({
        "schema_version": 1,
        "request_id": Uuid::new_v4(),
        "insight_id": payload.insight_id,
        "resolver_id": citation.resolver_id,
        "expected_chunk_hash": cited.source_hash,
        "nonce": "ab".repeat(32),
        "created_at": resolve_now,
        "expires_at": resolve_now + 60
    }))
    .expect("kind-24823 payload");
    let resolve_request_event = buzz_sdk::core_protocol::build_core_evidence_resolve_request(
        PRIVATE_CHANNEL,
        &relay.public_key(),
        &request_payload,
        resolve_now,
    )
    .expect("relay evidence request")
    .sign_with_keys(&blake)
    .expect("sign relay evidence request");
    assert_eq!(resolve_request_event.kind.as_u16(), 24_823);

    let resolved = match resolve_source_evidence(&pool, community, resolution_request)
        .await
        .expect("resolve current authorized evidence")
    {
        EvidenceResolution::Resolved(resolved) => resolved,
        other => panic!("expected current authorized evidence, got {other:?}"),
    };
    let result_payload = EvidenceResolveResultPayload::resolved(
        request_payload.request_id,
        request_payload.expires_at,
        &resolved.title,
        resolved.modified_at.timestamp(),
        EvidenceResolvedSourceType::CrmRecord,
        &resolved.resolvable_link,
        resolve_now,
    )
    .expect("kind-24824 payload");
    let resolve_result_event = buzz_sdk::core_protocol::encrypt_core_evidence_resolve_result(
        PRIVATE_CHANNEL,
        &blake.public_key(),
        &relay,
        &result_payload,
        resolve_now,
    )
    .expect("encrypted relay evidence result")
    .sign_with_keys(&relay)
    .expect("sign relay evidence result");
    assert_eq!(resolve_result_event.kind.as_u16(), 24_824);

    sqlx::query(
        "UPDATE source_chunks SET content_hash=$3 \
         WHERE community_id=$1 AND item_id=$2 AND content_hash=$4",
    )
    .bind(community.as_uuid())
    .bind(resolver_id.source_item_id())
    .bind(vec![88_u8; 32])
    .bind(&chunk_hash)
    .execute(&pool)
    .await
    .expect("simulate changed source chunk");
    assert_eq!(
        resolve_source_evidence(&pool, community, resolution_request)
            .await
            .expect("deny changed source chunk"),
        EvidenceResolution::Stale
    );
    sqlx::query(
        "UPDATE source_chunks SET content_hash=$3 \
         WHERE community_id=$1 AND item_id=$2 AND content_hash=$4",
    )
    .bind(community.as_uuid())
    .bind(resolver_id.source_item_id())
    .bind(&chunk_hash)
    .bind(vec![88_u8; 32])
    .execute(&pool)
    .await
    .expect("restore cited source chunk");

    sqlx::query(
        "UPDATE source_items SET status='unavailable', tombstoned_at=NOW() \
         WHERE community_id=$1 AND id=$2",
    )
    .bind(community.as_uuid())
    .bind(resolver_id.source_item_id())
    .execute(&pool)
    .await
    .expect("tombstone evidence before resolution");
    assert_eq!(
        resolve_source_evidence(&pool, community, resolution_request)
            .await
            .expect("deny tombstoned evidence"),
        EvidenceResolution::Unavailable
    );
    sqlx::query(
        "UPDATE source_items SET status='active', tombstoned_at=NULL \
         WHERE community_id=$1 AND id=$2",
    )
    .bind(community.as_uuid())
    .bind(resolver_id.source_item_id())
    .execute(&pool)
    .await
    .expect("restore evidence after tombstone proof");

    sqlx::query("DELETE FROM source_item_acls WHERE community_id=$1 AND item_id=$2")
        .bind(community.as_uuid())
        .bind(resolver_id.source_item_id())
        .execute(&pool)
        .await
        .expect("revoke evidence immediately before resolution");
    assert_eq!(
        resolve_source_evidence(&pool, community, resolution_request)
            .await
            .expect("deny freshly revoked evidence"),
        EvidenceResolution::Denied
    );
    sqlx::query(
        "INSERT INTO source_item_acls \
         (community_id, item_id, principal_type, principal_pubkey) \
         VALUES ($1, $2, 'user', $3)",
    )
    .bind(community.as_uuid())
    .bind(resolver_id.source_item_id())
    .bind(owner_bytes.as_slice())
    .execute(&pool)
    .await
    .expect("restore synthetic user ACL for later race proof");

    let raw_source_body = page.upserts()[0].source().as_untrusted_text();
    let opaque_external_id = page.upserts()[0].external_item_id().as_str();
    let log_visible = format!(
        "{page:?}{turn:?}{:?}{:?}",
        page.upserts()[0],
        payload.evidence
    );
    let visible_outputs = format!("{}{}{}", model.inputs.join(""), event.content, log_visible);
    for forbidden in [
        raw_source_body,
        opaque_external_id,
        CREDENTIAL_REFERENCE,
        &account_id.to_string(),
        &scope_id.to_string(),
        &worker_id.to_string(),
    ] {
        assert!(
            !visible_outputs.contains(forbidden),
            "private raw material reached a model, publish, or Debug surface"
        );
    }
    let model_envelope: Value = serde_json::from_str(
        model.inputs[0]
            .split_once('{')
            .map(|(_, json)| format!("{{{json}"))
            .as_deref()
            .expect("model envelope"),
    )
    .expect("serialized minimized envelope");
    assert_eq!(
        model_envelope.get("trust").and_then(Value::as_str),
        Some("untrusted_external_source")
    );

    sqlx::query(
        "UPDATE connector_delta_cursors \
         SET last_success_at=NOW() - INTERVAL '16 minutes' \
         WHERE community_id=$1 AND account_id=$2 AND scope_id=$3 AND stream=$4",
    )
    .bind(community.as_uuid())
    .bind(account_id)
    .bind(scope_id)
    .bind(STREAM)
    .execute(&pool)
    .await
    .expect("make synthetic cursor stale");
    let mut stale_resolver = resolver(
        community,
        blake.public_key(),
        assistant.public_key(),
        PRIVATE_CHANNEL,
    );
    let mut stale_retriever = PgAuthorizedFtsRetriever::new(&pool);
    let mut stale_model = Model::default();
    let mut stale_sink = Sink::default();
    run_private_assistant_turn(
        &turn,
        &versions(),
        &mut stale_resolver,
        &mut stale_retriever,
        &mut stale_model,
        &mut stale_sink,
        CREATED_AT,
    )
    .await
    .expect("stale evidence remains explicitly labeled");
    let stale_event = stale_sink
        .0
        .pop()
        .expect("one stale publish command")
        .sign_with_keys(&assistant)
        .expect("sign stale synthetic command");
    let stale_payload: Value =
        serde_json::from_str(&stale_event.content).expect("stale insight payload");
    assert_eq!(stale_payload["freshness"], "stale");
    assert!(stale_payload["confidence"]
        .as_u64()
        .is_some_and(|value| value <= 50));

    let mut revoking_resolver = resolver(
        community,
        blake.public_key(),
        assistant.public_key(),
        PRIVATE_CHANNEL,
    );
    let mut revoking_retriever = RevokingPgRetriever {
        pool: &pool,
        community,
        account_id,
        scope_id,
        calls: 0,
    };
    let mut revoking_model = Model::default();
    let mut revoked_sink = Sink::default();
    assert_eq!(
        run_private_assistant_turn(
            &turn,
            &versions(),
            &mut revoking_resolver,
            &mut revoking_retriever,
            &mut revoking_model,
            &mut revoked_sink,
            CREATED_AT,
        )
        .await,
        Err(TurnError::AuthorizationChanged)
    );
    assert_eq!(revoking_retriever.calls, 2);
    assert_eq!(revoking_model.inputs.len(), 1);
    assert!(revoked_sink.0.is_empty());

    drop_scratch_db(&admin, pool, &database_name).await;
}
