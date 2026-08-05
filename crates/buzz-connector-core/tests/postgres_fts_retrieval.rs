use buzz_connector_core::{
    retrieval::{
        retrieve_authorized_fts, source_item_identity_hash, CitationFreshness,
        FullTextRetrievalQuery, RetrievalAudience,
    },
    types::{ConnectorProvider, RemoteVersion, SourceKind},
};
use buzz_core::CommunityId;
use buzz_db::core_storage::{
    recheck_source_chunk_fts, resolve_source_evidence, search_source_chunks_fts, source_chunk_hash,
    EvidenceResolution, EvidenceResolveRequest, ServerResolvedSourceAudience,
    SourceFtsCandidateRecheckRequest, SourceFtsSearchRequest,
};
use sqlx::PgPool;
use uuid::Uuid;

const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz";
const OWNER: [u8; 32] = [3; 32];
const ALLOWED: [u8; 32] = [41; 32];
const DENIED: [u8; 32] = [42; 32];
const CONTENT: &str = "needle confidential evidence";

fn test_db_url() -> String {
    std::env::var("BUZZ_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| TEST_DB_URL.to_owned())
}

async fn scratch_db() -> (PgPool, PgPool, String) {
    let admin = PgPool::connect(&test_db_url())
        .await
        .expect("connect to Postgres test instance");
    let name = format!("connector_fts_{}", Uuid::new_v4().simple());
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

async fn seed_community(pool: &PgPool, label: &str) -> (CommunityId, Uuid) {
    let community = Uuid::new_v4();
    let channel = Uuid::new_v4();
    sqlx::query("INSERT INTO communities (id, host) VALUES ($1, $2)")
        .bind(community)
        .bind(format!("{label}-{}.example", community.simple()))
        .execute(pool)
        .await
        .expect("insert community");
    for pubkey in [OWNER, ALLOWED, DENIED] {
        sqlx::query("INSERT INTO users (community_id, pubkey) VALUES ($1, $2)")
            .bind(community)
            .bind(pubkey.as_slice())
            .execute(pool)
            .await
            .expect("insert user");
    }
    sqlx::query(
        "INSERT INTO channels (community_id, id, name, created_by) VALUES ($1, $2, $3, $4)",
    )
    .bind(community)
    .bind(channel)
    .bind(format!("{label}-channel"))
    .bind(OWNER.as_slice())
    .execute(pool)
    .await
    .expect("insert channel");
    (CommunityId::from_uuid(community), channel)
}

struct SeededSource {
    account_id: Uuid,
    scope_id: Uuid,
    item_id: Uuid,
    chunk_id: Uuid,
}

async fn seed_cursor(
    pool: &PgPool,
    community: CommunityId,
    source: &SeededSource,
    stream: &str,
    state_sql: &str,
) {
    let sql = format!(
        "INSERT INTO connector_delta_cursors \
         (community_id, account_id, scope_id, stream, encrypted_cursor, \
          cursor_integrity_hash, cursor_key_version, last_success_at, next_retry_at, last_error_code) \
         VALUES ($1, $2, $3, $4, decode('01', 'hex'), decode(repeat('11', 32), 'hex'), 1, {state_sql})"
    );
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(community.as_uuid())
        .bind(source.account_id)
        .bind(source.scope_id)
        .bind(stream)
        .execute(pool)
        .await
        .expect("insert connector cursor");
}

async fn seed_source(pool: &PgPool, community: CommunityId, channel_id: Uuid) -> SeededSource {
    let account_id = Uuid::new_v4();
    let scope_id = Uuid::new_v4();
    let item_id = Uuid::new_v4();
    let chunk_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO connector_accounts \
         (community_id, id, provider, owner_pubkey, external_account_id, credential_reference) \
         VALUES ($1, $2, 'microsoft_graph', $3, $4, $5)",
    )
    .bind(community.as_uuid())
    .bind(account_id)
    .bind(OWNER.as_slice())
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
    .expect("insert scope");
    sqlx::query(
        "INSERT INTO source_items \
         (community_id, id, account_id, scope_id, external_item_id, remote_version, \
          remote_etag, title, source_type, modified_at, resolvable_link, last_authorization_check_at) \
         VALUES ($1, $2, $3, $4, $5, 'v1', 'etag-v1', 'Needle source', 'document', \
                 NOW() - INTERVAL '1 minute', 'https://contoso.sharepoint.com/item', NOW())",
    )
    .bind(community.as_uuid())
    .bind(item_id)
    .bind(account_id)
    .bind(scope_id)
    .bind(format!("external-{item_id}"))
    .execute(pool)
    .await
    .expect("insert source item");
    sqlx::query(
        "INSERT INTO source_chunks \
         (community_id, id, item_id, chunk_index, start_char, end_char, content, content_hash) \
         VALUES ($1, $2, $3, 0, 0, 28, $4, $5)",
    )
    .bind(community.as_uuid())
    .bind(chunk_id)
    .bind(item_id)
    .bind(CONTENT)
    .bind(source_chunk_hash(0, 0, 28, CONTENT).to_vec())
    .execute(pool)
    .await
    .expect("insert source chunk without embedding");
    sqlx::query(
        "INSERT INTO source_item_acls \
         (community_id, id, item_id, principal_type, principal_pubkey) \
         VALUES ($1, $2, $3, 'user', $4)",
    )
    .bind(community.as_uuid())
    .bind(Uuid::new_v4())
    .bind(item_id)
    .bind(ALLOWED.as_slice())
    .execute(pool)
    .await
    .expect("insert user ACL");
    sqlx::query(
        "INSERT INTO source_item_acls \
         (community_id, id, item_id, principal_type, channel_id) \
         VALUES ($1, $2, $3, 'channel', $4)",
    )
    .bind(community.as_uuid())
    .bind(Uuid::new_v4())
    .bind(item_id)
    .bind(channel_id)
    .execute(pool)
    .await
    .expect("insert channel ACL");
    SeededSource {
        account_id,
        scope_id,
        item_id,
        chunk_id,
    }
}

fn query(community: CommunityId, caller: [u8; 32], channels: Vec<Uuid>) -> FullTextRetrievalQuery {
    FullTextRetrievalQuery::new(
        *community.as_uuid(),
        RetrievalAudience::server_resolved(caller, channels),
        "needle",
        10,
    )
    .expect("valid FTS query")
}

async fn read_freshness(pool: &PgPool, community: CommunityId) -> CitationFreshness {
    retrieve_authorized_fts(pool, community, &query(community, ALLOWED, vec![]))
        .await
        .expect("authorized freshness read")[0]
        .citation()
        .freshness
}

#[test]
fn item_identity_hash_is_domain_separated_and_binds_full_authority() {
    let original = source_item_identity_hash(
        Uuid::from_u128(1),
        Uuid::from_u128(2),
        Uuid::from_u128(3),
        "provider-item-9",
    )
    .expect("valid item identity");
    assert_eq!(
        hex::encode(original),
        "4d3d88ad0c0137025a8f72feafbf980df44bbec493b6731ee3c9f69e5f8fe7b0"
    );
    assert_ne!(
        original,
        source_item_identity_hash(
            Uuid::from_u128(9),
            Uuid::from_u128(2),
            Uuid::from_u128(3),
            "provider-item-9",
        )
        .expect("valid alternate tenant")
    );
    assert_ne!(
        original,
        source_item_identity_hash(
            Uuid::from_u128(1),
            Uuid::from_u128(9),
            Uuid::from_u128(3),
            "provider-item-9",
        )
        .expect("valid alternate account")
    );
    assert_ne!(
        original,
        source_item_identity_hash(
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            Uuid::from_u128(9),
            "provider-item-9",
        )
        .expect("valid alternate scope")
    );
    assert_ne!(
        original,
        source_item_identity_hash(
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            Uuid::from_u128(3),
            "provider-item-10",
        )
        .expect("valid alternate item")
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn fts_adapter_retrieves_before_embeddings_and_enforces_current_authority() {
    let (admin, pool, name) = scratch_db().await;
    let (community, channel) = seed_community(&pool, "fts-a").await;
    let (other_community, _) = seed_community(&pool, "fts-b").await;
    let source = seed_source(&pool, community, channel).await;

    let embedding_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM embedding_versions")
        .fetch_one(&pool)
        .await
        .expect("count embedding versions");
    assert_eq!(embedding_rows, 0, "FTS must work before embeddings exist");

    let excerpts = retrieve_authorized_fts(&pool, community, &query(community, ALLOWED, vec![]))
        .await
        .expect("authorized FTS retrieval");
    assert_eq!(excerpts.len(), 1);
    assert_eq!(excerpts[0].text(), CONTENT);
    assert_eq!(excerpts[0].source_item_id(), Some(source.item_id));
    assert_eq!(
        excerpts[0].citation().freshness,
        CitationFreshness::Stale,
        "a scope with no configured cursor is stale"
    );
    assert_eq!(
        excerpts[0].citation().provider,
        ConnectorProvider::MicrosoftGraph
    );
    assert_eq!(excerpts[0].citation().source_kind, SourceKind::Document);
    assert_eq!(
        excerpts[0].citation().version_hash,
        RemoteVersion::new("v1", Some("etag-v1".into()))
            .expect("valid version")
            .digest()
    );

    assert!(
        retrieve_authorized_fts(&pool, community, &query(community, DENIED, vec![]))
            .await
            .expect("denied-user search")
            .is_empty()
    );
    assert!(
        retrieve_authorized_fts(&pool, community, &query(community, DENIED, vec![channel]),)
            .await
            .expect("forged-channel search")
            .is_empty()
    );
    assert!(retrieve_authorized_fts(
        &pool,
        other_community,
        &query(other_community, ALLOWED, vec![channel]),
    )
    .await
    .expect("other-tenant search")
    .is_empty());
    assert!(
        retrieve_authorized_fts(&pool, other_community, &query(community, ALLOWED, vec![]),)
            .await
            .is_err()
    );

    sqlx::query(
        "INSERT INTO channel_members (community_id, channel_id, pubkey, role) \
         VALUES ($1, $2, $3, 'member')",
    )
    .bind(community.as_uuid())
    .bind(channel)
    .bind(DENIED.as_slice())
    .execute(&pool)
    .await
    .expect("grant current channel membership");
    assert_eq!(
        retrieve_authorized_fts(&pool, community, &query(community, DENIED, vec![channel]),)
            .await
            .expect("current channel member search")
            .len(),
        1
    );
    sqlx::query(
        "UPDATE channel_members SET removed_at=NOW() \
         WHERE community_id=$1 AND channel_id=$2 AND pubkey=$3",
    )
    .bind(community.as_uuid())
    .bind(channel)
    .bind(DENIED.as_slice())
    .execute(&pool)
    .await
    .expect("revoke channel membership");
    assert!(
        retrieve_authorized_fts(&pool, community, &query(community, DENIED, vec![channel]),)
            .await
            .expect("revoked channel search")
            .is_empty()
    );

    sqlx::query("UPDATE source_items SET tombstoned_at=NOW() WHERE community_id=$1 AND id=$2")
        .bind(community.as_uuid())
        .bind(source.item_id)
        .execute(&pool)
        .await
        .expect("tombstone source");
    assert!(
        retrieve_authorized_fts(&pool, community, &query(community, ALLOWED, vec![]))
            .await
            .expect("tombstoned search")
            .is_empty()
    );
    sqlx::query("UPDATE source_items SET tombstoned_at=NULL WHERE community_id=$1 AND id=$2")
        .bind(community.as_uuid())
        .bind(source.item_id)
        .execute(&pool)
        .await
        .expect("restore source");
    sqlx::query(
        "UPDATE approved_source_scopes SET status='paused' \
         WHERE community_id=$1 AND account_id=$2 AND id=$3",
    )
    .bind(community.as_uuid())
    .bind(source.account_id)
    .bind(source.scope_id)
    .execute(&pool)
    .await
    .expect("pause source scope");
    assert!(
        retrieve_authorized_fts(&pool, community, &query(community, ALLOWED, vec![]))
            .await
            .expect("inactive-scope search")
            .is_empty()
    );

    drop_scratch_db(&admin, pool, &name).await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn fts_freshness_requires_every_configured_cursor_to_be_recent_and_healthy() {
    let (admin, pool, name) = scratch_db().await;
    let (community, channel) = seed_community(&pool, "fts-freshness").await;
    let source = seed_source(&pool, community, channel).await;

    assert_eq!(
        read_freshness(&pool, community).await,
        CitationFreshness::Stale
    );

    seed_cursor(&pool, community, &source, "messages", "NOW(), NULL, NULL").await;
    assert_eq!(
        read_freshness(&pool, community).await,
        CitationFreshness::Fresh
    );

    seed_cursor(
        &pool,
        community,
        &source,
        "calendar",
        "NOW() - INTERVAL '16 minutes', NULL, NULL",
    )
    .await;
    assert_eq!(
        read_freshness(&pool, community).await,
        CitationFreshness::Stale
    );

    sqlx::query(
        "UPDATE connector_delta_cursors SET last_success_at=NOW(), \
         next_retry_at=NOW() + INTERVAL '1 minute', last_error_code='retry' \
         WHERE community_id=$1 AND account_id=$2 AND scope_id=$3 AND stream='calendar'",
    )
    .bind(community.as_uuid())
    .bind(source.account_id)
    .bind(source.scope_id)
    .execute(&pool)
    .await
    .expect("mark cursor retrying");
    assert_eq!(
        read_freshness(&pool, community).await,
        CitationFreshness::Stale
    );

    sqlx::query(
        "UPDATE connector_delta_cursors SET next_retry_at=NULL, last_error_code=NULL \
         WHERE community_id=$1 AND account_id=$2 AND scope_id=$3",
    )
    .bind(community.as_uuid())
    .bind(source.account_id)
    .bind(source.scope_id)
    .execute(&pool)
    .await
    .expect("make all cursors healthy");
    assert_eq!(
        read_freshness(&pool, community).await,
        CitationFreshness::Fresh
    );

    drop_scratch_db(&admin, pool, &name).await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn evidence_resolution_returns_metadata_only_after_current_complete_authorization() {
    let (admin, pool, name) = scratch_db().await;
    let (community, channel) = seed_community(&pool, "evidence-a").await;
    let (other_community, _) = seed_community(&pool, "evidence-b").await;
    let source = seed_source(&pool, community, channel).await;
    let chunk_hash = source_chunk_hash(0, 0, 28, CONTENT);
    let direct_audience = ServerResolvedSourceAudience::new(ALLOWED.as_slice(), &[]);

    let resolved = resolve_source_evidence(
        &pool,
        community,
        EvidenceResolveRequest {
            item_id: source.item_id,
            chunk_hash: &chunk_hash,
            channel_id: channel,
            audience: direct_audience,
        },
    )
    .await
    .expect("resolve authorized source");
    let EvidenceResolution::Resolved(metadata) = resolved else {
        panic!("authorized evidence must resolve");
    };
    assert_eq!(metadata.title, "Needle source");
    assert_eq!(metadata.source_type, "document");
    assert_eq!(
        metadata.resolvable_link,
        "https://contoso.sharepoint.com/item"
    );

    assert!(!matches!(
        resolve_source_evidence(
            &pool,
            other_community,
            EvidenceResolveRequest {
                item_id: source.item_id,
                chunk_hash: &chunk_hash,
                channel_id: channel,
                audience: direct_audience,
            },
        )
        .await
        .expect("cross-tenant resolution"),
        EvidenceResolution::Resolved(_)
    ));
    let denied_audience = ServerResolvedSourceAudience::new(DENIED.as_slice(), &[]);
    assert_eq!(
        resolve_source_evidence(
            &pool,
            community,
            EvidenceResolveRequest {
                item_id: source.item_id,
                chunk_hash: &chunk_hash,
                channel_id: channel,
                audience: denied_audience,
            },
        )
        .await
        .expect("denied-user resolution"),
        EvidenceResolution::Denied
    );
    let forged_channels = [channel];
    let forged_channel_audience =
        ServerResolvedSourceAudience::new(DENIED.as_slice(), &forged_channels);
    assert_eq!(
        resolve_source_evidence(
            &pool,
            community,
            EvidenceResolveRequest {
                item_id: source.item_id,
                chunk_hash: &chunk_hash,
                channel_id: channel,
                audience: forged_channel_audience,
            },
        )
        .await
        .expect("non-member channel resolution"),
        EvidenceResolution::Denied
    );

    let different_channel = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO channels (community_id, id, name, created_by) VALUES ($1, $2, $3, $4)",
    )
    .bind(community.as_uuid())
    .bind(different_channel)
    .bind("different-private-channel")
    .bind(OWNER.as_slice())
    .execute(&pool)
    .await
    .expect("insert different request channel");
    sqlx::query(
        "INSERT INTO channel_members (community_id, channel_id, pubkey, role) \
         VALUES ($1, $2, $3, 'member')",
    )
    .bind(community.as_uuid())
    .bind(channel)
    .bind(DENIED.as_slice())
    .execute(&pool)
    .await
    .expect("grant membership in source-authorized channel");
    let authorized_channels = [channel, different_channel];
    let multi_channel_audience =
        ServerResolvedSourceAudience::new(DENIED.as_slice(), &authorized_channels);
    assert_eq!(
        resolve_source_evidence(
            &pool,
            community,
            EvidenceResolveRequest {
                item_id: source.item_id,
                chunk_hash: &chunk_hash,
                channel_id: different_channel,
                audience: multi_channel_audience,
            },
        )
        .await
        .expect("different-channel resolution"),
        EvidenceResolution::Denied,
        "an ACL on another authorized channel must not resolve in this channel"
    );

    let changed_hash = [9_u8; 32];
    assert_eq!(
        resolve_source_evidence(
            &pool,
            community,
            EvidenceResolveRequest {
                item_id: source.item_id,
                chunk_hash: &changed_hash,
                channel_id: channel,
                audience: direct_audience,
            },
        )
        .await
        .expect("changed-hash resolution"),
        EvidenceResolution::Stale
    );

    sqlx::query(
        "DELETE FROM source_item_acls WHERE community_id=$1 AND item_id=$2 AND principal_type='user'",
    )
    .bind(community.as_uuid())
    .bind(source.item_id)
    .execute(&pool)
    .await
    .expect("revoke direct ACL");
    assert_eq!(
        resolve_source_evidence(
            &pool,
            community,
            EvidenceResolveRequest {
                item_id: source.item_id,
                chunk_hash: &chunk_hash,
                channel_id: channel,
                audience: direct_audience,
            },
        )
        .await
        .expect("revoked resolution"),
        EvidenceResolution::Denied
    );

    sqlx::query(
        "INSERT INTO source_item_acls \
         (community_id, id, item_id, principal_type, principal_pubkey) \
         VALUES ($1, $2, $3, 'user', $4)",
    )
    .bind(community.as_uuid())
    .bind(Uuid::new_v4())
    .bind(source.item_id)
    .bind(ALLOWED.as_slice())
    .execute(&pool)
    .await
    .expect("restore direct ACL");
    sqlx::query("UPDATE source_items SET tombstoned_at=NOW() WHERE community_id=$1 AND id=$2")
        .bind(community.as_uuid())
        .bind(source.item_id)
        .execute(&pool)
        .await
        .expect("tombstone source");
    assert_eq!(
        resolve_source_evidence(
            &pool,
            community,
            EvidenceResolveRequest {
                item_id: source.item_id,
                chunk_hash: &chunk_hash,
                channel_id: channel,
                audience: direct_audience,
            },
        )
        .await
        .expect("tombstoned resolution"),
        EvidenceResolution::Unavailable
    );
    sqlx::query("UPDATE source_items SET tombstoned_at=NULL WHERE community_id=$1 AND id=$2")
        .bind(community.as_uuid())
        .bind(source.item_id)
        .execute(&pool)
        .await
        .expect("restore source after tombstone check");
    sqlx::query(
        "UPDATE approved_source_scopes SET status='paused' \
         WHERE community_id=$1 AND account_id=$2 AND id=$3",
    )
    .bind(community.as_uuid())
    .bind(source.account_id)
    .bind(source.scope_id)
    .execute(&pool)
    .await
    .expect("pause evidence scope");
    assert_eq!(
        resolve_source_evidence(
            &pool,
            community,
            EvidenceResolveRequest {
                item_id: source.item_id,
                chunk_hash: &chunk_hash,
                channel_id: channel,
                audience: direct_audience,
            },
        )
        .await
        .expect("paused-scope resolution"),
        EvidenceResolution::Unavailable
    );

    drop_scratch_db(&admin, pool, &name).await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn fts_adapter_fails_closed_on_malformed_ranked_metadata() {
    let (admin, pool, name) = scratch_db().await;
    let (community, channel) = seed_community(&pool, "fts-malformed").await;
    let source = seed_source(&pool, community, channel).await;
    sqlx::query(
        "UPDATE source_items SET resolvable_link='not a URL' WHERE community_id=$1 AND id=$2",
    )
    .bind(community.as_uuid())
    .bind(source.item_id)
    .execute(&pool)
    .await
    .expect("seed malformed stored metadata");

    assert!(
        retrieve_authorized_fts(&pool, community, &query(community, ALLOWED, vec![]))
            .await
            .is_err()
    );
    let embedding_version_id: Option<Uuid> =
        sqlx::query_scalar("SELECT embedding_version_id FROM source_chunks WHERE id=$1")
            .bind(source.chunk_id)
            .fetch_one(&pool)
            .await
            .expect("read embedding-free chunk");
    assert_eq!(embedding_version_id, None);

    drop_scratch_db(&admin, pool, &name).await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn fts_recheck_omits_ranked_candidates_after_revocation_or_version_change() {
    let (admin, pool, name) = scratch_db().await;
    let (community, channel) = seed_community(&pool, "fts-race").await;
    let source = seed_source(&pool, community, channel).await;
    let audience = ServerResolvedSourceAudience::new(ALLOWED.as_slice(), &[]);
    let ranked = search_source_chunks_fts(
        &pool,
        community,
        SourceFtsSearchRequest {
            query: "needle",
            audience,
            limit: 10,
        },
    )
    .await
    .expect("rank authorized candidate")
    .pop()
    .expect("ranked candidate");

    sqlx::query(
        "DELETE FROM source_item_acls \
         WHERE community_id=$1 AND item_id=$2 AND principal_type='user'",
    )
    .bind(community.as_uuid())
    .bind(source.item_id)
    .execute(&pool)
    .await
    .expect("revoke user ACL after rank");
    assert!(recheck_source_chunk_fts(
        &pool,
        community,
        SourceFtsCandidateRecheckRequest {
            item_id: ranked.item_id,
            chunk_id: ranked.chunk_id,
            remote_version: &ranked.remote_version,
            remote_etag: ranked.remote_etag.as_deref(),
            chunk_hash: &ranked.chunk_hash,
            reconciliation_fresh: ranked.reconciliation_fresh,
            audience,
        },
    )
    .await
    .expect("recheck revoked candidate")
    .is_none());

    sqlx::query(
        "INSERT INTO source_item_acls \
         (community_id, id, item_id, principal_type, principal_pubkey) \
         VALUES ($1, $2, $3, 'user', $4)",
    )
    .bind(community.as_uuid())
    .bind(Uuid::new_v4())
    .bind(source.item_id)
    .bind(ALLOWED.as_slice())
    .execute(&pool)
    .await
    .expect("restore user ACL");
    sqlx::query("UPDATE source_items SET remote_version='v2' WHERE community_id=$1 AND id=$2")
        .bind(community.as_uuid())
        .bind(source.item_id)
        .execute(&pool)
        .await
        .expect("change remote version after rank");
    assert!(recheck_source_chunk_fts(
        &pool,
        community,
        SourceFtsCandidateRecheckRequest {
            item_id: ranked.item_id,
            chunk_id: ranked.chunk_id,
            remote_version: &ranked.remote_version,
            remote_etag: ranked.remote_etag.as_deref(),
            chunk_hash: &ranked.chunk_hash,
            reconciliation_fresh: ranked.reconciliation_fresh,
            audience,
        },
    )
    .await
    .expect("recheck changed candidate")
    .is_none());

    drop_scratch_db(&admin, pool, &name).await;
}
