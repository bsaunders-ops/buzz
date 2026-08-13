use buzz_core::CommunityId;
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgRow, PgPool, Row};
use url::Url;

use super::{
    require_hash, require_pubkey, source_chunk_hash, AuthorizedSourceExcerptRecord,
    AuthorizedSourceFtsExcerptRecord, EvidenceResolution, EvidenceResolveRequest,
    ResolvedSourceEvidence, SourceCandidateRecheckRequest, SourceCitationRecord,
    SourceFtsCandidateRecheckRequest, SourceFtsCitationRecord, SourceFtsSearchRequest,
    SourceSearchRequest, SourceVectorSearchRequest, EMBEDDING_DIMENSIONS,
};

const RECONCILIATION_FRESHNESS_MINUTES: i32 = 15;

fn validate_limit(limit: i64) -> crate::Result<()> {
    if !(1..=100).contains(&limit) {
        return Err(crate::DbError::InvalidData(
            "source search limit must be between 1 and 100".into(),
        ));
    }
    Ok(())
}

fn citation_from_row(row: PgRow) -> crate::Result<SourceCitationRecord> {
    Ok(SourceCitationRecord {
        item_id: row.try_get("item_id")?,
        chunk_id: row.try_get("chunk_id")?,
        account_id: row.try_get("account_id")?,
        scope_id: row.try_get("scope_id")?,
        external_item_id: row.try_get("external_item_id")?,
        provider: row.try_get("provider")?,
        title: row.try_get("title")?,
        source_type: row.try_get("source_type")?,
        modified_at: row.try_get("modified_at")?,
        resolvable_link: row.try_get("resolvable_link")?,
        remote_version: row.try_get("remote_version")?,
        remote_etag: row.try_get("remote_etag")?,
        chunk_hash: row.try_get("chunk_hash")?,
        embedding_version_id: row.try_get("embedding_version_id")?,
        start_char: row.try_get("start_char")?,
        end_char: row.try_get("end_char")?,
    })
}

fn fts_citation_from_row(row: PgRow) -> crate::Result<SourceFtsCitationRecord> {
    Ok(SourceFtsCitationRecord {
        item_id: row.try_get("item_id")?,
        chunk_id: row.try_get("chunk_id")?,
        account_id: row.try_get("account_id")?,
        scope_id: row.try_get("scope_id")?,
        external_item_id: row.try_get("external_item_id")?,
        provider: row.try_get("provider")?,
        title: row.try_get("title")?,
        source_type: row.try_get("source_type")?,
        modified_at: row.try_get("modified_at")?,
        resolvable_link: row.try_get("resolvable_link")?,
        remote_version: row.try_get("remote_version")?,
        remote_etag: row.try_get("remote_etag")?,
        chunk_hash: row.try_get("chunk_hash")?,
        start_char: row.try_get("start_char")?,
        end_char: row.try_get("end_char")?,
        reconciliation_fresh: row.try_get("reconciliation_fresh")?,
    })
}

/// Rank full-text source chunks after current tenant, lifecycle, positive ACL,
/// and channel-membership filtering, without requiring an embedding version.
pub async fn search_source_chunks_fts(
    pool: &PgPool,
    community_id: CommunityId,
    request: SourceFtsSearchRequest<'_>,
) -> crate::Result<Vec<SourceFtsCitationRecord>> {
    let requester_pubkey = request.audience.requester_pubkey();
    let authorized_channel_ids = request.audience.authorized_channel_ids();
    require_pubkey("requester_pubkey", requester_pubkey)?;
    validate_limit(request.limit)?;
    if request.query.trim().is_empty() {
        return Ok(Vec::new());
    }
    if request.query.chars().count() > 1_024 || request.query.contains('\0') {
        return Err(crate::DbError::InvalidData(
            "source search query is invalid".into(),
        ));
    }

    let rows = sqlx::query(
        "WITH eligible_items AS MATERIALIZED ( \
             SELECT i.community_id, i.id, i.account_id, i.scope_id, i.external_item_id, \
                    a.provider, i.title, i.source_type, i.modified_at, \
                    i.resolvable_link, i.remote_version, i.remote_etag, \
                    (EXISTS ( \
                        SELECT 1 FROM connector_delta_cursors cursor \
                        WHERE cursor.community_id=i.community_id \
                          AND cursor.account_id=i.account_id AND cursor.scope_id=i.scope_id \
                    ) AND NOT EXISTS ( \
                        SELECT 1 FROM connector_delta_cursors cursor \
                        WHERE cursor.community_id=i.community_id \
                          AND cursor.account_id=i.account_id AND cursor.scope_id=i.scope_id \
                          AND (cursor.last_success_at IS NULL \
                               OR cursor.last_success_at < statement_timestamp() - make_interval(mins => $6) \
                               OR cursor.last_success_at > statement_timestamp() \
                               OR cursor.next_retry_at IS NOT NULL \
                               OR cursor.last_error_code IS NOT NULL) \
                    )) AS reconciliation_fresh \
             FROM source_items i \
             JOIN connector_accounts a \
               ON a.community_id=i.community_id AND a.id=i.account_id AND a.status='active' \
             JOIN approved_source_scopes s \
               ON s.community_id=i.community_id AND s.account_id=i.account_id \
              AND s.id=i.scope_id AND s.status='active' AND s.can_read \
             WHERE i.community_id=$1 AND i.status='active' AND i.tombstoned_at IS NULL \
               AND EXISTS ( \
                   SELECT 1 FROM source_item_acls acl \
                   WHERE acl.community_id=i.community_id AND acl.item_id=i.id \
                     AND ( \
                       (acl.principal_type='user' AND acl.principal_pubkey=$2) \
                       OR \
                       (acl.principal_type='channel' AND acl.channel_id=ANY($3::uuid[]) \
                        AND EXISTS ( \
                            SELECT 1 FROM channel_members member \
                            WHERE member.community_id=acl.community_id \
                              AND member.channel_id=acl.channel_id \
                              AND member.pubkey=$2 AND member.removed_at IS NULL \
                        )) \
                     ) \
               ) \
         ) \
         SELECT i.id AS item_id, c.id AS chunk_id, i.account_id, i.scope_id, \
                i.external_item_id, i.provider, i.title, i.source_type, i.modified_at, \
                i.resolvable_link, i.remote_version, i.remote_etag, \
                c.content_hash AS chunk_hash, c.start_char, c.end_char, \
                i.reconciliation_fresh \
         FROM eligible_items i \
         JOIN source_chunks c ON c.community_id=i.community_id AND c.item_id=i.id \
         WHERE c.search_tsv @@ websearch_to_tsquery('simple', $4) \
         ORDER BY ts_rank_cd(c.search_tsv, websearch_to_tsquery('simple', $4)) DESC, \
                  i.id, c.id \
         LIMIT $5",
    )
    .bind(community_id.as_uuid())
    .bind(requester_pubkey)
    .bind(authorized_channel_ids)
    .bind(request.query)
    .bind(request.limit)
    .bind(RECONCILIATION_FRESHNESS_MINUTES)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(fts_citation_from_row).collect()
}

/// Search source chunks after a materialized positive ACL and lifecycle filter.
pub async fn search_source_chunks(
    pool: &PgPool,
    community_id: CommunityId,
    request: SourceSearchRequest<'_>,
) -> crate::Result<Vec<SourceCitationRecord>> {
    require_pubkey("requester_pubkey", request.requester_pubkey)?;
    validate_limit(request.limit)?;
    if request.query.trim().is_empty() {
        return Ok(Vec::new());
    }
    if request.query.chars().count() > 1_024 || request.query.contains('\0') {
        return Err(crate::DbError::InvalidData(
            "source search query is invalid".into(),
        ));
    }

    let rows = sqlx::query(
        "WITH eligible_items AS MATERIALIZED ( \
             SELECT i.community_id, i.id, i.account_id, i.scope_id, i.external_item_id, \
                    a.provider, i.title, i.source_type, i.modified_at, \
                    i.resolvable_link, i.remote_version, i.remote_etag \
             FROM source_items i \
             JOIN connector_accounts a \
               ON a.community_id=i.community_id AND a.id=i.account_id AND a.status='active' \
             JOIN approved_source_scopes s \
               ON s.community_id=i.community_id AND s.account_id=i.account_id \
              AND s.id=i.scope_id AND s.status='active' AND s.can_read \
             WHERE i.community_id=$1 AND i.status='active' AND i.tombstoned_at IS NULL \
               AND EXISTS ( \
                   SELECT 1 FROM source_item_acls acl \
                   WHERE acl.community_id=i.community_id AND acl.item_id=i.id \
                     AND ( \
                       (acl.principal_type='user' AND acl.principal_pubkey=$2) \
                       OR \
                       (acl.principal_type='channel' AND acl.channel_id=ANY($3::uuid[]) \
                        AND EXISTS ( \
                            SELECT 1 FROM channel_members member \
                            WHERE member.community_id=acl.community_id \
                              AND member.channel_id=acl.channel_id \
                              AND member.pubkey=$2 \
                              AND member.removed_at IS NULL \
                        )) \
                     ) \
               ) \
         ), eligible_chunks AS MATERIALIZED ( \
             SELECT i.id AS item_id, c.id AS chunk_id, i.account_id, i.scope_id, \
                    i.external_item_id, i.provider, i.title, i.source_type, i.modified_at, \
                    i.resolvable_link, i.remote_version, i.remote_etag, \
                    c.content_hash AS chunk_hash, c.start_char, c.end_char, \
                    c.embedding_version_id, c.search_tsv \
             FROM eligible_items i \
             JOIN source_chunks c ON c.community_id=i.community_id AND c.item_id=i.id \
             JOIN embedding_versions ev \
               ON ev.community_id=c.community_id AND ev.id=c.embedding_version_id \
              AND ev.id=$4 AND ev.status='active' AND ev.activated_at IS NOT NULL \
         ) \
         SELECT item_id, chunk_id, account_id, scope_id, external_item_id, provider, \
                title, source_type, modified_at, resolvable_link, remote_version, \
                remote_etag, chunk_hash, embedding_version_id, start_char, end_char \
         FROM eligible_chunks \
         WHERE search_tsv @@ websearch_to_tsquery('simple', $5) \
         ORDER BY ts_rank_cd(search_tsv, websearch_to_tsquery('simple', $5)) DESC, item_id, chunk_id \
         LIMIT $6",
    )
    .bind(community_id.as_uuid())
    .bind(request.requester_pubkey)
    .bind(request.authorized_channel_ids)
    .bind(request.embedding_version_id)
    .bind(request.query)
    .bind(request.limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(citation_from_row).collect()
}

fn pgvector_literal(embedding: &[f32]) -> crate::Result<String> {
    if embedding.len() != EMBEDDING_DIMENSIONS {
        return Err(crate::DbError::InvalidData(format!(
            "embedding must have exactly {EMBEDDING_DIMENSIONS} dimensions"
        )));
    }
    if embedding.iter().any(|value| !value.is_finite()) {
        return Err(crate::DbError::InvalidData(
            "embedding values must be finite".into(),
        ));
    }
    let values = embedding
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!("[{values}]"))
}

/// Rank local pgvector embeddings only after positive ACL/lifecycle filtering.
pub async fn search_source_chunks_by_embedding(
    pool: &PgPool,
    community_id: CommunityId,
    request: SourceVectorSearchRequest<'_>,
) -> crate::Result<Vec<SourceCitationRecord>> {
    require_pubkey("requester_pubkey", request.requester_pubkey)?;
    validate_limit(request.limit)?;
    let vector_storage_available: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname='vector') \
         AND EXISTS (SELECT 1 FROM information_schema.columns \
                     WHERE table_schema='public' AND table_name='source_chunks' AND column_name='embedding')",
    )
    .fetch_one(pool)
    .await?;
    if !vector_storage_available {
        return Err(crate::DbError::InvalidData(
            "local pgvector source storage is not enabled on this database".into(),
        ));
    }
    let embedding = pgvector_literal(request.embedding)?;
    let rows = sqlx::query(
        "WITH eligible_items AS MATERIALIZED ( \
             SELECT i.community_id, i.id, i.account_id, i.scope_id, i.external_item_id, \
                    a.provider, i.title, i.source_type, i.modified_at, \
                    i.resolvable_link, i.remote_version, i.remote_etag \
             FROM source_items i \
             JOIN connector_accounts a \
               ON a.community_id=i.community_id AND a.id=i.account_id AND a.status='active' \
             JOIN approved_source_scopes s \
               ON s.community_id=i.community_id AND s.account_id=i.account_id \
              AND s.id=i.scope_id AND s.status='active' AND s.can_read \
             WHERE i.community_id=$1 AND i.status='active' AND i.tombstoned_at IS NULL \
               AND EXISTS ( \
                   SELECT 1 FROM source_item_acls acl \
                   WHERE acl.community_id=i.community_id AND acl.item_id=i.id \
                     AND ( \
                       (acl.principal_type='user' AND acl.principal_pubkey=$2) \
                       OR \
                       (acl.principal_type='channel' AND acl.channel_id=ANY($3::uuid[]) \
                        AND EXISTS ( \
                            SELECT 1 FROM channel_members member \
                            WHERE member.community_id=acl.community_id \
                              AND member.channel_id=acl.channel_id \
                              AND member.pubkey=$2 \
                              AND member.removed_at IS NULL \
                        )) \
                     ) \
               ) \
         ), eligible_chunks AS MATERIALIZED ( \
             SELECT i.id AS item_id, c.id AS chunk_id, i.account_id, i.scope_id, \
                    i.external_item_id, i.provider, i.title, i.source_type, i.modified_at, \
                    i.resolvable_link, i.remote_version, i.remote_etag, \
                    c.content_hash AS chunk_hash, c.start_char, c.end_char, \
                    c.embedding_version_id, c.embedding \
             FROM eligible_items i \
             JOIN source_chunks c ON c.community_id=i.community_id AND c.item_id=i.id \
             JOIN embedding_versions ev \
               ON ev.community_id=c.community_id AND ev.id=c.embedding_version_id \
              AND ev.id=$4 AND ev.status='active' AND ev.activated_at IS NOT NULL \
             WHERE c.embedding IS NOT NULL \
         ) \
         SELECT item_id, chunk_id, account_id, scope_id, external_item_id, provider, \
                title, source_type, modified_at, resolvable_link, remote_version, \
                remote_etag, chunk_hash, embedding_version_id, start_char, end_char \
         FROM eligible_chunks \
         ORDER BY embedding <=> CAST($5 AS vector), item_id, chunk_id \
         LIMIT $6",
    )
    .bind(community_id.as_uuid())
    .bind(request.requester_pubkey)
    .bind(request.authorized_channel_ids)
    .bind(request.embedding_version_id)
    .bind(embedding)
    .bind(request.limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(citation_from_row).collect()
}

/// Re-read one ranked candidate and return its content only if its exact
/// version, chunk hash, account/scope lifecycle, positive ACL, and current
/// channel membership still authorize the authenticated caller.
pub async fn recheck_source_chunk(
    pool: &PgPool,
    community_id: CommunityId,
    request: SourceCandidateRecheckRequest<'_>,
) -> crate::Result<Option<AuthorizedSourceExcerptRecord>> {
    require_pubkey("requester_pubkey", request.requester_pubkey)?;
    require_hash("chunk_hash", request.chunk_hash)?;
    if request.remote_version.is_empty() || request.remote_version.len() > 512 {
        return Err(crate::DbError::InvalidData(
            "remote_version must be between 1 and 512 bytes".into(),
        ));
    }
    if request
        .remote_etag
        .is_some_and(|etag| etag.is_empty() || etag.len() > 512)
    {
        return Err(crate::DbError::InvalidData(
            "remote_etag must be between 1 and 512 bytes when present".into(),
        ));
    }

    let row = sqlx::query(
        "SELECT i.id AS item_id, c.id AS chunk_id, i.account_id, i.scope_id, \
                i.external_item_id, a.provider, i.title, i.source_type, i.modified_at, \
                i.resolvable_link, i.remote_version, i.remote_etag, c.content_hash AS chunk_hash, \
                c.embedding_version_id, c.chunk_index, c.start_char, c.end_char, \
                c.content, clock_timestamp() AS authorization_checked_at, \
                COALESCE(( \
                    SELECT string_agg( \
                        CASE WHEN acl.principal_type='user' \
                             THEN 'u:' || encode(acl.principal_pubkey, 'hex') \
                             ELSE 'c:' || acl.channel_id::text END, \
                        ',' ORDER BY acl.principal_type, acl.principal_pubkey, acl.channel_id) \
                    FROM source_item_acls acl \
                    WHERE acl.community_id=i.community_id AND acl.item_id=i.id \
                ), '') AS acl_revision_material \
         FROM source_items i \
         JOIN connector_accounts a \
           ON a.community_id=i.community_id AND a.id=i.account_id AND a.status='active' \
         JOIN approved_source_scopes s \
           ON s.community_id=i.community_id AND s.account_id=i.account_id \
          AND s.id=i.scope_id AND s.status='active' AND s.can_read \
         JOIN source_chunks c ON c.community_id=i.community_id AND c.item_id=i.id \
         JOIN embedding_versions ev \
           ON ev.community_id=c.community_id AND ev.id=c.embedding_version_id \
          AND ev.id=$9 AND ev.status='active' AND ev.activated_at IS NOT NULL \
         WHERE i.community_id=$1 AND i.id=$2 AND c.id=$3 \
           AND i.status='active' AND i.tombstoned_at IS NULL \
           AND i.remote_version=$4 AND i.remote_etag IS NOT DISTINCT FROM $5 \
           AND c.content_hash=$6 \
           AND EXISTS ( \
               SELECT 1 FROM source_item_acls acl \
               WHERE acl.community_id=i.community_id AND acl.item_id=i.id \
                 AND ( \
                   (acl.principal_type='user' AND acl.principal_pubkey=$7) \
                   OR \
                   (acl.principal_type='channel' AND acl.channel_id=ANY($8::uuid[]) \
                    AND EXISTS ( \
                        SELECT 1 FROM channel_members member \
                        WHERE member.community_id=acl.community_id \
                          AND member.channel_id=acl.channel_id \
                          AND member.pubkey=$7 AND member.removed_at IS NULL \
                    )) \
                 ) \
           )",
    )
    .bind(community_id.as_uuid())
    .bind(request.item_id)
    .bind(request.chunk_id)
    .bind(request.remote_version)
    .bind(request.remote_etag)
    .bind(request.chunk_hash)
    .bind(request.requester_pubkey)
    .bind(request.authorized_channel_ids)
    .bind(request.embedding_version_id)
    .fetch_optional(pool)
    .await?;

    row.map(|row| {
        let acl_material: String = row.try_get("acl_revision_material")?;
        let chunk_index: i32 = row.try_get("chunk_index")?;
        let start_char: i64 = row.try_get("start_char")?;
        let end_char: i64 = row.try_get("end_char")?;
        let content: String = row.try_get("content")?;
        let chunk_hash: Vec<u8> = row.try_get("chunk_hash")?;
        let content_chars = i64::try_from(content.chars().count()).map_err(|_| {
            crate::DbError::InvalidData("source chunk integrity validation failed".into())
        })?;
        let expected_start = i64::from(chunk_index).checked_mul(1_080);
        let index_u64 = u64::try_from(chunk_index).ok();
        let start_u64 = u64::try_from(start_char).ok();
        let end_u64 = u64::try_from(end_char).ok();
        let integrity_matches =
            index_u64
                .zip(start_u64)
                .zip(end_u64)
                .is_some_and(|((index, start), end)| {
                    expected_start == Some(start_char)
                        && end_char.checked_sub(start_char) == Some(content_chars)
                        && (1..=1_200).contains(&content_chars)
                        && source_chunk_hash(index, start, end, &content).as_slice()
                            == chunk_hash.as_slice()
                });
        if !integrity_matches {
            return Err(crate::DbError::InvalidData(
                "source chunk integrity validation failed".into(),
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(b"core-buzz:source-acl-revision:v1\0");
        hasher.update(community_id.as_uuid().as_bytes());
        hasher.update(request.item_id.as_bytes());
        hasher.update(acl_material.as_bytes());
        Ok(AuthorizedSourceExcerptRecord {
            item_id: row.try_get("item_id")?,
            chunk_id: row.try_get("chunk_id")?,
            account_id: row.try_get("account_id")?,
            scope_id: row.try_get("scope_id")?,
            external_item_id: row.try_get("external_item_id")?,
            provider: row.try_get("provider")?,
            title: row.try_get("title")?,
            source_type: row.try_get("source_type")?,
            modified_at: row.try_get("modified_at")?,
            resolvable_link: row.try_get("resolvable_link")?,
            remote_version: row.try_get("remote_version")?,
            remote_etag: row.try_get("remote_etag")?,
            chunk_hash,
            embedding_version_id: row.try_get("embedding_version_id")?,
            start_char,
            end_char,
            content,
            acl_revision: hasher.finalize().to_vec(),
            authorization_checked_at: row.try_get("authorization_checked_at")?,
        })
    })
    .transpose()
}

/// Re-read an embedding-independent FTS candidate and release its bounded
/// chunk only while the exact item, version, ETag, hash, lifecycle, ACL, and
/// current channel membership still match.
pub async fn recheck_source_chunk_fts(
    pool: &PgPool,
    community_id: CommunityId,
    request: SourceFtsCandidateRecheckRequest<'_>,
) -> crate::Result<Option<AuthorizedSourceFtsExcerptRecord>> {
    let requester_pubkey = request.audience.requester_pubkey();
    let authorized_channel_ids = request.audience.authorized_channel_ids();
    require_pubkey("requester_pubkey", requester_pubkey)?;
    require_hash("chunk_hash", request.chunk_hash)?;
    if request.remote_version.is_empty() || request.remote_version.len() > 512 {
        return Err(crate::DbError::InvalidData(
            "remote_version must be between 1 and 512 bytes".into(),
        ));
    }
    if request
        .remote_etag
        .is_some_and(|etag| etag.is_empty() || etag.len() > 512)
    {
        return Err(crate::DbError::InvalidData(
            "remote_etag must be between 1 and 512 bytes when present".into(),
        ));
    }

    let row = sqlx::query(
        "SELECT i.id AS item_id, c.id AS chunk_id, i.account_id, i.scope_id, \
                i.external_item_id, a.provider, i.title, i.source_type, i.modified_at, \
                i.resolvable_link, i.remote_version, i.remote_etag, c.content_hash AS chunk_hash, \
                c.chunk_index, c.start_char, c.end_char, c.content, \
                (EXISTS ( \
                    SELECT 1 FROM connector_delta_cursors cursor \
                    WHERE cursor.community_id=i.community_id \
                      AND cursor.account_id=i.account_id AND cursor.scope_id=i.scope_id \
                ) AND NOT EXISTS ( \
                    SELECT 1 FROM connector_delta_cursors cursor \
                    WHERE cursor.community_id=i.community_id \
                      AND cursor.account_id=i.account_id AND cursor.scope_id=i.scope_id \
                      AND (cursor.last_success_at IS NULL \
                           OR cursor.last_success_at < statement_timestamp() - make_interval(mins => $10) \
                           OR cursor.last_success_at > statement_timestamp() \
                           OR cursor.next_retry_at IS NOT NULL \
                           OR cursor.last_error_code IS NOT NULL) \
                )) AS reconciliation_fresh, \
                clock_timestamp() AS authorization_checked_at, \
                COALESCE(( \
                    SELECT string_agg( \
                        CASE WHEN acl.principal_type='user' \
                             THEN 'u:' || encode(acl.principal_pubkey, 'hex') \
                             ELSE 'c:' || acl.channel_id::text END, \
                        ',' ORDER BY acl.principal_type, acl.principal_pubkey, acl.channel_id) \
                    FROM source_item_acls acl \
                    WHERE acl.community_id=i.community_id AND acl.item_id=i.id \
                ), '') AS acl_revision_material \
         FROM source_items i \
         JOIN connector_accounts a \
           ON a.community_id=i.community_id AND a.id=i.account_id AND a.status='active' \
         JOIN approved_source_scopes s \
           ON s.community_id=i.community_id AND s.account_id=i.account_id \
          AND s.id=i.scope_id AND s.status='active' AND s.can_read \
         JOIN source_chunks c ON c.community_id=i.community_id AND c.item_id=i.id \
         WHERE i.community_id=$1 AND i.id=$2 AND c.id=$3 \
           AND i.status='active' AND i.tombstoned_at IS NULL \
           AND i.remote_version=$4 AND i.remote_etag IS NOT DISTINCT FROM $5 \
           AND c.content_hash=$6 \
           AND (EXISTS ( \
                SELECT 1 FROM connector_delta_cursors cursor \
                WHERE cursor.community_id=i.community_id \
                  AND cursor.account_id=i.account_id AND cursor.scope_id=i.scope_id \
           ) AND NOT EXISTS ( \
                SELECT 1 FROM connector_delta_cursors cursor \
                WHERE cursor.community_id=i.community_id \
                  AND cursor.account_id=i.account_id AND cursor.scope_id=i.scope_id \
                  AND (cursor.last_success_at IS NULL \
                       OR cursor.last_success_at < statement_timestamp() - make_interval(mins => $10) \
                       OR cursor.last_success_at > statement_timestamp() \
                       OR cursor.next_retry_at IS NOT NULL \
                       OR cursor.last_error_code IS NOT NULL) \
           ))=$9 \
           AND EXISTS ( \
               SELECT 1 FROM source_item_acls acl \
               WHERE acl.community_id=i.community_id AND acl.item_id=i.id \
                 AND ( \
                   (acl.principal_type='user' AND acl.principal_pubkey=$7) \
                   OR \
                   (acl.principal_type='channel' AND acl.channel_id=ANY($8::uuid[]) \
                    AND EXISTS ( \
                        SELECT 1 FROM channel_members member \
                        WHERE member.community_id=acl.community_id \
                          AND member.channel_id=acl.channel_id \
                          AND member.pubkey=$7 AND member.removed_at IS NULL \
                    )) \
                 ) \
           )",
    )
    .bind(community_id.as_uuid())
    .bind(request.item_id)
    .bind(request.chunk_id)
    .bind(request.remote_version)
    .bind(request.remote_etag)
    .bind(request.chunk_hash)
    .bind(requester_pubkey)
    .bind(authorized_channel_ids)
    .bind(request.reconciliation_fresh)
    .bind(RECONCILIATION_FRESHNESS_MINUTES)
    .fetch_optional(pool)
    .await?;

    row.map(|row| {
        let acl_material: String = row.try_get("acl_revision_material")?;
        let chunk_index: i32 = row.try_get("chunk_index")?;
        let start_char: i64 = row.try_get("start_char")?;
        let end_char: i64 = row.try_get("end_char")?;
        let content: String = row.try_get("content")?;
        let chunk_hash: Vec<u8> = row.try_get("chunk_hash")?;
        let content_chars = i64::try_from(content.chars().count()).map_err(|_| {
            crate::DbError::InvalidData("source chunk integrity validation failed".into())
        })?;
        let expected_start = i64::from(chunk_index).checked_mul(1_080);
        let index_u64 = u64::try_from(chunk_index).ok();
        let start_u64 = u64::try_from(start_char).ok();
        let end_u64 = u64::try_from(end_char).ok();
        let integrity_matches =
            index_u64
                .zip(start_u64)
                .zip(end_u64)
                .is_some_and(|((index, start), end)| {
                    expected_start == Some(start_char)
                        && end_char.checked_sub(start_char) == Some(content_chars)
                        && (1..=1_200).contains(&content_chars)
                        && source_chunk_hash(index, start, end, &content).as_slice()
                            == chunk_hash.as_slice()
                });
        if !integrity_matches {
            return Err(crate::DbError::InvalidData(
                "source chunk integrity validation failed".into(),
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(b"core-buzz:source-acl-revision:v1\0");
        hasher.update(community_id.as_uuid().as_bytes());
        hasher.update(request.item_id.as_bytes());
        hasher.update(acl_material.as_bytes());
        Ok(AuthorizedSourceFtsExcerptRecord {
            item_id: row.try_get("item_id")?,
            chunk_id: row.try_get("chunk_id")?,
            account_id: row.try_get("account_id")?,
            scope_id: row.try_get("scope_id")?,
            external_item_id: row.try_get("external_item_id")?,
            provider: row.try_get("provider")?,
            title: row.try_get("title")?,
            source_type: row.try_get("source_type")?,
            modified_at: row.try_get("modified_at")?,
            resolvable_link: row.try_get("resolvable_link")?,
            remote_version: row.try_get("remote_version")?,
            remote_etag: row.try_get("remote_etag")?,
            chunk_hash,
            start_char,
            end_char,
            content,
            acl_revision: hasher.finalize().to_vec(),
            authorization_checked_at: row.try_get("authorization_checked_at")?,
            reconciliation_fresh: row.try_get("reconciliation_fresh")?,
        })
    })
    .transpose()
}

fn evidence_link_is_allowed(provider: &str, raw_link: &str) -> bool {
    let Ok(link) = Url::parse(raw_link) else {
        return false;
    };
    if link.scheme() != "https"
        || link.port().is_some()
        || !link.username().is_empty()
        || link.password().is_some()
        || link.fragment().is_some()
    {
        return false;
    }
    let Some(host) = link.host_str() else {
        return false;
    };
    match provider {
        "microsoft_graph" => {
            host.eq_ignore_ascii_case("outlook.office.com")
                || host.eq_ignore_ascii_case("outlook.office365.com")
                || host
                    .to_ascii_lowercase()
                    .strip_suffix(".sharepoint.com")
                    .is_some_and(|tenant| !tenant.is_empty() && !tenant.contains('.'))
        }
        "google_drive" => [
            "drive.google.com",
            "docs.google.com",
            "sheets.google.com",
            "slides.google.com",
        ]
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed)),
        "core_crm" => host.eq_ignore_ascii_case("crm.coreadvs.com"),
        _ => false,
    }
}

/// Resolve one opaque evidence locator only after a current tenant, lifecycle,
/// exact-revision, scope, ACL, and channel-membership authorization read.
pub async fn resolve_source_evidence(
    pool: &PgPool,
    community_id: CommunityId,
    request: EvidenceResolveRequest<'_>,
) -> crate::Result<EvidenceResolution> {
    let requester_pubkey = request.audience.requester_pubkey();
    require_pubkey("requester_pubkey", requester_pubkey)?;
    require_hash("chunk_hash", request.chunk_hash)?;

    let resolved = sqlx::query(
        "SELECT a.provider, i.title, i.source_type, i.modified_at, i.resolvable_link \
         FROM source_items i \
         JOIN connector_accounts a \
           ON a.community_id=i.community_id AND a.id=i.account_id AND a.status='active' \
         JOIN approved_source_scopes s \
           ON s.community_id=i.community_id AND s.account_id=i.account_id \
          AND s.id=i.scope_id AND s.status='active' AND s.can_read \
         WHERE i.community_id=$1 AND i.id=$2 \
            AND i.status='active' AND i.tombstoned_at IS NULL \
            AND EXISTS ( \
                SELECT 1 FROM channels request_channel \
                JOIN channel_members requester_membership \
                  ON requester_membership.community_id=request_channel.community_id \
                 AND requester_membership.channel_id=request_channel.id \
                 AND requester_membership.pubkey=$4 \
                 AND requester_membership.removed_at IS NULL \
                WHERE request_channel.community_id=i.community_id \
                  AND request_channel.id=$5 \
                  AND request_channel.visibility='private' \
                  AND request_channel.archived_at IS NULL \
                  AND request_channel.deleted_at IS NULL \
            ) \
            AND EXISTS ( \
               SELECT 1 FROM source_chunks chunk \
               WHERE chunk.community_id=i.community_id AND chunk.item_id=i.id \
                 AND chunk.content_hash=$3 \
           ) \
           AND EXISTS ( \
               SELECT 1 FROM source_item_acls acl \
               WHERE acl.community_id=i.community_id AND acl.item_id=i.id \
                 AND ( \
                   (acl.principal_type='user' AND acl.principal_pubkey=$4) \
                   OR \
                   (acl.principal_type='channel' AND acl.channel_id=$5 \
                    AND EXISTS ( \
                        SELECT 1 FROM channel_members member \
                        WHERE member.community_id=acl.community_id \
                          AND member.channel_id=acl.channel_id \
                          AND member.pubkey=$4 AND member.removed_at IS NULL \
                    )) \
                 ) \
           )",
    )
    .bind(community_id.as_uuid())
    .bind(request.item_id)
    .bind(request.chunk_hash)
    .bind(requester_pubkey)
    .bind(request.channel_id)
    .fetch_optional(pool)
    .await?;

    if let Some(row) = resolved {
        let provider: String = row.try_get("provider")?;
        let resolvable_link: String = row.try_get("resolvable_link")?;
        if !evidence_link_is_allowed(&provider, &resolvable_link) {
            return Ok(EvidenceResolution::Unavailable);
        }
        return Ok(EvidenceResolution::Resolved(ResolvedSourceEvidence {
            title: row.try_get("title")?,
            source_type: row.try_get("source_type")?,
            modified_at: row.try_get("modified_at")?,
            resolvable_link,
        }));
    }

    let state = sqlx::query(
        "SELECT i.id IS NOT NULL AS item_exists, i.status, i.tombstoned_at, \
                EXISTS ( \
                    SELECT 1 FROM channels request_channel \
                    JOIN channel_members requester_membership \
                      ON requester_membership.community_id=request_channel.community_id \
                     AND requester_membership.channel_id=request_channel.id \
                     AND requester_membership.pubkey=$3 \
                     AND requester_membership.removed_at IS NULL \
                    WHERE request_channel.community_id=$1 \
                      AND request_channel.id=$4 \
                      AND request_channel.visibility='private' \
                      AND request_channel.archived_at IS NULL \
                      AND request_channel.deleted_at IS NULL \
                ) AS channel_authorized, \
                EXISTS ( \
                    SELECT 1 FROM connector_accounts a \
                    WHERE a.community_id=i.community_id AND a.id=i.account_id \
                      AND a.status='active' \
                ) AND EXISTS ( \
                    SELECT 1 FROM approved_source_scopes s \
                    WHERE s.community_id=i.community_id AND s.account_id=i.account_id \
                      AND s.id=i.scope_id AND s.status='active' AND s.can_read \
                ) AS source_readable, \
                EXISTS ( \
                    SELECT 1 FROM source_item_acls acl \
                    WHERE acl.community_id=i.community_id AND acl.item_id=i.id \
                      AND ( \
                        (acl.principal_type='user' AND acl.principal_pubkey=$3) \
                        OR \
                        (acl.principal_type='channel' AND acl.channel_id=$4 \
                         AND EXISTS ( \
                             SELECT 1 FROM channel_members member \
                             WHERE member.community_id=acl.community_id \
                               AND member.channel_id=acl.channel_id \
                               AND member.pubkey=$3 AND member.removed_at IS NULL \
                         )) \
                      ) \
                ) AS has_authority, \
                EXISTS ( \
                    SELECT 1 FROM source_chunks chunk \
                    WHERE chunk.community_id=i.community_id AND chunk.item_id=i.id \
                      AND chunk.content_hash=$5 \
                ) AS exact_chunk \
         FROM (SELECT 1) singleton \
         LEFT JOIN source_items i ON i.community_id=$1 AND i.id=$2",
    )
    .bind(community_id.as_uuid())
    .bind(request.item_id)
    .bind(requester_pubkey)
    .bind(request.channel_id)
    .bind(request.chunk_hash)
    .fetch_optional(pool)
    .await?;

    let Some(row) = state else {
        return Ok(EvidenceResolution::Unavailable);
    };
    if !row.try_get::<bool, _>("channel_authorized")? {
        return Ok(EvidenceResolution::Denied);
    }
    if !row.try_get::<bool, _>("item_exists")? {
        return Ok(EvidenceResolution::Unavailable);
    }
    let status: String = row.try_get("status")?;
    let tombstoned_at: Option<chrono::DateTime<chrono::Utc>> = row.try_get("tombstoned_at")?;
    if status != "active" || tombstoned_at.is_some() {
        Ok(EvidenceResolution::Unavailable)
    } else if !row.try_get::<bool, _>("source_readable")?
        || !row.try_get::<bool, _>("has_authority")?
    {
        Ok(EvidenceResolution::Denied)
    } else if !row.try_get::<bool, _>("exact_chunk")? {
        Ok(EvidenceResolution::Stale)
    } else {
        Ok(EvidenceResolution::Unavailable)
    }
}
