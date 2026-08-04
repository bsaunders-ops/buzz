use buzz_core::CommunityId;
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgRow, PgPool, Row};

use super::{
    require_hash, require_pubkey, source_chunk_hash, AuthorizedSourceExcerptRecord,
    AuthorizedSourceFtsExcerptRecord, SourceCandidateRecheckRequest, SourceCitationRecord,
    SourceFtsCandidateRecheckRequest, SourceFtsCitationRecord, SourceFtsSearchRequest,
    SourceSearchRequest, SourceVectorSearchRequest, EMBEDDING_DIMENSIONS,
};

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
                              AND member.pubkey=$2 AND member.removed_at IS NULL \
                        )) \
                     ) \
               ) \
         ) \
         SELECT i.id AS item_id, c.id AS chunk_id, i.account_id, i.scope_id, \
                i.external_item_id, i.provider, i.title, i.source_type, i.modified_at, \
                i.resolvable_link, i.remote_version, i.remote_etag, \
                c.content_hash AS chunk_hash, c.start_char, c.end_char \
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
        })
    })
    .transpose()
}
