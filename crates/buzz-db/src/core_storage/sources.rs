use buzz_core::CommunityId;
use sqlx::{postgres::PgRow, PgPool, Row};

use super::{
    require_pubkey, SourceCitationRecord, SourceSearchRequest, SourceVectorSearchRequest,
    EMBEDDING_DIMENSIONS,
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
        title: row.try_get("title")?,
        source_type: row.try_get("source_type")?,
        modified_at: row.try_get("modified_at")?,
        resolvable_link: row.try_get("resolvable_link")?,
        remote_version: row.try_get("remote_version")?,
        chunk_hash: row.try_get("chunk_hash")?,
    })
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

    let rows = sqlx::query(
        "WITH eligible_items AS MATERIALIZED ( \
             SELECT i.community_id, i.id, i.title, i.source_type, i.modified_at, \
                    i.resolvable_link, i.remote_version \
             FROM source_items i \
             JOIN connector_accounts a \
               ON a.community_id=i.community_id AND a.id=i.account_id AND a.status='active' \
             JOIN approved_source_scopes s \
               ON s.community_id=i.community_id AND s.id=i.scope_id AND s.status='active' AND s.can_read \
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
             SELECT i.id AS item_id, c.id AS chunk_id, i.title, i.source_type, i.modified_at, \
                    i.resolvable_link, i.remote_version, c.content_hash AS chunk_hash, c.search_tsv \
             FROM eligible_items i \
             JOIN source_chunks c ON c.community_id=i.community_id AND c.item_id=i.id \
         ) \
         SELECT item_id, chunk_id, title, source_type, modified_at, resolvable_link, \
                remote_version, chunk_hash \
         FROM eligible_chunks \
         WHERE search_tsv @@ websearch_to_tsquery('simple', $4) \
         ORDER BY ts_rank_cd(search_tsv, websearch_to_tsquery('simple', $4)) DESC, item_id, chunk_id \
         LIMIT $5",
    )
    .bind(community_id.as_uuid())
    .bind(request.requester_pubkey)
    .bind(request.authorized_channel_ids)
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
             SELECT i.community_id, i.id, i.title, i.source_type, i.modified_at, \
                    i.resolvable_link, i.remote_version \
             FROM source_items i \
             JOIN connector_accounts a \
               ON a.community_id=i.community_id AND a.id=i.account_id AND a.status='active' \
             JOIN approved_source_scopes s \
               ON s.community_id=i.community_id AND s.id=i.scope_id AND s.status='active' AND s.can_read \
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
             SELECT i.id AS item_id, c.id AS chunk_id, i.title, i.source_type, i.modified_at, \
                    i.resolvable_link, i.remote_version, c.content_hash AS chunk_hash, c.embedding \
             FROM eligible_items i \
             JOIN source_chunks c ON c.community_id=i.community_id AND c.item_id=i.id \
             WHERE c.embedding_version_id=$4 AND c.embedding IS NOT NULL \
         ) \
         SELECT item_id, chunk_id, title, source_type, modified_at, resolvable_link, \
                remote_version, chunk_hash \
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
