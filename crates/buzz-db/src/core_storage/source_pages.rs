use std::collections::BTreeSet;

use buzz_core::CommunityId;
use sqlx::{PgPool, Row};
use url::Url;
use uuid::Uuid;

use super::{
    require_hash, source_chunk_hash, NewIndexedSourceItem, NewSourceAclPrincipal,
    NewSourceChangePage, SourcePageApplyOutcome,
};

const MAX_CHUNK_CHARS: i64 = 1_200;
const CHUNK_OVERLAP_CHARS: usize = 120;
const CHUNK_STEP_CHARS: i64 = 1_080;

fn validate_safe_identifier(name: &str, value: &str) -> crate::Result<()> {
    if value.is_empty() || value.len() > 512 || value.contains('\0') {
        return Err(crate::DbError::InvalidData(format!(
            "{name} must be between 1 and 512 bytes"
        )));
    }
    Ok(())
}

fn resolver_link_is_allowed(
    provider: super::ExternalConnector,
    value: &str,
    configured_hosts: Option<&[String]>,
) -> bool {
    let Ok(link) = Url::parse(value) else {
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
        super::ExternalConnector::MicrosoftGraph => {
            host.eq_ignore_ascii_case("outlook.office.com")
                || host.eq_ignore_ascii_case("outlook.office365.com")
                || (host
                    .to_ascii_lowercase()
                    .strip_suffix(".sharepoint.com")
                    .is_some_and(|tenant| !tenant.is_empty() && !tenant.contains('.'))
                    && configured_hosts.is_none_or(|configured| {
                        configured
                            .iter()
                            .any(|allowed| host.eq_ignore_ascii_case(allowed))
                    }))
        }
        super::ExternalConnector::GoogleDrive => [
            "drive.google.com",
            "docs.google.com",
            "sheets.google.com",
            "slides.google.com",
        ]
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed)),
        super::ExternalConnector::CoreCrm => host.eq_ignore_ascii_case("crm.coreadvs.com"),
    }
}

fn validate_page(page: NewSourceChangePage<'_>) -> crate::Result<()> {
    validate_safe_identifier("stream", page.stream)?;
    if !page
        .stream
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(crate::DbError::InvalidData(
            "stream contains unsupported characters".into(),
        ));
    }
    if page.lease_generation <= 0 {
        return Err(crate::DbError::InvalidData(
            "lease_generation must be positive".into(),
        ));
    }
    require_hash(
        "expected_cursor_integrity_hash",
        page.expected_cursor_integrity_hash,
    )?;
    require_hash(
        "next_cursor_integrity_hash",
        page.next_cursor_integrity_hash,
    )?;
    if page.next_encrypted_cursor.is_empty() || page.next_encrypted_cursor.len() > 65_536 {
        return Err(crate::DbError::InvalidData(
            "next_encrypted_cursor must be between 1 and 65536 bytes".into(),
        ));
    }
    if page.next_cursor_key_version <= 0 {
        return Err(crate::DbError::InvalidData(
            "next_cursor_key_version must be positive".into(),
        ));
    }
    require_hash("page_digest", page.page_digest)?;
    if page.upserts.len().saturating_add(page.tombstones.len()) > 1_000 {
        return Err(crate::DbError::InvalidData(
            "source change page exceeds 1000 item changes".into(),
        ));
    }

    let mut item_ids = BTreeSet::new();
    let mut page_characters = 0_usize;
    for item in page.upserts {
        validate_safe_identifier("external_item_id", &item.external_item_id)?;
        validate_safe_identifier("remote_version", &item.remote_version)?;
        if let Some(etag) = &item.remote_etag {
            validate_safe_identifier("remote_etag", etag)?;
        }
        if item.title.trim().is_empty()
            || item.title.chars().count() > 1_024
            || item.title.contains('\0')
        {
            return Err(crate::DbError::InvalidData(
                "source title is invalid".into(),
            ));
        }
        if !resolver_link_is_allowed(page.provider, &item.resolvable_link, None)
            || item.resolvable_link.len() > 8_192
            || item.resolvable_link.contains('\0')
        {
            return Err(crate::DbError::InvalidData(
                "source link must be bounded HTTPS".into(),
            ));
        }
        if !item_ids.insert(item.external_item_id.as_str()) {
            return Err(crate::DbError::InvalidData(
                "source page contains duplicate item changes".into(),
            ));
        }
        if item.acls.is_empty() && !item.chunks.is_empty() {
            return Err(crate::DbError::InvalidData(
                "source chunks require at least one positive ACL".into(),
            ));
        }
        if item.acls.len() > 2_000 || item.chunks.len() > 2_048 {
            return Err(crate::DbError::InvalidData(
                "source item ACL or chunk bound exceeded".into(),
            ));
        }
        let acl_count = item.acls.iter().collect::<BTreeSet<_>>().len();
        if acl_count != item.acls.len() {
            return Err(crate::DbError::InvalidData(
                "source item contains duplicate ACL principals".into(),
            ));
        }
        for (expected_index, chunk) in item.chunks.iter().enumerate() {
            let expected_index = i32::try_from(expected_index).map_err(|_| {
                crate::DbError::InvalidData("source chunk index is out of range".into())
            })?;
            let content_chars = i64::try_from(chunk.content.chars().count()).map_err(|_| {
                crate::DbError::InvalidData("source chunk character count is out of range".into())
            })?;
            let expected_start = i64::from(expected_index)
                .checked_mul(CHUNK_STEP_CHARS)
                .ok_or_else(|| {
                    crate::DbError::InvalidData("source chunk offset is out of range".into())
                })?;
            let expected_end = chunk.start_char.checked_add(content_chars).ok_or_else(|| {
                crate::DbError::InvalidData("source chunk offset is out of range".into())
            })?;
            let index_u64 = u64::try_from(chunk.chunk_index).map_err(|_| {
                crate::DbError::InvalidData("source chunk index is out of range".into())
            })?;
            let start_u64 = u64::try_from(chunk.start_char).map_err(|_| {
                crate::DbError::InvalidData("source chunk offset is out of range".into())
            })?;
            let end_u64 = u64::try_from(chunk.end_char).map_err(|_| {
                crate::DbError::InvalidData("source chunk offset is out of range".into())
            })?;
            let expected_hash = source_chunk_hash(index_u64, start_u64, end_u64, &chunk.content);
            if chunk.chunk_index != expected_index
                || chunk.start_char != expected_start
                || chunk.end_char != expected_end
                || content_chars == 0
                || content_chars > MAX_CHUNK_CHARS
                || (usize::try_from(expected_index)
                    .is_ok_and(|index| index + 1 < item.chunks.len())
                    && content_chars != MAX_CHUNK_CHARS)
                || chunk.content.contains('\0')
                || chunk.content_hash != expected_hash
            {
                return Err(crate::DbError::InvalidData(
                    "source chunk is malformed".into(),
                ));
            }
            if let Some(previous) = expected_index
                .checked_sub(1)
                .and_then(|index| usize::try_from(index).ok())
                .and_then(|index| item.chunks.get(index))
            {
                let previous_overlap = previous
                    .content
                    .chars()
                    .rev()
                    .take(CHUNK_OVERLAP_CHARS)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<String>();
                let current_overlap = chunk
                    .content
                    .chars()
                    .take(CHUNK_OVERLAP_CHARS)
                    .collect::<String>();
                if previous_overlap != current_overlap {
                    return Err(crate::DbError::InvalidData(
                        "source chunk overlap is inconsistent".into(),
                    ));
                }
            }
            page_characters = page_characters
                .checked_add(usize::try_from(content_chars).map_err(|_| {
                    crate::DbError::InvalidData(
                        "source chunk character count is out of range".into(),
                    )
                })?)
                .ok_or_else(|| {
                    crate::DbError::InvalidData(
                        "source page character count is out of range".into(),
                    )
                })?;
        }
    }
    for tombstone in page.tombstones {
        validate_safe_identifier("external_item_id", &tombstone.external_item_id)?;
        if !item_ids.insert(tombstone.external_item_id.as_str()) {
            return Err(crate::DbError::InvalidData(
                "source page contains conflicting item changes".into(),
            ));
        }
    }
    if page_characters > 5_000_000 {
        return Err(crate::DbError::InvalidData(
            "source page exceeds the character bound".into(),
        ));
    }
    Ok(())
}

async fn replace_item(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    community_id: CommunityId,
    page: NewSourceChangePage<'_>,
    item: &NewIndexedSourceItem,
) -> crate::Result<()> {
    let item_id: Uuid = sqlx::query_scalar(
        "INSERT INTO source_items \
         (community_id, id, account_id, scope_id, external_item_id, remote_version, remote_etag, \
          title, source_type, modified_at, resolvable_link, status, tombstoned_at, \
          last_authorization_check_at, updated_at) \
         VALUES ($1, gen_random_uuid(), $2, $3, $4, $5, $6, $7, $8, $9, $10, \
                 'active', NULL, $11, $11) \
         ON CONFLICT (community_id, account_id, scope_id, external_item_id) DO UPDATE SET \
           remote_version=EXCLUDED.remote_version, remote_etag=EXCLUDED.remote_etag, \
           title=EXCLUDED.title, source_type=EXCLUDED.source_type, \
           modified_at=EXCLUDED.modified_at, resolvable_link=EXCLUDED.resolvable_link, \
           status='active', tombstoned_at=NULL, \
           last_authorization_check_at=EXCLUDED.last_authorization_check_at, updated_at=EXCLUDED.updated_at \
         RETURNING id",
    )
    .bind(community_id.as_uuid())
    .bind(page.account_id)
    .bind(page.scope_id)
    .bind(&item.external_item_id)
    .bind(&item.remote_version)
    .bind(&item.remote_etag)
    .bind(&item.title)
    .bind(item.source_kind.as_str())
    .bind(item.modified_at)
    .bind(&item.resolvable_link)
    .bind(page.now)
    .fetch_one(&mut **transaction)
    .await?;

    sqlx::query("DELETE FROM source_chunks WHERE community_id=$1 AND item_id=$2")
        .bind(community_id.as_uuid())
        .bind(item_id)
        .execute(&mut **transaction)
        .await?;
    sqlx::query("DELETE FROM source_item_acls WHERE community_id=$1 AND item_id=$2")
        .bind(community_id.as_uuid())
        .bind(item_id)
        .execute(&mut **transaction)
        .await?;

    for acl in &item.acls {
        match acl {
            NewSourceAclPrincipal::User(pubkey) => {
                sqlx::query(
                    "INSERT INTO source_item_acls \
                     (community_id, id, item_id, principal_type, principal_pubkey) \
                     VALUES ($1, gen_random_uuid(), $2, 'user', $3)",
                )
                .bind(community_id.as_uuid())
                .bind(item_id)
                .bind(pubkey.as_slice())
                .execute(&mut **transaction)
                .await?;
            }
            NewSourceAclPrincipal::Channel(channel_id) => {
                sqlx::query(
                    "INSERT INTO source_item_acls \
                     (community_id, id, item_id, principal_type, channel_id) \
                     VALUES ($1, gen_random_uuid(), $2, 'channel', $3)",
                )
                .bind(community_id.as_uuid())
                .bind(item_id)
                .bind(channel_id)
                .execute(&mut **transaction)
                .await?;
            }
        }
    }
    for chunk in &item.chunks {
        sqlx::query(
            "INSERT INTO source_chunks \
             (community_id, id, item_id, chunk_index, start_char, end_char, content, content_hash) \
             VALUES ($1, gen_random_uuid(), $2, $3, $4, $5, $6, $7)",
        )
        .bind(community_id.as_uuid())
        .bind(item_id)
        .bind(chunk.chunk_index)
        .bind(chunk.start_char)
        .bind(chunk.end_char)
        .bind(&chunk.content)
        .bind(chunk.content_hash.as_slice())
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

/// Apply all item/ACL/chunk/tombstone changes and advance the encrypted cursor
/// in one tenant-scoped transaction fenced by the current delta lease.
pub async fn apply_source_change_page(
    pool: &PgPool,
    community_id: CommunityId,
    page: NewSourceChangePage<'_>,
) -> crate::Result<SourcePageApplyOutcome> {
    if page.community_id != community_id {
        return Err(crate::DbError::AccessDenied(
            "source page tenant does not match storage authority".into(),
        ));
    }
    validate_page(page)?;
    let mut transaction = pool.begin().await?;
    let cursor = sqlx::query(
        "SELECT cursor.encrypted_cursor, cursor.cursor_integrity_hash, \
                cursor.cursor_key_version, cursor.generation, cursor.lease_owner, \
                cursor.lease_until, cursor.last_page_digest, account.provider, \
                scope.resolver_hosts \
         FROM connector_delta_cursors cursor \
         JOIN connector_accounts account \
           ON account.community_id=cursor.community_id AND account.id=cursor.account_id \
          AND account.status='active' \
         JOIN approved_source_scopes scope \
           ON scope.community_id=cursor.community_id AND scope.account_id=cursor.account_id \
          AND scope.id=cursor.scope_id AND scope.status='active' AND scope.can_read \
         WHERE cursor.community_id=$1 AND cursor.account_id=$2 \
           AND cursor.scope_id=$3 AND cursor.stream=$4 \
         FOR UPDATE OF cursor, account, scope",
    )
    .bind(community_id.as_uuid())
    .bind(page.account_id)
    .bind(page.scope_id)
    .bind(page.stream)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| crate::DbError::AccessDenied("source cursor is inactive or absent".into()))?;

    let provider: String = cursor.try_get("provider")?;
    if provider != page.provider.as_str() {
        return Err(crate::DbError::AccessDenied(
            "source page provider does not match the account".into(),
        ));
    }
    let resolver_hosts: Vec<String> = cursor.try_get("resolver_hosts")?;
    if resolver_hosts.len() > 16
        || resolver_hosts.iter().any(|host| {
            host.is_empty()
                || host.len() > 253
                || host != &host.to_ascii_lowercase()
                || host.starts_with('.')
                || host.ends_with('.')
                || !host
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        })
        || page.upserts.iter().any(|item| {
            !resolver_link_is_allowed(page.provider, &item.resolvable_link, Some(&resolver_hosts))
        })
    {
        return Err(crate::DbError::AccessDenied(
            "source resolver authority is not approved for the scope".into(),
        ));
    }
    let current_cursor: Vec<u8> = cursor.try_get("encrypted_cursor")?;
    let current_hash: Vec<u8> = cursor.try_get("cursor_integrity_hash")?;
    let current_key_version: i32 = cursor.try_get("cursor_key_version")?;
    if current_cursor == page.next_encrypted_cursor
        && current_hash == page.next_cursor_integrity_hash
        && current_key_version == page.next_cursor_key_version
    {
        let last_page_digest: Option<Vec<u8>> = cursor.try_get("last_page_digest")?;
        if last_page_digest.as_deref() != Some(page.page_digest) {
            return Err(crate::DbError::AccessDenied(
                "replayed source cursor does not match the committed page".into(),
            ));
        }
        transaction.rollback().await?;
        return Ok(SourcePageApplyOutcome::AlreadyApplied);
    }

    let lease_owner: Option<Uuid> = cursor.try_get("lease_owner")?;
    let lease_generation: i64 = cursor.try_get("generation")?;
    let lease_until: Option<chrono::DateTime<chrono::Utc>> = cursor.try_get("lease_until")?;
    if current_hash != page.expected_cursor_integrity_hash
        || lease_owner != Some(page.worker_id)
        || lease_generation != page.lease_generation
        || lease_until.is_none_or(|until| until <= page.now)
    {
        return Err(crate::DbError::AccessDenied(
            "source page cursor lease is stale".into(),
        ));
    }

    for item in page.upserts {
        replace_item(&mut transaction, community_id, page, item).await?;
    }
    for tombstone in page.tombstones {
        let item_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM source_items \
             WHERE community_id=$1 AND account_id=$2 AND scope_id=$3 AND external_item_id=$4 \
             FOR UPDATE",
        )
        .bind(community_id.as_uuid())
        .bind(page.account_id)
        .bind(page.scope_id)
        .bind(&tombstone.external_item_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(item_id) = item_id {
            sqlx::query("DELETE FROM source_chunks WHERE community_id=$1 AND item_id=$2")
                .bind(community_id.as_uuid())
                .bind(item_id)
                .execute(&mut *transaction)
                .await?;
            sqlx::query("DELETE FROM source_item_acls WHERE community_id=$1 AND item_id=$2")
                .bind(community_id.as_uuid())
                .bind(item_id)
                .execute(&mut *transaction)
                .await?;
            sqlx::query(
                "UPDATE source_items SET status='unavailable', tombstoned_at=$3, \
                 last_authorization_check_at=$3, updated_at=$3 \
                 WHERE community_id=$1 AND id=$2",
            )
            .bind(community_id.as_uuid())
            .bind(item_id)
            .bind(page.now)
            .execute(&mut *transaction)
            .await?;
        }
    }

    let updated = sqlx::query(
        "UPDATE connector_delta_cursors \
         SET encrypted_cursor=$8, cursor_integrity_hash=$9, cursor_key_version=$10, \
             last_page_digest=$12, \
             last_success_at=$7, lease_owner=NULL, lease_until=NULL, retry_count=0, \
             next_retry_at=NULL, last_error_code=NULL, updated_at=$7 \
         WHERE community_id=$1 AND account_id=$2 AND scope_id=$3 AND stream=$4 \
           AND lease_owner=$5 AND generation=$6 AND lease_until > $7 \
           AND cursor_integrity_hash=$11",
    )
    .bind(community_id.as_uuid())
    .bind(page.account_id)
    .bind(page.scope_id)
    .bind(page.stream)
    .bind(page.worker_id)
    .bind(page.lease_generation)
    .bind(page.now)
    .bind(page.next_encrypted_cursor)
    .bind(page.next_cursor_integrity_hash)
    .bind(page.next_cursor_key_version)
    .bind(page.expected_cursor_integrity_hash)
    .bind(page.page_digest)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if updated != 1 {
        return Err(crate::DbError::AccessDenied(
            "source page lost its cursor lease before commit".into(),
        ));
    }
    transaction.commit().await?;
    Ok(SourcePageApplyOutcome::Applied {
        changed_items: page.upserts.len().saturating_add(page.tombstones.len()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_validation_rejects_index_content_without_acl() {
        let item = NewIndexedSourceItem {
            external_item_id: "item".into(),
            remote_version: "v1".into(),
            remote_etag: None,
            title: "title".into(),
            source_kind: super::super::IndexedSourceKind::Document,
            modified_at: chrono::Utc::now(),
            resolvable_link: "https://example.invalid/item".into(),
            acls: Vec::new(),
            chunks: vec![super::super::NewIndexedSourceChunk {
                chunk_index: 0,
                start_char: 0,
                end_char: 6,
                content: "secret".into(),
                content_hash: source_chunk_hash(0, 0, 6, "secret"),
            }],
        };
        let page = NewSourceChangePage {
            community_id: CommunityId::from_uuid(Uuid::new_v4()),
            account_id: Uuid::new_v4(),
            scope_id: Uuid::new_v4(),
            provider: super::super::ExternalConnector::GoogleDrive,
            stream: "changes",
            worker_id: Uuid::new_v4(),
            lease_generation: 1,
            expected_cursor_integrity_hash: &[1; 32],
            next_encrypted_cursor: &[2; 32],
            next_cursor_integrity_hash: &[3; 32],
            next_cursor_key_version: 1,
            page_digest: &[4; 32],
            upserts: &[item],
            tombstones: &[],
            now: chrono::Utc::now(),
        };
        assert!(validate_page(page).is_err());
    }

    fn unicode_page(chunks: Vec<super::super::NewIndexedSourceChunk>) -> NewIndexedSourceItem {
        NewIndexedSourceItem {
            external_item_id: "item".into(),
            remote_version: "v1".into(),
            remote_etag: None,
            title: "title".into(),
            source_kind: super::super::IndexedSourceKind::Document,
            modified_at: chrono::Utc::now(),
            resolvable_link: "https://drive.google.com/item".into(),
            acls: vec![super::super::NewSourceAclPrincipal::User([7; 32])],
            chunks,
        }
    }

    fn page_for(items: &[NewIndexedSourceItem]) -> NewSourceChangePage<'_> {
        NewSourceChangePage {
            community_id: CommunityId::from_uuid(Uuid::new_v4()),
            account_id: Uuid::new_v4(),
            scope_id: Uuid::new_v4(),
            provider: super::super::ExternalConnector::GoogleDrive,
            stream: "changes",
            worker_id: Uuid::new_v4(),
            lease_generation: 1,
            expected_cursor_integrity_hash: &[1; 32],
            next_encrypted_cursor: &[2; 32],
            next_cursor_integrity_hash: &[3; 32],
            next_cursor_key_version: 1,
            page_digest: &[4; 32],
            upserts: items,
            tombstones: &[],
            now: chrono::Utc::now(),
        }
    }

    #[test]
    fn page_validation_rechecks_unicode_scalar_offsets_and_hash() {
        let content = "é🙂a";
        let mut chunk = super::super::NewIndexedSourceChunk {
            chunk_index: 0,
            start_char: 0,
            end_char: 3,
            content: content.into(),
            content_hash: source_chunk_hash(0, 0, 3, content),
        };
        let items = [unicode_page(vec![chunk.clone()])];
        assert!(validate_page(page_for(&items)).is_ok());

        chunk.end_char = 5;
        let items = [unicode_page(vec![chunk])];
        assert!(validate_page(page_for(&items)).is_err());
    }

    #[test]
    fn page_validation_rejects_hash_and_overlap_corruption() {
        let first_content = "a".repeat(1_080) + &"b".repeat(120);
        let second_content = "c".repeat(120) + "tail";
        let first = super::super::NewIndexedSourceChunk {
            chunk_index: 0,
            start_char: 0,
            end_char: 1_200,
            content_hash: source_chunk_hash(0, 0, 1_200, &first_content),
            content: first_content,
        };
        let second = super::super::NewIndexedSourceChunk {
            chunk_index: 1,
            start_char: 1_080,
            end_char: 1_204,
            content_hash: source_chunk_hash(1, 1_080, 1_204, &second_content),
            content: second_content,
        };
        let items = [unicode_page(vec![first.clone(), second])];
        assert!(validate_page(page_for(&items)).is_err());

        let mut corrupted = first;
        corrupted.content_hash = [9; 32];
        let items = [unicode_page(vec![corrupted])];
        assert!(validate_page(page_for(&items)).is_err());
    }

    #[test]
    fn page_validation_rejects_provider_link_authority_and_userinfo() {
        for link in [
            "https://attacker.invalid/item",
            "https://user@drive.google.com/item",
            "https://user:secret@drive.google.com/item",
            "https://drive.google.com:444/item",
        ] {
            let content = "content";
            let chunk = super::super::NewIndexedSourceChunk {
                chunk_index: 0,
                start_char: 0,
                end_char: 7,
                content: content.into(),
                content_hash: source_chunk_hash(0, 0, 7, content),
            };
            let mut item = unicode_page(vec![chunk]);
            item.resolvable_link = link.into();
            assert!(validate_page(page_for(&[item])).is_err());
        }
    }

    #[test]
    fn microsoft_sharepoint_links_require_the_exact_scope_host() {
        let approved = vec!["coreadvs.sharepoint.com".to_owned()];
        assert!(resolver_link_is_allowed(
            super::super::ExternalConnector::MicrosoftGraph,
            "https://coreadvs.sharepoint.com/sites/deals/file",
            Some(&approved),
        ));
        assert!(!resolver_link_is_allowed(
            super::super::ExternalConnector::MicrosoftGraph,
            "https://attacker.sharepoint.com/sites/deals/file",
            Some(&approved),
        ));
    }
}
