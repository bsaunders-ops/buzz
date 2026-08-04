//! PostgreSQL adapter for the provider-neutral page transaction.

use buzz_core::CommunityId;
use buzz_db::core_storage::{
    apply_source_change_page, ExternalConnector, IndexedSourceKind, NewIndexedSourceChunk,
    NewIndexedSourceItem, NewSourceAclPrincipal, NewSourceChangePage, NewSourceTombstone,
    SourcePageApplyOutcome,
};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    apply::ApplyOutcome,
    chunk::{chunk_source, ChunkBounds},
    types::{AclPrincipal, ChangePage, ConnectorProvider, SourceKind},
};

fn provider(value: ConnectorProvider) -> ExternalConnector {
    match value {
        ConnectorProvider::MicrosoftGraph => ExternalConnector::MicrosoftGraph,
        ConnectorProvider::GoogleDrive => ExternalConnector::GoogleDrive,
        ConnectorProvider::CoreCrm => ExternalConnector::CoreCrm,
    }
}

fn source_kind(value: SourceKind) -> IndexedSourceKind {
    match value {
        SourceKind::Email => IndexedSourceKind::Email,
        SourceKind::CalendarEvent => IndexedSourceKind::CalendarEvent,
        SourceKind::Document => IndexedSourceKind::Document,
        SourceKind::Spreadsheet => IndexedSourceKind::Spreadsheet,
        SourceKind::Presentation => IndexedSourceKind::Presentation,
        SourceKind::CrmRecord => IndexedSourceKind::CrmRecord,
        SourceKind::CrmTranscript => IndexedSourceKind::CrmTranscript,
    }
}

/// Commit one already validated connector page and its encrypted cursor in a
/// single fenced database transaction. Provider workers never receive generic
/// SQL, raw database credentials, or a way to advance a cursor independently.
pub async fn apply_postgres_change_page(
    pool: &PgPool,
    community_id: CommunityId,
    page: &ChangePage,
    worker_id: Uuid,
    lease_generation: i64,
    now: DateTime<Utc>,
) -> buzz_db::Result<ApplyOutcome> {
    if page.tenant_id() != *community_id.as_uuid() || page.schema_version() != 1 {
        return Err(buzz_db::DbError::AccessDenied(
            "source page tenant or schema does not match storage authority".into(),
        ));
    }
    let page_generation = i64::try_from(page.next_cursor().generation()).map_err(|_| {
        buzz_db::DbError::InvalidData("source page generation is out of range".into())
    })?;
    if page_generation != lease_generation {
        return Err(buzz_db::DbError::AccessDenied(
            "source page does not match its fenced lease generation".into(),
        ));
    }
    let next_cursor_key_version =
        i32::try_from(page.next_cursor().key_version()).map_err(|_| {
            buzz_db::DbError::InvalidData("source cursor key version is out of range".into())
        })?;

    let mut upserts = Vec::with_capacity(page.upserts().len());
    for item in page.upserts() {
        let acls = item
            .acls()
            .iter()
            .map(|acl| match acl {
                AclPrincipal::User { pubkey } => NewSourceAclPrincipal::User(*pubkey),
                AclPrincipal::Channel { channel_id } => NewSourceAclPrincipal::Channel(*channel_id),
            })
            .collect::<Vec<_>>();
        let chunks = if acls.is_empty() {
            Vec::new()
        } else {
            chunk_source(item.source(), ChunkBounds::month_one())
                .map_err(|_| {
                    buzz_db::DbError::InvalidData(
                        "source failed deterministic chunk validation".into(),
                    )
                })?
                .into_iter()
                .map(|chunk| {
                    let content_hash: [u8; 32] = chunk.content_hash.try_into().map_err(|_| {
                        buzz_db::DbError::InvalidData("source chunk hash is not 32 bytes".into())
                    })?;
                    let chunk_index = i32::try_from(chunk.chunk_index).map_err(|_| {
                        buzz_db::DbError::InvalidData("source chunk index is out of range".into())
                    })?;
                    Ok(NewIndexedSourceChunk {
                        chunk_index,
                        start_char: i64::try_from(chunk.start_char).map_err(|_| {
                            buzz_db::DbError::InvalidData(
                                "source chunk start offset is out of range".into(),
                            )
                        })?,
                        end_char: i64::try_from(chunk.end_char).map_err(|_| {
                            buzz_db::DbError::InvalidData(
                                "source chunk end offset is out of range".into(),
                            )
                        })?,
                        content: chunk.content,
                        content_hash,
                    })
                })
                .collect::<buzz_db::Result<Vec<_>>>()?
        };
        upserts.push(NewIndexedSourceItem {
            external_item_id: item.external_item_id().as_str().to_owned(),
            remote_version: item.remote_version().value().to_owned(),
            remote_etag: item.remote_version().etag().map(ToOwned::to_owned),
            title: item.title().to_owned(),
            source_kind: source_kind(item.source_kind()),
            modified_at: item.modified_at(),
            resolvable_link: item.resolvable_link().to_owned(),
            acls,
            chunks,
        });
    }
    let tombstones = page
        .tombstones()
        .iter()
        .map(|item| NewSourceTombstone {
            external_item_id: item.external_item_id().as_str().to_owned(),
        })
        .collect::<Vec<_>>();

    let outcome = apply_source_change_page(
        pool,
        community_id,
        NewSourceChangePage {
            community_id,
            account_id: page.account_id().as_uuid(),
            scope_id: page.scope_id().as_uuid(),
            provider: provider(page.provider()),
            stream: page.stream(),
            worker_id,
            lease_generation,
            expected_cursor_integrity_hash: &page.previous_cursor_hash(),
            next_encrypted_cursor: page.next_cursor().ciphertext(),
            next_cursor_integrity_hash: &page.next_cursor().integrity_hash(),
            next_cursor_key_version,
            page_digest: &page.page_digest(),
            upserts: &upserts,
            tombstones: &tombstones,
            now,
        },
    )
    .await?;
    Ok(match outcome {
        SourcePageApplyOutcome::Applied { changed_items } => {
            ApplyOutcome::Applied { changed_items }
        }
        SourcePageApplyOutcome::AlreadyApplied => ApplyOutcome::AlreadyApplied,
    })
}
