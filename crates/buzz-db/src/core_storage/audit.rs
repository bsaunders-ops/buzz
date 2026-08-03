use std::time::Duration as StdDuration;

use buzz_core::CommunityId;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgRow, PgPool, Row};
use uuid::Uuid;

use super::{bounded_lease, require_hash, AuditEnvelope, AuditExportBatch, CoreAuditOutboxRecord};

async fn lock_audit_chain(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    community_id: CommunityId,
) -> crate::Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('core_audit:' || $1::text, 0))")
        .bind(community_id.as_uuid())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn audit_entry_hash(
    community_id: CommunityId,
    sequence: i64,
    prior_entry_hash: Option<&[u8]>,
    envelope: AuditEnvelope<'_>,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, community_id.as_uuid().as_bytes());
    hash_field(&mut hasher, &sequence.to_be_bytes());
    hash_field(&mut hasher, prior_entry_hash.unwrap_or_default());
    hash_field(&mut hasher, envelope.event_type.as_str().as_bytes());
    hash_field(&mut hasher, envelope.entity_type.as_str().as_bytes());
    hash_field(&mut hasher, envelope.entity_id.as_bytes());
    hash_field(&mut hasher, envelope.object_hash);
    hash_field(
        &mut hasher,
        envelope
            .version
            .map_or("", super::AuditObjectVersion::as_str)
            .as_bytes(),
    );
    hash_field(
        &mut hasher,
        &envelope.occurred_at.timestamp_micros().to_be_bytes(),
    );
    hash_field(&mut hasher, envelope.outcome.as_str().as_bytes());
    hasher.finalize().to_vec()
}

fn outbox_from_row(community_id: CommunityId, row: &PgRow) -> crate::Result<CoreAuditOutboxRecord> {
    Ok(CoreAuditOutboxRecord {
        community_id,
        sequence: row.try_get("sequence")?,
        event_type: row.try_get("event_type")?,
        entity_type: row.try_get("entity_type")?,
        entity_id: row.try_get("entity_id")?,
        object_hash: row.try_get("object_hash")?,
        object_version: row.try_get("object_version")?,
        occurred_at: row.try_get("occurred_at")?,
        outcome: row.try_get("outcome")?,
        prior_entry_hash: row.try_get("prior_entry_hash")?,
        entry_hash: row.try_get("entry_hash")?,
        signing_state: row.try_get("signing_state")?,
        signer_identifier: row.try_get("signer_identifier")?,
        signature: row.try_get("signature")?,
        retry_count: row.try_get("retry_count")?,
    })
}

/// Append one typed, content-free envelope to a tenant's audit hash chain.
pub async fn append_audit_entry(
    pool: &PgPool,
    community_id: CommunityId,
    envelope: AuditEnvelope<'_>,
) -> crate::Result<CoreAuditOutboxRecord> {
    require_hash("object_hash", envelope.object_hash)?;
    let mut tx = pool.begin().await?;
    lock_audit_chain(&mut tx, community_id).await?;
    let previous = sqlx::query(
        "SELECT sequence, entry_hash FROM core_audit_outbox \
         WHERE community_id=$1 ORDER BY sequence DESC LIMIT 1",
    )
    .bind(community_id.as_uuid())
    .fetch_optional(&mut *tx)
    .await?;
    let (sequence, prior_entry_hash) = match previous {
        Some(row) => (
            row.get::<i64, _>("sequence")
                .checked_add(1)
                .ok_or_else(|| {
                    crate::DbError::InvalidData("audit sequence is out of range".into())
                })?,
            Some(row.get::<Vec<u8>, _>("entry_hash")),
        ),
        None => (1, None),
    };
    let entry_hash = audit_entry_hash(
        community_id,
        sequence,
        prior_entry_hash.as_deref(),
        envelope,
    );
    sqlx::query(
        "INSERT INTO core_audit_outbox \
         (community_id, sequence, event_type, entity_type, entity_id, object_hash, object_version, occurred_at, outcome, prior_entry_hash, entry_hash) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(community_id.as_uuid())
    .bind(sequence)
    .bind(envelope.event_type.as_str())
    .bind(envelope.entity_type.as_str())
    .bind(envelope.entity_id)
    .bind(envelope.object_hash)
    .bind(envelope.version.map(super::AuditObjectVersion::as_str))
    .bind(envelope.occurred_at)
    .bind(envelope.outcome.as_str())
    .bind(&prior_entry_hash)
    .bind(&entry_hash)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(CoreAuditOutboxRecord {
        community_id,
        sequence,
        event_type: envelope.event_type.as_str().to_owned(),
        entity_type: envelope.entity_type.as_str().to_owned(),
        entity_id: envelope.entity_id,
        object_hash: envelope.object_hash.to_vec(),
        object_version: envelope.version.map(|version| version.as_str().to_owned()),
        occurred_at: envelope.occurred_at,
        outcome: envelope.outcome.as_str().to_owned(),
        prior_entry_hash,
        entry_hash,
        signing_state: "unsigned".into(),
        signer_identifier: None,
        signature: None,
        retry_count: 0,
    })
}

/// Claim the next ordered audit prefix for immutable-Blob export.
pub async fn claim_audit_export_batch(
    pool: &PgPool,
    community_id: CommunityId,
    worker_id: Uuid,
    now: DateTime<Utc>,
    lease_for: StdDuration,
    limit: i64,
) -> crate::Result<Option<AuditExportBatch>> {
    if !(1..=1_000).contains(&limit) {
        return Err(crate::DbError::InvalidData(
            "audit export limit must be between 1 and 1000".into(),
        ));
    }
    let claim_until = now
        .checked_add_signed(bounded_lease(lease_for)?)
        .ok_or_else(|| {
            crate::DbError::InvalidData("audit lease timestamp is out of range".into())
        })?;
    let batch_id = Uuid::new_v4();
    let mut tx = pool.begin().await?;
    lock_audit_chain(&mut tx, community_id).await?;
    sqlx::query(
        "UPDATE core_audit_outbox \
         SET export_state='retry', export_batch_id=NULL, export_claimed_by=NULL, \
             export_claimed_at=NULL, export_claim_until=NULL, retry_count=retry_count+1, next_retry_at=$2 \
         WHERE community_id=$1 AND export_state='claimed' AND export_claim_until <= $2",
    )
    .bind(community_id.as_uuid())
    .bind(now)
    .execute(&mut *tx)
    .await?;
    let checkpoint = sqlx::query_scalar(
        "SELECT last_exported_sequence FROM core_audit_checkpoints \
         WHERE community_id=$1 ORDER BY last_exported_sequence DESC LIMIT 1 FOR UPDATE",
    )
    .bind(community_id.as_uuid())
    .fetch_optional(&mut *tx)
    .await?
    .unwrap_or(0_i64);
    let rows = sqlx::query(
        "SELECT sequence, event_type, entity_type, entity_id, object_hash, object_version, \
                occurred_at, outcome, prior_entry_hash, entry_hash, signing_state, signer_identifier, \
                signature, retry_count, export_state, next_retry_at \
         FROM core_audit_outbox WHERE community_id=$1 AND sequence > $2 \
         ORDER BY sequence LIMIT $3 FOR UPDATE",
    )
    .bind(community_id.as_uuid())
    .bind(checkpoint)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await?;
    let mut entries = Vec::new();
    for (offset, row) in rows.iter().enumerate() {
        let expected = i64::try_from(offset)
            .ok()
            .and_then(|value| checkpoint.checked_add(value))
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| crate::DbError::InvalidData("audit sequence is out of range".into()))?;
        let sequence: i64 = row.try_get("sequence")?;
        let state: String = row.try_get("export_state")?;
        let signing_state: String = row.try_get("signing_state")?;
        let signer_identifier: Option<String> = row.try_get("signer_identifier")?;
        let signature: Option<Vec<u8>> = row.try_get("signature")?;
        let retry_at: DateTime<Utc> = row.try_get("next_retry_at")?;
        if sequence != expected
            || !matches!(state.as_str(), "pending" | "retry")
            || retry_at > now
            || signing_state != "signed"
            || signer_identifier.is_none()
            || signature.as_ref().is_none_or(|value| value.len() != 64)
        {
            break;
        }
        entries.push(outbox_from_row(community_id, row)?);
    }
    if entries.is_empty() {
        tx.commit().await?;
        return Ok(None);
    }
    let sequences = entries
        .iter()
        .map(|entry| entry.sequence)
        .collect::<Vec<_>>();
    sqlx::query(
        "UPDATE core_audit_outbox SET export_state='claimed', export_batch_id=$3, \
         export_claimed_by=$4, export_claimed_at=$5, export_claim_until=$6 \
         WHERE community_id=$1 AND sequence=ANY($2::bigint[])",
    )
    .bind(community_id.as_uuid())
    .bind(&sequences)
    .bind(batch_id)
    .bind(worker_id)
    .bind(now)
    .bind(claim_until)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(AuditExportBatch {
        batch_id,
        entries,
        claim_until,
    }))
}

/// Release a failed audit export claim at an explicit retry time.
pub async fn retry_audit_export_batch(
    pool: &PgPool,
    community_id: CommunityId,
    batch_id: Uuid,
    retry_at: DateTime<Utc>,
) -> crate::Result<bool> {
    let updated = sqlx::query(
        "UPDATE core_audit_outbox \
         SET export_state='retry', export_batch_id=NULL, export_claimed_by=NULL, \
             export_claimed_at=NULL, export_claim_until=NULL, retry_count=retry_count+1, next_retry_at=$3 \
         WHERE community_id=$1 AND export_batch_id=$2 AND export_state='claimed'",
    )
    .bind(community_id.as_uuid())
    .bind(batch_id)
    .bind(retry_at)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(updated > 0)
}

/// Commit an immutable-Blob checkpoint before marking its ordered rows exported.
#[allow(clippy::too_many_arguments)]
pub async fn complete_audit_export_batch(
    pool: &PgPool,
    community_id: CommunityId,
    batch_id: Uuid,
    blob_object_key: &str,
    blob_content_hash: &[u8],
    blob_etag: &str,
    now: DateTime<Utc>,
) -> crate::Result<bool> {
    require_hash("blob_content_hash", blob_content_hash)?;
    let valid_object_key = !blob_object_key.is_empty()
        && blob_object_key.len() <= 1_024
        && !blob_object_key.starts_with('/')
        && !blob_object_key.contains("//")
        && !blob_object_key.contains("://")
        && !blob_object_key
            .chars()
            .any(|character| character.is_control() || matches!(character, '?' | '#' | '\\'))
        && !blob_object_key.split('/').any(|part| part == "..");
    if !valid_object_key || blob_etag.is_empty() || blob_etag.len() > 256 {
        return Err(crate::DbError::InvalidData(
            "blob_object_key must be a non-secret object key and blob_etag must be 1-256 bytes"
                .into(),
        ));
    }
    let mut tx = pool.begin().await?;
    lock_audit_chain(&mut tx, community_id).await?;
    let checkpoint = sqlx::query_scalar(
        "SELECT last_exported_sequence FROM core_audit_checkpoints \
         WHERE community_id=$1 ORDER BY last_exported_sequence DESC LIMIT 1 FOR UPDATE",
    )
    .bind(community_id.as_uuid())
    .fetch_optional(&mut *tx)
    .await?
    .unwrap_or(0_i64);
    let rows = sqlx::query(
        "SELECT sequence, entry_hash FROM core_audit_outbox \
         WHERE community_id=$1 AND export_batch_id=$2 AND export_state='claimed' \
         ORDER BY sequence FOR UPDATE",
    )
    .bind(community_id.as_uuid())
    .bind(batch_id)
    .fetch_all(&mut *tx)
    .await?;
    if rows.is_empty() {
        tx.commit().await?;
        return Ok(false);
    }
    for (offset, row) in rows.iter().enumerate() {
        let expected = i64::try_from(offset)
            .ok()
            .and_then(|value| checkpoint.checked_add(value))
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| crate::DbError::InvalidData("audit sequence is out of range".into()))?;
        if row.try_get::<i64, _>("sequence")? != expected {
            return Err(crate::DbError::InvalidData(
                "audit export batch is not the next contiguous chain prefix".into(),
            ));
        }
    }
    let last = rows.last().ok_or_else(|| {
        crate::DbError::InvalidData("audit export batch unexpectedly empty".into())
    })?;
    let last_sequence: i64 = last.try_get("sequence")?;
    let last_entry_hash: Vec<u8> = last.try_get("entry_hash")?;
    sqlx::query(
        "INSERT INTO core_audit_checkpoints \
         (community_id, last_exported_sequence, last_entry_hash, blob_object_key, blob_content_hash, blob_etag, checkpointed_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(community_id.as_uuid())
    .bind(last_sequence)
    .bind(&last_entry_hash)
    .bind(blob_object_key)
    .bind(blob_content_hash)
    .bind(blob_etag)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE core_audit_outbox \
         SET export_state='exported', exported_at=$3, export_batch_id=NULL, \
             export_claimed_by=NULL, export_claimed_at=NULL, export_claim_until=NULL \
         WHERE community_id=$1 AND export_batch_id=$2 AND export_state='claimed'",
    )
    .bind(community_id.as_uuid())
    .bind(batch_id)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}
