use std::time::Duration as StdDuration;

use buzz_core::CommunityId;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use super::{bounded_lease, require_hash, CoreCrmDeltaScopeClaim, DeltaLeaseClaim};

fn validate_stream(stream: &str) -> crate::Result<()> {
    let mut bytes = stream.bytes();
    let valid = stream.len() <= 128
        && bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'));
    if !valid {
        return Err(crate::DbError::InvalidData(
            "stream must be a 1-128 byte safe identifier".into(),
        ));
    }
    Ok(())
}

fn validate_error_code(error_code: &str) -> crate::Result<()> {
    let mut bytes = error_code.bytes();
    let valid = error_code.len() <= 128
        && bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'));
    if !valid {
        return Err(crate::DbError::InvalidData(
            "error_code must be a 1-128 byte safe identifier".into(),
        ));
    }
    Ok(())
}

/// Claim at most one due, active, strictly read-only Core CRM known-record stream.
///
/// Provider, scope capability, private owner ACL, cursor, and fencing generation
/// are resolved in one database transaction; caller input cannot select another
/// provider or authority.
pub async fn claim_next_core_crm_delta_scope(
    pool: &PgPool,
    worker_id: Uuid,
    now: DateTime<Utc>,
    lease_for: StdDuration,
) -> crate::Result<Option<CoreCrmDeltaScopeClaim>> {
    let lease_until = now
        .checked_add_signed(bounded_lease(lease_for)?)
        .ok_or_else(|| {
            crate::DbError::InvalidData("delta lease timestamp is out of range".into())
        })?;
    let mut transaction = pool.begin().await?;
    let row = sqlx::query(
        "WITH due AS ( \
           SELECT cursor.community_id, cursor.account_id, cursor.scope_id, cursor.stream \
           FROM connector_delta_cursors cursor \
           JOIN connector_accounts account \
             ON account.community_id=cursor.community_id AND account.id=cursor.account_id \
           JOIN approved_source_scopes scope \
             ON scope.community_id=cursor.community_id AND scope.account_id=cursor.account_id \
            AND scope.id=cursor.scope_id \
           WHERE account.provider='core_crm' AND account.status='active' \
             AND scope.status='active' AND scope.can_read=true AND scope.can_write=false \
             AND cursor.stream='known-records' \
             AND (cursor.lease_until IS NULL OR cursor.lease_until <= $1) \
             AND (cursor.next_retry_at IS NULL OR cursor.next_retry_at <= $1) \
             AND (cursor.last_success_at IS NULL \
                  OR cursor.last_success_at > $1 \
                  OR cursor.last_success_at <= $1 - INTERVAL '5 minutes') \
           ORDER BY cursor.updated_at, cursor.community_id, cursor.account_id, cursor.scope_id \
           FOR UPDATE OF cursor SKIP LOCKED \
           LIMIT 1 \
         ) \
         UPDATE connector_delta_cursors cursor \
         SET lease_owner=$2, lease_until=$3, generation=cursor.generation+1, updated_at=$1 \
         FROM due, connector_accounts account \
         WHERE cursor.community_id=due.community_id AND cursor.account_id=due.account_id \
           AND cursor.scope_id=due.scope_id AND cursor.stream=due.stream \
           AND account.community_id=cursor.community_id AND account.id=cursor.account_id \
         RETURNING cursor.community_id, cursor.account_id, cursor.scope_id, cursor.stream, \
                   account.owner_pubkey, cursor.encrypted_cursor, \
                   cursor.cursor_integrity_hash, cursor.cursor_key_version, \
                   cursor.generation, cursor.lease_until",
    )
    .bind(now)
    .bind(worker_id)
    .bind(lease_until)
    .fetch_optional(&mut *transaction)
    .await?;
    transaction.commit().await?;

    row.map(|row| {
        let community_id: Uuid = row.try_get("community_id")?;
        Ok(CoreCrmDeltaScopeClaim {
            community_id: CommunityId::from_uuid(community_id),
            account_id: row.try_get("account_id")?,
            scope_id: row.try_get("scope_id")?,
            stream: row.try_get("stream")?,
            owner_pubkey: row.try_get("owner_pubkey")?,
            lease: DeltaLeaseClaim {
                encrypted_cursor: row.try_get("encrypted_cursor")?,
                cursor_integrity_hash: row.try_get("cursor_integrity_hash")?,
                cursor_key_version: row.try_get("cursor_key_version")?,
                generation: row.try_get("generation")?,
                lease_until: row.try_get("lease_until")?,
            },
        })
    })
    .transpose()
}

/// Claim or recover one encrypted delta stream with a bounded fenced lease.
#[allow(clippy::too_many_arguments)]
pub async fn claim_delta_scope(
    pool: &PgPool,
    community_id: CommunityId,
    account_id: Uuid,
    scope_id: Uuid,
    stream: &str,
    worker_id: Uuid,
    now: DateTime<Utc>,
    lease_for: StdDuration,
) -> crate::Result<Option<DeltaLeaseClaim>> {
    validate_stream(stream)?;
    let lease_until = now
        .checked_add_signed(bounded_lease(lease_for)?)
        .ok_or_else(|| {
            crate::DbError::InvalidData("delta lease timestamp is out of range".into())
        })?;
    let row = sqlx::query(
        "UPDATE connector_delta_cursors \
         SET lease_owner=$6, lease_until=$7, generation=generation+1, updated_at=$5 \
         WHERE community_id=$1 AND account_id=$2 AND scope_id=$3 AND stream=$4 \
           AND (lease_until IS NULL OR lease_until <= $5) \
           AND (next_retry_at IS NULL OR next_retry_at <= $5) \
           AND EXISTS ( \
               SELECT 1 FROM connector_accounts account \
               JOIN approved_source_scopes scope \
                 ON scope.community_id=account.community_id AND scope.account_id=account.id \
               WHERE account.community_id=$1 AND account.id=$2 AND account.status='active' \
                 AND scope.id=$3 AND scope.status='active' AND scope.can_read=true \
           ) \
         RETURNING encrypted_cursor, cursor_integrity_hash, cursor_key_version, generation, lease_until",
    )
    .bind(community_id.as_uuid())
    .bind(account_id)
    .bind(scope_id)
    .bind(stream)
    .bind(now)
    .bind(worker_id)
    .bind(lease_until)
    .fetch_optional(pool)
    .await?;

    row.map(|row| {
        Ok(DeltaLeaseClaim {
            encrypted_cursor: row.try_get("encrypted_cursor")?,
            cursor_integrity_hash: row.try_get("cursor_integrity_hash")?,
            cursor_key_version: row.try_get("cursor_key_version")?,
            generation: row.try_get("generation")?,
            lease_until: row.try_get("lease_until")?,
        })
    })
    .transpose()
}

/// Advance an encrypted delta cursor only for the current lease generation.
#[allow(clippy::too_many_arguments)]
pub async fn complete_delta_scope(
    pool: &PgPool,
    community_id: CommunityId,
    account_id: Uuid,
    scope_id: Uuid,
    stream: &str,
    worker_id: Uuid,
    generation: i64,
    encrypted_cursor: &[u8],
    cursor_integrity_hash: &[u8],
    cursor_key_version: i32,
    now: DateTime<Utc>,
) -> crate::Result<bool> {
    validate_stream(stream)?;
    if encrypted_cursor.is_empty() {
        return Err(crate::DbError::InvalidData(
            "encrypted_cursor must not be empty".into(),
        ));
    }
    require_hash("cursor_integrity_hash", cursor_integrity_hash)?;
    if cursor_key_version <= 0 {
        return Err(crate::DbError::InvalidData(
            "cursor_key_version must be positive".into(),
        ));
    }
    let updated = sqlx::query(
        "UPDATE connector_delta_cursors \
         SET encrypted_cursor=$8, cursor_integrity_hash=$9, cursor_key_version=$10, \
             last_success_at=$11, lease_owner=NULL, lease_until=NULL, retry_count=0, \
             next_retry_at=NULL, last_error_code=NULL, updated_at=$11 \
         WHERE community_id=$1 AND account_id=$2 AND scope_id=$3 AND stream=$4 \
           AND lease_owner=$5 AND generation=$6 AND lease_until > $7",
    )
    .bind(community_id.as_uuid())
    .bind(account_id)
    .bind(scope_id)
    .bind(stream)
    .bind(worker_id)
    .bind(generation)
    .bind(now)
    .bind(encrypted_cursor)
    .bind(cursor_integrity_hash)
    .bind(cursor_key_version)
    .bind(now)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(updated == 1)
}

/// Record a fenced delta failure, release its lease, and defer retry.
#[allow(clippy::too_many_arguments)]
pub async fn fail_delta_scope(
    pool: &PgPool,
    community_id: CommunityId,
    account_id: Uuid,
    scope_id: Uuid,
    stream: &str,
    worker_id: Uuid,
    generation: i64,
    error_code: &str,
    now: DateTime<Utc>,
    retry_after: StdDuration,
) -> crate::Result<bool> {
    validate_stream(stream)?;
    validate_error_code(error_code)?;
    if retry_after.is_zero() || retry_after > StdDuration::from_secs(24 * 60 * 60) {
        return Err(crate::DbError::InvalidData(
            "delta retry delay must be between 1 second and 24 hours".into(),
        ));
    }
    let delay = chrono::Duration::from_std(retry_after)
        .map_err(|_| crate::DbError::InvalidData("delta retry delay is out of range".into()))?;
    let retry_at = now.checked_add_signed(delay).ok_or_else(|| {
        crate::DbError::InvalidData("delta retry timestamp is out of range".into())
    })?;
    let updated = sqlx::query(
        "UPDATE connector_delta_cursors \
         SET retry_count=retry_count+1, next_retry_at=$8, last_error_code=$9, \
             lease_owner=NULL, lease_until=NULL, updated_at=$7 \
         WHERE community_id=$1 AND account_id=$2 AND scope_id=$3 AND stream=$4 \
           AND lease_owner=$5 AND generation=$6 AND lease_until > $7",
    )
    .bind(community_id.as_uuid())
    .bind(account_id)
    .bind(scope_id)
    .bind(stream)
    .bind(worker_id)
    .bind(generation)
    .bind(now)
    .bind(retry_at)
    .bind(error_code)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(updated == 1)
}
