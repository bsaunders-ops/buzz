use std::fmt;

use nostr::{nips::nip44, Keys};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use super::FinalizedSegment;

pub const MAX_RECOVERY_AGE_MS: u64 = 24 * 60 * 60 * 1_000;
const MAX_RECOVERY_SEGMENTS: usize = 2_048;
const MAX_RECOVERY_TEXT_BYTES: usize = 512 * 1_024;
const MAX_RECOVERY_ENVELOPE_BYTES: usize = 1_048_576;

/// Minimal OS-keyring boundary. Production addresses one key per local call,
/// so deleting it makes any surviving ciphertext copy unusable.
pub trait RecoveryKeyStore: Clone + Send + Sync + 'static {
    fn load(&self, call_id: Uuid) -> Result<Option<String>, String>;
    fn store(&self, call_id: Uuid, secret: &str) -> Result<(), String>;
    fn delete(&self, call_id: Uuid) -> Result<(), String>;
}

/// Minimal restricted app-data boundary. Implementations must use an
/// owner-only directory/file policy and atomic replacement.
pub trait RecoveryBlobStore: Clone + Send + Sync + 'static {
    fn load(&self, call_id: Uuid) -> Result<Option<Vec<u8>>, String>;
    fn write(&self, call_id: Uuid, bytes: &[u8]) -> Result<(), String>;
    fn delete(&self, call_id: Uuid) -> Result<(), String>;
    fn list_call_ids(&self) -> Result<Vec<Uuid>, String>;
}

/// Authenticated transcript content recovered only for local review.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPayload {
    pub schema_version: u8,
    pub call_id: Uuid,
    pub ended_at_ms: u64,
    pub expires_at_ms: u64,
    pub segments: Vec<FinalizedSegment>,
}

impl fmt::Debug for RecoveryPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryPayload")
            .field("schema_version", &self.schema_version)
            .field("call_id", &"<redacted>")
            .field("ended_at_ms", &self.ended_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .field(
                "segments",
                &format_args!("<redacted:{}>", self.segments.len()),
            )
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryEnvelope {
    schema_version: u8,
    call_id: Uuid,
    expires_at_ms: u64,
    ciphertext: String,
}

/// Authenticated, bounded recovery lifecycle independent of a concrete
/// keyring or filesystem so failure ordering is exhaustively testable.
pub struct RecoveryManager<K, B> {
    keys: K,
    blobs: B,
}

impl<K: RecoveryKeyStore, B: RecoveryBlobStore> RecoveryManager<K, B> {
    pub const fn new(keys: K, blobs: B) -> Self {
        Self { keys, blobs }
    }

    pub fn persist(
        &self,
        call_id: Uuid,
        ended_at_ms: u64,
        expires_at_ms: u64,
        segments: Vec<FinalizedSegment>,
    ) -> Result<(), String> {
        validate_recovery_input(call_id, ended_at_ms, expires_at_ms, &segments)?;
        if self.keys.load(call_id)?.is_some() || self.blobs.load(call_id)?.is_some() {
            return Err("call recovery material already exists".into());
        }
        let payload = RecoveryPayload {
            schema_version: 1,
            call_id,
            ended_at_ms,
            expires_at_ms,
            segments,
        };
        let mut plaintext = serde_json::to_string(&payload)
            .map_err(|_| "call recovery payload could not be serialized".to_string())?;
        let recovery_keys = Keys::generate();
        let ciphertext = nip44::encrypt(
            recovery_keys.secret_key(),
            &recovery_keys.public_key(),
            &plaintext,
            nip44::Version::V2,
        )
        .map_err(|_| "call recovery encryption failed".to_string())?;
        plaintext.zeroize();

        let mut secret = recovery_keys.secret_key().to_secret_hex();
        if let Err(error) = self.keys.store(call_id, &secret) {
            secret.zeroize();
            return Err(error);
        }
        secret.zeroize();

        let envelope = RecoveryEnvelope {
            schema_version: 1,
            call_id,
            expires_at_ms,
            ciphertext,
        };
        let bytes = serde_json::to_vec(&envelope)
            .map_err(|_| "call recovery envelope could not be serialized".to_string())?;
        if bytes.len() > MAX_RECOVERY_ENVELOPE_BYTES {
            let _ = self.keys.delete(call_id);
            return Err("call recovery envelope exceeds its local bound".into());
        }
        if let Err(error) = self.blobs.write(call_id, &bytes) {
            let _ = self.keys.delete(call_id);
            let _ = self.blobs.delete(call_id);
            return Err(error);
        }
        Ok(())
    }

    pub fn load(&self, call_id: Uuid, now_ms: u64) -> Result<Option<RecoveryPayload>, String> {
        let Some(bytes) = self.blobs.load(call_id)? else {
            return Ok(None);
        };
        if bytes.len() > MAX_RECOVERY_ENVELOPE_BYTES {
            let _ = self.purge(call_id);
            return Err("call recovery envelope exceeds its local bound".into());
        }
        let envelope: RecoveryEnvelope = serde_json::from_slice(&bytes).map_err(|_| {
            let _ = self.purge(call_id);
            "call recovery envelope is invalid".to_string()
        })?;
        if envelope.schema_version != 1
            || envelope.call_id != call_id
            || envelope.call_id.get_version_num() != 4
        {
            let _ = self.purge(call_id);
            return Err("call recovery metadata is invalid".into());
        }
        if now_ms > envelope.expires_at_ms {
            self.purge(call_id)?;
            return Ok(None);
        }
        let mut secret = self
            .keys
            .load(call_id)?
            .ok_or_else(|| "call recovery decryption material is unavailable".to_string())?;
        let recovery_keys = Keys::parse(&secret).map_err(|_| {
            secret.zeroize();
            "call recovery decryption material is invalid".to_string()
        })?;
        secret.zeroize();
        let mut plaintext = nip44::decrypt(
            recovery_keys.secret_key(),
            &recovery_keys.public_key(),
            &envelope.ciphertext,
        )
        .map_err(|_| "call recovery authentication failed".to_string())?;
        let payload: RecoveryPayload = serde_json::from_str(&plaintext).map_err(|_| {
            plaintext.zeroize();
            "call recovery payload is invalid".to_string()
        })?;
        plaintext.zeroize();
        if validate_recovery_input(
            payload.call_id,
            payload.ended_at_ms,
            payload.expires_at_ms,
            &payload.segments,
        )
        .is_err()
            || payload.schema_version != 1
            || payload.call_id != envelope.call_id
            || payload.expires_at_ms != envelope.expires_at_ms
        {
            let _ = self.purge(call_id);
            return Err("authenticated call recovery metadata does not match its envelope".into());
        }
        Ok(Some(payload))
    }

    pub fn canonical_record_arrived(&self, call_id: Uuid) -> Result<(), String> {
        self.purge(call_id)
    }

    pub fn purge_expired(&self, now_ms: u64) -> Result<Vec<Uuid>, String> {
        let mut purged = Vec::new();
        let mut call_ids = self.blobs.list_call_ids()?;
        call_ids.sort_unstable();
        for call_id in call_ids {
            let Some(bytes) = self.blobs.load(call_id)? else {
                continue;
            };
            let envelope: RecoveryEnvelope = serde_json::from_slice(&bytes).map_err(|_| {
                let _ = self.purge(call_id);
                "call recovery envelope is invalid".to_string()
            })?;
            if envelope.schema_version != 1
                || envelope.call_id != call_id
                || envelope.expires_at_ms < now_ms
            {
                self.purge(call_id)?;
                purged.push(call_id);
            }
        }
        Ok(purged)
    }

    pub fn purge(&self, call_id: Uuid) -> Result<(), String> {
        let key_result = self.keys.delete(call_id);
        let blob_result = self.blobs.delete(call_id);
        match (key_result, blob_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(key), Ok(())) => Err(format!("call recovery key purge failed: {key}")),
            (Ok(()), Err(blob)) => Err(format!("call recovery file purge failed: {blob}")),
            (Err(key), Err(blob)) => Err(format!(
                "call recovery key and file purge failed: {key}; {blob}"
            )),
        }
    }
}

fn validate_recovery_input(
    call_id: Uuid,
    ended_at_ms: u64,
    expires_at_ms: u64,
    segments: &[FinalizedSegment],
) -> Result<(), String> {
    let lifetime = expires_at_ms.checked_sub(ended_at_ms);
    if call_id.get_version_num() != 4
        || lifetime.is_none_or(|value| value == 0 || value > MAX_RECOVERY_AGE_MS)
        || segments.is_empty()
        || segments.len() > MAX_RECOVERY_SEGMENTS
    {
        return Err("invalid call recovery lifetime, session, or segment count".into());
    }
    let mut text_bytes = 0usize;
    let mut previous_sequence = None;
    for segment in segments {
        text_bytes = text_bytes
            .checked_add(segment.text.len())
            .ok_or_else(|| "call recovery text bound overflowed".to_string())?;
        if segment.schema_version != 1
            || segment.call_id != call_id
            || segment.segment_id.get_version_num() != 4
            || segment.sequence == 0
            || previous_sequence.is_some_and(|previous| segment.sequence <= previous)
            || segment.text.trim().is_empty()
            || segment.ended_at_ms < segment.started_at_ms
            || segment.confidence > 100
        {
            return Err("invalid finalized segment in call recovery".into());
        }
        previous_sequence = Some(segment.sequence);
    }
    if text_bytes > MAX_RECOVERY_TEXT_BYTES {
        return Err("call recovery transcript exceeds its local bound".into());
    }
    Ok(())
}
