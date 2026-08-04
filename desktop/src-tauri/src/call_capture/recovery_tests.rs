use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use uuid::Uuid;

use super::{
    FinalizedSegment, RecoveryBlobStore, RecoveryKeyStore, RecoveryManager, TranscriptSpeaker,
    MAX_RECOVERY_AGE_MS,
};

#[derive(Clone, Default)]
struct MemoryKeys {
    values: Arc<Mutex<HashMap<Uuid, String>>>,
    fail_store: Arc<Mutex<bool>>,
}

impl RecoveryKeyStore for MemoryKeys {
    fn load(&self, call_id: Uuid) -> Result<Option<String>, String> {
        Ok(self.values.lock().unwrap().get(&call_id).cloned())
    }

    fn store(&self, call_id: Uuid, secret: &str) -> Result<(), String> {
        if *self.fail_store.lock().unwrap() {
            return Err("keyring unavailable".into());
        }
        self.values
            .lock()
            .unwrap()
            .insert(call_id, secret.to_string());
        Ok(())
    }

    fn delete(&self, call_id: Uuid) -> Result<(), String> {
        self.values.lock().unwrap().remove(&call_id);
        Ok(())
    }
}

#[derive(Clone, Default)]
struct MemoryBlobs {
    values: Arc<Mutex<HashMap<Uuid, Vec<u8>>>>,
    fail_write: Arc<Mutex<bool>>,
}

impl RecoveryBlobStore for MemoryBlobs {
    fn load(&self, call_id: Uuid) -> Result<Option<Vec<u8>>, String> {
        Ok(self.values.lock().unwrap().get(&call_id).cloned())
    }

    fn write(&self, call_id: Uuid, bytes: &[u8]) -> Result<(), String> {
        if *self.fail_write.lock().unwrap() {
            return Err("disk unavailable".into());
        }
        self.values.lock().unwrap().insert(call_id, bytes.to_vec());
        Ok(())
    }

    fn delete(&self, call_id: Uuid) -> Result<(), String> {
        self.values.lock().unwrap().remove(&call_id);
        Ok(())
    }

    fn list_call_ids(&self) -> Result<Vec<Uuid>, String> {
        Ok(self.values.lock().unwrap().keys().copied().collect())
    }
}

fn segments(call_id: Uuid, text: &str) -> Vec<FinalizedSegment> {
    vec![FinalizedSegment {
        schema_version: 1,
        segment_id: Uuid::new_v4(),
        call_id,
        sequence: 1,
        speaker: TranscriptSpeaker::SelfSpeaker,
        text: text.into(),
        started_at_ms: 10,
        ended_at_ms: 20,
        confidence: 90,
        model_version: "parakeet-v1".into(),
    }]
}

#[test]
fn recovery_ciphertext_round_trips_without_plaintext_or_unauthenticated_metadata() {
    let keys = MemoryKeys::default();
    let blobs = MemoryBlobs::default();
    let manager = RecoveryManager::new(keys.clone(), blobs.clone());
    let call_id = Uuid::new_v4();
    let sentinel = "MNPI-SENTINEL-RECOVERY";
    let expires = 1_000 + MAX_RECOVERY_AGE_MS;

    manager
        .persist(call_id, 1_000, expires, segments(call_id, sentinel))
        .unwrap();
    let raw = blobs.load(call_id).unwrap().unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains(sentinel));

    let restored = manager.load(call_id, 2_000).unwrap().unwrap();
    assert_eq!(restored.call_id, call_id);
    assert_eq!(restored.expires_at_ms, expires);
    assert_eq!(restored.segments[0].text, sentinel);

    let mut envelope: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    envelope["expires_at_ms"] = serde_json::json!(expires - 1);
    blobs
        .write(call_id, &serde_json::to_vec(&envelope).unwrap())
        .unwrap();
    assert!(manager.load(call_id, 2_000).is_err());
}

#[test]
fn canonical_arrival_and_expiry_remove_both_ciphertext_and_decryption_material() {
    let keys = MemoryKeys::default();
    let blobs = MemoryBlobs::default();
    let manager = RecoveryManager::new(keys.clone(), blobs.clone());
    let canonical_call = Uuid::new_v4();
    let expired_call = Uuid::new_v4();

    manager
        .persist(
            canonical_call,
            1_000,
            2_000,
            segments(canonical_call, "one"),
        )
        .unwrap();
    manager
        .persist(expired_call, 1_000, 2_000, segments(expired_call, "two"))
        .unwrap();
    manager.canonical_record_arrived(canonical_call).unwrap();
    assert!(keys.load(canonical_call).unwrap().is_none());
    assert!(blobs.load(canonical_call).unwrap().is_none());

    assert_eq!(manager.purge_expired(2_001).unwrap(), vec![expired_call]);
    assert!(keys.load(expired_call).unwrap().is_none());
    assert!(blobs.load(expired_call).unwrap().is_none());
}

#[test]
fn ciphertext_cannot_be_opened_after_key_purge_even_if_a_blob_copy_survives() {
    let keys = MemoryKeys::default();
    let blobs = MemoryBlobs::default();
    let manager = RecoveryManager::new(keys.clone(), blobs.clone());
    let call_id = Uuid::new_v4();
    manager
        .persist(call_id, 1_000, 2_000, segments(call_id, "sensitive"))
        .unwrap();
    let surviving_copy = blobs.load(call_id).unwrap().unwrap();
    manager.purge(call_id).unwrap();
    blobs.write(call_id, &surviving_copy).unwrap();

    assert!(manager.load(call_id, 1_500).is_err());
}

#[test]
fn every_persist_failure_rolls_back_partial_key_or_blob_material() {
    let keys = MemoryKeys::default();
    let blobs = MemoryBlobs::default();
    let manager = RecoveryManager::new(keys.clone(), blobs.clone());
    let call_id = Uuid::new_v4();
    *blobs.fail_write.lock().unwrap() = true;

    assert!(manager
        .persist(call_id, 1_000, 2_000, segments(call_id, "sensitive"))
        .is_err());
    assert!(keys.load(call_id).unwrap().is_none());
    assert!(blobs.load(call_id).unwrap().is_none());

    *blobs.fail_write.lock().unwrap() = false;
    *keys.fail_store.lock().unwrap() = true;
    assert!(manager
        .persist(call_id, 1_000, 2_000, segments(call_id, "sensitive"))
        .is_err());
    assert!(blobs.load(call_id).unwrap().is_none());
}

#[test]
fn empty_overlong_future_or_foreign_session_recovery_fails_closed() {
    let manager = RecoveryManager::new(MemoryKeys::default(), MemoryBlobs::default());
    let call_id = Uuid::new_v4();
    assert!(manager.persist(call_id, 1_000, 2_000, Vec::new()).is_err());
    assert!(manager
        .persist(
            call_id,
            1_000,
            1_000 + MAX_RECOVERY_AGE_MS + 1,
            segments(call_id, "too long"),
        )
        .is_err());
    assert!(manager
        .persist(call_id, 2_000, 1_999, segments(call_id, "reversed"),)
        .is_err());
    assert!(manager
        .persist(call_id, 1_000, 2_000, segments(Uuid::new_v4(), "foreign"),)
        .is_err());
}
