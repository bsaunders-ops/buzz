//! Relay-mediated authorization recheck for private insight evidence.

use std::sync::Arc;

use buzz_auth::DEFAULT_REPLAY_TTL_SECS;
use buzz_core::core_protocol::{
    CoreEnvelope, EvidenceResolveResultPayload, EvidenceResolveStatus, EvidenceResolvedSourceType,
    MAX_EVIDENCE_RESOLVE_LIFETIME_SECONDS,
};
use buzz_core::event::StoredEvent;
use buzz_db::core_storage::{
    EvidenceResolution, EvidenceResolveRequest, ServerResolvedSourceAudience,
};
use buzz_pubsub::EventTopic;
use nostr::{Event, EventId, Keys, PublicKey};
use sha2::{Digest, Sha256};
use tracing::warn;
use uuid::Uuid;

use crate::connection::ConnectionState;
use crate::protocol::RelayMessage;
use crate::state::AppState;

const EVIDENCE_NONCE_DOMAIN: &[u8] = b"core-evidence-resolve/v1/nonce";

pub(crate) fn resolved_source_type(value: &str) -> Option<EvidenceResolvedSourceType> {
    match value {
        "email" => Some(EvidenceResolvedSourceType::Email),
        "calendar_event" => Some(EvidenceResolvedSourceType::CalendarEvent),
        "document" => Some(EvidenceResolvedSourceType::Document),
        "spreadsheet" => Some(EvidenceResolvedSourceType::Spreadsheet),
        "presentation" => Some(EvidenceResolvedSourceType::Presentation),
        "crm_record" => Some(EvidenceResolvedSourceType::CrmRecord),
        "crm_transcript" => Some(EvidenceResolvedSourceType::CrmTranscript),
        _ => None,
    }
}

pub(crate) fn evidence_nonce_event_id(owner: &PublicKey, nonce: &str) -> EventId {
    let mut hasher = Sha256::new();
    hasher.update(EVIDENCE_NONCE_DOMAIN);
    hasher.update(owner.to_bytes());
    hasher.update(nonce.as_bytes());
    EventId::from_byte_array(hasher.finalize().into())
}

pub(crate) fn build_result_event(
    channel_id: Uuid,
    owner: &PublicKey,
    relay_keys: &Keys,
    payload: &EvidenceResolveResultPayload,
    now: i64,
) -> Result<Event, ()> {
    let builder = buzz_sdk::core_protocol::encrypt_core_evidence_resolve_result(
        channel_id, owner, relay_keys, payload, now,
    )
    .map_err(|_| ())?;
    builder.sign_with_keys(relay_keys).map_err(|_| ())
}

fn unavailable_result(
    request_id: buzz_core::core_protocol::CanonicalUuidV4,
    expires_at: i64,
    now: i64,
) -> Result<EvidenceResolveResultPayload, ()> {
    EvidenceResolveResultPayload::unresolved(
        request_id,
        EvidenceResolveStatus::Unavailable,
        expires_at,
        now,
    )
    .map_err(|_| ())
}

/// Resolve a signature-verified, Core-authorized kind-24823 request.
///
/// The request and result remain ephemeral. Only the encrypted result is sent
/// through Redis, and no provider metadata is included in logs.
pub(crate) async fn handle_verified_request(
    event: &Event,
    envelope: CoreEnvelope,
    event_id_hex: &str,
    conn: &Arc<ConnectionState>,
    state: &Arc<AppState>,
) {
    let now = chrono::Utc::now().timestamp();
    let payload =
        match buzz_sdk::core_protocol::parse_evidence_resolve_request_at(&event.content, now) {
            Ok(payload) => payload,
            Err(_) => {
                conn.send(RelayMessage::ok(
                    event_id_hex,
                    false,
                    "invalid: evidence resolution request",
                ));
                return;
            }
        };

    let replay_id = evidence_nonce_event_id(&event.pubkey, payload.nonce.as_str());
    match state
        .nip98_replay
        .try_mark(&conn.tenant, &replay_id, DEFAULT_REPLAY_TTL_SECS)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            conn.send(RelayMessage::ok(
                event_id_hex,
                false,
                "invalid: evidence resolution nonce was already used",
            ));
            return;
        }
        Err(_) => {
            warn!(
                event_id = %event_id_hex,
                "evidence resolution replay guard unavailable"
            );
            conn.send(RelayMessage::ok(
                event_id_hex,
                false,
                "error: evidence resolution unavailable",
            ));
            return;
        }
    }

    let owner_bytes = event.pubkey.to_bytes();
    let channels = [envelope.channel_id];
    let audience = ServerResolvedSourceAudience::new(&owner_bytes, &channels);
    let chunk_hash = match hex::decode(payload.expected_chunk_hash.as_str()) {
        Ok(hash) => hash,
        Err(_) => {
            conn.send(RelayMessage::ok(
                event_id_hex,
                false,
                "invalid: evidence resolution hash",
            ));
            return;
        }
    };
    let request = EvidenceResolveRequest {
        item_id: payload.resolver_id.source_item_id(),
        chunk_hash: &chunk_hash,
        channel_id: envelope.channel_id,
        audience,
    };
    let resolution = match state
        .db
        .resolve_source_evidence(conn.tenant.community(), request)
        .await
    {
        Ok(resolution) => resolution,
        Err(_) => {
            warn!(event_id = %event_id_hex, "evidence resolution database read failed");
            EvidenceResolution::Unavailable
        }
    };

    let Some(max_result_expiry) = now.checked_add(MAX_EVIDENCE_RESOLVE_LIFETIME_SECONDS) else {
        conn.send(RelayMessage::ok(
            event_id_hex,
            false,
            "error: evidence resolution unavailable",
        ));
        return;
    };
    // A resolution must never outlive the short-lived request that authorized it.
    let expires_at = payload.expires_at.min(max_result_expiry);
    let result = match resolution {
        EvidenceResolution::Resolved(resolved) => match resolved_source_type(&resolved.source_type)
        {
            Some(source_type) => EvidenceResolveResultPayload::resolved(
                payload.request_id,
                expires_at,
                &resolved.title,
                resolved.modified_at.timestamp(),
                source_type,
                &resolved.resolvable_link,
                now,
            )
            .map_err(|_| ())
            .or_else(|_| unavailable_result(payload.request_id, expires_at, now)),
            None => unavailable_result(payload.request_id, expires_at, now),
        },
        EvidenceResolution::Denied => EvidenceResolveResultPayload::unresolved(
            payload.request_id,
            EvidenceResolveStatus::Denied,
            expires_at,
            now,
        )
        .map_err(|_| ()),
        EvidenceResolution::Stale => EvidenceResolveResultPayload::unresolved(
            payload.request_id,
            EvidenceResolveStatus::Stale,
            expires_at,
            now,
        )
        .map_err(|_| ()),
        EvidenceResolution::Unavailable => unavailable_result(payload.request_id, expires_at, now),
    };
    let Ok(result) = result else {
        conn.send(RelayMessage::ok(
            event_id_hex,
            false,
            "error: evidence resolution unavailable",
        ));
        return;
    };
    let response = match build_result_event(
        envelope.channel_id,
        &event.pubkey,
        &state.relay_keypair,
        &result,
        now,
    ) {
        Ok(response) => response,
        Err(()) => {
            warn!(event_id = %event_id_hex, "evidence resolution response build failed");
            conn.send(RelayMessage::ok(
                event_id_hex,
                false,
                "error: evidence resolution unavailable",
            ));
            return;
        }
    };

    state.mark_local_event(conn.tenant.community(), &response.id);
    if state
        .pubsub
        .publish_event(
            &conn.tenant,
            EventTopic::Channel(envelope.channel_id),
            &response,
        )
        .await
        .is_err()
    {
        state
            .local_event_ids
            .invalidate(&(conn.tenant.community(), response.id.to_bytes()));
        warn!(event_id = %event_id_hex, "evidence resolution Redis publish failed");
    }
    let stored = StoredEvent::new(response, Some(envelope.channel_id));
    super::event::fan_out_event_to_local_subscribers(state, conn.tenant.community(), &stored).await;
    conn.send(RelayMessage::ok(event_id_hex, true, ""));
}

#[cfg(test)]
mod tests {
    use buzz_core::core_protocol::{
        CanonicalUuidV4, EvidenceResolveResultPayload, EvidenceResolveStatus,
        EvidenceResolvedSourceType,
    };
    use nostr::Keys;
    use uuid::Uuid;

    use super::{build_result_event, evidence_nonce_event_id, resolved_source_type};

    const CHANNEL_ID: &str = "550e8400-e29b-41d4-a716-446655440099";
    const REQUEST_ID: &str = "550e8400-e29b-41d4-a716-446655440010";

    #[test]
    fn maps_only_closed_persisted_source_types() {
        assert_eq!(
            resolved_source_type("crm_record"),
            Some(EvidenceResolvedSourceType::CrmRecord)
        );
        assert_eq!(
            resolved_source_type("crm_transcript"),
            Some(EvidenceResolvedSourceType::CrmTranscript)
        );
        assert_eq!(resolved_source_type("unknown"), None);
    }

    #[test]
    fn nonce_replay_coordinate_is_author_and_nonce_bound() {
        let owner_a = Keys::generate().public_key();
        let owner_b = Keys::generate().public_key();
        let nonce_a = "a".repeat(64);
        let nonce_b = "b".repeat(64);

        assert_eq!(
            evidence_nonce_event_id(&owner_a, &nonce_a),
            evidence_nonce_event_id(&owner_a, &nonce_a)
        );
        assert_ne!(
            evidence_nonce_event_id(&owner_a, &nonce_a),
            evidence_nonce_event_id(&owner_b, &nonce_a)
        );
        assert_ne!(
            evidence_nonce_event_id(&owner_a, &nonce_a),
            evidence_nonce_event_id(&owner_a, &nonce_b)
        );
    }

    #[test]
    fn result_event_is_relay_signed_encrypted_and_exactly_addressed() {
        let relay = Keys::generate();
        let owner = Keys::generate();
        let now = 1_700_000_000;
        let request_id = CanonicalUuidV4::try_from(REQUEST_ID).expect("request UUID");
        let payload = EvidenceResolveResultPayload::unresolved(
            request_id,
            EvidenceResolveStatus::Denied,
            now + 60,
            now,
        )
        .expect("denied payload");
        let channel_id = Uuid::parse_str(CHANNEL_ID).expect("channel UUID");

        let event = build_result_event(channel_id, &owner.public_key(), &relay, &payload, now)
            .expect("encrypted result event");

        assert_eq!(event.kind.as_u16(), 24_824);
        assert_eq!(event.pubkey, relay.public_key());
        assert!(event.verify_id());
        assert!(event.verify_signature());
        let tags: Vec<Vec<String>> = event
            .tags
            .iter()
            .map(|tag| tag.as_slice().to_vec())
            .collect();
        assert_eq!(
            tags,
            vec![
                vec!["h".into(), CHANNEL_ID.into()],
                vec!["p".into(), owner.public_key().to_hex()],
            ]
        );
        let decrypted: EvidenceResolveResultPayload =
            buzz_core::observer::decrypt_observer_payload(&owner, &event)
                .expect("owner decrypts relay result");
        assert_eq!(decrypted, payload);
    }
}
