use buzz_core_pkg::{
    core_protocol::{CopilotSuggestionPayload, TranscriptSegmentPayload},
    kind::{is_ephemeral, KIND_CORE_COPILOT_SUGGESTION, KIND_CORE_TRANSCRIPT_SEGMENT},
};
use nostr::{nips::nip44, Event, EventBuilder, JsonUtil, Keys, Kind};
use uuid::Uuid;

use super::{
    decrypt_copilot_suggestion, encrypt_finalized_segment, CallCaptureRoute, FinalizedSegment,
    TranscriptSpeaker,
};

fn finalized(call_id: Uuid, text: &str) -> FinalizedSegment {
    FinalizedSegment {
        schema_version: 1,
        segment_id: Uuid::new_v4(),
        call_id,
        sequence: 1,
        speaker: TranscriptSpeaker::Others,
        text: text.into(),
        started_at_ms: 10,
        ended_at_ms: 20,
        confidence: 92,
        model_version: "parakeet-v1".into(),
    }
}

#[test]
fn finalized_segment_is_protocol_valid_nip44_with_only_frozen_private_tags() {
    let owner = Keys::generate();
    let assistant = Keys::generate();
    let channel_id = Uuid::new_v4();
    let call_id = Uuid::new_v4();
    let sentinel = "MNPI-SENTINEL-ONLY-IN-CIPHERTEXT";
    let route = CallCaptureRoute::new(channel_id, assistant.public_key()).unwrap();

    let event = encrypt_finalized_segment(&owner, &route, &finalized(call_id, sentinel)).unwrap();
    assert_eq!(
        event.kind,
        Kind::Custom(KIND_CORE_TRANSCRIPT_SEGMENT as u16)
    );
    assert!(event.verify().is_ok());
    assert!(!event.content.contains(sentinel));
    assert_eq!(event.tags.len(), 2);
    let tags: Vec<_> = event.tags.iter().collect();
    assert_eq!(tags[0].as_slice()[0], "h");
    assert_eq!(tags[0].as_slice()[1], channel_id.to_string());
    assert_eq!(tags[1].as_slice()[0], "p");
    assert_eq!(tags[1].as_slice()[1], assistant.public_key().to_hex());

    let plaintext =
        nip44::decrypt(assistant.secret_key(), &owner.public_key(), &event.content).unwrap();
    let payload: TranscriptSegmentPayload = serde_json::from_str(&plaintext).unwrap();
    assert_eq!(payload.call_id.as_uuid(), call_id);
    assert_eq!(payload.text.as_str(), sentinel);
}

fn signed_suggestion(
    assistant: &Keys,
    owner: &Keys,
    route: &CallCaptureRoute,
    call_id: Uuid,
) -> Event {
    let plaintext = serde_json::json!({
        "schema_version": 1,
        "suggestion_id": Uuid::new_v4(),
        "call_id": call_id,
        "sequence": 1,
        "category": "decision",
        "interrupt": "quiet",
        "text": "Decision captured",
        "created_at": 1_775_000_000_i64,
        "model_version": "gpt-5",
        "confidence": 90,
        "evidence_hashes": []
    });
    let validated: CopilotSuggestionPayload = serde_json::from_value(plaintext).unwrap();
    let ciphertext = nip44::encrypt(
        assistant.secret_key(),
        &owner.public_key(),
        serde_json::to_string(&validated).unwrap(),
        nip44::Version::V2,
    )
    .unwrap();
    buzz_sdk_pkg::core_protocol::build_core_copilot_suggestion(
        route.channel_id(),
        &owner.public_key(),
        &ciphertext,
    )
    .unwrap()
    .sign_with_keys(assistant)
    .unwrap()
}

#[test]
fn inbound_suggestion_requires_signature_pair_channel_active_call_and_exact_kind() {
    let owner = Keys::generate();
    let assistant = Keys::generate();
    let route = CallCaptureRoute::new(Uuid::new_v4(), assistant.public_key()).unwrap();
    let call_id = Uuid::new_v4();
    let event = signed_suggestion(&assistant, &owner, &route, call_id);

    let payload = decrypt_copilot_suggestion(&owner, &route, call_id, &event).unwrap();
    assert_eq!(payload.call_id.as_uuid(), call_id);
    assert_eq!(payload.text.as_str(), "Decision captured");

    assert!(decrypt_copilot_suggestion(&owner, &route, Uuid::new_v4(), &event).is_err());
    let wrong_route = CallCaptureRoute::new(Uuid::new_v4(), assistant.public_key()).unwrap();
    assert!(decrypt_copilot_suggestion(&owner, &wrong_route, call_id, &event).is_err());

    let mut forged_json: serde_json::Value = serde_json::from_str(&event.as_json()).unwrap();
    forged_json["content"] = serde_json::Value::String("A".repeat(132));
    let forged: Event = serde_json::from_value(forged_json).unwrap();
    assert!(decrypt_copilot_suggestion(&owner, &route, call_id, &forged).is_err());

    let wrong_kind = EventBuilder::new(
        Kind::Custom(KIND_CORE_TRANSCRIPT_SEGMENT as u16),
        event.content,
    )
    .tags(event.tags)
    .sign_with_keys(&assistant)
    .unwrap();
    assert!(decrypt_copilot_suggestion(&owner, &route, call_id, &wrong_kind).is_err());
}

#[test]
fn all_call_transport_kinds_are_ephemeral_and_outside_persistent_queries() {
    for kind in [24820, 24821, KIND_CORE_COPILOT_SUGGESTION] {
        assert!(is_ephemeral(kind));
        assert!(!buzz_core_pkg::core_protocol::is_persistent_core_kind(kind));
    }
}

#[test]
fn route_debug_redacts_pair_and_channel_identifiers() {
    let assistant = Keys::generate();
    let route = CallCaptureRoute::new(Uuid::new_v4(), assistant.public_key()).unwrap();
    let debug = format!("{route:?}");
    assert!(!debug.contains(&route.channel_id().to_string()));
    assert!(!debug.contains(&assistant.public_key().to_hex()));
    assert!(debug.contains("<redacted>"));
}
