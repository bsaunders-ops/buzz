use std::fmt;

use buzz_core_pkg::{
    core_protocol::{self, CallControlPayload, CopilotSuggestionPayload, TranscriptSegmentPayload},
    kind::{KIND_CORE_COPILOT_SUGGESTION, KIND_CORE_TRANSCRIPT_SEGMENT},
};
use nostr::{nips::nip44, Event, Keys, PublicKey};
use uuid::Uuid;

use super::FinalizedSegment;

/// Frozen private pair/channel route supplied by sealed Core configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct CallCaptureRoute {
    channel_id: Uuid,
    assistant: PublicKey,
}

impl CallCaptureRoute {
    pub fn new(channel_id: Uuid, assistant: PublicKey) -> Result<Self, String> {
        if channel_id.is_nil() {
            return Err("call capture requires a non-nil private channel identifier".into());
        }
        Ok(Self {
            channel_id,
            assistant,
        })
    }

    pub const fn channel_id(&self) -> Uuid {
        self.channel_id
    }

    pub const fn assistant(&self) -> PublicKey {
        self.assistant
    }
}

impl fmt::Debug for CallCaptureRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallCaptureRoute")
            .field("channel_id", &"<redacted>")
            .field("assistant", &"<redacted>")
            .finish()
    }
}

/// Encrypt and sign one locally finalized segment for the exact Core assistant.
pub fn encrypt_finalized_segment(
    owner: &Keys,
    route: &CallCaptureRoute,
    segment: &FinalizedSegment,
) -> Result<Event, String> {
    if owner.public_key() == route.assistant {
        return Err("call capture route must target a distinct assistant identity".into());
    }
    let value = serde_json::to_value(segment)
        .map_err(|_| "finalized transcript could not be encoded".to_string())?;
    let payload: TranscriptSegmentPayload = serde_json::from_value(value)
        .map_err(|_| "finalized transcript violates the frozen protocol".to_string())?;
    if payload.sequence == 0 {
        return Err("finalized transcript sequence must be positive".into());
    }
    let plaintext = serde_json::to_string(&payload)
        .map_err(|_| "finalized transcript could not be serialized".to_string())?;
    let ciphertext = nip44::encrypt(
        owner.secret_key(),
        &route.assistant,
        plaintext,
        nip44::Version::V2,
    )
    .map_err(|_| "finalized transcript encryption failed".to_string())?;
    let event = buzz_sdk_pkg::core_protocol::build_core_transcript_segment(
        route.channel_id,
        &route.assistant,
        &ciphertext,
    )
    .map_err(|_| "finalized transcript envelope failed".to_string())?
    .sign_with_keys(owner)
    .map_err(|_| "finalized transcript signing failed".to_string())?;
    validate_outbound_event(&event, owner, route, KIND_CORE_TRANSCRIPT_SEGMENT)?;
    Ok(event)
}

/// Encrypt and sign one session control update for the same frozen route.
pub fn encrypt_call_control(
    owner: &Keys,
    route: &CallCaptureRoute,
    payload: &CallControlPayload,
) -> Result<Event, String> {
    if owner.public_key() == route.assistant || payload.sequence == 0 {
        return Err("invalid call-control route or sequence".into());
    }
    let plaintext = serde_json::to_string(payload)
        .map_err(|_| "call-control payload could not be serialized".to_string())?;
    let ciphertext = nip44::encrypt(
        owner.secret_key(),
        &route.assistant,
        plaintext,
        nip44::Version::V2,
    )
    .map_err(|_| "call-control encryption failed".to_string())?;
    let event = buzz_sdk_pkg::core_protocol::build_core_call_control(
        route.channel_id,
        &route.assistant,
        &ciphertext,
    )
    .map_err(|_| "call-control envelope failed".to_string())?
    .sign_with_keys(owner)
    .map_err(|_| "call-control signing failed".to_string())?;
    validate_outbound_event(
        &event,
        owner,
        route,
        buzz_core_pkg::kind::KIND_CORE_CALL_CONTROL,
    )?;
    Ok(event)
}

/// Verify, decrypt, and parse one UI-only suggestion from the exact assistant.
pub fn decrypt_copilot_suggestion(
    owner: &Keys,
    route: &CallCaptureRoute,
    active_call_id: Uuid,
    event: &Event,
) -> Result<CopilotSuggestionPayload, String> {
    if event.kind.as_u16() != KIND_CORE_COPILOT_SUGGESTION as u16
        || event.pubkey != route.assistant
        || owner.public_key() == route.assistant
        || event.verify().is_err()
    {
        return Err("copilot suggestion signature, kind, or author is invalid".into());
    }
    let envelope = core_protocol::validate_core_envelope(event)
        .map_err(|_| "copilot suggestion private envelope is invalid".to_string())?;
    if envelope.channel_id != route.channel_id || envelope.recipient != owner.public_key() {
        return Err("copilot suggestion does not match the active private route".into());
    }
    let plaintext = nip44::decrypt(owner.secret_key(), &route.assistant, &event.content)
        .map_err(|_| "copilot suggestion decryption failed".to_string())?;
    let payload: CopilotSuggestionPayload =
        buzz_sdk_pkg::core_protocol::parse_core_payload(&plaintext)
            .map_err(|_| "copilot suggestion payload is invalid".to_string())?;
    if payload.call_id.as_uuid() != active_call_id || payload.sequence == 0 {
        return Err("copilot suggestion does not match the active call session".into());
    }
    Ok(payload)
}

fn validate_outbound_event(
    event: &Event,
    owner: &Keys,
    route: &CallCaptureRoute,
    expected_kind: u32,
) -> Result<(), String> {
    if event.kind.as_u16() != expected_kind as u16
        || event.pubkey != owner.public_key()
        || event.verify().is_err()
    {
        return Err("outbound call event signature or kind is invalid".into());
    }
    let envelope = core_protocol::validate_core_envelope(event)
        .map_err(|_| "outbound call private envelope is invalid".to_string())?;
    if envelope.channel_id != route.channel_id || envelope.recipient != route.assistant {
        return Err("outbound call event escaped the frozen private route".into());
    }
    Ok(())
}
