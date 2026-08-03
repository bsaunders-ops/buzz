//! Typed SDK surface for the frozen Core Month-1 protocol.

use serde::{de::DeserializeOwned, Serialize};

use nostr::{nips::nip44::v2::ConversationKey, EventBuilder, Kind, PublicKey, Tag};
use uuid::Uuid;

use crate::SdkError;

pub use buzz_core::core_protocol::*;

/// Parse a relay-readable or decrypted Core payload with fail-closed serde rules.
pub fn parse_core_payload<T: DeserializeOwned>(json: &str) -> Result<T, SdkError> {
    serde_json::from_str(json).map_err(|error| SdkError::InvalidInput(error.to_string()))
}

/// Parse and wall-clock validate a Core action proposal.
pub fn parse_action_proposal_at(json: &str, now: i64) -> Result<ActionProposalPayload, SdkError> {
    let payload: ActionProposalPayload = parse_core_payload(json)?;
    payload
        .validate_at(now)
        .map_err(|error| SdkError::InvalidInput(error.to_string()))?;
    Ok(payload)
}

fn private_tags(channel_id: Uuid, recipient: &PublicKey) -> Result<Vec<Tag>, SdkError> {
    Ok(vec![
        Tag::parse(["h", channel_id.hyphenated().to_string().as_str()])
            .map_err(|error| SdkError::InvalidTag(error.to_string()))?,
        Tag::parse(["p", recipient.to_hex().as_str()])
            .map_err(|error| SdkError::InvalidTag(error.to_string()))?,
    ])
}

fn plaintext_builder<T: Serialize>(
    kind: u32,
    channel_id: Uuid,
    recipient: &PublicKey,
    payload: &T,
) -> Result<EventBuilder, SdkError> {
    let content = serde_json::to_string(payload)
        .map_err(|error| SdkError::InvalidInput(error.to_string()))?;
    validate_core_plaintext_content_size(&content)
        .map_err(|error| SdkError::InvalidInput(error.to_string()))?;
    Ok(EventBuilder::new(Kind::Custom(kind as u16), content)
        .tags(private_tags(channel_id, recipient)?))
}

fn encrypted_builder(
    kind: u32,
    channel_id: Uuid,
    recipient: &PublicKey,
    ciphertext: &str,
    coordinate: Option<&Sha256Hex>,
) -> Result<EventBuilder, SdkError> {
    if buzz_core::observer::validate_syntactic_nip44_v2(ciphertext).is_err() {
        return Err(SdkError::InvalidInput(
            "ciphertext must fit the NIP-44 v2 envelope".into(),
        ));
    }
    let mut tags = private_tags(channel_id, recipient)?;
    if let Some(coordinate) = coordinate {
        tags.push(
            Tag::parse(["d", coordinate.as_str()])
                .map_err(|error| SdkError::InvalidTag(error.to_string()))?,
        );
    }
    Ok(EventBuilder::new(Kind::Custom(kind as u16), ciphertext).tags(tags))
}

/// Build a kind-44300 assistant insight.
pub fn build_core_insight(
    channel_id: Uuid,
    owner: &PublicKey,
    payload: &InsightPayload,
) -> Result<EventBuilder, SdkError> {
    plaintext_builder(
        buzz_core::kind::KIND_CORE_INSIGHT,
        channel_id,
        owner,
        payload,
    )
}

/// Build a kind-44301 owner insight disposition.
pub fn build_core_insight_disposition(
    channel_id: Uuid,
    agent: &PublicKey,
    payload: &InsightDispositionPayload,
) -> Result<EventBuilder, SdkError> {
    plaintext_builder(
        buzz_core::kind::KIND_CORE_INSIGHT_DISPOSITION,
        channel_id,
        agent,
        payload,
    )
}

/// Build a kind-44310 external action proposal.
pub fn build_core_action_proposal(
    channel_id: Uuid,
    owner: &PublicKey,
    payload: &ActionProposalPayload,
    now: i64,
) -> Result<EventBuilder, SdkError> {
    payload
        .validate_at(now)
        .map_err(|error| SdkError::InvalidInput(error.to_string()))?;
    plaintext_builder(
        buzz_core::kind::KIND_CORE_ACTION_PROPOSAL,
        channel_id,
        owner,
        payload,
    )
}

/// Build a kind-44311 exact signed action decision.
pub fn build_core_action_decision(
    channel_id: Uuid,
    broker: &PublicKey,
    payload: &ActionDecisionPayload,
) -> Result<EventBuilder, SdkError> {
    plaintext_builder(
        buzz_core::kind::KIND_CORE_ACTION_DECISION,
        channel_id,
        broker,
        payload,
    )
}

/// Build a kind-44312 external action receipt.
pub fn build_core_action_receipt(
    channel_id: Uuid,
    owner: &PublicKey,
    payload: &ActionReceiptPayload,
) -> Result<EventBuilder, SdkError> {
    plaintext_builder(
        buzz_core::kind::KIND_CORE_ACTION_RECEIPT,
        channel_id,
        owner,
        payload,
    )
}

/// Build a kind-44210 encrypted append-only learning record.
pub fn build_core_learning_record(
    channel_id: Uuid,
    recipient: &PublicKey,
    ciphertext: &str,
) -> Result<EventBuilder, SdkError> {
    encrypted_builder(
        buzz_core::kind::KIND_CORE_LEARNING_RECORD,
        channel_id,
        recipient,
        ciphertext,
        None,
    )
}

/// Build a kind-30179 encrypted learning bundle head.
pub fn build_core_learning_bundle_head(
    channel_id: Uuid,
    owner: &PublicKey,
    conversation_key: &ConversationKey,
    layer: LearningLayer,
    domain: LearningDomain,
    ciphertext: &str,
) -> Result<EventBuilder, SdkError> {
    let coordinate = learning_bundle_coordinate(conversation_key, layer, domain);
    encrypted_builder(
        buzz_core::kind::KIND_CORE_LEARNING_BUNDLE_HEAD,
        channel_id,
        owner,
        ciphertext,
        Some(&coordinate),
    )
}

/// Build a kind-24820 encrypted ephemeral call-control event.
pub fn build_core_call_control(
    channel_id: Uuid,
    recipient: &PublicKey,
    ciphertext: &str,
) -> Result<EventBuilder, SdkError> {
    encrypted_builder(
        buzz_core::kind::KIND_CORE_CALL_CONTROL,
        channel_id,
        recipient,
        ciphertext,
        None,
    )
}

/// Build a kind-24821 encrypted finalized transcript segment.
pub fn build_core_transcript_segment(
    channel_id: Uuid,
    assistant: &PublicKey,
    ciphertext: &str,
) -> Result<EventBuilder, SdkError> {
    encrypted_builder(
        buzz_core::kind::KIND_CORE_TRANSCRIPT_SEGMENT,
        channel_id,
        assistant,
        ciphertext,
        None,
    )
}

/// Build a kind-24822 encrypted copilot suggestion.
pub fn build_core_copilot_suggestion(
    channel_id: Uuid,
    owner: &PublicKey,
    ciphertext: &str,
) -> Result<EventBuilder, SdkError> {
    encrypted_builder(
        buzz_core::kind::KIND_CORE_COPILOT_SUGGESTION,
        channel_id,
        owner,
        ciphertext,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::Keys;

    #[test]
    fn plaintext_builder_accepts_exact_cap_and_rejects_cap_plus_one() {
        let recipient = Keys::generate().public_key();
        let channel_id =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("fixed UUID");
        // JSON string serialization adds exactly two quote bytes.
        let at_cap = "a".repeat(MAX_CORE_PLAINTEXT_CONTENT_LEN - 2);
        let over_cap = "a".repeat(MAX_CORE_PLAINTEXT_CONTENT_LEN - 1);

        assert!(plaintext_builder(
            buzz_core::kind::KIND_CORE_INSIGHT,
            channel_id,
            &recipient,
            &at_cap,
        )
        .is_ok());
        assert!(plaintext_builder(
            buzz_core::kind::KIND_CORE_INSIGHT,
            channel_id,
            &recipient,
            &over_cap,
        )
        .is_err());
    }
}
