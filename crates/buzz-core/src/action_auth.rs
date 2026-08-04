//! Opaque, cryptographically verified capabilities for durable Core actions.

use nostr::Event;
use uuid::Uuid;

use crate::core_protocol::{
    validate_core_envelope, validate_core_plaintext_content, ActionDecision, ActionDecisionPayload,
    ActionProposalPayload, ActionReceiptPayload, ProtocolValidationError,
};
use crate::kind::{
    event_kind_u32, KIND_CORE_ACTION_DECISION, KIND_CORE_ACTION_PROPOSAL, KIND_CORE_ACTION_RECEIPT,
};

/// Exact prepared proposal and private routing expected in a signed event.
#[derive(Clone)]
pub struct ProposalExpectation {
    /// Frozen protocol payload derived from canonical operation bytes.
    pub payload: ActionProposalPayload,
    /// Private approval channel.
    pub channel_id: Uuid,
    /// Owner receiving the proposal.
    pub owner_pubkey: [u8; 32],
    /// Broker signing the proposal.
    pub broker_pubkey: [u8; 32],
}

/// Signed proposal capability required before durable insertion.
#[derive(Clone, Copy)]
pub struct VerifiedActionProposal {
    proposal_id: Uuid,
    nonce: Uuid,
    operation_hash: [u8; 32],
    channel_id: Uuid,
    owner_pubkey: [u8; 32],
    broker_pubkey: [u8; 32],
    event_hash: [u8; 32],
    proposed_at: i64,
    expires_at: i64,
}

impl VerifiedActionProposal {
    /// Stable proposal identifier.
    #[must_use]
    pub const fn proposal_id(&self) -> Uuid {
        self.proposal_id
    }

    /// One-time proposal nonce.
    #[must_use]
    pub const fn nonce(&self) -> Uuid {
        self.nonce
    }

    /// Exact canonical operation hash.
    #[must_use]
    pub const fn operation_hash(&self) -> [u8; 32] {
        self.operation_hash
    }

    /// Private approval channel.
    #[must_use]
    pub const fn channel_id(&self) -> Uuid {
        self.channel_id
    }

    /// Owner recipient public key.
    #[must_use]
    pub const fn owner_pubkey(&self) -> [u8; 32] {
        self.owner_pubkey
    }

    /// Broker signer public key.
    #[must_use]
    pub const fn broker_pubkey(&self) -> [u8; 32] {
        self.broker_pubkey
    }

    /// Hash of the exact signed proposal event.
    #[must_use]
    pub const fn event_hash(&self) -> [u8; 32] {
        self.event_hash
    }

    /// Signed proposal timestamp.
    #[must_use]
    pub const fn proposed_at(&self) -> i64 {
        self.proposed_at
    }

    /// Hard proposal expiry.
    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

impl std::fmt::Debug for VerifiedActionProposal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedActionProposal")
            .field("bindings", &"<redacted>")
            .field("proposed_at", &self.proposed_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Verify the exact broker-authored proposal event prepared for Desktop review.
pub fn validate_signed_action_proposal(
    event: &Event,
    expected: &ProposalExpectation,
    now: i64,
) -> Result<VerifiedActionProposal, ProtocolValidationError> {
    require_kind(event, KIND_CORE_ACTION_PROPOSAL, "proposal")?;
    event
        .verify()
        .map_err(|_| ProtocolValidationError("proposal event signature is invalid".into()))?;
    let envelope = validate_core_envelope(event)?;
    validate_core_plaintext_content(event, now)?;
    let payload: ActionProposalPayload = serde_json::from_str(&event.content)
        .map_err(|_| ProtocolValidationError("proposal payload is invalid".into()))?;
    if payload != expected.payload {
        return Err(ProtocolValidationError(
            "proposal payload does not match the prepared canonical operation".into(),
        ));
    }
    if event.pubkey.to_bytes() != expected.broker_pubkey
        || envelope.recipient.to_bytes() != expected.owner_pubkey
        || envelope.channel_id != expected.channel_id
    {
        return Err(ProtocolValidationError(
            "proposal signer/recipient/channel does not match the registered pair".into(),
        ));
    }
    let event_created_at = event_time(event, "proposal")?;
    if event_created_at != payload.proposed_at {
        return Err(ProtocolValidationError(
            "proposal timestamp is not event-bound".into(),
        ));
    }
    let operation_hash = decode_labeled_hash(payload.operation_hash.as_str(), "proposal")?;
    Ok(VerifiedActionProposal {
        proposal_id: payload.proposal_id.as_uuid(),
        nonce: payload.nonce.as_uuid(),
        operation_hash,
        channel_id: expected.channel_id,
        owner_pubkey: expected.owner_pubkey,
        broker_pubkey: expected.broker_pubkey,
        event_hash: event.id.to_bytes(),
        proposed_at: payload.proposed_at,
        expires_at: payload.expires_at,
    })
}

/// Exact durable receipt and private routing expected in a signed event.
#[derive(Clone)]
pub struct ReceiptExpectation {
    /// Receipt payload reconstructed from durable rows.
    pub payload: ActionReceiptPayload,
    /// Private approval channel.
    pub channel_id: Uuid,
    /// Owner receiving the receipt.
    pub owner_pubkey: [u8; 32],
    /// Broker signing the receipt.
    pub broker_pubkey: [u8; 32],
}

/// Signed receipt capability required to complete durable publication.
#[derive(Clone, Copy)]
pub struct VerifiedActionReceipt {
    receipt_id: Uuid,
    proposal_id: Uuid,
    decision_id: Uuid,
    operation_hash: [u8; 32],
    channel_id: Uuid,
    owner_pubkey: [u8; 32],
    broker_pubkey: [u8; 32],
    event_hash: [u8; 32],
    occurred_at: i64,
}

impl VerifiedActionReceipt {
    /// Stable receipt identifier.
    #[must_use]
    pub const fn receipt_id(&self) -> Uuid {
        self.receipt_id
    }

    /// Proposal whose outcome is reported.
    #[must_use]
    pub const fn proposal_id(&self) -> Uuid {
        self.proposal_id
    }

    /// Signed decision controlling execution.
    #[must_use]
    pub const fn decision_id(&self) -> Uuid {
        self.decision_id
    }

    /// Exact canonical operation hash.
    #[must_use]
    pub const fn operation_hash(&self) -> [u8; 32] {
        self.operation_hash
    }

    /// Private channel carrying the receipt.
    #[must_use]
    pub const fn channel_id(&self) -> Uuid {
        self.channel_id
    }

    /// Owner recipient public key.
    #[must_use]
    pub const fn owner_pubkey(&self) -> [u8; 32] {
        self.owner_pubkey
    }

    /// Broker signer public key.
    #[must_use]
    pub const fn broker_pubkey(&self) -> [u8; 32] {
        self.broker_pubkey
    }

    /// Hash of the exact signed receipt event.
    #[must_use]
    pub const fn event_hash(&self) -> [u8; 32] {
        self.event_hash
    }

    /// Durable outcome timestamp.
    #[must_use]
    pub const fn occurred_at(&self) -> i64 {
        self.occurred_at
    }
}

impl std::fmt::Debug for VerifiedActionReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedActionReceipt")
            .field("bindings", &"<redacted>")
            .field("occurred_at", &self.occurred_at)
            .finish()
    }
}

/// Verify an exact broker-authored receipt reconstructed from durable rows.
pub fn validate_signed_action_receipt(
    event: &Event,
    expected: &ReceiptExpectation,
    now: i64,
) -> Result<VerifiedActionReceipt, ProtocolValidationError> {
    require_kind(event, KIND_CORE_ACTION_RECEIPT, "receipt")?;
    event
        .verify()
        .map_err(|_| ProtocolValidationError("receipt event signature is invalid".into()))?;
    let envelope = validate_core_envelope(event)?;
    validate_core_plaintext_content(event, now)?;
    let payload: ActionReceiptPayload = serde_json::from_str(&event.content)
        .map_err(|_| ProtocolValidationError("receipt payload is invalid".into()))?;
    if payload != expected.payload {
        return Err(ProtocolValidationError(
            "receipt payload does not match the durable outcome".into(),
        ));
    }
    if event.pubkey.to_bytes() != expected.broker_pubkey
        || envelope.recipient.to_bytes() != expected.owner_pubkey
        || envelope.channel_id != expected.channel_id
    {
        return Err(ProtocolValidationError(
            "receipt signer/recipient/channel does not match the registered pair".into(),
        ));
    }
    let event_created_at = event_time(event, "receipt")?;
    if event_created_at != payload.occurred_at {
        return Err(ProtocolValidationError(
            "receipt timestamp is not event-bound".into(),
        ));
    }
    let operation_hash = decode_labeled_hash(payload.operation_hash.as_str(), "receipt")?;
    Ok(VerifiedActionReceipt {
        receipt_id: payload.receipt_id.as_uuid(),
        proposal_id: payload.proposal_id.as_uuid(),
        decision_id: payload.decision_id.as_uuid(),
        operation_hash,
        channel_id: expected.channel_id,
        owner_pubkey: expected.owner_pubkey,
        broker_pubkey: expected.broker_pubkey,
        event_hash: event.id.to_bytes(),
        occurred_at: payload.occurred_at,
    })
}

/// Immutable proposal fields that a signed Desktop decision must match.
#[derive(Clone, Copy)]
pub struct DecisionExpectation {
    /// Proposal UUIDv4.
    pub proposal_id: Uuid,
    /// One-time proposal nonce.
    pub nonce: Uuid,
    /// Domain-separated canonical proposal hash.
    pub operation_hash: [u8; 32],
    /// Private channel carrying the decision.
    pub channel_id: Uuid,
    /// Only authorized Desktop signer.
    pub owner_pubkey: [u8; 32],
    /// Exact registered broker recipient.
    pub broker_pubkey: [u8; 32],
    /// Signed proposal creation time.
    pub proposed_at: i64,
    /// Hard proposal expiry.
    pub expires_at: i64,
}

impl std::fmt::Debug for DecisionExpectation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DecisionExpectation")
            .field("bindings", &"<redacted>")
            .field("proposed_at", &self.proposed_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Proposal-bound owner decision that can only be created by signature validation.
#[derive(Clone, Copy)]
pub struct VerifiedActionDecision {
    decision_id: Uuid,
    proposal_id: Uuid,
    nonce: Uuid,
    operation_hash: [u8; 32],
    channel_id: Uuid,
    owner_pubkey: [u8; 32],
    broker_pubkey: [u8; 32],
    decision: ActionDecision,
    event_hash: [u8; 32],
    decided_at: i64,
}

impl VerifiedActionDecision {
    /// Stable decision UUIDv4.
    #[must_use]
    pub const fn decision_id(&self) -> Uuid {
        self.decision_id
    }

    /// Proposal receiving the decision.
    #[must_use]
    pub const fn proposal_id(&self) -> Uuid {
        self.proposal_id
    }

    /// One-time proposal nonce bound by the signature.
    #[must_use]
    pub const fn nonce(&self) -> Uuid {
        self.nonce
    }

    /// Exact canonical operation hash bound by the signature.
    #[must_use]
    pub const fn operation_hash(&self) -> [u8; 32] {
        self.operation_hash
    }

    /// Private channel carrying the signed decision.
    #[must_use]
    pub const fn channel_id(&self) -> Uuid {
        self.channel_id
    }

    /// Verified owner signer public key.
    #[must_use]
    pub const fn owner_pubkey(&self) -> [u8; 32] {
        self.owner_pubkey
    }

    /// Verified broker recipient public key.
    #[must_use]
    pub const fn broker_pubkey(&self) -> [u8; 32] {
        self.broker_pubkey
    }

    /// Whether the owner approved rather than denied the exact proposal.
    #[must_use]
    pub const fn approved(&self) -> bool {
        matches!(self.decision, ActionDecision::Approve)
    }

    /// Hash of the exact signed Nostr decision event.
    #[must_use]
    pub const fn event_hash(&self) -> [u8; 32] {
        self.event_hash
    }

    /// Signed decision time in Unix seconds.
    #[must_use]
    pub const fn decided_at(&self) -> i64 {
        self.decided_at
    }
}

impl std::fmt::Debug for VerifiedActionDecision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedActionDecision")
            .field("bindings", &"<redacted>")
            .field("approved", &self.approved())
            .field("decided_at", &self.decided_at)
            .finish()
    }
}

/// Verify a Nostr signature/envelope and bind every executable decision field.
pub fn validate_signed_action_decision(
    event: &Event,
    expected: &DecisionExpectation,
    now: i64,
) -> Result<VerifiedActionDecision, ProtocolValidationError> {
    require_kind(event, KIND_CORE_ACTION_DECISION, "decision")?;
    event
        .verify()
        .map_err(|_| ProtocolValidationError("decision event signature is invalid".into()))?;
    let envelope = validate_core_envelope(event)?;
    validate_core_plaintext_content(event, now)?;
    let payload: ActionDecisionPayload = serde_json::from_str(&event.content)
        .map_err(|_| ProtocolValidationError("decision payload is invalid".into()))?;

    if event.pubkey.to_bytes() != expected.owner_pubkey
        || envelope.recipient.to_bytes() != expected.broker_pubkey
        || payload.signer.as_str() != hex::encode(expected.owner_pubkey)
    {
        return Err(ProtocolValidationError(
            "decision signer/recipient does not match the registered pair".into(),
        ));
    }
    if envelope.channel_id != expected.channel_id {
        return Err(ProtocolValidationError(
            "decision channel does not match the proposal".into(),
        ));
    }
    if payload.proposal_id.as_uuid() != expected.proposal_id
        || payload.nonce.as_uuid() != expected.nonce
    {
        return Err(ProtocolValidationError(
            "decision proposal/nonce binding does not match".into(),
        ));
    }
    let operation_hash = decode_hash(payload.operation_hash.as_str())?;
    if operation_hash != expected.operation_hash {
        return Err(ProtocolValidationError(
            "decision operation hash does not match".into(),
        ));
    }
    let event_created_at = i64::try_from(event.created_at.as_secs())
        .map_err(|_| ProtocolValidationError("decision timestamp is out of range".into()))?;
    if payload.decided_at != event_created_at
        || payload.decided_at < expected.proposed_at
        || payload.decided_at >= expected.expires_at
        || now >= expected.expires_at
        || payload.decided_at > now.saturating_add(300)
    {
        return Err(ProtocolValidationError(
            "decision timestamp is stale, expired, or not event-bound".into(),
        ));
    }
    Ok(VerifiedActionDecision {
        decision_id: payload.decision_id.as_uuid(),
        proposal_id: expected.proposal_id,
        nonce: expected.nonce,
        operation_hash,
        channel_id: expected.channel_id,
        owner_pubkey: expected.owner_pubkey,
        broker_pubkey: expected.broker_pubkey,
        decision: payload.decision,
        event_hash: event.id.to_bytes(),
        decided_at: payload.decided_at,
    })
}

fn require_kind(event: &Event, expected: u32, label: &str) -> Result<(), ProtocolValidationError> {
    if event_kind_u32(event) != expected {
        return Err(ProtocolValidationError(format!(
            "{label} event kind is invalid"
        )));
    }
    Ok(())
}

fn decode_hash(value: &str) -> Result<[u8; 32], ProtocolValidationError> {
    decode_labeled_hash(value, "decision")
}

fn decode_labeled_hash(value: &str, label: &str) -> Result<[u8; 32], ProtocolValidationError> {
    let bytes = hex::decode(value)
        .map_err(|_| ProtocolValidationError(format!("{label} operation hash is invalid")))?;
    bytes
        .try_into()
        .map_err(|_| ProtocolValidationError(format!("{label} operation hash is invalid")))
}

fn event_time(event: &Event, label: &str) -> Result<i64, ProtocolValidationError> {
    i64::try_from(event.created_at.as_secs())
        .map_err(|_| ProtocolValidationError(format!("{label} timestamp is out of range")))
}
