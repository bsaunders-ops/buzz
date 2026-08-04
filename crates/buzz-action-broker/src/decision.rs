use buzz_core::core_protocol::{
    validate_core_envelope, validate_core_plaintext_content, ActionDecision, ActionDecisionPayload,
};
use nostr::Event;
use uuid::Uuid;

use crate::error::BrokerError;

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
            .field("proposal_id", &"<redacted>")
            .field("nonce", &"<redacted>")
            .field("operation_hash", &"<redacted>")
            .field("channel_id", &"<redacted>")
            .field("owner_pubkey", &"<redacted>")
            .field("broker_pubkey", &"<redacted>")
            .field("proposed_at", &self.proposed_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Cryptographically verified, proposal-bound owner decision.
#[derive(Clone, Copy)]
pub struct VerifiedActionDecision {
    decision_id: Uuid,
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
            .field("decision_id", &"<redacted>")
            .field("approved", &self.approved())
            .field("event_hash", &"<redacted>")
            .field("decided_at", &self.decided_at)
            .finish()
    }
}

/// Verify the Nostr signature/envelope and bind every executable decision field.
pub fn validate_signed_decision(
    event: &Event,
    expected: &DecisionExpectation,
    now: i64,
) -> Result<VerifiedActionDecision, BrokerError> {
    event
        .verify()
        .map_err(|_| BrokerError::Policy("decision event signature is invalid".into()))?;
    let envelope = validate_core_envelope(event)
        .map_err(|_| BrokerError::Policy("decision routing envelope is invalid".into()))?;
    validate_core_plaintext_content(event, now)
        .map_err(|_| BrokerError::Policy("decision payload is invalid".into()))?;
    let payload: ActionDecisionPayload = serde_json::from_str(&event.content)
        .map_err(|_| BrokerError::Policy("decision payload is invalid".into()))?;

    if event.pubkey.to_bytes() != expected.owner_pubkey
        || envelope.recipient.to_bytes() != expected.broker_pubkey
    {
        return Err(BrokerError::Policy(
            "decision signer/recipient does not match the registered pair".into(),
        ));
    }
    if envelope.channel_id != expected.channel_id {
        return Err(BrokerError::Policy(
            "decision channel does not match the proposal".into(),
        ));
    }
    if payload.proposal_id.as_uuid() != expected.proposal_id
        || payload.nonce.as_uuid() != expected.nonce
    {
        return Err(BrokerError::Policy(
            "decision proposal/nonce binding does not match".into(),
        ));
    }
    let operation_hash = decode_hash(payload.operation_hash.as_str())?;
    if operation_hash != expected.operation_hash {
        return Err(BrokerError::Policy(
            "decision operation hash does not match".into(),
        ));
    }
    let event_created_at = i64::try_from(event.created_at.as_secs())
        .map_err(|_| BrokerError::Policy("decision timestamp is out of range".into()))?;
    if payload.decided_at != event_created_at
        || payload.decided_at < expected.proposed_at
        || payload.decided_at >= expected.expires_at
        || now >= expected.expires_at
        || payload.decided_at > now.saturating_add(300)
    {
        return Err(BrokerError::Policy(
            "decision timestamp is stale, expired, or not event-bound".into(),
        ));
    }
    Ok(VerifiedActionDecision {
        decision_id: payload.decision_id.as_uuid(),
        decision: payload.decision,
        event_hash: event.id.to_bytes(),
        decided_at: payload.decided_at,
    })
}

fn decode_hash(value: &str) -> Result<[u8; 32], BrokerError> {
    let bytes = hex::decode(value)
        .map_err(|_| BrokerError::Policy("decision operation hash is invalid".into()))?;
    bytes
        .try_into()
        .map_err(|_| BrokerError::Policy("decision operation hash is invalid".into()))
}

/// Fail-closed durable action lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionLifecycleState {
    /// Awaiting an owner decision.
    Proposed,
    /// Exact action was approved and may be claimed once.
    Approved,
    /// Owner explicitly denied the action.
    Denied,
    /// Proposal expired before execution.
    Expired,
    /// Durable execution intent was claimed before remote I/O.
    Executing,
    /// Provider conclusively confirmed success.
    Succeeded,
    /// Provider conclusively rejected the write.
    Failed,
    /// Outcome after dispatch is ambiguous and must be reconciled.
    ReconciliationRequired,
}

/// The only legal lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionTransition {
    /// Signed owner approval.
    Approve,
    /// Signed owner denial.
    Deny,
    /// Wall-clock expiry.
    Expire,
    /// One-time execution claim.
    Claim,
    /// Definitive provider success.
    Succeed,
    /// Definitive provider rejection.
    Fail,
    /// Ambiguous post-dispatch outcome.
    RequireReconciliation,
}

impl ActionLifecycleState {
    /// Apply one typed transition without permitting terminal-state replay.
    pub fn transition(
        self,
        transition: ActionTransition,
        now: i64,
        expires_at: i64,
    ) -> Result<Self, BrokerError> {
        let next = match (self, transition) {
            (Self::Proposed, ActionTransition::Approve) if now < expires_at => Self::Approved,
            (Self::Proposed, ActionTransition::Deny) => Self::Denied,
            (Self::Proposed | Self::Approved, ActionTransition::Expire) => Self::Expired,
            (Self::Approved, ActionTransition::Claim) if now < expires_at => Self::Executing,
            (Self::Executing, ActionTransition::Succeed) => Self::Succeeded,
            (Self::Executing, ActionTransition::Fail) => Self::Failed,
            (Self::Executing, ActionTransition::RequireReconciliation) => {
                Self::ReconciliationRequired
            }
            _ => {
                return Err(BrokerError::Policy(
                    "illegal or expired external-action state transition".into(),
                ));
            }
        };
        Ok(next)
    }
}
