use std::{collections::HashSet, fmt};

use buzz_core::action_auth::{
    validate_signed_action_proposal, ProposalExpectation, VerifiedActionProposal,
};
use buzz_core::core_protocol::{ActionTarget, EvidenceRef, PositiveWriteOperation};
use nostr::Event;
use uuid::Uuid;

use crate::{
    canonical::{build_envelope, build_member, CanonicalProposal},
    error::BrokerError,
    policy::{validate_request, MAX_BUNDLE_MEMBERS},
};

/// One typed operation requested from the model-facing proposal surface.
#[derive(Clone, PartialEq, Eq)]
pub struct RequestedOperation {
    /// Stable UUIDv4 identifying the independently reconcilable operation.
    pub operation_id: Uuid,
    /// UUIDv4 provider idempotency key dedicated to this operation.
    pub idempotency_key: Uuid,
    /// Exact configured connector account, approved scope, and remote object.
    pub target: ActionTarget,
    /// One of the frozen 23 positive Month-1 write operations.
    pub operation: PositiveWriteOperation,
}

impl fmt::Debug for RequestedOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestedOperation")
            .field("operation_id", &"<redacted>")
            .field("idempotency_key", &"<redacted>")
            .field("target", &"<redacted connector target>")
            .field("operation", &"<redacted typed positive operation>")
            .finish()
    }
}

/// Fresh, connector-normalized state used to build an approval card.
#[derive(Clone, PartialEq, Eq)]
pub struct FreshReadState {
    /// Current remote state; absent only for create operations.
    pub before: Option<Vec<u8>>,
    /// Exact state expected after the typed operation.
    pub after: Vec<u8>,
    /// Current remote ETag/version; absent only for create operations.
    pub expected_remote_version: Option<String>,
}

impl fmt::Debug for FreshReadState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshReadState")
            .field("has_before", &self.before.is_some())
            .field("after", &"<redacted normalized state>")
            .field(
                "expected_remote_version",
                &self.expected_remote_version.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Narrow read-only adapter used while preparing an action proposal.
///
/// Concrete provider writers are intentionally not part of this trait.
#[allow(async_fn_in_trait)]
pub trait FreshReadAdapter: Send + Sync {
    /// Re-read the target and normalize exact before/after state.
    async fn fresh_read(&self, request: &RequestedOperation)
        -> Result<FreshReadState, BrokerError>;
}

/// Complete request for a private, owner-confirmed action proposal.
#[derive(Clone, PartialEq, Eq)]
pub struct ProposalRequest {
    /// Tenant owning every durable key.
    pub tenant_id: Uuid,
    /// Stable proposal UUIDv4.
    pub proposal_id: Uuid,
    /// Private owner/broker channel UUIDv4.
    pub channel_id: Uuid,
    /// Exact owner Nostr public key.
    pub owner_pubkey: [u8; 32],
    /// Exact registered broker Nostr public key.
    pub broker_pubkey: [u8; 32],
    /// One-time UUIDv4 decision nonce.
    pub nonce: Uuid,
    /// Signed proposal creation time in Unix seconds.
    pub proposed_at: i64,
    /// Expiry time, no more than 15 minutes after creation.
    pub expires_at: i64,
    /// Ordered, individually visible positive operations.
    pub operations: Vec<RequestedOperation>,
    /// Hashed evidence references supporting the proposal.
    pub evidence: Vec<EvidenceRef>,
}

impl fmt::Debug for ProposalRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProposalRequest")
            .field("tenant_id", &"<redacted>")
            .field("proposal_id", &"<redacted>")
            .field("channel_id", &"<redacted>")
            .field("owner_pubkey", &"<redacted>")
            .field("broker_pubkey", &"<redacted>")
            .field("nonce", &"<redacted>")
            .field("proposed_at", &self.proposed_at)
            .field("expires_at", &self.expires_at)
            .field("operation_count", &self.operations.len())
            .field("evidence_count", &self.evidence.len())
            .finish()
    }
}

/// Perform a fresh read for every member before producing canonical approval bytes.
pub async fn prepare_proposal<A: FreshReadAdapter>(
    request: &ProposalRequest,
    adapter: &A,
) -> Result<CanonicalProposal, BrokerError> {
    validate_request(request)?;
    let mut members = Vec::with_capacity(request.operations.len());
    for requested in &request.operations {
        let fresh = adapter.fresh_read(requested).await?;
        members.push(build_member(request, requested, fresh)?);
    }
    build_envelope(request, members)
}

/// Verify the exact signed kind `44310` event before durable proposal insertion.
pub fn validate_signed_proposal(
    event: &Event,
    proposal: &CanonicalProposal,
    now: i64,
) -> Result<VerifiedActionProposal, BrokerError> {
    let record = proposal.database_record();
    let owner_pubkey = record
        .owner_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| BrokerError::Policy("invalid owner public key".into()))?;
    let broker_pubkey = record
        .broker_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| BrokerError::Policy("invalid broker public key".into()))?;
    validate_signed_action_proposal(
        event,
        &ProposalExpectation {
            payload: proposal.protocol_payload().clone(),
            channel_id: record.channel_id,
            owner_pubkey,
            broker_pubkey,
        },
        now,
    )
    .map_err(|error| BrokerError::Policy(error.to_string()))
}

pub(crate) fn validate_request_uniqueness(request: &ProposalRequest) -> Result<(), BrokerError> {
    if request.operations.is_empty() || request.operations.len() > MAX_BUNDLE_MEMBERS {
        return Err(BrokerError::Policy(
            "bundle must contain 1..=10 operations".into(),
        ));
    }
    let mut operation_ids = HashSet::with_capacity(request.operations.len());
    let mut idempotency_keys = HashSet::with_capacity(request.operations.len());
    for operation in &request.operations {
        if !operation_ids.insert(operation.operation_id)
            || !idempotency_keys.insert(operation.idempotency_key)
        {
            return Err(BrokerError::Policy(
                "operation IDs and idempotency keys must be unique".into(),
            ));
        }
    }
    Ok(())
}
