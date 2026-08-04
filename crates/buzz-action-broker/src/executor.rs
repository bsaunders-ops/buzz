use std::fmt;

use buzz_core::CommunityId;
use buzz_db::core_storage::{
    begin_action_remote_attempt, claim_action_execution, record_action_member_outcome,
    ActionExecutionClaim, ActionExecutionItem, ActionMemberOutcome, ActionRemoteAttempt,
    NewActionMemberOutcome,
};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::CanonicalProposal;

/// Content-free failure categories for executor control flow and logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExecutionError {
    /// A durable claim could not be loaded safely.
    #[error("durable external-action claim failed")]
    ClaimRejected,
    /// Durable and canonical values did not match exactly.
    #[error("external-action binding validation failed")]
    BindingRejected,
    /// A required durable state transition failed.
    #[error("external-action durable state transition failed")]
    DurableStore,
    /// A member had already consumed its sole remote-attempt capability.
    #[error("external-action remote attempt is unavailable")]
    AttemptUnavailable,
}

/// Explicit tenant-scoped request to claim one approved proposal.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExecuteActionRequest {
    /// Server-resolved tenant.
    pub community_id: CommunityId,
    /// Durable proposal to claim.
    pub proposal_id: Uuid,
    /// UUIDv4 execution worker identity.
    pub worker_id: Uuid,
    /// Explicit trusted clock value used for expiry checks.
    pub now: DateTime<Utc>,
}

impl fmt::Debug for ExecuteActionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecuteActionRequest")
            .field("identifiers", &"<redacted>")
            .field("now", &self.now)
            .finish()
    }
}

/// Aggregate result of one bundle execution pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecuteActionResult {
    /// No approved one-time claim was available.
    NotClaimed,
    /// Every member reached a durable definitive or reconciliation outcome.
    Completed {
        /// Provider-confirmed successes.
        succeeded: usize,
        /// Pre-dispatch or provider-confirmed failures.
        failed: usize,
        /// Ambiguous post-dispatch outcomes requiring a typed re-read.
        reconciliation_required: usize,
    },
}

/// Fresh provider state returned by a read-only adapter before dispatch.
#[derive(Clone, PartialEq, Eq)]
pub struct RemotePrecondition {
    /// Whether the exact target already exists.
    pub resource_exists: bool,
    /// Hash of normalized current state, if a resource exists.
    pub state_hash: Option<[u8; 32]>,
    /// Exact current provider ETag/version, if a resource exists.
    pub version: Option<String>,
}

impl fmt::Debug for RemotePrecondition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemotePrecondition")
            .field("resource_exists", &self.resource_exists)
            .field("state_hash", &self.state_hash.map(|_| "<redacted>"))
            .field("version", &self.version.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Closed read failure that cannot carry provider bodies or identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterReadFailure {
    /// Provider state could not be read safely.
    Unavailable,
    /// Current credentials or approved scope no longer authorize the read.
    Unauthorized,
}

/// Known failure detected before a provider write attempt exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreDispatchFailure {
    /// Current normalized state or version differs from the approval card.
    StaleRemoteState,
    /// A create target already exists and must be proposed again.
    TargetAlreadyExists,
    /// The mandatory fresh read could not be completed.
    AdapterUnavailable,
    /// The mandatory fresh read is no longer authorized.
    AuthorizationRevoked,
}

/// Closed provider rejection categories with no raw response data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderFailureCode {
    /// Provider rejected the optimistic-concurrency precondition.
    PreconditionRejected,
    /// Provider rejected the write for lack of authorization.
    PermissionDenied,
    /// Provider rejected typed input conclusively.
    ValidationRejected,
}

/// Result of the sole provider dispatch for one member.
#[derive(Clone, PartialEq, Eq)]
pub enum AdapterDispatchOutcome {
    /// Provider conclusively committed the change.
    Succeeded {
        /// Opaque provider-scoped result identifier for the receipt only.
        external_result_id: String,
        /// Exact returned version for the receipt only.
        external_result_version: String,
        /// Optional hash of the provider resource identifier.
        external_resource_id_hash: Option<[u8; 32]>,
    },
    /// Provider conclusively rejected the change.
    DefinitiveFailure {
        /// Closed, content-free rejection category.
        code: ProviderFailureCode,
    },
    /// Dispatch occurred but timeout/disconnect left the remote result unknown.
    AmbiguousTimeout,
}

impl fmt::Debug for AdapterDispatchOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Succeeded { .. } => formatter
                .debug_struct("Succeeded")
                .field("external_result", &"<redacted>")
                .finish(),
            Self::DefinitiveFailure { code } => formatter
                .debug_struct("DefinitiveFailure")
                .field("code", code)
                .finish(),
            Self::AmbiguousTimeout => formatter.write_str("AmbiguousTimeout"),
        }
    }
}

/// Narrow durable state boundary used by the connector-independent executor.
#[allow(async_fn_in_trait)]
pub trait DurableExecutionStore: Send + Sync {
    /// Atomically claim the approved proposal and record execution intent.
    async fn claim(
        &self,
        request: &ExecuteActionRequest,
    ) -> Result<Option<ActionExecutionClaim>, ExecutionError>;

    /// Record the sole actual remote attempt after fresh-read validation.
    async fn begin_remote_attempt(
        &self,
        request: &ExecuteActionRequest,
        claim: &ActionExecutionClaim,
        item: &ActionExecutionItem,
    ) -> Result<Option<ActionRemoteAttempt>, ExecutionError>;

    /// Durably close a member that failed before any provider dispatch.
    async fn record_pre_dispatch_failure(
        &self,
        request: &ExecuteActionRequest,
        claim: &ActionExecutionClaim,
        item: &ActionExecutionItem,
        failure: PreDispatchFailure,
    ) -> Result<(), ExecutionError>;

    /// Durably record the exact provider outcome and receipt-outbox state.
    async fn record_dispatch_outcome(
        &self,
        request: &ExecuteActionRequest,
        claim: &ActionExecutionClaim,
        item: &ActionExecutionItem,
        attempt: &ActionRemoteAttempt,
        outcome: &AdapterDispatchOutcome,
    ) -> Result<(), ExecutionError>;
}

/// Typed provider adapter with no URL, method, token, or generic-body surface.
#[allow(async_fn_in_trait)]
pub trait TypedWriteAdapter: Send + Sync {
    /// Re-read the exact normalized target and current optimistic version.
    async fn read_current(
        &self,
        item: &ActionExecutionItem,
    ) -> Result<RemotePrecondition, AdapterReadFailure>;

    /// Execute exactly the typed, already-canonicalized member once.
    async fn dispatch(
        &self,
        item: &ActionExecutionItem,
        attempt: &ActionRemoteAttempt,
    ) -> AdapterDispatchOutcome;
}

/// PostgreSQL-backed durable boundary; it owns no provider credential or adapter.
#[derive(Clone)]
pub struct PgExecutionStore {
    pool: PgPool,
}

impl PgExecutionStore {
    /// Wrap the application pool used by the sole external-action executor.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl fmt::Debug for PgExecutionStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PgExecutionStore")
            .field("pool", &"<redacted>")
            .finish()
    }
}

impl DurableExecutionStore for PgExecutionStore {
    async fn claim(
        &self,
        request: &ExecuteActionRequest,
    ) -> Result<Option<ActionExecutionClaim>, ExecutionError> {
        claim_action_execution(
            &self.pool,
            request.community_id,
            request.proposal_id,
            request.worker_id,
            request.now,
        )
        .await
        .map_err(|_| ExecutionError::ClaimRejected)
    }

    async fn begin_remote_attempt(
        &self,
        _request: &ExecuteActionRequest,
        claim: &ActionExecutionClaim,
        item: &ActionExecutionItem,
    ) -> Result<Option<ActionRemoteAttempt>, ExecutionError> {
        begin_action_remote_attempt(
            &self.pool,
            claim.community_id,
            claim.proposal_id,
            claim.claim_id,
            item.item_index,
            Utc::now(),
        )
        .await
        .map_err(|_| ExecutionError::DurableStore)
    }

    async fn record_pre_dispatch_failure(
        &self,
        _request: &ExecuteActionRequest,
        claim: &ActionExecutionClaim,
        item: &ActionExecutionItem,
        _failure: PreDispatchFailure,
    ) -> Result<(), ExecutionError> {
        persist_member_outcome(
            &self.pool,
            claim,
            item,
            None,
            ActionMemberOutcome::Failed,
            None,
            None,
            None,
        )
        .await
    }

    async fn record_dispatch_outcome(
        &self,
        _request: &ExecuteActionRequest,
        claim: &ActionExecutionClaim,
        item: &ActionExecutionItem,
        attempt: &ActionRemoteAttempt,
        outcome: &AdapterDispatchOutcome,
    ) -> Result<(), ExecutionError> {
        match outcome {
            AdapterDispatchOutcome::Succeeded {
                external_result_id,
                external_result_version,
                external_resource_id_hash,
            } => {
                persist_member_outcome(
                    &self.pool,
                    claim,
                    item,
                    Some(attempt.attempt_id),
                    ActionMemberOutcome::Succeeded,
                    Some(external_result_id.clone()),
                    Some(external_result_version.clone()),
                    external_resource_id_hash.map(|hash| hash.to_vec()),
                )
                .await
            }
            AdapterDispatchOutcome::DefinitiveFailure { .. } => {
                persist_member_outcome(
                    &self.pool,
                    claim,
                    item,
                    Some(attempt.attempt_id),
                    ActionMemberOutcome::Failed,
                    None,
                    None,
                    None,
                )
                .await
            }
            AdapterDispatchOutcome::AmbiguousTimeout => {
                persist_member_outcome(
                    &self.pool,
                    claim,
                    item,
                    Some(attempt.attempt_id),
                    ActionMemberOutcome::ReconciliationRequired,
                    None,
                    None,
                    None,
                )
                .await
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn persist_member_outcome(
    pool: &PgPool,
    claim: &ActionExecutionClaim,
    item: &ActionExecutionItem,
    attempt_id: Option<Uuid>,
    outcome: ActionMemberOutcome,
    remote_result_id: Option<String>,
    remote_version: Option<String>,
    remote_resource_id_hash: Option<Vec<u8>>,
) -> Result<(), ExecutionError> {
    let recorded = record_action_member_outcome(
        pool,
        claim.community_id,
        &NewActionMemberOutcome {
            proposal_id: claim.proposal_id,
            claim_id: claim.claim_id,
            item_index: item.item_index,
            attempt_id,
            operation_id: item.operation_id,
            member_hash: item.member_hash.clone(),
            remote_result_id,
            remote_version,
            remote_resource_id_hash,
            outcome,
            occurred_at: Utc::now(),
        },
    )
    .await
    .map_err(|_| ExecutionError::DurableStore)?;
    if recorded {
        Ok(())
    } else {
        Err(ExecutionError::DurableStore)
    }
}

/// Claim and execute one typed bundle sequentially without blind retries.
pub async fn execute_once<S, A>(
    store: &S,
    adapter: &A,
    request: &ExecuteActionRequest,
) -> Result<ExecuteActionResult, ExecutionError>
where
    S: DurableExecutionStore,
    A: TypedWriteAdapter,
{
    let Some(claim) = store.claim(request).await? else {
        return Ok(ExecuteActionResult::NotClaimed);
    };
    validate_claim_binding(request, &claim)?;

    let mut succeeded = 0;
    let mut failed = 0;
    let mut reconciliation_required = 0;
    for item in &claim.items {
        let remote = match adapter.read_current(item).await {
            Ok(remote) => remote,
            Err(AdapterReadFailure::Unavailable) => {
                store
                    .record_pre_dispatch_failure(
                        request,
                        &claim,
                        item,
                        PreDispatchFailure::AdapterUnavailable,
                    )
                    .await?;
                failed += 1;
                continue;
            }
            Err(AdapterReadFailure::Unauthorized) => {
                store
                    .record_pre_dispatch_failure(
                        request,
                        &claim,
                        item,
                        PreDispatchFailure::AuthorizationRevoked,
                    )
                    .await?;
                failed += 1;
                continue;
            }
        };
        if let Some(precondition_failure) = validate_remote_precondition(item, &remote)? {
            store
                .record_pre_dispatch_failure(request, &claim, item, precondition_failure)
                .await?;
            failed += 1;
            continue;
        }
        let attempt = store
            .begin_remote_attempt(request, &claim, item)
            .await?
            .ok_or(ExecutionError::AttemptUnavailable)?;
        let outcome = adapter.dispatch(item, &attempt).await;
        store
            .record_dispatch_outcome(request, &claim, item, &attempt, &outcome)
            .await?;
        match outcome {
            AdapterDispatchOutcome::Succeeded { .. } => succeeded += 1,
            AdapterDispatchOutcome::DefinitiveFailure { .. } => failed += 1,
            AdapterDispatchOutcome::AmbiguousTimeout => reconciliation_required += 1,
        }
    }
    Ok(ExecuteActionResult::Completed {
        succeeded,
        failed,
        reconciliation_required,
    })
}

fn validate_claim_binding(
    request: &ExecuteActionRequest,
    claim: &ActionExecutionClaim,
) -> Result<(), ExecutionError> {
    if request.worker_id.get_version_num() != 4
        || request.proposal_id != claim.proposal_id
        || request.community_id != claim.community_id
        || request.now >= claim.expires_at
        || claim.claim_id.get_version_num() != 4
        || claim.decision_id.get_version_num() != 4
        || claim.signer_pubkey != claim.owner_pubkey
        || claim.decision_event_hash.len() != 32
    {
        return Err(ExecutionError::BindingRejected);
    }
    let canonical =
        CanonicalProposal::parse_exact(&claim.canonical_proposal, &claim.operation_hash)
            .map_err(|_| ExecutionError::BindingRejected)?;
    let record = canonical.database_record();
    let exact_header = canonical.tenant_id() == *claim.community_id.as_uuid()
        && record.id == claim.proposal_id
        && record.owner_pubkey == claim.owner_pubkey
        && record.broker_pubkey == claim.broker_pubkey
        && record.channel_id == claim.channel_id
        && record.canonical_proposal == claim.canonical_proposal
        && record.operation_hash == claim.operation_hash
        && record.ordered_members_hash == claim.ordered_members_hash
        && record.nonce == claim.nonce
        && record.proposed_at == claim.proposed_at
        && record.expires_at == claim.expires_at
        && usize::try_from(claim.member_count).ok() == Some(claim.items.len())
        && record.items.len() == claim.items.len();
    if !exact_header {
        return Err(ExecutionError::BindingRejected);
    }
    for (index, (expected, actual)) in record.items.iter().zip(&claim.items).enumerate() {
        let exact_member = usize::try_from(actual.item_index).ok() == Some(index)
            && expected.operation_id == actual.operation_id
            && expected.account_id == actual.account_id
            && expected.scope_id == actual.scope_id
            && expected.connector == actual.connector
            && expected.operation == actual.operation
            && expected.target_hash == actual.target_hash
            && expected.canonical_operation == actual.canonical_operation
            && expected.canonical_operation_hash == actual.canonical_operation_hash
            && expected.before_hash == actual.before_hash
            && expected.after_hash == actual.after_hash
            && expected.expected_remote_version == actual.expected_remote_version
            && expected.idempotency_key == actual.idempotency_key
            && expected.member_hash == actual.member_hash;
        if !exact_member {
            return Err(ExecutionError::BindingRejected);
        }
    }
    Ok(())
}

fn validate_remote_precondition(
    item: &ActionExecutionItem,
    remote: &RemotePrecondition,
) -> Result<Option<PreDispatchFailure>, ExecutionError> {
    match (&item.before_hash, &item.expected_remote_version) {
        (None, None) => Ok(remote
            .resource_exists
            .then_some(PreDispatchFailure::TargetAlreadyExists)),
        (Some(expected_hash), Some(expected_version)) => {
            if !remote.resource_exists
                || remote.state_hash.as_ref().map(<[u8; 32]>::as_slice)
                    != Some(expected_hash.as_slice())
                || remote.version.as_deref() != Some(expected_version.as_str())
            {
                Ok(Some(PreDispatchFailure::StaleRemoteState))
            } else {
                Ok(None)
            }
        }
        _ => Err(ExecutionError::BindingRejected),
    }
}
