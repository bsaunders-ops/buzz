//! One bounded, provider-neutral connector iteration.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;

use buzz_connector_core::{
    apply::ApplyOutcome,
    types::{AccountId, AclPrincipal, ChangePage, ConnectorProvider, EncryptedCursor, ScopeId},
};
use uuid::Uuid;

/// Opaque failure returned by an injected trusted boundary.
///
/// This type intentionally carries no provider content, credentials, authority
/// identifiers, cursor material, or ACL values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectorBoundaryError;

impl ConnectorBoundaryError {
    /// Construct a redacted boundary failure.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for ConnectorBoundaryError {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ConnectorBoundaryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("connector iteration boundary failed")
    }
}

impl std::error::Error for ConnectorBoundaryError {}

/// Closed provider-page failure categories accepted by the worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderPageError {
    /// Provider authentication was rejected.
    AuthenticationRejected,
    /// Provider throttling deferred the read.
    RateLimited,
    /// The configured provider resource was not found.
    NotFound,
    /// The bounded provider response was invalid.
    InvalidResponse,
    /// The bounded provider request timed out.
    Timeout,
}

/// Closed safe failure codes recorded against a fenced lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorIterationFailureCode {
    /// Provider authentication was rejected.
    ProviderAuthenticationRejected,
    /// Provider throttling deferred the read.
    ProviderRateLimited,
    /// The configured provider resource was not found.
    ProviderNotFound,
    /// The bounded provider response was invalid.
    ProviderInvalidResponse,
    /// The bounded provider request timed out.
    ProviderTimeout,
    /// The page authority did not exactly match the trusted claim.
    PageAuthorityMismatch,
    /// An item ACL did not exactly match the configured positive principals.
    PageAclMismatch,
    /// The atomic page application boundary rejected the page.
    PageApplyRejected,
}

impl From<ProviderPageError> for ConnectorIterationFailureCode {
    fn from(value: ProviderPageError) -> Self {
        match value {
            ProviderPageError::AuthenticationRejected => Self::ProviderAuthenticationRejected,
            ProviderPageError::RateLimited => Self::ProviderRateLimited,
            ProviderPageError::NotFound => Self::ProviderNotFound,
            ProviderPageError::InvalidResponse => Self::ProviderInvalidResponse,
            ProviderPageError::Timeout => Self::ProviderTimeout,
        }
    }
}

/// One trusted due-scope claim resolved entirely by server configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct TrustedConnectorClaim {
    community_id: Uuid,
    account_id: AccountId,
    scope_id: ScopeId,
    provider: ConnectorProvider,
    stream: String,
    lease_generation: u64,
    current_cursor: EncryptedCursor,
    acl_principals: BTreeSet<AclPrincipal>,
}

impl std::fmt::Debug for TrustedConnectorClaim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrustedConnectorClaim")
            .field("provider", &self.provider)
            .field("authority_cursor_and_acl_values_redacted", &true)
            .finish()
    }
}

impl TrustedConnectorClaim {
    /// Validate one server-resolved claim with a positive ACL allowlist.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        community_id: Uuid,
        account_id: AccountId,
        scope_id: ScopeId,
        provider: ConnectorProvider,
        stream: impl Into<String>,
        lease_generation: u64,
        current_cursor: EncryptedCursor,
        acl_principals: BTreeSet<AclPrincipal>,
    ) -> Result<Self, ConnectorBoundaryError> {
        let stream = stream.into();
        let mut stream_bytes = stream.bytes();
        let valid_stream = stream.len() <= 128
            && stream_bytes
                .next()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && stream_bytes.all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
            });
        if !valid_stream || lease_generation == 0 || acl_principals.is_empty() {
            return Err(ConnectorBoundaryError::new());
        }
        Ok(Self {
            community_id,
            account_id,
            scope_id,
            provider,
            stream,
            lease_generation,
            current_cursor,
            acl_principals,
        })
    }

    /// Server-resolved community boundary.
    #[must_use]
    pub const fn community_id(&self) -> Uuid {
        self.community_id
    }

    /// Server-resolved connector account.
    #[must_use]
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Server-resolved approved scope.
    #[must_use]
    pub const fn scope_id(&self) -> ScopeId {
        self.scope_id
    }

    /// Closed configured provider.
    #[must_use]
    pub const fn provider(&self) -> ConnectorProvider {
        self.provider
    }

    /// Configured provider stream.
    #[must_use]
    pub fn stream(&self) -> &str {
        &self.stream
    }

    /// Current fenced lease generation.
    #[must_use]
    pub const fn lease_generation(&self) -> u64 {
        self.lease_generation
    }

    /// Current application-encrypted cursor.
    #[must_use]
    pub const fn current_cursor(&self) -> &EncryptedCursor {
        &self.current_cursor
    }

    /// Exact server-configured positive ACL principals.
    #[must_use]
    pub const fn acl_principals(&self) -> &BTreeSet<AclPrincipal> {
        &self.acl_principals
    }
}

/// Result of exactly one connector iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorIterationOutcome {
    /// No trusted scope was due.
    Idle,
    /// One page and its cursor were committed atomically.
    Applied {
        /// Count of changed item identities.
        changed_items: usize,
    },
    /// The exact page was already committed by an earlier attempt.
    AlreadyApplied,
    /// The claimed scope was fenced as failed and deferred.
    Deferred {
        /// Closed safe failure code recorded for the claim.
        code: ConnectorIterationFailureCode,
    },
    /// The claim lease changed before its failure could be recorded.
    LostLease {
        /// Closed safe failure code that was not recorded under the stale lease.
        code: ConnectorIterationFailureCode,
    },
}

/// Boxed result of one injected connector iteration.
pub type ConnectorIterationFuture<'a> = Pin<
    Box<dyn Future<Output = Result<ConnectorIterationOutcome, ConnectorBoundaryError>> + Send + 'a>,
>;

/// Object-safe provider registry entry used by the long-lived worker host.
pub trait ConnectorIterationRunner: Send {
    /// Run exactly one bounded claim/fetch/apply attempt.
    fn run_once(&mut self) -> ConnectorIterationFuture<'_>;
}

/// Claims at most one trusted due scope.
pub trait DueScopeClaimer {
    /// Return one trusted claim, or `None` when no scope is due.
    async fn claim_one(&mut self) -> Result<Option<TrustedConnectorClaim>, ConnectorBoundaryError>;
}

/// Fetches exactly one bounded provider page for a trusted claim.
pub trait PageProvider {
    /// Fetch one page without following provider pagination in this call.
    async fn fetch_one_page(
        &mut self,
        claim: &TrustedConnectorClaim,
    ) -> Result<ChangePage, ProviderPageError>;
}

/// Atomically applies a validated page and its next cursor.
pub trait PageApplier {
    /// Apply the page only while the exact claim lease remains current.
    async fn apply_page(
        &mut self,
        claim: &TrustedConnectorClaim,
        page: &ChangePage,
    ) -> Result<ApplyOutcome, ConnectorBoundaryError>;
}

/// Records one failure only while the exact claim lease remains current.
pub trait FencedFailureRecorder {
    /// Record a closed safe failure code and defer retry.
    async fn record_failure(
        &mut self,
        claim: &TrustedConnectorClaim,
        code: ConnectorIterationFailureCode,
    ) -> Result<bool, ConnectorBoundaryError>;
}

fn validate_page(
    claim: &TrustedConnectorClaim,
    page: &ChangePage,
) -> Result<(), ConnectorIterationFailureCode> {
    if page.tenant_id() != claim.community_id
        || page.account_id() != claim.account_id
        || page.scope_id() != claim.scope_id
        || page.provider() != claim.provider
        || page.stream() != claim.stream
        || page.previous_cursor_hash() != claim.current_cursor.integrity_hash()
        || page.next_cursor().generation() != claim.lease_generation
    {
        return Err(ConnectorIterationFailureCode::PageAuthorityMismatch);
    }
    for item in page.upserts() {
        let page_principals = item.acls().iter().cloned().collect::<BTreeSet<_>>();
        if page_principals != claim.acl_principals {
            return Err(ConnectorIterationFailureCode::PageAclMismatch);
        }
    }
    Ok(())
}

async fn record_deferred<F: FencedFailureRecorder>(
    recorder: &mut F,
    claim: &TrustedConnectorClaim,
    code: ConnectorIterationFailureCode,
) -> Result<ConnectorIterationOutcome, ConnectorBoundaryError> {
    if recorder.record_failure(claim, code).await? {
        Ok(ConnectorIterationOutcome::Deferred { code })
    } else {
        Ok(ConnectorIterationOutcome::LostLease { code })
    }
}

/// Claim, fetch, validate, and apply at most one provider page.
///
/// Provider, validation, and apply failures invoke the fenced failure boundary
/// exactly once. This unit performs no logging and contains no retry or polling
/// loop.
pub async fn run_connector_iteration<C, P, A, F>(
    claimer: &mut C,
    provider: &mut P,
    applier: &mut A,
    failure_recorder: &mut F,
) -> Result<ConnectorIterationOutcome, ConnectorBoundaryError>
where
    C: DueScopeClaimer,
    P: PageProvider,
    A: PageApplier,
    F: FencedFailureRecorder,
{
    let Some(claim) = claimer.claim_one().await? else {
        return Ok(ConnectorIterationOutcome::Idle);
    };
    let page = match provider.fetch_one_page(&claim).await {
        Ok(page) => page,
        Err(error) => {
            return record_deferred(failure_recorder, &claim, error.into()).await;
        }
    };
    if let Err(code) = validate_page(&claim, &page) {
        return record_deferred(failure_recorder, &claim, code).await;
    }
    match applier.apply_page(&claim, &page).await {
        Ok(ApplyOutcome::Applied { changed_items }) => {
            Ok(ConnectorIterationOutcome::Applied { changed_items })
        }
        Ok(ApplyOutcome::AlreadyApplied) => Ok(ConnectorIterationOutcome::AlreadyApplied),
        Err(_) => {
            record_deferred(
                failure_recorder,
                &claim,
                ConnectorIterationFailureCode::PageApplyRejected,
            )
            .await
        }
    }
}
