//! Explicit provider egress allowlists and redacted error contracts.

use std::{net::IpAddr, str::FromStr, time::Duration};

use sha2::{Digest, Sha256};
use url::Url;

use crate::{types::ConnectorProvider, ConnectorError, Result};

const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_REQUEST_TIME: Duration = Duration::from_secs(60);

/// Bounded outbound request metadata. No token or body is retained here.
#[derive(Clone, PartialEq, Eq)]
pub struct EgressRequest {
    url: String,
    max_response_bytes: u64,
    timeout: Duration,
}

impl std::fmt::Debug for EgressRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EgressRequest")
            .field("url_redacted", &true)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl EgressRequest {
    /// Construct request metadata for policy validation.
    #[must_use]
    pub fn new(url: impl Into<String>, max_response_bytes: u64, timeout: Duration) -> Self {
        Self {
            url: url.into(),
            max_response_bytes,
            timeout,
        }
    }
}

/// Redirect behavior is fail-closed by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectMode {
    /// HTTP clients must not automatically follow redirects.
    Disabled,
}

/// Approved endpoint family for one connector worker.
#[derive(Debug, Clone)]
pub struct ProviderEgressPolicy {
    provider: ConnectorProvider,
    redirect_mode: RedirectMode,
}

impl ProviderEgressPolicy {
    /// Frozen Month-1 policy for one provider worker.
    #[must_use]
    pub const fn for_provider(provider: ConnectorProvider) -> Self {
        Self {
            provider,
            redirect_mode: RedirectMode::Disabled,
        }
    }

    /// HTTP-client redirect mode.
    #[must_use]
    pub const fn redirect_mode(&self) -> RedirectMode {
        self.redirect_mode
    }

    /// Validate scheme, authority, exact host, path prefix, and resource bounds.
    pub fn validate(&self, request: EgressRequest) -> Result<ValidatedEgressRequest> {
        if request.max_response_bytes == 0 || request.max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(ConnectorError::EgressDenied("response size bound"));
        }
        if request.timeout.is_zero() || request.timeout > MAX_REQUEST_TIME {
            return Err(ConnectorError::EgressDenied("request timeout bound"));
        }
        let parsed = validate_provider_url(self.provider, &request.url)?;
        Ok(ValidatedEgressRequest {
            provider: self.provider,
            url: parsed,
            max_response_bytes: request.max_response_bytes,
            timeout: request.timeout,
        })
    }

    /// Revalidate a redirect target before a caller issues a distinct request.
    /// The original request must also belong to this provider policy.
    pub fn revalidate_redirect(&self, original: &str, target: &str) -> Result<ValidatedRedirect> {
        let original = validate_provider_url(self.provider, original)?;
        let target = validate_provider_url(self.provider, target)?;
        Ok(ValidatedRedirect { original, target })
    }
}

fn validate_provider_url(provider: ConnectorProvider, value: &str) -> Result<Url> {
    let url = Url::parse(value).map_err(|_| ConnectorError::EgressDenied("URL is invalid"))?;
    if url.scheme() != "https"
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some_and(|query| query.len() > 8_192)
        || url.fragment().is_some()
    {
        return Err(ConnectorError::EgressDenied(
            "URL authority is not approved",
        ));
    }
    let host = url
        .host_str()
        .ok_or(ConnectorError::EgressDenied("URL host is missing"))?;
    if IpAddr::from_str(host).is_ok() {
        return Err(ConnectorError::EgressDenied(
            "IP-literal destinations are disabled",
        ));
    }
    let path = url.path();
    let allowed = match provider {
        ConnectorProvider::MicrosoftGraph => {
            host.eq_ignore_ascii_case("graph.microsoft.com") && path.starts_with("/v1.0/")
        }
        ConnectorProvider::GoogleDrive => {
            (host.eq_ignore_ascii_case("www.googleapis.com") && path.starts_with("/drive/v3/"))
                || (host.eq_ignore_ascii_case("docs.googleapis.com") && path.starts_with("/v1/"))
                || (host.eq_ignore_ascii_case("sheets.googleapis.com") && path.starts_with("/v4/"))
                || (host.eq_ignore_ascii_case("slides.googleapis.com") && path.starts_with("/v1/"))
        }
        ConnectorProvider::CoreCrm => {
            host.eq_ignore_ascii_case("crm.coreadvs.com")
                && (path == "/api/mcp" || path.starts_with("/api/mcp/"))
        }
    };
    if !allowed {
        return Err(ConnectorError::EgressDenied(
            "provider host or path is not allowlisted",
        ));
    }
    Ok(url)
}

/// Request after provider policy validation.
#[derive(Clone)]
pub struct ValidatedEgressRequest {
    provider: ConnectorProvider,
    url: Url,
    max_response_bytes: u64,
    timeout: Duration,
}

impl std::fmt::Debug for ValidatedEgressRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedEgressRequest")
            .field("provider", &self.provider)
            .field("url_redacted", &true)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl ValidatedEgressRequest {
    /// Provider worker allowed to execute the request.
    #[must_use]
    pub const fn provider(&self) -> ConnectorProvider {
        self.provider
    }

    /// Exact validated URL.
    #[must_use]
    pub const fn url(&self) -> &Url {
        &self.url
    }

    /// Hard response-body byte bound.
    #[must_use]
    pub const fn max_response_bytes(&self) -> u64 {
        self.max_response_bytes
    }

    /// Hard request deadline.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }
}

/// Explicit redirect revalidation result.
#[derive(Clone)]
pub struct ValidatedRedirect {
    original: Url,
    target: Url,
}

impl std::fmt::Debug for ValidatedRedirect {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedRedirect")
            .field("urls_redacted", &true)
            .finish()
    }
}

impl ValidatedRedirect {
    /// Initially validated provider URL.
    #[must_use]
    pub const fn original(&self) -> &Url {
        &self.original
    }

    /// Separately validated same-provider redirect target.
    #[must_use]
    pub const fn target(&self) -> &Url {
        &self.target
    }
}

/// Closed structured connector failure category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorFailureCode {
    /// Authentication was rejected.
    AuthenticationRejected,
    /// Provider quota or throttling delayed reads.
    RateLimited,
    /// Provider resource is no longer available.
    NotFound,
    /// Bounded response could not be parsed.
    InvalidResponse,
    /// Request ended before a trusted result was received.
    Timeout,
}

/// Secret-redacted provider error safe for logs and metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedConnectorFailure {
    /// Closed failure category.
    pub code: ConnectorFailureCode,
    /// Connector provider.
    pub provider: ConnectorProvider,
    /// One-way request correlation digest, never a token or URL.
    pub correlation_hash: [u8; 32],
}

impl RedactedConnectorFailure {
    /// Build from an operator-generated non-secret request correlation ID.
    #[must_use]
    pub fn new(
        code: ConnectorFailureCode,
        provider: ConnectorProvider,
        correlation_id: &[u8],
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"core-buzz:connector-correlation:v1\0");
        hasher.update(correlation_id);
        Self {
            code,
            provider,
            correlation_hash: hasher.finalize().into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_provider_policies_deny_metadata_and_private_networks() {
        for provider in [
            ConnectorProvider::MicrosoftGraph,
            ConnectorProvider::GoogleDrive,
            ConnectorProvider::CoreCrm,
        ] {
            let policy = ProviderEgressPolicy::for_provider(provider);
            for url in [
                "https://169.254.169.254/metadata/identity/oauth2/token",
                "https://127.0.0.1/private",
                "https://10.0.0.1/private",
                "https://localhost/private",
            ] {
                assert!(policy
                    .validate(EgressRequest::new(url, 1, Duration::from_secs(1)))
                    .is_err());
            }
            assert_eq!(policy.redirect_mode(), RedirectMode::Disabled);
        }
    }
}
