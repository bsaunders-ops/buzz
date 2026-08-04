/// A broker validation or connector-preparation failure.
///
/// Inner diagnostics are retained for local control flow but deliberately do
/// not appear in `Debug` or `Display`, because parser/adapter diagnostics may
/// echo action bodies, external identifiers, versions, or public keys.
#[derive(thiserror::Error)]
pub enum BrokerError {
    /// JSON was malformed, non-canonical, duplicated, or outside the typed schema.
    #[error("invalid canonical external action")]
    InvalidCanonical(String),
    /// A typed protocol or cross-field policy invariant failed.
    #[error("external action policy rejected the request")]
    Policy(String),
    /// A fresh connector read could not prepare the exact operation.
    #[error("fresh connector read failed")]
    FreshRead(String),
}

impl std::fmt::Debug for BrokerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCanonical(_) => "InvalidCanonical(<redacted>)",
            Self::Policy(_) => "Policy(<redacted>)",
            Self::FreshRead(_) => "FreshRead(<redacted>)",
        })
    }
}
