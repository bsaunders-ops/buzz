//! Connector-core error contracts.

use thiserror::Error;

/// A fail-closed connector, indexing, or retrieval error.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConnectorError {
    /// A caller supplied malformed or open-ended data.
    #[error("invalid connector data: {0}")]
    InvalidData(&'static str),
    /// A configured or remote bound was exceeded.
    #[error("connector bound exceeded: {0}")]
    BoundExceeded(&'static str),
    /// The page did not follow the currently committed cursor.
    #[error("delta cursor conflict")]
    CursorConflict,
    /// The account or source scope is not active and readable.
    #[error("connector source is inactive")]
    SourceInactive,
    /// A webhook notification failed provider authentication.
    #[error("connector notification authentication failed")]
    NotificationAuthentication,
    /// A local embedding artifact failed closed verification.
    #[error("local embedding artifact verification failed: {0}")]
    ArtifactVerification(&'static str),
    /// A requested outbound destination or bound is not approved.
    #[error("connector egress denied: {0}")]
    EgressDenied(&'static str),
    /// An item was no longer authorized during the post-rank recheck.
    #[error("source authorization changed during retrieval")]
    AuthorizationChanged,
}

/// Connector-core result alias.
pub type Result<T> = std::result::Result<T, ConnectorError>;
