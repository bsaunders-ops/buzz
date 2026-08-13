#![deny(unsafe_code)]
#![warn(missing_docs)]
//! Provider-neutral contracts for deterministic connector synchronization,
//! local-only indexing, and authorization-preserving retrieval.

/// Atomic connector-page application contracts.
pub mod apply;
/// Deterministic normalization and chunking.
pub mod chunk;
/// Bounded read-only Core CRM MCP adapter.
pub mod core_crm;
/// Deterministic known-record reconciliation for Core CRM snapshots.
pub mod core_crm_sync;
/// Provider-specific outbound network policy contracts.
pub mod egress;
/// Local embedding artifact and version contracts.
pub mod embedding;
/// PostgreSQL atomic page-application adapter.
pub mod persistence;
/// Authorization-preserving retrieval and citation contracts.
pub mod retrieval;
/// Provider notification wake-hint contracts.
pub mod sync;
/// Closed connector data-plane types.
pub mod types;

mod error;

pub use error::{ConnectorError, Result};
