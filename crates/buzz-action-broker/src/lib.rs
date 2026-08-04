//! Core Buzz's connector-independent external action broker.
//!
//! This crate deliberately exposes only typed Month-1 operations. It has no
//! generic HTTP, shell, SQL, connector-method, or provider-token surface.

mod canonical;
mod decision;
mod error;
mod executor;
mod policy;
mod proposal;
mod receipt;

pub use canonical::CanonicalProposal;
pub use decision::{
    validate_signed_decision, ActionLifecycleState, ActionTransition, DecisionExpectation,
    VerifiedActionDecision,
};
pub use error::BrokerError;
pub use executor::{
    execute_once, AdapterDispatchOutcome, AdapterReadFailure, DurableExecutionStore,
    ExecuteActionRequest, ExecuteActionResult, ExecutionError, PgExecutionStore,
    PreDispatchFailure, ProviderFailureCode, RemotePrecondition, TypedWriteAdapter,
};
pub use proposal::{
    prepare_proposal, FreshReadAdapter, FreshReadState, ProposalRequest, RequestedOperation,
};
pub use receipt::{prepare_receipt_event, PreparedReceiptEvent};

/// Proposal prepared from fresh normalized connector state.
pub type PreparedProposal = CanonicalProposal;
