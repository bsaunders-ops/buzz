use crate::error::BrokerError;

pub use buzz_core::action_auth::{DecisionExpectation, VerifiedActionDecision};

/// Verify the signed owner decision and return an opaque durable capability.
pub fn validate_signed_decision(
    event: &nostr::Event,
    expected: &DecisionExpectation,
    now: i64,
) -> Result<VerifiedActionDecision, BrokerError> {
    buzz_core::action_auth::validate_signed_action_decision(event, expected, now)
        .map_err(|error| BrokerError::Policy(error.to_string()))
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
