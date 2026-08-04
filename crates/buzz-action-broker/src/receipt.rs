use std::fmt;

use buzz_core::{
    action_auth::{validate_signed_action_receipt, ReceiptExpectation, VerifiedActionReceipt},
    core_protocol::ActionReceiptPayload,
};
use buzz_db::core_storage::{ActionMemberOutcome, ActionReceiptPublication};
use nostr::Event;
use serde_json::json;
use uuid::Uuid;

use crate::ExecutionError;

/// Exact validated receipt content and private routing derived from durable rows.
pub struct PreparedReceiptEvent {
    channel_id: Uuid,
    recipient_pubkey: [u8; 32],
    signer_pubkey: [u8; 32],
    content: String,
}

impl PreparedReceiptEvent {
    /// Private channel committed by the approved proposal.
    #[must_use]
    pub const fn channel_id(&self) -> Uuid {
        self.channel_id
    }

    /// Exact owner recipient for the kind `44312` event.
    #[must_use]
    pub const fn recipient_pubkey(&self) -> [u8; 32] {
        self.recipient_pubkey
    }

    /// Exact registered broker expected to sign the receipt event.
    #[must_use]
    pub const fn signer_pubkey(&self) -> [u8; 32] {
        self.signer_pubkey
    }

    /// Validated kind `44312` JSON content ready for signing.
    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }
}

impl fmt::Debug for PreparedReceiptEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedReceiptEvent")
            .field("routing", &"<redacted>")
            .field("content", &"<redacted>")
            .finish()
    }
}

/// Build a kind `44312` payload only from a claimed durable receipt projection.
pub fn prepare_receipt_event(
    publication: &ActionReceiptPublication,
) -> Result<PreparedReceiptEvent, ExecutionError> {
    if publication.receipt_id.get_version_num() != 4
        || publication.proposal_id.get_version_num() != 4
        || publication.decision_id.get_version_num() != 4
        || publication.channel_id.get_version_num() != 4
        || publication.operation_hash.len() != 32
        || publication.results.is_empty()
        || publication.results.len() > 10
    {
        return Err(ExecutionError::BindingRejected);
    }
    let recipient_pubkey: [u8; 32] = publication
        .owner_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| ExecutionError::BindingRejected)?;
    let signer_pubkey: [u8; 32] = publication
        .broker_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| ExecutionError::BindingRejected)?;
    if recipient_pubkey == signer_pubkey {
        return Err(ExecutionError::BindingRejected);
    }

    let results = publication
        .results
        .iter()
        .map(|result| {
            if result.operation_id.get_version_num() != 4
                || result.idempotency_key.get_version_num() != 4
                || result.operation_hash.len() != 32
            {
                return Err(ExecutionError::BindingRejected);
            }
            Ok(json!({
                "operation_id": result.operation_id.to_string(),
                "operation_hash": hex::encode(&result.operation_hash),
                "idempotency_key": result.idempotency_key.to_string(),
                "outcome": match result.outcome {
                    ActionMemberOutcome::Succeeded => "succeeded",
                    ActionMemberOutcome::Failed => "failed",
                    ActionMemberOutcome::ReconciliationRequired => "reconciliation_required",
                },
                "external_result_id": result.external_result_id,
                "external_result_version": result.external_result_version,
                "reconciliation_status": result.reconciliation_status,
            }))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let value = json!({
        "schema_version": 1,
        "receipt_id": publication.receipt_id.to_string(),
        "proposal_id": publication.proposal_id.to_string(),
        "decision_id": publication.decision_id.to_string(),
        "operation_hash": hex::encode(&publication.operation_hash),
        "results": results,
        "occurred_at": publication.occurred_at.timestamp(),
    });
    let payload: ActionReceiptPayload =
        serde_json::from_value(value).map_err(|_| ExecutionError::BindingRejected)?;
    payload
        .validate()
        .map_err(|_| ExecutionError::BindingRejected)?;
    let content = serde_json::to_string(&payload).map_err(|_| ExecutionError::BindingRejected)?;
    Ok(PreparedReceiptEvent {
        channel_id: publication.channel_id,
        recipient_pubkey,
        signer_pubkey,
        content,
    })
}

/// Verify the exact signed kind `44312` event before marking its outbox row published.
pub fn validate_signed_receipt(
    event: &Event,
    prepared: &PreparedReceiptEvent,
    now: i64,
) -> Result<VerifiedActionReceipt, ExecutionError> {
    let payload: ActionReceiptPayload =
        serde_json::from_str(prepared.content()).map_err(|_| ExecutionError::BindingRejected)?;
    validate_signed_action_receipt(
        event,
        &ReceiptExpectation {
            payload,
            channel_id: prepared.channel_id(),
            owner_pubkey: prepared.recipient_pubkey(),
            broker_pubkey: prepared.signer_pubkey(),
        },
        now,
    )
    .map_err(|_| ExecutionError::BindingRejected)
}
