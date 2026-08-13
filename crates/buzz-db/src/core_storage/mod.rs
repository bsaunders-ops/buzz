//! Durable storage contracts for the Core Month-1 data plane.
//!
//! Every database entry point in this module requires a server-resolved
//! [`buzz_core::CommunityId`]. Connector secrets never cross this boundary;
//! only non-secret credential references and encrypted opaque cursor bytes are
//! accepted.

mod action_hash;
mod actions;
mod audit;
mod delta;
mod insights;
mod source_hash;
mod source_pages;
mod sources;
mod types;

pub use action_hash::{
    action_member_hash, action_member_operation_hash, action_operation_hash,
    action_ordered_members_hash, ActionMemberHashInput, ACTION_MEMBER_HASH_DOMAIN,
    ACTION_MEMBER_OPERATION_HASH_DOMAIN, ACTION_OPERATION_HASH_DOMAIN,
    ACTION_ORDERED_MEMBERS_HASH_DOMAIN,
};
pub use actions::{
    begin_action_remote_attempt, claim_action_execution, claim_action_receipt_publication,
    complete_action_receipt_publication, insert_action_proposal,
    mark_action_timeout_for_reconciliation, record_action_decision, record_action_member_outcome,
    retry_action_receipt_publication,
};
pub use audit::{
    append_audit_entry, claim_audit_export_batch, complete_audit_export_batch,
    retry_audit_export_batch,
};
pub use delta::{
    claim_delta_scope, claim_next_core_crm_delta_scope, complete_delta_scope, fail_delta_scope,
};
pub use insights::claim_insight_slot;
pub use source_hash::source_chunk_hash;
pub use source_pages::apply_source_change_page;
pub use sources::{
    recheck_source_chunk, recheck_source_chunk_fts, resolve_source_evidence, search_source_chunks,
    search_source_chunks_by_embedding, search_source_chunks_fts,
};
pub use types::*;

const HASH_BYTES: usize = 32;

fn require_hash(name: &str, value: &[u8]) -> crate::Result<()> {
    if value.len() != HASH_BYTES {
        return Err(crate::DbError::InvalidData(format!(
            "{name} must be exactly {HASH_BYTES} bytes"
        )));
    }
    Ok(())
}

fn require_pubkey(name: &str, value: &[u8]) -> crate::Result<()> {
    require_hash(name, value)
}

fn bounded_lease(lease_for: std::time::Duration) -> crate::Result<chrono::Duration> {
    const MAX_LEASE_SECONDS: u64 = 300;
    if lease_for.is_zero() || lease_for.as_secs() > MAX_LEASE_SECONDS {
        return Err(crate::DbError::InvalidData(format!(
            "lease must be between 1 and {MAX_LEASE_SECONDS} seconds"
        )));
    }
    chrono::Duration::from_std(lease_for)
        .map_err(|_| crate::DbError::InvalidData("lease duration is out of range".into()))
}
