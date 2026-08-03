use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{ExternalConnector, ExternalOperation};

/// Frozen operation-hash domain shared with the action protocol integration.
pub const ACTION_OPERATION_HASH_DOMAIN: &[u8] = b"CORE-BUZZ-ACTION-V1\0";
/// Versioned domain for one member's canonical operation bytes.
pub const ACTION_MEMBER_OPERATION_HASH_DOMAIN: &[u8] = b"CORE-BUZZ-ACTION-MEMBER-OP-V1\0";
/// Versioned domain for one action bundle member.
pub const ACTION_MEMBER_HASH_DOMAIN: &[u8] = b"CORE-BUZZ-ACTION-MEMBER-V1\0";
/// Versioned domain for an ordered action bundle.
pub const ACTION_ORDERED_MEMBERS_HASH_DOMAIN: &[u8] = b"CORE-BUZZ-ACTION-ORDERED-MEMBERS-V1\0";

/// Exact immutable fields committed by one member hash.
#[derive(Debug, Clone, Copy)]
pub struct ActionMemberHashInput<'a> {
    /// Tenant-scoped connector account.
    pub account_id: Uuid,
    /// Approved connector scope.
    pub scope_id: Uuid,
    /// Stable protocol member identifier.
    pub operation_id: Uuid,
    /// Owner approving the member.
    pub owner_pubkey: &'a [u8],
    /// Typed connector.
    pub connector: ExternalConnector,
    /// Typed operation.
    pub operation: ExternalOperation,
    /// Hash of the remote target.
    pub target_hash: &'a [u8],
    /// Optional before-state hash.
    pub before_hash: Option<&'a [u8]>,
    /// Required after-state hash.
    pub after_hash: &'a [u8],
    /// Optional optimistic-concurrency version.
    pub expected_remote_version: Option<&'a str>,
    /// Per-member UUIDv4 idempotency key.
    pub idempotency_key: Uuid,
    /// Hash of the exact canonical operation bytes.
    pub canonical_operation_hash: &'a [u8],
}

fn hash_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

/// Hash exact RFC8785 canonical operation bytes with the frozen protocol domain.
#[must_use]
pub fn action_operation_hash(canonical_proposal: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ACTION_OPERATION_HASH_DOMAIN);
    hasher.update(canonical_proposal);
    hasher.finalize().into()
}

/// Hash exact RFC8785 canonical operation bytes for one bundle member.
#[must_use]
pub fn action_member_operation_hash(canonical_operation: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ACTION_MEMBER_OPERATION_HASH_DOMAIN);
    hasher.update(canonical_operation);
    hasher.finalize().into()
}

/// Hash every immutable member field with an explicit versioned domain.
#[must_use]
pub fn action_member_hash(input: ActionMemberHashInput<'_>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ACTION_MEMBER_HASH_DOMAIN);
    for field in [
        input.account_id.as_bytes().as_slice(),
        input.scope_id.as_bytes().as_slice(),
        input.operation_id.as_bytes().as_slice(),
        input.owner_pubkey,
        input.connector.as_str().as_bytes(),
        input.operation.as_str().as_bytes(),
        input.target_hash,
        input.before_hash.unwrap_or_default(),
        input.after_hash,
        input.expected_remote_version.unwrap_or_default().as_bytes(),
        input.idempotency_key.as_bytes().as_slice(),
        input.canonical_operation_hash,
    ] {
        hash_length_prefixed(&mut hasher, field);
    }
    hasher.finalize().into()
}

/// Hash the exact ordered member-hash list and its count.
#[must_use]
pub fn action_ordered_members_hash(member_hashes: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ACTION_ORDERED_MEMBERS_HASH_DOMAIN);
    hash_length_prefixed(&mut hasher, &(member_hashes.len() as u64).to_be_bytes());
    for member_hash in member_hashes {
        hash_length_prefixed(&mut hasher, member_hash);
    }
    hasher.finalize().into()
}
