//! Canonical, content-free export records for Core's immutable audit archive.

use std::str::FromStr;

use chrono::{DateTime, SecondsFormat, SubsecRound, Utc};
use nostr::secp256k1::schnorr::Signature;
use nostr::secp256k1::Message;
use nostr::{Keys, PublicKey, SECP256K1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Frozen schema version for Core audit export lines.
pub const CORE_AUDIT_EXPORT_SCHEMA_VERSION: u16 = 1;

const SIGNING_CONTEXT: &str = "core-buzz-audit-export-v1";
const MAX_EXPORT_LINES: usize = 1_000;
const MAX_EXPORT_BYTES: usize = 1_048_576;

/// Typed event represented by one Core audit-chain entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreAuditEventTypeV1 {
    /// Entra/Buzz identity binding changed.
    IdentityBindingChanged,
    /// Connector account authorization changed.
    ConnectorAccountChanged,
    /// A deterministic source synchronization completed.
    SourceSync,
    /// An assistant insight was claimed for delivery.
    InsightClaimed,
    /// A governed external-action proposal was decided.
    ActionProposalDecided,
    /// A governed external action reached an execution outcome.
    ActionExecution,
    /// A learning revision changed lifecycle state.
    LearningRevisionChanged,
    /// An immutable audit export was checkpointed.
    AuditExport,
}

impl CoreAuditEventTypeV1 {
    fn as_str(self) -> &'static str {
        match self {
            Self::IdentityBindingChanged => "identity_binding_changed",
            Self::ConnectorAccountChanged => "connector_account_changed",
            Self::SourceSync => "source_sync",
            Self::InsightClaimed => "insight_claimed",
            Self::ActionProposalDecided => "action_proposal_decided",
            Self::ActionExecution => "action_execution",
            Self::LearningRevisionChanged => "learning_revision_changed",
            Self::AuditExport => "audit_export",
        }
    }
}

/// Typed entity represented by one Core audit-chain entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreAuditEntityTypeV1 {
    /// Entra/Buzz identity binding.
    IdentityBinding,
    /// Connector account.
    ConnectorAccount,
    /// Approved connector scope.
    SourceScope,
    /// Mirrored source item.
    SourceItem,
    /// Assistant insight.
    AssistantInsight,
    /// External-action proposal.
    ExternalActionProposal,
    /// Learning revision.
    LearningRevision,
    /// Immutable audit checkpoint.
    AuditCheckpoint,
}

impl CoreAuditEntityTypeV1 {
    fn as_str(self) -> &'static str {
        match self {
            Self::IdentityBinding => "identity_binding",
            Self::ConnectorAccount => "connector_account",
            Self::SourceScope => "source_scope",
            Self::SourceItem => "source_item",
            Self::AssistantInsight => "assistant_insight",
            Self::ExternalActionProposal => "external_action_proposal",
            Self::LearningRevision => "learning_revision",
            Self::AuditCheckpoint => "audit_checkpoint",
        }
    }
}

/// Non-sensitive outcome represented in the immutable archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreAuditOutcomeV1 {
    /// Accepted by the deterministic boundary.
    Accepted,
    /// Rejected by the deterministic boundary.
    Rejected,
    /// Completed successfully.
    Succeeded,
    /// Completed with a terminal failure.
    Failed,
    /// Provider outcome could not be established before timeout.
    Timeout,
    /// Provider state must be reconciled before another attempt.
    ReconciliationRequired,
    /// Authorization was revoked.
    Revoked,
    /// Mirrored content was tombstoned.
    Tombstoned,
    /// A failed export or deterministic operation was retried.
    Retried,
}

impl CoreAuditOutcomeV1 {
    fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Timeout => "timeout",
            Self::ReconciliationRequired => "reconciliation_required",
            Self::Revoked => "revoked",
            Self::Tombstoned => "tombstoned",
            Self::Retried => "retried",
        }
    }
}

/// Trusted, in-process input for one audit export line.
///
/// The raw entity UUID is accepted only to derive a tenant-bound opaque hash;
/// it is never serialized into the archive.
#[derive(Clone)]
pub struct CoreAuditExportInputV1 {
    /// Server-resolved tenant.
    pub tenant_id: Uuid,
    /// Monotonic tenant-local sequence, starting at one.
    pub sequence: u64,
    /// Prior chain hash; absent only for sequence one.
    pub prior_entry_hash: Option<[u8; 32]>,
    /// Current chain entry hash.
    pub entry_hash: [u8; 32],
    /// Typed event name.
    pub event_type: CoreAuditEventTypeV1,
    /// Typed entity name.
    pub entity_type: CoreAuditEntityTypeV1,
    /// Raw database identifier, hashed before serialization.
    pub entity_id: Uuid,
    /// Hash of the affected object/state; never its body.
    pub object_hash: [u8; 32],
    /// Non-sensitive outcome.
    pub outcome: CoreAuditOutcomeV1,
    /// Event time, normalized to Postgres microsecond precision.
    pub occurred_at: DateTime<Utc>,
}

/// One self-verifying NDJSON line for the immutable Core audit archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreAuditExportLineV1 {
    /// Exact wire schema version. Unknown versions fail closed.
    pub schema_version: u16,
    /// Tenant leading the storage and verification key.
    pub tenant_id: Uuid,
    /// Monotonic tenant-local sequence.
    pub sequence: u64,
    /// Lowercase prior SHA-256 hash, absent only for genesis.
    pub prior_entry_hash: Option<String>,
    /// Lowercase current SHA-256 hash.
    pub entry_hash: String,
    /// Typed event name.
    pub event_type: CoreAuditEventTypeV1,
    /// Typed entity name.
    pub entity_type: CoreAuditEntityTypeV1,
    /// Tenant-bound opaque hash of the entity UUID.
    pub entity_id_hash: String,
    /// Hash of affected state; no copied source or message body.
    pub object_hash: String,
    /// Non-sensitive outcome.
    pub outcome: CoreAuditOutcomeV1,
    /// RFC3339 UTC timestamp at fixed microsecond precision.
    pub occurred_at: String,
    /// Lowercase x-only Nostr/secp256k1 signer public key.
    pub signer_pubkey: String,
    /// Lowercase BIP-340 Schnorr signature over every preceding field.
    pub signature: String,
}

/// Fail-closed audit export validation errors.
#[derive(Debug, thiserror::Error)]
pub enum CoreAuditExportError {
    /// Input or decoded data violates the frozen schema contract.
    #[error("invalid Core audit export: {0}")]
    Invalid(&'static str),
    /// A line is not valid JSON for schema version one.
    #[error("invalid Core audit export JSON")]
    InvalidJson,
    /// The BIP-340 signature is invalid.
    #[error("invalid Core audit export signature")]
    InvalidSignature,
}

impl CoreAuditExportLineV1 {
    /// Build and sign one content-free export line.
    pub fn sign(
        input: CoreAuditExportInputV1,
        signer: &Keys,
    ) -> Result<Self, CoreAuditExportError> {
        if input.tenant_id.is_nil() || input.entity_id.is_nil() {
            return Err(CoreAuditExportError::Invalid("nil tenant or entity UUID"));
        }
        validate_chain_shape(input.sequence, input.prior_entry_hash.as_ref())?;
        let occurred_at = input
            .occurred_at
            .trunc_subsecs(6)
            .to_rfc3339_opts(SecondsFormat::Micros, true);
        let entity_id_hash =
            opaque_entity_id_hash(input.tenant_id, input.entity_type, input.entity_id);
        let mut line = Self {
            schema_version: CORE_AUDIT_EXPORT_SCHEMA_VERSION,
            tenant_id: input.tenant_id,
            sequence: input.sequence,
            prior_entry_hash: input.prior_entry_hash.map(hex::encode),
            entry_hash: hex::encode(input.entry_hash),
            event_type: input.event_type,
            entity_type: input.entity_type,
            entity_id_hash: hex::encode(entity_id_hash),
            object_hash: hex::encode(input.object_hash),
            outcome: input.outcome,
            occurred_at,
            signer_pubkey: signer.public_key().to_hex(),
            signature: String::new(),
        };
        let message = line.signing_message()?;
        line.signature = signer.sign_schnorr(&message).to_string();
        Ok(line)
    }

    /// Verify schema, chain-shape, canonical values, and embedded signature.
    ///
    /// This proves the line is internally self-consistent. Archive
    /// authentication must use [`Self::verify_for`] with a tenant-bound trusted
    /// signer.
    pub fn verify(&self) -> Result<(), CoreAuditExportError> {
        self.verify_embedded_signature()
    }

    /// Verify this line for a trusted tenant archive signer.
    pub fn verify_for(
        &self,
        expected_tenant_id: Uuid,
        expected_signer: &PublicKey,
    ) -> Result<(), CoreAuditExportError> {
        self.verify_embedded_signature()?;
        if self.tenant_id != expected_tenant_id {
            return Err(CoreAuditExportError::Invalid("unexpected tenant UUID"));
        }
        if self.signer_pubkey != expected_signer.to_hex() {
            return Err(CoreAuditExportError::Invalid(
                "unexpected signer public key",
            ));
        }
        Ok(())
    }

    fn verify_embedded_signature(&self) -> Result<(), CoreAuditExportError> {
        if self.schema_version != CORE_AUDIT_EXPORT_SCHEMA_VERSION {
            return Err(CoreAuditExportError::Invalid("unknown schema version"));
        }
        if self.tenant_id.is_nil() {
            return Err(CoreAuditExportError::Invalid("nil tenant UUID"));
        }
        validate_chain_shape(self.sequence, self.prior_entry_hash.as_ref())?;
        if self
            .prior_entry_hash
            .as_deref()
            .is_some_and(|value| !is_canonical_hash(value))
        {
            return Err(CoreAuditExportError::Invalid("invalid prior entry hash"));
        }
        for value in [
            self.entry_hash.as_str(),
            self.entity_id_hash.as_str(),
            self.object_hash.as_str(),
        ] {
            if !is_canonical_hash(value) {
                return Err(CoreAuditExportError::Invalid("invalid SHA-256 field"));
            }
        }
        validate_canonical_timestamp(&self.occurred_at)?;
        if self.signer_pubkey.len() != 64 || !is_lowercase_hex(&self.signer_pubkey) {
            return Err(CoreAuditExportError::Invalid("invalid signer public key"));
        }
        if self.signature.len() != 128 || !is_lowercase_hex(&self.signature) {
            return Err(CoreAuditExportError::Invalid("invalid signature encoding"));
        }

        let signer = PublicKey::from_hex(&self.signer_pubkey)
            .map_err(|_| CoreAuditExportError::Invalid("invalid signer public key"))?;
        let signer = signer
            .xonly()
            .map_err(|_| CoreAuditExportError::Invalid("invalid signer public key"))?;
        let signature = Signature::from_str(&self.signature)
            .map_err(|_| CoreAuditExportError::Invalid("invalid signature encoding"))?;
        SECP256K1
            .verify_schnorr(&signature, &self.signing_message()?, &signer)
            .map_err(|_| CoreAuditExportError::InvalidSignature)
    }

    /// Serialize one verified record as exactly one newline-terminated JSON line.
    pub fn to_ndjson_line(
        &self,
        expected_tenant_id: Uuid,
        expected_signer: &PublicKey,
    ) -> Result<String, CoreAuditExportError> {
        self.verify_for(expected_tenant_id, expected_signer)?;
        let mut encoded =
            serde_json::to_string(self).map_err(|_| CoreAuditExportError::InvalidJson)?;
        encoded.push('\n');
        Ok(encoded)
    }

    fn signing_preimage(&self) -> Result<String, CoreAuditExportError> {
        if self.schema_version != CORE_AUDIT_EXPORT_SCHEMA_VERSION {
            return Err(CoreAuditExportError::Invalid("unknown schema version"));
        }
        let prior = self.prior_entry_hash.as_deref().unwrap_or("-");
        Ok(format!(
            "{SIGNING_CONTEXT}\n\
             schema_version={}\n\
             tenant_id={}\n\
             sequence={}\n\
             prior_entry_hash={}\n\
             entry_hash={}\n\
             event_type={}\n\
             entity_type={}\n\
             entity_id_hash={}\n\
             object_hash={}\n\
             outcome={}\n\
             occurred_at={}\n\
             signer_pubkey={}",
            self.schema_version,
            self.tenant_id,
            self.sequence,
            prior,
            self.entry_hash,
            self.event_type.as_str(),
            self.entity_type.as_str(),
            self.entity_id_hash,
            self.object_hash,
            self.outcome.as_str(),
            self.occurred_at,
            self.signer_pubkey,
        ))
    }

    fn signing_message(&self) -> Result<Message, CoreAuditExportError> {
        let digest = Sha256::digest(self.signing_preimage()?.as_bytes());
        Ok(Message::from_digest(digest.into()))
    }
}

/// Parse and verify a bounded, contiguous NDJSON export batch.
pub fn parse_and_verify_ndjson(
    encoded: &str,
    expected_tenant_id: Uuid,
    expected_signer: &PublicKey,
) -> Result<Vec<CoreAuditExportLineV1>, CoreAuditExportError> {
    if encoded.is_empty()
        || encoded.len() > MAX_EXPORT_BYTES
        || !encoded.ends_with('\n')
        || encoded.contains('\r')
    {
        return Err(CoreAuditExportError::Invalid("invalid NDJSON framing"));
    }
    let mut records = Vec::new();
    for raw_line in encoded.split_terminator('\n') {
        if raw_line.is_empty() || records.len() >= MAX_EXPORT_LINES {
            return Err(CoreAuditExportError::Invalid("invalid NDJSON framing"));
        }
        let record: CoreAuditExportLineV1 =
            serde_json::from_str(raw_line).map_err(|_| CoreAuditExportError::InvalidJson)?;
        record.verify_for(expected_tenant_id, expected_signer)?;
        let canonical =
            serde_json::to_string(&record).map_err(|_| CoreAuditExportError::InvalidJson)?;
        if canonical != raw_line {
            return Err(CoreAuditExportError::Invalid("non-canonical JSON line"));
        }
        if let Some(previous) = records.last() {
            verify_successor(previous, &record)?;
        }
        records.push(record);
    }
    if records.is_empty() {
        return Err(CoreAuditExportError::Invalid("empty export batch"));
    }
    Ok(records)
}

fn opaque_entity_id_hash(
    tenant_id: Uuid,
    entity_type: CoreAuditEntityTypeV1,
    entity_id: Uuid,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"core-buzz-audit-entity-id-v1");
    hasher.update(tenant_id.as_bytes());
    hasher.update(entity_type.as_str().as_bytes());
    hasher.update(entity_id.as_bytes());
    hasher.finalize().into()
}

fn validate_chain_shape<T>(
    sequence: u64,
    prior_entry_hash: Option<&T>,
) -> Result<(), CoreAuditExportError> {
    if sequence == 0
        || (sequence == 1 && prior_entry_hash.is_some())
        || (sequence > 1 && prior_entry_hash.is_none())
    {
        return Err(CoreAuditExportError::Invalid("invalid chain shape"));
    }
    Ok(())
}

fn verify_successor(
    previous: &CoreAuditExportLineV1,
    current: &CoreAuditExportLineV1,
) -> Result<(), CoreAuditExportError> {
    let expected_sequence = previous
        .sequence
        .checked_add(1)
        .ok_or(CoreAuditExportError::Invalid("audit sequence overflow"))?;
    if current.tenant_id != previous.tenant_id
        || current.signer_pubkey != previous.signer_pubkey
        || current.sequence != expected_sequence
        || current.prior_entry_hash.as_deref() != Some(previous.entry_hash.as_str())
    {
        return Err(CoreAuditExportError::Invalid(
            "audit export is not one contiguous tenant chain",
        ));
    }
    Ok(())
}

fn is_lowercase_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_canonical_hash(value: &str) -> bool {
    value.len() == 64 && is_lowercase_hex(value)
}

fn validate_canonical_timestamp(value: &str) -> Result<(), CoreAuditExportError> {
    let timestamp = DateTime::parse_from_rfc3339(value)
        .map_err(|_| CoreAuditExportError::Invalid("invalid timestamp"))?
        .with_timezone(&Utc);
    if timestamp.to_rfc3339_opts(SecondsFormat::Micros, true) != value {
        return Err(CoreAuditExportError::Invalid("non-canonical timestamp"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn occurred_at() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-03T12:34:56.123456789Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn input(tenant_id: Uuid, sequence: u64, prior: Option<[u8; 32]>) -> CoreAuditExportInputV1 {
        CoreAuditExportInputV1 {
            tenant_id,
            sequence,
            prior_entry_hash: prior,
            entry_hash: [0x22; 32],
            event_type: CoreAuditEventTypeV1::ActionExecution,
            entity_type: CoreAuditEntityTypeV1::ExternalActionProposal,
            entity_id: Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
            object_hash: [0x33; 32],
            outcome: CoreAuditOutcomeV1::Succeeded,
            occurred_at: occurred_at(),
        }
    }

    fn to_ndjson_line(line: &CoreAuditExportLineV1, tenant_id: Uuid, keys: &Keys) -> String {
        line.to_ndjson_line(tenant_id, &keys.public_key()).unwrap()
    }

    fn parse_batch(
        encoded: &str,
        tenant_id: Uuid,
        keys: &Keys,
    ) -> Result<Vec<CoreAuditExportLineV1>, CoreAuditExportError> {
        parse_and_verify_ndjson(encoded, tenant_id, &keys.public_key())
    }

    #[test]
    fn signed_line_round_trips_without_serializing_raw_entity_id() {
        let tenant = Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();
        let keys = Keys::generate();
        let raw_entity_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let line = CoreAuditExportLineV1::sign(input(tenant, 1, None), &keys).unwrap();

        line.verify().unwrap();
        line.verify_for(tenant, &keys.public_key()).unwrap();
        let encoded = to_ndjson_line(&line, tenant, &keys);
        assert!(encoded.ends_with('\n'));
        assert_eq!(encoded.lines().count(), 1);
        assert!(!encoded.contains(raw_entity_id));
        assert!(!encoded.contains("prompt"));
        assert!(!encoded.contains("body"));
        assert_eq!(line.occurred_at, "2026-08-03T12:34:56.123456Z");

        let decoded = parse_batch(&encoded, tenant, &keys).unwrap();
        assert_eq!(decoded, vec![line]);
    }

    #[test]
    fn trusted_tenant_and_signer_are_required() {
        let tenant = Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();
        let wrong_tenant = Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap();
        let keys = Keys::generate();
        let line = CoreAuditExportLineV1::sign(input(tenant, 1, None), &keys).unwrap();
        let encoded = to_ndjson_line(&line, tenant, &keys);

        assert!(line.verify_for(wrong_tenant, &keys.public_key()).is_err());
        assert!(line
            .verify_for(tenant, &Keys::generate().public_key())
            .is_err());
        assert!(parse_and_verify_ndjson(&encoded, wrong_tenant, &keys.public_key()).is_err());
        assert!(parse_and_verify_ndjson(&encoded, tenant, &Keys::generate().public_key()).is_err());
    }

    #[test]
    fn signature_binds_outcome_sequence_and_tenant() {
        let tenant = Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();
        let line = CoreAuditExportLineV1::sign(input(tenant, 1, None), &Keys::generate()).unwrap();

        let mut changed = line.clone();
        changed.outcome = CoreAuditOutcomeV1::Failed;
        assert!(matches!(
            changed.verify(),
            Err(CoreAuditExportError::InvalidSignature)
        ));

        let mut changed = line.clone();
        changed.sequence = 2;
        changed.prior_entry_hash = Some(hex::encode([0x11; 32]));
        assert!(matches!(
            changed.verify(),
            Err(CoreAuditExportError::InvalidSignature)
        ));

        let mut changed = line;
        changed.tenant_id = Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap();
        assert!(matches!(
            changed.verify(),
            Err(CoreAuditExportError::InvalidSignature)
        ));
    }

    #[test]
    fn tenant_is_part_of_the_opaque_entity_hash() {
        let keys = Keys::generate();
        let a = CoreAuditExportLineV1::sign(
            input(
                Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
                1,
                None,
            ),
            &keys,
        )
        .unwrap();
        let b = CoreAuditExportLineV1::sign(
            input(
                Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap(),
                1,
                None,
            ),
            &keys,
        )
        .unwrap();
        assert_ne!(a.entity_id_hash, b.entity_id_hash);
    }

    #[test]
    fn genesis_and_non_genesis_shape_fail_closed() {
        let tenant = Uuid::new_v4();
        let keys = Keys::generate();
        assert!(CoreAuditExportLineV1::sign(input(tenant, 0, None), &keys).is_err());
        assert!(CoreAuditExportLineV1::sign(input(tenant, 1, Some([0x11; 32])), &keys).is_err());
        assert!(CoreAuditExportLineV1::sign(input(tenant, 2, None), &keys).is_err());

        let mut nil_tenant = input(tenant, 1, None);
        nil_tenant.tenant_id = Uuid::nil();
        assert!(CoreAuditExportLineV1::sign(nil_tenant, &keys).is_err());

        let mut nil_entity = input(tenant, 1, None);
        nil_entity.entity_id = Uuid::nil();
        assert!(CoreAuditExportLineV1::sign(nil_entity, &keys).is_err());
    }

    #[test]
    fn parser_rejects_unknown_schema_fields_and_chain_discontinuity() {
        let tenant = Uuid::new_v4();
        let keys = Keys::generate();
        let first = CoreAuditExportLineV1::sign(input(tenant, 1, None), &keys).unwrap();
        let second =
            CoreAuditExportLineV1::sign(input(tenant, 2, Some([0x22; 32])), &keys).unwrap();
        let encoded = format!(
            "{}{}",
            to_ndjson_line(&first, tenant, &keys),
            to_ndjson_line(&second, tenant, &keys)
        );
        assert_eq!(parse_batch(&encoded, tenant, &keys).unwrap().len(), 2);

        let unknown_version = encoded.replacen("\"schema_version\":1", "\"schema_version\":2", 1);
        assert!(parse_batch(&unknown_version, tenant, &keys).is_err());

        let unknown_field = encoded.replacen("{", "{\"copied_body\":\"MNPI\",", 1);
        assert!(parse_batch(&unknown_field, tenant, &keys).is_err());

        let non_canonical_json = encoded.replacen("{", "{ ", 1);
        assert!(parse_batch(&non_canonical_json, tenant, &keys).is_err());

        let wrong_prior =
            CoreAuditExportLineV1::sign(input(tenant, 2, Some([0x44; 32])), &keys).unwrap();
        let wrong_prior = to_ndjson_line(&wrong_prior, tenant, &keys);
        let discontinuous = format!("{}{wrong_prior}", to_ndjson_line(&first, tenant, &keys));
        assert!(parse_batch(&discontinuous, tenant, &keys).is_err());
    }

    #[test]
    fn parser_rejects_valid_successor_signed_by_untrusted_key() {
        let tenant = Uuid::new_v4();
        let trusted_keys = Keys::generate();
        let untrusted_keys = Keys::generate();
        let first = CoreAuditExportLineV1::sign(input(tenant, 1, None), &trusted_keys).unwrap();
        let second = CoreAuditExportLineV1::sign(
            input(tenant, 2, Some(hex_to_hash(&first.entry_hash))),
            &untrusted_keys,
        )
        .unwrap();
        let encoded = format!(
            "{}{}",
            to_ndjson_line(&first, tenant, &trusted_keys),
            to_ndjson_line(&second, tenant, &untrusted_keys)
        );

        assert!(parse_batch(&encoded, tenant, &trusted_keys).is_err());
    }

    #[test]
    fn parser_rejects_sequence_overflow_instead_of_accepting_a_duplicate() {
        let tenant = Uuid::new_v4();
        let keys = Keys::generate();
        let first =
            CoreAuditExportLineV1::sign(input(tenant, u64::MAX, Some([0x22; 32])), &keys).unwrap();
        let duplicate =
            CoreAuditExportLineV1::sign(input(tenant, u64::MAX, Some([0x22; 32])), &keys).unwrap();
        let encoded = format!(
            "{}{}",
            to_ndjson_line(&first, tenant, &keys),
            to_ndjson_line(&duplicate, tenant, &keys)
        );
        assert!(parse_batch(&encoded, tenant, &keys).is_err());
    }

    fn hex_to_hash(value: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        hex::decode_to_slice(value, &mut out).unwrap();
        out
    }
}
