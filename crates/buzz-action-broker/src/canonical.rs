use std::{collections::HashSet, fmt};

use buzz_core::core_protocol::{
    ActionProposalPayload, ActionSideEffect, ActionState, ActionTarget, BundleSemantics,
    CanonicalUuidV4, EvidenceRef, ExternalOperationMember, LowercasePubkey, PositiveWriteOperation,
    ProtocolLabel, Sha256Hex, Version1,
};
use buzz_db::core_storage::{
    action_member_hash, action_member_operation_hash, action_operation_hash,
    action_ordered_members_hash, ActionMemberHashInput, NewExternalActionProposal,
    NewExternalActionProposalItem,
};
use serde::{de::DeserializeSeed, Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    error::BrokerError,
    policy::{
        describe_operation, parse_uuid_v4, timestamp, validate_member_policy, validate_timing,
        validate_uuid_v4, MAX_BUNDLE_MEMBERS,
    },
    proposal::{FreshReadState, ProposalRequest, RequestedOperation},
};

const ACTION_TARGET_HASH_DOMAIN: &[u8] = b"CORE-BUZZ-ACTION-TARGET-V1\0";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CanonicalMemberV1 {
    pub(crate) operation_id: CanonicalUuidV4,
    pub(crate) operation_hash: Sha256Hex,
    pub(crate) member_hash: Sha256Hex,
    pub(crate) idempotency_key: CanonicalUuidV4,
    pub(crate) target: ActionTarget,
    pub(crate) before: Option<ActionState>,
    pub(crate) after: ActionState,
    pub(crate) expected_remote_version: Option<ProtocolLabel>,
    pub(crate) side_effects: Vec<ActionSideEffect>,
    pub(crate) operation: PositiveWriteOperation,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalEnvelopeV1 {
    schema_version: Version1,
    tenant_id: CanonicalUuidV4,
    proposal_id: CanonicalUuidV4,
    channel_id: CanonicalUuidV4,
    owner_pubkey: LowercasePubkey,
    broker_pubkey: LowercasePubkey,
    nonce: CanonicalUuidV4,
    proposed_at: i64,
    expires_at: i64,
    bundle_semantics: BundleSemantics,
    member_count: u16,
    ordered_members_hash: Sha256Hex,
    operations: Vec<CanonicalMemberV1>,
    evidence: Vec<EvidenceRef>,
}

/// Strictly parsed and semantically rebound canonical action proposal.
#[derive(Clone)]
pub struct CanonicalProposal {
    tenant_id: Uuid,
    canonical_bytes: Vec<u8>,
    operation_hash: [u8; 32],
    protocol_payload: ActionProposalPayload,
    database_record: NewExternalActionProposal,
}

impl fmt::Debug for CanonicalProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalProposal")
            .field("member_count", &self.database_record.items.len())
            .field("canonical_bytes", &"<redacted>")
            .field("protocol_payload", &"<redacted>")
            .finish()
    }
}

impl CanonicalProposal {
    /// Tenant UUID bound inside the exact canonical envelope.
    #[must_use]
    pub const fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    /// Parse exact RFC 8785 bytes, reject duplicates/non-canonical encodings,
    /// recompute every nested hash, and rebind the typed durable projection.
    pub fn parse_exact(canonical: &[u8], claimed_hash: &[u8]) -> Result<Self, BrokerError> {
        if canonical.is_empty() || canonical.len() > 65_535 {
            return Err(BrokerError::InvalidCanonical(
                "proposal must contain 1..=65535 bytes".into(),
            ));
        }
        if claimed_hash.len() != 32 {
            return Err(BrokerError::InvalidCanonical(
                "operation hash must contain exactly 32 bytes".into(),
            ));
        }
        let value = parse_strict_json(canonical)?;
        let envelope: CanonicalEnvelopeV1 = serde_json::from_value(value)
            .map_err(|error| BrokerError::InvalidCanonical(error.to_string()))?;
        let recanonicalized = serde_json_canonicalizer::to_vec(&envelope)
            .map_err(|error| BrokerError::InvalidCanonical(error.to_string()))?;
        if recanonicalized != canonical {
            return Err(BrokerError::InvalidCanonical(
                "proposal bytes are not exact RFC 8785 canonical JSON".into(),
            ));
        }
        let operation_hash = action_operation_hash(canonical);
        if operation_hash.as_slice() != claimed_hash {
            return Err(BrokerError::InvalidCanonical(
                "proposal hash does not match canonical bytes".into(),
            ));
        }
        Self::validate_and_project(envelope, recanonicalized, operation_hash)
    }

    /// Exact RFC 8785 bytes that were displayed and signed for approval.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Domain-separated SHA-256 over [`Self::canonical_bytes`].
    #[must_use]
    pub fn operation_hash(&self) -> &[u8] {
        &self.operation_hash
    }

    /// Frozen relay payload derived from the exact canonical envelope.
    #[must_use]
    pub fn protocol_payload(&self) -> &ActionProposalPayload {
        &self.protocol_payload
    }

    /// Fully rebound durable projection ready for tenant-scoped insertion.
    #[must_use]
    pub fn database_record(&self) -> &NewExternalActionProposal {
        &self.database_record
    }

    fn validate_and_project(
        envelope: CanonicalEnvelopeV1,
        canonical_bytes: Vec<u8>,
        operation_hash: [u8; 32],
    ) -> Result<Self, BrokerError> {
        let tenant_id = envelope.tenant_id.as_uuid();
        validate_uuid_v4("tenant_id", tenant_id)?;
        validate_uuid_v4("proposal_id", envelope.proposal_id.as_uuid())?;
        validate_uuid_v4("channel_id", envelope.channel_id.as_uuid())?;
        validate_uuid_v4("nonce", envelope.nonce.as_uuid())?;
        validate_timing(envelope.proposed_at, envelope.expires_at)?;
        if envelope.operations.is_empty() || envelope.operations.len() > MAX_BUNDLE_MEMBERS {
            return Err(BrokerError::Policy(
                "bundle must contain 1..=10 operations".into(),
            ));
        }
        if usize::from(envelope.member_count) != envelope.operations.len() {
            return Err(BrokerError::Policy(
                "member_count does not match the ordered operation list".into(),
            ));
        }

        let owner = decode_pubkey(&envelope.owner_pubkey)?;
        let broker = decode_pubkey(&envelope.broker_pubkey)?;
        if owner == broker {
            return Err(BrokerError::Policy(
                "owner and broker public keys must differ".into(),
            ));
        }

        let mut seen_operation_ids = HashSet::with_capacity(envelope.operations.len());
        let mut seen_idempotency_keys = HashSet::with_capacity(envelope.operations.len());
        let mut seen_member_hashes = HashSet::with_capacity(envelope.operations.len());
        let mut item_records = Vec::with_capacity(envelope.operations.len());
        let mut member_hashes = Vec::with_capacity(envelope.operations.len());
        let mut protocol_members = Vec::with_capacity(envelope.operations.len());

        for member in &envelope.operations {
            let operation_id = member.operation_id.as_uuid();
            let idempotency_key = member.idempotency_key.as_uuid();
            validate_uuid_v4("operation_id", operation_id)?;
            validate_uuid_v4("idempotency_key", idempotency_key)?;
            if !seen_operation_ids.insert(operation_id)
                || !seen_idempotency_keys.insert(idempotency_key)
            {
                return Err(BrokerError::Policy(
                    "operation IDs and idempotency keys must be unique".into(),
                ));
            }

            validate_action_state(member.before.as_ref())?;
            validate_action_state(Some(&member.after))?;
            let descriptor = describe_operation(&member.operation);
            validate_member_policy(member, descriptor)?;

            let member_preimage = MemberPreimageV1::from(member);
            let member_canonical = serde_json_canonicalizer::to_vec(&member_preimage)
                .map_err(|error| BrokerError::InvalidCanonical(error.to_string()))?;
            let canonical_operation_hash = action_member_operation_hash(&member_canonical);
            if hex::encode(canonical_operation_hash) != member.operation_hash.as_str() {
                return Err(BrokerError::InvalidCanonical(
                    "member operation hash does not match typed preimage".into(),
                ));
            }

            let account_id = parse_uuid_v4("target.account_id", member.target.account_id.as_str())?;
            let scope_id = parse_uuid_v4("target.scope_id", member.target.scope_id.as_str())?;
            let target_hash = target_hash(&member.target)?;
            let before_hash = member
                .before
                .as_ref()
                .map(|state| decode_hash(&state.value_hash))
                .transpose()?;
            let after_hash = decode_hash(&member.after.value_hash)?;
            let expected_remote_version = member
                .expected_remote_version
                .as_ref()
                .map(|version| version.as_str().to_owned());
            let calculated_member_hash = action_member_hash(ActionMemberHashInput {
                account_id,
                scope_id,
                operation_id,
                owner_pubkey: &owner,
                connector: descriptor.connector,
                operation: descriptor.operation,
                target_hash: &target_hash,
                before_hash: before_hash.as_ref().map(<[u8; 32]>::as_slice),
                after_hash: &after_hash,
                expected_remote_version: expected_remote_version.as_deref(),
                idempotency_key,
                canonical_operation_hash: &canonical_operation_hash,
            });
            if hex::encode(calculated_member_hash) != member.member_hash.as_str() {
                return Err(BrokerError::InvalidCanonical(
                    "member hash does not match all durable fields".into(),
                ));
            }
            if !seen_member_hashes.insert(calculated_member_hash) {
                return Err(BrokerError::Policy(
                    "member hashes must be unique within a bundle".into(),
                ));
            }
            member_hashes.push(calculated_member_hash);
            item_records.push(NewExternalActionProposalItem {
                operation_id,
                account_id,
                scope_id,
                connector: descriptor.connector,
                operation: descriptor.operation,
                target_hash: target_hash.to_vec(),
                canonical_operation: member_canonical,
                canonical_operation_hash: canonical_operation_hash.to_vec(),
                before_hash: before_hash.map(|hash| hash.to_vec()),
                after_hash: after_hash.to_vec(),
                expected_remote_version,
                idempotency_key,
                member_hash: calculated_member_hash.to_vec(),
            });
            protocol_members.push(member.to_protocol_member()?);
        }

        let ordered_members_hash = action_ordered_members_hash(&member_hashes);
        if hex::encode(ordered_members_hash) != envelope.ordered_members_hash.as_str() {
            return Err(BrokerError::InvalidCanonical(
                "ordered member hash does not match the exact member order".into(),
            ));
        }
        let protocol_payload =
            build_protocol_payload(&envelope, &operation_hash, protocol_members)?;
        protocol_payload
            .validate_at(envelope.proposed_at)
            .map_err(|error| BrokerError::Policy(error.to_string()))?;

        let database_record = NewExternalActionProposal {
            id: envelope.proposal_id.as_uuid(),
            owner_pubkey: owner.to_vec(),
            broker_pubkey: broker.to_vec(),
            channel_id: envelope.channel_id.as_uuid(),
            canonical_proposal: canonical_bytes.clone(),
            operation_hash: operation_hash.to_vec(),
            ordered_members_hash: ordered_members_hash.to_vec(),
            nonce: envelope.nonce.as_uuid(),
            proposed_at: timestamp(envelope.proposed_at)?,
            expires_at: timestamp(envelope.expires_at)?,
            items: item_records,
        };
        Ok(Self {
            tenant_id,
            canonical_bytes,
            operation_hash,
            protocol_payload,
            database_record,
        })
    }
}

pub(crate) fn build_envelope(
    request: &ProposalRequest,
    members: Vec<CanonicalMemberV1>,
) -> Result<CanonicalProposal, BrokerError> {
    let member_hashes = members
        .iter()
        .map(|member| decode_hash(&member.member_hash))
        .collect::<Result<Vec<_>, _>>()?;
    let ordered_members_hash = action_ordered_members_hash(&member_hashes);
    let envelope = CanonicalEnvelopeV1 {
        schema_version: Version1,
        tenant_id: canonical_uuid(request.tenant_id)?,
        proposal_id: canonical_uuid(request.proposal_id)?,
        channel_id: canonical_uuid(request.channel_id)?,
        owner_pubkey: lowercase_pubkey(&request.owner_pubkey)?,
        broker_pubkey: lowercase_pubkey(&request.broker_pubkey)?,
        nonce: canonical_uuid(request.nonce)?,
        proposed_at: request.proposed_at,
        expires_at: request.expires_at,
        bundle_semantics: BundleSemantics::IndependentOperations,
        member_count: u16::try_from(members.len())
            .map_err(|_| BrokerError::Policy("bundle member count is out of range".into()))?,
        ordered_members_hash: sha256_hex(&ordered_members_hash)?,
        operations: members,
        evidence: request.evidence.clone(),
    };
    let canonical = serde_json_canonicalizer::to_vec(&envelope)
        .map_err(|error| BrokerError::InvalidCanonical(error.to_string()))?;
    let hash = action_operation_hash(&canonical);
    CanonicalProposal::parse_exact(&canonical, &hash)
}

#[derive(Serialize)]
struct MemberPreimageV1<'a> {
    schema_version: Version1,
    operation_id: &'a CanonicalUuidV4,
    idempotency_key: &'a CanonicalUuidV4,
    target: &'a ActionTarget,
    before: &'a Option<ActionState>,
    after: &'a ActionState,
    expected_remote_version: &'a Option<ProtocolLabel>,
    side_effects: &'a [ActionSideEffect],
    operation: &'a PositiveWriteOperation,
}

impl<'a> From<&'a CanonicalMemberV1> for MemberPreimageV1<'a> {
    fn from(member: &'a CanonicalMemberV1) -> Self {
        Self {
            schema_version: Version1,
            operation_id: &member.operation_id,
            idempotency_key: &member.idempotency_key,
            target: &member.target,
            before: &member.before,
            after: &member.after,
            expected_remote_version: &member.expected_remote_version,
            side_effects: &member.side_effects,
            operation: &member.operation,
        }
    }
}

pub(crate) fn build_member(
    request: &ProposalRequest,
    requested: &RequestedOperation,
    fresh: FreshReadState,
) -> Result<CanonicalMemberV1, BrokerError> {
    let descriptor = describe_operation(&requested.operation);
    let before = fresh.before.as_deref().map(action_state).transpose()?;
    let after = action_state(&fresh.after)?;
    let expected_remote_version = fresh
        .expected_remote_version
        .as_deref()
        .map(protocol_label)
        .transpose()?;
    if descriptor.create != before.is_none()
        || descriptor.create != expected_remote_version.is_none()
    {
        return Err(BrokerError::Policy(
            "creates require no before/version; updates require both".into(),
        ));
    }
    let mut member = CanonicalMemberV1 {
        operation_id: canonical_uuid(requested.operation_id)?,
        operation_hash: sha256_hex(&[0; 32])?,
        member_hash: sha256_hex(&[0; 32])?,
        idempotency_key: canonical_uuid(requested.idempotency_key)?,
        target: requested.target.clone(),
        before,
        after,
        expected_remote_version,
        side_effects: vec![descriptor.side_effect],
        operation: requested.operation.clone(),
    };
    validate_member_policy(&member, descriptor)?;
    let canonical_operation = serde_json_canonicalizer::to_vec(&MemberPreimageV1::from(&member))
        .map_err(|error| BrokerError::InvalidCanonical(error.to_string()))?;
    let operation_hash = action_member_operation_hash(&canonical_operation);
    member.operation_hash = sha256_hex(&operation_hash)?;

    let account_id = parse_uuid_v4("target.account_id", member.target.account_id.as_str())?;
    let scope_id = parse_uuid_v4("target.scope_id", member.target.scope_id.as_str())?;
    let target_hash = target_hash(&member.target)?;
    let before_hash = member
        .before
        .as_ref()
        .map(|state| decode_hash(&state.value_hash))
        .transpose()?;
    let after_hash = decode_hash(&member.after.value_hash)?;
    let expected_version = member
        .expected_remote_version
        .as_ref()
        .map(ProtocolLabel::as_str);
    let member_hash = action_member_hash(ActionMemberHashInput {
        account_id,
        scope_id,
        operation_id: requested.operation_id,
        owner_pubkey: &request.owner_pubkey,
        connector: descriptor.connector,
        operation: descriptor.operation,
        target_hash: &target_hash,
        before_hash: before_hash.as_ref().map(<[u8; 32]>::as_slice),
        after_hash: &after_hash,
        expected_remote_version: expected_version,
        idempotency_key: requested.idempotency_key,
        canonical_operation_hash: &operation_hash,
    });
    member.member_hash = sha256_hex(&member_hash)?;
    Ok(member)
}

impl CanonicalMemberV1 {
    fn to_protocol_member(&self) -> Result<ExternalOperationMember, BrokerError> {
        let value = serde_json::json!({
            "operation_id": self.operation_id,
            "operation_hash": self.operation_hash,
            "idempotency_key": self.idempotency_key,
            "target": self.target,
            "before": self.before,
            "after": self.after,
            "expected_remote_version": self.expected_remote_version,
            "side_effects": self.side_effects,
            "operation": self.operation,
        });
        serde_json::from_value(value).map_err(|error| BrokerError::Policy(error.to_string()))
    }
}

fn build_protocol_payload(
    envelope: &CanonicalEnvelopeV1,
    operation_hash: &[u8; 32],
    operations: Vec<ExternalOperationMember>,
) -> Result<ActionProposalPayload, BrokerError> {
    let value = serde_json::json!({
        "schema_version": 1,
        "proposal_id": envelope.proposal_id,
        "nonce": envelope.nonce,
        "operation_hash": hex::encode(operation_hash),
        "proposed_at": envelope.proposed_at,
        "expires_at": envelope.expires_at,
        "bundle_semantics": envelope.bundle_semantics,
        "operations": operations,
        "evidence": envelope.evidence,
    });
    serde_json::from_value(value).map_err(|error| BrokerError::Policy(error.to_string()))
}

fn canonical_uuid(value: Uuid) -> Result<CanonicalUuidV4, BrokerError> {
    validate_uuid_v4("UUID", value)?;
    CanonicalUuidV4::try_from(value.hyphenated().to_string().as_str())
        .map_err(|error| BrokerError::Policy(error.to_string()))
}

fn lowercase_pubkey(value: &[u8; 32]) -> Result<LowercasePubkey, BrokerError> {
    LowercasePubkey::try_from(hex::encode(value).as_str())
        .map_err(|error| BrokerError::Policy(error.to_string()))
}

fn decode_pubkey(value: &LowercasePubkey) -> Result<[u8; 32], BrokerError> {
    let bytes = hex::decode(value.as_str())
        .map_err(|error| BrokerError::InvalidCanonical(error.to_string()))?;
    bytes
        .try_into()
        .map_err(|_| BrokerError::InvalidCanonical("public key must contain 32 bytes".into()))
}

fn sha256_hex(value: &[u8; 32]) -> Result<Sha256Hex, BrokerError> {
    Sha256Hex::try_from(hex::encode(value).as_str())
        .map_err(|error| BrokerError::Policy(error.to_string()))
}

fn decode_hash(value: &Sha256Hex) -> Result<[u8; 32], BrokerError> {
    let bytes = hex::decode(value.as_str())
        .map_err(|error| BrokerError::InvalidCanonical(error.to_string()))?;
    bytes
        .try_into()
        .map_err(|_| BrokerError::InvalidCanonical("hash must contain 32 bytes".into()))
}

fn protocol_label(value: &str) -> Result<ProtocolLabel, BrokerError> {
    ProtocolLabel::try_from(value).map_err(|error| BrokerError::Policy(error.to_string()))
}

fn target_hash(target: &ActionTarget) -> Result<[u8; 32], BrokerError> {
    let canonical = serde_json_canonicalizer::to_vec(target)
        .map_err(|error| BrokerError::InvalidCanonical(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(ACTION_TARGET_HASH_DOMAIN);
    hasher.update(canonical);
    Ok(hasher.finalize().into())
}

fn action_state(raw: &[u8]) -> Result<ActionState, BrokerError> {
    if raw.is_empty() || raw.len() > 4096 {
        return Err(BrokerError::Policy(
            "normalized state must contain 1..=4096 bytes".into(),
        ));
    }
    let value = parse_strict_json(raw)?;
    let canonical = serde_json_canonicalizer::to_vec(&value)
        .map_err(|error| BrokerError::InvalidCanonical(error.to_string()))?;
    let canonical_value = String::from_utf8(canonical)
        .map_err(|error| BrokerError::InvalidCanonical(error.to_string()))?;
    let hash: [u8; 32] = Sha256::digest(canonical_value.as_bytes()).into();
    serde_json::from_value(serde_json::json!({
        "canonical_value": canonical_value,
        "value_hash": hex::encode(hash),
    }))
    .map_err(|error| BrokerError::Policy(error.to_string()))
}

fn validate_action_state(state: Option<&ActionState>) -> Result<(), BrokerError> {
    let Some(state) = state else {
        return Ok(());
    };
    let raw = state.canonical_value.as_str().as_bytes();
    let value = parse_strict_json(raw)?;
    let recanonicalized = serde_json_canonicalizer::to_vec(&value)
        .map_err(|error| BrokerError::InvalidCanonical(error.to_string()))?;
    if recanonicalized != raw {
        return Err(BrokerError::InvalidCanonical(
            "nested action state is not exact canonical JSON".into(),
        ));
    }
    let expected: [u8; 32] = Sha256::digest(raw).into();
    if decode_hash(&state.value_hash)? != expected {
        return Err(BrokerError::InvalidCanonical(
            "nested action-state hash does not match its canonical value".into(),
        ));
    }
    Ok(())
}

fn parse_strict_json(bytes: &[u8]) -> Result<Value, BrokerError> {
    use serde::de::{MapAccess, SeqAccess, Visitor};

    struct StrictValue;

    impl<'de> DeserializeSeed<'de> for StrictValue {
        type Value = Value;

        fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
            deserializer.deserialize_any(StrictValue)
        }
    }

    impl<'de> Visitor<'de> for StrictValue {
        type Value = Value;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("valid JSON with unique object member names")
        }

        fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
            Ok(Value::Bool(value))
        }

        fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
            Ok(Value::Number(value.into()))
        }

        fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
            Ok(Value::Number(value.into()))
        }

        fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Value, E> {
            serde_json::Number::from_f64(value)
                .map(Value::Number)
                .ok_or_else(|| E::custom("non-finite JSON number"))
        }

        fn visit_str<E>(self, value: &str) -> Result<Value, E> {
            Ok(Value::String(value.to_owned()))
        }

        fn visit_string<E>(self, value: String) -> Result<Value, E> {
            Ok(Value::String(value))
        }

        fn visit_unit<E>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }

        fn visit_none<E>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }

        fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
            deserializer.deserialize_any(StrictValue)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
            let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or_default());
            while let Some(value) = sequence.next_element_seed(StrictValue)? {
                values.push(value);
            }
            Ok(Value::Array(values))
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
            use serde::de::Error;

            let mut seen = HashSet::new();
            let mut values = serde_json::Map::new();
            while let Some(key) = map.next_key::<String>()? {
                if !seen.insert(key.clone()) {
                    return Err(A::Error::custom(format!(
                        "duplicate object member name: {key}"
                    )));
                }
                values.insert(key, map.next_value_seed(StrictValue)?);
            }
            Ok(Value::Object(values))
        }
    }

    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue
        .deserialize(&mut deserializer)
        .map_err(|error| BrokerError::InvalidCanonical(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| BrokerError::InvalidCanonical(error.to_string()))?;
    Ok(value)
}
