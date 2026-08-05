//! Frozen version-1 values shared by Core protocol producers and the relay.

use std::{fmt, marker::PhantomData};

use nostr::nips::nip44::v2::ConversationKey;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::kind::{
    KIND_CORE_ACTION_DECISION, KIND_CORE_ACTION_PROPOSAL, KIND_CORE_ACTION_RECEIPT,
    KIND_CORE_CALL_CONTROL, KIND_CORE_COPILOT_SUGGESTION, KIND_CORE_INSIGHT,
    KIND_CORE_INSIGHT_DISPOSITION, KIND_CORE_LEARNING_BUNDLE_HEAD, KIND_CORE_LEARNING_RECORD,
    KIND_CORE_TRANSCRIPT_SEGMENT,
};

/// Maximum lifetime of an external action proposal, in seconds.
pub const MAX_PROPOSAL_LIFETIME_SECONDS: i64 = 900;
/// Maximum amount by which a proposal timestamp may lead relay wall time.
pub const MAX_PROPOSAL_FUTURE_SKEW_SECONDS: i64 = 300;
/// Maximum disposition snooze window (30 days), in seconds.
pub const MAX_SNOOZE_SECONDS: i64 = 30 * 24 * 60 * 60;
/// Maximum serialized content size for relay-readable Core payloads.
pub const MAX_CORE_PLAINTEXT_CONTENT_LEN: usize = 65_535;
/// Domain separator for owner-agent learning bundle coordinates.
pub const CORE_LEARNING_BUNDLE_COORDINATE_DOMAIN: &[u8] = b"core-learning/v1/bundle-coordinate";

/// Fixed author/recipient direction for a Core event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreDirection {
    /// The registered agent authors and its owner is the `p` recipient.
    AgentToOwner,
    /// The owner authors and its registered agent is the `p` recipient.
    OwnerToAgent,
    /// Either member of the registered pair may author to the other.
    Either,
}

/// Structurally validated public routing envelope for a Core event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreEnvelope {
    /// Canonical private-channel identifier from the sole `h` tag.
    pub channel_id: Uuid,
    /// Exact non-author recipient from the sole `p` tag.
    pub recipient: nostr::PublicKey,
    /// Required relationship direction for this kind.
    pub direction: CoreDirection,
}

/// Return whether a kind belongs to the frozen Core protocol.
pub const fn is_core_kind(kind: u32) -> bool {
    matches!(
        kind,
        KIND_CORE_INSIGHT
            | KIND_CORE_INSIGHT_DISPOSITION
            | KIND_CORE_ACTION_PROPOSAL
            | KIND_CORE_ACTION_DECISION
            | KIND_CORE_ACTION_RECEIPT
            | KIND_CORE_LEARNING_RECORD
            | KIND_CORE_LEARNING_BUNDLE_HEAD
            | KIND_CORE_CALL_CONTROL
            | KIND_CORE_TRANSCRIPT_SEGMENT
            | KIND_CORE_COPILOT_SUGGESTION
    )
}

/// Return whether a Core kind is durable rather than ephemeral.
pub const fn is_persistent_core_kind(kind: u32) -> bool {
    matches!(
        kind,
        KIND_CORE_INSIGHT
            | KIND_CORE_INSIGHT_DISPOSITION
            | KIND_CORE_ACTION_PROPOSAL
            | KIND_CORE_ACTION_DECISION
            | KIND_CORE_ACTION_RECEIPT
            | KIND_CORE_LEARNING_RECORD
            | KIND_CORE_LEARNING_BUNDLE_HEAD
    )
}

/// Return the frozen pair direction for a Core kind.
pub const fn core_direction(kind: u32) -> Option<CoreDirection> {
    match kind {
        KIND_CORE_INSIGHT
        | KIND_CORE_ACTION_PROPOSAL
        | KIND_CORE_ACTION_RECEIPT
        | KIND_CORE_LEARNING_BUNDLE_HEAD
        | KIND_CORE_COPILOT_SUGGESTION => Some(CoreDirection::AgentToOwner),
        KIND_CORE_INSIGHT_DISPOSITION
        | KIND_CORE_ACTION_DECISION
        | KIND_CORE_TRANSCRIPT_SEGMENT => Some(CoreDirection::OwnerToAgent),
        KIND_CORE_LEARNING_RECORD | KIND_CORE_CALL_CONTROL => Some(CoreDirection::Either),
        _ => None,
    }
}

/// Validate the public `h`/`p` routing envelope and encrypted-body shape.
///
/// Relationship, membership, and channel visibility require relay state and
/// are intentionally checked by the relay after this zero-I/O shape check.
pub fn validate_core_envelope(
    event: &nostr::Event,
) -> Result<CoreEnvelope, ProtocolValidationError> {
    let kind = crate::kind::event_kind_u32(event);
    let direction = core_direction(kind)
        .ok_or_else(|| ProtocolValidationError("event is not a Core kind".into()))?;

    let h_tags: Vec<_> = event
        .tags
        .iter()
        .filter(|tag| {
            let parts = tag.as_slice();
            parts.first().map(|part| part.as_str()) == Some("h")
        })
        .collect();
    let raw_channel = match h_tags.as_slice() {
        [tag] if tag.as_slice().len() == 2 => tag.as_slice()[1].as_str(),
        _ => {
            return Err(ProtocolValidationError(
                "Core events require exactly one two-element h tag".into(),
            ));
        }
    };
    let channel_id = Uuid::parse_str(raw_channel)
        .map_err(|_| ProtocolValidationError("Core h tag must be a canonical UUID".into()))?;
    if channel_id.hyphenated().to_string() != raw_channel {
        return Err(ProtocolValidationError(
            "Core h tag must be a canonical lowercase hyphenated UUID".into(),
        ));
    }

    let p_tags: Vec<_> = event
        .tags
        .iter()
        .filter(|tag| {
            let parts = tag.as_slice();
            parts.first().map(|part| part.as_str()) == Some("p")
        })
        .collect();
    let raw_recipient = match p_tags.as_slice() {
        [tag] if tag.as_slice().len() == 2 => tag.as_slice()[1].as_str(),
        _ => {
            return Err(ProtocolValidationError(
                "Core events require exactly one two-element p tag".into(),
            ));
        }
    };
    if raw_recipient.len() != 64
        || !raw_recipient
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProtocolValidationError(
            "Core p tag must be a lowercase 64-hex pubkey".into(),
        ));
    }
    let recipient = raw_recipient
        .parse::<nostr::PublicKey>()
        .map_err(|_| ProtocolValidationError("Core p tag is not a valid pubkey".into()))?;
    if recipient == event.pubkey {
        return Err(ProtocolValidationError(
            "Core p recipient must differ from the author".into(),
        ));
    }

    let d_tags: Vec<_> = event
        .tags
        .iter()
        .filter(|tag| {
            let parts = tag.as_slice();
            parts.first().map(|part| part.as_str()) == Some("d")
        })
        .collect();
    if kind == KIND_CORE_LEARNING_BUNDLE_HEAD {
        let coordinate = match d_tags.as_slice() {
            [tag] if tag.as_slice().len() == 2 => tag.as_slice()[1].as_str(),
            _ => {
                return Err(ProtocolValidationError(
                    "Core learning bundle heads require exactly one d tag".into(),
                ));
            }
        };
        Sha256Hex::try_from(coordinate).map_err(|_| {
            ProtocolValidationError(
                "Core learning bundle d tag must be a lowercase 64-hex coordinate".into(),
            )
        })?;
    } else if !d_tags.is_empty() {
        return Err(ProtocolValidationError(
            "non-addressable Core events must not carry d tags".into(),
        ));
    }

    let encrypted = matches!(
        kind,
        KIND_CORE_LEARNING_RECORD
            | KIND_CORE_LEARNING_BUNDLE_HEAD
            | KIND_CORE_CALL_CONTROL
            | KIND_CORE_TRANSCRIPT_SEGMENT
            | KIND_CORE_COPILOT_SUGGESTION
    );
    if encrypted && crate::observer::validate_syntactic_nip44_v2(&event.content).is_err() {
        return Err(ProtocolValidationError(
            "encrypted Core content must fit the NIP-44 v2 envelope".into(),
        ));
    }

    Ok(CoreEnvelope {
        channel_id,
        recipient,
        direction,
    })
}

/// Validate the serialized size of relay-readable Core JSON content.
pub fn validate_core_plaintext_content_size(content: &str) -> Result<(), ProtocolValidationError> {
    if content.len() > MAX_CORE_PLAINTEXT_CONTENT_LEN {
        return Err(ProtocolValidationError(format!(
            "Core plaintext content exceeds {MAX_CORE_PLAINTEXT_CONTENT_LEN} bytes"
        )));
    }
    Ok(())
}

/// Parse and validate relay-readable Core JSON content for its exact kind.
///
/// Encrypted Core kinds are intentionally not decrypted by the relay and are
/// accepted here after [`validate_core_envelope`] checks their NIP-44 shape.
pub fn validate_core_plaintext_content(
    event: &nostr::Event,
    now: i64,
) -> Result<(), ProtocolValidationError> {
    let kind = crate::kind::event_kind_u32(event);
    let relay_readable = matches!(
        kind,
        KIND_CORE_INSIGHT
            | KIND_CORE_INSIGHT_DISPOSITION
            | KIND_CORE_ACTION_PROPOSAL
            | KIND_CORE_ACTION_DECISION
            | KIND_CORE_ACTION_RECEIPT
    );
    if relay_readable {
        validate_core_plaintext_content_size(&event.content)?;
    }
    let parse_error = |error: serde_json::Error| ProtocolValidationError(error.to_string());
    match kind {
        KIND_CORE_INSIGHT => {
            serde_json::from_str::<InsightPayload>(&event.content).map_err(parse_error)?;
        }
        KIND_CORE_INSIGHT_DISPOSITION => {
            let payload = serde_json::from_str::<InsightDispositionPayload>(&event.content)
                .map_err(parse_error)?;
            payload.validate()?;
        }
        KIND_CORE_ACTION_PROPOSAL => {
            let payload = serde_json::from_str::<ActionProposalPayload>(&event.content)
                .map_err(parse_error)?;
            payload.validate_at(now)?;
        }
        KIND_CORE_ACTION_DECISION => {
            let payload = serde_json::from_str::<ActionDecisionPayload>(&event.content)
                .map_err(parse_error)?;
            if payload.signer.as_str() != event.pubkey.to_hex() {
                return Err(ProtocolValidationError(
                    "decision signer must equal event pubkey".into(),
                ));
            }
        }
        KIND_CORE_ACTION_RECEIPT => {
            let payload = serde_json::from_str::<ActionReceiptPayload>(&event.content)
                .map_err(parse_error)?;
            payload.validate()?;
        }
        KIND_CORE_LEARNING_RECORD
        | KIND_CORE_LEARNING_BUNDLE_HEAD
        | KIND_CORE_CALL_CONTROL
        | KIND_CORE_TRANSCRIPT_SEGMENT
        | KIND_CORE_COPILOT_SUGGESTION => {}
        _ => {
            return Err(ProtocolValidationError("event is not a Core kind".into()));
        }
    }
    Ok(())
}

/// Error returned when a parsed Core payload violates a cross-field invariant.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ProtocolValidationError(pub String);

/// A string whose length and character class are validated during deserialization.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BoundedString<const MAX: usize, const OPAQUE_ID: bool> {
    value: String,
    marker: PhantomData<()>,
}

impl<const MAX: usize, const OPAQUE_ID: bool> BoundedString<MAX, OPAQUE_ID> {
    /// Borrow the validated value.
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl<const MAX: usize, const OPAQUE_ID: bool> TryFrom<&str> for BoundedString<MAX, OPAQUE_ID> {
    type Error = ProtocolValidationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.is_empty()
            || value.len() > MAX
            || value
                .chars()
                .any(|character| character.is_control() || is_bidi_control(character))
        {
            return Err(ProtocolValidationError(format!(
                "value must contain 1..={MAX} non-control bytes"
            )));
        }
        if OPAQUE_ID
            && !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        {
            return Err(ProtocolValidationError(
                "opaque ID contains URL/path or unsupported characters".into(),
            ));
        }
        Ok(Self {
            value: value.to_owned(),
            marker: PhantomData,
        })
    }
}

const fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )
}

impl<const MAX: usize, const OPAQUE_ID: bool> Serialize for BoundedString<MAX, OPAQUE_ID> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.value)
    }
}

impl<'de, const MAX: usize, const OPAQUE_ID: bool> Deserialize<'de>
    for BoundedString<MAX, OPAQUE_ID>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value.as_str()).map_err(de::Error::custom)
    }
}

/// Provider-scoped opaque identifier; URLs and paths are structurally rejected.
pub type OpaqueId = BoundedString<256, true>;
/// Short protocol label or version stamp.
pub type ProtocolLabel = BoundedString<128, false>;
/// Human-readable protocol text with a 4 KiB ceiling.
pub type ProtocolText = BoundedString<4096, false>;

/// Integer confidence percentage in the inclusive range 0..=100.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Confidence(u8);

impl Confidence {
    /// Return the validated percentage.
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Canonical lowercase Nostr public key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LowercasePubkey(String);

impl LowercasePubkey {
    /// Borrow the canonical public-key string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for LowercasePubkey {
    type Error = ProtocolValidationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || value.parse::<nostr::PublicKey>().is_err()
        {
            return Err(ProtocolValidationError(
                "signer must be a lowercase 64-hex Nostr pubkey".into(),
            ));
        }
        Ok(Self(value.to_owned()))
    }
}

impl Serialize for LowercasePubkey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for LowercasePubkey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value.as_str()).map_err(de::Error::custom)
    }
}

/// Validated email recipient address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EmailAddress(String);

impl TryFrom<&str> for EmailAddress {
    type Error = ProtocolValidationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut parts = value.split('@');
        let valid = value.len() <= 254
            && parts.next().is_some_and(|part| !part.is_empty())
            && parts.next().is_some_and(|part| part.contains('.'))
            && parts.next().is_none()
            && !value
                .chars()
                .any(|ch| ch.is_whitespace() || ch.is_control());
        if !valid {
            return Err(ProtocolValidationError("invalid email recipient".into()));
        }
        Ok(Self(value.to_owned()))
    }
}

impl Serialize for EmailAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for EmailAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value.as_str()).map_err(de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for Confidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        if value <= 100 {
            Ok(Self(value))
        } else {
            Err(de::Error::custom("confidence must be in 0..=100"))
        }
    }
}

/// The only supported Core payload schema version.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Version1;

impl Serialize for Version1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(1)
    }
}

impl<'de> Deserialize<'de> for Version1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let version = u64::deserialize(deserializer)?;
        if version == 1 {
            Ok(Self)
        } else {
            Err(de::Error::custom(format!(
                "unsupported schema_version {version}"
            )))
        }
    }
}

/// A canonical lowercase, hyphenated UUIDv4 string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CanonicalUuidV4(Uuid);

impl CanonicalUuidV4 {
    /// Return the parsed UUID.
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl fmt::Display for CanonicalUuidV4 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.hyphenated().fmt(formatter)
    }
}

impl TryFrom<&str> for CanonicalUuidV4 {
    type Error = ProtocolValidationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let parsed = Uuid::parse_str(value)
            .map_err(|_| ProtocolValidationError("value must be a canonical UUIDv4".into()))?;
        if parsed.get_version_num() != 4 || parsed.hyphenated().to_string() != value {
            return Err(ProtocolValidationError(
                "value must be a canonical lowercase hyphenated UUIDv4".into(),
            ));
        }
        Ok(Self(parsed))
    }
}

impl Serialize for CanonicalUuidV4 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for CanonicalUuidV4 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value.as_str()).map_err(de::Error::custom)
    }
}

/// A lowercase 64-hex SHA-256 digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sha256Hex(String);

impl Sha256Hex {
    /// Borrow the canonical digest string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Sha256Hex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl TryFrom<&str> for Sha256Hex {
    type Error = ProtocolValidationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ProtocolValidationError(
                "value must be a lowercase 64-hex SHA-256 digest".into(),
            ));
        }
        Ok(Self(value.to_owned()))
    }
}

impl Serialize for Sha256Hex {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Sha256Hex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value.as_str()).map_err(de::Error::custom)
    }
}

/// Typed origin of evidence cited by a Core payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    /// Core CRM record.
    Crm,
    /// Outlook mail record.
    Outlook,
    /// Microsoft calendar record.
    Calendar,
    /// Read-only OneDrive record.
    OneDrive,
    /// Google Drive record.
    GoogleDrive,
    /// Granola meeting record.
    Granola,
    /// A Buzz event/message referenced by opaque event ID.
    BuzzEvent,
    /// Sanitized public-web research with a non-authoritative citation resolver.
    PublicWeb,
}

/// Safe citation descriptor for evidence resolution.
///
/// The resolver identifier is opaque and must be reauthorized by trusted
/// runtime code before it is exchanged for a provider link. It is never an
/// executable URL.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CitationRef {
    /// Bounded human-readable citation title.
    pub title: ProtocolLabel,
    /// Provider modification time as Unix seconds.
    pub modified_at: i64,
    /// Opaque resolver identifier; never an executable URL.
    pub resolver_id: OpaqueId,
}

/// Opaque, hashed evidence reference. Source bodies and arbitrary URLs are absent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    /// Connector/source family.
    pub source: EvidenceSource,
    /// Provider-scoped opaque record identifier.
    pub source_id: OpaqueId,
    /// SHA-256 of the exact evidence revision used.
    pub source_hash: Sha256Hex,
    /// Required non-authoritative citation for `public_web` evidence.
    pub citation: Option<CitationRef>,
}

fn deserialize_evidence<'de, D>(deserializer: D) -> Result<Vec<EvidenceRef>, D::Error>
where
    D: Deserializer<'de>,
{
    let evidence = Vec::<EvidenceRef>::deserialize(deserializer)?;
    if evidence.is_empty() || evidence.len() > 32 {
        return Err(de::Error::custom("evidence must contain 1..=32 references"));
    }
    for (index, item) in evidence.iter().enumerate() {
        if item.source == EvidenceSource::PublicWeb && item.citation.is_none() {
            return Err(de::Error::custom(
                "public_web evidence requires citation metadata",
            ));
        }
        if item
            .citation
            .as_ref()
            .is_some_and(|citation| citation.modified_at < 0)
        {
            return Err(de::Error::custom(
                "citation modified_at must be a non-negative Unix timestamp",
            ));
        }
        if evidence[..index].iter().any(|prior| {
            prior.source == item.source
                && prior.source_id == item.source_id
                && prior.source_hash == item.source_hash
        }) {
            return Err(de::Error::custom("duplicate evidence reference"));
        }
    }
    Ok(evidence)
}

fn bounded_unique_vec<'de, D, T>(
    deserializer: D,
    min: usize,
    max: usize,
    label: &str,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + PartialEq,
{
    let values = Vec::<T>::deserialize(deserializer)?;
    if values.len() < min || values.len() > max {
        return Err(de::Error::custom(format!(
            "{label} must contain {min}..={max} values"
        )));
    }
    for index in 0..values.len() {
        if values[..index].contains(&values[index]) {
            return Err(de::Error::custom(format!("duplicate {label} value")));
        }
    }
    Ok(values)
}

fn deserialize_recipient_list<'de, D>(deserializer: D) -> Result<Vec<EmailAddress>, D::Error>
where
    D: Deserializer<'de>,
{
    bounded_unique_vec(deserializer, 0, 50, "recipient list")
}

fn deserialize_draft_recipients<'de, D>(deserializer: D) -> Result<DraftRecipients, D::Error>
where
    D: Deserializer<'de>,
{
    let recipients = DraftRecipients::deserialize(deserializer)?;
    let all = recipients
        .to
        .iter()
        .chain(&recipients.cc)
        .chain(&recipients.bcc)
        .collect::<Vec<_>>();
    if all.is_empty() || all.len() > 50 {
        return Err(de::Error::custom("draft must contain 1..=50 recipients"));
    }
    if all
        .iter()
        .enumerate()
        .any(|(index, value)| all[..index].contains(value))
    {
        return Err(de::Error::custom(
            "draft recipient may appear in only one of to, cc, or bcc",
        ));
    }
    Ok(recipients)
}

fn deserialize_attachments<'de, D>(deserializer: D) -> Result<Vec<DraftAttachment>, D::Error>
where
    D: Deserializer<'de>,
{
    bounded_unique_vec(deserializer, 0, 20, "attachments")
}

fn deserialize_slides<'de, D>(deserializer: D) -> Result<Vec<ProtocolText>, D::Error>
where
    D: Deserializer<'de>,
{
    bounded_unique_vec(deserializer, 1, 100, "slides")
}

fn deserialize_sheet_values<'de, D>(deserializer: D) -> Result<Vec<Vec<ProtocolLabel>>, D::Error>
where
    D: Deserializer<'de>,
{
    let rows = Vec::<Vec<ProtocolLabel>>::deserialize(deserializer)?;
    if rows.is_empty()
        || rows.len() > 100
        || rows.iter().any(|row| row.is_empty() || row.len() > 50)
    {
        return Err(de::Error::custom(
            "sheet values require 1..=100 rows of 1..=50 cells",
        ));
    }
    Ok(rows)
}

fn deserialize_side_effects<'de, D>(deserializer: D) -> Result<Vec<ActionSideEffect>, D::Error>
where
    D: Deserializer<'de>,
{
    bounded_unique_vec(deserializer, 1, 4, "side_effects")
}

fn deserialize_operation_members<'de, D>(
    deserializer: D,
) -> Result<Vec<ExternalOperationMember>, D::Error>
where
    D: Deserializer<'de>,
{
    let members = Vec::<ExternalOperationMember>::deserialize(deserializer)?;
    if members.is_empty() || members.len() > 10 {
        return Err(de::Error::custom(
            "operation bundle must contain 1..=10 members",
        ));
    }
    for (index, member) in members.iter().enumerate() {
        if members[..index].iter().any(|prior| {
            prior.operation_id == member.operation_id
                || prior.operation_hash == member.operation_hash
                || prior.idempotency_key == member.idempotency_key
        }) {
            return Err(de::Error::custom(
                "operation bundle contains duplicate id, hash, or idempotency key",
            ));
        }
    }
    Ok(members)
}

fn deserialize_hashes<'de, D>(deserializer: D) -> Result<Vec<Sha256Hex>, D::Error>
where
    D: Deserializer<'de>,
{
    bounded_unique_vec(deserializer, 0, 32, "hashes")
}

fn deserialize_degraded_reasons<'de, D>(
    deserializer: D,
) -> Result<Vec<CallDegradedReason>, D::Error>
where
    D: Deserializer<'de>,
{
    bounded_unique_vec(deserializer, 0, 4, "degraded_reasons")
}

/// Closed CRM activity types permitted by the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrmActivityType {
    /// Telephone call.
    Call,
    /// Meeting.
    Meeting,
    /// Email interaction.
    Email,
    /// Non-destructive informational note.
    Note,
}

/// Explicit mutable contact fields; unknown/destructive fields are rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactPatch {
    /// Display name.
    pub name: Option<ProtocolLabel>,
    /// Email address.
    pub email: Option<ProtocolLabel>,
    /// Phone number.
    pub phone: Option<ProtocolLabel>,
    /// Job title.
    pub title: Option<ProtocolLabel>,
    /// Existing company relationship by opaque ID.
    pub company_id: Option<OpaqueId>,
}

impl ContactPatch {
    fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.email.is_none()
            && self.phone.is_none()
            && self.title.is_none()
            && self.company_id.is_none()
    }
}

/// Explicit mutable company fields; unknown/destructive fields are rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompanyPatch {
    /// Company name.
    pub name: Option<ProtocolLabel>,
    /// Company domain label.
    pub domain: Option<ProtocolLabel>,
    /// Company description.
    pub description: Option<ProtocolText>,
}

impl CompanyPatch {
    fn is_empty(&self) -> bool {
        self.name.is_none() && self.domain.is_none() && self.description.is_none()
    }
}

/// Closed project status values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectStatus {
    /// Active project.
    Active,
    /// Completed project.
    Completed,
    /// Paused project.
    Paused,
}

/// Explicit mutable project fields; unknown/destructive fields are rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectPatch {
    /// Project name.
    pub name: Option<ProtocolLabel>,
    /// Project description.
    pub description: Option<ProtocolText>,
    /// Project status.
    pub status: Option<ProjectStatus>,
}

impl ProjectPatch {
    fn is_empty(&self) -> bool {
        self.name.is_none() && self.description.is_none() && self.status.is_none()
    }
}

/// Positive CRM writes admitted by the frozen Month-1 protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum CrmWriteOperation {
    /// Add a note to an existing CRM record.
    AddNote {
        /// Opaque CRM record identifier.
        record_id: OpaqueId,
        /// Note body.
        body: ProtocolText,
    },
    /// Log an activity against an existing CRM record.
    LogActivity {
        /// Opaque CRM record identifier.
        record_id: OpaqueId,
        /// Constrained CRM activity type.
        activity_type: CrmActivityType,
        /// Activity body.
        body: ProtocolText,
    },
    /// Create a contact from explicit string fields.
    CreateContact {
        /// Connector-supported contact fields.
        fields: ContactPatch,
    },
    /// Update an existing contact after an expected-version re-read.
    UpdateContact {
        /// Opaque contact identifier.
        contact_id: OpaqueId,
        /// Expected remote version.
        expected_remote_version: ProtocolLabel,
        /// Connector-supported contact fields.
        fields: ContactPatch,
    },
    /// Create a company from explicit string fields.
    CreateCompany {
        /// Connector-supported company fields.
        fields: CompanyPatch,
    },
    /// Update an existing company after an expected-version re-read.
    UpdateCompany {
        /// Opaque company identifier.
        company_id: OpaqueId,
        /// Expected remote version.
        expected_remote_version: ProtocolLabel,
        /// Connector-supported company fields.
        fields: CompanyPatch,
    },
    /// Create a manual CRM task.
    CreateManualTask {
        /// Task subject.
        subject: ProtocolLabel,
        /// Unix-seconds due time.
        due_at: i64,
    },
    /// Update a manual CRM task after an expected-version re-read.
    UpdateManualTask {
        /// Opaque task identifier.
        task_id: OpaqueId,
        /// Expected remote version.
        expected_remote_version: ProtocolLabel,
        /// Replacement subject.
        subject: ProtocolLabel,
        /// Replacement Unix-seconds due time.
        due_at: i64,
    },
    /// Complete a manual CRM task after an expected-version re-read.
    CompleteManualTask {
        /// Opaque task identifier.
        task_id: OpaqueId,
        /// Expected remote version.
        expected_remote_version: ProtocolLabel,
    },
    /// Create a CRM project from explicit string fields.
    CreateProject {
        /// Connector-supported project fields.
        fields: ProjectPatch,
    },
    /// Update a CRM project after an expected-version re-read.
    UpdateProject {
        /// Opaque project identifier.
        project_id: OpaqueId,
        /// Expected remote version.
        expected_remote_version: ProtocolLabel,
        /// Connector-supported project fields.
        fields: ProjectPatch,
    },
    /// Add a tag to an existing CRM record.
    AddTag {
        /// Opaque CRM record identifier.
        record_id: OpaqueId,
        /// Tag to add.
        tag: ProtocolLabel,
    },
    /// Link an existing Granola record to a CRM record.
    LinkGranolaRecord {
        /// Opaque CRM record identifier.
        record_id: OpaqueId,
        /// Opaque Granola record identifier.
        granola_record_id: OpaqueId,
    },
}

/// Positive Outlook draft writes admitted by the frozen Month-1 protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftRecipients {
    /// Primary recipients.
    #[serde(deserialize_with = "deserialize_recipient_list")]
    pub to: Vec<EmailAddress>,
    /// Carbon-copy recipients.
    #[serde(deserialize_with = "deserialize_recipient_list")]
    pub cc: Vec<EmailAddress>,
    /// Blind-carbon-copy recipients.
    #[serde(deserialize_with = "deserialize_recipient_list")]
    pub bcc: Vec<EmailAddress>,
}

/// Positive Outlook draft writes admitted by the frozen Month-1 protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DraftAttachment {
    /// Existing local/provider file reference.
    ExistingFile {
        /// Opaque attachment identifier.
        attachment_id: OpaqueId,
    },
    /// Existing Drive link reference.
    DriveLink {
        /// Opaque Drive item identifier.
        drive_item_id: OpaqueId,
    },
}

/// Positive Outlook draft writes admitted by the frozen Month-1 protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum OutlookWriteOperation {
    /// Create an unsent draft.
    CreateDraft {
        /// Exact draft recipients.
        #[serde(deserialize_with = "deserialize_draft_recipients")]
        recipients: DraftRecipients,
        /// Draft subject.
        subject: ProtocolLabel,
        /// Draft body.
        body: ProtocolText,
        /// Exact existing attachments or Drive links.
        #[serde(deserialize_with = "deserialize_attachments")]
        attachments: Vec<DraftAttachment>,
    },
    /// Update a draft that was created and remains owned by Buzz.
    UpdateBuzzOwnedDraft {
        /// Opaque draft identifier.
        draft_id: OpaqueId,
        /// Expected remote version.
        expected_remote_version: ProtocolLabel,
        /// Exact replacement recipients.
        #[serde(deserialize_with = "deserialize_draft_recipients")]
        recipients: DraftRecipients,
        /// Replacement subject.
        subject: ProtocolLabel,
        /// Replacement body.
        body: ProtocolText,
        /// Exact replacement attachment set.
        #[serde(deserialize_with = "deserialize_attachments")]
        attachments: Vec<DraftAttachment>,
    },
    /// Attach an already-existing file to a Buzz-owned draft.
    AttachExistingFile {
        /// Opaque draft identifier.
        draft_id: OpaqueId,
        /// Expected remote version.
        expected_remote_version: ProtocolLabel,
        /// Opaque existing attachment identifier.
        attachment_id: OpaqueId,
    },
    /// Attach a stable existing Drive link to a Buzz-owned draft.
    AttachDriveLink {
        /// Opaque draft identifier.
        draft_id: OpaqueId,
        /// Expected remote version.
        expected_remote_version: ProtocolLabel,
        /// Opaque Drive item identifier.
        drive_item_id: OpaqueId,
    },
}

/// Positive Google native-file writes admitted by the frozen Month-1 protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum GoogleWriteOperation {
    /// Create a Google Doc.
    CreateDoc {
        /// Document title.
        title: ProtocolLabel,
        /// Initial document text.
        text: ProtocolText,
    },
    /// Create a Google Sheet.
    CreateSheet {
        /// Spreadsheet title.
        title: ProtocolLabel,
    },
    /// Create a simple Google Slides presentation.
    CreateSimpleSlides {
        /// Presentation title.
        title: ProtocolLabel,
        /// Plain-text slide bodies in order.
        #[serde(deserialize_with = "deserialize_slides")]
        slides: Vec<ProtocolText>,
    },
    /// Replace the editable body of a Google Doc.
    EditDoc {
        /// Opaque document identifier.
        document_id: OpaqueId,
        /// Expected remote version.
        expected_remote_version: ProtocolLabel,
        /// Replacement text.
        text: ProtocolText,
    },
    /// Edit an explicit A1 range in a Google Sheet.
    EditSheetRange {
        /// Opaque spreadsheet identifier.
        spreadsheet_id: OpaqueId,
        /// Explicit A1 range.
        range: ProtocolLabel,
        /// Expected remote version.
        expected_remote_version: ProtocolLabel,
        /// Replacement cell strings.
        #[serde(deserialize_with = "deserialize_sheet_values")]
        values: Vec<Vec<ProtocolLabel>>,
    },
    /// Replace plain text in a simple Slides presentation.
    ReplaceSlidesText {
        /// Opaque presentation identifier.
        presentation_id: OpaqueId,
        /// Expected remote version.
        expected_remote_version: ProtocolLabel,
        /// Literal text to find.
        find: ProtocolLabel,
        /// Replacement text.
        replace: ProtocolLabel,
    },
}

/// Complete positive write allowlist. No generic or provider escape hatch exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "provider",
    content = "operation",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum PositiveWriteOperation {
    /// Core CRM write.
    Crm(CrmWriteOperation),
    /// Outlook draft-only write.
    Outlook(OutlookWriteOperation),
    /// Google native-file write.
    Google(GoogleWriteOperation),
}

struct OperationShape<'a> {
    provider: ActionProvider,
    create: bool,
    target_id: Option<&'a str>,
    version: Option<&'a str>,
    side_effect: ActionSideEffect,
    patch_nonempty: bool,
}

impl PositiveWriteOperation {
    fn shape(&self) -> OperationShape<'_> {
        match self {
            Self::Crm(operation) => match operation {
                CrmWriteOperation::CreateContact { fields } => OperationShape {
                    provider: ActionProvider::Crm,
                    create: true,
                    target_id: None,
                    version: None,
                    side_effect: ActionSideEffect::CreatesRecord,
                    patch_nonempty: !fields.is_empty(),
                },
                CrmWriteOperation::CreateCompany { fields } => OperationShape {
                    provider: ActionProvider::Crm,
                    create: true,
                    target_id: None,
                    version: None,
                    side_effect: ActionSideEffect::CreatesRecord,
                    patch_nonempty: !fields.is_empty(),
                },
                CrmWriteOperation::CreateManualTask { .. } => OperationShape {
                    provider: ActionProvider::Crm,
                    create: true,
                    target_id: None,
                    version: None,
                    side_effect: ActionSideEffect::CreatesRecord,
                    patch_nonempty: true,
                },
                CrmWriteOperation::CreateProject { fields } => OperationShape {
                    provider: ActionProvider::Crm,
                    create: true,
                    target_id: None,
                    version: None,
                    side_effect: ActionSideEffect::CreatesRecord,
                    patch_nonempty: !fields.is_empty(),
                },
                CrmWriteOperation::UpdateContact {
                    contact_id,
                    expected_remote_version,
                    fields,
                } => OperationShape {
                    provider: ActionProvider::Crm,
                    create: false,
                    target_id: Some(contact_id.as_str()),
                    version: Some(expected_remote_version.as_str()),
                    side_effect: ActionSideEffect::UpdatesRecord,
                    patch_nonempty: !fields.is_empty(),
                },
                CrmWriteOperation::UpdateCompany {
                    company_id,
                    expected_remote_version,
                    fields,
                } => OperationShape {
                    provider: ActionProvider::Crm,
                    create: false,
                    target_id: Some(company_id.as_str()),
                    version: Some(expected_remote_version.as_str()),
                    side_effect: ActionSideEffect::UpdatesRecord,
                    patch_nonempty: !fields.is_empty(),
                },
                CrmWriteOperation::UpdateManualTask {
                    task_id,
                    expected_remote_version,
                    ..
                }
                | CrmWriteOperation::CompleteManualTask {
                    task_id,
                    expected_remote_version,
                } => OperationShape {
                    provider: ActionProvider::Crm,
                    create: false,
                    target_id: Some(task_id.as_str()),
                    version: Some(expected_remote_version.as_str()),
                    side_effect: ActionSideEffect::UpdatesRecord,
                    patch_nonempty: true,
                },
                CrmWriteOperation::UpdateProject {
                    project_id,
                    expected_remote_version,
                    fields,
                } => OperationShape {
                    provider: ActionProvider::Crm,
                    create: false,
                    target_id: Some(project_id.as_str()),
                    version: Some(expected_remote_version.as_str()),
                    side_effect: ActionSideEffect::UpdatesRecord,
                    patch_nonempty: !fields.is_empty(),
                },
                CrmWriteOperation::AddNote { record_id, .. }
                | CrmWriteOperation::LogActivity { record_id, .. }
                | CrmWriteOperation::AddTag { record_id, .. }
                | CrmWriteOperation::LinkGranolaRecord { record_id, .. } => OperationShape {
                    provider: ActionProvider::Crm,
                    create: false,
                    target_id: Some(record_id.as_str()),
                    version: None,
                    side_effect: ActionSideEffect::UpdatesRecord,
                    patch_nonempty: true,
                },
            },
            Self::Outlook(operation) => match operation {
                OutlookWriteOperation::CreateDraft { .. } => OperationShape {
                    provider: ActionProvider::Outlook,
                    create: true,
                    target_id: None,
                    version: None,
                    side_effect: ActionSideEffect::CreatesDraft,
                    patch_nonempty: true,
                },
                OutlookWriteOperation::UpdateBuzzOwnedDraft {
                    draft_id,
                    expected_remote_version,
                    ..
                } => OperationShape {
                    provider: ActionProvider::Outlook,
                    create: false,
                    target_id: Some(draft_id.as_str()),
                    version: Some(expected_remote_version.as_str()),
                    side_effect: ActionSideEffect::UpdatesRecord,
                    patch_nonempty: true,
                },
                OutlookWriteOperation::AttachExistingFile {
                    draft_id,
                    expected_remote_version,
                    ..
                }
                | OutlookWriteOperation::AttachDriveLink {
                    draft_id,
                    expected_remote_version,
                    ..
                } => OperationShape {
                    provider: ActionProvider::Outlook,
                    create: false,
                    target_id: Some(draft_id.as_str()),
                    version: Some(expected_remote_version.as_str()),
                    side_effect: ActionSideEffect::AttachesReference,
                    patch_nonempty: true,
                },
            },
            Self::Google(operation) => match operation {
                GoogleWriteOperation::CreateDoc { .. }
                | GoogleWriteOperation::CreateSheet { .. }
                | GoogleWriteOperation::CreateSimpleSlides { .. } => OperationShape {
                    provider: ActionProvider::Google,
                    create: true,
                    target_id: None,
                    version: None,
                    side_effect: ActionSideEffect::CreatesRecord,
                    patch_nonempty: true,
                },
                GoogleWriteOperation::EditDoc {
                    document_id,
                    expected_remote_version,
                    ..
                } => OperationShape {
                    provider: ActionProvider::Google,
                    create: false,
                    target_id: Some(document_id.as_str()),
                    version: Some(expected_remote_version.as_str()),
                    side_effect: ActionSideEffect::UpdatesRecord,
                    patch_nonempty: true,
                },
                GoogleWriteOperation::EditSheetRange {
                    spreadsheet_id,
                    expected_remote_version,
                    ..
                } => OperationShape {
                    provider: ActionProvider::Google,
                    create: false,
                    target_id: Some(spreadsheet_id.as_str()),
                    version: Some(expected_remote_version.as_str()),
                    side_effect: ActionSideEffect::UpdatesRecord,
                    patch_nonempty: true,
                },
                GoogleWriteOperation::ReplaceSlidesText {
                    presentation_id,
                    expected_remote_version,
                    ..
                } => OperationShape {
                    provider: ActionProvider::Google,
                    create: false,
                    target_id: Some(presentation_id.as_str()),
                    version: Some(expected_remote_version.as_str()),
                    side_effect: ActionSideEffect::UpdatesRecord,
                    patch_nonempty: true,
                },
            },
        }
    }
}

/// Relay-readable action proposal payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionProposalPayload {
    /// Payload schema version; only integer `1` is accepted.
    pub schema_version: Version1,
    /// Proposal identifier.
    pub proposal_id: CanonicalUuidV4,
    /// One-time approval nonce.
    pub nonce: CanonicalUuidV4,
    /// SHA-256 over the canonical full operation bytes.
    pub operation_hash: Sha256Hex,
    /// Unix seconds at proposal creation.
    pub proposed_at: i64,
    /// Unix seconds at proposal expiry.
    pub expires_at: i64,
    /// Explicitly non-atomic bundle execution semantics.
    pub bundle_semantics: BundleSemantics,
    /// Independently hashed and validated operation members.
    #[serde(deserialize_with = "deserialize_operation_members")]
    pub operations: Vec<ExternalOperationMember>,
    /// Typed evidence supporting the proposal.
    #[serde(deserialize_with = "deserialize_evidence")]
    pub evidence: Vec<EvidenceRef>,
}

/// Execution semantics of a multi-operation proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleSemantics {
    /// Each operation is approved together but executes independently; there is no cross-provider atomicity.
    IndependentOperations,
}

/// One independently executable and reconcilable proposal member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalOperationMember {
    /// Stable member identifier.
    pub operation_id: CanonicalUuidV4,
    /// Hash of this member's exact canonical operation bytes.
    pub operation_hash: Sha256Hex,
    /// Connector idempotency key dedicated to this member.
    pub idempotency_key: CanonicalUuidV4,
    /// Exact connector account and target object.
    pub target: ActionTarget,
    /// Canonical pre-write state, absent only for creates.
    pub before: Option<ActionState>,
    /// Canonical intended post-write state.
    pub after: ActionState,
    /// Remote version that execution must re-read and match.
    pub expected_remote_version: Option<ProtocolLabel>,
    /// Closed list of declared effects.
    #[serde(deserialize_with = "deserialize_side_effects")]
    pub side_effects: Vec<ActionSideEffect>,
    /// The exact positive write requested.
    pub operation: PositiveWriteOperation,
}

/// Connector family for an executable external write target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionProvider {
    /// Core CRM MCP.
    Crm,
    /// Outlook draft surface.
    Outlook,
    /// Google native content surface.
    Google,
}

/// Exact account/object target of an external write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionTarget {
    /// Connector provider.
    pub provider: ActionProvider,
    /// Opaque configured connector-account identifier.
    pub account_id: OpaqueId,
    /// Approved remote scope or container (CRM workspace, mailbox, or Drive folder).
    pub scope_id: OpaqueId,
    /// Opaque remote object identifier; absent only for create operations.
    pub object_id: Option<OpaqueId>,
}

/// Canonical before/after state bound into an operation hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionState {
    /// Bounded RFC-8785-style canonical JSON bytes represented as text.
    pub canonical_value: ProtocolText,
    /// SHA-256 of `canonical_value`.
    pub value_hash: Sha256Hex,
}

/// Closed declared side effects for positive writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionSideEffect {
    /// Creates a new remote record.
    CreatesRecord,
    /// Updates an existing remote record.
    UpdatesRecord,
    /// Creates an unsent Outlook draft.
    CreatesDraft,
    /// Attaches an existing reference to a draft.
    AttachesReference,
}

impl ActionProposalPayload {
    /// Validate proposal timing against a supplied relay wall-clock time.
    pub fn validate_at(&self, now: i64) -> Result<(), ProtocolValidationError> {
        if self.proposed_at >= self.expires_at {
            return Err(ProtocolValidationError(
                "proposed_at must be before expires_at".into(),
            ));
        }
        if self
            .expires_at
            .checked_sub(self.proposed_at)
            .is_none_or(|lifetime| lifetime > MAX_PROPOSAL_LIFETIME_SECONDS)
        {
            return Err(ProtocolValidationError(
                "proposal lifetime exceeds 900 seconds".into(),
            ));
        }
        if self.expires_at <= now {
            return Err(ProtocolValidationError(
                "proposal is already expired".into(),
            ));
        }
        if self.proposed_at > now.saturating_add(MAX_PROPOSAL_FUTURE_SKEW_SECONDS) {
            return Err(ProtocolValidationError(
                "proposal is implausibly future-dated".into(),
            ));
        }
        for operation in &self.operations {
            operation.validate()?;
        }
        Ok(())
    }
}

impl ExternalOperationMember {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        let shape = self.operation.shape();
        if self.target.provider != shape.provider {
            return Err(ProtocolValidationError(
                "operation provider does not match target provider".into(),
            ));
        }
        if !shape.patch_nonempty {
            return Err(ProtocolValidationError(
                "create/update patch must not be empty".into(),
            ));
        }
        if shape.create {
            if self.target.object_id.is_some()
                || self.before.is_some()
                || self.expected_remote_version.is_some()
            {
                return Err(ProtocolValidationError(
                    "create operation must not bind object_id, before, or expected version".into(),
                ));
            }
        } else {
            let target_id = self.target.object_id.as_ref().ok_or_else(|| {
                ProtocolValidationError("update operation requires target object_id".into())
            })?;
            if self.before.is_none() || self.expected_remote_version.is_none() {
                return Err(ProtocolValidationError(
                    "update operation requires before state and expected version".into(),
                ));
            }
            if shape.target_id.is_some_and(|id| id != target_id.as_str()) {
                return Err(ProtocolValidationError(
                    "operation object ID does not match target object ID".into(),
                ));
            }
        }
        if let Some(operation_version) = shape.version {
            if self
                .expected_remote_version
                .as_ref()
                .is_none_or(|version| version.as_str() != operation_version)
            {
                return Err(ProtocolValidationError(
                    "operation expected version does not match proposal".into(),
                ));
            }
        }
        if self.side_effects.as_slice() != [shape.side_effect] {
            return Err(ProtocolValidationError(
                "declared side effects do not match operation".into(),
            ));
        }
        Ok(())
    }
}

/// Priority assigned to a proactive assistant insight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InsightPriority {
    /// Low-priority context.
    Low,
    /// Normal-priority context.
    Normal,
    /// High-priority follow-up.
    High,
    /// Time-critical item.
    Urgent,
}

/// Frozen proactive-insight category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InsightCategory {
    /// Commitment or deadline movement.
    CommitmentDeadline,
    /// Deal or client movement.
    DealMovement,
    /// Meeting movement or preparation.
    MeetingMovement,
    /// Relationship or buyer opportunity.
    RelationshipOpportunity,
}

/// Freshness bucket for evidence behind an insight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InsightFreshness {
    /// Event observed live.
    Realtime,
    /// Event observed during the current local day.
    SameDay,
    /// Event remains useful but is older than the current day.
    Recent,
}

/// Optional safe draft included with an insight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InsightDraft {
    /// Unsent Outlook draft text.
    OutlookDraft {
        /// Draft subject.
        subject: ProtocolLabel,
        /// Draft body.
        body: ProtocolText,
    },
    /// CRM note draft text.
    CrmNote {
        /// Note body.
        body: ProtocolText,
    },
    /// Google Doc draft text.
    GoogleDoc {
        /// Document title.
        title: ProtocolLabel,
        /// Document body.
        body: ProtocolText,
    },
}

/// Relay-readable proactive assistant insight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InsightPayload {
    /// Payload schema version.
    pub schema_version: Version1,
    /// Stable insight identifier.
    pub insight_id: CanonicalUuidV4,
    /// Frozen insight category.
    pub category: InsightCategory,
    /// Display/ranking priority.
    pub priority: InsightPriority,
    /// What changed.
    pub change: ProtocolText,
    /// Why the change matters to the owner.
    pub why_it_matters: ProtocolText,
    /// Typed evidence references.
    #[serde(deserialize_with = "deserialize_evidence")]
    pub evidence: Vec<EvidenceRef>,
    /// Model/system confidence percentage.
    pub confidence: Confidence,
    /// Evidence freshness bucket.
    pub freshness: InsightFreshness,
    /// Positive recommendation.
    pub recommendation: ProtocolText,
    /// Optional safe draft; never an executed write.
    pub draft: Option<InsightDraft>,
    /// Deterministic deduplication hash.
    pub dedupe_key: Sha256Hex,
    /// Unix-seconds creation time.
    pub created_at: i64,
    /// Immutable base safety-policy version.
    pub safety_policy_version: ProtocolLabel,
    /// Persona version.
    pub persona_version: ProtocolLabel,
    /// Firm bundle version.
    pub firm_version: ProtocolLabel,
    /// Personal bundle version.
    pub personal_version: ProtocolLabel,
    /// Model version.
    pub model_version: ProtocolLabel,
}

/// Owner disposition over a proactive insight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InsightDisposition {
    /// Recommended follow-up is complete.
    Done,
    /// Insight should be shown later.
    Snoozed,
    /// The owner had already handled it.
    AlreadyHandled,
    /// Insight was not relevant.
    NotRelevant,
    /// Evidence was attached to the wrong relationship or deal context.
    WrongContext,
    /// Insight surfaced information that should remain suppressed.
    TooSensitive,
    /// Recommendation quality was unacceptable.
    BadRecommendation,
}

/// Relay-readable owner disposition payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InsightDispositionPayload {
    /// Payload schema version.
    pub schema_version: Version1,
    /// Stable disposition identifier.
    pub disposition_id: CanonicalUuidV4,
    /// Insight being dispositioned.
    pub insight_id: CanonicalUuidV4,
    /// Exact disposition.
    pub disposition: InsightDisposition,
    /// Bounded owner rationale.
    pub reason: ProtocolText,
    /// Optional corrected context for learning feedback.
    pub correction: Option<DispositionCorrection>,
    /// Required resume time only for `snoozed`.
    pub resume_at: Option<i64>,
    /// Unix-seconds decision time.
    pub occurred_at: i64,
}

/// Bounded correction attached to an owner disposition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispositionCorrection {
    /// Corrected relationship/deal context.
    pub context: ProtocolText,
    /// Optional replacement evidence reference.
    pub evidence: Option<EvidenceRef>,
}

impl InsightDispositionPayload {
    /// Validate disposition-specific resume semantics.
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        match (self.disposition, self.resume_at) {
            (InsightDisposition::Snoozed, Some(resume))
                if resume > self.occurred_at
                    && resume
                        .checked_sub(self.occurred_at)
                        .is_some_and(|window| window <= MAX_SNOOZE_SECONDS) =>
            {
                Ok(())
            }
            (InsightDisposition::Snoozed, _) => Err(ProtocolValidationError(
                "snoozed disposition requires resume_at within 30 days".into(),
            )),
            (_, None) => Ok(()),
            (_, Some(_)) => Err(ProtocolValidationError(
                "resume_at is only valid for snoozed disposition".into(),
            )),
        }
    }
}

/// The only decisions that can authorize or deny an external action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionDecision {
    /// Approve the exact bound operation hash.
    Approve,
    /// Deny the exact bound operation hash.
    Deny,
}

/// Relay-readable signed action decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionDecisionPayload {
    /// Payload schema version.
    pub schema_version: Version1,
    /// Stable decision identifier.
    pub decision_id: CanonicalUuidV4,
    /// Proposal being decided.
    pub proposal_id: CanonicalUuidV4,
    /// Exact one-time proposal nonce.
    pub nonce: CanonicalUuidV4,
    /// Full canonical operation hash.
    pub operation_hash: Sha256Hex,
    /// Exact approve-or-deny choice.
    pub decision: ActionDecision,
    /// Owner signer bound redundantly inside the signed payload.
    pub signer: LowercasePubkey,
    /// Unix-seconds decision time.
    pub decided_at: i64,
}

/// Final broker outcome represented by an action receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionOutcome {
    /// Connector confirmed success.
    Succeeded,
    /// Connector confirmed failure.
    Failed,
    /// Remote outcome is ambiguous and requires reconciliation.
    ReconciliationRequired,
}

/// Relay-readable action receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionReceiptPayload {
    /// Payload schema version.
    pub schema_version: Version1,
    /// Stable receipt identifier.
    pub receipt_id: CanonicalUuidV4,
    /// Proposal that was executed or refused.
    pub proposal_id: CanonicalUuidV4,
    /// Signed decision that controlled execution.
    pub decision_id: CanonicalUuidV4,
    /// Full canonical operation hash.
    pub operation_hash: Sha256Hex,
    /// Ordered results corresponding one-for-one with proposal members.
    #[serde(deserialize_with = "deserialize_receipt_results")]
    pub results: Vec<ActionReceiptMember>,
    /// Unix-seconds outcome time.
    pub occurred_at: i64,
}

impl ActionReceiptPayload {
    /// Validate outcome, remote-result, and reconciliation consistency.
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        for result in &self.results {
            result.validate()?;
        }
        Ok(())
    }
}

/// Outcome of one ordered operation in a proposal bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionReceiptMember {
    /// Proposal member identifier.
    pub operation_id: CanonicalUuidV4,
    /// Proposal member hash.
    pub operation_hash: Sha256Hex,
    /// Connector idempotency key used for this exact member.
    pub idempotency_key: CanonicalUuidV4,
    /// Final or reconciliation outcome.
    pub outcome: ActionOutcome,
    /// Opaque external result identifier.
    pub external_result_id: Option<OpaqueId>,
    /// External result version after the attempt.
    pub external_result_version: Option<ProtocolLabel>,
    /// Typed reconciliation posture.
    pub reconciliation_status: ReconciliationStatus,
}

impl ActionReceiptMember {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        match (self.outcome, self.reconciliation_status) {
            (ActionOutcome::Succeeded, ReconciliationStatus::NotRequired)
            | (ActionOutcome::Succeeded, ReconciliationStatus::Reconciled) => {
                if self.external_result_id.is_some() && self.external_result_version.is_some() {
                    Ok(())
                } else {
                    Err(ProtocolValidationError(
                        "successful receipt requires external result id and version".into(),
                    ))
                }
            }
            (ActionOutcome::Failed, ReconciliationStatus::NotRequired) => Ok(()),
            (ActionOutcome::ReconciliationRequired, ReconciliationStatus::Pending)
            | (ActionOutcome::ReconciliationRequired, ReconciliationStatus::ManualReview) => Ok(()),
            _ => Err(ProtocolValidationError(
                "receipt outcome and reconciliation status are inconsistent".into(),
            )),
        }
    }
}

fn deserialize_receipt_results<'de, D>(
    deserializer: D,
) -> Result<Vec<ActionReceiptMember>, D::Error>
where
    D: Deserializer<'de>,
{
    let results = Vec::<ActionReceiptMember>::deserialize(deserializer)?;
    if results.is_empty() || results.len() > 10 {
        return Err(de::Error::custom("receipt must contain 1..=10 results"));
    }
    for (index, result) in results.iter().enumerate() {
        if results[..index].iter().any(|prior| {
            prior.operation_id == result.operation_id
                || prior.operation_hash == result.operation_hash
                || prior.idempotency_key == result.idempotency_key
        }) {
            return Err(de::Error::custom(
                "receipt contains duplicate id, hash, or idempotency key",
            ));
        }
    }
    Ok(results)
}

/// Reconciliation state for an external action receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationStatus {
    /// Connector result was definitive.
    NotRequired,
    /// Outcome is ambiguous and awaiting re-read.
    Pending,
    /// A subsequent re-read reconciled the outcome.
    Reconciled,
    /// Human review is required.
    ManualReview,
}

/// Decrypted append-only learning record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearningRecordPayload {
    /// Payload schema version.
    pub schema_version: Version1,
    /// Stable record identifier.
    pub record_id: CanonicalUuidV4,
    /// Personal or sanitized-firm layer.
    pub layer: LearningLayer,
    /// Closed learning domain.
    pub domain: LearningDomain,
    /// Monotonic domain revision.
    pub revision: u64,
    /// Hash of this exact record.
    pub record_hash: Sha256Hex,
    /// Typed state transition after decryption.
    pub record: LearningRecordBody,
    /// Unix-seconds record time.
    pub created_at: i64,
    /// Hash-only evidence references used by evaluation.
    #[serde(deserialize_with = "deserialize_hashes")]
    pub evidence_hashes: Vec<Sha256Hex>,
}

/// Governed learning layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LearningLayer {
    /// Owner-private learning.
    Personal,
    /// Firm-wide learning after mandatory sanitization.
    SanitizedFirm,
}

impl LearningLayer {
    const fn coordinate_label(self) -> &'static [u8] {
        match self {
            Self::Personal => b"personal",
            Self::SanitizedFirm => b"sanitized_firm",
        }
    }
}

/// Closed domains in which governed learning may operate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LearningDomain {
    /// Ranking inside an immutable policy tier.
    RankingWithinPolicyTier,
    /// Timing inside the configured feed window.
    TimingWithinAllowedFeedWindow,
    /// Card and presentation preferences.
    CardPresentationPreference,
    /// Writing-style traits.
    WritingStyleTraits,
    /// Relationship-priority hints.
    RelationshipPriorityHints,
    /// Source-quality weights.
    SourceQualityWeights,
    /// Buyer-selection heuristics.
    BuyerSelectionHeuristics,
    /// Research heuristics.
    ResearchHeuristics,
    /// Bounded workflow ordering.
    BoundedWorkflowOrdering,
}

impl LearningDomain {
    const fn coordinate_label(self) -> &'static [u8] {
        match self {
            Self::RankingWithinPolicyTier => b"ranking_within_policy_tier",
            Self::TimingWithinAllowedFeedWindow => b"timing_within_allowed_feed_window",
            Self::CardPresentationPreference => b"card_presentation_preference",
            Self::WritingStyleTraits => b"writing_style_traits",
            Self::RelationshipPriorityHints => b"relationship_priority_hints",
            Self::SourceQualityWeights => b"source_quality_weights",
            Self::BuyerSelectionHeuristics => b"buyer_selection_heuristics",
            Self::ResearchHeuristics => b"research_heuristics",
            Self::BoundedWorkflowOrdering => b"bounded_workflow_ordering",
        }
    }
}

/// Derive the canonical private coordinate for one governed learning bundle.
///
/// The coordinate is
/// `HMAC-SHA256(K_c, domain-separator || 0x00 || layer || 0x00 || domain)`.
/// The NIP-44 conversation key makes the result identical for both members of
/// the owner-agent pair while preventing unrelated pairs from linking bundles.
pub fn learning_bundle_coordinate(
    conversation_key: &ConversationKey,
    layer: LearningLayer,
    domain: LearningDomain,
) -> Sha256Hex {
    let digest = crate::engram::coordinate_hmac(
        conversation_key,
        CORE_LEARNING_BUNDLE_COORDINATE_DOMAIN,
        &[layer.coordinate_label(), domain.coordinate_label()],
    );
    Sha256Hex(hex::encode(digest))
}

/// Closed candidate evaluation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LearningEvaluationOutcome {
    /// Candidate passed evaluation.
    Passed,
    /// Candidate failed evaluation.
    Failed,
    /// Candidate requires more evidence.
    NeedsEvidence,
}

/// Closed quarantine reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LearningQuarantineReason {
    /// Candidate may contain MNPI.
    SensitiveContent,
    /// Candidate attempted to affect policy or permission state.
    PolicyBoundary,
    /// Candidate contains prohibited entity-specific firm data.
    FirmSanitization,
    /// Candidate failed a quality gate.
    QualityGate,
}

/// Typed append-only governed-learning transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LearningRecordBody {
    /// A bounded behavioral signal was observed.
    Signal {
        /// Signal summary.
        signal: ProtocolText,
        /// Exact evidence hash.
        evidence_hash: Sha256Hex,
    },
    /// A candidate learning was proposed from a signal.
    Candidate {
        /// Candidate content.
        candidate: ProtocolText,
        /// Source signal hash.
        source_signal_hash: Sha256Hex,
    },
    /// A candidate was evaluated.
    Evaluation {
        /// Candidate hash.
        candidate_hash: Sha256Hex,
        /// Evaluation score.
        score: Confidence,
        /// Closed evaluation outcome.
        outcome: LearningEvaluationOutcome,
    },
    /// A verified bundle was activated.
    Activation {
        /// Activated bundle hash.
        bundle_hash: Sha256Hex,
    },
    /// An active bundle was rolled back.
    Rollback {
        /// Bundle hash being replaced.
        from_bundle_hash: Sha256Hex,
        /// Bundle hash restored.
        to_bundle_hash: Sha256Hex,
        /// Bounded rollback reason.
        reason: ProtocolLabel,
    },
    /// A candidate was quarantined.
    Quarantine {
        /// Candidate hash.
        candidate_hash: Sha256Hex,
        /// Closed quarantine reason.
        reason: LearningQuarantineReason,
    },
}

/// Decrypted active learning bundle head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearningBundleHeadPayload {
    /// Payload schema version.
    pub schema_version: Version1,
    /// Personal or sanitized-firm layer.
    pub layer: LearningLayer,
    /// Closed learning domain.
    pub domain: LearningDomain,
    /// Monotonic active revision.
    pub revision: u64,
    /// Hash of the exact active encrypted bundle.
    pub bundle_hash: Sha256Hex,
    /// Immutable base safety-policy version.
    pub safety_policy_version: ProtocolLabel,
    /// Persona version used during evaluation.
    pub persona_version: ProtocolLabel,
    /// Firm bundle version.
    pub firm_version: ProtocolLabel,
    /// Personal bundle version.
    pub personal_version: ProtocolLabel,
    /// Model version used during evaluation.
    pub model_version: ProtocolLabel,
    /// Unix-seconds activation time.
    pub activated_at: i64,
}

/// Encrypted call-control command after decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallCommand {
    /// Start a consented call session.
    Start,
    /// Stop a call session.
    Stop,
    /// Record explicit consent.
    ConsentGranted,
    /// Revoke consent and stop capture.
    ConsentRevoked,
    /// Keep an active in-memory session alive.
    Heartbeat,
}

/// Decrypted ephemeral call-control payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallControlPayload {
    /// Payload schema version.
    pub schema_version: Version1,
    /// Stable call identifier.
    pub call_id: CanonicalUuidV4,
    /// Exact control command.
    pub command: CallCommand,
    /// Current in-memory call session state.
    pub session_state: CallSessionState,
    /// Health of both local audio sources.
    pub source_health: CallSourceHealth,
    /// Closed degraded-mode reasons.
    #[serde(deserialize_with = "deserialize_degraded_reasons")]
    pub degraded_reasons: Vec<CallDegradedReason>,
    /// Strictly increasing per-call sequence.
    pub sequence: u64,
    /// Optional typed meeting context.
    pub meeting_context: Option<MeetingContext>,
    /// Unix-seconds command time.
    pub occurred_at: i64,
}

/// In-memory live-call session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallSessionState {
    /// Session is starting.
    Starting,
    /// Session is active.
    Active,
    /// Session is stopping.
    Stopping,
    /// Session ended and must be purged.
    Ended,
}

/// Health of one local audio source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AudioSourceHealth {
    /// Source is producing usable audio.
    Healthy,
    /// Source is available with reduced quality.
    Degraded,
    /// Source is unavailable.
    Unavailable,
}

/// Health of separately captured microphone and selected-output sources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallSourceHealth {
    /// Microphone endpoint health.
    pub microphone: AudioSourceHealth,
    /// Selected output endpoint health.
    pub output: AudioSourceHealth,
}

/// Closed live-call degraded reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallDegradedReason {
    /// Microphone endpoint is silent.
    MicrophoneSilent,
    /// Selected output endpoint is silent.
    OutputSilent,
    /// Local transcription is behind realtime.
    TranscriptionLag,
    /// Consent is missing or revoked.
    ConsentMissing,
}

/// Typed source of meeting context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeetingContextSource {
    /// Calendar event.
    Calendar,
    /// CRM activity or meeting record.
    Crm,
    /// Granola meeting record.
    Granola,
}

/// Bounded meeting context attached to a call session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeetingContext {
    /// Context provider.
    pub source: MeetingContextSource,
    /// Opaque provider record identifier.
    pub source_id: OpaqueId,
    /// Bounded display title.
    pub title: ProtocolLabel,
}

/// Speaker label for a finalized transcript segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptSpeaker {
    /// The owner using Buzz.
    #[serde(rename = "self")]
    SelfSpeaker,
    /// Another call participant.
    #[serde(rename = "others")]
    Others,
}

/// Decrypted finalized transcript segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptSegmentPayload {
    /// Payload schema version.
    pub schema_version: Version1,
    /// Stable segment identifier.
    pub segment_id: CanonicalUuidV4,
    /// Stable call identifier.
    pub call_id: CanonicalUuidV4,
    /// Strictly increasing per-call sequence.
    pub sequence: u64,
    /// Self/other speaker label.
    pub speaker: TranscriptSpeaker,
    /// Finalized transcript text.
    pub text: ProtocolText,
    /// Session-relative start time in milliseconds.
    pub started_at_ms: u64,
    /// Session-relative end time in milliseconds.
    pub ended_at_ms: u64,
    /// Local transcription model version.
    pub model_version: ProtocolLabel,
    /// Segment confidence percentage.
    pub confidence: Confidence,
}

/// Decrypted ephemeral call-copilot suggestion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "CopilotSuggestionWire")]
pub struct CopilotSuggestionPayload {
    /// Payload schema version.
    pub schema_version: Version1,
    /// Stable suggestion identifier.
    pub suggestion_id: CanonicalUuidV4,
    /// Stable call identifier.
    pub call_id: CanonicalUuidV4,
    /// Strictly increasing per-call sequence.
    pub sequence: u64,
    /// Closed suggestion category.
    pub category: CopilotSuggestionCategory,
    /// Whether the UI may interrupt or should remain quiet.
    pub interrupt: CopilotInterrupt,
    /// Minimized suggestion text.
    pub text: ProtocolText,
    /// Unix-seconds creation time.
    pub created_at: i64,
    /// Model version producing the suggestion.
    pub model_version: ProtocolLabel,
    /// Suggestion confidence percentage.
    pub confidence: Confidence,
    /// Hash-only evidence references.
    #[serde(deserialize_with = "deserialize_hashes")]
    pub evidence_hashes: Vec<Sha256Hex>,
}

/// Closed live-call copilot suggestion categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CopilotSuggestionCategory {
    /// Quiet decision summary.
    Decision,
    /// Quiet action update.
    Action,
    /// Quiet question whose answer is private.
    PrivateQuestion,
    /// Evaluable missed commitment backed by evidence.
    MissedCommitment,
    /// Evaluable contradiction backed by evidence.
    Contradiction,
}

/// Closed UI interrupt posture for a copilot suggestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CopilotInterrupt {
    /// Normal suggestion shown quietly.
    Quiet,
    /// Critical suggestion may interrupt visibly.
    Critical,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CopilotSuggestionWire {
    schema_version: Version1,
    suggestion_id: CanonicalUuidV4,
    call_id: CanonicalUuidV4,
    sequence: u64,
    category: CopilotSuggestionCategory,
    interrupt: CopilotInterrupt,
    text: ProtocolText,
    created_at: i64,
    model_version: ProtocolLabel,
    confidence: Confidence,
    #[serde(deserialize_with = "deserialize_hashes")]
    evidence_hashes: Vec<Sha256Hex>,
}

impl TryFrom<CopilotSuggestionWire> for CopilotSuggestionPayload {
    type Error = ProtocolValidationError;

    fn try_from(wire: CopilotSuggestionWire) -> Result<Self, Self::Error> {
        let quiet_category = matches!(
            wire.category,
            CopilotSuggestionCategory::Decision
                | CopilotSuggestionCategory::Action
                | CopilotSuggestionCategory::PrivateQuestion
        );
        let critical_category = matches!(
            wire.category,
            CopilotSuggestionCategory::MissedCommitment | CopilotSuggestionCategory::Contradiction
        );
        if (wire.interrupt == CopilotInterrupt::Quiet && !quiet_category)
            || (wire.interrupt == CopilotInterrupt::Critical
                && (!critical_category || wire.evidence_hashes.is_empty()))
        {
            return Err(ProtocolValidationError(
                "critical copilot suggestions require evidenced missed_commitment or contradiction"
                    .into(),
            ));
        }
        Ok(Self {
            schema_version: wire.schema_version,
            suggestion_id: wire.suggestion_id,
            call_id: wire.call_id,
            sequence: wire.sequence,
            category: wire.category,
            interrupt: wire.interrupt,
            text: wire.text,
            created_at: wire.created_at,
            model_version: wire.model_version,
            confidence: wire.confidence,
            evidence_hashes: wire.evidence_hashes,
        })
    }
}
