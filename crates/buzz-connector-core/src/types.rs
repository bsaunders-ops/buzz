//! Closed provider-neutral connector types.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

use crate::{ConnectorError, Result};

const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_TITLE_CHARS: usize = 1_024;
const MAX_SOURCE_CHARS: usize = 2_000_000;
const MAX_PAGE_CHANGES: usize = 1_000;
const MAX_PAGE_SOURCE_CHARS: usize = 5_000_000;
const MAX_LINK_BYTES: usize = 8_192;

fn update_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
}

fn bounded_text(value: impl Into<String>, max: usize, error: &'static str) -> Result<String> {
    let value = value.into();
    if value.is_empty() || value.len() > max || value.contains('\0') {
        return Err(ConnectorError::InvalidData(error));
    }
    Ok(value)
}

/// Provider adapters normalize resolver links from trusted response fields;
/// raw source text never selects a clickable host. Recheck that closed mapping
/// again at the provider-neutral boundary before storage or disclosure.
pub(crate) fn provider_link_is_allowed(provider: ConnectorProvider, link: &Url) -> bool {
    if link.scheme() != "https"
        || link.port().is_some()
        || !link.username().is_empty()
        || link.password().is_some()
        || link.fragment().is_some()
    {
        return false;
    }
    let Some(host) = link.host_str() else {
        return false;
    };
    match provider {
        ConnectorProvider::MicrosoftGraph => {
            host.eq_ignore_ascii_case("outlook.office.com")
                || host.eq_ignore_ascii_case("outlook.office365.com")
                || host
                    .to_ascii_lowercase()
                    .strip_suffix(".sharepoint.com")
                    .is_some_and(|tenant| !tenant.is_empty() && !tenant.contains('.'))
        }
        ConnectorProvider::GoogleDrive => [
            "drive.google.com",
            "docs.google.com",
            "sheets.google.com",
            "slides.google.com",
        ]
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed)),
        ConnectorProvider::CoreCrm => host.eq_ignore_ascii_case("crm.coreadvs.com"),
    }
}

/// Closed provider family. Display names and URLs never select authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorProvider {
    /// Microsoft Graph for Outlook, calendar, and selected OneDrive reads.
    MicrosoftGraph,
    /// Google Drive API for approved Shared Drives.
    GoogleDrive,
    /// Core CRM's MCP endpoint.
    CoreCrm,
}

impl ConnectorProvider {
    pub(crate) const fn wire_name(self) -> &'static str {
        match self {
            Self::MicrosoftGraph => "microsoft_graph",
            Self::GoogleDrive => "google_drive",
            Self::CoreCrm => "core_crm",
        }
    }
}

/// Tenant-scoped local connector account identifier.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccountId(Uuid);

impl std::fmt::Debug for AccountId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AccountId")
            .field("identifier_redacted", &true)
            .finish()
    }
}

impl AccountId {
    /// Construct from a server-created UUID.
    #[must_use]
    pub const fn new(value: Uuid) -> Self {
        Self(value)
    }

    /// Return the UUID value.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

/// Tenant-scoped approved source-scope identifier.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ScopeId(Uuid);

impl std::fmt::Debug for ScopeId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScopeId")
            .field("identifier_redacted", &true)
            .finish()
    }
}

impl ScopeId {
    /// Construct from a server-created UUID.
    #[must_use]
    pub const fn new(value: Uuid) -> Self {
        Self(value)
    }

    /// Return the UUID value.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

/// Closed connector-account lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    /// Reads are enabled.
    Active,
    /// Reads are temporarily paused.
    Paused,
    /// Credentials and authorization were revoked.
    Revoked,
    /// A deterministic connector error requires operator review.
    Error,
}

/// Closed approved-scope lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeStatus {
    /// Reads are enabled.
    Active,
    /// Reads are temporarily paused.
    Paused,
    /// The grant was revoked.
    Revoked,
    /// A deterministic scope error requires operator review.
    Error,
}

/// Closed external scope kinds used by the Month-1 connectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceScopeKind {
    /// One mailbox folder delta stream.
    OutlookMailFolder,
    /// Read-only primary calendar delta stream.
    OutlookCalendar,
    /// The single selected OneDrive folder.
    OneDriveSelectedFolder,
    /// One immutable Google Shared Drive ID.
    GoogleSharedDrive,
    /// A folder pinned beneath an approved Shared Drive.
    GoogleDriveFolder,
    /// Core CRM's read corpus.
    CoreCrmCorpus,
}

/// Closed indexed source kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// Email message body.
    Email,
    /// Calendar event.
    CalendarEvent,
    /// Document or plain text material.
    Document,
    /// Spreadsheet cell text.
    Spreadsheet,
    /// Simple slide text.
    Presentation,
    /// CRM entity or activity record.
    CrmRecord,
    /// Granola transcript exposed through Core CRM.
    CrmTranscript,
}

impl SourceKind {
    const fn hash_tag(self) -> u8 {
        match self {
            Self::Email => 0,
            Self::CalendarEvent => 1,
            Self::Document => 2,
            Self::Spreadsheet => 3,
            Self::Presentation => 4,
            Self::CrmRecord => 5,
            Self::CrmTranscript => 6,
        }
    }
}

/// Immutable provider-side item identifier.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ExternalItemId(String);

impl std::fmt::Debug for ExternalItemId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExternalItemId")
            .field("redacted", &true)
            .field("bytes", &self.0.len())
            .finish()
    }
}

impl ExternalItemId {
    /// Validate a non-empty bounded provider identifier.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        bounded_text(value, MAX_IDENTIFIER_BYTES, "external item id is invalid").map(Self)
    }

    /// Validated provider identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact provider version and optional ETag used for authorization rechecks.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteVersion {
    value: String,
    etag: Option<String>,
}

impl std::fmt::Debug for RemoteVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteVersion")
            .field("redacted", &true)
            .field("etag_present", &self.etag.is_some())
            .finish()
    }
}

impl RemoteVersion {
    /// Validate provider version material.
    pub fn new(value: impl Into<String>, etag: Option<String>) -> Result<Self> {
        let value = bounded_text(value, MAX_IDENTIFIER_BYTES, "remote version is invalid")?;
        let etag = etag
            .map(|value| bounded_text(value, MAX_IDENTIFIER_BYTES, "remote etag is invalid"))
            .transpose()?;
        Ok(Self { value, etag })
    }

    /// Provider version value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Optional provider ETag.
    #[must_use]
    pub fn etag(&self) -> Option<&str> {
        self.etag.as_deref()
    }

    /// Stable hash for citation and cache version binding.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"core-buzz:remote-version:v1\0");
        update_len_prefixed(&mut hasher, self.value.as_bytes());
        update_len_prefixed(&mut hasher, self.etag.as_deref().unwrap_or("").as_bytes());
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TrustMarker {
    UntrustedExternalSource,
}

/// Source body whose type preserves the rule that provider text is data only.
///
/// It deliberately has no conversion to a chat role, broker operation, or
/// instruction type. Parsers and retrieval layers can only extract bounded
/// untrusted text.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UntrustedSourceData {
    #[serde(rename = "trust")]
    trust: TrustMarker,
    #[serde(rename = "text")]
    text: String,
}

impl std::fmt::Debug for UntrustedSourceData {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UntrustedSourceData")
            .field("trust", &"untrusted_external_source")
            .field("redacted", &true)
            .field("characters", &self.char_count())
            .finish()
    }
}

impl UntrustedSourceData {
    /// Wrap source text without interpreting embedded content.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            trust: TrustMarker::UntrustedExternalSource,
            text: value.into(),
        }
    }

    /// Read source content while retaining its explicit untrusted type.
    #[must_use]
    pub fn as_untrusted_text(&self) -> &str {
        &self.text
    }

    /// Stable context label serialized beside every excerpt.
    #[must_use]
    pub const fn trust_label(&self) -> &'static str {
        "untrusted_external_source"
    }

    pub(crate) fn char_count(&self) -> usize {
        self.text.chars().count()
    }
}

/// Positive item ACL principal. Absence of principals denies all access.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "principal_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AclPrincipal {
    /// One Buzz signing public key.
    User {
        /// Exact 32-byte Nostr public key.
        pubkey: [u8; 32],
    },
    /// One private Buzz channel, additionally requiring current membership.
    Channel {
        /// Server-resolved channel identifier.
        channel_id: Uuid,
    },
}

impl std::fmt::Debug for AclPrincipal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let principal_type = match self {
            Self::User { .. } => "user",
            Self::Channel { .. } => "channel",
        };
        formatter
            .debug_struct("AclPrincipal")
            .field("principal_type", &principal_type)
            .field("identifier_redacted", &true)
            .finish()
    }
}

impl AclPrincipal {
    /// Construct a user principal.
    #[must_use]
    pub const fn user(pubkey: [u8; 32]) -> Self {
        Self::User { pubkey }
    }

    /// Construct a channel principal.
    #[must_use]
    pub const fn channel(channel_id: Uuid) -> Self {
        Self::Channel { channel_id }
    }
}

/// One current provider item and its complete replacement ACL/body.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceItemUpsert {
    external_item_id: ExternalItemId,
    remote_version: RemoteVersion,
    title: String,
    source_kind: SourceKind,
    modified_at: DateTime<Utc>,
    resolvable_link: String,
    source: UntrustedSourceData,
    acls: Vec<AclPrincipal>,
}

impl std::fmt::Debug for SourceItemUpsert {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceItemUpsert")
            .field("source_kind", &self.source_kind)
            .field("source_characters", &self.source.char_count())
            .field("acl_count", &self.acls.len())
            .field("identifiers_and_content_redacted", &true)
            .finish()
    }
}

impl SourceItemUpsert {
    /// Validate one complete current item snapshot.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        external_item_id: ExternalItemId,
        remote_version: RemoteVersion,
        title: impl Into<String>,
        source_kind: SourceKind,
        modified_at: DateTime<Utc>,
        resolvable_link: impl Into<String>,
        source: UntrustedSourceData,
        acls: Vec<AclPrincipal>,
    ) -> Result<Self> {
        let title = title.into();
        if title.trim().is_empty()
            || title.chars().count() > MAX_TITLE_CHARS
            || title.contains('\0')
        {
            return Err(ConnectorError::InvalidData("source title is invalid"));
        }
        if source.char_count() > MAX_SOURCE_CHARS {
            return Err(ConnectorError::BoundExceeded("source item characters"));
        }
        let resolvable_link = resolvable_link.into();
        if resolvable_link.len() > MAX_LINK_BYTES || resolvable_link.contains('\0') {
            return Err(ConnectorError::BoundExceeded("resolvable link bytes"));
        }
        let link = Url::parse(&resolvable_link)
            .map_err(|_| ConnectorError::InvalidData("resolvable link is invalid"))?;
        if link.scheme() != "https"
            || link.host_str().is_none()
            || !link.username().is_empty()
            || link.password().is_some()
        {
            return Err(ConnectorError::InvalidData("resolvable link must be HTTPS"));
        }
        let mut unique = BTreeSet::new();
        for acl in &acls {
            if !unique.insert(acl.clone()) {
                return Err(ConnectorError::InvalidData("duplicate ACL principal"));
            }
        }
        Ok(Self {
            external_item_id,
            remote_version,
            title,
            source_kind,
            modified_at,
            resolvable_link,
            source,
            acls,
        })
    }

    /// Provider item ID.
    #[must_use]
    pub fn external_item_id(&self) -> &ExternalItemId {
        &self.external_item_id
    }

    /// Provider version.
    #[must_use]
    pub fn remote_version(&self) -> &RemoteVersion {
        &self.remote_version
    }

    /// Human-readable citation title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Typed source kind.
    #[must_use]
    pub const fn source_kind(&self) -> SourceKind {
        self.source_kind
    }

    /// Provider modification timestamp.
    #[must_use]
    pub const fn modified_at(&self) -> DateTime<Utc> {
        self.modified_at
    }

    /// Stable provider source link.
    #[must_use]
    pub fn resolvable_link(&self) -> &str {
        &self.resolvable_link
    }

    /// Untrusted source body.
    #[must_use]
    pub const fn source(&self) -> &UntrustedSourceData {
        &self.source
    }

    /// Complete positive ACL replacement.
    #[must_use]
    pub fn acls(&self) -> &[AclPrincipal] {
        &self.acls
    }
}

/// Closed source-removal cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TombstoneReason {
    /// Provider reports deletion.
    Deleted,
    /// Authorization was revoked.
    Revoked,
    /// Provider reports the item inaccessible.
    Inaccessible,
    /// Item no longer resides beneath the approved scope.
    RemovedFromScope,
}

impl TombstoneReason {
    const fn hash_tag(self) -> u8 {
        match self {
            Self::Deleted => 0,
            Self::Revoked => 1,
            Self::Inaccessible => 2,
            Self::RemovedFromScope => 3,
        }
    }
}

/// A provider item whose active index and ACLs must be removed immediately.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Tombstone {
    external_item_id: ExternalItemId,
    reason: TombstoneReason,
}

impl std::fmt::Debug for Tombstone {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Tombstone")
            .field("reason", &self.reason)
            .field("external_item_id_redacted", &true)
            .finish()
    }
}

impl Tombstone {
    /// Parse the closed removal reason.
    pub fn new(external_item_id: ExternalItemId, reason: &str) -> Result<Self> {
        let reason = match reason {
            "deleted" => TombstoneReason::Deleted,
            "revoked" => TombstoneReason::Revoked,
            "inaccessible" => TombstoneReason::Inaccessible,
            "removed_from_scope" => TombstoneReason::RemovedFromScope,
            _ => return Err(ConnectorError::InvalidData("unknown tombstone reason")),
        };
        Ok(Self {
            external_item_id,
            reason,
        })
    }

    /// Provider item ID.
    #[must_use]
    pub const fn external_item_id(&self) -> &ExternalItemId {
        &self.external_item_id
    }

    /// Closed removal reason.
    #[must_use]
    pub const fn reason(&self) -> TombstoneReason {
        self.reason
    }
}

/// Application-encrypted provider delta cursor and fencing generation.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedCursor {
    ciphertext: Vec<u8>,
    integrity_hash: [u8; 32],
    key_version: u32,
    generation: u64,
}

impl std::fmt::Debug for EncryptedCursor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EncryptedCursor")
            .field("ciphertext_redacted", &true)
            .field("ciphertext_bytes", &self.ciphertext.len())
            .field("key_version", &self.key_version)
            .field("generation", &self.generation)
            .finish()
    }
}

impl EncryptedCursor {
    /// Validate opaque encrypted cursor metadata.
    pub fn new(
        ciphertext: Vec<u8>,
        integrity_hash: [u8; 32],
        key_version: u32,
        generation: u64,
    ) -> Result<Self> {
        if ciphertext.is_empty() || ciphertext.len() > 65_536 {
            return Err(ConnectorError::BoundExceeded("encrypted cursor bytes"));
        }
        if key_version == 0 {
            return Err(ConnectorError::InvalidData(
                "cursor key version must be positive",
            ));
        }
        Ok(Self {
            ciphertext,
            integrity_hash,
            key_version,
            generation,
        })
    }

    /// Opaque application-encrypted bytes.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Integrity hash verified by the cursor encryption boundary.
    #[must_use]
    pub const fn integrity_hash(&self) -> [u8; 32] {
        self.integrity_hash
    }

    /// Key version used to encrypt the opaque cursor.
    #[must_use]
    pub const fn key_version(&self) -> u32 {
        self.key_version
    }

    /// Monotonic stream generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Non-authoritative provider checkpoint retained for reconciliation evidence.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteCheckpoint {
    kind: String,
    value: String,
}

impl std::fmt::Debug for RemoteCheckpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteCheckpoint")
            .field("provider_checkpoint_redacted", &true)
            .finish()
    }
}

impl RemoteCheckpoint {
    /// Validate bounded checkpoint metadata.
    pub fn new(kind: impl Into<String>, value: impl Into<String>) -> Result<Self> {
        Ok(Self {
            kind: bounded_text(kind, 128, "checkpoint kind is invalid")?,
            value: bounded_text(value, 512, "checkpoint value is invalid")?,
        })
    }
}

/// A deterministic delta page. Applying its changes and next cursor is atomic.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChangePage {
    schema_version: u16,
    tenant_id: Uuid,
    provider: ConnectorProvider,
    account_id: AccountId,
    scope_id: ScopeId,
    stream: String,
    previous_cursor_hash: [u8; 32],
    upserts: Vec<SourceItemUpsert>,
    tombstones: Vec<Tombstone>,
    next_cursor: EncryptedCursor,
    remote_checkpoint: RemoteCheckpoint,
    page_digest: [u8; 32],
}

impl std::fmt::Debug for ChangePage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ChangePage")
            .field("schema_version", &self.schema_version)
            .field("provider", &self.provider)
            .field("upsert_count", &self.upserts.len())
            .field("tombstone_count", &self.tombstones.len())
            .field("authority_cursor_and_content_redacted", &true)
            .finish()
    }
}

impl ChangePage {
    /// Validate and hash one bounded deterministic provider page.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: Uuid,
        provider: ConnectorProvider,
        account_id: AccountId,
        scope_id: ScopeId,
        stream: impl Into<String>,
        previous_cursor_hash: [u8; 32],
        upserts: Vec<SourceItemUpsert>,
        tombstones: Vec<Tombstone>,
        next_cursor: EncryptedCursor,
        remote_checkpoint: RemoteCheckpoint,
    ) -> Result<Self> {
        let stream = bounded_text(stream, 128, "delta stream is invalid")?;
        if !stream
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
        {
            return Err(ConnectorError::InvalidData("delta stream is invalid"));
        }
        if upserts.len().saturating_add(tombstones.len()) > MAX_PAGE_CHANGES {
            return Err(ConnectorError::BoundExceeded("delta page changes"));
        }
        let total_chars = upserts
            .iter()
            .try_fold(0_usize, |total, item| {
                total.checked_add(item.source.char_count())
            })
            .ok_or(ConnectorError::BoundExceeded(
                "delta page source characters",
            ))?;
        if total_chars > MAX_PAGE_SOURCE_CHARS {
            return Err(ConnectorError::BoundExceeded(
                "delta page source characters",
            ));
        }
        let mut identities = BTreeSet::new();
        for item in &upserts {
            if !identities.insert(item.external_item_id.clone()) {
                return Err(ConnectorError::InvalidData("duplicate item in delta page"));
            }
        }
        for item in &tombstones {
            if !identities.insert(item.external_item_id.clone()) {
                return Err(ConnectorError::InvalidData(
                    "conflicting item changes in delta page",
                ));
            }
        }
        let mut page = Self {
            schema_version: 1,
            tenant_id,
            provider,
            account_id,
            scope_id,
            stream,
            previous_cursor_hash,
            upserts,
            tombstones,
            next_cursor,
            remote_checkpoint,
            page_digest: [0; 32],
        };
        if page.upserts.iter().any(|item| {
            Url::parse(item.resolvable_link())
                .map(|link| !provider_link_is_allowed(page.provider, &link))
                .unwrap_or(true)
        }) {
            return Err(ConnectorError::InvalidData(
                "source resolver link is outside the provider allowlist",
            ));
        }
        page.page_digest = page.calculate_digest();
        Ok(page)
    }

    fn calculate_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"core-buzz:connector-change-page:v1\0");
        hasher.update(self.tenant_id.as_bytes());
        update_len_prefixed(&mut hasher, self.provider.wire_name().as_bytes());
        hasher.update(self.account_id.as_uuid().as_bytes());
        hasher.update(self.scope_id.as_uuid().as_bytes());
        update_len_prefixed(&mut hasher, self.stream.as_bytes());
        hasher.update(self.previous_cursor_hash);
        for item in &self.upserts {
            update_len_prefixed(&mut hasher, item.external_item_id.as_str().as_bytes());
            hasher.update(item.remote_version.digest());
            update_len_prefixed(&mut hasher, item.title.as_bytes());
            hasher.update([item.source_kind.hash_tag()]);
            hasher.update(item.modified_at.timestamp_micros().to_be_bytes());
            update_len_prefixed(&mut hasher, item.resolvable_link.as_bytes());
            update_len_prefixed(&mut hasher, item.source.as_untrusted_text().as_bytes());
            for acl in &item.acls {
                match acl {
                    AclPrincipal::User { pubkey } => {
                        hasher.update([0]);
                        hasher.update(pubkey);
                    }
                    AclPrincipal::Channel { channel_id } => {
                        hasher.update([1]);
                        hasher.update(channel_id.as_bytes());
                    }
                }
            }
        }
        for tombstone in &self.tombstones {
            update_len_prefixed(&mut hasher, tombstone.external_item_id.as_str().as_bytes());
            hasher.update([tombstone.reason.hash_tag()]);
        }
        hasher.update(self.next_cursor.integrity_hash);
        update_len_prefixed(&mut hasher, &self.next_cursor.ciphertext);
        hasher.update(self.next_cursor.key_version.to_be_bytes());
        hasher.update(self.next_cursor.generation.to_be_bytes());
        update_len_prefixed(&mut hasher, self.remote_checkpoint.kind.as_bytes());
        update_len_prefixed(&mut hasher, self.remote_checkpoint.value.as_bytes());
        hasher.finalize().into()
    }

    /// Schema version, currently exactly one.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    /// Connector provider.
    #[must_use]
    pub const fn provider(&self) -> ConnectorProvider {
        self.provider
    }

    /// Account boundary.
    #[must_use]
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Scope boundary.
    #[must_use]
    pub const fn scope_id(&self) -> ScopeId {
        self.scope_id
    }

    /// Stream name derived from connector configuration.
    #[must_use]
    pub fn stream(&self) -> &str {
        &self.stream
    }

    /// Cursor integrity expected before applying.
    #[must_use]
    pub const fn previous_cursor_hash(&self) -> [u8; 32] {
        self.previous_cursor_hash
    }

    /// Complete item upserts.
    #[must_use]
    pub fn upserts(&self) -> &[SourceItemUpsert] {
        &self.upserts
    }

    /// Item tombstones.
    #[must_use]
    pub fn tombstones(&self) -> &[Tombstone] {
        &self.tombstones
    }

    /// Cursor committed atomically with the page.
    #[must_use]
    pub const fn next_cursor(&self) -> &EncryptedCursor {
        &self.next_cursor
    }

    /// Deterministic page digest used to recognize retries.
    #[must_use]
    pub const fn page_digest(&self) -> [u8; 32] {
        self.page_digest
    }
}

/// Stable tenant-leading versioned source identity.
#[derive(Clone, PartialEq, Eq)]
pub struct StableItemIdentity {
    tenant_id: Uuid,
    provider: ConnectorProvider,
    account_id: AccountId,
    scope_id: ScopeId,
    external_item_id: ExternalItemId,
    remote_version: RemoteVersion,
}

impl std::fmt::Debug for StableItemIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StableItemIdentity")
            .field("identity_redacted", &true)
            .finish()
    }
}

impl StableItemIdentity {
    /// Construct an authority identity from immutable IDs rather than labels.
    #[must_use]
    pub const fn new(
        tenant_id: Uuid,
        provider: ConnectorProvider,
        account_id: AccountId,
        scope_id: ScopeId,
        external_item_id: ExternalItemId,
        remote_version: RemoteVersion,
    ) -> Self {
        Self {
            tenant_id,
            provider,
            account_id,
            scope_id,
            external_item_id,
            remote_version,
        }
    }

    /// SHA-256 over the tenant-leading, length-delimited identity fields.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"core-buzz:stable-source-item:v1\0");
        hasher.update(self.tenant_id.as_bytes());
        update_len_prefixed(&mut hasher, self.provider.wire_name().as_bytes());
        hasher.update(self.account_id.as_uuid().as_bytes());
        hasher.update(self.scope_id.as_uuid().as_bytes());
        update_len_prefixed(&mut hasher, self.external_item_id.as_str().as_bytes());
        hasher.update(self.remote_version.digest());
        hasher.finalize().into()
    }
}
