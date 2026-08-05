use buzz_core::CommunityId;
use chrono::{DateTime, NaiveDate, Utc};
use uuid::Uuid;

/// Fixed local CPU embedding width used by Month-1 corpora.
pub const EMBEDDING_DIMENSIONS: usize = 384;

/// Validated non-secret Azure Key Vault secret name.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyVaultSecretName(String);

impl std::fmt::Debug for KeyVaultSecretName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeyVaultSecretName")
            .field("name_redacted", &true)
            .finish()
    }
}

impl KeyVaultSecretName {
    /// Accept Azure's 1-127 ASCII alphanumeric/hyphen secret-name grammar.
    pub fn new(value: impl Into<String>) -> crate::Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 127
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(crate::DbError::InvalidData(
                "credential reference must be a 1-127 byte Key Vault secret name".into(),
            ));
        }
        Ok(Self(value))
    }

    /// Validated secret name, never a URI or token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Durable Entra-to-Buzz identity binding metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct IdentityBindingRecord {
    /// Tenant owning the binding.
    pub community_id: CommunityId,
    /// Binding identifier.
    pub id: Uuid,
    /// Microsoft Entra object identifier.
    pub entra_object_id: Uuid,
    /// Bound Buzz public key.
    pub buzz_pubkey: Vec<u8>,
    /// Current lifecycle state.
    pub lifecycle_state: String,
    /// Hash of the one-time proof challenge.
    pub challenge_hash: Vec<u8>,
    /// Optional tenant-scoped connector account.
    pub connector_account_id: Option<Uuid>,
    /// Revocation timestamp, when revoked.
    pub revoked_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for IdentityBindingRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IdentityBindingRecord")
            .field("lifecycle_state", &self.lifecycle_state)
            .field("revoked", &self.revoked_at.is_some())
            .field("identity_and_challenge_redacted", &true)
            .finish()
    }
}

/// Durable connector account metadata without credential values.
#[derive(Clone, PartialEq, Eq)]
pub struct ConnectorAccountRecord {
    /// Tenant owning the account.
    pub community_id: CommunityId,
    /// Account identifier.
    pub id: Uuid,
    /// Typed connector provider.
    pub provider: String,
    /// Buzz owner public key.
    pub owner_pubkey: Vec<u8>,
    /// Immutable provider-side account identifier.
    pub external_account_id: String,
    /// Non-secret Key Vault credential reference.
    pub credential_reference: KeyVaultSecretName,
    /// Account lifecycle status.
    pub status: String,
}

impl std::fmt::Debug for ConnectorAccountRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectorAccountRecord")
            .field("provider", &self.provider)
            .field("status", &self.status)
            .field("account_authority_redacted", &true)
            .finish()
    }
}

/// Approved external source scope and its granted capabilities.
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovedSourceScopeRecord {
    /// Tenant owning the scope.
    pub community_id: CommunityId,
    /// Scope identifier.
    pub id: Uuid,
    /// Parent connector account identifier.
    pub account_id: Uuid,
    /// Immutable provider-side scope identifier.
    pub external_scope_id: String,
    /// Exact configured clickable-link hosts for account-specific authorities.
    pub resolver_hosts: Vec<String>,
    /// Provider-specific scope type.
    pub scope_type: String,
    /// Whether reads are permitted.
    pub can_read: bool,
    /// Whether writes are permitted.
    pub can_write: bool,
    /// Whether the scope is pinned to the active deal.
    pub active_deal_pinned: bool,
    /// Scope lifecycle status.
    pub status: String,
}

impl std::fmt::Debug for ApprovedSourceScopeRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApprovedSourceScopeRecord")
            .field("scope_type", &self.scope_type)
            .field("resolver_host_count", &self.resolver_hosts.len())
            .field("can_read", &self.can_read)
            .field("can_write", &self.can_write)
            .field("active_deal_pinned", &self.active_deal_pinned)
            .field("status", &self.status)
            .field("scope_authority_redacted", &true)
            .finish()
    }
}

/// Current encrypted delta cursor and lease state for a source stream.
#[derive(Clone, PartialEq, Eq)]
pub struct ConnectorDeltaCursorRecord {
    /// Tenant owning the cursor.
    pub community_id: CommunityId,
    /// Parent connector account identifier.
    pub account_id: Uuid,
    /// Parent approved scope identifier.
    pub scope_id: Uuid,
    /// Typed source stream name.
    pub stream: String,
    /// Application-encrypted opaque cursor bytes.
    pub encrypted_cursor: Vec<u8>,
    /// Integrity hash of the encrypted cursor.
    pub cursor_integrity_hash: Vec<u8>,
    /// Encryption key version marker.
    pub cursor_key_version: i32,
    /// Monotonic lease generation.
    pub generation: i64,
    /// Last successful advancement time.
    pub last_success_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for ConnectorDeltaCursorRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectorDeltaCursorRecord")
            .field("cursor_redacted", &true)
            .field("cursor_bytes", &self.encrypted_cursor.len())
            .field("cursor_key_version", &self.cursor_key_version)
            .field("generation", &self.generation)
            .finish()
    }
}

/// Migratable local embedding version metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct EmbeddingVersionRecord {
    /// Tenant owning the embedding corpus.
    pub community_id: CommunityId,
    /// Embedding version identifier.
    pub id: Uuid,
    /// Local model name.
    pub model_name: String,
    /// Stored vector dimensions.
    pub dimensions: i32,
    /// Monotonic model version.
    pub version: i32,
    /// Build or activation state.
    pub status: String,
}

impl std::fmt::Debug for EmbeddingVersionRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EmbeddingVersionRecord")
            .field("model_name", &self.model_name)
            .field("dimensions", &self.dimensions)
            .field("version", &self.version)
            .field("status", &self.status)
            .field("tenant_and_identifier_redacted", &true)
            .finish()
    }
}

/// Stable provider item identity and citation metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct SourceItemRecord {
    /// Tenant owning the item.
    pub community_id: CommunityId,
    /// Local item identifier.
    pub id: Uuid,
    /// Connector account identifier.
    pub account_id: Uuid,
    /// Approved source scope identifier.
    pub scope_id: Uuid,
    /// Immutable provider-side item identifier.
    pub external_item_id: String,
    /// Provider-side version used for rechecks.
    pub remote_version: String,
    /// Optional provider ETag.
    pub remote_etag: Option<String>,
    /// Citation title.
    pub title: String,
    /// Typed source kind.
    pub source_type: String,
    /// Provider modification time.
    pub modified_at: DateTime<Utc>,
    /// Stable resolvable citation link.
    pub resolvable_link: String,
    /// Tombstone timestamp.
    pub tombstoned_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for SourceItemRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceItemRecord")
            .field("source_metadata_redacted", &true)
            .field("source_type", &self.source_type)
            .field("tombstoned", &self.tombstoned_at.is_some())
            .finish()
    }
}

/// Source chunk content, hash, and local embedding metadata.
#[derive(Clone, PartialEq)]
pub struct SourceChunkRecord {
    /// Tenant owning the chunk.
    pub community_id: CommunityId,
    /// Local chunk identifier.
    pub id: Uuid,
    /// Parent source item identifier.
    pub item_id: Uuid,
    /// Stable chunk order within the item.
    pub chunk_index: i32,
    /// Extracted source content.
    pub content: String,
    /// Content hash used for citation rechecks.
    pub content_hash: Vec<u8>,
    /// Local embedding version identifier.
    pub embedding_version_id: Option<Uuid>,
    /// Local embedding vector.
    pub embedding: Option<Vec<f32>>,
}

impl std::fmt::Debug for SourceChunkRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceChunkRecord")
            .field("chunk_index", &self.chunk_index)
            .field("content_redacted", &true)
            .field("content_characters", &self.content.chars().count())
            .field("embedding_present", &self.embedding.is_some())
            .finish()
    }
}

/// Positive source-item ACL principal.
#[derive(Clone, PartialEq, Eq)]
pub struct SourceItemAclRecord {
    /// Tenant owning the ACL.
    pub community_id: CommunityId,
    /// ACL identifier.
    pub id: Uuid,
    /// Protected source item identifier.
    pub item_id: Uuid,
    /// Either `user` or `channel`.
    pub principal_type: String,
    /// User public key for a user ACL.
    pub principal_pubkey: Option<Vec<u8>>,
    /// Channel identifier for a channel ACL.
    pub channel_id: Option<Uuid>,
}

impl std::fmt::Debug for SourceItemAclRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceItemAclRecord")
            .field("principal_type", &self.principal_type)
            .field("authority_identifiers_redacted", &true)
            .finish()
    }
}

/// Closed indexed source kind accepted by the connector storage boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexedSourceKind {
    /// Email body.
    Email,
    /// Calendar event.
    CalendarEvent,
    /// Document or plain text.
    Document,
    /// Spreadsheet cell text.
    Spreadsheet,
    /// Simple slide text.
    Presentation,
    /// CRM entity or activity.
    CrmRecord,
    /// Granola transcript exposed by CRM.
    CrmTranscript,
}

impl IndexedSourceKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::CalendarEvent => "calendar_event",
            Self::Document => "document",
            Self::Spreadsheet => "spreadsheet",
            Self::Presentation => "presentation",
            Self::CrmRecord => "crm_record",
            Self::CrmTranscript => "crm_transcript",
        }
    }
}

/// Positive source ACL replacement accepted by a change page.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum NewSourceAclPrincipal {
    /// One exact Buzz user signing key.
    User([u8; 32]),
    /// One private channel; reads still require current membership.
    Channel(Uuid),
}

impl std::fmt::Debug for NewSourceAclPrincipal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let principal_type = match self {
            Self::User(_) => "user",
            Self::Channel(_) => "channel",
        };
        formatter
            .debug_struct("NewSourceAclPrincipal")
            .field("principal_type", &principal_type)
            .field("authority_identifier_redacted", &true)
            .finish()
    }
}

/// One deterministic normalized source chunk in an item upsert.
#[derive(Clone, PartialEq, Eq)]
pub struct NewIndexedSourceChunk {
    /// Stable zero-based order within the item.
    pub chunk_index: i32,
    /// Inclusive Unicode-scalar offset in the normalized source text.
    pub start_char: i64,
    /// Exclusive Unicode-scalar offset in the normalized source text.
    pub end_char: i64,
    /// Bounded normalized untrusted source text.
    pub content: String,
    /// Domain-separated chunk hash.
    pub content_hash: [u8; 32],
}

impl std::fmt::Debug for NewIndexedSourceChunk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NewIndexedSourceChunk")
            .field("chunk_index", &self.chunk_index)
            .field("start_char", &self.start_char)
            .field("end_char", &self.end_char)
            .field("content_redacted", &true)
            .field("content_characters", &self.content.chars().count())
            .finish()
    }
}

/// One complete source item, chunk, and positive ACL replacement.
#[derive(Clone, PartialEq, Eq)]
pub struct NewIndexedSourceItem {
    /// Immutable provider-side item identifier.
    pub external_item_id: String,
    /// Exact current provider version.
    pub remote_version: String,
    /// Optional current provider ETag.
    pub remote_etag: Option<String>,
    /// Citation title.
    pub title: String,
    /// Closed source kind.
    pub source_kind: IndexedSourceKind,
    /// Provider modification time.
    pub modified_at: DateTime<Utc>,
    /// Stable provider link.
    pub resolvable_link: String,
    /// Complete current positive ACL set.
    pub acls: Vec<NewSourceAclPrincipal>,
    /// Deterministic chunks. Empty ACLs require empty chunks.
    pub chunks: Vec<NewIndexedSourceChunk>,
}

impl std::fmt::Debug for NewIndexedSourceItem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NewIndexedSourceItem")
            .field("source_kind", &self.source_kind)
            .field("acl_count", &self.acls.len())
            .field("chunk_count", &self.chunks.len())
            .field("metadata_and_content_redacted", &true)
            .finish()
    }
}

/// Provider item whose active ACL and index material must be removed.
#[derive(Clone, PartialEq, Eq)]
pub struct NewSourceTombstone {
    /// Immutable provider-side item identifier.
    pub external_item_id: String,
}

impl std::fmt::Debug for NewSourceTombstone {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NewSourceTombstone")
            .field("external_item_id_redacted", &true)
            .finish()
    }
}

/// One fenced source change page committed with its encrypted cursor.
#[derive(Clone, Copy)]
pub struct NewSourceChangePage<'a> {
    /// Server-resolved tenant embedded as the leading page authority.
    pub community_id: CommunityId,
    /// Connector account boundary.
    pub account_id: Uuid,
    /// Approved source scope boundary.
    pub scope_id: Uuid,
    /// Closed connector provider expected on the account.
    pub provider: ExternalConnector,
    /// Preconfigured stream name.
    pub stream: &'a str,
    /// Worker holding the current fenced cursor lease.
    pub worker_id: Uuid,
    /// Current fenced lease generation.
    pub lease_generation: i64,
    /// Current cursor integrity hash expected by this page.
    pub expected_cursor_integrity_hash: &'a [u8],
    /// Next application-encrypted cursor bytes.
    pub next_encrypted_cursor: &'a [u8],
    /// Integrity hash for the next cursor bytes.
    pub next_cursor_integrity_hash: &'a [u8],
    /// Encryption key version for the next cursor.
    pub next_cursor_key_version: i32,
    /// Deterministic digest of the complete page and remote checkpoint.
    pub page_digest: &'a [u8],
    /// Whether this page completed a full known-record reconciliation cycle.
    pub reconciliation_complete: bool,
    /// Complete item replacements.
    pub upserts: &'a [NewIndexedSourceItem],
    /// Item tombstones.
    pub tombstones: &'a [NewSourceTombstone],
    /// Explicit database-comparable application time.
    pub now: DateTime<Utc>,
}

impl std::fmt::Debug for NewSourceChangePage<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NewSourceChangePage")
            .field("provider", &self.provider)
            .field("upsert_count", &self.upserts.len())
            .field("tombstone_count", &self.tombstones.len())
            .field("reconciliation_complete", &self.reconciliation_complete)
            .field("authority_cursor_and_content_redacted", &true)
            .finish()
    }
}

/// Durable source-page application outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourcePageApplyOutcome {
    /// Item changes and cursor committed together.
    Applied {
        /// Number of item identities in the page.
        changed_items: usize,
    },
    /// The exact next cursor was already committed, so no changes were replayed.
    AlreadyApplied,
}

/// Closed feed priority mapping persisted as 0=low through 3=urgent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsightPriority {
    /// Low priority.
    Low,
    /// Normal priority.
    Normal,
    /// High priority.
    High,
    /// Urgent priority.
    Urgent,
}

impl InsightPriority {
    pub(crate) const fn as_i16(self) -> i16 {
        match self {
            Self::Low => 0,
            Self::Normal => 1,
            Self::High => 2,
            Self::Urgent => 3,
        }
    }
}

/// New insight values consumed by the atomic daily-budget claim.
#[derive(Debug, Clone, Copy)]
pub struct NewAssistantInsight<'a> {
    /// Owner public key.
    pub owner_pubkey: &'a [u8],
    /// Destination channel.
    pub channel_id: Uuid,
    /// Stable content/evidence dedupe hash.
    pub dedupe_key: &'a [u8],
    /// Feed priority.
    pub priority: InsightPriority,
    /// Hash of the typed evidence identifiers.
    pub evidence_hash: &'a [u8],
    /// Number of supporting evidence identifiers.
    pub evidence_count: i32,
    /// Optional expiration time.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Visible accepted assistant insight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssistantInsightRecord {
    /// Tenant owning the insight.
    pub community_id: CommunityId,
    /// Insight identifier.
    pub id: Uuid,
    /// Owner public key.
    pub owner_pubkey: Vec<u8>,
    /// Destination channel.
    pub channel_id: Uuid,
    /// America/New_York feed date.
    pub new_york_date: NaiveDate,
    /// Dedupe hash.
    pub dedupe_key: Vec<u8>,
    /// Feed priority.
    pub priority: InsightPriority,
    /// Insight lifecycle state.
    pub status: String,
    /// Evidence identifier hash.
    pub evidence_hash: Vec<u8>,
    /// Evidence identifier count.
    pub evidence_count: i32,
    /// Acceptance time.
    pub created_at: DateTime<Utc>,
}

/// Durable per-owner New York daily feed budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsightDailyBudgetRecord {
    /// Tenant owning the budget.
    pub community_id: CommunityId,
    /// Owner public key.
    pub owner_pubkey: Vec<u8>,
    /// America/New_York calendar date.
    pub new_york_date: NaiveDate,
    /// Accepted visible insight count, capped at ten.
    pub accepted_count: i16,
}

/// Pure result of checking an insight claim against dedupe and budget state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsightClaimDecision {
    /// The dedupe key already has a visible insight.
    Duplicate,
    /// The daily maximum of ten is already reached.
    BudgetExhausted,
    /// The claim may create one visible insight.
    Claim,
}

impl InsightClaimDecision {
    /// Evaluate dedupe before the hard daily budget.
    #[must_use]
    pub const fn evaluate(already_exists: bool, accepted_count: i16) -> Self {
        if already_exists {
            Self::Duplicate
        } else if accepted_count >= 10 {
            Self::BudgetExhausted
        } else {
            Self::Claim
        }
    }
}

/// Outcome of the atomic insight budget/dedupe claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsightClaimOutcome {
    /// A visible insight was accepted.
    Claimed(AssistantInsightRecord),
    /// The dedupe key already existed.
    Duplicate,
    /// The owner's ten-item daily budget was exhausted.
    BudgetExhausted,
}

/// External action proposal state relevant to execution claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionProposalStatus {
    /// Awaiting a signer decision.
    Proposed,
    /// Approved and eligible before expiry.
    Approved,
    /// Explicitly denied.
    Denied,
    /// Expired before execution.
    Expired,
    /// Claimed by one execution worker.
    Executing,
    /// Remote execution succeeded.
    Succeeded,
    /// Remote outcome must be reconciled.
    ReconciliationRequired,
    /// Execution failed conclusively.
    Failed,
}

/// Closed connector family stored on an external action proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalConnector {
    /// Microsoft Graph account used only for Outlook draft operations.
    MicrosoftGraph,
    /// Google Drive account used for document operations.
    GoogleDrive,
    /// Core CRM account used for CRM mutations.
    CoreCrm,
}

impl ExternalConnector {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::MicrosoftGraph => "microsoft_graph",
            Self::GoogleDrive => "google_drive",
            Self::CoreCrm => "core_crm",
        }
    }

    pub(crate) fn from_db(value: &str) -> crate::Result<Self> {
        match value {
            "microsoft_graph" => Ok(Self::MicrosoftGraph),
            "google_drive" => Ok(Self::GoogleDrive),
            "core_crm" => Ok(Self::CoreCrm),
            _ => Err(crate::DbError::InvalidData(format!(
                "unknown external connector {value:?}"
            ))),
        }
    }
}

/// Closed positive set of permitted external operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalOperation {
    /// Add a CRM note.
    CrmAddNote,
    /// Log CRM activity.
    CrmLogActivity,
    /// Create a CRM contact.
    CrmCreateContact,
    /// Update a CRM contact.
    CrmUpdateContact,
    /// Create a CRM company.
    CrmCreateCompany,
    /// Update a CRM company.
    CrmUpdateCompany,
    /// Create a manual CRM task.
    CrmCreateManualTask,
    /// Update a manual CRM task.
    CrmUpdateManualTask,
    /// Complete a manual CRM task.
    CrmCompleteManualTask,
    /// Create a CRM project.
    CrmCreateProject,
    /// Update a CRM project.
    CrmUpdateProject,
    /// Add a CRM tag.
    CrmAddTag,
    /// Link a Granola record in CRM.
    CrmLinkGranolaRecord,
    /// Create an Outlook draft.
    OutlookCreateDraft,
    /// Update a Buzz-owned Outlook draft.
    OutlookUpdateBuzzOwnedDraft,
    /// Attach an existing file to an Outlook draft.
    OutlookAttachExistingFile,
    /// Attach a Drive link to an Outlook draft.
    OutlookAttachDriveLink,
    /// Create a Google document.
    GoogleCreateDoc,
    /// Create a Google sheet.
    GoogleCreateSheet,
    /// Create a simple Google slides deck.
    GoogleCreateSimpleSlides,
    /// Edit a Google document.
    GoogleEditDoc,
    /// Edit a Google sheet range.
    GoogleEditSheetRange,
    /// Replace text in Google slides.
    GoogleReplaceSlidesText,
}

impl ExternalOperation {
    /// Parse an exact protocol wire name without a generic fallback.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        Some(match value {
            "crm/add_note" => Self::CrmAddNote,
            "crm/log_activity" => Self::CrmLogActivity,
            "crm/create_contact" => Self::CrmCreateContact,
            "crm/update_contact" => Self::CrmUpdateContact,
            "crm/create_company" => Self::CrmCreateCompany,
            "crm/update_company" => Self::CrmUpdateCompany,
            "crm/create_manual_task" => Self::CrmCreateManualTask,
            "crm/update_manual_task" => Self::CrmUpdateManualTask,
            "crm/complete_manual_task" => Self::CrmCompleteManualTask,
            "crm/create_project" => Self::CrmCreateProject,
            "crm/update_project" => Self::CrmUpdateProject,
            "crm/add_tag" => Self::CrmAddTag,
            "crm/link_granola_record" => Self::CrmLinkGranolaRecord,
            "outlook/create_draft" => Self::OutlookCreateDraft,
            "outlook/update_buzz_owned_draft" => Self::OutlookUpdateBuzzOwnedDraft,
            "outlook/attach_existing_file" => Self::OutlookAttachExistingFile,
            "outlook/attach_drive_link" => Self::OutlookAttachDriveLink,
            "google/create_doc" => Self::GoogleCreateDoc,
            "google/create_sheet" => Self::GoogleCreateSheet,
            "google/create_simple_slides" => Self::GoogleCreateSimpleSlides,
            "google/edit_doc" => Self::GoogleEditDoc,
            "google/edit_sheet_range" => Self::GoogleEditSheetRange,
            "google/replace_slides_text" => Self::GoogleReplaceSlidesText,
            _ => return None,
        })
    }

    /// Exact protocol wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CrmAddNote => "crm/add_note",
            Self::CrmLogActivity => "crm/log_activity",
            Self::CrmCreateContact => "crm/create_contact",
            Self::CrmUpdateContact => "crm/update_contact",
            Self::CrmCreateCompany => "crm/create_company",
            Self::CrmUpdateCompany => "crm/update_company",
            Self::CrmCreateManualTask => "crm/create_manual_task",
            Self::CrmUpdateManualTask => "crm/update_manual_task",
            Self::CrmCompleteManualTask => "crm/complete_manual_task",
            Self::CrmCreateProject => "crm/create_project",
            Self::CrmUpdateProject => "crm/update_project",
            Self::CrmAddTag => "crm/add_tag",
            Self::CrmLinkGranolaRecord => "crm/link_granola_record",
            Self::OutlookCreateDraft => "outlook/create_draft",
            Self::OutlookUpdateBuzzOwnedDraft => "outlook/update_buzz_owned_draft",
            Self::OutlookAttachExistingFile => "outlook/attach_existing_file",
            Self::OutlookAttachDriveLink => "outlook/attach_drive_link",
            Self::GoogleCreateDoc => "google/create_doc",
            Self::GoogleCreateSheet => "google/create_sheet",
            Self::GoogleCreateSimpleSlides => "google/create_simple_slides",
            Self::GoogleEditDoc => "google/edit_doc",
            Self::GoogleEditSheetRange => "google/edit_sheet_range",
            Self::GoogleReplaceSlidesText => "google/replace_slides_text",
        }
    }

    pub(crate) const fn connector(self) -> ExternalConnector {
        match self {
            Self::CrmAddNote
            | Self::CrmLogActivity
            | Self::CrmCreateContact
            | Self::CrmUpdateContact
            | Self::CrmCreateCompany
            | Self::CrmUpdateCompany
            | Self::CrmCreateManualTask
            | Self::CrmUpdateManualTask
            | Self::CrmCompleteManualTask
            | Self::CrmCreateProject
            | Self::CrmUpdateProject
            | Self::CrmAddTag
            | Self::CrmLinkGranolaRecord => ExternalConnector::CoreCrm,
            Self::OutlookCreateDraft
            | Self::OutlookUpdateBuzzOwnedDraft
            | Self::OutlookAttachExistingFile
            | Self::OutlookAttachDriveLink => ExternalConnector::MicrosoftGraph,
            Self::GoogleCreateDoc
            | Self::GoogleCreateSheet
            | Self::GoogleCreateSimpleSlides
            | Self::GoogleEditDoc
            | Self::GoogleEditSheetRange
            | Self::GoogleReplaceSlidesText => ExternalConnector::GoogleDrive,
        }
    }

    pub(crate) const fn is_create(self) -> bool {
        matches!(
            self,
            Self::CrmCreateContact
                | Self::CrmCreateCompany
                | Self::CrmCreateManualTask
                | Self::CrmCreateProject
                | Self::OutlookCreateDraft
                | Self::GoogleCreateDoc
                | Self::GoogleCreateSheet
                | Self::GoogleCreateSimpleSlides
        )
    }
}

impl ActionProposalStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Executing => "executing",
            Self::Succeeded => "succeeded",
            Self::ReconciliationRequired => "reconciliation_required",
            Self::Failed => "failed",
        }
    }
}

/// Pure decision for an external-action execution claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionClaimDecision {
    /// The exact approved row may be claimed.
    Claim,
    /// The proposal is at or beyond its expiry instant.
    Expired,
    /// The proposal state is not eligible.
    NotApproved,
    /// A worker already claimed the proposal.
    AlreadyClaimed,
}

/// Outcome of the atomic durable decision compare-and-swap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionDecisionRecordOutcome {
    /// Exact proposal and every member moved to approved.
    Approved,
    /// Exact proposal and every member moved permanently to denied.
    Denied,
    /// Proposal expired before the signed decision could be applied.
    Expired,
    /// Binding, pair, membership, replay, or state validation failed closed.
    Rejected,
}

impl ActionClaimDecision {
    /// Evaluate approval, expiry, and one-time claim state.
    #[must_use]
    pub fn evaluate(
        status: ActionProposalStatus,
        expires_at: DateTime<Utc>,
        already_claimed: bool,
        now: DateTime<Utc>,
    ) -> Self {
        if status != ActionProposalStatus::Approved {
            Self::NotApproved
        } else if expires_at.timestamp_micros() <= now.timestamp_micros() {
            Self::Expired
        } else if already_claimed {
            Self::AlreadyClaimed
        } else {
            Self::Claim
        }
    }
}

/// One immutable member of an approved external-action bundle.
#[derive(Clone, PartialEq, Eq)]
pub struct ActionExecutionItem {
    /// Zero-based position committed by the proposal bundle hash.
    pub item_index: i16,
    /// Stable UUIDv4 protocol member identifier.
    pub operation_id: Uuid,
    /// Connector account whose approved scope authorizes this member.
    pub account_id: Uuid,
    /// Approved connector scope, such as a Google destination folder.
    pub scope_id: Uuid,
    /// Typed connector for this member.
    pub connector: ExternalConnector,
    /// Typed positive operation for this member.
    pub operation: ExternalOperation,
    /// Hash of the exact remote resource targeted by this member.
    pub target_hash: Vec<u8>,
    /// Exact canonical operation bytes approved by the signer.
    pub canonical_operation: Vec<u8>,
    /// Hash bound to the canonical operation.
    pub canonical_operation_hash: Vec<u8>,
    /// Optional hash of the state shown before execution.
    pub before_hash: Option<Vec<u8>>,
    /// Hash of the state expected after execution.
    pub after_hash: Vec<u8>,
    /// Expected provider version for optimistic concurrency.
    pub expected_remote_version: Option<String>,
    /// Stable provider idempotency key unique to this member.
    pub idempotency_key: Uuid,
    /// Hash binding this member's position, target, operation, and versions.
    pub member_hash: Vec<u8>,
}

impl std::fmt::Debug for ActionExecutionItem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActionExecutionItem")
            .field("item_index", &self.item_index)
            .field("connector", &self.connector)
            .field("operation", &self.operation)
            .field("canonical_operation", &"<redacted>")
            .field("identifiers_and_hashes", &"<redacted>")
            .finish()
    }
}

/// Exact immutable values returned to the sole action executor.
#[derive(Clone, PartialEq, Eq)]
pub struct ActionExecutionClaim {
    /// Tenant owning the action.
    pub community_id: CommunityId,
    /// Proposal identifier.
    pub proposal_id: Uuid,
    /// Unique one-time claim identifier.
    pub claim_id: Uuid,
    /// Stable signed decision identifier needed by the receipt payload.
    pub decision_id: Uuid,
    /// Owner and expected approving public key.
    pub owner_pubkey: Vec<u8>,
    /// Broker/agent public key addressed by the signed decision.
    pub broker_pubkey: Vec<u8>,
    /// Private channel that scoped the signed decision.
    pub channel_id: Uuid,
    /// Exact RFC8785 canonical proposal bytes approved by the signer.
    pub canonical_proposal: Vec<u8>,
    /// Frozen protocol hash of `canonical_proposal`.
    pub operation_hash: Vec<u8>,
    /// Hash binding the complete ordered member list.
    pub ordered_members_hash: Vec<u8>,
    /// Number of members committed by the proposal.
    pub member_count: i16,
    /// Ordered, individually bound operations in the approved bundle.
    pub items: Vec<ActionExecutionItem>,
    /// One-time nonce bound to the proposal.
    pub nonce: Uuid,
    /// Signed canonical proposal time.
    pub proposed_at: DateTime<Utc>,
    /// Proposal expiry time.
    pub expires_at: DateTime<Utc>,
    /// Public key that approved the proposal.
    pub signer_pubkey: Vec<u8>,
    /// Hash of the signed decision event.
    pub decision_event_hash: Vec<u8>,
}

impl std::fmt::Debug for ActionExecutionClaim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActionExecutionClaim")
            .field("identifiers_pubkeys_hashes", &"<redacted>")
            .field("canonical_proposal", &"<redacted>")
            .field("member_count", &self.member_count)
            .field("items", &self.items)
            .field("proposed_at", &self.proposed_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Durable proof that exactly one provider call may now begin for a member.
#[derive(Clone, PartialEq, Eq)]
pub struct ActionRemoteAttempt {
    /// Internal attempt identifier used to bind the durable outcome.
    pub attempt_id: Uuid,
    /// Ordered member receiving the sole provider dispatch.
    pub item_index: i16,
}

impl std::fmt::Debug for ActionRemoteAttempt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActionRemoteAttempt")
            .field("attempt_id", &"<redacted>")
            .field("item_index", &self.item_index)
            .finish()
    }
}

/// Closed durable outcome for one external-action member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionMemberOutcome {
    /// Provider conclusively committed the operation.
    Succeeded,
    /// A pre-dispatch check or provider conclusively rejected the operation.
    Failed,
    /// A dispatched operation has an ambiguous remote result.
    ReconciliationRequired,
}

impl ActionMemberOutcome {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::ReconciliationRequired => "reconciliation_required",
        }
    }

    pub(crate) fn from_db(value: &str) -> crate::Result<Self> {
        match value {
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "reconciliation_required" => Ok(Self::ReconciliationRequired),
            _ => Err(crate::DbError::InvalidData(
                "unknown external action outcome".into(),
            )),
        }
    }
}

/// Exact durable outcome recorded after a pre-check or one provider dispatch.
#[derive(Clone, PartialEq, Eq)]
pub struct NewActionMemberOutcome {
    /// Parent proposal.
    pub proposal_id: Uuid,
    /// One-time bundle claim.
    pub claim_id: Uuid,
    /// Ordered member index.
    pub item_index: i16,
    /// Attempt ID, absent only for a deterministic pre-dispatch failure.
    pub attempt_id: Option<Uuid>,
    /// Bound operation UUIDv4.
    pub operation_id: Uuid,
    /// Bound member hash.
    pub member_hash: Vec<u8>,
    /// Opaque provider result identifier, required only for success.
    pub remote_result_id: Option<String>,
    /// Provider version after success.
    pub remote_version: Option<String>,
    /// Optional hash of the provider resource identifier.
    pub remote_resource_id_hash: Option<Vec<u8>>,
    /// Closed final or reconciliation outcome.
    pub outcome: ActionMemberOutcome,
    /// Explicit durable observation time.
    pub occurred_at: DateTime<Utc>,
}

impl std::fmt::Debug for NewActionMemberOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NewActionMemberOutcome")
            .field("identifiers_hashes", &"<redacted>")
            .field("item_index", &self.item_index)
            .field("has_attempt", &self.attempt_id.is_some())
            .field("remote_result", &"<redacted>")
            .field("outcome", &self.outcome)
            .finish()
    }
}

/// One immutable member projected into a receipt publication.
#[derive(Clone, PartialEq, Eq)]
pub struct ActionReceiptPublicationItem {
    /// Bound operation UUIDv4.
    pub operation_id: Uuid,
    /// Bound member hash.
    pub operation_hash: Vec<u8>,
    /// Provider idempotency key approved for this member.
    pub idempotency_key: Uuid,
    /// Final or reconciliation outcome.
    pub outcome: ActionMemberOutcome,
    /// Opaque provider result identifier.
    pub external_result_id: Option<String>,
    /// Provider result version.
    pub external_result_version: Option<String>,
    /// Durable reconciliation posture.
    pub reconciliation_status: String,
}

impl std::fmt::Debug for ActionReceiptPublicationItem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActionReceiptPublicationItem")
            .field("identifiers_hashes", &"<redacted>")
            .field("outcome", &self.outcome)
            .field("external_result", &"<redacted>")
            .field("reconciliation_status", &self.reconciliation_status)
            .finish()
    }
}

/// Crash-safe durable receipt payload projection claimed for event signing.
#[derive(Clone, PartialEq, Eq)]
pub struct ActionReceiptPublication {
    /// One-time lease claim required to complete or retry publication.
    pub publish_claim_id: Uuid,
    /// Stable receipt UUIDv4.
    pub receipt_id: Uuid,
    /// Parent proposal UUIDv4.
    pub proposal_id: Uuid,
    /// Signed decision UUIDv4.
    pub decision_id: Uuid,
    /// Private channel carrying the receipt event.
    pub channel_id: Uuid,
    /// Owner recipient of the broker-signed receipt.
    pub owner_pubkey: Vec<u8>,
    /// Registered broker expected to sign the receipt.
    pub broker_pubkey: Vec<u8>,
    /// Exact canonical proposal hash.
    pub operation_hash: Vec<u8>,
    /// Ordered one-for-one member results.
    pub results: Vec<ActionReceiptPublicationItem>,
    /// Durable outcome timestamp.
    pub occurred_at: DateTime<Utc>,
}

impl std::fmt::Debug for ActionReceiptPublication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActionReceiptPublication")
            .field("identifiers_hashes", &"<redacted>")
            .field("result_count", &self.results.len())
            .field("results", &self.results)
            .field("occurred_at", &self.occurred_at)
            .finish()
    }
}

/// Durable external action proposal.
#[derive(Clone, PartialEq, Eq)]
pub struct ExternalActionProposalRecord {
    /// Tenant owning the proposal.
    pub community_id: CommunityId,
    /// Proposal identifier.
    pub id: Uuid,
    /// Owner and expected approving public key.
    pub owner_pubkey: Vec<u8>,
    /// Broker/agent public key snapshot bound to the proposal.
    pub broker_pubkey: Vec<u8>,
    /// Private channel that scopes the decision.
    pub channel_id: Uuid,
    /// Exact RFC8785 canonical proposal bytes approved by the signer.
    pub canonical_proposal: Vec<u8>,
    /// Frozen protocol hash of `canonical_proposal`.
    pub operation_hash: Vec<u8>,
    /// Hash binding the complete ordered member list.
    pub ordered_members_hash: Vec<u8>,
    /// Number of ordered members in the bundle.
    pub member_count: i16,
    /// Ordered, individually bound operations.
    pub items: Vec<ActionExecutionItem>,
    /// One-time nonce.
    pub nonce: Uuid,
    /// Signed canonical proposal time.
    pub proposed_at: DateTime<Utc>,
    /// Expiry timestamp.
    pub expires_at: DateTime<Utc>,
    /// Proposal state.
    pub status: ActionProposalStatus,
    /// Hash of the signed decision event after approval or rejection.
    pub decision_event_hash: Option<Vec<u8>>,
}

impl std::fmt::Debug for ExternalActionProposalRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExternalActionProposalRecord")
            .field("identifiers_pubkeys_hashes", &"<redacted>")
            .field("canonical_proposal", &"<redacted>")
            .field("member_count", &self.member_count)
            .field("items", &self.items)
            .field("status", &self.status)
            .finish()
    }
}

/// A proposed member whose position is derived from its place in the bundle.
#[derive(Clone, PartialEq, Eq)]
pub struct NewExternalActionProposalItem {
    /// Stable UUIDv4 protocol member identifier.
    pub operation_id: Uuid,
    /// Connector account authorized for this member.
    pub account_id: Uuid,
    /// Approved connector scope, such as a destination folder.
    pub scope_id: Uuid,
    /// Typed connector for the account.
    pub connector: ExternalConnector,
    /// Closed positive operation.
    pub operation: ExternalOperation,
    /// Hash of the exact remote resource targeted by this member.
    pub target_hash: Vec<u8>,
    /// Canonical operation bytes shown for approval.
    pub canonical_operation: Vec<u8>,
    /// Hash of the canonical operation.
    pub canonical_operation_hash: Vec<u8>,
    /// Optional hash of existing remote state.
    pub before_hash: Option<Vec<u8>>,
    /// Required hash of expected remote state after the mutation.
    pub after_hash: Vec<u8>,
    /// Expected provider version for optimistic concurrency.
    pub expected_remote_version: Option<String>,
    /// UUIDv4 idempotency key unique to this member.
    pub idempotency_key: Uuid,
    /// Hash binding position, target, operation, versions, and idempotency.
    pub member_hash: Vec<u8>,
}

impl std::fmt::Debug for NewExternalActionProposalItem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NewExternalActionProposalItem")
            .field("connector", &self.connector)
            .field("operation", &self.operation)
            .field("canonical_operation", &"<redacted>")
            .field("identifiers_versions_hashes", &"<redacted>")
            .finish()
    }
}

/// A complete proposed cross-provider action bundle inserted atomically.
#[derive(Clone, PartialEq, Eq)]
pub struct NewExternalActionProposal {
    /// Caller-selected proposal identifier.
    pub id: Uuid,
    /// Owner whose private-channel decision is required.
    pub owner_pubkey: Vec<u8>,
    /// Broker/agent that the decision must address.
    pub broker_pubkey: Vec<u8>,
    /// Private channel authorizing both owner and broker.
    pub channel_id: Uuid,
    /// Exact RFC8785 canonical proposal bytes shown for approval.
    pub canonical_proposal: Vec<u8>,
    /// Frozen protocol hash of `canonical_proposal`.
    pub operation_hash: Vec<u8>,
    /// Hash binding the exact ordered member set.
    pub ordered_members_hash: Vec<u8>,
    /// One-time proposal nonce.
    pub nonce: Uuid,
    /// Signed canonical proposal time; never replaced by insertion time.
    pub proposed_at: DateTime<Utc>,
    /// Short proposal expiry.
    pub expires_at: DateTime<Utc>,
    /// Ordered bundle members; the storage layer derives indices and count.
    pub items: Vec<NewExternalActionProposalItem>,
}

impl std::fmt::Debug for NewExternalActionProposal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NewExternalActionProposal")
            .field("identifiers_pubkeys_hashes", &"<redacted>")
            .field("canonical_proposal", &"<redacted>")
            .field("item_count", &self.items.len())
            .finish()
    }
}

/// Durable external action attempt metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct ExternalActionAttemptRecord {
    /// Tenant owning the attempt.
    pub community_id: CommunityId,
    /// Attempt identifier.
    pub id: Uuid,
    /// Parent proposal identifier.
    pub proposal_id: Uuid,
    /// Ordered bundle member attempted.
    pub item_index: i16,
    /// One-time execution claim identifier.
    pub claim_id: Uuid,
    /// Monotonic attempt number.
    pub attempt_number: i32,
    /// Typed remote outcome.
    pub outcome: String,
}

impl std::fmt::Debug for ExternalActionAttemptRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExternalActionAttemptRecord")
            .field("identifiers", &"<redacted>")
            .field("item_index", &self.item_index)
            .field("attempt_number", &self.attempt_number)
            .field("outcome", &self.outcome)
            .finish()
    }
}

/// Durable action receipt and reconciliation metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct ExternalActionReceiptRecord {
    /// Tenant owning the receipt.
    pub community_id: CommunityId,
    /// Receipt identifier.
    pub id: Uuid,
    /// Parent proposal identifier.
    pub proposal_id: Uuid,
    /// Ordered bundle member receiving the outcome.
    pub item_index: i16,
    /// Stable protocol member identifier copied into the receipt binding.
    pub operation_id: Uuid,
    /// Approved member hash copied into the receipt binding.
    pub member_hash: Vec<u8>,
    /// Parent attempt identifier.
    pub attempt_id: Uuid,
    /// Bounded provider-scoped opaque result identifier.
    pub remote_result_id: Option<String>,
    /// Provider version returned with the result.
    pub remote_version: Option<String>,
    /// Typed remote outcome.
    pub outcome: String,
    /// Reconciliation lifecycle state.
    pub reconciliation_state: String,
}

impl std::fmt::Debug for ExternalActionReceiptRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExternalActionReceiptRecord")
            .field("identifiers_hashes", &"<redacted>")
            .field("item_index", &self.item_index)
            .field("remote_result", &"<redacted>")
            .field("outcome", &self.outcome)
            .field("reconciliation_state", &self.reconciliation_state)
            .finish()
    }
}

/// Pure result of checking a cursor lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaLeaseDecision {
    /// The lease can be acquired or recovered.
    Claim,
    /// Another worker holds an unexpired lease.
    Busy,
}

impl DeltaLeaseDecision {
    /// Evaluate a lease using an explicit database time.
    #[must_use]
    pub fn evaluate(
        lease_owner: Option<Uuid>,
        lease_until: Option<DateTime<Utc>>,
        _worker_id: Uuid,
        now: DateTime<Utc>,
    ) -> Self {
        if lease_until.is_some_and(|until| until > now) && lease_owner.is_some() {
            Self::Busy
        } else {
            Self::Claim
        }
    }
}

/// Claimed encrypted cursor and fencing generation.
#[derive(Clone, PartialEq, Eq)]
pub struct DeltaLeaseClaim {
    /// Application-encrypted cursor bytes.
    pub encrypted_cursor: Vec<u8>,
    /// Integrity hash for the encrypted bytes.
    pub cursor_integrity_hash: Vec<u8>,
    /// Encryption key version.
    pub cursor_key_version: i32,
    /// Fencing generation required by completion.
    pub generation: i64,
    /// Bounded lease expiry.
    pub lease_until: DateTime<Utc>,
}

/// One globally due read-only Core CRM cursor claimed with its complete server authority.
#[derive(Clone, PartialEq, Eq)]
pub struct CoreCrmDeltaScopeClaim {
    /// Tenant owning the claimed cursor.
    pub community_id: CommunityId,
    /// Connector account boundary.
    pub account_id: Uuid,
    /// Approved source-scope boundary.
    pub scope_id: Uuid,
    /// Configured cursor stream.
    pub stream: String,
    /// Private account owner receiving the indexed source ACL.
    pub owner_pubkey: Vec<u8>,
    /// Fenced encrypted cursor lease.
    pub lease: DeltaLeaseClaim,
}

impl std::fmt::Debug for CoreCrmDeltaScopeClaim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CoreCrmDeltaScopeClaim")
            .field("stream", &self.stream)
            .field("generation", &self.lease.generation)
            .field("authority_cursor_and_owner_redacted", &true)
            .finish()
    }
}

impl std::fmt::Debug for DeltaLeaseClaim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeltaLeaseClaim")
            .field("encrypted_cursor_and_integrity_redacted", &true)
            .field("cursor_bytes", &self.encrypted_cursor.len())
            .field("cursor_key_version", &self.cursor_key_version)
            .field("generation", &self.generation)
            .field("lease_until", &self.lease_until)
            .finish()
    }
}

/// Positive-ACL-filtered citation result.
#[derive(Clone, PartialEq, Eq)]
pub struct SourceCitationRecord {
    /// Local source item identifier.
    pub item_id: Uuid,
    /// Local source chunk identifier.
    pub chunk_id: Uuid,
    /// Connector account identifier used in the stable authority key.
    pub account_id: Uuid,
    /// Approved source scope used in the stable authority key.
    pub scope_id: Uuid,
    /// Immutable provider-side item identifier.
    pub external_item_id: String,
    /// Closed connector provider.
    pub provider: String,
    /// Source title.
    pub title: String,
    /// Typed source kind.
    pub source_type: String,
    /// Provider modification time.
    pub modified_at: DateTime<Utc>,
    /// Stable resolvable source link.
    pub resolvable_link: String,
    /// Provider version used for authorization rechecks.
    pub remote_version: String,
    /// Optional provider ETag used for authorization rechecks.
    pub remote_etag: Option<String>,
    /// Chunk hash used for post-ranking citation checks.
    pub chunk_hash: Vec<u8>,
    /// Exact active local embedding version used for the retrieval.
    pub embedding_version_id: Uuid,
    /// Inclusive Unicode-scalar offset in normalized source text.
    pub start_char: i64,
    /// Exclusive Unicode-scalar offset in normalized source text.
    pub end_char: i64,
}

/// Server-authenticated source retrieval audience.
///
/// Channel identifiers are only a server-resolved request subset. Storage
/// always rejoins them to current membership and never treats them as grants.
#[derive(Clone, Copy)]
pub struct ServerResolvedSourceAudience<'a> {
    requester_pubkey: &'a [u8],
    authorized_channel_ids: &'a [Uuid],
}

impl<'a> ServerResolvedSourceAudience<'a> {
    /// Bind an authenticated caller to channels resolved by the server.
    #[must_use]
    pub const fn new(requester_pubkey: &'a [u8], authorized_channel_ids: &'a [Uuid]) -> Self {
        Self {
            requester_pubkey,
            authorized_channel_ids,
        }
    }

    pub(super) const fn requester_pubkey(self) -> &'a [u8] {
        self.requester_pubkey
    }

    pub(super) const fn authorized_channel_ids(self) -> &'a [Uuid] {
        self.authorized_channel_ids
    }
}

impl std::fmt::Debug for ServerResolvedSourceAudience<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServerResolvedSourceAudience")
            .field("caller_redacted", &true)
            .field("channel_count", &self.authorized_channel_ids.len())
            .finish()
    }
}

/// Content-free full-text candidate that does not require an embedding model.
#[derive(Clone, PartialEq, Eq)]
pub struct SourceFtsCitationRecord {
    /// Local source item identifier.
    pub item_id: Uuid,
    /// Local source chunk identifier.
    pub chunk_id: Uuid,
    /// Connector account identifier used in the stable authority key.
    pub account_id: Uuid,
    /// Approved source scope used in the stable authority key.
    pub scope_id: Uuid,
    /// Immutable provider-side item identifier.
    pub external_item_id: String,
    /// Closed connector provider wire value.
    pub provider: String,
    /// Source title.
    pub title: String,
    /// Typed source kind wire value.
    pub source_type: String,
    /// Provider modification time.
    pub modified_at: DateTime<Utc>,
    /// Stable resolvable source link.
    pub resolvable_link: String,
    /// Provider version used for authorization rechecks.
    pub remote_version: String,
    /// Optional provider ETag used for authorization rechecks.
    pub remote_etag: Option<String>,
    /// Chunk hash used for post-ranking checks.
    pub chunk_hash: Vec<u8>,
    /// Inclusive Unicode-scalar offset in normalized source text.
    pub start_char: i64,
    /// Exclusive Unicode-scalar offset in normalized source text.
    pub end_char: i64,
    /// Whether every configured cursor for this account/scope reconciled
    /// successfully within the server-controlled freshness objective.
    pub reconciliation_fresh: bool,
}

impl std::fmt::Debug for SourceFtsCitationRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceFtsCitationRecord")
            .field("provider", &self.provider)
            .field("source_type", &self.source_type)
            .field("metadata_and_identifiers_redacted", &true)
            .finish()
    }
}

impl std::fmt::Debug for SourceCitationRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceCitationRecord")
            .field("provider", &self.provider)
            .field("source_type", &self.source_type)
            .field("metadata_and_identifiers_redacted", &true)
            .finish()
    }
}

/// One ranked source candidate to re-read after ranking and before disclosure.
#[derive(Clone, Copy)]
pub struct SourceCandidateRecheckRequest<'a> {
    /// Candidate item returned by the pre-authorized rank query.
    pub item_id: Uuid,
    /// Candidate chunk returned by the pre-authorized rank query.
    pub chunk_id: Uuid,
    /// Exact remote version returned by the rank query.
    pub remote_version: &'a str,
    /// Exact optional ETag returned by the rank query.
    pub remote_etag: Option<&'a str>,
    /// Exact chunk hash returned by the rank query.
    pub chunk_hash: &'a [u8],
    /// Exact active local embedding version returned by the rank query.
    pub embedding_version_id: Uuid,
    /// Authenticated requesting user's Buzz public key.
    pub requester_pubkey: &'a [u8],
    /// Request-local channels resolved by the server; membership is rejoined.
    pub authorized_channel_ids: &'a [Uuid],
}

impl std::fmt::Debug for SourceCandidateRecheckRequest<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceCandidateRecheckRequest")
            .field("candidate_and_audience_redacted", &true)
            .field("channel_count", &self.authorized_channel_ids.len())
            .finish()
    }
}

/// Source content returned only after a fresh lifecycle/version/ACL recheck.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizedSourceExcerptRecord {
    /// Local source item identifier.
    pub item_id: Uuid,
    /// Local source chunk identifier.
    pub chunk_id: Uuid,
    /// Connector account identifier.
    pub account_id: Uuid,
    /// Approved source scope identifier.
    pub scope_id: Uuid,
    /// Immutable provider item identifier.
    pub external_item_id: String,
    /// Closed connector provider.
    pub provider: String,
    /// Citation title.
    pub title: String,
    /// Typed source kind.
    pub source_type: String,
    /// Provider modification time.
    pub modified_at: DateTime<Utc>,
    /// Stable provider source link.
    pub resolvable_link: String,
    /// Exact provider version rechecked after ranking.
    pub remote_version: String,
    /// Optional provider ETag rechecked after ranking.
    pub remote_etag: Option<String>,
    /// Exact chunk hash rechecked after ranking.
    pub chunk_hash: Vec<u8>,
    /// Exact local embedding version rechecked before disclosure.
    pub embedding_version_id: Uuid,
    /// Inclusive Unicode-scalar offset in normalized source text.
    pub start_char: i64,
    /// Exclusive Unicode-scalar offset in normalized source text.
    pub end_char: i64,
    /// Authorized source chunk content.
    pub content: String,
    /// Hash of the complete current positive ACL set.
    pub acl_revision: Vec<u8>,
    /// Database timestamp of the authorization recheck.
    pub authorization_checked_at: DateTime<Utc>,
}

/// Source content returned by the embedding-independent FTS recheck only.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizedSourceFtsExcerptRecord {
    /// Local source item identifier.
    pub item_id: Uuid,
    /// Local source chunk identifier.
    pub chunk_id: Uuid,
    /// Connector account identifier.
    pub account_id: Uuid,
    /// Approved source scope identifier.
    pub scope_id: Uuid,
    /// Immutable provider item identifier.
    pub external_item_id: String,
    /// Closed connector provider wire value.
    pub provider: String,
    /// Citation title.
    pub title: String,
    /// Typed source kind wire value.
    pub source_type: String,
    /// Provider modification time.
    pub modified_at: DateTime<Utc>,
    /// Stable provider source link.
    pub resolvable_link: String,
    /// Exact provider version rechecked after ranking.
    pub remote_version: String,
    /// Optional provider ETag rechecked after ranking.
    pub remote_etag: Option<String>,
    /// Exact chunk hash rechecked after ranking.
    pub chunk_hash: Vec<u8>,
    /// Inclusive Unicode-scalar offset in normalized source text.
    pub start_char: i64,
    /// Exclusive Unicode-scalar offset in normalized source text.
    pub end_char: i64,
    /// Authorized bounded source chunk content.
    pub content: String,
    /// Hash of the complete current positive ACL set.
    pub acl_revision: Vec<u8>,
    /// Database timestamp of the authorization recheck.
    pub authorization_checked_at: DateTime<Utc>,
    /// Whether every configured cursor still satisfies the server-controlled
    /// freshness objective at the authorization recheck.
    pub reconciliation_fresh: bool,
}

impl std::fmt::Debug for AuthorizedSourceFtsExcerptRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizedSourceFtsExcerptRecord")
            .field("provider", &self.provider)
            .field("source_type", &self.source_type)
            .field("content_and_metadata_redacted", &true)
            .field("content_characters", &self.content.chars().count())
            .finish()
    }
}

/// Embedding-independent full-text source retrieval request.
#[derive(Clone, Copy, Debug)]
pub struct SourceFtsSearchRequest<'a> {
    /// Full-text query.
    pub query: &'a str,
    /// Server-authenticated request audience.
    pub audience: ServerResolvedSourceAudience<'a>,
    /// Maximum returned candidates.
    pub limit: i64,
}

/// One embedding-independent FTS candidate to re-read before disclosure.
#[derive(Clone, Copy, Debug)]
pub struct SourceFtsCandidateRecheckRequest<'a> {
    /// Candidate item returned by the rank query.
    pub item_id: Uuid,
    /// Candidate chunk returned by the rank query.
    pub chunk_id: Uuid,
    /// Exact remote version returned by the rank query.
    pub remote_version: &'a str,
    /// Exact optional ETag returned by the rank query.
    pub remote_etag: Option<&'a str>,
    /// Exact chunk hash returned by the rank query.
    pub chunk_hash: &'a [u8],
    /// Exact reconciliation state observed during candidate ranking.
    pub reconciliation_fresh: bool,
    /// Server-authenticated request audience.
    pub audience: ServerResolvedSourceAudience<'a>,
}

/// Authorization-bound request to resolve one opaque local evidence locator.
#[derive(Clone, Copy, Debug)]
pub struct EvidenceResolveRequest<'a> {
    /// Opaque tenant-local source item UUID carried by the trusted broker.
    pub item_id: Uuid,
    /// Exact cited source chunk hash.
    pub chunk_hash: &'a [u8],
    /// Exact private channel carrying the resolve request.
    pub channel_id: Uuid,
    /// Server-authenticated direct-user and channel audience.
    pub audience: ServerResolvedSourceAudience<'a>,
}

/// Provider metadata released only after a complete current authorization read.
#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedSourceEvidence {
    /// Human-readable source title.
    pub title: String,
    /// Closed source type wire value.
    pub source_type: String,
    /// Provider modification timestamp.
    pub modified_at: DateTime<Utc>,
    /// Stable provider HTTPS link, validated by the connector layer before use.
    pub resolvable_link: String,
}

impl std::fmt::Debug for ResolvedSourceEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResolvedSourceEvidence")
            .field("source_metadata_redacted", &true)
            .finish()
    }
}

/// Outcome of a current evidence authorization and revision check.
#[derive(Clone, PartialEq, Eq)]
pub enum EvidenceResolution {
    /// Current authority and exact chunk revision matched.
    Resolved(ResolvedSourceEvidence),
    /// The source exists but the requester lacks current positive authority.
    Denied,
    /// The opaque source exists but the cited chunk revision no longer matches.
    Stale,
    /// The source is absent, inactive, tombstoned, or otherwise unavailable.
    Unavailable,
}

impl std::fmt::Debug for EvidenceResolution {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Resolved(_) => "EvidenceResolution::Resolved(<redacted>)",
            Self::Denied => "EvidenceResolution::Denied",
            Self::Stale => "EvidenceResolution::Stale",
            Self::Unavailable => "EvidenceResolution::Unavailable",
        })
    }
}

impl std::fmt::Debug for AuthorizedSourceExcerptRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizedSourceExcerptRecord")
            .field("provider", &self.provider)
            .field("source_type", &self.source_type)
            .field("content_and_metadata_redacted", &true)
            .field("content_characters", &self.content.chars().count())
            .finish()
    }
}

/// Full-text source retrieval request.
#[derive(Clone, Copy)]
pub struct SourceSearchRequest<'a> {
    /// Full-text query.
    pub query: &'a str,
    /// Required active local embedding version for this hybrid retrieval.
    pub embedding_version_id: Uuid,
    /// Requesting user's Buzz public key.
    pub requester_pubkey: &'a [u8],
    /// Explicitly authorized request-local channels.
    pub authorized_channel_ids: &'a [Uuid],
    /// Maximum returned citations.
    pub limit: i64,
}

impl std::fmt::Debug for SourceSearchRequest<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceSearchRequest")
            .field("query_and_audience_redacted", &true)
            .field("query_characters", &self.query.chars().count())
            .field("channel_count", &self.authorized_channel_ids.len())
            .field("limit", &self.limit)
            .finish()
    }
}

/// Local-vector source retrieval request.
#[derive(Clone, Copy)]
pub struct SourceVectorSearchRequest<'a> {
    /// Exactly 384 local embedding values.
    pub embedding: &'a [f32],
    /// Required active embedding version.
    pub embedding_version_id: Uuid,
    /// Requesting user's Buzz public key.
    pub requester_pubkey: &'a [u8],
    /// Explicitly authorized request-local channels.
    pub authorized_channel_ids: &'a [Uuid],
    /// Maximum returned citations.
    pub limit: i64,
}

impl std::fmt::Debug for SourceVectorSearchRequest<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceVectorSearchRequest")
            .field("embedding_and_audience_redacted", &true)
            .field("embedding_dimensions", &self.embedding.len())
            .field("channel_count", &self.authorized_channel_ids.len())
            .field("limit", &self.limit)
            .finish()
    }
}

/// Closed protocol set of learnable domains; policy and permissions are absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LearningDomain {
    /// Ranking preferences only within a policy-approved tier.
    RankingWithinPolicyTier,
    /// Timing within the already allowed feed window.
    TimingWithinAllowedFeedWindow,
    /// Card presentation preferences.
    CardPresentationPreference,
    /// Non-sensitive writing-style traits.
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
    /// Parse an exact protocol wire value; unknown and policy domains fail closed.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        Some(match value {
            "ranking_within_policy_tier" => Self::RankingWithinPolicyTier,
            "timing_within_allowed_feed_window" => Self::TimingWithinAllowedFeedWindow,
            "card_presentation_preference" => Self::CardPresentationPreference,
            "writing_style_traits" => Self::WritingStyleTraits,
            "relationship_priority_hints" => Self::RelationshipPriorityHints,
            "source_quality_weights" => Self::SourceQualityWeights,
            "buyer_selection_heuristics" => Self::BuyerSelectionHeuristics,
            "research_heuristics" => Self::ResearchHeuristics,
            "bounded_workflow_ordering" => Self::BoundedWorkflowOrdering,
            _ => return None,
        })
    }

    /// Exact serialized protocol value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RankingWithinPolicyTier => "ranking_within_policy_tier",
            Self::TimingWithinAllowedFeedWindow => "timing_within_allowed_feed_window",
            Self::CardPresentationPreference => "card_presentation_preference",
            Self::WritingStyleTraits => "writing_style_traits",
            Self::RelationshipPriorityHints => "relationship_priority_hints",
            Self::SourceQualityWeights => "source_quality_weights",
            Self::BuyerSelectionHeuristics => "buyer_selection_heuristics",
            Self::ResearchHeuristics => "research_heuristics",
            Self::BoundedWorkflowOrdering => "bounded_workflow_ordering",
        }
    }
}

/// Encrypted learning candidate or active revision metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LearningRevisionRecord {
    /// Tenant owning the revision.
    pub community_id: CommunityId,
    /// Revision identifier.
    pub id: Uuid,
    /// Personal or sanitized-firm layer.
    pub layer: String,
    /// Personal owner, absent for sanitized-firm learning.
    pub owner_pubkey: Option<Vec<u8>>,
    /// Learning domain.
    pub domain: LearningDomain,
    /// Monotonic domain version.
    pub version: i32,
    /// Application-encrypted revision bundle.
    pub encrypted_bundle: Vec<u8>,
    /// Immutable base-policy version.
    pub base_policy_version: String,
    /// Evidence count.
    pub evidence_count: i32,
    /// Activation, rollback, or quarantine state.
    pub state: String,
}

/// Hashed learning evidence feedback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LearningFeedbackRecord {
    /// Tenant owning the feedback.
    pub community_id: CommunityId,
    /// Feedback identifier.
    pub id: Uuid,
    /// Revision receiving feedback.
    pub revision_id: Uuid,
    /// Hash of the evidence identifier.
    pub evidence_id_hash: Vec<u8>,
    /// Typed feedback outcome.
    pub outcome: String,
    /// Evidence observation time.
    pub occurred_at: DateTime<Utc>,
}

/// Active learning head and rollback target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LearningHeadRecord {
    /// Tenant owning the head.
    pub community_id: CommunityId,
    /// Personal or sanitized-firm layer.
    pub layer: String,
    /// Personal owner, absent for sanitized-firm learning.
    pub owner_pubkey: Option<Vec<u8>>,
    /// Learning domain.
    pub domain: LearningDomain,
    /// Current active revision.
    pub active_revision_id: Uuid,
    /// Optional rollback revision.
    pub rollback_revision_id: Option<Uuid>,
    /// Immutable base-policy version.
    pub base_policy_version: String,
    /// Head activation state.
    pub state: String,
}

/// Closed audit event category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventType {
    /// Identity binding lifecycle change.
    IdentityBindingChanged,
    /// Connector account lifecycle change.
    ConnectorAccountChanged,
    /// Source synchronization outcome.
    SourceSync,
    /// Insight budget claim outcome.
    InsightClaimed,
    /// External action decision.
    ActionProposalDecided,
    /// External action execution outcome.
    ActionExecution,
    /// Learning revision lifecycle change.
    LearningRevisionChanged,
    /// Audit export outcome.
    AuditExport,
}

impl AuditEventType {
    pub(crate) const fn as_str(self) -> &'static str {
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

/// Closed audit entity category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEntityType {
    /// Identity binding.
    IdentityBinding,
    /// Connector account.
    ConnectorAccount,
    /// Approved source scope.
    SourceScope,
    /// Source item.
    SourceItem,
    /// Assistant insight.
    AssistantInsight,
    /// External action proposal.
    ExternalActionProposal,
    /// Learning revision.
    LearningRevision,
    /// Immutable audit checkpoint.
    AuditCheckpoint,
}

impl AuditEntityType {
    pub(crate) const fn as_str(self) -> &'static str {
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

/// Closed audit outcome category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    /// Accepted locally.
    Accepted,
    /// Rejected locally.
    Rejected,
    /// Completed successfully.
    Succeeded,
    /// Failed conclusively.
    Failed,
    /// Remote call timed out.
    Timeout,
    /// Remote state requires reconciliation.
    ReconciliationRequired,
    /// Authorization or object was revoked.
    Revoked,
    /// Source was tombstoned.
    Tombstoned,
    /// Durable operation was scheduled for retry.
    Retried,
}

impl AuditOutcome {
    pub(crate) const fn as_str(self) -> &'static str {
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

/// Bounded non-secret version marker permitted in audit storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditObjectVersion(String);

impl AuditObjectVersion {
    /// Validate a 1-128 byte marker containing only identifier punctuation.
    pub fn new(value: impl Into<String>) -> crate::Result<Self> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= 128
            && value.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_alphanumeric()
                    || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
            });
        if !valid {
            return Err(crate::DbError::InvalidData(
                "audit object version must be a 1-128 byte identifier marker".into(),
            ));
        }
        Ok(Self(value))
    }

    /// Validated marker text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Typed, content-free audit envelope to append.
#[derive(Debug, Clone, Copy)]
pub struct AuditEnvelope<'a> {
    /// Typed event name.
    pub event_type: AuditEventType,
    /// Typed entity name.
    pub entity_type: AuditEntityType,
    /// Entity identifier.
    pub entity_id: Uuid,
    /// Hash of the affected object or canonical operation.
    pub object_hash: &'a [u8],
    /// Optional non-secret version marker.
    pub version: Option<&'a AuditObjectVersion>,
    /// Event timestamp.
    pub occurred_at: DateTime<Utc>,
    /// Typed outcome.
    pub outcome: AuditOutcome,
}

/// One append-only audit outbox entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreAuditOutboxRecord {
    /// Tenant owning the chain.
    pub community_id: CommunityId,
    /// Tenant-leading chain sequence.
    pub sequence: i64,
    /// Typed event name.
    pub event_type: String,
    /// Typed entity name.
    pub entity_type: String,
    /// Entity identifier.
    pub entity_id: Uuid,
    /// Affected object hash.
    pub object_hash: Vec<u8>,
    /// Optional non-secret version marker.
    pub object_version: Option<String>,
    /// Event timestamp.
    pub occurred_at: DateTime<Utc>,
    /// Typed outcome.
    pub outcome: String,
    /// Prior entry hash, absent only for genesis.
    pub prior_entry_hash: Option<Vec<u8>>,
    /// Hash-chain entry hash.
    pub entry_hash: Vec<u8>,
    /// Export-ready signing lifecycle state.
    pub signing_state: String,
    /// Public signing key/version identifier used for rotation.
    pub signer_identifier: Option<String>,
    /// Public 64-byte signature; never a private key.
    pub signature: Option<Vec<u8>>,
    /// Current export retry count.
    pub retry_count: i32,
}

/// Claimed ordered audit export batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditExportBatch {
    /// Claim identifier shared by every batch row.
    pub batch_id: Uuid,
    /// Ordered, contiguous audit entries.
    pub entries: Vec<CoreAuditOutboxRecord>,
    /// Bounded claim expiry.
    pub claim_until: DateTime<Utc>,
}

/// Immutable Blob checkpoint for the exported audit prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreAuditCheckpointRecord {
    /// Tenant owning the chain.
    pub community_id: CommunityId,
    /// Last sequence durably represented by the blob.
    pub last_exported_sequence: i64,
    /// Hash of the last exported entry.
    pub last_entry_hash: Vec<u8>,
    /// Non-secret immutable container/object key.
    pub blob_object_key: String,
    /// Hash of the immutable blob bytes.
    pub blob_content_hash: Vec<u8>,
    /// Immutable blob ETag/version marker.
    pub blob_etag: String,
    /// Checkpoint commit time.
    pub checkpointed_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::{KeyVaultSecretName, LearningDomain};

    #[test]
    fn learning_domain_rejects_policy_and_unknown_values() {
        assert!(LearningDomain::from_wire("permissions").is_none());
        assert!(LearningDomain::from_wire("unknown").is_none());
        assert_eq!(
            LearningDomain::from_wire("bounded_workflow_ordering"),
            Some(LearningDomain::BoundedWorkflowOrdering)
        );
    }

    #[test]
    fn key_vault_reference_rejects_urls_tokens_controls_and_oversize() {
        for invalid in [
            "https://vault.invalid/secrets/name?sig=token",
            "secret?sig=token",
            "secret\nname",
        ] {
            assert!(KeyVaultSecretName::new(invalid).is_err());
        }
        assert!(KeyVaultSecretName::new("a".repeat(128)).is_err());
        assert!(KeyVaultSecretName::new("core-graph-credential").is_ok());
    }
}
