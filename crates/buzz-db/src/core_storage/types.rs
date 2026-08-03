use buzz_core::CommunityId;
use chrono::{DateTime, NaiveDate, Utc};
use uuid::Uuid;

/// Fixed local CPU embedding width used by Month-1 corpora.
pub const EMBEDDING_DIMENSIONS: usize = 384;

/// Validated non-secret Azure Key Vault secret name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyVaultSecretName(String);

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
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Durable connector account metadata without credential values.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Approved external source scope and its granted capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedSourceScopeRecord {
    /// Tenant owning the scope.
    pub community_id: CommunityId,
    /// Scope identifier.
    pub id: Uuid,
    /// Parent connector account identifier.
    pub account_id: Uuid,
    /// Immutable provider-side scope identifier.
    pub external_scope_id: String,
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

/// Current encrypted delta cursor and lease state for a source stream.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Migratable local embedding version metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Stable provider item identity and citation metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Source chunk content, hash, and local embedding metadata.
#[derive(Debug, Clone, PartialEq)]
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

/// Positive source-item ACL principal.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Exact immutable values returned to the sole action executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionExecutionClaim {
    /// Tenant owning the action.
    pub community_id: CommunityId,
    /// Proposal identifier.
    pub proposal_id: Uuid,
    /// Unique one-time claim identifier.
    pub claim_id: Uuid,
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

/// Durable external action proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// A proposed member whose position is derived from its place in the bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// A complete proposed cross-provider action bundle inserted atomically.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Durable external action attempt metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Durable action receipt and reconciliation metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Positive-ACL-filtered citation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceCitationRecord {
    /// Local source item identifier.
    pub item_id: Uuid,
    /// Local source chunk identifier.
    pub chunk_id: Uuid,
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
    /// Chunk hash used for post-ranking citation checks.
    pub chunk_hash: Vec<u8>,
}

/// Full-text source retrieval request.
#[derive(Debug, Clone, Copy)]
pub struct SourceSearchRequest<'a> {
    /// Full-text query.
    pub query: &'a str,
    /// Requesting user's Buzz public key.
    pub requester_pubkey: &'a [u8],
    /// Explicitly authorized request-local channels.
    pub authorized_channel_ids: &'a [Uuid],
    /// Maximum returned citations.
    pub limit: i64,
}

/// Local-vector source retrieval request.
#[derive(Debug, Clone, Copy)]
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
