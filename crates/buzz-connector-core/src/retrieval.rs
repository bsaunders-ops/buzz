//! Hybrid retrieval, post-rank authorization, citations, and minimized context.

use std::{cmp::Ordering, collections::BTreeSet};

use buzz_core::CommunityId;
use buzz_db::core_storage::{
    recheck_source_chunk_fts, search_source_chunks_fts, AuthorizedSourceFtsExcerptRecord,
    ServerResolvedSourceAudience, SourceFtsCandidateRecheckRequest, SourceFtsCitationRecord,
    SourceFtsSearchRequest,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::{
    types::{
        provider_link_is_allowed, ConnectorProvider, ExternalItemId, RemoteVersion, SourceKind,
    },
    ConnectorError, Result,
};

const MAX_QUERY_CHARS: usize = 1_024;
const MAX_RESULTS: usize = 20;
const MAX_EXCERPT_CHARS: usize = 4_000;
const MAX_LINK_BYTES: usize = 8_192;

/// Server-authenticated retrieval audience.
///
/// SQL must still join every supplied channel against current membership; the
/// IDs are a request-local subset and can never grant access by themselves.
#[derive(Clone, PartialEq, Eq)]
pub struct RetrievalAudience {
    caller_pubkey: [u8; 32],
    channel_ids: Vec<Uuid>,
}

impl std::fmt::Debug for RetrievalAudience {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetrievalAudience")
            .field("caller_redacted", &true)
            .field("channel_count", &self.channel_ids.len())
            .finish()
    }
}

impl RetrievalAudience {
    /// Construct from the authenticated signer and server-resolved channels.
    #[must_use]
    pub fn server_resolved(caller_pubkey: [u8; 32], channel_ids: Vec<Uuid>) -> Self {
        let mut channel_ids = channel_ids;
        channel_ids.sort_unstable();
        channel_ids.dedup();
        Self {
            caller_pubkey,
            channel_ids,
        }
    }

    /// Authenticated caller public key.
    #[must_use]
    pub const fn caller_pubkey(&self) -> &[u8; 32] {
        &self.caller_pubkey
    }

    /// Server-resolved request-local channel subset.
    #[must_use]
    pub fn channel_ids(&self) -> &[Uuid] {
        &self.channel_ids
    }
}

/// Bounded hybrid retrieval request.
#[derive(Clone, PartialEq, Eq)]
pub struct RetrievalQuery {
    tenant_id: Uuid,
    audience: RetrievalAudience,
    query: String,
    embedding_version_id: Uuid,
    limit: usize,
}

impl std::fmt::Debug for RetrievalQuery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetrievalQuery")
            .field("query_redacted", &true)
            .field("query_characters", &self.query.chars().count())
            .field("channel_count", &self.audience.channel_ids.len())
            .field("limit", &self.limit)
            .finish()
    }
}

impl RetrievalQuery {
    /// Validate a tenant-scoped search request.
    pub fn new(
        tenant_id: Uuid,
        audience: RetrievalAudience,
        query: impl Into<String>,
        embedding_version_id: Uuid,
        limit: usize,
    ) -> Result<Self> {
        let query = query.into();
        if query.trim().is_empty()
            || query.chars().count() > MAX_QUERY_CHARS
            || query.contains('\0')
        {
            return Err(ConnectorError::InvalidData("retrieval query is invalid"));
        }
        if limit == 0 || limit > MAX_RESULTS {
            return Err(ConnectorError::BoundExceeded("retrieval result count"));
        }
        Ok(Self {
            tenant_id,
            audience,
            query,
            embedding_version_id,
            limit,
        })
    }

    /// Tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    /// Authenticated request audience.
    #[must_use]
    pub const fn audience(&self) -> &RetrievalAudience {
        &self.audience
    }

    /// Search text.
    #[must_use]
    pub fn query(&self) -> &str {
        &self.query
    }

    /// Exact active local embedding version.
    #[must_use]
    pub const fn embedding_version_id(&self) -> Uuid {
        self.embedding_version_id
    }

    /// Maximum authorized excerpts.
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }
}

/// Bounded embedding-independent full-text retrieval request.
#[derive(Clone, PartialEq, Eq)]
pub struct FullTextRetrievalQuery {
    tenant_id: Uuid,
    audience: RetrievalAudience,
    query: String,
    limit: usize,
}

impl std::fmt::Debug for FullTextRetrievalQuery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FullTextRetrievalQuery")
            .field("query_redacted", &true)
            .field("query_characters", &self.query.chars().count())
            .field("channel_count", &self.audience.channel_ids.len())
            .field("limit", &self.limit)
            .finish()
    }
}

impl FullTextRetrievalQuery {
    /// Validate a tenant-scoped FTS request without an embedding version.
    pub fn new(
        tenant_id: Uuid,
        audience: RetrievalAudience,
        query: impl Into<String>,
        limit: usize,
    ) -> Result<Self> {
        let query = query.into();
        if query.trim().is_empty()
            || query.chars().count() > MAX_QUERY_CHARS
            || query.contains('\0')
        {
            return Err(ConnectorError::InvalidData("retrieval query is invalid"));
        }
        if limit == 0 || limit > MAX_RESULTS {
            return Err(ConnectorError::BoundExceeded("retrieval result count"));
        }
        Ok(Self {
            tenant_id,
            audience,
            query,
            limit,
        })
    }

    /// Tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    /// Authenticated request audience.
    #[must_use]
    pub const fn audience(&self) -> &RetrievalAudience {
        &self.audience
    }

    /// Full-text query.
    #[must_use]
    pub fn query(&self) -> &str {
        &self.query
    }

    /// Maximum authorized excerpts.
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }
}

/// Compute the domain-separated stable tenant/account/scope/provider-item
/// authority identity.
pub fn source_item_identity_hash(
    tenant_id: Uuid,
    account_id: Uuid,
    scope_id: Uuid,
    external_item_id: &str,
) -> Result<[u8; 32]> {
    let external_item = ExternalItemId::new(external_item_id)?;
    let external_item_id = external_item.as_str().as_bytes();
    let external_item_bytes = u64::try_from(external_item_id.len())
        .map_err(|_| ConnectorError::BoundExceeded("external item id bytes"))?;
    let mut hasher = Sha256::new();
    hasher.update(b"core-buzz:source-item-identity:v1\0");
    hasher.update(tenant_id.as_bytes());
    hasher.update(account_id.as_bytes());
    hasher.update(scope_id.as_bytes());
    hasher.update(external_item_bytes.to_be_bytes());
    hasher.update(external_item_id);
    Ok(hasher.finalize().into())
}

/// A bounded SQL-preauthorized hybrid candidate without source content.
#[derive(Clone, PartialEq)]
pub struct HybridCandidate {
    /// Stable versioned item identity hash.
    pub item_hash: [u8; 32],
    /// Exact remote-version hash.
    pub version_hash: [u8; 32],
    /// Exact source-chunk hash.
    pub chunk_hash: [u8; 32],
    /// Optional normalized full-text rank.
    pub fts_score: Option<f32>,
    /// Optional normalized local-vector rank.
    pub vector_score: Option<f32>,
}

impl std::fmt::Debug for HybridCandidate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HybridCandidate")
            .field("authority_hashes_redacted", &true)
            .field("fts_score", &self.fts_score)
            .field("vector_score", &self.vector_score)
            .finish()
    }
}

impl HybridCandidate {
    /// Deterministic weighted score. Non-finite or out-of-range ranks fail closed.
    pub fn fused_score(&self) -> Result<f32> {
        fn valid(score: Option<f32>) -> bool {
            score.is_none_or(|value| value.is_finite() && (0.0..=1.0).contains(&value))
        }
        if !valid(self.fts_score) || !valid(self.vector_score) {
            return Err(ConnectorError::InvalidData("hybrid rank score is invalid"));
        }
        let fts = self.fts_score.unwrap_or_default();
        let vector = self.vector_score.unwrap_or_default();
        Ok((fts * 0.55) + (vector * 0.45))
    }
}

/// Deterministically rank bounded hybrid candidates after SQL authorization.
pub fn rank_hybrid(
    mut candidates: Vec<HybridCandidate>,
    limit: usize,
) -> Result<Vec<HybridCandidate>> {
    if limit == 0 || limit > MAX_RESULTS || candidates.len() > 200 {
        return Err(ConnectorError::BoundExceeded("hybrid candidate count"));
    }
    for candidate in &candidates {
        candidate.fused_score()?;
    }
    candidates.sort_by(|left, right| {
        right
            .fused_score()
            .unwrap_or_default()
            .partial_cmp(&left.fused_score().unwrap_or_default())
            .unwrap_or(Ordering::Equal)
            .then_with(|| left.item_hash.cmp(&right.item_hash))
            .then_with(|| left.chunk_hash.cmp(&right.chunk_hash))
    });
    candidates.truncate(limit);
    Ok(candidates)
}

/// Citation freshness at the post-rank authorization read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CitationFreshness {
    /// Provider state was recently reconciled within its configured objective.
    Fresh,
    /// Provider state is older than its objective and clearly labeled.
    Stale,
}

/// Complete evidence metadata returned with every authorized excerpt.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct Citation {
    /// Human-readable source title.
    pub title: String,
    /// Closed connector provider.
    pub provider: ConnectorProvider,
    /// Closed source kind.
    pub source_kind: SourceKind,
    /// Provider modification timestamp.
    pub modified_at: DateTime<Utc>,
    /// Authorization/index as-of timestamp.
    pub as_of: DateTime<Utc>,
    /// Stable resolvable provider link.
    pub resolvable_link: String,
    /// Tenant-leading stable item hash.
    pub item_hash: [u8; 32],
    /// Exact provider version/ETag.
    pub remote_version: RemoteVersion,
    /// Exact version hash.
    pub version_hash: [u8; 32],
    /// Exact chunk hash.
    pub chunk_hash: [u8; 32],
    /// Freshness label.
    pub freshness: CitationFreshness,
}

impl std::fmt::Debug for Citation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Citation")
            .field("provider", &self.provider)
            .field("source_kind", &self.source_kind)
            .field("freshness", &self.freshness)
            .field("title_link_version_redacted", &true)
            .finish()
    }
}

impl Citation {
    /// Validate complete source provenance.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        title: impl Into<String>,
        provider: ConnectorProvider,
        source_kind: SourceKind,
        modified_at: DateTime<Utc>,
        as_of: DateTime<Utc>,
        resolvable_link: impl Into<String>,
        item_hash: [u8; 32],
        remote_version: RemoteVersion,
        chunk_hash: [u8; 32],
        freshness: CitationFreshness,
    ) -> Result<Self> {
        let title = title.into();
        let resolvable_link = resolvable_link.into();
        let link = Url::parse(&resolvable_link)
            .map_err(|_| ConnectorError::InvalidData("citation link is invalid"))?;
        if title.trim().is_empty()
            || title.chars().count() > 1_024
            || title.contains('\0')
            || resolvable_link.len() > MAX_LINK_BYTES
            || resolvable_link.contains('\0')
            || link.scheme() != "https"
            || link.host_str().is_none()
            || !link.username().is_empty()
            || link.password().is_some()
            || !provider_link_is_allowed(provider, &link)
            || modified_at > as_of
        {
            return Err(ConnectorError::InvalidData("citation is invalid"));
        }
        let version_hash = remote_version.digest();
        Ok(Self {
            title,
            provider,
            source_kind,
            modified_at,
            as_of,
            resolvable_link,
            item_hash,
            remote_version,
            version_hash,
            chunk_hash,
            freshness,
        })
    }
}

/// A post-rank reauthorized, turn-minimized source excerpt.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizedExcerpt {
    source_item_id: Option<Uuid>,
    citation: Citation,
    text: String,
    start_char: usize,
    end_char: usize,
}

impl std::fmt::Debug for AuthorizedExcerpt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizedExcerpt")
            .field("citation", &self.citation)
            .field("excerpt_redacted", &true)
            .field("excerpt_characters", &self.text.chars().count())
            .finish()
    }
}

impl AuthorizedExcerpt {
    /// Validate minimized excerpt text and stable source offsets.
    pub fn new(
        citation: Citation,
        text: impl Into<String>,
        start_char: usize,
        end_char: usize,
    ) -> Result<Self> {
        let text = text.into();
        let text_chars = text.chars().count();
        if text.trim().is_empty()
            || text_chars > MAX_EXCERPT_CHARS
            || end_char <= start_char
            || end_char.saturating_sub(start_char) != text_chars
        {
            return Err(ConnectorError::InvalidData("source excerpt is invalid"));
        }
        Ok(Self {
            source_item_id: None,
            citation,
            text,
            start_char,
            end_char,
        })
    }

    /// Complete post-rank citation.
    #[must_use]
    pub const fn citation(&self) -> &Citation {
        &self.citation
    }

    /// Trusted tenant-local source item locator.
    ///
    /// This value is present only for database-authorized retrievals and is
    /// deliberately excluded from model excerpt serialization.
    #[must_use]
    pub const fn source_item_id(&self) -> Option<Uuid> {
        self.source_item_id
    }

    fn new_with_source_item_id(
        source_item_id: Uuid,
        citation: Citation,
        text: impl Into<String>,
        start_char: usize,
        end_char: usize,
    ) -> Result<Self> {
        let mut excerpt = Self::new(citation, text, start_char, end_char)?;
        excerpt.source_item_id = Some(source_item_id);
        Ok(excerpt)
    }

    /// Selected source text only.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Check that a newly authorized read still names the same source version,
    /// metadata, offsets, and bytes. The authorization observation timestamp
    /// is deliberately excluded because every database recheck records a new
    /// `as_of` value even when authority and content are unchanged.
    #[must_use]
    pub fn matches_current_authorized_content(&self, current: &Self) -> bool {
        self.text == current.text
            && self.source_item_id == current.source_item_id
            && self.start_char == current.start_char
            && self.end_char == current.end_char
            && current.citation.as_of >= self.citation.as_of
            && self.citation.title == current.citation.title
            && self.citation.provider == current.citation.provider
            && self.citation.source_kind == current.citation.source_kind
            && self.citation.modified_at == current.citation.modified_at
            && self.citation.resolvable_link == current.citation.resolvable_link
            && self.citation.item_hash == current.citation.item_hash
            && self.citation.remote_version == current.citation.remote_version
            && self.citation.version_hash == current.citation.version_hash
            && self.citation.chunk_hash == current.citation.chunk_hash
            && self.citation.freshness == current.citation.freshness
    }
}

/// Cache identity whose audience and source-version fields force revocation misses.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RetrievalCacheKey {
    tenant_id: Uuid,
    caller_pubkey: [u8; 32],
    channel_audience: Vec<Uuid>,
    acl_revision: [u8; 32],
    item_version: String,
    embedding_version: Uuid,
}

impl std::fmt::Debug for RetrievalCacheKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetrievalCacheKey")
            .field("authority_and_version_redacted", &true)
            .field("channel_count", &self.channel_audience.len())
            .finish()
    }
}

impl RetrievalCacheKey {
    /// Construct a tenant-, caller-, audience-, ACL-, item-, and model-bound key.
    #[must_use]
    pub fn new(
        tenant_id: Uuid,
        caller_pubkey: [u8; 32],
        channel_audience: Vec<Uuid>,
        acl_revision: [u8; 32],
        item_version: impl Into<String>,
        embedding_version: Uuid,
    ) -> Self {
        let mut channel_audience = channel_audience;
        channel_audience.sort_unstable();
        channel_audience.dedup();
        Self {
            tenant_id,
            caller_pubkey,
            channel_audience,
            acl_revision,
            item_version: item_version.into(),
            embedding_version,
        }
    }
}

/// Narrow storage contract: rank content-free candidates only after positive
/// SQL tenant/account/scope/tombstone/user/channel filters, then re-read every
/// selected item and ACL before returning source text.
pub trait AuthorizedRetrievalStore {
    /// SQL-preauthorized content-free candidates.
    fn rank_pre_authorized(&mut self, query: &RetrievalQuery) -> Result<Vec<HybridCandidate>>;
    /// Fresh version/hash/lifecycle/ACL recheck plus query-specific minimization.
    fn recheck_and_minimize(
        &mut self,
        query: &RetrievalQuery,
        candidate: &HybridCandidate,
    ) -> Result<Option<AuthorizedExcerpt>>;
}

/// Perform bounded hybrid ranking followed by an authorization recheck for
/// every excerpt. A candidate that changes or is revoked is silently omitted.
pub fn retrieve_authorized<S: AuthorizedRetrievalStore>(
    store: &mut S,
    query: &RetrievalQuery,
) -> Result<Vec<AuthorizedExcerpt>> {
    let candidates = rank_hybrid(store.rank_pre_authorized(query)?, query.limit())?;
    let mut excerpts = Vec::with_capacity(candidates.len());
    let mut seen = BTreeSet::new();
    for candidate in candidates {
        if !seen.insert((candidate.item_hash, candidate.chunk_hash)) {
            continue;
        }
        if let Some(excerpt) = store.recheck_and_minimize(query, &candidate)? {
            if excerpt.citation.item_hash != candidate.item_hash
                || excerpt.citation.version_hash != candidate.version_hash
                || excerpt.citation.chunk_hash != candidate.chunk_hash
            {
                return Err(ConnectorError::AuthorizationChanged);
            }
            excerpts.push(excerpt);
        }
    }
    Ok(excerpts)
}

/// Fail-closed error from the PostgreSQL FTS retrieval adapter.
#[derive(Debug, Error)]
pub enum PostgresFtsRetrievalError {
    /// Storage rejected or could not complete the authorized read.
    #[error(transparent)]
    Database(#[from] buzz_db::DbError),
    /// Stored metadata violated the connector retrieval contract.
    #[error(transparent)]
    Contract(#[from] ConnectorError),
}

fn provider_from_db(value: &str) -> Result<ConnectorProvider> {
    match value {
        "microsoft_graph" => Ok(ConnectorProvider::MicrosoftGraph),
        "google_drive" => Ok(ConnectorProvider::GoogleDrive),
        "core_crm" => Ok(ConnectorProvider::CoreCrm),
        _ => Err(ConnectorError::InvalidData(
            "stored connector provider is invalid",
        )),
    }
}

fn source_kind_from_db(value: &str) -> Result<SourceKind> {
    match value {
        "email" => Ok(SourceKind::Email),
        "calendar_event" => Ok(SourceKind::CalendarEvent),
        "document" => Ok(SourceKind::Document),
        "spreadsheet" => Ok(SourceKind::Spreadsheet),
        "presentation" => Ok(SourceKind::Presentation),
        "crm_record" => Ok(SourceKind::CrmRecord),
        "crm_transcript" => Ok(SourceKind::CrmTranscript),
        _ => Err(ConnectorError::InvalidData("stored source kind is invalid")),
    }
}

fn candidate_hashes(
    tenant_id: Uuid,
    candidate: &SourceFtsCitationRecord,
) -> Result<([u8; 32], RemoteVersion, [u8; 32])> {
    let item_hash = source_item_identity_hash(
        tenant_id,
        candidate.account_id,
        candidate.scope_id,
        &candidate.external_item_id,
    )?;
    let remote_version = RemoteVersion::new(
        candidate.remote_version.clone(),
        candidate.remote_etag.clone(),
    )?;
    let chunk_hash = candidate
        .chunk_hash
        .as_slice()
        .try_into()
        .map_err(|_| ConnectorError::InvalidData("stored chunk hash is invalid"))?;
    Ok((item_hash, remote_version, chunk_hash))
}

fn excerpt_from_recheck(
    tenant_id: Uuid,
    candidate: &SourceFtsCitationRecord,
    candidate_item_hash: [u8; 32],
    candidate_version: &RemoteVersion,
    candidate_chunk_hash: [u8; 32],
    rechecked: AuthorizedSourceFtsExcerptRecord,
) -> Result<AuthorizedExcerpt> {
    let rechecked_item_hash = source_item_identity_hash(
        tenant_id,
        rechecked.account_id,
        rechecked.scope_id,
        &rechecked.external_item_id,
    )?;
    let rechecked_version = RemoteVersion::new(
        rechecked.remote_version.clone(),
        rechecked.remote_etag.clone(),
    )?;
    let rechecked_chunk_hash: [u8; 32] = rechecked
        .chunk_hash
        .as_slice()
        .try_into()
        .map_err(|_| ConnectorError::InvalidData("stored chunk hash is invalid"))?;
    if rechecked.item_id != candidate.item_id
        || rechecked.chunk_id != candidate.chunk_id
        || rechecked_item_hash != candidate_item_hash
        || rechecked_version != *candidate_version
        || rechecked_chunk_hash != candidate_chunk_hash
        || rechecked.reconciliation_fresh != candidate.reconciliation_fresh
        || rechecked.acl_revision.len() != 32
    {
        return Err(ConnectorError::AuthorizationChanged);
    }
    let citation = Citation::new(
        rechecked.title,
        provider_from_db(&rechecked.provider)?,
        source_kind_from_db(&rechecked.source_type)?,
        rechecked.modified_at,
        rechecked.authorization_checked_at,
        rechecked.resolvable_link,
        rechecked_item_hash,
        rechecked_version,
        rechecked_chunk_hash,
        if rechecked.reconciliation_fresh {
            CitationFreshness::Fresh
        } else {
            CitationFreshness::Stale
        },
    )?;
    let start_char = usize::try_from(rechecked.start_char)
        .map_err(|_| ConnectorError::InvalidData("stored source offsets are invalid"))?;
    let end_char = usize::try_from(rechecked.end_char)
        .map_err(|_| ConnectorError::InvalidData("stored source offsets are invalid"))?;
    AuthorizedExcerpt::new_with_source_item_id(
        rechecked.item_id,
        citation,
        rechecked.content,
        start_char,
        end_char,
    )
}

/// Rank authorized PostgreSQL FTS candidates and re-read every candidate before
/// releasing its already-bounded stored chunk. This path has no embedding or
/// embedding-version dependency.
pub async fn retrieve_authorized_fts(
    pool: &PgPool,
    community_id: CommunityId,
    query: &FullTextRetrievalQuery,
) -> std::result::Result<Vec<AuthorizedExcerpt>, PostgresFtsRetrievalError> {
    if query.tenant_id() != *community_id.as_uuid() {
        return Err(ConnectorError::AuthorizationChanged.into());
    }
    let audience = ServerResolvedSourceAudience::new(
        query.audience().caller_pubkey(),
        query.audience().channel_ids(),
    );
    let limit = i64::try_from(query.limit())
        .map_err(|_| ConnectorError::BoundExceeded("retrieval result count"))?;
    let candidates = search_source_chunks_fts(
        pool,
        community_id,
        SourceFtsSearchRequest {
            query: query.query(),
            audience,
            limit,
        },
    )
    .await?;
    if candidates.len() > query.limit() {
        return Err(ConnectorError::BoundExceeded("retrieval result count").into());
    }

    let mut excerpts = Vec::with_capacity(candidates.len());
    let mut seen = BTreeSet::new();
    for candidate in candidates {
        let (item_hash, remote_version, chunk_hash) =
            candidate_hashes(query.tenant_id(), &candidate)?;
        if !seen.insert((item_hash, chunk_hash)) {
            continue;
        }
        let rechecked = recheck_source_chunk_fts(
            pool,
            community_id,
            SourceFtsCandidateRecheckRequest {
                item_id: candidate.item_id,
                chunk_id: candidate.chunk_id,
                remote_version: remote_version.value(),
                remote_etag: remote_version.etag(),
                chunk_hash: &chunk_hash,
                reconciliation_fresh: candidate.reconciliation_fresh,
                audience,
            },
        )
        .await?;
        if let Some(rechecked) = rechecked {
            excerpts.push(excerpt_from_recheck(
                query.tenant_id(),
                &candidate,
                item_hash,
                &remote_version,
                chunk_hash,
                rechecked,
            )?);
        }
    }
    Ok(excerpts)
}

/// Sink that can receive minimized, authorized, untrusted excerpts only.
pub trait ModelExcerptSink {
    /// Sink-specific error.
    type Error;
    /// Accept one serialized excerpt envelope.
    fn accept(&mut self, excerpt: &str) -> std::result::Result<(), Self::Error>;
}

/// Delivery error preserving serialization failures separately from sink failures.
#[derive(Debug)]
pub enum ModelDeliveryError<E> {
    /// A bounded envelope unexpectedly failed JSON serialization.
    Serialization(serde_json::Error),
    /// The configured model boundary rejected an envelope.
    Sink(E),
}

#[derive(Serialize)]
struct ModelExcerptEnvelope<'a> {
    trust: &'static str,
    citation: &'a Citation,
    excerpt: &'a str,
    start_char: usize,
    end_char: usize,
}

/// Serialize only selected post-rank authorized excerpts to a model boundary.
/// Raw source bodies are not accepted by this API.
pub fn deliver_minimized<S: ModelExcerptSink>(
    sink: &mut S,
    excerpts: &[AuthorizedExcerpt],
) -> std::result::Result<(), ModelDeliveryError<S::Error>> {
    for excerpt in excerpts {
        let envelope = ModelExcerptEnvelope {
            trust: "untrusted_external_source",
            citation: &excerpt.citation,
            excerpt: &excerpt.text,
            start_char: excerpt.start_char,
            end_char: excerpt.end_char,
        };
        let serialized =
            serde_json::to_string(&envelope).map_err(ModelDeliveryError::Serialization)?;
        sink.accept(&serialized).map_err(ModelDeliveryError::Sink)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::RemoteVersion;
    use chrono::TimeZone;

    fn candidate() -> HybridCandidate {
        HybridCandidate {
            item_hash: [1; 32],
            version_hash: RemoteVersion::new("v1", None)
                .expect("valid version")
                .digest(),
            chunk_hash: [2; 32],
            fts_score: Some(1.0),
            vector_score: Some(0.8),
        }
    }

    fn excerpt() -> AuthorizedExcerpt {
        let version = RemoteVersion::new("v1", None).expect("valid version");
        let citation = Citation::new(
            "title",
            ConnectorProvider::GoogleDrive,
            SourceKind::Document,
            Utc.with_ymd_and_hms(2026, 8, 3, 0, 0, 0)
                .single()
                .expect("valid timestamp"),
            Utc.with_ymd_and_hms(2026, 8, 3, 0, 1, 0)
                .single()
                .expect("valid timestamp"),
            "https://drive.google.com/item",
            [1; 32],
            version,
            [2; 32],
            CitationFreshness::Fresh,
        )
        .expect("valid citation");
        AuthorizedExcerpt::new(citation, "authorized", 10, 20).expect("valid excerpt")
    }

    #[test]
    fn post_rank_revocation_race_returns_no_content() {
        struct Store {
            revoked_after_rank: bool,
        }
        impl AuthorizedRetrievalStore for Store {
            fn rank_pre_authorized(
                &mut self,
                _query: &RetrievalQuery,
            ) -> Result<Vec<HybridCandidate>> {
                self.revoked_after_rank = true;
                Ok(vec![candidate()])
            }

            fn recheck_and_minimize(
                &mut self,
                _query: &RetrievalQuery,
                _candidate: &HybridCandidate,
            ) -> Result<Option<AuthorizedExcerpt>> {
                Ok((!self.revoked_after_rank).then(excerpt))
            }
        }
        let query = RetrievalQuery::new(
            Uuid::from_u128(1),
            RetrievalAudience::server_resolved([9; 32], Vec::new()),
            "query",
            Uuid::from_u128(2),
            10,
        )
        .expect("valid query");
        let mut store = Store {
            revoked_after_rank: false,
        };
        assert!(retrieve_authorized(&mut store, &query)
            .expect("retrieval succeeds closed")
            .is_empty());
    }

    #[test]
    fn changed_candidate_hash_fails_closed() {
        struct Store;
        impl AuthorizedRetrievalStore for Store {
            fn rank_pre_authorized(
                &mut self,
                _query: &RetrievalQuery,
            ) -> Result<Vec<HybridCandidate>> {
                Ok(vec![candidate()])
            }
            fn recheck_and_minimize(
                &mut self,
                _query: &RetrievalQuery,
                _candidate: &HybridCandidate,
            ) -> Result<Option<AuthorizedExcerpt>> {
                let mut result = excerpt();
                result.citation.chunk_hash = [8; 32];
                Ok(Some(result))
            }
        }
        let query = RetrievalQuery::new(
            Uuid::from_u128(1),
            RetrievalAudience::server_resolved([9; 32], Vec::new()),
            "query",
            Uuid::from_u128(2),
            10,
        )
        .expect("valid query");
        assert_eq!(
            retrieve_authorized(&mut Store, &query),
            Err(ConnectorError::AuthorizationChanged)
        );
    }
}
