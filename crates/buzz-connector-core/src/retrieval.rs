//! Hybrid retrieval, post-rank authorization, citations, and minimized context.

use std::{cmp::Ordering, collections::BTreeSet};

use chrono::{DateTime, Utc};
use serde::Serialize;
use url::Url;
use uuid::Uuid;

use crate::{
    types::{provider_link_is_allowed, ConnectorProvider, RemoteVersion, SourceKind},
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

    /// Selected source text only.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
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
