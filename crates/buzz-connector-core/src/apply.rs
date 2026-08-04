//! Atomic deterministic `ChangePage` application contracts.

use std::collections::BTreeMap;

use crate::{
    chunk::{chunk_source, ChunkBounds, SourceChunk},
    types::{
        AccountId, AccountStatus, AclPrincipal, ChangePage, ConnectorProvider, EncryptedCursor,
        ExternalItemId, RemoteVersion, ScopeId, ScopeStatus, SourceKind, SourceScopeKind,
    },
    ConnectorError, Result,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Result of applying one deterministic page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// Page and cursor committed together.
    Applied {
        /// Count of changed item identities.
        changed_items: usize,
    },
    /// Exact page retry after its cursor already committed.
    AlreadyApplied,
}

/// Current provider-neutral item projection used by a durable store adapter.
#[derive(Clone, PartialEq, Eq)]
pub struct SnapshotItem {
    remote_version: RemoteVersion,
    title: String,
    source_kind: SourceKind,
    modified_at: DateTime<Utc>,
    resolvable_link: String,
    chunks: Vec<SourceChunk>,
    acls: Vec<AclPrincipal>,
    tombstoned: bool,
}

impl std::fmt::Debug for SnapshotItem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SnapshotItem")
            .field("source_kind", &self.source_kind)
            .field("chunk_count", &self.chunks.len())
            .field("acl_count", &self.acls.len())
            .field("metadata_and_content_redacted", &true)
            .finish()
    }
}

impl SnapshotItem {
    /// Current provider version.
    #[must_use]
    pub const fn remote_version(&self) -> &RemoteVersion {
        &self.remote_version
    }

    /// Whether active index material has been removed.
    #[must_use]
    pub const fn tombstoned(&self) -> bool {
        self.tombstoned
    }

    /// Current citation title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Current typed source kind.
    #[must_use]
    pub const fn source_kind(&self) -> SourceKind {
        self.source_kind
    }

    /// Current provider modification time.
    #[must_use]
    pub const fn modified_at(&self) -> DateTime<Utc> {
        self.modified_at
    }

    /// Current stable provider link.
    #[must_use]
    pub fn resolvable_link(&self) -> &str {
        &self.resolvable_link
    }
}

/// In-memory reference implementation of the transaction contract.
///
/// Durable adapters must perform the same validation and commit item changes,
/// ACL replacements, tombstones, and cursor advancement in one transaction.
#[derive(Clone)]
pub struct ConnectorSnapshot {
    tenant_id: Uuid,
    provider: ConnectorProvider,
    account_id: AccountId,
    scope_id: ScopeId,
    stream: String,
    cursor: EncryptedCursor,
    account_status: AccountStatus,
    scope_status: ScopeStatus,
    scope_kind: SourceScopeKind,
    items: BTreeMap<ExternalItemId, SnapshotItem>,
    last_page_digest: Option<[u8; 32]>,
}

impl std::fmt::Debug for ConnectorSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectorSnapshot")
            .field("provider", &self.provider)
            .field("scope_kind", &self.scope_kind)
            .field("item_count", &self.items.len())
            .field("authority_and_content_redacted", &true)
            .finish()
    }
}

impl ConnectorSnapshot {
    /// Construct one tenant/account/scope/stream projection.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: Uuid,
        provider: ConnectorProvider,
        account_id: AccountId,
        scope_id: ScopeId,
        stream: impl Into<String>,
        cursor: EncryptedCursor,
        account_status: AccountStatus,
        scope_status: ScopeStatus,
        scope_kind: SourceScopeKind,
    ) -> Result<Self> {
        let stream = stream.into();
        if stream.is_empty() || stream.len() > 128 {
            return Err(ConnectorError::InvalidData("delta stream is invalid"));
        }
        Ok(Self {
            tenant_id,
            provider,
            account_id,
            scope_id,
            stream,
            cursor,
            account_status,
            scope_status,
            scope_kind,
            items: BTreeMap::new(),
            last_page_digest: None,
        })
    }

    /// Apply all page effects and its cursor atomically.
    pub fn apply(&mut self, page: &ChangePage) -> Result<ApplyOutcome> {
        if self.account_status != AccountStatus::Active || self.scope_status != ScopeStatus::Active
        {
            return Err(ConnectorError::SourceInactive);
        }
        if page.schema_version() != 1
            || page.tenant_id() != self.tenant_id
            || page.provider() != self.provider
            || page.account_id() != self.account_id
            || page.scope_id() != self.scope_id
            || page.stream() != self.stream
        {
            return Err(ConnectorError::InvalidData("delta page authority mismatch"));
        }
        if self.cursor.integrity_hash() == page.next_cursor().integrity_hash()
            && self.cursor.generation() == page.next_cursor().generation()
            && self.last_page_digest == Some(page.page_digest())
        {
            return Ok(ApplyOutcome::AlreadyApplied);
        }
        if page.previous_cursor_hash() != self.cursor.integrity_hash()
            || page.next_cursor().generation() != self.cursor.generation().saturating_add(1)
        {
            return Err(ConnectorError::CursorConflict);
        }

        let mut next_items = self.items.clone();
        for upsert in page.upserts() {
            let acls = upsert.acls().to_vec();
            let chunks = if acls.is_empty() {
                Vec::new()
            } else {
                chunk_source(upsert.source(), ChunkBounds::month_one())?
            };
            next_items.insert(
                upsert.external_item_id().clone(),
                SnapshotItem {
                    remote_version: upsert.remote_version().clone(),
                    title: upsert.title().to_owned(),
                    source_kind: upsert.source_kind(),
                    modified_at: upsert.modified_at(),
                    resolvable_link: upsert.resolvable_link().to_owned(),
                    chunks,
                    acls,
                    tombstoned: false,
                },
            );
        }
        for tombstone in page.tombstones() {
            if let Some(item) = next_items.get_mut(tombstone.external_item_id()) {
                item.chunks.clear();
                item.acls.clear();
                item.tombstoned = true;
            }
        }

        self.items = next_items;
        self.cursor = page.next_cursor().clone();
        self.last_page_digest = Some(page.page_digest());
        Ok(ApplyOutcome::Applied {
            changed_items: page.upserts().len().saturating_add(page.tombstones().len()),
        })
    }

    /// Current item projection including metadata-only tombstones.
    #[must_use]
    pub const fn items(&self) -> &BTreeMap<ExternalItemId, SnapshotItem> {
        &self.items
    }

    /// All active indexed chunks.
    #[must_use]
    pub fn active_chunks(&self) -> Vec<&SourceChunk> {
        self.items
            .values()
            .filter(|item| !item.tombstoned)
            .flat_map(|item| item.chunks.iter())
            .collect()
    }

    /// All active positive ACL principals.
    #[must_use]
    pub fn active_acls(&self) -> Vec<&AclPrincipal> {
        self.items
            .values()
            .filter(|item| !item.tombstoned)
            .flat_map(|item| item.acls.iter())
            .collect()
    }

    /// Mark the account inactive and purge active index material.
    pub fn set_account_status(&mut self, status: AccountStatus) {
        self.account_status = status;
        if status != AccountStatus::Active {
            self.purge_active_index();
        }
    }

    /// Mark the scope inactive and purge active index material.
    pub fn set_scope_status(&mut self, status: ScopeStatus) {
        self.scope_status = status;
        if status != ScopeStatus::Active {
            self.purge_active_index();
        }
    }

    fn purge_active_index(&mut self) {
        for item in self.items.values_mut() {
            item.chunks.clear();
            item.acls.clear();
            item.tombstoned = true;
        }
    }

    /// Frozen scope kind used to validate provider adapters.
    #[must_use]
    pub const fn scope_kind(&self) -> SourceScopeKind {
        self.scope_kind
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{RemoteCheckpoint, SourceItemUpsert, Tombstone, UntrustedSourceData};
    use chrono::TimeZone;

    fn cursor(byte: u8, generation: u64) -> EncryptedCursor {
        EncryptedCursor::new(vec![byte; 32], [byte; 32], 1, generation).expect("valid test cursor")
    }

    #[test]
    fn failed_page_is_atomic() {
        let tenant = Uuid::from_u128(1);
        let account = AccountId::new(Uuid::from_u128(2));
        let scope = ScopeId::new(Uuid::from_u128(3));
        let mut snapshot = ConnectorSnapshot::new(
            tenant,
            ConnectorProvider::GoogleDrive,
            account,
            scope,
            "changes",
            cursor(1, 0),
            AccountStatus::Active,
            ScopeStatus::Active,
            SourceScopeKind::GoogleSharedDrive,
        )
        .expect("valid snapshot");
        let huge = "x".repeat(2_000_001);
        let invalid = SourceItemUpsert::new(
            ExternalItemId::new("item").expect("valid item id"),
            RemoteVersion::new("v1", None).expect("valid version"),
            "title",
            SourceKind::Document,
            Utc.with_ymd_and_hms(2026, 8, 3, 0, 0, 0)
                .single()
                .expect("valid timestamp"),
            "https://example.invalid/item",
            UntrustedSourceData::new(huge),
            vec![AclPrincipal::user([1; 32])],
        );
        assert_eq!(
            invalid,
            Err(ConnectorError::BoundExceeded("source item characters"))
        );
        assert!(snapshot.items().is_empty());

        let tombstone = Tombstone::new(
            ExternalItemId::new("missing").expect("valid item id"),
            "deleted",
        )
        .expect("valid tombstone");
        let wrong_cursor_page = ChangePage::new(
            tenant,
            ConnectorProvider::GoogleDrive,
            account,
            scope,
            "changes",
            [9; 32],
            Vec::new(),
            vec![tombstone],
            cursor(2, 1),
            RemoteCheckpoint::new("change", "2").expect("valid checkpoint"),
        )
        .expect("valid page shape");
        assert_eq!(
            snapshot.apply(&wrong_cursor_page),
            Err(ConnectorError::CursorConflict)
        );
        assert!(snapshot.items().is_empty());
    }
}
