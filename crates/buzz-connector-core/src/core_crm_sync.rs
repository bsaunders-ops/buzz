//! Deterministic reconciliation for the bounded Core CRM detail-read surface.
//!
//! The current MCP contract has no authoritative whole-corpus cursor. This
//! module therefore reconciles only exact records already discovered or
//! configured by the trusted server. Absence from a capped search/list result
//! is never interpreted as deletion.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{
    core_crm::{CoreCrmReadOperation, CoreCrmSnapshot},
    types::{ExternalItemId, SourceItemUpsert, Tombstone},
    ConnectorError, Result,
};

const CURSOR_VERSION: u16 = 1;
const MAX_CURSOR_BYTES: usize = 64 * 1024;
const MAX_TRACKED_TARGETS: usize = 1_000;
const MAX_ITEMS_PER_TARGET: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", content = "key", rename_all = "snake_case")]
enum TargetKind {
    Contact(Uuid),
    Company(Uuid),
    Project(Uuid),
    Activity(Uuid),
    GuidanceDocument(String),
}

/// One exact Core CRM detail record tracked by the trusted synchronizer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CoreCrmSyncTarget(TargetKind);

impl CoreCrmSyncTarget {
    /// Track one exact contact UUID.
    #[must_use]
    pub const fn contact(id: Uuid) -> Self {
        Self(TargetKind::Contact(id))
    }

    /// Track one exact company UUID.
    #[must_use]
    pub const fn company(id: Uuid) -> Self {
        Self(TargetKind::Company(id))
    }

    /// Track one exact project UUID.
    #[must_use]
    pub const fn project(id: Uuid) -> Self {
        Self(TargetKind::Project(id))
    }

    /// Track one exact activity UUID and its complete transcript children.
    #[must_use]
    pub const fn activity(id: Uuid) -> Self {
        Self(TargetKind::Activity(id))
    }

    /// Track one exact validated guidance-document slug.
    pub fn guidance_document(slug: impl Into<String>) -> Result<Self> {
        let slug = slug.into();
        CoreCrmReadOperation::try_from_tool_call("get_guidance_doc", json!({"slug": &slug}))?;
        Ok(Self(TargetKind::GuidanceDocument(slug)))
    }

    fn operation(&self) -> Result<CoreCrmReadOperation> {
        let (name, arguments) = match &self.0 {
            TargetKind::Contact(id) => ("get_contact", json!({"id": id, "activity_limit": 20})),
            TargetKind::Company(id) => ("get_company", json!({"id": id})),
            TargetKind::Project(id) => ("get_project", json!({"id": id})),
            TargetKind::Activity(id) => ("get_activity", json!({"id": id})),
            TargetKind::GuidanceDocument(slug) => ("get_guidance_doc", json!({"slug": slug})),
        };
        CoreCrmReadOperation::try_from_tool_call(name, arguments)
    }

    fn accepts_item(&self, item_id: &ExternalItemId) -> bool {
        let item_id = item_id.as_str();
        match &self.0 {
            TargetKind::Contact(id) => item_id == format!("core-crm:contact:{id}"),
            TargetKind::Company(id) => item_id == format!("core-crm:company:{id}"),
            TargetKind::Project(id) => item_id == format!("core-crm:project:{id}"),
            TargetKind::Activity(id) => {
                item_id == format!("core-crm:activity:{id}")
                    || item_id.starts_with("core-crm:transcript:")
            }
            TargetKind::GuidanceDocument(_) => item_id.starts_with("core-crm:guidance:"),
        }
    }
}

/// One exact target plus the source item identities produced by its last
/// successful complete detail read.
#[derive(Clone, PartialEq, Eq)]
pub struct CoreCrmTrackedTarget {
    target: CoreCrmSyncTarget,
    item_ids: Vec<ExternalItemId>,
}

impl std::fmt::Debug for CoreCrmTrackedTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CoreCrmTrackedTarget")
            .field("item_count", &self.item_ids.len())
            .field("identities_redacted", &true)
            .finish()
    }
}

impl CoreCrmTrackedTarget {
    /// Bind one exact target to its last complete set of item identities.
    pub fn new(target: CoreCrmSyncTarget, mut item_ids: Vec<ExternalItemId>) -> Result<Self> {
        if item_ids.len() > MAX_ITEMS_PER_TARGET
            || item_ids.iter().any(|item| !target.accepts_item(item))
        {
            return Err(ConnectorError::InvalidData(
                "Core CRM tracked items do not match their target",
            ));
        }
        item_ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        if item_ids
            .windows(2)
            .any(|pair| pair[0].as_str() == pair[1].as_str())
        {
            return Err(ConnectorError::InvalidData(
                "Core CRM tracked items are ambiguous",
            ));
        }
        Ok(Self { target, item_ids })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorWire {
    version: u16,
    cycle: u64,
    current_index: usize,
    targets: Vec<TrackedTargetWire>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrackedTargetWire {
    target: CoreCrmSyncTarget,
    item_ids: Vec<String>,
}

/// Versioned deterministic cursor for one bounded known-record reconciliation
/// cycle. Cursor bytes must be application-encrypted before persistence.
#[derive(Clone, PartialEq, Eq)]
pub struct CoreCrmSyncCursorV1 {
    cycle: u64,
    current_index: usize,
    targets: Vec<CoreCrmTrackedTarget>,
}

impl std::fmt::Debug for CoreCrmSyncCursorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CoreCrmSyncCursorV1")
            .field("cycle", &self.cycle)
            .field("target_count", &self.targets.len())
            .field("cursor_and_identities_redacted", &true)
            .finish()
    }
}

impl CoreCrmSyncCursorV1 {
    /// Create a stable first-cycle cursor from trusted exact targets.
    pub fn new(mut targets: Vec<CoreCrmTrackedTarget>) -> Result<Self> {
        targets.sort_by(|left, right| left.target.cmp(&right.target));
        Self::validate_targets(&targets)?;
        Ok(Self {
            cycle: 0,
            current_index: 0,
            targets,
        })
    }

    fn validate_targets(targets: &[CoreCrmTrackedTarget]) -> Result<()> {
        if targets.is_empty()
            || targets.len() > MAX_TRACKED_TARGETS
            || targets
                .windows(2)
                .any(|pair| pair[0].target >= pair[1].target)
        {
            return Err(ConnectorError::InvalidData(
                "Core CRM reconciliation targets are invalid",
            ));
        }
        for tracked in targets {
            CoreCrmTrackedTarget::new(tracked.target.clone(), tracked.item_ids.clone())?;
        }
        Ok(())
    }

    /// Decode a strict known cursor version. Unknown or ambiguous state fails
    /// closed before any provider request is made.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_CURSOR_BYTES {
            return Err(ConnectorError::BoundExceeded("Core CRM cursor bytes"));
        }
        let wire: CursorWire = serde_json::from_slice(bytes)
            .map_err(|_| ConnectorError::InvalidData("Core CRM cursor is invalid"))?;
        let targets = wire
            .targets
            .into_iter()
            .map(|tracked| {
                if tracked.item_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
                    return Err(ConnectorError::InvalidData(
                        "Core CRM cursor item order is invalid",
                    ));
                }
                let item_ids = tracked
                    .item_ids
                    .into_iter()
                    .map(ExternalItemId::new)
                    .collect::<Result<Vec<_>>>()?;
                CoreCrmTrackedTarget::new(tracked.target, item_ids)
            })
            .collect::<Result<Vec<_>>>()?;
        if wire.version != CURSOR_VERSION
            || wire.current_index >= targets.len()
            || targets.len() > MAX_TRACKED_TARGETS
        {
            return Err(ConnectorError::InvalidData(
                "Core CRM cursor version or position is invalid",
            ));
        }
        Self::validate_targets(&targets)?;
        Ok(Self {
            cycle: wire.cycle,
            current_index: wire.current_index,
            targets,
        })
    }

    /// Encode stable logical cursor bytes for the application-encryption
    /// boundary.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(&CursorWire {
            version: CURSOR_VERSION,
            cycle: self.cycle,
            current_index: self.current_index,
            targets: self
                .targets
                .iter()
                .map(|tracked| TrackedTargetWire {
                    target: tracked.target.clone(),
                    item_ids: tracked
                        .item_ids
                        .iter()
                        .map(|item| item.as_str().to_owned())
                        .collect(),
                })
                .collect(),
        })
        .map_err(|_| ConnectorError::InvalidData("Core CRM cursor is invalid"))?;
        if bytes.len() > MAX_CURSOR_BYTES {
            return Err(ConnectorError::BoundExceeded("Core CRM cursor bytes"));
        }
        Ok(bytes)
    }

    /// Exact closed detail operation for the current position.
    pub fn current_operation(&self) -> Result<CoreCrmReadOperation> {
        self.targets[self.current_index].target.operation()
    }

    /// Item identities produced by the current target's last complete read.
    #[must_use]
    pub fn current_tracked_items(&self) -> &[ExternalItemId] {
        &self.targets[self.current_index].item_ids
    }

    /// Reconcile one complete, identity-bound detail snapshot.
    pub fn reconcile_snapshot(self, snapshot: &CoreCrmSnapshot) -> Result<CoreCrmReconcileStep> {
        if snapshot.upserts().is_empty() || !snapshot.discovery_results().is_empty() {
            return Err(ConnectorError::InvalidData(
                "Core CRM detail snapshot is incomplete",
            ));
        }
        let target = &self.targets[self.current_index].target;
        if snapshot
            .upserts()
            .iter()
            .any(|item| !target.accepts_item(item.external_item_id()))
        {
            return Err(ConnectorError::InvalidData(
                "Core CRM detail snapshot does not match its target",
            ));
        }
        let current = snapshot
            .upserts()
            .iter()
            .map(|item| item.external_item_id().clone())
            .collect::<BTreeSet<_>>();
        let previous = self.targets[self.current_index]
            .item_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let tombstones = previous
            .difference(&current)
            .cloned()
            .map(|item| Tombstone::new(item, "removed_from_scope"))
            .collect::<Result<Vec<_>>>()?;
        self.advance(
            snapshot.upserts().to_vec(),
            tombstones,
            current.into_iter().collect(),
        )
    }

    /// Reconcile an explicit provider result that the exact detail record was
    /// deleted, revoked, or inaccessible. Generic errors must not call this
    /// method and therefore cannot infer tombstones.
    pub fn reconcile_missing(self, state: CoreCrmMissingState) -> Result<CoreCrmReconcileStep> {
        let reason = match state {
            CoreCrmMissingState::Deleted => "deleted",
            CoreCrmMissingState::Revoked => "revoked",
            CoreCrmMissingState::Inaccessible => "inaccessible",
        };
        let tombstones = self.targets[self.current_index]
            .item_ids
            .iter()
            .cloned()
            .map(|item| Tombstone::new(item, reason))
            .collect::<Result<Vec<_>>>()?;
        self.advance(Vec::new(), tombstones, Vec::new())
    }

    fn advance(
        mut self,
        upserts: Vec<SourceItemUpsert>,
        tombstones: Vec<Tombstone>,
        next_items: Vec<ExternalItemId>,
    ) -> Result<CoreCrmReconcileStep> {
        self.targets[self.current_index].item_ids = next_items;
        self.current_index += 1;
        let cycle_complete = self.current_index == self.targets.len();
        if cycle_complete {
            self.current_index = 0;
            self.cycle = self
                .cycle
                .checked_add(1)
                .ok_or(ConnectorError::BoundExceeded("Core CRM cursor cycle"))?;
        }
        Ok(CoreCrmReconcileStep {
            upserts,
            tombstones,
            next_cursor: self,
            cycle_complete,
        })
    }
}

/// Explicit, closed missing-record results that are authoritative enough to
/// remove previously tracked index material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreCrmMissingState {
    /// The exact provider record no longer exists.
    Deleted,
    /// The connector account or scope was revoked.
    Revoked,
    /// The exact provider record is no longer readable.
    Inaccessible,
}

/// One deterministic reconciliation step and its next logical cursor.
pub struct CoreCrmReconcileStep {
    upserts: Vec<SourceItemUpsert>,
    tombstones: Vec<Tombstone>,
    next_cursor: CoreCrmSyncCursorV1,
    cycle_complete: bool,
}

impl std::fmt::Debug for CoreCrmReconcileStep {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CoreCrmReconcileStep")
            .field("upsert_count", &self.upserts.len())
            .field("tombstone_count", &self.tombstones.len())
            .field("cycle_complete", &self.cycle_complete)
            .field("content_and_identities_redacted", &true)
            .finish()
    }
}

impl CoreCrmReconcileStep {
    /// Complete current item replacements.
    #[must_use]
    pub fn upserts(&self) -> &[SourceItemUpsert] {
        &self.upserts
    }

    /// Authoritative removals of previously tracked items.
    #[must_use]
    pub fn tombstones(&self) -> &[Tombstone] {
        &self.tombstones
    }

    /// Next logical cursor to encrypt and commit atomically with this step.
    #[must_use]
    pub const fn next_cursor(&self) -> &CoreCrmSyncCursorV1 {
        &self.next_cursor
    }

    /// Whether this step completed a full pass over every known target.
    #[must_use]
    pub const fn cycle_complete(&self) -> bool {
        self.cycle_complete
    }
}
