//! Core CRM detail reconciliation composed behind injected read and cursor
//! boundaries.

use buzz_connector_core::{
    core_crm::{CoreCrmReadOperation, CoreCrmSnapshot},
    core_crm_sync::{CoreCrmMissingState, CoreCrmSyncCursorV1},
    types::{AclPrincipal, ChangePage, ConnectorProvider, EncryptedCursor, RemoteCheckpoint},
};

use crate::connector_iteration::{PageProvider, ProviderPageError, TrustedConnectorClaim};

/// Application cursor-encryption boundary. Production implementations must
/// authenticate the tenant/account/scope/stream authority as associated data.
pub trait CoreCrmCursorCodec: Send {
    /// Decrypt and validate the current logical cursor.
    fn decode(
        &mut self,
        claim: &TrustedConnectorClaim,
    ) -> Result<CoreCrmSyncCursorV1, ProviderPageError>;

    /// Encrypt the next logical cursor at the claim's fenced generation.
    fn encode(
        &mut self,
        claim: &TrustedConnectorClaim,
        cursor: &CoreCrmSyncCursorV1,
    ) -> Result<EncryptedCursor, ProviderPageError>;
}

/// Closed result of reading one exact Core CRM detail target.
pub enum CoreCrmReadOutcome {
    /// Complete identity-bound detail snapshot.
    Snapshot(CoreCrmSnapshot),
    /// Explicit authoritative missing-state result for the exact target.
    Missing(CoreCrmMissingState),
}

/// Exact-detail reader boundary used by the worker provider.
pub trait CoreCrmSnapshotReader: Send {
    /// Read one closed operation with ACLs supplied only by the trusted claim.
    async fn read(
        &mut self,
        operation: &CoreCrmReadOperation,
        acls: Vec<AclPrincipal>,
    ) -> Result<CoreCrmReadOutcome, ProviderPageError>;
}

/// One registered Core CRM provider that produces exactly one deterministic
/// change page per worker iteration.
pub struct CoreCrmPageProvider<R, C> {
    reader: R,
    codec: C,
}

impl<R, C> CoreCrmPageProvider<R, C> {
    /// Compose injected production or synthetic boundaries.
    #[must_use]
    pub const fn new(reader: R, codec: C) -> Self {
        Self { reader, codec }
    }
}

impl<R, C> PageProvider for CoreCrmPageProvider<R, C>
where
    R: CoreCrmSnapshotReader,
    C: CoreCrmCursorCodec,
{
    async fn fetch_one_page(
        &mut self,
        claim: &TrustedConnectorClaim,
    ) -> Result<ChangePage, ProviderPageError> {
        if claim.provider() != ConnectorProvider::CoreCrm {
            return Err(ProviderPageError::InvalidResponse);
        }
        let cursor = self.codec.decode(claim)?;
        let operation = cursor
            .current_operation()
            .map_err(|_| ProviderPageError::InvalidResponse)?;
        let acls = claim.acl_principals().iter().cloned().collect();
        let step = match self.reader.read(&operation, acls).await? {
            CoreCrmReadOutcome::Snapshot(snapshot) => cursor
                .reconcile_snapshot(&snapshot)
                .map_err(|_| ProviderPageError::InvalidResponse)?,
            CoreCrmReadOutcome::Missing(state) => cursor
                .reconcile_missing(state)
                .map_err(|_| ProviderPageError::InvalidResponse)?,
        };
        let next_cursor = self.codec.encode(claim, step.next_cursor())?;
        let checkpoint = if step.cycle_complete() {
            "cycle-complete"
        } else {
            "cycle-partial"
        };
        ChangePage::new_reconciliation(
            claim.community_id(),
            claim.provider(),
            claim.account_id(),
            claim.scope_id(),
            claim.stream(),
            claim.current_cursor().integrity_hash(),
            step.upserts().to_vec(),
            step.tombstones().to_vec(),
            next_cursor,
            RemoteCheckpoint::new("known-record-reconciliation", checkpoint)
                .map_err(|_| ProviderPageError::InvalidResponse)?,
            step.cycle_complete(),
        )
        .map_err(|_| ProviderPageError::InvalidResponse)
    }
}
