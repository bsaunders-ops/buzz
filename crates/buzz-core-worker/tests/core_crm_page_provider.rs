use std::collections::BTreeSet;

use buzz_connector_core::{
    core_crm::{normalize_core_crm_response, CoreCrmReadOperation, CoreCrmSnapshot},
    core_crm_sync::{
        CoreCrmMissingState, CoreCrmSyncCursorV1, CoreCrmSyncTarget, CoreCrmTrackedTarget,
    },
    types::{
        AccountId, AclPrincipal, ConnectorProvider, EncryptedCursor, ExternalItemId, ScopeId,
        TombstoneReason,
    },
};
use buzz_core_worker::{
    connector_iteration::{PageProvider, ProviderPageError, TrustedConnectorClaim},
    core_crm_provider::{
        CoreCrmCursorCodec, CoreCrmPageProvider, CoreCrmReadOutcome, CoreCrmSnapshotReader,
    },
};
use uuid::Uuid;

const CONTACT_RESPONSE: &[u8] =
    include_bytes!("../../buzz-connector-core/tests/fixtures/core-crm/get-contact.response.json");
const TENANT: Uuid = Uuid::from_u128(1);
const ACCOUNT: AccountId = AccountId::new(Uuid::from_u128(2));
const SCOPE: ScopeId = ScopeId::new(Uuid::from_u128(3));
const GENERATION: u64 = 8;
const CONTACT_ITEM: &str = "core-crm:contact:11111111-1111-4111-8111-111111111111";

fn target() -> CoreCrmSyncTarget {
    CoreCrmSyncTarget::contact(
        Uuid::parse_str("11111111-1111-4111-8111-111111111111").expect("fixture UUID"),
    )
}

struct ErrorReader;

impl CoreCrmSnapshotReader for ErrorReader {
    async fn read(
        &mut self,
        _operation: &CoreCrmReadOperation,
        _acls: Vec<AclPrincipal>,
    ) -> Result<CoreCrmReadOutcome, ProviderPageError> {
        Err(ProviderPageError::InvalidResponse)
    }
}

fn claim() -> TrustedConnectorClaim {
    TrustedConnectorClaim::new(
        TENANT,
        ACCOUNT,
        SCOPE,
        ConnectorProvider::CoreCrm,
        "known-records",
        GENERATION,
        EncryptedCursor::new(vec![1; 48], [1; 32], 1, GENERATION - 1).expect("current cursor"),
        BTreeSet::from([AclPrincipal::user([7; 32])]),
    )
    .expect("claim")
}

struct FakeCodec {
    cursor: Option<CoreCrmSyncCursorV1>,
}

impl CoreCrmCursorCodec for FakeCodec {
    fn decode(
        &mut self,
        _claim: &TrustedConnectorClaim,
    ) -> Result<CoreCrmSyncCursorV1, buzz_core_worker::connector_iteration::ProviderPageError> {
        self.cursor
            .take()
            .ok_or(buzz_core_worker::connector_iteration::ProviderPageError::InvalidResponse)
    }

    fn encode(
        &mut self,
        _claim: &TrustedConnectorClaim,
        cursor: &CoreCrmSyncCursorV1,
    ) -> Result<EncryptedCursor, buzz_core_worker::connector_iteration::ProviderPageError> {
        let bytes = cursor.encode().map_err(|_| {
            buzz_core_worker::connector_iteration::ProviderPageError::InvalidResponse
        })?;
        EncryptedCursor::new(bytes, [2; 32], 1, GENERATION)
            .map_err(|_| buzz_core_worker::connector_iteration::ProviderPageError::InvalidResponse)
    }
}

struct FakeReader {
    outcome: Option<CoreCrmReadOutcome>,
}

impl CoreCrmSnapshotReader for FakeReader {
    async fn read(
        &mut self,
        operation: &CoreCrmReadOperation,
        acls: Vec<AclPrincipal>,
    ) -> Result<CoreCrmReadOutcome, buzz_core_worker::connector_iteration::ProviderPageError> {
        match self.outcome.take().expect("one read") {
            CoreCrmReadOutcome::Snapshot(_) => {
                normalize_core_crm_response(operation, 1, CONTACT_RESPONSE, acls)
                    .map(CoreCrmReadOutcome::Snapshot)
                    .map_err(|_| {
                        buzz_core_worker::connector_iteration::ProviderPageError::InvalidResponse
                    })
            }
            missing => Ok(missing),
        }
    }
}

fn provider(
    previous_items: &[&str],
    outcome: CoreCrmReadOutcome,
) -> CoreCrmPageProvider<FakeReader, FakeCodec> {
    let tracked = CoreCrmTrackedTarget::new(
        target(),
        previous_items
            .iter()
            .map(|item| ExternalItemId::new(*item).expect("item ID"))
            .collect(),
    )
    .expect("tracked target");
    CoreCrmPageProvider::new(
        FakeReader {
            outcome: Some(outcome),
        },
        FakeCodec {
            cursor: Some(CoreCrmSyncCursorV1::new(vec![tracked]).expect("cursor")),
        },
    )
}

fn placeholder_snapshot() -> CoreCrmSnapshot {
    normalize_core_crm_response(
        &CoreCrmReadOperation::try_from_tool_call(
            "get_contact",
            serde_json::json!({
                "id": "11111111-1111-4111-8111-111111111111",
                "activity_limit": 20
            }),
        )
        .expect("operation"),
        1,
        CONTACT_RESPONSE,
        vec![AclPrincipal::user([7; 32])],
    )
    .expect("snapshot")
}

#[tokio::test]
async fn core_crm_provider_builds_one_authority_bound_change_page() {
    let mut provider = provider(&[], CoreCrmReadOutcome::Snapshot(placeholder_snapshot()));

    let page = provider.fetch_one_page(&claim()).await.expect("page");

    assert_eq!(page.provider(), ConnectorProvider::CoreCrm);
    assert_eq!(page.tenant_id(), TENANT);
    assert_eq!(page.account_id(), ACCOUNT);
    assert_eq!(page.scope_id(), SCOPE);
    assert_eq!(page.previous_cursor_hash(), [1; 32]);
    assert_eq!(page.next_cursor().generation(), GENERATION);
    assert_eq!(page.upserts().len(), 1);
    assert_eq!(page.upserts()[0].external_item_id().as_str(), CONTACT_ITEM);
    assert_eq!(page.upserts()[0].acls(), &[AclPrincipal::user([7; 32])]);
    assert!(page.tombstones().is_empty());
    assert!(page.reconciliation_complete());
}

#[tokio::test]
async fn multi_target_reconciliation_marks_intermediate_page_partial() {
    let contact = CoreCrmTrackedTarget::new(target(), Vec::new()).expect("contact target");
    let activity = CoreCrmTrackedTarget::new(
        CoreCrmSyncTarget::activity(
            Uuid::parse_str("44444444-4444-4444-8444-444444444444").expect("activity UUID"),
        ),
        Vec::new(),
    )
    .expect("activity target");
    let mut provider = CoreCrmPageProvider::new(
        FakeReader {
            outcome: Some(CoreCrmReadOutcome::Snapshot(placeholder_snapshot())),
        },
        FakeCodec {
            cursor: Some(
                CoreCrmSyncCursorV1::new(vec![activity, contact]).expect("multi-target cursor"),
            ),
        },
    );

    let page = provider
        .fetch_one_page(&claim())
        .await
        .expect("partial page");

    assert_eq!(page.upserts().len(), 1);
    assert!(!page.reconciliation_complete());
}

#[tokio::test]
async fn only_explicit_missing_outcome_creates_a_tombstone() {
    let mut provider = provider(
        &[CONTACT_ITEM],
        CoreCrmReadOutcome::Missing(CoreCrmMissingState::Deleted),
    );

    let page = provider.fetch_one_page(&claim()).await.expect("page");

    assert!(page.upserts().is_empty());
    assert_eq!(page.tombstones().len(), 1);
    assert_eq!(page.tombstones()[0].reason(), TombstoneReason::Deleted);
    assert_eq!(
        page.tombstones()[0].external_item_id().as_str(),
        CONTACT_ITEM
    );
}

#[tokio::test]
async fn generic_provider_error_cannot_create_a_tombstone_page() {
    let tracked = CoreCrmTrackedTarget::new(
        target(),
        vec![ExternalItemId::new(CONTACT_ITEM).expect("item ID")],
    )
    .expect("tracked target");
    let mut provider = CoreCrmPageProvider::new(
        ErrorReader,
        FakeCodec {
            cursor: Some(CoreCrmSyncCursorV1::new(vec![tracked]).expect("cursor")),
        },
    );

    assert_eq!(
        provider.fetch_one_page(&claim()).await.err(),
        Some(ProviderPageError::InvalidResponse)
    );
}
