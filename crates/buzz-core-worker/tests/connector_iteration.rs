use std::collections::BTreeSet;

use buzz_connector_core::{
    apply::ApplyOutcome,
    types::{
        AccountId, AclPrincipal, ChangePage, ConnectorProvider, EncryptedCursor, ExternalItemId,
        RemoteCheckpoint, RemoteVersion, ScopeId, SourceItemUpsert, SourceKind,
        UntrustedSourceData,
    },
};
use buzz_core_worker::connector_iteration::{
    run_connector_iteration, ConnectorBoundaryError, ConnectorIterationFailureCode,
    ConnectorIterationOutcome, DueScopeClaimer, FencedFailureRecorder, PageApplier, PageProvider,
    ProviderPageError, TrustedConnectorClaim,
};
use chrono::{TimeZone, Utc};
use uuid::Uuid;

const TENANT: Uuid = Uuid::from_u128(1);
const OTHER_TENANT: Uuid = Uuid::from_u128(11);
const ACCOUNT: AccountId = AccountId::new(Uuid::from_u128(2));
const OTHER_ACCOUNT: AccountId = AccountId::new(Uuid::from_u128(12));
const SCOPE: ScopeId = ScopeId::new(Uuid::from_u128(3));
const OTHER_SCOPE: ScopeId = ScopeId::new(Uuid::from_u128(13));
const PROVIDER: ConnectorProvider = ConnectorProvider::GoogleDrive;
const STREAM: &str = "changes";
const CURRENT_CURSOR_HASH: [u8; 32] = [4; 32];
const NEXT_CURSOR_HASH: [u8; 32] = [5; 32];
const LEASE_GENERATION: u64 = 8;

fn configured_acls() -> BTreeSet<AclPrincipal> {
    BTreeSet::from([AclPrincipal::user([6; 32])])
}

fn claim() -> TrustedConnectorClaim {
    TrustedConnectorClaim::new(
        TENANT,
        ACCOUNT,
        SCOPE,
        PROVIDER,
        STREAM,
        LEASE_GENERATION,
        EncryptedCursor::new(vec![4; 16], CURRENT_CURSOR_HASH, 1, 7).expect("valid current cursor"),
        configured_acls(),
    )
    .expect("valid trusted claim")
}

#[allow(clippy::too_many_arguments)]
fn page(
    tenant: Uuid,
    account: AccountId,
    scope: ScopeId,
    provider: ConnectorProvider,
    stream: &str,
    previous_cursor_hash: [u8; 32],
    generation: u64,
    acls: BTreeSet<AclPrincipal>,
) -> ChangePage {
    let resolvable_link = match provider {
        ConnectorProvider::MicrosoftGraph => "https://outlook.office.com/mail/item-1",
        ConnectorProvider::GoogleDrive => "https://drive.google.com/file/d/item-1/view",
        ConnectorProvider::CoreCrm => "https://crm.coreadvs.com/records/item-1",
    };
    let upsert = SourceItemUpsert::new(
        ExternalItemId::new("item-1").expect("valid item id"),
        RemoteVersion::new("version-1", Some("etag-1".to_owned())).expect("valid version"),
        "Quarterly plan",
        SourceKind::Document,
        Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0)
            .single()
            .expect("valid timestamp"),
        resolvable_link,
        UntrustedSourceData::new("synthetic source body"),
        acls.into_iter().collect(),
    )
    .expect("valid synthetic upsert");
    ChangePage::new(
        tenant,
        provider,
        account,
        scope,
        stream,
        previous_cursor_hash,
        vec![upsert],
        Vec::new(),
        EncryptedCursor::new(vec![5; 16], NEXT_CURSOR_HASH, 1, generation)
            .expect("valid next cursor"),
        RemoteCheckpoint::new("synthetic", "checkpoint-1").expect("valid checkpoint"),
    )
    .expect("valid synthetic page")
}

fn matching_page() -> ChangePage {
    page(
        TENANT,
        ACCOUNT,
        SCOPE,
        PROVIDER,
        STREAM,
        CURRENT_CURSOR_HASH,
        LEASE_GENERATION,
        configured_acls(),
    )
}

struct FakeClaimer {
    claim: Option<TrustedConnectorClaim>,
}

impl DueScopeClaimer for FakeClaimer {
    async fn claim_one(&mut self) -> Result<Option<TrustedConnectorClaim>, ConnectorBoundaryError> {
        Ok(self.claim.take())
    }
}

struct FakeProvider {
    response: Option<Result<ChangePage, ProviderPageError>>,
    fetches: usize,
}

impl PageProvider for FakeProvider {
    async fn fetch_one_page(
        &mut self,
        _claim: &TrustedConnectorClaim,
    ) -> Result<ChangePage, ProviderPageError> {
        self.fetches += 1;
        self.response
            .take()
            .unwrap_or(Err(ProviderPageError::InvalidResponse))
    }
}

struct FakeApplier {
    response: Result<ApplyOutcome, ConnectorBoundaryError>,
    applications: usize,
    committed_cursor_hash: [u8; 32],
}

impl PageApplier for FakeApplier {
    async fn apply_page(
        &mut self,
        _claim: &TrustedConnectorClaim,
        page: &ChangePage,
    ) -> Result<ApplyOutcome, ConnectorBoundaryError> {
        self.applications += 1;
        match self.response {
            Ok(outcome) => {
                self.committed_cursor_hash = page.next_cursor().integrity_hash();
                Ok(outcome)
            }
            Err(error) => Err(error),
        }
    }
}

#[derive(Default)]
struct FakeFailureRecorder {
    codes: Vec<ConnectorIterationFailureCode>,
}

impl FencedFailureRecorder for FakeFailureRecorder {
    async fn record_failure(
        &mut self,
        _claim: &TrustedConnectorClaim,
        code: ConnectorIterationFailureCode,
    ) -> Result<bool, ConnectorBoundaryError> {
        self.codes.push(code);
        Ok(true)
    }
}

fn successful_applier(outcome: ApplyOutcome) -> FakeApplier {
    FakeApplier {
        response: Ok(outcome),
        applications: 0,
        committed_cursor_hash: CURRENT_CURSOR_HASH,
    }
}

#[tokio::test]
async fn applies_exactly_one_trusted_page() {
    let mut claimer = FakeClaimer {
        claim: Some(claim()),
    };
    let mut provider = FakeProvider {
        response: Some(Ok(matching_page())),
        fetches: 0,
    };
    let mut applier = successful_applier(ApplyOutcome::Applied { changed_items: 1 });
    let mut failures = FakeFailureRecorder::default();

    let outcome = run_connector_iteration(&mut claimer, &mut provider, &mut applier, &mut failures)
        .await
        .expect("synthetic iteration succeeds");

    assert_eq!(
        outcome,
        ConnectorIterationOutcome::Applied { changed_items: 1 }
    );
    assert_eq!(provider.fetches, 1);
    assert_eq!(applier.applications, 1);
    assert_eq!(applier.committed_cursor_hash, NEXT_CURSOR_HASH);
    assert!(failures.codes.is_empty());
}

#[tokio::test]
async fn returns_idle_without_fetching_when_no_scope_is_due() {
    let mut claimer = FakeClaimer { claim: None };
    let mut provider = FakeProvider {
        response: None,
        fetches: 0,
    };
    let mut applier = successful_applier(ApplyOutcome::Applied { changed_items: 1 });
    let mut failures = FakeFailureRecorder::default();

    let outcome = run_connector_iteration(&mut claimer, &mut provider, &mut applier, &mut failures)
        .await
        .expect("idle iteration succeeds");

    assert_eq!(outcome, ConnectorIterationOutcome::Idle);
    assert_eq!(provider.fetches, 0);
    assert_eq!(applier.applications, 0);
    assert!(failures.codes.is_empty());
}

#[tokio::test]
async fn reports_an_exact_retry_as_already_applied() {
    let mut claimer = FakeClaimer {
        claim: Some(claim()),
    };
    let mut provider = FakeProvider {
        response: Some(Ok(matching_page())),
        fetches: 0,
    };
    let mut applier = successful_applier(ApplyOutcome::AlreadyApplied);
    applier.committed_cursor_hash = NEXT_CURSOR_HASH;
    let mut failures = FakeFailureRecorder::default();

    let outcome = run_connector_iteration(&mut claimer, &mut provider, &mut applier, &mut failures)
        .await
        .expect("idempotent retry succeeds");

    assert_eq!(outcome, ConnectorIterationOutcome::AlreadyApplied);
    assert_eq!(provider.fetches, 1);
    assert_eq!(applier.applications, 1);
    assert_eq!(applier.committed_cursor_hash, NEXT_CURSOR_HASH);
    assert!(failures.codes.is_empty());
}

#[tokio::test]
async fn rejects_every_page_authority_mismatch_before_apply() {
    let cases = [
        page(
            OTHER_TENANT,
            ACCOUNT,
            SCOPE,
            PROVIDER,
            STREAM,
            CURRENT_CURSOR_HASH,
            LEASE_GENERATION,
            configured_acls(),
        ),
        page(
            TENANT,
            OTHER_ACCOUNT,
            SCOPE,
            PROVIDER,
            STREAM,
            CURRENT_CURSOR_HASH,
            LEASE_GENERATION,
            configured_acls(),
        ),
        page(
            TENANT,
            ACCOUNT,
            OTHER_SCOPE,
            PROVIDER,
            STREAM,
            CURRENT_CURSOR_HASH,
            LEASE_GENERATION,
            configured_acls(),
        ),
        page(
            TENANT,
            ACCOUNT,
            SCOPE,
            ConnectorProvider::MicrosoftGraph,
            STREAM,
            CURRENT_CURSOR_HASH,
            LEASE_GENERATION,
            configured_acls(),
        ),
        page(
            TENANT,
            ACCOUNT,
            SCOPE,
            PROVIDER,
            "other-stream",
            CURRENT_CURSOR_HASH,
            LEASE_GENERATION,
            configured_acls(),
        ),
        page(
            TENANT,
            ACCOUNT,
            SCOPE,
            PROVIDER,
            STREAM,
            [44; 32],
            LEASE_GENERATION,
            configured_acls(),
        ),
        page(
            TENANT,
            ACCOUNT,
            SCOPE,
            PROVIDER,
            STREAM,
            CURRENT_CURSOR_HASH,
            LEASE_GENERATION + 1,
            configured_acls(),
        ),
    ];

    for untrusted_page in cases {
        let mut claimer = FakeClaimer {
            claim: Some(claim()),
        };
        let mut provider = FakeProvider {
            response: Some(Ok(untrusted_page)),
            fetches: 0,
        };
        let mut applier = successful_applier(ApplyOutcome::Applied { changed_items: 1 });
        let mut failures = FakeFailureRecorder::default();

        let outcome =
            run_connector_iteration(&mut claimer, &mut provider, &mut applier, &mut failures)
                .await
                .expect("rejection is recorded");

        assert_eq!(
            outcome,
            ConnectorIterationOutcome::Deferred {
                code: ConnectorIterationFailureCode::PageAuthorityMismatch,
            }
        );
        assert_eq!(applier.applications, 0);
        assert_eq!(applier.committed_cursor_hash, CURRENT_CURSOR_HASH);
        assert_eq!(
            failures.codes,
            vec![ConnectorIterationFailureCode::PageAuthorityMismatch]
        );
    }
}

#[tokio::test]
async fn rejects_acl_escalation_before_apply() {
    let escalated_acls =
        BTreeSet::from([AclPrincipal::user([6; 32]), AclPrincipal::user([66; 32])]);
    let mut claimer = FakeClaimer {
        claim: Some(claim()),
    };
    let mut provider = FakeProvider {
        response: Some(Ok(page(
            TENANT,
            ACCOUNT,
            SCOPE,
            PROVIDER,
            STREAM,
            CURRENT_CURSOR_HASH,
            LEASE_GENERATION,
            escalated_acls,
        ))),
        fetches: 0,
    };
    let mut applier = successful_applier(ApplyOutcome::Applied { changed_items: 1 });
    let mut failures = FakeFailureRecorder::default();

    let outcome = run_connector_iteration(&mut claimer, &mut provider, &mut applier, &mut failures)
        .await
        .expect("ACL rejection is recorded");

    assert_eq!(
        outcome,
        ConnectorIterationOutcome::Deferred {
            code: ConnectorIterationFailureCode::PageAclMismatch,
        }
    );
    assert_eq!(applier.applications, 0);
    assert_eq!(applier.committed_cursor_hash, CURRENT_CURSOR_HASH);
    assert_eq!(
        failures.codes,
        vec![ConnectorIterationFailureCode::PageAclMismatch]
    );
}

#[tokio::test]
async fn provider_failure_is_fenced_once_without_cursor_advance() {
    let mut claimer = FakeClaimer {
        claim: Some(claim()),
    };
    let mut provider = FakeProvider {
        response: Some(Err(ProviderPageError::RateLimited)),
        fetches: 0,
    };
    let mut applier = successful_applier(ApplyOutcome::Applied { changed_items: 1 });
    let mut failures = FakeFailureRecorder::default();

    let outcome = run_connector_iteration(&mut claimer, &mut provider, &mut applier, &mut failures)
        .await
        .expect("provider failure is recorded");

    assert_eq!(
        outcome,
        ConnectorIterationOutcome::Deferred {
            code: ConnectorIterationFailureCode::ProviderRateLimited,
        }
    );
    assert_eq!(applier.applications, 0);
    assert_eq!(applier.committed_cursor_hash, CURRENT_CURSOR_HASH);
    assert_eq!(
        failures.codes,
        vec![ConnectorIterationFailureCode::ProviderRateLimited]
    );
}

#[tokio::test]
async fn atomic_apply_failure_is_fenced_once_without_cursor_advance() {
    let mut claimer = FakeClaimer {
        claim: Some(claim()),
    };
    let mut provider = FakeProvider {
        response: Some(Ok(matching_page())),
        fetches: 0,
    };
    let mut applier = FakeApplier {
        response: Err(ConnectorBoundaryError::new()),
        applications: 0,
        committed_cursor_hash: CURRENT_CURSOR_HASH,
    };
    let mut failures = FakeFailureRecorder::default();

    let outcome = run_connector_iteration(&mut claimer, &mut provider, &mut applier, &mut failures)
        .await
        .expect("apply failure is recorded");

    assert_eq!(
        outcome,
        ConnectorIterationOutcome::Deferred {
            code: ConnectorIterationFailureCode::PageApplyRejected,
        }
    );
    assert_eq!(applier.applications, 1);
    assert_eq!(applier.committed_cursor_hash, CURRENT_CURSOR_HASH);
    assert_eq!(
        failures.codes,
        vec![ConnectorIterationFailureCode::PageApplyRejected]
    );
}
