use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use buzz_action_broker::{
    execute_once, prepare_proposal, prepare_receipt_event, validate_signed_proposal,
    validate_signed_receipt, AdapterDispatchOutcome, AdapterReadFailure, DurableExecutionStore,
    ExecuteActionRequest, ExecuteActionResult, ExecutionError, FreshReadAdapter, FreshReadState,
    PreDispatchFailure, ProposalRequest, RemotePrecondition, RequestedOperation, TypedWriteAdapter,
};
use buzz_core::{core_protocol::PositiveWriteOperation, CommunityId};
use buzz_db::core_storage::{
    ActionExecutionClaim, ActionExecutionItem, ActionMemberOutcome, ActionReceiptPublication,
    ActionReceiptPublicationItem, ActionRemoteAttempt, ExternalConnector, ExternalOperation,
};
use chrono::{TimeZone, Utc};
use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};
use serde_json::json;
use uuid::Uuid;

const OWNER: [u8; 32] = [0x41; 32];
const BROKER: [u8; 32] = [0x42; 32];
const PROPOSED_AT: i64 = 1_780_000_000;
const EXPIRES_AT: i64 = PROPOSED_AT + 600;

struct ProposalReader;

impl FreshReadAdapter for ProposalReader {
    async fn fresh_read(
        &self,
        _request: &RequestedOperation,
    ) -> Result<FreshReadState, buzz_action_broker::BrokerError> {
        Ok(FreshReadState {
            before: Some(br#"{"body":"before"}"#.to_vec()),
            after: br#"{"body":"after"}"#.to_vec(),
            expected_remote_version: Some("etag-before".into()),
        })
    }
}

fn proposal_request() -> ProposalRequest {
    ProposalRequest {
        tenant_id: Uuid::parse_str("10000000-0000-4000-8000-000000000001").expect("tenant"),
        proposal_id: Uuid::parse_str("20000000-0000-4000-8000-000000000002").expect("proposal"),
        channel_id: Uuid::parse_str("30000000-0000-4000-8000-000000000003").expect("channel"),
        owner_pubkey: OWNER,
        broker_pubkey: BROKER,
        nonce: Uuid::parse_str("40000000-0000-4000-8000-000000000004").expect("nonce"),
        proposed_at: PROPOSED_AT,
        expires_at: EXPIRES_AT,
        operations: vec![RequestedOperation {
            operation_id: Uuid::parse_str("50000000-0000-4000-8000-000000000005")
                .expect("operation"),
            idempotency_key: Uuid::parse_str("60000000-0000-4000-8000-000000000006")
                .expect("idempotency"),
            target: serde_json::from_value(json!({
                "provider": "crm",
                "account_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "scope_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "object_id": "contact-sensitive"
            }))
            .expect("target"),
            operation: serde_json::from_value::<PositiveWriteOperation>(json!({
                "provider": "crm",
                "operation": {
                    "action": "add_note",
                    "record_id": "contact-sensitive",
                    "body": "mnpi-sensitive-body"
                }
            }))
            .expect("operation"),
        }],
        evidence: vec![serde_json::from_value(json!({
            "source": "crm",
            "source_id": "contact-sensitive",
            "source_hash": "33".repeat(32),
            "citation": null
        }))
        .expect("evidence")],
    }
}

async fn claim() -> ActionExecutionClaim {
    let prepared = prepare_proposal(&proposal_request(), &ProposalReader)
        .await
        .expect("prepared proposal");
    let record = prepared.database_record();
    let items = record
        .items
        .iter()
        .enumerate()
        .map(|(index, item)| ActionExecutionItem {
            item_index: i16::try_from(index).expect("index"),
            operation_id: item.operation_id,
            account_id: item.account_id,
            scope_id: item.scope_id,
            connector: item.connector,
            operation: item.operation,
            target_hash: item.target_hash.clone(),
            canonical_operation: item.canonical_operation.clone(),
            canonical_operation_hash: item.canonical_operation_hash.clone(),
            before_hash: item.before_hash.clone(),
            after_hash: item.after_hash.clone(),
            expected_remote_version: item.expected_remote_version.clone(),
            idempotency_key: item.idempotency_key,
            member_hash: item.member_hash.clone(),
        })
        .collect::<Vec<_>>();
    ActionExecutionClaim {
        community_id: CommunityId::from_uuid(proposal_request().tenant_id),
        proposal_id: record.id,
        claim_id: Uuid::parse_str("70000000-0000-4000-8000-000000000007").expect("claim"),
        decision_id: Uuid::parse_str("80000000-0000-4000-8000-000000000008").expect("decision"),
        owner_pubkey: record.owner_pubkey.clone(),
        broker_pubkey: record.broker_pubkey.clone(),
        channel_id: record.channel_id,
        canonical_proposal: record.canonical_proposal.clone(),
        operation_hash: record.operation_hash.clone(),
        ordered_members_hash: record.ordered_members_hash.clone(),
        member_count: i16::try_from(items.len()).expect("member count"),
        items,
        nonce: record.nonce,
        proposed_at: Utc.timestamp_opt(PROPOSED_AT, 0).single().expect("time"),
        expires_at: Utc.timestamp_opt(EXPIRES_AT, 0).single().expect("time"),
        signer_pubkey: OWNER.to_vec(),
        decision_event_hash: vec![0x77; 32],
    }
}

#[tokio::test]
async fn signed_proposal_capability_binds_exact_prepared_payload_and_routing() {
    let owner = Keys::generate();
    let broker = Keys::generate();
    let mut request = proposal_request();
    request.owner_pubkey = owner.public_key().to_bytes();
    request.broker_pubkey = broker.public_key().to_bytes();
    let prepared = prepare_proposal(&request, &ProposalReader)
        .await
        .expect("prepare proposal");
    let channel = request.channel_id.to_string();
    let recipient = owner.public_key().to_hex();
    let event = EventBuilder::new(
        Kind::Custom(44_310),
        serde_json::to_string(prepared.protocol_payload()).expect("proposal payload"),
    )
    .tags(vec![
        Tag::parse(["h", channel.as_str()]).expect("proposal h tag"),
        Tag::parse(["p", recipient.as_str()]).expect("proposal p tag"),
    ])
    .custom_created_at(Timestamp::from(PROPOSED_AT as u64))
    .sign_with_keys(&broker)
    .expect("sign proposal event");

    let verified = validate_signed_proposal(&event, &prepared, PROPOSED_AT)
        .expect("verify exact proposal event");
    assert_eq!(verified.proposal_id(), request.proposal_id);
    assert_eq!(verified.event_hash(), event.id.to_bytes());
    assert_eq!(verified.broker_pubkey(), broker.public_key().to_bytes());

    let wrong_kind = EventBuilder::new(
        Kind::Custom(44_312),
        serde_json::to_string(prepared.protocol_payload()).expect("proposal payload"),
    )
    .tags(vec![
        Tag::parse(["h", channel.as_str()]).expect("proposal h tag"),
        Tag::parse(["p", recipient.as_str()]).expect("proposal p tag"),
    ])
    .custom_created_at(Timestamp::from(PROPOSED_AT as u64))
    .sign_with_keys(&broker)
    .expect("sign wrong-kind proposal event");
    assert!(validate_signed_proposal(&wrong_kind, &prepared, PROPOSED_AT).is_err());
}

fn request() -> ExecuteActionRequest {
    ExecuteActionRequest {
        community_id: CommunityId::from_uuid(proposal_request().tenant_id),
        proposal_id: proposal_request().proposal_id,
        worker_id: Uuid::new_v4(),
        now: Utc
            .timestamp_opt(PROPOSED_AT + 60, 0)
            .single()
            .expect("now"),
    }
}

#[derive(Clone)]
struct FakeStore {
    claim: Arc<Mutex<Option<ActionExecutionClaim>>>,
    attempts: Arc<Mutex<HashSet<i16>>>,
    failures: Arc<Mutex<Vec<PreDispatchFailure>>>,
    outcomes: Arc<Mutex<Vec<AdapterDispatchOutcome>>>,
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl FakeStore {
    fn new(claim: Option<ActionExecutionClaim>, events: Arc<Mutex<Vec<&'static str>>>) -> Self {
        Self {
            claim: Arc::new(Mutex::new(claim)),
            attempts: Arc::new(Mutex::new(HashSet::new())),
            failures: Arc::new(Mutex::new(Vec::new())),
            outcomes: Arc::new(Mutex::new(Vec::new())),
            events,
        }
    }
}

impl DurableExecutionStore for FakeStore {
    async fn claim(
        &self,
        _request: &ExecuteActionRequest,
    ) -> Result<Option<ActionExecutionClaim>, ExecutionError> {
        self.events.lock().expect("events").push("claim");
        Ok(self.claim.lock().expect("claim").take())
    }

    async fn begin_remote_attempt(
        &self,
        _request: &ExecuteActionRequest,
        _claim: &ActionExecutionClaim,
        item: &ActionExecutionItem,
    ) -> Result<Option<ActionRemoteAttempt>, ExecutionError> {
        self.events.lock().expect("events").push("intent");
        if !self
            .attempts
            .lock()
            .expect("attempts")
            .insert(item.item_index)
        {
            return Ok(None);
        }
        Ok(Some(ActionRemoteAttempt {
            attempt_id: Uuid::new_v4(),
            item_index: item.item_index,
        }))
    }

    async fn record_pre_dispatch_failure(
        &self,
        _request: &ExecuteActionRequest,
        _claim: &ActionExecutionClaim,
        _item: &ActionExecutionItem,
        failure: PreDispatchFailure,
    ) -> Result<(), ExecutionError> {
        self.events.lock().expect("events").push("pre-failure");
        self.failures.lock().expect("failures").push(failure);
        Ok(())
    }

    async fn record_dispatch_outcome(
        &self,
        _request: &ExecuteActionRequest,
        _claim: &ActionExecutionClaim,
        _item: &ActionExecutionItem,
        _attempt: &ActionRemoteAttempt,
        outcome: &AdapterDispatchOutcome,
    ) -> Result<(), ExecutionError> {
        self.events.lock().expect("events").push("outcome");
        self.outcomes
            .lock()
            .expect("outcomes")
            .push(outcome.clone());
        Ok(())
    }
}

#[derive(Clone)]
struct FakeAdapter {
    remote: Result<RemotePrecondition, AdapterReadFailure>,
    dispatch: AdapterDispatchOutcome,
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl TypedWriteAdapter for FakeAdapter {
    async fn read_current(
        &self,
        _item: &ActionExecutionItem,
    ) -> Result<RemotePrecondition, AdapterReadFailure> {
        self.events.lock().expect("events").push("read");
        self.remote.clone()
    }

    async fn dispatch(
        &self,
        _item: &ActionExecutionItem,
        _attempt: &ActionRemoteAttempt,
    ) -> AdapterDispatchOutcome {
        self.events.lock().expect("events").push("dispatch");
        self.dispatch.clone()
    }
}

fn matching_remote(claim: &ActionExecutionClaim) -> RemotePrecondition {
    RemotePrecondition {
        resource_exists: true,
        state_hash: claim.items[0]
            .before_hash
            .clone()
            .map(|value| value.try_into().expect("hash")),
        version: claim.items[0].expected_remote_version.clone(),
    }
}

fn success() -> AdapterDispatchOutcome {
    AdapterDispatchOutcome::Succeeded {
        external_result_id: "opaque-result".into(),
        external_result_version: "etag-after".into(),
        external_resource_id_hash: Some([0x99; 32]),
    }
}

#[tokio::test]
async fn fresh_version_check_and_durable_intent_precede_the_only_dispatch() {
    let claim = claim().await;
    let events = Arc::new(Mutex::new(Vec::new()));
    let store = FakeStore::new(Some(claim.clone()), Arc::clone(&events));
    let adapter = FakeAdapter {
        remote: Ok(matching_remote(&claim)),
        dispatch: success(),
        events: Arc::clone(&events),
    };

    assert_eq!(
        execute_once(&store, &adapter, &request())
            .await
            .expect("execute"),
        ExecuteActionResult::Completed {
            succeeded: 1,
            failed: 0,
            reconciliation_required: 0,
        }
    );
    assert_eq!(
        *events.lock().expect("events"),
        ["claim", "read", "intent", "dispatch", "outcome"]
    );
}

#[tokio::test]
async fn concurrent_workers_dispatch_an_approved_member_at_most_once() {
    let claim = claim().await;
    let events = Arc::new(Mutex::new(Vec::new()));
    let store = FakeStore::new(Some(claim.clone()), Arc::clone(&events));
    let adapter = FakeAdapter {
        remote: Ok(matching_remote(&claim)),
        dispatch: success(),
        events: Arc::clone(&events),
    };
    let first_request = request();
    let second_request = request();
    let (first, second) = tokio::join!(
        execute_once(&store, &adapter, &first_request),
        execute_once(&store, &adapter, &second_request)
    );
    assert!(first.is_ok());
    assert!(second.is_ok());
    assert_eq!(
        events
            .lock()
            .expect("events")
            .iter()
            .filter(|event| **event == "dispatch")
            .count(),
        1
    );
}

#[tokio::test]
async fn stale_remote_state_hash_mismatch_and_expiry_dispatch_zero_times() {
    let baseline = claim().await;
    let cases = [
        (
            baseline.clone(),
            request(),
            Some(matching_remote(&baseline)),
        ),
        {
            let mut hash_mismatch = baseline.clone();
            hash_mismatch.operation_hash[0] ^= 0xff;
            (hash_mismatch, request(), Some(matching_remote(&baseline)))
        },
        {
            let mut expired = request();
            expired.now = baseline.expires_at;
            (baseline.clone(), expired, Some(matching_remote(&baseline)))
        },
    ];

    for (claim, request, remote) in cases {
        let events = Arc::new(Mutex::new(Vec::new()));
        let store = FakeStore::new(Some(claim), Arc::clone(&events));
        let mut remote = remote.expect("remote");
        if request.now < baseline.expires_at
            && store
                .claim
                .lock()
                .expect("claim")
                .as_ref()
                .is_some_and(|value| value.operation_hash == baseline.operation_hash)
        {
            remote.version = Some("stale-etag".into());
        }
        let adapter = FakeAdapter {
            remote: Ok(remote),
            dispatch: success(),
            events: Arc::clone(&events),
        };
        let _ = execute_once(&store, &adapter, &request).await;
        assert!(!events.lock().expect("events").contains(&"dispatch"));
        assert!(store.attempts.lock().expect("attempts").is_empty());
    }

    let events = Arc::new(Mutex::new(Vec::new()));
    let denied_store = FakeStore::new(None, Arc::clone(&events));
    let adapter = FakeAdapter {
        remote: Err(AdapterReadFailure::Unavailable),
        dispatch: success(),
        events: Arc::clone(&events),
    };
    assert_eq!(
        execute_once(&denied_store, &adapter, &request())
            .await
            .expect("denied/no claim"),
        ExecuteActionResult::NotClaimed
    );
    assert!(!events.lock().expect("events").contains(&"dispatch"));
}

#[tokio::test]
async fn ambiguous_timeout_is_durable_and_never_blindly_retried() {
    let claim = claim().await;
    let events = Arc::new(Mutex::new(Vec::new()));
    let store = FakeStore::new(Some(claim.clone()), Arc::clone(&events));
    let adapter = FakeAdapter {
        remote: Ok(matching_remote(&claim)),
        dispatch: AdapterDispatchOutcome::AmbiguousTimeout,
        events: Arc::clone(&events),
    };
    let result = execute_once(&store, &adapter, &request())
        .await
        .expect("timeout is a durable outcome");
    assert_eq!(
        result,
        ExecuteActionResult::Completed {
            succeeded: 0,
            failed: 0,
            reconciliation_required: 1,
        }
    );
    assert_eq!(
        execute_once(&store, &adapter, &request())
            .await
            .expect("second worker"),
        ExecuteActionResult::NotClaimed
    );
    assert_eq!(
        events
            .lock()
            .expect("events")
            .iter()
            .filter(|event| **event == "dispatch")
            .count(),
        1
    );
}

#[tokio::test]
async fn debug_and_errors_never_expose_action_bodies_ids_versions_or_pubkeys() {
    let claim = claim().await;
    for debug in [
        format!("{claim:?}"),
        format!("{:?}", claim.items[0]),
        format!("{:?}", ExecutionError::ClaimRejected),
    ] {
        for secret in [
            "mnpi-sensitive-body",
            "contact-sensitive",
            "etag-before",
            "20000000-0000-4000-8000-000000000002",
            "50000000-0000-4000-8000-000000000005",
            &hex::encode(OWNER),
            &hex::encode(BROKER),
        ] {
            assert!(
                !debug.contains(secret),
                "debug output leaked sensitive action data"
            );
        }
    }
}

#[test]
fn positive_operation_enum_has_no_generic_or_destructive_capability() {
    for forbidden in [
        (ExternalConnector::CoreCrm, "crm/delete_contact"),
        (ExternalConnector::CoreCrm, "crm/merge_company"),
        (ExternalConnector::MicrosoftGraph, "outlook/send"),
        (ExternalConnector::MicrosoftGraph, "calendar/write"),
        (ExternalConnector::GoogleDrive, "google/delete"),
        (ExternalConnector::GoogleDrive, "google/share"),
        (ExternalConnector::GoogleDrive, "http/request"),
    ] {
        assert!(ExternalOperation::from_wire(forbidden.1).is_none());
    }
}

#[tokio::test]
async fn receipt_content_and_private_routing_are_derived_only_from_durable_outcome() {
    let claim = claim().await;
    let owner = Keys::generate();
    let broker = Keys::generate();
    let publication = ActionReceiptPublication {
        publish_claim_id: Uuid::new_v4(),
        receipt_id: Uuid::new_v4(),
        proposal_id: claim.proposal_id,
        decision_id: claim.decision_id,
        channel_id: claim.channel_id,
        owner_pubkey: owner.public_key().to_bytes().to_vec(),
        broker_pubkey: broker.public_key().to_bytes().to_vec(),
        operation_hash: claim.operation_hash.clone(),
        results: vec![ActionReceiptPublicationItem {
            operation_id: claim.items[0].operation_id,
            operation_hash: claim.items[0].member_hash.clone(),
            idempotency_key: claim.items[0].idempotency_key,
            outcome: ActionMemberOutcome::Succeeded,
            external_result_id: Some("opaque-result-sensitive".into()),
            external_result_version: Some("etag-result-sensitive".into()),
            reconciliation_status: "not_required".into(),
        }],
        occurred_at: Utc::now(),
    };
    let prepared = prepare_receipt_event(&publication).expect("prepare durable receipt event");
    let payload: buzz_core::core_protocol::ActionReceiptPayload =
        serde_json::from_str(prepared.content()).expect("valid receipt payload");
    payload.validate().expect("valid receipt invariants");
    assert_eq!(prepared.channel_id(), claim.channel_id);
    assert_eq!(prepared.recipient_pubkey(), owner.public_key().to_bytes());
    assert_eq!(prepared.signer_pubkey(), broker.public_key().to_bytes());
    let receipt_channel = publication.channel_id.to_string();
    let receipt_recipient = owner.public_key().to_hex();
    let receipt_event = EventBuilder::new(Kind::Custom(44_312), prepared.content())
        .tags(vec![
            Tag::parse(["h", receipt_channel.as_str()]).expect("receipt h tag"),
            Tag::parse(["p", receipt_recipient.as_str()]).expect("receipt p tag"),
        ])
        .custom_created_at(Timestamp::from(publication.occurred_at.timestamp() as u64))
        .sign_with_keys(&broker)
        .expect("sign receipt event");
    let verified_receipt = validate_signed_receipt(
        &receipt_event,
        &prepared,
        publication.occurred_at.timestamp(),
    )
    .expect("verify exact receipt event");
    assert_eq!(verified_receipt.receipt_id(), publication.receipt_id);
    assert_eq!(verified_receipt.event_hash(), receipt_event.id.to_bytes());
    let wrong_signer = EventBuilder::new(Kind::Custom(44_312), prepared.content())
        .tags(vec![
            Tag::parse(["h", receipt_channel.as_str()]).expect("receipt h tag"),
            Tag::parse(["p", receipt_recipient.as_str()]).expect("receipt p tag"),
        ])
        .custom_created_at(Timestamp::from(publication.occurred_at.timestamp() as u64))
        .sign_with_keys(&owner)
        .expect("sign wrong-signer receipt event");
    assert!(validate_signed_receipt(
        &wrong_signer,
        &prepared,
        publication.occurred_at.timestamp(),
    )
    .is_err());
    let debug = format!("{prepared:?}");
    for secret in [
        "opaque-result-sensitive",
        "etag-result-sensitive",
        &claim.proposal_id.to_string(),
        &hex::encode(OWNER),
        &hex::encode(BROKER),
    ] {
        assert!(!debug.contains(secret));
    }

    let mut tampered = publication;
    tampered.operation_hash.pop();
    assert!(prepare_receipt_event(&tampered).is_err());
}
