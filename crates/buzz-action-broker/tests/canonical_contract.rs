use std::sync::{Arc, Mutex};

use buzz_action_broker::{
    prepare_proposal, BrokerError, CanonicalProposal, FreshReadAdapter, FreshReadState,
    ProposalRequest, RequestedOperation,
};
use buzz_core::core_protocol::{ActionTarget, EvidenceRef, PositiveWriteOperation};
use buzz_db::core_storage::action_operation_hash;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const OWNER: [u8; 32] = [0x11; 32];
const BROKER: [u8; 32] = [0x22; 32];

#[derive(Clone)]
struct FakeFreshReader {
    calls: Arc<Mutex<Vec<Uuid>>>,
}

impl FreshReadAdapter for FakeFreshReader {
    async fn fresh_read(
        &self,
        request: &RequestedOperation,
    ) -> Result<FreshReadState, buzz_action_broker::BrokerError> {
        self.calls
            .lock()
            .expect("fake call log")
            .push(request.operation_id);
        Ok(FreshReadState {
            before: Some(br#"{"body":"old"}"#.to_vec()),
            after: br#"{"body":"new"}"#.to_vec(),
            expected_remote_version: Some("etag-1".to_owned()),
        })
    }
}

fn request() -> ProposalRequest {
    let target: ActionTarget = serde_json::from_value(json!({
        "provider": "crm",
        "account_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "scope_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "object_id": "contact-1"
    }))
    .expect("target fixture");
    let operation: PositiveWriteOperation = serde_json::from_value(json!({
        "provider": "crm",
        "operation": {
            "action": "add_note",
            "record_id": "contact-1",
            "body": "Follow up next week"
        }
    }))
    .expect("operation fixture");
    let evidence: EvidenceRef = serde_json::from_value(json!({
        "source": "crm",
        "source_id": "contact-1",
        "source_hash": "33".repeat(32),
        "citation": null
    }))
    .expect("evidence fixture");

    ProposalRequest {
        tenant_id: Uuid::parse_str("10000000-0000-4000-8000-000000000001").expect("tenant UUID"),
        proposal_id: Uuid::parse_str("20000000-0000-4000-8000-000000000002")
            .expect("proposal UUID"),
        channel_id: Uuid::parse_str("30000000-0000-4000-8000-000000000003").expect("channel UUID"),
        owner_pubkey: OWNER,
        broker_pubkey: BROKER,
        nonce: Uuid::parse_str("40000000-0000-4000-8000-000000000004").expect("nonce UUID"),
        proposed_at: 1_780_000_000,
        expires_at: 1_780_000_600,
        operations: vec![RequestedOperation {
            operation_id: Uuid::parse_str("50000000-0000-4000-8000-000000000005")
                .expect("operation UUID"),
            idempotency_key: Uuid::parse_str("60000000-0000-4000-8000-000000000006")
                .expect("idempotency UUID"),
            target,
            operation,
        }],
        evidence: vec![evidence],
    }
}

async fn prepared() -> buzz_action_broker::PreparedProposal {
    prepare_proposal(
        &request(),
        &FakeFreshReader {
            calls: Arc::new(Mutex::new(Vec::new())),
        },
    )
    .await
    .expect("prepare proposal")
}

fn leaf_pointers(value: &serde_json::Value) -> Vec<String> {
    fn visit(value: &serde_json::Value, path: &str, pointers: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(fields) => {
                for (key, child) in fields {
                    let key = key.replace('~', "~0").replace('/', "~1");
                    visit(child, &format!("{path}/{key}"), pointers);
                }
            }
            serde_json::Value::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    visit(child, &format!("{path}/{index}"), pointers);
                }
            }
            _ => pointers.push(path.to_owned()),
        }
    }

    let mut pointers = Vec::new();
    visit(value, "", &mut pointers);
    pointers
}

fn mutate_leaf(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Null => *value = json!("mutated"),
        serde_json::Value::Bool(value) => *value = !*value,
        serde_json::Value::Number(value) => {
            let next = value.as_i64().expect("integer canonical field") + 1;
            *value = serde_json::Number::from(next);
        }
        serde_json::Value::String(value) => value.push('x'),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            panic!("mutation target must be a scalar leaf")
        }
    }
}

#[tokio::test]
async fn canonical_hash_is_stable_and_domain_separated() {
    let first = prepared().await;
    let second = prepared().await;
    assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    assert_eq!(first.operation_hash(), second.operation_hash());

    let mut hasher = Sha256::new();
    hasher.update(b"CORE-BUZZ-ACTION-V1\0");
    hasher.update(first.canonical_bytes());
    assert_eq!(first.operation_hash(), hasher.finalize().as_slice());
}

#[tokio::test]
async fn fresh_read_precedes_canonical_proposal_construction() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let reader = FakeFreshReader {
        calls: Arc::clone(&calls),
    };
    let proposal = prepare_proposal(&request(), &reader)
        .await
        .expect("prepare proposal");
    assert_eq!(calls.lock().expect("call log").len(), 1);
    assert!(proposal
        .canonical_bytes()
        .windows(6)
        .any(|part| part == b"etag-1"));
}

#[tokio::test]
async fn every_executable_field_is_hash_sensitive() {
    let baseline = prepared().await;
    let mut changed = request();
    changed.channel_id = Uuid::new_v4();
    let changed = prepare_proposal(
        &changed,
        &FakeFreshReader {
            calls: Arc::new(Mutex::new(Vec::new())),
        },
    )
    .await
    .expect("changed proposal");
    assert_ne!(baseline.operation_hash(), changed.operation_hash());

    let baseline_value: serde_json::Value =
        serde_json::from_slice(baseline.canonical_bytes()).expect("canonical value");
    let pointers = leaf_pointers(&baseline_value);
    assert!(
        pointers.len() >= 34,
        "fixture must exercise every field family in the canonical envelope"
    );
    for pointer in pointers {
        let mut mutation = baseline_value.clone();
        let field = mutation
            .pointer_mut(&pointer)
            .unwrap_or_else(|| panic!("missing executable field {pointer}"));
        mutate_leaf(field);
        let canonical = serde_json_canonicalizer::to_vec(&mutation).expect("canonical mutation");
        let mutated_hash = action_operation_hash(&canonical);
        assert_ne!(
            baseline.operation_hash(),
            mutated_hash,
            "hash did not bind {pointer}"
        );
        if let Ok(parsed) = CanonicalProposal::parse_exact(&canonical, &mutated_hash) {
            assert_ne!(parsed.operation_hash(), baseline.operation_hash());
        }
    }
}

#[tokio::test]
async fn exact_parser_rejects_noncanonical_duplicate_unknown_and_wrong_version_json() {
    let proposal = prepared().await;
    CanonicalProposal::parse_exact(proposal.canonical_bytes(), proposal.operation_hash())
        .expect("exact canonical proposal");

    let spaced = format!(" {}", String::from_utf8_lossy(proposal.canonical_bytes()));
    assert!(CanonicalProposal::parse_exact(spaced.as_bytes(), proposal.operation_hash()).is_err());

    let canonical = String::from_utf8(proposal.canonical_bytes().to_vec()).expect("utf8");
    let duplicate = canonical.replacen(
        "{\"broker_pubkey\"",
        "{\"schema_version\":1,\"broker_pubkey\"",
        1,
    );
    assert!(
        CanonicalProposal::parse_exact(duplicate.as_bytes(), proposal.operation_hash()).is_err()
    );

    let unknown = canonical.replacen(
        "{\"broker_pubkey\"",
        "{\"escape_hatch\":\"DELETE\",\"broker_pubkey\"",
        1,
    );
    assert!(CanonicalProposal::parse_exact(unknown.as_bytes(), proposal.operation_hash()).is_err());

    let wrong_version = canonical.replacen("\"schema_version\":1", "\"schema_version\":2", 1);
    assert!(
        CanonicalProposal::parse_exact(wrong_version.as_bytes(), proposal.operation_hash())
            .is_err()
    );
}

#[tokio::test]
async fn nested_action_state_must_be_exact_canonical_json_without_duplicate_keys() {
    let proposal = prepared().await;
    let canonical = String::from_utf8(proposal.canonical_bytes().to_vec()).expect("utf8");
    let duplicate_nested = canonical.replacen(
        "{\\\"body\\\":\\\"old\\\"}",
        "{\\\"body\\\":\\\"old\\\",\\\"body\\\":\\\"new\\\"}",
        1,
    );
    let mut hasher = Sha256::new();
    hasher.update(b"CORE-BUZZ-ACTION-V1\0");
    hasher.update(duplicate_nested.as_bytes());
    let hash = hasher.finalize();
    assert!(CanonicalProposal::parse_exact(duplicate_nested.as_bytes(), &hash).is_err());
}

#[tokio::test]
async fn debug_output_redacts_action_bodies_evidence_and_canonical_state() {
    let request = request();
    let prepared = prepared().await;
    let fresh = FreshReadState {
        before: Some(br#"{"secret":"mnpi-before"}"#.to_vec()),
        after: br#"{"secret":"mnpi-after"}"#.to_vec(),
        expected_remote_version: Some("secret-etag".to_owned()),
    };
    for debug in [
        format!("{request:?}"),
        format!("{:?}", request.operations[0]),
        format!("{fresh:?}"),
        format!("{prepared:?}"),
    ] {
        for secret in [
            "Follow up next week",
            "contact-1",
            "mnpi-before",
            "mnpi-after",
            "secret-etag",
            "canonical_value",
            "10000000-0000-4000-8000-000000000001",
            "20000000-0000-4000-8000-000000000002",
            "30000000-0000-4000-8000-000000000003",
            "40000000-0000-4000-8000-000000000004",
            "50000000-0000-4000-8000-000000000005",
            "60000000-0000-4000-8000-000000000006",
            &hex::encode(OWNER),
            &hex::encode(BROKER),
        ] {
            assert!(!debug.contains(secret), "debug output leaked {secret:?}");
        }
    }

    let error =
        BrokerError::FreshRead("mnpi-sensitive-error 20000000-0000-4000-8000-000000000002".into());
    for rendered in [format!("{error:?}"), error.to_string()] {
        assert!(!rendered.contains("mnpi-sensitive-error"));
        assert!(!rendered.contains("20000000-0000-4000-8000-000000000002"));
    }
}
