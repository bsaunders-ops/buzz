use buzz_action_broker::{
    validate_signed_decision, ActionLifecycleState, ActionTransition, DecisionExpectation,
};
use nostr::{Event, EventBuilder, Keys, Kind, Tag, Timestamp};
use serde_json::json;
use uuid::Uuid;

const PROPOSED_AT: i64 = 1_780_000_000;
const EXPIRES_AT: i64 = PROPOSED_AT + 600;
const DECIDED_AT: i64 = PROPOSED_AT + 30;

struct Fixture {
    owner: Keys,
    broker: Keys,
    expectation: DecisionExpectation,
}

fn fixture() -> Fixture {
    let owner = Keys::generate();
    let broker = Keys::generate();
    Fixture {
        expectation: DecisionExpectation {
            proposal_id: Uuid::parse_str("20000000-0000-4000-8000-000000000002").expect("proposal"),
            nonce: Uuid::parse_str("40000000-0000-4000-8000-000000000004").expect("nonce"),
            operation_hash: [0x44; 32],
            channel_id: Uuid::parse_str("30000000-0000-4000-8000-000000000003").expect("channel"),
            owner_pubkey: owner.public_key().to_bytes(),
            broker_pubkey: broker.public_key().to_bytes(),
            proposed_at: PROPOSED_AT,
            expires_at: EXPIRES_AT,
        },
        owner,
        broker,
    }
}

fn decision_event(
    fixture: &Fixture,
    author: &Keys,
    channel_id: Uuid,
    recipient_hex: &str,
    overrides: serde_json::Value,
) -> Event {
    let mut payload = json!({
        "schema_version": 1,
        "decision_id": "70000000-0000-4000-8000-000000000007",
        "proposal_id": fixture.expectation.proposal_id.to_string(),
        "nonce": fixture.expectation.nonce.to_string(),
        "operation_hash": hex::encode(fixture.expectation.operation_hash),
        "decision": "approve",
        "signer": fixture.owner.public_key().to_hex(),
        "decided_at": DECIDED_AT
    });
    let object = payload.as_object_mut().expect("payload object");
    for (key, value) in overrides.as_object().expect("override object") {
        object.insert(key.clone(), value.clone());
    }
    EventBuilder::new(
        Kind::Custom(44_311),
        serde_json::to_string(&payload).expect("decision JSON"),
    )
    .tags(vec![
        Tag::parse(["h", channel_id.to_string().as_str()]).expect("h"),
        Tag::parse(["p", recipient_hex]).expect("p"),
    ])
    .custom_created_at(Timestamp::from(DECIDED_AT as u64))
    .sign_with_keys(author)
    .expect("signed event")
}

#[test]
fn exact_signed_owner_decision_is_verified_and_bound() {
    let fixture = fixture();
    let event = decision_event(
        &fixture,
        &fixture.owner,
        fixture.expectation.channel_id,
        &fixture.broker.public_key().to_hex(),
        json!({}),
    );
    let verified = validate_signed_decision(&event, &fixture.expectation, DECIDED_AT)
        .expect("valid signed decision");
    assert!(verified.approved());
    assert_eq!(verified.event_hash(), event.id.to_bytes());
}

#[test]
fn signer_channel_pair_hash_nonce_expiry_and_signature_mismatches_fail_closed() {
    let fixture = fixture();
    let stranger = Keys::generate();
    let cases = [
        decision_event(
            &fixture,
            &stranger,
            fixture.expectation.channel_id,
            &fixture.broker.public_key().to_hex(),
            json!({"signer": stranger.public_key().to_hex()}),
        ),
        decision_event(
            &fixture,
            &fixture.owner,
            Uuid::new_v4(),
            &fixture.broker.public_key().to_hex(),
            json!({}),
        ),
        decision_event(
            &fixture,
            &fixture.owner,
            fixture.expectation.channel_id,
            &stranger.public_key().to_hex(),
            json!({}),
        ),
        decision_event(
            &fixture,
            &fixture.owner,
            fixture.expectation.channel_id,
            &fixture.broker.public_key().to_hex(),
            json!({"operation_hash": "55".repeat(32)}),
        ),
        decision_event(
            &fixture,
            &fixture.owner,
            fixture.expectation.channel_id,
            &fixture.broker.public_key().to_hex(),
            json!({"nonce": Uuid::new_v4().to_string()}),
        ),
    ];
    for event in cases {
        assert!(validate_signed_decision(&event, &fixture.expectation, DECIDED_AT).is_err());
    }

    let valid = decision_event(
        &fixture,
        &fixture.owner,
        fixture.expectation.channel_id,
        &fixture.broker.public_key().to_hex(),
        json!({}),
    );
    assert!(validate_signed_decision(&valid, &fixture.expectation, EXPIRES_AT).is_err());

    let mut broken_signature = valid;
    broken_signature.content.push(' ');
    assert!(validate_signed_decision(&broken_signature, &fixture.expectation, DECIDED_AT).is_err());
}

#[test]
fn owner_signed_event_with_stranger_payload_signer_is_rejected() {
    let fixture = fixture();
    let stranger = Keys::generate();
    let event = decision_event(
        &fixture,
        &fixture.owner,
        fixture.expectation.channel_id,
        &fixture.broker.public_key().to_hex(),
        json!({"signer": stranger.public_key().to_hex()}),
    );

    assert!(validate_signed_decision(&event, &fixture.expectation, DECIDED_AT).is_err());
}

#[test]
fn action_state_machine_never_reopens_terminal_or_ambiguous_states() {
    assert_eq!(
        ActionLifecycleState::Proposed
            .transition(ActionTransition::Approve, PROPOSED_AT + 1, EXPIRES_AT)
            .expect("approve"),
        ActionLifecycleState::Approved
    );
    assert_eq!(
        ActionLifecycleState::Approved
            .transition(ActionTransition::Claim, PROPOSED_AT + 2, EXPIRES_AT)
            .expect("claim"),
        ActionLifecycleState::Executing
    );
    assert_eq!(
        ActionLifecycleState::Executing
            .transition(
                ActionTransition::RequireReconciliation,
                PROPOSED_AT + 3,
                EXPIRES_AT
            )
            .expect("ambiguous"),
        ActionLifecycleState::ReconciliationRequired
    );
    for terminal in [
        ActionLifecycleState::Denied,
        ActionLifecycleState::Expired,
        ActionLifecycleState::Succeeded,
        ActionLifecycleState::Failed,
        ActionLifecycleState::ReconciliationRequired,
    ] {
        for transition in [
            ActionTransition::Approve,
            ActionTransition::Claim,
            ActionTransition::Succeed,
        ] {
            assert!(terminal
                .transition(transition, PROPOSED_AT + 4, EXPIRES_AT)
                .is_err());
        }
    }
    assert!(ActionLifecycleState::Proposed
        .transition(ActionTransition::Approve, EXPIRES_AT, EXPIRES_AT)
        .is_err());
}
