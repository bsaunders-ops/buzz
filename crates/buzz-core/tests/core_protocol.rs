use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use buzz_core::core_protocol::{
    learning_bundle_coordinate, validate_core_envelope, validate_core_plaintext_content,
    ActionDecisionPayload, ActionProposalPayload, ActionReceiptPayload, CallControlPayload,
    CanonicalUuidV4, CopilotSuggestionPayload, CoreDirection, InsightDispositionPayload,
    InsightPayload, LearningBundleHeadPayload, LearningDomain, LearningLayer,
    LearningRecordPayload, PositiveWriteOperation, Sha256Hex, TranscriptSegmentPayload, Version1,
};
use buzz_core::engram::conversation_key;
use nostr::{EventBuilder, Keys, Kind, Tag};

const LEARNING_COORDINATE_PERSONAL_RANKING: &str =
    "5057dfc0c146934621eee8ceb95aa90a6a1729caf14676bbe377999eb1f0544d";

fn learning_pair() -> (Keys, Keys) {
    let agent = Keys::parse("0000000000000000000000000000000000000000000000000000000000000001")
        .expect("fixed agent key");
    let owner = Keys::parse("0000000000000000000000000000000000000000000000000000000000000002")
        .expect("fixed owner key");
    (agent, owner)
}

#[test]
fn learning_bundle_coordinate_matches_fixed_vector() {
    let (agent, owner) = learning_pair();
    let key = conversation_key(agent.secret_key(), &owner.public_key());

    assert_eq!(
        learning_bundle_coordinate(
            &key,
            LearningLayer::Personal,
            LearningDomain::RankingWithinPolicyTier,
        )
        .as_str(),
        LEARNING_COORDINATE_PERSONAL_RANKING
    );
}

#[test]
fn learning_bundle_coordinate_is_pair_symmetric() {
    let (agent, owner) = learning_pair();
    let agent_key = conversation_key(agent.secret_key(), &owner.public_key());
    let owner_key = conversation_key(owner.secret_key(), &agent.public_key());

    assert_eq!(
        learning_bundle_coordinate(
            &agent_key,
            LearningLayer::Personal,
            LearningDomain::RankingWithinPolicyTier,
        ),
        learning_bundle_coordinate(
            &owner_key,
            LearningLayer::Personal,
            LearningDomain::RankingWithinPolicyTier,
        )
    );
}

#[test]
fn learning_bundle_coordinate_separates_layers() {
    let (agent, owner) = learning_pair();
    let key = conversation_key(agent.secret_key(), &owner.public_key());

    assert_ne!(
        learning_bundle_coordinate(
            &key,
            LearningLayer::Personal,
            LearningDomain::RankingWithinPolicyTier,
        ),
        learning_bundle_coordinate(
            &key,
            LearningLayer::SanitizedFirm,
            LearningDomain::RankingWithinPolicyTier,
        )
    );
}

#[test]
fn learning_bundle_coordinate_separates_domains() {
    let (agent, owner) = learning_pair();
    let key = conversation_key(agent.secret_key(), &owner.public_key());

    assert_ne!(
        learning_bundle_coordinate(
            &key,
            LearningLayer::Personal,
            LearningDomain::RankingWithinPolicyTier,
        ),
        learning_bundle_coordinate(
            &key,
            LearningLayer::Personal,
            LearningDomain::WritingStyleTraits,
        )
    );
}

fn action_proposal_with_times(proposed_at: i64, expires_at: i64) -> ActionProposalPayload {
    serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "proposal_id": "550e8400-e29b-41d4-a716-446655440000",
        "nonce": "6ba7b810-9dad-41d1-80b4-00c04fd430c8",
        "operation_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "proposed_at": proposed_at,
        "expires_at": expires_at,
        "bundle_semantics": "independent_operations",
        "operations": [{
            "operation_id": "6ba7b812-9dad-41d1-80b4-00c04fd430c8",
            "operation_hash": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "idempotency_key": "6ba7b811-9dad-41d1-80b4-00c04fd430c8",
            "target": {
                "provider": "crm",
                "account_id": "acct:1",
                "scope_id": "workspace:1",
                "object_id": "contact:1"
            },
            "before": {
                "canonical_value": "old",
                "value_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            },
            "after": {
                "canonical_value": "new",
                "value_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            },
            "expected_remote_version": "v1",
            "side_effects": ["updates_record"],
            "operation": {
                "provider": "crm",
                "operation": {
                    "action": "add_tag",
                    "record_id": "contact:1",
                    "tag": "priority"
                }
            }
        }],
        "evidence": [{
            "source": "crm",
            "source_id": "contact:1",
            "source_hash": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        }]
    }))
    .expect("valid action proposal fixture")
}

#[test]
fn security_values_fail_closed() {
    assert!(serde_json::from_str::<Version1>("1").is_ok());
    assert!(serde_json::from_str::<Version1>("2").is_err());

    assert!(
        serde_json::from_str::<CanonicalUuidV4>(r#""550e8400-e29b-41d4-a716-446655440000""#)
            .is_ok()
    );
    assert!(
        serde_json::from_str::<CanonicalUuidV4>(r#""550e8400-e29b-11d4-a716-446655440000""#)
            .is_err()
    );

    let lower = "ab".repeat(32);
    assert!(serde_json::from_str::<Sha256Hex>(&format!(r#""{lower}""#)).is_ok());
    assert!(serde_json::from_str::<Sha256Hex>(&format!(r#""{}""#, lower.to_uppercase())).is_err());

    for bidi in [
        '\u{202a}', '\u{202e}', '\u{2066}', '\u{2069}', '\u{200e}', '\u{200f}', '\u{061c}',
    ] {
        let spoofed = serde_json::to_string(&format!("approve{bidi}deny")).expect("json");
        assert!(serde_json::from_str::<buzz_core::core_protocol::ProtocolLabel>(&spoofed).is_err());
        assert!(serde_json::from_str::<buzz_core::core_protocol::ProtocolText>(&spoofed).is_err());
    }
}

#[test]
fn forbidden_and_unknown_action_shapes_do_not_deserialize() {
    let send = r#"{"provider":"outlook","operation":{"action":"send","draft_id":"550e8400-e29b-41d4-a716-446655440000"}}"#;
    assert!(serde_json::from_str::<PositiveWriteOperation>(send).is_err());

    let delete =
        r#"{"provider":"crm","operation":{"action":"delete_contact","contact_id":"opaque"}}"#;
    assert!(serde_json::from_str::<PositiveWriteOperation>(delete).is_err());
}

#[test]
fn proposal_rejects_unknown_fields_and_invalid_expiry_window() {
    let base = r#"{
        "schema_version":1,
        "proposal_id":"550e8400-e29b-41d4-a716-446655440000",
        "nonce":"6ba7b810-9dad-41d1-80b4-00c04fd430c8",
        "operation_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "proposed_at":1700000000,
        "expires_at":1700000901,
        "bundle_semantics":"independent_operations",
        "operations":[{
            "operation_id":"6ba7b812-9dad-41d1-80b4-00c04fd430c8",
            "operation_hash":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "idempotency_key":"6ba7b811-9dad-41d1-80b4-00c04fd430c8",
            "target":{"provider":"crm","account_id":"acct:1","scope_id":"workspace:1","object_id":"contact:1"},
            "before":{"canonical_value":"old","value_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
            "after":{"canonical_value":"new","value_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
            "expected_remote_version":"v1",
            "side_effects":["updates_record"],
            "operation":{"provider":"crm","operation":{"action":"add_tag","record_id":"contact:1","tag":"priority"}}
        }],
        "evidence":[{"source":"crm","source_id":"contact:1","source_hash":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}]
    }"#;
    let proposal: ActionProposalPayload = serde_json::from_str(base).expect("shape parses");
    assert!(proposal.validate_at(1_700_000_000).is_err());

    let mut unknown: serde_json::Value = serde_json::from_str(base).expect("fixture json");
    unknown
        .as_object_mut()
        .expect("fixture object")
        .insert("approval".into(), serde_json::Value::Bool(true));
    assert!(serde_json::from_value::<ActionProposalPayload>(unknown).is_err());
}

#[test]
fn proposal_lifetime_rejects_i64_extremes_without_overflow() {
    let proposal = action_proposal_with_times(i64::MIN, i64::MAX);
    assert!(proposal.validate_at(0).is_err());
}

#[test]
fn proposal_future_skew_saturates_at_i64_max() {
    let proposal = action_proposal_with_times(i64::MAX - 50, i64::MAX);
    assert!(proposal.validate_at(i64::MAX - 100).is_ok());
}

#[test]
fn disposition_snooze_rejects_i64_extremes_without_overflow() {
    let disposition: InsightDispositionPayload = serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "disposition_id": "550e8400-e29b-41d4-a716-446655440000",
        "insight_id": "6ba7b810-9dad-41d1-80b4-00c04fd430c8",
        "disposition": "snoozed",
        "reason": "Later",
        "correction": null,
        "resume_at": i64::MAX,
        "occurred_at": i64::MIN
    }))
    .expect("valid disposition fixture");
    assert!(disposition.validate().is_err());
}

#[test]
fn every_frozen_payload_rejects_unknown_schema_versions() {
    type RejectFixture = (&'static str, fn(&str) -> bool);
    let fixtures: &[RejectFixture] = &[
        (
            r#"{"schema_version":2,"insight_id":"550e8400-e29b-41d4-a716-446655440000","dedupe_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","priority":"high","title":"Renewal","summary":"Follow up","created_at":1700000000,"evidence":[]}"#,
            |json| serde_json::from_str::<InsightPayload>(json).is_err(),
        ),
        (
            r#"{"schema_version":2,"disposition_id":"550e8400-e29b-41d4-a716-446655440000","insight_id":"6ba7b810-9dad-41d1-80b4-00c04fd430c8","disposition":"dismissed","occurred_at":1700000000}"#,
            |json| serde_json::from_str::<InsightDispositionPayload>(json).is_err(),
        ),
        (
            r#"{"schema_version":2,"decision_id":"550e8400-e29b-41d4-a716-446655440000","proposal_id":"6ba7b810-9dad-41d1-80b4-00c04fd430c8","nonce":"6ba7b811-9dad-41d1-80b4-00c04fd430c8","operation_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","decision":"approve","decided_at":1700000000}"#,
            |json| serde_json::from_str::<ActionDecisionPayload>(json).is_err(),
        ),
        (
            r#"{"schema_version":2,"receipt_id":"550e8400-e29b-41d4-a716-446655440000","proposal_id":"6ba7b810-9dad-41d1-80b4-00c04fd430c8","decision_id":"6ba7b811-9dad-41d1-80b4-00c04fd430c8","operation_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","idempotency_key":"6ba7b812-9dad-41d1-80b4-00c04fd430c8","outcome":"succeeded","occurred_at":1700000000}"#,
            |json| serde_json::from_str::<ActionReceiptPayload>(json).is_err(),
        ),
        (
            r#"{"schema_version":2,"record_id":"550e8400-e29b-41d4-a716-446655440000","domain":"communication","revision":1,"record_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","content":"Prefer concise updates","created_at":1700000000,"evidence_hashes":[]}"#,
            |json| serde_json::from_str::<LearningRecordPayload>(json).is_err(),
        ),
        (
            r#"{"schema_version":2,"domain":"communication","revision":1,"bundle_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","safety_policy_version":"s1","persona_version":"p1","firm_version":"f1","personal_version":"u1","model_version":"m1","activated_at":1700000000}"#,
            |json| serde_json::from_str::<LearningBundleHeadPayload>(json).is_err(),
        ),
        (
            r#"{"schema_version":2,"call_id":"550e8400-e29b-41d4-a716-446655440000","command":"stop","occurred_at":1700000000}"#,
            |json| serde_json::from_str::<CallControlPayload>(json).is_err(),
        ),
        (
            r#"{"schema_version":2,"segment_id":"550e8400-e29b-41d4-a716-446655440000","call_id":"6ba7b810-9dad-41d1-80b4-00c04fd430c8","speaker":"owner","text":"hello","started_at_ms":1,"ended_at_ms":2}"#,
            |json| serde_json::from_str::<TranscriptSegmentPayload>(json).is_err(),
        ),
        (
            r#"{"schema_version":2,"suggestion_id":"550e8400-e29b-41d4-a716-446655440000","call_id":"6ba7b810-9dad-41d1-80b4-00c04fd430c8","text":"Ask about timing","created_at":1700000000,"evidence_hashes":[]}"#,
            |json| serde_json::from_str::<CopilotSuggestionPayload>(json).is_err(),
        ),
    ];

    for (json, rejects) in fixtures {
        assert!(rejects(json), "payload accepted schema_version 2: {json}");
    }
}

#[test]
fn positive_write_allowlist_accepts_each_frozen_operation_family() {
    let fixtures = [
        r#"{"provider":"crm","operation":{"action":"add_note","record_id":"contact:1","body":"note"}}"#,
        r#"{"provider":"crm","operation":{"action":"log_activity","record_id":"contact:1","activity_type":"call","body":"summary"}}"#,
        r#"{"provider":"crm","operation":{"action":"create_contact","fields":{"name":"A"}}}"#,
        r#"{"provider":"crm","operation":{"action":"update_contact","contact_id":"1","expected_remote_version":"v1","fields":{"name":"B"}}}"#,
        r#"{"provider":"crm","operation":{"action":"create_company","fields":{"name":"C"}}}"#,
        r#"{"provider":"crm","operation":{"action":"update_company","company_id":"1","expected_remote_version":"v1","fields":{"name":"D"}}}"#,
        r#"{"provider":"crm","operation":{"action":"create_manual_task","subject":"Call","due_at":1700000000}}"#,
        r#"{"provider":"crm","operation":{"action":"update_manual_task","task_id":"1","expected_remote_version":"v1","subject":"Call later","due_at":1700000001}}"#,
        r#"{"provider":"crm","operation":{"action":"complete_manual_task","task_id":"1","expected_remote_version":"v1"}}"#,
        r#"{"provider":"crm","operation":{"action":"create_project","fields":{"name":"P"}}}"#,
        r#"{"provider":"crm","operation":{"action":"update_project","project_id":"1","expected_remote_version":"v1","fields":{"name":"P2"}}}"#,
        r#"{"provider":"crm","operation":{"action":"link_granola_record","record_id":"1","granola_record_id":"g1"}}"#,
        r#"{"provider":"crm","operation":{"action":"add_tag","record_id":"contact:1","tag":"priority"}}"#,
        r#"{"provider":"outlook","operation":{"action":"create_draft","recipients":{"to":["client@example.com"],"cc":[],"bcc":[]},"subject":"S","body":"B","attachments":[]}}"#,
        r#"{"provider":"outlook","operation":{"action":"update_buzz_owned_draft","draft_id":"d1","expected_remote_version":"v1","recipients":{"to":["client@example.com"],"cc":[],"bcc":[]},"subject":"S","body":"B","attachments":[]}}"#,
        r#"{"provider":"outlook","operation":{"action":"attach_existing_file","draft_id":"d1","expected_remote_version":"v1","attachment_id":"f1"}}"#,
        r#"{"provider":"outlook","operation":{"action":"attach_drive_link","draft_id":"d1","expected_remote_version":"v1","drive_item_id":"i1"}}"#,
        r#"{"provider":"google","operation":{"action":"create_doc","title":"T","text":"Body"}}"#,
        r#"{"provider":"google","operation":{"action":"create_sheet","title":"T"}}"#,
        r#"{"provider":"google","operation":{"action":"create_simple_slides","title":"T","slides":["one"]}}"#,
        r#"{"provider":"google","operation":{"action":"edit_doc","document_id":"d1","expected_remote_version":"v1","text":"new"}}"#,
        r#"{"provider":"google","operation":{"action":"edit_sheet_range","spreadsheet_id":"s1","range":"Sheet1!A1:B2","expected_remote_version":"v1","values":[["a","b"]]}}"#,
        r#"{"provider":"google","operation":{"action":"replace_slides_text","presentation_id":"p1","expected_remote_version":"v1","find":"old","replace":"new"}}"#,
    ];

    assert_eq!(
        fixtures.len(),
        23,
        "frozen allowlist must contain 23 operations"
    );

    for json in fixtures {
        assert!(
            serde_json::from_str::<PositiveWriteOperation>(json).is_ok(),
            "allowed operation was rejected: {json}"
        );
    }
}

fn core_event(keys: &Keys, kind: u32, tags: Vec<Tag>, content: &str) -> nostr::Event {
    EventBuilder::new(Kind::Custom(kind as u16), content)
        .tags(tags)
        .sign_with_keys(keys)
        .expect("test event signs")
}

fn synthetic_nip44_v2(padded_plaintext_len: usize) -> String {
    let mut decoded = vec![0u8; 67 + padded_plaintext_len];
    decoded[0] = 2;
    BASE64_STANDARD.encode(decoded)
}

#[test]
fn nip44_v2_validator_enforces_actual_padding_buckets() {
    for padded_len in [256, 320, 384, 448, 512, 65_536] {
        assert!(
            buzz_core::observer::validate_syntactic_nip44_v2(&synthetic_nip44_v2(padded_len))
                .is_ok(),
            "rejected valid NIP-44 padded length {padded_len}"
        );
    }

    assert!(
        buzz_core::observer::validate_syntactic_nip44_v2(&synthetic_nip44_v2(288)).is_err(),
        "accepted impossible 288-byte NIP-44 padded length"
    );
}

#[test]
fn encrypted_core_content_uses_ciphertext_not_plaintext_size_bound() {
    let author = Keys::generate();
    let recipient = Keys::generate().public_key().to_hex();
    let tags = vec![
        Tag::parse(["h", "550e8400-e29b-41d4-a716-446655440000"]).expect("h"),
        Tag::parse(["p", recipient.as_str()]).expect("p"),
    ];
    let max_ciphertext = synthetic_nip44_v2(65_536);
    assert_eq!(max_ciphertext.len(), 87_472);
    let encrypted = core_event(&author, 44_210, tags.clone(), &max_ciphertext);

    assert!(validate_core_envelope(&encrypted).is_ok());
    assert!(validate_core_plaintext_content(&encrypted, 1_700_000_000).is_ok());

    let oversized_plaintext = core_event(&author, 44_300, tags, &"x".repeat(65_536));
    let error = validate_core_plaintext_content(&oversized_plaintext, 1_700_000_000)
        .expect_err("relay-readable plaintext must retain its size cap");
    assert!(error.to_string().contains("exceeds 65535 bytes"));
}

#[test]
fn core_envelope_requires_exact_canonical_private_route() {
    let author = Keys::generate();
    let recipient = Keys::generate().public_key().to_hex();
    let channel = "550e8400-e29b-41d4-a716-446655440000";
    let tags = vec![
        Tag::parse(["h", channel]).expect("h tag"),
        Tag::parse(["p", recipient.as_str()]).expect("p tag"),
    ];
    let event = core_event(&author, 44_300, tags.clone(), "{}");
    let envelope = validate_core_envelope(&event).expect("valid envelope");
    assert_eq!(envelope.channel_id.to_string(), channel);
    assert_eq!(envelope.recipient.to_hex(), recipient);
    assert_eq!(envelope.direction, CoreDirection::AgentToOwner);

    let mut duplicate_h = tags.clone();
    duplicate_h.push(Tag::parse(["h", channel]).expect("h tag"));
    assert!(validate_core_envelope(&core_event(&author, 44_300, duplicate_h, "{}")).is_err());

    let uppercase_p = vec![
        Tag::parse(["h", channel]).expect("h tag"),
        Tag::parse(["p", recipient.to_uppercase().as_str()]).expect("p tag"),
    ];
    assert!(validate_core_envelope(&core_event(&author, 44_300, uppercase_p, "{}")).is_err());

    let self_p = vec![
        Tag::parse(["h", channel]).expect("h tag"),
        Tag::parse(["p", author.public_key().to_hex().as_str()]).expect("p tag"),
    ];
    assert!(validate_core_envelope(&core_event(&author, 44_300, self_p, "{}")).is_err());
}

#[test]
fn bundle_head_requires_one_lowercase_hash_coordinate() {
    let author = Keys::generate();
    let recipient = Keys::generate();
    let recipient_hex = recipient.public_key().to_hex();
    let encrypted = buzz_core::observer::encrypt_observer_payload(
        &author,
        &recipient.public_key(),
        &serde_json::json!({"schema_version": 1}),
    )
    .expect("NIP-44 v2 fixture");
    let base = vec![
        Tag::parse(["h", "550e8400-e29b-41d4-a716-446655440000"]).expect("h tag"),
        Tag::parse(["p", recipient_hex.as_str()]).expect("p tag"),
    ];
    assert!(
        validate_core_envelope(&core_event(&author, 30_179, base.clone(), &encrypted)).is_err()
    );

    let mut valid = base;
    valid.push(
        Tag::parse([
            "d",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ])
        .expect("d tag"),
    );
    assert!(validate_core_envelope(&core_event(&author, 30_179, valid, &encrypted)).is_ok());
}

#[test]
fn malformed_duplicate_route_tags_fail_closed() {
    let author = Keys::generate();
    let recipient = Keys::generate().public_key().to_hex();
    let channel = "550e8400-e29b-41d4-a716-446655440000";
    let base = vec![
        Tag::parse(["h", channel]).expect("h tag"),
        Tag::parse(["p", recipient.as_str()]).expect("p tag"),
    ];

    for malformed in [
        Tag::parse(["h", channel, "extra"]).expect("malformed h tag parses"),
        Tag::parse(["p", recipient.as_str(), "extra"]).expect("malformed p tag parses"),
    ] {
        let mut tags = base.clone();
        tags.push(malformed);
        assert!(validate_core_envelope(&core_event(&author, 44_300, tags, "{}")).is_err());
    }

    let mut non_addressable_d = base.clone();
    non_addressable_d.push(Tag::parse(["d", &"a".repeat(64)]).expect("d tag"));
    assert!(validate_core_envelope(&core_event(&author, 44_300, non_addressable_d, "{}")).is_err());

    let mut bundle_tags = base;
    bundle_tags.push(Tag::parse(["d", &"a".repeat(64)]).expect("d tag"));
    bundle_tags.push(Tag::parse(["d", &"b".repeat(64), "extra"]).expect("malformed d"));
    assert!(
        validate_core_envelope(&core_event(&author, 30_179, bundle_tags, &"A".repeat(132),))
            .is_err()
    );
}

#[test]
fn v1_wire_enums_match_the_frozen_contract() {
    for disposition in [
        "done",
        "snoozed",
        "already_handled",
        "not_relevant",
        "wrong_context",
        "too_sensitive",
        "bad_recommendation",
    ] {
        let resume_at = if disposition == "snoozed" {
            "1700003600"
        } else {
            "null"
        };
        let json = format!(
            r#"{{"schema_version":1,"disposition_id":"550e8400-e29b-41d4-a716-446655440000","insight_id":"6ba7b810-9dad-41d1-80b4-00c04fd430c8","disposition":"{disposition}","reason":"owner reason","correction":null,"resume_at":{resume_at},"occurred_at":1700000000}}"#
        );
        assert!(
            serde_json::from_str::<InsightDispositionPayload>(&json).is_ok(),
            "frozen disposition rejected: {disposition}"
        );
    }
    for disposition in ["useful", "dismissed", "approved"] {
        let json = format!(
            r#"{{"schema_version":1,"disposition_id":"550e8400-e29b-41d4-a716-446655440000","insight_id":"6ba7b810-9dad-41d1-80b4-00c04fd430c8","disposition":"{disposition}","reason":"reason","correction":null,"resume_at":null,"occurred_at":1700000000}}"#
        );
        assert!(serde_json::from_str::<InsightDispositionPayload>(&json).is_err());
    }

    let self_speaker = r#"{"schema_version":1,"segment_id":"550e8400-e29b-41d4-a716-446655440000","call_id":"6ba7b810-9dad-41d1-80b4-00c04fd430c8","sequence":1,"speaker":"self","text":"hello","started_at_ms":1,"ended_at_ms":2,"model_version":"parakeet-v1","confidence":90}"#;
    let others_speaker = self_speaker.replace("\"self\"", "\"others\"");
    assert!(serde_json::from_str::<TranscriptSegmentPayload>(self_speaker).is_ok());
    assert!(serde_json::from_str::<TranscriptSegmentPayload>(&others_speaker).is_ok());
}

#[test]
fn evidence_and_operation_strings_are_bounded_and_typed() {
    let url_evidence = r#"{"source":"crm","source_id":"https://attacker.example/private","source_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    assert!(serde_json::from_str::<buzz_core::core_protocol::EvidenceRef>(url_evidence).is_err());

    let arbitrary_activity = r#"{"provider":"crm","operation":{"action":"log_activity","record_id":"contact:1","activity_type":"delete_everything","body":"summary"}}"#;
    assert!(serde_json::from_str::<PositiveWriteOperation>(arbitrary_activity).is_err());

    let oversized = "x".repeat(4097);
    let oversized_note = format!(
        r#"{{"provider":"crm","operation":{{"action":"add_note","record_id":"contact:1","body":"{oversized}"}}}}"#
    );
    assert!(serde_json::from_str::<PositiveWriteOperation>(&oversized_note).is_err());
}

#[test]
fn assistant_insight_v1_has_frozen_evidence_and_version_shape() {
    let json = r#"{
        "schema_version":1,
        "insight_id":"550e8400-e29b-41d4-a716-446655440000",
        "category":"commitment_deadline",
        "priority":"high",
        "change":"A promised follow-up is due",
        "why_it_matters":"The client is waiting",
        "evidence":[{"source":"buzz_event","source_id":"event:abc","source_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],
        "confidence":92,
        "freshness":"same_day",
        "recommendation":"Send a concise update",
        "draft":{"kind":"outlook_draft","subject":"Update","body":"Draft body"},
        "dedupe_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "created_at":1700000000,
        "safety_policy_version":"s1",
        "persona_version":"p1",
        "firm_version":"f1",
        "personal_version":"u1",
        "model_version":"m1"
    }"#;
    assert!(serde_json::from_str::<InsightPayload>(json).is_ok());
    assert!(serde_json::from_str::<InsightPayload>(&json.replace("92", "101")).is_err());
}

#[test]
fn proposal_and_receipt_bind_target_state_and_reconciliation() {
    let proposal = r#"{
        "schema_version":1,
        "proposal_id":"550e8400-e29b-41d4-a716-446655440000",
        "nonce":"6ba7b810-9dad-41d1-80b4-00c04fd430c8",
        "operation_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "proposed_at":1700000000,
        "expires_at":1700000900,
        "bundle_semantics":"independent_operations",
        "operations":[{
            "operation_id":"6ba7b812-9dad-41d1-80b4-00c04fd430c8",
            "operation_hash":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "idempotency_key":"6ba7b811-9dad-41d1-80b4-00c04fd430c8",
            "target":{"provider":"crm","account_id":"acct:1","scope_id":"workspace:1","object_id":"contact:1"},
            "before":{"canonical_value":"{\"name\":\"A\"}","value_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
            "after":{"canonical_value":"{\"name\":\"B\"}","value_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
            "expected_remote_version":"v1",
            "side_effects":["updates_record"],
            "operation":{"provider":"crm","operation":{"action":"add_tag","record_id":"contact:1","tag":"priority"}}
        }],
        "evidence":[{"source":"crm","source_id":"contact:1","source_hash":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}]
    }"#;
    assert!(serde_json::from_str::<ActionProposalPayload>(proposal).is_ok());

    let receipt = r#"{
        "schema_version":1,
        "receipt_id":"550e8400-e29b-41d4-a716-446655440000",
        "proposal_id":"6ba7b810-9dad-41d1-80b4-00c04fd430c8",
        "decision_id":"6ba7b811-9dad-41d1-80b4-00c04fd430c8",
        "operation_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "results":[{
            "operation_id":"6ba7b812-9dad-41d1-80b4-00c04fd430c8",
            "operation_hash":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "idempotency_key":"6ba7b813-9dad-41d1-80b4-00c04fd430c8",
            "outcome":"succeeded",
            "external_result_id":"remote:1",
            "external_result_version":"v2",
            "reconciliation_status":"not_required"
        }],
        "occurred_at":1700000000
    }"#;
    assert!(serde_json::from_str::<ActionReceiptPayload>(receipt).is_ok());
}

#[test]
fn learning_and_call_payloads_are_typed_and_sequenced() {
    let learning = r#"{
        "schema_version":1,
        "record_id":"550e8400-e29b-41d4-a716-446655440000",
        "layer":"personal",
        "domain":"writing_style_traits",
        "revision":1,
        "record_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "record":{"kind":"candidate","candidate":"Prefer concise updates","source_signal_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        "created_at":1700000000,
        "evidence_hashes":[]
    }"#;
    assert!(serde_json::from_str::<LearningRecordPayload>(learning).is_ok());

    let call = r#"{
        "schema_version":1,
        "call_id":"550e8400-e29b-41d4-a716-446655440000",
        "command":"heartbeat",
        "session_state":"active",
        "source_health":{"microphone":"healthy","output":"degraded"},
        "degraded_reasons":["output_silent"],
        "sequence":4,
        "meeting_context":{"source":"calendar","source_id":"meeting:1","title":"Client call"},
        "occurred_at":1700000000
    }"#;
    assert!(serde_json::from_str::<CallControlPayload>(call).is_ok());

    let transcript = r#"{
        "schema_version":1,
        "segment_id":"550e8400-e29b-41d4-a716-446655440000",
        "call_id":"6ba7b810-9dad-41d1-80b4-00c04fd430c8",
        "sequence":5,
        "speaker":"self",
        "text":"hello",
        "started_at_ms":1,
        "ended_at_ms":2,
        "model_version":"parakeet-v1",
        "confidence":88
    }"#;
    assert!(serde_json::from_str::<TranscriptSegmentPayload>(transcript).is_ok());
}

#[test]
fn relay_plaintext_validation_rejects_unknown_version_and_expired_proposal() {
    let author = Keys::generate();
    let recipient = Keys::generate().public_key().to_hex();
    let tags = vec![
        Tag::parse(["h", "550e8400-e29b-41d4-a716-446655440000"]).expect("h"),
        Tag::parse(["p", recipient.as_str()]).expect("p"),
    ];
    let bad_insight = core_event(&author, 44_300, tags.clone(), INSIGHT_JSON_VERSION_2);
    assert!(validate_core_plaintext_content(&bad_insight, 1_700_000_000).is_err());

    let expired = r#"{
        "schema_version":1,
        "proposal_id":"550e8400-e29b-41d4-a716-446655440000",
        "nonce":"6ba7b810-9dad-41d1-80b4-00c04fd430c8",
        "operation_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "proposed_at":1699999000,
        "expires_at":1699999900,
        "bundle_semantics":"independent_operations",
        "operations":[{
            "operation_id":"6ba7b812-9dad-41d1-80b4-00c04fd430c8",
            "operation_hash":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "idempotency_key":"6ba7b811-9dad-41d1-80b4-00c04fd430c8",
            "target":{"provider":"crm","account_id":"acct:1","scope_id":"workspace:1","object_id":"contact:1"},
            "before":{"canonical_value":"old","value_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
            "after":{"canonical_value":"new","value_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
            "expected_remote_version":"v1",
            "side_effects":["updates_record"],
            "operation":{"provider":"crm","operation":{"action":"add_tag","record_id":"contact:1","tag":"priority"}}
        }],
        "evidence":[{"source":"crm","source_id":"contact:1","source_hash":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}]
    }"#;
    let proposal = core_event(&author, 44_310, tags, expired);
    assert!(validate_core_plaintext_content(&proposal, 1_700_000_000).is_err());
}

const INSIGHT_JSON_VERSION_2: &str = r#"{
    "schema_version":2,
    "insight_id":"550e8400-e29b-41d4-a716-446655440000",
    "category":"commitment_deadline",
    "change":"changed",
    "why_it_matters":"matters",
    "evidence":[],
    "confidence":92,
    "freshness":"same_day",
    "recommendation":"act",
    "draft":null,
    "dedupe_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "created_at":1700000000,
    "safety_policy_version":"s1","persona_version":"p1","firm_version":"f1",
    "personal_version":"u1","model_version":"m1"
}"#;

#[test]
fn insight_and_proposal_evidence_is_nonempty_bounded_and_unique() {
    let public_web = r#"{"source":"public_web","source_id":"article:abc","source_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","citation":{"title":"Public filing","resolver_id":"citation:abc"}}"#;
    assert!(serde_json::from_str::<buzz_core::core_protocol::EvidenceRef>(public_web).is_ok());

    let valid = r#"{
        "schema_version":1,"insight_id":"550e8400-e29b-41d4-a716-446655440000",
        "category":"deal_movement","change":"changed","why_it_matters":"matters",
        "priority":"normal",
        "evidence":[{"source":"public_web","source_id":"article:abc","source_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","citation":{"title":"Public filing","resolver_id":"citation:abc"}}],
        "confidence":80,"freshness":"recent","recommendation":"review","draft":null,
        "dedupe_key":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "created_at":1700000000,"safety_policy_version":"s1","persona_version":"p1",
        "firm_version":"f1","personal_version":"u1","model_version":"m1"
}"#;
    assert!(serde_json::from_str::<InsightPayload>(valid).is_ok());
    assert!(serde_json::from_str::<InsightPayload>(&valid.replace(
        r#"[{"source":"public_web","source_id":"article:abc","source_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","citation":{"title":"Public filing","resolver_id":"citation:abc"}}]"#,
        "[]"
    )).is_err());
    let evidence = r#"{"source":"public_web","source_id":"article:abc","source_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","citation":{"title":"Public filing","resolver_id":"citation:abc"}}"#;
    assert!(serde_json::from_str::<InsightPayload>(&valid.replace(
        format!("[{evidence}]").as_str(),
        format!("[{evidence},{evidence}]").as_str()
    ))
    .is_err());
    let too_many = std::iter::repeat_n(evidence, 33)
        .collect::<Vec<_>>()
        .join(",");
    assert!(serde_json::from_str::<InsightPayload>(&valid.replace(
        format!("[{evidence}]").as_str(),
        format!("[{too_many}]").as_str()
    ))
    .is_err());
}

#[test]
fn proposal_cross_field_invariants_fail_closed() {
    let valid = r#"{
        "schema_version":1,"proposal_id":"550e8400-e29b-41d4-a716-446655440000",
        "nonce":"6ba7b810-9dad-41d1-80b4-00c04fd430c8",
        "operation_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "proposed_at":1700000000,"expires_at":1700000900,
        "bundle_semantics":"independent_operations","operations":[{
            "operation_id":"6ba7b812-9dad-41d1-80b4-00c04fd430c8",
            "operation_hash":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "idempotency_key":"6ba7b811-9dad-41d1-80b4-00c04fd430c8",
            "target":{"provider":"crm","account_id":"acct:1","scope_id":"workspace:1","object_id":"contact:1"},
            "before":{"canonical_value":"old","value_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
            "after":{"canonical_value":"new","value_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
            "expected_remote_version":"v1","side_effects":["updates_record"],
            "operation":{"provider":"crm","operation":{"action":"add_tag","record_id":"contact:1","tag":"priority"}}
        }],
        "evidence":[{"source":"crm","source_id":"contact:1","source_hash":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}]
    }"#;
    let proposal: ActionProposalPayload = serde_json::from_str(valid).expect("valid shape");
    assert!(proposal.validate_at(1_700_000_000).is_ok());

    let mismatch: ActionProposalPayload = serde_json::from_str(&valid.replace(
        "\"provider\":\"crm\",\"account_id\"",
        "\"provider\":\"google\",\"account_id\"",
    ))
    .expect("shape");
    assert!(mismatch.validate_at(1_700_000_000).is_err());

    assert!(
        serde_json::from_str::<ActionProposalPayload>(&valid.replace(
            r#"["updates_record"]"#,
            r#"["updates_record","updates_record"]"#,
        ))
        .is_err()
    );
}

#[test]
fn decision_signer_and_receipt_outcome_are_bound() {
    let author = Keys::generate();
    let recipient = Keys::generate().public_key().to_hex();
    let decision = format!(
        r#"{{"schema_version":1,"decision_id":"550e8400-e29b-41d4-a716-446655440000","proposal_id":"6ba7b810-9dad-41d1-80b4-00c04fd430c8","nonce":"6ba7b811-9dad-41d1-80b4-00c04fd430c8","operation_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","decision":"approve","signer":"{}","decided_at":1700000000}}"#,
        author.public_key().to_hex()
    );
    let tags = vec![
        Tag::parse(["h", "550e8400-e29b-41d4-a716-446655440000"]).expect("h"),
        Tag::parse(["p", recipient.as_str()]).expect("p"),
    ];
    let event = core_event(&author, 44_311, tags.clone(), &decision);
    assert!(validate_core_plaintext_content(&event, 1_700_000_000).is_ok());
    let mismatched = core_event(
        &author,
        44_311,
        tags,
        &decision.replace(
            &author.public_key().to_hex(),
            &Keys::generate().public_key().to_hex(),
        ),
    );
    assert!(validate_core_plaintext_content(&mismatched, 1_700_000_000).is_err());

    let failure = r#"{"schema_version":1,"receipt_id":"550e8400-e29b-41d4-a716-446655440000","proposal_id":"6ba7b810-9dad-41d1-80b4-00c04fd430c8","decision_id":"6ba7b811-9dad-41d1-80b4-00c04fd430c8","operation_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","results":[{"operation_id":"6ba7b812-9dad-41d1-80b4-00c04fd430c8","operation_hash":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","idempotency_key":"6ba7b813-9dad-41d1-80b4-00c04fd430c8","outcome":"failed","external_result_id":null,"external_result_version":null,"reconciliation_status":"not_required"}],"occurred_at":1700000000}"#;
    let receipt: ActionReceiptPayload = serde_json::from_str(failure).expect("definitive failure");
    assert!(receipt.validate().is_ok());
}

#[test]
fn collection_limits_and_copilot_interrupt_semantics_are_closed() {
    let slides = std::iter::repeat_n("\"slide\"", 101)
        .collect::<Vec<_>>()
        .join(",");
    let operation = format!(
        r#"{{"provider":"google","operation":{{"action":"create_simple_slides","title":"T","slides":[{slides}]}}}}"#
    );
    assert!(serde_json::from_str::<PositiveWriteOperation>(&operation).is_err());

    let suggestion = r#"{"schema_version":1,"suggestion_id":"550e8400-e29b-41d4-a716-446655440000","call_id":"6ba7b810-9dad-41d1-80b4-00c04fd430c8","sequence":6,"category":"decision","interrupt":"quiet","text":"Confirm the deadline","created_at":1700000000,"model_version":"m1","confidence":90,"evidence_hashes":[]}"#;
    assert!(serde_json::from_str::<CopilotSuggestionPayload>(suggestion).is_ok());
    assert!(serde_json::from_str::<CopilotSuggestionPayload>(
        &suggestion.replace("\"quiet\"", "\"loud\"")
    )
    .is_err());
}

#[test]
fn proposal_bundle_is_bounded_and_validates_every_member() {
    let member = r#"{"operation_id":"6ba7b812-9dad-41d1-80b4-00c04fd430c8","operation_hash":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","idempotency_key":"6ba7b813-9dad-41d1-80b4-00c04fd430c8","target":{"provider":"crm","account_id":"acct:1","scope_id":"workspace:1","object_id":"contact:1"},"before":{"canonical_value":"old","value_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"after":{"canonical_value":"new","value_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"expected_remote_version":"v1","side_effects":["updates_record"],"operation":{"provider":"crm","operation":{"action":"add_tag","record_id":"contact:1","tag":"priority"}}}"#;
    let proposal = format!(
        r#"{{"schema_version":1,"proposal_id":"550e8400-e29b-41d4-a716-446655440000","nonce":"6ba7b810-9dad-41d1-80b4-00c04fd430c8","operation_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","proposed_at":1700000000,"expires_at":1700000900,"bundle_semantics":"independent_operations","operations":[{member}],"evidence":[{{"source":"crm","source_id":"contact:1","source_hash":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}}]}}"#
    );
    let parsed: ActionProposalPayload = serde_json::from_str(&proposal).expect("one-member bundle");
    assert!(parsed.validate_at(1_700_000_000).is_ok());

    let mismatched = proposal.replace(
        r#""target":{"provider":"crm""#,
        r#""target":{"provider":"google""#,
    );
    let parsed: ActionProposalPayload = serde_json::from_str(&mismatched).expect("shape");
    assert!(parsed.validate_at(1_700_000_000).is_err());

    let too_many = std::iter::repeat_n(member, 11)
        .collect::<Vec<_>>()
        .join(",");
    assert!(
        serde_json::from_str::<ActionProposalPayload>(&proposal.replace(
            format!("[{member}]").as_str(),
            format!("[{too_many}]").as_str(),
        ))
        .is_err()
    );
}

#[test]
fn bundle_receipt_reports_ordered_member_results_with_idempotency_bindings() {
    let receipt = r#"{
        "schema_version":1,
        "receipt_id":"550e8400-e29b-41d4-a716-446655440000",
        "proposal_id":"6ba7b810-9dad-41d1-80b4-00c04fd430c8",
        "decision_id":"6ba7b811-9dad-41d1-80b4-00c04fd430c8",
        "operation_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "results":[
            {
                "operation_id":"6ba7b812-9dad-41d1-80b4-00c04fd430c8",
                "operation_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "idempotency_key":"6ba7b813-9dad-41d1-80b4-00c04fd430c8",
                "outcome":"succeeded",
                "external_result_id":"remote:1",
                "external_result_version":"v2",
                "reconciliation_status":"not_required"
            },
            {
                "operation_id":"6ba7b814-9dad-41d1-80b4-00c04fd430c8",
                "operation_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "idempotency_key":"6ba7b815-9dad-41d1-80b4-00c04fd430c8",
                "outcome":"reconciliation_required",
                "external_result_id":null,
                "external_result_version":null,
                "reconciliation_status":"pending"
            }
        ],
        "occurred_at":1700000000
    }"#;
    let parsed: ActionReceiptPayload = serde_json::from_str(receipt).expect("bundle receipt");
    assert_eq!(parsed.results.len(), 2);
    assert!(parsed.validate().is_ok());
}

#[test]
fn action_target_binds_approved_scope_and_member_idempotency() {
    let proposal = r#"{
        "schema_version":1,"proposal_id":"550e8400-e29b-41d4-a716-446655440000",
        "nonce":"6ba7b810-9dad-41d1-80b4-00c04fd430c8",
        "operation_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "proposed_at":1700000000,"expires_at":1700000900,
        "bundle_semantics":"independent_operations","operations":[{
            "operation_id":"6ba7b812-9dad-41d1-80b4-00c04fd430c8",
            "operation_hash":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "idempotency_key":"6ba7b813-9dad-41d1-80b4-00c04fd430c8",
            "target":{"provider":"google","account_id":"acct:1","scope_id":"folder:approved","object_id":null},
            "before":null,
            "after":{"canonical_value":"new","value_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
            "expected_remote_version":null,"side_effects":["creates_record"],
            "operation":{"provider":"google","operation":{"action":"create_doc","title":"Plan","text":"Body"}}
        }],
        "evidence":[{"source":"google_drive","source_id":"folder:approved","source_hash":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}]
    }"#;
    let parsed: ActionProposalPayload = serde_json::from_str(proposal).expect("scoped create");
    assert_eq!(
        parsed.operations[0].target.scope_id.as_str(),
        "folder:approved"
    );
    assert!(parsed.validate_at(1_700_000_000).is_ok());
}

#[test]
fn outlook_recipient_classes_and_outer_operation_shape_are_frozen() {
    let draft = r#"{"provider":"outlook","operation":{"action":"create_draft","recipients":{"to":["to@example.com"],"cc":["cc@example.com"],"bcc":["bcc@example.com"]},"subject":"Subject","body":"Body","attachments":[]}}"#;
    assert!(serde_json::from_str::<PositiveWriteOperation>(draft).is_ok());
    assert!(serde_json::from_str::<PositiveWriteOperation>(
        r#"{"provider":"outlook","operation":{"action":"create_draft","recipients":{"to":["to@example.com"],"cc":[],"bcc":[]},"subject":"Subject","body":"Body","attachments":[]},"smuggled":true}"#,
    )
    .is_err());
}

#[test]
fn copilot_interrupts_only_for_evidenced_missed_commitments_or_contradictions() {
    let quiet = r#"{"schema_version":1,"suggestion_id":"550e8400-e29b-41d4-a716-446655440000","call_id":"6ba7b810-9dad-41d1-80b4-00c04fd430c8","sequence":1,"category":"private_question","interrupt":"quiet","text":"Ask privately","created_at":1700000000,"model_version":"local-v1","confidence":80,"evidence_hashes":[]}"#;
    assert!(serde_json::from_str::<CopilotSuggestionPayload>(quiet).is_ok());

    let critical = quiet
        .replace("private_question", "missed_commitment")
        .replace("\"quiet\"", "\"critical\"")
        .replace("\"evidence_hashes\":[]", "\"evidence_hashes\":[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]");
    assert!(serde_json::from_str::<CopilotSuggestionPayload>(&critical).is_ok());
    assert!(serde_json::from_str::<CopilotSuggestionPayload>(
        &critical.replace("missed_commitment", "action"),
    )
    .is_err());
    assert!(serde_json::from_str::<CopilotSuggestionPayload>(
        &critical.replace(
            "\"evidence_hashes\":[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]",
            "\"evidence_hashes\":[]",
        ),
    )
    .is_err());
}

#[test]
fn learning_domains_snooze_window_and_nip44_framing_are_closed() {
    assert!(
        serde_json::from_str::<buzz_core::core_protocol::LearningLayer>("\"sanitized_firm\"")
            .is_ok()
    );
    assert!(serde_json::from_str::<buzz_core::core_protocol::LearningLayer>("\"firm\"").is_err());
    for domain in [
        "ranking_within_policy_tier",
        "timing_within_allowed_feed_window",
        "card_presentation_preference",
        "writing_style_traits",
        "relationship_priority_hints",
        "source_quality_weights",
        "buyer_selection_heuristics",
        "research_heuristics",
        "bounded_workflow_ordering",
    ] {
        let json = format!("\"{domain}\"");
        assert!(serde_json::from_str::<buzz_core::core_protocol::LearningDomain>(&json).is_ok());
    }
    assert!(
        serde_json::from_str::<buzz_core::core_protocol::LearningDomain>("\"communication\"")
            .is_err()
    );

    let too_far = r#"{"schema_version":1,"disposition_id":"550e8400-e29b-41d4-a716-446655440000","insight_id":"6ba7b810-9dad-41d1-80b4-00c04fd430c8","disposition":"snoozed","reason":"Later","correction":null,"resume_at":1702678401,"occurred_at":1700000000}"#;
    let disposition: InsightDispositionPayload = serde_json::from_str(too_far).expect("shape");
    assert!(disposition.validate().is_err());

    let author = Keys::generate();
    let recipient = Keys::generate().public_key().to_hex();
    let tags = vec![
        Tag::parse(["h", "550e8400-e29b-41d4-a716-446655440000"]).expect("h"),
        Tag::parse(["p", recipient.as_str()]).expect("p"),
    ];
    let non_base64 = core_event(&author, 44_210, tags.clone(), &"!".repeat(132));
    assert!(validate_core_envelope(&non_base64).is_err());
    let wrong_version = core_event(&author, 44_210, tags, &"A".repeat(132));
    assert!(validate_core_envelope(&wrong_version).is_err());
}
