use buzz_core::engram::conversation_key;
use buzz_sdk::core_protocol::{InsightPayload, LearningDomain, LearningLayer};
use buzz_sdk::{
    build_agent_observer_frame, build_core_insight, build_core_learning_bundle_head,
    build_core_learning_record, parse_core_payload,
};
use nostr::Keys;
use uuid::Uuid;

const INSIGHT: &str = r#"{
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
    "draft":null,
    "dedupe_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "created_at":1700000000,
    "safety_policy_version":"s1",
    "persona_version":"p1",
    "firm_version":"f1",
    "personal_version":"u1",
    "model_version":"m1"
}"#;

const VALID_NIP44_V2: &str = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const WRONG_NIP44_VERSION: &str = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const WRONG_NIP44_PADDING: &str = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
const LEARNING_COORDINATE_PERSONAL_RANKING: &str =
    "5057dfc0c146934621eee8ceb95aa90a6a1729caf14676bbe377999eb1f0544d";

#[test]
fn sdk_builds_exact_private_core_envelope() {
    let author = Keys::generate();
    let recipient = Keys::generate();
    let channel = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("uuid");
    let payload: InsightPayload = parse_core_payload(INSIGHT).expect("valid payload");

    let event = build_core_insight(channel, &recipient.public_key(), &payload)
        .expect("builder")
        .sign_with_keys(&author)
        .expect("sign");
    assert_eq!(event.kind.as_u16(), 44_300);
    let tags: Vec<Vec<String>> = event
        .tags
        .iter()
        .map(|tag| tag.as_slice().iter().map(ToString::to_string).collect())
        .collect();
    assert_eq!(
        tags,
        vec![
            vec!["h".into(), channel.to_string()],
            vec!["p".into(), recipient.public_key().to_hex()],
        ]
    );
}

#[test]
fn sdk_parser_rejects_unknown_versions_and_fields() {
    assert!(parse_core_payload::<InsightPayload>(
        &INSIGHT.replace("\"schema_version\":1", "\"schema_version\":2")
    )
    .is_err());
    assert!(parse_core_payload::<InsightPayload>(
        &INSIGHT.replace("\"draft\":null", "\"draft\":null,\"approval\":true")
    )
    .is_err());
}

#[test]
fn sdk_encrypted_builders_require_strict_nip44_v2_framing() {
    let agent = Keys::generate();
    let recipient = Keys::generate();
    let channel = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("uuid");

    for malformed in [
        "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
        WRONG_NIP44_VERSION,
        WRONG_NIP44_PADDING,
    ] {
        assert!(
            build_core_learning_record(channel, &recipient.public_key(), malformed).is_err(),
            "Core encrypted builder accepted malformed framing"
        );
        assert!(
            build_agent_observer_frame(
                &recipient.public_key().to_hex(),
                &agent.public_key().to_hex(),
                "telemetry",
                malformed,
            )
            .is_err(),
            "observer encrypted builder accepted malformed framing"
        );
    }

    assert!(build_core_learning_record(channel, &recipient.public_key(), VALID_NIP44_V2).is_ok());
}

#[test]
fn learning_bundle_builder_derives_canonical_coordinate() {
    let agent = Keys::parse("0000000000000000000000000000000000000000000000000000000000000001")
        .expect("fixed agent key");
    let owner = Keys::parse("0000000000000000000000000000000000000000000000000000000000000002")
        .expect("fixed owner key");
    let conversation_key = conversation_key(agent.secret_key(), &owner.public_key());
    let channel = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("uuid");

    let event = build_core_learning_bundle_head(
        channel,
        &owner.public_key(),
        &conversation_key,
        LearningLayer::Personal,
        LearningDomain::RankingWithinPolicyTier,
        VALID_NIP44_V2,
    )
    .expect("builder")
    .sign_with_keys(&agent)
    .expect("sign");
    let d_tags: Vec<&str> = event
        .tags
        .iter()
        .filter_map(|tag| {
            let parts = tag.as_slice();
            (parts.first().map(|part| part.as_str()) == Some("d"))
                .then(|| parts.get(1).map(|part| part.as_str()))
                .flatten()
        })
        .collect();

    assert_eq!(d_tags, vec![LEARNING_COORDINATE_PERSONAL_RANKING]);
}
