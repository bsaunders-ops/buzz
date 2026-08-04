use std::{future::Future, pin::Pin};

use buzz_assistant_broker::{
    run_private_assistant_turn, AssistantAuthorityResolver, AssistantModel, AuthorizedFtsRetriever,
    BrokerVersionStamps, InsightCommandSink, ModelFailure, ModelRequest, PrivateAssistantRoute,
    PublishFailure, RetrievalFailure, ServerAuthenticatedTurn, TurnError, LOCKED_SYSTEM_POLICY,
};
use buzz_connector_core::{
    retrieval::{AuthorizedExcerpt, Citation, CitationFreshness, FullTextRetrievalQuery},
    types::{ConnectorProvider, RemoteVersion, SourceKind},
};
use buzz_core::{
    core_protocol::{EvidenceSource, InsightPayload},
    CommunityId,
};
use chrono::{TimeZone, Utc};
use nostr::{EventBuilder, Keys};
use serde_json::Value;
use uuid::Uuid;

const COMMUNITY: Uuid = Uuid::from_u128(0x100);
const PRIVATE_CHANNEL: Uuid = Uuid::from_u128(0x200);
const SOURCE_CHANNEL: Uuid = Uuid::from_u128(0x300);
const CREATED_AT: i64 = 1_700_000_000;

fn excerpt() -> AuthorizedExcerpt {
    let citation = Citation::new(
        "Client follow-up",
        ConnectorProvider::MicrosoftGraph,
        SourceKind::Email,
        Utc.with_ymd_and_hms(2026, 8, 3, 12, 0, 0)
            .single()
            .expect("timestamp"),
        Utc.with_ymd_and_hms(2026, 8, 3, 12, 5, 0)
            .single()
            .expect("timestamp"),
        "https://outlook.office.com/mail/deeplink/read/opaque",
        [1; 32],
        RemoteVersion::new("v7", Some("etag-v7".into())).expect("remote version"),
        [3; 32],
        CitationFreshness::Fresh,
    )
    .expect("citation");
    AuthorizedExcerpt::new(citation, "The client follow-up is due Friday.", 10, 45)
        .expect("authorized excerpt")
}

struct Resolver {
    route: PrivateAssistantRoute,
    channels: Vec<Uuid>,
}

impl AssistantAuthorityResolver for Resolver {
    fn resolve_private_assistant(
        &mut self,
        _community: CommunityId,
        _caller: &nostr::PublicKey,
    ) -> Result<PrivateAssistantRoute, TurnError> {
        Ok(self.route.clone())
    }

    fn resolve_accessible_channels(
        &mut self,
        _community: CommunityId,
        _caller: &nostr::PublicKey,
    ) -> Result<Vec<Uuid>, TurnError> {
        Ok(self.channels.clone())
    }
}

struct Retriever {
    excerpts: Vec<AuthorizedExcerpt>,
    seen_channels: Vec<Vec<Uuid>>,
}

impl AuthorizedFtsRetriever for Retriever {
    fn retrieve<'a>(
        &'a mut self,
        _community: CommunityId,
        query: &'a FullTextRetrievalQuery,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<AuthorizedExcerpt>, RetrievalFailure>> + Send + 'a>>
    {
        self.seen_channels
            .push(query.audience().channel_ids().to_vec());
        let excerpts = self.excerpts.clone();
        Box::pin(async move { Ok(excerpts) })
    }
}

#[derive(Default)]
struct Model {
    inputs: Vec<(String, String, Vec<String>)>,
}

impl AssistantModel for Model {
    fn complete(&mut self, request: ModelRequest<'_>) -> Result<String, ModelFailure> {
        self.inputs.push((
            request.system_policy().to_owned(),
            request.question().to_owned(),
            request.excerpt_envelopes().to_vec(),
        ));
        Ok(r#"{"change":"A client follow-up is due Friday.","why_it_matters":"The client is waiting for a response.","recommendation":"Send a concise status update today.","citations":[0]}"#.into())
    }
}

#[derive(Default)]
struct Sink(Vec<EventBuilder>);

impl InsightCommandSink for Sink {
    fn enqueue(&mut self, command: EventBuilder) -> Result<(), PublishFailure> {
        self.0.push(command);
        Ok(())
    }
}

fn versions() -> BrokerVersionStamps {
    BrokerVersionStamps::new(
        "safety-v1",
        "persona-v2",
        "firm-v3",
        "personal-v4",
        "model-v5",
    )
    .expect("versions")
}

#[tokio::test]
async fn authorized_turn_emits_exact_trusted_insight_from_only_minimized_context() {
    let caller = Keys::generate();
    let assistant = Keys::generate();
    let community = CommunityId::from_uuid(COMMUNITY);
    let turn = ServerAuthenticatedTurn::from_server_facts(
        community,
        caller.public_key(),
        assistant.public_key(),
        PRIVATE_CHANNEL,
        "What needs my attention?",
    )
    .expect("turn");
    let route = PrivateAssistantRoute::server_verified(
        community,
        caller.public_key(),
        assistant.public_key(),
        PRIVATE_CHANNEL,
    );
    let mut resolver = Resolver {
        route,
        channels: vec![SOURCE_CHANNEL],
    };
    let mut retriever = Retriever {
        excerpts: vec![excerpt()],
        seen_channels: vec![],
    };
    let mut model = Model::default();
    let mut sink = Sink::default();

    run_private_assistant_turn(
        &turn,
        &versions(),
        &mut resolver,
        &mut retriever,
        &mut model,
        &mut sink,
        CREATED_AT,
    )
    .await
    .expect("authorized turn");

    assert_eq!(retriever.seen_channels, vec![vec![SOURCE_CHANNEL]; 2]);
    assert_eq!(model.inputs.len(), 1);
    assert_eq!(model.inputs[0].0, LOCKED_SYSTEM_POLICY);
    assert_eq!(model.inputs[0].1, "What needs my attention?");
    assert_eq!(model.inputs[0].2.len(), 1);
    let complete_model_input = format!(
        "{}{}{}",
        model.inputs[0].0,
        model.inputs[0].1,
        model.inputs[0].2.join("")
    );
    for private_identifier in [
        COMMUNITY.to_string(),
        PRIVATE_CHANNEL.to_string(),
        SOURCE_CHANNEL.to_string(),
        caller.public_key().to_hex(),
        assistant.public_key().to_hex(),
    ] {
        assert!(!complete_model_input.contains(&private_identifier));
    }
    let envelope: Value = serde_json::from_str(&model.inputs[0].2[0]).expect("envelope JSON");
    assert_eq!(
        envelope.get("trust").and_then(Value::as_str),
        Some("untrusted_external_source")
    );
    assert_eq!(
        envelope.get("excerpt").and_then(Value::as_str),
        Some("The client follow-up is due Friday.")
    );
    assert_eq!(
        envelope
            .as_object()
            .expect("object")
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["citation", "end_char", "excerpt", "start_char", "trust"]
    );

    assert_eq!(sink.0.len(), 1);
    let event = sink
        .0
        .pop()
        .expect("command")
        .sign_with_keys(&assistant)
        .expect("sign command");
    assert_eq!(event.kind.as_u16(), 44_300);
    let tags: Vec<Vec<String>> = event
        .tags
        .iter()
        .map(|tag| tag.as_slice().iter().map(ToString::to_string).collect())
        .collect();
    assert_eq!(
        tags,
        vec![
            vec!["h".into(), PRIVATE_CHANNEL.to_string()],
            vec!["p".into(), caller.public_key().to_hex()],
        ]
    );
    let payload: InsightPayload = serde_json::from_str(&event.content).expect("insight payload");
    assert_eq!(payload.created_at, CREATED_AT);
    assert_eq!(payload.evidence.len(), 1);
    assert_eq!(payload.evidence[0].source, EvidenceSource::Outlook);
    assert_eq!(
        payload.evidence[0].source_id.as_str(),
        format!("item:{}", hex::encode([1; 32]))
    );
    assert_eq!(
        payload.evidence[0].source_hash.as_str(),
        hex::encode([3; 32])
    );
    assert_eq!(payload.safety_policy_version.as_str(), "safety-v1");
    assert_eq!(payload.persona_version.as_str(), "persona-v2");
    assert_eq!(payload.firm_version.as_str(), "firm-v3");
    assert_eq!(payload.personal_version.as_str(), "personal-v4");
    assert_eq!(payload.model_version.as_str(), "model-v5");
}

#[tokio::test]
async fn empty_or_denied_retrieval_emits_no_model_call_and_no_command() {
    let caller = Keys::generate();
    let assistant = Keys::generate();
    let community = CommunityId::from_uuid(COMMUNITY);
    let turn = ServerAuthenticatedTurn::from_server_facts(
        community,
        caller.public_key(),
        assistant.public_key(),
        PRIVATE_CHANNEL,
        "What needs my attention?",
    )
    .expect("turn");
    let mut resolver = Resolver {
        route: PrivateAssistantRoute::server_verified(
            community,
            caller.public_key(),
            assistant.public_key(),
            PRIVATE_CHANNEL,
        ),
        channels: vec![SOURCE_CHANNEL],
    };
    let mut retriever = Retriever {
        excerpts: vec![],
        seen_channels: vec![],
    };
    let mut model = Model::default();
    let mut sink = Sink::default();

    let result = run_private_assistant_turn(
        &turn,
        &versions(),
        &mut resolver,
        &mut retriever,
        &mut model,
        &mut sink,
        CREATED_AT,
    )
    .await;

    assert_eq!(result, Err(TurnError::NoEvidence));
    assert!(model.inputs.is_empty());
    assert!(sink.0.is_empty());
}

struct RevokedRetriever {
    calls: usize,
}

impl AuthorizedFtsRetriever for RevokedRetriever {
    fn retrieve<'a>(
        &'a mut self,
        _community: CommunityId,
        _query: &'a FullTextRetrievalQuery,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<AuthorizedExcerpt>, RetrievalFailure>> + Send + 'a>>
    {
        self.calls += 1;
        let result = if self.calls == 1 {
            vec![excerpt()]
        } else {
            vec![]
        };
        Box::pin(async move { Ok(result) })
    }
}

#[tokio::test]
async fn revocation_between_model_and_use_emits_no_command() {
    let caller = Keys::generate();
    let assistant = Keys::generate();
    let community = CommunityId::from_uuid(COMMUNITY);
    let turn = ServerAuthenticatedTurn::from_server_facts(
        community,
        caller.public_key(),
        assistant.public_key(),
        PRIVATE_CHANNEL,
        "What needs my attention?",
    )
    .expect("turn");
    let mut resolver = Resolver {
        route: PrivateAssistantRoute::server_verified(
            community,
            caller.public_key(),
            assistant.public_key(),
            PRIVATE_CHANNEL,
        ),
        channels: vec![SOURCE_CHANNEL],
    };
    let mut retriever = RevokedRetriever { calls: 0 };
    let mut model = Model::default();
    let mut sink = Sink::default();

    let result = run_private_assistant_turn(
        &turn,
        &versions(),
        &mut resolver,
        &mut retriever,
        &mut model,
        &mut sink,
        CREATED_AT,
    )
    .await;

    assert_eq!(result, Err(TurnError::AuthorizationChanged));
    assert_eq!(model.inputs.len(), 1);
    assert!(sink.0.is_empty());
}

#[tokio::test]
async fn mismatched_assistant_or_private_channel_emits_no_model_call_or_command() {
    let caller = Keys::generate();
    let assistant = Keys::generate();
    let other_assistant = Keys::generate();
    let community = CommunityId::from_uuid(COMMUNITY);
    let turn = ServerAuthenticatedTurn::from_server_facts(
        community,
        caller.public_key(),
        assistant.public_key(),
        PRIVATE_CHANNEL,
        "What needs my attention?",
    )
    .expect("turn");

    for route in [
        PrivateAssistantRoute::server_verified(
            community,
            caller.public_key(),
            other_assistant.public_key(),
            PRIVATE_CHANNEL,
        ),
        PrivateAssistantRoute::server_verified(
            community,
            caller.public_key(),
            assistant.public_key(),
            Uuid::from_u128(0x201),
        ),
    ] {
        let mut resolver = Resolver {
            route,
            channels: vec![SOURCE_CHANNEL],
        };
        let mut retriever = Retriever {
            excerpts: vec![excerpt()],
            seen_channels: vec![],
        };
        let mut model = Model::default();
        let mut sink = Sink::default();
        let result = run_private_assistant_turn(
            &turn,
            &versions(),
            &mut resolver,
            &mut retriever,
            &mut model,
            &mut sink,
            CREATED_AT,
        )
        .await;
        assert_eq!(result, Err(TurnError::AuthorityDenied));
        assert!(model.inputs.is_empty());
        assert!(sink.0.is_empty());
    }
}

struct FixedModel {
    output: String,
    calls: usize,
}

impl AssistantModel for FixedModel {
    fn complete(&mut self, _request: ModelRequest<'_>) -> Result<String, ModelFailure> {
        self.calls += 1;
        Ok(self.output.clone())
    }
}

#[tokio::test]
async fn malformed_or_privileged_model_output_emits_no_command() {
    let caller = Keys::generate();
    let assistant = Keys::generate();
    let community = CommunityId::from_uuid(COMMUNITY);
    let turn = ServerAuthenticatedTurn::from_server_facts(
        community,
        caller.public_key(),
        assistant.public_key(),
        PRIVATE_CHANNEL,
        "What needs my attention?",
    )
    .expect("turn");
    let malformed = [
        "not JSON".to_owned(),
        r#"{"change":"x","why_it_matters":"y","recommendation":"z","citations":[0],"h":"attacker-channel"}"#.to_owned(),
        r#"{"change":"x","why_it_matters":"y","recommendation":"z","citations":[0],"evidence":[]}"#.to_owned(),
        r#"{"change":"x","why_it_matters":"y","recommendation":"z","citations":[0],"confidence":100}"#.to_owned(),
        r#"{"change":"x","why_it_matters":"y","recommendation":"z","citations":[0],"kind":44300}"#.to_owned(),
        format!(
            r#"{{"change":"{}","why_it_matters":"y","recommendation":"z","citations":[0]}}"#,
            "x".repeat(4097)
        ),
    ];

    for output in malformed {
        let mut resolver = Resolver {
            route: PrivateAssistantRoute::server_verified(
                community,
                caller.public_key(),
                assistant.public_key(),
                PRIVATE_CHANNEL,
            ),
            channels: vec![SOURCE_CHANNEL],
        };
        let mut retriever = Retriever {
            excerpts: vec![excerpt()],
            seen_channels: vec![],
        };
        let mut model = FixedModel { output, calls: 0 };
        let mut sink = Sink::default();
        let result = run_private_assistant_turn(
            &turn,
            &versions(),
            &mut resolver,
            &mut retriever,
            &mut model,
            &mut sink,
            CREATED_AT,
        )
        .await;
        assert_eq!(result, Err(TurnError::MalformedModelOutput));
        assert_eq!(model.calls, 1);
        assert!(sink.0.is_empty());
    }
}

#[tokio::test]
async fn duplicate_citation_selection_emits_no_command() {
    let caller = Keys::generate();
    let assistant = Keys::generate();
    let community = CommunityId::from_uuid(COMMUNITY);
    let turn = ServerAuthenticatedTurn::from_server_facts(
        community,
        caller.public_key(),
        assistant.public_key(),
        PRIVATE_CHANNEL,
        "What needs my attention?",
    )
    .expect("turn");
    let mut resolver = Resolver {
        route: PrivateAssistantRoute::server_verified(
            community,
            caller.public_key(),
            assistant.public_key(),
            PRIVATE_CHANNEL,
        ),
        channels: vec![SOURCE_CHANNEL],
    };
    let mut retriever = Retriever {
        excerpts: vec![excerpt()],
        seen_channels: vec![],
    };
    let mut model = FixedModel {
        output: r#"{"change":"x","why_it_matters":"y","recommendation":"z","citations":[0,0]}"#
            .into(),
        calls: 0,
    };
    let mut sink = Sink::default();

    let result = run_private_assistant_turn(
        &turn,
        &versions(),
        &mut resolver,
        &mut retriever,
        &mut model,
        &mut sink,
        CREATED_AT,
    )
    .await;

    assert_eq!(result, Err(TurnError::DuplicateEvidence));
    assert!(sink.0.is_empty());
}

fn unsupported_excerpt() -> AuthorizedExcerpt {
    let citation = Citation::new(
        "Unexpected source",
        ConnectorProvider::GoogleDrive,
        SourceKind::Email,
        Utc.with_ymd_and_hms(2026, 8, 3, 12, 0, 0)
            .single()
            .expect("timestamp"),
        Utc.with_ymd_and_hms(2026, 8, 3, 12, 5, 0)
            .single()
            .expect("timestamp"),
        "https://drive.google.com/open?id=opaque",
        [8; 32],
        RemoteVersion::new("v1", None).expect("remote version"),
        [9; 32],
        CitationFreshness::Fresh,
    )
    .expect("citation");
    AuthorizedExcerpt::new(citation, "Unexpected source text.", 0, 23).expect("authorized excerpt")
}

#[tokio::test]
async fn unsupported_provider_source_pair_emits_no_command() {
    let caller = Keys::generate();
    let assistant = Keys::generate();
    let community = CommunityId::from_uuid(COMMUNITY);
    let turn = ServerAuthenticatedTurn::from_server_facts(
        community,
        caller.public_key(),
        assistant.public_key(),
        PRIVATE_CHANNEL,
        "What needs my attention?",
    )
    .expect("turn");
    let mut resolver = Resolver {
        route: PrivateAssistantRoute::server_verified(
            community,
            caller.public_key(),
            assistant.public_key(),
            PRIVATE_CHANNEL,
        ),
        channels: vec![SOURCE_CHANNEL],
    };
    let mut retriever = Retriever {
        excerpts: vec![unsupported_excerpt()],
        seen_channels: vec![],
    };
    let mut model = Model::default();
    let mut sink = Sink::default();

    let result = run_private_assistant_turn(
        &turn,
        &versions(),
        &mut resolver,
        &mut retriever,
        &mut model,
        &mut sink,
        CREATED_AT,
    )
    .await;

    assert_eq!(result, Err(TurnError::UnsupportedEvidence));
    assert!(sink.0.is_empty());
}

#[tokio::test]
async fn dedupe_and_insight_id_are_stable_across_delivery_time() {
    let caller = Keys::generate();
    let assistant = Keys::generate();
    let community = CommunityId::from_uuid(COMMUNITY);
    let turn = ServerAuthenticatedTurn::from_server_facts(
        community,
        caller.public_key(),
        assistant.public_key(),
        PRIVATE_CHANNEL,
        "What needs my attention?",
    )
    .expect("turn");
    let route = PrivateAssistantRoute::server_verified(
        community,
        caller.public_key(),
        assistant.public_key(),
        PRIVATE_CHANNEL,
    );
    let mut payloads = Vec::new();

    for created_at in [CREATED_AT, CREATED_AT + 60] {
        let mut resolver = Resolver {
            route: route.clone(),
            channels: vec![SOURCE_CHANNEL],
        };
        let mut retriever = Retriever {
            excerpts: vec![excerpt()],
            seen_channels: vec![],
        };
        let mut model = Model::default();
        let mut sink = Sink::default();
        run_private_assistant_turn(
            &turn,
            &versions(),
            &mut resolver,
            &mut retriever,
            &mut model,
            &mut sink,
            created_at,
        )
        .await
        .expect("turn");
        let event = sink
            .0
            .pop()
            .expect("command")
            .sign_with_keys(&assistant)
            .expect("sign");
        payloads
            .push(serde_json::from_str::<InsightPayload>(&event.content).expect("insight payload"));
    }

    assert_eq!(payloads[0].dedupe_key, payloads[1].dedupe_key);
    assert_eq!(payloads[0].insight_id, payloads[1].insight_id);
    assert_ne!(payloads[0].created_at, payloads[1].created_at);
}
