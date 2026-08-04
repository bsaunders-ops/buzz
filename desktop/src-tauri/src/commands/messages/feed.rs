use nostr::Event;
use tauri::State;

use crate::{
    app_state::AppState,
    models::{FeedItemInfo, FeedMeta, FeedResponse, FeedSections},
    relay::query_relay,
};

#[tauri::command]
pub async fn get_feed(
    since: Option<i64>,
    limit: Option<u32>,
    types: Option<String>,
    state: State<'_, AppState>,
) -> Result<FeedResponse, String> {
    let cap = limit.unwrap_or(50).min(100);

    // Parse types filter — if absent, run all sub-queries.
    // Comma-separated: e.g. "mentions,needs_action".
    let want_mentions = feed_type_requested(types.as_deref(), "mentions");
    let want_needs_action = feed_type_requested(types.as_deref(), "needs_action");
    let want_agent_activity = feed_type_requested(types.as_deref(), "agent_activity");

    let my_pubkey = {
        let keys = state.keys.lock().map_err(|e| e.to_string())?;
        keys.public_key().to_hex()
    };

    // Mentions: messages that reference me via #p.
    let mut mention_filter = serde_json::json!({
        "kinds": [
            9,
            40002,
            1,
            45001,
            45003,
            buzz_core_pkg::kind::KIND_GIT_PULL_REQUEST,
            buzz_core_pkg::kind::KIND_GIT_PR_UPDATE,
            buzz_core_pkg::kind::KIND_GIT_ISSUE,
            buzz_core_pkg::kind::KIND_GIT_STATUS_OPEN,
            buzz_core_pkg::kind::KIND_GIT_STATUS_MERGED,
            buzz_core_pkg::kind::KIND_GIT_STATUS_CLOSED,
            buzz_core_pkg::kind::KIND_GIT_STATUS_DRAFT,
        ],
        "#p": [my_pubkey],
        "limit": cap,
    });
    if let Some(s) = since {
        mention_filter["since"] = serde_json::json!(s);
    }
    // Needs-action: workflow approval-request events sent to me.
    let mut approval_filter = serde_json::json!({
        "kinds": [46010, 46011, 46012],
        "#p": [my_pubkey],
        "limit": 20,
    });
    if let Some(s) = since {
        approval_filter["since"] = serde_json::json!(s);
    }
    let insight_filter = build_core_insight_feed_filter(&my_pubkey, cap, since);

    let mention_events = if want_mentions {
        query_relay(&state, &[mention_filter])
            .await
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let approval_events = if want_needs_action {
        query_relay(&state, &[approval_filter])
            .await
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let agent_activity_events = if want_agent_activity {
        query_relay(&state, &[insight_filter])
            .await
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let mentions: Vec<FeedItemInfo> = mention_events
        .iter()
        .map(|ev| feed_item_from_event(ev, "mentions"))
        .collect();
    let needs_action: Vec<FeedItemInfo> = approval_events
        .iter()
        .map(|ev| feed_item_from_event(ev, "needs_action"))
        .collect();
    let agent_activity: Vec<FeedItemInfo> = agent_activity_events
        .iter()
        .map(|ev| feed_item_from_event(ev, "agent_activity"))
        .collect();

    let total = (mentions.len() + needs_action.len() + agent_activity.len()) as u64;
    Ok(FeedResponse {
        feed: FeedSections {
            mentions,
            needs_action,
            activity: Vec::new(),
            agent_activity,
        },
        meta: FeedMeta {
            since: since.unwrap_or(0),
            total,
            generated_at: chrono::Utc::now().timestamp(),
        },
    })
}

fn channel_id_from_tags(ev: &Event) -> Option<String> {
    ev.tags.iter().find_map(|t| {
        let s = t.as_slice();
        if s.len() >= 2 && s[0] == "h" {
            Some(s[1].clone())
        } else {
            None
        }
    })
}

fn tags_to_vec(ev: &Event) -> Vec<Vec<String>> {
    ev.tags.iter().map(|t| t.as_slice().to_vec()).collect()
}

fn feed_type_requested(types: Option<&str>, requested: &str) -> bool {
    types
        .map(|value| value.split(',').any(|entry| entry.trim() == requested))
        .unwrap_or(true)
}

fn build_core_insight_feed_filter(
    owner_pubkey_hex: &str,
    cap: u32,
    since: Option<i64>,
) -> serde_json::Value {
    let mut filter = serde_json::json!({
        "kinds": [buzz_core_pkg::kind::KIND_CORE_INSIGHT],
        "#p": [owner_pubkey_hex],
        "limit": cap,
    });
    if let Some(s) = since {
        filter["since"] = serde_json::json!(s);
    }
    filter
}

fn feed_item_from_event(ev: &Event, category: &str) -> FeedItemInfo {
    let channel_id = channel_id_from_tags(ev);
    FeedItemInfo {
        id: ev.id.to_hex(),
        kind: ev.kind.as_u16() as u32,
        pubkey: ev.pubkey.to_hex(),
        content: ev.content.clone(),
        created_at: ev.created_at.as_secs(),
        channel_id,
        channel_name: String::new(),
        channel_type: None,
        tags: tags_to_vec(ev),
        category: category.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feed_type_requested_defaults_to_all_and_matches_trimmed_entries() {
        assert!(feed_type_requested(None, "agent_activity"));
        assert!(feed_type_requested(
            Some("mentions, needs_action, agent_activity"),
            "agent_activity"
        ));
        assert!(!feed_type_requested(
            Some("mentions,needs_action"),
            "agent_activity"
        ));
    }

    #[test]
    fn core_insight_feed_filter_targets_owner_and_private_insight_kind() {
        let filter = build_core_insight_feed_filter(
            "abababababababababababababababababababababababababababababababab",
            25,
            Some(1_700_000_000),
        );

        assert_eq!(
            filter["kinds"],
            serde_json::json!([buzz_core_pkg::kind::KIND_CORE_INSIGHT])
        );
        assert_eq!(
            filter["#p"],
            serde_json::json!(["abababababababababababababababababababababababababababababababab"])
        );
        assert_eq!(filter["limit"], serde_json::json!(25));
        assert_eq!(filter["since"], serde_json::json!(1_700_000_000));
    }
}
