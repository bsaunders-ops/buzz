use buzz_connector_core::{
    core_crm::{normalize_core_crm_response, CoreCrmReadOperation},
    core_crm_sync::{
        CoreCrmMissingState, CoreCrmSyncCursorV1, CoreCrmSyncTarget, CoreCrmTrackedTarget,
    },
    types::{AclPrincipal, ExternalItemId, TombstoneReason},
};
use serde_json::{json, Value};
use uuid::Uuid;

const ACTIVITY_RESPONSE: &[u8] = include_bytes!("fixtures/core-crm/get-activity.response.json");

fn operation(name: &str, arguments: Value) -> CoreCrmReadOperation {
    CoreCrmReadOperation::try_from_tool_call(name, arguments).expect("synthetic operation")
}

fn activity_target() -> CoreCrmSyncTarget {
    CoreCrmSyncTarget::activity(
        Uuid::parse_str("44444444-4444-4444-8444-444444444444").expect("fixture UUID"),
    )
}

fn contact_target() -> CoreCrmSyncTarget {
    CoreCrmSyncTarget::contact(
        Uuid::parse_str("11111111-1111-4111-8111-111111111111").expect("fixture UUID"),
    )
}

fn tracked(target: CoreCrmSyncTarget, item_ids: &[&str]) -> CoreCrmTrackedTarget {
    CoreCrmTrackedTarget::new(
        target,
        item_ids
            .iter()
            .map(|value| ExternalItemId::new(*value).expect("synthetic item ID"))
            .collect(),
    )
    .expect("tracked target")
}

#[test]
fn cursor_encoding_is_deterministic_and_selects_targets_in_stable_order() {
    let activity = tracked(activity_target(), &[]);
    let contact = tracked(contact_target(), &[]);
    let first = CoreCrmSyncCursorV1::new(vec![activity.clone(), contact.clone()]).expect("cursor");
    let second = CoreCrmSyncCursorV1::new(vec![contact, activity]).expect("cursor");

    assert_eq!(
        first.encode().expect("encode"),
        second.encode().expect("encode")
    );
    assert_eq!(
        first.current_operation().expect("operation").tool_name(),
        "get_contact"
    );
}

#[test]
fn unknown_cursor_versions_and_ambiguous_targets_fail_closed() {
    let cursor = CoreCrmSyncCursorV1::new(vec![tracked(contact_target(), &[])]).expect("cursor");
    let mut wire: Value =
        serde_json::from_slice(&cursor.encode().expect("encode")).expect("cursor JSON");
    wire["version"] = json!(2);

    assert!(CoreCrmSyncCursorV1::decode(&serde_json::to_vec(&wire).expect("cursor JSON")).is_err());
    assert!(CoreCrmSyncCursorV1::new(vec![
        tracked(contact_target(), &[]),
        tracked(contact_target(), &[]),
    ])
    .is_err());
}

#[test]
fn noncanonical_cursor_item_order_fails_closed() {
    let cursor = CoreCrmSyncCursorV1::new(vec![tracked(
        activity_target(),
        &[
            "core-crm:activity:44444444-4444-4444-8444-444444444444",
            "core-crm:transcript:66666666-6666-4666-8666-666666666666",
        ],
    )])
    .expect("cursor");
    let mut wire: Value =
        serde_json::from_slice(&cursor.encode().expect("encode")).expect("cursor JSON");
    wire["targets"][0]["item_ids"]
        .as_array_mut()
        .expect("item array")
        .reverse();

    assert!(CoreCrmSyncCursorV1::decode(&serde_json::to_vec(&wire).expect("cursor JSON")).is_err());
}

#[test]
fn explicit_missing_record_tombstones_only_its_previously_tracked_items() {
    let previous_activity = "core-crm:activity:44444444-4444-4444-8444-444444444444";
    let previous_transcript = "core-crm:transcript:66666666-6666-4666-8666-666666666666";
    let cursor = CoreCrmSyncCursorV1::new(vec![tracked(
        activity_target(),
        &[previous_activity, previous_transcript],
    )])
    .expect("cursor");

    let step = cursor
        .reconcile_missing(CoreCrmMissingState::Deleted)
        .expect("missing record reconciliation");

    assert!(step.upserts().is_empty());
    assert_eq!(step.tombstones().len(), 2);
    assert!(step
        .tombstones()
        .iter()
        .all(|item| item.reason() == TombstoneReason::Deleted));
    assert!(step.cycle_complete());
    assert!(step.next_cursor().current_tracked_items().is_empty());
}

#[test]
fn every_explicit_missing_state_maps_to_its_closed_tombstone_reason() {
    for (state, reason) in [
        (CoreCrmMissingState::Deleted, TombstoneReason::Deleted),
        (CoreCrmMissingState::Revoked, TombstoneReason::Revoked),
        (
            CoreCrmMissingState::Inaccessible,
            TombstoneReason::Inaccessible,
        ),
    ] {
        let cursor = CoreCrmSyncCursorV1::new(vec![tracked(
            contact_target(),
            &["core-crm:contact:11111111-1111-4111-8111-111111111111"],
        )])
        .expect("cursor");
        let step = cursor.reconcile_missing(state).expect("explicit missing");
        assert_eq!(step.tombstones().len(), 1);
        assert_eq!(step.tombstones()[0].reason(), reason);
    }
}

#[test]
fn capped_search_absence_cannot_enter_destructive_reconciliation() {
    let cursor = CoreCrmSyncCursorV1::new(vec![tracked(
        contact_target(),
        &["core-crm:contact:11111111-1111-4111-8111-111111111111"],
    )])
    .expect("cursor");
    let response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"content": [{"type": "text", "text": json!([{
            "id": "99999999-9999-4999-8999-999999999999",
            "name": "Different Synthetic Contact",
            "title": null,
            "email": null,
            "phone": null,
            "relationship_type": "prospect",
            "status": "relevant",
            "last_contacted": null,
            "company_id": null,
            "companies": null,
            "fuzzy": false,
            "merged_into_contact_id": null
        }]).to_string()}]}
    });
    let response = serde_json::to_vec(&response).expect("discovery response");
    let snapshot = normalize_core_crm_response(
        &operation(
            "search_contacts",
            json!({"query": "synthetic", "limit": 50}),
        ),
        1,
        &response,
        vec![AclPrincipal::user([7; 32])],
    )
    .expect("bounded discovery fixture");

    assert!(!snapshot.discovery_results().is_empty());
    assert!(cursor.reconcile_snapshot(&snapshot).is_err());
}

#[test]
fn complete_detail_snapshot_replaces_items_and_tombstones_disappeared_children() {
    let current_activity = "core-crm:activity:44444444-4444-4444-8444-444444444444";
    let current_transcript = "core-crm:transcript:66666666-6666-4666-8666-666666666666";
    let disappeared_transcript = "core-crm:transcript:77777777-7777-4777-8777-777777777777";
    let cursor = CoreCrmSyncCursorV1::new(vec![tracked(
        activity_target(),
        &[current_activity, current_transcript, disappeared_transcript],
    )])
    .expect("cursor");
    let snapshot = normalize_core_crm_response(
        &operation(
            "get_activity",
            json!({"id": "44444444-4444-4444-8444-444444444444"}),
        ),
        1,
        ACTIVITY_RESPONSE,
        vec![AclPrincipal::user([7; 32])],
    )
    .expect("activity fixture");

    let step = cursor
        .reconcile_snapshot(&snapshot)
        .expect("reconciliation");

    assert_eq!(step.upserts().len(), 2);
    assert_eq!(step.tombstones().len(), 1);
    assert_eq!(
        step.tombstones()[0].external_item_id().as_str(),
        disappeared_transcript
    );
    assert_eq!(
        step.tombstones()[0].reason(),
        TombstoneReason::RemovedFromScope
    );
    assert!(step.cycle_complete());
    assert_eq!(step.next_cursor().current_tracked_items().len(), 2);
}
