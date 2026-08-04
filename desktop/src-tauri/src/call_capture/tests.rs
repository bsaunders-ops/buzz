use super::{
    AudioEndpointKind, CallCaptureFeature, CallCapturePhase, CallCaptureStateMachine,
    DegradedReason, StopReason,
};

const MIC_ID: &str = "mic-1";
const OUTPUT_ID: &str = "output-1";

fn enabled_machine() -> CallCaptureStateMachine {
    CallCaptureStateMachine::new(CallCaptureFeature::Enabled)
}

#[test]
fn fresh_single_use_consent_is_required_for_every_start() {
    let mut machine = enabled_machine();

    assert!(machine
        .start(MIC_ID, OUTPUT_ID, uuid::Uuid::new_v4(), 1_000)
        .is_err());

    let consent = machine.issue_consent(MIC_ID, OUTPUT_ID, 1_000).unwrap();
    let call_id = machine
        .start(MIC_ID, OUTPUT_ID, consent.token, 1_001)
        .unwrap();
    assert_eq!(machine.snapshot(1_001).phase, CallCapturePhase::Active);

    machine.stop(StopReason::Explicit, 2_000).unwrap();
    assert_eq!(machine.snapshot(2_000).phase, CallCapturePhase::Ended);
    assert_eq!(machine.snapshot(2_000).call_id, Some(call_id));

    assert!(machine
        .start(MIC_ID, OUTPUT_ID, consent.token, 2_001)
        .is_err());
    assert_eq!(machine.snapshot(2_001).phase, CallCapturePhase::Ended);
}

#[test]
fn consent_is_bound_to_the_selected_microphone_and_output_endpoint() {
    let mut machine = enabled_machine();
    let consent = machine.issue_consent(MIC_ID, OUTPUT_ID, 1_000).unwrap();

    assert!(machine
        .start("different-mic", OUTPUT_ID, consent.token, 1_001)
        .is_err());
    assert!(machine
        .start(MIC_ID, "different-output", consent.token, 1_001)
        .is_err());
}

#[test]
fn forged_random_consent_tokens_are_rejected_without_starting_capture() {
    let mut machine = enabled_machine();
    let issued = machine.issue_consent(MIC_ID, OUTPUT_ID, 1_000).unwrap();

    assert!(machine
        .start(MIC_ID, OUTPUT_ID, uuid::Uuid::new_v4(), 1_001)
        .is_err());
    assert_eq!(machine.snapshot(1_001).phase, CallCapturePhase::Idle);

    assert!(machine
        .start(MIC_ID, OUTPUT_ID, issued.token, 1_002)
        .is_ok());
}

#[test]
fn expired_or_future_consent_is_rejected_without_consuming_it() {
    let mut machine = enabled_machine();
    let expired = machine.issue_consent(MIC_ID, OUTPUT_ID, 1_000).unwrap();
    assert!(machine
        .start(MIC_ID, OUTPUT_ID, expired.token, 61_001)
        .is_err());

    let future = machine.issue_consent(MIC_ID, OUTPUT_ID, 80_000).unwrap();
    assert!(machine
        .start(MIC_ID, OUTPUT_ID, future.token, 79_999)
        .is_err());

    let fresh = machine.issue_consent(MIC_ID, OUTPUT_ID, 90_000).unwrap();
    assert!(machine
        .start(MIC_ID, OUTPUT_ID, fresh.token, 150_000)
        .is_ok());
}

#[test]
fn segment_sequences_are_monotonic_and_unavailable_outside_an_active_session() {
    let mut machine = enabled_machine();
    assert!(machine.next_segment_sequence().is_err());

    let consent = machine.issue_consent(MIC_ID, OUTPUT_ID, 1_000).unwrap();
    machine
        .start(MIC_ID, OUTPUT_ID, consent.token, 1_001)
        .unwrap();

    assert_eq!(machine.next_segment_sequence().unwrap(), 1);
    assert_eq!(machine.next_segment_sequence().unwrap(), 2);
    assert_eq!(machine.next_segment_sequence().unwrap(), 3);

    machine.stop(StopReason::Explicit, 2_000).unwrap();
    assert!(machine.next_segment_sequence().is_err());
}

#[test]
fn selected_endpoint_loss_degrades_then_stops_without_switching_devices() {
    let mut machine = enabled_machine();
    let consent = machine.issue_consent(MIC_ID, OUTPUT_ID, 1_000).unwrap();
    machine
        .start(MIC_ID, OUTPUT_ID, consent.token, 1_001)
        .unwrap();

    machine
        .endpoint_unavailable(AudioEndpointKind::Output, OUTPUT_ID, 1_500)
        .unwrap();
    let degraded = machine.snapshot(1_500);
    assert_eq!(degraded.phase, CallCapturePhase::Ended);
    assert_eq!(degraded.selected_microphone_id.as_deref(), Some(MIC_ID));
    assert_eq!(degraded.selected_output_id.as_deref(), Some(OUTPUT_ID));
    assert!(degraded
        .degraded_reasons
        .contains(&DegradedReason::OutputEndpointLost));
    assert_eq!(degraded.stop_reason, Some(StopReason::DeviceFailure));
}

#[test]
fn minimize_does_not_stop_but_suspend_exit_and_consent_loss_do() {
    for stop in [
        StopReason::Suspend,
        StopReason::AppExit,
        StopReason::ConsentRevoked,
    ] {
        let mut machine = enabled_machine();
        let consent = machine.issue_consent(MIC_ID, OUTPUT_ID, 1_000).unwrap();
        machine
            .start(MIC_ID, OUTPUT_ID, consent.token, 1_001)
            .unwrap();

        machine.on_main_window_minimized(1_200).unwrap();
        assert_eq!(machine.snapshot(1_200).phase, CallCapturePhase::Active);

        machine.stop(stop, 1_300).unwrap();
        assert_eq!(machine.snapshot(1_300).phase, CallCapturePhase::Ended);
        assert_eq!(machine.snapshot(1_300).stop_reason, Some(stop));
    }
}

#[test]
fn a_stopped_or_recovered_session_never_auto_resumes() {
    let mut machine = enabled_machine();
    let consent = machine.issue_consent(MIC_ID, OUTPUT_ID, 1_000).unwrap();
    machine
        .start(MIC_ID, OUTPUT_ID, consent.token, 1_001)
        .unwrap();
    machine.stop(StopReason::Suspend, 1_100).unwrap();

    machine.resume_signal(2_000).unwrap();
    assert_eq!(machine.snapshot(2_000).phase, CallCapturePhase::Ended);

    let recovered = CallCaptureStateMachine::recover_after_crash(true);
    assert_eq!(recovered.snapshot(3_000).phase, CallCapturePhase::Ended);
    assert_eq!(
        recovered.snapshot(3_000).stop_reason,
        Some(StopReason::CrashRecovery)
    );
}

#[test]
fn feature_disabled_and_non_windows_capability_fail_closed() {
    let mut disabled = CallCaptureStateMachine::new(CallCaptureFeature::Disabled);
    assert!(disabled.issue_consent(MIC_ID, OUTPUT_ID, 1_000).is_err());
    assert!(disabled
        .start(MIC_ID, OUTPUT_ID, uuid::Uuid::new_v4(), 1_001)
        .is_err());
    assert_eq!(disabled.snapshot(1_001).phase, CallCapturePhase::Disabled);
}

#[test]
fn lifecycle_debug_output_redacts_consent_and_selected_endpoint_identifiers() {
    let sentinel = "MNPI-SENTINEL-DO-NOT-LOG";
    let mut machine = enabled_machine();
    let consent = machine.issue_consent(sentinel, sentinel, 1_000).unwrap();
    assert!(!format!("{machine:?}").contains(sentinel));
    machine
        .start(sentinel, sentinel, consent.token, 1_001)
        .unwrap();
    assert!(!format!("{:?}", machine.snapshot(1_001)).contains(sentinel));
}
