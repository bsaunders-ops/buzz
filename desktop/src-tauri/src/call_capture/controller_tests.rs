use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use uuid::Uuid;

use super::{
    AudioEndpointKind, AudioSourceHealth, CallCaptureConsentRequest, CallCaptureController,
    CallCaptureDevice, CallCaptureFeature, CallCapturePhase, CallCaptureRuntime,
    CallCaptureSourceState, CallCaptureStartRequest, CallMeetingContext, CallMeetingContextSource,
    StopReason,
};

struct FakeRuntime {
    stopped: Arc<AtomicBool>,
}

impl CallCaptureRuntime for FakeRuntime {
    fn stop(&mut self) -> Result<(), String> {
        self.stopped.store(true, Ordering::Release);
        Ok(())
    }
}

struct FailingRuntime {
    stopped: Arc<AtomicBool>,
}

impl CallCaptureRuntime for FailingRuntime {
    fn stop(&mut self) -> Result<(), String> {
        self.stopped.store(true, Ordering::Release);
        Ok(())
    }

    fn failure_reason(&self) -> Option<StopReason> {
        Some(StopReason::DeviceFailure)
    }
}

struct MeteredRuntime;

impl CallCaptureRuntime for MeteredRuntime {
    fn stop(&mut self) -> Result<(), String> {
        Ok(())
    }

    fn source_states(&self) -> (CallCaptureSourceState, CallCaptureSourceState) {
        (
            CallCaptureSourceState {
                health: AudioSourceHealth::Healthy,
                level_percent: 42,
            },
            CallCaptureSourceState {
                health: AudioSourceHealth::Degraded,
                level_percent: 7,
            },
        )
    }
}

fn devices() -> Vec<CallCaptureDevice> {
    vec![
        CallCaptureDevice {
            schema_version: 1,
            id: "mic-1".into(),
            label: "USB Microphone".into(),
            kind: AudioEndpointKind::Microphone,
            is_default: true,
            sample_rate_hz: 48_000,
            channels: 1,
        },
        CallCaptureDevice {
            schema_version: 1,
            id: "output-1".into(),
            label: "Laptop Speakers".into(),
            kind: AudioEndpointKind::Output,
            is_default: true,
            sample_rate_hz: 48_000,
            channels: 2,
        },
    ]
}

fn consent_request() -> CallCaptureConsentRequest {
    CallCaptureConsentRequest {
        schema_version: 1,
        microphone_id: "mic-1".into(),
        output_id: "output-1".into(),
        consent_notice_version: 1,
        consent_acknowledged: true,
    }
}

fn start_request(consent_token: Uuid) -> CallCaptureStartRequest {
    CallCaptureStartRequest {
        schema_version: 1,
        microphone_id: "mic-1".into(),
        output_id: "output-1".into(),
        consent_token,
        meeting_context: None,
    }
}

#[test]
fn controller_requires_visible_per_call_consent_and_exact_device_kinds() {
    let mut controller = CallCaptureController::new(CallCaptureFeature::Enabled);
    let mut missing = consent_request();
    missing.consent_acknowledged = false;
    assert!(controller
        .acknowledge_consent(missing, &devices(), 1_000)
        .is_err());

    let mut swapped = consent_request();
    swapped.microphone_id = "output-1".into();
    swapped.output_id = "mic-1".into();
    assert!(controller
        .acknowledge_consent(swapped, &devices(), 1_000)
        .is_err());
}

#[test]
fn controller_start_consumes_only_the_exact_backend_minted_token() {
    let mut controller = CallCaptureController::new(CallCaptureFeature::Enabled);
    let consent = controller
        .acknowledge_consent(consent_request(), &devices(), 1_000)
        .unwrap();

    assert!(controller
        .start(
            start_request(Uuid::new_v4()),
            &devices(),
            1_001,
            |_, _, _| unreachable!(),
        )
        .is_err());
    assert_eq!(controller.snapshot(1_001).phase, CallCapturePhase::Idle);

    assert!(controller
        .start(
            start_request(consent.token),
            &devices(),
            1_002,
            |_, _, _| Ok(Box::new(FakeRuntime {
                stopped: Arc::new(AtomicBool::new(false))
            })),
        )
        .is_ok());
}

#[test]
fn controller_rejects_endpoint_swap_future_expired_and_replayed_consent() {
    let mut controller = CallCaptureController::new(CallCaptureFeature::Enabled);
    let consent = controller
        .acknowledge_consent(consent_request(), &devices(), 1_000)
        .unwrap();
    let mut swapped = start_request(consent.token);
    swapped.output_id = "mic-1".into();
    assert!(controller
        .start(swapped, &devices(), 1_001, |_, _, _| unreachable!())
        .is_err());

    let expired = controller
        .acknowledge_consent(consent_request(), &devices(), 2_000)
        .unwrap();
    assert!(controller
        .start(
            start_request(expired.token),
            &devices(),
            62_001,
            |_, _, _| unreachable!()
        )
        .is_err());

    let future = controller
        .acknowledge_consent(consent_request(), &devices(), 80_000)
        .unwrap();
    assert!(controller
        .start(
            start_request(future.token),
            &devices(),
            79_999,
            |_, _, _| unreachable!()
        )
        .is_err());

    let fresh = controller
        .acknowledge_consent(consent_request(), &devices(), 90_000)
        .unwrap();
    controller
        .start(start_request(fresh.token), &devices(), 90_001, |_, _, _| {
            Ok(Box::new(FakeRuntime {
                stopped: Arc::new(AtomicBool::new(false)),
            }))
        })
        .unwrap();
    controller.stop(StopReason::Explicit, 90_002).unwrap();
    assert!(controller
        .start(
            start_request(fresh.token),
            &devices(),
            90_003,
            |_, _, _| unreachable!()
        )
        .is_err());
}

#[test]
fn successful_start_installs_runtime_and_stop_is_synchronous() {
    let mut controller = CallCaptureController::new(CallCaptureFeature::Enabled);
    let stopped = Arc::new(AtomicBool::new(false));
    let stopped_for_runtime = Arc::clone(&stopped);
    let consent = controller
        .acknowledge_consent(consent_request(), &devices(), 999)
        .unwrap();

    let state = controller
        .start(
            start_request(consent.token),
            &devices(),
            1_000,
            move |_, mic, output| {
                assert_eq!(mic.id, "mic-1");
                assert_eq!(output.id, "output-1");
                Ok(Box::new(FakeRuntime {
                    stopped: stopped_for_runtime,
                }))
            },
        )
        .unwrap();
    assert_eq!(state.phase, CallCapturePhase::Active);

    let stopped_state = controller.stop(StopReason::Explicit, 2_000).unwrap();
    assert!(stopped.load(Ordering::Acquire));
    assert_eq!(stopped_state.phase, CallCapturePhase::Ended);
    assert_eq!(stopped_state.stop_reason, Some(StopReason::Explicit));
}

#[test]
fn active_snapshot_exposes_typed_separate_source_health_and_levels() {
    let mut controller = CallCaptureController::new(CallCaptureFeature::Enabled);
    let consent = controller
        .acknowledge_consent(consent_request(), &devices(), 999)
        .unwrap();
    let state = controller
        .start(
            start_request(consent.token),
            &devices(),
            1_000,
            |_, _, _| Ok(Box::new(MeteredRuntime)),
        )
        .unwrap();

    assert_eq!(state.microphone_source.health, AudioSourceHealth::Healthy);
    assert_eq!(state.microphone_source.level_percent, 42);
    assert_eq!(state.output_source.health, AudioSourceHealth::Degraded);
    assert_eq!(state.output_source.level_percent, 7);
}

#[test]
fn failed_native_start_fails_closed_and_same_consent_nonce_cannot_replay() {
    let mut controller = CallCaptureController::new(CallCaptureFeature::Enabled);
    let consent = controller
        .acknowledge_consent(consent_request(), &devices(), 999)
        .unwrap();
    assert!(controller
        .start(
            start_request(consent.token),
            &devices(),
            1_000,
            |_, _, _| { Err("Parakeet initialization failed".into()) }
        )
        .is_err());
    assert_ne!(controller.snapshot(1_001).phase, CallCapturePhase::Active);

    assert!(controller
        .start(
            start_request(consent.token),
            &devices(),
            1_002,
            |_, _, _| {
                Ok(Box::new(FakeRuntime {
                    stopped: Arc::new(AtomicBool::new(false)),
                }))
            }
        )
        .is_err());
}

#[test]
fn suspend_exit_and_consent_loss_stop_the_runtime_and_resume_does_nothing() {
    for reason in [
        StopReason::Suspend,
        StopReason::AppExit,
        StopReason::ConsentRevoked,
    ] {
        let mut controller = CallCaptureController::new(CallCaptureFeature::Enabled);
        let stopped = Arc::new(AtomicBool::new(false));
        let runtime_flag = Arc::clone(&stopped);
        let consent = controller
            .acknowledge_consent(consent_request(), &devices(), 999)
            .unwrap();
        controller
            .start(
                start_request(consent.token),
                &devices(),
                1_000,
                move |_, _, _| {
                    Ok(Box::new(FakeRuntime {
                        stopped: runtime_flag,
                    }))
                },
            )
            .unwrap();

        controller.stop_if_active(reason, 1_100).unwrap();
        controller.resume_signal(1_200).unwrap();
        assert!(stopped.load(Ordering::Acquire));
        assert_eq!(controller.snapshot(1_200).phase, CallCapturePhase::Ended);
    }
}

#[test]
fn disabled_controller_never_calls_the_native_factory() {
    let mut controller = CallCaptureController::new(CallCaptureFeature::Disabled);
    let called = Arc::new(AtomicBool::new(false));
    let factory_called = Arc::clone(&called);
    assert!(controller
        .acknowledge_consent(consent_request(), &devices(), 999)
        .is_err());
    assert!(controller
        .start(
            start_request(Uuid::new_v4()),
            &devices(),
            1_000,
            move |_, _, _| {
                factory_called.store(true, Ordering::Release);
                Err("must not run".into())
            }
        )
        .is_err());
    assert!(!called.load(Ordering::Acquire));
}

#[test]
fn runtime_device_loss_is_reconciled_into_a_synchronous_fail_closed_stop() {
    let mut controller = CallCaptureController::new(CallCaptureFeature::Enabled);
    let stopped = Arc::new(AtomicBool::new(false));
    let runtime_stopped = Arc::clone(&stopped);
    let consent = controller
        .acknowledge_consent(consent_request(), &devices(), 999)
        .unwrap();
    controller
        .start(
            start_request(consent.token),
            &devices(),
            1_000,
            move |_, _, _| {
                Ok(Box::new(FailingRuntime {
                    stopped: runtime_stopped,
                }))
            },
        )
        .unwrap();

    let state = controller.reconcile_runtime(1_001).unwrap();
    assert!(stopped.load(Ordering::Acquire));
    assert_eq!(state.phase, CallCapturePhase::Ended);
    assert_eq!(state.stop_reason, Some(StopReason::DeviceFailure));
}

#[test]
fn dropping_an_active_controller_synchronously_stops_its_native_runtime() {
    let stopped = Arc::new(AtomicBool::new(false));
    {
        let mut controller = CallCaptureController::new(CallCaptureFeature::Enabled);
        let runtime_stopped = Arc::clone(&stopped);
        let consent = controller
            .acknowledge_consent(consent_request(), &devices(), 999)
            .unwrap();
        controller
            .start(
                start_request(consent.token),
                &devices(),
                1_000,
                move |_, _, _| {
                    Ok(Box::new(FakeRuntime {
                        stopped: runtime_stopped,
                    }))
                },
            )
            .unwrap();
    }

    assert!(stopped.load(Ordering::Acquire));
}

#[test]
fn device_consent_start_and_meeting_debug_output_redacts_identifiers() {
    let sentinel = "MNPI-SENTINEL-DO-NOT-LOG";
    let mut device = devices().remove(0);
    device.id = sentinel.into();
    device.label = sentinel.into();
    let consent = CallCaptureConsentRequest {
        schema_version: 1,
        microphone_id: sentinel.into(),
        output_id: sentinel.into(),
        consent_notice_version: 1,
        consent_acknowledged: true,
    };
    let start = CallCaptureStartRequest {
        schema_version: 1,
        microphone_id: sentinel.into(),
        output_id: sentinel.into(),
        consent_token: Uuid::new_v4(),
        meeting_context: Some(CallMeetingContext {
            source: CallMeetingContextSource::Crm,
            source_id: sentinel.into(),
            title: sentinel.into(),
        }),
    };

    for debug in [
        format!("{device:?}"),
        format!("{consent:?}"),
        format!("{start:?}"),
    ] {
        assert!(!debug.contains(sentinel));
        assert!(debug.contains("<redacted>"));
    }
}
