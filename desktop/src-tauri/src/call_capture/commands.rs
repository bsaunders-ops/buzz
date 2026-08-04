use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use buzz_core_pkg::core_protocol::{CallControlPayload, CopilotSuggestionPayload};
use nostr::{Event, JsonUtil, Keys, PublicKey};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use uuid::Uuid;

use crate::app_state::AppState;

use super::{
    decrypt_copilot_suggestion, encrypt_call_control, encrypt_finalized_segment,
    platform::{PlatformRecoveryBlobStore, PlatformRecoveryKeyStore},
    AudioSourceHealth, CallCaptureConsentRequest, CallCaptureController, CallCaptureDevice,
    CallCaptureFeature, CallCapturePhase, CallCaptureRoute, CallCaptureRuntime,
    CallCaptureSnapshot, CallCaptureStartRequest, CallMeetingContext, FinalizedSegment,
    LiveSessionAccumulator, RecoveryManager, SegmentIngestOutcome, SequencedEphemeral,
    SequencedEphemeralBuffer, StopReason, MAX_RECOVERY_AGE_MS,
};

const STATE_EVENT: &str = "call-capture-state";
const PRIVATE_EVENT_READY: &str = "call-capture-private-event-ready";
const SUGGESTION_EVENT: &str = "call-capture-suggestion";
const CAPTURE_WINDOW_LABEL: &str = "core-call-capture";
const TRANSPORT_QUEUE_CAPACITY: usize = 64;
const SUSPEND_POLL: Duration = Duration::from_millis(500);
const SUSPEND_GAP: Duration = Duration::from_secs(3);

type PlatformRecovery = RecoveryManager<PlatformRecoveryKeyStore, PlatformRecoveryBlobStore>;

pub(crate) struct CallCaptureCommandState {
    inner: Mutex<CallCaptureCommandInner>,
    recovery: PlatformRecovery,
    configuration_error: Option<String>,
}

struct CallCaptureCommandInner {
    controller: CallCaptureController,
    route: Option<CallCaptureRoute>,
    active: Option<ActiveCall>,
}

struct ActiveCall {
    call_id: Uuid,
    route: CallCaptureRoute,
    owner: Keys,
    meeting_context: Option<CallMeetingContext>,
    accumulator: Arc<Mutex<LiveSessionAccumulator>>,
    suggestions: SequencedEphemeralBuffer<CopilotSuggestionPayload>,
    last_suggestion_emitted: u64,
    control_sequence: u64,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateRelayEventReady {
    schema_version: u8,
    event: Event,
}

impl CallCaptureCommandState {
    pub(crate) fn initialize(app: &AppHandle) -> Result<Self, String> {
        let app_data_dir = app
            .path()
            .app_data_dir()
            .map_err(|_| "call capture app-data directory is unavailable".to_string())?;
        let blobs = PlatformRecoveryBlobStore::new(&app_data_dir)?;
        let recovery = RecoveryManager::new(PlatformRecoveryKeyStore, blobs);
        let (feature, route, configuration_error) = configured_route();
        let state = Self {
            inner: Mutex::new(CallCaptureCommandInner {
                controller: CallCaptureController::new(feature),
                route,
                active: None,
            }),
            recovery,
            configuration_error,
        };
        let _ = state.recovery.purge_expired(now_ms()?);
        Ok(state)
    }

    fn ensure_enabled(&self) -> Result<(), String> {
        if let Some(error) = &self.configuration_error {
            return Err(error.clone());
        }
        let inner = self.inner.lock().map_err(|error| error.to_string())?;
        if inner.controller.snapshot(0).phase == CallCapturePhase::Disabled || inner.route.is_none()
        {
            return Err("Core call capture is disabled".into());
        }
        Ok(())
    }
}

fn configured_route() -> (CallCaptureFeature, Option<CallCaptureRoute>, Option<String>) {
    if !cfg!(target_os = "windows") {
        return (CallCaptureFeature::Disabled, None, None);
    }
    let enabled = std::env::var("BUZZ_CORE_CALL_CAPTURE_ENABLED")
        .ok()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("true"));
    if !enabled {
        return (CallCaptureFeature::Disabled, None, None);
    }
    let channel = std::env::var("BUZZ_CORE_CALL_CHANNEL_ID")
        .ok()
        .and_then(|value| Uuid::parse_str(value.trim()).ok());
    let assistant = std::env::var("BUZZ_CORE_CALL_ASSISTANT_PUBKEY")
        .ok()
        .and_then(|value| value.trim().parse::<PublicKey>().ok());
    match (channel, assistant) {
        (Some(channel), Some(assistant)) => match CallCaptureRoute::new(channel, assistant) {
            Ok(route) => (CallCaptureFeature::Enabled, Some(route), None),
            Err(_) => (
                CallCaptureFeature::Disabled,
                None,
                Some("Core call capture route configuration is invalid".into()),
            ),
        },
        _ => (
            CallCaptureFeature::Disabled,
            None,
            Some("Core call capture private route is not configured".into()),
        ),
    }
}

#[tauri::command]
pub(crate) fn list_call_capture_devices(
    state: State<'_, CallCaptureCommandState>,
) -> Result<Vec<CallCaptureDevice>, String> {
    state.ensure_enabled()?;
    list_platform_devices()
}

#[tauri::command]
pub(crate) fn acknowledge_call_capture_consent(
    request: CallCaptureConsentRequest,
    state: State<'_, CallCaptureCommandState>,
) -> Result<super::ConsentAcknowledgement, String> {
    state.ensure_enabled()?;
    let devices = list_platform_devices()?;
    state
        .inner
        .lock()
        .map_err(|error| error.to_string())?
        .controller
        .acknowledge_consent(request, &devices, now_ms()?)
}

#[tauri::command]
pub(crate) fn start_call_capture(
    request: CallCaptureStartRequest,
    app: AppHandle,
    state: State<'_, CallCaptureCommandState>,
    app_state: State<'_, AppState>,
) -> Result<CallCaptureSnapshot, String> {
    state.ensure_enabled()?;
    let devices = list_platform_devices()?;
    let owner = app_state.signing_keys()?;
    let meeting_context = request.meeting_context.clone();
    let mut created_accumulator = None;
    let snapshot = {
        let mut inner = state.inner.lock().map_err(|error| error.to_string())?;
        let route = inner
            .route
            .clone()
            .ok_or_else(|| "Core call capture private route is unavailable".to_string())?;
        let runtime_app = app.clone();
        let runtime_owner = owner.clone();
        let runtime_route = route.clone();
        let snapshot = inner.controller.start(
            request,
            &devices,
            now_ms()?,
            |call_id, microphone, output| {
                let accumulator = Arc::new(Mutex::new(LiveSessionAccumulator::production(call_id)));
                let runtime = start_platform_runtime(
                    call_id,
                    microphone,
                    output,
                    runtime_app,
                    runtime_owner,
                    runtime_route,
                    Arc::clone(&accumulator),
                )?;
                created_accumulator = Some(accumulator);
                Ok(runtime)
            },
        )?;
        let call_id = snapshot
            .call_id
            .ok_or_else(|| "active call capture omitted its session identifier".to_string())?;
        let accumulator = created_accumulator
            .take()
            .ok_or_else(|| "call capture runtime omitted its live accumulator".to_string())?;
        inner.active = Some(ActiveCall {
            call_id,
            route,
            owner,
            meeting_context,
            accumulator,
            suggestions: SequencedEphemeralBuffer::new(call_id, 64, 16)?,
            last_suggestion_emitted: 0,
            control_sequence: 1,
        });
        snapshot
    };

    if let Err(error) = show_capture_window(&app)
        .and_then(|()| emit_control_for_active(&app, &state, &snapshot, "start", "active"))
        .and_then(|()| emit_snapshot(&app, &snapshot))
    {
        let _ = stop_call_capture_with_reason(&app, &state, StopReason::TranscriberFailure);
        return Err(error);
    }
    Ok(snapshot)
}

#[tauri::command]
pub(crate) fn stop_call_capture(
    app: AppHandle,
    state: State<'_, CallCaptureCommandState>,
) -> Result<CallCaptureSnapshot, String> {
    stop_call_capture_with_reason(&app, &state, StopReason::Explicit)
}

#[tauri::command]
pub(crate) fn get_call_capture_state(
    app: AppHandle,
    state: State<'_, CallCaptureCommandState>,
) -> Result<CallCaptureSnapshot, String> {
    let now = now_ms()?;
    let (snapshot, ended) = {
        let mut inner = state.inner.lock().map_err(|error| error.to_string())?;
        let result = inner.controller.reconcile_runtime(now);
        let snapshot = inner.controller.snapshot(now);
        let ended = if snapshot.phase != CallCapturePhase::Active {
            inner.active.take()
        } else {
            None
        };
        if let Err(error) = result {
            if ended.is_none() {
                return Err(error);
            }
        }
        (snapshot, ended)
    };
    if let Some(active) = ended {
        finalize_active_call(&state, active, now)?;
        hide_capture_window(&app);
    }
    emit_snapshot(&app, &snapshot)?;
    Ok(snapshot)
}

#[tauri::command]
pub(crate) fn accept_call_copilot_suggestion(
    event_json: String,
    app: AppHandle,
    state: State<'_, CallCaptureCommandState>,
) -> Result<SegmentIngestOutcome, String> {
    state.ensure_enabled()?;
    let event = Event::from_json(event_json)
        .map_err(|_| "copilot suggestion event is malformed".to_string())?;
    let (outcome, ready) = {
        let mut inner = state.inner.lock().map_err(|error| error.to_string())?;
        let active = inner
            .active
            .as_mut()
            .ok_or_else(|| "copilot suggestion requires an active call".to_string())?;
        let payload =
            decrypt_copilot_suggestion(&active.owner, &active.route, active.call_id, &event)?;
        let outcome = active.suggestions.ingest(SequencedEphemeral {
            call_id: active.call_id,
            sequence: payload.sequence,
            value: payload,
        })?;
        let ready = if matches!(outcome, SegmentIngestOutcome::Accepted { .. }) {
            let values = active
                .suggestions
                .values()
                .into_iter()
                .filter(|payload| payload.sequence > active.last_suggestion_emitted)
                .collect::<Vec<_>>();
            if let Some(last) = values.last() {
                active.last_suggestion_emitted = last.sequence;
            }
            values
        } else {
            Vec::new()
        };
        (outcome, ready)
    };
    for payload in ready {
        app.emit(SUGGESTION_EVENT, payload)
            .map_err(|_| "copilot suggestion UI event failed".to_string())?;
    }
    Ok(outcome)
}

pub(crate) fn stop_call_capture_for_shutdown(app: &AppHandle) {
    if let Some(state) = app.try_state::<CallCaptureCommandState>() {
        let _ = stop_call_capture_with_reason(app, &state, StopReason::AppExit);
    }
}

pub(crate) fn stop_call_capture_for_window_close(app: &AppHandle) {
    if let Some(state) = app.try_state::<CallCaptureCommandState>() {
        let _ = stop_call_capture_with_reason(app, &state, StopReason::Explicit);
    }
}

pub(crate) fn start_suspend_watchdog(app: AppHandle) {
    let _ = thread::Builder::new()
        .name("core-call-suspend-watchdog".into())
        .spawn(move || {
            let mut last = Instant::now();
            loop {
                thread::sleep(SUSPEND_POLL);
                let now = Instant::now();
                if now.duration_since(last) > SUSPEND_GAP {
                    if let Some(state) = app.try_state::<CallCaptureCommandState>() {
                        let _ = stop_call_capture_with_reason(&app, &state, StopReason::Suspend);
                    }
                }
                last = now;
            }
        });
}

fn stop_call_capture_with_reason(
    app: &AppHandle,
    state: &CallCaptureCommandState,
    reason: StopReason,
) -> Result<CallCaptureSnapshot, String> {
    let now = now_ms()?;
    let (snapshot, active, stop_error) = {
        let mut inner = state.inner.lock().map_err(|error| error.to_string())?;
        let stop_result = inner.controller.stop_if_active(reason, now);
        let snapshot = inner.controller.snapshot(now);
        let active = if snapshot.phase != CallCapturePhase::Active {
            inner.active.take()
        } else {
            None
        };
        (snapshot, active, stop_result.err())
    };
    let mut cleanup_error = None;
    if let Some(mut active) = active {
        active.control_sequence = active.control_sequence.saturating_add(1);
        let _ = emit_control(app, &active, &snapshot, "stop", "ended");
        cleanup_error = finalize_active_call(state, active, now).err();
    }
    hide_capture_window(app);
    let _ = emit_snapshot(app, &snapshot);
    match (stop_error, cleanup_error) {
        (None, None) => Ok(snapshot),
        (Some(error), None) | (None, Some(error)) => Err(error),
        (Some(stop), Some(cleanup)) => Err(format!("{stop}; {cleanup}")),
    }
}

fn finalize_active_call(
    state: &CallCaptureCommandState,
    mut active: ActiveCall,
    ended_at_ms: u64,
) -> Result<(), String> {
    active.suggestions.purge();
    let segments = {
        let mut accumulator = active
            .accumulator
            .lock()
            .map_err(|error| error.to_string())?;
        let segments = accumulator.segments().cloned().collect::<Vec<_>>();
        accumulator.purge();
        segments
    };
    if segments.is_empty() {
        return Ok(());
    }
    state.recovery.persist(
        active.call_id,
        ended_at_ms,
        ended_at_ms.saturating_add(MAX_RECOVERY_AGE_MS),
        segments,
    )
}

fn emit_control_for_active(
    app: &AppHandle,
    state: &CallCaptureCommandState,
    snapshot: &CallCaptureSnapshot,
    command: &str,
    session_state: &str,
) -> Result<(), String> {
    let inner = state.inner.lock().map_err(|error| error.to_string())?;
    let active = inner
        .active
        .as_ref()
        .ok_or_else(|| "call control requires an active local session".to_string())?;
    emit_control(app, active, snapshot, command, session_state)
}

fn emit_control(
    app: &AppHandle,
    active: &ActiveCall,
    snapshot: &CallCaptureSnapshot,
    command: &str,
    session_state: &str,
) -> Result<(), String> {
    let meeting_context = active
        .meeting_context
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| "call meeting context could not be serialized".to_string())?;
    let payload: CallControlPayload = serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "call_id": active.call_id,
        "command": command,
        "session_state": session_state,
        "source_health": {
            "microphone": protocol_health(snapshot.microphone_source.health),
            "output": protocol_health(snapshot.output_source.health),
        },
        "degraded_reasons": [],
        "sequence": active.control_sequence,
        "meeting_context": meeting_context,
        "occurred_at": i64::try_from(now_ms()? / 1_000).unwrap_or(i64::MAX),
    }))
    .map_err(|_| "call control violates the frozen protocol".to_string())?;
    let event = encrypt_call_control(&active.owner, &active.route, &payload)?;
    emit_private_event(app, event)
}

fn protocol_health(health: AudioSourceHealth) -> &'static str {
    match health {
        AudioSourceHealth::Healthy => "healthy",
        AudioSourceHealth::Degraded => "degraded",
        AudioSourceHealth::Unavailable => "unavailable",
    }
}

fn emit_private_event(app: &AppHandle, event: Event) -> Result<(), String> {
    app.emit(
        PRIVATE_EVENT_READY,
        PrivateRelayEventReady {
            schema_version: 1,
            event,
        },
    )
    .map_err(|_| "private call relay event could not reach the Desktop transport".to_string())
}

fn emit_snapshot(app: &AppHandle, snapshot: &CallCaptureSnapshot) -> Result<(), String> {
    app.emit(STATE_EVENT, snapshot)
        .map_err(|_| "call capture state event could not be emitted".to_string())
}

fn now_ms() -> Result<u64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_string())?;
    u64::try_from(duration.as_millis()).map_err(|_| "system clock overflowed".to_string())
}

fn show_capture_window(app: &AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window(CAPTURE_WINDOW_LABEL) {
        window
            .show()
            .map_err(|_| "call capture bar could not be shown".to_string())?;
        let _ = window.set_always_on_top(true);
        return Ok(());
    }
    tauri::WebviewWindowBuilder::new(
        app,
        CAPTURE_WINDOW_LABEL,
        tauri::WebviewUrl::App("index.html?coreCallCaptureBar=1".into()),
    )
    .title("Core Call Copilot")
    .inner_size(680.0, 188.0)
    .min_inner_size(560.0, 172.0)
    .resizable(true)
    .always_on_top(true)
    .skip_taskbar(false)
    .build()
    .map(|_| ())
    .map_err(|_| "dedicated call capture bar could not be created".to_string())
}

fn hide_capture_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(CAPTURE_WINDOW_LABEL) {
        let _ = window.hide();
    }
}

struct TransportRuntime {
    native: Box<dyn CallCaptureRuntime>,
    transport_worker: Option<thread::JoinHandle<()>>,
    transport_failed: Arc<AtomicBool>,
}

impl CallCaptureRuntime for TransportRuntime {
    fn stop(&mut self) -> Result<(), String> {
        let native_result = self.native.stop();
        let transport_result = self
            .transport_worker
            .take()
            .map(thread::JoinHandle::join)
            .transpose()
            .map_err(|_| "private call transport worker terminated unexpectedly".to_string());
        native_result?;
        transport_result?;
        Ok(())
    }

    fn failure_reason(&self) -> Option<StopReason> {
        if self.transport_failed.load(Ordering::Acquire) {
            Some(StopReason::TranscriberFailure)
        } else {
            self.native.failure_reason()
        }
    }

    fn source_states(&self) -> (super::CallCaptureSourceState, super::CallCaptureSourceState) {
        self.native.source_states()
    }
}

fn run_transport(
    receiver: Receiver<FinalizedSegment>,
    app: AppHandle,
    owner: Keys,
    route: CallCaptureRoute,
    accumulator: Arc<Mutex<LiveSessionAccumulator>>,
    failed: &AtomicBool,
) {
    let mut last_published = 0u64;
    while let Ok(segment) = receiver.recv() {
        let ready = match accumulator.lock() {
            Ok(mut context) => match context.ingest(segment) {
                Ok(SegmentIngestOutcome::Accepted { .. }) => context
                    .segments()
                    .filter(|segment| segment.sequence > last_published)
                    .cloned()
                    .collect::<Vec<_>>(),
                Ok(_) => Vec::new(),
                Err(_) => {
                    failed.store(true, Ordering::Release);
                    return;
                }
            },
            Err(_) => {
                failed.store(true, Ordering::Release);
                return;
            }
        };
        for segment in ready {
            let sequence = segment.sequence;
            let event = match encrypt_finalized_segment(&owner, &route, &segment) {
                Ok(event) => event,
                Err(_) => {
                    failed.store(true, Ordering::Release);
                    return;
                }
            };
            if emit_private_event(&app, event).is_err() {
                failed.store(true, Ordering::Release);
                return;
            }
            last_published = sequence;
        }
    }
}

#[cfg(target_os = "windows")]
fn start_platform_runtime(
    call_id: Uuid,
    microphone: &CallCaptureDevice,
    output: &CallCaptureDevice,
    app: AppHandle,
    owner: Keys,
    route: CallCaptureRoute,
    accumulator: Arc<Mutex<LiveSessionAccumulator>>,
) -> Result<Box<dyn CallCaptureRuntime>, String> {
    let (sender, receiver) = mpsc::sync_channel(TRANSPORT_QUEUE_CAPACITY);
    let native = super::native::start(call_id, microphone, output, app.clone(), sender)?;
    let failed = Arc::new(AtomicBool::new(false));
    let thread_failed = Arc::clone(&failed);
    let transport_worker = thread::Builder::new()
        .name("core-call-private-transport".into())
        .spawn(move || {
            run_transport(receiver, app, owner, route, accumulator, &thread_failed);
        })
        .map_err(|_| "private call transport worker could not start".to_string())?;
    Ok(Box::new(TransportRuntime {
        native,
        transport_worker: Some(transport_worker),
        transport_failed: failed,
    }))
}

#[cfg(not(target_os = "windows"))]
fn start_platform_runtime(
    _call_id: Uuid,
    _microphone: &CallCaptureDevice,
    _output: &CallCaptureDevice,
    _app: AppHandle,
    _owner: Keys,
    _route: CallCaptureRoute,
    _accumulator: Arc<Mutex<LiveSessionAccumulator>>,
) -> Result<Box<dyn CallCaptureRuntime>, String> {
    Err("Core call capture is available only on Windows".into())
}

#[cfg(target_os = "windows")]
fn list_platform_devices() -> Result<Vec<CallCaptureDevice>, String> {
    super::native::list_devices()
}

#[cfg(not(target_os = "windows"))]
fn list_platform_devices() -> Result<Vec<CallCaptureDevice>, String> {
    Err("Core call capture is available only on Windows".into())
}
