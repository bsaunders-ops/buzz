use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    AudioEndpointKind, CallCaptureFeature, CallCapturePhase, CallCaptureSnapshot,
    CallCaptureSourceState, CallCaptureStateMachine, StopReason,
};

const SCHEMA_VERSION: u8 = 1;
const CONSENT_NOTICE_VERSION: u8 = 1;

/// One explicitly selectable local endpoint.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallCaptureDevice {
    pub schema_version: u8,
    pub id: String,
    pub label: String,
    pub kind: AudioEndpointKind,
    pub is_default: bool,
    pub sample_rate_hz: u32,
    pub channels: u16,
}

impl fmt::Debug for CallCaptureDevice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallCaptureDevice")
            .field("schema_version", &self.schema_version)
            .field("id", &"<redacted>")
            .field("label", &"<redacted>")
            .field("kind", &self.kind)
            .field("is_default", &self.is_default)
            .field("sample_rate_hz", &self.sample_rate_hz)
            .field("channels", &self.channels)
            .finish()
    }
}

impl CallCaptureDevice {
    fn validate(&self) -> Result<(), String> {
        if self.schema_version != SCHEMA_VERSION {
            return Err("unsupported call capture device schema".into());
        }
        if self.id.is_empty()
            || self.id.len() > 512
            || self.label.is_empty()
            || self.label.len() > 256
            || self
                .id
                .chars()
                .chain(self.label.chars())
                .any(char::is_control)
            || self.sample_rate_hz < 8_000
            || self.sample_rate_hz > 384_000
            || self.channels == 0
            || self.channels > 32
        {
            return Err("invalid call capture device metadata".into());
        }
        Ok(())
    }
}

/// Optional, bounded meeting context. It contains no raw source body.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallMeetingContext {
    pub source: CallMeetingContextSource,
    pub source_id: String,
    pub title: String,
}

impl fmt::Debug for CallMeetingContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallMeetingContext")
            .field("source", &self.source)
            .field("source_id", &"<redacted>")
            .field("title", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallMeetingContextSource {
    Calendar,
    Crm,
    Granola,
}

/// Explicit local acknowledgment submitted before a start token is minted.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallCaptureConsentRequest {
    pub schema_version: u8,
    pub microphone_id: String,
    pub output_id: String,
    pub consent_notice_version: u8,
    pub consent_acknowledged: bool,
}

impl fmt::Debug for CallCaptureConsentRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallCaptureConsentRequest")
            .field("schema_version", &self.schema_version)
            .field("microphone_id", &"<redacted>")
            .field("output_id", &"<redacted>")
            .field("consent_notice_version", &self.consent_notice_version)
            .field("consent_acknowledged", &self.consent_acknowledged)
            .finish()
    }
}

/// Start consumes an exact backend-minted, endpoint-bound consent token.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallCaptureStartRequest {
    pub schema_version: u8,
    pub microphone_id: String,
    pub output_id: String,
    pub consent_token: Uuid,
    pub meeting_context: Option<CallMeetingContext>,
}

impl fmt::Debug for CallCaptureStartRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallCaptureStartRequest")
            .field("schema_version", &self.schema_version)
            .field("microphone_id", &"<redacted>")
            .field("output_id", &"<redacted>")
            .field("consent_token", &"<redacted>")
            .field(
                "meeting_context",
                &self.meeting_context.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Native handles are opaque: the controller can only stop them.
pub trait CallCaptureRuntime: Send {
    fn stop(&mut self) -> Result<(), String>;

    fn failure_reason(&self) -> Option<StopReason> {
        None
    }

    fn source_states(&self) -> (CallCaptureSourceState, CallCaptureSourceState) {
        (
            CallCaptureSourceState::ACTIVE,
            CallCaptureSourceState::ACTIVE,
        )
    }
}

/// Serializes consent, native handle lifetime, and the pure session machine.
pub struct CallCaptureController {
    machine: CallCaptureStateMachine,
    runtime: Option<Box<dyn CallCaptureRuntime>>,
}

impl CallCaptureController {
    pub fn new(feature: CallCaptureFeature) -> Self {
        Self {
            machine: CallCaptureStateMachine::new(feature),
            runtime: None,
        }
    }

    pub fn acknowledge_consent(
        &mut self,
        request: CallCaptureConsentRequest,
        devices: &[CallCaptureDevice],
        now_ms: u64,
    ) -> Result<super::ConsentAcknowledgement, String> {
        self.validate_consent_request(&request)?;
        select_device(
            devices,
            &request.microphone_id,
            AudioEndpointKind::Microphone,
        )?;
        select_device(devices, &request.output_id, AudioEndpointKind::Output)?;
        self.machine
            .issue_consent(&request.microphone_id, &request.output_id, now_ms)
    }

    pub fn start<F>(
        &mut self,
        request: CallCaptureStartRequest,
        devices: &[CallCaptureDevice],
        now_ms: u64,
        start_native: F,
    ) -> Result<CallCaptureSnapshot, String>
    where
        F: FnOnce(
            Uuid,
            &CallCaptureDevice,
            &CallCaptureDevice,
        ) -> Result<Box<dyn CallCaptureRuntime>, String>,
    {
        self.validate_start_request(&request)?;
        if self.runtime.is_some() || self.machine.snapshot(now_ms).phase == CallCapturePhase::Active
        {
            return Err("call capture is already active".into());
        }
        let microphone = select_device(
            devices,
            &request.microphone_id,
            AudioEndpointKind::Microphone,
        )?;
        let output = select_device(devices, &request.output_id, AudioEndpointKind::Output)?;

        let call_id = self.machine.start(
            &request.microphone_id,
            &request.output_id,
            request.consent_token,
            now_ms,
        )?;

        match start_native(call_id, microphone, output) {
            Ok(runtime) => {
                self.runtime = Some(runtime);
                Ok(self.snapshot(now_ms))
            }
            Err(error) => {
                let _ = self.machine.stop(StopReason::TranscriberFailure, now_ms);
                Err(error)
            }
        }
    }

    pub fn stop(&mut self, reason: StopReason, now_ms: u64) -> Result<CallCaptureSnapshot, String> {
        let runtime_error = self
            .runtime
            .take()
            .and_then(|mut runtime| runtime.stop().err());
        let state_result = self.machine.stop(reason, now_ms);
        if let Some(error) = runtime_error {
            let _ = state_result;
            return Err(format!("native call capture stop failed: {error}"));
        }
        state_result?;
        Ok(self.snapshot(now_ms))
    }

    pub fn stop_if_active(
        &mut self,
        reason: StopReason,
        now_ms: u64,
    ) -> Result<CallCaptureSnapshot, String> {
        if matches!(
            self.machine.snapshot(now_ms).phase,
            CallCapturePhase::Active
        ) {
            self.stop(reason, now_ms)
        } else {
            Ok(self.snapshot(now_ms))
        }
    }

    pub fn resume_signal(&mut self, now_ms: u64) -> Result<CallCaptureSnapshot, String> {
        self.machine.resume_signal(now_ms)?;
        Ok(self.snapshot(now_ms))
    }

    pub fn reconcile_runtime(&mut self, now_ms: u64) -> Result<CallCaptureSnapshot, String> {
        let failure = self
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.failure_reason());
        if let Some(reason) = failure {
            return self.stop(reason, now_ms);
        }
        Ok(self.snapshot(now_ms))
    }

    pub fn snapshot(&self, now_ms: u64) -> CallCaptureSnapshot {
        let mut snapshot = self.machine.snapshot(now_ms);
        if let Some(runtime) = &self.runtime {
            let (microphone, output) = runtime.source_states();
            snapshot.microphone_source = microphone;
            snapshot.output_source = output;
        }
        snapshot
    }

    fn validate_start_request(&self, request: &CallCaptureStartRequest) -> Result<(), String> {
        if request.schema_version != SCHEMA_VERSION {
            return Err("unsupported call capture start schema".into());
        }
        if request.consent_token.get_version_num() != 4 {
            return Err("call capture consent token must be UUIDv4".into());
        }
        if let Some(context) = &request.meeting_context {
            if context.source_id.is_empty()
                || context.source_id.len() > 256
                || context.title.is_empty()
                || context.title.len() > 128
                || context
                    .source_id
                    .chars()
                    .chain(context.title.chars())
                    .any(char::is_control)
            {
                return Err("invalid bounded meeting context".into());
            }
        }
        // Also fail closed while the feature is disabled before native enumeration/start.
        if self.machine.snapshot(0).phase == CallCapturePhase::Disabled {
            return Err("Core call capture is disabled".into());
        }
        Ok(())
    }

    fn validate_consent_request(&self, request: &CallCaptureConsentRequest) -> Result<(), String> {
        if request.schema_version != SCHEMA_VERSION
            || request.consent_notice_version != CONSENT_NOTICE_VERSION
        {
            return Err("unsupported call capture consent schema or notice".into());
        }
        if !request.consent_acknowledged {
            return Err("call capture requires explicit local consent acknowledgment".into());
        }
        if self.machine.snapshot(0).phase == CallCapturePhase::Disabled {
            return Err("Core call capture is disabled".into());
        }
        Ok(())
    }
}

impl Drop for CallCaptureController {
    fn drop(&mut self) {
        if let Some(mut runtime) = self.runtime.take() {
            let _ = runtime.stop();
        }
    }
}

fn select_device<'a>(
    devices: &'a [CallCaptureDevice],
    id: &str,
    expected_kind: AudioEndpointKind,
) -> Result<&'a CallCaptureDevice, String> {
    let matching: Vec<&CallCaptureDevice> =
        devices.iter().filter(|device| device.id == id).collect();
    let device = match matching.as_slice() {
        [device] => *device,
        [] => return Err("selected call capture endpoint is unavailable".into()),
        _ => return Err("selected call capture endpoint identifier is ambiguous".into()),
    };
    device.validate()?;
    if device.kind != expected_kind {
        return Err("selected call capture endpoint has the wrong source kind".into());
    }
    Ok(device)
}
