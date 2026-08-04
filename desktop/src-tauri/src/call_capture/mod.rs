use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

mod pipeline;
pub use pipeline::*;
#[cfg(feature = "call-capture-platform")]
mod commands;
mod controller;
#[cfg(target_os = "windows")]
mod native;
mod native_boundary;
#[cfg(target_os = "windows")]
mod parakeet;
#[cfg(feature = "call-capture-platform")]
mod platform;
mod recovery;
mod session;
mod transport;
#[cfg(feature = "call-capture-platform")]
pub(crate) use commands::*;
pub use controller::*;
pub use recovery::*;
pub use session::*;
pub use transport::*;

const SCHEMA_VERSION: u8 = 1;
const CONSENT_FRESHNESS_MS: u64 = 60_000;

/// Build/runtime gate for Core's Windows-only call copilot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallCaptureFeature {
    Disabled,
    Enabled,
}

/// Lifecycle exposed to the Desktop UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallCapturePhase {
    Disabled,
    Idle,
    Active,
    Ended,
}

/// The two streams are deliberately separate for source attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AudioEndpointKind {
    Microphone,
    Output,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AudioSourceHealth {
    Healthy,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallCaptureSourceState {
    pub health: AudioSourceHealth,
    pub level_percent: u8,
}

impl CallCaptureSourceState {
    const UNAVAILABLE: Self = Self {
        health: AudioSourceHealth::Unavailable,
        level_percent: 0,
    };

    const ACTIVE: Self = Self {
        health: AudioSourceHealth::Healthy,
        level_percent: 0,
    };
}

/// Closed reasons that can degrade or terminate capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradedReason {
    MicrophoneEndpointLost,
    OutputEndpointLost,
    MicrophoneSilent,
    OutputSilent,
    TranscriptionLag,
    TranscriberUnavailable,
    ConsentMissing,
}

/// Closed stop vocabulary. There is intentionally no remote or automatic start reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Explicit,
    Suspend,
    AppExit,
    ConsentRevoked,
    DeviceFailure,
    TranscriberFailure,
    CrashRecovery,
}

/// A short-lived, endpoint-bound acknowledgment minted for the visible start control.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentAcknowledgement {
    pub schema_version: u8,
    pub token: Uuid,
    pub microphone_id: String,
    pub output_id: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

impl fmt::Debug for ConsentAcknowledgement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsentAcknowledgement")
            .field("schema_version", &self.schema_version)
            .field("token", &"<redacted>")
            .field("microphone_id", &"<redacted>")
            .field("output_id", &"<redacted>")
            .field("issued_at_ms", &self.issued_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

/// Serializable state snapshot; it contains no transcript or audio data.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallCaptureSnapshot {
    pub schema_version: u8,
    pub phase: CallCapturePhase,
    pub call_id: Option<Uuid>,
    pub selected_microphone_id: Option<String>,
    pub selected_output_id: Option<String>,
    pub microphone_source: CallCaptureSourceState,
    pub output_source: CallCaptureSourceState,
    pub degraded_reasons: Vec<DegradedReason>,
    pub stop_reason: Option<StopReason>,
    pub started_at_ms: Option<u64>,
    pub elapsed_ms: u64,
    pub last_segment_sequence: u64,
}

impl fmt::Debug for CallCaptureSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallCaptureSnapshot")
            .field("schema_version", &self.schema_version)
            .field("phase", &self.phase)
            .field("call_id", &self.call_id.map(|_| "<redacted>"))
            .field(
                "selected_microphone_id",
                &self.selected_microphone_id.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "selected_output_id",
                &self.selected_output_id.as_ref().map(|_| "<redacted>"),
            )
            .field("microphone_source", &self.microphone_source)
            .field("output_source", &self.output_source)
            .field("degraded_reasons", &self.degraded_reasons)
            .field("stop_reason", &self.stop_reason)
            .field("started_at_ms", &self.started_at_ms)
            .field("elapsed_ms", &self.elapsed_ms)
            .field("last_segment_sequence", &self.last_segment_sequence)
            .finish()
    }
}

/// Pure, fail-closed lifecycle machine used by both native and fake capture backends.
pub struct CallCaptureStateMachine {
    feature: CallCaptureFeature,
    phase: CallCapturePhase,
    call_id: Option<Uuid>,
    selected_microphone_id: Option<String>,
    selected_output_id: Option<String>,
    degraded_reasons: Vec<DegradedReason>,
    stop_reason: Option<StopReason>,
    started_at_ms: Option<u64>,
    last_segment_sequence: u64,
    pending_consent: Option<ConsentAcknowledgement>,
}

impl fmt::Debug for CallCaptureStateMachine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallCaptureStateMachine")
            .field("feature", &self.feature)
            .field("phase", &self.phase)
            .field("call_id", &self.call_id.map(|_| "<redacted>"))
            .field(
                "selected_microphone_id",
                &self.selected_microphone_id.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "selected_output_id",
                &self.selected_output_id.as_ref().map(|_| "<redacted>"),
            )
            .field("degraded_reasons", &self.degraded_reasons)
            .field("stop_reason", &self.stop_reason)
            .field("started_at_ms", &self.started_at_ms)
            .field("last_segment_sequence", &self.last_segment_sequence)
            .field("pending_consent", &self.pending_consent)
            .finish()
    }
}

impl CallCaptureStateMachine {
    pub fn new(feature: CallCaptureFeature) -> Self {
        let phase = match feature {
            CallCaptureFeature::Disabled => CallCapturePhase::Disabled,
            CallCaptureFeature::Enabled => CallCapturePhase::Idle,
        };
        Self {
            feature,
            phase,
            call_id: None,
            selected_microphone_id: None,
            selected_output_id: None,
            degraded_reasons: Vec::new(),
            stop_reason: None,
            started_at_ms: None,
            last_segment_sequence: 0,
            pending_consent: None,
        }
    }

    pub fn recover_after_crash(had_active_session: bool) -> Self {
        let mut machine = Self::new(CallCaptureFeature::Enabled);
        if had_active_session {
            machine.phase = CallCapturePhase::Ended;
            machine.stop_reason = Some(StopReason::CrashRecovery);
        }
        machine
    }

    pub fn issue_consent(
        &mut self,
        microphone_id: &str,
        output_id: &str,
        now_ms: u64,
    ) -> Result<ConsentAcknowledgement, String> {
        self.ensure_enabled()?;
        if self.phase == CallCapturePhase::Active {
            return Err("call capture is already active".into());
        }
        if microphone_id.trim().is_empty() || output_id.trim().is_empty() {
            return Err("both selected endpoint identifiers are required".into());
        }
        let acknowledgement = ConsentAcknowledgement {
            schema_version: SCHEMA_VERSION,
            token: Uuid::new_v4(),
            microphone_id: microphone_id.to_owned(),
            output_id: output_id.to_owned(),
            issued_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(CONSENT_FRESHNESS_MS),
        };
        self.pending_consent = Some(acknowledgement.clone());
        Ok(acknowledgement)
    }

    pub fn start(
        &mut self,
        microphone_id: &str,
        output_id: &str,
        consent_token: Uuid,
        now_ms: u64,
    ) -> Result<Uuid, String> {
        self.ensure_enabled()?;
        if self.phase == CallCapturePhase::Active {
            return Err("call capture is already active".into());
        }
        let consent = self
            .pending_consent
            .as_ref()
            .ok_or_else(|| "fresh visible consent is required".to_string())?;
        if consent.schema_version != SCHEMA_VERSION || consent.token != consent_token {
            return Err("consent is unknown, stale, or already used".into());
        }
        if consent.microphone_id != microphone_id || consent.output_id != output_id {
            return Err("consent does not match the selected endpoints".into());
        }
        let consent_age_ms = now_ms
            .checked_sub(consent.issued_at_ms)
            .ok_or_else(|| "consent timestamp is in the future".to_string())?;
        if consent_age_ms > CONSENT_FRESHNESS_MS || now_ms > consent.expires_at_ms {
            return Err("consent has expired".into());
        }
        self.pending_consent = None;
        let call_id = Uuid::new_v4();
        self.phase = CallCapturePhase::Active;
        self.call_id = Some(call_id);
        self.selected_microphone_id = Some(microphone_id.to_owned());
        self.selected_output_id = Some(output_id.to_owned());
        self.degraded_reasons.clear();
        self.stop_reason = None;
        self.started_at_ms = Some(now_ms);
        self.last_segment_sequence = 0;
        Ok(call_id)
    }

    pub fn stop(&mut self, reason: StopReason, _now_ms: u64) -> Result<(), String> {
        self.ensure_enabled()?;
        if self.phase != CallCapturePhase::Active {
            return Err("no active call capture session".into());
        }
        self.phase = CallCapturePhase::Ended;
        self.stop_reason = Some(reason);
        self.pending_consent = None;
        Ok(())
    }

    pub fn next_segment_sequence(&mut self) -> Result<u64, String> {
        if self.phase != CallCapturePhase::Active {
            return Err("transcript segments require an active call session".into());
        }
        self.last_segment_sequence = self
            .last_segment_sequence
            .checked_add(1)
            .ok_or_else(|| "call segment sequence exhausted".to_string())?;
        Ok(self.last_segment_sequence)
    }

    pub fn endpoint_unavailable(
        &mut self,
        kind: AudioEndpointKind,
        endpoint_id: &str,
        now_ms: u64,
    ) -> Result<(), String> {
        if self.phase != CallCapturePhase::Active {
            return Err("no active call capture session".into());
        }
        let selected_matches = match kind {
            AudioEndpointKind::Microphone => {
                self.selected_microphone_id.as_deref() == Some(endpoint_id)
            }
            AudioEndpointKind::Output => self.selected_output_id.as_deref() == Some(endpoint_id),
        };
        if !selected_matches {
            return Err("device event does not match the selected endpoint".into());
        }
        let reason = match kind {
            AudioEndpointKind::Microphone => DegradedReason::MicrophoneEndpointLost,
            AudioEndpointKind::Output => DegradedReason::OutputEndpointLost,
        };
        if !self.degraded_reasons.contains(&reason) {
            self.degraded_reasons.push(reason);
        }
        self.stop(StopReason::DeviceFailure, now_ms)
    }

    pub fn on_main_window_minimized(&mut self, _now_ms: u64) -> Result<(), String> {
        self.ensure_enabled()
    }

    pub fn resume_signal(&mut self, _now_ms: u64) -> Result<(), String> {
        self.ensure_enabled()
    }

    pub fn snapshot(&self, now_ms: u64) -> CallCaptureSnapshot {
        CallCaptureSnapshot {
            schema_version: SCHEMA_VERSION,
            phase: self.phase,
            call_id: self.call_id,
            selected_microphone_id: self.selected_microphone_id.clone(),
            selected_output_id: self.selected_output_id.clone(),
            microphone_source: CallCaptureSourceState::UNAVAILABLE,
            output_source: CallCaptureSourceState::UNAVAILABLE,
            degraded_reasons: self.degraded_reasons.clone(),
            stop_reason: self.stop_reason,
            started_at_ms: self.started_at_ms,
            elapsed_ms: self
                .started_at_ms
                .map_or(0, |started| now_ms.saturating_sub(started)),
            last_segment_sequence: self.last_segment_sequence,
        }
    }

    fn ensure_enabled(&self) -> Result<(), String> {
        match self.feature {
            CallCaptureFeature::Enabled => Ok(()),
            CallCaptureFeature::Disabled => Err("Core call capture is disabled".into()),
        }
    }
}

#[cfg(test)]
mod controller_tests;
#[cfg(test)]
mod native_boundary_tests;
#[cfg(test)]
mod pipeline_tests;
#[cfg(test)]
mod recovery_tests;
#[cfg(test)]
mod session_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod transport_tests;
