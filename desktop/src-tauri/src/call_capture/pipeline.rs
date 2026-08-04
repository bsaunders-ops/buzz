use std::{
    collections::VecDeque,
    fmt,
    ops::Deref,
    sync::atomic::{compiler_fence, Ordering},
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::AudioEndpointKind;

/// Parakeet's canonical input rate. Native streams must be converted in memory.
pub const CALL_TRANSCRIPTION_SAMPLE_RATE: u32 = 16_000;
const MAX_RAW_FRAME_SAMPLES: usize = CALL_TRANSCRIPTION_SAMPLE_RATE as usize * 30;
const MAX_TRANSCRIPT_TEXT_BYTES: usize = 65_535;

/// Self/others attribution derived only from the unmixed capture source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptSpeaker {
    #[serde(rename = "self")]
    SelfSpeaker,
    #[serde(rename = "others")]
    Others,
}

/// One in-memory, canonical-rate PCM frame. Samples are scrubbed on drop.
pub struct RawAudioFrame {
    source: AudioEndpointKind,
    samples: Vec<f32>,
    started_at_ms: u64,
    ended_at_ms: u64,
}

impl RawAudioFrame {
    pub fn new(
        source: AudioEndpointKind,
        mut samples: Vec<f32>,
        sample_rate: u32,
        started_at_ms: u64,
        ended_at_ms: u64,
    ) -> Result<Self, String> {
        validate_raw_audio_input(&mut samples, sample_rate, started_at_ms, ended_at_ms)?;
        Ok(Self {
            source,
            samples,
            started_at_ms,
            ended_at_ms,
        })
    }
}

pub(super) fn validate_raw_audio_input(
    samples: &mut [f32],
    sample_rate: u32,
    started_at_ms: u64,
    ended_at_ms: u64,
) -> Result<(), String> {
    let error = if sample_rate != CALL_TRANSCRIPTION_SAMPLE_RATE {
        Some("raw call audio must be converted to 16 kHz before transcription")
    } else if samples.is_empty() || samples.len() > MAX_RAW_FRAME_SAMPLES {
        Some("raw call audio frame is empty or exceeds 30 seconds")
    } else if samples.iter().any(|sample| !sample.is_finite()) {
        Some("raw call audio contains a non-finite sample")
    } else if ended_at_ms < started_at_ms {
        Some("raw call audio timestamps are reversed")
    } else {
        None
    };
    if let Some(error) = error {
        samples.fill(0.0);
        compiler_fence(Ordering::SeqCst);
        return Err(error.into());
    }
    Ok(())
}

impl Drop for RawAudioFrame {
    fn drop(&mut self) {
        self.samples.fill(0.0);
        compiler_fence(Ordering::SeqCst);
    }
}

/// Fixed-capacity in-memory PCM ring. It never grows after construction.
pub struct BoundedAudioRing {
    samples: Vec<f32>,
    start: usize,
    len: usize,
}

impl BoundedAudioRing {
    pub fn new(capacity: usize) -> Result<Self, String> {
        if capacity == 0 || capacity > MAX_RAW_FRAME_SAMPLES {
            return Err("audio ring capacity must be between one sample and 30 seconds".into());
        }
        Ok(Self {
            samples: vec![0.0; capacity],
            start: 0,
            len: 0,
        })
    }

    pub fn push(&mut self, incoming: &[f32]) -> Result<(), String> {
        if incoming.iter().any(|sample| !sample.is_finite()) {
            return Err("audio ring rejected a non-finite sample".into());
        }
        for &sample in incoming {
            if self.len < self.samples.len() {
                let index = (self.start + self.len) % self.samples.len();
                self.samples[index] = sample;
                self.len += 1;
            } else {
                self.samples[self.start] = sample;
                self.start = (self.start + 1) % self.samples.len();
            }
        }
        Ok(())
    }

    pub fn copy_samples(&self) -> Vec<f32> {
        (0..self.len)
            .map(|offset| self.samples[(self.start + offset) % self.samples.len()])
            .collect()
    }

    fn sensitive_copy(&self) -> SensitiveSamples {
        SensitiveSamples(self.copy_samples())
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn clear(&mut self) {
        self.samples.fill(0.0);
        compiler_fence(Ordering::SeqCst);
        self.start = 0;
        self.len = 0;
    }
}

/// Temporary transcription copy that is scrubbed on every return path, including errors.
struct SensitiveSamples(Vec<f32>);

impl Deref for SensitiveSamples {
    type Target = [f32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SensitiveSamples {
    fn drop(&mut self) {
        self.0.fill(0.0);
        compiler_fence(Ordering::SeqCst);
    }
}

impl Drop for BoundedAudioRing {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Final text emitted by a local, non-networked transcriber.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalTranscript {
    pub text: String,
    pub confidence: u8,
    pub started_at_ms: u64,
    pub ended_at_ms: u64,
    pub model_version: String,
}

impl fmt::Debug for LocalTranscript {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalTranscript")
            .field("text", &"<redacted>")
            .field("confidence", &self.confidence)
            .field("started_at_ms", &self.started_at_ms)
            .field("ended_at_ms", &self.ended_at_ms)
            .field("model_version", &self.model_version)
            .finish()
    }
}

/// Narrow local-only transcription boundary. It has no URL, client, or persistence handle.
pub trait LocalTranscriber {
    fn transcribe(
        &mut self,
        source: AudioEndpointKind,
        samples: &[f32],
        started_at_ms: u64,
        ended_at_ms: u64,
    ) -> Result<Option<LocalTranscript>, String>;
}

/// Finalized text contract. Raw audio is unrepresentable at this boundary.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedSegment {
    pub schema_version: u8,
    pub segment_id: Uuid,
    pub call_id: Uuid,
    pub sequence: u64,
    pub speaker: TranscriptSpeaker,
    pub text: String,
    pub started_at_ms: u64,
    pub ended_at_ms: u64,
    pub confidence: u8,
    pub model_version: String,
}

impl fmt::Debug for FinalizedSegment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalizedSegment")
            .field("schema_version", &self.schema_version)
            .field("segment_id", &self.segment_id)
            .field("call_id", &self.call_id)
            .field("sequence", &self.sequence)
            .field("speaker", &self.speaker)
            .field("text", &"<redacted>")
            .field("started_at_ms", &self.started_at_ms)
            .field("ended_at_ms", &self.ended_at_ms)
            .field("confidence", &self.confidence)
            .field("model_version", &self.model_version)
            .finish()
    }
}

/// The only transport-visible boundary exposed by the local audio pipeline.
pub trait FinalizedSegmentSink {
    fn publish(&mut self, segment: FinalizedSegment) -> Result<(), String>;
}

/// Text-free counters safe for local performance instrumentation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallCaptureMetrics {
    pub finalized_segments: u64,
    pub dropped_audio_frames: u64,
    pub last_finalization_latency_ms: Option<u64>,
    pub p95_finalization_latency_ms: Option<u64>,
}

/// Keeps microphone and loopback audio in distinct bounded rings until local STT finalizes it.
pub struct LocalAudioPipeline<T, S> {
    call_id: Uuid,
    transcriber: T,
    sink: S,
    microphone: BoundedAudioRing,
    output: BoundedAudioRing,
    next_sequence: u64,
    metrics: CallCaptureMetrics,
    finalization_latency_window_ms: VecDeque<u64>,
}

impl<T: LocalTranscriber, S: FinalizedSegmentSink> LocalAudioPipeline<T, S> {
    pub fn new(
        call_id: Uuid,
        transcriber: T,
        sink: S,
        ring_capacity_samples: usize,
    ) -> Result<Self, String> {
        Ok(Self {
            call_id,
            transcriber,
            sink,
            microphone: BoundedAudioRing::new(ring_capacity_samples)?,
            output: BoundedAudioRing::new(ring_capacity_samples)?,
            next_sequence: 1,
            metrics: CallCaptureMetrics::default(),
            finalization_latency_window_ms: VecDeque::with_capacity(128),
        })
    }

    pub fn push_frame(&mut self, frame: RawAudioFrame, finalized_at_ms: u64) -> Result<(), String> {
        self.push_frame_with_clock(frame, || finalized_at_ms)
    }

    pub fn push_frame_with_clock<F>(
        &mut self,
        frame: RawAudioFrame,
        finalized_at_ms: F,
    ) -> Result<(), String>
    where
        F: FnOnce() -> u64,
    {
        let ring = match frame.source {
            AudioEndpointKind::Microphone => &mut self.microphone,
            AudioEndpointKind::Output => &mut self.output,
        };
        ring.push(&frame.samples)?;
        let transcription_input = ring.sensitive_copy();
        ring.clear();

        let transcript = self.transcriber.transcribe(
            frame.source,
            &transcription_input,
            frame.started_at_ms,
            frame.ended_at_ms,
        )?;
        if let Some(transcript) = transcript {
            self.publish_transcript(frame.source, transcript, finalized_at_ms())?;
        }
        Ok(())
    }

    pub fn buffered_sample_count(&self) -> usize {
        self.microphone.len() + self.output.len()
    }

    pub fn metrics(&self) -> CallCaptureMetrics {
        self.metrics
    }

    pub fn stop_and_scrub(&mut self) {
        self.microphone.clear();
        self.output.clear();
    }

    fn publish_transcript(
        &mut self,
        source: AudioEndpointKind,
        transcript: LocalTranscript,
        finalized_at_ms: u64,
    ) -> Result<(), String> {
        let text = transcript.text.trim();
        if text.is_empty() || text.len() > MAX_TRANSCRIPT_TEXT_BYTES {
            return Err("local transcript is empty or exceeds the private event limit".into());
        }
        if transcript.confidence > 100
            || transcript.ended_at_ms < transcript.started_at_ms
            || finalized_at_ms < transcript.ended_at_ms
            || transcript.model_version.trim().is_empty()
        {
            return Err("local transcriber returned invalid finalized metadata".into());
        }
        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| "call transcript sequence exhausted".to_string())?;
        let segment = FinalizedSegment {
            schema_version: 1,
            segment_id: Uuid::new_v4(),
            call_id: self.call_id,
            sequence,
            speaker: match source {
                AudioEndpointKind::Microphone => TranscriptSpeaker::SelfSpeaker,
                AudioEndpointKind::Output => TranscriptSpeaker::Others,
            },
            text: text.to_owned(),
            started_at_ms: transcript.started_at_ms,
            ended_at_ms: transcript.ended_at_ms,
            confidence: transcript.confidence,
            model_version: transcript.model_version,
        };
        self.sink.publish(segment)?;
        self.metrics.finalized_segments = self.metrics.finalized_segments.saturating_add(1);
        let finalization_latency_ms = finalized_at_ms - transcript.ended_at_ms;
        if self.finalization_latency_window_ms.len() == 128 {
            self.finalization_latency_window_ms.pop_front();
        }
        self.finalization_latency_window_ms
            .push_back(finalization_latency_ms);
        self.metrics.last_finalization_latency_ms = Some(finalization_latency_ms);
        let mut ordered: Vec<u64> = self
            .finalization_latency_window_ms
            .iter()
            .copied()
            .collect();
        ordered.sort_unstable();
        let p95_index = (ordered.len() * 95).div_ceil(100).saturating_sub(1);
        self.metrics.p95_finalization_latency_ms = ordered.get(p95_index).copied();
        Ok(())
    }
}

impl<T, S> Drop for LocalAudioPipeline<T, S> {
    fn drop(&mut self) {
        self.microphone.clear();
        self.output.clear();
    }
}
