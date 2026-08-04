use super::{
    pipeline::validate_raw_audio_input, AudioEndpointKind, BoundedAudioRing, FinalizedSegment,
    FinalizedSegmentSink, LocalAudioPipeline, LocalTranscriber, LocalTranscript, RawAudioFrame,
    TranscriptSpeaker,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

struct RecordingTranscriber {
    calls: Arc<Mutex<Vec<(AudioEndpointKind, Vec<f32>)>>>,
}

impl LocalTranscriber for RecordingTranscriber {
    fn transcribe(
        &mut self,
        source: AudioEndpointKind,
        samples: &[f32],
        started_at_ms: u64,
        ended_at_ms: u64,
    ) -> Result<Option<LocalTranscript>, String> {
        self.calls.lock().unwrap().push((source, samples.to_vec()));
        Ok(Some(LocalTranscript {
            text: match source {
                AudioEndpointKind::Microphone => "I will send it".into(),
                AudioEndpointKind::Output => "Thank you".into(),
            },
            confidence: 91,
            started_at_ms,
            ended_at_ms,
            model_version: "parakeet-tdt-ctc-110m-en-int8".into(),
        }))
    }
}

struct RecordingFinalizedSink {
    segments: Arc<Mutex<Vec<FinalizedSegment>>>,
}

impl FinalizedSegmentSink for RecordingFinalizedSink {
    fn publish(&mut self, segment: FinalizedSegment) -> Result<(), String> {
        self.segments.lock().unwrap().push(segment);
        Ok(())
    }
}

fn frame(source: AudioEndpointKind, value: f32, start: u64, end: u64) -> RawAudioFrame {
    RawAudioFrame::new(source, vec![value; 160], 16_000, start, end).unwrap()
}

fn recording_pipeline(
    call_id: Uuid,
) -> (
    LocalAudioPipeline<RecordingTranscriber, RecordingFinalizedSink>,
    Arc<Mutex<Vec<(AudioEndpointKind, Vec<f32>)>>>,
    Arc<Mutex<Vec<FinalizedSegment>>>,
) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let segments = Arc::new(Mutex::new(Vec::new()));
    let pipeline = LocalAudioPipeline::new(
        call_id,
        RecordingTranscriber {
            calls: Arc::clone(&calls),
        },
        RecordingFinalizedSink {
            segments: Arc::clone(&segments),
        },
        1_600,
    )
    .unwrap();
    (pipeline, calls, segments)
}

#[test]
fn bounded_raw_ring_evicts_oldest_samples_and_clears_in_memory() {
    let mut ring = BoundedAudioRing::new(4).unwrap();
    ring.push(&[1.0, 2.0, 3.0]).unwrap();
    ring.push(&[4.0, 5.0, 6.0]).unwrap();

    assert_eq!(ring.copy_samples(), vec![3.0, 4.0, 5.0, 6.0]);
    assert_eq!(ring.len(), 4);
    ring.clear();
    assert!(ring.copy_samples().is_empty());
}

#[test]
fn raw_audio_reaches_only_local_transcription_and_sink_receives_finalized_text() {
    let call_id = Uuid::new_v4();
    let (mut pipeline, calls, segments) = recording_pipeline(call_id);

    pipeline
        .push_frame(frame(AudioEndpointKind::Microphone, 0.25, 10, 20), 30)
        .unwrap();

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1, vec![0.25; 160]);
    let segments = segments.lock().unwrap();
    assert_eq!(segments.len(), 1);
    let segment = &segments[0];
    assert_eq!(segment.call_id, call_id);
    assert_eq!(segment.sequence, 1);
    assert_eq!(segment.speaker, TranscriptSpeaker::SelfSpeaker);
    assert_eq!(segment.text, "I will send it");
    assert_eq!(pipeline.buffered_sample_count(), 0);
}

#[test]
fn microphone_and_loopback_remain_separate_and_get_stable_speaker_labels() {
    let (mut pipeline, calls, segments) = recording_pipeline(Uuid::new_v4());

    pipeline
        .push_frame(frame(AudioEndpointKind::Output, -0.5, 1, 2), 3)
        .unwrap();
    pipeline
        .push_frame(frame(AudioEndpointKind::Microphone, 0.5, 3, 4), 5)
        .unwrap();

    let calls = calls.lock().unwrap();
    let segments = segments.lock().unwrap();
    assert_eq!(calls[0].0, AudioEndpointKind::Output);
    assert_eq!(segments[0].speaker, TranscriptSpeaker::Others);
    assert_eq!(segments[1].speaker, TranscriptSpeaker::SelfSpeaker);
    assert_eq!(segments[0].sequence, 1);
    assert_eq!(segments[1].sequence, 2);
}

#[test]
fn invalid_rate_time_or_non_finite_audio_fails_before_transcription() {
    assert!(RawAudioFrame::new(AudioEndpointKind::Microphone, vec![0.1], 48_000, 1, 2,).is_err());
    assert!(RawAudioFrame::new(AudioEndpointKind::Microphone, vec![0.1], 16_000, 2, 1,).is_err());
    assert!(
        RawAudioFrame::new(AudioEndpointKind::Microphone, vec![f32::NAN], 16_000, 1, 2,).is_err()
    );
}

#[test]
fn rejected_raw_audio_is_scrubbed_before_its_allocation_is_released() {
    for (mut samples, sample_rate, start, end) in [
        (vec![0.25], 48_000, 1, 2),
        (vec![0.25], 16_000, 2, 1),
        (vec![f32::NAN], 16_000, 1, 2),
    ] {
        assert!(validate_raw_audio_input(&mut samples, sample_rate, start, end).is_err());
        assert!(samples.iter().all(|sample| *sample == 0.0));
    }
}

struct ClockAdvancingTranscriber {
    clock_ms: Arc<AtomicU64>,
}

impl LocalTranscriber for ClockAdvancingTranscriber {
    fn transcribe(
        &mut self,
        _source: AudioEndpointKind,
        _samples: &[f32],
        started_at_ms: u64,
        ended_at_ms: u64,
    ) -> Result<Option<LocalTranscript>, String> {
        self.clock_ms.store(975, Ordering::Release);
        Ok(Some(LocalTranscript {
            text: "finalized after local inference".into(),
            confidence: 90,
            started_at_ms,
            ended_at_ms,
            model_version: "parakeet-v1".into(),
        }))
    }
}

#[test]
fn finalization_clock_is_sampled_after_local_transcription() {
    let clock_ms = Arc::new(AtomicU64::new(600));
    let segments = Arc::new(Mutex::new(Vec::new()));
    let mut pipeline = LocalAudioPipeline::new(
        Uuid::new_v4(),
        ClockAdvancingTranscriber {
            clock_ms: Arc::clone(&clock_ms),
        },
        RecordingFinalizedSink { segments },
        1_600,
    )
    .unwrap();

    pipeline
        .push_frame_with_clock(frame(AudioEndpointKind::Microphone, 0.1, 100, 350), || {
            clock_ms.load(Ordering::Acquire)
        })
        .unwrap();

    assert_eq!(pipeline.metrics().last_finalization_latency_ms, Some(625));
}

#[test]
fn finalized_latency_metrics_contain_no_text_or_audio() {
    let (mut pipeline, _, _) = recording_pipeline(Uuid::new_v4());
    pipeline
        .push_frame(frame(AudioEndpointKind::Microphone, 0.1, 100, 350), 600)
        .unwrap();

    let metrics = pipeline.metrics();
    assert_eq!(metrics.finalized_segments, 1);
    assert_eq!(metrics.last_finalization_latency_ms, Some(250));
    assert_eq!(metrics.p95_finalization_latency_ms, Some(250));
    assert_eq!(metrics.dropped_audio_frames, 0);
}

#[test]
fn transcript_debug_output_redacts_text() {
    let sentinel = "MNPI-SENTINEL-DO-NOT-LOG";
    let transcript = LocalTranscript {
        text: sentinel.into(),
        confidence: 90,
        started_at_ms: 1,
        ended_at_ms: 2,
        model_version: "parakeet-v1".into(),
    };
    let segment = FinalizedSegment {
        schema_version: 1,
        segment_id: Uuid::new_v4(),
        call_id: Uuid::new_v4(),
        sequence: 1,
        speaker: TranscriptSpeaker::SelfSpeaker,
        text: sentinel.into(),
        started_at_ms: 1,
        ended_at_ms: 2,
        confidence: 90,
        model_version: "parakeet-v1".into(),
    };

    let transcript_debug = format!("{transcript:?}");
    let segment_debug = format!("{segment:?}");
    assert!(!transcript_debug.contains(sentinel));
    assert!(!segment_debug.contains(sentinel));
    assert!(transcript_debug.contains("<redacted>"));
    assert!(segment_debug.contains("<redacted>"));
}
