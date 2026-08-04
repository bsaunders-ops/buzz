use std::{
    ops::Deref,
    str::FromStr,
    sync::{
        atomic::{compiler_fence, AtomicBool, AtomicU8, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
        Arc,
    },
    thread,
    time::Duration,
};

use earshot::{DefaultPredictor, Detector};
use rodio::cpal::{
    self,
    traits::{DeviceTrait, HostTrait, StreamTrait},
    FromSample, Sample, SampleFormat, SizedSample,
};
use tauri::{AppHandle, Emitter};
use uuid::Uuid;

use super::{
    native_boundary::{BoundedNativeAudioQueue, LinearMonoResampler, NativeAudioChunk},
    parakeet::ParakeetTranscriber,
    AudioEndpointKind, AudioSourceHealth, BoundedAudioRing, CallCaptureDevice, CallCaptureRuntime,
    CallCaptureSourceState, FinalizedSegment, FinalizedSegmentSink, LocalAudioPipeline,
    RawAudioFrame, StopReason, CALL_TRANSCRIPTION_SAMPLE_RATE,
};

const NATIVE_QUEUE_CAPACITY: usize = 64;
const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(20);
const VAD_FRAME_SAMPLES: usize = 256;
const SILENCE_FLUSH_FRAMES: usize = 19;
const MAX_SPEECH_SAMPLES: usize = CALL_TRANSCRIPTION_SAMPLE_RATE as usize * 30;

const FAILURE_NONE: u8 = 0;
const FAILURE_MICROPHONE: u8 = 1;
const FAILURE_OUTPUT: u8 = 2;
const FAILURE_TRANSCRIBER: u8 = 3;

/// Enumerate exact, stable CPAL/WASAPI identifiers. Human-readable labels are
/// display-only and are never used to reopen a selected endpoint.
pub(super) fn list_devices() -> Result<Vec<CallCaptureDevice>, String> {
    let host = cpal::default_host();
    let default_microphone_id = host
        .default_input_device()
        .and_then(|device| device.id().ok())
        .map(|id| id.to_string());
    let default_output_id = host
        .default_output_device()
        .and_then(|device| device.id().ok())
        .map(|id| id.to_string());

    let mut devices = Vec::new();
    for device in host
        .input_devices()
        .map_err(|_| "Windows microphone endpoint enumeration failed".to_string())?
    {
        devices.push(map_device(
            device,
            AudioEndpointKind::Microphone,
            default_microphone_id.as_deref(),
        )?);
    }
    for device in host
        .output_devices()
        .map_err(|_| "Windows output endpoint enumeration failed".to_string())?
    {
        devices.push(map_device(
            device,
            AudioEndpointKind::Output,
            default_output_id.as_deref(),
        )?);
    }
    Ok(devices)
}

fn map_device(
    device: cpal::Device,
    kind: AudioEndpointKind,
    default_id: Option<&str>,
) -> Result<CallCaptureDevice, String> {
    let id = device
        .id()
        .map_err(|_| "Windows audio endpoint has no stable identifier".to_string())?
        .to_string();
    let label = device
        .description()
        .map_err(|_| "Windows audio endpoint has no display label".to_string())?
        .name()
        .to_owned();
    let config = match kind {
        AudioEndpointKind::Microphone => device.default_input_config(),
        AudioEndpointKind::Output => device.default_output_config(),
    }
    .map_err(|_| "Windows audio endpoint has no usable shared-mode format".to_string())?;

    Ok(CallCaptureDevice {
        schema_version: 1,
        is_default: default_id == Some(id.as_str()),
        id,
        label,
        kind,
        sample_rate_hz: config.sample_rate(),
        channels: config.channels(),
    })
}

/// Start separate microphone and selected-output WASAPI input streams. CPAL's
/// mature WASAPI backend sets `AUDCLNT_STREAMFLAGS_LOOPBACK` when an input
/// stream is opened on an output endpoint; Buzz adds no FFI or `unsafe` code.
pub(super) fn start(
    call_id: Uuid,
    microphone: &CallCaptureDevice,
    output: &CallCaptureDevice,
    app: AppHandle,
    finalized_tx: SyncSender<FinalizedSegment>,
) -> Result<Box<dyn CallCaptureRuntime>, String> {
    let model_dir = crate::huddle::models::stt_model_dir()
        .ok_or_else(|| "local Parakeet model is not ready".to_string())?;
    let host = cpal::default_host();
    let microphone_device = exact_device(&host, microphone, AudioEndpointKind::Microphone)?;
    let output_device = exact_device(&host, output, AudioEndpointKind::Output)?;
    let microphone_config = microphone_device
        .default_input_config()
        .map_err(|_| "selected microphone has no usable shared-mode format".to_string())?;
    let output_config = output_device
        .default_output_config()
        .map_err(|_| "selected output has no usable shared-mode format".to_string())?;
    let microphone_rate_hz = microphone_config.sample_rate();
    let output_rate_hz = output_config.sample_rate();
    let session_started = std::time::Instant::now();

    let (queue, receiver, dropped_chunks) = BoundedNativeAudioQueue::new(NATIVE_QUEUE_CAPACITY)?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let failure = Arc::new(AtomicU8::new(FAILURE_NONE));
    let microphone_level = Arc::new(AtomicU8::new(0));
    let output_level = Arc::new(AtomicU8::new(0));
    let (init_tx, init_rx) = mpsc::sync_channel(1);
    let thread_shutdown = Arc::clone(&shutdown);
    let thread_failure = Arc::clone(&failure);
    let worker = thread::Builder::new()
        .name("core-call-transcription".into())
        .spawn(move || {
            let transcriber = match ParakeetTranscriber::initialize(&model_dir) {
                Ok(transcriber) => {
                    let _ = init_tx.send(Ok(()));
                    transcriber
                }
                Err(error) => {
                    let _ = init_tx.send(Err(error));
                    return;
                }
            };
            let sink = NativeFinalizedSink { app, finalized_tx };
            let mut pipeline =
                match LocalAudioPipeline::new(call_id, transcriber, sink, MAX_SPEECH_SAMPLES) {
                    Ok(pipeline) => pipeline,
                    Err(_) => {
                        set_failure(&thread_failure, FAILURE_TRANSCRIBER);
                        return;
                    }
                };
            let result = run_worker(
                receiver,
                microphone_rate_hz,
                output_rate_hz,
                session_started,
                &thread_shutdown,
                &thread_failure,
                &mut pipeline,
            );
            pipeline.stop_and_scrub();
            if result.is_err() {
                set_failure(&thread_failure, FAILURE_TRANSCRIBER);
            }
        })
        .map_err(|_| "call transcription worker could not start".to_string())?;

    match init_rx.recv_timeout(Duration::from_secs(15)) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            shutdown.store(true, Ordering::Release);
            drop(queue);
            let _ = worker.join();
            return Err(error);
        }
        Err(_) => {
            shutdown.store(true, Ordering::Release);
            drop(queue);
            let _ = worker.join();
            return Err("local Parakeet initialization timed out".into());
        }
    }

    let microphone_stream = match build_capture_stream(
        &microphone_device,
        microphone_config,
        AudioEndpointKind::Microphone,
        queue.clone(),
        Arc::clone(&failure),
        Arc::clone(&microphone_level),
    ) {
        Ok(stream) => stream,
        Err(error) => {
            shutdown.store(true, Ordering::Release);
            drop(queue);
            let _ = worker.join();
            return Err(error);
        }
    };
    let output_stream = match build_capture_stream(
        &output_device,
        output_config,
        AudioEndpointKind::Output,
        queue,
        Arc::clone(&failure),
        Arc::clone(&output_level),
    ) {
        Ok(stream) => stream,
        Err(error) => {
            shutdown.store(true, Ordering::Release);
            let _ = microphone_stream.pause();
            drop(microphone_stream);
            let _ = worker.join();
            return Err(error);
        }
    };
    if microphone_stream.play().is_err() {
        shutdown.store(true, Ordering::Release);
        drop(microphone_stream);
        drop(output_stream);
        let _ = worker.join();
        return Err("selected microphone could not start".into());
    }
    if output_stream.play().is_err() {
        let _ = microphone_stream.pause();
        shutdown.store(true, Ordering::Release);
        let _ = worker.join();
        return Err("selected output loopback could not start".into());
    }

    Ok(Box::new(WindowsCallCaptureRuntime {
        microphone_stream: Some(microphone_stream),
        output_stream: Some(output_stream),
        shutdown,
        failure,
        dropped_chunks,
        microphone_level,
        output_level,
        worker: Some(worker),
    }))
}

fn exact_device(
    host: &cpal::Host,
    selected: &CallCaptureDevice,
    expected_kind: AudioEndpointKind,
) -> Result<cpal::Device, String> {
    if selected.kind != expected_kind {
        return Err("selected Windows audio endpoint has the wrong source kind".into());
    }
    let id = cpal::DeviceId::from_str(&selected.id)
        .map_err(|_| "selected Windows audio endpoint identifier is invalid".to_string())?;
    let device = host
        .device_by_id(&id)
        .ok_or_else(|| "selected Windows audio endpoint is unavailable".to_string())?;
    let direction_matches = match expected_kind {
        AudioEndpointKind::Microphone => device.supports_input(),
        AudioEndpointKind::Output => device.supports_output(),
    };
    if !direction_matches {
        return Err("selected Windows audio endpoint direction changed".into());
    }
    Ok(device)
}

fn build_capture_stream(
    device: &cpal::Device,
    config: cpal::SupportedStreamConfig,
    source: AudioEndpointKind,
    queue: BoundedNativeAudioQueue,
    failure: Arc<AtomicU8>,
    level: Arc<AtomicU8>,
) -> Result<cpal::Stream, String> {
    match config.sample_format() {
        SampleFormat::I8 => build_typed_stream::<i8>(device, config, source, queue, failure, level),
        SampleFormat::I16 => {
            build_typed_stream::<i16>(device, config, source, queue, failure, level)
        }
        SampleFormat::I24 => {
            build_typed_stream::<cpal::I24>(device, config, source, queue, failure, level)
        }
        SampleFormat::I32 => {
            build_typed_stream::<i32>(device, config, source, queue, failure, level)
        }
        SampleFormat::I64 => {
            build_typed_stream::<i64>(device, config, source, queue, failure, level)
        }
        SampleFormat::U8 => build_typed_stream::<u8>(device, config, source, queue, failure, level),
        SampleFormat::U16 => {
            build_typed_stream::<u16>(device, config, source, queue, failure, level)
        }
        SampleFormat::U24 => {
            build_typed_stream::<cpal::U24>(device, config, source, queue, failure, level)
        }
        SampleFormat::U32 => {
            build_typed_stream::<u32>(device, config, source, queue, failure, level)
        }
        SampleFormat::U64 => {
            build_typed_stream::<u64>(device, config, source, queue, failure, level)
        }
        SampleFormat::F32 => {
            build_typed_stream::<f32>(device, config, source, queue, failure, level)
        }
        SampleFormat::F64 => {
            build_typed_stream::<f64>(device, config, source, queue, failure, level)
        }
        _ => Err("selected Windows audio endpoint uses an unsupported DSD format".into()),
    }
}

fn build_typed_stream<T>(
    device: &cpal::Device,
    config: cpal::SupportedStreamConfig,
    source: AudioEndpointKind,
    queue: BoundedNativeAudioQueue,
    failure: Arc<AtomicU8>,
    level: Arc<AtomicU8>,
) -> Result<cpal::Stream, String>
where
    T: Sample + SizedSample + Copy,
    f32: FromSample<T>,
{
    let channels = config.channels();
    let sample_rate_hz = config.sample_rate();
    let stream_config = config.config();
    let callback_failure = Arc::clone(&failure);
    let error_failure = Arc::clone(&failure);
    let device_failure = match source {
        AudioEndpointKind::Microphone => FAILURE_MICROPHONE,
        AudioEndpointKind::Output => FAILURE_OUTPUT,
    };
    device
        .build_input_stream::<T, _, _>(
            &stream_config,
            move |interleaved, _| {
                let chunk = NativeAudioChunk::from_interleaved(
                    source,
                    interleaved,
                    channels,
                    sample_rate_hz,
                    |sample| f32::from_sample(*sample),
                );
                match chunk {
                    Ok(chunk) => {
                        level.store(chunk.level_percent(), Ordering::Release);
                        if queue.try_push(chunk).is_err() {
                            set_failure(&callback_failure, FAILURE_TRANSCRIBER);
                        }
                    }
                    Err(_) => set_failure(&callback_failure, device_failure),
                }
            },
            move |_| set_failure(&error_failure, device_failure),
            None,
        )
        .map_err(|_| "selected Windows audio endpoint could not open for capture".to_string())
}

fn set_failure(failure: &AtomicU8, code: u8) {
    let _ = failure.compare_exchange(FAILURE_NONE, code, Ordering::AcqRel, Ordering::Acquire);
}

struct WindowsCallCaptureRuntime {
    microphone_stream: Option<cpal::Stream>,
    output_stream: Option<cpal::Stream>,
    shutdown: Arc<AtomicBool>,
    failure: Arc<AtomicU8>,
    dropped_chunks: Arc<std::sync::atomic::AtomicU64>,
    microphone_level: Arc<AtomicU8>,
    output_level: Arc<AtomicU8>,
    worker: Option<thread::JoinHandle<()>>,
}

impl CallCaptureRuntime for WindowsCallCaptureRuntime {
    fn stop(&mut self) -> Result<(), String> {
        self.shutdown.store(true, Ordering::Release);
        let microphone_result = self.microphone_stream.take().map(|stream| stream.pause());
        let output_result = self.output_stream.take().map(|stream| stream.pause());
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                return Err("call transcription worker terminated unexpectedly".into());
            }
        }
        if microphone_result.is_some_and(|result| result.is_err())
            || output_result.is_some_and(|result| result.is_err())
        {
            return Err("one or more call capture streams could not stop cleanly".into());
        }
        Ok(())
    }

    fn failure_reason(&self) -> Option<StopReason> {
        match self.failure.load(Ordering::Acquire) {
            FAILURE_NONE => None,
            FAILURE_MICROPHONE | FAILURE_OUTPUT => Some(StopReason::DeviceFailure),
            _ => Some(StopReason::TranscriberFailure),
        }
    }

    fn source_states(&self) -> (CallCaptureSourceState, CallCaptureSourceState) {
        let failure = self.failure.load(Ordering::Acquire);
        let lagged = self.dropped_chunks.load(Ordering::Acquire) > 0;
        let state = |level: &AtomicU8, unavailable| CallCaptureSourceState {
            health: if unavailable {
                AudioSourceHealth::Unavailable
            } else if lagged {
                AudioSourceHealth::Degraded
            } else {
                AudioSourceHealth::Healthy
            },
            level_percent: level.load(Ordering::Acquire).min(100),
        };
        (
            state(&self.microphone_level, failure == FAILURE_MICROPHONE),
            state(&self.output_level, failure == FAILURE_OUTPUT),
        )
    }
}

impl Drop for WindowsCallCaptureRuntime {
    fn drop(&mut self) {
        let _ = self.stop();
        let _ = self.dropped_chunks.load(Ordering::Acquire);
    }
}

struct NativeFinalizedSink {
    app: AppHandle,
    finalized_tx: SyncSender<FinalizedSegment>,
}

impl FinalizedSegmentSink for NativeFinalizedSink {
    fn publish(&mut self, segment: FinalizedSegment) -> Result<(), String> {
        self.app
            .emit("call-capture-finalized-transcript", &segment)
            .map_err(|_| "local finalized transcript event could not be emitted".to_string())?;
        match self.finalized_tx.try_send(segment) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                Err("private finalized transcript transport is backpressured".into())
            }
            Err(TrySendError::Disconnected(_)) => {
                Err("private finalized transcript transport is unavailable".into())
            }
        }
    }
}

fn run_worker<T, S>(
    receiver: Receiver<NativeAudioChunk>,
    microphone_rate_hz: u32,
    output_rate_hz: u32,
    session_started: std::time::Instant,
    shutdown: &AtomicBool,
    failure: &AtomicU8,
    pipeline: &mut LocalAudioPipeline<T, S>,
) -> Result<(), String>
where
    T: super::LocalTranscriber,
    S: FinalizedSegmentSink,
{
    let mut microphone_resampler =
        LinearMonoResampler::new(microphone_rate_hz, CALL_TRANSCRIPTION_SAMPLE_RATE)?;
    let mut output_resampler =
        LinearMonoResampler::new(output_rate_hz, CALL_TRANSCRIPTION_SAMPLE_RATE)?;
    let mut microphone_vad = SpeechAccumulator::new(AudioEndpointKind::Microphone)?;
    let mut output_vad = SpeechAccumulator::new(AudioEndpointKind::Output)?;

    while !shutdown.load(Ordering::Acquire) {
        if failure.load(Ordering::Acquire) != FAILURE_NONE {
            break;
        }
        let chunk = match receiver.recv_timeout(WORKER_POLL_INTERVAL) {
            Ok(chunk) => chunk,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
                return Err("native audio callback queue disconnected".into());
            }
        };
        match chunk.source() {
            AudioEndpointKind::Microphone => process_chunk(
                &chunk,
                &mut microphone_resampler,
                &mut microphone_vad,
                pipeline,
                &session_started,
            )?,
            AudioEndpointKind::Output => process_chunk(
                &chunk,
                &mut output_resampler,
                &mut output_vad,
                pipeline,
                &session_started,
            )?,
        }
    }
    microphone_resampler.scrub();
    output_resampler.scrub();
    Ok(())
}

fn process_chunk<T, S>(
    chunk: &NativeAudioChunk,
    resampler: &mut LinearMonoResampler,
    vad: &mut SpeechAccumulator,
    pipeline: &mut LocalAudioPipeline<T, S>,
    session_started: &std::time::Instant,
) -> Result<(), String>
where
    T: super::LocalTranscriber,
    S: FinalizedSegmentSink,
{
    let mut resampled = SensitiveMonoBuffer::default();
    resampler.process(
        chunk.samples_for_local_transcription(),
        &mut resampled.samples,
    )?;
    for frame in vad.push(&resampled)? {
        pipeline.push_frame_with_clock(frame, || {
            u64::try_from(session_started.elapsed().as_millis()).unwrap_or(u64::MAX)
        })?;
    }
    Ok(())
}

#[derive(Default)]
struct SensitiveMonoBuffer {
    samples: Vec<f32>,
}

impl Deref for SensitiveMonoBuffer {
    type Target = [f32];

    fn deref(&self) -> &Self::Target {
        &self.samples
    }
}

impl Drop for SensitiveMonoBuffer {
    fn drop(&mut self) {
        self.samples.fill(0.0);
        compiler_fence(Ordering::SeqCst);
    }
}

struct SpeechAccumulator {
    source: AudioEndpointKind,
    detector: Detector<DefaultPredictor>,
    frame: [f32; VAD_FRAME_SAMPLES],
    frame_len: usize,
    speech: BoundedAudioRing,
    speech_started_at_sample: Option<u64>,
    total_samples: u64,
    silence_frames: usize,
}

impl SpeechAccumulator {
    fn new(source: AudioEndpointKind) -> Result<Self, String> {
        Ok(Self {
            source,
            detector: Detector::new(DefaultPredictor::new()),
            frame: [0.0; VAD_FRAME_SAMPLES],
            frame_len: 0,
            speech: BoundedAudioRing::new(MAX_SPEECH_SAMPLES)?,
            speech_started_at_sample: None,
            total_samples: 0,
            silence_frames: 0,
        })
    }

    fn push(&mut self, samples: &[f32]) -> Result<Vec<RawAudioFrame>, String> {
        let mut finalized = Vec::new();
        for &sample in samples {
            self.frame[self.frame_len] = sample.clamp(-1.0, 1.0);
            self.frame_len += 1;
            if self.frame_len == VAD_FRAME_SAMPLES {
                if let Some(frame) = self.process_full_frame()? {
                    finalized.push(frame);
                }
            }
        }
        Ok(finalized)
    }

    fn process_full_frame(&mut self) -> Result<Option<RawAudioFrame>, String> {
        let probability = self.detector.predict_f32(&self.frame);
        let is_speech = probability > 0.5;
        let frame_start = self.total_samples;
        self.total_samples = self
            .total_samples
            .checked_add(VAD_FRAME_SAMPLES as u64)
            .ok_or_else(|| "call audio timeline exhausted".to_string())?;
        if is_speech {
            if self.speech_started_at_sample.is_none() {
                self.speech_started_at_sample = Some(frame_start);
            }
            self.silence_frames = 0;
            self.speech.push(&self.frame)?;
        } else if self.speech_started_at_sample.is_some() {
            self.speech.push(&self.frame)?;
            self.silence_frames += 1;
        }
        self.frame.fill(0.0);
        self.frame_len = 0;
        if self.silence_frames >= SILENCE_FLUSH_FRAMES || self.speech.len() >= MAX_SPEECH_SAMPLES {
            return self.flush();
        }
        Ok(None)
    }

    fn flush(&mut self) -> Result<Option<RawAudioFrame>, String> {
        let Some(start_sample) = self.speech_started_at_sample.take() else {
            self.speech.clear();
            self.silence_frames = 0;
            return Ok(None);
        };
        if self.speech.is_empty() {
            self.silence_frames = 0;
            return Ok(None);
        }
        let samples = self.speech.copy_samples();
        self.speech.clear();
        self.silence_frames = 0;
        let started_at_ms =
            start_sample.saturating_mul(1_000) / u64::from(CALL_TRANSCRIPTION_SAMPLE_RATE);
        let ended_at_ms =
            self.total_samples.saturating_mul(1_000) / u64::from(CALL_TRANSCRIPTION_SAMPLE_RATE);
        RawAudioFrame::new(
            self.source,
            samples,
            CALL_TRANSCRIPTION_SAMPLE_RATE,
            started_at_ms,
            ended_at_ms,
        )
        .map(Some)
    }
}

impl Drop for SpeechAccumulator {
    fn drop(&mut self) {
        self.frame.fill(0.0);
        self.speech.clear();
    }
}

pub(super) const FINALIZED_TRANSPORT_QUEUE_CAPACITY: usize = 64;
