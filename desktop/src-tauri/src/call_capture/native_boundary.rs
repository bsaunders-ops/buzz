use std::sync::{
    atomic::{compiler_fence, AtomicU64, Ordering},
    mpsc::{self, Receiver, SyncSender, TrySendError},
    Arc,
};

use super::AudioEndpointKind;

const MIN_NATIVE_SAMPLE_RATE: u32 = 8_000;
const MAX_NATIVE_SAMPLE_RATE: u32 = 384_000;
const MAX_NATIVE_CHANNELS: u16 = 32;
const MAX_CALLBACK_SECONDS: usize = 2;

/// A single callback-owned mono audio chunk. It has no serialization, filesystem,
/// network, logging, or clone boundary and scrubs its allocation on every drop path.
pub(super) struct NativeAudioChunk {
    source: AudioEndpointKind,
    sample_rate_hz: u32,
    samples: Vec<f32>,
}

impl NativeAudioChunk {
    pub(super) fn from_interleaved_f32(
        source: AudioEndpointKind,
        interleaved: &[f32],
        channels: u16,
        sample_rate_hz: u32,
    ) -> Result<Self, String> {
        Self::from_interleaved(source, interleaved, channels, sample_rate_hz, |sample| {
            *sample
        })
    }

    pub(super) fn from_interleaved<T, F>(
        source: AudioEndpointKind,
        interleaved: &[T],
        channels: u16,
        sample_rate_hz: u32,
        normalize: F,
    ) -> Result<Self, String>
    where
        F: Fn(&T) -> f32,
    {
        let channel_count = usize::from(channels);
        if !(MIN_NATIVE_SAMPLE_RATE..=MAX_NATIVE_SAMPLE_RATE).contains(&sample_rate_hz)
            || channels == 0
            || channels > MAX_NATIVE_CHANNELS
            || interleaved.is_empty()
            || interleaved.len() % channel_count != 0
            || interleaved.len() / channel_count > sample_rate_hz as usize * MAX_CALLBACK_SECONDS
        {
            return Err("invalid or oversized native audio callback".into());
        }

        let mut samples = Vec::with_capacity(interleaved.len() / channel_count);
        for frame in interleaved.chunks_exact(channel_count) {
            let mut sum = 0.0f64;
            for sample in frame {
                let normalized = normalize(sample);
                if !normalized.is_finite() {
                    samples.fill(0.0);
                    compiler_fence(Ordering::SeqCst);
                    return Err("native audio callback contained a non-finite sample".into());
                }
                sum += f64::from(normalized.clamp(-1.0, 1.0));
            }
            samples.push((sum / f64::from(channels)) as f32);
        }

        Ok(Self {
            source,
            sample_rate_hz,
            samples,
        })
    }

    pub(super) const fn source(&self) -> AudioEndpointKind {
        self.source
    }

    pub(super) const fn sample_rate_hz(&self) -> u32 {
        self.sample_rate_hz
    }

    pub(super) fn samples_for_local_transcription(&self) -> &[f32] {
        &self.samples
    }

    pub(super) fn level_percent(&self) -> u8 {
        let peak = self
            .samples
            .iter()
            .fold(0.0f32, |current, sample| current.max(sample.abs()));
        (peak.clamp(0.0, 1.0) * 100.0).round() as u8
    }

    pub(super) fn scrub(&mut self) {
        self.samples.fill(0.0);
        compiler_fence(Ordering::SeqCst);
    }
}

impl Drop for NativeAudioChunk {
    fn drop(&mut self) {
        self.scrub();
    }
}

/// Non-blocking bounded handoff from real-time callbacks to the local worker.
pub(super) struct BoundedNativeAudioQueue {
    sender: SyncSender<NativeAudioChunk>,
    dropped_chunks: Arc<AtomicU64>,
}

impl Clone for BoundedNativeAudioQueue {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            dropped_chunks: Arc::clone(&self.dropped_chunks),
        }
    }
}

impl BoundedNativeAudioQueue {
    pub(super) fn new(
        capacity: usize,
    ) -> Result<(Self, Receiver<NativeAudioChunk>, Arc<AtomicU64>), String> {
        if capacity == 0 || capacity > 1_024 {
            return Err("native audio queue capacity must be in 1..=1024".into());
        }
        let (sender, receiver) = mpsc::sync_channel(capacity);
        let dropped_chunks = Arc::new(AtomicU64::new(0));
        Ok((
            Self {
                sender,
                dropped_chunks: Arc::clone(&dropped_chunks),
            },
            receiver,
            dropped_chunks,
        ))
    }

    /// A full callback queue drops and scrubs the newest chunk rather than
    /// blocking an operating-system audio thread.
    pub(super) fn try_push(&self, chunk: NativeAudioChunk) -> Result<(), String> {
        match self.sender.try_send(chunk) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(mut chunk)) => {
                chunk.scrub();
                self.dropped_chunks.fetch_add(1, Ordering::AcqRel);
                Ok(())
            }
            Err(TrySendError::Disconnected(mut chunk)) => {
                chunk.scrub();
                Err("local call transcription worker is unavailable".into())
            }
        }
    }
}

/// Small stateful linear resampler for callback-sized, mono speech chunks.
/// State spans chunks so there is no repeated boundary discontinuity.
pub(super) struct LinearMonoResampler {
    input_rate_hz: u32,
    output_rate_hz: u32,
    consumed_input_samples: u64,
    next_output_numerator: u128,
    previous_sample: Option<f32>,
}

impl LinearMonoResampler {
    pub(super) fn new(input_rate_hz: u32, output_rate_hz: u32) -> Result<Self, String> {
        if !(MIN_NATIVE_SAMPLE_RATE..=MAX_NATIVE_SAMPLE_RATE).contains(&input_rate_hz)
            || !(MIN_NATIVE_SAMPLE_RATE..=MAX_NATIVE_SAMPLE_RATE).contains(&output_rate_hz)
        {
            return Err("unsupported native audio resampling rate".into());
        }
        Ok(Self {
            input_rate_hz,
            output_rate_hz,
            consumed_input_samples: 0,
            next_output_numerator: 0,
            previous_sample: None,
        })
    }

    pub(super) fn process(&mut self, input: &[f32], output: &mut Vec<f32>) -> Result<(), String> {
        if input.is_empty() {
            return Ok(());
        }
        if input.len() > self.input_rate_hz as usize * MAX_CALLBACK_SECONDS
            || input.iter().any(|sample| !sample.is_finite())
        {
            return Err("invalid or oversized mono resampler input".into());
        }

        let first_index = u128::from(self.consumed_input_samples);
        let end_index = first_index
            .checked_add(input.len() as u128)
            .ok_or_else(|| "native audio timeline exhausted".to_string())?;
        let denominator = u128::from(self.output_rate_hz);
        while self.next_output_numerator / denominator < end_index {
            let left_index = self.next_output_numerator / denominator;
            let fraction = self.next_output_numerator % denominator;
            let right_index = left_index + u128::from(fraction != 0);
            if right_index >= end_index {
                break;
            }

            let left = self.sample_at(left_index, first_index, input)?;
            let right = self.sample_at(right_index, first_index, input)?;
            let weight = fraction as f64 / denominator as f64;
            output.push((f64::from(left) + (f64::from(right) - f64::from(left)) * weight) as f32);
            self.next_output_numerator = self
                .next_output_numerator
                .checked_add(u128::from(self.input_rate_hz))
                .ok_or_else(|| "native audio resampling timeline exhausted".to_string())?;
        }

        self.consumed_input_samples = self
            .consumed_input_samples
            .checked_add(input.len() as u64)
            .ok_or_else(|| "native audio timeline exhausted".to_string())?;
        self.previous_sample = input.last().copied();
        Ok(())
    }

    fn sample_at(&self, index: u128, first_index: u128, input: &[f32]) -> Result<f32, String> {
        if index < first_index {
            if index + 1 == first_index {
                return self
                    .previous_sample
                    .ok_or_else(|| "native audio resampler lost boundary state".to_string());
            }
            return Err("native audio resampler requested stale input".into());
        }
        let offset = usize::try_from(index - first_index)
            .map_err(|_| "native audio resampler index overflow".to_string())?;
        input
            .get(offset)
            .copied()
            .ok_or_else(|| "native audio resampler requested unavailable input".into())
    }

    pub(super) fn scrub(&mut self) {
        if let Some(previous) = &mut self.previous_sample {
            *previous = 0.0;
        }
        compiler_fence(Ordering::SeqCst);
        self.previous_sample = None;
        self.consumed_input_samples = 0;
        self.next_output_numerator = 0;
    }
}

impl Drop for LinearMonoResampler {
    fn drop(&mut self) {
        self.scrub();
    }
}
