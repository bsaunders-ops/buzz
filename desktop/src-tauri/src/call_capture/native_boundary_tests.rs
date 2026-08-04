use std::sync::atomic::Ordering;

use super::{
    native_boundary::{BoundedNativeAudioQueue, LinearMonoResampler, NativeAudioChunk},
    AudioEndpointKind,
};

#[test]
fn callback_downmix_is_bounded_mono_finite_and_locally_scrubbable() {
    let mut chunk = NativeAudioChunk::from_interleaved_f32(
        AudioEndpointKind::Output,
        &[1.0, -1.0, 0.5, 0.5],
        2,
        48_000,
    )
    .unwrap();

    assert_eq!(chunk.source(), AudioEndpointKind::Output);
    assert_eq!(chunk.sample_rate_hz(), 48_000);
    assert_eq!(chunk.samples_for_local_transcription(), &[0.0, 0.5]);
    assert_eq!(chunk.level_percent(), 50);
    chunk.scrub();
    assert_eq!(chunk.samples_for_local_transcription(), &[0.0, 0.0]);

    assert!(NativeAudioChunk::from_interleaved_f32(
        AudioEndpointKind::Microphone,
        &[f32::NAN],
        1,
        48_000,
    )
    .is_err());
}

#[test]
fn callback_queue_is_bounded_and_counts_drops_without_blocking() {
    let (queue, receiver, dropped) = BoundedNativeAudioQueue::new(1).unwrap();
    queue
        .try_push(
            NativeAudioChunk::from_interleaved_f32(
                AudioEndpointKind::Microphone,
                &[0.25],
                1,
                48_000,
            )
            .unwrap(),
        )
        .unwrap();
    assert!(queue
        .try_push(
            NativeAudioChunk::from_interleaved_f32(AudioEndpointKind::Output, &[0.5], 1, 48_000,)
                .unwrap(),
        )
        .is_ok());

    assert_eq!(dropped.load(Ordering::Acquire), 1);
    assert_eq!(
        receiver.try_recv().unwrap().source(),
        AudioEndpointKind::Microphone
    );
}

#[test]
fn streaming_resampler_converts_to_parakeet_rate_across_chunk_boundaries() {
    let mut resampler = LinearMonoResampler::new(48_000, 16_000).unwrap();
    let mut output = Vec::new();
    resampler.process(&vec![0.25; 481], &mut output).unwrap();
    resampler.process(&vec![0.25; 479], &mut output).unwrap();

    assert!((319..=321).contains(&output.len()), "len={}", output.len());
    assert!(output.iter().all(|sample| sample.is_finite()));
    assert!(output
        .iter()
        .all(|sample| (*sample - 0.25).abs() < 0.000_001));

    output.fill(0.0);
    resampler.scrub();
}
