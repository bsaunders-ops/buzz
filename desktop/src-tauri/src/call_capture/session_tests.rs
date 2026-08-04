use super::{
    FinalizedSegment, LiveSessionAccumulator, SegmentIngestOutcome, SequencedEphemeral,
    SequencedEphemeralBuffer, TranscriptSpeaker,
};
use uuid::Uuid;

fn segment(call_id: Uuid, sequence: u64, text: &str) -> FinalizedSegment {
    FinalizedSegment {
        schema_version: 1,
        segment_id: Uuid::new_v4(),
        call_id,
        sequence,
        speaker: TranscriptSpeaker::SelfSpeaker,
        text: text.into(),
        started_at_ms: sequence * 100,
        ended_at_ms: sequence * 100 + 50,
        confidence: 90,
        model_version: "parakeet-v1".into(),
    }
}

#[test]
fn live_context_deduplicates_and_releases_out_of_order_segments_contiguously() {
    let call_id = Uuid::new_v4();
    let mut context = LiveSessionAccumulator::new(call_id, 8, 1_024, 2).unwrap();

    assert_eq!(
        context.ingest(segment(call_id, 2, "second")).unwrap(),
        SegmentIngestOutcome::BufferedOutOfOrder
    );
    assert_eq!(context.segment_count(), 0);

    let accepted = context.ingest(segment(call_id, 1, "first")).unwrap();
    assert_eq!(accepted, SegmentIngestOutcome::Accepted { contiguous: 2 });
    assert_eq!(context.transcript_text(), "first\nsecond");

    assert_eq!(
        context.ingest(segment(call_id, 2, "duplicate")).unwrap(),
        SegmentIngestOutcome::Duplicate
    );
    assert_eq!(context.transcript_text(), "first\nsecond");
}

#[test]
fn live_context_rejects_wrong_session_and_bounds_gaps_and_retained_text() {
    let call_id = Uuid::new_v4();
    let mut context = LiveSessionAccumulator::new(call_id, 2, 10, 1).unwrap();

    assert!(context
        .ingest(segment(Uuid::new_v4(), 1, "foreign"))
        .is_err());
    assert_eq!(
        context.ingest(segment(call_id, 3, "gap-three")).unwrap(),
        SegmentIngestOutcome::BufferedOutOfOrder
    );
    assert_eq!(
        context.ingest(segment(call_id, 4, "gap-four")).unwrap(),
        SegmentIngestOutcome::DroppedOutOfOrder
    );

    let mut bounded = LiveSessionAccumulator::new(call_id, 2, 10, 1).unwrap();
    bounded.ingest(segment(call_id, 1, "12345")).unwrap();
    bounded.ingest(segment(call_id, 2, "67890")).unwrap();
    bounded.ingest(segment(call_id, 3, "abcde")).unwrap();
    assert_eq!(bounded.segment_count(), 1);
    assert_eq!(bounded.transcript_text(), "abcde");
    assert_eq!(bounded.evicted_segments(), 2);
}

#[test]
fn ephemeral_suggestions_are_session_bound_ordered_and_purged_on_end() {
    let call_id = Uuid::new_v4();
    let mut buffer = SequencedEphemeralBuffer::new(call_id, 2, 1).unwrap();

    assert_eq!(
        buffer
            .ingest(SequencedEphemeral {
                call_id,
                sequence: 2,
                value: "second".to_string(),
            })
            .unwrap(),
        SegmentIngestOutcome::BufferedOutOfOrder
    );
    assert_eq!(
        buffer
            .ingest(SequencedEphemeral {
                call_id,
                sequence: 1,
                value: "first".to_string(),
            })
            .unwrap(),
        SegmentIngestOutcome::Accepted { contiguous: 2 }
    );
    assert_eq!(buffer.values(), vec!["first", "second"]);
    assert_eq!(
        buffer
            .ingest(SequencedEphemeral {
                call_id,
                sequence: 2,
                value: "replay".to_string(),
            })
            .unwrap(),
        SegmentIngestOutcome::Duplicate
    );
    assert!(buffer
        .ingest(SequencedEphemeral {
            call_id: Uuid::new_v4(),
            sequence: 3,
            value: "foreign".to_string(),
        })
        .is_err());

    buffer.purge();
    assert!(buffer.values().is_empty());
    assert_eq!(buffer.pending_count(), 0);
}
