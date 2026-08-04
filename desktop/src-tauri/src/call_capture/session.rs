use std::collections::{BTreeMap, VecDeque};

use uuid::Uuid;

use super::FinalizedSegment;

const MAX_SESSION_SEGMENTS: usize = 2_048;
const MAX_SESSION_TEXT_BYTES: usize = 512 * 1_024;
const MAX_PENDING_GAP: usize = 32;

/// Result of a monotonic, per-session ingest operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SegmentIngestOutcome {
    Accepted { contiguous: usize },
    Duplicate,
    BufferedOutOfOrder,
    DroppedOutOfOrder,
}

/// One bounded in-memory transcript context. It orders before forwarding so a
/// delayed callback cannot create one model turn or recovery row per fragment.
pub struct LiveSessionAccumulator {
    call_id: Uuid,
    retained: VecDeque<FinalizedSegment>,
    pending: BTreeMap<u64, FinalizedSegment>,
    next_sequence: u64,
    max_segments: usize,
    max_text_bytes: usize,
    max_pending: usize,
    retained_text_bytes: usize,
    evicted_segments: u64,
}

impl LiveSessionAccumulator {
    pub fn production(call_id: Uuid) -> Self {
        Self::new(
            call_id,
            MAX_SESSION_SEGMENTS,
            MAX_SESSION_TEXT_BYTES,
            MAX_PENDING_GAP,
        )
        .unwrap_or_else(|_| unreachable!("fixed production bounds are valid"))
    }

    pub fn new(
        call_id: Uuid,
        max_segments: usize,
        max_text_bytes: usize,
        max_pending: usize,
    ) -> Result<Self, String> {
        if call_id.get_version_num() != 4
            || max_segments == 0
            || max_segments > MAX_SESSION_SEGMENTS
            || max_text_bytes == 0
            || max_text_bytes > MAX_SESSION_TEXT_BYTES
            || max_pending == 0
            || max_pending > MAX_PENDING_GAP
        {
            return Err("invalid bounded live-session configuration".into());
        }
        Ok(Self {
            call_id,
            retained: VecDeque::with_capacity(max_segments),
            pending: BTreeMap::new(),
            next_sequence: 1,
            max_segments,
            max_text_bytes,
            max_pending,
            retained_text_bytes: 0,
            evicted_segments: 0,
        })
    }

    pub fn ingest(&mut self, segment: FinalizedSegment) -> Result<SegmentIngestOutcome, String> {
        self.validate(&segment)?;
        if segment.sequence < self.next_sequence || self.pending.contains_key(&segment.sequence) {
            return Ok(SegmentIngestOutcome::Duplicate);
        }
        if segment.sequence > self.next_sequence {
            if self.pending.len() == self.max_pending {
                return Ok(SegmentIngestOutcome::DroppedOutOfOrder);
            }
            self.pending.insert(segment.sequence, segment);
            return Ok(SegmentIngestOutcome::BufferedOutOfOrder);
        }

        let mut contiguous = 1;
        self.append(segment);
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| "call transcript sequence exhausted".to_string())?;
        while let Some(segment) = self.pending.remove(&self.next_sequence) {
            self.append(segment);
            self.next_sequence = self
                .next_sequence
                .checked_add(1)
                .ok_or_else(|| "call transcript sequence exhausted".to_string())?;
            contiguous += 1;
        }
        Ok(SegmentIngestOutcome::Accepted { contiguous })
    }

    pub fn segment_count(&self) -> usize {
        self.retained.len()
    }

    pub fn transcript_text(&self) -> String {
        self.retained
            .iter()
            .map(|segment| segment.text.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn segments(&self) -> impl Iterator<Item = &FinalizedSegment> {
        self.retained.iter()
    }

    pub const fn evicted_segments(&self) -> u64 {
        self.evicted_segments
    }

    pub fn purge(&mut self) {
        for segment in &mut self.retained {
            segment.text.clear();
        }
        for segment in self.pending.values_mut() {
            segment.text.clear();
        }
        self.retained.clear();
        self.pending.clear();
        self.retained_text_bytes = 0;
    }

    fn validate(&self, segment: &FinalizedSegment) -> Result<(), String> {
        if segment.schema_version != 1
            || segment.segment_id.get_version_num() != 4
            || segment.call_id != self.call_id
            || segment.sequence == 0
            || segment.text.trim().is_empty()
            || segment.text.len() > self.max_text_bytes
            || segment.text.chars().any(char::is_control)
            || segment.ended_at_ms < segment.started_at_ms
            || segment.confidence > 100
            || segment.model_version.trim().is_empty()
        {
            return Err("invalid finalized segment for live session".into());
        }
        Ok(())
    }

    fn append(&mut self, segment: FinalizedSegment) {
        let separator = usize::from(!self.retained.is_empty());
        self.retained_text_bytes = self
            .retained_text_bytes
            .saturating_add(separator + segment.text.len());
        self.retained.push_back(segment);
        while self.retained.len() > self.max_segments
            || self.retained_text_bytes > self.max_text_bytes
        {
            if let Some(mut removed) = self.retained.pop_front() {
                self.retained_text_bytes =
                    self.retained_text_bytes.saturating_sub(removed.text.len());
                if !self.retained.is_empty() {
                    self.retained_text_bytes = self.retained_text_bytes.saturating_sub(1);
                }
                removed.text.clear();
                self.evicted_segments = self.evicted_segments.saturating_add(1);
            }
        }
    }
}

impl Drop for LiveSessionAccumulator {
    fn drop(&mut self) {
        self.purge();
    }
}

/// A session-bound value that is never serializable as a collection or exposed
/// to an archive/query API.
pub struct SequencedEphemeral<T> {
    pub call_id: Uuid,
    pub sequence: u64,
    pub value: T,
}

/// Bounded UI-only ordering buffer for decrypted kind-24822 suggestions.
pub struct SequencedEphemeralBuffer<T> {
    call_id: Uuid,
    retained: VecDeque<T>,
    pending: BTreeMap<u64, T>,
    next_sequence: u64,
    max_retained: usize,
    max_pending: usize,
}

impl<T: Clone> SequencedEphemeralBuffer<T> {
    pub fn new(call_id: Uuid, max_retained: usize, max_pending: usize) -> Result<Self, String> {
        if call_id.get_version_num() != 4
            || max_retained == 0
            || max_retained > 128
            || max_pending == 0
            || max_pending > MAX_PENDING_GAP
        {
            return Err("invalid ephemeral suggestion buffer bounds".into());
        }
        Ok(Self {
            call_id,
            retained: VecDeque::with_capacity(max_retained),
            pending: BTreeMap::new(),
            next_sequence: 1,
            max_retained,
            max_pending,
        })
    }

    pub fn ingest(
        &mut self,
        suggestion: SequencedEphemeral<T>,
    ) -> Result<SegmentIngestOutcome, String> {
        if suggestion.call_id != self.call_id || suggestion.sequence == 0 {
            return Err("ephemeral suggestion does not match the active session".into());
        }
        if suggestion.sequence < self.next_sequence
            || self.pending.contains_key(&suggestion.sequence)
        {
            return Ok(SegmentIngestOutcome::Duplicate);
        }
        if suggestion.sequence > self.next_sequence {
            if self.pending.len() == self.max_pending {
                return Ok(SegmentIngestOutcome::DroppedOutOfOrder);
            }
            self.pending.insert(suggestion.sequence, suggestion.value);
            return Ok(SegmentIngestOutcome::BufferedOutOfOrder);
        }

        let mut contiguous = 1;
        self.append(suggestion.value);
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| "copilot suggestion sequence exhausted".to_string())?;
        while let Some(value) = self.pending.remove(&self.next_sequence) {
            self.append(value);
            self.next_sequence = self
                .next_sequence
                .checked_add(1)
                .ok_or_else(|| "copilot suggestion sequence exhausted".to_string())?;
            contiguous += 1;
        }
        Ok(SegmentIngestOutcome::Accepted { contiguous })
    }

    pub fn values(&self) -> Vec<T> {
        self.retained.iter().cloned().collect()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn purge(&mut self) {
        self.retained.clear();
        self.pending.clear();
    }

    fn append(&mut self, value: T) {
        if self.retained.len() == self.max_retained {
            self.retained.pop_front();
        }
        self.retained.push_back(value);
    }
}

impl<T> Drop for SequencedEphemeralBuffer<T> {
    fn drop(&mut self) {
        self.retained.clear();
        self.pending.clear();
    }
}
