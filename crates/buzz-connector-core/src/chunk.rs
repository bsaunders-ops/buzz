//! Deterministic source normalization and bounded chunking.

use crate::{types::UntrustedSourceData, ConnectorError, Result};

/// Explicit deterministic chunking limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkBounds {
    max_chunk_chars: usize,
    overlap_chars: usize,
    max_chunks: usize,
    max_item_chars: usize,
}

impl ChunkBounds {
    /// Validate a bounded fixed-window chunk policy.
    pub fn new(
        max_chunk_chars: usize,
        overlap_chars: usize,
        max_chunks: usize,
        max_item_chars: usize,
    ) -> Result<Self> {
        if max_chunk_chars == 0
            || max_chunk_chars > 8_192
            || overlap_chars >= max_chunk_chars
            || max_chunks == 0
            || max_chunks > 4_096
            || max_item_chars == 0
            || max_item_chars > 2_000_000
        {
            return Err(ConnectorError::InvalidData("chunk bounds are invalid"));
        }
        Ok(Self {
            max_chunk_chars,
            overlap_chars,
            max_chunks,
            max_item_chars,
        })
    }

    /// Month-1 indexing defaults.
    #[must_use]
    pub const fn month_one() -> Self {
        Self {
            max_chunk_chars: 1_200,
            overlap_chars: 120,
            max_chunks: 2_048,
            max_item_chars: 2_000_000,
        }
    }
}

/// A deterministic character-offset source chunk.
#[derive(Clone, PartialEq, Eq)]
pub struct SourceChunk {
    /// Stable zero-based chunk index.
    pub chunk_index: usize,
    /// Inclusive Unicode-scalar offset in normalized source text.
    pub start_char: usize,
    /// Exclusive Unicode-scalar offset in normalized source text.
    pub end_char: usize,
    /// Bounded normalized content.
    pub content: String,
    /// Domain-separated content and offset hash.
    pub content_hash: Vec<u8>,
}

impl std::fmt::Debug for SourceChunk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceChunk")
            .field("chunk_index", &self.chunk_index)
            .field("start_char", &self.start_char)
            .field("end_char", &self.end_char)
            .field("content_redacted", &true)
            .field("content_characters", &self.content.chars().count())
            .finish()
    }
}

fn normalize(text: &str) -> String {
    let mut normalized = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                normalized.push('\n');
            }
            '\0' => normalized.push('\u{fffd}'),
            _ => normalized.push(character),
        }
    }
    normalized
}

fn chunk_hash(index: usize, start: usize, end: usize, content: &str) -> Result<Vec<u8>> {
    let index =
        u64::try_from(index).map_err(|_| ConnectorError::BoundExceeded("source chunk index"))?;
    let start =
        u64::try_from(start).map_err(|_| ConnectorError::BoundExceeded("source chunk offset"))?;
    let end =
        u64::try_from(end).map_err(|_| ConnectorError::BoundExceeded("source chunk offset"))?;
    Ok(buzz_db::core_storage::source_chunk_hash(index, start, end, content).to_vec())
}

/// Normalize and chunk untrusted source data without interpreting instructions.
pub fn chunk_source(source: &UntrustedSourceData, bounds: ChunkBounds) -> Result<Vec<SourceChunk>> {
    let normalized = normalize(source.as_untrusted_text());
    let characters = normalized.chars().collect::<Vec<_>>();
    if characters.len() > bounds.max_item_chars {
        return Err(ConnectorError::BoundExceeded("source item characters"));
    }
    if characters.is_empty() {
        return Ok(Vec::new());
    }
    let step = bounds.max_chunk_chars - bounds.overlap_chars;
    let chunk_count = characters
        .len()
        .saturating_sub(1)
        .checked_div(step)
        .and_then(|count| count.checked_add(1))
        .ok_or(ConnectorError::BoundExceeded("source chunks"))?;
    if chunk_count > bounds.max_chunks {
        return Err(ConnectorError::BoundExceeded("source chunks"));
    }
    let mut chunks = Vec::with_capacity(chunk_count);
    let mut start = 0_usize;
    while start < characters.len() {
        let end = start
            .saturating_add(bounds.max_chunk_chars)
            .min(characters.len());
        let content = characters[start..end].iter().collect::<String>();
        let chunk_index = chunks.len();
        chunks.push(SourceChunk {
            chunk_index,
            start_char: start,
            end_char: end,
            content_hash: chunk_hash(chunk_index, start, end, &content)?,
            content,
        });
        if end == characters.len() {
            break;
        }
        start = start
            .checked_add(step)
            .ok_or(ConnectorError::BoundExceeded("source chunk offset"))?;
    }
    Ok(chunks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_fail_before_partial_output() {
        let source = UntrustedSourceData::new("abcdefghijk");
        let bounds = ChunkBounds::new(4, 1, 2, 100).expect("valid test bounds");
        assert_eq!(
            chunk_source(&source, bounds),
            Err(ConnectorError::BoundExceeded("source chunks"))
        );
    }

    #[test]
    fn utf8_offsets_are_scalar_offsets_not_bytes() {
        let source = UntrustedSourceData::new("é🙂abc");
        let bounds = ChunkBounds::new(3, 1, 10, 100).expect("valid test bounds");
        let chunks = chunk_source(&source, bounds).expect("chunk unicode source");
        assert_eq!(chunks[0].content, "é🙂a");
        assert_eq!((chunks[0].start_char, chunks[0].end_char), (0, 3));
        assert_eq!(chunks[1].content, "abc");
        assert_eq!((chunks[1].start_char, chunks[1].end_char), (2, 5));
    }
}
