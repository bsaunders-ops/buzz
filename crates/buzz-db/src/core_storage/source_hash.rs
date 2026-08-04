use sha2::{Digest, Sha256};

/// Compute the frozen, domain-separated hash for one normalized source chunk.
///
/// Offsets are Unicode-scalar offsets, not UTF-8 byte positions. Keeping this
/// primitive in the storage crate lets both the deterministic indexer adapter
/// and the final database boundary use exactly the same preimage.
#[must_use]
pub fn source_chunk_hash(
    chunk_index: u64,
    start_char: u64,
    end_char: u64,
    content: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"core-buzz:source-chunk:v1\0");
    hasher.update(chunk_index.to_be_bytes());
    hasher.update(start_char.to_be_bytes());
    hasher.update(end_char.to_be_bytes());
    let content_bytes = u64::try_from(content.len()).unwrap_or(u64::MAX);
    hasher.update(content_bytes.to_be_bytes());
    hasher.update(content.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_and_utf8_bytes_are_bound_into_the_hash() {
        let original = source_chunk_hash(0, 0, 2, "é🙂");
        assert_ne!(original, source_chunk_hash(1, 0, 2, "é🙂"));
        assert_ne!(original, source_chunk_hash(0, 1, 3, "é🙂"));
        assert_ne!(original, source_chunk_hash(0, 0, 2, "🙂é"));
    }
}
