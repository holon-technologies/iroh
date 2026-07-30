//! Bounded, effect-free adapters for fuzzing relay protocol arithmetic.

use std::num::NonZeroU16;

use bytes::Bytes;

use crate::protos::relay::{Datagrams, MAX_PACKET_SIZE};

/// Maximum payload accepted by the bounded relay segmentation fuzz adapter.
pub const FUZZ_MAX_RELAY_CONTENT_BYTES: usize = MAX_PACKET_SIZE;

/// Result of one bounded relay segmentation operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuzzSegmentationSummary {
    /// Input bytes before segmentation.
    pub input_bytes: usize,
    /// Bytes returned in the selected prefix.
    pub taken_bytes: usize,
    /// Bytes retained for later transmission.
    pub remaining_bytes: usize,
    /// Whether the selected prefix still represents multiple datagrams.
    pub taken_is_batch: bool,
    /// Whether the retained suffix still represents multiple datagrams.
    pub remaining_is_batch: bool,
}

/// Input exceeded the relay protocol's bounded packet size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuzzRelayInputTooLarge;

/// Exercises production relay segmentation arithmetic on a bounded synthetic payload.
pub fn fuzz_relay_segmentation(
    contents: &[u8],
    segment_size: u16,
    num_segments: usize,
) -> Result<FuzzSegmentationSummary, FuzzRelayInputTooLarge> {
    if contents.len() > FUZZ_MAX_RELAY_CONTENT_BYTES {
        return Err(FuzzRelayInputTooLarge);
    }
    let mut datagrams = Datagrams {
        ecn: None,
        segment_size: NonZeroU16::new(segment_size),
        contents: Bytes::copy_from_slice(contents),
    };
    let taken = datagrams.take_segments(num_segments);
    let observed = taken
        .contents
        .len()
        .checked_add(datagrams.contents.len())
        .expect("two bounded relay payload lengths must not overflow");
    assert_eq!(
        observed,
        contents.len(),
        "relay segmentation must conserve every input byte"
    );
    Ok(FuzzSegmentationSummary {
        input_bytes: contents.len(),
        taken_bytes: taken.contents.len(),
        remaining_bytes: datagrams.contents.len(),
        taken_is_batch: taken.segment_size.is_some(),
        remaining_is_batch: datagrams.segment_size.is_some(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_relay_segmentation_conserves_bytes_and_rejects_oversized_input() {
        let summary = fuzz_relay_segmentation(&[7; 15], 1, 10).expect("bounded relay segmentation");
        assert_eq!(summary.input_bytes, 15);
        assert_eq!(summary.taken_bytes, 10);
        assert_eq!(summary.remaining_bytes, 5);
        assert!(summary.taken_is_batch);
        assert!(summary.remaining_is_batch);

        assert_eq!(
            fuzz_relay_segmentation(&vec![0; FUZZ_MAX_RELAY_CONTENT_BYTES + 1], 1, 1),
            Err(FuzzRelayInputTooLarge)
        );
    }
}
