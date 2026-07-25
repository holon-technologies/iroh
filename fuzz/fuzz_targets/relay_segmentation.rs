#![no_main]

use iroh_relay::fuzz::fuzz_relay_segmentation;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let Some(header) = input.get(..10) else {
        return;
    };
    let segment_size = u16::from_le_bytes(
        header[..2]
            .try_into()
            .expect("two-byte segment-size slice must convert to an array"),
    );
    let raw_count = u64::from_le_bytes(
        header[2..10]
            .try_into()
            .expect("eight-byte segment-count slice must convert to an array"),
    );
    let num_segments = usize::try_from(raw_count).unwrap_or(usize::MAX);
    let _summary = fuzz_relay_segmentation(&input[10..], segment_size, num_segments);
});
