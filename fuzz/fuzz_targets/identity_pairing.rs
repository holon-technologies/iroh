#![no_main]

use std::borrow::Cow;

use krikos_identity::{
    CanonicalWire, DeviceAuthorizationProposal, DevicePresenceChallenge, PairingPossessionProof,
    PairingTicket, PairingTranscript, PresenceProof, limits::MAX_ACCOUNT_EVENT_BYTES,
};
use libfuzzer_sys::fuzz_target;

type Decoder = fn(&[u8]);

const DECODERS: [Decoder; 6] = [
    round_trip::<PairingTicket>,
    round_trip::<PairingTranscript>,
    round_trip::<PairingPossessionProof>,
    round_trip::<DeviceAuthorizationProposal>,
    round_trip::<DevicePresenceChallenge>,
    round_trip::<PresenceProof>,
];

fn round_trip<T: CanonicalWire>(payload: &[u8]) {
    let Ok(decoded) = T::from_canonical_bytes(payload) else {
        return;
    };
    assert_eq!(
        decoded.to_canonical_bytes().as_deref(),
        Ok(payload),
        "an accepted pairing or presence object failed canonical reproduction"
    );
}

fn canonical_payload(payload: &[u8]) -> Option<Cow<'_, [u8]>> {
    let Some(hexadecimal) = payload.strip_prefix(b"hex:") else {
        return (payload.len() <= MAX_ACCOUNT_EVENT_BYTES).then_some(Cow::Borrowed(payload));
    };
    let hexadecimal_len = hexadecimal
        .iter()
        .filter(|byte| !byte.is_ascii_whitespace())
        .count();
    if !hexadecimal_len.is_multiple_of(2) || hexadecimal_len / 2 > MAX_ACCOUNT_EVENT_BYTES {
        return None;
    }
    let mut decoded = Vec::with_capacity(hexadecimal_len / 2);
    let mut high_nibble = None;
    for byte in hexadecimal
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
    {
        let nibble = hex_nibble(byte)?;
        if let Some(high) = high_nibble.take() {
            decoded.push((high << 4) | nibble);
        } else {
            high_nibble = Some(nibble);
        }
    }
    Some(Cow::Owned(decoded))
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fuzz_target!(|input: &[u8]| {
    let Some((&selector, encoded_payload)) = input.split_first() else {
        return;
    };
    let Some(payload) = canonical_payload(encoded_payload) else {
        return;
    };
    // The reviewed pairing corpus has always used ASCII `0` through `5` as its selector namespace.
    // Preserve those exact values and reject unknown selectors so appending a decoder cannot
    // silently remap an existing reproducer.
    let Some(decoder_index) = selector.checked_sub(b'0').map(usize::from) else {
        return;
    };
    let Some(decoder) = DECODERS.get(decoder_index) else {
        return;
    };
    decoder(&payload);
});
