#![no_main]

use krikos_identity::{
    CanonicalWire, CheckpointBody, InclusionReceipt, ProviderEquivocationEvidence,
    ProviderHeadBody, ProviderLogEntryBody, ProviderReceipts, SignedCheckpoint, SignedProviderHead,
    limits::MAX_ENCODED_OBJECT_BYTES,
    merkle::{
        MerkleConsistencyProof, MerkleInclusionProof, MerkleNonMembershipProof, MerkleSetKey,
        MerkleSetLeaf,
    },
};
use libfuzzer_sys::fuzz_target;

type Decoder = fn(&[u8]);

const DECODERS: [Decoder; 13] = [
    round_trip::<MerkleSetKey>,
    round_trip::<MerkleSetLeaf>,
    round_trip::<MerkleInclusionProof>,
    round_trip::<MerkleConsistencyProof>,
    round_trip::<MerkleNonMembershipProof>,
    round_trip::<ProviderLogEntryBody>,
    round_trip::<ProviderHeadBody>,
    round_trip::<SignedProviderHead>,
    round_trip::<InclusionReceipt>,
    round_trip::<ProviderReceipts>,
    round_trip::<ProviderEquivocationEvidence>,
    round_trip::<CheckpointBody>,
    round_trip::<SignedCheckpoint>,
];

fn round_trip<T: CanonicalWire>(payload: &[u8]) {
    let Ok(decoded) = T::from_canonical_bytes(payload) else {
        return;
    };
    assert_eq!(
        decoded.to_canonical_bytes().as_deref(),
        Ok(payload),
        "an accepted Merkle object failed canonical reproduction"
    );
}

fuzz_target!(|input: &[u8]| {
    let Some((&selector, payload)) = input.split_first() else {
        return;
    };
    if payload.len() > MAX_ENCODED_OBJECT_BYTES {
        return;
    }
    // Raw selector values are append-only. `b'm'` is retained as an alias for the historical
    // `merkle-proof-v1` corpus seed, which previously reached index five through `% 13`.
    let decoder_index = if selector == b'm' {
        5
    } else {
        usize::from(selector)
    };
    let Some(decoder) = DECODERS.get(decoder_index) else {
        return;
    };
    decoder(payload);
});
