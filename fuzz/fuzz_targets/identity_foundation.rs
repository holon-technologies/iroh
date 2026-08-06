#![no_main]

use krikos_identity::{
    AeadAlgorithm, AgreementAlgorithm, AgreementPublicKey, CanonicalWire, Digest, DurationMillis,
    Epoch, Extensions, HashAlgorithm, KdfAlgorithm, OperationKind, ProtocolSignature,
    ProtocolVersion, Sequence, SignatureAlgorithm, SigningPublicKey, Timestamp,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let _ = HashAlgorithm::from_canonical_bytes(input);
    let _ = SignatureAlgorithm::from_canonical_bytes(input);
    let _ = AgreementAlgorithm::from_canonical_bytes(input);
    let _ = KdfAlgorithm::from_canonical_bytes(input);
    let _ = AeadAlgorithm::from_canonical_bytes(input);
    let _ = OperationKind::from_canonical_bytes(input);
    let _ = ProtocolVersion::from_canonical_bytes(input);
    let _ = Epoch::from_canonical_bytes(input);
    let _ = Sequence::from_canonical_bytes(input);
    let _ = Timestamp::from_canonical_bytes(input);
    let _ = DurationMillis::from_canonical_bytes(input);
    let _ = Digest::from_canonical_bytes(input);
    let _ = SigningPublicKey::from_canonical_bytes(input);
    let _ = AgreementPublicKey::from_canonical_bytes(input);
    let _ = ProtocolSignature::from_canonical_bytes(input);
    let _ = Extensions::from_canonical_bytes(input);
});
