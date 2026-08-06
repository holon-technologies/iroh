use std::{convert::Infallible, fmt};

use krikos_identity::{
    AccountId, ApplicationId, CanonicalWire, CheckpointId, Digest, Epoch, Extensions,
    HashAlgorithm, IdentityError, PrivateArtifactContext, PrivateMetadata, PrivateMetadataEnvelope,
    PrivateMetadataKey,
};
use rand_core::{TryCryptoRng, TryRng};

fn typed_id<T: CanonicalWire>(fill: u8) -> T {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [fill; 32]);
    T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
}

fn context() -> PrivateArtifactContext {
    PrivateArtifactContext::try_new(
        typed_id::<AccountId>(1),
        typed_id::<CheckpointId>(2),
        Epoch::new(3),
        Some(typed_id::<ApplicationId>(4)),
        5,
        Extensions::default(),
    )
    .unwrap()
}

struct RepeatingRng(u8);

impl TryRng for RepeatingRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(u32::from(self.0))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(u64::from(self.0))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        destination.fill(self.0);
        Ok(())
    }
}

impl TryCryptoRng for RepeatingRng {}

#[derive(Debug, Clone, Copy)]
struct InjectedEntropyFailure;

impl fmt::Display for InjectedEntropyFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected entropy failure")
    }
}

impl std::error::Error for InjectedEntropyFailure {}

struct FailingRng;

impl TryRng for FailingRng {
    type Error = InjectedEntropyFailure;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Err(InjectedEntropyFailure)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Err(InjectedEntropyFailure)
    }

    fn try_fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), Self::Error> {
        Err(InjectedEntropyFailure)
    }
}

impl TryCryptoRng for FailingRng {}

#[test]
fn private_metadata_is_deterministic_with_injected_entropy_and_round_trips() {
    let key = PrivateMetadataKey::try_new([0x31; 32]).unwrap();
    let plaintext = PrivateMetadata::try_new(b"private profile: alpine orchid".to_vec()).unwrap();

    let first = PrivateMetadataEnvelope::seal_with_rng(
        context(),
        &key,
        &plaintext,
        &mut RepeatingRng(0x41),
    )
    .unwrap();
    let second = PrivateMetadataEnvelope::seal_with_rng(
        context(),
        &key,
        &plaintext,
        &mut RepeatingRng(0x41),
    )
    .unwrap();
    assert_eq!(
        first.to_canonical_bytes().unwrap(),
        second.to_canonical_bytes().unwrap()
    );
    assert_eq!(
        PrivateMetadataEnvelope::from_canonical_bytes(&first.to_canonical_bytes().unwrap())
            .unwrap(),
        first
    );
    assert_eq!(first.open(&key).unwrap().as_bytes(), plaintext.as_bytes());

    let encoded = first.to_canonical_bytes().unwrap();
    assert!(
        !encoded
            .windows(plaintext.as_bytes().len())
            .any(|window| window == plaintext.as_bytes())
    );
    assert_eq!(format!("{key:?}"), "PrivateMetadataKey(<redacted>)");
    assert_eq!(format!("{plaintext:?}"), "PrivateMetadata(<redacted>)");
}

#[test]
fn wrong_key_and_ciphertext_corruption_share_one_failure() {
    let key = PrivateMetadataKey::try_new([0x32; 32]).unwrap();
    let wrong = PrivateMetadataKey::try_new([0x33; 32]).unwrap();
    let plaintext = PrivateMetadata::try_new(vec![0x55; 128]).unwrap();
    let envelope = PrivateMetadataEnvelope::seal_with_rng(
        context(),
        &key,
        &plaintext,
        &mut RepeatingRng(0x42),
    )
    .unwrap();
    assert_eq!(
        envelope.open(&wrong),
        Err(IdentityError::PrivateArtifactAuthenticationFailed)
    );

    let mut corrupted = envelope.to_canonical_bytes().unwrap();
    let ciphertext_byte = corrupted
        .len()
        .checked_sub(2)
        .and_then(|index| corrupted.get_mut(index))
        .unwrap();
    *ciphertext_byte ^= 1;
    let corrupted = PrivateMetadataEnvelope::from_canonical_bytes(&corrupted).unwrap();
    assert_eq!(
        corrupted.open(&key),
        Err(IdentityError::PrivateArtifactAuthenticationFailed)
    );
}

#[test]
fn metadata_bounds_and_entropy_failure_are_typed() {
    assert!(matches!(
        PrivateMetadata::try_new(Vec::new()),
        Err(IdentityError::EmptyCollection { .. })
    ));
    assert!(matches!(
        PrivateMetadata::try_new(vec![
            0;
            krikos_identity::limits::MAX_PRIVATE_METADATA_BYTES + 1
        ]),
        Err(IdentityError::LimitExceeded { .. })
    ));

    let key = PrivateMetadataKey::try_new([0x34; 32]).unwrap();
    let plaintext = PrivateMetadata::try_new(vec![0x56; 32]).unwrap();
    assert_eq!(
        PrivateMetadataEnvelope::seal_with_rng(context(), &key, &plaintext, &mut FailingRng),
        Err(IdentityError::EntropyUnavailable)
    );
}
