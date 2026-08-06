use krikos_identity::{
    AlgorithmPublicKey, AlgorithmSignature, CanonicalWire, ControllerWeight, GroupKeyEpoch,
    IdentityError, ProviderQuorum, RequiredWeight,
    limits::{MAX_ALGORITHM_PUBLIC_KEY_BYTES, MAX_ALGORITHM_SIGNATURE_BYTES},
};

#[test]
fn schema_scalars_reject_zero_and_advance_checked() {
    assert!(matches!(
        ControllerWeight::new(0),
        Err(IdentityError::ZeroValue { .. })
    ));
    assert!(matches!(
        RequiredWeight::new(0),
        Err(IdentityError::ZeroValue { .. })
    ));
    assert!(matches!(
        ProviderQuorum::new(0),
        Err(IdentityError::ZeroValue { .. })
    ));
    assert_eq!(GroupKeyEpoch::GENESIS.checked_next().unwrap().get(), 1);
    assert!(GroupKeyEpoch::new(u64::MAX).checked_next().is_err());
}

#[test]
fn migration_key_and_signature_material_is_bounded() {
    let future_key = AlgorithmPublicKey::new(2, vec![7; MAX_ALGORITHM_PUBLIC_KEY_BYTES]).unwrap();
    assert_eq!(
        AlgorithmPublicKey::from_canonical_bytes(&future_key.to_canonical_bytes().unwrap())
            .unwrap(),
        future_key
    );
    assert!(matches!(
        AlgorithmPublicKey::new(2, vec![0; MAX_ALGORITHM_PUBLIC_KEY_BYTES + 1]),
        Err(IdentityError::LimitExceeded { .. })
    ));

    let future_signature =
        AlgorithmSignature::new(2, vec![9; MAX_ALGORITHM_SIGNATURE_BYTES]).unwrap();
    assert_eq!(
        AlgorithmSignature::from_canonical_bytes(&future_signature.to_canonical_bytes().unwrap())
            .unwrap(),
        future_signature
    );
    assert!(matches!(
        AlgorithmSignature::new(2, vec![0; MAX_ALGORITHM_SIGNATURE_BYTES + 1]),
        Err(IdentityError::LimitExceeded { .. })
    ));
}
