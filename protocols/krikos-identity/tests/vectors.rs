use krikos_identity::{
    AeadAlgorithm, AgreementAlgorithm, AgreementPublicKey, CanonicalWire, Digest, Epoch, Extension,
    Extensions, HashAlgorithm, IdentityError, KdfAlgorithm, OperationKind, ProtocolSignature,
    ProtocolVersion, RESERVED_PUBLISH_CHECKPOINT_CODE, Sequence, SignatureAlgorithm,
    SigningPublicKey, Timestamp,
    limits::{MAX_ENCODED_OBJECT_BYTES, MAX_EXTENSIONS, MAX_TOTAL_EXTENSION_BYTES},
};

const VALID_ED25519_KEY: [u8; 32] = [
    0xae, 0x58, 0xff, 0x88, 0x33, 0x24, 0x1a, 0xc8, 0x2d, 0x6f, 0xf7, 0x61, 0x10, 0x46, 0xed, 0x67,
    0xb5, 0x07, 0x2d, 0x14, 0x2c, 0x58, 0x8d, 0x00, 0x63, 0xe9, 0x42, 0xd9, 0xa7, 0x55, 0x02, 0xb6,
];

#[test]
fn v1_algorithm_codepoints_are_frozen() {
    assert_eq!(HashAlgorithm::Blake3_256.code(), 1);
    assert_eq!(SignatureAlgorithm::Ed25519.code(), 1);
    assert_eq!(AgreementAlgorithm::X25519.code(), 1);
    assert_eq!(KdfAlgorithm::Blake3DeriveKey.code(), 1);
    assert_eq!(AeadAlgorithm::XChaCha20Poly1305.code(), 1);
}

#[test]
fn v1_operation_codepoints_are_frozen() {
    let expected = [
        (OperationKind::AuthorizeDevice, 1),
        (OperationKind::UpdateDeviceAuthorization, 2),
        (OperationKind::UpdateDeviceMetadata, 3),
        (OperationKind::SuspendDevice, 4),
        (OperationKind::ReinstateDevice, 5),
        (OperationKind::RevokeDevice, 6),
        (OperationKind::RotateDeviceKeys, 7),
        (OperationKind::AddController, 8),
        (OperationKind::RemoveController, 9),
        (OperationKind::ChangeControlPolicy, 10),
        (OperationKind::ChangeRecoveryPolicy, 11),
        (OperationKind::ChangeProviderPolicy, 12),
        (OperationKind::BeginRecovery, 13),
        (OperationKind::VetoRecovery, 14),
        (OperationKind::CancelRecovery, 15),
        (OperationKind::FinalizeRecovery, 16),
        (OperationKind::ResolveFork, 17),
        (OperationKind::BeginCryptoMigration, 18),
        (OperationKind::ActivateCryptoMigration, 19),
        (OperationKind::RetireCryptoSuite, 20),
        (OperationKind::UpgradeProtocol, 21),
        (OperationKind::RetireAccount, 22),
    ];
    for (kind, code) in expected {
        assert_eq!(kind.code(), code);
        assert_eq!(OperationKind::from_code(code).unwrap(), kind);
    }
    assert_eq!(RESERVED_PUBLISH_CHECKPOINT_CODE, 23);
    assert!(matches!(
        OperationKind::from_code(RESERVED_PUBLISH_CHECKPOINT_CODE),
        Err(IdentityError::ReservedCodepoint { code: 23, .. })
    ));
}

#[test]
fn extensions_are_sorted_bounded_and_preserve_noncritical_unknown_values() {
    let extensions = Extensions::new(vec![
        Extension::new(9, false, vec![9, 8]).unwrap(),
        Extension::new(2, false, vec![2]).unwrap(),
    ])
    .unwrap();
    assert_eq!(extensions.as_slice()[0].code(), 2);
    assert_eq!(extensions.as_slice()[1].code(), 9);

    let encoded = extensions.to_canonical_bytes().unwrap();
    assert_eq!(encoded, [2, 2, 0, 1, 2, 9, 0, 2, 9, 8]);
    assert_eq!(
        Extensions::from_canonical_bytes(&encoded).unwrap(),
        extensions
    );
    extensions.validate_critical(&[2]).unwrap();

    let critical = Extensions::new(vec![Extension::new(7, true, vec![]).unwrap()]).unwrap();
    assert!(matches!(
        critical.validate_critical(&[2]),
        Err(IdentityError::UnknownCriticalExtension { code: 7 })
    ));

    let duplicates = vec![
        Extension::new(1, false, vec![]).unwrap(),
        Extension::new(1, false, vec![1]).unwrap(),
    ];
    assert!(matches!(
        Extensions::new(duplicates),
        Err(IdentityError::DuplicateExtension { code: 1 })
    ));

    let too_many = (1..=u32::try_from(MAX_EXTENSIONS + 1).unwrap())
        .map(|code| Extension::new(code, false, vec![]).unwrap())
        .collect();
    assert!(matches!(
        Extensions::new(too_many),
        Err(IdentityError::LimitExceeded {
            maximum: MAX_EXTENSIONS,
            ..
        })
    ));

    assert!(Extension::new(1, false, vec![0; MAX_TOTAL_EXTENSION_BYTES + 1]).is_err());

    let unsorted_wire = [2, 2, 0, 0, 1, 0, 0];
    assert!(matches!(
        Extensions::from_canonical_bytes(&unsorted_wire),
        Err(IdentityError::NonCanonical)
    ));

    let duplicate_wire = [2, 1, 0, 0, 1, 0, 0];
    assert!(matches!(
        Extensions::from_canonical_bytes(&duplicate_wire),
        Err(IdentityError::DuplicateExtension { code: 1 })
    ));
}

#[test]
fn canonical_foundation_vectors_are_frozen() {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [0xab; 32]);
    let mut expected_digest = vec![1];
    expected_digest.extend_from_slice(&[0xab; 32]);
    assert_eq!(digest.to_canonical_bytes().unwrap(), expected_digest);
    assert_eq!(
        Digest::from_canonical_bytes(&expected_digest).unwrap(),
        digest
    );

    let key = SigningPublicKey::ed25519(VALID_ED25519_KEY).unwrap();
    let mut expected_key = vec![1];
    expected_key.extend_from_slice(&VALID_ED25519_KEY);
    assert_eq!(key.to_canonical_bytes().unwrap(), expected_key);

    let mut agreement_bytes = [0; 32];
    agreement_bytes[0] = 9;
    let agreement_key = AgreementPublicKey::x25519(agreement_bytes).unwrap();
    let mut expected_agreement_key = vec![1];
    expected_agreement_key.extend_from_slice(&agreement_bytes);
    assert_eq!(
        agreement_key.to_canonical_bytes().unwrap(),
        expected_agreement_key
    );
    assert_eq!(
        AgreementPublicKey::from_canonical_bytes(&expected_agreement_key).unwrap(),
        agreement_key
    );

    let signature = ProtocolSignature::ed25519([0x5a; 64]);
    let mut expected_signature = vec![1];
    expected_signature.extend_from_slice(&[0x5a; 64]);
    assert_eq!(signature.to_canonical_bytes().unwrap(), expected_signature);

    assert_eq!(ProtocolVersion::V1.to_canonical_bytes().unwrap(), [1]);
}

#[test]
fn canonical_decode_rejects_trailing_and_noncanonical_bytes() {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [7; 32]);
    let mut trailing = digest.to_canonical_bytes().unwrap();
    trailing.push(0);
    assert!(matches!(
        Digest::from_canonical_bytes(&trailing),
        Err(IdentityError::NonCanonical)
    ));

    let mut overlong_algorithm = vec![0x81, 0x00];
    overlong_algorithm.extend_from_slice(&[7; 32]);
    assert!(matches!(
        Digest::from_canonical_bytes(&overlong_algorithm),
        Err(IdentityError::NonCanonical)
    ));
}

#[test]
fn canonical_decode_rejects_unknown_codepoints_and_oversized_input() {
    let mut unknown_hash = vec![99];
    unknown_hash.extend_from_slice(&[0; 32]);
    assert!(matches!(
        Digest::from_canonical_bytes(&unknown_hash),
        Err(IdentityError::UnsupportedAlgorithm { code: 99, .. })
    ));

    let oversized = vec![0; MAX_ENCODED_OBJECT_BYTES + 1];
    assert!(matches!(
        Digest::from_canonical_bytes(&oversized),
        Err(IdentityError::LimitExceeded {
            maximum: MAX_ENCODED_OBJECT_BYTES,
            ..
        })
    ));
}

#[test]
fn x25519_public_keys_are_canonical_and_contributory() {
    let mut basepoint = [0; 32];
    basepoint[0] = 9;
    assert!(AgreementPublicKey::x25519(basepoint).is_ok());

    let mut high_bit_alias = basepoint;
    high_bit_alias[31] = 0x80;
    assert!(matches!(
        AgreementPublicKey::x25519(high_bit_alias),
        Err(IdentityError::InvalidPublicKey { .. })
    ));

    let mut field_modulus = [0xff; 32];
    field_modulus[0] = 0xed;
    field_modulus[31] = 0x7f;
    assert!(matches!(
        AgreementPublicKey::x25519(field_modulus),
        Err(IdentityError::InvalidPublicKey { .. })
    ));

    let mut low_order = [0; 32];
    low_order[0] = 1;
    assert!(matches!(
        AgreementPublicKey::x25519(low_order),
        Err(IdentityError::InvalidPublicKey { .. })
    ));
}

#[test]
fn ed25519_public_keys_reject_weak_points() {
    let mut identity_point = [0; 32];
    identity_point[0] = 1;
    assert!(matches!(
        SigningPublicKey::ed25519(identity_point),
        Err(IdentityError::InvalidPublicKey { .. })
    ));
}

#[test]
fn aggregate_extension_bound_is_exercised() {
    let at_limit = (1..=4)
        .map(|code| Extension::new(code, false, vec![0; 16 * 1024]).unwrap())
        .collect();
    assert!(Extensions::new(at_limit).is_ok());

    let over_limit = (1..=5)
        .map(|code| {
            let length = if code == 5 { 1 } else { 16 * 1024 };
            Extension::new(code, false, vec![0; length]).unwrap()
        })
        .collect();
    assert!(matches!(
        Extensions::new(over_limit),
        Err(IdentityError::LimitExceeded {
            maximum: MAX_TOTAL_EXTENSION_BYTES,
            ..
        })
    ));
}

#[test]
fn numeric_newtypes_use_checked_arithmetic() {
    assert_eq!(Epoch::GENESIS.checked_next().unwrap().get(), 1);
    assert_eq!(Sequence::GENESIS.checked_next().unwrap().get(), 1);
    assert!(Epoch::new(u64::MAX).checked_next().is_err());
    assert!(Sequence::new(u64::MAX).checked_next().is_err());
    assert_eq!(Timestamp::from_unix_millis(42).as_unix_millis(), 42);
}

proptest::proptest! {
    #[test]
    fn digest_canonical_round_trip(bytes in proptest::array::uniform32(proptest::num::u8::ANY)) {
        let value = Digest::new(HashAlgorithm::Blake3_256, bytes);
        let encoded = value.to_canonical_bytes().unwrap();
        proptest::prop_assert_eq!(Digest::from_canonical_bytes(&encoded).unwrap(), value);
    }
}
