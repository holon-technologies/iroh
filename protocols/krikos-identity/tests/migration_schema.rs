use krikos_identity::{
    AccountId, ActivateCryptoMigration, AlgorithmPublicKey, AlgorithmSignature,
    BeginCryptoMigration, CanonicalWire, ControllerId, ControllerKeyBinding,
    ControllerKeyBindingProof, ControllerKeyBindingProofSet, ControllerKeyId, CryptoMigrationBody,
    CryptoSuiteDescriptor, CryptoSuiteId, Digest, EventId, Extension, Extensions, HashAlgorithm,
    IdentityError, ProtocolMajor, ProtocolUpgrade, ProtocolVersion, RetireAccount,
    RetireCryptoSuite, RetireCryptoSuiteMode, RevocationReasonCode, UpgradeCompatibility,
    limits::{MAX_ALGORITHM_PUBLIC_KEY_BYTES, MAX_ALGORITHM_SIGNATURE_BYTES, MAX_CONTROLLERS},
};

fn digest_id<T: CanonicalWire>(byte: u8) -> T {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [byte; 32]);
    T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
}

fn future_suite(signature_code: u16) -> CryptoSuiteDescriptor {
    CryptoSuiteDescriptor::try_new(
        ProtocolVersion::V1,
        2,
        1,
        signature_code,
        1,
        1,
        1,
        Extensions::default(),
    )
    .unwrap()
}

fn binding(controller_byte: u8, key_byte: u8) -> ControllerKeyBinding {
    ControllerKeyBinding::try_new(
        digest_id::<ControllerId>(controller_byte),
        digest_id::<ControllerKeyId>(controller_byte.wrapping_add(0x40)),
        AlgorithmPublicKey::new(2, vec![key_byte]).unwrap(),
        Extensions::default(),
    )
    .unwrap()
}

fn migration(bindings: Vec<ControllerKeyBinding>) -> CryptoMigrationBody {
    CryptoMigrationBody::try_new(
        ProtocolVersion::V1,
        digest_id::<AccountId>(0x11),
        digest_id::<CryptoSuiteId>(0x22),
        future_suite(2),
        bindings,
        None,
        [0x77; 32],
        Extensions::default(),
    )
    .unwrap()
}

fn proof(
    migration_id: krikos_identity::CryptoMigrationId,
    controller_id: ControllerId,
) -> ControllerKeyBindingProof {
    ControllerKeyBindingProof::try_new(
        migration_id,
        controller_id,
        AlgorithmSignature::new(1, vec![0x81; 64]).unwrap(),
        AlgorithmSignature::new(2, vec![0x82, 0x83]).unwrap(),
    )
    .unwrap()
}

#[test]
fn crypto_suite_descriptor_and_id_vector_is_frozen() {
    let suite = future_suite(2);
    assert_eq!(
        suite.to_canonical_bytes().unwrap(),
        [1, 2, 1, 2, 1, 1, 1, 0]
    );
    assert_eq!(
        suite.crypto_suite_id().unwrap().to_string(),
        "b3:00015fc3f0269d59b8f2bfdfe6a5ae497e3e62b04771f2f740b631077f067faa"
    );
    assert_eq!(
        CryptoSuiteDescriptor::from_canonical_bytes(&suite.to_canonical_bytes().unwrap()).unwrap(),
        suite
    );
}

#[test]
fn begin_activate_abort_and_retire_vectors_round_trip() {
    let migration = migration(vec![binding(2, 2), binding(1, 1)]);
    assert_eq!(
        migration.bindings()[0].controller_id(),
        digest_id::<ControllerId>(1)
    );
    assert_eq!(
        migration.bindings()[1].controller_id(),
        digest_id::<ControllerId>(2)
    );

    let migration_id = migration.crypto_migration_id().unwrap();
    assert_eq!(
        hex::encode(migration.to_canonical_bytes().unwrap()),
        "01011111111111111111111111111111111111111111111111111111111111111111012222222222222222222222222222222222222222222222222222222222222222010201020101010002010101010101010101010101010101010101010101010101010101010101010101014141414141414141414141414141414141414141414141414141414141414141020101000102020202020202020202020202020202020202020202020202020202020202020142424242424242424242424242424242424242424242424242424242424242420201020000777777777777777777777777777777777777777777777777777777777777777700"
    );
    assert_eq!(
        migration_id.to_string(),
        "b3:4f665be79b9f4132828bbacc0eee43e29724c331824b46af38894f71b3ca55bc"
    );
    let proofs = ControllerKeyBindingProofSet::try_new(vec![
        proof(migration_id, digest_id::<ControllerId>(2)),
        proof(migration_id, digest_id::<ControllerId>(1)),
    ])
    .unwrap();
    let begin = BeginCryptoMigration::try_new(
        ProtocolVersion::V1,
        migration,
        proofs,
        Extensions::default(),
    )
    .unwrap();
    let begin_bytes = begin.to_canonical_bytes().unwrap();
    assert_eq!(
        hex::encode(&begin_bytes),
        "010101111111111111111111111111111111111111111111111111111111111111111101222222222222222222222222222222222222222222222222222222222222222201020102010101000201010101010101010101010101010101010101010101010101010101010101010101414141414141414141414141414141414141414141414141414141414141414102010100010202020202020202020202020202020202020202020202020202020202020202014242424242424242424242424242424242424242424242424242424242424242020102000077777777777777777777777777777777777777777777777777777777777777770002014f665be79b9f4132828bbacc0eee43e29724c331824b46af38894f71b3ca55bc01010101010101010101010101010101010101010101010101010101010101010101408181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818102028283014f665be79b9f4132828bbacc0eee43e29724c331824b46af38894f71b3ca55bc0102020202020202020202020202020202020202020202020202020202020202020140818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181810202828300"
    );
    assert_eq!(
        BeginCryptoMigration::from_canonical_bytes(&begin_bytes).unwrap(),
        begin
    );

    let begin_event_id = digest_id::<EventId>(0x51);
    let activate = ActivateCryptoMigration::try_new(
        ProtocolVersion::V1,
        migration_id,
        begin_event_id,
        Extensions::default(),
    )
    .unwrap();
    let activate_bytes = activate.to_canonical_bytes().unwrap();
    let mut expected_activate = vec![1];
    expected_activate.extend_from_slice(&migration_id.to_canonical_bytes().unwrap());
    expected_activate.extend_from_slice(&begin_event_id.to_canonical_bytes().unwrap());
    expected_activate.push(0);
    assert_eq!(activate_bytes, expected_activate);

    let abort = RetireCryptoSuite::try_new(
        ProtocolVersion::V1,
        migration_id,
        RetireCryptoSuiteMode::AbortCandidate,
        begin_event_id,
        None,
        Extensions::default(),
    )
    .unwrap();
    let mut expected_abort = vec![1];
    expected_abort.extend_from_slice(&migration_id.to_canonical_bytes().unwrap());
    expected_abort.push(1);
    expected_abort.extend_from_slice(&begin_event_id.to_canonical_bytes().unwrap());
    expected_abort.extend_from_slice(&[0, 0]);
    assert_eq!(abort.to_canonical_bytes().unwrap(), expected_abort);

    let activate_event_id = digest_id::<EventId>(0x52);
    let successor = digest_id::<AccountId>(0x53);
    let retire = RetireCryptoSuite::try_new(
        ProtocolVersion::V1,
        migration_id,
        RetireCryptoSuiteMode::RetirePrevious,
        activate_event_id,
        Some(successor),
        Extensions::default(),
    )
    .unwrap();
    let retire_bytes = retire.to_canonical_bytes().unwrap();
    assert_eq!(retire_bytes[34], 2);
    assert_eq!(
        RetireCryptoSuite::from_canonical_bytes(&retire_bytes).unwrap(),
        retire
    );
}

#[test]
fn migration_requires_distinct_suites_nonzero_nonce_and_signature_only_in_place_change() {
    let suite = future_suite(2);
    let suite_id = suite.crypto_suite_id().unwrap();
    let account_id = digest_id::<AccountId>(1);
    let one_binding = vec![binding(1, 1)];

    assert!(matches!(
        CryptoMigrationBody::try_new(
            ProtocolVersion::V1,
            account_id,
            suite_id,
            suite.clone(),
            one_binding.clone(),
            None,
            [1; 32],
            Extensions::default(),
        ),
        Err(IdentityError::InvalidRelationship { .. })
    ));
    assert!(matches!(
        CryptoMigrationBody::try_new(
            ProtocolVersion::V1,
            account_id,
            digest_id::<CryptoSuiteId>(3),
            suite,
            one_binding.clone(),
            None,
            [0; 32],
            Extensions::default(),
        ),
        Err(IdentityError::ZeroValue { .. })
    ));

    let digest_break_suite = CryptoSuiteDescriptor::try_new(
        ProtocolVersion::V1,
        3,
        2,
        2,
        1,
        1,
        1,
        Extensions::default(),
    )
    .unwrap();
    assert!(matches!(
        CryptoMigrationBody::try_new(
            ProtocolVersion::V1,
            account_id,
            digest_id::<CryptoSuiteId>(3),
            digest_break_suite.clone(),
            one_binding.clone(),
            None,
            [1; 32],
            Extensions::default(),
        ),
        Err(IdentityError::InvalidRelationship { .. })
    ));
    assert!(
        CryptoMigrationBody::try_new(
            ProtocolVersion::V1,
            account_id,
            digest_id::<CryptoSuiteId>(3),
            digest_break_suite,
            one_binding,
            Some(digest_id::<AccountId>(4)),
            [1; 32],
            Extensions::default(),
        )
        .is_ok()
    );
}

#[test]
fn begin_requires_a_complete_unique_cross_binding_proof_set() {
    let migration = migration(vec![binding(1, 1), binding(2, 2)]);
    let migration_id = migration.crypto_migration_id().unwrap();
    let incomplete = ControllerKeyBindingProofSet::try_new(vec![proof(
        migration_id,
        digest_id::<ControllerId>(1),
    )])
    .unwrap();
    assert!(matches!(
        BeginCryptoMigration::try_new(
            ProtocolVersion::V1,
            migration.clone(),
            incomplete,
            Extensions::default(),
        ),
        Err(IdentityError::InvalidRelationship { .. })
    ));

    let wrong_id = digest_id(0x99);
    let mismatched = ControllerKeyBindingProofSet::try_new(vec![
        proof(wrong_id, digest_id::<ControllerId>(1)),
        proof(wrong_id, digest_id::<ControllerId>(2)),
    ])
    .unwrap();
    assert!(matches!(
        BeginCryptoMigration::try_new(
            ProtocolVersion::V1,
            migration,
            mismatched,
            Extensions::default(),
        ),
        Err(IdentityError::InvalidRelationship { .. })
    ));
}

#[test]
fn migration_collections_and_algorithm_material_are_bounded_and_unique() {
    let duplicate = vec![binding(1, 1), binding(1, 2)];
    assert!(matches!(
        CryptoMigrationBody::try_new(
            ProtocolVersion::V1,
            digest_id::<AccountId>(1),
            digest_id::<CryptoSuiteId>(2),
            future_suite(2),
            duplicate,
            None,
            [1; 32],
            Extensions::default(),
        ),
        Err(IdentityError::DuplicateElement { .. })
    ));

    let too_many = (0..=MAX_CONTROLLERS)
        .map(|index| {
            binding(
                u8::try_from(index + 1).unwrap(),
                u8::try_from(index + 1).unwrap(),
            )
        })
        .collect();
    assert!(matches!(
        CryptoMigrationBody::try_new(
            ProtocolVersion::V1,
            digest_id::<AccountId>(1),
            digest_id::<CryptoSuiteId>(2),
            future_suite(2),
            too_many,
            None,
            [1; 32],
            Extensions::default(),
        ),
        Err(IdentityError::LimitExceeded {
            maximum: MAX_CONTROLLERS,
            ..
        })
    ));

    assert!(AlgorithmPublicKey::new(2, vec![1; MAX_ALGORITHM_PUBLIC_KEY_BYTES]).is_ok());
    assert!(matches!(
        AlgorithmPublicKey::new(2, vec![1; MAX_ALGORITHM_PUBLIC_KEY_BYTES + 1]),
        Err(IdentityError::LimitExceeded { .. })
    ));
    assert!(AlgorithmSignature::new(2, vec![1; MAX_ALGORITHM_SIGNATURE_BYTES]).is_ok());
    assert!(matches!(
        AlgorithmSignature::new(2, vec![1; MAX_ALGORITHM_SIGNATURE_BYTES + 1]),
        Err(IdentityError::LimitExceeded { .. })
    ));
}

#[test]
fn canonical_decode_rejects_unsorted_and_duplicate_controller_bindings() {
    let canonical = migration(vec![binding(1, 1), binding(2, 2)])
        .to_canonical_bytes()
        .unwrap();

    // The frozen v1 prefix is version + two digest IDs + suite + collection length.
    const FIRST_BINDING: usize = 76;
    const BINDING_LENGTH: usize = 70;
    let second_binding = FIRST_BINDING + BINDING_LENGTH;
    let after_bindings = second_binding + BINDING_LENGTH;

    let mut unsorted = canonical.clone();
    let first = unsorted[FIRST_BINDING..second_binding].to_vec();
    let second = unsorted[second_binding..after_bindings].to_vec();
    unsorted[FIRST_BINDING..second_binding].copy_from_slice(&second);
    unsorted[second_binding..after_bindings].copy_from_slice(&first);
    assert!(CryptoMigrationBody::from_canonical_bytes(&unsorted).is_err());

    let mut duplicate = canonical;
    let first = duplicate[FIRST_BINDING..second_binding].to_vec();
    duplicate[second_binding..after_bindings].copy_from_slice(&first);
    assert!(CryptoMigrationBody::from_canonical_bytes(&duplicate).is_err());
}

#[test]
fn proof_sets_reject_duplicates_over_limit_and_wrong_candidate_algorithms() {
    let migration = migration(vec![binding(1, 1)]);
    let migration_id = migration.crypto_migration_id().unwrap();
    let duplicate = vec![
        proof(migration_id, digest_id::<ControllerId>(1)),
        proof(migration_id, digest_id::<ControllerId>(1)),
    ];
    assert!(matches!(
        ControllerKeyBindingProofSet::try_new(duplicate),
        Err(IdentityError::DuplicateElement { .. })
    ));

    let too_many = (0..=MAX_CONTROLLERS)
        .map(|index| {
            proof(
                migration_id,
                digest_id::<ControllerId>(u8::try_from(index + 1).unwrap()),
            )
        })
        .collect();
    assert!(matches!(
        ControllerKeyBindingProofSet::try_new(too_many),
        Err(IdentityError::LimitExceeded {
            maximum: MAX_CONTROLLERS,
            ..
        })
    ));

    let wrong_algorithm = ControllerKeyBindingProofSet::try_new(vec![
        ControllerKeyBindingProof::try_new(
            migration_id,
            digest_id::<ControllerId>(1),
            AlgorithmSignature::new(1, vec![0x81; 64]).unwrap(),
            AlgorithmSignature::new(3, vec![0x82]).unwrap(),
        )
        .unwrap(),
    ])
    .unwrap();
    assert!(matches!(
        BeginCryptoMigration::try_new(
            ProtocolVersion::V1,
            migration,
            wrong_algorithm,
            Extensions::default(),
        ),
        Err(IdentityError::InvalidRelationship { .. })
    ));
}

#[test]
fn raw_codepoints_and_cross_field_relationships_fail_closed() {
    assert!(matches!(
        CryptoSuiteDescriptor::try_new(
            ProtocolVersion::V1,
            0,
            1,
            2,
            1,
            1,
            1,
            Extensions::default(),
        ),
        Err(IdentityError::ZeroValue { .. })
    ));

    let wrong_key_algorithm = ControllerKeyBinding::try_new(
        digest_id::<ControllerId>(1),
        digest_id::<ControllerKeyId>(2),
        AlgorithmPublicKey::new(3, vec![1]).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    assert!(matches!(
        CryptoMigrationBody::try_new(
            ProtocolVersion::V1,
            digest_id::<AccountId>(1),
            digest_id::<CryptoSuiteId>(2),
            future_suite(2),
            vec![wrong_key_algorithm],
            None,
            [1; 32],
            Extensions::default(),
        ),
        Err(IdentityError::InvalidRelationship { .. })
    ));

    let account_id = digest_id::<AccountId>(4);
    assert!(matches!(
        CryptoMigrationBody::try_new(
            ProtocolVersion::V1,
            account_id,
            digest_id::<CryptoSuiteId>(2),
            future_suite(2),
            vec![binding(1, 1)],
            Some(account_id),
            [1; 32],
            Extensions::default(),
        ),
        Err(IdentityError::InvalidRelationship { .. })
    ));

    // Version, no successor, present zero reason, then empty extensions.
    assert!(RetireAccount::from_canonical_bytes(&[1, 0, 1, 0, 0]).is_err());
}

#[test]
fn unknown_noncritical_extensions_are_signed_and_critical_extensions_fail_closed() {
    let noncritical =
        Extensions::new(vec![Extension::new(9, false, vec![0xaa, 0xbb]).unwrap()]).unwrap();
    let suite =
        CryptoSuiteDescriptor::try_new(ProtocolVersion::V1, 2, 1, 2, 1, 1, 1, noncritical).unwrap();
    assert_eq!(
        suite.to_canonical_bytes().unwrap(),
        [1, 2, 1, 2, 1, 1, 1, 1, 9, 0, 2, 0xaa, 0xbb]
    );
    assert_eq!(suite.extensions().as_slice()[0].code(), 9);

    let critical = Extensions::new(vec![Extension::new(9, true, vec![]).unwrap()]).unwrap();
    assert!(matches!(
        CryptoSuiteDescriptor::try_new(ProtocolVersion::V1, 2, 1, 2, 1, 1, 1, critical,),
        Err(IdentityError::UnknownCriticalExtension { code: 9 })
    ));
    assert!(
        CryptoSuiteDescriptor::from_canonical_bytes(&[1, 2, 1, 2, 1, 1, 1, 1, 9, 1, 0]).is_err()
    );
}

#[test]
fn upgrade_and_terminal_retirement_vectors_are_frozen() {
    assert_eq!(
        RetireCryptoSuiteMode::AbortCandidate
            .to_canonical_bytes()
            .unwrap(),
        [1]
    );
    assert_eq!(
        RetireCryptoSuiteMode::RetirePrevious
            .to_canonical_bytes()
            .unwrap(),
        [2]
    );
    assert_eq!(
        UpgradeCompatibility::OldClientsReadOnly
            .to_canonical_bytes()
            .unwrap(),
        [1]
    );
    assert!(RetireCryptoSuiteMode::from_canonical_bytes(&[3]).is_err());
    assert!(UpgradeCompatibility::from_canonical_bytes(&[2]).is_err());

    let from = ProtocolMajor::new(1).unwrap();
    let to = ProtocolMajor::new(2).unwrap();
    let spec_digest = Digest::new(HashAlgorithm::Blake3_256, [0x91; 32]);
    let successor = digest_id::<AccountId>(0x92);
    let upgrade = ProtocolUpgrade::try_new(
        ProtocolVersion::V1,
        from,
        to,
        spec_digest,
        UpgradeCompatibility::OldClientsReadOnly,
        Some(successor),
        Extensions::default(),
    )
    .unwrap();
    let mut expected_upgrade = vec![1, 1, 2, 1];
    expected_upgrade.extend_from_slice(&[0x91; 32]);
    expected_upgrade.extend_from_slice(&[1, 1, 1]);
    expected_upgrade.extend_from_slice(&[0x92; 32]);
    expected_upgrade.push(0);
    assert_eq!(upgrade.to_canonical_bytes().unwrap(), expected_upgrade);
    assert!(
        ProtocolUpgrade::try_new(
            ProtocolVersion::V1,
            to,
            from,
            spec_digest,
            UpgradeCompatibility::OldClientsReadOnly,
            None,
            Extensions::default(),
        )
        .is_err()
    );

    let retired = RetireAccount::try_new(
        ProtocolVersion::V1,
        Some(successor),
        Some(RevocationReasonCode::new(7).unwrap()),
        Extensions::default(),
    )
    .unwrap();
    let mut expected_retired = vec![1, 1, 1];
    expected_retired.extend_from_slice(&[0x92; 32]);
    expected_retired.extend_from_slice(&[1, 7, 0]);
    assert_eq!(retired.to_canonical_bytes().unwrap(), expected_retired);
    assert_eq!(
        RetireAccount::from_canonical_bytes(&expected_retired).unwrap(),
        retired
    );
}

#[test]
fn abort_mode_cannot_publish_a_successor() {
    assert!(matches!(
        RetireCryptoSuite::try_new(
            ProtocolVersion::V1,
            digest_id(1),
            RetireCryptoSuiteMode::AbortCandidate,
            digest_id(2),
            Some(digest_id(3)),
            Extensions::default(),
        ),
        Err(IdentityError::InvalidRelationship { .. })
    ));
}
