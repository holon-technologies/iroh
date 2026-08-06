use krikos_identity::{
    AccountGenesis, CanonicalWire, ControlPolicy, ControllerClass, ControllerDescriptor,
    ControllerScope, ControllerSelector, ControllerThreshold, ControllerWeight, DurationMillis,
    Extensions, FreshnessRequirement, IdentityError, OperationKind, PolicyRule, ProviderPolicy,
    ProviderPolicyVersion, RecoveryAuthority, RecoveryPolicy, RecoveryPolicyVersion,
    RequiredWeight, SigningPublicKey, Timestamp, limits::MAX_CONTROLLERS,
};

const VALID_KEY: [u8; 32] = [
    0xae, 0x58, 0xff, 0x88, 0x33, 0x24, 0x1a, 0xc8, 0x2d, 0x6f, 0xf7, 0x61, 0x10, 0x46, 0xed, 0x67,
    0xb5, 0x07, 0x2d, 0x14, 0x2c, 0x58, 0x8d, 0x00, 0x63, 0xe9, 0x42, 0xd9, 0xa7, 0x55, 0x02, 0xb6,
];

fn fixture() -> AccountGenesis {
    let controller = ControllerDescriptor::new(
        SigningPublicKey::ed25519(VALID_KEY).unwrap(),
        ControllerClass::PersonalDevice,
        ControllerWeight::new(1).unwrap(),
        ControllerScope::all_v1_operations(),
        Extensions::default(),
    )
    .unwrap();
    let rules = [
        OperationKind::ChangeControlPolicy,
        OperationKind::ResolveFork,
    ]
    .into_iter()
    .map(|operation| {
        PolicyRule::new(
            operation,
            RequiredWeight::new(1).unwrap(),
            ControllerSelector::any_active(),
            FreshnessRequirement::latest_known(),
            None,
            Extensions::default(),
        )
        .unwrap()
    })
    .collect();
    let control = ControlPolicy::new(rules, Extensions::default()).unwrap();
    let recovery = RecoveryPolicy::new(
        RecoveryPolicyVersion::GENESIS,
        RecoveryAuthority::controller_threshold(ControllerThreshold::new(
            ControllerSelector::any_active(),
            RequiredWeight::new(1).unwrap(),
        )),
        DurationMillis::new(60_000),
        DurationMillis::new(120_000),
        Extensions::default(),
    )
    .unwrap();
    AccountGenesis::new(
        [7; 32],
        Timestamp::from_unix_millis(1_700_000_000_000),
        control,
        vec![controller],
        recovery,
        ProviderPolicy::local_only(ProviderPolicyVersion::GENESIS, Extensions::default()).unwrap(),
        Extensions::default(),
    )
    .unwrap()
}

#[test]
fn genesis_bytes_anchor_and_account_id_are_stable() {
    let genesis = fixture();
    let encoded = genesis.to_canonical_bytes().unwrap();
    assert_eq!(
        hex::encode(&encoded),
        concat!(
            "010707070707070707070707070707070707070707070707070707070707070707",
            "80d095ffbc310101020a01010000010000001101010000010000000100010101ae",
            "58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b60101",
            "010000010001010100000100e0d403c0a90700010001000000"
        )
    );
    assert_eq!(
        genesis.account_id().unwrap().to_string(),
        "b3:af84c06d8905295e7231e960820bb57f73ab31b5fab87b490bcf6de3feac1ce7"
    );
    assert_eq!(
        genesis.genesis_anchor().unwrap().to_string(),
        "b3:c0733bc78c4136c28b6fb0582d578134abdb2223961364c912fe8c02ea0f5f5b"
    );
    assert_eq!(
        AccountGenesis::from_canonical_bytes(&encoded).unwrap(),
        genesis
    );
    assert_ne!(
        genesis.genesis_anchor().unwrap().as_digest(),
        genesis.account_id().unwrap().as_digest()
    );
}

#[test]
fn genesis_rejects_zero_nonce_and_duplicate_controller_keys() {
    let valid = fixture();
    assert!(
        valid
            .initial_policy()
            .validate_satisfiable(valid.initial_controllers())
            .is_ok()
    );
    assert!(
        AccountGenesis::new(
            [0; 32],
            valid.created_at(),
            valid.initial_policy().clone(),
            valid.initial_controllers().to_vec(),
            valid.initial_recovery_policy().clone(),
            valid.initial_provider_policy().clone(),
            Extensions::default(),
        )
        .is_err()
    );

    let repeated_controller = valid.initial_controllers()[0].clone();
    assert!(matches!(
        AccountGenesis::new(
            [7; 32],
            valid.created_at(),
            valid.initial_policy().clone(),
            vec![repeated_controller; MAX_CONTROLLERS + 1],
            valid.initial_recovery_policy().clone(),
            valid.initial_provider_policy().clone(),
            Extensions::default(),
        ),
        Err(IdentityError::LimitExceeded {
            resource: "initial controllers",
            actual,
            maximum: MAX_CONTROLLERS,
        }) if actual == MAX_CONTROLLERS + 1
    ));
}
