use krikos_identity::{
    AgreementPublicKey, CanonicalWire, ControlPolicy, ControllerClass, ControllerDescriptor,
    ControllerScope, ControllerSelector, ControllerThreshold, ControllerWeight, Digest,
    DurationMillis, EndpointPublicKey, Extensions, FreshnessRequirement, GuardianSetRoot,
    GuardianThreshold, HashAlgorithm, IdentityError, OperationKind, PolicyRule, ProtocolVersion,
    ProviderDescriptor, ProviderPolicy, ProviderPolicyVersion, ProviderQuorum,
    ProviderRotationRule, RecoveryAuthority, RecoveryPolicy, RecoveryPolicyVersion, RequiredWeight,
    SigningPublicKey, limits::MAX_TRANSPARENCY_PROVIDERS,
};

const SIGNING_KEY_1: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
const SIGNING_KEY_2: [u8; 32] = [
    0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
    0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
];
const SIGNING_KEY_3: [u8; 32] = [
    0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0, 0x58,
    0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90, 0x80, 0x25,
];

fn signing_key(bytes: [u8; 32]) -> SigningPublicKey {
    SigningPublicKey::ed25519(bytes).unwrap()
}

fn controller(weight: u32) -> ControllerDescriptor {
    ControllerDescriptor::new(
        signing_key(SIGNING_KEY_1),
        ControllerClass::PersonalDevice,
        ControllerWeight::new(weight).unwrap(),
        ControllerScope::all_v1_operations(),
        Extensions::default(),
    )
    .unwrap()
}

fn rule(required_weight: u32) -> PolicyRule {
    PolicyRule::new(
        OperationKind::ChangeControlPolicy,
        RequiredWeight::new(required_weight).unwrap(),
        ControllerSelector::any_active(),
        FreshnessRequirement::latest_known(),
        None,
        Extensions::default(),
    )
    .unwrap()
}

#[test]
fn controller_class_and_scope_codepoints_are_frozen() {
    assert_eq!(ControllerClass::PersonalDevice.code(), 1);
    assert_eq!(ControllerClass::HardwareSecurityKey.code(), 2);
    assert_eq!(ControllerClass::OfflineRecovery.code(), 3);
    assert_eq!(ControllerClass::GuardianAccount.code(), 4);
    assert_eq!(ControllerClass::Institutional.code(), 5);

    let scope = ControllerScope::operations(vec![
        OperationKind::RevokeDevice,
        OperationKind::AuthorizeDevice,
    ])
    .unwrap();
    assert_eq!(
        scope.as_operations().unwrap(),
        [OperationKind::AuthorizeDevice, OperationKind::RevokeDevice]
    );
    assert!(matches!(
        ControllerScope::operations(vec![
            OperationKind::AuthorizeDevice,
            OperationKind::AuthorizeDevice,
        ]),
        Err(IdentityError::DuplicateElement { .. })
    ));
    assert_eq!(
        ControllerScope::all_v1_operations()
            .to_canonical_bytes()
            .unwrap(),
        [1, 0]
    );
    assert_eq!(scope.to_canonical_bytes().unwrap(), [2, 2, 1, 6]);
}

#[test]
fn unsorted_operation_scope_wire_is_rejected_not_normalized() {
    let unsorted = postcard::to_stdvec(&(
        2_u16,
        vec![OperationKind::RevokeDevice, OperationKind::AuthorizeDevice],
    ))
    .unwrap();
    assert!(ControllerScope::from_canonical_bytes(&unsorted).is_err());
}

#[test]
fn unsorted_selector_rules_and_providers_are_rejected_not_normalized() {
    let second_controller = ControllerDescriptor::new(
        signing_key(SIGNING_KEY_2),
        ControllerClass::HardwareSecurityKey,
        ControllerWeight::new(1).unwrap(),
        ControllerScope::all_v1_operations(),
        Extensions::default(),
    )
    .unwrap();
    let mut identifiers = vec![controller(1).id().unwrap(), second_controller.id().unwrap()];
    identifiers.sort_unstable();
    identifiers.reverse();
    let unsorted_selector = postcard::to_stdvec(&(
        2_u16,
        Some(identifiers),
        Option::<Vec<ControllerClass>>::None,
    ))
    .unwrap();
    assert!(ControllerSelector::from_canonical_bytes(&unsorted_selector).is_err());

    let resolve_rule = PolicyRule::new(
        OperationKind::ResolveFork,
        RequiredWeight::new(1).unwrap(),
        ControllerSelector::any_active(),
        FreshnessRequirement::latest_known(),
        None,
        Extensions::default(),
    )
    .unwrap();
    let unsorted_policy = postcard::to_stdvec(&(
        ProtocolVersion::V1,
        vec![resolve_rule, rule(1)],
        true,
        Extensions::default(),
    ))
    .unwrap();
    assert!(ControlPolicy::from_canonical_bytes(&unsorted_policy).is_err());

    let providers = [SIGNING_KEY_1, SIGNING_KEY_2, SIGNING_KEY_3]
        .into_iter()
        .map(|key| ProviderDescriptor::new(signing_key(key), Extensions::default()).unwrap())
        .collect::<Vec<_>>();
    let canonical = ProviderPolicy::replicated(
        ProviderPolicyVersion::GENESIS,
        providers,
        ProviderQuorum::new(2).unwrap(),
        ProviderQuorum::new(3).unwrap(),
        DurationMillis::new(60_000),
        Extensions::default(),
    )
    .unwrap();
    let mut reversed = canonical.providers().unwrap().to_vec();
    reversed.reverse();
    let replicated_payload = (
        reversed,
        ProviderQuorum::new(2).unwrap(),
        ProviderQuorum::new(3).unwrap(),
        DurationMillis::new(60_000),
        ProviderRotationRule::AccountEventOnly,
    );
    let unsorted_provider_policy = postcard::to_stdvec(&(
        ProtocolVersion::V1,
        ProviderPolicyVersion::GENESIS,
        (2_u16, Some(replicated_payload)),
        Extensions::default(),
    ))
    .unwrap();
    assert!(ProviderPolicy::from_canonical_bytes(&unsorted_provider_policy).is_err());
}

#[test]
fn controller_provider_and_device_ids_are_stable() {
    let descriptor = controller(2);
    let id = descriptor.id().unwrap();
    let decoded =
        ControllerDescriptor::from_canonical_bytes(&descriptor.to_canonical_bytes().unwrap())
            .unwrap();
    assert_eq!(decoded.id().unwrap(), id);

    let provider =
        ProviderDescriptor::new(signing_key(SIGNING_KEY_2), Extensions::default()).unwrap();
    assert_eq!(
        ProviderDescriptor::from_canonical_bytes(&provider.to_canonical_bytes().unwrap())
            .unwrap()
            .id()
            .unwrap(),
        provider.id().unwrap()
    );

    let mut agreement_bytes = [0; 32];
    agreement_bytes[0] = 9;
    let device = krikos_identity::DeviceDescriptor::new(
        signing_key(SIGNING_KEY_1),
        AgreementPublicKey::x25519(agreement_bytes).unwrap(),
        EndpointPublicKey::new(signing_key(SIGNING_KEY_2)),
        Extensions::default(),
    )
    .unwrap();
    assert_eq!(
        krikos_identity::DeviceDescriptor::from_canonical_bytes(
            &device.to_canonical_bytes().unwrap()
        )
        .unwrap()
        .id()
        .unwrap(),
        device.id().unwrap()
    );

    assert!(matches!(
        krikos_identity::DeviceDescriptor::new(
            signing_key(SIGNING_KEY_1),
            AgreementPublicKey::x25519(agreement_bytes).unwrap(),
            EndpointPublicKey::new(signing_key(SIGNING_KEY_1)),
            Extensions::default(),
        ),
        Err(IdentityError::InvalidRelationship { .. })
    ));
}

#[test]
fn control_policy_sorts_rules_and_validates_weight() {
    let second = PolicyRule::new(
        OperationKind::ResolveFork,
        RequiredWeight::new(1).unwrap(),
        ControllerSelector::any_active(),
        FreshnessRequirement::latest_known(),
        None,
        Extensions::default(),
    )
    .unwrap();
    let policy = ControlPolicy::new(vec![second, rule(2)], Extensions::default()).unwrap();
    assert_eq!(
        policy.rules()[0].operation(),
        OperationKind::ChangeControlPolicy
    );
    assert!(policy.default_deny());
    policy.validate_satisfiable(&[controller(2)]).unwrap();
    assert!(matches!(
        policy.validate_satisfiable(&[controller(1)]),
        Err(IdentityError::UnsatisfiableThreshold)
    ));

    assert!(matches!(
        ControlPolicy::new(vec![rule(1), rule(1)], Extensions::default()),
        Err(IdentityError::DuplicateElement { .. })
    ));
}

#[test]
fn duplicate_active_controller_key_cannot_multiply_weight() {
    let first = controller(1);
    let second = ControllerDescriptor::new(
        signing_key(SIGNING_KEY_1),
        ControllerClass::HardwareSecurityKey,
        ControllerWeight::new(1).unwrap(),
        ControllerScope::all_v1_operations(),
        Extensions::default(),
    )
    .unwrap();
    let policy = ControlPolicy::new(vec![rule(1)], Extensions::default()).unwrap();
    assert!(matches!(
        policy.validate_satisfiable(&[first, second]),
        Err(IdentityError::DuplicateSigningKey)
    ));
}

#[test]
fn replicated_provider_policy_enforces_thresholds() {
    let providers = [SIGNING_KEY_1, SIGNING_KEY_2, SIGNING_KEY_3]
        .into_iter()
        .map(|key| ProviderDescriptor::new(signing_key(key), Extensions::default()).unwrap())
        .collect::<Vec<_>>();
    let policy = ProviderPolicy::replicated(
        ProviderPolicyVersion::GENESIS,
        providers.clone(),
        ProviderQuorum::new(2).unwrap(),
        ProviderQuorum::new(3).unwrap(),
        DurationMillis::new(60_000),
        Extensions::default(),
    )
    .unwrap();
    assert_eq!(policy.providers().unwrap().len(), 3);
    assert_eq!(
        ProviderPolicy::from_canonical_bytes(&policy.to_canonical_bytes().unwrap())
            .unwrap()
            .id()
            .unwrap(),
        policy.id().unwrap()
    );

    assert!(matches!(
        ProviderPolicy::replicated(
            ProviderPolicyVersion::GENESIS,
            vec![providers[0].clone(); MAX_TRANSPARENCY_PROVIDERS + 1],
            ProviderQuorum::new(1).unwrap(),
            ProviderQuorum::new(1).unwrap(),
            DurationMillis::new(60_000),
            Extensions::default(),
        ),
        Err(IdentityError::LimitExceeded {
            resource: "provider policy providers",
            actual,
            maximum: MAX_TRANSPARENCY_PROVIDERS,
        }) if actual == MAX_TRANSPARENCY_PROVIDERS + 1
    ));

    assert!(matches!(
        ProviderPolicy::replicated(
            ProviderPolicyVersion::GENESIS,
            providers,
            ProviderQuorum::new(3).unwrap(),
            ProviderQuorum::new(2).unwrap(),
            DurationMillis::new(60_000),
            Extensions::default(),
        ),
        Err(IdentityError::InvalidPolicy { .. })
    ));

    let duplicate_key = vec![
        ProviderDescriptor::new(signing_key(SIGNING_KEY_1), Extensions::default()).unwrap(),
        ProviderDescriptor::new(
            signing_key(SIGNING_KEY_1),
            Extensions::new(vec![
                krikos_identity::Extension::new(7, false, vec![1]).unwrap(),
            ])
            .unwrap(),
        )
        .unwrap(),
    ];
    assert!(matches!(
        ProviderPolicy::replicated(
            ProviderPolicyVersion::GENESIS,
            duplicate_key,
            ProviderQuorum::new(1).unwrap(),
            ProviderQuorum::new(2).unwrap(),
            DurationMillis::new(60_000),
            Extensions::default(),
        ),
        Err(IdentityError::DuplicateSigningKey)
    ));

    assert!(
        ProviderPolicy::replicated(
            ProviderPolicyVersion::GENESIS,
            vec![
                ProviderDescriptor::new(signing_key(SIGNING_KEY_1), Extensions::default()).unwrap()
            ],
            ProviderQuorum::new(1).unwrap(),
            ProviderQuorum::new(1).unwrap(),
            DurationMillis::new(0),
            Extensions::default(),
        )
        .is_err()
    );
}

#[test]
fn recovery_policy_supports_controller_or_private_guardian_authority() {
    let controller_authority = RecoveryAuthority::controller_threshold(ControllerThreshold::new(
        ControllerSelector::any_active(),
        RequiredWeight::new(2).unwrap(),
    ));
    let controller_policy = RecoveryPolicy::new(
        RecoveryPolicyVersion::GENESIS,
        controller_authority,
        DurationMillis::new(10_000),
        DurationMillis::new(60_000),
        Extensions::default(),
    )
    .unwrap();
    assert_eq!(
        RecoveryPolicy::from_canonical_bytes(&controller_policy.to_canonical_bytes().unwrap())
            .unwrap()
            .id()
            .unwrap(),
        controller_policy.id().unwrap()
    );

    let guardians = GuardianThreshold::new(
        GuardianSetRoot::new(Digest::new(HashAlgorithm::Blake3_256, [7; 32])).unwrap(),
        3,
        3,
        RequiredWeight::new(2).unwrap(),
    )
    .unwrap();
    RecoveryPolicy::new(
        RecoveryPolicyVersion::GENESIS,
        RecoveryAuthority::guardian_threshold(guardians),
        DurationMillis::new(10_000),
        DurationMillis::new(60_000),
        Extensions::default(),
    )
    .unwrap();

    assert!(
        GuardianThreshold::new(
            GuardianSetRoot::new(Digest::new(HashAlgorithm::Blake3_256, [8; 32])).unwrap(),
            3,
            3,
            RequiredWeight::new(4).unwrap(),
        )
        .is_err()
    );
    assert!(
        GuardianThreshold::new(
            GuardianSetRoot::new(Digest::new(HashAlgorithm::Blake3_256, [8; 32])).unwrap(),
            17,
            17,
            RequiredWeight::new(1).unwrap(),
        )
        .is_err()
    );

    assert!(
        RecoveryPolicy::new(
            RecoveryPolicyVersion::GENESIS,
            RecoveryAuthority::controller_threshold(ControllerThreshold::new(
                ControllerSelector::any_active(),
                RequiredWeight::new(1).unwrap(),
            )),
            DurationMillis::new(0),
            DurationMillis::new(60_000),
            Extensions::default(),
        )
        .is_err()
    );
    assert!(
        RecoveryPolicy::new(
            RecoveryPolicyVersion::GENESIS,
            RecoveryAuthority::controller_threshold(ControllerThreshold::new(
                ControllerSelector::any_active(),
                RequiredWeight::new(1).unwrap(),
            )),
            DurationMillis::new(60_000),
            DurationMillis::new(60_000),
            Extensions::default(),
        )
        .is_err()
    );
}

#[test]
fn recovery_control_rules_are_gates_not_duplicate_authorization_policies() {
    let nonexistent = controller(1).id().unwrap();
    let recovery_rule = PolicyRule::new(
        OperationKind::BeginRecovery,
        RequiredWeight::new(u32::MAX).unwrap(),
        ControllerSelector::controller_ids(vec![nonexistent]).unwrap(),
        FreshnessRequirement::latest_known(),
        None,
        Extensions::default(),
    )
    .unwrap();
    let policy = ControlPolicy::new(vec![recovery_rule], Extensions::default()).unwrap();
    let active = ControllerDescriptor::new(
        signing_key(SIGNING_KEY_2),
        ControllerClass::PersonalDevice,
        ControllerWeight::new(1).unwrap(),
        ControllerScope::operations(vec![
            OperationKind::BeginRecovery,
            OperationKind::CancelRecovery,
        ])
        .unwrap(),
        Extensions::default(),
    )
    .unwrap();

    policy.validate_satisfiable(&[active]).unwrap();
}

#[test]
fn controller_recovery_threshold_must_cover_begin_and_cancel_scopes() {
    let begin_only = ControllerDescriptor::new(
        signing_key(SIGNING_KEY_1),
        ControllerClass::OfflineRecovery,
        ControllerWeight::new(1).unwrap(),
        ControllerScope::operations(vec![OperationKind::BeginRecovery]).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let threshold = ControllerThreshold::new(
        ControllerSelector::any_active(),
        RequiredWeight::new(1).unwrap(),
    );

    assert_eq!(
        threshold.validate_satisfiable(&[begin_only]),
        Err(IdentityError::UnsatisfiableThreshold)
    );
}
