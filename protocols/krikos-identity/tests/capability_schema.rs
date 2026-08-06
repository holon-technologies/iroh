use krikos_identity::{
    AccountId, AuthorizationContext, CanonicalWire, CapabilityAction, CapabilityConstraint,
    CapabilityGrant, CapabilityGrantId, CapabilityNamespace, CapabilityRoot, CheckpointId,
    DelegationBody, DelegationChain, DelegationDepth, DelegationPermission, DeviceId, Digest,
    Epoch, Extensions, HashAlgorithm, IdentityError, ProtocolSignature, ResourcePath,
    ResourceSelector, SignedDelegation, Timestamp,
    limits::{
        MAX_CAPABILITY_NAME_BYTES, MAX_CONSTRAINTS_PER_CAPABILITY, MAX_DELEGATION_DEPTH,
        MAX_RESOURCE_SELECTOR_BYTES,
    },
};

fn digest(seed: u8) -> Digest {
    Digest::new(HashAlgorithm::Blake3_256, [seed; 32])
}

fn account_id(seed: u8) -> AccountId {
    AccountId::from_canonical_bytes(&digest(seed).to_canonical_bytes().unwrap()).unwrap()
}

fn checkpoint_id(seed: u8) -> CheckpointId {
    CheckpointId::from_canonical_bytes(&digest(seed).to_canonical_bytes().unwrap()).unwrap()
}

fn device_id(seed: u8) -> DeviceId {
    DeviceId::from_canonical_bytes(&digest(seed).to_canonical_bytes().unwrap()).unwrap()
}

fn capability_grant_id(seed: u8) -> CapabilityGrantId {
    CapabilityGrantId::from_canonical_bytes(&digest(seed).to_canonical_bytes().unwrap()).unwrap()
}

fn context(account_seed: u8, epoch: u64) -> AuthorizationContext {
    AuthorizationContext::new(
        account_id(account_seed),
        Epoch::new(epoch),
        checkpoint_id(epoch.to_le_bytes()[0]),
    )
}

fn path(segments: &[&[u8]]) -> ResourcePath {
    ResourcePath::new(segments.iter().map(|segment| segment.to_vec()).collect()).unwrap()
}

fn grant(
    resource: ResourceSelector,
    constraints: Vec<CapabilityConstraint>,
    delegation: DelegationPermission,
    expires_at: Option<Timestamp>,
) -> CapabilityGrant {
    CapabilityGrant::new(
        CapabilityNamespace::new("krikos.database").unwrap(),
        CapabilityAction::new("write").unwrap(),
        resource,
        constraints,
        delegation,
        expires_at,
        Extensions::default(),
    )
    .unwrap()
}

#[test]
fn capability_grant_golden_bytes_and_id_are_stable() {
    let grant = CapabilityGrant::new(
        CapabilityNamespace::new("krikos.game").unwrap(),
        CapabilityAction::new("sign-move").unwrap(),
        ResourceSelector::exact(path(&[b"match", b"42"])).unwrap(),
        vec![
            CapabilityConstraint::ValidFrom(Timestamp::from_unix_millis(100)),
            CapabilityConstraint::AccountEpochAtLeast(Epoch::new(3)),
        ],
        DelegationPermission::delegable(DelegationDepth::new(2).unwrap()),
        Some(Timestamp::from_unix_millis(200)),
        Extensions::default(),
    )
    .unwrap();

    let expected = hex::decode(concat!(
        "01",
        "0b6b72696b6f732e67616d65",
        "097369676e2d6d6f7665",
        "0102056d61746368023432",
        "0201030364",
        "0202",
        "01c801",
        "00",
    ))
    .unwrap();
    assert_eq!(grant.to_canonical_bytes().unwrap(), expected);
    assert_eq!(
        CapabilityGrant::from_canonical_bytes(&expected).unwrap(),
        grant
    );

    let grant_id = grant.capability_grant_id().unwrap();
    assert_eq!(
        grant_id.to_string(),
        "b3:3cc2b6caf0c765c8deb1a749978953ebb630fd8d5423e6dcc3408113ef87d19e"
    );
}

#[test]
fn delegation_body_golden_bytes_and_id_are_stable() {
    let child_grant = CapabilityGrant::new(
        CapabilityNamespace::new("n").unwrap(),
        CapabilityAction::new("a").unwrap(),
        ResourceSelector::exact(path(&[b"x"])).unwrap(),
        Vec::new(),
        DelegationPermission::NotDelegable,
        None,
        Extensions::default(),
    )
    .unwrap();
    let body = DelegationBody::new(
        capability_grant_id(9),
        child_grant,
        device_id(1),
        device_id(2),
        context(3, 5),
        Timestamp::from_unix_millis(7),
        [8; 16],
        Extensions::default(),
    )
    .unwrap();

    let mut expected = vec![1, 1];
    expected.extend_from_slice(&[9; 32]);
    expected.extend_from_slice(&hex::decode("01016e0161010101780001000000").unwrap());
    expected.push(1);
    expected.extend_from_slice(&[1; 32]);
    expected.push(1);
    expected.extend_from_slice(&[2; 32]);
    expected.push(1);
    expected.extend_from_slice(&[3; 32]);
    expected.push(5);
    expected.push(1);
    expected.extend_from_slice(&[5; 32]);
    expected.push(7);
    expected.extend_from_slice(&[8; 16]);
    expected.push(0);

    assert_eq!(body.to_canonical_bytes().unwrap(), expected);
    assert_eq!(
        DelegationBody::from_canonical_bytes(&expected).unwrap(),
        body
    );
    assert_eq!(
        body.delegation_id().unwrap().to_string(),
        "b3:466ccccfebb378badd1f067864b859439d9a7b6a44ed7455f0f8b27915466b45"
    );
}

#[test]
fn names_paths_and_constraints_enforce_closed_bounds() {
    assert!(matches!(
        CapabilityNamespace::new(""),
        Err(IdentityError::EmptyCollection { .. })
    ));
    assert!(matches!(
        CapabilityAction::new("x".repeat(MAX_CAPABILITY_NAME_BYTES + 1)),
        Err(IdentityError::LimitExceeded { .. })
    ));
    assert!(CapabilityAction::new("é".repeat(MAX_CAPABILITY_NAME_BYTES / 2)).is_ok());
    assert!(
        CapabilityAction::new(format!("{}a", "é".repeat(MAX_CAPABILITY_NAME_BYTES / 2))).is_err()
    );

    assert!(matches!(
        ResourcePath::new(Vec::new()),
        Err(IdentityError::EmptyCollection { .. })
    ));
    assert!(matches!(
        ResourcePath::new(vec![Vec::new()]),
        Err(IdentityError::EmptyCollection { .. })
    ));
    assert!(ResourcePath::new(vec![vec![7]; 64]).is_ok());
    assert!(matches!(
        ResourcePath::new(vec![vec![7]; 65]),
        Err(IdentityError::LimitExceeded { .. })
    ));
    assert!(matches!(
        ResourcePath::new(vec![vec![7; MAX_RESOURCE_SELECTOR_BYTES]]),
        Err(IdentityError::LimitExceeded { .. })
    ));

    // Constructing a contradictory range is rejected before a grant exists.
    assert!(matches!(
        CapabilityGrant::new(
            CapabilityNamespace::new("krikos.database").unwrap(),
            CapabilityAction::new("write").unwrap(),
            ResourceSelector::prefix(path(&[b"collection"])).unwrap(),
            vec![
                CapabilityConstraint::AccountEpochAtLeast(Epoch::new(9)),
                CapabilityConstraint::AccountEpochAtMost(Epoch::new(8)),
            ],
            DelegationPermission::NotDelegable,
            None,
            Extensions::default(),
        ),
        Err(IdentityError::InvalidCapability { .. })
    ));

    let duplicate_constraints = vec![
        CapabilityConstraint::ValidFrom(Timestamp::from_unix_millis(1));
        MAX_CONSTRAINTS_PER_CAPABILITY.min(2)
    ];
    assert!(matches!(
        CapabilityGrant::new(
            CapabilityNamespace::new("krikos.database").unwrap(),
            CapabilityAction::new("write").unwrap(),
            ResourceSelector::exact(path(&[b"record"])).unwrap(),
            duplicate_constraints,
            DelegationPermission::NotDelegable,
            None,
            Extensions::default(),
        ),
        Err(IdentityError::DuplicateElement { .. })
    ));

    let excessive_constraints = vec![
        CapabilityConstraint::ValidFrom(Timestamp::from_unix_millis(1));
        MAX_CONSTRAINTS_PER_CAPABILITY + 1
    ];
    assert!(matches!(
        CapabilityGrant::new(
            CapabilityNamespace::new("krikos.database").unwrap(),
            CapabilityAction::new("write").unwrap(),
            ResourceSelector::exact(path(&[b"record"])).unwrap(),
            excessive_constraints,
            DelegationPermission::NotDelegable,
            None,
            Extensions::default(),
        ),
        Err(IdentityError::LimitExceeded { .. })
    ));
}

#[test]
fn closed_tags_and_noncanonical_wire_forms_are_rejected() {
    assert!(CapabilityConstraint::from_canonical_bytes(&[4, 0]).is_err());
    assert!(DelegationPermission::from_canonical_bytes(&[1, 1]).is_err());
    assert!(ResourceSelector::from_canonical_bytes(&[3, 1, 1, b'x']).is_err());

    let mut oversized_name = vec![0x81, 0x01];
    oversized_name.extend_from_slice(&[b'a'; MAX_CAPABILITY_NAME_BYTES + 1]);
    assert!(CapabilityAction::from_canonical_bytes(&oversized_name).is_err());
    assert!(CapabilityNamespace::from_canonical_bytes(&[1, 0xff]).is_err());

    // Exact selector, one path segment, declared segment length 1025. The bounded
    // segment visitor rejects the declared size before attempting to allocate it.
    assert!(ResourceSelector::from_canonical_bytes(&[1, 1, 0x81, 0x08]).is_err());

    // Constraint code 3 precedes code 1. Constructors sort, but decoders reject
    // wire input that is not already in canonical registry-code order.
    let unsorted_grant = hex::decode("01016e016101010178020301010101000000").unwrap();
    assert!(CapabilityGrant::from_canonical_bytes(&unsorted_grant).is_err());
}

#[test]
fn delegation_chain_accepts_only_semantic_strict_narrowing() {
    let root_grant = grant(
        ResourceSelector::prefix(path(&[b"collection"])).unwrap(),
        vec![CapabilityConstraint::AccountEpochAtLeast(Epoch::new(1))],
        DelegationPermission::delegable(DelegationDepth::new(2).unwrap()),
        Some(Timestamp::from_unix_millis(300)),
    );
    let root = CapabilityRoot::new(
        context(1, 1),
        device_id(10),
        root_grant.clone(),
        Extensions::default(),
    )
    .unwrap();

    let child_one = grant(
        ResourceSelector::prefix(path(&[b"collection", b"blue"])).unwrap(),
        vec![CapabilityConstraint::AccountEpochAtLeast(Epoch::new(2))],
        DelegationPermission::delegable(DelegationDepth::new(1).unwrap()),
        Some(Timestamp::from_unix_millis(250)),
    );
    let first_body = DelegationBody::new(
        root_grant.capability_grant_id().unwrap(),
        child_one.clone(),
        device_id(10),
        device_id(11),
        context(1, 2),
        Timestamp::from_unix_millis(20),
        [1; 16],
        Extensions::default(),
    )
    .unwrap();
    let first = SignedDelegation::new(first_body, ProtocolSignature::ed25519([1; 64]));

    let child_two = grant(
        ResourceSelector::exact(path(&[b"collection", b"blue", b"record-7"])).unwrap(),
        vec![CapabilityConstraint::AccountEpochAtLeast(Epoch::new(2))],
        DelegationPermission::NotDelegable,
        Some(Timestamp::from_unix_millis(250)),
    );
    let second_body = DelegationBody::new(
        child_one.capability_grant_id().unwrap(),
        child_two.clone(),
        device_id(11),
        device_id(12),
        context(1, 2),
        Timestamp::from_unix_millis(21),
        [2; 16],
        Extensions::default(),
    )
    .unwrap();
    let second = SignedDelegation::new(second_body, ProtocolSignature::ed25519([2; 64]));

    assert!(matches!(
        DelegationChain::new(root.clone(), vec![second.clone(), first.clone()]),
        Err(IdentityError::InvalidDelegation { .. })
    ));

    let cycle = SignedDelegation::new(
        DelegationBody::new(
            child_one.capability_grant_id().unwrap(),
            child_two.clone(),
            device_id(11),
            device_id(10),
            context(1, 2),
            Timestamp::from_unix_millis(21),
            [9; 16],
            Extensions::default(),
        )
        .unwrap(),
        ProtocolSignature::ed25519([9; 64]),
    );
    assert!(matches!(
        DelegationChain::new(root.clone(), vec![first.clone(), cycle]),
        Err(IdentityError::InvalidDelegation { .. })
    ));

    let chain = DelegationChain::new(root, vec![first, second]).unwrap();
    assert_eq!(chain.links().len(), 2);
    assert_eq!(chain.leaf_grant(), &child_two);
    let encoded = chain.to_canonical_bytes().unwrap();
    assert_eq!(
        DelegationChain::from_canonical_bytes(&encoded).unwrap(),
        chain
    );
}

#[test]
fn delegation_chain_rejects_broadening_wrong_order_and_cross_account_links() {
    let root_grant = grant(
        ResourceSelector::prefix(path(&[b"collection", b"blue"])).unwrap(),
        vec![CapabilityConstraint::AccountEpochAtLeast(Epoch::new(4))],
        DelegationPermission::delegable(DelegationDepth::new(2).unwrap()),
        Some(Timestamp::from_unix_millis(200)),
    );
    let root = CapabilityRoot::new(
        context(1, 4),
        device_id(1),
        root_grant.clone(),
        Extensions::default(),
    )
    .unwrap();

    let broader = grant(
        ResourceSelector::prefix(path(&[b"collection"])).unwrap(),
        vec![CapabilityConstraint::AccountEpochAtLeast(Epoch::new(3))],
        DelegationPermission::delegable(DelegationDepth::new(1).unwrap()),
        Some(Timestamp::from_unix_millis(201)),
    );
    let broadening = SignedDelegation::new(
        DelegationBody::new(
            root_grant.capability_grant_id().unwrap(),
            broader,
            device_id(1),
            device_id(2),
            context(1, 4),
            Timestamp::from_unix_millis(10),
            [3; 16],
            Extensions::default(),
        )
        .unwrap(),
        ProtocolSignature::ed25519([3; 64]),
    );
    assert!(matches!(
        DelegationChain::new(root.clone(), vec![broadening]),
        Err(IdentityError::InvalidDelegation { .. })
    ));

    let narrowed = grant(
        ResourceSelector::exact(path(&[b"collection", b"blue", b"record"])).unwrap(),
        vec![CapabilityConstraint::AccountEpochAtLeast(Epoch::new(5))],
        DelegationPermission::delegable(DelegationDepth::new(1).unwrap()),
        Some(Timestamp::from_unix_millis(190)),
    );
    let cross_account = SignedDelegation::new(
        DelegationBody::new(
            root_grant.capability_grant_id().unwrap(),
            narrowed,
            device_id(1),
            device_id(2),
            context(9, 5),
            Timestamp::from_unix_millis(10),
            [4; 16],
            Extensions::default(),
        )
        .unwrap(),
        ProtocolSignature::ed25519([4; 64]),
    );
    assert!(matches!(
        DelegationChain::new(root.clone(), vec![cross_account]),
        Err(IdentityError::InvalidDelegation { .. })
    ));

    assert!(matches!(
        DelegationChain::new(root.clone(), Vec::new()),
        Err(IdentityError::EmptyCollection { .. })
    ));

    let repeated = (0..=MAX_DELEGATION_DEPTH)
        .map(|index| {
            let index_byte = index.to_le_bytes()[0];
            let child = grant(
                ResourceSelector::exact(path(&[b"collection", b"blue"])).unwrap(),
                vec![CapabilityConstraint::AccountEpochAtLeast(Epoch::new(5))],
                DelegationPermission::NotDelegable,
                Some(Timestamp::from_unix_millis(190)),
            );
            SignedDelegation::new(
                DelegationBody::new(
                    root_grant.capability_grant_id().unwrap(),
                    child,
                    device_id(1),
                    device_id(index_byte.saturating_add(20)),
                    context(1, 5),
                    Timestamp::from_unix_millis(10),
                    [index_byte; 16],
                    Extensions::default(),
                )
                .unwrap(),
                ProtocolSignature::ed25519([index_byte; 64]),
            )
        })
        .collect();
    assert!(matches!(
        DelegationChain::new(root, repeated),
        Err(IdentityError::LimitExceeded { .. })
    ));
}
