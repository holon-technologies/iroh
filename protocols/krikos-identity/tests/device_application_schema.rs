use krikos_identity::{
    AccountId, AgreementPublicKey, ApplicationEventBody, ApplicationEventCounter, ApplicationId,
    CanonicalWire, CapabilityAction, CapabilityGrant, CapabilityNamespace, CheckpointId,
    CryptoSuiteDescriptor, CryptoSuiteId, DelegationPermission, DeviceAuthorization,
    DeviceAuthorizationUpdate, DeviceClass, DeviceDescriptor, DeviceId, DeviceMetadataUpdate,
    DeviceUpdate, Digest, EndpointPublicKey, Epoch, Extension, Extensions, GroupId, GroupKeyEpoch,
    GroupKeyWrapHeader, HashAlgorithm, IdentityError, KeyWrapNonce, ProtocolSignature,
    RecipientKeyWraps, ReinstateDevice, ResourcePath, ResourceSelector, RevocationReasonCode,
    RevokeDevice, RotateDeviceKeys, SignedApplicationEvent, SigningPublicKey, SuspendDevice,
    WrappedGroupKey,
    limits::{MAX_APPLICATION_PAYLOAD_BYTES, MAX_CAPABILITIES_PER_DEVICE, MAX_KEY_WRAP_BYTES},
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

fn digest(seed: u8) -> Digest {
    Digest::new(HashAlgorithm::Blake3_256, [seed; 32])
}

fn typed_id<T: CanonicalWire>(seed: u8) -> T {
    T::from_canonical_bytes(&digest(seed).to_canonical_bytes().unwrap()).unwrap()
}

fn v1_suite_id() -> CryptoSuiteId {
    CryptoSuiteDescriptor::v1()
        .unwrap()
        .crypto_suite_id()
        .unwrap()
}

fn signing_key(bytes: [u8; 32]) -> SigningPublicKey {
    SigningPublicKey::ed25519(bytes).unwrap()
}

fn descriptor(seed: u8) -> DeviceDescriptor {
    let signing = if seed & 1 == 0 {
        SIGNING_KEY_1
    } else {
        SIGNING_KEY_2
    };
    let endpoint = if seed & 1 == 0 {
        SIGNING_KEY_2
    } else {
        SIGNING_KEY_3
    };
    let mut agreement = [0_u8; 32];
    agreement[0] = seed.max(9);
    DeviceDescriptor::new(
        signing_key(signing),
        AgreementPublicKey::x25519(agreement).unwrap(),
        EndpointPublicKey::new(signing_key(endpoint)),
        Extensions::default(),
    )
    .unwrap()
}

fn capability(namespace: &str, action: &str) -> CapabilityGrant {
    CapabilityGrant::new(
        CapabilityNamespace::new(namespace).unwrap(),
        CapabilityAction::new(action).unwrap(),
        ResourceSelector::exact(ResourcePath::new(vec![b"root".to_vec()]).unwrap()).unwrap(),
        Vec::new(),
        DelegationPermission::NotDelegable,
        None,
        Extensions::default(),
    )
    .unwrap()
}

fn commitment(seed: u8) -> krikos_identity::BlindedMetadataCommitment {
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = seed.wrapping_add(u8::try_from(index).unwrap());
    }
    krikos_identity::BlindedMetadataCommitment::new(bytes).unwrap()
}

fn authorization(seed: u8) -> DeviceAuthorization {
    let descriptor = descriptor(seed);
    DeviceAuthorization::new(
        descriptor.id().unwrap(),
        descriptor,
        DeviceClass::ApplicationOnly,
        Some(commitment(seed)),
        vec![capability("krikos.test", "read")],
        Epoch::new(2),
        Extensions::default(),
    )
    .unwrap()
}

#[test]
fn device_classes_commitments_and_updates_are_closed_and_canonical() {
    assert_eq!(DeviceClass::GeneralPurpose.code(), 1);
    assert_eq!(DeviceClass::HardwareBacked.code(), 2);
    assert_eq!(DeviceClass::ApplicationOnly.code(), 3);
    assert_eq!(DeviceClass::Service.code(), 4);
    assert_eq!(
        DeviceClass::GeneralPurpose.to_canonical_bytes().unwrap(),
        [1]
    );
    assert!(DeviceClass::from_canonical_bytes(&[5]).is_err());

    assert!(krikos_identity::BlindedMetadataCommitment::new([0; 32]).is_err());
    assert!(krikos_identity::BlindedMetadataCommitment::new([7; 32]).is_err());

    let auth = authorization(9);
    let authorization_update = DeviceAuthorizationUpdate::new(
        auth.device_id(),
        DeviceClass::HardwareBacked,
        vec![capability("krikos.test", "write")],
        Epoch::new(3),
        Extensions::default(),
    )
    .unwrap();
    let metadata_update = DeviceMetadataUpdate::new(
        auth.device_id(),
        Some(commitment(31)),
        Extensions::default(),
    )
    .unwrap();
    let authorization_wire = DeviceUpdate::Authorization(authorization_update)
        .to_canonical_bytes()
        .unwrap();
    let metadata_wire = DeviceUpdate::Metadata(metadata_update)
        .to_canonical_bytes()
        .unwrap();
    assert_eq!(authorization_wire[0], 1);
    assert_eq!(metadata_wire[0], 2);
    assert!(
        DeviceUpdate::from_canonical_bytes(&postcard::to_stdvec(&(99_u16, ())).unwrap()).is_err()
    );
}

#[test]
fn authorization_binds_descriptor_and_rejects_oversized_or_noncanonical_grant_sets() {
    let descriptor = descriptor(10);
    let wrong_id: DeviceId = typed_id(99);
    assert!(matches!(
        DeviceAuthorization::new(
            wrong_id,
            descriptor.clone(),
            DeviceClass::GeneralPurpose,
            None,
            Vec::new(),
            Epoch::GENESIS,
            Extensions::default(),
        ),
        Err(IdentityError::InvalidIdentifier { .. })
    ));

    let grant = capability("krikos.test", "read");
    assert!(matches!(
        DeviceAuthorization::new(
            descriptor.id().unwrap(),
            descriptor.clone(),
            DeviceClass::GeneralPurpose,
            None,
            vec![grant; MAX_CAPABILITIES_PER_DEVICE + 1],
            Epoch::GENESIS,
            Extensions::default(),
        ),
        Err(IdentityError::LimitExceeded { .. })
    ));

    let mut grants = vec![
        capability("krikos.test", "read"),
        capability("krikos.test", "write"),
    ];
    grants.sort_unstable_by_key(|grant| grant.capability_grant_id().unwrap());
    grants.reverse();
    let unsorted = postcard::to_stdvec(&(
        krikos_identity::ProtocolVersion::V1,
        descriptor.id().unwrap(),
        descriptor,
        DeviceClass::GeneralPurpose,
        Option::<krikos_identity::BlindedMetadataCommitment>::None,
        grants,
        Epoch::GENESIS,
        Extensions::default(),
    ))
    .unwrap();
    assert!(DeviceAuthorization::from_canonical_bytes(&unsorted).is_err());
}

#[test]
fn lifecycle_payloads_are_typed_and_rotation_is_atomic() {
    let old = authorization(9);
    let new = authorization(10);
    let suspend = SuspendDevice::new(old.device_id(), Extensions::default()).unwrap();
    let reinstate = ReinstateDevice::new(old.device_id(), Extensions::default()).unwrap();
    let revoke = RevokeDevice::new(
        old.device_id(),
        Some(RevocationReasonCode::new(7).unwrap()),
        Extensions::default(),
    )
    .unwrap();
    assert_eq!(suspend.device_id(), reinstate.device_id());
    assert_eq!(revoke.reason_code().unwrap().get(), 7);
    assert!(RotateDeviceKeys::new(old.device_id(), old.clone(), Extensions::default()).is_err());

    let rotation = RotateDeviceKeys::new(old.device_id(), new, Extensions::default()).unwrap();
    assert_ne!(
        rotation.old_device_id(),
        rotation.new_authorization().device_id()
    );
    assert_eq!(
        RotateDeviceKeys::from_canonical_bytes(&rotation.to_canonical_bytes().unwrap()).unwrap(),
        rotation
    );

    let critical = Extensions::new(vec![Extension::new(77, true, vec![1]).unwrap()]).unwrap();
    assert!(DeviceMetadataUpdate::new(old.device_id(), None, critical).is_err());
}

#[test]
fn signed_application_event_is_context_bound_bounded_and_stable() {
    let auth = authorization(9);
    let body = ApplicationEventBody::new(
        typed_id::<AccountId>(1),
        ApplicationId::new(digest(2)),
        auth.device_id(),
        Epoch::new(4),
        typed_id::<CheckpointId>(3),
        ApplicationEventCounter::new(8),
        b"ok".to_vec(),
        Extensions::default(),
    )
    .unwrap();
    let signed = SignedApplicationEvent::new(body, ProtocolSignature::ed25519([5; 64])).unwrap();
    signed.validate_authorization(&auth).unwrap();
    assert_eq!(
        SignedApplicationEvent::from_canonical_bytes(&signed.to_canonical_bytes().unwrap())
            .unwrap(),
        signed
    );
    assert_eq!(
        signed.application_event_id().unwrap().to_string(),
        "b3:72587781c758650dfe6fa6a7dbd3dc1dad7aa464c79c13b3f89cd46cc8b1a285"
    );
    assert_eq!(
        hex::encode(signed.to_canonical_bytes().unwrap()),
        "01010101010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202017e5dc5cf5bb6d50a38d7bd5cca8e6e8d6bf653c38ed04155fb8ce4aa45988ffb0401030303030303030303030303030303030303030303030303030303030303030308026f6b000105050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505"
    );

    let stale = ApplicationEventBody::new(
        typed_id::<AccountId>(1),
        ApplicationId::new(digest(2)),
        auth.device_id(),
        Epoch::new(1),
        typed_id::<CheckpointId>(3),
        ApplicationEventCounter::GENESIS,
        Vec::new(),
        Extensions::default(),
    )
    .unwrap();
    let stale = SignedApplicationEvent::new(stale, ProtocolSignature::ed25519([5; 64])).unwrap();
    assert!(stale.validate_authorization(&auth).is_err());

    assert!(
        ApplicationEventBody::new(
            typed_id::<AccountId>(1),
            ApplicationId::new(digest(2)),
            auth.device_id(),
            Epoch::new(4),
            typed_id::<CheckpointId>(3),
            ApplicationEventCounter::GENESIS,
            vec![0; MAX_APPLICATION_PAYLOAD_BYTES + 1],
            Extensions::default(),
        )
        .is_err()
    );
    let large_extensions = Extensions::new(
        (1_u32..=4)
            .map(|code| {
                Extension::new(code, false, vec![u8::try_from(code).unwrap(); 16 * 1024]).unwrap()
            })
            .collect(),
    )
    .unwrap();
    let oversized_envelope_body = ApplicationEventBody::new(
        typed_id::<AccountId>(1),
        ApplicationId::new(digest(2)),
        auth.device_id(),
        Epoch::new(4),
        typed_id::<CheckpointId>(3),
        ApplicationEventCounter::GENESIS,
        vec![0; MAX_APPLICATION_PAYLOAD_BYTES],
        large_extensions,
    )
    .unwrap();
    assert!(
        SignedApplicationEvent::new(oversized_envelope_body, ProtocolSignature::ed25519([5; 64]),)
            .is_err()
    );
    let critical = Extensions::new(vec![Extension::new(91, true, vec![1]).unwrap()]).unwrap();
    assert!(
        ApplicationEventBody::new(
            typed_id::<AccountId>(1),
            ApplicationId::new(digest(2)),
            auth.device_id(),
            Epoch::new(4),
            typed_id::<CheckpointId>(3),
            ApplicationEventCounter::GENESIS,
            Vec::new(),
            critical,
        )
        .is_err()
    );
    assert!(
        ApplicationEventCounter::new(u64::MAX)
            .checked_next()
            .is_err()
    );
}

#[test]
fn key_wrap_header_binds_recipient_and_context() {
    let auth = authorization(9);
    let suite_id = v1_suite_id();
    let account_id: AccountId = typed_id(12);
    let application_id = ApplicationId::new(digest(13));
    let group_id = GroupId::new(digest(14));
    let ephemeral = AgreementPublicKey::x25519({
        let mut bytes = [0; 32];
        bytes[0] = 21;
        bytes
    })
    .unwrap();
    let nonce = KeyWrapNonce::new([19; 24]);
    let header = GroupKeyWrapHeader::new_for_recipient(
        suite_id,
        account_id,
        application_id,
        group_id,
        Epoch::new(4),
        GroupKeyEpoch::new(2),
        &auth,
        ephemeral,
        nonce,
        Extensions::default(),
    )
    .unwrap();
    header.validate_recipient(&auth).unwrap();
    assert_eq!(header.recipient_device_id(), auth.device_id());

    let wrong_auth = authorization(10);
    assert!(header.validate_recipient(&wrong_auth).is_err());
    assert_eq!(KeyWrapNonce::new([0; 24]).as_bytes(), &[0; 24]);
    assert!(
        GroupKeyWrapHeader::new_for_recipient(
            suite_id,
            account_id,
            application_id,
            group_id,
            Epoch::new(4),
            GroupKeyEpoch::new(2),
            &auth,
            auth.descriptor().agreement_key(),
            nonce,
            Extensions::default(),
        )
        .is_err()
    );
    let critical = Extensions::new(vec![Extension::new(92, true, vec![1]).unwrap()]).unwrap();
    assert!(
        GroupKeyWrapHeader::new_for_recipient(
            suite_id,
            account_id,
            application_id,
            group_id,
            Epoch::new(4),
            GroupKeyEpoch::new(2),
            &auth,
            ephemeral,
            nonce,
            critical,
        )
        .is_err()
    );
}

#[test]
fn wrapped_keys_are_bounded_sorted_unique_and_have_stable_ids() {
    let first = authorization(9);
    let second = authorization(10);
    let suite_id = v1_suite_id();
    let account_id: AccountId = typed_id(22);
    let application_id = ApplicationId::new(digest(23));
    let group_id = GroupId::new(digest(24));
    let make_wrap = |authorization: &DeviceAuthorization, nonce_seed: u8| {
        let ephemeral = AgreementPublicKey::x25519({
            let mut bytes = [0; 32];
            bytes[0] = nonce_seed.wrapping_add(17);
            bytes
        })
        .unwrap();
        let header = GroupKeyWrapHeader::new_for_recipient(
            suite_id,
            account_id,
            application_id,
            group_id,
            Epoch::new(7),
            GroupKeyEpoch::new(3),
            authorization,
            ephemeral,
            KeyWrapNonce::new([nonce_seed; 24]),
            Extensions::default(),
        )
        .unwrap();
        WrappedGroupKey::new(header, vec![nonce_seed; 48], Extensions::default()).unwrap()
    };
    let first_wrap = make_wrap(&first, 31);
    let second_wrap = make_wrap(&second, 32);
    assert_eq!(
        first_wrap.group_key_wrap_id().unwrap().to_string(),
        "b3:1196705741b216350b7aa5a0b81c30177b7537c35ddeeb7f3fe4a3c8740c7816"
    );
    let actual_wrap_bytes = hex::encode(first_wrap.to_canonical_bytes().unwrap());
    let expected_wrap_bytes = format!(
        "{}{}00",
        "01018ff40ee1a62f16342b90d738eb35827198fecb38c8b8cef4e949427a1d7b27ea0116161616161616161616161616161616161616161616161616161616161616160117171717171717171717171717171717171717171717171717171717171717170118181818181818181818181818181818181818181818181818181818181818180703017e5dc5cf5bb6d50a38d7bd5cca8e6e8d6bf653c38ed04155fb8ce4aa45988ffb01e427efacc4b7fe639631f9af0447d539676a9627f5a928eb4f6410988fee2d2f0130000000000000000000000000000000000000000000000000000000000000001f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f0030",
        "1f".repeat(48),
    );
    assert_eq!(actual_wrap_bytes.len(), expected_wrap_bytes.len());
    assert_eq!(actual_wrap_bytes, expected_wrap_bytes);
    assert!(
        WrappedGroupKey::new(
            first_wrap.header().clone(),
            vec![0; MAX_KEY_WRAP_BYTES + 1],
            Extensions::default(),
        )
        .is_err()
    );
    assert!(RecipientKeyWraps::new(vec![first_wrap.clone(), first_wrap.clone()]).is_err());
    let reused_ephemeral_and_nonce = make_wrap(&second, 31);
    assert!(RecipientKeyWraps::new(vec![first_wrap.clone(), reused_ephemeral_and_nonce]).is_err());

    let set = RecipientKeyWraps::new(vec![second_wrap.clone(), first_wrap.clone()]).unwrap();
    assert_eq!(set.as_slice().len(), 2);
    assert!(set.as_slice()[0].recipient_device_id() < set.as_slice()[1].recipient_device_id());
    assert_eq!(
        RecipientKeyWraps::from_canonical_bytes(&set.to_canonical_bytes().unwrap()).unwrap(),
        set
    );

    let mut reversed = set.as_slice().to_vec();
    reversed.reverse();
    let noncanonical = postcard::to_stdvec(&reversed).unwrap();
    assert!(RecipientKeyWraps::from_canonical_bytes(&noncanonical).is_err());
}
