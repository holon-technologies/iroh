use krikos_identity::*;

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

fn digest(fill: u8) -> Digest {
    Digest::new(HashAlgorithm::Blake3_256, [fill; 32])
}

fn typed_id<T: CanonicalWire>(fill: u8) -> T {
    T::from_canonical_bytes(&digest(fill).to_canonical_bytes().unwrap()).unwrap()
}

fn controller() -> ControllerDescriptor {
    ControllerDescriptor::new(
        SigningPublicKey::ed25519(SIGNING_KEY_1).unwrap(),
        ControllerClass::PersonalDevice,
        ControllerWeight::new(1).unwrap(),
        ControllerScope::all_v1_operations(),
        Extensions::default(),
    )
    .unwrap()
}

fn device_descriptor(signing: [u8; 32], endpoint: [u8; 32]) -> DeviceDescriptor {
    let mut agreement = [0_u8; 32];
    agreement[0] = 9;
    DeviceDescriptor::new(
        SigningPublicKey::ed25519(signing).unwrap(),
        AgreementPublicKey::x25519(agreement).unwrap(),
        EndpointPublicKey::new(SigningPublicKey::ed25519(endpoint).unwrap()),
        Extensions::default(),
    )
    .unwrap()
}

fn device_authorization(signing: [u8; 32], endpoint: [u8; 32]) -> DeviceAuthorization {
    let descriptor = device_descriptor(signing, endpoint);
    DeviceAuthorization::new(
        descriptor.id().unwrap(),
        descriptor,
        DeviceClass::GeneralPurpose,
        None,
        Vec::new(),
        Epoch::new(2),
        Extensions::default(),
    )
    .unwrap()
}

fn policy_rule(operation: OperationKind) -> PolicyRule {
    PolicyRule::new(
        operation,
        RequiredWeight::new(1).unwrap(),
        ControllerSelector::any_active(),
        FreshnessRequirement::latest_known(),
        None,
        Extensions::default(),
    )
    .unwrap()
}

fn control_policy() -> ControlPolicy {
    ControlPolicy::new(
        vec![policy_rule(OperationKind::ChangeControlPolicy)],
        Extensions::default(),
    )
    .unwrap()
}

fn recovery_policy(version: u64) -> RecoveryPolicy {
    RecoveryPolicy::new(
        RecoveryPolicyVersion::new(version),
        RecoveryAuthority::controller_threshold(ControllerThreshold::new(
            ControllerSelector::any_active(),
            RequiredWeight::new(1).unwrap(),
        )),
        DurationMillis::new(100),
        DurationMillis::new(1_000),
        Extensions::default(),
    )
    .unwrap()
}

fn recovery_proposal() -> RecoveryProposal {
    let plan = RecoveryAuthorityPlan::try_new(
        ProtocolVersion::V1,
        typed_id::<AccountId>(1),
        typed_id::<CheckpointId>(2),
        typed_id::<EventId>(3),
        typed_id::<RecoveryPolicyId>(4),
        RecoveryPolicyVersion::new(4),
        [5; 32],
        vec![controller()],
        control_policy(),
        recovery_policy(5),
        Vec::new(),
        Timestamp::from_unix_millis(2_000),
        Extensions::default(),
    )
    .unwrap();
    RecoveryProposal::try_new(ProtocolVersion::V1, plan, Extensions::default()).unwrap()
}

fn provider_receipt(account_id: AccountId, proposal_id: ProposalId) -> InclusionReceipt {
    let provider_id = typed_id::<ProviderId>(31);
    let log_id = typed_id::<ProviderLogId>(32);
    let entry = ProviderLogEntryBody::new(
        provider_id,
        log_id,
        account_id,
        ProviderLogSubject::EventIntent(proposal_id),
        Timestamp::from_unix_millis(300),
        Extensions::default(),
    )
    .unwrap();
    let head = ProviderHeadBody::new(
        provider_id,
        log_id,
        ProviderKeyVersion::GENESIS,
        1,
        digest(33),
        Timestamp::from_unix_millis(301),
        Extensions::default(),
    )
    .unwrap();
    InclusionReceipt::new(
        entry,
        0,
        Vec::new(),
        SignedProviderHead::new(head, ProtocolSignature::ed25519([34; 64])),
    )
    .unwrap()
}

fn recovery_operations() -> (
    BeginRecovery,
    VetoRecovery,
    CancelRecovery,
    FinalizeRecovery,
) {
    let proposal = recovery_proposal();
    let recovery_id = proposal.recovery_id().unwrap();
    let evidence = RecoveryThresholdEvidence::controller_policy(
        proposal.plan().recovery_policy_id(),
        proposal.plan().recovery_policy_version(),
    );
    let begin = BeginRecovery::try_new(
        ProtocolVersion::V1,
        proposal.clone(),
        evidence.clone(),
        Extensions::default(),
    )
    .unwrap();
    let freshness = FreshnessEvidence::local_known(proposal.plan().prior_checkpoint_id());
    let veto = VetoRecovery::try_new(
        ProtocolVersion::V1,
        recovery_id,
        typed_id::<ControlPolicyId>(35),
        freshness.clone(),
        Extensions::default(),
    )
    .unwrap();
    let cancel = CancelRecovery::try_new(
        ProtocolVersion::V1,
        recovery_id,
        evidence,
        freshness,
        Extensions::default(),
    )
    .unwrap();
    let begin_proposal_id = typed_id::<ProposalId>(36);
    let receipts = ProviderReceipts::new(vec![provider_receipt(
        proposal.plan().account_id(),
        begin_proposal_id,
    )])
    .unwrap();
    let anchor = RecoveryDelayAnchor::try_new(
        ProtocolVersion::V1,
        proposal.plan().account_id(),
        recovery_id,
        begin_proposal_id,
        typed_id::<ProviderPolicyId>(37),
        ProviderQuorum::new(1).unwrap(),
        receipts,
        Extensions::default(),
    )
    .unwrap();
    let finalize = FinalizeRecovery::try_new(
        ProtocolVersion::V1,
        recovery_id,
        anchor,
        Timestamp::from_unix_millis(400),
        Extensions::default(),
    )
    .unwrap();
    (begin, veto, cancel, finalize)
}

fn migration_parts() -> (BeginCryptoMigration, CryptoMigrationId) {
    let binding = ControllerKeyBinding::try_new(
        typed_id::<ControllerId>(41),
        typed_id::<ControllerKeyId>(42),
        AlgorithmPublicKey::new(2, vec![43]).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let migration = CryptoMigrationBody::try_new(
        ProtocolVersion::V1,
        typed_id::<AccountId>(1),
        typed_id::<CryptoSuiteId>(44),
        CryptoSuiteDescriptor::try_new(
            ProtocolVersion::V1,
            2,
            1,
            2,
            1,
            1,
            1,
            Extensions::default(),
        )
        .unwrap(),
        vec![binding],
        None,
        [45; 32],
        Extensions::default(),
    )
    .unwrap();
    let migration_id = migration.crypto_migration_id().unwrap();
    let proof = ControllerKeyBindingProof::try_new(
        migration_id,
        typed_id::<ControllerId>(41),
        AlgorithmSignature::new(1, vec![46; 64]).unwrap(),
        AlgorithmSignature::new(2, vec![47]).unwrap(),
    )
    .unwrap();
    let begin = BeginCryptoMigration::try_new(
        ProtocolVersion::V1,
        migration,
        ControllerKeyBindingProofSet::try_new(vec![proof]).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    (begin, migration_id)
}

fn account_operations() -> Vec<AccountOperation> {
    let old_authorization = device_authorization(SIGNING_KEY_1, SIGNING_KEY_2);
    let new_authorization = device_authorization(SIGNING_KEY_2, SIGNING_KEY_3);
    let old_device_id = old_authorization.device_id();
    let (begin_recovery, veto_recovery, cancel_recovery, finalize_recovery) = recovery_operations();
    let fork = ForkDescriptor::try_new(
        ProtocolVersion::V1,
        typed_id::<AccountId>(1),
        ForkCommonAncestor::Event(typed_id::<EventId>(48)),
        vec![typed_id::<EventId>(49), typed_id::<EventId>(50)],
        Extensions::default(),
    )
    .unwrap();
    let resolution = ResolveFork::try_new(
        ProtocolVersion::V1,
        fork,
        typed_id::<EventId>(49),
        vec![typed_id::<ControllerId>(51)],
        vec![typed_id::<DeviceId>(52)],
        Extensions::default(),
    )
    .unwrap();
    let (begin_migration, migration_id) = migration_parts();
    vec![
        AccountOperation::AuthorizeDevice(old_authorization.clone()),
        AccountOperation::UpdateDeviceAuthorization(
            DeviceAuthorizationUpdate::new(
                old_device_id,
                DeviceClass::HardwareBacked,
                Vec::new(),
                Epoch::new(3),
                Extensions::default(),
            )
            .unwrap(),
        ),
        AccountOperation::UpdateDeviceMetadata(
            DeviceMetadataUpdate::new(old_device_id, None, Extensions::default()).unwrap(),
        ),
        AccountOperation::SuspendDevice(
            SuspendDevice::new(old_device_id, Extensions::default()).unwrap(),
        ),
        AccountOperation::ReinstateDevice(
            ReinstateDevice::new(old_device_id, Extensions::default()).unwrap(),
        ),
        AccountOperation::RevokeDevice(
            RevokeDevice::new(
                old_device_id,
                Some(RevocationReasonCode::new(7).unwrap()),
                Extensions::default(),
            )
            .unwrap(),
        ),
        AccountOperation::RotateDeviceKeys(
            RotateDeviceKeys::new(old_device_id, new_authorization, Extensions::default()).unwrap(),
        ),
        AccountOperation::AddController(controller()),
        AccountOperation::RemoveController(typed_id::<ControllerId>(53)),
        AccountOperation::ChangeControlPolicy(control_policy()),
        AccountOperation::ChangeRecoveryPolicy(recovery_policy(6)),
        AccountOperation::ChangeProviderPolicy(
            ProviderPolicy::local_only(ProviderPolicyVersion::new(7), Extensions::default())
                .unwrap(),
        ),
        AccountOperation::BeginRecovery(begin_recovery),
        AccountOperation::VetoRecovery(veto_recovery),
        AccountOperation::CancelRecovery(cancel_recovery),
        AccountOperation::FinalizeRecovery(finalize_recovery),
        AccountOperation::ResolveFork(resolution),
        AccountOperation::BeginCryptoMigration(begin_migration),
        AccountOperation::ActivateCryptoMigration(
            ActivateCryptoMigration::try_new(
                ProtocolVersion::V1,
                migration_id,
                typed_id::<EventId>(54),
                Extensions::default(),
            )
            .unwrap(),
        ),
        AccountOperation::RetireCryptoSuite(
            RetireCryptoSuite::try_new(
                ProtocolVersion::V1,
                migration_id,
                RetireCryptoSuiteMode::AbortCandidate,
                typed_id::<EventId>(55),
                None,
                Extensions::default(),
            )
            .unwrap(),
        ),
        AccountOperation::UpgradeProtocol(
            ProtocolUpgrade::try_new(
                ProtocolVersion::V1,
                ProtocolMajor::new(1).unwrap(),
                ProtocolMajor::new(2).unwrap(),
                digest(56),
                UpgradeCompatibility::OldClientsReadOnly,
                None,
                Extensions::default(),
            )
            .unwrap(),
        ),
        AccountOperation::RetireAccount(
            RetireAccount::try_new(
                ProtocolVersion::V1,
                None,
                Some(RevocationReasonCode::new(8).unwrap()),
                Extensions::default(),
            )
            .unwrap(),
        ),
    ]
}

fn keyed_signature(fill: u8) -> KeyedSignature {
    KeyedSignature::new(
        typed_id::<CryptoSuiteId>(60),
        typed_id::<ControllerKeyId>(61),
        AlgorithmSignature::new(1, vec![fill; 64]).unwrap(),
    )
}

fn event_body() -> EventBody {
    EventBody::new(
        typed_id::<AccountId>(1),
        Sequence::new(1),
        Epoch::new(1),
        EventPredecessors::genesis(typed_id::<GenesisAnchor>(62)),
        AccountOperation::ChangeProviderPolicy(
            ProviderPolicy::local_only(ProviderPolicyVersion::new(1), Extensions::default())
                .unwrap(),
        ),
        Timestamp::from_unix_millis(63),
        [64; 16],
        Extensions::default(),
    )
    .unwrap()
}

fn authorized_event() -> AuthorizedEvent {
    let body = event_body();
    let proposal_id = body.proposal_id().unwrap();
    let checkpoint_id = typed_id::<CheckpointId>(65);
    let evidence = AdmissionEvidence::new(
        proposal_id,
        checkpoint_id,
        typed_id::<ProviderPolicyId>(66),
        FreshnessEvidence::local_known(checkpoint_id),
        DelayEvidence::none(),
        Extensions::default(),
    )
    .unwrap();
    let event_id = evidence.event_id_for_body(&body).unwrap();
    let approval = SignedControllerApproval::new(
        ControllerApprovalBody::event(
            typed_id::<ControllerId>(67),
            event_id,
            evidence.admission_evidence_id().unwrap(),
            Extensions::default(),
        )
        .unwrap(),
        vec![keyed_signature(68)],
    )
    .unwrap();
    AuthorizedEvent::new(
        body,
        evidence,
        ControllerApprovals::new(vec![approval]).unwrap(),
    )
    .unwrap()
}

fn checkpoint_body() -> CheckpointBody {
    CheckpointBody::new(
        typed_id::<AccountId>(1),
        Epoch::new(2),
        Sequence::new(3),
        typed_id::<EventId>(4),
        digest(5),
        digest(6),
        digest(7),
        typed_id::<ControlPolicyId>(8),
        typed_id::<RecoveryPolicyId>(9),
        typed_id::<ProviderPolicyId>(10),
        typed_id::<CryptoStateId>(11),
        AccountLifecycle::Active,
        Timestamp::from_unix_millis(12),
        Extensions::default(),
    )
    .unwrap()
}

fn transition_authorized_event() -> AuthorizedEvent {
    let body = EventBody::new(
        typed_id::<AccountId>(1),
        Sequence::new(1),
        Epoch::new(1),
        EventPredecessors::genesis(typed_id::<GenesisAnchor>(86)),
        AccountOperation::RetireAccount(
            RetireAccount::try_new(
                ProtocolVersion::V1,
                None,
                Some(RevocationReasonCode::new(9).unwrap()),
                Extensions::default(),
            )
            .unwrap(),
        ),
        Timestamp::from_unix_millis(87),
        [88; 16],
        Extensions::default(),
    )
    .unwrap();
    let proposal_id = body.proposal_id().unwrap();
    let checkpoint_id = typed_id::<CheckpointId>(89);
    let evidence = AdmissionEvidence::new(
        proposal_id,
        checkpoint_id,
        typed_id::<ProviderPolicyId>(90),
        FreshnessEvidence::local_known(checkpoint_id),
        DelayEvidence::none(),
        Extensions::default(),
    )
    .unwrap();
    let event_id = evidence.event_id_for_body(&body).unwrap();
    let approval = SignedControllerApproval::new(
        ControllerApprovalBody::event(
            typed_id::<ControllerId>(91),
            event_id,
            evidence.admission_evidence_id().unwrap(),
            Extensions::default(),
        )
        .unwrap(),
        vec![keyed_signature(92)],
    )
    .unwrap();
    AuthorizedEvent::new(
        body,
        evidence,
        ControllerApprovals::new(vec![approval]).unwrap(),
    )
    .unwrap()
}

fn retired_checkpoint_body(event_head: EventId) -> CheckpointBody {
    CheckpointBody::new(
        typed_id::<AccountId>(1),
        Epoch::new(2),
        Sequence::new(3),
        event_head,
        digest(5),
        digest(6),
        digest(7),
        typed_id::<ControlPolicyId>(8),
        typed_id::<RecoveryPolicyId>(9),
        typed_id::<ProviderPolicyId>(10),
        typed_id::<CryptoStateId>(11),
        AccountLifecycle::Retired,
        Timestamp::from_unix_millis(12),
        Extensions::default(),
    )
    .unwrap()
}

fn guardian_evidence() -> (
    GuardianApprovalBody,
    SignedGuardianApproval,
    GuardianApprovalSet,
    RecoveryThresholdEvidence,
) {
    let proposal = recovery_proposal();
    let recovery_id = proposal.recovery_id().unwrap();
    let grant = GuardianGrant::try_new(
        ProtocolVersion::V1,
        proposal.plan().account_id(),
        proposal.plan().recovery_policy_id(),
        typed_id::<AccountId>(70),
        SigningPublicKey::ed25519(SIGNING_KEY_2).unwrap(),
        ControllerWeight::new(1).unwrap(),
        Epoch::GENESIS,
        Some(Timestamp::from_unix_millis(1_000)),
        Extensions::default(),
    )
    .unwrap();
    let opening = GuardianGrantOpening::try_new(
        ProtocolVersion::V1,
        grant,
        BlindingSecret::try_new([71; 32]).unwrap(),
        GuardianSetRoot::new(digest(72)).unwrap(),
        0,
        Vec::new(),
        Extensions::default(),
    )
    .unwrap();
    let body = GuardianApprovalBody::try_new(
        ProtocolVersion::V1,
        proposal.plan().account_id(),
        recovery_id,
        GuardianApprovalDecision::Begin,
        opening.guardian_grant_id(),
        Epoch::GENESIS,
        Timestamp::from_unix_millis(500),
        Extensions::default(),
    )
    .unwrap();
    let signed = SignedGuardianApproval::try_new(
        body.clone(),
        opening,
        ProtocolSignature::ed25519([73; 64]),
    )
    .unwrap();
    let approvals = GuardianApprovalSet::try_new(vec![signed.clone()]).unwrap();
    let evidence = RecoveryThresholdEvidence::guardian_approvals(
        proposal.plan().recovery_policy_id(),
        proposal.plan().recovery_policy_version(),
        approvals.clone(),
    )
    .unwrap();
    (body, signed, approvals, evidence)
}

fn check_vector<T>(name: &str, value: &T, expected_hex: &str)
where
    T: CanonicalWire + std::fmt::Debug + PartialEq,
{
    let encoded = value.to_canonical_bytes().unwrap();
    let actual_hex = hex::encode(&encoded);
    assert_eq!(actual_hex, expected_hex, "{name} canonical bytes changed");
    assert_eq!(
        T::from_canonical_bytes(&encoded).unwrap(),
        *value,
        "{name} canonical decode changed"
    );
}

const ACCOUNT_OPERATION_HEX: [&str; 22] = [
    "010101da52d8e74be6cd6ae1e32b6a67d7087f4f06efbc3558e30f81bac9138337c4a30101d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a010900000000000000000000000000000000000000000000000000000000000000013d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c000100000200",
    "020101da52d8e74be6cd6ae1e32b6a67d7087f4f06efbc3558e30f81bac9138337c4a302000300",
    "030101da52d8e74be6cd6ae1e32b6a67d7087f4f06efbc3558e30f81bac9138337c4a30000",
    "040101da52d8e74be6cd6ae1e32b6a67d7087f4f06efbc3558e30f81bac9138337c4a300",
    "050101da52d8e74be6cd6ae1e32b6a67d7087f4f06efbc3558e30f81bac9138337c4a300",
    "060101da52d8e74be6cd6ae1e32b6a67d7087f4f06efbc3558e30f81bac9138337c4a3010700",
    "070101da52d8e74be6cd6ae1e32b6a67d7087f4f06efbc3558e30f81bac9138337c4a301017e5dc5cf5bb6d50a38d7bd5cca8e6e8d6bf653c38ed04155fb8ce4aa45988ffb01013d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c01090000000000000000000000000000000000000000000000000000000000000001fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb91154890802500010000020000",
    "080101d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a0101010000",
    "09013535353535353535353535353535353535353535353535353535353535353535",
    "0a01010a01010000010000000100",
    "0b01060101010000010064e80700",
    "0c0107010000",
    "0d010001f7bf3243431c5b8cf610cb04f668c90f537419e0338daee80de4de6d8d647adc0101010101010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202010303030303030303030303030303030303030303030303030303030303030303010404040404040404040404040404040404040404040404040404040404040404040505050505050505050505050505050505050505050505050505050505050505010101d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a010101000001010a0101000001000000010001050101010000010064e8070000d00f0000010104040404040404040404040404040404040404040404040404040404040404040400",
    "0e0101f7bf3243431c5b8cf610cb04f668c90f537419e0338daee80de4de6d8d647adc0123232323232323232323232323232323232323232323232323232323232323230101020202020202020202020202020202020202020202020202020202020202020200",
    "0f0101f7bf3243431c5b8cf610cb04f668c90f537419e0338daee80de4de6d8d647adc01010404040404040404040404040404040404040404040404040404040404040404040101020202020202020202020202020202020202020202020202020202020202020200",
    "100101f7bf3243431c5b8cf610cb04f668c90f537419e0338daee80de4de6d8d647adc0101010101010101010101010101010101010101010101010101010101010101010101f7bf3243431c5b8cf610cb04f668c90f537419e0338daee80de4de6d8d647adc01242424242424242424242424242424242424242424242424242424242424242401252525252525252525252525252525252525252525252525252525252525252501ac020101011f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f01202020202020202020202020202020202020202020202020202020202020202001010101010101010101010101010101010101010101010101010101010101010102012424242424242424242424242424242424242424242424242424242424242424ac0200000001011f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f0120202020202020202020202020202020202020202020202020202020202020200001012121212121212121212121212121212121212121212121212121212121212121ad0200012222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222200900300",
    "11010181e98d3929ad1faa900488c5ea00185c2b6098505dd8b5c805851c1e0e1ddfcf01010101010101010101010101010101010101010101010101010101010101010101020130303030303030303030303030303030303030303030303030303030303030300201313131313131313131313131313131313131313131313131313131313131313101323232323232323232323232323232323232323232323232323232323232323200013131313131313131313131313131313131313131313131313131313131313131010133333333333333333333333333333333333333333333333333333333333333330101343434343434343434343434343434343434343434343434343434343434343400",
    "120101010101010101010101010101010101010101010101010101010101010101010101012c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c010201020101010001012929292929292929292929292929292929292929292929292929292929292929012a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a02012b00002d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d000101811a0ad367661b6f148e53a680a4bebb585d2e99210ec7f7a742263bd5cb1d6001292929292929292929292929292929292929292929292929292929292929292901402e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e02012f00",
    "130101811a0ad367661b6f148e53a680a4bebb585d2e99210ec7f7a742263bd5cb1d6001363636363636363636363636363636363636363636363636363636363636363600",
    "140101811a0ad367661b6f148e53a680a4bebb585d2e99210ec7f7a742263bd5cb1d60010137373737373737373737373737373737373737373737373737373737373737370000",
    "15010102013838383838383838383838383838383838383838383838383838383838383838010000",
    "160100010800",
];

#[test]
fn account_operation_vectors_cover_every_v1_code() {
    let operations = account_operations();
    assert_eq!(operations.len(), 22);
    for (index, (operation, expected_hex)) in
        operations.iter().zip(ACCOUNT_OPERATION_HEX).enumerate()
    {
        let expected_code = u16::try_from(index + 1).unwrap();
        assert_eq!(operation.kind().code(), expected_code);
        check_vector(
            &format!("account_operation_{expected_code}"),
            operation,
            expected_hex,
        );
    }
}

#[test]
fn event_and_controller_approval_vectors_are_frozen() {
    let proposal_id = typed_id::<ProposalId>(80);
    let intent_body = EventIntentApprovalBody::new(
        typed_id::<ControllerId>(81),
        proposal_id,
        Extensions::default(),
    )
    .unwrap();
    let signed_intent =
        SignedEventIntentApproval::new(intent_body.clone(), vec![keyed_signature(82)]).unwrap();
    let authorized = authorized_event();
    let approval = &authorized.approvals().as_slice()[0];

    check_vector(
        "event_intent_approval_body",
        &intent_body,
        "0101515151515151515151515151515151515151515151515151515151515151515101505050505050505050505050505050505050505050505050505050505050505000",
    );
    check_vector(
        "signed_event_intent_approval",
        &signed_intent,
        "010151515151515151515151515151515151515151515151515151515151515151510150505050505050505050505050505050505050505050505050505050505050500001013c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c013d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d014052525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252",
    );
    check_vector(
        "controller_approval_body",
        approval.body(),
        "010143434343434343434343434343434343434343434343434343434343434343430101fe5309a3fe9d29f354a0d40622c6c09ea45122b9fcce6531ef6fded48935cf3301e02065abe46435c7aebf6928ca7aa94321b0e63dea3e1f65180b9c72e433059e00",
    );
    check_vector(
        "signed_controller_approval",
        approval,
        "010143434343434343434343434343434343434343434343434343434343434343430101fe5309a3fe9d29f354a0d40622c6c09ea45122b9fcce6531ef6fded48935cf3301e02065abe46435c7aebf6928ca7aa94321b0e63dea3e1f65180b9c72e433059e0001013c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c013d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d014044444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444",
    );
    check_vector(
        "authorized_event",
        &authorized,
        "01010101010101010101010101010101010101010101010101010101010101010101010101013e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e0c01010100003f40404040404040404040404040404040000101f0d88014b200765346052222fe45aba219e8fddbc86692aac618440c7417c54d01414141414141414141414141414141414141414141414141414141414141414101424242424242424242424242424242424242424242424242424242424242424201014141414141414141414141414141414141414141414141414141414141414141000001010143434343434343434343434343434343434343434343434343434343434343430101fe5309a3fe9d29f354a0d40622c6c09ea45122b9fcce6531ef6fded48935cf3301e02065abe46435c7aebf6928ca7aa94321b0e63dea3e1f65180b9c72e433059e0001013c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c013d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d014044444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444",
    );
    assert_eq!(
        intent_body.event_intent_approval_id().unwrap().to_string(),
        "b3:3a9db552289e4f1fa5d19ebb2bbc40ea56411a25c87b574b0d699d6af674fde1"
    );
    assert_eq!(
        authorized.body().proposal_id().unwrap().to_string(),
        "b3:f0d88014b200765346052222fe45aba219e8fddbc86692aac618440c7417c54d"
    );
    assert_eq!(
        authorized.event_id().unwrap().to_string(),
        "b3:fe5309a3fe9d29f354a0d40622c6c09ea45122b9fcce6531ef6fded48935cf33"
    );
    assert_eq!(
        authorized
            .admission_evidence()
            .admission_evidence_id()
            .unwrap()
            .to_string(),
        "b3:e02065abe46435c7aebf6928ca7aa94321b0e63dea3e1f65180b9c72e433059e"
    );
    assert_eq!(
        approval
            .body()
            .controller_approval_id()
            .unwrap()
            .to_string(),
        "b3:6514d38bc0a5d12dd3603238a31c7a5982562f32c28503f0f5ba51a2f6673f39"
    );
}

#[test]
fn checkpoint_authorization_vectors_cover_both_modes() {
    let body = checkpoint_body();
    let checkpoint_id = body.checkpoint_id().unwrap();
    let approval = SignedControllerApproval::new(
        ControllerApprovalBody::checkpoint(
            typed_id::<ControllerId>(83),
            checkpoint_id,
            Extensions::default(),
        )
        .unwrap(),
        vec![keyed_signature(84)],
    )
    .unwrap();
    let controllers = CheckpointAuthorization::controllers(
        checkpoint_id,
        ControllerApprovals::new(vec![approval]).unwrap(),
    )
    .unwrap();
    let transition_event = transition_authorized_event();
    let transition = CheckpointAuthorization::transition_derived(&transition_event).unwrap();
    let witness = transition.transition_witness().unwrap();
    let controller_signed = SignedCheckpoint::new(body.clone(), controllers.clone()).unwrap();
    let transition_signed = SignedCheckpoint::new(
        retired_checkpoint_body(transition_event.event_id().unwrap()),
        transition.clone(),
    )
    .unwrap();

    check_vector(
        "checkpoint_authorization_controllers",
        &controllers,
        "01010101535353535353535353535353535353535353535353535353535353535353535302012ec9928a9a1c43fdaf59ac0228675cbb7249d25ea44acd54961e8318f5078e4e0001013c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c013d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d014054545454545454545454545454545454545454545454545454545454545454545454545454545454545454545454545454545454545454545454545454545454",
    );
    check_vector(
        "checkpoint_authorization_transition",
        &transition,
        "02010201244a01e7a028943953b80ebfd13eea75600c325e419d9e3a655c74615e3e39ad010246eaea6cedb35c757369da02d4c095004ecfb28f77e0ea98bb436538f15651",
    );
    check_vector(
        "transition_checkpoint_witness",
        witness,
        "010201244a01e7a028943953b80ebfd13eea75600c325e419d9e3a655c74615e3e39ad010246eaea6cedb35c757369da02d4c095004ecfb28f77e0ea98bb436538f15651",
    );
    check_vector(
        "signed_checkpoint_controllers",
        &controller_signed,
        "010101010101010101010101010101010101010101010101010101010101010101010203010404040404040404040404040404040404040404040404040404040404040404010505050505050505050505050505050505050505050505050505050505050505010606060606060606060606060606060606060606060606060606060606060606010707070707070707070707070707070707070707070707070707070707070707010808080808080808080808080808080808080808080808080808080808080808010909090909090909090909090909090909090909090909090909090909090909010a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b010c0001010101535353535353535353535353535353535353535353535353535353535353535302012ec9928a9a1c43fdaf59ac0228675cbb7249d25ea44acd54961e8318f5078e4e0001013c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c013d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d014054545454545454545454545454545454545454545454545454545454545454545454545454545454545454545454545454545454545454545454545454545454",
    );
    check_vector(
        "signed_checkpoint_transition",
        &transition_signed,
        "01010101010101010101010101010101010101010101010101010101010101010101020301244a01e7a028943953b80ebfd13eea75600c325e419d9e3a655c74615e3e39ad010505050505050505050505050505050505050505050505050505050505050505010606060606060606060606060606060606060606060606060606060606060606010707070707070707070707070707070707070707070707070707070707070707010808080808080808080808080808080808080808080808080808080808080808010909090909090909090909090909090909090909090909090909090909090909010a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b060c0002010201244a01e7a028943953b80ebfd13eea75600c325e419d9e3a655c74615e3e39ad010246eaea6cedb35c757369da02d4c095004ecfb28f77e0ea98bb436538f15651",
    );
    assert_eq!(
        checkpoint_id.to_string(),
        "b3:2ec9928a9a1c43fdaf59ac0228675cbb7249d25ea44acd54961e8318f5078e4e"
    );
    assert_eq!(
        transition_event
            .event_authorization_id()
            .unwrap()
            .to_string(),
        "b3:0246eaea6cedb35c757369da02d4c095004ecfb28f77e0ea98bb436538f15651"
    );
}

#[test]
fn recovery_operation_and_signed_evidence_vectors_are_frozen() {
    let (begin, veto, cancel, finalize) = recovery_operations();
    let (body, signed, approvals, evidence) = guardian_evidence();

    check_vector(
        "begin_recovery",
        &begin,
        "010001f7bf3243431c5b8cf610cb04f668c90f537419e0338daee80de4de6d8d647adc0101010101010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202010303030303030303030303030303030303030303030303030303030303030303010404040404040404040404040404040404040404040404040404040404040404040505050505050505050505050505050505050505050505050505050505050505010101d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a010101000001010a0101000001000000010001050101010000010064e8070000d00f0000010104040404040404040404040404040404040404040404040404040404040404040400",
    );
    check_vector(
        "veto_recovery",
        &veto,
        "0101f7bf3243431c5b8cf610cb04f668c90f537419e0338daee80de4de6d8d647adc0123232323232323232323232323232323232323232323232323232323232323230101020202020202020202020202020202020202020202020202020202020202020200",
    );
    check_vector(
        "cancel_recovery",
        &cancel,
        "0101f7bf3243431c5b8cf610cb04f668c90f537419e0338daee80de4de6d8d647adc01010404040404040404040404040404040404040404040404040404040404040404040101020202020202020202020202020202020202020202020202020202020202020200",
    );
    check_vector(
        "finalize_recovery",
        &finalize,
        "0101f7bf3243431c5b8cf610cb04f668c90f537419e0338daee80de4de6d8d647adc0101010101010101010101010101010101010101010101010101010101010101010101f7bf3243431c5b8cf610cb04f668c90f537419e0338daee80de4de6d8d647adc01242424242424242424242424242424242424242424242424242424242424242401252525252525252525252525252525252525252525252525252525252525252501ac020101011f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f01202020202020202020202020202020202020202020202020202020202020202001010101010101010101010101010101010101010101010101010101010101010102012424242424242424242424242424242424242424242424242424242424242424ac0200000001011f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f0120202020202020202020202020202020202020202020202020202020202020200001012121212121212121212121212121212121212121212121212121212121212121ad0200012222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222200900300",
    );
    check_vector(
        "guardian_approval_body",
        &body,
        "0101010101010101010101010101010101010101010101010101010101010101010101f7bf3243431c5b8cf610cb04f668c90f537419e0338daee80de4de6d8d647adc0101db8d671e2e8011e4b3ba98f0c521b30f2aa52322f74eb1f82da20a6def02074e00f40300",
    );
    check_vector(
        "signed_guardian_approval",
        &signed,
        "0101010101010101010101010101010101010101010101010101010101010101010101f7bf3243431c5b8cf610cb04f668c90f537419e0338daee80de4de6d8d647adc0101db8d671e2e8011e4b3ba98f0c521b30f2aa52322f74eb1f82da20a6def02074e00f403000101db8d671e2e8011e4b3ba98f0c521b30f2aa52322f74eb1f82da20a6def02074e01010101010101010101010101010101010101010101010101010101010101010101010404040404040404040404040404040404040404040404040404040404040404014646464646464646464646464646464646464646464646464646464646464646013d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c010001e8070047474747474747474747474747474747474747474747474747474747474747470148484848484848484848484848484848484848484848484848484848484848480000000149494949494949494949494949494949494949494949494949494949494949494949494949494949494949494949494949494949494949494949494949494949",
    );
    check_vector(
        "guardian_approval_set",
        &approvals,
        "010101010101010101010101010101010101010101010101010101010101010101010101f7bf3243431c5b8cf610cb04f668c90f537419e0338daee80de4de6d8d647adc0101db8d671e2e8011e4b3ba98f0c521b30f2aa52322f74eb1f82da20a6def02074e00f403000101db8d671e2e8011e4b3ba98f0c521b30f2aa52322f74eb1f82da20a6def02074e01010101010101010101010101010101010101010101010101010101010101010101010404040404040404040404040404040404040404040404040404040404040404014646464646464646464646464646464646464646464646464646464646464646013d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c010001e8070047474747474747474747474747474747474747474747474747474747474747470148484848484848484848484848484848484848484848484848484848484848480000000149494949494949494949494949494949494949494949494949494949494949494949494949494949494949494949494949494949494949494949494949494949",
    );
    check_vector(
        "guardian_threshold_evidence",
        &evidence,
        "0201040404040404040404040404040404040404040404040404040404040404040404010101010101010101010101010101010101010101010101010101010101010101010101f7bf3243431c5b8cf610cb04f668c90f537419e0338daee80de4de6d8d647adc0101db8d671e2e8011e4b3ba98f0c521b30f2aa52322f74eb1f82da20a6def02074e00f403000101db8d671e2e8011e4b3ba98f0c521b30f2aa52322f74eb1f82da20a6def02074e01010101010101010101010101010101010101010101010101010101010101010101010404040404040404040404040404040404040404040404040404040404040404014646464646464646464646464646464646464646464646464646464646464646013d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c010001e8070047474747474747474747474747474747474747474747474747474747474747470148484848484848484848484848484848484848484848484848484848484848480000000149494949494949494949494949494949494949494949494949494949494949494949494949494949494949494949494949494949494949494949494949494949",
    );
    assert_eq!(
        begin.recovery_id().to_string(),
        "b3:f7bf3243431c5b8cf610cb04f668c90f537419e0338daee80de4de6d8d647adc"
    );
    assert_eq!(
        signed.opening().guardian_grant_id().to_string(),
        "b3:db8d671e2e8011e4b3ba98f0c521b30f2aa52322f74eb1f82da20a6def02074e"
    );
}
