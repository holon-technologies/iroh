use krikos_identity::{
    AccountId, AccountOperation, AdmissionEvidence, AlgorithmSignature, AuthorizedEvent,
    BeginRecovery, BlindingSecret, CancelRecovery, CanonicalWire, CheckpointId, ControlPolicy,
    ControllerApprovalBody, ControllerApprovals, ControllerClass, ControllerDescriptor,
    ControllerId, ControllerKeyId, ControllerScope, ControllerSelector, ControllerThreshold,
    ControllerWeight, CryptoSuiteId, DelayEvidence, DeviceId, Digest, DurationMillis, Epoch,
    EventBody, EventId, EventPredecessors, Extension, Extensions, FinalizeRecovery,
    ForkCommonAncestor, ForkDescriptor, ForkId, FreshnessEvidence, GenesisAnchor,
    GuardianApprovalBody, GuardianApprovalDecision, GuardianApprovalSet, GuardianGrant,
    GuardianGrantId, GuardianGrantOpening, GuardianSetRoot, HashAlgorithm, IdentityError,
    InclusionReceipt, KeyedSignature, OperationKind, PolicyRule, ProtocolSignature,
    ProtocolVersion, ProviderHeadBody, ProviderId, ProviderKeyVersion, ProviderLogEntryBody,
    ProviderLogId, ProviderLogSubject, ProviderPolicyId, ProviderQuorum, RecoveryAuthority,
    RecoveryAuthorityPlan, RecoveryDelayAnchor, RecoveryId, RecoveryPolicy, RecoveryPolicyId,
    RecoveryPolicyVersion, RecoveryProposal, RecoveryThresholdEvidence, RequiredWeight,
    ResolveFork, Sequence, SignedControllerApproval, SignedGuardianApproval, SignedProviderHead,
    SigningPublicKey, Timestamp, VetoRecovery,
    limits::{MAX_FORK_HEADS, MAX_RECOVERY_GUARDIANS},
};

const SIGNING_KEY_1: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
const SIGNING_KEY_2: [u8; 32] = [
    0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
    0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
];

fn typed_id<T: CanonicalWire>(fill: u8) -> T {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [fill; 32]);
    T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
}

fn controller(key: [u8; 32]) -> ControllerDescriptor {
    ControllerDescriptor::new(
        SigningPublicKey::ed25519(key).unwrap(),
        ControllerClass::PersonalDevice,
        ControllerWeight::new(1).unwrap(),
        ControllerScope::all_v1_operations(),
        Extensions::default(),
    )
    .unwrap()
}

fn control_policy() -> ControlPolicy {
    let rules = [
        OperationKind::BeginRecovery,
        OperationKind::VetoRecovery,
        OperationKind::CancelRecovery,
        OperationKind::FinalizeRecovery,
        OperationKind::ResolveFork,
    ]
    .into_iter()
    .map(|operation| {
        PolicyRule::new(
            operation,
            RequiredWeight::new(1).unwrap(),
            ControllerSelector::any_active(),
            krikos_identity::FreshnessRequirement::latest_known(),
            None,
            Extensions::default(),
        )
        .unwrap()
    })
    .collect();
    ControlPolicy::new(rules, Extensions::default()).unwrap()
}

fn recovery_policy(version: u64) -> RecoveryPolicy {
    RecoveryPolicy::new(
        RecoveryPolicyVersion::new(version),
        RecoveryAuthority::controller_threshold(ControllerThreshold::new(
            ControllerSelector::any_active(),
            RequiredWeight::new(1).unwrap(),
        )),
        DurationMillis::new(1_000),
        DurationMillis::new(10_000),
        Extensions::default(),
    )
    .unwrap()
}

fn plan() -> RecoveryAuthorityPlan {
    RecoveryAuthorityPlan::try_new(
        ProtocolVersion::V1,
        typed_id::<AccountId>(1),
        typed_id::<CheckpointId>(2),
        typed_id::<EventId>(3),
        typed_id::<RecoveryPolicyId>(4),
        RecoveryPolicyVersion::new(4),
        [5; 32],
        vec![controller(SIGNING_KEY_2), controller(SIGNING_KEY_1)],
        control_policy(),
        recovery_policy(5),
        vec![typed_id::<DeviceId>(8), typed_id::<DeviceId>(7)],
        Timestamp::from_unix_millis(20_000),
        Extensions::default(),
    )
    .unwrap()
}

fn proposal() -> RecoveryProposal {
    RecoveryProposal::try_new(ProtocolVersion::V1, plan(), Extensions::default()).unwrap()
}

fn begin_recovery() -> BeginRecovery {
    let proposal = proposal();
    let evidence = RecoveryThresholdEvidence::controller_policy(
        proposal.plan().recovery_policy_id(),
        proposal.plan().recovery_policy_version(),
    );
    BeginRecovery::try_new(
        ProtocolVersion::V1,
        proposal,
        evidence,
        Extensions::default(),
    )
    .unwrap()
}

fn final_approval(event_id: EventId, evidence: &AdmissionEvidence) -> ControllerApprovals {
    let body = ControllerApprovalBody::event(
        typed_id::<ControllerId>(41),
        event_id,
        evidence.admission_evidence_id().unwrap(),
        Extensions::default(),
    )
    .unwrap();
    ControllerApprovals::new(vec![
        SignedControllerApproval::new(
            body,
            vec![KeyedSignature::new(
                typed_id::<CryptoSuiteId>(42),
                typed_id::<ControllerKeyId>(43),
                AlgorithmSignature::new(1, vec![44; 64]).unwrap(),
            )],
        )
        .unwrap(),
    ])
    .unwrap()
}

#[test]
fn begin_recovery_event_binds_prior_head_and_checkpoint() {
    let begin = begin_recovery();
    let plan = begin.proposal().plan();

    assert!(matches!(
        EventBody::new(
            plan.account_id(),
            Sequence::new(1),
            Epoch::new(1),
            EventPredecessors::genesis(typed_id(31)),
            AccountOperation::BeginRecovery(begin.clone()),
            Timestamp::from_unix_millis(10),
            [32; 16],
            Extensions::default(),
        ),
        Err(IdentityError::InvalidPredecessor)
    ));

    assert!(matches!(
        EventBody::new(
            plan.account_id(),
            Sequence::new(2),
            Epoch::new(1),
            EventPredecessors::events(vec![typed_id(33)]).unwrap(),
            AccountOperation::BeginRecovery(begin.clone()),
            Timestamp::from_unix_millis(10),
            [34; 16],
            Extensions::default(),
        ),
        Err(IdentityError::InvalidPredecessor)
    ));

    let body = EventBody::new(
        plan.account_id(),
        Sequence::new(2),
        Epoch::new(1),
        EventPredecessors::events(vec![plan.prior_event_head()]).unwrap(),
        AccountOperation::BeginRecovery(begin),
        Timestamp::from_unix_millis(10),
        [35; 16],
        Extensions::default(),
    )
    .unwrap();
    let wrong_checkpoint = typed_id::<CheckpointId>(36);
    let admission = AdmissionEvidence::new(
        body.proposal_id().unwrap(),
        wrong_checkpoint,
        typed_id::<ProviderPolicyId>(37),
        FreshnessEvidence::local_known(wrong_checkpoint),
        DelayEvidence::none(),
        Extensions::default(),
    )
    .unwrap();
    let approvals = final_approval(admission.event_id_for_body(&body).unwrap(), &admission);
    assert!(matches!(
        AuthorizedEvent::new(body.clone(), admission.clone(), approvals.clone()),
        Err(IdentityError::InvalidRelationship { .. })
    ));

    let wire = postcard::to_stdvec(&(body, admission, approvals)).unwrap();
    assert!(AuthorizedEvent::from_canonical_bytes(&wire).is_err());
}

fn provider_receipt(
    provider_fill: u8,
    account_id: AccountId,
    proposal_id: krikos_identity::ProposalId,
    observed_at: u64,
) -> InclusionReceipt {
    let provider_id = typed_id::<ProviderId>(provider_fill);
    let log_id = typed_id::<ProviderLogId>(provider_fill.wrapping_add(32));
    let entry = ProviderLogEntryBody::new(
        provider_id,
        log_id,
        account_id,
        ProviderLogSubject::EventIntent(proposal_id),
        Timestamp::from_unix_millis(observed_at),
        Extensions::default(),
    )
    .unwrap();
    let head = ProviderHeadBody::new(
        provider_id,
        log_id,
        ProviderKeyVersion::GENESIS,
        1,
        Digest::new(HashAlgorithm::Blake3_256, [provider_fill; 32]),
        Timestamp::from_unix_millis(observed_at + 1),
        Extensions::default(),
    )
    .unwrap();
    InclusionReceipt::new(
        entry,
        0,
        vec![],
        SignedProviderHead::new(head, ProtocolSignature::ed25519([provider_fill; 64])),
    )
    .unwrap()
}

#[test]
fn recovery_plan_is_sorted_bounded_and_body_id_is_stable() {
    let proposal = proposal();
    let authority_plan = proposal.plan();
    assert!(
        authority_plan.replacement_controllers()[0].id().unwrap()
            < authority_plan.replacement_controllers()[1].id().unwrap()
    );
    assert_eq!(
        authority_plan.retained_devices(),
        &[typed_id::<DeviceId>(7), typed_id::<DeviceId>(8)]
    );
    assert_eq!(
        RecoveryProposal::from_canonical_bytes(&proposal.to_canonical_bytes().unwrap()).unwrap(),
        proposal
    );
    assert_eq!(
        proposal.recovery_id().unwrap().to_string(),
        "b3:57a8b5623760855c922b2aeeb98b72339f967939f802f6dabf4124e0417e80c5"
    );

    let base = plan();
    assert!(matches!(
        RecoveryAuthorityPlan::try_new(
            ProtocolVersion::V1,
            base.account_id(),
            base.prior_checkpoint_id(),
            base.prior_event_head(),
            base.recovery_policy_id(),
            base.recovery_policy_version(),
            [0; 32],
            base.replacement_controllers().to_vec(),
            base.replacement_control_policy().clone(),
            base.replacement_recovery_policy().clone(),
            base.retained_devices().to_vec(),
            base.expires_at(),
            Extensions::default(),
        ),
        Err(IdentityError::ZeroValue { .. })
    ));
    assert!(
        RecoveryAuthorityPlan::try_new(
            ProtocolVersion::V1,
            base.account_id(),
            base.prior_checkpoint_id(),
            base.prior_event_head(),
            base.recovery_policy_id(),
            base.recovery_policy_version(),
            [1; 32],
            base.replacement_controllers().to_vec(),
            base.replacement_control_policy().clone(),
            base.replacement_recovery_policy().clone(),
            vec![typed_id::<DeviceId>(9), typed_id::<DeviceId>(9)],
            base.expires_at(),
            Extensions::default(),
        )
        .is_err()
    );

    let duplicate_controller = base.replacement_controllers()[0].clone();
    assert!(matches!(
        RecoveryAuthorityPlan::try_new(
            ProtocolVersion::V1,
            base.account_id(),
            base.prior_checkpoint_id(),
            base.prior_event_head(),
            base.recovery_policy_id(),
            base.recovery_policy_version(),
            [1; 32],
            vec![duplicate_controller.clone(), duplicate_controller],
            base.replacement_control_policy().clone(),
            base.replacement_recovery_policy().clone(),
            base.retained_devices().to_vec(),
            base.expires_at(),
            Extensions::default(),
        ),
        Err(IdentityError::DuplicateElement { .. })
    ));

    let mut reversed_controllers = base.replacement_controllers().to_vec();
    reversed_controllers.reverse();
    let unsorted_wire = postcard::to_stdvec(&(
        ProtocolVersion::V1,
        base.account_id(),
        base.prior_checkpoint_id(),
        base.prior_event_head(),
        base.recovery_policy_id(),
        base.recovery_policy_version(),
        [1; 32],
        reversed_controllers,
        base.replacement_control_policy().clone(),
        base.replacement_recovery_policy().clone(),
        base.retained_devices().to_vec(),
        base.expires_at(),
        Extensions::default(),
    ))
    .unwrap();
    assert!(RecoveryAuthorityPlan::from_canonical_bytes(&unsorted_wire).is_err());
}

#[test]
fn guardian_openings_and_approvals_are_bound_and_mergeable() {
    let protected_account = typed_id::<AccountId>(1);
    let recovery_policy_id = typed_id::<RecoveryPolicyId>(4);
    let root = GuardianSetRoot::new(Digest::new(HashAlgorithm::Blake3_256, [9; 32])).unwrap();
    let recovery_id = proposal().recovery_id().unwrap();

    let signed = |guardian_fill: u8, key: [u8; 32]| {
        let grant = GuardianGrant::try_new(
            ProtocolVersion::V1,
            protected_account,
            recovery_policy_id,
            typed_id::<AccountId>(guardian_fill),
            SigningPublicKey::ed25519(key).unwrap(),
            ControllerWeight::new(1).unwrap(),
            Epoch::GENESIS,
            Some(Timestamp::from_unix_millis(30_000)),
            Extensions::default(),
        )
        .unwrap();
        let opening = GuardianGrantOpening::try_new(
            ProtocolVersion::V1,
            grant,
            BlindingSecret::try_new([guardian_fill; 32]).unwrap(),
            root,
            u16::from(guardian_fill - 1),
            vec![],
            Extensions::default(),
        )
        .unwrap();
        let body = GuardianApprovalBody::try_new(
            ProtocolVersion::V1,
            protected_account,
            recovery_id,
            GuardianApprovalDecision::Begin,
            opening.guardian_grant_id(),
            Epoch::GENESIS,
            Timestamp::from_unix_millis(10_000),
            Extensions::default(),
        )
        .unwrap();
        SignedGuardianApproval::try_new(
            body,
            opening,
            ProtocolSignature::ed25519([guardian_fill; 64]),
        )
        .unwrap()
    };

    let first = signed(1, SIGNING_KEY_1);
    let second = signed(2, SIGNING_KEY_2);
    let one = GuardianApprovalSet::try_new(vec![first.clone()]).unwrap();
    let two = GuardianApprovalSet::try_new(vec![second, first.clone()]).unwrap();
    assert_eq!(one.merge(&two).unwrap(), two);
    assert_eq!(two.recovery_id(), recovery_id);
    assert_eq!(two.guardian_set_root(), root);
    assert!(GuardianApprovalSet::try_new(vec![first.clone(), first.clone()]).is_err());
    assert_eq!(
        GuardianApprovalSet::from_canonical_bytes(&two.to_canonical_bytes().unwrap()).unwrap(),
        two
    );

    let mut reversed = two.as_slice().to_vec();
    reversed.reverse();
    let reversed_wire = postcard::to_stdvec(&reversed).unwrap();
    assert!(GuardianApprovalSet::from_canonical_bytes(&reversed_wire).is_err());

    let oversized = vec![first.clone(); MAX_RECOVERY_GUARDIANS + 1];
    let oversized_wire = postcard::to_stdvec(&oversized).unwrap();
    assert!(GuardianApprovalSet::from_canonical_bytes(&oversized_wire).is_err());

    assert!(matches!(
        BlindingSecret::try_new([0; 32]),
        Err(IdentityError::ZeroValue { .. })
    ));

    let mut tampered_approval = first.to_canonical_bytes().unwrap();
    let original_id = first
        .body()
        .guardian_grant_id()
        .to_canonical_bytes()
        .unwrap();
    let replacement_id = typed_id::<GuardianGrantId>(99)
        .to_canonical_bytes()
        .unwrap();
    let occurrences = tampered_approval
        .windows(original_id.len())
        .enumerate()
        .filter_map(|(index, window)| (window == original_id).then_some(index))
        .collect::<Vec<_>>();
    assert_eq!(occurrences.len(), 2);
    let opening_id_offset = occurrences[1];
    tampered_approval[opening_id_offset..opening_id_offset + original_id.len()]
        .copy_from_slice(&replacement_id);
    assert!(SignedGuardianApproval::from_canonical_bytes(&tampered_approval).is_err());
}

#[test]
fn recovery_operations_bind_vacancy_policy_and_exact_pending_id() {
    let proposal = proposal();
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
    assert!(begin.requires_vacant_recovery_slot());
    assert_eq!(begin.recovery_id(), recovery_id);

    let occupied_wire = postcard::to_stdvec(&(
        ProtocolVersion::V1,
        Some(recovery_id),
        recovery_id,
        proposal.clone(),
        evidence.clone(),
        Extensions::default(),
    ))
    .unwrap();
    assert!(BeginRecovery::from_canonical_bytes(&occupied_wire).is_err());
    let wrong_id_wire = postcard::to_stdvec(&(
        ProtocolVersion::V1,
        Option::<RecoveryId>::None,
        typed_id::<RecoveryId>(90),
        proposal.clone(),
        evidence.clone(),
        Extensions::default(),
    ))
    .unwrap();
    assert!(BeginRecovery::from_canonical_bytes(&wrong_id_wire).is_err());

    let checkpoint = proposal.plan().prior_checkpoint_id();
    let freshness = FreshnessEvidence::local_known(checkpoint);
    let veto = VetoRecovery::try_new(
        ProtocolVersion::V1,
        recovery_id,
        typed_id(22),
        freshness.clone(),
        Extensions::default(),
    )
    .unwrap();
    assert_eq!(veto.expected_pending_recovery(), recovery_id);

    let cancel = CancelRecovery::try_new(
        ProtocolVersion::V1,
        recovery_id,
        evidence,
        freshness,
        Extensions::default(),
    )
    .unwrap();
    assert_eq!(cancel.expected_pending_recovery(), recovery_id);
    assert_eq!(
        CancelRecovery::from_canonical_bytes(&cancel.to_canonical_bytes().unwrap()).unwrap(),
        cancel
    );
}

#[test]
fn finalize_delay_anchor_is_the_quorum_th_earliest_distinct_observation() {
    let account_id = typed_id::<AccountId>(1);
    let recovery_id = proposal().recovery_id().unwrap();
    let begin_proposal_id = typed_id(44);
    let receipts = krikos_identity::ProviderReceipts::new(vec![
        provider_receipt(3, account_id, begin_proposal_id, 300),
        provider_receipt(1, account_id, begin_proposal_id, 100),
        provider_receipt(2, account_id, begin_proposal_id, 200),
    ])
    .unwrap();
    let anchor = RecoveryDelayAnchor::try_new(
        ProtocolVersion::V1,
        account_id,
        recovery_id,
        begin_proposal_id,
        typed_id::<ProviderPolicyId>(45),
        ProviderQuorum::new(2).unwrap(),
        receipts,
        Extensions::default(),
    )
    .unwrap();
    assert_eq!(anchor.observed_at(), Timestamp::from_unix_millis(200));
    assert!(matches!(
        FinalizeRecovery::try_new(
            ProtocolVersion::V1,
            recovery_id,
            anchor.clone(),
            Timestamp::from_unix_millis(199),
            Extensions::default(),
        ),
        Err(IdentityError::InvalidRelationship { .. })
    ));
    let finalize = FinalizeRecovery::try_new(
        ProtocolVersion::V1,
        recovery_id,
        anchor,
        Timestamp::from_unix_millis(1_200),
        Extensions::default(),
    )
    .unwrap();
    assert_eq!(finalize.expected_pending_recovery(), recovery_id);

    let insufficient = krikos_identity::ProviderReceipts::new(vec![provider_receipt(
        1,
        account_id,
        begin_proposal_id,
        100,
    )])
    .unwrap();
    assert!(matches!(
        RecoveryDelayAnchor::try_new(
            ProtocolVersion::V1,
            account_id,
            recovery_id,
            begin_proposal_id,
            typed_id::<ProviderPolicyId>(45),
            ProviderQuorum::new(2).unwrap(),
            insufficient,
            Extensions::default(),
        ),
        Err(IdentityError::UnsatisfiableThreshold)
    ));
}

#[test]
fn fork_descriptor_and_choose_one_resolution_are_canonical() {
    let account_id = typed_id::<AccountId>(1);
    let ancestor = typed_id::<EventId>(2);
    let first = typed_id::<EventId>(3);
    let second = typed_id::<EventId>(4);
    let fork = ForkDescriptor::try_new(
        ProtocolVersion::V1,
        account_id,
        ForkCommonAncestor::Event(ancestor),
        vec![second, first],
        Extensions::default(),
    )
    .unwrap();
    assert_eq!(fork.heads(), &[first, second]);
    assert_eq!(fork.common_ancestor(), ForkCommonAncestor::Event(ancestor));
    assert_eq!(
        hex::encode(fork.to_canonical_bytes().unwrap()),
        "01010101010101010101010101010101010101010101010101010101010101010101020102020202020202020202020202020202020202020202020202020202020202020201030303030303030303030303030303030303030303030303030303030303030301040404040404040404040404040404040404040404040404040404040404040400"
    );
    assert_eq!(
        fork.fork_id().unwrap().to_string(),
        "b3:a15afec9c970e685ed3f0cc380c77dcfea47798e70cf6e443ac00784ad93b36a"
    );

    let genesis_fork = ForkDescriptor::try_new(
        ProtocolVersion::V1,
        account_id,
        ForkCommonAncestor::Genesis(typed_id::<GenesisAnchor>(2)),
        vec![first, second],
        Extensions::default(),
    )
    .unwrap();
    assert_eq!(
        ForkDescriptor::from_canonical_bytes(&genesis_fork.to_canonical_bytes().unwrap()).unwrap(),
        genesis_fork
    );
    assert_ne!(genesis_fork.fork_id().unwrap(), fork.fork_id().unwrap());

    let resolution = ResolveFork::try_new(
        ProtocolVersion::V1,
        fork.clone(),
        second,
        vec![typed_id::<ControllerId>(7), typed_id::<ControllerId>(6)],
        vec![typed_id::<DeviceId>(9), typed_id::<DeviceId>(8)],
        Extensions::default(),
    )
    .unwrap();
    assert_eq!(resolution.selected_head(), second);
    assert_eq!(
        resolution.revoked_controllers(),
        &[typed_id(6), typed_id(7)]
    );
    assert_eq!(resolution.revoked_devices(), &[typed_id(8), typed_id(9)]);
    assert!(
        ResolveFork::try_new(
            ProtocolVersion::V1,
            fork.clone(),
            typed_id::<EventId>(99),
            vec![],
            vec![],
            Extensions::default(),
        )
        .is_err()
    );
    assert!(
        ForkDescriptor::try_new(
            ProtocolVersion::V1,
            account_id,
            ForkCommonAncestor::Event(ancestor),
            vec![first, first],
            Extensions::default(),
        )
        .is_err()
    );
    assert_eq!(
        ForkDescriptor::try_new(
            ProtocolVersion::V1,
            account_id,
            ForkCommonAncestor::Event(first),
            vec![first, second],
            Extensions::default(),
        ),
        Err(IdentityError::InvalidRelationship {
            resource: "fork ancestor/head",
        })
    );
    assert!(
        ResolveFork::try_new(
            ProtocolVersion::V1,
            fork.clone(),
            second,
            vec![typed_id::<ControllerId>(6), typed_id::<ControllerId>(6)],
            vec![],
            Extensions::default(),
        )
        .is_err()
    );

    let tampered_id_wire = postcard::to_stdvec(&(
        ProtocolVersion::V1,
        typed_id::<ForkId>(90),
        fork,
        second,
        Vec::<ControllerId>::new(),
        Vec::<DeviceId>::new(),
        Extensions::default(),
    ))
    .unwrap();
    assert!(ResolveFork::from_canonical_bytes(&tampered_id_wire).is_err());
}

#[test]
fn adversarial_wire_rejects_unsorted_oversized_and_unknown_critical_fields() {
    let account_id = typed_id::<AccountId>(1);
    let ancestor = typed_id::<EventId>(2);
    let first = typed_id::<EventId>(3);
    let second = typed_id::<EventId>(4);
    let unsorted = postcard::to_stdvec(&(
        ProtocolVersion::V1,
        account_id,
        ForkCommonAncestor::Event(ancestor),
        vec![second, first],
        Extensions::default(),
    ))
    .unwrap();
    assert!(ForkDescriptor::from_canonical_bytes(&unsorted).is_err());

    let oversized = postcard::to_stdvec(&(
        ProtocolVersion::V1,
        account_id,
        ForkCommonAncestor::Event(ancestor),
        vec![first; MAX_FORK_HEADS + 1],
        Extensions::default(),
    ))
    .unwrap();
    assert!(ForkDescriptor::from_canonical_bytes(&oversized).is_err());

    let unknown_ancestor = postcard::to_stdvec(&(
        ProtocolVersion::V1,
        account_id,
        (3_u16, ancestor),
        vec![first, second],
        Extensions::default(),
    ))
    .unwrap();
    assert_eq!(
        ForkDescriptor::from_canonical_bytes(&unknown_ancestor),
        Err(IdentityError::InvalidEncoding)
    );

    let critical = Extensions::new(vec![Extension::new(999, true, vec![]).unwrap()]).unwrap();
    assert!(
        ForkDescriptor::try_new(
            ProtocolVersion::V1,
            account_id,
            ForkCommonAncestor::Event(ancestor),
            vec![first, second],
            critical,
        )
        .is_err()
    );
}
