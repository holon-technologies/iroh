use krikos_identity::{
    AccountId, AccountLifecycle, AccountOperation, AdmissionEvidence, AlgorithmSignature,
    AuthorizedEvent, CanonicalWire, CheckpointAuthorization, CheckpointBody, CheckpointId,
    CheckpointTransitionKind, ControlPolicyId, ControllerApprovalBody, ControllerApprovals,
    ControllerId, ControllerKeyId, CryptoStateId, CryptoSuiteId, DelayEvidence, Digest, Epoch,
    EventBody, EventId, EventPredecessors, Extension, Extensions, FreshnessEvidence, HashAlgorithm,
    IdentityError, InclusionReceipt, KeyedSignature, ProtocolSignature, ProtocolVersion,
    ProviderHeadBody, ProviderId, ProviderKeyVersion, ProviderLogEntryBody, ProviderLogId,
    ProviderLogSubject, ProviderPolicy, ProviderPolicyId, ProviderPolicyVersion, ProviderReceipts,
    RecoveryPolicyId, RetireAccount, Sequence, SignedCheckpoint, SignedControllerApproval,
    SignedProviderHead, Timestamp,
};

fn typed_id<T: CanonicalWire>(fill: u8) -> T {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [fill; 32]);
    T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
}

fn unknown_critical_extensions() -> Extensions {
    Extensions::new(vec![Extension::new(65_535, true, vec![1]).unwrap()]).unwrap()
}

fn authorized_retirement() -> AuthorizedEvent {
    authorized_event(AccountOperation::RetireAccount(
        RetireAccount::try_new(ProtocolVersion::V1, None, None, Extensions::default()).unwrap(),
    ))
}

fn authorized_event(operation: AccountOperation) -> AuthorizedEvent {
    let body = EventBody::new(
        typed_id::<AccountId>(20),
        Sequence::new(1),
        Epoch::new(1),
        EventPredecessors::genesis(typed_id(21)),
        operation,
        Timestamp::from_unix_millis(22),
        [23; 16],
        Extensions::default(),
    )
    .unwrap();
    let checkpoint_id = typed_id::<CheckpointId>(24);
    let evidence = AdmissionEvidence::new(
        body.proposal_id().unwrap(),
        checkpoint_id,
        typed_id::<ProviderPolicyId>(25),
        FreshnessEvidence::local_known(checkpoint_id),
        DelayEvidence::none(),
        Extensions::default(),
    )
    .unwrap();
    let approval_body = ControllerApprovalBody::event(
        typed_id::<ControllerId>(26),
        evidence.event_id_for_body(&body).unwrap(),
        evidence.admission_evidence_id().unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let approval = SignedControllerApproval::new(
        approval_body,
        vec![KeyedSignature::new(
            typed_id::<CryptoSuiteId>(27),
            typed_id::<ControllerKeyId>(28),
            AlgorithmSignature::new(1, vec![29; 64]).unwrap(),
        )],
    )
    .unwrap();
    AuthorizedEvent::new(
        body,
        evidence,
        ControllerApprovals::new(vec![approval]).unwrap(),
    )
    .unwrap()
}

fn checkpoint_body(event_head: EventId, lifecycle: AccountLifecycle) -> CheckpointBody {
    CheckpointBody::new(
        typed_id(20),
        Epoch::new(1),
        Sequence::new(1),
        event_head,
        Digest::new(HashAlgorithm::Blake3_256, [30; 32]),
        Digest::new(HashAlgorithm::Blake3_256, [31; 32]),
        Digest::new(HashAlgorithm::Blake3_256, [32; 32]),
        typed_id::<ControlPolicyId>(33),
        typed_id::<RecoveryPolicyId>(34),
        typed_id::<ProviderPolicyId>(35),
        typed_id::<CryptoStateId>(36),
        lifecycle,
        Timestamp::from_unix_millis(37),
        Extensions::default(),
    )
    .unwrap()
}

#[test]
fn transition_checkpoint_witness_is_typed_eligible_and_head_bound() {
    let event = authorized_retirement();
    let event_id = event.event_id().unwrap();
    let authorization = CheckpointAuthorization::transition_derived(&event).unwrap();
    let witness = authorization.transition_witness().unwrap();
    assert_eq!(
        witness.transition_kind(),
        CheckpointTransitionKind::RetireAccount
    );
    assert_eq!(witness.event_id(), event_id);
    assert_eq!(
        witness.event_authorization_id(),
        event.event_authorization_id().unwrap()
    );

    let checkpoint = SignedCheckpoint::new(
        checkpoint_body(event_id, AccountLifecycle::Retired),
        authorization.clone(),
    )
    .unwrap();
    assert_eq!(
        SignedCheckpoint::from_canonical_bytes(&checkpoint.to_canonical_bytes().unwrap()).unwrap(),
        checkpoint
    );

    assert!(matches!(
        SignedCheckpoint::new(
            checkpoint_body(typed_id(38), AccountLifecycle::Retired),
            authorization.clone(),
        ),
        Err(IdentityError::InvalidRelationship { .. })
    ));
    assert!(matches!(
        SignedCheckpoint::new(
            checkpoint_body(event_id, AccountLifecycle::Active),
            authorization,
        ),
        Err(IdentityError::InvalidRelationship { .. })
    ));

    let ordinary = authorized_event(AccountOperation::ChangeProviderPolicy(
        ProviderPolicy::local_only(ProviderPolicyVersion::GENESIS, Extensions::default()).unwrap(),
    ));
    assert!(matches!(
        CheckpointAuthorization::transition_derived(&ordinary),
        Err(IdentityError::InvalidRelationship { .. })
    ));
}

#[test]
fn checkpoint_constructors_reject_unknown_critical_extensions() {
    assert!(matches!(
        ProviderLogEntryBody::new(
            typed_id(1),
            typed_id(2),
            typed_id(3),
            ProviderLogSubject::Checkpoint(typed_id(4)),
            Timestamp::from_unix_millis(5),
            unknown_critical_extensions(),
        ),
        Err(IdentityError::UnknownCriticalExtension { code: 65_535 })
    ));
    assert!(matches!(
        ProviderHeadBody::new(
            typed_id(1),
            typed_id(2),
            ProviderKeyVersion::GENESIS,
            1,
            Digest::new(HashAlgorithm::Blake3_256, [3; 32]),
            Timestamp::from_unix_millis(5),
            unknown_critical_extensions(),
        ),
        Err(IdentityError::UnknownCriticalExtension { code: 65_535 })
    ));
    assert!(matches!(
        CheckpointBody::new(
            typed_id(1),
            Epoch::new(2),
            Sequence::new(3),
            typed_id(4),
            Digest::new(HashAlgorithm::Blake3_256, [5; 32]),
            Digest::new(HashAlgorithm::Blake3_256, [6; 32]),
            Digest::new(HashAlgorithm::Blake3_256, [7; 32]),
            typed_id::<ControlPolicyId>(8),
            typed_id::<RecoveryPolicyId>(9),
            typed_id::<ProviderPolicyId>(10),
            typed_id::<CryptoStateId>(11),
            AccountLifecycle::Active,
            Timestamp::from_unix_millis(12),
            unknown_critical_extensions(),
        ),
        Err(IdentityError::UnknownCriticalExtension { code: 65_535 })
    ));
}

#[test]
fn provider_receipts_are_bounded_sorted_and_subject_consistent() {
    let account_id: AccountId = typed_id(1);
    let checkpoint_id: CheckpointId = typed_id(2);
    let provider_id: ProviderId = typed_id(3);
    let log_id: ProviderLogId = typed_id(4);
    let entry = ProviderLogEntryBody::new(
        provider_id,
        log_id,
        account_id,
        ProviderLogSubject::Checkpoint(checkpoint_id),
        Timestamp::from_unix_millis(100),
        Extensions::default(),
    )
    .unwrap();
    let head = ProviderHeadBody::new(
        provider_id,
        log_id,
        ProviderKeyVersion::GENESIS,
        1,
        Digest::new(HashAlgorithm::Blake3_256, [5; 32]),
        Timestamp::from_unix_millis(101),
        Extensions::default(),
    )
    .unwrap();
    let receipt = InclusionReceipt::new(
        entry,
        0,
        vec![],
        SignedProviderHead::new(head, ProtocolSignature::ed25519([6; 64])),
    )
    .unwrap();
    let receipts = ProviderReceipts::new(vec![receipt.clone()]).unwrap();
    assert_eq!(receipts.as_slice(), std::slice::from_ref(&receipt));

    assert!(ProviderReceipts::new(vec![receipt.clone(), receipt]).is_err());
    assert_eq!(
        ProviderReceipts::from_canonical_bytes(&receipts.to_canonical_bytes().unwrap()).unwrap(),
        receipts
    );
}

#[test]
fn checkpoint_id_hashes_only_the_canonical_body() {
    let body = CheckpointBody::new(
        typed_id(1),
        Epoch::new(2),
        Sequence::new(3),
        typed_id(4),
        Digest::new(HashAlgorithm::Blake3_256, [5; 32]),
        Digest::new(HashAlgorithm::Blake3_256, [6; 32]),
        Digest::new(HashAlgorithm::Blake3_256, [7; 32]),
        typed_id::<ControlPolicyId>(8),
        typed_id::<RecoveryPolicyId>(9),
        typed_id::<ProviderPolicyId>(10),
        typed_id::<CryptoStateId>(11),
        AccountLifecycle::Active,
        Timestamp::from_unix_millis(12),
        Extensions::default(),
    )
    .unwrap();
    let checkpoint_id = body.checkpoint_id().unwrap();
    assert_eq!(
        hex::encode(body.to_canonical_bytes().unwrap()),
        "010101010101010101010101010101010101010101010101010101010101010101010203010404040404040404040404040404040404040404040404040404040404040404010505050505050505050505050505050505050505050505050505050505050505010606060606060606060606060606060606060606060606060606060606060606010707070707070707070707070707070707070707070707070707070707070707010808080808080808080808080808080808080808080808080808080808080808010909090909090909090909090909090909090909090909090909090909090909010a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b010c00"
    );
    assert_eq!(
        checkpoint_id.to_string(),
        "b3:2ec9928a9a1c43fdaf59ac0228675cbb7249d25ea44acd54961e8318f5078e4e"
    );
    assert_eq!(
        CheckpointBody::from_canonical_bytes(&body.to_canonical_bytes().unwrap())
            .unwrap()
            .checkpoint_id()
            .unwrap(),
        checkpoint_id
    );
}
