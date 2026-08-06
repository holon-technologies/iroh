use krikos_base::SecretKey;
use krikos_identity::{
    AccountGenesis, AccountId, AccountOperation, AccountState, AdmissionEvidence,
    AlgorithmSignature, CanonicalWire, CheckpointId, ControlPolicy, ControllerApprovalBody,
    ControllerApprovals, ControllerClass, ControllerDescriptor, ControllerKeyId, ControllerScope,
    ControllerSelector, ControllerThreshold, ControllerWeight, CryptoSuiteDescriptor,
    DelayEvidence, Digest, DurationMillis, Epoch, EventBody, EventId, EventIntentApprovalBody,
    EventIntentApprovals, EventPredecessors, Extensions, FreshnessEvidence, FreshnessRequirement,
    HashAlgorithm, IdentityError, InclusionReceipt, KeyedSignature, OperationKind, PolicyRule,
    ProtocolSignature, ProviderDescriptor, ProviderFreshness, ProviderHeadBody, ProviderKeyVersion,
    ProviderLogEntryBody, ProviderLogId, ProviderLogSubject, ProviderPolicy, ProviderPolicyId,
    ProviderPolicyVersion, ProviderQuorum, ProviderReceipts, RecoveryAuthority, RecoveryPolicy,
    RecoveryPolicyVersion, RequiredWeight, Sequence, SignedControllerApproval,
    SignedEventIntentApproval, SignedProviderHead, SigningPublicKey, Timestamp,
    verify_event_intent_admission,
};

fn typed_id<T: CanonicalWire>(fill: u8) -> T {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [fill; 32]);
    T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
}

fn descriptor(secret: &SecretKey, weight: u32, scope: ControllerScope) -> ControllerDescriptor {
    ControllerDescriptor::new(
        SigningPublicKey::ed25519(*secret.public().as_bytes()).unwrap(),
        ControllerClass::PersonalDevice,
        ControllerWeight::new(weight).unwrap(),
        scope,
        Extensions::default(),
    )
    .unwrap()
}

fn state(required_weight: u32) -> (AccountState, SecretKey, SecretKey) {
    let first = SecretKey::from_bytes(&[11; 32]);
    let second = SecretKey::from_bytes(&[12; 32]);
    let controllers = vec![
        descriptor(&first, 1, ControllerScope::all_v1_operations()),
        descriptor(&second, 1, ControllerScope::all_v1_operations()),
    ];
    let policy = ControlPolicy::new(
        vec![
            PolicyRule::new(
                OperationKind::AddController,
                RequiredWeight::new(required_weight).unwrap(),
                ControllerSelector::any_active(),
                FreshnessRequirement::latest_known(),
                None,
                Extensions::default(),
            )
            .unwrap(),
        ],
        Extensions::default(),
    )
    .unwrap();
    let recovery = RecoveryPolicy::new(
        RecoveryPolicyVersion::GENESIS,
        RecoveryAuthority::controller_threshold(ControllerThreshold::new(
            ControllerSelector::any_active(),
            RequiredWeight::new(1).unwrap(),
        )),
        DurationMillis::new(10),
        DurationMillis::new(100),
        Extensions::default(),
    )
    .unwrap();
    let genesis = AccountGenesis::new(
        [2; 32],
        Timestamp::from_unix_millis(1),
        policy,
        controllers,
        recovery,
        ProviderPolicy::local_only(ProviderPolicyVersion::GENESIS, Extensions::default()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    (AccountState::from_genesis(&genesis).unwrap(), first, second)
}

fn delayed_state() -> (
    AccountState,
    SecretKey,
    SecretKey,
    SecretKey,
    ProviderDescriptor,
) {
    delayed_state_with_freshness(FreshnessRequirement::provider_quorum(
        ProviderFreshness::new(ProviderQuorum::new(1).unwrap(), DurationMillis::new(100)).unwrap(),
    ))
}

fn delayed_state_with_freshness(
    rule_freshness: FreshnessRequirement,
) -> (
    AccountState,
    SecretKey,
    SecretKey,
    SecretKey,
    ProviderDescriptor,
) {
    let first = SecretKey::from_bytes(&[21; 32]);
    let second = SecretKey::from_bytes(&[22; 32]);
    let provider_secret = SecretKey::from_bytes(&[23; 32]);
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*provider_secret.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let policy = ControlPolicy::new(
        vec![
            PolicyRule::new(
                OperationKind::AddController,
                RequiredWeight::new(2).unwrap(),
                ControllerSelector::any_active(),
                rule_freshness,
                Some(DurationMillis::new(10)),
                Extensions::default(),
            )
            .unwrap(),
        ],
        Extensions::default(),
    )
    .unwrap();
    let recovery = RecoveryPolicy::new(
        RecoveryPolicyVersion::GENESIS,
        RecoveryAuthority::controller_threshold(ControllerThreshold::new(
            ControllerSelector::any_active(),
            RequiredWeight::new(1).unwrap(),
        )),
        DurationMillis::new(10),
        DurationMillis::new(100),
        Extensions::default(),
    )
    .unwrap();
    let genesis = AccountGenesis::new(
        [3; 32],
        Timestamp::from_unix_millis(1),
        policy,
        vec![
            descriptor(&first, 1, ControllerScope::all_v1_operations()),
            descriptor(&second, 1, ControllerScope::all_v1_operations()),
        ],
        recovery,
        ProviderPolicy::replicated(
            ProviderPolicyVersion::GENESIS,
            vec![provider.clone()],
            ProviderQuorum::new(1).unwrap(),
            ProviderQuorum::new(1).unwrap(),
            DurationMillis::new(100),
            Extensions::default(),
        )
        .unwrap(),
        Extensions::default(),
    )
    .unwrap();
    (
        AccountState::from_genesis(&genesis).unwrap(),
        first,
        second,
        provider_secret,
        provider,
    )
}

fn replicated_freshness_state(
    account_quorum: u16,
) -> (
    AccountState,
    SecretKey,
    SecretKey,
    ProviderDescriptor,
    SecretKey,
    ProviderDescriptor,
) {
    let controller_secret = SecretKey::from_bytes(&[31; 32]);
    let first_provider_secret = SecretKey::from_bytes(&[32; 32]);
    let second_provider_secret = SecretKey::from_bytes(&[33; 32]);
    let first_provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*first_provider_secret.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let second_provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*second_provider_secret.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let policy = ControlPolicy::new(
        vec![
            PolicyRule::new(
                OperationKind::AddController,
                RequiredWeight::new(1).unwrap(),
                ControllerSelector::any_active(),
                FreshnessRequirement::provider_quorum(
                    ProviderFreshness::new(
                        ProviderQuorum::new(1).unwrap(),
                        DurationMillis::new(100),
                    )
                    .unwrap(),
                ),
                None,
                Extensions::default(),
            )
            .unwrap(),
        ],
        Extensions::default(),
    )
    .unwrap();
    let recovery = RecoveryPolicy::new(
        RecoveryPolicyVersion::GENESIS,
        RecoveryAuthority::controller_threshold(ControllerThreshold::new(
            ControllerSelector::any_active(),
            RequiredWeight::new(1).unwrap(),
        )),
        DurationMillis::new(10),
        DurationMillis::new(100),
        Extensions::default(),
    )
    .unwrap();
    let genesis = AccountGenesis::new(
        [4; 32],
        Timestamp::from_unix_millis(1),
        policy,
        vec![descriptor(
            &controller_secret,
            1,
            ControllerScope::all_v1_operations(),
        )],
        recovery,
        ProviderPolicy::replicated(
            ProviderPolicyVersion::GENESIS,
            vec![first_provider.clone(), second_provider.clone()],
            ProviderQuorum::new(account_quorum).unwrap(),
            ProviderQuorum::new(2).unwrap(),
            DurationMillis::new(100),
            Extensions::default(),
        )
        .unwrap(),
        Extensions::default(),
    )
    .unwrap();
    (
        AccountState::from_genesis(&genesis).unwrap(),
        controller_secret,
        first_provider_secret,
        first_provider,
        second_provider_secret,
        second_provider,
    )
}

fn provider_receipt(
    provider: &ProviderDescriptor,
    provider_secret: &SecretKey,
    state: &AccountState,
    subject: ProviderLogSubject,
    observed_at: u64,
    fill: u8,
) -> InclusionReceipt {
    provider_receipt_with_head_time(
        provider,
        provider_secret,
        state,
        subject,
        observed_at,
        observed_at,
        fill,
    )
}

fn provider_receipt_with_head_time(
    provider: &ProviderDescriptor,
    provider_secret: &SecretKey,
    state: &AccountState,
    subject: ProviderLogSubject,
    entry_observed_at: u64,
    head_observed_at: u64,
    fill: u8,
) -> InclusionReceipt {
    let log_id = typed_id::<ProviderLogId>(fill);
    let entry = ProviderLogEntryBody::new(
        provider.id().unwrap(),
        log_id,
        state.account_id(),
        subject,
        Timestamp::from_unix_millis(entry_observed_at),
        Extensions::default(),
    )
    .unwrap();
    let leaf_root = entry.merkle_leaf_hash().unwrap();
    let head = ProviderHeadBody::new(
        provider.id().unwrap(),
        log_id,
        ProviderKeyVersion::GENESIS,
        1,
        leaf_root,
        Timestamp::from_unix_millis(head_observed_at),
        Extensions::default(),
    )
    .unwrap();
    let signature = provider_secret.sign(&head.signing_bytes().unwrap());
    InclusionReceipt::new(
        entry,
        0,
        Vec::new(),
        SignedProviderHead::new(head, ProtocolSignature::ed25519(signature.to_bytes())),
    )
    .unwrap()
}

fn signed_intent(
    state: &AccountState,
    proposal_id: krikos_identity::ProposalId,
    controller_secret: &SecretKey,
    signing_secret: &SecretKey,
) -> SignedEventIntentApproval {
    let signing_key = SigningPublicKey::ed25519(*controller_secret.public().as_bytes()).unwrap();
    let controller_id = state
        .active_controllers()
        .iter()
        .find(|controller| controller.signing_key() == signing_key)
        .unwrap()
        .id();
    let body =
        EventIntentApprovalBody::new(controller_id, proposal_id, Extensions::default()).unwrap();
    let signature = signing_secret.sign(&body.to_canonical_bytes().unwrap());
    SignedEventIntentApproval::new(
        body,
        vec![KeyedSignature::new(
            CryptoSuiteDescriptor::v1()
                .unwrap()
                .crypto_suite_id()
                .unwrap(),
            ControllerKeyId::for_signing_key(&signing_key).unwrap(),
            AlgorithmSignature::new(1, signature.to_bytes().to_vec()).unwrap(),
        )],
    )
    .unwrap()
}

fn delayed_event(
    state: &AccountState,
    final_signers: &[&SecretKey],
    intents: Vec<SignedEventIntentApproval>,
    provider: &ProviderDescriptor,
    provider_secret: &SecretKey,
) -> krikos_identity::AuthorizedEvent {
    let body = unsigned_body(state);
    let checkpoint_id = typed_id::<CheckpointId>(0x57);
    let proposal_id = body.proposal_id().unwrap();
    let intent_receipts = ProviderReceipts::new(vec![provider_receipt(
        provider,
        provider_secret,
        state,
        ProviderLogSubject::EventIntent(proposal_id),
        10,
        0x71,
    )])
    .unwrap();
    let completion_receipts = ProviderReceipts::new(vec![provider_receipt_with_head_time(
        provider,
        provider_secret,
        state,
        ProviderLogSubject::Checkpoint(checkpoint_id),
        5,
        20,
        0x72,
    )])
    .unwrap();
    let evidence = AdmissionEvidence::new(
        proposal_id,
        checkpoint_id,
        state.provider_policy_id(),
        FreshnessEvidence::provider_quorum(
            checkpoint_id,
            state.provider_policy_id(),
            completion_receipts,
        )
        .unwrap(),
        DelayEvidence::provider_quorum(
            state.provider_policy_id(),
            ProviderQuorum::new(1).unwrap(),
            EventIntentApprovals::new(intents).unwrap(),
            intent_receipts,
        )
        .unwrap(),
        Extensions::default(),
    )
    .unwrap();
    authorized_event_with_evidence(state, body, evidence, final_signers)
}

fn event_with_provider_freshness(
    state: &AccountState,
    signer: &SecretKey,
    checkpoint_id: CheckpointId,
    receipts: ProviderReceipts,
) -> krikos_identity::AuthorizedEvent {
    let body = unsigned_body(state);
    let evidence = AdmissionEvidence::new(
        body.proposal_id().unwrap(),
        checkpoint_id,
        state.provider_policy_id(),
        FreshnessEvidence::provider_quorum(checkpoint_id, state.provider_policy_id(), receipts)
            .unwrap(),
        DelayEvidence::none(),
        Extensions::default(),
    )
    .unwrap();
    authorized_event_with_evidence(state, body, evidence, &[signer])
}

fn unsigned_body(state: &AccountState) -> EventBody {
    EventBody::new(
        state.account_id(),
        Sequence::new(1),
        Epoch::new(1),
        EventPredecessors::genesis(state.genesis_anchor()),
        AccountOperation::AddController(descriptor(
            &SecretKey::from_bytes(&[13; 32]),
            1,
            ControllerScope::all_v1_operations(),
        )),
        Timestamp::from_unix_millis(2),
        [9; 16],
        Extensions::default(),
    )
    .unwrap()
}

fn signed_event(
    state: &AccountState,
    body: EventBody,
    signers: &[&SecretKey],
) -> krikos_identity::AuthorizedEvent {
    signed_event_with_provider_policy(state, body, signers, state.provider_policy_id())
}

fn signed_event_with_provider_policy(
    state: &AccountState,
    body: EventBody,
    signers: &[&SecretKey],
    provider_policy_id: ProviderPolicyId,
) -> krikos_identity::AuthorizedEvent {
    signed_event_with_checkpoint(state, body, signers, provider_policy_id, 0x55)
}

fn signed_event_with_checkpoint(
    state: &AccountState,
    body: EventBody,
    signers: &[&SecretKey],
    provider_policy_id: ProviderPolicyId,
    checkpoint_fill: u8,
) -> krikos_identity::AuthorizedEvent {
    let checkpoint = typed_id::<CheckpointId>(checkpoint_fill);
    let evidence = AdmissionEvidence::new(
        body.proposal_id().unwrap(),
        checkpoint,
        provider_policy_id,
        FreshnessEvidence::local_known(checkpoint),
        DelayEvidence::none(),
        Extensions::default(),
    )
    .unwrap();
    authorized_event_with_evidence(state, body, evidence, signers)
}

fn authorized_event_with_evidence(
    state: &AccountState,
    body: EventBody,
    evidence: AdmissionEvidence,
    signers: &[&SecretKey],
) -> krikos_identity::AuthorizedEvent {
    let event_id = evidence.event_id_for_body(&body).unwrap();
    let evidence_id = evidence.admission_evidence_id().unwrap();
    let suite_id = CryptoSuiteDescriptor::v1()
        .unwrap()
        .crypto_suite_id()
        .unwrap();
    let approvals = signers
        .iter()
        .map(|secret| {
            let signing_key = SigningPublicKey::ed25519(*secret.public().as_bytes()).unwrap();
            let controller_id = state
                .active_controllers()
                .iter()
                .find(|controller| controller.signing_key() == signing_key)
                .unwrap()
                .id();
            let approval_body = ControllerApprovalBody::event(
                controller_id,
                event_id,
                evidence_id,
                Extensions::default(),
            )
            .unwrap();
            let signature = secret.sign(&approval_body.to_canonical_bytes().unwrap());
            SignedControllerApproval::new(
                approval_body,
                vec![KeyedSignature::new(
                    suite_id,
                    ControllerKeyId::for_signing_key(&signing_key).unwrap(),
                    AlgorithmSignature::new(1, signature.to_bytes().to_vec()).unwrap(),
                )],
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    krikos_identity::AuthorizedEvent::new(
        body,
        evidence,
        ControllerApprovals::new(approvals).unwrap(),
    )
    .unwrap()
}

#[test]
fn sequence_predecessor_account_and_evidence_policy_are_bound_without_mutation() {
    let (mut projected, first, _) = state(1);
    let before = projected.clone();
    let operation = || {
        AccountOperation::AddController(descriptor(
            &SecretKey::from_bytes(&[13; 32]),
            1,
            ControllerScope::all_v1_operations(),
        ))
    };

    let skipped_sequence = EventBody::new(
        projected.account_id(),
        Sequence::new(2),
        Epoch::new(1),
        EventPredecessors::events(vec![typed_id::<EventId>(0x61)]).unwrap(),
        operation(),
        Timestamp::from_unix_millis(2),
        [0x61; 16],
        Extensions::default(),
    )
    .unwrap();
    assert_eq!(
        projected.validate_and_apply(&signed_event(&projected, skipped_sequence, &[&first])),
        Err(IdentityError::InvalidSequence)
    );
    assert_eq!(projected, before);

    let wrong_predecessor = EventBody::new(
        projected.account_id(),
        Sequence::new(1),
        Epoch::new(1),
        EventPredecessors::genesis(typed_id(0x62)),
        operation(),
        Timestamp::from_unix_millis(2),
        [0x62; 16],
        Extensions::default(),
    )
    .unwrap();
    assert_eq!(
        projected.validate_and_apply(&signed_event(&projected, wrong_predecessor, &[&first])),
        Err(IdentityError::InvalidPredecessor)
    );
    assert_eq!(projected, before);

    let wrong_account = EventBody::new(
        typed_id::<AccountId>(0x63),
        Sequence::new(1),
        Epoch::new(1),
        EventPredecessors::genesis(projected.genesis_anchor()),
        operation(),
        Timestamp::from_unix_millis(2),
        [0x63; 16],
        Extensions::default(),
    )
    .unwrap();
    assert_eq!(
        projected.validate_and_apply(&signed_event(&projected, wrong_account, &[&first])),
        Err(IdentityError::AccountMismatch)
    );
    assert_eq!(projected, before);

    let wrong_policy = signed_event_with_provider_policy(
        &projected,
        unsigned_body(&projected),
        &[&first],
        typed_id(0x64),
    );
    assert_eq!(
        projected.validate_and_apply(&wrong_policy),
        Err(IdentityError::PolicyVersionMismatch)
    );
    assert_eq!(projected, before);
}

#[test]
fn delayed_intent_uses_the_same_pre_state_threshold_and_exact_key_binding() {
    let (base, first, second, provider_secret, provider) = delayed_state();
    let proposal_id = unsigned_body(&base).proposal_id().unwrap();

    let mut valid_state = base.clone();
    let valid = delayed_event(
        &valid_state,
        &[&first, &second],
        vec![
            signed_intent(&valid_state, proposal_id, &first, &first),
            signed_intent(&valid_state, proposal_id, &second, &second),
        ],
        &provider,
        &provider_secret,
    );
    valid_state.validate_and_apply(&valid).unwrap();
    assert_eq!(valid_state.active_controllers().len(), 3);

    let mut insufficient_state = base.clone();
    let insufficient = delayed_event(
        &insufficient_state,
        &[&first, &second],
        vec![signed_intent(
            &insufficient_state,
            proposal_id,
            &first,
            &first,
        )],
        &provider,
        &provider_secret,
    );
    let before = insufficient_state.clone();
    assert_eq!(
        insufficient_state.validate_and_apply(&insufficient),
        Err(IdentityError::AuthorizationDenied)
    );
    assert_eq!(insufficient_state, before);

    let mut forged_state = base;
    let forged = delayed_event(
        &forged_state,
        &[&first, &second],
        vec![
            signed_intent(&forged_state, proposal_id, &first, &second),
            signed_intent(&forged_state, proposal_id, &second, &second),
        ],
        &provider,
        &provider_secret,
    );
    let before = forged_state.clone();
    assert_eq!(
        forged_state.validate_and_apply(&forged),
        Err(IdentityError::InvalidSignature)
    );
    assert_eq!(forged_state, before);
}

#[test]
fn provider_intent_admission_is_opaque_and_bound_to_the_exact_delayed_body() {
    let (base, first, second, _, _) = delayed_state();
    let body = unsigned_body(&base);
    let proposal_id = body.proposal_id().unwrap();
    let approvals = EventIntentApprovals::new(vec![
        signed_intent(&base, proposal_id, &first, &first),
        signed_intent(&base, proposal_id, &second, &second),
    ])
    .unwrap();

    let admission = verify_event_intent_admission(&base, &body, &approvals).unwrap();
    assert_eq!(admission.account_id(), base.account_id());
    assert_eq!(
        admission.subject(),
        ProviderLogSubject::EventIntent(proposal_id)
    );

    let insufficient =
        EventIntentApprovals::new(vec![signed_intent(&base, proposal_id, &first, &first)]).unwrap();
    assert_eq!(
        verify_event_intent_admission(&base, &body, &insufficient),
        Err(IdentityError::AuthorizationDenied)
    );

    let wrong_epoch = EventBody::new(
        base.account_id(),
        Sequence::new(1),
        Epoch::GENESIS,
        EventPredecessors::genesis(base.genesis_anchor()),
        body.operation().clone(),
        Timestamp::from_unix_millis(2),
        [0x75; 16],
        Extensions::default(),
    )
    .unwrap();
    assert_eq!(
        verify_event_intent_admission(&base, &wrong_epoch, &approvals),
        Err(IdentityError::InvalidEpoch)
    );

    let (undelayed, undelayed_first, undelayed_second) = state(2);
    let undelayed_body = unsigned_body(&undelayed);
    let undelayed_proposal = undelayed_body.proposal_id().unwrap();
    let undelayed_approvals = EventIntentApprovals::new(vec![
        signed_intent(
            &undelayed,
            undelayed_proposal,
            &undelayed_first,
            &undelayed_first,
        ),
        signed_intent(
            &undelayed,
            undelayed_proposal,
            &undelayed_second,
            &undelayed_second,
        ),
    ])
    .unwrap();
    assert!(matches!(
        verify_event_intent_admission(&undelayed, &undelayed_body, &undelayed_approvals),
        Err(IdentityError::InvalidRelationship { .. })
    ));
}

#[test]
fn latest_known_delayed_rule_derives_completion_from_authenticated_intent_heads() {
    let (base, first, second, provider_secret, provider) =
        delayed_state_with_freshness(FreshnessRequirement::latest_known());
    let build = |state: &AccountState, head_time: u64, fill: u8| {
        let body = unsigned_body(state);
        let proposal_id = body.proposal_id().unwrap();
        let checkpoint_id = typed_id::<CheckpointId>(0x58);
        let delay_receipts = ProviderReceipts::new(vec![provider_receipt_with_head_time(
            &provider,
            &provider_secret,
            state,
            ProviderLogSubject::EventIntent(proposal_id),
            10,
            head_time,
            fill,
        )])
        .unwrap();
        let evidence = AdmissionEvidence::new(
            proposal_id,
            checkpoint_id,
            state.provider_policy_id(),
            FreshnessEvidence::local_known(checkpoint_id),
            DelayEvidence::provider_quorum(
                state.provider_policy_id(),
                ProviderQuorum::new(1).unwrap(),
                EventIntentApprovals::new(vec![
                    signed_intent(state, proposal_id, &first, &first),
                    signed_intent(state, proposal_id, &second, &second),
                ])
                .unwrap(),
                delay_receipts,
            )
            .unwrap(),
            Extensions::default(),
        )
        .unwrap();
        authorized_event_with_evidence(state, body, evidence, &[&first, &second])
    };

    let mut below_boundary = base.clone();
    let before = below_boundary.clone();
    assert_eq!(
        below_boundary.validate_and_apply(&build(&below_boundary, 19, 0x79)),
        Err(IdentityError::DelayNotElapsed)
    );
    assert_eq!(below_boundary, before);

    let mut exact_boundary = base;
    exact_boundary
        .validate_and_apply(&build(&exact_boundary, 20, 0x7a))
        .unwrap();
}

#[test]
fn provider_freshness_uses_monotonic_quorum_and_signed_head_age_boundaries() {
    let (
        base,
        controller,
        first_provider_secret,
        first_provider,
        second_provider_secret,
        second_provider,
    ) = replicated_freshness_state(1);
    let checkpoint_id = typed_id::<CheckpointId>(0x73);
    let stale = provider_receipt_with_head_time(
        &first_provider,
        &first_provider_secret,
        &base,
        ProviderLogSubject::Checkpoint(checkpoint_id),
        10,
        111,
        0x74,
    );
    let exact_boundary = provider_receipt_with_head_time(
        &second_provider,
        &second_provider_secret,
        &base,
        ProviderLogSubject::Checkpoint(checkpoint_id),
        10,
        110,
        0x75,
    );
    let mut with_extra_stale = base.clone();
    let event = event_with_provider_freshness(
        &with_extra_stale,
        &controller,
        checkpoint_id,
        ProviderReceipts::new(vec![stale.clone(), exact_boundary]).unwrap(),
    );
    with_extra_stale.validate_and_apply(&event).unwrap();

    let mut only_stale = base.clone();
    let stale_event = event_with_provider_freshness(
        &only_stale,
        &controller,
        checkpoint_id,
        ProviderReceipts::new(vec![stale]).unwrap(),
    );
    let before = only_stale.clone();
    assert_eq!(
        only_stale.validate_and_apply(&stale_event),
        Err(IdentityError::StaleEvidence)
    );
    assert_eq!(only_stale, before);

    let forged_receipt = provider_receipt_with_head_time(
        &first_provider,
        &second_provider_secret,
        &base,
        ProviderLogSubject::Checkpoint(checkpoint_id),
        10,
        110,
        0x7a,
    );
    let mut forged_state = base.clone();
    let forged_event = event_with_provider_freshness(
        &forged_state,
        &controller,
        checkpoint_id,
        ProviderReceipts::new(vec![forged_receipt]).unwrap(),
    );
    let before = forged_state.clone();
    assert_eq!(
        forged_state.validate_and_apply(&forged_event),
        Err(IdentityError::InvalidSignature)
    );
    assert_eq!(forged_state, before);

    let (mut account_requires_two, controller, first_provider_secret, first_provider, _, _) =
        replicated_freshness_state(2);
    let one_valid = provider_receipt_with_head_time(
        &first_provider,
        &first_provider_secret,
        &account_requires_two,
        ProviderLogSubject::Checkpoint(checkpoint_id),
        10,
        110,
        0x76,
    );
    let one_provider_event = event_with_provider_freshness(
        &account_requires_two,
        &controller,
        checkpoint_id,
        ProviderReceipts::new(vec![one_valid]).unwrap(),
    );
    assert_eq!(
        account_requires_two.validate_and_apply(&one_provider_event),
        Err(IdentityError::FreshnessUnavailable)
    );

    let mut reversed_time = base;
    let invalid_time = provider_receipt_with_head_time(
        &first_provider,
        &first_provider_secret,
        &reversed_time,
        ProviderLogSubject::Checkpoint(checkpoint_id),
        11,
        10,
        0x77,
    );
    let invalid_time_event = event_with_provider_freshness(
        &reversed_time,
        &controller,
        checkpoint_id,
        ProviderReceipts::new(vec![invalid_time]).unwrap(),
    );
    assert_eq!(
        reversed_time.validate_and_apply(&invalid_time_event),
        Err(IdentityError::InvalidRelationship {
            resource: "provider head observation time"
        })
    );
}

#[test]
fn weighted_threshold_is_evaluated_from_pre_state() {
    let (mut state, first, second) = state(2);
    let body = unsigned_body(&state);
    let short = signed_event(&state, body.clone(), &[&first]);
    let before = state.clone();
    assert_eq!(
        state.validate_and_apply(&short),
        Err(IdentityError::AuthorizationDenied)
    );
    assert_eq!(state, before);

    let sufficient = signed_event(&state, body, &[&first, &second]);
    state.validate_and_apply(&sufficient).unwrap();
    assert_eq!(state.active_controllers().len(), 3);
}

#[test]
fn empty_outer_approvals_are_rejected_for_ordinary_operations() {
    let (state, first, _) = state(1);
    let valid = signed_event(&state, unsigned_body(&state), &[&first]);
    let empty = ControllerApprovals::new(Vec::new()).unwrap();
    assert_eq!(
        krikos_identity::AuthorizedEvent::new(
            valid.body().clone(),
            valid.admission_evidence().clone(),
            empty,
        ),
        Err(IdentityError::InvalidRelationship {
            resource: "authorized event controller approval cardinality"
        })
    );
}

#[test]
fn invalid_signature_and_wrong_key_binding_fail_closed() {
    let (mut state, first, second) = state(1);
    let body = unsigned_body(&state);
    let event = signed_event(&state, body, &[&first]);
    let first_key = SigningPublicKey::ed25519(*first.public().as_bytes()).unwrap();
    let first_controller = state
        .active_controllers()
        .iter()
        .find(|controller| controller.signing_key() == first_key)
        .unwrap()
        .id();
    let approval_body = ControllerApprovalBody::event(
        first_controller,
        event.event_id().unwrap(),
        event.admission_evidence().admission_evidence_id().unwrap(),
        Extensions::default(),
    );
    let approval_body = approval_body.unwrap();
    let forged_signature = second.sign(&approval_body.to_canonical_bytes().unwrap());
    let forged = krikos_identity::AuthorizedEvent::new(
        event.body().clone(),
        event.admission_evidence().clone(),
        ControllerApprovals::new(vec![
            SignedControllerApproval::new(
                approval_body.clone(),
                vec![KeyedSignature::new(
                    CryptoSuiteDescriptor::v1()
                        .unwrap()
                        .crypto_suite_id()
                        .unwrap(),
                    ControllerKeyId::for_signing_key(&first_key).unwrap(),
                    AlgorithmSignature::new(1, forged_signature.to_bytes().to_vec()).unwrap(),
                )],
            )
            .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();

    let before = state.clone();
    assert_eq!(
        state.validate_and_apply(&forged),
        Err(IdentityError::InvalidSignature)
    );
    assert_eq!(state, before);

    let valid_signature = first.sign(&approval_body.to_canonical_bytes().unwrap());
    let wrong_key_binding = krikos_identity::AuthorizedEvent::new(
        event.body().clone(),
        event.admission_evidence().clone(),
        ControllerApprovals::new(vec![
            SignedControllerApproval::new(
                approval_body,
                vec![KeyedSignature::new(
                    CryptoSuiteDescriptor::v1()
                        .unwrap()
                        .crypto_suite_id()
                        .unwrap(),
                    ControllerKeyId::for_signing_key(
                        &SigningPublicKey::ed25519(*second.public().as_bytes()).unwrap(),
                    )
                    .unwrap(),
                    AlgorithmSignature::new(1, valid_signature.to_bytes().to_vec()).unwrap(),
                )],
            )
            .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        state.validate_and_apply(&wrong_key_binding),
        Err(IdentityError::InvalidSignature)
    );
    assert_eq!(state, before);
}

#[test]
fn disjoint_valid_signature_subsets_merge_without_creating_a_fork() {
    let (mut state, first, second) = state(1);
    let body = unsigned_body(&state);
    let first_subset = signed_event(&state, body.clone(), &[&first]);
    let second_subset = signed_event(&state, body, &[&second]);
    assert_eq!(
        first_subset.admission_evidence(),
        second_subset.admission_evidence()
    );
    let event_id = first_subset.event_id().unwrap();
    assert_eq!(second_subset.event_id().unwrap(), event_id);
    state.validate_and_apply(&first_subset).unwrap();

    let merged = state.validate_and_apply(&second_subset).unwrap();
    assert_eq!(
        merged.disposition(),
        krikos_identity::ApplyDisposition::ApprovalsMerged
    );
    assert_eq!(merged.event_id(), event_id);
    assert_eq!(state.heads(), [event_id]);
    assert_eq!(
        state.lifecycle(),
        krikos_identity::ProjectionLifecycle::Active
    );
    assert_eq!(
        state
            .validate_and_apply(&first_subset)
            .unwrap()
            .disposition(),
        krikos_identity::ApplyDisposition::Replay
    );
}

#[test]
fn distinct_valid_admission_envelopes_converge_to_one_detectable_fork() {
    let (base, first, _) = state(1);
    let body = unsigned_body(&base);
    let first_envelope = signed_event_with_checkpoint(
        &base,
        body.clone(),
        &[&first],
        base.provider_policy_id(),
        0x31,
    );
    let second_envelope =
        signed_event_with_checkpoint(&base, body, &[&first], base.provider_policy_id(), 0x32);
    assert_ne!(
        first_envelope.admission_evidence(),
        second_envelope.admission_evidence()
    );
    assert_ne!(
        first_envelope.event_id().unwrap(),
        second_envelope.event_id().unwrap()
    );

    let mut left = base.clone();
    left.validate_and_apply(&first_envelope).unwrap();
    assert_eq!(
        left.validate_and_apply(&second_envelope)
            .unwrap()
            .disposition(),
        krikos_identity::ApplyDisposition::ForkDetected
    );

    let mut right = base;
    right.validate_and_apply(&second_envelope).unwrap();
    assert_eq!(
        right
            .validate_and_apply(&first_envelope)
            .unwrap()
            .disposition(),
        krikos_identity::ApplyDisposition::ForkDetected
    );

    assert_eq!(left, right);
    assert_eq!(
        left.lifecycle(),
        krikos_identity::ProjectionLifecycle::Forked
    );
    let mut expected_heads = vec![
        first_envelope.event_id().unwrap(),
        second_envelope.event_id().unwrap(),
    ];
    expected_heads.sort_unstable();
    assert_eq!(left.heads(), expected_heads);
}

#[test]
fn missing_policy_rule_is_default_deny() {
    let (state, first, _) = state(1);
    let body = EventBody::new(
        state.account_id(),
        Sequence::new(1),
        Epoch::new(1),
        EventPredecessors::genesis(state.genesis_anchor()),
        AccountOperation::RemoveController(state.active_controllers()[1].id()),
        Timestamp::from_unix_millis(2),
        [10; 16],
        Extensions::default(),
    )
    .unwrap();
    let event = signed_event(&state, body, &[&first]);
    let mut projected = state;
    assert_eq!(
        projected.validate_and_apply(&event),
        Err(IdentityError::AuthorizationDenied)
    );
}
