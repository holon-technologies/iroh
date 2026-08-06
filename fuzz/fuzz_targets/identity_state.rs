#![no_main]

use krikos_base::SecretKey;
use krikos_identity::{
    AccountGenesis, AccountOperation, AccountState, AdmissionEvidence, AlgorithmSignature,
    ApplyDisposition, CanonicalWire, CheckpointId, ControlPolicy, ControllerApprovalBody,
    ControllerApprovals, ControllerClass, ControllerDescriptor, ControllerKeyId, ControllerScope,
    ControllerSelector, ControllerThreshold, ControllerWeight, CryptoSuiteDescriptor,
    DelayEvidence, Digest, DurationMillis, Epoch, EventBody, EventPredecessors, Extensions,
    FreshnessEvidence, FreshnessRequirement, HashAlgorithm, OperationKind, PolicyRule,
    ProjectionLifecycle, ProviderPolicy, ProviderPolicyVersion, RecoveryAuthority, RecoveryPolicy,
    RecoveryPolicyVersion, RequiredWeight, Sequence, SignedControllerApproval, SigningPublicKey,
    Timestamp,
};
use libfuzzer_sys::fuzz_target;

fn typed_id<T: CanonicalWire>(fill: u8) -> T {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [fill; 32]);
    T::from_canonical_bytes(&digest.to_canonical_bytes().expect("digest encodes"))
        .expect("typed digest ID decodes")
}

fn controller(secret: &SecretKey) -> ControllerDescriptor {
    ControllerDescriptor::new(
        SigningPublicKey::ed25519(*secret.public().as_bytes()).expect("valid key"),
        ControllerClass::PersonalDevice,
        ControllerWeight::new(1).expect("nonzero weight"),
        ControllerScope::all_v1_operations(),
        Extensions::default(),
    )
    .expect("valid controller")
}

fn rule(operation: OperationKind) -> PolicyRule {
    PolicyRule::new(
        operation,
        RequiredWeight::new(1).expect("nonzero weight"),
        ControllerSelector::any_active(),
        FreshnessRequirement::latest_known(),
        None,
        Extensions::default(),
    )
    .expect("valid rule")
}

fn fixture() -> (AccountState, SecretKey) {
    let secret = SecretKey::from_bytes(&[0x31; 32]);
    let policy = ControlPolicy::new(
        vec![
            rule(OperationKind::AddController),
            rule(OperationKind::ChangeProviderPolicy),
        ],
        Extensions::default(),
    )
    .expect("valid policy");
    let recovery = RecoveryPolicy::new(
        RecoveryPolicyVersion::GENESIS,
        RecoveryAuthority::controller_threshold(ControllerThreshold::new(
            ControllerSelector::any_active(),
            RequiredWeight::new(1).expect("nonzero weight"),
        )),
        DurationMillis::new(10),
        DurationMillis::new(100),
        Extensions::default(),
    )
    .expect("valid recovery policy");
    let genesis = AccountGenesis::new(
        [0x31; 32],
        Timestamp::from_unix_millis(1),
        policy,
        vec![controller(&secret)],
        recovery,
        ProviderPolicy::local_only(ProviderPolicyVersion::GENESIS, Extensions::default())
            .expect("valid provider policy"),
        Extensions::default(),
    )
    .expect("valid genesis");
    (
        AccountState::from_genesis(&genesis).expect("genesis projects"),
        secret,
    )
}

fn event(
    state: &AccountState,
    operation: AccountOperation,
    resulting_epoch: Epoch,
    nonce: u8,
    signer: &SecretKey,
) -> krikos_identity::AuthorizedEvent {
    let predecessors = if state.sequence() == Sequence::GENESIS {
        EventPredecessors::genesis(state.genesis_anchor())
    } else {
        EventPredecessors::events(state.heads().to_vec()).expect("bounded heads")
    };
    let body = EventBody::new(
        state.account_id(),
        state.sequence().checked_next().expect("bounded sequence"),
        resulting_epoch,
        predecessors,
        operation,
        Timestamp::from_unix_millis(u64::from(nonce)),
        [nonce.max(1); 16],
        Extensions::default(),
    )
    .expect("valid event body");
    let checkpoint_id = typed_id::<CheckpointId>(0x44);
    let evidence = AdmissionEvidence::new(
        body.proposal_id().expect("proposal ID"),
        checkpoint_id,
        state.provider_policy_id(),
        FreshnessEvidence::local_known(checkpoint_id),
        DelayEvidence::none(),
        Extensions::default(),
    )
    .expect("valid admission evidence");
    let event_id = evidence
        .event_id_for_body(&body)
        .expect("admitted event ID");
    let signing_key = SigningPublicKey::ed25519(*signer.public().as_bytes()).expect("valid key");
    let controller_id = state
        .active_controllers()
        .iter()
        .find(|projected| projected.signing_key() == signing_key)
        .expect("signer is active")
        .id();
    let approval_body = ControllerApprovalBody::event(
        controller_id,
        event_id,
        evidence
            .admission_evidence_id()
            .expect("admission evidence ID"),
        Extensions::default(),
    )
    .expect("valid approval body");
    let signature = signer.sign(
        &approval_body
            .to_canonical_bytes()
            .expect("approval body encodes"),
    );
    let approval = SignedControllerApproval::new(
        approval_body,
        vec![krikos_identity::KeyedSignature::new(
            CryptoSuiteDescriptor::v1()
                .expect("v1 suite")
                .crypto_suite_id()
                .expect("suite ID"),
            ControllerKeyId::for_signing_key(&signing_key).expect("controller key ID"),
            AlgorithmSignature::new(1, signature.to_bytes().to_vec()).expect("valid signature"),
        )],
    )
    .expect("valid approval");
    krikos_identity::AuthorizedEvent::new(
        body,
        evidence,
        ControllerApprovals::new(vec![approval]).expect("approval set"),
    )
    .expect("authorized event")
}

fn policy_change(
    state: &AccountState,
    signer: &SecretKey,
    version: u64,
    nonce: u8,
) -> krikos_identity::AuthorizedEvent {
    event(
        state,
        AccountOperation::ChangeProviderPolicy(
            ProviderPolicy::local_only(ProviderPolicyVersion::new(version), Extensions::default())
                .expect("valid provider version"),
        ),
        state.epoch().checked_next().expect("bounded epoch"),
        nonce.max(1),
        signer,
    )
}

fn check_linear_model(input: &[u8]) {
    let (mut state, signer) = fixture();
    let steps = input.len().clamp(1, 16);
    for index in 0..steps {
        let version = u64::try_from(index + 1).expect("small index");
        let nonce = input.get(index).copied().unwrap_or(1).max(1);
        let next = policy_change(&state, &signer, version, nonce);
        let before_sequence = state.sequence();
        let before_epoch = state.epoch();
        state.validate_and_apply(&next).expect("valid linear event");
        assert_eq!(state.sequence(), before_sequence.checked_next().unwrap());
        assert_eq!(state.epoch(), before_epoch.checked_next().unwrap());
        assert_eq!(state.sequence().get(), version);
        assert_eq!(state.epoch().get(), version);
    }

    let replay = policy_change(
        &fixture().0,
        &signer,
        1,
        input.first().copied().unwrap_or(1).max(1),
    );
    let (mut replay_state, _) = fixture();
    replay_state
        .validate_and_apply(&replay)
        .expect("first application succeeds");
    let applied = replay_state.clone();
    assert_eq!(
        replay_state
            .validate_and_apply(&replay)
            .expect("replay validates")
            .disposition(),
        ApplyDisposition::Replay
    );
    assert_eq!(replay_state, applied);

    let invalid_version = u64::try_from(steps + 1).expect("small step count");
    let invalid = event(
        &state,
        AccountOperation::ChangeProviderPolicy(
            ProviderPolicy::local_only(
                ProviderPolicyVersion::new(invalid_version),
                Extensions::default(),
            )
            .expect("valid provider version"),
        ),
        state.epoch(),
        0xfd,
        &signer,
    );
    let before_invalid = state.clone();
    assert!(state.validate_and_apply(&invalid).is_err());
    assert_eq!(state, before_invalid);
}

fn check_branch_convergence(input: &[u8]) {
    let (base, signer) = fixture();
    let left_secret = SecretKey::from_bytes(&[0x32; 32]);
    let right_secret = SecretKey::from_bytes(&[0x33; 32]);
    let seed = input.first().copied().unwrap_or(7).max(1);
    let left = event(
        &base,
        AccountOperation::AddController(controller(&left_secret)),
        Epoch::new(1),
        seed,
        &signer,
    );
    let mut right_nonce = seed.wrapping_add(1);
    if right_nonce == 0 {
        right_nonce = 1;
    }
    let right = event(
        &base,
        AccountOperation::AddController(controller(&right_secret)),
        Epoch::new(1),
        right_nonce,
        &signer,
    );
    let mut left_projection = base.clone();
    left_projection
        .validate_and_apply(&left)
        .expect("left applies");
    let descendant = policy_change(&left_projection, &signer, 1, seed.wrapping_add(2).max(1));

    let mut late_conflict = base.clone();
    late_conflict
        .validate_and_apply(&left)
        .expect("left applies");
    late_conflict
        .validate_and_apply(&descendant)
        .expect("descendant applies");
    late_conflict
        .validate_and_apply(&right)
        .expect("late conflict opens fork");

    let mut fork_first = base;
    fork_first.validate_and_apply(&left).expect("left applies");
    fork_first
        .validate_and_apply(&right)
        .expect("right opens fork");
    fork_first
        .validate_and_apply(&descendant)
        .expect("branch descendant applies");
    assert_eq!(fork_first, late_conflict);
    assert_eq!(fork_first.lifecycle(), ProjectionLifecycle::Forked);
    assert_eq!(fork_first.sequence(), Sequence::new(2));
}

fuzz_target!(|input: &[u8]| {
    if input.len() > 64 {
        return;
    }
    check_linear_model(input);
    check_branch_convergence(input);
});
