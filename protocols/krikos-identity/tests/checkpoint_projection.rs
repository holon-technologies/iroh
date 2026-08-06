use krikos_base::SecretKey;
use krikos_identity::{
    AccountGenesis, AccountLifecycle, AccountOperation, AccountState, AdmissionEvidence,
    AgreementPublicKey, AlgorithmSignature, CHECKPOINT_AUTHORIZED_DEVICE_TYPE_TAG,
    CHECKPOINT_REVOKED_DEVICE_TYPE_TAG, CanonicalWire, CheckpointAuthorization, CheckpointBody,
    CheckpointId, ControlPolicy, ControllerApprovalBody, ControllerApprovals, ControllerClass,
    ControllerDescriptor, ControllerKeyId, ControllerScope, ControllerSelector,
    ControllerThreshold, ControllerWeight, CryptoSuiteDescriptor, DelayEvidence,
    DeviceAuthorization, DeviceClass, DeviceDescriptor, Digest, DurationMillis, EndpointPublicKey,
    EventBody, EventPredecessors, Extensions, ForkCommonAncestor, ForkDescriptor,
    FreshnessEvidence, FreshnessRequirement, HashAlgorithm, IdentityError, InclusionReceipt,
    KeyedSignature, MemoryTransparencyLog, OperationKind, PolicyRule, ProtocolSignature,
    ProtocolVersion, ProviderDescriptor, ProviderFreshness, ProviderHeadBody, ProviderHeadSigner,
    ProviderKeyVersion, ProviderLogEntryBody, ProviderLogId, ProviderLogSubject, ProviderPolicy,
    ProviderPolicyVersion, ProviderQuorum, ProviderReceipts, RecoveryAuthority, RecoveryPolicy,
    RecoveryPolicyVersion, RequiredWeight, ResolveFork, RetireAccount, RevokeDevice, Sequence,
    SignedCheckpoint, SignedControllerApproval, SignedProviderHead, SigningPublicKey, Timestamp,
    bootstrap_checkpoint_from_genesis, bootstrap_checkpoint_from_prior, build_checkpoint_body,
    build_checkpoint_merkle_sets, build_provider_checkpoint_bundle_from_genesis,
    merkle::{MerkleSetKey, empty_merkle_root},
    verify_checkpoint,
};
#[cfg(feature = "provider-store")]
use krikos_identity::{
    ProviderAdmissionControl, ProviderAdmissionRequest, RedbProviderStore,
    authorize_provider_append,
};

struct TestProviderSigner(SecretKey);

impl ProviderHeadSigner for TestProviderSigner {
    fn sign_provider_head(&self, message: &[u8]) -> Result<ProtocolSignature, IdentityError> {
        Ok(ProtocolSignature::ed25519(self.0.sign(message).to_bytes()))
    }
}

#[cfg(feature = "provider-store")]
struct AllowProviderAdmission;

#[cfg(feature = "provider-store")]
impl ProviderAdmissionControl for AllowProviderAdmission {
    fn check(
        &self,
        _admission: krikos_identity::ProviderLogAdmission,
        _request: ProviderAdmissionRequest,
    ) -> Result<(), IdentityError> {
        Ok(())
    }
}

fn typed_id<T: CanonicalWire>(fill: u8) -> T {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [fill; 32]);
    T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
}

fn controller(secret: &SecretKey) -> ControllerDescriptor {
    ControllerDescriptor::new(
        SigningPublicKey::ed25519(*secret.public().as_bytes()).unwrap(),
        ControllerClass::PersonalDevice,
        ControllerWeight::new(1).unwrap(),
        ControllerScope::all_v1_operations(),
        Extensions::default(),
    )
    .unwrap()
}

fn device_descriptor(
    application_secret: &SecretKey,
    endpoint_secret: &SecretKey,
) -> DeviceDescriptor {
    DeviceDescriptor::new(
        SigningPublicKey::ed25519(*application_secret.public().as_bytes()).unwrap(),
        AgreementPublicKey::x25519([0x33; 32]).unwrap(),
        EndpointPublicKey::new(
            SigningPublicKey::ed25519(*endpoint_secret.public().as_bytes()).unwrap(),
        ),
        Extensions::default(),
    )
    .unwrap()
}

fn fixture() -> (AccountGenesis, AccountState, SecretKey) {
    fixture_with_provider(
        ProviderPolicy::local_only(ProviderPolicyVersion::GENESIS, Extensions::default()).unwrap(),
    )
}

fn fixture_with_provider(
    provider_policy: ProviderPolicy,
) -> (AccountGenesis, AccountState, SecretKey) {
    let secret = SecretKey::from_bytes(&[0x11; 32]);
    let policy = ControlPolicy::new(
        vec![
            PolicyRule::new(
                OperationKind::AddController,
                RequiredWeight::new(1).unwrap(),
                ControllerSelector::any_active(),
                FreshnessRequirement::latest_known(),
                None,
                Extensions::default(),
            )
            .unwrap(),
            PolicyRule::new(
                OperationKind::RetireAccount,
                RequiredWeight::new(1).unwrap(),
                ControllerSelector::any_active(),
                FreshnessRequirement::latest_known(),
                None,
                Extensions::default(),
            )
            .unwrap(),
            PolicyRule::new(
                OperationKind::AuthorizeDevice,
                RequiredWeight::new(1).unwrap(),
                ControllerSelector::any_active(),
                FreshnessRequirement::latest_known(),
                None,
                Extensions::default(),
            )
            .unwrap(),
            PolicyRule::new(
                OperationKind::RevokeDevice,
                RequiredWeight::new(1).unwrap(),
                ControllerSelector::any_active(),
                FreshnessRequirement::latest_known(),
                None,
                Extensions::default(),
            )
            .unwrap(),
            PolicyRule::new(
                OperationKind::ChangeProviderPolicy,
                RequiredWeight::new(1).unwrap(),
                ControllerSelector::any_active(),
                FreshnessRequirement::latest_known(),
                None,
                Extensions::default(),
            )
            .unwrap(),
            PolicyRule::new(
                OperationKind::ResolveFork,
                RequiredWeight::new(1).unwrap(),
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
        [0x12; 32],
        Timestamp::from_unix_millis(1),
        policy,
        vec![controller(&secret)],
        recovery,
        provider_policy,
        Extensions::default(),
    )
    .unwrap();
    let state = AccountState::from_genesis(&genesis).unwrap();
    (genesis, state, secret)
}

fn event(
    state: &AccountState,
    signer: &SecretKey,
    added_seed: u8,
    nonce: u8,
) -> krikos_identity::AuthorizedEvent {
    authorized_operation(
        state,
        signer,
        AccountOperation::AddController(controller(&SecretKey::from_bytes(&[added_seed; 32]))),
        nonce,
    )
}

fn authorized_operation(
    state: &AccountState,
    signer: &SecretKey,
    operation: AccountOperation,
    nonce: u8,
) -> krikos_identity::AuthorizedEvent {
    let resulting_epoch = state.expected_epoch_for(&operation).unwrap();
    authorized_operation_at_epoch(state, signer, operation, resulting_epoch, nonce)
}

fn authorized_operation_at_epoch(
    state: &AccountState,
    signer: &SecretKey,
    operation: AccountOperation,
    resulting_epoch: krikos_identity::Epoch,
    nonce: u8,
) -> krikos_identity::AuthorizedEvent {
    let predecessors = if state.sequence() == Sequence::GENESIS {
        EventPredecessors::genesis(state.genesis_anchor())
    } else {
        EventPredecessors::events(state.heads().to_vec()).unwrap()
    };
    let body = EventBody::new(
        state.account_id(),
        state.sequence().checked_next().unwrap(),
        resulting_epoch,
        predecessors,
        operation,
        Timestamp::from_unix_millis(2),
        [nonce; 16],
        Extensions::default(),
    )
    .unwrap();
    let checkpoint_id = typed_id::<CheckpointId>(0x21);
    let evidence = AdmissionEvidence::new(
        body.proposal_id().unwrap(),
        checkpoint_id,
        state.provider_policy_id(),
        FreshnessEvidence::local_known(checkpoint_id),
        DelayEvidence::none(),
        Extensions::default(),
    )
    .unwrap();
    let signing_key = SigningPublicKey::ed25519(*signer.public().as_bytes()).unwrap();
    let controller_id = state
        .active_controllers()
        .iter()
        .find(|controller| controller.signing_key() == signing_key)
        .unwrap()
        .id();
    let approval_body = ControllerApprovalBody::event(
        controller_id,
        evidence.event_id_for_body(&body).unwrap(),
        evidence.admission_evidence_id().unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let signature = signer.sign(&approval_body.to_canonical_bytes().unwrap());
    let approval = SignedControllerApproval::new(
        approval_body,
        vec![KeyedSignature::new(
            CryptoSuiteDescriptor::v1()
                .unwrap()
                .crypto_suite_id()
                .unwrap(),
            ControllerKeyId::for_signing_key(&signing_key).unwrap(),
            AlgorithmSignature::new(1, signature.to_bytes().to_vec()).unwrap(),
        )],
    )
    .unwrap();
    krikos_identity::AuthorizedEvent::new(
        body,
        evidence,
        ControllerApprovals::new(vec![approval]).unwrap(),
    )
    .unwrap()
}

fn signed_checkpoint(
    state: &AccountState,
    signer: &SecretKey,
    body: CheckpointBody,
) -> SignedCheckpoint {
    let checkpoint_id = body.checkpoint_id().unwrap();
    let approval = checkpoint_approval(state, signer, checkpoint_id);
    SignedCheckpoint::new(
        body,
        CheckpointAuthorization::controllers(
            checkpoint_id,
            ControllerApprovals::new(vec![approval]).unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
}

fn checkpoint_approval(
    state: &AccountState,
    signer: &SecretKey,
    checkpoint_id: CheckpointId,
) -> SignedControllerApproval {
    let signing_key = SigningPublicKey::ed25519(*signer.public().as_bytes()).unwrap();
    let controller_id = state
        .active_controllers()
        .iter()
        .find(|controller| controller.signing_key() == signing_key)
        .unwrap()
        .id();
    let approval_body =
        ControllerApprovalBody::checkpoint(controller_id, checkpoint_id, Extensions::default())
            .unwrap();
    let signature = signer.sign(&approval_body.to_canonical_bytes().unwrap());
    SignedControllerApproval::new(
        approval_body,
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

fn checkpoint_receipt(
    provider_secret: &SecretKey,
    provider: &ProviderDescriptor,
    account_id: krikos_identity::AccountId,
    checkpoint_id: CheckpointId,
    valid_signature: bool,
) -> InclusionReceipt {
    let entry = ProviderLogEntryBody::new(
        provider.id().unwrap(),
        typed_id::<ProviderLogId>(0xc1),
        account_id,
        ProviderLogSubject::Checkpoint(checkpoint_id),
        Timestamp::from_unix_millis(10),
        Extensions::default(),
    )
    .unwrap();
    let head = ProviderHeadBody::new(
        provider.id().unwrap(),
        entry.log_id(),
        ProviderKeyVersion::GENESIS,
        1,
        entry.merkle_leaf_hash().unwrap(),
        Timestamp::from_unix_millis(50),
        Extensions::default(),
    )
    .unwrap();
    let signature = if valid_signature {
        ProtocolSignature::ed25519(
            provider_secret
                .sign(&head.signing_bytes().unwrap())
                .to_bytes(),
        )
    } else {
        ProtocolSignature::ed25519([0; 64])
    };
    InclusionReceipt::new(
        entry,
        0,
        Vec::new(),
        SignedProviderHead::new(head, signature),
    )
    .unwrap()
}

#[test]
fn checkpoint_roots_are_deterministic_complete_and_directly_verifiable() {
    let (genesis, mut state, signer) = fixture();
    let applied = event(&state, &signer, 0x13, 1);
    state.validate_and_apply(&applied).unwrap();
    let issued_at = Timestamp::from_unix_millis(99);
    let body = build_checkpoint_body(&state, issued_at).unwrap();
    assert_eq!(body.account_id(), state.account_id());
    assert_eq!(body.account_epoch(), state.epoch());
    assert_eq!(body.sequence(), state.sequence());
    assert_eq!(body.event_head(), state.heads()[0]);
    assert_eq!(build_checkpoint_body(&state, issued_at).unwrap(), body);
    assert_eq!(
        body.state_root().to_string(),
        "b3:1fa3cb4786e6ef78ad5bd2fd7bfbc29c0a7b949bb3a42c5067c518df6c0e484f"
    );
    assert_eq!(
        body.authorized_set_root().to_string(),
        "b3:ac852bf31ef19b5d18fd8df40dcb4f07a8ea8066ca4094464f431618ebf339b7"
    );
    assert_eq!(body.revoked_set_root(), body.authorized_set_root());
    assert_eq!(
        body.crypto_state_id().to_string(),
        "b3:099052dac8de6b8b96a007c10c91e7a0e97c1f210e0b833a0cc4fab90aaae645"
    );

    let checkpoint = signed_checkpoint(&state, &signer, body);
    let verified = verify_checkpoint(&state, &checkpoint, None).unwrap();
    assert_eq!(
        verified.checkpoint_id(),
        checkpoint.checkpoint_id().unwrap()
    );
    let provider_bundle = build_provider_checkpoint_bundle_from_genesis(
        &genesis,
        std::slice::from_ref(&applied),
        &checkpoint,
        None,
    )
    .unwrap();
    assert_eq!(
        provider_bundle.provider_log_admission().account_id(),
        state.account_id()
    );

    let evidence = FreshnessEvidence::local_known(verified.checkpoint_id());
    let trusted = bootstrap_checkpoint_from_genesis(
        &genesis,
        std::slice::from_ref(&applied),
        &checkpoint,
        None,
        &evidence,
        FreshnessRequirement::latest_known(),
        Timestamp::from_unix_millis(100),
        &[],
    )
    .unwrap();
    assert_eq!(trusted.state(), &state);
    assert_eq!(
        trusted.checkpoint().checkpoint_id(),
        verified.checkpoint_id()
    );
    assert_eq!(
        trusted.freshness().context().checkpoint_id(),
        verified.checkpoint_id()
    );
    assert!(
        bootstrap_checkpoint_from_genesis(
            &genesis,
            &[],
            &checkpoint,
            None,
            &evidence,
            FreshnessRequirement::latest_known(),
            Timestamp::from_unix_millis(100),
            &[],
        )
        .is_err()
    );
    assert_eq!(
        bootstrap_checkpoint_from_genesis(
            &genesis,
            std::slice::from_ref(&applied),
            &checkpoint,
            None,
            &evidence,
            FreshnessRequirement::latest_known(),
            Timestamp::from_unix_millis(100),
            &[applied.event_id().unwrap()],
        ),
        Err(IdentityError::AccountForked)
    );

    let body = checkpoint.body();
    let substituted = CheckpointBody::new(
        body.account_id(),
        body.account_epoch(),
        body.sequence(),
        body.event_head(),
        Digest::new(HashAlgorithm::Blake3_256, [0x99; 32]),
        body.authorized_set_root(),
        body.revoked_set_root(),
        body.control_policy_id(),
        body.recovery_policy_id(),
        body.provider_policy_id(),
        body.crypto_state_id(),
        body.lifecycle(),
        body.issued_at(),
        Extensions::default(),
    )
    .unwrap();
    let forged = signed_checkpoint(&state, &signer, substituted);
    assert_eq!(
        verify_checkpoint(&state, &forged, None),
        Err(IdentityError::InvalidProof)
    );
}

#[test]
fn checkpoint_build_rejects_genesis_and_unresolved_fork() {
    let (_, base, signer) = fixture();
    assert!(matches!(
        build_checkpoint_body(&base, Timestamp::from_unix_millis(3)),
        Err(IdentityError::InvalidRelationship { .. })
    ));

    let left = event(&base, &signer, 0x14, 2);
    let right = event(&base, &signer, 0x15, 3);
    let mut forked = base;
    forked.validate_and_apply(&left).unwrap();
    forked.validate_and_apply(&right).unwrap();
    assert_eq!(
        build_checkpoint_body(&forked, Timestamp::from_unix_millis(4)),
        Err(IdentityError::AccountForked)
    );
}

#[test]
fn destructive_transition_checkpoint_retains_and_replays_exact_authority() {
    let (genesis, mut state, signer) = fixture();
    let retirement = authorized_operation(
        &state,
        &signer,
        AccountOperation::RetireAccount(
            RetireAccount::try_new(ProtocolVersion::V1, None, None, Extensions::default()).unwrap(),
        ),
        5,
    );
    let unrelated = authorized_operation(
        &state,
        &signer,
        AccountOperation::RetireAccount(
            RetireAccount::try_new(ProtocolVersion::V1, None, None, Extensions::default()).unwrap(),
        ),
        6,
    );
    state.validate_and_apply(&retirement).unwrap();
    let body = build_checkpoint_body(&state, Timestamp::from_unix_millis(5)).unwrap();
    assert_eq!(body.lifecycle(), AccountLifecycle::Retired);
    let checkpoint = SignedCheckpoint::new(
        body,
        CheckpointAuthorization::transition_derived(&retirement).unwrap(),
    )
    .unwrap();

    let verified = verify_checkpoint(&state, &checkpoint, Some(&retirement)).unwrap();
    assert_eq!(verified.transition_event(), Some(&retirement));
    assert_eq!(
        verify_checkpoint(&state, &checkpoint, None),
        Err(IdentityError::InvalidProof)
    );
    assert_eq!(
        verify_checkpoint(&state, &checkpoint, Some(&unrelated)),
        Err(IdentityError::InvalidProof)
    );

    let evidence = FreshnessEvidence::local_known(verified.checkpoint_id());
    let trusted = bootstrap_checkpoint_from_genesis(
        &genesis,
        std::slice::from_ref(&retirement),
        &checkpoint,
        Some(&retirement),
        &evidence,
        FreshnessRequirement::latest_known(),
        Timestamp::from_unix_millis(100),
        &[],
    )
    .unwrap();
    assert_eq!(trusted.checkpoint().transition_event(), Some(&retirement));
    assert_eq!(trusted.state(), &state);
}

#[test]
fn device_authorization_and_revocation_change_exact_checkpoint_sets() {
    let (_, mut state, signer) = fixture();
    let descriptor = device_descriptor(
        &SecretKey::from_bytes(&[0xa1; 32]),
        &SecretKey::from_bytes(&[0xa2; 32]),
    );
    let device_id = descriptor.id().unwrap();
    let authorization = DeviceAuthorization::new(
        device_id,
        descriptor,
        DeviceClass::ApplicationOnly,
        None,
        Vec::new(),
        state.epoch().checked_next().unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let authorize = authorized_operation(
        &state,
        &signer,
        AccountOperation::AuthorizeDevice(authorization),
        7,
    );
    state.validate_and_apply(&authorize).unwrap();
    let authorized_body = build_checkpoint_body(&state, Timestamp::from_unix_millis(7)).unwrap();
    let authorized_sets = build_checkpoint_merkle_sets(&state).unwrap();
    assert_ne!(authorized_body.authorized_set_root(), empty_merkle_root());
    assert_eq!(authorized_body.revoked_set_root(), empty_merkle_root());
    assert_eq!(
        authorized_sets.authorized_devices().root().unwrap(),
        authorized_body.authorized_set_root()
    );
    let authorized_key = MerkleSetKey::new(
        CHECKPOINT_AUTHORIZED_DEVICE_TYPE_TAG,
        *device_id.as_digest(),
    )
    .unwrap();
    let authorized_leaf = authorized_sets
        .authorized_devices()
        .entries()
        .iter()
        .find(|leaf| leaf.key() == authorized_key)
        .unwrap();
    authorized_sets
        .authorized_devices()
        .inclusion_proof(authorized_key)
        .unwrap()
        .verify(authorized_leaf, authorized_body.authorized_set_root())
        .unwrap();
    verify_checkpoint(
        &state,
        &signed_checkpoint(&state, &signer, authorized_body.clone()),
        None,
    )
    .unwrap();

    let revoke = authorized_operation(
        &state,
        &signer,
        AccountOperation::RevokeDevice(
            RevokeDevice::new(device_id, None, Extensions::default()).unwrap(),
        ),
        8,
    );
    state.validate_and_apply(&revoke).unwrap();
    let revoked_body = build_checkpoint_body(&state, Timestamp::from_unix_millis(8)).unwrap();
    let revoked_sets = build_checkpoint_merkle_sets(&state).unwrap();
    assert_ne!(revoked_body.state_root(), authorized_body.state_root());
    assert_eq!(revoked_body.authorized_set_root(), empty_merkle_root());
    assert_ne!(revoked_body.revoked_set_root(), empty_merkle_root());
    revoked_sets
        .authorized_devices()
        .non_membership_proof(authorized_key)
        .unwrap()
        .verify(authorized_key, revoked_body.authorized_set_root())
        .unwrap();
    let revoked_key =
        MerkleSetKey::new(CHECKPOINT_REVOKED_DEVICE_TYPE_TAG, *device_id.as_digest()).unwrap();
    let revoked_leaf = revoked_sets
        .revoked_devices()
        .entries()
        .iter()
        .find(|leaf| leaf.key() == revoked_key)
        .unwrap();
    revoked_sets
        .revoked_devices()
        .inclusion_proof(revoked_key)
        .unwrap()
        .verify(revoked_leaf, revoked_body.revoked_set_root())
        .unwrap();
    verify_checkpoint(
        &state,
        &signed_checkpoint(&state, &signer, revoked_body),
        None,
    )
    .unwrap();
}

#[test]
fn prior_checkpoint_bootstrap_requires_the_complete_advancing_lineage() {
    let (_, mut prior_state, signer) = fixture();
    let first = event(&prior_state, &signer, 0xb1, 9);
    prior_state.validate_and_apply(&first).unwrap();
    let prior_checkpoint = signed_checkpoint(
        &prior_state,
        &signer,
        build_checkpoint_body(&prior_state, Timestamp::from_unix_millis(9)).unwrap(),
    );
    let verified_prior = verify_checkpoint(&prior_state, &prior_checkpoint, None).unwrap();

    let second = event(&prior_state, &signer, 0xb2, 10);
    let mut current_state = prior_state.clone();
    current_state.validate_and_apply(&second).unwrap();
    let current_checkpoint = signed_checkpoint(
        &current_state,
        &signer,
        build_checkpoint_body(&current_state, Timestamp::from_unix_millis(10)).unwrap(),
    );
    let current_id = current_checkpoint.checkpoint_id().unwrap();
    let evidence = FreshnessEvidence::local_known(current_id);
    let trusted = bootstrap_checkpoint_from_prior(
        &prior_state,
        &verified_prior,
        std::slice::from_ref(&second),
        &current_checkpoint,
        None,
        &evidence,
        FreshnessRequirement::latest_known(),
        Timestamp::from_unix_millis(10),
        &[],
    )
    .unwrap();
    assert_eq!(trusted.state(), &current_state);
    assert_eq!(trusted.checkpoint().checkpoint_id(), current_id);
    assert!(
        bootstrap_checkpoint_from_prior(
            &prior_state,
            &verified_prior,
            &[],
            &current_checkpoint,
            None,
            &evidence,
            FreshnessRequirement::latest_known(),
            Timestamp::from_unix_millis(10),
            &[],
        )
        .is_err()
    );
}

#[test]
fn replicated_bootstrap_requires_verified_policy_compatible_provider_evidence() {
    let provider_secret = SecretKey::from_bytes(&[0xc2; 32]);
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*provider_secret.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let provider_policy = ProviderPolicy::replicated(
        ProviderPolicyVersion::GENESIS,
        vec![provider.clone()],
        ProviderQuorum::new(1).unwrap(),
        ProviderQuorum::new(1).unwrap(),
        DurationMillis::new(100),
        Extensions::default(),
    )
    .unwrap();
    let (genesis, mut state, signer) = fixture_with_provider(provider_policy.clone());
    let applied = event(&state, &signer, 0xc3, 11);
    state.validate_and_apply(&applied).unwrap();
    let checkpoint = signed_checkpoint(
        &state,
        &signer,
        build_checkpoint_body(&state, Timestamp::from_unix_millis(11)).unwrap(),
    );
    let checkpoint_id = checkpoint.checkpoint_id().unwrap();
    let evidence = FreshnessEvidence::provider_quorum(
        checkpoint_id,
        provider_policy.id().unwrap(),
        ProviderReceipts::new(vec![checkpoint_receipt(
            &provider_secret,
            &provider,
            state.account_id(),
            checkpoint_id,
            true,
        )])
        .unwrap(),
    )
    .unwrap();
    let trusted = bootstrap_checkpoint_from_genesis(
        &genesis,
        std::slice::from_ref(&applied),
        &checkpoint,
        None,
        &evidence,
        FreshnessRequirement::latest_known(),
        Timestamp::from_unix_millis(50),
        &[],
    )
    .unwrap();
    assert_eq!(trusted.state(), &state);
    assert_eq!(
        trusted.freshness().required_quorum(),
        Some(ProviderQuorum::new(1).unwrap())
    );

    let forged = FreshnessEvidence::provider_quorum(
        checkpoint_id,
        provider_policy.id().unwrap(),
        ProviderReceipts::new(vec![checkpoint_receipt(
            &provider_secret,
            &provider,
            state.account_id(),
            checkpoint_id,
            false,
        )])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        bootstrap_checkpoint_from_genesis(
            &genesis,
            std::slice::from_ref(&applied),
            &checkpoint,
            None,
            &forged,
            FreshnessRequirement::latest_known(),
            Timestamp::from_unix_millis(50),
            &[],
        ),
        Err(IdentityError::InvalidSignature)
    );
    let stricter = FreshnessRequirement::provider_quorum(
        ProviderFreshness::new(ProviderQuorum::new(2).unwrap(), DurationMillis::new(100)).unwrap(),
    );
    assert_eq!(
        bootstrap_checkpoint_from_genesis(
            &genesis,
            std::slice::from_ref(&applied),
            &checkpoint,
            None,
            &evidence,
            stricter,
            Timestamp::from_unix_millis(50),
            &[],
        ),
        Err(IdentityError::FreshnessUnavailable)
    );
}

#[test]
fn direct_checkpoint_requires_the_provider_policy_control_threshold() {
    let first_secret = SecretKey::from_bytes(&[0xd1; 32]);
    let second_secret = SecretKey::from_bytes(&[0xd2; 32]);
    let policy = ControlPolicy::new(
        vec![
            PolicyRule::new(
                OperationKind::AddController,
                RequiredWeight::new(1).unwrap(),
                ControllerSelector::any_active(),
                FreshnessRequirement::latest_known(),
                None,
                Extensions::default(),
            )
            .unwrap(),
            PolicyRule::new(
                OperationKind::ChangeProviderPolicy,
                RequiredWeight::new(2).unwrap(),
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
        [0xd3; 32],
        Timestamp::from_unix_millis(1),
        policy,
        vec![controller(&first_secret), controller(&second_secret)],
        recovery,
        ProviderPolicy::local_only(ProviderPolicyVersion::GENESIS, Extensions::default()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let mut state = AccountState::from_genesis(&genesis).unwrap();
    let event = authorized_operation(
        &state,
        &first_secret,
        AccountOperation::AddController(controller(&SecretKey::from_bytes(&[0xd4; 32]))),
        0xd4,
    );
    state.validate_and_apply(&event).unwrap();
    let body = build_checkpoint_body(&state, Timestamp::from_unix_millis(10)).unwrap();
    let checkpoint_id = body.checkpoint_id().unwrap();
    let one_approval = SignedCheckpoint::new(
        body.clone(),
        CheckpointAuthorization::controllers(
            checkpoint_id,
            ControllerApprovals::new(vec![checkpoint_approval(
                &state,
                &first_secret,
                checkpoint_id,
            )])
            .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        verify_checkpoint(&state, &one_approval, None),
        Err(IdentityError::AuthorizationDenied)
    );

    let threshold_approval = SignedCheckpoint::new(
        body,
        CheckpointAuthorization::controllers(
            checkpoint_id,
            ControllerApprovals::new(vec![
                checkpoint_approval(&state, &first_secret, checkpoint_id),
                checkpoint_approval(&state, &second_secret, checkpoint_id),
            ])
            .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    verify_checkpoint(&state, &threshold_approval, None).unwrap();
}

#[test]
fn provider_bundle_serves_lineage_and_rejects_late_historical_checkpoint_as_current() {
    let (genesis, mut first_state, controller_secret) = fixture();
    let first_event = event(&first_state, &controller_secret, 0xe1, 0xe1);
    first_state.validate_and_apply(&first_event).unwrap();
    let first_checkpoint = signed_checkpoint(
        &first_state,
        &controller_secret,
        build_checkpoint_body(&first_state, Timestamp::from_unix_millis(10)).unwrap(),
    );
    let first_bundle = build_provider_checkpoint_bundle_from_genesis(
        &genesis,
        std::slice::from_ref(&first_event),
        &first_checkpoint,
        None,
    )
    .unwrap();

    let second_event = event(&first_state, &controller_secret, 0xe2, 0xe2);
    let mut second_state = first_state.clone();
    second_state.validate_and_apply(&second_event).unwrap();
    let second_checkpoint = signed_checkpoint(
        &second_state,
        &controller_secret,
        build_checkpoint_body(&second_state, Timestamp::from_unix_millis(20)).unwrap(),
    );
    let second_bundle = build_provider_checkpoint_bundle_from_genesis(
        &genesis,
        &[first_event, second_event],
        &second_checkpoint,
        None,
    )
    .unwrap();

    let provider_secret = SecretKey::from_bytes(&[0xe3; 32]);
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*provider_secret.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let mut log = MemoryTransparencyLog::new(provider, typed_id::<ProviderLogId>(0xe4));
    let signer = TestProviderSigner(provider_secret);
    log.append(
        second_bundle.provider_log_admission(),
        Timestamp::from_unix_millis(200),
        &signer,
    )
    .unwrap();
    let tree_size = log.tree_size().unwrap();
    assert_eq!(
        log.append(
            first_bundle.provider_log_admission(),
            Timestamp::from_unix_millis(300),
            &signer,
        ),
        Err(IdentityError::ProviderRollback)
    );
    assert_eq!(log.tree_size().unwrap(), tree_size);

    let served = log
        .latest_checkpoint_bundle(second_state.account_id())
        .unwrap()
        .unwrap();
    assert_eq!(
        served.verified_checkpoint().checkpoint_id(),
        second_checkpoint.checkpoint_id().unwrap()
    );
    let served_genesis = served.genesis().unwrap();
    let served_events = served.events();
    let served_checkpoint = served.verified_checkpoint().checkpoint();
    bootstrap_checkpoint_from_genesis(
        served_genesis,
        served_events,
        served_checkpoint,
        served.verified_checkpoint().transition_event(),
        &FreshnessEvidence::local_known(served.verified_checkpoint().checkpoint_id()),
        FreshnessRequirement::latest_known(),
        Timestamp::from_unix_millis(300),
        &[],
    )
    .unwrap();
}

#[test]
fn provider_bundle_requires_retained_prior_and_surfaces_equal_sequence_forks() {
    let (genesis, mut first_state, controller_secret) = fixture();
    let first_event = event(&first_state, &controller_secret, 0xf1, 0xf1);
    first_state.validate_and_apply(&first_event).unwrap();
    let first_checkpoint = signed_checkpoint(
        &first_state,
        &controller_secret,
        build_checkpoint_body(&first_state, Timestamp::from_unix_millis(10)).unwrap(),
    );
    let first_bundle = build_provider_checkpoint_bundle_from_genesis(
        &genesis,
        std::slice::from_ref(&first_event),
        &first_checkpoint,
        None,
    )
    .unwrap();

    let continuation_event = event(&first_state, &controller_secret, 0xf2, 0xf2);
    let mut continuation_state = first_state.clone();
    continuation_state
        .validate_and_apply(&continuation_event)
        .unwrap();
    let continuation_checkpoint = signed_checkpoint(
        &continuation_state,
        &controller_secret,
        build_checkpoint_body(&continuation_state, Timestamp::from_unix_millis(20)).unwrap(),
    );
    let continuation = krikos_identity::build_provider_checkpoint_bundle_from_prior(
        &first_state,
        first_bundle.verified_checkpoint(),
        std::slice::from_ref(&continuation_event),
        &continuation_checkpoint,
        None,
    )
    .unwrap();

    let provider_secret = SecretKey::from_bytes(&[0xf3; 32]);
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*provider_secret.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let signer = TestProviderSigner(provider_secret);
    let mut log = MemoryTransparencyLog::new(provider, typed_id::<ProviderLogId>(0xf4));
    assert_eq!(
        log.append(
            continuation.provider_log_admission(),
            Timestamp::from_unix_millis(100),
            &signer,
        ),
        Err(IdentityError::InvalidProof)
    );
    assert_eq!(log.tree_size().unwrap(), 0);

    log.append(
        first_bundle.provider_log_admission(),
        Timestamp::from_unix_millis(101),
        &signer,
    )
    .unwrap();
    log.append(
        continuation.provider_log_admission(),
        Timestamp::from_unix_millis(102),
        &signer,
    )
    .unwrap();
    assert_eq!(
        log.latest_checkpoint_bundle(first_state.account_id())
            .unwrap()
            .unwrap()
            .verified_checkpoint()
            .checkpoint_id(),
        continuation_checkpoint.checkpoint_id().unwrap()
    );

    let mut fork_state = AccountState::from_genesis(&genesis).unwrap();
    let fork_event = event(&fork_state, &controller_secret, 0xf5, 0xf5);
    fork_state.validate_and_apply(&fork_event).unwrap();
    let fork_checkpoint = signed_checkpoint(
        &fork_state,
        &controller_secret,
        build_checkpoint_body(&fork_state, Timestamp::from_unix_millis(30)).unwrap(),
    );
    let fork_bundle = build_provider_checkpoint_bundle_from_genesis(
        &genesis,
        std::slice::from_ref(&fork_event),
        &fork_checkpoint,
        None,
    )
    .unwrap();
    let mut fork_log =
        MemoryTransparencyLog::new(log.provider().clone(), typed_id::<ProviderLogId>(0xf6));
    fork_log
        .append(
            first_bundle.provider_log_admission(),
            Timestamp::from_unix_millis(200),
            &signer,
        )
        .unwrap();
    fork_log
        .append(
            fork_bundle.provider_log_admission(),
            Timestamp::from_unix_millis(201),
            &signer,
        )
        .unwrap();
    assert_eq!(
        fork_log.latest_checkpoint_bundle(first_state.account_id()),
        Err(IdentityError::AccountForked)
    );
    assert_eq!(fork_log.tree_size().unwrap(), 2);
}

#[test]
fn provider_bundle_replays_complete_fork_evidence_through_explicit_resolution() {
    let (genesis, genesis_state, controller_secret) = fixture();
    let first_branch = event(&genesis_state, &controller_secret, 0xfa, 0xfa);
    let second_branch = event(&genesis_state, &controller_secret, 0xfb, 0xfb);
    let mut resolved_state = genesis_state.clone();
    resolved_state.validate_and_apply(&first_branch).unwrap();
    assert_eq!(
        resolved_state
            .validate_and_apply(&second_branch)
            .unwrap()
            .disposition(),
        krikos_identity::ApplyDisposition::ForkDetected
    );
    let fork = ForkDescriptor::try_new(
        ProtocolVersion::V1,
        resolved_state.account_id(),
        ForkCommonAncestor::Genesis(resolved_state.genesis_anchor()),
        resolved_state.heads().to_vec(),
        Extensions::default(),
    )
    .unwrap();
    let resolution = authorized_operation_at_epoch(
        &resolved_state,
        &controller_secret,
        AccountOperation::ResolveFork(
            ResolveFork::try_new(
                ProtocolVersion::V1,
                fork,
                first_branch.event_id().unwrap(),
                Vec::new(),
                Vec::new(),
                Extensions::default(),
            )
            .unwrap(),
        ),
        krikos_identity::Epoch::new(2),
        0xfc,
    );
    resolved_state.validate_and_apply(&resolution).unwrap();
    let checkpoint = signed_checkpoint(
        &resolved_state,
        &controller_secret,
        build_checkpoint_body(&resolved_state, Timestamp::from_unix_millis(40)).unwrap(),
    );

    let bundle = build_provider_checkpoint_bundle_from_genesis(
        &genesis,
        &[first_branch, second_branch, resolution],
        &checkpoint,
        None,
    )
    .unwrap();
    assert_eq!(
        bundle.verified_checkpoint().checkpoint_id(),
        checkpoint.checkpoint_id().unwrap()
    );
}

#[test]
fn provider_log_does_not_choose_a_longer_fork_and_accepts_complete_resolution() {
    let (genesis, genesis_state, controller_secret) = fixture();
    let short_event = event(&genesis_state, &controller_secret, 0xd1, 0xd1);
    let mut short_state = genesis_state.clone();
    short_state.validate_and_apply(&short_event).unwrap();
    let short_checkpoint = signed_checkpoint(
        &short_state,
        &controller_secret,
        build_checkpoint_body(&short_state, Timestamp::from_unix_millis(10)).unwrap(),
    );
    let short_bundle = build_provider_checkpoint_bundle_from_genesis(
        &genesis,
        std::slice::from_ref(&short_event),
        &short_checkpoint,
        None,
    )
    .unwrap();

    let long_first = event(&genesis_state, &controller_secret, 0xd2, 0xd2);
    let mut long_state = genesis_state.clone();
    long_state.validate_and_apply(&long_first).unwrap();
    let long_second = event(&long_state, &controller_secret, 0xd3, 0xd3);
    long_state.validate_and_apply(&long_second).unwrap();
    let long_checkpoint = signed_checkpoint(
        &long_state,
        &controller_secret,
        build_checkpoint_body(&long_state, Timestamp::from_unix_millis(20)).unwrap(),
    );
    let long_bundle = build_provider_checkpoint_bundle_from_genesis(
        &genesis,
        &[long_first.clone(), long_second.clone()],
        &long_checkpoint,
        None,
    )
    .unwrap();

    let provider_secret = SecretKey::from_bytes(&[0xd4; 32]);
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*provider_secret.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    #[cfg(feature = "provider-store")]
    let persistent_provider = provider.clone();
    let signer = TestProviderSigner(provider_secret);
    let mut log = MemoryTransparencyLog::new(provider, typed_id::<ProviderLogId>(0xd5));
    log.append(
        short_bundle.provider_log_admission(),
        Timestamp::from_unix_millis(100),
        &signer,
    )
    .unwrap();
    log.append(
        long_bundle.provider_log_admission(),
        Timestamp::from_unix_millis(101),
        &signer,
    )
    .unwrap();
    assert_eq!(
        log.latest_checkpoint_bundle(genesis_state.account_id()),
        Err(IdentityError::AccountForked)
    );

    let mut resolved_state = genesis_state.clone();
    resolved_state.validate_and_apply(&short_event).unwrap();
    assert_eq!(
        resolved_state
            .validate_and_apply(&long_first)
            .unwrap()
            .disposition(),
        krikos_identity::ApplyDisposition::ForkDetected
    );
    resolved_state.validate_and_apply(&long_second).unwrap();
    let fork = ForkDescriptor::try_new(
        ProtocolVersion::V1,
        resolved_state.account_id(),
        ForkCommonAncestor::Genesis(resolved_state.genesis_anchor()),
        resolved_state.heads().to_vec(),
        Extensions::default(),
    )
    .unwrap();
    let resolution = authorized_operation_at_epoch(
        &resolved_state,
        &controller_secret,
        AccountOperation::ResolveFork(
            ResolveFork::try_new(
                ProtocolVersion::V1,
                fork,
                long_second.event_id().unwrap(),
                Vec::new(),
                Vec::new(),
                Extensions::default(),
            )
            .unwrap(),
        ),
        krikos_identity::Epoch::new(3),
        0xd6,
    );
    resolved_state.validate_and_apply(&resolution).unwrap();
    let resolved_checkpoint = signed_checkpoint(
        &resolved_state,
        &controller_secret,
        build_checkpoint_body(&resolved_state, Timestamp::from_unix_millis(30)).unwrap(),
    );
    let resolved_bundle = build_provider_checkpoint_bundle_from_genesis(
        &genesis,
        &[short_event, long_first, long_second, resolution],
        &resolved_checkpoint,
        None,
    )
    .unwrap();
    log.append(
        resolved_bundle.provider_log_admission(),
        Timestamp::from_unix_millis(102),
        &signer,
    )
    .unwrap();
    assert_eq!(
        log.latest_checkpoint_bundle(genesis_state.account_id())
            .unwrap()
            .unwrap()
            .verified_checkpoint()
            .checkpoint_id(),
        resolved_checkpoint.checkpoint_id().unwrap()
    );

    #[cfg(feature = "provider-store")]
    {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("resolved-provider.redb");
        let log_id = typed_id::<ProviderLogId>(0xd7);
        {
            let store = RedbProviderStore::open(
                &path,
                persistent_provider.clone(),
                log_id,
                ProviderKeyVersion::GENESIS,
            )
            .unwrap();
            for (offset, bundle) in [&short_bundle, &long_bundle, &resolved_bundle]
                .into_iter()
                .enumerate()
            {
                let admission = bundle.provider_log_admission();
                let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
                store
                    .append(
                        authorize_provider_append(admission, request, &AllowProviderAdmission)
                            .unwrap(),
                        Timestamp::from_unix_millis(200 + u64::try_from(offset).unwrap()),
                        &signer,
                    )
                    .unwrap();
            }
            assert_eq!(
                store
                    .latest_checkpoint_bundle(genesis_state.account_id())
                    .unwrap()
                    .unwrap(),
                resolved_bundle
            );
        }

        let reopened = RedbProviderStore::open(
            &path,
            persistent_provider,
            log_id,
            ProviderKeyVersion::GENESIS,
        )
        .unwrap();
        let current = reopened
            .latest_checkpoint_bundle(genesis_state.account_id())
            .unwrap()
            .unwrap();
        assert_eq!(current, resolved_bundle);
        assert_eq!(
            current
                .verified_checkpoint()
                .checkpoint()
                .body()
                .event_head(),
            resolved_checkpoint.body().event_head()
        );
    }
}

#[test]
fn provider_log_treats_recheckpointing_the_same_state_as_non_forking() {
    let (genesis, mut state, controller_secret) = fixture();
    let applied = event(&state, &controller_secret, 0xe5, 0xe5);
    state.validate_and_apply(&applied).unwrap();
    let first = signed_checkpoint(
        &state,
        &controller_secret,
        build_checkpoint_body(&state, Timestamp::from_unix_millis(10)).unwrap(),
    );
    let second = signed_checkpoint(
        &state,
        &controller_secret,
        build_checkpoint_body(&state, Timestamp::from_unix_millis(11)).unwrap(),
    );
    let first_bundle = build_provider_checkpoint_bundle_from_genesis(
        &genesis,
        std::slice::from_ref(&applied),
        &first,
        None,
    )
    .unwrap();
    let second_bundle = build_provider_checkpoint_bundle_from_genesis(
        &genesis,
        std::slice::from_ref(&applied),
        &second,
        None,
    )
    .unwrap();
    let provider_secret = SecretKey::from_bytes(&[0xe6; 32]);
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*provider_secret.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let signer = TestProviderSigner(provider_secret);
    let mut log = MemoryTransparencyLog::new(provider, typed_id::<ProviderLogId>(0xe7));
    log.append(
        first_bundle.provider_log_admission(),
        Timestamp::from_unix_millis(100),
        &signer,
    )
    .unwrap();
    log.append(
        second_bundle.provider_log_admission(),
        Timestamp::from_unix_millis(101),
        &signer,
    )
    .unwrap();
    assert_eq!(
        log.latest_checkpoint_bundle(state.account_id())
            .unwrap()
            .unwrap()
            .verified_checkpoint()
            .checkpoint_id(),
        second.checkpoint_id().unwrap()
    );
}

#[cfg(feature = "provider-store")]
#[test]
fn provider_rotation_is_an_account_authorized_descriptor_and_log_generation_boundary() {
    let old_provider_secret = SecretKey::from_bytes(&[0xe1; 32]);
    let new_provider_secret = SecretKey::from_bytes(&[0xe2; 32]);
    let old_provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*old_provider_secret.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let new_provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*new_provider_secret.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let old_policy = ProviderPolicy::replicated(
        ProviderPolicyVersion::GENESIS,
        vec![old_provider.clone()],
        ProviderQuorum::new(1).unwrap(),
        ProviderQuorum::new(1).unwrap(),
        DurationMillis::new(1_000),
        Extensions::default(),
    )
    .unwrap();
    let new_policy = ProviderPolicy::replicated(
        ProviderPolicyVersion::GENESIS.checked_next().unwrap(),
        vec![new_provider.clone()],
        ProviderQuorum::new(1).unwrap(),
        ProviderQuorum::new(1).unwrap(),
        DurationMillis::new(1_000),
        Extensions::default(),
    )
    .unwrap();
    let (genesis, mut state, controller_secret) = fixture_with_provider(old_policy.clone());
    let before_rotation = event(&state, &controller_secret, 0xe3, 0xe3);
    state.validate_and_apply(&before_rotation).unwrap();
    let old_checkpoint = signed_checkpoint(
        &state,
        &controller_secret,
        build_checkpoint_body(&state, Timestamp::from_unix_millis(10)).unwrap(),
    );
    let old_bundle = build_provider_checkpoint_bundle_from_genesis(
        &genesis,
        std::slice::from_ref(&before_rotation),
        &old_checkpoint,
        None,
    )
    .unwrap();
    assert_eq!(
        old_checkpoint.body().provider_policy_id(),
        old_policy.id().unwrap()
    );

    let rotate = authorized_operation(
        &state,
        &controller_secret,
        AccountOperation::ChangeProviderPolicy(new_policy.clone()),
        0xe4,
    );
    state.validate_and_apply(&rotate).unwrap();
    let new_checkpoint = signed_checkpoint(
        &state,
        &controller_secret,
        build_checkpoint_body(&state, Timestamp::from_unix_millis(20)).unwrap(),
    );
    let new_bundle = build_provider_checkpoint_bundle_from_genesis(
        &genesis,
        &[before_rotation, rotate.clone()],
        &new_checkpoint,
        None,
    )
    .unwrap();
    assert_eq!(
        rotate.body().operation().kind(),
        OperationKind::ChangeProviderPolicy
    );
    assert_eq!(
        new_checkpoint.body().provider_policy_id(),
        new_policy.id().unwrap()
    );

    let directory = tempfile::tempdir().unwrap();
    let old_path = directory.path().join("provider-old.redb");
    let new_path = directory.path().join("provider-new.redb");
    let rejected_path = directory.path().join("provider-in-place-version.redb");
    let old_log_id = typed_id::<ProviderLogId>(0xe5);
    let new_log_id = typed_id::<ProviderLogId>(0xe6);
    let old_signer = TestProviderSigner(old_provider_secret);
    let new_signer = TestProviderSigner(new_provider_secret);
    {
        let old_store = RedbProviderStore::open(
            &old_path,
            old_provider.clone(),
            old_log_id,
            ProviderKeyVersion::GENESIS,
        )
        .unwrap();
        let admission = old_bundle.provider_log_admission();
        let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
        old_store
            .append(
                authorize_provider_append(admission, request, &AllowProviderAdmission).unwrap(),
                Timestamp::from_unix_millis(100),
                &old_signer,
            )
            .unwrap();

        let new_store = RedbProviderStore::open(
            &new_path,
            new_provider.clone(),
            new_log_id,
            ProviderKeyVersion::GENESIS,
        )
        .unwrap();
        let admission = new_bundle.provider_log_admission();
        let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
        new_store
            .append(
                authorize_provider_append(admission, request, &AllowProviderAdmission).unwrap(),
                Timestamp::from_unix_millis(101),
                &new_signer,
            )
            .unwrap();
    }

    assert!(matches!(
        RedbProviderStore::open(
            &rejected_path,
            new_provider.clone(),
            new_log_id,
            ProviderKeyVersion::new(1),
        ),
        Err(IdentityError::InvalidRelationship {
            resource: "provider signing-key generation",
        })
    ));
    let old_reopened = RedbProviderStore::open(
        &old_path,
        old_provider,
        old_log_id,
        ProviderKeyVersion::GENESIS,
    )
    .unwrap();
    assert_eq!(
        old_reopened
            .latest_checkpoint_bundle(state.account_id())
            .unwrap()
            .unwrap(),
        old_bundle
    );
    let new_reopened = RedbProviderStore::open(
        &new_path,
        new_provider,
        new_log_id,
        ProviderKeyVersion::GENESIS,
    )
    .unwrap();
    assert_eq!(
        new_reopened
            .latest_checkpoint_bundle(state.account_id())
            .unwrap()
            .unwrap(),
        new_bundle
    );
    let rollback = old_bundle.provider_log_admission();
    let rollback_request = ProviderAdmissionRequest::for_admission(&rollback).unwrap();
    assert_eq!(
        new_reopened.append(
            authorize_provider_append(rollback, rollback_request, &AllowProviderAdmission).unwrap(),
            Timestamp::from_unix_millis(102),
            &new_signer,
        ),
        Err(IdentityError::ProviderRollback)
    );
    assert_eq!(new_reopened.snapshot().unwrap().tree_size(), 1);
}
