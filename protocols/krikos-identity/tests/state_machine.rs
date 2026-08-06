use krikos_base::SecretKey;
use krikos_identity::{
    AccountGenesis, AccountOperation, AccountState, ActivateCryptoMigration, AdmissionEvidence,
    AgreementPublicKey, AlgorithmPublicKey, AlgorithmSignature, ApplyDisposition,
    BeginCryptoMigration, BeginRecovery, BlindingSecret, CancelRecovery, CanonicalWire,
    CheckpointAuthorization, CheckpointBody, CheckpointId, ControlPolicy, ControllerApprovalBody,
    ControllerApprovals, ControllerClass, ControllerDescriptor, ControllerKeyBinding,
    ControllerKeyBindingProof, ControllerKeyBindingProofSet, ControllerKeyId, ControllerScope,
    ControllerSelector, ControllerThreshold, ControllerWeight, CryptoMigrationBody,
    CryptoMigrationId, CryptoSuiteDescriptor, DelayEvidence, DeviceAuthorization, DeviceClass,
    DeviceDescriptor, Digest, DurationMillis, EndpointPublicKey, Epoch, EventBody, EventId,
    EventIntentApprovalBody, EventIntentApprovals, EventPredecessors, Extension, Extensions,
    FinalizeRecovery, ForkCommonAncestor, ForkDescriptor, FreshnessEvidence, FreshnessRequirement,
    GuardianApprovalBody, GuardianApprovalDecision, GuardianApprovalSet, GuardianGrant,
    GuardianGrantOpening, GuardianSetRoot, GuardianThreshold, HashAlgorithm, IdentityError,
    InclusionReceipt, KeyedSignature, MemoryTransparencyLog, OperationKind, PolicyRule,
    ProjectionLifecycle, ProtocolSignature, ProtocolVersion, ProviderDescriptor, ProviderFreshness,
    ProviderHeadBody, ProviderHeadSigner, ProviderKeyVersion, ProviderLogEntryBody, ProviderLogId,
    ProviderLogSubject, ProviderPolicy, ProviderPolicyVersion, ProviderQuorum, ProviderReceipts,
    RecoveryAuthority, RecoveryAuthorityPlan, RecoveryDelayAnchor, RecoveryId, RecoveryPolicy,
    RecoveryPolicyId, RecoveryPolicyVersion, RecoveryProposal, RecoveryThresholdEvidence,
    RequiredWeight, ResolveFork, RetireAccount, RetireCryptoSuite, RetireCryptoSuiteMode,
    RevokeDevice, RotateDeviceKeys, Sequence, SignedCheckpoint, SignedControllerApproval,
    SignedEventIntentApproval, SignedGuardianApproval, SignedProviderHead, SigningPublicKey,
    Timestamp, VetoRecovery, build_checkpoint_body, merkle::MerkleSet, verify_checkpoint,
    verify_event_intent_admission, verify_guardian_recovery_intent_admission,
};

fn typed_id<T: CanonicalWire>(fill: u8) -> T {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [fill; 32]);
    T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
}

struct TestProviderSigner(SecretKey);

impl ProviderHeadSigner for TestProviderSigner {
    fn sign_provider_head(&self, message: &[u8]) -> Result<ProtocolSignature, IdentityError> {
        Ok(ProtocolSignature::ed25519(self.0.sign(message).to_bytes()))
    }
}

fn controller(secret: &SecretKey, weight: u32) -> ControllerDescriptor {
    ControllerDescriptor::new(
        SigningPublicKey::ed25519(*secret.public().as_bytes()).unwrap(),
        ControllerClass::PersonalDevice,
        ControllerWeight::new(weight).unwrap(),
        ControllerScope::all_v1_operations(),
        Extensions::default(),
    )
    .unwrap()
}

fn large_controller(secret: &SecretKey) -> ControllerDescriptor {
    let extensions = Extensions::new(
        (100_u32..104)
            .map(|code| Extension::new(code, false, vec![0xa5; 15 * 1024]).unwrap())
            .collect(),
    )
    .unwrap();
    ControllerDescriptor::new(
        SigningPublicKey::ed25519(*secret.public().as_bytes()).unwrap(),
        ControllerClass::HardwareSecurityKey,
        ControllerWeight::new(1).unwrap(),
        ControllerScope::all_v1_operations(),
        extensions,
    )
    .unwrap()
}

fn device_descriptor(
    application_secret: &SecretKey,
    agreement_seed: u8,
    endpoint_secret: &SecretKey,
) -> DeviceDescriptor {
    let mut agreement = [0_u8; 32];
    agreement[0] = agreement_seed;
    DeviceDescriptor::new(
        SigningPublicKey::ed25519(*application_secret.public().as_bytes()).unwrap(),
        AgreementPublicKey::x25519(agreement).unwrap(),
        EndpointPublicKey::new(
            SigningPublicKey::ed25519(*endpoint_secret.public().as_bytes()).unwrap(),
        ),
        Extensions::default(),
    )
    .unwrap()
}

fn device_authorization(descriptor: DeviceDescriptor, epoch: Epoch) -> DeviceAuthorization {
    DeviceAuthorization::new(
        descriptor.id().unwrap(),
        descriptor,
        DeviceClass::ApplicationOnly,
        None,
        Vec::new(),
        epoch,
        Extensions::default(),
    )
    .unwrap()
}

fn rule(operation: OperationKind, required_weight: u32) -> PolicyRule {
    PolicyRule::new(
        operation,
        RequiredWeight::new(required_weight).unwrap(),
        ControllerSelector::any_active(),
        FreshnessRequirement::latest_known(),
        None,
        Extensions::default(),
    )
    .unwrap()
}

fn provider_rule(operation: OperationKind, required_weight: u32) -> PolicyRule {
    PolicyRule::new(
        operation,
        RequiredWeight::new(required_weight).unwrap(),
        ControllerSelector::any_active(),
        FreshnessRequirement::provider_quorum(
            ProviderFreshness::new(ProviderQuorum::new(1).unwrap(), DurationMillis::new(1_000))
                .unwrap(),
        ),
        None,
        Extensions::default(),
    )
    .unwrap()
}

fn fixture() -> (AccountGenesis, SecretKey) {
    let secret = SecretKey::from_bytes(&[7; 32]);
    let descriptor = controller(&secret, 1);
    let policy = ControlPolicy::new(
        vec![
            rule(OperationKind::AddController, 1),
            rule(OperationKind::RemoveController, 1),
            rule(OperationKind::AuthorizeDevice, 1),
            rule(OperationKind::RevokeDevice, 1),
            rule(OperationKind::RotateDeviceKeys, 1),
            rule(OperationKind::ChangeProviderPolicy, 1),
            rule(OperationKind::BeginRecovery, 1),
            rule(OperationKind::VetoRecovery, 1),
            rule(OperationKind::CancelRecovery, 1),
            provider_rule(OperationKind::FinalizeRecovery, 1),
            rule(OperationKind::ResolveFork, 1),
            rule(OperationKind::BeginCryptoMigration, 1),
            rule(OperationKind::ActivateCryptoMigration, 1),
            rule(OperationKind::RetireCryptoSuite, 1),
            rule(OperationKind::RetireAccount, 1),
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
    let provider_secret = SecretKey::from_bytes(&[99; 32]);
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*provider_secret.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let genesis = AccountGenesis::new(
        [1; 32],
        Timestamp::from_unix_millis(1),
        policy,
        vec![descriptor],
        recovery,
        ProviderPolicy::replicated(
            ProviderPolicyVersion::GENESIS,
            vec![provider],
            ProviderQuorum::new(1).unwrap(),
            ProviderQuorum::new(1).unwrap(),
            DurationMillis::new(1_000),
            Extensions::default(),
        )
        .unwrap(),
        Extensions::default(),
    )
    .unwrap();
    (genesis, secret)
}

fn authorized_event(
    state: &AccountState,
    operation: AccountOperation,
    resulting_epoch: Epoch,
    nonce: u8,
    signer: &SecretKey,
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
        Timestamp::from_unix_millis(u64::from(nonce)),
        [nonce; 16],
        Extensions::default(),
    )
    .unwrap();
    authorize_body(state, body, signer)
}

fn authorize_body(
    state: &AccountState,
    body: EventBody,
    signer: &SecretKey,
) -> krikos_identity::AuthorizedEvent {
    let checkpoint_id = typed_id::<CheckpointId>(0x44);
    let delay = if matches!(body.operation(), AccountOperation::BeginRecovery(_)) {
        let proposal_id = body.proposal_id().unwrap();
        let observed_at = 100;
        DelayEvidence::provider_quorum(
            state.provider_policy_id(),
            ProviderQuorum::new(1).unwrap(),
            controller_intent_approvals(state, &body, signer),
            ProviderReceipts::new(vec![provider_receipt(
                state,
                ProviderLogSubject::EventIntent(proposal_id),
                observed_at,
                observed_at,
                0x67,
            )])
            .unwrap(),
        )
        .unwrap()
    } else {
        DelayEvidence::none()
    };
    let evidence = AdmissionEvidence::new(
        body.proposal_id().unwrap(),
        checkpoint_id,
        state.provider_policy_id(),
        FreshnessEvidence::local_known(checkpoint_id),
        delay,
        Extensions::default(),
    )
    .unwrap();
    authorize_body_with_evidence(state, body, evidence, signer)
}

fn controller_intent_approvals(
    state: &AccountState,
    body: &EventBody,
    signer: &SecretKey,
) -> EventIntentApprovals {
    let signer_key = SigningPublicKey::ed25519(*signer.public().as_bytes()).unwrap();
    let controller_id = state
        .active_controllers()
        .iter()
        .find(|controller| controller.signing_key() == signer_key)
        .unwrap()
        .id();
    let intent_body = EventIntentApprovalBody::new(
        controller_id,
        body.proposal_id().unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let intent_signature = signer.sign(&intent_body.to_canonical_bytes().unwrap());
    EventIntentApprovals::new(vec![
        SignedEventIntentApproval::new(
            intent_body,
            vec![KeyedSignature::new(
                CryptoSuiteDescriptor::v1()
                    .unwrap()
                    .crypto_suite_id()
                    .unwrap(),
                ControllerKeyId::for_signing_key(&signer_key).unwrap(),
                AlgorithmSignature::new(1, intent_signature.to_bytes().to_vec()).unwrap(),
            )],
        )
        .unwrap(),
    ])
    .unwrap()
}

fn authorize_body_with_evidence(
    state: &AccountState,
    body: EventBody,
    evidence: AdmissionEvidence,
    signer: &SecretKey,
) -> krikos_identity::AuthorizedEvent {
    let event_id = evidence.event_id_for_body(&body).unwrap();
    let signer_key = SigningPublicKey::ed25519(*signer.public().as_bytes()).unwrap();
    let signer_controller = state
        .active_controllers()
        .iter()
        .find(|controller| controller.signing_key() == signer_key)
        .unwrap();
    let approval_body = ControllerApprovalBody::event(
        signer_controller.id(),
        event_id,
        evidence.admission_evidence_id().unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let bytes = approval_body.to_canonical_bytes().unwrap();
    let signature = signer.sign(&bytes);
    let keyed = KeyedSignature::new(
        CryptoSuiteDescriptor::v1()
            .unwrap()
            .crypto_suite_id()
            .unwrap(),
        ControllerKeyId::for_signing_key(&signer_key).unwrap(),
        AlgorithmSignature::new(1, signature.to_bytes().to_vec()).unwrap(),
    );
    let approval = SignedControllerApproval::new(approval_body, vec![keyed]).unwrap();
    krikos_identity::AuthorizedEvent::new(
        body,
        evidence,
        ControllerApprovals::new(vec![approval]).unwrap(),
    )
    .unwrap()
}

fn authorize_body_with_crypto_keys(
    state: &AccountState,
    body: EventBody,
    controller_id: krikos_identity::ControllerId,
    signers: &[(&CryptoSuiteDescriptor, &SecretKey, bool)],
) -> krikos_identity::AuthorizedEvent {
    let checkpoint_id = typed_id::<CheckpointId>(0x44);
    let evidence = AdmissionEvidence::new(
        body.proposal_id().unwrap(),
        checkpoint_id,
        state.provider_policy_id(),
        FreshnessEvidence::local_known(checkpoint_id),
        DelayEvidence::none(),
        Extensions::default(),
    )
    .unwrap();
    let event_id = evidence.event_id_for_body(&body).unwrap();
    let approval_body = ControllerApprovalBody::event(
        controller_id,
        event_id,
        evidence.admission_evidence_id().unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let bytes = approval_body.to_canonical_bytes().unwrap();
    let keyed = signers
        .iter()
        .map(|(suite, signer, migrated_key_encoding)| {
            let signing_key = SigningPublicKey::ed25519(*signer.public().as_bytes()).unwrap();
            let controller_key_id = if *migrated_key_encoding {
                ControllerKeyId::for_algorithm_key(
                    &AlgorithmPublicKey::new(
                        suite.signature_algorithm_code(),
                        signing_key.as_bytes().to_vec(),
                    )
                    .unwrap(),
                )
                .unwrap()
            } else {
                ControllerKeyId::for_signing_key(&signing_key).unwrap()
            };
            KeyedSignature::new(
                suite.crypto_suite_id().unwrap(),
                controller_key_id,
                AlgorithmSignature::new(
                    suite.signature_algorithm_code(),
                    signer.sign(&bytes).to_bytes().to_vec(),
                )
                .unwrap(),
            )
        })
        .collect();
    let approval = SignedControllerApproval::new(approval_body, keyed).unwrap();
    krikos_identity::AuthorizedEvent::new(
        body,
        evidence,
        ControllerApprovals::new(vec![approval]).unwrap(),
    )
    .unwrap()
}

fn authorized_event_with_crypto_keys(
    state: &AccountState,
    operation: AccountOperation,
    resulting_epoch: Epoch,
    nonce: u8,
    controller_id: krikos_identity::ControllerId,
    signers: &[(&CryptoSuiteDescriptor, &SecretKey, bool)],
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
        Timestamp::from_unix_millis(u64::from(nonce)),
        [nonce; 16],
        Extensions::default(),
    )
    .unwrap();
    authorize_body_with_crypto_keys(state, body, controller_id, signers)
}

fn signed_checkpoint_with_crypto_keys(
    body: CheckpointBody,
    controller_id: krikos_identity::ControllerId,
    signers: &[(&CryptoSuiteDescriptor, &SecretKey, bool)],
) -> SignedCheckpoint {
    let checkpoint_id = body.checkpoint_id().unwrap();
    let approval_body =
        ControllerApprovalBody::checkpoint(controller_id, checkpoint_id, Extensions::default())
            .unwrap();
    let bytes = approval_body.to_canonical_bytes().unwrap();
    let keyed = signers
        .iter()
        .map(|(suite, signer, migrated_key_encoding)| {
            let signing_key = SigningPublicKey::ed25519(*signer.public().as_bytes()).unwrap();
            let controller_key_id = if *migrated_key_encoding {
                ControllerKeyId::for_algorithm_key(
                    &AlgorithmPublicKey::new(
                        suite.signature_algorithm_code(),
                        signing_key.as_bytes().to_vec(),
                    )
                    .unwrap(),
                )
                .unwrap()
            } else {
                ControllerKeyId::for_signing_key(&signing_key).unwrap()
            };
            KeyedSignature::new(
                suite.crypto_suite_id().unwrap(),
                controller_key_id,
                AlgorithmSignature::new(
                    suite.signature_algorithm_code(),
                    signer.sign(&bytes).to_bytes().to_vec(),
                )
                .unwrap(),
            )
        })
        .collect();
    let approval = SignedControllerApproval::new(approval_body, keyed).unwrap();
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

fn migrate_to_in_place_ed25519_suite(
    state: &mut AccountState,
    original_secret: &SecretKey,
    migrated_secret: &SecretKey,
) -> CryptoSuiteDescriptor {
    let v1_suite = CryptoSuiteDescriptor::v1().unwrap();
    let migrated_suite = CryptoSuiteDescriptor::try_new(
        ProtocolVersion::V1,
        2,
        v1_suite.hash_algorithm_code(),
        v1_suite.signature_algorithm_code(),
        v1_suite.agreement_algorithm_code(),
        v1_suite.kdf_algorithm_code(),
        v1_suite.aead_algorithm_code(),
        Extensions::default(),
    )
    .unwrap();
    let controller_id = state.active_controllers()[0].id();
    let original_key = state.active_controllers()[0].signing_key();
    let migrated_key = AlgorithmPublicKey::new(
        migrated_suite.signature_algorithm_code(),
        migrated_secret.public().as_bytes().to_vec(),
    )
    .unwrap();
    let migration = CryptoMigrationBody::try_new(
        ProtocolVersion::V1,
        state.account_id(),
        v1_suite.crypto_suite_id().unwrap(),
        migrated_suite.clone(),
        vec![
            ControllerKeyBinding::try_new(
                controller_id,
                ControllerKeyId::for_signing_key(&original_key).unwrap(),
                migrated_key,
                Extensions::default(),
            )
            .unwrap(),
        ],
        None,
        [0xd1; 32],
        Extensions::default(),
    )
    .unwrap();
    let migration_id = migration.crypto_migration_id().unwrap();
    let migration_id_bytes = migration_id.to_canonical_bytes().unwrap();
    let proof = ControllerKeyBindingProof::try_new(
        migration_id,
        controller_id,
        AlgorithmSignature::new(
            1,
            original_secret
                .sign(&migration_id_bytes)
                .to_bytes()
                .to_vec(),
        )
        .unwrap(),
        AlgorithmSignature::new(
            1,
            migrated_secret
                .sign(&migration_id_bytes)
                .to_bytes()
                .to_vec(),
        )
        .unwrap(),
    )
    .unwrap();
    let begin = AccountOperation::BeginCryptoMigration(
        BeginCryptoMigration::try_new(
            ProtocolVersion::V1,
            migration,
            ControllerKeyBindingProofSet::try_new(vec![proof]).unwrap(),
            Extensions::default(),
        )
        .unwrap(),
    );
    let begin = authorized_event_with_crypto_keys(
        state,
        begin,
        state.epoch(),
        0xd1,
        controller_id,
        &[(&v1_suite, original_secret, false)],
    );
    let begin_event_id = begin.event_id().unwrap();
    state.validate_and_apply(&begin).unwrap();

    let activate = AccountOperation::ActivateCryptoMigration(
        ActivateCryptoMigration::try_new(
            ProtocolVersion::V1,
            migration_id,
            begin_event_id,
            Extensions::default(),
        )
        .unwrap(),
    );
    let activate = authorized_event_with_crypto_keys(
        state,
        activate,
        state.epoch().checked_next().unwrap(),
        0xd2,
        controller_id,
        &[(&v1_suite, original_secret, false)],
    );
    let activation_event_id = activate.event_id().unwrap();
    state.validate_and_apply(&activate).unwrap();

    let retire = AccountOperation::RetireCryptoSuite(
        RetireCryptoSuite::try_new(
            ProtocolVersion::V1,
            migration_id,
            RetireCryptoSuiteMode::RetirePrevious,
            activation_event_id,
            None,
            Extensions::default(),
        )
        .unwrap(),
    );
    let retire = authorized_event_with_crypto_keys(
        state,
        retire,
        state.epoch().checked_next().unwrap(),
        0xd3,
        controller_id,
        &[
            (&v1_suite, original_secret, false),
            (&migrated_suite, migrated_secret, true),
        ],
    );
    state.validate_and_apply(&retire).unwrap();
    migrated_suite
}

fn in_place_suite(suite_code: u16) -> CryptoSuiteDescriptor {
    let v1 = CryptoSuiteDescriptor::v1().unwrap();
    CryptoSuiteDescriptor::try_new(
        ProtocolVersion::V1,
        suite_code,
        v1.hash_algorithm_code(),
        v1.signature_algorithm_code(),
        v1.agreement_algorithm_code(),
        v1.kdf_algorithm_code(),
        v1.aead_algorithm_code(),
        Extensions::default(),
    )
    .unwrap()
}

fn begin_migration_event(
    state: &AccountState,
    from_suite: &CryptoSuiteDescriptor,
    old_secret: &SecretKey,
    to_suite: CryptoSuiteDescriptor,
    new_secret: &SecretKey,
    nonce: u8,
) -> (krikos_identity::AuthorizedEvent, CryptoMigrationId) {
    let controller_id = state.active_controllers()[0].id();
    let old_signing_key = SigningPublicKey::ed25519(*old_secret.public().as_bytes()).unwrap();
    let old_key_id = if from_suite == &CryptoSuiteDescriptor::v1().unwrap() {
        ControllerKeyId::for_signing_key(&old_signing_key).unwrap()
    } else {
        ControllerKeyId::for_algorithm_key(
            &AlgorithmPublicKey::new(
                from_suite.signature_algorithm_code(),
                old_signing_key.as_bytes().to_vec(),
            )
            .unwrap(),
        )
        .unwrap()
    };
    let migration = CryptoMigrationBody::try_new(
        ProtocolVersion::V1,
        state.account_id(),
        from_suite.crypto_suite_id().unwrap(),
        to_suite.clone(),
        vec![
            ControllerKeyBinding::try_new(
                controller_id,
                old_key_id,
                AlgorithmPublicKey::new(
                    to_suite.signature_algorithm_code(),
                    new_secret.public().as_bytes().to_vec(),
                )
                .unwrap(),
                Extensions::default(),
            )
            .unwrap(),
        ],
        None,
        [nonce; 32],
        Extensions::default(),
    )
    .unwrap();
    let migration_id = migration.crypto_migration_id().unwrap();
    let migration_bytes = migration_id.to_canonical_bytes().unwrap();
    let proof = ControllerKeyBindingProof::try_new(
        migration_id,
        controller_id,
        AlgorithmSignature::new(1, old_secret.sign(&migration_bytes).to_bytes().to_vec()).unwrap(),
        AlgorithmSignature::new(1, new_secret.sign(&migration_bytes).to_bytes().to_vec()).unwrap(),
    )
    .unwrap();
    let begin = AccountOperation::BeginCryptoMigration(
        BeginCryptoMigration::try_new(
            ProtocolVersion::V1,
            migration,
            ControllerKeyBindingProofSet::try_new(vec![proof]).unwrap(),
            Extensions::default(),
        )
        .unwrap(),
    );
    (
        authorized_event_with_crypto_keys(
            state,
            begin,
            state.epoch(),
            nonce,
            controller_id,
            &[(from_suite, old_secret, from_suite.suite_code() != 1)],
        ),
        migration_id,
    )
}

fn complete_in_place_migration(
    state: &mut AccountState,
    from_suite: &CryptoSuiteDescriptor,
    old_secret: &SecretKey,
    to_suite: &CryptoSuiteDescriptor,
    new_secret: &SecretKey,
    nonce: u8,
) {
    let controller_id = state.active_controllers()[0].id();
    let (begin, migration_id) = begin_migration_event(
        state,
        from_suite,
        old_secret,
        to_suite.clone(),
        new_secret,
        nonce,
    );
    let begin_event_id = begin.event_id().unwrap();
    state.validate_and_apply(&begin).unwrap();
    let activate = authorized_event_with_crypto_keys(
        state,
        AccountOperation::ActivateCryptoMigration(
            ActivateCryptoMigration::try_new(
                ProtocolVersion::V1,
                migration_id,
                begin_event_id,
                Extensions::default(),
            )
            .unwrap(),
        ),
        state.epoch().checked_next().unwrap(),
        nonce.saturating_add(1),
        controller_id,
        &[(from_suite, old_secret, from_suite.suite_code() != 1)],
    );
    let activation_event_id = activate.event_id().unwrap();
    state.validate_and_apply(&activate).unwrap();
    let retire = authorized_event_with_crypto_keys(
        state,
        AccountOperation::RetireCryptoSuite(
            RetireCryptoSuite::try_new(
                ProtocolVersion::V1,
                migration_id,
                RetireCryptoSuiteMode::RetirePrevious,
                activation_event_id,
                None,
                Extensions::default(),
            )
            .unwrap(),
        ),
        state.epoch().checked_next().unwrap(),
        nonce.saturating_add(2),
        controller_id,
        &[
            (from_suite, old_secret, from_suite.suite_code() != 1),
            (to_suite, new_secret, true),
        ],
    );
    state.validate_and_apply(&retire).unwrap();
}

fn authorize_body_without_controller_approvals(
    state: &AccountState,
    body: EventBody,
) -> krikos_identity::AuthorizedEvent {
    let checkpoint_id = typed_id::<CheckpointId>(0x44);
    authorize_body_without_controller_approvals_with_freshness(
        state,
        body,
        FreshnessEvidence::local_known(checkpoint_id),
    )
}

fn authorize_body_without_controller_approvals_with_freshness(
    state: &AccountState,
    body: EventBody,
    freshness: FreshnessEvidence,
) -> krikos_identity::AuthorizedEvent {
    let checkpoint_id = freshness.checkpoint_id();
    let evidence = AdmissionEvidence::new(
        body.proposal_id().unwrap(),
        checkpoint_id,
        state.provider_policy_id(),
        freshness,
        DelayEvidence::none(),
        Extensions::default(),
    )
    .unwrap();
    krikos_identity::AuthorizedEvent::new(
        body,
        evidence,
        ControllerApprovals::new(Vec::new()).unwrap(),
    )
    .unwrap()
}

fn recovery_provider_receipt(
    state: &AccountState,
    proposal_id: krikos_identity::ProposalId,
    observed_at: u64,
) -> InclusionReceipt {
    provider_receipt(
        state,
        ProviderLogSubject::EventIntent(proposal_id),
        observed_at,
        observed_at + 10,
        0x67,
    )
}

fn finalize_recovery_event(
    state: &AccountState,
    recovery_id: RecoveryId,
    begin_proposal_id: krikos_identity::ProposalId,
    nonce: u8,
) -> krikos_identity::AuthorizedEvent {
    let provider_secret = SecretKey::from_bytes(&[99; 32]);
    finalize_recovery_event_with_anchor_signer(
        state,
        recovery_id,
        begin_proposal_id,
        nonce,
        &provider_secret,
    )
}

fn finalize_recovery_event_with_anchor_signer(
    state: &AccountState,
    recovery_id: RecoveryId,
    begin_proposal_id: krikos_identity::ProposalId,
    nonce: u8,
    anchor_signer: &SecretKey,
) -> krikos_identity::AuthorizedEvent {
    let configured_provider = match state.provider_policy().mode() {
        krikos_identity::ProviderMode::LocalOnly => panic!("fixture uses replicated providers"),
        krikos_identity::ProviderMode::Replicated(policy) => &policy.providers()[0],
    };
    let anchor = RecoveryDelayAnchor::try_new(
        ProtocolVersion::V1,
        state.account_id(),
        recovery_id,
        begin_proposal_id,
        state.provider_policy_id(),
        ProviderQuorum::new(1).unwrap(),
        ProviderReceipts::new(vec![provider_receipt_for_descriptor_signed_by(
            state,
            ProviderLogSubject::EventIntent(begin_proposal_id),
            100,
            110,
            0x67,
            configured_provider,
            anchor_signer,
        )])
        .unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let finalize = AccountOperation::FinalizeRecovery(
        FinalizeRecovery::try_new(
            ProtocolVersion::V1,
            recovery_id,
            anchor,
            Timestamp::from_unix_millis(110),
            Extensions::default(),
        )
        .unwrap(),
    );
    let body = EventBody::new(
        state.account_id(),
        state.sequence().checked_next().unwrap(),
        state.epoch().checked_next().unwrap(),
        EventPredecessors::events(state.heads().to_vec()).unwrap(),
        finalize,
        Timestamp::from_unix_millis(110),
        [nonce; 16],
        Extensions::default(),
    )
    .unwrap();
    let checkpoint_id = typed_id::<CheckpointId>(0x44);
    let completion = ProviderReceipts::new(vec![provider_receipt(
        state,
        ProviderLogSubject::Checkpoint(checkpoint_id),
        100,
        110,
        nonce,
    )])
    .unwrap();
    authorize_body_without_controller_approvals_with_freshness(
        state,
        body,
        FreshnessEvidence::provider_quorum(checkpoint_id, state.provider_policy_id(), completion)
            .unwrap(),
    )
}

fn provider_receipt(
    state: &AccountState,
    subject: ProviderLogSubject,
    entry_observed_at: u64,
    head_observed_at: u64,
    log_fill: u8,
) -> InclusionReceipt {
    let provider_secret = SecretKey::from_bytes(&[99; 32]);
    provider_receipt_signed_by(
        state,
        subject,
        entry_observed_at,
        head_observed_at,
        log_fill,
        &provider_secret,
    )
}

fn provider_receipt_signed_by(
    state: &AccountState,
    subject: ProviderLogSubject,
    entry_observed_at: u64,
    head_observed_at: u64,
    log_fill: u8,
    provider_secret: &SecretKey,
) -> InclusionReceipt {
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*provider_secret.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    provider_receipt_for_descriptor_signed_by(
        state,
        subject,
        entry_observed_at,
        head_observed_at,
        log_fill,
        &provider,
        provider_secret,
    )
}

#[allow(clippy::too_many_arguments)]
fn provider_receipt_for_descriptor_signed_by(
    state: &AccountState,
    subject: ProviderLogSubject,
    entry_observed_at: u64,
    head_observed_at: u64,
    log_fill: u8,
    provider: &ProviderDescriptor,
    signing_secret: &SecretKey,
) -> InclusionReceipt {
    let log_id = typed_id::<ProviderLogId>(log_fill);
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
    let signature = signing_secret.sign(&head.signing_bytes().unwrap());
    InclusionReceipt::new(
        entry,
        0,
        Vec::new(),
        SignedProviderHead::new(head, ProtocolSignature::ed25519(signature.to_bytes())),
    )
    .unwrap()
}

fn begin_recovery_operation(
    state: &AccountState,
    signer: &SecretKey,
) -> (AccountOperation, RecoveryId) {
    let plan = RecoveryAuthorityPlan::try_new(
        ProtocolVersion::V1,
        state.account_id(),
        typed_id::<CheckpointId>(0x44),
        state.heads()[0],
        state.recovery_policy_id(),
        state.recovery_policy().policy_version(),
        [0x51; 32],
        vec![controller(signer, 1)],
        state.control_policy().clone(),
        state.recovery_policy().clone(),
        Vec::new(),
        Timestamp::from_unix_millis(1_000),
        Extensions::default(),
    )
    .unwrap();
    let proposal =
        RecoveryProposal::try_new(ProtocolVersion::V1, plan, Extensions::default()).unwrap();
    let recovery_id = proposal.recovery_id().unwrap();
    let evidence = RecoveryThresholdEvidence::controller_policy(
        state.recovery_policy_id(),
        state.recovery_policy().policy_version(),
    );
    (
        AccountOperation::BeginRecovery(
            BeginRecovery::try_new(
                ProtocolVersion::V1,
                proposal,
                evidence,
                Extensions::default(),
            )
            .unwrap(),
        ),
        recovery_id,
    )
}

#[test]
fn genesis_projection_and_linear_transition_are_deterministic() {
    let (genesis, signer) = fixture();
    let mut state = AccountState::from_genesis(&genesis).unwrap();
    assert_eq!(state.sequence(), Sequence::GENESIS);
    assert_eq!(state.epoch(), Epoch::GENESIS);
    assert_eq!(state.lifecycle(), ProjectionLifecycle::Active);
    assert!(state.heads().is_empty());

    let added_secret = SecretKey::from_bytes(&[8; 32]);
    let event = authorized_event(
        &state,
        AccountOperation::AddController(controller(&added_secret, 1)),
        Epoch::new(1),
        2,
        &signer,
    );
    let event_id = event.event_id().unwrap();
    let outcome = state.validate_and_apply(&event).unwrap();

    assert_eq!(outcome.disposition(), ApplyDisposition::Applied);
    assert_eq!(outcome.event_id(), event_id);
    assert_eq!(state.sequence(), Sequence::new(1));
    assert_eq!(state.epoch(), Epoch::new(1));
    assert_eq!(state.heads(), [event_id]);
    assert_eq!(state.active_controllers().len(), 2);
}

#[test]
fn invalid_event_does_not_mutate_projection() {
    let (genesis, signer) = fixture();
    let mut state = AccountState::from_genesis(&genesis).unwrap();
    let added_secret = SecretKey::from_bytes(&[8; 32]);
    let event = authorized_event(
        &state,
        AccountOperation::AddController(controller(&added_secret, 1)),
        Epoch::GENESIS,
        3,
        &signer,
    );
    let before = state.clone();

    assert_eq!(
        state.validate_and_apply(&event),
        Err(IdentityError::InvalidEpoch)
    );
    assert_eq!(state, before);
}

#[test]
fn device_and_controller_public_keys_are_permanently_role_separated() {
    let (genesis, signer) = fixture();
    let mut state = AccountState::from_genesis(&genesis).unwrap();

    let controller_as_application =
        device_descriptor(&signer, 0xa0, &SecretKey::from_bytes(&[0xa1; 32]));
    let cross_tier = authorized_event(
        &state,
        AccountOperation::AuthorizeDevice(device_authorization(
            controller_as_application,
            Epoch::new(1),
        )),
        Epoch::new(1),
        0xa1,
        &signer,
    );
    let before = state.clone();
    assert_eq!(
        state.validate_and_apply(&cross_tier),
        Err(IdentityError::InvalidRelationship {
            resource: "controller/device public-key role separation"
        })
    );
    assert_eq!(state, before);

    let application_secret = SecretKey::from_bytes(&[0xa2; 32]);
    let endpoint_secret = SecretKey::from_bytes(&[0xa3; 32]);
    let original_descriptor = device_descriptor(&application_secret, 0xa4, &endpoint_secret);
    let original_id = original_descriptor.id().unwrap();
    let authorize = authorized_event(
        &state,
        AccountOperation::AuthorizeDevice(device_authorization(
            original_descriptor.clone(),
            Epoch::new(1),
        )),
        Epoch::new(1),
        0xa2,
        &signer,
    );
    state.validate_and_apply(&authorize).unwrap();

    let reused_descriptors = [
        device_descriptor(
            &application_secret,
            0xa5,
            &SecretKey::from_bytes(&[0xa6; 32]),
        ),
        device_descriptor(
            &SecretKey::from_bytes(&[0xa7; 32]),
            0xa4,
            &SecretKey::from_bytes(&[0xa8; 32]),
        ),
        device_descriptor(&SecretKey::from_bytes(&[0xa9; 32]), 0xaa, &endpoint_secret),
    ];
    for (offset, descriptor) in reused_descriptors.into_iter().enumerate() {
        let event = authorized_event(
            &state,
            AccountOperation::AuthorizeDevice(device_authorization(descriptor, Epoch::new(2))),
            Epoch::new(2),
            u8::try_from(0xab + offset).unwrap(),
            &signer,
        );
        let before = state.clone();
        assert_eq!(
            state.validate_and_apply(&event),
            Err(IdentityError::InvalidRelationship {
                resource: "retained device public-key reuse"
            })
        );
        assert_eq!(state, before);
    }

    let rotation = RotateDeviceKeys::new(
        original_id,
        device_authorization(
            device_descriptor(&SecretKey::from_bytes(&[0xac; 32]), 0xad, &endpoint_secret),
            Epoch::new(2),
        ),
        Extensions::default(),
    )
    .unwrap();
    let rotation = authorized_event(
        &state,
        AccountOperation::RotateDeviceKeys(rotation),
        Epoch::new(2),
        0xae,
        &signer,
    );
    let before = state.clone();
    assert_eq!(
        state.validate_and_apply(&rotation),
        Err(IdentityError::InvalidRelationship {
            resource: "retained device public-key reuse"
        })
    );
    assert_eq!(state, before);

    let revoke = authorized_event(
        &state,
        AccountOperation::RevokeDevice(
            RevokeDevice::new(original_id, None, Extensions::default()).unwrap(),
        ),
        Epoch::new(2),
        0xaf,
        &signer,
    );
    state.validate_and_apply(&revoke).unwrap();

    let tombstone_reuse = authorized_event(
        &state,
        AccountOperation::AuthorizeDevice(device_authorization(
            device_descriptor(
                &application_secret,
                0xb0,
                &SecretKey::from_bytes(&[0xb1; 32]),
            ),
            Epoch::new(3),
        )),
        Epoch::new(3),
        0xb1,
        &signer,
    );
    let before = state.clone();
    assert_eq!(
        state.validate_and_apply(&tombstone_reuse),
        Err(IdentityError::InvalidRelationship {
            resource: "retained device public-key reuse"
        })
    );
    assert_eq!(state, before);

    let controller_reuse = authorized_event(
        &state,
        AccountOperation::AddController(controller(&endpoint_secret, 1)),
        Epoch::new(3),
        0xb2,
        &signer,
    );
    assert_eq!(
        state.validate_and_apply(&controller_reuse),
        Err(IdentityError::InvalidRelationship {
            resource: "controller/device public-key role separation"
        })
    );
    assert_eq!(state, before);
}

#[test]
fn pending_recovery_gates_unrelated_operations_and_supports_exact_cancel_or_veto() {
    let (genesis, signer) = fixture();
    let mut state = AccountState::from_genesis(&genesis).unwrap();
    let baseline = authorized_event(
        &state,
        AccountOperation::AddController(controller(&SecretKey::from_bytes(&[8; 32]), 1)),
        Epoch::new(1),
        10,
        &signer,
    );
    state.validate_and_apply(&baseline).unwrap();

    let (begin, recovery_id) = begin_recovery_operation(&state, &signer);
    let begin = authorized_event(&state, begin, Epoch::new(2), 11, &signer);
    state.validate_and_apply(&begin).unwrap();
    assert_eq!(state.lifecycle(), ProjectionLifecycle::RecoveryPending);
    assert_eq!(state.epoch(), Epoch::new(2));

    let blocked = authorized_event(
        &state,
        AccountOperation::ChangeProviderPolicy(
            ProviderPolicy::local_only(ProviderPolicyVersion::new(1), Extensions::default())
                .unwrap(),
        ),
        Epoch::new(3),
        12,
        &signer,
    );
    let pending = state.clone();
    assert_eq!(
        state.validate_and_apply(&blocked),
        Err(IdentityError::RecoveryPending)
    );
    assert_eq!(state, pending);

    let unconfigured_provider = SecretKey::from_bytes(&[98; 32]);
    let begin_proposal_id = begin.body().proposal_id().unwrap();
    let forged_anchor = RecoveryDelayAnchor::try_new(
        ProtocolVersion::V1,
        state.account_id(),
        recovery_id,
        begin_proposal_id,
        state.provider_policy_id(),
        ProviderQuorum::new(1).unwrap(),
        ProviderReceipts::new(vec![
            provider_receipt_signed_by(
                &state,
                ProviderLogSubject::EventIntent(begin_proposal_id),
                0,
                0,
                0x66,
                &unconfigured_provider,
            ),
            recovery_provider_receipt(&state, begin_proposal_id, 100),
        ])
        .unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let forged_operation = AccountOperation::FinalizeRecovery(
        FinalizeRecovery::try_new(
            ProtocolVersion::V1,
            recovery_id,
            forged_anchor,
            Timestamp::from_unix_millis(110),
            Extensions::default(),
        )
        .unwrap(),
    );
    let forged_body = EventBody::new(
        state.account_id(),
        state.sequence().checked_next().unwrap(),
        Epoch::new(3),
        EventPredecessors::events(state.heads().to_vec()).unwrap(),
        forged_operation,
        Timestamp::from_unix_millis(110),
        [0x66; 16],
        Extensions::default(),
    )
    .unwrap();
    let checkpoint_id = typed_id::<CheckpointId>(0x44);
    let completion = ProviderReceipts::new(vec![provider_receipt(
        &state,
        ProviderLogSubject::Checkpoint(checkpoint_id),
        100,
        110,
        0x66,
    )])
    .unwrap();
    let forged_finalize = authorize_body_without_controller_approvals_with_freshness(
        &state,
        forged_body,
        FreshnessEvidence::provider_quorum(checkpoint_id, state.provider_policy_id(), completion)
            .unwrap(),
    );
    let before_forged_anchor = state.clone();
    assert_eq!(
        state.validate_and_apply(&forged_finalize),
        Err(IdentityError::InvalidRelationship {
            resource: "recovery begin observation binding",
        })
    );
    assert_eq!(state, before_forged_anchor);

    let forged_configured_signature = finalize_recovery_event_with_anchor_signer(
        &state,
        recovery_id,
        begin_proposal_id,
        0x65,
        &unconfigured_provider,
    );
    let before_forged_signature = state.clone();
    assert_eq!(
        state.validate_and_apply(&forged_configured_signature),
        Err(IdentityError::InvalidSignature)
    );
    assert_eq!(state, before_forged_signature);

    let mut finalized = state.clone();
    let finalize_event =
        |projected: &AccountState, anchor_head_time: u64, outer_head_time: u64, nonce: u8| {
            let delay_anchor = RecoveryDelayAnchor::try_new(
                ProtocolVersion::V1,
                projected.account_id(),
                recovery_id,
                begin_proposal_id,
                projected.provider_policy_id(),
                ProviderQuorum::new(1).unwrap(),
                ProviderReceipts::new(vec![provider_receipt(
                    projected,
                    ProviderLogSubject::EventIntent(begin_proposal_id),
                    100,
                    anchor_head_time,
                    0x67,
                )])
                .unwrap(),
                Extensions::default(),
            )
            .unwrap();
            let operation = AccountOperation::FinalizeRecovery(
                FinalizeRecovery::try_new(
                    ProtocolVersion::V1,
                    recovery_id,
                    delay_anchor.clone(),
                    Timestamp::from_unix_millis(900),
                    Extensions::default(),
                )
                .unwrap(),
            );
            let body = EventBody::new(
                projected.account_id(),
                projected.sequence().checked_next().unwrap(),
                Epoch::new(3),
                EventPredecessors::events(projected.heads().to_vec()).unwrap(),
                operation,
                Timestamp::from_unix_millis(900),
                [nonce; 16],
                Extensions::default(),
            )
            .unwrap();
            let checkpoint_id = typed_id::<CheckpointId>(0x44);
            let receipts = ProviderReceipts::new(vec![provider_receipt(
                projected,
                ProviderLogSubject::Checkpoint(checkpoint_id),
                100,
                outer_head_time,
                nonce,
            )])
            .unwrap();
            authorize_body_without_controller_approvals_with_freshness(
                projected,
                body,
                FreshnessEvidence::provider_quorum(
                    checkpoint_id,
                    projected.provider_policy_id(),
                    receipts,
                )
                .unwrap(),
            )
        };

    let insufficient_nested_quorum = finalize_event(&finalized, 109, 110, 0x68);
    let before_finalize = finalized.clone();
    assert_eq!(
        finalized.validate_and_apply(&insufficient_nested_quorum),
        Err(IdentityError::DelayNotElapsed)
    );
    assert_eq!(finalized, before_finalize);

    let finalize = finalize_event(&finalized, 110, 109, 0x69);
    finalized.validate_and_apply(&finalize).unwrap();
    assert_eq!(finalized.lifecycle(), ProjectionLifecycle::Active);
    assert_eq!(finalized.epoch(), Epoch::new(3));
    assert_eq!(finalized.active_controllers().len(), 1);

    let threshold = RecoveryThresholdEvidence::controller_policy(
        state.recovery_policy_id(),
        state.recovery_policy().policy_version(),
    );
    let wrong_cancel = AccountOperation::CancelRecovery(
        CancelRecovery::try_new(
            ProtocolVersion::V1,
            typed_id::<RecoveryId>(0x52),
            threshold.clone(),
            FreshnessEvidence::local_known(typed_id::<CheckpointId>(0x44)),
            Extensions::default(),
        )
        .unwrap(),
    );
    let wrong_cancel = authorized_event(&state, wrong_cancel, Epoch::new(3), 13, &signer);
    assert_eq!(
        state.validate_and_apply(&wrong_cancel),
        Err(IdentityError::InvalidRelationship {
            resource: "cancel pending recovery compare-and-set"
        })
    );
    assert_eq!(state, pending);

    let mut cancelled = state.clone();
    let cancel = AccountOperation::CancelRecovery(
        CancelRecovery::try_new(
            ProtocolVersion::V1,
            recovery_id,
            threshold,
            FreshnessEvidence::local_known(typed_id::<CheckpointId>(0x44)),
            Extensions::default(),
        )
        .unwrap(),
    );
    let cancel = authorized_event(&cancelled, cancel, Epoch::new(3), 14, &signer);
    cancelled.validate_and_apply(&cancel).unwrap();
    assert_eq!(cancelled.lifecycle(), ProjectionLifecycle::Active);
    assert_eq!(cancelled.epoch(), Epoch::new(3));

    let veto = AccountOperation::VetoRecovery(
        VetoRecovery::try_new(
            ProtocolVersion::V1,
            recovery_id,
            state.control_policy_id(),
            FreshnessEvidence::local_known(typed_id::<CheckpointId>(0x44)),
            Extensions::default(),
        )
        .unwrap(),
    );
    let veto = authorized_event(&state, veto, Epoch::new(3), 15, &signer);
    state.validate_and_apply(&veto).unwrap();
    assert_eq!(state.lifecycle(), ProjectionLifecycle::Active);
    assert_eq!(state.epoch(), Epoch::new(3));
}

#[test]
fn recovery_anchor_quorum_and_nested_completion_cannot_be_bypassed_by_outer_receipts() {
    let (genesis, signer) = fixture();
    let first_provider_secret = SecretKey::from_bytes(&[99; 32]);
    let second_provider_secret = SecretKey::from_bytes(&[98; 32]);
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
    let mut state = AccountState::from_genesis(&genesis).unwrap();
    let provider_change = authorized_event(
        &state,
        AccountOperation::ChangeProviderPolicy(
            ProviderPolicy::replicated(
                ProviderPolicyVersion::new(1),
                vec![first_provider.clone(), second_provider.clone()],
                ProviderQuorum::new(2).unwrap(),
                ProviderQuorum::new(2).unwrap(),
                DurationMillis::new(1_000),
                Extensions::default(),
            )
            .unwrap(),
        ),
        Epoch::new(1),
        0x60,
        &signer,
    );
    state.validate_and_apply(&provider_change).unwrap();
    let (begin, recovery_id) = begin_recovery_operation(&state, &signer);
    let begin_body = EventBody::new(
        state.account_id(),
        state.sequence().checked_next().unwrap(),
        Epoch::new(2),
        EventPredecessors::events(state.heads().to_vec()).unwrap(),
        begin,
        Timestamp::from_unix_millis(0x61),
        [0x61; 16],
        Extensions::default(),
    )
    .unwrap();
    let begin_proposal_id = begin_body.proposal_id().unwrap();
    let checkpoint_id = typed_id::<CheckpointId>(0x44);
    let begin_evidence = AdmissionEvidence::new(
        begin_proposal_id,
        checkpoint_id,
        state.provider_policy_id(),
        FreshnessEvidence::local_known(checkpoint_id),
        DelayEvidence::provider_quorum(
            state.provider_policy_id(),
            ProviderQuorum::new(2).unwrap(),
            controller_intent_approvals(&state, &begin_body, &signer),
            ProviderReceipts::new(vec![
                provider_receipt_for_descriptor_signed_by(
                    &state,
                    ProviderLogSubject::EventIntent(begin_proposal_id),
                    0x61,
                    0x61,
                    0x61,
                    &first_provider,
                    &first_provider_secret,
                ),
                provider_receipt_for_descriptor_signed_by(
                    &state,
                    ProviderLogSubject::EventIntent(begin_proposal_id),
                    0x61,
                    0x61,
                    0x62,
                    &second_provider,
                    &second_provider_secret,
                ),
            ])
            .unwrap(),
        )
        .unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let begin = authorize_body_with_evidence(&state, begin_body, begin_evidence, &signer);
    state.validate_and_apply(&begin).unwrap();

    let build_finalize =
        |projected: &AccountState, required: u16, second_nested_head: u64, nonce: u8| {
            let mut nested = vec![provider_receipt_for_descriptor_signed_by(
                projected,
                ProviderLogSubject::EventIntent(begin_proposal_id),
                0x61,
                110,
                0x61,
                &first_provider,
                &first_provider_secret,
            )];
            if required > 1 {
                nested.push(provider_receipt_for_descriptor_signed_by(
                    projected,
                    ProviderLogSubject::EventIntent(begin_proposal_id),
                    0x61,
                    second_nested_head,
                    0x62,
                    &second_provider,
                    &second_provider_secret,
                ));
            }
            let anchor = RecoveryDelayAnchor::try_new(
                ProtocolVersion::V1,
                projected.account_id(),
                recovery_id,
                begin_proposal_id,
                projected.provider_policy_id(),
                ProviderQuorum::new(required).unwrap(),
                ProviderReceipts::new(nested).unwrap(),
                Extensions::default(),
            )
            .unwrap();
            let operation = AccountOperation::FinalizeRecovery(
                FinalizeRecovery::try_new(
                    ProtocolVersion::V1,
                    recovery_id,
                    anchor,
                    Timestamp::from_unix_millis(110),
                    Extensions::default(),
                )
                .unwrap(),
            );
            let body = EventBody::new(
                projected.account_id(),
                projected.sequence().checked_next().unwrap(),
                Epoch::new(3),
                EventPredecessors::events(projected.heads().to_vec()).unwrap(),
                operation,
                Timestamp::from_unix_millis(110),
                [nonce; 16],
                Extensions::default(),
            )
            .unwrap();
            let checkpoint_id = typed_id::<CheckpointId>(0x44);
            let outer = ProviderReceipts::new(vec![
                provider_receipt_for_descriptor_signed_by(
                    projected,
                    ProviderLogSubject::Checkpoint(checkpoint_id),
                    100,
                    110,
                    nonce.saturating_add(2),
                    &first_provider,
                    &first_provider_secret,
                ),
                provider_receipt_for_descriptor_signed_by(
                    projected,
                    ProviderLogSubject::Checkpoint(checkpoint_id),
                    100,
                    110,
                    nonce.saturating_add(3),
                    &second_provider,
                    &second_provider_secret,
                ),
            ])
            .unwrap();
            authorize_body_without_controller_approvals_with_freshness(
                projected,
                body,
                FreshnessEvidence::provider_quorum(
                    checkpoint_id,
                    projected.provider_policy_id(),
                    outer,
                )
                .unwrap(),
            )
        };

    let before = state.clone();
    assert_eq!(
        state.validate_and_apply(&build_finalize(&state, 1, 110, 0x62)),
        Err(IdentityError::FreshnessUnavailable)
    );
    assert_eq!(state, before);
    assert_eq!(
        state.validate_and_apply(&build_finalize(&state, 2, 106, 0x66)),
        Err(IdentityError::DelayNotElapsed)
    );
    assert_eq!(state, before);
    state
        .validate_and_apply(&build_finalize(&state, 2, 107, 0x6a))
        .unwrap();
    assert_eq!(state.lifecycle(), ProjectionLifecycle::Active);
}

#[test]
fn different_valid_begin_admissions_are_detectable_forks_and_bind_completion() {
    let (genesis, signer) = fixture();
    let first_provider_secret = SecretKey::from_bytes(&[99; 32]);
    let second_provider_secret = SecretKey::from_bytes(&[98; 32]);
    let third_provider_secret = SecretKey::from_bytes(&[97; 32]);
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
    let third_provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*third_provider_secret.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();

    let mut base = AccountState::from_genesis(&genesis).unwrap();
    let provider_change = authorized_event(
        &base,
        AccountOperation::ChangeProviderPolicy(
            ProviderPolicy::replicated(
                ProviderPolicyVersion::new(1),
                vec![
                    first_provider.clone(),
                    second_provider.clone(),
                    third_provider.clone(),
                ],
                ProviderQuorum::new(2).unwrap(),
                ProviderQuorum::new(2).unwrap(),
                DurationMillis::new(1_000),
                Extensions::default(),
            )
            .unwrap(),
        ),
        Epoch::new(1),
        0x70,
        &signer,
    );
    base.validate_and_apply(&provider_change).unwrap();

    let (operation, recovery_id) = begin_recovery_operation(&base, &signer);
    let begin_body = EventBody::new(
        base.account_id(),
        base.sequence().checked_next().unwrap(),
        Epoch::new(2),
        EventPredecessors::events(base.heads().to_vec()).unwrap(),
        operation,
        Timestamp::from_unix_millis(100),
        [0x71; 16],
        Extensions::default(),
    )
    .unwrap();
    let begin_proposal_id = begin_body.proposal_id().unwrap();
    let checkpoint_id = typed_id::<CheckpointId>(0x44);
    let build_begin = |receipts: ProviderReceipts| {
        let evidence = AdmissionEvidence::new(
            begin_proposal_id,
            checkpoint_id,
            base.provider_policy_id(),
            FreshnessEvidence::local_known(checkpoint_id),
            DelayEvidence::provider_quorum(
                base.provider_policy_id(),
                ProviderQuorum::new(2).unwrap(),
                controller_intent_approvals(&base, &begin_body, &signer),
                receipts,
            )
            .unwrap(),
            Extensions::default(),
        )
        .unwrap();
        authorize_body_with_evidence(&base, begin_body.clone(), evidence, &signer)
    };
    let first_subset_first_receipt = || {
        provider_receipt_for_descriptor_signed_by(
            &base,
            ProviderLogSubject::EventIntent(begin_proposal_id),
            100,
            100,
            0x71,
            &first_provider,
            &first_provider_secret,
        )
    };
    let first_subset_second_receipt = || {
        provider_receipt_for_descriptor_signed_by(
            &base,
            ProviderLogSubject::EventIntent(begin_proposal_id),
            100,
            100,
            0x72,
            &second_provider,
            &second_provider_secret,
        )
    };
    let second_subset_first_receipt = || {
        provider_receipt_for_descriptor_signed_by(
            &base,
            ProviderLogSubject::EventIntent(begin_proposal_id),
            105,
            105,
            0x73,
            &first_provider,
            &first_provider_secret,
        )
    };
    let second_subset_third_receipt = || {
        provider_receipt_for_descriptor_signed_by(
            &base,
            ProviderLogSubject::EventIntent(begin_proposal_id),
            105,
            105,
            0x74,
            &third_provider,
            &third_provider_secret,
        )
    };
    let first_subset = build_begin(
        ProviderReceipts::new(vec![
            first_subset_first_receipt(),
            first_subset_second_receipt(),
        ])
        .unwrap(),
    );
    let second_subset = build_begin(
        ProviderReceipts::new(vec![
            second_subset_first_receipt(),
            second_subset_third_receipt(),
        ])
        .unwrap(),
    );

    let mut projected_from_first_subset = base.clone();
    projected_from_first_subset
        .validate_and_apply(&first_subset)
        .unwrap();
    let mut projected_from_second_subset = base.clone();
    projected_from_second_subset
        .validate_and_apply(&second_subset)
        .unwrap();
    assert_ne!(projected_from_first_subset, projected_from_second_subset);
    assert_ne!(
        first_subset.event_id().unwrap(),
        second_subset.event_id().unwrap()
    );
    assert_ne!(
        projected_from_first_subset.revision_token(),
        projected_from_second_subset.revision_token()
    );
    assert_eq!(
        projected_from_first_subset.revision_token().heads(),
        [first_subset.event_id().unwrap()]
    );
    assert_eq!(
        projected_from_second_subset.revision_token().heads(),
        [second_subset.event_id().unwrap()]
    );
    assert_ne!(
        build_checkpoint_body(
            &projected_from_first_subset,
            Timestamp::from_unix_millis(106)
        )
        .unwrap(),
        build_checkpoint_body(
            &projected_from_second_subset,
            Timestamp::from_unix_millis(106)
        )
        .unwrap()
    );

    let mut forked_first_order = projected_from_first_subset.clone();
    assert_eq!(
        forked_first_order
            .validate_and_apply(&second_subset)
            .unwrap()
            .disposition(),
        ApplyDisposition::ForkDetected
    );
    let mut forked_second_order = projected_from_second_subset.clone();
    assert_eq!(
        forked_second_order
            .validate_and_apply(&first_subset)
            .unwrap()
            .disposition(),
        ApplyDisposition::ForkDetected
    );
    assert_eq!(forked_first_order, forked_second_order);
    assert_eq!(forked_first_order.lifecycle(), ProjectionLifecycle::Forked);
    let mut expected_heads = vec![
        first_subset.event_id().unwrap(),
        second_subset.event_id().unwrap(),
    ];
    expected_heads.sort_unstable();
    assert_eq!(forked_first_order.heads(), expected_heads);

    let before_replay = projected_from_first_subset.clone();
    assert_eq!(
        projected_from_first_subset
            .validate_and_apply(&first_subset)
            .unwrap()
            .disposition(),
        ApplyDisposition::Replay
    );
    assert_eq!(projected_from_first_subset, before_replay);

    let build_finalize =
        |projected: &AccountState, use_first_subset: bool, observed_at: u64, nonce: u8| {
            let completion_at = observed_at.checked_add(10).unwrap();
            let mut receipts = Vec::with_capacity(2);
            if use_first_subset {
                receipts.push(provider_receipt_for_descriptor_signed_by(
                    projected,
                    ProviderLogSubject::EventIntent(begin_proposal_id),
                    observed_at,
                    completion_at,
                    0x71,
                    &first_provider,
                    &first_provider_secret,
                ));
                receipts.push(provider_receipt_for_descriptor_signed_by(
                    projected,
                    ProviderLogSubject::EventIntent(begin_proposal_id),
                    observed_at,
                    completion_at,
                    0x72,
                    &second_provider,
                    &second_provider_secret,
                ));
            } else {
                receipts.push(provider_receipt_for_descriptor_signed_by(
                    projected,
                    ProviderLogSubject::EventIntent(begin_proposal_id),
                    observed_at,
                    completion_at,
                    0x73,
                    &first_provider,
                    &first_provider_secret,
                ));
                receipts.push(provider_receipt_for_descriptor_signed_by(
                    projected,
                    ProviderLogSubject::EventIntent(begin_proposal_id),
                    observed_at,
                    completion_at,
                    0x74,
                    &third_provider,
                    &third_provider_secret,
                ));
            }
            let anchor = RecoveryDelayAnchor::try_new(
                ProtocolVersion::V1,
                projected.account_id(),
                recovery_id,
                begin_proposal_id,
                projected.provider_policy_id(),
                ProviderQuorum::new(2).unwrap(),
                ProviderReceipts::new(receipts).unwrap(),
                Extensions::default(),
            )
            .unwrap();
            let operation = AccountOperation::FinalizeRecovery(
                FinalizeRecovery::try_new(
                    ProtocolVersion::V1,
                    recovery_id,
                    anchor,
                    Timestamp::from_unix_millis(completion_at),
                    Extensions::default(),
                )
                .unwrap(),
            );
            let body = EventBody::new(
                projected.account_id(),
                projected.sequence().checked_next().unwrap(),
                Epoch::new(3),
                EventPredecessors::events(projected.heads().to_vec()).unwrap(),
                operation,
                Timestamp::from_unix_millis(completion_at),
                [nonce; 16],
                Extensions::default(),
            )
            .unwrap();
            let outer = ProviderReceipts::new(vec![
                provider_receipt_for_descriptor_signed_by(
                    projected,
                    ProviderLogSubject::Checkpoint(checkpoint_id),
                    100,
                    completion_at,
                    0x78,
                    &first_provider,
                    &first_provider_secret,
                ),
                provider_receipt_for_descriptor_signed_by(
                    projected,
                    ProviderLogSubject::Checkpoint(checkpoint_id),
                    100,
                    completion_at,
                    0x79,
                    &second_provider,
                    &second_provider_secret,
                ),
            ])
            .unwrap();
            authorize_body_without_controller_approvals_with_freshness(
                projected,
                body,
                FreshnessEvidence::provider_quorum(
                    checkpoint_id,
                    projected.provider_policy_id(),
                    outer,
                )
                .unwrap(),
            )
        };

    let alternate = build_finalize(&projected_from_first_subset, false, 105, 0x76);
    let before_alternate = projected_from_first_subset.clone();
    assert_eq!(
        projected_from_first_subset.validate_and_apply(&alternate),
        Err(IdentityError::InvalidRelationship {
            resource: "recovery begin observation binding",
        })
    );
    assert_eq!(projected_from_first_subset, before_alternate);

    let exact = build_finalize(&projected_from_first_subset, true, 100, 0x77);
    projected_from_first_subset
        .validate_and_apply(&exact)
        .unwrap();
    assert_eq!(
        projected_from_first_subset.lifecycle(),
        ProjectionLifecycle::Active
    );

    let alternate = build_finalize(&projected_from_second_subset, true, 100, 0x78);
    let before_alternate = projected_from_second_subset.clone();
    assert_eq!(
        projected_from_second_subset.validate_and_apply(&alternate),
        Err(IdentityError::InvalidRelationship {
            resource: "recovery begin observation binding",
        })
    );
    assert_eq!(projected_from_second_subset, before_alternate);

    let exact = build_finalize(&projected_from_second_subset, false, 105, 0x79);
    projected_from_second_subset
        .validate_and_apply(&exact)
        .unwrap();
    assert_eq!(
        projected_from_second_subset.lifecycle(),
        ProjectionLifecycle::Active
    );
}

#[test]
fn cancel_recovery_requires_cancel_scope_not_begin_scope() {
    let (genesis, signer) = fixture();
    let mut state = AccountState::from_genesis(&genesis).unwrap();
    let begin_only_secret = SecretKey::from_bytes(&[0x5a; 32]);
    let begin_only = ControllerDescriptor::new(
        SigningPublicKey::ed25519(*begin_only_secret.public().as_bytes()).unwrap(),
        ControllerClass::OfflineRecovery,
        ControllerWeight::new(1).unwrap(),
        ControllerScope::operations(vec![OperationKind::BeginRecovery]).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let add = authorized_event(
        &state,
        AccountOperation::AddController(begin_only),
        Epoch::new(1),
        0x5a,
        &signer,
    );
    state.validate_and_apply(&add).unwrap();

    let (begin, recovery_id) = begin_recovery_operation(&state, &signer);
    let begin = authorized_event(
        &state,
        begin,
        state.epoch().checked_next().unwrap(),
        0x5b,
        &begin_only_secret,
    );
    state.validate_and_apply(&begin).unwrap();

    let cancel = AccountOperation::CancelRecovery(
        CancelRecovery::try_new(
            ProtocolVersion::V1,
            recovery_id,
            RecoveryThresholdEvidence::controller_policy(
                state.recovery_policy_id(),
                state.recovery_policy().policy_version(),
            ),
            FreshnessEvidence::local_known(typed_id::<CheckpointId>(0x44)),
            Extensions::default(),
        )
        .unwrap(),
    );
    let cancel = authorized_event(
        &state,
        cancel,
        state.epoch().checked_next().unwrap(),
        0x5c,
        &begin_only_secret,
    );
    let before = state.clone();
    assert_eq!(
        state.validate_and_apply(&cancel),
        Err(IdentityError::IneligibleController)
    );
    assert_eq!(state, before);
}

#[test]
fn delayed_begin_recovery_uses_recovery_policy_threshold_not_control_rule_weight() {
    let signer = SecretKey::from_bytes(&[0x5d; 32]);
    let provider_secret = SecretKey::from_bytes(&[99; 32]);
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*provider_secret.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let policy = ControlPolicy::new(
        vec![
            rule(OperationKind::AddController, 1),
            PolicyRule::new(
                OperationKind::BeginRecovery,
                RequiredWeight::new(u32::MAX).unwrap(),
                ControllerSelector::any_active(),
                FreshnessRequirement::latest_known(),
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
        [0x5d; 32],
        Timestamp::from_unix_millis(1),
        policy,
        vec![controller(&signer, 1)],
        recovery,
        ProviderPolicy::replicated(
            ProviderPolicyVersion::GENESIS,
            vec![provider],
            ProviderQuorum::new(1).unwrap(),
            ProviderQuorum::new(1).unwrap(),
            DurationMillis::new(1_000),
            Extensions::default(),
        )
        .unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let mut state = AccountState::from_genesis(&genesis).unwrap();
    let baseline = authorized_event(
        &state,
        AccountOperation::AddController(controller(&SecretKey::from_bytes(&[0x5e; 32]), 1)),
        Epoch::new(1),
        0x5e,
        &signer,
    );
    state.validate_and_apply(&baseline).unwrap();

    let (operation, _) = begin_recovery_operation(&state, &signer);
    let body = EventBody::new(
        state.account_id(),
        state.sequence().checked_next().unwrap(),
        state.epoch().checked_next().unwrap(),
        EventPredecessors::events(state.heads().to_vec()).unwrap(),
        operation,
        Timestamp::from_unix_millis(110),
        [0x5f; 16],
        Extensions::default(),
    )
    .unwrap();
    let proposal_id = body.proposal_id().unwrap();
    let signer_key = SigningPublicKey::ed25519(*signer.public().as_bytes()).unwrap();
    let controller_id = state
        .active_controllers()
        .iter()
        .find(|controller| controller.signing_key() == signer_key)
        .unwrap()
        .id();
    let intent_body =
        EventIntentApprovalBody::new(controller_id, proposal_id, Extensions::default()).unwrap();
    let intent_signature = signer.sign(&intent_body.to_canonical_bytes().unwrap());
    let intent = SignedEventIntentApproval::new(
        intent_body,
        vec![KeyedSignature::new(
            CryptoSuiteDescriptor::v1()
                .unwrap()
                .crypto_suite_id()
                .unwrap(),
            ControllerKeyId::for_signing_key(&signer_key).unwrap(),
            AlgorithmSignature::new(1, intent_signature.to_bytes().to_vec()).unwrap(),
        )],
    )
    .unwrap();
    let intent_approvals = EventIntentApprovals::new(vec![intent]).unwrap();
    let admission = verify_event_intent_admission(&state, &body, &intent_approvals).unwrap();
    assert_eq!(admission.account_id(), state.account_id());
    assert_eq!(
        admission.subject(),
        ProviderLogSubject::EventIntent(proposal_id)
    );
    let delay_receipts = ProviderReceipts::new(vec![provider_receipt(
        &state,
        ProviderLogSubject::EventIntent(proposal_id),
        100,
        110,
        0x5f,
    )])
    .unwrap();
    let checkpoint_id = typed_id::<CheckpointId>(0x44);
    let evidence = AdmissionEvidence::new(
        proposal_id,
        checkpoint_id,
        state.provider_policy_id(),
        FreshnessEvidence::local_known(checkpoint_id),
        DelayEvidence::provider_quorum(
            state.provider_policy_id(),
            ProviderQuorum::new(1).unwrap(),
            intent_approvals,
            delay_receipts,
        )
        .unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let begin = authorize_body_with_evidence(&state, body, evidence, &signer);
    state.validate_and_apply(&begin).unwrap();
    assert_eq!(state.lifecycle(), ProjectionLifecycle::RecoveryPending);
}

#[test]
fn guardian_recovery_requires_authenticated_provider_time_and_accepts_valid_authority() {
    let guardian_secret = SecretKey::from_bytes(&[0x82; 32]);
    let (genesis, controller_secret) = fixture();
    let mut state = AccountState::from_genesis(&genesis).unwrap();
    let baseline = authorized_event(
        &state,
        AccountOperation::AddController(controller(&SecretKey::from_bytes(&[0x85; 32]), 1)),
        Epoch::new(1),
        1,
        &controller_secret,
    );
    state.validate_and_apply(&baseline).unwrap();

    // First install a guardian recovery policy under the original controller authority. The
    // guardian leaf excludes the recovery-policy ID to avoid a circular root/ID dependency.
    let blinding_bytes = [0x83; 32];
    let guardian_account_id = typed_id::<krikos_identity::AccountId>(0x88);
    let placeholder_policy_id = typed_id::<RecoveryPolicyId>(0x89);
    let placeholder_grant = GuardianGrant::try_new(
        ProtocolVersion::V1,
        state.account_id(),
        placeholder_policy_id,
        guardian_account_id,
        SigningPublicKey::ed25519(*guardian_secret.public().as_bytes()).unwrap(),
        ControllerWeight::new(1).unwrap(),
        Epoch::GENESIS,
        Some(Timestamp::from_unix_millis(1_000)),
        Extensions::default(),
    )
    .unwrap();
    let guardian_set = MerkleSet::new(vec![
        placeholder_grant
            .blinded_merkle_leaf(&BlindingSecret::try_new(blinding_bytes).unwrap())
            .unwrap(),
    ])
    .unwrap();
    let root = GuardianSetRoot::new(guardian_set.root().unwrap()).unwrap();
    let guardian_policy = RecoveryPolicy::new(
        RecoveryPolicyVersion::new(1),
        RecoveryAuthority::guardian_threshold(
            GuardianThreshold::new(root, 1, 1, RequiredWeight::new(1).unwrap()).unwrap(),
        ),
        DurationMillis::new(10),
        DurationMillis::new(100),
        Extensions::default(),
    )
    .unwrap();
    let guardian_control_policy = ControlPolicy::new(
        vec![
            provider_rule(OperationKind::BeginRecovery, 1),
            provider_rule(OperationKind::CancelRecovery, 1),
            provider_rule(OperationKind::FinalizeRecovery, 1),
        ],
        Extensions::default(),
    )
    .unwrap();
    let replacement_secret = SecretKey::from_bytes(&[0x87; 32]);
    let install_plan = RecoveryAuthorityPlan::try_new(
        ProtocolVersion::V1,
        state.account_id(),
        typed_id::<CheckpointId>(0x44),
        state.heads()[0],
        state.recovery_policy_id(),
        state.recovery_policy().policy_version(),
        [0x86; 32],
        vec![controller(&replacement_secret, 1)],
        guardian_control_policy,
        guardian_policy.clone(),
        Vec::new(),
        Timestamp::from_unix_millis(1_000),
        Extensions::default(),
    )
    .unwrap();
    let install_proposal =
        RecoveryProposal::try_new(ProtocolVersion::V1, install_plan, Extensions::default())
            .unwrap();
    let install_recovery_id = install_proposal.recovery_id().unwrap();
    let install = AccountOperation::BeginRecovery(
        BeginRecovery::try_new(
            ProtocolVersion::V1,
            install_proposal,
            RecoveryThresholdEvidence::controller_policy(
                state.recovery_policy_id(),
                state.recovery_policy().policy_version(),
            ),
            Extensions::default(),
        )
        .unwrap(),
    );
    let install = authorized_event(&state, install, Epoch::new(2), 0x86, &controller_secret);
    let install_proposal_id = install.body().proposal_id().unwrap();
    state.validate_and_apply(&install).unwrap();
    let finalize = finalize_recovery_event(&state, install_recovery_id, install_proposal_id, 0x87);
    state.validate_and_apply(&finalize).unwrap();
    assert_eq!(state.recovery_policy_id(), guardian_policy.id().unwrap());

    let plan = RecoveryAuthorityPlan::try_new(
        ProtocolVersion::V1,
        state.account_id(),
        typed_id::<CheckpointId>(0x44),
        state.heads()[0],
        state.recovery_policy_id(),
        state.recovery_policy().policy_version(),
        [0x88; 32],
        vec![controller(&replacement_secret, 1)],
        state.control_policy().clone(),
        state.recovery_policy().clone(),
        Vec::new(),
        Timestamp::from_unix_millis(1_000),
        Extensions::default(),
    )
    .unwrap();
    let proposal =
        RecoveryProposal::try_new(ProtocolVersion::V1, plan, Extensions::default()).unwrap();
    let recovery_id = proposal.recovery_id().unwrap();
    let protected_account_id = state.account_id();
    let recovery_policy_id = state.recovery_policy_id();
    let guardian_signing_key =
        SigningPublicKey::ed25519(*guardian_secret.public().as_bytes()).unwrap();
    let guardian_grant = || {
        GuardianGrant::try_new(
            ProtocolVersion::V1,
            protected_account_id,
            recovery_policy_id,
            guardian_account_id,
            guardian_signing_key,
            ControllerWeight::new(1).unwrap(),
            Epoch::GENESIS,
            Some(Timestamp::from_unix_millis(1_000)),
            Extensions::default(),
        )
        .unwrap()
    };
    let grant = guardian_grant();
    let proof = guardian_set
        .inclusion_proof(
            grant
                .blinded_merkle_leaf(&BlindingSecret::try_new(blinding_bytes).unwrap())
                .unwrap()
                .key(),
        )
        .unwrap();
    let opening = GuardianGrantOpening::try_new(
        ProtocolVersion::V1,
        grant,
        BlindingSecret::try_new(blinding_bytes).unwrap(),
        root,
        u16::try_from(proof.leaf_index()).unwrap(),
        proof.audit_path().to_vec(),
        Extensions::default(),
    )
    .unwrap();
    let guardian_grant_id = opening.guardian_grant_id();
    let guardian_body = GuardianApprovalBody::try_new(
        ProtocolVersion::V1,
        state.account_id(),
        recovery_id,
        GuardianApprovalDecision::Begin,
        guardian_grant_id,
        state.epoch(),
        Timestamp::from_unix_millis(200),
        Extensions::default(),
    )
    .unwrap();
    let guardian_signature = guardian_secret.sign(&guardian_body.signing_bytes().unwrap());
    let guardian_approval = SignedGuardianApproval::try_new(
        guardian_body.clone(),
        opening,
        ProtocolSignature::ed25519(guardian_signature.to_bytes()),
    )
    .unwrap();
    let forged_signature = guardian_approval.with_signature(ProtocolSignature::ed25519([0x5a; 64]));
    let build_begin_body = |approval: SignedGuardianApproval, nonce: u8| {
        let threshold = RecoveryThresholdEvidence::guardian_approvals(
            state.recovery_policy_id(),
            state.recovery_policy().policy_version(),
            GuardianApprovalSet::try_new(vec![approval]).unwrap(),
        )
        .unwrap();
        let begin = AccountOperation::BeginRecovery(
            BeginRecovery::try_new(
                ProtocolVersion::V1,
                proposal.clone(),
                threshold,
                Extensions::default(),
            )
            .unwrap(),
        );
        EventBody::new(
            state.account_id(),
            state.sequence().checked_next().unwrap(),
            state.epoch().checked_next().unwrap(),
            EventPredecessors::events(state.heads().to_vec()).unwrap(),
            begin,
            Timestamp::from_unix_millis(200),
            [nonce; 16],
            Extensions::default(),
        )
        .unwrap()
    };
    let begin_body = build_begin_body(guardian_approval, 0x8a);

    let forged_signature_body = build_begin_body(forged_signature, 0x8b);
    assert_eq!(
        verify_guardian_recovery_intent_admission(
            &state,
            &forged_signature_body,
            Timestamp::from_unix_millis(200),
        ),
        Err(IdentityError::InvalidSignature)
    );

    let forged_opening = GuardianGrantOpening::try_new(
        ProtocolVersion::V1,
        guardian_grant(),
        BlindingSecret::try_new([0x84; 32]).unwrap(),
        root,
        0,
        Vec::new(),
        Extensions::default(),
    )
    .unwrap();
    let forged_membership_body = GuardianApprovalBody::try_new(
        ProtocolVersion::V1,
        state.account_id(),
        recovery_id,
        GuardianApprovalDecision::Begin,
        forged_opening.guardian_grant_id(),
        state.epoch(),
        Timestamp::from_unix_millis(200),
        Extensions::default(),
    )
    .unwrap();
    let forged_membership_signature =
        guardian_secret.sign(&forged_membership_body.signing_bytes().unwrap());
    let forged_membership = SignedGuardianApproval::try_new(
        forged_membership_body,
        forged_opening,
        ProtocolSignature::ed25519(forged_membership_signature.to_bytes()),
    )
    .unwrap();
    let forged_membership_body = build_begin_body(forged_membership, 0x8c);
    assert!(
        verify_guardian_recovery_intent_admission(
            &state,
            &forged_membership_body,
            Timestamp::from_unix_millis(200),
        )
        .is_err()
    );
    assert_eq!(
        verify_guardian_recovery_intent_admission(
            &state,
            &begin_body,
            Timestamp::from_unix_millis(199),
        ),
        Err(IdentityError::StaleEvidence)
    );
    assert_eq!(
        verify_guardian_recovery_intent_admission(
            &state,
            &begin_body,
            Timestamp::from_unix_millis(1_000),
        ),
        Err(IdentityError::StaleEvidence)
    );
    let begin_without_time =
        authorize_body_without_controller_approvals(&state, begin_body.clone());
    let before = state.clone();
    assert_eq!(
        state.validate_and_apply(&begin_without_time),
        Err(IdentityError::FreshnessUnavailable)
    );
    assert_eq!(state, before);

    let provider_secret = SecretKey::from_bytes(&[99; 32]);
    let configured_provider = match state.provider_policy().mode() {
        krikos_identity::ProviderMode::LocalOnly => panic!("fixture uses replicated providers"),
        krikos_identity::ProviderMode::Replicated(policy) => policy.providers()[0].clone(),
    };
    let provider_signer = TestProviderSigner(provider_secret);
    let mut provider_log =
        MemoryTransparencyLog::new(configured_provider, typed_id::<ProviderLogId>(0x8d));
    let observed_at = Timestamp::from_unix_millis(200);
    let admission =
        verify_guardian_recovery_intent_admission(&state, &begin_body, observed_at).unwrap();
    assert!(
        provider_log
            .append(
                admission.clone(),
                Timestamp::from_unix_millis(201),
                &provider_signer,
            )
            .is_err()
    );
    assert_eq!(provider_log.tree_size().unwrap(), 0);
    let initial_receipt = provider_log
        .append(admission, observed_at, &provider_signer)
        .unwrap();
    let begin_proposal_id = begin_body.proposal_id().unwrap();
    assert_eq!(
        initial_receipt.entry().subject(),
        ProviderLogSubject::EventIntent(begin_proposal_id)
    );

    let checkpoint_id = typed_id::<CheckpointId>(0x44);
    let freshness_receipts = ProviderReceipts::new(vec![provider_receipt(
        &state,
        ProviderLogSubject::Checkpoint(checkpoint_id),
        200,
        200,
        0x8a,
    )])
    .unwrap();
    let begin_evidence = AdmissionEvidence::new(
        begin_proposal_id,
        checkpoint_id,
        state.provider_policy_id(),
        FreshnessEvidence::provider_quorum(
            checkpoint_id,
            state.provider_policy_id(),
            freshness_receipts,
        )
        .unwrap(),
        DelayEvidence::guardian_recovery(
            state.provider_policy_id(),
            ProviderQuorum::new(1).unwrap(),
            ProviderReceipts::new(vec![initial_receipt.clone()]).unwrap(),
        )
        .unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let begin = krikos_identity::AuthorizedEvent::new(
        begin_body,
        begin_evidence,
        ControllerApprovals::new(Vec::new()).unwrap(),
    )
    .unwrap();
    state.validate_and_apply(&begin).unwrap();
    assert_eq!(state.lifecycle(), ProjectionLifecycle::RecoveryPending);

    let cancel_observed_at = Timestamp::from_unix_millis(205);
    let cancel_guardian_body = GuardianApprovalBody::try_new(
        ProtocolVersion::V1,
        state.account_id(),
        recovery_id,
        GuardianApprovalDecision::Cancel,
        guardian_grant_id,
        state.epoch(),
        cancel_observed_at,
        Extensions::default(),
    )
    .unwrap();
    let cancel_guardian_signature =
        guardian_secret.sign(&cancel_guardian_body.signing_bytes().unwrap());
    let cancel_opening = GuardianGrantOpening::try_new(
        ProtocolVersion::V1,
        guardian_grant(),
        BlindingSecret::try_new(blinding_bytes).unwrap(),
        root,
        u16::try_from(proof.leaf_index()).unwrap(),
        proof.audit_path().to_vec(),
        Extensions::default(),
    )
    .unwrap();
    let cancel_guardian_approval = SignedGuardianApproval::try_new(
        cancel_guardian_body,
        cancel_opening,
        ProtocolSignature::ed25519(cancel_guardian_signature.to_bytes()),
    )
    .unwrap();
    let cancel_threshold = RecoveryThresholdEvidence::guardian_approvals(
        state.recovery_policy_id(),
        state.recovery_policy().policy_version(),
        GuardianApprovalSet::try_new(vec![cancel_guardian_approval]).unwrap(),
    )
    .unwrap();
    let cancel_freshness = FreshnessEvidence::provider_quorum(
        checkpoint_id,
        state.provider_policy_id(),
        ProviderReceipts::new(vec![provider_receipt(
            &state,
            ProviderLogSubject::Checkpoint(checkpoint_id),
            200,
            205,
            0x90,
        )])
        .unwrap(),
    )
    .unwrap();
    let cancel_operation = AccountOperation::CancelRecovery(
        CancelRecovery::try_new(
            ProtocolVersion::V1,
            recovery_id,
            cancel_threshold,
            cancel_freshness.clone(),
            Extensions::default(),
        )
        .unwrap(),
    );
    let cancel_body = EventBody::new(
        state.account_id(),
        state.sequence().checked_next().unwrap(),
        state.epoch().checked_next().unwrap(),
        EventPredecessors::events(state.heads().to_vec()).unwrap(),
        cancel_operation,
        cancel_observed_at,
        [0x90; 16],
        Extensions::default(),
    )
    .unwrap();
    assert_eq!(
        verify_guardian_recovery_intent_admission(
            &state,
            &cancel_body,
            Timestamp::from_unix_millis(204),
        ),
        Err(IdentityError::StaleEvidence)
    );
    let cancel_admission =
        verify_guardian_recovery_intent_admission(&state, &cancel_body, cancel_observed_at)
            .unwrap();
    let cancel_receipt = provider_log
        .append(cancel_admission, cancel_observed_at, &provider_signer)
        .unwrap();
    let cancel_proposal_id = cancel_body.proposal_id().unwrap();
    assert_eq!(
        cancel_receipt.entry().subject(),
        ProviderLogSubject::EventIntent(cancel_proposal_id)
    );
    assert_eq!(
        AdmissionEvidence::new(
            cancel_proposal_id,
            checkpoint_id,
            state.provider_policy_id(),
            cancel_freshness.clone(),
            DelayEvidence::guardian_recovery(
                state.provider_policy_id(),
                ProviderQuorum::new(1).unwrap(),
                ProviderReceipts::new(vec![initial_receipt.clone()]).unwrap(),
            )
            .unwrap(),
            Extensions::default(),
        ),
        Err(IdentityError::InvalidRelationship {
            resource: "admission delayed proposal",
        })
    );

    let unrelated_checkpoint_only = AdmissionEvidence::new(
        cancel_proposal_id,
        checkpoint_id,
        state.provider_policy_id(),
        cancel_freshness.clone(),
        DelayEvidence::none(),
        Extensions::default(),
    )
    .unwrap();
    let unrelated_checkpoint_only = krikos_identity::AuthorizedEvent::new(
        cancel_body.clone(),
        unrelated_checkpoint_only,
        ControllerApprovals::new(Vec::new()).unwrap(),
    )
    .unwrap();
    let mut cancelled = state.clone();
    let before_cancel = cancelled.clone();
    assert_eq!(
        cancelled.validate_and_apply(&unrelated_checkpoint_only),
        Err(IdentityError::FreshnessUnavailable)
    );
    assert_eq!(cancelled, before_cancel);

    let cancel_evidence = AdmissionEvidence::new(
        cancel_proposal_id,
        checkpoint_id,
        state.provider_policy_id(),
        cancel_freshness,
        DelayEvidence::guardian_recovery(
            state.provider_policy_id(),
            ProviderQuorum::new(1).unwrap(),
            ProviderReceipts::new(vec![cancel_receipt]).unwrap(),
        )
        .unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let cancel = krikos_identity::AuthorizedEvent::new(
        cancel_body,
        cancel_evidence,
        ControllerApprovals::new(Vec::new()).unwrap(),
    )
    .unwrap();
    cancelled.validate_and_apply(&cancel).unwrap();
    assert_eq!(cancelled.lifecycle(), ProjectionLifecycle::Active);

    let build_finalize =
        |state: &AccountState, intent_receipt: InclusionReceipt, finalized_at: u64, nonce: u8| {
            let delay_anchor = RecoveryDelayAnchor::try_new(
                ProtocolVersion::V1,
                state.account_id(),
                recovery_id,
                begin_proposal_id,
                state.provider_policy_id(),
                ProviderQuorum::new(1).unwrap(),
                ProviderReceipts::new(vec![intent_receipt]).unwrap(),
                Extensions::default(),
            )
            .unwrap();
            let finalize = AccountOperation::FinalizeRecovery(
                FinalizeRecovery::try_new(
                    ProtocolVersion::V1,
                    recovery_id,
                    delay_anchor,
                    Timestamp::from_unix_millis(finalized_at),
                    Extensions::default(),
                )
                .unwrap(),
            );
            let body = EventBody::new(
                state.account_id(),
                state.sequence().checked_next().unwrap(),
                state.epoch().checked_next().unwrap(),
                EventPredecessors::events(state.heads().to_vec()).unwrap(),
                finalize,
                Timestamp::from_unix_millis(finalized_at),
                [nonce; 16],
                Extensions::default(),
            )
            .unwrap();
            authorize_body_without_controller_approvals_with_freshness(
                state,
                body,
                FreshnessEvidence::provider_quorum(
                    checkpoint_id,
                    state.provider_policy_id(),
                    ProviderReceipts::new(vec![provider_receipt(
                        state,
                        ProviderLogSubject::Checkpoint(checkpoint_id),
                        200,
                        finalized_at,
                        nonce,
                    )])
                    .unwrap(),
                )
                .unwrap(),
            )
        };
    let intent_receipt_209 = provider_log
        .observe(
            initial_receipt.leaf_index(),
            Timestamp::from_unix_millis(209),
            &provider_signer,
        )
        .unwrap();
    let too_early = build_finalize(&state, intent_receipt_209, 209, 0x8e);
    let pending = state.clone();
    assert_eq!(
        state.validate_and_apply(&too_early),
        Err(IdentityError::DelayNotElapsed)
    );
    assert_eq!(state, pending);

    let intent_receipt_210 = provider_log
        .observe(
            initial_receipt.leaf_index(),
            Timestamp::from_unix_millis(210),
            &provider_signer,
        )
        .unwrap();
    let finalize = build_finalize(&state, intent_receipt_210, 210, 0x8f);
    state.validate_and_apply(&finalize).unwrap();
    assert_eq!(state.lifecycle(), ProjectionLifecycle::Active);
}

#[test]
fn recovery_cannot_reintroduce_a_revoked_controller_signing_key_under_a_new_id() {
    let (genesis, signer) = fixture();
    let revoked_secret = SecretKey::from_bytes(&[0xc1; 32]);
    let mut state = AccountState::from_genesis(&genesis).unwrap();
    let added_descriptor = controller(&revoked_secret, 1);
    let revoked_id = added_descriptor.id().unwrap();
    let add = authorized_event(
        &state,
        AccountOperation::AddController(added_descriptor),
        Epoch::new(1),
        0xc1,
        &signer,
    );
    state.validate_and_apply(&add).unwrap();
    let remove = authorized_event(
        &state,
        AccountOperation::RemoveController(revoked_id),
        Epoch::new(2),
        0xc2,
        &signer,
    );
    state.validate_and_apply(&remove).unwrap();
    assert_eq!(state.revoked_controllers().len(), 1);

    let replacement_with_new_id = controller(&revoked_secret, 2);
    assert_ne!(replacement_with_new_id.id().unwrap(), revoked_id);
    let plan = RecoveryAuthorityPlan::try_new(
        ProtocolVersion::V1,
        state.account_id(),
        typed_id::<CheckpointId>(0x44),
        state.heads()[0],
        state.recovery_policy_id(),
        state.recovery_policy().policy_version(),
        [0xc3; 32],
        vec![controller(&signer, 1), replacement_with_new_id],
        state.control_policy().clone(),
        state.recovery_policy().clone(),
        Vec::new(),
        Timestamp::from_unix_millis(1_000),
        Extensions::default(),
    )
    .unwrap();
    let proposal =
        RecoveryProposal::try_new(ProtocolVersion::V1, plan, Extensions::default()).unwrap();
    let recovery_id = proposal.recovery_id().unwrap();
    let begin = BeginRecovery::try_new(
        ProtocolVersion::V1,
        proposal,
        RecoveryThresholdEvidence::controller_policy(
            state.recovery_policy_id(),
            state.recovery_policy().policy_version(),
        ),
        Extensions::default(),
    )
    .unwrap();
    let begin = authorized_event(
        &state,
        AccountOperation::BeginRecovery(begin),
        Epoch::new(3),
        0xc3,
        &signer,
    );
    let begin_proposal_id = begin.body().proposal_id().unwrap();
    state.validate_and_apply(&begin).unwrap();

    let anchor = RecoveryDelayAnchor::try_new(
        ProtocolVersion::V1,
        state.account_id(),
        recovery_id,
        begin_proposal_id,
        state.provider_policy_id(),
        ProviderQuorum::new(1).unwrap(),
        ProviderReceipts::new(vec![recovery_provider_receipt(
            &state,
            begin_proposal_id,
            100,
        )])
        .unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let finalize = AccountOperation::FinalizeRecovery(
        FinalizeRecovery::try_new(
            ProtocolVersion::V1,
            recovery_id,
            anchor,
            Timestamp::from_unix_millis(110),
            Extensions::default(),
        )
        .unwrap(),
    );
    let body = EventBody::new(
        state.account_id(),
        state.sequence().checked_next().unwrap(),
        Epoch::new(4),
        EventPredecessors::events(state.heads().to_vec()).unwrap(),
        finalize,
        Timestamp::from_unix_millis(110),
        [0xc4; 16],
        Extensions::default(),
    )
    .unwrap();
    let checkpoint_id = typed_id::<CheckpointId>(0x44);
    let completion = ProviderReceipts::new(vec![provider_receipt(
        &state,
        ProviderLogSubject::Checkpoint(checkpoint_id),
        100,
        110,
        0xc4,
    )])
    .unwrap();
    let finalize = authorize_body_without_controller_approvals_with_freshness(
        &state,
        body,
        FreshnessEvidence::provider_quorum(checkpoint_id, state.provider_policy_id(), completion)
            .unwrap(),
    );
    let before = state.clone();
    assert_eq!(
        state.validate_and_apply(&finalize),
        Err(IdentityError::DuplicateSigningKey)
    );
    assert_eq!(state, before);
}

#[test]
fn recovery_cannot_rebind_an_active_signing_key_to_a_new_controller_id() {
    let (genesis, signer) = fixture();
    let mut state = AccountState::from_genesis(&genesis).unwrap();
    let add = authorized_event(
        &state,
        AccountOperation::AddController(controller(&SecretKey::from_bytes(&[0xc5; 32]), 1)),
        Epoch::new(1),
        0xc5,
        &signer,
    );
    state.validate_and_apply(&add).unwrap();

    let original_id = controller(&signer, 1).id().unwrap();
    let rebound = controller(&signer, 2);
    assert_ne!(rebound.id().unwrap(), original_id);
    let plan = RecoveryAuthorityPlan::try_new(
        ProtocolVersion::V1,
        state.account_id(),
        typed_id::<CheckpointId>(0x44),
        state.heads()[0],
        state.recovery_policy_id(),
        state.recovery_policy().policy_version(),
        [0xc6; 32],
        vec![rebound],
        state.control_policy().clone(),
        state.recovery_policy().clone(),
        Vec::new(),
        Timestamp::from_unix_millis(1_000),
        Extensions::default(),
    )
    .unwrap();
    let proposal =
        RecoveryProposal::try_new(ProtocolVersion::V1, plan, Extensions::default()).unwrap();
    let recovery_id = proposal.recovery_id().unwrap();
    let begin = AccountOperation::BeginRecovery(
        BeginRecovery::try_new(
            ProtocolVersion::V1,
            proposal,
            RecoveryThresholdEvidence::controller_policy(
                state.recovery_policy_id(),
                state.recovery_policy().policy_version(),
            ),
            Extensions::default(),
        )
        .unwrap(),
    );
    let begin = authorized_event(
        &state,
        begin,
        state.epoch().checked_next().unwrap(),
        0xc6,
        &signer,
    );
    let begin_proposal_id = begin.body().proposal_id().unwrap();
    state.validate_and_apply(&begin).unwrap();

    let finalize = finalize_recovery_event(&state, recovery_id, begin_proposal_id, 0xc7);
    let before = state.clone();
    assert_eq!(
        state.validate_and_apply(&finalize),
        Err(IdentityError::DuplicateSigningKey)
    );
    assert_eq!(state, before);
}

#[test]
fn dual_suite_checkpoint_requires_complete_old_and_new_controller_signatures() {
    let (genesis, original_secret) = fixture();
    let migrated_secret = SecretKey::from_bytes(&[0xcf; 32]);
    let mut state = AccountState::from_genesis(&genesis).unwrap();
    let original_suite = CryptoSuiteDescriptor::v1().unwrap();
    let migrated_suite = in_place_suite(2);
    let controller_id = state.active_controllers()[0].id();

    let (begin, migration_id) = begin_migration_event(
        &state,
        &original_suite,
        &original_secret,
        migrated_suite.clone(),
        &migrated_secret,
        0xcf,
    );
    let begin_event_id = begin.event_id().unwrap();
    state.validate_and_apply(&begin).unwrap();
    let activate = authorized_event_with_crypto_keys(
        &state,
        AccountOperation::ActivateCryptoMigration(
            ActivateCryptoMigration::try_new(
                ProtocolVersion::V1,
                migration_id,
                begin_event_id,
                Extensions::default(),
            )
            .unwrap(),
        ),
        state.epoch().checked_next().unwrap(),
        0xd0,
        controller_id,
        &[(&original_suite, &original_secret, false)],
    );
    state.validate_and_apply(&activate).unwrap();
    assert_eq!(state.lifecycle(), ProjectionLifecycle::MigrationDual);

    let body = build_checkpoint_body(&state, Timestamp::from_unix_millis(300)).unwrap();
    let incomplete = signed_checkpoint_with_crypto_keys(
        body.clone(),
        controller_id,
        &[(&original_suite, &original_secret, false)],
    );
    let before = state.clone();
    assert_eq!(
        verify_checkpoint(&state, &incomplete, None),
        Err(IdentityError::InvalidSignature)
    );
    assert_eq!(state, before);

    let complete = signed_checkpoint_with_crypto_keys(
        body,
        controller_id,
        &[
            (&original_suite, &original_secret, false),
            (&migrated_suite, &migrated_secret, true),
        ],
    );
    let verified = verify_checkpoint(&state, &complete, None).unwrap();
    assert_eq!(verified.checkpoint_id(), complete.checkpoint_id().unwrap());
    assert_eq!(state, before);
}

#[test]
fn post_migration_controller_additions_receive_current_suite_verification_keys() {
    let (genesis, original_secret) = fixture();
    let migrated_secret = SecretKey::from_bytes(&[0xd0; 32]);
    let mut state = AccountState::from_genesis(&genesis).unwrap();
    let migrated_suite =
        migrate_to_in_place_ed25519_suite(&mut state, &original_secret, &migrated_secret);
    assert_eq!(state.lifecycle(), ProjectionLifecycle::Active);

    let original_controller_id = state.active_controllers()[0].id();
    let added_secret = SecretKey::from_bytes(&[0xd4; 32]);
    let added_descriptor = controller(&added_secret, 1);
    let added_controller_id = added_descriptor.id().unwrap();
    let add = authorized_event_with_crypto_keys(
        &state,
        AccountOperation::AddController(added_descriptor),
        state.epoch().checked_next().unwrap(),
        0xd4,
        original_controller_id,
        &[(&migrated_suite, &migrated_secret, true)],
    );
    state.validate_and_apply(&add).unwrap();

    let remove_original = authorized_event_with_crypto_keys(
        &state,
        AccountOperation::RemoveController(original_controller_id),
        state.epoch().checked_next().unwrap(),
        0xd5,
        added_controller_id,
        &[(&migrated_suite, &added_secret, true)],
    );
    state.validate_and_apply(&remove_original).unwrap();
    assert_eq!(state.active_controllers().len(), 1);
    assert_eq!(state.active_controllers()[0].id(), added_controller_id);
}

#[test]
fn retired_crypto_suites_and_keys_are_permanent_tombstones() {
    let (genesis, original_secret) = fixture();
    let mut state = AccountState::from_genesis(&genesis).unwrap();
    let v1 = CryptoSuiteDescriptor::v1().unwrap();
    let suite2 = in_place_suite(2);
    let suite2_secret = SecretKey::from_bytes(&[0x42; 32]);
    complete_in_place_migration(
        &mut state,
        &v1,
        &original_secret,
        &suite2,
        &suite2_secret,
        0x41,
    );

    let downgrade_secret = SecretKey::from_bytes(&[0x43; 32]);
    let (downgrade, _) = begin_migration_event(
        &state,
        &suite2,
        &suite2_secret,
        v1.clone(),
        &downgrade_secret,
        0x44,
    );
    let before_downgrade = state.clone();
    assert_eq!(
        state.validate_and_apply(&downgrade),
        Err(IdentityError::InvalidRelationship {
            resource: "retired cryptographic suite reuse"
        })
    );
    assert_eq!(state, before_downgrade);

    let suite3 = in_place_suite(3);
    let suite3_secret = SecretKey::from_bytes(&[0x45; 32]);
    complete_in_place_migration(
        &mut state,
        &suite2,
        &suite2_secret,
        &suite3,
        &suite3_secret,
        0x45,
    );

    let suite4 = in_place_suite(4);
    let (reused_retired_key, _) = begin_migration_event(
        &state,
        &suite3,
        &suite3_secret,
        suite4,
        &suite2_secret,
        0x48,
    );
    let before_reuse = state.clone();
    assert_eq!(
        state.validate_and_apply(&reused_retired_key),
        Err(IdentityError::DuplicateSigningKey)
    );
    assert_eq!(state, before_reuse);

    let controller_id = state.active_controllers()[0].id();
    let authorize_reused_device = authorized_event_with_crypto_keys(
        &state,
        AccountOperation::AuthorizeDevice(device_authorization(
            device_descriptor(&suite2_secret, 0x49, &SecretKey::from_bytes(&[0x4a; 32])),
            state.epoch().checked_next().unwrap(),
        )),
        state.epoch().checked_next().unwrap(),
        0x49,
        controller_id,
        &[(&suite3, &suite3_secret, true)],
    );
    assert_eq!(
        state.validate_and_apply(&authorize_reused_device),
        Err(IdentityError::InvalidRelationship {
            resource: "device/cryptographic key tombstone separation"
        })
    );
    assert_eq!(state, before_reuse);

    let add_reused_controller = authorized_event_with_crypto_keys(
        &state,
        AccountOperation::AddController(controller(&suite2_secret, 1)),
        state.epoch().checked_next().unwrap(),
        0x4a,
        controller_id,
        &[(&suite3, &suite3_secret, true)],
    );
    assert_eq!(
        state.validate_and_apply(&add_reused_controller),
        Err(IdentityError::DuplicateSigningKey)
    );
    assert_eq!(state, before_reuse);
}

#[test]
fn recovery_fails_closed_under_a_migrated_stable_suite() {
    let (genesis, original_secret) = fixture();
    let migrated_secret = SecretKey::from_bytes(&[0xe0; 32]);
    let mut state = AccountState::from_genesis(&genesis).unwrap();
    let migrated_suite =
        migrate_to_in_place_ed25519_suite(&mut state, &original_secret, &migrated_secret);
    let controller_id = state.active_controllers()[0].id();

    let plan = RecoveryAuthorityPlan::try_new(
        ProtocolVersion::V1,
        state.account_id(),
        typed_id::<CheckpointId>(0x44),
        state.heads()[0],
        state.recovery_policy_id(),
        state.recovery_policy().policy_version(),
        [0xe1; 32],
        vec![state.active_controllers()[0].descriptor().clone()],
        state.control_policy().clone(),
        state.recovery_policy().clone(),
        Vec::new(),
        Timestamp::from_unix_millis(1_000),
        Extensions::default(),
    )
    .unwrap();
    let proposal =
        RecoveryProposal::try_new(ProtocolVersion::V1, plan, Extensions::default()).unwrap();
    let begin = AccountOperation::BeginRecovery(
        BeginRecovery::try_new(
            ProtocolVersion::V1,
            proposal,
            RecoveryThresholdEvidence::controller_policy(
                state.recovery_policy_id(),
                state.recovery_policy().policy_version(),
            ),
            Extensions::default(),
        )
        .unwrap(),
    );
    let begin = authorized_event_with_crypto_keys(
        &state,
        begin,
        state.epoch().checked_next().unwrap(),
        0xe1,
        controller_id,
        &[(&migrated_suite, &migrated_secret, true)],
    );
    let before = state.clone();
    assert_eq!(
        state.validate_and_apply(&begin),
        Err(IdentityError::UnsupportedPolicyFeature {
            feature: "recovery under a migrated cryptographic suite",
        })
    );
    assert_eq!(state, before);
}

#[test]
fn identical_body_replay_is_idempotent_and_not_a_fork() {
    let (genesis, signer) = fixture();
    let mut state = AccountState::from_genesis(&genesis).unwrap();
    let added_secret = SecretKey::from_bytes(&[8; 32]);
    let event = authorized_event(
        &state,
        AccountOperation::AddController(controller(&added_secret, 1)),
        Epoch::new(1),
        4,
        &signer,
    );
    let event_id = event.event_id().unwrap();

    assert_eq!(
        state.validate_and_apply(&event).unwrap().disposition(),
        ApplyDisposition::Applied
    );
    let stable = state.clone();
    let replay = state.validate_and_apply(&event).unwrap();
    assert_eq!(replay.disposition(), ApplyDisposition::Replay);
    assert_eq!(replay.event_id(), event_id);
    assert_eq!(state, stable);
    assert_eq!(state.lifecycle(), ProjectionLifecycle::Active);
}

#[test]
fn valid_conflicting_bodies_are_retained_without_branch_selection() {
    let (genesis, signer) = fixture();
    let mut state = AccountState::from_genesis(&genesis).unwrap();
    let base = state.clone();
    let left = authorized_event(
        &base,
        AccountOperation::AddController(controller(&SecretKey::from_bytes(&[8; 32]), 1)),
        Epoch::new(1),
        5,
        &signer,
    );
    let right = authorized_event(
        &base,
        AccountOperation::AddController(controller(&SecretKey::from_bytes(&[9; 32]), 1)),
        Epoch::new(1),
        6,
        &signer,
    );
    state.validate_and_apply(&left).unwrap();

    let outcome = state.validate_and_apply(&right).unwrap();
    let mut expected = vec![left.event_id().unwrap(), right.event_id().unwrap()];
    expected.sort_unstable();
    assert_eq!(outcome.disposition(), ApplyDisposition::ForkDetected);
    assert_eq!(state.lifecycle(), ProjectionLifecycle::Forked);
    assert_eq!(state.heads(), expected);
    assert_eq!(state.active_controllers().len(), 1);
}

#[test]
fn fork_branches_accept_descendants_replace_tips_and_converge_by_arrival_order() {
    let (genesis, signer) = fixture();
    let base = AccountState::from_genesis(&genesis).unwrap();
    let left = authorized_event(
        &base,
        AccountOperation::AddController(controller(&SecretKey::from_bytes(&[0x81; 32]), 1)),
        Epoch::new(1),
        0x81,
        &signer,
    );
    let right = authorized_event(
        &base,
        AccountOperation::AddController(controller(&SecretKey::from_bytes(&[0x82; 32]), 1)),
        Epoch::new(1),
        0x82,
        &signer,
    );

    let mut left_projection = base.clone();
    left_projection.validate_and_apply(&left).unwrap();
    let left_descendant = authorized_event(
        &left_projection,
        AccountOperation::ChangeProviderPolicy(
            ProviderPolicy::local_only(ProviderPolicyVersion::new(1), Extensions::default())
                .unwrap(),
        ),
        Epoch::new(2),
        0x83,
        &signer,
    );

    let mut late_conflict = base.clone();
    late_conflict.validate_and_apply(&left).unwrap();
    late_conflict.validate_and_apply(&left_descendant).unwrap();
    late_conflict.validate_and_apply(&right).unwrap();

    let mut fork_first = base.clone();
    fork_first.validate_and_apply(&left).unwrap();
    fork_first.validate_and_apply(&right).unwrap();
    fork_first.validate_and_apply(&left_descendant).unwrap();
    assert_eq!(fork_first, late_conflict);
    let mut expected_heads = vec![
        left_descendant.event_id().unwrap(),
        right.event_id().unwrap(),
    ];
    expected_heads.sort_unstable();
    assert_eq!(fork_first.heads(), expected_heads);
    assert_eq!(fork_first.sequence(), Sequence::new(2));

    let mut right_projection = base;
    right_projection.validate_and_apply(&right).unwrap();
    let right_descendant = authorized_event(
        &right_projection,
        AccountOperation::ChangeProviderPolicy(
            ProviderPolicy::local_only(ProviderPolicyVersion::new(1), Extensions::default())
                .unwrap(),
        ),
        Epoch::new(2),
        0x84,
        &signer,
    );
    right_projection
        .validate_and_apply(&right_descendant)
        .unwrap();
    let right_grandchild = authorized_event(
        &right_projection,
        AccountOperation::ChangeProviderPolicy(
            ProviderPolicy::local_only(ProviderPolicyVersion::new(2), Extensions::default())
                .unwrap(),
        ),
        Epoch::new(3),
        0x85,
        &signer,
    );
    fork_first.validate_and_apply(&right_descendant).unwrap();
    fork_first.validate_and_apply(&right_grandchild).unwrap();
    let mut unequal_heads = vec![
        left_descendant.event_id().unwrap(),
        right_grandchild.event_id().unwrap(),
    ];
    unequal_heads.sort_unstable();
    assert_eq!(fork_first.heads(), unequal_heads);
    assert_eq!(fork_first.sequence(), Sequence::new(3));
}

#[test]
fn frozen_epoch_table_covers_every_v1_operation_kind() {
    let advancing = [
        OperationKind::AuthorizeDevice,
        OperationKind::UpdateDeviceAuthorization,
        OperationKind::SuspendDevice,
        OperationKind::ReinstateDevice,
        OperationKind::RevokeDevice,
        OperationKind::RotateDeviceKeys,
        OperationKind::AddController,
        OperationKind::RemoveController,
        OperationKind::ChangeControlPolicy,
        OperationKind::ChangeRecoveryPolicy,
        OperationKind::ChangeProviderPolicy,
        OperationKind::BeginRecovery,
        OperationKind::VetoRecovery,
        OperationKind::CancelRecovery,
        OperationKind::FinalizeRecovery,
        OperationKind::ResolveFork,
        OperationKind::ActivateCryptoMigration,
        OperationKind::UpgradeProtocol,
        OperationKind::RetireAccount,
    ];
    for kind in advancing {
        assert_eq!(
            AccountState::operation_kind_advances_epoch(kind),
            Some(true)
        );
    }
    assert_eq!(
        AccountState::operation_kind_advances_epoch(OperationKind::UpdateDeviceMetadata),
        Some(false)
    );
    assert_eq!(
        AccountState::operation_kind_advances_epoch(OperationKind::BeginCryptoMigration),
        Some(false)
    );
    assert_eq!(
        AccountState::operation_kind_advances_epoch(OperationKind::RetireCryptoSuite),
        None
    );
    assert_eq!(advancing.len() + 3, 22);

    let (genesis, _) = fixture();
    let state = AccountState::from_genesis(&genesis).unwrap();
    let abort = AccountOperation::RetireCryptoSuite(
        RetireCryptoSuite::try_new(
            ProtocolVersion::V1,
            typed_id::<CryptoMigrationId>(0x70),
            RetireCryptoSuiteMode::AbortCandidate,
            typed_id::<EventId>(0x71),
            None,
            Extensions::default(),
        )
        .unwrap(),
    );
    let retire_previous = AccountOperation::RetireCryptoSuite(
        RetireCryptoSuite::try_new(
            ProtocolVersion::V1,
            typed_id::<CryptoMigrationId>(0x72),
            RetireCryptoSuiteMode::RetirePrevious,
            typed_id::<EventId>(0x73),
            None,
            Extensions::default(),
        )
        .unwrap(),
    );
    assert_eq!(state.expected_epoch_for(&abort).unwrap(), Epoch::GENESIS);
    assert_eq!(
        state.expected_epoch_for(&retire_previous).unwrap(),
        Epoch::new(1)
    );
}

#[test]
fn late_conflict_at_a_retained_ancestor_reopens_a_fork() {
    let (genesis, signer) = fixture();
    let mut state = AccountState::from_genesis(&genesis).unwrap();
    let baseline = authorized_event(
        &state,
        AccountOperation::AddController(controller(&SecretKey::from_bytes(&[8; 32]), 1)),
        Epoch::new(1),
        20,
        &signer,
    );
    state.validate_and_apply(&baseline).unwrap();
    let divergence = state.clone();

    let accepted = authorized_event(
        &state,
        AccountOperation::ChangeProviderPolicy(
            ProviderPolicy::local_only(ProviderPolicyVersion::new(1), Extensions::default())
                .unwrap(),
        ),
        Epoch::new(2),
        21,
        &signer,
    );
    state.validate_and_apply(&accepted).unwrap();
    let descendant = authorized_event(
        &state,
        AccountOperation::ChangeProviderPolicy(
            ProviderPolicy::local_only(ProviderPolicyVersion::new(2), Extensions::default())
                .unwrap(),
        ),
        Epoch::new(3),
        22,
        &signer,
    );
    state.validate_and_apply(&descendant).unwrap();

    let late = authorized_event(
        &divergence,
        AccountOperation::ChangeProviderPolicy(
            ProviderPolicy::local_only(ProviderPolicyVersion::new(1), Extensions::default())
                .unwrap(),
        ),
        Epoch::new(2),
        23,
        &signer,
    );
    assert_eq!(
        state.validate_and_apply(&late).unwrap().disposition(),
        ApplyDisposition::ForkDetected
    );
    let mut heads = vec![descendant.event_id().unwrap(), late.event_id().unwrap()];
    heads.sort_unstable();
    assert_eq!(state.heads(), heads);
    assert_eq!(state.lifecycle(), ProjectionLifecycle::Forked);
    assert_eq!(
        state.active_controllers().len(),
        divergence.active_controllers().len()
    );

    let descriptor = ForkDescriptor::try_new(
        ProtocolVersion::V1,
        state.account_id(),
        ForkCommonAncestor::Event(baseline.event_id().unwrap()),
        state.heads().to_vec(),
        Extensions::default(),
    )
    .unwrap();
    let resolution = authorized_event(
        &state,
        AccountOperation::ResolveFork(
            ResolveFork::try_new(
                ProtocolVersion::V1,
                descriptor,
                late.event_id().unwrap(),
                Vec::new(),
                Vec::new(),
                Extensions::default(),
            )
            .unwrap(),
        ),
        Epoch::new(4),
        24,
        &signer,
    );
    state.validate_and_apply(&resolution).unwrap();
    assert_eq!(state.lifecycle(), ProjectionLifecycle::Active);
    assert_eq!(state.epoch(), Epoch::new(4));
    assert_eq!(
        state.validate_and_apply(&resolution).unwrap().disposition(),
        ApplyDisposition::Replay
    );
}

#[test]
fn first_event_fork_is_resolvable_from_the_genesis_anchor() {
    let (genesis, signer) = fixture();
    let mut state = AccountState::from_genesis(&genesis).unwrap();
    let genesis_state = state.clone();
    let left = authorized_event(
        &genesis_state,
        AccountOperation::AddController(controller(&SecretKey::from_bytes(&[0xf1; 32]), 1)),
        Epoch::new(1),
        0xf1,
        &signer,
    );
    let right = authorized_event(
        &genesis_state,
        AccountOperation::AddController(controller(&SecretKey::from_bytes(&[0xf2; 32]), 1)),
        Epoch::new(1),
        0xf2,
        &signer,
    );
    state.validate_and_apply(&left).unwrap();
    assert_eq!(
        state.validate_and_apply(&right).unwrap().disposition(),
        ApplyDisposition::ForkDetected
    );
    let fork = ForkDescriptor::try_new(
        ProtocolVersion::V1,
        state.account_id(),
        ForkCommonAncestor::Genesis(state.genesis_anchor()),
        state.heads().to_vec(),
        Extensions::default(),
    )
    .unwrap();
    let resolution = authorized_event(
        &state,
        AccountOperation::ResolveFork(
            ResolveFork::try_new(
                ProtocolVersion::V1,
                fork,
                left.event_id().unwrap(),
                Vec::new(),
                Vec::new(),
                Extensions::default(),
            )
            .unwrap(),
        ),
        Epoch::new(2),
        0xf3,
        &signer,
    );
    state.validate_and_apply(&resolution).unwrap();
    assert_eq!(state.lifecycle(), ProjectionLifecycle::Active);
    assert_eq!(state.epoch(), Epoch::new(2));
    assert_eq!(state.active_controllers().len(), 2);
}

#[test]
fn explicit_fork_resolution_selects_a_branch_and_competing_resolution_reopens() {
    let (genesis, signer) = fixture();
    let mut state = AccountState::from_genesis(&genesis).unwrap();
    let baseline = authorized_event(
        &state,
        AccountOperation::AddController(controller(&SecretKey::from_bytes(&[8; 32]), 1)),
        Epoch::new(1),
        30,
        &signer,
    );
    let common_ancestor = baseline.event_id().unwrap();
    state.validate_and_apply(&baseline).unwrap();
    let divergence = state.clone();
    let left = authorized_event(
        &divergence,
        AccountOperation::ChangeProviderPolicy(
            ProviderPolicy::local_only(ProviderPolicyVersion::new(1), Extensions::default())
                .unwrap(),
        ),
        Epoch::new(2),
        31,
        &signer,
    );
    let right = authorized_event(
        &divergence,
        AccountOperation::ChangeProviderPolicy(
            ProviderPolicy::local_only(ProviderPolicyVersion::new(1), Extensions::default())
                .unwrap(),
        ),
        Epoch::new(2),
        32,
        &signer,
    );
    state.validate_and_apply(&left).unwrap();
    state.validate_and_apply(&right).unwrap();
    let forked = state.clone();
    let descriptor = ForkDescriptor::try_new(
        ProtocolVersion::V1,
        state.account_id(),
        ForkCommonAncestor::Event(common_ancestor),
        state.heads().to_vec(),
        Extensions::default(),
    )
    .unwrap();
    let resolve_left = authorized_event(
        &forked,
        AccountOperation::ResolveFork(
            ResolveFork::try_new(
                ProtocolVersion::V1,
                descriptor.clone(),
                left.event_id().unwrap(),
                Vec::new(),
                Vec::new(),
                Extensions::default(),
            )
            .unwrap(),
        ),
        Epoch::new(3),
        33,
        &signer,
    );
    let resolve_right = authorized_event(
        &forked,
        AccountOperation::ResolveFork(
            ResolveFork::try_new(
                ProtocolVersion::V1,
                descriptor,
                right.event_id().unwrap(),
                Vec::new(),
                Vec::new(),
                Extensions::default(),
            )
            .unwrap(),
        ),
        Epoch::new(3),
        34,
        &signer,
    );
    state.validate_and_apply(&resolve_left).unwrap();
    assert_eq!(state.lifecycle(), ProjectionLifecycle::Active);
    assert_eq!(state.epoch(), Epoch::new(3));
    assert_eq!(
        state
            .validate_and_apply(&resolve_right)
            .unwrap()
            .disposition(),
        ApplyDisposition::ForkDetected
    );
    assert_eq!(state.lifecycle(), ProjectionLifecycle::Forked);
    let mut resolution_heads = vec![
        resolve_left.event_id().unwrap(),
        resolve_right.event_id().unwrap(),
    ];
    resolution_heads.sort_unstable();
    assert_eq!(state.heads(), resolution_heads);
}

#[test]
fn retirement_is_terminal_but_identical_replay_remains_idempotent() {
    let (genesis, signer) = fixture();
    let mut state = AccountState::from_genesis(&genesis).unwrap();
    let retirement = authorized_event(
        &state,
        AccountOperation::RetireAccount(
            RetireAccount::try_new(ProtocolVersion::V1, None, None, Extensions::default()).unwrap(),
        ),
        Epoch::new(1),
        40,
        &signer,
    );
    state.validate_and_apply(&retirement).unwrap();
    assert_eq!(state.lifecycle(), ProjectionLifecycle::Retired);
    assert_eq!(
        state.validate_and_apply(&retirement).unwrap().disposition(),
        ApplyDisposition::Replay
    );

    let later = authorized_event(
        &state,
        AccountOperation::AddController(controller(&SecretKey::from_bytes(&[9; 32]), 1)),
        Epoch::new(2),
        41,
        &signer,
    );
    let before = state.clone();
    assert_eq!(
        state.validate_and_apply(&later),
        Err(IdentityError::AccountRetired)
    );
    assert_eq!(state, before);
}

#[test]
fn generated_linear_history_matches_a_small_reference_model() {
    let (genesis, signer) = fixture();
    let mut state = AccountState::from_genesis(&genesis).unwrap();
    let mut model_sequence = 0_u64;
    let mut model_epoch = 0_u64;
    for version in 1_u64..=32 {
        let event = authorized_event(
            &state,
            AccountOperation::ChangeProviderPolicy(
                ProviderPolicy::local_only(
                    ProviderPolicyVersion::new(version),
                    Extensions::default(),
                )
                .unwrap(),
            ),
            Epoch::new(model_epoch + 1),
            u8::try_from(version).unwrap(),
            &signer,
        );
        let event_id = event.event_id().unwrap();
        state.validate_and_apply(&event).unwrap();
        model_sequence += 1;
        model_epoch += 1;
        assert_eq!(state.sequence(), Sequence::new(model_sequence));
        assert_eq!(state.epoch(), Epoch::new(model_epoch));
        assert_eq!(state.heads(), [event_id]);
        assert_eq!(state.revision_token().heads(), [event_id]);
    }
}

#[test]
fn evicted_lineage_requests_authenticated_history_instead_of_losing_late_branches() {
    let (genesis, signer) = fixture();
    let origin = AccountState::from_genesis(&genesis).unwrap();
    let mut state = origin.clone();
    let mut first_accepted = None;
    for version in 1_u64..=257 {
        let nonce = u8::try_from(((version - 1) % 254) + 1).unwrap();
        let event = authorized_event(
            &state,
            AccountOperation::ChangeProviderPolicy(
                ProviderPolicy::replicated(
                    ProviderPolicyVersion::new(version),
                    state.provider_policy().providers().unwrap().to_vec(),
                    ProviderQuorum::new(1).unwrap(),
                    ProviderQuorum::new(1).unwrap(),
                    DurationMillis::new(1_000),
                    Extensions::default(),
                )
                .unwrap(),
            ),
            Epoch::new(version),
            nonce,
            &signer,
        );
        if version == 1 {
            first_accepted = Some(event.clone());
        }
        state.validate_and_apply(&event).unwrap();
    }

    let alternate = authorized_event(
        &origin,
        AccountOperation::AddController(controller(&SecretKey::from_bytes(&[0x92; 32]), 1)),
        Epoch::new(1),
        0x91,
        &signer,
    );
    let before = state.clone();
    assert_eq!(
        state.validate_and_apply(&alternate),
        Err(IdentityError::HistoricalStateRequired { sequence: 1 })
    );
    assert_eq!(state, before);

    assert!(first_accepted.is_some());
}

#[test]
fn lineage_byte_budget_evicts_validation_snapshots_before_the_event_count_cap() {
    let (genesis, signer) = fixture();
    let origin = AccountState::from_genesis(&genesis).unwrap();
    let mut state = origin.clone();
    let first = authorized_event(
        &state,
        AccountOperation::AddController(large_controller(&SecretKey::from_bytes(&[0x93; 32]))),
        Epoch::new(1),
        0x93,
        &signer,
    );
    state.validate_and_apply(&first).unwrap();
    for version in 1_u64..=80 {
        let event = authorized_event(
            &state,
            AccountOperation::ChangeProviderPolicy(
                ProviderPolicy::local_only(
                    ProviderPolicyVersion::new(version),
                    Extensions::default(),
                )
                .unwrap(),
            ),
            Epoch::new(version + 1),
            u8::try_from(version).unwrap(),
            &signer,
        );
        state.validate_and_apply(&event).unwrap();
    }
    assert!(state.sequence().get() < 256);

    let alternate = authorized_event(
        &origin,
        AccountOperation::AddController(controller(&SecretKey::from_bytes(&[0x94; 32]), 1)),
        Epoch::new(1),
        0x94,
        &signer,
    );
    let before = state.clone();
    assert_eq!(
        state.validate_and_apply(&alternate),
        Err(IdentityError::HistoricalStateRequired { sequence: 1 })
    );
    assert_eq!(state, before);
}

#[test]
fn fork_budget_counts_retained_branch_validation_states_not_only_tip_events() {
    let (genesis, signer) = fixture();
    let mut common = AccountState::from_genesis(&genesis).unwrap();
    let large = authorized_event(
        &common,
        AccountOperation::AddController(large_controller(&SecretKey::from_bytes(&[0x95; 32]))),
        Epoch::new(1),
        0x95,
        &signer,
    );
    common.validate_and_apply(&large).unwrap();
    let left = authorized_event(
        &common,
        AccountOperation::ChangeProviderPolicy(
            ProviderPolicy::local_only(ProviderPolicyVersion::new(1), Extensions::default())
                .unwrap(),
        ),
        Epoch::new(2),
        0x96,
        &signer,
    );
    let right = authorized_event(
        &common,
        AccountOperation::ChangeProviderPolicy(
            ProviderPolicy::local_only(ProviderPolicyVersion::new(1), Extensions::default())
                .unwrap(),
        ),
        Epoch::new(2),
        0x97,
        &signer,
    );
    let mut branch_projection = common.clone();
    branch_projection.validate_and_apply(&left).unwrap();
    let mut forked = common;
    forked.validate_and_apply(&left).unwrap();
    forked.validate_and_apply(&right).unwrap();

    let mut bounded_rejection = None;
    for version in 2_u64..=100 {
        let event = authorized_event(
            &branch_projection,
            AccountOperation::ChangeProviderPolicy(
                ProviderPolicy::local_only(
                    ProviderPolicyVersion::new(version),
                    Extensions::default(),
                )
                .unwrap(),
            ),
            Epoch::new(version + 1),
            u8::try_from(version).unwrap(),
            &signer,
        );
        branch_projection.validate_and_apply(&event).unwrap();
        let before = forked.clone();
        match forked.validate_and_apply(&event) {
            Ok(_) => {}
            Err(error) => {
                assert_eq!(forked, before);
                bounded_rejection = Some(error);
                break;
            }
        }
    }
    assert!(matches!(
        bounded_rejection,
        Some(IdentityError::LimitExceeded {
            resource: "account fork evidence bytes",
            ..
        })
    ));
}
