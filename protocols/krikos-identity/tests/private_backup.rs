use std::{convert::Infallible, fmt};

use krikos_base::SecretKey;
use krikos_identity::{
    AccountGenesis, AccountOperation, AccountState, AdmissionEvidence, AlgorithmSignature,
    ApplicationBackupData, ApplicationDataRestoration, BackupAuthorityBundle, BackupEnvelope,
    BackupPassphrase, CanonicalWire, CheckpointAuthorization, CheckpointBody, CheckpointId,
    ControlPolicy, ControllerApprovalBody, ControllerApprovals, ControllerClass,
    ControllerDescriptor, ControllerKeyId, ControllerScope, ControllerSelector,
    ControllerThreshold, ControllerWeight, CryptoSuiteDescriptor, DelayEvidence, Digest,
    DurationMillis, EventBody, EventPredecessors, Extensions, FreshnessEvidence,
    FreshnessRequirement, HashAlgorithm, IdentityError, KeyedSignature, OperationKind, PolicyRule,
    PrivateArtifactContext, ProviderPolicy, ProviderPolicyVersion, RecoveryAuthority,
    RecoveryPolicy, RecoveryPolicyVersion, RequiredWeight, Sequence, SignedCheckpoint,
    SignedControllerApproval, SigningPublicKey, Timestamp, build_checkpoint_body,
};
use rand_core::{TryCryptoRng, TryRng};

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

fn genesis(signer: &SecretKey) -> AccountGenesis {
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
    AccountGenesis::new(
        [0x12; 32],
        Timestamp::from_unix_millis(1),
        policy,
        vec![controller(signer)],
        recovery,
        ProviderPolicy::local_only(ProviderPolicyVersion::GENESIS, Extensions::default()).unwrap(),
        Extensions::default(),
    )
    .unwrap()
}

fn authorized_event(state: &AccountState, signer: &SecretKey) -> krikos_identity::AuthorizedEvent {
    let operation =
        AccountOperation::AddController(controller(&SecretKey::from_bytes(&[0x13; 32])));
    let predecessors = if state.sequence() == Sequence::GENESIS {
        EventPredecessors::genesis(state.genesis_anchor())
    } else {
        EventPredecessors::events(state.heads().to_vec()).unwrap()
    };
    let body = EventBody::new(
        state.account_id(),
        state.sequence().checked_next().unwrap(),
        state.expected_epoch_for(&operation).unwrap(),
        predecessors,
        operation,
        Timestamp::from_unix_millis(2),
        [0x14; 16],
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
    let approval_body = ControllerApprovalBody::event(
        state.active_controllers()[0].id(),
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

fn authority_fixture() -> (BackupAuthorityBundle, AccountState) {
    let signer = SecretKey::from_bytes(&[0x11; 32]);
    let genesis = genesis(&signer);
    let mut state = AccountState::from_genesis(&genesis).unwrap();
    let event = authorized_event(&state, &signer);
    state.validate_and_apply(&event).unwrap();
    let checkpoint = signed_checkpoint(
        &state,
        &signer,
        build_checkpoint_body(&state, Timestamp::from_unix_millis(99)).unwrap(),
    );
    (
        BackupAuthorityBundle::try_new(genesis, vec![event], checkpoint).unwrap(),
        state,
    )
}

fn context(bundle: &BackupAuthorityBundle) -> PrivateArtifactContext {
    PrivateArtifactContext::try_new(
        bundle.account_id(),
        bundle.checkpoint_id(),
        bundle.account_epoch(),
        None,
        1,
        Extensions::default(),
    )
    .unwrap()
}

struct RepeatingRng(u8);

impl TryRng for RepeatingRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(u32::from(self.0))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(u64::from(self.0))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        destination.fill(self.0);
        Ok(())
    }
}

impl TryCryptoRng for RepeatingRng {}

#[derive(Debug)]
struct RngFailure;

impl fmt::Display for RngFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected entropy failure")
    }
}

impl std::error::Error for RngFailure {}

struct FailedRng;

impl TryRng for FailedRng {
    type Error = RngFailure;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Err(RngFailure)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Err(RngFailure)
    }

    fn try_fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), Self::Error> {
        Err(RngFailure)
    }
}

impl TryCryptoRng for FailedRng {}

#[test]
fn backup_round_trip_validates_authority_and_separates_application_data() {
    let (bundle, expected_state) = authority_fixture();
    let passphrase = BackupPassphrase::try_new(b"correct horse battery staple".to_vec()).unwrap();
    let without_data = BackupEnvelope::seal_with_rng(
        context(&bundle),
        &passphrase,
        &bundle,
        None,
        &mut RepeatingRng(0x61),
    )
    .unwrap();
    let restored = without_data.restore(&passphrase).unwrap();
    assert_eq!(restored.account_authority().state(), &expected_state);
    assert_eq!(
        restored.account_authority().checkpoint_id(),
        bundle.checkpoint_id()
    );
    assert!(matches!(
        restored.application_data(),
        ApplicationDataRestoration::Unavailable
    ));

    let app_data = ApplicationBackupData::try_new(b"wrapped app keys".to_vec()).unwrap();
    let with_data = BackupEnvelope::seal_with_rng(
        context(&bundle),
        &passphrase,
        &bundle,
        Some(&app_data),
        &mut RepeatingRng(0x62),
    )
    .unwrap();
    let restored = with_data.restore(&passphrase).unwrap();
    let ApplicationDataRestoration::Restored(restored_data) = restored.application_data() else {
        panic!("authenticated application backup data must be reported as restored");
    };
    assert_eq!(restored_data.as_bytes(), app_data.as_bytes());
}

#[test]
fn backup_wrong_passphrase_and_corruption_are_uniform() {
    let (bundle, _) = authority_fixture();
    let passphrase = BackupPassphrase::try_new(b"correct horse battery staple".to_vec()).unwrap();
    let wrong = BackupPassphrase::try_new(b"correct horse battery stapler".to_vec()).unwrap();
    let envelope = BackupEnvelope::seal_with_rng(
        context(&bundle),
        &passphrase,
        &bundle,
        None,
        &mut RepeatingRng(0x63),
    )
    .unwrap();
    assert!(matches!(
        envelope.restore(&wrong),
        Err(IdentityError::PrivateArtifactAuthenticationFailed)
    ));

    let mut corrupted = envelope.to_canonical_bytes().unwrap();
    let ciphertext_byte = corrupted
        .len()
        .checked_sub(2)
        .and_then(|index| corrupted.get_mut(index))
        .unwrap();
    *ciphertext_byte ^= 1;
    let corrupted = BackupEnvelope::from_canonical_bytes(&corrupted).unwrap();
    assert!(matches!(
        corrupted.restore(&passphrase),
        Err(IdentityError::PrivateArtifactAuthenticationFailed)
    ));
}

#[test]
fn invalid_authority_and_passphrase_inputs_fail_before_restore() {
    let signer = SecretKey::from_bytes(&[0x11; 32]);
    let genesis = genesis(&signer);
    let state = AccountState::from_genesis(&genesis).unwrap();
    assert!(
        BackupAuthorityBundle::try_new(
            genesis,
            Vec::new(),
            // This placeholder is intentionally unavailable because a genesis-only state cannot
            // produce a valid checkpoint; use the valid fixture's checkpoint to prove mismatch.
            authority_fixture().0.checkpoint().clone(),
        )
        .is_err()
    );
    assert_eq!(state.sequence(), Sequence::GENESIS);

    assert!(matches!(
        BackupPassphrase::try_new(Vec::new()),
        Err(IdentityError::EmptyCollection { .. })
    ));
    assert!(matches!(
        BackupPassphrase::try_new(vec![0; 1025]),
        Err(IdentityError::LimitExceeded { .. })
    ));
    assert_eq!(
        format!(
            "{:?}",
            BackupPassphrase::try_new(b"secret".to_vec()).unwrap()
        ),
        "BackupPassphrase(<redacted>)"
    );

    assert!(matches!(
        ApplicationBackupData::try_new(vec![
            0;
            krikos_identity::limits::MAX_APPLICATION_BACKUP_DATA_BYTES
                + 1
        ]),
        Err(IdentityError::LimitExceeded { .. })
    ));
}

#[test]
fn backup_vector_rejects_version_and_kdf_parameter_substitution_before_restore() {
    let (bundle, _) = authority_fixture();
    let passphrase = BackupPassphrase::try_new(b"correct horse battery staple".to_vec()).unwrap();
    let mut entropy = RepeatingRng(0x64);
    let envelope =
        BackupEnvelope::seal_with_rng(context(&bundle), &passphrase, &bundle, None, &mut entropy)
            .unwrap();
    let encoded = envelope.to_canonical_bytes().unwrap();
    assert_eq!(&encoded[..4], &[1, 2, 1, 19]);
    assert_eq!(
        blake3::hash(&encoded).as_bytes(),
        &[
            0x9e, 0xeb, 0xd1, 0x8a, 0xd7, 0x20, 0xd4, 0x0e, 0x91, 0x99, 0xb9, 0x64, 0x6c, 0x63,
            0x04, 0xc6, 0x9c, 0x93, 0xb0, 0x10, 0xde, 0xbb, 0x7a, 0x5a, 0x5a, 0xbe, 0xfe, 0x45,
            0x18, 0xb1, 0x3d, 0x7e,
        ]
    );

    let mut wrong_version = encoded.clone();
    wrong_version[0] = 2;
    assert!(BackupEnvelope::from_canonical_bytes(&wrong_version).is_err());

    let mut wrong_kdf = encoded;
    wrong_kdf[2] = 2;
    assert!(BackupEnvelope::from_canonical_bytes(&wrong_kdf).is_err());
}

#[test]
fn backup_injected_entropy_failure_is_retryable_and_emits_no_envelope() {
    let (bundle, _) = authority_fixture();
    let passphrase = BackupPassphrase::try_new(b"correct horse battery staple".to_vec()).unwrap();
    assert!(matches!(
        BackupEnvelope::seal_with_rng(context(&bundle), &passphrase, &bundle, None, &mut FailedRng,),
        Err(IdentityError::EntropyUnavailable)
    ));
}
