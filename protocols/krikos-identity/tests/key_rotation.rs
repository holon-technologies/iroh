use std::convert::Infallible;

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use krikos_base::SecretKey;
use krikos_identity::{
    AccountGenesis, AccountOperation, AccountState, AccountStore, ActivateCryptoMigration,
    AdmissionEvidence, AgreementPublicKey, AgreementSecretKey, AlgorithmPublicKey,
    AlgorithmSignature, ApplicationId, BeginCryptoMigration, BeginRecovery, CanonicalWire,
    CheckpointId, ClaimEffects, ControlPolicy, ControllerApprovalBody, ControllerApprovals,
    ControllerClass, ControllerDescriptor, ControllerKeyBinding, ControllerKeyBindingProof,
    ControllerKeyBindingProofSet, ControllerKeyId, ControllerScope, ControllerSelector,
    ControllerThreshold, ControllerWeight, CryptoMigrationBody, CryptoMigrationId,
    CryptoSuiteDescriptor, DelayEvidence, DeviceAuthorization, DeviceClass, DeviceDescriptor,
    DeviceId, Digest, DurationMillis, EndpointPublicKey, Epoch, EventBody, EventIntentApprovalBody,
    EventIntentApprovals, EventPredecessors, Extension, Extensions, FreshnessEvidence,
    FreshnessRequirement, GroupId, GroupKey, GroupKeyDistributionSnapshot, GroupKeyEpoch,
    GroupKeyRotation, GroupKeyWrapHeader, HashAlgorithm, IdentityError, InclusionReceipt,
    KeyWrapNonce, KeyedSignature, LeaseId, MemoryAccountStore, OperationKind, PolicyRule,
    ProjectionEffect, ProjectionLifecycle, ProtocolMajor, ProtocolSignature, ProtocolUpgrade,
    ProtocolVersion, ProviderDescriptor, ProviderHeadBody, ProviderKeyVersion,
    ProviderLogEntryBody, ProviderLogId, ProviderLogSubject, ProviderPolicy, ProviderPolicyVersion,
    ProviderQuorum, ProviderReceipts, RecoveryAuthority, RecoveryAuthorityPlan, RecoveryPolicy,
    RecoveryPolicyVersion, RecoveryProposal, RecoveryThresholdEvidence, RequiredWeight,
    RetireAccount, RevokeDevice, Sequence, SignedControllerApproval, SignedEventIntentApproval,
    SignedProviderHead, SigningPublicKey, SuspendDevice, Timestamp, UpgradeCompatibility,
    WrappedGroupKey, rotate_group_key_with_rng, unwrap_group_key,
};
use rand_core::{TryCryptoRng, TryRng};
use x25519_dalek::{PublicKey, StaticSecret};

const KDF_CONTEXT: &str = "KRIKOS-ID/group-key-wrap-key/v1";

struct ScriptedRng {
    bytes: Vec<u8>,
    offset: usize,
}

impl ScriptedRng {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl TryRng for ScriptedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        let end = self
            .offset
            .checked_add(destination.len())
            .expect("test vector must contain every requested random byte");
        destination.copy_from_slice(&self.bytes[self.offset..end]);
        self.offset = end;
        Ok(())
    }
}

impl TryCryptoRng for ScriptedRng {}

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

fn digest(seed: u8) -> Digest {
    Digest::new(HashAlgorithm::Blake3_256, [seed; 32])
}

fn typed_id<T: CanonicalWire>(seed: u8) -> T {
    T::from_canonical_bytes(&digest(seed).to_canonical_bytes().unwrap()).unwrap()
}

fn signing_key(seed: u8) -> SigningPublicKey {
    let secret = SecretKey::from_bytes(&[seed; 32]);
    SigningPublicKey::ed25519(*secret.public().as_bytes()).unwrap()
}

fn authorization(secret: &AgreementSecretKey, index: usize, epoch: u64) -> DeviceAuthorization {
    let index = u8::try_from(index).unwrap();
    let signing_seed = 0x40_u8.checked_add(index.checked_mul(2).unwrap()).unwrap();
    let endpoint_seed = signing_seed.checked_add(1).unwrap();
    let descriptor = DeviceDescriptor::new(
        signing_key(signing_seed),
        secret.public_key().unwrap(),
        EndpointPublicKey::new(signing_key(endpoint_seed)),
        Extensions::default(),
    )
    .unwrap();
    DeviceAuthorization::new(
        descriptor.id().unwrap(),
        descriptor,
        DeviceClass::ApplicationOnly,
        None,
        Vec::new(),
        Epoch::new(epoch),
        Extensions::default(),
    )
    .unwrap()
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

fn rule(operation: OperationKind) -> PolicyRule {
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

fn genesis_with_operations(
    operations: Vec<OperationKind>,
    provider_policy: ProviderPolicy,
) -> (AccountState, SecretKey) {
    let signer = SecretKey::from_bytes(&[7; 32]);
    let control_policy = ControlPolicy::new(
        operations.into_iter().map(rule).collect(),
        Extensions::default(),
    )
    .unwrap();
    let recovery_policy = RecoveryPolicy::new(
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
        [0x81; 32],
        Timestamp::from_unix_millis(1),
        control_policy,
        vec![controller(&signer)],
        recovery_policy,
        provider_policy,
        Extensions::default(),
    )
    .unwrap();
    (AccountState::from_genesis(&genesis).unwrap(), signer)
}

fn genesis() -> (AccountState, SecretKey) {
    genesis_with_operations(
        vec![
            OperationKind::AuthorizeDevice,
            OperationKind::SuspendDevice,
            OperationKind::RevokeDevice,
        ],
        ProviderPolicy::local_only(ProviderPolicyVersion::GENESIS, Extensions::default()).unwrap(),
    )
}

fn lifecycle_genesis() -> (AccountState, SecretKey) {
    let provider_secret = SecretKey::from_bytes(&[99; 32]);
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*provider_secret.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    genesis_with_operations(
        vec![
            OperationKind::AuthorizeDevice,
            OperationKind::SuspendDevice,
            OperationKind::RevokeDevice,
            OperationKind::BeginRecovery,
            OperationKind::BeginCryptoMigration,
            OperationKind::ActivateCryptoMigration,
            OperationKind::UpgradeProtocol,
            OperationKind::RetireAccount,
        ],
        ProviderPolicy::replicated(
            ProviderPolicyVersion::GENESIS,
            vec![provider],
            ProviderQuorum::new(1).unwrap(),
            ProviderQuorum::new(1).unwrap(),
            DurationMillis::new(1_000),
            Extensions::default(),
        )
        .unwrap(),
    )
}

fn recovery_intent_approvals(
    state: &AccountState,
    body: &EventBody,
    signer: &SecretKey,
) -> EventIntentApprovals {
    let signing_key = SigningPublicKey::ed25519(*signer.public().as_bytes()).unwrap();
    let approval_body = EventIntentApprovalBody::new(
        state.active_controllers()[0].id(),
        body.proposal_id().unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let signature = signer.sign(&approval_body.to_canonical_bytes().unwrap());
    let keyed_signature = KeyedSignature::new(
        CryptoSuiteDescriptor::v1()
            .unwrap()
            .crypto_suite_id()
            .unwrap(),
        ControllerKeyId::for_signing_key(&signing_key).unwrap(),
        AlgorithmSignature::new(1, signature.to_bytes().to_vec()).unwrap(),
    );
    EventIntentApprovals::new(vec![
        SignedEventIntentApproval::new(approval_body, vec![keyed_signature]).unwrap(),
    ])
    .unwrap()
}

fn recovery_observation_receipt(state: &AccountState, body: &EventBody) -> InclusionReceipt {
    let provider_secret = SecretKey::from_bytes(&[99; 32]);
    let provider = match state.provider_policy().mode() {
        krikos_identity::ProviderMode::LocalOnly => {
            panic!("recovery lifecycle fixture uses a replicated provider")
        }
        krikos_identity::ProviderMode::Replicated(policy) => &policy.providers()[0],
    };
    let log_id = typed_id::<ProviderLogId>(0x67);
    let entry = ProviderLogEntryBody::new(
        provider.id().unwrap(),
        log_id,
        state.account_id(),
        ProviderLogSubject::EventIntent(body.proposal_id().unwrap()),
        Timestamp::from_unix_millis(100),
        Extensions::default(),
    )
    .unwrap();
    let head = ProviderHeadBody::new(
        provider.id().unwrap(),
        log_id,
        ProviderKeyVersion::GENESIS,
        1,
        entry.merkle_leaf_hash().unwrap(),
        Timestamp::from_unix_millis(100),
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

fn authorize_body(
    state: &AccountState,
    body: EventBody,
    signer: &SecretKey,
) -> krikos_identity::AuthorizedEvent {
    let checkpoint_id = typed_id::<CheckpointId>(0x44);
    let delay = if matches!(body.operation(), AccountOperation::BeginRecovery(_)) {
        DelayEvidence::provider_quorum(
            state.provider_policy_id(),
            ProviderQuorum::new(1).unwrap(),
            recovery_intent_approvals(state, &body, signer),
            ProviderReceipts::new(vec![recovery_observation_receipt(state, &body)]).unwrap(),
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
    let event_id = evidence.event_id_for_body(&body).unwrap();
    let approval_body = ControllerApprovalBody::event(
        state.active_controllers()[0].id(),
        event_id,
        evidence.admission_evidence_id().unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let signature = signer.sign(&approval_body.to_canonical_bytes().unwrap());
    let keyed_signature = KeyedSignature::new(
        CryptoSuiteDescriptor::v1()
            .unwrap()
            .crypto_suite_id()
            .unwrap(),
        ControllerKeyId::for_signing_key(
            &SigningPublicKey::ed25519(*signer.public().as_bytes()).unwrap(),
        )
        .unwrap(),
        AlgorithmSignature::new(1, signature.to_bytes().to_vec()).unwrap(),
    );
    let approval = SignedControllerApproval::new(approval_body, vec![keyed_signature]).unwrap();
    krikos_identity::AuthorizedEvent::new(
        body,
        evidence,
        ControllerApprovals::new(vec![approval]).unwrap(),
    )
    .unwrap()
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

fn project_authorizations(
    mut state: AccountState,
    signer: SecretKey,
    authorizations: &[DeviceAuthorization],
) -> (AccountState, SecretKey) {
    for (index, authorization) in authorizations.iter().enumerate() {
        let epoch = u64::try_from(index).unwrap().checked_add(1).unwrap();
        assert_eq!(authorization.authorization_epoch(), Epoch::new(epoch));
        let event = authorized_event(
            &state,
            AccountOperation::AuthorizeDevice(authorization.clone()),
            Epoch::new(epoch),
            u8::try_from(index).unwrap().checked_add(10).unwrap(),
            &signer,
        );
        state.validate_and_apply(&event).unwrap();
    }
    (state, signer)
}

fn active_state(authorizations: &[DeviceAuthorization]) -> (AccountState, SecretKey) {
    let (state, signer) = genesis();
    project_authorizations(state, signer, authorizations)
}

fn lifecycle_active_state(authorizations: &[DeviceAuthorization]) -> (AccountState, SecretKey) {
    let (state, signer) = lifecycle_genesis();
    project_authorizations(state, signer, authorizations)
}

fn begin_recovery_operation(state: &AccountState, signer: &SecretKey) -> AccountOperation {
    let retained_devices = state.devices().iter().map(|device| device.id()).collect();
    let plan = RecoveryAuthorityPlan::try_new(
        ProtocolVersion::V1,
        state.account_id(),
        typed_id::<CheckpointId>(0x44),
        state.heads()[0],
        state.recovery_policy_id(),
        state.recovery_policy().policy_version(),
        [0x51; 32],
        vec![controller(signer)],
        state.control_policy().clone(),
        state.recovery_policy().clone(),
        retained_devices,
        Timestamp::from_unix_millis(1_000),
        Extensions::default(),
    )
    .unwrap();
    let proposal =
        RecoveryProposal::try_new(ProtocolVersion::V1, plan, Extensions::default()).unwrap();
    AccountOperation::BeginRecovery(
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
    )
}

fn begin_migration_operation(
    state: &AccountState,
    signer: &SecretKey,
) -> (AccountOperation, CryptoMigrationId) {
    let v1_suite = CryptoSuiteDescriptor::v1().unwrap();
    let candidate_suite = CryptoSuiteDescriptor::try_new(
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
    let migrated_signer = SecretKey::from_bytes(&[0x91; 32]);
    let controller = &state.active_controllers()[0];
    let migrated_key = AlgorithmPublicKey::new(
        candidate_suite.signature_algorithm_code(),
        migrated_signer.public().as_bytes().to_vec(),
    )
    .unwrap();
    let migration = CryptoMigrationBody::try_new(
        ProtocolVersion::V1,
        state.account_id(),
        v1_suite.crypto_suite_id().unwrap(),
        candidate_suite,
        vec![
            ControllerKeyBinding::try_new(
                controller.id(),
                ControllerKeyId::for_signing_key(&controller.signing_key()).unwrap(),
                migrated_key,
                Extensions::default(),
            )
            .unwrap(),
        ],
        None,
        [0x92; 32],
        Extensions::default(),
    )
    .unwrap();
    let migration_id = migration.crypto_migration_id().unwrap();
    let message = migration_id.to_canonical_bytes().unwrap();
    let proof = ControllerKeyBindingProof::try_new(
        migration_id,
        controller.id(),
        AlgorithmSignature::new(
            v1_suite.signature_algorithm_code(),
            signer.sign(&message).to_bytes().to_vec(),
        )
        .unwrap(),
        AlgorithmSignature::new(
            v1_suite.signature_algorithm_code(),
            migrated_signer.sign(&message).to_bytes().to_vec(),
        )
        .unwrap(),
    )
    .unwrap();
    (
        AccountOperation::BeginCryptoMigration(
            BeginCryptoMigration::try_new(
                ProtocolVersion::V1,
                migration,
                ControllerKeyBindingProofSet::try_new(vec![proof]).unwrap(),
                Extensions::default(),
            )
            .unwrap(),
        ),
        migration_id,
    )
}

fn snapshot(state: &AccountState, recipients: Vec<DeviceId>) -> GroupKeyDistributionSnapshot {
    GroupKeyDistributionSnapshot::from_post_state(
        state,
        ApplicationId::new(digest(0xa1)),
        GroupId::new(digest(0xb2)),
        GroupKeyEpoch::new(3),
        recipients,
    )
    .unwrap()
}

#[test]
fn fixed_v1_reference_stages_and_round_trip_are_frozen() {
    let recipient_secret = AgreementSecretKey::from_bytes([0x20; 32]);
    let recipient = authorization(&recipient_secret, 0, 1);
    let (state, _) = active_state(std::slice::from_ref(&recipient));
    let snapshot = snapshot(&state, vec![recipient.device_id()]);
    let group_key = GroupKey::new([0x90; 32]);
    let random_bytes: Vec<u8> = (0x40_u8..=0x77).collect();
    let mut random = ScriptedRng::new(random_bytes.clone());

    let rotation = rotate_group_key_with_rng(&snapshot, &group_key, &mut random).unwrap();
    let wrapped = &rotation.recipient_key_wraps().as_slice()[0];

    let ephemeral_secret_bytes: [u8; 32] = random_bytes[..32].try_into().unwrap();
    let nonce_bytes: [u8; 24] = random_bytes[32..].try_into().unwrap();
    let reference_ephemeral_secret = StaticSecret::from(ephemeral_secret_bytes);
    let reference_ephemeral_public = PublicKey::from(&reference_ephemeral_secret);
    let reference_recipient_public =
        PublicKey::from(*recipient.descriptor().agreement_key().as_bytes());
    let reference_shared = reference_ephemeral_secret.diffie_hellman(&reference_recipient_public);
    let mut kdf_material = [0_u8; 96];
    kdf_material[..32].copy_from_slice(reference_shared.as_bytes());
    kdf_material[32..64].copy_from_slice(reference_ephemeral_public.as_bytes());
    kdf_material[64..].copy_from_slice(reference_recipient_public.as_bytes());
    let reference_key = blake3::derive_key(KDF_CONTEXT, &kdf_material);
    let reference_aad = postcard::to_stdvec(&(wrapped.header(), wrapped.extensions())).unwrap();
    let reference_cipher = XChaCha20Poly1305::new(&Key::from(reference_key));
    let reference_ciphertext = reference_cipher
        .encrypt(
            &XNonce::from(nonce_bytes),
            Payload {
                msg: group_key.as_bytes(),
                aad: &reference_aad,
            },
        )
        .unwrap();

    assert_eq!(
        hex::encode(reference_ephemeral_public.as_bytes()),
        "79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a"
    );
    assert_eq!(
        hex::encode(reference_shared.as_bytes()),
        "e711c769e2ffcffd4138bd1c9a98edc4d4e4eb2387a3bacaaa83c4cdbea7c86f"
    );
    assert_eq!(
        hex::encode(reference_key),
        "f9bb12d93810013a19fece5587d69c754a58d114374b2508567164b044601bee"
    );
    assert_eq!(
        hex::encode(&reference_aad),
        "01018ff40ee1a62f16342b90d738eb35827198fecb38c8b8cef4e949427a1d7b27ea0117206292de38719a908ec5fcbdcbfaa5cd396a56df6b8b5237ecd3855149883101a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a101b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b20103012b14395570cbf755d9df2a69b1b9362cb3a5ef7934aae464aea17f11dbc53c2301ecc22ebef4b41a173f3763d2bea3bb274a8e4cd64103196f9da03efadc5ab1d40179a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a606162636465666768696a6b6c6d6e6f70717273747576770000"
    );
    assert_eq!(
        hex::encode(&reference_ciphertext),
        "889a9197793033a7da7d80f78aaba54868df0f6c5a0a523982aa9bec72e6a4f92281cbb69471263eb0a5958572da5626"
    );
    assert_eq!(wrapped.ciphertext(), reference_ciphertext);
    assert_eq!(
        wrapped.group_key_wrap_id().unwrap().to_string(),
        "b3:4a4f13c30b1c657bf2f97a4e1207383c0b4940b18d913d221983691c078fbe1c"
    );
    let unwrapped = unwrap_group_key(&snapshot, wrapped, &recipient_secret).unwrap();
    assert_eq!(unwrapped.as_bytes(), group_key.as_bytes());
    assert_eq!(format!("{group_key:?}"), "GroupKey(<redacted>)");
    assert_eq!(
        format!("{recipient_secret:?}"),
        "AgreementSecretKey(<redacted>)"
    );
}

#[test]
fn unwrap_rejects_wrong_secret_ciphertext_and_header_or_outer_substitution() {
    let first_secret = AgreementSecretKey::from_bytes([0x21; 32]);
    let second_secret = AgreementSecretKey::from_bytes([0x22; 32]);
    let first = authorization(&first_secret, 0, 1);
    let second = authorization(&second_secret, 1, 2);
    let (state, _) = active_state(&[first.clone(), second.clone()]);
    let snapshot = snapshot(&state, vec![first.device_id(), second.device_id()]);
    let mut random = ScriptedRng::new((0_u8..112).collect());
    let rotation =
        rotate_group_key_with_rng(&snapshot, &GroupKey::new([0x44; 32]), &mut random).unwrap();
    let wrapped = rotation
        .recipient_key_wraps()
        .as_slice()
        .iter()
        .find(|wrapped| wrapped.recipient_device_id() == first.device_id())
        .unwrap();

    assert!(matches!(
        unwrap_group_key(&snapshot, wrapped, &second_secret),
        Err(IdentityError::KeyWrapAuthenticationFailed)
    ));

    let mut tampered_ciphertext = wrapped.ciphertext().to_vec();
    tampered_ciphertext[0] ^= 0x80;
    let tampered = WrappedGroupKey::new(
        wrapped.header().clone(),
        tampered_ciphertext,
        Extensions::default(),
    )
    .unwrap();
    assert!(matches!(
        unwrap_group_key(&snapshot, &tampered, &first_secret),
        Err(IdentityError::KeyWrapAuthenticationFailed)
    ));

    let substituted_outer_extensions =
        Extensions::new(vec![Extension::new(90, false, vec![1, 2, 3]).unwrap()]).unwrap();
    let substituted_outer = WrappedGroupKey::new(
        wrapped.header().clone(),
        wrapped.ciphertext().to_vec(),
        substituted_outer_extensions,
    )
    .unwrap();
    assert!(matches!(
        unwrap_group_key(&snapshot, &substituted_outer, &first_secret),
        Err(IdentityError::KeyWrapAuthenticationFailed)
    ));

    let substituted_header = GroupKeyWrapHeader::new_for_recipient(
        snapshot.crypto_suite_id(),
        snapshot.account_id(),
        snapshot.application_id(),
        snapshot.group_id(),
        snapshot.authorizing_account_epoch(),
        snapshot.group_key_epoch(),
        &second,
        wrapped.header().ephemeral_public_key(),
        wrapped.header().nonce(),
        Extensions::default(),
    )
    .unwrap();
    let substituted = WrappedGroupKey::new(
        substituted_header,
        wrapped.ciphertext().to_vec(),
        Extensions::default(),
    )
    .unwrap();
    assert!(matches!(
        unwrap_group_key(&snapshot, &substituted, &second_secret),
        Err(IdentityError::KeyWrapAuthenticationFailed)
    ));
}

#[test]
fn constructors_reject_low_order_keys_unsupported_suites_and_non_48_byte_ciphertexts() {
    assert!(matches!(
        AgreementPublicKey::x25519([0; 32]),
        Err(IdentityError::InvalidPublicKey { .. })
    ));

    let recipient_secret = AgreementSecretKey::from_bytes([0x23; 32]);
    let recipient = authorization(&recipient_secret, 0, 1);
    let (state, _) = active_state(std::slice::from_ref(&recipient));
    let snapshot = snapshot(&state, vec![recipient.device_id()]);
    let unsupported = CryptoSuiteDescriptor::try_new(
        ProtocolVersion::V1,
        2,
        1,
        1,
        1,
        1,
        1,
        Extensions::default(),
    )
    .unwrap()
    .crypto_suite_id()
    .unwrap();
    assert!(matches!(
        GroupKeyWrapHeader::new_for_recipient(
            unsupported,
            snapshot.account_id(),
            snapshot.application_id(),
            snapshot.group_id(),
            snapshot.authorizing_account_epoch(),
            snapshot.group_key_epoch(),
            &recipient,
            AgreementSecretKey::from_bytes([0x67; 32])
                .public_key()
                .unwrap(),
            KeyWrapNonce::new([0x68; 24]),
            Extensions::default(),
        ),
        Err(IdentityError::UnsupportedKeyWrapSuite)
    ));

    let mut random = ScriptedRng::new(vec![0x69; 56]);
    let rotation =
        rotate_group_key_with_rng(&snapshot, &GroupKey::new([0x6a; 32]), &mut random).unwrap();
    let valid = &rotation.recipient_key_wraps().as_slice()[0];

    let unsupported_header_wire = postcard::to_stdvec(&(
        ProtocolVersion::V1,
        unsupported,
        valid.header().account_id(),
        valid.header().application_id(),
        valid.header().group_id(),
        valid.header().authorizing_account_epoch(),
        valid.header().group_key_epoch(),
        valid.header().recipient_device_id(),
        valid.header().recipient_agreement_key_id(),
        valid.header().ephemeral_public_key(),
        valid.header().nonce(),
        Extensions::default(),
    ))
    .unwrap();
    assert!(GroupKeyWrapHeader::from_canonical_bytes(&unsupported_header_wire).is_err());

    for length in [0, 47, 49, 4096] {
        assert!(
            WrappedGroupKey::new(
                valid.header().clone(),
                vec![0; length],
                Extensions::default(),
            )
            .is_err()
        );
    }
    for length in [47, 49] {
        let invalid_wrap_wire = postcard::to_stdvec(&(
            valid.header().clone(),
            vec![0_u8; length],
            Extensions::default(),
        ))
        .unwrap();
        assert!(WrappedGroupKey::from_canonical_bytes(&invalid_wrap_wire).is_err());
    }
}

#[test]
fn snapshot_derives_authority_and_binds_complete_application_membership() {
    let first_secret = AgreementSecretKey::from_bytes([0x24; 32]);
    let second_secret = AgreementSecretKey::from_bytes([0x25; 32]);
    let third_secret = AgreementSecretKey::from_bytes([0x26; 32]);
    let first = authorization(&first_secret, 0, 1);
    let second = authorization(&second_secret, 1, 2);
    let third = authorization(&third_secret, 2, 3);
    let (active, signer) = active_state(&[first.clone(), second.clone(), third.clone()]);

    let expected = vec![second.device_id(), first.device_id()];
    let snapshot = snapshot(&active, expected);
    let mut expected_sorted = vec![first.device_id(), second.device_id()];
    expected_sorted.sort_unstable();
    assert_eq!(
        snapshot.expected_recipient_ids().collect::<Vec<_>>(),
        expected_sorted
    );
    assert_eq!(snapshot.account_revision(), &active.revision_token());
    assert_eq!(snapshot.account_id(), active.account_id());
    assert_eq!(snapshot.authorizing_account_epoch(), active.epoch());

    assert!(matches!(
        GroupKeyDistributionSnapshot::from_post_state(
            &active,
            snapshot.application_id(),
            snapshot.group_id(),
            snapshot.group_key_epoch(),
            vec![first.device_id(), first.device_id()],
        ),
        Err(IdentityError::DuplicateElement { .. })
    ));
    assert!(matches!(
        GroupKeyDistributionSnapshot::from_post_state(
            &active,
            snapshot.application_id(),
            snapshot.group_id(),
            snapshot.group_key_epoch(),
            vec![typed_id::<DeviceId>(0xee)],
        ),
        Err(IdentityError::DeviceNotAuthorized)
    ));
    assert!(
        !snapshot
            .expected_recipient_ids()
            .any(|device_id| device_id == third.device_id())
    );

    let mut suspended = active.clone();
    let suspend = authorized_event(
        &suspended,
        AccountOperation::SuspendDevice(
            SuspendDevice::new(second.device_id(), Extensions::default()).unwrap(),
        ),
        Epoch::new(4),
        40,
        &signer,
    );
    suspended.validate_and_apply(&suspend).unwrap();
    assert!(matches!(
        GroupKeyDistributionSnapshot::from_post_state(
            &suspended,
            snapshot.application_id(),
            snapshot.group_id(),
            snapshot.group_key_epoch(),
            vec![second.device_id()],
        ),
        Err(IdentityError::DeviceSuspended)
    ));

    let mut revoked = active;
    let revoke = authorized_event(
        &revoked,
        AccountOperation::RevokeDevice(
            RevokeDevice::new(third.device_id(), None, Extensions::default()).unwrap(),
        ),
        Epoch::new(4),
        41,
        &signer,
    );
    revoked.validate_and_apply(&revoke).unwrap();
    assert!(matches!(
        GroupKeyDistributionSnapshot::from_post_state(
            &revoked,
            snapshot.application_id(),
            snapshot.group_id(),
            snapshot.group_key_epoch(),
            vec![third.device_id()],
        ),
        Err(IdentityError::DeviceRevoked)
    ));
}

#[test]
fn snapshot_account_lifecycle_gate_covers_every_projection_state() {
    let first_secret = AgreementSecretKey::from_bytes([0x27; 32]);
    let second_secret = AgreementSecretKey::from_bytes([0x28; 32]);
    let first = authorization(&first_secret, 0, 1);
    let second = authorization(&second_secret, 1, 2);
    let (active, signer) = lifecycle_active_state(&[first.clone(), second.clone()]);
    assert_eq!(active.lifecycle(), ProjectionLifecycle::Active);
    snapshot(&active, vec![first.device_id()]);

    let mut recovery_pending = active.clone();
    let begin_recovery = authorized_event(
        &recovery_pending,
        begin_recovery_operation(&recovery_pending, &signer),
        recovery_pending.epoch().checked_next().unwrap(),
        0xa1,
        &signer,
    );
    recovery_pending
        .validate_and_apply(&begin_recovery)
        .unwrap();
    assert_eq!(
        recovery_pending.lifecycle(),
        ProjectionLifecycle::RecoveryPending
    );
    assert!(matches!(
        GroupKeyDistributionSnapshot::from_post_state(
            &recovery_pending,
            ApplicationId::new(digest(0xa1)),
            GroupId::new(digest(0xb2)),
            GroupKeyEpoch::new(3),
            vec![first.device_id()],
        ),
        Err(IdentityError::RecoveryPending)
    ));

    let mut migration_pending = active.clone();
    let (begin_migration, migration_id) = begin_migration_operation(&migration_pending, &signer);
    let begin_migration = authorized_event(
        &migration_pending,
        begin_migration,
        migration_pending.epoch(),
        0xa2,
        &signer,
    );
    let begin_migration_event_id = begin_migration.event_id().unwrap();
    migration_pending
        .validate_and_apply(&begin_migration)
        .unwrap();
    assert_eq!(
        migration_pending.lifecycle(),
        ProjectionLifecycle::MigrationPending
    );
    snapshot(&migration_pending, vec![first.device_id()]);

    let mut migration_dual = migration_pending;
    let activate_migration = authorized_event(
        &migration_dual,
        AccountOperation::ActivateCryptoMigration(
            ActivateCryptoMigration::try_new(
                ProtocolVersion::V1,
                migration_id,
                begin_migration_event_id,
                Extensions::default(),
            )
            .unwrap(),
        ),
        migration_dual.epoch().checked_next().unwrap(),
        0xa3,
        &signer,
    );
    migration_dual
        .validate_and_apply(&activate_migration)
        .unwrap();
    assert_eq!(
        migration_dual.lifecycle(),
        ProjectionLifecycle::MigrationDual
    );
    snapshot(&migration_dual, vec![first.device_id()]);

    let mut upgrade_pending = active.clone();
    let upgrade = authorized_event(
        &upgrade_pending,
        AccountOperation::UpgradeProtocol(
            ProtocolUpgrade::try_new(
                ProtocolVersion::V1,
                ProtocolMajor::new(1).unwrap(),
                ProtocolMajor::new(2).unwrap(),
                digest(0xa4),
                UpgradeCompatibility::OldClientsReadOnly,
                None,
                Extensions::default(),
            )
            .unwrap(),
        ),
        upgrade_pending.epoch().checked_next().unwrap(),
        0xa4,
        &signer,
    );
    upgrade_pending.validate_and_apply(&upgrade).unwrap();
    assert_eq!(
        upgrade_pending.lifecycle(),
        ProjectionLifecycle::UpgradePending
    );
    assert!(matches!(
        GroupKeyDistributionSnapshot::from_post_state(
            &upgrade_pending,
            ApplicationId::new(digest(0xa1)),
            GroupId::new(digest(0xb2)),
            GroupKeyEpoch::new(3),
            vec![first.device_id()],
        ),
        Err(IdentityError::ProtocolUpgradeReadOnly)
    ));

    let mut retired = active.clone();
    let retirement = authorized_event(
        &retired,
        AccountOperation::RetireAccount(
            RetireAccount::try_new(ProtocolVersion::V1, None, None, Extensions::default()).unwrap(),
        ),
        retired.epoch().checked_next().unwrap(),
        0xa5,
        &signer,
    );
    retired.validate_and_apply(&retirement).unwrap();
    assert_eq!(retired.lifecycle(), ProjectionLifecycle::Retired);
    assert!(matches!(
        GroupKeyDistributionSnapshot::from_post_state(
            &retired,
            ApplicationId::new(digest(0xa1)),
            GroupId::new(digest(0xb2)),
            GroupKeyEpoch::new(3),
            vec![first.device_id()],
        ),
        Err(IdentityError::AccountRetired)
    ));

    let fork_pre_state = active;
    let left = authorized_event(
        &fork_pre_state,
        AccountOperation::SuspendDevice(
            SuspendDevice::new(second.device_id(), Extensions::default()).unwrap(),
        ),
        fork_pre_state.epoch().checked_next().unwrap(),
        0xa6,
        &signer,
    );
    let right = authorized_event(
        &fork_pre_state,
        AccountOperation::RevokeDevice(
            RevokeDevice::new(second.device_id(), None, Extensions::default()).unwrap(),
        ),
        fork_pre_state.epoch().checked_next().unwrap(),
        0xa7,
        &signer,
    );
    let mut forked = fork_pre_state;
    forked.validate_and_apply(&left).unwrap();
    forked.validate_and_apply(&right).unwrap();
    assert_eq!(forked.lifecycle(), ProjectionLifecycle::Forked);
    assert!(matches!(
        GroupKeyDistributionSnapshot::from_post_state(
            &forked,
            ApplicationId::new(digest(0xa1)),
            GroupId::new(digest(0xb2)),
            GroupKeyEpoch::new(3),
            vec![first.device_id()],
        ),
        Err(IdentityError::AccountForked)
    ));
}

#[test]
fn rotation_artifact_rejects_stale_and_forked_persistence_revisions() {
    let first_secret = AgreementSecretKey::from_bytes([0x29; 32]);
    let second_secret = AgreementSecretKey::from_bytes([0x2a; 32]);
    let first = authorization(&first_secret, 0, 1);
    let second = authorization(&second_secret, 1, 2);
    let (active, signer) = active_state(&[first.clone(), second.clone()]);
    let old_snapshot = snapshot(&active, vec![first.device_id()]);
    let old_revision = active.revision_token();
    let artifact: GroupKeyRotation = rotate_group_key_with_rng(
        &old_snapshot,
        &GroupKey::new([0x72; 32]),
        &mut ScriptedRng::new(vec![0x73; 56]),
    )
    .unwrap();
    assert_eq!(artifact.account_revision(), &old_revision);
    artifact.validate_current_revision(&active).unwrap();

    let mut advanced = active.clone();
    let suspend_other = authorized_event(
        &advanced,
        AccountOperation::SuspendDevice(
            SuspendDevice::new(second.device_id(), Extensions::default()).unwrap(),
        ),
        advanced.epoch().checked_next().unwrap(),
        0xb1,
        &signer,
    );
    advanced.validate_and_apply(&suspend_other).unwrap();
    assert_eq!(artifact.account_revision(), &old_revision);
    assert!(matches!(
        artifact.validate_current_revision(&advanced),
        Err(IdentityError::StaleRevision)
    ));

    let current_snapshot = snapshot(&advanced, vec![first.device_id()]);
    let current_artifact = rotate_group_key_with_rng(
        &current_snapshot,
        &GroupKey::new([0x74; 32]),
        &mut ScriptedRng::new(vec![0x75; 56]),
    )
    .unwrap();
    current_artifact
        .validate_current_revision(&advanced)
        .unwrap();
    assert_ne!(
        artifact.account_revision(),
        current_artifact.account_revision()
    );

    let suspend_recipient = authorized_event(
        &advanced,
        AccountOperation::SuspendDevice(
            SuspendDevice::new(first.device_id(), Extensions::default()).unwrap(),
        ),
        advanced.epoch().checked_next().unwrap(),
        0xb2,
        &signer,
    );
    advanced.validate_and_apply(&suspend_recipient).unwrap();
    assert!(matches!(
        GroupKeyDistributionSnapshot::from_post_state(
            &advanced,
            old_snapshot.application_id(),
            old_snapshot.group_id(),
            old_snapshot.group_key_epoch(),
            vec![first.device_id()],
        ),
        Err(IdentityError::DeviceSuspended)
    ));

    let left = authorized_event(
        &active,
        AccountOperation::SuspendDevice(
            SuspendDevice::new(second.device_id(), Extensions::default()).unwrap(),
        ),
        active.epoch().checked_next().unwrap(),
        0xb3,
        &signer,
    );
    let right = authorized_event(
        &active,
        AccountOperation::RevokeDevice(
            RevokeDevice::new(second.device_id(), None, Extensions::default()).unwrap(),
        ),
        active.epoch().checked_next().unwrap(),
        0xb4,
        &signer,
    );
    let mut forked = active;
    forked.validate_and_apply(&left).unwrap();
    forked.validate_and_apply(&right).unwrap();
    assert!(matches!(
        artifact.validate_current_revision(&forked),
        Err(IdentityError::AccountForked)
    ));
    assert!(matches!(
        GroupKeyDistributionSnapshot::from_post_state(
            &forked,
            old_snapshot.application_id(),
            old_snapshot.group_id(),
            old_snapshot.group_key_epoch(),
            vec![first.device_id()],
        ),
        Err(IdentityError::AccountForked)
    ));
}

#[test]
fn rotation_output_exactly_matches_snapshot_and_rejects_randomness_reuse() {
    let first_secret = AgreementSecretKey::from_bytes([0x31; 32]);
    let second_secret = AgreementSecretKey::from_bytes([0x32; 32]);
    let first = authorization(&first_secret, 0, 1);
    let second = authorization(&second_secret, 1, 2);
    let (state, _) = active_state(&[first.clone(), second.clone()]);
    let snapshot = snapshot(&state, vec![second.device_id(), first.device_id()]);
    let group_key = GroupKey::new([0x77; 32]);

    assert!(matches!(
        rotate_group_key_with_rng(&snapshot, &group_key, &mut RepeatingRng(5)),
        Err(IdentityError::DuplicateElement { .. })
    ));

    let mut repeated_ephemeral = vec![0x39; 32];
    repeated_ephemeral.extend_from_slice(&[0x41; 24]);
    repeated_ephemeral.extend_from_slice(&[0x39; 32]);
    repeated_ephemeral.extend_from_slice(&[0x42; 24]);
    let repeated_ephemeral_result = rotate_group_key_with_rng(
        &snapshot,
        &group_key,
        &mut ScriptedRng::new(repeated_ephemeral),
    );
    assert!(
        matches!(
            &repeated_ephemeral_result,
            Err(IdentityError::DuplicateElement {
                resource: "recipient key wrap ephemeral public keys"
            })
        ),
        "{repeated_ephemeral_result:?}"
    );

    let mut repeated_nonce = vec![0x39; 32];
    repeated_nonce.extend_from_slice(&[0x43; 24]);
    repeated_nonce.extend_from_slice(&[0x3a; 32]);
    repeated_nonce.extend_from_slice(&[0x43; 24]);
    assert!(matches!(
        rotate_group_key_with_rng(&snapshot, &group_key, &mut ScriptedRng::new(repeated_nonce),),
        Err(IdentityError::DuplicateElement {
            resource: "recipient key wrap nonces"
        })
    ));

    let rotation = rotate_group_key_with_rng(
        &snapshot,
        &group_key,
        &mut ScriptedRng::new((0_u8..112).collect()),
    )
    .unwrap();
    assert_eq!(rotation.account_revision(), snapshot.account_revision());
    assert_eq!(rotation.account_id(), snapshot.account_id());
    assert_eq!(rotation.application_id(), snapshot.application_id());
    assert_eq!(rotation.group_id(), snapshot.group_id());
    assert_eq!(
        rotation.authorizing_account_epoch(),
        snapshot.authorizing_account_epoch()
    );
    assert_eq!(rotation.group_key_epoch(), snapshot.group_key_epoch());
    assert_eq!(
        rotation.expected_recipient_ids().collect::<Vec<_>>(),
        snapshot.expected_recipient_ids().collect::<Vec<_>>()
    );
    rotation.validate_current_revision(&state).unwrap();
    let wraps = rotation.recipient_key_wraps();
    assert_eq!(
        wraps
            .as_slice()
            .iter()
            .map(WrappedGroupKey::recipient_device_id)
            .collect::<Vec<_>>(),
        snapshot.expected_recipient_ids().collect::<Vec<_>>()
    );
    assert_ne!(
        wraps.as_slice()[0].header().ephemeral_public_key(),
        wraps.as_slice()[1].header().ephemeral_public_key()
    );
    assert_ne!(
        wraps.as_slice()[0].header().nonce(),
        wraps.as_slice()[1].header().nonce()
    );
}

#[test]
fn atomic_store_revalidates_rotation_revision_and_gates_protected_writes() {
    let signer = SecretKey::from_bytes(&[7; 32]);
    let control_policy = ControlPolicy::new(
        vec![rule(OperationKind::AuthorizeDevice)],
        Extensions::default(),
    )
    .unwrap();
    let recovery_policy = RecoveryPolicy::new(
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
        [0x82; 32],
        Timestamp::from_unix_millis(1),
        control_policy,
        vec![controller(&signer)],
        recovery_policy,
        ProviderPolicy::local_only(ProviderPolicyVersion::GENESIS, Extensions::default()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let account_id = genesis.account_id().unwrap();
    let first_secret = AgreementSecretKey::from_bytes([0x31; 32]);
    let second_secret = AgreementSecretKey::from_bytes([0x32; 32]);
    let first = authorization(&first_secret, 0, 1);
    let second = authorization(&second_secret, 1, 2);
    let application_id = ApplicationId::new(digest(0xa1));
    let group_id = GroupId::new(digest(0xb2));
    let store = MemoryAccountStore::new();
    let initial = futures_lite::future::block_on(store.create_account(genesis)).unwrap();

    let first_event = authorized_event(
        initial.state(),
        AccountOperation::AuthorizeDevice(first.clone()),
        Epoch::new(1),
        10,
        &signer,
    );
    let after_first =
        futures_lite::future::block_on(store.commit_event(initial.revision().clone(), first_event))
            .unwrap();
    let stale_snapshot = GroupKeyDistributionSnapshot::from_post_state(
        after_first.snapshot().state(),
        application_id,
        group_id,
        GroupKeyEpoch::new(1),
        vec![first.device_id()],
    )
    .unwrap();
    let stale_rotation = rotate_group_key_with_rng(
        &stale_snapshot,
        &GroupKey::new([0x72; 32]),
        &mut ScriptedRng::new(vec![0x73; 56]),
    )
    .unwrap();

    let second_event = authorized_event(
        after_first.snapshot().state(),
        AccountOperation::AuthorizeDevice(second.clone()),
        Epoch::new(2),
        11,
        &signer,
    );
    let after_second = futures_lite::future::block_on(
        store.commit_event(after_first.snapshot().revision().clone(), second_event),
    )
    .unwrap();
    let current_snapshot = GroupKeyDistributionSnapshot::from_post_state(
        after_second.snapshot().state(),
        application_id,
        group_id,
        GroupKeyEpoch::new(2),
        vec![first.device_id(), second.device_id()],
    )
    .unwrap();
    let current_rotation = rotate_group_key_with_rng(
        &current_snapshot,
        &GroupKey::new([0x74; 32]),
        &mut ScriptedRng::new((0_u8..112).collect()),
    )
    .unwrap();
    let retry_rotation = rotate_group_key_with_rng(
        &current_snapshot,
        &GroupKey::new([0x74; 32]),
        &mut ScriptedRng::new((0_u8..112).collect()),
    )
    .unwrap();
    let conflicting_current_rotation = rotate_group_key_with_rng(
        &current_snapshot,
        &GroupKey::new([0x77; 32]),
        &mut ScriptedRng::new((112_u8..224).collect()),
    )
    .unwrap();
    assert_eq!(
        futures_lite::future::block_on(store.authorize_protected_write(
            after_second.snapshot().revision().clone(),
            application_id,
            group_id,
        )),
        Err(IdentityError::ProtectedWritesBlocked)
    );

    let lease_id = LeaseId::new([0x76; 16]).unwrap();
    let claim = ClaimEffects::new(
        Timestamp::from_unix_millis(100),
        Timestamp::from_unix_millis(200),
        lease_id,
        8,
    )
    .unwrap();
    let effects = futures_lite::future::block_on(store.claim_effects(account_id, claim)).unwrap();
    let stale_effect_id = effects
        .iter()
        .find_map(|record| match record.effect() {
            ProjectionEffect::RotateGroupKeys { epoch, .. } if epoch == Epoch::new(1) => {
                Some(record.id())
            }
            _ => None,
        })
        .unwrap();
    let current_effect_id = effects
        .iter()
        .find_map(|record| match record.effect() {
            ProjectionEffect::RotateGroupKeys { epoch, .. } if epoch == Epoch::new(2) => {
                Some(record.id())
            }
            _ => None,
        })
        .unwrap();
    assert!(matches!(
        futures_lite::future::block_on(store.commit_group_key_rotation(
            stale_effect_id,
            lease_id,
            stale_rotation,
            Timestamp::from_unix_millis(150),
        )),
        Err(IdentityError::StaleRevision)
    ));
    let stored = futures_lite::future::block_on(store.commit_group_key_rotation(
        current_effect_id,
        lease_id,
        current_rotation,
        Timestamp::from_unix_millis(150),
    ))
    .unwrap();
    assert_eq!(stored.group_key_epoch(), GroupKeyEpoch::new(2));
    assert_eq!(
        futures_lite::future::block_on(store.commit_group_key_rotation(
            current_effect_id,
            lease_id,
            retry_rotation,
            Timestamp::from_unix_millis(150),
        ))
        .unwrap(),
        stored
    );
    assert_eq!(
        futures_lite::future::block_on(store.commit_group_key_rotation(
            current_effect_id,
            lease_id,
            conflicting_current_rotation,
            Timestamp::from_unix_millis(151),
        )),
        Err(IdentityError::StaleRevision)
    );
    futures_lite::future::block_on(store.authorize_protected_write(
        after_second.snapshot().revision().clone(),
        application_id,
        group_id,
    ))
    .unwrap();
}
