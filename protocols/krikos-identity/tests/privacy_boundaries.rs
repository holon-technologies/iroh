use std::{cell::RefCell, convert::Infallible};

use krikos_base::SecretKey;
use krikos_identity::{
    AccountId, AccountOperation, AdmissionEvidence, AlgorithmSignature, BlindedCommitment,
    BlindingSecret, CanonicalSigningRequest, CanonicalWire, CheckpointId, ControllerApprovalBody,
    ControllerClass, ControllerDescriptor, ControllerScope, ControllerWeight, CredentialClaim,
    CredentialVerificationContext, DelayEvidence, Digest, Epoch, EventBody, EventPredecessors,
    Extensions, FreshnessEvidence, HardwareApprovalRequest, HardwareController, HashAlgorithm,
    IdentityError, LookupHandleSecret, OfflineSigner, OperationKind, PairwiseIdentifier,
    PairwiseMasterSecret, PortableCredentialBody, PrivateCheckpointLookupHandle, PrivateLabel,
    ProtocolVersion, ProviderId, ProviderPolicyId, RelyingPartyContext, Sequence,
    SignedPortableCredential, SigningPublicKey, SigningPurpose, Timestamp,
    verify_portable_credential,
};
use rand_core::{TryCryptoRng, TryRng};

fn typed_id<T: CanonicalWire>(fill: u8) -> T {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [fill; 32]);
    T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
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

#[test]
fn fresh_blinding_hides_equal_low_entropy_labels() {
    let label = PrivateLabel::try_new(b"family".to_vec()).unwrap();
    let first = BlindingSecret::generate_with_rng(&mut RepeatingRng(0x11)).unwrap();
    let second = BlindingSecret::generate_with_rng(&mut RepeatingRng(0x12)).unwrap();
    let first_commitment = BlindedCommitment::relationship_label(&label, &first).unwrap();
    let second_commitment = BlindedCommitment::relationship_label(&label, &second).unwrap();
    assert_ne!(first_commitment, second_commitment);

    let guessed = PrivateLabel::try_new(b"family".to_vec()).unwrap();
    let attacker_blinding = BlindingSecret::generate_with_rng(&mut RepeatingRng(0x13)).unwrap();
    assert_ne!(
        first_commitment,
        BlindedCommitment::relationship_label(&guessed, &attacker_blinding).unwrap()
    );
    let encoded = first_commitment.to_canonical_bytes().unwrap();
    assert_eq!(
        BlindedCommitment::from_canonical_bytes(&encoded).unwrap(),
        first_commitment
    );
    assert_eq!(
        blake3::hash(&encoded).as_bytes(),
        &[
            0x2f, 0x4e, 0x2b, 0x35, 0x99, 0x48, 0x76, 0x01, 0xf0, 0x34, 0x12, 0xf5, 0x93, 0x81,
            0x80, 0x62, 0x41, 0xb7, 0xe0, 0x70, 0x07, 0xf6, 0x80, 0x59, 0x21, 0x30, 0xb4, 0x00,
            0x37, 0x46, 0xa7, 0x31,
        ]
    );
    assert_eq!(format!("{label:?}"), "PrivateLabel(<redacted>)");
    assert_eq!(format!("{first:?}"), "BlindingSecret(<redacted>)");
}

#[test]
fn lookup_handles_rotate_and_bind_provider_account_and_generation() {
    let secret = LookupHandleSecret::try_new([0x21; 32]).unwrap();
    let account = typed_id::<AccountId>(0x22);
    let other_account = typed_id::<AccountId>(0x23);
    let provider = typed_id::<ProviderId>(0x24);
    let other_provider = typed_id::<ProviderId>(0x25);

    assert!(matches!(
        PrivateCheckpointLookupHandle::derive(&secret, provider, account, 0),
        Err(IdentityError::ZeroValue { .. })
    ));

    let handle = PrivateCheckpointLookupHandle::derive(&secret, provider, account, 1).unwrap();
    assert_eq!(
        handle,
        PrivateCheckpointLookupHandle::derive(&secret, provider, account, 1).unwrap()
    );
    assert_ne!(
        handle,
        PrivateCheckpointLookupHandle::derive(&secret, provider, account, 2).unwrap()
    );
    assert_ne!(
        handle,
        PrivateCheckpointLookupHandle::derive(&secret, other_provider, account, 1).unwrap()
    );
    assert_ne!(
        handle,
        PrivateCheckpointLookupHandle::derive(&secret, provider, other_account, 1).unwrap()
    );
    assert!(
        !handle
            .to_canonical_bytes()
            .unwrap()
            .windows(32)
            .any(|window| { window == account.to_canonical_bytes().unwrap().as_slice() })
    );
    let encoded = handle.to_canonical_bytes().unwrap();
    assert_eq!(
        PrivateCheckpointLookupHandle::from_canonical_bytes(&encoded).unwrap(),
        handle
    );
    assert_eq!(
        blake3::hash(&encoded).as_bytes(),
        &[
            0x64, 0x2c, 0x1b, 0x8a, 0x59, 0x54, 0xe6, 0xad, 0xfe, 0x6a, 0xde, 0xd8, 0x07, 0x21,
            0x13, 0x55, 0x11, 0x9f, 0x89, 0xc3, 0xf9, 0x6d, 0x2a, 0xcd, 0xf0, 0x61, 0xee, 0xdf,
            0x20, 0x51, 0xb2, 0x1d,
        ]
    );
}

#[test]
fn pairwise_identifiers_normalize_context_and_separate_relying_parties() {
    let master = PairwiseMasterSecret::try_new([0x31; 32]).unwrap();
    let account = typed_id::<AccountId>(0x32);
    let normalized = RelyingPartyContext::try_new("Login.Example.COM").unwrap();
    assert_eq!(normalized.as_str(), "login.example.com");
    let same = RelyingPartyContext::try_new("login.example.com").unwrap();
    let other = RelyingPartyContext::try_new("payments.example.com").unwrap();
    assert_eq!(
        PairwiseIdentifier::derive(&master, account, &normalized).unwrap(),
        PairwiseIdentifier::derive(&master, account, &same).unwrap()
    );
    assert_ne!(
        PairwiseIdentifier::derive(&master, account, &normalized).unwrap(),
        PairwiseIdentifier::derive(&master, account, &other).unwrap()
    );
    assert_ne!(
        PairwiseIdentifier::derive(&master, account, &normalized).unwrap(),
        PairwiseIdentifier::derive(&master, typed_id::<AccountId>(0x33), &normalized).unwrap()
    );
    for ambiguous in [
        "",
        ".example.com",
        "example..com",
        "-example.com",
        "éxample.com",
    ] {
        assert!(RelyingPartyContext::try_new(ambiguous).is_err());
    }
    let identifier = PairwiseIdentifier::derive(&master, account, &normalized).unwrap();
    let encoded = identifier.to_canonical_bytes().unwrap();
    assert_eq!(
        PairwiseIdentifier::from_canonical_bytes(&encoded).unwrap(),
        identifier
    );
    assert_eq!(
        blake3::hash(&encoded).as_bytes(),
        &[
            0x79, 0x3b, 0x72, 0x09, 0x7c, 0xe1, 0x50, 0x96, 0x47, 0x75, 0x4a, 0xab, 0x82, 0x46,
            0x48, 0x10, 0xfd, 0x81, 0xbc, 0x42, 0xcf, 0x4f, 0x5f, 0x7b, 0x21, 0x2c, 0x46, 0xe9,
            0xdb, 0x72, 0x16, 0x60,
        ]
    );
}

struct FakeOfflineSigner {
    secret: SecretKey,
    observed: RefCell<Vec<u8>>,
}

impl OfflineSigner for FakeOfflineSigner {
    fn sign_exact(
        &self,
        request: &CanonicalSigningRequest,
    ) -> Result<AlgorithmSignature, IdentityError> {
        self.observed.replace(request.canonical_message().to_vec());
        let signature = self.secret.sign(request.canonical_message());
        AlgorithmSignature::new(1, signature.to_bytes().to_vec())
    }
}

impl HardwareController for FakeOfflineSigner {
    fn approve_exact(
        &self,
        request: &HardwareApprovalRequest,
    ) -> Result<AlgorithmSignature, IdentityError> {
        self.observed.replace(request.canonical_message().to_vec());
        let signature = self.secret.sign(request.canonical_message());
        AlgorithmSignature::new(1, signature.to_bytes().to_vec())
    }
}

fn account_approval_fixture(
    signing_key: SigningPublicKey,
    nonce: u8,
) -> (
    EventBody,
    AdmissionEvidence,
    ControllerApprovalBody,
    ControllerDescriptor,
) {
    let controller = ControllerDescriptor::new(
        signing_key,
        ControllerClass::PersonalDevice,
        ControllerWeight::new(1).unwrap(),
        ControllerScope::all_v1_operations(),
        Extensions::default(),
    )
    .unwrap();
    let added_secret = SecretKey::from_bytes(&[nonce.checked_add(0x20).unwrap(); 32]);
    let added_controller = ControllerDescriptor::new(
        SigningPublicKey::ed25519(*added_secret.public().as_bytes()).unwrap(),
        ControllerClass::PersonalDevice,
        ControllerWeight::new(1).unwrap(),
        ControllerScope::all_v1_operations(),
        Extensions::default(),
    )
    .unwrap();
    let body = EventBody::new(
        typed_id::<AccountId>(nonce.checked_add(0x30).unwrap()),
        Sequence::new(1),
        Epoch::new(1),
        EventPredecessors::genesis(typed_id(nonce.checked_add(0x31).unwrap())),
        AccountOperation::AddController(added_controller),
        Timestamp::from_unix_millis(10),
        [nonce; 16],
        Extensions::default(),
    )
    .unwrap();
    let checkpoint_id = typed_id::<CheckpointId>(nonce.checked_add(0x32).unwrap());
    let admission = AdmissionEvidence::new(
        body.proposal_id().unwrap(),
        checkpoint_id,
        typed_id::<ProviderPolicyId>(nonce.checked_add(0x33).unwrap()),
        FreshnessEvidence::local_known(checkpoint_id),
        DelayEvidence::none(),
        Extensions::default(),
    )
    .unwrap();
    let approval = ControllerApprovalBody::event(
        controller.id().unwrap(),
        admission.event_id_for_body(&body).unwrap(),
        admission.admission_evidence_id().unwrap(),
        Extensions::default(),
    )
    .unwrap();
    (body, admission, approval, controller)
}

#[test]
fn credential_export_discloses_only_selected_claims_and_binds_exact_authority() {
    let issuer_secret = SecretKey::from_bytes(&[0x41; 32]);
    let issuer_key = SigningPublicKey::ed25519(*issuer_secret.public().as_bytes()).unwrap();
    let subject_key =
        SigningPublicKey::ed25519(*SecretKey::from_bytes(&[0x42; 32]).public().as_bytes()).unwrap();
    let account = typed_id::<AccountId>(0x43);
    let checkpoint = typed_id::<CheckpointId>(0x44);
    let selected = CredentialClaim::try_new("display-name", b"Ada".to_vec()).unwrap();
    let omitted_value = b"ada@example.invalid";
    let body = PortableCredentialBody::try_new(
        account,
        checkpoint,
        Epoch::GENESIS,
        vec![subject_key],
        account,
        issuer_key,
        Timestamp::from_unix_millis(10),
        Timestamp::from_unix_millis(20),
        vec![selected],
        Extensions::default(),
    )
    .unwrap();
    let export_bytes = body.to_canonical_bytes().unwrap();
    assert!(
        !export_bytes
            .windows(omitted_value.len())
            .any(|window| window == omitted_value)
    );

    let signer = FakeOfflineSigner {
        secret: issuer_secret,
        observed: RefCell::new(Vec::new()),
    };
    let request = CanonicalSigningRequest::for_portable_credential(&body).unwrap();
    assert_eq!(request.purpose(), SigningPurpose::PortableCredential);
    assert_eq!(request.account_id(), account);
    assert_eq!(request.signer_account_id(), account);
    assert_eq!(request.account_epoch(), Epoch::GENESIS);
    assert_eq!(request.operation_kind(), None);
    assert_eq!(request.expected_signing_key(), issuer_key);
    let signature = signer.sign_exact(&request).unwrap();
    assert_eq!(
        signer.observed.borrow().as_slice(),
        body.signing_bytes().unwrap()
    );
    let credential = SignedPortableCredential::try_new(body, signature).unwrap();
    let encoded = credential.to_canonical_bytes().unwrap();
    assert_eq!(
        SignedPortableCredential::from_canonical_bytes(&encoded).unwrap(),
        credential
    );
    assert_eq!(
        blake3::hash(&encoded).as_bytes(),
        &[
            0x64, 0x6d, 0x54, 0xda, 0xec, 0x92, 0xd0, 0x84, 0x33, 0xff, 0xde, 0x0a, 0xc2, 0xa8,
            0x5b, 0xb3, 0xd3, 0xba, 0x6d, 0x55, 0xb1, 0xe8, 0xb0, 0x28, 0x37, 0x2b, 0x7a, 0xe1,
            0x4b, 0x98, 0x94, 0x65,
        ]
    );
    let context = CredentialVerificationContext::try_new(
        account,
        checkpoint,
        Epoch::GENESIS,
        account,
        issuer_key,
        Timestamp::from_unix_millis(19),
    )
    .unwrap();
    let verified = verify_portable_credential(&credential, &context).unwrap();
    assert_eq!(verified.claims()[0].name(), "display-name");

    let substituted = CredentialVerificationContext::try_new(
        account,
        typed_id::<CheckpointId>(0x45),
        Epoch::GENESIS,
        account,
        issuer_key,
        Timestamp::from_unix_millis(19),
    )
    .unwrap();
    assert!(verify_portable_credential(&credential, &substituted).is_err());

    for invalid in [
        CredentialVerificationContext::try_new(
            typed_id::<AccountId>(0x46),
            checkpoint,
            Epoch::GENESIS,
            account,
            issuer_key,
            Timestamp::from_unix_millis(19),
        )
        .unwrap(),
        CredentialVerificationContext::try_new(
            account,
            checkpoint,
            Epoch::new(2),
            account,
            issuer_key,
            Timestamp::from_unix_millis(19),
        )
        .unwrap(),
        CredentialVerificationContext::try_new(
            account,
            checkpoint,
            Epoch::GENESIS,
            typed_id::<AccountId>(0x47),
            issuer_key,
            Timestamp::from_unix_millis(19),
        )
        .unwrap(),
        CredentialVerificationContext::try_new(
            account,
            checkpoint,
            Epoch::GENESIS,
            account,
            SigningPublicKey::ed25519(*SecretKey::from_bytes(&[0x48; 32]).public().as_bytes())
                .unwrap(),
            Timestamp::from_unix_millis(19),
        )
        .unwrap(),
    ] {
        assert!(verify_portable_credential(&credential, &invalid).is_err());
    }
    let expired = CredentialVerificationContext::try_new(
        account,
        checkpoint,
        Epoch::GENESIS,
        account,
        issuer_key,
        Timestamp::from_unix_millis(20),
    )
    .unwrap();
    assert_eq!(
        verify_portable_credential(&credential, &expired),
        Err(IdentityError::StaleEvidence)
    );
    assert_eq!(
        SignedPortableCredential::try_new(
            credential.body().clone(),
            AlgorithmSignature::new(1, vec![0x49; 64]).unwrap(),
        ),
        Err(IdentityError::InvalidSignature)
    );
}

#[test]
fn hardware_boundary_receives_only_exact_typed_approval_bytes() {
    let secret = SecretKey::from_bytes(&[0x51; 32]);
    let signing_key = SigningPublicKey::ed25519(*secret.public().as_bytes()).unwrap();
    let (body, admission, approval, controller) = account_approval_fixture(signing_key, 0x11);
    let message = approval.to_canonical_bytes().unwrap();
    let fake = FakeOfflineSigner {
        secret,
        observed: RefCell::new(Vec::new()),
    };
    let request =
        HardwareApprovalRequest::for_account_approval(&body, &admission, &approval, &controller)
            .unwrap();
    let signature = fake.approve_exact(&request).unwrap();
    assert_eq!(fake.observed.borrow().as_slice(), message);
    request.verify_response(&signature).unwrap();
    assert_eq!(request.protocol_version(), ProtocolVersion::V1);
    assert_eq!(request.account_id(), body.account_id());
    assert_eq!(request.resulting_epoch(), body.resulting_epoch());
    assert_eq!(request.operation_kind(), OperationKind::AddController);
    assert_eq!(request.expected_signing_key(), signing_key);
}

#[test]
fn offline_and_hardware_account_approval_boundaries_sign_only_the_exact_body() {
    let secret = SecretKey::from_bytes(&[0x61; 32]);
    let signing_key = SigningPublicKey::ed25519(*secret.public().as_bytes()).unwrap();
    let (body, admission, approval, controller) = account_approval_fixture(signing_key, 0x12);
    let approval_bytes = approval.to_canonical_bytes().unwrap();
    let fake = FakeOfflineSigner {
        secret,
        observed: RefCell::new(Vec::new()),
    };

    let offline_request =
        CanonicalSigningRequest::for_account_approval(&body, &admission, &approval, &controller)
            .unwrap();
    let offline_signature = fake.sign_exact(&offline_request).unwrap();
    assert_eq!(fake.observed.borrow().as_slice(), approval_bytes);
    assert_eq!(offline_request.purpose(), SigningPurpose::AccountApproval);
    assert_eq!(offline_request.account_id(), body.account_id());
    assert_eq!(offline_request.signer_account_id(), body.account_id());
    assert_eq!(offline_request.account_epoch(), body.resulting_epoch());
    assert_eq!(
        offline_request.operation_kind(),
        Some(OperationKind::AddController)
    );
    offline_request.verify_response(&offline_signature).unwrap();

    let hardware_request =
        HardwareApprovalRequest::for_account_approval(&body, &admission, &approval, &controller)
            .unwrap();
    let hardware_signature = fake.approve_exact(&hardware_request).unwrap();
    assert_eq!(fake.observed.borrow().as_slice(), approval_bytes);
    assert_eq!(
        hardware_request.operation_kind(),
        OperationKind::AddController
    );
    assert_eq!(hardware_request.expected_signing_key(), signing_key);
    hardware_request
        .verify_response(&hardware_signature)
        .unwrap();

    let (substituted_body, substituted_admission, substituted_approval, substituted_controller) =
        account_approval_fixture(signing_key, 0x13);
    let substituted = HardwareApprovalRequest::for_account_approval(
        &substituted_body,
        &substituted_admission,
        &substituted_approval,
        &substituted_controller,
    )
    .unwrap();
    assert_eq!(
        substituted.verify_response(&hardware_signature),
        Err(IdentityError::InvalidSignature)
    );

    assert!(
        CanonicalSigningRequest::for_account_approval(
            &substituted_body,
            &admission,
            &approval,
            &controller,
        )
        .is_err(),
        "a host cannot combine display context from one event with another event's approval"
    );
    assert!(
        HardwareApprovalRequest::for_account_approval(
            &body,
            &substituted_admission,
            &approval,
            &controller,
        )
        .is_err(),
        "a host cannot substitute admission evidence behind the signer's display"
    );

    let wrong_secret = SecretKey::from_bytes(&[0x62; 32]);
    let wrong_controller = ControllerDescriptor::new(
        SigningPublicKey::ed25519(*wrong_secret.public().as_bytes()).unwrap(),
        ControllerClass::PersonalDevice,
        ControllerWeight::new(1).unwrap(),
        ControllerScope::all_v1_operations(),
        Extensions::default(),
    )
    .unwrap();
    assert!(
        CanonicalSigningRequest::for_account_approval(
            &body,
            &admission,
            &approval,
            &wrong_controller,
        )
        .is_err(),
        "a host cannot substitute the displayed key/controller"
    );

    let scoped_controller = ControllerDescriptor::new(
        signing_key,
        ControllerClass::PersonalDevice,
        ControllerWeight::new(1).unwrap(),
        ControllerScope::operations(vec![OperationKind::CancelRecovery]).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let scoped_approval = ControllerApprovalBody::event(
        scoped_controller.id().unwrap(),
        admission.event_id_for_body(&body).unwrap(),
        admission.admission_evidence_id().unwrap(),
        Extensions::default(),
    )
    .unwrap();
    assert_eq!(
        HardwareApprovalRequest::for_account_approval(
            &body,
            &admission,
            &scoped_approval,
            &scoped_controller,
        )
        .err(),
        Some(IdentityError::IneligibleController)
    );
}

#[test]
fn privacy_sensitive_debug_surfaces_are_redacted() {
    let blinding = BlindingSecret::try_new([0x71; 32]).unwrap();
    let label = PrivateLabel::try_new(b"private-family-label".to_vec()).unwrap();
    let lookup = LookupHandleSecret::try_new([0x72; 32]).unwrap();
    let pairwise = PairwiseMasterSecret::try_new([0x73; 32]).unwrap();
    assert_eq!(format!("{blinding:?}"), "BlindingSecret(<redacted>)");
    assert_eq!(format!("{label:?}"), "PrivateLabel(<redacted>)");
    assert_eq!(format!("{lookup:?}"), "LookupHandleSecret(<redacted>)");
    assert_eq!(format!("{pairwise:?}"), "PairwiseMasterSecret(<redacted>)");

    let claim = CredentialClaim::try_new("email", b"private@example.invalid".to_vec()).unwrap();
    let debug = format!("{claim:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("private@example.invalid"));

    let signing_key =
        SigningPublicKey::ed25519(*SecretKey::from_bytes(&[0x74; 32]).public().as_bytes()).unwrap();
    let (body, admission, approval, controller) = account_approval_fixture(signing_key, 0x14);
    let exact_message = approval.to_canonical_bytes().unwrap();
    let request =
        CanonicalSigningRequest::for_account_approval(&body, &admission, &approval, &controller)
            .unwrap();
    let debug = format!("{request:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains(&hex::encode(exact_message)));
}
