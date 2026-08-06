use krikos_base::SecretKey;
use krikos_identity::{
    AccountId, AgreementSecretKey, ApplicationAuthorizationView, ApplicationDeviceStatus,
    AuthorizationContext, CanonicalWire, CheckpointId, DeviceAuthorization, DeviceClass,
    DeviceDescriptor, DeviceId, DevicePresenceChallenge, Digest, EndpointPublicKey, Epoch,
    Extensions, HashAlgorithm, IdentityError, PresenceProof, PresenceSessionId,
    PresenceVerifierChallenge, ProtocolSignature, SigningPublicKey, Timestamp,
    verify_presence_proof,
};

fn typed_id<T: CanonicalWire>(seed: u8) -> T {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [seed; 32]);
    T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
}

struct DeviceSecrets {
    application: SecretKey,
    agreement: AgreementSecretKey,
    endpoint: SecretKey,
}

impl DeviceSecrets {
    fn new(seed: u8) -> Self {
        Self {
            application: SecretKey::from_bytes(&[seed; 32]),
            agreement: AgreementSecretKey::from_bytes([seed.checked_add(1).unwrap(); 32]),
            endpoint: SecretKey::from_bytes(&[seed.checked_add(2).unwrap(); 32]),
        }
    }

    fn descriptor(&self) -> DeviceDescriptor {
        DeviceDescriptor::new(
            SigningPublicKey::ed25519(*self.application.public().as_bytes()).unwrap(),
            self.agreement.public_key().unwrap(),
            EndpointPublicKey::new(
                SigningPublicKey::ed25519(*self.endpoint.public().as_bytes()).unwrap(),
            ),
            Extensions::default(),
        )
        .unwrap()
    }
}

struct View {
    context: AuthorizationContext,
    status: ApplicationDeviceStatus,
    authorization: DeviceAuthorization,
}

impl ApplicationAuthorizationView for View {
    fn authorization_context(&self) -> AuthorizationContext {
        self.context
    }

    fn device_status(&self, device_id: DeviceId) -> ApplicationDeviceStatus {
        if device_id == self.authorization.device_id() {
            self.status
        } else {
            ApplicationDeviceStatus::Unknown
        }
    }

    fn device_authorization(&self, device_id: DeviceId) -> Option<&DeviceAuthorization> {
        (device_id == self.authorization.device_id()).then_some(&self.authorization)
    }
}

fn fixture() -> (DeviceSecrets, View, DevicePresenceChallenge) {
    let secrets = DeviceSecrets::new(10);
    let descriptor = secrets.descriptor();
    let device_id = descriptor.id().unwrap();
    let account_id: AccountId = typed_id(1);
    let checkpoint_id: CheckpointId = typed_id(2);
    let authorization = DeviceAuthorization::new(
        device_id,
        descriptor.clone(),
        DeviceClass::GeneralPurpose,
        None,
        Vec::new(),
        Epoch::new(7),
        Extensions::default(),
    )
    .unwrap();
    let view = View {
        context: AuthorizationContext::new(account_id, Epoch::new(7), checkpoint_id),
        status: ApplicationDeviceStatus::Active,
        authorization,
    };
    let challenge = DevicePresenceChallenge::new(
        account_id,
        device_id,
        PresenceVerifierChallenge::new([0x31; 32]).unwrap(),
        PresenceSessionId::new([0x41; 32]).unwrap(),
        Digest::new(HashAlgorithm::Blake3_256, [0x51; 32]),
        checkpoint_id,
        Timestamp::from_unix_millis(1_000),
        Timestamp::from_unix_millis(301_000),
        descriptor.application_signing_key(),
        Extensions::default(),
    )
    .unwrap();
    (secrets, view, challenge)
}

fn signed_proof(secrets: &DeviceSecrets, challenge: DevicePresenceChallenge) -> PresenceProof {
    let signature = secrets
        .application
        .sign(&challenge.signing_bytes().unwrap());
    PresenceProof::new(challenge, ProtocolSignature::ed25519(signature.to_bytes())).unwrap()
}

#[test]
fn exact_active_known_checkpoint_presence_proof_verifies() {
    let (secrets, view, challenge) = fixture();
    let proof = signed_proof(&secrets, challenge.clone());
    let encoded = proof.to_canonical_bytes().unwrap();
    let challenge_bytes = challenge.to_canonical_bytes().unwrap();
    assert_eq!(
        hex::encode(&challenge_bytes),
        "0101010101010101010101010101010101010101010101010101010101010101010101343b62f7a40db173198b2d5d3ff1df419169d8e27f50f0f7b8845d993abdff0a31313131313131313131313131313131313131313131313131313131313131314141414141414141414141414141414141414141414141414141414141414141015151515151515151515151515151515151515151515151515151515151515151010202020202020202020202020202020202020202020202020202020202020202e807c8af120143a72e714401762df66b68c26dfbdf2682aaec9f2474eca4613e424a0fbafd3c00"
    );
    let signing_bytes = challenge.signing_bytes().unwrap();
    assert!(signing_bytes.starts_with(b"KRIKOS-ID/device-presence-signature/v1\0"));
    assert!(signing_bytes.ends_with(&challenge_bytes));
    assert_eq!(
        hex::encode(proof.signature().as_bytes()),
        concat!(
            "5fb96b07b0867bd83e5674d136f3c6a04344f37589c82033771fef248fd26edb",
            "e6ad61318b1f29d9ac87fe047c2ce3ce0c47c8bb009fa6d5277b6bff5ba62601"
        )
    );
    assert_eq!(
        proof.proof_id().unwrap().as_digest().to_string(),
        "b3:0a4f077d3a4092e04871eb868d7a14c3ac0eb6b5fc2852a076efd8320c109b86"
    );

    assert_eq!(
        PresenceProof::from_canonical_bytes(&encoded).unwrap(),
        proof
    );
    assert!(
        verify_presence_proof(
            &proof,
            &challenge,
            Timestamp::from_unix_millis(1_000),
            &view,
        )
        .is_ok()
    );
}

#[test]
fn challenge_session_transcript_checkpoint_and_account_substitution_fail() {
    let (secrets, view, challenge) = fixture();
    let proof = signed_proof(&secrets, challenge.clone());
    let variants = [
        DevicePresenceChallenge::new(
            challenge.account_id(),
            challenge.device_id(),
            PresenceVerifierChallenge::new([0x32; 32]).unwrap(),
            challenge.session_id(),
            challenge.transcript_binding(),
            challenge.checkpoint_id(),
            challenge.issued_at(),
            challenge.expires_at(),
            challenge.signing_key(),
            Extensions::default(),
        )
        .unwrap(),
        DevicePresenceChallenge::new(
            challenge.account_id(),
            challenge.device_id(),
            challenge.verifier_challenge(),
            PresenceSessionId::new([0x42; 32]).unwrap(),
            challenge.transcript_binding(),
            challenge.checkpoint_id(),
            challenge.issued_at(),
            challenge.expires_at(),
            challenge.signing_key(),
            Extensions::default(),
        )
        .unwrap(),
        DevicePresenceChallenge::new(
            challenge.account_id(),
            challenge.device_id(),
            challenge.verifier_challenge(),
            challenge.session_id(),
            Digest::new(HashAlgorithm::Blake3_256, [0x52; 32]),
            challenge.checkpoint_id(),
            challenge.issued_at(),
            challenge.expires_at(),
            challenge.signing_key(),
            Extensions::default(),
        )
        .unwrap(),
        DevicePresenceChallenge::new(
            challenge.account_id(),
            challenge.device_id(),
            challenge.verifier_challenge(),
            challenge.session_id(),
            challenge.transcript_binding(),
            typed_id(3),
            challenge.issued_at(),
            challenge.expires_at(),
            challenge.signing_key(),
            Extensions::default(),
        )
        .unwrap(),
        DevicePresenceChallenge::new(
            typed_id(4),
            challenge.device_id(),
            challenge.verifier_challenge(),
            challenge.session_id(),
            challenge.transcript_binding(),
            challenge.checkpoint_id(),
            challenge.issued_at(),
            challenge.expires_at(),
            challenge.signing_key(),
            Extensions::default(),
        )
        .unwrap(),
    ];

    for substituted in variants {
        assert!(matches!(
            verify_presence_proof(
                &proof,
                &substituted,
                Timestamp::from_unix_millis(1_000),
                &view,
            ),
            Err(IdentityError::InvalidRelationship { .. })
        ));
    }
}

#[test]
fn inactive_or_wrong_exact_device_key_is_rejected() {
    let (secrets, mut view, challenge) = fixture();
    let proof = signed_proof(&secrets, challenge.clone());
    view.status = ApplicationDeviceStatus::Suspended;
    assert_eq!(
        verify_presence_proof(
            &proof,
            &challenge,
            Timestamp::from_unix_millis(1_000),
            &view,
        )
        .unwrap_err(),
        IdentityError::DeviceSuspended
    );

    view.status = ApplicationDeviceStatus::Revoked;
    assert_eq!(
        verify_presence_proof(
            &proof,
            &challenge,
            Timestamp::from_unix_millis(1_000),
            &view,
        )
        .unwrap_err(),
        IdentityError::DeviceRevoked
    );

    view.status = ApplicationDeviceStatus::Active;
    let wrong = DeviceSecrets::new(70);
    let wrong_challenge = DevicePresenceChallenge::new(
        challenge.account_id(),
        challenge.device_id(),
        challenge.verifier_challenge(),
        challenge.session_id(),
        challenge.transcript_binding(),
        challenge.checkpoint_id(),
        challenge.issued_at(),
        challenge.expires_at(),
        wrong.descriptor().application_signing_key(),
        Extensions::default(),
    )
    .unwrap();
    let wrong_proof = signed_proof(&wrong, wrong_challenge.clone());
    assert!(matches!(
        verify_presence_proof(
            &wrong_proof,
            &wrong_challenge,
            Timestamp::from_unix_millis(1_000),
            &view,
        ),
        Err(IdentityError::InvalidRelationship { .. })
    ));
}

#[test]
fn forged_signature_and_device_replay_are_rejected() {
    let (secrets, view, challenge) = fixture();
    let wrong = DeviceSecrets::new(90);
    let signature = wrong.application.sign(&challenge.signing_bytes().unwrap());
    let forged = PresenceProof::new(
        challenge.clone(),
        ProtocolSignature::ed25519(signature.to_bytes()),
    )
    .unwrap();
    assert_eq!(
        verify_presence_proof(
            &forged,
            &challenge,
            Timestamp::from_unix_millis(1_000),
            &view,
        )
        .unwrap_err(),
        IdentityError::InvalidSignature
    );

    let proof = signed_proof(&secrets, challenge.clone());
    let other_device = wrong.descriptor().id().unwrap();
    let replay_context = DevicePresenceChallenge::new(
        challenge.account_id(),
        other_device,
        challenge.verifier_challenge(),
        challenge.session_id(),
        challenge.transcript_binding(),
        challenge.checkpoint_id(),
        challenge.issued_at(),
        challenge.expires_at(),
        challenge.signing_key(),
        Extensions::default(),
    )
    .unwrap();
    assert!(matches!(
        verify_presence_proof(
            &proof,
            &replay_context,
            Timestamp::from_unix_millis(1_000),
            &view,
        ),
        Err(IdentityError::InvalidRelationship { .. })
    ));
}

#[test]
fn five_minute_lifetime_expiry_and_two_minute_future_skew_edges_are_exact() {
    let (secrets, view, challenge) = fixture();
    let proof = signed_proof(&secrets, challenge.clone());
    assert!(
        verify_presence_proof(
            &proof,
            &challenge,
            Timestamp::from_unix_millis(301_000),
            &view,
        )
        .is_ok()
    );
    assert_eq!(
        verify_presence_proof(
            &proof,
            &challenge,
            Timestamp::from_unix_millis(301_001),
            &view,
        )
        .unwrap_err(),
        IdentityError::StaleEvidence
    );

    let future = DevicePresenceChallenge::new(
        challenge.account_id(),
        challenge.device_id(),
        challenge.verifier_challenge(),
        challenge.session_id(),
        challenge.transcript_binding(),
        challenge.checkpoint_id(),
        Timestamp::from_unix_millis(121_000),
        Timestamp::from_unix_millis(421_000),
        challenge.signing_key(),
        Extensions::default(),
    )
    .unwrap();
    let future_proof = signed_proof(&secrets, future.clone());
    assert!(
        verify_presence_proof(
            &future_proof,
            &future,
            Timestamp::from_unix_millis(1_000),
            &view,
        )
        .is_ok()
    );
    assert!(matches!(
        verify_presence_proof(
            &future_proof,
            &future,
            Timestamp::from_unix_millis(999),
            &view,
        ),
        Err(IdentityError::InvalidRelationship { .. })
    ));

    assert!(
        DevicePresenceChallenge::new(
            challenge.account_id(),
            challenge.device_id(),
            challenge.verifier_challenge(),
            challenge.session_id(),
            challenge.transcript_binding(),
            challenge.checkpoint_id(),
            Timestamp::from_unix_millis(1_000),
            Timestamp::from_unix_millis(301_001),
            challenge.signing_key(),
            Extensions::default(),
        )
        .is_err()
    );
    assert!(matches!(
        verify_presence_proof(
            &proof,
            &challenge,
            Timestamp::from_unix_millis(u64::MAX),
            &view,
        ),
        Err(IdentityError::ArithmeticOverflow { .. })
    ));
}
