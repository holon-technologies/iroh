use krikos_base::SecretKey;
use krikos_identity::{
    AccountId, AlgorithmSignature, CanonicalWire, CheckpointId, Digest, Extensions, HashAlgorithm,
    IdentityError, SignedSocialAttestation, SigningPublicKey, SocialAttestationBody,
    SocialAttestationVerificationContext, SocialTransitivityPolicy, Timestamp,
    evaluate_social_trust, verify_social_attestation,
};

fn typed_id<T: CanonicalWire>(fill: u8) -> T {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [fill; 32]);
    T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
}

fn signed_attestation(
    issuer_secret: &SecretKey,
    issuer_account: AccountId,
    issuer_checkpoint: CheckpointId,
    subject_secret: &SecretKey,
    subject_account: AccountId,
    subject_checkpoint: CheckpointId,
    claim_fill: u8,
) -> SignedSocialAttestation {
    signed_attestation_for_interval(
        issuer_secret,
        issuer_account,
        issuer_checkpoint,
        subject_secret,
        subject_account,
        subject_checkpoint,
        claim_fill,
        Timestamp::from_unix_millis(10),
        Some(Timestamp::from_unix_millis(20)),
    )
}

#[allow(clippy::too_many_arguments)]
fn signed_attestation_for_interval(
    issuer_secret: &SecretKey,
    issuer_account: AccountId,
    issuer_checkpoint: CheckpointId,
    subject_secret: &SecretKey,
    subject_account: AccountId,
    subject_checkpoint: CheckpointId,
    claim_fill: u8,
    issued_at: Timestamp,
    expires_at: Option<Timestamp>,
) -> SignedSocialAttestation {
    let body = SocialAttestationBody::try_new(
        issuer_account,
        issuer_checkpoint,
        SigningPublicKey::ed25519(*issuer_secret.public().as_bytes()).unwrap(),
        subject_account,
        subject_checkpoint,
        SigningPublicKey::ed25519(*subject_secret.public().as_bytes()).unwrap(),
        Digest::new(HashAlgorithm::Blake3_256, [claim_fill; 32]),
        issued_at,
        expires_at,
        Extensions::default(),
    )
    .unwrap();
    let signature = issuer_secret.sign(&body.signing_bytes().unwrap());
    SignedSocialAttestation::try_new(
        body,
        AlgorithmSignature::new(1, signature.to_bytes().to_vec()).unwrap(),
    )
    .unwrap()
}

#[test]
fn transitive_edges_with_disjoint_validity_windows_never_form_a_trust_path() {
    let first_secret = SecretKey::from_bytes(&[0x01; 32]);
    let second_secret = SecretKey::from_bytes(&[0x02; 32]);
    let third_secret = SecretKey::from_bytes(&[0x03; 32]);
    let first = signed_attestation_for_interval(
        &first_secret,
        typed_id::<AccountId>(0x04),
        typed_id::<CheckpointId>(0x05),
        &second_secret,
        typed_id::<AccountId>(0x06),
        typed_id::<CheckpointId>(0x07),
        0x08,
        Timestamp::from_unix_millis(10),
        Some(Timestamp::from_unix_millis(20)),
    );
    let second = signed_attestation_for_interval(
        &second_secret,
        typed_id::<AccountId>(0x06),
        typed_id::<CheckpointId>(0x07),
        &third_secret,
        typed_id::<AccountId>(0x09),
        typed_id::<CheckpointId>(0x0a),
        0x08,
        Timestamp::from_unix_millis(30),
        Some(Timestamp::from_unix_millis(40)),
    );
    let first = verify_social_attestation(
        &first,
        &context_from_body(first.body(), Timestamp::from_unix_millis(19)),
    )
    .unwrap();
    let second = verify_social_attestation(
        &second,
        &context_from_body(second.body(), Timestamp::from_unix_millis(31)),
    )
    .unwrap();

    assert_eq!(
        evaluate_social_trust(
            &[first, second],
            SocialTransitivityPolicy::bounded(2).unwrap(),
            Timestamp::from_unix_millis(31),
        ),
        Err(IdentityError::StaleEvidence)
    );
}

fn context_from_body(
    body: &SocialAttestationBody,
    authority_time: Timestamp,
) -> SocialAttestationVerificationContext {
    SocialAttestationVerificationContext::try_new(
        body.issuer_account_id(),
        body.issuer_checkpoint_id(),
        body.issuer_signing_key(),
        body.subject_account_id(),
        body.subject_checkpoint_id(),
        body.subject_signing_key(),
        body.claim_digest(),
        authority_time,
    )
    .unwrap()
}

#[test]
fn social_attestation_binds_signature_subject_checkpoint_claim_and_expiry() {
    let issuer_secret = SecretKey::from_bytes(&[0x11; 32]);
    let subject_secret = SecretKey::from_bytes(&[0x12; 32]);
    let issuer_account = typed_id::<AccountId>(0x13);
    let issuer_checkpoint = typed_id::<CheckpointId>(0x14);
    let subject_account = typed_id::<AccountId>(0x15);
    let subject_checkpoint = typed_id::<CheckpointId>(0x16);
    let attestation = signed_attestation(
        &issuer_secret,
        issuer_account,
        issuer_checkpoint,
        &subject_secret,
        subject_account,
        subject_checkpoint,
        0x17,
    );
    let context = SocialAttestationVerificationContext::try_new(
        issuer_account,
        issuer_checkpoint,
        SigningPublicKey::ed25519(*issuer_secret.public().as_bytes()).unwrap(),
        subject_account,
        subject_checkpoint,
        SigningPublicKey::ed25519(*subject_secret.public().as_bytes()).unwrap(),
        Digest::new(HashAlgorithm::Blake3_256, [0x17; 32]),
        Timestamp::from_unix_millis(19),
    )
    .unwrap();
    let verified = verify_social_attestation(&attestation, &context).unwrap();
    assert_eq!(verified.subject_account_id(), subject_account);
    assert_eq!(verified.authority_time(), Timestamp::from_unix_millis(19));

    let wrong_claim = SocialAttestationVerificationContext::try_new(
        issuer_account,
        issuer_checkpoint,
        SigningPublicKey::ed25519(*issuer_secret.public().as_bytes()).unwrap(),
        subject_account,
        subject_checkpoint,
        SigningPublicKey::ed25519(*subject_secret.public().as_bytes()).unwrap(),
        Digest::new(HashAlgorithm::Blake3_256, [0x18; 32]),
        Timestamp::from_unix_millis(19),
    )
    .unwrap();
    assert!(verify_social_attestation(&attestation, &wrong_claim).is_err());

    let wrong_subject_account = SocialAttestationVerificationContext::try_new(
        issuer_account,
        issuer_checkpoint,
        SigningPublicKey::ed25519(*issuer_secret.public().as_bytes()).unwrap(),
        typed_id::<AccountId>(0x19),
        subject_checkpoint,
        SigningPublicKey::ed25519(*subject_secret.public().as_bytes()).unwrap(),
        Digest::new(HashAlgorithm::Blake3_256, [0x17; 32]),
        Timestamp::from_unix_millis(19),
    )
    .unwrap();
    assert!(verify_social_attestation(&attestation, &wrong_subject_account).is_err());

    let wrong_subject_checkpoint = SocialAttestationVerificationContext::try_new(
        issuer_account,
        issuer_checkpoint,
        SigningPublicKey::ed25519(*issuer_secret.public().as_bytes()).unwrap(),
        subject_account,
        typed_id::<CheckpointId>(0x1a),
        SigningPublicKey::ed25519(*subject_secret.public().as_bytes()).unwrap(),
        Digest::new(HashAlgorithm::Blake3_256, [0x17; 32]),
        Timestamp::from_unix_millis(19),
    )
    .unwrap();
    assert!(verify_social_attestation(&attestation, &wrong_subject_checkpoint).is_err());

    let replacement_subject = SecretKey::from_bytes(&[0x1b; 32]);
    let wrong_subject_key = SocialAttestationVerificationContext::try_new(
        issuer_account,
        issuer_checkpoint,
        SigningPublicKey::ed25519(*issuer_secret.public().as_bytes()).unwrap(),
        subject_account,
        subject_checkpoint,
        SigningPublicKey::ed25519(*replacement_subject.public().as_bytes()).unwrap(),
        Digest::new(HashAlgorithm::Blake3_256, [0x17; 32]),
        Timestamp::from_unix_millis(19),
    )
    .unwrap();
    assert!(verify_social_attestation(&attestation, &wrong_subject_key).is_err());

    let expired = SocialAttestationVerificationContext::try_new(
        issuer_account,
        issuer_checkpoint,
        SigningPublicKey::ed25519(*issuer_secret.public().as_bytes()).unwrap(),
        subject_account,
        subject_checkpoint,
        SigningPublicKey::ed25519(*subject_secret.public().as_bytes()).unwrap(),
        Digest::new(HashAlgorithm::Blake3_256, [0x17; 32]),
        Timestamp::from_unix_millis(20),
    )
    .unwrap();
    assert_eq!(
        verify_social_attestation(&attestation, &expired),
        Err(IdentityError::StaleEvidence)
    );

    let forged_body = attestation.body().clone();
    assert_eq!(
        SignedSocialAttestation::try_new(
            forged_body,
            AlgorithmSignature::new(1, vec![0x55; 64]).unwrap(),
        ),
        Err(IdentityError::InvalidSignature)
    );
}

#[test]
fn transitivity_is_default_off_explicitly_bounded_and_cycle_free() {
    let first_secret = SecretKey::from_bytes(&[0x21; 32]);
    let second_secret = SecretKey::from_bytes(&[0x22; 32]);
    let third_secret = SecretKey::from_bytes(&[0x23; 32]);
    let first_account = typed_id::<AccountId>(0x24);
    let second_account = typed_id::<AccountId>(0x25);
    let third_account = typed_id::<AccountId>(0x26);
    let first_checkpoint = typed_id::<CheckpointId>(0x27);
    let second_checkpoint = typed_id::<CheckpointId>(0x28);
    let third_checkpoint = typed_id::<CheckpointId>(0x29);
    let first = signed_attestation(
        &first_secret,
        first_account,
        first_checkpoint,
        &second_secret,
        second_account,
        second_checkpoint,
        0x2a,
    );
    let second = signed_attestation(
        &second_secret,
        second_account,
        second_checkpoint,
        &third_secret,
        third_account,
        third_checkpoint,
        0x2a,
    );
    let first = verify_social_attestation(
        &first,
        &context_from_body(first.body(), Timestamp::from_unix_millis(19)),
    )
    .unwrap();
    let second = verify_social_attestation(
        &second,
        &context_from_body(second.body(), Timestamp::from_unix_millis(19)),
    )
    .unwrap();
    assert!(
        evaluate_social_trust(
            &[first.clone(), second.clone()],
            SocialTransitivityPolicy::default(),
            Timestamp::from_unix_millis(19),
        )
        .is_err()
    );
    assert!(
        evaluate_social_trust(
            &[first.clone(), second.clone()],
            SocialTransitivityPolicy::bounded(1).unwrap(),
            Timestamp::from_unix_millis(19),
        )
        .is_err()
    );
    assert!(SocialTransitivityPolicy::bounded(0).is_err());
    assert!(
        SocialTransitivityPolicy::bounded(
            u8::try_from(krikos_identity::limits::MAX_SOCIAL_TRANSITIVITY_DEPTH + 1).unwrap()
        )
        .is_err()
    );
    let hint = evaluate_social_trust(
        &[first.clone(), second],
        SocialTransitivityPolicy::bounded(2).unwrap(),
        Timestamp::from_unix_millis(19),
    )
    .unwrap();
    assert_eq!(hint.depth(), 2);
    assert_eq!(hint.subject_account_id(), third_account);
    assert_eq!(hint.authority_time(), Timestamp::from_unix_millis(19));

    let cycle = signed_attestation(
        &second_secret,
        second_account,
        second_checkpoint,
        &first_secret,
        first_account,
        first_checkpoint,
        0x2a,
    );
    let cycle = verify_social_attestation(
        &cycle,
        &context_from_body(cycle.body(), Timestamp::from_unix_millis(19)),
    )
    .unwrap();
    assert!(
        evaluate_social_trust(
            &[first, cycle],
            SocialTransitivityPolicy::bounded(2).unwrap(),
            Timestamp::from_unix_millis(19),
        )
        .is_err()
    );
}

#[test]
fn previously_verified_edge_cannot_be_replayed_after_expiry() {
    let issuer_secret = SecretKey::from_bytes(&[0x2b; 32]);
    let subject_secret = SecretKey::from_bytes(&[0x2c; 32]);
    let attestation = signed_attestation(
        &issuer_secret,
        typed_id::<AccountId>(0x2d),
        typed_id::<CheckpointId>(0x2e),
        &subject_secret,
        typed_id::<AccountId>(0x2f),
        typed_id::<CheckpointId>(0x30),
        0x31,
    );
    let verified = verify_social_attestation(
        &attestation,
        &context_from_body(attestation.body(), Timestamp::from_unix_millis(19)),
    )
    .unwrap();

    assert_eq!(
        evaluate_social_trust(
            &[verified],
            SocialTransitivityPolicy::default(),
            Timestamp::from_unix_millis(20),
        ),
        Err(IdentityError::StaleEvidence)
    );
}

#[test]
fn social_body_and_signature_vector_is_canonical_and_bounded() {
    let issuer = SecretKey::from_bytes(&[0x31; 32]);
    let subject = SecretKey::from_bytes(&[0x32; 32]);
    let attestation = signed_attestation(
        &issuer,
        typed_id::<AccountId>(0x33),
        typed_id::<CheckpointId>(0x34),
        &subject,
        typed_id::<AccountId>(0x35),
        typed_id::<CheckpointId>(0x36),
        0x37,
    );
    let encoded = attestation.to_canonical_bytes().unwrap();
    assert_eq!(
        SignedSocialAttestation::from_canonical_bytes(&encoded).unwrap(),
        attestation
    );
    assert_eq!(
        blake3::hash(&encoded).as_bytes(),
        &[
            0x1d, 0x9c, 0xf8, 0xfa, 0x8e, 0x4d, 0x68, 0x42, 0xe3, 0xae, 0xc5, 0x30, 0x4e, 0xe0,
            0x26, 0x4c, 0xca, 0xe3, 0x6b, 0x85, 0x45, 0xef, 0x31, 0x9d, 0x15, 0xd8, 0x33, 0xc5,
            0xc7, 0x5a, 0x0b, 0xb2,
        ]
    );
}
