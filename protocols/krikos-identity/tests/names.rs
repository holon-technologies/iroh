use krikos_base::SecretKey;
use krikos_identity::{
    AccountId, AlgorithmSignature, CanonicalWire, CheckpointId, Digest, Extensions, HashAlgorithm,
    IdentityError, NameAuthorityContext, NameClaimBody, NameResolver, NormalizedName,
    SignedNameClaim, SigningPublicKey, Timestamp, TofuDecision, TofuObservation,
    evaluate_name_tofu, resolve_name_candidates, verify_name_candidates,
};

fn typed_id<T: CanonicalWire>(fill: u8) -> T {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [fill; 32]);
    T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
}

fn signed_claim(
    name: &str,
    secret: &SecretKey,
    account_id: AccountId,
    checkpoint_id: CheckpointId,
    issued_at: u64,
    expires_at: Option<u64>,
) -> SignedNameClaim {
    let body = NameClaimBody::try_new(
        NormalizedName::try_new(name).unwrap(),
        account_id,
        checkpoint_id,
        SigningPublicKey::ed25519(*secret.public().as_bytes()).unwrap(),
        Timestamp::from_unix_millis(issued_at),
        expires_at.map(Timestamp::from_unix_millis),
        Extensions::default(),
    )
    .unwrap();
    let signature = secret.sign(&body.signing_bytes().unwrap());
    SignedNameClaim::try_new(
        body,
        AlgorithmSignature::new(1, signature.to_bytes().to_vec()).unwrap(),
    )
    .unwrap()
}

fn context_from_body(body: &NameClaimBody, authority_time: Timestamp) -> NameAuthorityContext {
    NameAuthorityContext::try_new(
        body.name().clone(),
        body.subject_account_id(),
        body.subject_checkpoint_id(),
        body.subject_signing_key(),
        authority_time,
    )
    .unwrap()
}

#[test]
fn normalized_name_and_signed_claim_bind_exact_authority_and_time() {
    let name = NormalizedName::try_new("Alice.Example").unwrap();
    assert_eq!(name.as_str(), "alice.example");
    assert!(NormalizedName::try_new("alice..example").is_err());
    assert!(NormalizedName::try_new("álîce.example").is_err());
    assert!(NormalizedName::try_new(&format!("{}.example", "a".repeat(64))).is_err());

    let secret = SecretKey::from_bytes(&[0x11; 32]);
    let account_id = typed_id::<AccountId>(0x12);
    let checkpoint_id = typed_id::<CheckpointId>(0x13);
    let claim = signed_claim(
        name.as_str(),
        &secret,
        account_id,
        checkpoint_id,
        10,
        Some(20),
    );
    let context = NameAuthorityContext::try_new(
        name.clone(),
        account_id,
        checkpoint_id,
        SigningPublicKey::ed25519(*secret.public().as_bytes()).unwrap(),
        Timestamp::from_unix_millis(19),
    )
    .unwrap();
    let candidates = krikos_identity::NameCandidateSet::try_new(vec![claim.clone()]).unwrap();
    let verified = verify_name_candidates(&candidates, &[context]).unwrap();
    assert_eq!(verified.as_slice().len(), 1);
    assert_eq!(verified.as_slice()[0].name(), &name);

    let wrong_checkpoint = NameAuthorityContext::try_new(
        name.clone(),
        account_id,
        typed_id::<CheckpointId>(0x14),
        SigningPublicKey::ed25519(*secret.public().as_bytes()).unwrap(),
        Timestamp::from_unix_millis(19),
    )
    .unwrap();
    assert!(
        verify_name_candidates(&candidates, &[wrong_checkpoint])
            .unwrap()
            .as_slice()
            .is_empty()
    );

    let replacement = SecretKey::from_bytes(&[0x15; 32]);
    let wrong_key = NameAuthorityContext::try_new(
        name.clone(),
        account_id,
        checkpoint_id,
        SigningPublicKey::ed25519(*replacement.public().as_bytes()).unwrap(),
        Timestamp::from_unix_millis(19),
    )
    .unwrap();
    assert!(
        verify_name_candidates(&candidates, &[wrong_key])
            .unwrap()
            .as_slice()
            .is_empty()
    );

    let expired = NameAuthorityContext::try_new(
        name,
        account_id,
        checkpoint_id,
        SigningPublicKey::ed25519(*secret.public().as_bytes()).unwrap(),
        Timestamp::from_unix_millis(20),
    )
    .unwrap();
    assert!(
        verify_name_candidates(&candidates, &[expired])
            .unwrap()
            .as_slice()
            .is_empty()
    );

    assert_eq!(
        SignedNameClaim::try_new(
            claim.body().clone(),
            AlgorithmSignature::new(1, vec![0x55; 64]).unwrap(),
        ),
        Err(IdentityError::InvalidSignature)
    );
}

struct StaticResolver {
    candidates: Vec<SignedNameClaim>,
}

impl NameResolver for StaticResolver {
    fn resolve(
        &self,
        _name: &NormalizedName,
        _maximum_candidates: usize,
    ) -> Result<Vec<SignedNameClaim>, IdentityError> {
        Ok(self.candidates.clone())
    }
}

#[test]
fn malicious_resolver_is_bounded_and_candidates_are_cryptographically_filtered() {
    let secret = SecretKey::from_bytes(&[0x21; 32]);
    let other = SecretKey::from_bytes(&[0x22; 32]);
    let account_id = typed_id::<AccountId>(0x23);
    let checkpoint_id = typed_id::<CheckpointId>(0x24);
    let valid = signed_claim(
        "alice.example",
        &secret,
        account_id,
        checkpoint_id,
        10,
        Some(20),
    );
    let wrong_name = signed_claim(
        "mallory.example",
        &secret,
        account_id,
        checkpoint_id,
        10,
        Some(20),
    );
    let wrong_authority = signed_claim(
        "alice.example",
        &other,
        typed_id::<AccountId>(0x25),
        typed_id::<CheckpointId>(0x26),
        10,
        Some(20),
    );
    let resolver = StaticResolver {
        candidates: vec![valid, wrong_name, wrong_authority],
    };
    let name = NormalizedName::try_new("alice.example").unwrap();
    let candidates = resolve_name_candidates(&resolver, &name).unwrap();
    let context = NameAuthorityContext::try_new(
        name,
        account_id,
        checkpoint_id,
        SigningPublicKey::ed25519(*secret.public().as_bytes()).unwrap(),
        Timestamp::from_unix_millis(19),
    )
    .unwrap();
    let verified = verify_name_candidates(&candidates, &[context]).unwrap();
    assert_eq!(verified.as_slice().len(), 1);
    assert_eq!(verified.as_slice()[0].account_id(), account_id);

    let oversized = StaticResolver {
        candidates: vec![
            resolver.candidates[0].clone();
            krikos_identity::limits::MAX_NAME_CLAIMS + 1
        ],
    };
    assert!(matches!(
        resolve_name_candidates(
            &oversized,
            &NormalizedName::try_new("alice.example").unwrap()
        ),
        Err(IdentityError::LimitExceeded { .. })
    ));
}

#[test]
fn tofu_first_use_unchanged_and_key_change_are_pure_decisions() {
    let first_secret = SecretKey::from_bytes(&[0x31; 32]);
    let replacement_secret = SecretKey::from_bytes(&[0x32; 32]);
    let account_id = typed_id::<AccountId>(0x33);
    let first_claim = signed_claim(
        "alice.example",
        &first_secret,
        account_id,
        typed_id::<CheckpointId>(0x34),
        10,
        Some(40),
    );
    let first_context = context_from_body(first_claim.body(), Timestamp::from_unix_millis(20));
    let first_candidates = krikos_identity::NameCandidateSet::try_new(vec![first_claim]).unwrap();
    let first = verify_name_candidates(&first_candidates, &[first_context])
        .unwrap()
        .as_slice()[0]
        .clone();
    let first_decision = evaluate_name_tofu(None, &first).unwrap();
    let TofuDecision::FirstUse { observation } = first_decision else {
        panic!("expected explicit first-use decision")
    };
    let pinned = observation.clone();
    assert!(matches!(
        evaluate_name_tofu(Some(&pinned), &first).unwrap(),
        TofuDecision::Unchanged { .. }
    ));

    let checkpoint_changed_claim = signed_claim(
        "alice.example",
        &first_secret,
        account_id,
        typed_id::<CheckpointId>(0x35),
        21,
        Some(40),
    );
    let checkpoint_changed_context = context_from_body(
        checkpoint_changed_claim.body(),
        Timestamp::from_unix_millis(22),
    );
    let checkpoint_changed_candidates =
        krikos_identity::NameCandidateSet::try_new(vec![checkpoint_changed_claim]).unwrap();
    let checkpoint_changed = verify_name_candidates(
        &checkpoint_changed_candidates,
        &[checkpoint_changed_context],
    )
    .unwrap()
    .as_slice()[0]
        .clone();
    let checkpoint_decision = evaluate_name_tofu(Some(&pinned), &checkpoint_changed).unwrap();
    let TofuDecision::CheckpointChanged { previous, current } = checkpoint_decision else {
        panic!("expected explicit checkpoint-change decision")
    };
    assert_eq!(previous, pinned);
    assert_ne!(previous.checkpoint_id(), current.checkpoint_id());
    assert!(matches!(
        evaluate_name_tofu(Some(&current), &first).unwrap(),
        TofuDecision::CheckpointChanged { .. }
    ));

    let changed_claim = signed_claim(
        "alice.example",
        &replacement_secret,
        account_id,
        typed_id::<CheckpointId>(0x36),
        23,
        Some(40),
    );
    let changed_context = context_from_body(changed_claim.body(), Timestamp::from_unix_millis(24));
    let changed_candidates =
        krikos_identity::NameCandidateSet::try_new(vec![changed_claim]).unwrap();
    let changed = verify_name_candidates(&changed_candidates, &[changed_context])
        .unwrap()
        .as_slice()[0]
        .clone();
    let decision = evaluate_name_tofu(Some(&pinned), &changed).unwrap();
    let TofuDecision::KeyChanged { previous, current } = decision else {
        panic!("expected explicit key-change decision")
    };
    assert_eq!(previous, pinned);
    assert_ne!(previous.signing_key(), current.signing_key());
    assert_eq!(pinned, observation);
}

#[test]
fn signed_name_claim_vector_is_canonical() {
    let secret = SecretKey::from_bytes(&[0x41; 32]);
    let claim = signed_claim(
        "alice.example",
        &secret,
        typed_id::<AccountId>(0x42),
        typed_id::<CheckpointId>(0x43),
        10,
        Some(20),
    );
    let encoded = claim.to_canonical_bytes().unwrap();
    assert_eq!(
        SignedNameClaim::from_canonical_bytes(&encoded).unwrap(),
        claim
    );
    assert_eq!(
        blake3::hash(&encoded).as_bytes(),
        &[
            0x38, 0x86, 0x8c, 0x61, 0xa6, 0xb0, 0xaa, 0xfa, 0x86, 0xbf, 0x2b, 0xb9, 0x7f, 0xb5,
            0x7b, 0x7e, 0xa7, 0xcb, 0xa5, 0x67, 0x5e, 0xfc, 0x06, 0x70, 0xc6, 0x08, 0x3b, 0x5b,
            0x2e, 0x3b, 0x80, 0xa2,
        ]
    );
}

#[test]
fn tofu_observation_is_an_explicit_value_not_a_mutable_store_handle() {
    fn assert_value_traits<T: Clone + Eq + std::fmt::Debug>() {}
    assert_value_traits::<TofuObservation>();
}
