use krikos_base::SecretKey;
use krikos_identity::{
    AccountId, AuthorizationContext, CanonicalWire, CheckpointId, Digest, DurationMillis, Epoch,
    Extensions, FreshnessEvidence, FreshnessRequirement, HashAlgorithm, IdentityError,
    InclusionReceipt, ProtocolSignature, ProviderDescriptor, ProviderFreshness, ProviderHeadBody,
    ProviderKeyVersion, ProviderLogEntryBody, ProviderLogId, ProviderLogSubject, ProviderPolicy,
    ProviderPolicyVersion, ProviderQuorum, ProviderReceipts, SignedProviderHead, SigningPublicKey,
    Timestamp, evaluate_freshness,
};

fn typed_id<T: CanonicalWire>(fill: u8) -> T {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [fill; 32]);
    T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
}

fn descriptor(secret: &SecretKey) -> ProviderDescriptor {
    ProviderDescriptor::new(
        SigningPublicKey::ed25519(*secret.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap()
}

fn receipt(
    secret: &SecretKey,
    provider: &ProviderDescriptor,
    context: AuthorizationContext,
    entry_time: u64,
    head_time: u64,
    fill: u8,
) -> InclusionReceipt {
    let entry = ProviderLogEntryBody::new(
        provider.id().unwrap(),
        typed_id::<ProviderLogId>(fill),
        context.account_id(),
        ProviderLogSubject::Checkpoint(context.checkpoint_id()),
        Timestamp::from_unix_millis(entry_time),
        Extensions::default(),
    )
    .unwrap();
    let body = ProviderHeadBody::new(
        provider.id().unwrap(),
        entry.log_id(),
        ProviderKeyVersion::GENESIS,
        1,
        entry.merkle_leaf_hash().unwrap(),
        Timestamp::from_unix_millis(head_time),
        Extensions::default(),
    )
    .unwrap();
    let signature = secret.sign(&body.signing_bytes().unwrap());
    InclusionReceipt::new(
        entry,
        0,
        Vec::new(),
        SignedProviderHead::new(body, ProtocolSignature::ed25519(signature.to_bytes())),
    )
    .unwrap()
}

#[test]
fn caller_and_account_freshness_combine_only_monotonically() {
    let first_secret = SecretKey::from_bytes(&[0x21; 32]);
    let second_secret = SecretKey::from_bytes(&[0x22; 32]);
    let first = descriptor(&first_secret);
    let second = descriptor(&second_secret);
    let policy = ProviderPolicy::replicated(
        ProviderPolicyVersion::GENESIS,
        vec![first.clone(), second.clone()],
        ProviderQuorum::new(1).unwrap(),
        ProviderQuorum::new(2).unwrap(),
        DurationMillis::new(100),
        Extensions::default(),
    )
    .unwrap();
    let context = AuthorizationContext::new(
        typed_id::<AccountId>(0x31),
        Epoch::new(7),
        typed_id::<CheckpointId>(0x32),
    );
    let receipts = ProviderReceipts::new(vec![
        receipt(&first_secret, &first, context, 10, 60, 0x41),
        receipt(&second_secret, &second, context, 20, 70, 0x42),
    ])
    .unwrap();
    let evidence =
        FreshnessEvidence::provider_quorum(context.checkpoint_id(), policy.id().unwrap(), receipts)
            .unwrap();
    let account_requirement = FreshnessRequirement::provider_quorum(
        ProviderFreshness::new(ProviderQuorum::new(1).unwrap(), DurationMillis::new(100)).unwrap(),
    );
    let caller_requirement = FreshnessRequirement::provider_quorum(
        ProviderFreshness::new(ProviderQuorum::new(2).unwrap(), DurationMillis::new(50)).unwrap(),
    );

    let decision = evaluate_freshness(
        context,
        &policy,
        account_requirement,
        caller_requirement,
        &evidence,
        Timestamp::from_unix_millis(60),
    )
    .unwrap();
    assert_eq!(decision.context(), context);
    assert_eq!(
        decision.required_quorum(),
        Some(ProviderQuorum::new(2).unwrap())
    );
    assert_eq!(decision.maximum_age(), Some(DurationMillis::new(50)));
    assert_eq!(
        decision.provider_observed_at(),
        Some(Timestamp::from_unix_millis(20))
    );
}

#[test]
fn latest_known_makes_no_online_or_provider_time_claim() {
    let policy =
        ProviderPolicy::local_only(ProviderPolicyVersion::GENESIS, Extensions::default()).unwrap();
    let context = AuthorizationContext::new(
        typed_id::<AccountId>(0x33),
        Epoch::new(2),
        typed_id::<CheckpointId>(0x34),
    );
    let decision = evaluate_freshness(
        context,
        &policy,
        FreshnessRequirement::latest_known(),
        FreshnessRequirement::latest_known(),
        &FreshnessEvidence::local_known(context.checkpoint_id()),
        Timestamp::from_unix_millis(1),
    )
    .unwrap();
    assert_eq!(decision.provider_observed_at(), None);
    assert_eq!(decision.required_quorum(), None);
}

#[test]
fn provider_rotation_and_exact_signed_age_boundary_fail_closed() {
    let old_secret = SecretKey::from_bytes(&[0x23; 32]);
    let current_secret = SecretKey::from_bytes(&[0x24; 32]);
    let old_provider = descriptor(&old_secret);
    let current_provider = descriptor(&current_secret);
    let policy = ProviderPolicy::replicated(
        ProviderPolicyVersion::new(2),
        vec![current_provider.clone()],
        ProviderQuorum::new(1).unwrap(),
        ProviderQuorum::new(1).unwrap(),
        DurationMillis::new(100),
        Extensions::default(),
    )
    .unwrap();
    let context = AuthorizationContext::new(
        typed_id::<AccountId>(0x35),
        Epoch::new(3),
        typed_id::<CheckpointId>(0x36),
    );
    let requirement = FreshnessRequirement::provider_quorum(
        ProviderFreshness::new(ProviderQuorum::new(1).unwrap(), DurationMillis::new(100)).unwrap(),
    );

    let rotated_out = FreshnessEvidence::provider_quorum(
        context.checkpoint_id(),
        policy.id().unwrap(),
        ProviderReceipts::new(vec![receipt(
            &old_secret,
            &old_provider,
            context,
            100,
            100,
            0x43,
        )])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        evaluate_freshness(
            context,
            &policy,
            requirement,
            requirement,
            &rotated_out,
            Timestamp::from_unix_millis(100),
        ),
        Err(IdentityError::FreshnessUnavailable)
    );

    let exact_boundary = FreshnessEvidence::provider_quorum(
        context.checkpoint_id(),
        policy.id().unwrap(),
        ProviderReceipts::new(vec![receipt(
            &current_secret,
            &current_provider,
            context,
            100,
            200,
            0x44,
        )])
        .unwrap(),
    )
    .unwrap();
    let decision = evaluate_freshness(
        context,
        &policy,
        requirement,
        FreshnessRequirement::latest_known(),
        &exact_boundary,
        Timestamp::from_unix_millis(200),
    )
    .unwrap();
    assert_eq!(
        decision.provider_observed_at(),
        Some(Timestamp::from_unix_millis(100))
    );

    let stale = FreshnessEvidence::provider_quorum(
        context.checkpoint_id(),
        policy.id().unwrap(),
        ProviderReceipts::new(vec![receipt(
            &current_secret,
            &current_provider,
            context,
            100,
            201,
            0x45,
        )])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        evaluate_freshness(
            context,
            &policy,
            requirement,
            requirement,
            &stale,
            Timestamp::from_unix_millis(201),
        ),
        Err(IdentityError::StaleEvidence)
    );

    let impossible_caller = FreshnessRequirement::provider_quorum(
        ProviderFreshness::new(ProviderQuorum::new(2).unwrap(), DurationMillis::new(100)).unwrap(),
    );
    assert_eq!(
        evaluate_freshness(
            context,
            &policy,
            requirement,
            impossible_caller,
            &exact_boundary,
            Timestamp::from_unix_millis(200),
        ),
        Err(IdentityError::FreshnessUnavailable)
    );
}

#[test]
fn initial_receipt_replay_expires_at_explicit_verifier_time() {
    let provider_secret = SecretKey::from_bytes(&[0x51; 32]);
    let provider = descriptor(&provider_secret);
    let policy = ProviderPolicy::replicated(
        ProviderPolicyVersion::GENESIS,
        vec![provider.clone()],
        ProviderQuorum::new(1).unwrap(),
        ProviderQuorum::new(1).unwrap(),
        DurationMillis::new(100),
        Extensions::default(),
    )
    .unwrap();
    let context = AuthorizationContext::new(
        typed_id::<AccountId>(0x52),
        Epoch::new(4),
        typed_id::<CheckpointId>(0x53),
    );
    let requirement = FreshnessRequirement::provider_quorum(
        ProviderFreshness::new(ProviderQuorum::new(1).unwrap(), DurationMillis::new(100)).unwrap(),
    );
    let evidence = FreshnessEvidence::provider_quorum(
        context.checkpoint_id(),
        policy.id().unwrap(),
        ProviderReceipts::new(vec![receipt(
            &provider_secret,
            &provider,
            context,
            100,
            100,
            0x54,
        )])
        .unwrap(),
    )
    .unwrap();

    assert_eq!(
        evaluate_freshness(
            context,
            &policy,
            requirement,
            requirement,
            &evidence,
            Timestamp::from_unix_millis(10_000),
        ),
        Err(IdentityError::StaleEvidence)
    );

    let replay_under_later_head = FreshnessEvidence::provider_quorum(
        context.checkpoint_id(),
        policy.id().unwrap(),
        ProviderReceipts::new(vec![receipt(
            &provider_secret,
            &provider,
            context,
            100,
            10_000,
            0x55,
        )])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        evaluate_freshness(
            context,
            &policy,
            requirement,
            requirement,
            &replay_under_later_head,
            Timestamp::from_unix_millis(10_000),
        ),
        Err(IdentityError::StaleEvidence)
    );
}
