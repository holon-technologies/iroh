use krikos_base::SecretKey;
use krikos_identity::{
    AccountId, CanonicalWire, CheckpointId, Digest, Extensions, HashAlgorithm, IdentityError,
    InclusionReceipt, ProtocolSignature, ProviderDescriptor, ProviderEquivocationEvidence,
    ProviderHeadAuditDisposition, ProviderHeadAuditor, ProviderHeadBody, ProviderKeyVersion,
    ProviderLogEntryBody, ProviderLogId, ProviderLogSubject, SignedProviderHead, SigningPublicKey,
    Timestamp, merkle::AppendOnlyMerkleLog, verify_provider_head_progression,
};

fn typed_id<T: CanonicalWire>(seed: u8) -> T {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [seed; 32]);
    T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
}

fn provider_descriptor(secret: &SecretKey) -> ProviderDescriptor {
    ProviderDescriptor::new(
        SigningPublicKey::ed25519(*secret.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap()
}

fn entry(provider: &ProviderDescriptor, observed_at: u64) -> ProviderLogEntryBody {
    ProviderLogEntryBody::new(
        provider.id().unwrap(),
        typed_id::<ProviderLogId>(0x42),
        typed_id::<AccountId>(0x43),
        ProviderLogSubject::Checkpoint(typed_id::<CheckpointId>(0x44)),
        Timestamp::from_unix_millis(observed_at),
        Extensions::default(),
    )
    .unwrap()
}

fn signed_head(
    secret: &SecretKey,
    provider: &ProviderDescriptor,
    tree_root: Digest,
    tree_size: u64,
    observed_at: u64,
) -> SignedProviderHead {
    let body = ProviderHeadBody::new(
        provider.id().unwrap(),
        typed_id::<ProviderLogId>(0x42),
        ProviderKeyVersion::GENESIS,
        tree_size,
        tree_root,
        Timestamp::from_unix_millis(observed_at),
        Extensions::default(),
    )
    .unwrap();
    let signature = secret.sign(&body.signing_bytes().unwrap());
    SignedProviderHead::new(body, ProtocolSignature::ed25519(signature.to_bytes()))
}

#[test]
fn provider_head_signature_and_single_leaf_receipt_verify() {
    let secret = SecretKey::from_bytes(&[0x71; 32]);
    let provider = provider_descriptor(&secret);
    let entry = entry(&provider, 100);
    let root = entry.merkle_leaf_hash().unwrap();
    let head = signed_head(&secret, &provider, root, 1, 105);
    let receipt = InclusionReceipt::new(entry, 0, Vec::new(), head).unwrap();

    receipt.verify(&provider).unwrap();
    assert_eq!(receipt.leaf_index(), 0);
    assert_eq!(receipt.signed_head().body().tree_root(), root);
    assert!(
        receipt
            .signed_head()
            .body()
            .signing_bytes()
            .unwrap()
            .starts_with(b"KRIKOS-ID/provider-head-signature/v1\0")
    );
}

#[test]
fn provider_receipt_rejects_signature_root_path_and_time_substitution() {
    let secret = SecretKey::from_bytes(&[0x72; 32]);
    let provider = provider_descriptor(&secret);
    let entry = entry(&provider, 200);
    let leaf = entry.merkle_leaf_hash().unwrap();

    let invalid_signature = InclusionReceipt::new(
        entry.clone(),
        0,
        Vec::new(),
        SignedProviderHead::new(
            signed_head(&secret, &provider, leaf, 1, 210).body().clone(),
            ProtocolSignature::ed25519([0; 64]),
        ),
    )
    .unwrap();
    assert_eq!(
        invalid_signature.verify(&provider),
        Err(IdentityError::InvalidSignature)
    );

    let wrong_root = Digest::new(HashAlgorithm::Blake3_256, [0x99; 32]);
    let bad_root = InclusionReceipt::new(
        entry.clone(),
        0,
        Vec::new(),
        signed_head(&secret, &provider, wrong_root, 1, 210),
    )
    .unwrap();
    assert_eq!(bad_root.verify(&provider), Err(IdentityError::InvalidProof));

    let extra_path = InclusionReceipt::new(
        entry.clone(),
        0,
        vec![leaf],
        signed_head(&secret, &provider, leaf, 1, 210),
    )
    .unwrap();
    assert_eq!(
        extra_path.verify(&provider),
        Err(IdentityError::InvalidProof)
    );

    let backwards_time = InclusionReceipt::new(
        entry,
        0,
        Vec::new(),
        signed_head(&secret, &provider, leaf, 1, 199),
    )
    .unwrap();
    assert!(matches!(
        backwards_time.verify(&provider),
        Err(IdentityError::InvalidRelationship { .. })
    ));
}

#[test]
fn provider_receipt_rejects_wrong_descriptor_and_key_version() {
    let secret = SecretKey::from_bytes(&[0x73; 32]);
    let provider = provider_descriptor(&secret);
    let entry = entry(&provider, 300);
    let leaf = entry.merkle_leaf_hash().unwrap();
    let receipt = InclusionReceipt::new(
        entry.clone(),
        0,
        Vec::new(),
        signed_head(&secret, &provider, leaf, 1, 301),
    )
    .unwrap();
    let other = provider_descriptor(&SecretKey::from_bytes(&[0x74; 32]));
    assert!(matches!(
        receipt.verify(&other),
        Err(IdentityError::InvalidRelationship { .. })
    ));

    let body = ProviderHeadBody::new(
        provider.id().unwrap(),
        entry.log_id(),
        ProviderKeyVersion::new(1),
        1,
        leaf,
        Timestamp::from_unix_millis(301),
        Extensions::default(),
    )
    .unwrap();
    let signature = secret.sign(&body.signing_bytes().unwrap());
    let wrong_version = InclusionReceipt::new(
        entry,
        0,
        Vec::new(),
        SignedProviderHead::new(body, ProtocolSignature::ed25519(signature.to_bytes())),
    )
    .unwrap();
    assert!(matches!(
        wrong_version.verify(&provider),
        Err(IdentityError::InvalidRelationship { .. })
    ));
}

#[test]
fn signed_head_progression_detects_rollback_and_durable_equivocation() {
    let secret = SecretKey::from_bytes(&[0x75; 32]);
    let provider = provider_descriptor(&secret);
    let mut log = AppendOnlyMerkleLog::new();
    log.append(entry(&provider, 400).merkle_leaf_hash().unwrap())
        .unwrap();
    let first_root = log.root().unwrap();
    let first = signed_head(&secret, &provider, first_root, 1, 401);
    log.append(entry(&provider, 402).merkle_leaf_hash().unwrap())
        .unwrap();
    let second = signed_head(&secret, &provider, log.root().unwrap(), 2, 403);

    verify_provider_head_progression(
        &provider,
        &first,
        &second,
        &log.consistency_proof(1).unwrap(),
    )
    .unwrap();
    assert_eq!(
        verify_provider_head_progression(
            &provider,
            &second,
            &first,
            &log.consistency_proof(1).unwrap(),
        ),
        Err(IdentityError::ProviderRollback)
    );

    let conflicting = signed_head(&secret, &provider, digest(0x99), 2, 404);
    assert_eq!(
        verify_provider_head_progression(
            &provider,
            &second,
            &conflicting,
            &log.consistency_proof(2).unwrap(),
        ),
        Err(IdentityError::ProviderEquivocation)
    );
    let evidence = ProviderEquivocationEvidence::new(&provider, second, conflicting).unwrap();
    let encoded = evidence.to_canonical_bytes().unwrap();
    assert_eq!(
        ProviderEquivocationEvidence::from_canonical_bytes(&encoded).unwrap(),
        evidence
    );
}

#[test]
fn auditor_pins_log_generation_and_retains_first_equivocation() {
    let secret = SecretKey::from_bytes(&[0x76; 32]);
    let provider = provider_descriptor(&secret);
    let log_id = typed_id::<ProviderLogId>(0x42);
    let mut log = AppendOnlyMerkleLog::new();
    log.append(entry(&provider, 500).merkle_leaf_hash().unwrap())
        .unwrap();
    let first = signed_head(&secret, &provider, log.root().unwrap(), 1, 501);
    let mut auditor = ProviderHeadAuditor::new(provider.clone(), log_id);
    assert_eq!(
        auditor.observe(first.clone(), None).unwrap(),
        ProviderHeadAuditDisposition::FirstObserved
    );

    let wrong_log_body = ProviderHeadBody::new(
        provider.id().unwrap(),
        typed_id::<ProviderLogId>(0x77),
        ProviderKeyVersion::GENESIS,
        1,
        log.root().unwrap(),
        Timestamp::from_unix_millis(502),
        Extensions::default(),
    )
    .unwrap();
    let wrong_log_signature = secret.sign(&wrong_log_body.signing_bytes().unwrap());
    let before_wrong_log = auditor.clone();
    assert!(matches!(
        auditor.observe(
            SignedProviderHead::new(
                wrong_log_body,
                ProtocolSignature::ed25519(wrong_log_signature.to_bytes()),
            ),
            None,
        ),
        Err(IdentityError::InvalidRelationship { .. })
    ));
    assert_eq!(auditor, before_wrong_log);

    let refreshed = signed_head(&secret, &provider, log.root().unwrap(), 1, 503);
    assert_eq!(
        auditor.observe(refreshed, None).unwrap(),
        ProviderHeadAuditDisposition::HeadRefreshed
    );
    log.append(entry(&provider, 504).merkle_leaf_hash().unwrap())
        .unwrap();
    let advanced = signed_head(&secret, &provider, log.root().unwrap(), 2, 505);
    assert_eq!(
        auditor
            .observe(advanced.clone(), Some(&log.consistency_proof(1).unwrap()))
            .unwrap(),
        ProviderHeadAuditDisposition::TreeAdvanced
    );
    let before_rollback = auditor.clone();
    assert_eq!(
        auditor.observe(first, None),
        Err(IdentityError::ProviderRollback)
    );
    assert_eq!(auditor, before_rollback);

    let conflicting = signed_head(&secret, &provider, digest(0x9a), 2, 506);
    assert_eq!(
        auditor.observe(conflicting, None),
        Err(IdentityError::ProviderEquivocation)
    );
    auditor
        .equivocation_evidence()
        .unwrap()
        .verify(&provider)
        .unwrap();
    assert_eq!(auditor.latest_head(), Some(&advanced));
    assert_eq!(
        auditor.observe(advanced, None),
        Err(IdentityError::ProviderEquivocation)
    );
}

fn digest(fill: u8) -> Digest {
    Digest::new(HashAlgorithm::Blake3_256, [fill; 32])
}

#[test]
fn provider_leaf_head_and_append_proofs_match_frozen_vectors() {
    fn digest_hex(value: &str) -> Digest {
        let bytes: [u8; 32] = hex::decode(value).unwrap().try_into().unwrap();
        Digest::new(HashAlgorithm::Blake3_256, bytes)
    }

    fn raw_hash(domain: &[u8], payload: &[u8]) -> Digest {
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        hasher.update(&[0]);
        hasher.update(payload);
        Digest::new(HashAlgorithm::Blake3_256, *hasher.finalize().as_bytes())
    }

    let secret = SecretKey::from_bytes(&[0x71; 32]);
    let provider = provider_descriptor(&secret);
    let first_entry = entry(&provider, 100);
    let entry_wire = first_entry.to_canonical_bytes().unwrap();
    assert_eq!(
        hex::encode(&entry_wire),
        "0101b3cee1bf5a7e0941686c9d3395a04086c25b94838b272b4da873ea39d6fb5ba0014242424242424242424242424242424242424242424242424242424242424242014343434343434343434343434343434343434343434343434343434343434343010144444444444444444444444444444444444444444444444444444444444444446400"
    );
    let first_leaf = first_entry.merkle_leaf_hash().unwrap();
    assert_eq!(
        first_leaf,
        digest_hex("e26e2eefa64f1da02e71fa98226c34fe43e307cfa149c6bb355e168656a33c44")
    );
    assert_eq!(
        first_leaf,
        raw_hash(b"KRIKOS-ID/provider-log-entry/v1", &entry_wire)
    );

    let first_head = signed_head(&secret, &provider, first_leaf, 1, 105);
    assert_eq!(
        hex::encode(first_head.body().to_canonical_bytes().unwrap()),
        "0101b3cee1bf5a7e0941686c9d3395a04086c25b94838b272b4da873ea39d6fb5ba0014242424242424242424242424242424242424242424242424242424242424242000101e26e2eefa64f1da02e71fa98226c34fe43e307cfa149c6bb355e168656a33c446900"
    );
    assert_eq!(
        hex::encode(first_head.body().signing_bytes().unwrap()),
        "4b52494b4f532d49442f70726f76696465722d686561642d7369676e61747572652f7631000101b3cee1bf5a7e0941686c9d3395a04086c25b94838b272b4da873ea39d6fb5ba0014242424242424242424242424242424242424242424242424242424242424242000101e26e2eefa64f1da02e71fa98226c34fe43e307cfa149c6bb355e168656a33c446900"
    );
    assert_eq!(
        hex::encode(first_head.signature().as_bytes()),
        "af72f387a09078cc766e7b6afa7cfbdb6be6d4c1a3ced76fe1534332a89a642de3e9919ae0dd072c36cddee99e7a5f0a80984d3918f29865c39e714d022ac50d"
    );
    first_head.verify(&provider).unwrap();

    let second_entry = entry(&provider, 101);
    let second_leaf = second_entry.merkle_leaf_hash().unwrap();
    assert_eq!(
        second_leaf,
        digest_hex("bb7957c02cd486f406209c28dd8ee911d1b4c9f733239cdb67f56af028323721")
    );
    let log = AppendOnlyMerkleLog::from_leaf_hashes(vec![first_leaf, second_leaf]).unwrap();
    let expected_root =
        digest_hex("0e54dda3746ab990a6449e27d1e8474546e3c365fad260ce0bc5cd2b66a2c9fe");
    assert_eq!(log.root().unwrap(), expected_root);
    let mut node_payload = Vec::with_capacity(66);
    node_payload.push(1);
    node_payload.extend_from_slice(first_leaf.as_bytes());
    node_payload.push(1);
    node_payload.extend_from_slice(second_leaf.as_bytes());
    assert_eq!(
        expected_root,
        raw_hash(b"KRIKOS-ID/merkle-node/v1", &node_payload)
    );
    assert_eq!(log.inclusion_proof(0).unwrap().audit_path(), &[second_leaf]);
    assert_eq!(
        log.consistency_proof(1).unwrap().audit_path(),
        &[second_leaf]
    );
}
