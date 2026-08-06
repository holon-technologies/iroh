use krikos_base::SecretKey;
use krikos_identity::{
    AccountGenesis, AccountOperation, AccountState, AlgorithmSignature, CanonicalWire,
    ControlPolicy, ControllerClass, ControllerDescriptor, ControllerKeyId, ControllerScope,
    ControllerSelector, ControllerThreshold, ControllerWeight, CryptoSuiteDescriptor, Digest,
    DurableProviderAuditor, DurationMillis, EventBody, EventIntentApprovalBody,
    EventIntentApprovals, EventPredecessors, Extensions, FreshnessRequirement, HashAlgorithm,
    IdentityError, KeyedSignature, MAX_PROVIDER_EXPORT_CHUNK_BYTES,
    MAX_PROVIDER_EXPORT_CHUNK_ITEMS, MAX_PROVIDER_EXPORT_ITEM_BYTES, MemoryProviderAuditStore,
    MemoryProviderStore, OperationKind, PolicyRule, ProtocolSignature, ProviderAdmissionControl,
    ProviderAdmissionRequest, ProviderAuditExportAssembler, ProviderAuditExportChunk,
    ProviderAuditExportManifest, ProviderAuditSnapshot, ProviderDescriptor,
    ProviderEquivocationEvidence, ProviderExportComponent, ProviderExportComponentDescriptor,
    ProviderGenerationExport, ProviderGenerationExportAssembler, ProviderGenerationExportChunk,
    ProviderGenerationExportManifest, ProviderHeadSigner, ProviderId, ProviderKeyVersion,
    ProviderLogId, ProviderPolicy, ProviderPolicyVersion, ProviderQuorum, ProviderRecoveryExport,
    ProviderRecoveryExportManifest, RecoveryAuthority, RecoveryPolicy, RecoveryPolicyVersion,
    RequiredWeight, SignedEventIntentApproval, SignedProviderHead, SigningPublicKey, Timestamp,
    authorize_provider_append, verify_event_intent_admission,
};
use serde::{Deserialize, Serialize};

use krikos_identity::limits::MAX_MERKLE_LOG_LEAVES;

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

struct Allow;

impl ProviderAdmissionControl for Allow {
    fn check(
        &self,
        _admission: krikos_identity::ProviderLogAdmission,
        _request: ProviderAdmissionRequest,
    ) -> Result<(), IdentityError> {
        Ok(())
    }
}

struct Signer(SecretKey);

impl ProviderHeadSigner for Signer {
    fn sign_provider_head(&self, message: &[u8]) -> Result<ProtocolSignature, IdentityError> {
        Ok(ProtocolSignature::ed25519(self.0.sign(message).to_bytes()))
    }
}

fn intent_approval(
    controller_id: krikos_identity::ControllerId,
    proposal_id: krikos_identity::ProposalId,
    signer: &SecretKey,
) -> SignedEventIntentApproval {
    let body =
        EventIntentApprovalBody::new(controller_id, proposal_id, Extensions::default()).unwrap();
    let signing_key = SigningPublicKey::ed25519(*signer.public().as_bytes()).unwrap();
    let signature = signer.sign(&body.to_canonical_bytes().unwrap());
    SignedEventIntentApproval::new(
        body,
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

fn populated_fixture(
    entry_count: usize,
    provider_fill: u8,
    log_fill: u8,
) -> (
    ProviderGenerationExport,
    ProviderAuditSnapshot,
    ProviderRecoveryExport,
) {
    let provider_secret = SecretKey::from_bytes(&[provider_fill; 32]);
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
        DurationMillis::new(1_000),
        Extensions::default(),
    )
    .unwrap();
    let controller_secret = SecretKey::from_bytes(&[0x41; 32]);
    let policy = ControlPolicy::new(
        vec![
            PolicyRule::new(
                OperationKind::AddController,
                RequiredWeight::new(1).unwrap(),
                ControllerSelector::any_active(),
                FreshnessRequirement::latest_known(),
                Some(DurationMillis::new(1)),
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
        [0x51; 32],
        Timestamp::from_unix_millis(1),
        policy,
        vec![controller(&controller_secret)],
        recovery,
        provider_policy,
        Extensions::default(),
    )
    .unwrap();
    let account = AccountState::from_genesis(&genesis).unwrap();
    let controller_id = account.active_controllers()[0].id();
    let operation =
        AccountOperation::AddController(controller(&SecretKey::from_bytes(&[0x52; 32])));
    let log_id = typed_id::<ProviderLogId>(log_fill);
    let store =
        MemoryProviderStore::new(provider.clone(), log_id, ProviderKeyVersion::GENESIS).unwrap();
    let signer = Signer(provider_secret);
    let audit_store = MemoryProviderAuditStore::new(provider.clone(), log_id);
    let auditor = DurableProviderAuditor::new(audit_store);

    for index in 0..entry_count {
        let index = u64::try_from(index).unwrap();
        let nonce_value = index.checked_add(1).unwrap();
        let nonce: [u8; 16] = nonce_value.to_le_bytes().repeat(2).try_into().unwrap();
        let body = EventBody::new(
            account.account_id(),
            account.sequence().checked_next().unwrap(),
            account.expected_epoch_for(&operation).unwrap(),
            EventPredecessors::genesis(account.genesis_anchor()),
            operation.clone(),
            Timestamp::from_unix_millis(index.saturating_add(2)),
            nonce,
            Extensions::default(),
        )
        .unwrap();
        let proposal_id = body.proposal_id().unwrap();
        let approvals = EventIntentApprovals::new(vec![intent_approval(
            controller_id,
            proposal_id,
            &controller_secret,
        )])
        .unwrap();
        let admission = verify_event_intent_admission(&account, &body, &approvals).unwrap();
        let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
        store
            .append(
                authorize_provider_append(admission, request, &Allow).unwrap(),
                Timestamp::from_unix_millis(index.saturating_add(10_000)),
                &signer,
            )
            .unwrap();
        let snapshot = store.snapshot().unwrap();
        let consistency_proof = if index == 0 {
            None
        } else {
            Some(store.consistency_proof(index, index + 1).unwrap())
        };
        auditor
            .observe(
                snapshot.latest_head().unwrap().clone(),
                consistency_proof.as_ref(),
            )
            .unwrap();
    }

    let generation = store.export_generation().unwrap();
    let audit = auditor.snapshot().unwrap();
    let recovery = ProviderRecoveryExport::new(generation.clone(), audit.clone()).unwrap();
    (generation, audit, recovery)
}

fn assert_canonical<T: CanonicalWire + PartialEq + core::fmt::Debug>(value: &T) {
    let bytes = value.to_canonical_bytes().unwrap();
    assert_eq!(T::from_canonical_bytes(&bytes).unwrap(), *value);
}

#[derive(Debug, Serialize, Deserialize)]
struct DescriptorMirror {
    format_version: u16,
    component_code: u16,
    item_count: u64,
    chunk_count: u32,
    total_payload_bytes: u64,
    chunk_list_commitment: Digest,
}

#[derive(Debug, Serialize, Deserialize)]
struct GenerationManifestMirror {
    format_version: u16,
    provider: ProviderDescriptor,
    log_id: ProviderLogId,
    key_version: ProviderKeyVersion,
    tree_size: u64,
    tree_root: Digest,
    latest_head: Option<SignedProviderHead>,
    generation_commitment: Digest,
    total_payload_bytes: u64,
    components: Vec<DescriptorMirror>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GenerationChunkMirror {
    format_version: u16,
    provider_id: ProviderId,
    log_id: ProviderLogId,
    key_version: ProviderKeyVersion,
    generation_commitment: Digest,
    component_code: u16,
    ordinal: u32,
    start_index: u64,
    end_index: u64,
    item_payload_bytes: u64,
    payload: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuditManifestMirror {
    format_version: u16,
    provider: ProviderDescriptor,
    log_id: ProviderLogId,
    latest_head: Option<SignedProviderHead>,
    equivocation: Option<ProviderEquivocationEvidence>,
    record_count: u64,
    chunk_count: u32,
    total_payload_bytes: u64,
    audit_commitment: Digest,
    artifact_count: u64,
    artifact_commitment: Digest,
    chunk_list_commitment: Digest,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuditChunkMirror {
    format_version: u16,
    provider_id: ProviderId,
    log_id: ProviderLogId,
    audit_commitment: Digest,
    ordinal: u32,
    start_sequence: u64,
    end_sequence: u64,
    item_payload_bytes: u64,
    payload: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RecoveryManifestMirror {
    format_version: u16,
    generation: ProviderGenerationExportManifest,
    audit: ProviderAuditExportManifest,
    generation_manifest_commitment: Digest,
    audit_manifest_commitment: Digest,
    generation_commitment: Digest,
    audit_commitment: Digest,
    artifact_commitment: Digest,
    recovery_commitment: Digest,
}

fn generation_manifest_mirror(
    manifest: &ProviderGenerationExportManifest,
) -> GenerationManifestMirror {
    postcard::from_bytes(&manifest.to_canonical_bytes().unwrap()).unwrap()
}

fn generation_manifest_from_mirror(
    mirror: &GenerationManifestMirror,
) -> Result<ProviderGenerationExportManifest, IdentityError> {
    ProviderGenerationExportManifest::from_canonical_bytes(&postcard::to_stdvec(mirror).unwrap())
}

fn generation_chunk_mirror(chunk: &ProviderGenerationExportChunk) -> GenerationChunkMirror {
    postcard::from_bytes(&chunk.to_canonical_bytes().unwrap()).unwrap()
}

fn generation_chunk_from_mirror(
    mirror: &GenerationChunkMirror,
) -> Result<ProviderGenerationExportChunk, IdentityError> {
    ProviderGenerationExportChunk::from_canonical_bytes(&postcard::to_stdvec(mirror).unwrap())
}

fn audit_manifest_mirror(manifest: &ProviderAuditExportManifest) -> AuditManifestMirror {
    postcard::from_bytes(&manifest.to_canonical_bytes().unwrap()).unwrap()
}

fn audit_manifest_from_mirror(
    mirror: &AuditManifestMirror,
) -> Result<ProviderAuditExportManifest, IdentityError> {
    ProviderAuditExportManifest::from_canonical_bytes(&postcard::to_stdvec(mirror).unwrap())
}

fn audit_chunk_mirror(chunk: &ProviderAuditExportChunk) -> AuditChunkMirror {
    postcard::from_bytes(&chunk.to_canonical_bytes().unwrap()).unwrap()
}

fn audit_chunk_from_mirror(
    mirror: &AuditChunkMirror,
) -> Result<ProviderAuditExportChunk, IdentityError> {
    ProviderAuditExportChunk::from_canonical_bytes(&postcard::to_stdvec(mirror).unwrap())
}

fn recovery_manifest_mirror(manifest: &ProviderRecoveryExportManifest) -> RecoveryManifestMirror {
    postcard::from_bytes(&manifest.to_canonical_bytes().unwrap()).unwrap()
}

fn recovery_manifest_from_mirror(
    mirror: &RecoveryManifestMirror,
) -> Result<ProviderRecoveryExportManifest, IdentityError> {
    ProviderRecoveryExportManifest::from_canonical_bytes(&postcard::to_stdvec(mirror).unwrap())
}

#[test]
fn provider_interchange_boundaries_are_canonical_and_fail_closed() {
    let (generation, audit, recovery) = populated_fixture(1, 0x61, 0x62);
    let (generation_manifest, generation_chunks) = generation.interchange_parts().unwrap();
    let (audit_manifest, audit_chunks) = audit.interchange_parts().unwrap();
    let (recovery_manifest, _, _) = recovery.interchange_parts().unwrap();

    assert_canonical(&ProviderExportComponent::Entries);
    assert_canonical(&generation_manifest);
    assert_canonical(&audit_manifest);
    assert_canonical(&recovery_manifest);
    let mut wrong_recovery_version = recovery_manifest_mirror(&recovery_manifest);
    wrong_recovery_version.format_version = 2;
    assert!(recovery_manifest_from_mirror(&wrong_recovery_version).is_err());
    let mut wrong_recovery_commitment = recovery_manifest_mirror(&recovery_manifest);
    wrong_recovery_commitment.recovery_commitment =
        Digest::new(HashAlgorithm::Blake3_256, [0x66; 32]);
    assert!(recovery_manifest_from_mirror(&wrong_recovery_commitment).is_err());
    for chunk in &generation_chunks {
        assert_canonical(chunk);
        assert!(chunk.to_canonical_bytes().unwrap().len() <= MAX_PROVIDER_EXPORT_CHUNK_BYTES);
    }
    for chunk in &audit_chunks {
        assert_canonical(chunk);
        assert!(chunk.to_canonical_bytes().unwrap().len() <= MAX_PROVIDER_EXPORT_CHUNK_BYTES);
    }

    let mut trailing = generation_manifest.to_canonical_bytes().unwrap();
    trailing.push(0);
    assert!(ProviderGenerationExportManifest::from_canonical_bytes(&trailing).is_err());

    let mut wrong_version = generation_manifest_mirror(&generation_manifest);
    wrong_version.format_version = 2;
    assert!(generation_manifest_from_mirror(&wrong_version).is_err());
    assert!(
        ProviderExportComponent::from_canonical_bytes(
            &postcard::to_stdvec(&(1_u16, 99_u16)).unwrap()
        )
        .is_err()
    );
    assert!(ProviderExportComponent::from_canonical_bytes(&[0x81, 0x00, 0x01]).is_err());
    let mut oversized_descriptor: DescriptorMirror = postcard::from_bytes(
        &generation_manifest
            .descriptor(ProviderExportComponent::Entries)
            .unwrap()
            .to_canonical_bytes()
            .unwrap(),
    )
    .unwrap();
    oversized_descriptor.item_count = u64::try_from(MAX_MERKLE_LOG_LEAVES + 1).unwrap();
    assert!(
        ProviderExportComponentDescriptor::from_canonical_bytes(
            &postcard::to_stdvec(&oversized_descriptor).unwrap()
        )
        .is_err()
    );
    assert!(
        ProviderGenerationExportChunk::from_canonical_bytes(&vec![
            0;
            MAX_PROVIDER_EXPORT_CHUNK_BYTES
                + 1
        ])
        .is_err()
    );

    let mut oversized_item = generation_chunk_mirror(&generation_chunks[0]);
    oversized_item.start_index = 0;
    oversized_item.end_index = 1;
    oversized_item.item_payload_bytes = u64::try_from(MAX_PROVIDER_EXPORT_ITEM_BYTES + 1).unwrap();
    oversized_item.payload =
        postcard::to_stdvec(&vec![vec![0_u8; MAX_PROVIDER_EXPORT_ITEM_BYTES + 1]]).unwrap();
    assert!(generation_chunk_from_mirror(&oversized_item).is_err());

    let (empty_generation, _, _) = populated_fixture(0, 0x63, 0x64);
    let (empty_manifest, empty_chunks) = empty_generation.interchange_parts().unwrap();
    assert!(empty_chunks.is_empty());
    let mut bad_empty_root = generation_manifest_mirror(&empty_manifest);
    bad_empty_root.tree_root = Digest::new(HashAlgorithm::Blake3_256, [0x65; 32]);
    assert!(generation_manifest_from_mirror(&bad_empty_root).is_err());
}

#[test]
fn provider_interchange_assembles_out_of_order_and_rejects_tampering() {
    let (generation, audit, recovery_257) =
        populated_fixture(MAX_PROVIDER_EXPORT_CHUNK_ITEMS + 1, 0x71, 0x72);
    assert_eq!(recovery_257.audit().records().len(), 257);
    let (manifest, chunks) = generation.interchange_parts().unwrap();
    let entries = manifest
        .descriptor(ProviderExportComponent::Entries)
        .unwrap();
    assert_eq!(entries.item_count(), 257);
    assert_eq!(entries.chunk_count(), 2);

    let mut reversed = chunks.clone();
    reversed.reverse();
    let replay = reversed.remove(0);
    let mut assembler = ProviderGenerationExportAssembler::new(manifest.clone()).unwrap();
    assert!(assembler.insert(replay.clone()).unwrap());
    assert!(!assembler.insert(replay).unwrap());
    for chunk in reversed {
        assert!(assembler.insert(chunk).unwrap());
    }
    assert_eq!(assembler.finish().unwrap(), generation);

    let mut incomplete = ProviderGenerationExportAssembler::new(manifest.clone()).unwrap();
    for chunk in chunks.iter().take(chunks.len() - 1).cloned() {
        incomplete.insert(chunk).unwrap();
    }
    assert!(incomplete.finish().is_err());

    let entry_chunks = chunks
        .iter()
        .filter(|chunk| chunk.component().unwrap() == ProviderExportComponent::Entries)
        .cloned()
        .collect::<Vec<_>>();
    let mut conflicting = generation_chunk_mirror(&entry_chunks[1]);
    conflicting.ordinal = 0;
    let conflicting = generation_chunk_from_mirror(&conflicting).unwrap();
    let mut conflict_assembler = ProviderGenerationExportAssembler::new(manifest.clone()).unwrap();
    conflict_assembler.insert(entry_chunks[0].clone()).unwrap();
    assert!(conflict_assembler.insert(conflicting).is_err());

    let mut overlap = generation_chunk_mirror(&entry_chunks[1]);
    overlap.start_index -= 1;
    overlap.end_index -= 1;
    let overlap = generation_chunk_from_mirror(&overlap).unwrap();
    let mut overlap_assembler = ProviderGenerationExportAssembler::new(manifest.clone()).unwrap();
    for chunk in chunks.iter().cloned() {
        if chunk.component().unwrap() == ProviderExportComponent::Entries && chunk.ordinal() == 1 {
            overlap_assembler.insert(overlap.clone()).unwrap();
        } else {
            overlap_assembler.insert(chunk).unwrap();
        }
    }
    assert!(overlap_assembler.finish().is_err());

    let mut gap = generation_chunk_mirror(&entry_chunks[0]);
    gap.start_index += 1;
    gap.end_index += 1;
    let gap = generation_chunk_from_mirror(&gap).unwrap();
    let mut gap_assembler = ProviderGenerationExportAssembler::new(manifest.clone()).unwrap();
    for chunk in chunks.iter().cloned() {
        if chunk.component().unwrap() == ProviderExportComponent::Entries && chunk.ordinal() == 0 {
            gap_assembler.insert(gap.clone()).unwrap();
        } else {
            gap_assembler.insert(chunk).unwrap();
        }
    }
    assert!(gap_assembler.finish().is_err());

    let mut tampered_manifest = generation_manifest_mirror(&manifest);
    let entry_descriptor = tampered_manifest
        .components
        .iter_mut()
        .find(|descriptor| descriptor.component_code == ProviderExportComponent::Entries.code())
        .unwrap();
    entry_descriptor.chunk_list_commitment = Digest::new(HashAlgorithm::Blake3_256, [0x73; 32]);
    let tampered_manifest = generation_manifest_from_mirror(&tampered_manifest).unwrap();
    let mut root_assembler = ProviderGenerationExportAssembler::new(tampered_manifest).unwrap();
    for chunk in chunks.iter().cloned() {
        root_assembler.insert(chunk).unwrap();
    }
    assert!(root_assembler.finish().is_err());

    let (foreign_generation, foreign_audit, _) = populated_fixture(1, 0x74, 0x75);
    let (_, foreign_chunks) = foreign_generation.interchange_parts().unwrap();
    let mut cross_manifest = ProviderGenerationExportAssembler::new(manifest.clone()).unwrap();
    assert!(cross_manifest.insert(foreign_chunks[0].clone()).is_err());

    let (audit_manifest, audit_chunks) = audit.interchange_parts().unwrap();
    assert_eq!(audit_manifest.record_count(), 257);
    assert_eq!(audit_manifest.chunk_count(), 2);

    let mut bad_payload_accounting = audit_chunk_mirror(&audit_chunks[0]);
    bad_payload_accounting.item_payload_bytes += 1;
    assert!(audit_chunk_from_mirror(&bad_payload_accounting).is_err());

    let mut conflicting_audit = audit_chunk_mirror(&audit_chunks[1]);
    conflicting_audit.ordinal = 0;
    let conflicting_audit = audit_chunk_from_mirror(&conflicting_audit).unwrap();
    let mut audit_conflict = ProviderAuditExportAssembler::new(audit_manifest.clone()).unwrap();
    audit_conflict.insert(audit_chunks[0].clone()).unwrap();
    assert!(audit_conflict.insert(conflicting_audit).is_err());

    let mut overlapping_audit = audit_chunk_mirror(&audit_chunks[1]);
    overlapping_audit.start_sequence -= 1;
    overlapping_audit.end_sequence -= 1;
    let overlapping_audit = audit_chunk_from_mirror(&overlapping_audit).unwrap();
    let mut audit_overlap = ProviderAuditExportAssembler::new(audit_manifest.clone()).unwrap();
    audit_overlap.insert(audit_chunks[0].clone()).unwrap();
    audit_overlap.insert(overlapping_audit).unwrap();
    assert!(audit_overlap.finish().is_err());

    let mut tampered_audit_manifest = audit_manifest_mirror(&audit_manifest);
    tampered_audit_manifest.chunk_list_commitment =
        Digest::new(HashAlgorithm::Blake3_256, [0x76; 32]);
    let tampered_audit_manifest = audit_manifest_from_mirror(&tampered_audit_manifest).unwrap();
    let mut audit_root = ProviderAuditExportAssembler::new(tampered_audit_manifest).unwrap();
    for chunk in audit_chunks.iter().cloned() {
        audit_root.insert(chunk).unwrap();
    }
    assert!(audit_root.finish().is_err());

    let (_, foreign_audit_chunks) = foreign_audit.interchange_parts().unwrap();
    let mut audit_cross = ProviderAuditExportAssembler::new(audit_manifest.clone()).unwrap();
    assert!(audit_cross.insert(foreign_audit_chunks[0].clone()).is_err());

    let mut reversed_audit_chunks = audit_chunks.clone();
    reversed_audit_chunks.reverse();
    let replay = reversed_audit_chunks[0].clone();
    let mut audit_assembler = ProviderAuditExportAssembler::new(audit_manifest).unwrap();
    assert!(audit_assembler.insert(replay.clone()).unwrap());
    assert!(!audit_assembler.insert(replay).unwrap());
    for chunk in reversed_audit_chunks.into_iter().skip(1) {
        audit_assembler.insert(chunk).unwrap();
    }
    let rebuilt_audit = audit_assembler.finish().unwrap();
    assert_eq!(rebuilt_audit, audit);

    let (_, _, recovery) = populated_fixture(2, 0x77, 0x78);
    let (recovery_manifest, generation_chunks, audit_chunks) =
        recovery.interchange_parts().unwrap();
    let mut generation_assembler =
        ProviderGenerationExportAssembler::new(recovery_manifest.generation().clone()).unwrap();
    for chunk in generation_chunks.into_iter().rev() {
        generation_assembler.insert(chunk).unwrap();
    }
    let mut audit_assembler =
        ProviderAuditExportAssembler::new(recovery_manifest.audit().clone()).unwrap();
    for chunk in audit_chunks.into_iter().rev() {
        audit_assembler.insert(chunk).unwrap();
    }
    assert_eq!(
        recovery_manifest
            .finish(
                generation_assembler.finish().unwrap(),
                audit_assembler.finish().unwrap(),
            )
            .unwrap(),
        recovery
    );
}

#[test]
fn provider_recovery_manifest_rejects_incomplete_component_finish() {
    let (_, _, recovery) = populated_fixture(2, 0x81, 0x82);
    let (manifest, generation_chunks, audit_chunks) = recovery.interchange_parts().unwrap();
    assert_canonical::<ProviderRecoveryExportManifest>(&manifest);

    let mut generation =
        ProviderGenerationExportAssembler::new(manifest.generation().clone()).unwrap();
    for chunk in generation_chunks {
        generation.insert(chunk).unwrap();
    }
    let generation = generation.finish().unwrap();
    let incomplete_audit = ProviderAuditExportAssembler::new(manifest.audit().clone()).unwrap();
    assert!(incomplete_audit.finish().is_err());
    assert_ne!(generation.latest_head(), None);
    assert!(!audit_chunks.is_empty());
}
