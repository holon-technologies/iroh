#![no_main]

use std::{
    fs::{self, OpenOptions},
    path::Path,
};

use krikos_base::SecretKey;
use krikos_identity::{
    AccountGenesis, AccountOperation, AccountState, AdmissionEvidence, AlgorithmSignature,
    CanonicalWire, CheckpointAuthorization, CheckpointId, ControlPolicy, ControllerApprovalBody,
    ControllerApprovals, ControllerClass, ControllerDescriptor, ControllerKeyId, ControllerScope,
    ControllerSelector, ControllerThreshold, ControllerWeight, CryptoSuiteDescriptor,
    DelayEvidence, Digest, DurableProviderAuditor, DurationMillis, EventBody, EventPredecessors,
    Extensions, FreshnessEvidence, FreshnessRequirement, HashAlgorithm, IdentityError,
    KeyedSignature, MemoryProviderAuditStore, MemoryProviderStore, OpaqueProviderAnchorCommitment,
    OperationKind, PolicyRule, ProtocolSignature, ProviderAdmissionControl,
    ProviderAdmissionRequest, ProviderAuditExportChunk, ProviderAuditExportManifest,
    ProviderCheckpointBundle, ProviderCompactionManifest, ProviderDescriptor,
    ProviderExportComponent, ProviderExportComponentDescriptor, ProviderGenerationExport,
    ProviderGenerationExportChunk, ProviderGenerationExportManifest, ProviderGenerationSnapshot,
    ProviderHeadSigner, ProviderKeyVersion, ProviderLogId, ProviderPolicy, ProviderPolicyVersion,
    ProviderRecoveryExport, ProviderRecoveryExportManifest, RecoveryAuthority, RecoveryPolicy,
    RecoveryPolicyVersion, RedbProviderStore, RequiredWeight, Sequence, SignedCheckpoint,
    SignedControllerApproval, SigningPublicKey, Timestamp, authorize_provider_append,
    build_checkpoint_body, build_provider_checkpoint_bundle_from_genesis,
    derive_provider_retention_inventory, verify_checkpoint, verify_provider_compaction,
};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_INPUT_BYTES: usize = 4_096;
const MAX_HISTORY_BYTES: usize = 4 * 1_024 * 1_024;

struct AllowAdmission;

impl ProviderAdmissionControl for AllowAdmission {
    fn check(
        &self,
        _admission: krikos_identity::ProviderLogAdmission,
        _request: ProviderAdmissionRequest,
    ) -> Result<(), IdentityError> {
        Ok(())
    }
}

struct ProviderSigner(SecretKey);

impl ProviderHeadSigner for ProviderSigner {
    fn sign_provider_head(&self, message: &[u8]) -> Result<ProtocolSignature, IdentityError> {
        Ok(ProtocolSignature::ed25519(self.0.sign(message).to_bytes()))
    }
}

fn typed_id<T: CanonicalWire>(fill: u8) -> T {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [fill; 32]);
    T::from_canonical_bytes(&digest.to_canonical_bytes().expect("digest encodes"))
        .expect("typed digest ID decodes")
}

fn recovery_export(generation: ProviderGenerationExport) -> ProviderRecoveryExport {
    let audit_store =
        MemoryProviderAuditStore::new(generation.provider().clone(), generation.log_id());
    let auditor = DurableProviderAuditor::new(audit_store.clone());
    if let Some(head) = generation.latest_head() {
        auditor
            .observe(head.clone(), None)
            .expect("provider head audits");
    }
    ProviderRecoveryExport::new(
        generation,
        audit_store.snapshot().expect("provider audit snapshot"),
    )
    .expect("provider recovery export")
}

fn bounded_fault_offset(input: &[u8], start: usize, upper_bound: u64) -> u64 {
    if upper_bound == 0 {
        return 0;
    }
    let mut bytes = [0_u8; 8];
    for (output, value) in bytes.iter_mut().zip(input.iter().skip(start)) {
        *output = *value;
    }
    u64::from_le_bytes(bytes) % upper_bound
}

fn controller(secret: &SecretKey) -> ControllerDescriptor {
    ControllerDescriptor::new(
        SigningPublicKey::ed25519(*secret.public().as_bytes()).expect("valid signing key"),
        ControllerClass::PersonalDevice,
        ControllerWeight::new(1).expect("nonzero controller weight"),
        ControllerScope::all_v1_operations(),
        Extensions::default(),
    )
    .expect("valid controller")
}

fn rule(operation: OperationKind) -> PolicyRule {
    PolicyRule::new(
        operation,
        RequiredWeight::new(1).expect("nonzero policy weight"),
        ControllerSelector::any_active(),
        FreshnessRequirement::latest_known(),
        None,
        Extensions::default(),
    )
    .expect("valid policy rule")
}

fn checkpoint_bundle(seed: u8) -> ProviderCheckpointBundle {
    let signer = SecretKey::from_bytes(&[seed; 32]);
    let added = SecretKey::from_bytes(&[seed.wrapping_add(1); 32]);
    let control_policy = ControlPolicy::new(
        vec![
            rule(OperationKind::AddController),
            rule(OperationKind::ChangeProviderPolicy),
        ],
        Extensions::default(),
    )
    .expect("valid control policy");
    let recovery_policy = RecoveryPolicy::new(
        RecoveryPolicyVersion::GENESIS,
        RecoveryAuthority::controller_threshold(ControllerThreshold::new(
            ControllerSelector::any_active(),
            RequiredWeight::new(1).expect("nonzero recovery weight"),
        )),
        DurationMillis::new(10),
        DurationMillis::new(100),
        Extensions::default(),
    )
    .expect("valid recovery policy");
    let genesis = AccountGenesis::new(
        [seed; 32],
        Timestamp::from_unix_millis(1),
        control_policy,
        vec![controller(&signer)],
        recovery_policy,
        ProviderPolicy::local_only(ProviderPolicyVersion::GENESIS, Extensions::default())
            .expect("valid provider policy"),
        Extensions::default(),
    )
    .expect("valid genesis");
    let mut state = AccountState::from_genesis(&genesis).expect("genesis projects");
    let operation = AccountOperation::AddController(controller(&added));
    let body = EventBody::new(
        state.account_id(),
        Sequence::new(1),
        state
            .expected_epoch_for(&operation)
            .expect("operation epoch"),
        EventPredecessors::genesis(state.genesis_anchor()),
        operation,
        Timestamp::from_unix_millis(2),
        [seed.max(1); 16],
        Extensions::default(),
    )
    .expect("valid event body");
    let preceding_checkpoint = typed_id::<CheckpointId>(seed.wrapping_add(2));
    let evidence = AdmissionEvidence::new(
        body.proposal_id().expect("proposal ID"),
        preceding_checkpoint,
        state.provider_policy_id(),
        FreshnessEvidence::local_known(preceding_checkpoint),
        DelayEvidence::none(),
        Extensions::default(),
    )
    .expect("valid admission evidence");
    let event_id = body
        .admitted_event_id(
            evidence
                .admission_evidence_id()
                .expect("admission evidence ID"),
        )
        .expect("event ID");
    let signing_key =
        SigningPublicKey::ed25519(*signer.public().as_bytes()).expect("valid signing key");
    let controller_id = state.active_controllers()[0].id();
    let approval_body = ControllerApprovalBody::event(
        controller_id,
        event_id,
        evidence
            .admission_evidence_id()
            .expect("admission evidence ID"),
        Extensions::default(),
    )
    .expect("valid event approval body");
    let event_signature = signer.sign(
        &approval_body
            .to_canonical_bytes()
            .expect("event approval encodes"),
    );
    let event_approval = SignedControllerApproval::new(
        approval_body,
        vec![KeyedSignature::new(
            CryptoSuiteDescriptor::v1()
                .expect("v1 suite")
                .crypto_suite_id()
                .expect("suite ID"),
            ControllerKeyId::for_signing_key(&signing_key).expect("controller key ID"),
            AlgorithmSignature::new(1, event_signature.to_bytes().to_vec())
                .expect("valid event signature"),
        )],
    )
    .expect("valid event approval");
    let event = krikos_identity::AuthorizedEvent::new(
        body,
        evidence,
        ControllerApprovals::new(vec![event_approval]).expect("event approval set"),
    )
    .expect("authorized event");
    state
        .validate_and_apply(&event)
        .expect("event projects into state");

    let checkpoint_body =
        build_checkpoint_body(&state, Timestamp::from_unix_millis(3)).expect("checkpoint body");
    let checkpoint_id = checkpoint_body.checkpoint_id().expect("checkpoint ID");
    let checkpoint_approval_body =
        ControllerApprovalBody::checkpoint(controller_id, checkpoint_id, Extensions::default())
            .expect("valid checkpoint approval body");
    let checkpoint_signature = signer.sign(
        &checkpoint_approval_body
            .to_canonical_bytes()
            .expect("checkpoint approval encodes"),
    );
    let checkpoint_approval = SignedControllerApproval::new(
        checkpoint_approval_body,
        vec![KeyedSignature::new(
            CryptoSuiteDescriptor::v1()
                .expect("v1 suite")
                .crypto_suite_id()
                .expect("suite ID"),
            ControllerKeyId::for_signing_key(&signing_key).expect("controller key ID"),
            AlgorithmSignature::new(1, checkpoint_signature.to_bytes().to_vec())
                .expect("valid checkpoint signature"),
        )],
    )
    .expect("valid checkpoint approval");
    let checkpoint = SignedCheckpoint::new(
        checkpoint_body,
        CheckpointAuthorization::controllers(
            checkpoint_id,
            ControllerApprovals::new(vec![checkpoint_approval]).expect("checkpoint approval set"),
        )
        .expect("checkpoint authorization"),
    )
    .expect("signed checkpoint");
    verify_checkpoint(&state, &checkpoint, None).expect("checkpoint verifies");
    build_provider_checkpoint_bundle_from_genesis(
        &genesis,
        std::slice::from_ref(&event),
        &checkpoint,
        None,
    )
    .expect("provider checkpoint bundle")
}

fn append_bundle(
    store: &RedbProviderStore,
    bundle: &ProviderCheckpointBundle,
    observed_at: u64,
    signer: &ProviderSigner,
) -> krikos_identity::InclusionReceipt {
    let admission = bundle.provider_log_admission();
    let request = ProviderAdmissionRequest::for_admission(&admission).expect("bounded admission");
    let permit = authorize_provider_append(admission, request, &AllowAdmission)
        .expect("verified append permit");
    store
        .append(permit, Timestamp::from_unix_millis(observed_at), signer)
        .expect("provider append")
}

fn assert_corrupt_reopen_fails_closed(
    path: &Path,
    provider: &ProviderDescriptor,
    log_id: ProviderLogId,
    committed_snapshot: &ProviderGenerationSnapshot,
    committed_export: &ProviderGenerationExport,
) {
    match RedbProviderStore::open(path, provider.clone(), log_id, ProviderKeyVersion::GENESIS) {
        Ok(reopened) => {
            let snapshot = reopened
                .snapshot()
                .expect("a successfully reopened generation authenticates");
            assert_eq!(
                snapshot, *committed_snapshot,
                "corruption normalized provider state"
            );
            assert_eq!(
                reopened
                    .export_generation()
                    .expect("reopened provider export"),
                *committed_export,
                "corruption changed authenticated provider export"
            );
        }
        Err(_typed_error) => {}
    }
}

fuzz_target!(|input: &[u8]| {
    if input.is_empty() || input.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }
    match input[0] {
        b'7' => {
            let _ = ProviderExportComponent::from_canonical_bytes(&input[1..]);
            return;
        }
        b'8' => {
            let _ = ProviderExportComponentDescriptor::from_canonical_bytes(&input[1..]);
            return;
        }
        b'9' => {
            let _ = ProviderGenerationExportChunk::from_canonical_bytes(&input[1..]);
            return;
        }
        b'a' => {
            let _ = ProviderAuditExportChunk::from_canonical_bytes(&input[1..]);
            return;
        }
        b'b' => {
            let _ = ProviderGenerationExportManifest::from_canonical_bytes(&input[1..]);
            return;
        }
        b'c' => {
            let _ = ProviderAuditExportManifest::from_canonical_bytes(&input[1..]);
            return;
        }
        b'd' => {
            let _ = ProviderRecoveryExportManifest::from_canonical_bytes(&input[1..]);
            return;
        }
        b'e' => {
            let _ = ProviderCompactionManifest::from_canonical_bytes(&input[1..]);
            return;
        }
        b'f' => {
            let _ = OpaqueProviderAnchorCommitment::from_canonical_bytes(&input[1..]);
            return;
        }
        _ => {}
    }
    // Selectors `0` through `6` are the original persistent-store scenarios. Interchange
    // decoders extend that ASCII namespace append-only at `7` through `f` above.
    // Reject every other value rather than wrapping or reducing it modulo the scenario count.
    let Some(selector) = input[0].checked_sub(b'0').filter(|selector| *selector < 7) else {
        return;
    };
    let first_seed = input.get(1).copied().unwrap_or(0x31).max(1);
    let second_seed = first_seed.wrapping_add(1).max(1);
    let provider_signer = ProviderSigner(SecretKey::from_bytes(&[0x71; 32]));
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*provider_signer.0.public().as_bytes())
            .expect("valid provider key"),
        Extensions::default(),
    )
    .expect("valid provider");
    let log_id = typed_id::<ProviderLogId>(0x72);
    let directory = tempfile::tempdir().expect("temporary provider directory");
    let path = directory.path().join("provider.redb");
    let store =
        RedbProviderStore::open(&path, provider.clone(), log_id, ProviderKeyVersion::GENESIS)
            .expect("provider store opens");
    let first_bundle = checkpoint_bundle(first_seed);
    let second_bundle = checkpoint_bundle(second_seed);
    let first_receipt = append_bundle(&store, &first_bundle, 10, &provider_signer);
    let second_receipt = append_bundle(&store, &second_bundle, 11, &provider_signer);
    assert_eq!(first_receipt.leaf_index(), 0);
    assert_eq!(second_receipt.leaf_index(), 1);
    let committed = store.snapshot().expect("provider snapshot");
    let committed_export = store.export_generation().expect("provider export");
    assert_eq!(committed.tree_size(), 2);

    match selector {
        0 => {
            drop(store);
            let reopened = RedbProviderStore::open(
                &path,
                provider.clone(),
                log_id,
                ProviderKeyVersion::GENESIS,
            )
            .expect("provider reopens");
            assert_eq!(reopened.snapshot().expect("reopened snapshot"), committed);
            let account_id = first_bundle.provider_log_admission().account_id();
            let page = reopened
                .account_history(account_id, None, 1, MAX_HISTORY_BYTES)
                .expect("bounded account history");
            assert_eq!(page.records().len(), 1);
        }
        1 => {
            let replay = append_bundle(&store, &first_bundle, 12, &provider_signer);
            assert_eq!(replay.leaf_index(), first_receipt.leaf_index());
            assert_eq!(store.snapshot().expect("replay snapshot").tree_size(), 2);
            store.consistency_proof(0, 2).expect("empty prefix proof");
            store.consistency_proof(1, 2).expect("proper prefix proof");
            store.consistency_proof(2, 2).expect("equal prefix proof");
        }
        2 => {
            let source = store.export_generation().expect("provider export");
            let mirror = MemoryProviderStore::restore_generation(source.clone())
                .expect("provider mirror restores");
            assert_eq!(mirror.snapshot().expect("mirror snapshot"), committed);
            let mirror_export = mirror.export_generation().expect("mirror export");
            let source_recovery = recovery_export(source);
            let mirror_recovery = recovery_export(mirror_export);
            let inventory =
                derive_provider_retention_inventory(&source_recovery).expect("retention inventory");
            let authorization =
                verify_provider_compaction(&source_recovery, &mirror_recovery, &inventory)
                    .expect("compaction authorization");
            store
                .record_compaction_manifest(&authorization, &mirror_recovery, &inventory)
                .expect("durable compaction manifest");
            drop(store);
            let reopened = RedbProviderStore::open(
                &path,
                provider.clone(),
                log_id,
                ProviderKeyVersion::GENESIS,
            )
            .expect("compacted provider reopens");
            assert_eq!(
                reopened
                    .compaction_manifests()
                    .expect("recorded manifests")
                    .len(),
                1
            );
            reopened
                .consistency_proof(1, 2)
                .expect("proof survives compaction authorization");
        }
        3 => {
            drop(store);
            let mut bytes = fs::read(&path).expect("provider bytes");
            if !bytes.is_empty() {
                let length = u64::try_from(bytes.len()).expect("provider file length fits u64");
                let offset = usize::try_from(bounded_fault_offset(input, 2, length))
                    .expect("bounded provider byte offset fits usize");
                bytes[offset] ^= input.get(3).copied().unwrap_or(1).max(1);
                fs::write(&path, bytes).expect("fault injection write");
            }
            assert_corrupt_reopen_fails_closed(
                &path,
                &provider,
                log_id,
                &committed,
                &committed_export,
            );
        }
        4 => {
            drop(store);
            let length = fs::metadata(&path).expect("provider metadata").len();
            let retained = bounded_fault_offset(input, 2, length);
            OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("provider file opens for fault injection")
                .set_len(retained)
                .expect("provider truncation");
            assert!(
                RedbProviderStore::open(
                    &path,
                    provider.clone(),
                    log_id,
                    ProviderKeyVersion::GENESIS,
                )
                .is_err(),
                "truncated provider generation normalized into a valid store"
            );
        }
        5 => {
            drop(store);
            assert!(matches!(
                RedbProviderStore::open(
                    &path,
                    provider.clone(),
                    typed_id::<ProviderLogId>(0x73),
                    ProviderKeyVersion::GENESIS,
                ),
                Err(IdentityError::InvalidRelationship {
                    resource: "provider store generation"
                })
            ));
        }
        _ => {
            let admission = first_bundle.provider_log_admission();
            let exact =
                ProviderAdmissionRequest::for_admission(&admission).expect("exact admission size");
            let undercharged = ProviderAdmissionRequest::new(exact.encoded_bytes() - 1)
                .expect("positive undercharge");
            assert!(matches!(
                authorize_provider_append(admission, undercharged, &AllowAdmission),
                Err(IdentityError::InvalidRelationship {
                    resource: "provider append request byte undercharge"
                })
            ));
            assert_eq!(store.snapshot().expect("unchanged snapshot"), committed);
        }
    }
});
