use krikos_base::SecretKey;
use krikos_identity::{
    AccountGenesis, AccountId, AccountOperation, AccountState, AdmissionEvidence,
    AlgorithmSignature, AuthorizedEvent, CanonicalWire, CheckpointAuthorization, CheckpointId,
    ControlPolicy, ControllerApprovalBody, ControllerApprovals, ControllerClass,
    ControllerDescriptor, ControllerKeyId, ControllerScope, ControllerSelector,
    ControllerThreshold, ControllerWeight, CryptoSuiteDescriptor, DelayEvidence, Digest,
    DurableProviderAuditor, DurationMillis, Epoch, EventBody, EventId, EventPredecessors,
    Extensions, FreshnessEvidence, FreshnessRequirement, HashAlgorithm, IdentityError,
    InclusionReceipt, KeyedSignature, MemoryProviderAuditStore, MemoryProviderStore,
    OpaqueProviderAnchorCommitment, OperationKind, PolicyRule, ProtocolSignature,
    ProviderAdmissionControl, ProviderAdmissionRequest, ProviderAuditStatus,
    ProviderCheckpointBundle, ProviderCompactionManifest, ProviderDescriptor,
    ProviderGenerationExport, ProviderGenerationExportAssembler, ProviderHeadAuditDisposition,
    ProviderHeadBody, ProviderHeadSigner, ProviderKeyVersion, ProviderLogEntryBody, ProviderLogId,
    ProviderPolicy, ProviderPolicyVersion, ProviderRecoveryExport, ProviderRetentionClass,
    ProviderRetentionInventory, ProviderRetentionItem, RecoveryAuthority, RecoveryPolicy,
    RecoveryPolicyVersion, RequiredWeight, Sequence, SignedCheckpoint, SignedControllerApproval,
    SignedProviderHead, SigningPublicKey, Timestamp, authorize_provider_append,
    bootstrap_checkpoint_from_genesis, bootstrap_checkpoint_from_prior, build_checkpoint_body,
    build_provider_checkpoint_bundle_from_genesis, build_provider_checkpoint_bundle_from_prior,
    derive_provider_retention_inventory, verify_checkpoint, verify_provider_compaction,
};
#[cfg(feature = "provider-store")]
use krikos_identity::{
    ProviderGenerationRegistry, ProviderGenerationRoute, ProviderQuorum, RedbProviderAuditStore,
    RedbProviderStore,
};
#[cfg(feature = "provider-store")]
use redb::{Database, ReadableTable, TableDefinition};
#[cfg(feature = "provider-store")]
use std::{
    collections::BTreeSet,
    sync::{Arc, Barrier},
    thread,
};

#[cfg(feature = "provider-store")]
const TEST_PROVIDER_COMMITTED_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("krikos-provider-generation-v1");

#[derive(serde::Serialize)]
struct ProviderAnchorCommitmentMirror<'a> {
    format_version: u16,
    manifest: &'a ProviderCompactionManifest,
}

#[derive(serde::Serialize)]
struct ProviderCheckpointBundleCommitmentMirror<'a> {
    genesis: Option<&'a AccountGenesis>,
    prior_checkpoint_id: Option<CheckpointId>,
    events: &'a [krikos_identity::AuthorizedEvent],
    checkpoint: &'a SignedCheckpoint,
    transition_event: Option<&'a krikos_identity::AuthorizedEvent>,
}

#[derive(serde::Serialize)]
struct ProviderGenerationExportCommitmentMirror<'a> {
    format_version: u16,
    provider: &'a ProviderDescriptor,
    log_id: ProviderLogId,
    key_version: ProviderKeyVersion,
    entries: &'a [ProviderLogEntryBody],
    leaf_hashes: &'a [Digest],
    latest_head: Option<&'a SignedProviderHead>,
    receipts: &'a [InclusionReceipt],
    checkpoint_bundles: Vec<ProviderCheckpointBundleCommitmentMirror<'a>>,
    compaction_manifests: &'a [ProviderCompactionManifest],
}

#[derive(serde::Serialize)]
struct ProviderAuditArtifactSetCommitmentMirror<'a> {
    format_version: u16,
    artifact_commitments: &'a [Digest],
}

#[derive(serde::Serialize)]
struct RetainedProviderRecordCommitmentMirror<'a> {
    leaf_index: u64,
    entry: &'a ProviderLogEntryBody,
    receipt: &'a InclusionReceipt,
}

#[derive(serde::Serialize)]
struct RetainedCheckpointMaterialCommitmentMirror<'a> {
    genesis: Option<&'a AccountGenesis>,
    prior_checkpoint_id: Option<CheckpointId>,
    events: &'a [AuthorizedEvent],
    checkpoint: &'a SignedCheckpoint,
    transition_event: Option<&'a AuthorizedEvent>,
}

#[derive(serde::Serialize)]
struct ProviderCheckpointIndexCommitmentMirror<'a> {
    account_id: AccountId,
    greatest_sequence: Sequence,
    greatest_epoch: Epoch,
    current_checkpoint_id: Option<CheckpointId>,
    projection_heads: &'a [EventId],
    forked: bool,
}

#[derive(serde::Serialize)]
struct RetainedProviderEvidenceCommitmentMirror<'a> {
    format_version: u16,
    records: Vec<RetainedProviderRecordCommitmentMirror<'a>>,
    checkpoint_evidence: Vec<RetainedCheckpointMaterialCommitmentMirror<'a>>,
    checkpoint_index: Vec<ProviderCheckpointIndexCommitmentMirror<'a>>,
    audit_artifact_commitment: Digest,
}

fn raw_provider_commitment<T: serde::Serialize>(domain: &[u8], value: &T) -> Digest {
    let bytes = postcard::to_stdvec(value).unwrap();
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(&bytes);
    Digest::new(HashAlgorithm::Blake3_256, *hasher.finalize().as_bytes())
}

fn raw_provider_generation_commitment(export: &ProviderGenerationExport) -> Digest {
    raw_provider_commitment(
        b"KRIKOS-ID/provider-generation-export/v1",
        &ProviderGenerationExportCommitmentMirror {
            format_version: 1,
            provider: export.provider(),
            log_id: export.log_id(),
            key_version: export.key_version(),
            entries: export.entries(),
            leaf_hashes: export.leaf_hashes(),
            latest_head: export.latest_head(),
            receipts: export.receipts(),
            checkpoint_bundles: export
                .checkpoint_bundles()
                .iter()
                .map(|bundle| {
                    let verified = bundle.verified_checkpoint();
                    ProviderCheckpointBundleCommitmentMirror {
                        genesis: bundle.genesis(),
                        prior_checkpoint_id: bundle.prior_checkpoint_id(),
                        events: bundle.events(),
                        checkpoint: verified.checkpoint(),
                        transition_event: verified.transition_event(),
                    }
                })
                .collect(),
            compaction_manifests: export.compaction_manifests(),
        },
    )
}

fn raw_single_checkpoint_retained_commitment(export: &ProviderGenerationExport) -> Digest {
    assert_eq!(export.entries().len(), 1);
    assert_eq!(export.receipts().len(), 1);
    assert_eq!(export.checkpoint_bundles().len(), 1);
    let bundle = &export.checkpoint_bundles()[0];
    let genesis = bundle.genesis().unwrap();
    let mut state = AccountState::from_genesis(genesis).unwrap();
    for event in bundle.events() {
        state.validate_and_apply(event).unwrap();
    }
    let verified = bundle.verified_checkpoint();
    let artifact_commitment = raw_provider_commitment(
        b"KRIKOS-ID/provider-audit-artifacts/v1",
        &ProviderAuditArtifactSetCommitmentMirror {
            format_version: 1,
            artifact_commitments: &[],
        },
    );
    raw_provider_commitment(
        b"KRIKOS-ID/provider-retained-evidence/v1",
        &RetainedProviderEvidenceCommitmentMirror {
            format_version: 1,
            records: vec![RetainedProviderRecordCommitmentMirror {
                leaf_index: 0,
                entry: &export.entries()[0],
                receipt: &export.receipts()[0],
            }],
            checkpoint_evidence: vec![RetainedCheckpointMaterialCommitmentMirror {
                genesis: Some(genesis),
                prior_checkpoint_id: bundle.prior_checkpoint_id(),
                events: bundle.events(),
                checkpoint: verified.checkpoint(),
                transition_event: verified.transition_event(),
            }],
            checkpoint_index: vec![ProviderCheckpointIndexCommitmentMirror {
                account_id: state.account_id(),
                greatest_sequence: state.sequence(),
                greatest_epoch: state.epoch(),
                current_checkpoint_id: Some(verified.checkpoint_id()),
                projection_heads: state.heads(),
                forked: false,
            }],
            audit_artifact_commitment: artifact_commitment,
        },
    )
}

#[cfg(feature = "provider-store")]
fn corrupt_unique_committed_subsequence(path: &std::path::Path, needle: &[u8]) {
    let database = Database::create(path).unwrap();
    let write = database.begin_write().unwrap();
    {
        let mut table = write.open_table(TEST_PROVIDER_COMMITTED_TABLE).unwrap();
        let value = table.get(b"active".as_slice()).unwrap().unwrap();
        let mut bytes = value.value().to_vec();
        drop(value);
        let offsets = bytes
            .windows(needle.len())
            .enumerate()
            .filter_map(|(offset, candidate)| (candidate == needle).then_some(offset))
            .collect::<Vec<_>>();
        assert_eq!(
            offsets.len(),
            1,
            "corruption target must be exact and unique"
        );
        let target = offsets[0] + needle.len() / 2;
        bytes[target] ^= 0x01;
        table
            .insert(b"active".as_slice(), bytes.as_slice())
            .unwrap();
    }
    write.commit().unwrap();
}

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

fn authorized_add_controller(
    state: &AccountState,
    signer: &SecretKey,
    added: &SecretKey,
    nonce: u64,
) -> krikos_identity::AuthorizedEvent {
    let predecessors = if state.sequence() == Sequence::GENESIS {
        EventPredecessors::genesis(state.genesis_anchor())
    } else {
        EventPredecessors::events(state.heads().to_vec()).unwrap()
    };
    let nonce_bytes: [u8; 16] = nonce.to_le_bytes().repeat(2).try_into().unwrap();
    let event_body = EventBody::new(
        state.account_id(),
        state.sequence().checked_next().unwrap(),
        state
            .expected_epoch_for(&AccountOperation::AddController(controller(added)))
            .unwrap(),
        predecessors,
        AccountOperation::AddController(controller(added)),
        Timestamp::from_unix_millis(nonce),
        nonce_bytes,
        Extensions::default(),
    )
    .unwrap();
    let admission_checkpoint = typed_id::<CheckpointId>(0x42);
    let evidence = AdmissionEvidence::new(
        event_body.proposal_id().unwrap(),
        admission_checkpoint,
        state.provider_policy_id(),
        FreshnessEvidence::local_known(admission_checkpoint),
        DelayEvidence::none(),
        Extensions::default(),
    )
    .unwrap();
    let signing_key = SigningPublicKey::ed25519(*signer.public().as_bytes()).unwrap();
    let controller_id = state
        .active_controllers()
        .iter()
        .find(|candidate| candidate.signing_key() == signing_key)
        .unwrap()
        .id();
    let approval_body = ControllerApprovalBody::event(
        controller_id,
        evidence.event_id_for_body(&event_body).unwrap(),
        evidence.admission_evidence_id().unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let approval_signature = signer.sign(&approval_body.to_canonical_bytes().unwrap());
    let approval = SignedControllerApproval::new(
        approval_body,
        vec![KeyedSignature::new(
            CryptoSuiteDescriptor::v1()
                .unwrap()
                .crypto_suite_id()
                .unwrap(),
            ControllerKeyId::for_signing_key(&signing_key).unwrap(),
            AlgorithmSignature::new(1, approval_signature.to_bytes().to_vec()).unwrap(),
        )],
    )
    .unwrap();
    krikos_identity::AuthorizedEvent::new(
        event_body,
        evidence,
        ControllerApprovals::new(vec![approval]).unwrap(),
    )
    .unwrap()
}

fn checkpoint_bundle(nonce: u8) -> ProviderCheckpointBundle {
    checkpoint_bundle_at(nonce, 1, nonce.wrapping_add(10), 10_000)
}

fn alternate_checkpoint_approval_bundle(
    retained: &ProviderCheckpointBundle,
    alternate_secret: &SecretKey,
) -> ProviderCheckpointBundle {
    let genesis = retained.genesis().unwrap();
    let mut state = AccountState::from_genesis(genesis).unwrap();
    for event in retained.events() {
        state.validate_and_apply(event).unwrap();
    }
    let alternate_key = SigningPublicKey::ed25519(*alternate_secret.public().as_bytes()).unwrap();
    let alternate_controller = state
        .active_controllers()
        .iter()
        .find(|controller| controller.signing_key() == alternate_key)
        .unwrap()
        .id();
    let retained_checkpoint = retained.verified_checkpoint().checkpoint();
    let checkpoint_id = retained_checkpoint.checkpoint_id().unwrap();
    let approval_body = ControllerApprovalBody::checkpoint(
        alternate_controller,
        checkpoint_id,
        Extensions::default(),
    )
    .unwrap();
    let approval = SignedControllerApproval::new(
        approval_body.clone(),
        vec![KeyedSignature::new(
            CryptoSuiteDescriptor::v1()
                .unwrap()
                .crypto_suite_id()
                .unwrap(),
            ControllerKeyId::for_signing_key(&alternate_key).unwrap(),
            AlgorithmSignature::new(
                1,
                alternate_secret
                    .sign(&approval_body.to_canonical_bytes().unwrap())
                    .to_bytes()
                    .to_vec(),
            )
            .unwrap(),
        )],
    )
    .unwrap();
    let checkpoint = SignedCheckpoint::new(
        retained_checkpoint.body().clone(),
        CheckpointAuthorization::controllers(
            checkpoint_id,
            ControllerApprovals::new(vec![approval]).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    build_provider_checkpoint_bundle_from_genesis(genesis, retained.events(), &checkpoint, None)
        .unwrap()
}

fn checkpoint_bundle_at(
    nonce: u8,
    event_count: u8,
    branch_seed: u8,
    checkpoint_issued_at: u64,
) -> ProviderCheckpointBundle {
    let signer = SecretKey::from_bytes(&[0x41; 32]);
    let control_policy = ControlPolicy::new(
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
        [nonce; 32],
        Timestamp::from_unix_millis(1),
        control_policy,
        vec![controller(&signer)],
        recovery_policy,
        ProviderPolicy::local_only(ProviderPolicyVersion::GENESIS, Extensions::default()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let mut state = AccountState::from_genesis(&genesis).unwrap();
    let mut events = Vec::new();
    for event_index in 0..event_count {
        let event_nonce = u64::from(branch_seed)
            .saturating_mul(10)
            .saturating_add(u64::from(event_index))
            .saturating_add(2);
        let added = SecretKey::from_bytes(&[branch_seed.wrapping_add(event_index); 32]);
        let event = authorized_add_controller(&state, &signer, &added, event_nonce);
        state.validate_and_apply(&event).unwrap();
        events.push(event);
    }

    let body =
        build_checkpoint_body(&state, Timestamp::from_unix_millis(checkpoint_issued_at)).unwrap();
    let checkpoint_id = body.checkpoint_id().unwrap();
    let signing_key = SigningPublicKey::ed25519(*signer.public().as_bytes()).unwrap();
    let checkpoint_controller_id = state
        .active_controllers()
        .iter()
        .find(|candidate| candidate.signing_key() == signing_key)
        .unwrap()
        .id();
    let checkpoint_approval_body = ControllerApprovalBody::checkpoint(
        checkpoint_controller_id,
        checkpoint_id,
        Extensions::default(),
    )
    .unwrap();
    let checkpoint_signature = signer.sign(&checkpoint_approval_body.to_canonical_bytes().unwrap());
    let checkpoint_approval = SignedControllerApproval::new(
        checkpoint_approval_body,
        vec![KeyedSignature::new(
            CryptoSuiteDescriptor::v1()
                .unwrap()
                .crypto_suite_id()
                .unwrap(),
            ControllerKeyId::for_signing_key(&signing_key).unwrap(),
            AlgorithmSignature::new(1, checkpoint_signature.to_bytes().to_vec()).unwrap(),
        )],
    )
    .unwrap();
    let checkpoint = SignedCheckpoint::new(
        body,
        CheckpointAuthorization::controllers(
            checkpoint_id,
            ControllerApprovals::new(vec![checkpoint_approval]).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    verify_checkpoint(&state, &checkpoint, None).unwrap();
    build_provider_checkpoint_bundle_from_genesis(&genesis, &events, &checkpoint, None).unwrap()
}

fn continuation_bundle(prior: &ProviderCheckpointBundle) -> ProviderCheckpointBundle {
    let signer = SecretKey::from_bytes(&[0x41; 32]);
    let mut prior_state = AccountState::from_genesis(prior.genesis().unwrap()).unwrap();
    for event in prior.events() {
        prior_state.validate_and_apply(event).unwrap();
    }
    let mut next_state = prior_state.clone();
    let event = authorized_add_controller(
        &next_state,
        &signer,
        &SecretKey::from_bytes(&[0x76; 32]),
        76,
    );
    next_state.validate_and_apply(&event).unwrap();
    let body = build_checkpoint_body(&next_state, Timestamp::from_unix_millis(20_000)).unwrap();
    let checkpoint_id = body.checkpoint_id().unwrap();
    let signing_key = SigningPublicKey::ed25519(*signer.public().as_bytes()).unwrap();
    let controller_id = next_state
        .active_controllers()
        .iter()
        .find(|candidate| candidate.signing_key() == signing_key)
        .unwrap()
        .id();
    let approval_body =
        ControllerApprovalBody::checkpoint(controller_id, checkpoint_id, Extensions::default())
            .unwrap();
    let approval = SignedControllerApproval::new(
        approval_body.clone(),
        vec![KeyedSignature::new(
            CryptoSuiteDescriptor::v1()
                .unwrap()
                .crypto_suite_id()
                .unwrap(),
            ControllerKeyId::for_signing_key(&signing_key).unwrap(),
            AlgorithmSignature::new(
                1,
                signer
                    .sign(&approval_body.to_canonical_bytes().unwrap())
                    .to_bytes()
                    .to_vec(),
            )
            .unwrap(),
        )],
    )
    .unwrap();
    let checkpoint = SignedCheckpoint::new(
        body,
        CheckpointAuthorization::controllers(
            checkpoint_id,
            ControllerApprovals::new(vec![approval]).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    build_provider_checkpoint_bundle_from_prior(
        &prior_state,
        prior.verified_checkpoint(),
        &[event],
        &checkpoint,
        None,
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

struct Deny;

impl ProviderAdmissionControl for Deny {
    fn check(
        &self,
        _admission: krikos_identity::ProviderLogAdmission,
        _request: ProviderAdmissionRequest,
    ) -> Result<(), IdentityError> {
        Err(IdentityError::ProviderRateLimited)
    }
}

struct Signer(SecretKey);

impl ProviderHeadSigner for Signer {
    fn sign_provider_head(&self, message: &[u8]) -> Result<ProtocolSignature, IdentityError> {
        Ok(ProtocolSignature::ed25519(self.0.sign(message).to_bytes()))
    }
}

fn signed_head(
    provider: &ProviderDescriptor,
    log_id: ProviderLogId,
    tree_size: u64,
    root_fill: u8,
    observed_at: u64,
    signer: &Signer,
) -> SignedProviderHead {
    let body = ProviderHeadBody::new(
        provider.id().unwrap(),
        log_id,
        ProviderKeyVersion::GENESIS,
        tree_size,
        Digest::new(HashAlgorithm::Blake3_256, [root_fill; 32]),
        Timestamp::from_unix_millis(observed_at),
        Extensions::default(),
    )
    .unwrap();
    let signature = signer
        .sign_provider_head(&body.signing_bytes().unwrap())
        .unwrap();
    SignedProviderHead::new(body, signature)
}

fn recovery_export(generation: ProviderGenerationExport) -> ProviderRecoveryExport {
    let audit_store =
        MemoryProviderAuditStore::new(generation.provider().clone(), generation.log_id());
    let auditor = DurableProviderAuditor::new(audit_store.clone());
    if let Some(head) = generation.latest_head() {
        auditor.observe(head.clone(), None).unwrap();
    }
    ProviderRecoveryExport::new(generation, audit_store.snapshot().unwrap()).unwrap()
}

#[cfg(feature = "provider-store")]
fn recovery_export_with_attacks(
    generation: ProviderGenerationExport,
    signer: &Signer,
) -> ProviderRecoveryExport {
    let provider = generation.provider().clone();
    let log_id = generation.log_id();
    let accepted = generation.latest_head().unwrap().clone();
    assert!(accepted.body().tree_size() >= 2);
    let accepted_at = accepted.body().observed_at().as_unix_millis();
    let audit_store = MemoryProviderAuditStore::new(provider.clone(), log_id);
    let auditor = DurableProviderAuditor::new(audit_store.clone());
    auditor.observe(accepted.clone(), None).unwrap();
    let rollback = signed_head(
        &provider,
        log_id,
        accepted.body().tree_size() - 1,
        0xf1,
        accepted_at.saturating_add(1),
        signer,
    );
    assert_eq!(
        auditor.observe(rollback, None),
        Err(IdentityError::ProviderRollback)
    );
    let conflict = signed_head(
        &provider,
        log_id,
        accepted.body().tree_size(),
        0xf2,
        accepted_at.saturating_add(2),
        signer,
    );
    assert_eq!(
        auditor.observe(conflict, None),
        Err(IdentityError::ProviderEquivocation)
    );
    ProviderRecoveryExport::new(generation, audit_store.snapshot().unwrap()).unwrap()
}

#[cfg(feature = "provider-store")]
struct UnavailableSigner;

#[cfg(feature = "provider-store")]
impl ProviderHeadSigner for UnavailableSigner {
    fn sign_provider_head(&self, _message: &[u8]) -> Result<ProtocolSignature, IdentityError> {
        Err(IdentityError::ProviderUnavailable)
    }
}

#[test]
fn verified_admission_is_atomic_idempotent_and_availability_controls_are_non_authoritative() {
    let signer = Signer(SecretKey::from_bytes(&[0x51; 32]));
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let log_id = typed_id::<ProviderLogId>(0x52);
    let store =
        MemoryProviderStore::new(provider.clone(), log_id, ProviderKeyVersion::GENESIS).unwrap();
    let checkpoint = checkpoint_bundle(0x53);
    let admission = checkpoint.provider_log_admission();
    let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
    let undercharged = ProviderAdmissionRequest::new(request.encoded_bytes() - 1).unwrap();

    assert_eq!(
        authorize_provider_append(admission.clone(), undercharged, &Allow),
        Err(IdentityError::InvalidRelationship {
            resource: "provider append request byte undercharge",
        })
    );
    assert_eq!(store.snapshot().unwrap().tree_size(), 0);

    assert_eq!(
        authorize_provider_append(admission.clone(), request, &Deny),
        Err(IdentityError::ProviderRateLimited)
    );
    assert_eq!(store.snapshot().unwrap().tree_size(), 0);

    let permit = authorize_provider_append(admission.clone(), request, &Allow).unwrap();
    let first = store
        .append(permit, Timestamp::from_unix_millis(10), &signer)
        .unwrap();
    first.verify(&provider).unwrap();
    let replay_permit = authorize_provider_append(admission.clone(), request, &Allow).unwrap();
    let replay = store
        .append(replay_permit, Timestamp::from_unix_millis(11), &signer)
        .unwrap();
    assert_eq!(first.leaf_index(), replay.leaf_index());
    assert_eq!(store.snapshot().unwrap().tree_size(), 1);
    assert_eq!(
        store.checkpoint_bundles().unwrap(),
        vec![checkpoint.clone()]
    );
    assert_eq!(
        store
            .latest_checkpoint_bundle(admission.account_id())
            .unwrap()
            .unwrap(),
        checkpoint
    );

    let page = store
        .account_history(admission.account_id(), None, 1, 4 * 1024 * 1024)
        .unwrap();
    assert_eq!(page.records().len(), 1);
    assert_eq!(page.records()[0].entry(), first.entry());

    let export = store.export_generation().unwrap();
    let mirror = MemoryProviderStore::restore_generation(export.clone()).unwrap();
    assert_eq!(mirror.snapshot().unwrap(), store.snapshot().unwrap());
    mirror
        .consistency_proof(0, mirror.snapshot().unwrap().tree_size())
        .unwrap();

    let mirror_export = mirror.export_generation().unwrap();
    let source_recovery = recovery_export(store.export_generation().unwrap());
    let mirror_recovery = recovery_export(mirror_export.clone());
    let mandatory = derive_provider_retention_inventory(&source_recovery).unwrap();
    assert_eq!(mandatory.tree_size(), 1);
    assert_eq!(mandatory.items().len(), 1);
    assert_eq!(
        mandatory.items()[0].class(),
        ProviderRetentionClass::CheckpointLineage
    );
    let omitted = ProviderRetentionInventory::new(1, Vec::new()).unwrap();
    assert!(matches!(
        verify_provider_compaction(&source_recovery, &mirror_recovery, &omitted,),
        Err(IdentityError::InvalidRelationship {
            resource: "provider compaction mandatory retention inventory",
        })
    ));
    let misclassified = ProviderRetentionInventory::new(
        1,
        vec![ProviderRetentionItem::new(0, ProviderRetentionClass::Recovery).unwrap()],
    )
    .unwrap();
    assert!(matches!(
        verify_provider_compaction(&source_recovery, &mirror_recovery, &misclassified,),
        Err(IdentityError::InvalidRelationship {
            resource: "provider compaction mandatory retention inventory",
        })
    ));
    let inventory = ProviderRetentionInventory::new(
        1,
        vec![ProviderRetentionItem::new(0, ProviderRetentionClass::CheckpointLineage).unwrap()],
    )
    .unwrap();
    let authorization =
        verify_provider_compaction(&source_recovery, &mirror_recovery, &inventory).unwrap();
    assert_eq!(source_recovery.artifacts(), &[]);
    assert_eq!(
        authorization.manifest().retained_evidence_commitment(),
        raw_single_checkpoint_retained_commitment(source_recovery.generation()),
        "retained evidence must bind nonempty checkpoint material and projection index"
    );
    authorization
        .manifest()
        .verify(&source_recovery, &mirror_recovery, &inventory)
        .unwrap();
    assert!(store.compaction_manifests().unwrap().is_empty());
    let recorded = store
        .record_compaction_manifest(&authorization, &mirror_recovery, &inventory)
        .unwrap();
    assert_eq!(&recorded, authorization.manifest());
    store
        .record_compaction_manifest(&authorization, &mirror_recovery, &inventory)
        .unwrap();
    assert_eq!(store.compaction_manifests().unwrap(), vec![recorded]);
    let post_manifest_recovery = recovery_export(store.export_generation().unwrap());
    assert_eq!(
        post_manifest_recovery.generation_commitment(),
        raw_provider_generation_commitment(post_manifest_recovery.generation()),
        "the complete nonempty generation and its recorded manifest must use the v1 preimage"
    );
    assert_ne!(
        post_manifest_recovery.generation_commitment(),
        source_recovery.generation_commitment(),
        "later generation commitments must include already-durable manifests"
    );
    let next_inventory = derive_provider_retention_inventory(&post_manifest_recovery).unwrap();
    let next_authorization = verify_provider_compaction(
        &post_manifest_recovery,
        &post_manifest_recovery,
        &next_inventory,
    )
    .unwrap();
    assert_eq!(
        next_authorization.manifest().generation_commitment(),
        post_manifest_recovery.generation_commitment()
    );
    assert_ne!(
        next_authorization.manifest().archive_commitment(),
        authorization.manifest().archive_commitment()
    );
    let opaque =
        OpaqueProviderAnchorCommitment::from_compaction_manifest(authorization.manifest()).unwrap();
    assert_ne!(opaque.as_bytes(), &[0; 32]);
    assert_eq!(
        opaque.digest(),
        raw_provider_commitment(
            b"KRIKOS-ID/provider-anchor-commitment/v1",
            &ProviderAnchorCommitmentMirror {
                format_version: 1,
                manifest: authorization.manifest(),
            },
        )
    );

    let wrong_inventory = ProviderRetentionInventory::new(2, Vec::new()).unwrap();
    assert_eq!(
        verify_provider_compaction(&recovery_export(export), &mirror_recovery, &wrong_inventory,),
        Err(IdentityError::InvalidRelationship {
            resource: "provider compaction inventory tree size",
        })
    );
}

#[test]
fn duplicate_checkpoint_approvals_merge_without_adding_a_provider_leaf() {
    let nonce = 0xf0;
    let first = checkpoint_bundle(nonce);
    let alternate = alternate_checkpoint_approval_bundle(
        &first,
        &SecretKey::from_bytes(&[nonce.wrapping_add(10); 32]),
    );
    assert_ne!(first, alternate);
    assert_eq!(
        first.verified_checkpoint().checkpoint_id(),
        alternate.verified_checkpoint().checkpoint_id()
    );

    let signer = Signer(SecretKey::from_bytes(&[0xf1; 32]));
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let mut merged_results = Vec::new();
    for (log_seed, ordered) in [(0xf2, [&first, &alternate]), (0xf3, [&alternate, &first])] {
        let store = MemoryProviderStore::new(
            provider.clone(),
            typed_id::<ProviderLogId>(log_seed),
            ProviderKeyVersion::GENESIS,
        )
        .unwrap();
        let mut receipts = Vec::new();
        for bundle in ordered {
            let admission = bundle.provider_log_admission();
            let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
            receipts.push(
                store
                    .append(
                        authorize_provider_append(admission, request, &Allow).unwrap(),
                        Timestamp::from_unix_millis(600),
                        &signer,
                    )
                    .unwrap(),
            );
        }
        assert_eq!(receipts[0], receipts[1]);
        assert_eq!(store.snapshot().unwrap().tree_size(), 1);
        let merged = store
            .latest_checkpoint_bundle(first.verified_checkpoint().checkpoint().body().account_id())
            .unwrap()
            .unwrap();
        assert_eq!(
            merged
                .verified_checkpoint()
                .checkpoint()
                .authorization()
                .controller_approvals()
                .unwrap()
                .as_slice()
                .len(),
            2
        );
        merged_results.push(merged);
    }
    assert_eq!(merged_results[0], merged_results[1]);
}

#[test]
fn immutable_memory_recovery_archive_rejects_new_compaction_manifests() {
    let signer = Signer(SecretKey::from_bytes(&[0xf4; 32]));
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let active = MemoryProviderStore::new(
        provider,
        typed_id::<ProviderLogId>(0xf5),
        ProviderKeyVersion::GENESIS,
    )
    .unwrap();
    let bundle = checkpoint_bundle(0xf6);
    let admission = bundle.provider_log_admission();
    let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
    active
        .append(
            authorize_provider_append(admission, request, &Allow).unwrap(),
            Timestamp::from_unix_millis(700),
            &signer,
        )
        .unwrap();
    let recovery = recovery_export(active.export_generation().unwrap());
    let inventory = derive_provider_retention_inventory(&recovery).unwrap();
    let authorization = verify_provider_compaction(&recovery, &recovery, &inventory).unwrap();
    let archive = MemoryProviderStore::restore_recovery(recovery.clone()).unwrap();

    assert_eq!(
        archive.record_compaction_manifest(&authorization, &recovery, &inventory),
        Err(IdentityError::ProviderArchiveRequired)
    );
    assert_eq!(archive.archived_recovery_export().unwrap(), recovery);
}

#[cfg(feature = "provider-store")]
#[test]
fn redb_duplicate_approval_merge_and_archive_immutability_survive_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let signer = Signer(SecretKey::from_bytes(&[0xf7; 32]));
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let first = checkpoint_bundle(0xf8);
    let alternate = alternate_checkpoint_approval_bundle(
        &first,
        &SecretKey::from_bytes(&[0xf8_u8.wrapping_add(10); 32]),
    );
    let account_id = first.verified_checkpoint().checkpoint().body().account_id();
    let mut merged_results = Vec::new();
    for (index, ordered) in [[&first, &alternate], [&alternate, &first]]
        .into_iter()
        .enumerate()
    {
        let path = directory.path().join(format!("duplicate-{index}.redb"));
        let log_id = typed_id::<ProviderLogId>(0xf9_u8.wrapping_add(u8::try_from(index).unwrap()));
        {
            let store = RedbProviderStore::open(
                &path,
                provider.clone(),
                log_id,
                ProviderKeyVersion::GENESIS,
            )
            .unwrap();
            let mut receipts = Vec::new();
            for bundle in ordered {
                let admission = bundle.provider_log_admission();
                let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
                receipts.push(
                    store
                        .append(
                            authorize_provider_append(admission, request, &Allow).unwrap(),
                            Timestamp::from_unix_millis(800),
                            &signer,
                        )
                        .unwrap(),
                );
            }
            assert_eq!(receipts[0], receipts[1]);
            assert_eq!(store.snapshot().unwrap().tree_size(), 1);
        }
        let reopened =
            RedbProviderStore::open(&path, provider.clone(), log_id, ProviderKeyVersion::GENESIS)
                .unwrap();
        let merged = reopened
            .latest_checkpoint_bundle(account_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            merged
                .verified_checkpoint()
                .checkpoint()
                .authorization()
                .controller_approvals()
                .unwrap()
                .as_slice()
                .len(),
            2
        );
        merged_results.push(merged);
    }
    assert_eq!(merged_results[0], merged_results[1]);

    let active = MemoryProviderStore::new(
        provider.clone(),
        typed_id::<ProviderLogId>(0xfc),
        ProviderKeyVersion::GENESIS,
    )
    .unwrap();
    let admission = first.provider_log_admission();
    let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
    active
        .append(
            authorize_provider_append(admission, request, &Allow).unwrap(),
            Timestamp::from_unix_millis(801),
            &signer,
        )
        .unwrap();
    let recovery = recovery_export(active.export_generation().unwrap());
    let inventory = derive_provider_retention_inventory(&recovery).unwrap();
    let authorization = verify_provider_compaction(&recovery, &recovery, &inventory).unwrap();
    let archive_path = directory.path().join("immutable-archive.redb");
    {
        let archive = RedbProviderStore::restore_recovery(&archive_path, recovery.clone()).unwrap();
        assert_eq!(
            archive.record_compaction_manifest(&authorization, &recovery, &inventory),
            Err(IdentityError::ProviderArchiveRequired)
        );
        assert_eq!(archive.archived_recovery_export().unwrap(), recovery);
    }
    let reopened = RedbProviderStore::open(
        &archive_path,
        provider,
        typed_id::<ProviderLogId>(0xfc),
        ProviderKeyVersion::GENESIS,
    )
    .unwrap();
    assert_eq!(reopened.archived_recovery_export().unwrap(), recovery);
    drop(reopened);
    RedbProviderStore::restore_recovery(&archive_path, recovery).unwrap();
}

#[test]
fn checkpoint_lineage_pages_stitch_and_bootstrap_an_explicit_retained_branch() {
    let signer = Signer(SecretKey::from_bytes(&[0x81; 32]));
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let log_id = typed_id::<ProviderLogId>(0x82);
    let store =
        MemoryProviderStore::new(provider.clone(), log_id, ProviderKeyVersion::GENESIS).unwrap();
    let first = checkpoint_bundle(0x83);
    let second = continuation_bundle(&first);
    for (bundle, observed_at) in [(&first, 30_u64), (&second, 31_u64)] {
        let admission = bundle.provider_log_admission();
        let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
        store
            .append(
                authorize_provider_append(admission, request, &Allow).unwrap(),
                Timestamp::from_unix_millis(observed_at),
                &signer,
            )
            .unwrap();
    }
    let export = store.export_generation().unwrap();
    let (manifest, chunks) = export.interchange_parts().unwrap();
    let mut assembler = ProviderGenerationExportAssembler::new(manifest).unwrap();
    for chunk in chunks.into_iter().rev() {
        assembler.insert(chunk).unwrap();
    }
    assert_eq!(assembler.finish().unwrap(), export);
    let account_id = first.verified_checkpoint().checkpoint().body().account_id();
    let second_id = second.verified_checkpoint().checkpoint_id();
    let first_id = first.verified_checkpoint().checkpoint_id();
    let first_page = store
        .checkpoint_lineage_page(account_id, second_id, 1, 4 * 1024 * 1024)
        .unwrap()
        .unwrap();
    assert_eq!(first_page.checkpoints().len(), 1);
    assert_eq!(first_page.next_prior_checkpoint_id(), Some(first_id));
    let second_page = store
        .checkpoint_lineage_page(
            account_id,
            first_page.next_prior_checkpoint_id().unwrap(),
            1,
            4 * 1024 * 1024,
        )
        .unwrap()
        .unwrap();
    assert_eq!(second_page.next_prior_checkpoint_id(), None);
    let mut stitched = first_page.checkpoints().to_vec();
    stitched.extend_from_slice(second_page.checkpoints());
    stitched.reverse();
    assert_eq!(stitched.len(), 2);
    for checkpoint in &stitched {
        checkpoint.receipt().verify(&provider).unwrap();
    }
    let first_bootstrap = bootstrap_checkpoint_from_genesis(
        stitched[0].bundle().genesis().unwrap(),
        stitched[0].bundle().events(),
        stitched[0].bundle().verified_checkpoint().checkpoint(),
        stitched[0]
            .bundle()
            .verified_checkpoint()
            .transition_event(),
        &FreshnessEvidence::local_known(first_id),
        FreshnessRequirement::latest_known(),
        Timestamp::from_unix_millis(100),
        &[],
    )
    .unwrap();
    let final_bootstrap = bootstrap_checkpoint_from_prior(
        first_bootstrap.state(),
        first_bootstrap.checkpoint(),
        stitched[1].bundle().events(),
        stitched[1].bundle().verified_checkpoint().checkpoint(),
        stitched[1]
            .bundle()
            .verified_checkpoint()
            .transition_event(),
        &FreshnessEvidence::local_known(second_id),
        FreshnessRequirement::latest_known(),
        Timestamp::from_unix_millis(100),
        &[],
    )
    .unwrap();
    assert_eq!(final_bootstrap.checkpoint().checkpoint_id(), second_id);
    assert!(
        store
            .checkpoint_lineage_page(account_id, typed_id::<CheckpointId>(0xfe), 1, 1024)
            .unwrap()
            .is_none()
    );
}

#[test]
fn sealed_generation_releases_benign_history_but_keeps_current_checkpoint_proofs() {
    let signer = Signer(SecretKey::from_bytes(&[0x84; 32]));
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let log_id = typed_id::<ProviderLogId>(0x85);
    let store =
        MemoryProviderStore::new(provider.clone(), log_id, ProviderKeyVersion::GENESIS).unwrap();
    let first = checkpoint_bundle(0x86);
    let second = continuation_bundle(&first);
    for (bundle, observed_at) in [(&first, 40_u64), (&second, 41_u64)] {
        let admission = bundle.provider_log_admission();
        let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
        store
            .append(
                authorize_provider_append(admission, request, &Allow).unwrap(),
                Timestamp::from_unix_millis(observed_at),
                &signer,
            )
            .unwrap();
    }
    let recovery = recovery_export(store.export_generation().unwrap());
    let inventory = derive_provider_retention_inventory(&recovery).unwrap();
    let authorization = verify_provider_compaction(&recovery, &recovery, &inventory).unwrap();
    assert_eq!(
        store
            .seal_after_verified_mirror(&authorization, &recovery, &inventory)
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .seal_after_verified_mirror(&authorization, &recovery, &inventory)
            .unwrap(),
        1,
        "an exact seal replay must return the original release result"
    );
    let account_id = second
        .verified_checkpoint()
        .checkpoint()
        .body()
        .account_id();
    let second_id = second.verified_checkpoint().checkpoint_id();
    assert_eq!(
        store.latest_checkpoint_bundle(account_id),
        Err(IdentityError::ProviderArchiveRequired)
    );
    let retained = store
        .latest_retained_checkpoint_evidence(account_id)
        .unwrap()
        .unwrap();
    assert_eq!(retained.checkpoint().checkpoint_id().unwrap(), second_id);
    assert_eq!(
        retained.prior_checkpoint_id(),
        Some(first.verified_checkpoint().checkpoint_id())
    );
    assert_eq!(retained.receipt().leaf_index(), 1);
    assert_eq!(
        store.checkpoint_bundle(account_id, second_id),
        Err(IdentityError::ProviderArchiveRequired)
    );
    assert_eq!(
        store
            .retained_checkpoint_evidence(account_id, first.verified_checkpoint().checkpoint_id(),),
        Err(IdentityError::ProviderArchiveRequired)
    );
    assert_eq!(
        store.account_history(account_id, None, 1, 4 * 1024 * 1024),
        Err(IdentityError::ProviderArchiveRequired)
    );
    assert_eq!(
        store.export_generation(),
        Err(IdentityError::ProviderArchiveRequired)
    );
    let admission = first.provider_log_admission();
    let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
    assert_eq!(
        store.append(
            authorize_provider_append(admission, request, &Allow).unwrap(),
            Timestamp::from_unix_millis(42),
            &signer,
        ),
        Err(IdentityError::ProviderArchiveRequired)
    );
}

#[cfg(feature = "provider-store")]
#[test]
fn redb_seal_is_atomic_idempotent_and_survives_deep_validated_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider-sealed.redb");
    let signer = Signer(SecretKey::from_bytes(&[0x87; 32]));
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let log_id = typed_id::<ProviderLogId>(0x88);
    let first = checkpoint_bundle(0x89);
    let second = continuation_bundle(&first);
    let account_id = second
        .verified_checkpoint()
        .checkpoint()
        .body()
        .account_id();
    let second_id = second.verified_checkpoint().checkpoint_id();
    let (authorization, recovery, inventory) = {
        let store =
            RedbProviderStore::open(&path, provider.clone(), log_id, ProviderKeyVersion::GENESIS)
                .unwrap();
        for (bundle, observed_at) in [(&first, 60_u64), (&second, 61_u64)] {
            let admission = bundle.provider_log_admission();
            let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
            store
                .append(
                    authorize_provider_append(admission, request, &Allow).unwrap(),
                    Timestamp::from_unix_millis(observed_at),
                    &signer,
                )
                .unwrap();
        }
        let recovery = recovery_export(store.export_generation().unwrap());
        let inventory = derive_provider_retention_inventory(&recovery).unwrap();
        let authorization = verify_provider_compaction(&recovery, &recovery, &inventory).unwrap();
        assert_eq!(
            store
                .seal_after_verified_mirror(&authorization, &recovery, &inventory)
                .unwrap(),
            1
        );
        (authorization, recovery, inventory)
    };

    let reopened =
        RedbProviderStore::open(&path, provider, log_id, ProviderKeyVersion::GENESIS).unwrap();
    assert_eq!(reopened.snapshot().unwrap().tree_size(), 2);
    assert_eq!(
        reopened.latest_checkpoint_bundle(account_id),
        Err(IdentityError::ProviderArchiveRequired)
    );
    let retained = reopened
        .latest_retained_checkpoint_evidence(account_id)
        .unwrap()
        .unwrap();
    assert_eq!(retained.checkpoint().checkpoint_id().unwrap(), second_id);
    assert_eq!(retained.receipt().leaf_index(), 1);
    reopened.consistency_proof(1, 2).unwrap();
    assert_eq!(
        reopened
            .seal_after_verified_mirror(&authorization, &recovery, &inventory)
            .unwrap(),
        1
    );
    assert_eq!(
        reopened.account_history(account_id, None, 2, 4 * 1024 * 1024),
        Err(IdentityError::ProviderArchiveRequired)
    );
    assert_eq!(
        reopened.export_generation(),
        Err(IdentityError::ProviderArchiveRequired)
    );
    let admission = first.provider_log_admission();
    let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
    assert_eq!(
        reopened.append(
            authorize_provider_append(admission, request, &Allow).unwrap(),
            Timestamp::from_unix_millis(64),
            &signer,
        ),
        Err(IdentityError::ProviderArchiveRequired)
    );
    assert_eq!(
        reopened.record_compaction_manifest(&authorization, &recovery, &inventory),
        Err(IdentityError::ProviderArchiveRequired)
    );
}

#[cfg(feature = "provider-store")]
#[test]
fn sealed_reopen_rejects_changed_outer_checkpoint_approval_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory
        .path()
        .join("provider-sealed-approval-corruption.redb");
    let signer = Signer(SecretKey::from_bytes(&[0x8d; 32]));
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let log_id = typed_id::<ProviderLogId>(0x8e);
    let first = checkpoint_bundle(0x8f);
    let second = continuation_bundle(&first);
    let approval_bytes = second
        .verified_checkpoint()
        .checkpoint()
        .authorization()
        .controller_approvals()
        .unwrap()
        .as_slice()[0]
        .signatures()[0]
        .signature()
        .as_bytes()
        .to_vec();
    {
        let store =
            RedbProviderStore::open(&path, provider.clone(), log_id, ProviderKeyVersion::GENESIS)
                .unwrap();
        for (bundle, observed_at) in [(&first, 62_u64), (&second, 63_u64)] {
            let admission = bundle.provider_log_admission();
            let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
            store
                .append(
                    authorize_provider_append(admission, request, &Allow).unwrap(),
                    Timestamp::from_unix_millis(observed_at),
                    &signer,
                )
                .unwrap();
        }
        let recovery = recovery_export(store.export_generation().unwrap());
        let inventory = derive_provider_retention_inventory(&recovery).unwrap();
        let authorization = verify_provider_compaction(&recovery, &recovery, &inventory).unwrap();
        store
            .seal_after_verified_mirror(&authorization, &recovery, &inventory)
            .unwrap();
    }
    corrupt_unique_committed_subsequence(&path, &approval_bytes);
    assert!(matches!(
        RedbProviderStore::open(&path, provider, log_id, ProviderKeyVersion::GENESIS,),
        Err(IdentityError::StorageCorruption)
    ));
}

#[cfg(feature = "provider-store")]
#[test]
fn composite_recovery_archives_round_trip_full_history_and_remain_read_only() {
    let directory = tempfile::tempdir().unwrap();
    let archive_path = directory.path().join("provider-recovery-archive.redb");
    let signer = Signer(SecretKey::from_bytes(&[0x8a; 32]));
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let log_id = typed_id::<ProviderLogId>(0x8b);
    let active =
        MemoryProviderStore::new(provider.clone(), log_id, ProviderKeyVersion::GENESIS).unwrap();
    let first = checkpoint_bundle(0x8c);
    let second = continuation_bundle(&first);
    for (bundle, observed_at) in [(&first, 70_u64), (&second, 71_u64)] {
        let admission = bundle.provider_log_admission();
        let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
        active
            .append(
                authorize_provider_append(admission, request, &Allow).unwrap(),
                Timestamp::from_unix_millis(observed_at),
                &signer,
            )
            .unwrap();
    }
    let recovery = recovery_export_with_attacks(active.export_generation().unwrap(), &signer);
    assert_eq!(recovery.audit().records().len(), 3);
    assert_eq!(recovery.artifacts().len(), 2);

    let archive = MemoryProviderStore::restore_recovery(recovery.clone()).unwrap();
    assert_eq!(archive.archived_recovery_export().unwrap(), recovery);
    assert_eq!(
        archive.archived_audit_snapshot().unwrap(),
        *recovery.audit()
    );
    assert_eq!(
        archive.retained_audit_artifacts().unwrap(),
        recovery.artifacts()
    );
    assert_eq!(archive.export_generation().unwrap(), *recovery.generation());
    let account_id = second
        .verified_checkpoint()
        .checkpoint()
        .body()
        .account_id();
    let history = archive
        .account_history(account_id, None, 8, 4 * 1024 * 1024)
        .unwrap();
    assert_eq!(history.records().len(), 2);
    assert!(
        archive
            .checkpoint_bundle(account_id, first.verified_checkpoint().checkpoint_id())
            .unwrap()
            .is_some()
    );
    let lineage = archive
        .checkpoint_lineage_page(
            account_id,
            second.verified_checkpoint().checkpoint_id(),
            8,
            4 * 1024 * 1024,
        )
        .unwrap()
        .unwrap();
    assert_eq!(lineage.checkpoints().len(), 2);
    let admission = first.provider_log_admission();
    let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
    assert_eq!(
        archive.append(
            authorize_provider_append(admission.clone(), request, &Allow).unwrap(),
            Timestamp::from_unix_millis(72),
            &signer,
        ),
        Err(IdentityError::ProviderArchiveRequired)
    );

    {
        let redb = RedbProviderStore::restore_recovery(&archive_path, recovery.clone()).unwrap();
        assert_eq!(redb.archived_recovery_export().unwrap(), recovery);
        assert_eq!(redb.archived_audit_snapshot().unwrap(), *recovery.audit());
        assert_eq!(
            redb.retained_audit_artifacts().unwrap(),
            recovery.artifacts()
        );
        assert_eq!(
            redb.append(
                authorize_provider_append(admission.clone(), request, &Allow).unwrap(),
                Timestamp::from_unix_millis(73),
                &signer,
            ),
            Err(IdentityError::ProviderArchiveRequired)
        );
    }
    let reopened =
        RedbProviderStore::open(&archive_path, provider, log_id, ProviderKeyVersion::GENESIS)
            .unwrap();
    assert_eq!(reopened.archived_recovery_export().unwrap(), recovery);
    drop(reopened);
    RedbProviderStore::restore_recovery(&archive_path, recovery).unwrap();
}

#[cfg(feature = "provider-store")]
#[test]
fn independently_addressed_generations_route_without_an_implicit_winner() {
    let directory = tempfile::tempdir().unwrap();
    let old_path = directory.path().join("provider-old-generation.redb");
    let new_path = directory.path().join("provider-new-generation.redb");
    let archive_path = directory.path().join("provider-old-archive.redb");
    let old_signer = Signer(SecretKey::from_bytes(&[0xa1; 32]));
    let new_signer = Signer(SecretKey::from_bytes(&[0xa2; 32]));
    let old_provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*old_signer.0.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let new_provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*new_signer.0.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    assert_ne!(old_provider.id().unwrap(), new_provider.id().unwrap());
    let old_log_id = typed_id::<ProviderLogId>(0xa3);
    let new_log_id = typed_id::<ProviderLogId>(0xa4);
    let old_store = RedbProviderStore::open(
        &old_path,
        old_provider.clone(),
        old_log_id,
        ProviderKeyVersion::GENESIS,
    )
    .unwrap();
    let new_store = RedbProviderStore::open(
        &new_path,
        new_provider.clone(),
        new_log_id,
        ProviderKeyVersion::GENESIS,
    )
    .unwrap();
    let old_prior_checkpoint = checkpoint_bundle(0xa5);
    let old_prior_admission = old_prior_checkpoint.provider_log_admission();
    let old_prior_request = ProviderAdmissionRequest::for_admission(&old_prior_admission).unwrap();
    old_store
        .append(
            authorize_provider_append(old_prior_admission, old_prior_request, &Allow).unwrap(),
            Timestamp::from_unix_millis(80),
            &old_signer,
        )
        .unwrap();
    let old_checkpoint = continuation_bundle(&old_prior_checkpoint);
    let old_admission = old_checkpoint.provider_log_admission();
    let old_request = ProviderAdmissionRequest::for_admission(&old_admission).unwrap();
    let old_receipt = old_store
        .append(
            authorize_provider_append(old_admission.clone(), old_request, &Allow).unwrap(),
            Timestamp::from_unix_millis(81),
            &old_signer,
        )
        .unwrap();
    let old_recovery = recovery_export(old_store.export_generation().unwrap());
    let old_inventory = derive_provider_retention_inventory(&old_recovery).unwrap();
    let old_authorization =
        verify_provider_compaction(&old_recovery, &old_recovery, &old_inventory).unwrap();
    old_store
        .seal_after_verified_mirror(&old_authorization, &old_recovery, &old_inventory)
        .unwrap();

    let new_checkpoint = checkpoint_bundle(0xa6);
    let new_admission = new_checkpoint.provider_log_admission();
    let new_request = ProviderAdmissionRequest::for_admission(&new_admission).unwrap();
    let new_receipt = new_store
        .append(
            authorize_provider_append(new_admission, new_request, &Allow).unwrap(),
            Timestamp::from_unix_millis(82),
            &new_signer,
        )
        .unwrap();
    assert!(old_receipt.verify(&new_provider).is_err());
    assert!(new_receipt.verify(&old_provider).is_err());

    let old_route = old_store.generation_route().unwrap();
    let new_route = new_store.generation_route().unwrap();
    assert_eq!(old_route.provider_id(), old_provider.id().unwrap());
    assert_eq!(old_route.log_id(), old_log_id);
    assert_eq!(old_route.key_version(), ProviderKeyVersion::GENESIS);
    assert_eq!(new_route.provider_id(), new_provider.id().unwrap());
    assert_eq!(new_route.log_id(), new_log_id);
    let mut registry = ProviderGenerationRegistry::new();
    registry.insert(old_store.clone()).unwrap();
    registry.insert(new_store.clone()).unwrap();
    assert_eq!(registry.len(), 2);
    let policy = ProviderPolicy::replicated(
        ProviderPolicyVersion::GENESIS,
        vec![new_provider.clone()],
        ProviderQuorum::new(1).unwrap(),
        ProviderQuorum::new(1).unwrap(),
        DurationMillis::new(1_000),
        Extensions::default(),
    )
    .unwrap();
    assert_eq!(
        registry
            .for_policy(&policy, new_route)
            .unwrap()
            .snapshot()
            .unwrap()
            .tree_size(),
        1
    );
    assert!(matches!(
        registry.for_policy(&policy, old_route),
        Err(IdentityError::InvalidRelationship {
            resource: "provider generation account policy",
        })
    ));
    let cross_route =
        ProviderGenerationRoute::new(&new_provider, old_log_id, ProviderKeyVersion::GENESIS)
            .unwrap();
    assert!(matches!(
        registry.require(cross_route),
        Err(IdentityError::InvalidRelationship {
            resource: "provider generation route",
        })
    ));
    let old_account = old_checkpoint
        .verified_checkpoint()
        .checkpoint()
        .body()
        .account_id();
    let retained_evidence = old_store
        .latest_retained_checkpoint_evidence(old_account)
        .unwrap()
        .unwrap();
    assert!(retained_evidence.genesis().is_none());
    assert_eq!(
        retained_evidence.prior_checkpoint_id(),
        Some(old_prior_checkpoint.verified_checkpoint().checkpoint_id())
    );
    let mut old_prior_state =
        AccountState::from_genesis(old_prior_checkpoint.genesis().unwrap()).unwrap();
    for event in old_prior_checkpoint.events() {
        old_prior_state.validate_and_apply(event).unwrap();
    }
    let reconstructed_from_raw = build_provider_checkpoint_bundle_from_prior(
        &old_prior_state,
        old_prior_checkpoint.verified_checkpoint(),
        retained_evidence.events(),
        retained_evidence.checkpoint(),
        retained_evidence.transition_event(),
    )
    .unwrap();
    assert_eq!(reconstructed_from_raw, old_checkpoint);
    assert_eq!(
        old_store.export_generation(),
        Err(IdentityError::ProviderArchiveRequired)
    );

    let archive = RedbProviderStore::restore_recovery(&archive_path, old_recovery.clone()).unwrap();
    assert_eq!(archive.archived_recovery_export().unwrap(), old_recovery);
    assert!(matches!(
        registry.insert(archive.clone()),
        Err(IdentityError::DuplicateElement {
            resource: "provider generation route",
        })
    ));
    assert_eq!(registry.len(), 2);
    let mut archive_first_registry = ProviderGenerationRegistry::new();
    archive_first_registry.insert(archive.clone()).unwrap();
    assert!(matches!(
        archive_first_registry.insert(old_store.clone()),
        Err(IdentityError::DuplicateElement {
            resource: "provider generation route",
        })
    ));
    assert_eq!(archive_first_registry.len(), 1);
    assert!(
        archive
            .checkpoint_bundle(
                old_account,
                old_checkpoint.verified_checkpoint().checkpoint_id(),
            )
            .unwrap()
            .is_some()
    );
    let raw_admission = reconstructed_from_raw.provider_log_admission();
    let raw_request = ProviderAdmissionRequest::for_admission(&raw_admission).unwrap();
    let archive_before_raw_append = archive.archived_recovery_export().unwrap();
    assert_eq!(
        archive.append(
            authorize_provider_append(raw_admission, raw_request, &Allow).unwrap(),
            Timestamp::from_unix_millis(83),
            &old_signer,
        ),
        Err(IdentityError::ProviderArchiveRequired)
    );
    assert_eq!(
        archive.archived_recovery_export().unwrap(),
        archive_before_raw_append
    );
    assert_eq!(
        archive.resume_append(&old_signer),
        Err(IdentityError::ProviderArchiveRequired)
    );
    assert_eq!(
        archive.cancel_prepared_append(),
        Err(IdentityError::ProviderArchiveRequired)
    );
    assert_eq!(
        archive.seal_after_verified_mirror(&old_authorization, &old_recovery, &old_inventory,),
        Err(IdentityError::ProviderArchiveRequired)
    );

    drop(registry);
    drop(archive_first_registry);
    drop(archive);
    drop(old_store);
    drop(new_store);
    RedbProviderStore::restore_recovery(&archive_path, old_recovery.clone()).unwrap();
    let conflicting_recovery = recovery_export(
        MemoryProviderStore::new(
            old_provider.clone(),
            old_log_id,
            ProviderKeyVersion::GENESIS,
        )
        .unwrap()
        .export_generation()
        .unwrap(),
    );
    assert!(matches!(
        RedbProviderStore::restore_recovery(&archive_path, conflicting_recovery),
        Err(IdentityError::InvalidRelationship {
            resource: "provider recovery archive destination",
        })
    ));
    assert!(matches!(
        RedbProviderStore::open(
            &old_path,
            new_provider.clone(),
            new_log_id,
            ProviderKeyVersion::GENESIS,
        ),
        Err(IdentityError::InvalidRelationship {
            resource: "provider store generation",
        })
    ));
    let old_reopened = RedbProviderStore::open(
        &old_path,
        old_provider.clone(),
        old_log_id,
        ProviderKeyVersion::GENESIS,
    )
    .unwrap();
    let new_reopened = RedbProviderStore::open(
        &new_path,
        new_provider,
        new_log_id,
        ProviderKeyVersion::GENESIS,
    )
    .unwrap();
    let archive_reopened = RedbProviderStore::open(
        &archive_path,
        old_provider,
        old_log_id,
        ProviderKeyVersion::GENESIS,
    )
    .unwrap();
    assert_eq!(old_reopened.snapshot().unwrap().tree_size(), 2);
    assert_eq!(new_reopened.snapshot().unwrap().tree_size(), 1);
    assert_eq!(
        archive_reopened.archived_recovery_export().unwrap(),
        old_recovery
    );
}

#[cfg(feature = "provider-store")]
#[test]
fn concurrent_redb_appends_are_linearizable_and_duplicate_idempotent() {
    const WRITERS: usize = 4;
    const MAX_ATTEMPTS: usize = 2_000;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider-concurrent.redb");
    let signer_fill = 0xb1;
    let signer = Signer(SecretKey::from_bytes(&[signer_fill; 32]));
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let log_id = typed_id::<ProviderLogId>(0xb2);
    let store =
        RedbProviderStore::open(&path, provider.clone(), log_id, ProviderKeyVersion::GENESIS)
            .unwrap();
    let barrier = Arc::new(Barrier::new(WRITERS));
    let mut threads = Vec::new();
    for writer in 0..WRITERS {
        let store = store.clone();
        let barrier = barrier.clone();
        threads.push(thread::spawn(move || {
            let bundle = checkpoint_bundle(0xd0_u8.saturating_add(u8::try_from(writer).unwrap()));
            let checkpoint_id = bundle.verified_checkpoint().checkpoint_id();
            let observed_at = Timestamp::from_unix_millis(120);
            let admission = bundle.provider_log_admission();
            let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
            let signer = Signer(SecretKey::from_bytes(&[signer_fill; 32]));
            barrier.wait();
            for _ in 0..MAX_ATTEMPTS {
                let permit = authorize_provider_append(admission.clone(), request, &Allow).unwrap();
                match store.append(permit, observed_at, &signer) {
                    Ok(receipt) => return (checkpoint_id, receipt),
                    Err(IdentityError::ResourceBusy) => thread::yield_now(),
                    Err(error) => panic!("unexpected concurrent append failure: {error:?}"),
                }
            }
            panic!("concurrent append retry bound exhausted");
        }));
    }
    let mut leaf_indices = BTreeSet::new();
    let mut checkpoint_ids = BTreeSet::new();
    let writer_count = u64::try_from(WRITERS).unwrap();
    let duplicate_checkpoint_id = checkpoint_bundle(0xd0)
        .verified_checkpoint()
        .checkpoint_id();
    let mut duplicate_leaf_index = None;
    for handle in threads {
        let (checkpoint_id, receipt) = handle.join().unwrap();
        receipt.verify(&provider).unwrap();
        if checkpoint_id == duplicate_checkpoint_id {
            duplicate_leaf_index = Some(receipt.leaf_index());
        }
        checkpoint_ids.insert(checkpoint_id);
        leaf_indices.insert(receipt.leaf_index());
    }
    assert_eq!(checkpoint_ids.len(), WRITERS);
    assert_eq!(leaf_indices, (0..writer_count).collect());
    assert_eq!(store.snapshot().unwrap().tree_size(), writer_count);
    let duplicate_leaf_index = duplicate_leaf_index.unwrap();

    let duplicate_barrier = Arc::new(Barrier::new(WRITERS));
    let mut duplicate_threads = Vec::new();
    for _ in 0..WRITERS {
        let store = store.clone();
        let barrier = duplicate_barrier.clone();
        duplicate_threads.push(thread::spawn(move || {
            let observed_at = Timestamp::from_unix_millis(120);
            let admission = checkpoint_bundle(0xd0).provider_log_admission();
            let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
            let signer = Signer(SecretKey::from_bytes(&[signer_fill; 32]));
            barrier.wait();
            for _ in 0..MAX_ATTEMPTS {
                let permit = authorize_provider_append(admission.clone(), request, &Allow).unwrap();
                match store.append(permit, observed_at, &signer) {
                    Ok(receipt) => return receipt,
                    Err(IdentityError::ResourceBusy) => thread::yield_now(),
                    Err(error) => panic!("unexpected duplicate append failure: {error:?}"),
                }
            }
            panic!("duplicate append retry bound exhausted");
        }));
    }
    for handle in duplicate_threads {
        assert_eq!(handle.join().unwrap().leaf_index(), duplicate_leaf_index);
    }
    let export = store.export_generation().unwrap();
    assert_eq!(export.entries().len(), WRITERS);
    assert_eq!(export.receipts().len(), WRITERS);
    assert_eq!(store.snapshot().unwrap().tree_size(), writer_count);
    drop(store);
    let reopened =
        RedbProviderStore::open(&path, provider, log_id, ProviderKeyVersion::GENESIS).unwrap();
    assert_eq!(reopened.export_generation().unwrap(), export);
}

#[test]
fn provider_checkpoint_index_rejects_rollback_and_retains_asymmetric_fork() {
    let signer = Signer(SecretKey::from_bytes(&[0x91; 32]));
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let store = MemoryProviderStore::new(
        provider.clone(),
        typed_id::<ProviderLogId>(0x92),
        ProviderKeyVersion::GENESIS,
    )
    .unwrap();
    let current = checkpoint_bundle_at(0x93, 1, 0xa0, 2_000);
    let refreshed = checkpoint_bundle_at(0x93, 1, 0xa0, 2_001);
    let conflict = checkpoint_bundle_at(0x93, 2, 0xb0, 2_002);
    let longer_conflict = checkpoint_bundle_at(0x93, 3, 0xb0, 2_003);
    let lower = checkpoint_bundle_at(0x93, 1, 0xa0, 2_004);
    let account_id = current
        .verified_checkpoint()
        .checkpoint()
        .body()
        .account_id();
    let current_admission = current.provider_log_admission();
    let current_request = ProviderAdmissionRequest::for_admission(&current_admission).unwrap();

    store
        .append(
            authorize_provider_append(current_admission, current_request, &Allow).unwrap(),
            Timestamp::from_unix_millis(40),
            &signer,
        )
        .unwrap();
    store
        .append(
            {
                let admission = refreshed.provider_log_admission();
                let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
                authorize_provider_append(admission, request, &Allow).unwrap()
            },
            Timestamp::from_unix_millis(41),
            &signer,
        )
        .unwrap();
    assert_eq!(
        store.latest_checkpoint_bundle(account_id).unwrap().unwrap(),
        refreshed
    );

    store
        .append(
            {
                let admission = conflict.provider_log_admission();
                let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
                authorize_provider_append(admission, request, &Allow).unwrap()
            },
            Timestamp::from_unix_millis(42),
            &signer,
        )
        .unwrap();
    assert_eq!(
        store.latest_checkpoint_bundle(account_id),
        Err(IdentityError::AccountForked)
    );
    let conflict_id = conflict.verified_checkpoint().checkpoint_id();
    let explicit_conflict = store
        .checkpoint_bundle(account_id, conflict_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        explicit_conflict
            .bundle()
            .verified_checkpoint()
            .checkpoint_id(),
        conflict_id
    );
    explicit_conflict.receipt().verify(&provider).unwrap();
    let exact_page = store
        .checkpoint_lineage_page(account_id, conflict_id, 1, 4 * 1024 * 1024)
        .unwrap()
        .unwrap();
    assert_eq!(exact_page.checkpoints().len(), 1);
    assert_eq!(exact_page.next_prior_checkpoint_id(), None);
    store
        .append(
            {
                let admission = longer_conflict.provider_log_admission();
                let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
                authorize_provider_append(admission, request, &Allow).unwrap()
            },
            Timestamp::from_unix_millis(43),
            &signer,
        )
        .unwrap();
    assert_eq!(store.snapshot().unwrap().tree_size(), 4);
    assert_eq!(
        store.latest_checkpoint_bundle(account_id),
        Err(IdentityError::AccountForked)
    );
    assert_eq!(
        store.append(
            {
                let admission = lower.provider_log_admission();
                let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
                authorize_provider_append(admission, request, &Allow).unwrap()
            },
            Timestamp::from_unix_millis(44),
            &signer,
        ),
        Err(IdentityError::ProviderRollback)
    );
    assert_eq!(store.snapshot().unwrap().tree_size(), 4);
    let restored =
        MemoryProviderStore::restore_generation(store.export_generation().unwrap()).unwrap();
    assert_eq!(
        restored.latest_checkpoint_bundle(account_id),
        Err(IdentityError::AccountForked)
    );
}

#[cfg(feature = "provider-store")]
#[test]
fn redb_reopen_retains_signing_candidate_and_resumes_exactly() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider.redb");
    let signer = Signer(SecretKey::from_bytes(&[0x61; 32]));
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let log_id = typed_id::<ProviderLogId>(0x62);
    let checkpoint = checkpoint_bundle(0x63);
    let admission = checkpoint.provider_log_admission();
    let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();

    {
        let store =
            RedbProviderStore::open(&path, provider.clone(), log_id, ProviderKeyVersion::GENESIS)
                .unwrap();
        let permit = authorize_provider_append(admission.clone(), request, &Allow).unwrap();
        assert_eq!(
            store.append(permit, Timestamp::from_unix_millis(20), &UnavailableSigner,),
            Err(IdentityError::ProviderUnavailable)
        );
        assert_eq!(store.snapshot().unwrap().tree_size(), 0);
    }

    let store =
        RedbProviderStore::open(&path, provider.clone(), log_id, ProviderKeyVersion::GENESIS)
            .unwrap();
    assert_eq!(store.snapshot().unwrap().tree_size(), 0);
    let receipt = store.resume_append(&signer).unwrap();
    receipt.verify(&provider).unwrap();
    let export = store.export_generation().unwrap();
    let mirror = MemoryProviderStore::restore_generation(export.clone()).unwrap();
    let mirror_export = mirror.export_generation().unwrap();
    let recovery = recovery_export(export);
    let mirror_recovery = recovery_export(mirror_export);
    let inventory = derive_provider_retention_inventory(&recovery).unwrap();
    let authorization =
        verify_provider_compaction(&recovery, &mirror_recovery, &inventory).unwrap();
    store
        .record_compaction_manifest(&authorization, &mirror_recovery, &inventory)
        .unwrap();
    let expected = store.snapshot().unwrap();
    drop(store);

    let reopened =
        RedbProviderStore::open(&path, provider, log_id, ProviderKeyVersion::GENESIS).unwrap();
    assert_eq!(reopened.snapshot().unwrap(), expected);
    assert_eq!(
        reopened.compaction_manifests().unwrap(),
        vec![authorization.manifest().clone()]
    );
    let page = reopened
        .account_history(admission.account_id(), None, 1, 4 * 1024 * 1024)
        .unwrap();
    assert_eq!(page.records().len(), 1);
    assert_eq!(
        reopened
            .latest_checkpoint_bundle(admission.account_id())
            .unwrap()
            .unwrap(),
        checkpoint
    );
    reopened.consistency_proof(0, 1).unwrap();
}

#[cfg(feature = "provider-store")]
#[test]
fn redb_checkpoint_index_reopens_without_selecting_a_longer_fork() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider-fork-index.redb");
    let signer = Signer(SecretKey::from_bytes(&[0xb1; 32]));
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let log_id = typed_id::<ProviderLogId>(0xb2);
    let current = checkpoint_bundle_at(0xb3, 1, 0xc0, 3_000);
    let refreshed = checkpoint_bundle_at(0xb3, 1, 0xc0, 3_001);
    let conflict = checkpoint_bundle_at(0xb3, 2, 0xd0, 3_002);
    let longer_conflict = checkpoint_bundle_at(0xb3, 3, 0xd0, 3_003);
    let lower = checkpoint_bundle_at(0xb3, 1, 0xc0, 3_004);
    let account_id = current
        .verified_checkpoint()
        .checkpoint()
        .body()
        .account_id();

    {
        let store =
            RedbProviderStore::open(&path, provider.clone(), log_id, ProviderKeyVersion::GENESIS)
                .unwrap();
        for (offset, bundle) in [current, refreshed, conflict, longer_conflict]
            .into_iter()
            .enumerate()
        {
            let admission = bundle.provider_log_admission();
            let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
            store
                .append(
                    authorize_provider_append(admission, request, &Allow).unwrap(),
                    Timestamp::from_unix_millis(50 + u64::try_from(offset).unwrap()),
                    &signer,
                )
                .unwrap();
        }
        assert_eq!(store.snapshot().unwrap().tree_size(), 4);
        assert_eq!(
            store.latest_checkpoint_bundle(account_id),
            Err(IdentityError::AccountForked)
        );
    }

    let reopened =
        RedbProviderStore::open(&path, provider, log_id, ProviderKeyVersion::GENESIS).unwrap();
    assert_eq!(reopened.snapshot().unwrap().tree_size(), 4);
    assert_eq!(
        reopened.latest_checkpoint_bundle(account_id),
        Err(IdentityError::AccountForked)
    );
    let admission = lower.provider_log_admission();
    let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
    assert_eq!(
        reopened.append(
            authorize_provider_append(admission, request, &Allow).unwrap(),
            Timestamp::from_unix_millis(55),
            &signer,
        ),
        Err(IdentityError::ProviderRollback)
    );
    assert_eq!(reopened.snapshot().unwrap().tree_size(), 4);
}

#[test]
fn auditor_retains_authenticated_rollback_and_equivocation_across_instances() {
    let signer = Signer(SecretKey::from_bytes(&[0x71; 32]));
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let log_id = typed_id::<ProviderLogId>(0x72);
    let store = MemoryProviderAuditStore::new(provider.clone(), log_id);
    let auditor = DurableProviderAuditor::new(store.clone());
    let first = signed_head(&provider, log_id, 2, 0x73, 30, &signer);

    assert_eq!(
        auditor.observe(first.clone(), None).unwrap(),
        ProviderHeadAuditDisposition::FirstObserved
    );
    let rollback = signed_head(&provider, log_id, 1, 0x74, 31, &signer);
    assert_eq!(
        auditor.observe(rollback, None),
        Err(IdentityError::ProviderRollback)
    );
    assert_eq!(
        store.snapshot().unwrap().records().last().unwrap().status(),
        ProviderAuditStatus::Rollback
    );

    let conflict = signed_head(&provider, log_id, 2, 0x75, 32, &signer);
    assert_eq!(
        auditor.observe(conflict, None),
        Err(IdentityError::ProviderEquivocation)
    );
    let retained = store.snapshot().unwrap();
    retained
        .equivocation_evidence()
        .unwrap()
        .verify(&provider)
        .unwrap();

    let reopened = DurableProviderAuditor::new(store);
    assert_eq!(
        reopened.observe(first, None),
        Err(IdentityError::ProviderEquivocation)
    );
}

#[cfg(feature = "provider-store")]
#[test]
fn redb_auditor_reopens_with_terminal_equivocation_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider-audit.redb");
    let signer = Signer(SecretKey::from_bytes(&[0x81; 32]));
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let log_id = typed_id::<ProviderLogId>(0x82);
    let first = signed_head(&provider, log_id, 3, 0x83, 40, &signer);
    let conflict = signed_head(&provider, log_id, 3, 0x84, 41, &signer);
    {
        let store = RedbProviderAuditStore::open(&path, provider.clone(), log_id).unwrap();
        let auditor = DurableProviderAuditor::new(store);
        auditor.observe(first, None).unwrap();
        assert_eq!(
            auditor.observe(conflict, None),
            Err(IdentityError::ProviderEquivocation)
        );
    }

    let reopened = RedbProviderAuditStore::open(&path, provider.clone(), log_id).unwrap();
    let evidence = reopened
        .snapshot()
        .unwrap()
        .equivocation_evidence()
        .cloned()
        .unwrap();
    evidence.verify(&provider).unwrap();
}
