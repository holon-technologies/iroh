#![cfg(all(feature = "fs-store", feature = "provider-store"))]

use std::{
    collections::BTreeSet,
    convert::Infallible,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use futures_lite::future::block_on;
use krikos_base::SecretKey;
use krikos_identity::{
    AccountGenesis, AccountId, AccountOperation, AccountState, AccountStore, AdmissionEvidence,
    AgreementSecretKey, AlgorithmSignature, ApplicationId, BeginRecovery, CanonicalWire,
    CheckpointAuthorization, CheckpointId, ClaimEffects, ControlPolicy, ControllerApprovalBody,
    ControllerApprovals, ControllerClass, ControllerDescriptor, ControllerKeyId, ControllerScope,
    ControllerSelector, ControllerThreshold, ControllerWeight, CryptoSuiteDescriptor,
    DelayEvidence, DeviceAuthorization, DeviceClass, DeviceDescriptor, Digest, DurationMillis,
    EffectFailure, EffectId, EffectRecord, EffectStatus, EndpointPublicKey, Epoch, EventBody,
    EventIntentApprovalBody, EventIntentApprovals, EventPredecessors, Extensions, FinalizeRecovery,
    FreshnessEvidence, FreshnessRequirement, GroupId, GroupKey, GroupKeyDistributionSnapshot,
    GroupKeyEpoch, HashAlgorithm, IdentityError, InclusionReceipt, KeyedSignature, LeaseId,
    MemoryAccountStore, MemoryOperationalEffectStore, OperationKind,
    OperationalCheckpointAuthorizer, OperationalCheckpointBuild, OperationalEffectJournal,
    OperationalEffectPhase, OperationalEffectStore, OperationalPeerNotifier, PolicyRule,
    ProjectionEffect, ProjectionLifecycle, ProtocolSignature, ProtocolVersion,
    ProviderAdmissionControl, ProviderAdmissionRequest, ProviderDescriptor, ProviderFreshness,
    ProviderHeadBody, ProviderHeadSigner, ProviderKeyVersion, ProviderLogEntryBody, ProviderLogId,
    ProviderLogSubject, ProviderPolicy, ProviderPolicyVersion, ProviderQuorum, ProviderReceipts,
    PublicationStage, PublicationTracker, RecoveryAuthority, RecoveryAuthorityPlan,
    RecoveryDelayAnchor, RecoveryId, RecoveryPolicy, RecoveryPolicyVersion, RecoveryProposal,
    RecoveryThresholdEvidence, RedbAccountStore, RedbOperationalEffectStore, RedbProviderStore,
    RequiredWeight, Sequence, SignedCheckpoint, SignedControllerApproval,
    SignedEventIntentApproval, SignedProviderHead, SigningPublicKey, StoreFuture, Timestamp,
    authorize_provider_append, build_authorize_and_commit_checkpoint, build_checkpoint_body,
    build_provider_checkpoint_bundle_from_genesis, complete_ready_effect,
    merkle::MerkleConsistencyProof, rotate_group_key_with_rng, verify_checkpoint,
};
use rand_core::{TryCryptoRng, TryRng};
use redb::{Database, ReadableTable, TableDefinition};

const TEST_OPERATION_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("krikos-operational-effects-v1");

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

struct ProviderSigner(SecretKey);

impl ProviderHeadSigner for ProviderSigner {
    fn sign_provider_head(&self, message: &[u8]) -> Result<ProtocolSignature, IdentityError> {
        Ok(ProtocolSignature::ed25519(self.0.sign(message).to_bytes()))
    }
}

struct AllowProviderAdmission;

impl ProviderAdmissionControl for AllowProviderAdmission {
    fn check(
        &self,
        _admission: krikos_identity::ProviderLogAdmission,
        _request: ProviderAdmissionRequest,
    ) -> Result<(), IdentityError> {
        Ok(())
    }
}

#[derive(Clone, Default)]
struct IdempotentNotifier {
    notified: Arc<Mutex<BTreeSet<EffectId>>>,
}

impl IdempotentNotifier {
    fn unique_notifications(&self) -> usize {
        self.notified.lock().unwrap().len()
    }
}

impl OperationalPeerNotifier for IdempotentNotifier {
    fn notify<'a>(&'a self, effect: &'a EffectRecord) -> StoreFuture<'a, ()> {
        let result = self
            .notified
            .lock()
            .map_err(|_| IdentityError::StorageCorruption)
            .map(|mut notified| {
                notified.insert(effect.id());
            });
        Box::pin(async move { result })
    }
}

fn digest(fill: u8) -> Digest {
    Digest::new(HashAlgorithm::Blake3_256, [fill; 32])
}

fn typed_id<T: CanonicalWire>(fill: u8) -> T {
    T::from_canonical_bytes(&digest(fill).to_canonical_bytes().unwrap()).unwrap()
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

fn provider(secret: &SecretKey) -> ProviderDescriptor {
    ProviderDescriptor::new(
        SigningPublicKey::ed25519(*secret.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap()
}

fn rule(operation: OperationKind, provider_freshness: bool) -> PolicyRule {
    let freshness = if provider_freshness {
        FreshnessRequirement::provider_quorum(
            ProviderFreshness::new(ProviderQuorum::new(2).unwrap(), DurationMillis::new(1_000))
                .unwrap(),
        )
    } else {
        FreshnessRequirement::latest_known()
    };
    PolicyRule::new(
        operation,
        RequiredWeight::new(1).unwrap(),
        ControllerSelector::any_active(),
        freshness,
        None,
        Extensions::default(),
    )
    .unwrap()
}

fn fixture(
    first_provider: &ProviderDescriptor,
    second_provider: &ProviderDescriptor,
) -> (AccountGenesis, SecretKey) {
    let controller_secret = SecretKey::from_bytes(&[0x11; 32]);
    let control_policy = ControlPolicy::new(
        vec![
            rule(OperationKind::AuthorizeDevice, false),
            rule(OperationKind::BeginRecovery, false),
            rule(OperationKind::CancelRecovery, false),
            rule(OperationKind::FinalizeRecovery, true),
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
    let provider_policy = ProviderPolicy::replicated(
        ProviderPolicyVersion::GENESIS,
        vec![first_provider.clone(), second_provider.clone()],
        ProviderQuorum::new(2).unwrap(),
        ProviderQuorum::new(2).unwrap(),
        DurationMillis::new(1_000),
        Extensions::default(),
    )
    .unwrap();
    let genesis = AccountGenesis::new(
        [0x12; 32],
        Timestamp::from_unix_millis(1),
        control_policy,
        vec![controller(&controller_secret)],
        recovery_policy,
        provider_policy,
        Extensions::default(),
    )
    .unwrap();
    (genesis, controller_secret)
}

fn device_authorization(agreement_secret: &AgreementSecretKey) -> DeviceAuthorization {
    let application_secret = SecretKey::from_bytes(&[0x21; 32]);
    let endpoint_secret = SecretKey::from_bytes(&[0x22; 32]);
    let descriptor = DeviceDescriptor::new(
        SigningPublicKey::ed25519(*application_secret.public().as_bytes()).unwrap(),
        agreement_secret.public_key().unwrap(),
        EndpointPublicKey::new(
            SigningPublicKey::ed25519(*endpoint_secret.public().as_bytes()).unwrap(),
        ),
        Extensions::default(),
    )
    .unwrap();
    DeviceAuthorization::new(
        descriptor.id().unwrap(),
        descriptor,
        DeviceClass::ApplicationOnly,
        None,
        Vec::new(),
        Epoch::new(1),
        Extensions::default(),
    )
    .unwrap()
}

fn controller_intent_approvals(
    state: &AccountState,
    body: &EventBody,
    signer: &SecretKey,
) -> EventIntentApprovals {
    let signing_key = SigningPublicKey::ed25519(*signer.public().as_bytes()).unwrap();
    let controller_id = state
        .active_controllers()
        .iter()
        .find(|controller| controller.signing_key() == signing_key)
        .unwrap()
        .id();
    let body = EventIntentApprovalBody::new(
        controller_id,
        body.proposal_id().unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let signature = signer.sign(&body.to_canonical_bytes().unwrap());
    EventIntentApprovals::new(vec![
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
        .unwrap(),
    ])
    .unwrap()
}

fn authorize_with_evidence(
    state: &AccountState,
    body: EventBody,
    evidence: AdmissionEvidence,
    signer: &SecretKey,
) -> krikos_identity::AuthorizedEvent {
    let event_id = evidence.event_id_for_body(&body).unwrap();
    let signing_key = SigningPublicKey::ed25519(*signer.public().as_bytes()).unwrap();
    let controller_id = state
        .active_controllers()
        .iter()
        .find(|controller| controller.signing_key() == signing_key)
        .unwrap()
        .id();
    let approval_body = ControllerApprovalBody::event(
        controller_id,
        event_id,
        evidence.admission_evidence_id().unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let signature = signer.sign(&approval_body.to_canonical_bytes().unwrap());
    let approval = SignedControllerApproval::new(
        approval_body,
        vec![KeyedSignature::new(
            CryptoSuiteDescriptor::v1()
                .unwrap()
                .crypto_suite_id()
                .unwrap(),
            ControllerKeyId::for_signing_key(&signing_key).unwrap(),
            AlgorithmSignature::new(1, signature.to_bytes().to_vec()).unwrap(),
        )],
    )
    .unwrap();
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
    nonce: u8,
    signer: &SecretKey,
) -> krikos_identity::AuthorizedEvent {
    let epoch = state.expected_epoch_for(&operation).unwrap();
    let predecessors = if state.sequence() == Sequence::GENESIS {
        EventPredecessors::genesis(state.genesis_anchor())
    } else {
        EventPredecessors::events(state.heads().to_vec()).unwrap()
    };
    let body = EventBody::new(
        state.account_id(),
        state.sequence().checked_next().unwrap(),
        epoch,
        predecessors,
        operation,
        Timestamp::from_unix_millis(u64::from(nonce)),
        [nonce; 16],
        Extensions::default(),
    )
    .unwrap();
    let checkpoint_id = typed_id::<CheckpointId>(0x31);
    let evidence = AdmissionEvidence::new(
        body.proposal_id().unwrap(),
        checkpoint_id,
        state.provider_policy_id(),
        FreshnessEvidence::local_known(checkpoint_id),
        DelayEvidence::none(),
        Extensions::default(),
    )
    .unwrap();
    authorize_with_evidence(state, body, evidence, signer)
}

#[allow(clippy::too_many_arguments)]
fn provider_receipt(
    provider_secret: &SecretKey,
    provider: &ProviderDescriptor,
    account_id: krikos_identity::AccountId,
    subject: ProviderLogSubject,
    log_fill: u8,
    entry_observed_at: u64,
    head_observed_at: u64,
) -> InclusionReceipt {
    let log_id = typed_id::<ProviderLogId>(log_fill);
    let entry = ProviderLogEntryBody::new(
        provider.id().unwrap(),
        log_id,
        account_id,
        subject,
        Timestamp::from_unix_millis(entry_observed_at),
        Extensions::default(),
    )
    .unwrap();
    let head = ProviderHeadBody::new(
        provider.id().unwrap(),
        log_id,
        ProviderKeyVersion::GENESIS,
        1,
        entry.merkle_leaf_hash().unwrap(),
        Timestamp::from_unix_millis(head_observed_at),
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

fn begin_recovery_event(
    state: &AccountState,
    signer: &SecretKey,
    retained_device: krikos_identity::DeviceId,
    providers: &[(&SecretKey, &ProviderDescriptor, u8)],
) -> (krikos_identity::AuthorizedEvent, RecoveryId) {
    let plan = RecoveryAuthorityPlan::try_new(
        ProtocolVersion::V1,
        state.account_id(),
        typed_id::<CheckpointId>(0x32),
        state.heads()[0],
        state.recovery_policy_id(),
        state.recovery_policy().policy_version(),
        [0x33; 32],
        vec![controller(signer)],
        state.control_policy().clone(),
        state.recovery_policy().clone(),
        vec![retained_device],
        Timestamp::from_unix_millis(1_000),
        Extensions::default(),
    )
    .unwrap();
    let proposal =
        RecoveryProposal::try_new(ProtocolVersion::V1, plan, Extensions::default()).unwrap();
    let recovery_id = proposal.recovery_id().unwrap();
    let operation = AccountOperation::BeginRecovery(
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
    );
    let body = EventBody::new(
        state.account_id(),
        state.sequence().checked_next().unwrap(),
        state.expected_epoch_for(&operation).unwrap(),
        EventPredecessors::events(state.heads().to_vec()).unwrap(),
        operation,
        Timestamp::from_unix_millis(100),
        [0x34; 16],
        Extensions::default(),
    )
    .unwrap();
    let proposal_id = body.proposal_id().unwrap();
    let delay_receipts = providers
        .iter()
        .map(|(secret, descriptor, log_fill)| {
            provider_receipt(
                secret,
                descriptor,
                state.account_id(),
                ProviderLogSubject::EventIntent(proposal_id),
                *log_fill,
                100,
                100,
            )
        })
        .collect();
    let checkpoint_id = typed_id::<CheckpointId>(0x32);
    let evidence = AdmissionEvidence::new(
        proposal_id,
        checkpoint_id,
        state.provider_policy_id(),
        FreshnessEvidence::local_known(checkpoint_id),
        DelayEvidence::provider_quorum(
            state.provider_policy_id(),
            ProviderQuorum::new(2).unwrap(),
            controller_intent_approvals(state, &body, signer),
            ProviderReceipts::new(delay_receipts).unwrap(),
        )
        .unwrap(),
        Extensions::default(),
    )
    .unwrap();
    (
        authorize_with_evidence(state, body, evidence, signer),
        recovery_id,
    )
}

fn finalize_recovery_event(
    state: &AccountState,
    recovery_id: RecoveryId,
    begin_proposal_id: krikos_identity::ProposalId,
    providers: &[(&SecretKey, &ProviderDescriptor, u8)],
) -> krikos_identity::AuthorizedEvent {
    let anchor_receipts = providers
        .iter()
        .map(|(secret, descriptor, log_fill)| {
            provider_receipt(
                secret,
                descriptor,
                state.account_id(),
                ProviderLogSubject::EventIntent(begin_proposal_id),
                *log_fill,
                100,
                110,
            )
        })
        .collect();
    let anchor = RecoveryDelayAnchor::try_new(
        ProtocolVersion::V1,
        state.account_id(),
        recovery_id,
        begin_proposal_id,
        state.provider_policy_id(),
        ProviderQuorum::new(2).unwrap(),
        ProviderReceipts::new(anchor_receipts).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let operation = AccountOperation::FinalizeRecovery(
        FinalizeRecovery::try_new(
            ProtocolVersion::V1,
            recovery_id,
            anchor,
            Timestamp::from_unix_millis(110),
            Extensions::default(),
        )
        .unwrap(),
    );
    let body = EventBody::new(
        state.account_id(),
        state.sequence().checked_next().unwrap(),
        state.epoch().checked_next().unwrap(),
        EventPredecessors::events(state.heads().to_vec()).unwrap(),
        operation,
        Timestamp::from_unix_millis(110),
        [0x36; 16],
        Extensions::default(),
    )
    .unwrap();
    let checkpoint_id = typed_id::<CheckpointId>(0x37);
    let completion_receipts = providers
        .iter()
        .enumerate()
        .map(|(index, (secret, descriptor, _))| {
            provider_receipt(
                secret,
                descriptor,
                state.account_id(),
                ProviderLogSubject::Checkpoint(checkpoint_id),
                0x40 + u8::try_from(index).unwrap(),
                100,
                110,
            )
        })
        .collect();
    let evidence = AdmissionEvidence::new(
        body.proposal_id().unwrap(),
        checkpoint_id,
        state.provider_policy_id(),
        FreshnessEvidence::provider_quorum(
            checkpoint_id,
            state.provider_policy_id(),
            ProviderReceipts::new(completion_receipts).unwrap(),
        )
        .unwrap(),
        DelayEvidence::none(),
        Extensions::default(),
    )
    .unwrap();
    krikos_identity::AuthorizedEvent::new(
        body,
        evidence,
        ControllerApprovals::new(Vec::new()).unwrap(),
    )
    .unwrap()
}

fn effect_for_event(
    effects: &[EffectRecord],
    event_id: krikos_identity::EventId,
    matches_kind: impl Fn(ProjectionEffect) -> bool,
) -> EffectRecord {
    effects
        .iter()
        .find(|effect| {
            let effect_event_id = match effect.effect() {
                ProjectionEffect::PublishAccountEvent { event_id }
                | ProjectionEffect::RotateGroupKeys { event_id, .. }
                | ProjectionEffect::NotifyAccountChanged { event_id }
                | ProjectionEffect::NotifyForkDetected { event_id } => event_id,
            };
            effect_event_id == event_id && matches_kind(effect.effect())
        })
        .unwrap()
        .clone()
}

fn append_checkpoint(
    store: &RedbProviderStore,
    bundle: &krikos_identity::ProviderCheckpointBundle,
    observed_at: u64,
    signer: &ProviderSigner,
) -> InclusionReceipt {
    let admission = bundle.provider_log_admission();
    let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
    store
        .append(
            authorize_provider_append(admission, request, &AllowProviderAdmission).unwrap(),
            Timestamp::from_unix_millis(observed_at),
            signer,
        )
        .unwrap()
}

fn observe_checkpoint(
    store: &RedbProviderStore,
    bundle: &krikos_identity::ProviderCheckpointBundle,
    observed_at: u64,
    signer: &ProviderSigner,
) -> (InclusionReceipt, MerkleConsistencyProof) {
    let receipt = append_checkpoint(store, bundle, observed_at, signer);
    let proof = store.consistency_proof(1, 1).unwrap();
    (receipt, proof)
}

#[derive(Clone)]
struct DirectSubsetAuthorizer {
    signer_fills: Vec<u8>,
    calls: Arc<AtomicUsize>,
}

impl DirectSubsetAuthorizer {
    fn new(signer_fills: Vec<u8>) -> Self {
        Self {
            signer_fills,
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl OperationalCheckpointAuthorizer for DirectSubsetAuthorizer {
    fn authorize<'a>(
        &'a self,
        body: &'a krikos_identity::CheckpointBody,
    ) -> StoreFuture<'a, SignedCheckpoint> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let result = (|| {
            let checkpoint_id = body.checkpoint_id()?;
            let mut approvals = Vec::with_capacity(self.signer_fills.len());
            for fill in &self.signer_fills {
                let signer = SecretKey::from_bytes(&[*fill; 32]);
                let descriptor = controller(&signer);
                let signing_key = descriptor.signing_key();
                let approval_body = ControllerApprovalBody::checkpoint(
                    descriptor.id()?,
                    checkpoint_id,
                    Extensions::default(),
                )?;
                let signature = signer.sign(&approval_body.to_canonical_bytes()?);
                approvals.push(SignedControllerApproval::new(
                    approval_body,
                    vec![KeyedSignature::new(
                        CryptoSuiteDescriptor::v1()?.crypto_suite_id()?,
                        ControllerKeyId::for_signing_key(&signing_key)?,
                        AlgorithmSignature::new(1, signature.to_bytes().to_vec())?,
                    )],
                )?);
            }
            SignedCheckpoint::new(
                body.clone(),
                CheckpointAuthorization::controllers(
                    checkpoint_id,
                    ControllerApprovals::new(approvals)?,
                )?,
            )
        })();
        Box::pin(async move { result })
    }
}

#[derive(Debug, Clone, Copy)]
struct DirectSubsetRetryContext {
    account_id: AccountId,
    effect_id: EffectId,
}

fn prepare_direct_subset_checkpoint_crash<A, J>(
    account_store: &A,
    journal: &OperationalEffectJournal<J>,
) -> DirectSubsetRetryContext
where
    A: AccountStore + ?Sized,
    J: OperationalEffectStore,
{
    let first = SecretKey::from_bytes(&[0x91; 32]);
    let second = SecretKey::from_bytes(&[0x92; 32]);
    let third = SecretKey::from_bytes(&[0x93; 32]);
    let control_policy = ControlPolicy::new(
        vec![
            rule(OperationKind::AddController, false),
            rule(OperationKind::ChangeProviderPolicy, false),
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
        [0x94; 32],
        Timestamp::from_unix_millis(1),
        control_policy,
        vec![controller(&first), controller(&second)],
        recovery_policy,
        ProviderPolicy::local_only(ProviderPolicyVersion::GENESIS, Extensions::default()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let account_id = genesis.account_id().unwrap();
    let initial = block_on(account_store.create_account(genesis)).unwrap();
    let event = authorized_event(
        initial.state(),
        AccountOperation::AddController(controller(&third)),
        0x95,
        &first,
    );
    let event_id = event.event_id().unwrap();
    let committed =
        block_on(account_store.commit_event(initial.revision().clone(), event)).unwrap();
    let claimed = block_on(
        account_store.claim_effects(
            account_id,
            ClaimEffects::new(
                Timestamp::from_unix_millis(200),
                Timestamp::from_unix_millis(250),
                LeaseId::new([0x96; 16]).unwrap(),
                8,
            )
            .unwrap(),
        ),
    )
    .unwrap();
    let publish = effect_for_event(&claimed, event_id, |effect| {
        matches!(effect, ProjectionEffect::PublishAccountEvent { .. })
    });
    journal
        .begin(&publish, Timestamp::from_unix_millis(201))
        .unwrap();
    let body = build_checkpoint_body(
        committed.snapshot().state(),
        Timestamp::from_unix_millis(210),
    )
    .unwrap();
    journal
        .record_checkpoint_draft(publish.id(), body.clone(), Timestamp::from_unix_millis(211))
        .unwrap();
    let first_subset = DirectSubsetAuthorizer::new(vec![0x91]);
    let signed = block_on(first_subset.authorize(&body)).unwrap();
    let verified = verify_checkpoint(committed.snapshot().state(), &signed, None).unwrap();
    block_on(account_store.commit_checkpoint(committed.snapshot().revision().clone(), verified))
        .unwrap();
    assert_eq!(first_subset.calls(), 1);
    assert!(
        journal
            .load(publish.id())
            .unwrap()
            .unwrap()
            .checkpoint()
            .is_none()
    );
    DirectSubsetRetryContext {
        account_id,
        effect_id: publish.id(),
    }
}

fn finish_direct_subset_checkpoint_retry<A, J>(
    account_store: &A,
    journal: &OperationalEffectJournal<J>,
    context: DirectSubsetRetryContext,
) where
    A: AccountStore + ?Sized,
    J: OperationalEffectStore,
{
    let snapshot = block_on(account_store.load_account(context.account_id))
        .unwrap()
        .unwrap();
    let alternate_subset = DirectSubsetAuthorizer::new(vec![0x92]);
    let build = OperationalCheckpointBuild::new(
        context.effect_id,
        &snapshot,
        Timestamp::from_unix_millis(210),
        None,
        Timestamp::from_unix_millis(211),
        Timestamp::from_unix_millis(212),
    );
    let committed = block_on(build_authorize_and_commit_checkpoint(
        account_store,
        journal,
        &alternate_subset,
        build,
    ))
    .unwrap();
    let approvals = committed
        .checkpoint()
        .checkpoint()
        .authorization()
        .controller_approvals()
        .unwrap();
    assert_eq!(approvals.as_slice().len(), 2);
    assert_eq!(alternate_subset.calls(), 1);
    let retained = journal.load(context.effect_id).unwrap().unwrap();
    assert_eq!(
        retained
            .checkpoint()
            .unwrap()
            .authorization()
            .controller_approvals()
            .unwrap()
            .as_slice()
            .len(),
        2
    );

    let replayed = block_on(build_authorize_and_commit_checkpoint(
        account_store,
        journal,
        &alternate_subset,
        build,
    ))
    .unwrap();
    assert_eq!(
        replayed.checkpoint().checkpoint_id(),
        committed.checkpoint().checkpoint_id()
    );
    assert_eq!(alternate_subset.calls(), 1);
}

#[test]
fn memory_checkpoint_retry_merges_an_alternate_sufficient_approval_subset() {
    let account_store = MemoryAccountStore::new();
    let operation_store = MemoryOperationalEffectStore::new();
    let context = prepare_direct_subset_checkpoint_crash(
        &account_store,
        &OperationalEffectJournal::new(operation_store.clone()),
    );
    finish_direct_subset_checkpoint_retry(
        &account_store,
        &OperationalEffectJournal::new(operation_store),
        context,
    );
}

#[test]
fn redb_checkpoint_retry_merges_an_alternate_sufficient_subset_after_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let account_path = directory.path().join("alternate-subset-accounts.redb");
    let operation_path = directory.path().join("alternate-subset-operations.redb");
    let context = {
        let account_store = RedbAccountStore::open(&account_path).unwrap();
        let operation_store = RedbOperationalEffectStore::open(&operation_path).unwrap();
        prepare_direct_subset_checkpoint_crash(
            &account_store,
            &OperationalEffectJournal::new(operation_store),
        )
    };
    let account_store = RedbAccountStore::open(&account_path).unwrap();
    let operation_store = RedbOperationalEffectStore::open(&operation_path).unwrap();
    finish_direct_subset_checkpoint_retry(
        &account_store,
        &OperationalEffectJournal::new(operation_store),
        context,
    );
}

#[test]
fn redb_truncated_operational_effect_is_rejected_on_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let account_path = directory.path().join("corrupt-effect-accounts.redb");
    let operation_path = directory.path().join("corrupt-effect-operations.redb");
    let context = {
        let account_store = RedbAccountStore::open(&account_path).unwrap();
        let operation_store = RedbOperationalEffectStore::open(&operation_path).unwrap();
        prepare_direct_subset_checkpoint_crash(
            &account_store,
            &OperationalEffectJournal::new(operation_store),
        )
    };
    let database = Database::create(&operation_path).unwrap();
    let write = database.begin_write().unwrap();
    {
        let mut table = write.open_table(TEST_OPERATION_TABLE).unwrap();
        let value = table
            .get(context.effect_id.as_bytes().as_slice())
            .unwrap()
            .unwrap();
        let mut bytes = value.value().to_vec();
        drop(value);
        bytes.pop().unwrap();
        table
            .insert(context.effect_id.as_bytes().as_slice(), bytes.as_slice())
            .unwrap();
    }
    write.commit().unwrap();
    drop(database);
    assert!(matches!(
        RedbOperationalEffectStore::open(&operation_path),
        Err(IdentityError::StorageCorruption)
    ));
}

#[test]
fn finalized_recovery_effects_reconcile_across_every_durable_boundary() {
    let directory = tempfile::tempdir().unwrap();
    let account_path = directory.path().join("accounts.redb");
    let operation_path = directory.path().join("operations.redb");
    let first_provider_path = directory.path().join("provider-first.redb");
    let second_provider_path = directory.path().join("provider-second.redb");
    let first_provider_secret = SecretKey::from_bytes(&[0x41; 32]);
    let second_provider_secret = SecretKey::from_bytes(&[0x42; 32]);
    let first_provider = provider(&first_provider_secret);
    let second_provider = provider(&second_provider_secret);
    let providers = [
        (&first_provider_secret, &first_provider, 0x51),
        (&second_provider_secret, &second_provider, 0x52),
    ];
    let (genesis, controller_secret) = fixture(&first_provider, &second_provider);
    let account_id = genesis.account_id().unwrap();
    let agreement_secret = AgreementSecretKey::from_bytes([0x23; 32]);
    let device = device_authorization(&agreement_secret);
    let device_id = device.device_id();

    let account_store = RedbAccountStore::open(&account_path).unwrap();
    let initial = block_on(account_store.create_account(genesis.clone())).unwrap();
    let authorize_device = authorized_event(
        initial.state(),
        AccountOperation::AuthorizeDevice(device),
        0x24,
        &controller_secret,
    );
    let authorized =
        block_on(account_store.commit_event(initial.revision().clone(), authorize_device.clone()))
            .unwrap();
    let (begin_recovery, recovery_id) = begin_recovery_event(
        authorized.snapshot().state(),
        &controller_secret,
        device_id,
        &providers,
    );
    let begin_proposal_id = begin_recovery.body().proposal_id().unwrap();
    let pending = block_on(account_store.commit_event(
        authorized.snapshot().revision().clone(),
        begin_recovery.clone(),
    ))
    .unwrap();
    assert_eq!(
        pending.snapshot().state().lifecycle(),
        ProjectionLifecycle::RecoveryPending
    );
    drop(account_store);

    let account_store = RedbAccountStore::open(&account_path).unwrap();
    let pending = block_on(account_store.load_account(account_id))
        .unwrap()
        .unwrap();
    assert_eq!(
        pending.state().lifecycle(),
        ProjectionLifecycle::RecoveryPending
    );
    let finalize_recovery =
        finalize_recovery_event(pending.state(), recovery_id, begin_proposal_id, &providers);
    let final_event_id = finalize_recovery.event_id().unwrap();
    let finalized =
        block_on(account_store.commit_event(pending.revision().clone(), finalize_recovery.clone()))
            .unwrap();
    assert_eq!(
        finalized.snapshot().state().lifecycle(),
        ProjectionLifecycle::Active
    );
    let final_revision = finalized.snapshot().revision().clone();
    let final_state = finalized.snapshot().state().clone();
    drop(account_store);

    let account_store = RedbAccountStore::open(&account_path).unwrap();
    let reopened = block_on(account_store.load_account(account_id))
        .unwrap()
        .unwrap();
    assert_eq!(reopened.revision(), &final_revision);
    assert_eq!(reopened.state(), &final_state);
    let first_lease = LeaseId::new([0x61; 16]).unwrap();
    let claimed = block_on(
        account_store.claim_effects(
            account_id,
            ClaimEffects::new(
                Timestamp::from_unix_millis(200),
                Timestamp::from_unix_millis(250),
                first_lease,
                32,
            )
            .unwrap(),
        ),
    )
    .unwrap();
    let rotation_effect = effect_for_event(&claimed, final_event_id, |effect| {
        matches!(effect, ProjectionEffect::RotateGroupKeys { .. })
    });
    let publish_effect = effect_for_event(&claimed, final_event_id, |effect| {
        matches!(effect, ProjectionEffect::PublishAccountEvent { .. })
    });
    let notification_effect = effect_for_event(&claimed, final_event_id, |effect| {
        matches!(effect, ProjectionEffect::NotifyAccountChanged { .. })
    });
    let operation_store = RedbOperationalEffectStore::open(&operation_path).unwrap();
    let journal = OperationalEffectJournal::new(operation_store.clone());
    for effect in [&rotation_effect, &publish_effect, &notification_effect] {
        journal
            .begin(effect, Timestamp::from_unix_millis(201))
            .unwrap();
    }

    let application_id = ApplicationId::new(digest(0x62));
    let group_id = GroupId::new(digest(0x63));
    assert_eq!(
        block_on(account_store.authorize_protected_write(
            final_revision.clone(),
            application_id,
            group_id,
        )),
        Err(IdentityError::ProtectedWritesBlocked)
    );
    let distribution = GroupKeyDistributionSnapshot::from_post_state(
        &final_state,
        application_id,
        group_id,
        GroupKeyEpoch::new(3),
        vec![device_id],
    )
    .unwrap();
    let rotation = rotate_group_key_with_rng(
        &distribution,
        &GroupKey::new([0x64; 32]),
        &mut RepeatingRng(0x65),
    )
    .unwrap();
    let replay_rotation = rotate_group_key_with_rng(
        &distribution,
        &GroupKey::new([0x64; 32]),
        &mut RepeatingRng(0x65),
    )
    .unwrap();
    let stored_rotation = block_on(account_store.commit_group_key_rotation(
        rotation_effect.id(),
        first_lease,
        rotation,
        Timestamp::from_unix_millis(202),
    ))
    .unwrap();
    drop(journal);
    drop(operation_store);
    drop(account_store);

    let account_store = RedbAccountStore::open(&account_path).unwrap();
    let replayed_rotation = block_on(account_store.commit_group_key_rotation(
        rotation_effect.id(),
        first_lease,
        replay_rotation,
        Timestamp::from_unix_millis(202),
    ))
    .unwrap();
    assert_eq!(replayed_rotation, stored_rotation);
    let operation_store = RedbOperationalEffectStore::open(&operation_path).unwrap();
    let journal = OperationalEffectJournal::new(operation_store.clone());
    journal
        .record_rotation_committed(
            rotation_effect.id(),
            &stored_rotation,
            Timestamp::from_unix_millis(203),
        )
        .unwrap();
    journal
        .record_completed(rotation_effect.id(), Timestamp::from_unix_millis(204))
        .unwrap();
    block_on(account_store.authorize_protected_write(
        final_revision.clone(),
        application_id,
        group_id,
    ))
    .unwrap();

    let checkpoint_body =
        build_checkpoint_body(&final_state, Timestamp::from_unix_millis(210)).unwrap();
    let checkpoint = SignedCheckpoint::new(
        checkpoint_body.clone(),
        CheckpointAuthorization::transition_derived(&finalize_recovery).unwrap(),
    )
    .unwrap();
    let verified = verify_checkpoint(&final_state, &checkpoint, Some(&finalize_recovery)).unwrap();
    journal
        .record_checkpoint_draft(
            publish_effect.id(),
            checkpoint_body,
            Timestamp::from_unix_millis(211),
        )
        .unwrap();
    let checkpoint_commit =
        block_on(account_store.commit_checkpoint(final_revision.clone(), verified.clone()))
            .unwrap();
    drop(journal);
    drop(operation_store);
    drop(account_store);

    let account_store = RedbAccountStore::open(&account_path).unwrap();
    let replayed_checkpoint =
        block_on(account_store.commit_checkpoint(final_revision.clone(), verified.clone()))
            .unwrap();
    assert_eq!(
        replayed_checkpoint.checkpoint_id(),
        checkpoint_commit.checkpoint_id()
    );
    let operation_store = RedbOperationalEffectStore::open(&operation_path).unwrap();
    let journal = OperationalEffectJournal::new(operation_store.clone());
    journal
        .record_checkpoint_authorized(
            publish_effect.id(),
            &verified,
            final_state.provider_policy(),
            Timestamp::from_unix_millis(212),
        )
        .unwrap();

    let bundle = build_provider_checkpoint_bundle_from_genesis(
        &genesis,
        &[authorize_device, begin_recovery, finalize_recovery.clone()],
        &checkpoint,
        Some(&finalize_recovery),
    )
    .unwrap();
    let first_signer = ProviderSigner(first_provider_secret);
    let second_signer = ProviderSigner(second_provider_secret);
    let first_store = RedbProviderStore::open(
        &first_provider_path,
        first_provider.clone(),
        typed_id::<ProviderLogId>(0x71),
        ProviderKeyVersion::GENESIS,
    )
    .unwrap();
    let second_store = RedbProviderStore::open(
        &second_provider_path,
        second_provider.clone(),
        typed_id::<ProviderLogId>(0x72),
        ProviderKeyVersion::GENESIS,
    )
    .unwrap();
    let first_publication = append_checkpoint(&first_store, &bundle, 220, &first_signer);
    let checkpoint_id = verified.checkpoint_id();
    let mut tracker = PublicationTracker::new(
        account_id,
        checkpoint_id,
        final_state.provider_policy_id(),
        final_state.provider_policy(),
    )
    .unwrap();
    tracker.mark_authorized(&verified).unwrap();
    tracker
        .record_publication(first_publication.clone())
        .unwrap();
    let partial = journal
        .record_publications(
            publish_effect.id(),
            &tracker,
            Timestamp::from_unix_millis(221),
        )
        .unwrap();
    assert_eq!(partial.phase(), OperationalEffectPhase::Published);
    assert_eq!(partial.provider_receipts().len(), 1);

    let transient = EffectFailure::transient(0x73).unwrap();
    block_on(account_store.retry_effect(
        account_id,
        publish_effect.id(),
        first_lease,
        Timestamp::from_unix_millis(300),
        transient,
    ))
    .unwrap();
    drop(journal);
    drop(operation_store);
    drop(account_store);

    let account_store = RedbAccountStore::open(&account_path).unwrap();
    let operation_store = RedbOperationalEffectStore::open(&operation_path).unwrap();
    let journal = OperationalEffectJournal::new(operation_store.clone());
    journal
        .record_failure(
            publish_effect.id(),
            publish_effect.attempt_count(),
            transient,
            Timestamp::from_unix_millis(301),
        )
        .unwrap();
    let second_lease = LeaseId::new([0x74; 16]).unwrap();
    let retried = block_on(
        account_store.claim_effects(
            account_id,
            ClaimEffects::new(
                Timestamp::from_unix_millis(300),
                Timestamp::from_unix_millis(400),
                second_lease,
                32,
            )
            .unwrap(),
        ),
    )
    .unwrap();
    let retried_publish = effect_for_event(&retried, final_event_id, |effect| {
        matches!(effect, ProjectionEffect::PublishAccountEvent { .. })
    });
    let retried_notification = effect_for_event(&retried, final_event_id, |effect| {
        matches!(effect, ProjectionEffect::NotifyAccountChanged { .. })
    });
    let resumed = journal
        .begin(&retried_publish, Timestamp::from_unix_millis(302))
        .unwrap();
    assert_eq!(resumed.phase(), OperationalEffectPhase::Published);
    journal
        .begin(&retried_notification, Timestamp::from_unix_millis(302))
        .unwrap();

    let second_publication = append_checkpoint(&second_store, &bundle, 222, &second_signer);
    let mut tracker = PublicationTracker::new(
        account_id,
        checkpoint_id,
        final_state.provider_policy_id(),
        final_state.provider_policy(),
    )
    .unwrap();
    tracker.mark_authorized(&verified).unwrap();
    tracker
        .record_publication(first_publication.clone())
        .unwrap();
    tracker
        .record_publication(second_publication.clone())
        .unwrap();
    assert_eq!(tracker.stage(), PublicationStage::Replicated);
    let replicated = journal
        .record_publications(
            publish_effect.id(),
            &tracker,
            Timestamp::from_unix_millis(303),
        )
        .unwrap();
    assert_eq!(replicated.phase(), OperationalEffectPhase::Replicated);
    assert_eq!(replicated.provider_receipts().len(), 2);

    let (first_observation, first_proof) =
        observe_checkpoint(&first_store, &bundle, 230, &first_signer);
    tracker
        .record_observation(first_observation.clone(), &first_proof)
        .unwrap();
    let one_observation = journal
        .record_observation(
            publish_effect.id(),
            &tracker,
            first_observation.clone(),
            first_proof.clone(),
            Timestamp::from_unix_millis(304),
        )
        .unwrap();
    assert_eq!(one_observation.phase(), OperationalEffectPhase::Replicated);
    assert_eq!(
        one_observation
            .provider_receipts()
            .iter()
            .filter(|receipt| receipt.observation().is_some())
            .count(),
        1
    );
    drop(journal);
    drop(operation_store);

    let operation_store = RedbOperationalEffectStore::open(&operation_path).unwrap();
    let journal = OperationalEffectJournal::new(operation_store.clone());
    let retained = journal.load(publish_effect.id()).unwrap().unwrap();
    assert_eq!(retained.phase(), OperationalEffectPhase::Replicated);
    assert_eq!(
        retained
            .provider_receipts()
            .iter()
            .filter(|receipt| receipt.observation().is_some())
            .count(),
        1
    );
    let (second_observation, second_proof) =
        observe_checkpoint(&second_store, &bundle, 231, &second_signer);
    let mut tracker = PublicationTracker::new(
        account_id,
        checkpoint_id,
        final_state.provider_policy_id(),
        final_state.provider_policy(),
    )
    .unwrap();
    tracker.mark_authorized(&verified).unwrap();
    tracker.record_publication(first_publication).unwrap();
    tracker.record_publication(second_publication).unwrap();
    tracker
        .record_observation(first_observation, &first_proof)
        .unwrap();
    tracker
        .record_observation(second_observation.clone(), &second_proof)
        .unwrap();
    let observed = journal
        .record_observation(
            publish_effect.id(),
            &tracker,
            second_observation,
            second_proof,
            Timestamp::from_unix_millis(305),
        )
        .unwrap();
    assert_eq!(observed.phase(), OperationalEffectPhase::Observed);

    block_on(account_store.complete_effect(
        account_id,
        retried_publish.id(),
        second_lease,
        Timestamp::from_unix_millis(306),
    ))
    .unwrap();
    drop(journal);
    drop(operation_store);
    drop(account_store);

    let account_store = RedbAccountStore::open(&account_path).unwrap();
    let operation_store = RedbOperationalEffectStore::open(&operation_path).unwrap();
    let journal = OperationalEffectJournal::new(operation_store.clone());
    let snapshot = block_on(account_store.load_account(account_id))
        .unwrap()
        .unwrap();
    let completed_publish = snapshot
        .outbox()
        .iter()
        .find(|effect| effect.id() == retried_publish.id())
        .unwrap();
    assert_eq!(completed_publish.status(), EffectStatus::Completed);
    block_on(complete_ready_effect(
        &account_store,
        &journal,
        completed_publish,
        Timestamp::from_unix_millis(307),
    ))
    .unwrap();

    let notifier = IdempotentNotifier::default();
    block_on(notifier.notify(&retried_notification)).unwrap();
    journal
        .record_peers_notified(retried_notification.id(), Timestamp::from_unix_millis(308))
        .unwrap();
    drop(journal);
    drop(operation_store);

    let operation_store = RedbOperationalEffectStore::open(&operation_path).unwrap();
    let journal = OperationalEffectJournal::new(operation_store.clone());
    block_on(notifier.notify(&retried_notification)).unwrap();
    assert_eq!(notifier.unique_notifications(), 1);
    block_on(account_store.complete_effect(
        account_id,
        retried_notification.id(),
        second_lease,
        Timestamp::from_unix_millis(309),
    ))
    .unwrap();
    drop(journal);
    drop(operation_store);
    drop(account_store);

    let account_store = RedbAccountStore::open(&account_path).unwrap();
    let operation_store = RedbOperationalEffectStore::open(&operation_path).unwrap();
    let journal = OperationalEffectJournal::new(operation_store.clone());
    let snapshot = block_on(account_store.load_account(account_id))
        .unwrap()
        .unwrap();
    let completed_notification = snapshot
        .outbox()
        .iter()
        .find(|effect| effect.id() == retried_notification.id())
        .unwrap();
    block_on(complete_ready_effect(
        &account_store,
        &journal,
        completed_notification,
        Timestamp::from_unix_millis(310),
    ))
    .unwrap();

    for effect_id in [
        rotation_effect.id(),
        retried_publish.id(),
        retried_notification.id(),
    ] {
        assert_eq!(
            journal.load(effect_id).unwrap().unwrap().phase(),
            OperationalEffectPhase::Completed
        );
    }
    let snapshot = block_on(account_store.load_account(account_id))
        .unwrap()
        .unwrap();
    for effect_id in [
        rotation_effect.id(),
        retried_publish.id(),
        retried_notification.id(),
    ] {
        assert_eq!(
            snapshot
                .outbox()
                .iter()
                .find(|effect| effect.id() == effect_id)
                .unwrap()
                .status(),
            EffectStatus::Completed
        );
    }
    let metrics = operation_store.metrics().unwrap();
    assert_eq!(metrics.completed(), 3);
    assert_eq!(metrics.publication_shortfalls(), 0);
}
