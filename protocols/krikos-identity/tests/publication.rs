use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use futures_lite::future::block_on;
use krikos_base::SecretKey;
use krikos_identity::{
    AccountGenesis, AccountId, AccountOperation, AccountState, AdmissionEvidence,
    AlgorithmSignature, CanonicalWire, CheckpointAuthorization, CheckpointId, ControlPolicy,
    ControllerApprovalBody, ControllerApprovals, ControllerClass, ControllerDescriptor,
    ControllerKeyId, ControllerScope, ControllerSelector, ControllerThreshold, ControllerWeight,
    CryptoSuiteDescriptor, DelayEvidence, Digest, DurationMillis, Epoch, EventBody,
    EventPredecessors, Extensions, FreshnessEvidence, FreshnessRequirement, HashAlgorithm,
    IdentityError, InclusionReceipt, KeyedSignature, OperationKind, PolicyRule, ProtocolSignature,
    ProviderCheckpointBundle, ProviderCheckpointLineagePage, ProviderDescriptor, ProviderHeadBody,
    ProviderId, ProviderKeyVersion, ProviderLogEntryBody, ProviderLogId, ProviderLogSubject,
    ProviderPolicy, ProviderPolicyVersion, ProviderQuorum, PublicationStage, PublicationTracker,
    PublishedCheckpoint, RecoveryAuthority, RecoveryPolicy, RecoveryPolicyVersion, RequiredWeight,
    Sequence, SignedCheckpoint, SignedControllerApproval, SignedProviderHead, SigningPublicKey,
    StoreFuture, Timestamp, TransparencyClient, build_checkpoint_body,
    build_provider_checkpoint_bundle_from_genesis, limits::MAX_HISTORY_PAGE_EVENTS,
    merkle::AppendOnlyMerkleLog, publish_checkpoint_concurrently,
};

fn typed_id<T: CanonicalWire>(fill: u8) -> T {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [fill; 32]);
    T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
}

fn provider(secret: &SecretKey) -> ProviderDescriptor {
    ProviderDescriptor::new(
        SigningPublicKey::ed25519(*secret.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap()
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

fn verified_checkpoint(policy: &ProviderPolicy) -> (AccountId, ProviderCheckpointBundle) {
    let signer = SecretKey::from_bytes(&[0x71; 32]);
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
        [0x72; 32],
        Timestamp::from_unix_millis(1),
        control_policy,
        vec![controller(&signer)],
        recovery_policy,
        policy.clone(),
        Extensions::default(),
    )
    .unwrap();
    let mut state = AccountState::from_genesis(&genesis).unwrap();
    let event_body = EventBody::new(
        state.account_id(),
        Sequence::new(1),
        Epoch::new(1),
        EventPredecessors::genesis(state.genesis_anchor()),
        AccountOperation::AddController(controller(&SecretKey::from_bytes(&[0x73; 32]))),
        Timestamp::from_unix_millis(2),
        [0x74; 16],
        Extensions::default(),
    )
    .unwrap();
    let admission_checkpoint = typed_id::<CheckpointId>(0x75);
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
    let event_approval_body = ControllerApprovalBody::event(
        state.active_controllers()[0].id(),
        evidence.event_id_for_body(&event_body).unwrap(),
        evidence.admission_evidence_id().unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let event_signature = signer.sign(&event_approval_body.to_canonical_bytes().unwrap());
    let event_approval = SignedControllerApproval::new(
        event_approval_body,
        vec![KeyedSignature::new(
            CryptoSuiteDescriptor::v1()
                .unwrap()
                .crypto_suite_id()
                .unwrap(),
            ControllerKeyId::for_signing_key(&signing_key).unwrap(),
            AlgorithmSignature::new(1, event_signature.to_bytes().to_vec()).unwrap(),
        )],
    )
    .unwrap();
    let event = krikos_identity::AuthorizedEvent::new(
        event_body,
        evidence,
        ControllerApprovals::new(vec![event_approval]).unwrap(),
    )
    .unwrap();
    state.validate_and_apply(&event).unwrap();

    let checkpoint_body = build_checkpoint_body(&state, Timestamp::from_unix_millis(3)).unwrap();
    let checkpoint_id = checkpoint_body.checkpoint_id().unwrap();
    let controller_id = state
        .active_controllers()
        .iter()
        .find(|controller| controller.signing_key() == signing_key)
        .unwrap()
        .id();
    let checkpoint_approval_body =
        ControllerApprovalBody::checkpoint(controller_id, checkpoint_id, Extensions::default())
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
        checkpoint_body,
        CheckpointAuthorization::controllers(
            checkpoint_id,
            ControllerApprovals::new(vec![checkpoint_approval]).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let bundle = build_provider_checkpoint_bundle_from_genesis(
        &genesis,
        std::slice::from_ref(&event),
        &checkpoint,
        None,
    )
    .unwrap();
    (state.account_id(), bundle)
}

fn receipt(
    secret: &SecretKey,
    provider: &ProviderDescriptor,
    account_id: AccountId,
    checkpoint_id: CheckpointId,
    observed_at: u64,
    head_at: u64,
    fill: u8,
) -> InclusionReceipt {
    let entry = ProviderLogEntryBody::new(
        provider.id().unwrap(),
        typed_id::<ProviderLogId>(fill),
        account_id,
        ProviderLogSubject::Checkpoint(checkpoint_id),
        Timestamp::from_unix_millis(observed_at),
        Extensions::default(),
    )
    .unwrap();
    let root = entry.merkle_leaf_hash().unwrap();
    let body = ProviderHeadBody::new(
        provider.id().unwrap(),
        entry.log_id(),
        ProviderKeyVersion::GENESIS,
        1,
        root,
        Timestamp::from_unix_millis(head_at),
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

struct ConcurrentResultFuture {
    started: Arc<AtomicUsize>,
    expected: usize,
    registered: bool,
    result: Option<Result<InclusionReceipt, IdentityError>>,
}

impl Future for ConcurrentResultFuture {
    type Output = Result<InclusionReceipt, IdentityError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.registered {
            self.started.fetch_add(1, Ordering::SeqCst);
            self.registered = true;
        }
        if self.started.load(Ordering::SeqCst) >= self.expected {
            Poll::Ready(self.result.take().unwrap())
        } else {
            context.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

struct Client {
    provider_id: ProviderId,
    result: Result<InclusionReceipt, IdentityError>,
    started: Arc<AtomicUsize>,
    expected: usize,
}

impl TransparencyClient for Client {
    fn provider_id(&self) -> ProviderId {
        self.provider_id
    }

    fn publish_checkpoint<'a>(
        &'a self,
        _checkpoint: &'a ProviderCheckpointBundle,
    ) -> StoreFuture<'a, InclusionReceipt> {
        Box::pin(ConcurrentResultFuture {
            started: Arc::clone(&self.started),
            expected: self.expected,
            registered: false,
            result: Some(self.result.clone()),
        })
    }

    fn latest_checkpoint(
        &self,
        _account_id: AccountId,
    ) -> StoreFuture<'_, Option<PublishedCheckpoint>> {
        Box::pin(async { Ok(None) })
    }

    fn fetch_checkpoint_bundle(
        &self,
        _account_id: AccountId,
        _checkpoint_id: CheckpointId,
    ) -> StoreFuture<'_, Option<PublishedCheckpoint>> {
        Box::pin(async { Err(IdentityError::ProviderUnavailable) })
    }

    fn fetch_checkpoint_lineage_page(
        &self,
        _account_id: AccountId,
        _start_checkpoint_id: CheckpointId,
        _maximum_records: usize,
        _maximum_bytes: usize,
    ) -> StoreFuture<'_, Option<krikos_identity::ProviderCheckpointLineagePage>> {
        Box::pin(async { Err(IdentityError::ProviderUnavailable) })
    }

    fn consistency_proof(
        &self,
        _log_id: ProviderLogId,
        _old_size: u64,
        _new_size: u64,
    ) -> StoreFuture<'_, krikos_identity::merkle::MerkleConsistencyProof> {
        Box::pin(async { Err(IdentityError::ProviderUnavailable) })
    }
}

#[test]
fn publication_never_overclaims_threshold_or_submission_ack_observation() {
    let first_secret = SecretKey::from_bytes(&[0x41; 32]);
    let second_secret = SecretKey::from_bytes(&[0x42; 32]);
    let first = provider(&first_secret);
    let second = provider(&second_secret);
    let policy = ProviderPolicy::replicated(
        ProviderPolicyVersion::GENESIS,
        vec![first.clone(), second.clone()],
        ProviderQuorum::new(2).unwrap(),
        ProviderQuorum::new(2).unwrap(),
        krikos_identity::DurationMillis::new(1_000),
        Extensions::default(),
    )
    .unwrap();
    let (account_id, verified) = verified_checkpoint(&policy);
    let checkpoint_id = verified.verified_checkpoint().checkpoint_id();
    let mut tracker =
        PublicationTracker::new(account_id, checkpoint_id, policy.id().unwrap(), &policy).unwrap();
    assert_eq!(tracker.stage(), PublicationStage::Draft);
    let mut unrelated = PublicationTracker::new(
        account_id,
        typed_id::<CheckpointId>(0x52),
        policy.id().unwrap(),
        &policy,
    )
    .unwrap();
    assert!(matches!(
        unrelated.mark_authorized(verified.verified_checkpoint()),
        Err(IdentityError::InvalidRelationship { .. })
    ));
    assert_eq!(unrelated.stage(), PublicationStage::Draft);

    let first_submission = receipt(
        &first_secret,
        &first,
        account_id,
        checkpoint_id,
        10,
        10,
        0x61,
    );
    let served =
        PublishedCheckpoint::new(verified.clone(), first_submission.clone(), &first).unwrap();
    assert_eq!(
        served.bundle().verified_checkpoint().checkpoint_id(),
        checkpoint_id
    );
    assert_eq!(served.receipt(), &first_submission);
    assert!(PublishedCheckpoint::new(verified.clone(), first_submission.clone(), &second).is_err());
    assert!(matches!(
        tracker.record_publication(first_submission.clone()),
        Err(IdentityError::InvalidRelationship { .. })
    ));
    tracker
        .mark_authorized(verified.verified_checkpoint())
        .unwrap();
    tracker
        .record_publication(first_submission.clone())
        .unwrap();
    assert_eq!(tracker.stage(), PublicationStage::Published);
    tracker
        .record_publication(first_submission.clone())
        .unwrap();
    assert_eq!(tracker.published_provider_count(), 1);
    assert_eq!(
        tracker.publication_receipts(),
        std::slice::from_ref(&first_submission)
    );
    let different_log_retry = receipt(
        &first_secret,
        &first,
        account_id,
        checkpoint_id,
        12,
        12,
        0x69,
    );
    tracker.record_publication(different_log_retry).unwrap();
    assert_eq!(tracker.published_provider_count(), 1);
    assert_eq!(
        tracker.publication_receipts(),
        std::slice::from_ref(&first_submission)
    );
    let same_log_equivocation = receipt(
        &first_secret,
        &first,
        account_id,
        checkpoint_id,
        12,
        12,
        0x61,
    );
    assert_eq!(
        tracker.record_publication(same_log_equivocation),
        Err(IdentityError::ProviderEquivocation)
    );
    assert_eq!(tracker.published_provider_count(), 1);

    let second_submission = receipt(
        &second_secret,
        &second,
        account_id,
        checkpoint_id,
        11,
        11,
        0x62,
    );
    tracker
        .record_publication(second_submission.clone())
        .unwrap();
    assert_eq!(tracker.stage(), PublicationStage::Replicated);
    assert!(tracker.preferred_replication_reached());

    let equal_size_proof = AppendOnlyMerkleLog::from_leaf_hashes(vec![
        first_submission.entry().merkle_leaf_hash().unwrap(),
    ])
    .unwrap()
    .consistency_proof(1)
    .unwrap();
    assert!(matches!(
        tracker.record_observation(first_submission, &equal_size_proof),
        Err(IdentityError::InvalidRelationship { .. })
    ));
    let first_observation = receipt(
        &first_secret,
        &first,
        account_id,
        checkpoint_id,
        10,
        20,
        0x61,
    );
    tracker
        .record_observation(first_observation, &equal_size_proof)
        .unwrap();
    assert_eq!(tracker.stage(), PublicationStage::Replicated);

    let second_proof = AppendOnlyMerkleLog::from_leaf_hashes(vec![
        second_submission.entry().merkle_leaf_hash().unwrap(),
    ])
    .unwrap()
    .consistency_proof(1)
    .unwrap();
    let second_observation = receipt(
        &second_secret,
        &second,
        account_id,
        checkpoint_id,
        11,
        21,
        0x62,
    );
    tracker
        .record_observation(second_observation, &second_proof)
        .unwrap();
    assert_eq!(tracker.stage(), PublicationStage::Observed);
}

#[test]
fn public_lineage_page_rejects_record_overflow_before_relationship_work() {
    let secret = SecretKey::from_bytes(&[0x43; 32]);
    let descriptor = provider(&secret);
    let policy = ProviderPolicy::replicated(
        ProviderPolicyVersion::GENESIS,
        vec![descriptor.clone()],
        ProviderQuorum::new(1).unwrap(),
        ProviderQuorum::new(1).unwrap(),
        krikos_identity::DurationMillis::new(1_000),
        Extensions::default(),
    )
    .unwrap();
    let (account_id, bundle) = verified_checkpoint(&policy);
    let checkpoint_id = bundle.verified_checkpoint().checkpoint_id();
    let receipt = receipt(
        &secret,
        &descriptor,
        account_id,
        checkpoint_id,
        10,
        10,
        0x62,
    );
    let log_id = receipt.entry().log_id();
    let published = PublishedCheckpoint::new(bundle, receipt, &descriptor).unwrap();
    let checkpoints = vec![published; MAX_HISTORY_PAGE_EVENTS + 1];

    assert_eq!(
        ProviderCheckpointLineagePage::new(
            account_id,
            checkpoint_id,
            checkpoints,
            None,
            &descriptor,
            log_id,
        ),
        Err(IdentityError::LimitExceeded {
            resource: "provider checkpoint lineage records",
            actual: MAX_HISTORY_PAGE_EVENTS + 1,
            maximum: MAX_HISTORY_PAGE_EVENTS,
        })
    );
}

#[test]
fn publication_rejects_unconfigured_or_wrong_subject_receipts_without_mutation() {
    let configured_secret = SecretKey::from_bytes(&[0x43; 32]);
    let outsider_secret = SecretKey::from_bytes(&[0x44; 32]);
    let configured = provider(&configured_secret);
    let outsider = provider(&outsider_secret);
    let policy = ProviderPolicy::replicated(
        ProviderPolicyVersion::GENESIS,
        vec![configured],
        ProviderQuorum::new(1).unwrap(),
        ProviderQuorum::new(1).unwrap(),
        krikos_identity::DurationMillis::new(1_000),
        Extensions::default(),
    )
    .unwrap();
    let (account_id, verified) = verified_checkpoint(&policy);
    let checkpoint_id = verified.verified_checkpoint().checkpoint_id();
    let mut tracker =
        PublicationTracker::new(account_id, checkpoint_id, policy.id().unwrap(), &policy).unwrap();
    tracker
        .mark_authorized(verified.verified_checkpoint())
        .unwrap();
    let before = tracker.clone();
    let outsider_receipt = receipt(
        &outsider_secret,
        &outsider,
        account_id,
        checkpoint_id,
        10,
        10,
        0x63,
    );
    assert_eq!(
        tracker.record_publication(outsider_receipt),
        Err(IdentityError::FreshnessUnavailable)
    );
    assert_eq!(tracker, before);
}

#[test]
fn concurrent_publication_preserves_partial_failures_and_retry_thresholds() {
    let first_secret = SecretKey::from_bytes(&[0x81; 32]);
    let second_secret = SecretKey::from_bytes(&[0x82; 32]);
    let third_secret = SecretKey::from_bytes(&[0x83; 32]);
    let first = provider(&first_secret);
    let second = provider(&second_secret);
    let third = provider(&third_secret);
    let policy = ProviderPolicy::replicated(
        ProviderPolicyVersion::GENESIS,
        vec![first.clone(), second.clone(), third.clone()],
        ProviderQuorum::new(2).unwrap(),
        ProviderQuorum::new(3).unwrap(),
        DurationMillis::new(1_000),
        Extensions::default(),
    )
    .unwrap();
    let (account_id, verified) = verified_checkpoint(&policy);
    let checkpoint_id = verified.verified_checkpoint().checkpoint_id();
    let first_receipt = receipt(
        &first_secret,
        &first,
        account_id,
        checkpoint_id,
        10,
        10,
        0x84,
    );
    let second_receipt = receipt(
        &second_secret,
        &second,
        account_id,
        checkpoint_id,
        11,
        11,
        0x85,
    );
    let started = Arc::new(AtomicUsize::new(0));
    let first_client = Client {
        provider_id: first.id().unwrap(),
        result: Ok(first_receipt),
        started: Arc::clone(&started),
        expected: 3,
    };
    let second_timeout = Client {
        provider_id: second.id().unwrap(),
        result: Err(IdentityError::ProviderTimeout),
        started: Arc::clone(&started),
        expected: 3,
    };
    let third_rate_limited = Client {
        provider_id: third.id().unwrap(),
        result: Err(IdentityError::ProviderRateLimited),
        started: Arc::clone(&started),
        expected: 3,
    };
    let mut tracker =
        PublicationTracker::new(account_id, checkpoint_id, policy.id().unwrap(), &policy).unwrap();
    let batch = block_on(publish_checkpoint_concurrently(
        &mut tracker,
        &verified,
        &[&first_client, &second_timeout, &third_rate_limited],
    ))
    .unwrap();
    assert_eq!(started.load(Ordering::SeqCst), 3);
    assert_eq!(batch.stage(), PublicationStage::Published);
    assert_eq!(tracker.published_provider_count(), 1);
    assert!(batch.outcomes().iter().any(|outcome| {
        outcome.provider_id() == second.id().unwrap()
            && outcome.result() == &Err(IdentityError::ProviderTimeout)
    }));
    assert!(batch.outcomes().iter().any(|outcome| {
        outcome.provider_id() == third.id().unwrap()
            && outcome.result() == &Err(IdentityError::ProviderRateLimited)
    }));

    let retry_started = Arc::new(AtomicUsize::new(0));
    let second_retry = Client {
        provider_id: second.id().unwrap(),
        result: Ok(second_receipt),
        started: Arc::clone(&retry_started),
        expected: 1,
    };
    let retry = block_on(publish_checkpoint_concurrently(
        &mut tracker,
        &verified,
        &[&second_retry],
    ))
    .unwrap();
    assert_eq!(retry_started.load(Ordering::SeqCst), 1);
    assert_eq!(retry.stage(), PublicationStage::Replicated);
    assert_eq!(tracker.published_provider_count(), 2);
    assert!(!tracker.preferred_replication_reached());
    assert!(retry.outcomes().iter().any(|outcome| {
        outcome.provider_id() == third.id().unwrap()
            && outcome.result() == &Err(IdentityError::ProviderUnavailable)
    }));
}

#[cfg(feature = "provider-store")]
#[test]
fn durable_operational_journal_recomputes_thresholds_and_retains_same_phase_receipts() {
    use krikos_identity::{
        AccountStore as _, ClaimEffects, LeaseId, MemoryAccountStore, OperationalEffectJournal,
        OperationalEffectPhase, ProjectionEffect, RedbOperationalEffectStore,
    };

    let first_secret = SecretKey::from_bytes(&[0x91; 32]);
    let second_secret = SecretKey::from_bytes(&[0x92; 32]);
    let third_secret = SecretKey::from_bytes(&[0x93; 32]);
    let first = provider(&first_secret);
    let second = provider(&second_secret);
    let third = provider(&third_secret);
    let policy = ProviderPolicy::replicated(
        ProviderPolicyVersion::GENESIS,
        vec![first.clone(), second.clone(), third.clone()],
        ProviderQuorum::new(3).unwrap(),
        ProviderQuorum::new(3).unwrap(),
        DurationMillis::new(1_000),
        Extensions::default(),
    )
    .unwrap();
    let (account_id, bundle) = verified_checkpoint(&policy);
    let checkpoint = bundle.verified_checkpoint();
    let checkpoint_id = checkpoint.checkpoint_id();

    let account_store = MemoryAccountStore::new();
    let initial =
        block_on(account_store.create_account(bundle.genesis().unwrap().clone())).unwrap();
    block_on(account_store.commit_event(initial.revision().clone(), bundle.events()[0].clone()))
        .unwrap();
    let lease_id = LeaseId::new([0x94; 16]).unwrap();
    let claimed = block_on(
        account_store.claim_effects(
            account_id,
            ClaimEffects::new(
                Timestamp::from_unix_millis(100),
                Timestamp::from_unix_millis(200),
                lease_id,
                4,
            )
            .unwrap(),
        ),
    )
    .unwrap();
    let effect = claimed
        .iter()
        .find(|effect| {
            matches!(
                effect.effect(),
                ProjectionEffect::PublishAccountEvent { .. }
            )
        })
        .unwrap();

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operational-publication.redb");
    let store = RedbOperationalEffectStore::open(&path).unwrap();
    let journal = OperationalEffectJournal::new(store.clone());
    journal
        .begin(effect, Timestamp::from_unix_millis(101))
        .unwrap();
    journal
        .record_checkpoint_draft(
            effect.id(),
            checkpoint.checkpoint().body().clone(),
            Timestamp::from_unix_millis(102),
        )
        .unwrap();
    journal
        .record_checkpoint_authorized(
            effect.id(),
            checkpoint,
            &policy,
            Timestamp::from_unix_millis(103),
        )
        .unwrap();
    assert!(matches!(
        journal.record_completed(effect.id(), Timestamp::from_unix_millis(103)),
        Err(IdentityError::InvalidRelationship { .. })
    ));

    let first_publication = receipt(
        &first_secret,
        &first,
        account_id,
        checkpoint_id,
        10,
        10,
        0xa1,
    );
    let second_publication = receipt(
        &second_secret,
        &second,
        account_id,
        checkpoint_id,
        11,
        11,
        0xa2,
    );
    let third_publication = receipt(
        &third_secret,
        &third,
        account_id,
        checkpoint_id,
        12,
        12,
        0xa3,
    );
    let mut tracker =
        PublicationTracker::new(account_id, checkpoint_id, policy.id().unwrap(), &policy).unwrap();
    tracker.mark_authorized(checkpoint).unwrap();
    tracker
        .record_publication(first_publication.clone())
        .unwrap();
    let first_record = journal
        .record_publications(effect.id(), &tracker, Timestamp::from_unix_millis(104))
        .unwrap();
    assert_eq!(first_record.phase(), OperationalEffectPhase::Published);
    assert_eq!(first_record.provider_receipts().len(), 1);
    assert_eq!(first_record.publication_policy(), Some(&policy));

    tracker
        .record_publication(second_publication.clone())
        .unwrap();
    let same_phase = journal
        .record_publications(effect.id(), &tracker, Timestamp::from_unix_millis(105))
        .unwrap();
    assert_eq!(same_phase.phase(), OperationalEffectPhase::Published);
    assert_eq!(same_phase.provider_receipts().len(), 2);
    assert_eq!(same_phase.revision(), 5);
    drop(journal);
    drop(store);

    let reopened = RedbOperationalEffectStore::open(&path).unwrap();
    let journal = OperationalEffectJournal::new(reopened);
    let retained = journal.load(effect.id()).unwrap().unwrap();
    assert_eq!(retained.phase(), OperationalEffectPhase::Published);
    assert_eq!(retained.provider_receipts().len(), 2);
    assert_eq!(retained.publication_policy(), Some(&policy));

    tracker
        .record_publication(third_publication.clone())
        .unwrap();
    let replicated = journal
        .record_publications(effect.id(), &tracker, Timestamp::from_unix_millis(106))
        .unwrap();
    assert_eq!(replicated.phase(), OperationalEffectPhase::Replicated);

    for (index, (secret, descriptor, publication, fill)) in [
        (&first_secret, &first, &first_publication, 0xa1),
        (&second_secret, &second, &second_publication, 0xa2),
        (&third_secret, &third, &third_publication, 0xa3),
    ]
    .into_iter()
    .enumerate()
    {
        let proof = AppendOnlyMerkleLog::from_leaf_hashes(vec![
            publication.entry().merkle_leaf_hash().unwrap(),
        ])
        .unwrap()
        .consistency_proof(1)
        .unwrap();
        let observation = receipt(
            secret,
            descriptor,
            account_id,
            checkpoint_id,
            10 + u64::try_from(index).unwrap(),
            20 + u64::try_from(index).unwrap(),
            fill,
        );
        tracker
            .record_observation(observation.clone(), &proof)
            .unwrap();
        let retained = journal
            .record_observation(
                effect.id(),
                &tracker,
                observation,
                proof,
                Timestamp::from_unix_millis(107 + u64::try_from(index).unwrap()),
            )
            .unwrap();
        let expected = if index == 2 {
            OperationalEffectPhase::Observed
        } else {
            OperationalEffectPhase::Replicated
        };
        assert_eq!(retained.phase(), expected);
        assert_eq!(
            retained
                .provider_receipts()
                .iter()
                .filter(|provider| provider.observation().is_some())
                .count(),
            index + 1
        );
    }

    drop(journal);
    let reopened = RedbOperationalEffectStore::open(&path).unwrap();
    let journal = OperationalEffectJournal::new(reopened);
    let observed = journal.load(effect.id()).unwrap().unwrap();
    assert_eq!(observed.phase(), OperationalEffectPhase::Observed);
    assert_eq!(observed.provider_receipts().len(), 3);
    assert!(
        observed
            .provider_receipts()
            .iter()
            .all(|provider| provider.observation().is_some())
    );
}
