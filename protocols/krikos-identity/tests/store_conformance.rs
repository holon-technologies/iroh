use futures_lite::future::block_on;
use krikos_base::SecretKey;
use krikos_identity::{
    AccountGenesis, AccountOperation, AccountState, AccountStore, AdmissionEvidence,
    AlgorithmSignature, ApplyDisposition, CanonicalWire, CheckpointAuthorization, CheckpointId,
    ClaimEffects, ControlPolicy, ControllerApprovalBody, ControllerApprovals, ControllerClass,
    ControllerDescriptor, ControllerKeyId, ControllerScope, ControllerSelector,
    ControllerThreshold, ControllerWeight, CryptoSuiteDescriptor, DelayEvidence, Digest,
    DurationMillis, EffectFailure, EffectStatus, EventBody, EventPredecessors, Extensions,
    FreshnessEvidence, FreshnessRequirement, HashAlgorithm, KeyedSignature, LeaseId,
    MemoryAccountStore, MemoryOperationalEffectStore, OperationKind, OperationalEffectJournal,
    OperationalEffectPhase, PolicyRule, ProjectionEffect, ProviderPolicy, ProviderPolicyVersion,
    RecoveryAuthority, RecoveryPolicy, RecoveryPolicyVersion, RequiredWeight, Sequence,
    SignedCheckpoint, SignedControllerApproval, SigningPublicKey, SyncFrame, SyncRequest,
    Timestamp, VerifiedCheckpoint, build_checkpoint_body, complete_ready_effect,
    reconcile_sync_frame, serve_sync_request, verify_checkpoint,
};

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

fn genesis() -> AccountGenesis {
    let secret = SecretKey::from_bytes(&[7; 32]);
    let controller = controller(&secret);
    let rules = [
        OperationKind::AddController,
        OperationKind::ChangeProviderPolicy,
    ]
    .into_iter()
    .map(|operation| {
        PolicyRule::new(
            operation,
            RequiredWeight::new(1).unwrap(),
            ControllerSelector::any_active(),
            FreshnessRequirement::latest_known(),
            None,
            Extensions::default(),
        )
        .unwrap()
    })
    .collect();
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
    AccountGenesis::new(
        [1; 32],
        Timestamp::from_unix_millis(1),
        ControlPolicy::new(rules, Extensions::default()).unwrap(),
        vec![controller],
        recovery,
        ProviderPolicy::local_only(ProviderPolicyVersion::GENESIS, Extensions::default()).unwrap(),
        Extensions::default(),
    )
    .unwrap()
}

fn authorized_add_controller(
    state: &AccountState,
    signer: &SecretKey,
    added: &SecretKey,
    nonce: u8,
) -> krikos_identity::AuthorizedEvent {
    authorized_operation(
        state,
        signer,
        AccountOperation::AddController(controller(added)),
        u64::from(nonce),
    )
}

fn authorized_operation(
    state: &AccountState,
    signer: &SecretKey,
    operation: AccountOperation,
    nonce: u64,
) -> krikos_identity::AuthorizedEvent {
    let predecessors = if state.sequence() == Sequence::GENESIS {
        EventPredecessors::genesis(state.genesis_anchor())
    } else {
        EventPredecessors::events(state.heads().to_vec()).unwrap()
    };
    let nonce_bytes = nonce.to_le_bytes().repeat(2);
    let nonce_bytes: [u8; 16] = nonce_bytes.try_into().unwrap();
    let body = EventBody::new(
        state.account_id(),
        state.sequence().checked_next().unwrap(),
        state.expected_epoch_for(&operation).unwrap(),
        predecessors,
        operation,
        Timestamp::from_unix_millis(nonce),
        nonce_bytes,
        Extensions::default(),
    )
    .unwrap();
    let checkpoint_id = typed_id::<CheckpointId>(0x44);
    let evidence = AdmissionEvidence::new(
        body.proposal_id().unwrap(),
        checkpoint_id,
        state.provider_policy_id(),
        FreshnessEvidence::local_known(checkpoint_id),
        DelayEvidence::none(),
        Extensions::default(),
    )
    .unwrap();
    let event_id = evidence.event_id_for_body(&body).unwrap();
    let signing_key = SigningPublicKey::ed25519(*signer.public().as_bytes()).unwrap();
    let controller_id = state
        .active_controllers()
        .iter()
        .find(|candidate| candidate.signing_key() == signing_key)
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

fn verified_checkpoint(
    state: &AccountState,
    signer: &SecretKey,
    issued_at: Timestamp,
) -> VerifiedCheckpoint {
    let body = build_checkpoint_body(state, issued_at).unwrap();
    let checkpoint_id = body.checkpoint_id().unwrap();
    let signing_key = SigningPublicKey::ed25519(*signer.public().as_bytes()).unwrap();
    let controller_id = state
        .active_controllers()
        .iter()
        .find(|candidate| candidate.signing_key() == signing_key)
        .unwrap()
        .id();
    let approval_body =
        ControllerApprovalBody::checkpoint(controller_id, checkpoint_id, Extensions::default())
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
    let signed = SignedCheckpoint::new(
        body,
        CheckpointAuthorization::controllers(
            checkpoint_id,
            ControllerApprovals::new(vec![approval]).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    verify_checkpoint(state, &signed, None).unwrap()
}

#[test]
fn memory_store_create_load_reconstructs_projection_and_distinguishes_absence() {
    let genesis = genesis();
    let account_id = genesis.account_id().unwrap();
    let expected = AccountState::from_genesis(&genesis)
        .unwrap()
        .revision_token();
    let store = MemoryAccountStore::new();

    assert!(block_on(store.load_account(account_id)).unwrap().is_none());
    let created = block_on(store.create_account(genesis.clone())).unwrap();
    assert_eq!(created.revision(), &expected);

    let loaded = block_on(store.load_account(account_id))
        .unwrap()
        .expect("created account must be present");
    assert_eq!(loaded.genesis(), &genesis);
    assert_eq!(loaded.state().revision_token(), expected);
    assert!(loaded.events().is_empty());
    assert!(loaded.checkpoints().is_empty());
    assert!(loaded.fork_evidence().is_empty());
}

#[test]
fn memory_commit_is_exact_cas_and_event_plus_outbox_are_atomic_and_idempotent() {
    let genesis = genesis();
    let account_id = genesis.account_id().unwrap();
    let signer = SecretKey::from_bytes(&[7; 32]);
    let store = MemoryAccountStore::new();
    let initial = block_on(store.create_account(genesis)).unwrap();
    let first = authorized_add_controller(
        initial.state(),
        &signer,
        &SecretKey::from_bytes(&[8; 32]),
        1,
    );

    let committed =
        block_on(store.commit_event(initial.revision().clone(), first.clone())).unwrap();
    assert_eq!(committed.outcome().disposition(), ApplyDisposition::Applied);
    assert_eq!(committed.snapshot().events(), std::slice::from_ref(&first));
    assert_eq!(committed.snapshot().outbox().len(), 3);
    assert!(
        committed
            .snapshot()
            .outbox()
            .iter()
            .all(|effect| effect.status() == EffectStatus::Pending)
    );

    let second = authorized_add_controller(
        committed.snapshot().state(),
        &signer,
        &SecretKey::from_bytes(&[9; 32]),
        2,
    );
    assert_eq!(
        block_on(store.commit_event(initial.revision().clone(), second)),
        Err(krikos_identity::IdentityError::StaleRevision)
    );

    let unchanged = block_on(store.load_account(account_id)).unwrap().unwrap();
    assert_eq!(unchanged.revision(), committed.snapshot().revision());
    assert_eq!(unchanged.events().len(), 1);
    assert_eq!(unchanged.outbox().len(), 3);

    let replay = block_on(store.commit_event(unchanged.revision().clone(), first)).unwrap();
    assert_eq!(replay.outcome().disposition(), ApplyDisposition::Replay);
    assert_eq!(replay.snapshot().outbox().len(), 3);
}

#[test]
fn event_history_is_bounded_and_frozen_to_the_exact_source_revision() {
    let genesis = genesis();
    let account_id = genesis.account_id().unwrap();
    let signer = SecretKey::from_bytes(&[7; 32]);
    let store = MemoryAccountStore::new();
    let initial = block_on(store.create_account(genesis)).unwrap();
    let first = authorized_add_controller(
        initial.state(),
        &signer,
        &SecretKey::from_bytes(&[8; 32]),
        1,
    );
    let after_first = block_on(store.commit_event(initial.revision().clone(), first.clone()))
        .unwrap()
        .snapshot()
        .clone();
    let frozen = after_first.revision().clone();
    let second = authorized_add_controller(
        after_first.state(),
        &signer,
        &SecretKey::from_bytes(&[9; 32]),
        2,
    );
    let current = block_on(store.commit_event(after_first.revision().clone(), second.clone()))
        .unwrap()
        .snapshot()
        .clone();

    let frozen_page =
        block_on(store.event_history(frozen.clone(), None, 1, 4 * 1024 * 1024)).unwrap();
    assert_eq!(frozen_page.source_revision(), &frozen);
    assert_eq!(frozen_page.records().len(), 1);
    assert_eq!(frozen_page.records()[0].cursor(), 0);
    assert_eq!(frozen_page.records()[0].event(), &first);
    assert!(frozen_page.next_cursor().is_none());

    let first_page =
        block_on(store.event_history(current.revision().clone(), None, 1, 4 * 1024 * 1024))
            .unwrap();
    assert_eq!(first_page.records()[0].event(), &first);
    let first_cursor = first_page.next_cursor().unwrap().clone();
    assert_eq!(first_cursor.source_revision(), current.revision());
    assert_eq!(first_cursor.position(), 0);
    let second_page = block_on(store.event_history(
        current.revision().clone(),
        Some(first_cursor.clone()),
        1,
        4 * 1024 * 1024,
    ))
    .unwrap();
    assert_eq!(second_page.records()[0].cursor(), 1);
    assert_eq!(second_page.records()[0].event(), &second);
    assert!(second_page.next_cursor().is_none());

    assert_eq!(
        block_on(store.event_history(frozen.clone(), Some(first_cursor), 1, 1024)),
        Err(krikos_identity::IdentityError::InvalidRelationship {
            resource: "account event-history cursor revision",
        })
    );
    assert!(matches!(
        block_on(store.event_history(current.revision().clone(), None, 1, 1)),
        Err(krikos_identity::IdentityError::LimitExceeded {
            resource: "account event-history bytes",
            ..
        })
    ));

    let other = MemoryAccountStore::new();
    let other_revision = block_on(
        other.create_account(
            AccountGenesis::new(
                [2; 32],
                Timestamp::from_unix_millis(2),
                initial.genesis().initial_policy().clone(),
                initial.genesis().initial_controllers().to_vec(),
                initial.genesis().initial_recovery_policy().clone(),
                initial.genesis().initial_provider_policy().clone(),
                Extensions::default(),
            )
            .unwrap(),
        ),
    )
    .unwrap()
    .revision()
    .clone();
    assert_eq!(
        block_on(store.event_history(other_revision, None, 1, 1024)),
        Err(krikos_identity::IdentityError::InvalidRelationship {
            resource: "account store missing account",
        })
    );
    assert_eq!(account_id, current.revision().account_id());

    let cursor_key = krikos_identity::CursorKey::new([0x44; 32]).unwrap();
    let first_request = SyncRequest::new(account_id, Vec::new(), None, 1, 4 * 1024 * 1024).unwrap();
    let first_response = block_on(serve_sync_request(&store, &cursor_key, &first_request)).unwrap();
    let first_frame = first_response.as_frame().unwrap();
    assert_eq!(first_frame.events(), std::slice::from_ref(&first));
    let continuation = first_frame.continuation().unwrap().clone();
    assert_eq!(continuation.source_heads(), current.revision().heads());
    assert_eq!(
        usize::try_from(continuation.delivered_bytes()).unwrap(),
        first_request.to_canonical_bytes().unwrap().len()
            + first_response.to_canonical_bytes().unwrap().len()
    );
    let packed = block_on(serve_sync_request(
        &store,
        &cursor_key,
        &SyncRequest::new(
            account_id,
            Vec::new(),
            None,
            2,
            first_response.to_canonical_bytes().unwrap().len(),
        )
        .unwrap(),
    ))
    .unwrap();
    assert_eq!(packed.as_frame().unwrap().events().len(), 1);
    assert!(packed.as_frame().unwrap().continuation().is_some());

    let exhausted = krikos_identity::SyncCursor::issue(
        &cursor_key,
        account_id,
        current.revision().heads().to_vec(),
        1,
        krikos_identity::limits::MAX_SYNC_SESSION_BYTES - 1,
    )
    .unwrap();
    assert!(matches!(
        block_on(serve_sync_request(
            &store,
            &cursor_key,
            &SyncRequest::new(account_id, Vec::new(), Some(exhausted), 1, 4 * 1024 * 1024,)
                .unwrap(),
        )),
        Err(krikos_identity::IdentityError::LimitExceeded {
            resource: "sync session bytes",
            ..
        })
    ));
    let substituted_heads = krikos_identity::SyncCursor::issue(
        &cursor_key,
        account_id,
        vec![typed_id::<krikos_identity::EventId>(0xfe)],
        0,
        0,
    )
    .unwrap();
    assert_eq!(
        block_on(serve_sync_request(
            &store,
            &cursor_key,
            &SyncRequest::new(account_id, Vec::new(), Some(substituted_heads), 1, 1024,).unwrap(),
        )),
        Err(krikos_identity::IdentityError::InvalidRelationship {
            resource: "account event-history source revision",
        })
    );
    let foreign_cursor = krikos_identity::SyncCursor::issue(
        &krikos_identity::CursorKey::new([0x45; 32]).unwrap(),
        account_id,
        current.revision().heads().to_vec(),
        1,
        0,
    )
    .unwrap();
    assert_eq!(
        block_on(serve_sync_request(
            &store,
            &cursor_key,
            &SyncRequest::new(account_id, Vec::new(), Some(foreign_cursor), 1, 1024,).unwrap(),
        )),
        Err(krikos_identity::IdentityError::InvalidProof)
    );

    let third = authorized_add_controller(
        current.state(),
        &signer,
        &SecretKey::from_bytes(&[10; 32]),
        3,
    );
    block_on(store.commit_event(current.revision().clone(), third)).unwrap();
    let resumed = block_on(serve_sync_request(
        &store,
        &cursor_key,
        &SyncRequest::new(
            account_id,
            Vec::new(),
            Some(continuation),
            1,
            4 * 1024 * 1024,
        )
        .unwrap(),
    ))
    .unwrap();
    let resumed_frame = resumed.as_frame().unwrap();
    assert_eq!(resumed_frame.events(), std::slice::from_ref(&second));
    assert!(resumed_frame.continuation().is_none());
}

#[test]
fn checkpoint_journal_is_revision_bound_idempotent_and_bounded() {
    let genesis = genesis();
    let signer = SecretKey::from_bytes(&[7; 32]);
    let account_id = genesis.account_id().unwrap();
    let store = MemoryAccountStore::new();
    let initial = block_on(store.create_account(genesis)).unwrap();
    let event = authorized_add_controller(
        initial.state(),
        &signer,
        &SecretKey::from_bytes(&[10; 32]),
        10,
    );
    let committed = block_on(store.commit_event(initial.revision().clone(), event)).unwrap();
    let checkpoint = verified_checkpoint(
        committed.snapshot().state(),
        &signer,
        Timestamp::from_unix_millis(11),
    );

    let first = block_on(
        store.commit_checkpoint(committed.snapshot().revision().clone(), checkpoint.clone()),
    )
    .unwrap();
    assert_eq!(first.checkpoint_id(), checkpoint.checkpoint_id());
    assert_eq!(first.snapshot().checkpoints().len(), 1);
    let replay = block_on(
        store.commit_checkpoint(committed.snapshot().revision().clone(), checkpoint.clone()),
    )
    .unwrap();
    assert_eq!(replay.snapshot().checkpoints().len(), 1);

    let lease_id = LeaseId::new([0x22; 16]).unwrap();
    let claimed = block_on(
        store.claim_effects(
            account_id,
            ClaimEffects::new(
                Timestamp::from_unix_millis(20),
                Timestamp::from_unix_millis(30),
                lease_id,
                3,
            )
            .unwrap(),
        ),
    )
    .unwrap();
    let publish = claimed
        .iter()
        .find(|record| {
            matches!(
                record.effect(),
                ProjectionEffect::PublishAccountEvent { .. }
            )
        })
        .unwrap()
        .clone();
    let operational_store = MemoryOperationalEffectStore::new();
    let journal = OperationalEffectJournal::new(operational_store.clone());
    assert_eq!(
        journal
            .begin(&publish, Timestamp::from_unix_millis(21))
            .unwrap()
            .phase(),
        OperationalEffectPhase::Claimed
    );
    journal
        .record_checkpoint_draft(
            publish.id(),
            checkpoint.checkpoint().body().clone(),
            Timestamp::from_unix_millis(22),
        )
        .unwrap();
    let authorized = journal
        .record_checkpoint_authorized(
            publish.id(),
            &checkpoint,
            committed.snapshot().state().provider_policy(),
            Timestamp::from_unix_millis(23),
        )
        .unwrap();
    assert_eq!(
        authorized.phase(),
        OperationalEffectPhase::CheckpointAuthorized
    );
    assert_eq!(
        operational_store
            .metrics()
            .unwrap()
            .publication_shortfalls(),
        0
    );
    assert_eq!(
        journal
            .record_failure(
                publish.id(),
                1,
                EffectFailure::transient(9).unwrap(),
                Timestamp::from_unix_millis(25),
            )
            .unwrap()
            .phase(),
        OperationalEffectPhase::RetryScheduled
    );
    let changed_failure = journal
        .record_failure(
            publish.id(),
            1,
            EffectFailure::transient(10).unwrap(),
            Timestamp::from_unix_millis(26),
        )
        .unwrap();
    assert_eq!(
        changed_failure.last_failure(),
        Some(EffectFailure::transient(10).unwrap())
    );
    assert_eq!(changed_failure.revision(), 5);

    block_on(store.retry_effect(
        account_id,
        publish.id(),
        lease_id,
        Timestamp::from_unix_millis(30),
        EffectFailure::transient(10).unwrap(),
    ))
    .unwrap();
    let retry_lease = LeaseId::new([0x23; 16]).unwrap();
    let retried = block_on(
        store.claim_effects(
            account_id,
            ClaimEffects::new(
                Timestamp::from_unix_millis(30),
                Timestamp::from_unix_millis(40),
                retry_lease,
                3,
            )
            .unwrap(),
        ),
    )
    .unwrap()
    .into_iter()
    .find(|record| record.id() == publish.id())
    .unwrap();
    let resumed = journal
        .begin(&retried, Timestamp::from_unix_millis(31))
        .unwrap();
    assert_eq!(
        resumed.phase(),
        OperationalEffectPhase::CheckpointAuthorized
    );
    assert_eq!(resumed.checkpoint(), Some(checkpoint.checkpoint()));
    assert_eq!(resumed.lease_id(), retry_lease);
    assert_eq!(resumed.attempt_count(), 2);
    assert_eq!(resumed.last_failure(), retried.last_failure());
    assert_eq!(
        block_on(store.commit_checkpoint(initial.revision().clone(), checkpoint)),
        Err(krikos_identity::IdentityError::StaleRevision)
    );

    let page = block_on(store.checkpoint_history(account_id, None, 1, 4 * 1024 * 1024)).unwrap();
    assert_eq!(page.records().len(), 1);
    assert_eq!(page.records()[0].checkpoint_id(), first.checkpoint_id());
    assert!(page.next_cursor().is_none());
}

#[test]
fn local_only_checkpoint_effect_completes_without_synthetic_provider_stages() {
    let genesis = genesis();
    let signer = SecretKey::from_bytes(&[7; 32]);
    let account_id = genesis.account_id().unwrap();
    let store = MemoryAccountStore::new();
    let initial = block_on(store.create_account(genesis)).unwrap();
    let event = authorized_add_controller(
        initial.state(),
        &signer,
        &SecretKey::from_bytes(&[0x61; 32]),
        61,
    );
    let committed = block_on(store.commit_event(initial.revision().clone(), event)).unwrap();
    let checkpoint = verified_checkpoint(
        committed.snapshot().state(),
        &signer,
        Timestamp::from_unix_millis(62),
    );
    let lease_id = LeaseId::new([0x62; 16]).unwrap();
    let claimed = block_on(
        store.claim_effects(
            account_id,
            ClaimEffects::new(
                Timestamp::from_unix_millis(70),
                Timestamp::from_unix_millis(80),
                lease_id,
                4,
            )
            .unwrap(),
        ),
    )
    .unwrap();
    let publish = claimed
        .iter()
        .find(|effect| {
            matches!(
                effect.effect(),
                ProjectionEffect::PublishAccountEvent { .. }
            )
        })
        .unwrap();
    let operational_store = MemoryOperationalEffectStore::new();
    let journal = OperationalEffectJournal::new(operational_store.clone());
    journal
        .begin(publish, Timestamp::from_unix_millis(71))
        .unwrap();
    journal
        .record_checkpoint_draft(
            publish.id(),
            checkpoint.checkpoint().body().clone(),
            Timestamp::from_unix_millis(72),
        )
        .unwrap();
    assert_eq!(
        block_on(complete_ready_effect(
            &store,
            &journal,
            publish,
            Timestamp::from_unix_millis(73),
        )),
        Err(krikos_identity::IdentityError::InvalidRelationship {
            resource: "operational completion prerequisite"
        })
    );
    let before_authorization = block_on(store.load_account(account_id)).unwrap().unwrap();
    assert_eq!(
        before_authorization
            .outbox()
            .iter()
            .find(|effect| effect.id() == publish.id())
            .unwrap()
            .status(),
        EffectStatus::Claimed
    );
    let authorized = journal
        .record_checkpoint_authorized(
            publish.id(),
            &checkpoint,
            committed.snapshot().state().provider_policy(),
            Timestamp::from_unix_millis(74),
        )
        .unwrap();
    assert_eq!(
        authorized.phase(),
        OperationalEffectPhase::CheckpointAuthorized
    );
    assert!(authorized.provider_receipts().is_empty());
    block_on(complete_ready_effect(
        &store,
        &journal,
        publish,
        Timestamp::from_unix_millis(75),
    ))
    .unwrap();

    let completed = journal.load(publish.id()).unwrap().unwrap();
    assert_eq!(completed.phase(), OperationalEffectPhase::Completed);
    assert!(completed.provider_receipts().is_empty());
    assert!(completed.audit().iter().all(|audit| {
        !matches!(
            audit.phase(),
            OperationalEffectPhase::Published
                | OperationalEffectPhase::Replicated
                | OperationalEffectPhase::Observed
        )
    }));
    let snapshot = block_on(store.load_account(account_id)).unwrap().unwrap();
    assert_eq!(
        snapshot
            .outbox()
            .iter()
            .find(|effect| effect.id() == publish.id())
            .unwrap()
            .status(),
        EffectStatus::Completed
    );
    assert_eq!(operational_store.metrics().unwrap().completed(), 1);
    assert_eq!(
        operational_store
            .metrics()
            .unwrap()
            .publication_shortfalls(),
        0
    );
}

#[test]
fn stale_sibling_cas_retains_both_valid_sequence_one_branches() {
    let genesis = genesis();
    let signer = SecretKey::from_bytes(&[7; 32]);
    let store = MemoryAccountStore::new();
    let initial = block_on(store.create_account(genesis)).unwrap();
    let left = authorized_add_controller(
        initial.state(),
        &signer,
        &SecretKey::from_bytes(&[11; 32]),
        11,
    );
    let right = authorized_add_controller(
        initial.state(),
        &signer,
        &SecretKey::from_bytes(&[12; 32]),
        12,
    );

    block_on(store.commit_event(initial.revision().clone(), left.clone())).unwrap();
    let fork = block_on(store.commit_event(initial.revision().clone(), right.clone())).unwrap();

    assert_eq!(fork.outcome().disposition(), ApplyDisposition::ForkDetected);
    assert_eq!(fork.snapshot().revision().heads().len(), 2);
    assert!(
        fork.snapshot()
            .revision()
            .heads()
            .contains(&left.event_id().unwrap())
    );
    assert!(
        fork.snapshot()
            .revision()
            .heads()
            .contains(&right.event_id().unwrap())
    );
    assert_eq!(fork.snapshot().fork_evidence().len(), 1);
    assert_eq!(
        fork.snapshot().fork_evidence()[0].sequence(),
        Sequence::new(1)
    );
    assert_eq!(fork.snapshot().outbox().len(), 5);
}

#[test]
fn evicted_lineage_conflict_is_authenticated_from_durable_sources() {
    let genesis = genesis();
    let signer = SecretKey::from_bytes(&[7; 32]);
    let store = MemoryAccountStore::new();
    let initial = block_on(store.create_account(genesis)).unwrap();
    let initial_revision = initial.revision().clone();
    let mut snapshot = initial;
    for version in 1_u64..=257 {
        let policy =
            ProviderPolicy::local_only(ProviderPolicyVersion::new(version), Extensions::default())
                .unwrap();
        let event = authorized_operation(
            snapshot.state(),
            &signer,
            AccountOperation::ChangeProviderPolicy(policy),
            version,
        );
        snapshot = block_on(store.commit_event(snapshot.revision().clone(), event))
            .unwrap()
            .snapshot()
            .clone();
    }
    let [durable_tip] = snapshot.revision().heads() else {
        panic!("linear durable history must have one tip");
    };
    let durable_tip = *durable_tip;
    let alternate = authorized_add_controller(
        &AccountState::from_genesis(snapshot.genesis()).unwrap(),
        &signer,
        &SecretKey::from_bytes(&[50; 32]),
        50,
    );
    let alternate_id = alternate.event_id().unwrap();

    let fork = block_on(store.commit_event(initial_revision, alternate)).unwrap();
    assert_eq!(fork.outcome().disposition(), ApplyDisposition::ForkDetected);
    assert_eq!(fork.snapshot().revision().heads().len(), 2);
    assert_eq!(fork.snapshot().events().len(), 258);
    assert_eq!(fork.snapshot().fork_evidence().len(), 1);
    let mut expected_heads = vec![durable_tip, alternate_id];
    expected_heads.sort_unstable();
    assert_eq!(fork.snapshot().revision().heads(), expected_heads);
}

#[test]
fn effect_claim_retry_and_completion_are_bounded_and_idempotent() {
    let genesis = genesis();
    let account_id = genesis.account_id().unwrap();
    let signer = SecretKey::from_bytes(&[7; 32]);
    let store = MemoryAccountStore::new();
    let initial = block_on(store.create_account(genesis)).unwrap();
    let event = authorized_add_controller(
        initial.state(),
        &signer,
        &SecretKey::from_bytes(&[20; 32]),
        20,
    );
    block_on(store.commit_event(initial.revision().clone(), event)).unwrap();

    let lease = LeaseId::new([1; 16]).unwrap();
    let claim = ClaimEffects::new(
        Timestamp::from_unix_millis(100),
        Timestamp::from_unix_millis(200),
        lease,
        2,
    )
    .unwrap();
    let first_claim = block_on(store.claim_effects(account_id, claim)).unwrap();
    assert_eq!(first_claim.len(), 2);
    assert!(
        first_claim.iter().all(|effect| {
            effect.status() == EffectStatus::Claimed && effect.attempt_count() == 1
        })
    );

    let repeated = block_on(store.claim_effects(account_id, claim)).unwrap();
    assert_eq!(repeated, first_claim);

    let completed_id = first_claim[0].id();
    block_on(store.complete_effect(
        account_id,
        completed_id,
        lease,
        Timestamp::from_unix_millis(150),
    ))
    .unwrap();
    block_on(store.complete_effect(
        account_id,
        completed_id,
        lease,
        Timestamp::from_unix_millis(150),
    ))
    .unwrap();

    let retried_id = first_claim[1].id();
    let failure = EffectFailure::transient(7).unwrap();
    block_on(store.retry_effect(
        account_id,
        retried_id,
        lease,
        Timestamp::from_unix_millis(300),
        failure,
    ))
    .unwrap();
    let before_retry = ClaimEffects::new(
        Timestamp::from_unix_millis(299),
        Timestamp::from_unix_millis(350),
        LeaseId::new([2; 16]).unwrap(),
        2,
    )
    .unwrap();
    assert!(
        block_on(store.claim_effects(account_id, before_retry))
            .unwrap()
            .iter()
            .all(|record| record.id() != retried_id)
    );
    let at_retry = ClaimEffects::new(
        Timestamp::from_unix_millis(300),
        Timestamp::from_unix_millis(400),
        LeaseId::new([3; 16]).unwrap(),
        3,
    )
    .unwrap();
    let claimed_again = block_on(store.claim_effects(account_id, at_retry)).unwrap();
    let retried = claimed_again
        .iter()
        .find(|record| record.id() == retried_id)
        .expect("scheduled retry must become claimable at its exact timestamp");
    assert_eq!(retried.attempt_count(), 2);
    assert_eq!(retried.last_failure(), Some(failure));
}

#[test]
fn sync_reconciliation_is_reorder_duplicate_tolerant_and_frame_atomic() {
    let genesis = genesis();
    let account_id = genesis.account_id().unwrap();
    let signer = SecretKey::from_bytes(&[7; 32]);
    let store = MemoryAccountStore::new();
    let initial = block_on(store.create_account(genesis)).unwrap();
    let first = authorized_add_controller(
        initial.state(),
        &signer,
        &SecretKey::from_bytes(&[30; 32]),
        30,
    );
    let mut after_first = initial.state().clone();
    after_first.validate_and_apply(&first).unwrap();
    let second =
        authorized_add_controller(&after_first, &signer, &SecretKey::from_bytes(&[31; 32]), 31);
    let frame = SyncFrame::new(
        account_id,
        vec![second.event_id().unwrap()],
        vec![second.clone(), first.clone(), first],
        None,
    )
    .unwrap();
    let reconciled = block_on(reconcile_sync_frame(
        &store,
        initial.revision().clone(),
        &frame,
    ))
    .unwrap();
    assert_eq!(reconciled.snapshot().events().len(), 2);
    assert_eq!(reconciled.snapshot().outbox().len(), 6);
    assert_eq!(
        reconciled.snapshot().revision().heads(),
        frame.source_heads()
    );

    let other_genesis = AccountGenesis::new(
        [2; 32],
        Timestamp::from_unix_millis(2),
        initial.genesis().initial_policy().clone(),
        initial.genesis().initial_controllers().to_vec(),
        initial.genesis().initial_recovery_policy().clone(),
        initial.genesis().initial_provider_policy().clone(),
        Extensions::default(),
    )
    .unwrap();
    let other_state = AccountState::from_genesis(&other_genesis).unwrap();
    let wrong_account_event =
        authorized_add_controller(&other_state, &signer, &SecretKey::from_bytes(&[32; 32]), 32);
    let next_valid = authorized_add_controller(
        reconciled.snapshot().state(),
        &signer,
        &SecretKey::from_bytes(&[33; 32]),
        33,
    );
    let invalid_frame = SyncFrame::new(
        account_id,
        vec![next_valid.event_id().unwrap()],
        vec![next_valid, wrong_account_event],
        None,
    )
    .unwrap();
    assert_eq!(
        block_on(reconcile_sync_frame(
            &store,
            reconciled.snapshot().revision().clone(),
            &invalid_frame,
        )),
        Err(krikos_identity::IdentityError::AccountMismatch)
    );
    let unchanged = block_on(store.load_account(account_id)).unwrap().unwrap();
    assert_eq!(unchanged.revision(), reconciled.snapshot().revision());
    assert_eq!(unchanged.events().len(), 2);
    assert_eq!(unchanged.outbox().len(), 6);
}

#[cfg(feature = "fs-store")]
#[test]
fn redb_reopen_preserves_atomic_event_and_outbox_and_rejects_truncation() {
    use krikos_identity::RedbAccountStore;
    use redb::{Database, TableDefinition};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("identity.redb");
    let genesis = genesis();
    let account_id = genesis.account_id().unwrap();
    let signer = SecretKey::from_bytes(&[7; 32]);
    let frozen_revision;
    {
        let store = RedbAccountStore::open(&path).unwrap();
        let initial = block_on(store.create_account(genesis)).unwrap();
        let event = authorized_add_controller(
            initial.state(),
            &signer,
            &SecretKey::from_bytes(&[40; 32]),
            40,
        );
        let committed = block_on(store.commit_event(initial.revision().clone(), event)).unwrap();
        let second = authorized_add_controller(
            committed.snapshot().state(),
            &signer,
            &SecretKey::from_bytes(&[41; 32]),
            41,
        );
        let committed =
            block_on(store.commit_event(committed.snapshot().revision().clone(), second)).unwrap();
        frozen_revision = committed.snapshot().revision().clone();
        assert_eq!(committed.snapshot().events().len(), 2);
        assert_eq!(committed.snapshot().outbox().len(), 6);
        let checkpoint = verified_checkpoint(
            committed.snapshot().state(),
            &signer,
            Timestamp::from_unix_millis(42),
        );
        block_on(store.commit_checkpoint(committed.snapshot().revision().clone(), checkpoint))
            .unwrap();
    }
    {
        let reopened = RedbAccountStore::open(&path).unwrap();
        let snapshot = block_on(reopened.load_account(account_id))
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.events().len(), 2);
        assert_eq!(snapshot.outbox().len(), 6);
        assert_eq!(snapshot.checkpoint_count(), 1);
        assert_eq!(snapshot.checkpoints().len(), 1);
        let page =
            block_on(reopened.checkpoint_history(account_id, None, 1, 4 * 1024 * 1024)).unwrap();
        assert_eq!(page.records().len(), 1);
        let event_page =
            block_on(reopened.event_history(frozen_revision.clone(), None, 1, 4 * 1024 * 1024))
                .unwrap();
        assert_eq!(event_page.source_revision(), &frozen_revision);
        assert_eq!(event_page.records().len(), 1);
        let cursor = event_page.next_cursor().unwrap().clone();
        drop(event_page);
        drop(reopened);

        let reopened = RedbAccountStore::open(&path).unwrap();
        let resumed = block_on(reopened.event_history(
            frozen_revision.clone(),
            Some(cursor),
            1,
            4 * 1024 * 1024,
        ))
        .unwrap();
        assert_eq!(resumed.records().len(), 1);
        assert!(resumed.next_cursor().is_none());
    }
    {
        const TABLE: TableDefinition<&[u8], &[u8]> =
            TableDefinition::new("krikos-identity-accounts-v1");
        let database = Database::create(&path).unwrap();
        let write = database.begin_write().unwrap();
        {
            let mut table = write.open_table(TABLE).unwrap();
            let key = account_id.to_canonical_bytes().unwrap();
            table.insert(key.as_slice(), &[0xff, 0x00][..]).unwrap();
        }
        write.commit().unwrap();
    }
    assert!(matches!(
        RedbAccountStore::open(&path),
        Err(krikos_identity::IdentityError::StorageCorruption)
    ));
}

#[cfg(feature = "fs-store")]
#[test]
fn redb_terminal_effect_failure_remains_auditable_after_reopen() {
    use krikos_identity::{IdentityError, RedbAccountStore};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("identity.redb");
    let genesis = genesis();
    let account_id = genesis.account_id().unwrap();
    let signer = SecretKey::from_bytes(&[7; 32]);
    let lease_id = LeaseId::new([9; 16]).unwrap();
    let failure = EffectFailure::permanent(42).unwrap();
    let effect_id;

    {
        let store = RedbAccountStore::open(&path).unwrap();
        let initial = block_on(store.create_account(genesis)).unwrap();
        let event = authorized_add_controller(
            initial.state(),
            &signer,
            &SecretKey::from_bytes(&[41; 32]),
            41,
        );
        block_on(store.commit_event(initial.revision().clone(), event)).unwrap();
        let claim = ClaimEffects::new(
            Timestamp::from_unix_millis(100),
            Timestamp::from_unix_millis(200),
            lease_id,
            1,
        )
        .unwrap();
        effect_id = block_on(store.claim_effects(account_id, claim)).unwrap()[0].id();
        assert_eq!(
            block_on(store.retry_effect(
                account_id,
                effect_id,
                lease_id,
                Timestamp::from_unix_millis(300),
                failure,
            )),
            Err(IdentityError::RetryExhausted)
        );
    }

    let reopened = RedbAccountStore::open(&path).unwrap();
    let snapshot = block_on(reopened.load_account(account_id))
        .unwrap()
        .unwrap();
    let exhausted = snapshot
        .outbox()
        .iter()
        .find(|record| record.id() == effect_id)
        .unwrap();
    assert_eq!(exhausted.status(), EffectStatus::Pending);
    assert_eq!(exhausted.last_failure(), Some(failure));
    assert!(exhausted.retry_exhausted());
}

#[cfg(feature = "provider-store")]
#[test]
fn redb_operational_substeps_reopen_by_stable_task6_effect_id() {
    use krikos_identity::RedbOperationalEffectStore;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operations.redb");
    let genesis = genesis();
    let account_id = genesis.account_id().unwrap();
    let signer = SecretKey::from_bytes(&[7; 32]);
    let account_store = MemoryAccountStore::new();
    let initial = block_on(account_store.create_account(genesis)).unwrap();
    let event = authorized_add_controller(
        initial.state(),
        &signer,
        &SecretKey::from_bytes(&[51; 32]),
        51,
    );
    block_on(account_store.commit_event(initial.revision().clone(), event)).unwrap();
    let lease_id = LeaseId::new([0x33; 16]).unwrap();
    let claimed = block_on(
        account_store.claim_effects(
            account_id,
            ClaimEffects::new(
                Timestamp::from_unix_millis(100),
                Timestamp::from_unix_millis(200),
                lease_id,
                3,
            )
            .unwrap(),
        ),
    )
    .unwrap();
    let notification = claimed
        .iter()
        .find(|record| {
            matches!(
                record.effect(),
                ProjectionEffect::NotifyAccountChanged { .. }
            )
        })
        .unwrap();
    let effect_id = notification.id();

    {
        let operation_store = RedbOperationalEffectStore::open(&path).unwrap();
        let journal = OperationalEffectJournal::new(operation_store);
        journal
            .begin(notification, Timestamp::from_unix_millis(110))
            .unwrap();
        journal
            .record_peers_notified(effect_id, Timestamp::from_unix_millis(111))
            .unwrap();
        block_on(account_store.complete_effect(
            account_id,
            effect_id,
            lease_id,
            Timestamp::from_unix_millis(112),
        ))
        .unwrap();
        journal
            .record_completed(effect_id, Timestamp::from_unix_millis(113))
            .unwrap();
    }

    let reopened = RedbOperationalEffectStore::open(&path).unwrap();
    let journal = OperationalEffectJournal::new(reopened.clone());
    assert_eq!(
        journal.load(effect_id).unwrap().unwrap().phase(),
        OperationalEffectPhase::Completed
    );
    assert_eq!(reopened.metrics().unwrap().completed(), 1);
}
