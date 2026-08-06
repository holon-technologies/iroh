use krikos_runtime::RootSeed;
use krikos_sim::evidence::{
    ArtifactStore, BackendCapabilities, CryptoMode, DeterminismGrade, MANIFEST_SCHEMA_VERSION,
    RunBudgets, RunManifest, SIMULATOR_VERSION, SourceIdentity, TraceComparisonMode,
};
use krikos_sim::identity::{
    AccountControlModel, ApplyDisposition, ControllerId, DeviceId, DifferentialError, EventId,
    ExpectedModelRejection, ForkResolution, ForkScenarioOperation, FormalMutation, FormalProperty,
    IdentityAction, IdentityArtifactBundle, IdentityCorpus, IdentityDeliveryFault, IdentityEvent,
    IdentityFailureClass, IdentityFailureSignature, IdentityMinimizer, IdentityOperation,
    IdentityRejectionClass, IdentityRunOutcome, IdentityScenario, IdentityScenarioAction,
    IdentityScenarioError, IdentityScenarioRunner, MAX_IDENTITY_SCENARIO_BYTES, MigrationPhase,
    MigrationState, ModelController, ModelError, ModelPolicy, RecoveryController, RecoveryPlan,
    Section36Mutation, check_account_control_model, check_formal_mutation,
    replay_identity_artifacts, run_differential_history,
};

fn controller(id: u16, weight: u16) -> ModelController {
    ModelController::new(ControllerId::new(id), weight).unwrap()
}

fn model(required_weight: u16) -> AccountControlModel {
    AccountControlModel::new(
        [0x11; 32],
        vec![controller(1, 1), controller(2, 1)],
        ModelPolicy::new(required_weight).unwrap(),
    )
    .unwrap()
}

fn event(
    id: u64,
    predecessor: u64,
    sequence: u64,
    approvals: &[u16],
    operation: IdentityOperation,
) -> IdentityEvent {
    event_at_epoch(id, predecessor, sequence, sequence, approvals, operation)
}

fn event_at_epoch(
    id: u64,
    predecessor: u64,
    sequence: u64,
    resulting_epoch: u64,
    approvals: &[u16],
    operation: IdentityOperation,
) -> IdentityEvent {
    IdentityEvent::new(
        EventId::new(id),
        EventId::new(predecessor),
        sequence,
        resulting_epoch,
        approvals.iter().copied().map(ControllerId::new).collect(),
        operation,
    )
    .unwrap()
}

#[test]
fn policy_change_is_authorized_by_the_prior_threshold_and_rejection_is_atomic() {
    let mut state = model(2);
    let insufficient = event(
        1,
        0,
        1,
        &[1],
        IdentityOperation::ChangePolicy(ModelPolicy::new(1).unwrap()),
    );
    let before = state.snapshot();

    assert_eq!(
        state.apply(&insufficient),
        Err(ModelError::InsufficientWeight {
            actual: 1,
            required: 2,
        })
    );
    assert_eq!(state.snapshot(), before);

    let sufficient = event(
        2,
        0,
        1,
        &[1, 2],
        IdentityOperation::ChangePolicy(ModelPolicy::new(1).unwrap()),
    );
    assert_eq!(state.apply(&sufficient).unwrap(), ApplyDisposition::Applied);
    assert_eq!(state.snapshot().policy.required_weight(), 1);
}

#[test]
fn revoked_controller_cannot_authorize_future_state() {
    let mut state = model(1);
    state
        .apply(&event(
            1,
            0,
            1,
            &[1],
            IdentityOperation::RevokeController(ControllerId::new(2)),
        ))
        .unwrap();
    let before = state.snapshot();

    assert_eq!(
        state.apply(&event(
            2,
            1,
            2,
            &[2],
            IdentityOperation::AddController(controller(3, 1)),
        )),
        Err(ModelError::RevokedController(ControllerId::new(2)))
    );
    assert_eq!(state.snapshot(), before);
}

#[test]
fn concurrent_child_is_detected_as_a_fork_and_never_selected_by_arrival_order() {
    let mut first_order = model(1);
    let left = event(
        1,
        0,
        1,
        &[1],
        IdentityOperation::AddController(controller(3, 1)),
    );
    let right = event(
        2,
        0,
        1,
        &[2],
        IdentityOperation::AuthorizeDevice(DeviceId::new(7)),
    );
    assert_eq!(first_order.apply(&left).unwrap(), ApplyDisposition::Applied);
    assert_eq!(
        first_order.apply(&right).unwrap(),
        ApplyDisposition::ForkDetected
    );

    let mut reverse_order = model(1);
    assert_eq!(
        reverse_order.apply(&right).unwrap(),
        ApplyDisposition::Applied
    );
    assert_eq!(
        reverse_order.apply(&left).unwrap(),
        ApplyDisposition::ForkDetected
    );

    assert!(first_order.snapshot().forked);
    assert!(reverse_order.snapshot().forked);
    assert_eq!(
        first_order.snapshot().heads,
        [EventId::new(1), EventId::new(2)]
    );
    assert_eq!(
        reverse_order.snapshot().heads,
        [EventId::new(1), EventId::new(2)]
    );
}

#[test]
fn explicit_fork_resolution_selects_one_branch_and_consumes_every_declared_head() {
    let mut state = model(1);
    let left = event(
        1,
        0,
        1,
        &[1],
        IdentityOperation::AddController(controller(3, 1)),
    );
    let right = event(
        2,
        0,
        1,
        &[2],
        IdentityOperation::AuthorizeDevice(DeviceId::new(7)),
    );
    state.apply(&left).unwrap();
    state.apply(&right).unwrap();

    let resolution = ForkResolution::new(
        EventId::new(3),
        vec![EventId::new(2), EventId::new(1)],
        EventId::new(2),
        2,
        2,
        vec![ControllerId::new(1)],
        vec![ControllerId::new(2)],
        Vec::new(),
    )
    .unwrap();
    assert_eq!(
        state.resolve_fork(&resolution).unwrap(),
        ApplyDisposition::Applied
    );
    assert_eq!(
        state.resolve_fork(&resolution).unwrap(),
        ApplyDisposition::Replay
    );

    let snapshot = state.snapshot();
    assert!(!snapshot.forked);
    assert_eq!(snapshot.heads, [EventId::new(3)]);
    assert_eq!(
        snapshot.devices.get(&DeviceId::new(7)),
        Some(&krikos_sim::identity::DeviceLifecycle::Active)
    );
    assert_eq!(snapshot.active_controllers, [controller(1, 1)]);
    assert!(snapshot.revoked_controllers.contains(&ControllerId::new(2)));
}

#[test]
fn migration_phases_are_ordered_and_an_invalid_phase_is_atomic() {
    let mut state = model(1);
    let before = state.snapshot();
    assert_eq!(
        state.apply(&event(1, 0, 1, &[1], IdentityOperation::ActivateMigration,)),
        Err(ModelError::InvalidMigration)
    );
    assert_eq!(state.snapshot(), before);

    state
        .apply(&event_at_epoch(
            2,
            0,
            1,
            0,
            &[1],
            IdentityOperation::BeginMigration,
        ))
        .unwrap();
    state
        .apply(&event_at_epoch(
            3,
            2,
            2,
            1,
            &[1],
            IdentityOperation::ActivateMigration,
        ))
        .unwrap();
    state
        .apply(&event_at_epoch(
            4,
            3,
            3,
            2,
            &[1],
            IdentityOperation::CompleteMigration,
        ))
        .unwrap();
    assert_eq!(state.snapshot().migration, MigrationState::Complete);
}

#[test]
fn recovery_replaces_authority_and_revoked_devices_never_receive_future_group_keys() {
    let mut state = model(1);
    state
        .apply(&event(
            1,
            0,
            1,
            &[1],
            IdentityOperation::AuthorizeDevice(DeviceId::new(7)),
        ))
        .unwrap();
    state
        .apply(&event(
            2,
            1,
            2,
            &[1],
            IdentityOperation::AuthorizeDevice(DeviceId::new(8)),
        ))
        .unwrap();
    state
        .apply(&event(
            3,
            2,
            3,
            &[1],
            IdentityOperation::RevokeDevice(DeviceId::new(7)),
        ))
        .unwrap();
    state
        .apply(&event(4, 3, 4, &[1], IdentityOperation::RotateGroupKey))
        .unwrap();
    assert_eq!(state.snapshot().group_key_recipients, [DeviceId::new(8)]);

    let plan = RecoveryPlan::new(vec![controller(9, 2)], ModelPolicy::new(2).unwrap()).unwrap();
    state
        .apply_recovery(&event(5, 4, 5, &[], IdentityOperation::Recover(plan)))
        .unwrap();
    let snapshot = state.snapshot();
    assert_eq!(snapshot.active_controllers, [controller(9, 2)]);
    assert!(snapshot.revoked_controllers.contains(&ControllerId::new(1)));
    assert!(snapshot.revoked_controllers.contains(&ControllerId::new(2)));
    assert_eq!(
        snapshot.devices.get(&DeviceId::new(7)),
        Some(&krikos_sim::identity::DeviceLifecycle::Revoked)
    );
    assert_eq!(
        snapshot.devices.get(&DeviceId::new(8)),
        Some(&krikos_sim::identity::DeviceLifecycle::Revoked)
    );
    assert!(snapshot.group_key_recipients.is_empty());
}

#[test]
fn root_seed_type_is_available_for_generated_history_and_scenario_replay() {
    let seed = RootSeed::new([0x42; 32]);
    assert_eq!(seed.as_bytes(), &[0x42; 32]);
}

fn compound_scenario() -> IdentityScenario {
    let at = 10_u64;
    IdentityScenario::new(
        "identity/compound",
        vec![
            IdentityAction::new("partition", 0, IdentityScenarioAction::Partition).unwrap(),
            IdentityAction::new(
                "delay",
                1,
                IdentityScenarioAction::DeliveryFault {
                    fault: IdentityDeliveryFault::Delay,
                },
            )
            .unwrap(),
            IdentityAction::new(
                "reorder",
                2,
                IdentityScenarioAction::DeliveryFault {
                    fault: IdentityDeliveryFault::Reorder,
                },
            )
            .unwrap(),
            IdentityAction::new(
                "loss",
                3,
                IdentityScenarioAction::DeliveryFault {
                    fault: IdentityDeliveryFault::Loss,
                },
            )
            .unwrap(),
            IdentityAction::new(
                "duplicate",
                4,
                IdentityScenarioAction::DeliveryFault {
                    fault: IdentityDeliveryFault::Duplicate,
                },
            )
            .unwrap(),
            IdentityAction::new("heal", 5, IdentityScenarioAction::Heal).unwrap(),
            IdentityAction::new(
                "device-7",
                6,
                IdentityScenarioAction::AuthorizeDevice {
                    device: 7,
                    approvals: vec![1],
                },
            )
            .unwrap(),
            IdentityAction::new(
                "device-8",
                7,
                IdentityScenarioAction::AuthorizeDevice {
                    device: 8,
                    approvals: vec![1],
                },
            )
            .unwrap(),
            IdentityAction::new(
                "revoke-device",
                8,
                IdentityScenarioAction::RevokeDevice {
                    device: 7,
                    approvals: vec![1],
                },
            )
            .unwrap(),
            IdentityAction::new(
                "publish-device-revocation",
                9,
                IdentityScenarioAction::PublishRevocation {
                    subject: "device:7".to_owned(),
                },
            )
            .unwrap(),
            IdentityAction::new(
                "fork-left",
                at,
                IdentityScenarioAction::ForkProposal {
                    fork: "fork-1".to_owned(),
                    branch: "left".to_owned(),
                    approvals: vec![1],
                    operation: ForkScenarioOperation::AddController {
                        controller: 3,
                        weight: 1,
                    },
                },
            )
            .unwrap(),
            IdentityAction::new(
                "fork-right",
                at,
                IdentityScenarioAction::ForkProposal {
                    fork: "fork-1".to_owned(),
                    branch: "right".to_owned(),
                    approvals: vec![1],
                    operation: ForkScenarioOperation::ChangePolicy { required_weight: 1 },
                },
            )
            .unwrap(),
            IdentityAction::new(
                "resolve-fork",
                11,
                IdentityScenarioAction::ResolveFork {
                    fork: "fork-1".to_owned(),
                    selected_branch: "right".to_owned(),
                    approvals: vec![1],
                    revoked_controllers: vec![2],
                    revoked_devices: Vec::new(),
                },
            )
            .unwrap(),
            IdentityAction::new(
                "provider-outage",
                12,
                IdentityScenarioAction::ProviderOutage,
            )
            .unwrap(),
            IdentityAction::new(
                "sensitive-probe",
                13,
                IdentityScenarioAction::SensitiveProbe,
            )
            .unwrap(),
            IdentityAction::new(
                "provider-equivocation",
                14,
                IdentityScenarioAction::ProviderEquivocation,
            )
            .unwrap(),
            IdentityAction::new(
                "sensitive-probe-2",
                15,
                IdentityScenarioAction::SensitiveProbe,
            )
            .unwrap(),
            IdentityAction::new(
                "provider-restore",
                16,
                IdentityScenarioAction::ProviderRestore,
            )
            .unwrap(),
            IdentityAction::new(
                "recover",
                17,
                IdentityScenarioAction::Recover {
                    controllers: vec![
                        RecoveryController {
                            controller: 9,
                            weight: 2,
                        },
                        RecoveryController {
                            controller: 10,
                            weight: 1,
                        },
                    ],
                    required_weight: 2,
                },
            )
            .unwrap(),
            IdentityAction::new(
                "authorize-post-recovery-device",
                18,
                IdentityScenarioAction::AuthorizeDevice {
                    device: 11,
                    approvals: vec![9],
                },
            )
            .unwrap(),
            IdentityAction::new(
                "revoke-controller",
                19,
                IdentityScenarioAction::RevokeController {
                    controller: 10,
                    approvals: vec![9],
                },
            )
            .unwrap(),
            IdentityAction::new(
                "migration-begin",
                20,
                IdentityScenarioAction::Migration {
                    phase: MigrationPhase::Begin,
                    approvals: vec![9],
                },
            )
            .unwrap(),
            IdentityAction::new(
                "migration-activate",
                21,
                IdentityScenarioAction::Migration {
                    phase: MigrationPhase::Activate,
                    approvals: vec![9],
                },
            )
            .unwrap(),
            IdentityAction::new(
                "migration-complete",
                22,
                IdentityScenarioAction::Migration {
                    phase: MigrationPhase::Complete,
                    approvals: vec![9],
                },
            )
            .unwrap(),
            IdentityAction::new(
                "rotate-group-key",
                23,
                IdentityScenarioAction::RotateGroupKey { approvals: vec![9] },
            )
            .unwrap(),
            IdentityAction::new("crash", 24, IdentityScenarioAction::Crash { replica: 1 }).unwrap(),
            IdentityAction::new(
                "reopen-loss",
                25,
                IdentityScenarioAction::Reopen {
                    replica: 1,
                    storage_loss: true,
                },
            )
            .unwrap(),
            IdentityAction::new("offline", 26, IdentityScenarioAction::OfflineValidate).unwrap(),
            IdentityAction::new("social", 27, IdentityScenarioAction::SocialRelationship).unwrap(),
        ],
    )
    .unwrap()
}

#[test]
fn every_identity_action_is_kernel_owned_and_checks_every_section_36_invariant() {
    let scenario = compound_scenario();
    let record = IdentityScenarioRunner::run(&scenario, RootSeed::new([0x31; 32])).unwrap();

    assert_eq!(record.report.steps.len(), scenario.actions().len());
    assert_eq!(record.report.tasks.len(), scenario.actions().len());
    assert!(record.report.tasks.iter().all(|task| !task.live));
    assert!(record.report.scheduler.seeded);
    assert!(record.report.scheduler.decisions > 0);
    assert!(record.report.coverage.covers_lane_a());
    assert_eq!(record.report.delivery.delayed, 1);
    assert_eq!(record.report.delivery.reordered, 1);
    assert_eq!(record.report.delivery.dropped, 1);
    assert_eq!(record.report.delivery.duplicate_deliveries, 1);
    assert!(!record.report.delivery.delivered.is_empty());
    let step = |id: &str| {
        record
            .report
            .steps
            .iter()
            .find(|step| step.action_id == id)
            .unwrap()
    };
    assert!(step("partition").environment.partitioned);
    assert!(!step("heal").environment.partitioned);
    assert!(!step("provider-outage").environment.provider_available);
    assert!(
        !step("provider-equivocation")
            .environment
            .provider_consistent
    );
    let crashed = &step("crash").environment.replicas[0];
    assert!(crashed.crashed);
    let reopened = &step("reopen-loss").environment.replicas[0];
    assert!(!reopened.crashed);
    assert!(!reopened.has_projection);
    assert!(
        record
            .report
            .invariants
            .all_checked_at_each_step(scenario.actions().len())
    );
    assert_eq!(
        record.report.final_state.group_key_recipients,
        [DeviceId::new(11)]
    );
}

#[test]
fn same_root_seed_replays_identity_report_and_raw_trace_exactly() {
    let scenario = compound_scenario();
    let seed = RootSeed::new([0x51; 32]);
    let first = IdentityScenarioRunner::run(&scenario, seed).unwrap();
    let second = IdentityScenarioRunner::run(&scenario, seed).unwrap();

    assert_eq!(first.report, second.report);
    assert_eq!(first.trace, second.trace);
}

#[test]
fn root_seed_controls_co_timed_delivery_order_without_changing_causal_actions() {
    let scenario = IdentityScenario::new(
        "identity/co-timed-delivery",
        vec![
            IdentityAction::new("partition", 0, IdentityScenarioAction::Partition).unwrap(),
            IdentityAction::new(
                "delay",
                1,
                IdentityScenarioAction::DeliveryFault {
                    fault: IdentityDeliveryFault::Delay,
                },
            )
            .unwrap(),
            IdentityAction::new(
                "reorder",
                1,
                IdentityScenarioAction::DeliveryFault {
                    fault: IdentityDeliveryFault::Reorder,
                },
            )
            .unwrap(),
            IdentityAction::new("heal", 2, IdentityScenarioAction::Heal).unwrap(),
        ],
    )
    .unwrap();
    let mut observed = std::collections::BTreeSet::new();
    for fill in 0_u8..32 {
        let report = IdentityScenarioRunner::run(&scenario, RootSeed::new([fill; 32]))
            .unwrap()
            .report;
        observed.insert(report.delivery.delivered);
    }
    assert!(observed.len() > 1);
}

#[test]
fn strict_scenario_validation_rejects_malformed_semantics_before_execution() {
    let oversized = vec![b' '; MAX_IDENTITY_SCENARIO_BYTES + 1];
    assert!(matches!(
        IdentityScenario::from_json(&oversized),
        Err(IdentityScenarioError::InputTooLarge { actual, maximum })
            if actual == MAX_IDENTITY_SCENARIO_BYTES + 1
                && maximum == MAX_IDENTITY_SCENARIO_BYTES
    ));

    let zero_threshold = serde_json::json!({
        "schema_version": 1,
        "id": "identity/invalid-zero-threshold",
        "actions": [{
            "id": "invalid-policy",
            "at_nanos": 0,
            "action": {
                "kind": "change_policy",
                "required_weight": 0,
                "approvals": [1]
            }
        }]
    });
    assert!(IdentityScenario::from_json(&serde_json::to_vec(&zero_threshold).unwrap()).is_err());
    assert!(
        IdentityAction::new(
            "duplicate-approvals",
            0,
            IdentityScenarioAction::AuthorizeDevice {
                device: 7,
                approvals: vec![1, 1],
            },
        )
        .is_err()
    );
    assert!(
        IdentityAction::new(
            "invalid-recovery",
            0,
            IdentityScenarioAction::Recover {
                controllers: vec![RecoveryController {
                    controller: 3,
                    weight: 1,
                }],
                required_weight: 2,
            },
        )
        .is_err()
    );
    let unresolved = IdentityScenario::new(
        "identity/invalid-fork-reference",
        vec![
            IdentityAction::new(
                "resolve",
                0,
                IdentityScenarioAction::ResolveFork {
                    fork: "missing".into(),
                    selected_branch: "missing".into(),
                    approvals: vec![1],
                    revoked_controllers: Vec::new(),
                    revoked_devices: Vec::new(),
                },
            )
            .unwrap(),
        ],
    );
    assert!(unresolved.is_err());
    assert!(
        IdentityAction::new("provider-outage", 0, IdentityScenarioAction::ProviderOutage)
            .unwrap()
            .expect_model_rejection(ExpectedModelRejection::InsufficientWeight)
            .is_err()
    );
}

#[test]
fn strict_scenario_validation_rejects_unrepresentable_recovery_weight_before_execution() {
    let scenario = serde_json::json!({
        "schema_version": 1,
        "id": "identity/invalid-recovery-weight-total",
        "actions": [{
            "id": "invalid-recovery",
            "at_nanos": 0,
            "action": {
                "kind": "recover",
                "controllers": [
                    { "controller": 3, "weight": 65535 },
                    { "controller": 4, "weight": 1 }
                ],
                "required_weight": 1
            }
        }]
    });

    let error = IdentityScenario::from_json(&serde_json::to_vec(&scenario).unwrap()).unwrap_err();
    assert!(matches!(
        error,
        IdentityScenarioError::InvalidAction { action, reason }
            if action == "invalid-recovery"
                && reason == "recovery authority weight exceeds model representation"
    ));
}

#[test]
fn immutable_identity_artifacts_replay_with_source_report_and_raw_trace_binding() {
    let scenario = compound_scenario();
    let seed = RootSeed::new([0x61; 32]);
    let record = IdentityScenarioRunner::run(&scenario, seed).unwrap();
    let scenario_bytes = scenario.to_canonical_json().unwrap();
    let manifest = RunManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        simulator_version: SIMULATOR_VERSION.to_owned(),
        source: SourceIdentity {
            revision: "identity-test-source".to_owned(),
            dirty_digest: None,
        },
        root_seed: "61".repeat(32),
        scenario_id: scenario.id().to_owned(),
        scenario_hash: blake3::hash(&scenario_bytes).to_hex().to_string(),
        normalized_config: std::collections::BTreeMap::from([(
            "lane".to_owned(),
            "identity".to_owned(),
        )]),
        features: Vec::new(),
        wall_clock_epoch_secs: 0,
        backend: BackendCapabilities::deterministic_kernel(),
        budgets: RunBudgets {
            max_events: 10_000,
            max_virtual_time_nanos: 60_000_000_000,
            max_tasks: 512,
            max_packets: 1,
        },
        scheduling_profile: "seeded-kernel-v1".to_owned(),
        fault_profile: "identity-actions-v1".to_owned(),
        lockfile_digest: "ab".repeat(32),
        crypto_mode: CryptoMode::DeterministicTest,
        trace_comparison: TraceComparisonMode::Raw,
        fidelity_exceptions: vec!["deterministic_test_crypto".to_owned()],
        determinism_grade: DeterminismGrade::FullyDeterministic,
        escapes: Vec::new(),
        unsafe_test_only: true,
    };
    let directory = tempfile::tempdir().unwrap();
    let store = ArtifactStore::new(directory.path()).unwrap();
    IdentityArtifactBundle {
        scenario: &scenario,
        manifest: &manifest,
        record: &record,
    }
    .write(&store)
    .unwrap();

    let replayed = replay_identity_artifacts(store.root(), &manifest.replay_identity()).unwrap();
    assert_eq!(replayed, record);
}

#[test]
fn identity_minimizer_keeps_only_actions_required_for_the_confirmed_signature() {
    let scenario = IdentityScenario::new(
        "identity/minimize",
        vec![
            IdentityAction::new(
                "noise-before",
                0,
                IdentityScenarioAction::SocialRelationship,
            )
            .unwrap(),
            IdentityAction::new("trigger", 1, IdentityScenarioAction::OfflineValidate).unwrap(),
            IdentityAction::new("noise-after", 2, IdentityScenarioAction::SocialRelationship)
                .unwrap(),
        ],
    )
    .unwrap();
    let signature = IdentityFailureSignature::new("invariant/test", b"stable evidence").unwrap();
    let expected = signature.clone();
    let result = IdentityMinimizer::new(16)
        .unwrap()
        .minimize(scenario, signature, &mut |candidate| {
            Ok(candidate
                .actions()
                .iter()
                .any(|action| action.id() == "trigger")
                .then_some(expected.clone()))
        })
        .unwrap();

    assert_eq!(result.scenario.actions().len(), 1);
    assert_eq!(result.scenario.actions()[0].id(), "trigger");
    assert!(result.attempts.iter().any(|attempt| attempt.accepted));
}

#[test]
fn real_identity_runner_invariant_failure_has_stable_evidence_trace_and_report() {
    let scenario = IdentityScenario::new(
        "identity/real-failure",
        vec![
            IdentityAction::new(
                "noise-before",
                0,
                IdentityScenarioAction::SocialRelationship,
            )
            .unwrap(),
            IdentityAction::new(
                "section36-fault",
                1,
                IdentityScenarioAction::Section36Fault {
                    mutation: Section36Mutation::AccountIsDevice,
                },
            )
            .unwrap(),
            IdentityAction::new("noise-after", 2, IdentityScenarioAction::SocialRelationship)
                .unwrap(),
        ],
    )
    .unwrap();
    let seed = RootSeed::new([0xa4; 32]);

    let first = IdentityScenarioRunner::run_detailed(&scenario, seed).unwrap();
    let second = IdentityScenarioRunner::run_detailed(&scenario, seed).unwrap();
    let (IdentityRunOutcome::Failed(first), IdentityRunOutcome::Failed(second)) = (first, second)
    else {
        panic!("the real runner must report the product failure");
    };

    assert_eq!(first.signature().unwrap(), second.signature().unwrap());
    assert_eq!(first.report, second.report);
    assert_eq!(first.trace, second.trace);
    assert_eq!(first.report.steps.len(), scenario.actions().len());
    assert!(!first.trace.is_empty());
    assert_eq!(first.evidence.class, IdentityFailureClass::Invariant);
    assert!(!first.evidence.detail.is_empty());
}

#[test]
fn every_section36_oracle_rejects_its_real_runner_counterexample() {
    for (mutation, invariant) in [
        (Section36Mutation::AccountIsDevice, "account_is_not_device"),
        (
            Section36Mutation::OrdinaryPrivateKeyReplication,
            "no_ordinary_private_key_replication",
        ),
        (
            Section36Mutation::DeviceNotIndependentlyRevocable,
            "device_independently_revocable",
        ),
        (
            Section36Mutation::PriorPolicyBypass,
            "prior_policy_authorization",
        ),
        (
            Section36Mutation::AccountIdentityChanged,
            "stable_account_identity",
        ),
        (
            Section36Mutation::ProviderCreatedState,
            "provider_cannot_create_state",
        ),
        (
            Section36Mutation::SocialRelationshipCreatedAuthority,
            "social_no_implicit_authority",
        ),
        (
            Section36Mutation::PublishedRevocationUndiscoverable,
            "published_revocation_discoverability",
        ),
        (
            Section36Mutation::OfflineValidationWithoutBasis,
            "offline_validation_has_basis",
        ),
        (
            Section36Mutation::SensitiveActionDidNotFailClosed,
            "sensitive_actions_fail_closed",
        ),
        (
            Section36Mutation::RevokedDeviceReceivedGroupKey,
            "revoked_device_excluded_from_group_keys",
        ),
        (
            Section36Mutation::ConflictSilentlyMerged,
            "conflicts_detected_not_merged",
        ),
    ] {
        let scenario = section36_mutation_scenario(mutation);
        let outcome = IdentityScenarioRunner::run_with_invariant_mutation(
            &scenario,
            RootSeed::new([0xc6; 32]),
            mutation,
        )
        .unwrap();
        let IdentityRunOutcome::Failed(failure) = outcome else {
            panic!("{invariant} mutation escaped the real runner");
        };
        assert_eq!(failure.evidence.class, IdentityFailureClass::Invariant);
        assert!(failure.evidence.detail.contains(invariant));
    }
}

#[test]
fn retained_fork_allows_a_sensitive_probe_to_fail_closed_without_a_false_oracle_failure() {
    let scenario = IdentityScenario::new(
        "identity/fork-sensitive-probe",
        vec![
            IdentityAction::new(
                "left",
                0,
                IdentityScenarioAction::ForkProposal {
                    fork: "fork-a".into(),
                    branch: "left".into(),
                    approvals: vec![1],
                    operation: ForkScenarioOperation::AddController {
                        controller: 3,
                        weight: 1,
                    },
                },
            )
            .unwrap(),
            IdentityAction::new(
                "right",
                1,
                IdentityScenarioAction::ForkProposal {
                    fork: "fork-a".into(),
                    branch: "right".into(),
                    approvals: vec![1],
                    operation: ForkScenarioOperation::AuthorizeDevice { device: 7 },
                },
            )
            .unwrap(),
            IdentityAction::new("provider-outage", 2, IdentityScenarioAction::ProviderOutage)
                .unwrap(),
            IdentityAction::new("crash", 3, IdentityScenarioAction::Crash { replica: 1 }).unwrap(),
            IdentityAction::new(
                "reopen",
                4,
                IdentityScenarioAction::Reopen {
                    replica: 1,
                    storage_loss: true,
                },
            )
            .unwrap(),
            IdentityAction::new("probe", 5, IdentityScenarioAction::SensitiveProbe).unwrap(),
            IdentityAction::new(
                "provider-restore",
                6,
                IdentityScenarioAction::ProviderRestore,
            )
            .unwrap(),
            IdentityAction::new(
                "resolve",
                7,
                IdentityScenarioAction::ResolveFork {
                    fork: "fork-a".into(),
                    selected_branch: "left".into(),
                    approvals: vec![1],
                    revoked_controllers: Vec::new(),
                    revoked_devices: Vec::new(),
                },
            )
            .unwrap(),
        ],
    )
    .unwrap();

    let outcome =
        IdentityScenarioRunner::run_detailed(&scenario, RootSeed::new([0xd6; 32])).unwrap();
    let IdentityRunOutcome::Success(record) = outcome else {
        panic!("a retained conflict must allow the probe to fail closed");
    };
    let probe = record
        .report
        .steps
        .iter()
        .find(|step| step.action_id == "probe")
        .unwrap();
    assert_eq!(probe.outcome, "failed_closed");
    assert!(probe.state.forked);
    assert_eq!(probe.state.heads.len(), 2);
    assert!(!record.report.final_state.forked);
    assert_eq!(record.report.final_state.heads.len(), 1);
}

fn section36_mutation_scenario(mutation: Section36Mutation) -> IdentityScenario {
    let actions = match mutation {
        Section36Mutation::AccountIsDevice
        | Section36Mutation::OrdinaryPrivateKeyReplication
        | Section36Mutation::AccountIdentityChanged
        | Section36Mutation::SocialRelationshipCreatedAuthority => vec![
            IdentityAction::new("social", 0, IdentityScenarioAction::SocialRelationship).unwrap(),
        ],
        Section36Mutation::DeviceNotIndependentlyRevocable
        | Section36Mutation::RevokedDeviceReceivedGroupKey => vec![
            IdentityAction::new(
                "authorize-device",
                0,
                IdentityScenarioAction::AuthorizeDevice {
                    device: 7,
                    approvals: vec![1],
                },
            )
            .unwrap(),
            IdentityAction::new(
                "revoke-device",
                1,
                IdentityScenarioAction::RevokeDevice {
                    device: 7,
                    approvals: vec![1],
                },
            )
            .unwrap(),
        ],
        Section36Mutation::PriorPolicyBypass => vec![
            IdentityAction::new(
                "add-controller",
                0,
                IdentityScenarioAction::AddController {
                    controller: 3,
                    weight: 1,
                    approvals: vec![1],
                },
            )
            .unwrap(),
        ],
        Section36Mutation::ProviderCreatedState => vec![
            IdentityAction::new("provider-outage", 0, IdentityScenarioAction::ProviderOutage)
                .unwrap(),
        ],
        Section36Mutation::PublishedRevocationUndiscoverable => vec![
            IdentityAction::new(
                "authorize-device",
                0,
                IdentityScenarioAction::AuthorizeDevice {
                    device: 7,
                    approvals: vec![1],
                },
            )
            .unwrap(),
            IdentityAction::new(
                "revoke-device",
                1,
                IdentityScenarioAction::RevokeDevice {
                    device: 7,
                    approvals: vec![1],
                },
            )
            .unwrap(),
            IdentityAction::new(
                "publish-revocation",
                2,
                IdentityScenarioAction::PublishRevocation {
                    subject: "device:7".into(),
                },
            )
            .unwrap(),
        ],
        Section36Mutation::OfflineValidationWithoutBasis => vec![
            IdentityAction::new("offline", 0, IdentityScenarioAction::OfflineValidate).unwrap(),
        ],
        Section36Mutation::SensitiveActionDidNotFailClosed => vec![
            IdentityAction::new("provider-outage", 0, IdentityScenarioAction::ProviderOutage)
                .unwrap(),
            IdentityAction::new("probe", 1, IdentityScenarioAction::SensitiveProbe).unwrap(),
        ],
        Section36Mutation::ConflictSilentlyMerged => vec![
            IdentityAction::new(
                "left",
                0,
                IdentityScenarioAction::ForkProposal {
                    fork: "fork-a".into(),
                    branch: "left".into(),
                    approvals: vec![1],
                    operation: ForkScenarioOperation::AddController {
                        controller: 3,
                        weight: 1,
                    },
                },
            )
            .unwrap(),
            IdentityAction::new(
                "right",
                1,
                IdentityScenarioAction::ForkProposal {
                    fork: "fork-a".into(),
                    branch: "right".into(),
                    approvals: vec![1],
                    operation: ForkScenarioOperation::AuthorizeDevice { device: 7 },
                },
            )
            .unwrap(),
        ],
    };
    IdentityScenario::new(format!("identity/section36-{mutation:?}"), actions).unwrap()
}

#[test]
fn strict_recorded_identity_corpus_proves_complete_coverage_and_replays_both_seeds() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("identity-corpus");
    let corpus = IdentityCorpus::load(&root).unwrap();

    assert_eq!(corpus.entries().len(), 2);
    assert!(corpus.coverage().covers_lane_a());
    let reports = corpus.test().unwrap();
    assert_eq!(reports.len(), 2);
    assert!(reports.iter().all(|entry| entry.report.scheduler.seeded));
    assert!(
        reports
            .iter()
            .all(|entry| entry.report.tasks.len() == entry.report.steps.len())
    );
}

#[test]
fn generated_history_matches_the_implementation_across_every_required_authority_transition() {
    let seed = RootSeed::new([0x73; 32]);
    let first = run_differential_history(seed).unwrap();
    let replay = run_differential_history(seed).unwrap();

    assert_eq!(first, replay);
    assert!(first.coverage.policy_change);
    assert!(first.coverage.controller_revocation);
    assert!(first.coverage.device_revocation);
    assert!(first.coverage.fork_and_resolution);
    assert!(first.coverage.recovery);
    assert!(first.coverage.migration);
    assert!(first.coverage.group_recipient_rotation);
    assert!(
        first
            .production_evidence
            .migration_crypto_commitment_changed
    );
    assert!(first.production_evidence.new_suite_authorized);
    assert!(first.production_evidence.old_suite_rejected);
    assert!(first.production_evidence.revoked_recipient_rejected);
    assert_eq!(first.production_evidence.group_rotation_wraps, 1);
    assert!(first.steps.len() >= 12);
    assert!(
        first
            .steps
            .iter()
            .all(|step| step.implementation == step.reference)
    );
    let expected_positions = [
        ("genesis", 0, 0, 0),
        ("policy_change", 1, 1, 0),
        ("authorize_device_7", 2, 2, 0),
        ("authorize_device_8", 3, 3, 0),
        ("revoke_device", 4, 4, 0),
        ("fork_detected", 5, 4, 0),
        ("fork_resolved", 6, 6, 0),
        ("recovery", 8, 8, 0),
        ("authorize_post_recovery_device", 9, 9, 0),
        ("revoke_controller", 10, 10, 0),
        ("migration_begin", 11, 10, 0),
        ("migration_activate", 12, 11, 0),
        ("migration_complete", 13, 12, 0),
        ("group_recipient_rotation", 13, 12, 1),
    ];
    let account_id = first.steps[0].implementation.account_id;
    for (action, sequence, epoch, group_key_generation) in expected_positions {
        let snapshot = &first
            .steps
            .iter()
            .find(|step| step.action == action)
            .unwrap()
            .implementation;
        assert_eq!(snapshot.account_id, account_id, "{action}");
        assert_eq!(snapshot.sequence, sequence, "{action}");
        assert_eq!(snapshot.epoch, epoch, "{action}");
        assert_eq!(
            snapshot.group_key_generation, group_key_generation,
            "{action}"
        );
    }
    let fork = &first
        .steps
        .iter()
        .find(|step| step.action == "fork_detected")
        .unwrap()
        .implementation;
    assert_eq!(fork.canonical_heads.len(), 2);
    let mut fork_predecessors = fork.canonical_heads.values();
    let common_predecessor = fork_predecessors.next().unwrap();
    assert_eq!(common_predecessor.len(), 1);
    assert!(fork_predecessors.all(|predecessors| predecessors == common_predecessor));
    let resolution = &first
        .steps
        .iter()
        .find(|step| step.action == "fork_resolved")
        .unwrap()
        .implementation;
    assert_eq!(resolution.canonical_heads.len(), 1);
    assert_eq!(resolution.canonical_heads.values().next().unwrap().len(), 2);
    assert_eq!(
        first
            .steps
            .iter()
            .find(|step| step.action == "migration_begin")
            .unwrap()
            .implementation
            .migration,
        MigrationState::Pending
    );
    assert_eq!(
        first
            .steps
            .iter()
            .find(|step| step.action == "migration_activate")
            .unwrap()
            .implementation
            .migration,
        MigrationState::Dual
    );
    assert_eq!(
        first
            .steps
            .iter()
            .find(|step| step.action == "migration_complete")
            .unwrap()
            .implementation
            .migration,
        MigrationState::Complete
    );
}

#[test]
fn differential_comparator_rejects_a_projection_only_position_perturbation() {
    let report = run_differential_history(RootSeed::new([0x74; 32])).unwrap();
    let checkpoint = report
        .steps
        .iter()
        .find(|step| step.action == "migration_begin")
        .unwrap();
    let mut perturbed = checkpoint.reference.clone();
    perturbed.epoch = perturbed.epoch.checked_add(1).unwrap();

    let error = checkpoint
        .implementation
        .clone()
        .compare("projection_epoch_perturbation", perturbed)
        .unwrap_err();
    assert!(matches!(
        error,
        DifferentialError::Divergence { action, .. }
            if action == "projection_epoch_perturbation"
    ));
}

#[test]
fn production_identity_dependency_is_confined_to_the_differential_adapter() {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/identity");
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        if !entry.file_type().unwrap().is_file() || entry.file_name() == "adapter.rs" {
            continue;
        }
        let text = std::fs::read_to_string(entry.path()).unwrap();
        assert!(
            !text.contains("krikos_identity"),
            "production dependency escaped into {}",
            entry.path().display()
        );
    }
}

#[test]
fn formal_bfs_and_checked_in_tla_are_non_vacuous_and_semantically_equivalent() {
    let report = check_account_control_model().unwrap();
    assert!(report.is_non_vacuous());
    assert!(report.states_explored > 1);
    assert!(report.transitions_explored > report.states_explored);
    assert_eq!(report.property_checks.len(), 6);
    assert_eq!(report.tla_actions_validated, 6);
    assert_eq!(report.tla_properties_validated, 6);
    assert!(report.semantic_parity_cases >= report.transitions_explored);
    assert!(report.asymmetric_weight_witnesses > 0);
    assert_eq!(report.transition_mutations_rejected, 7);
    assert_eq!(report.portable_mutations_rejected, 2);
    assert_eq!(report.property_evidence.len(), 6);
    assert!(report.property_evidence.values().all(|evidence| {
        evidence.evaluations == report.transitions_explored
            && evidence.antecedent_witnesses > 0
            && evidence.accepted_witnesses > 0
            && evidence.rejected_witnesses > 0
    }));
}

#[test]
fn identity_cli_checks_the_reviewed_corpus_and_formal_model() {
    let binary = env!("CARGO_BIN_EXE_cargo-sim");
    let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("identity-corpus");
    let corpus_output = std::process::Command::new(binary)
        .args(["identity", "corpus-test"])
        .arg(corpus)
        .output()
        .unwrap();
    assert!(
        corpus_output.status.success(),
        "{}",
        String::from_utf8_lossy(&corpus_output.stderr)
    );
    let reports: Vec<krikos_sim::identity::IdentityCorpusReport> =
        serde_json::from_slice(&corpus_output.stdout).unwrap();
    assert_eq!(reports.len(), 2);

    let formal_output = std::process::Command::new(binary)
        .args(["identity", "model-check"])
        .output()
        .unwrap();
    assert!(
        formal_output.status.success(),
        "{}",
        String::from_utf8_lossy(&formal_output.stderr)
    );
    let report: krikos_sim::identity::FormalCheckReport =
        serde_json::from_slice(&formal_output.stdout).unwrap();
    assert!(report.is_non_vacuous());
}

#[test]
fn identity_cli_run_artifacts_replay_report_and_traces_exactly() {
    let binary = env!("CARGO_BIN_EXE_cargo-sim");
    let scenario = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("identity-corpus/network-storage-provider.json");
    let directory = tempfile::tempdir().unwrap();
    let artifacts = directory.path().join("identity-run");
    let run = std::process::Command::new(binary)
        .args(["identity", "run"])
        .arg(scenario)
        .args(["--seed", &"81".repeat(32), "--artifacts"])
        .arg(&artifacts)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );

    let replay = std::process::Command::new(binary)
        .args(["identity", "replay"])
        .arg(artifacts.join("manifest.json"))
        .output()
        .unwrap();
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert!(String::from_utf8_lossy(&replay.stdout).contains("status=replay_ok"));
}

#[test]
fn identity_cli_replays_expected_model_rejection_without_product_failure_artifacts() {
    let binary = env!("CARGO_BIN_EXE_cargo-sim");
    let directory = tempfile::tempdir().unwrap();
    let scenario_path = directory.path().join("expected-rejection.json");
    let artifacts = directory.path().join("identity-expected-rejection");
    let scenario = IdentityScenario::new(
        "identity/expected-model-rejection",
        vec![
            IdentityAction::new(
                "insufficient-approval",
                0,
                IdentityScenarioAction::ChangePolicy {
                    required_weight: 1,
                    approvals: Vec::new(),
                },
            )
            .unwrap()
            .expect_model_rejection(ExpectedModelRejection::InsufficientWeight)
            .unwrap(),
        ],
    )
    .unwrap();
    std::fs::write(&scenario_path, scenario.to_canonical_json().unwrap()).unwrap();

    let unmarked = IdentityScenario::new(
        "identity/unmarked-model-rejection",
        vec![
            IdentityAction::new(
                "insufficient-approval",
                0,
                IdentityScenarioAction::ChangePolicy {
                    required_weight: 1,
                    approvals: Vec::new(),
                },
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let IdentityRunOutcome::Failed(unmarked_failure) =
        IdentityScenarioRunner::run_detailed(&unmarked, RootSeed::new([0xb4; 32])).unwrap()
    else {
        panic!("an unmarked model rejection must remain a product failure");
    };
    assert_eq!(unmarked_failure.evidence.class, IdentityFailureClass::Model);

    let unknown_controller = IdentityScenario::new(
        "identity/expected-unknown-controller",
        vec![
            IdentityAction::new(
                "unknown-controller-approval",
                0,
                IdentityScenarioAction::ChangePolicy {
                    required_weight: 1,
                    approvals: vec![99],
                },
            )
            .unwrap()
            .expect_model_rejection(ExpectedModelRejection::UnknownController)
            .unwrap(),
        ],
    )
    .unwrap();
    let IdentityRunOutcome::ExpectedRejection(unknown_controller_rejection) =
        IdentityScenarioRunner::run_detailed(&unknown_controller, RootSeed::new([0xb4; 32]))
            .unwrap()
    else {
        panic!("a marked unknown controller must be an expected rejection");
    };
    assert_eq!(
        unknown_controller_rejection.evidence.rejection,
        ExpectedModelRejection::UnknownController
    );
    assert_eq!(
        unknown_controller_rejection.report.final_state,
        model(1).snapshot(),
        "an expected model rejection must leave account state unchanged"
    );

    let mismatched = IdentityScenario::new(
        "identity/mismatched-model-rejection",
        vec![
            IdentityAction::new(
                "insufficient-approval",
                0,
                IdentityScenarioAction::ChangePolicy {
                    required_weight: 1,
                    approvals: Vec::new(),
                },
            )
            .unwrap()
            .expect_model_rejection(ExpectedModelRejection::UnknownController)
            .unwrap(),
        ],
    )
    .unwrap();
    let IdentityRunOutcome::Failed(mismatched_failure) =
        IdentityScenarioRunner::run_detailed(&mismatched, RootSeed::new([0xb4; 32])).unwrap()
    else {
        panic!("a mismatched model rejection must remain a product failure");
    };
    assert_eq!(
        mismatched_failure.evidence.class,
        IdentityFailureClass::Model
    );

    let unexpectedly_successful = IdentityScenario::new(
        "identity/expected-rejection-succeeded",
        vec![
            IdentityAction::new(
                "authorized-policy-change",
                0,
                IdentityScenarioAction::ChangePolicy {
                    required_weight: 1,
                    approvals: vec![1],
                },
            )
            .unwrap()
            .expect_model_rejection(ExpectedModelRejection::InsufficientWeight)
            .unwrap(),
        ],
    )
    .unwrap();
    let IdentityRunOutcome::Failed(success_failure) =
        IdentityScenarioRunner::run_detailed(&unexpectedly_successful, RootSeed::new([0xb4; 32]))
            .unwrap()
    else {
        panic!("an expected rejection that succeeds must be a product failure");
    };
    assert_eq!(
        success_failure.evidence.class,
        IdentityFailureClass::Execution
    );

    let outcome =
        IdentityScenarioRunner::run_detailed(&scenario, RootSeed::new([0xb4; 32])).unwrap();
    let IdentityRunOutcome::ExpectedRejection(rejection) = outcome else {
        panic!("insufficient prior-policy approval must be an expected rejection");
    };
    assert_eq!(rejection.evidence.class, IdentityRejectionClass::Model);
    assert_eq!(
        rejection.evidence.rejection,
        ExpectedModelRejection::InsufficientWeight
    );

    let run = std::process::Command::new(binary)
        .args(["identity", "run"])
        .arg(&scenario_path)
        .args(["--seed", &"b4".repeat(32), "--artifacts"])
        .arg(&artifacts)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(String::from_utf8_lossy(&run.stdout).contains("terminal=expected_rejection"));
    assert!(artifacts.join("identity-rejection-report.json").is_file());
    for forbidden in [
        "failure-artifacts.json",
        "failure-minimization.json",
        "failure-signature.json",
        "identity-failure-report.json",
    ] {
        assert!(
            !artifacts.join(forbidden).exists(),
            "expected rejection wrote product artifact {forbidden}"
        );
    }

    let replay = std::process::Command::new(binary)
        .args(["identity", "replay"])
        .arg(artifacts.join("manifest.json"))
        .output()
        .unwrap();
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert!(String::from_utf8_lossy(&replay.stdout).contains("terminal=expected_rejection"));
}

#[test]
fn identity_rejection_replay_rejects_noncanonical_report_bytes() {
    let binary = env!("CARGO_BIN_EXE_cargo-sim");
    let directory = tempfile::tempdir().unwrap();
    let scenario_path = directory.path().join("expected-rejection.json");
    let artifacts = directory.path().join("identity-expected-rejection");
    let scenario = IdentityScenario::new(
        "identity/noncanonical-rejection-report",
        vec![
            IdentityAction::new(
                "insufficient-approval",
                0,
                IdentityScenarioAction::ChangePolicy {
                    required_weight: 1,
                    approvals: Vec::new(),
                },
            )
            .unwrap()
            .expect_model_rejection(ExpectedModelRejection::InsufficientWeight)
            .unwrap(),
        ],
    )
    .unwrap();
    std::fs::write(&scenario_path, scenario.to_canonical_json().unwrap()).unwrap();

    let run = std::process::Command::new(binary)
        .args(["identity", "run"])
        .arg(&scenario_path)
        .args(["--seed", &"b5".repeat(32), "--artifacts"])
        .arg(&artifacts)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );

    let report_path = artifacts.join("identity-rejection-report.json");
    let mut noncanonical = std::fs::read(&report_path).unwrap();
    noncanonical.extend_from_slice(b" \n");
    std::fs::write(&report_path, noncanonical).unwrap();

    let replay = std::process::Command::new(binary)
        .args(["identity", "replay"])
        .arg(artifacts.join("manifest.json"))
        .output()
        .unwrap();
    assert!(!replay.status.success());
    assert!(
        String::from_utf8_lossy(&replay.stderr)
            .contains("identity replay expected-rejection report diverged")
    );
}

#[test]
fn identity_cli_confirms_minimizes_replays_and_stages_a_real_failure_for_review() {
    let binary = env!("CARGO_BIN_EXE_cargo-sim");
    let directory = tempfile::tempdir().unwrap();
    let scenario_path = directory.path().join("failing-scenario.json");
    let artifacts = directory.path().join("identity-failure");
    let candidate = directory.path().join("promotion-candidate");
    let scenario = IdentityScenario::new(
        "identity/real-cli-failure",
        vec![
            IdentityAction::new(
                "noise-before",
                0,
                IdentityScenarioAction::SocialRelationship,
            )
            .unwrap(),
            IdentityAction::new(
                "section36-fault",
                1,
                IdentityScenarioAction::Section36Fault {
                    mutation: Section36Mutation::AccountIsDevice,
                },
            )
            .unwrap(),
            IdentityAction::new("noise-after", 2, IdentityScenarioAction::SocialRelationship)
                .unwrap(),
        ],
    )
    .unwrap();
    std::fs::write(&scenario_path, scenario.to_canonical_json().unwrap()).unwrap();

    let run = std::process::Command::new(binary)
        .args(["identity", "run"])
        .arg(&scenario_path)
        .args(["--seed", &"a4".repeat(32), "--artifacts"])
        .arg(&artifacts)
        .args(["--max-minimization-attempts", "16"])
        .output()
        .unwrap();
    assert!(
        !run.status.success(),
        "a recorded product failure stays nonzero"
    );
    for name in [
        "manifest.json",
        "scenario.json",
        "failure-original.json",
        "failure-minimized.json",
        "failure-signature.json",
        "failure-minimization.json",
        "failure-confirmation.json",
        "identity-failure-original-report.json",
        "identity-failure-report.json",
        "trace-original.raw.jsonl",
        "trace-original.jsonl",
        "trace.raw.jsonl",
        "trace.jsonl",
        "failure-artifacts.json",
    ] {
        assert!(artifacts.join(name).is_file(), "missing {name}");
    }
    let minimized =
        IdentityScenario::from_json(&std::fs::read(artifacts.join("scenario.json")).unwrap())
            .unwrap();
    assert_eq!(minimized.actions().len(), 1);
    assert_eq!(minimized.actions()[0].id(), "section36-fault");

    let replay = std::process::Command::new(binary)
        .args(["identity", "replay"])
        .arg(artifacts.join("manifest.json"))
        .output()
        .unwrap();
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert!(String::from_utf8_lossy(&replay.stdout).contains("terminal=expected_failure"));

    let promote = std::process::Command::new(binary)
        .args(["identity", "promotion-candidate"])
        .arg(artifacts.join("manifest.json"))
        .args(["--output"])
        .arg(&candidate)
        .args(["--issue", "https://example.invalid/issues/123"])
        .output()
        .unwrap();
    assert!(
        promote.status.success(),
        "{}",
        String::from_utf8_lossy(&promote.stderr)
    );
    let entry: serde_json::Value =
        serde_json::from_slice(&std::fs::read(candidate.join("entry.json")).unwrap()).unwrap();
    assert_eq!(entry["reviewed"], false);
    assert_eq!(entry["expectation"]["terminal"], "expected_failure");
    assert!(candidate.join("scenario.json").is_file());

    for target in [
        "manifest.json",
        "scenario.json",
        "failure-original.json",
        "failure-minimized.json",
        "failure-signature.json",
        "failure-minimization.json",
        "failure-confirmation.json",
        "identity-failure-original-report.json",
        "identity-failure-report.json",
        "trace-original.raw.jsonl",
        "trace-original.jsonl",
        "trace.raw.jsonl",
        "trace.jsonl",
    ] {
        let tampered = directory
            .path()
            .join(format!("tampered-{}", target.replace('.', "-")));
        std::fs::create_dir(&tampered).unwrap();
        for artifact in std::fs::read_dir(&artifacts).unwrap() {
            let artifact = artifact.unwrap();
            std::fs::copy(artifact.path(), tampered.join(artifact.file_name())).unwrap();
        }
        let target_path = tampered.join(target);
        let mut bytes = std::fs::read(&target_path).unwrap();
        bytes.push(b' ');
        std::fs::write(&target_path, bytes).unwrap();
        let rejected = std::process::Command::new(binary)
            .args(["identity", "replay"])
            .arg(tampered.join("manifest.json"))
            .output()
            .unwrap();
        assert!(!rejected.status.success(), "tampered {target} replayed");
    }

    let original_scenario_tamper = directory.path().join("tampered-original-reindexed");
    copy_identity_failure_artifacts(&artifacts, &original_scenario_tamper);
    std::fs::write(
        original_scenario_tamper.join("failure-original.json"),
        b"{}\n",
    )
    .unwrap();
    reindex_identity_failure_artifact(&original_scenario_tamper, "failure-original.json");
    let rejected = std::process::Command::new(binary)
        .args(["identity", "replay"])
        .arg(original_scenario_tamper.join("manifest.json"))
        .output()
        .unwrap();
    assert!(
        !rejected.status.success(),
        "a reindexed original-scenario substitution replayed"
    );

    let confirmation_tamper = directory.path().join("tampered-confirmation-reindexed");
    copy_identity_failure_artifacts(&artifacts, &confirmation_tamper);
    let confirmation_path = confirmation_tamper.join("failure-confirmation.json");
    let mut confirmation: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&confirmation_path).unwrap()).unwrap();
    confirmation["original_report_digest"] = "00".repeat(32).into();
    let mut confirmation_bytes = serde_json::to_vec_pretty(&confirmation).unwrap();
    confirmation_bytes.push(b'\n');
    std::fs::write(&confirmation_path, confirmation_bytes).unwrap();
    reindex_identity_failure_artifact(&confirmation_tamper, "failure-confirmation.json");
    let rejected = std::process::Command::new(binary)
        .args(["identity", "replay"])
        .arg(confirmation_tamper.join("manifest.json"))
        .output()
        .unwrap();
    assert!(
        !rejected.status.success(),
        "a reindexed original-confirmation substitution replayed"
    );

    let minimization_tamper = directory.path().join("tampered-minimization-reindexed");
    copy_identity_failure_artifacts(&artifacts, &minimization_tamper);
    let minimization_path = minimization_tamper.join("failure-minimization.json");
    let mut minimization: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&minimization_path).unwrap()).unwrap();
    minimization["attempts"][0]["candidate_digest"] = "00".repeat(32).into();
    let mut minimization_bytes = serde_json::to_vec_pretty(&minimization).unwrap();
    minimization_bytes.push(b'\n');
    std::fs::write(&minimization_path, minimization_bytes).unwrap();
    reindex_identity_failure_artifact(&minimization_tamper, "failure-minimization.json");
    let rejected = std::process::Command::new(binary)
        .args(["identity", "replay"])
        .arg(minimization_tamper.join("manifest.json"))
        .output()
        .unwrap();
    assert!(
        !rejected.status.success(),
        "a reindexed reduction-provenance substitution replayed"
    );

    let promoted_corpus = directory.path().join("promoted-corpus");
    std::fs::create_dir(&promoted_corpus).unwrap();
    let checked_in = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("identity-corpus");
    for name in ["authority-lifecycle.json", "network-storage-provider.json"] {
        std::fs::copy(checked_in.join(name), promoted_corpus.join(name)).unwrap();
    }
    std::fs::copy(
        candidate.join("scenario.json"),
        promoted_corpus.join("real-cli-failure.json"),
    )
    .unwrap();
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(checked_in.join("manifest.json")).unwrap()).unwrap();
    let mut pending_entry = entry.clone();
    pending_entry["scenario_file"] = "real-cli-failure.json".into();
    manifest["entries"]
        .as_array_mut()
        .unwrap()
        .push(pending_entry);
    std::fs::write(
        promoted_corpus.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    assert!(IdentityCorpus::load(&promoted_corpus).is_err());

    manifest["entries"][2]["reviewed"] = true.into();
    std::fs::write(
        promoted_corpus.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let reviewed = IdentityCorpus::load(&promoted_corpus).unwrap();
    let reports = reviewed.test().unwrap();
    assert_eq!(reports.len(), 3);
    assert!(reports.iter().any(|report| report.failure.is_some()));

    manifest["entries"][2]["seed"] = "11".repeat(32).into();
    std::fs::write(
        promoted_corpus.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    assert!(IdentityCorpus::load(&promoted_corpus).is_err());
}

fn copy_identity_failure_artifacts(source: &std::path::Path, target: &std::path::Path) {
    std::fs::create_dir(target).unwrap();
    for artifact in std::fs::read_dir(source).unwrap() {
        let artifact = artifact.unwrap();
        std::fs::copy(artifact.path(), target.join(artifact.file_name())).unwrap();
    }
}

fn reindex_identity_failure_artifact(root: &std::path::Path, name: &str) {
    let index_path = root.join("failure-artifacts.json");
    let mut index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&index_path).unwrap()).unwrap();
    let bytes = std::fs::read(root.join(name)).unwrap();
    index["files"][name] = blake3::hash(&bytes).to_hex().to_string().into();
    let mut index_bytes = serde_json::to_vec_pretty(&index).unwrap();
    index_bytes.push(b'\n');
    std::fs::write(index_path, index_bytes).unwrap();
}

fn assert_mutation(mutation: FormalMutation, expected: FormalProperty) {
    let violation = check_formal_mutation(mutation).unwrap_err();
    assert_eq!(violation.property, expected);
}

#[test]
fn formal_mutation_revoked_controller_authorizes_is_rejected() {
    assert_mutation(
        FormalMutation::RevokedControllerAuthorizes,
        FormalProperty::RevokedControllersCannotAuthorize,
    );
}

#[test]
fn formal_mutation_policy_authorizes_itself_is_rejected() {
    assert_mutation(
        FormalMutation::PolicyAuthorizesItself,
        FormalProperty::PolicyChangesUsePreviousPolicy,
    );
}

#[test]
fn formal_mutation_hidden_fork_is_rejected() {
    assert_mutation(
        FormalMutation::ForkIsHidden,
        FormalProperty::ForksAreDetectable,
    );
}

#[test]
fn formal_mutation_unsatisfied_threshold_is_rejected() {
    assert_mutation(
        FormalMutation::ThresholdBecomesUnsatisfied,
        FormalProperty::ThresholdRequirementsPreserved,
    );
}

#[test]
fn formal_mutation_recovery_retains_old_controller_is_rejected() {
    assert_mutation(
        FormalMutation::RecoveryRetainsOldController,
        FormalProperty::RecoveryDoesNotRetainOldControllers,
    );
}

#[test]
fn formal_mutation_nonunique_predecessor_is_rejected() {
    assert_mutation(
        FormalMutation::AcceptedEventHasTwoPredecessors,
        FormalProperty::AcceptedEventsHaveUniquePredecessor,
    );
}

#[test]
fn formal_regression_recovery_cannot_hide_an_unresolved_fork() {
    assert_mutation(
        FormalMutation::RecoveryHidesFork,
        FormalProperty::ForksAreDetectable,
    );
}
