use std::{
    fs,
    process::Command,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use iroh_sim::{
    ActionSchedule, ActionSpec, AllowedTerminal, CryptoMode, DeterminismGrade, IpFamily,
    NatFilteringBehavior, NatMappingBehavior, ObservationTrigger, PATCHBAY_RECEIPT_SCHEMA_VERSION,
    PatchbayReceipt, ReferencedSwarmSpec, RunManifest, SWARM_SCHEMA_VERSION, Scenario,
    ScenarioAction, ScenarioBuilder, ScenarioOperation, SwarmChoice, SwarmMutation, SwarmOption,
    SwarmSpec, TraceComparisonMode,
};

static NEXT: AtomicU64 = AtomicU64::new(1);
static CLI_RUN_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn cargo_sim_help_lists_the_stable_command_surface() {
    let output = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    for command in [
        "run", "campaign", "replay", "minimize", "corpus", "explain", "parity",
    ] {
        assert!(stdout.contains(command), "missing {command} in {stdout}");
    }
}

#[test]
fn parity_export_and_compare_are_canonical_immutable_and_fail_on_difference() {
    let _guard = CLI_RUN_LOCK.lock().unwrap();
    let root = temp_dir();
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let first = root.join("deterministic-a.json");
    let second = root.join("deterministic-b.json");
    for output in [&first, &second] {
        let export = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
            .current_dir(workspace)
            .args([
                "parity",
                "export",
                "public",
                "--seed",
                &"77".repeat(32),
                "--source-revision",
                "test-revision",
                "--observed-at-unix-secs",
                "1784671072",
                "--output",
            ])
            .arg(output)
            .output()
            .unwrap();
        assert!(
            export.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&export.stdout),
            String::from_utf8_lossy(&export.stderr)
        );
    }
    assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());

    let report = root.join("comparison.json");
    let comparison = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .args(["parity", "compare"])
        .arg(&first)
        .arg(&second)
        .arg("--output")
        .arg(&report)
        .output()
        .unwrap();
    assert!(comparison.status.success());
    assert!(
        String::from_utf8(comparison.stdout)
            .unwrap()
            .contains("\"match\"")
    );

    let overwrite = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .args([
            "parity",
            "export",
            "public",
            "--seed",
            &"77".repeat(32),
            "--source-revision",
            "test-revision",
            "--observed-at-unix-secs",
            "1784671072",
            "--output",
        ])
        .arg(&first)
        .output()
        .unwrap();
    assert!(!overwrite.status.success(), "fixture writes are immutable");

    let mut changed: serde_json::Value =
        serde_json::from_slice(&fs::read(&second).unwrap()).unwrap();
    changed["result"]["outcome"]["corrupt_deliveries"] = 1.into();
    fs::write(&second, serde_json::to_vec_pretty(&changed).unwrap()).unwrap();
    let difference = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .args(["parity", "compare"])
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert_eq!(difference.status.code(), Some(66));
    assert!(
        String::from_utf8(difference.stderr)
            .unwrap()
            .contains("delivery")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn patchbay_receipt_import_produces_fresh_comparable_evidence() {
    let _guard = CLI_RUN_LOCK.lock().unwrap();
    let root = temp_dir();
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let receipt = PatchbayReceipt {
        schema_version: PATCHBAY_RECEIPT_SCHEMA_VERSION,
        case_id: "parity/patchbay-public".into(),
        test_id: "patchbay/nat/nat_none_x_none".into(),
        authenticated_connections: 1,
        successful_exchanges: 1,
        corrupt_exchanges: 0,
        selected_paths: vec!["relay".into(), "direct_ipv4".into()],
    };
    let receipt_path = root.join("receipt.json");
    fs::write(&receipt_path, receipt.to_canonical_json().unwrap()).unwrap();
    let patchbay = root.join("patchbay.json");
    let imported = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .args(["parity", "import-patchbay"])
        .arg(&receipt_path)
        .args([
            "--source-revision",
            "test-revision",
            "--observed-at-unix-secs",
            "1784671072",
            "--output",
        ])
        .arg(&patchbay)
        .output()
        .unwrap();
    assert!(
        imported.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&imported.stdout),
        String::from_utf8_lossy(&imported.stderr)
    );

    let deterministic = root.join("deterministic.json");
    let exported = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .args(["parity", "export", "public"])
        .args([
            "--seed",
            &"77".repeat(32),
            "--source-revision",
            "test-revision",
            "--observed-at-unix-secs",
            "1784671072",
            "--output",
        ])
        .arg(&deterministic)
        .output()
        .unwrap();
    assert!(exported.status.success());
    let comparison = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .args(["parity", "compare"])
        .arg(&deterministic)
        .arg(&patchbay)
        .output()
        .unwrap();
    assert!(
        comparison.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&comparison.stdout),
        String::from_utf8_lossy(&comparison.stderr)
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn pre_manifest_usage_failures_do_not_print_replay_commands() {
    let output = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .args(["campaign", "scenario.json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(64));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains("cargo sim replay"));
}

#[test]
fn stage_two_run_writes_immutable_artifacts_and_replays_exactly() {
    let _guard = CLI_RUN_LOCK.lock().unwrap();
    let root = temp_dir();
    let run_dir = root.join("run");
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let scenario = workspace.join("iroh-sim/tests/fixtures/ipv4-stream.json");
    let output = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .arg("run")
        .arg(&scenario)
        .args(["--seed", &"11".repeat(32), "--artifacts"])
        .arg(&run_dir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for name in [
        "manifest.json",
        "trace.jsonl",
        "trace.raw.jsonl",
        "trace.chunk.00000000.jsonl",
        "trace.raw.chunk.00000000.jsonl",
    ] {
        assert!(run_dir.join(name).is_file(), "missing {name}");
    }
    let manifest =
        RunManifest::from_json(&fs::read(run_dir.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(
        manifest.determinism_grade,
        DeterminismGrade::FullyDeterministic
    );
    assert_eq!(manifest.crypto_mode, CryptoMode::DeterministicTest);
    assert_eq!(manifest.trace_comparison, TraceComparisonMode::Raw);
    assert!(manifest.backend.synthetic_ip);
    assert!(manifest.escapes.is_empty());
    assert_eq!(manifest.fidelity_exceptions, ["deterministic_test_crypto"]);

    let replay = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .arg("replay")
        .arg(run_dir.join("manifest.json"))
        .output()
        .unwrap();
    assert!(
        replay.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );
    assert!(
        String::from_utf8(replay.stdout)
            .unwrap()
            .contains("replay_ok")
    );

    let trace_path = run_dir.join("trace.raw.jsonl");
    let mut trace = fs::read(&trace_path).unwrap();
    assert_eq!(trace.pop(), Some(b'\n'));
    let first_missing_line = trace.iter().filter(|byte| **byte == b'\n').count() + 1;
    fs::write(&trace_path, trace).unwrap();
    let divergent = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .arg("replay")
        .arg(run_dir.join("manifest.json"))
        .output()
        .unwrap();
    assert_eq!(divergent.status.code(), Some(66));
    assert!(
        String::from_utf8(divergent.stderr)
            .unwrap()
            .contains(&format!("line={first_missing_line}"))
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn production_crypto_run_records_semantic_contract_and_replays() {
    let _guard = CLI_RUN_LOCK.lock().unwrap();
    let root = temp_dir();
    let run_dir = root.join("production-crypto");
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let scenario = workspace.join("iroh-sim/tests/fixtures/v2-ipv4-stream.json");
    let run = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .arg("run")
        .arg(&scenario)
        .args([
            "--seed",
            &"12".repeat(32),
            "--crypto",
            "production-provider",
            "--artifacts",
        ])
        .arg(&run_dir)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let manifest =
        RunManifest::from_json(&fs::read(run_dir.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(
        manifest.determinism_grade,
        DeterminismGrade::SemanticallyDeterministic
    );
    assert_eq!(manifest.crypto_mode, CryptoMode::ProductionProvider);
    assert_eq!(manifest.trace_comparison, TraceComparisonMode::Semantic);
    assert_eq!(manifest.escapes, ["production_crypto_entropy"]);
    assert!(manifest.fidelity_exceptions.is_empty());

    let replay = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .arg("replay")
        .arg(run_dir.join("manifest.json"))
        .output()
        .unwrap();
    assert!(
        replay.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn declarative_run_and_expected_failure_replay_through_the_same_cli() {
    let _guard = CLI_RUN_LOCK.lock().unwrap();
    let root = temp_dir();
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let fixture = workspace.join("iroh-sim/tests/fixtures/v2-ipv4-stream.json");

    let success_dir = root.join("success");
    let run = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .arg("run")
        .arg(&fixture)
        .args(["--seed", &"22".repeat(32), "--artifacts"])
        .arg(&success_dir)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(success_dir.join("scenario.json").is_file());
    assert!(success_dir.join("terminal-report.json").is_file());
    let replay = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .arg("replay")
        .arg(success_dir.join("manifest.json"))
        .output()
        .unwrap();
    assert!(
        replay.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );

    let mut failing = Scenario::from_json(&fs::read(&fixture).unwrap()).unwrap();
    failing.metadata.id = "cli/expected-trigger-stall".to_owned();
    failing
        .allowed_terminals
        .push(AllowedTerminal::ExpectedFailure);
    failing.actions.push(ActionSpec {
        id: "99-never".to_owned(),
        schedule: ActionSchedule::AfterObservation {
            observation: ObservationTrigger::EndpointState {
                endpoint: "client".to_owned(),
                state: "failed".to_owned(),
            },
        },
        action: ScenarioAction::ExpectFailure {
            class: "trigger_stall".to_owned(),
        },
    });
    let failing_path = root.join("failing.json");
    fs::write(&failing_path, failing.to_canonical_json().unwrap()).unwrap();
    let failure_dir = root.join("failure");
    let run = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .arg("run")
        .arg(&failing_path)
        .args(["--seed", &"23".repeat(32), "--artifacts"])
        .arg(&failure_dir)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let stdout = String::from_utf8(run.stdout).unwrap();
    assert!(stdout.contains("status=expected_failure"));
    assert_eq!(stdout.matches("cargo sim replay").count(), 1);
    for name in [
        "failure-signature.json",
        "failure-artifacts.json",
        "decision-prefix.jsonl",
        "scenario-inventory.json",
    ] {
        assert!(failure_dir.join(name).is_file(), "missing {name}");
    }
    let replay = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .arg("replay")
        .arg(failure_dir.join("manifest.json"))
        .output()
        .unwrap();
    assert!(
        replay.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );
    assert!(
        String::from_utf8(replay.stdout)
            .unwrap()
            .contains("expected_failure")
    );
    let explained = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .arg("explain")
        .arg(failure_dir.join("manifest.json"))
        .output()
        .unwrap();
    assert!(
        explained.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&explained.stdout),
        String::from_utf8_lossy(&explained.stderr)
    );
    let explanation = String::from_utf8(explained.stdout).unwrap();
    assert!(explanation.contains("causal_trace_suffix"));
    assert!(explanation.contains("minimize_command"));
    assert!(explanation.contains("scenario_inventory"));

    let minimize_dir = root.join("minimize");
    let minimized = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .arg("minimize")
        .arg(failure_dir.join("manifest.json"))
        .arg("--output")
        .arg(&minimize_dir)
        .args(["--max-attempts", "200"])
        .output()
        .unwrap();
    assert!(
        minimized.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&minimized.stdout),
        String::from_utf8_lossy(&minimized.stderr)
    );
    assert!(minimize_dir.join("best.scenario.json").is_file());
    assert!(minimize_dir.join("minimize.jsonl").is_file());
    assert!(minimize_dir.join("minimize-result.json").is_file());
    let best = fs::read(minimize_dir.join("best.scenario.json")).unwrap();
    assert!(best.len() < fs::read(failure_dir.join("scenario.json")).unwrap().len());

    let mut minimized_replays = Vec::new();
    for label in ["minimized-replay-a", "minimized-replay-b"] {
        let artifacts = root.join(label);
        let replay = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
            .current_dir(workspace)
            .arg("run")
            .arg(minimize_dir.join("best.scenario.json"))
            .args(["--seed", &"23".repeat(32), "--artifacts"])
            .arg(&artifacts)
            .output()
            .unwrap();
        assert!(
            replay.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&replay.stdout),
            String::from_utf8_lossy(&replay.stderr)
        );
        minimized_replays.push((
            fs::read(artifacts.join("decision-prefix.jsonl")).unwrap(),
            fs::read(artifacts.join("scheduler-snapshot.json")).unwrap(),
            fs::read(artifacts.join("failure-signature.json")).unwrap(),
        ));
    }
    assert_eq!(minimized_replays[0], minimized_replays[1]);
    assert!(!minimized_replays[0].0.is_empty());
    assert_eq!(
        minimized_replays[0].2,
        fs::read(failure_dir.join("failure-signature.json")).unwrap()
    );

    let resumed = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .arg("minimize")
        .arg(failure_dir.join("manifest.json"))
        .arg("--output")
        .arg(&minimize_dir)
        .args(["--resume", "--max-attempts", "200"])
        .output()
        .unwrap();
    assert!(
        resumed.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&resumed.stdout),
        String::from_utf8_lossy(&resumed.stderr)
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn corpus_and_parallel_campaign_collect_all_expected_failure_artifacts() {
    let _guard = CLI_RUN_LOCK.lock().unwrap();
    let root = temp_dir();
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let corpus_root = workspace.join("iroh-sim/corpus");
    let corpus = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .arg("corpus")
        .arg("test")
        .arg(&corpus_root)
        .output()
        .unwrap();
    assert!(
        corpus.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&corpus.stdout),
        String::from_utf8_lossy(&corpus.stderr)
    );
    assert!(
        String::from_utf8(corpus.stdout)
            .unwrap()
            .contains("corpus_ok")
    );

    let campaign_root = root.join("campaign");
    let scenario = corpus_root.join("stage3-trigger-stall/scenario.json");
    let campaign = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .arg("campaign")
        .arg(scenario)
        .args(["--seeds", "4..8", "--jobs", "2", "--artifacts"])
        .arg(&campaign_root)
        .arg("--continue-on-failure")
        .output()
        .unwrap();
    assert_eq!(campaign.status.code(), Some(74));
    assert!(
        String::from_utf8_lossy(&campaign.stderr).contains("campaign contained 4 failed runs"),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&campaign.stdout),
        String::from_utf8_lossy(&campaign.stderr)
    );
    assert!(campaign_root.join("campaign-summary.json").is_file());
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(campaign_root.join("campaign-summary.json")).unwrap())
            .unwrap();
    assert!(summary.get("template_inventory").is_some());
    assert_eq!(
        fs::read_dir(&campaign_root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().unwrap().is_dir())
            .count(),
        4
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn swarm_campaign_records_selections_and_surfaces_seeded_zero_time_livelock() {
    let _guard = CLI_RUN_LOCK.lock().unwrap();
    let root = temp_dir();
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let mut base =
        ScenarioBuilder::direct_ip_echo("swarm/cli", IpFamily::Ipv4, ScenarioOperation::Stream)
            .unwrap()
            .build()
            .unwrap();
    base.budgets.max_events = 1_024;
    base.budgets.max_trace_events = 4_096;
    for invariant in &mut base.invariants {
        if invariant.max_events.is_some() {
            invariant.max_events = Some(base.budgets.max_events);
        }
    }
    let swarm = SwarmSpec {
        schema_version: SWARM_SCHEMA_VERSION,
        id: "cli-smoke".into(),
        base,
        safety_liveness: None,
        choices: vec![SwarmChoice {
            id: "latency".into(),
            options: vec![
                SwarmOption {
                    id: "fast".into(),
                    weight: 1,
                    mutation: SwarmMutation::LinkLatencyNanos {
                        link: "lan".into(),
                        nanos: 1_000,
                    },
                },
                SwarmOption {
                    id: "slow".into(),
                    weight: 1,
                    mutation: SwarmMutation::LinkLatencyNanos {
                        link: "lan".into(),
                        nanos: 2_000_000,
                    },
                },
            ],
        }],
    };
    let swarm_path = root.join("swarm.json");
    fs::write(&swarm_path, swarm.to_canonical_json().unwrap()).unwrap();
    let campaign_root = root.join("campaign");
    let output = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .arg("campaign")
        .args(["--swarm"])
        .arg(&swarm_path)
        .args(["--seeds", "0..2", "--jobs", "2", "--artifacts"])
        .arg(&campaign_root)
        .arg("--continue-on-failure")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(74));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("campaign contained 1 failed runs"),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(campaign_root.join("swarm.json").is_file());
    for ordinal in 0..2 {
        let run = campaign_root.join(format!("seed-{ordinal:020}"));
        assert!(run.join("swarm-selection.json").is_file());
        assert!(run.join("scenario.json").is_file());
    }
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(campaign_root.join("campaign-summary.json")).unwrap())
            .unwrap();
    assert_eq!(summary["results"][0]["terminal"]["terminal"], "failure");
    assert_eq!(
        summary["results"][0]["terminal"]["terminal_class"],
        "cleanup"
    );
    assert_eq!(summary["results"][1]["terminal"]["terminal"], "success");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn referenced_swarm_campaign_resolves_workspace_base_and_records_source_identity() {
    let _guard = CLI_RUN_LOCK.lock().unwrap();
    let root = temp_dir();
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let base_path = "iroh-sim/corpus/stage4-nat-rebind-expiry/scenario.json";
    let base_bytes = fs::read(workspace.join(base_path)).unwrap();
    let template = ReferencedSwarmSpec {
        schema_version: SWARM_SCHEMA_VERSION,
        id: "cli-referenced".into(),
        base_path: base_path.into(),
        base_blake3: blake3::hash(&base_bytes).to_hex().to_string(),
        safety_liveness: None,
        choices: vec![SwarmChoice {
            id: "nat".into(),
            options: vec![SwarmOption {
                id: "endpoint-independent".into(),
                weight: 1,
                mutation: SwarmMutation::NatBehavior {
                    nat: "edge".into(),
                    mapping: NatMappingBehavior::EndpointIndependent,
                    filtering: NatFilteringBehavior::EndpointIndependent,
                },
            }],
        }],
    };
    let template_path = root.join("template.json");
    fs::write(&template_path, template.to_canonical_json().unwrap()).unwrap();
    let campaign_root = root.join("campaign");
    let output = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .arg("campaign")
        .args(["--swarm"])
        .arg(&template_path)
        .args(["--seeds", "0..1", "--jobs", "1", "--artifacts"])
        .arg(&campaign_root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(campaign_root.join("swarm-template.json").is_file());
    assert!(campaign_root.join("swarm-template.blake3").is_file());
    assert!(campaign_root.join("swarm.json").is_file());
    assert!(
        campaign_root
            .join("seed-00000000000000000000/scenario.json")
            .is_file()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn campaign_supports_and_records_the_production_crypto_soak_lane() {
    let _guard = CLI_RUN_LOCK.lock().unwrap();
    let root = temp_dir();
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let campaign_root = root.join("campaign");
    let output = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .arg("campaign")
        .arg("iroh-sim/corpus/stage6-rare-ready-order/scenario.json")
        .args([
            "--seeds",
            "0..1",
            "--jobs",
            "1",
            "--crypto",
            "production-provider",
            "--artifacts",
        ])
        .arg(&campaign_root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(campaign_root.join("crypto-mode.txt")).unwrap(),
        "production_provider\n"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn campaign_collects_artifacts_but_exits_nonzero_when_product_failures_exist() {
    let _guard = CLI_RUN_LOCK.lock().unwrap();
    let root = temp_dir();
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let mut scenario = ScenarioBuilder::direct_ip_echo(
        "campaign/failure",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap()
    .build()
    .unwrap();
    scenario
        .actions
        .iter_mut()
        .find(|action| action.id == "03-connect")
        .unwrap()
        .schedule = ActionSchedule::At { nanos: 1_000 };
    let scenario_path = root.join("scenario.json");
    fs::write(&scenario_path, scenario.to_canonical_json().unwrap()).unwrap();
    let campaign_root = root.join("campaign");
    let output = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .arg("campaign")
        .arg(&scenario_path)
        .args([
            "--seeds",
            "0..2",
            "--jobs",
            "2",
            "--continue-on-failure",
            "--artifacts",
        ])
        .arg(&campaign_root)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(74));
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(campaign_root.join("campaign-summary.json")).unwrap())
            .unwrap();
    assert!(!summary["unique_failures"].as_array().unwrap().is_empty());
    assert!(
        campaign_root
            .join("seed-00000000000000000000/failure-signature.json")
            .is_file()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn default_in_worktree_artifacts_do_not_change_replay_source_identity() {
    let _guard = CLI_RUN_LOCK.lock().unwrap();
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let scenario = workspace.join("iroh-sim/tests/fixtures/ipv4-stream.json");
    let ordinal = NEXT.fetch_add(1, Ordering::Relaxed);
    let seed_prefix = format!("{:08x}{:08x}", std::process::id(), ordinal);
    let seed = seed_prefix.repeat(4);
    let run_dir = workspace
        .join("artifacts")
        .join(format!("direct-ip-ipv4-stream-{seed_prefix}"));
    assert!(!run_dir.exists(), "test artifact path unexpectedly exists");

    let run = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .arg("run")
        .arg(&scenario)
        .args(["--seed", &seed])
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let replay = Command::new(env!("CARGO_BIN_EXE_cargo-sim"))
        .current_dir(workspace)
        .arg("replay")
        .arg(run_dir.join("manifest.json"))
        .output()
        .unwrap();
    fs::remove_dir_all(&run_dir).unwrap();
    assert!(
        replay.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );
}

fn temp_dir() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "iroh-sim-cli-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    path
}
