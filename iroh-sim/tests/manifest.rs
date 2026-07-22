use std::collections::BTreeMap;

use iroh_sim::{
    BackendCapabilities, CryptoMode, DeterminismGrade, MANIFEST_SCHEMA_VERSION, RunBudgets,
    RunManifest, SIMULATOR_VERSION, SourceIdentity, TraceComparisonMode,
};

#[test]
fn manifest_round_trips_canonically_and_rejects_unknown_fields() {
    let manifest = fixture();
    let encoded = manifest.to_canonical_json().unwrap();
    assert_eq!(RunManifest::from_json(&encoded).unwrap(), manifest);
    assert_eq!(manifest.to_canonical_json().unwrap(), encoded);

    let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    value["unknown"] = serde_json::json!(true);
    assert!(RunManifest::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn compatibility_is_explicit_and_fail_closed() {
    let manifest = fixture();
    manifest
        .check_compatible(&manifest.replay_identity())
        .unwrap();

    let mut incompatible = manifest.replay_identity();
    incompatible.source.revision = "other-revision".to_owned();
    let error = manifest.check_compatible(&incompatible).unwrap_err();
    assert!(error.to_string().contains("source revision"));
}

#[test]
fn manifest_rejects_host_paths_and_malformed_seed() {
    let mut manifest = fixture();
    manifest.escapes.push("/home/alice/private".to_owned());
    assert!(manifest.validate().is_err());

    let mut value: serde_json::Value =
        serde_json::from_slice(&fixture().to_canonical_json().unwrap()).unwrap();
    value["root_seed"] = serde_json::json!("1234");
    assert!(RunManifest::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn manifest_enforces_crypto_grade_and_trace_comparison_matrix() {
    let deterministic = fixture();
    deterministic.validate().unwrap();

    let mut semantic = fixture();
    semantic.crypto_mode = CryptoMode::ProductionProvider;
    semantic.trace_comparison = TraceComparisonMode::Semantic;
    semantic.fidelity_exceptions.clear();
    semantic.determinism_grade = DeterminismGrade::SemanticallyDeterministic;
    semantic.escapes = vec!["production_crypto_entropy".to_owned()];
    semantic.validate().unwrap();

    let mut wrong_comparison = deterministic.clone();
    wrong_comparison.trace_comparison = TraceComparisonMode::Semantic;
    assert!(wrong_comparison.validate().is_err());

    let mut extra_escape = semantic.clone();
    extra_escape.escapes.push("scheduler".to_owned());
    assert!(extra_escape.validate().is_err());

    let mut legacy_grade = semantic;
    legacy_grade.determinism_grade = DeterminismGrade::ControlledRuntime;
    assert!(legacy_grade.validate().is_err());
}

fn fixture() -> RunManifest {
    RunManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        simulator_version: SIMULATOR_VERSION.to_owned(),
        source: SourceIdentity {
            revision: "f2eb930dda".to_owned(),
            dirty_digest: Some("abcd".repeat(16)),
        },
        root_seed: "11".repeat(32),
        scenario_id: "connect/basic".to_owned(),
        scenario_hash: "22".repeat(32),
        normalized_config: BTreeMap::from([("transport".to_owned(), "synthetic-ip".to_owned())]),
        features: vec!["ipv4".to_owned(), "ipv6".to_owned()],
        wall_clock_epoch_secs: 1_700_000_000,
        backend: BackendCapabilities::deterministic_kernel(),
        budgets: RunBudgets {
            max_events: 10_000,
            max_virtual_time_nanos: 60_000_000_000,
            max_tasks: 1_000,
            max_packets: 100_000,
        },
        scheduling_profile: "fifo".to_owned(),
        fault_profile: "none".to_owned(),
        lockfile_digest: "33".repeat(32),
        crypto_mode: CryptoMode::DeterministicTest,
        trace_comparison: TraceComparisonMode::Raw,
        fidelity_exceptions: vec!["deterministic_test_crypto".to_owned()],
        determinism_grade: DeterminismGrade::FullyDeterministic,
        escapes: vec![],
        unsafe_test_only: true,
    }
}
