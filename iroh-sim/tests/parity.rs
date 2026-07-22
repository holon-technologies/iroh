use std::{collections::BTreeMap, sync::Arc, time::SystemTime};

use iroh_runtime::RootSeed;
use iroh_sim::{
    CanonicalParityCase, PARITY_FIXTURE_SCHEMA_VERSION, PATCHBAY_RECEIPT_SCHEMA_VERSION,
    ParityBackend, ParityComparisonStatus, ParityEvidence, ParityFixture, ParityFixtureResult,
    PatchbayReceipt, Scenario, ScenarioRunner, SemanticDimension, SemanticOutcome,
    SemanticTerminal, TraceBuffer, canonical_patchbay_scenarios, compare_parity_fixtures,
    compare_parity_fixtures_at, compare_semantic_outcomes, deterministic_semantic_outcome,
};

#[test]
fn patchbay_fixture_import_is_strict_canonical_and_reports_capability_skips() {
    let fixture =
        ParityFixture::from_json(include_bytes!("fixtures/patchbay-public.json")).unwrap();
    assert_eq!(fixture.backend, ParityBackend::Patchbay);
    assert_eq!(
        fixture.to_canonical_json().unwrap(),
        include_bytes!("fixtures/patchbay-public.json")
    );

    let skipped = ParityFixture {
        schema_version: PARITY_FIXTURE_SCHEMA_VERSION,
        case_id: "patchbay/symmetric-x-symmetric".to_owned(),
        backend: ParityBackend::Deterministic,
        source_revision: "stage-4".to_owned(),
        evidence: evidence("stage-4"),
        capabilities: vec![SemanticDimension::Terminal],
        observed_dimensions: vec![SemanticDimension::Terminal],
        result: ParityFixtureResult::Skipped {
            missing_capabilities: vec![SemanticDimension::Path],
            reason: "production relay and path selection become deterministic in Stage 5"
                .to_owned(),
        },
    };
    skipped.validate().unwrap();

    let production_local_skip = ParityFixture {
        schema_version: PARITY_FIXTURE_SCHEMA_VERSION,
        case_id: "relay/kernel-routing".to_owned(),
        backend: ParityBackend::ProductionLocal,
        source_revision: "stage-5".to_owned(),
        evidence: evidence("stage-5"),
        capabilities: vec![
            SemanticDimension::Terminal,
            SemanticDimension::Authentication,
            SemanticDimension::Delivery,
            SemanticDimension::Relay,
            SemanticDimension::Path,
        ],
        observed_dimensions: vec![
            SemanticDimension::Terminal,
            SemanticDimension::Authentication,
            SemanticDimension::Delivery,
            SemanticDimension::Relay,
            SemanticDimension::Path,
        ],
        result: ParityFixtureResult::Skipped {
            missing_capabilities: vec![SemanticDimension::Nat],
            reason: "the production-local relay fixture has no synthetic NAT boundary".to_owned(),
        },
    };
    production_local_skip.validate().unwrap();

    let mut invalid = skipped.clone();
    invalid.capabilities = vec![SemanticDimension::Path, SemanticDimension::Terminal];
    assert!(invalid.validate().is_err(), "lists must be sorted");
    let mut invalid = skipped;
    invalid.capabilities.push(SemanticDimension::Path);
    assert!(
        invalid.validate().is_err(),
        "missing cannot also be supported"
    );
}

#[test]
fn canonical_catalog_covers_representative_patchbay_behavior_classes() {
    let catalog = canonical_patchbay_scenarios().unwrap();
    assert_eq!(catalog.len(), 8);
    assert_eq!(catalog[0].case, CanonicalParityCase::Public);
    assert_eq!(catalog[7].case, CanonicalParityCase::SwitchUplink);
    assert!(catalog.iter().all(|entry| {
        entry.scenario.validate().is_ok()
            && !entry.patchbay_tests.is_empty()
            && (entry.deferred_dimensions == [SemanticDimension::Path]
                || entry.case == CanonicalParityCase::DoubleNat)
    }));
}

#[test]
fn patchbay_receipt_import_is_strict_fresh_and_bound_to_real_observations() {
    let receipt = PatchbayReceipt {
        schema_version: PATCHBAY_RECEIPT_SCHEMA_VERSION,
        case_id: "parity/patchbay-public".into(),
        test_id: "patchbay/nat/nat_none_x_none".into(),
        authenticated_connections: 1,
        successful_exchanges: 1,
        corrupt_exchanges: 0,
        selected_paths: vec!["relay".into(), "direct_ipv4".into()],
    };
    let bytes = receipt.to_canonical_json().unwrap();
    assert_eq!(PatchbayReceipt::from_json(&bytes).unwrap(), receipt);
    let fixture = receipt
        .to_fixture("revision-123", "11".repeat(32), 1_000_000)
        .unwrap();
    assert_eq!(fixture.backend, ParityBackend::Patchbay);
    assert_eq!(
        fixture.capabilities,
        [
            SemanticDimension::Terminal,
            SemanticDimension::Authentication,
            SemanticDimension::Delivery,
            SemanticDimension::Path,
        ]
    );
    assert_eq!(fixture.evidence.run_id.len(), 64);
    assert!(matches!(
        fixture.result,
        ParityFixtureResult::Completed {
            outcome: SemanticOutcome {
                authenticated_connections: 1,
                intact_deliveries: 1,
                corrupt_deliveries: 0,
                ..
            }
        }
    ));

    let mut unknown: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    unknown["ambient_host"] = "/tmp/runner".into();
    assert!(PatchbayReceipt::from_json(&serde_json::to_vec(&unknown).unwrap()).is_err());
    let mut invalid = receipt;
    invalid.authenticated_connections = 0;
    assert!(invalid.validate().is_err());
}

#[test]
fn delivery_parity_compares_success_and_integrity_not_backend_specific_event_counts() {
    let deterministic = SemanticOutcome::successful(1, 2);
    let patchbay = SemanticOutcome::successful(1, 1);
    let comparison =
        compare_semantic_outcomes(&deterministic, &patchbay, &[SemanticDimension::Delivery])
            .unwrap();
    assert_eq!(comparison.status, ParityComparisonStatus::Match);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn canonical_deterministic_parity_scenarios_execute_real_quic() {
    for (ordinal, entry) in canonical_patchbay_scenarios()
        .unwrap()
        .into_iter()
        .enumerate()
    {
        let trace = Arc::new(TraceBuffer::default());
        let report = ScenarioRunner::deterministic(
            entry.scenario,
            RootSeed::new([u8::try_from(90 + ordinal).unwrap(); 32]),
            SystemTime::UNIX_EPOCH,
            trace.clone(),
        )
        .unwrap()
        .run()
        .await
        .unwrap_or_else(|error| panic!("{:?} failed: {error}", entry.case));
        let outcome = deterministic_semantic_outcome(&report, &trace.events());
        assert_eq!(outcome.terminal, SemanticTerminal::Success);
        assert_eq!(outcome.authenticated_connections, 1);
        assert!(outcome.intact_deliveries >= 2);
        assert_eq!(outcome.corrupt_deliveries, 0);
    }
}

#[test]
fn comparison_uses_selected_semantics_and_ignores_packet_timing_by_construction() {
    let patchbay = SemanticOutcome {
        terminal: SemanticTerminal::Success,
        authenticated_connections: 1,
        intact_deliveries: 2,
        corrupt_deliveries: 0,
        nat_transitions: BTreeMap::new(),
        firewall_decisions: BTreeMap::new(),
        mobility_transitions: BTreeMap::new(),
        relay_transitions: BTreeMap::new(),
        selected_paths: vec!["relay".to_owned(), "direct_ipv4".to_owned()],
    };
    let mut deterministic = patchbay.clone();
    deterministic.selected_paths.clear();

    let common = compare_semantic_outcomes(
        &patchbay,
        &deterministic,
        &[
            SemanticDimension::Terminal,
            SemanticDimension::Authentication,
            SemanticDimension::Delivery,
        ],
    )
    .unwrap();
    assert_eq!(common.status, ParityComparisonStatus::Match);

    let path =
        compare_semantic_outcomes(&patchbay, &deterministic, &[SemanticDimension::Path]).unwrap();
    assert_eq!(path.status, ParityComparisonStatus::Difference);
    assert_eq!(path.differences, ["path"]);
}

#[test]
fn fixture_comparison_is_case_scoped_capability_intersected_and_skip_safe() {
    let outcome = SemanticOutcome::successful(1, 2);
    let fixture = |backend, capabilities: Vec<SemanticDimension>, result| ParityFixture {
        schema_version: PARITY_FIXTURE_SCHEMA_VERSION,
        case_id: "parity/public".to_owned(),
        backend,
        source_revision: "fixture-revision".to_owned(),
        evidence: evidence("fixture-revision"),
        observed_dimensions: capabilities.clone(),
        capabilities,
        result,
    };
    let deterministic = fixture(
        ParityBackend::Deterministic,
        vec![
            SemanticDimension::Terminal,
            SemanticDimension::Authentication,
            SemanticDimension::Delivery,
            SemanticDimension::Path,
        ],
        ParityFixtureResult::Completed {
            outcome: outcome.clone(),
        },
    );
    let patchbay = fixture(
        ParityBackend::Patchbay,
        vec![
            SemanticDimension::Terminal,
            SemanticDimension::Authentication,
            SemanticDimension::Delivery,
        ],
        ParityFixtureResult::Completed { outcome },
    );
    let comparison = compare_parity_fixtures(&deterministic, &patchbay).unwrap();
    assert_eq!(comparison.status, ParityComparisonStatus::Match);
    assert_eq!(
        comparison.compared,
        [
            SemanticDimension::Terminal,
            SemanticDimension::Authentication,
            SemanticDimension::Delivery
        ]
    );

    let skipped = fixture(
        ParityBackend::Patchbay,
        vec![SemanticDimension::Terminal],
        ParityFixtureResult::Skipped {
            missing_capabilities: vec![SemanticDimension::Path],
            reason: "runner has no path observer".to_owned(),
        },
    );
    assert_eq!(
        compare_parity_fixtures(&deterministic, &skipped)
            .unwrap()
            .status,
        ParityComparisonStatus::Skipped
    );

    let mut wrong_scenario = patchbay.clone();
    wrong_scenario.evidence.scenario_hash = "ff".repeat(32);
    assert!(compare_parity_fixtures(&deterministic, &wrong_scenario).is_err());
    let mut wrong_case = patchbay;
    wrong_case.case_id = "parity/other".to_owned();
    assert!(compare_parity_fixtures(&deterministic, &wrong_case).is_err());
}

#[test]
fn evidence_freshness_false_capabilities_and_skip_regressions_fail_closed() {
    let fixture = ParityFixture {
        schema_version: PARITY_FIXTURE_SCHEMA_VERSION,
        case_id: "parity/freshness".into(),
        backend: ParityBackend::Patchbay,
        source_revision: "revision".into(),
        evidence: evidence("freshness"),
        capabilities: vec![SemanticDimension::Terminal],
        observed_dimensions: vec![SemanticDimension::Terminal],
        result: ParityFixtureResult::Completed {
            outcome: SemanticOutcome::successful(1, 1),
        },
    };
    assert!(compare_parity_fixtures_at(&fixture, &fixture, 1_000_100).is_ok());
    assert!(compare_parity_fixtures_at(&fixture, &fixture, 1_100_000).is_err());
    let mut false_capability = fixture.clone();
    false_capability.capabilities.push(SemanticDimension::Path);
    assert!(false_capability.validate().is_err());
    let mut skipped = fixture.clone();
    skipped.result = ParityFixtureResult::Skipped {
        missing_capabilities: vec![SemanticDimension::Path],
        reason: "backend does not expose path evidence".into(),
    };
    assert_eq!(
        compare_parity_fixtures(&fixture, &skipped).unwrap().status,
        ParityComparisonStatus::Skipped
    );
}

fn evidence(label: &str) -> ParityEvidence {
    let digest = blake3::hash(label.as_bytes()).to_hex().to_string();
    ParityEvidence {
        run_id: digest.clone(),
        scenario_hash: digest,
        observed_at_unix_secs: 1_000_000,
        valid_for_secs: 86_400,
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn deterministic_report_projects_authenticated_delivery_semantics() {
    let scenario = Scenario::from_json(include_bytes!("fixtures/v2-ipv4-stream.json")).unwrap();
    let trace = Arc::new(TraceBuffer::default());
    let report = ScenarioRunner::deterministic(
        scenario,
        RootSeed::new([77; 32]),
        SystemTime::UNIX_EPOCH,
        trace.clone(),
    )
    .unwrap()
    .run()
    .await
    .unwrap();
    let outcome = deterministic_semantic_outcome(&report, &trace.events());
    assert_eq!(outcome.terminal, SemanticTerminal::Success);
    assert_eq!(outcome.authenticated_connections, 1);
    assert_eq!(outcome.intact_deliveries, 2);
    assert_eq!(outcome.corrupt_deliveries, 0);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn relay_restart_projects_backend_neutral_lifecycle_and_path_semantics() {
    let scenario = Scenario::from_json(include_bytes!(
        "../corpus/stage5-relay-restart/scenario.json"
    ))
    .unwrap();
    let trace = Arc::new(TraceBuffer::default());
    let report = ScenarioRunner::deterministic(
        scenario,
        RootSeed::new([78; 32]),
        SystemTime::UNIX_EPOCH,
        trace.clone(),
    )
    .unwrap()
    .run()
    .await
    .unwrap();
    let outcome = deterministic_semantic_outcome(&report, &trace.events());
    assert_eq!(outcome.terminal, SemanticTerminal::Success);
    assert_eq!(outcome.relay_transitions.get("relay/offline"), Some(&1));
    assert_eq!(outcome.relay_transitions.get("relay/online"), Some(&1));
    assert_eq!(outcome.selected_paths, ["relay"]);
    assert_eq!(outcome.corrupt_deliveries, 0);
}
