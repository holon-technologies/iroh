use std::{collections::BTreeMap, fs};

use iroh_runtime::{TraceContext, TraceEvent, TraceEventKind, TraceSequence};
use iroh_sim::{
    ArtifactStore, FailureArtifactBundle, FailureReplayError, FailureSignature, InvariantClass,
    InvariantFailure, InvariantName, InvariantSnapshot, ResourceLedgerSnapshot, RunnerError,
    Scenario, compare_failure_replay, verify_failure_artifacts,
};

#[test]
fn failure_signature_is_typed_normalized_and_bounded() {
    let trace = trace(8);
    let error = invariant_error(vec!["server".to_owned(), "connection-1".to_owned()]);
    let reordered = invariant_error(vec!["connection-1".to_owned(), "server".to_owned()]);

    let first = FailureSignature::from_runner_error(&error, &trace, 3).unwrap();
    let second = FailureSignature::from_runner_error(&reordered, &trace, 3).unwrap();

    assert_eq!(first, second);
    assert_eq!(first.terminal_class.as_str(), "invariant/safety");
    assert_eq!(first.invariant, Some(InvariantName::DeliveryIntegrity));
    assert_eq!(first.entities, ["connection-1", "server"]);
    assert_eq!(first.causal_event_count, 3);
    assert_eq!(first.causal_suffix_digest.len(), 64);
}

#[test]
fn replay_compares_signature_before_the_full_trace() {
    let expected_trace = trace(4);
    let actual_trace = trace(5);
    let error = invariant_error(vec!["connection-1".to_owned()]);
    let expected = FailureSignature::from_runner_error(&error, &expected_trace, 2).unwrap();

    let different = FailureSignature::from_runner_error(
        &RunnerError::TriggerStall(vec!["never".to_owned()]),
        &actual_trace,
        2,
    )
    .unwrap();
    assert!(matches!(
        compare_failure_replay(&expected, Some(&different), &expected_trace, &actual_trace),
        Err(FailureReplayError::DifferentFailure { .. })
    ));
    assert!(matches!(
        compare_failure_replay(&expected, None, &expected_trace, &actual_trace),
        Err(FailureReplayError::FailureDisappeared)
    ));

    let actual = FailureSignature::from_runner_error(&error, &actual_trace, 2).unwrap();
    assert!(matches!(
        compare_failure_replay(&actual, Some(&actual), &expected_trace, &actual_trace),
        Err(FailureReplayError::TraceDivergence { .. })
    ));
}

#[test]
fn failure_bundle_is_immutable_and_detects_missing_or_truncated_chunks() {
    let root = temp_dir("bundle");
    let store = ArtifactStore::new(&root).unwrap();
    let scenario = Scenario::from_json(include_bytes!("fixtures/v2-ipv4-stream.json")).unwrap();
    let trace = trace(7);
    let error = invariant_error(vec!["connection-1".to_owned()]);
    let signature = FailureSignature::from_runner_error(&error, &trace, 4).unwrap();
    let bundle = FailureArtifactBundle {
        scenario: &scenario,
        error: &error,
        signature: &signature,
        invariants: &InvariantSnapshot::default(),
        resources: &ResourceLedgerSnapshot::default(),
        model: None,
        observations: None,
        virtual_time_nanos: None,
        scheduler: None,
        tasks: None,
        trace: &trace,
        events_per_chunk: 3,
    };

    let index = bundle.write(&store).unwrap();
    for name in [
        "scenario.json",
        "terminal-report.json",
        "invariant-snapshot.json",
        "failure-signature.json",
        "resource-snapshot.json",
        "scheduler-snapshot.json",
        "task-ownership.json",
        "scenario-inventory.json",
        "decision-prefix.jsonl",
        "trace.jsonl",
        "trace.raw.jsonl",
        "trace.chunk.00000000.jsonl",
        "trace.chunk.00000001.jsonl",
        "trace.chunk.00000002.jsonl",
        "failure-artifacts.json",
    ] {
        assert!(root.join(name).is_file(), "missing {name}");
    }
    assert_eq!(verify_failure_artifacts(&root).unwrap(), index);

    fs::remove_file(root.join("trace.chunk.00000001.jsonl")).unwrap();
    assert!(matches!(
        verify_failure_artifacts(&root),
        Err(FailureReplayError::MissingChunk { ordinal: 1 })
    ));
    fs::remove_dir_all(root).unwrap();

    let root = temp_dir("truncated");
    let store = ArtifactStore::new(&root).unwrap();
    bundle.write(&store).unwrap();
    let chunk = root.join("trace.chunk.00000002.jsonl");
    let mut bytes = fs::read(&chunk).unwrap();
    bytes.pop();
    fs::write(&chunk, bytes).unwrap();
    assert!(matches!(
        verify_failure_artifacts(&root),
        Err(FailureReplayError::TruncatedChunk { ordinal: 2 })
    ));
    fs::remove_dir_all(root).unwrap();
}

fn invariant_error(entities: Vec<String>) -> RunnerError {
    RunnerError::Invariant(InvariantFailure {
        name: InvariantName::DeliveryIntegrity,
        class: InvariantClass::Safety,
        observation_sequence: 17,
        virtual_time_nanos: 42,
        entities,
        evidence: BTreeMap::from([("corruption".to_owned(), "true".to_owned())]),
    })
}

fn trace(count: u64) -> Vec<TraceEvent> {
    (1..=count)
        .map(|sequence| {
            let event = TraceEvent::new(
                TraceSequence::new(sequence).unwrap(),
                sequence * 10,
                TraceContext::default(),
                TraceEventKind::StateTransition {
                    component: "fixture".to_owned(),
                    from: (sequence - 1).to_string(),
                    to: sequence.to_string(),
                },
            );
            if sequence > 1 {
                event.with_causal_parent(TraceSequence::new(sequence - 1).unwrap())
            } else {
                event
            }
        })
        .collect()
}

fn temp_dir(label: &str) -> std::path::PathBuf {
    let path =
        std::env::temp_dir().join(format!("iroh-sim-failure-{label}-{}", std::process::id()));
    if path.exists() {
        fs::remove_dir_all(&path).unwrap();
    }
    fs::create_dir(&path).unwrap();
    path
}
