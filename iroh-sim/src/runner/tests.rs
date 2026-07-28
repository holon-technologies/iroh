use super::*;
use crate::{
    IpFamily, LedgerError, RelayProtocolVersion, RelaySpec, ScenarioBuilder, ScenarioOperation,
    TraceBuffer,
};

#[derive(Debug, Eq, PartialEq)]
struct AdmissionEvidence {
    error: String,
    trace: Vec<iroh_runtime::TraceEvent>,
    resources_after_rejection: ResourceLedgerSnapshot,
    resources_after_cleanup: ResourceLedgerSnapshot,
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn connection_admission_rejects_before_dial_and_replays_identically() {
    let first = connection_admission_evidence([81; 32]).await;
    let replay = connection_admission_evidence([81; 32]).await;

    assert_eq!(first, replay);
}

async fn connection_admission_evidence(seed: [u8; 32]) -> AdmissionEvidence {
    let mut scenario = ScenarioBuilder::direct_ip_echo(
        "runner/connection-admission",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .expect("standard scenario is valid")
    .build()
    .expect("standard scenario normalizes");
    scenario.budgets.resources.max_connections = 1;
    let trace = TraceBuffer::default();
    let mut backend = DeterministicScenarioBackend::new(
        &scenario,
        RootSeed::new(seed),
        SystemTime::UNIX_EPOCH,
        Arc::new(trace.clone()),
        iroh::simulation::SimulationCryptoMode::DeterministicTest,
    )
    .expect("bounded deterministic backend constructs");
    backend
        .prepare(&scenario)
        .await
        .expect("standard topology prepares");

    for action_id in ["01-start-client", "02-start-server", "03-connect"] {
        let action = scenario
            .actions
            .iter()
            .find(|action| action.id == action_id)
            .expect("standard scenario action exists");
        backend
            .execute(action)
            .await
            .expect("first connection is admitted");
    }
    assert_eq!(backend.connections.len(), 1);

    let trace_before = trace.events();
    let scheduler_before = backend.backend.kernel().scheduler_snapshot();
    let tasks_before = backend.backend.kernel().task_ownership_snapshot();
    let rejected = ActionSpec {
        id: "04-rejected-connect".to_owned(),
        schedule: ActionSchedule::At { nanos: 0 },
        action: ScenarioAction::Connect {
            client: "client".to_owned(),
            server: "server".to_owned(),
            connection: "c2".to_owned(),
        },
    };
    let error = backend
        .execute(&rejected)
        .await
        .expect_err("second live connection exceeds the configured ceiling");

    assert!(matches!(
        error,
        RunnerError::Ledger(LedgerError::LimitExceeded {
            kind: ResourceKind::Connection,
            limit: 1,
        })
    ));
    assert_eq!(backend.connections.len(), 1);
    assert_eq!(trace.events(), trace_before, "rejection must not dial");
    assert_eq!(
        backend.backend.kernel().scheduler_snapshot(),
        scheduler_before,
        "rejection must not poll connection tasks"
    );
    assert_eq!(
        backend.backend.kernel().task_ownership_snapshot(),
        tasks_before,
        "rejection must not create connection tasks"
    );
    let resources_after_rejection = backend.resource_snapshot();
    assert_eq!(
        resources_after_rejection.current(ResourceKind::Connection),
        1
    );
    assert_eq!(
        resources_after_rejection.high_water(ResourceKind::Connection),
        1
    );

    backend
        .shutdown()
        .await
        .expect("admitted connection and endpoints shut down");
    let resources_after_cleanup = backend.resource_snapshot();
    assert!(resources_after_cleanup.is_empty());
    assert_eq!(
        resources_after_cleanup.high_water(ResourceKind::Connection),
        1
    );

    AdmissionEvidence {
        error: error.to_string(),
        trace: trace.events(),
        resources_after_rejection,
        resources_after_cleanup,
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn relay_admission_rejects_before_construction_rolls_back_and_replays_identically() {
    let first = relay_admission_evidence([82; 32]).await;
    let replay = relay_admission_evidence([82; 32]).await;

    assert_eq!(first, replay);
}

async fn relay_admission_evidence(seed: [u8; 32]) -> AdmissionEvidence {
    let mut builder = ScenarioBuilder::direct_ip_echo(
        "runner/relay-admission",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .expect("standard scenario is valid");
    let scenario = builder.scenario_mut();
    scenario.topology.relays.extend([
        relay_spec("first", "https://first.invalid", 8),
        // This constructor-invalid sentinel proves that relay construction was not reached:
        // admission must return the typed ledger failure first.
        relay_spec("sentinel", "https://sentinel.invalid", 0),
    ]);
    scenario.budgets.resources.max_relays = 1;
    let scenario = scenario.clone();
    let trace = TraceBuffer::default();
    let mut backend = DeterministicScenarioBackend::new(
        &scenario,
        RootSeed::new(seed),
        SystemTime::UNIX_EPOCH,
        Arc::new(trace.clone()),
        iroh::simulation::SimulationCryptoMode::DeterministicTest,
    )
    .expect("bounded deterministic backend constructs");
    let scheduler_before = backend.backend.kernel().scheduler_snapshot();
    let tasks_before = backend.backend.kernel().task_ownership_snapshot();

    let error = backend
        .prepare(&scenario)
        .await
        .expect_err("second relay exceeds the configured ceiling");

    assert!(matches!(
        error,
        RunnerError::Ledger(LedgerError::LimitExceeded {
            kind: ResourceKind::Relay,
            limit: 1,
        })
    ));
    assert!(
        trace.events().is_empty(),
        "rejection must not construct relays"
    );
    assert_eq!(
        backend.backend.kernel().scheduler_snapshot(),
        scheduler_before
    );
    assert_eq!(
        backend.backend.kernel().task_ownership_snapshot(),
        tasks_before
    );
    let resources_after_rejection = backend.resource_snapshot();
    assert!(resources_after_rejection.is_empty());
    assert_eq!(resources_after_rejection.current(ResourceKind::Relay), 0);
    assert_eq!(resources_after_rejection.high_water(ResourceKind::Relay), 1);
    backend
        .shutdown()
        .await
        .expect("failed preparation cleans up");
    let resources_after_cleanup = backend.resource_snapshot();

    AdmissionEvidence {
        error: error.to_string(),
        trace: trace.events(),
        resources_after_rejection,
        resources_after_cleanup,
    }
}

fn relay_spec(id: &str, url: &str, max_sessions: u64) -> RelaySpec {
    RelaySpec {
        id: id.to_owned(),
        url: url.to_owned(),
        online: true,
        max_sessions,
        byte_capacity: 256 * 1_024,
        protocol_version: RelayProtocolVersion::V2,
    }
}
