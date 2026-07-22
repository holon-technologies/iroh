use std::{sync::Arc, time::SystemTime};

use iroh_runtime::RootSeed;
use iroh_sim::{
    ActionSchedule, ActionSpec, DiscoveryProviderSpec, DiscoveryRecordState, FirewallAction,
    FirewallConnectionState, FirewallDirection, FirewallProtocol, FirewallRuleSpec, FirewallSpec,
    InvariantName, InvariantSpec, IpFamily, NatFilteringBehavior, NatMappingBehavior, NatSpec,
    ReferenceModel, RelayImpairmentSpec, RelayProtocolVersion, RelaySpec, RunnerError, Scenario,
    ScenarioAction, ScenarioBuilder, ScenarioOperation, ScenarioRunner, TraceBuffer,
    first_trace_divergence,
};

fn enable_relay_routing_invariant(scenario: &mut Scenario) {
    scenario.invariants.push(InvariantSpec {
        name: InvariantName::RelayRouting,
        deadline_nanos: None,
        max_events: None,
    });
}

fn assert_production_relay_coverage(
    report: &iroh_sim::ScenarioReport,
    minimum_authenticated_sessions: u64,
) {
    assert!(report.observations.iter().any(|observation| matches!(
        observation.kind,
        iroh_sim::ObservationKind::RelayCoverage {
            authenticated_sessions,
            forwarded_packets,
            ..
        } if authenticated_sessions >= minimum_authenticated_sessions && forwarded_packets > 0
    )));
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn declarative_scenario_runs_real_quic_and_replays_the_same_report_and_trace() {
    let scenario = Scenario::from_json(include_bytes!("fixtures/v2-ipv4-stream.json")).unwrap();
    let (first_report, first_trace) = run(scenario.clone(), [44; 32]).await;
    let (second_report, second_trace) = run(scenario, [44; 32]).await;

    assert_eq!(
        first_trace_divergence(&first_trace, &second_trace).unwrap(),
        None
    );
    assert_eq!(first_report, second_report);
    assert_eq!(first_report.actions_completed, 7);
    assert!(first_report.resources.is_empty());
    let scheduler = first_report
        .scheduler
        .expect("kernel scheduler diagnostics");
    assert!(scheduler.seeded && scheduler.decisions > 0);
    assert!(
        first_report
            .tasks
            .iter()
            .any(|task| matches!(task.metadata.kind, iroh_runtime::TaskKind::SocketActor))
    );
    assert!(
        first_report
            .tasks
            .iter()
            .any(|task| matches!(task.metadata.kind, iroh_runtime::TaskKind::Noq))
    );
    assert!(first_report.tasks.iter().any(|task| {
        matches!(task.metadata.kind, iroh_runtime::TaskKind::Other(ref kind) if kind == "remote-state-actor")
            && task.metadata.name == "remote-state-actor"
    }));
    assert!(first_report.tasks.iter().all(|task| !task.live));
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn production_crypto_lane_replays_semantically_and_matches_test_crypto_outcomes() {
    let scenario = ScenarioBuilder::direct_ip_echo(
        "runner/production-crypto-parity",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap()
    .build()
    .unwrap();
    let (deterministic_report, deterministic_trace) = run(scenario.clone(), [45; 32]).await;
    let (first_report, first_trace) = run_with_crypto_mode(
        scenario.clone(),
        [45; 32],
        iroh::simulation::SimulationCryptoMode::ProductionProvider,
    )
    .await;
    let (replay_report, replay_trace) = run_with_crypto_mode(
        scenario,
        [45; 32],
        iroh::simulation::SimulationCryptoMode::ProductionProvider,
    )
    .await;

    assert_eq!(first_report, replay_report);
    assert_eq!(deterministic_report, first_report);
    assert_eq!(
        first_trace_divergence(&first_trace, &replay_trace).unwrap(),
        None
    );
    assert_eq!(
        first_trace_divergence(&deterministic_trace, &first_trace).unwrap(),
        None
    );
    assert_ne!(
        first_trace, replay_trace,
        "production ciphertext must remain opaque"
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn relay_only_scenario_runs_production_quic_client_and_server_sessions() {
    let mut builder = ScenarioBuilder::direct_ip_echo(
        "runner/relay-only",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap();
    let scenario = builder.scenario_mut();
    scenario.requirements.relay = true;
    enable_relay_routing_invariant(scenario);
    scenario.topology.relays.push(RelaySpec {
        id: "home".to_owned(),
        url: "https://home.invalid".to_owned(),
        online: true,
        max_sessions: 8,
        byte_capacity: 256 * 1024,
        protocol_version: RelayProtocolVersion::V2,
    });
    for endpoint in &mut scenario.endpoints {
        endpoint.direct = false;
        endpoint.relay = Some("home".to_owned());
    }

    let scenario = builder.build().unwrap();
    let (report, trace) = run(scenario.clone(), [61; 32]).await;
    let (replay, replay_trace) = run(scenario, [61; 32]).await;
    assert_eq!(report, replay);
    if trace != replay_trace {
        let index = trace
            .iter()
            .zip(&replay_trace)
            .position(|(expected, actual)| expected != actual)
            .unwrap_or_else(|| trace.len().min(replay_trace.len()));
        panic!(
            "raw relay trace diverged at {index}: expected={:?} actual={:?}",
            trace.get(index),
            replay_trace.get(index)
        );
    }
    assert_eq!(first_trace_divergence(&trace, &replay_trace).unwrap(), None);
    assert_eq!(report.actions_completed, 7);
    assert!(report.resources.is_empty());
    assert!(report.observations.iter().any(|observation| matches!(
        observation.kind,
        iroh_sim::ObservationKind::PathState { ref path, active: true, .. }
            if path.as_str() == "relay"
    )));
    assert_production_relay_coverage(&report, 2);
    assert!(report.tasks.iter().any(|task| {
        matches!(task.metadata.kind, iroh_runtime::TaskKind::Relay)
            && task.metadata.name == "active-relay-actor"
    }));
    assert!(report.tasks.iter().all(|task| !task.live));
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn relay_frame_loss_is_recovered_by_production_quic_and_remains_observable() {
    let mut builder = ScenarioBuilder::direct_ip_echo(
        "runner/relay-frame-loss",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap();
    let scenario = builder.scenario_mut();
    scenario.requirements.relay = true;
    enable_relay_routing_invariant(scenario);
    scenario.topology.relays.push(RelaySpec {
        id: "lossy".to_owned(),
        url: "https://lossy-quic.invalid".to_owned(),
        online: true,
        max_sessions: 8,
        byte_capacity: 256 * 1024,
        protocol_version: RelayProtocolVersion::V2,
    });
    scenario
        .topology
        .relay_impairments
        .push(RelayImpairmentSpec {
            relay: "lossy".to_owned(),
            connection_delay_nanos: 0,
            reject_connect_attempts: Vec::new(),
            drop_every_nth_packet: Some(3),
            ..RelayImpairmentSpec::default()
        });
    for endpoint in &mut scenario.endpoints {
        endpoint.direct = false;
        endpoint.relay = Some("lossy".to_owned());
    }

    let report = run(builder.build().unwrap(), [69; 32]).await.0;
    assert!(report.observations.iter().any(|observation| matches!(
        observation.kind,
        iroh_sim::ObservationKind::RelayCoverage {
            forwarded_packets,
            dropped_packets,
            ..
        } if forwarded_packets > 0 && dropped_packets > 0
    )));
    assert!(report.resources.is_empty());
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn direct_failure_falls_back_to_the_production_relay_path() {
    let mut builder = ScenarioBuilder::direct_ip_echo(
        "runner/direct-relay-fallback",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap();
    let scenario = builder.scenario_mut();
    scenario.requirements.relay = true;
    enable_relay_routing_invariant(scenario);
    scenario.topology.relays.push(RelaySpec {
        id: "home".to_owned(),
        url: "https://fallback.invalid".to_owned(),
        online: true,
        max_sessions: 8,
        byte_capacity: 256 * 1024,
        protocol_version: RelayProtocolVersion::V2,
    });
    for endpoint in &mut scenario.endpoints {
        endpoint.relay = Some("home".to_owned());
    }
    scenario.actions[3].id = "05-stream".to_owned();
    scenario.actions[4].id = "08-close".to_owned();
    scenario.actions[5].id = "09-stop-client".to_owned();
    scenario.actions[6].id = "10-stop-server".to_owned();
    scenario.actions.extend([
        ActionSpec {
            id: "04-stabilize-direct".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "03-connect".to_owned(),
            },
            action: ScenarioAction::AdvanceTime {
                by_nanos: 1_000_000_000,
            },
        },
        ActionSpec {
            id: "06-partition-direct".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "05-stream".to_owned(),
            },
            action: ScenarioAction::Partition {
                link: "lan".to_owned(),
                from: "client".to_owned(),
                to: "server".to_owned(),
            },
        },
        ActionSpec {
            id: "07-exchange-fallback".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "06-partition-direct".to_owned(),
            },
            action: ScenarioAction::StreamRoundTrip {
                connection: "c1".to_owned(),
                payload: iroh_sim::PayloadSpec {
                    bytes: 41,
                    fill: 0x6d,
                },
            },
        },
    ]);

    let report = run(builder.build().unwrap(), [62; 32]).await.0;
    let paths = report
        .observations
        .iter()
        .filter_map(|observation| match &observation.kind {
            iroh_sim::ObservationKind::PathState { path, .. } => Some(path.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(paths, ["direct_ipv4", "relay"]);
    assert_production_relay_coverage(&report, 2);
    assert!(report.resources.is_empty());
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn relay_restart_invalidates_sessions_and_recovers_the_quic_connection() {
    let mut builder = ScenarioBuilder::direct_ip_echo(
        "runner/relay-restart",
        IpFamily::Ipv4,
        ScenarioOperation::Datagram,
    )
    .unwrap();
    let scenario = builder.scenario_mut();
    scenario.requirements.relay = true;
    enable_relay_routing_invariant(scenario);
    scenario.topology.relays.push(RelaySpec {
        id: "home".to_owned(),
        url: "https://restart.invalid".to_owned(),
        online: true,
        max_sessions: 8,
        byte_capacity: 256 * 1024,
        protocol_version: RelayProtocolVersion::V2,
    });
    for endpoint in &mut scenario.endpoints {
        endpoint.direct = false;
        endpoint.relay = Some("home".to_owned());
    }
    scenario.actions[4].id = "10-close-recovered".to_owned();
    let ScenarioAction::CloseConnection { connection } = &mut scenario.actions[4].action else {
        unreachable!();
    };
    *connection = "c2".to_owned();
    scenario.actions[5].id = "11-stop-client".to_owned();
    scenario.actions[6].id = "12-stop-server".to_owned();
    scenario.actions.extend([
        ActionSpec {
            id: "05-relay-offline".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "04-stream".to_owned(),
            },
            action: ScenarioAction::RelayLifecycle {
                relay: "home".to_owned(),
                online: false,
            },
        },
        ActionSpec {
            id: "06-relay-online".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "05-relay-offline".to_owned(),
            },
            action: ScenarioAction::RelayLifecycle {
                relay: "home".to_owned(),
                online: true,
            },
        },
        ActionSpec {
            id: "07-reconnect-window".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "06-relay-online".to_owned(),
            },
            action: ScenarioAction::AdvanceTime {
                by_nanos: 2_000_000_000,
            },
        },
        ActionSpec {
            id: "08-connect-recovered".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "07-reconnect-window".to_owned(),
            },
            action: ScenarioAction::Connect {
                client: "client".to_owned(),
                server: "server".to_owned(),
                connection: "c2".to_owned(),
            },
        },
        ActionSpec {
            id: "09-datagram-after-restart".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "08-connect-recovered".to_owned(),
            },
            action: ScenarioAction::DatagramRoundTrip {
                connection: "c2".to_owned(),
                payload: iroh_sim::PayloadSpec {
                    bytes: 37,
                    fill: 0x5a,
                },
            },
        },
    ]);

    let report = run(builder.build().unwrap(), [63; 32]).await.0;
    assert_eq!(report.actions_completed, 12);
    let transitions = report
        .observations
        .iter()
        .filter_map(|observation| match &observation.kind {
            iroh_sim::ObservationKind::RelayState {
                online,
                generation,
                sessions,
                ..
            } => Some((*online, *generation, *sessions)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(transitions, [(false, 0, 0), (true, 1, 0)]);
    assert_production_relay_coverage(&report, 4);
    assert!(report.resources.is_empty());
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn relay_connection_upgrades_to_a_discovered_direct_path() {
    let mut builder = ScenarioBuilder::direct_ip_echo(
        "runner/relay-direct-upgrade",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap();
    let scenario = builder.scenario_mut();
    scenario.requirements.relay = true;
    enable_relay_routing_invariant(scenario);
    scenario.requirements.discovery = true;
    scenario.topology.relays.push(RelaySpec {
        id: "home".to_owned(),
        url: "https://upgrade.invalid".to_owned(),
        online: true,
        max_sessions: 8,
        byte_capacity: 256 * 1024,
        protocol_version: RelayProtocolVersion::V2,
    });
    scenario.topology.discovery.push(DiscoveryProviderSpec {
        id: "primary".to_owned(),
        max_records: 8,
    });
    for endpoint in &mut scenario.endpoints {
        endpoint.relay = Some("home".to_owned());
    }
    scenario.actions[4].id = "08-close".to_owned();
    scenario.actions[5].id = "09-stop-client".to_owned();
    scenario.actions[6].id = "10-stop-server".to_owned();
    scenario.actions.extend([
        ActionSpec {
            id: "05-publish-direct".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "04-stream".to_owned(),
            },
            action: ScenarioAction::DiscoveryUpdate {
                provider: "primary".to_owned(),
                record: "server-direct".to_owned(),
                endpoint: "server".to_owned(),
                addresses: vec!["192.0.2.2:31002".to_owned()],
                delay_nanos: 0,
                ttl_nanos: 30_000_000_000,
                state: DiscoveryRecordState::Published,
            },
        },
        ActionSpec {
            id: "06-direct-validation-window".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "05-publish-direct".to_owned(),
            },
            action: ScenarioAction::AdvanceTime {
                by_nanos: 1_000_000_000,
            },
        },
        ActionSpec {
            id: "07-stream-direct".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "06-direct-validation-window".to_owned(),
            },
            action: ScenarioAction::StreamRoundTrip {
                connection: "c1".to_owned(),
                payload: iroh_sim::PayloadSpec {
                    bytes: 43,
                    fill: 0xa7,
                },
            },
        },
    ]);

    let report = run(builder.build().unwrap(), [64; 32]).await.0;
    let paths = report
        .observations
        .iter()
        .filter_map(|observation| match &observation.kind {
            iroh_sim::ObservationKind::PathState { path, .. } => Some(path.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(paths, ["relay", "direct_ipv4"]);
    assert!(report.resources.is_empty());
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn endpoints_on_distinct_relays_route_without_cross_relay_identity_leakage() {
    let mut builder = ScenarioBuilder::direct_ip_echo(
        "runner/multiple-relays",
        IpFamily::Ipv4,
        ScenarioOperation::Datagram,
    )
    .unwrap();
    let scenario = builder.scenario_mut();
    scenario.requirements.relay = true;
    enable_relay_routing_invariant(scenario);
    scenario.topology.relays.extend([
        RelaySpec {
            id: "west".to_owned(),
            url: "https://west.invalid".to_owned(),
            online: true,
            max_sessions: 8,
            byte_capacity: 256 * 1024,
            protocol_version: RelayProtocolVersion::V2,
        },
        RelaySpec {
            id: "east".to_owned(),
            url: "https://east.invalid".to_owned(),
            online: true,
            max_sessions: 8,
            byte_capacity: 256 * 1024,
            protocol_version: RelayProtocolVersion::V2,
        },
    ]);
    for endpoint in &mut scenario.endpoints {
        endpoint.direct = false;
        endpoint.relay = Some(if endpoint.id == "client" {
            "west".to_owned()
        } else {
            "east".to_owned()
        });
    }

    let report = run(builder.build().unwrap(), [65; 32]).await.0;
    assert_eq!(report.actions_completed, 7);
    assert!(report.observations.iter().any(|observation| matches!(
        observation.kind,
        iroh_sim::ObservationKind::PathState { ref path, .. } if path.as_str() == "relay"
    )));
    assert!(report.resources.is_empty());
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn initially_unavailable_home_relay_recovers_before_the_production_dial() {
    let mut builder = ScenarioBuilder::direct_ip_echo(
        "runner/unavailable-home-relay",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap();
    let scenario = builder.scenario_mut();
    scenario.requirements.relay = true;
    enable_relay_routing_invariant(scenario);
    scenario.topology.relays.push(RelaySpec {
        id: "home".to_owned(),
        url: "https://unavailable.invalid".to_owned(),
        online: false,
        max_sessions: 8,
        byte_capacity: 256 * 1024,
        protocol_version: RelayProtocolVersion::V2,
    });
    for endpoint in &mut scenario.endpoints {
        endpoint.direct = false;
        endpoint.relay = Some("home".to_owned());
    }
    for (index, id) in [
        "05-connect",
        "06-stream",
        "07-close",
        "08-stop-client",
        "09-stop-server",
    ]
    .into_iter()
    .enumerate()
    {
        scenario.actions[index + 2].id = id.to_owned();
    }
    scenario.actions.extend([
        ActionSpec {
            id: "03-relay-online".to_owned(),
            schedule: ActionSchedule::At { nanos: 0 },
            action: ScenarioAction::RelayLifecycle {
                relay: "home".to_owned(),
                online: true,
            },
        },
        ActionSpec {
            id: "04-reconnect-window".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "03-relay-online".to_owned(),
            },
            action: ScenarioAction::AdvanceTime {
                by_nanos: 1_000_000_000,
            },
        },
    ]);

    let report = run(builder.build().unwrap(), [66; 32]).await.0;
    assert_eq!(report.actions_completed, 9);
    assert_production_relay_coverage(&report, 2);
    assert!(report.resources.is_empty());
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn shutdown_during_relay_reconnect_cancels_waiters_and_releases_resources() {
    let mut builder = ScenarioBuilder::direct_ip_echo(
        "runner/shutdown-during-relay-reconnect",
        IpFamily::Ipv4,
        ScenarioOperation::Datagram,
    )
    .unwrap();
    let scenario = builder.scenario_mut();
    scenario.requirements.relay = true;
    enable_relay_routing_invariant(scenario);
    scenario.topology.relays.push(RelaySpec {
        id: "home".to_owned(),
        url: "https://shutdown.invalid".to_owned(),
        online: true,
        max_sessions: 8,
        byte_capacity: 256 * 1024,
        protocol_version: RelayProtocolVersion::V2,
    });
    for endpoint in &mut scenario.endpoints {
        endpoint.direct = false;
        endpoint.relay = Some("home".to_owned());
    }
    scenario.actions[5].id = "07-stop-client".to_owned();
    scenario.actions[6].id = "08-stop-server".to_owned();
    scenario.actions.push(ActionSpec {
        id: "06-relay-offline".to_owned(),
        schedule: ActionSchedule::AfterAction {
            action: "05-close".to_owned(),
        },
        action: ScenarioAction::RelayLifecycle {
            relay: "home".to_owned(),
            online: false,
        },
    });

    let report = run(builder.build().unwrap(), [67; 32]).await.0;
    assert_eq!(report.actions_completed, 8);
    assert_production_relay_coverage(&report, 2);
    assert!(report.resources.is_empty());
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn endpoint_restart_reauthenticates_and_routes_on_a_new_runtime_incarnation() {
    let mut builder = ScenarioBuilder::direct_ip_echo(
        "runner/endpoint-restart",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap();
    let scenario = builder.scenario_mut();
    scenario.requirements.relay = true;
    enable_relay_routing_invariant(scenario);
    scenario.topology.relays.push(RelaySpec {
        id: "home".to_owned(),
        url: "https://endpoint-restart.invalid".to_owned(),
        online: true,
        max_sessions: 8,
        byte_capacity: 256 * 1024,
        protocol_version: RelayProtocolVersion::V2,
    });
    for endpoint in &mut scenario.endpoints {
        endpoint.direct = false;
        endpoint.relay = Some("home".to_owned());
    }
    let mut restarted = scenario.endpoints[0].clone();
    restarted.id = "client-restarted".to_owned();
    restarted.bind = "192.0.2.1:31003".to_owned();
    scenario.endpoints.push(restarted);
    scenario.actions[6].id = "12-stop-server".to_owned();
    scenario.actions.extend([
        ActionSpec {
            id: "07-start-restarted-client".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "06-stop-client".to_owned(),
            },
            action: ScenarioAction::StartEndpoint {
                endpoint: "client-restarted".to_owned(),
            },
        },
        ActionSpec {
            id: "08-connect-restarted".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "07-start-restarted-client".to_owned(),
            },
            action: ScenarioAction::Connect {
                client: "client-restarted".to_owned(),
                server: "server".to_owned(),
                connection: "c2".to_owned(),
            },
        },
        ActionSpec {
            id: "09-stream-restarted".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "08-connect-restarted".to_owned(),
            },
            action: ScenarioAction::StreamRoundTrip {
                connection: "c2".to_owned(),
                payload: iroh_sim::PayloadSpec {
                    bytes: 47,
                    fill: 0x47,
                },
            },
        },
        ActionSpec {
            id: "10-close-restarted".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "09-stream-restarted".to_owned(),
            },
            action: ScenarioAction::CloseConnection {
                connection: "c2".to_owned(),
            },
        },
        ActionSpec {
            id: "11-stop-restarted-client".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "10-close-restarted".to_owned(),
            },
            action: ScenarioAction::StopEndpoint {
                endpoint: "client-restarted".to_owned(),
            },
        },
    ]);

    let report = run(builder.build().unwrap(), [68; 32]).await.0;
    assert_eq!(report.actions_completed, 12);
    assert_production_relay_coverage(&report, 3);
    assert!(report.resources.is_empty());
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn partition_and_heal_actions_preserve_production_stream_delivery() {
    let mut builder = ScenarioBuilder::direct_ip_echo(
        "runner/partition-heal",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap();
    let scenario = builder.scenario_mut();
    scenario.actions[3].id = "06-stream".to_owned();
    scenario.actions[4].id = "07-close".to_owned();
    scenario.actions[5].id = "08-stop-client".to_owned();
    scenario.actions[6].id = "09-stop-server".to_owned();
    scenario.actions.extend([
        ActionSpec {
            id: "04-partition".to_owned(),
            schedule: ActionSchedule::At { nanos: 0 },
            action: ScenarioAction::Partition {
                link: "lan".to_owned(),
                from: "client".to_owned(),
                to: "server".to_owned(),
            },
        },
        ActionSpec {
            id: "05-heal".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "04-partition".to_owned(),
            },
            action: ScenarioAction::Heal {
                link: "lan".to_owned(),
                from: "client".to_owned(),
                to: "server".to_owned(),
            },
        },
    ]);
    let report = run(builder.build().unwrap(), [45; 32]).await.0;
    assert_eq!(report.actions_completed, 9);
    assert!(report.resources.is_empty());
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn interface_down_up_notifies_production_socket_actor_and_preserves_quic() {
    let mut builder = ScenarioBuilder::direct_ip_echo(
        "runner/interface-down-up",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap();
    let scenario = builder.scenario_mut();
    scenario.requirements.mobility = true;
    let client = scenario
        .topology
        .hosts
        .iter_mut()
        .find(|host| host.id == "client")
        .unwrap();
    client.interfaces.push(iroh_sim::InterfaceSpec {
        id: "wifi0".to_owned(),
        link: "lan".to_owned(),
        addresses: vec!["192.0.3.1/0".to_owned()],
    });
    scenario
        .topology
        .hosts
        .iter_mut()
        .find(|host| host.id == "server")
        .unwrap()
        .interfaces[0]
        .addresses[0] = "192.0.2.2/0".to_owned();
    scenario
        .endpoints
        .iter_mut()
        .find(|endpoint| endpoint.id == "client")
        .unwrap()
        .bind = "0.0.0.0:31001".to_owned();
    scenario.actions[3].id = "05-stream-secondary".to_owned();
    scenario.actions[4].id = "16-close".to_owned();
    scenario.actions[5].id = "17-stop-client".to_owned();
    scenario.actions[6].id = "18-stop-server".to_owned();
    scenario.actions.extend([
        ActionSpec {
            id: "04-interface-down".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "03-connect".to_owned(),
            },
            action: ScenarioAction::InterfaceChange {
                host: "client".to_owned(),
                interface: "eth0".to_owned(),
                up: false,
            },
        },
        ActionSpec {
            id: "06-interface-up".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "05-stream-secondary".to_owned(),
            },
            action: ScenarioAction::InterfaceChange {
                host: "client".to_owned(),
                interface: "eth0".to_owned(),
                up: true,
            },
        },
        ActionSpec {
            id: "07-stream-primary".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "06-interface-up".to_owned(),
            },
            action: ScenarioAction::StreamRoundTrip {
                connection: "c1".to_owned(),
                payload: iroh_sim::PayloadSpec {
                    bytes: 31,
                    fill: 90,
                },
            },
        },
        ActionSpec {
            id: "08-address-remove".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "07-stream-primary".to_owned(),
            },
            action: ScenarioAction::AddressChange {
                host: "client".to_owned(),
                interface: "wifi0".to_owned(),
                address: "192.0.3.1/0".to_owned(),
                present: false,
            },
        },
        ActionSpec {
            id: "09-address-add".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "08-address-remove".to_owned(),
            },
            action: ScenarioAction::AddressChange {
                host: "client".to_owned(),
                interface: "wifi0".to_owned(),
                address: "192.0.3.1/0".to_owned(),
                present: true,
            },
        },
        ActionSpec {
            id: "10-route-add".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "09-address-add".to_owned(),
            },
            action: ScenarioAction::RouteChange {
                host: "client".to_owned(),
                route: "prefer-wifi".to_owned(),
                destination: "192.0.2.2/32".to_owned(),
                interface: "wifi0".to_owned(),
                next_hop: Some("server".to_owned()),
                active: true,
            },
        },
        ActionSpec {
            id: "11-stream-routed".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "10-route-add".to_owned(),
            },
            action: ScenarioAction::StreamRoundTrip {
                connection: "c1".to_owned(),
                payload: iroh_sim::PayloadSpec {
                    bytes: 35,
                    fill: 75,
                },
            },
        },
        ActionSpec {
            id: "12-route-remove".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "11-stream-routed".to_owned(),
            },
            action: ScenarioAction::RouteChange {
                host: "client".to_owned(),
                route: "prefer-wifi".to_owned(),
                destination: "192.0.2.2/32".to_owned(),
                interface: "wifi0".to_owned(),
                next_hop: Some("server".to_owned()),
                active: false,
            },
        },
        ActionSpec {
            id: "13-sleep".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "12-route-remove".to_owned(),
            },
            action: ScenarioAction::HostSleep {
                host: "client".to_owned(),
                sleeping: true,
            },
        },
        ActionSpec {
            id: "14-resume".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "13-sleep".to_owned(),
            },
            action: ScenarioAction::HostSleep {
                host: "client".to_owned(),
                sleeping: false,
            },
        },
        ActionSpec {
            id: "15-stream-resumed".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "14-resume".to_owned(),
            },
            action: ScenarioAction::StreamRoundTrip {
                connection: "c1".to_owned(),
                payload: iroh_sim::PayloadSpec {
                    bytes: 37,
                    fill: 60,
                },
            },
        },
    ]);
    let scenario = builder.build().unwrap();

    let (first_report, first_trace) = run(scenario.clone(), [50; 32]).await;
    let (second_report, second_trace) = run(scenario, [50; 32]).await;

    assert_eq!(first_report, second_report);
    assert_eq!(first_report.actions_completed, 18);
    assert!(first_report.resources.is_empty());
    let interface_events = first_trace
        .iter()
        .filter(|event| {
            matches!(
                &event.event,
                iroh_runtime::TraceEventKind::InterfaceState { host, .. } if host == "client"
            )
        })
        .count();
    assert_eq!(interface_events, 2);
    assert_eq!(
        first_trace
            .iter()
            .filter(|event| matches!(
                &event.event,
                iroh_runtime::TraceEventKind::InterfaceAddress { host, .. } if host == "client"
            ))
            .count(),
        2
    );
    assert_eq!(
        first_report
            .observations
            .iter()
            .filter(|observation| matches!(
                &observation.kind,
                iroh_sim::ObservationKind::RouteState { host, .. } if host == "client"
            ))
            .count(),
        2
    );
    assert_eq!(
        first_trace
            .iter()
            .filter(|event| matches!(
                &event.event,
                iroh_runtime::TraceEventKind::HostPower { host, .. } if host == "client"
            ))
            .count(),
        2
    );
    assert!(first_trace.iter().any(|event| {
        matches!(
            &event.event,
            iroh_runtime::TraceEventKind::PacketCreated { source, .. }
                if source.starts_with("192.0.3.1:")
        )
    }));
    assert_eq!(
        first_trace_divergence(&first_trace, &second_trace).unwrap(),
        None
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn declared_stateful_nat_and_firewall_carry_real_quic_and_replay() {
    let mut builder = ScenarioBuilder::direct_ip_echo(
        "runner/stateful-nat-firewall",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap();
    let scenario = builder.scenario_mut();
    scenario.requirements.nat = true;
    for host in &mut scenario.topology.hosts {
        host.interfaces[0].addresses[0] = match host.id.as_str() {
            "client" => "192.0.2.1/0".to_owned(),
            "server" => "192.0.2.2/0".to_owned(),
            other => panic!("unexpected host {other}"),
        };
    }
    scenario.topology.nats.push(NatSpec {
        id: "home".to_owned(),
        inside_host: "client".to_owned(),
        upstream_nat: Some("carrier".to_owned()),
        public_ip: "203.0.113.7".to_owned(),
        port_start: 40_000,
        port_end: 40_127,
        mapping_behavior: NatMappingBehavior::EndpointIndependent,
        filtering_behavior: NatFilteringBehavior::AddressAndPortDependent,
        mapping_ttl_nanos: 5_000_000,
        hairpin: true,
        max_mappings: 128,
        firewall: Some(FirewallSpec {
            id: "home-policy".to_owned(),
            rules: vec![
                FirewallRuleSpec {
                    id: "allow-established".to_owned(),
                    protocol: FirewallProtocol::Udp,
                    direction: Some(FirewallDirection::Inbound),
                    source: None,
                    destination: None,
                    source_ports: None,
                    destination_ports: None,
                    connection_state: FirewallConnectionState::Established,
                    action: FirewallAction::Allow,
                },
                FirewallRuleSpec {
                    id: "allow-outbound".to_owned(),
                    protocol: FirewallProtocol::Udp,
                    direction: Some(FirewallDirection::Outbound),
                    source: None,
                    destination: None,
                    source_ports: None,
                    destination_ports: None,
                    connection_state: FirewallConnectionState::Any,
                    action: FirewallAction::Allow,
                },
            ],
            default_action: FirewallAction::Drop,
        }),
    });
    scenario.topology.nats.push(NatSpec {
        id: "carrier".to_owned(),
        inside_host: "client".to_owned(),
        upstream_nat: None,
        public_ip: "198.18.0.1".to_owned(),
        port_start: 41_000,
        port_end: 41_127,
        mapping_behavior: NatMappingBehavior::EndpointIndependent,
        filtering_behavior: NatFilteringBehavior::EndpointIndependent,
        mapping_ttl_nanos: 5_000_000,
        hairpin: true,
        max_mappings: 128,
        firewall: None,
    });
    scenario.actions[2].id = "04-connect".to_owned();
    scenario.actions[2].schedule = ActionSchedule::AfterAction {
        action: "03-port-map-on".to_owned(),
    };
    scenario.actions[3].id = "07-stream".to_owned();
    scenario.actions[3].schedule = ActionSchedule::AfterAction {
        action: "06-expire-mappings".to_owned(),
    };
    scenario.actions[4].id = "09-close".to_owned();
    scenario.actions[4].schedule = ActionSchedule::AfterAction {
        action: "08-port-map-off".to_owned(),
    };
    scenario.actions[5].id = "10-stop-client".to_owned();
    scenario.actions[5].schedule = ActionSchedule::AfterAction {
        action: "09-close".to_owned(),
    };
    scenario.actions[6].id = "11-stop-server".to_owned();
    scenario.actions[6].schedule = ActionSchedule::AfterAction {
        action: "10-stop-client".to_owned(),
    };
    scenario.actions.extend([
        ActionSpec {
            id: "03-port-map-on".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "01-start-client".to_owned(),
            },
            action: ScenarioAction::PortMap {
                endpoint: "client".to_owned(),
                active: true,
            },
        },
        ActionSpec {
            id: "05-nat-rebind".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "04-connect".to_owned(),
            },
            action: ScenarioAction::NatChange {
                nat: "home".to_owned(),
                public_ip: "203.0.113.8".to_owned(),
                preserve_ports: true,
            },
        },
        ActionSpec {
            id: "06-expire-mappings".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "05-nat-rebind".to_owned(),
            },
            action: ScenarioAction::AdvanceTime {
                by_nanos: 10_000_000,
            },
        },
        ActionSpec {
            id: "08-port-map-off".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "07-stream".to_owned(),
            },
            action: ScenarioAction::PortMap {
                endpoint: "client".to_owned(),
                active: false,
            },
        },
    ]);
    let scenario = builder.build().unwrap();

    let (first_report, first_trace) = run(scenario.clone(), [49; 32]).await;
    let (second_report, second_trace) = run(scenario, [49; 32]).await;

    assert_eq!(first_report, second_report);
    assert_eq!(first_report.actions_completed, 11);
    assert!(first_report.resources.is_empty());
    assert_eq!(
        first_report
            .observations
            .iter()
            .filter(|observation| matches!(
                observation.kind,
                iroh_sim::ObservationKind::PortMappingState { .. }
            ))
            .count(),
        2
    );
    assert!(first_trace.iter().any(|event| matches!(
        &event.event,
        iroh_runtime::TraceEventKind::NatMapping { .. }
    )));
    assert!(first_trace.iter().any(|event| matches!(
        &event.event,
        iroh_runtime::TraceEventKind::NatMapping { transition, .. }
            if transition == "rebound"
    )));
    assert!(first_trace.iter().any(|event| matches!(
        &event.event,
        iroh_runtime::TraceEventKind::NatMapping { transition, .. }
            if transition == "expired"
    )));
    assert!(first_trace.iter().any(|event| matches!(
        &event.event,
        iroh_runtime::TraceEventKind::NatTranslation { .. }
    )));
    assert!(first_trace.iter().any(|event| matches!(
        &event.event,
        iroh_runtime::TraceEventKind::FirewallDecision { .. }
    )));
    assert_eq!(
        first_trace_divergence(&first_trace, &second_trace).unwrap(),
        None
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn production_connect_aggregates_conflicting_delayed_discovery_and_expires_records() {
    let mut builder = ScenarioBuilder::direct_ip_echo(
        "runner/discovery-conflict",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap();
    let scenario = builder.scenario_mut();
    scenario.requirements.discovery = true;
    scenario.topology.discovery = ["bad", "error", "good"]
        .into_iter()
        .map(|id| DiscoveryProviderSpec {
            id: id.to_owned(),
            max_records: 4,
        })
        .collect();
    scenario.actions[2].id = "06-connect".to_owned();
    scenario.actions[2].schedule = ActionSchedule::AfterAction {
        action: "05-good-record".to_owned(),
    };
    scenario.actions[3].id = "08-stream-after-expiry".to_owned();
    scenario.actions[3].schedule = ActionSchedule::AfterAction {
        action: "07-expire-records".to_owned(),
    };
    scenario.actions[4].id = "09-close".to_owned();
    scenario.actions[4].schedule = ActionSchedule::AfterAction {
        action: "08-stream-after-expiry".to_owned(),
    };
    scenario.actions[5].id = "14-stop-client".to_owned();
    scenario.actions[5].schedule = ActionSchedule::AfterAction {
        action: "13-close-reconnected".to_owned(),
    };
    scenario.actions[6].id = "15-stop-server".to_owned();
    scenario.actions[6].schedule = ActionSchedule::AfterAction {
        action: "14-stop-client".to_owned(),
    };
    scenario.actions.extend([
        discovery_action(
            "03-bad-record",
            "02-start-server",
            "bad",
            "bad-server",
            vec!["192.0.2.99:31002".to_owned()],
            1_000_000,
            DiscoveryRecordState::Published,
        ),
        discovery_action(
            "04-error-record",
            "03-bad-record",
            "error",
            "error-server",
            Vec::new(),
            2_000_000,
            DiscoveryRecordState::Failed,
        ),
        discovery_action(
            "05-good-record",
            "04-error-record",
            "good",
            "good-server",
            vec!["192.0.2.2:31002".to_owned()],
            3_000_000,
            DiscoveryRecordState::Published,
        ),
        ActionSpec {
            id: "07-expire-records".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "06-connect".to_owned(),
            },
            action: ScenarioAction::AdvanceTime {
                by_nanos: 30_000_000,
            },
        },
        discovery_action(
            "10-good-refresh",
            "09-close",
            "good",
            "good-server-refresh",
            vec!["192.0.2.2:31002".to_owned()],
            1_000_000,
            DiscoveryRecordState::Published,
        ),
        ActionSpec {
            id: "11-reconnect".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "10-good-refresh".to_owned(),
            },
            action: ScenarioAction::Connect {
                client: "client".to_owned(),
                server: "server".to_owned(),
                connection: "c2".to_owned(),
            },
        },
        ActionSpec {
            id: "12-stream-reconnected".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "11-reconnect".to_owned(),
            },
            action: ScenarioAction::StreamRoundTrip {
                connection: "c2".to_owned(),
                payload: iroh_sim::PayloadSpec {
                    bytes: 33,
                    fill: 87,
                },
            },
        },
        ActionSpec {
            id: "13-close-reconnected".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "12-stream-reconnected".to_owned(),
            },
            action: ScenarioAction::CloseConnection {
                connection: "c2".to_owned(),
            },
        },
    ]);
    let scenario = builder.build().unwrap();

    let (first_report, first_trace) = run(scenario.clone(), [54; 32]).await;
    let (second_report, second_trace) = run(scenario, [54; 32]).await;

    assert_eq!(first_report, second_report);
    assert_eq!(first_report.actions_completed, 15);
    assert!(first_report.resources.is_empty());
    assert_eq!(
        first_report
            .observations
            .iter()
            .filter(|observation| matches!(
                observation.kind,
                iroh_sim::ObservationKind::DiscoveryRecordState { .. }
            ))
            .count(),
        4
    );
    assert!(first_trace.iter().any(|event| matches!(
        &event.event,
        iroh_runtime::TraceEventKind::DiscoveryRecord { transition, .. }
            if transition == "resolved"
    )));
    assert!(
        first_trace
            .iter()
            .filter(|event| matches!(
                &event.event,
                iroh_runtime::TraceEventKind::DiscoveryRecord { transition, .. }
                    if transition == "expired"
            ))
            .count()
            >= 3
    );
    assert_eq!(
        first_trace_divergence(&first_trace, &second_trace).unwrap(),
        None
    );
}

fn discovery_action(
    id: &str,
    after: &str,
    provider: &str,
    record: &str,
    addresses: Vec<String>,
    delay_nanos: u64,
    state: DiscoveryRecordState,
) -> ActionSpec {
    ActionSpec {
        id: id.to_owned(),
        schedule: ActionSchedule::AfterAction {
            action: after.to_owned(),
        },
        action: ScenarioAction::DiscoveryUpdate {
            provider: provider.to_owned(),
            record: record.to_owned(),
            endpoint: "server".to_owned(),
            addresses,
            delay_nanos,
            ttl_nanos: 20_000_000,
            state,
        },
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn observation_completion_stops_pending_actions_and_performs_cleanup() {
    let mut builder = ScenarioBuilder::direct_ip_echo(
        "runner/observation-completion",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap();
    builder.scenario_mut().completion = iroh_sim::CompletionPolicy::Observation {
        trigger: iroh_sim::ObservationTrigger::EndpointState {
            endpoint: "client".to_owned(),
            state: "running".to_owned(),
        },
        shutdown_deadline_nanos: 60_000_000_000,
    };
    let report = run(builder.build().unwrap(), [48; 32]).await.0;
    assert_eq!(report.actions_completed, 1);
    assert!(report.resources.is_empty());
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn unsupported_capability_and_unsatisfied_trigger_are_typed() {
    let mut capability = ScenarioBuilder::direct_ip_echo(
        "runner/capability",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap()
    .build()
    .unwrap();
    capability.requirements.nat = true;
    let trace = TraceBuffer::default();
    let error = ScenarioRunner::deterministic(
        capability,
        RootSeed::new([46; 32]),
        SystemTime::UNIX_EPOCH,
        Arc::new(trace),
    )
    .unwrap_err();
    assert!(matches!(error, RunnerError::UnsupportedCapabilities(_)));

    let mut stalled = ScenarioBuilder::direct_ip_echo(
        "runner/stalled-trigger",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap();
    stalled.scenario_mut().actions.push(ActionSpec {
        id: "99-never".to_owned(),
        schedule: ActionSchedule::AfterObservation {
            observation: iroh_sim::ObservationTrigger::EndpointState {
                endpoint: "client".to_owned(),
                state: "failed".to_owned(),
            },
        },
        action: ScenarioAction::ExpectFailure {
            class: "never".to_owned(),
        },
    });
    let scenario = stalled.build().unwrap();
    let trace = TraceBuffer::default();
    let runner = ScenarioRunner::deterministic(
        scenario,
        RootSeed::new([47; 32]),
        SystemTime::UNIX_EPOCH,
        Arc::new(trace),
    )
    .unwrap();
    assert!(matches!(
        runner.run().await,
        Err(RunnerError::TriggerStall(_))
    ));
}

#[test]
fn reference_model_rejects_a_missing_production_observation() {
    let scenario = ScenarioBuilder::direct_ip_echo(
        "runner/model-mismatch",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap()
    .build()
    .unwrap();
    let mut model = ReferenceModel::new(&scenario).unwrap();
    let error = model
        .validate_action_outcome(&scenario.actions[0], &[])
        .unwrap_err();
    assert!(matches!(error, RunnerError::ModelMismatch { .. }));
}

async fn run(
    scenario: Scenario,
    seed: [u8; 32],
) -> (iroh_sim::ScenarioReport, Vec<iroh_runtime::TraceEvent>) {
    let trace = TraceBuffer::default();
    let runner = ScenarioRunner::deterministic(
        scenario,
        RootSeed::new(seed),
        SystemTime::UNIX_EPOCH,
        Arc::new(trace.clone()),
    )
    .unwrap();
    let report = runner.run().await.unwrap();
    (report, trace.events())
}

async fn run_with_crypto_mode(
    scenario: Scenario,
    seed: [u8; 32],
    crypto_mode: iroh::simulation::SimulationCryptoMode,
) -> (iroh_sim::ScenarioReport, Vec<iroh_runtime::TraceEvent>) {
    let trace = TraceBuffer::default();
    let runner = ScenarioRunner::with_crypto_mode(
        scenario,
        RootSeed::new(seed),
        SystemTime::UNIX_EPOCH,
        Arc::new(trace.clone()),
        crypto_mode,
    )
    .unwrap();
    let report = runner.run().await.unwrap();
    (report, trace.events())
}
