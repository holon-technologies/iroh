use std::collections::BTreeMap;

use iroh_sim::{
    ActionSchedule, ActionSpec, FailureSignature, InvariantClass, InvariantFailure, InvariantName,
    MinimizationConfig, MinimizationError, Minimizer, RunnerError, ScenarioAction, ScenarioBuilder,
    ScenarioInventory, ScenarioOperation,
};

#[test]
fn deterministic_ddmin_removes_irrelevant_causes_and_preserves_signature() {
    let mut builder = ScenarioBuilder::direct_ip_echo(
        "minimize/multi-cause",
        iroh_sim::IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap();
    let scenario = builder.scenario_mut();
    scenario.metadata.description = "verbose diagnostic fixture".to_owned();
    scenario.metadata.tags = vec!["generated".to_owned(), "nightly".to_owned()];
    scenario.topology.hosts.push(iroh_sim::HostSpec {
        id: "noise-host".to_owned(),
        interfaces: vec![iroh_sim::InterfaceSpec {
            id: "eth0".to_owned(),
            link: "lan".to_owned(),
            addresses: vec!["10.0.0.99/24".to_owned()],
        }],
    });
    scenario.endpoints.push(iroh_sim::EndpointSpec {
        id: "noise-endpoint".to_owned(),
        host: "noise-host".to_owned(),
        bind: "10.0.0.99:46000".to_owned(),
        identity_ordinal: 99,
        direct: true,
        relay: None,
    });
    scenario.fault_rules.push(iroh_sim::FaultRule {
        id: "noise-fault".to_owned(),
        link: "lan".to_owned(),
        effect: iroh_sim::PacketFault::Duplication,
        probability_per_million: 1,
        start_nanos: 0,
        end_nanos: scenario.budgets.max_virtual_time_nanos,
        max_applications: u64::MAX,
    });
    scenario.actions.extend([
        ActionSpec {
            id: "90-irrelevant-a".to_owned(),
            schedule: ActionSchedule::At { nanos: 0 },
            action: ScenarioAction::ExpectFailure {
                class: "noise-a".to_owned(),
            },
        },
        ActionSpec {
            id: "91-required-cause".to_owned(),
            schedule: ActionSchedule::At { nanos: 0 },
            action: ScenarioAction::ExpectFailure {
                class: "cause".to_owned(),
            },
        },
        ActionSpec {
            id: "92-irrelevant-b".to_owned(),
            schedule: ActionSchedule::At { nanos: 0 },
            action: ScenarioAction::ExpectFailure {
                class: "noise-b".to_owned(),
            },
        },
    ]);
    let scenario = builder.build().unwrap();
    let original_size = scenario.to_canonical_json().unwrap().len();
    let signature = fixture_signature();
    let mut evaluations = 0;
    let mut evaluator = |candidate: &iroh_sim::Scenario| {
        evaluations += 1;
        Ok(candidate.actions.iter().any(|action| {
            matches!(&action.action, ScenarioAction::ExpectFailure { class } if class == "cause")
        })
        .then(|| signature.clone()))
    };

    let first = Minimizer::new(MinimizationConfig { max_attempts: 500 })
        .minimize(scenario, signature.clone(), &mut evaluator)
        .unwrap();
    assert!(first.scenario.to_canonical_json().unwrap().len() < original_size);
    assert!(first.scenario.actions.iter().any(|action| {
        matches!(&action.action, ScenarioAction::ExpectFailure { class } if class == "cause")
    }));
    assert!(!first.scenario.actions.iter().any(|action| {
        matches!(&action.action, ScenarioAction::ExpectFailure { class } if class.starts_with("noise"))
    }));
    assert!(first.scenario.fault_rules.is_empty());
    assert!(
        first
            .scenario
            .endpoints
            .iter()
            .all(|endpoint| endpoint.id != "noise-endpoint")
    );
    assert!(
        first
            .scenario
            .topology
            .hosts
            .iter()
            .all(|host| host.id != "noise-host")
    );
    assert!(first.attempts.iter().any(|attempt| attempt.accepted));
    assert!(!first.exhausted);

    let mut evaluator = |candidate: &iroh_sim::Scenario| {
        Ok(candidate.actions.iter().any(|action| {
            matches!(&action.action, ScenarioAction::ExpectFailure { class } if class == "cause")
        })
        .then(|| signature.clone()))
    };
    let second = Minimizer::new(MinimizationConfig { max_attempts: 500 })
        .minimize(first.scenario.clone(), signature.clone(), &mut evaluator)
        .unwrap();
    assert_eq!(second.scenario, first.scenario);
    assert!(second.attempts.iter().all(|attempt| !attempt.accepted));
    assert!(evaluations > 0);
}

#[test]
fn domain_reducers_remove_irrelevant_nat_firewall_discovery_interfaces_and_routes() {
    let mut entry = iroh_sim::canonical_patchbay_scenarios()
        .unwrap()
        .into_iter()
        .find(|entry| entry.case == iroh_sim::CanonicalParityCase::PortRestricted)
        .unwrap();
    let scenario = &mut entry.scenario;
    scenario.requirements.discovery = true;
    scenario.requirements.mobility = true;
    scenario
        .topology
        .discovery
        .push(iroh_sim::DiscoveryProviderSpec {
            id: "noise-discovery".to_owned(),
            max_records: 8,
        });
    scenario
        .topology
        .hosts
        .iter_mut()
        .find(|host| host.id == "client")
        .unwrap()
        .interfaces
        .push(iroh_sim::InterfaceSpec {
            id: "noise0".to_owned(),
            link: "lan".to_owned(),
            addresses: vec!["10.1.0.1/24".to_owned(), "10.1.0.2/24".to_owned()],
        });
    scenario.actions.extend([
        ActionSpec {
            id: "80-noise-discovery".to_owned(),
            schedule: ActionSchedule::At { nanos: 0 },
            action: ScenarioAction::DiscoveryUpdate {
                provider: "noise-discovery".to_owned(),
                record: "noise-record".to_owned(),
                endpoint: "server".to_owned(),
                addresses: vec!["192.0.2.2:31002".to_owned()],
                delay_nanos: 10,
                ttl_nanos: 20,
                state: iroh_sim::DiscoveryRecordState::Published,
            },
        },
        ActionSpec {
            id: "81-noise-route".to_owned(),
            schedule: ActionSchedule::At { nanos: 0 },
            action: ScenarioAction::RouteChange {
                host: "client".to_owned(),
                route: "noise-route".to_owned(),
                destination: "192.0.2.2/32".to_owned(),
                interface: "noise0".to_owned(),
                next_hop: Some("server".to_owned()),
                active: true,
            },
        },
        ActionSpec {
            id: "99-required-cause".to_owned(),
            schedule: ActionSchedule::At { nanos: 0 },
            action: ScenarioAction::ExpectFailure {
                class: "cause".to_owned(),
            },
        },
    ]);
    scenario.budgets.max_actions = 128;
    let scenario = scenario.clone().normalized().unwrap();
    let before = ScenarioInventory::from_scenario(&scenario);
    assert_eq!(before.nats, 1);
    assert_eq!(before.firewalls, 1);
    assert_eq!(before.discovery_records, 1);
    assert_eq!(before.routes, 1);

    let signature = fixture_signature();
    let mut evaluator = |candidate: &iroh_sim::Scenario| {
        Ok(candidate.actions.iter().any(|action| {
            matches!(&action.action, ScenarioAction::ExpectFailure { class } if class == "cause")
        })
        .then(|| signature.clone()))
    };
    let result = Minimizer::new(MinimizationConfig {
        max_attempts: 1_000,
    })
    .minimize(scenario, signature.clone(), &mut evaluator)
    .unwrap();
    let after = ScenarioInventory::from_scenario(&result.scenario);
    assert_eq!(after.nats, 0);
    assert_eq!(after.firewalls, 0);
    assert_eq!(after.discovery_providers, 0);
    assert_eq!(after.discovery_records, 0);
    assert_eq!(after.routes, 0);
    assert!(
        result
            .attempts
            .iter()
            .any(|attempt| { attempt.transformation.starts_with("firewall-rules/delete/") })
    );
    assert!(result.attempts.iter().any(|attempt| {
        attempt
            .transformation
            .starts_with("discovery-providers/delete/")
    }));
    assert!(
        result
            .attempts
            .iter()
            .any(|attempt| attempt.transformation.starts_with("nats/delete/"))
    );
    assert!(
        result
            .attempts
            .iter()
            .any(|attempt| { attempt.transformation.starts_with("interfaces/delete/") })
    );
}

#[test]
fn relay_reducers_remove_unrelated_service_lifecycle_and_shrink_required_configuration() {
    let mut builder = ScenarioBuilder::direct_ip_echo(
        "minimize/relay",
        iroh_sim::IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap();
    let scenario = builder.scenario_mut();
    scenario.requirements.relay = true;
    for (id, url) in [
        ("required", "https://required.invalid"),
        ("noise", "https://noise.invalid"),
    ] {
        scenario.topology.relays.push(iroh_sim::RelaySpec {
            id: id.to_owned(),
            url: url.to_owned(),
            online: true,
            max_sessions: 64,
            byte_capacity: 1024 * 1024,
            protocol_version: iroh_sim::RelayProtocolVersion::V2,
        });
    }
    scenario.topology.relay_impairments.extend([
        iroh_sim::RelayImpairmentSpec {
            relay: "required".to_owned(),
            connection_delay_nanos: 9_000_000,
            reject_connect_attempts: vec![2, 4, 8],
            drop_every_nth_packet: Some(70),
            ..iroh_sim::RelayImpairmentSpec::default()
        },
        iroh_sim::RelayImpairmentSpec {
            relay: "noise".to_owned(),
            connection_delay_nanos: 10_000_000,
            reject_connect_attempts: vec![1],
            drop_every_nth_packet: Some(3),
            ..iroh_sim::RelayImpairmentSpec::default()
        },
    ]);
    scenario.actions.extend([
        ActionSpec {
            id: "90-noise-relay-outage".to_owned(),
            schedule: ActionSchedule::At { nanos: 0 },
            action: ScenarioAction::RelayLifecycle {
                relay: "noise".to_owned(),
                online: false,
            },
        },
        ActionSpec {
            id: "99-required-cause".to_owned(),
            schedule: ActionSchedule::At { nanos: 0 },
            action: ScenarioAction::ExpectFailure {
                class: "cause".to_owned(),
            },
        },
    ]);
    let scenario = builder.build().unwrap();
    let signature = fixture_signature();
    let mut evaluator = |candidate: &iroh_sim::Scenario| {
        Ok((candidate
            .topology
            .relays
            .iter()
            .any(|relay| relay.id == "required")
            && candidate
                .topology
                .relay_impairments
                .iter()
                .any(|impairment| impairment.relay == "required")
            && candidate.actions.iter().any(|action| {
                matches!(&action.action, ScenarioAction::ExpectFailure { class } if class == "cause")
            }))
        .then(|| signature.clone()))
    };

    let result = Minimizer::new(MinimizationConfig {
        max_attempts: 1_000,
    })
    .minimize(scenario, signature.clone(), &mut evaluator)
    .unwrap();
    assert_eq!(result.scenario.topology.relays.len(), 1);
    let relay = &result.scenario.topology.relays[0];
    assert_eq!(relay.id, "required");
    assert_eq!(relay.max_sessions, 1);
    assert_eq!(relay.byte_capacity, 1);
    assert_eq!(relay.protocol_version, iroh_sim::RelayProtocolVersion::V1);
    assert_eq!(result.scenario.topology.relay_impairments.len(), 1);
    let impairment = &result.scenario.topology.relay_impairments[0];
    assert_eq!(impairment.relay, "required");
    assert_eq!(impairment.connection_delay_nanos, 0);
    assert_eq!(impairment.reject_connect_attempts, [2]);
    assert_eq!(impairment.drop_every_nth_packet, Some(1));
    assert!(!result.scenario.actions.iter().any(|action| matches!(
        &action.action,
        ScenarioAction::RelayLifecycle { relay, .. } if relay == "noise"
    )));
    assert!(
        result
            .attempts
            .iter()
            .any(|attempt| { attempt.transformation == "relays/delete/noise" && attempt.accepted })
    );
}

#[test]
fn minimizer_distinguishes_nonfailure_changed_signature_and_budget_exhaustion() {
    let scenario = ScenarioBuilder::direct_ip_echo(
        "minimize/errors",
        iroh_sim::IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap()
    .build()
    .unwrap();
    let expected = fixture_signature();
    let mut nonfailing = |_candidate: &iroh_sim::Scenario| Ok(None);
    assert!(matches!(
        Minimizer::new(MinimizationConfig { max_attempts: 10 }).minimize(
            scenario.clone(),
            expected.clone(),
            &mut nonfailing
        ),
        Err(MinimizationError::InputDoesNotFail)
    ));

    let different = FailureSignature::from_runner_error(
        &RunnerError::TriggerStall(vec!["other".to_owned()]),
        &[],
        4,
    )
    .unwrap();
    let mut changed = |_candidate: &iroh_sim::Scenario| Ok(Some(different.clone()));
    assert!(matches!(
        Minimizer::new(MinimizationConfig { max_attempts: 10 }).minimize(
            scenario.clone(),
            expected.clone(),
            &mut changed
        ),
        Err(MinimizationError::InputSignatureMismatch { .. })
    ));

    let mut same = |_candidate: &iroh_sim::Scenario| Ok(Some(expected.clone()));
    let result = Minimizer::new(MinimizationConfig { max_attempts: 1 })
        .minimize(scenario, expected.clone(), &mut same)
        .unwrap();
    assert!(result.exhausted);
    assert_eq!(result.attempts.len(), 1);
}

fn fixture_signature() -> FailureSignature {
    FailureSignature::from_runner_error(
        &RunnerError::Invariant(InvariantFailure {
            name: InvariantName::DeliveryIntegrity,
            class: InvariantClass::Safety,
            observation_sequence: 5,
            virtual_time_nanos: 10,
            entities: vec!["connection-1".to_owned()],
            evidence: BTreeMap::new(),
        }),
        &[],
        4,
    )
    .unwrap()
}
