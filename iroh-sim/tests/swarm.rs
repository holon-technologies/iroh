use std::{collections::BTreeSet, sync::Arc, time::SystemTime};

use iroh_runtime::RootSeed;
use iroh_sim::{
    ActionSchedule, DiscoveryRecordState, InvariantName, IpFamily, NatFilteringBehavior,
    NatMappingBehavior, ReferencedSwarmSpec, SWARM_SCHEMA_VERSION, SafetyLivenessPhases, Scenario,
    ScenarioAction, ScenarioBuilder, ScenarioOperation, ScenarioRunner, SwarmChoice, SwarmMutation,
    SwarmOption, SwarmSpec, SwarmTemplate, TraceBuffer,
};

fn fixture() -> SwarmSpec {
    let base =
        ScenarioBuilder::direct_ip_echo("swarm/base", IpFamily::Ipv4, ScenarioOperation::Stream)
            .unwrap()
            .build()
            .unwrap();
    SwarmSpec {
        schema_version: SWARM_SCHEMA_VERSION,
        id: "direct-smoke".into(),
        base,
        safety_liveness: None,
        choices: vec![
            SwarmChoice {
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
            },
            SwarmChoice {
                id: "payload".into(),
                options: vec![
                    SwarmOption {
                        id: "large".into(),
                        weight: 1,
                        mutation: SwarmMutation::PayloadBytes {
                            action: "04-stream".into(),
                            bytes: 4_096,
                        },
                    },
                    SwarmOption {
                        id: "small".into(),
                        weight: 1,
                        mutation: SwarmMutation::PayloadBytes {
                            action: "04-stream".into(),
                            bytes: 1,
                        },
                    },
                ],
            },
        ],
    }
}

#[test]
fn strict_schema_rejects_unknown_noncanonical_unbounded_and_dangling_input() {
    let spec = fixture();
    let bytes = spec.to_canonical_json().unwrap();
    assert_eq!(SwarmSpec::from_json(&bytes).unwrap(), spec);
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["unknown"] = true.into();
    assert!(SwarmSpec::from_json(&serde_json::to_vec(&value).unwrap()).is_err());

    let mut invalid = fixture();
    invalid.choices.reverse();
    assert!(invalid.validate().is_err());
    let mut invalid = fixture();
    invalid.choices[0].options[0].weight = 0;
    assert!(invalid.validate().is_err());
    let mut invalid = fixture();
    invalid.choices[0].options[0].mutation = SwarmMutation::LinkMtu {
        link: "missing".into(),
        mtu: 1_500,
    };
    assert!(invalid.validate().is_err());
}

#[test]
fn materialization_is_repeatable_domain_separated_and_covers_fixed_options() {
    let spec = fixture();
    let first = spec.materialize(RootSeed::new([7; 32])).unwrap();
    let second = spec.materialize(RootSeed::new([7; 32])).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.1.choices.len(), 2);
    assert!(
        first
            .0
            .metadata
            .tags
            .contains(&"swarm-direct-smoke".to_owned())
    );

    let mut latency = BTreeSet::new();
    let mut payload = BTreeSet::new();
    for byte in 0..64u8 {
        let (_, selection) = spec.materialize(RootSeed::new([byte; 32])).unwrap();
        latency.insert(selection.choices[0].option_id.clone());
        payload.insert(selection.choices[1].option_id.clone());
    }
    assert_eq!(latency, BTreeSet::from(["fast".into(), "slow".into()]));
    assert_eq!(payload, BTreeSet::from(["large".into(), "small".into()]));
}

#[test]
fn checked_direct_swarm_is_valid_and_bounded() {
    let spec = SwarmSpec::from_json(include_bytes!("../swarms/direct-smoke.json")).unwrap();
    assert_eq!(spec.id, "direct-smoke");
    assert_eq!(spec.choices.len(), 3);
    for ordinal in 0..8u8 {
        let (scenario, selection) = spec.materialize(RootSeed::new([ordinal; 32])).unwrap();
        assert_eq!(selection.choices.len(), spec.choices.len());
        scenario.validate().unwrap();
    }
}

#[test]
fn checked_domain_templates_resolve_and_fixed_seeds_cover_every_option() {
    for (template_bytes, base_bytes) in domain_template_fixtures() {
        let spec = SwarmTemplate::from_json(template_bytes)
            .unwrap()
            .resolve(base_bytes)
            .unwrap();
        let expected: BTreeSet<(String, String)> = spec
            .choices
            .iter()
            .flat_map(|choice| {
                choice
                    .options
                    .iter()
                    .map(|option| (choice.id.clone(), option.id.clone()))
            })
            .collect();
        let mut observed = BTreeSet::new();
        for byte in 0..=u8::MAX {
            let (scenario, selection) = spec.materialize(RootSeed::new([byte; 32])).unwrap();
            scenario.validate().unwrap();
            observed.extend(
                selection
                    .choices
                    .into_iter()
                    .map(|choice| (choice.choice_id, choice.option_id)),
            );
        }
        assert_eq!(
            observed, expected,
            "incomplete option coverage for {}",
            spec.id
        );
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn every_checked_domain_option_executes_to_success() {
    for (template_bytes, base_bytes) in domain_template_fixtures() {
        let spec = SwarmTemplate::from_json(template_bytes)
            .unwrap()
            .resolve(base_bytes)
            .unwrap();
        let mut executed = BTreeSet::new();
        for byte in 0..=u8::MAX {
            let seed = RootSeed::new([byte; 32]);
            let (scenario, selection) = spec.materialize(seed).unwrap();
            let selection_key = selection
                .choices
                .iter()
                .map(|choice| format!("{}/{}", choice.choice_id, choice.option_id))
                .collect::<Vec<_>>();
            if !executed.insert(selection_key) {
                continue;
            }
            let trace = Arc::new(TraceBuffer::default());
            ScenarioRunner::deterministic(scenario, seed, SystemTime::UNIX_EPOCH, trace)
                .unwrap()
                .run()
                .await
                .unwrap_or_else(|error| panic!("{} option failed: {error}", spec.id));
        }
        let expected_options: usize = spec.choices.iter().map(|choice| choice.options.len()).sum();
        assert_eq!(executed.len(), expected_options, "{} option runs", spec.id);
    }
}

fn domain_template_fixtures() -> [(&'static [u8], &'static [u8]); 5] {
    [
        (
            include_bytes!("../swarms/nat-behavior.json"),
            include_bytes!("../corpus/stage4-nat-rebind-expiry/scenario.json"),
        ),
        (
            include_bytes!("../swarms/discovery-timing.json"),
            include_bytes!("../corpus/stage4-discovery-conflict/scenario.json"),
        ),
        (
            include_bytes!("../swarms/mobility-timing.json"),
            include_bytes!("fixtures/stage4-mobility.json"),
        ),
        (
            include_bytes!("../swarms/relay-lifecycle.json"),
            include_bytes!("../corpus/stage5-relay-restart/scenario.json"),
        ),
        (
            include_bytes!("../swarms/ready-order-pressure.json"),
            include_bytes!("../corpus/stage6-rare-ready-order/scenario.json"),
        ),
    ]
}

#[test]
fn referenced_template_resolves_only_the_digest_bound_canonical_base() {
    let base = ScenarioBuilder::direct_ip_echo(
        "swarm/referenced",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap()
    .build()
    .unwrap();
    let base_bytes = base.to_canonical_json().unwrap();
    let referenced = ReferencedSwarmSpec {
        schema_version: SWARM_SCHEMA_VERSION,
        id: "referenced".into(),
        base_path: "iroh-sim/corpus/referenced/scenario.json".into(),
        base_blake3: blake3::hash(&base_bytes).to_hex().to_string(),
        safety_liveness: None,
        choices: fixture().choices,
    };
    let bytes = referenced.to_canonical_json().unwrap();
    let parsed = SwarmTemplate::from_json(&bytes).unwrap();
    assert_eq!(parsed.base_path(), Some(referenced.base_path.as_str()));
    assert_eq!(parsed.resolve(&base_bytes).unwrap().base, base);

    let mut corrupt = base_bytes;
    corrupt.push(b' ');
    assert!(parsed.resolve(&corrupt).is_err());
}

#[test]
fn referenced_template_rejects_host_absolute_traversal_and_malformed_digest() {
    let valid = ReferencedSwarmSpec {
        schema_version: SWARM_SCHEMA_VERSION,
        id: "referenced".into(),
        base_path: "iroh-sim/corpus/referenced/scenario.json".into(),
        base_blake3: "00".repeat(32),
        safety_liveness: None,
        choices: fixture().choices,
    };
    for path in [
        "../outside.json",
        "/tmp/outside.json",
        "https://example.com/scenario.json",
        "iroh-sim/corpus/./scenario.json",
    ] {
        let mut invalid = valid.clone();
        invalid.base_path = path.into();
        assert!(invalid.validate().is_err(), "accepted {path:?}");
    }
    let mut invalid = valid;
    invalid.base_blake3 = "not-a-digest".into();
    assert!(invalid.validate().is_err());
}

#[test]
fn domain_mutations_cover_nat_discovery_mobility_relay_and_ready_pressure() {
    let nat = materialize_one(
        Scenario::from_json(include_bytes!(
            "../corpus/stage4-nat-rebind-expiry/scenario.json"
        ))
        .unwrap(),
        SwarmMutation::NatBehavior {
            nat: "edge".into(),
            mapping: NatMappingBehavior::AddressAndPortDependent,
            filtering: NatFilteringBehavior::EndpointIndependent,
        },
    );
    assert_eq!(
        nat.topology.nats[0].mapping_behavior,
        NatMappingBehavior::AddressAndPortDependent
    );
    assert_eq!(
        nat.topology.nats[0].filtering_behavior,
        NatFilteringBehavior::EndpointIndependent
    );

    let discovery = materialize_one(
        Scenario::from_json(include_bytes!(
            "../corpus/stage4-discovery-conflict/scenario.json"
        ))
        .unwrap(),
        SwarmMutation::DiscoveryTiming {
            action: "04-good-record".into(),
            delay_nanos: 7_000_000,
            ttl_nanos: 11_000_000,
            state: DiscoveryRecordState::Published,
        },
    );
    assert!(matches!(
        discovery
            .actions
            .iter()
            .find(|item| item.id == "04-good-record")
            .unwrap()
            .action,
        ScenarioAction::DiscoveryUpdate {
            delay_nanos: 7_000_000,
            ttl_nanos: 11_000_000,
            state: DiscoveryRecordState::Published,
            ..
        }
    ));

    let mobility = materialize_one(
        Scenario::from_json(include_bytes!("fixtures/stage4-mobility.json")).unwrap(),
        SwarmMutation::ActionAtNanos {
            action: "05-old-uplink-down".into(),
            nanos: 5_000_000,
        },
    );
    assert_eq!(
        mobility
            .actions
            .iter()
            .find(|item| item.id == "05-old-uplink-down")
            .unwrap()
            .schedule,
        ActionSchedule::At { nanos: 5_000_000 }
    );

    let relay = materialize_one(
        Scenario::from_json(include_bytes!(
            "../corpus/stage5-relay-restart/scenario.json"
        ))
        .unwrap(),
        SwarmMutation::RelayImpairment {
            relay: "home".into(),
            connection_delay_nanos: 2_000_000,
            drop_every_nth_packet: Some(7),
        },
    );
    assert_eq!(
        relay.topology.relay_impairments[0].connection_delay_nanos,
        2_000_000
    );
    assert_eq!(
        relay.topology.relay_impairments[0].drop_every_nth_packet,
        Some(7)
    );

    let pressure = materialize_one(
        Scenario::from_json(include_bytes!(
            "../corpus/stage6-rare-ready-order/scenario.json"
        ))
        .unwrap(),
        SwarmMutation::CoSchedule {
            actions: vec![
                "01-start-client".into(),
                "02-start-server".into(),
                "03-connect".into(),
            ],
            nanos: 9_000,
        },
    );
    let co_scheduled = ["01-start-client", "02-start-server", "03-connect"];
    assert!(
        pressure
            .actions
            .iter()
            .filter(|item| co_scheduled.contains(&item.id.as_str()))
            .all(|item| item.schedule == ActionSchedule::At { nanos: 9_000 })
    );
}

#[test]
fn domain_mutations_reject_invalid_bounds_shapes_ordering_and_references() {
    let direct =
        ScenarioBuilder::direct_ip_echo("swarm/invalid", IpFamily::Ipv4, ScenarioOperation::Stream)
            .unwrap()
            .build()
            .unwrap();
    assert!(
        single_option_spec(
            direct.clone(),
            SwarmMutation::ActionAtNanos {
                action: "04-stream".into(),
                nanos: direct.budgets.max_virtual_time_nanos + 1,
            },
        )
        .validate()
        .is_err()
    );
    assert!(
        single_option_spec(
            direct,
            SwarmMutation::CoSchedule {
                actions: vec!["04-stream".into(), "04-stream".into()],
                nanos: 1,
            },
        )
        .validate()
        .is_err()
    );

    let discovery = Scenario::from_json(include_bytes!(
        "../corpus/stage4-discovery-conflict/scenario.json"
    ))
    .unwrap();
    assert!(
        single_option_spec(
            discovery,
            SwarmMutation::DiscoveryTiming {
                action: "04-good-record".into(),
                delay_nanos: 0,
                ttl_nanos: 0,
                state: DiscoveryRecordState::Withdrawn,
            },
        )
        .validate()
        .is_err()
    );

    let relay = Scenario::from_json(include_bytes!(
        "../corpus/stage5-relay-restart/scenario.json"
    ))
    .unwrap();
    assert!(
        single_option_spec(
            relay,
            SwarmMutation::RelayImpairment {
                relay: "home".into(),
                connection_delay_nanos: 0,
                drop_every_nth_packet: Some(0),
            },
        )
        .validate()
        .is_err()
    );

    let nat = Scenario::from_json(include_bytes!(
        "../corpus/stage4-nat-rebind-expiry/scenario.json"
    ))
    .unwrap();
    assert!(
        single_option_spec(
            nat,
            SwarmMutation::NatBehavior {
                nat: "missing".into(),
                mapping: NatMappingBehavior::EndpointIndependent,
                filtering: NatFilteringBehavior::EndpointIndependent,
            },
        )
        .validate()
        .is_err()
    );
}

#[test]
fn safety_liveness_phases_require_matching_recovery_fairness_and_bounded_probe() {
    let base = Scenario::from_json(include_bytes!(
        "../corpus/stage5-relay-restart/scenario.json"
    ))
    .unwrap();
    let phases = SafetyLivenessPhases {
        safety_action: "05-relay-offline".into(),
        recovery_action: "06-relay-online".into(),
        liveness_probe_action: "08-connect-recovered".into(),
    };
    let mut spec = single_option_spec(
        base.clone(),
        SwarmMutation::RelayImpairment {
            relay: "home".into(),
            connection_delay_nanos: 0,
            drop_every_nth_packet: None,
        },
    );
    spec.safety_liveness = Some(phases.clone());
    spec.validate().unwrap();
    let (_, selection) = spec.materialize(RootSeed::new([19; 32])).unwrap();
    assert_eq!(selection.safety_liveness, Some(phases));

    let mut invalid = spec.clone();
    invalid
        .base
        .invariants
        .retain(|invariant| invariant.name != InvariantName::ReachableConnectLiveness);
    assert!(invalid.validate().is_err());
    let mut invalid = spec;
    invalid.safety_liveness.as_mut().unwrap().recovery_action = "05-relay-offline".into();
    assert!(invalid.validate().is_err());
}

fn materialize_one(base: Scenario, mutation: SwarmMutation) -> Scenario {
    single_option_spec(base, mutation)
        .materialize(RootSeed::new([42; 32]))
        .unwrap()
        .0
}

fn single_option_spec(base: Scenario, mutation: SwarmMutation) -> SwarmSpec {
    SwarmSpec {
        schema_version: SWARM_SCHEMA_VERSION,
        id: "domain-mutation".into(),
        base,
        safety_liveness: None,
        choices: vec![SwarmChoice {
            id: "choice".into(),
            options: vec![SwarmOption {
                id: "selected".into(),
                weight: 1,
                mutation,
            }],
        }],
    }
}
