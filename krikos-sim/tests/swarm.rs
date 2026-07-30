mod support;

use std::{collections::BTreeSet, sync::Arc, time::SystemTime};

use krikos_runtime::{RootSeed, TraceEventKind};
use support::{
    ActionSchedule, ActionSpec, DiscoveryRecordState, InvariantName, IpFamily,
    NatFilteringBehavior, NatMappingBehavior, ReferencedSwarmSpec, RunnerError,
    SWARM_SCHEMA_VERSION, SafetyLivenessPhases, Scenario, ScenarioAction, ScenarioBuilder,
    ScenarioOperation, ScenarioRunner, SwarmChoice, SwarmMutation, SwarmOption, SwarmSpec,
    SwarmTemplate, TraceBuffer,
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
fn link_capacity_mutations_materialize_and_cannot_expand_base_bounds() {
    let mut spec = fixture();
    let base_link = spec.base.topology.links[0].clone();
    spec.choices = vec![
        SwarmChoice {
            id: "bandwidth".into(),
            options: vec![SwarmOption {
                id: "constrained".into(),
                weight: 1,
                mutation: SwarmMutation::LinkBandwidthBitsPerSecond {
                    link: base_link.id.clone(),
                    bits_per_second: 10_000_000,
                },
            }],
        },
        SwarmChoice {
            id: "queueing".into(),
            options: vec![SwarmOption {
                id: "constrained".into(),
                weight: 1,
                mutation: SwarmMutation::LinkQueuePackets {
                    link: base_link.id.clone(),
                    packets: 32,
                },
            }],
        },
    ];

    spec.validate().unwrap();
    let (scenario, _) = spec.materialize(RootSeed::new([17; 32])).unwrap();
    assert_eq!(scenario.topology.links[0].bits_per_second, 10_000_000);
    assert_eq!(scenario.topology.links[0].queue_packets, 32);

    let mut expanded_bandwidth = spec.clone();
    expanded_bandwidth.choices[0].options[0].mutation = SwarmMutation::LinkBandwidthBitsPerSecond {
        link: base_link.id.clone(),
        bits_per_second: base_link.bits_per_second + 1,
    };
    assert!(expanded_bandwidth.validate().is_err());

    let mut expanded_queue = spec.clone();
    expanded_queue.choices[1].options[0].mutation = SwarmMutation::LinkQueuePackets {
        link: base_link.id,
        packets: base_link.queue_packets + 1,
    };
    assert!(expanded_queue.validate().is_err());
}

#[test]
fn sleep_duration_mutation_is_bounded_and_targets_sleep_actions() {
    let mut base = fixture().base;
    base.actions.push(ActionSpec {
        id: "08-blackhole-hold".into(),
        schedule: ActionSchedule::AfterAction {
            action: "07-stop-server".into(),
        },
        action: ScenarioAction::Sleep { duration_nanos: 1 },
    });
    let base = base.normalized().unwrap();

    let materialized = materialize_one(
        base.clone(),
        SwarmMutation::SleepDurationNanos {
            action: "08-blackhole-hold".into(),
            duration_nanos: 5_000_000,
        },
    );
    assert!(matches!(
        materialized
            .actions
            .iter()
            .find(|action| action.id == "08-blackhole-hold")
            .unwrap()
            .action,
        ScenarioAction::Sleep {
            duration_nanos: 5_000_000
        }
    ));

    for mutation in [
        SwarmMutation::SleepDurationNanos {
            action: "08-blackhole-hold".into(),
            duration_nanos: 0,
        },
        SwarmMutation::SleepDurationNanos {
            action: "08-blackhole-hold".into(),
            duration_nanos: base.budgets.max_virtual_time_nanos + 1,
        },
        SwarmMutation::SleepDurationNanos {
            action: "missing".into(),
            duration_nanos: 1,
        },
        SwarmMutation::SleepDurationNanos {
            action: "04-stream".into(),
            duration_nanos: 1,
        },
    ] {
        assert!(
            single_option_spec(base.clone(), mutation)
                .validate()
                .is_err()
        );
    }
}

#[test]
fn materialization_is_repeatable_domain_separated_and_covers_fixed_options() {
    let mut spec = fixture();
    spec.base.budgets.resources.max_connections = 7;
    spec.base.budgets.resources.max_streams = 3;
    let resources = spec.base.budgets.resources;
    let first = spec.materialize(RootSeed::new([7; 32])).unwrap();
    let second = spec.materialize(RootSeed::new([7; 32])).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.1.choices.len(), 2);
    assert_eq!(first.0.budgets.resources, resources);
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
fn checked_link_impairment_swarm_declares_explicit_blackhole_recovery() {
    let spec = SwarmSpec::from_json(include_bytes!("../swarms/link-impairment.json")).unwrap();
    assert_eq!(
        spec.safety_liveness,
        Some(SafetyLivenessPhases {
            safety_action: "04-partition".into(),
            recovery_action: "08-heal".into(),
            liveness_probe_action: "10-connect-recovered".into(),
        })
    );
    assert!(spec.base.invariants.iter().any(|invariant| {
        invariant.name == InvariantName::ReachableConnectLiveness
            && invariant.deadline_nanos == Some(10_000_000_000)
            && invariant.max_events == Some(50_000)
    }));

    let action = |id: &str| {
        spec.base
            .actions
            .iter()
            .find(|action| action.id == id)
            .unwrap()
    };
    assert!(matches!(
        action("04-partition").action,
        ScenarioAction::Partition {
            ref link,
            ref from,
            ref to,
        } if link == "lan" && from == "client" && to == "server"
    ));
    assert_eq!(
        action("05-send-blackholed").schedule,
        ActionSchedule::AfterAction {
            action: "04-partition".into(),
        }
    );
    assert!(matches!(
        action("05-send-blackholed").action,
        ScenarioAction::SendDatagram {
            ref connection,
            payload: support::PayloadSpec { bytes: 64, fill: 165 },
        } if connection == "c1"
    ));
    assert_eq!(
        action("06-blackhole-hold").schedule,
        ActionSchedule::AfterAction {
            action: "05-send-blackholed".into(),
        }
    );
    assert!(matches!(
        action("06-blackhole-hold").action,
        ScenarioAction::Sleep {
            duration_nanos: 5_000_000
        }
    ));
    assert_eq!(
        action("07-assert-blackholed").schedule,
        ActionSchedule::AfterAction {
            action: "06-blackhole-hold".into(),
        }
    );
    assert!(matches!(
        action("07-assert-blackholed").action,
        ScenarioAction::AssertNoDatagram {
            ref connection,
            duration_nanos: 10_000_000,
        } if connection == "c1"
    ));
    assert_eq!(
        action("08-heal").schedule,
        ActionSchedule::AfterAction {
            action: "07-assert-blackholed".into(),
        }
    );
    assert!(matches!(
        action("08-heal").action,
        ScenarioAction::Heal {
            ref link,
            ref from,
            ref to,
        } if link == "lan" && from == "client" && to == "server"
    ));
    assert_eq!(
        action("09-stream-restored").schedule,
        ActionSchedule::AfterAction {
            action: "08-heal".into(),
        }
    );
    assert!(matches!(
        action("09-stream-restored").action,
        ScenarioAction::StreamRoundTrip {
            ref connection,
            payload: support::PayloadSpec {
                bytes: 65_536,
                fill: 165,
            },
        } if connection == "c1"
    ));
    assert_eq!(
        action("10-connect-recovered").schedule,
        ActionSchedule::AfterAction {
            action: "09-stream-restored".into(),
        }
    );
    assert!(matches!(
        action("10-connect-recovered").action,
        ScenarioAction::Connect { ref connection, .. } if connection == "c2"
    ));
    assert_eq!(
        action("11-stream-recovered").schedule,
        ActionSchedule::AfterAction {
            action: "10-connect-recovered".into(),
        }
    );
    assert!(matches!(
        action("11-stream-recovered").action,
        ScenarioAction::StreamRoundTrip { ref connection, .. } if connection == "c2"
    ));

    let duration = spec
        .choices
        .iter()
        .find(|choice| choice.id == "blackhole-duration")
        .unwrap();
    assert_eq!(
        duration
            .options
            .iter()
            .map(|option| (option.id.as_str(), option.weight, &option.mutation))
            .collect::<Vec<_>>(),
        vec![
            (
                "brief",
                3,
                &SwarmMutation::SleepDurationNanos {
                    action: "06-blackhole-hold".into(),
                    duration_nanos: 5_000_000,
                },
            ),
            (
                "sustained",
                1,
                &SwarmMutation::SleepDurationNanos {
                    action: "06-blackhole-hold".into(),
                    duration_nanos: 250_000_000,
                },
            ),
        ]
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn checked_link_impairment_blackhole_drops_real_traffic_and_fails_open() {
    let spec = SwarmSpec::from_json(include_bytes!("../swarms/link-impairment.json")).unwrap();
    let trace = Arc::new(TraceBuffer::default());
    ScenarioRunner::deterministic(
        spec.base.clone(),
        RootSeed::new([71; 32]),
        SystemTime::UNIX_EPOCH,
        trace.clone(),
    )
    .unwrap()
    .run()
    .await
    .unwrap();
    assert!(trace.events().iter().any(|event| matches!(
        &event.event,
        TraceEventKind::PacketOutcome { outcome } if outcome == "dropped:partition"
    )));

    let mut fails_open = spec.base;
    fails_open
        .actions
        .iter_mut()
        .find(|action| action.id == "04-partition")
        .unwrap()
        .action = ScenarioAction::Heal {
        link: "lan".into(),
        from: "client".into(),
        to: "server".into(),
    };
    fails_open
        .fault_rules
        .iter_mut()
        .find(|rule| rule.id == "reordering")
        .unwrap()
        .probability_per_million = 1_000_000;
    for ordinal in 0..64u32 {
        let mut seed_bytes = [0; 32];
        seed_bytes[..4].copy_from_slice(&ordinal.to_le_bytes());
        let error = ScenarioRunner::deterministic(
            fails_open.clone(),
            RootSeed::new(seed_bytes),
            SystemTime::UNIX_EPOCH,
            Arc::new(TraceBuffer::default()),
        )
        .unwrap()
        .run()
        .await
        .unwrap_err();
        assert!(
            matches!(error, RunnerError::Operation(message) if message.contains("unexpected datagram delivery")),
            "fail-open seed ordinal {ordinal} did not report unexpected datagram delivery"
        );
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
        let expected_combinations: usize = spec
            .choices
            .iter()
            .map(|choice| choice.options.len())
            .product();
        let mut executed = BTreeSet::new();
        for ordinal in 0..4096u32 {
            let mut seed_bytes = [0; 32];
            seed_bytes[..4].copy_from_slice(&ordinal.to_le_bytes());
            let seed = RootSeed::new(seed_bytes);
            let (scenario, selection) = spec.materialize(seed).unwrap();
            let selection_key = selection
                .choices
                .iter()
                .map(|choice| format!("{}/{}", choice.choice_id, choice.option_id))
                .collect::<Vec<_>>();
            if !executed.insert(selection_key.clone()) {
                continue;
            }
            let trace = Arc::new(TraceBuffer::default());
            ScenarioRunner::deterministic(scenario, seed, SystemTime::UNIX_EPOCH, trace)
                .unwrap()
                .run()
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "{} combination {selection_key:?} selected by seed ordinal {ordinal} failed: {error}",
                        spec.id
                    )
                });
            if executed.len() == expected_combinations {
                break;
            }
        }
        assert_eq!(
            executed.len(),
            expected_combinations,
            "{} option-combination runs",
            spec.id
        );
    }
}

fn domain_template_fixtures() -> [(&'static [u8], &'static [u8]); 6] {
    [
        (include_bytes!("../swarms/link-impairment.json"), &[]),
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
