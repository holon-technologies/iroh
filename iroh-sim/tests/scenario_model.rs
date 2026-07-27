use std::time::Duration;

use iroh_runtime::RootSeed;
use iroh_sim::{
    ActionSchedule, ActionSpec, DiscoveryProviderSpec, DiscoveryRecordState, GeneratorConfig,
    IpFamily, NatFilteringBehavior, NatMappingBehavior, NatSpec, ObservationTrigger,
    RelayImpairmentSpec, RelayProtocolVersion, RelaySpec, SCENARIO_SCHEMA_VERSION, Scenario,
    ScenarioAction, ScenarioBuilder, ScenarioGenerator, ScenarioModelError, ScenarioOperation,
    ScenarioResourceLimits,
};
use proptest::prelude::*;

#[test]
fn strict_v3_fixture_matches_the_rust_builder_and_round_trips_canonically() {
    let fixture = include_bytes!("fixtures/v2-ipv4-stream.json");
    let parsed = Scenario::from_json(fixture).unwrap();
    let built = ScenarioBuilder::direct_ip_echo(
        "direct-ip/v2-ipv4-stream",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap()
    .build()
    .unwrap();

    assert_eq!(parsed, built);
    assert_eq!(parsed.schema_version, SCENARIO_SCHEMA_VERSION);
    let canonical = parsed.to_canonical_json().unwrap();
    assert_eq!(Scenario::from_json(&canonical).unwrap(), parsed);
    assert_eq!(canonical, parsed.to_canonical_json().unwrap());
}

#[test]
fn v3_resource_limits_are_required_strict_and_allow_zero_live_capacity() {
    let mut scenario = ScenarioBuilder::direct_ip_echo(
        "schema/resource-limits",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap()
    .build()
    .unwrap();
    scenario.budgets.resources = ScenarioResourceLimits {
        max_scheduled_events: 1,
        max_trace_events: 1,
        max_timers: 0,
        max_sockets: 0,
        max_connections: 0,
        max_streams: 0,
        max_relays: 0,
    };
    scenario.validate().unwrap();

    scenario.budgets.resources.max_scheduled_events = 0;
    assert!(matches!(
        scenario.validate(),
        Err(ScenarioModelError::InvalidBudgets)
    ));
    scenario.budgets.resources.max_scheduled_events = 1;
    scenario.budgets.resources.max_trace_events = 0;
    assert!(matches!(
        scenario.validate(),
        Err(ScenarioModelError::InvalidBudgets)
    ));

    let mut encoded = serde_json::to_value(
        ScenarioBuilder::direct_ip_echo(
            "schema/resource-limits-strict",
            IpFamily::Ipv4,
            ScenarioOperation::Stream,
        )
        .unwrap()
        .build()
        .unwrap(),
    )
    .unwrap();
    encoded["budgets"]["resources"]["surprise"] = serde_json::json!(1);
    assert!(matches!(
        Scenario::from_json(&serde_json::to_vec(&encoded).unwrap()),
        Err(ScenarioModelError::Json(_))
    ));
}

#[test]
fn v2_documents_migrate_exact_resource_limits_and_are_not_current_schema() {
    let fixture = include_bytes!("fixtures/schema-v2-ipv4-stream.json");
    assert!(matches!(
        Scenario::from_json(fixture),
        Err(ScenarioModelError::UnsupportedSchema(2))
    ));

    let migrated = Scenario::from_versioned_json(fixture).unwrap();
    assert_eq!(migrated.schema_version, 3);
    assert_eq!(
        migrated.budgets.resources,
        ScenarioResourceLimits {
            max_scheduled_events: 100_000,
            max_trace_events: 200_000,
            max_timers: 100_000,
            max_sockets: 100_000,
            max_connections: 64,
            max_streams: 64,
            max_relays: 1,
        }
    );
}

#[test]
fn sleep_actions_are_positive_bounded_and_counted_in_inventory() {
    let mut scenario =
        ScenarioBuilder::direct_ip_echo("schema/sleep", IpFamily::Ipv4, ScenarioOperation::Stream)
            .unwrap()
            .build()
            .unwrap();
    scenario.actions.push(ActionSpec {
        id: "08-sleep".to_owned(),
        schedule: ActionSchedule::At { nanos: 0 },
        action: ScenarioAction::Sleep { duration_nanos: 1 },
    });
    scenario.validate().unwrap();
    assert_eq!(
        iroh_sim::ScenarioInventory::from_scenario(&scenario).sleep_actions,
        1
    );

    scenario.actions.last_mut().unwrap().action = ScenarioAction::Sleep { duration_nanos: 0 };
    assert!(matches!(
        scenario.validate(),
        Err(ScenarioModelError::InvalidAction("sleep"))
    ));
    scenario.actions.last_mut().unwrap().action = ScenarioAction::Sleep {
        duration_nanos: scenario.budgets.max_virtual_time_nanos + 1,
    };
    assert!(matches!(
        scenario.validate(),
        Err(ScenarioModelError::InvalidAction("sleep"))
    ));
}

#[test]
fn datagram_probe_actions_validate_connection_payload_and_round_trip() {
    let mut scenario = ScenarioBuilder::direct_ip_echo(
        "schema/datagram-probe",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap()
    .build()
    .unwrap();
    scenario.actions.extend([
        ActionSpec {
            id: "08-send-datagram".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "03-connect".to_owned(),
            },
            action: ScenarioAction::SendDatagram {
                connection: "c1".to_owned(),
                payload: iroh_sim::PayloadSpec { bytes: 64, fill: 7 },
            },
        },
        ActionSpec {
            id: "09-assert-no-datagram".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "08-send-datagram".to_owned(),
            },
            action: ScenarioAction::AssertNoDatagram {
                connection: "c1".to_owned(),
                duration_nanos: 10_000_000,
            },
        },
    ]);
    scenario.validate().unwrap();
    let encoded = scenario.to_canonical_json().unwrap();
    assert_eq!(Scenario::from_json(&encoded).unwrap(), scenario);

    let mut invalid_payload = scenario.clone();
    let ScenarioAction::SendDatagram { payload, .. } = &mut invalid_payload.actions[7].action
    else {
        panic!("datagram probe action ordering changed");
    };
    payload.bytes = 0;
    assert!(matches!(
        invalid_payload.validate(),
        Err(ScenarioModelError::InvalidPayload(0))
    ));

    for duration_nanos in [0, scenario.budgets.max_virtual_time_nanos + 1] {
        let mut invalid_duration = scenario.clone();
        let ScenarioAction::AssertNoDatagram {
            duration_nanos: candidate,
            ..
        } = &mut invalid_duration.actions[8].action
        else {
            panic!("datagram probe action ordering changed");
        };
        *candidate = duration_nanos;
        assert!(matches!(
            invalid_duration.validate(),
            Err(ScenarioModelError::InvalidAction("assert_no_datagram"))
        ));
    }

    for index in [7, 8] {
        let mut dangling = scenario.clone();
        match &mut dangling.actions[index].action {
            ScenarioAction::SendDatagram { connection, .. }
            | ScenarioAction::AssertNoDatagram { connection, .. } => {
                *connection = "missing".to_owned();
            }
            _ => panic!("datagram probe action ordering changed"),
        }
        assert!(matches!(
            dangling.validate(),
            Err(ScenarioModelError::UnknownConnection(_))
        ));
    }
}

#[test]
fn relay_schema_requires_declared_bounded_relays_and_resolves_lifecycle_actions() {
    let mut scenario =
        ScenarioBuilder::direct_ip_echo("schema/relay", IpFamily::Ipv4, ScenarioOperation::Stream)
            .unwrap()
            .build()
            .unwrap();
    scenario.requirements.relay = true;
    scenario.topology.relays.push(RelaySpec {
        id: "home".to_owned(),
        url: "https://home-relay.invalid".to_owned(),
        online: true,
        max_sessions: 8,
        byte_capacity: 65_536,
        protocol_version: RelayProtocolVersion::V2,
    });
    scenario.actions.push(ActionSpec {
        id: "08-relay-offline".to_owned(),
        schedule: ActionSchedule::At { nanos: 0 },
        action: ScenarioAction::RelayLifecycle {
            relay: "home".to_owned(),
            online: false,
        },
    });
    scenario
        .topology
        .relay_impairments
        .push(RelayImpairmentSpec {
            relay: "home".to_owned(),
            connection_delay_nanos: 1_000_000,
            reject_connect_attempts: vec![1, 3],
            drop_every_nth_packet: Some(5),
            ..RelayImpairmentSpec::default()
        });
    scenario.validate().unwrap();

    let mut unknown = scenario.clone();
    let ScenarioAction::RelayLifecycle { relay, .. } =
        &mut unknown.actions.last_mut().unwrap().action
    else {
        unreachable!();
    };
    *relay = "missing".to_owned();
    assert!(matches!(
        unknown.validate(),
        Err(ScenarioModelError::UnknownRelay(_))
    ));

    let mut invalid_impairment = scenario.clone();
    invalid_impairment.topology.relay_impairments[0].drop_every_nth_packet = Some(0);
    assert!(matches!(
        invalid_impairment.validate(),
        Err(ScenarioModelError::InvalidRelay(_))
    ));

    let mut unbounded = scenario;
    unbounded.topology.relays[0].max_sessions = 0;
    assert!(matches!(
        unbounded.validate(),
        Err(ScenarioModelError::InvalidRelay(_))
    ));
}

#[test]
fn schema_rejects_unknown_fields_dangling_references_and_missing_capabilities() {
    let unknown = br#"{
        "schema_version": 3,
        "metadata": {"id": "bad", "description": "", "tags": []},
        "requirements": {"controlled_runtime": true, "virtual_time": true,
          "synthetic_ip": true, "nat": false, "relay": false, "discovery": false,
          "mobility": false},
        "budgets": {"max_events": 1, "max_virtual_time_nanos": 1, "max_tasks": 1,
          "max_packets": 1, "max_obligations": 1, "max_actions": 1,
          "max_payload_bytes": 1, "resources": {"max_scheduled_events": 1,
          "max_trace_events": 1, "max_timers": 0, "max_sockets": 0,
          "max_connections": 0, "max_streams": 0, "max_relays": 0}},
        "topology": {"hosts": [], "links": []}, "endpoints": [], "actions": [],
        "fault_rules": [], "fairness": [],
        "completion": {"kind": "all_actions", "shutdown_deadline_nanos": 1},
        "allowed_terminals": ["success"], "invariants": [], "surprise": true
    }"#;
    assert!(matches!(
        Scenario::from_json(unknown),
        Err(ScenarioModelError::Json(_))
    ));

    let mut dangling = ScenarioBuilder::direct_ip_echo(
        "direct-ip/dangling",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap()
    .build()
    .unwrap();
    let iroh_sim::ScenarioAction::Connect { connection, .. } = &mut dangling.actions[2].action
    else {
        panic!("builder action ordering changed");
    };
    *connection = "missing".to_owned();
    assert!(matches!(
        dangling.validate(),
        Err(ScenarioModelError::UnknownConnection(_))
    ));

    let mut capability = dangling;
    capability.actions[2].action = iroh_sim::ScenarioAction::NatChange {
        nat: "home".to_owned(),
        public_ip: "203.0.113.7".to_owned(),
        preserve_ports: false,
    };
    assert!(matches!(
        capability.validate(),
        Err(ScenarioModelError::MissingCapability("nat"))
    ));

    let mut trigger = ScenarioBuilder::direct_ip_echo(
        "direct-ip/dangling-trigger",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap()
    .build()
    .unwrap();
    trigger.actions[0].schedule = ActionSchedule::AfterObservation {
        observation: ObservationTrigger::EndpointState {
            endpoint: "missing".to_owned(),
            state: "running".to_owned(),
        },
    };
    assert!(matches!(
        trigger.validate(),
        Err(ScenarioModelError::UnknownEndpoint(_))
    ));
}

#[test]
fn nat_topology_rejects_cycles_unknown_gateways_and_ambiguous_roots() {
    let scenario = || {
        let mut scenario = ScenarioBuilder::direct_ip_echo(
            "schema/nat-chain",
            IpFamily::Ipv4,
            ScenarioOperation::Stream,
        )
        .unwrap()
        .build()
        .unwrap();
        scenario.requirements.nat = true;
        scenario
    };
    let nat = |id: &str, upstream: Option<&str>, public_ip: &str| NatSpec {
        id: id.to_owned(),
        inside_host: "client".to_owned(),
        upstream_nat: upstream.map(str::to_owned),
        public_ip: public_ip.to_owned(),
        port_start: 40_000,
        port_end: 40_127,
        mapping_behavior: NatMappingBehavior::EndpointIndependent,
        filtering_behavior: NatFilteringBehavior::EndpointIndependent,
        mapping_ttl_nanos: 1_000_000_000,
        hairpin: true,
        max_mappings: 128,
        firewall: None,
    };

    let mut cyclic = scenario();
    cyclic.topology.nats = vec![
        nat("home", Some("carrier"), "203.0.113.7"),
        nat("carrier", Some("home"), "198.18.0.1"),
    ];
    assert!(matches!(
        cyclic.validate(),
        Err(ScenarioModelError::InvalidNat(_))
    ));

    let mut unknown = scenario();
    unknown.topology.nats = vec![nat("home", Some("missing"), "203.0.113.7")];
    assert!(matches!(
        unknown.validate(),
        Err(ScenarioModelError::UnknownNat(_))
    ));

    let mut ambiguous = scenario();
    ambiguous.topology.nats = vec![
        nat("first", None, "203.0.113.7"),
        nat("second", None, "203.0.113.8"),
    ];
    assert!(matches!(
        ambiguous.validate(),
        Err(ScenarioModelError::InvalidNat(_))
    ));
}

#[test]
fn discovery_schema_requires_declared_bounded_providers_and_strict_record_shapes() {
    let mut scenario = ScenarioBuilder::direct_ip_echo(
        "schema/discovery",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap()
    .build()
    .unwrap();
    scenario.requirements.discovery = true;
    scenario.topology.discovery.push(DiscoveryProviderSpec {
        id: "primary".to_owned(),
        max_records: 8,
    });
    scenario.actions.push(ActionSpec {
        id: "08-discovery".to_owned(),
        schedule: ActionSchedule::At { nanos: 0 },
        action: ScenarioAction::DiscoveryUpdate {
            provider: "primary".to_owned(),
            record: "server".to_owned(),
            endpoint: "server".to_owned(),
            addresses: vec!["192.0.2.2:31002".to_owned()],
            delay_nanos: 20,
            ttl_nanos: 10,
            state: DiscoveryRecordState::Published,
        },
    });
    scenario.validate().unwrap();

    let mut unknown = scenario.clone();
    let ScenarioAction::DiscoveryUpdate { provider, .. } =
        &mut unknown.actions.last_mut().unwrap().action
    else {
        unreachable!();
    };
    *provider = "missing".to_owned();
    assert!(matches!(
        unknown.validate(),
        Err(ScenarioModelError::UnknownDiscovery(_))
    ));

    let mut invalid = scenario;
    let ScenarioAction::DiscoveryUpdate {
        addresses,
        ttl_nanos,
        state,
        ..
    } = &mut invalid.actions.last_mut().unwrap().action
    else {
        unreachable!();
    };
    addresses.clear();
    *ttl_nanos = 1;
    *state = DiscoveryRecordState::Published;
    assert!(matches!(
        invalid.validate(),
        Err(ScenarioModelError::InvalidDiscovery(_))
    ));
}

#[test]
fn generated_scenarios_are_domain_reproducible_and_bounded() {
    let config = GeneratorConfig {
        max_actions: 16,
        max_payload_bytes: 4_096,
        max_virtual_time: Duration::from_secs(10),
    };
    let first = ScenarioGenerator::new(RootSeed::new([9; 32]), config.clone())
        .generate("generated/9")
        .unwrap();
    let second = ScenarioGenerator::new(RootSeed::new([9; 32]), config)
        .generate("generated/9")
        .unwrap();

    assert_eq!(first, second);
    assert!(first.actions.len() <= 16);
    assert_eq!(first.budgets.resources.max_connections, 16);
    assert_eq!(first.budgets.resources.max_streams, 16);
    assert!(first.actions.iter().all(|action| {
        action
            .schedule
            .deadline_nanos()
            .is_none_or(|value| value <= 10_000_000_000)
    }));
    first.validate().unwrap();
}

#[test]
fn legacy_stage_two_documents_migrate_explicitly_to_v3() {
    for (fixture, operation) in [
        (
            include_bytes!("fixtures/ipv4-stream.json").as_slice(),
            ScenarioOperation::Stream,
        ),
        (
            include_bytes!("fixtures/ipv6-stream.json").as_slice(),
            ScenarioOperation::Stream,
        ),
        (
            include_bytes!("fixtures/ipv6-datagram.json").as_slice(),
            ScenarioOperation::Datagram,
        ),
        (
            include_bytes!("fixtures/ipv4-stream-loss.json").as_slice(),
            ScenarioOperation::Stream,
        ),
        (
            include_bytes!("fixtures/ipv4-stream-corruption.json").as_slice(),
            ScenarioOperation::Stream,
        ),
    ] {
        let migrated = Scenario::from_versioned_json(fixture).unwrap();
        assert_eq!(migrated.schema_version, SCENARIO_SCHEMA_VERSION);
        assert!(migrated.metadata.tags.contains(&"migrated-v1".to_owned()));
        assert!(migrated.actions.iter().any(|action| matches!(
            (&action.action, operation),
            (
                iroh_sim::ScenarioAction::StreamRoundTrip { .. },
                ScenarioOperation::Stream
            ) | (
                iroh_sim::ScenarioAction::DatagramRoundTrip { .. },
                ScenarioOperation::Datagram
            )
        )));
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn canonical_parse_encode_is_idempotent(seed in any::<[u8; 32]>(), ordinal in 0u64..1_000) {
        let scenario = ScenarioGenerator::new(
            RootSeed::new(seed),
            GeneratorConfig {
                max_actions: 16,
                max_payload_bytes: 8_192,
                max_virtual_time: Duration::from_secs(30),
            },
        )
        .generate(&format!("generated/{ordinal}"))
        .unwrap();
        let first = scenario.to_canonical_json().unwrap();
        let reparsed = Scenario::from_json(&first).unwrap();
        let second = reparsed.to_canonical_json().unwrap();
        prop_assert_eq!(first, second);
    }
}
