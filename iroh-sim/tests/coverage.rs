mod support;

use std::collections::BTreeMap;

use support::{
    BehaviorTransition, ConnectionId, ConnectionState, CoverageError, CoverageLedger,
    CoverageObservation, CoveragePhase, CoveragePolicy, CryptoMode, EndpointId, EndpointState,
    InvariantName, OBSERVATION_SCHEMA_VERSION, Observation, ObservationKind, OperationId,
    SafetyLivenessPhases, SwarmSpec,
};

fn direct_swarm() -> SwarmSpec {
    SwarmSpec::from_json(include_bytes!("../swarms/direct-smoke.json")).unwrap()
}

fn policy_json(domain_id: &str, swarm_id: &str) -> Vec<u8> {
    format!(
        r#"{{
  "schema_version": 2,
  "id": "test-policy",
  "rolling_window_days": 7,
  "providers": ["deterministic_test", "production_provider"],
  "lanes": [
    {{"lane": "pull_request", "maximum_runs_per_domain": 8, "maximum_wall_minutes": 15}},
    {{"lane": "main", "maximum_runs_per_domain": 64, "maximum_wall_minutes": 30}},
    {{"lane": "continuous", "maximum_runs_per_domain": 1000000, "maximum_wall_minutes": 240}}
  ],
  "dimensions": [
    {{
      "id": "impairment",
      "values": [
        {{
          "id": "jitter",
          "disposition": "known_gap",
          "owners": ["continuous"],
          "evidence": [{{"kind": "known_gap", "id": "link-jitter"}}]
        }},
        {{
          "id": "latency-fast",
          "disposition": "continuous",
          "owners": ["continuous"],
          "evidence": [{{
            "kind": "swarm_option",
            "domain": "direct",
            "choice_id": "latency",
            "option_id": "fast"
          }}]
        }},
        {{
          "id": "path-active",
          "disposition": "continuous",
          "owners": ["continuous"],
          "evidence": [{{
            "kind": "behavior_transition",
            "domain": "direct",
            "transition": {{"transition": "path", "active": true}}
          }}]
        }}
      ]
    }}
  ],
  "domains": [
    {{
      "id": "{domain_id}",
      "swarm_id": "{swarm_id}",
      "individual_obligation": "all_options",
      "pairwise_obligation": "all_cross_choice_pairs",
      "higher_order": [
        {{
          "selections": [
            {{"choice_id": "latency", "option_id": "fast"}},
            {{"choice_id": "mtu", "option_id": "minimum"}},
            {{"choice_id": "payload", "option_id": "large"}}
          ]
        }}
      ],
      "owners": ["pull_request", "main", "continuous"]
    }}
  ],
  "known_gaps": [
    {{"id": "link-jitter", "dimension": "impairment", "reason": "not modeled by the current swarm"}}
  ]
}}"#
    )
    .into_bytes()
}

#[test]
fn checked_policy_expands_provider_individual_pair_and_higher_order_obligations() {
    let policy = CoveragePolicy::from_json(&policy_json("direct", "direct-smoke")).unwrap();
    let swarms = BTreeMap::from([("direct-smoke".to_owned(), direct_swarm())]);

    let obligations = policy.obligations(&swarms).unwrap();

    assert_eq!(obligations.individuals.len(), 12);
    assert_eq!(obligations.pairs.len(), 24);
    assert_eq!(obligations.higher_order.len(), 2);
    assert_eq!(obligations.transitions.len(), 2);
    assert_eq!(obligations.dimensions.len(), 1);
    assert_eq!(obligations.known_gaps.len(), 1);
    assert!(
        obligations
            .individuals
            .iter()
            .any(|bucket| bucket.domain == "direct"
                && bucket.provider == CryptoMode::ProductionProvider
                && bucket.choice_id == "mtu"
                && bucket.option_id == "minimum")
    );
}

#[test]
fn policy_parsing_and_swarm_binding_fail_closed() {
    let unsupported = policy_json("direct", "direct-smoke");
    let unsupported = String::from_utf8(unsupported).unwrap().replacen(
        "\"schema_version\": 2",
        "\"schema_version\": 99",
        1,
    );
    assert!(matches!(
        CoveragePolicy::from_json(unsupported.as_bytes()),
        Err(CoverageError::UnsupportedSchema(99))
    ));

    let unknown_field = String::from_utf8(policy_json("direct", "direct-smoke"))
        .unwrap()
        .replacen(
            "\"rolling_window_days\": 7,",
            "\"rolling_window_days\": 7, \"unexpected\": true,",
            1,
        );
    assert!(matches!(
        CoveragePolicy::from_json(unknown_field.as_bytes()),
        Err(CoverageError::Encoding(_))
    ));

    let policy = CoveragePolicy::from_json(&policy_json("direct", "missing-swarm")).unwrap();
    assert!(matches!(
        policy.obligations(&BTreeMap::new()),
        Err(CoverageError::UnknownSwarm(id)) if id == "missing-swarm"
    ));

    let unresolved_gap = String::from_utf8(policy_json("direct", "direct-smoke"))
        .unwrap()
        .replacen("\"id\": \"link-jitter\"", "\"id\": \"missing-gap\"", 1);
    assert!(matches!(
        CoveragePolicy::from_json(unresolved_gap.as_bytes()),
        Err(CoverageError::UnknownKnownGap(id)) if id == "missing-gap"
    ));

    let unresolved_option = String::from_utf8(policy_json("direct", "direct-smoke"))
        .unwrap()
        .replace("\"option_id\": \"fast\"", "\"option_id\": \"missing\"");
    let policy = CoveragePolicy::from_json(unresolved_option.as_bytes()).unwrap();
    assert!(matches!(
        policy.obligations(&BTreeMap::from([(
            "direct-smoke".to_owned(),
            direct_swarm()
        )])),
        Err(CoverageError::UnknownOption { option, .. }) if option == "missing"
    ));
}

#[test]
fn observations_capture_configuration_transitions_oracles_and_phases() {
    let swarm = direct_swarm();
    let (scenario, mut selection) = swarm
        .materialize(iroh_runtime::RootSeed::new([7; 32]))
        .unwrap();
    selection.safety_liveness = Some(SafetyLivenessPhases {
        safety_action: "fault".to_owned(),
        recovery_action: "recover".to_owned(),
        liveness_probe_action: "probe".to_owned(),
    });
    let observations = vec![
        observation(
            1,
            ObservationKind::EndpointState {
                endpoint: EndpointId::new("client").unwrap(),
                from: EndpointState::Created,
                to: EndpointState::Running,
            },
        ),
        observation(
            2,
            ObservationKind::ConnectionState {
                connection: ConnectionId::new("c1").unwrap(),
                owner: EndpointId::new("client").unwrap(),
                peer_identity: None,
                from: ConnectionState::Created,
                to: ConnectionState::Dialing,
            },
        ),
        operation_completed(3, "fault"),
        operation_completed(4, "recover"),
        operation_completed(5, "probe"),
    ];

    let coverage = CoverageObservation::from_run(
        "direct",
        CryptoMode::DeterministicTest,
        &selection,
        &scenario,
        &observations,
    )
    .unwrap();

    assert_eq!(coverage.individuals.len(), 3);
    assert_eq!(coverage.pairs.len(), 3);
    assert!(
        coverage
            .transitions
            .contains(&BehaviorTransition::Endpoint {
                from: EndpointState::Created,
                to: EndpointState::Running,
            })
    );
    assert!(
        coverage
            .transitions
            .contains(&BehaviorTransition::Connection {
                from: ConnectionState::Created,
                to: ConnectionState::Dialing,
            })
    );
    assert!(coverage.oracles.contains(&InvariantName::DeliveryIntegrity));
    assert_eq!(
        coverage.phases,
        vec![
            CoveragePhase::SafetyFault,
            CoveragePhase::Recovery,
            CoveragePhase::LivenessProbe,
        ]
    );
}

#[test]
fn ledger_reports_missing_obligations_and_merges_deterministically() {
    let policy = CoveragePolicy::from_json(&policy_json("direct", "direct-smoke")).unwrap();
    let swarm = direct_swarm();
    let swarms = BTreeMap::from([("direct-smoke".to_owned(), swarm.clone())]);
    let obligations = policy.obligations(&swarms).unwrap();
    let (scenario, selection) = swarm
        .materialize(iroh_runtime::RootSeed::new([9; 32]))
        .unwrap();
    let observation = CoverageObservation::from_run(
        "direct",
        CryptoMode::DeterministicTest,
        &selection,
        &scenario,
        &[],
    )
    .unwrap();

    let mut first = CoverageLedger::new(obligations.clone());
    first.observe(&observation).unwrap();
    let mut second = CoverageLedger::new(obligations);
    second.observe(&observation).unwrap();
    first.merge(&second).unwrap();

    let report = first.report();
    assert_eq!(report.completed_runs, 2);
    assert_eq!(report.observed_individuals.len(), 3);
    assert_eq!(report.observed_individuals[0].occurrences, 2);
    assert_eq!(report.missing_individuals.len(), 9);
    assert_eq!(report.missing_pairs.len(), 21);
    assert_eq!(report.missing_higher_order.len(), 2);
    assert_eq!(report.missing_transitions.len(), 2);
    assert_eq!(report.known_gaps.len(), 1);
}

#[test]
fn rejected_observation_does_not_partially_mutate_the_ledger() {
    let policy = CoveragePolicy::from_json(&policy_json("direct", "direct-smoke")).unwrap();
    let swarm = direct_swarm();
    let swarms = BTreeMap::from([("direct-smoke".to_owned(), swarm.clone())]);
    let obligations = policy.obligations(&swarms).unwrap();
    let (scenario, selection) = swarm
        .materialize(iroh_runtime::RootSeed::new([11; 32]))
        .unwrap();
    let mut observation = CoverageObservation::from_run(
        "direct",
        CryptoMode::DeterministicTest,
        &selection,
        &scenario,
        &[],
    )
    .unwrap();
    observation.oracles.push(InvariantName::RelayRouting);

    let mut ledger = CoverageLedger::new(obligations);
    assert!(matches!(
        ledger.observe(&observation),
        Err(CoverageError::UnexpectedOracle(_))
    ));

    let report = ledger.report();
    assert_eq!(report.completed_runs, 0);
    assert!(report.observed_individuals.is_empty());
    assert!(report.observed_pairs.is_empty());
}

#[test]
fn recovery_phase_cannot_be_credited_before_the_safety_fault() {
    let swarm = direct_swarm();
    let (scenario, mut selection) = swarm
        .materialize(iroh_runtime::RootSeed::new([12; 32]))
        .unwrap();
    selection.safety_liveness = Some(SafetyLivenessPhases {
        safety_action: "fault".to_owned(),
        recovery_action: "recover".to_owned(),
        liveness_probe_action: "probe".to_owned(),
    });

    assert!(matches!(
        CoverageObservation::from_run(
            "direct",
            CryptoMode::DeterministicTest,
            &selection,
            &scenario,
            &[operation_completed(1, "recover")],
        ),
        Err(CoverageError::InvalidPhaseOrder)
    ));
}

#[test]
fn checked_repository_policy_covers_every_current_soak_domain() {
    let policy = CoveragePolicy::from_json(include_bytes!("../coverage-policy.json")).unwrap();
    let mut swarms = BTreeMap::new();
    for (id, bytes) in [
        (
            "direct-smoke",
            include_bytes!("../swarms/direct-smoke.json").as_slice(),
        ),
        (
            "discovery-timing",
            include_bytes!("../swarms/discovery-timing.json").as_slice(),
        ),
        (
            "link-impairment",
            include_bytes!("../swarms/link-impairment.json").as_slice(),
        ),
        (
            "mobility-timing",
            include_bytes!("../swarms/mobility-timing.json").as_slice(),
        ),
        (
            "nat-behavior",
            include_bytes!("../swarms/nat-behavior.json").as_slice(),
        ),
        (
            "ready-order-pressure",
            include_bytes!("../swarms/ready-order-pressure.json").as_slice(),
        ),
        (
            "relay-lifecycle",
            include_bytes!("../swarms/relay-lifecycle.json").as_slice(),
        ),
    ] {
        swarms.insert(id.to_owned(), resolve_swarm(bytes));
    }

    let obligations = policy.obligations(&swarms).unwrap();

    let domains = obligations
        .individuals
        .iter()
        .map(|bucket| bucket.domain.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        domains,
        std::collections::BTreeSet::from([
            "direct",
            "discovery",
            "impairment",
            "mobility",
            "nat",
            "ready-order",
            "relay",
        ])
    );

    let dimensions = policy
        .dimensions
        .iter()
        .map(|dimension| {
            (
                dimension.id.as_str(),
                dimension
                    .values
                    .iter()
                    .map(|value| value.id.as_str())
                    .collect::<std::collections::BTreeSet<_>>(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        dimensions.keys().copied().collect::<Vec<_>>(),
        [
            "addressing",
            "cryptography",
            "discovery",
            "impairment",
            "lifecycle",
            "middlebox",
            "resource",
            "scheduling",
            "topology",
        ]
    );
    for (dimension, required_values) in [
        (
            "addressing",
            &["dual-stack", "interface-migration", "ipv4", "ipv6"][..],
        ),
        (
            "cryptography",
            &["deterministic-test", "production-provider"][..],
        ),
        (
            "discovery",
            &[
                "absence",
                "conflict",
                "delay",
                "freshness",
                "provider-disagreement",
                "rotation",
            ][..],
        ),
        (
            "impairment",
            &[
                "bandwidth",
                "blackhole",
                "corruption",
                "duplication",
                "jitter",
                "latency",
                "loss",
                "partition",
                "queueing",
                "rejection",
                "reordering",
            ][..],
        ),
        (
            "lifecycle",
            &["connection", "endpoint", "interface", "relay"][..],
        ),
        (
            "middlebox",
            &[
                "filtering",
                "mapping",
                "mapping-expiry",
                "nested-nat",
                "nat-rebinding",
                "udp-blocking",
            ][..],
        ),
        (
            "resource",
            &[
                "connections",
                "continuous-pressure",
                "mappings",
                "packets",
                "queues",
                "relays",
                "sockets",
                "streams",
                "tasks",
                "timers",
                "trace-storage",
            ][..],
        ),
        (
            "scheduling",
            &[
                "backpressure",
                "cancellation",
                "ready-order",
                "timeout-boundary",
            ][..],
        ),
        (
            "topology",
            &[
                "direct",
                "fallback",
                "multi-path",
                "multi-region-relay",
                "relay",
            ][..],
        ),
    ] {
        assert_eq!(
            dimensions[dimension],
            required_values.iter().copied().collect()
        );
    }

    let referenced_gaps = policy
        .dimensions
        .iter()
        .flat_map(|dimension| &dimension.values)
        .flat_map(|value| &value.evidence)
        .filter_map(|evidence| match evidence {
            support::CoverageEvidence::KnownGap { id } => Some(id.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(referenced_gaps.len(), policy.known_gaps.len());
    assert_eq!(
        referenced_gaps
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        policy
            .known_gaps
            .iter()
            .map(|gap| gap.id.as_str())
            .collect()
    );
    assert_eq!(policy.known_gaps.len(), 12);
    for promoted_value in [
        "bandwidth",
        "blackhole",
        "duplication",
        "queueing",
        "reordering",
    ] {
        let value = policy
            .dimensions
            .iter()
            .find(|dimension| dimension.id == "impairment")
            .and_then(|dimension| {
                dimension
                    .values
                    .iter()
                    .find(|value| value.id == promoted_value)
            })
            .expect("promoted impairment value must remain declared");
        assert_eq!(value.disposition, support::CoverageDisposition::Continuous);
        assert!(value.evidence.iter().any(|evidence| matches!(
            evidence,
            support::CoverageEvidence::SwarmOption { domain, .. }
                if domain == "impairment"
        )));
    }
    let blackhole = policy
        .dimensions
        .iter()
        .find(|dimension| dimension.id == "impairment")
        .and_then(|dimension| {
            dimension
                .values
                .iter()
                .find(|value| value.id == "blackhole")
        })
        .expect("promoted blackhole value must remain declared");
    assert!(blackhole.evidence.iter().any(|evidence| matches!(
        evidence,
        support::CoverageEvidence::SwarmOption {
            domain,
            choice_id,
            option_id,
        } if domain == "impairment"
            && choice_id == "blackhole-duration"
            && option_id == "sustained"
    )));
    let impairment = policy
        .domains
        .iter()
        .find(|domain| domain.id == "impairment")
        .expect("impairment policy domain must remain declared");
    assert!(impairment.higher_order.iter().any(|combination| {
        combination.selections.iter().any(|selection| {
            selection.choice_id == "blackhole-duration" && selection.option_id == "sustained"
        })
    }));
}

fn observation(sequence: u64, kind: ObservationKind) -> Observation {
    Observation {
        schema_version: OBSERVATION_SCHEMA_VERSION,
        sequence,
        virtual_time_nanos: sequence,
        caused_by: None,
        kind,
    }
}

fn operation_completed(sequence: u64, operation: &str) -> Observation {
    observation(
        sequence,
        ObservationKind::OperationCompleted {
            operation: OperationId::new(operation).unwrap(),
            outcome: "success".to_owned(),
        },
    )
}

fn resolve_swarm(bytes: &[u8]) -> SwarmSpec {
    let template = support::SwarmTemplate::from_json(bytes).unwrap();
    match template {
        support::SwarmTemplate::Embedded(spec) => *spec,
        support::SwarmTemplate::Referenced(reference) => {
            let relative = reference.base_path.strip_prefix("iroh-sim/").unwrap();
            let base =
                std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative))
                    .unwrap();
            reference.resolve(&base).unwrap()
        }
    }
}
