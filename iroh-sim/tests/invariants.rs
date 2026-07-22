use std::collections::BTreeMap;

use iroh_sim::{
    ConnectionId, ConnectionState, EndpointId, EndpointState, FairnessAssumption, InvariantClass,
    InvariantError, InvariantName, InvariantRegistry, InvariantSpec, Observation, ObservationKind,
    PayloadDigest, ResourceKind, ScenarioBuilder, ScenarioOperation, StreamId,
};

fn registry(extra: &[(InvariantName, Option<u64>, Option<u64>)]) -> InvariantRegistry {
    let mut scenario = ScenarioBuilder::direct_ip_echo(
        "invariants/test",
        iroh_sim::IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap()
    .build()
    .unwrap();
    for (name, deadline_nanos, max_events) in extra {
        if !scenario.invariants.iter().any(|item| item.name == *name) {
            scenario.invariants.push(InvariantSpec {
                name: *name,
                deadline_nanos: *deadline_nanos,
                max_events: *max_events,
            });
        }
    }
    scenario.invariants.sort_by_key(|item| item.name);
    InvariantRegistry::from_scenario(&scenario).unwrap()
}

#[test]
fn authentication_change_fails_at_the_first_invalid_observation() {
    let mut registry = registry(&[]);
    let connection = ConnectionId::new("c1").unwrap();
    registry
        .observe(Observation::new(
            1,
            10,
            ObservationKind::ConnectionState {
                connection: connection.clone(),
                owner: EndpointId::new("client").unwrap(),
                peer_identity: Some("server-key".to_owned()),
                from: ConnectionState::Dialing,
                to: ConnectionState::Connected,
            },
        ))
        .unwrap();

    let error = registry
        .observe(Observation::new(
            2,
            11,
            ObservationKind::ConnectionState {
                connection,
                owner: EndpointId::new("client").unwrap(),
                peer_identity: Some("attacker-key".to_owned()),
                from: ConnectionState::Connected,
                to: ConnectionState::Connected,
            },
        ))
        .unwrap_err();
    let InvariantError::Failure(failure) = error else {
        panic!("unexpected error: {error:?}");
    };
    assert_eq!(failure.name, InvariantName::AuthenticationIdentity);
    assert_eq!(failure.class, InvariantClass::Safety);
    assert_eq!(failure.observation_sequence, 2);
}

#[test]
fn delivery_integrity_misdelivery_and_order_are_continuously_checked() {
    let mut registry = registry(&[(InvariantName::DeliveryOrdering, None, None)]);
    let stream = StreamId::new("s1").unwrap();
    let digest = PayloadDigest::from_bytes(b"expected");
    registry
        .observe(Observation::new(
            1,
            1,
            ObservationKind::Delivery {
                connection: ConnectionId::new("c1").unwrap(),
                stream: Some(stream.clone()),
                sequence: 0,
                source: EndpointId::new("client").unwrap(),
                destination: EndpointId::new("server").unwrap(),
                intended_destination: EndpointId::new("server").unwrap(),
                expected: digest.clone(),
                actual: digest,
            },
        ))
        .unwrap();

    let error = registry
        .observe(Observation::new(
            2,
            2,
            ObservationKind::Delivery {
                connection: ConnectionId::new("c1").unwrap(),
                stream: Some(stream),
                sequence: 2,
                source: EndpointId::new("client").unwrap(),
                destination: EndpointId::new("other").unwrap(),
                intended_destination: EndpointId::new("server").unwrap(),
                expected: PayloadDigest::from_bytes(b"expected"),
                actual: PayloadDigest::from_bytes(b"corrupt"),
            },
        ))
        .unwrap_err();
    let InvariantError::Failure(failure) = error else {
        panic!("unexpected error: {error:?}");
    };
    assert_eq!(failure.name, InvariantName::DeliveryIntegrity);
    assert_eq!(failure.observation_sequence, 2);
    assert_eq!(
        failure.evidence.get("misdelivery"),
        Some(&"true".to_owned())
    );
    assert_eq!(failure.evidence.get("corruption"), Some(&"true".to_owned()));
}

#[test]
fn relay_routing_rejects_delivery_to_an_unaddressed_identity() {
    let mut scenario = ScenarioBuilder::direct_ip_echo(
        "invariants/relay-routing",
        iroh_sim::IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap()
    .build()
    .unwrap();
    scenario.invariants = vec![InvariantSpec {
        name: InvariantName::RelayRouting,
        deadline_nanos: None,
        max_events: None,
    }];
    let mut registry = InvariantRegistry::from_scenario(&scenario).unwrap();
    registry
        .observe(Observation::new(
            1,
            1,
            ObservationKind::PathState {
                connection: ConnectionId::new("c1").unwrap(),
                path: iroh_sim::PathId::new("relay").unwrap(),
                active: true,
            },
        ))
        .unwrap();
    let error = registry
        .observe(Observation::new(
            2,
            2,
            ObservationKind::Delivery {
                connection: ConnectionId::new("c1").unwrap(),
                stream: None,
                sequence: 0,
                source: EndpointId::new("client").unwrap(),
                destination: EndpointId::new("wrong").unwrap(),
                intended_destination: EndpointId::new("server").unwrap(),
                expected: PayloadDigest::from_bytes(b"payload"),
                actual: PayloadDigest::from_bytes(b"payload"),
            },
        ))
        .unwrap_err();
    let InvariantError::Failure(failure) = error else {
        panic!("unexpected error: {error:?}");
    };
    assert_eq!(failure.name, InvariantName::RelayRouting);
}

#[test]
fn lifecycle_rejects_resurrection_even_if_a_later_state_would_close() {
    let mut registry = registry(&[]);
    let endpoint = EndpointId::new("client").unwrap();
    for (sequence, from, to) in [
        (1, EndpointState::Created, EndpointState::Running),
        (2, EndpointState::Running, EndpointState::Stopping),
        (3, EndpointState::Stopping, EndpointState::Stopped),
    ] {
        registry
            .observe(Observation::new(
                sequence,
                sequence,
                ObservationKind::EndpointState {
                    endpoint: endpoint.clone(),
                    from,
                    to,
                },
            ))
            .unwrap();
    }
    let error = registry
        .observe(Observation::new(
            4,
            4,
            ObservationKind::EndpointState {
                endpoint,
                from: EndpointState::Stopped,
                to: EndpointState::Running,
            },
        ))
        .unwrap_err();
    assert!(matches!(
        error,
        InvariantError::Failure(ref failure)
            if failure.name == InvariantName::MonotonicLifecycle
    ));
}

#[test]
fn reachable_connect_liveness_expires_only_when_fairness_is_satisfied() {
    let mut registry = registry(&[(InvariantName::ReachableConnectLiveness, Some(100), Some(5))]);
    registry
        .observe(Observation::new(
            1,
            0,
            ObservationKind::ConnectionState {
                connection: ConnectionId::new("c1").unwrap(),
                owner: EndpointId::new("client").unwrap(),
                peer_identity: None,
                from: ConnectionState::Created,
                to: ConnectionState::Dialing,
            },
        ))
        .unwrap();
    registry.set_fairness(FairnessAssumption::ReachableNetwork, false);
    assert!(registry.check_before_time_advance(101, 6).is_ok());

    registry.set_fairness(FairnessAssumption::ReachableNetwork, true);
    let error = registry.check_before_time_advance(101, 6).unwrap_err();
    assert!(matches!(
        error,
        InvariantError::Failure(ref failure)
            if failure.name == InvariantName::ReachableConnectLiveness
                && failure.class == InvariantClass::BoundedLiveness
    ));
}

#[test]
fn resource_ceiling_and_cleanup_have_distinct_failure_classes() {
    let mut ceiling = registry(&[(InvariantName::ResourceCeiling, None, None)]);
    let error = ceiling
        .observe(Observation::new(
            1,
            0,
            ObservationKind::Resource {
                kind: ResourceKind::QueuedPacket,
                current: 3,
                limit: 2,
            },
        ))
        .unwrap_err();
    assert!(matches!(
        error,
        InvariantError::Failure(ref failure) if failure.class == InvariantClass::Safety
    ));

    let mut cleanup = registry(&[]);
    cleanup
        .observe(Observation::new(
            1,
            0,
            ObservationKind::Resource {
                kind: ResourceKind::Socket,
                current: 1,
                limit: 10,
            },
        ))
        .unwrap();
    let error = cleanup.finish(10, 2).unwrap_err();
    assert!(matches!(
        error,
        InvariantError::Failure(ref failure)
            if failure.name == InvariantName::ResourceCleanup
                && failure.class == InvariantClass::Cleanup
    ));
}

#[test]
fn registry_rejects_non_monotonic_observation_sequences() {
    let mut registry = registry(&[]);
    registry
        .observe(Observation::new(
            1,
            5,
            ObservationKind::EndpointState {
                endpoint: EndpointId::new("client").unwrap(),
                from: EndpointState::Created,
                to: EndpointState::Running,
            },
        ))
        .unwrap();
    let error = registry
        .observe(Observation::new(
            1,
            4,
            ObservationKind::Marker {
                name: "late".to_owned(),
                fields: BTreeMap::new(),
            },
        ))
        .unwrap_err();
    assert!(matches!(error, InvariantError::NonMonotonicObservation));
}
