use std::{
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::{Duration, SystemTime},
};

use iroh::simulation::{IpSocket, IpSocketSender};
use iroh_runtime::{RootSeed, TraceEventKind};
use iroh_sim::{
    FirewallAction, FirewallConfig, FirewallConnectionState, FirewallDirection, FirewallProtocol,
    FirewallRule, IpCidr, Kernel, KernelConfig, LinkConfig, NatConfig, NatFilteringBehavior,
    NatMappingBehavior, NetworkConfig, NetworkError, ResourceKind, SyntheticNetwork, TraceBuffer,
    normalized_trace_json,
};
use proptest::prelude::*;

struct Fixture {
    kernel: Kernel,
    trace: TraceBuffer,
    network: SyntheticNetwork,
}

impl Fixture {
    fn new(seed: [u8; 32]) -> Self {
        Self::with_network_config(
            seed,
            NetworkConfig {
                max_packets: 1_000,
                ephemeral_port_start: 40_000,
            },
        )
    }

    fn with_network_config(seed: [u8; 32], network_config: NetworkConfig) -> Self {
        let trace = TraceBuffer::default();
        let kernel = Kernel::new(
            KernelConfig {
                max_events: 10_000,
                max_virtual_time: Duration::from_secs(60),
                max_tasks: 64,
            },
            Arc::new(trace.clone()),
        )
        .unwrap();
        let context = Arc::new(kernel.runtime_context(RootSeed::new(seed), SystemTime::UNIX_EPOCH));
        let network =
            SyntheticNetwork::new(kernel.clone(), context.clone(), network_config).unwrap();
        Self {
            kernel,
            trace,
            network,
        }
    }

    fn direct_dual_stack(seed: [u8; 32], link: LinkConfig) -> Self {
        let fixture = Self::new(seed);
        fixture.network.add_host("a").unwrap();
        fixture.network.add_host("b").unwrap();
        fixture.network.add_link("lan", link).unwrap();
        fixture
            .network
            .add_interface(
                "a",
                "a0",
                "lan",
                [
                    IpCidr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 24).unwrap(),
                    IpCidr::new("2001:db8::1".parse().unwrap(), 64).unwrap(),
                ],
            )
            .unwrap();
        fixture
            .network
            .add_interface(
                "b",
                "b0",
                "lan",
                [
                    IpCidr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 24).unwrap(),
                    IpCidr::new("2001:db8::2".parse().unwrap(), 64).unwrap(),
                ],
            )
            .unwrap();
        fixture
    }
}

#[test]
fn ipv4_and_ipv6_datagrams_cross_the_real_ip_socket_boundary() {
    let fixture = Fixture::direct_dual_stack([1; 32], LinkConfig::default());
    let a = fixture.network.socket_factory("a").unwrap();
    let b = fixture.network.socket_factory("b").unwrap();

    for (source, destination, payload) in [
        (
            SocketAddr::from(([192, 0, 2, 1], 10_001)),
            SocketAddr::from(([192, 0, 2, 2], 10_002)),
            b"ipv4".as_slice(),
        ),
        (
            SocketAddr::new("2001:db8::1".parse().unwrap(), 20_001),
            SocketAddr::new("2001:db8::2".parse().unwrap(), 20_002),
            b"ipv6".as_slice(),
        ),
    ] {
        let source_socket = a.bind(source).unwrap();
        let destination_socket = b.bind(destination).unwrap();
        send(&source_socket, destination, payload).unwrap();
        fixture.kernel.run_until_idle().unwrap();

        let received = recv(&destination_socket, 64).expect("packet delivered");
        assert_eq!(&received.0, payload);
        assert_eq!(received.1.addr, source);
        assert_eq!(received.1.dst_ip, Some(destination.ip()));
    }

    assert_eq!(
        fixture.kernel.ledger().current(ResourceKind::QueuedPacket),
        0
    );
}

#[test]
fn stateful_nat_translates_real_socket_outbound_and_reply_paths() {
    let fixture = Fixture::new([17; 32]);
    fixture.network.add_host("private").unwrap();
    fixture.network.add_host("remote").unwrap();
    fixture
        .network
        .add_link("wan", LinkConfig::default())
        .unwrap();
    fixture
        .network
        .add_interface(
            "private",
            "eth0",
            "wan",
            [IpCidr::new("10.0.0.2".parse().unwrap(), 24).unwrap()],
        )
        .unwrap();
    fixture
        .network
        .add_interface(
            "remote",
            "eth0",
            "wan",
            [IpCidr::new("198.51.100.2".parse().unwrap(), 24).unwrap()],
        )
        .unwrap();
    let default = IpCidr::new("0.0.0.0".parse().unwrap(), 0).unwrap();
    fixture
        .network
        .add_route("private", "default", default, "eth0", None)
        .unwrap();
    fixture
        .network
        .add_route("remote", "default", default, "eth0", None)
        .unwrap();
    fixture
        .network
        .add_nat_with_firewall(
            "private",
            NatConfig {
                id: "home".to_owned(),
                public_ip: Ipv4Addr::new(203, 0, 113, 7),
                port_start: 40_000,
                port_end: 40_100,
                mapping_behavior: NatMappingBehavior::EndpointIndependent,
                filtering_behavior: NatFilteringBehavior::EndpointIndependent,
                mapping_ttl: Duration::from_secs(30),
                hairpin: true,
                max_mappings: 32,
            },
            FirewallConfig {
                id: "edge".to_owned(),
                rules: vec![
                    FirewallRule {
                        id: "allow-outbound".to_owned(),
                        protocol: FirewallProtocol::Udp,
                        direction: Some(FirewallDirection::Outbound),
                        source: None,
                        destination: None,
                        source_ports: None,
                        destination_ports: None,
                        connection_state: FirewallConnectionState::New,
                        action: FirewallAction::Allow,
                    },
                    FirewallRule {
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
                ],
                default_action: FirewallAction::Drop,
            },
        )
        .unwrap();
    let private = fixture.network.socket_factory("private").unwrap();
    let remote = fixture.network.socket_factory("remote").unwrap();
    let private = private.bind("10.0.0.2:5000".parse().unwrap()).unwrap();
    let remote = remote.bind("198.51.100.2:6000".parse().unwrap()).unwrap();
    send(&private, remote.local_addr().unwrap(), b"outbound").unwrap();
    assert!(matches!(
        fixture.kernel.step().unwrap(),
        iroh_sim::KernelStep::Progress
    ));
    let received = recv(&remote, 64).unwrap();
    assert_eq!(received.0, b"outbound");
    assert_eq!(received.1.addr.ip(), Ipv4Addr::new(203, 0, 113, 7));
    let external = received.1.addr;

    send(&remote, external, b"reply").unwrap();
    assert!(matches!(
        fixture.kernel.step().unwrap(),
        iroh_sim::KernelStep::Progress
    ));
    let reply = recv(&private, 64).unwrap();
    assert_eq!(reply.0, b"reply");
    assert_eq!(reply.1.addr, remote.local_addr().unwrap());
    assert_eq!(reply.1.dst_ip, Some(Ipv4Addr::new(10, 0, 0, 2).into()));
    assert_eq!(fixture.network.nat_snapshot("home").unwrap().len(), 1);
    assert!(fixture.trace.events().iter().any(|event| matches!(
        &event.event,
        TraceEventKind::PacketCreated {
            source,
            original_source,
            original_destination,
            ..
        } if source.starts_with("203.0.113.7:")
            && original_source == "10.0.0.2:5000"
            && original_destination == "198.51.100.2:6000"
    )));
    assert!(fixture.trace.events().iter().any(|event| {
        event.context.packet.is_some()
            && matches!(&event.event, TraceEventKind::NatTranslation { .. })
    }));

    let unsolicited = fixture
        .network
        .socket_factory("remote")
        .unwrap()
        .bind("198.51.100.2:6001".parse().unwrap())
        .unwrap();
    send(&unsolicited, external, b"unsolicited").unwrap();
    assert!(matches!(
        fixture.kernel.step().unwrap(),
        iroh_sim::KernelStep::Progress
    ));
    assert!(recv(&private, 64).is_none());
    assert!(fixture.trace.events().iter().any(|event| {
        matches!(
            &event.event,
            TraceEventKind::FirewallDecision { action, .. } if action == "drop"
        )
    }));

    let expiry = fixture.network.nat_snapshot("home").unwrap()[0].expires_nanos;
    let run = fixture.kernel.run_until_idle().unwrap();
    assert_eq!(run.virtual_time, Duration::from_nanos(expiry));
    assert!(fixture.network.nat_snapshot("home").unwrap().is_empty());
    assert_eq!(fixture.kernel.ledger().current(ResourceKind::Mapping), 0);
    assert!(fixture.trace.events().iter().any(|event| {
        matches!(
            &event.event,
            TraceEventKind::NatMapping { transition, .. } if transition == "expired"
        )
    }));
}

#[test]
fn double_nat_chain_translates_real_socket_traffic_in_both_directions() {
    let fixture = Fixture::new([18; 32]);
    for host in ["private", "remote"] {
        fixture.network.add_host(host).unwrap();
    }
    fixture
        .network
        .add_link("wan", LinkConfig::default())
        .unwrap();
    for (host, address) in [("private", "10.0.0.2"), ("remote", "198.51.100.2")] {
        fixture
            .network
            .add_interface(
                host,
                "eth0",
                "wan",
                [IpCidr::new(address.parse().unwrap(), 0).unwrap()],
            )
            .unwrap();
    }
    fixture
        .network
        .add_nat(
            "private",
            NatConfig {
                id: "carrier".to_owned(),
                public_ip: Ipv4Addr::new(198, 18, 0, 1),
                port_start: 41_000,
                port_end: 41_127,
                mapping_behavior: NatMappingBehavior::EndpointIndependent,
                filtering_behavior: NatFilteringBehavior::EndpointIndependent,
                mapping_ttl: Duration::from_secs(30),
                hairpin: true,
                max_mappings: 128,
            },
        )
        .unwrap();
    fixture
        .network
        .add_chained_nat(
            "private",
            "carrier",
            NatConfig {
                id: "home".to_owned(),
                public_ip: Ipv4Addr::new(203, 0, 113, 9),
                port_start: 40_000,
                port_end: 40_127,
                mapping_behavior: NatMappingBehavior::EndpointIndependent,
                filtering_behavior: NatFilteringBehavior::EndpointIndependent,
                mapping_ttl: Duration::from_secs(30),
                hairpin: true,
                max_mappings: 128,
            },
        )
        .unwrap();
    let private = fixture
        .network
        .socket_factory("private")
        .unwrap()
        .bind("10.0.0.2:5000".parse().unwrap())
        .unwrap();
    let remote = fixture
        .network
        .socket_factory("remote")
        .unwrap()
        .bind("198.51.100.2:6000".parse().unwrap())
        .unwrap();

    send(&private, remote.local_addr().unwrap(), b"double").unwrap();
    fixture.kernel.step().unwrap();
    let outbound = recv(&remote, 64).unwrap();
    assert_eq!(outbound.0, b"double");
    assert_eq!(outbound.1.addr.ip(), Ipv4Addr::new(198, 18, 0, 1));
    assert_eq!(fixture.network.nat_snapshot("home").unwrap().len(), 1);
    assert_eq!(fixture.network.nat_snapshot("carrier").unwrap().len(), 1);

    send(&remote, outbound.1.addr, b"reply").unwrap();
    fixture.kernel.step().unwrap();
    assert_eq!(recv(&private, 64).unwrap().0, b"reply");
    assert!(
        fixture
            .trace
            .events()
            .iter()
            .filter(|event| { matches!(&event.event, TraceEventKind::NatTranslation { .. }) })
            .count()
            >= 4
    );
}

#[test]
fn link_latency_and_bandwidth_advance_virtual_time_exactly() {
    let fixture = Fixture::direct_dual_stack(
        [2; 32],
        LinkConfig {
            latency: Duration::from_millis(2),
            bits_per_second: 1_000_000,
            ..LinkConfig::default()
        },
    );
    let a = fixture.network.socket_factory("a").unwrap();
    let b = fixture.network.socket_factory("b").unwrap();
    let source = a.bind("192.0.2.1:1001".parse().unwrap()).unwrap();
    let destination = b.bind("192.0.2.2:1002".parse().unwrap()).unwrap();

    send(&source, destination.local_addr().unwrap(), &[7; 1_000]).unwrap();
    let run = fixture.kernel.run_until_idle().unwrap();

    assert_eq!(run.virtual_time, Duration::from_millis(10));
    assert!(recv(&destination, 1_024).is_some());
}

#[test]
fn mtu_rejection_and_partition_drop_have_distinct_outcomes() {
    let fixture = Fixture::direct_dual_stack(
        [3; 32],
        LinkConfig {
            mtu: 64,
            ..LinkConfig::default()
        },
    );
    let a = fixture.network.socket_factory("a").unwrap();
    let b = fixture.network.socket_factory("b").unwrap();
    let source = a.bind("192.0.2.1:1001".parse().unwrap()).unwrap();
    let destination = b.bind("192.0.2.2:1002".parse().unwrap()).unwrap();
    fixture
        .network
        .add_nat(
            "a",
            NatConfig {
                id: "mtu-nat".to_owned(),
                public_ip: Ipv4Addr::new(203, 0, 113, 31),
                port_start: 40_000,
                port_end: 40_127,
                mapping_behavior: NatMappingBehavior::EndpointIndependent,
                filtering_behavior: NatFilteringBehavior::EndpointIndependent,
                mapping_ttl: Duration::from_secs(30),
                hairpin: true,
                max_mappings: 128,
            },
        )
        .unwrap();

    let mtu_error = send(&source, destination.local_addr().unwrap(), &[0; 65]).unwrap_err();
    assert_eq!(mtu_error.kind(), io::ErrorKind::InvalidInput);
    assert!(fixture.network.nat_snapshot("mtu-nat").unwrap().is_empty());

    fixture
        .network
        .set_partition("lan", "a", "b", true)
        .unwrap();
    send(&source, destination.local_addr().unwrap(), b"partitioned").unwrap();
    fixture.kernel.run_until_idle().unwrap();
    assert!(recv(&destination, 64).is_none());

    let transitions: Vec<_> = fixture
        .trace
        .events()
        .into_iter()
        .filter_map(|event| match event.event {
            TraceEventKind::PacketOutcome { outcome } => Some(outcome),
            _ => None,
        })
        .collect();
    assert!(transitions.iter().any(|value| value == "rejected:mtu"));
    assert!(transitions.iter().any(|value| value == "dropped:partition"));
}

#[test]
fn deterministic_duplication_and_corruption_are_applied_before_delivery() {
    let fixture = Fixture::direct_dual_stack(
        [4; 32],
        LinkConfig {
            duplicate_per_million: 1_000_000,
            corrupt_per_million: 1_000_000,
            ..LinkConfig::default()
        },
    );
    let a = fixture.network.socket_factory("a").unwrap();
    let b = fixture.network.socket_factory("b").unwrap();
    let source = a.bind("192.0.2.1:1001".parse().unwrap()).unwrap();
    let destination = b.bind("192.0.2.2:1002".parse().unwrap()).unwrap();

    send(&source, destination.local_addr().unwrap(), b"original").unwrap();
    fixture.kernel.run_until_idle().unwrap();

    let first = recv(&destination, 64).unwrap().0;
    let second = recv(&destination, 64).unwrap().0;
    assert_ne!(first, b"original");
    assert_eq!(first, second);
}

#[test]
fn routed_multi_hop_delivery_uses_longest_prefix_and_rejects_ambiguity() {
    let fixture = Fixture::new([5; 32]);
    for host in ["a", "router", "b"] {
        fixture.network.add_host(host).unwrap();
    }
    fixture
        .network
        .add_link("left", LinkConfig::default())
        .unwrap();
    fixture
        .network
        .add_link("right", LinkConfig::default())
        .unwrap();
    fixture
        .network
        .add_interface(
            "a",
            "a0",
            "left",
            [IpCidr::new("10.0.0.2".parse().unwrap(), 24).unwrap()],
        )
        .unwrap();
    fixture
        .network
        .add_interface(
            "router",
            "r0",
            "left",
            [IpCidr::new("10.0.0.1".parse().unwrap(), 24).unwrap()],
        )
        .unwrap();
    fixture
        .network
        .add_interface(
            "router",
            "r1",
            "right",
            [IpCidr::new("10.0.1.1".parse().unwrap(), 24).unwrap()],
        )
        .unwrap();
    fixture
        .network
        .add_interface(
            "b",
            "b0",
            "right",
            [IpCidr::new("10.0.1.2".parse().unwrap(), 24).unwrap()],
        )
        .unwrap();
    fixture
        .network
        .add_route(
            "a",
            "default",
            IpCidr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).unwrap(),
            "a0",
            Some("router"),
        )
        .unwrap();

    assert!(matches!(
        fixture.network.add_route(
            "a",
            "ambiguous",
            IpCidr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).unwrap(),
            "a0",
            Some("router"),
        ),
        Err(NetworkError::AmbiguousRoute { .. })
    ));

    let a = fixture.network.socket_factory("a").unwrap();
    let b = fixture.network.socket_factory("b").unwrap();
    let source = a.bind("10.0.0.2:1001".parse().unwrap()).unwrap();
    let destination = b.bind("10.0.1.2:1002".parse().unwrap()).unwrap();
    send(&source, destination.local_addr().unwrap(), b"routed").unwrap();

    assert_eq!(
        fixture.kernel.run_until_idle().unwrap().quiescence,
        iroh_sim::Quiescence::Complete
    );
    assert_eq!(recv(&destination, 64).unwrap().0, b"routed");
    let hops: Vec<_> = fixture
        .trace
        .events()
        .into_iter()
        .filter_map(|event| match event.event {
            TraceEventKind::PacketHopScheduled {
                link,
                from,
                to,
                deadline_nanos,
            } => Some((link, from, to, deadline_nanos)),
            _ => None,
        })
        .collect();
    assert_eq!(
        hops.iter()
            .map(|(link, from, to, _)| (link.as_str(), from.as_str(), to.as_str()))
            .collect::<Vec<_>>(),
        [("left", "a", "router"), ("right", "router", "b")]
    );
    assert!(hops.windows(2).all(|pair| pair[0].3 <= pair[1].3));
}

#[test]
fn ephemeral_rebind_and_socket_drop_balance_resources() {
    let fixture = Fixture::direct_dual_stack([6; 32], LinkConfig::default());
    let factory = fixture.network.socket_factory("a").unwrap();
    let socket = factory.bind("192.0.2.1:0".parse().unwrap()).unwrap();
    let first = socket.local_addr().unwrap();

    socket.rebind().unwrap();
    let second = socket.local_addr().unwrap();
    assert_eq!(first.port(), 40_000);
    assert_eq!(second.port(), 40_001);
    assert_eq!(fixture.kernel.ledger().current(ResourceKind::Socket), 1);

    drop(socket);
    assert_eq!(fixture.kernel.ledger().current(ResourceKind::Socket), 0);
}

#[test]
fn same_seed_faulted_network_trace_is_byte_identical() {
    fn execute() -> Vec<Vec<u8>> {
        let fixture = Fixture::direct_dual_stack(
            [7; 32],
            LinkConfig {
                loss_per_million: 250_000,
                duplicate_per_million: 250_000,
                corrupt_per_million: 250_000,
                reorder_window: Duration::from_millis(5),
                ..LinkConfig::default()
            },
        );
        let a = fixture.network.socket_factory("a").unwrap();
        let b = fixture.network.socket_factory("b").unwrap();
        let source = a.bind("192.0.2.1:1001".parse().unwrap()).unwrap();
        let destination = b.bind("192.0.2.2:1002".parse().unwrap()).unwrap();
        for payload in [b"one".as_slice(), b"two", b"three", b"four"] {
            send(&source, destination.local_addr().unwrap(), payload).unwrap();
        }
        fixture.kernel.run_until_idle().unwrap();
        fixture
            .trace
            .events()
            .iter()
            .map(|event| normalized_trace_json(event).unwrap())
            .collect()
    }

    assert_eq!(execute(), execute());
}

#[test]
fn queue_overflow_drops_atomically_without_leaking_capacity() {
    let fixture = Fixture::direct_dual_stack(
        [8; 32],
        LinkConfig {
            queue_packets: 1,
            duplicate_per_million: 1_000_000,
            ..LinkConfig::default()
        },
    );
    let a = fixture.network.socket_factory("a").unwrap();
    let b = fixture.network.socket_factory("b").unwrap();
    let source = a.bind("192.0.2.1:1001".parse().unwrap()).unwrap();
    let destination = b.bind("192.0.2.2:1002".parse().unwrap()).unwrap();

    send(&source, destination.local_addr().unwrap(), b"duplicate").unwrap();
    fixture.kernel.run_until_idle().unwrap();

    assert!(recv(&destination, 64).is_none());
    assert_eq!(
        fixture.kernel.ledger().current(ResourceKind::QueuedPacket),
        0
    );
    assert!(packet_outcomes(&fixture).contains(&"dropped:queue_overflow".to_owned()));
}

#[test]
fn packet_budget_rejection_does_not_reserve_phantom_link_time() {
    let fixture = Fixture::with_network_config(
        [14; 32],
        NetworkConfig {
            max_packets: 1,
            ephemeral_port_start: 40_000,
        },
    );
    fixture.network.add_host("a").unwrap();
    fixture.network.add_host("b").unwrap();
    fixture
        .network
        .add_link(
            "lan",
            LinkConfig {
                latency: Duration::ZERO,
                bits_per_second: 8,
                queue_packets: 10,
                ..LinkConfig::default()
            },
        )
        .unwrap();
    fixture
        .network
        .add_interface(
            "a",
            "a0",
            "lan",
            [IpCidr::new("192.0.2.1".parse().unwrap(), 24).unwrap()],
        )
        .unwrap();
    fixture
        .network
        .add_interface(
            "b",
            "b0",
            "lan",
            [IpCidr::new("192.0.2.2".parse().unwrap(), 24).unwrap()],
        )
        .unwrap();
    fixture
        .network
        .add_nat_with_firewall(
            "a",
            NatConfig {
                id: "transactional-nat".to_owned(),
                public_ip: Ipv4Addr::new(203, 0, 113, 14),
                port_start: 40_000,
                port_end: 40_127,
                mapping_behavior: NatMappingBehavior::AddressAndPortDependent,
                filtering_behavior: NatFilteringBehavior::EndpointIndependent,
                mapping_ttl: Duration::from_secs(30),
                hairpin: true,
                max_mappings: 128,
            },
            FirewallConfig {
                id: "transactional-firewall".to_owned(),
                rules: vec![
                    FirewallRule {
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
                    FirewallRule {
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
                ],
                default_action: FirewallAction::Drop,
            },
        )
        .unwrap();
    fixture
        .network
        .add_route(
            "b",
            "default",
            IpCidr::new(Ipv4Addr::UNSPECIFIED.into(), 0).unwrap(),
            "b0",
            None,
        )
        .unwrap();
    let a = fixture.network.socket_factory("a").unwrap();
    let b = fixture.network.socket_factory("b").unwrap();
    let source = a.bind("192.0.2.1:1001".parse().unwrap()).unwrap();
    let destination = b.bind("192.0.2.2:1002".parse().unwrap()).unwrap();
    let second_destination = b.bind("192.0.2.2:1003".parse().unwrap()).unwrap();

    send(&source, destination.local_addr().unwrap(), b"1").unwrap();
    let external = fixture.network.nat_snapshot("transactional-nat").unwrap()[0].external;
    assert_eq!(
        fixture
            .network
            .nat_snapshot("transactional-nat")
            .unwrap()
            .len(),
        1
    );
    let rejected = send(&source, second_destination.local_addr().unwrap(), b"2").unwrap_err();
    assert_eq!(rejected.kind(), io::ErrorKind::Other);
    assert_eq!(
        fixture
            .network
            .nat_snapshot("transactional-nat")
            .unwrap()
            .len(),
        1,
        "packet admission failure must roll back a newly-created NAT mapping"
    );
    assert!(fixture.trace.events().iter().any(|event| matches!(
        &event.event,
        TraceEventKind::NatMapping { transition, .. } if transition == "rolled_back"
    )));
    assert!(matches!(
        fixture.kernel.step().unwrap(),
        iroh_sim::KernelStep::Progress
    ));
    assert_eq!(fixture.kernel.now(), Duration::from_secs(1));

    send(&source, destination.local_addr().unwrap(), b"3").unwrap();
    assert!(matches!(
        fixture.kernel.step().unwrap(),
        iroh_sim::KernelStep::Progress
    ));
    assert_eq!(fixture.kernel.now(), Duration::from_secs(2));

    send(&second_destination, external, b"phantom").unwrap();
    assert!(matches!(
        fixture.kernel.step().unwrap(),
        iroh_sim::KernelStep::Progress
    ));
    assert!(
        recv(&source, 64).is_none(),
        "rejected outbound traffic must not create phantom established-firewall state"
    );
    fixture.network.clear_nats().unwrap();
}

#[test]
fn unroutable_and_invalid_source_sends_are_distinct_and_traced() {
    let fixture = Fixture::direct_dual_stack([9; 32], LinkConfig::default());
    let source = fixture
        .network
        .socket_factory("a")
        .unwrap()
        .bind("0.0.0.0:1001".parse().unwrap())
        .unwrap();

    let no_route = send(&source, "198.51.100.2:1002".parse().unwrap(), b"lost").unwrap_err();
    assert_eq!(no_route.kind(), io::ErrorKind::NetworkUnreachable);

    let mut sender = source.clone().create_sender();
    let transmit = noq_udp::Transmit {
        destination: "192.0.2.2:1002".parse().unwrap(),
        ecn: None,
        contents: b"spoofed",
        segment_size: None,
        src_ip: Some("192.0.2.99".parse().unwrap()),
    };
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let invalid_source = match sender.as_mut().poll_send(&transmit, &mut cx) {
        Poll::Ready(Err(error)) => error,
        result => panic!("unexpected send result: {result:?}"),
    };
    assert_eq!(invalid_source.kind(), io::ErrorKind::InvalidInput);

    let outcomes = packet_outcomes(&fixture);
    assert!(outcomes.contains(&"rejected:no_route".to_owned()));
    assert!(outcomes.contains(&"rejected:invalid_source".to_owned()));
}

#[test]
fn conflicting_specific_and_wildcard_binds_are_rejected() {
    let fixture = Fixture::direct_dual_stack([10; 32], LinkConfig::default());
    let factory = fixture.network.socket_factory("a").unwrap();
    let _first = factory.bind("0.0.0.0:7000".parse().unwrap()).unwrap();
    let error = factory.bind("192.0.2.1:7000".parse().unwrap()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
}

#[test]
fn equal_connected_routes_on_different_interfaces_are_rejected() {
    let fixture = Fixture::new([11; 32]);
    fixture.network.add_host("a").unwrap();
    fixture
        .network
        .add_link("left", LinkConfig::default())
        .unwrap();
    fixture
        .network
        .add_link("right", LinkConfig::default())
        .unwrap();
    fixture
        .network
        .add_interface(
            "a",
            "a0",
            "left",
            [IpCidr::new("10.0.0.1".parse().unwrap(), 24).unwrap()],
        )
        .unwrap();

    assert!(matches!(
        fixture.network.add_interface(
            "a",
            "a1",
            "right",
            [IpCidr::new("10.0.0.2".parse().unwrap(), 24).unwrap()],
        ),
        Err(NetworkError::AmbiguousRoute { .. })
    ));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn routed_delivery_is_independent_of_behavioral_seed(seed in any::<[u8; 32]>()) {
        let fixture = routed_fixture(seed);
        let a = fixture.network.socket_factory("a").unwrap();
        let b = fixture.network.socket_factory("b").unwrap();
        let source = a.bind("10.0.0.2:1001".parse().unwrap()).unwrap();
        let destination = b.bind("10.0.1.2:1002".parse().unwrap()).unwrap();

        send(&source, destination.local_addr().unwrap(), b"routed").unwrap();
        fixture.kernel.run_until_idle().unwrap();

        prop_assert_eq!(recv(&destination, 64).unwrap().0, b"routed");
    }

    #[test]
    fn queued_packet_ledger_never_exceeds_link_capacity(
        capacity in 1u64..8,
        sends in 1usize..20,
        duplicate in any::<bool>(),
    ) {
        let fixture = Fixture::direct_dual_stack(
            [13; 32],
            LinkConfig {
                latency: Duration::from_secs(1),
                queue_packets: capacity,
                duplicate_per_million: if duplicate { 1_000_000 } else { 0 },
                ..LinkConfig::default()
            },
        );
        let a = fixture.network.socket_factory("a").unwrap();
        let b = fixture.network.socket_factory("b").unwrap();
        let source = a.bind("192.0.2.1:1001".parse().unwrap()).unwrap();
        let destination = b.bind("192.0.2.2:1002".parse().unwrap()).unwrap();

        for _ in 0..sends {
            send(&source, destination.local_addr().unwrap(), b"queued").unwrap();
            prop_assert!(
                fixture.kernel.ledger().current(ResourceKind::QueuedPacket) <= capacity
            );
        }
        prop_assert!(
            fixture.kernel.ledger().high_water(ResourceKind::QueuedPacket) <= capacity
        );
        fixture.kernel.run_until_idle().unwrap();
        prop_assert_eq!(fixture.kernel.ledger().current(ResourceKind::QueuedPacket), 0);
    }
}

#[test]
fn closing_destination_before_delivery_drops_packet_and_releases_resources() {
    let fixture = Fixture::direct_dual_stack(
        [12; 32],
        LinkConfig {
            latency: Duration::from_millis(10),
            ..LinkConfig::default()
        },
    );
    let a = fixture.network.socket_factory("a").unwrap();
    let b = fixture.network.socket_factory("b").unwrap();
    let source = a.bind("192.0.2.1:1001".parse().unwrap()).unwrap();
    let destination = b.bind("192.0.2.2:1002".parse().unwrap()).unwrap();

    send(&source, destination.local_addr().unwrap(), b"closed").unwrap();
    drop(destination);
    fixture.kernel.run_until_idle().unwrap();

    assert!(packet_outcomes(&fixture).contains(&"dropped:no_socket".to_owned()));
    assert_eq!(
        fixture.kernel.ledger().current(ResourceKind::QueuedPacket),
        0
    );
}

fn routed_fixture(seed: [u8; 32]) -> Fixture {
    let fixture = Fixture::new(seed);
    for host in ["a", "router", "b"] {
        fixture.network.add_host(host).unwrap();
    }
    fixture
        .network
        .add_link("left", LinkConfig::default())
        .unwrap();
    fixture
        .network
        .add_link("right", LinkConfig::default())
        .unwrap();
    fixture
        .network
        .add_interface(
            "a",
            "a0",
            "left",
            [IpCidr::new("10.0.0.2".parse().unwrap(), 24).unwrap()],
        )
        .unwrap();
    fixture
        .network
        .add_interface(
            "router",
            "r0",
            "left",
            [IpCidr::new("10.0.0.1".parse().unwrap(), 24).unwrap()],
        )
        .unwrap();
    fixture
        .network
        .add_interface(
            "router",
            "r1",
            "right",
            [IpCidr::new("10.0.1.1".parse().unwrap(), 24).unwrap()],
        )
        .unwrap();
    fixture
        .network
        .add_interface(
            "b",
            "b0",
            "right",
            [IpCidr::new("10.0.1.2".parse().unwrap(), 24).unwrap()],
        )
        .unwrap();
    fixture
        .network
        .add_route(
            "a",
            "default",
            IpCidr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).unwrap(),
            "a0",
            Some("router"),
        )
        .unwrap();
    fixture
}

fn packet_outcomes(fixture: &Fixture) -> Vec<String> {
    fixture
        .trace
        .events()
        .into_iter()
        .filter_map(|event| match event.event {
            TraceEventKind::PacketOutcome { outcome } => Some(outcome),
            _ => None,
        })
        .collect()
}

fn send(socket: &Arc<dyn IpSocket>, destination: SocketAddr, payload: &[u8]) -> io::Result<()> {
    let mut sender = socket.clone().create_sender();
    let transmit = noq_udp::Transmit {
        destination,
        ecn: None,
        contents: payload,
        segment_size: None,
        src_ip: None,
    };
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    match sender.as_mut().poll_send(&transmit, &mut cx) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("synthetic sender is deterministically writable"),
    }
}

fn recv(socket: &Arc<dyn IpSocket>, capacity: usize) -> Option<(Vec<u8>, noq_udp::RecvMeta)> {
    let mut bytes = vec![0; capacity];
    let mut bufs = [IoSliceMut::new(&mut bytes)];
    let mut metas = [noq_udp::RecvMeta::default()];
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    match socket.poll_recv(&mut cx, &mut bufs, &mut metas) {
        Poll::Ready(Ok(1)) => {
            bytes.truncate(metas[0].len);
            Some((bytes, metas[0]))
        }
        Poll::Pending | Poll::Ready(Ok(0)) => None,
        Poll::Ready(Ok(count)) => panic!("unexpected receive count {count}"),
        Poll::Ready(Err(error)) => panic!("receive failed: {error}"),
    }
}

#[allow(dead_code)]
fn assert_sender_object_safe(_: Pin<Box<dyn IpSocketSender>>) {}
