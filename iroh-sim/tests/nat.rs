use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime},
};

use iroh_runtime::RootSeed;
use iroh_sim::{
    Firewall, FirewallAction, FirewallConfig, FirewallConnectionState, FirewallDirection,
    FirewallPacket, FirewallProtocol, FirewallRule, IpCidr, Kernel, KernelConfig, NatConfig,
    NatError, NatFilteringBehavior, NatMappingBehavior, NatTable, ResourceKind, TraceBuffer,
    normalized_trace_json,
};

#[test]
fn mapping_and_filtering_behaviors_match_the_declared_policy() {
    let internal: SocketAddr = "10.0.0.2:5000".parse().unwrap();
    let remote_a: SocketAddr = "198.51.100.1:6000".parse().unwrap();
    let remote_a_other_port: SocketAddr = "198.51.100.1:6001".parse().unwrap();
    let remote_b: SocketAddr = "198.51.100.2:6000".parse().unwrap();

    for (behavior, same_ip_reuses, other_ip_reuses) in [
        (NatMappingBehavior::EndpointIndependent, true, true),
        (NatMappingBehavior::AddressDependent, true, false),
        (NatMappingBehavior::AddressAndPortDependent, false, false),
    ] {
        let fixture = Fixture::new(behavior, NatFilteringBehavior::EndpointIndependent, true);
        let mut nat = fixture.nat;
        let first = nat.translate_outbound(0, internal, remote_a).unwrap();
        let same_ip = nat
            .translate_outbound(1, internal, remote_a_other_port)
            .unwrap();
        let other_ip = nat.translate_outbound(2, internal, remote_b).unwrap();
        assert_eq!(first.source == same_ip.source, same_ip_reuses);
        assert_eq!(first.source == other_ip.source, other_ip_reuses);
    }

    for (filter, same_ip_allowed, other_ip_allowed) in [
        (NatFilteringBehavior::EndpointIndependent, true, true),
        (NatFilteringBehavior::AddressDependent, true, false),
        (NatFilteringBehavior::AddressAndPortDependent, false, false),
    ] {
        let fixture = Fixture::new(NatMappingBehavior::EndpointIndependent, filter, true);
        let mut nat = fixture.nat;
        let mapped = nat.translate_outbound(0, internal, remote_a).unwrap();
        assert_eq!(
            nat.translate_inbound(1, mapped.source, remote_a_other_port)
                .is_ok(),
            same_ip_allowed
        );
        assert_eq!(
            nat.translate_inbound(2, mapped.source, remote_b).is_ok(),
            other_ip_allowed
        );
    }
}

#[test]
fn expiry_boundary_and_rebind_release_or_preserve_mapping_resources() {
    let fixture = Fixture::new(
        NatMappingBehavior::EndpointIndependent,
        NatFilteringBehavior::EndpointIndependent,
        true,
    );
    let kernel = fixture.kernel.clone();
    let mut nat = fixture.nat;
    let internal = "10.0.0.2:5000".parse().unwrap();
    let remote = "198.51.100.1:6000".parse().unwrap();
    let mapped = nat.translate_outbound(0, internal, remote).unwrap();
    assert_eq!(kernel.ledger().current(ResourceKind::Mapping), 1);
    assert!(nat.expire(99).unwrap().is_empty());
    assert_eq!(nat.expire(100).unwrap().len(), 1);
    assert_eq!(kernel.ledger().current(ResourceKind::Mapping), 0);
    assert!(matches!(
        nat.translate_inbound(100, mapped.source, remote),
        Err(NatError::NoMapping(_))
    ));

    let mapped = nat.translate_outbound(101, internal, remote).unwrap();
    nat.rebind(102, Ipv4Addr::new(203, 0, 113, 9), true)
        .unwrap();
    let preserved = nat.snapshot().pop().unwrap();
    assert_eq!(preserved.external.port(), mapped.source.port());
    assert_eq!(preserved.external.ip(), Ipv4Addr::new(203, 0, 113, 9));
    nat.rebind(103, Ipv4Addr::new(203, 0, 113, 10), false)
        .unwrap();
    assert!(nat.snapshot().is_empty());
    assert_eq!(kernel.ledger().current(ResourceKind::Mapping), 0);
    assert!(fixture.trace.events().iter().any(|event| {
        matches!(
            &event.event,
            iroh_runtime::TraceEventKind::NatMapping { transition, .. } if transition == "expired"
        )
    }));
}

#[test]
fn hairpin_and_double_nat_are_deterministic_and_family_safe() {
    let fixture = Fixture::new(
        NatMappingBehavior::EndpointIndependent,
        NatFilteringBehavior::EndpointIndependent,
        true,
    );
    let mut nat = fixture.nat;
    let remote = "198.51.100.1:7000".parse().unwrap();
    let target_internal = "10.0.0.3:5001".parse().unwrap();
    let target = nat.translate_outbound(0, target_internal, remote).unwrap();
    let source_internal = "10.0.0.2:5000".parse().unwrap();
    let hairpin = nat
        .translate_outbound(1, source_internal, target.source)
        .unwrap();
    assert_eq!(hairpin.hairpin_target, Some(target_internal));
    assert_eq!(hairpin.destination, target_internal);
    assert!(matches!(
        nat.translate_outbound(
            2,
            "[fd00::2]:5000".parse().unwrap(),
            "[2001:db8::1]:7000".parse().unwrap()
        ),
        Err(NatError::UnsupportedFamily(_))
    ));

    let first = double_nat_trace([8; 32]);
    let second = double_nat_trace([8; 32]);
    assert_eq!(first, second);
}

#[test]
fn disabled_hairpin_and_port_exhaustion_are_distinct() {
    let fixture = Fixture::new_with_port_end(
        NatMappingBehavior::AddressAndPortDependent,
        NatFilteringBehavior::EndpointIndependent,
        false,
        40_001,
    );
    let mut nat = fixture.nat;
    let remote = "198.51.100.1:7000".parse().unwrap();
    let target = nat
        .translate_outbound(0, "10.0.0.3:5001".parse().unwrap(), remote)
        .unwrap();
    assert!(matches!(
        nat.translate_outbound(1, "10.0.0.2:5000".parse().unwrap(), target.source),
        Err(NatError::HairpinDisabled)
    ));
    nat.translate_outbound(2, "10.0.0.4:5002".parse().unwrap(), remote)
        .unwrap();
    let error = nat
        .translate_outbound(3, "10.0.0.5:5003".parse().unwrap(), remote)
        .unwrap_err();
    assert!(matches!(error, NatError::PortExhausted));
}

#[test]
fn explicit_port_mapping_conflicts_with_an_existing_eim_dynamic_mapping() {
    let fixture = Fixture::new(
        NatMappingBehavior::EndpointIndependent,
        NatFilteringBehavior::EndpointIndependent,
        true,
    );
    let mut nat = fixture.nat;
    let internal = "10.0.0.2:5000".parse().unwrap();
    nat.translate_outbound(0, internal, "198.51.100.1:7000".parse().unwrap())
        .unwrap();

    assert!(matches!(
        nat.procure_port_mapping(1, internal),
        Err(NatError::PortMappingConflict(address)) if address == internal
    ));
    assert_eq!(nat.snapshot().len(), 1);
}

#[test]
fn firewall_rule_order_state_and_default_actions_are_explicit() {
    let trace = TraceBuffer::default();
    let kernel = Kernel::new(
        KernelConfig {
            max_events: 100,
            max_virtual_time: Duration::from_secs(1),
            max_tasks: 1,
        },
        Arc::new(trace.clone()),
    )
    .unwrap();
    let context = Arc::new(kernel.runtime_context(RootSeed::new([10; 32]), SystemTime::UNIX_EPOCH));
    let mut firewall = Firewall::new(
        context,
        FirewallConfig {
            id: "edge".to_owned(),
            rules: vec![
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
                FirewallRule {
                    id: "reject-admin".to_owned(),
                    protocol: FirewallProtocol::Udp,
                    direction: Some(FirewallDirection::Inbound),
                    source: Some(IpCidr::new("198.51.100.0".parse().unwrap(), 24).unwrap()),
                    destination: None,
                    source_ports: None,
                    destination_ports: Some((9000, 9000)),
                    connection_state: FirewallConnectionState::Any,
                    action: FirewallAction::Reject,
                },
            ],
            default_action: FirewallAction::Drop,
        },
    )
    .unwrap();
    let internal = "10.0.0.2:5000".parse().unwrap();
    let remote = "198.51.100.1:9000".parse().unwrap();
    let packet = FirewallPacket {
        source: internal,
        destination: remote,
    };
    assert_eq!(
        firewall
            .evaluate(FirewallDirection::Outbound, packet)
            .unwrap()
            .action,
        FirewallAction::Drop
    );

    let mut allowing = Firewall::new(
        Arc::new(kernel.runtime_context(RootSeed::new([11; 32]), SystemTime::UNIX_EPOCH)),
        FirewallConfig {
            id: "stateful".to_owned(),
            rules: vec![
                FirewallRule {
                    id: "allow-out".to_owned(),
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
            default_action: FirewallAction::Reject,
        },
    )
    .unwrap();
    allowing
        .evaluate(FirewallDirection::Outbound, packet)
        .unwrap();
    let inbound = allowing
        .evaluate(
            FirewallDirection::Inbound,
            FirewallPacket {
                source: remote,
                destination: internal,
            },
        )
        .unwrap();
    assert!(inbound.established);
    assert_eq!(inbound.rule, "allow-established");
    allowing.clear_state();
    assert_eq!(
        allowing
            .evaluate(
                FirewallDirection::Inbound,
                FirewallPacket {
                    source: remote,
                    destination: internal,
                },
            )
            .unwrap()
            .action,
        FirewallAction::Reject
    );
}

struct Fixture {
    kernel: Kernel,
    trace: TraceBuffer,
    nat: NatTable,
}

impl Fixture {
    fn new(
        mapping_behavior: NatMappingBehavior,
        filtering_behavior: NatFilteringBehavior,
        hairpin: bool,
    ) -> Self {
        Self::new_with_port_end(mapping_behavior, filtering_behavior, hairpin, 40_010)
    }

    fn new_with_port_end(
        mapping_behavior: NatMappingBehavior,
        filtering_behavior: NatFilteringBehavior,
        hairpin: bool,
        port_end: u16,
    ) -> Self {
        let trace = TraceBuffer::default();
        let kernel = Kernel::new(
            KernelConfig {
                max_events: 1_000,
                max_virtual_time: Duration::from_secs(1),
                max_tasks: 8,
            },
            Arc::new(trace.clone()),
        )
        .unwrap();
        let context =
            Arc::new(kernel.runtime_context(RootSeed::new([7; 32]), SystemTime::UNIX_EPOCH));
        let nat = NatTable::new(
            kernel.clone(),
            context,
            NatConfig {
                id: "home".to_owned(),
                public_ip: Ipv4Addr::new(203, 0, 113, 1),
                port_start: 40_000,
                port_end,
                mapping_behavior,
                filtering_behavior,
                mapping_ttl: Duration::from_nanos(100),
                hairpin,
                max_mappings: 16,
            },
        )
        .unwrap();
        Self { kernel, trace, nat }
    }
}

fn double_nat_trace(seed: [u8; 32]) -> Vec<Vec<u8>> {
    let trace = TraceBuffer::default();
    let kernel = Kernel::new(
        KernelConfig {
            max_events: 1_000,
            max_virtual_time: Duration::from_secs(1),
            max_tasks: 8,
        },
        Arc::new(trace.clone()),
    )
    .unwrap();
    let context = Arc::new(kernel.runtime_context(RootSeed::new(seed), SystemTime::UNIX_EPOCH));
    let config = |id: &str, public_ip| NatConfig {
        id: id.to_owned(),
        public_ip,
        port_start: 41_000,
        port_end: 41_100,
        mapping_behavior: NatMappingBehavior::EndpointIndependent,
        filtering_behavior: NatFilteringBehavior::EndpointIndependent,
        mapping_ttl: Duration::from_secs(1),
        hairpin: true,
        max_mappings: 32,
    };
    let mut inner = NatTable::new(
        kernel.clone(),
        context.clone(),
        config("home", Ipv4Addr::new(100, 64, 0, 2)),
    )
    .unwrap();
    let mut outer = NatTable::new(
        kernel,
        context,
        config("cgnat", Ipv4Addr::new(203, 0, 113, 2)),
    )
    .unwrap();
    let remote = "198.51.100.1:7000".parse().unwrap();
    let first = inner
        .translate_outbound(0, "10.0.0.2:5000".parse().unwrap(), remote)
        .unwrap();
    outer.translate_outbound(0, first.source, remote).unwrap();
    trace
        .events()
        .iter()
        .map(|event| normalized_trace_json(event).unwrap())
        .collect()
}
