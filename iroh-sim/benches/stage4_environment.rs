use std::{hint::black_box, net::Ipv4Addr, sync::Arc, time::Duration};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use iroh::{SecretKey, endpoint::PortmapperConfig};
use iroh_runtime::{NoopTraceSink, RootSeed};
use iroh_sim::{
    DeterministicDiscovery, Firewall, FirewallAction, FirewallConfig, FirewallConnectionState,
    FirewallDirection, FirewallPacket, FirewallProtocol, FirewallRule, Kernel, KernelConfig,
    NatConfig, NatFilteringBehavior, NatMappingBehavior, NatTable,
};

fn stage4_environment(c: &mut Criterion) {
    let mut group = c.benchmark_group("stage4_environment");
    group.throughput(Throughput::Elements(1));

    let mut nat = nat_table();
    let internal = "10.0.0.2:5000".parse().unwrap();
    let remote = "198.51.100.1:6000".parse().unwrap();
    nat.translate_outbound(0, internal, remote).unwrap();
    group.bench_function("nat_mapping_reuse", |b| {
        let mut now = 1u64;
        b.iter(|| {
            now += 1;
            black_box(nat.translate_outbound(now, internal, remote).unwrap());
        });
    });

    let (_firewall_kernel, mut firewall) = firewall();
    let packet = FirewallPacket {
        source: internal,
        destination: remote,
    };
    group.bench_function("firewall_ordered_allow", |b| {
        b.iter(|| {
            black_box(
                firewall
                    .evaluate(FirewallDirection::Outbound, packet)
                    .unwrap(),
            );
        });
    });

    let (discovery, endpoint) = discovery();
    let address = "192.0.2.2:31002".parse().unwrap();
    group.bench_function("discovery_replace_and_withdraw", |b| {
        b.iter(|| {
            black_box(
                discovery
                    .publish(
                        "server",
                        "server",
                        endpoint,
                        vec![address],
                        0,
                        1_000_000_000,
                        false,
                    )
                    .unwrap(),
            );
            black_box(discovery.withdraw("server", "server").unwrap());
        });
    });

    // Production defaults retain `None` for every simulation-only hook. Keep this constructor
    // benchmark as the disabled-path regression baseline; it performs no simulator allocation.
    group.bench_function("production_builder_simulation_hooks_disabled", |b| {
        b.iter(|| black_box(iroh::endpoint::Builder::empty()));
    });
    group.bench_function("production_builder_portmapper_disabled", |b| {
        b.iter(|| {
            black_box(
                iroh::endpoint::Builder::empty().portmapper_config(PortmapperConfig::Disabled),
            )
        });
    });
    group.finish();
}

fn kernel(seed: [u8; 32]) -> (Kernel, Arc<iroh_runtime::RuntimeContext>) {
    let kernel = Kernel::new(
        KernelConfig {
            max_events: 1_000_000,
            max_virtual_time: Duration::from_secs(60),
            max_tasks: 8,
        },
        Arc::new(NoopTraceSink),
    )
    .unwrap();
    let context =
        Arc::new(kernel.runtime_context(RootSeed::new(seed), std::time::SystemTime::UNIX_EPOCH));
    (kernel, context)
}

fn nat_table() -> NatTable {
    let (kernel, context) = kernel([1; 32]);
    NatTable::new(
        kernel,
        context,
        NatConfig {
            id: "bench".to_owned(),
            public_ip: Ipv4Addr::new(203, 0, 113, 1),
            port_start: 40_000,
            port_end: 40_127,
            mapping_behavior: NatMappingBehavior::EndpointIndependent,
            filtering_behavior: NatFilteringBehavior::AddressAndPortDependent,
            mapping_ttl: Duration::from_secs(60),
            hairpin: false,
            max_mappings: 128,
        },
    )
    .unwrap()
}

fn firewall() -> (Kernel, Firewall) {
    let (kernel, context) = kernel([2; 32]);
    let firewall = Firewall::new(
        context,
        FirewallConfig {
            id: "bench".to_owned(),
            rules: vec![FirewallRule {
                id: "allow-outbound".to_owned(),
                protocol: FirewallProtocol::Udp,
                direction: Some(FirewallDirection::Outbound),
                source: None,
                destination: None,
                source_ports: None,
                destination_ports: None,
                connection_state: FirewallConnectionState::Any,
                action: FirewallAction::Allow,
            }],
            default_action: FirewallAction::Drop,
        },
    )
    .unwrap();
    (kernel, firewall)
}

fn discovery() -> (DeterministicDiscovery, iroh::EndpointId) {
    let (kernel, context) = kernel([3; 32]);
    (
        DeterministicDiscovery::new("bench", 1, kernel, context).unwrap(),
        SecretKey::from_bytes(&[4; 32]).public(),
    )
}

criterion_group!(benches, stage4_environment);
criterion_main!(benches);
