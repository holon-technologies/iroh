use std::{net::SocketAddr, sync::Arc, time::Duration};

use iroh::{
    Endpoint, EndpointAddr, NetReportConfig, SecretKey,
    endpoint::{PortmapperConfig, presets},
    simulation::SimulationCryptoMaterial,
};
use iroh_runtime::{RootSeed, UnsafeTestOnly};
use iroh_sim::{
    DeterministicBackend, DeterministicBackendConfig, IpCidr, KernelConfig, LinkConfig,
    NetworkConfig, ResourceKind, RunBudgets, ScenarioHarness, Stage2Scenario, TraceBuffer,
    first_trace_divergence,
};

const ALPN: &[u8] = b"iroh-sim/endpoint-echo/1";

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn named_ipv6_stream_scenario_runs_production_quic_to_clean_shutdown() {
    let scenario = Stage2Scenario {
        schema_version: iroh_sim::STAGE2_SCENARIO_SCHEMA_VERSION,
        id: "direct-ip/ipv6-stream".to_owned(),
    };
    let harness = ScenarioHarness::new(
        scenario,
        RootSeed::new([19; 32]),
        std::time::SystemTime::UNIX_EPOCH,
        &RunBudgets {
            max_events: 100_000,
            max_virtual_time_nanos: 60_000_000_000,
            max_tasks: 1_024,
            max_packets: 10_000,
        },
    )
    .unwrap();

    let observation = harness.run().await.unwrap();

    assert!(observation.events > 0);
    assert!(observation.packet_high_water > 0);
    assert!(harness.backend().kernel().ledger().is_empty());
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn named_fault_scenarios_recover_or_fail_as_specified_through_production_quic() {
    for (id, seed) in [
        ("direct-ip/ipv4-stream-loss", [30; 32]),
        ("direct-ip/ipv4-stream-corruption", [31; 32]),
    ] {
        let harness = ScenarioHarness::new(
            Stage2Scenario {
                schema_version: iroh_sim::STAGE2_SCENARIO_SCHEMA_VERSION,
                id: id.to_owned(),
            },
            RootSeed::new(seed),
            std::time::SystemTime::UNIX_EPOCH,
            &RunBudgets {
                max_events: 100_000,
                max_virtual_time_nanos: 60_000_000_000,
                max_tasks: 1_024,
                max_packets: 10_000,
            },
        )
        .unwrap();

        harness
            .run()
            .await
            .unwrap_or_else(|error| panic!("{id}: {error}"));
        assert!(harness.backend().kernel().ledger().is_empty());
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn production_endpoints_exchange_a_quic_stream_over_the_synthetic_network() {
    let trace = TraceBuffer::default();
    let backend = DeterministicBackend::new(
        DeterministicBackendConfig {
            root_seed: RootSeed::new([42; 32]),
            wall_epoch: std::time::SystemTime::UNIX_EPOCH,
            kernel: KernelConfig {
                max_events: 100_000,
                max_virtual_time: Duration::from_secs(60),
                max_tasks: 1_024,
            },
            network: NetworkConfig {
                max_packets: 10_000,
                ephemeral_port_start: 40_000,
            },
            max_driver_turns: 200_000,
            crypto_mode: iroh::simulation::SimulationCryptoMode::DeterministicTest,
        },
        Arc::new(trace.clone()),
    )
    .unwrap();
    let kernel = backend.kernel().clone();
    let network = backend.network().clone();
    network.add_host("client").unwrap();
    network.add_host("server").unwrap();
    network
        .add_link(
            "lan",
            LinkConfig {
                latency: Duration::from_millis(2),
                bits_per_second: 100_000_000,
                ..LinkConfig::default()
            },
        )
        .unwrap();
    network
        .add_interface(
            "client",
            "eth0",
            "lan",
            [IpCidr::new("192.0.2.1".parse().unwrap(), 24).unwrap()],
        )
        .unwrap();
    network
        .add_interface(
            "server",
            "eth0",
            "lan",
            [IpCidr::new("192.0.2.2".parse().unwrap(), 24).unwrap()],
        )
        .unwrap();

    let client_addr: SocketAddr = "192.0.2.1:30001".parse().unwrap();
    let server_addr: SocketAddr = "192.0.2.2:30002".parse().unwrap();
    let client = bind_endpoint(&backend, "client", client_addr, [1; 32]).await;
    let server = bind_endpoint(&backend, "server", server_addr, [2; 32]).await;

    let server_id = server.id();
    let server_operation = {
        let server = server.clone();
        async move {
            let incoming = server
                .accept()
                .await
                .ok_or_else(|| "server endpoint closed".to_owned())?;
            let connection = incoming.await.map_err(|error| error.to_string())?;
            let (mut send, mut receive) = connection
                .accept_bi()
                .await
                .map_err(|error| error.to_string())?;
            let payload = receive
                .read_to_end(1_024)
                .await
                .map_err(|error| error.to_string())?;
            send.write_all(&payload)
                .await
                .map_err(|error| error.to_string())?;
            send.finish().map_err(|error| error.to_string())?;
            connection.closed().await;
            Ok::<_, String>(payload)
        }
    };
    let client_operation = {
        let client = client.clone();
        async move {
            let destination = EndpointAddr::new(server_id).with_ip_addr(server_addr);
            let connection = client
                .connect(destination, ALPN)
                .await
                .map_err(|error| error.to_string())?;
            let (mut send, mut receive) = connection
                .open_bi()
                .await
                .map_err(|error| error.to_string())?;
            send.write_all(b"production-path")
                .await
                .map_err(|error| error.to_string())?;
            send.finish().map_err(|error| error.to_string())?;
            let echoed = receive
                .read_to_end(1_024)
                .await
                .map_err(|error| error.to_string())?;
            connection.close(0u32.into(), b"complete");
            Ok::<_, String>(echoed)
        }
    };

    let exchange = backend
        .driver()
        .drive(async move {
            let (server, client) = tokio::join!(server_operation, client_operation);
            Ok::<_, String>((server, client))
        })
        .await
        .unwrap_or_else(|error| {
            panic!(
                "kernel driver failed: {error}; ready: {:?}; tasks: {:?}; tail: {:?}",
                kernel.ready_task_snapshot(),
                kernel.task_ownership_snapshot(),
                trace
                    .events()
                    .into_iter()
                    .rev()
                    .take(20)
                    .collect::<Vec<_>>(),
            )
        })
        .unwrap();
    let (server_payload, client_payload) = (exchange.0.unwrap(), exchange.1.unwrap());
    assert_eq!(server_payload, b"production-path");
    assert_eq!(client_payload, b"production-path");

    backend
        .driver()
        .drive(async { tokio::join!(client.close(), server.close()) })
        .await
        .unwrap();
    drop(client);
    drop(server);
    backend
        .driver()
        .drive_until(|| {
            kernel.ledger().current(ResourceKind::QueuedPacket) == 0
                && kernel.ledger().current(ResourceKind::Socket) == 0
        })
        .await
        .unwrap();
    assert_eq!(kernel.ledger().current(ResourceKind::QueuedPacket), 0);
    assert_eq!(kernel.ledger().current(ResourceKind::Socket), 0);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn ipv6_quic_datagrams_have_repeated_same_seed_traces() {
    let first = run_ipv6_datagram([77; 32]).await;
    let second = run_ipv6_datagram([77; 32]).await;
    if first != second {
        let index = first
            .iter()
            .zip(&second)
            .position(|(expected, actual)| expected != actual)
            .unwrap_or_else(|| first.len().min(second.len()));
        panic!(
            "deterministic TLS trace diverged at {index}: expected={:?} actual={:?}",
            first.get(index),
            second.get(index)
        );
    }
    if let Some(divergence) = first_trace_divergence(&first, &second).unwrap() {
        panic!(
            "trace diverged at {}: expected={} actual={}",
            divergence.index,
            divergence
                .expected
                .map(|value| String::from_utf8(value).unwrap())
                .unwrap_or_else(|| "<missing>".to_owned()),
            divergence
                .actual
                .map(|value| String::from_utf8(value).unwrap())
                .unwrap_or_else(|| "<missing>".to_owned())
        );
    }
}

async fn run_ipv6_datagram(seed: [u8; 32]) -> Vec<iroh_runtime::TraceEvent> {
    let trace = TraceBuffer::default();
    let backend = DeterministicBackend::new(
        DeterministicBackendConfig {
            root_seed: RootSeed::new(seed),
            wall_epoch: std::time::SystemTime::UNIX_EPOCH,
            kernel: KernelConfig {
                max_events: 100_000,
                max_virtual_time: Duration::from_secs(60),
                max_tasks: 1_024,
            },
            network: NetworkConfig {
                max_packets: 10_000,
                ephemeral_port_start: 40_000,
            },
            max_driver_turns: 200_000,
            crypto_mode: iroh::simulation::SimulationCryptoMode::DeterministicTest,
        },
        Arc::new(trace.clone()),
    )
    .unwrap();
    let network = backend.network();
    network.add_host("client6").unwrap();
    network.add_host("server6").unwrap();
    network.add_link("lan6", LinkConfig::default()).unwrap();
    network
        .add_interface(
            "client6",
            "eth0",
            "lan6",
            [IpCidr::new("2001:db8::1".parse().unwrap(), 64).unwrap()],
        )
        .unwrap();
    network
        .add_interface(
            "server6",
            "eth0",
            "lan6",
            [IpCidr::new("2001:db8::2".parse().unwrap(), 64).unwrap()],
        )
        .unwrap();
    let client_addr: SocketAddr = "[2001:db8::1]:31001".parse().unwrap();
    let server_addr: SocketAddr = "[2001:db8::2]:31002".parse().unwrap();
    let client = bind_endpoint(&backend, "client6", client_addr, [3; 32]).await;
    let server = bind_endpoint(&backend, "server6", server_addr, [4; 32]).await;

    let server_id = server.id();
    let server_operation = {
        let server = server.clone();
        async move {
            let incoming = server
                .accept()
                .await
                .ok_or_else(|| "server endpoint closed".to_owned())?;
            let connection = incoming.await.map_err(|error| error.to_string())?;
            let payload = connection
                .read_datagram()
                .await
                .map_err(|error| error.to_string())?;
            connection
                .send_datagram(payload.clone())
                .map_err(|error| error.to_string())?;
            connection.closed().await;
            Ok::<_, String>(payload)
        }
    };
    let client_operation = {
        let client = client.clone();
        async move {
            let connection = client
                .connect(EndpointAddr::new(server_id).with_ip_addr(server_addr), ALPN)
                .await
                .map_err(|error| error.to_string())?;
            connection
                .send_datagram(b"ipv6-datagram".as_slice().into())
                .map_err(|error| error.to_string())?;
            let echoed = connection
                .read_datagram()
                .await
                .map_err(|error| error.to_string())?;
            connection.close(0u32.into(), b"complete");
            Ok::<_, String>(echoed)
        }
    };
    let exchange = backend
        .driver()
        .drive(async move {
            let (server, client) = tokio::join!(server_operation, client_operation);
            Ok::<_, String>((server?, client?))
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(exchange.0.as_ref(), b"ipv6-datagram");
    assert_eq!(exchange.1.as_ref(), b"ipv6-datagram");

    backend
        .driver()
        .drive(async { tokio::join!(client.close(), server.close()) })
        .await
        .unwrap();
    drop(client);
    drop(server);
    backend
        .driver()
        .drive_until(|| backend.kernel().ledger().is_empty())
        .await
        .unwrap();
    assert!(backend.kernel().ledger().is_empty());

    trace.events()
}

async fn bind_endpoint(
    backend: &DeterministicBackend,
    host: &str,
    address: SocketAddr,
    secret: [u8; 32],
) -> Endpoint {
    let environment = backend
        .endpoint_environment(
            host,
            SimulationCryptoMaterial::new(secret, [secret[0].wrapping_add(1); 32]),
        )
        .unwrap();
    Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&secret))
        .alpns(vec![ALPN.to_vec()])
        .clear_ip_transports()
        .bind_addr(address)
        .unwrap()
        .portmapper_config(PortmapperConfig::Disabled)
        .net_report_config(NetReportConfig::minimal())
        .simulation_environment_for_test(environment, UnsafeTestOnly::acknowledge())
        .bind()
        .await
        .unwrap()
}
