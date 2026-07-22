use std::{
    net::Ipv4Addr,
    num::NonZeroU16,
    sync::Arc,
    time::{Duration, SystemTime},
};

use iroh::simulation::{IpSocket, PortMapper};
use iroh_runtime::RootSeed;
use iroh_sim::{
    DeterministicPortMapper, IpCidr, Kernel, KernelConfig, LinkConfig, NatConfig,
    NatFilteringBehavior, NatMappingBehavior, NetworkConfig, ResourceKind, SyntheticNetwork,
    TraceBuffer,
};

#[test]
fn injected_port_mapping_opens_renews_expires_and_cleans_up_nat_state() {
    let trace = TraceBuffer::default();
    let kernel = Kernel::new(
        KernelConfig {
            max_events: 1_000,
            max_virtual_time: Duration::from_secs(60),
            max_tasks: 16,
        },
        Arc::new(trace),
    )
    .unwrap();
    let context = Arc::new(kernel.runtime_context(RootSeed::new([51; 32]), SystemTime::UNIX_EPOCH));
    let network = SyntheticNetwork::new(
        kernel.clone(),
        context,
        NetworkConfig {
            max_packets: 100,
            ephemeral_port_start: 50_000,
        },
    )
    .unwrap();
    for host in ["private", "remote"] {
        network.add_host(host).unwrap();
    }
    network.add_link("wan", LinkConfig::default()).unwrap();
    for (host, address) in [("private", "10.0.0.2"), ("remote", "198.51.100.2")] {
        network
            .add_interface(
                host,
                "eth0",
                "wan",
                [IpCidr::new(address.parse().unwrap(), 0).unwrap()],
            )
            .unwrap();
    }
    network
        .add_nat(
            "private",
            NatConfig {
                id: "home".to_owned(),
                public_ip: Ipv4Addr::new(203, 0, 113, 17),
                port_start: 40_000,
                port_end: 40_127,
                mapping_behavior: NatMappingBehavior::AddressAndPortDependent,
                filtering_behavior: NatFilteringBehavior::AddressAndPortDependent,
                mapping_ttl: Duration::from_secs(10),
                hairpin: true,
                max_mappings: 128,
            },
        )
        .unwrap();
    let mapper = DeterministicPortMapper::new(
        "private/port-mapper",
        "private",
        "home",
        kernel.clone(),
        network.clone(),
    );
    let mut external = mapper.watch_external_address();
    mapper.update_local_port(NonZeroU16::new(5_000).unwrap());
    mapper.procure_mapping();
    assert!(mapper.take_error().is_none());
    let public = external.borrow_and_update().expect("mapping published");
    let snapshot = network.nat_snapshot("home").unwrap();
    assert_eq!(snapshot.len(), 1);
    assert!(snapshot[0].port_mapping);
    let first_expiry = snapshot[0].expires_nanos;

    let private = network
        .socket_factory("private")
        .unwrap()
        .bind("10.0.0.2:5000".parse().unwrap())
        .unwrap();
    let remote = network
        .socket_factory("remote")
        .unwrap()
        .bind("198.51.100.2:6000".parse().unwrap())
        .unwrap();
    send(&remote, public.into(), b"inbound");
    kernel.step().unwrap();
    assert_eq!(recv(&private), b"inbound");

    mapper.procure_mapping();
    let renewed = network.nat_snapshot("home").unwrap();
    assert!(renewed[0].expires_nanos > first_expiry);
    network
        .rebind_nat("home", Ipv4Addr::new(203, 0, 113, 18), true)
        .unwrap();
    mapper.refresh();
    assert!(mapper.take_error().is_none());
    assert_eq!(
        external.borrow_and_update().expect("rebind published").ip(),
        &Ipv4Addr::new(203, 0, 113, 18)
    );
    kernel.run_until_idle().unwrap();
    assert!(network.nat_snapshot("home").unwrap().is_empty());
    assert!(external.borrow_and_update().is_none());
    assert_eq!(kernel.ledger().current(ResourceKind::Mapping), 0);

    mapper.deactivate();
    assert!(mapper.take_error().is_none());
}

fn send(socket: &Arc<dyn IpSocket>, destination: std::net::SocketAddr, payload: &[u8]) {
    use std::task::{Context, Poll, Waker};

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
    assert!(matches!(
        sender.as_mut().poll_send(&transmit, &mut cx),
        Poll::Ready(Ok(()))
    ));
}

fn recv(socket: &Arc<dyn IpSocket>) -> Vec<u8> {
    use std::{
        io::IoSliceMut,
        task::{Context, Poll, Waker},
    };

    let mut bytes = vec![0; 64];
    let mut bufs = [IoSliceMut::new(&mut bytes)];
    let mut metas = [noq_udp::RecvMeta::default()];
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    match socket.poll_recv(&mut cx, &mut bufs, &mut metas) {
        Poll::Ready(Ok(1)) => {
            bytes.truncate(metas[0].len);
            bytes
        }
        other => panic!("unexpected receive result: {other:?}"),
    }
}
