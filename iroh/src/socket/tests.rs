use std::{net::SocketAddrV4, sync::Arc, time::Duration};

use data_encoding::HEXLOWER;
use iroh_base::{EndpointAddr, EndpointId, TransportAddr};
use iroh_relay::tls::{CaTlsConfig, default_provider};
use n0_error::{Result, StackResultExt, StdResultExt};
use n0_future::{MergeBounded, StreamExt, time};
use n0_tracing_test::traced_test;
use n0_watcher::Watcher;
use rand::{CryptoRng, Rng, RngExt, SeedableRng};
use tokio_util::task::AbortOnDropHandle;
use tracing::{Instrument, error, info, info_span, instrument};

use super::{Options, noq_behavioral_seed};
use crate::{
    Endpoint, SecretKey,
    address_lookup::memory::MemoryLookup,
    dns::DnsResolver,
    endpoint::{QuicTransportConfig, presets},
    socket::{
        EndpointInner, StaticConfig, TransportConfig,
        biased_rtt_path_selector::BiasedRttPathSelector,
        mapped_addrs::{EndpointIdMappedAddr, MappedAddr},
    },
    tls::{self, DEFAULT_MAX_TLS_TICKETS, misc::RustlsTokenKey},
};

const ALPN: &[u8] = b"n0/test/1";

#[test]
fn noq_seed_is_replayable_and_endpoint_scoped() {
    let context = iroh_runtime::RuntimeContext::tokio(
        iroh_runtime::RootSeed::new([31; 32]),
        Arc::new(iroh_runtime::NoopTraceSink),
    );
    let first = SecretKey::from_bytes(&[1; 32]).public();
    let second = SecretKey::from_bytes(&[2; 32]).public();

    assert_eq!(
        noq_behavioral_seed(&context, first).unwrap(),
        noq_behavioral_seed(&context, first).unwrap()
    );
    assert_ne!(
        noq_behavioral_seed(&context, first).unwrap(),
        noq_behavioral_seed(&context, second).unwrap()
    );
}

fn default_options(rng: &mut impl CryptoRng) -> Options {
    let crypto_provider = default_provider();
    let secret_key = SecretKey::from_bytes(&rng.random());
    let runtime_context = Arc::new(iroh_runtime::RuntimeContext::production(Arc::new(
        iroh_runtime::NoopTraceSink,
    )));
    let tls_config = tls::TlsConfig::new(
        secret_key.clone(),
        DEFAULT_MAX_TLS_TICKETS,
        crypto_provider.clone(),
    );
    let static_config = StaticConfig {
        server_config: tls_config.make_server_config(false).unwrap(),
        client_config: tls_config.make_client_config(false).unwrap(),
        tls_config,
        token_key: Arc::new(RustlsTokenKey::new(rng, &crypto_provider).unwrap()),
        token_store: Arc::new(noq::TokenMemoryCache::default()),
        transport_config: QuicTransportConfig::default(),
        runtime_context: runtime_context.clone(),
        simulation_initial_dst_cid_provider: None,
        limits: crate::endpoint::EndpointLimits::default(),
    };
    let server_config = static_config.create_server_config(vec![]);
    Options {
        transports: vec![
            TransportConfig::default_ipv4(),
            TransportConfig::default_ipv6(),
        ],
        secret_key,
        proxy_url: None,
        dns_resolver: DnsResolver::new(),
        runtime_context,
        ip_socket_factory: Arc::new(crate::simulation::OsIpSocketFactory),
        network_monitor: None,
        simulation_port_mapper: None,
        simulation_relay_connector: None,
        simulation_preferred_relay: None,
        simulation_reset_key: None,
        server_config,
        tls_config: CaTlsConfig::default()
            .client_config(crypto_provider.clone())
            .unwrap(),
        #[cfg(any(test, feature = "test-utils"))]
        address_lookup_user_data: None,
        metrics: Default::default(),
        hooks: Default::default(),
        path_selector: Arc::new(BiasedRttPathSelector::default()),
        portmapper_config: Default::default(),
        net_report_config: Default::default(),
        static_config,
        configured_addrs: Default::default(),
        limits: crate::endpoint::EndpointLimits::default(),
    }
}

#[instrument(skip_all, fields(me = %ep.id().fmt_short()))]
async fn echo_receiver(ep: Endpoint, loss: ExpectedLoss) -> Result {
    info!("accepting conn");
    let conn = ep.accept().await.expect("no conn");

    info!("accepting");
    let conn = conn.await.context("accepting")?;
    info!("accepting bi");
    let (mut send_bi, mut recv_bi) = conn.accept_bi().await.std_context("accept bi")?;

    info!("reading");
    let val = recv_bi
        .read_to_end(usize::MAX)
        .await
        .std_context("read to end")?;

    info!("replying");
    for chunk in val.chunks(12) {
        send_bi.write_all(chunk).await.std_context("write all")?;
    }

    info!("finishing");
    send_bi.finish().std_context("finish")?;

    let stats = conn.stats();
    info!("stats: {:#?}", stats);
    if matches!(loss, ExpectedLoss::AlmostNone) {
        for info in conn.paths().iter() {
            assert!(
                info.stats().lost_packets < 10,
                "[receiver] path {:?} should not loose many packets",
                info.remote_addr()
            );
        }
    }

    conn.closed().await;
    info!("closed");
    ep.inner()?.noq_endpoint().wait_idle().await;
    info!("idle");

    Ok(())
}

#[instrument(skip_all, fields(me = %ep.id().fmt_short()))]
async fn echo_sender(ep: Endpoint, dest_id: EndpointId, msg: &[u8], loss: ExpectedLoss) -> Result {
    info!("connecting to {}", dest_id.fmt_short());
    let dest = EndpointAddr::new(dest_id);
    let conn = ep.connect(dest, ALPN).await?;

    info!("opening bi");
    let (mut send_bi, mut recv_bi) = conn.open_bi().await.std_context("open bi")?;

    info!("writing message");
    send_bi.write_all(msg).await.std_context("write all")?;

    info!("finishing");
    send_bi.finish().std_context("finish")?;

    info!("reading_to_end");
    let val = recv_bi
        .read_to_end(usize::MAX)
        .await
        .std_context("read to end")?;
    assert_eq!(
        val,
        msg,
        "[sender] expected {}, got {}",
        HEXLOWER.encode(msg),
        HEXLOWER.encode(&val)
    );

    let stats = conn.stats();
    info!("stats: {:#?}", stats);
    if matches!(loss, ExpectedLoss::AlmostNone) {
        for info in conn.paths().iter() {
            assert!(
                info.stats().lost_packets < 10,
                "[sender] path {:?} should not loose many packets",
                info.remote_addr()
            );
        }
    }

    conn.close(0u32.into(), b"done");
    info!("closed");
    ep.inner()?.noq_endpoint().wait_idle().await;
    info!("idle");
    Ok(())
}

#[derive(Debug, Copy, Clone)]
enum ExpectedLoss {
    AlmostNone,
    YeahSure,
}

/// Runs a roundtrip between the [`echo_sender`] and [`echo_receiver`].
async fn run_roundtrip(
    sender: Endpoint,
    receiver: Endpoint,
    payload: &[u8],
    loss: ExpectedLoss,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async move {
        let send_endpoint_id = sender.id();
        let recv_endpoint_id = receiver.id();
        info!("\nroundtrip: {send_endpoint_id:#} -> {recv_endpoint_id:#}");

        let receiver_task = AbortOnDropHandle::new(tokio::spawn(echo_receiver(receiver, loss)));
        let sender_res = echo_sender(sender, recv_endpoint_id, payload, loss).await;
        let sender_is_err = match sender_res {
            Ok(()) => false,
            Err(err) => {
                error!("[sender] Error:\n{err:#?}");
                true
            }
        };
        let receiver_is_err = match receiver_task.await {
            Ok(Ok(())) => false,
            Ok(Err(err)) => {
                error!("[receiver] Error:\n{err:#?}");
                true
            }
            Err(joinerr) => {
                if joinerr.is_panic() {
                    std::panic::resume_unwind(joinerr.into_panic());
                } else {
                    error!("[receiver] Error:\n{joinerr:#?}");
                }
                true
            }
        };
        if sender_is_err || receiver_is_err {
            panic!("Sender or receiver errored");
        }
    })
    .await
    .std_context("timeout")?;
    Ok(())
}

/// Returns a pair of endpoints with a shared [`MemoryLookup`].
///
/// The endpoints do not use a relay server but can connect to each other via local
/// addresses.  Dialing by [`EndpointId`] is possible, and the addresses get updated even if
/// the endpoints rebind.
async fn endpoint_pair() -> (AbortOnDropHandle<()>, Endpoint, Endpoint) {
    let address_lookup = MemoryLookup::new();
    let ep1 = Endpoint::builder(presets::Minimal)
        .alpns(vec![ALPN.to_vec()])
        .address_lookup(address_lookup.clone())
        .bind()
        .await
        .unwrap();
    let ep2 = Endpoint::builder(presets::Minimal)
        .alpns(vec![ALPN.to_vec()])
        .address_lookup(address_lookup.clone())
        .bind()
        .await
        .unwrap();
    address_lookup.add_endpoint_info(ep1.addr());
    address_lookup.add_endpoint_info(ep2.addr());

    let ep1_addr_stream = ep1.watch_addr().stream();
    let ep2_addr_stream = ep2.watch_addr().stream();
    let mut addr_stream = MergeBounded::from_iter([ep1_addr_stream, ep2_addr_stream]);
    let task = tokio::spawn(async move {
        while let Some(addr) = addr_stream.next().await {
            address_lookup.add_endpoint_info(addr);
        }
    });

    (AbortOnDropHandle::new(task), ep1, ep2)
}

#[tokio::test(flavor = "multi_thread")]
#[traced_test]
async fn test_two_devices_roundtrip_noq_small() -> Result {
    let (_guard, m1, m2) = endpoint_pair().await;

    run_roundtrip(
        m1.clone(),
        m2.clone(),
        b"hello m1",
        ExpectedLoss::AlmostNone,
    )
    .await?;
    run_roundtrip(
        m2.clone(),
        m1.clone(),
        b"hello m2",
        ExpectedLoss::AlmostNone,
    )
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[traced_test]
async fn test_two_devices_roundtrip_noq_large() -> Result {
    let (_guard, m1, m2) = endpoint_pair().await;
    let mut data = vec![0u8; 10 * 1024];
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
    rng.fill_bytes(&mut data);
    run_roundtrip(m1.clone(), m2.clone(), &data, ExpectedLoss::AlmostNone).await?;
    run_roundtrip(m2.clone(), m1.clone(), &data, ExpectedLoss::AlmostNone).await?;

    Ok(())
}

// EADDRINUSE on the GitHub Android emulator persists past
// `force_network_change()`, so the rebind fails and connect() never
// wakes the connection driver. Passes locally.
#[cfg_attr(
    target_os = "android",
    ignore = "rebind flakes against the GitHub Android emulator"
)]
#[tokio::test]
#[traced_test]
async fn test_regression_network_change_rebind_wakes_connection_driver() -> Result {
    let (_guard, m1, m2) = endpoint_pair().await;

    println!("Net change");
    m1.inner()?.force_network_change(true).await;
    tokio::time::sleep(Duration::from_secs(1)).await; // wait for socket rebinding

    let _handle = AbortOnDropHandle::new(tokio::spawn({
        let endpoint = m2.clone();
        async move {
            while let Some(incoming) = endpoint.accept().await {
                println!("Incoming first conn!");
                let conn = incoming.await.anyerr()?;
                conn.closed().await;
            }

            n0_error::Ok(())
        }
    }));

    println!("first conn!");
    let conn = m1.connect(m2.addr(), ALPN).await?;
    println!("Closing first conn");
    conn.close(0u32.into(), b"bye lolz");
    conn.closed().await;
    println!("Closed first conn");

    Ok(())
}

fn offset(rng: &mut rand_chacha::ChaCha8Rng) -> Duration {
    let delay = rng.random_range(1..=5);
    Duration::from_millis(delay * 50)
}

/// Same structure as `test_two_devices_roundtrip_noq`, but interrupts regularly
/// with (simulated) network changes.
/// Regular network changes to m1 only.
#[tokio::test(flavor = "multi_thread")]
#[traced_test]
async fn test_two_devices_roundtrip_network_change_only_a() -> Result {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
    let (_guard, m1, m2) = endpoint_pair().await;

    let _network_change_guard = {
        let m1 = m1.clone();
        let mut rng = rng.clone();
        let task = tokio::spawn(async move {
            loop {
                info!("[m1] network change");
                m1.inner()
                    .expect("haven't closed the endpoint yet")
                    .force_network_change(true)
                    .await;
                time::sleep(offset(&mut rng)).await;
            }
        });
        AbortOnDropHandle::new(task)
    };

    let mut data = vec![0u8; 10 * 1024];
    rng.fill_bytes(&mut data);
    run_roundtrip(m1.clone(), m2.clone(), &data, ExpectedLoss::YeahSure).await?;
    run_roundtrip(m2.clone(), m1.clone(), &data, ExpectedLoss::YeahSure).await?;

    Ok(())
}

/// Regular network changes to both m1 and m2.
#[tokio::test(flavor = "multi_thread")]
#[traced_test]
async fn test_two_devices_roundtrip_network_change_a_and_b() -> Result {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
    let (_guard, m1, m2) = endpoint_pair().await;

    let _network_change_guard = {
        let m1 = m1.clone();
        let m2 = m2.clone();
        let mut rng = rng.clone();
        let task = tokio::spawn(async move {
            info!("-- [m1] network change");
            m1.inner()
                .expect("haven't closed the endpoint yet")
                .force_network_change(true)
                .await;
            info!("-- [m2] network change");
            m2.inner()
                .expect("haven't closed the endpoint yet")
                .force_network_change(true)
                .await;
            time::sleep(offset(&mut rng)).await;
        });
        AbortOnDropHandle::new(task)
    };

    let mut data = vec![0u8; 10 * 1024];
    rng.fill_bytes(&mut data);
    run_roundtrip(m1.clone(), m2.clone(), &data, ExpectedLoss::YeahSure).await?;
    run_roundtrip(m2.clone(), m1.clone(), &data, ExpectedLoss::YeahSure).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[traced_test]
async fn test_two_devices_setup_teardown() -> Result {
    for i in 0..10 {
        info!("-- round {i}");
        info!("setting up stack");
        let (_guard, m1, m2) = endpoint_pair().await;

        info!("closing endpoints");
        let sock1 = m1.inner()?;
        let sock2 = m2.inner()?;
        m1.close().await;
        m2.close().await;

        assert!(sock1.is_closed());
        assert!(sock2.is_closed());
    }
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_direct_addresses() {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
    let sock = EndpointInner::bind(default_options(&mut rng))
        .await
        .unwrap();

    // See if we can get endpoints.
    let eps0 = sock.ip_addrs().get();
    info!("{eps0:?}");
    assert!(!eps0.is_empty());

    // Getting the endpoints again immediately should give the same results.
    let eps1 = sock.ip_addrs().get();
    info!("{eps1:?}");
    assert_eq!(eps0, eps1);
}

/// Creates a new [`noq::Endpoint`] hooked up to a [`Socket`].
///
/// This is without involving [`crate::endpoint::Endpoint`].  The socket will accept
/// connections using [`ALPN`].
///
/// Use [`socket_connect`] to establish connections.
#[instrument(name = "ep", skip_all, fields(me = %secret_key.public().fmt_short()))]
async fn socket_ep(secret_key: SecretKey) -> Result<EndpointInner> {
    let crypto_provider = default_provider();
    let runtime_context = Arc::new(iroh_runtime::RuntimeContext::production(Arc::new(
        iroh_runtime::NoopTraceSink,
    )));
    let tls_config = tls::TlsConfig::new(
        secret_key.clone(),
        DEFAULT_MAX_TLS_TICKETS,
        crypto_provider.clone(),
    );
    let keylog = true;
    let static_config = StaticConfig {
        server_config: tls_config.make_server_config(keylog).unwrap(),
        client_config: tls_config.make_client_config(keylog).unwrap(),
        tls_config,
        token_key: Arc::new(RustlsTokenKey::new(&mut rand::rng(), &crypto_provider).unwrap()),
        token_store: Arc::new(noq::TokenMemoryCache::default()),
        transport_config: QuicTransportConfig::default(),
        runtime_context: runtime_context.clone(),
        simulation_initial_dst_cid_provider: None,
        limits: crate::endpoint::EndpointLimits::default(),
    };
    let server_config = static_config.create_server_config(vec![ALPN.to_vec()]);

    let dns_resolver = DnsResolver::new();
    let opts = Options {
        transports: vec![
            TransportConfig::default_ipv4(),
            TransportConfig::default_ipv6(),
        ],
        secret_key: secret_key.clone(),
        address_lookup_user_data: None,
        dns_resolver,
        runtime_context,
        ip_socket_factory: Arc::new(crate::simulation::OsIpSocketFactory),
        network_monitor: None,
        simulation_port_mapper: None,
        simulation_relay_connector: None,
        simulation_preferred_relay: None,
        simulation_reset_key: None,
        proxy_url: None,
        server_config,
        tls_config: CaTlsConfig::default()
            .client_config(crypto_provider.clone())
            .unwrap(),
        metrics: Default::default(),
        hooks: Default::default(),
        path_selector: Arc::new(BiasedRttPathSelector::default()),
        portmapper_config: Default::default(),
        net_report_config: Default::default(),
        static_config,
        configured_addrs: Default::default(),
        limits: crate::endpoint::EndpointLimits::default(),
    };
    let sock = EndpointInner::bind(opts).await?;
    Ok(sock)
}

/// Connects from `ep` returned by [`socket_ep`] to the `endpoint_id`.
///
/// Uses [`ALPN`], `endpoint_id`, must match `addr`.
#[instrument(name = "connect", skip_all, fields(me = %ep_secret_key.public().fmt_short()))]
async fn socket_connect(
    ep: noq::Endpoint,
    ep_secret_key: SecretKey,
    addr: EndpointIdMappedAddr,
    endpoint_id: EndpointId,
) -> Result<noq::Connection> {
    // Endpoint::connect sets this, do the same to have similar behaviour.
    let mut transport_config = noq::TransportConfig::default();
    transport_config.server_handshake_migration(true);
    transport_config.keep_alive_interval(Some(Duration::from_secs(1)));

    socket_connect_with_transport_config(
        ep,
        ep_secret_key,
        addr,
        endpoint_id,
        Arc::new(transport_config),
    )
    .await
}

/// Connects from `ep` returned by [`socket_ep`] to the `endpoint_id`.
///
/// This version allows customising the transport config.
///
/// Uses [`ALPN`], `endpoint_id`, must match `addr`.
#[instrument(name = "connect", skip_all, fields(me = %ep_secret_key.public().fmt_short()))]
async fn socket_connect_with_transport_config(
    ep: noq::Endpoint,
    ep_secret_key: SecretKey,
    mapped_addr: EndpointIdMappedAddr,
    endpoint_id: EndpointId,
    transport_config: Arc<noq::TransportConfig>,
) -> Result<noq::Connection> {
    let mut quic_client_config = tls::TlsConfig::new(
        ep_secret_key.clone(),
        DEFAULT_MAX_TLS_TICKETS,
        default_provider(),
    )
    .make_client_config(true)?;
    quic_client_config.set_alpn_protocols(vec![ALPN.to_vec()]);
    let mut client_config = noq::ClientConfig::new(Arc::new(quic_client_config));
    client_config.transport_config(transport_config);
    let connect = ep
        .connect_with(
            client_config,
            mapped_addr.private_socket_addr(),
            &tls::name::encode(endpoint_id),
        )
        .std_context("connect")?;
    let connection = connect.await.anyerr()?;
    Ok(connection)
}

#[tokio::test]
#[traced_test]
async fn test_try_send_no_send_addr() {
    // Regression test: if there is no send_addr we should keep being able to use the
    // Endpoint.

    let secret_key_1 = SecretKey::from_bytes(&[1u8; 32]);
    let secret_key_2 = SecretKey::from_bytes(&[2u8; 32]);
    let endpoint_id_2 = secret_key_2.public();
    let secret_key_missing_endpoint = SecretKey::from_bytes(&[255u8; 32]);
    let endpoint_id_missing_endpoint = secret_key_missing_endpoint.public();

    let sock_1 = socket_ep(secret_key_1.clone()).await.unwrap();

    // Generate an address not present in the RemoteMap.
    let bad_addr = EndpointIdMappedAddr::generate();

    // 500ms is rather fast here.  Running this locally it should always be the correct
    // timeout.  If this is too slow however the test will not become flaky as we are
    // expecting the timeout, we might just get the timeout for the wrong reason.  But
    // this speeds up the test.
    let res = tokio::time::timeout(
        Duration::from_millis(500),
        socket_connect(
            sock_1.noq_endpoint().clone(),
            secret_key_1.clone(),
            bad_addr,
            endpoint_id_missing_endpoint,
        ),
    )
    .await;
    assert!(res.is_err(), "expecting timeout");

    // Now check we can still create another connection with this endpoint.
    let sock_2 = socket_ep(secret_key_2.clone()).await.unwrap();

    // This needs an accept task
    let accept_task = tokio::spawn({
        async fn accept(ep: noq::Endpoint) -> Result<()> {
            let incoming = ep.accept().await.std_context("no incoming")?;
            let _conn = incoming
                .accept()
                .std_context("accept")?
                .await
                .std_context("accepting")?;

            // Keep this connection alive for a while
            tokio::time::sleep(Duration::from_secs(10)).await;
            info!("accept finished");
            Ok(())
        }
        let ep = sock_2.noq_endpoint().clone();
        async move {
            if let Err(err) = accept(ep).await {
                error!("{err:#}");
            }
        }
        .instrument(info_span!("ep2.accept, me = endpoint_id_2.fmt_short()"))
    });
    let _accept_task = AbortOnDropHandle::new(accept_task);

    let addrs = sock_2
        .ip_addrs()
        .get()
        .into_iter()
        .map(|x| TransportAddr::Ip(x.addr));
    let endpoint_addr_2 = EndpointAddr::try_from_parts(endpoint_id_2, addrs)
        .expect("test endpoint address is bounded");
    let addr = sock_1
        .resolve_remote(endpoint_addr_2)
        .await
        .unwrap()
        .unwrap();
    let res = tokio::time::timeout(
        Duration::from_secs(10),
        socket_connect(
            sock_1.noq_endpoint().clone(),
            secret_key_1.clone(),
            addr,
            endpoint_id_2,
        ),
    )
    .await
    .expect("timeout while connecting");

    // aka assert!(res.is_ok()) but with nicer error reporting.
    res.unwrap();

    // TODO: Now check if we can connect to a repaired ep_3, but we can't modify that
    // much internal state for now.
}

#[tokio::test]
#[traced_test]
async fn test_try_send_no_udp_addr_or_relay_url() {
    // This specifically tests the `if udp_addr.is_none() && relay_url.is_none()`
    // behaviour of Socket::try_send.

    let secret_key_1 = SecretKey::from_bytes(&[1u8; 32]);
    let secret_key_2 = SecretKey::from_bytes(&[2u8; 32]);
    let endpoint_id_2 = secret_key_2.public();

    let sock_1 = socket_ep(secret_key_1.clone()).await.unwrap();
    let sock_2 = socket_ep(secret_key_2.clone()).await.unwrap();
    let ep_2 = sock_2.noq_endpoint().clone();

    // We need a task to accept the connection.
    let accept_task = tokio::spawn({
        async fn accept(ep: noq::Endpoint) -> Result<()> {
            let incoming = ep.accept().await.std_context("no incoming")?;
            let conn = incoming
                .accept()
                .std_context("accept")?
                .await
                .std_context("connecting")?;
            let mut stream = conn.accept_uni().await.std_context("accept uni")?;
            stream
                .read_to_end(1 << 16)
                .await
                .std_context("read to end")?;
            info!("accept finished");
            Ok(())
        }
        async move {
            if let Err(err) = accept(ep_2).await {
                error!("{err:#}");
            }
        }
        .instrument(info_span!("ep2.accept", me = %endpoint_id_2.fmt_short()))
    });
    let _accept_task = AbortOnDropHandle::new(accept_task);

    // Add an entry in the RemoteMap of ep_1 with an invalid socket address
    let empty_addr_2 = EndpointAddr::try_from_parts(
        endpoint_id_2,
        [TransportAddr::Ip(
            // Reserved IP range for documentation (unreachable)
            SocketAddrV4::new([192, 0, 2, 1].into(), 12345).into(),
        )],
    )
    .expect("test endpoint address is bounded");
    let addr_2 = sock_1.resolve_remote(empty_addr_2).await.unwrap().unwrap();

    // Set a low max_idle_timeout so noq gives up on this quickly and our test does
    // not take forever.  You need to check the log output to verify this is really
    // triggering the correct error.
    // In test_try_send_no_send_addr() above you may have noticed we used
    // tokio::time::timeout() on the connection attempt instead.  Here however we want
    // Noq itself to have fully given up on the connection attempt because we will
    // later connect to **the same** endpoint.  If Noq did not give up on the connection
    // we'd close it on drop, and the retransmits of the close packets would interfere
    // with the next handshake, closing it during the handshake.  This makes the test a
    // little slower though.
    let mut transport_config = noq::TransportConfig::default();
    transport_config.server_handshake_migration(true);
    transport_config.max_idle_timeout(Some(Duration::from_millis(200).try_into().unwrap()));
    let res = socket_connect_with_transport_config(
        sock_1.noq_endpoint().clone(),
        secret_key_1.clone(),
        addr_2,
        endpoint_id_2,
        Arc::new(transport_config),
    )
    .await;
    assert!(res.is_err(), "expected timeout");
    info!("first connect timed out as expected");

    // Provide correct addressing information
    let correct_addr_2 = EndpointAddr::try_from_parts(
        endpoint_id_2,
        sock_2
            .ip_addrs()
            .get()
            .into_iter()
            .map(|x| TransportAddr::Ip(x.addr)),
    )
    .expect("test endpoint address is bounded");
    let addr_2a = sock_1
        .resolve_remote(correct_addr_2)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(addr_2, addr_2a);

    // We can now connect
    tokio::time::timeout(Duration::from_secs(10), async move {
        info!("establishing new connection");
        let conn = socket_connect(
            sock_1.noq_endpoint().clone(),
            secret_key_1.clone(),
            addr_2,
            endpoint_id_2,
        )
        .await
        .unwrap();
        info!("have connection");
        let mut stream = conn.open_uni().await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        stream.finish().unwrap();
        stream.stopped().await.unwrap();
        info!("finished stream");
    })
    .await
    .expect("connection timed out");

    // TODO: could remove the addresses again, send, add it back and see it recover.
    // But we don't have that much private access to the RemoteMap.  This will do for now.
}
