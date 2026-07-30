use std::{
    collections::BTreeMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4},
    pin::Pin,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use assert_matches::assert_matches;
use krikos_base::{EndpointAddr, EndpointId, RelayUrl, SecretKey, TransportAddr};
use krikos_dns::endpoint_info::UserData;
use krikos_relay::{RelayConfig, RelayQuicConfig, server::Access, tls::CaTlsConfig};
use n0_error::{AnyError as Error, Result, StdResultExt};
use n0_future::{BufferedStreamExt, StreamExt, future::now_or_never, stream, time};
use n0_tracing_test::traced_test;
use n0_watcher::Watcher;
use noq::PathStats;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha8Rng;
use tokio::sync::oneshot;
use tracing::{Instrument, debug_span, error_span, info, info_span, instrument};

use super::{Builder, Endpoint};
use crate::{
    RelayMap, RelayMode,
    address_lookup::memory::MemoryLookup,
    endpoint::{
        ApplicationClose, BindError, BindOpts, ConnectError, ConnectOptions, ConnectWithOptsError,
        Connection, ConnectionError, EndpointLimits, PathEvent, PathEventStream, presets,
    },
    protocol::{AcceptError, ProtocolHandler, Router},
    test_utils::{
        QlogFileGroup, run_relay_server, run_relay_server_with, run_relay_server_with_access,
    },
};

const TEST_ALPN: &[u8] = b"n0/iroh/test";

#[cfg(not(wasm_browser))]
#[derive(Debug)]
struct StableMonitor(n0_watcher::Watchable<netwatch::netmon::State>);

#[cfg(not(wasm_browser))]
impl crate::simulation::NetworkMonitor for StableMonitor {
    fn interface_state(&self) -> n0_watcher::Direct<netwatch::netmon::State> {
        self.0.watch()
    }

    fn network_change(&self) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(std::future::ready(()))
    }
}

#[cfg(not(wasm_browser))]
fn stable_monitor() -> Arc<dyn crate::simulation::NetworkMonitor> {
    Arc::new(StableMonitor(n0_watcher::Watchable::new(
        netwatch::netmon::State::fake(),
    )))
}

#[test]
fn builder_uses_production_runtime_default_lazily() {
    assert!(Builder::empty().simulation_environment.is_none());
}

#[cfg(not(wasm_browser))]
#[test]
fn builder_retains_one_complete_simulation_environment() {
    #[derive(Debug)]
    struct NeverBind(krikos_runtime::ClockDomain);

    impl crate::simulation::IpSocketFactory for NeverBind {
        fn clock_domain(&self) -> Option<krikos_runtime::ClockDomain> {
            Some(self.0)
        }

        fn bind(&self, _addr: SocketAddr) -> std::io::Result<Arc<dyn crate::simulation::IpSocket>> {
            panic!("retention test must not bind")
        }
    }

    let context = Arc::new(krikos_runtime::RuntimeContext::tokio(
        krikos_runtime::RootSeed::new([23; 32]),
        Arc::new(krikos_runtime::NoopTraceSink),
    ));
    let factory: Arc<dyn crate::simulation::IpSocketFactory> =
        Arc::new(NeverBind(context.clock().domain()));
    let monitor = stable_monitor();
    let crypto = crate::simulation::SimulationCryptoMaterial::new([11; 32], [12; 32]);
    let environment = crate::simulation::SimulationEnvironment::new(
        context.clone(),
        factory.clone(),
        monitor.clone(),
        crypto,
    )
    .expect("coherent test environment");
    let builder = Builder::empty()
        .simulation_environment_for_test(environment, krikos_runtime::UnsafeTestOnly::acknowledge());
    let installed = builder
        .simulation_environment
        .as_ref()
        .expect("environment installed atomically");

    assert!(Arc::ptr_eq(&installed.runtime(), &context));
    assert!(Arc::ptr_eq(&installed.ip_sockets(), &factory));
    assert!(Arc::ptr_eq(&installed.network_monitor(), &monitor));
    assert_eq!(installed.crypto(), crypto);
}

#[cfg(not(wasm_browser))]
#[tokio::test]
async fn explicit_simulation_environment_reaches_bound_endpoint() {
    #[derive(Debug)]
    struct RuntimeOwnedOsSockets(krikos_runtime::ClockDomain);

    impl crate::simulation::IpSocketFactory for RuntimeOwnedOsSockets {
        fn clock_domain(&self) -> Option<krikos_runtime::ClockDomain> {
            Some(self.0)
        }

        fn bind(&self, addr: SocketAddr) -> std::io::Result<Arc<dyn crate::simulation::IpSocket>> {
            crate::simulation::IpSocketFactory::bind(&crate::simulation::OsIpSocketFactory, addr)
        }
    }

    let context = Arc::new(krikos_runtime::RuntimeContext::tokio(
        krikos_runtime::RootSeed::new([29; 32]),
        Arc::new(krikos_runtime::NoopTraceSink),
    ));
    let environment = crate::simulation::SimulationEnvironment::new(
        context.clone(),
        Arc::new(RuntimeOwnedOsSockets(context.clock().domain())),
        stable_monitor(),
        crate::simulation::SimulationCryptoMaterial::new([31; 32], [32; 32]),
    )
    .expect("coherent test environment");
    let endpoint = Endpoint::builder(presets::Minimal)
        .simulation_environment_for_test(environment, krikos_runtime::UnsafeTestOnly::acknowledge())
        .bind()
        .await
        .unwrap();

    assert!(Arc::ptr_eq(endpoint.inner.runtime_context(), &context));
    endpoint.close().await;
    assert!(endpoint.inner.runtime_task_snapshot().tasks.is_empty());
}

#[cfg(not(wasm_browser))]
#[tokio::test]
async fn injected_ip_factory_prevents_os_socket_binding() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct RejectBind {
        calls: Arc<AtomicUsize>,
        domain: krikos_runtime::ClockDomain,
    }

    impl crate::simulation::IpSocketFactory for RejectBind {
        fn clock_domain(&self) -> Option<krikos_runtime::ClockDomain> {
            Some(self.domain)
        }

        fn bind(&self, _addr: SocketAddr) -> std::io::Result<Arc<dyn crate::simulation::IpSocket>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected socket rejection",
            ))
        }
    }

    let bind_calls = Arc::new(AtomicUsize::new(0));
    let context = Arc::new(krikos_runtime::RuntimeContext::tokio(
        krikos_runtime::RootSeed::new([37; 32]),
        Arc::new(krikos_runtime::NoopTraceSink),
    ));
    let environment = crate::simulation::SimulationEnvironment::new(
        context.clone(),
        Arc::new(RejectBind {
            calls: bind_calls.clone(),
            domain: context.clock().domain(),
        }),
        stable_monitor(),
        crate::simulation::SimulationCryptoMaterial::new([38; 32], [39; 32]),
    )
    .expect("coherent rejecting environment");
    let result = Endpoint::builder(presets::Minimal)
        .simulation_environment_for_test(environment, krikos_runtime::UnsafeTestOnly::acknowledge())
        .bind()
        .await;

    assert!(result.is_err());
    assert_eq!(bind_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
#[traced_test]
async fn test_connect_self() -> Result {
    let ep = Endpoint::builder(presets::Minimal)
        .alpns(vec![TEST_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let my_addr = ep.addr();
    let res = ep.connect(my_addr.clone(), TEST_ALPN).await;
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert!(err.to_string().starts_with("Connecting to ourself"));

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_connect_empty_alpn() -> Result {
    let server = Endpoint::builder(presets::Minimal)
        .alpns(vec![TEST_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let server_addr = server.addr();

    let client = Endpoint::builder(presets::Minimal).bind().await.unwrap();
    let res = client.connect(server_addr, b"").await;
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_matches!(
        err,
        ConnectError::Connect {
            source: ConnectWithOptsError::InvalidAlpn { .. },
            ..
        }
    );

    Ok(())
}

#[tokio::test]
async fn connection_capacity_is_exact_and_recovers_after_noq_drains() -> Result {
    let limits = EndpointLimits::default()
        .with_max_connections(std::num::NonZeroUsize::new(2).expect("nonzero test capacity"));
    let server = Endpoint::builder(presets::Minimal)
        .alpns(vec![TEST_ALPN.to_vec()])
        .bind()
        .await?;
    let server_addr = server.addr();
    let client = Endpoint::builder(presets::Minimal)
        .limits(limits)
        .bind()
        .await?;

    async fn connect_pair(
        client: &Endpoint,
        server: &Endpoint,
        server_addr: EndpointAddr,
    ) -> Result<(Connection, Connection)> {
        let outgoing = async { client.connect(server_addr, TEST_ALPN).await.anyerr() };
        let incoming = async { server.accept().await.anyerr()?.await.anyerr() };
        tokio::try_join!(outgoing, incoming)
    }

    let (client_first, server_first) = connect_pair(&client, &server, server_addr.clone()).await?;
    let (client_second, server_second) =
        connect_pair(&client, &server, server_addr.clone()).await?;
    let saturated = client.connection_capacity_snapshot();
    assert_eq!(saturated.maximum, 2);
    assert_eq!(saturated.current, 2);
    assert_eq!(saturated.high_water, 2);

    let third = client
        .connect_with_opts(server_addr.clone(), TEST_ALPN, ConnectOptions::default())
        .await;
    assert_matches!(
        third,
        Err(ConnectWithOptsError::ConnectionCapacityFull { .. })
    );
    assert_eq!(client.connection_capacity_snapshot().rejections, 1);

    client_first.close(0u8.into(), b"test capacity release");
    drop(client_first);
    drop(server_first);
    tokio::time::timeout(Duration::from_secs(10), async {
        while client.connection_capacity_snapshot().current == 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .anyerr()?;
    assert_eq!(client.connection_capacity_snapshot().current, 1);

    let (client_third, server_third) = connect_pair(&client, &server, server_addr).await?;
    assert_eq!(client.connection_capacity_snapshot().current, 2);

    drop(client_second);
    drop(server_second);
    drop(client_third);
    drop(server_third);
    client.close().await;
    server.close().await;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn endpoint_connect_close() -> Result {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
    let (relay_map, relay_url, _guard) = run_relay_server().await?;
    let server_secret_key = SecretKey::from_bytes(&rng.random());
    let server_peer_id = server_secret_key.public();

    let qlog = QlogFileGroup::from_env("endpoint_connect_close");

    // Wait for the endpoint to be started to make sure it's up before clients try to connect
    let ep = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(relay_map.clone()))
        .secret_key(server_secret_key)
        .transport_config(qlog.create("server")?)
        .alpns(vec![TEST_ALPN.to_vec()])
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .bind()
        .await?;
    // Wait for the endpoint to be reachable via relay
    ep.online().await;

    let server = tokio::spawn(
        async move {
            info!("accepting connection");
            let incoming = ep.accept().await.anyerr()?;
            let conn = incoming.await.anyerr()?;
            let mut stream = conn.accept_uni().await.anyerr()?;
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await.anyerr()?;
            info!("Accepted 1 stream, received {buf:?}.  Closing now.");
            // close the connection
            conn.close(7u8.into(), b"bye");

            let res = conn.accept_uni().await;
            assert_eq!(res.unwrap_err(), ConnectionError::LocallyClosed);

            let res = stream.read_to_end(10).await;
            assert_eq!(
                res.unwrap_err(),
                noq::ReadToEndError::Read(noq::ReadError::ConnectionLost(
                    ConnectionError::LocallyClosed
                ))
            );
            info!("Closing the endpoint");
            ep.close().await;
            info!("server test completed");
            Ok::<_, Error>(())
        }
        .instrument(info_span!("test-server")),
    );

    let client = tokio::spawn(
        async move {
            let ep = Endpoint::builder(presets::Minimal)
                .relay_mode(RelayMode::Custom(relay_map))
                .alpns(vec![TEST_ALPN.to_vec()])
                .ca_tls_config(CaTlsConfig::insecure_skip_verify())
                .transport_config(qlog.create("client")?)
                .bind()
                .await?;
            info!("client connecting");
            let endpoint_addr = EndpointAddr::new(server_peer_id).with_relay_url(relay_url);
            let conn = ep.connect(endpoint_addr, TEST_ALPN).await?;
            let mut stream = conn.open_uni().await.anyerr()?;

            // First write is accepted by server.  We need this bit of synchronisation
            // because if the server closes after simply accepting the connection we can
            // not be sure our .open_uni() call would succeed as it may already receive
            // the error.
            stream.write_all(b"hello").await.anyerr()?;

            info!("waiting for closed");
            // Remote now closes the connection, we should see an error sometime soon.
            let err = conn.closed().await;
            let expected_err = ConnectionError::ApplicationClosed(ApplicationClose {
                error_code: 7u8.into(),
                reason: b"bye".to_vec().into(),
            });
            assert_eq!(err, expected_err);

            info!("opening new - expect it to fail");
            let res = conn.open_uni().await;
            assert_eq!(res.unwrap_err(), expected_err);
            info!("Closing the client");
            ep.close().await;
            info!("client test completed");
            Ok::<_, Error>(())
        }
        .instrument(info_span!("test-client")),
    );

    let (server, client) = tokio::time::timeout(
        Duration::from_secs(30),
        n0_future::future::zip(server, client),
    )
    .await
    .anyerr()?;
    server.anyerr()??;
    client.anyerr()??;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn endpoint_relay_connect_loop() -> Result {
    let test_start = Instant::now();
    let n_clients = 5;
    let n_chunks_per_client = 2;
    let chunk_size = 100;
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
    let (relay_map, relay_url, _relay_guard) = run_relay_server().await.unwrap();
    let server_secret_key = SecretKey::from_bytes(&rng.random());
    let server_endpoint_id = server_secret_key.public();

    // Make sure the server is bound before having clients connect to it:
    let ep = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(relay_map.clone()))
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .secret_key(server_secret_key)
        .alpns(vec![TEST_ALPN.to_vec()])
        .bind()
        .await?;
    // Also make sure the server has a working relay connection
    ep.online().await;

    info!(time = ?test_start.elapsed(), "test setup done");

    // The server accepts the connections of the clients sequentially.
    let server = tokio::spawn(
        async move {
            let eps = ep.bound_sockets();

            info!(me = %ep.id().fmt_short(), eps = ?eps, "server listening on");
            for i in 0..n_clients {
                let res = tokio::time::timeout(Duration::from_secs(5), async {
                    let round_start = Instant::now();
                    info!("[server] round {i}");
                    let incoming = ep.accept().await.anyerr()?;
                    let conn = incoming.await.anyerr()?;
                    let endpoint_id = conn.remote_id();
                    info!(%i, peer = %endpoint_id.fmt_short(), "accepted connection");
                    let (mut send, mut recv) = conn.accept_bi().await.anyerr()?;
                    let mut buf = vec![0u8; chunk_size];
                    for _i in 0..n_chunks_per_client {
                        recv.read_exact(&mut buf).await.anyerr()?;
                        send.write_all(&buf).await.anyerr()?;
                    }
                    info!(%i, peer = %endpoint_id.fmt_short(), "finishing");
                    send.finish().anyerr()?;
                    conn.closed().await; // we're the last to send data, so we wait for the other side to close
                    info!(%i, peer = %endpoint_id.fmt_short(), "finished");
                    info!("[server] round {i} done in {:?}", round_start.elapsed());
                    Ok::<_, Error>(())
                })
                .await
                .std_context("timeout");
                match res {
                    Err(err) | Ok(Err(err)) => {
                        // ensure we close the endpoint before returning early
                        // on error
                        ep.close().await;
                        return Err(err);
                    }
                    _ => {
                        // if this round went `Ok` don't close the endpoint yet
                    }
                }
            }
            // close the endpoint before dropping the server task
            ep.close().await;
            Ok::<_, Error>(())
        }
        .instrument(debug_span!("server")),
    );

    let client = tokio::spawn(async move {
        for i in 0..n_clients {
            let round_start = Instant::now();
            info!("[client] round {i}");
            let client_secret_key = SecretKey::from_bytes(&rng.random());
            let ep = Endpoint::builder(presets::Minimal)
                .relay_mode(RelayMode::Custom(relay_map.clone()))
                .alpns(vec![TEST_ALPN.to_vec()])
                .ca_tls_config(CaTlsConfig::insecure_skip_verify())
                .secret_key(client_secret_key)
                .bind()
                .await?;
            let ep_1 = ep.clone();
            let res = tokio::time::timeout(
                Duration::from_secs(5),
                async {
                    info!("client binding");
                    let eps = ep.bound_sockets();

                    info!(me = %ep.id().fmt_short(), eps=?eps, "client bound");
                    let endpoint_addr =
                        EndpointAddr::new(server_endpoint_id).with_relay_url(relay_url.clone());
                    info!(to = ?endpoint_addr, "client connecting");
                    let conn = ep.connect(endpoint_addr, TEST_ALPN).await.anyerr()?;
                    info!("client connected");
                    let (mut send, mut recv) = conn.open_bi().await.anyerr()?;

                    for i in 0..n_chunks_per_client {
                        let mut buf = vec![i; chunk_size];
                        send.write_all(&buf).await.anyerr()?;
                        recv.read_exact(&mut buf).await.anyerr()?;
                        assert_eq!(buf, vec![i; chunk_size]);
                    }
                    // we're the last to receive data, so we close
                    conn.close(0u32.into(), b"bye!");
                    info!("client finished");
                    Ok::<_, Error>(())
                }
                .instrument(debug_span!("client", %i)),
            )
            .await
            .std_context("timeout");
            ep_1.close().await;
            info!("client endpoint closed");
            res??;
            info!("[client] round {i} done in {:?}", round_start.elapsed());
        }
        Ok::<_, Error>(())
    });

    server.await.anyerr()??;
    client.await.anyerr()??;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn endpoint_send_relay() -> Result {
    let (relay_map, _relay_url, _guard) = run_relay_server().await?;
    let client = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(relay_map.clone()))
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .bind()
        .await?;
    let server = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(relay_map))
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .alpns(vec![TEST_ALPN.to_vec()])
        .bind()
        .await?;

    let task = tokio::spawn({
        let server = server.clone();
        async move {
            let Some(conn) = server.accept().await else {
                n0_error::bail_any!("Expected an incoming connection");
            };
            let conn = conn.await.anyerr()?;
            let (mut send, mut recv) = conn.accept_bi().await.anyerr()?;
            let data = recv.read_to_end(1000).await.anyerr()?;
            send.write_all(&data).await.anyerr()?;
            send.finish().anyerr()?;
            conn.closed().await;

            Ok::<_, Error>(())
        }
    });

    let addr = server.addr();
    let conn = client.connect(addr, TEST_ALPN).await?;
    let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
    send.write_all(b"Hello, world!").await.anyerr()?;
    send.finish().anyerr()?;
    let data = recv.read_to_end(1000).await.anyerr()?;
    conn.close(0u32.into(), b"bye!");

    task.await.anyerr()??;

    client.close().await;
    server.close().await;

    assert_eq!(&data, b"Hello, world!");

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn endpoint_two_direct_only() -> Result {
    // Connect two endpoints on the same network, without a relay server, without
    // Address Lookup.
    let ep1 = {
        let span = info_span!("server");
        let _guard = span.enter();
        Endpoint::builder(presets::N0)
            .alpns(vec![TEST_ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await?
    };
    let ep2 = {
        let span = info_span!("client");
        let _guard = span.enter();
        Endpoint::builder(presets::N0)
            .alpns(vec![TEST_ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await?
    };
    let ep1_nodeaddr = ep1.addr();

    #[instrument(name = "client", skip_all)]
    async fn connect(ep: Endpoint, dst: EndpointAddr) -> Result<ConnectionError> {
        info!(me = %ep.id().fmt_short(), "client starting");
        let conn = ep.connect(dst, TEST_ALPN).await?;
        let mut send = conn.open_uni().await.anyerr()?;
        send.write_all(b"hello").await.anyerr()?;
        send.finish().anyerr()?;
        Ok(conn.closed().await)
    }

    #[instrument(name = "server", skip_all)]
    async fn accept(ep: Endpoint, src: EndpointId) -> Result {
        info!(me = %ep.id().fmt_short(), "server starting");
        let conn = ep.accept().await.anyerr()?.await.anyerr()?;
        let node_id = conn.remote_id();
        assert_eq!(node_id, src);
        let mut recv = conn.accept_uni().await.anyerr()?;
        let msg = recv.read_to_end(100).await.anyerr()?;
        assert_eq!(msg, b"hello");
        // Dropping the connection closes it just fine.
        Ok(())
    }

    let ep1_accept = tokio::spawn(accept(ep1.clone(), ep2.id()));
    let ep2_connect = tokio::spawn(connect(ep2.clone(), ep1_nodeaddr));

    ep1_accept.await.anyerr()??;
    let conn_closed = dbg!(ep2_connect.await.anyerr()??);
    assert!(matches!(
        conn_closed,
        ConnectionError::ApplicationClosed(ApplicationClose { .. })
    ));

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn endpoint_two_relay_only_becomes_direct() -> Result {
    // Connect two endpoints on the same network, via a relay server, without
    // Address Lookup.  Wait until there is a direct connection.
    let (relay_map, _relay_url, _relay_server_guard) = run_relay_server().await?;
    let (node_addr_tx, node_addr_rx) = oneshot::channel();
    let qlog = Arc::new(QlogFileGroup::from_env("two_relay_only_becomes_direct"));

    #[instrument(name = "client", skip_all)]
    async fn connect(
        relay_map: RelayMap,
        node_addr_rx: oneshot::Receiver<EndpointAddr>,
        qlog: Arc<QlogFileGroup>,
    ) -> Result<ConnectionError> {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let secret = SecretKey::from_bytes(&rng.random());
        let ep = Endpoint::builder(presets::N0)
            .secret_key(secret)
            .alpns(vec![TEST_ALPN.to_vec()])
            .ca_tls_config(CaTlsConfig::insecure_skip_verify())
            .relay_mode(RelayMode::Custom(relay_map))
            .transport_config(qlog.create("client")?)
            .bind()
            .await?;
        info!(me = %ep.id().fmt_short(), "client starting");
        let dst = node_addr_rx.await.anyerr()?;

        info!(me = %ep.id().fmt_short(), "client connecting");
        let conn = ep.connect(dst, TEST_ALPN).await?;
        let mut send = conn.open_uni().await.anyerr()?;
        send.write_all(b"hello").await.anyerr()?;
        let mut paths = conn.paths_stream();
        info!("Waiting for direct connection");
        while let Some(infos) = paths.next().await {
            info!(?infos, "new PathInfos");
            if infos.iter().any(|info| info.is_ip()) {
                break;
            }
        }
        info!("Have direct connection");
        #[cfg(feature = "metrics")]
        {
            // Validate holepunch metrics.
            assert_eq!(ep.metrics().socket.num_conns_opened.get(), 1);
            assert_eq!(ep.metrics().socket.num_conns_direct.get(), 1);
        }

        send.write_all(b"close please").await.anyerr()?;
        send.finish().anyerr()?;

        let res = conn.closed().await;
        ep.close().await;
        Ok(res)
    }

    #[instrument(name = "server", skip_all)]
    async fn accept(
        relay_map: RelayMap,
        node_addr_tx: oneshot::Sender<EndpointAddr>,
        qlog: Arc<QlogFileGroup>,
    ) -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(1u64);
        let secret = SecretKey::from_bytes(&rng.random());
        let ep = Endpoint::builder(presets::N0)
            .secret_key(secret)
            .alpns(vec![TEST_ALPN.to_vec()])
            .ca_tls_config(CaTlsConfig::insecure_skip_verify())
            .transport_config(qlog.create("server")?)
            .relay_mode(RelayMode::Custom(relay_map))
            .bind()
            .await?;
        ep.online().await;
        let mut node_addr = ep.addr();
        node_addr.addrs.retain(|addr| addr.is_relay());
        node_addr_tx.send(node_addr).unwrap();

        info!(me = %ep.id().fmt_short(), "server starting");
        let conn = ep.accept().await.anyerr()?.await.anyerr()?;
        // let node_id = conn.remote_node_id()?;
        // assert_eq!(node_id, src);
        let mut recv = conn.accept_uni().await.anyerr()?;
        let mut msg = [0u8; 5];
        recv.read_exact(&mut msg).await.anyerr()?;
        assert_eq!(&msg, b"hello");
        info!("received hello");
        let msg = recv.read_to_end(100).await.anyerr()?;
        assert_eq!(msg, b"close please");
        info!("received 'close please'");
        // Closing the endpoint closes all connections.
        ep.close().await;
        Ok(())
    }

    let server_task = tokio::spawn(accept(relay_map.clone(), node_addr_tx, qlog.clone()));
    let client_task = tokio::spawn(connect(relay_map, node_addr_rx, qlog));

    server_task.await.anyerr()??;
    let conn_closed = dbg!(client_task.await.anyerr()??);
    assert!(matches!(
        conn_closed,
        ConnectionError::ApplicationClosed(ApplicationClose { .. })
    ));

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn endpoint_two_relay_only_no_ip() -> Result {
    // Connect two endpoints on the same network, via a relay server, without
    // Address Lookup.
    let (relay_map, _relay_url, _relay_server_guard) = run_relay_server().await?;
    let (node_addr_tx, node_addr_rx) = oneshot::channel();

    #[instrument(name = "client", skip_all)]
    async fn connect(
        relay_map: RelayMap,
        node_addr_rx: oneshot::Receiver<EndpointAddr>,
    ) -> Result<ConnectionError> {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let secret = SecretKey::from_bytes(&rng.random());
        let ep = Endpoint::builder(presets::N0)
            .secret_key(secret)
            .alpns(vec![TEST_ALPN.to_vec()])
            .ca_tls_config(CaTlsConfig::insecure_skip_verify())
            .relay_mode(RelayMode::Custom(relay_map))
            .clear_ip_transports() // disable direct
            .bind()
            .await?;
        info!(me = %ep.id().fmt_short(), "client starting");
        let dst = node_addr_rx.await.anyerr()?;

        info!(me = %ep.id().fmt_short(), "client connecting");
        let conn = ep.connect(dst, TEST_ALPN).await?;
        let mut send = conn.open_uni().await.anyerr()?;
        send.write_all(b"hello").await.anyerr()?;
        let mut paths = conn.paths_stream();
        info!("Waiting for connection");
        'outer: while let Some(infos) = paths.next().await {
            info!(?infos, "new PathInfos");
            for info in infos.iter() {
                if info.is_ip() {
                    panic!("should not happen: {:?}", info);
                }
                if info.is_relay() {
                    break 'outer;
                }
            }
        }
        info!("Have relay connection");

        send.write_all(b"close please").await.anyerr()?;
        send.finish().anyerr()?;
        let res = conn.closed().await;
        ep.close().await;
        Ok(res)
    }

    #[instrument(name = "server", skip_all)]
    async fn accept(relay_map: RelayMap, node_addr_tx: oneshot::Sender<EndpointAddr>) -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(1u64);
        let secret = SecretKey::from_bytes(&rng.random());
        let ep = Endpoint::builder(presets::N0)
            .secret_key(secret)
            .alpns(vec![TEST_ALPN.to_vec()])
            .ca_tls_config(CaTlsConfig::insecure_skip_verify())
            .relay_mode(RelayMode::Custom(relay_map))
            .clear_ip_transports()
            .bind()
            .await?;
        ep.online().await;
        let node_addr = ep.addr();
        node_addr_tx.send(node_addr).unwrap();

        info!(me = %ep.id().fmt_short(), "server starting");
        let conn = ep.accept().await.anyerr()?.await.anyerr()?;
        // let node_id = conn.remote_node_id()?;
        // assert_eq!(node_id, src);
        let mut recv = conn.accept_uni().await.anyerr()?;
        let mut msg = [0u8; 5];
        recv.read_exact(&mut msg).await.anyerr()?;
        assert_eq!(&msg, b"hello");
        info!("received hello");
        let msg = recv.read_to_end(100).await.anyerr()?;
        assert_eq!(msg, b"close please");
        info!("received 'close please'");
        // Closing the endpoint closes all connections.
        ep.close().await;
        Ok(())
    }

    let server_task = tokio::spawn(accept(relay_map.clone(), node_addr_tx));
    let client_task = tokio::spawn(connect(relay_map, node_addr_rx));

    server_task.await.anyerr()??;
    let conn_closed = dbg!(client_task.await.anyerr()??);
    assert!(matches!(
        conn_closed,
        ConnectionError::ApplicationClosed(ApplicationClose { .. })
    ));

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn endpoint_two_direct_add_relay() -> Result {
    // Connect two endpoints on the same network, without relay server and without
    // Address Lookup.  Add a relay connection later.
    let (relay_map, _relay_url, _relay_server_guard) = run_relay_server().await?;
    let (node_addr_tx, node_addr_rx) = oneshot::channel();

    #[instrument(name = "client", skip_all)]
    async fn connect(
        relay_map: RelayMap,
        node_addr_rx: oneshot::Receiver<EndpointAddr>,
    ) -> Result<()> {
        let secret = SecretKey::from([0u8; 32]);
        let ep = Endpoint::builder(presets::N0)
            .secret_key(secret)
            .alpns(vec![TEST_ALPN.to_vec()])
            .ca_tls_config(CaTlsConfig::insecure_skip_verify())
            .relay_mode(RelayMode::Custom(relay_map))
            .bind()
            .await?;
        info!(me = %ep.id().fmt_short(), "client starting");
        let dst = node_addr_rx.await.anyerr()?;

        info!(me = %ep.id().fmt_short(), "client connecting");
        let conn = ep.connect(dst, TEST_ALPN).await?;
        info!(me = %ep.id().fmt_short(), "client connected");

        // We should be connected via IP, because it is faster than the relay server.
        // TODO: Maybe not panic if this is not true?

        let path_info = conn.paths();
        assert_eq!(path_info.len(), 1);
        assert!(path_info.iter().next().unwrap().is_ip());

        let mut paths = conn.paths_stream();
        time::timeout(Duration::from_secs(5), async move {
            while let Some(infos) = paths.next().await {
                info!(?infos, "new PathInfos");
                if infos.iter().any(|info| info.is_relay()) {
                    info!("client has a relay path");
                    break;
                }
            }
        })
        .await
        .anyerr()?;

        // wait for the server to signal it has the relay connection
        let mut stream = conn.accept_uni().await.anyerr()?;
        stream.read_to_end(100).await.anyerr()?;

        info!("client closing");
        conn.close(0u8.into(), b"");
        ep.close().await;
        Ok(())
    }

    #[instrument(name = "server", skip_all)]
    async fn accept(
        relay_map: RelayMap,
        node_addr_tx: oneshot::Sender<EndpointAddr>,
    ) -> Result<ConnectionError> {
        let secret = SecretKey::from([1u8; 32]);
        let ep = Endpoint::builder(presets::N0)
            .secret_key(secret)
            .alpns(vec![TEST_ALPN.to_vec()])
            .ca_tls_config(CaTlsConfig::insecure_skip_verify())
            .relay_mode(RelayMode::Custom(relay_map))
            .bind()
            .await?;
        ep.online().await;
        let node_addr = ep.addr();
        node_addr_tx.send(node_addr).unwrap();

        info!(me = %ep.id().fmt_short(), "server starting");
        let conn = ep.accept().await.anyerr()?.await.anyerr()?;
        info!(me = %ep.id().fmt_short(), "server accepted connection");

        // Wait for a relay connection to be added.  Client does all the asserting here,
        // we just want to wait so we get to see all the mechanics of the connection
        // being added on this side too.
        let mut paths = conn.paths_stream();
        time::timeout(Duration::from_secs(5), async move {
            while let Some(infos) = paths.next().await {
                info!(?infos, "new PathInfos");
                if infos.iter().any(|path| path.is_relay()) {
                    info!("server has a relay path");
                    break;
                }
            }
        })
        .await
        .anyerr()?;

        let mut stream = conn.open_uni().await.anyerr()?;
        stream.write_all(b"have relay").await.anyerr()?;
        stream.finish().anyerr()?;
        info!("waiting conn.closed()");

        Ok(conn.closed().await)
    }

    let server_task = tokio::spawn(accept(relay_map.clone(), node_addr_tx));
    let client_task = tokio::spawn(connect(relay_map, node_addr_rx));

    client_task.await.anyerr()??;
    let conn_closed = dbg!(server_task.await.anyerr()??);
    assert!(matches!(
        conn_closed,
        ConnectionError::ApplicationClosed(ApplicationClose { .. })
    ));

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn endpoint_relay_map_change() -> Result {
    let (relay_map, relay_url, _guard1) = run_relay_server().await?;
    let client = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(relay_map.clone()))
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .bind()
        .await?;
    let server = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(relay_map))
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .alpns(vec![TEST_ALPN.to_vec()])
        .bind()
        .await?;

    let task = tokio::spawn({
        let server = server.clone();
        async move {
            for i in 0..2 {
                println!("accept: round {i}");
                let Some(conn) = server.accept().await else {
                    n0_error::bail_any!("Expected an incoming connection");
                };
                let conn = conn.await.anyerr()?;
                let (mut send, mut recv) = conn.accept_bi().await.anyerr()?;
                let data = recv.read_to_end(1000).await.anyerr()?;
                send.write_all(&data).await.anyerr()?;
                send.finish().anyerr()?;
                conn.closed().await;
            }
            Ok::<_, Error>(())
        }
    });

    server.online().await;

    let mut addr = server.addr();
    println!("round1: {:?}", addr);

    // remove direct addrs to force relay usage
    addr.addrs
        .retain(|addr| !matches!(addr, TransportAddr::Ip(_)));

    let conn = client.connect(addr, TEST_ALPN).await?;
    let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
    send.write_all(b"Hello, world!").await.anyerr()?;
    send.finish().anyerr()?;
    let data = recv.read_to_end(1000).await.anyerr()?;
    conn.close(0u32.into(), b"bye!");

    assert_eq!(&data, b"Hello, world!");

    // setup a second relay server
    let (new_relay_map, new_relay_url, _guard2) = run_relay_server().await?;
    let new_endpoint = new_relay_map
        .get(&new_relay_url)
        .expect("missing endpoint")
        .clone();
    dbg!(&new_relay_map);

    let addr_watcher = server.watch_addr();

    // add new new relay
    assert!(
        server
            .insert_relay(new_relay_url.clone(), new_endpoint.clone())
            .await
            .is_none()
    );
    // remove the old relay
    assert!(server.remove_relay(&relay_url).await.is_some());

    println!("------- changed ----- ");

    let mut addr = tokio::time::timeout(Duration::from_secs(10), async move {
        let mut stream = addr_watcher.stream();
        while let Some(addr) = stream.next().await {
            if addr.relay_urls().next() != Some(&relay_url) {
                return addr;
            }
        }
        panic!("failed to change relay");
    })
    .await
    .anyerr()?;

    println!("round2: {:?}", addr);
    assert_eq!(addr.relay_urls().next(), Some(&new_relay_url));

    // remove direct addrs to force relay usage
    addr.addrs
        .retain(|addr| !matches!(addr, TransportAddr::Ip(_)));

    let conn = client.connect(addr, TEST_ALPN).await?;
    let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
    send.write_all(b"Hello, world!").await.anyerr()?;
    send.finish().anyerr()?;
    let data = recv.read_to_end(1000).await.anyerr()?;
    conn.close(0u32.into(), b"bye!");

    task.await.anyerr()??;

    client.close().await;
    server.close().await;

    assert_eq!(&data, b"Hello, world!");

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn endpoint_bidi_send_recv() -> Result {
    let disco = MemoryLookup::new();
    let ep1 = Endpoint::builder(presets::Minimal)
        .address_lookup(disco.clone())
        .alpns(vec![TEST_ALPN.to_vec()])
        .bind()
        .await?;

    let ep2 = Endpoint::builder(presets::Minimal)
        .address_lookup(disco.clone())
        .alpns(vec![TEST_ALPN.to_vec()])
        .bind()
        .await?;

    disco.add_endpoint_info(ep1.addr());
    disco.add_endpoint_info(ep2.addr());

    let ep1_endpointid = ep1.id();
    let ep2_endpointid = ep2.id();
    eprintln!("endpoint id 1 {ep1_endpointid}");
    eprintln!("endpoint id 2 {ep2_endpointid}");

    async fn connect_hello(ep: Endpoint, dst: EndpointId) -> Result {
        let conn = ep.connect(dst, TEST_ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
        info!("sending hello");
        send.write_all(b"hello").await.anyerr()?;
        send.finish().anyerr()?;
        info!("receiving world");
        let m = recv.read_to_end(100).await.anyerr()?;
        assert_eq!(m, b"world");
        conn.close(1u8.into(), b"done");
        Ok(())
    }

    async fn accept_world(ep: Endpoint, src: EndpointId) -> Result {
        let incoming = ep.accept().await.anyerr()?;
        let mut iconn = incoming.accept().anyerr()?;
        let alpn = iconn.alpn().await?;
        let conn = iconn.await.anyerr()?;
        let endpoint_id = conn.remote_id();
        assert_eq!(endpoint_id, src);
        assert_eq!(alpn, TEST_ALPN);
        let (mut send, mut recv) = conn.accept_bi().await.anyerr()?;
        info!("receiving hello");
        let m = recv.read_to_end(100).await.anyerr()?;
        assert_eq!(m, b"hello");
        info!("sending hello");
        send.write_all(b"world").await.anyerr()?;
        send.finish().anyerr()?;
        match conn.closed().await {
            ConnectionError::ApplicationClosed(closed) => {
                assert_eq!(closed.error_code, 1u8.into());
                Ok(())
            }
            _ => panic!("wrong close error"),
        }
    }

    let p1_accept = tokio::spawn(
        accept_world(ep1.clone(), ep2_endpointid).instrument(info_span!(
            "p1_accept",
            ep1 = %ep1.id().fmt_short(),
            dst = %ep2_endpointid.fmt_short(),
        )),
    );
    let p2_accept = tokio::spawn(
        accept_world(ep2.clone(), ep1_endpointid).instrument(info_span!(
            "p2_accept",
            ep2 = %ep2.id().fmt_short(),
            dst = %ep1_endpointid.fmt_short(),
        )),
    );
    let p1_connect = tokio::spawn(connect_hello(ep1.clone(), ep2_endpointid).instrument(
        info_span!(
            "p1_connect",
            ep1 = %ep1.id().fmt_short(),
            dst = %ep2_endpointid.fmt_short(),
        ),
    ));
    let p2_connect = tokio::spawn(connect_hello(ep2.clone(), ep1_endpointid).instrument(
        info_span!(
            "p2_connect",
            ep2 = %ep2.id().fmt_short(),
            dst = %ep1_endpointid.fmt_short(),
        ),
    ));

    p1_accept.await.anyerr()??;
    p2_accept.await.anyerr()??;
    p1_connect.await.anyerr()??;
    p2_connect.await.anyerr()??;

    Ok(())
}

/// Regression test: Don't fail connections with dead relays on Windows.
///
/// A single client connecting to a single server over a usable direct path
/// must succeed even when both are configured with an unreachable home relay
/// (`https://127.0.0.1:1`, nothing listening). The dead relay should be irrelevant:
/// the direct path works and the connection comes up in milliseconds.
///
/// This was broken on Windows because QaD sends over the same socket to the dead
/// relay, and the socket would return recv errors on the next recv to report ICMP
/// errors for the previous send. We now skip over these errors, implemented in
/// https://github.com/n0-computer/net-tools/pull/166, so this no longer fails.
#[tokio::test]
async fn endpoint_unreachable_relay_direct_connect_succeeds() -> Result {
    // The relay url and its QADv4 probe must both hit closed ports, so the relay is
    // unreachable and the probe draws the ICMP port-unreachable the Windows socket
    // reports on its next recv. Claim an ephemeral port, then close it: it's now free,
    // so nothing answers. There's nothing stopping the kernel from reusing a port
    // right away, but on most machines that's unlikely. The url is dialed over TCP
    // (HTTPS), the probe over UDP, so claim each with the matching socket type.
    let closed_tcp_port = {
        let sock = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        sock.local_addr().expect("local addr").port()
    };
    let closed_udp_port = {
        let sock = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        sock.local_addr().expect("local addr").port()
    };
    let dead_relay: RelayUrl = format!("https://127.0.0.1:{closed_tcp_port}")
        .parse()
        .expect("valid relay url");
    let dead_relay_config = RelayConfig::new(
        dead_relay.clone(),
        Some(RelayQuicConfig::new(closed_udp_port)),
    );

    let bind_endpoint = async || {
        Endpoint::builder(presets::Minimal)
            // Use the broken relay to trigger the ICMP errors from the QaD sends.
            .relay_mode(RelayMode::Custom(RelayMap::from_iter([
                dead_relay_config.clone()
            ])))
            .ca_tls_config(CaTlsConfig::insecure_skip_verify())
            .alpns(vec![TEST_ALPN.to_vec()])
            // Bind on IPv4 only to ensure a single socket to not have spurious polls.
            .bind_addr((Ipv4Addr::LOCALHOST, 0))
            .expect("valid addr")
            .bind()
            .await
    };

    let server = bind_endpoint().await?;
    let server_addr = server.addr().with_relay_url(dead_relay.clone());
    let client = bind_endpoint().await?;

    // Server accepts the incoming connection and holds it open until the test ends.
    let accept = tokio::spawn(async move {
        let incoming = server.accept().await.anyerr()?;
        let conn = incoming.await.anyerr()?;
        conn.closed().await;
        server.close().await;
        n0_error::Ok(())
    });

    // The connect must complete over the direct loopback path despite the dead relay.
    let _conn = tokio::time::timeout(
        Duration::from_secs(10),
        client.connect(server_addr, TEST_ALPN),
    )
    .await
    .expect("connection should succeed")?;
    client.close().await;
    accept.await.anyerr()??;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_direct_addresses_no_qad_relay() -> Result {
    let (relay_map, _, _guard) = run_relay_server_with(false).await.unwrap();

    let ep = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(relay_map))
        .alpns(vec![TEST_ALPN.to_vec()])
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .bind()
        .await?;

    assert!(ep.addr().ip_addrs().count() > 0);

    Ok(())
}

/// Test that configured external addresses are included in the endpoint's
/// direct addresses, both when set via builder and at runtime.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[traced_test]
async fn test_external_addr() -> Result {
    let configured_addr = SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 12345));

    // Test builder-configured external address
    let ep = Endpoint::builder(presets::Minimal)
        .external_addr(configured_addr)
        .bind()
        .await?;

    let addr = ep.addr();
    assert!(
        addr.ip_addrs().any(|a| *a == configured_addr),
        "builder-configured external addr {configured_addr} not found in endpoint addr: {addr:?}"
    );

    // Test runtime add
    let runtime_addr = SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(5, 6, 7, 8), 54321));
    ep.add_external_addr(runtime_addr).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let addr = ep.addr();
    assert!(
        addr.ip_addrs().any(|a| *a == runtime_addr),
        "runtime-added external addr {runtime_addr} not found in endpoint addr: {addr:?}"
    );

    // Test runtime remove
    let removed = ep.remove_external_addr(&runtime_addr).await;
    assert!(removed);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let addr = ep.addr();
    assert!(
        !addr.ip_addrs().any(|a| *a == runtime_addr),
        "removed external addr {runtime_addr} still found in endpoint addr: {addr:?}"
    );
    assert!(
        addr.ip_addrs().any(|a| *a == configured_addr),
        "builder-configured external addr should still be present: {addr:?}"
    );

    ep.close().await;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn graceful_close() -> Result {
    let client = Endpoint::bind(presets::Minimal).await?;
    let server = Endpoint::builder(presets::Minimal)
        .alpns(vec![TEST_ALPN.to_vec()])
        .bind()
        .await?;
    let server_addr = server.addr();
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.anyerr()?;
        let conn = incoming.await.anyerr()?;
        let (mut send, mut recv) = conn.accept_bi().await.anyerr()?;
        let msg = recv.read_to_end(1_000).await.anyerr()?;
        send.write_all(&msg).await.anyerr()?;
        send.finish().anyerr()?;
        let close_reason = conn.closed().await;
        Ok::<_, Error>(close_reason)
    });

    let conn = client.connect(server_addr, TEST_ALPN).await?;
    let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
    send.write_all(b"Hello, world!").await.anyerr()?;
    send.finish().anyerr()?;
    recv.read_to_end(1_000).await.anyerr()?;
    conn.close(42u32.into(), b"thanks, bye!");
    client.close().await;

    let close_err = server_task.await.anyerr()??;
    let ConnectionError::ApplicationClosed(app_close) = close_err else {
        panic!("Unexpected close reason: {close_err:?}");
    };

    assert_eq!(app_close.error_code, 42u32.into());
    assert_eq!(app_close.reason.as_ref(), b"thanks, bye!");

    Ok(())
}

#[cfg(feature = "metrics")]
#[tokio::test]
#[traced_test]
async fn metrics_smoke() -> Result {
    use iroh_metrics::Registry;

    let secret_key = SecretKey::from_bytes(&[0u8; 32]);
    let client = Endpoint::builder(presets::Minimal)
        .secret_key(secret_key)
        .bind()
        .await?;
    let secret_key = SecretKey::from_bytes(&[1u8; 32]);
    let server = Endpoint::builder(presets::Minimal)
        .secret_key(secret_key)
        .alpns(vec![TEST_ALPN.to_vec()])
        .bind()
        .await?;
    let server_addr = server.addr();
    let server_task = tokio::task::spawn(async move {
        let conn = server.accept().await.anyerr()?.await.anyerr()?;
        let mut uni = conn.accept_uni().await.anyerr()?;
        uni.read_to_end(10).await.anyerr()?;
        drop(conn);
        Ok::<_, Error>(server)
    });
    let conn = client.connect(server_addr, TEST_ALPN).await?;
    let mut uni = conn.open_uni().await.anyerr()?;
    uni.write_all(b"helloworld").await.anyerr()?;
    uni.finish().anyerr()?;
    conn.closed().await;
    drop(conn);
    let server = server_task.await.anyerr()??;

    let m = client.metrics();
    // assert_eq!(m.socket.num_direct_conns_added.get(), 1);
    // assert_eq!(m.socket.connection_became_direct.get(), 1);
    // assert_eq!(m.socket.connection_handshake_success.get(), 1);
    // assert_eq!(m.socket.endpoints_contacted_directly.get(), 1);
    assert!(m.socket.recv_datagrams.get() > 0);

    let m = server.metrics();
    // assert_eq!(m.socket.num_direct_conns_added.get(), 1);
    // assert_eq!(m.socket.connection_became_direct.get(), 1);
    // assert_eq!(m.socket.endpoints_contacted_directly.get(), 1);
    // assert_eq!(m.socket.connection_handshake_success.get(), 1);
    assert!(m.socket.recv_datagrams.get() > 0);

    // test openmetrics encoding with labeled subregistries per endpoint
    fn register_endpoint(registry: &mut Registry, endpoint: &Endpoint) {
        let id = endpoint.id().fmt_short();
        let sub_registry = registry.sub_registry_with_label("id", id.to_string());
        sub_registry.register_all(endpoint.metrics());
    }
    let mut registry = Registry::default();
    register_endpoint(&mut registry, &client);
    register_endpoint(&mut registry, &server);
    // let s = registry.encode_openmetrics_to_string().anyerr()?;
    // assert!(s.contains(r#"socket_endpoints_contacted_directly_total{id="3b6a27bcce"} 1"#));
    // assert!(s.contains(r#"socket_endpoints_contacted_directly_total{id="8a88e3dd74"} 1"#));
    Ok(())
}

/// Configures the accept side to take `accept_alpns` ALPNs, then connects to it with `primary_connect_alpn`
/// with `secondary_connect_alpns` set, and finally returns the negotiated ALPN.
async fn alpn_connection_test(
    accept_alpns: Vec<Vec<u8>>,
    primary_connect_alpn: &[u8],
    secondary_connect_alpns: Vec<Vec<u8>>,
) -> Result<Vec<u8>> {
    let client = Endpoint::bind(presets::Minimal).await?;
    let server = Endpoint::builder(presets::Minimal)
        .alpns(accept_alpns)
        .bind()
        .await?;
    let server_addr = server.addr();
    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            let incoming = server.accept().await.anyerr()?;
            let conn = incoming.await.anyerr()?;
            conn.close(0u32.into(), b"bye!");
            n0_error::Ok(conn.alpn().to_vec())
        }
    });

    let conn = client
        .connect_with_opts(
            server_addr,
            primary_connect_alpn,
            ConnectOptions::new().with_additional_alpns(secondary_connect_alpns),
        )
        .await?;
    let conn = conn.await.anyerr()?;
    let client_alpn = conn.alpn();
    conn.closed().await;
    client.close().await;
    server.close().await;

    let server_alpn = server_task.await.anyerr()??;

    assert_eq!(client_alpn, server_alpn);

    Ok(server_alpn.to_vec())
}

#[tokio::test]
#[traced_test]
async fn connect_multiple_alpn_negotiated() -> Result {
    const ALPN_ONE: &[u8] = b"alpn/1";
    const ALPN_TWO: &[u8] = b"alpn/2";

    assert_eq!(
        alpn_connection_test(
            // Prefer version 2 over version 1 on the accept side
            vec![ALPN_TWO.to_vec(), ALPN_ONE.to_vec()],
            ALPN_TWO,
            vec![ALPN_ONE.to_vec()],
        )
        .await?,
        ALPN_TWO.to_vec(),
        "accept side prefers version 2 over 1"
    );

    assert_eq!(
        alpn_connection_test(
            // Only support the old version
            vec![ALPN_ONE.to_vec()],
            ALPN_TWO,
            vec![ALPN_ONE.to_vec()],
        )
        .await?,
        ALPN_ONE.to_vec(),
        "accept side only supports the old version"
    );

    assert_eq!(
        alpn_connection_test(
            vec![ALPN_TWO.to_vec(), ALPN_ONE.to_vec()],
            ALPN_ONE,
            vec![ALPN_TWO.to_vec()],
        )
        .await?,
        ALPN_TWO.to_vec(),
        "connect side ALPN order doesn't matter"
    );

    assert_eq!(
        alpn_connection_test(vec![ALPN_TWO.to_vec(), ALPN_ONE.to_vec()], ALPN_ONE, vec![],).await?,
        ALPN_ONE.to_vec(),
        "connect side only supports the old version"
    );

    Ok(())
}

#[tokio::test]
#[traced_test]
#[cfg(feature = "unstable-net-report")]
async fn watch_net_report() -> Result {
    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Staging)
        .bind()
        .await?;

    // can get a first report
    endpoint.net_report().updated().await.anyerr()?;

    Ok(())
}

/// Tests that initial connection establishment isn't extremely slow compared
/// to subsequent connections.
///
/// This is a time based test, but uses a very large ratio to reduce flakiness.
/// It also does a number of connections to average out any anomalies.
#[tokio::test]
#[traced_test]
async fn connect_multi_time() -> Result {
    let n = 32;

    const NOOP_ALPN: &[u8] = b"noop";

    #[derive(Debug, Clone)]
    struct Noop;

    impl ProtocolHandler for Noop {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            connection.closed().await;
            Ok(())
        }
    }

    async fn noop_server() -> Result<(Router, EndpointAddr)> {
        let endpoint = Endpoint::bind(presets::Minimal).await.anyerr()?;
        let addr = endpoint.addr();
        let router = Router::builder(endpoint).accept(NOOP_ALPN, Noop).spawn();
        Ok((router, addr))
    }

    let routers = stream::iter(0..n)
        .map(|_| noop_server())
        .buffered_unordered(32)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .anyerr()?;

    let addrs = routers
        .iter()
        .map(|(_, addr)| addr.clone())
        .collect::<Vec<_>>();
    let ids = addrs.iter().map(|addr| addr.id).collect::<Vec<_>>();
    let address_lookup = MemoryLookup::from_endpoint_info(addrs);
    let endpoint = Endpoint::builder(presets::Minimal)
        .address_lookup(address_lookup)
        .bind()
        .await
        .anyerr()?;
    // wait for the endpoint to be initialized. This should not be needed,
    // but we don't want to measure endpoint init time but connection time
    // from a fully initialized endpoint.
    endpoint.addr();
    let t0 = Instant::now();
    for id in &ids {
        let conn = endpoint.connect(*id, NOOP_ALPN).await?;
        conn.close(0u32.into(), b"done");
    }
    let dt0 = t0.elapsed().as_secs_f64();
    let t1 = Instant::now();
    for id in &ids {
        let conn = endpoint.connect(*id, NOOP_ALPN).await?;
        conn.close(0u32.into(), b"done");
    }
    let dt1 = t1.elapsed().as_secs_f64();

    assert!(dt0 / dt1 < 20.0, "First round: {dt0}s, second round {dt1}s");
    Ok(())
}

#[tokio::test]
async fn test_custom_relay() -> Result {
    let _ep = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::custom([RelayUrl::from_str(
            "https://use1-1.relay.n0.iroh.link.",
        )?]))
        .bind()
        .await?;

    let relays = RelayMap::try_from_iter([
        "https://use1-1.relay.n0.iroh.link/",
        "https://euc1-1.relay.n0.iroh.link/",
    ])?;
    let _ep = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(relays))
        .bind()
        .await?;

    Ok(())
}

/// Testing bind_addr: Clear IP transports and add single IPv4 bind
#[tokio::test]
#[traced_test]
async fn test_bind_addr_clear() -> Result {
    let ep = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, 0))?
        .bind()
        .await?;
    let bound_sockets = ep.bound_sockets();
    assert_eq!(bound_sockets.len(), 1);
    assert_eq!(bound_sockets[0].ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    ep.close().await;
    Ok(())
}

/// Testing bind_addr: Do not clear IP transports and add single non-default IPv4 bind
///
/// This will bind two sockets: default wildcard bind for IPv6, and our
/// manually-added IPv4 bind.
#[tokio::test]
#[traced_test]
async fn test_bind_addr_no_clear() -> Result {
    let ep = Endpoint::builder(presets::Minimal)
        .bind_addr((Ipv4Addr::LOCALHOST, 0))?
        .bind()
        .await?;
    let bound_sockets = ep.bound_sockets();
    assert_eq!(bound_sockets.len(), 2);
    assert_eq!(bound_sockets.iter().filter(|x| x.is_ipv4()).count(), 1);
    assert_eq!(bound_sockets.iter().filter(|x| x.is_ipv6()).count(), 1);
    // Test that our manually added socket is there
    assert!(
        bound_sockets
            .iter()
            .any(|x| x.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST))
    );
    ep.close().await;
    Ok(())
}

// Testing bind_addr: Do not clear IP transports and add single default IPv4 bind.
//
// This replaces the default IPv4 bind added by the builder,
// but keeps the default wildcard IPv6 bind.
#[tokio::test]
#[traced_test]
async fn test_bind_addr_default() -> Result {
    let ep = Endpoint::builder(presets::Minimal)
        .bind_addr_with_opts(
            (Ipv4Addr::LOCALHOST, 0),
            BindOpts::default().set_is_default_route(true),
        )?
        .bind()
        .await?;
    let bound_sockets = ep.bound_sockets();
    assert_eq!(bound_sockets.len(), 2);
    assert_eq!(bound_sockets.iter().filter(|x| x.is_ipv4()).count(), 1);
    assert_eq!(bound_sockets.iter().filter(|x| x.is_ipv6()).count(), 1);
    assert!(
        bound_sockets
            .iter()
            .any(|x| x.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST))
    );
    ep.close().await;
    drop(ep);

    Ok(())
}

/// Testing bind_addr: Do not clear IP transports and add single IPv4 bind with a non-zero prefix len
///
/// This will bind three sockets: default wildcard bind for IPv4 and IPv6, and our
/// manually-added IPv4 bind.
#[tokio::test]
#[traced_test]
async fn test_bind_addr_nonzero_prefix() -> Result {
    let ep = Endpoint::builder(presets::Minimal)
        .bind_addr_with_opts(
            (Ipv4Addr::LOCALHOST, 0),
            BindOpts::default().set_prefix_len(32),
        )?
        .bind()
        .await?;
    let bound_sockets = ep.bound_sockets();
    assert_eq!(bound_sockets.len(), 3);
    assert_eq!(bound_sockets.iter().filter(|x| x.is_ipv4()).count(), 2);
    assert_eq!(bound_sockets.iter().filter(|x| x.is_ipv6()).count(), 1);
    // Test that the default wildcard socket is there
    assert!(
        bound_sockets
            .iter()
            .any(|x| x.ip() == IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    );
    // Test that our manually added socket is there
    assert!(
        bound_sockets
            .iter()
            .any(|x| x.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST))
    );
    ep.close().await;
    Ok(())
}

/// Bind on an unusable port with the default opts.
///
/// Binding the endpoint fails with an AddrInUse error.
#[tokio::test]
#[traced_test]
async fn test_bind_addr_badport() -> Result {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = socket.local_addr()?.port();

    let res = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, port))?
        .bind()
        .await;

    assert!(matches!(
        res,
        Err(BindError::Sockets {
            source: io_error,
            ..
        })
        if io_error.kind() == io::ErrorKind::AddrInUse
    ));
    Ok(())
}

/// Bind a non-default route on an unusable port, but set is_required = false.
///
/// Binding the endpoint succeeds.
#[tokio::test]
#[traced_test]
async fn test_bind_addr_badport_notrequired() -> Result {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = socket.local_addr()?.port();

    let ep = Endpoint::builder(presets::Minimal)
        .bind_addr_with_opts(
            (Ipv4Addr::LOCALHOST, port),
            BindOpts::default()
                .set_prefix_len(32)
                .set_is_required(false),
        )?
        .bind()
        .await?;
    let bound_sockets = ep.bound_sockets();
    // just the default wildcard binds
    assert_eq!(bound_sockets.len(), 2);
    // our requested bind addr is not included because it failed to bind
    assert!(
        !bound_sockets
            .iter()
            .any(|x| x.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST))
    );
    Ok(())
}

/// Bind on a default route on an unusable port, but set is_required = false.
///
/// Binding the endpoint succeeds.
#[tokio::test]
#[traced_test]
async fn test_bind_addr_badport_default_notrequired() -> Result {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = socket.local_addr()?.port();

    let ep = Endpoint::builder(presets::Minimal)
        .bind_addr_with_opts(
            (Ipv4Addr::LOCALHOST, port),
            BindOpts::default().set_is_required(false),
        )?
        .bind()
        .await?;
    let bound_sockets = ep.bound_sockets();
    // just the IPv6 default, but no IPv4 bind at all because we replaced the default
    // with a bind with an unusable port and set it to not be required.
    assert_eq!(bound_sockets.len(), 1);
    assert!(bound_sockets[0].is_ipv6());
    Ok(())
}

/// Bind on an unusable port, with is_required = false, and no other transports.
///
/// Binding the endpoint fails with "no valid address available".
#[tokio::test]
#[traced_test]
async fn test_bind_addr_badport_notrequired_no_other_transports() -> Result {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = socket.local_addr()?.port();

    let res = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr_with_opts(
            (Ipv4Addr::LOCALHOST, port),
            BindOpts::default().set_is_required(false),
        )?
        .bind()
        .await;

    assert!(matches!(
        res,
        Err(BindError::CreateQuicEndpoint {
            source: io_error,
            ..
        })
        if io_error.kind() == io::ErrorKind::Other && io_error.to_string() == "no valid address available"
    ));
    Ok(())
}

/// Bind with prefix len 0 but set the route as non-default.
#[tokio::test]
#[traced_test]
async fn test_bind_addr_prefix_len_0_not_default() -> Result {
    let ep = Endpoint::builder(presets::Minimal)
        .bind_addr_with_opts(
            (Ipv4Addr::LOCALHOST, 0),
            BindOpts::default().set_is_default_route(false),
        )?
        .bind()
        .await?;
    let bound_sockets = ep.bound_sockets();
    // The two default wildcard binds plus our additional route (which does not replace the default route
    // because we set is_default_route to false explicitly).
    assert_eq!(bound_sockets.len(), 3);
    assert!(
        bound_sockets
            .iter()
            .any(|x| x.ip() == IpAddr::V6(Ipv6Addr::UNSPECIFIED))
    );
    assert!(
        bound_sockets
            .iter()
            .any(|x| x.ip() == IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    );
    assert!(
        bound_sockets
            .iter()
            .any(|x| x.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST))
    );
    Ok(())
}

#[ignore = "flaky"]
#[tokio::test]
#[traced_test]
async fn connect_via_relay_becomes_direct_and_sends_direct() -> Result {
    let (relay_map, relay_url, _relay_server_guard) = run_relay_server().await?;
    let qlog = Arc::new(QlogFileGroup::from_env(
        "connect_via_relay_becomes_direct_and_sends_direct",
    ));
    let transfer_size = 1_000_000;

    async fn collect_stats(mut events: PathEventStream) -> BTreeMap<TransportAddr, PathStats> {
        let mut stats = BTreeMap::new();
        while let Some(event) = events.next().await {
            if let PathEvent::Closed {
                remote_addr,
                last_stats,
                ..
            } = event
            {
                stats.insert(remote_addr, *last_stats);
            }
        }
        stats
    }

    let client = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(relay_map.clone()))
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .transport_config(qlog.create("client")?)
        .bind()
        .await?;
    let server = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(relay_map))
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .transport_config(qlog.create("server")?)
        .alpns(vec![TEST_ALPN.to_vec()])
        .bind()
        .await?;
    let server_addr = EndpointAddr::new(server.id()).with_relay_url(relay_url);
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.anyerr()?;
        let conn = incoming.await.anyerr()?;
        let stats_task = tokio::spawn(collect_stats(conn.path_events()));
        let (mut send, mut recv) = conn.accept_bi().await.anyerr()?;
        let msg = recv.read_to_end(transfer_size).await.anyerr()?;
        send.write_all(&msg).await.anyerr()?;
        send.finish().anyerr()?;
        conn.closed().await;
        let stats = stats_task.await.expect("stats task panicked");
        Ok::<_, Error>(stats)
    });

    let conn = client.connect(server_addr, TEST_ALPN).await?;
    let client_stats_task = tokio::spawn(collect_stats(conn.path_events()));
    let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
    send.write_all(&vec![42u8; transfer_size]).await.anyerr()?;
    send.finish().anyerr()?;
    recv.read_to_end(transfer_size).await.anyerr()?;
    conn.close(0u32.into(), b"thanks, bye!");
    client.close().await;
    let client_stats = client_stats_task.await.expect("stats task panicked");
    let server_stats = server_task.await.anyerr()??;

    info!("client stats: {client_stats:#?}");
    info!("server stats: {server_stats:#?}");

    let client_total_relay_tx = client_stats
        .iter()
        .filter(|(remote, _stats)| remote.is_relay())
        .map(|(_, stats)| stats.udp_tx.bytes)
        .sum::<u64>();
    let client_total_relay_rx = client_stats
        .iter()
        .filter(|(remote, _stats)| remote.is_relay())
        .map(|(_, stats)| stats.udp_rx.bytes)
        .sum::<u64>();
    let server_total_relay_tx = server_stats
        .iter()
        .filter(|(remote, _stats)| remote.is_relay())
        .map(|(_, stats)| stats.udp_tx.bytes)
        .sum::<u64>();
    let server_total_relay_rx = server_stats
        .iter()
        .filter(|(remote, _stats)| remote.is_relay())
        .map(|(_, stats)| stats.udp_rx.bytes)
        .sum::<u64>();

    info!(?client_total_relay_tx, "total");
    info!(?client_total_relay_rx, "total");
    info!(?server_total_relay_tx, "total");
    info!(?server_total_relay_rx, "total");

    // We should send/receive only the minorty of traffic via the relay.
    assert!(client_total_relay_tx < transfer_size as u64 / 2);
    assert!(client_total_relay_rx < transfer_size as u64 / 2);
    assert!(server_total_relay_tx < transfer_size as u64 / 2);
    assert!(server_total_relay_rx < transfer_size as u64 / 2);

    Ok(())
}

/// Tests that correct logs are emitted when connecting two endpoints with same secret keys to a relay.
#[tokio::test]
#[traced_test]
async fn same_endpoint_id_relay() -> Result {
    let (relay_map, relay_url, _relay_server_guard) = run_relay_server().await?;
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(1u64);
    let secret_key = SecretKey::from_bytes(&rng.random());

    let client = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(relay_map.clone()))
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .bind()
        .instrument(error_span!("ep-client"))
        .await?;

    info!("client {}", client.id());

    // bind ep1 and wait until connected to relay.
    let ep1 = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(relay_map.clone()))
        .secret_key(secret_key.clone())
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .alpns(vec![TEST_ALPN.to_vec()])
        .bind()
        .instrument(error_span!("ep1"))
        .await?;
    info!("ep1 bound {:?}", ep1.id());
    ep1.online().await;
    info!("ep1 online");

    let addr = EndpointAddr::new(secret_key.public()).with_relay_url(relay_url.clone());

    tokio::try_join!(
        async {
            let conn = client.connect(addr.clone(), TEST_ALPN).await?;
            let reason = conn.closed().await;
            assert!(is_application_closed(&reason, 1));
            n0_error::Ok(())
        },
        async {
            let conn = ep1.accept().await.unwrap().await?;
            conn.close(1u32.into(), b"bye");
            n0_error::Ok(())
        }
    )?;
    info!("client connected to ep1");

    // now start second endpoint with same secret key
    let ep2 = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(relay_map))
        .secret_key(secret_key.clone())
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .alpns(vec![TEST_ALPN.to_vec()])
        .bind()
        .instrument(error_span!("ep2"))
        .await?;
    info!("ep2 bound {:?}", ep2.id());
    ep2.online().await;
    println!("ep2 online");

    // `online` does not mean that the connection to the home relay was *established*,
    // only that the home relay was *chosen* based on the net report probes.
    // We need to wait for the connection to be established though, to be sure that new packets
    // will be routed to the new endpoint and not to the old endpoint anymore.
    // We don't expose being connected to the home relay on the endpoint currently,
    // so we resort to log assertions.
    // TODO(Frando): Replace once we add a proper API for this.
    let expected_log_line = format!(
        "ep2:endpoint{{id={}}}:relay-actor:active-relay{{url={relay_url}}}:connected: iroh::_events::relay::connected",
        ep2.id().fmt_short()
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while !logs_contain(&expected_log_line) {
            tokio::time::sleep(Duration::from_millis(10)).await
        }
    })
    .await
    .std_context("relay connection did not establish in time")?;

    tokio::try_join!(
        async {
            let conn = client.connect(addr.clone(), TEST_ALPN).await?;
            let reason = conn.closed().await;
            assert!(is_application_closed(&reason, 1));
            n0_error::Ok(())
        },
        async {
            let conn = ep2.accept().await.unwrap().await?;
            conn.close(1u32.into(), b"bye");
            n0_error::Ok(())
        }
    )?;
    println!("client connected to ep2");

    // assert that ep1 did not receive a connection
    assert!(now_or_never(ep1.accept()).is_none());

    // We assert that we get the warn log once for endpoint 1, and not at all for endpoint 2.
    logs_assert(|logs| {
        let expected_line = |line: &str| {
            line.contains("WARN") && line.contains("Another endpoint connected with the same endpoint id. No more messages will be received")
        };
        let count_line_ep1 = logs
            .iter()
            .filter(|line| line.contains(":ep1:") && expected_line(line))
            .count();
        let count_line_ep2 = logs
            .iter()
            .filter(|line| line.contains(":ep2:") && expected_line(line))
            .count();
        if count_line_ep1 == 1 && count_line_ep2 == 0 {
            Ok(())
        } else {
            Err("Logs don't match expectations".to_string())
        }
    });
    tokio::join!(ep1.close(), ep2.close(), client.close());
    Ok(())
}

fn is_application_closed(close_reason: &ConnectionError, code: u32) -> bool {
    matches!(
        close_reason,
        ConnectionError::ApplicationClosed(f) if f.error_code ==code.into()
    )
}

#[tokio::test]
#[traced_test]
async fn test_closed_endpoint_behaviour() -> Result {
    // create endpoint
    // call endpoint.close
    // ensure methods behave in the expected way
    info!("Creating endpoint");
    let ep = Endpoint::builder(presets::N0).bind().await?;
    let closed = ep.closed();
    info!("Closing endpoint");
    let now = Instant::now();
    ep.close().await;
    info!("Endpoint closed in {:?}", now.elapsed());

    // Assert that the `closed` cancellation token is now cancelled
    assert_eq!(now_or_never(closed), Some(()));

    info!("Set ALPNS fails silently");
    ep.set_alpns(vec![b"test".into()]);

    info!("Insert Relay returns None");
    let relay_config = crate::defaults::staging::default_na_east_relay();
    assert!(
        ep.insert_relay("localhost:300".parse()?, Arc::new(relay_config))
            .await
            .is_none()
    );

    info!("Remove Relay returns None");
    assert!(ep.remove_relay(&"localhost:300".parse()?).await.is_none());

    info!("Connecting");
    let mut rng = ChaCha8Rng::seed_from_u64(41);
    let ep_id = SecretKey::from_bytes(&rng.random()).public();

    // should likely be an error that states that the
    // endpoint is closed instead:
    if let ConnectError::Connect { source, .. } = ep.connect(ep_id, b"test").await.unwrap_err() {
        assert!(matches!(
            source,
            ConnectWithOptsError::EndpointClosed { .. }
        ));
    } else {
        panic!("unexpected error for connect");
    }

    info!("Accepting!");
    assert!(ep.accept().await.is_none());

    // this should work
    info!("Addr: {:?}", ep.addr());

    // create watchers to verify they terminate after the endpoint is dropped.
    let mut addrs = ep.watch_addr().stream();

    #[cfg(feature = "unstable-net-report")]
    let mut net_reports = {
        let net_reports = ep.net_report().stream();

        // returns None
        let net_report = ep.net_report().get();
        info!("last Net report {net_report:?}");
        net_reports
    };

    // this should work
    let sockets = ep.bound_sockets();
    info!("Sockets: {sockets:?}");

    // these should return errors
    assert!(ep.dns_resolver().is_err());
    assert!(ep.address_lookup().is_err());

    #[cfg(feature = "metrics")]
    {
        // this should work
        let metrics = ep.metrics();
        info!("Metrics: {metrics:?}");
    }

    // this should return none
    assert!(ep.remote_info(ep_id).await.is_none());

    // this should fail silently
    ep.network_change().await;

    // this should fail silently
    ep.set_user_data_for_address_lookup(Some(
        UserData::try_from("TEST".to_string()).expect("valid string"),
    ));
    drop(ep);
    // now that the endpoint is dropped, all watchers should terminate.
    tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(addr) = addrs.next().await {
            info!("Addrs stream: {addr:?}");
        }

        #[cfg(feature = "unstable-net-report")]
        while let Some(net_report) = net_reports.next().await {
            info!("Net report stream: {net_report:?}");
        }
    })
    .await
    .expect("watchers not closed");

    info!("Done!");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn endpoint_close_is_idempotent() -> Result {
    let endpoint = Endpoint::builder(presets::N0).bind().await?;

    endpoint.close().await;
    tokio::time::timeout(Duration::from_secs(1), endpoint.close())
        .await
        .expect("a repeated close completes immediately");

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_closed_endpoint_unpolled_accept_fut() -> Result {
    info!("Creating endpoint");
    let ep = Endpoint::builder(presets::N0).bind().await?;

    info!("Get accept future");
    let accept_fut = ep.accept();

    info!("Closing endpoint");
    let now = Instant::now();
    tokio::time::timeout(Duration::from_secs(5), ep.close())
        .await
        .expect("Endpoint closes in a reasonable time");
    info!("Endpoint closed in {:?}", now.elapsed());

    info!("Accept future returns None after the endpoint has closed");
    let incoming = accept_fut.await;
    assert!(incoming.is_none());
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_closed_endpoint_polled_accept_fut() -> Result {
    info!("Creating endpoint");
    let ep = Endpoint::builder(presets::N0).bind().await?;

    info!("Run an accept task");
    let ep2 = ep.clone();
    let accept_task = tokio::spawn(async move {
        info!("Waiting on Accept");
        let res = ep2.accept().await;
        info!("Accept await has returned");
        res
    });

    // Try to ensure the accept future is polled at least once.
    tokio::time::sleep(Duration::from_millis(10)).await;

    info!("Closing the endpoint");
    tokio::time::timeout(Duration::from_secs(5), ep.close())
        .await
        .expect("Endpoint closes in a reasonable time");
    info!("Endpoint closed");

    info!("Await the accept task");
    let incoming = accept_task.await.expect("accept task panicked");
    assert!(incoming.is_none());

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_endpoint_online_add_relay() -> Result {
    let ep = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(RelayMap::empty()))
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .bind()
        .await?;
    // should not come online without relays.
    let res = tokio::time::timeout(Duration::from_millis(500), ep.online()).await;
    assert!(res.is_err());

    // should come online after a relay is added.
    let (relay_map, relay_url, _relay_server_guard) = run_relay_server().await?;
    ep.insert_relay(relay_url.clone(), relay_map.get(&relay_url).unwrap())
        .await;
    let res = tokio::time::timeout(Duration::from_millis(1000), ep.online()).await;
    assert!(res.is_ok());

    // online should still return after endpoint close, if the endpoint was last online
    let ep_clone = ep.clone();
    let task = tokio::task::spawn(async move {
        tokio::time::timeout(Duration::from_millis(500), ep_clone.online()).await
    });
    ep.close().await;
    let res = task.await.unwrap();
    assert!(res.is_ok());
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_endpoint_online_close() -> Result {
    let ep = Endpoint::bind(presets::Minimal).await?;
    // should not come online without relays.
    let res = tokio::time::timeout(Duration::from_millis(500), ep.online()).await;
    assert!(res.is_err());

    // online should remain pending after the endpoint is closed.
    let ep_clone = ep.clone();
    let task = tokio::task::spawn(async move {
        tokio::time::timeout(Duration::from_millis(500), ep_clone.online()).await
    });
    ep.close().await;
    let res = task.await.unwrap();
    assert!(res.is_err());
    Ok(())
}

/// Verifies that an endpoint configured with [`RelayConfig::with_auth_token`]
/// is admitted to a relay whose access control checks the token only when
/// the token matches.
#[tokio::test]
#[traced_test]
async fn test_endpoint_relay_auth_token() -> Result {
    const TOKEN: &str = "valid-token";

    /// Admits a connection only if it carries the expected auth token.
    #[derive(Debug)]
    struct TokenAccess(&'static str);

    impl krikos_relay::server::AccessControl for TokenAccess {
        async fn on_connect(&self, request: &krikos_relay::server::ClientRequest) -> Access {
            if request.auth_token().as_deref() == Some(self.0) {
                Access::Allow
            } else {
                Access::Deny { reason: None }
            }
        }
    }

    let access = Arc::new(TokenAccess(TOKEN));
    let (_relay_map, relay_url, _guard) = run_relay_server_with_access(false, access).await?;

    // Wrong token: the connection attempt fails and last_error reports
    // the relay-side denial.
    let bad_map: RelayMap = RelayConfig::new(relay_url.clone(), None)
        .with_auth_token("wrong-token")
        .into();
    let bad_ep = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(bad_map))
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .bind()
        .await?;
    let mut stream = bad_ep.home_relay_status().stream();
    let auth_err: String = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(status) = stream.next().await {
            if let Some(err) = status.iter().filter_map(|s| s.last_error()).next() {
                return format!("{err:#}");
            }
        }
        panic!("home relay stream ended");
    })
    .await
    .std_context("waiting for auth error")?;
    assert!(
        auth_err.contains("not authorized"),
        "expected 'not authorized' in error, got: {auth_err}"
    );

    // Correct token: the endpoint reaches the connected state.
    let good_map: RelayMap = RelayConfig::new(relay_url, None)
        .with_auth_token(TOKEN)
        .into();
    let good_ep = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(good_map))
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .bind()
        .await?;
    tokio::time::timeout(Duration::from_secs(5), good_ep.online())
        .await
        .std_context("waiting for endpoint to come online")?;

    Ok(())
}
