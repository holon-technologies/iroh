//! Create a QUIC server that accepts connections
//! for QUIC address discovery.
use std::{net::SocketAddr, sync::Arc};

use n0_error::stack_error;
use n0_future::time::Duration;
use noq::{VarInt, crypto::rustls::QuicClientConfig};

/// ALPN for our quic addr discovery
pub const ALPN_QUIC_ADDR_DISC: &[u8] = b"/iroh-qad/0";
/// Default maximum number of active QUIC address-discovery connections.
pub const DEFAULT_MAX_QAD_CONNECTIONS: usize = 1_024;
/// Endpoint close error code
pub const QUIC_ADDR_DISC_CLOSE_CODE: VarInt = VarInt::from_u32(1);
/// Endpoint close reason
pub const QUIC_ADDR_DISC_CLOSE_REASON: &[u8] = b"finished";

#[cfg(feature = "server")]
pub(crate) mod server {
    use std::num::NonZeroUsize;

    use n0_error::e;
    use noq::{
        ApplicationClose, ConnectionError, ConnectionLifetimeToken, EventQueueLimits,
        crypto::rustls::{NoInitialCipherSuite, QuicServerConfig},
    };
    use tokio::{sync::Semaphore, task::JoinSet};
    use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
    use tracing::{Instrument, debug, info, info_span};

    use super::*;
    use crate::server::Metrics;

    pub(crate) struct QuicServer {
        bind_addr: SocketAddr,
        cancel: CancellationToken,
        handle: AbortOnDropHandle<()>,
    }

    #[derive(Clone, Debug)]
    pub(super) struct QadAdmission {
        slots: Arc<Semaphore>,
    }

    impl QadAdmission {
        pub(super) fn new(capacity: NonZeroUsize) -> Self {
            Self {
                slots: Arc::new(Semaphore::new(capacity.get())),
            }
        }

        pub(super) fn try_acquire(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
            self.slots.clone().try_acquire_owned().ok()
        }
    }

    /// Server spawn errors
    #[allow(missing_docs)]
    #[stack_error(derive, add_meta)]
    #[non_exhaustive]
    pub enum QuicSpawnError {
        #[error("TLS not configured")]
        TlsNotConfigured {},
        #[error(transparent)]
        NoInitialCipherSuite {
            #[error(std_err, from)]
            source: NoInitialCipherSuite,
        },
        #[error("Unable to spawn a QUIC endpoint server")]
        EndpointServer {
            #[error(std_err)]
            source: std::io::Error,
        },
        #[error("Unable to get the local address from the endpoint")]
        LocalAddr {
            #[error(std_err)]
            source: std::io::Error,
        },
        #[error("max_connections must be greater than zero")]
        ZeroMaxConnections {},
        #[error("max_connections {value} exceeds supported maximum {maximum}")]
        MaxConnectionsTooLarge { value: usize, maximum: usize },
    }

    impl QuicServer {
        /// Returns a handle for this server.
        ///
        /// The server runs in the background as several async tasks.  This allows controlling
        /// the server, in particular it allows gracefully shutting down the server.
        pub(crate) fn handle(&self) -> ServerHandle {
            ServerHandle {
                cancel_token: self.cancel.clone(),
            }
        }

        /// Returns the [`AbortOnDropHandle`] for the supervisor task managing the endpoint.
        ///
        /// This is the root of all the tasks for the QUIC address discovery service.  Aborting it will abort all the
        /// other tasks for the service.  Awaiting it will complete when all the service tasks are
        /// completed.[]
        pub(crate) fn task_handle(&mut self) -> &mut AbortOnDropHandle<()> {
            &mut self.handle
        }

        /// Returns the socket address for this QUIC server.
        pub(crate) fn bind_addr(&self) -> SocketAddr {
            self.bind_addr
        }

        /// Spawns a QUIC server that creates and QUIC endpoint and listens
        /// for QUIC connections for address discovery
        ///
        /// # Errors
        /// If the given `quic_config` contains a [`rustls::ServerConfig`] that cannot
        /// be converted to a [`QuicServerConfig`], usually because it does not support
        /// TLS 1.3, a [`NoInitialCipherSuite`] will occur.
        ///
        /// # Panics
        /// If there is a panic during a connection, it will be propagated
        /// up here. Any other errors in a connection will be logged as a
        ///  warning.
        pub(crate) fn spawn(
            bind_addr: SocketAddr,
            mut server_config: rustls::ServerConfig,
            max_connections: usize,
            metrics: Arc<Metrics>,
        ) -> Result<Self, QuicSpawnError> {
            let max_connections = NonZeroUsize::new(max_connections)
                .ok_or_else(|| e!(QuicSpawnError::ZeroMaxConnections))?;
            if max_connections.get() > Semaphore::MAX_PERMITS {
                return Err(e!(QuicSpawnError::MaxConnectionsTooLarge {
                    value: max_connections.get(),
                    maximum: Semaphore::MAX_PERMITS,
                }));
            }
            server_config.alpn_protocols = vec![crate::quic::ALPN_QUIC_ADDR_DISC.to_vec()];
            let server_config = QuicServerConfig::try_from(server_config)?;
            let mut server_config = noq::ServerConfig::with_crypto(Arc::new(server_config));
            let transport_config =
                Arc::get_mut(&mut server_config.transport).expect("not used yet");
            transport_config
                .max_concurrent_uni_streams(0_u8.into())
                .max_concurrent_bidi_streams(0_u8.into())
                // enable sending quic address discovery frames
                .send_observed_address_reports(true);

            let socket = std::net::UdpSocket::bind(bind_addr)
                .map_err(|err| e!(QuicSpawnError::EndpointServer, err))?;
            socket
                .set_nonblocking(true)
                .map_err(|err| e!(QuicSpawnError::EndpointServer, err))?;
            let defaults = EventQueueLimits::default();
            let event_limits = EventQueueLimits::new(
                max_connections,
                defaults.max_packet_events_per_connection(),
                defaults.max_packet_bytes_per_endpoint(),
                defaults.max_control_events_per_endpoint(),
            );
            let endpoint = noq::Endpoint::new_with_limits(
                noq::EndpointConfig::default(),
                Some(server_config),
                socket,
                Arc::new(noq::TokioRuntime),
                event_limits,
            )
            .map_err(|err| e!(QuicSpawnError::EndpointServer, err))?;
            let bind_addr = endpoint
                .local_addr()
                .map_err(|err| e!(QuicSpawnError::LocalAddr, err))?;

            info!(?bind_addr, "QUIC server listening on");

            let cancel = CancellationToken::new();
            let cancel_accept_loop = cancel.clone();
            let admission = QadAdmission::new(max_connections);

            let task = tokio::task::spawn(
                async move {
                    let mut set = JoinSet::new();
                    debug!("waiting for connections...");
                    loop {
                        tokio::select! {
                            biased;
                            _ = cancel_accept_loop.cancelled() => {
                                break;
                            }
                            Some(res) = set.join_next() => {
                                if let Err(err) = res {
                                    if err.is_panic() {
                                        panic!("quic task panicked: {err:#?}");
                                    } else {
                                        debug!("quic task cancelled: {err:#?}");
                                    }
                                }
                            }
                            res = endpoint.accept() => match res {
                                Some(incoming) => {
                                     let permit = match admission.try_acquire() {
                                         Some(permit) => permit,
                                         None => {
                                             metrics.qad_admission_full.inc();
                                             incoming.refuse();
                                             continue;
                                         }
                                     };
                                     let remote_addr = incoming.remote_address();
                                     set.spawn(
                                         handle_connection(incoming, permit, metrics.clone())
                                             .instrument(info_span!("qad-conn", %remote_addr))
                                     );                                }
                                None => {
                                    debug!("endpoint closed");
                                    break;
                                }
                            }
                        }
                    }
                    // close all connections and wait until they have all grace
                    // fully closed.
                    endpoint.close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
                    endpoint.wait_idle().await;

                    // all tasks should be closed, since the endpoint has shutdown
                    // all connections, but await to ensure they are finished.
                    set.abort_all();
                    while !set.is_empty() {
                        _ = set.join_next().await;
                    }

                    debug!("quic endpoint has been shutdown.");
                }
                .instrument(info_span!("quic-endpoint")),
            );
            Ok(Self {
                bind_addr,
                cancel,
                handle: AbortOnDropHandle::new(task),
            })
        }

        /// Closes the underlying QUIC endpoint and the tasks running the
        /// QUIC connections.
        pub(crate) async fn shutdown(mut self) {
            self.cancel.cancel();
            if !self.task_handle().is_finished() {
                // only possible error is a `JoinError`, no errors about what might
                // have happened during a connection are propagated.
                _ = self.task_handle().await;
            }
        }
    }

    /// A handle for the Server side of QUIC address discovery.
    ///
    /// This does not allow access to the task but can communicate with it.
    #[derive(Debug, Clone)]
    pub(crate) struct ServerHandle {
        cancel_token: CancellationToken,
    }

    impl ServerHandle {
        /// Gracefully shut down the quic endpoint.
        pub(crate) fn shutdown(&self) {
            self.cancel_token.cancel()
        }
    }

    /// Handle the connection from the client.
    async fn handle_connection(
        incoming: noq::Incoming,
        permit: tokio::sync::OwnedSemaphorePermit,
        metrics: Arc<Metrics>,
    ) -> Result<(), ConnectionError> {
        metrics.qad_incoming.inc();
        debug!("incoming");
        let connecting = match incoming.accept_with_lifetime(ConnectionLifetimeToken::new(permit)) {
            Ok(connecting) => connecting,
            Err(err) => {
                metrics.qad_incoming_error.inc();
                return Err(err);
            }
        };
        let connection = match connecting.await {
            Ok(conn) => conn,
            Err(e) => {
                debug!("establishing failed: {e:#}");
                metrics.qad_incoming_error.inc();
                return Err(e);
            }
        };
        metrics.qad_connections.inc();
        debug!("established");
        // wait for the client to close the connection
        let connection_err = connection.closed().await;
        metrics.qad_connections_closed.inc();
        match connection_err {
            noq::ConnectionError::ApplicationClosed(ApplicationClose { error_code, .. })
                if error_code == QUIC_ADDR_DISC_CLOSE_CODE =>
            {
                debug!("peer disconnected");
                Ok(())
            }
            _ => {
                debug!("peer disconnected with {connection_err:#}");
                metrics.qad_connections_errored.inc();
                Err(connection_err)
            }
        }
    }
}

/// Quic client related errors.
#[allow(missing_docs)]
#[stack_error(derive, add_meta, from_sources, std_sources)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Connect {
        #[error(std_err)]
        source: noq::ConnectError,
    },
    #[error(transparent)]
    Connection {
        #[error(std_err)]
        source: noq::ConnectionError,
    },
    NoObservedAddr,
}

/// Error constructing a QUIC address-discovery client.
#[stack_error(derive, add_meta, from_sources, std_sources)]
#[non_exhaustive]
pub enum QuicClientBuildError {
    /// The Rustls provider has no cipher suite usable for QUIC Initial packets.
    #[error("Rustls configuration has no QUIC Initial cipher suite")]
    NoInitialCipherSuite {
        /// The invalid Rustls cipher-suite selection.
        #[error(std_err)]
        source: noq::crypto::rustls::NoInitialCipherSuite,
    },
}

/// Handles the client side of QUIC address discovery.
#[derive(Debug, Clone)]
pub struct QuicClient {
    /// A QUIC Endpoint.
    ep: noq::Endpoint,
    /// A client config.
    client_config: noq::ClientConfig,
}

impl QuicClient {
    /// Create a new QuicClient to handle the client side of QUIC
    /// address discovery.
    pub fn new(
        ep: noq::Endpoint,
        mut client_config: rustls::ClientConfig,
    ) -> Result<Self, QuicClientBuildError> {
        // add QAD alpn
        client_config.alpn_protocols = vec![ALPN_QUIC_ADDR_DISC.into()];
        // go from rustls client config to rustls QUIC specific client config to
        // a noq client config
        let mut client_config =
            noq::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_config)?));

        // enable the receive side of address discovery
        let mut transport = noq_proto::TransportConfig::default();
        // Setting the initial RTT estimate to a low value means
        // we're sacrificing initial throughput, which is fine for
        // QAD, which doesn't require us to have good initial throughput.
        // It also implies a 999ms probe timeout, which means that
        // if the packet gets lost (e.g. because we're probing ipv6, but
        // ipv6 packets always get lost in our network configuration) we
        // time out *closing the connection* after only 999ms.
        // Even if the round trip time is bigger than 999ms, this doesn't
        // prevent us from connecting, since that's dependent on the idle
        // timeout (set to 30s by default).
        transport.initial_rtt(Duration::from_millis(111));
        transport.receive_observed_address_reports(true);

        // keep it alive
        transport.keep_alive_interval(Some(Duration::from_secs(25)));
        transport.max_idle_timeout(Some(
            Duration::from_secs(35).try_into().expect("known value"),
        ));
        client_config.transport_config(Arc::new(transport));

        Ok(Self { ep, client_config })
    }

    /// Client side of QUIC address discovery.
    ///
    /// Creates a connection and returns the observed address
    /// and estimated latency of the connection.
    ///
    /// Consumes and gracefully closes the connection.
    #[cfg(all(test, feature = "server"))]
    async fn get_addr_and_latency(
        &self,
        server_addr: SocketAddr,
        host: &str,
    ) -> Result<(SocketAddr, std::time::Duration), Error> {
        use n0_future::StreamExt;
        use noq_proto::PathId;

        let connecting = self
            .ep
            .connect_with(self.client_config.clone(), server_addr, host);
        let conn = connecting?.await?;
        let mut external_addresses = conn.observed_external_addr();
        // TODO(ramfox): I'd like to be able to cancel this so we can close cleanly
        // if there the task that runs this function gets aborted.
        // tokio::select! {
        //     _ = cancel.cancelled() => {
        //         conn.close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
        //         bail_any!("QUIC address discovery canceled early");
        //     },
        //     res = external_addresses.wait_for(|addr| addr.is_some()) => {
        //         let addr = res?.expect("checked");
        //         let latency = conn.rtt() / 2;
        //         // gracefully close the connections
        //         conn.close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
        //         Ok((addr, latency))
        //     }

        let Some(mut observed_addr) = external_addresses.next().await else {
            n0_error::bail!(Error::NoObservedAddr);
        };
        // if we've sent to an ipv4 address, but received an observed address
        // that is ivp6 then the address is an [IPv4-Mapped IPv6 Addresses](https://doc.rust-lang.org/beta/std/net/struct.Ipv6Addr.html#ipv4-mapped-ipv6-addresses)
        observed_addr = SocketAddr::new(observed_addr.ip().to_canonical(), observed_addr.port());
        let latency = conn.rtt(PathId::ZERO).unwrap_or_default();
        // gracefully close the connections
        conn.close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
        Ok((observed_addr, latency))
    }

    /// Create a connection usable for qad
    pub async fn create_conn(
        &self,
        server_addr: SocketAddr,
        host: &str,
    ) -> Result<noq::Connection, Error> {
        let config = self.client_config.clone();
        let connecting = self.ep.connect_with(config, server_addr, host);
        let conn = connecting?.await?;
        Ok(conn)
    }

    /// Creates a QAD connection while retaining an embedder-owned lifetime token.
    pub async fn create_conn_with_lifetime(
        &self,
        server_addr: SocketAddr,
        host: &str,
        lifetime: noq::ConnectionLifetimeToken,
    ) -> Result<noq::Connection, Error> {
        let config = self.client_config.clone();
        let connecting =
            self.ep
                .connect_with_config_and_lifetime(config, server_addr, host, lifetime);
        let conn = connecting?.await?;
        Ok(conn)
    }
}

#[cfg(all(test, feature = "server", with_crypto_provider))]
mod tests {
    use std::{net::Ipv4Addr, sync::Arc};

    use n0_error::{Result, StdResultExt};
    use n0_future::{
        task::AbortOnDropHandle,
        time::{self, Instant},
    };
    use n0_tracing_test::traced_test;
    use noq::crypto::rustls::QuicServerConfig;
    use tracing::{Instrument, debug, info, info_span};
    use webpki_types::PrivatePkcs8KeyDer;

    use super::*;

    #[test]
    fn qad_admission_limit_is_exact_and_recovers() {
        let capacity = std::num::NonZeroUsize::new(2).unwrap();
        let admission = server::QadAdmission::new(capacity);

        let first = admission.try_acquire().expect("first slot");
        let _second = admission.try_acquire().expect("second slot");
        assert!(admission.try_acquire().is_none(), "third slot must reject");

        drop(first);
        assert!(
            admission.try_acquire().is_some(),
            "released capacity must be reusable"
        );
    }

    #[tokio::test]
    async fn qad_client_rejects_provider_without_initial_cipher_suite() -> Result {
        let endpoint = noq::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into())
            .std_context("client endpoint")?;
        let mut provider = rustls::crypto::ring::default_provider();
        provider
            .cipher_suites
            .retain(|suite| suite.suite() != rustls::CipherSuite::TLS13_AES_128_GCM_SHA256);
        assert!(!provider.cipher_suites.is_empty());
        let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .std_context("TLS 1.3 provider")?
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        let error = QuicClient::new(endpoint, client_config)
            .expect_err("QAD requires TLS13_AES_128_GCM_SHA256 for Initial packets");
        assert!(matches!(
            error,
            QuicClientBuildError::NoInitialCipherSuite { .. }
        ));
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "test-utils")]
    async fn zero_qad_connection_capacity_is_rejected() {
        let host = Ipv4Addr::LOCALHOST;
        let (_, server_config) = super::super::server::testing::self_signed_tls_certs_and_config();
        let result =
            server::QuicServer::spawn((host, 0).into(), server_config, 0, Default::default());

        assert!(matches!(
            result,
            Err(server::QuicSpawnError::ZeroMaxConnections { .. })
        ));
    }

    #[tokio::test]
    #[traced_test]
    #[cfg(feature = "test-utils")]
    async fn quic_endpoint_basic() -> Result {
        use super::server::QuicServer;

        let host: Ipv4Addr = "127.0.0.1".parse().unwrap();
        // create a server config with self signed certificates
        let (_, server_config) = super::super::server::testing::self_signed_tls_certs_and_config();
        let bind_addr = SocketAddr::new(host.into(), 0);
        let quic_server = QuicServer::spawn(
            bind_addr,
            server_config,
            DEFAULT_MAX_QAD_CONNECTIONS,
            Default::default(),
        )?;

        // create a client-side endpoint
        let client_endpoint =
            noq::Endpoint::client(SocketAddr::new(host.into(), 0)).std_context("client")?;
        let client_addr = client_endpoint.local_addr().std_context("local addr")?;

        // create the client configuration used for the client endpoint when they
        // initiate a connection with the server
        let client_config = crate::tls::make_dangerous_client_config();
        let quic_client = QuicClient::new(client_endpoint.clone(), client_config)?;

        let (addr, _latency) = quic_client
            .get_addr_and_latency(quic_server.bind_addr(), &host.to_string())
            .await?;

        // wait until the endpoint delivers the closing message to the server
        client_endpoint.wait_idle().await;
        // shut down the quic server
        quic_server.shutdown().await;

        assert_eq!(client_addr, addr);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    #[traced_test]
    async fn test_qad_client_closes_unresponsive_fast() -> Result {
        // create a client-side endpoint
        let client_endpoint = noq::Endpoint::client(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .std_context("client")?;

        // create an socket that does not respond.
        let server_socket =
            tokio::net::UdpSocket::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
                .await
                .std_context("bind")?;
        let server_addr = server_socket.local_addr().std_context("local addr")?;

        // create the client configuration used for the client endpoint when they
        // initiate a connection with the server
        let client_config = crate::tls::make_dangerous_client_config();
        let quic_client = QuicClient::new(client_endpoint.clone(), client_config)?;

        // Start a connection attempt with nirvana - this will fail
        let task = AbortOnDropHandle::new(tokio::spawn({
            async move {
                quic_client
                    .get_addr_and_latency(server_addr, "localhost")
                    .await
            }
        }));

        // Even if we wait longer than the probe timeout, we will still be attempting to connect:
        tokio::time::sleep(Duration::from_millis(1000)).await;
        assert!(!task.is_finished());

        // time the closing of the client endpoint
        let before = Instant::now();
        client_endpoint.close(0u32.into(), b"byeeeee");
        client_endpoint.wait_idle().await;
        let time = Instant::now().duration_since(before);

        assert_eq!(time, Duration::from_millis(999));

        Ok(())
    }

    /// Makes sure that, even though the RTT was set to some fairly low value,
    /// we *do* try to connect for longer than what the time out would be after closing
    /// the connection, when we *don't* close the connection.
    ///
    /// In this case we don't simulate it via synthetically high RTT, but by dropping
    /// all packets on the server-side for 2 seconds.
    #[tokio::test]
    #[traced_test]
    async fn test_qad_connect_delayed() -> Result {
        // Create a socket for our QAD server.  We need the socket separately because we
        // need to pop off messages before we attach it to the Noq Endpoint.
        let socket = tokio::net::UdpSocket::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .std_context("bind")?;
        let server_addr = socket.local_addr().std_context("local addr")?;
        info!(addr = ?server_addr, "server socket bound");

        // Create a QAD server with a self-signed cert, all manually.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .std_context("self signed")?;
        let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
        let mut server_crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .std_context("crypto provider")?
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.into()], key.into())
        .std_context("tls")?;
        server_crypto.key_log = Arc::new(rustls::KeyLogFile::new());
        server_crypto.alpn_protocols = vec![ALPN_QUIC_ADDR_DISC.to_vec()];
        let mut server_config = noq::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_crypto).std_context("config")?,
        ));
        let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
        transport_config.send_observed_address_reports(true);

        let start = Instant::now();
        let server_task = tokio::spawn(
            async move {
                info!("Dropping all packets");
                time::timeout(Duration::from_secs(2), async {
                    let mut buf = [0u8; 1500];
                    loop {
                        let (len, src) = socket.recv_from(&mut buf).await.unwrap();
                        debug!(%len, ?src, "Dropped a packet");
                    }
                })
                .await
                .ok();
                info!("starting server");
                let server = noq::Endpoint::new(
                    Default::default(),
                    Some(server_config),
                    socket.into_std().unwrap(),
                    Arc::new(noq::TokioRuntime),
                )
                .std_context("endpoint new")?;
                info!("accepting conn");
                let incoming = server.accept().await.expect("missing conn");
                info!("incoming!");
                let conn = incoming.await.std_context("incoming")?;
                conn.closed().await;
                server.wait_idle().await;
                n0_error::Ok(())
            }
            .instrument(info_span!("server")),
        );
        let server_task = AbortOnDropHandle::new(server_task);

        info!("starting client");
        let client_endpoint = noq::Endpoint::client(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .std_context("client")?;

        // create the client configuration used for the client endpoint when they
        // initiate a connection with the server
        let client_config = crate::tls::make_dangerous_client_config();
        let quic_client = QuicClient::new(client_endpoint.clone(), client_config)?;

        // Now we should still connect, but it should take more than 1s.
        info!("making QAD request");
        let (addr, latency) = time::timeout(
            Duration::from_secs(10),
            quic_client.get_addr_and_latency(server_addr, "localhost"),
        )
        .await
        .std_context("timeout")??;
        let duration = start.elapsed();
        info!(?duration, ?addr, ?latency, "QAD succeeded");
        assert!(duration >= Duration::from_secs(1));

        time::timeout(Duration::from_secs(10), server_task)
            .await
            .std_context("timeout")?
            .std_context("server task")??;

        Ok(())
    }
}
