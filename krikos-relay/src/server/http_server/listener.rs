use derive_more::Debug;

use super::*;

/// The Relay HTTP server.
///
/// A running HTTP server serving the relay endpoint and optionally a number of additional
/// HTTP services added with [`ServerBuilder::request_handler`].  If configured using
/// [`ServerBuilder::tls_config`] the server will handle TLS as well.
///
/// Created using [`ServerBuilder::spawn`].
#[derive(Debug)]
pub(crate) struct Server {
    addr: SocketAddr,
    http_server_task: AbortOnDropHandle<()>,
    cancel_server_loop: CancellationToken,
    service: RelayService,
}

impl Server {
    /// Returns a handle for this server.
    ///
    /// The server runs in the background as several async tasks.  This allows controlling
    /// the server, in particular it allows gracefully shutting down the server.
    pub(crate) fn handle(&self) -> ServerHandle {
        ServerHandle {
            cancel_token: self.cancel_server_loop.clone(),
        }
    }

    /// Closes the underlying relay server and the HTTP(S) server tasks.
    pub(crate) fn shutdown(&self) {
        self.cancel_server_loop.cancel();
    }

    /// Returns the [`AbortOnDropHandle`] for the supervisor task managing the server.
    ///
    /// This is the root of all the tasks for the server.  Aborting it will abort all the
    /// other tasks for the server.  Awaiting it will complete when all the server tasks are
    /// completed.
    pub(crate) fn task_handle(&mut self) -> &mut AbortOnDropHandle<()> {
        &mut self.http_server_task
    }

    /// Returns the local address of this server.
    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Returns the [`RelayService`] driving this server.
    pub(crate) fn service(&self) -> &RelayService {
        &self.service
    }
}

/// A handle for the [`Server`].
///
/// This does not allow access to the task but can communicate with it.
#[derive(Debug, Clone)]
pub(crate) struct ServerHandle {
    cancel_token: CancellationToken,
}

impl ServerHandle {
    /// Gracefully shut down the server.
    pub(crate) fn shutdown(&self) {
        self.cancel_token.cancel()
    }
}

/// Configuration to use for the TLS connection
///
/// This struct wraps a rustls server configuration and TLS acceptor for use with
/// [`RelayService::handle_connection`].
///
/// # Example
///
/// ```
/// use std::sync::Arc;
///
/// use krikos_relay::server::http_server::TlsConfig;
/// use rustls::ServerConfig;
/// use webpki_types::{CertificateDer, PrivateKeyDer};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Set ring as the process-level default crypto provider
/// rustls::crypto::ring::default_provider()
///     .install_default()
///     .ok();
/// // Generate a self-signed certificate for testing
/// let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
/// let cert_der = cert.cert.der().to_vec();
/// let private_key_der = cert.signing_key.serialize_der();
///
/// // Create rustls types
/// let cert_chain = vec![CertificateDer::from(cert_der)];
/// let private_key = PrivateKeyDer::try_from(private_key_der)?;
///
/// // Create a rustls ServerConfig
/// let server_config = Arc::new(
///     ServerConfig::builder()
///         .with_no_client_auth()
///         .with_single_cert(cert_chain, private_key)?,
/// );
///
/// // Create TlsConfig for use with RelayService
/// let tls_config = TlsConfig::new(server_config);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// The server config
    pub(crate) config: Arc<rustls::ServerConfig>,
    /// The kind
    pub(crate) acceptor: TlsAcceptor,
}

impl TlsConfig {
    /// Creates a new `TlsConfig` from a rustls `ServerConfig`.
    ///
    /// This creates a manual TLS acceptor using the provided server configuration.
    /// The acceptor will handle TLS handshakes for incoming connections.
    ///
    /// # Example
    ///
    /// ```
    /// use std::sync::Arc;
    ///
    /// use krikos_relay::server::http_server::TlsConfig;
    /// use rustls::ServerConfig;
    /// use webpki_types::{CertificateDer, PrivateKeyDer};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // Set ring as the process-level default crypto provider
    /// rustls::crypto::ring::default_provider()
    ///     .install_default()
    ///     .ok();
    /// // Generate a self-signed certificate for testing
    /// let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    /// let cert_der = cert.cert.der().to_vec();
    /// let private_key_der = cert.signing_key.serialize_der();
    ///
    /// // Create rustls types
    /// let cert_chain = vec![CertificateDer::from(cert_der)];
    /// let private_key = PrivateKeyDer::try_from(private_key_der)?;
    ///
    /// let server_config = Arc::new(
    ///     ServerConfig::builder()
    ///         .with_no_client_auth()
    ///         .with_single_cert(cert_chain, private_key)?,
    /// );
    ///
    /// let tls_config = TlsConfig::new(server_config);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(config: Arc<rustls::ServerConfig>) -> Self {
        let acceptor = tokio_rustls::TlsAcceptor::from(config.clone());
        Self {
            config,
            acceptor: TlsAcceptor::Manual(acceptor),
        }
    }
}

/// Builder for the Relay HTTP Server.
///
/// Defaults to handling relay requests on the "/relay" (and "/derp" for backwards compatibility) endpoint.
/// Other HTTP endpoints can be added using [`ServerBuilder::request_handler`].
#[derive(derive_more::Debug)]
pub(crate) struct ServerBuilder {
    /// The ip + port combination for this server.
    addr: SocketAddr,
    /// Optional tls configuration/TlsAcceptor combination.
    ///
    /// When `None`, the server will serve HTTP, otherwise it will serve HTTPS.
    tls_config: Option<TlsConfig>,
    /// A map of request handlers to routes.
    ///
    /// Used when certain routes in your server should be made available at the same port as
    /// the relay server, and so must be handled along side requests to the relay endpoint.
    handlers: Handlers,
    /// Headers to use for HTTP responses.
    headers: HeaderMap,
    /// Rate-limiting configuration for an individual client connection.
    ///
    /// Rate-limiting is enforced on received traffic from individual clients.  This
    /// configuration applies to a single client connection.
    client_rx_ratelimit: Option<ClientRateLimit>,
    /// The capacity of the key cache.
    key_cache_capacity: usize,
    /// Access control for endpoints.
    access: Arc<dyn DynAccessControl>,
    metrics: Option<Arc<Metrics>>,
    establish_timeout: Duration,
    admission_policy: Option<AdmissionPolicy>,
}

impl ServerBuilder {
    /// Creates a new [ServerBuilder].
    pub(crate) fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            tls_config: None,
            handlers: Default::default(),
            headers: HeaderMap::new(),
            client_rx_ratelimit: None,
            key_cache_capacity: DEFAULT_KEY_CACHE_CAPACITY,
            access: Arc::new(AllowAll),
            metrics: None,
            establish_timeout: ESTABLISH_TIMEOUT,
            admission_policy: None,
        }
    }

    /// Sets the validated connection and session admission policy.
    pub(crate) fn admission_policy(mut self, policy: AdmissionPolicy) -> Self {
        self.admission_policy = Some(policy);
        self
    }

    /// Sets the metrics collector.
    pub(crate) fn metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Set the access control.
    pub(crate) fn access(mut self, access: Arc<dyn DynAccessControl>) -> Self {
        self.access = access;
        self
    }

    /// Serves all requests content using TLS.
    pub(crate) fn tls_config(mut self, config: Option<TlsConfig>) -> Self {
        self.tls_config = config;
        self
    }

    /// Sets the timeout after which connections are aborted if they don't become fully established.
    ///
    /// The timeout is started immediately after a TCP connection comes in, and cleared once
    /// the connection has finished the TLS handshake and fully processed the WebSocket request
    /// to initiate the relay protocol. If the timeout expires before being cleared, the
    /// connection is aborted.
    ///
    /// Defaults to 30s.
    #[cfg(test)]
    pub(crate) fn establish_timeout(mut self, timeout: Duration) -> Self {
        self.establish_timeout = timeout;
        self
    }

    /// Sets the per-client rate-limit configuration for incoming data.
    ///
    /// On each client connection the incoming data is rate-limited.  By default
    /// no rate limit is enforced.
    pub(crate) fn client_rx_ratelimit(mut self, config: ClientRateLimit) -> Self {
        self.client_rx_ratelimit = Some(config);
        self
    }

    /// Adds a custom handler for a specific Method & URI.
    pub(crate) fn request_handler(
        mut self,
        method: Method,
        uri_path: &'static str,
        handler: HyperHandler,
    ) -> Self {
        self.handlers.insert((method, uri_path), handler);
        self
    }

    /// Adds HTTP headers to responses.
    pub(crate) fn headers(mut self, headers: HeaderMap) -> Self {
        for (k, v) in headers.iter() {
            self.headers.insert(k.clone(), v.clone());
        }
        self
    }

    /// Set the capacity of the cache for public keys.
    pub(crate) fn key_cache_capacity(mut self, capacity: usize) -> Self {
        self.key_cache_capacity = capacity;
        self
    }

    /// Builds and spawns an HTTP(S) Relay Server.
    pub(crate) async fn spawn(self) -> Result<Server, SpawnError> {
        let cancel_token = CancellationToken::new();
        let admission = Arc::new(AdmissionControl::new(
            self.admission_policy.unwrap_or_default(),
        ));

        let service = RelayService::new_with_admission(
            self.handlers,
            self.headers,
            self.client_rx_ratelimit,
            KeyCache::new(self.key_cache_capacity),
            self.access,
            self.metrics.unwrap_or_default(),
            admission.clone(),
        );

        let addr = self.addr;
        let tls_config = self.tls_config;

        // Bind a TCP listener on `addr` and handles content using HTTPS.

        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|err| e!(super::SpawnError::BindTcpListener { addr }, err))?;

        let addr = listener
            .local_addr()
            .map_err(|err| e!(super::SpawnError::NoLocalAddr, err))?;
        let http_str = tls_config.as_ref().map_or("HTTP/WS", |_| "HTTPS/WSS");
        info!("[{http_str}] relay: serving on {addr}");

        let cancel = cancel_token.clone();
        let loop_service = service.clone();
        let task = tokio::task::spawn(
            async move {
                let service = loop_service;
                // create a join set to track all our connection tasks
                let mut set = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        biased;
                        _ = cancel.cancelled() => {
                            break;
                        }
                        Some(res) = set.join_next() => {
                            if let Err(err) = res
                                && err.is_panic()
                            {
                                panic!("task panicked: {err:#?}");
                            }
                        }
                        res = listener.accept() => match res {
                            Ok((stream, peer_addr)) => {
                                match admission.try_establishment() {
                                    EstablishmentAdmission::Accepted(lease) => {
                                        debug!("connection opened from {peer_addr}");
                                        let tls_config = tls_config.clone();
                                        let service = service.clone();
                                        // The task owns the establishment lease until the relay
                                        // session registers or the connection terminates.
                                        set.spawn(async move {
                                            service
                                                .handle_connection_with_lease(
                                                    stream,
                                                    tls_config,
                                                    self.establish_timeout,
                                                    lease,
                                                )
                                                .await
                                        }.instrument(info_span!("conn", peer = %peer_addr)));
                                    }
                                    EstablishmentAdmission::RateLimited => {
                                        service.0.metrics.admission_rate_limited.inc();
                                        debug!(%peer_addr, "rejecting rate-limited connection");
                                    }
                                    EstablishmentAdmission::PendingCapacityFull => {
                                        service.0.metrics.admission_pending_full.inc();
                                        debug!(%peer_addr, "rejecting connection: pending capacity full");
                                    }
                                }
                            }
                            Err(err) => {
                                error!("failed to accept connection: {err}");
                            }
                        }
                    }
                }
                service.shutdown().await;
                set.shutdown().await;
                debug!("server has been shutdown.");
            }
            .instrument(info_span!("relay-http-serve")),
        );

        Ok(Server {
            addr,
            http_server_task: AbortOnDropHandle::new(task),
            cancel_server_loop: cancel_token,
            service,
        })
    }
}
