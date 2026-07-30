use derive_more::Debug;

use super::*;

/// The hyper Service that serves the actual relay endpoints.
///
/// This service can be used standalone or embedded into an existing HTTP server.
#[derive(Clone, Debug)]
pub struct RelayService(pub(super) Arc<Inner>);

#[derive(Debug)]
pub(super) struct Inner {
    handlers: Handlers,
    pub(super) headers: HeaderMap,
    clients: Clients,
    write_timeout: Duration,
    rate_limit: watch::Sender<Option<ClientRateLimit>>,
    key_cache: KeyCache,
    access: Arc<dyn DynAccessControl>,
    pub(super) metrics: Arc<Metrics>,
}

/// Combines [`RelayService`] with a notification token.
///
/// This struct implements [`Service`]. Note that the service has to be called with hyper's `io`
/// argument set to [`MaybeTlsStream`] wrapped by [`hyper_util::rt::TokioIo`], otherwise handling
/// WebSocket requests at `/relay` will fail at runtime with [`ConnectionHandlerError::DowncastUpgrade`].
///
/// The notification token is triggered once the relay connection is fully established. It can be used
/// to cancel a timeout aborting the TCP connection if no upgrade request is received in some time.
///
/// ## Example
///
/// ```no_run
/// # use std::sync::Arc;
/// # use http::HeaderMap;
/// # use hyper::server::conn::http1;
/// # use hyper_util::rt::TokioIo;
/// # use tokio::{net::TcpListener, sync::Notify};
/// # use krikos_relay::{
/// #     KeyCache,
/// #     server::{
/// #         AllowAll, Metrics,
/// #         http_server::{Handlers, RelayService, RelayServiceWithNotify},
/// #         streams::MaybeTlsStream
/// #     },
/// # };
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let service = RelayService::new(
///     Handlers::default(),
///     HeaderMap::new(),
///     None,
///     KeyCache::new(1024),
///     Arc::new(AllowAll),
///     Arc::new(Metrics::default()),
/// );
/// let service = RelayServiceWithNotify::new(service, Arc::new(Notify::new()));
///
/// let listener = TcpListener::bind("127.0.0.1:0").await?;
/// let (stream, _peer) = listener.accept().await?;
/// // Wrap the TCP stream in `MaybeTlsStream`, otherwise the relay WebSocket handler will error at runtime
/// // for all WebSocket requests to `/relay`.
/// let stream = MaybeTlsStream::Plain(stream);
/// http1::Builder::new()
///     .serve_connection(TokioIo::new(stream), service)
///     .with_upgrades()
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct RelayServiceWithNotify {
    pub(super) service: RelayService,
    pub(super) on_establish: Arc<Notify>,
    pub(super) establishment_lease: Arc<Mutex<Option<EstablishmentLease>>>,
}

impl RelayServiceWithNotify {
    /// Creates a new service wrapper for a connection.
    ///
    /// The `on_establish` notification is triggered once the connection is passed to the
    /// relay protocol, i.e. after a WebSocket request on /relay is received and established.
    pub fn new(service: RelayService, on_establish: Arc<Notify>) -> Self {
        Self {
            service,
            on_establish,
            establishment_lease: Arc::new(Mutex::new(None)),
        }
    }

    fn new_with_establishment_lease(
        service: RelayService,
        on_establish: Arc<Notify>,
        establishment_lease: Arc<Mutex<Option<EstablishmentLease>>>,
    ) -> Self {
        Self {
            service,
            on_establish,
            establishment_lease,
        }
    }
}

impl Service<Request<Incoming>> for RelayServiceWithNotify {
    type Response = Response<BytesBody>;
    type Error = HyperError;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        // Create a client if the request hits the relay endpoint.
        if matches!(
            (req.method(), req.uri().path()),
            (&hyper::Method::GET, RELAY_PATH)
        ) {
            let response = match self.handle_relay_ws_upgrade(req) {
                Ok(response) => Ok(response),
                // It's convention to send back the version(s) we *do* support
                Err(e @ RelayUpgradeReqError::UnsupportedWebsocketVersion { .. }) => self
                    .build_response()
                    .status(StatusCode::BAD_REQUEST)
                    .header(SEC_WEBSOCKET_VERSION, SUPPORTED_WEBSOCKET_VERSION)
                    .body(body_full(e.to_string())),
                Err(e) => self
                    .build_response()
                    .status(StatusCode::BAD_REQUEST)
                    .body(body_full(e.to_string())),
            }
            .map_err(Into::into);
            return std::future::ready(response);
        }
        // Otherwise handle the relay connection as normal.

        // Check all other possible endpoints.
        let uri = req.uri().clone();
        if let Some(handler) = self
            .service
            .0
            .handlers
            .get(&(req.method().clone(), uri.path()))
        {
            let response = handler(req, self.service.0.default_response());
            return std::future::ready(response);
        }

        // Otherwise return 404
        let response = self
            .service
            .0
            .not_found_fn(req, self.service.0.default_response());
        std::future::ready(response)
    }
}

impl Inner {
    fn default_response(&self) -> ResponseBuilder {
        let mut response = Response::builder();
        for (key, value) in self.headers.iter() {
            response = response.header(key.clone(), value.clone());
        }
        response
    }

    fn not_found_fn(
        &self,
        _req: Request<Incoming>,
        mut res: ResponseBuilder,
    ) -> HyperResult<Response<BytesBody>> {
        for (k, v) in self.headers.iter() {
            res = res.header(k.clone(), v.clone());
        }
        let body = body_full("Not Found");
        let r = res.status(StatusCode::NOT_FOUND).body(body)?;
        HyperResult::Ok(r)
    }

    /// The server HTTP handler to do HTTP upgrades.
    ///
    /// This handler runs while doing the connection upgrade handshake.  Once the connection
    /// is upgraded it sends the stream to the relay server which takes it over.  After
    /// having sent off the connection this handler returns.
    pub(super) async fn relay_connection_handler(
        &self,
        upgraded: Upgraded,
        request_parts: http::request::Parts,
        protocol_version: ProtocolVersion,
    ) -> Result<(), ConnectionHandlerError> {
        debug!("relay_connection upgraded");
        let (io, read_buf) = downcast_upgrade(upgraded)?;
        if !read_buf.is_empty() {
            return Err(e!(ConnectionHandlerError::BufferNotEmpty { buf: read_buf }));
        }

        self.accept(io, request_parts, protocol_version).await?;
        Ok(())
    }

    /// Adds a new connection to the server and serves it.
    ///
    /// Will error if it takes too long (10 sec) to write or read to the connection, if there is
    /// some read or write error to the connection,  if the server is meant to verify clients,
    /// and is unable to verify this one, or if there is some issue communicating with the server.
    ///
    /// The provided [`AsyncRead`] and [`AsyncWrite`] must be already connected to the connection.
    ///
    /// [`AsyncRead`]: tokio::io::AsyncRead
    /// [`AsyncWrite`]: tokio::io::AsyncWrite
    pub(super) async fn accept(
        &self,
        io: MaybeTlsStream,
        request_parts: http::request::Parts,
        protocol_version: ProtocolVersion,
    ) -> Result<(), AcceptError> {
        trace!("accept: start");

        // Set the socket to NO_DELAY.
        io.disable_nagle();

        let io = RateLimited::from_watcher(io, self.rate_limit.subscribe(), self.metrics.clone())
            .map_err(|err| e!(AcceptError::RateLimitingMisconfigured, err))?;

        // Create a server builder with default config
        let websocket = tokio_websockets::ServerBuilder::new()
            .limits(tokio_websockets::Limits::default().max_payload_len(Some(MAX_FRAME_SIZE)))
            // Serve will create a WebSocketStream on an already upgraded connection
            .serve(io);

        let io = WsBytesFramed { io: websocket };

        self.accept_framed(io, request_parts, protocol_version)
            .await
    }

    /// Authenticates, authorizes, and registers one transport-independent relay session.
    async fn accept_framed<S>(
        &self,
        mut io: S,
        request_parts: http::request::Parts,
        protocol_version: ProtocolVersion,
    ) -> Result<(), AcceptError>
    where
        S: BytesStreamSink + crate::ExportKeyingMaterial + Send + 'static,
    {
        let client_auth_header = request_parts.headers.get(CLIENT_AUTH_HEADER).cloned();
        let challenge = self.clients.next_auth_challenge();
        let authentication =
            handshake::serverside_with_challenge(&mut io, client_auth_header, challenge).await?;

        trace!(?authentication.mechanism, "accept: verified authentication");

        let request =
            ClientRequest::new(authentication.client_key, protocol_version, request_parts);

        // Authorize the request against the configured `AccessControl`.
        let guard = authentication
            .authorize_with(&request, &self.access, &mut io)
            .await?;

        trace!("accept: verified authorization");

        let io = RelayedStream::new(io, self.key_cache.clone());

        trace!("accept: build client conn");
        let mut client_conn_builder = Config::new(guard, io, protocol_version);
        client_conn_builder.write_timeout = self.write_timeout;
        trace!(endpoint_id = %request.endpoint_id().fmt_short(), "create client");

        // build and register client, starting up read & write loops for the client
        // connection
        match self
            .clients
            .register(client_conn_builder, self.metrics.clone())
        {
            Ok(()) => {}
            Err(RegisterError::GlobalSessionFull { .. }) => {
                return Err(e!(AcceptError::GlobalSessionFull));
            }
            Err(RegisterError::EndpointSessionFull { .. }) => {
                return Err(e!(AcceptError::EndpointSessionFull));
            }
            Err(RegisterError::Runtime { source, .. }) => {
                return Err(e!(AcceptError::Runtime, source));
            }
        }
        Ok(())
    }
}

/// TLS Certificate Authority acceptor.
#[derive(Clone, derive_more::Debug)]
pub(crate) enum TlsAcceptor {
    /// Uses Let's Encrypt as the Certificate Authority. This is used in production.
    #[cfg(feature = "server-acme")]
    LetsEncrypt {
        #[debug("rustls::ServerConfig")]
        challenge_config: Arc<rustls::ServerConfig>,
    },
    /// Manually added tls acceptor. Generally used for tests or for when we've passed in
    /// a certificate via a file.
    Manual(#[debug("tokio_rustls::TlsAcceptor")] tokio_rustls::TlsAcceptor),
}

impl RelayService {
    /// Creates a new RelayService.
    ///
    /// This allows embedding the relay service into an existing HTTP server.
    pub fn new(
        handlers: Handlers,
        headers: HeaderMap,
        rate_limit: Option<ClientRateLimit>,
        key_cache: KeyCache,
        access: Arc<dyn DynAccessControl>,
        metrics: Arc<Metrics>,
    ) -> Self {
        let admission = Arc::new(AdmissionControl::new(AdmissionPolicy::default()));
        Self::new_with_admission(
            handlers, headers, rate_limit, key_cache, access, metrics, admission,
        )
    }

    pub(super) fn new_with_admission(
        handlers: Handlers,
        headers: HeaderMap,
        rate_limit: Option<ClientRateLimit>,
        key_cache: KeyCache,
        access: Arc<dyn DynAccessControl>,
        metrics: Arc<Metrics>,
        admission: Arc<AdmissionControl>,
    ) -> Self {
        Self::from_clients(
            handlers,
            headers,
            rate_limit,
            key_cache,
            access,
            metrics,
            Clients::with_admission(admission),
        )
    }

    /// Creates a relay service whose per-client actors use an explicitly owned runtime.
    #[doc(hidden)]
    #[cfg(feature = "test-utils")]
    pub fn new_with_runtime(
        handlers: Handlers,
        headers: HeaderMap,
        rate_limit: Option<ClientRateLimit>,
        key_cache: KeyCache,
        access: Arc<dyn DynAccessControl>,
        metrics: Arc<Metrics>,
        runtime: RelayServiceRuntime,
    ) -> Result<Self, krikos_runtime::DecisionError> {
        let clients = Clients::with_runtime(runtime.context, &runtime.decision_path)?;
        Ok(Self::from_clients(
            handlers, headers, rate_limit, key_cache, access, metrics, clients,
        ))
    }

    fn from_clients(
        handlers: Handlers,
        headers: HeaderMap,
        rate_limit: Option<ClientRateLimit>,
        key_cache: KeyCache,
        access: Arc<dyn DynAccessControl>,
        metrics: Arc<Metrics>,
        clients: Clients,
    ) -> Self {
        Self(Arc::new(Inner {
            handlers,
            headers,
            clients,
            write_timeout: SERVER_WRITE_TIMEOUT,
            rate_limit: watch::Sender::new(rate_limit),
            key_cache,
            access,
            metrics,
        }))
    }

    /// Updates the per-client receive rate limit.
    ///
    /// The new rate limit will be applied to all current and future client connections.
    /// Passing `None` will remove rate limiting from all connections.
    pub fn set_client_rate_limit(&self, rate_limit: Option<ClientRateLimit>) {
        self.0.rate_limit.send_replace(rate_limit);
    }

    /// Shuts down the relay service, disconnecting all clients.
    pub async fn shutdown(&self) {
        self.0.clients.shutdown().await;
    }

    /// Opens one production relay client/server session over an in-memory byte pipe.
    ///
    /// DNS, TCP, TLS, and HTTP upgrade mechanics are bypassed. The normal WebSocket framing,
    /// challenge authentication, authorization, server client actor, registry, and routing code
    /// remain in the call path. This API is reserved for repository simulation infrastructure.
    #[doc(hidden)]
    #[cfg(feature = "test-utils")]
    pub async fn connect_in_memory(
        &self,
        builder: &crate::client::ClientBuilder,
        protocol_version: ProtocolVersion,
        byte_capacity: usize,
    ) -> Result<crate::client::Client, InMemoryConnectError> {
        let request_parts = builder
            .in_memory_request_parts()
            .map_err(|error| e!(InMemoryConnectError::Client, error))?;
        let (client_io, server_io) = tokio::io::duplex(byte_capacity.max(1));
        let server_io = RateLimited::from_watcher(
            MaybeTlsStream::Test(server_io),
            self.0.rate_limit.subscribe(),
            self.0.metrics.clone(),
        )
        .map_err(|error| e!(AcceptError::RateLimitingMisconfigured, error))
        .map_err(|error| e!(InMemoryConnectError::Server, error))?;
        let websocket = tokio_websockets::ServerBuilder::new()
            .limits(tokio_websockets::Limits::default().max_payload_len(Some(MAX_FRAME_SIZE)))
            .serve(server_io);
        let framed = WsBytesFramed { io: websocket };
        let server = async {
            self.0
                .accept_framed(framed, request_parts, protocol_version)
                .await
                .map_err(|error| e!(InMemoryConnectError::Server, error))
        };
        let client = async {
            builder
                .connect_in_memory(client_io, protocol_version)
                .await
                .map_err(|error| e!(InMemoryConnectError::Client, error))
        };
        let ((), client) = tokio::try_join!(server, client)?;
        Ok(client)
    }

    /// Returns a reference to the registry of currently connected clients.
    ///
    /// The returned [`Clients`] handle can be used at runtime to disconnect a
    /// connected endpoint via [`Clients::disconnect`].
    pub fn clients(&self) -> &Clients {
        &self.0.clients
    }

    /// Handle the incoming connection.
    ///
    /// If a `tls_config` is given, will serve the connection using HTTPS, otherwise HTTP.
    ///
    /// If the connection did not fully upgrade to a relay WebSocket connection after
    /// `establish_timeout`, the connection is aborted.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::{sync::Arc, time::Duration};
    /// # use tokio::net::TcpStream;
    /// # use http::HeaderMap;
    /// # use krikos_relay::server::http_server::{Handlers, RelayService, TlsConfig};
    /// # use krikos_relay::{KeyCache, server::{AllowAll, Metrics}};
    /// # use webpki_types::{CertificateDer, PrivateKeyDer};
    /// # async fn example(stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    /// // Create a relay service
    /// let handlers = Handlers::default();
    /// let headers = HeaderMap::new();
    /// let key_cache = KeyCache::new(1024);
    /// let metrics = Arc::new(Metrics::default());
    /// let relay_service = RelayService::new(
    ///     handlers,
    ///     headers,
    ///     None, // No rate limiting
    ///     key_cache,
    ///     Arc::new(AllowAll),
    ///     metrics,
    /// );
    ///
    /// // Generate a self-signed certificate for HTTPS
    /// let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    /// let cert_der = cert.cert.der().to_vec();
    /// let private_key_der = cert.signing_key.serialize_der();
    /// let cert_chain = vec![CertificateDer::from(cert_der)];
    /// let private_key = PrivateKeyDer::try_from(private_key_der)?;
    ///
    /// // Serve with HTTPS
    /// let server_config = Arc::new(
    ///     rustls::ServerConfig::builder()
    ///         .with_no_client_auth()
    ///         .with_single_cert(cert_chain, private_key)?,
    /// );
    /// let tls_config = TlsConfig::new(server_config);
    /// relay_service
    ///     .clone()
    ///     .handle_connection(stream, Some(tls_config), Duration::from_secs(30))
    ///     .await;
    ///
    /// // Or serve with plain HTTP
    /// # let stream = TcpStream::connect("127.0.0.1:0").await?;
    /// relay_service
    ///     .handle_connection(stream, None, Duration::from_secs(30))
    ///     .await;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn handle_connection(
        self,
        stream: TcpStream,
        tls_config: Option<TlsConfig>,
        establish_timeout: Duration,
    ) {
        self.handle_connection_inner(stream, tls_config, establish_timeout, None)
            .await;
    }

    pub(super) async fn handle_connection_with_lease(
        self,
        stream: TcpStream,
        tls_config: Option<TlsConfig>,
        establish_timeout: Duration,
        lease: EstablishmentLease,
    ) {
        self.handle_connection_inner(stream, tls_config, establish_timeout, Some(lease))
            .await;
    }

    async fn handle_connection_inner(
        self,
        stream: TcpStream,
        tls_config: Option<TlsConfig>,
        establish_timeout: Duration,
        establishment_lease: Option<EstablishmentLease>,
    ) {
        let metrics = self.0.metrics.clone();
        metrics.http_connections.inc();
        // We create a notification token to be triggered once the connection is fully established
        // and passed to the relay server.
        let on_establish = Arc::new(Notify::new());
        let establishment_lease = Arc::new(Mutex::new(establishment_lease));
        let service = RelayServiceWithNotify::new_with_establishment_lease(
            self,
            on_establish.clone(),
            establishment_lease.clone(),
        );

        // This is the main connection future, driving the connection to completion.
        let serve_fut = async move {
            match tls_config {
                Some(tls_config) => {
                    debug!("HTTPS: serve connection");
                    service.tls_serve_connection(stream, tls_config).await
                }
                None => {
                    debug!("HTTP: serve connection");
                    let stream = MaybeTlsStream::Plain(stream);
                    service.serve_connection(stream).await
                }
            }
        };

        // We set a timeout for the connection to limit lingering connections during establishment.
        // The timeout is cleared once the connection has completed the TLS and WebSocket
        // handshakes and has been passed over to the relay protocol handler.
        // If the timeout expires before that happens, the connection is aborted.
        let res = clearable_timeout(
            establish_timeout,
            on_establish,
            establishment_lease,
            serve_fut,
        )
        .await
        .map_err(|_elapsed| e!(ServeConnectionError::EstablishTimeout))
        .flatten();

        metrics.http_connections_closed.inc();

        if let Err(error) = res {
            match error {
                ServeConnectionError::ManualAccept { source, .. }
                    if source.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    debug!(reason=?source, "peer disconnected");
                }
                #[cfg(feature = "server-acme")]
                ServeConnectionError::LetsEncryptAccept { source, .. }
                    if source.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    debug!(reason=?source, "peer disconnected");
                }
                // From hyper: <https://github.com/hyperium/hyper/commit/271bba16672ff54a44e043c5cc1ae6b9345bb172>
                // `hyper::Error::IncompleteMessage` is hyper's equivalent of UnexpectedEof
                ServeConnectionError::Https { source, .. }
                | ServeConnectionError::Http { source, .. }
                    if source.is_incomplete_message() =>
                {
                    debug!(reason=?source, "peer disconnected");
                }
                _ => {
                    metrics.http_connections_errored.inc();
                    error!(?error, "failed to handle connection");
                }
            }
        }
    }
}

/// Run-owned runtime inputs for an in-memory relay service.
#[doc(hidden)]
#[cfg(feature = "test-utils")]
#[derive(Clone, Debug)]
pub struct RelayServiceRuntime {
    context: Arc<krikos_runtime::RuntimeContext>,
    decision_path: String,
}

#[cfg(feature = "test-utils")]
impl RelayServiceRuntime {
    /// Creates runtime inputs with a domain-separated relay decision path.
    pub fn new(
        context: Arc<krikos_runtime::RuntimeContext>,
        decision_path: impl Into<String>,
    ) -> Self {
        Self {
            context,
            decision_path: decision_path.into(),
        }
    }
}

impl RelayServiceWithNotify {
    /// Serves a TLS connection.
    async fn tls_serve_connection(
        self,
        stream: TcpStream,
        tls_config: TlsConfig,
    ) -> Result<(), ServeConnectionError> {
        let TlsConfig { acceptor, config } = tls_config;
        #[cfg(not(feature = "server-acme"))]
        let _ = config;
        let stream = match acceptor {
            #[cfg(feature = "server-acme")]
            TlsAcceptor::LetsEncrypt { challenge_config } => {
                let start_handshake =
                    tokio_rustls::LazyConfigAcceptor::new(Default::default(), stream)
                        .await
                        .map_err(|err| e!(ServeConnectionError::LetsEncryptAccept, err))?;
                if tokio_rustls_acme::is_tls_alpn_challenge(&start_handshake.client_hello()) {
                    info!("TLS[acme]: received TLS-ALPN-01 validation request");
                    start_handshake
                        .into_stream(challenge_config)
                        .await
                        .map_err(|err| e!(ServeConnectionError::TlsHandshake, err))?;
                    return Ok(());
                }
                debug!("TLS[acme]: start handshake");
                let tls_stream = start_handshake
                    .into_stream(config)
                    .await
                    .map_err(|err| e!(ServeConnectionError::TlsHandshake, err))?;
                MaybeTlsStream::Tls(tls_stream)
            }
            TlsAcceptor::Manual(a) => {
                debug!("TLS[manual]: accept");
                let tls_stream = a
                    .accept(stream)
                    .await
                    .map_err(|err| e!(ServeConnectionError::ManualAccept, err))?;
                MaybeTlsStream::Tls(tls_stream)
            }
        };
        self.serve_connection(stream).await
    }

    /// Wrapper for the actual http connection (with upgrades)
    async fn serve_connection(self, io: MaybeTlsStream) -> Result<(), ServeConnectionError> {
        hyper::server::conn::http1::Builder::new()
            .serve_connection(hyper_util::rt::TokioIo::new(io), self)
            .with_upgrades()
            .await
            .map_err(|err| e!(ServeConnectionError::ServeConnection, err))
    }
}

/// A collection of HTTP request handlers for custom endpoints.
#[derive(Default)]
pub struct Handlers(HashMap<(Method, &'static str), HyperHandler>);

impl std::fmt::Debug for Handlers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.0.keys().fold(String::new(), |curr, next| {
            let (method, uri) = next;
            format!("{curr}\n({method},{uri}): Box<Fn(ResponseBuilder) -> Result<Response<Body>> + Send + Sync + 'static>")
        });
        write!(f, "HashMap<{s}>")
    }
}

impl std::ops::Deref for Handlers {
    type Target = HashMap<(Method, &'static str), HyperHandler>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Handlers {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
