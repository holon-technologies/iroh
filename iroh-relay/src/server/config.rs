use derive_more::Debug;

use super::*;

/// Configuration for the full Relay.
///
/// Be aware the generic parameters are for when using the Let's Encrypt TLS configuration.
/// If not used dummy ones need to be provided, e.g. `ServerConfig::<(), ()>::default()`.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct ServerConfig {
    /// Configuration for the Relay server, disabled if `None`.
    pub relay: Option<RelayConfig>,
    /// Configuration for the QUIC server, disabled if `None`.
    pub quic: Option<QuicConfig>,
    /// Socket to serve metrics on.
    #[cfg(feature = "metrics")]
    pub metrics_addr: Option<SocketAddr>,
}

/// Configuration for the Relay HTTP and HTTPS server.
///
/// This includes the HTTP services hosted by the Relay server, the Relay `/relay` HTTP
/// endpoint is only one of the services served.
#[derive(Debug)]
#[non_exhaustive]
pub struct RelayConfig {
    /// The socket address on which the Relay HTTP server should bind.
    ///
    /// Normally you'd choose port `80`.  The bind address for the HTTPS server is
    /// configured in [`RelayConfig::tls`].
    ///
    /// If [`RelayConfig::tls`] is `None` then this serves all the HTTP services without
    /// TLS.
    pub http_bind_addr: SocketAddr,
    /// TLS configuration for the HTTPS server.
    ///
    /// If *None* all the HTTP services that would be served here are served from
    /// [`RelayConfig::http_bind_addr`].
    pub tls: Option<TlsConfig>,
    /// Rate limits.
    pub limits: Limits,
    /// Key cache capacity.
    pub key_cache_capacity: Option<usize>,
    /// Access control for incoming connections.
    pub access: Arc<dyn DynAccessControl>,
}

impl RelayConfig {
    /// Creates a new [`RelayConfig`] bound to `http_bind_addr` with default settings.
    ///
    /// TLS is disabled, default [`Limits`] are used, the key cache capacity is unset, and
    /// access defaults to [`AllowAll`]. Adjust any of these by assigning to the
    /// corresponding fields after construction.
    pub fn new(http_bind_addr: impl Into<SocketAddr>) -> Self {
        Self {
            http_bind_addr: http_bind_addr.into(),
            tls: None,
            limits: Limits::default(),
            key_cache_capacity: None,
            access: Arc::new(AllowAll),
        }
    }
}

/// A process-unique identifier for a single relay client connection.
///
/// A new id is assigned to every incoming connection when its [`ClientRequest`]
/// is created, before the access check runs. The same id is passed to
/// [`AccessControl::on_connect`] and [`AccessControl::on_disconnect`], so an
/// implementation can match the two callbacks even when one endpoint holds
/// several concurrent connections.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, derive_more::Display)]
#[display("{_0}")]
pub struct ConnectionId(u64);

impl ConnectionId {
    /// Returns a fresh, process-unique connection id.
    fn next() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

/// Details about an incoming relay client connection.
///
/// Passed to [`AccessControl::on_connect`] to decide whether to admit the connection.
#[derive(Debug, Clone)]
pub struct ClientRequest {
    connection_id: ConnectionId,
    endpoint_id: EndpointId,
    protocol_version: ProtocolVersion,
    request: http::request::Parts,
}

impl ClientRequest {
    /// Creates a new [`ClientRequest`] from an [`EndpointId`] and HTTP request parts.
    ///
    /// The [`EndpointId`] must be proven by the relay handshake. The request parts
    /// come from the client's WebSocket request. A fresh [`ConnectionId`] is assigned.
    pub fn new(
        endpoint_id: EndpointId,
        protocol_version: ProtocolVersion,
        request: http::request::Parts,
    ) -> Self {
        Self {
            connection_id: ConnectionId::next(),
            endpoint_id,
            protocol_version,
            request,
        }
    }

    /// Returns the [`ConnectionId`] assigned to this connection.
    pub fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Returns the [`ProtocolVersion`] negotiated for this connection.
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the [`EndpointId`] of the client.
    ///
    /// The relay handshake authenticates this id before the access hook
    /// is invoked. The client proves possession of the secret key for
    /// this public key by either signing keying material exported from
    /// the TLS session or a challenge issued by the server.
    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    /// Returns the URI of the HTTP request with which the client connected.
    pub fn uri(&self) -> &http::Uri {
        &self.request.uri
    }

    /// Returns an iterator over the query parameters set in the URI of the HTTP request.
    ///
    /// Each item is a `(name, value)` pair. Both names and values are percent-decoded.
    /// The query string is parsed in order, and the same name may appear more than once.
    pub fn query_pairs(&self) -> impl Iterator<Item = (Cow<'_, str>, Cow<'_, str>)> {
        url::form_urlencoded::parse(self.request.uri.query().unwrap_or("").as_bytes())
    }

    /// Returns the headers of the HTTP request with which the client connected.
    pub fn headers(&self) -> &http::HeaderMap {
        &self.request.headers
    }

    /// Returns the authorization token from the client's HTTP request, if any.
    ///
    /// Walks the `Authorization` headers in order and returns the value of
    /// the first one whose scheme is `Bearer` (matched case-insensitively).
    /// Headers with a different scheme are skipped.
    ///
    /// If none of the `Authorization` headers carries a `Bearer` scheme,
    /// returns the value of the `token` URL query parameter, or `None` if
    /// the URL has no `token` parameter.
    ///
    /// If an `Authorization` header value is not valid UTF-8 the function returns
    /// `None` immediately, without checking later headers or the URL query.
    pub fn auth_token(&self) -> Option<String> {
        for value in self.request.headers.get_all(AUTHORIZATION) {
            let value = value.to_str().ok()?;
            if let Some((scheme, token)) = value.split_once(' ')
                && scheme.eq_ignore_ascii_case("Bearer")
            {
                return Some(token.to_string());
            }
        }
        self.query_pairs()
            .find(|(name, _)| name == AUTH_TOKEN_URL_QUERY_PARAM)
            .map(|(_, value)| value.into_owned())
    }
}

/// Controls which endpoints may use the relay and observes their lifecycle.
///
/// Implement this trait to gate access to a relay server.
///
/// Both callbacks carry the connection's [`ConnectionId`], so an implementation
/// can index connections precisely even when one endpoint holds several.
pub trait AccessControl: std::fmt::Debug + Send + Sync + 'static {
    /// Decides whether a connecting client is admitted.
    ///
    /// Called once per incoming connection, before the connection is
    /// registered. Returns [`Access::Allow`] to admit it or [`Access::Deny`]
    /// to reject it.
    ///
    /// Can be implemented as `async fn on_connect(&self, request: &ClientRequest) -> Access`.
    fn on_connect(&self, request: &ClientRequest) -> impl Future<Output = Access> + Send;

    /// Notifies that a connection has ended.
    ///
    /// Called once for every connection that [`Self::on_connect`] admitted,
    /// identified by the same [`ConnectionId`].
    ///
    /// Note that this is a sync method being called in an async context. Make sure that your
    /// implementation does not block the runtime.
    fn on_disconnect(&self, endpoint_id: EndpointId, connection_id: ConnectionId) {
        let _ = (endpoint_id, connection_id);
    }
}

/// A dyn-compatible version of [`AccessControl`] that returns boxed futures.
///
/// Any type that implements [`AccessControl`] automatically implements
/// `DynAccessControl`. Wrap it in an `Arc` to store it as an
/// `Arc<dyn DynAccessControl>`, for example in [`RelayConfig::access`].
pub trait DynAccessControl: std::fmt::Debug + Send + Sync + 'static {
    /// See [`AccessControl::on_connect`].
    fn on_connect<'a>(
        &'a self,
        request: &'a ClientRequest,
    ) -> Pin<Box<dyn Future<Output = Access> + Send + 'a>>;

    /// See [`AccessControl::on_disconnect`].
    fn on_disconnect(&self, endpoint_id: EndpointId, connection_id: ConnectionId);
}

impl<T: AccessControl> DynAccessControl for T {
    fn on_connect<'a>(
        &'a self,
        request: &'a ClientRequest,
    ) -> Pin<Box<dyn Future<Output = Access> + Send + 'a>> {
        Box::pin(<Self as AccessControl>::on_connect(self, request))
    }

    fn on_disconnect(&self, endpoint_id: EndpointId, connection_id: ConnectionId) {
        <Self as AccessControl>::on_disconnect(self, endpoint_id, connection_id)
    }
}

/// An [`AccessControl`] that admits every endpoint.
///
/// This is the default used by [`RelayConfig::new`].
#[derive(Debug, Clone, Copy)]
pub struct AllowAll;

impl AccessControl for AllowAll {
    async fn on_connect(&self, _request: &ClientRequest) -> Access {
        Access::Allow
    }
}

/// Access restriction for an endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    /// Access is allowed.
    Allow,
    /// Access is denied.
    Deny {
        /// Optional reason for denial to send back to the client.
        reason: Option<String>,
    },
}

/// Reports a connection's disconnect to [`AccessControl`] when dropped.
///
/// A guard is created the moment [`AccessControl::on_connect`] admits a
/// connection, and is then held for the connection's entire lifetime. Dropping
/// it - whether the connection closed cleanly, hit an error, or setup returned
/// early - calls [`AccessControl::on_disconnect`] exactly once.
///
/// Threading the guard through connection setup and into the connection actor
/// makes it impossible to admit a connection without eventually reporting its
/// disconnect, even as the surrounding code changes.
///
/// Embedders that register connections through [`Clients::register`] construct
/// the guard themselves; see that method for the expected lifecycle.
///
/// [`Clients::register`]: crate::server::clients::Clients::register
#[derive(Debug)]
pub struct OnDisconnectGuard {
    access: Option<Arc<dyn DynAccessControl>>,
    endpoint_id: EndpointId,
    connection_id: ConnectionId,
}

impl OnDisconnectGuard {
    /// Creates a guard for the connection described by `request`.
    ///
    /// Dropping the guard calls [`AccessControl::on_disconnect`] on `access`
    /// with the request's [`EndpointId`] and [`ConnectionId`]. Create it only
    /// once [`AccessControl::on_connect`] has admitted the connection.
    pub fn for_access_control(access: Arc<dyn DynAccessControl>, request: &ClientRequest) -> Self {
        Self {
            access: Some(access),
            endpoint_id: request.endpoint_id(),
            connection_id: request.connection_id(),
        }
    }

    /// Creates a no-op guard for `endpoint_id`.
    ///
    /// The guard carries `endpoint_id` and a fresh [`ConnectionId`] but has no
    /// access control attached, so dropping it does nothing.
    pub fn empty(endpoint_id: EndpointId) -> Self {
        Self {
            access: None,
            endpoint_id,
            connection_id: ConnectionId::next(),
        }
    }

    /// Returns the [`EndpointId`] of the guarded connection.
    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    /// Returns the [`ConnectionId`] of the guarded connection.
    pub fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }
}

impl Drop for OnDisconnectGuard {
    fn drop(&mut self) {
        if let Some(access) = self.access.as_ref() {
            access.on_disconnect(self.endpoint_id, self.connection_id);
        }
    }
}

/// Configuration for the QUIC server.
#[derive(Debug)]
#[non_exhaustive]
pub struct QuicConfig {
    /// The socket address on which the QUIC server should bind.
    ///
    /// Normally you'd chose port `7842`, see [`crate::defaults::DEFAULT_RELAY_QUIC_PORT`].
    pub bind_addr: SocketAddr,
    /// The TLS server configuration for the QUIC server.
    ///
    /// If this [`rustls::ServerConfig`] does not support TLS 1.3, the QUIC server will fail
    /// to spawn.
    ///
    /// Will use the TLS config from [`RelayConfig::tls`] if unset. If neither is set the QUIC
    /// server will fail to spawn.
    pub server_config: Option<rustls::ServerConfig>,
    /// Maximum number of active QUIC address-discovery connections.
    pub max_connections: usize,
}

impl QuicConfig {
    /// Creates a new [`QuicConfig`] bound to `bind_addr`.
    ///
    /// The TLS server config is left unset and inherited from [`RelayConfig::tls`].
    pub fn new(bind_addr: impl Into<SocketAddr>) -> Self {
        Self {
            bind_addr: bind_addr.into(),
            server_config: None,
            max_connections: crate::quic::DEFAULT_MAX_QAD_CONNECTIONS,
        }
    }
}

/// TLS configuration for Relay server.
///
/// Normally the Relay server accepts connections on both HTTPS and HTTP.
#[derive(Debug)]
#[non_exhaustive]
pub struct TlsConfig {
    /// The socket address on which to serve the HTTPS server.
    ///
    /// Since the captive portal probe has to run over plain text HTTP and TLS is used for
    /// the main relay server this has to be on a different port.  When TLS is not enabled
    /// this is served on the [`RelayConfig::http_bind_addr`] socket address.
    ///
    /// Normally you'd choose port `443`.
    pub https_bind_addr: SocketAddr,
    /// Mode for getting a cert.
    pub cert: CertConfig,
}

impl TlsConfig {
    /// Creates a new [`TlsConfig`] with the given bind address and certificate configuration.
    pub fn new(https_bind_addr: impl Into<SocketAddr>, cert: CertConfig) -> Self {
        Self {
            https_bind_addr: https_bind_addr.into(),
            cert,
        }
    }
}

/// Per-client rate limit configuration.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClientRateLimit {
    /// Max number of bytes per second to read from the client connection.
    pub bytes_per_second: NonZeroU32,
    /// Max number of bytes to read in a single burst.
    pub max_burst_bytes: Option<NonZeroU32>,
}

impl ClientRateLimit {
    /// Creates a new [`ClientRateLimit`] with the given byte rate.
    ///
    /// `max_burst_bytes` is left unset; assign it after construction to allow bursting.
    pub fn new(bytes_per_second: NonZeroU32) -> Self {
        Self {
            bytes_per_second,
            max_burst_bytes: None,
        }
    }
}
