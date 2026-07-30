use super::*;

/// Contains options for `Socket::listen`.
#[derive(derive_more::Debug)]
pub(crate) struct Options {
    /// The configuration for the different transports.
    pub(crate) transports: Vec<TransportConfig>,

    /// Secret key for this endpoint.
    pub(crate) secret_key: SecretKey,

    /// Optional user-defined Address Lookup data.
    pub(crate) address_lookup_user_data: Option<UserData>,

    /// A DNS resolver to use for resolving relay URLs.
    ///
    /// You can use [`crate::dns::DnsResolver::new`] for a resolver
    /// that uses the system's DNS configuration.
    #[cfg(not(wasm_browser))]
    pub(crate) dns_resolver: DnsResolver,

    /// Coherent runtime capabilities explicitly selected by the endpoint builder.
    #[cfg(not(wasm_browser))]
    pub(crate) runtime_context: Arc<krikos_runtime::RuntimeContext>,
    #[cfg(not(wasm_browser))]
    pub(crate) ip_socket_factory: Arc<dyn crate::simulation::IpSocketFactory>,
    #[cfg(not(wasm_browser))]
    pub(crate) network_monitor: Option<Arc<dyn crate::simulation::NetworkMonitor>>,
    #[cfg(not(wasm_browser))]
    pub(crate) simulation_port_mapper: Option<Arc<dyn crate::simulation::PortMapper>>,
    #[cfg(not(wasm_browser))]
    pub(crate) simulation_relay_connector: Option<Arc<dyn crate::simulation::RelayConnector>>,
    #[cfg(not(wasm_browser))]
    pub(crate) simulation_preferred_relay: Option<RelayUrl>,
    #[cfg(not(wasm_browser))]
    pub(crate) simulation_reset_key: Option<[u8; 32]>,

    /// Proxy configuration.
    pub(crate) proxy_url: Option<Url>,

    /// TLS configuration for HTTPS and non-krikos-QUIC connections.
    pub(crate) tls_config: rustls::ClientConfig,

    /// ServerConfig for the internal QUIC endpoint
    pub(crate) server_config: noq_proto::ServerConfig,

    pub(crate) metrics: EndpointMetrics,
    pub(crate) hooks: EndpointHooksList,
    pub(crate) path_selector: Arc<dyn PathSelector>,
    pub(crate) portmapper_config: portmapper::PortmapperConfig,
    pub(crate) net_report_config: crate::net_report::NetReportConfig,

    /// Static configuration for the endpoint.
    pub(crate) static_config: StaticConfig,

    /// Explicitly configured external addresses to advertise.
    pub(crate) configured_addrs: BTreeSet<SocketAddr>,

    /// Finite task, connection, and actor capacities for this endpoint.
    pub(crate) limits: crate::endpoint::EndpointLimits,
}

/// Configuration for a [`noq::Endpoint`] that cannot be changed at runtime.
#[derive(derive_more::Debug)]
pub(crate) struct StaticConfig {
    pub(crate) tls_config: tls::TlsConfig,
    #[debug("QuicServerConifg")]
    pub(crate) server_config: QuicServerConfig,
    #[debug("QuicClientConfig")]
    pub(crate) client_config: QuicClientConfig,
    #[debug("Arc<RustlsTokenKey>")]
    pub(crate) token_key: Arc<RustlsTokenKey>,
    #[debug("Arc<dyn TokenStore>")]
    pub(crate) token_store: Arc<dyn TokenStore>,
    pub(crate) transport_config: QuicTransportConfig,
    pub(crate) limits: crate::endpoint::EndpointLimits,
    #[cfg(not(wasm_browser))]
    pub(crate) runtime_context: Arc<krikos_runtime::RuntimeContext>,
    #[cfg(not(wasm_browser))]
    #[debug("Option<simulation initial DCID provider>")]
    pub(crate) simulation_initial_dst_cid_provider:
        Option<Arc<dyn Fn() -> noq::ConnectionId + Send + Sync>>,
}

impl StaticConfig {
    /// Create a [`noq_proto::ServerConfig`] with the specified ALPN protocols.
    pub(crate) fn create_server_config(
        &self,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> noq_proto::ServerConfig {
        let mut quic_server_config = self.server_config.clone();
        quic_server_config.set_alpn_protocols(alpn_protocols);
        let mut inner =
            noq::ServerConfig::new(Arc::new(quic_server_config), self.token_key.clone());
        inner.transport_config(self.transport_config.to_inner_arc());
        inner.max_incoming(self.limits.max_connections().get());
        #[cfg(not(wasm_browser))]
        inner.time_source(Arc::new(crate::runtime::NoqWallClock::new(
            self.runtime_context.wall_clock(),
        )));
        inner
    }

    /// Create a [`noq_proto::ClientConfig`] with the specified ALPN protocols.
    pub(crate) fn create_client_config(
        &self,
        alpn_protocols: Vec<Vec<u8>>,
        transport_config: Arc<noq::TransportConfig>,
    ) -> noq_proto::ClientConfig {
        let mut quic_client_config = self.client_config.clone();
        quic_client_config.set_alpn_protocols(alpn_protocols);
        let mut inner = noq::ClientConfig::new(Arc::new(quic_client_config));
        inner.transport_config(transport_config);
        inner.token_store(self.token_store.clone());
        #[cfg(not(wasm_browser))]
        if let Some(provider) = &self.simulation_initial_dst_cid_provider {
            inner.initial_dst_cid_provider(provider.clone());
        }
        inner
    }
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum BindError {
    #[error("Failed to bind sockets")]
    Sockets { source: io::Error },
    #[error("Failed to create internal QUIC endpoint")]
    CreateQuicEndpoint { source: io::Error },
    #[error("Failed to create netmon monitor")]
    CreateNetmonMonitor { source: AnyError },
    #[error("Invalid transport configuration")]
    InvalidTransportConfig,
    #[error("Invalid CA root configuration")]
    InvalidCaRootConfig { source: io::Error },
    #[error("Failed to create an address lookup service")]
    AddressLookup {
        #[error(from)]
        source: crate::address_lookup::AddressLookupBuilderError,
    },
    #[error("Missing or incompatible rustls crypto provider configured")]
    InvalidCryptoProvider,
    #[error("Error constructing TLS configuration")]
    TlsConfigError {
        #[error(from)]
        source: tls::TlsConfigError,
    },
    #[error("Failed to create QUIC address-discovery client")]
    CreateQuicClient {
        source: krikos_relay::quic::QuicClientBuildError,
    },
    #[error("Invalid deterministic runtime context")]
    RuntimeContext { source: AnyError },
    #[error("Endpoint task capacity cannot cover its configured connection and actor limits")]
    InvalidEndpointLimits,
}
