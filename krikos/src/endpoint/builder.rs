use super::*;

/// Builder for [`Endpoint`].
///
/// By default the endpoint will generate a new random [`SecretKey`], which will result in a
/// new [`EndpointId`].
///
/// To create the [`Endpoint`] call [`Builder::bind`].
#[derive(Debug)]
pub struct Builder {
    secret_key: Option<SecretKey>,
    alpn_protocols: Vec<Vec<u8>>,
    transport_config: QuicTransportConfig,
    keylog: bool,
    address_lookup: Vec<Box<dyn DynAddressLookupBuilder>>,
    address_lookup_user_data: Option<UserData>,
    /// Default address filter applied to all address lookup services added via
    /// [`Builder::address_lookup`].
    addr_filter: Option<AddrFilter>,
    proxy_url: Option<Url>,
    ca_tls_config: Option<CaTlsConfig>,
    #[cfg(not(wasm_browser))]
    dns_resolver: Option<DnsResolver>,
    transports: Vec<TransportConfig>,
    max_tls_tickets: usize,
    hooks: EndpointHooksList,
    path_selector: Arc<dyn PathSelector>,
    portmapper_config: PortmapperConfig,
    net_report_config: NetReportConfig,
    crypto_provider: Option<Arc<rustls::crypto::CryptoProvider>>,
    configured_addrs: BTreeSet<SocketAddr>,
    #[cfg(not(wasm_browser))]
    pub(super) simulation_environment: Option<crate::simulation::SimulationEnvironment>,
    limits: EndpointLimits,
}

impl From<RelayMode> for Option<TransportConfig> {
    fn from(mode: RelayMode) -> Self {
        match mode {
            RelayMode::Disabled => None,
            RelayMode::Default => Some(TransportConfig::Relay {
                relay_map: mode.relay_map(),
                is_user_defined: true,
            }),
            RelayMode::Staging => Some(TransportConfig::Relay {
                relay_map: mode.relay_map(),
                is_user_defined: true,
            }),
            RelayMode::Custom(relay_map) => Some(TransportConfig::Relay {
                relay_map,
                is_user_defined: true,
            }),
        }
    }
}

impl Builder {
    // The ordering of public methods is reflected directly in the documentation.  This is
    // roughly ordered by what is most commonly needed by users.

    /// Creates a new [`Builder`] using the given [`Preset`].
    ///
    /// See [`presets`] for more.
    pub fn new(preset: impl Preset) -> Self {
        Self::empty().preset(preset)
    }

    /// Applies the given [`Preset`].
    pub fn preset(mut self, preset: impl Preset) -> Self {
        self = preset.apply(self);
        self
    }

    /// Creates an empty builder with no address lookup services, and [`RelayMode::Disabled`].
    pub fn empty() -> Self {
        let transports = vec![
            #[cfg(not(wasm_browser))]
            TransportConfig::default_ipv4(),
            #[cfg(not(wasm_browser))]
            TransportConfig::default_ipv6(),
        ];

        Self {
            secret_key: Default::default(),
            alpn_protocols: Default::default(),
            transport_config: QuicTransportConfig::default(),
            keylog: Default::default(),
            address_lookup: Default::default(),
            address_lookup_user_data: Default::default(),
            addr_filter: None,
            proxy_url: None,
            ca_tls_config: None,
            #[cfg(not(wasm_browser))]
            dns_resolver: None,
            max_tls_tickets: DEFAULT_MAX_TLS_TICKETS,
            transports,
            hooks: Default::default(),
            path_selector: Arc::new(BiasedRttPathSelector::default()),
            portmapper_config: Default::default(),
            net_report_config: Default::default(),
            crypto_provider: None,
            configured_addrs: Default::default(),
            #[cfg(not(wasm_browser))]
            simulation_environment: None,
            limits: EndpointLimits::default(),
        }
    }

    // # The final constructor that everyone needs.

    /// Binds the endpoint.
    pub async fn bind(self) -> Result<Endpoint, BindError> {
        if let Err(error) = self.limits.validate() {
            tracing::warn!(?error, "invalid endpoint capacity limits");
            return Err(e!(BindError::InvalidEndpointLimits));
        }
        let secret_key = self.secret_key.unwrap_or_else(SecretKey::generate);

        #[cfg(not(wasm_browser))]
        let simulation_environment = self.simulation_environment;
        #[cfg(not(wasm_browser))]
        let runtime_context = simulation_environment
            .as_ref()
            .map(crate::simulation::SimulationEnvironment::runtime)
            .unwrap_or_else(|| {
                Arc::new(krikos_runtime::RuntimeContext::production(Arc::new(
                    krikos_runtime::NoopTraceSink,
                )))
            });

        #[cfg(not(wasm_browser))]
        let environment_crypto_provider = simulation_environment
            .as_ref()
            .and_then(crate::simulation::SimulationEnvironment::crypto_provider);
        #[cfg(wasm_browser)]
        let environment_crypto_provider = None;
        let crypto_provider = environment_crypto_provider
            .or(self.crypto_provider)
            .ok_or_else(|| e!(BindError::InvalidCryptoProvider))?;

        #[cfg(not(wasm_browser))]
        let simulation_crypto = simulation_environment
            .as_ref()
            .map(crate::simulation::SimulationEnvironment::crypto);
        #[cfg(not(wasm_browser))]
        let token_key = if let Some(material) = simulation_crypto {
            RustlsTokenKey::from_key(material.token_key(), &crypto_provider)
                .ok_or_else(|| e!(BindError::InvalidCryptoProvider))?
        } else {
            RustlsTokenKey::new(&mut rand::rng(), &crypto_provider)
                .ok_or_else(|| e!(BindError::InvalidCryptoProvider))?
        };
        #[cfg(wasm_browser)]
        let token_key = RustlsTokenKey::new(&mut rand::rng(), &crypto_provider)
            .ok_or_else(|| e!(BindError::InvalidCryptoProvider))?;
        let token_key = Arc::new(token_key);

        let span = info_span!("endpoint", id = %secret_key.public().fmt_short());
        let _guard = span.enter();

        let tls_config = tls::TlsConfig::new(
            secret_key.clone(),
            self.max_tls_tickets,
            crypto_provider.clone(),
        );
        let static_config = StaticConfig {
            server_config: tls_config.make_server_config(self.keylog)?,
            client_config: tls_config.make_client_config(self.keylog)?,
            tls_config,
            transport_config: self.transport_config.clone(),
            token_key,
            token_store: Arc::new(noq::TokenMemoryCache::default()),
            #[cfg(not(wasm_browser))]
            runtime_context: runtime_context.clone(),
            #[cfg(not(wasm_browser))]
            simulation_initial_dst_cid_provider: simulation_crypto.map(|material| {
                socket::deterministic_simulation_initial_dst_cid_provider(material.reset_key())
            }),
            limits: self.limits,
        };
        let server_config = static_config.create_server_config(self.alpn_protocols);

        #[cfg(not(wasm_browser))]
        let dns_resolver = self.dns_resolver.unwrap_or_default();

        let metrics = EndpointMetrics::default();

        let tls_config = self
            .ca_tls_config
            .unwrap_or_default()
            .client_config(crypto_provider)
            .map_err(|err| e!(BindError::InvalidCaRootConfig, err))?;

        let sock_opts = socket::Options {
            transports: self.transports,
            secret_key,
            address_lookup_user_data: self.address_lookup_user_data,
            proxy_url: self.proxy_url,
            #[cfg(not(wasm_browser))]
            dns_resolver,
            #[cfg(not(wasm_browser))]
            runtime_context,
            #[cfg(not(wasm_browser))]
            ip_socket_factory: simulation_environment
                .as_ref()
                .map(crate::simulation::SimulationEnvironment::ip_sockets)
                .unwrap_or_else(|| Arc::new(crate::simulation::OsIpSocketFactory)),
            #[cfg(not(wasm_browser))]
            network_monitor: simulation_environment
                .as_ref()
                .map(crate::simulation::SimulationEnvironment::network_monitor),
            #[cfg(not(wasm_browser))]
            simulation_port_mapper: simulation_environment
                .as_ref()
                .and_then(crate::simulation::SimulationEnvironment::port_mapper),
            #[cfg(not(wasm_browser))]
            simulation_relay_connector: simulation_environment
                .as_ref()
                .and_then(crate::simulation::SimulationEnvironment::relay_connector),
            #[cfg(not(wasm_browser))]
            simulation_preferred_relay: simulation_environment
                .as_ref()
                .and_then(crate::simulation::SimulationEnvironment::preferred_relay),
            #[cfg(not(wasm_browser))]
            simulation_reset_key: simulation_crypto.map(|material| material.reset_key()),
            server_config,
            tls_config,
            metrics,
            hooks: self.hooks,
            path_selector: self.path_selector,
            portmapper_config: self.portmapper_config,
            net_report_config: self.net_report_config,
            static_config,
            configured_addrs: self.configured_addrs,
            limits: self.limits,
        };

        let inner = socket::EndpointInner::bind(sock_opts)
            .instrument(Span::current())
            .await?;
        debug!(
            id = %inner.static_config.tls_config.secret_key.public(),
            krikos_version = %env!("CARGO_PKG_VERSION"),
            "krikos endpoint bound"
        );

        let ep = Endpoint {
            inner: Arc::new(inner),
        };

        // Add Address Lookup mechanisms
        let address_lookup = ep.address_lookup().expect("just created the endpoint");
        if let Some(filter) = self.addr_filter {
            address_lookup.set_addr_filter(filter);
        }
        for create_service in self.address_lookup {
            let service = create_service.into_address_lookup(&ep)?;
            address_lookup.add_boxed(service);
        }

        Ok(ep)
    }

    /// Installs one coherent deterministic environment for repository simulation runs.
    #[doc(hidden)]
    #[cfg(not(wasm_browser))]
    pub fn simulation_environment_for_test(
        mut self,
        environment: crate::simulation::SimulationEnvironment,
        _marker: krikos_runtime::UnsafeTestOnly,
    ) -> Self {
        self.simulation_environment = Some(environment);
        self
    }

    // # The very common methods everyone basically needs.

    /// Binds an IP socket at the provided socket address.
    ///
    /// This is an advanced API to tightly control the sockets used by the endpoint. Most
    /// uses do not need to explicitly bind sockets.
    ///
    /// # Warning
    ///
    /// - The builder always comes pre-configured with an IPv4 socket to be bound on the
    ///   *unspecified* address: `0.0.0.0`. This is the equivalent of using `INADDR_ANY`
    ///   special bind address and results in a socket listening on *all* interfaces
    ///   available.
    ///
    /// - Likewise the builder always comes pre-configured with an IPv6 socket to be bound
    ///   on the *unspecified* address: `[::]`. This bind is allowed to fail however.
    ///
    /// - Adding a bind address removes the pre-configured unspecified bind address for this
    ///   address family. Use [`Self::bind_addr_with_opts`] to bind additional addresses without
    ///   replacing the default bind address.
    ///
    /// - This should be called at most once for each address family: once for IPv4 and/or
    ///   once for IPv6. Calling it multiple times for the same address family will result
    ///   in undefined routing behaviour. To bind multiple sockets of the same address
    ///   family, use [`Self::bind_addr_with_opts`].
    ///
    /// # Description
    ///
    /// Requests a socket to be bound on a specific address, with an implied netmask of
    /// `/0`. This allows restricting binding to only one network interface for a given
    /// address family.
    ///
    /// If the port specified is already in use, binding the endpoint will fail. Using
    /// port `0` in the socket address assigns a random free port.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(with_crypto_provider)]
    /// # {
    /// # #[tokio::main]
    /// # async fn main() -> n0_error::Result<()> {
    /// # use krikos::{Endpoint, endpoint::presets};
    /// let endpoint = Endpoint::builder(presets::N0)
    ///     .clear_ip_transports()
    ///     .bind_addr("127.0.0.1:0")?
    ///     .bind_addr("[::1]:0")?
    ///     .bind()
    ///     .await?;
    /// # Ok(()) }
    /// # }
    /// ```
    #[cfg(not(wasm_browser))]
    pub fn bind_addr<A>(self, addr: A) -> Result<Self, InvalidSocketAddr>
    where
        A: ToSocketAddr,
        <A as ToSocketAddr>::Err: Into<InvalidSocketAddr>,
    {
        self.bind_addr_with_opts(addr, BindOpts::default())
    }

    /// Binds an IP socket at the provided socket address.
    ///
    /// This is an advanced API to tightly control the sockets used by the endpoint. Most
    /// uses do not need to explicitly bind sockets.
    ///
    /// # Warning
    ///
    /// - The builder always comes pre-configured with an IPv4 socket to be bound on the
    ///   *unspecified* address: `0.0.0.0`. This is the equivalent of using `INADDR_ANY`
    ///   special bind address and results in a socket listening on *all* interfaces
    ///   available.
    ///
    /// - Likewise the builder always comes pre-configured with an IPv6 socket to be bound
    ///   on the *unspecified* address: `[::]`. This bind is allowed to fail however.
    ///
    /// # Description
    ///
    /// Requests a socket to be bound on a specific address. This allows restricting binding
    /// to only one network interface for a given address family.
    ///
    /// [`BindOpts::set_prefix_len`] **should** be used to configure the netmask of the
    /// network interface. This allows outgoing datagrams that start a new network flow to
    /// be sent over the socket which is attached to the subnet of the destination
    /// address. If multiple sockets are bound the standard routing-table semantics are
    /// used: the socket attached to the subnet with the longest prefix matching the
    /// destination is used. Practically this means the smallest subnets are at the top of
    /// the routing table, and the first subnet containing the destination address is
    /// chosen.
    ///
    /// If no socket is bound to a subnet that contains the destination address, the notion
    /// of "default route" is used. At most one socket per address family may be marked as
    /// the default route using [`BindOpts::set_is_default_route`], and this will be used
    /// for destinations not contained by the subnets of the bound sockets. This network is
    /// expected to have a default gateway configured. A socket with a prefix length of `/0`
    /// will be set as a "default route" implicitly, unless [`BindOpts::set_is_default_route`]
    /// is set to `false` explicitly.
    ///
    /// Be aware that using a subnet with a prefix length of `/0` will always contain all
    /// destination addresses. It is valid to configure this, but no more than one such
    /// socket should be bound or the routing will be non-deterministic.
    ///
    /// To use a subnet with a non-zero prefix length as the default route in addition to
    /// being routed when its prefix matches, use [`BindOpts::set_is_default_route`].
    /// Subnets with a prefix length of zero are always marked as default routes.
    ///
    /// Finally note that most outgoing datagrams are part of an existing network flow. That
    /// is, they are in response to an incoming datagram. In this case the outgoing datagram
    /// will be sent over the same socket as the incoming datagram was received on, and the
    /// routing with the prefix length and default route as described above does not apply.
    ///
    /// Using port `0` in the socket address assigns a random free port.
    ///
    /// If the port specified is already in use, binding the endpoint will fail, unless
    /// [`BindOpts::set_is_required`] is set to `false`
    ///
    /// # Example
    /// ```no_run
    /// # #[cfg(with_crypto_provider)]
    /// # {
    /// # #[tokio::main]
    /// # async fn main() -> n0_error::Result<()> {
    /// # use krikos::{Endpoint, endpoint::{BindOpts, presets}};
    /// let endpoint = Endpoint::builder(presets::N0)
    ///     .clear_ip_transports()
    ///     .bind_addr_with_opts("127.0.0.1:0", BindOpts::default().set_prefix_len(24))?
    ///     .bind_addr_with_opts("[::1]:0", BindOpts::default().set_prefix_len(48))?
    ///     .bind()
    ///     .await?;
    /// # Ok(()) }
    /// # }
    /// ```
    #[cfg(not(wasm_browser))]
    pub fn bind_addr_with_opts<A>(
        mut self,
        addr: A,
        opts: BindOpts,
    ) -> Result<Self, InvalidSocketAddr>
    where
        A: ToSocketAddr,
        <A as ToSocketAddr>::Err: Into<InvalidSocketAddr>,
    {
        let addr = addr.to_socket_addr().map_err(Into::into)?;
        match addr {
            SocketAddr::V4(addr) => {
                if self
                    .transports
                    .iter()
                    .any(|t| t.is_ipv4_default() && t.is_user_defined())
                {
                    bail!(InvalidSocketAddr::DuplicateDefaultAddr);
                }

                let ip_net = Ipv4Net::new(*addr.ip(), opts.prefix_len())
                    .map_err(|_| e!(InvalidSocketAddr::InvalidPrefixLength))?;
                self.transports.push(TransportConfig::Ip {
                    config: IpConfig::V4 {
                        ip_net,
                        port: addr.port(),
                        is_required: opts.is_required(),
                        is_default: opts.is_default_route(),
                    },
                    is_user_defined: true,
                });
            }
            SocketAddr::V6(addr) => {
                if self
                    .transports
                    .iter()
                    .any(|t| t.is_ipv6_default() && t.is_user_defined())
                {
                    bail!(InvalidSocketAddr::DuplicateDefaultAddr);
                }

                let ip_net = Ipv6Net::new(*addr.ip(), opts.prefix_len())
                    .map_err(|_| e!(InvalidSocketAddr::InvalidPrefixLength))?;
                self.transports.push(TransportConfig::Ip {
                    config: IpConfig::V6 {
                        ip_net,
                        scope_id: addr.scope_id(),
                        port: addr.port(),
                        is_required: opts.is_required(),
                        is_default: opts.is_default_route(),
                    },
                    is_user_defined: true,
                });
            }
        }
        Ok(self)
    }

    /// Removes all IP based transports.
    #[cfg(not(wasm_browser))]
    pub fn clear_ip_transports(mut self) -> Self {
        self.transports
            .retain(|t| !matches!(t, TransportConfig::Ip { .. }));
        self
    }

    /// Removes all relay based transports.
    pub fn clear_relay_transports(mut self) -> Self {
        self.transports
            .retain(|t| !matches!(t, TransportConfig::Relay { .. }));
        self
    }

    /// Sets a secret key to authenticate with other peers.
    ///
    /// This secret key's public key will be the [`PublicKey`] of this endpoint and thus
    /// also its [`EndpointId`]
    ///
    /// If not set, a new secret key will be generated.
    ///
    /// [`PublicKey`]: krikos_base::PublicKey
    pub fn secret_key(mut self, secret_key: SecretKey) -> Self {
        self.secret_key = Some(secret_key);
        self
    }

    /// Sets the [ALPN] protocols that this endpoint will accept on incoming connections.
    ///
    /// Not setting this will still allow creating connections, but to accept incoming
    /// connections at least one [ALPN] must be set.
    ///
    /// [ALPN]: https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation
    pub fn alpns(mut self, alpn_protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = alpn_protocols;
        self
    }

    /// Sets finite task, connection, and actor capacities for this endpoint.
    ///
    /// [`Builder::bind`] returns an error if the task limit cannot cover the configured
    /// connection and actor limits plus fixed endpoint supervision tasks.
    pub fn limits(mut self, limits: EndpointLimits) -> Self {
        self.limits = limits;
        self
    }

    // # Methods for common customisation items.

    /// Sets the relay servers to assist in establishing connectivity.
    ///
    /// Relay servers are used to establish initial connection with another krikos endpoint.
    /// They also perform various functions related to hole punching, see the [crate docs]
    /// for more details.
    ///
    /// By default the [number 0] relay servers are used, see [`RelayMode::Default`].
    ///
    /// When using [RelayMode::Custom], the provided `relay_map` must contain at least one
    /// configured relay endpoint.  If an invalid RelayMap is provided [`bind`]
    /// will result in an error.
    ///
    /// [`bind`]: Builder::bind
    /// [crate docs]: crate
    /// [number 0]: https://n0.computer
    pub fn relay_mode(mut self, relay_mode: RelayMode) -> Self {
        let transport: Option<_> = relay_mode.into();
        match transport {
            Some(transport) => {
                if let Some(og) = self
                    .transports
                    .iter_mut()
                    .find(|t| matches!(t, TransportConfig::Relay { .. }))
                {
                    *og = transport;
                } else {
                    self.transports.push(transport);
                }
            }
            None => {
                self.transports
                    .retain(|t| !matches!(t, TransportConfig::Relay { .. }));
            }
        }
        self
    }

    /// Removes all Address Lookup services from the builder.
    ///
    /// If no Address Lookup is set, connecting to an endpoint without providing its
    /// direct addresses or relay URLs will fail.
    ///
    /// See the documentation of the [`crate::address_lookup::AddressLookup`] trait for details.
    pub fn clear_address_lookup(mut self) -> Self {
        self.address_lookup.clear();
        self
    }

    /// Adds an additional Address Lookup for this endpoint.
    ///
    /// Once the endpoint is created the provided [`AddressLookupBuilder::into_address_lookup`] will be
    /// called. This allows Address Lookup's to finalize their configuration by e.g. using
    /// the secret key from the endpoint which can be needed to sign published information.
    ///
    /// This method can be called multiple times and all the Address Lookup's passed in
    /// will be combined using an internal instance of the
    /// [`crate::address_lookup::AddressLookupServices`]. To clear all Address Lookup's, use
    /// [`Self::clear_address_lookup`].
    ///
    /// If no Address Lookup is set, connecting to an endpoint without providing its
    /// direct addresses or relay URLs will fail.
    ///
    /// See the documentation of the [`crate::address_lookup::AddressLookup`] trait for details.
    pub fn address_lookup(mut self, address_lookup: impl AddressLookupBuilder) -> Self {
        self.address_lookup.push(Box::new(address_lookup));
        self
    }

    /// Sets the address filter applied to all address data before publishing.
    ///
    /// This filter is applied once, at the [`AddressLookupServices`] level, before
    /// distributing data to any individual address lookup service. This ensures
    /// consistent filtering regardless of how the services are configured.
    ///
    /// [`AddressLookupServices`]: crate::address_lookup::AddressLookupServices
    pub fn addr_filter(mut self, filter: AddrFilter) -> Self {
        self.addr_filter = Some(filter);
        self
    }

    /// Clears the address filter, allowing all addresses to be published.
    ///
    /// This removes any filter previously set via [`Self::addr_filter`], including
    /// filters set by presets.
    pub fn clear_addr_filter(mut self) -> Self {
        self.addr_filter = None;
        self
    }

    /// Sets the initial user-defined data to be published in Address Lookup's for this node.
    ///
    /// When using Address Lookup's, this string of [`UserData`] will be published together
    /// with the endpoint's addresses and relay URL. When other endpoints discover this endpoint,
    /// they retrieve the [`UserData`] in addition to the addressing info.
    ///
    /// Krikos itself does not interpret the user-defined data in any way, it is purely left
    /// for applications to parse and use.
    pub fn user_data_for_address_lookup(mut self, user_data: UserData) -> Self {
        self.address_lookup_user_data = Some(user_data);
        self
    }

    /// Adds an external address on which this endpoint is directly reachable.
    ///
    /// This address will be advertised to peers together with any discovered external addresses
    /// and will be used in NAT traversal and to establish direct connections.
    ///
    /// Can be called multiple times. See also [`Endpoint::add_external_addr`] for
    /// adding addresses at runtime.
    pub fn external_addr(mut self, addr: SocketAddr) -> Self {
        self.configured_addrs.insert(addr);
        self
    }

    // # Methods for more specialist customisation.

    /// Sets a custom [`QuicTransportConfig`] for this endpoint.
    ///
    /// The transport config contains parameters governing the QUIC state machine.
    ///
    /// If unset, the default config is used. Default values should be suitable for most
    /// internet applications. Applications protocols which forbid remotely-initiated
    /// streams should set `max_concurrent_bidi_streams` and `max_concurrent_uni_streams` to
    /// zero.
    ///
    /// Please be aware that changing some settings may have adverse effects on establishing
    /// and maintaining direct connections.
    pub fn transport_config(mut self, transport_config: QuicTransportConfig) -> Self {
        self.transport_config = transport_config;
        self
    }

    /// Optionally sets a custom DNS resolver to use for this endpoint.
    ///
    /// The DNS resolver is used to resolve relay hostnames, and endpoint addresses if
    /// [`crate::address_lookup::DnsAddressLookup`] is configured.
    ///
    /// By default, a new DNS resolver is created which is configured to use the
    /// host system's DNS configuration. You can pass a custom instance of [`DnsResolver`]
    /// here to use a differently configured DNS resolver for this endpoint, or to share
    /// a [`DnsResolver`] between multiple endpoints.
    #[cfg(not(wasm_browser))]
    pub fn dns_resolver(mut self, dns_resolver: DnsResolver) -> Self {
        self.dns_resolver = Some(dns_resolver);
        self
    }

    /// Sets an explicit proxy url to proxy all HTTP(S) traffic through.
    pub fn proxy_url(mut self, url: Url) -> Self {
        self.proxy_url.replace(url);
        self
    }

    /// Sets the proxy url from the environment, in this order:
    ///
    /// - `HTTP_PROXY`
    /// - `http_proxy`
    /// - `HTTPS_PROXY`
    /// - `https_proxy`
    pub fn proxy_from_env(mut self) -> Self {
        self.proxy_url = proxy_url_from_env();
        self
    }

    /// Sets the trusted CA root certificates for non-krikos TLS connections.
    ///
    /// These Certificate Authority roots are used as trust anchors for verifying
    /// the validity of TLS certificates presented by external services, such as
    /// krikos relays, pkarr servers, or DNS-over-HTTPS resolvers.
    /// They don't need to be trusted for the integrity or authenticity of native
    /// krikos connections, which rely on krikos's own cryptographic authentication mechanisms.
    pub fn ca_tls_config(mut self, ca_tls_config: CaTlsConfig) -> Self {
        self.ca_tls_config = Some(ca_tls_config);
        self
    }

    /// Renamed to [`Builder::ca_tls_config`].
    #[deprecated(since = "1.0.0", note = "Renamed to `ca_tls_config`")]
    pub fn ca_roots_config(self, ca_roots_config: CaTlsConfig) -> Self {
        self.ca_tls_config(ca_roots_config)
    }

    /// Enables saving the TLS pre-master key for connections.
    ///
    /// This key should normally remain secret but can be useful to debug networking issues
    /// by decrypting captured traffic.
    ///
    /// If *keylog* is `true` then setting the `SSLKEYLOGFILE` environment variable to a
    /// filename will result in this file being used to log the TLS pre-master keys.
    pub fn keylog(mut self, keylog: bool) -> Self {
        self.keylog = keylog;
        self
    }

    /// Set the maximum number of TLS tickets to cache.
    ///
    /// Set this to a larger value if you want to do 0rtt connections to a large
    /// number of clients.
    ///
    /// The default is 256, taking about 150 KiB in memory.
    pub fn max_tls_tickets(mut self, n: usize) -> Self {
        self.max_tls_tickets = n;
        self
    }

    /// Specify the rustls cryptography to use for all TLS operations.
    ///
    /// This includes
    /// - TLS for encryption and authentication of krikos connections themselves, but also
    /// - HTTPS connections to relays
    /// - Pkarr relay publishing HTTPS connections
    /// - and any other Address Lookup services that decide to use [`Endpoint::tls_config`].
    ///
    /// The two most common crypto providers in use today are `ring` as well as `aws-lc-rs`.
    ///
    /// If either the `tls-ring` or `tls-aws-lc-rs` feature is set in krikos, this function doesn't
    /// need to be called.
    ///
    /// If none of these features are set, then calling this function in the builder is mandatory.
    pub fn crypto_provider(mut self, crypto_provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        self.crypto_provider = Some(crypto_provider);
        self
    }

    /// Install hooks onto the endpoint.
    ///
    /// Endpoint hooks intercept the connection establishment process of an [`Endpoint`].
    ///
    /// You can install multiple [`EndpointHooks`] by calling this function multiple times.
    /// Order matters: hooks are invoked in the order they were installed onto the endpoint
    /// builder. Once a hook returns reject, further processing
    /// is aborted and other hooks won't be invoked.
    ///
    /// See [`EndpointHooks`] for details on the possible interception points in the connection lifecycle.
    pub fn hooks(mut self, hooks: impl EndpointHooks + 'static) -> Self {
        self.hooks.push(hooks);
        self
    }

    /// Configures the portmapper service (UPnP, PCP, NAT-PMP).
    ///
    /// Defaults to [`PortmapperConfig::Enabled`]. Pass
    /// [`PortmapperConfig::Disabled`] to avoid gateway probing (e.g. if it
    /// triggers firewall prompts).
    pub fn portmapper_config(mut self, config: PortmapperConfig) -> Self {
        self.portmapper_config = config;
        self
    }

    /// Configures the net report.
    ///
    /// The net report component is responsible for figuring out if and how the endpoint is connected to the internet.
    /// It does this by doing various probes to the configured relay servers to get public addresses, NAT behaviour, and
    /// relay latencies. In addition it tries to detect captive portals.
    ///
    /// Some non-essential features of the net report component can be disabled via this configuration.
    pub fn net_report_config(mut self, config: NetReportConfig) -> Self {
        self.net_report_config = config;
        self
    }

    /// Adds a custom transport to the endpoint.
    ///
    /// <div class="warning">
    ///
    /// This API is unstable and gated behind the `unstable-custom-transport` feature.
    /// It is not covered by semantic versioning guarantees and may change in any release
    /// without a major version bump.
    ///
    /// </div>
    #[cfg(feature = "unstable-custom-transports")]
    pub fn add_custom_transport(mut self, factory: Arc<dyn CustomTransport>) -> Self {
        self.transports.push(TransportConfig::Custom(factory));
        self
    }

    /// Sets a custom [`PathSelector`] for this endpoint.
    ///
    /// The path selector decides which path to use among the candidate paths to a
    /// remote endpoint.  By default krikos uses a built-in selector that sorts paths by
    /// biased RTT (with IPv6 preferred over IPv4 and relay treated as backup) and is
    /// sticky to avoid flapping.  Pass a custom [`PathSelector`] here to override that
    /// policy — for example, to make a custom transport always win over IP.
    ///
    /// Takes an `Arc<dyn PathSelector>` so the same selector instance can be shared
    /// across multiple endpoints if desired.  See `examples/custom-transport.rs` for
    /// an example implementation.
    ///
    /// <div class="warning">
    ///
    /// This API is unstable and gated behind the `unstable-custom-transport` feature.
    /// It is not covered by semantic versioning guarantees and may change in any release
    /// without a major version bump.
    ///
    /// </div>
    ///
    /// [`PathSelector`]: socket::remote_map::PathSelector
    #[cfg(feature = "unstable-custom-transports")]
    pub fn path_selector(mut self, selector: Arc<dyn PathSelector>) -> Self {
        self.path_selector = selector;
        self
    }
}
