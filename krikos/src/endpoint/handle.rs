use super::*;

/// Controls an krikos endpoint, establishing connections with other endpoints.
///
/// This is the main API interface to create connections to, and accept connections from
/// other krikos endpoints.  The connections are peer-to-peer and encrypted, a Relay server is
/// used to make the connections reliable.  See the [crate docs] for a more detailed
/// overview of krikos.
///
/// It is recommended to only create a single instance per application.  This ensures all
/// the connections made share the same peer-to-peer connections to other krikos endpoints,
/// while still remaining independent connections.  This will result in more optimal network
/// behaviour.
///
/// The endpoint is created using the [`Builder`], which can be created using
/// [`Endpoint::builder`].
///
/// Once an endpoint exists, new connections are typically created using the
/// [`Endpoint::connect`] and [`Endpoint::accept`] methods.  Once established, the
/// [`Connection`] gives access to most [QUIC] features.  Individual streams to send data to
/// the peer are created using the [`Connection::open_bi`], [`Connection::accept_bi`],
/// [`Connection::open_uni`] and [`Connection::accept_uni`] functions.
///
/// Note that due to the light-weight properties of streams a stream will only be accepted
/// once the initiating peer has sent some data on it.
///
/// # Usage on Android
///
/// The endpoint's default [`DnsResolver`] reads the system DNS configuration
/// through JNI, which needs a JVM context published to [`ndk_context`]. Apps
/// should initialize that context before constructing the endpoint. See
/// [`krikos_dns::install_android_jni_context`] for details (the function is also
/// exported as `krikos::dns::install_android_jni_context`).
///
/// If no JNI context is installed, krikos relies on panic unwinding to detect
/// the error, and will then use Google's fallback DNS servers. Note that if
/// your compilation profile sets `panic = "abort"`, this can't work, and thus
/// your app will panic if using a default `DnsResolver` without first initializing
/// the JNI context.
///
/// [QUIC]: https://quicwg.org
/// [`DnsResolver`]: crate::dns::DnsResolver
/// [`ndk_context`]: https://docs.rs/ndk-context
/// [`krikos_dns::install_android_jni_context`]: https://docs.rs/krikos-dns/latest/krikos_dns/fn.install_android_jni_context.html
// The last link can't be a normal doclink, because #[cfg(doc)] can't cross crate boundaries unfortunately.
#[derive(Clone, Debug)]
pub struct Endpoint {
    pub(super) inner: Arc<EndpointInner>,
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta, from_sources)]
#[non_exhaustive]
#[allow(private_interfaces)]
pub enum ConnectWithOptsError {
    #[error("Connecting to ourself is not supported")]
    SelfConnect,
    #[error("No addressing information available")]
    NoAddress { source: AddressLookupFailed },
    #[error("Unable to connect to remote")]
    Noq {
        #[error(std_err)]
        source: QuicConnectError,
    },
    #[error("Internal consistency error")]
    InternalConsistencyError {
        /// Private source type, cannot be created publicly.
        source: RemoteStateActorStoppedError,
    },
    #[error("Connection was rejected locally")]
    LocallyRejected,
    #[error("Endpoint is closed")]
    EndpointClosed,
    #[error("Invalid ALPN")]
    InvalidAlpn,
    #[error("Endpoint connection capacity is full")]
    ConnectionCapacityFull,
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta, from_sources)]
#[non_exhaustive]
pub enum ConnectError {
    #[error(transparent)]
    Connect { source: ConnectWithOptsError },
    #[error(transparent)]
    Connecting { source: ConnectingError },
    #[error(transparent)]
    Connection {
        #[error(std_err)]
        source: ConnectionError,
    },
}

impl Endpoint {
    // The ordering of public methods is reflected directly in the documentation.  This is
    // roughly ordered by what is most commonly needed by users, but grouped in similar
    // items.

    // # Methods relating to construction.

    /// Returns the builder for an [`Endpoint`], with the given [`Preset`] configuration.
    pub fn builder(preset: impl Preset) -> Builder {
        Builder::new(preset)
    }

    /// Constructs a default [`Endpoint`] using the provided [`Preset`] and binds it immediately.
    pub async fn bind(preset: impl Preset) -> Result<Self, BindError> {
        Self::builder(preset).bind().await
    }

    /// Sets the list of accepted ALPN protocols.
    ///
    /// This will only affect new incoming connections.
    /// Note that this *overrides* the current list of ALPNs.
    ///
    /// If the endpoint is closed, this method will log a warning and ignore
    /// the request to set new ALPNs.
    pub fn set_alpns(&self, alpns: Vec<Vec<u8>>) {
        if self.is_closed() {
            warn!("Attempting to set ALPNs for a closed endpoint. Ignoring.");
            return;
        }
        let server_config = self.inner.static_config.create_server_config(alpns);
        self.inner
            .noq_endpoint()
            .set_server_config(Some(server_config));
    }

    /// Adds the provided configuration to the [`RelayMap`].
    ///
    /// Replacing and returning any existing configuration for [`RelayUrl`].
    ///
    /// Will also return `None` if the endpoint is closed.
    pub async fn insert_relay(
        &self,
        relay: RelayUrl,
        config: Arc<RelayConfig>,
    ) -> Option<Arc<RelayConfig>> {
        if self.is_closed() {
            return None;
        }
        self.inner.insert_relay(relay, config).await
    }

    /// Removes the configuration from the [`RelayMap`] for the provided [`RelayUrl`].
    ///
    /// Returns any existing configuration if it exists. Will also return `None` if the endpoint is closed.
    pub async fn remove_relay(&self, relay: &RelayUrl) -> Option<Arc<RelayConfig>> {
        if self.is_closed() {
            return None;
        }
        self.inner.remove_relay(relay).await
    }

    /// Adds an external address on which this endpoint is directly reachable.
    ///
    /// This address will be advertised to peers together with any discovered external addresses
    /// and will be used in NAT traversal and to establish direct connections.
    ///
    /// See also [`Builder::external_addr`] for setting addresses at build time.
    pub async fn add_external_addr(&self, addr: SocketAddr) {
        if self.is_closed() {
            warn!("Attempting to add external addr for a closed endpoint. Ignoring.");
            return;
        }
        self.inner.add_external_addr(addr).await;
    }

    /// Removes a configured external address. Returns `true` if it was present.
    pub async fn remove_external_addr(&self, addr: &SocketAddr) -> bool {
        if self.is_closed() {
            return false;
        }
        self.inner.remove_external_addr(addr).await
    }

    // # Methods for establishing connectivity.

    /// Connects to a remote [`Endpoint`].
    ///
    /// A value that can be converted into an [`EndpointAddr`] is required. This can be either an
    /// [`EndpointAddr`] or an [`EndpointId`].
    ///
    /// The [`EndpointAddr`] must contain the [`EndpointId`] to dial and may also contain a [`RelayUrl`]
    /// and direct addresses. If direct addresses are provided, they will be used to try and
    /// establish a direct connection without involving a relay server.
    ///
    /// If neither a [`RelayUrl`] or direct addresses are configured in the [`EndpointAddr`] it
    /// may still be possible a connection can be established.  This depends on which, if any,
    /// [`crate::address_lookup::AddressLookup`]s were configured using [`Builder::address_lookup`].  The Address Lookup
    /// service will also be used if the remote endpoint is not reachable on the provided direct
    /// addresses and there is no [`RelayUrl`].
    ///
    /// If addresses or relay servers are neither provided nor can be discovered, the
    /// connection attempt will fail with an error.
    ///
    /// The `alpn`, or application-level protocol identifier, is also required. The remote
    /// endpoint must support this `alpn`, otherwise the connection attempt will fail with
    /// an error.
    ///
    /// [`RelayUrl`]: crate::RelayUrl
    pub async fn connect(
        &self,
        endpoint_addr: impl Into<EndpointAddr>,
        alpn: &[u8],
    ) -> Result<Connection, ConnectError> {
        let endpoint_addr = endpoint_addr.into();
        let remote = endpoint_addr.id;
        let connecting = self
            .connect_with_opts(endpoint_addr, alpn, Default::default())
            .await?;
        let conn = connecting.await?;

        debug!(
            me = %self.id().fmt_short(),
            remote = %remote.fmt_short(),
            alpn = %String::from_utf8_lossy(alpn),
            "Connection established."
        );
        Ok(conn)
    }

    /// Starts a connection attempt with a remote [`Endpoint`].
    ///
    /// Like [`Endpoint::connect`] (see also its docs for general details), but allows for a more
    /// advanced connection setup with more customization in two aspects:
    /// 1. The returned future resolves to a [`Connecting`], which can be further processed into
    ///    a [`Connection`] by awaiting, or alternatively allows connecting with 0-RTT via
    ///    [`Connecting::into_0rtt`].
    ///    **Note:** Please read the documentation for `into_0rtt` carefully to assess
    ///    security concerns.
    /// 2. The [`QuicTransportConfig`] for the connection can be modified via the provided
    ///    [`ConnectOptions`].
    ///    **Note:** Please be aware that changing transport config settings may have adverse effects on
    ///    establishing and maintaining direct connections.  Carefully test settings you use and
    ///    consider this currently as still rather experimental.
    #[instrument(name = "connect", skip_all, fields(
        me = %self.id().fmt_short(),
        remote = tracing::field::Empty,
        alpn = %String::from_utf8_lossy(alpn).to_string(),
    ))]
    pub async fn connect_with_opts(
        &self,
        endpoint_addr: impl Into<EndpointAddr>,
        alpn: &[u8],
        options: ConnectOptions,
    ) -> Result<Connecting, ConnectWithOptsError> {
        if self.is_closed() {
            return Err(e!(ConnectWithOptsError::EndpointClosed));
        }

        let endpoint_addr: EndpointAddr = endpoint_addr.into();
        let endpoint_id = endpoint_addr.id;

        Span::current().record("remote", tracing::field::display(endpoint_id.fmt_short()));

        if let BeforeConnectOutcome::Reject =
            self.inner.hooks.before_connect(&endpoint_addr, alpn).await
        {
            return Err(e!(ConnectWithOptsError::LocallyRejected));
        }

        // Connecting to ourselves is not supported.
        ensure!(endpoint_id != self.id(), ConnectWithOptsError::SelfConnect);
        ensure!(!alpn.is_empty(), ConnectWithOptsError::InvalidAlpn);
        let connection_permit = self.inner.connection_admission.try_acquire().map_err(|_| {
            self.inner
                .metrics
                .socket
                .connection_capacity_rejections
                .inc();
            e!(ConnectWithOptsError::ConnectionCapacityFull)
        })?;

        event!(
            target: "krikos::_events::conn::connecting",
            tracing::Level::DEBUG,
            remote_id = %endpoint_id.fmt_short(),
            alpn = %String::from_utf8_lossy(alpn),
        );

        debug!(
            relay_url = ?endpoint_addr.relay_urls().next().cloned(),
            ip_addresses = ?endpoint_addr.ip_addrs().cloned().collect::<Vec<_>>(),
            "connecting",
        );

        let mapped_addr = self.inner.resolve_remote(endpoint_addr).await??;

        let transport_config = options
            .transport_config
            .map(|cfg| cfg.to_inner_arc())
            .unwrap_or(self.inner.static_config.transport_config.to_inner_arc());

        // Start connecting via noq. This will time out after 10 seconds if no reachable
        // address is available.

        let mut alpn_protocols = vec![alpn.to_vec()];
        alpn_protocols.extend(options.additional_alpns);
        let client_config = self
            .inner
            .static_config
            .create_client_config(alpn_protocols, transport_config.clone());

        let dest_addr = mapped_addr.private_socket_addr();
        let server_name = &tls::name::encode(endpoint_id);
        let lifetime = noq::ConnectionLifetimeToken::new(connection_permit);
        let connect = self.inner.noq_endpoint().connect_with_config_and_lifetime(
            client_config,
            dest_addr,
            server_name,
            lifetime,
        )?;

        Ok(Connecting::new(connect, self.clone(), endpoint_id))
    }

    /// Accepts an incoming connection on the endpoint.
    ///
    /// Only connections with the ALPNs configured in [`Builder::alpns`] will be accepted.
    /// If multiple ALPNs have been configured the ALPN can be inspected before accepting
    /// the connection using [`Connecting::alpn`].
    ///
    /// The returned future will yield `None` if the endpoint is closed by calling
    /// [`Endpoint::close`].
    pub fn accept(&self) -> Accept<'_> {
        Accept {
            inner: self.inner.noq_endpoint().accept(),
            ep: self.clone(),
        }
    }

    // # Getter methods for properties of this Endpoint itself.

    /// Returns the secret_key of this endpoint.
    pub fn secret_key(&self) -> &SecretKey {
        &self.inner.static_config.tls_config.secret_key
    }

    /// Returns the endpoint id of this endpoint.
    ///
    /// This ID is the unique addressing information of this endpoint and other peers must know
    /// it to be able to connect to this endpoint.
    pub fn id(&self) -> EndpointId {
        self.inner.static_config.tls_config.secret_key.public()
    }

    /// Returns this endpoint's finite task, connection, and actor capacities.
    pub fn limits(&self) -> EndpointLimits {
        self.inner.static_config.limits
    }

    /// Returns the current [`EndpointAddr`].
    /// As long as the endpoint was able to bind to a network interface, some
    /// local addresses will be available.
    ///
    /// The state of other fields depends on the state of networking and connectivity.
    /// Use the [`Endpoint::online`] method to ensure that the endpoint is considered
    /// "online" (has contacted a relay server) before calling this method, if you want
    /// to ensure that the `EndpointAddr` will contain enough information to allow this endpoint
    /// to be dialable by a remote endpoint over the internet.
    ///
    /// You can use the [`Endpoint::watch_addr`] method to get updates when the `EndpointAddr`
    /// changes.
    pub fn addr(&self) -> EndpointAddr {
        self.watch_addr().get()
    }

    /// Returns a [`Watcher`] for the current [`EndpointAddr`] for this endpoint.
    ///
    /// The observed [`EndpointAddr`] will have the current [`RelayUrl`] and direct addresses.
    ///
    /// ```no_run
    /// # #[cfg(with_crypto_provider)]
    /// # {
    /// # async fn wrapper() -> n0_error::Result<()> {
    /// use krikos::{Endpoint, Watcher, endpoint::presets};
    ///
    /// let endpoint = Endpoint::builder(presets::N0)
    ///     .alpns(vec![b"my-alpn".to_vec()])
    ///     .bind()
    ///     .await?;
    /// let endpoint_addr = endpoint.watch_addr().get();
    /// # let _ = endpoint_addr;
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    ///
    /// The [`Endpoint::online`] method can be used as a convenience method to
    /// understand if the endpoint has ever been considered "online". But after
    /// that initial call to [`Endpoint::online`], to understand if your
    /// endpoint is no longer able to be connected to by endpoints outside
    /// of the private or local network, watch for changes in its [`EndpointAddr`].
    /// If there are no `addrs` in the [`EndpointAddr`], you may not be dialable by other endpoints
    /// on the internet.
    ///
    /// The `EndpointAddr` will change as:
    /// - network conditions change
    /// - the endpoint connects to a relay server
    /// - the endpoint changes its preferred relay server
    /// - more addresses are discovered for this endpoint
    ///
    /// ## Closing behavior
    ///
    /// The returned watcher only becomes disconnected once the last clone of the [`Endpoint`]
    /// is dropped. Closing the endpoint does not disconnect the watcher. Thus, a stream created
    /// via [`Watcher::stream`] only terminates once the endpoint is fully dropped. To stop a task
    /// that loops over a watcher stream once the endpoint stops, combine with [`Self::closed`]:
    ///
    /// ```no_run
    /// # #[cfg(with_crypto_provider)]
    /// # {
    /// # use krikos::{Watcher, Endpoint, endpoint::presets};
    /// # use n0_future::StreamExt;
    /// # use tracing::info;
    /// # async fn wrapper() -> n0_error::Result<()> {
    /// let endpoint = Endpoint::bind(presets::N0).await?;
    /// // We want to watch address changes in a different task, and stop our task
    /// // once the endpoint stops.
    /// let mut addr_stream = endpoint.watch_addr().stream();
    /// let endpoint_closed = endpoint.closed();
    /// tokio::spawn(endpoint_closed.run_until(async move {
    ///     while let Some(addr) = addr_stream.next().await {
    ///         info!("our address changed: {addr:?}");
    ///     }
    ///     info!("endpoint closed");
    /// }));
    /// // Do fancy things, then close the endpoint.
    /// // Our task above will stop even if there are still clones of `Endpoint` alive somewhere.
    /// endpoint.close().await;
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    ///
    /// [`RelayUrl`]: crate::RelayUrl
    #[cfg(not(wasm_browser))]
    #[allow(deprecated)] // Locally observed addresses are trusted and this watcher is infallible.
    pub fn watch_addr(&self) -> impl n0_watcher::Watcher<Value = EndpointAddr> + use<> {
        let watch_addrs = self.inner.ip_addrs();
        let watch_relay = self.inner.home_relay();
        let endpoint_id = self.id();

        watch_addrs.or(watch_relay).map(move |(addrs, relays)| {
            EndpointAddr::from_parts(
                endpoint_id,
                relays
                    .into_iter()
                    .map(TransportAddr::Relay)
                    .chain(addrs.into_iter().map(|x| TransportAddr::Ip(x.addr))),
            )
        })
    }

    /// Returns a [`Watcher`] for the current [`EndpointAddr`] for this endpoint.
    ///
    /// When compiled to Wasm, this function returns a watcher that initializes
    /// with an [`EndpointAddr`] that only contains a relay URL, but no direct addresses,
    /// as there are no APIs for directly using sockets in browsers.
    ///
    /// The returned watcher only becomes disconnected once the last clone of the [`Endpoint`]
    /// is dropped. Closing the endpoint does not disconnect the watcher. Thus, a stream created
    /// via [`Watcher::stream`] only terminates once the endpoint stops. If you want to stop a
    /// task once the endpoint stops combine with [`Self::closed`].
    #[cfg(wasm_browser)]
    #[allow(deprecated)] // Locally configured relays are trusted and this watcher is infallible.
    pub fn watch_addr(&self) -> impl n0_watcher::Watcher<Value = EndpointAddr> + use<> {
        // In browsers, there will never be any direct addresses, so we wait
        // for the home relay instead. This makes the `EndpointAddr` have *some* way
        // of connecting to us.
        let watch_relay = self.inner.home_relay();
        let endpoint_id = self.id();
        watch_relay.map(move |mut relays| {
            EndpointAddr::from_parts(endpoint_id, relays.into_iter().map(TransportAddr::Relay))
        })
    }

    /// A convenience method that waits for the endpoint to be considered "online".
    ///
    /// This currently means at least one relay server has completed its
    /// connection handshake (i.e. the endpoint is registered and reachable
    /// via that relay). Merely selecting a relay URL is not sufficient.
    ///
    /// If no relays are configured, this will pend forever.
    ///
    /// This has no timeout, so if that is needed, you need to wrap it in a
    /// timeout. We recommend using a timeout close to
    /// [`crate::NET_REPORT_TIMEOUT`]s, so you can be sure that at least one
    /// net report has been attempted.
    ///
    /// To understand if the endpoint has gone back "offline",
    /// you must use the [`Endpoint::watch_addr`] method, to
    /// get information on the current relay and direct address information.
    ///
    /// In the common case where the endpoint's configured relay servers are
    /// only accessible via a wide area network (WAN) connection, this method
    /// will await indefinitely when the endpoint has no WAN connection. If you're
    /// writing an app that's designed to work without a WAN connection, defer
    /// any calls to `online` as long as possible, or avoid calling `online`
    /// entirely.
    ///
    /// The online method does not interact with [`crate::address_lookup::AddressLookup`]
    /// services, which means that any Address Lookup that relies on a WAN
    /// connection is independent of the endpoint's online status.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(with_crypto_provider)]
    /// # {
    /// # #[tokio::main]
    /// # async fn main() -> n0_error::Result<()> {
    /// # use krikos::{Endpoint, endpoint::presets};
    /// // After this await returns, the endpoint is bound to a local socket.
    /// // It can be dialed, but almost certainly hasn't finished picking a
    /// // relay.
    /// let endpoint = Endpoint::bind(presets::N0).await?;
    ///
    /// // After this await returns we have a connection to at least one relay
    /// // and holepunching should work as expected.
    /// endpoint.online().await;
    /// # Ok(()) }
    /// # }
    /// ```
    pub async fn online(&self) {
        let mut watcher = self.inner.home_relay_status();
        let mut value = watcher.get();
        loop {
            if value.into_iter().any(|status| status.is_connected()) {
                return;
            }
            value = match watcher.updated().await {
                Ok(value) => value,
                Err(_disconnected) => {
                    std::future::pending::<()>().await;
                    break;
                }
            }
        }
    }

    /// Returns a [`Watcher`] over the connection status of the endpoint's home relays.
    ///
    /// The watched value has one entry per home relay whose URL is known,
    /// and is empty when no relays are configured or before the endpoint has
    /// selected a home relay from the list of configured relays.
    /// The watcher updates whenever any home relay's connection status changes.
    /// See [`RelayStatus`] for the information available on each entry.
    ///
    /// The returned watcher only becomes disconnected once the last clone of
    /// the [`Endpoint`] is dropped. Closing the endpoint does not disconnect
    /// the watcher. To stop a task once the endpoint stops, combine with
    /// [`Self::closed`].
    pub fn home_relay_status(&self) -> impl Watcher<Value = Vec<RelayStatus>> + use<> {
        self.inner.home_relay_status()
    }

    /// Returns a [`Watcher`] for any net report runs from this [`Endpoint`].
    ///
    /// <div class="warning">
    ///
    /// This API is unstable and gated behind the `unstable-net-report` feature.
    /// It is not covered by semantic versioning guarantees and may change in any release
    /// without a major version bump.
    ///
    /// </div>
    ///
    /// A net report checks the network conditions of the [`Endpoint`], such as
    /// whether it is connected to the internet via IPv4 and/or IPv6, its NAT
    /// status, its latency to the relay servers, and its public addresses.
    ///
    /// The [`Endpoint`] continuously runs net reports to monitor if network
    /// conditions have changed. This [`Watcher`] will return the latest
    /// net report.
    ///
    /// When issuing the first call to this method the first report might
    /// still be underway, in this case the [`Watcher`] might not be initialized
    /// with [`Some`] value yet.  Once the net report has been successfully
    /// run, the [`Watcher`] will always return [`Some`] immediately, which
    /// is the most recently run net report.
    ///
    /// The returned watcher only becomes disconnected once the last clone of the [`Endpoint`]
    /// is dropped. Closing the endpoint does not disconnect the watcher. Thus, a stream created
    /// via [`Watcher::stream`] only terminates once the endpoint stops. If you want to stop a
    /// task once the endpoint stops combine with [`Self::closed`].
    ///
    /// # Examples
    ///
    /// To get the first report use [`Watcher::initialized`]:
    /// ```no_run
    /// # #[cfg(with_crypto_provider)]
    /// # {
    /// use krikos::{Endpoint, Watcher as _, endpoint::presets};
    ///
    /// # let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    /// # rt.block_on(async move {
    /// let ep = Endpoint::bind(presets::N0).await.unwrap();
    /// let _report = ep.net_report().initialized().await;
    /// # });
    /// # }
    /// ```
    #[cfg(feature = "unstable-net-report")]
    pub fn net_report(&self) -> impl Watcher<Value = Option<NetReport>> + use<> {
        self.inner.net_report()
    }

    /// Returns the local socket addresses on which the underlying sockets are bound.
    ///
    /// The [`Endpoint`] always binds on an IPv4 address and also tries to bind on an IPv6
    /// address if available.
    #[cfg(not(wasm_browser))]
    pub fn bound_sockets(&self) -> Vec<SocketAddr> {
        self.inner
            .local_addr()
            .into_iter()
            .filter_map(|addr| addr.into_socket_addr())
            .collect()
    }

    // # Methods for less common getters.
    //
    // Partially they return things passed into the builder.

    /// Returns the DNS resolver used in this [`Endpoint`].
    ///
    /// # Errors
    ///
    /// Returns an `EndpointError::Closed` error if the endpoint is closed.
    ///
    /// See [`Builder::dns_resolver`].
    #[cfg(not(wasm_browser))]
    pub fn dns_resolver(&self) -> Result<&DnsResolver, EndpointError> {
        if self.is_closed() {
            return Err(e!(EndpointError::Closed));
        }
        Ok(self.inner.dns_resolver())
    }

    /// Returns the [`rustls::ClientConfig`] used by the endpoint for connecting to external services.
    ///
    /// This might be useful for address lookup services or other functions
    /// that want to use the same trust anchors as krikos does for verifying the
    /// validity of TLS certificates presented by external services.
    ///
    /// Note that this TLS config is unrelated to how krikos validates the authenticity
    /// of krikos connections itself.
    ///
    /// The config is based on the trust anchors set via [`Builder::ca_tls_config`].
    pub fn tls_config(&self) -> &rustls::ClientConfig {
        &self.inner.tls_config
    }

    /// Returns the Address Lookup service, if configured.
    ///
    /// # Errors
    ///
    /// Returns a `EndpointError::Closed` error if the endpoint is closed.
    ///
    /// See [`Builder::address_lookup`].
    pub fn address_lookup(&self) -> Result<&AddressLookupServices, EndpointError> {
        if self.is_closed() {
            return Err(e!(EndpointError::Closed));
        }
        Ok(self.inner.address_lookup())
    }

    /// Returns metrics collected for this endpoint.
    ///
    /// The endpoint internally collects various metrics about its operation.
    /// The returned [`EndpointMetrics`] struct contains all of these metrics.
    ///
    /// You can access individual metrics directly by using the public fields:
    /// ```rust
    /// # use std::collections::BTreeMap;
    /// # use krikos::endpoint::{Endpoint, presets};
    /// # async fn wrapper() -> n0_error::Result<()> {
    /// let endpoint = Endpoint::bind(presets::N0).await?;
    /// assert_eq!(endpoint.metrics().socket.recv_datagrams.get(), 0);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`EndpointMetrics`] implements [`MetricsGroupSet`], and each field
    /// implements [`MetricsGroup`]. These traits provide methods to iterate over
    /// the groups in the set, and over the individual metrics in each group, without having
    /// to access each field manually. With these methods, it is straightforward to collect
    /// all metrics into a map or push their values to a metrics collector.
    ///
    /// For example, the following snippet collects all metrics into a map:
    /// ```rust
    /// # use std::collections::BTreeMap;
    /// # use iroh_metrics::{Metric, MetricsGroup, MetricValue, MetricsGroupSet};
    /// # use krikos::endpoint::{Endpoint, presets};
    /// # async fn wrapper() -> n0_error::Result<()> {
    /// let endpoint = Endpoint::bind(presets::N0).await?;
    /// let metrics: BTreeMap<String, MetricValue> = endpoint
    ///     .metrics()
    ///     .iter()
    ///     .map(|(group, metric)| {
    ///         let name = [group, metric.name()].join(":");
    ///         (name, metric.value())
    ///     })
    ///     .collect();
    ///
    /// assert_eq!(metrics["socket:recv_datagrams"], MetricValue::Counter(0));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// The metrics can also be encoded into the OpenMetrics text format, as used by Prometheus.
    /// To do so, use the [`iroh_metrics::Registry`], add the endpoint metrics to the
    /// registry with [`Registry::register_all`], and encode the metrics to a string with
    /// [`encode_openmetrics_to_string`]:
    /// ```rust
    /// # use iroh_metrics::{Registry, MetricsSource};
    /// # use krikos::endpoint::{Endpoint, presets};
    /// # async fn wrapper() -> n0_error::Result<()> {
    /// let endpoint = Endpoint::bind(presets::N0).await?;
    /// let mut registry = Registry::default();
    /// registry.register_all(endpoint.metrics());
    /// let s = registry.encode_openmetrics_to_string()?;
    /// assert!(s.contains(r#"TYPE socket_recv_datagrams counter"#));
    /// assert!(s.contains(r#"socket_recv_datagrams_total 0"#));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Through a registry, you can also add labels or prefixes to metrics with
    /// [`Registry::sub_registry_with_label`] or [`Registry::sub_registry_with_prefix`].
    /// Furthermore, the optional `iroh_metrics::service` module provides functions to start services
    /// to serve the metrics with a HTTP server, dump them to a file, or push them
    /// to a Prometheus gateway. Applications using these APIs must enable the `service` feature on
    /// their direct `iroh-metrics` dependency.
    ///
    /// For example, the following snippet launches an HTTP server that serves the metrics in the
    /// OpenMetrics text format:
    /// ```ignore
    /// # use std::sync::{Arc, RwLock};
    /// # use iroh_metrics::{Registry, MetricsSource};
    /// # use krikos::endpoint::{Endpoint, presets};
    /// # use n0_error::{StackResultExt, StdResultExt};
    /// # async fn wrapper() -> n0_error::Result<()> {
    /// // Create a registry, wrapped in a read-write lock so that we can register and serve
    /// // the metrics independently.
    /// let registry = Arc::new(RwLock::new(Registry::default()));
    /// // Spawn an OpenMetrics HTTP server backed by the registry.
    /// let addr = "0.0.0.0:9100".parse().unwrap();
    /// let metrics_server = iroh_metrics::service::MetricsServer::spawn(addr, registry.clone())
    ///     .await
    ///     .std_context("spawn metrics server")?;
    ///
    /// // Spawn an endpoint and add the metrics to the registry.
    /// let endpoint = Endpoint::bind(presets::N0).await?;
    /// registry.write().unwrap().register_all(endpoint.metrics());
    ///
    /// // Fetch the metrics via HTTP.
    /// let res = reqwest::get("http://localhost:9100/metrics")
    ///     .await
    ///     .std_context("get")?
    ///     .text()
    ///     .await
    ///     .std_context("text")?;
    ///
    /// assert!(res.contains(r#"TYPE socket_recv_datagrams counter"#));
    /// assert!(res.contains(r#"socket_recv_datagrams_total 0"#));
    /// # metrics_server.shutdown().await;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`Registry`]: iroh_metrics::Registry
    /// [`Registry::register_all`]: iroh_metrics::Registry::register_all
    /// [`Registry::sub_registry_with_label`]: iroh_metrics::Registry::sub_registry_with_label
    /// [`Registry::sub_registry_with_prefix`]: iroh_metrics::Registry::sub_registry_with_prefix
    /// [`encode_openmetrics_to_string`]: iroh_metrics::MetricsSource::encode_openmetrics_to_string
    /// [`MetricsGroup`]: iroh_metrics::MetricsGroup
    /// [`MetricsGroupSet`]: iroh_metrics::MetricsGroupSet
    #[cfg(feature = "metrics")]
    pub fn metrics(&self) -> &EndpointMetrics {
        self.internal_metrics()
    }

    pub(crate) fn internal_metrics(&self) -> &EndpointMetrics {
        &self.inner.metrics
    }

    /// Returns active-connection capacity utilization and rejection counters.
    pub fn connection_capacity_snapshot(&self) -> CapacitySnapshot {
        self.inner.connection_admission.snapshot()
    }

    /// Returns live-task capacity utilization and rejection counters.
    pub fn task_capacity_snapshot(&self) -> TaskCapacitySnapshot {
        self.inner.runtime_task_capacity_snapshot()
    }

    /// Returns Noq's bounded internal connection and event-queue diagnostics.
    pub fn noq_event_queue_stats(&self) -> noq::EventQueueStats {
        self.inner.noq_endpoint().event_queue_stats()
    }

    /// Returns addressing information about a recently used remote endpoint.
    ///
    /// The returned [`RemoteInfo`] contains a list of all transport addresses for the remote
    /// that we know about. This is a snapshot in time and not a watcher.
    ///
    /// Returns `None` if the endpoint doesn't have information about the remote or if the endpoint is closed.
    /// When remote endpoints are no longer used, our endpoint will keep information around
    /// for a little while, and then drop it. Afterwards, this will return `None`.
    pub async fn remote_info(&self, endpoint_id: EndpointId) -> Option<RemoteInfo> {
        if self.is_closed() {
            return None;
        }
        self.inner.remote_info(endpoint_id).await
    }

    // # Methods for less common state updates.

    /// Notifies the system of potential network changes.
    ///
    /// On many systems krikos is able to detect network changes by itself, however
    /// some systems like android do not expose this functionality to native code.
    /// Android does however provide this functionality to Java code.  This
    /// function allows for notifying krikos of any potential network changes like
    /// this.
    ///
    /// Even when the network did not change, or krikos was already able to detect
    /// the network change itself, there is no harm in calling this function.
    ///
    /// If the endpoint is closed, this method will log a warning and ignore the request.
    pub async fn network_change(&self) {
        if self.is_closed() {
            debug!("Attempting to notify a closed endpoint about a network change. Ignoring.");
            return;
        }
        self.inner.network_change().await;
    }

    // # Methods to update internal state.

    /// Sets the initial user-defined data to be published in Address Lookups for this endpoint.
    ///
    /// If the user-defined data passed to this function is different to the previous one,
    /// the endpoint will republish its endpoint info to the configured Address Lookups.
    ///
    /// See also [`Builder::user_data_for_address_lookup`] for setting an initial value when
    /// building the endpoint.
    ///
    /// If the endpoint is closed, this method will log a warning and ignore the
    /// request.
    pub fn set_user_data_for_address_lookup(&self, user_data: Option<UserData>) {
        if self.is_closed() {
            warn!("Attempting to set user data for a closed endpoint. Ignoring.");
            return;
        }
        self.inner.set_user_data_for_address_lookup(user_data);
    }

    // # Methods for terminating the endpoint.

    /// Closes the QUIC endpoint and the socket.
    ///
    /// This will close any remaining open [`Connection`]s with an error code
    /// of `0` and an empty reason.  Though it is best practice to close those
    /// explicitly before with a custom error code and reason.
    ///
    /// It will then make a best effort to wait for all close notifications to be
    /// acknowledged by the peers, re-transmitting them if needed. This ensures the
    /// peers are aware of the closed connections instead of having to wait for a timeout
    /// on the connection. Once all connections are closed or timed out, the future
    /// finishes.
    ///
    /// The maximum time-out that this future will wait for depends on QUIC transport
    /// configurations of non-drained connections at the time of calling, and their current
    /// estimates of round trip time. With default parameters and a conservative estimate
    /// of round trip time, this call's future should take 3 seconds to resolve in cases of
    /// bad connectivity or failed connections. In the usual case, this call's future should
    /// return much more quickly.
    ///
    /// It is highly recommended you *do* wait for this close call to finish, if possible.
    /// Not doing so will make connections that were still open while closing the endpoint
    /// time out on the remote end. Thus remote ends will assume connections to have failed
    /// even if all application data was transmitted successfully.
    ///
    /// Note: Someone used to closing TCP sockets might wonder why it is necessary to wait
    /// for timeouts when closing QUIC endpoints, while they don't have to do this for TCP
    /// sockets. This is due to QUIC and its acknowledgments being implemented in user-land,
    /// while TCP sockets usually get closed and drained by the operating system in the
    /// kernel during the "Time-Wait" period of the TCP socket.
    ///
    /// Be aware however that the underlying UDP sockets are only closed once all clones of
    /// the respective [`Endpoint`] are dropped.
    pub async fn close(&self) {
        self.inner.close().await;
    }

    /// Check if this endpoint is still alive, or already closed.
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Returns a future that resolves once the endpoint closes.
    ///
    /// The returned future does not contain a clone or reference to the [`Endpoint`],
    /// so keeping the returned future alive does not prevent the endpoint from being dropped.
    ///
    /// To run a task and stop it once the endpoint closes, you can use
    /// [`EndpointClosed::run_until`]:
    /// ```no_run
    /// # #[cfg(with_crypto_provider)]
    /// # {
    /// # use krikos::endpoint::{Endpoint, presets};
    /// # async fn wrapper() -> n0_error::Result<()> {
    /// let endpoint = Endpoint::bind(presets::N0).await?;
    /// tokio::spawn(endpoint.closed().run_until(async move {
    ///     // the future will be aborted once the endpoint closes.
    /// }));
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    pub fn closed(&self) -> EndpointClosed {
        EndpointClosed {
            inner: self.inner.closed(),
        }
    }

    /// Create a [`ServerConfigBuilder`] for this endpoint that includes the given alpns.
    ///
    /// Use the [`ServerConfigBuilder`] to customize the [`ServerConfig`] connection configuration
    /// for a connection accepted using the [`Incoming::accept_with`] method.
    pub fn create_server_config_builder(&self, alpns: Vec<Vec<u8>>) -> ServerConfigBuilder {
        let inner = self.inner.static_config.create_server_config(alpns);
        ServerConfigBuilder::new(inner, self.inner.static_config.transport_config.clone())
    }

    // # Remaining private methods

    /// Translates a raw [`SocketAddr`] (which may be a synthetic mapped address) into
    /// a transport address.
    pub(crate) fn to_transport_addr(&self, addr: SocketAddr) -> crate::socket::transports::Addr {
        self.inner.to_transport_addr(addr)
    }

    #[cfg(all(test, with_crypto_provider))]
    pub(crate) fn inner(&self) -> Result<Arc<EndpointInner>, EndpointError> {
        if self.is_closed() {
            return Err(e!(EndpointError::Closed));
        }
        Ok(self.inner.clone())
    }
}
