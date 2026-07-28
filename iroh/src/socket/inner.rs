use super::*;

/// Error returned when the endpoint state actor stopped while waiting for a reply.
#[stack_error(add_meta, derive)]
#[error("endpoint state actor stopped")]
#[derive(Clone)]
pub(crate) struct RemoteStateActorStoppedError;

#[stack_error(derive, add_meta, from_sources)]
#[derive(Clone)]
pub(crate) enum RemoteStateRegistrationError {
    #[error("endpoint state actor stopped")]
    ActorStopped,
    #[error("remote-state actor admission failed")]
    Admission {
        #[error(from)]
        source: RemoteStateAdmissionError,
    },
}

impl From<mpsc::error::SendError<RemoteStateMessage>> for RemoteStateActorStoppedError {
    #[track_caller]
    fn from(_value: mpsc::error::SendError<RemoteStateMessage>) -> Self {
        Self::new()
    }
}

/// Inner state for an iroh [`crate::Endpoint`].
///
/// Dereferences to [`Socket`], and handles closing.
#[derive(Debug, derive_more::Deref)]
pub(crate) struct EndpointInner {
    #[deref(forward)]
    sock: Arc<Socket>,
    // empty when shutdown
    #[cfg(wasm_browser)]
    actor_task: Mutex<Option<AbortOnDropHandle<()>>>,
    // empty when shutdown
    #[cfg(not(wasm_browser))]
    actor_task: Mutex<Option<iroh_runtime::OwnedTaskHandle>>,
    /// Channel to send to the internal actor.
    actor_sender: mpsc::Sender<ActorMessage>,
    // noq endpoint
    endpoint: noq::Endpoint,
    // Runtime used by noq
    runtime: Arc<Runtime>,
    pub(crate) connection_admission: Arc<crate::endpoint::limits::AdmissionLedger>,
    /// Static configuration for the endpoint.
    pub(crate) static_config: StaticConfig,
}

impl Drop for EndpointInner {
    fn drop(&mut self) {
        if self.sock.is_closed() {
            return;
        }
        tracing::error!(
            "Endpoint dropped without calling `Endpoint::close`. Aborting ungracefully."
        );
        self.abort();
    }
}

/// This coordinates the shutdown of the [`Socket`] and all its tasks.
///
/// It also tightly binds to the [`EndpointInner`] and [`Actor`] closing as that is where
/// most of the logic lives.
#[derive(Debug)]
struct ShutdownState {
    /// Token that is cancelled at the moment [`crate::Endpoint::close`] is called.
    ///
    /// Currently cancelled from [`EndpointInner::close`].
    at_close_start: CancellationToken,
    /// Token that is cancelled once the [`noq::Endpoint`] is drained.
    ///
    /// Only 100ms after this is cancelled will the [`Actor`] task be cancelled, it should
    /// have exited already by then as it is considered an error if it was still running.
    at_endpoint_closed: CancellationToken,
    /// Set if the endpoint is closed and all tasks are stopped.
    ///
    /// This is only set once both [`Self::at_close_start`] and [`Self::at_endpoint_closed`]
    /// are cancelled **and** the [`Actor`] task is no longer running.
    closed: AtomicBool,
}

impl Default for ShutdownState {
    fn default() -> Self {
        Self {
            at_close_start: CancellationToken::new(),
            at_endpoint_closed: CancellationToken::new(),
            closed: AtomicBool::new(false),
        }
    }
}

impl ShutdownState {
    /// Whether the endpoint has started closing, or is already closed.
    ///
    /// This is true once [`crate::Endpoint::close`] is called, and remains true forever
    /// after. Tasks might still be shutting down.
    fn is_closing(&self) -> bool {
        self.at_close_start.is_cancelled()
    }

    /// Whether the endpoint is fully closed and all tasks stopped.
    ///
    /// The endpoint will be drained, all transports and sockets will be closed.
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }
}

/// Iroh connectivity layer.
///
/// This is responsible for routing packets to endpoints based on endpoint IDs, it will initially
/// route packets via a relay and transparently try and establish an endpoint-to-endpoint
/// connection and upgrade to it.  It will also keep looking for better connections as the
/// network details of both endpoints change.
///
/// It is usually only necessary to use a single [`Socket`] instance in an application, it
/// means any QUIC endpoints on top will be sharing as much information about endpoints as
/// possible.
#[derive(Debug)]
pub(crate) struct Socket {
    /// Read-only view of the per-remote `RemoteStateActor` inboxes.
    ///
    /// Lets callers send to an existing `RemoteStateActor` without going through
    /// the socket actor.
    ///
    /// A missing entry means no actor is running for that remote. Spawning new
    /// `RemoteStateActor`s must go through the socket actor channel.
    remote_actors: ReadOnlyMap<EndpointId, mpsc::Sender<RemoteStateMessage>>,

    // - Shutdown Management
    shutdown: ShutdownState,

    // - Networking Info
    /// Our discovered direct addresses.
    direct_addrs: DiscoveredDirectAddrs,
    /// Our latest net-report
    pub(super) net_report: Watchable<(Option<Report>, UpdateReason)>,
    /// If the last net_report report, reports IPv6 to be available.
    pub(super) ipv6_reported: Arc<AtomicBool>,
    /// Maps for resolving mapped addrs to/from IP and relay addresses.
    pub(super) mapped_addrs: MappedAddrs,

    /// Local addresses
    local_addrs_watch: LocalAddrsWatch,
    home_relay_watch: HomeRelayWatcher,
    /// Currently bound IP addresses of all sockets
    #[cfg(not(wasm_browser))]
    ip_bind_addrs: Vec<SocketAddr>,
    /// The DNS resolver to be used in this socket.
    #[cfg(not(wasm_browser))]
    pub(super) dns_resolver: DnsResolver,
    relay_map: RelayMap,

    /// Optional Address Lookup
    address_lookup: address_lookup::AddressLookupServices,
    /// Optional user-defined discover data.
    address_lookup_user_data: RwLock<Option<UserData>>,
    /// Explicitly configured external addresses to advertise.
    pub(super) configured_addrs: RwLock<BTreeSet<SocketAddr>>,

    pub(crate) tls_config: rustls::ClientConfig,

    /// Metrics
    pub(crate) metrics: EndpointMetrics,
    pub(crate) hooks: EndpointHooksList,
    /// Tracing span for this endpoint.
    pub(crate) span: Span,
}

impl Socket {
    /// Returns the relay endpoint we are connected to, that has the best latency.
    ///
    /// If `None`, then we are not connected to any relay endpoints.
    pub(crate) fn my_relay(&self) -> Option<RelayUrl> {
        self.local_addr().into_iter().find_map(|a| {
            if let transports::Addr::Relay(url, _) = a {
                Some(url)
            } else {
                None
            }
        })
    }

    /// Whether the iroh endpoint is closed and all its actors stopped.
    pub(crate) fn is_closed(&self) -> bool {
        self.shutdown.is_closed()
    }

    /// Whether [`crate::Endpoint::close`] has been called.
    fn is_closing(&self) -> bool {
        self.shutdown.is_closing()
    }

    /// Returns a future that resolves once endpoint shutdown has started.
    pub(crate) fn closed(&self) -> WaitForCancellationFutureOwned {
        self.shutdown.at_close_start.clone().cancelled_owned()
    }

    /// Get the cached version of addresses.
    pub(crate) fn local_addr(&self) -> Vec<transports::Addr> {
        self.local_addrs_watch.clone().get()
    }

    #[cfg(not(wasm_browser))]
    pub(super) fn ip_bind_addrs(&self) -> &[SocketAddr] {
        &self.ip_bind_addrs
    }

    pub(super) fn ip_local_addrs(&self) -> impl Iterator<Item = SocketAddr> + use<> {
        self.local_addr()
            .into_iter()
            .filter_map(|addr| addr.into_socket_addr())
    }

    /// Tries to send a [`RemoteStateMessage`] to the `RemoteStateActor` for given [`EndpointId`].
    ///
    /// Returns an error if there currently is no remote state actor running for this, or when it
    /// is currently shutting down.
    pub(crate) fn try_send_remote_state_msg(
        &self,
        endpoint_id: EndpointId,
        message: RemoteStateMessage,
    ) -> Result<(), RemoteStateMessage> {
        let Some(sender) = self.remote_actors.get(&endpoint_id) else {
            return Err(message);
        };
        sender.try_send(message).map_err(|err| err.into_inner())
    }

    /// Returns a [`Watcher`] for this socket's direct addresses.
    ///
    /// The [`Socket`] continuously monitors the direct addresses, the network addresses
    /// it might be able to be contacted on, for changes.  Whenever changes are detected
    /// this [`Watcher`] will yield a new list of addresses.
    ///
    /// Upon the first creation on the [`Socket`] it may not yet have completed a first
    /// net report to discover IP addresses, in this case the current item in this [`Watcher`] will be
    /// [`None`].  Once the first set of ip addresses are discovered the [`Watcher`] will
    /// store [`Some`] set of addresses.
    ///
    /// To get the current direct addresses, use [`Watcher::initialized`].
    ///
    /// [`Watcher`]: n0_watcher::Watcher
    /// [`Watcher::initialized`]: n0_watcher::Watcher::initialized
    pub(crate) fn ip_addrs(&self) -> n0_watcher::Direct<BTreeSet<DirectAddr>> {
        self.direct_addrs.watch()
    }

    /// Returns a [`Watcher`] for this socket's net-report.
    ///
    /// The [`Socket`] continuously monitors the network conditions for changes.
    /// Whenever changes are detected this [`Watcher`] will yield a new report.
    ///
    /// Upon the first creation on the [`Socket`] it may not yet have completed
    /// a first net-report. In this case, the current item in this [`Watcher`] will
    /// be [`None`].  Once the first report has been run, the [`Watcher`] will
    /// store [`Some`] report.
    ///
    /// To get the current `net-report`, use [`Watcher::initialized`].
    ///
    /// [`Watcher`]: n0_watcher::Watcher
    /// [`Watcher::initialized`]: n0_watcher::Watcher::initialized
    #[cfg(feature = "unstable-net-report")]
    pub(crate) fn net_report(&self) -> impl Watcher<Value = Option<Report>> + use<> {
        self.net_report.watch().map(|(r, _)| r)
    }

    /// Watch for changes to the home relay.
    ///
    /// Note that this can be used to wait for the initial home relay to be known using
    /// [`Watcher::initialized`].
    pub(crate) fn home_relay(&self) -> impl Watcher<Value = Vec<RelayUrl>> + use<> {
        self.local_addrs_watch.clone().map(|addrs| {
            addrs
                .into_iter()
                .filter_map(|addr| {
                    if let transports::Addr::Relay(url, _) = addr {
                        Some(url)
                    } else {
                        None
                    }
                })
                .collect()
        })
    }

    pub(crate) fn home_relay_status(&self) -> impl Watcher<Value = Vec<RelayStatus>> + use<> {
        self.home_relay_watch.clone()
    }

    /// Stores a new set of direct addresses.
    ///
    /// If the direct addresses have changed from the previous set, they are published to
    /// the address lookup system.
    pub(super) fn store_direct_addresses(&self, addrs: BTreeSet<DirectAddr>) {
        let updated = self.direct_addrs.update(addrs);
        if updated {
            self.publish_my_addr();
        }
    }

    /// Get a reference to the DNS resolver used in this [`Socket`].
    #[cfg(not(wasm_browser))]
    pub(crate) fn dns_resolver(&self) -> &DnsResolver {
        &self.dns_resolver
    }

    /// Translates a raw [`SocketAddr`] (which may be a synthetic mapped address) into
    /// a [`transports::Addr`].
    ///
    /// For regular IP addresses this returns `Addr::Ip`. For synthetic relay-mapped
    /// IPv6 addresses this performs a reverse lookup and returns `Addr::Relay`.
    ///
    /// This lookup only makes sense for a remote address of the
    /// underlying QUIC connection.
    ///
    /// If you call this with a mapped address for which no mapping exists,
    /// it will return the address as an `Addr::Ip`.
    pub(crate) fn to_transport_addr(&self, addr: SocketAddr) -> transports::Addr {
        remote_map::to_transport_addr(
            addr,
            &self.mapped_addrs.relay_addrs,
            &self.mapped_addrs.custom_addrs,
        )
        .unwrap_or(transports::Addr::Ip(addr))
    }

    pub(crate) fn to_local_transport_addr(
        &self,
        local_ip: Option<IpAddr>,
        remote_addr: SocketAddr,
    ) -> LocalTransportAddr {
        let remote_addr = self.to_transport_addr(remote_addr);
        LocalTransportAddr::from_noq_local_ip(
            local_ip,
            &remote_addr,
            &self.mapped_addrs.custom_addrs,
        )
    }

    /// Reference to the internal Address Lookup
    pub(crate) fn address_lookup(&self) -> &address_lookup::AddressLookupServices {
        &self.address_lookup
    }

    /// Updates the user-defined Address Lookup data for this endpoint.
    pub(crate) fn set_user_data_for_address_lookup(&self, user_data: Option<UserData>) {
        let mut guard = self
            .address_lookup_user_data
            .write()
            .expect("lock poisened");
        if *guard != user_data {
            *guard = user_data;
            drop(guard);
            self.publish_my_addr();
        }
    }

    /// Process datagrams received from all the transports.
    ///
    /// All the `bufs` and `metas` should have initialized packets in them.
    ///
    /// This fixes up the datagrams to use the correct [`MultipathMappedAddr`] and extracts
    /// DISCO packets, processing them inside the socket.
    ///
    /// [`MultipathMappedAddr`]: mapped_addrs::MultipathMappedAddr
    pub(super) fn process_datagrams(
        &self,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        recv_infos: &[transports::RecvInfo],
    ) {
        assert_eq!(bufs.len(), metas.len(), "non matching bufs & metas");
        assert_eq!(
            bufs.len(),
            recv_infos.len(),
            "non matching bufs & recv_infos"
        );

        // zip is slow :(
        for i in 0..metas.len() {
            let noq_meta = &mut metas[i];
            let recv_info = &recv_infos[i];
            let remote_addr = recv_info.remote();
            let datagram_count = if noq_meta.stride == 0 {
                if noq_meta.len > 0 {
                    warn!(
                        src = ?remote_addr,
                        len = noq_meta.len,
                        "received datagram with stride=0 but len>0",
                    );
                    // fix the weird len
                    noq_meta.len = 0;
                }
                // one empty datagram
                1
            } else {
                noq_meta.len.div_ceil(noq_meta.stride)
            };
            self.metrics
                .socket
                .recv_datagrams
                .inc_by(datagram_count as _);
            if noq_meta.len > noq_meta.stride {
                trace!(
                    src = ?remote_addr,
                    len = noq_meta.len,
                    stride = %noq_meta.stride,
                    datagram_count,
                    "GRO datagram received",
                );
                self.metrics.socket.recv_gro_datagrams.inc();
            } else {
                trace!(src = ?remote_addr, len = noq_meta.len, "datagram received");
            }
            match remote_addr {
                transports::Addr::Ip(SocketAddr::V4(..)) => {
                    self.metrics.socket.recv_data_ipv4.inc_by(noq_meta.len as _);
                }
                transports::Addr::Ip(SocketAddr::V6(..)) => {
                    self.metrics.socket.recv_data_ipv6.inc_by(noq_meta.len as _);
                }
                transports::Addr::Relay(src_url, src_node) => {
                    self.metrics
                        .socket
                        .recv_data_relay
                        .inc_by(noq_meta.len as _);

                    // Fill in the correct mapped address
                    let mapped_addr = self
                        .mapped_addrs
                        .relay_addrs
                        .get(&(src_url.clone(), *src_node));
                    noq_meta.addr = mapped_addr.private_socket_addr();
                }
                transports::Addr::Custom(remote) => {
                    self.metrics
                        .socket
                        .recv_data_custom
                        .inc_by(noq_meta.len as _);
                    // Fill in the correct mapped address
                    let mapped_addr = self.mapped_addrs.custom_addrs.get(remote);
                    noq_meta.addr = mapped_addr.private_socket_addr();
                    if let Some(local) = recv_info.local() {
                        let local_mapped = self.mapped_addrs.custom_addrs.get(local);
                        noq_meta.dst_ip = Some(local_mapped.private_socket_addr().ip());
                    }
                }
            }
        }
    }

    /// Publishes our address to an address lookup service, if configured.
    ///
    /// Called whenever our addresses or home relay endpoint changes.
    pub(super) fn publish_my_addr(&self) {
        let relay_url = self.my_relay();
        let mut addrs: Vec<_> = self
            .direct_addrs
            .sockaddrs()
            .map(TransportAddr::Ip)
            .collect();

        let user_data = self
            .address_lookup_user_data
            .read()
            .expect("lock poisened")
            .clone();
        if relay_url.is_none() && addrs.is_empty() && user_data.is_none() {
            // do not bother publishing if we don't have any information
            return;
        }
        if let Some(url) = relay_url {
            addrs.push(TransportAddr::Relay(url));
        }

        let mut data = EndpointData::new(addrs);
        data.set_user_data(user_data);
        self.address_lookup.publish(&data);
    }
}

impl EndpointInner {
    #[cfg(all(test, not(wasm_browser)))]
    pub(crate) fn runtime_context(&self) -> &Arc<iroh_runtime::RuntimeContext> {
        self.runtime.context()
    }

    #[cfg(all(test, not(wasm_browser)))]
    pub(crate) fn runtime_task_snapshot(&self) -> iroh_runtime::TaskGroupSnapshot {
        self.runtime.task_snapshot()
    }

    pub(crate) fn runtime_task_capacity_snapshot(&self) -> crate::endpoint::TaskCapacitySnapshot {
        self.runtime.task_capacity_snapshot()
    }

    /// Creates a [`EndpointInner`].
    pub(crate) async fn bind(opts: Options) -> Result<Self, BindError> {
        // Use the current span as the main span for all tasks spawned in this endpoint.
        // `EndpointInner::bind` is not public and only called from `crate::endpoint::Builder::bind`,
        // which instruments the call with a span created for this purpose.
        let span = tracing::Span::current();

        let Options {
            secret_key,
            transports: transport_configs,
            address_lookup_user_data,
            #[cfg(not(wasm_browser))]
            dns_resolver,
            #[cfg(not(wasm_browser))]
            runtime_context,
            #[cfg(not(wasm_browser))]
            ip_socket_factory,
            #[cfg(not(wasm_browser))]
            network_monitor,
            #[cfg(not(wasm_browser))]
            simulation_port_mapper,
            #[cfg(not(wasm_browser))]
            simulation_relay_connector,
            #[cfg(not(wasm_browser))]
            simulation_preferred_relay,
            #[cfg(not(wasm_browser))]
            simulation_reset_key,
            proxy_url,
            server_config,
            tls_config,
            metrics,
            hooks,
            path_selector,
            portmapper_config,
            net_report_config,
            static_config,
            configured_addrs,
            limits,
        } = opts;

        #[cfg(not(wasm_browser))]
        let runtime = Arc::new(Runtime::new_with_limits(
            secret_key.public(),
            runtime_context.clone(),
            limits,
        ));
        #[cfg(wasm_browser)]
        let runtime = Arc::new(Runtime::new_with_limits(secret_key.public(), limits));
        let connection_admission =
            crate::endpoint::limits::AdmissionLedger::new(limits.max_connections());

        let address_lookup = address_lookup::AddressLookupServices::default();
        #[cfg(not(wasm_browser))]
        let port_mapper = portmapper::create_client(&portmapper_config, simulation_port_mapper);
        #[cfg(wasm_browser)]
        let port_mapper = portmapper::create_client(&portmapper_config);

        let relay_transport_configs: Vec<_> = transport_configs
            .iter()
            .filter(|t| matches!(t, TransportConfig::Relay { .. }))
            .collect();

        // Currently we only support a single relay transport
        if relay_transport_configs.len() > 1 {
            bail!(BindError::InvalidTransportConfig);
        }
        let relay_map = relay_transport_configs
            .iter()
            .filter_map(|t| {
                #[allow(irrefutable_let_patterns)]
                if let TransportConfig::Relay { relay_map, .. } = t {
                    Some(relay_map.clone())
                } else {
                    None
                }
            })
            .next()
            .unwrap_or_else(RelayMap::empty);

        let ipv6_reported = Arc::new(AtomicBool::new(false));

        #[cfg(not(wasm_browser))]
        let has_simulation_relay_connector = simulation_relay_connector.is_some();

        let relay_actor_config = RelayActorConfig {
            my_relay: HomeRelayWatch::default(),
            secret_key: secret_key.clone(),
            #[cfg(not(wasm_browser))]
            dns_resolver: dns_resolver.clone(),
            proxy_url: proxy_url.clone(),
            ipv6_reported: ipv6_reported.clone(),
            tls_config: tls_config.clone(),
            metrics: metrics.socket.clone(),
            relay_map: relay_map.clone(),
            #[cfg(not(wasm_browser))]
            relay_connector: simulation_relay_connector,
            #[cfg(not(wasm_browser))]
            initial_relay: simulation_preferred_relay,
            limits,
        };

        let shutdown_state = ShutdownState::default();
        let shutdown_token = shutdown_state.at_endpoint_closed.child_token();

        let transports = Transports::bind(
            &transport_configs,
            relay_actor_config,
            &metrics,
            shutdown_token.child_token(),
            #[cfg(not(wasm_browser))]
            runtime.clone(),
            #[cfg(not(wasm_browser))]
            ip_socket_factory,
        )
        .map_err(|err| e!(BindError::Sockets, err))?;

        if let Some(v4_port) = transports.local_addrs().into_iter().find_map(|t| {
            if let transports::Addr::Ip(SocketAddr::V4(addr)) = t {
                Some(addr.port())
            } else {
                None
            }
        }) {
            // NOTE: we can end up with a zero port if `netwatch::UdpSocket::socket_addr` fails
            match v4_port.try_into() {
                Ok(non_zero_port) => {
                    port_mapper.update_local_port(non_zero_port);
                }
                Err(_zero_port) => debug!("Skipping port mapping with zero local port"),
            }
        }

        let (actor_sender, actor_receiver) = mpsc::channel(256);

        #[cfg(not(wasm_browser))]
        let has_ipv6_transport = transports
            .ip_bind_addrs()
            .into_iter()
            .any(|addr| addr.is_ipv6());

        #[cfg(not(wasm_browser))]
        let has_ip_transports = !transports.ip_bind_addrs().is_empty();

        let direct_addrs = DiscoveredDirectAddrs::default();

        let remote_map = {
            RemoteMap::new(
                metrics.socket.clone(),
                direct_addrs.watch(),
                address_lookup.clone(),
                shutdown_token.child_token(),
                path_selector,
                span.clone(),
                limits,
                #[cfg(not(wasm_browser))]
                runtime.clone(),
            )
        };

        let home_relay_watch = transports.home_relay_watch();

        let sock = Arc::new(Socket {
            remote_actors: remote_map.senders(),
            shutdown: shutdown_state,
            ipv6_reported,
            mapped_addrs: remote_map.mapped_addrs.clone(),
            address_lookup,
            relay_map: relay_map.clone(),
            address_lookup_user_data: RwLock::new(address_lookup_user_data),
            configured_addrs: RwLock::new(configured_addrs),
            direct_addrs,
            net_report: Watchable::new((None, UpdateReason::None)),
            #[cfg(not(wasm_browser))]
            dns_resolver: dns_resolver.clone(),
            metrics: metrics.clone(),
            local_addrs_watch: transports.local_addrs_watch(),
            home_relay_watch,
            #[cfg(not(wasm_browser))]
            ip_bind_addrs: transports.ip_bind_addrs(),
            tls_config: tls_config.clone(),
            hooks,
            span: span.clone(),
        });

        #[cfg(not(wasm_browser))]
        let reset_key = match simulation_reset_key {
            Some(key) => Blake3HmacKey::from_key(key),
            None => Blake3HmacKey::new(&mut rand::rng()),
        };
        #[cfg(wasm_browser)]
        let reset_key = Blake3HmacKey::new(&mut rand::rng());
        let mut endpoint_config = noq::EndpointConfig::new(Arc::new(reset_key));
        #[cfg(not(wasm_browser))]
        {
            let seed = noq_behavioral_seed(&runtime_context, secret_key.public())
                .map_err(|err| e!(BindError::RuntimeContext, anyerr!(err)))?;
            endpoint_config.rng_seed(Some(seed));
            if let Some(reset_key) = simulation_reset_key {
                endpoint_config.cid_generator(Arc::new(move || {
                    Box::new(DeterministicSimulationConnectionIdGenerator::new(reset_key))
                }));
            }
        }
        // Setting this to false means that noq will ignore packets that have the QUIC fixed bit
        // set to 0. The fixed bit is the 3rd bit of the first byte of a packet.
        // For performance reasons and to not rewrite buffers we pass non-QUIC UDP packets straight
        // through to noq. We set the first byte of the packet to zero, which makes noq ignore
        // the packet if grease_quic_bit is set to false.
        endpoint_config.grease_quic_bit(false);

        let local_addrs_watch = transports.local_addrs_watch();
        let transports_network_change = transports.create_network_change_sender();

        let endpoint = noq::Endpoint::new_with_abstract_socket_and_limits(
            endpoint_config,
            Some(server_config),
            Box::new(Transport::new(sock.clone(), transports)),
            runtime.clone(),
            limits.noq_event_limits(),
        )
        .map_err(|err| e!(BindError::CreateQuicEndpoint, err))?;

        #[cfg(not(wasm_browser))]
        let network_monitor: Arc<dyn crate::simulation::NetworkMonitor> = match network_monitor {
            Some(monitor) => monitor,
            None => Arc::new(
                crate::simulation::OsNetworkMonitor::new()
                    .await
                    .map_err(|err| e!(BindError::CreateNetmonMonitor, anyerr!(err)))?,
            ),
        };
        #[cfg(wasm_browser)]
        let network_monitor = netmon::Monitor::new()
            .await
            .map_err(|err| e!(BindError::CreateNetmonMonitor, anyerr!(err)))?;

        #[cfg(not(wasm_browser))]
        let net_report_config = {
            // Set a `QuicConfig` for address discovery (QAD), but only if we have IP transports.
            //
            // If there are no IP transports configured, then we don't set a QuicConfig.
            // If we would, the `noq::Endpoint` passed along will not have IP connectivity,
            // and the QAD probes that connect to the relay's QUIC endpoints would time out
            // because all outgoing packets to IP destinations would be dropped.
            let qad_config =
                (has_ip_transports && !has_simulation_relay_connector).then(|| QuicConfig {
                    ep: endpoint.clone(),
                    client_config: tls_config.clone(),
                    ipv4: true,
                    ipv6: has_ipv6_transport,
                    connection_admission: connection_admission.clone(),
                });
            net_report::Options::new(tls_config.clone())
                .quic_config(qad_config)
                .net_report_config(net_report_config)
        };

        #[cfg(wasm_browser)]
        let net_report_config = net_report::Options::default().net_report_config(net_report_config);

        #[cfg(not(wasm_browser))]
        let net_report_relay_map = if has_simulation_relay_connector {
            // The injected connector owns relay reachability. Probing its synthetic URLs through
            // OS UDP/HTTPS would escape the selected environment and cannot influence home-relay
            // selection, which is supplied explicitly by the simulation environment.
            RelayMap::empty()
        } else {
            relay_map.clone()
        };
        #[cfg(wasm_browser)]
        let net_report_relay_map = relay_map.clone();

        let net_reporter = net_report::Client::new(
            #[cfg(not(wasm_browser))]
            dns_resolver,
            net_report_relay_map,
            net_report_config,
            metrics.net_report.clone(),
        )
        .map_err(|source| e!(BindError::CreateQuicClient, source))?;

        let (direct_addr_done_tx, direct_addr_done_rx) = mpsc::channel(8);
        let direct_addr_update_state = DirectAddrUpdateState::new(
            sock.clone(),
            port_mapper,
            Arc::new(AsyncMutex::new(net_reporter)),
            relay_map,
            direct_addr_done_tx,
            sock.shutdown.at_close_start.child_token(),
            #[cfg(not(wasm_browser))]
            runtime.clone(),
        );

        let local_interfaces_watcher = network_monitor.interface_state();

        #[cfg(not(wasm_browser))]
        let mut re_stun_decisions = runtime
            .context()
            .decisions()
            .stream(&format!("endpoint/{}/socket/re-stun-period", runtime.id()))
            .map_err(|err| e!(BindError::RuntimeContext, anyerr!(err)))?;
        #[cfg(not(wasm_browser))]
        let periodic_re_stun_timer =
            new_re_stun_timer(runtime.context().clock(), false, re_stun_decisions.as_mut())
                .map_err(|err| e!(BindError::RuntimeContext, anyerr!(err)))?;
        #[cfg(wasm_browser)]
        let periodic_re_stun_timer = new_re_stun_timer(false);

        #[cfg_attr(not(wasm_browser), allow(unused_mut))]
        let mut actor = Actor {
            endpoint: endpoint.clone(),
            sock: sock.clone(),
            remote_map,
            periodic_re_stun_timer,
            #[cfg(not(wasm_browser))]
            re_stun_decisions,
            #[cfg(not(wasm_browser))]
            runtime_clock: runtime.context().clock(),
            network_monitor,
            local_interfaces_watcher,
            direct_addr_update_state,
            transports_network_change,
            direct_addr_done_rx,
            call_notify_quic_network_change: None,
        };
        // Initialize addresses
        #[cfg(not(wasm_browser))]
        actor.update_direct_addresses(None);

        let actor_future = actor
            .run(
                actor_receiver,
                shutdown_token.child_token(),
                local_addrs_watch,
            )
            .instrument(info_span!(parent: span, "actor"));
        #[cfg(not(wasm_browser))]
        let actor_task = runtime
            .spawn_owned(
                iroh_runtime::TaskKind::SocketActor,
                "socket-actor",
                Box::pin(actor_future),
            )
            .map_err(|err| e!(BindError::RuntimeContext, anyerr!(err)))?;
        #[cfg(wasm_browser)]
        let actor_task = AbortOnDropHandle::new(task::spawn(actor_future));

        let actor_task = Mutex::new(Some(actor_task));

        Ok(EndpointInner {
            sock,
            actor_sender,
            actor_task,
            endpoint,
            runtime,
            connection_admission,
            static_config,
        })
    }

    /// Returns a reference to the underlying [`noq::Endpoint`].
    pub(crate) fn noq_endpoint(&self) -> &noq::Endpoint {
        &self.endpoint
    }

    /// Closes the iroh endpoint.
    ///
    /// Only the first close does anything. Any later closes return nil.  Polling the socket
    /// ([`noq::AsyncUdpSocket::poll_recv`]) will return [`Poll::Pending`] indefinitely
    /// after this call.
    ///
    /// [`Poll::Pending`]: std::task::Poll::Pending
    #[instrument(skip_all, parent = self.sock.span.clone())]
    pub(crate) async fn close(&self) {
        if self.sock.is_closed() || self.sock.is_closing() {
            return;
        }
        trace!("socket closing...");

        // Cancel at_close_start token, which cancels running netreports.
        self.sock.shutdown.at_close_start.cancel();

        // Remove address lookup services
        self.sock.address_lookup().clear();

        // Initiate closing all connections, and refuse future connections.
        self.noq_endpoint().close(0u16.into(), b"");

        // In the history of this code, this call had been
        // - removed: https://github.com/n0-computer/iroh/pull/1753
        // - then added back in: https://github.com/n0-computer/iroh/pull/2227/files#diff-ba27e40e2986a3919b20f6b412ad4fe63154af648610ea5d9ed0b5d5b0e2d780R573
        // - then removed again: https://github.com/n0-computer/iroh/pull/3165
        // and finally added back in together with this comment.
        // So before removing this call, please consider carefully.
        // Among other things, this call tries its best to make sure that any queued close frames
        // (e.g. via the call to `endpoint.close(...)` above), are flushed out to the sockets
        // *and acknowledged* (or time out with the "probe timeout" of usually 3 seconds).
        // This allows the other endpoints for these connections to be notified to release
        // their resources, or - depending on the protocol - that all data was received.
        // With the current noq API, this is the only way to ensure protocol code can use
        // connection close codes, and close the endpoint properly.
        // If this call is skipped, then connections that protocols close just shortly before the
        // call to `Endpoint::close` will in most cases cause connection time-outs on remote ends.
        trace!("wait_all_draining start");
        self.noq_endpoint().wait_all_draining().await;
        trace!("wait_all_draining done");

        // Start cancellation of all actors.
        self.sock.shutdown.at_endpoint_closed.cancel();

        // MutexGuard is not held across await points
        let task = self.actor_task.lock().expect("poisoned").take();
        if let Some(task) = task {
            // give the tasks a moment to shutdown cleanly
            #[cfg(wasm_browser)]
            let shutdown_done = time::timeout(Duration::from_millis(100), async move {
                if let Err(err) = task.await {
                    warn!("unexpected error in task shutdown: {:?}", err);
                }
            })
            .await;
            #[cfg(wasm_browser)]
            match shutdown_done {
                Ok(_) => trace!("tasks finished in time, shutdown complete"),
                Err(time::Elapsed { .. }) => {
                    // Dropping the task will abort it
                    warn!("tasks didn't finish in time, aborting");
                }
            }
            #[cfg(not(wasm_browser))]
            match crate::runtime::RuntimeTimeout::after(
                self.runtime.context().clock(),
                Duration::from_millis(100),
                async move {
                    if let Err(err) = task.join().await {
                        warn!("unexpected error in task shutdown: {:?}", err);
                    }
                },
            ) {
                Ok(timeout) => match timeout.await {
                    Ok(()) => trace!("tasks finished in time, shutdown complete"),
                    Err(iroh_runtime::TimeoutError::Elapsed) => {
                        warn!("tasks didn't finish in time, aborting");
                    }
                    Err(iroh_runtime::TimeoutError::Clock(error)) => {
                        self.runtime.latch_failure(error.to_string());
                    }
                },
                Err(error) => self.runtime.latch_failure(error.to_string()),
            }
        }

        // Waits for the EndpointDriver and all ConnectionDrivers to shut down
        // Expects that the `noq::Endpoint` has been closed before this call,
        // otherwise, the runtime will never shutdown.
        self.runtime.shutdown().await;

        self.sock.shutdown.closed.store(true, Ordering::SeqCst);

        trace!("socket closed");
    }

    /// Aborts the endpoint ungracefully:
    ///
    /// - Calls cancellation token that stops running net reports
    /// - Removes all address lookup services
    /// - Calls cancellation token that stops all the Socket actors
    /// - Aborts the runtime
    /// - Drops the actor task
    /// - Sets the `Socket::is_closed` state to true
    ///
    /// This does not wait for any current connections or tasks to close gracefully.
    ///
    /// This should only be called in the `iroh::Endpoint` `Drop` impl when the
    /// `iroh::Endpoint` is dropped without first calling `Endpoint::close`.
    #[instrument(skip_all, parent = self.sock.span.clone())]
    pub(crate) fn abort(&self) {
        if self.sock.is_closed() || self.sock.is_closing() {
            return;
        }
        trace!("socket aborting...");

        // Cancel at_close_start token, which cancels running netreports.
        self.sock.shutdown.at_close_start.cancel();

        self.sock.address_lookup().clear();

        // Cancel all actors.
        self.sock.shutdown.at_endpoint_closed.cancel();

        // Aborts all tasks, not waiting for any to close gracefully.
        self.runtime.abort();

        self.actor_task.lock().expect("poisoned").take();

        self.sock.shutdown.closed.store(true, Ordering::SeqCst);
        trace!("socket closed");
    }

    pub(crate) async fn insert_relay(
        &self,
        relay: RelayUrl,
        endpoint: Arc<RelayConfig>,
    ) -> Option<Arc<RelayConfig>> {
        let res = self.relay_map.insert(relay, endpoint);
        self.actor_sender
            .send(ActorMessage::RelayMapChange)
            .await
            .ok();
        res
    }

    pub(crate) async fn remove_relay(&self, relay: &RelayUrl) -> Option<Arc<RelayConfig>> {
        let res = self.relay_map.remove(relay);
        self.actor_sender
            .send(ActorMessage::RelayMapChange)
            .await
            .ok();
        res
    }

    /// Adds an external address to advertise to peers.
    pub(crate) async fn add_external_addr(&self, addr: SocketAddr) {
        self.sock
            .configured_addrs
            .write()
            .expect("poisoned")
            .insert(addr);
        self.actor_sender
            .send(ActorMessage::DirectAddrRefresh)
            .await
            .ok();
    }

    /// Removes a configured external address. Returns `true` if it was present.
    pub(crate) async fn remove_external_addr(&self, addr: &SocketAddr) -> bool {
        let removed = self
            .sock
            .configured_addrs
            .write()
            .expect("poisoned")
            .remove(addr);
        if removed {
            self.actor_sender
                .send(ActorMessage::DirectAddrRefresh)
                .await
                .ok();
        }
        removed
    }

    /// Call to notify the system of potential network changes.
    pub(crate) async fn network_change(&self) {
        self.actor_sender
            .send(ActorMessage::NetworkChange)
            .await
            .ok();
    }

    #[cfg(all(test, with_crypto_provider))]
    pub(super) async fn force_network_change(&self, is_major: bool) {
        self.actor_sender
            .send(ActorMessage::ForceNetworkChange(is_major))
            .await
            .ok();
    }

    /// Resolves an [`EndpointAddr`] to an [`EndpointIdMappedAddr`] to connect to via [`EndpointInner::endpoint`].
    ///
    /// This starts a `RemoteStateActor` for the remote if not running already, and then checks
    /// if the actor has any known paths to the remote. If not, it starts address lookup and waits for
    /// at least one result to arrive.
    ///
    /// Returns `Ok(Ok(EndpointIdMappedAddr))` if there is a known path or Address Lookup produced
    /// at least one result. This does not mean there is a working path, only that we have at least
    /// one transport address we can try to connect to.
    ///
    /// Returns `Ok(Err(address_lookup_error))` if there are no known paths to the remote and Address Lookup
    /// failed or produced no results. This means that we don't have any transport address for
    /// the remote, thus there is no point in trying to connect over the noq endpoint.
    ///
    /// Returns `Err(RemoteStateActorStoppedError)` if the `RemoteStateActor` for the remote has stopped,
    /// which may never happen and thus is a bug if it does.
    pub(crate) async fn resolve_remote(
        &self,
        addr: EndpointAddr,
    ) -> Result<Result<EndpointIdMappedAddr, AddressLookupFailed>, RemoteStateActorStoppedError>
    {
        let (tx, rx) = oneshot::channel();
        let remote_id = addr.id;
        self.actor_sender
            .send(ActorMessage::ResolveRemote(addr, tx))
            .await
            .ok();
        let reply = rx.await.map_err(|_| RemoteStateActorStoppedError::new())?;
        match reply {
            Ok(()) => Ok(Ok(self.mapped_addrs.endpoint_addrs.get(&remote_id))),
            Err(err) => Ok(Err(err)),
        }
    }

    /// Fetches the [`RemoteInfo`] about a remote from the `RemoteStateActor`.
    ///
    /// Returns `None` if no actor is running for the remote.
    pub(crate) async fn remote_info(&self, id: EndpointId) -> Option<RemoteInfo> {
        let (tx, rx) = oneshot::channel();
        self.remote_actors
            .get(&id)?
            .send(RemoteStateMessage::RemoteInfo(tx))
            .await
            .ok()?;
        rx.await.ok()
    }

    /// Registers the connection in the `RemoteStateActor`.
    ///
    /// The actor is responsible for holepunching and opening additional paths to this
    /// connection.
    ///
    /// Returns a future that resolves to a [`PathStateReceiver`] for the new connection.
    ///
    /// The returned future is `'static`, so it can be stored without being lifetime-bound to `&self`.
    pub(crate) fn register_connection(
        &self,
        remote: EndpointId,
        conn: noq::Connection,
    ) -> impl Future<Output = Result<PathStateReceiver, RemoteStateRegistrationError>> + Send + 'static
    {
        let (tx, rx) = oneshot::channel();
        let sender = self.actor_sender.clone();
        async move {
            sender
                .send(ActorMessage::AddConnection(remote, conn, tx))
                .await
                .map_err(|_| e!(RemoteStateRegistrationError::ActorStopped))?;
            rx.await
                .map_err(|_| e!(RemoteStateRegistrationError::ActorStopped))?
                .map_err(|source| e!(RemoteStateRegistrationError::Admission, source))
        }
    }
}
