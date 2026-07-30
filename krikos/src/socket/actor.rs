use super::*;

#[derive(derive_more::Debug)]
#[allow(clippy::enum_variant_names)]
pub(super) enum ActorMessage {
    NetworkChange,
    RelayMapChange,
    #[debug("ResolveRemote(..)")]
    ResolveRemote(
        EndpointAddr,
        oneshot::Sender<Result<(), AddressLookupFailed>>,
    ),
    #[debug("AddConnection(..)")]
    AddConnection(
        EndpointId,
        noq::Connection,
        oneshot::Sender<Result<PathStateReceiver, RemoteStateAdmissionError>>,
    ),
    /// Re-evaluate direct addresses, e.g. after configured external addresses changed.
    DirectAddrRefresh,
    #[cfg(all(test, with_crypto_provider))]
    ForceNetworkChange(bool),
}

/// State for polling until a default route is available after a network change.
///
/// When a network change is detected but no default route exists yet (e.g.,
/// interface just came up but gateway not assigned), we poll with exponential
/// backoff until the gateway appears. This avoids the fixed 2s delay that was
/// too slow for interface recovery scenarios.
pub(super) struct PendingNetworkChangeNotify {
    /// Next time to check for default route.
    next_check: Instant,
    /// Current backoff interval.
    interval: Duration,
    /// Whether this was a major change.
    is_major: bool,
    /// When we started polling (to enforce a max wait).
    started: Instant,
}

impl PendingNetworkChangeNotify {
    const INITIAL_INTERVAL: Duration = Duration::from_millis(100);
    const MAX_INTERVAL: Duration = Duration::from_secs(1);
    const MAX_WAIT: Duration = Duration::from_secs(5);

    fn new(is_major: bool, now: Instant) -> Self {
        Self {
            next_check: now + Self::INITIAL_INTERVAL,
            interval: Self::INITIAL_INTERVAL,
            is_major,
            started: now,
        }
    }

    /// Advance to the next check interval (exponential backoff, capped).
    fn advance(&mut self, now: Instant) {
        self.interval = (self.interval * 2).min(Self::MAX_INTERVAL);
        self.next_check = now + self.interval;
    }

    /// Whether we've exceeded the maximum wait time.
    fn expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.started) >= Self::MAX_WAIT
    }
}

pub(super) struct Actor {
    /// A clone of the quinn Endpoint.
    ///
    /// The task of this actor is owned by the [`crate::Endpoint`]. Native endpoints use an
    /// [`krikos_runtime::OwnedTaskHandle`], while browser endpoints use an
    /// [`n0_future::task::AbortOnDropHandle`]. When [`crate::Endpoint::close`] is called,
    /// various subsystems are stopped. Then, when `ShutdownState::at_endpoint_closed` is
    /// called by [`crate::Endpoint::close`], this actor itself is stopped via its
    /// [`CancellationToken`] and we drop this clone of the endpoint. The endpoint is
    /// finally dropped when the [`crate::Endpoint`] itself is dropped.
    ///
    /// All of this to say: keeping the quinn endpoint alive here does not impact the
    /// lifetime of it since it's lifetime is shorter than that one that's stored in the
    /// [`crate::Endpoint`].
    pub(super) endpoint: noq::Endpoint,
    /// Shared state between an awful lot of iroh subsystems.
    ///
    /// In particular both the [`EndpointInner`] as well as this actor itself have a
    /// copy. But also other subsystems that consequently have access to way to much state.
    pub(super) sock: Arc<Socket>,
    /// Tracks the networkmap endpoint entity for each endpoint discovery key.
    pub(super) remote_map: RemoteMap,
    /// When set, is an AfterFunc timer that will call Socket::do_periodic_stun.
    #[cfg(not(wasm_browser))]
    pub(super) periodic_re_stun_timer: crate::runtime::RuntimeInterval,
    #[cfg(wasm_browser)]
    pub(super) periodic_re_stun_timer: time::Interval,
    #[cfg(not(wasm_browser))]
    pub(super) re_stun_decisions: Box<dyn krikos_runtime::DecisionStream>,
    #[cfg(not(wasm_browser))]
    pub(super) runtime_clock: Arc<dyn krikos_runtime::Clock>,
    /// An actor watching the local network interfaces.
    ///
    /// The monitored changes are emitted via [`Self::local_interfaces_watcher`].
    #[cfg(not(wasm_browser))]
    pub(super) network_monitor: Arc<dyn crate::simulation::NetworkMonitor>,
    #[cfg(wasm_browser)]
    pub(super) network_monitor: netmon::Monitor,
    /// Watcher for changes to the local network interfaces, IP addresses and routes.
    pub(super) local_interfaces_watcher: n0_watcher::Direct<netmon::State>,
    pub(super) transports_network_change: transports::NetworkChangeSender,
    /// Indicates the direct addr update state.
    pub(super) direct_addr_update_state: DirectAddrUpdateState,
    pub(super) direct_addr_done_rx: mpsc::Receiver<()>,
    /// Polling state for [`Actor::notify_quic_network_change`].
    ///
    /// When a network change is detected but no default route is available yet,
    /// we poll with exponential backoff (100ms, 200ms, 400ms, 800ms, 1s, 1s, ...)
    /// until the gateway appears. Once it does, we notify immediately.
    /// After 5s total we notify anyway even without a gateway.
    pub(super) call_notify_quic_network_change: Option<PendingNetworkChangeNotify>,
}

impl Actor {
    pub(super) async fn run(
        mut self,
        mut msg_receiver: mpsc::Receiver<ActorMessage>,
        shutdown_token: CancellationToken,
        mut local_addrs_watcher: impl Watcher<Value = Vec<transports::Addr>> + Send + Sync,
    ) {
        // Setup network monitoring
        let mut current_netmon_state = self.local_interfaces_watcher.get();

        let mut portmap_watcher = self
            .direct_addr_update_state
            .port_mapper
            .watch_external_address();

        let mut receiver_closed = false;
        let mut portmap_watcher_closed = false;

        let mut net_report_watcher = self.sock.net_report.watch();

        // ensure we are doing an initial publish of our addresses
        self.sock.publish_my_addr();

        while !shutdown_token.is_cancelled() {
            self.sock.metrics.socket.actor_tick_main.inc();
            let portmap_watcher_changed = portmap_watcher.changed();

            #[cfg(not(wasm_browser))]
            let notify_quic_network_change = match &self.call_notify_quic_network_change {
                Some(pending) => match crate::runtime::RuntimeSleep::new(
                    self.runtime_clock.clone(),
                    pending.next_check,
                ) {
                    Ok(timer) => MaybeFuture::Some(timer),
                    Err(error) => {
                        warn!(%error, "runtime network-change timer failed");
                        return;
                    }
                },
                None => MaybeFuture::None,
            };
            #[cfg(wasm_browser)]
            let notify_quic_network_change = match &self.call_notify_quic_network_change {
                Some(pending) => {
                    MaybeFuture::Some(n0_future::time::sleep_until(pending.next_check))
                }
                None => MaybeFuture::None,
            };
            n0_future::pin!(notify_quic_network_change);

            tokio::select! {
                biased;

                _ = shutdown_token.cancelled() => {
                    debug!("tick: shutting down");
                    return;
                }
                msg = msg_receiver.recv(), if !receiver_closed => {
                    let Some(msg) = msg else {
                        trace!("tick: socket receiver closed");
                        self.sock.metrics.socket.actor_tick_other.inc();
                        receiver_closed = true;
                        continue;
                    };

                    trace!(?msg, "tick: msg");
                    self.sock.metrics.socket.actor_tick_msg.inc();
                    self.handle_actor_message(msg).await;
                }
                tick = self.periodic_re_stun_timer.tick() => {
                    trace!("tick: re_stun {:?}", tick);
                    #[cfg(not(wasm_browser))]
                    if let Err(error) = tick {
                        warn!(%error, "runtime periodic re-STUN timer failed");
                        return;
                    }
                    self.sock.metrics.socket.actor_tick_re_stun.inc();
                    self.re_stun(UpdateReason::Periodic);
                }
                new_addr = local_addrs_watcher.updated() => {
                    match new_addr {
                        Ok(addrs) => {
                            if !addrs.is_empty() {
                                trace!(?addrs, "local addrs");
                                self.sock.publish_my_addr();
                            }
                        }
                        Err(_) => {
                            warn!("local addr watcher stopped");
                        }
                    }
                }
                report = net_report_watcher.updated() => {
                    match report {
                        Ok((report, _)) => {
                            self.handle_net_report_report(report);
                            #[cfg(not(wasm_browser))]
                            {
                                match new_re_stun_timer(
                                    self.runtime_clock.clone(),
                                    true,
                                    self.re_stun_decisions.as_mut(),
                                ) {
                                    Ok(timer) => self.periodic_re_stun_timer = timer,
                                    Err(error) => {
                                        warn!(%error, "failed to reset runtime periodic re-STUN timer");
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            warn!("net report watcher stopped");
                        }
                    }
                }
                reason = self.direct_addr_done_rx.recv() => {
                    match reason {
                        Some(()) => {
                            // check if a new run needs to be scheduled
                            let state = self.local_interfaces_watcher.get();
                            self.direct_addr_update_state.try_run(state.into());
                        }
                        None => {
                            warn!("direct addr watcher died");
                        }
                    }
                }
                change = portmap_watcher_changed, if !portmap_watcher_closed => {
                    if change.is_err() {
                        trace!("tick: portmap watcher closed");
                        self.sock.metrics.socket.actor_tick_other.inc();

                        portmap_watcher_closed = true;
                        continue;
                    }

                    trace!("tick: portmap changed");
                    self.sock.metrics.socket.actor_tick_portmap_changed.inc();
                    let new_external_address = *portmap_watcher.borrow();
                    if new_external_address.is_some() {
                        self.sock.metrics.net_report.portmap_external_address_updated.inc();
                    }
                    debug!("external address updated: {new_external_address:?}");
                    self.re_stun(UpdateReason::PortmapUpdated);
                },
                state = self.local_interfaces_watcher.updated() => {
                    let Ok(state) = state else {
                        trace!("tick: link change receiver closed");
                        self.sock.metrics.socket.actor_tick_other.inc();
                        continue;
                    };
                    let is_major = state.is_major_change(&current_netmon_state);
                    event!(
                        target: "iroh::_events::link_change",
                        Level::DEBUG,
                        ?state,
                        is_major
                    );
                    current_netmon_state = state;
                    self.sock.metrics.socket.actor_link_change.inc();
                    self.handle_network_change(is_major);
                }
                _remote_id = self.remote_map.cleanup() => {},
                _ = &mut notify_quic_network_change => {
                    let now = self.runtime_now();
                    let has_network = self.has_usable_network();
                    let Some(pending) = self.call_notify_quic_network_change.as_mut() else {
                        continue;
                    };
                    if has_network || pending.expired(now) {
                        // Gateway appeared or we've waited long enough, notify now.
                        let is_major = pending.is_major;
                        self.call_notify_quic_network_change = None;
                        self.notify_quic_network_change(is_major);
                    } else {
                        // No gateway yet, back off and try again.
                        trace!(
                            interval = ?pending.interval,
                            elapsed = ?now.saturating_duration_since(pending.started),
                            "no default route yet, retrying"
                        );
                        pending.advance(now);
                    }
                }
                else => {
                    trace!("tick: else");
                }
            }
        }
    }

    /// Whether the local network has a default route and at least one IP address.
    fn has_usable_network(&mut self) -> bool {
        #[cfg(target_family = "wasm")]
        {
            true
        }
        #[cfg(not(target_family = "wasm"))]
        {
            let interfaces = self.local_interfaces_watcher.get();
            interfaces.default_route_interface.is_some()
                && (interfaces.have_v4 || interfaces.have_v6)
        }
    }

    fn runtime_now(&self) -> Instant {
        #[cfg(not(wasm_browser))]
        {
            self.runtime_clock.now()
        }
        #[cfg(wasm_browser)]
        {
            Instant::now()
        }
    }

    /// Handles a change detected in the local network conditions.
    ///
    /// This is triggered when the netmon actor detects a change in the local network
    /// interfaces, assigned IP addresses and routes.
    fn handle_network_change(&mut self, is_major: bool) {
        debug!(is_major, "link change detected");

        if is_major {
            if let Err(err) = self.transports_network_change.rebind() {
                warn!("failed to rebind transports: {err:?}");
            }
            self.transports_network_change.check_relay_connection();

            #[cfg(not(wasm_browser))]
            self.sock.dns_resolver.reset();
            self.re_stun(UpdateReason::LinkChangeMajor);
        } else {
            self.re_stun(UpdateReason::LinkChangeMinor);
        }

        if self.has_usable_network() {
            // This is considered a usable network change, propagate it to the QUIC stack
            // right away.
            self.call_notify_quic_network_change = None;
            self.notify_quic_network_change(is_major);
        } else {
            // No default route yet (e.g., interface just came up but gateway not
            // assigned). Poll with exponential backoff until the gateway appears.
            match &mut self.call_notify_quic_network_change {
                Some(pending) => {
                    // Update is_major if this change is more severe.
                    pending.is_major |= is_major;
                }
                None => {
                    let now = self.runtime_now();
                    self.call_notify_quic_network_change =
                        Some(PendingNetworkChangeNotify::new(is_major, now));
                }
            }
        }
    }

    /// Notifies the QUIC stack of the network change we observed.
    ///
    /// This is decoupled from receiving the network change, because we try to debounce
    /// network changes as they often arrive in groups.
    fn notify_quic_network_change(&mut self, is_major: bool) {
        #[derive(Debug)]
        struct Hint {
            local_addrs: FxHashSet<IpAddr>,
        }

        impl NetworkChangeHint for Hint {
            fn is_path_recoverable(
                &self,
                _path_id: noq::PathId,
                network_path: noq_proto::FourTuple,
            ) -> bool {
                match MultipathMappedAddr::from(network_path.remote()) {
                    MultipathMappedAddr::Mixed(_) => {
                        // This address is only ever used to send an Initial packet to, it
                        // should never appear as an established path.
                        error!("A mixed address can not be used for network changes");
                        false
                    }
                    MultipathMappedAddr::Relay(_) => {
                        // We pretend the relay path is never affected by link changes. The
                        // relay actor transparently reconnects and the addresses never
                        // change.
                        true
                    }
                    MultipathMappedAddr::Ip(_) => {
                        // If we no longer have a valid interface to send from for a local
                        // IP then it can not be recovered.
                        match network_path.local_ip() {
                            Some(local_ip) => self.local_addrs.contains(&local_ip),
                            None => true,
                        }
                    }
                    MultipathMappedAddr::Custom(_) => {
                        // Assume it is unrecoverable for now
                        false
                    }
                }
            }
        }

        let hint = Hint {
            #[cfg(not(wasm_browser))]
            local_addrs: {
                let interfaces = self.local_interfaces_watcher.get();
                interfaces
                    .local_addresses
                    .regular
                    .iter()
                    .chain(interfaces.local_addresses.loopback.iter())
                    .copied()
                    .collect()
            },
            #[cfg(wasm_browser)]
            local_addrs: Default::default(),
        };

        self.endpoint.handle_network_change(Some(Arc::new(hint)));
        self.remote_map.on_network_change(is_major);
    }

    fn handle_relay_map_change(&mut self) {
        self.re_stun(UpdateReason::RelayMapChange);
    }

    fn re_stun(&mut self, why: UpdateReason) {
        let state = self.local_interfaces_watcher.get();
        self.direct_addr_update_state
            .schedule_run(why, state.into());
    }

    /// Processes an incoming actor message.
    ///
    /// Returns `true` if it was a shutdown.
    async fn handle_actor_message(&mut self, msg: ActorMessage) {
        match msg {
            ActorMessage::NetworkChange => {
                #[cfg(not(wasm_browser))]
                self.network_monitor.network_change().await;
                #[cfg(wasm_browser)]
                self.network_monitor.network_change().await.ok();
            }
            ActorMessage::RelayMapChange => {
                self.handle_relay_map_change();
            }
            ActorMessage::ResolveRemote(addr, tx) => {
                self.remote_map.resolve_remote(addr, tx).await;
            }
            ActorMessage::AddConnection(remote, conn, tx) => {
                self.remote_map.add_connection(remote, conn, tx).await;
            }
            ActorMessage::DirectAddrRefresh => {
                #[cfg(not(wasm_browser))]
                {
                    let (report, _reason) = self.sock.net_report.get();
                    self.update_direct_addresses(report.as_ref());
                }
            }
            #[cfg(all(test, with_crypto_provider))]
            ActorMessage::ForceNetworkChange(is_major) => {
                self.handle_network_change(is_major);
            }
        }
    }

    /// Updates the direct addresses of this socket.
    ///
    /// Updates the [`DiscoveredDirectAddrs`] of this [`Socket`] with the current set of
    /// direct addresses from:
    ///
    /// - The portmapper.
    /// - A net_report report.
    /// - The local interfaces IP addresses.
    /// - User configured addresses.
    #[cfg(not(wasm_browser))]
    pub(super) fn update_direct_addresses(
        &mut self,
        net_report_report: Option<&net_report::Report>,
    ) {
        // We only want to have one DirectAddr for each SocketAddr we have.  So we store
        // this as a map of SocketAddr -> DirectAddrType.  At the end we will construct a
        // DirectAddr from each entry.
        let mut addrs: BTreeMap<SocketAddr, (DirectAddrType, Option<Ipv6AddrFlags>)> =
            BTreeMap::new();

        // First add PortMapper provided addresses.
        let portmap_watcher = self
            .direct_addr_update_state
            .port_mapper
            .watch_external_address();
        let maybe_port_mapped = *portmap_watcher.borrow();
        if let Some(portmap_ext) = maybe_port_mapped.map(SocketAddr::V4) {
            addrs
                .entry(portmap_ext)
                .or_insert((DirectAddrType::Portmapped, None));
        }

        // Next add STUN addresses from the net_report report.
        if let Some(net_report_report) = net_report_report {
            if let Some(global_v4) = net_report_report.global_v4 {
                addrs
                    .entry(global_v4.into())
                    .or_insert((DirectAddrType::Qad, None));

                // If they're behind a hard NAT and are using a fixed
                // port locally, assume they might've added a static
                // port mapping on their router to the same explicit
                // port that we are running with. Worst case it's an invalid candidate mapping.
                let port = self.sock.ip_bind_addrs().iter().find_map(|addr| {
                    if addr.port() != 0 {
                        Some(addr.port())
                    } else {
                        None
                    }
                });

                if let Some(port) = port
                    && net_report_report
                        .mapping_varies_by_dest()
                        .unwrap_or_default()
                {
                    let mut addr = global_v4;
                    addr.set_port(port);
                    addrs
                        .entry(addr.into())
                        .or_insert((DirectAddrType::Qad4LocalPort, None));
                }
            }
            if let Some(global_v6) = net_report_report.global_v6 {
                addrs
                    .entry(global_v6.into())
                    .or_insert((DirectAddrType::Qad, None));
            }
        }

        self.collect_local_addresses(&mut addrs);

        // Add configured external addresses.
        for addr in self.sock.configured_addrs.read().expect("poisoned").iter() {
            addrs.entry(*addr).or_insert((DirectAddrType::Config, None));
        }

        // Finally create and store store all these direct addresses
        let stored_addrs = addrs
            .into_iter()
            .filter_map(|(addr, (typ, flags))| {
                // Filter out deprecated IPs
                let is_deprecated = flags.map(|f| f.deprecated).unwrap_or(false);
                if is_deprecated {
                    return None;
                }
                Some(DirectAddr { addr, typ })
            })
            .collect();
        self.sock.store_direct_addresses(stored_addrs);
    }

    #[cfg(not(wasm_browser))]
    fn collect_local_addresses(
        &mut self,
        addrs: &mut BTreeMap<SocketAddr, (DirectAddrType, Option<Ipv6AddrFlags>)>,
    ) {
        let netmon_state = self.local_interfaces_watcher.get();

        // Matches the addresses that have been bound vs the requested ones.
        let local_addrs: Vec<(SocketAddr, SocketAddr)> = self
            .sock
            .ip_bind_addrs()
            .iter()
            .copied()
            .zip(self.sock.ip_local_addrs())
            .collect();

        // Do we listen on any IPv4 unspecified address?
        let has_ipv4_unspecified = local_addrs.iter().find_map(|(_, a)| {
            if a.is_ipv4() && a.ip().is_unspecified() {
                Some(a.port())
            } else {
                None
            }
        });
        // Do we listen on any IPv6 unspecified address?
        let has_ipv6_unspecified = local_addrs.iter().find_map(|(_, a)| {
            if a.is_ipv6() && a.ip().is_unspecified() {
                Some(a.port())
            } else {
                None
            }
        });

        // If a socket is bound to the unspecified address, create SocketAddrs for
        // each local IP address by pairing it with the port the socket is bound on.
        if local_addrs
            .iter()
            .any(|(_, local)| local.ip().is_unspecified())
        {
            let LocalAddresses {
                regular: mut ips,
                loopback,
            } = self.local_interfaces_watcher.get().local_addresses;
            if ips.is_empty() && addrs.is_empty() {
                // Include loopback addresses only if there are no other interfaces
                // or public addresses, this allows testing offline.
                ips = loopback;
            }

            for ip in ips {
                let port_if_unspecified = match ip {
                    IpAddr::V4(_) => has_ipv4_unspecified,
                    IpAddr::V6(_) => has_ipv6_unspecified,
                };
                if let Some(port) = port_if_unspecified {
                    let addr = SocketAddr::new(ip, port);
                    let flags = find_flags(&netmon_state, ip);
                    addrs.entry(addr).or_insert((DirectAddrType::Local, flags));
                }
            }
        }

        // If a socket is bound to a specific address, add it.
        for (bound, local) in local_addrs {
            if !bound.ip().is_unspecified() {
                let flags = find_flags(&netmon_state, local.ip());
                addrs.entry(local).or_insert((DirectAddrType::Local, flags));
            }
        }
    }

    fn handle_net_report_report(&mut self, mut report: Option<net_report::Report>) {
        if let Some(ref mut r) = report {
            self.sock.ipv6_reported.store(r.udp_v6, Ordering::Relaxed);
            if r.preferred_relay.is_none()
                && let Some(my_relay) = self.sock.my_relay()
            {
                r.preferred_relay.replace(my_relay);
            }

            // Notify all transports
            self.transports_network_change.on_network_change(r);
        }

        #[cfg(not(wasm_browser))]
        self.update_direct_addresses(report.as_ref());
    }
}
