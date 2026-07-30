use super::*;

/// Manages currently running net reports to learn this endpoint's IP addresses.
///
/// Invariants:
/// - only one direct addr update must be running at a time
/// - if an update is scheduled while another one is running, remember that
///   and start a new one when the current one has finished
#[derive(Debug)]
pub(super) struct DirectAddrUpdateState {
    /// If set, start a new update as soon as the current one is finished.
    want_update: Option<UpdateReason>,
    sock: Arc<Socket>,
    pub(super) port_mapper: portmapper::Client,
    /// The prober that discovers local network conditions, including the closest relay relay and NAT mappings.
    net_reporter: Arc<AsyncMutex<net_report::Client>>,
    relay_map: RelayMap,
    run_done: mpsc::Sender<()>,
    shutdown_token: CancellationToken,
    #[cfg(not(wasm_browser))]
    runtime: Arc<Runtime>,
}

#[derive(Default, Debug, PartialEq, Eq, Clone, Copy)]
pub(super) enum UpdateReason {
    /// Initial state
    #[default]
    None,
    Periodic,
    PortmapUpdated,
    LinkChangeMajor,
    LinkChangeMinor,
    RelayMapChange,
}

impl UpdateReason {
    fn is_major(self) -> bool {
        matches!(self, Self::LinkChangeMajor | Self::RelayMapChange)
    }
}

impl DirectAddrUpdateState {
    pub(super) fn new(
        sock: Arc<Socket>,
        port_mapper: portmapper::Client,
        net_reporter: Arc<AsyncMutex<net_report::Client>>,
        relay_map: RelayMap,
        run_done: mpsc::Sender<()>,
        shutdown_token: CancellationToken,
        #[cfg(not(wasm_browser))] runtime: Arc<Runtime>,
    ) -> Self {
        DirectAddrUpdateState {
            want_update: Default::default(),
            port_mapper,
            net_reporter,
            sock,
            relay_map,
            run_done,
            shutdown_token,
            #[cfg(not(wasm_browser))]
            runtime,
        }
    }

    /// Schedules a new run, either starting it immediately if none is running or
    /// scheduling it for later.
    pub(super) fn schedule_run(&mut self, why: UpdateReason, if_state: IfStateDetails) {
        match self.net_reporter.clone().try_lock_owned() {
            Ok(net_reporter) => {
                self.run(why, if_state, net_reporter);
            }
            Err(_) => {
                let _ = self.want_update.insert(why);
            }
        }
    }

    /// If another run is needed, triggers this run, otherwise does nothing.
    pub(super) fn try_run(&mut self, if_state: IfStateDetails) {
        match self.net_reporter.clone().try_lock_owned() {
            Ok(net_reporter) => {
                if let Some(why) = self.want_update.take() {
                    self.run(why, if_state, net_reporter);
                }
            }
            Err(_) => {
                // do nothing
            }
        }
    }

    /// Trigger a new run.
    fn run(
        &mut self,
        why: UpdateReason,
        if_state: IfStateDetails,
        mut net_reporter: tokio::sync::OwnedMutexGuard<net_report::Client>,
    ) {
        debug!("starting direct addr update ({:?})", why);
        // Don't start a net report probe if we know
        // we are shutting down
        if self.shutdown_token.is_cancelled() {
            debug!("skipping net_report, socket is shutting down");
            // deactivate portmapper
            self.port_mapper.deactivate();
            return;
        }
        if self.relay_map.is_empty() {
            debug!("skipping net_report, empty RelayMap");
            self.sock.net_report.set((None, why)).ok();
            return;
        }

        self.sock.metrics.net_report.portmap_attempts.inc();
        self.port_mapper.procure_mapping();

        trace!("requesting net_report report");
        let sock = self.sock.clone();

        let run_done = self.run_done.clone();

        // Ensure that reports are cancelled when we shutdown
        let token = self.shutdown_token.child_token();
        let inner_token = token.child_token();
        #[cfg(wasm_browser)]
        let future = async move {
            let fut = token.run_until_cancelled(time::timeout(
                NET_REPORT_TIMEOUT,
                net_reporter.get_report(if_state, why.is_major(), inner_token),
            ));

            match fut.await {
                Some(Ok(report)) => {
                    sock.net_report.set((Some(report), why)).ok();
                }
                Some(Err(time::Elapsed { .. })) => {
                    warn!("net_report report timed out");
                }
                None => {
                    trace!("net_report cancelled");
                }
            }

            // mark run as finished
            debug!("direct addr update done ({:?})", why);
            run_done.send(()).await.ok();
        }
        .instrument(tracing::Span::current());
        #[cfg(not(wasm_browser))]
        let runtime = self.runtime.clone();
        #[cfg(not(wasm_browser))]
        let future = async move {
            let timeout = crate::runtime::RuntimeTimeout::after(
                runtime.context().clock(),
                NET_REPORT_TIMEOUT,
                net_reporter.get_report(if_state, why.is_major(), inner_token),
            );
            match timeout {
                Ok(timeout) => match token.run_until_cancelled(timeout).await {
                    Some(Ok(report)) => {
                        sock.net_report.set((Some(report), why)).ok();
                    }
                    Some(Err(krikos_runtime::TimeoutError::Elapsed)) => {
                        warn!("net_report report timed out");
                    }
                    Some(Err(krikos_runtime::TimeoutError::Clock(error))) => {
                        runtime.latch_failure(error.to_string());
                    }
                    None => trace!("net_report cancelled"),
                },
                Err(error) => runtime.latch_failure(error.to_string()),
            }

            debug!("direct addr update done ({:?})", why);
            run_done.send(()).await.ok();
        }
        .instrument(tracing::Span::current());
        #[cfg(not(wasm_browser))]
        if let Err(error) = self.runtime.spawn(
            krikos_runtime::TaskKind::NetReport,
            "direct-address-update",
            Box::pin(future),
        ) {
            warn!(%error, "runtime rejected direct address update task");
        }
        #[cfg(wasm_browser)]
        task::spawn(future);
    }
}

#[cfg(not(wasm_browser))]
pub(super) fn find_flags(state: &netmon::State, ip: IpAddr) -> Option<Ipv6AddrFlags> {
    if ip.is_ipv6() {
        state
            .interfaces
            .values()
            .flat_map(|i| i.addrs())
            .find_map(|addr| match addr {
                IpNet::V4(_) => None,
                IpNet::V6 { net, flags, .. } => {
                    if net.addr() == ip {
                        Some(flags)
                    } else {
                        None
                    }
                }
            })
    } else {
        None
    }
}

#[cfg(not(wasm_browser))]
pub(super) fn new_re_stun_timer(
    clock: Arc<dyn krikos_runtime::Clock>,
    initial_delay: bool,
    decisions: &mut dyn krikos_runtime::DecisionStream,
) -> Result<crate::runtime::RuntimeInterval, io::Error> {
    let seconds = decisions.range_u64(20..27).map_err(io::Error::other)?;
    let period = Duration::from_secs(seconds);
    let initial_delay = if initial_delay {
        period
    } else {
        Duration::ZERO
    };
    debug!(seconds, "scheduling periodic re-STUN on the runtime clock");
    crate::runtime::RuntimeInterval::new(clock, initial_delay, period).map_err(io::Error::other)
}

#[cfg(wasm_browser)]
pub(super) fn new_re_stun_timer(initial_delay: bool) -> time::Interval {
    // Pick a random duration between 20 and 26 seconds (just under 30s,
    // a common UDP NAT timeout on Linux,etc)
    let mut rng = rand::rng();
    let d: Duration = rng.random_range(Duration::from_secs(20)..=Duration::from_secs(26));
    if initial_delay {
        debug!("scheduling periodic_stun to run in {}s", d.as_secs());
        time::interval_at(time::Instant::now() + d, d)
    } else {
        debug!(
            "scheduling periodic_stun to run immediately and in {}s",
            d.as_secs()
        );
        time::interval(d)
    }
}

/// The discovered direct addresses of this [`Socket`].
///
/// These are all the [`DirectAddr`]s that this [`Socket`] is aware of for itself.
/// They include all locally bound ones as well as those discovered by other mechanisms like
/// QAD.
#[derive(derive_more::Debug, Clone, Default)]
pub(super) struct DiscoveredDirectAddrs {
    /// The last set of discovered direct addresses.
    addrs: Watchable<BTreeSet<DirectAddr>>,
}

impl DiscoveredDirectAddrs {
    /// Updates the direct addresses, returns `true` if they changed, `false` if not.
    pub(super) fn update(&self, addrs: BTreeSet<DirectAddr>) -> bool {
        let updated = self.addrs.set(addrs).is_ok();
        if updated {
            event!(
                target: "krikos::_events::direct_addrs",
                Level::DEBUG,
                addrs = ?self.addrs.get(),
            );
        }
        updated
    }

    pub(super) fn watch(&self) -> n0_watcher::Direct<BTreeSet<DirectAddr>> {
        self.addrs.watch()
    }

    pub(super) fn sockaddrs(&self) -> impl Iterator<Item = SocketAddr> {
        self.addrs.get().into_iter().map(|da| da.addr)
    }
}

/// A *direct address* on which an krikos-endpoint might be contactable.
///
/// Direct addresses are UDP socket addresses on which an krikos endpoint could potentially be
/// contacted.  These can come from various sources depending on the network topology of the
/// krikos endpoint, see [`DirectAddrType`] for the several kinds of sources.
///
/// This is essentially a combination of our local addresses combined with any reflexive
/// transport addresses we discovered using QAD.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DirectAddr {
    /// The address.
    pub addr: SocketAddr,
    /// The origin of this direct address.
    pub typ: DirectAddrType,
}

/// The type of direct address.
///
/// These are the various sources or origins from which an krikos endpoint might have found a
/// possible [`DirectAddr`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum DirectAddrType {
    /// Not yet determined..
    Unknown,
    /// A locally bound socket address.
    Local,
    /// Public internet address discovered via QAD.
    ///
    /// When possible an krikos endpoint will perform QAD to discover which is the address
    /// from which it sends data on the public internet.  This can be different from locally
    /// bound addresses when the endpoint is on a local network which performs NAT or similar.
    Qad,
    /// An address assigned by the router using port mapping.
    ///
    /// When possible an krikos endpoint will request a port mapping from the local router to
    /// get a publicly routable direct address.
    Portmapped,
    /// Hard NAT: QAD'ed IPv4 address + local fixed port.
    ///
    /// It is possible to configure krikos to bound to a specific port and independently
    /// configure the router to forward this port to the krikos endpoint.  This indicates a
    /// situation like this, which still uses QAD to discover the public address.
    Qad4LocalPort,
    /// An address explicitly provided by the user via configuration.
    Config,
}

impl Display for DirectAddrType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DirectAddrType::Unknown => write!(f, "?"),
            DirectAddrType::Local => write!(f, "local"),
            DirectAddrType::Qad => write!(f, "qad"),
            DirectAddrType::Portmapped => write!(f, "portmap"),
            DirectAddrType::Qad4LocalPort => write!(f, "qad4localport"),
            DirectAddrType::Config => write!(f, "config"),
        }
    }
}
