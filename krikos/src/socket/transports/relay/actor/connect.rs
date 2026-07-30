use super::*;

/// Configuration needed to create a connection to a relay server.
#[derive(Debug, Clone)]
pub(super) struct RelayConnectionOptions {
    pub(super) secret_key: SecretKey,
    #[cfg(not(wasm_browser))]
    pub(super) dns_resolver: DnsResolver,
    pub(super) proxy_url: Option<Url>,
    pub(super) prefer_ipv6: Arc<AtomicBool>,
    pub(super) tls_config: rustls::ClientConfig,
    pub(super) auth_token: Option<String>,
}

/// Possible reasons for a failed relay connection.
#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
pub(super) enum RelayConnectionError {
    #[error("Failed to connect to relay server")]
    Dial { source: DialError },
    #[error("Failed to handshake with relay server")]
    Handshake { source: RunError },
    #[error("Lost connection to relay server")]
    Established { source: RunError },
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
pub(super) enum RunError {
    #[error("Send timeout")]
    SendTimeout,
    #[error("Ping timeout")]
    PingTimeout,
    #[error("Local IP no longer valid")]
    LocalIpInvalid,
    #[error("No local address")]
    LocalAddrMissing,
    #[error("Stream closed by server.")]
    StreamClosedServer,
    #[error("Client stream read failed")]
    ClientStreamRead {
        #[error(std_err)]
        source: RecvError,
    },
    #[error("Client stream write failed")]
    ClientStreamWrite {
        #[error(std_err)]
        source: SendError,
    },
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
pub(super) enum DialError {
    #[error("timeout (>{timeout:?}) trying to establish a connection")]
    Timeout { timeout: Duration },
    #[error("unable to connect")]
    Connect { source: ConnectError },
    #[cfg(not(wasm_browser))]
    #[error("injected relay connector failed")]
    Injected {
        #[error(std_err)]
        source: crate::simulation::RelayConnectError,
    },
}

impl ActiveRelayActor {
    pub(super) fn new(opts: ActiveRelayActorOptions) -> Result<Self, String> {
        let ActiveRelayActorOptions {
            url,
            prio_inbox_: prio_inbox,
            inbox,
            relay_datagrams_send,
            relay_datagrams_recv,
            connection_opts,
            #[cfg(not(wasm_browser))]
            relay_connector,
            #[cfg(not(wasm_browser))]
            runtime,
            stop_token,
            metrics,
            my_relay,
        } = opts;
        #[cfg(not(wasm_browser))]
        let relay_connect_request = crate::simulation::RelayConnectRequest::new(
            url.clone(),
            connection_opts.secret_key.clone(),
            connection_opts.auth_token.clone(),
        );
        let relay_client_builder = Self::create_relay_builder(url.clone(), connection_opts);
        #[cfg(not(wasm_browser))]
        let inactive_timeout =
            RuntimeSleep::after(runtime.context().clock(), RELAY_INACTIVE_CLEANUP_TIME)
                .map_err(|error| error.to_string())?;
        #[cfg(not(wasm_browser))]
        let relay_key = blake3::hash(url.as_str().as_bytes()).to_hex();
        #[cfg(not(wasm_browser))]
        let ping_decisions = runtime
            .context()
            .decisions()
            .stream(&format!("relay/ping/{}", &relay_key[..16]))
            .map_err(|error| error.to_string())?;
        #[cfg(not(wasm_browser))]
        let backoff_decisions = runtime
            .context()
            .decisions()
            .stream(&format!("relay/backoff/{}", &relay_key[..16]))
            .map_err(|error| error.to_string())?;
        Ok(ActiveRelayActor {
            prio_inbox,
            inbox,
            relay_datagrams_recv,
            relay_datagrams_send,
            url,
            relay_client_builder,
            #[cfg(not(wasm_browser))]
            relay_connector,
            #[cfg(not(wasm_browser))]
            relay_connect_request,
            is_home_relay: false,
            #[cfg(wasm_browser)]
            inactive_timeout: Box::pin(time::sleep(RELAY_INACTIVE_CLEANUP_TIME)),
            #[cfg(not(wasm_browser))]
            inactive_timeout,
            #[cfg(not(wasm_browser))]
            runtime,
            #[cfg(not(wasm_browser))]
            ping_decisions,
            #[cfg(not(wasm_browser))]
            backoff_decisions,
            stop_token,
            metrics,
            my_relay,
        })
    }

    fn create_relay_builder(
        url: RelayUrl,
        opts: RelayConnectionOptions,
    ) -> relay::client::ClientBuilder {
        let RelayConnectionOptions {
            secret_key,
            #[cfg(not(wasm_browser))]
            dns_resolver,
            proxy_url,
            prefer_ipv6,
            tls_config,
            auth_token,
        } = opts;

        let mut builder = relay::client::ClientBuilder::new(
            url,
            secret_key,
            #[cfg(not(wasm_browser))]
            dns_resolver,
        )
        .tls_client_config(tls_config)
        .address_family_selector(move || prefer_ipv6.load(Ordering::Relaxed));
        if let Some(proxy_url) = proxy_url {
            builder = builder.proxy_url(proxy_url);
        }

        if let Some(token) = auth_token {
            builder = builder.auth_token(token);
        }
        builder
    }

    /// The main actor run loop.
    ///
    /// Primarily switches between the dialing and connected states.
    pub(super) async fn run(mut self) {
        let mut backoff = Self::build_backoff();

        while let Err(err) = self.run_once().await {
            warn!("{err:#}");
            let was_established = matches!(err, RelayConnectionError::Established { .. });
            let last_error = Some(Arc::new(AnyError::from(err)));
            self.my_relay
                .set_status(&self.url, RelayConnectionState::Disconnected { last_error });
            if !was_established {
                // If dialing failed, or if the relay connection failed before we received a pong,
                // we wait an exponentially increasing time until we attempt to reconnect again.
                let Some(delay) = backoff.next() else {
                    warn!("retries exceeded");
                    break;
                };
                #[cfg(not(wasm_browser))]
                let delay = match self.jitter_backoff(delay) {
                    Ok(delay) => delay,
                    Err(error) => {
                        self.runtime.latch_failure(error);
                        break;
                    }
                };
                debug!("retry in {delay:?}");
                #[cfg(wasm_browser)]
                time::sleep(delay).await;
                #[cfg(not(wasm_browser))]
                match RuntimeSleep::after(self.runtime.context().clock(), delay) {
                    Ok(sleep) => {
                        if let Err(error) = sleep.await {
                            self.runtime.latch_failure(error.to_string());
                            break;
                        }
                    }
                    Err(error) => {
                        self.runtime.latch_failure(error.to_string());
                        break;
                    }
                }
            } else {
                // If the relay connection remained established long enough so that we received a pong
                // from the relay server, we reset the backoff and attempt to reconnect immediately.
                backoff = Self::build_backoff();
            }
        }
        debug!("exiting");
    }

    fn build_backoff() -> impl Backoff {
        let builder = ExponentialBuilder::new()
            .with_min_delay(Duration::from_millis(10))
            .with_max_delay(Duration::from_secs(16))
            .without_max_times();
        #[cfg(wasm_browser)]
        let builder = builder.with_jitter();
        builder.build()
    }

    #[cfg(not(wasm_browser))]
    fn jitter_backoff(&mut self, base: Duration) -> Result<Duration, String> {
        let factor = self
            .backoff_decisions
            .range_u64(500_000..1_500_001)
            .map_err(|error| error.to_string())?;
        let nanos = base
            .as_nanos()
            .checked_mul(u128::from(factor))
            .and_then(|value| value.checked_div(1_000_000))
            .ok_or_else(|| "relay backoff jitter overflow".to_owned())?;
        let nanos = u64::try_from(nanos)
            .map_err(|_| "relay backoff jitter exceeds runtime duration".to_owned())?;
        Ok(Duration::from_nanos(nanos))
    }

    /// Attempt to connect to the relay, and run the connected actor loop.
    ///
    /// Returns `Ok(())` if the actor loop should shut down. Returns an error if dialing failed,
    /// or if the relay connection failed while connected. In both cases, the connection should
    /// be retried with a backoff.
    async fn run_once(&mut self) -> Result<(), RelayConnectionError> {
        self.my_relay
            .set_status(&self.url, RelayConnectionState::Connecting);
        let client = match self.run_dialing().instrument(info_span!("dialing")).await {
            Some(client_res) => client_res.map_err(|err| e!(RelayConnectionError::Dial, err))?,
            None => return Ok(()),
        };
        self.my_relay
            .set_status(&self.url, RelayConnectionState::Connected);
        self.run_connected(client)
            .instrument(info_span!("connected"))
            .await
    }

    fn reset_inactive_timeout(&mut self) {
        #[cfg(wasm_browser)]
        self.inactive_timeout
            .as_mut()
            .reset(Instant::now() + RELAY_INACTIVE_CLEANUP_TIME);
        #[cfg(not(wasm_browser))]
        if let Err(error) = self
            .inactive_timeout
            .reset(self.runtime.context().clock().now() + RELAY_INACTIVE_CLEANUP_TIME)
        {
            self.runtime.latch_failure(error.to_string());
            self.stop_token.cancel();
        }
    }

    fn set_home_relay(&mut self, is_home: bool) {
        let prev = std::mem::replace(&mut self.is_home_relay, is_home);
        if self.is_home_relay != prev {
            event!(
                target: "krikos::_events::relay::home_changed",
                Level::DEBUG,
                url = %self.url,
                home_relay = self.is_home_relay,
            );
        }
    }

    #[cfg(not(wasm_browser))]
    fn new_ping(&mut self, tracker: &mut PingTracker) -> Result<[u8; 8], String> {
        let mut data = [0; 8];
        self.ping_decisions
            .fill_bytes(&mut data)
            .map_err(|error| error.to_string())?;
        Ok(tracker.new_ping_with_data_at(
            tracker.ping_timeout(),
            data,
            self.runtime.context().clock().now(),
        ))
    }

    /// Actor loop when connecting to the relay server.
    ///
    /// Returns `None` if the actor needs to shut down.  Returns `Some(Ok(client))` when the
    /// connection is established, and `Some(Err(err))` if dialing the relay failed.
    async fn run_dialing(&mut self) -> Option<Result<krikos_relay::client::Client, DialError>> {
        trace!("Actor loop: connecting to relay.");

        // We regularly flush the relay_datagrams_send queue so it is not full of stale
        // packets while reconnecting.  Those datagrams are dropped and the QUIC congestion
        // controller will have to handle this (DISCO packets do not yet have retry).  This
        // is not an ideal mechanism, an alternative approach would be to use
        // e.g. ConcurrentQueue with force_push, though now you might still send very stale
        // packets when eventually connected.  So perhaps this is a reasonable compromise.
        #[cfg(wasm_browser)]
        let mut send_datagram_flush = time::interval(UNDELIVERABLE_DATAGRAM_TIMEOUT);
        #[cfg(wasm_browser)]
        send_datagram_flush.set_missed_tick_behavior(MissedTickBehavior::Delay);
        #[cfg(wasm_browser)]
        send_datagram_flush.reset(); // Skip the immediate interval
        #[cfg(not(wasm_browser))]
        let mut send_datagram_flush = match RuntimeInterval::new(
            self.runtime.context().clock(),
            UNDELIVERABLE_DATAGRAM_TIMEOUT,
            UNDELIVERABLE_DATAGRAM_TIMEOUT,
        ) {
            Ok(interval) => interval,
            Err(error) => {
                self.runtime.latch_failure(error.to_string());
                return None;
            }
        };

        let dialing_fut = self.dial_relay();
        tokio::pin!(dialing_fut);
        loop {
            tokio::select! {
                biased;
                _ = self.stop_token.cancelled() => {
                    debug!("Shutdown.");
                    break None;
                }
                msg = self.prio_inbox.recv() => {
                    let Some(msg) = msg else {
                        warn!("Priority inbox closed, shutdown.");
                        break None;
                    };
                    match msg {
                        ActiveRelayPrioMessage::HasEndpointRoute(_peer, sender) => {
                            sender.send(false).ok();
                        }
                    }
                }
                res = &mut dialing_fut => {
                    match res {
                        Ok(client) => {
                            break Some(Ok(client));
                        }
                        Err(err) => {
                            break Some(Err(err));
                        }
                    }
                }
                msg = self.inbox.recv() => {
                    let Some(msg) = msg else {
                        debug!("Inbox closed, shutdown.");
                        break None;
                    };
                    match msg {
                        ActiveRelayMessage::SetHomeRelay(is_home) => {
                            self.set_home_relay(is_home);
                        }
                        ActiveRelayMessage::CheckConnection { .. } => {}
                        #[cfg(test)]
                        ActiveRelayMessage::GetLocalAddr(sender) => {
                            sender.send(None).ok();
                        }
                        #[cfg(test)]
                        ActiveRelayMessage::PingServer(sender) => {
                            drop(sender);
                        }
                    }
                }
                tick = send_datagram_flush.tick() => {
                    #[cfg(not(wasm_browser))]
                    if let Err(error) = tick {
                        self.runtime.latch_failure(error.to_string());
                        break None;
                    }
                    self.reset_inactive_timeout();
                    let mut logged = false;
                    while self.relay_datagrams_send.try_recv().is_ok() {
                        if !logged {
                            debug!(?UNDELIVERABLE_DATAGRAM_TIMEOUT, "Dropping datagrams to send.");
                            logged = true;
                        }
                    }
                }
                timeout = &mut self.inactive_timeout, if !self.is_home_relay => {
                    #[cfg(not(wasm_browser))]
                    if let Err(error) = timeout {
                        self.runtime.latch_failure(error.to_string());
                    }
                    debug!(?RELAY_INACTIVE_CLEANUP_TIME, "Inactive, exiting.");
                    break None;
                }
            }
        }
    }

    /// Returns a future which will complete once connected to the relay server.
    ///
    /// The future only completes once the connection is established and retries
    /// connections.  It currently does not ever return `Err` as the retries continue
    /// forever.
    // This is using `impl Future` to return a future without a reference to self.
    pub(super) fn dial_relay(&self) -> impl Future<Output = Result<Client, DialError>> + use<> {
        let client_builder = self.relay_client_builder.clone();
        #[cfg(not(wasm_browser))]
        let relay_connector = self.relay_connector.clone();
        #[cfg(not(wasm_browser))]
        let relay_connect_request = self.relay_connect_request.clone();
        #[cfg(not(wasm_browser))]
        let runtime = self.runtime.clone();
        async move {
            #[cfg(not(wasm_browser))]
            let connect = async move {
                if let Some(connector) = relay_connector {
                    connector
                        .connect(relay_connect_request)
                        .await
                        .map_err(|err| e!(DialError::Injected, err))
                } else {
                    client_builder
                        .connect()
                        .await
                        .map_err(|err| e!(DialError::Connect, err))
                }
            };
            #[cfg(wasm_browser)]
            let connect = async move {
                client_builder
                    .connect()
                    .await
                    .map_err(|err| e!(DialError::Connect, err))
            };
            #[cfg(wasm_browser)]
            let result = time::timeout(CONNECT_TIMEOUT, connect).await;
            #[cfg(not(wasm_browser))]
            let result =
                match RuntimeTimeout::after(runtime.context().clock(), CONNECT_TIMEOUT, connect) {
                    Ok(timeout) => timeout.await.map_err(|error| match error {
                        krikos_runtime::TimeoutError::Elapsed => None,
                        krikos_runtime::TimeoutError::Clock(error) => Some(error),
                    }),
                    Err(error) => Err(Some(error)),
                };
            #[cfg(wasm_browser)]
            match result {
                Ok(Ok(client)) => Ok(client),
                Ok(Err(err)) => Err(err),
                Err(_) => Err(e!(DialError::Timeout {
                    timeout: CONNECT_TIMEOUT
                })),
            }
            #[cfg(not(wasm_browser))]
            match result {
                Ok(Ok(client)) => Ok(client),
                Ok(Err(err)) => Err(err),
                Err(None) => Err(e!(DialError::Timeout {
                    timeout: CONNECT_TIMEOUT
                })),
                Err(Some(error)) => {
                    runtime.latch_failure(error.to_string());
                    Err(e!(DialError::Timeout {
                        timeout: CONNECT_TIMEOUT
                    }))
                }
            }
        }
    }

    /// Runs the actor loop when connected to a relay server.
    ///
    /// Returns `Ok` if the actor needs to shut down.  `Err` is returned if the connection
    /// to the relay server is lost.
    async fn run_connected(
        &mut self,
        client: krikos_relay::client::Client,
    ) -> Result<(), RelayConnectionError> {
        trace!("Actor loop: connected to relay");
        event!(
            target: "krikos::_events::relay::connected",
            Level::DEBUG,
            url = %self.url,
            home_relay = self.is_home_relay,
        );

        let (mut client_stream, client_sink) = client.split();
        let mut client_sink = client_sink.sink_map_err(|e| e!(RunError::ClientStreamWrite, e));

        let mut state = ConnectedRelayState {
            ping_tracker: PingTracker::default(),
            endpoints_present: BTreeSet::new(),
            last_packet_src: None,
            pong_pending: None,
            established: false,
            #[cfg(test)]
            test_pong: None,
        };

        // A buffer to pass through multiple datagrams at once as an optimisation.
        let mut send_datagrams_buf = Vec::with_capacity(SEND_DATAGRAM_BATCH_SIZE);

        // Regularly send pings so we know the connection is healthy.
        // The first ping will be sent immediately.
        #[cfg(wasm_browser)]
        let mut ping_interval = time::interval(PING_INTERVAL);
        #[cfg(wasm_browser)]
        ping_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        #[cfg(not(wasm_browser))]
        let mut ping_interval = match RuntimeInterval::new(
            self.runtime.context().clock(),
            Duration::ZERO,
            PING_INTERVAL,
        ) {
            Ok(interval) => interval,
            Err(error) => {
                self.runtime.latch_failure(error.to_string());
                return Err(state.map_err(e!(RunError::PingTimeout)));
            }
        };

        let res = loop {
            if let Some(data) = state.pong_pending.take() {
                let fut = client_sink.send(ClientToRelayMsg::Pong(data));
                self.run_sending(fut, &mut state, &mut client_stream)
                    .await?;
            }
            let ping_deadline = state.ping_tracker.deadline();
            #[cfg(not(wasm_browser))]
            let ping_sleep = match ping_deadline {
                Some(deadline) => match RuntimeSleep::new(self.runtime.context().clock(), deadline)
                {
                    Ok(sleep) => MaybeFuture::Some(sleep),
                    Err(error) => {
                        self.runtime.latch_failure(error.to_string());
                        break Err(e!(RunError::PingTimeout));
                    }
                },
                None => MaybeFuture::None,
            };
            #[cfg(not(wasm_browser))]
            let ping_timeout = async move { ping_sleep.await.map_err(|error| error.to_string()) };
            #[cfg(wasm_browser)]
            let ping_timeout = async move {
                match ping_deadline {
                    Some(deadline) => time::sleep_until(deadline).await,
                    None => std::future::pending().await,
                }
                Ok::<(), String>(())
            };
            tokio::pin!(ping_timeout);
            tokio::select! {
                biased;
                _ = self.stop_token.cancelled() => {
                    debug!("Shutdown.");
                    break Ok(());
                }
                msg = self.prio_inbox.recv() => {
                    let Some(msg) = msg else {
                        warn!("Priority inbox closed, shutdown.");
                        break Ok(());
                    };
                    match msg {
                        ActiveRelayPrioMessage::HasEndpointRoute(peer, sender) => {
                            let has_peer = state.endpoints_present.contains(&peer);
                            sender.send(has_peer).ok();
                        }
                    }
                }
                timeout = &mut ping_timeout => {
                    #[cfg(not(wasm_browser))]
                    if let Err(error) = timeout {
                        self.runtime.latch_failure(error);
                    }
                    state.ping_tracker.timeout_elapsed();
                    break Err(e!(RunError::PingTimeout));
                }
                tick = ping_interval.tick() => {
                    #[cfg(not(wasm_browser))]
                    if let Err(error) = tick {
                        self.runtime.latch_failure(error.to_string());
                        break Err(e!(RunError::PingTimeout));
                    }
                    #[cfg(wasm_browser)]
                    let data = state.ping_tracker.new_ping();
                    #[cfg(not(wasm_browser))]
                    let data = match self.new_ping(&mut state.ping_tracker) {
                        Ok(data) => data,
                        Err(error) => {
                            self.runtime.latch_failure(error);
                            break Err(e!(RunError::PingTimeout));
                        }
                    };
                    let fut = client_sink.send(ClientToRelayMsg::Ping(data));
                    self.run_sending(fut, &mut state, &mut client_stream).await?;
                }
                msg = self.inbox.recv() => {
                    let Some(msg) = msg else {
                        warn!("Inbox closed, shutdown.");
                        break Ok(());
                    };
                    match msg {
                        ActiveRelayMessage::SetHomeRelay(is_home) => {
                            self.set_home_relay(is_home);
                            // We are in `run_connected`, so if we just became the home
                            // relay, publish `Connected` (the `RelayActor` only sets
                            // `Connecting` on the URL change since it cannot know our
                            // actual state).
                            if is_home {
                                self.my_relay
                                    .set_status(&self.url, RelayConnectionState::Connected);
                            }
                        }
                        ActiveRelayMessage::CheckConnection { local_ips } => {
                            match client_stream.local_addr() {
                                Some(addr) if local_ips.contains(&addr.ip()) => {
                                    #[cfg(wasm_browser)]
                                    let data = state.ping_tracker.new_ping();
                                    #[cfg(not(wasm_browser))]
                                    let data = match self.new_ping(&mut state.ping_tracker) {
                                        Ok(data) => data,
                                        Err(error) => {
                                            self.runtime.latch_failure(error);
                                            break Err(e!(RunError::PingTimeout));
                                        }
                                    };
                                    let fut = client_sink.send(ClientToRelayMsg::Ping(data));
                                    self.run_sending(fut, &mut state, &mut client_stream).await?;
                                }
                                Some(_) => break Err(e!(RunError::LocalIpInvalid)),
                                None => break Err(e!(RunError::LocalAddrMissing)),
                            }
                        }
                        #[cfg(test)]
                        ActiveRelayMessage::GetLocalAddr(sender) => {
                            let addr = client_stream.local_addr();
                            sender.send(addr).ok();
                        }
                        #[cfg(test)]
                        ActiveRelayMessage::PingServer(sender) => {
                            let data = rand::random();
                            state.test_pong = Some((data, sender));
                            let fut = client_sink.send(ClientToRelayMsg::Ping(data));
                            self.run_sending(fut, &mut state, &mut client_stream).await?;
                        }
                    }
                }
                count = self.relay_datagrams_send.recv_many(
                    &mut send_datagrams_buf,
                    SEND_DATAGRAM_BATCH_SIZE,
                ) => {
                    if count == 0 {
                        warn!("Datagram inbox closed, shutdown");
                        break Ok(());
                    };
                    self.reset_inactive_timeout();
                    // TODO(frando): can we avoid the clone here?
                    let metrics = self.metrics.clone();
                    let packet_iter = send_datagrams_buf.drain(..).map(|item| {
                        metrics.send_relay.inc_by(item.datagrams.contents.len() as _);
                        Ok(ClientToRelayMsg::Datagrams {
                            dst_endpoint_id: item.remote_endpoint,
                            datagrams: item.datagrams,
                        })
                    });
                    let mut packet_stream = n0_future::stream::iter(packet_iter);
                    let fut = client_sink.send_all(&mut packet_stream);
                    self.run_sending(fut, &mut state, &mut client_stream).await?;
                }
                msg = client_stream.next() => {
                    let Some(msg) = msg else {
                        break Err(e!(RunError::StreamClosedServer));
                    };
                    match msg {
                        Ok(msg) => {
                            self.handle_relay_msg(msg, &mut state);
                            // reset the ping timer, we have just received a message
                            #[cfg(wasm_browser)]
                            ping_interval.reset();
                            #[cfg(not(wasm_browser))]
                            if let Err(error) = ping_interval.reset() {
                                self.runtime.latch_failure(error.to_string());
                                break Err(e!(RunError::PingTimeout));
                            }
                        },
                        Err(err) => break Err(e!(RunError::ClientStreamRead, err)),
                    }
                }
                timeout = &mut self.inactive_timeout, if !self.is_home_relay => {
                    #[cfg(not(wasm_browser))]
                    if let Err(error) = timeout {
                        self.runtime.latch_failure(error.to_string());
                    }
                    debug!("Inactive for {RELAY_INACTIVE_CLEANUP_TIME:?}, exiting (running).");
                    break Ok(());
                }
            }
        };

        if res.is_ok()
            && let Err(err) = client_sink.close().await
        {
            debug!("Failed to close client sink gracefully: {err:#}");
        }

        res.map_err(|err| state.map_err(err))
    }

    fn handle_relay_msg(&mut self, msg: RelayToClientMsg, state: &mut ConnectedRelayState) {
        match msg {
            RelayToClientMsg::Datagrams {
                remote_endpoint_id,
                datagrams,
            } => {
                trace!(len = datagrams.contents.len(), "received msg");
                // If this is a new sender, register a route for this peer.
                if state
                    .last_packet_src
                    .as_ref()
                    .map(|p| *p != remote_endpoint_id)
                    .unwrap_or(true)
                {
                    // Avoid map lookup with high throughput single peer.
                    state.last_packet_src = Some(remote_endpoint_id);
                    state.endpoints_present.insert(remote_endpoint_id);
                }

                if let Err(err) = self.relay_datagrams_recv.try_send(RelayRecvDatagram {
                    url: self.url.clone(),
                    src: remote_endpoint_id,
                    datagrams,
                }) {
                    warn!("Dropping received relay packet: {err:#}");
                }
            }
            RelayToClientMsg::EndpointGone(endpoint_id) => {
                state.endpoints_present.remove(&endpoint_id);
            }
            RelayToClientMsg::Ping(data) => state.pong_pending = Some(data),
            RelayToClientMsg::Pong(data) => {
                #[cfg(test)]
                {
                    if let Some((expected_data, sender)) = state.test_pong.take() {
                        if data == expected_data {
                            sender.send(()).ok();
                        } else {
                            state.test_pong = Some((expected_data, sender));
                        }
                    }
                }
                #[cfg(wasm_browser)]
                state.ping_tracker.pong_received(data);
                #[cfg(not(wasm_browser))]
                state
                    .ping_tracker
                    .pong_received_at(data, self.runtime.context().clock().now());
                state.established = true;
            }
            RelayToClientMsg::Status(status) => match status {
                Status::Healthy => info!("Relay server reports: {status}"),
                _ => warn!("Relay server reports problem: {status}"),
            },
            RelayToClientMsg::Restarting { .. } => {
                trace!("Ignoring {msg:?}")
            }
            // Deprecated variants, kept for backwards compatibility with older relay protocol versions.
            RelayToClientMsg::Health { problem } => {
                warn!("Relay server reports problem: {problem}");
            }
            _ => unreachable!(
                "got unknown RelayToClientMsg but krikos is released in sync with krikos-relay"
            ),
        }
    }

    /// Run the actor main loop while sending to the relay server.
    ///
    /// While sending the actor should not read any inboxes which will give it more things
    /// to send to the relay server.
    ///
    /// # Returns
    ///
    /// On `Err` the relay connection should be disconnected.  An `Ok` return means either
    /// the actor should shut down, consult the [`ActiveRelayActor::stop_token`] and
    /// [`ActiveRelayActor::inactive_timeout`] for this, or the send was successful.
    #[instrument(name = "tx", skip_all)]
    async fn run_sending<T>(
        &mut self,
        sending_fut: impl Future<Output = Result<T, RunError>>,
        state: &mut ConnectedRelayState,
        client_stream: &mut krikos_relay::client::ClientStream,
    ) -> Result<(), RelayConnectionError> {
        // we use the same time as for our ping interval
        let send_timeout = PING_INTERVAL;

        #[cfg(wasm_browser)]
        let mut timeout = pin!(time::sleep(send_timeout));
        #[cfg(not(wasm_browser))]
        let mut timeout = match RuntimeSleep::after(self.runtime.context().clock(), send_timeout) {
            Ok(timeout) => timeout,
            Err(error) => {
                self.runtime.latch_failure(error.to_string());
                return Err(state.map_err(e!(RunError::SendTimeout)));
            }
        };
        let mut sending_fut = pin!(sending_fut);
        let res = loop {
            let ping_deadline = state.ping_tracker.deadline();
            #[cfg(not(wasm_browser))]
            let ping_sleep = match ping_deadline {
                Some(deadline) => match RuntimeSleep::new(self.runtime.context().clock(), deadline)
                {
                    Ok(sleep) => MaybeFuture::Some(sleep),
                    Err(error) => {
                        self.runtime.latch_failure(error.to_string());
                        break Err(e!(RunError::PingTimeout));
                    }
                },
                None => MaybeFuture::None,
            };
            #[cfg(not(wasm_browser))]
            let ping_timeout = async move { ping_sleep.await.map_err(|error| error.to_string()) };
            #[cfg(wasm_browser)]
            let ping_timeout = async move {
                match ping_deadline {
                    Some(deadline) => time::sleep_until(deadline).await,
                    None => std::future::pending().await,
                }
                Ok::<(), String>(())
            };
            tokio::pin!(ping_timeout);
            tokio::select! {
                biased;
                _ = self.stop_token.cancelled() => {
                    break Ok(());
                }
                elapsed = &mut timeout => {
                    #[cfg(not(wasm_browser))]
                    if let Err(error) = elapsed {
                        self.runtime.latch_failure(error.to_string());
                    }
                    break Err(e!(RunError::SendTimeout));
                }
                msg = self.prio_inbox.recv() => {
                    let Some(msg) = msg else {
                        warn!("Priority inbox closed, shutdown.");
                        break Ok(());
                    };
                    match msg {
                        ActiveRelayPrioMessage::HasEndpointRoute(peer, sender) => {
                            let has_peer = state.endpoints_present.contains(&peer);
                            sender.send(has_peer).ok();
                        }
                    }
                }
                res = &mut sending_fut => {
                    match res {
                        Ok(_) => break Ok(()),
                        Err(err) => break Err(err),
                    }
                }
                elapsed = &mut ping_timeout => {
                    #[cfg(not(wasm_browser))]
                    if let Err(error) = elapsed {
                        self.runtime.latch_failure(error);
                    }
                    state.ping_tracker.timeout_elapsed();
                    break Err(e!(RunError::PingTimeout));
                }
                // No need to read the inbox or datagrams to send.
                msg = client_stream.next() => {
                    let Some(msg) = msg else {
                        break Err(e!(RunError::StreamClosedServer));
                    };
                    match msg {
                        Ok(msg) => self.handle_relay_msg(msg, state),
                        Err(err) => break Err(e!(RunError::ClientStreamRead, err)),
                    }
                }
                elapsed = &mut self.inactive_timeout, if !self.is_home_relay => {
                    #[cfg(not(wasm_browser))]
                    if let Err(error) = elapsed {
                        self.runtime.latch_failure(error.to_string());
                    }
                    debug!("Inactive for {RELAY_INACTIVE_CLEANUP_TIME:?}, exiting (sending).");
                    break Ok(());
                }
            }
        };
        res.map_err(|err| state.map_err(err))
    }
}
