//! The relay actor.
//!
//! The [`RelayActor`] handles all the relay connections.  It is helped by the
//! [`ActiveRelayActor`] which handles a single relay connection.
//!
//! - The [`RelayActor`] manages all connections to relay servers.
//!   - It starts a new [`ActiveRelayActor`] for each relay server needed.
//!   - The [`ActiveRelayActor`] will exit when unused.
//!     - Unless it is for the home relay, this one never exits.
//!   - Each [`ActiveRelayActor`] uses a relay [`Client`].
//!     - The relay [`Client`] is a `Stream` and `Sink` directly connected to the
//!       `TcpStream` connected to the relay server.
//!   - Each [`ActiveRelayActor`] will try and maintain a connection with the relay server.
//!     - If connections fail, exponential backoff is used for reconnections.
//! - When `AsyncUdpSocket` needs to send datagrams:
//!   - It puts them on a queue to the [`RelayActor`].
//!   - The [`RelayActor`] ensures the correct [`ActiveRelayActor`] is running and
//!     forwards datagrams to it.
//!   - The ActiveRelayActor sends datagrams directly to the relay server.
//! - The relay receive path is:
//!   - Whenever [`ActiveRelayActor`] is connected it reads from the underlying `TcpStream`.
//!   - Received datagrams are placed on an mpsc channel that now bypasses the
//!     [`RelayActor`] and goes straight to the `AsyncUpdSocket` interface.
//!
//! [`Client`]: iroh_relay::client::Client

#[cfg(test)]
use std::net::SocketAddr;
#[cfg(not(wasm_browser))]
use std::panic::AssertUnwindSafe;
#[cfg(wasm_browser)]
use std::pin::Pin;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    net::IpAddr,
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use backon::{Backoff, BackoffBuilder, ExponentialBuilder};
#[cfg(not(wasm_browser))]
use futures_util::FutureExt;
use iroh_base::{EndpointId, RelayUrl, SecretKey};
use iroh_relay::{
    self as relay, PingTracker, RelayMap,
    client::{Client, ConnectError, RecvError, SendError},
    protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg, Status},
};
#[cfg(not(wasm_browser))]
use iroh_runtime::DecisionStream;
use n0_error::{AnyError, e, stack_error};
#[cfg(wasm_browser)]
use n0_future::task::JoinSet;
#[cfg(wasm_browser)]
use n0_future::time::{self, Instant, MissedTickBehavior};
use n0_future::{FuturesUnorderedBounded, MaybeFuture, SinkExt, StreamExt, time::Duration};
use n0_watcher::Watchable;
use netwatch::interfaces;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, Level, debug, error, event, info, info_span, instrument, trace, warn};
use url::Url;

#[cfg(not(wasm_browser))]
use crate::dns::DnsResolver;
#[cfg(not(wasm_browser))]
use crate::runtime::{Runtime, RuntimeInterval, RuntimeSleep, RuntimeTimeout};
use crate::{
    endpoint::{
        EndpointLimits, RelayStatus,
        limits::{AdmissionError, AdmissionLedger, AdmissionPermit},
    },
    net_report::Report,
    socket::Metrics as SocketMetrics,
};

mod connect;
mod messages;
mod session;

use connect::{RelayConnectionError, RelayConnectionOptions, RunError};
pub(super) use messages::RelayActorMessage;
pub(crate) use messages::{
    Config, HomeRelayWatch, RelayConnectionState, RelayRecvDatagram, RelaySendItem,
};
use session::{
    ActiveRelayActor, ActiveRelayActorOptions, ActiveRelayHandle, ActiveRelayMessage,
    ActiveRelayPrioMessage, ConnectedRelayState,
};

/// How long a non-home relay connection needs to be idle (last written to) before we close it.
const RELAY_INACTIVE_CLEANUP_TIME: Duration = Duration::from_secs(60);

/// Interval in which we ping the relay server to ensure the connection is alive.
///
/// The default QUIC max_idle_timeout is 30s, so setting that to half this time gives some
/// chance of recovering.
const PING_INTERVAL: Duration = Duration::from_secs(15);

/// Number of datagrams which can be sent to the relay server in one batch.
///
/// This means while this batch is sending to the server no other relay protocol frames can
/// be sent to the server, e.g. no Ping frames or so.  While the maximum packet size is
/// rather large, each item can typically be expected to up to 1500 or the max GSO size.
const SEND_DATAGRAM_BATCH_SIZE: usize = 20;

/// Timeout for establishing the relay connection.
///
/// This includes DNS, dialing the server, upgrading the connection, and completing the
/// handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Time after which the [`ActiveRelayActor`] will drop undeliverable datagrams.
///
/// When the [`ActiveRelayActor`] is not connected it can not deliver datagrams.  However it
/// will still receive datagrams to send from the [`RelayActor`].  If connecting takes
/// longer than this timeout datagrams will be dropped.
///
/// This value is set to 3 times the QUIC initial Probe Timeout (PTO).
const UNDELIVERABLE_DATAGRAM_TIMEOUT: Duration = Duration::from_secs(3);

pub(super) struct RelayActor {
    config: Config,
    /// Queue on which to put received datagrams.
    relay_datagram_recv_queue: mpsc::Sender<RelayRecvDatagram>,
    /// The actors managing each currently used relay server.
    ///
    /// These actors will exit when they have any inactivity.  Otherwise they will keep
    /// trying to maintain a connection to the relay server as needed.
    active_relays: BTreeMap<RelayUrl, ActiveRelayHandle>,
    /// The tasks for the [`ActiveRelayActor`]s in `active_relays` above.
    #[cfg(wasm_browser)]
    active_relay_tasks: JoinSet<AdmissionPermit>,
    /// Native task execution is owned by the endpoint runtime; this channel retains the relay
    /// actor's completion/reap protocol.
    #[cfg(not(wasm_browser))]
    active_relay_completions_tx: mpsc::Sender<ActiveRelayCompletion>,
    #[cfg(not(wasm_browser))]
    active_relay_completions_rx: mpsc::Receiver<ActiveRelayCompletion>,
    #[cfg(not(wasm_browser))]
    active_relay_task_count: usize,
    #[cfg(not(wasm_browser))]
    runtime: Arc<Runtime>,
    admission: Arc<AdmissionLedger>,
    cancel_token: CancellationToken,
}

#[cfg(not(wasm_browser))]
enum ActiveRelayCompletion {
    Finished(AdmissionPermit),
    Panicked(AdmissionPermit),
}

#[stack_error(derive, add_meta)]
#[derive(Clone)]
enum ActiveRelayAdmissionError {
    #[error("active-relay actor capacity is full")]
    CapacityFull,
    #[error("active-relay actor accounting exhausted")]
    CounterExhausted,
    #[error("active-relay actor task spawn was rejected")]
    SpawnRejected,
    #[error("active-relay actor construction failed")]
    ConstructionFailed,
}

impl From<AdmissionError> for ActiveRelayAdmissionError {
    fn from(error: AdmissionError) -> Self {
        match error {
            AdmissionError::CapacityFull => e!(Self::CapacityFull),
            AdmissionError::CounterExhausted => e!(Self::CounterExhausted),
        }
    }
}

impl RelayActor {
    pub(super) fn new(
        config: Config,
        relay_datagram_recv_queue: mpsc::Sender<RelayRecvDatagram>,
        cancel_token: CancellationToken,
        #[cfg(not(wasm_browser))] runtime: Arc<Runtime>,
    ) -> Self {
        #[cfg(not(wasm_browser))]
        let (active_relay_completions_tx, active_relay_completions_rx) =
            mpsc::channel(config.limits.max_active_relay_actors().get());
        let admission = AdmissionLedger::new(config.limits.max_active_relay_actors());
        Self {
            config,
            relay_datagram_recv_queue,
            active_relays: Default::default(),
            #[cfg(wasm_browser)]
            active_relay_tasks: JoinSet::new(),
            #[cfg(not(wasm_browser))]
            active_relay_completions_tx,
            #[cfg(not(wasm_browser))]
            active_relay_completions_rx,
            #[cfg(not(wasm_browser))]
            active_relay_task_count: 0,
            #[cfg(not(wasm_browser))]
            runtime,
            admission,
            cancel_token,
        }
    }

    pub(super) async fn run(
        mut self,
        mut receiver: mpsc::Receiver<RelayActorMessage>,
        mut datagram_send_channel: mpsc::Receiver<RelaySendItem>,
    ) {
        #[cfg(not(wasm_browser))]
        if let Some(url) = self.config.initial_relay.clone() {
            self.config
                .my_relay
                .set(url.clone(), RelayConnectionState::Connecting);
            self.set_home_relay(url).await;
        }

        // When this future is present, it is sending pending datagrams to an
        // ActiveRelayActor.  We can not process further datagrams during this time.
        let mut datagram_send_fut = std::pin::pin!(MaybeFuture::None);

        loop {
            #[cfg(wasm_browser)]
            let has_active_relay_tasks = !self.active_relay_tasks.is_empty();
            #[cfg(wasm_browser)]
            let active_relay_completion = self.active_relay_tasks.join_next();
            #[cfg(not(wasm_browser))]
            let active_relay_completion = self.active_relay_completions_rx.recv();
            #[cfg(not(wasm_browser))]
            let has_active_relay_tasks = self.active_relay_task_count > 0;

            tokio::select! {
                biased;
                _ = self.cancel_token.cancelled() => {
                    debug!("shutting down");
                    break;
                }
                completion = active_relay_completion, if has_active_relay_tasks => {
                    #[cfg(wasm_browser)]
                    if let Some(res) = completion {
                        match res {
                            Ok(permit) => drop(permit),
                            Err(err) if err.is_panic() => {
                                error!("ActiveRelayActor task panicked: {err:#?}");
                            }
                            Err(err) if err.is_cancelled() => {
                                error!("ActiveRelayActor cancelled: {err:#?}");
                            }
                            Err(err) => error!("ActiveRelayActor failed: {err:#?}"),
                        }
                    }
                    #[cfg(not(wasm_browser))]
                    if let Some(completion) = completion {
                        self.active_relay_task_count = self
                            .active_relay_task_count
                            .checked_sub(1)
                            .expect("active-relay task count must not underflow");
                        match completion {
                            ActiveRelayCompletion::Finished(permit) => drop(permit),
                            ActiveRelayCompletion::Panicked(permit) => {
                                drop(permit);
                                error!("ActiveRelayActor task panicked");
                            }
                        }
                    }
                    self.reap_active_relays();
                }
                msg = receiver.recv() => {
                    let Some(msg) = msg else {
                        debug!("Inbox dropped, shutting down.");
                        break;
                    };
                    let cancel_token = self.cancel_token.child_token();
                    cancel_token.run_until_cancelled(self.handle_msg(msg)).await;
                }
                // Only poll for new datagrams if we are not blocked on sending them.
                item = datagram_send_channel.recv(), if datagram_send_fut.is_none() => {
                    let Some(item) = item else {
                        debug!("Datagram send channel dropped, shutting down.");
                        break;
                    };
                    let token = self.cancel_token.child_token();
                    if let Some(Some(fut)) = token.run_until_cancelled(
                        self.try_send_datagram(item)
                    ).await {
                        datagram_send_fut.as_mut().set_future(fut);
                    }
                }
                // Only poll this future if it is in use.
                _ = &mut datagram_send_fut, if datagram_send_fut.is_some() => {
                    datagram_send_fut.as_mut().set_none();
                }
            }
        }

        // try shutdown
        #[cfg(wasm_browser)]
        if time::timeout(Duration::from_secs(3), self.close_all_active_relays())
            .await
            .is_err()
        {
            warn!("Failed to shut down all ActiveRelayActors");
        }
        #[cfg(not(wasm_browser))]
        {
            let runtime = self.runtime.clone();
            let clock = runtime.context().clock();
            match RuntimeTimeout::after(
                clock,
                Duration::from_secs(3),
                self.close_all_active_relays(),
            ) {
                Ok(timeout) => match timeout.await {
                    Ok(()) => {}
                    Err(iroh_runtime::TimeoutError::Elapsed) => {
                        warn!("Failed to shut down all ActiveRelayActors");
                    }
                    Err(iroh_runtime::TimeoutError::Clock(error)) => {
                        runtime.latch_failure(error.to_string());
                    }
                },
                Err(error) => runtime.latch_failure(error.to_string()),
            }
        }
    }

    async fn handle_msg(&mut self, msg: RelayActorMessage) {
        match msg {
            RelayActorMessage::NetworkChange { report } => {
                self.on_network_change(report).await;
            }
            RelayActorMessage::MaybeCloseRelaysOnRebind => {
                self.maybe_close_relays_on_rebind().await;
            }
            RelayActorMessage::CheckConnectionAfterNetworkChange => {
                self.check_connection_after_network_change().await;
            }
        }
    }

    /// Sends datagrams to the correct [`ActiveRelayActor`], or returns a future.
    ///
    /// If the datagram can not be sent immediately, because the destination channel is
    /// full, a future is returned that will complete once the datagrams have been sent to
    /// the [`ActiveRelayActor`].
    async fn try_send_datagram(
        &mut self,
        item: RelaySendItem,
    ) -> Option<impl Future<Output = ()> + use<>> {
        let url = item.url.clone();
        let handle = match self
            .active_relay_handle_for_endpoint(&item.url, &item.remote_endpoint)
            .await
        {
            Ok(handle) => handle,
            Err(error) => {
                self.config.metrics.active_relay_datagrams_rejected.inc();
                warn!(?url, %error, "Dropped datagram(s): active-relay capacity unavailable");
                return None;
            }
        };
        match handle.datagrams_send_queue.try_send(item) {
            Ok(()) => None,
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!(?url, "Dropped datagram(s): ActiveRelayActor closed.");
                None
            }
            Err(mpsc::error::TrySendError::Full(item)) => {
                let sender = handle.datagrams_send_queue.clone();
                let fut = async move {
                    if sender.send(item).await.is_err() {
                        warn!(?url, "Dropped datagram(s): ActiveRelayActor closed.");
                    }
                };
                Some(fut)
            }
        }
    }

    async fn on_network_change(&mut self, report: Report) {
        let prev = self.config.my_relay.get();
        let prev_url = prev.as_ref().map(RelayStatus::url);
        if report.preferred_relay.as_ref() == prev_url {
            // No change.
            return;
        }

        if let Some(relay_url) = report.preferred_relay {
            self.config.metrics.relay_home_change.inc();

            // On change, notify all currently connected relay servers and
            // start connecting to our home relay if we are not already.
            info!("home is now relay {}, was {:?}", relay_url, prev_url);
            // Publish `Connecting` initially. If an `ActiveRelayActor` already
            // exists for this URL it will republish its actual status (e.g.
            // `Connected`) when it receives the `SetHomeRelay(true)` message
            // sent below.
            self.config
                .my_relay
                .set(relay_url.clone(), RelayConnectionState::Connecting);
            self.set_home_relay(relay_url).await;
        } else {
            self.config.my_relay.clear();
        }
    }

    async fn set_home_relay(&mut self, home_url: RelayUrl) {
        let home_url_ref = &home_url;
        n0_future::join_all(self.active_relays.iter().map(|(url, handle)| async move {
            let is_preferred = url == home_url_ref;
            handle
                .inbox_addr
                .send(ActiveRelayMessage::SetHomeRelay(is_preferred))
                .await
                .ok()
        }))
        .await;
        // Ensure we have an ActiveRelayActor for the current home relay.
        if let Err(error) = self.active_relay_handle(home_url.clone()) {
            self.config.my_relay.set_status(
                &home_url,
                RelayConnectionState::Disconnected {
                    last_error: Some(Arc::new(AnyError::from(error))),
                },
            );
        }
    }

    /// Returns the handle for the [`ActiveRelayActor`] to reach `remote_endpoint`.
    ///
    /// The endpoint is expected to be reachable on `url`, but if no [`ActiveRelayActor`] for
    /// `url` exists but another existing [`ActiveRelayActor`] already knows about the endpoint,
    /// that other endpoint is used.
    async fn active_relay_handle_for_endpoint(
        &mut self,
        url: &RelayUrl,
        remote_endpoint: &EndpointId,
    ) -> Result<ActiveRelayHandle, ActiveRelayAdmissionError> {
        if let Some(handle) = self.active_relays.get(url) {
            return Ok(handle.clone());
        }

        let mut found_relay: Option<RelayUrl> = None;
        // If we don't have an open connection to the remote endpoint's home relay, see if
        // we have an open connection to a relay endpoint where we'd heard from that peer
        // already.  E.g. maybe they dialed our home relay recently.
        {
            // Futures which return Some(RelayUrl) if the relay knows about the remote endpoint.
            let check_futs = self.active_relays.iter().map(|(url, handle)| async move {
                let (tx, rx) = oneshot::channel();
                handle
                    .prio_inbox_addr
                    .send(ActiveRelayPrioMessage::HasEndpointRoute(
                        *remote_endpoint,
                        tx,
                    ))
                    .await
                    .ok();
                match rx.await {
                    Ok(true) => Some(url.clone()),
                    _ => None,
                }
            });
            let mut futures = FuturesUnorderedBounded::from_iter(check_futs);
            while let Some(maybe_url) = futures.next().await {
                if maybe_url.is_some() {
                    found_relay = maybe_url;
                    break;
                }
            }
        }
        let url = found_relay.unwrap_or(url.clone());
        self.active_relay_handle(url)
    }

    /// Returns the handle of the [`ActiveRelayActor`].
    fn active_relay_handle(
        &mut self,
        url: RelayUrl,
    ) -> Result<ActiveRelayHandle, ActiveRelayAdmissionError> {
        match self.active_relays.get(&url) {
            Some(e) => Ok(e.clone()),
            None => {
                let handle = self.start_active_relay(url.clone())?;
                if Some(&url) == self.config.my_relay.get().as_ref().map(RelayStatus::url)
                    && let Err(err) = handle
                        .inbox_addr
                        .try_send(ActiveRelayMessage::SetHomeRelay(true))
                {
                    error!("Home relay not set, send to new actor failed: {err:#}.");
                }
                self.active_relays.insert(url, handle.clone());
                self.log_active_relay();
                Ok(handle)
            }
        }
    }

    fn start_active_relay(
        &mut self,
        url: RelayUrl,
    ) -> Result<ActiveRelayHandle, ActiveRelayAdmissionError> {
        let permit = self.admission.try_acquire().map_err(|error| {
            self.config.metrics.active_relay_capacity_rejections.inc();
            ActiveRelayAdmissionError::from(error)
        })?;
        debug!(?url, "Adding relay connection");

        let auth_token = self
            .config
            .relay_map
            .get(&url)
            .and_then(|cfg| cfg.auth_token.clone());
        let connection_opts = RelayConnectionOptions {
            secret_key: self.config.secret_key.clone(),
            #[cfg(not(wasm_browser))]
            dns_resolver: self.config.dns_resolver.clone(),
            proxy_url: self.config.proxy_url.clone(),
            prefer_ipv6: self.config.ipv6_reported.clone(),
            tls_config: self.config.tls_config.clone(),
            auth_token,
        };

        // TODO: Replace 64 with PER_CLIENT_SEND_QUEUE_DEPTH once that's unused
        let (send_datagram_tx, send_datagram_rx) = mpsc::channel(64);
        let (prio_inbox_tx, prio_inbox_rx) = mpsc::channel(32);
        let (inbox_tx, inbox_rx) = mpsc::channel(64);
        let span = info_span!("active-relay", %url);
        let opts = ActiveRelayActorOptions {
            url,
            prio_inbox_: prio_inbox_rx,
            inbox: inbox_rx,
            relay_datagrams_send: send_datagram_rx,
            relay_datagrams_recv: self.relay_datagram_recv_queue.clone(),
            connection_opts,
            #[cfg(not(wasm_browser))]
            relay_connector: self.config.relay_connector.clone(),
            #[cfg(not(wasm_browser))]
            runtime: self.runtime.clone(),
            stop_token: self.cancel_token.child_token(),
            metrics: self.config.metrics.clone(),
            my_relay: self.config.my_relay.clone(),
        };
        let handle = ActiveRelayHandle {
            prio_inbox_addr: prio_inbox_tx,
            inbox_addr: inbox_tx,
            datagrams_send_queue: send_datagram_tx,
        };
        #[cfg(wasm_browser)]
        let actor = ActiveRelayActor::new(opts).expect("browser relay timer setup is infallible");
        #[cfg(not(wasm_browser))]
        let actor = match ActiveRelayActor::new(opts) {
            Ok(actor) => actor,
            Err(error) => {
                self.runtime.latch_failure(error);
                return Err(e!(ActiveRelayAdmissionError::ConstructionFailed));
            }
        };
        #[cfg(wasm_browser)]
        self.active_relay_tasks.spawn(
            async move {
                actor.run().await;
                permit
            }
            .instrument(span),
        );
        #[cfg(not(wasm_browser))]
        {
            let completions = self.active_relay_completions_tx.clone();
            let future = async move {
                let actor = actor.run().instrument(span);
                match AssertUnwindSafe(actor).catch_unwind().await {
                    Ok(()) => {
                        let _ = completions
                            .send(ActiveRelayCompletion::Finished(permit))
                            .await;
                    }
                    Err(panic) => {
                        let _ = completions
                            .send(ActiveRelayCompletion::Panicked(permit))
                            .await;
                        std::panic::resume_unwind(panic);
                    }
                }
            };
            if self
                .runtime
                .spawn(
                    iroh_runtime::TaskKind::Relay,
                    "active-relay-actor",
                    Box::pin(future),
                )
                .is_ok()
            {
                self.active_relay_task_count = self
                    .active_relay_task_count
                    .checked_add(1)
                    .expect("active-relay task count must not overflow");
            } else {
                self.config.metrics.active_relay_spawn_rejections.inc();
                return Err(e!(ActiveRelayAdmissionError::SpawnRejected));
            }
        }
        self.log_active_relay();
        Ok(handle)
    }

    /// Triggers an immediate health check on all relay connections after a network change.
    async fn check_connection_after_network_change(&mut self) {
        self.send_check_connection().await;
    }

    /// Closes the relay connections not originating from a local IP address.
    ///
    /// Called in response to a rebind, any relay connection originating from an address
    /// that's not known to be currently a local IP address should be closed.  All the other
    /// relay connections are pinged.
    async fn maybe_close_relays_on_rebind(&mut self) {
        self.send_check_connection().await;
        self.log_active_relay();
    }

    /// Sends a [`ActiveRelayMessage::CheckConnection`] to all active relays with current
    /// local IPs.
    async fn send_check_connection(&self) {
        #[cfg(not(wasm_browser))]
        let ifs = interfaces::State::new().await;
        #[cfg(not(wasm_browser))]
        let local_ips: Vec<_> = ifs
            .interfaces
            .values()
            .flat_map(|netif| netif.addrs())
            .map(|ipnet| ipnet.addr())
            .collect();
        // In browsers, we don't have this information. This will do the right thing
        // in the ActiveRelayActor, though.
        #[cfg(wasm_browser)]
        let local_ips = Vec::new();
        let send_futs = self.active_relays.values().map(|handle| {
            let local_ips = local_ips.clone();
            async move {
                handle
                    .inbox_addr
                    .send(ActiveRelayMessage::CheckConnection { local_ips })
                    .await
                    .ok();
            }
        });
        n0_future::join_all(send_futs).await;
    }

    /// Cleans up [`ActiveRelayActor`]s which have stopped running.
    fn reap_active_relays(&mut self) {
        self.active_relays
            .retain(|_url, handle| !handle.inbox_addr.is_closed());

        // Make sure home relay exists
        if let Some(status) = self.config.my_relay.get() {
            let url = status.url().clone();
            if let Err(error) = self.active_relay_handle(url.clone()) {
                self.config.my_relay.set_status(
                    &url,
                    RelayConnectionState::Disconnected {
                        last_error: Some(Arc::new(AnyError::from(error))),
                    },
                );
            }
        }
        self.log_active_relay();
    }

    /// Stops all [`ActiveRelayActor`]s and awaits for them to finish.
    async fn close_all_active_relays(&mut self) {
        self.cancel_token.cancel();
        #[cfg(wasm_browser)]
        {
            let tasks = std::mem::take(&mut self.active_relay_tasks);
            tasks.join_all().await;
        }
        #[cfg(not(wasm_browser))]
        while self.active_relay_task_count > 0 {
            match self.active_relay_completions_rx.recv().await {
                Some(completion) => {
                    drop(completion);
                    self.active_relay_task_count = self
                        .active_relay_task_count
                        .checked_sub(1)
                        .expect("active-relay shutdown task count must not underflow");
                }
                None => break,
            }
        }

        self.log_active_relay();
    }

    fn log_active_relay(&self) {
        debug!("{} active relay conns{}", self.active_relays.len(), {
            let mut s = String::new();
            if !self.active_relays.is_empty() {
                s += ":";
                for endpoint in self.active_relay_sorted() {
                    s += &format!(" relay-{endpoint}");
                }
            }
            s
        });
    }

    fn active_relay_sorted(&self) -> impl Iterator<Item = RelayUrl> + use<> {
        let mut ids: Vec<_> = self.active_relays.keys().cloned().collect();
        ids.sort();

        ids.into_iter()
    }
}

#[cfg(test)]
mod tests;
