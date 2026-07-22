//! The "Server" side of the client. Uses the `ClientConnManager`.
// Based on tailscale/derp/derp_server.go

use std::{
    collections::HashSet,
    fmt,
    sync::atomic::{AtomicU64, Ordering},
    sync::{Arc, Mutex},
};

use dashmap::DashMap;
use iroh_base::EndpointId;
use iroh_runtime::{DecisionError, DecisionStream, RuntimeContext, TaskGroup};
use n0_future::IterExt;
use rand::Rng;
use tokio::sync::mpsc::error::TrySendError;
use tracing::{debug, trace};

use super::{
    ConnectionId, OnDisconnectGuard,
    client::{Client, Config, ForwardPacketError},
};
use crate::{
    protos::{
        relay::{Datagrams, Status},
        streams::BytesStreamSink,
    },
    server::{client::SendError, metrics::Metrics},
};

/// Registry of connected relay clients.
///
/// This type manages the collection of active client connections and
/// handles routing messages between them.
#[derive(Debug, Clone)]
pub struct Clients(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    /// The list of all currently connected clients.
    clients: DashMap<EndpointId, ClientState>,
    /// Map of which client has sent where
    sent_to: DashMap<EndpointId, HashSet<EndpointId>>,
    runtime: Arc<RuntimeContext>,
    tasks: Arc<dyn TaskGroup>,
    decisions: Mutex<Box<dyn DecisionStream>>,
    challenge_entropy: ChallengeEntropy,
    #[cfg(feature = "test-utils")]
    drop_every_nth_packet: AtomicU64,
    #[cfg(feature = "test-utils")]
    packet_ordinal: AtomicU64,
}

enum ChallengeEntropy {
    Production,
    Deterministic { key: [u8; 32], next: AtomicU64 },
}

impl fmt::Debug for ChallengeEntropy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Production => formatter.write_str("Production"),
            Self::Deterministic { next, .. } => formatter
                .debug_struct("Deterministic")
                .field("key", &"[redacted]")
                .field("next", &next.load(Ordering::Relaxed))
                .finish(),
        }
    }
}

impl Default for Clients {
    fn default() -> Self {
        let runtime = Arc::new(RuntimeContext::production(Arc::new(
            iroh_runtime::NoopTraceSink,
        )));
        match Self::build(
            runtime,
            "relay-server/production",
            ChallengeEntropy::Production,
        ) {
            Ok(clients) => clients,
            Err(_) => unreachable!("the built-in relay decision path is valid"),
        }
    }
}

#[derive(Debug)]
struct ClientState {
    active: Client,
    inactive: Vec<Client>,
}

impl ClientState {
    async fn shutdown_all(mut self) {
        [self.active]
            .into_iter()
            .chain(self.inactive.drain(..))
            .map(Client::shutdown)
            .join_all()
            .await;
    }
}

impl Clients {
    pub(super) fn with_runtime(
        runtime: Arc<RuntimeContext>,
        decision_path: &str,
    ) -> Result<Self, DecisionError> {
        let mut hasher = blake3::Hasher::new_derive_key(
            "iroh relay deterministic simulation authentication challenges v1",
        );
        hasher.update(runtime.root_seed().as_bytes());
        hasher.update(&(decision_path.len() as u32).to_le_bytes());
        hasher.update(decision_path.as_bytes());
        let challenge_entropy = ChallengeEntropy::Deterministic {
            key: *hasher.finalize().as_bytes(),
            next: AtomicU64::new(0),
        };
        Self::build(runtime, decision_path, challenge_entropy)
    }

    fn build(
        runtime: Arc<RuntimeContext>,
        decision_path: &str,
        challenge_entropy: ChallengeEntropy,
    ) -> Result<Self, DecisionError> {
        let decisions = runtime.decisions().stream(decision_path)?;
        let tasks = runtime.executor().new_group(None);
        Ok(Self(Arc::new(Inner {
            clients: DashMap::new(),
            sent_to: DashMap::new(),
            runtime,
            tasks,
            decisions: Mutex::new(decisions),
            challenge_entropy,
            #[cfg(feature = "test-utils")]
            drop_every_nth_packet: AtomicU64::new(0),
            #[cfg(feature = "test-utils")]
            packet_ordinal: AtomicU64::new(0),
        })))
    }

    pub(super) fn next_auth_challenge(&self) -> [u8; 16] {
        let mut challenge = [0; 16];
        match &self.0.challenge_entropy {
            ChallengeEntropy::Production => rand::rng().fill_bytes(&mut challenge),
            ChallengeEntropy::Deterministic { key, next } => {
                let counter = next
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                        value.checked_add(1)
                    })
                    .expect("relay authentication challenge counter exhausted");
                let digest = blake3::keyed_hash(key, &counter.to_le_bytes());
                challenge.copy_from_slice(&digest.as_bytes()[..16]);
            }
        }
        challenge
    }

    pub(super) fn runtime(&self) -> &Arc<RuntimeContext> {
        &self.0.runtime
    }

    pub(super) fn tasks(&self) -> &Arc<dyn TaskGroup> {
        &self.0.tasks
    }

    pub(super) fn next_ping_delay(&self) -> Result<std::time::Duration, DecisionError> {
        let seconds = self
            .0
            .decisions
            .lock()
            .expect("relay decision stream lock poisoned")
            .range_u64(1..6)?;
        Ok(crate::protos::relay::PING_INTERVAL + std::time::Duration::from_secs(seconds))
    }

    pub(super) fn next_ping_data(&self) -> Result<[u8; 8], DecisionError> {
        let mut data = [0; 8];
        self.0
            .decisions
            .lock()
            .expect("relay decision stream lock poisoned")
            .fill_bytes(&mut data)?;
        Ok(data)
    }

    /// Installs deterministic routed-packet loss for repository simulation tests.
    #[doc(hidden)]
    #[cfg(feature = "test-utils")]
    pub fn set_test_drop_every_nth_packet(&self, every: Option<u64>) {
        self.0
            .drop_every_nth_packet
            .store(every.unwrap_or(0), Ordering::Relaxed);
        self.0.packet_ordinal.store(0, Ordering::Relaxed);
    }

    /// Returns the number of currently registered client sessions.
    ///
    /// Duplicate endpoint identities count once for each active or inactive connection.
    #[doc(hidden)]
    pub fn connection_count(&self) -> usize {
        self.0
            .clients
            .iter()
            .map(|entry| 1usize.saturating_add(entry.inactive.len()))
            .sum()
    }

    /// Shuts down all connected clients.
    ///
    /// This method gracefully disconnects all active client connections managed by
    /// this registry. It will wait for all clients to complete their shutdown before
    /// returning.
    pub async fn shutdown(&self) {
        let keys: Vec<_> = self.0.clients.iter().map(|x| *x.key()).collect();
        trace!("shutting down {} clients", keys.len());
        let clients = keys.into_iter().filter_map(|k| self.0.clients.remove(&k));
        n0_future::join_all(clients.map(|(_, state)| state.shutdown_all())).await;
    }

    /// Builds the client handler and starts the read & write loops for the connection.
    ///
    /// Once the client disconnects, the [`OnDisconnectGuard`] set in `config` will be dropped,
    /// allowing callers to be notified of the disconnect.
    pub fn register<S>(
        &self,
        client_config: Config<S>,
        metrics: Arc<Metrics>,
    ) -> Result<(), iroh_runtime::SpawnError>
    where
        S: BytesStreamSink + Send + 'static,
    {
        let endpoint_id = client_config.guard.endpoint_id;
        trace!(remote_endpoint = %endpoint_id.fmt_short(), "registering client");

        let client = Client::new(client_config, self, metrics.clone())?;
        match self.0.clients.entry(endpoint_id) {
            dashmap::Entry::Occupied(mut entry) => {
                let state = entry.get_mut();
                let old_client = std::mem::replace(&mut state.active, client);
                debug!(
                    remote_endpoint = %endpoint_id.fmt_short(),
                    "multiple connections found, deactivating old connection",
                );
                old_client
                    .try_send_health(Status::SameEndpointIdConnected)
                    .ok();
                state.inactive.push(old_client);
                metrics.clients_inactive_added.inc();
            }
            dashmap::Entry::Vacant(entry) => {
                entry.insert(ClientState {
                    active: client,
                    inactive: Vec::new(),
                });
            }
        }
        Ok(())
    }

    /// Removes the client from the map of clients, & sends a notification
    /// to each client that peers has sent data to, to let them know that
    /// peer is gone from the network.
    ///
    /// Must be passed a matching connection_id.
    pub(super) fn unregister(&self, guard: OnDisconnectGuard, metrics: &Metrics) {
        let endpoint_id = guard.endpoint_id;
        let connection_id = guard.connection_id;
        trace!(
            endpoint_id = %endpoint_id.fmt_short(),
            %connection_id, "unregistering client"
        );

        let mut notify_peers = None;

        self.0.clients.remove_if_mut(&endpoint_id, |_id, state| {
            if state.active.connection_id() == connection_id {
                // The unregistering client is the currently active client
                if let Some(last_inactive_client) = state.inactive.pop() {
                    metrics.clients_inactive_removed.inc();
                    // There is an inactive client, promote to active again.
                    state.active = last_inactive_client;
                    // Inform the old client that it is healthy again.
                    state.active.try_send_health(Status::Healthy).ok();
                    // Don't remove the entry from client map.
                    false
                } else {
                    // No inactive clients: collect sent_to set for peer-gone notifications.
                    notify_peers = self.0.sent_to.remove(&endpoint_id).map(|(_, peers)| peers);
                    // Remove entry from the client map.
                    true
                }
            } else {
                // The unregistering client is already inactive. Remove from the list of inactive clients.
                state
                    .inactive
                    .retain(|client| client.connection_id() != connection_id);
                metrics.clients_inactive_removed.inc();
                // Active client is unmodified: keep entry in map.
                false
            }
        });

        // Inform peers that this endpoint is gone.
        // Done outside the remove_if_mut closure to avoid DashMap deadlocks.
        if let Some(peers) = notify_peers {
            for peer_id in peers {
                if let Some(peer) = self.0.clients.get(&peer_id) {
                    match peer.active.try_send_peer_gone(endpoint_id) {
                        Ok(_) => {}
                        Err(TrySendError::Full(_)) => {
                            debug!(
                                dst = %peer_id.fmt_short(),
                                "client too busy to receive peer gone notification, dropping"
                            );
                        }
                        Err(TrySendError::Closed(_)) => {
                            debug!(
                                dst = %peer_id.fmt_short(),
                                "can no longer write to client, dropping peer gone notification"
                            );
                        }
                    }
                }
            }
        }
    }

    /// Disconnects connections registered for `endpoint_id`.
    ///
    /// With `Some(connection_id)`, disconnects only that connection (active or
    /// an inactive duplicate). With `None`, disconnects every connection for the
    /// endpoint. Returns `true` if a matching connection was found, or `false`
    /// otherwise.
    ///
    /// Shutdown happens asynchronously: each per-connection actor exits its run
    /// loop and unregisters itself after this call returns.
    pub fn disconnect(&self, endpoint_id: EndpointId, connection_id: Option<ConnectionId>) -> bool {
        let Some(state) = self.0.clients.get(&endpoint_id) else {
            return false;
        };
        let mut clients = state.inactive.iter().chain([&state.active]);
        if let Some(id) = connection_id {
            let Some(client) = clients.find(|c| c.connection_id() == id) else {
                return false;
            };
            client.start_shutdown();
        } else {
            for client in clients {
                client.start_shutdown();
            }
        }
        true
    }

    /// Attempt to send a packet to client with [`EndpointId`] `dst`.
    pub(super) fn send_packet(
        &self,
        dst: EndpointId,
        data: Datagrams,
        src: EndpointId,
        metrics: &Metrics,
    ) -> Result<(), ForwardPacketError> {
        #[cfg(feature = "test-utils")]
        {
            let every = self.0.drop_every_nth_packet.load(Ordering::Relaxed);
            let ordinal = self.0.packet_ordinal.fetch_add(1, Ordering::Relaxed) + 1;
            if every != 0 && ordinal.is_multiple_of(every) {
                debug!(%ordinal, "deterministic test impairment dropped packet");
                metrics.send_packets_dropped.inc();
                return Ok(());
            }
        }
        let Some(client) = self.0.clients.get(&dst) else {
            debug!(dst = %dst.fmt_short(), "no connected client, dropped packet");
            metrics.send_packets_dropped.inc();
            return Ok(());
        };
        match client.active.try_send_packet(src, data) {
            Ok(_) => {
                // Record sent_to relationship
                self.0.sent_to.entry(src).or_default().insert(dst);
                Ok(())
            }
            Err(TrySendError::Full(_)) => {
                debug!(
                    dst = %dst.fmt_short(),
                    "client too busy to receive packet, dropping packet"
                );
                Err(ForwardPacketError::new(SendError::Full))
            }
            Err(TrySendError::Closed(_)) => {
                debug!(
                    dst = %dst.fmt_short(),
                    "can no longer write to client, dropping message and pruning connection"
                );
                client.active.start_shutdown();
                Err(ForwardPacketError::new(SendError::Closed))
            }
        }
    }

    #[cfg(test)]
    fn active_connection_id(&self, endpoint_id: EndpointId) -> Option<ConnectionId> {
        self.0
            .clients
            .get(&endpoint_id)
            .map(|s| s.active.connection_id())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iroh_base::SecretKey;
    use iroh_runtime::{NoopTraceSink, RootSeed};
    use n0_error::{Result, StdResultExt};
    use n0_future::{Stream, StreamExt};
    use n0_tracing_test::traced_test;
    use rand::{RngExt, SeedableRng};

    use super::*;
    use crate::{
        client::conn::Conn,
        http::ProtocolVersion,
        protos::{common::FrameType, relay::RelayToClientMsg, streams::WsBytesFramed},
        server::streams::{MaybeTlsStream, RateLimited, ServerRelayedStream},
    };

    fn runtime(seed: [u8; 32]) -> Arc<RuntimeContext> {
        Arc::new(RuntimeContext::tokio(
            RootSeed::new(seed),
            Arc::new(NoopTraceSink),
        ))
    }

    #[test]
    fn simulation_challenges_are_repeatable_and_scope_separated() {
        let first = Clients::with_runtime(runtime([9; 32]), "relay-server/a/behavior").unwrap();
        let replay = Clients::with_runtime(runtime([9; 32]), "relay-server/a/behavior").unwrap();
        let other = Clients::with_runtime(runtime([9; 32]), "relay-server/b/behavior").unwrap();

        assert_eq!(first.next_auth_challenge(), replay.next_auth_challenge());
        assert_ne!(first.next_auth_challenge(), other.next_auth_challenge());
    }

    async fn recv_frame<
        E: std::error::Error + Sync + Send + 'static,
        S: Stream<Item = Result<RelayToClientMsg, E>> + Unpin,
    >(
        frame_type: FrameType,
        mut stream: S,
    ) -> Result<RelayToClientMsg> {
        match stream.next().await {
            Some(Ok(frame)) => {
                if frame_type != frame.typ() {
                    n0_error::bail_any!(
                        "Unexpected frame, got {:?}, but expected {:?}",
                        frame.typ(),
                        frame_type
                    );
                }
                Ok(frame)
            }
            Some(Err(err)) => Err(err).anyerr(),
            None => n0_error::bail_any!("Unexpected EOF, expected frame {frame_type:?}"),
        }
    }

    fn test_client_builder(
        key: EndpointId,
    ) -> (Config<WsBytesFramed<RateLimited<MaybeTlsStream>>>, Conn) {
        let (server, client) = tokio::io::duplex(1024);
        let guard = OnDisconnectGuard::empty(key);
        let protocol_version = ProtocolVersion::default();
        let mut config = Config::new(guard, ServerRelayedStream::test(server), protocol_version);
        config.write_timeout = Duration::from_secs(1);
        config.channel_capacity = 10;
        (config, Conn::test(client, protocol_version))
    }

    #[tokio::test]
    #[traced_test]
    async fn test_clients() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();

        let (builder_a, mut a_rw) = test_client_builder(a_key);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        clients.register(builder_a, metrics.clone()).anyerr()?;

        // send packet
        let data = b"hello world!";
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        {
            let client = clients.0.clients.get(&a_key).unwrap();
            // shutdown client a, this should trigger the removal from the clients list
            client.active.start_shutdown();
        }

        // need to wait a moment for the removal to be processed
        let c = clients.clone();
        tokio::time::timeout(Duration::from_secs(1), async move {
            loop {
                if !c.0.clients.contains_key(&a_key) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .std_context("timeout")?;
        clients.shutdown().await;

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_clients_same_endpoint_id() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();

        let (a1_builder, mut a1_rw) = test_client_builder(a_key);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());

        // register client a
        clients.register(a1_builder, metrics.clone()).anyerr()?;
        let a1_conn_id = clients.active_connection_id(a_key).unwrap();

        // send packet and verify it is send to a1
        let data = b"hello world!";
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a1_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        // register new client with same endpoint id
        let (a2_builder, mut a2_rw) = test_client_builder(a_key);
        clients.register(a2_builder, metrics.clone()).anyerr()?;
        let a2_conn_id = clients.active_connection_id(a_key).unwrap();
        assert!(a2_conn_id != a1_conn_id);

        // a1 is marked inactive and should receive a health frame
        let frame = recv_frame(FrameType::Status, &mut a1_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Status(Status::SameEndpointIdConnected)
        );

        // send packet and verify it is send to a2
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a2_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        // disconnect a2
        clients
            .0
            .clients
            .get(&a_key)
            .unwrap()
            .active
            .start_shutdown();

        // need to wait a moment for the removal to be processed
        tokio::time::timeout(Duration::from_secs(1), {
            let clients = clients.clone();
            async move {
                // wait until the active connection is no longer a2 (which we unregistered)
                while clients.active_connection_id(a_key) == Some(a2_conn_id) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        })
        .await
        .std_context("timeout")?;

        // a1 should be marked active again now
        assert_eq!(clients.active_connection_id(a_key), Some(a1_conn_id));

        // a1 is marked active again and should receive a health frame
        let frame = recv_frame(FrameType::Status, &mut a1_rw).await?;
        assert_eq!(frame, RelayToClientMsg::Status(Status::Healthy));

        // a1 should receive packets
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a1_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        // after shutting down the now-active client, there should no longer be an entry for that endpoint id
        clients
            .0
            .clients
            .get(&a_key)
            .unwrap()
            .active
            .start_shutdown();

        // need to wait a moment for the removal to be processed
        tokio::time::timeout(Duration::from_secs(1), {
            let clients = clients.clone();
            async move {
                // wait until the active connection is no longer a2 (which we unregistered)
                while clients.0.clients.contains_key(&a_key) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        })
        .await
        .std_context("timeout")?;

        clients.shutdown().await;

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_peer_gone_notification() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());

        // Register both clients
        let (builder_a, _a_rw) = test_client_builder(a_key);
        let (builder_b, mut b_rw) = test_client_builder(b_key);
        clients.register(builder_a, metrics.clone()).anyerr()?;
        clients.register(builder_b, metrics.clone()).anyerr()?;

        // A sends a packet to B (records sent_to[A] = {B})
        let data = b"hello b!";
        clients.send_packet(b_key, Datagrams::from(&data[..]), a_key, &metrics)?;

        // B receives the packet
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut b_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: a_key,
                datagrams: data.to_vec().into(),
            }
        );

        // Disconnect A
        {
            let client = clients.0.clients.get(&a_key).unwrap();
            client.active.start_shutdown();
        }

        // Wait for A to unregister
        tokio::time::timeout(Duration::from_secs(1), {
            let clients = clients.clone();
            async move {
                while clients.0.clients.contains_key(&a_key) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        })
        .await
        .std_context("timeout waiting for A to unregister")?;

        // B should receive EndpointGone(a_key): notifying B that A is gone
        let frame = recv_frame(FrameType::EndpointGone, &mut b_rw).await?;
        assert_eq!(frame, RelayToClientMsg::EndpointGone(a_key));

        clients.shutdown().await;
        Ok(())
    }
}
