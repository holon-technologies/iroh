//! The server-side representation of an ongoing client relaying connection.

use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use iroh_base::EndpointId;
use n0_error::{e, stack_error};
use n0_future::{SinkExt, StreamExt};
use time::{Date, OffsetDateTime};
use tokio::sync::{
    Notify,
    mpsc::{self, error::TrySendError},
};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, trace, warn};

use iroh_runtime::{
    Clock, ClockError, ClockSleep, ClockTimeout, DecisionError, OwnedTaskHandle, SpawnError,
    TaskKind, TaskOutcome, TimeoutError, WallClock,
};

use crate::{
    PingTracker,
    defaults::timeouts::SERVER_WRITE_TIMEOUT,
    http::ProtocolVersion,
    protos::{
        relay::{
            ClientToRelayMsg, Datagrams, PER_CLIENT_SEND_QUEUE_DEPTH, RelayToClientMsg, Status,
        },
        streams::BytesStreamSink,
    },
    server::{
        ConnectionId, OnDisconnectGuard,
        admission::SessionLease,
        clients::Clients,
        metrics::Metrics,
        streams::{RecvError as RelayRecvError, RelayedStream, SendError as RelaySendError},
    },
};

/// A request to write a dataframe to a Client
#[derive(Debug, Clone)]
pub(super) struct Packet {
    /// The sender of the packet
    src: EndpointId,
    /// The data packet bytes.
    data: Datagrams,
}

/// Configuration for a client connection.
///
/// Generic over the stream type to support different WebSocket implementations.
#[derive(Debug)]
#[non_exhaustive]
pub struct Config<S> {
    /// Reports the disconnect once the connection ends.
    ///
    /// Also the owner of this connection's [`EndpointId`] and [`ConnectionId`].
    pub guard: OnDisconnectGuard,
    /// The relayed stream connection
    pub stream: RelayedStream<S>,
    /// Write timeout for the client connection
    pub write_timeout: Duration,
    /// Channel capacity for internal message queues
    pub channel_capacity: usize,
    /// Protocol version negotiated for this client
    pub protocol_version: ProtocolVersion,
}

impl<S> Config<S> {
    /// Creates a new config with sensible default values for `write_timeout` and `channel_capacity`.
    ///
    /// The endpoint and connection ids are taken from `guard`.
    pub fn new(
        guard: OnDisconnectGuard,
        stream: RelayedStream<S>,
        protocol_version: ProtocolVersion,
    ) -> Self {
        Self {
            guard,
            stream,
            protocol_version,
            write_timeout: SERVER_WRITE_TIMEOUT,
            channel_capacity: PER_CLIENT_SEND_QUEUE_DEPTH,
        }
    }
}

/// The [`Server`] side representation of a [`Client`]'s connection.
///
/// [`Server`]: crate::server::Server
/// [`Client`]: crate::client::Client
#[derive(Debug)]
pub(super) struct Client {
    /// Identity of the connected peer.
    endpoint_id: EndpointId,
    /// Connection identifier.
    connection_id: ConnectionId,
    /// Used to close the connection loop.
    done: CancellationToken,
    /// Actor handle.
    handle: OwnedTaskHandle,
    /// Channel to send packets intended for the client.
    packet_queue: mpsc::Sender<Packet>,
    /// Channel to send non-packet messages to the client.
    message_queue: mpsc::Sender<RelayToClientMsg>,
    /// Relay protocol version negotiated for this client.
    protocol_version: ProtocolVersion,
    /// Owns one global registered-session capacity slot.
    _session_lease: SessionLease,
    /// Prevents the actor from running before this client is present in the registry.
    start_gate: Arc<StartGate>,
}

#[derive(Debug, Default)]
struct StartGate {
    started: AtomicBool,
    notify: Notify,
}

impl Client {
    /// Creates a client from a connection & starts a read and write loop to handle io to and from
    /// the client
    ///
    /// The `guard` is moved into the connection actor and reports the disconnect to access
    /// control once the connection ends.
    ///
    /// Call [`Client::shutdown`] to close the read and write loops before dropping the [`Client`]
    pub(super) fn new<S>(
        config: Config<S>,
        clients: &Clients,
        metrics: Arc<Metrics>,
        session_lease: SessionLease,
    ) -> Result<Client, SpawnError>
    where
        S: BytesStreamSink + Send + 'static,
    {
        let Config {
            guard,
            stream,
            write_timeout,
            channel_capacity,
            protocol_version,
        } = config;
        let endpoint_id = guard.endpoint_id;
        let connection_id = guard.connection_id;

        let (packet_send_queue_s, packet_send_queue_r) = mpsc::channel(channel_capacity);
        let (message_send_queue_s, message_send_queue_r) = mpsc::channel(channel_capacity);
        let done = CancellationToken::new();
        let start_gate = Arc::new(StartGate::default());

        let runtime = clients.runtime().clone();
        let actor = Actor {
            stream,
            timeout: write_timeout,
            packet_send_queue: packet_send_queue_r,
            message_send_queue: message_send_queue_r,
            guard: Some(guard),
            endpoint_id,
            registered: false,
            clients: clients.clone(),
            client_counter: ClientCounter::new(runtime.wall_clock()),
            ping_tracker: PingTracker::default(),
            metrics,
            clock: runtime.clock(),
        };

        // start io loop
        let io_done = done.clone();
        let actor_start_gate = start_gate.clone();
        let handle = clients.tasks().spawn_owned(
            TaskKind::Relay,
            "relay-server-client",
            Box::pin(
                async move {
                    actor_start_gate.notify.notified().await;
                    if actor_start_gate.started.load(Ordering::Acquire) {
                        actor.run(io_done).await;
                    }
                }
                .instrument(tracing::info_span!(
                    "client-connection-actor",
                    remote_endpoint = %endpoint_id.fmt_short(),
                    connection_id = %connection_id
                )),
            ),
        )?;

        Ok(Client {
            endpoint_id,
            connection_id,
            handle,
            done,
            packet_queue: packet_send_queue_s,
            message_queue: message_send_queue_s,
            protocol_version,
            _session_lease: session_lease,
            start_gate,
        })
    }

    /// Allows the actor to run after the client has been inserted into the registry.
    pub(super) fn start(&self) {
        self.start_gate.started.store(true, Ordering::Release);
        self.start_gate.notify.notify_one();
    }

    pub(super) fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Shutdown the reader and writer loops and closes the connection.
    ///
    /// Any shutdown errors will be logged as warnings.
    pub(super) async fn shutdown(self) {
        self.start_shutdown();
        let endpoint_id = self.endpoint_id;
        match self.handle.join().await {
            Ok(TaskOutcome::Completed | TaskOutcome::Cancelled) => {}
            Ok(TaskOutcome::Panicked) => warn!(
                remote_endpoint = %endpoint_id.fmt_short(),
                "relay client actor panicked while closing",
            ),
            Err(error) => warn!(
                remote_endpoint = %endpoint_id.fmt_short(),
                "error closing relay client actor: {error}",
            ),
        }
    }

    /// Starts the process of shutdown.
    pub(super) fn start_shutdown(&self) {
        self.done.cancel();
    }

    pub(super) fn try_send_packet(
        &self,
        src: EndpointId,
        data: Datagrams,
    ) -> Result<(), TrySendError<Packet>> {
        self.packet_queue.try_send(Packet { src, data })
    }

    pub(super) fn try_send_peer_gone(
        &self,
        key: EndpointId,
    ) -> Result<(), TrySendError<RelayToClientMsg>> {
        self.message_queue
            .try_send(RelayToClientMsg::EndpointGone(key))
    }

    pub(super) fn try_send_health(
        &self,
        status: Status,
    ) -> Result<(), TrySendError<RelayToClientMsg>> {
        let message = match self.protocol_version {
            ProtocolVersion::V2 => RelayToClientMsg::Status(status),
            ProtocolVersion::V1 => RelayToClientMsg::Health {
                problem: status.to_string(),
            },
        };
        self.message_queue.try_send(message)
    }
}

/// Error when handling an incoming frame from a client.
#[stack_error(derive, add_meta, from_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum HandleFrameError {
    #[error(transparent)]
    ForwardPacket { source: ForwardPacketError },
    #[error("Stream terminated")]
    StreamTerminated {},
    #[error(transparent)]
    Recv { source: RelayRecvError },
    #[error(transparent)]
    Send { source: WriteFrameError },
}

/// Error when writing a frame to a client.
#[stack_error(derive, add_meta, from_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum WriteFrameError {
    #[error(transparent)]
    Stream { source: RelaySendError },
    #[error(transparent)]
    Timeout {
        #[error(std_err)]
        source: TimeoutError,
    },
}

/// Run error
#[stack_error(derive, add_meta)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum RunError {
    #[error(transparent)]
    ForwardPacket {
        #[error(from)]
        source: ForwardPacketError,
    },
    #[error("Flush")]
    Flush {},
    #[error(transparent)]
    HandleFrame {
        #[error(from)]
        source: HandleFrameError,
    },
    #[error("Failed to send packet")]
    PacketSend { source: WriteFrameError },
    #[error("Handle was dropped")]
    HandleDropped {},
    #[error("Writing a frame failed")]
    WriteFrame { source: WriteFrameError },
    #[error("Tick flush")]
    TickFlush {},
    #[error("Relay server timer failed")]
    Timer {
        #[error(std_err, from)]
        source: ClockError,
    },
    #[error("Relay server decision failed")]
    Decision {
        #[error(std_err, from)]
        source: DecisionError,
    },
}

/// Manages all the reads and writes to this client. It periodically sends a `KEEP_ALIVE`
/// message to the client to keep the connection alive.
///
/// Call `run` to manage the input and output to and from the connection and the server.
/// Once it hits its first write error or error receiving off a channel,
/// it errors on return.
/// If writes do not complete in the given `timeout`, it will also error.
///
/// On the "write" side, the [`Actor`] can send the client:
///  - a KEEP_ALIVE frame
///  - a PEER_GONE frame to inform the client that a peer they have previously sent messages to
///    is gone from the network
///  - packets from other peers
///
/// On the "read" side, it can:
///     - receive a ping and write a pong back
///     to speak to the endpoint ID associated with that client.
#[derive(Debug)]
struct Actor<S> {
    /// IO Stream to talk to the client
    stream: RelayedStream<S>,
    /// Maximum time we wait to complete a write to the client
    timeout: Duration,
    /// Receiver for packets to be sent to the client.
    packet_send_queue: mpsc::Receiver<Packet>,
    /// Receiver for non-packet messages to be sent to the client.
    message_send_queue: mpsc::Receiver<RelayToClientMsg>,
    /// Reports the disconnect to access control when dropped.
    ///
    /// Also the owner of this connection's [`EndpointId`] and [`ConnectionId`].
    guard: Option<OnDisconnectGuard>,
    endpoint_id: EndpointId,
    registered: bool,
    /// Reference to the other connected clients.
    clients: Clients,
    /// Statistics about the connected clients
    client_counter: ClientCounter,
    ping_tracker: PingTracker,
    metrics: Arc<Metrics>,
    clock: Arc<dyn Clock>,
}

impl<S> Actor<S>
where
    S: BytesStreamSink,
{
    async fn run(mut self, done: CancellationToken) {
        // Note the accept and disconnects metrics must be in a pair.  Technically the
        // connection is accepted long before this in the HTTP server, but it is clearer to
        // handle the metric here.
        self.metrics.accepts.inc();
        self.registered = true;
        if self.client_counter.update(self.endpoint_id) {
            self.metrics.unique_client_keys.inc();
        }
        match self.run_inner(done).await {
            Err(e) => {
                warn!("actor errored {e:#}, exiting");
            }
            Ok(()) => {
                debug!("actor finished, exiting");
            }
        }
    }

    async fn run_inner(&mut self, done: CancellationToken) -> Result<(), RunError> {
        // Preserve the server's jittered keepalive policy, but source it from the run-owned
        // decision stream and clock.
        let base_ping_delay = self.clients.next_ping_delay()?;
        let mut ping_sleep = ClockSleep::after(self.clock.clone(), base_ping_delay)?;

        loop {
            let ping_timeout = wait_for_deadline(self.clock.clone(), self.ping_tracker.deadline());
            tokio::pin!(ping_timeout);
            tokio::select! {
                biased;

                _ = done.cancelled() => {
                    trace!("actor loop cancelled, exiting");
                    // final flush
                    self.stream.flush().await.map_err(|_| e!(RunError::Flush))?;
                    break;
                }
                maybe_frame = self.stream.next() => {
                    self
                        .handle_frame(maybe_frame)
                        .await?;
                    // reset the ping interval, we just received a message
                    ping_sleep.reset(deadline_after(&*self.clock, base_ping_delay)?)?;
                }
                // Second priority, sending regular packets
                packet = self.packet_send_queue.recv() => {
                    let packet = packet.ok_or_else(|| e!(RunError::HandleDropped))?;
                    self.send_packet(packet)
                        .await
                        .map_err(|err| e!(RunError::PacketSend, err))?;
                }
                // Last priority, sending other message
                message = self.message_send_queue.recv() => {
                    let message = message.ok_or_else(|| e!(RunError::HandleDropped))?;
                    trace!("send {message:?}");
                    self.write_frame(message)
                        .await
                        .map_err(|err| e!(RunError::WriteFrame, err))?;
                }
                result = &mut ping_timeout => {
                    result?;
                    trace!("pong timed out");
                    self.ping_tracker.timeout_elapsed();
                    break;
                }
                result = &mut ping_sleep => {
                    result?;
                    trace!("keep alive ping");
                    // new interval
                    let next = self.clients.next_ping_delay()?;
                    ping_sleep.reset(deadline_after(&*self.clock, next)?)?;
                    let data = self.clients.next_ping_data()?;
                    let timeout = self.ping_tracker.ping_timeout();
                    self.ping_tracker.new_ping_with_data_at(timeout, data, self.clock.now());
                    self.write_frame(RelayToClientMsg::Ping(data))
                        .await
                        .map_err(|err| e!(RunError::WriteFrame, err))?;
                }
            }

            self.stream
                .flush()
                .await
                .map_err(|_| e!(RunError::TickFlush))?;
        }
        Ok(())
    }

    /// Writes the given frame to the connection.
    ///
    /// Errors if the send does not happen within the `timeout` duration
    async fn write_frame(&mut self, frame: RelayToClientMsg) -> Result<(), WriteFrameError> {
        let timeout =
            ClockTimeout::after(self.clock.clone(), self.timeout, self.stream.send(frame))
                .map_err(TimeoutError::Clock)
                .map_err(|error| e!(WriteFrameError::Timeout, error))?;
        timeout
            .await
            .map_err(|error| e!(WriteFrameError::Timeout, error))??;
        Ok(())
    }

    /// Writes contents to the client in a `RECV_PACKET` frame.
    ///
    /// Errors if the send does not happen within the `timeout` duration
    /// Does not flush.
    async fn send_raw(&mut self, packet: Packet) -> Result<(), WriteFrameError> {
        let remote_endpoint_id = packet.src;
        let datagrams = packet.data;

        if let Ok(len) = datagrams.contents.len().try_into() {
            self.metrics.bytes_sent.inc_by(len);
        }
        self.write_frame(RelayToClientMsg::Datagrams {
            remote_endpoint_id,
            datagrams,
        })
        .await
    }

    async fn send_packet(&mut self, packet: Packet) -> Result<(), WriteFrameError> {
        trace!("send packet");
        match self.send_raw(packet).await {
            Ok(()) => {
                self.metrics.send_packets_sent.inc();
                Ok(())
            }
            Err(err) => {
                self.metrics.send_packets_dropped.inc();
                Err(err)
            }
        }
    }

    /// Handles frame read results.
    async fn handle_frame(
        &mut self,
        maybe_frame: Option<Result<ClientToRelayMsg, RelayRecvError>>,
    ) -> Result<(), HandleFrameError> {
        trace!(?maybe_frame, "handle incoming frame");
        let frame = match maybe_frame {
            Some(frame) => frame?,
            None => return Err(e!(HandleFrameError::StreamTerminated)),
        };

        match frame {
            ClientToRelayMsg::Datagrams {
                dst_endpoint_id: dst_key,
                datagrams,
            } => {
                let packet_len = datagrams.contents.len();
                if let Err(err @ ForwardPacketError { .. }) =
                    self.handle_frame_send_packet(dst_key, datagrams)
                {
                    warn!("failed to handle send packet frame: {err:#}");
                }
                self.metrics.bytes_recv.inc_by(packet_len as u64);
            }
            ClientToRelayMsg::Ping(data) => {
                self.metrics.got_ping.inc();
                // TODO: add rate limiter
                self.write_frame(RelayToClientMsg::Pong(data)).await?;
                self.metrics.sent_pong.inc();
            }
            ClientToRelayMsg::Pong(data) => {
                self.ping_tracker.pong_received_at(data, self.clock.now());
            }
        }
        Ok(())
    }

    fn handle_frame_send_packet(
        &self,
        dst: EndpointId,
        data: Datagrams,
    ) -> Result<(), ForwardPacketError> {
        self.metrics.send_packets_recv.inc();
        self.clients
            .send_packet(dst, data, self.endpoint_id, &self.metrics)?;

        Ok(())
    }
}

impl<S> Drop for Actor<S> {
    fn drop(&mut self) {
        if !self.registered {
            return;
        }
        if let Some(guard) = self.guard.take() {
            self.clients.unregister(guard, &self.metrics);
            self.metrics.disconnects.inc();
        }
    }
}

#[derive(Debug)]
pub(crate) enum SendError {
    Full,
    Closed,
}

/// Error returned when forwarding a packet to a client fails.
///
/// This error occurs when the relay server cannot deliver a packet to its intended
/// recipient, typically due to the client's send queue being full or the client
/// disconnecting.
#[stack_error(derive, add_meta)]
#[error("failed to forward packet: {reason:?}")]
pub struct ForwardPacketError {
    reason: SendError,
}

/// Tracks how many unique endpoints have been seen during the last day.
#[derive(Debug)]
struct ClientCounter {
    clients: HashSet<EndpointId>,
    last_clear_date: Date,
    wall_clock: Arc<dyn WallClock>,
}

impl ClientCounter {
    fn new(wall_clock: Arc<dyn WallClock>) -> Self {
        let last_clear_date = OffsetDateTime::from(wall_clock.now_system()).date();
        Self {
            clients: HashSet::new(),
            last_clear_date,
            wall_clock,
        }
    }

    fn check_and_clear(&mut self) {
        let today = OffsetDateTime::from(self.wall_clock.now_system()).date();
        if today != self.last_clear_date {
            self.clients.clear();
            self.last_clear_date = today;
        }
    }

    /// Marks this endpoint as seen, returns whether it is new today or not.
    fn update(&mut self, client: EndpointId) -> bool {
        self.check_and_clear();
        self.clients.insert(client)
    }
}

fn deadline_after(clock: &dyn Clock, duration: Duration) -> Result<std::time::Instant, ClockError> {
    clock
        .now()
        .checked_add(duration)
        .ok_or(ClockError::TimelineOverflow)
}

async fn wait_for_deadline(
    clock: Arc<dyn Clock>,
    deadline: Option<std::time::Instant>,
) -> Result<(), ClockError> {
    match deadline {
        Some(deadline) => ClockSleep::new(clock, deadline)?.await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;
    use n0_error::{Result, StdResultExt, bail_any};
    use n0_future::Stream;
    use n0_tracing_test::traced_test;
    use rand::{RngExt, SeedableRng};
    use tracing::info;

    use super::*;
    use crate::{
        client::conn::Conn,
        http::ProtocolVersion,
        protos::{common::FrameType, relay::Status, streams::WsBytesFramed},
        server::streams::{MaybeTlsStream, RateLimited, ServerRelayedStream},
    };

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
                    bail_any!(
                        "Unexpected frame, got {:?}, but expected {:?}",
                        frame.typ(),
                        frame_type
                    );
                }
                Ok(frame)
            }
            Some(Err(err)) => Err(err).anyerr(),
            None => bail_any!("Unexpected EOF, expected frame {frame_type:?}"),
        }
    }

    #[tokio::test]
    #[traced_test]
    async fn test_client_actor_basic() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        let (send_queue_s, send_queue_r) = mpsc::channel(10);
        let (message_s, message_r) = mpsc::channel(10);

        let endpoint_id = SecretKey::from_bytes(&rng.random()).public();
        let (io, io_rw) = tokio::io::duplex(1024);
        let mut io_rw = Conn::test(io_rw, Default::default());
        let stream = RelayedStream::test(io);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        let actor = Actor {
            stream,
            timeout: Duration::from_secs(1),
            packet_send_queue: send_queue_r,
            message_send_queue: message_r,
            guard: Some(OnDisconnectGuard::empty(endpoint_id)),
            endpoint_id,
            registered: false,
            clients: clients.clone(),
            client_counter: ClientCounter::new(clients.runtime().wall_clock()),
            ping_tracker: PingTracker::default(),
            metrics,
            clock: clients.runtime().clock(),
        };

        let done = CancellationToken::new();
        let io_done = done.clone();
        let handle = tokio::task::spawn(async move { actor.run(io_done).await });

        // Write tests
        println!("-- write");
        let data = b"hello world!";

        // send packet
        println!("  send packet");
        let packet = Packet {
            src: endpoint_id,
            data: Datagrams::from(&data[..]),
        };
        send_queue_s
            .send(packet.clone())
            .await
            .std_context("send")?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut io_rw)
            .await
            .anyerr()?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: endpoint_id,
                datagrams: data.to_vec().into()
            }
        );

        // send peer_gone
        println!("send peer gone");
        message_s
            .send(RelayToClientMsg::EndpointGone(endpoint_id))
            .await
            .std_context("send")?;
        let frame = recv_frame(FrameType::EndpointGone, &mut io_rw)
            .await
            .anyerr()?;
        assert_eq!(frame, RelayToClientMsg::EndpointGone(endpoint_id));

        // Read tests
        println!("--read");

        // send ping, expect pong
        let data = b"pingpong";
        io_rw.send(ClientToRelayMsg::Ping(*data)).await?;

        // recv pong
        println!(" recv pong");
        let frame = recv_frame(FrameType::Pong, &mut io_rw).await?;
        assert_eq!(frame, RelayToClientMsg::Pong(*data));

        let target = SecretKey::from_bytes(&rng.random()).public();

        // send packet
        println!("  send packet");
        let data = b"hello world!";
        io_rw
            .send(ClientToRelayMsg::Datagrams {
                dst_endpoint_id: target,
                datagrams: Datagrams::from(data),
            })
            .await
            .std_context("send")?;

        done.cancel();
        handle.await.std_context("join")?;
        Ok(())
    }

    fn test_client_builder(
        key: EndpointId,
        protocol_version: ProtocolVersion,
    ) -> (Config<WsBytesFramed<RateLimited<MaybeTlsStream>>>, Conn) {
        let (server, client) = tokio::io::duplex(1024);
        let guard = OnDisconnectGuard::empty(key);
        let mut config = Config::new(guard, ServerRelayedStream::test(server), protocol_version);
        config.write_timeout = Duration::from_secs(1);
        config.channel_capacity = 10;
        (config, Conn::test(client, protocol_version))
    }

    #[tokio::test]
    #[traced_test]
    async fn test_client_v1_protocol() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();

        let (builder_a, mut a_rw) = test_client_builder(a_key, ProtocolVersion::V1);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        clients.register(builder_a, metrics.clone()).anyerr()?;

        // Verify basic packet delivery works with V1.
        let data = b"hello world v1!";
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        clients.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_client_v2_protocol() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();

        let (builder_a, mut a_rw) = test_client_builder(a_key, ProtocolVersion::V2);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        clients.register(builder_a, metrics.clone()).anyerr()?;

        // Verify basic packet delivery works with V2.
        let data = b"hello world v2!";
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        clients.shutdown().await;
        Ok(())
    }

    /// Test for versioned protocol: v1 client should receive V1Health frame.
    #[tokio::test]
    #[traced_test]
    async fn test_duplicate_endpoint_v1_receives_v1health() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42u64);
        let key = SecretKey::from_bytes(&rng.random()).public();

        let (builder_first, mut first_rw) = test_client_builder(key, ProtocolVersion::V1);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        clients.register(builder_first, metrics.clone()).anyerr()?;

        // Register a second client with the same endpoint ID.
        // The first client should receive a V1Health message.
        let (builder_second, _second_rw) = test_client_builder(key, ProtocolVersion::V1);
        clients.register(builder_second, metrics.clone()).anyerr()?;

        let frame = recv_frame(FrameType::Health, &mut first_rw).await?;
        assert!(
            matches!(frame, RelayToClientMsg::Health { .. }),
            "expected V1Health frame for V1 client, got {frame:?}"
        );

        clients.shutdown().await;
        Ok(())
    }

    /// Test for versioned protocol: v2 client should receive V2Health frame.
    #[tokio::test]
    #[traced_test]
    async fn test_duplicate_endpoint_v2_receives_health() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42u64);
        let key = SecretKey::from_bytes(&rng.random()).public();

        let (builder_first, mut first_rw) = test_client_builder(key, ProtocolVersion::V2);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        clients.register(builder_first, metrics.clone()).anyerr()?;

        // Register a second client with the same endpoint ID.
        // The first client should receive a Health message (V2 frame).
        let (builder_second, _second_rw) = test_client_builder(key, ProtocolVersion::V2);
        clients.register(builder_second, metrics.clone()).anyerr()?;

        let frame = recv_frame(FrameType::Status, &mut first_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Status(Status::SameEndpointIdConnected)
        );

        clients.shutdown().await;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    #[traced_test]
    async fn test_rate_limit() -> Result {
        const LIMIT: u32 = 50;
        const MAX_FRAMES: u32 = 100;

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        // Build the rate limited stream.
        let (io_read, io_write) = tokio::io::duplex((LIMIT * MAX_FRAMES) as _);
        let mut frame_writer = Conn::test(io_write, Default::default());
        // Rate limiter allowing LIMIT bytes/s
        let mut stream = RelayedStream::test_limited(io_read, LIMIT / 10, LIMIT)?;

        // Prepare a frame to send, assert its size.
        let data = Datagrams::from(b"hello world!!!!!");
        let target = SecretKey::from_bytes(&rng.random()).public();
        let frame = ClientToRelayMsg::Datagrams {
            dst_endpoint_id: target,
            datagrams: data.clone(),
        };
        let frame_len = frame.to_bytes().len();
        assert_eq!(frame_len, LIMIT as usize);

        // Send a frame, it should arrive.
        info!("-- send packet");
        frame_writer.send(frame.clone()).await.std_context("send")?;
        frame_writer.flush().await.std_context("flush")?;
        let recv_frame = tokio::time::timeout(Duration::from_millis(500), stream.next())
            .await
            .expect("timeout")
            .expect("option")
            .expect("ok");
        assert_eq!(recv_frame, frame);

        // Next frame does not arrive.
        info!("-- send packet");
        frame_writer.send(frame.clone()).await.std_context("send")?;
        frame_writer.flush().await.std_context("flush")?;
        let res = tokio::time::timeout(Duration::from_millis(100), stream.next()).await;
        assert!(res.is_err(), "expecting a timeout");
        info!("-- timeout happened");

        // Wait long enough.
        info!("-- sleep");
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Frame arrives.
        let recv_frame = tokio::time::timeout(Duration::from_millis(500), stream.next())
            .await
            .expect("timeout")
            .expect("option")
            .expect("ok");
        assert_eq!(recv_frame, frame);

        Ok(())
    }
}
