use super::*;

/// An actor which handles the connection to a single relay server.
///
/// It is responsible for maintaining the connection to the relay server and handling all
/// communication with it.
///
/// The actor shuts down itself on inactivity: inactivity is determined when no more
/// datagrams are being queued to send.
///
/// This actor has 3 main states it can be in, each has it's dedicated run loop:
///
/// - Dialing the relay server.
///
///   This will continuously dial the server until connected, using exponential backoff if
///   it can not connect.  See [`ActiveRelayActor::run_dialing`].
///
/// - Connected to the relay server.
///
///   This state allows receiving from the relay server, though sending is idle in this
///   state.  See [`ActiveRelayActor::run_connected`].
///
/// - Sending to the relay server.
///
///   This is a sub-state of `connected` so the actor can still be receiving from the relay
///   server at this time.  However it is actively sending data to the server so can not
///   consume any further items from inboxes which will result in sending more data to the
///   server until the actor goes back to the `connected` state.
///
/// All these are driven from the top-level [`ActiveRelayActor::run`] loop.
#[derive(Debug)]
pub(super) struct ActiveRelayActor {
    // The inboxes and channels this actor communicates over.
    /// Inbox for messages which should be handled without any blocking.
    pub(super) prio_inbox: mpsc::Receiver<ActiveRelayPrioMessage>,
    /// Inbox for messages which involve sending to the relay server.
    pub(super) inbox: mpsc::Receiver<ActiveRelayMessage>,
    /// Queue for received relay datagrams.
    pub(super) relay_datagrams_recv: mpsc::Sender<RelayRecvDatagram>,
    /// Channel on which we queue packets to send to the relay.
    pub(super) relay_datagrams_send: mpsc::Receiver<RelaySendItem>,

    // Other actor state.
    /// The relay server for this actor.
    pub(super) url: RelayUrl,
    /// Builder which can repeatedly build a relay client.
    pub(super) relay_client_builder: relay::client::ClientBuilder,
    #[cfg(not(wasm_browser))]
    pub(super) relay_connector: Option<Arc<dyn crate::simulation::RelayConnector>>,
    #[cfg(not(wasm_browser))]
    pub(super) relay_connect_request: crate::simulation::RelayConnectRequest,
    /// Whether or not this is the home relay server.
    ///
    /// The home relay server needs to maintain it's connection to the relay server, even if
    /// the relay actor is otherwise idle.
    pub(super) is_home_relay: bool,
    /// When this expires the actor has been idle and should shut down.
    ///
    /// Unless it is managing the home relay connection.  Inactivity is only tracked on the
    /// last datagram sent to the relay, received datagrams will trigger QUIC ACKs which is
    /// sufficient to keep active connections open.
    #[cfg(wasm_browser)]
    pub(super) inactive_timeout: Pin<Box<time::Sleep>>,
    #[cfg(not(wasm_browser))]
    pub(super) inactive_timeout: RuntimeSleep,
    #[cfg(not(wasm_browser))]
    pub(super) runtime: Arc<Runtime>,
    #[cfg(not(wasm_browser))]
    pub(super) ping_decisions: Box<dyn DecisionStream>,
    #[cfg(not(wasm_browser))]
    pub(super) backoff_decisions: Box<dyn DecisionStream>,
    /// Token indicating the [`ActiveRelayActor`] should stop.
    pub(super) stop_token: CancellationToken,
    pub(super) metrics: Arc<SocketMetrics>,
    pub(super) my_relay: HomeRelayWatch,
}

#[derive(Debug)]
pub(super) enum ActiveRelayMessage {
    /// Triggers a connection check to the relay server.
    ///
    /// Sometimes it is known the local network interfaces have changed in which case it
    /// might be prudent to check if the relay connection is still working.  `Vec<IpAddr>`
    /// should contain the current local IP addresses.  If the connection uses a local
    /// socket with an IP address in this list the relay server will be pinged.  If the
    /// connection uses a local socket with an IP address not in this list the server will
    /// always re-connect.
    CheckConnection { local_ips: Vec<IpAddr> },
    /// Sets this relay as the home relay, or not.
    SetHomeRelay(bool),
    #[cfg(test)]
    GetLocalAddr(oneshot::Sender<Option<SocketAddr>>),
    #[cfg(test)]
    PingServer(oneshot::Sender<()>),
}

/// Messages for the [`ActiveRelayActor`] which should never block.
///
/// Most messages in the [`ActiveRelayMessage`] enum trigger sending to the relay server,
/// which can be blocking.  So the actor may not always be processing that inbox.  Messages
/// here are processed immediately.
#[derive(Debug)]
pub(super) enum ActiveRelayPrioMessage {
    /// Returns whether or not this relay can reach the EndpointId.
    HasEndpointRoute(EndpointId, oneshot::Sender<bool>),
}

/// Configuration needed to start an [`ActiveRelayActor`].
#[derive(Debug)]
pub(super) struct ActiveRelayActorOptions {
    pub(super) url: RelayUrl,
    pub(super) prio_inbox_: mpsc::Receiver<ActiveRelayPrioMessage>,
    pub(super) inbox: mpsc::Receiver<ActiveRelayMessage>,
    pub(super) relay_datagrams_send: mpsc::Receiver<RelaySendItem>,
    pub(super) relay_datagrams_recv: mpsc::Sender<RelayRecvDatagram>,
    pub(super) connection_opts: RelayConnectionOptions,
    #[cfg(not(wasm_browser))]
    pub(super) relay_connector: Option<Arc<dyn crate::simulation::RelayConnector>>,
    #[cfg(not(wasm_browser))]
    pub(super) runtime: Arc<Runtime>,
    pub(super) stop_token: CancellationToken,
    pub(super) metrics: Arc<SocketMetrics>,
    pub(super) my_relay: HomeRelayWatch,
}

/// Shared state when the [`ActiveRelayActor`] is connected to a relay server.
///
/// Common state between [`ActiveRelayActor::run_connected`] and
/// [`ActiveRelayActor::run_sending`].
#[derive(Debug)]
pub(super) struct ConnectedRelayState {
    /// Tracks pings we have sent, awaits pong replies.
    pub(super) ping_tracker: PingTracker,
    /// Endpoints which are reachable via this relay server.
    pub(super) endpoints_present: BTreeSet<EndpointId>,
    /// The [`EndpointId`] from whom we received the last packet.
    ///
    /// This is to avoid a slower lookup in the [`ConnectedRelayState::endpoints_present`] map
    /// when we are only communicating to a single remote endpoint.
    pub(super) last_packet_src: Option<EndpointId>,
    /// A pong we need to send ASAP.
    pub(super) pong_pending: Option<[u8; 8]>,
    /// Whether the connection is to be considered established.
    ///
    /// This is set to `true` once a pong was received from the server.
    pub(super) established: bool,
    #[cfg(test)]
    pub(super) test_pong: Option<([u8; 8], oneshot::Sender<()>)>,
}

impl ConnectedRelayState {
    pub(super) fn map_err(&self, error: RunError) -> RelayConnectionError {
        if self.established {
            e!(RelayConnectionError::Established, error)
        } else {
            e!(RelayConnectionError::Handshake, error)
        }
    }
}

/// Handle to one [`ActiveRelayActor`].
#[derive(Debug, Clone)]
pub(super) struct ActiveRelayHandle {
    pub(super) prio_inbox_addr: mpsc::Sender<ActiveRelayPrioMessage>,
    pub(super) inbox_addr: mpsc::Sender<ActiveRelayMessage>,
    pub(super) datagrams_send_queue: mpsc::Sender<RelaySendItem>,
}
