use super::*;

pub(crate) enum RelayActorMessage {
    MaybeCloseRelaysOnRebind,
    NetworkChange {
        report: Report,
    },
    /// Trigger an immediate health check on all relay connections.
    ///
    /// Sent after a major network change to detect broken connections faster
    /// using RTT-based timeouts instead of the default 5s ping timeout.
    CheckConnectionAfterNetworkChange,
}

#[derive(Debug, Clone)]
pub(crate) struct RelaySendItem {
    /// The destination for the datagrams.
    pub(crate) remote_endpoint: EndpointId,
    /// The home relay of the remote endpoint.
    pub(crate) url: RelayUrl,
    /// One or more datagrams to send.
    pub(crate) datagrams: Datagrams,
}

#[derive(Debug, Clone)]
pub(crate) struct Config {
    pub my_relay: HomeRelayWatch,
    pub secret_key: SecretKey,
    #[cfg(not(wasm_browser))]
    pub dns_resolver: DnsResolver,
    /// Proxy
    pub proxy_url: Option<Url>,
    /// If the last net_report report, reports IPv6 to be available.
    pub ipv6_reported: Arc<AtomicBool>,
    pub tls_config: rustls::ClientConfig,
    pub metrics: Arc<SocketMetrics>,
    /// Per-relay configuration. Consulted when starting a connection to
    /// look up the auth token and any future per-relay options.
    pub relay_map: RelayMap,
    #[cfg(not(wasm_browser))]
    pub relay_connector: Option<Arc<dyn crate::simulation::RelayConnector>>,
    #[cfg(not(wasm_browser))]
    pub initial_relay: Option<RelayUrl>,
    pub limits: EndpointLimits,
}

/// Connection state of the home relay.
///
/// Published via [`HomeRelayWatch`] so that [`Endpoint::online`] and the public
/// [`Endpoint::home_relay_status`] watcher can observe the connection state.
/// This type is `pub(crate)`; the public surface lives on
/// [`crate::endpoint::RelayStatus`], and this enum is intentionally free to
/// evolve without affecting the public API.
///
/// [`Endpoint::online`]: crate::Endpoint::online
/// [`Endpoint::home_relay_status`]: crate::Endpoint::home_relay_status
#[derive(Debug, Clone)]
pub(crate) enum RelayConnectionState {
    /// Dialing or performing the relay handshake.
    Connecting,
    /// Connected and handshaked.
    Connected,
    /// Not connected. Either the connection was lost after having been
    /// established, or an attempt to connect failed.
    ///
    /// `last_error` carries the most recent connection error, if any. The
    /// initial transition into this state (before any attempt has produced
    /// an error) carries `None`.
    ///
    /// The `Arc` is compared by pointer identity: each new failure produces
    /// a fresh allocation, so the watcher fires on every new error.
    Disconnected { last_error: Option<Arc<AnyError>> },
}

impl RelayConnectionState {
    pub(crate) fn is_connected(&self) -> bool {
        matches!(self, Self::Connected)
    }

    pub(crate) fn last_error(&self) -> Option<&Arc<AnyError>> {
        match self {
            Self::Disconnected { last_error } => last_error.as_ref(),
            _ => None,
        }
    }
}

impl PartialEq for RelayConnectionState {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Connecting, Self::Connecting) | (Self::Connected, Self::Connected) => true,
            (Self::Disconnected { last_error: a }, Self::Disconnected { last_error: b }) => {
                match (a, b) {
                    (None, None) => true,
                    (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                    _ => false,
                }
            }
            _ => false,
        }
    }
}

impl Eq for RelayConnectionState {}

/// Shared watchable for the home relay URL and connection status.
///
/// Owned by [`RelayActor`] and cloned into each [`ActiveRelayActor`].
///
/// # Write discipline
///
/// The [`RelayActor`] writes the URL (via [`Self::set`] and [`Self::clear`]).
/// Each [`ActiveRelayActor`] updates only the status (via [`Self::set_status`]),
/// which guards against stale writes: if another relay has become home since this actor
/// was designated, the write is silently dropped.
#[derive(Debug, Clone)]
pub(crate) struct HomeRelayWatch {
    inner: Watchable<Option<RelayStatus>>,
}

impl Default for HomeRelayWatch {
    fn default() -> Self {
        Self {
            inner: Watchable::new(None),
        }
    }
}

impl HomeRelayWatch {
    /// Set the home relay URL and status. Used by [`RelayActor`] on relay changes.
    pub(super) fn set(&self, url: RelayUrl, state: RelayConnectionState) {
        let _ = self.inner.set(Some(RelayStatus::new(url, state)));
    }

    /// Clear the home relay (no preferred relay). Used by [`RelayActor`].
    pub(super) fn clear(&self) {
        let _ = self.inner.set(None);
    }

    /// Update the status, but only if `url` is still the current home relay.
    ///
    /// This is the only write method [`ActiveRelayActor`] should use. It prevents a
    /// demoted actor from overwriting a newer home relay's status: the [`RelayActor`]
    /// updates the URL in the watchable *before* sending `SetHomeRelay(false)`, so by
    /// the time the old actor tries to write, the URL no longer matches.
    pub(super) fn set_status(&self, url: &RelayUrl, state: RelayConnectionState) {
        if self.inner.get().as_ref().map(RelayStatus::url) == Some(url) {
            let _ = self.inner.set(Some(RelayStatus::new(url.clone(), state)));
        }
    }

    pub(super) fn get(&self) -> Option<RelayStatus> {
        self.inner.get()
    }

    pub(crate) fn watch(&self) -> n0_watcher::Direct<Option<RelayStatus>> {
        self.inner.watch()
    }
}

/// A single datagram received from a relay server.
///
/// This could be either a QUIC or DISCO packet.
#[derive(Debug)]
pub(crate) struct RelayRecvDatagram {
    pub(crate) url: RelayUrl,
    pub(crate) src: EndpointId,
    pub(crate) datagrams: Datagrams,
}
