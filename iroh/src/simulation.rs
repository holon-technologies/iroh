//! Internal environment capabilities used by deterministic repository simulations.
//!
//! These APIs are deliberately not selected by normal endpoint builders. They are public only so
//! the private `iroh-sim` workspace crate can supply implementations without creating a dependency
//! cycle. They are not covered by Iroh's stable public API guarantees.

#![doc(hidden)]

#[cfg(not(wasm_browser))]
mod deterministic_crypto;

use std::{
    fmt,
    future::Future,
    io::{self, IoSliceMut},
    net::{SocketAddr, SocketAddrV4},
    num::{NonZeroU16, NonZeroUsize},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

#[cfg(not(wasm_browser))]
use iroh_base::{EndpointId, RelayUrl, SecretKey};

/// Simulation-only QUIC token and stateless-reset material.
///
/// These bytes must be derived independently of behavioral decision streams and must never be
/// installed by a normal production builder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SimulationCryptoMaterial {
    token_key: [u8; 32],
    reset_key: [u8; 32],
}

/// TLS provider mode selected explicitly by repository simulation infrastructure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimulationCryptoMode {
    /// Run-owned deterministic entropy and X25519 for byte-exact replay.
    DeterministicTest,
    /// The configured production cryptography provider and semantic replay.
    ProductionProvider,
}

impl SimulationCryptoMaterial {
    /// Creates explicit unsafe-test-only protocol material.
    pub const fn new(token_key: [u8; 32], reset_key: [u8; 32]) -> Self {
        Self {
            token_key,
            reset_key,
        }
    }

    pub(crate) const fn token_key(self) -> [u8; 32] {
        self.token_key
    }

    pub(crate) const fn reset_key(self) -> [u8; 32] {
        self.reset_key
    }
}

/// Complete environment bundle installed by the deterministic simulator.
#[derive(Clone, Debug)]
pub struct SimulationEnvironment {
    pub(crate) runtime: Arc<iroh_runtime::RuntimeContext>,
    pub(crate) ip_sockets: Arc<dyn IpSocketFactory>,
    pub(crate) network_monitor: Arc<dyn NetworkMonitor>,
    pub(crate) port_mapper: Option<Arc<dyn PortMapper>>,
    #[cfg(not(wasm_browser))]
    pub(crate) relay_connector: Option<Arc<dyn RelayConnector>>,
    #[cfg(not(wasm_browser))]
    pub(crate) preferred_relay: Option<RelayUrl>,
    pub(crate) crypto: SimulationCryptoMaterial,
    pub(crate) crypto_mode: SimulationCryptoMode,
    pub(crate) crypto_provider: Option<Arc<rustls::crypto::CryptoProvider>>,
}

impl SimulationEnvironment {
    /// Creates a coherent explicit simulation environment.
    pub fn new(
        runtime: Arc<iroh_runtime::RuntimeContext>,
        ip_sockets: Arc<dyn IpSocketFactory>,
        network_monitor: Arc<dyn NetworkMonitor>,
        crypto: SimulationCryptoMaterial,
    ) -> Self {
        Self {
            runtime,
            ip_sockets,
            network_monitor,
            port_mapper: None,
            #[cfg(not(wasm_browser))]
            relay_connector: None,
            #[cfg(not(wasm_browser))]
            preferred_relay: None,
            crypto,
            crypto_mode: SimulationCryptoMode::ProductionProvider,
            crypto_provider: None,
        }
    }

    /// Installs run- and endpoint-scoped deterministic test TLS.
    pub fn with_deterministic_test_tls(
        mut self,
        provider: Arc<rustls::crypto::CryptoProvider>,
        run_seed: [u8; 32],
        endpoint_scope: &str,
    ) -> Self {
        self.crypto_provider = Some(deterministic_crypto::deterministic_test_crypto_provider(
            provider,
            run_seed,
            endpoint_scope,
        ));
        self.crypto_mode = SimulationCryptoMode::DeterministicTest;
        self
    }

    /// Returns the explicitly selected simulation TLS mode.
    pub const fn crypto_mode(&self) -> SimulationCryptoMode {
        self.crypto_mode
    }

    /// Installs a simulator-owned port-mapping capability.
    pub fn with_port_mapper(mut self, port_mapper: Arc<dyn PortMapper>) -> Self {
        self.port_mapper = Some(port_mapper);
        self
    }

    /// Installs a simulator-owned relay connection capability.
    #[cfg(not(wasm_browser))]
    pub fn with_relay_connector(mut self, relay_connector: Arc<dyn RelayConnector>) -> Self {
        self.relay_connector = Some(relay_connector);
        self
    }

    /// Supplies the simulator-owned initial preferred relay selection.
    #[cfg(not(wasm_browser))]
    pub fn with_preferred_relay(mut self, preferred_relay: RelayUrl) -> Self {
        self.preferred_relay = Some(preferred_relay);
        self
    }
}

/// Owned inputs for one relay connection attempt made by the production relay actor.
#[cfg(not(wasm_browser))]
#[derive(Clone, Debug)]
pub struct RelayConnectRequest {
    url: RelayUrl,
    secret_key: SecretKey,
    auth_token: Option<String>,
}

#[cfg(not(wasm_browser))]
impl RelayConnectRequest {
    pub(crate) fn new(url: RelayUrl, secret_key: SecretKey, auth_token: Option<String>) -> Self {
        Self {
            url,
            secret_key,
            auth_token,
        }
    }

    /// Relay URL selected by the production relay actor.
    pub fn url(&self) -> &RelayUrl {
        &self.url
    }

    /// Secret identity used by the normal relay challenge authentication.
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Public endpoint identity corresponding to [`Self::secret_key`].
    pub fn endpoint_id(&self) -> EndpointId {
        self.secret_key.public()
    }

    /// Optional bearer token configured for this relay.
    pub fn auth_token(&self) -> Option<&str> {
        self.auth_token.as_deref()
    }
}

/// Failure returned by an injected relay connection capability.
#[cfg(not(wasm_browser))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayConnectError {
    message: Arc<str>,
}

#[cfg(not(wasm_browser))]
impl RelayConnectError {
    /// Creates a sanitized connection error. Secret material must not be included.
    pub fn new(message: impl Into<Arc<str>>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[cfg(not(wasm_browser))]
impl fmt::Display for RelayConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

#[cfg(not(wasm_browser))]
impl std::error::Error for RelayConnectError {}

/// Simulation-only connection factory consumed by Iroh's production relay actor.
#[cfg(not(wasm_browser))]
pub trait RelayConnector: fmt::Debug + Send + Sync + 'static {
    /// Starts one owned relay connection attempt.
    fn connect(
        &self,
        request: RelayConnectRequest,
    ) -> Pin<Box<dyn Future<Output = Result<iroh_relay::client::Client, RelayConnectError>> + Send>>;
}

/// Environment-owned port mapper consumed by the production socket actor.
pub trait PortMapper: fmt::Debug + Send + Sync + 'static {
    fn procure_mapping(&self);
    fn update_local_port(&self, port: NonZeroU16);
    fn deactivate(&self);
    fn watch_external_address(&self) -> tokio::sync::watch::Receiver<Option<SocketAddrV4>>;
}

/// Interface-state source observed by the production socket actor.
pub trait NetworkMonitor: fmt::Debug + Send + Sync + 'static {
    /// Returns the current state and a deterministic update stream.
    fn interface_state(&self) -> n0_watcher::Direct<netwatch::netmon::State>;

    /// Refreshes interface state after an explicit network-change notification.
    fn network_change(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// Normal OS-backed network monitor installed by production endpoint builders.
#[derive(Debug)]
pub struct OsNetworkMonitor {
    inner: netwatch::netmon::Monitor,
}

impl OsNetworkMonitor {
    /// Creates the platform network monitor and its owned observation task.
    pub async fn new() -> Result<Self, netwatch::netmon::Error> {
        Ok(Self {
            inner: netwatch::netmon::Monitor::new().await?,
        })
    }
}

impl NetworkMonitor for OsNetworkMonitor {
    fn interface_state(&self) -> n0_watcher::Direct<netwatch::netmon::State> {
        self.inner.interface_state()
    }

    fn network_change(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            self.inner.network_change().await.ok();
        })
    }
}

/// Creates environment-owned IP/UDP sockets for an endpoint.
pub trait IpSocketFactory: fmt::Debug + Send + Sync + 'static {
    /// Binds one socket using production-compatible address semantics.
    fn bind(&self, addr: SocketAddr) -> io::Result<Arc<dyn IpSocket>>;
}

/// Bound IP/UDP socket consumed by Iroh's production IP transport.
pub trait IpSocket: fmt::Debug + Send + Sync + 'static {
    /// Creates an independent sender with its own readiness registration.
    fn create_sender(self: Arc<Self>) -> Pin<Box<dyn IpSocketSender>>;

    /// Receives a batch of Noq-compatible UDP datagrams.
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
    ) -> Poll<io::Result<usize>>;

    /// Returns the currently bound address.
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Rebinds after an environment network change.
    fn rebind(&self) -> io::Result<()>;

    /// Maximum number of GSO transmit segments.
    fn max_transmit_segments(&self) -> NonZeroUsize {
        NonZeroUsize::MIN
    }

    /// Maximum number of GRO receive segments.
    fn max_receive_segments(&self) -> NonZeroUsize {
        NonZeroUsize::MIN
    }

    /// Whether the IP layer may fragment outgoing datagrams.
    fn may_fragment(&self) -> bool {
        false
    }
}

/// Independent readiness and send state for an [`IpSocket`].
pub trait IpSocketSender: fmt::Debug + Send + Sync + 'static {
    /// Sends a Noq UDP transmit or registers for readiness.
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &noq_udp::Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>>;

    /// Maximum number of GSO transmit segments.
    fn max_transmit_segments(&self) -> NonZeroUsize {
        NonZeroUsize::MIN
    }
}

#[cfg(all(test, with_crypto_provider, not(wasm_browser)))]
mod crypto_ownership_tests {
    use super::*;
    use rustls::crypto::{GetRandomFailed, SecureRandom};

    #[derive(Debug)]
    struct RunOwnedRandom([u8; 1]);

    impl SecureRandom for RunOwnedRandom {
        fn fill(&self, destination: &mut [u8]) -> Result<(), GetRandomFailed> {
            destination.fill(self.0[0]);
            Ok(())
        }
    }

    #[test]
    fn rustls_provider_owns_run_scoped_randomness() {
        let random: Arc<dyn SecureRandom> = Arc::new(RunOwnedRandom([7]));
        let mut provider = (*iroh_relay::tls::default_provider()).clone();
        provider.secure_random = random.clone();

        let mut bytes = [0; 4];
        provider.secure_random.fill(&mut bytes).unwrap();
        assert_eq!(bytes, [7; 4]);
        assert_eq!(Arc::strong_count(&random), 2);
    }
}

/// Normal OS-backed socket factory installed by production endpoint builders.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsIpSocketFactory;

impl IpSocketFactory for OsIpSocketFactory {
    fn bind(&self, addr: SocketAddr) -> io::Result<Arc<dyn IpSocket>> {
        Ok(Arc::new(OsIpSocket {
            inner: Arc::new(netwatch::UdpSocket::bind_full(addr)?),
        }))
    }
}

#[derive(Debug)]
struct OsIpSocket {
    inner: Arc<netwatch::UdpSocket>,
}

impl IpSocket for OsIpSocket {
    fn create_sender(self: Arc<Self>) -> Pin<Box<dyn IpSocketSender>> {
        Box::pin(OsIpSocketSender {
            inner: self.inner.clone().create_sender(),
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv_noq(cx, bufs, metas)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn rebind(&self) -> io::Result<()> {
        self.inner.rebind()
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        self.inner.max_gso_segments()
    }

    fn max_receive_segments(&self) -> NonZeroUsize {
        self.inner.gro_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[derive(Debug)]
struct OsIpSocketSender {
    inner: netwatch::UdpSender,
}

impl IpSocketSender for OsIpSocketSender {
    fn poll_send(
        mut self: Pin<&mut Self>,
        transmit: &noq_udp::Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_send(transmit, cx)
    }
}
