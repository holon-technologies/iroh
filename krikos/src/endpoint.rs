//! The [`Endpoint`] allows establishing connections to other krikos endpoints.
//!
//! The [`Endpoint`] is the main API interface to manage a local krikos endpoint.  It allows
//! connecting to and accepting connections from other endpoints.  See the [module docs] for
//! more details on how krikos connections work.
//!
//! The main items in this module are:
//!
//! - [`Endpoint`] to establish krikos connections with other endpoints.
//! - [`Builder`] to create an [`Endpoint`].
//!
//! [module docs]: crate

use std::{collections::BTreeSet, net::SocketAddr, pin::Pin, sync::Arc};

#[cfg(not(wasm_browser))]
use ipnet::{Ipv4Net, Ipv6Net};
use krikos_base::{EndpointAddr, EndpointId, RelayUrl, SecretKey, TransportAddr};
use krikos_relay::{RelayConfig, RelayMap, tls::CaTlsConfig};
#[cfg(not(wasm_browser))]
use n0_error::bail;
use n0_error::{AnyError, e, ensure, stack_error};
use n0_watcher::Watcher;
use pin_project::pin_project;
use tokio_util::sync::WaitForCancellationFutureOwned;
use tracing::{Instrument, Span, debug, event, info_span, instrument, warn};
use url::Url;

#[cfg(feature = "unstable-custom-transports")]
pub mod transports {
    //! Types for defining custom transports and path selectors.
    //!
    //! <div class="warning">
    //!
    //! These items are unstable and gated behind the `unstable-custom-transport` feature.
    //! They are not covered by semantic versioning guarantees and may change in any release
    //! without a major version bump.
    //!
    //! </div>

    pub use super::socket::{
        remote_map::{PathSelection, PathSelectionContext, PathSelectionData, PathSelector},
        transports::{
            Addr, AddrKind, FourTuple, RecvInfo, Transmit,
            custom::{CustomEndpoint, CustomSender, CustomTransport},
        },
    };
}

use self::hooks::EndpointHooksList;
pub use super::socket::{
    BindError, DirectAddr, DirectAddrType,
    remote_map::{
        Path, PathEvent, PathEventStream, PathList, PathListIter, PathListStream, RemoteInfo,
        TransportAddrInfo, TransportAddrUsage,
    },
    transports::LocalTransportAddr,
};
#[cfg(wasm_browser)]
use crate::address_lookup::PkarrResolver;
#[cfg(not(wasm_browser))]
use crate::dns::DnsResolver;
#[cfg(feature = "unstable-custom-transports")]
use crate::endpoint::transports::CustomTransport;
#[cfg(feature = "unstable-net-report")]
use crate::net_report::Report as NetReport;
pub use crate::tls::TlsConfigError;
use crate::{
    address_lookup::{
        AddrFilter, AddressLookupBuilder, AddressLookupFailed, AddressLookupServices,
        DynAddressLookupBuilder, UserData,
    },
    endpoint::presets::Preset,
    metrics::EndpointMetrics,
    socket::{
        self, EndpointInner, RemoteStateActorStoppedError, StaticConfig,
        biased_rtt_path_selector::BiasedRttPathSelector, mapped_addrs::MappedAddr,
        remote_map::PathSelector, transports::RelayConnectionState,
    },
    tls::{self, DEFAULT_MAX_TLS_TICKETS, misc::RustlsTokenKey},
};

mod builder;
mod handle;
mod lifecycle;
mod relay_status;

pub use builder::Builder;
pub use handle::{ConnectError, ConnectWithOptsError, Endpoint};
pub use lifecycle::EndpointClosed;
pub use relay_status::{
    ENV_FORCE_STAGING_RELAYS, RelayMode, RelayStatus, default_relay_mode, force_staging_infra,
};

#[cfg(not(wasm_browser))]
mod bind;
mod connection;
pub(crate) mod hooks;
pub(crate) mod limits;
pub mod presets;
pub(crate) mod quic;

#[cfg(not(wasm_browser))]
pub use bind::{BindOpts, InvalidSocketAddr, ToSocketAddr};
pub use hooks::{AfterHandshakeOutcome, BeforeConnectOutcome, EndpointHooks};
pub use limits::{
    CapacitySnapshot, DEFAULT_MAX_ACTIVE_RELAY_ACTORS, DEFAULT_MAX_CONNECTIONS,
    DEFAULT_MAX_LIVE_TASKS, DEFAULT_MAX_REMOTE_STATE_ACTORS, EndpointLimits, TaskCapacitySnapshot,
};

#[cfg(feature = "qlog")]
pub use self::quic::{QlogConfig, QlogFactory, QlogFileFactory};
pub use self::{
    connection::{
        Accept, Accepting, AlpnError, AuthenticationError, Connecting, ConnectingError, Connection,
        ConnectionState, HandshakeCompleted, Incoming, IncomingAddr, IncomingZeroRtt,
        IncomingZeroRttConnection, OutgoingZeroRtt, OutgoingZeroRttConnection,
        RemoteEndpointIdError, RetryError, WeakConnectionHandle, ZeroRttStatus,
    },
    quic::{
        AcceptBi, AcceptUni, AckFrequencyConfig, ApplicationClose, Chunk, Closed, ClosedStream,
        ConnectionClose, ConnectionError, ConnectionStats, Controller, ControllerFactory,
        ControllerMetrics, CryptoError, DecryptedInitial, Dir, ExportKeyingMaterialError,
        FrameStats, FrameType, HandshakeTokenKey, HeaderKey, IdleTimeout, IncomingAlpns, Keys,
        MtuDiscoveryConfig, OpenBi, OpenUni, PacketKey, PathId, PathStats, QuicConnectError,
        QuicTransportConfig, QuicTransportConfigBuilder, ReadDatagram, ReadError, ReadExactError,
        ReadToEndError, RecvStream, ResetError, RttEstimator, SendDatagram, SendDatagramError,
        SendStream, ServerConfig, ServerConfigBuilder, Side, StoppedError, StreamId, TimeSource,
        TokenLog, TokenReuseError, TransportError, TransportErrorCode, TransportParameters,
        UdpStats, UnorderedRecvStream, UnsupportedVersion, ValidationTokenConfig, VarInt,
        VarIntBoundsExceeded, WriteError,
    },
};
#[cfg(not(wasm_browser))]
use crate::socket::transports::IpConfig;
use crate::socket::transports::TransportConfig;
pub use crate::{net_report::NetReportConfig, portmapper::PortmapperConfig};

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum EndpointError {
    #[error("Endpoint is closed")]
    Closed,
}

/// Options for the [`Endpoint::connect_with_opts`] function.
#[derive(Default, Debug, Clone)]
pub struct ConnectOptions {
    transport_config: Option<QuicTransportConfig>,
    additional_alpns: Vec<Vec<u8>>,
}

impl ConnectOptions {
    /// Initializes new connection options.
    ///
    /// By default, the connection will use the same options
    /// as [`Endpoint::connect`], e.g. a default [`QuicTransportConfig`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the QUIC transport config options for this connection.
    pub fn with_transport_config(mut self, transport_config: QuicTransportConfig) -> Self {
        self.transport_config = Some(transport_config);
        self
    }

    /// Sets [ALPN] identifiers that should be signaled as supported on connection, *in
    /// addition* to the main [ALPN] identifier used in [`Endpoint::connect_with_opts`].
    ///
    /// This allows connecting to servers that may only support older versions of your
    /// protocol. In this case, you would add the older [ALPN] identifiers with this
    /// function.
    ///
    /// You'll know the final negotiated [ALPN] identifier once your connection was
    /// established using [`Connection::alpn`], or even slightly earlier in the
    /// handshake by using [`Connecting::alpn`].
    /// The negotiated [ALPN] identifier may be any of the [ALPN] identifiers in this
    /// list or the main [ALPN] used in [`Endpoint::connect_with_opts`].
    ///
    /// The [ALPN] identifier order on the connect side doesn't matter, since it's the
    /// accept side that determines the protocol.
    ///
    /// For setting the supported [ALPN] identifiers on the accept side, see the endpoint
    /// builder's [`Builder::alpns`] function.
    ///
    /// [ALPN]: https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation
    pub fn with_additional_alpns(mut self, alpns: Vec<Vec<u8>>) -> Self {
        self.additional_alpns = alpns;
        self
    }
}

/// Read a proxy url from the environment, in this order
///
/// - `HTTP_PROXY`
/// - `http_proxy`
/// - `HTTPS_PROXY`
/// - `https_proxy`
fn proxy_url_from_env() -> Option<Url> {
    if let Some(url) = std::env::var("HTTP_PROXY")
        .ok()
        .and_then(|s| s.parse::<Url>().ok())
    {
        if is_cgi() {
            warn!("HTTP_PROXY environment variable ignored in CGI");
        } else {
            return Some(url);
        }
    }
    if let Some(url) = std::env::var("http_proxy")
        .ok()
        .and_then(|s| s.parse::<Url>().ok())
    {
        return Some(url);
    }
    if let Some(url) = std::env::var("HTTPS_PROXY")
        .ok()
        .and_then(|s| s.parse::<Url>().ok())
    {
        return Some(url);
    }
    if let Some(url) = std::env::var("https_proxy")
        .ok()
        .and_then(|s| s.parse::<Url>().ok())
    {
        return Some(url);
    }

    None
}

/// Check if we are being executed in a CGI context.
///
/// If so, a malicious client can send the `Proxy:` header, and it will
/// be in the `HTTP_PROXY` env var. So we don't use it :)
fn is_cgi() -> bool {
    std::env::var_os("REQUEST_METHOD").is_some()
}

#[cfg(all(test, with_crypto_provider))]
mod tests;
