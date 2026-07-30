//! Implements a socket that can change its communication path while in use, actively searching for the best way to communicate.
//!
//!
//! ### `RelayOnly` path selection:
//! When set this will force all packets to be sent over
//! the relay connection, regardless of whether or
//! not we have a direct UDP address for the given endpoint.
//!
//! The intended use is for testing the relay protocol inside the Socket
//! to ensure that we can rely on the relay to send packets when two endpoints
//! are unable to find direct UDP connections to each other.
//!
//! This also prevent this endpoint from attempting to hole punch and prevents it
//! from responding to any hole punching attempts. This endpoint will still,
//! however, read any packets that come off the UDP sockets.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use iroh_base::{EndpointAddr, EndpointId, RelayUrl, SecretKey, TransportAddr};
use iroh_relay::{RelayConfig, RelayMap};
#[cfg(not(wasm_browser))]
use iroh_runtime::Instant;
use mapped_addrs::MultipathMappedAddr;
use n0_error::{AnyError, anyerr, bail, e, stack_error};
#[cfg(wasm_browser)]
use n0_future::task::{self, AbortOnDropHandle};
#[cfg(wasm_browser)]
use n0_future::time::{self, Instant};
use n0_future::{MaybeFuture, time::Duration};
use n0_watcher::{self, Watchable, Watcher};
use netwatch::netmon;
#[cfg(not(wasm_browser))]
use netwatch::{
    interfaces::{IpNet, Ipv6AddrFlags},
    ip::LocalAddresses,
};
use noq::{
    NetworkChangeHint, TokenStore,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
#[cfg(wasm_browser)]
use rand::RngExt;
use rustc_hash::FxHashSet;
use tokio::sync::{
    Mutex as AsyncMutex,
    mpsc::{self},
    oneshot,
};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};
use tracing::{Instrument, Level, Span, debug, error, event, info_span, instrument, trace, warn};
use transports::{LocalAddrsWatch, Transport, TransportConfig};
use url::Url;

use self::{
    remote_map::{RemoteMap, RemoteStateAdmissionError, RemoteStateMessage},
    transports::{RelayActorConfig, Transports},
};
#[cfg(not(wasm_browser))]
use crate::dns::DnsResolver;
#[cfg(not(wasm_browser))]
use crate::net_report::QuicConfig;
use crate::{
    address_lookup::{self, AddressLookupFailed, EndpointData, UserData},
    defaults::timeouts::NET_REPORT_TIMEOUT,
    endpoint::{
        LocalTransportAddr, RelayStatus, hooks::EndpointHooksList, quic::QuicTransportConfig,
    },
    metrics::EndpointMetrics,
    net_report::{self, IfStateDetails, Report},
    portmapper,
    runtime::Runtime,
    socket::{
        concurrent_read_map::ReadOnlyMap,
        remote_map::{MappedAddrs, PathSelector, PathStateReceiver, RemoteInfo},
        transports::{HomeRelayWatch, HomeRelayWatcher},
    },
    tls::{
        self,
        misc::{Blake3HmacKey, RustlsTokenKey},
    },
};

mod actor;
mod config;
mod direct_addr;
mod inner;

pub use config::BindError;
pub(crate) use config::{Options, StaticConfig};
pub use direct_addr::{DirectAddr, DirectAddrType};
pub(crate) use inner::{
    EndpointInner, RemoteStateActorStoppedError, RemoteStateRegistrationError, Socket,
};

#[cfg(not(wasm_browser))]
use self::direct_addr::find_flags;
use self::{
    actor::{Actor, ActorMessage},
    direct_addr::{DirectAddrUpdateState, DiscoveredDirectAddrs, UpdateReason, new_re_stun_timer},
};

mod metrics;

pub(crate) mod biased_rtt_path_selector;
pub(crate) mod concurrent_read_map;
pub(crate) mod mapped_addrs;
pub(crate) mod remote_map;
pub(crate) mod transports;

use self::mapped_addrs::{EndpointIdMappedAddr, MappedAddr};
pub use self::metrics::Metrics;

// TODO: Use this
// /// How long we consider a QAD-derived endpoint valid for. UDP NAT mappings typically
// /// expire at 30 seconds, so this is a few seconds shy of that.
// const ENDPOINTS_FRESH_ENOUGH_DURATION: Duration = Duration::from_secs(27);

/// The duration in which we send keep-alives.
///
/// If a path is idle for this long, a PING frame will be sent to keep the connection
/// alive.
pub(crate) const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// The maximum time a path can stay idle before being closed.
///
/// 15s gives 3x [`HEARTBEAT_INTERVAL`] (5s) for multiple retry chances, and enough
/// margin for real-world outages (WiFi reconnect 2-5s, cellular handoff 2-10s).
/// iroh 0.35 used 10s at the QUIC level; tailscale uses 45s at the WireGuard session
/// level with 3s heartbeats.
pub(crate) const PATH_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(15);

/// The maximum time a relay path can stay idle before being closed.
///
/// Relay paths need a longer idle timeout than direct paths because the relay actor
/// manages the WebSocket connection and transparently reconnects after network changes
/// or relay server restarts. During network outages the interface may be down for
/// 5-15s, during which no relay traffic flows. Once the interface recovers, the relay
/// actor reconnects (DNS + TCP + TLS + WebSocket upgrade), which adds another 1-2s.
///
/// Set to match the connection-level idle timeout (30s) so the relay path survives
/// as long as the connection itself.
pub(crate) const RELAY_PATH_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of concurrent QUIC multipath paths per connection.
///
/// We expect 1 relay path, and then leave space for ~3 IP and custom transport paths.
/// On top of that, when we expect a network change, we might be closing these paths
/// (except for the relay path) and open new ones, and give us 3 more paths to spare.
/// And finally we round that up to 8 for good measure.
pub(crate) const MAX_MULTIPATH_PATHS: u32 = 8;

/// Maximum number of n0 QUIC NAT Traversal addresses that the QUIC stack should allow.
///
/// This needs to be big enough to accommodate for machines which have lots of network
/// interfaces enabled. We've seen MacOS machines with >25 interfaces in the wild
/// (mostly due to VPN TUN and docket interfaces), so this seems like a reasonable
/// value.
pub(crate) const MAX_QNT_ADDRESSES: u8 = 32;

#[cfg(not(wasm_browser))]
fn noq_behavioral_seed(
    context: &iroh_runtime::RuntimeContext,
    endpoint_id: EndpointId,
) -> Result<[u8; 32], iroh_runtime::DecisionError> {
    let path = format!("endpoint/{endpoint_id}/noq");
    let mut stream = context.decisions().stream(&path)?;
    let mut seed = [0; 32];
    stream.fill_bytes(&mut seed)?;
    Ok(seed)
}

/// Connection IDs normally come from Noq's process entropy source, independently of its seeded
/// endpoint RNG. Repository simulations replace that factory explicitly so raw packet traces can
/// be replayed byte-for-byte. The key is simulation-only cryptographic material, not a behavioral
/// decision stream.
#[cfg(not(wasm_browser))]
struct DeterministicSimulationConnectionIdGenerator {
    key: [u8; 32],
    counter: u64,
}

#[cfg(not(wasm_browser))]
pub(crate) fn deterministic_simulation_initial_dst_cid_provider(
    reset_key: [u8; 32],
) -> Arc<dyn Fn() -> noq::ConnectionId + Send + Sync> {
    const INITIAL_DST_CID_LEN: usize = 20;
    let key = blake3::derive_key(
        "iroh simulation QUIC initial destination connection IDs v1",
        &reset_key,
    );
    let counter = AtomicU64::new(0);
    Arc::new(move || {
        let counter = counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .expect("simulation initial destination connection ID counter exhausted");
        let digest = blake3::keyed_hash(&key, &counter.to_le_bytes());
        noq::ConnectionId::new(&digest.as_bytes()[..INITIAL_DST_CID_LEN])
    })
}

#[cfg(not(wasm_browser))]
impl DeterministicSimulationConnectionIdGenerator {
    const CID_LEN: usize = 16;

    fn new(reset_key: [u8; 32]) -> Self {
        let key = blake3::derive_key("iroh simulation QUIC connection IDs v1", &reset_key);
        Self { key, counter: 0 }
    }
}

#[cfg(not(wasm_browser))]
impl noq::ConnectionIdGenerator for DeterministicSimulationConnectionIdGenerator {
    fn generate_cid(&mut self) -> noq::ConnectionId {
        let mut input = [0u8; 8];
        input.copy_from_slice(&self.counter.to_le_bytes());
        self.counter = self
            .counter
            .checked_add(1)
            .expect("simulation connection ID counter exhausted");
        let digest = blake3::keyed_hash(&self.key, &input);
        noq::ConnectionId::new(&digest.as_bytes()[..Self::CID_LEN])
    }

    fn cid_len(&self) -> usize {
        Self::CID_LEN
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

#[cfg(all(test, with_crypto_provider))]
mod tests;
