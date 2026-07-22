//! Simulator-owned lifecycle around production relay client/server sessions.

use std::{
    collections::BTreeMap,
    fmt,
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    sync::{Arc, Mutex},
};

use iroh::{RelayUrl, SecretKey};
use iroh_relay::{
    KeyCache,
    client::{Client, ClientBuilder},
    http::ProtocolVersion,
    server::{
        AllowAll, ClientRateLimit, Metrics,
        http_server::{RelayService, RelayServiceRuntime},
    },
};
use iroh_runtime::{Clock, ClockSleep, RuntimeContext, TokioClock};

use crate::{RelayImpairmentSpec, RelayProtocolVersion, RelaySpec};

/// A bounded collection of independent production relay session services.
#[derive(Clone)]
pub struct RelayEnvironment {
    inner: Arc<Inner>,
}

impl fmt::Debug for RelayEnvironment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayEnvironment")
            .field("relay_ids", &self.inner.by_id.keys().collect::<Vec<_>>())
            .finish()
    }
}

struct Inner {
    by_id: BTreeMap<String, Arc<RelayNode>>,
    by_url: BTreeMap<RelayUrl, Arc<RelayNode>>,
}

struct RelayNode {
    spec: RelaySpec,
    url: RelayUrl,
    service: RelayService,
    metrics: Arc<Metrics>,
    lifecycle: Mutex<Lifecycle>,
    availability: tokio::sync::watch::Sender<bool>,
    admission: tokio::sync::Mutex<()>,
    connect_attempts: AtomicU64,
    authenticated_sessions: AtomicU64,
    impairment: RelayImpairmentSpec,
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for RelayNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayNode")
            .field("id", &self.spec.id)
            .field("url", &self.url)
            .field("lifecycle", &self.lifecycle)
            .field("sessions", &self.service.clients().connection_count())
            .finish()
    }
}

#[derive(Clone, Copy, Debug)]
struct Lifecycle {
    online: bool,
    generation: u64,
}

impl RelayEnvironment {
    /// Builds independent bounded relay services from validated topology entries.
    pub fn new(specs: &[RelaySpec]) -> Result<Self, RelayEnvironmentError> {
        Self::new_with_impairments(specs, &[])
    }

    /// Builds services with optional bounded deterministic connection and routed-frame faults.
    pub fn new_with_impairments(
        specs: &[RelaySpec],
        impairments: &[RelayImpairmentSpec],
    ) -> Result<Self, RelayEnvironmentError> {
        Self::new_with_clock(specs, impairments, Arc::new(TokioClock::default()))
    }

    /// Builds services using an explicitly owned monotonic clock.
    pub fn new_with_clock(
        specs: &[RelaySpec],
        impairments: &[RelayImpairmentSpec],
        clock: Arc<dyn Clock>,
    ) -> Result<Self, RelayEnvironmentError> {
        Self::build(specs, impairments, clock, None)
    }

    /// Builds services whose production relay actors use the supplied run-owned runtime.
    pub fn new_with_runtime(
        specs: &[RelaySpec],
        impairments: &[RelayImpairmentSpec],
        runtime: Arc<RuntimeContext>,
    ) -> Result<Self, RelayEnvironmentError> {
        Self::build(specs, impairments, runtime.clock(), Some(runtime))
    }

    fn build(
        specs: &[RelaySpec],
        impairments: &[RelayImpairmentSpec],
        clock: Arc<dyn Clock>,
        runtime: Option<Arc<RuntimeContext>>,
    ) -> Result<Self, RelayEnvironmentError> {
        let mut impairment_by_relay = BTreeMap::new();
        for impairment in impairments {
            if !specs.iter().any(|spec| spec.id == impairment.relay)
                || impairment.connection_delay_nanos > 60_000_000_000
                || impairment.reject_connect_attempts.contains(&0)
                || impairment.drop_every_nth_packet == Some(0)
                || impairment.client_rx_bytes_per_second == Some(0)
                || impairment.client_rx_max_burst_bytes == Some(0)
                || (impairment.client_rx_max_burst_bytes.is_some()
                    && impairment.client_rx_bytes_per_second.is_none())
                || impairment_by_relay
                    .insert(impairment.relay.as_str(), impairment)
                    .is_some()
            {
                return Err(RelayEnvironmentError::InvalidSpec(impairment.relay.clone()));
            }
        }
        let mut by_id = BTreeMap::new();
        let mut by_url = BTreeMap::new();
        for spec in specs {
            if spec.id.is_empty()
                || spec.max_sessions == 0
                || spec.byte_capacity == 0
                || spec.byte_capacity > 16 * 1024 * 1024
            {
                return Err(RelayEnvironmentError::InvalidSpec(spec.id.clone()));
            }
            let url = spec
                .url
                .parse::<RelayUrl>()
                .map_err(|_| RelayEnvironmentError::InvalidSpec(spec.id.clone()))?;
            if by_id.contains_key(&spec.id) || by_url.contains_key(&url) {
                return Err(RelayEnvironmentError::Duplicate(spec.id.clone()));
            }
            let metrics = Arc::new(Metrics::default());
            let rate_limit = impairment_by_relay
                .get(spec.id.as_str())
                .and_then(|impairment| impairment.client_rx_bytes_per_second)
                .and_then(std::num::NonZeroU32::new)
                .map(|bytes_per_second| {
                    let mut limit = ClientRateLimit::new(bytes_per_second);
                    limit.max_burst_bytes = impairment_by_relay
                        .get(spec.id.as_str())
                        .and_then(|impairment| impairment.client_rx_max_burst_bytes)
                        .and_then(std::num::NonZeroU32::new);
                    limit
                });
            let service = match &runtime {
                Some(runtime) => RelayService::new_with_runtime(
                    Default::default(),
                    Default::default(),
                    rate_limit,
                    KeyCache::new(128),
                    Arc::new(AllowAll),
                    metrics.clone(),
                    RelayServiceRuntime::new(
                        runtime.clone(),
                        format!("relay-server/{}/behavior", spec.id),
                    ),
                )
                .map_err(|_| RelayEnvironmentError::InvalidSpec(spec.id.clone()))?,
                None => RelayService::new(
                    Default::default(),
                    Default::default(),
                    rate_limit,
                    KeyCache::new(128),
                    Arc::new(AllowAll),
                    metrics.clone(),
                ),
            };
            let impairment = impairment_by_relay
                .get(spec.id.as_str())
                .copied()
                .cloned()
                .unwrap_or_else(|| RelayImpairmentSpec {
                    relay: spec.id.clone(),
                    client_rx_bytes_per_second: None,
                    client_rx_max_burst_bytes: None,
                    ..RelayImpairmentSpec::default()
                });
            service
                .clients()
                .set_test_drop_every_nth_packet(impairment.drop_every_nth_packet);
            let node = Arc::new(RelayNode {
                spec: spec.clone(),
                url: url.clone(),
                service,
                metrics,
                lifecycle: Mutex::new(Lifecycle {
                    online: spec.online,
                    generation: 0,
                }),
                availability: tokio::sync::watch::Sender::new(spec.online),
                admission: tokio::sync::Mutex::new(()),
                connect_attempts: AtomicU64::new(0),
                authenticated_sessions: AtomicU64::new(0),
                impairment,
                clock: clock.clone(),
            });
            by_id.insert(spec.id.clone(), node.clone());
            by_url.insert(url, node);
        }
        Ok(Self {
            inner: Arc::new(Inner { by_id, by_url }),
        })
    }

    /// Opens a production authenticated session by stable relay ID.
    pub async fn connect_client(
        &self,
        relay: &str,
        secret_key: SecretKey,
        auth_token: Option<String>,
    ) -> Result<Client, RelayEnvironmentError> {
        let node = self
            .inner
            .by_id
            .get(relay)
            .cloned()
            .ok_or_else(|| RelayEnvironmentError::UnknownRelay(relay.to_owned()))?;
        Self::connect_node(node, secret_key, auth_token).await
    }

    async fn connect_node(
        node: Arc<RelayNode>,
        secret_key: SecretKey,
        auth_token: Option<String>,
    ) -> Result<Client, RelayEnvironmentError> {
        let _admission = node.admission.lock().await;
        let attempt = node.connect_attempts.fetch_add(1, Ordering::Relaxed) + 1;
        if node.impairment.connection_delay_nanos != 0 {
            ClockSleep::after(
                node.clock.clone(),
                std::time::Duration::from_nanos(node.impairment.connection_delay_nanos),
            )
            .map_err(|error| RelayEnvironmentError::Clock(error.to_string()))?
            .await
            .map_err(|error| RelayEnvironmentError::Clock(error.to_string()))?;
        }
        if node.impairment.reject_connect_attempts.contains(&attempt) {
            return Err(RelayEnvironmentError::Impaired {
                relay: node.spec.id.clone(),
                attempt,
            });
        }
        if !node
            .lifecycle
            .lock()
            .expect("relay lifecycle poisoned")
            .online
        {
            return Err(RelayEnvironmentError::Offline(node.spec.id.clone()));
        }
        let sessions = node.service.clients().connection_count();
        let maximum = usize::try_from(node.spec.max_sessions).unwrap_or(usize::MAX);
        if sessions >= maximum {
            return Err(RelayEnvironmentError::Capacity {
                relay: node.spec.id.clone(),
                maximum: node.spec.max_sessions,
            });
        }
        let mut builder =
            ClientBuilder::new(node.url.clone(), secret_key, iroh::dns::DnsResolver::new());
        if let Some(token) = auth_token {
            builder = builder.auth_token(token);
        }
        let client = node
            .service
            .connect_in_memory(
                &builder,
                protocol_version(node.spec.protocol_version),
                node.spec.byte_capacity,
            )
            .await
            .map_err(|error| RelayEnvironmentError::Connect {
                relay: node.spec.id.clone(),
                details: error.to_string(),
            })?;
        node.authenticated_sessions.fetch_add(1, Ordering::Relaxed);
        Ok(client)
    }

    /// Applies an outage or restart transition and closes all pre-transition sessions.
    pub async fn set_online(&self, relay: &str, online: bool) -> Result<(), RelayEnvironmentError> {
        let node = self
            .inner
            .by_id
            .get(relay)
            .cloned()
            .ok_or_else(|| RelayEnvironmentError::UnknownRelay(relay.to_owned()))?;
        let _admission = node.admission.lock().await;
        let changed = {
            let mut lifecycle = node.lifecycle.lock().expect("relay lifecycle poisoned");
            let changed = lifecycle.online != online;
            if changed && online {
                lifecycle.generation = lifecycle.generation.saturating_add(1);
            }
            lifecycle.online = online;
            changed
        };
        if changed {
            node.availability.send_replace(online);
        }
        if changed && !online {
            node.service.shutdown().await;
        }
        Ok(())
    }

    /// Returns the current lifecycle generation for one relay.
    pub fn generation(&self, relay: &str) -> Result<u64, RelayEnvironmentError> {
        let node = self
            .inner
            .by_id
            .get(relay)
            .ok_or_else(|| RelayEnvironmentError::UnknownRelay(relay.to_owned()))?;
        Ok(node
            .lifecycle
            .lock()
            .expect("relay lifecycle poisoned")
            .generation)
    }

    /// Returns the exact number of registered sessions for one relay.
    pub fn session_count(&self, relay: &str) -> Result<usize, RelayEnvironmentError> {
        let node = self
            .inner
            .by_id
            .get(relay)
            .ok_or_else(|| RelayEnvironmentError::UnknownRelay(relay.to_owned()))?;
        Ok(node.service.clients().connection_count())
    }

    /// Returns the number of datagram frames routed successfully by all relay services.
    pub fn forwarded_packets(&self) -> u64 {
        self.inner
            .by_id
            .values()
            .map(|node| node.metrics.send_packets_sent.get())
            .sum()
    }

    /// Returns per-relay production-handler coverage counters in stable relay-ID order.
    pub fn coverage(&self) -> BTreeMap<String, RelayCoverage> {
        self.inner
            .by_id
            .iter()
            .map(|(id, node)| {
                (
                    id.clone(),
                    RelayCoverage {
                        connect_attempts: node.connect_attempts.load(Ordering::Relaxed),
                        authenticated_sessions: node.authenticated_sessions.load(Ordering::Relaxed),
                        forwarded_packets: node.metrics.send_packets_sent.get(),
                        dropped_packets: node.metrics.send_packets_dropped.get(),
                    },
                )
            })
            .collect()
    }

    /// Disconnects every production server session.
    pub async fn shutdown(&self) {
        for node in self.inner.by_id.values() {
            let _admission = node.admission.lock().await;
            node.service.shutdown().await;
        }
    }
}

impl iroh::simulation::RelayConnector for RelayEnvironment {
    fn connect(
        &self,
        request: iroh::simulation::RelayConnectRequest,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        iroh_relay::client::Client,
                        iroh::simulation::RelayConnectError,
                    >,
                > + Send,
        >,
    > {
        let this = self.clone();
        Box::pin(async move {
            let node = this
                .inner
                .by_url
                .get(request.url())
                .cloned()
                .ok_or_else(|| iroh::simulation::RelayConnectError::new("unknown relay URL"))?;
            if !*node.availability.borrow() {
                let mut availability = node.availability.subscribe();
                while !*availability.borrow_and_update() {
                    availability.changed().await.map_err(|_| {
                        iroh::simulation::RelayConnectError::new("relay lifecycle ended")
                    })?;
                }
            }
            Self::connect_node(
                node,
                request.secret_key().clone(),
                request.auth_token().map(str::to_owned),
            )
            .await
            .map_err(|error| iroh::simulation::RelayConnectError::new(error.to_string()))
        })
    }
}

fn protocol_version(version: RelayProtocolVersion) -> ProtocolVersion {
    match version {
        RelayProtocolVersion::V1 => ProtocolVersion::V1,
        RelayProtocolVersion::V2 => ProtocolVersion::V2,
    }
}

/// Invalid relay topology or lifecycle/connection operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayEnvironmentError {
    InvalidSpec(String),
    Duplicate(String),
    UnknownRelay(String),
    Offline(String),
    Capacity { relay: String, maximum: u64 },
    Impaired { relay: String, attempt: u64 },
    Connect { relay: String, details: String },
    Clock(String),
}

impl fmt::Display for RelayEnvironmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSpec(relay) => write!(f, "invalid relay specification {relay:?}"),
            Self::Duplicate(relay) => write!(f, "duplicate relay identity or URL {relay:?}"),
            Self::UnknownRelay(relay) => write!(f, "unknown relay {relay:?}"),
            Self::Offline(relay) => write!(f, "relay {relay:?} is offline"),
            Self::Capacity { relay, maximum } => {
                write!(f, "relay {relay:?} reached session capacity {maximum}")
            }
            Self::Impaired { relay, attempt } => {
                write!(
                    f,
                    "relay {relay:?} rejected deterministic attempt {attempt}"
                )
            }
            Self::Connect { relay, details } => {
                write!(f, "relay {relay:?} connection failed: {details}")
            }
            Self::Clock(details) => write!(f, "relay clock failed: {details}"),
        }
    }
}

impl std::error::Error for RelayEnvironmentError {}

/// Monotonic evidence that production relay connection and routing handlers executed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RelayCoverage {
    pub connect_attempts: u64,
    pub authenticated_sessions: u64,
    pub forwarded_packets: u64,
    pub dropped_packets: u64,
}

/// Small deterministic relay-routing oracle used only for differential assertions.
///
/// This model deliberately knows nothing about WebSockets, authentication frames, actors, or
/// QUIC. Consequently, executing it never counts as production relay coverage.
#[derive(Clone, Debug)]
pub struct RelayRoutingOracle {
    relays: BTreeMap<String, OracleRelay>,
}

#[derive(Clone, Debug)]
struct OracleRelay {
    online: bool,
    max_sessions: u64,
    sessions: BTreeMap<String, u64>,
}

/// Admission result shared by the oracle's connection and differential tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayAdmissionDecision {
    Accepted,
    Offline,
    Capacity,
    UnknownRelay,
}

/// Routing result produced without executing any production relay code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayRouteDecision {
    Routed,
    Offline,
    UnknownRelay,
    UnknownSource,
    UnknownDestination,
}

impl RelayRoutingOracle {
    pub fn new(specs: &[RelaySpec]) -> Result<Self, RelayEnvironmentError> {
        let mut relays = BTreeMap::new();
        for spec in specs {
            if spec.id.is_empty() || spec.max_sessions == 0 {
                return Err(RelayEnvironmentError::InvalidSpec(spec.id.clone()));
            }
            if relays
                .insert(
                    spec.id.clone(),
                    OracleRelay {
                        online: spec.online,
                        max_sessions: spec.max_sessions,
                        sessions: BTreeMap::new(),
                    },
                )
                .is_some()
            {
                return Err(RelayEnvironmentError::Duplicate(spec.id.clone()));
            }
        }
        Ok(Self { relays })
    }

    /// Attempts to admit one stable endpoint identity.
    pub fn connect(&mut self, relay: &str, endpoint: &str) -> RelayAdmissionDecision {
        let Some(node) = self.relays.get_mut(relay) else {
            return RelayAdmissionDecision::UnknownRelay;
        };
        if !node.online {
            return RelayAdmissionDecision::Offline;
        }
        let session_count = node.sessions.values().copied().sum::<u64>();
        if session_count >= node.max_sessions {
            return RelayAdmissionDecision::Capacity;
        }
        *node.sessions.entry(endpoint.to_owned()).or_default() += 1;
        RelayAdmissionDecision::Accepted
    }

    /// Applies a lifecycle transition; outages invalidate all admitted sessions.
    pub fn set_online(&mut self, relay: &str, online: bool) -> RelayAdmissionDecision {
        let Some(node) = self.relays.get_mut(relay) else {
            return RelayAdmissionDecision::UnknownRelay;
        };
        node.online = online;
        if !online {
            node.sessions.clear();
        }
        RelayAdmissionDecision::Accepted
    }

    /// Decides whether a frame can route between two identities on one relay.
    pub fn route(&self, relay: &str, source: &str, destination: &str) -> RelayRouteDecision {
        let Some(node) = self.relays.get(relay) else {
            return RelayRouteDecision::UnknownRelay;
        };
        if !node.online {
            return RelayRouteDecision::Offline;
        }
        if !node.sessions.contains_key(source) {
            return RelayRouteDecision::UnknownSource;
        }
        if !node.sessions.contains_key(destination) {
            return RelayRouteDecision::UnknownDestination;
        }
        RelayRouteDecision::Routed
    }

    /// Stable identity inventory for deterministic-order assertions and diagnostics.
    pub fn sessions(&self, relay: &str) -> Option<Vec<&str>> {
        self.relays
            .get(relay)
            .map(|node| node.sessions.keys().map(String::as_str).collect())
    }
}
