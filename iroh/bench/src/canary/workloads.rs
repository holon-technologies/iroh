//! Bounded production workload lanes.

#![forbid(unsafe_code)]

use std::{
    error::Error,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket},
    num::NonZeroUsize,
    path::Path,
    pin::Pin,
    time::{Duration, Instant as StdInstant},
};

use bytes::Bytes;
use http_body_util::Empty;
use hyper::{Request, client::conn::http2::SendRequest};
use hyper_util::rt::{TokioExecutor, TokioIo};
use iroh::{
    Endpoint, EndpointAddr, SecretKey,
    dns::DnsResolver,
    endpoint::{
        CapacitySnapshot, ConnectOptions, ConnectWithOptsError, Connection, EndpointLimits,
        TaskCapacitySnapshot, presets,
    },
};
use iroh_dns_server::{
    Server as DnsServer,
    config::{Config as DnsServerConfig, MetricsConfig, RateLimitConfig},
    test_utils::{RESOURCE_CANARY_UDP_HOLD_DURATION, RESOURCE_CANARY_UDP_HOLD_NAME},
};
use iroh_relay::{
    client::{Client, ClientBuilder, ConnectError},
    protos::relay::{ClientToRelayMsg, RelayToClientMsg},
    server::{
        Limits as RelayLimits, RelayConfig, Server as RelayServer,
        ServerConfig as RelayServerConfig,
    },
    tls::{CaTlsConfig, default_provider},
};
use n0_future::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::{mpsc, oneshot, watch},
    task::JoinSet,
};

use super::{CanaryError, WorkloadConservation, require_loopback};

const CANARY_ALPN: &[u8] = b"iroh/resource-canary/1";
const MAX_ENDPOINT_OFFERED_CONNECTIONS: usize = 4_096;
const MAX_RELAY_PENDING_OFFERED: usize = 512;
const MAX_RELAY_SESSIONS_OFFERED: usize = 8_192;
const MAX_RELAY_CONNECTION_RATE: usize = 10_000;
const MAX_DNS_UDP_OFFERED: usize = 2_048;
const MAX_DNS_UDP_RATE: usize = 10_000;
const MAX_DNS_TCP_OFFERED: usize = 512;
const MAX_DNS_HTTP_CONNECTIONS_OFFERED: usize = 1_024;
const MAX_DNS_HTTP_REQUESTS_OFFERED: usize = 2_048;
const MAX_DNS_HTTP2_STREAMS_PER_CONNECTION: usize = 1_024;
const MINIMUM_ACHIEVED_RATE_PERCENT: u64 = 95;
const MAX_RESOURCE_PHASE_OPERATIONS: usize = 4_096;

type LaneResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
type H2RequestBody = Empty<Bytes>;
type H2RequestSender = SendRequest<H2RequestBody>;
type H2Driver = Pin<Box<dyn Future<Output = LaneResult<()>> + Send>>;

/// Lifecycle phase attached to every retained resource sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LanePhase {
    /// Listener and workload construction before timed pressure.
    Setup,
    /// Initial timed stabilization period at target pressure.
    Warmup,
    /// Primary retained measurement period.
    Measurement,
    /// Final timed observation period before release.
    Cooldown,
    /// Client release, worker drain, and server shutdown.
    Shutdown,
}

impl LanePhase {
    /// Stable artifact label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::Warmup => "warmup",
            Self::Measurement => "measurement",
            Self::Cooldown => "cooldown",
            Self::Shutdown => "shutdown",
        }
    }
}

/// Bounded last-known accounting retained while one lane is running.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LaneProgress {
    /// Attempts launched by the harness.
    pub offered: usize,
    /// Attempts admitted by the production boundary.
    pub admitted: usize,
    /// Attempts rejected by the production boundary.
    pub rejected: usize,
    /// Attempts that failed before a classified admission result.
    pub transport_failed: usize,
    /// Resources currently retained by the harness.
    pub active: usize,
    /// Largest retained-resource count observed so far.
    pub high_water: usize,
}

/// Last-known phase and bounded workload accounting for one lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaneState {
    /// Current lifecycle phase.
    pub phase: LanePhase,
    /// Latest workload counters.
    pub progress: LaneProgress,
}

impl Default for LaneState {
    fn default() -> Self {
        Self {
            phase: LanePhase::Setup,
            progress: LaneProgress::default(),
        }
    }
}

/// Shared phase and progress signal for one monitored lane.
#[derive(Clone, Debug)]
pub struct PhaseReporter {
    sender: watch::Sender<LaneState>,
}

impl PhaseReporter {
    /// Creates one reporter and its sampling receiver.
    pub fn new() -> (Self, watch::Receiver<LaneState>) {
        let (sender, receiver) = watch::channel(LaneState::default());
        (Self { sender }, receiver)
    }

    fn enter(&self, phase: LanePhase) {
        let mut state = *self.sender.borrow();
        state.phase = phase;
        self.sender.send_replace(state);
    }

    fn record(&self, progress: LaneProgress) {
        let mut state = *self.sender.borrow();
        state.progress = progress;
        self.sender.send_replace(state);
    }
}

/// Validated warm-up, measurement, and cooldown durations for one workload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaneTiming {
    warmup: Duration,
    measurement: Duration,
    cooldown: Duration,
    total: Duration,
}

impl LaneTiming {
    /// Creates nonzero timed phases.
    pub fn new(
        warmup: Duration,
        measurement: Duration,
        cooldown: Duration,
    ) -> Result<Self, CanaryError> {
        for (field, duration) in [
            ("warmup", warmup),
            ("measurement", measurement),
            ("cooldown", cooldown),
        ] {
            if duration.is_zero() {
                return Err(CanaryError::ZeroDuration { field });
            }
        }
        let total = warmup
            .checked_add(measurement)
            .and_then(|duration| duration.checked_add(cooldown))
            .ok_or(CanaryError::ArithmeticOverflow)?;
        Ok(Self {
            warmup,
            measurement,
            cooldown,
            total,
        })
    }

    /// Total duration across all timed phases.
    pub const fn total(self) -> Duration {
        self.total
    }
}

/// Bounded operation latency distribution in microseconds.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LatencySummary {
    /// Number of retained latency observations.
    pub samples: usize,
    /// Median latency.
    pub p50_micros: u64,
    /// 95th percentile latency.
    pub p95_micros: u64,
    /// 99th percentile latency.
    pub p99_micros: u64,
    /// Largest observed latency.
    pub maximum_micros: u64,
}

#[derive(Debug)]
struct LatencyAccumulator {
    values_micros: Vec<u64>,
    maximum_samples: usize,
}

impl LatencyAccumulator {
    fn new(maximum_samples: usize) -> Self {
        Self {
            values_micros: Vec::with_capacity(maximum_samples),
            maximum_samples,
        }
    }

    fn record(&mut self, latency: Duration) -> LaneResult<()> {
        if self.values_micros.len() >= self.maximum_samples {
            return Err(lane_error(format!(
                "latency sample count exceeds maximum {}",
                self.maximum_samples
            )));
        }
        let micros = u64::try_from(latency.as_micros())
            .map_err(|_| lane_error("latency is out of range"))?;
        self.values_micros.push(micros);
        Ok(())
    }

    fn finish(mut self) -> LaneResult<LatencySummary> {
        if self.values_micros.is_empty() {
            return Ok(LatencySummary::default());
        }
        self.values_micros.sort_unstable();
        let samples = self.values_micros.len();
        Ok(LatencySummary {
            samples,
            p50_micros: percentile(&self.values_micros, 50)?,
            p95_micros: percentile(&self.values_micros, 95)?,
            p99_micros: percentile(&self.values_micros, 99)?,
            maximum_micros: *self
                .values_micros
                .last()
                .ok_or_else(|| lane_error("nonempty latency samples must have a maximum"))?,
        })
    }
}

fn percentile(sorted: &[u64], percentile: usize) -> LaneResult<u64> {
    let rank = sorted
        .len()
        .checked_mul(percentile)
        .and_then(|value| value.checked_add(99))
        .map(|value| value / 100)
        .ok_or_else(|| lane_error("latency percentile rank overflowed"))?;
    let index = rank
        .checked_sub(1)
        .ok_or_else(|| lane_error("latency percentile rank must be nonzero"))?;
    sorted
        .get(index)
        .copied()
        .ok_or_else(|| lane_error("latency percentile index is out of range"))
}

/// Retained absolute-deadline arrival-rate evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ArrivalSummary {
    /// Configured attempt rate.
    pub target_per_second: usize,
    /// Attempts launched against absolute deadlines.
    pub attempts: usize,
    /// Elapsed launch window from the first through final attempt.
    pub elapsed_micros: u64,
    /// Achieved launches per second, scaled by 1,000.
    pub achieved_per_second_milli: u64,
    /// Largest observed delay after an absolute launch deadline.
    pub maximum_schedule_lag_micros: u64,
}

#[derive(Debug)]
struct ScheduleTracker {
    started: tokio::time::Instant,
    rate_per_second: NonZeroUsize,
    attempts: usize,
    last_launch_elapsed: Duration,
    maximum_lag: Duration,
}

impl ScheduleTracker {
    fn new(rate_per_second: NonZeroUsize) -> Self {
        Self {
            started: tokio::time::Instant::now(),
            rate_per_second,
            attempts: 0,
            last_launch_elapsed: Duration::ZERO,
            maximum_lag: Duration::ZERO,
        }
    }

    async fn wait_for_attempt(&mut self) -> LaneResult<()> {
        let ordinal = self.attempts;
        let deadline_nanos = ordinal
            .checked_mul(1_000_000_000)
            .map(|value| value / self.rate_per_second.get())
            .ok_or_else(|| lane_error("arrival deadline overflowed"))?;
        let deadline = self
            .started
            .checked_add(Duration::from_nanos(
                u64::try_from(deadline_nanos)
                    .map_err(|_| lane_error("arrival deadline is out of range"))?,
            ))
            .ok_or_else(|| lane_error("arrival deadline overflowed"))?;
        tokio::time::sleep_until(deadline).await;
        let now = tokio::time::Instant::now();
        self.last_launch_elapsed = now.duration_since(self.started);
        self.maximum_lag = self
            .maximum_lag
            .max(now.saturating_duration_since(deadline));
        self.attempts = checked_increment(self.attempts, "scheduled arrival")?;
        Ok(())
    }

    fn finish(self) -> LaneResult<ArrivalSummary> {
        let elapsed_micros = u64::try_from(self.last_launch_elapsed.as_micros())
            .map_err(|_| lane_error("arrival elapsed time is out of range"))?;
        let maximum_schedule_lag_micros = u64::try_from(self.maximum_lag.as_micros())
            .map_err(|_| lane_error("arrival lag is out of range"))?;
        let achieved_per_second_milli = if self.attempts <= 1 {
            u64::try_from(self.rate_per_second.get())
                .map_err(|_| lane_error("arrival rate is out of range"))?
                .checked_mul(1_000)
                .ok_or_else(|| lane_error("arrival rate overflowed"))?
        } else {
            let intervals = u64::try_from(self.attempts - 1)
                .map_err(|_| lane_error("arrival attempt count is out of range"))?;
            let elapsed_nanos = u64::try_from(self.last_launch_elapsed.as_nanos())
                .map_err(|_| lane_error("arrival elapsed time is out of range"))?
                .max(1);
            intervals
                .checked_mul(1_000_000_000)
                .and_then(|value| value.checked_mul(1_000))
                .map(|value| value / elapsed_nanos)
                .ok_or_else(|| lane_error("achieved arrival rate overflowed"))?
        };
        let target = u64::try_from(self.rate_per_second.get())
            .map_err(|_| lane_error("arrival rate is out of range"))?;
        let minimum = target
            .checked_mul(1_000)
            .and_then(|value| value.checked_mul(MINIMUM_ACHIEVED_RATE_PERCENT))
            .map(|value| value / 100)
            .ok_or_else(|| lane_error("minimum arrival rate overflowed"))?;
        if self.attempts >= 20 && achieved_per_second_milli < minimum {
            return Err(lane_error(format!(
                "achieved arrival rate {achieved_per_second_milli} milli-attempts/s is below required {minimum}"
            )));
        }
        Ok(ArrivalSummary {
            target_per_second: self.rate_per_second.get(),
            attempts: self.attempts,
            elapsed_micros,
            achieved_per_second_milli,
            maximum_schedule_lag_micros,
        })
    }
}

/// Validated endpoint admission workload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointLaneConfig {
    capacity: NonZeroUsize,
    offered: NonZeroUsize,
    timing: LaneTiming,
    operation_timeout: Duration,
}

impl EndpointLaneConfig {
    /// Creates a bounded endpoint lane.
    pub fn new(
        capacity: NonZeroUsize,
        offered: NonZeroUsize,
        timing: LaneTiming,
        operation_timeout: Duration,
    ) -> Result<Self, CanaryError> {
        if offered.get() <= capacity.get() {
            return Err(CanaryError::InvalidOfferedLoad {
                offered: offered.get(),
                capacity: capacity.get(),
            });
        }
        if offered.get() > MAX_ENDPOINT_OFFERED_CONNECTIONS {
            return Err(CanaryError::WorkloadTooLarge {
                field: "endpoint_connections",
                requested: offered.get(),
                maximum: MAX_ENDPOINT_OFFERED_CONNECTIONS,
            });
        }
        if operation_timeout.is_zero() {
            return Err(CanaryError::ZeroDuration {
                field: "operation_timeout",
            });
        }
        Ok(Self {
            capacity,
            offered,
            timing,
            operation_timeout,
        })
    }
}

/// Retained endpoint admission and shutdown evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointLaneOutcome {
    /// Total connection attempts.
    pub offered: usize,
    /// Connections retained during measurement.
    pub accepted: usize,
    /// Locally rejected excess attempts.
    pub rejected: usize,
    /// Exact initial connection-attempt accounting.
    pub initial_conservation: WorkloadConservation,
    /// Whether one released slot admitted a replacement.
    pub recovered: bool,
    /// Successful initial connection latency.
    pub accepted_connection_latency: LatencySummary,
    /// Rejected initial connection-attempt latency.
    pub rejected_connection_latency: LatencySummary,
    /// Successful replacement operations during timed pressure.
    pub continuity_successes: usize,
    /// Capacity rejections observed during timed pressure.
    pub continuity_rejections: usize,
    /// Successful replacement latency during timed pressure.
    pub continuity_success_latency: LatencySummary,
    /// Rejection latency during timed pressure.
    pub continuity_rejection_latency: LatencySummary,
    /// Endpoint admission ledger.
    pub admission: CapacitySnapshot,
    /// Client endpoint live-task capacity.
    pub client_tasks: TaskCapacitySnapshot,
    /// Server endpoint live-task capacity.
    pub server_tasks: TaskCapacitySnapshot,
    /// Client endpoint Noq queue diagnostics.
    pub client_noq: noq::EventQueueStats,
    /// Server endpoint Noq queue diagnostics.
    pub server_noq: noq::EventQueueStats,
    /// Measured endpoint shutdown time.
    pub shutdown: Duration,
}

/// Saturates the endpoint connection ledger at a bounded offered load.
pub async fn run_endpoint_lane(
    config: EndpointLaneConfig,
    phases: PhaseReporter,
) -> LaneResult<EndpointLaneOutcome> {
    let limits = EndpointLimits::default().with_max_connections(config.capacity);
    let server = bind_loopback_endpoint(limits, true).await?;
    let client = match bind_loopback_endpoint(limits, false).await {
        Ok(client) => client,
        Err(error) => {
            tokio::time::timeout(config.operation_timeout, server.close())
                .await
                .map_err(|_| lane_error("endpoint setup cleanup timed out"))?;
            return Err(error);
        }
    };
    let result = run_endpoint_lane_body(config, phases.clone(), &server, &client).await;
    if result.is_err() {
        phases.enter(LanePhase::Shutdown);
        tokio::time::timeout(config.operation_timeout, async {
            tokio::join!(client.close(), server.close());
        })
        .await
        .map_err(|_| lane_error("endpoint failure cleanup timed out"))?;
    }
    result
}

async fn run_endpoint_lane_body(
    config: EndpointLaneConfig,
    phases: PhaseReporter,
    server: &Endpoint,
    client: &Endpoint,
) -> LaneResult<EndpointLaneOutcome> {
    let bound = *server
        .bound_sockets()
        .first()
        .ok_or_else(|| lane_error("endpoint server did not bind a socket"))?;
    require_loopback(bound)?;
    let server_addr = EndpointAddr::new(server.id()).with_ip_addr(bound);

    let mut connections = Vec::with_capacity(config.capacity.get());
    let mut rejected = 0usize;
    let mut accepted_latency = LatencyAccumulator::new(config.capacity.get());
    let rejected_capacity = config
        .offered
        .get()
        .checked_sub(config.capacity.get())
        .ok_or_else(|| lane_error("endpoint rejected-connection capacity underflowed"))?;
    let mut rejected_latency = LatencyAccumulator::new(rejected_capacity);
    for attempt in 0..config.offered.get() {
        if attempt < config.capacity.get() {
            let started = StdInstant::now();
            let pair = tokio::time::timeout(
                config.operation_timeout,
                connect_pair(client, server, server_addr.clone()),
            )
            .await
            .map_err(|_| lane_error("endpoint connection attempt timed out"))??;
            accepted_latency.record(started.elapsed())?;
            connections.push(pair);
            continue;
        }

        let started = StdInstant::now();
        let result = tokio::time::timeout(
            config.operation_timeout,
            client.connect_with_opts(server_addr.clone(), CANARY_ALPN, ConnectOptions::default()),
        )
        .await
        .map_err(|_| lane_error("endpoint rejection attempt timed out"))?;
        rejected_latency.record(started.elapsed())?;
        match result {
            Err(ConnectWithOptsError::ConnectionCapacityFull { .. }) => {
                rejected = rejected
                    .checked_add(1)
                    .ok_or_else(|| lane_error("endpoint rejection counter overflowed"))?;
            }
            Err(error) => {
                return Err(lane_error(format!(
                    "unexpected endpoint rejection at attempt {attempt}: {error}"
                )));
            }
            Ok(_) => {
                return Err(lane_error(format!(
                    "endpoint admitted attempt {attempt} above capacity {}",
                    config.capacity
                )));
            }
        }
    }
    phases.record(LaneProgress {
        offered: config.offered.get(),
        admitted: connections.len(),
        rejected,
        transport_failed: 0,
        active: connections.len(),
        high_water: connections.len(),
    });

    let mut continuity_success_latency = LatencyAccumulator::new(MAX_RESOURCE_PHASE_OPERATIONS);
    let mut continuity_rejection_latency = LatencyAccumulator::new(MAX_RESOURCE_PHASE_OPERATIONS);
    let (continuity_successes, continuity_rejections) = run_endpoint_phases(
        config,
        &phases,
        client,
        server,
        &server_addr,
        &mut connections,
        &mut continuity_success_latency,
        &mut continuity_rejection_latency,
    )
    .await?;
    phases.enter(LanePhase::Shutdown);

    let admission = client.connection_capacity_snapshot();
    let client_tasks = client.task_capacity_snapshot();
    let server_tasks = server.task_capacity_snapshot();
    let client_noq = client.noq_event_queue_stats();
    let server_noq = server.noq_event_queue_stats();
    let shutdown_started = StdInstant::now();
    tokio::time::timeout(config.operation_timeout, async {
        for (client_connection, server_connection) in connections {
            client_connection.close(0u8.into(), b"resource canary complete");
            server_connection.close(0u8.into(), b"resource canary complete");
        }
        tokio::join!(client.close(), server.close());
    })
    .await
    .map_err(|_| lane_error("endpoint whole-lane shutdown timed out"))?;
    let shutdown = shutdown_started.elapsed();
    let initial_conservation =
        WorkloadConservation::new(config.offered.get(), config.capacity.get(), rejected, 0)?;

    Ok(EndpointLaneOutcome {
        offered: config.offered.get(),
        accepted: config.capacity.get(),
        rejected,
        initial_conservation,
        recovered: continuity_successes > 0,
        accepted_connection_latency: accepted_latency.finish()?,
        rejected_connection_latency: rejected_latency.finish()?,
        continuity_successes,
        continuity_rejections,
        continuity_success_latency: continuity_success_latency.finish()?,
        continuity_rejection_latency: continuity_rejection_latency.finish()?,
        admission,
        client_tasks,
        server_tasks,
        client_noq,
        server_noq,
        shutdown,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "phase continuity retains explicit ownership and bounded accumulators"
)]
async fn run_endpoint_phases(
    config: EndpointLaneConfig,
    phases: &PhaseReporter,
    client: &Endpoint,
    server: &Endpoint,
    server_addr: &EndpointAddr,
    connections: &mut Vec<(Connection, Connection)>,
    success_latency: &mut LatencyAccumulator,
    rejection_latency: &mut LatencyAccumulator,
) -> LaneResult<(usize, usize)> {
    let mut successes = 0usize;
    let mut rejections = 0usize;
    for (phase, duration) in [
        (LanePhase::Warmup, config.timing.warmup),
        (LanePhase::Measurement, config.timing.measurement),
        (LanePhase::Cooldown, config.timing.cooldown),
    ] {
        phases.enter(phase);
        let deadline = tokio::time::Instant::now()
            .checked_add(duration)
            .ok_or_else(|| lane_error("endpoint phase deadline overflowed"))?;
        while tokio::time::Instant::now() < deadline {
            let (released_client, released_server) = connections
                .pop()
                .ok_or_else(|| lane_error("endpoint continuity requires an accepted connection"))?;
            released_client.close(0u8.into(), b"resource canary continuity");
            released_server.close(0u8.into(), b"resource canary continuity");
            drop(released_client);
            drop(released_server);
            wait_for_condition(
                config.operation_timeout,
                "endpoint continuity release",
                || {
                    client.connection_capacity_snapshot().current < config.capacity.get()
                        && server.connection_capacity_snapshot().current < config.capacity.get()
                },
            )
            .await?;

            let started = StdInstant::now();
            let replacement = tokio::time::timeout(
                config.operation_timeout,
                connect_pair(client, server, server_addr.clone()),
            )
            .await
            .map_err(|_| lane_error("endpoint continuity connection timed out"))??;
            success_latency.record(started.elapsed())?;
            connections.push(replacement);
            successes = checked_increment(successes, "endpoint continuity success")?;

            let started = StdInstant::now();
            let rejection = tokio::time::timeout(
                config.operation_timeout,
                client.connect_with_opts(
                    server_addr.clone(),
                    CANARY_ALPN,
                    ConnectOptions::default(),
                ),
            )
            .await
            .map_err(|_| lane_error("endpoint continuity rejection timed out"))?;
            rejection_latency.record(started.elapsed())?;
            match rejection {
                Err(ConnectWithOptsError::ConnectionCapacityFull { .. }) => {
                    rejections = checked_increment(rejections, "endpoint continuity rejection")?;
                }
                Err(error) => {
                    return Err(lane_error(format!(
                        "unexpected endpoint continuity rejection: {error}"
                    )));
                }
                Ok(connecting) => {
                    drop(connecting);
                    return Err(lane_error(
                        "endpoint admitted continuity overload above capacity",
                    ));
                }
            }
            phases.record(LaneProgress {
                offered: config
                    .offered
                    .get()
                    .checked_add(rejections)
                    .ok_or_else(|| lane_error("endpoint progress offered count overflowed"))?,
                admitted: config.capacity.get(),
                rejected: config
                    .offered
                    .get()
                    .checked_sub(config.capacity.get())
                    .and_then(|value| value.checked_add(rejections))
                    .ok_or_else(|| lane_error("endpoint progress rejection count overflowed"))?,
                transport_failed: 0,
                active: connections.len(),
                high_water: config.capacity.get(),
            });
            let next = tokio::time::Instant::now()
                .checked_add(Duration::from_secs(1))
                .ok_or_else(|| lane_error("endpoint continuity deadline overflowed"))?
                .min(deadline);
            tokio::time::sleep_until(next).await;
        }
    }
    Ok((successes, rejections))
}

async fn bind_loopback_endpoint(
    limits: EndpointLimits,
    accept_connections: bool,
) -> LaneResult<Endpoint> {
    let mut builder = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .clear_relay_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, 0))?
        .limits(limits);
    if accept_connections {
        builder = builder.alpns(vec![CANARY_ALPN.to_vec()]);
    }
    Ok(builder.bind().await?)
}

async fn connect_pair(
    client: &Endpoint,
    server: &Endpoint,
    server_addr: EndpointAddr,
) -> LaneResult<(Connection, Connection)> {
    let outgoing = client.connect(server_addr, CANARY_ALPN);
    let incoming = async {
        let incoming = server
            .accept()
            .await
            .ok_or_else(|| lane_error("endpoint closed before accepting connection"))?;
        incoming
            .await
            .map_err(|error| lane_error(format!("incoming endpoint handshake failed: {error}")))
    };
    let (outgoing, incoming) = tokio::join!(outgoing, incoming);
    let outgoing = outgoing
        .map_err(|error| lane_error(format!("outgoing endpoint handshake failed: {error}")))?;
    let incoming = incoming?;
    Ok((outgoing, incoming))
}

fn lane_error(message: impl Into<String>) -> Box<dyn Error + Send + Sync> {
    Box::new(io::Error::other(message.into()))
}

/// Validated relay pending-establishment and session workload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayLaneConfig {
    pending_capacity: NonZeroUsize,
    session_capacity: NonZeroUsize,
    sessions_per_identity: NonZeroUsize,
    pending_offered: NonZeroUsize,
    sessions_offered: NonZeroUsize,
    fill_rate_per_second: NonZeroUsize,
    overload_rate_per_second: NonZeroUsize,
    accept_burst: NonZeroUsize,
    timing: LaneTiming,
    operation_timeout: Duration,
}

impl RelayLaneConfig {
    /// Creates a bounded relay workload.
    #[allow(
        clippy::too_many_arguments,
        reason = "all independent production bounds stay explicit"
    )]
    pub fn new(
        pending_capacity: NonZeroUsize,
        session_capacity: NonZeroUsize,
        sessions_per_identity: NonZeroUsize,
        pending_offered: NonZeroUsize,
        sessions_offered: NonZeroUsize,
        fill_rate_per_second: NonZeroUsize,
        overload_rate_per_second: NonZeroUsize,
        accept_burst: NonZeroUsize,
        timing: LaneTiming,
        operation_timeout: Duration,
    ) -> Result<Self, CanaryError> {
        validate_offered(
            pending_offered,
            pending_capacity,
            "relay_pending_establishments",
        )?;
        validate_offered(sessions_offered, session_capacity, "relay_sessions")?;
        validate_maximum(
            pending_offered,
            MAX_RELAY_PENDING_OFFERED,
            "relay_pending_establishments",
        )?;
        validate_maximum(
            sessions_offered,
            MAX_RELAY_SESSIONS_OFFERED,
            "relay_sessions",
        )?;
        validate_maximum(
            fill_rate_per_second,
            MAX_RELAY_CONNECTION_RATE,
            "relay_fill_rate_per_second",
        )?;
        validate_maximum(
            overload_rate_per_second,
            MAX_RELAY_CONNECTION_RATE,
            "relay_overload_rate_per_second",
        )?;
        if sessions_per_identity.get() > session_capacity.get() {
            return Err(CanaryError::WorkloadTooLarge {
                field: "relay_sessions_per_identity",
                requested: sessions_per_identity.get(),
                maximum: session_capacity.get(),
            });
        }
        if operation_timeout.is_zero() {
            return Err(CanaryError::ZeroDuration {
                field: "operation_timeout",
            });
        }
        Ok(Self {
            pending_capacity,
            session_capacity,
            sessions_per_identity,
            pending_offered,
            sessions_offered,
            fill_rate_per_second,
            overload_rate_per_second,
            accept_burst,
            timing,
            operation_timeout,
        })
    }
}

fn validate_offered(
    offered: NonZeroUsize,
    capacity: NonZeroUsize,
    _field: &'static str,
) -> Result<(), CanaryError> {
    if offered.get() <= capacity.get() {
        return Err(CanaryError::InvalidOfferedLoad {
            offered: offered.get(),
            capacity: capacity.get(),
        });
    }
    Ok(())
}

fn validate_maximum(
    value: NonZeroUsize,
    maximum: usize,
    field: &'static str,
) -> Result<(), CanaryError> {
    if value.get() > maximum {
        return Err(CanaryError::WorkloadTooLarge {
            field,
            requested: value.get(),
            maximum,
        });
    }
    Ok(())
}

fn validate_schedule_within_hold(
    attempts: NonZeroUsize,
    rate_per_second: NonZeroUsize,
    hold: Duration,
    field: &'static str,
) -> Result<(), CanaryError> {
    let intervals =
        u128::try_from(attempts.get() - 1).map_err(|_| CanaryError::ArithmeticOverflow)?;
    let rate =
        u128::try_from(rate_per_second.get()).map_err(|_| CanaryError::ArithmeticOverflow)?;
    let last_launch_nanos = intervals
        .checked_mul(1_000_000_000)
        .map(|value| value / rate)
        .ok_or(CanaryError::ArithmeticOverflow)?;
    if last_launch_nanos >= hold.as_nanos() {
        return Err(CanaryError::ArrivalWindowTooLong { field });
    }
    Ok(())
}

/// Retained relay admission and shutdown evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayLaneOutcome {
    /// Raw TCP connections offered to pending establishment admission.
    pub pending_offered: usize,
    /// Pending-establishment capacity rejections.
    pub pending_rejections: u64,
    /// Pending-establishment connection-rate rejections.
    pub pending_rate_rejections: u64,
    /// Exact pending-establishment admission accounting.
    pub pending_conservation: WorkloadConservation,
    /// Authenticated relay sessions offered.
    pub sessions_offered: usize,
    /// Sessions retained during measurement.
    pub sessions_accepted: usize,
    /// Session attempts rejected during overload.
    pub sessions_rejected: usize,
    /// Exact initial authenticated-session accounting.
    pub session_conservation: WorkloadConservation,
    /// Largest observed registered-session count.
    pub session_high_water: usize,
    /// Per-identity session-capacity rejections.
    pub endpoint_session_rejections: u64,
    /// Global session-capacity rejections.
    pub global_session_rejections: u64,
    /// Pending-establishment rejections during session campaigns.
    pub session_pending_rejections: u64,
    /// Global connection-rate rejections across both relay phases.
    pub rate_rejections: u64,
    /// Whether one released session admitted a replacement.
    pub recovered: bool,
    /// Successful relay session-establishment latency.
    pub accepted_session_latency: LatencySummary,
    /// Rejected relay session-attempt latency.
    pub rejected_session_latency: LatencySummary,
    /// Absolute-deadline fill arrival evidence.
    pub fill_arrival: ArrivalSummary,
    /// Absolute-deadline per-identity overload arrival evidence.
    pub identity_overload_arrival: ArrivalSummary,
    /// Absolute-deadline overload arrival evidence.
    pub overload_arrival: ArrivalSummary,
    /// Client-visible results for every initial overload attempt.
    pub rejection_client_outcomes: RelayClientOutcomeCounts,
    /// Client-visible results for timed overload attempts.
    pub continuity_client_outcomes: RelayClientOutcomeCounts,
    /// Successful relay pings during timed pressure.
    pub continuity_successes: usize,
    /// Capacity rejections during timed pressure.
    pub continuity_rejections: usize,
    /// Relay ping latency during timed pressure.
    pub continuity_success_latency: LatencySummary,
    /// Rejected session latency during timed pressure.
    pub continuity_rejection_latency: LatencySummary,
    /// Measured relay shutdown time.
    pub shutdown: Duration,
}

/// Client-visible relay establishment results backed by server admission counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RelayClientOutcomeCounts {
    /// Connections whose HTTP upgrade completed before the server closed the session.
    pub connected_then_rejected: usize,
    /// Connections rejected with HTTP 429.
    pub rate_limited: usize,
    /// Connections closed after upgrade while server admission rejected the session.
    pub protocol_closed: usize,
    /// Connections that exceeded the operation deadline.
    pub timed_out: usize,
}

impl RelayClientOutcomeCounts {
    /// Returns the checked total across all client-visible classes.
    pub fn total(self) -> Result<usize, CanaryError> {
        self.connected_then_rejected
            .checked_add(self.rate_limited)
            .and_then(|value| value.checked_add(self.protocol_closed))
            .and_then(|value| value.checked_add(self.timed_out))
            .ok_or(CanaryError::ArithmeticOverflow)
    }
}

/// Saturates relay pending and authenticated-session admission at bounded load.
pub async fn run_relay_lane(
    config: RelayLaneConfig,
    phases: PhaseReporter,
) -> LaneResult<RelayLaneOutcome> {
    let mut relay_config = RelayConfig::new((Ipv4Addr::LOCALHOST, 0));
    let mut limits = RelayLimits::default();
    let accept_rate = u32::try_from(config.fill_rate_per_second.get())
        .map_err(|_| lane_error("relay accept rate is out of range"))?;
    limits.accept_conn_limit = Some(f64::from(accept_rate));
    limits.accept_conn_burst = Some(config.accept_burst.get());
    limits.max_pending_establishments = config.pending_capacity.get();
    limits.max_registered_sessions = config.session_capacity.get();
    limits.max_sessions_per_endpoint = config.sessions_per_identity.get();
    relay_config.limits = limits;
    let mut server_config = RelayServerConfig::default();
    server_config.relay = Some(relay_config);
    let server = RelayServer::spawn(server_config).await?;
    let result = run_relay_lane_body(config, phases.clone(), &server).await;
    let shutdown_started = result
        .as_ref()
        .map(|(_, started)| *started)
        .unwrap_or_else(|_| {
            phases.enter(LanePhase::Shutdown);
            StdInstant::now()
        });
    let remaining = config
        .operation_timeout
        .checked_sub(shutdown_started.elapsed())
        .unwrap_or(Duration::from_millis(1));
    let shutdown_result = tokio::time::timeout(remaining, server.shutdown())
        .await
        .map_err(|_| lane_error("relay server shutdown timed out"))
        .and_then(|result| result.map_err(|error| lane_error(error.to_string())));
    match (result, shutdown_result) {
        (Ok((mut outcome, started)), Ok(())) => {
            outcome.shutdown = started.elapsed();
            if outcome.shutdown > config.operation_timeout {
                return Err(lane_error("relay whole-lane shutdown deadline exhausted"));
            }
            Ok(outcome)
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(workload), Err(shutdown)) => Err(lane_error(format!(
            "{workload}; relay cleanup also failed: {shutdown}"
        ))),
    }
}

async fn run_relay_lane_body(
    config: RelayLaneConfig,
    phases: PhaseReporter,
    server: &RelayServer,
) -> LaneResult<(RelayLaneOutcome, StdInstant)> {
    let server_addr = server
        .http_addr()
        .ok_or_else(|| lane_error("relay did not bind an HTTP address"))?;
    require_loopback(server_addr)?;
    let relay_url = server
        .http_url()
        .ok_or_else(|| lane_error("relay did not publish an HTTP URL"))?;
    let metrics = server.metrics().server.clone();

    let pending_before = metrics.admission_pending_full.get();
    let rate_before_pending = metrics.admission_rate_limited.get();
    let mut pending_tasks = JoinSet::new();
    for _ in 0..config.pending_offered.get() {
        pending_tasks.spawn(async move {
            tokio::time::timeout(config.operation_timeout, TcpStream::connect(server_addr))
                .await
                .map_err(|_| lane_error("relay pending-establishment connect timed out"))?
                .map_err(|error| {
                    lane_error(format!(
                        "relay pending-establishment connect failed: {error}"
                    ))
                })
        });
    }
    let mut pending_sockets = Vec::with_capacity(config.pending_offered.get());
    while let Some(result) = pending_tasks.join_next().await {
        pending_sockets.push(
            result.map_err(|error| lane_error(format!("relay pending task failed: {error}")))??,
        );
    }
    let expected_pending_rejections = config
        .pending_offered
        .get()
        .checked_sub(config.pending_capacity.get())
        .ok_or_else(|| lane_error("relay pending rejection target underflowed"))?;
    wait_for_condition(
        config.operation_timeout,
        "exact relay pending overload",
        || {
            pending_rejection_total(&metrics, pending_before, rate_before_pending)
                .is_ok_and(|count| usize::try_from(count) == Ok(expected_pending_rejections))
        },
    )
    .await?;
    let pending_rejections = metrics
        .admission_pending_full
        .get()
        .checked_sub(pending_before)
        .ok_or_else(|| lane_error("relay pending rejection counter regressed"))?;
    let pending_rate_rejections = metrics
        .admission_rate_limited
        .get()
        .checked_sub(rate_before_pending)
        .ok_or_else(|| lane_error("relay pending rate rejection counter regressed"))?;
    let pending_rejected = usize::try_from(
        pending_rejections
            .checked_add(pending_rate_rejections)
            .ok_or_else(|| lane_error("relay pending rejection count overflowed"))?,
    )
    .map_err(|_| lane_error("relay pending rejection count is out of range"))?;
    let pending_conservation = WorkloadConservation::new(
        config.pending_offered.get(),
        config.pending_capacity.get(),
        pending_rejected,
        0,
    )?;
    phases.record(LaneProgress {
        offered: config.pending_offered.get(),
        admitted: config.pending_capacity.get(),
        rejected: pending_rejected,
        transport_failed: 0,
        active: config.pending_capacity.get(),
        high_water: config.pending_capacity.get(),
    });
    drop(pending_sockets);
    let refill_millis = config
        .accept_burst
        .get()
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(config.fill_rate_per_second.get() - 1))
        .map(|value| value / config.fill_rate_per_second.get())
        .and_then(|value| value.checked_add(50))
        .ok_or_else(|| lane_error("relay token refill duration overflowed"))?;
    tokio::time::sleep(Duration::from_millis(
        u64::try_from(refill_millis)
            .map_err(|_| lane_error("relay token refill duration is out of range"))?,
    ))
    .await;
    let rate_before_sessions = metrics.admission_rate_limited.get();
    let pending_before_sessions = metrics.admission_pending_full.get();

    let tls_config = CaTlsConfig::default().client_config(default_provider())?;
    let mut client_drivers = JoinSet::new();
    let mut clients = Vec::with_capacity(config.session_capacity.get());
    let mut high_water = 0usize;
    let mut accepted_latency = LatencyAccumulator::new(config.session_capacity.get());
    let rejected_capacity = config
        .sessions_offered
        .get()
        .checked_sub(config.session_capacity.get())
        .ok_or_else(|| lane_error("relay rejected-session capacity underflowed"))?;
    let mut rejected_latency = LatencyAccumulator::new(rejected_capacity);

    let mut fill_schedule = ScheduleTracker::new(config.fill_rate_per_second);
    for _ in 0..config.sessions_per_identity.get() {
        fill_schedule.wait_for_attempt().await?;
        let started = StdInstant::now();
        let client = connect_relay_client(
            relay_url.clone(),
            deterministic_secret(0)?,
            tls_config.clone(),
            config.operation_timeout,
        )
        .await
        .map_err(|error| lane_error(error.to_string()))?;
        accepted_latency.record(started.elapsed())?;
        clients.push(RetainedRelayClient::new(
            client,
            config.operation_timeout,
            &mut client_drivers,
        ));
        high_water = high_water.max(relay_connection_count(server)?);
    }

    let endpoint_rejections_before = metrics.admission_endpoint_session_full.get();
    let mut identity_overload_schedule = ScheduleTracker::new(config.overload_rate_per_second);
    identity_overload_schedule.wait_for_attempt().await?;
    let started = StdInstant::now();
    let duplicate = connect_relay_client(
        relay_url.clone(),
        deterministic_secret(0)?,
        tls_config.clone(),
        config.operation_timeout,
    )
    .await;
    rejected_latency.record(started.elapsed())?;
    let identity_overload_arrival = identity_overload_schedule.finish()?;
    let mut rejection_client_outcomes = RelayClientOutcomeCounts::default();
    let duplicate_client = record_relay_client_outcome(&mut rejection_client_outcomes, duplicate)?;
    wait_for_condition(
        config.operation_timeout,
        "relay per-identity rejection",
        || {
            metrics.admission_endpoint_session_full.get() > endpoint_rejections_before
                && relay_connection_count(server)
                    .map(|count| count == config.sessions_per_identity.get())
                    .unwrap_or(false)
        },
    )
    .await?;
    drop(duplicate_client);

    let remaining_fill = config
        .session_capacity
        .get()
        .checked_sub(clients.len())
        .ok_or_else(|| lane_error("relay accepted-session accounting regressed"))?;
    let mut fill_tasks = JoinSet::new();
    for ordinal in 0..remaining_fill {
        fill_schedule.wait_for_attempt().await?;
        let identity = 1usize
            .checked_add(ordinal / config.sessions_per_identity.get())
            .ok_or_else(|| lane_error("relay identity index overflowed"))?;
        let relay_url = relay_url.clone();
        let tls_config = tls_config.clone();
        fill_tasks.spawn(async move {
            let started = StdInstant::now();
            let result = connect_relay_client(
                relay_url,
                deterministic_secret(identity)?,
                tls_config,
                config.operation_timeout,
            )
            .await;
            Ok::<_, Box<dyn Error + Send + Sync>>((started.elapsed(), result))
        });
        while let Some(result) = fill_tasks.try_join_next() {
            let (latency, client) = result
                .map_err(|error| lane_error(format!("relay fill task failed: {error}")))??;
            retain_relay_fill_client(
                latency,
                client,
                config.operation_timeout,
                &mut accepted_latency,
                &mut clients,
                &mut client_drivers,
            )?;
        }
        ensure_relay_client_drivers_running(&mut client_drivers)?;
    }
    while let Some(result) = fill_tasks.join_next().await {
        let (latency, client) =
            result.map_err(|error| lane_error(format!("relay fill task failed: {error}")))??;
        retain_relay_fill_client(
            latency,
            client,
            config.operation_timeout,
            &mut accepted_latency,
            &mut clients,
            &mut client_drivers,
        )?;
    }
    if clients.len() != config.session_capacity.get() {
        return Err(lane_error(format!(
            "relay retained {} sessions instead of configured capacity {}",
            clients.len(),
            config.session_capacity
        )));
    }
    ensure_relay_client_drivers_running(&mut client_drivers)?;
    let fill_arrival = fill_schedule.finish()?;
    wait_for_condition(
        config.operation_timeout,
        "relay global session saturation",
        || {
            relay_connection_count(server)
                .map(|count| count == config.session_capacity.get())
                .unwrap_or(false)
        },
    )
    .await?;
    high_water = high_water.max(relay_connection_count(server)?);
    phases.record(LaneProgress {
        offered: config.session_capacity.get(),
        admitted: clients.len(),
        rejected: 0,
        transport_failed: 0,
        active: clients.len(),
        high_water,
    });

    let overload_identity_base = config
        .session_capacity
        .get()
        .checked_add(1)
        .ok_or_else(|| lane_error("relay overload identity index overflowed"))?;
    let overload_attempts = rejected_capacity
        .checked_sub(1)
        .ok_or_else(|| lane_error("relay overload requires a global rejection attempt"))?;
    let rejection_before_overload = rejection_total(&metrics)?;
    let expected_rejections_after_overload = rejection_before_overload
        .checked_add(
            u64::try_from(overload_attempts)
                .map_err(|_| lane_error("relay overload attempt count is out of range"))?,
        )
        .ok_or_else(|| lane_error("relay overload rejection target overflowed"))?;
    let mut overload_schedule = ScheduleTracker::new(config.overload_rate_per_second);
    let mut overload_tasks = JoinSet::new();
    for ordinal in 0..overload_attempts {
        overload_schedule.wait_for_attempt().await?;
        let identity = overload_identity_base
            .checked_add(ordinal)
            .ok_or_else(|| lane_error("relay overload identity index overflowed"))?;
        let relay_url = relay_url.clone();
        let tls_config = tls_config.clone();
        overload_tasks.spawn(async move {
            let started = StdInstant::now();
            let result = connect_relay_client(
                relay_url,
                deterministic_secret(identity)?,
                tls_config,
                config.operation_timeout,
            )
            .await;
            Ok::<_, Box<dyn Error + Send + Sync>>((started.elapsed(), result))
        });
    }
    let overload_arrival = overload_schedule.finish()?;
    let mut rejected_clients = Vec::with_capacity(overload_attempts);
    while let Some(result) = overload_tasks.join_next().await {
        let (latency, result) = result
            .map_err(|error| lane_error(format!("relay overload task failed: {error}")))??;
        rejected_latency.record(latency)?;
        if let Some(client) = record_relay_client_outcome(&mut rejection_client_outcomes, result)? {
            rejected_clients.push(client);
        }
    }
    let global_rejection_result =
        wait_for_condition(config.operation_timeout, "relay global rejection", || {
            rejection_total(&metrics)
                .map(|current| current >= expected_rejections_after_overload)
                .unwrap_or(false)
                && relay_connection_count(server)
                    .map(|count| count == config.session_capacity.get())
                    .unwrap_or(false)
        })
        .await;
    if let Err(error) = global_rejection_result {
        return Err(lane_error(format!(
            "{error}: observed_rejections={}, expected_rejections={}, registered_sessions={}, retained_rejection_clients={}",
            rejection_total(&metrics)?,
            expected_rejections_after_overload,
            relay_connection_count(server)?,
            rejected_clients.len(),
        )));
    }
    if rejection_total(&metrics)? != expected_rejections_after_overload {
        return Err(lane_error(
            "relay overload rejection counters exceeded offered attempts",
        ));
    }
    drop(rejected_clients);
    phases.record(LaneProgress {
        offered: config.sessions_offered.get(),
        admitted: clients.len(),
        rejected: rejection_client_outcomes
            .total()?
            .checked_sub(rejection_client_outcomes.timed_out)
            .ok_or_else(|| lane_error("relay classified rejection count underflowed"))?,
        transport_failed: rejection_client_outcomes.timed_out,
        active: clients.len(),
        high_water,
    });

    let mut continuity_success_latency = LatencyAccumulator::new(MAX_RESOURCE_PHASE_OPERATIONS);
    let mut continuity_rejection_latency = LatencyAccumulator::new(MAX_RESOURCE_PHASE_OPERATIONS);
    let (continuity_successes, continuity_rejections, continuity_client_outcomes) =
        run_relay_phases(
            config,
            &phases,
            server,
            &relay_url,
            &tls_config,
            &metrics,
            &clients,
            &mut continuity_success_latency,
            &mut continuity_rejection_latency,
        )
        .await?;
    phases.enter(LanePhase::Shutdown);
    let shutdown_started = StdInstant::now();

    let endpoint_session_rejections = metrics
        .admission_endpoint_session_full
        .get()
        .checked_sub(endpoint_rejections_before)
        .ok_or_else(|| lane_error("relay endpoint rejection counter regressed"))?;
    let global_session_rejections = metrics.admission_global_session_full.get();
    let session_pending_rejections = metrics
        .admission_pending_full
        .get()
        .checked_sub(pending_before_sessions)
        .ok_or_else(|| lane_error("relay pending rejection counter regressed"))?;
    let rate_rejections = metrics
        .admission_rate_limited
        .get()
        .checked_sub(rate_before_sessions)
        .ok_or_else(|| lane_error("relay rate rejection counter regressed"))?;

    tokio::time::timeout(config.operation_timeout, async {
        drop(
            clients
                .pop()
                .ok_or_else(|| lane_error("relay recovery requires one accepted client"))?,
        );
        wait_for_condition(
            config.operation_timeout,
            "relay released session capacity",
            || {
                relay_connection_count(server)
                    .map(|count| count < config.session_capacity.get())
                    .unwrap_or(false)
            },
        )
        .await?;
        let replacement = connect_relay_client(
            relay_url,
            deterministic_secret(
                config
                    .sessions_offered
                    .get()
                    .checked_add(
                        continuity_rejections
                            .checked_add(1)
                            .ok_or_else(|| lane_error("relay replacement identity overflowed"))?,
                    )
                    .ok_or_else(|| lane_error("relay replacement identity index overflowed"))?,
            )?,
            tls_config,
            config.operation_timeout,
        )
        .await
        .map_err(|error| lane_error(error.to_string()))?;
        clients.push(RetainedRelayClient::new(
            replacement,
            config.operation_timeout,
            &mut client_drivers,
        ));
        wait_for_condition(
            config.operation_timeout,
            "relay replacement registration",
            || {
                relay_connection_count(server)
                    .map(|count| count == config.session_capacity.get())
                    .unwrap_or(false)
            },
        )
        .await?;
        drop(clients);
        while let Some(result) = client_drivers.join_next().await {
            result.map_err(|error| {
                lane_error(format!("relay client driver task failed: {error}"))
            })??;
        }
        wait_for_condition(config.operation_timeout, "relay client drain", || {
            relay_connection_count(server)
                .map(|count| count == 0)
                .unwrap_or(false)
        })
        .await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    })
    .await
    .map_err(|_| lane_error("relay shutdown timed out"))??;
    let shutdown = shutdown_started.elapsed();
    let initial_client_outcomes = rejection_client_outcomes.total()?;
    if initial_client_outcomes != rejected_capacity {
        return Err(lane_error(format!(
            "relay observed {initial_client_outcomes} initial rejection outcomes for {rejected_capacity} attempts"
        )));
    }
    let session_rejected = initial_client_outcomes
        .checked_sub(rejection_client_outcomes.timed_out)
        .ok_or_else(|| lane_error("relay client rejection accounting underflowed"))?;
    let session_conservation = WorkloadConservation::new(
        config.sessions_offered.get(),
        config.session_capacity.get(),
        session_rejected,
        rejection_client_outcomes.timed_out,
    )?;

    Ok((
        RelayLaneOutcome {
            pending_offered: config.pending_offered.get(),
            pending_rejections,
            pending_rate_rejections,
            pending_conservation,
            sessions_offered: config.sessions_offered.get(),
            sessions_accepted: config.session_capacity.get(),
            sessions_rejected: session_rejected,
            session_conservation,
            session_high_water: high_water,
            endpoint_session_rejections,
            global_session_rejections,
            session_pending_rejections,
            rate_rejections,
            recovered: true,
            accepted_session_latency: accepted_latency.finish()?,
            rejected_session_latency: rejected_latency.finish()?,
            fill_arrival,
            identity_overload_arrival,
            overload_arrival,
            rejection_client_outcomes,
            continuity_client_outcomes,
            continuity_successes,
            continuity_rejections,
            continuity_success_latency: continuity_success_latency.finish()?,
            continuity_rejection_latency: continuity_rejection_latency.finish()?,
            shutdown,
        },
        shutdown_started,
    ))
}

#[allow(
    clippy::too_many_arguments,
    reason = "phase continuity retains explicit server, metric, client, and latency ownership"
)]
async fn run_relay_phases(
    config: RelayLaneConfig,
    phases: &PhaseReporter,
    server: &RelayServer,
    relay_url: &iroh::RelayUrl,
    tls_config: &rustls::ClientConfig,
    metrics: &iroh_relay::server::Metrics,
    clients: &[RetainedRelayClient],
    success_latency: &mut LatencyAccumulator,
    rejection_latency: &mut LatencyAccumulator,
) -> LaneResult<(usize, usize, RelayClientOutcomeCounts)> {
    let mut successes = 0usize;
    let mut rejections = 0usize;
    let mut client_outcomes = RelayClientOutcomeCounts::default();
    for (phase, duration) in [
        (LanePhase::Warmup, config.timing.warmup),
        (LanePhase::Measurement, config.timing.measurement),
        (LanePhase::Cooldown, config.timing.cooldown),
    ] {
        phases.enter(phase);
        let deadline = tokio::time::Instant::now()
            .checked_add(duration)
            .ok_or_else(|| lane_error("relay phase deadline overflowed"))?;
        while tokio::time::Instant::now() < deadline {
            let payload = u64::try_from(successes)
                .map_err(|_| lane_error("relay continuity ordinal is out of range"))?
                .to_le_bytes();
            let started = StdInstant::now();
            clients
                .first()
                .ok_or_else(|| lane_error("relay continuity requires an accepted client"))?
                .ping(payload, config.operation_timeout)
                .await?;
            success_latency.record(started.elapsed())?;
            successes = checked_increment(successes, "relay continuity success")?;

            let before = rejection_total(metrics)?;
            let identity = config
                .sessions_offered
                .get()
                .checked_add(rejections)
                .and_then(|value| value.checked_add(10_000))
                .ok_or_else(|| lane_error("relay continuity identity overflowed"))?;
            let started = StdInstant::now();
            let result = connect_relay_client(
                relay_url.clone(),
                deterministic_secret(identity)?,
                tls_config.clone(),
                config.operation_timeout,
            )
            .await;
            rejection_latency.record(started.elapsed())?;
            let rejected_client = record_relay_client_outcome(&mut client_outcomes, result)?;
            wait_for_condition(
                config.operation_timeout,
                "relay continuity rejection",
                || {
                    rejection_total(metrics)
                        .map(|current| current > before)
                        .unwrap_or(false)
                        && relay_connection_count(server)
                            .map(|count| count == config.session_capacity.get())
                            .unwrap_or(false)
                },
            )
            .await?;
            drop(rejected_client);
            rejections = checked_increment(rejections, "relay continuity rejection")?;
            let initial_rejections = config
                .sessions_offered
                .get()
                .checked_sub(config.session_capacity.get())
                .ok_or_else(|| lane_error("relay progress rejection count underflowed"))?;
            phases.record(LaneProgress {
                offered: config
                    .sessions_offered
                    .get()
                    .checked_add(rejections)
                    .ok_or_else(|| lane_error("relay progress offered count overflowed"))?,
                admitted: config.session_capacity.get(),
                rejected: initial_rejections
                    .checked_add(rejections)
                    .and_then(|value| value.checked_sub(client_outcomes.timed_out))
                    .ok_or_else(|| lane_error("relay progress rejection count overflowed"))?,
                transport_failed: client_outcomes.timed_out,
                active: clients.len(),
                high_water: config.session_capacity.get(),
            });

            let next = tokio::time::Instant::now()
                .checked_add(Duration::from_secs(1))
                .ok_or_else(|| lane_error("relay continuity deadline overflowed"))?
                .min(deadline);
            tokio::time::sleep_until(next).await;
        }
    }
    Ok((successes, rejections, client_outcomes))
}

async fn relay_ping(client: &mut Client, payload: [u8; 8], timeout: Duration) -> LaneResult<()> {
    tokio::time::timeout(timeout, async {
        client
            .send(ClientToRelayMsg::Ping(payload))
            .await
            .map_err(|error| lane_error(format!("relay continuity ping send failed: {error}")))?;
        for _ in 0..8 {
            let message = client
                .next()
                .await
                .ok_or_else(|| lane_error("relay continuity client closed"))?
                .map_err(|error| {
                    lane_error(format!("relay continuity ping receive failed: {error}"))
                })?;
            match message {
                RelayToClientMsg::Pong(received) if received == payload => return Ok(()),
                RelayToClientMsg::Ping(server_payload) => {
                    client
                        .send(ClientToRelayMsg::Pong(server_payload))
                        .await
                        .map_err(|error| {
                            lane_error(format!("relay continuity pong send failed: {error}"))
                        })?;
                }
                _ => {}
            }
        }
        Err(lane_error(
            "relay continuity ping exceeded message scan bound",
        ))
    })
    .await
    .map_err(|_| lane_error("relay continuity ping timed out"))?
}

#[derive(Debug)]
struct RetainedRelayClient {
    commands: mpsc::Sender<RelayClientCommand>,
}

#[derive(Debug)]
enum RelayClientCommand {
    Ping {
        payload: [u8; 8],
        response: oneshot::Sender<Result<(), String>>,
    },
}

impl RetainedRelayClient {
    fn new(
        client: Client,
        operation_timeout: Duration,
        drivers: &mut JoinSet<LaneResult<()>>,
    ) -> Self {
        let (commands, receiver) = mpsc::channel(1);
        drivers.spawn(drive_relay_client(client, receiver, operation_timeout));
        Self { commands }
    }

    async fn ping(&self, payload: [u8; 8], timeout: Duration) -> LaneResult<()> {
        let (response, receiver) = oneshot::channel();
        let result = tokio::time::timeout(timeout, async {
            self.commands
                .send(RelayClientCommand::Ping { payload, response })
                .await
                .map_err(|_| lane_error("relay client driver command channel closed"))?;
            receiver
                .await
                .map_err(|_| lane_error("relay client driver response channel closed"))
        })
        .await
        .map_err(|_| lane_error("relay client driver ping timed out"))??;
        result.map_err(lane_error)
    }
}

async fn drive_relay_client(
    mut client: Client,
    mut commands: mpsc::Receiver<RelayClientCommand>,
    operation_timeout: Duration,
) -> LaneResult<()> {
    loop {
        tokio::select! {
            biased;
            command = commands.recv() => {
                let Some(command) = command else {
                    return Ok(());
                };
                match command {
                    RelayClientCommand::Ping { payload, response } => {
                        let result = relay_ping(&mut client, payload, operation_timeout)
                            .await
                            .map_err(|error| error.to_string());
                        let failure = result.as_ref().err().cloned();
                        let _response_delivered = response.send(result).is_ok();
                        if let Some(failure) = failure {
                            return Err(lane_error(format!(
                                "retained relay client ping failed: {failure}"
                            )));
                        }
                    }
                }
            }
            message = client.next() => {
                match message {
                    Some(Ok(RelayToClientMsg::Ping(payload))) => {
                        client
                            .send(ClientToRelayMsg::Pong(payload))
                            .await
                            .map_err(|error| {
                                lane_error(format!(
                                    "retained relay client pong failed: {error}"
                                ))
                            })?;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(error)) => {
                        return Err(lane_error(format!(
                            "retained relay client receive failed: {error}"
                        )));
                    }
                    None => return Err(lane_error("retained relay client closed")),
                }
            }
        }
    }
}

fn ensure_relay_client_drivers_running(drivers: &mut JoinSet<LaneResult<()>>) -> LaneResult<()> {
    let Some(result) = drivers.try_join_next() else {
        return Ok(());
    };
    match result {
        Err(error) => Err(lane_error(format!(
            "relay client driver task failed: {error}"
        ))),
        Ok(Err(error)) => Err(error),
        Ok(Ok(())) => Err(lane_error(
            "relay client driver exited during retained load",
        )),
    }
}

fn retain_relay_fill_client(
    latency: Duration,
    client: Result<Client, RelayConnectFailure>,
    operation_timeout: Duration,
    accepted_latency: &mut LatencyAccumulator,
    clients: &mut Vec<RetainedRelayClient>,
    drivers: &mut JoinSet<LaneResult<()>>,
) -> LaneResult<()> {
    accepted_latency.record(latency)?;
    clients.push(RetainedRelayClient::new(
        client.map_err(|error| lane_error(error.to_string()))?,
        operation_timeout,
        drivers,
    ));
    Ok(())
}

async fn connect_relay_client(
    relay_url: iroh::RelayUrl,
    secret_key: SecretKey,
    tls_config: rustls::ClientConfig,
    timeout: Duration,
) -> Result<Client, RelayConnectFailure> {
    let builder =
        ClientBuilder::new(relay_url, secret_key, DnsResolver::new()).tls_client_config(tls_config);
    match tokio::time::timeout(timeout, builder.connect()).await {
        Err(_) => Err(RelayConnectFailure::Timeout),
        Ok(Err(ConnectError::UnexpectedUpgradeStatus { code, .. }))
            if code == hyper::StatusCode::TOO_MANY_REQUESTS =>
        {
            Err(RelayConnectFailure::RateLimited)
        }
        Ok(Err(error)) => Err(RelayConnectFailure::Protocol(error.to_string())),
        Ok(Ok(client)) => Ok(client),
    }
}

#[derive(Debug)]
enum RelayConnectFailure {
    Timeout,
    RateLimited,
    Protocol(String),
}

impl std::fmt::Display for RelayConnectFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => f.write_str("relay session establishment timed out"),
            Self::RateLimited => f.write_str("relay session establishment was rate limited"),
            Self::Protocol(error) => write!(f, "relay session establishment failed: {error}"),
        }
    }
}

impl Error for RelayConnectFailure {}

fn record_relay_client_outcome(
    counts: &mut RelayClientOutcomeCounts,
    result: Result<Client, RelayConnectFailure>,
) -> LaneResult<Option<Client>> {
    let (counter, client) = match result {
        Ok(client) => (&mut counts.connected_then_rejected, Some(client)),
        Err(RelayConnectFailure::RateLimited) => (&mut counts.rate_limited, None),
        Err(RelayConnectFailure::Protocol(_)) => (&mut counts.protocol_closed, None),
        Err(RelayConnectFailure::Timeout) => (&mut counts.timed_out, None),
    };
    *counter = checked_increment(*counter, "relay client outcome")?;
    Ok(client)
}

fn relay_connection_count(server: &RelayServer) -> LaneResult<usize> {
    Ok(server
        .relay_service()
        .ok_or_else(|| lane_error("relay service is unavailable"))?
        .clients()
        .connection_count())
}

fn deterministic_secret(identity: usize) -> LaneResult<SecretKey> {
    let mut bytes = [0xA5; 32];
    let identity =
        u64::try_from(identity).map_err(|_| lane_error("relay identity index is out of range"))?;
    bytes[..8].copy_from_slice(&identity.to_le_bytes());
    Ok(SecretKey::from_bytes(&bytes))
}

fn rejection_total(metrics: &iroh_relay::server::Metrics) -> LaneResult<u64> {
    metrics
        .admission_rate_limited
        .get()
        .checked_add(metrics.admission_pending_full.get())
        .and_then(|value| value.checked_add(metrics.admission_global_session_full.get()))
        .and_then(|value| value.checked_add(metrics.admission_endpoint_session_full.get()))
        .ok_or_else(|| lane_error("relay rejection metrics overflowed"))
}

fn pending_rejection_total(
    metrics: &iroh_relay::server::Metrics,
    pending_before: u64,
    rate_before: u64,
) -> LaneResult<u64> {
    let pending = metrics
        .admission_pending_full
        .get()
        .checked_sub(pending_before)
        .ok_or_else(|| lane_error("relay pending rejection counter regressed"))?;
    let rate = metrics
        .admission_rate_limited
        .get()
        .checked_sub(rate_before)
        .ok_or_else(|| lane_error("relay pending rate rejection counter regressed"))?;
    pending
        .checked_add(rate)
        .ok_or_else(|| lane_error("relay pending rejection metrics overflowed"))
}

async fn wait_for_condition(
    timeout: Duration,
    description: &'static str,
    mut condition: impl FnMut() -> bool,
) -> LaneResult<()> {
    tokio::time::timeout(timeout, async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| lane_error(format!("timed out waiting for {description}")))?;
    Ok(())
}

fn checked_increment(value: usize, field: &'static str) -> LaneResult<usize> {
    value
        .checked_add(1)
        .ok_or_else(|| lane_error(format!("{field} counter overflowed")))
}

/// Validated DNS-server UDP, TCP, and HTTP workload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsLaneConfig {
    udp_capacity: NonZeroUsize,
    udp_rate_per_second: NonZeroUsize,
    tcp_capacity: NonZeroUsize,
    http_connection_capacity: NonZeroUsize,
    http_request_capacity: NonZeroUsize,
    http2_streams_per_connection: NonZeroUsize,
    udp_offered: NonZeroUsize,
    tcp_offered: NonZeroUsize,
    http_connections_offered: NonZeroUsize,
    http_requests_offered: NonZeroUsize,
    http_accept_rate_per_second: NonZeroUsize,
    http_accept_burst: NonZeroUsize,
    timing: LaneTiming,
    operation_timeout: Duration,
}

impl DnsLaneConfig {
    /// Creates a bounded DNS-server workload.
    #[allow(
        clippy::too_many_arguments,
        reason = "all independent production bounds stay explicit"
    )]
    pub fn new(
        udp_capacity: NonZeroUsize,
        udp_rate_per_second: NonZeroUsize,
        tcp_capacity: NonZeroUsize,
        http_connection_capacity: NonZeroUsize,
        http_request_capacity: NonZeroUsize,
        http2_streams_per_connection: NonZeroUsize,
        udp_offered: NonZeroUsize,
        tcp_offered: NonZeroUsize,
        http_connections_offered: NonZeroUsize,
        http_requests_offered: NonZeroUsize,
        http_accept_rate_per_second: NonZeroUsize,
        http_accept_burst: NonZeroUsize,
        timing: LaneTiming,
        operation_timeout: Duration,
    ) -> Result<Self, CanaryError> {
        validate_offered(udp_offered, udp_capacity, "dns_udp_requests")?;
        validate_offered(tcp_offered, tcp_capacity, "dns_tcp_connections")?;
        validate_offered(
            http_connections_offered,
            http_connection_capacity,
            "dns_http_connections",
        )?;
        validate_offered(
            http_requests_offered,
            http_request_capacity,
            "dns_http_requests",
        )?;
        validate_maximum(udp_offered, MAX_DNS_UDP_OFFERED, "dns_udp_requests")?;
        validate_maximum(
            udp_rate_per_second,
            MAX_DNS_UDP_RATE,
            "dns_udp_request_rate",
        )?;
        validate_schedule_within_hold(
            udp_offered,
            udp_rate_per_second,
            RESOURCE_CANARY_UDP_HOLD_DURATION,
            "dns_udp_requests",
        )?;
        validate_maximum(tcp_offered, MAX_DNS_TCP_OFFERED, "dns_tcp_connections")?;
        validate_maximum(
            http_connections_offered,
            MAX_DNS_HTTP_CONNECTIONS_OFFERED,
            "dns_http_connections",
        )?;
        validate_maximum(
            http_requests_offered,
            MAX_DNS_HTTP_REQUESTS_OFFERED,
            "dns_http_requests",
        )?;
        validate_maximum(
            http2_streams_per_connection,
            MAX_DNS_HTTP2_STREAMS_PER_CONNECTION,
            "dns_http2_streams_per_connection",
        )?;
        validate_maximum(
            http_accept_rate_per_second,
            MAX_RELAY_CONNECTION_RATE,
            "dns_http_accept_rate",
        )?;
        if operation_timeout.is_zero() {
            return Err(CanaryError::ZeroDuration {
                field: "operation_timeout",
            });
        }
        Ok(Self {
            udp_capacity,
            udp_rate_per_second,
            tcp_capacity,
            http_connection_capacity,
            http_request_capacity,
            http2_streams_per_connection,
            udp_offered,
            tcp_offered,
            http_connections_offered,
            http_requests_offered,
            http_accept_rate_per_second,
            http_accept_burst,
            timing,
            operation_timeout,
        })
    }
}

/// Retained DNS-server admission and shutdown evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsLaneOutcome {
    /// UDP requests offered.
    pub udp_offered: usize,
    /// UDP requests with a response.
    pub udp_completed: usize,
    /// UDP requests that were dropped or exceeded the operation deadline.
    pub udp_timed_out: usize,
    /// Server-observed UDP capacity rejections.
    pub udp_rejections: u64,
    /// Exact UDP outcome accounting, separating admission rejection from unrelated transport loss.
    pub udp_conservation: WorkloadConservation,
    /// Absolute-deadline UDP arrival evidence.
    pub udp_arrival: ArrivalSummary,
    /// Successful DNS UDP request latency.
    pub udp_latency: LatencySummary,
    /// DNS TCP connections offered.
    pub tcp_offered: usize,
    /// Largest observed active DNS TCP connection count.
    pub tcp_active_high_water: usize,
    /// DNS TCP capacity rejections.
    pub tcp_rejections: u64,
    /// Exact initial DNS TCP connection accounting.
    pub tcp_conservation: WorkloadConservation,
    /// HTTP connections offered.
    pub http_connections_offered: usize,
    /// Largest observed active HTTP connection count.
    pub http_connections_active_high_water: usize,
    /// Initial HTTP connections rejected by the capacity limit.
    pub http_connection_capacity_rejections: u64,
    /// Initial HTTP connections rejected by the rate limit.
    pub http_connection_rate_rejections: u64,
    /// Total HTTP connection capacity and rate rejections, including timed continuity.
    pub http_connection_rejections: u64,
    /// Exact initial HTTP connection accounting.
    pub http_connection_conservation: WorkloadConservation,
    /// Absolute-deadline HTTP connection arrival evidence.
    pub http_connection_arrival: ArrivalSummary,
    /// HTTP requests offered.
    pub http_requests_offered: usize,
    /// HTTP requests admitted and held at the request ledger.
    pub http_requests_admitted: usize,
    /// Largest observed active HTTP request count.
    pub http_requests_active_high_water: usize,
    /// HTTP request-capacity rejections.
    pub http_request_rejections: u64,
    /// Exact initial HTTP request accounting.
    pub http_request_conservation: WorkloadConservation,
    /// Whether request admission accepted new work after complete release.
    pub http_request_recovered: bool,
    /// Successful post-release HTTP request latency.
    pub http_request_latency: LatencySummary,
    /// Successful UDP operations during timed pressure.
    pub continuity_udp_successes: usize,
    /// HTTP connection rejections during timed pressure.
    pub continuity_http_connection_rejections: usize,
    /// HTTP request rejections during timed pressure.
    pub continuity_http_request_rejections: usize,
    /// UDP latency during timed pressure.
    pub continuity_udp_latency: LatencySummary,
    /// Whether TCP and HTTP capacity admitted new work after complete release.
    pub recovered: bool,
    /// Persistent-store background failures.
    pub store_background_failures: u64,
    /// Measured server shutdown time.
    pub shutdown: Duration,
}

/// Saturates DNS TCP and HTTP connection admission while offering bounded UDP and HTTP work.
pub async fn run_dns_lane(
    config: DnsLaneConfig,
    phases: PhaseReporter,
) -> LaneResult<DnsLaneOutcome> {
    let temp_dir = tempfile::tempdir()?;
    let dns_port = reserve_shared_dns_port()?;
    let server_config = dns_server_config(config, temp_dir.path(), dns_port)?;
    let server = DnsServer::bind(server_config).await?;
    let result = run_dns_lane_body(config, phases.clone(), &server).await;
    let shutdown_started = result
        .as_ref()
        .map(|(_, started)| *started)
        .unwrap_or_else(|_| {
            phases.enter(LanePhase::Shutdown);
            StdInstant::now()
        });
    let remaining = config
        .operation_timeout
        .checked_sub(shutdown_started.elapsed())
        .unwrap_or(Duration::from_millis(1));
    let shutdown_result = tokio::time::timeout(remaining, server.shutdown())
        .await
        .map_err(|_| lane_error("DNS server shutdown timed out"))
        .and_then(|result| result.map_err(|error| lane_error(error.to_string())));
    drop(temp_dir);
    match (result, shutdown_result) {
        (Ok((mut outcome, started)), Ok(())) => {
            outcome.shutdown = started.elapsed();
            if outcome.shutdown > config.operation_timeout {
                return Err(lane_error("DNS whole-lane shutdown deadline exhausted"));
            }
            Ok(outcome)
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(workload), Err(shutdown)) => Err(lane_error(format!(
            "{workload}; DNS cleanup also failed: {shutdown}"
        ))),
    }
}

async fn run_dns_lane_body(
    config: DnsLaneConfig,
    phases: PhaseReporter,
    server: &DnsServer,
) -> LaneResult<(DnsLaneOutcome, StdInstant)> {
    let dns_addr = server.dns_addr();
    let http_addr = server
        .http_addr()
        .ok_or_else(|| lane_error("DNS server did not bind an HTTP address"))?;
    require_loopback(dns_addr)?;
    require_loopback(http_addr)?;
    let metrics = server.metrics().clone();

    let mut udp_tasks = JoinSet::new();
    let udp_probe_timeout = RESOURCE_CANARY_UDP_HOLD_DURATION
        .checked_add(Duration::from_secs(2))
        .ok_or_else(|| lane_error("DNS UDP probe timeout overflowed"))?;
    if udp_probe_timeout > config.operation_timeout {
        return Err(lane_error(
            "DNS operation timeout is shorter than the reserved UDP hold probe",
        ));
    }
    let udp_rejections_before = metrics.dns_udp_requests_rejected.get();
    let mut udp_schedule = ScheduleTracker::new(config.udp_rate_per_second);
    for ordinal in 0..config.udp_capacity.get() {
        udp_schedule.wait_for_attempt().await?;
        udp_tasks.spawn(udp_query(dns_addr, ordinal, udp_probe_timeout, true));
    }
    wait_for_condition(config.operation_timeout, "DNS UDP saturation", || {
        metrics.dns_udp_requests_active.get()
            == i64::try_from(config.udp_capacity.get()).unwrap_or(i64::MAX)
    })
    .await?;
    for ordinal in config.udp_capacity.get()..config.udp_offered.get() {
        udp_schedule.wait_for_attempt().await?;
        udp_tasks.spawn(udp_query(dns_addr, ordinal, udp_probe_timeout, true));
    }
    wait_for_condition(config.operation_timeout, "DNS UDP overload", || {
        metrics.dns_udp_requests_rejected.get() > udp_rejections_before
    })
    .await?;
    let udp_arrival = udp_schedule.finish()?;
    let mut udp_completed = 0usize;
    let mut udp_timed_out = 0usize;
    let mut udp_latency = LatencyAccumulator::new(config.udp_offered.get());
    while let Some(result) = udp_tasks.join_next().await {
        let (completed, latency) =
            result.map_err(|error| lane_error(format!("DNS UDP task failed: {error}")))??;
        if completed {
            udp_completed = checked_increment(udp_completed, "DNS UDP completion")?;
            udp_latency.record(latency)?;
        } else {
            udp_timed_out = checked_increment(udp_timed_out, "DNS UDP timeout")?;
        }
    }
    let udp_rejected_so_far = usize::try_from(
        metrics
            .dns_udp_requests_rejected
            .get()
            .checked_sub(udp_rejections_before)
            .ok_or_else(|| lane_error("DNS UDP rejection counter regressed"))?,
    )
    .map_err(|_| lane_error("DNS UDP rejection count is out of range"))?;
    phases.record(LaneProgress {
        offered: config.udp_offered.get(),
        admitted: udp_completed,
        rejected: udp_rejected_so_far,
        transport_failed: udp_timed_out.saturating_sub(udp_rejected_so_far),
        active: usize::try_from(metrics.dns_udp_requests_active.get()).unwrap_or(0),
        high_water: config.udp_capacity.get(),
    });

    let mut tcp_sockets = Vec::with_capacity(config.tcp_offered.get());
    for _ in 0..config.tcp_offered.get() {
        tcp_sockets.push(connect_tcp(dns_addr, config.operation_timeout).await?);
    }
    let expected_tcp_rejections = u64::try_from(
        config
            .tcp_offered
            .get()
            .checked_sub(config.tcp_capacity.get())
            .ok_or_else(|| lane_error("DNS TCP rejection target underflowed"))?,
    )
    .map_err(|_| lane_error("DNS TCP rejection target is out of range"))?;
    wait_for_condition(config.operation_timeout, "DNS TCP saturation", || {
        metrics.dns_tcp_connections_active.get()
            == i64::try_from(config.tcp_capacity.get()).unwrap_or(i64::MAX)
            && metrics.dns_tcp_connections_rejected.get() == expected_tcp_rejections
    })
    .await?;
    let tcp_active_high_water = usize::try_from(metrics.dns_tcp_connections_active.get())
        .map_err(|_| lane_error("DNS TCP active gauge is negative"))?;
    phases.record(LaneProgress {
        offered: config.tcp_offered.get(),
        admitted: tcp_active_high_water,
        rejected: usize::try_from(expected_tcp_rejections)
            .map_err(|_| lane_error("DNS TCP rejection target is out of range"))?,
        transport_failed: 0,
        active: tcp_active_high_water,
        high_water: tcp_active_high_water,
    });

    let offer_rate = twice_nonzero(
        config.http_accept_rate_per_second,
        "DNS HTTP offered connection rate",
    )?;
    let h2_client_count = ceiling_division(
        config.http_requests_offered.get(),
        config.http2_streams_per_connection.get(),
        "DNS HTTP/2 client count",
    )?;
    if h2_client_count > config.http_connection_capacity.get() {
        return Err(lane_error(format!(
            "{h2_client_count} HTTP/2 clients exceed HTTP connection capacity {}",
            config.http_connection_capacity
        )));
    }
    let mut h2_senders = Vec::with_capacity(h2_client_count);
    let mut h2_drivers = JoinSet::new();
    let mut http_schedule = ScheduleTracker::new(offer_rate);
    let mut h2_connect_tasks = JoinSet::new();
    for _ in 0..h2_client_count {
        http_schedule.wait_for_attempt().await?;
        h2_connect_tasks.spawn(connect_h2_client(http_addr, config.operation_timeout));
    }
    while let Some(result) = h2_connect_tasks.join_next().await {
        let (sender, driver) = result
            .map_err(|error| lane_error(format!("DNS HTTP/2 connect task failed: {error}")))??;
        h2_senders.push(sender);
        h2_drivers.spawn(driver);
    }

    let raw_http_attempts = config
        .http_connections_offered
        .get()
        .checked_sub(h2_client_count)
        .ok_or_else(|| lane_error("DNS raw HTTP connection count underflowed"))?;
    let mut http_connect_tasks = JoinSet::new();
    for _ in 0..raw_http_attempts {
        http_schedule.wait_for_attempt().await?;
        http_connect_tasks.spawn(connect_tcp(http_addr, config.operation_timeout));
    }
    let http_connection_arrival = http_schedule.finish()?;
    let mut http_sockets = Vec::with_capacity(raw_http_attempts);
    while let Some(result) = http_connect_tasks.join_next().await {
        http_sockets.push(
            result
                .map_err(|error| lane_error(format!("DNS HTTP connect task failed: {error}")))??,
        );
    }
    let expected_initial_http_connection_rejections = u64::try_from(
        config
            .http_connections_offered
            .get()
            .checked_sub(config.http_connection_capacity.get())
            .ok_or_else(|| lane_error("DNS HTTP connection rejection target underflowed"))?,
    )
    .map_err(|_| lane_error("DNS HTTP connection rejection target is out of range"))?;
    wait_for_condition(
        config.operation_timeout,
        "DNS HTTP connection saturation",
        || {
            metrics.http_connections_active.get()
                == i64::try_from(config.http_connection_capacity.get()).unwrap_or(i64::MAX)
                && dns_http_connection_rejections(&metrics).unwrap_or(0)
                    == expected_initial_http_connection_rejections
        },
    )
    .await?;
    let http_connections_active_high_water = usize::try_from(metrics.http_connections_active.get())
        .map_err(|_| lane_error("DNS HTTP active gauge is negative"))?;
    let http_connection_capacity_rejections = metrics.http_connections_rejected_capacity.get();
    let http_connection_rate_rejections = metrics.http_connections_rejected_rate.get();
    phases.record(LaneProgress {
        offered: config.http_connections_offered.get(),
        admitted: http_connections_active_high_water,
        rejected: usize::try_from(expected_initial_http_connection_rejections)
            .map_err(|_| lane_error("DNS HTTP connection rejection target is out of range"))?,
        transport_failed: 0,
        active: http_connections_active_high_water,
        high_water: http_connections_active_high_water,
    });

    let http_request_hold = config
        .timing
        .total()
        .checked_add(config.operation_timeout / 2)
        .ok_or_else(|| lane_error("DNS HTTP request hold overflowed"))?;
    let mut http_request_tasks = JoinSet::new();
    for ordinal in 0..config.http_requests_offered.get() {
        let client_index = ordinal / config.http2_streams_per_connection.get();
        let sender = h2_senders
            .get(client_index)
            .ok_or_else(|| lane_error("DNS HTTP/2 sender index is out of range"))?
            .clone();
        http_request_tasks.spawn(held_http_request(
            sender,
            http_addr,
            http_request_hold,
            config.operation_timeout,
        ));
    }
    let expected_http_request_rejections = u64::try_from(
        config
            .http_requests_offered
            .get()
            .checked_sub(config.http_request_capacity.get())
            .ok_or_else(|| lane_error("DNS HTTP request rejection target underflowed"))?,
    )
    .map_err(|_| lane_error("DNS HTTP request rejection target is out of range"))?;
    wait_for_condition(
        config.operation_timeout,
        "DNS HTTP request saturation",
        || {
            metrics.http_requests_active.get()
                == i64::try_from(config.http_request_capacity.get()).unwrap_or(i64::MAX)
                && metrics.http_requests_rejected_capacity.get() == expected_http_request_rejections
        },
    )
    .await?;
    let http_requests_active_high_water = usize::try_from(metrics.http_requests_active.get())
        .map_err(|_| lane_error("DNS HTTP request active gauge is negative"))?;
    let http_request_rejections = metrics.http_requests_rejected_capacity.get();
    phases.record(LaneProgress {
        offered: config.http_requests_offered.get(),
        admitted: http_requests_active_high_water,
        rejected: usize::try_from(expected_http_request_rejections)
            .map_err(|_| lane_error("DNS HTTP request rejection target is out of range"))?,
        transport_failed: 0,
        active: http_requests_active_high_water,
        high_water: http_requests_active_high_water,
    });

    let mut continuity_udp_latency = LatencyAccumulator::new(MAX_RESOURCE_PHASE_OPERATIONS);
    let (
        continuity_udp_successes,
        continuity_http_connection_rejections,
        continuity_http_request_rejections,
    ) = run_dns_phases(
        config,
        &phases,
        dns_addr,
        http_addr,
        &metrics,
        h2_senders
            .last()
            .ok_or_else(|| lane_error("DNS continuity requires one HTTP/2 client"))?,
        &mut continuity_udp_latency,
    )
    .await?;
    phases.enter(LanePhase::Shutdown);
    let shutdown_started = StdInstant::now();
    let (http_requests_admitted, http_request_recovered, http_request_latency) =
        tokio::time::timeout(config.operation_timeout, async {
            let mut admitted = 0usize;
            let mut rejected = 0usize;
            while let Some(result) = http_request_tasks.join_next().await {
                match result.map_err(|error| {
                    lane_error(format!("DNS HTTP request task failed: {error}"))
                })?? {
                    HeldHttpOutcome::Admitted => {
                        admitted = checked_increment(admitted, "DNS HTTP admitted request")?;
                    }
                    HeldHttpOutcome::Rejected => {
                        rejected = checked_increment(rejected, "DNS HTTP rejected request")?;
                    }
                }
            }
            if admitted
                .checked_add(rejected)
                .ok_or_else(|| lane_error("DNS HTTP request conservation overflowed"))?
                != config.http_requests_offered.get()
            {
                return Err(lane_error("DNS HTTP request outcomes are incomplete"));
            }

            if let Some(result) = h2_drivers.try_join_next() {
                match result {
                    Err(error) => {
                        return Err(lane_error(format!(
                            "DNS HTTP/2 driver task failed during timed load: {error}"
                        )));
                    }
                    Ok(Err(error)) => return Err(error),
                    Ok(Ok(())) => {
                        return Err(lane_error("DNS HTTP/2 driver exited during timed load"));
                    }
                }
            }
            drop(tcp_sockets);
            drop(http_sockets);
            drop(h2_senders);
            h2_drivers.abort_all();
            while let Some(result) = h2_drivers.join_next().await {
                match result {
                    Err(error) if error.is_cancelled() => {}
                    Err(error) => {
                        return Err(lane_error(format!(
                            "DNS HTTP/2 driver task failed: {error}"
                        )));
                    }
                    Ok(Err(error)) => return Err(error),
                    Ok(Ok(())) => {}
                }
            }
            wait_for_condition(config.operation_timeout, "DNS TCP drain", || {
                metrics.dns_tcp_connections_active.get() == 0
            })
            .await?;
            wait_for_condition(
                config.operation_timeout,
                "DNS HTTP connection drain",
                || metrics.http_connections_active.get() == 0,
            )
            .await?;

            let recovered_tcp = connect_tcp(dns_addr, config.operation_timeout).await?;
            wait_for_condition(config.operation_timeout, "DNS TCP recovery", || {
                metrics.dns_tcp_connections_active.get() == 1
            })
            .await?;
            drop(recovered_tcp);
            wait_for_condition(config.operation_timeout, "DNS TCP recovery drain", || {
                metrics.dns_tcp_connections_active.get() == 0
            })
            .await?;

            wait_for_accept_refill(config.http_accept_burst, config.http_accept_rate_per_second)
                .await?;
            let (request_recovered, latency) =
                http_get(http_addr, config.operation_timeout).await?;
            wait_for_condition(config.operation_timeout, "DNS HTTP recovery drain", || {
                metrics.http_connections_active.get() == 0
            })
            .await?;
            let mut latency_summary = LatencyAccumulator::new(1);
            if request_recovered {
                latency_summary.record(latency)?;
            }
            Ok::<_, Box<dyn Error + Send + Sync>>((
                admitted,
                request_recovered,
                latency_summary.finish()?,
            ))
        })
        .await
        .map_err(|_| lane_error("DNS whole-lane shutdown timed out"))??;
    let shutdown = shutdown_started.elapsed();
    let udp_rejections = metrics.dns_udp_requests_rejected.get();
    let tcp_rejections = metrics.dns_tcp_connections_rejected.get();
    let http_connection_rejections = dns_http_connection_rejections(&metrics)?;
    let store_background_failures = metrics.store_background_failures.get();
    let udp_rejected = usize::try_from(udp_rejections)
        .map_err(|_| lane_error("DNS UDP rejection count is out of range"))?;
    let udp_transport_failed = udp_timed_out
        .checked_sub(udp_rejected)
        .ok_or_else(|| lane_error("DNS UDP rejections exceed timed-out client outcomes"))?;
    let udp_conservation = WorkloadConservation::new(
        config.udp_offered.get(),
        udp_completed,
        udp_rejected,
        udp_transport_failed,
    )?;
    let tcp_conservation = WorkloadConservation::new(
        config.tcp_offered.get(),
        tcp_active_high_water,
        usize::try_from(tcp_rejections)
            .map_err(|_| lane_error("DNS TCP rejection count is out of range"))?,
        0,
    )?;
    let initial_http_connection_rejections = http_connection_capacity_rejections
        .checked_add(http_connection_rate_rejections)
        .ok_or_else(|| lane_error("DNS HTTP connection rejection count overflowed"))?;
    let http_connection_conservation = WorkloadConservation::new(
        config.http_connections_offered.get(),
        http_connections_active_high_water,
        usize::try_from(initial_http_connection_rejections)
            .map_err(|_| lane_error("DNS HTTP connection rejection count is out of range"))?,
        0,
    )?;
    let http_request_conservation = WorkloadConservation::new(
        config.http_requests_offered.get(),
        http_requests_admitted,
        usize::try_from(http_request_rejections)
            .map_err(|_| lane_error("DNS HTTP request rejection count is out of range"))?,
        0,
    )?;
    Ok((
        DnsLaneOutcome {
            udp_offered: config.udp_offered.get(),
            udp_completed,
            udp_timed_out,
            udp_rejections,
            udp_conservation,
            udp_arrival,
            udp_latency: udp_latency.finish()?,
            tcp_offered: config.tcp_offered.get(),
            tcp_active_high_water,
            tcp_rejections,
            tcp_conservation,
            http_connections_offered: config.http_connections_offered.get(),
            http_connections_active_high_water,
            http_connection_capacity_rejections,
            http_connection_rate_rejections,
            http_connection_rejections,
            http_connection_conservation,
            http_connection_arrival,
            http_requests_offered: config.http_requests_offered.get(),
            http_requests_admitted,
            http_requests_active_high_water,
            http_request_rejections,
            http_request_conservation,
            http_request_recovered,
            http_request_latency,
            continuity_udp_successes,
            continuity_http_connection_rejections,
            continuity_http_request_rejections,
            continuity_udp_latency: continuity_udp_latency.finish()?,
            recovered: true,
            store_background_failures,
            shutdown,
        },
        shutdown_started,
    ))
}

#[allow(
    clippy::too_many_arguments,
    reason = "phase continuity retains explicit addresses, metrics, and bounded latency state"
)]
async fn run_dns_phases(
    config: DnsLaneConfig,
    phases: &PhaseReporter,
    dns_addr: SocketAddr,
    http_addr: SocketAddr,
    metrics: &iroh_dns_server::Metrics,
    h2_sender: &H2RequestSender,
    udp_latency: &mut LatencyAccumulator,
) -> LaneResult<(usize, usize, usize)> {
    let mut udp_successes = 0usize;
    let mut connection_rejections = 0usize;
    let mut request_rejections = 0usize;
    for (phase, duration) in [
        (LanePhase::Warmup, config.timing.warmup),
        (LanePhase::Measurement, config.timing.measurement),
        (LanePhase::Cooldown, config.timing.cooldown),
    ] {
        phases.enter(phase);
        let deadline = tokio::time::Instant::now()
            .checked_add(duration)
            .ok_or_else(|| lane_error("DNS phase deadline overflowed"))?;
        while tokio::time::Instant::now() < deadline {
            let (completed, latency) =
                udp_query(dns_addr, udp_successes, config.operation_timeout, false).await?;
            if !completed {
                return Err(lane_error(
                    "DNS UDP continuity request failed during timed pressure",
                ));
            }
            udp_latency.record(latency)?;
            udp_successes = checked_increment(udp_successes, "DNS UDP continuity success")?;

            let connections_before = dns_http_connection_rejections(metrics)?;
            let socket = connect_tcp(http_addr, config.operation_timeout).await?;
            wait_for_condition(
                config.operation_timeout,
                "DNS HTTP continuity connection rejection",
                || {
                    dns_http_connection_rejections(metrics)
                        .map(|current| current > connections_before)
                        .unwrap_or(false)
                },
            )
            .await?;
            drop(socket);
            connection_rejections = checked_increment(
                connection_rejections,
                "DNS HTTP continuity connection rejection",
            )?;

            let requests_before = metrics.http_requests_rejected_capacity.get();
            let status =
                h2_get_status(h2_sender.clone(), http_addr, config.operation_timeout).await?;
            if status != hyper::StatusCode::SERVICE_UNAVAILABLE {
                return Err(lane_error(format!(
                    "DNS HTTP continuity request returned unexpected status {status}"
                )));
            }
            wait_for_condition(
                config.operation_timeout,
                "DNS HTTP continuity request rejection",
                || metrics.http_requests_rejected_capacity.get() > requests_before,
            )
            .await?;
            request_rejections =
                checked_increment(request_rejections, "DNS HTTP continuity request rejection")?;

            let next = tokio::time::Instant::now()
                .checked_add(Duration::from_secs(1))
                .ok_or_else(|| lane_error("DNS continuity deadline overflowed"))?
                .min(deadline);
            tokio::time::sleep_until(next).await;
        }
    }
    Ok((udp_successes, connection_rejections, request_rejections))
}

fn dns_server_config(
    config: DnsLaneConfig,
    data_dir: &Path,
    dns_port: u16,
) -> LaneResult<DnsServerConfig> {
    let mut server = DnsServerConfig::default();
    let http = server
        .http
        .as_mut()
        .ok_or_else(|| lane_error("default DNS server config lacks HTTP"))?;
    http.port = 0;
    http.bind_addr = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
    server.https = None;
    server.dns.port = dns_port;
    server.dns.bind_addr = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
    server.metrics = Some(MetricsConfig::disabled());
    server.mainline = None;
    server.pkarr_put_rate_limit = RateLimitConfig::Disabled;
    server.data_dir = Some(data_dir.to_owned());
    server.limits.max_dns_udp_requests = config.udp_capacity.get();
    server.limits.max_dns_tcp_connections = config.tcp_capacity.get();
    server.limits.max_http_connections = config.http_connection_capacity.get();
    server.limits.max_http_requests = config.http_request_capacity.get();
    server.limits.max_http2_streams_per_connection =
        u32::try_from(config.http2_streams_per_connection.get())
            .map_err(|_| lane_error("DNS HTTP/2 stream limit is out of range"))?;
    let accept_rate = u32::try_from(config.http_accept_rate_per_second.get())
        .map_err(|_| lane_error("DNS HTTP accept rate is out of range"))?;
    server.limits.http_accept_rate_per_second = Some(f64::from(accept_rate));
    server.limits.http_accept_burst = Some(config.http_accept_burst.get());
    server.limits.shutdown_timeout = config.operation_timeout;
    Ok(server)
}

fn reserve_shared_dns_port() -> LaneResult<u16> {
    let tcp = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = tcp.local_addr()?.port();
    let udp = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, port))?;
    drop(udp);
    drop(tcp);
    Ok(port)
}

async fn udp_query(
    server_addr: SocketAddr,
    ordinal: usize,
    timeout: Duration,
    hold_admission: bool,
) -> LaneResult<(bool, Duration)> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let transaction =
        u16::try_from(ordinal).map_err(|_| lane_error("DNS UDP ordinal is out of range"))?;
    let [high, low] = transaction.to_be_bytes();
    let mut query = Vec::with_capacity(64);
    query.extend_from_slice(&[
        high, low, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    if hold_admission {
        for label in RESOURCE_CANARY_UDP_HOLD_NAME
            .trim_end_matches('.')
            .split('.')
        {
            let label_length = u8::try_from(label.len())
                .map_err(|_| lane_error("DNS UDP canary label exceeds wire-format capacity"))?;
            if label_length == 0 || label_length > 63 {
                return Err(lane_error("DNS UDP canary label length is invalid"));
            }
            query.push(label_length);
            query.extend_from_slice(label.as_bytes());
        }
    }
    query.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
    let started = StdInstant::now();
    let exchange = async {
        socket.send_to(&query, server_addr).await?;
        let mut response = [0u8; 512];
        let (length, source) = socket.recv_from(&mut response).await?;
        Ok::<bool, io::Error>(length >= 12 && source == server_addr)
    };
    match tokio::time::timeout(timeout, exchange).await {
        Ok(result) => Ok((result?, started.elapsed())),
        Err(_) => Ok((false, started.elapsed())),
    }
}

async fn connect_tcp(address: SocketAddr, timeout: Duration) -> LaneResult<TcpStream> {
    tokio::time::timeout(timeout, TcpStream::connect(address))
        .await
        .map_err(|_| lane_error(format!("TCP connect to {address} timed out")))?
        .map_err(|error| lane_error(format!("TCP connect to {address} failed: {error}")))
}

async fn connect_h2_client(
    address: SocketAddr,
    timeout: Duration,
) -> LaneResult<(H2RequestSender, H2Driver)> {
    let stream = connect_tcp(address, timeout).await?;
    let io = TokioIo::new(stream);
    let handshake = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake::<_, H2RequestBody>(io);
    let (sender, connection) = tokio::time::timeout(timeout, handshake)
        .await
        .map_err(|_| lane_error("DNS HTTP/2 handshake timed out"))?
        .map_err(|error| lane_error(format!("DNS HTTP/2 handshake failed: {error}")))?;
    let driver = Box::pin(async move {
        connection
            .await
            .map_err(|error| lane_error(format!("DNS HTTP/2 connection failed: {error}")))
    });
    Ok((sender, driver))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeldHttpOutcome {
    Admitted,
    Rejected,
}

async fn held_http_request(
    mut sender: H2RequestSender,
    address: SocketAddr,
    hold: Duration,
    timeout: Duration,
) -> LaneResult<HeldHttpOutcome> {
    let request = Request::builder()
        .method("GET")
        .uri(format!("http://{address}/__iroh_test/hold"))
        .header(
            "x-iroh-test-hold-millis",
            u64::try_from(hold.as_millis())
                .map_err(|_| lane_error("DNS HTTP request hold is out of range"))?,
        )
        .body(Empty::<Bytes>::new())?;
    let response = tokio::time::timeout(
        hold.checked_add(timeout)
            .ok_or_else(|| lane_error("DNS held HTTP request timeout overflowed"))?,
        sender.send_request(request),
    )
    .await
    .map_err(|_| lane_error("DNS held HTTP request timed out"))?
    .map_err(|error| lane_error(format!("DNS held HTTP request failed: {error:?}")))?;
    match response.status() {
        hyper::StatusCode::SERVICE_UNAVAILABLE => Ok(HeldHttpOutcome::Rejected),
        hyper::StatusCode::OK => Ok(HeldHttpOutcome::Admitted),
        status => Err(lane_error(format!(
            "DNS held HTTP request returned unexpected status {status}"
        ))),
    }
}

async fn h2_get_status(
    mut sender: H2RequestSender,
    address: SocketAddr,
    timeout: Duration,
) -> LaneResult<hyper::StatusCode> {
    let request = Request::builder()
        .method("GET")
        .uri(format!("http://{address}/healthz"))
        .body(Empty::<Bytes>::new())?;
    let response = tokio::time::timeout(timeout, sender.send_request(request))
        .await
        .map_err(|_| lane_error("DNS HTTP/2 continuity request timed out"))?
        .map_err(|error| lane_error(format!("DNS HTTP/2 continuity request failed: {error:?}")))?;
    Ok(response.status())
}

async fn http_get(address: SocketAddr, timeout: Duration) -> LaneResult<(bool, Duration)> {
    let started = StdInstant::now();
    let mut stream = match connect_tcp(address, timeout).await {
        Ok(stream) => stream,
        Err(_) => return Ok((false, started.elapsed())),
    };
    let request = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let exchange = async {
        stream.write_all(request).await?;
        let mut response = [0u8; 4_096];
        let length = stream.read(&mut response).await?;
        Ok::<bool, io::Error>(
            response
                .get(..length)
                .is_some_and(|bytes| bytes.starts_with(b"HTTP/1.1 200")),
        )
    };
    match tokio::time::timeout(timeout, exchange).await {
        Ok(result) => Ok((result.unwrap_or(false), started.elapsed())),
        Err(_) => Ok((false, started.elapsed())),
    }
}

fn ceiling_division(value: usize, divisor: usize, field: &'static str) -> LaneResult<usize> {
    value
        .checked_add(divisor - 1)
        .map(|rounded| rounded / divisor)
        .ok_or_else(|| lane_error(format!("{field} overflowed")))
}

fn dns_http_connection_rejections(metrics: &iroh_dns_server::Metrics) -> LaneResult<u64> {
    metrics
        .http_connections_rejected_capacity
        .get()
        .checked_add(metrics.http_connections_rejected_rate.get())
        .ok_or_else(|| lane_error("DNS HTTP connection rejection counters overflowed"))
}

fn twice_nonzero(value: NonZeroUsize, field: &'static str) -> LaneResult<NonZeroUsize> {
    value
        .get()
        .checked_mul(2)
        .and_then(NonZeroUsize::new)
        .ok_or_else(|| lane_error(format!("{field} overflowed")))
}

async fn wait_for_accept_refill(
    burst: NonZeroUsize,
    rate_per_second: NonZeroUsize,
) -> LaneResult<()> {
    let millis = burst
        .get()
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(rate_per_second.get() - 1))
        .map(|value| value / rate_per_second.get())
        .and_then(|value| value.checked_add(50))
        .ok_or_else(|| lane_error("DNS HTTP token refill duration overflowed"))?;
    tokio::time::sleep(Duration::from_millis(u64::try_from(millis).map_err(
        |_| lane_error("DNS HTTP token refill duration is out of range"),
    )?))
    .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroUsize, time::Duration};

    use super::{
        DnsLaneConfig, EndpointLaneConfig, LanePhase, LaneProgress, LaneState, LaneTiming,
        PhaseReporter, RelayLaneConfig, run_dns_lane, run_endpoint_lane, run_relay_lane,
    };
    use crate::canary::CanaryError;

    fn test_timing() -> LaneTiming {
        LaneTiming::new(
            Duration::from_millis(20),
            Duration::from_millis(20),
            Duration::from_millis(20),
        )
        .expect("valid test timing")
    }

    #[test]
    fn phase_reporter_retains_last_bounded_progress_snapshot() {
        let (reporter, receiver) = PhaseReporter::new();
        reporter.enter(LanePhase::Measurement);
        reporter.record(LaneProgress {
            offered: 8,
            admitted: 4,
            rejected: 3,
            transport_failed: 1,
            active: 4,
            high_water: 4,
        });

        assert_eq!(
            *receiver.borrow(),
            LaneState {
                phase: LanePhase::Measurement,
                progress: LaneProgress {
                    offered: 8,
                    admitted: 4,
                    rejected: 3,
                    transport_failed: 1,
                    active: 4,
                    high_water: 4,
                },
            }
        );
    }

    #[test]
    fn dns_lane_rejects_udp_schedule_that_outlives_hold() {
        let one = NonZeroUsize::new(1).expect("nonzero rate");
        let two = NonZeroUsize::new(2).expect("nonzero capacity");
        let four = NonZeroUsize::new(4).expect("nonzero offered load");
        let error = DnsLaneConfig::new(
            two,
            one,
            two,
            two,
            two,
            NonZeroUsize::new(32).expect("nonzero HTTP/2 stream limit"),
            four,
            four,
            four,
            four,
            NonZeroUsize::new(100).expect("nonzero accept rate"),
            four,
            test_timing(),
            Duration::from_secs(10),
        )
        .expect_err("three-second arrival window must not equal the hold duration");

        assert_eq!(
            error,
            CanaryError::ArrivalWindowTooLong {
                field: "dns_udp_requests"
            }
        );
    }

    #[tokio::test]
    async fn endpoint_lane_saturates_rejects_recovers_and_shuts_down() {
        let config = EndpointLaneConfig::new(
            NonZeroUsize::new(2).expect("nonzero capacity"),
            NonZeroUsize::new(4).expect("nonzero offered load"),
            test_timing(),
            Duration::from_secs(10),
        )
        .expect("valid endpoint lane");

        let outcome = run_endpoint_lane(config, PhaseReporter::new().0)
            .await
            .expect("bounded endpoint lane");
        assert_eq!(outcome.offered, 4);
        assert_eq!(outcome.accepted, 2);
        assert_eq!(outcome.rejected, 2);
        assert_eq!(
            outcome.initial_conservation,
            super::WorkloadConservation::new(4, 2, 2, 0).expect("conserved endpoint outcomes")
        );
        assert!(outcome.recovered);
        assert_eq!(outcome.admission.maximum, 2);
        assert_eq!(outcome.admission.high_water, 2);
        assert_eq!(
            outcome.admission.rejections,
            u64::try_from(2 + outcome.continuity_rejections).expect("bounded endpoint rejections")
        );
        assert!(!outcome.admission.counter_exhausted);
        assert!(outcome.client_noq.active_connections_high_water <= 2);
        assert!(outcome.server_noq.active_connections_high_water <= 2);
        assert!(
            outcome.client_noq.packet_events_per_connection_high_water
                <= noq::DEFAULT_MAX_PACKET_EVENTS_PER_CONNECTION
        );
        assert!(
            outcome.server_noq.packet_events_per_connection_high_water
                <= noq::DEFAULT_MAX_PACKET_EVENTS_PER_CONNECTION
        );
        assert_eq!(outcome.client_noq.packet_event_rejections, 0);
        assert_eq!(outcome.server_noq.packet_event_rejections, 0);
        assert!(!outcome.client_noq.counter_exhausted);
        assert!(!outcome.server_noq.counter_exhausted);
        assert_eq!(outcome.accepted_connection_latency.samples, 2);
        assert_eq!(outcome.rejected_connection_latency.samples, 2);
        assert!(outcome.continuity_successes >= 3);
        assert_eq!(outcome.continuity_successes, outcome.continuity_rejections);
        assert!(outcome.shutdown <= Duration::from_secs(10));
    }

    #[tokio::test]
    async fn relay_lane_bounds_pending_and_sessions_then_recovers() {
        let config = RelayLaneConfig::new(
            NonZeroUsize::new(2).expect("nonzero pending capacity"),
            NonZeroUsize::new(2).expect("nonzero session capacity"),
            NonZeroUsize::new(1).expect("nonzero per-identity capacity"),
            NonZeroUsize::new(4).expect("nonzero pending offered load"),
            NonZeroUsize::new(4).expect("nonzero session offered load"),
            NonZeroUsize::new(1_000).expect("nonzero fill rate"),
            NonZeroUsize::new(2_000).expect("nonzero overload rate"),
            NonZeroUsize::new(4).expect("nonzero accept burst"),
            test_timing(),
            Duration::from_secs(10),
        )
        .expect("valid relay lane");

        let outcome = run_relay_lane(config, PhaseReporter::new().0)
            .await
            .expect("bounded relay lane");
        assert_eq!(outcome.pending_offered, 4);
        assert!(outcome.pending_rejections >= 1);
        assert_eq!(
            outcome.pending_conservation,
            super::WorkloadConservation::new(4, 2, 2, 0).expect("conserved pending relay outcomes")
        );
        assert_eq!(outcome.sessions_offered, 4);
        assert_eq!(outcome.sessions_accepted, 2);
        assert_eq!(outcome.sessions_rejected, 2);
        assert_eq!(
            outcome.session_conservation,
            super::WorkloadConservation::new(4, 2, 2, 0).expect("conserved relay outcomes")
        );
        assert_eq!(outcome.session_high_water, 2);
        assert!(outcome.endpoint_session_rejections >= 1);
        assert!(outcome.global_session_rejections + outcome.rate_rejections >= 1);
        assert_eq!(
            outcome
                .endpoint_session_rejections
                .checked_add(outcome.global_session_rejections)
                .and_then(|value| value.checked_add(outcome.session_pending_rejections))
                .and_then(|value| value.checked_add(outcome.rate_rejections))
                .expect("bounded relay rejection total"),
            u64::try_from(outcome.sessions_rejected + outcome.continuity_rejections)
                .expect("bounded offered relay rejections")
        );
        assert!(outcome.recovered);
        assert_eq!(outcome.accepted_session_latency.samples, 2);
        assert_eq!(outcome.rejected_session_latency.samples, 2);
        assert_eq!(outcome.fill_arrival.attempts, 2);
        assert_eq!(outcome.identity_overload_arrival.attempts, 1);
        assert_eq!(outcome.overload_arrival.attempts, 1);
        assert_eq!(
            outcome
                .rejection_client_outcomes
                .total()
                .expect("rejection client outcome total"),
            2
        );
        assert_eq!(
            outcome
                .continuity_client_outcomes
                .total()
                .expect("continuity client outcome total"),
            outcome.continuity_rejections
        );
        assert_eq!(outcome.rejection_client_outcomes.timed_out, 0);
        assert_eq!(outcome.continuity_client_outcomes.timed_out, 0);
        assert!(outcome.continuity_successes >= 3);
        assert_eq!(outcome.continuity_successes, outcome.continuity_rejections);
        assert!(outcome.shutdown <= Duration::from_secs(10));
    }

    #[tokio::test]
    async fn dns_lane_bounds_tcp_http_and_drains_all_work() {
        let two = NonZeroUsize::new(2).expect("nonzero capacity");
        let four = NonZeroUsize::new(4).expect("nonzero offered load");
        let config = DnsLaneConfig::new(
            two,
            NonZeroUsize::new(100).expect("nonzero UDP rate"),
            two,
            two,
            two,
            NonZeroUsize::new(32).expect("nonzero HTTP/2 stream limit"),
            four,
            four,
            four,
            four,
            NonZeroUsize::new(100).expect("nonzero accept rate"),
            four,
            test_timing(),
            Duration::from_secs(10),
        )
        .expect("valid DNS lane");

        let outcome = run_dns_lane(config, PhaseReporter::new().0)
            .await
            .expect("bounded DNS lane");
        assert_eq!(outcome.udp_offered, 4);
        assert_eq!(outcome.udp_completed + outcome.udp_timed_out, 4);
        assert_eq!(outcome.udp_completed, 2);
        assert_eq!(outcome.udp_rejections, 2);
        assert_eq!(
            outcome.udp_conservation,
            super::WorkloadConservation::new(4, 2, 2, 0).expect("conserved UDP outcomes")
        );
        assert_eq!(outcome.udp_arrival.attempts, 4);
        assert_eq!(
            u64::try_from(outcome.udp_completed)
                .expect("bounded UDP completion count")
                .checked_add(outcome.udp_rejections)
                .expect("bounded UDP admission outcomes"),
            4
        );
        assert_eq!(outcome.tcp_offered, 4);
        assert_eq!(outcome.tcp_active_high_water, 2);
        assert_eq!(outcome.tcp_rejections, 2);
        assert_eq!(
            outcome.tcp_conservation,
            super::WorkloadConservation::new(4, 2, 2, 0).expect("conserved TCP outcomes")
        );
        assert_eq!(outcome.http_connections_offered, 4);
        assert_eq!(outcome.http_connection_arrival.attempts, 4);
        assert_eq!(outcome.http_connections_active_high_water, 2);
        assert_eq!(outcome.http_connection_conservation.offered(), 4);
        assert_eq!(outcome.http_connection_conservation.admitted(), 2);
        assert_eq!(outcome.http_connection_conservation.rejected(), 2);
        assert_eq!(outcome.http_connection_conservation.transport_failed(), 0);
        assert!(outcome.http_connection_rejections >= 1);
        let initial_http_rejections = outcome
            .http_connection_capacity_rejections
            .checked_add(outcome.http_connection_rate_rejections)
            .expect("bounded initial HTTP rejections");
        assert_eq!(
            u64::try_from(outcome.http_connections_active_high_water)
                .expect("bounded HTTP high-water")
                .checked_add(initial_http_rejections)
                .expect("bounded HTTP connection outcomes"),
            u64::try_from(outcome.http_connections_offered).expect("bounded HTTP offered count")
        );
        assert_eq!(
            outcome.http_connection_rejections,
            initial_http_rejections
                .checked_add(
                    u64::try_from(outcome.continuity_http_connection_rejections)
                        .expect("bounded HTTP continuity rejections")
                )
                .expect("bounded total HTTP rejections")
        );
        assert_eq!(outcome.http_requests_offered, 4);
        assert_eq!(outcome.http_requests_admitted, 2);
        assert_eq!(
            outcome.http_request_conservation,
            super::WorkloadConservation::new(4, 2, 2, 0).expect("conserved HTTP request outcomes")
        );
        assert_eq!(outcome.http_requests_active_high_water, 2);
        assert!(outcome.http_request_rejections >= 1);
        assert!(outcome.http_request_recovered);
        assert!(outcome.continuity_udp_successes >= 3);
        assert_eq!(
            outcome.continuity_udp_successes,
            outcome.continuity_http_connection_rejections
        );
        assert_eq!(
            outcome.continuity_udp_successes,
            outcome.continuity_http_request_rejections
        );
        assert_eq!(outcome.udp_latency.samples, outcome.udp_completed);
        assert_eq!(
            outcome.http_request_latency.samples,
            usize::from(outcome.http_request_recovered)
        );
        assert!(outcome.recovered);
        assert_eq!(outcome.store_background_failures, 0);
        assert!(outcome.shutdown <= Duration::from_secs(10));
    }
}
