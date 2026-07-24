//! Deterministic configuration and acceptance model for the production resource canary.

#![forbid(unsafe_code)]

use std::{error::Error, fmt, net::SocketAddr, num::NonZeroUsize, time::Duration};

pub mod workloads;

const BASIS_POINTS_TOTAL: u16 = 10_000;
const EVIDENCE_WARMUP: Duration = Duration::from_secs(30);
const EVIDENCE_MEASUREMENT: Duration = Duration::from_secs(300);
const EVIDENCE_COOLDOWN: Duration = Duration::from_secs(30);
const EVIDENCE_SCALE_PERCENT: u8 = 100;
const MAX_SAMPLES: u64 = 4_096;
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(20);
const GIBIBYTE: u64 = 1024 * 1024 * 1024;

/// Invalid canary configuration or failed acceptance invariant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CanaryError {
    /// A named duration was zero.
    ZeroDuration {
        /// Configuration field.
        field: &'static str,
    },
    /// The requested sample set exceeds the retained artifact bound.
    TooManySamples {
        /// Requested samples.
        requested: u64,
        /// Largest supported sample count.
        maximum: u64,
    },
    /// A capacity could not be doubled without overflow.
    CapacityOverflow {
        /// Capacity field.
        field: &'static str,
    },
    /// A network target is not loopback.
    NonLoopback {
        /// Rejected address.
        address: SocketAddr,
    },
    /// Capacity evidence is restricted to the documented Linux x86-64 host class.
    UnsupportedProductionPlatform,
    /// CPU crossed the accepted usage ceiling.
    CpuHeadroom,
    /// RSS crossed the accepted usage ceiling.
    MemoryHeadroom,
    /// Descriptors crossed the accepted usage ceiling.
    FileDescriptorHeadroom,
    /// Resource-ratio arithmetic overflowed.
    ArithmeticOverflow,
    /// Shutdown exceeded the production deadline.
    ShutdownDeadline,
    /// The retained sample set is incomplete.
    IncompleteSamples,
    /// The admission ledger did not reach its configured maximum.
    AdmissionNotSaturated,
    /// The admission ledger exceeded its configured maximum.
    AdmissionExceeded,
    /// A 2x offered workload did not produce overload rejection evidence.
    MissingRejection,
    /// A bounded admission counter exhausted.
    CounterExhausted,
    /// A required Linux procfs field was absent.
    MissingProcField {
        /// Missing field.
        field: &'static str,
    },
    /// A Linux procfs field was malformed or out of range.
    InvalidProcField {
        /// Invalid field.
        field: &'static str,
    },
    /// Monotonic CPU counters moved backwards or did not advance.
    InvalidCpuDelta,
    /// The host has fewer online CPU cores than required.
    InsufficientCpuCores,
    /// The host exposes less total memory than required.
    InsufficientMemory,
    /// The host has less available memory than the clean-baseline requirement.
    BaselineMemoryPressure,
    /// The effective open-file limit is below the production requirement.
    InsufficientFileDescriptors,
    /// Artifact storage is below the production requirement.
    InsufficientStorage,
    /// Idle-baseline CPU use is too high.
    BaselineCpuPressure,
    /// One competing process consumes too much total host CPU.
    CompetingCpuPressure,
    /// One competing process consumes too much visible memory.
    CompetingMemoryPressure,
    /// Offered work does not exceed the admission capacity.
    InvalidOfferedLoad {
        /// Offered work.
        offered: usize,
        /// Configured admission capacity.
        capacity: usize,
    },
    /// A workload count exceeds the harness's compiled safety ceiling.
    WorkloadTooLarge {
        /// Workload field.
        field: &'static str,
        /// Requested count.
        requested: usize,
        /// Largest supported count.
        maximum: usize,
    },
    /// A paced campaign can outlive its deterministic admission hold.
    ArrivalWindowTooLong {
        /// Workload field.
        field: &'static str,
    },
}

impl fmt::Display for CanaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroDuration { field } => write!(f, "{field} must be greater than zero"),
            Self::TooManySamples { requested, maximum } => {
                write!(
                    f,
                    "requested {requested} samples exceeds supported maximum {maximum}"
                )
            }
            Self::CapacityOverflow { field } => {
                write!(f, "doubling {field} capacity overflowed")
            }
            Self::NonLoopback { address } => {
                write!(f, "canary address {address} is not loopback")
            }
            Self::UnsupportedProductionPlatform => {
                write!(f, "production evidence requires Linux x86-64")
            }
            Self::CpuHeadroom => write!(f, "CPU headroom is below the required threshold"),
            Self::MemoryHeadroom => write!(f, "memory headroom is below the required threshold"),
            Self::FileDescriptorHeadroom => {
                write!(
                    f,
                    "file-descriptor headroom is below the required threshold"
                )
            }
            Self::ArithmeticOverflow => write!(f, "resource acceptance arithmetic overflowed"),
            Self::ShutdownDeadline => write!(f, "shutdown exceeded the production deadline"),
            Self::IncompleteSamples => write!(f, "resource sample set is incomplete"),
            Self::AdmissionNotSaturated => {
                write!(f, "admission ledger did not reach its configured maximum")
            }
            Self::AdmissionExceeded => {
                write!(f, "admission ledger exceeded its configured maximum")
            }
            Self::MissingRejection => write!(f, "overload rejection evidence is missing"),
            Self::CounterExhausted => write!(f, "admission accounting counter exhausted"),
            Self::MissingProcField { field } => {
                write!(f, "required procfs field {field} is missing")
            }
            Self::InvalidProcField { field } => {
                write!(f, "procfs field {field} is invalid")
            }
            Self::InvalidCpuDelta => write!(f, "CPU counters regressed or did not advance"),
            Self::InsufficientCpuCores => {
                write!(f, "host has fewer CPU cores than the production minimum")
            }
            Self::InsufficientMemory => {
                write!(f, "host has less memory than the production minimum")
            }
            Self::BaselineMemoryPressure => {
                write!(
                    f,
                    "host available memory is below the clean-baseline requirement"
                )
            }
            Self::InsufficientFileDescriptors => {
                write!(f, "open-file limit is below the production minimum")
            }
            Self::InsufficientStorage => {
                write!(f, "artifact storage is below the production minimum")
            }
            Self::BaselineCpuPressure => {
                write!(f, "baseline CPU use exceeds the clean-host threshold")
            }
            Self::CompetingCpuPressure => {
                write!(f, "a competing process exceeds the CPU threshold")
            }
            Self::CompetingMemoryPressure => {
                write!(f, "a competing process exceeds the memory threshold")
            }
            Self::InvalidOfferedLoad { offered, capacity } => write!(
                f,
                "offered load {offered} must exceed admission capacity {capacity}"
            ),
            Self::WorkloadTooLarge {
                field,
                requested,
                maximum,
            } => write!(
                f,
                "{field} workload {requested} exceeds supported maximum {maximum}"
            ),
            Self::ArrivalWindowTooLong { field } => {
                write!(f, "{field} arrival window exceeds its admission hold")
            }
        }
    }
}

impl Error for CanaryError {}

/// Validated warm-up, measurement, cooldown, and sampling periods.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurationProfile {
    warmup: Duration,
    measurement: Duration,
    cooldown: Duration,
    sample_interval: Duration,
    minimum_samples: u64,
}

impl DurationProfile {
    /// Validates a timing profile and its retained sample count.
    pub fn new(
        warmup: Duration,
        measurement: Duration,
        cooldown: Duration,
        sample_interval: Duration,
    ) -> Result<Self, CanaryError> {
        validate_duration("warmup", warmup)?;
        validate_duration("measurement", measurement)?;
        validate_duration("cooldown", cooldown)?;
        validate_duration("sample_interval", sample_interval)?;

        let total_nanos = warmup
            .as_nanos()
            .checked_add(measurement.as_nanos())
            .and_then(|value| value.checked_add(cooldown.as_nanos()))
            .ok_or(CanaryError::ArithmeticOverflow)?;
        let interval_nanos = sample_interval.as_nanos();
        let rounded = total_nanos
            .checked_add(interval_nanos - 1)
            .ok_or(CanaryError::ArithmeticOverflow)?;
        let samples = rounded / interval_nanos;
        let samples = u64::try_from(samples).map_err(|_| CanaryError::TooManySamples {
            requested: u64::MAX,
            maximum: MAX_SAMPLES,
        })?;
        if samples > MAX_SAMPLES {
            return Err(CanaryError::TooManySamples {
                requested: samples,
                maximum: MAX_SAMPLES,
            });
        }

        Ok(Self {
            warmup,
            measurement,
            cooldown,
            sample_interval,
            minimum_samples: samples,
        })
    }

    /// Warm-up duration.
    pub const fn warmup(self) -> Duration {
        self.warmup
    }

    /// Measurement duration.
    pub const fn measurement(self) -> Duration {
        self.measurement
    }

    /// Cooldown duration.
    pub const fn cooldown(self) -> Duration {
        self.cooldown
    }

    /// Resource sample interval.
    pub const fn sample_interval(self) -> Duration {
        self.sample_interval
    }

    /// Minimum number of samples covering the configured timed phases.
    pub const fn minimum_samples(self) -> u64 {
        self.minimum_samples
    }
}

fn validate_duration(field: &'static str, duration: Duration) -> Result<(), CanaryError> {
    if duration.is_zero() {
        return Err(CanaryError::ZeroDuration { field });
    }
    Ok(())
}

/// Whether one invocation is capacity evidence or a reduced smoke check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanaryMode {
    /// Full timing and 100% workload scale.
    Evidence,
    /// Reduced timing or load that cannot close the operational audit.
    Smoke,
}

/// Process and source conditions required in addition to full timing and scale.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidencePrerequisites {
    all_lanes: bool,
    release_build: bool,
    source_clean: bool,
}

impl EvidencePrerequisites {
    /// Creates explicit evidence prerequisites.
    pub const fn new(all_lanes: bool, release_build: bool, source_clean: bool) -> Self {
        Self {
            all_lanes,
            release_build,
            source_clean,
        }
    }

    /// Prerequisites used to test only timing and scale classification.
    pub const fn ready() -> Self {
        Self::new(true, true, true)
    }

    const fn all_satisfied(self) -> bool {
        self.all_lanes && self.release_build && self.source_clean
    }
}

impl CanaryMode {
    /// Classifies one run without accepting a caller-provided evidence label.
    pub fn classify(
        timing: &DurationProfile,
        scale_percent: u8,
        prerequisites: EvidencePrerequisites,
    ) -> Self {
        if timing.warmup == EVIDENCE_WARMUP
            && timing.measurement == EVIDENCE_MEASUREMENT
            && timing.cooldown == EVIDENCE_COOLDOWN
            && timing.sample_interval == Duration::from_secs(1)
            && scale_percent == EVIDENCE_SCALE_PERCENT
            && prerequisites.all_satisfied()
        {
            Self::Evidence
        } else {
            Self::Smoke
        }
    }

    /// Returns whether this run can serve as retained capacity evidence.
    pub const fn is_evidence(self) -> bool {
        matches!(self, Self::Evidence)
    }
}

/// Bounded twice-production workload counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkloadProfile {
    dns_udp_capacity: NonZeroUsize,
    dns_tcp_capacity: NonZeroUsize,
    http_connection_capacity: NonZeroUsize,
    http_request_capacity: NonZeroUsize,
    http2_streams_per_connection: NonZeroUsize,
    http_accept_rate_per_second: NonZeroUsize,
    http_accept_burst: NonZeroUsize,
    dns_udp_requests: NonZeroUsize,
    dns_tcp_connections: NonZeroUsize,
    http_connections: NonZeroUsize,
    http_requests: NonZeroUsize,
    http_connections_per_second: NonZeroUsize,
    relay_pending_establishments: NonZeroUsize,
    relay_pending_capacity: NonZeroUsize,
    relay_sessions: NonZeroUsize,
    relay_session_capacity: NonZeroUsize,
    relay_sessions_per_identity: NonZeroUsize,
    relay_accept_rate_per_second: NonZeroUsize,
    relay_accept_burst: NonZeroUsize,
    endpoint_connections: NonZeroUsize,
    endpoint_connection_capacity: NonZeroUsize,
}

impl WorkloadProfile {
    /// Builds the twice-production workload with checked arithmetic.
    pub fn production_twice() -> Result<Self, CanaryError> {
        let dns = iroh_dns_server::config::LimitsConfig::default();
        let relay = iroh_relay::server::Limits::default();
        let endpoint = iroh::endpoint::EndpointLimits::default();
        let dns_udp_capacity = required_nonzero("max_dns_udp_requests", dns.max_dns_udp_requests)?;
        let dns_tcp_capacity =
            required_nonzero("max_dns_tcp_connections", dns.max_dns_tcp_connections)?;
        let http_connection_capacity =
            required_nonzero("max_http_connections", dns.max_http_connections)?;
        let http_request_capacity = required_nonzero("max_http_requests", dns.max_http_requests)?;
        let http2_streams_per_connection = required_nonzero(
            "max_http2_streams_per_connection",
            usize::try_from(dns.max_http2_streams_per_connection)
                .map_err(|_| CanaryError::ArithmeticOverflow)?,
        )?;
        let http_accept_rate_per_second = integral_rate(
            "http_accept_rate_per_second",
            dns.http_accept_rate_per_second
                .ok_or(CanaryError::CapacityOverflow {
                    field: "http_accept_rate_per_second",
                })?,
        )?;
        let http_accept_burst = required_nonzero(
            "http_accept_burst",
            dns.http_accept_burst.ok_or(CanaryError::CapacityOverflow {
                field: "http_accept_burst",
            })?,
        )?;
        let relay_pending_capacity = required_nonzero(
            "max_pending_establishments",
            relay.max_pending_establishments,
        )?;
        let relay_session_capacity =
            required_nonzero("max_registered_sessions", relay.max_registered_sessions)?;
        let relay_sessions_per_identity =
            required_nonzero("max_sessions_per_endpoint", relay.max_sessions_per_endpoint)?;
        let relay_accept_rate_per_second = integral_rate(
            "relay_accept_conn_limit",
            iroh_relay::server::DEFAULT_ACCEPT_CONN_LIMIT,
        )?;
        let relay_accept_burst = required_nonzero(
            "relay_accept_conn_burst",
            iroh_relay::server::DEFAULT_ACCEPT_CONN_BURST,
        )?;
        let endpoint_connection_capacity = endpoint.max_connections();
        Ok(Self {
            dns_udp_capacity,
            dns_tcp_capacity,
            http_connection_capacity,
            http_request_capacity,
            http2_streams_per_connection,
            http_accept_rate_per_second,
            http_accept_burst,
            dns_udp_requests: twice("max_dns_udp_requests", dns_udp_capacity.get())?,
            dns_tcp_connections: twice("max_dns_tcp_connections", dns_tcp_capacity.get())?,
            http_connections: twice("max_http_connections", http_connection_capacity.get())?,
            http_requests: twice("max_http_requests", http_request_capacity.get())?,
            http_connections_per_second: twice(
                "http_accept_rate_per_second",
                http_accept_rate_per_second.get(),
            )?,
            relay_pending_establishments: twice(
                "max_pending_establishments",
                relay_pending_capacity.get(),
            )?,
            relay_pending_capacity,
            relay_sessions: twice("max_registered_sessions", relay_session_capacity.get())?,
            relay_session_capacity,
            relay_sessions_per_identity,
            relay_accept_rate_per_second,
            relay_accept_burst,
            endpoint_connections: twice("max_connections", endpoint_connection_capacity.get())?,
            endpoint_connection_capacity,
        })
    }

    /// Production DNS UDP request capacity.
    pub const fn dns_udp_capacity(self) -> usize {
        self.dns_udp_capacity.get()
    }

    /// Production DNS TCP connection capacity.
    pub const fn dns_tcp_capacity(self) -> usize {
        self.dns_tcp_capacity.get()
    }

    /// Production HTTP connection capacity.
    pub const fn http_connection_capacity(self) -> usize {
        self.http_connection_capacity.get()
    }

    /// Production HTTP request capacity.
    pub const fn http_request_capacity(self) -> usize {
        self.http_request_capacity.get()
    }

    /// Production HTTP/2 stream limit per connection.
    pub const fn http2_streams_per_connection(self) -> usize {
        self.http2_streams_per_connection.get()
    }

    /// Production HTTP connection accept rate.
    pub const fn http_accept_rate_per_second(self) -> usize {
        self.http_accept_rate_per_second.get()
    }

    /// Production HTTP connection accept burst.
    pub const fn http_accept_burst(self) -> usize {
        self.http_accept_burst.get()
    }

    /// Offered concurrent DNS UDP requests.
    pub const fn dns_udp_requests(self) -> usize {
        self.dns_udp_requests.get()
    }

    /// Offered DNS TCP connections.
    pub const fn dns_tcp_connections(self) -> usize {
        self.dns_tcp_connections.get()
    }

    /// Offered HTTP connections.
    pub const fn http_connections(self) -> usize {
        self.http_connections.get()
    }

    /// Offered in-flight HTTP requests.
    pub const fn http_requests(self) -> usize {
        self.http_requests.get()
    }

    /// Offered new HTTP connections per second.
    pub const fn http_connections_per_second(self) -> usize {
        self.http_connections_per_second.get()
    }

    /// Offered pending relay establishments.
    pub const fn relay_pending_establishments(self) -> usize {
        self.relay_pending_establishments.get()
    }

    /// Production relay pending-establishment capacity.
    pub const fn relay_pending_capacity(self) -> usize {
        self.relay_pending_capacity.get()
    }

    /// Offered authenticated relay sessions.
    pub const fn relay_sessions(self) -> usize {
        self.relay_sessions.get()
    }

    /// Production relay registered-session capacity.
    pub const fn relay_session_capacity(self) -> usize {
        self.relay_session_capacity.get()
    }

    /// Maximum offered sessions for one relay identity.
    pub const fn relay_sessions_per_identity(self) -> usize {
        self.relay_sessions_per_identity.get()
    }

    /// Production relay accept rate.
    pub const fn relay_accept_rate_per_second(self) -> usize {
        self.relay_accept_rate_per_second.get()
    }

    /// Production relay accept burst.
    pub const fn relay_accept_burst(self) -> usize {
        self.relay_accept_burst.get()
    }

    /// Offered endpoint connections.
    pub const fn endpoint_connections(self) -> usize {
        self.endpoint_connections.get()
    }

    /// Production endpoint connection capacity.
    pub const fn endpoint_connection_capacity(self) -> usize {
        self.endpoint_connection_capacity.get()
    }
}

fn twice(field: &'static str, value: usize) -> Result<NonZeroUsize, CanaryError> {
    let value = value
        .checked_mul(2)
        .ok_or(CanaryError::CapacityOverflow { field })?;
    NonZeroUsize::new(value).ok_or(CanaryError::CapacityOverflow { field })
}

fn required_nonzero(field: &'static str, value: usize) -> Result<NonZeroUsize, CanaryError> {
    NonZeroUsize::new(value).ok_or(CanaryError::CapacityOverflow { field })
}

fn integral_rate(field: &'static str, value: f64) -> Result<NonZeroUsize, CanaryError> {
    if !value.is_finite() || value.fract() != 0.0 {
        return Err(CanaryError::CapacityOverflow { field });
    }
    let parsed = value
        .to_string()
        .parse::<usize>()
        .map_err(|_| CanaryError::CapacityOverflow { field })?;
    required_nonzero(field, parsed)
}

/// Static requirements for the documented minimum production host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostRequirements {
    cpu_cores: usize,
    memory_bytes: u64,
    file_descriptors: u64,
    free_storage_bytes: u64,
}

impl HostRequirements {
    /// Returns the documented minimum host profile.
    pub const fn production_minimum() -> Self {
        Self {
            cpu_cores: 8,
            memory_bytes: 30 * GIBIBYTE,
            file_descriptors: 8_192,
            free_storage_bytes: 20 * GIBIBYTE,
        }
    }

    /// Required online CPU cores.
    pub const fn cpu_cores(self) -> usize {
        self.cpu_cores
    }

    /// Required visible memory.
    pub const fn memory_bytes(self) -> u64 {
        self.memory_bytes
    }

    /// Required effective file-descriptor limit.
    pub const fn file_descriptors(self) -> u64 {
        self.file_descriptors
    }

    /// Required available artifact storage.
    pub const fn free_storage_bytes(self) -> u64 {
        self.free_storage_bytes
    }
}

/// Aggregate Linux CPU counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuTicks {
    total: u64,
    idle: u64,
}

impl CpuTicks {
    /// Sum of all aggregate CPU state ticks.
    pub const fn total(self) -> u64 {
        self.total
    }

    /// Idle and I/O-wait ticks.
    pub const fn idle(self) -> u64 {
        self.idle
    }
}

/// Parses the aggregate `cpu` row from Linux `/proc/stat`.
pub fn parse_cpu_ticks(input: &str) -> Result<CpuTicks, CanaryError> {
    let row = input
        .lines()
        .find(|line| line.starts_with("cpu "))
        .ok_or(CanaryError::MissingProcField { field: "cpu" })?;
    let values = row
        .split_whitespace()
        .skip(1)
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| CanaryError::InvalidProcField { field: "cpu" })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if values.len() < 5 {
        return Err(CanaryError::InvalidProcField { field: "cpu" });
    }
    // Linux already includes guest and guest_nice in user and nice. Summing
    // only the first eight fields avoids double-counting virtual CPU time.
    let total = values.iter().take(8).try_fold(0u64, |sum, value| {
        sum.checked_add(*value)
            .ok_or(CanaryError::InvalidProcField { field: "cpu" })
    })?;
    let idle = values[3]
        .checked_add(values[4])
        .ok_or(CanaryError::InvalidProcField { field: "cpu" })?;
    Ok(CpuTicks { total, idle })
}

/// Calculates host CPU use between two monotonic samples, where 10,000 is 100%.
pub fn cpu_usage_basis_points(before: CpuTicks, after: CpuTicks) -> Result<u16, CanaryError> {
    let total_delta = after
        .total
        .checked_sub(before.total)
        .ok_or(CanaryError::InvalidCpuDelta)?;
    let idle_delta = after
        .idle
        .checked_sub(before.idle)
        .ok_or(CanaryError::InvalidCpuDelta)?;
    if total_delta == 0 || idle_delta > total_delta {
        return Err(CanaryError::InvalidCpuDelta);
    }
    let busy_delta = total_delta - idle_delta;
    let scaled = busy_delta
        .checked_mul(u64::from(BASIS_POINTS_TOTAL))
        .ok_or(CanaryError::ArithmeticOverflow)?;
    let basis_points = scaled / total_delta;
    u16::try_from(basis_points).map_err(|_| CanaryError::ArithmeticOverflow)
}

/// Parsed Linux memory counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemorySnapshot {
    total_bytes: u64,
    available_bytes: u64,
    swap_used_bytes: u64,
}

impl MemorySnapshot {
    /// Total visible memory.
    pub const fn total_bytes(self) -> u64 {
        self.total_bytes
    }

    /// Memory available without swapping.
    pub const fn available_bytes(self) -> u64 {
        self.available_bytes
    }

    /// Historical allocated swap.
    pub const fn swap_used_bytes(self) -> u64 {
        self.swap_used_bytes
    }
}

/// Parses the required byte counters from Linux `/proc/meminfo`.
pub fn parse_meminfo(input: &str) -> Result<MemorySnapshot, CanaryError> {
    let total_bytes = parse_kib_field(input, "MemTotal")?;
    let available_bytes = parse_kib_field(input, "MemAvailable")?;
    let swap_total_bytes = parse_kib_field(input, "SwapTotal")?;
    let swap_free_bytes = parse_kib_field(input, "SwapFree")?;
    let swap_used_bytes = swap_total_bytes
        .checked_sub(swap_free_bytes)
        .ok_or(CanaryError::InvalidProcField { field: "SwapFree" })?;
    Ok(MemorySnapshot {
        total_bytes,
        available_bytes,
        swap_used_bytes,
    })
}

fn parse_kib_field(input: &str, field: &'static str) -> Result<u64, CanaryError> {
    let prefix = format!("{field}:");
    let row = input
        .lines()
        .find(|line| line.starts_with(&prefix))
        .ok_or(CanaryError::MissingProcField { field })?;
    let kib = row
        .split_whitespace()
        .nth(1)
        .ok_or(CanaryError::InvalidProcField { field })?
        .parse::<u64>()
        .map_err(|_| CanaryError::InvalidProcField { field })?;
    kib.checked_mul(1024)
        .ok_or(CanaryError::InvalidProcField { field })
}

/// Parsed per-process resource state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessSnapshot {
    rss_bytes: u64,
    threads: usize,
}

impl ProcessSnapshot {
    /// Resident memory.
    pub const fn rss_bytes(self) -> u64 {
        self.rss_bytes
    }

    /// Kernel thread count.
    pub const fn threads(self) -> usize {
        self.threads
    }
}

/// Parses RSS and thread count from Linux `/proc/<pid>/status`.
pub fn parse_process_status(input: &str) -> Result<ProcessSnapshot, CanaryError> {
    let rss_bytes = parse_kib_field(input, "VmRSS")?;
    let threads = parse_scalar_field(input, "Threads")?;
    Ok(ProcessSnapshot { rss_bytes, threads })
}

fn parse_scalar_field(input: &str, field: &'static str) -> Result<usize, CanaryError> {
    let prefix = format!("{field}:");
    let row = input
        .lines()
        .find(|line| line.starts_with(&prefix))
        .ok_or(CanaryError::MissingProcField { field })?;
    row.split_whitespace()
        .nth(1)
        .ok_or(CanaryError::InvalidProcField { field })?
        .parse::<usize>()
        .map_err(|_| CanaryError::InvalidProcField { field })
}

/// Parses the effective soft open-file limit from Linux `/proc/self/limits`.
pub fn parse_open_file_limit(input: &str) -> Result<u64, CanaryError> {
    let row = input
        .lines()
        .find(|line| line.starts_with("Max open files"))
        .ok_or(CanaryError::MissingProcField {
            field: "Max open files",
        })?;
    row["Max open files".len()..]
        .split_whitespace()
        .next()
        .ok_or(CanaryError::InvalidProcField {
            field: "Max open files",
        })?
        .parse::<u64>()
        .map_err(|_| CanaryError::InvalidProcField {
            field: "Max open files",
        })
}

/// Parses user and system CPU ticks from Linux `/proc/<pid>/stat`.
pub fn parse_process_cpu_ticks(input: &str) -> Result<u64, CanaryError> {
    let command_end = input
        .rfind(')')
        .ok_or(CanaryError::InvalidProcField { field: "pid stat" })?;
    let fields = input[command_end + 1..]
        .split_whitespace()
        .collect::<Vec<_>>();
    let user = fields
        .get(11)
        .ok_or(CanaryError::InvalidProcField { field: "pid utime" })?
        .parse::<u64>()
        .map_err(|_| CanaryError::InvalidProcField { field: "pid utime" })?;
    let system = fields
        .get(12)
        .ok_or(CanaryError::InvalidProcField { field: "pid stime" })?
        .parse::<u64>()
        .map_err(|_| CanaryError::InvalidProcField { field: "pid stime" })?;
    user.checked_add(system)
        .ok_or(CanaryError::InvalidProcField { field: "pid stat" })
}

/// Parses available 1,024-byte blocks from POSIX `df -Pk` output.
pub fn parse_storage_available_bytes(input: &str) -> Result<u64, CanaryError> {
    let row = input.lines().nth(1).ok_or(CanaryError::MissingProcField {
        field: "df available",
    })?;
    let blocks = row
        .split_whitespace()
        .nth(3)
        .ok_or(CanaryError::InvalidProcField {
            field: "df available",
        })?
        .parse::<u64>()
        .map_err(|_| CanaryError::InvalidProcField {
            field: "df available",
        })?;
    blocks
        .checked_mul(1024)
        .ok_or(CanaryError::InvalidProcField {
            field: "df available",
        })
}

/// Observed host state evaluated before any canary listener or worker starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostObservation {
    /// Online CPU cores.
    pub cpu_cores: usize,
    /// Total visible memory.
    pub memory_total_bytes: u64,
    /// Immediately available memory.
    pub memory_available_bytes: u64,
    /// Effective soft open-file limit.
    pub file_descriptor_limit: u64,
    /// Free build and artifact storage.
    pub free_storage_bytes: u64,
    /// Sampled idle-baseline CPU use.
    pub baseline_cpu_basis_points: u16,
    /// Largest one-process share of total host CPU.
    pub largest_competitor_cpu_basis_points: u16,
    /// Largest competing process RSS.
    pub largest_competitor_rss_bytes: u64,
}

/// Applies the documented minimum-host and clean-baseline requirements.
pub fn evaluate_host_preflight(
    observed: &HostObservation,
    required: HostRequirements,
) -> Result<(), CanaryError> {
    if observed.cpu_cores < required.cpu_cores {
        return Err(CanaryError::InsufficientCpuCores);
    }
    if observed.memory_total_bytes < required.memory_bytes {
        return Err(CanaryError::InsufficientMemory);
    }
    require_ratio_at_least(
        observed.memory_available_bytes,
        observed.memory_total_bytes,
        7_000,
        CanaryError::BaselineMemoryPressure,
    )?;
    if observed.file_descriptor_limit < required.file_descriptors {
        return Err(CanaryError::InsufficientFileDescriptors);
    }
    if observed.free_storage_bytes < required.free_storage_bytes {
        return Err(CanaryError::InsufficientStorage);
    }
    if observed.baseline_cpu_basis_points > 2_000 {
        return Err(CanaryError::BaselineCpuPressure);
    }
    if observed.largest_competitor_cpu_basis_points >= 2_000 {
        return Err(CanaryError::CompetingCpuPressure);
    }
    require_ratio_below(
        observed.largest_competitor_rss_bytes,
        observed.memory_total_bytes,
        2_000,
        CanaryError::CompetingMemoryPressure,
    )?;
    Ok(())
}

fn require_ratio_at_least(
    value: u64,
    total: u64,
    minimum_basis_points: u16,
    failure: CanaryError,
) -> Result<(), CanaryError> {
    let value_scaled = value
        .checked_mul(u64::from(BASIS_POINTS_TOTAL))
        .ok_or(CanaryError::ArithmeticOverflow)?;
    let minimum_scaled = total
        .checked_mul(u64::from(minimum_basis_points))
        .ok_or(CanaryError::ArithmeticOverflow)?;
    if value_scaled < minimum_scaled {
        return Err(failure);
    }
    Ok(())
}

fn require_ratio_below(
    used: u64,
    total: u64,
    maximum_usage_basis_points: u16,
    failure: CanaryError,
) -> Result<(), CanaryError> {
    let used_scaled = used
        .checked_mul(u64::from(BASIS_POINTS_TOTAL))
        .ok_or(CanaryError::ArithmeticOverflow)?;
    let maximum_scaled = total
        .checked_mul(u64::from(maximum_usage_basis_points))
        .ok_or(CanaryError::ArithmeticOverflow)?;
    if used_scaled >= maximum_scaled {
        return Err(failure);
    }
    Ok(())
}

/// Rejects any address that could send canary traffic off-host.
pub fn require_loopback(address: SocketAddr) -> Result<(), CanaryError> {
    if !address.ip().is_loopback() {
        return Err(CanaryError::NonLoopback { address });
    }
    Ok(())
}

/// Restricts retained production evidence to the documented host platform.
pub fn require_production_platform(os: &str, architecture: &str) -> Result<(), CanaryError> {
    if os != "linux" || architecture != "x86_64" {
        return Err(CanaryError::UnsupportedProductionPlatform);
    }
    Ok(())
}

/// Required unused resource percentage represented as basis points.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeadroomThreshold {
    required_basis_points: u16,
}

impl HeadroomThreshold {
    /// The production requirement of 30% unused capacity.
    pub const fn thirty_percent() -> Self {
        Self {
            required_basis_points: 3_000,
        }
    }

    const fn maximum_usage_basis_points(self) -> u16 {
        BASIS_POINTS_TOTAL - self.required_basis_points
    }
}

/// Point-in-time admission evidence from the intentionally saturated ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionSample {
    /// Configured admission maximum.
    pub maximum: usize,
    /// Largest observed active count.
    pub high_water: usize,
    /// Number of rejected admissions.
    pub rejections: u64,
    /// Whether checked accounting exhausted.
    pub counter_exhausted: bool,
}

/// Inputs required for deterministic acceptance evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptanceInput {
    /// Peak total CPU usage, where 10,000 is 100%.
    pub peak_cpu_basis_points: u16,
    /// Host-visible memory.
    pub visible_memory_bytes: u64,
    /// Peak process resident memory.
    pub peak_rss_bytes: u64,
    /// Effective descriptor limit.
    pub file_descriptor_limit: u64,
    /// Peak open descriptor count.
    pub peak_file_descriptors: u64,
    /// Measured lane shutdown duration.
    pub shutdown: Duration,
    /// Whether every expected resource sample was retained.
    pub samples_complete: bool,
    /// Saturated admission ledger evidence.
    pub admission: AdmissionSample,
}

/// Applies the production headroom and bounded-admission acceptance contract.
pub fn evaluate_acceptance(
    input: &AcceptanceInput,
    threshold: HeadroomThreshold,
) -> Result<(), CanaryError> {
    let maximum_usage = threshold.maximum_usage_basis_points();
    if input.peak_cpu_basis_points > maximum_usage {
        return Err(CanaryError::CpuHeadroom);
    }
    require_ratio_within(
        input.peak_rss_bytes,
        input.visible_memory_bytes,
        maximum_usage,
        CanaryError::MemoryHeadroom,
    )?;
    require_ratio_within(
        input.peak_file_descriptors,
        input.file_descriptor_limit,
        maximum_usage,
        CanaryError::FileDescriptorHeadroom,
    )?;
    if input.shutdown > SHUTDOWN_DEADLINE {
        return Err(CanaryError::ShutdownDeadline);
    }
    if !input.samples_complete {
        return Err(CanaryError::IncompleteSamples);
    }
    if input.admission.counter_exhausted {
        return Err(CanaryError::CounterExhausted);
    }
    if input.admission.high_water > input.admission.maximum {
        return Err(CanaryError::AdmissionExceeded);
    }
    if input.admission.high_water < input.admission.maximum {
        return Err(CanaryError::AdmissionNotSaturated);
    }
    if input.admission.rejections == 0 {
        return Err(CanaryError::MissingRejection);
    }
    Ok(())
}

fn require_ratio_within(
    used: u64,
    total: u64,
    maximum_usage_basis_points: u16,
    failure: CanaryError,
) -> Result<(), CanaryError> {
    let used_scaled = used
        .checked_mul(u64::from(BASIS_POINTS_TOTAL))
        .ok_or(CanaryError::ArithmeticOverflow)?;
    let maximum_scaled = total
        .checked_mul(u64::from(maximum_usage_basis_points))
        .ok_or(CanaryError::ArithmeticOverflow)?;
    if used_scaled > maximum_scaled {
        return Err(failure);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };

    use super::{
        AcceptanceInput, AdmissionSample, CanaryMode, DurationProfile, EvidencePrerequisites,
        HeadroomThreshold, HostObservation, HostRequirements, WorkloadProfile,
        cpu_usage_basis_points, evaluate_acceptance, evaluate_host_preflight, parse_cpu_ticks,
        parse_meminfo, parse_open_file_limit, parse_process_cpu_ticks, parse_process_status,
        parse_storage_available_bytes, require_loopback, require_production_platform,
    };

    #[test]
    fn duration_profile_rejects_zero_and_too_many_samples() {
        assert!(
            DurationProfile::new(
                Duration::ZERO,
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
            )
            .is_err()
        );
        assert!(
            DurationProfile::new(
                Duration::from_secs(1),
                Duration::from_secs(24 * 60 * 60),
                Duration::from_secs(1),
                Duration::from_millis(1),
            )
            .is_err()
        );
    }

    #[test]
    fn evidence_mode_requires_full_timing_and_scale() {
        let full = DurationProfile::new(
            Duration::from_secs(30),
            Duration::from_secs(300),
            Duration::from_secs(30),
            Duration::from_secs(1),
        )
        .expect("evidence duration profile");
        assert!(CanaryMode::classify(&full, 100, EvidencePrerequisites::ready()).is_evidence());
        assert_eq!(full.minimum_samples(), 360);

        let smoke = DurationProfile::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .expect("smoke duration profile");
        assert!(!CanaryMode::classify(&smoke, 100, EvidencePrerequisites::ready()).is_evidence());
        assert!(!CanaryMode::classify(&full, 10, EvidencePrerequisites::ready()).is_evidence());

        let longer = DurationProfile::new(
            Duration::from_secs(31),
            Duration::from_secs(301),
            Duration::from_secs(31),
            Duration::from_secs(1),
        )
        .expect("longer smoke duration profile");
        assert!(!CanaryMode::classify(&longer, 100, EvidencePrerequisites::ready()).is_evidence());

        let sparse = DurationProfile::new(
            Duration::from_secs(30),
            Duration::from_secs(300),
            Duration::from_secs(30),
            Duration::from_secs(360),
        )
        .expect("bounded sparse profile");
        assert!(!CanaryMode::classify(&sparse, 100, EvidencePrerequisites::ready()).is_evidence());
    }

    #[test]
    fn evidence_mode_requires_all_lanes_release_and_clean_source() {
        let full = DurationProfile::new(
            Duration::from_secs(30),
            Duration::from_secs(300),
            Duration::from_secs(30),
            Duration::from_secs(1),
        )
        .expect("evidence duration profile");
        for prerequisites in [
            EvidencePrerequisites::new(false, true, true),
            EvidencePrerequisites::new(true, false, true),
            EvidencePrerequisites::new(true, true, false),
        ] {
            assert!(!CanaryMode::classify(&full, 100, prerequisites).is_evidence());
        }
    }

    #[test]
    fn workload_profile_uses_checked_twice_capacity_arithmetic() {
        let profile = WorkloadProfile::production_twice().expect("production workload");
        assert_eq!(profile.dns_udp_requests(), 2_048);
        assert_eq!(profile.dns_tcp_connections(), 512);
        assert_eq!(profile.http_connections(), 1_024);
        assert_eq!(profile.http_requests(), 2_048);
        assert_eq!(profile.http_connections_per_second(), 400);
        assert_eq!(profile.relay_pending_establishments(), 512);
        assert_eq!(profile.relay_sessions(), 8_192);
        assert_eq!(profile.relay_sessions_per_identity(), 4);
        assert_eq!(profile.endpoint_connections(), 4_096);
    }

    #[test]
    fn host_profile_matches_documented_minimum() {
        let requirements = HostRequirements::production_minimum();
        assert_eq!(requirements.cpu_cores(), 8);
        assert_eq!(requirements.memory_bytes(), 30 * 1024 * 1024 * 1024);
        assert_eq!(requirements.file_descriptors(), 8_192);
        assert_eq!(requirements.free_storage_bytes(), 20 * 1024 * 1024 * 1024);
    }

    #[test]
    fn non_loopback_addresses_fail_closed() {
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        assert!(require_loopback(loopback).is_ok());

        let external = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 8080);
        assert!(require_loopback(external).is_err());
    }

    #[test]
    fn production_platform_is_linux_x86_64_only() {
        assert_eq!(require_production_platform("linux", "x86_64"), Ok(()));
        assert!(require_production_platform("linux", "aarch64").is_err());
        assert!(require_production_platform("windows", "x86_64").is_err());
    }

    #[test]
    fn exactly_thirty_percent_headroom_passes() {
        let threshold = HeadroomThreshold::thirty_percent();
        let input = AcceptanceInput {
            peak_cpu_basis_points: 7_000,
            visible_memory_bytes: 10_000,
            peak_rss_bytes: 7_000,
            file_descriptor_limit: 10_000,
            peak_file_descriptors: 7_000,
            shutdown: Duration::from_secs(20),
            samples_complete: true,
            admission: AdmissionSample {
                maximum: 2_048,
                high_water: 2_048,
                rejections: 1,
                counter_exhausted: false,
            },
        };

        assert!(evaluate_acceptance(&input, threshold).is_ok());
    }

    #[test]
    fn acceptance_rejects_threshold_overrun_or_missing_overload() {
        let threshold = HeadroomThreshold::thirty_percent();
        let mut input = AcceptanceInput {
            peak_cpu_basis_points: 7_001,
            visible_memory_bytes: 10_000,
            peak_rss_bytes: 7_000,
            file_descriptor_limit: 10_000,
            peak_file_descriptors: 7_000,
            shutdown: Duration::from_secs(20),
            samples_complete: true,
            admission: AdmissionSample {
                maximum: 2_048,
                high_water: 2_048,
                rejections: 1,
                counter_exhausted: false,
            },
        };
        assert!(evaluate_acceptance(&input, threshold).is_err());

        input.peak_cpu_basis_points = 7_000;
        input.admission.rejections = 0;
        assert!(evaluate_acceptance(&input, threshold).is_err());

        input.admission.rejections = 1;
        input.admission.high_water = 2_049;
        assert!(evaluate_acceptance(&input, threshold).is_err());

        input.admission.high_water = 2_048;
        input.samples_complete = false;
        assert!(evaluate_acceptance(&input, threshold).is_err());
    }

    #[test]
    fn proc_parsers_extract_bounded_resource_fields() {
        let cpu = parse_cpu_ticks("cpu  100 20 30 400 10 5 5 0 0 0\ncpu0 1 2 3 4\n")
            .expect("aggregate CPU ticks");
        assert_eq!(cpu.total(), 570);
        assert_eq!(cpu.idle(), 410);

        let memory = parse_meminfo(
            "MemTotal:       33554432 kB\nMemAvailable:   25165824 kB\nSwapTotal:       4194304 kB\nSwapFree:        1048576 kB\n",
        )
        .expect("memory fields");
        assert_eq!(memory.total_bytes(), 32 * 1024 * 1024 * 1024);
        assert_eq!(memory.available_bytes(), 24 * 1024 * 1024 * 1024);
        assert_eq!(memory.swap_used_bytes(), 3 * 1024 * 1024 * 1024);

        let process =
            parse_process_status("Name:\tresource-canary\nVmRSS:\t   12345 kB\nThreads:\t17\n")
                .expect("process status");
        assert_eq!(process.rss_bytes(), 12_641_280);
        assert_eq!(process.threads(), 17);

        let limit = parse_open_file_limit(
            "Limit                     Soft Limit           Hard Limit           Units\nMax open files            8192                 16384                files\n",
        )
        .expect("open-file limit");
        assert_eq!(limit, 8_192);
    }

    #[test]
    fn cpu_delta_uses_total_host_capacity() {
        let before = parse_cpu_ticks("cpu 100 0 100 800 0 0 0 0 0 0\n").expect("before");
        let after = parse_cpu_ticks("cpu 200 0 150 850 0 0 0 0 0 0\n").expect("after");
        assert_eq!(
            cpu_usage_basis_points(before, after).expect("CPU usage"),
            7_500
        );
        assert!(cpu_usage_basis_points(after, before).is_err());
    }

    #[test]
    fn cpu_parser_does_not_double_count_guest_time() {
        let ticks =
            parse_cpu_ticks("cpu 100 20 30 400 10 5 4 3 70 11\n").expect("aggregate CPU ticks");
        assert_eq!(ticks.total(), 572);
        assert_eq!(ticks.idle(), 410);
    }

    #[test]
    fn host_preflight_rejects_competitor_at_twenty_percent() {
        let requirements = HostRequirements::production_minimum();
        let exact = HostObservation {
            cpu_cores: 8,
            memory_total_bytes: 30 * 1024 * 1024 * 1024,
            memory_available_bytes: 21 * 1024 * 1024 * 1024,
            file_descriptor_limit: 8_192,
            free_storage_bytes: 20 * 1024 * 1024 * 1024,
            baseline_cpu_basis_points: 2_000,
            largest_competitor_cpu_basis_points: 1_999,
            largest_competitor_rss_bytes: 6 * 1024 * 1024 * 1024 - 1,
        };
        assert!(evaluate_host_preflight(&exact, requirements).is_ok());

        let mut pressured = exact;
        pressured.memory_available_bytes -= 1;
        assert!(evaluate_host_preflight(&pressured, requirements).is_err());

        pressured = exact;
        pressured.largest_competitor_cpu_basis_points = 2_000;
        assert!(evaluate_host_preflight(&pressured, requirements).is_err());

        pressured = exact;
        pressured.largest_competitor_rss_bytes = 6 * 1024 * 1024 * 1024;
        assert!(evaluate_host_preflight(&pressured, requirements).is_err());
    }

    #[test]
    fn process_stat_parser_handles_spaces_in_command_name() {
        let stat = "42 (qemu system worker) R 1 2 3 4 5 6 7 8 9 10 100 25 0 0 0 0 0 0 0\n";
        assert_eq!(
            parse_process_cpu_ticks(stat).expect("process CPU ticks"),
            125
        );
    }

    #[test]
    fn storage_parser_converts_posix_kibibyte_blocks() {
        let df = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 100000000 50000000 40000000 56% /\n";
        assert_eq!(
            parse_storage_available_bytes(df).expect("available storage"),
            40_960_000_000
        );
    }
}
