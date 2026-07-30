#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    error::Error,
    fs::{self, File, OpenOptions},
    future::Future,
    io::{self, Read, Write},
    num::{NonZeroU8, NonZeroU64, NonZeroUsize},
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, ExitCode},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use clap::{Parser, Subcommand, ValueEnum};
use krikos_bench::canary::{
    AcceptanceInput, AdmissionSample, CanaryError, CanaryMode, DurationProfile,
    EvidencePrerequisites, HeadroomThreshold, HostObservation, HostProfile, WorkloadProfile,
    cpu_usage_basis_points, evaluate_acceptance, evaluate_host_preflight, parse_cpu_ticks,
    parse_meminfo, parse_open_file_limit, parse_process_cpu_ticks, parse_process_status,
    parse_storage_available_bytes, require_production_platform,
    workloads::{
        ArrivalSummary, DnsLaneConfig, DnsLaneOutcome, EndpointLaneConfig, EndpointLaneOutcome,
        LanePhase, LaneProgress, LaneState, LaneTiming, LatencySummary, PhaseReporter,
        RelayLaneConfig, RelayLaneOutcome, run_dns_lane, run_endpoint_lane, run_relay_lane,
    },
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

const MAX_BASELINE_SECONDS: u64 = 60;
const MAX_PROCESSES: usize = 65_536;
const MAX_RESOURCE_SAMPLES: usize = 4_096;
const MAX_HOST_LABEL_BYTES: usize = 256;
const MAX_ARTIFACT_FILES: usize = 32;

#[derive(Debug, Parser)]
#[command(about = "Bounded loopback-only production resource canary")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate the minimum host and clean idle baseline without starting listeners.
    Preflight {
        /// Static host qualification applied before starting any workload.
        #[arg(long, value_enum, default_value_t = HostProfileArg::ProductionMinimum)]
        host_profile: HostProfileArg,
        /// Seconds over which idle CPU and competing process use are measured.
        #[arg(long, default_value = "5")]
        baseline_seconds: NonZeroU64,
        /// Parent directory beneath which an immutable report directory is created.
        #[arg(long, default_value = "target/resource-canary")]
        output: PathBuf,
    },
    /// Run one or all bounded loopback workload lanes after a clean-host preflight.
    Run {
        /// Static host qualification applied before starting any workload.
        #[arg(long, value_enum, default_value_t = HostProfileArg::ProductionMinimum)]
        host_profile: HostProfileArg,
        /// Workload lane to execute.
        #[arg(long, value_enum, default_value_t = LaneSelection::All)]
        lane: LaneSelection,
        /// Percentage of production capacity. Only 100% can be evidence.
        #[arg(long, default_value = "100")]
        scale_percent: NonZeroU8,
        /// Warm-up seconds retained in the lane hold interval.
        #[arg(long, default_value = "30")]
        warmup_seconds: NonZeroU64,
        /// Measurement seconds retained in the lane hold interval.
        #[arg(long, default_value = "300")]
        measurement_seconds: NonZeroU64,
        /// Cooldown seconds retained in the lane hold interval.
        #[arg(long, default_value = "30")]
        cooldown_seconds: NonZeroU64,
        /// Seconds between resource samples.
        #[arg(long, default_value = "1")]
        sample_interval_seconds: NonZeroU64,
        /// Seconds over which the clean-host baseline is measured.
        #[arg(long, default_value = "5")]
        baseline_seconds: NonZeroU64,
        /// Parent directory beneath which an immutable report directory is created.
        #[arg(long, default_value = "target/resource-canary")]
        output: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum LaneSelection {
    All,
    Dns,
    Relay,
    Endpoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum HostProfileArg {
    ProductionMinimum,
    GithubHostedStandard,
}

impl From<HostProfileArg> for HostProfile {
    fn from(value: HostProfileArg) -> Self {
        match value {
            HostProfileArg::ProductionMinimum => Self::ProductionMinimum,
            HostProfileArg::GithubHostedStandard => Self::GithubHostedStandard,
        }
    }
}

impl LaneSelection {
    const fn includes(self, lane: Self) -> bool {
        matches!(
            (self, lane),
            (Self::All, _)
                | (Self::Dns, Self::Dns)
                | (Self::Relay, Self::Relay)
                | (Self::Endpoint, Self::Endpoint)
        )
    }
}

#[derive(Debug, Clone)]
struct ProcessReading {
    name: String,
    cpu_ticks: u64,
    rss_bytes: u64,
}

#[derive(Debug, Serialize)]
struct CompetitorReport {
    pid: u32,
    name: String,
    cpu_basis_points: u16,
    rss_bytes: u64,
}

#[derive(Debug, Serialize)]
struct PreflightReport {
    schema_version: u16,
    recorded_unix_seconds: u64,
    source_revision: Option<String>,
    host_profile: &'static str,
    accepted: bool,
    failure: Option<String>,
    operating_system: &'static str,
    architecture: &'static str,
    kernel_release: String,
    cpu_model: String,
    load_averages: String,
    baseline_seconds: u64,
    cpu_cores: usize,
    memory_total_bytes: u64,
    memory_available_bytes: u64,
    swap_used_bytes: u64,
    file_descriptor_limit: u64,
    free_storage_bytes: u64,
    baseline_cpu_basis_points: u16,
    largest_competitor_cpu_basis_points: u16,
    largest_competitor_rss_bytes: u64,
    competitors: Vec<CompetitorReport>,
}

#[derive(Clone, Debug, Serialize)]
struct ResourceSample {
    elapsed_millis: u64,
    phase: &'static str,
    cpu_basis_points: u16,
    memory_total_bytes: u64,
    memory_available_bytes: u64,
    swap_used_bytes: u64,
    process_rss_bytes: u64,
    process_file_descriptors: u64,
    process_threads: usize,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct ResourceSummary {
    sample_count: usize,
    warmup_samples: usize,
    measurement_samples: usize,
    cooldown_samples: usize,
    peak_cpu_basis_points: u16,
    peak_rss_bytes: u64,
    peak_file_descriptors: u64,
    peak_threads: usize,
    minimum_available_memory_bytes: u64,
}

#[derive(Debug, Serialize)]
struct LaneReport {
    lane: &'static str,
    accepted: bool,
    failure: Option<String>,
    resources: Option<ResourceSummary>,
    outcome: Option<Value>,
    samples_file: String,
    diagnostic: LaneDiagnostic,
}

#[derive(Clone, Debug, Serialize)]
struct LaneDiagnostic {
    final_phase: &'static str,
    elapsed_millis: u64,
    error_class: Option<&'static str>,
    progress: LaneProgressReport,
    last_resource_sample: Option<ResourceSample>,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct LaneProgressReport {
    offered: usize,
    admitted: usize,
    rejected: usize,
    transport_failed: usize,
    active: usize,
    high_water: usize,
}

#[derive(Debug, Serialize)]
struct RunReport {
    schema_version: u16,
    recorded_unix_seconds: u64,
    source_revision: Option<String>,
    host_profile: &'static str,
    mode: &'static str,
    evidence: bool,
    build_profile: &'static str,
    optimization_level: &'static str,
    release_build: bool,
    source_clean: bool,
    all_lanes: bool,
    scale_percent: u8,
    warmup_seconds: u64,
    measurement_seconds: u64,
    cooldown_seconds: u64,
    sample_interval_seconds: u64,
    accepted: bool,
    lanes: Vec<LaneReport>,
}

#[derive(Debug, Serialize)]
struct ArtifactDigest {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct ArtifactManifest {
    schema_version: u16,
    source_revision: Option<String>,
    files: Vec<ArtifactDigest>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("resource_canary=warn"));
    if let Err(error) = tracing_subscriber::fmt().with_env_filter(filter).try_init() {
        eprintln!("resource canary tracing initialization failed: {error}");
    }
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("resource canary failed: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    match cli.command {
        Command::Preflight {
            host_profile,
            baseline_seconds,
            output,
        } => run_preflight(host_profile.into(), baseline_seconds.get(), &output).await,
        Command::Run {
            host_profile,
            lane,
            scale_percent,
            warmup_seconds,
            measurement_seconds,
            cooldown_seconds,
            sample_interval_seconds,
            baseline_seconds,
            output,
        } => {
            run_canary(
                host_profile.into(),
                lane,
                scale_percent.get(),
                warmup_seconds.get(),
                measurement_seconds.get(),
                cooldown_seconds.get(),
                sample_interval_seconds.get(),
                baseline_seconds.get(),
                &output,
            )
            .await
        }
    }
}

async fn run_preflight(
    host_profile: HostProfile,
    baseline_seconds: u64,
    output: &Path,
) -> Result<(), Box<dyn Error>> {
    if baseline_seconds > MAX_BASELINE_SECONDS {
        return Err(format!(
            "baseline_seconds {baseline_seconds} exceeds maximum {MAX_BASELINE_SECONDS}"
        )
        .into());
    }
    let artifact_dir = create_artifact_dir(output, "preflight")?;
    println!("{}", artifact_dir.display());
    let result = async {
        let (report, result) = observe_preflight(
            host_profile,
            Duration::from_secs(baseline_seconds),
            &artifact_dir,
        )
        .await?;
        let report_path = artifact_dir.join("preflight.json");
        write_json_new(&report_path, &report)?;
        result.map_err(|error| Box::new(error) as Box<dyn Error>)
    }
    .await;
    finish_artifact_run(&artifact_dir, result)
}

#[allow(
    clippy::too_many_arguments,
    reason = "CLI timing and scale remain explicit at the process boundary"
)]
async fn run_canary(
    host_profile: HostProfile,
    lane: LaneSelection,
    scale_percent: u8,
    warmup_seconds: u64,
    measurement_seconds: u64,
    cooldown_seconds: u64,
    sample_interval_seconds: u64,
    baseline_seconds: u64,
    output: &Path,
) -> Result<(), Box<dyn Error>> {
    if scale_percent > 100 {
        return Err("scale_percent must be in 1..=100".into());
    }
    if baseline_seconds > MAX_BASELINE_SECONDS {
        return Err(format!(
            "baseline_seconds {baseline_seconds} exceeds maximum {MAX_BASELINE_SECONDS}"
        )
        .into());
    }
    let timing = DurationProfile::new(
        Duration::from_secs(warmup_seconds),
        Duration::from_secs(measurement_seconds),
        Duration::from_secs(cooldown_seconds),
        Duration::from_secs(sample_interval_seconds),
    )?;
    let requested_evidence =
        CanaryMode::classify(&timing, scale_percent, EvidencePrerequisites::ready()).is_evidence();
    let release_build = is_release_build();
    let source_clean = source_tree_clean()?;
    let all_lanes = lane == LaneSelection::All;
    let mode = CanaryMode::classify(
        &timing,
        scale_percent,
        EvidencePrerequisites::new(all_lanes, release_build, source_clean, host_profile),
    );
    if requested_evidence && !mode.is_evidence() {
        return Err(format!(
            "evidence prerequisites failed: all_lanes={all_lanes}, release_build={release_build}, \
             source_clean={source_clean}, host_profile={}",
            host_profile.as_str()
        )
        .into());
    }
    let artifact_dir = create_artifact_dir(output, "run")?;
    println!("{}", artifact_dir.display());

    let result = async {
        let (preflight, preflight_result) = observe_preflight(
            host_profile,
            Duration::from_secs(baseline_seconds),
            &artifact_dir,
        )
        .await?;
        write_json_new(&artifact_dir.join("preflight.json"), &preflight)?;
        if let Err(error) = preflight_result {
            return Err(Box::new(error) as Box<dyn Error>);
        }

        let mut lanes = Vec::new();
        if lane.includes(LaneSelection::Dns) {
            let report = execute_dns_lane(scale_percent, timing, &preflight, &artifact_dir).await?;
            let accepted = report.accepted;
            lanes.push(report);
            write_run_report(
                &artifact_dir,
                host_profile,
                mode,
                scale_percent,
                timing,
                false,
                &lanes,
            )?;
            if !accepted {
                return Err("DNS resource lane failed acceptance".into());
            }
        }
        if lane.includes(LaneSelection::Relay) {
            let report =
                execute_relay_lane(scale_percent, timing, &preflight, &artifact_dir).await?;
            let accepted = report.accepted;
            lanes.push(report);
            write_run_report(
                &artifact_dir,
                host_profile,
                mode,
                scale_percent,
                timing,
                false,
                &lanes,
            )?;
            if !accepted {
                return Err("relay resource lane failed acceptance".into());
            }
        }
        if lane.includes(LaneSelection::Endpoint) {
            let report =
                execute_endpoint_lane(scale_percent, timing, &preflight, &artifact_dir).await?;
            let accepted = report.accepted;
            lanes.push(report);
            write_run_report(
                &artifact_dir,
                host_profile,
                mode,
                scale_percent,
                timing,
                false,
                &lanes,
            )?;
            if !accepted {
                return Err("endpoint resource lane failed acceptance".into());
            }
        }
        write_run_report(
            &artifact_dir,
            host_profile,
            mode,
            scale_percent,
            timing,
            true,
            &lanes,
        )?;
        Ok::<(), Box<dyn Error>>(())
    }
    .await;
    finish_artifact_run(&artifact_dir, result)
}

async fn execute_dns_lane(
    scale_percent: u8,
    timing: DurationProfile,
    preflight: &PreflightReport,
    artifact_dir: &Path,
) -> Result<LaneReport, Box<dyn Error>> {
    let production = WorkloadProfile::production_twice()?;
    let udp_capacity = scaled_nonzero(production.dns_udp_capacity(), scale_percent, 2)?;
    let tcp_capacity = scaled_nonzero(production.dns_tcp_capacity(), scale_percent, 2)?;
    let http_connection_capacity =
        scaled_nonzero(production.http_connection_capacity(), scale_percent, 2)?;
    let http_request_capacity =
        scaled_nonzero(production.http_request_capacity(), scale_percent, 2)?;
    let http2_streams_per_connection = nonzero(
        production.http2_streams_per_connection(),
        "DNS HTTP/2 streams per connection",
    )?;
    let http_accept_rate = if scale_percent == 100 {
        production.http_accept_rate_per_second()
    } else {
        100
    };
    let http_accept_rate = nonzero(http_accept_rate, "DNS HTTP accept rate")?;
    let http_accept_burst = if scale_percent == 100 {
        nonzero(production.http_accept_burst(), "DNS HTTP accept burst")?
    } else {
        doubled(http_connection_capacity, "DNS HTTP accept burst")?
    };
    let operation_timeout = operation_timeout(scale_percent);
    let udp_rate = scaled_nonzero(1_000, scale_percent, 100)?;
    let config = DnsLaneConfig::new(
        udp_capacity,
        udp_rate,
        tcp_capacity,
        http_connection_capacity,
        http_request_capacity,
        http2_streams_per_connection,
        doubled(udp_capacity, "DNS UDP offered load")?,
        doubled(tcp_capacity, "DNS TCP offered load")?,
        doubled(http_connection_capacity, "DNS HTTP connection offered load")?,
        doubled(http_request_capacity, "DNS HTTP request offered load")?,
        http_accept_rate,
        http_accept_burst,
        lane_timing(timing)?,
        operation_timeout,
    )?;
    let (phases, phase_receiver) = PhaseReporter::new();
    let (outcome, samples, final_state, elapsed) = monitor_lane(
        timing.sample_interval(),
        phase_receiver,
        run_dns_lane(config, phases),
    )
    .await?;
    let samples_file = "dns-samples.ndjson";
    write_samples(&artifact_dir.join(samples_file), &samples)?;
    let resources = resource_summary(&samples)?;
    match outcome {
        Ok(outcome) => {
            let udp_admission_outcomes = u64::try_from(outcome.udp_completed)
                .map_err(|_| "DNS UDP completion count is out of range")?
                .checked_add(outcome.udp_rejections)
                .ok_or(CanaryError::ArithmeticOverflow)?;
            let expected_udp_rejections = outcome
                .udp_offered
                .checked_sub(udp_capacity.get())
                .ok_or(CanaryError::ArithmeticOverflow)?;
            let initial_http_connection_rejections = outcome
                .http_connection_capacity_rejections
                .checked_add(outcome.http_connection_rate_rejections)
                .ok_or(CanaryError::ArithmeticOverflow)?;
            let initial_http_connection_outcomes =
                u64::try_from(outcome.http_connections_active_high_water)
                    .map_err(|_| "DNS HTTP connection high-water is out of range")?
                    .checked_add(initial_http_connection_rejections)
                    .ok_or(CanaryError::ArithmeticOverflow)?;
            let expected_total_http_connection_rejections = initial_http_connection_rejections
                .checked_add(
                    u64::try_from(outcome.continuity_http_connection_rejections)
                        .map_err(|_| "DNS HTTP continuity count is out of range")?,
                )
                .ok_or(CanaryError::ArithmeticOverflow)?;
            let acceptance = AcceptanceInput {
                peak_cpu_basis_points: resources.peak_cpu_basis_points,
                visible_memory_bytes: preflight.memory_total_bytes,
                peak_rss_bytes: resources.peak_rss_bytes,
                file_descriptor_limit: preflight.file_descriptor_limit,
                peak_file_descriptors: resources.peak_file_descriptors,
                shutdown: outcome.shutdown,
                samples_complete: phase_coverage_complete(timing, &samples)?,
                admission: AdmissionSample {
                    maximum: tcp_capacity.get(),
                    high_water: outcome.tcp_active_high_water,
                    rejections: outcome.tcp_rejections,
                    counter_exhausted: false,
                },
            };
            let mut failure = evaluate_acceptance(&acceptance, HeadroomThreshold::thirty_percent())
                .err()
                .map(|error| error.to_string());
            if failure.is_none() && !outcome.recovered {
                failure = Some("DNS admission did not recover after release".to_owned());
            }
            if failure.is_none()
                && outcome.tcp_rejections
                    != u64::try_from(
                        outcome
                            .tcp_offered
                            .checked_sub(tcp_capacity.get())
                            .ok_or(CanaryError::ArithmeticOverflow)?,
                    )
                    .map_err(|_| "DNS TCP rejection count is out of range")?
            {
                failure = Some("DNS TCP admission outcomes do not conserve attempts".to_owned());
            }
            if failure.is_none()
                && (outcome.udp_completed == 0
                    || outcome.udp_rejections == 0
                    || outcome.udp_arrival.attempts != outcome.udp_offered
                    || outcome.udp_completed != udp_capacity.get()
                    || outcome.udp_rejections
                        != u64::try_from(expected_udp_rejections)
                            .map_err(|_| "DNS UDP rejection count is out of range")?
                    || udp_admission_outcomes
                        != u64::try_from(outcome.udp_offered)
                            .map_err(|_| "DNS UDP offered count is out of range")?
                    || outcome
                        .udp_completed
                        .checked_add(outcome.udp_timed_out)
                        .is_none_or(|total| total != outcome.udp_offered))
            {
                failure = Some(
                    "DNS UDP admission lacks success, overload, or conserved outcomes".to_owned(),
                );
            }
            if failure.is_none()
                && (outcome.http_connections_active_high_water != http_connection_capacity.get()
                    || outcome.http_connection_rejections == 0
                    || outcome.http_connection_arrival.attempts != outcome.http_connections_offered
                    || initial_http_connection_outcomes
                        != u64::try_from(outcome.http_connections_offered)
                            .map_err(|_| "DNS HTTP offered count is out of range")?
                    || outcome.http_connection_rejections
                        != expected_total_http_connection_rejections)
            {
                failure = Some(
                    "DNS HTTP connection admission or arrival accounting was incomplete".to_owned(),
                );
            }
            if failure.is_none()
                && (outcome.http_requests_active_high_water != http_request_capacity.get()
                    || outcome.http_request_rejections == 0
                    || outcome.http_requests_admitted != http_request_capacity.get()
                    || !outcome.http_request_recovered
                    || u64::try_from(outcome.http_requests_admitted)
                        .ok()
                        .and_then(|admitted| admitted.checked_add(outcome.http_request_rejections))
                        != u64::try_from(outcome.http_requests_offered).ok())
            {
                failure = Some(
                    "DNS HTTP request admission lacks saturation, conservation, or recovery"
                        .to_owned(),
                );
            }
            if failure.is_none()
                && (outcome.continuity_udp_successes == 0
                    || outcome.continuity_http_connection_rejections == 0
                    || outcome.continuity_http_request_rejections == 0)
            {
                failure =
                    Some("DNS timed phases lacked continuing success or rejection".to_owned());
            }
            if failure.is_none() && outcome.store_background_failures != 0 {
                failure = Some(format!(
                    "DNS store reported {} background failures",
                    outcome.store_background_failures
                ));
            }
            let diagnostic = lane_diagnostic(
                final_state,
                elapsed,
                &samples,
                failure.as_ref().map(|_| "acceptance"),
            )?;
            Ok(LaneReport {
                lane: "dns",
                accepted: failure.is_none(),
                failure,
                resources: Some(resources),
                outcome: Some(dns_outcome_json(&outcome)?),
                samples_file: samples_file.to_owned(),
                diagnostic,
            })
        }
        Err(error) => {
            let diagnostic = lane_diagnostic(final_state, elapsed, &samples, Some("workload"))?;
            Ok(LaneReport {
                lane: "dns",
                accepted: false,
                failure: Some(error.to_string()),
                resources: Some(resources),
                outcome: None,
                samples_file: samples_file.to_owned(),
                diagnostic,
            })
        }
    }
}

async fn execute_relay_lane(
    scale_percent: u8,
    timing: DurationProfile,
    preflight: &PreflightReport,
    artifact_dir: &Path,
) -> Result<LaneReport, Box<dyn Error>> {
    let production = WorkloadProfile::production_twice()?;
    let pending_capacity = scaled_nonzero(production.relay_pending_capacity(), scale_percent, 2)?;
    let session_capacity = scaled_nonzero(production.relay_session_capacity(), scale_percent, 2)?;
    let sessions_per_identity = nonzero(
        production
            .relay_sessions_per_identity()
            .min(session_capacity.get()),
        "relay sessions per identity",
    )?;
    let (fill_rate, overload_rate, accept_burst) = if scale_percent == 100 {
        (
            nonzero(production.relay_accept_rate_per_second(), "relay fill rate")?,
            nonzero(
                production
                    .relay_accept_rate_per_second()
                    .checked_mul(2)
                    .ok_or(CanaryError::ArithmeticOverflow)?,
                "relay overload rate",
            )?,
            nonzero(production.relay_accept_burst(), "relay accept burst")?,
        )
    } else {
        (
            nonzero(100, "relay fill rate")?,
            nonzero(200, "relay overload rate")?,
            nonzero(production.relay_accept_burst(), "relay accept burst")?,
        )
    };
    let operation_timeout = operation_timeout(scale_percent);
    let config = RelayLaneConfig::new(
        pending_capacity,
        session_capacity,
        sessions_per_identity,
        doubled(pending_capacity, "relay pending offered load")?,
        doubled(session_capacity, "relay session offered load")?,
        fill_rate,
        overload_rate,
        accept_burst,
        lane_timing(timing)?,
        operation_timeout,
    )?;
    let (phases, phase_receiver) = PhaseReporter::new();
    let (outcome, samples, final_state, elapsed) = monitor_lane(
        timing.sample_interval(),
        phase_receiver,
        run_relay_lane(config, phases),
    )
    .await?;
    let samples_file = "relay-samples.ndjson";
    write_samples(&artifact_dir.join(samples_file), &samples)?;
    let resources = resource_summary(&samples)?;
    match outcome {
        Ok(outcome) => {
            let acceptance = AcceptanceInput {
                peak_cpu_basis_points: resources.peak_cpu_basis_points,
                visible_memory_bytes: preflight.memory_total_bytes,
                peak_rss_bytes: resources.peak_rss_bytes,
                file_descriptor_limit: preflight.file_descriptor_limit,
                peak_file_descriptors: resources.peak_file_descriptors,
                shutdown: outcome.shutdown,
                samples_complete: phase_coverage_complete(timing, &samples)?,
                admission: AdmissionSample {
                    maximum: session_capacity.get(),
                    high_water: outcome.session_high_water,
                    rejections: u64::try_from(outcome.sessions_rejected)
                        .map_err(|_| "relay rejection count is out of range")?,
                    counter_exhausted: false,
                },
            };
            let mut failure = evaluate_acceptance(&acceptance, HeadroomThreshold::thirty_percent())
                .err()
                .map(|error| error.to_string());
            if failure.is_none() && outcome.pending_rejections == 0 {
                failure = Some("relay pending admission did not reject overload".to_owned());
            }
            if failure.is_none() && outcome.endpoint_session_rejections == 0 {
                failure = Some("relay per-identity admission did not reject overload".to_owned());
            }
            if failure.is_none() && outcome.global_session_rejections == 0 {
                failure = Some("relay global admission did not reject overload".to_owned());
            }
            if failure.is_none()
                && (outcome.fill_arrival.attempts != outcome.sessions_accepted
                    || outcome
                        .identity_overload_arrival
                        .attempts
                        .checked_add(outcome.overload_arrival.attempts)
                        != Some(outcome.sessions_rejected))
            {
                failure = Some("relay arrival campaigns do not conserve attempts".to_owned());
            }
            if failure.is_none()
                && (outcome.rejection_client_outcomes.total()? != outcome.sessions_rejected
                    || outcome.continuity_client_outcomes.total()? != outcome.continuity_rejections
                    || outcome.rejection_client_outcomes.timed_out != 0
                    || outcome.continuity_client_outcomes.timed_out != 0)
            {
                failure = Some(
                    "relay client-visible outcome classes do not conserve attempts".to_owned(),
                );
            }
            if failure.is_none() && !outcome.recovered {
                failure = Some("relay admission did not recover after release".to_owned());
            }
            if failure.is_none()
                && (outcome.continuity_successes == 0 || outcome.continuity_rejections == 0)
            {
                failure =
                    Some("relay timed phases lacked continuing success or rejection".to_owned());
            }
            if failure.is_none()
                && outcome
                    .endpoint_session_rejections
                    .checked_add(outcome.global_session_rejections)
                    .and_then(|value| value.checked_add(outcome.session_pending_rejections))
                    .and_then(|value| value.checked_add(outcome.rate_rejections))
                    != u64::try_from(
                        outcome
                            .sessions_rejected
                            .checked_add(outcome.continuity_rejections)
                            .ok_or(CanaryError::ArithmeticOverflow)?,
                    )
                    .ok()
            {
                failure = Some("relay session status classes do not conserve attempts".to_owned());
            }
            let diagnostic = lane_diagnostic(
                final_state,
                elapsed,
                &samples,
                failure.as_ref().map(|_| "acceptance"),
            )?;
            Ok(LaneReport {
                lane: "relay",
                accepted: failure.is_none(),
                failure,
                resources: Some(resources),
                outcome: Some(relay_outcome_json(&outcome)?),
                samples_file: samples_file.to_owned(),
                diagnostic,
            })
        }
        Err(error) => {
            let diagnostic = lane_diagnostic(final_state, elapsed, &samples, Some("workload"))?;
            Ok(LaneReport {
                lane: "relay",
                accepted: false,
                failure: Some(error.to_string()),
                resources: Some(resources),
                outcome: None,
                samples_file: samples_file.to_owned(),
                diagnostic,
            })
        }
    }
}

async fn execute_endpoint_lane(
    scale_percent: u8,
    timing: DurationProfile,
    preflight: &PreflightReport,
    artifact_dir: &Path,
) -> Result<LaneReport, Box<dyn Error>> {
    let production = WorkloadProfile::production_twice()?;
    let capacity = scaled_nonzero(production.endpoint_connection_capacity(), scale_percent, 2)?;
    let offered = doubled(capacity, "endpoint offered load")?;
    let operation_timeout = operation_timeout(scale_percent);
    let config =
        EndpointLaneConfig::new(capacity, offered, lane_timing(timing)?, operation_timeout)?;
    let (phases, phase_receiver) = PhaseReporter::new();
    let (outcome, samples, final_state, elapsed) = monitor_lane(
        timing.sample_interval(),
        phase_receiver,
        run_endpoint_lane(config, phases),
    )
    .await?;
    let samples_file = "endpoint-samples.ndjson";
    write_samples(&artifact_dir.join(samples_file), &samples)?;
    let resources = resource_summary(&samples)?;
    match outcome {
        Ok(outcome) => {
            let acceptance = AcceptanceInput {
                peak_cpu_basis_points: resources.peak_cpu_basis_points,
                visible_memory_bytes: preflight.memory_total_bytes,
                peak_rss_bytes: resources.peak_rss_bytes,
                file_descriptor_limit: preflight.file_descriptor_limit,
                peak_file_descriptors: resources.peak_file_descriptors,
                shutdown: outcome.shutdown,
                samples_complete: phase_coverage_complete(timing, &samples)?,
                admission: AdmissionSample {
                    maximum: outcome.admission.maximum,
                    high_water: outcome.admission.high_water,
                    rejections: outcome.admission.rejections,
                    counter_exhausted: outcome.admission.counter_exhausted,
                },
            };
            let mut failure = evaluate_acceptance(&acceptance, HeadroomThreshold::thirty_percent())
                .err()
                .map(|error| error.to_string());
            if failure.is_none() && !outcome.recovered {
                failure = Some("endpoint admission did not recover after release".to_owned());
            }
            if failure.is_none()
                && (outcome.continuity_successes == 0 || outcome.continuity_rejections == 0)
            {
                failure =
                    Some("endpoint timed phases lacked continuing success or rejection".to_owned());
            }
            if failure.is_none()
                && (outcome.client_noq.counter_exhausted || outcome.server_noq.counter_exhausted)
            {
                failure = Some("Noq queue accounting exhausted".to_owned());
            }
            if failure.is_none() && !endpoint_task_headroom(&outcome)? {
                failure = Some("endpoint runtime tasks retained less than 30% headroom".to_owned());
            }
            if failure.is_none() && !endpoint_queue_headroom(&outcome)? {
                failure = Some("Noq internal queues retained less than 30% headroom".to_owned());
            }
            let diagnostic = lane_diagnostic(
                final_state,
                elapsed,
                &samples,
                failure.as_ref().map(|_| "acceptance"),
            )?;
            Ok(LaneReport {
                lane: "endpoint",
                accepted: failure.is_none(),
                failure,
                resources: Some(resources),
                outcome: Some(endpoint_outcome_json(&outcome)?),
                samples_file: samples_file.to_owned(),
                diagnostic,
            })
        }
        Err(error) => {
            let diagnostic = lane_diagnostic(final_state, elapsed, &samples, Some("workload"))?;
            Ok(LaneReport {
                lane: "endpoint",
                accepted: false,
                failure: Some(error.to_string()),
                resources: Some(resources),
                outcome: None,
                samples_file: samples_file.to_owned(),
                diagnostic,
            })
        }
    }
}

async fn monitor_lane<T, E>(
    sample_interval: Duration,
    phase_receiver: watch::Receiver<LaneState>,
    future: impl Future<Output = Result<T, E>>,
) -> Result<(Result<T, E>, Vec<ResourceSample>, LaneState, Duration), Box<dyn Error>> {
    let started = Instant::now();
    let final_state = phase_receiver.clone();
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut sampler = tokio::spawn(sample_resources(sample_interval, stop_rx, phase_receiver));
    tokio::select! {
        outcome = future => {
            stop_tx.send(true).map_err(|_| "resource sampler stopped before cancellation")?;
            let samples = sampler
                .await
                .map_err(|error| format!("resource sampler task failed: {error}"))?
                .map_err(io::Error::other)?;
            let state = *final_state.borrow();
            Ok((outcome, samples, state, started.elapsed()))
        }
        result = &mut sampler => {
            let samples = result
                .map_err(|error| format!("resource sampler task failed: {error}"))?
                .map_err(io::Error::other)?;
            Err(format!(
                "resource sampler stopped before the workload after {} samples",
                samples.len()
            )
            .into())
        }
    }
}

async fn sample_resources(
    interval: Duration,
    mut stop: watch::Receiver<bool>,
    phase: watch::Receiver<LaneState>,
) -> Result<Vec<ResourceSample>, String> {
    let started = Instant::now();
    let mut previous_cpu =
        parse_cpu_ticks(&fs::read_to_string("/proc/stat").map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let mut samples = Vec::new();
    let mut ticker = resource_sample_ticker(interval)?;
    loop {
        tokio::select! {
            changed = stop.changed() => {
                changed.map_err(|error| error.to_string())?;
                if *stop.borrow() {
                    if samples.is_empty() {
                        let (sample, _) = collect_resource_sample(
                            started,
                            previous_cpu,
                            phase.borrow().phase.as_str(),
                        )?;
                        samples.push(sample);
                    }
                    break;
                }
            }
            _ = ticker.tick() => {
                if samples.len() >= MAX_RESOURCE_SAMPLES {
                    return Err(format!(
                        "resource sample count exceeds maximum {MAX_RESOURCE_SAMPLES}"
                    ));
                }
                let (sample, current_cpu) = collect_resource_sample(
                    started,
                    previous_cpu,
                    phase.borrow().phase.as_str(),
                )?;
                samples.push(sample);
                previous_cpu = current_cpu;
            }
        }
    }
    Ok(samples)
}

fn resource_sample_ticker(interval: Duration) -> Result<tokio::time::Interval, String> {
    let first_sample = tokio::time::Instant::now()
        .checked_add(interval)
        .ok_or_else(|| "resource sample deadline overflowed".to_owned())?;
    let mut ticker = tokio::time::interval_at(first_sample, interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    Ok(ticker)
}

fn collect_resource_sample(
    started: Instant,
    previous_cpu: krikos_bench::canary::CpuTicks,
    phase: &'static str,
) -> Result<(ResourceSample, krikos_bench::canary::CpuTicks), String> {
    let current_cpu =
        parse_cpu_ticks(&fs::read_to_string("/proc/stat").map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let memory =
        parse_meminfo(&fs::read_to_string("/proc/meminfo").map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let process = parse_process_status(
        &fs::read_to_string("/proc/self/status").map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let elapsed_millis = u64::try_from(started.elapsed().as_millis())
        .map_err(|_| "sample elapsed time is out of range".to_owned())?;
    Ok((
        ResourceSample {
            elapsed_millis,
            phase,
            cpu_basis_points: cpu_usage_basis_points(previous_cpu, current_cpu)
                .map_err(|error| error.to_string())?,
            memory_total_bytes: memory.total_bytes(),
            memory_available_bytes: memory.available_bytes(),
            swap_used_bytes: memory.swap_used_bytes(),
            process_rss_bytes: process.rss_bytes(),
            process_file_descriptors: count_open_file_descriptors()
                .map_err(|error| error.to_string())?,
            process_threads: process.threads(),
        },
        current_cpu,
    ))
}

fn count_open_file_descriptors() -> Result<u64, io::Error> {
    let count = fs::read_dir("/proc/self/fd")?.count();
    u64::try_from(count).map_err(io::Error::other)
}

fn resource_summary(samples: &[ResourceSample]) -> Result<ResourceSummary, Box<dyn Error>> {
    if samples.is_empty() {
        return Err("resource sampler retained no samples".into());
    }
    Ok(ResourceSummary {
        sample_count: samples.len(),
        warmup_samples: phase_sample_count(samples, LanePhase::Warmup),
        measurement_samples: phase_sample_count(samples, LanePhase::Measurement),
        cooldown_samples: phase_sample_count(samples, LanePhase::Cooldown),
        peak_cpu_basis_points: samples
            .iter()
            .map(|sample| sample.cpu_basis_points)
            .max()
            .ok_or("resource sampler retained no CPU samples")?,
        peak_rss_bytes: samples
            .iter()
            .map(|sample| sample.process_rss_bytes)
            .max()
            .ok_or("resource sampler retained no RSS samples")?,
        peak_file_descriptors: samples
            .iter()
            .map(|sample| sample.process_file_descriptors)
            .max()
            .ok_or("resource sampler retained no descriptor samples")?,
        peak_threads: samples
            .iter()
            .map(|sample| sample.process_threads)
            .max()
            .ok_or("resource sampler retained no thread samples")?,
        minimum_available_memory_bytes: samples
            .iter()
            .map(|sample| sample.memory_available_bytes)
            .min()
            .ok_or("resource sampler retained no memory samples")?,
    })
}

fn lane_timing(timing: DurationProfile) -> Result<LaneTiming, CanaryError> {
    LaneTiming::new(timing.warmup(), timing.measurement(), timing.cooldown())
}

fn phase_sample_count(samples: &[ResourceSample], phase: LanePhase) -> usize {
    samples
        .iter()
        .filter(|sample| sample.phase == phase.as_str())
        .count()
}

fn phase_coverage_complete(
    timing: DurationProfile,
    samples: &[ResourceSample],
) -> Result<bool, CanaryError> {
    let interval_nanos = timing.sample_interval().as_nanos();
    let required = [
        (LanePhase::Warmup, timing.warmup()),
        (LanePhase::Measurement, timing.measurement()),
        (LanePhase::Cooldown, timing.cooldown()),
    ];
    for (phase, duration) in required {
        let expected = duration.as_nanos() / interval_nanos;
        let expected = usize::try_from(expected).map_err(|_| CanaryError::ArithmeticOverflow)?;
        let minimum = expected.saturating_sub(1);
        if phase_sample_count(samples, phase) < minimum {
            return Ok(false);
        }
    }
    let expected_total =
        usize::try_from(timing.minimum_samples()).map_err(|_| CanaryError::ArithmeticOverflow)?;
    Ok(!samples.is_empty() && samples.len() >= expected_total.saturating_sub(3))
}

fn endpoint_queue_headroom(outcome: &EndpointLaneOutcome) -> Result<bool, Box<dyn Error>> {
    let packet_byte_capacity = usize::try_from(noq::DEFAULT_MAX_PACKET_BYTES_PER_ENDPOINT)
        .map_err(|_| "Noq packet byte capacity is out of range")?;
    for stats in [outcome.client_noq, outcome.server_noq] {
        if stats.packet_event_rejections != 0
            || stats.packet_byte_rejections != 0
            || stats.connection_rejections != 0
            || stats.control_event_rejections != 0
            || !within_seventy_percent(
                stats.packet_events_per_connection_high_water,
                noq::DEFAULT_MAX_PACKET_EVENTS_PER_CONNECTION,
            )?
            || !within_seventy_percent(stats.packet_bytes_high_water, packet_byte_capacity)?
            || !within_seventy_percent(
                stats.control_events_high_water,
                noq::DEFAULT_MAX_CONTROL_EVENTS_PER_ENDPOINT,
            )?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn endpoint_task_headroom(outcome: &EndpointLaneOutcome) -> Result<bool, CanaryError> {
    for tasks in [outcome.client_tasks, outcome.server_tasks] {
        if tasks.counter_exhausted
            || tasks.rejections != 0
            || tasks.maximum == 0
            || !within_seventy_percent(tasks.current, tasks.maximum)?
            || !within_seventy_percent(tasks.high_water, tasks.maximum)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn within_seventy_percent(used: usize, total: usize) -> Result<bool, CanaryError> {
    let used = used
        .checked_mul(10_000)
        .ok_or(CanaryError::ArithmeticOverflow)?;
    let maximum = total
        .checked_mul(7_000)
        .ok_or(CanaryError::ArithmeticOverflow)?;
    Ok(used <= maximum)
}

fn scaled_nonzero(
    production: usize,
    scale_percent: u8,
    minimum: usize,
) -> Result<NonZeroUsize, Box<dyn Error>> {
    let scaled = production
        .checked_mul(usize::from(scale_percent))
        .and_then(|value| value.checked_add(99))
        .map(|value| value / 100)
        .ok_or(CanaryError::ArithmeticOverflow)?
        .max(minimum);
    nonzero(scaled, "scaled workload")
}

fn doubled(value: NonZeroUsize, field: &'static str) -> Result<NonZeroUsize, Box<dyn Error>> {
    let doubled = value
        .get()
        .checked_mul(2)
        .ok_or(CanaryError::CapacityOverflow { field })?;
    nonzero(doubled, field)
}

fn nonzero(value: usize, field: &'static str) -> Result<NonZeroUsize, Box<dyn Error>> {
    NonZeroUsize::new(value)
        .ok_or_else(|| Box::new(CanaryError::CapacityOverflow { field }) as Box<dyn Error>)
}

fn operation_timeout(scale_percent: u8) -> Duration {
    if scale_percent == 100 {
        Duration::from_secs(20)
    } else {
        Duration::from_secs(10)
    }
}

fn write_samples(path: &Path, samples: &[ResourceSample]) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    for sample in samples {
        serde_json::to_writer(&mut file, sample)?;
        file.write_all(b"\n")?;
    }
    file.flush()?;
    Ok(())
}

fn write_run_report(
    artifact_dir: &Path,
    host_profile: HostProfile,
    mode: CanaryMode,
    scale_percent: u8,
    timing: DurationProfile,
    complete: bool,
    lanes: &[LaneReport],
) -> Result<(), Box<dyn Error>> {
    let source_clean = source_tree_clean()?;
    if mode.is_evidence() && !source_clean {
        return Err("source tree became dirty during evidence run".into());
    }
    let report = RunReport {
        schema_version: 2,
        recorded_unix_seconds: unix_seconds()?,
        source_revision: source_revision(),
        host_profile: host_profile.as_str(),
        mode: if mode.is_evidence() {
            "evidence"
        } else {
            "smoke"
        },
        evidence: mode.is_evidence(),
        build_profile: env!("KRIKOS_BENCH_BUILD_PROFILE"),
        optimization_level: env!("KRIKOS_BENCH_OPT_LEVEL"),
        release_build: is_release_build(),
        source_clean,
        all_lanes: lanes.len() == 3,
        scale_percent,
        warmup_seconds: timing.warmup().as_secs(),
        measurement_seconds: timing.measurement().as_secs(),
        cooldown_seconds: timing.cooldown().as_secs(),
        sample_interval_seconds: timing.sample_interval().as_secs(),
        accepted: complete && lanes.iter().all(|lane| lane.accepted),
        lanes: lanes
            .iter()
            .map(|lane| LaneReport {
                lane: lane.lane,
                accepted: lane.accepted,
                failure: lane.failure.clone(),
                resources: lane.resources,
                outcome: lane.outcome.clone(),
                samples_file: lane.samples_file.clone(),
                diagnostic: lane.diagnostic.clone(),
            })
            .collect(),
    };
    let path = if complete {
        artifact_dir.join("run.json")
    } else {
        artifact_dir.join(format!("run-partial-{}.json", lanes.len()))
    };
    write_json_new(&path, &report)
}

fn is_release_build() -> bool {
    env!("KRIKOS_BENCH_BUILD_PROFILE") == "release"
        && env!("KRIKOS_BENCH_OPT_LEVEL") != "0"
        && !cfg!(debug_assertions)
}

fn lane_diagnostic(
    state: LaneState,
    elapsed: Duration,
    samples: &[ResourceSample],
    error_class: Option<&'static str>,
) -> Result<LaneDiagnostic, Box<dyn Error>> {
    let LaneProgress {
        offered,
        admitted,
        rejected,
        transport_failed,
        active,
        high_water,
    } = state.progress;
    Ok(LaneDiagnostic {
        final_phase: state.phase.as_str(),
        elapsed_millis: duration_millis(elapsed)?,
        error_class,
        progress: LaneProgressReport {
            offered,
            admitted,
            rejected,
            transport_failed,
            active,
            high_water,
        },
        last_resource_sample: samples.last().cloned(),
    })
}

fn endpoint_outcome_json(outcome: &EndpointLaneOutcome) -> Result<Value, Box<dyn Error>> {
    Ok(json!({
        "offered": outcome.offered,
        "accepted": outcome.accepted,
        "rejected": outcome.rejected,
        "initial_conservation": conservation_json(outcome.initial_conservation),
        "recovered": outcome.recovered,
        "accepted_connection_latency": latency_json(outcome.accepted_connection_latency),
        "rejected_connection_latency": latency_json(outcome.rejected_connection_latency),
        "continuity_successes": outcome.continuity_successes,
        "continuity_rejections": outcome.continuity_rejections,
        "continuity_success_latency": latency_json(outcome.continuity_success_latency),
        "continuity_rejection_latency": latency_json(outcome.continuity_rejection_latency),
        "admission": {
            "maximum": outcome.admission.maximum,
            "current": outcome.admission.current,
            "high_water": outcome.admission.high_water,
            "rejections": outcome.admission.rejections,
            "counter_exhausted": outcome.admission.counter_exhausted,
        },
        "client_tasks": {
            "maximum": outcome.client_tasks.maximum,
            "current": outcome.client_tasks.current,
            "high_water": outcome.client_tasks.high_water,
            "rejections": outcome.client_tasks.rejections,
            "counter_exhausted": outcome.client_tasks.counter_exhausted,
        },
        "server_tasks": {
            "maximum": outcome.server_tasks.maximum,
            "current": outcome.server_tasks.current,
            "high_water": outcome.server_tasks.high_water,
            "rejections": outcome.server_tasks.rejections,
            "counter_exhausted": outcome.server_tasks.counter_exhausted,
        },
        "client_noq": event_queue_stats_json(outcome.client_noq),
        "server_noq": event_queue_stats_json(outcome.server_noq),
        "shutdown_millis": duration_millis(outcome.shutdown)?,
    }))
}

fn event_queue_stats_json(stats: noq::EventQueueStats) -> Value {
    json!({
        "active_connections": stats.active_connections,
        "active_connections_high_water": stats.active_connections_high_water,
        "packet_events_current": stats.packet_events_current,
        "packet_events_high_water": stats.packet_events_high_water,
        "packet_events_per_connection_high_water": stats.packet_events_per_connection_high_water,
        "packet_bytes_current": stats.packet_bytes_current,
        "packet_bytes_high_water": stats.packet_bytes_high_water,
        "control_events_current": stats.control_events_current,
        "control_events_high_water": stats.control_events_high_water,
        "packet_event_rejections": stats.packet_event_rejections,
        "packet_byte_rejections": stats.packet_byte_rejections,
        "connection_rejections": stats.connection_rejections,
        "control_event_rejections": stats.control_event_rejections,
        "counter_exhausted": stats.counter_exhausted,
    })
}

fn relay_outcome_json(outcome: &RelayLaneOutcome) -> Result<Value, Box<dyn Error>> {
    Ok(json!({
        "pending_offered": outcome.pending_offered,
        "pending_rejections": outcome.pending_rejections,
        "pending_rate_rejections": outcome.pending_rate_rejections,
        "pending_conservation": conservation_json(outcome.pending_conservation),
        "sessions_offered": outcome.sessions_offered,
        "sessions_accepted": outcome.sessions_accepted,
        "sessions_rejected": outcome.sessions_rejected,
        "session_conservation": conservation_json(outcome.session_conservation),
        "session_high_water": outcome.session_high_water,
        "endpoint_session_rejections": outcome.endpoint_session_rejections,
        "global_session_rejections": outcome.global_session_rejections,
        "session_pending_rejections": outcome.session_pending_rejections,
        "rate_rejections": outcome.rate_rejections,
        "recovered": outcome.recovered,
        "accepted_session_latency": latency_json(outcome.accepted_session_latency),
        "rejected_session_latency": latency_json(outcome.rejected_session_latency),
        "fill_arrival": arrival_json(outcome.fill_arrival),
        "identity_overload_arrival": arrival_json(outcome.identity_overload_arrival),
        "overload_arrival": arrival_json(outcome.overload_arrival),
        "rejection_client_outcomes": relay_client_outcome_json(outcome.rejection_client_outcomes),
        "continuity_client_outcomes": relay_client_outcome_json(outcome.continuity_client_outcomes),
        "continuity_successes": outcome.continuity_successes,
        "continuity_rejections": outcome.continuity_rejections,
        "continuity_success_latency": latency_json(outcome.continuity_success_latency),
        "continuity_rejection_latency": latency_json(outcome.continuity_rejection_latency),
        "shutdown_millis": duration_millis(outcome.shutdown)?,
    }))
}

fn relay_client_outcome_json(
    outcomes: krikos_bench::canary::workloads::RelayClientOutcomeCounts,
) -> Value {
    json!({
        "connected_then_rejected": outcomes.connected_then_rejected,
        "rate_limited": outcomes.rate_limited,
        "protocol_closed": outcomes.protocol_closed,
        "timed_out": outcomes.timed_out,
    })
}

fn dns_outcome_json(outcome: &DnsLaneOutcome) -> Result<Value, Box<dyn Error>> {
    Ok(json!({
        "udp_offered": outcome.udp_offered,
        "udp_completed": outcome.udp_completed,
        "udp_timed_out": outcome.udp_timed_out,
        "udp_rejections": outcome.udp_rejections,
        "udp_conservation": conservation_json(outcome.udp_conservation),
        "udp_arrival": arrival_json(outcome.udp_arrival),
        "udp_latency": latency_json(outcome.udp_latency),
        "tcp_offered": outcome.tcp_offered,
        "tcp_active_high_water": outcome.tcp_active_high_water,
        "tcp_rejections": outcome.tcp_rejections,
        "tcp_conservation": conservation_json(outcome.tcp_conservation),
        "http_connections_offered": outcome.http_connections_offered,
        "http_connections_active_high_water": outcome.http_connections_active_high_water,
        "http_connection_capacity_rejections": outcome.http_connection_capacity_rejections,
        "http_connection_rate_rejections": outcome.http_connection_rate_rejections,
        "http_connection_rejections": outcome.http_connection_rejections,
        "http_connection_conservation": conservation_json(outcome.http_connection_conservation),
        "http_connection_arrival": arrival_json(outcome.http_connection_arrival),
        "http_requests_offered": outcome.http_requests_offered,
        "http_requests_admitted": outcome.http_requests_admitted,
        "http_requests_active_high_water": outcome.http_requests_active_high_water,
        "http_request_rejections": outcome.http_request_rejections,
        "http_request_conservation": conservation_json(outcome.http_request_conservation),
        "http_request_recovered": outcome.http_request_recovered,
        "http_request_latency": latency_json(outcome.http_request_latency),
        "continuity_udp_successes": outcome.continuity_udp_successes,
        "continuity_http_connection_rejections": outcome.continuity_http_connection_rejections,
        "continuity_http_request_rejections": outcome.continuity_http_request_rejections,
        "continuity_udp_latency": latency_json(outcome.continuity_udp_latency),
        "recovered": outcome.recovered,
        "store_background_failures": outcome.store_background_failures,
        "shutdown_millis": duration_millis(outcome.shutdown)?,
    }))
}

fn conservation_json(conservation: krikos_bench::canary::WorkloadConservation) -> Value {
    json!({
        "offered": conservation.offered(),
        "admitted": conservation.admitted(),
        "rejected": conservation.rejected(),
        "transport_failed": conservation.transport_failed(),
    })
}

fn latency_json(latency: LatencySummary) -> Value {
    json!({
        "samples": latency.samples,
        "p50_micros": latency.p50_micros,
        "p95_micros": latency.p95_micros,
        "p99_micros": latency.p99_micros,
        "maximum_micros": latency.maximum_micros,
    })
}

fn arrival_json(arrival: ArrivalSummary) -> Value {
    json!({
        "target_per_second": arrival.target_per_second,
        "attempts": arrival.attempts,
        "elapsed_micros": arrival.elapsed_micros,
        "achieved_per_second_milli": arrival.achieved_per_second_milli,
        "maximum_schedule_lag_micros": arrival.maximum_schedule_lag_micros,
    })
}

fn duration_millis(duration: Duration) -> Result<u64, Box<dyn Error>> {
    Ok(
        u64::try_from(duration.as_millis())
            .map_err(|_| "duration milliseconds are out of range")?,
    )
}

async fn observe_preflight(
    host_profile: HostProfile,
    baseline: Duration,
    artifact_dir: &Path,
) -> Result<(PreflightReport, Result<(), CanaryError>), Box<dyn Error>> {
    let before_cpu = parse_cpu_ticks(&fs::read_to_string("/proc/stat")?)?;
    let before_processes = read_processes()?;

    tokio::time::sleep(baseline).await;

    let after_cpu = parse_cpu_ticks(&fs::read_to_string("/proc/stat")?)?;
    let memory = parse_meminfo(&fs::read_to_string("/proc/meminfo")?)?;
    let file_descriptor_limit = parse_open_file_limit(&fs::read_to_string("/proc/self/limits")?)?;
    let free_storage_bytes = read_storage_available_bytes(artifact_dir)?;
    let after_processes = read_processes()?;
    let baseline_cpu_basis_points = cpu_usage_basis_points(before_cpu, after_cpu)?;
    let total_cpu_delta = after_cpu
        .total()
        .checked_sub(before_cpu.total())
        .ok_or(CanaryError::InvalidCpuDelta)?;
    let self_pid = std::process::id();
    let mut competitors = Vec::new();
    for (pid, after) in &after_processes {
        if *pid == self_pid {
            continue;
        }
        let cpu_basis_points = before_processes
            .get(pid)
            .and_then(|before| after.cpu_ticks.checked_sub(before.cpu_ticks))
            .and_then(|delta| delta.checked_mul(10_000))
            .map(|scaled| scaled / total_cpu_delta)
            .and_then(|value| u16::try_from(value).ok())
            .unwrap_or(0);
        competitors.push(CompetitorReport {
            pid: *pid,
            name: after.name.clone(),
            cpu_basis_points,
            rss_bytes: after.rss_bytes,
        });
    }
    competitors.sort_by(|left, right| {
        right
            .rss_bytes
            .cmp(&left.rss_bytes)
            .then_with(|| right.cpu_basis_points.cmp(&left.cpu_basis_points))
            .then_with(|| left.pid.cmp(&right.pid))
    });
    competitors.truncate(16);

    let largest_competitor_cpu_basis_points = after_processes
        .iter()
        .filter(|(pid, _)| **pid != self_pid)
        .filter_map(|(pid, after)| {
            let before = before_processes.get(pid)?;
            let delta = after.cpu_ticks.checked_sub(before.cpu_ticks)?;
            let scaled = delta.checked_mul(10_000)?;
            u16::try_from(scaled / total_cpu_delta).ok()
        })
        .max()
        .unwrap_or(0);
    let largest_competitor_rss_bytes = after_processes
        .iter()
        .filter(|(pid, _)| **pid != self_pid)
        .map(|(_, process)| process.rss_bytes)
        .max()
        .unwrap_or(0);
    let observation = HostObservation {
        cpu_cores: std::thread::available_parallelism()?.get(),
        memory_total_bytes: memory.total_bytes(),
        memory_available_bytes: memory.available_bytes(),
        file_descriptor_limit,
        free_storage_bytes,
        baseline_cpu_basis_points,
        largest_competitor_cpu_basis_points,
        largest_competitor_rss_bytes,
    };
    let result = require_production_platform(std::env::consts::OS, std::env::consts::ARCH)
        .and_then(|()| evaluate_host_preflight(&observation, host_profile.requirements()));
    let report = PreflightReport {
        schema_version: 2,
        recorded_unix_seconds: unix_seconds()?,
        source_revision: source_revision(),
        host_profile: host_profile.as_str(),
        accepted: result.is_ok(),
        failure: result.as_ref().err().map(ToString::to_string),
        operating_system: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        kernel_release: read_bounded_line("/proc/sys/kernel/osrelease", "kernel release")?,
        cpu_model: read_cpu_model()?,
        load_averages: read_load_averages()?,
        baseline_seconds: baseline.as_secs(),
        cpu_cores: observation.cpu_cores,
        memory_total_bytes: observation.memory_total_bytes,
        memory_available_bytes: observation.memory_available_bytes,
        swap_used_bytes: memory.swap_used_bytes(),
        file_descriptor_limit: observation.file_descriptor_limit,
        free_storage_bytes: observation.free_storage_bytes,
        baseline_cpu_basis_points: observation.baseline_cpu_basis_points,
        largest_competitor_cpu_basis_points,
        largest_competitor_rss_bytes,
        competitors,
    };
    Ok((report, result))
}

fn read_bounded_line(path: &str, field: &str) -> Result<String, Box<dyn Error>> {
    let value = fs::read_to_string(path)?;
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_HOST_LABEL_BYTES {
        return Err(format!("{field} must contain 1..={MAX_HOST_LABEL_BYTES} bytes").into());
    }
    Ok(value.to_owned())
}

fn read_cpu_model() -> Result<String, Box<dyn Error>> {
    let cpuinfo = fs::read_to_string("/proc/cpuinfo")?;
    let model = cpuinfo
        .lines()
        .find_map(|line| line.strip_prefix("model name"))
        .and_then(|line| line.split_once(':'))
        .map(|(_, value)| value.trim())
        .ok_or("CPU model is missing from /proc/cpuinfo")?;
    if model.is_empty() || model.len() > MAX_HOST_LABEL_BYTES {
        return Err(format!("CPU model must contain 1..={MAX_HOST_LABEL_BYTES} bytes").into());
    }
    Ok(model.to_owned())
}

fn read_load_averages() -> Result<String, Box<dyn Error>> {
    let loadavg = fs::read_to_string("/proc/loadavg")?;
    let values = loadavg.split_whitespace().take(3).collect::<Vec<_>>();
    if values.len() != 3
        || values
            .iter()
            .any(|value| value.parse::<f64>().is_err() || value.len() > 32)
    {
        return Err("load averages are malformed".into());
    }
    Ok(values.join(" "))
}

fn read_processes() -> Result<BTreeMap<u32, ProcessReading>, Box<dyn Error>> {
    let mut processes = BTreeMap::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if processes.len() >= MAX_PROCESSES {
            return Err(format!("process count exceeds maximum {MAX_PROCESSES}").into());
        }
        let stat = match fs::read_to_string(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(_) => continue,
        };
        let status = match fs::read_to_string(entry.path().join("status")) {
            Ok(status) => status,
            Err(_) => continue,
        };
        let cpu_ticks = match parse_process_cpu_ticks(&stat) {
            Ok(ticks) => ticks,
            Err(_) => continue,
        };
        let process = match parse_process_status(&status) {
            Ok(process) => process,
            Err(_) => continue,
        };
        let name = status
            .lines()
            .find_map(|line| line.strip_prefix("Name:\t"))
            .unwrap_or("unknown")
            .to_owned();
        processes.insert(
            pid,
            ProcessReading {
                name,
                cpu_ticks,
                rss_bytes: process.rss_bytes(),
            },
        );
    }
    Ok(processes)
}

fn read_storage_available_bytes(path: &Path) -> Result<u64, Box<dyn Error>> {
    let output = ProcessCommand::new("df")
        .args(["-Pk", "--"])
        .arg(path)
        .output()?;
    if !output.status.success() {
        return Err(format!("df failed with status {}", output.status).into());
    }
    let stdout = String::from_utf8(output.stdout)?;
    Ok(parse_storage_available_bytes(&stdout)?)
}

fn source_revision() -> Option<String> {
    let output = ProcessCommand::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|revision| revision.trim().to_owned())
}

fn source_tree_clean() -> Result<bool, Box<dyn Error>> {
    let output = ProcessCommand::new("git")
        .args(["status", "--porcelain", "--untracked-files=normal"])
        .output()?;
    if !output.status.success() {
        return Err(format!("git status failed with status {}", output.status).into());
    }
    Ok(output.stdout.is_empty())
}

fn create_artifact_dir(parent: &Path, prefix: &str) -> Result<PathBuf, Box<dyn Error>> {
    fs::create_dir_all(parent)?;
    let directory = parent.join(format!(
        "{prefix}-{}-{}",
        unix_seconds()?,
        std::process::id()
    ));
    fs::create_dir(&directory)?;
    Ok(directory)
}

fn write_json_new(path: &Path, value: &impl Serialize) -> Result<(), Box<dyn Error>> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&bytes)?;
    file.flush()?;
    Ok(())
}

fn finish_artifact_run(
    artifact_dir: &Path,
    result: Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    let mut failure = result.err().map(|error| error.to_string());
    if let Some(error) = failure.as_ref()
        && let Err(record_error) = write_json_new(
            &artifact_dir.join("failure.json"),
            &json!({
                "schema_version": 2,
                "error_class": "run",
                "error": error,
            }),
        )
    {
        failure = Some(format!(
            "{error}; failed to retain failure report: {record_error}"
        ));
    }

    let manifest_digest = match finalize_artifacts(artifact_dir) {
        Ok(digest) => digest,
        Err(finalize_error) => {
            return Err(match failure {
                Some(error) => {
                    format!("{error}; artifact finalization also failed: {finalize_error}").into()
                }
                None => format!("artifact finalization failed: {finalize_error}").into(),
            });
        }
    };
    println!("manifest_sha256={manifest_digest}");
    match failure {
        Some(error) => Err(error.into()),
        None => Ok(()),
    }
}

fn finalize_artifacts(artifact_dir: &Path) -> Result<String, Box<dyn Error>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(artifact_dir)? {
        let entry = entry?;
        if paths.len() >= MAX_ARTIFACT_FILES {
            return Err(format!("artifact file count exceeds maximum {MAX_ARTIFACT_FILES}").into());
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.file_type().is_file() {
            return Err(format!(
                "artifact entry is not a regular file: {}",
                entry.path().display()
            )
            .into());
        }
        paths.push(entry.path());
    }
    paths.sort();

    let mut files = Vec::with_capacity(paths.len());
    for path in &paths {
        let (bytes, sha256) = sha256_file(path)?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("artifact filename is not valid UTF-8")?;
        files.push(ArtifactDigest {
            path: name.to_owned(),
            bytes,
            sha256,
        });
    }
    let manifest = ArtifactManifest {
        schema_version: 1,
        source_revision: source_revision(),
        files,
    };
    let manifest_path = artifact_dir.join("manifest.json");
    write_json_new(&manifest_path, &manifest)?;
    let (_, manifest_digest) = sha256_file(&manifest_path)?;
    let digest_path = artifact_dir.join("manifest.sha256");
    let mut digest_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&digest_path)?;
    writeln!(digest_file, "{manifest_digest}  manifest.json")?;
    digest_file.flush()?;

    for path in paths.iter().chain([&manifest_path, &digest_path]) {
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_readonly(true);
        fs::set_permissions(path, permissions)?;
    }
    let mut directory_permissions = fs::metadata(artifact_dir)?.permissions();
    directory_permissions.set_readonly(true);
    fs::set_permissions(artifact_dir, directory_permissions)?;
    Ok(manifest_digest)
}

fn sha256_file(path: &Path) -> Result<(u64, String), Box<dyn Error>> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(u64::try_from(read)?)
            .ok_or("artifact byte count overflowed")?;
        digest.update(&buffer[..read]);
    }
    Ok((bytes, format!("{:x}", digest.finalize())))
}

fn unix_seconds() -> Result<u64, Box<dyn Error>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn assert_artifact_directory_is_readonly(path: &Path) {
        let permissions = fs::metadata(path)
            .expect("artifact directory metadata")
            .permissions();
        assert!(permissions.readonly());

        #[cfg(unix)]
        assert_eq!(permissions.mode() & 0o222, 0);
    }

    fn restore_artifact_directory_permissions(path: &Path) {
        let mut permissions = fs::metadata(path)
            .expect("artifact directory metadata")
            .permissions();

        #[cfg(unix)]
        permissions.set_mode(0o700);
        #[cfg(windows)]
        permissions.set_readonly(false);

        fs::set_permissions(path, permissions).expect("restore temporary directory");
    }

    fn sample(phase: LanePhase) -> ResourceSample {
        ResourceSample {
            elapsed_millis: 0,
            phase: phase.as_str(),
            cpu_basis_points: 0,
            memory_total_bytes: 1,
            memory_available_bytes: 1,
            swap_used_bytes: 0,
            process_rss_bytes: 0,
            process_file_descriptors: 0,
            process_threads: 1,
        }
    }

    #[test]
    fn phase_coverage_allows_only_one_boundary_sample_per_phase() {
        let timing = DurationProfile::new(
            Duration::from_secs(30),
            Duration::from_secs(300),
            Duration::from_secs(30),
            Duration::from_secs(1),
        )
        .expect("evidence timing");
        let mut samples = Vec::new();
        samples.extend((0..29).map(|_| sample(LanePhase::Warmup)));
        samples.extend((0..299).map(|_| sample(LanePhase::Measurement)));
        samples.extend((0..29).map(|_| sample(LanePhase::Cooldown)));

        assert!(phase_coverage_complete(timing, &samples).expect("coverage"));

        samples.pop();
        assert!(!phase_coverage_complete(timing, &samples).expect("coverage"));
    }

    #[test]
    fn phase_coverage_rejects_a_skewed_sample_set() {
        let timing = DurationProfile::new(
            Duration::from_secs(30),
            Duration::from_secs(300),
            Duration::from_secs(30),
            Duration::from_secs(1),
        )
        .expect("evidence timing");
        let mut samples = Vec::new();
        samples.extend((0..28).map(|_| sample(LanePhase::Warmup)));
        samples.extend((0..300).map(|_| sample(LanePhase::Measurement)));
        samples.extend((0..29).map(|_| sample(LanePhase::Cooldown)));

        assert_eq!(samples.len(), 357);
        assert!(!phase_coverage_complete(timing, &samples).expect("coverage"));
    }

    #[tokio::test(start_paused = true)]
    async fn resource_sampler_skips_missed_absolute_deadlines() {
        let mut ticker =
            resource_sample_ticker(Duration::from_secs(1)).expect("resource sample ticker");
        tokio::time::advance(Duration::from_secs(3)).await;
        ticker.tick().await;

        let before = tokio::time::Instant::now();
        ticker.tick().await;
        assert_eq!(before.elapsed(), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn resource_sampler_holds_exact_production_cadence_despite_collection_cost() {
        let started = tokio::time::Instant::now();
        let mut ticker =
            resource_sample_ticker(Duration::from_secs(1)).expect("resource sample ticker");
        for ordinal in 0..360 {
            ticker.tick().await;
            if ordinal < 359 {
                tokio::time::advance(Duration::from_millis(10)).await;
            }
        }

        assert_eq!(
            started.elapsed(),
            Duration::from_secs(360),
            "absolute sampling cadence must not accumulate collection overhead"
        );
    }

    #[test]
    fn lane_diagnostic_retains_failure_phase_progress_and_last_sample() {
        let state = LaneState {
            phase: LanePhase::Measurement,
            progress: LaneProgress {
                offered: 8,
                admitted: 4,
                rejected: 3,
                transport_failed: 1,
                active: 4,
                high_water: 4,
            },
        };
        let samples = vec![sample(LanePhase::Measurement)];
        let diagnostic =
            lane_diagnostic(state, Duration::from_secs(21), &samples, Some("workload"))
                .expect("lane diagnostic");
        let json = serde_json::to_value(diagnostic).expect("diagnostic JSON");

        assert_eq!(json["final_phase"], "measurement");
        assert_eq!(json["elapsed_millis"], 21_000);
        assert_eq!(json["error_class"], "workload");
        assert_eq!(json["progress"]["offered"], 8);
        assert_eq!(json["progress"]["transport_failed"], 1);
        assert_eq!(json["last_resource_sample"]["phase"], "measurement");
    }

    #[test]
    fn artifact_finalization_records_digest_and_removes_write_bits() {
        let temporary = tempfile::tempdir().expect("temporary artifact parent");
        let artifact_dir = temporary.path().join("artifact");
        fs::create_dir(&artifact_dir).expect("artifact directory");
        let preflight_path = artifact_dir.join("preflight.json");
        write_json_new(&preflight_path, &json!({"accepted": true})).expect("preflight artifact");

        let digest = finalize_artifacts(&artifact_dir).expect("artifact finalization");
        let (_, retained_digest) =
            sha256_file(&artifact_dir.join("manifest.json")).expect("manifest digest");
        assert_eq!(digest, retained_digest);
        assert_eq!(
            fs::read_to_string(artifact_dir.join("manifest.sha256"))
                .expect("retained manifest digest"),
            format!("{digest}  manifest.json\n")
        );

        let manifest: Value = serde_json::from_slice(
            &fs::read(artifact_dir.join("manifest.json")).expect("manifest"),
        )
        .expect("manifest JSON");
        assert_eq!(manifest["files"][0]["path"], "preflight.json");
        assert_artifact_directory_is_readonly(&artifact_dir);
        assert!(
            fs::metadata(preflight_path)
                .expect("preflight metadata")
                .permissions()
                .readonly()
        );

        restore_artifact_directory_permissions(&artifact_dir);
    }

    #[test]
    fn failed_artifact_run_retains_failure_and_manifest() {
        let temporary = tempfile::tempdir().expect("temporary artifact parent");
        let artifact_dir = temporary.path().join("artifact");
        fs::create_dir(&artifact_dir).expect("artifact directory");

        let error = finish_artifact_run(
            &artifact_dir,
            Err(io::Error::other("resource sampler failed").into()),
        )
        .expect_err("failed run");
        assert!(error.to_string().contains("resource sampler failed"));
        assert!(artifact_dir.join("failure.json").is_file());
        assert!(artifact_dir.join("manifest.json").is_file());
        assert!(artifact_dir.join("manifest.sha256").is_file());

        let failure: Value = serde_json::from_slice(
            &fs::read(artifact_dir.join("failure.json")).expect("failure artifact"),
        )
        .expect("failure JSON");
        assert_eq!(failure["error"], "resource sampler failed");
        assert_eq!(failure["schema_version"], 2);
        assert_eq!(failure["error_class"], "run");
        let manifest: Value = serde_json::from_slice(
            &fs::read(artifact_dir.join("manifest.json")).expect("manifest"),
        )
        .expect("manifest JSON");
        assert_eq!(manifest["files"][0]["path"], "failure.json");

        restore_artifact_directory_permissions(&artifact_dir);
    }
}
