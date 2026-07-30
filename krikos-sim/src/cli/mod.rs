//! Stable `cargo sim` command surface and versioned deterministic run/replay lanes.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

use clap::{Parser, Subcommand, ValueEnum};
use krikos_runtime::{RootSeed, TraceEvent, TraceSink, TraceSinkError};

use crate::{
    ArtifactError, ArtifactStore, ArtifactTraceWriter, BackendCapabilities, CampaignConfig,
    CampaignError, CampaignRunner, CampaignTerminal, CompatibilityError, Corpus, CorpusError,
    CorpusExpectation, CoverageError, CoverageLedger, CoverageObservation, CoveragePolicy,
    CoverageReport, DeterminismGrade, FailureArtifactBundle, FailureError, FailureReplayError,
    FailureSignature, GateError, GateSelection, GeneratorConfig, MANIFEST_SCHEMA_VERSION,
    ManifestError, MinimizationAttempt, MinimizationConfig, MinimizationError, Minimizer,
    OperationalOutcome, OperationalOutcomeClass, PARITY_FIXTURE_SCHEMA_VERSION, ParityBackend,
    ParityComparisonStatus, ParityError, ParityEvidence, ParityFixture, ParityFixtureResult,
    PatchbayReceipt, ReplayIdentity, RunBudgets, RunManifest, SCENARIO_SCHEMA_VERSION,
    SIMULATOR_VERSION, Scenario, ScenarioError, ScenarioGenerator, ScenarioHarness,
    ScenarioInventory, ScenarioModelError, ScenarioRunner, SeedLease, SeedLeaseError,
    SimulationGateTier, SoakConfig, SoakCryptoLane, SoakError, SoakLane, SoakPlan, SoakPlanError,
    SoakRunner, SoakSummary, SourceIdentity, Stage2Scenario, SwarmError, SwarmSpec, SwarmTemplate,
    TraceBuffer, bounded_io::read_file, canonical_patchbay_scenarios, compare_failure_replay,
    compare_parity_fixtures_at, derive_soak_seed_start, deterministic_semantic_outcome,
    normalized_trace_json, verify_failure_artifacts,
};

/// Exit code used when a requested later-stage backend is intentionally unavailable.
mod campaign;
mod corpus;
mod gate;
mod parity;
mod replay;
mod run;
mod shared;
mod soak;

use campaign::*;
use corpus::*;
use gate::*;
use parity::*;
use replay::*;
use run::*;
pub use shared::CliError;
use shared::*;
use soak::*;

pub const BACKEND_UNAVAILABLE_EXIT: u8 = 69;
const DEFAULT_WALL_EPOCH_SECS: u64 = 1_700_000_000;
const MAX_SOAK_FAILURE_ARTIFACTS: usize = 16;
const MAX_SOAK_ARTIFACT_BYTES: u64 = 256 * 1_024 * 1_024;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CryptoLane {
    DeterministicTest,
    ProductionProvider,
}

impl CryptoLane {
    const fn simulation_mode(self) -> krikos::simulation::SimulationCryptoMode {
        match self {
            Self::DeterministicTest => krikos::simulation::SimulationCryptoMode::DeterministicTest,
            Self::ProductionProvider => {
                krikos::simulation::SimulationCryptoMode::ProductionProvider
            }
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::DeterministicTest => "deterministic_test",
            Self::ProductionProvider => "production_provider",
        }
    }
}

/// Deterministic simulation command.
#[derive(Debug, Parser)]
#[command(name = "cargo sim", version, about)]
pub struct Cli {
    /// Simulator operation.
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Execute one versioned named or declarative scenario.
    Run {
        scenario: PathBuf,
        /// Lowercase 32-byte hexadecimal behavioral seed.
        #[arg(long)]
        seed: String,
        /// Immutable artifact directory (defaults under ./artifacts).
        #[arg(long)]
        artifacts: Option<PathBuf>,
        /// Cryptography lane: byte-replayable test crypto or semantic production crypto.
        #[arg(long, value_enum, default_value = "deterministic-test")]
        crypto: CryptoLane,
    },
    /// Execute a seeded campaign.
    Campaign {
        /// Canonical base scenario (omit when using `--swarm`).
        #[arg(required_unless_present = "swarm", conflicts_with = "swarm")]
        scenario: Option<PathBuf>,
        /// Strict swarm template to materialize once per seed.
        #[arg(long, conflicts_with_all = ["scenario", "generated"])]
        swarm: Option<PathBuf>,
        /// Half-open numeric seed range, for example `0..1000`.
        #[arg(long)]
        seeds: String,
        /// Parallel workers per deterministic batch.
        #[arg(long, default_value_t = 1)]
        jobs: usize,
        /// Campaign artifact root.
        #[arg(long)]
        artifacts: Option<PathBuf>,
        /// Finish all seeds instead of stopping after the first failing batch.
        #[arg(long)]
        continue_on_failure: bool,
        /// Generate one canonical scenario per seed from this scenario's bounds.
        #[arg(long)]
        generated: bool,
        /// Hard run-count bound.
        #[arg(long, default_value_t = 10_000)]
        max_runs: u64,
        /// Cryptography lane used by every run in this campaign.
        #[arg(long, value_enum, default_value = "deterministic-test")]
        crypto: CryptoLane,
    },
    /// Execute one bounded epoch from a strict multi-lane soak plan.
    Soak {
        /// Strict versioned soak plan.
        #[arg(long)]
        plan: PathBuf,
        /// Execute exactly one lane from the validated canonical plan.
        #[arg(long)]
        lane: Option<String>,
        /// Zero-based process ordinal in the daily seed window.
        #[arg(long)]
        epoch: u8,
        /// Monotonic workflow run number used to reserve replay seed space.
        #[arg(long)]
        seed_window: u64,
        /// Process wall budget in seconds.
        #[arg(long)]
        wall_seconds: u64,
        /// Parallel simulation workers.
        #[arg(long, default_value_t = 4)]
        jobs: usize,
        /// Scenarios between deadline checks and atomic checkpoints.
        #[arg(long, default_value_t = 64)]
        batch_runs: u64,
        /// Hard scenario count for this process.
        #[arg(long, default_value_t = 125_000)]
        max_runs: u64,
        /// Maximum retained failing runs.
        #[arg(long, default_value_t = MAX_SOAK_FAILURE_ARTIFACTS)]
        max_failure_artifacts: usize,
        /// Maximum retained failure-artifact bytes.
        #[arg(long, default_value_t = MAX_SOAK_ARTIFACT_BYTES)]
        max_artifact_bytes: u64,
        /// Fresh artifact directory for checkpoints and failures.
        #[arg(long)]
        artifacts: PathBuf,
    },
    /// Select bounded commit-derived pull-request or main gate work.
    GateSelect {
        /// Strict source-controlled path-to-domain policy.
        #[arg(long)]
        impact_policy: PathBuf,
        /// Coverage policy whose revision binds every derived seed.
        #[arg(long)]
        coverage_policy: PathBuf,
        /// Base Git revision; omit only when it cannot be resolved.
        #[arg(long)]
        base_revision: Option<String>,
        /// Exact candidate Git revision.
        #[arg(long)]
        candidate_revision: String,
        /// Pull-request or main budget tier.
        #[arg(long, value_enum)]
        tier: SimulationGateTier,
        /// Strict JSON array containing canonical changed paths.
        #[arg(long)]
        changes: PathBuf,
        /// Force the conservative all-domain fallback because no trustworthy diff exists.
        #[arg(long)]
        diff_unavailable: bool,
        /// Immutable gate-selection output.
        #[arg(long)]
        output: PathBuf,
    },
    /// Replay an exact versioned run manifest.
    Replay { manifest: PathBuf },
    /// Minimize a failing run.
    Minimize {
        manifest: PathBuf,
        /// Directory for the journal and atomically updated best scenario.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Continue from an existing best scenario and append to its journal.
        #[arg(long)]
        resume: bool,
        /// Maximum candidate executions in this invocation.
        #[arg(long, default_value_t = 10_000)]
        max_attempts: u64,
    },
    /// Inspect or update the regression corpus.
    Corpus {
        /// Corpus operation; Stage 3 supports `test`.
        operation: String,
        path: Option<PathBuf>,
    },
    /// Explain a manifest or trace artifact.
    Explain { artifact: PathBuf },
    /// Export or compare backend-neutral semantic parity fixtures.
    Parity {
        #[command(subcommand)]
        operation: ParityCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ParityCommand {
    /// Execute one canonical case and export a deterministic semantic fixture.
    Export {
        /// Canonical case: public, full-cone, port-restricted, symmetric, double-nat,
        /// degradation, outage-recovery, or switch-uplink.
        case: String,
        #[arg(long)]
        seed: String,
        #[arg(long)]
        source_revision: String,
        /// Explicit evidence observation epoch supplied by the backend job.
        #[arg(long)]
        observed_at_unix_secs: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Import observations emitted by a successful privileged Patchbay test.
    ImportPatchbay {
        receipt: PathBuf,
        #[arg(long)]
        source_revision: String,
        /// Explicit evidence observation epoch supplied by the Patchbay job.
        #[arg(long)]
        observed_at_unix_secs: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Compare two strict fixtures for their common declared semantic capabilities.
    Compare {
        expected: PathBuf,
        actual: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

/// Parses process arguments and returns a stable exit status.
pub fn run(args: impl IntoIterator<Item = OsString>) -> Result<(), CliError> {
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            print!("{error}");
            return Ok(());
        }
        Err(error) => return Err(CliError::Usage(error.to_string())),
    };
    match cli.command {
        Command::Run {
            scenario,
            seed,
            artifacts,
            crypto,
        } => execute_run(&scenario, &seed, artifacts.as_deref(), crypto),
        Command::Replay { manifest } => execute_replay(&manifest),
        Command::Campaign {
            scenario,
            swarm,
            seeds,
            jobs,
            artifacts,
            continue_on_failure,
            generated,
            max_runs,
            crypto,
        } => execute_campaign(CampaignOptions {
            scenario_path: scenario.as_deref(),
            swarm_path: swarm.as_deref(),
            seeds: &seeds,
            jobs,
            artifact_override: artifacts.as_deref(),
            continue_on_failure,
            generated,
            max_runs,
            crypto,
        }),
        Command::Soak {
            plan,
            lane,
            epoch,
            seed_window,
            wall_seconds,
            jobs,
            batch_runs,
            max_runs,
            max_failure_artifacts,
            max_artifact_bytes,
            artifacts,
        } => execute_soak(SoakOptions {
            plan_path: &plan,
            lane: lane.as_deref(),
            epoch,
            seed_window,
            wall_seconds,
            jobs,
            batch_runs,
            max_runs,
            max_failure_artifacts,
            max_artifact_bytes,
            artifact_root: &artifacts,
        }),
        Command::GateSelect {
            impact_policy,
            coverage_policy,
            base_revision,
            candidate_revision,
            tier,
            changes,
            diff_unavailable,
            output,
        } => execute_gate_select(
            &impact_policy,
            &coverage_policy,
            base_revision.as_deref(),
            &candidate_revision,
            tier,
            &changes,
            diff_unavailable,
            &output,
        ),
        Command::Minimize {
            manifest,
            output,
            resume,
            max_attempts,
        } => execute_minimize(&manifest, output.as_deref(), resume, max_attempts),
        Command::Corpus { operation, path } => execute_corpus(&operation, path.as_deref()),
        Command::Explain { artifact } => execute_explain(&artifact),
        Command::Parity { operation } => match operation {
            ParityCommand::Export {
                case,
                seed,
                source_revision,
                observed_at_unix_secs,
                output,
            } => execute_parity_export(
                &case,
                &seed,
                &source_revision,
                observed_at_unix_secs,
                &output,
            ),
            ParityCommand::ImportPatchbay {
                receipt,
                source_revision,
                observed_at_unix_secs,
                output,
            } => {
                execute_patchbay_import(&receipt, &source_revision, observed_at_unix_secs, &output)
            }
            ParityCommand::Compare {
                expected,
                actual,
                output,
            } => execute_parity_compare(&expected, &actual, output.as_deref()),
        },
    }
}
