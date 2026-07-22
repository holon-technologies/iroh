//! Stable `cargo sim` command surface and versioned deterministic run/replay lanes.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
    sync::Arc,
    time::{Duration, SystemTime},
};

use clap::{Parser, Subcommand, ValueEnum};
use iroh_runtime::{RootSeed, TraceEvent, TraceSink, TraceSinkError};

use crate::{
    ArtifactError, ArtifactStore, ArtifactTraceWriter, BackendCapabilities, CampaignConfig,
    CampaignError, CampaignRunner, CampaignTerminal, CompatibilityError, Corpus, CorpusError,
    CorpusExpectation, DeterminismGrade, FailureArtifactBundle, FailureError, FailureReplayError,
    FailureSignature, GeneratorConfig, MANIFEST_SCHEMA_VERSION, ManifestError, MinimizationAttempt,
    MinimizationConfig, MinimizationError, Minimizer, PARITY_FIXTURE_SCHEMA_VERSION, ParityBackend,
    ParityComparisonStatus, ParityError, ParityEvidence, ParityFixture, ParityFixtureResult,
    PatchbayReceipt, ReplayIdentity, RunBudgets, RunManifest, SCENARIO_SCHEMA_VERSION,
    SIMULATOR_VERSION, Scenario, ScenarioError, ScenarioGenerator, ScenarioHarness,
    ScenarioInventory, ScenarioModelError, ScenarioRunner, SourceIdentity, Stage2Scenario,
    SwarmError, SwarmSpec, SwarmTemplate, TraceBuffer, canonical_patchbay_scenarios,
    compare_failure_replay, compare_parity_fixtures_at, deterministic_semantic_outcome,
    normalized_trace_json, verify_failure_artifacts,
};

/// Exit code used when a requested later-stage backend is intentionally unavailable.
pub const BACKEND_UNAVAILABLE_EXIT: u8 = 69;
const DEFAULT_WALL_EPOCH_SECS: u64 = 1_700_000_000;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CryptoLane {
    DeterministicTest,
    ProductionProvider,
}

impl CryptoLane {
    const fn simulation_mode(self) -> iroh::simulation::SimulationCryptoMode {
        match self {
            Self::DeterministicTest => iroh::simulation::SimulationCryptoMode::DeterministicTest,
            Self::ProductionProvider => iroh::simulation::SimulationCryptoMode::ProductionProvider,
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

fn execute_run(
    scenario_path: &Path,
    seed_hex: &str,
    artifact_override: Option<&Path>,
    crypto: CryptoLane,
) -> Result<(), CliError> {
    let scenario_bytes = fs::read(scenario_path).map_err(CliError::Io)?;
    let schema_version = scenario_schema_version(&scenario_bytes)?;
    if schema_version == SCENARIO_SCHEMA_VERSION {
        return execute_declarative_run(
            Scenario::from_json(&scenario_bytes)?,
            seed_hex,
            artifact_override,
            crypto,
        );
    }
    let scenario = Stage2Scenario::from_json(&scenario_bytes)?;
    let seed = parse_seed(seed_hex)?;
    let workspace = workspace_root()?;
    let budgets = default_budgets();
    let wall_epoch = SystemTime::UNIX_EPOCH + Duration::from_secs(DEFAULT_WALL_EPOCH_SECS);
    let requested_artifact_root = artifact_override
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_artifact_root(&workspace, &scenario, seed_hex));
    let requested_artifact_root = absolutize(&requested_artifact_root)?;
    let store = ArtifactStore::new(&requested_artifact_root)?;
    let artifact_root = store.root().to_path_buf();
    let identity = scenario_identity(&workspace, &scenario, Some(&artifact_root))?;
    let trace_writer = Arc::new(ArtifactTraceWriter::new(store.clone(), 64)?);
    let harness = ScenarioHarness::new_with_crypto_mode_and_trace_sink(
        scenario.clone(),
        seed,
        wall_epoch,
        &budgets,
        trace_writer.clone(),
        crypto.simulation_mode(),
    )?;
    let fault_profile = identity
        .normalized_config
        .get("network_faults")
        .expect("scenario identity always includes network_faults")
        .clone();
    let manifest = RunManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        simulator_version: SIMULATOR_VERSION.to_owned(),
        source: identity.source,
        root_seed: seed_hex.to_owned(),
        scenario_id: scenario.id.clone(),
        scenario_hash: identity.scenario_hash,
        normalized_config: identity.normalized_config,
        features: identity.features,
        wall_clock_epoch_secs: DEFAULT_WALL_EPOCH_SECS,
        backend: harness.backend().capabilities(),
        budgets,
        scheduling_profile: "seeded-fair-kernel+root-driver".to_owned(),
        fault_profile,
        lockfile_digest: identity.lockfile_digest,
        crypto_mode: harness.backend().crypto_mode(),
        trace_comparison: harness.backend().trace_comparison(),
        fidelity_exceptions: harness.backend().fidelity_exceptions(),
        determinism_grade: harness.backend().determinism_grade(),
        escapes: harness.backend().escapes(),
        unsafe_test_only: true,
    };
    let manifest_path = store.write_manifest("manifest.json", &manifest)?;

    let runtime = simulation_runtime().map_err(|error| CliError::PostManifestFailure {
        error: error.to_string(),
        manifest: manifest_path.clone(),
    })?;
    let result = runtime.block_on(harness.run());
    trace_writer
        .flush()
        .map_err(|error| CliError::PostManifestFailure {
            error: error.to_string(),
            manifest: manifest_path.clone(),
        })?;
    let events = harness.trace();
    store
        .write_raw_trace("trace.raw.jsonl", &events)
        .map_err(|error| CliError::PostManifestFailure {
            error: error.to_string(),
            manifest: manifest_path.clone(),
        })?;
    store
        .write_trace("trace.jsonl", &events)
        .map_err(|error| CliError::PostManifestFailure {
            error: error.to_string(),
            manifest: manifest_path.clone(),
        })?;
    match result {
        Ok(observation) => {
            println!(
                "status=ok scenario={} events={} virtual_time_nanos={} packet_high_water={} artifacts={}",
                scenario.id,
                observation.events,
                observation.virtual_time.as_nanos(),
                observation.packet_high_water,
                artifact_root.display()
            );
            println!("cargo sim replay {}", manifest_path.display());
            Ok(())
        }
        Err(error) => Err(CliError::RunFailed {
            error,
            manifest: manifest_path,
        }),
    }
}

fn execute_declarative_run(
    scenario: Scenario,
    seed_hex: &str,
    artifact_override: Option<&Path>,
    crypto: CryptoLane,
) -> Result<(), CliError> {
    let seed = parse_seed(seed_hex)?;
    let workspace = workspace_root()?;
    let wall_epoch = SystemTime::UNIX_EPOCH + Duration::from_secs(DEFAULT_WALL_EPOCH_SECS);
    let requested_artifact_root = artifact_override
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_declarative_artifact_root(&workspace, &scenario, seed_hex));
    let store = ArtifactStore::new(absolutize(&requested_artifact_root)?)?;
    let artifact_root = store.root().to_path_buf();
    let identity = declarative_scenario_identity(&workspace, &scenario, Some(&artifact_root))?;
    let durable = ArtifactTraceWriter::new(store.clone(), 64)?;
    let memory = TraceBuffer::default();
    let trace = Arc::new(CapturingTraceSink {
        durable: durable.clone(),
        memory: memory.clone(),
    });
    let runner = ScenarioRunner::with_crypto_mode(
        scenario.clone(),
        seed,
        wall_epoch,
        trace,
        crypto.simulation_mode(),
    )?;
    let budgets = scenario.run_budgets();
    let manifest = RunManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        simulator_version: SIMULATOR_VERSION.to_owned(),
        source: identity.source,
        root_seed: seed_hex.to_owned(),
        scenario_id: scenario.metadata.id.clone(),
        scenario_hash: identity.scenario_hash,
        normalized_config: identity.normalized_config,
        features: identity.features,
        wall_clock_epoch_secs: DEFAULT_WALL_EPOCH_SECS,
        backend: BackendCapabilities::deterministic_kernel(),
        budgets,
        scheduling_profile: "seeded-fair-kernel+root-driver+declarative-v2".to_owned(),
        fault_profile: identity.fault_profile,
        lockfile_digest: identity.lockfile_digest,
        crypto_mode: manifest_crypto_mode(crypto.simulation_mode()),
        trace_comparison: trace_comparison(crypto.simulation_mode()),
        fidelity_exceptions: fidelity_exceptions(crypto.simulation_mode()),
        determinism_grade: determinism_grade(crypto.simulation_mode()),
        escapes: crypto_escapes(crypto.simulation_mode()),
        unsafe_test_only: true,
    };
    let manifest_path = store.write_manifest("manifest.json", &manifest)?;
    store
        .write_atomic(
            "scenario.json",
            &scenario
                .to_canonical_json()
                .map_err(|error| CliError::PostManifestFailure {
                    error: error.to_string(),
                    manifest: manifest_path.clone(),
                })?,
        )
        .map_err(|error| CliError::PostManifestFailure {
            error: error.to_string(),
            manifest: manifest_path.clone(),
        })?;
    let runtime = simulation_runtime().map_err(|error| CliError::PostManifestFailure {
        error: error.to_string(),
        manifest: manifest_path.clone(),
    })?;
    let result = runtime.block_on(runner.run_detailed());
    durable
        .flush()
        .map_err(|error| CliError::PostManifestFailure {
            error: error.to_string(),
            manifest: manifest_path.clone(),
        })?;
    let events = memory.events();
    match result {
        Ok(report) => {
            store
                .write_raw_trace("trace.raw.jsonl", &events)
                .and_then(|_| store.write_trace("trace.jsonl", &events))
                .map_err(|error| CliError::PostManifestFailure {
                    error: error.to_string(),
                    manifest: manifest_path.clone(),
                })?;
            write_json_artifact(&store, "terminal-report.json", &report, &manifest_path)?;
            write_json_artifact(
                &store,
                "invariant-snapshot.json",
                &report.invariants,
                &manifest_path,
            )?;
            write_json_artifact(
                &store,
                "resource-snapshot.json",
                &report.resources,
                &manifest_path,
            )?;
            write_json_artifact(
                &store,
                "scheduler-snapshot.json",
                &report.scheduler,
                &manifest_path,
            )?;
            write_json_artifact(&store, "task-ownership.json", &report.tasks, &manifest_path)?;
            write_json_artifact(
                &store,
                "scenario-inventory.json",
                &ScenarioInventory::from_scenario(&scenario),
                &manifest_path,
            )?;
            println!(
                "status=ok scenario={} observations={} virtual_time_nanos={} artifacts={}",
                scenario.metadata.id,
                report.observations.len(),
                report.virtual_time_nanos,
                artifact_root.display()
            );
            println!("cargo sim replay {}", manifest_path.display());
            Ok(())
        }
        Err(failure) => {
            let signature = FailureSignature::from_runner_error(&failure.error, &events, 64)?;
            FailureArtifactBundle {
                scenario: &scenario,
                error: &failure.error,
                signature: &signature,
                invariants: &failure.invariants,
                resources: &failure.resources,
                model: Some(&failure.model),
                observations: Some(&failure.observations),
                virtual_time_nanos: Some(failure.virtual_time_nanos),
                scheduler: failure.scheduler.as_ref(),
                tasks: Some(&failure.tasks),
                trace: &events,
                events_per_chunk: 64,
            }
            .write(&store)
            .map_err(|error| CliError::PostManifestFailure {
                error: error.to_string(),
                manifest: manifest_path.clone(),
            })?;
            if scenario
                .allowed_terminals
                .contains(&crate::AllowedTerminal::ExpectedFailure)
            {
                println!(
                    "status=expected_failure scenario={} class={} signature={} artifacts={}",
                    scenario.metadata.id,
                    signature.terminal_class.as_str(),
                    signature.causal_suffix_digest,
                    artifact_root.display()
                );
                println!("cargo sim replay {}", manifest_path.display());
                Ok(())
            } else {
                Err(CliError::DeclarativeRunFailed {
                    error: failure.error.to_string(),
                    manifest: manifest_path,
                    signature: signature.causal_suffix_digest,
                })
            }
        }
    }
}

fn execute_declarative_replay(
    manifest_path: &Path,
    manifest: &RunManifest,
    artifact_root: &Path,
) -> Result<(), CliError> {
    let scenario = Scenario::from_json(&fs::read(artifact_root.join("scenario.json"))?)?;
    let workspace = workspace_root()?;
    let identity = declarative_scenario_identity(&workspace, &scenario, Some(artifact_root))?;
    manifest.check_compatible(&ReplayIdentity {
        schema_version: MANIFEST_SCHEMA_VERSION,
        simulator_version: SIMULATOR_VERSION.to_owned(),
        source: identity.source,
        scenario_hash: identity.scenario_hash,
        normalized_config: identity.normalized_config,
        features: identity.features,
        lockfile_digest: identity.lockfile_digest,
    })?;
    let simulation_crypto_mode = simulation_crypto_mode(manifest.crypto_mode);
    if manifest.backend != BackendCapabilities::deterministic_kernel()
        || manifest.determinism_grade != determinism_grade(simulation_crypto_mode)
        || manifest.trace_comparison != trace_comparison(simulation_crypto_mode)
        || manifest.fidelity_exceptions != fidelity_exceptions(simulation_crypto_mode)
        || manifest.scheduling_profile != "seeded-fair-kernel+root-driver+declarative-v2"
        || manifest.fault_profile != identity.fault_profile
        || manifest.escapes != crypto_escapes(simulation_crypto_mode)
    {
        return Err(CliError::BackendIdentityMismatch);
    }
    let expected_failure = artifact_root.join("failure-signature.json").is_file();
    if expected_failure {
        verify_failure_artifacts(artifact_root)?;
    }
    let seed = parse_seed(&manifest.root_seed)?;
    let wall_epoch = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(manifest.wall_clock_epoch_secs))
        .ok_or(CliError::WallEpochOverflow)?;
    let trace = TraceBuffer::default();
    let runner = ScenarioRunner::with_crypto_mode(
        scenario,
        seed,
        wall_epoch,
        Arc::new(trace.clone()),
        simulation_crypto_mode,
    )?;
    let result = simulation_runtime()?.block_on(runner.run_detailed());
    let actual_trace = trace.events();
    let expected_trace = read_trace_jsonl(&artifact_root.join("trace.raw.jsonl"))?;
    if expected_failure {
        let expected_signature =
            FailureSignature::from_json(&fs::read(artifact_root.join("failure-signature.json"))?)?;
        let actual_signature = match &result {
            Err(failure) => Some(FailureSignature::from_runner_error(
                &failure.error,
                &actual_trace,
                usize::from(expected_signature.causal_event_count.max(1)),
            )?),
            Ok(_) => None,
        };
        compare_failure_replay(
            &expected_signature,
            actual_signature.as_ref(),
            &expected_trace,
            &actual_trace,
        )?;
        if manifest.trace_comparison == crate::TraceComparisonMode::Raw
            && expected_trace != actual_trace
        {
            return Err(CliError::TraceDivergence {
                line: first_raw_trace_divergence(&expected_trace, &actual_trace) + 1,
            });
        }
        println!(
            "status=replay_ok terminal=expected_failure scenario={} manifest={}",
            manifest.scenario_id,
            manifest_path.display()
        );
        return Ok(());
    }
    result.map_err(|failure| CliError::UnexpectedDeclarativeFailure(failure.error.to_string()))?;
    match manifest.trace_comparison {
        crate::TraceComparisonMode::Raw if expected_trace != actual_trace => {
            return Err(CliError::TraceDivergence {
                line: first_raw_trace_divergence(&expected_trace, &actual_trace) + 1,
            });
        }
        crate::TraceComparisonMode::Semantic => {
            if let Some(divergence) = crate::first_trace_divergence(&expected_trace, &actual_trace)
                .map_err(|error| CliError::Trace(error.to_string()))?
            {
                return Err(CliError::TraceDivergence {
                    line: divergence.index + 1,
                });
            }
        }
        crate::TraceComparisonMode::Raw => {}
    }
    println!(
        "status=replay_ok terminal=success scenario={} manifest={}",
        manifest.scenario_id,
        manifest_path.display()
    );
    Ok(())
}

fn execute_minimize(
    manifest_path: &Path,
    output: Option<&Path>,
    resume: bool,
    max_attempts: u64,
) -> Result<(), CliError> {
    let manifest_path = fs::canonicalize(absolutize(manifest_path)?)?;
    let artifact_root = manifest_path
        .parent()
        .ok_or(CliError::ManifestHasNoParent)?;
    verify_failure_artifacts(artifact_root)?;
    let manifest = RunManifest::from_json(&fs::read(&manifest_path)?)?;
    let workspace = workspace_root()?;
    let scenario = Scenario::from_json(&fs::read(artifact_root.join("scenario.json"))?)?;
    let identity = declarative_scenario_identity(&workspace, &scenario, Some(artifact_root))?;
    manifest.check_compatible(&ReplayIdentity {
        schema_version: MANIFEST_SCHEMA_VERSION,
        simulator_version: SIMULATOR_VERSION.to_owned(),
        source: identity.source,
        scenario_hash: identity.scenario_hash,
        normalized_config: identity.normalized_config,
        features: identity.features,
        lockfile_digest: identity.lockfile_digest,
    })?;
    let expected =
        FailureSignature::from_json(&fs::read(artifact_root.join("failure-signature.json"))?)?;
    let output = absolutize(
        output
            .map(Path::to_path_buf)
            .unwrap_or_else(|| artifact_root.join("minimized"))
            .as_path(),
    )?;
    let mut progress = MinimizationProgress::open(&output, resume)?;
    let starting = progress.resume_scenario()?.unwrap_or(scenario);
    progress.publish_best(&starting)?;

    let seed = parse_seed(&manifest.root_seed)?;
    let wall_epoch = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(manifest.wall_clock_epoch_secs))
        .ok_or(CliError::WallEpochOverflow)?;
    let suffix_bound = usize::from(expected.causal_event_count.max(1));
    let mut evaluator = |candidate: &Scenario| {
        let trace = TraceBuffer::default();
        let runner = ScenarioRunner::deterministic(
            candidate.clone(),
            seed,
            wall_epoch,
            Arc::new(trace.clone()),
        )
        .map_err(|error| error.to_string())?;
        let runtime = simulation_runtime().map_err(|error| error.to_string())?;
        match runtime.block_on(runner.run_detailed()) {
            Ok(_) => Ok(None),
            Err(failure) => {
                FailureSignature::from_runner_error(&failure.error, &trace.events(), suffix_bound)
                    .map(Some)
                    .map_err(|error| error.to_string())
            }
        }
    };
    let mut observer = |attempt: &MinimizationAttempt, accepted: Option<&Scenario>| {
        progress
            .record(attempt, accepted)
            .map_err(|error| error.to_string())
    };
    let result = Minimizer::new(MinimizationConfig { max_attempts }).minimize_with_observer(
        starting,
        expected,
        &mut evaluator,
        &mut observer,
    )?;
    progress.publish_result(&result)?;
    let status = if result.original_bytes == result.minimized_bytes {
        "already_minimal"
    } else if result.exhausted {
        "budget_exhausted"
    } else {
        "minimized"
    };
    println!(
        "status={status} attempts={} original_bytes={} minimized_bytes={} best={}",
        result.attempts.len(),
        result.original_bytes,
        result.minimized_bytes,
        output.join("best.scenario.json").display()
    );
    Ok(())
}

fn execute_parity_export(
    case_name: &str,
    seed_hex: &str,
    source_revision: &str,
    observed_at_unix_secs: u64,
    output: &Path,
) -> Result<(), CliError> {
    let case = canonical_patchbay_scenarios()?
        .into_iter()
        .find(|entry| parity_case_name(entry.case) == case_name)
        .ok_or_else(|| CliError::InvalidParityCase(case_name.to_owned()))?;
    let seed = parse_seed(seed_hex)?;
    let case_id = case.scenario.metadata.id.clone();
    let scenario_hash = blake3::hash(&case.scenario.to_canonical_json()?)
        .to_hex()
        .to_string();
    let mut run_hasher = blake3::Hasher::new_derive_key("iroh-sim parity evidence run id v1");
    run_hasher.update(source_revision.as_bytes());
    run_hasher.update(seed.as_bytes());
    run_hasher.update(scenario_hash.as_bytes());
    let trace = Arc::new(TraceBuffer::default());
    let runner = ScenarioRunner::deterministic(
        case.scenario,
        seed,
        SystemTime::UNIX_EPOCH + Duration::from_secs(DEFAULT_WALL_EPOCH_SECS),
        trace.clone(),
    )?;
    let report = simulation_runtime()?
        .block_on(runner.run_detailed())
        .map_err(|failure| CliError::UnexpectedDeclarativeFailure(failure.error.to_string()))?;
    let fixture = ParityFixture {
        schema_version: PARITY_FIXTURE_SCHEMA_VERSION,
        case_id,
        backend: ParityBackend::Deterministic,
        source_revision: source_revision.to_owned(),
        evidence: ParityEvidence {
            run_id: run_hasher.finalize().to_hex().to_string(),
            scenario_hash,
            observed_at_unix_secs,
            valid_for_secs: 30 * 24 * 60 * 60,
        },
        observed_dimensions: case.compared_dimensions.clone(),
        capabilities: case.compared_dimensions,
        result: ParityFixtureResult::Completed {
            outcome: deterministic_semantic_outcome(&report, &trace.events()),
        },
    };
    write_immutable(output, &fixture.to_canonical_json()?)?;
    println!(
        "status=parity_exported case={} backend=deterministic output={}",
        fixture.case_id,
        output.display()
    );
    Ok(())
}

fn execute_parity_compare(
    expected_path: &Path,
    actual_path: &Path,
    output: Option<&Path>,
) -> Result<(), CliError> {
    let expected = ParityFixture::from_json(&fs::read(expected_path)?)?;
    let actual = ParityFixture::from_json(&fs::read(actual_path)?)?;
    let now_unix_secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|error| CliError::Identity(error.to_string()))?
        .as_secs();
    let comparison = compare_parity_fixtures_at(&expected, &actual, now_unix_secs)?;
    let mut bytes = serde_json::to_vec_pretty(&comparison)
        .map_err(|error| CliError::Trace(error.to_string()))?;
    bytes.push(b'\n');
    if let Some(output) = output {
        write_immutable(output, &bytes)?;
    }
    print!("{}", String::from_utf8_lossy(&bytes));
    match comparison.status {
        ParityComparisonStatus::Match => Ok(()),
        ParityComparisonStatus::Difference | ParityComparisonStatus::Skipped => {
            Err(CliError::ParityDifference(comparison.differences.clone()))
        }
    }
}

fn execute_patchbay_import(
    receipt_path: &Path,
    source_revision: &str,
    observed_at_unix_secs: u64,
    output: &Path,
) -> Result<(), CliError> {
    let receipt = PatchbayReceipt::from_json(&fs::read(receipt_path)?)?;
    let case = canonical_patchbay_scenarios()?
        .into_iter()
        .find(|entry| entry.scenario.metadata.id == receipt.case_id)
        .ok_or_else(|| CliError::InvalidParityCase(receipt.case_id.clone()))?;
    let scenario_hash = blake3::hash(&case.scenario.to_canonical_json()?)
        .to_hex()
        .to_string();
    let fixture = receipt.to_fixture(source_revision, scenario_hash, observed_at_unix_secs)?;
    write_immutable(output, &fixture.to_canonical_json()?)?;
    println!(
        "status=parity_imported case={} backend=patchbay output={}",
        fixture.case_id,
        output.display()
    );
    Ok(())
}

fn parity_case_name(case: crate::CanonicalParityCase) -> &'static str {
    use crate::CanonicalParityCase as Case;
    match case {
        Case::Public => "public",
        Case::FullCone => "full-cone",
        Case::PortRestricted => "port-restricted",
        Case::Symmetric => "symmetric",
        Case::DoubleNat => "double-nat",
        Case::Degradation => "degradation",
        Case::OutageRecovery => "outage-recovery",
        Case::SwitchUplink => "switch-uplink",
    }
}

fn write_immutable(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let path = absolutize(path)?;
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn execute_corpus(operation: &str, root: Option<&Path>) -> Result<(), CliError> {
    if operation != "test" {
        return Err(CliError::Usage(format!(
            "unsupported corpus operation {operation:?}; expected `test`"
        )));
    }
    let workspace = workspace_root()?;
    let root = absolutize(
        root.map(Path::to_path_buf)
            .unwrap_or_else(|| workspace.join("iroh-sim/corpus"))
            .as_path(),
    )?;
    let corpus = Corpus::load(&root)?;
    let reports = corpus.test(|entry| {
        let seed = parse_seed(&entry.metadata.seed).map_err(|error| error.to_string())?;
        let trace = TraceBuffer::default();
        let runner = ScenarioRunner::deterministic(
            entry.scenario.clone(),
            seed,
            SystemTime::UNIX_EPOCH + Duration::from_secs(DEFAULT_WALL_EPOCH_SECS),
            Arc::new(trace.clone()),
        )
        .map_err(|error| error.to_string())?;
        match simulation_runtime()
            .map_err(|error| error.to_string())?
            .block_on(runner.run_detailed())
        {
            Ok(_) => Ok(None),
            Err(failure) => {
                let suffix_bound = match &entry.metadata.expectation {
                    CorpusExpectation::ExpectedFailure { signature } => {
                        usize::from(signature.causal_event_count.max(1))
                    }
                    CorpusExpectation::Success => 64,
                };
                FailureSignature::from_runner_error(&failure.error, &trace.events(), suffix_bound)
                    .map(Some)
                    .map_err(|error| error.to_string())
            }
        }
    })?;
    println!(
        "status=corpus_ok entries={} root={}",
        reports.len(),
        root.display()
    );
    Ok(())
}

struct CampaignOptions<'a> {
    scenario_path: Option<&'a Path>,
    swarm_path: Option<&'a Path>,
    seeds: &'a str,
    jobs: usize,
    artifact_override: Option<&'a Path>,
    continue_on_failure: bool,
    generated: bool,
    max_runs: u64,
    crypto: CryptoLane,
}

fn execute_campaign(options: CampaignOptions<'_>) -> Result<(), CliError> {
    let CampaignOptions {
        scenario_path,
        swarm_path,
        seeds,
        jobs,
        artifact_override,
        continue_on_failure,
        generated,
        max_runs,
        crypto,
    } = options;
    let workspace = workspace_root()?;
    let (swarm, swarm_template_bytes) = match swarm_path {
        Some(path) => {
            let (swarm, template_bytes) = load_swarm_template(path, &workspace)?;
            (Some(swarm), Some(template_bytes))
        }
        None => (None, None),
    };
    let scenario = match (&swarm, scenario_path) {
        (Some(swarm), None) => swarm.base.clone(),
        (None, Some(path)) => Scenario::from_versioned_json(&fs::read(path)?)?,
        _ => {
            return Err(CliError::Usage(
                "campaign requires exactly one scenario or --swarm".into(),
            ));
        }
    };
    let (seed_start, seed_end_exclusive) = parse_seed_range(seeds)?;
    let requested_root = artifact_override.map(Path::to_path_buf).unwrap_or_else(|| {
        workspace.join("artifacts").join(format!(
            "campaign-{}-{seed_start}-{seed_end_exclusive}",
            scenario.metadata.id.replace('/', "-")
        ))
    });
    let campaign_store = ArtifactStore::new(absolutize(&requested_root)?)?;
    let campaign_root = campaign_store.root().to_path_buf();
    campaign_store.write_atomic(
        "crypto-mode.txt",
        format!("{}\n", crypto.as_str()).as_bytes(),
    )?;
    if let Some(swarm) = &swarm {
        campaign_store.write_atomic("swarm.json", &swarm.to_canonical_json()?)?;
        let template_bytes = swarm_template_bytes
            .as_deref()
            .expect("a loaded swarm always retains its source template bytes");
        campaign_store.write_atomic("swarm-template.json", template_bytes)?;
        let digest = format!("{}\n", blake3::hash(template_bytes).to_hex());
        campaign_store.write_atomic("swarm-template.blake3", digest.as_bytes())?;
    }
    let execute = |seed_ordinal: u64, template: &Scenario| {
        let (seed, seed_hex) = campaign_seed(seed_ordinal);
        let (candidate, selection) = if let Some(swarm) = &swarm {
            let (scenario, selection) = swarm
                .materialize(swarm_materialization_seed(seed))
                .map_err(|error| error.to_string())?;
            (scenario, Some(selection))
        } else if generated {
            let scenario = ScenarioGenerator::new(
                seed,
                GeneratorConfig {
                    max_actions: template.budgets.max_actions.max(7),
                    max_payload_bytes: template.budgets.max_payload_bytes,
                    max_virtual_time: Duration::from_nanos(template.budgets.max_virtual_time_nanos),
                },
            )
            .generate(&format!("{}/seed-{seed_ordinal}", template.metadata.id))
            .map_err(|error| error.to_string())?;
            (scenario, None)
        } else {
            (template.clone(), None)
        };
        let trace = TraceBuffer::default();
        let runner = ScenarioRunner::with_crypto_mode(
            candidate.clone(),
            seed,
            SystemTime::UNIX_EPOCH + Duration::from_secs(DEFAULT_WALL_EPOCH_SECS),
            Arc::new(trace.clone()),
            crypto.simulation_mode(),
        )
        .map_err(|error| error.to_string())?;
        let result = simulation_runtime()
            .map_err(|error| error.to_string())?
            .block_on(runner.run_detailed());
        let events = trace.events();
        let run_store = ArtifactStore::new(campaign_root.join(format!("seed-{seed_ordinal:020}")))
            .map_err(|error| error.to_string())?;
        run_store
            .write_atomic("seed.txt", format!("{seed_hex}\n").as_bytes())
            .map_err(|error| error.to_string())?;
        if let Some(selection) = &selection {
            let mut bytes =
                serde_json::to_vec_pretty(selection).map_err(|error| error.to_string())?;
            bytes.push(b'\n');
            run_store
                .write_atomic("swarm-selection.json", &bytes)
                .map_err(|error| error.to_string())?;
        }
        match result {
            Ok(report) => {
                write_campaign_success(&run_store, &candidate, &report, &events)
                    .map_err(|error| error.to_string())?;
                Ok(CampaignTerminal::Success)
            }
            Err(failure) => {
                let signature = FailureSignature::from_runner_error(&failure.error, &events, 64)
                    .map_err(|error| error.to_string())?;
                FailureArtifactBundle {
                    scenario: &candidate,
                    error: &failure.error,
                    signature: &signature,
                    invariants: &failure.invariants,
                    resources: &failure.resources,
                    model: Some(&failure.model),
                    observations: Some(&failure.observations),
                    virtual_time_nanos: Some(failure.virtual_time_nanos),
                    scheduler: failure.scheduler.as_ref(),
                    tasks: Some(&failure.tasks),
                    trace: &events,
                    events_per_chunk: 64,
                }
                .write(&run_store)
                .map_err(|error| error.to_string())?;
                Ok(CampaignTerminal::Failure(signature))
            }
        }
    };
    let summary = CampaignRunner::run(
        CampaignConfig {
            seed_start,
            seed_end_exclusive,
            jobs,
            fail_fast: !continue_on_failure,
            max_runs,
        },
        &scenario,
        &execute,
    )?;
    let mut summary_bytes =
        serde_json::to_vec_pretty(&summary).map_err(|error| CliError::Trace(error.to_string()))?;
    summary_bytes.push(b'\n');
    campaign_store.write_atomic("campaign-summary.json", &summary_bytes)?;
    let run_failures = summary
        .results
        .iter()
        .filter(|result| {
            result.error.is_some() || matches!(result.terminal, Some(CampaignTerminal::Failure(_)))
        })
        .count();
    if run_failures != 0 {
        return Err(CliError::CampaignRunFailures(run_failures));
    }
    println!(
        "status=campaign_ok runs={} unique_failures={} stopped_early={} artifacts={}",
        summary.results.len(),
        summary.unique_failures.len(),
        summary.stopped_early,
        campaign_root.display()
    );
    Ok(())
}

fn load_swarm_template(path: &Path, workspace: &Path) -> Result<(SwarmSpec, Vec<u8>), CliError> {
    let template_bytes = fs::read(path)?;
    let template = SwarmTemplate::from_json(&template_bytes)?;
    let base_bytes = match template.base_path() {
        None => Vec::new(),
        Some(base_path) => {
            let canonical_workspace = workspace.canonicalize().map_err(CliError::Io)?;
            let canonical_base = workspace
                .join(base_path)
                .canonicalize()
                .map_err(CliError::Io)?;
            if !canonical_base.starts_with(&canonical_workspace) {
                return Err(CliError::Usage(
                    "referenced swarm base resolves outside the workspace".into(),
                ));
            }
            fs::read(canonical_base)?
        }
    };
    Ok((template.resolve(&base_bytes)?, template_bytes))
}

fn execute_explain(artifact: &Path) -> Result<(), CliError> {
    let artifact = fs::canonicalize(absolutize(artifact)?)?;
    let root = if artifact.is_dir() {
        artifact
    } else {
        artifact
            .parent()
            .ok_or(CliError::ManifestHasNoParent)?
            .to_path_buf()
    };
    let manifest_path = root.join("manifest.json");
    let manifest = if manifest_path.is_file() {
        Some(RunManifest::from_json(&fs::read(&manifest_path)?)?)
    } else {
        None
    };
    let signature_path = root.join("failure-signature.json");
    let signature = if signature_path.is_file() {
        Some(FailureSignature::from_json(&fs::read(&signature_path)?)?)
    } else {
        None
    };
    if signature.is_some() {
        verify_failure_artifacts(&root)?;
    }
    let trace_path = root.join("trace.raw.jsonl");
    let trace = if trace_path.is_file() {
        read_trace_jsonl(&trace_path)?
    } else {
        Vec::new()
    };
    let suffix_events = signature.as_ref().map_or(16usize, |value| {
        usize::from(value.causal_event_count.max(1))
    });
    let causal_trace = trace
        .into_iter()
        .rev()
        .take(suffix_events)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>();
    let terminal = read_optional_json(&root.join("terminal-report.json"))?;
    let invariants = read_optional_json(&root.join("invariant-snapshot.json"))?;
    let resources = read_optional_json(&root.join("resource-snapshot.json"))?;
    let scheduler = read_optional_json(&root.join("scheduler-snapshot.json"))?;
    let task_ownership = read_optional_json(&root.join("task-ownership.json"))?;
    let scenario_inventory = read_optional_json(&root.join("scenario-inventory.json"))?;
    let replay_command = manifest
        .as_ref()
        .map(|_| format!("cargo sim replay {}", manifest_path.display()));
    let minimize_command = signature
        .as_ref()
        .map(|_| format!("cargo sim minimize {}", manifest_path.display()));
    let report = serde_json::json!({
        "status": "explained",
        "scenario": manifest.as_ref().map(|value| value.scenario_id.as_str()),
        "terminal": terminal,
        "failure_signature": signature,
        "causal_trace_suffix": causal_trace,
        "invariants": invariants,
        "resources": resources,
        "scheduler": scheduler,
        "task_ownership": task_ownership,
        "scenario_inventory": scenario_inventory,
        "replay_command": replay_command,
        "minimize_command": minimize_command,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|error| CliError::Trace(error.to_string()))?
    );
    Ok(())
}

fn read_optional_json(path: &Path) -> Result<Option<serde_json::Value>, CliError> {
    if !path.is_file() {
        return Ok(None);
    }
    serde_json::from_slice(&fs::read(path)?)
        .map(Some)
        .map_err(|error| CliError::Trace(error.to_string()))
}

fn write_campaign_success(
    store: &ArtifactStore,
    scenario: &Scenario,
    report: &crate::ScenarioReport,
    trace: &[TraceEvent],
) -> Result<(), CliError> {
    store.write_atomic("scenario.json", &scenario.to_canonical_json()?)?;
    let mut report_bytes =
        serde_json::to_vec_pretty(report).map_err(|error| CliError::Trace(error.to_string()))?;
    report_bytes.push(b'\n');
    store.write_atomic("terminal-report.json", &report_bytes)?;
    let mut scheduler_bytes = serde_json::to_vec_pretty(&report.scheduler)
        .map_err(|error| CliError::Trace(error.to_string()))?;
    scheduler_bytes.push(b'\n');
    store.write_atomic("scheduler-snapshot.json", &scheduler_bytes)?;
    let mut tasks_bytes = serde_json::to_vec_pretty(&report.tasks)
        .map_err(|error| CliError::Trace(error.to_string()))?;
    tasks_bytes.push(b'\n');
    store.write_atomic("task-ownership.json", &tasks_bytes)?;
    let mut inventory_bytes =
        serde_json::to_vec_pretty(&ScenarioInventory::from_scenario(scenario))
            .map_err(|error| CliError::Trace(error.to_string()))?;
    inventory_bytes.push(b'\n');
    store.write_atomic("scenario-inventory.json", &inventory_bytes)?;
    store.write_raw_trace("trace.raw.jsonl", trace)?;
    store.write_trace("trace.jsonl", trace)?;
    Ok(())
}

fn parse_seed_range(value: &str) -> Result<(u64, u64), CliError> {
    let (start, end) = value
        .split_once("..")
        .ok_or_else(|| CliError::InvalidSeedRange(value.to_owned()))?;
    if start.is_empty() || end.is_empty() || end.starts_with('=') {
        return Err(CliError::InvalidSeedRange(value.to_owned()));
    }
    let start = start
        .parse()
        .map_err(|_| CliError::InvalidSeedRange(value.to_owned()))?;
    let end = end
        .parse()
        .map_err(|_| CliError::InvalidSeedRange(value.to_owned()))?;
    Ok((start, end))
}

fn campaign_seed(ordinal: u64) -> (RootSeed, String) {
    let mut hasher = blake3::Hasher::new_derive_key("iroh-sim campaign root seed v1");
    hasher.update(&ordinal.to_le_bytes());
    let bytes = *hasher.finalize().as_bytes();
    (
        RootSeed::new(bytes),
        bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
    )
}

fn swarm_materialization_seed(runtime_seed: RootSeed) -> RootSeed {
    let mut hasher = blake3::Hasher::new_derive_key("iroh-sim swarm materialization seed v1");
    hasher.update(runtime_seed.as_bytes());
    RootSeed::new(*hasher.finalize().as_bytes())
}

struct MinimizationProgress {
    root: PathBuf,
    journal: fs::File,
    resume: bool,
    temp_ordinal: u64,
}

impl MinimizationProgress {
    fn open(root: &Path, resume: bool) -> Result<Self, CliError> {
        if root.exists() && !resume {
            return Err(CliError::MinimizationOutputExists(root.to_path_buf()));
        }
        fs::create_dir_all(root)?;
        let journal = OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join("minimize.jsonl"))?;
        Ok(Self {
            root: root.to_path_buf(),
            journal,
            resume,
            temp_ordinal: 0,
        })
    }

    fn resume_scenario(&self) -> Result<Option<Scenario>, CliError> {
        let path = self.root.join("best.scenario.json");
        if self.resume && path.is_file() {
            return Scenario::from_json(&fs::read(path)?)
                .map(Some)
                .map_err(Into::into);
        }
        Ok(None)
    }

    fn record(
        &mut self,
        attempt: &MinimizationAttempt,
        accepted: Option<&Scenario>,
    ) -> Result<(), CliError> {
        serde_json::to_writer(&mut self.journal, attempt)
            .map_err(|error| CliError::Trace(error.to_string()))?;
        self.journal.write_all(b"\n")?;
        self.journal.flush()?;
        self.journal.sync_data()?;
        if let Some(best) = accepted {
            self.publish_best(best)?;
        }
        Ok(())
    }

    fn publish_best(&mut self, scenario: &Scenario) -> Result<(), CliError> {
        self.atomic_replace(
            "best.scenario.json",
            &scenario
                .to_canonical_json()
                .map_err(CliError::ScenarioModel)?,
        )
    }

    fn publish_result(&mut self, result: &crate::MinimizationResult) -> Result<(), CliError> {
        let mut bytes = serde_json::to_vec_pretty(result)
            .map_err(|error| CliError::Trace(error.to_string()))?;
        bytes.push(b'\n');
        self.atomic_replace("minimize-result.json", &bytes)
    }

    fn atomic_replace(&mut self, name: &str, bytes: &[u8]) -> Result<(), CliError> {
        self.temp_ordinal = self.temp_ordinal.saturating_add(1);
        let temporary = self.root.join(format!(
            ".{name}.tmp.{}.{}",
            std::process::id(),
            self.temp_ordinal
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, self.root.join(name))?;
        Ok(())
    }
}

#[derive(Debug)]
struct CapturingTraceSink {
    durable: ArtifactTraceWriter,
    memory: TraceBuffer,
}

impl TraceSink for CapturingTraceSink {
    fn record(&self, event: TraceEvent) -> Result<(), TraceSinkError> {
        self.durable.record(event.clone())?;
        self.memory.record(event)
    }
}

fn write_json_artifact<T: serde::Serialize + ?Sized>(
    store: &ArtifactStore,
    name: &str,
    value: &T,
    manifest: &Path,
) -> Result<(), CliError> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|error| CliError::PostManifestFailure {
            error: error.to_string(),
            manifest: manifest.to_path_buf(),
        })?;
    bytes.push(b'\n');
    store
        .write_atomic(name, &bytes)
        .map_err(|error| CliError::PostManifestFailure {
            error: error.to_string(),
            manifest: manifest.to_path_buf(),
        })?;
    Ok(())
}

fn execute_replay(manifest_path: &Path) -> Result<(), CliError> {
    let manifest_path = fs::canonicalize(absolutize(manifest_path)?).map_err(CliError::Io)?;
    let manifest = RunManifest::from_json(&fs::read(&manifest_path).map_err(CliError::Io)?)?;
    let workspace = workspace_root()?;
    let artifact_root = manifest_path
        .parent()
        .ok_or(CliError::ManifestHasNoParent)?;
    if artifact_root.join("scenario.json").is_file() {
        return execute_declarative_replay(&manifest_path, &manifest, artifact_root);
    }
    let scenario = Stage2Scenario {
        schema_version: crate::STAGE2_SCENARIO_SCHEMA_VERSION,
        id: manifest.scenario_id.clone(),
    };
    scenario.validate()?;
    let identity = scenario_identity(&workspace, &scenario, Some(artifact_root))?;
    let expected_fault_profile = identity
        .normalized_config
        .get("network_faults")
        .expect("scenario identity always includes network_faults")
        .clone();
    manifest.check_compatible(&ReplayIdentity {
        schema_version: MANIFEST_SCHEMA_VERSION,
        simulator_version: SIMULATOR_VERSION.to_owned(),
        source: identity.source,
        scenario_hash: identity.scenario_hash,
        normalized_config: identity.normalized_config,
        features: identity.features,
        lockfile_digest: identity.lockfile_digest,
    })?;
    let simulation_crypto_mode = simulation_crypto_mode(manifest.crypto_mode);
    if manifest.backend != BackendCapabilities::deterministic_kernel()
        || manifest.determinism_grade != determinism_grade(simulation_crypto_mode)
        || manifest.trace_comparison != trace_comparison(simulation_crypto_mode)
        || manifest.fidelity_exceptions != fidelity_exceptions(simulation_crypto_mode)
        || manifest.scheduling_profile != "seeded-fair-kernel+root-driver"
        || manifest.fault_profile != expected_fault_profile
        || manifest.escapes != crypto_escapes(simulation_crypto_mode)
    {
        return Err(CliError::BackendIdentityMismatch);
    }
    let seed = parse_seed(&manifest.root_seed)?;
    let wall_epoch = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(manifest.wall_clock_epoch_secs))
        .ok_or(CliError::WallEpochOverflow)?;
    let harness = ScenarioHarness::new_with_crypto_mode(
        scenario,
        seed,
        wall_epoch,
        &manifest.budgets,
        simulation_crypto_mode,
    )?;
    simulation_runtime()?.block_on(harness.run())?;
    let actual = match manifest.trace_comparison {
        crate::TraceComparisonMode::Raw => raw_trace_bytes(&harness.trace())?,
        crate::TraceComparisonMode::Semantic => normalized_trace_bytes(&harness.trace())?,
    };
    let expected_path = artifact_root.join(match manifest.trace_comparison {
        crate::TraceComparisonMode::Raw => "trace.raw.jsonl",
        crate::TraceComparisonMode::Semantic => "trace.jsonl",
    });
    let expected = fs::read(&expected_path).map_err(CliError::Io)?;
    if actual != expected {
        return Err(CliError::TraceDivergence {
            line: first_different_line(&expected, &actual),
        });
    }
    println!(
        "status=replay_ok scenario={} manifest={}",
        manifest.scenario_id,
        manifest_path.display()
    );
    Ok(())
}

fn simulation_runtime() -> Result<tokio::runtime::Runtime, CliError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .map_err(CliError::Io)
}

fn default_budgets() -> RunBudgets {
    RunBudgets {
        max_events: 100_000,
        max_virtual_time_nanos: 60_000_000_000,
        max_tasks: 1_024,
        max_packets: 10_000,
    }
}

struct CurrentIdentity {
    source: SourceIdentity,
    scenario_hash: String,
    normalized_config: BTreeMap<String, String>,
    features: Vec<String>,
    lockfile_digest: String,
}

struct DeclarativeIdentity {
    source: SourceIdentity,
    scenario_hash: String,
    normalized_config: BTreeMap<String, String>,
    features: Vec<String>,
    fault_profile: String,
    lockfile_digest: String,
}

fn declarative_scenario_identity(
    workspace: &Path,
    scenario: &Scenario,
    artifact_root: Option<&Path>,
) -> Result<DeclarativeIdentity, CliError> {
    let canonical = scenario.to_canonical_json()?;
    let fault_bytes = serde_json::to_vec(&scenario.fault_rules)
        .map_err(|error| CliError::Trace(error.to_string()))?;
    let fault_profile = blake3::hash(&fault_bytes).to_hex().to_string();
    let mut features = BTreeSet::new();
    if scenario.requirements.synthetic_ip {
        features.insert("synthetic-ip".to_owned());
    }
    if scenario.requirements.virtual_time {
        features.insert("virtual-time".to_owned());
    }
    if scenario.requirements.nat {
        features.insert("nat".to_owned());
    }
    if scenario.requirements.relay {
        features.insert("relay".to_owned());
    }
    if scenario.requirements.discovery {
        features.insert("discovery".to_owned());
    }
    if scenario.requirements.mobility {
        features.insert("mobility".to_owned());
    }
    for action in &scenario.actions {
        let feature = match action.action {
            crate::ScenarioAction::StreamRoundTrip { .. } => Some("quic-stream"),
            crate::ScenarioAction::DatagramRoundTrip { .. } => Some("quic-datagram"),
            crate::ScenarioAction::Partition { .. } | crate::ScenarioAction::Heal { .. } => {
                Some("partition")
            }
            crate::ScenarioAction::SetLink { .. } => Some("link-update"),
            _ => None,
        };
        if let Some(feature) = feature {
            features.insert(feature.to_owned());
        }
    }
    Ok(DeclarativeIdentity {
        source: source_identity(workspace, artifact_root)?,
        scenario_hash: blake3::hash(&canonical).to_hex().to_string(),
        normalized_config: BTreeMap::from([
            (
                "backend".to_owned(),
                "stage3-declarative-direct-ip".to_owned(),
            ),
            ("fault_profile".to_owned(), fault_profile.clone()),
            (
                "scenario_schema".to_owned(),
                SCENARIO_SCHEMA_VERSION.to_string(),
            ),
        ]),
        features: features.into_iter().collect(),
        fault_profile,
        lockfile_digest: digest_file(&workspace.join("Cargo.lock"))?,
    })
}

const fn manifest_crypto_mode(mode: iroh::simulation::SimulationCryptoMode) -> crate::CryptoMode {
    match mode {
        iroh::simulation::SimulationCryptoMode::DeterministicTest => {
            crate::CryptoMode::DeterministicTest
        }
        iroh::simulation::SimulationCryptoMode::ProductionProvider => {
            crate::CryptoMode::ProductionProvider
        }
    }
}

const fn simulation_crypto_mode(mode: crate::CryptoMode) -> iroh::simulation::SimulationCryptoMode {
    match mode {
        crate::CryptoMode::DeterministicTest => {
            iroh::simulation::SimulationCryptoMode::DeterministicTest
        }
        crate::CryptoMode::ProductionProvider => {
            iroh::simulation::SimulationCryptoMode::ProductionProvider
        }
    }
}

const fn determinism_grade(mode: iroh::simulation::SimulationCryptoMode) -> DeterminismGrade {
    match mode {
        iroh::simulation::SimulationCryptoMode::DeterministicTest => {
            DeterminismGrade::FullyDeterministic
        }
        iroh::simulation::SimulationCryptoMode::ProductionProvider => {
            DeterminismGrade::SemanticallyDeterministic
        }
    }
}

const fn trace_comparison(
    mode: iroh::simulation::SimulationCryptoMode,
) -> crate::TraceComparisonMode {
    match mode {
        iroh::simulation::SimulationCryptoMode::DeterministicTest => {
            crate::TraceComparisonMode::Raw
        }
        iroh::simulation::SimulationCryptoMode::ProductionProvider => {
            crate::TraceComparisonMode::Semantic
        }
    }
}

fn fidelity_exceptions(mode: iroh::simulation::SimulationCryptoMode) -> Vec<String> {
    match mode {
        iroh::simulation::SimulationCryptoMode::DeterministicTest => {
            vec!["deterministic_test_crypto".to_owned()]
        }
        iroh::simulation::SimulationCryptoMode::ProductionProvider => Vec::new(),
    }
}

fn crypto_escapes(mode: iroh::simulation::SimulationCryptoMode) -> Vec<String> {
    match mode {
        iroh::simulation::SimulationCryptoMode::DeterministicTest => Vec::new(),
        iroh::simulation::SimulationCryptoMode::ProductionProvider => {
            vec!["production_crypto_entropy".to_owned()]
        }
    }
}

fn scenario_schema_version(bytes: &[u8]) -> Result<u16, CliError> {
    #[derive(serde::Deserialize)]
    struct Probe {
        schema_version: u16,
    }
    serde_json::from_slice::<Probe>(bytes)
        .map(|probe| probe.schema_version)
        .map_err(|error| CliError::ScenarioModel(ScenarioModelError::Json(error.to_string())))
}

fn read_trace_jsonl(path: &Path) -> Result<Vec<TraceEvent>, CliError> {
    let bytes = fs::read(path)?;
    if !bytes.is_empty() && bytes.last() != Some(&b'\n') {
        return Err(CliError::Trace("trace JSONL is truncated".to_owned()));
    }
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            serde_json::from_slice(line).map_err(|error| CliError::Trace(error.to_string()))
        })
        .collect()
}

fn scenario_identity(
    workspace: &Path,
    scenario: &Stage2Scenario,
    artifact_root: Option<&Path>,
) -> Result<CurrentIdentity, CliError> {
    let canonical = scenario.to_canonical_json()?;
    let (features, fault_profile) = match scenario.id.as_str() {
        "direct-ip/ipv4-stream" => (vec!["ipv4".to_owned(), "quic-stream".to_owned()], "none"),
        "direct-ip/ipv4-stream-loss" => (
            vec![
                "fault-loss".to_owned(),
                "ipv4".to_owned(),
                "quic-stream".to_owned(),
            ],
            "loss-250000ppm",
        ),
        "direct-ip/ipv4-stream-corruption" => (
            vec![
                "fault-corruption".to_owned(),
                "ipv4".to_owned(),
                "quic-stream".to_owned(),
            ],
            "corruption-250000ppm",
        ),
        "direct-ip/ipv6-stream" => (vec!["ipv6".to_owned(), "quic-stream".to_owned()], "none"),
        "direct-ip/ipv6-datagram" => (vec!["ipv6".to_owned(), "quic-datagram".to_owned()], "none"),
        _ => {
            return Err(CliError::Scenario(ScenarioError::UnsupportedScenario(
                scenario.id.clone(),
            )));
        }
    };
    Ok(CurrentIdentity {
        source: source_identity(workspace, artifact_root)?,
        scenario_hash: blake3::hash(&canonical).to_hex().to_string(),
        normalized_config: BTreeMap::from([
            ("backend".to_owned(), "stage2-synthetic-ip".to_owned()),
            ("network_faults".to_owned(), fault_profile.to_owned()),
        ]),
        features,
        lockfile_digest: digest_file(&workspace.join("Cargo.lock"))?,
    })
}

fn source_identity(
    workspace: &Path,
    artifact_root: Option<&Path>,
) -> Result<SourceIdentity, CliError> {
    let revision = git_output(workspace, &["rev-parse", "HEAD"])?;
    let dirty = git_status_output_bytes(workspace, artifact_root)?;
    Ok(SourceIdentity {
        revision: String::from_utf8(revision)
            .map_err(|error| CliError::Identity(error.to_string()))?
            .trim()
            .to_owned(),
        dirty_digest: (!dirty.is_empty()).then(|| blake3::hash(&dirty).to_hex().to_string()),
    })
}

fn git_output(workspace: &Path, args: &[&str]) -> Result<Vec<u8>, CliError> {
    git_output_bytes(workspace, args)
}

fn git_output_bytes(workspace: &Path, args: &[&str]) -> Result<Vec<u8>, CliError> {
    let output = ProcessCommand::new("git")
        .args(args)
        .current_dir(workspace)
        .output()
        .map_err(CliError::Io)?;
    if !output.status.success() {
        return Err(CliError::Identity(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }
    Ok(output.stdout)
}

fn git_status_output_bytes(
    workspace: &Path,
    artifact_root: Option<&Path>,
) -> Result<Vec<u8>, CliError> {
    let mut command = ProcessCommand::new("git");
    command
        .args(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
        .current_dir(workspace);
    if let Some(relative) = artifact_root.and_then(|root| root.strip_prefix(workspace).ok())
        && !relative.as_os_str().is_empty()
    {
        let relative = relative
            .to_str()
            .ok_or_else(|| CliError::Identity("artifact path is not UTF-8".to_owned()))?
            .replace('\\', "/");
        command.args(["--", "."]);
        command.arg(format!(":(exclude){relative}/**"));
    }
    let output = command.output().map_err(CliError::Io)?;
    if !output.status.success() {
        return Err(CliError::Identity(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }
    Ok(output.stdout)
}

fn workspace_root() -> Result<PathBuf, CliError> {
    let mut current = std::env::current_dir().map_err(CliError::Io)?;
    loop {
        if current.join("Cargo.lock").is_file() && current.join(".git").exists() {
            return Ok(current);
        }
        if !current.pop() {
            return Err(CliError::WorkspaceNotFound);
        }
    }
}

fn digest_file(path: &Path) -> Result<String, CliError> {
    Ok(blake3::hash(&fs::read(path).map_err(CliError::Io)?)
        .to_hex()
        .to_string())
}

fn parse_seed(value: &str) -> Result<RootSeed, CliError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CliError::InvalidSeed);
    }
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(CliError::InvalidSeed);
    }
    let mut bytes = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| CliError::InvalidSeed)?;
        bytes[index] = u8::from_str_radix(text, 16).map_err(|_| CliError::InvalidSeed)?;
    }
    Ok(RootSeed::new(bytes))
}

fn default_artifact_root(workspace: &Path, scenario: &Stage2Scenario, seed: &str) -> PathBuf {
    workspace
        .join("artifacts")
        .join(format!("{}-{}", scenario.id.replace('/', "-"), &seed[..16]))
}

fn default_declarative_artifact_root(workspace: &Path, scenario: &Scenario, seed: &str) -> PathBuf {
    workspace.join("artifacts").join(format!(
        "{}-{}",
        scenario.metadata.id.replace('/', "-"),
        &seed[..16]
    ))
}

fn absolutize(path: &Path) -> Result<PathBuf, CliError> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir().map_err(CliError::Io)?.join(path))
    }
}

fn normalized_trace_bytes(events: &[iroh_runtime::TraceEvent]) -> Result<Vec<u8>, CliError> {
    let mut bytes = Vec::new();
    for event in events {
        bytes.extend(
            normalized_trace_json(event).map_err(|error| CliError::Trace(error.to_string()))?,
        );
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn raw_trace_bytes(events: &[iroh_runtime::TraceEvent]) -> Result<Vec<u8>, CliError> {
    let mut bytes = Vec::new();
    for event in events {
        bytes
            .extend(serde_json::to_vec(event).map_err(|error| CliError::Trace(error.to_string()))?);
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn first_raw_trace_divergence(
    expected: &[iroh_runtime::TraceEvent],
    actual: &[iroh_runtime::TraceEvent],
) -> usize {
    expected
        .iter()
        .zip(actual)
        .position(|(expected, actual)| expected != actual)
        .unwrap_or_else(|| expected.len().min(actual.len()))
}

fn first_different_line(expected: &[u8], actual: &[u8]) -> usize {
    let common_prefix = expected
        .iter()
        .zip(actual)
        .take_while(|(expected, actual)| expected == actual)
        .count();
    expected[..common_prefix]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
        + 1
}

/// Stable command failure classes.
#[derive(Debug)]
pub enum CliError {
    Usage(String),
    InvalidSeed,
    InvalidSeedRange(String),
    InvalidParityCase(String),
    Io(std::io::Error),
    Identity(String),
    WorkspaceNotFound,
    WallEpochOverflow,
    ManifestHasNoParent,
    Scenario(ScenarioError),
    ScenarioModel(ScenarioModelError),
    Runner(String),
    Manifest(ManifestError),
    Compatibility(CompatibilityError),
    Artifact(ArtifactError),
    Trace(String),
    TraceDivergence {
        line: usize,
    },
    BackendIdentityMismatch,
    Failure(FailureError),
    FailureReplay(FailureReplayError),
    Minimization(MinimizationError),
    MinimizationOutputExists(PathBuf),
    Corpus(CorpusError),
    Campaign(CampaignError),
    Swarm(SwarmError),
    CampaignRunFailures(usize),
    Parity(ParityError),
    ParityDifference(Vec<String>),
    UnexpectedDeclarativeFailure(String),
    DeclarativeRunFailed {
        error: String,
        manifest: PathBuf,
        signature: String,
    },
    RunFailed {
        error: ScenarioError,
        manifest: PathBuf,
    },
    PostManifestFailure {
        error: String,
        manifest: PathBuf,
    },
    BackendUnavailable {
        operation: &'static str,
        artifact: PathBuf,
    },
}

impl CliError {
    /// Process exit code for automation.
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_)
            | Self::InvalidSeed
            | Self::InvalidSeedRange(_)
            | Self::InvalidParityCase(_) => 64,
            Self::Scenario(_)
            | Self::ScenarioModel(_)
            | Self::Runner(_)
            | Self::RunFailed { .. }
            | Self::DeclarativeRunFailed { .. }
            | Self::UnexpectedDeclarativeFailure(_) => 70,
            Self::Compatibility(_) | Self::BackendIdentityMismatch => 65,
            Self::TraceDivergence { .. } | Self::FailureReplay(_) | Self::ParityDifference(_) => 66,
            Self::Io(_)
            | Self::Identity(_)
            | Self::WorkspaceNotFound
            | Self::Artifact(_)
            | Self::PostManifestFailure { .. }
            | Self::Failure(_)
            | Self::Minimization(_)
            | Self::Corpus(_)
            | Self::Campaign(_)
            | Self::Swarm(_)
            | Self::CampaignRunFailures(_)
            | Self::Parity(_) => 74,
            Self::MinimizationOutputExists(_) => 73,
            Self::Manifest(_)
            | Self::Trace(_)
            | Self::WallEpochOverflow
            | Self::ManifestHasNoParent => 65,
            Self::BackendUnavailable { .. } => BACKEND_UNAVAILABLE_EXIT,
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(message) => f.write_str(message),
            Self::InvalidSeed => f.write_str("seed must be 64 lowercase hexadecimal characters"),
            Self::InvalidSeedRange(value) => {
                write!(
                    f,
                    "seed range must be a nonempty half-open range: {value:?}"
                )
            }
            Self::InvalidParityCase(value) => write!(
                f,
                "unknown parity case {value:?}; expected public, full-cone, port-restricted, symmetric, double-nat, degradation, outage-recovery, or switch-uplink"
            ),
            Self::Io(error) => write!(f, "artifact or input I/O failed: {error}"),
            Self::Identity(error) => write!(f, "source identity failed: {error}"),
            Self::WorkspaceNotFound => {
                f.write_str("workspace root with .git and Cargo.lock not found")
            }
            Self::WallEpochOverflow => f.write_str("manifest wall-clock epoch overflow"),
            Self::ManifestHasNoParent => f.write_str("manifest has no artifact directory"),
            Self::Scenario(error) => error.fmt(f),
            Self::ScenarioModel(error) => error.fmt(f),
            Self::Runner(error) => write!(f, "scenario runner failed: {error}"),
            Self::Manifest(error) => error.fmt(f),
            Self::Compatibility(error) => error.fmt(f),
            Self::Artifact(error) => error.fmt(f),
            Self::Trace(error) => write!(f, "trace encoding failed: {error}"),
            Self::TraceDivergence { line } => write!(f, "status=trace_divergence line={line}"),
            Self::BackendIdentityMismatch => f.write_str("manifest backend identity mismatch"),
            Self::Failure(error) => error.fmt(f),
            Self::FailureReplay(error) => error.fmt(f),
            Self::Minimization(error) => error.fmt(f),
            Self::MinimizationOutputExists(path) => write!(
                f,
                "minimization output already exists (use --resume): {}",
                path.display()
            ),
            Self::Corpus(error) => error.fmt(f),
            Self::Campaign(error) => error.fmt(f),
            Self::Swarm(error) => error.fmt(f),
            Self::CampaignRunFailures(count) => {
                write!(f, "campaign contained {count} failed runs")
            }
            Self::Parity(error) => error.fmt(f),
            Self::ParityDifference(differences) => write!(
                f,
                "status=parity_difference dimensions={}",
                differences.join(",")
            ),
            Self::UnexpectedDeclarativeFailure(error) => {
                write!(f, "status=failure_appeared error={error}")
            }
            Self::DeclarativeRunFailed {
                error,
                manifest,
                signature,
            } => write!(
                f,
                "status=run_failed error={error} signature={signature}\ncargo sim replay {}",
                manifest.display()
            ),
            Self::RunFailed { error, manifest } => write!(
                f,
                "status=run_failed error={error}\ncargo sim replay {}",
                manifest.display()
            ),
            Self::PostManifestFailure { error, manifest } => write!(
                f,
                "status=artifact_failed error={error}\ncargo sim replay {}",
                manifest.display()
            ),
            Self::BackendUnavailable {
                operation,
                artifact,
            } => write!(
                f,
                "status=backend_unavailable operation={operation} stage=\"later than Stage 2\" input={:?}",
                artifact.file_name().unwrap_or_default()
            ),
        }
    }
}

impl std::error::Error for CliError {}

impl From<ScenarioError> for CliError {
    fn from(value: ScenarioError) -> Self {
        Self::Scenario(value)
    }
}
impl From<ScenarioModelError> for CliError {
    fn from(value: ScenarioModelError) -> Self {
        Self::ScenarioModel(value)
    }
}
impl From<crate::RunnerError> for CliError {
    fn from(value: crate::RunnerError) -> Self {
        Self::Runner(value.to_string())
    }
}
impl From<ManifestError> for CliError {
    fn from(value: ManifestError) -> Self {
        Self::Manifest(value)
    }
}
impl From<CompatibilityError> for CliError {
    fn from(value: CompatibilityError) -> Self {
        Self::Compatibility(value)
    }
}
impl From<ArtifactError> for CliError {
    fn from(value: ArtifactError) -> Self {
        Self::Artifact(value)
    }
}
impl From<FailureError> for CliError {
    fn from(value: FailureError) -> Self {
        Self::Failure(value)
    }
}
impl From<FailureReplayError> for CliError {
    fn from(value: FailureReplayError) -> Self {
        Self::FailureReplay(value)
    }
}
impl From<MinimizationError> for CliError {
    fn from(value: MinimizationError) -> Self {
        Self::Minimization(value)
    }
}
impl From<CorpusError> for CliError {
    fn from(value: CorpusError) -> Self {
        Self::Corpus(value)
    }
}
impl From<CampaignError> for CliError {
    fn from(value: CampaignError) -> Self {
        Self::Campaign(value)
    }
}
impl From<SwarmError> for CliError {
    fn from(value: SwarmError) -> Self {
        Self::Swarm(value)
    }
}
impl From<ParityError> for CliError {
    fn from(value: ParityError) -> Self {
        Self::Parity(value)
    }
}
impl From<std::io::Error> for CliError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
