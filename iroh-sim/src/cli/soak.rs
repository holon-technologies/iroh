use super::*;

pub(super) const DAILY_SOAK_LANE_IDS: [&str; 14] = [
    "direct/deterministic-test",
    "direct/production-provider",
    "discovery/deterministic-test",
    "discovery/production-provider",
    "impairment/deterministic-test",
    "impairment/production-provider",
    "mobility/deterministic-test",
    "mobility/production-provider",
    "nat/deterministic-test",
    "nat/production-provider",
    "ready-order/deterministic-test",
    "ready-order/production-provider",
    "relay/deterministic-test",
    "relay/production-provider",
];
pub(super) const MAX_DAILY_SOAK_WALL_SECONDS: u64 = 30 * 60;
pub(super) const MAX_DAILY_SOAK_JOBS: usize = 4;
pub(super) const MAX_DAILY_SOAK_BATCH_RUNS: u64 = 64;
pub(super) const MAX_DAILY_SOAK_RUNS_PER_EPOCH: u64 = 125_000;

pub(super) struct SoakOptions<'a> {
    pub(super) plan_path: &'a Path,
    pub(super) lane: Option<&'a str>,
    pub(super) epoch: u8,
    pub(super) seed_window: u64,
    pub(super) wall_seconds: u64,
    pub(super) jobs: usize,
    pub(super) batch_runs: u64,
    pub(super) max_runs: u64,
    pub(super) max_failure_artifacts: usize,
    pub(super) max_artifact_bytes: u64,
    pub(super) artifact_root: &'a Path,
}

pub(super) struct LoadedSoakLane {
    domain: String,
    swarm: SwarmSpec,
    crypto: CryptoLane,
}

pub(super) fn execute_soak(options: SoakOptions<'_>) -> Result<(), CliError> {
    validate_soak_options(&options)?;
    let workspace = workspace_root()?;
    let plan_bytes = read_file(options.plan_path)?;
    let plan = SoakPlan::from_json(&plan_bytes)?;
    validate_daily_soak_plan(&plan)?;
    let plan_blake3 = blake3::hash(&plan_bytes).to_hex().to_string();
    let canonical_workspace = workspace.canonicalize().map_err(CliError::Io)?;
    let coverage_policy_path = workspace.join(&plan.coverage_policy);
    let canonical_coverage_policy = coverage_policy_path.canonicalize().map_err(CliError::Io)?;
    if !canonical_coverage_policy.starts_with(&canonical_workspace) {
        return Err(CliError::Usage(format!(
            "soak coverage policy resolves outside the workspace: {}",
            plan.coverage_policy.display()
        )));
    }
    let coverage_policy_bytes = read_file(&canonical_coverage_policy)?;
    let actual_coverage_policy_blake3 = blake3::hash(&coverage_policy_bytes).to_hex().to_string();
    if actual_coverage_policy_blake3 != plan.coverage_policy_blake3 {
        return Err(CliError::SoakCoveragePolicyDigest {
            expected: plan.coverage_policy_blake3.clone(),
            actual: actual_coverage_policy_blake3,
        });
    }
    let coverage_policy = CoveragePolicy::from_json(&coverage_policy_bytes)?;
    let selected_lane_index = match options.lane {
        Some(requested_lane) => Some(
            plan.lanes
                .iter()
                .position(|lane| lane.id == requested_lane)
                .ok_or_else(|| {
                    CliError::Usage(format!(
                        "soak --lane must name one lane from the canonical daily plan: {requested_lane}"
                    ))
                })?,
        ),
        None => None,
    };

    let mut loaded = BTreeMap::new();
    let mut coverage_swarms = BTreeMap::new();
    for plan_lane in &plan.lanes {
        let swarm_path = workspace.join(&plan_lane.swarm);
        let canonical_swarm = swarm_path.canonicalize().map_err(CliError::Io)?;
        if !canonical_swarm.starts_with(&canonical_workspace) {
            return Err(CliError::Usage(format!(
                "soak swarm resolves outside the workspace: {}",
                plan_lane.swarm.display()
            )));
        }
        let swarm_bytes = read_file(&canonical_swarm)?;
        let actual_digest = blake3::hash(&swarm_bytes).to_hex().to_string();
        if actual_digest != plan_lane.swarm_blake3 {
            return Err(CliError::SoakSwarmDigest {
                lane: plan_lane.id.clone(),
                expected: plan_lane.swarm_blake3.clone(),
                actual: actual_digest,
            });
        }
        let (swarm, _) = load_swarm_template(&canonical_swarm, &workspace)?;
        let domain = plan_lane
            .id
            .split_once('/')
            .map(|(domain, _)| domain)
            .ok_or_else(|| {
                CliError::Usage(format!(
                    "daily soak lane must have domain/provider identity: {}",
                    plan_lane.id
                ))
            })?;
        match coverage_swarms.entry(swarm.id.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(swarm.clone());
            }
            std::collections::btree_map::Entry::Occupied(entry) if entry.get() == &swarm => {}
            std::collections::btree_map::Entry::Occupied(_) => {
                return Err(CliError::Usage(format!(
                    "daily soak swarm identity resolves to conflicting definitions: {}",
                    swarm.id
                )));
            }
        }
        loaded.insert(
            plan_lane.id.clone(),
            LoadedSoakLane {
                domain: domain.to_owned(),
                swarm,
                crypto: match plan_lane.crypto {
                    SoakCryptoLane::DeterministicTest => CryptoLane::DeterministicTest,
                    SoakCryptoLane::ProductionProvider => CryptoLane::ProductionProvider,
                },
            },
        );
    }
    let coverage_obligations = coverage_policy.obligations(&coverage_swarms)?;
    for lane in loaded.values() {
        coverage_obligations.validate_binding(
            &lane.domain,
            &lane.swarm.id,
            manifest_crypto_mode(lane.crypto.simulation_mode()),
        )?;
    }

    let lane_capacity = if selected_lane_index.is_some() {
        1
    } else {
        plan.lanes.len()
    };
    let mut lanes = Vec::with_capacity(lane_capacity);
    let mut seed_leases = Vec::with_capacity(lane_capacity);
    for (lane_index, plan_lane) in plan.lanes.iter().enumerate() {
        if selected_lane_index.is_some_and(|selected| selected != lane_index) {
            continue;
        }
        let loaded_lane = loaded
            .get(&plan_lane.id)
            .expect("validated canonical soak lanes must have loaded state");
        let seed_start = derive_soak_seed_start(options.seed_window, options.epoch, lane_index)?;
        let seed_lease = SeedLease::reserve(
            &plan.coverage_policy_blake3,
            &plan_blake3,
            &plan_lane.id,
            options.seed_window,
            options.epoch,
            lane_index,
        )?;
        assert_eq!(
            seed_start, seed_lease.seed_start,
            "seed lease and soak scheduler must share one derivation"
        );
        lanes.push(SoakLane {
            id: plan_lane.id.clone(),
            scenario: loaded_lane.swarm.base.clone(),
            seed_start,
        });
        seed_leases.push(seed_lease);
    }

    let requested_root = absolutize(options.artifact_root)?;
    if requested_root.exists() {
        return Err(CliError::SoakOutputExists(requested_root));
    }
    let parent = requested_root
        .parent()
        .ok_or_else(|| CliError::Usage("soak artifact root has no parent".to_owned()))?;
    fs::create_dir_all(parent)?;
    fs::create_dir(&requested_root)?;
    let artifact_store = ArtifactStore::new(&requested_root)?;
    let artifact_root = artifact_store.root().to_path_buf();
    artifact_store.write_atomic("plan.json", &plan_bytes)?;
    artifact_store.write_atomic(
        "plan.blake3",
        format!("{}\n", blake3::hash(&plan_bytes).to_hex()).as_bytes(),
    )?;
    artifact_store.write_atomic("coverage-policy.json", &coverage_policy_bytes)?;
    artifact_store.write_atomic(
        "coverage-policy.blake3",
        format!("{}\n", plan.coverage_policy_blake3).as_bytes(),
    )?;

    let retention = FailureRetention::new(
        artifact_root.clone(),
        options.max_failure_artifacts,
        options.max_artifact_bytes,
    );
    let started = Instant::now();
    let mut publisher = SoakReportPublisher::new(
        artifact_root.clone(),
        plan.id.clone(),
        options.epoch,
        options.seed_window,
    );
    let coverage_ledger = Arc::new(Mutex::new(CoverageLedger::new(coverage_obligations)));
    let execute = |lane_id: &str, seed_ordinal: u64, _template: &Scenario| {
        let lane = loaded
            .get(lane_id)
            .expect("validated soak lanes have matching loaded state");
        let (seed, seed_hex) = campaign_seed(seed_ordinal);
        let (candidate, selection) = lane
            .swarm
            .materialize(swarm_materialization_seed(seed))
            .map_err(|error| error.to_string())?;
        let trace = TraceBuffer::default();
        let runner = ScenarioRunner::with_crypto_mode(
            candidate.clone(),
            seed,
            SystemTime::UNIX_EPOCH + Duration::from_secs(DEFAULT_WALL_EPOCH_SECS),
            Arc::new(trace.clone()),
            lane.crypto.simulation_mode(),
        )
        .map_err(|error| error.to_string())?;
        let result = simulation_runtime()
            .map_err(|error| error.to_string())?
            .block_on(runner.run_detailed());
        let coverage = CoverageObservation::from_run(
            &lane.domain,
            manifest_crypto_mode(lane.crypto.simulation_mode()),
            &selection,
            &candidate,
            match &result {
                Ok(report) => &report.observations,
                Err(failure) => &failure.observations,
            },
        )
        .map_err(|error| error.to_string())?;
        let terminal = match result {
            Ok(_) => CampaignTerminal::Success,
            Err(failure) => {
                let events = trace.events();
                let signature = FailureSignature::from_runner_error(&failure.error, &events, 64)
                    .map_err(|error| error.to_string())?;
                retention.retain(FailureRetentionInput {
                    lane_id,
                    seed_ordinal,
                    seed_hex: &seed_hex,
                    crypto: lane.crypto,
                    selection: Some(&selection),
                    scenario: &candidate,
                    failure: &failure,
                    signature: &signature,
                    trace: &events,
                });
                CampaignTerminal::Failure(signature)
            }
        };
        coverage_ledger
            .lock()
            .map_err(|_| "coverage ledger lock poisoned".to_owned())?
            .observe(&coverage)
            .map_err(|error| error.to_string())?;
        Ok(terminal)
    };
    let elapsed_millis = || u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let wall_budget_millis = options
        .wall_seconds
        .checked_mul(1_000)
        .ok_or_else(|| CliError::Usage("soak wall budget overflows milliseconds".to_owned()))?;
    let summary = SoakRunner::run(
        SoakConfig {
            wall_budget_millis,
            jobs: options.jobs,
            batch_runs: options.batch_runs,
            max_runs: options.max_runs,
        },
        lanes,
        elapsed_millis,
        |summary| {
            let coverage = coverage_ledger
                .lock()
                .map_err(|_| "coverage ledger lock poisoned".to_owned())?
                .report();
            publisher
                .publish(summary, retention.snapshot(), &coverage, &seed_leases)
                .map_err(|error| error.to_string())
        },
        execute,
    )?;
    let retention_summary = retention.snapshot();
    let coverage = coverage_ledger
        .lock()
        .map_err(|_| CliError::CoverageTrackerPoisoned)?
        .report();
    publisher.publish(&summary, retention_summary.clone(), &coverage, &seed_leases)?;

    let infrastructure_error = retention_summary.infrastructure_error.clone();
    if summary.failed_runs != 0 || summary.errored_runs != 0 || infrastructure_error.is_some() {
        return Err(CliError::SoakRunFailures {
            failed: summary.failed_runs,
            errored: summary.errored_runs,
            infrastructure_error,
        });
    }
    println!(
        "status=soak_ok runs={} elapsed_millis={} artifacts={}",
        summary.completed_runs,
        summary.elapsed_millis,
        artifact_root.display()
    );
    Ok(())
}

pub(super) fn validate_soak_options(options: &SoakOptions<'_>) -> Result<(), CliError> {
    if options.wall_seconds == 0 || options.wall_seconds > MAX_DAILY_SOAK_WALL_SECONDS {
        return Err(CliError::Usage(format!(
            "soak --wall-seconds must be in 1..={MAX_DAILY_SOAK_WALL_SECONDS}"
        )));
    }
    if options.jobs == 0 || options.jobs > MAX_DAILY_SOAK_JOBS {
        return Err(CliError::Usage(format!(
            "soak --jobs must be in 1..={MAX_DAILY_SOAK_JOBS}"
        )));
    }
    if options.batch_runs == 0 || options.batch_runs > MAX_DAILY_SOAK_BATCH_RUNS {
        return Err(CliError::Usage(format!(
            "soak --batch-runs must be in 1..={MAX_DAILY_SOAK_BATCH_RUNS}"
        )));
    }
    if options.max_runs == 0 || options.max_runs > MAX_DAILY_SOAK_RUNS_PER_EPOCH {
        return Err(CliError::Usage(format!(
            "soak --max-runs must be in 1..={MAX_DAILY_SOAK_RUNS_PER_EPOCH}"
        )));
    }
    if options.max_failure_artifacts == 0
        || options.max_failure_artifacts > MAX_SOAK_FAILURE_ARTIFACTS
    {
        return Err(CliError::Usage(format!(
            "soak --max-failure-artifacts must be in 1..={MAX_SOAK_FAILURE_ARTIFACTS}"
        )));
    }
    if options.max_artifact_bytes == 0 || options.max_artifact_bytes > MAX_SOAK_ARTIFACT_BYTES {
        return Err(CliError::Usage(format!(
            "soak --max-artifact-bytes must be in 1..={MAX_SOAK_ARTIFACT_BYTES}"
        )));
    }
    Ok(())
}

pub(super) fn validate_daily_soak_plan(plan: &SoakPlan) -> Result<(), CliError> {
    let is_canonical = plan.id == "daily"
        && plan.lanes.len() == DAILY_SOAK_LANE_IDS.len()
        && plan
            .lanes
            .iter()
            .zip(DAILY_SOAK_LANE_IDS)
            .all(|(lane, expected_id)| {
                let expected_crypto = if expected_id.ends_with("/deterministic-test") {
                    SoakCryptoLane::DeterministicTest
                } else {
                    SoakCryptoLane::ProductionProvider
                };
                lane.id == expected_id && lane.crypto == expected_crypto
            });
    if !is_canonical {
        return Err(CliError::Usage(
            "daily soak plan must contain the canonical fourteen lane definitions".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FailureRetentionSummary {
    retained: u64,
    omitted: u64,
    retained_bytes: u64,
    byte_budget: u64,
    artifact_budget: usize,
    infrastructure_error: Option<String>,
}

#[derive(Debug)]
pub(super) struct FailureRetentionState {
    observed: u64,
    retained: u64,
    omitted: u64,
    retained_bytes: u64,
    infrastructure_error: Option<String>,
}

#[derive(Debug)]
pub(super) struct FailureRetention {
    root: PathBuf,
    max_artifacts: usize,
    max_bytes: u64,
    state: Mutex<FailureRetentionState>,
}

pub(super) struct FailureRetentionInput<'a> {
    lane_id: &'a str,
    seed_ordinal: u64,
    seed_hex: &'a str,
    crypto: CryptoLane,
    selection: Option<&'a crate::SwarmSelection>,
    scenario: &'a Scenario,
    failure: &'a crate::ScenarioFailureReport,
    signature: &'a FailureSignature,
    trace: &'a [TraceEvent],
}

impl FailureRetention {
    fn new(root: PathBuf, max_artifacts: usize, max_bytes: u64) -> Self {
        Self {
            root,
            max_artifacts,
            max_bytes,
            state: Mutex::new(FailureRetentionState {
                observed: 0,
                retained: 0,
                omitted: 0,
                retained_bytes: 0,
                infrastructure_error: None,
            }),
        }
    }

    fn retain(&self, input: FailureRetentionInput<'_>) {
        let mut state = self.state.lock().expect("failure retention lock poisoned");
        let result = self.retain_locked(&mut state, input);
        if let Err(error) = result {
            state.infrastructure_error.get_or_insert(error);
            match state.omitted.checked_add(1) {
                Some(omitted) => state.omitted = omitted,
                None => {
                    state.infrastructure_error =
                        Some("omitted failure counter overflow".to_owned());
                }
            }
        }
    }

    fn retain_locked(
        &self,
        state: &mut FailureRetentionState,
        input: FailureRetentionInput<'_>,
    ) -> Result<(), String> {
        state.observed = state
            .observed
            .checked_add(1)
            .ok_or_else(|| "failure observation counter overflow".to_owned())?;
        if state.infrastructure_error.is_some()
            || usize::try_from(state.retained).unwrap_or(usize::MAX) >= self.max_artifacts
        {
            state.omitted = state
                .omitted
                .checked_add(1)
                .ok_or_else(|| "omitted failure counter overflow".to_owned())?;
            return Ok(());
        }

        let candidate = self.root.join(format!(
            "failure-{:06}-seed-{:020}",
            state.observed, input.seed_ordinal
        ));
        let write_result = (|| -> Result<u64, String> {
            let store = ArtifactStore::new(&candidate).map_err(|error| error.to_string())?;
            store
                .write_atomic("lane-id.txt", format!("{}\n", input.lane_id).as_bytes())
                .map_err(|error| error.to_string())?;
            store
                .write_atomic(
                    "seed-ordinal.txt",
                    format!("{}\n", input.seed_ordinal).as_bytes(),
                )
                .map_err(|error| error.to_string())?;
            store
                .write_atomic("seed.txt", format!("{}\n", input.seed_hex).as_bytes())
                .map_err(|error| error.to_string())?;
            store
                .write_atomic(
                    "crypto-mode.txt",
                    format!("{}\n", input.crypto.as_str()).as_bytes(),
                )
                .map_err(|error| error.to_string())?;
            if let Some(selection) = input.selection {
                let mut bytes =
                    serde_json::to_vec_pretty(selection).map_err(|error| error.to_string())?;
                bytes.push(b'\n');
                store
                    .write_atomic("swarm-selection.json", &bytes)
                    .map_err(|error| error.to_string())?;
            }
            let signature_digest = blake3::hash(
                &input
                    .signature
                    .to_canonical_json()
                    .map_err(|error| error.to_string())?,
            )
            .to_hex()
            .to_string();
            let operational_outcome = OperationalOutcome::new(
                OperationalOutcomeClass::ProductCorrectness,
                signature_digest,
            )
            .map_err(|error| error.to_string())?;
            FailureArtifactBundle {
                scenario: input.scenario,
                error: &input.failure.error,
                signature: input.signature,
                operational_outcome: Some(&operational_outcome),
                invariants: &input.failure.invariants,
                resources: &input.failure.resources,
                model: Some(&input.failure.model),
                observations: Some(&input.failure.observations),
                virtual_time_nanos: Some(input.failure.virtual_time_nanos),
                scheduler: input.failure.scheduler.as_ref(),
                tasks: Some(&input.failure.tasks),
                trace: input.trace,
                events_per_chunk: 64,
            }
            .write(&store)
            .map_err(|error| error.to_string())?;
            let replay_crypto = input.crypto.as_str().replace('_', "-");
            store
                .write_atomic(
                    "replay.sh",
                    format!(
                        "#!/usr/bin/env bash\n\
                         set -euo pipefail\n\
                         failure_dir=$(cd \"$(dirname \"${{BASH_SOURCE[0]}}\")\" && pwd)\n\
                         cargo sim run \"$failure_dir/scenario.json\" \
                         --seed {} --crypto {} --artifacts \"$failure_dir/replay\"\n",
                        input.seed_hex, replay_crypto
                    )
                    .as_bytes(),
                )
                .map_err(|error| error.to_string())?;
            store
                .write_atomic(
                    "replay-command.txt",
                    b"From the exact source checkout: bash <failure-directory>/replay.sh\n",
                )
                .map_err(|error| error.to_string())?;
            directory_bytes(&candidate, self.max_bytes)
        })();
        let candidate_bytes = match write_result {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = fs::remove_dir_all(&candidate);
                return Err(format!("failure artifact write failed: {error}"));
            }
        };
        let next_bytes = state
            .retained_bytes
            .checked_add(candidate_bytes)
            .ok_or_else(|| "failure artifact byte counter overflow".to_owned())?;
        if next_bytes > self.max_bytes {
            fs::remove_dir_all(&candidate).map_err(|error| {
                format!(
                    "failed to remove over-budget failure artifact {}: {error}",
                    candidate.display()
                )
            })?;
            state.omitted = state
                .omitted
                .checked_add(1)
                .ok_or_else(|| "omitted failure counter overflow".to_owned())?;
            return Ok(());
        }
        state.retained = state
            .retained
            .checked_add(1)
            .ok_or_else(|| "retained failure counter overflow".to_owned())?;
        state.retained_bytes = next_bytes;
        Ok(())
    }

    fn snapshot(&self) -> FailureRetentionSummary {
        let state = self.state.lock().expect("failure retention lock poisoned");
        FailureRetentionSummary {
            retained: state.retained,
            omitted: state.omitted,
            retained_bytes: state.retained_bytes,
            byte_budget: self.max_bytes,
            artifact_budget: self.max_artifacts,
            infrastructure_error: state.infrastructure_error.clone(),
        }
    }
}

pub(super) fn directory_bytes(root: &Path, maximum: u64) -> Result<u64, String> {
    let mut total = 0_u64;
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let file_type = entry.file_type().map_err(|error| error.to_string())?;
            if file_type.is_symlink() {
                return Err(format!(
                    "failure artifact contains a symlink: {}",
                    entry.path().display()
                ));
            }
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                total = total
                    .checked_add(entry.metadata().map_err(|error| error.to_string())?.len())
                    .ok_or_else(|| "failure artifact byte counter overflow".to_owned())?;
                if total > maximum {
                    return Ok(total);
                }
            } else {
                return Err(format!(
                    "failure artifact contains an unsupported entry: {}",
                    entry.path().display()
                ));
            }
        }
    }
    Ok(total)
}

#[derive(serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SoakEpochReport<'a> {
    plan_id: &'a str,
    epoch: u8,
    seed_window: u64,
    failure_artifacts: FailureRetentionSummary,
    coverage: &'a CoverageReport,
    seed_leases: Vec<SeedLease>,
    #[serde(flatten)]
    summary: &'a SoakSummary,
}

pub(super) struct SoakReportPublisher {
    root: PathBuf,
    plan_id: String,
    epoch: u8,
    seed_window: u64,
    temporary_ordinal: u64,
}

impl SoakReportPublisher {
    fn new(root: PathBuf, plan_id: String, epoch: u8, seed_window: u64) -> Self {
        Self {
            root,
            plan_id,
            epoch,
            seed_window,
            temporary_ordinal: 0,
        }
    }

    fn publish(
        &mut self,
        summary: &SoakSummary,
        failure_artifacts: FailureRetentionSummary,
        coverage: &CoverageReport,
        seed_leases: &[SeedLease],
    ) -> Result<(), CliError> {
        let mut consumed_leases = Vec::with_capacity(seed_leases.len());
        for lease in seed_leases {
            let lane = summary
                .lanes
                .iter()
                .find(|lane| lane.id == lease.lane_id)
                .ok_or_else(|| {
                    CliError::Trace(format!(
                        "seed lease has no matching soak lane: {}",
                        lease.lane_id
                    ))
                })?;
            consumed_leases.push(lease.clone().with_consumed_runs(lane.completed_runs)?);
        }
        let report = SoakEpochReport {
            plan_id: &self.plan_id,
            epoch: self.epoch,
            seed_window: self.seed_window,
            failure_artifacts,
            coverage,
            seed_leases: consumed_leases,
            summary,
        };
        let mut bytes = serde_json::to_vec_pretty(&report)
            .map_err(|error| CliError::Trace(error.to_string()))?;
        bytes.push(b'\n');
        self.temporary_ordinal = self
            .temporary_ordinal
            .checked_add(1)
            .ok_or_else(|| CliError::Trace("soak checkpoint ordinal overflow".to_owned()))?;
        let temporary = self.root.join(format!(
            ".soak-summary.json.tmp.{}.{}",
            std::process::id(),
            self.temporary_ordinal
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        let write_result = (|| -> Result<(), std::io::Error> {
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, self.root.join("soak-summary.json"))?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        write_result.map_err(CliError::Io)
    }
}
