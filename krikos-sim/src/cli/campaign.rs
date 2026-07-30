use super::*;

pub(super) struct CampaignOptions<'a> {
    pub(super) scenario_path: Option<&'a Path>,
    pub(super) swarm_path: Option<&'a Path>,
    pub(super) seeds: &'a str,
    pub(super) jobs: usize,
    pub(super) artifact_override: Option<&'a Path>,
    pub(super) continue_on_failure: bool,
    pub(super) generated: bool,
    pub(super) max_runs: u64,
    pub(super) crypto: CryptoLane,
}

pub(super) fn execute_campaign(options: CampaignOptions<'_>) -> Result<(), CliError> {
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
        (None, Some(path)) => Scenario::from_versioned_json(&read_file(path)?)?,
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
                    operational_outcome: None,
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

pub(super) fn load_swarm_template(
    path: &Path,
    workspace: &Path,
) -> Result<(SwarmSpec, Vec<u8>), CliError> {
    let template_bytes = read_file(path)?;
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
            read_file(canonical_base)?
        }
    };
    Ok((template.resolve(&base_bytes)?, template_bytes))
}

pub(super) fn execute_explain(artifact: &Path) -> Result<(), CliError> {
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
        Some(RunManifest::from_json(&read_file(&manifest_path)?)?)
    } else {
        None
    };
    let signature_path = root.join("failure-signature.json");
    let signature = if signature_path.is_file() {
        Some(FailureSignature::from_json(&read_file(&signature_path)?)?)
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

pub(super) fn read_optional_json(path: &Path) -> Result<Option<serde_json::Value>, CliError> {
    if !path.is_file() {
        return Ok(None);
    }
    serde_json::from_slice(&read_file(path)?)
        .map(Some)
        .map_err(|error| CliError::Trace(error.to_string()))
}

pub(super) fn write_campaign_success(
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

pub(super) fn parse_seed_range(value: &str) -> Result<(u64, u64), CliError> {
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

pub(super) fn campaign_seed(ordinal: u64) -> (RootSeed, String) {
    let mut hasher = blake3::Hasher::new_derive_key("krikos-sim campaign root seed v1");
    hasher.update(&ordinal.to_le_bytes());
    let bytes = *hasher.finalize().as_bytes();
    (
        RootSeed::new(bytes),
        bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
    )
}

pub(super) fn swarm_materialization_seed(runtime_seed: RootSeed) -> RootSeed {
    let mut hasher = blake3::Hasher::new_derive_key("krikos-sim swarm materialization seed v1");
    hasher.update(runtime_seed.as_bytes());
    RootSeed::new(*hasher.finalize().as_bytes())
}

pub(super) struct MinimizationProgress {
    root: PathBuf,
    journal: fs::File,
    resume: bool,
    temp_ordinal: u64,
}

impl MinimizationProgress {
    pub(super) fn open(root: &Path, resume: bool) -> Result<Self, CliError> {
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

    pub(super) fn resume_scenario(&self) -> Result<Option<Scenario>, CliError> {
        let path = self.root.join("best.scenario.json");
        if self.resume && path.is_file() {
            return Scenario::from_json(&read_file(path)?)
                .map(Some)
                .map_err(Into::into);
        }
        Ok(None)
    }

    pub(super) fn record(
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

    pub(super) fn publish_best(&mut self, scenario: &Scenario) -> Result<(), CliError> {
        self.atomic_replace(
            "best.scenario.json",
            &scenario
                .to_canonical_json()
                .map_err(CliError::ScenarioModel)?,
        )
    }

    pub(super) fn publish_result(
        &mut self,
        result: &crate::MinimizationResult,
    ) -> Result<(), CliError> {
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
pub(super) struct CapturingTraceSink {
    pub(super) durable: ArtifactTraceWriter,
    pub(super) memory: TraceBuffer,
}

impl TraceSink for CapturingTraceSink {
    fn record(&self, event: TraceEvent) -> Result<(), TraceSinkError> {
        self.durable.record(event.clone())?;
        self.memory.record(event)
    }
}

pub(super) fn write_json_artifact<T: serde::Serialize + ?Sized>(
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
