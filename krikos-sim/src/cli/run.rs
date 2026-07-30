use super::*;

pub(super) fn execute_run(
    scenario_path: &Path,
    seed_hex: &str,
    artifact_override: Option<&Path>,
    crypto: CryptoLane,
) -> Result<(), CliError> {
    let scenario_bytes = read_file(scenario_path).map_err(CliError::Io)?;
    let schema_version = scenario_schema_version(&scenario_bytes)?;
    if schema_version != crate::STAGE2_SCENARIO_SCHEMA_VERSION {
        return execute_declarative_run(
            Scenario::from_versioned_json(&scenario_bytes)?,
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

pub(super) fn execute_declarative_run(
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
        scheduling_profile: "seeded-fair-kernel+root-driver+declarative-v3".to_owned(),
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
