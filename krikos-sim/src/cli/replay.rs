use super::*;

pub(super) fn execute_declarative_replay(
    manifest_path: &Path,
    manifest: &RunManifest,
    artifact_root: &Path,
) -> Result<(), CliError> {
    let scenario = Scenario::from_json(&read_file(artifact_root.join("scenario.json"))?)?;
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
        || manifest.scheduling_profile != "seeded-fair-kernel+root-driver+declarative-v3"
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
            FailureSignature::from_json(&read_file(artifact_root.join("failure-signature.json"))?)?;
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

pub(super) fn execute_minimize(
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
    let manifest = RunManifest::from_json(&read_file(&manifest_path)?)?;
    let workspace = workspace_root()?;
    let scenario = Scenario::from_json(&read_file(artifact_root.join("scenario.json"))?)?;
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
        FailureSignature::from_json(&read_file(artifact_root.join("failure-signature.json"))?)?;
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

pub(super) fn execute_replay(manifest_path: &Path) -> Result<(), CliError> {
    let manifest_path = fs::canonicalize(absolutize(manifest_path)?).map_err(CliError::Io)?;
    let manifest = RunManifest::from_json(&read_file(&manifest_path).map_err(CliError::Io)?)?;
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
    let expected = read_file(&expected_path).map_err(CliError::Io)?;
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
