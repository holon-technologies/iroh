use super::*;

pub(super) fn execute_identity(operation: IdentityCommand) -> Result<(), CliError> {
    match operation {
        IdentityCommand::Run {
            scenario,
            seed,
            artifacts,
            max_minimization_attempts,
        } => execute_run(&scenario, &seed, &artifacts, max_minimization_attempts),
        IdentityCommand::Replay { manifest } => execute_replay(&manifest),
        IdentityCommand::CorpusTest { path } => {
            let reports = crate::identity::IdentityCorpus::load(&path)
                .and_then(|corpus| corpus.test())
                .map_err(|error| CliError::Runner(error.to_string()))?;
            print_json(&reports)
        }
        IdentityCommand::ModelCheck => {
            let bytes = crate::identity::check_account_control_model()
                .and_then(|report| report.to_canonical_json())
                .map_err(|error| CliError::Runner(error.to_string()))?;
            print!("{}", String::from_utf8_lossy(&bytes));
            Ok(())
        }
        IdentityCommand::Differential { seed } => {
            let report = crate::identity::run_differential_history(parse_seed(&seed)?)
                .map_err(|error| CliError::Runner(error.to_string()))?;
            print_json(&report)
        }
        IdentityCommand::PromotionCandidate {
            manifest,
            output,
            issue,
        } => execute_promotion_candidate(&manifest, &output, issue),
    }
}

fn execute_run(
    scenario_path: &Path,
    seed_text: &str,
    artifacts: &Path,
    max_minimization_attempts: u64,
) -> Result<(), CliError> {
    let scenario = crate::identity::IdentityScenario::from_json(
        &read_file(scenario_path).map_err(CliError::Io)?,
    )
    .map_err(|error| CliError::Runner(error.to_string()))?;
    let seed = parse_seed(seed_text)?;
    let artifact_root = absolutize(artifacts)?;
    let workspace = workspace_root()?;
    let source = source_identity(&workspace, Some(&artifact_root))?;
    let lockfile_digest = digest_file(&workspace.join("Cargo.lock"))?;
    let canonical_scenario = scenario
        .to_canonical_json()
        .map_err(|error| CliError::Runner(error.to_string()))?;
    let outcome = crate::identity::IdentityScenarioRunner::run_detailed(&scenario, seed)
        .map_err(|error| CliError::Runner(error.to_string()))?;
    let original_first = match outcome {
        crate::identity::IdentityRunOutcome::Success(record) => {
            let manifest = identity_manifest(
                source,
                seed_text,
                &scenario,
                &canonical_scenario,
                lockfile_digest,
            );
            let store = ArtifactStore::new(&artifact_root)?;
            crate::identity::IdentityArtifactBundle {
                scenario: &scenario,
                manifest: &manifest,
                record: &record,
            }
            .write(&store)
            .map_err(|error| CliError::Runner(error.to_string()))?;
            println!(
                "status=success scenario={} manifest={}",
                scenario.id(),
                store.root().join("manifest.json").display()
            );
            return Ok(());
        }
        crate::identity::IdentityRunOutcome::ExpectedRejection(record) => {
            let manifest = identity_manifest(
                source,
                seed_text,
                &scenario,
                &canonical_scenario,
                lockfile_digest,
            );
            let store = ArtifactStore::new(&artifact_root)?;
            crate::identity::IdentityRejectionArtifactBundle {
                scenario: &scenario,
                manifest: &manifest,
                record: &record,
            }
            .write(&store)
            .map_err(|error| CliError::Runner(error.to_string()))?;
            println!(
                "status=expected_rejection terminal=expected_rejection scenario={} class={} rejection={} manifest={}",
                scenario.id(),
                record.evidence.class.as_str(),
                record.evidence.rejection.as_str(),
                store.root().join("manifest.json").display()
            );
            return Ok(());
        }
        crate::identity::IdentityRunOutcome::Failed(failure) => failure,
    };

    let original_second = require_failed_run(
        crate::identity::IdentityScenarioRunner::run_detailed(&scenario, seed)
            .map_err(|error| CliError::Runner(error.to_string()))?,
        "original confirmation unexpectedly succeeded",
    )?;
    let signature = original_first
        .signature()
        .map_err(|error| CliError::Runner(error.to_string()))?;
    if original_second
        .signature()
        .map_err(|error| CliError::Runner(error.to_string()))?
        != signature
        || original_first != original_second
    {
        return Err(CliError::Runner(
            "identity failure did not reproduce byte-exactly under the same seed".to_owned(),
        ));
    }
    let mut evaluator = |candidate: &crate::identity::IdentityScenario| {
        match crate::identity::IdentityScenarioRunner::run_detailed(candidate, seed)
            .map_err(|error| error.to_string())?
        {
            crate::identity::IdentityRunOutcome::Success(_) => Ok(None),
            crate::identity::IdentityRunOutcome::ExpectedRejection(_) => Ok(None),
            crate::identity::IdentityRunOutcome::Failed(failure) => failure
                .signature()
                .map(Some)
                .map_err(|error| error.to_string()),
        }
    };
    let minimized = crate::identity::IdentityMinimizer::new(max_minimization_attempts)
        .and_then(|minimizer| minimizer.minimize(scenario.clone(), signature, &mut evaluator))
        .map_err(|error| CliError::Runner(error.to_string()))?;
    let minimized_first = require_failed_run(
        crate::identity::IdentityScenarioRunner::run_detailed(&minimized.scenario, seed)
            .map_err(|error| CliError::Runner(error.to_string()))?,
        "minimized failure unexpectedly succeeded",
    )?;
    let minimized_second = require_failed_run(
        crate::identity::IdentityScenarioRunner::run_detailed(&minimized.scenario, seed)
            .map_err(|error| CliError::Runner(error.to_string()))?,
        "minimized replay confirmation unexpectedly succeeded",
    )?;
    let confirmation = crate::identity::IdentityFailureConfirmation::new(
        &scenario,
        &minimized.scenario,
        &original_first,
        &original_second,
        &minimized_first,
        &minimized_second,
    )
    .map_err(|error| CliError::Runner(error.to_string()))?;
    let canonical_minimized = minimized
        .scenario
        .to_canonical_json()
        .map_err(|error| CliError::Runner(error.to_string()))?;
    let manifest = identity_manifest(
        source,
        seed_text,
        &minimized.scenario,
        &canonical_minimized,
        lockfile_digest,
    );
    let store = ArtifactStore::new(&artifact_root)?;
    crate::identity::IdentityFailureArtifactBundle {
        original: &scenario,
        minimized: &minimized,
        manifest: &manifest,
        original_failure: &original_second,
        minimized_failure: &minimized_second,
        confirmation: &confirmation,
    }
    .write(&store)
    .map_err(|error| CliError::Runner(error.to_string()))?;
    Err(CliError::Runner(format!(
        "confirmed identity failure recorded: scenario={} signature={}/{} manifest={}",
        scenario.id(),
        minimized.signature.class,
        minimized.signature.evidence_digest,
        store.root().join("manifest.json").display()
    )))
}

fn require_failed_run(
    outcome: crate::identity::IdentityRunOutcome,
    success_error: &str,
) -> Result<crate::identity::IdentityFailedRunRecord, CliError> {
    match outcome {
        crate::identity::IdentityRunOutcome::Success(_) => {
            Err(CliError::Runner(success_error.to_owned()))
        }
        crate::identity::IdentityRunOutcome::ExpectedRejection(_) => Err(CliError::Runner(
            "identity product failure became an expected model rejection".to_owned(),
        )),
        crate::identity::IdentityRunOutcome::Failed(failure) => Ok(failure),
    }
}

fn execute_replay(manifest_path: &Path) -> Result<(), CliError> {
    let manifest_path = std::fs::canonicalize(absolutize(manifest_path)?).map_err(CliError::Io)?;
    let artifact_root = manifest_path
        .parent()
        .ok_or(CliError::ManifestHasNoParent)?;
    let manifest = RunManifest::from_json(&read_file(&manifest_path).map_err(CliError::Io)?)?;
    let scenario = crate::identity::IdentityScenario::from_json(
        &read_file(artifact_root.join("scenario.json")).map_err(CliError::Io)?,
    )
    .map_err(|error| CliError::Runner(error.to_string()))?;
    let workspace = workspace_root()?;
    let canonical_scenario = scenario
        .to_canonical_json()
        .map_err(|error| CliError::Runner(error.to_string()))?;
    let current = ReplayIdentity {
        schema_version: MANIFEST_SCHEMA_VERSION,
        simulator_version: SIMULATOR_VERSION.to_owned(),
        source: source_identity(&workspace, Some(artifact_root))?,
        scenario_hash: blake3::hash(&canonical_scenario).to_hex().to_string(),
        normalized_config: identity_config(),
        features: Vec::new(),
        lockfile_digest: digest_file(&workspace.join("Cargo.lock"))?,
    };
    if manifest.backend != BackendCapabilities::deterministic_kernel()
        || manifest.scheduling_profile != "seeded-kernel-v1"
        || manifest.fault_profile != "identity-actions-v1"
        || manifest.crypto_mode != crate::CryptoMode::DeterministicTest
        || manifest.trace_comparison != crate::TraceComparisonMode::Raw
        || manifest.determinism_grade != DeterminismGrade::FullyDeterministic
        || manifest.fidelity_exceptions != ["deterministic_test_crypto"]
        || !manifest.escapes.is_empty()
    {
        return Err(CliError::BackendIdentityMismatch);
    }
    let has_failure = artifact_root.join("failure-artifacts.json").is_file();
    let has_rejection = artifact_root
        .join("identity-rejection-report.json")
        .is_file();
    if has_failure && has_rejection {
        return Err(CliError::Runner(
            "identity artifact directory declares conflicting terminal classes".to_owned(),
        ));
    }
    if has_failure {
        let record = crate::identity::replay_identity_failure_artifacts(artifact_root, &current)
            .map_err(|error| CliError::Runner(error.to_string()))?;
        println!(
            "status=replay_ok terminal=expected_failure scenario={} steps={} manifest={}",
            scenario.id(),
            record.report.steps.len(),
            manifest_path.display()
        );
        return Ok(());
    }
    if has_rejection {
        let record = crate::identity::replay_identity_rejection_artifacts(artifact_root, &current)
            .map_err(|error| CliError::Runner(error.to_string()))?;
        println!(
            "status=replay_ok terminal=expected_rejection scenario={} class={} rejection={} steps={} manifest={}",
            scenario.id(),
            record.evidence.class.as_str(),
            record.evidence.rejection.as_str(),
            record.report.steps.len(),
            manifest_path.display()
        );
        return Ok(());
    }
    let record = crate::identity::replay_identity_artifacts(artifact_root, &current)
        .map_err(|error| CliError::Runner(error.to_string()))?;
    println!(
        "status=replay_ok scenario={} steps={} manifest={}",
        scenario.id(),
        record.report.steps.len(),
        manifest_path.display()
    );
    Ok(())
}

fn execute_promotion_candidate(
    manifest_path: &Path,
    output: &Path,
    issue: String,
) -> Result<(), CliError> {
    execute_replay(manifest_path)?;
    let manifest_path = std::fs::canonicalize(absolutize(manifest_path)?).map_err(CliError::Io)?;
    let failure_root = manifest_path
        .parent()
        .ok_or(CliError::ManifestHasNoParent)?;
    if !failure_root.join("failure-artifacts.json").is_file() {
        return Err(CliError::Runner(
            "identity corpus promotion requires a committed failure bundle".to_owned(),
        ));
    }
    let output = absolutize(output)?;
    let store = ArtifactStore::new(&output)?;
    let entry = crate::identity::write_identity_promotion_candidate(failure_root, &store, issue)
        .map_err(|error| CliError::Runner(error.to_string()))?;
    println!(
        "status=promotion_candidate_pending_review scenario={} entry={}",
        entry.id,
        store.root().join("entry.json").display()
    );
    Ok(())
}

fn identity_manifest(
    source: SourceIdentity,
    seed: &str,
    scenario: &crate::identity::IdentityScenario,
    canonical_scenario: &[u8],
    lockfile_digest: String,
) -> RunManifest {
    RunManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        simulator_version: SIMULATOR_VERSION.to_owned(),
        source,
        root_seed: seed.to_owned(),
        scenario_id: scenario.id().to_owned(),
        scenario_hash: blake3::hash(canonical_scenario).to_hex().to_string(),
        normalized_config: identity_config(),
        features: Vec::new(),
        wall_clock_epoch_secs: 0,
        backend: BackendCapabilities::deterministic_kernel(),
        budgets: RunBudgets {
            max_events: 10_000,
            max_virtual_time_nanos: 60_000_000_000,
            max_tasks: 512,
            max_packets: 1,
        },
        scheduling_profile: "seeded-kernel-v1".to_owned(),
        fault_profile: "identity-actions-v1".to_owned(),
        lockfile_digest,
        crypto_mode: crate::CryptoMode::DeterministicTest,
        trace_comparison: crate::TraceComparisonMode::Raw,
        fidelity_exceptions: vec!["deterministic_test_crypto".to_owned()],
        determinism_grade: DeterminismGrade::FullyDeterministic,
        escapes: Vec::new(),
        unsafe_test_only: true,
    }
}

fn identity_config() -> BTreeMap<String, String> {
    BTreeMap::from([("lane".to_owned(), "identity".to_owned())])
}

fn print_json(value: &impl serde::Serialize) -> Result<(), CliError> {
    let json =
        serde_json::to_string_pretty(value).map_err(|error| CliError::Trace(error.to_string()))?;
    println!("{json}");
    Ok(())
}
