use super::*;

pub(super) fn execute_parity_export(
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
    let mut run_hasher = blake3::Hasher::new_derive_key("krikos-sim parity evidence run id v1");
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

pub(super) fn execute_parity_compare(
    expected_path: &Path,
    actual_path: &Path,
    output: Option<&Path>,
) -> Result<(), CliError> {
    let expected = ParityFixture::from_json(&read_file(expected_path)?)?;
    let actual = ParityFixture::from_json(&read_file(actual_path)?)?;
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

pub(super) fn execute_patchbay_import(
    receipt_path: &Path,
    source_revision: &str,
    observed_at_unix_secs: u64,
    output: &Path,
) -> Result<(), CliError> {
    let receipt = PatchbayReceipt::from_json(&read_file(receipt_path)?)?;
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

pub(super) fn parity_case_name(case: crate::CanonicalParityCase) -> &'static str {
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

pub(super) fn write_immutable(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let path = absolutize(path)?;
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
