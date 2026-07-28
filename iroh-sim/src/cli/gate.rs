use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn execute_gate_select(
    impact_policy_path: &Path,
    coverage_policy_path: &Path,
    base_revision: Option<&str>,
    candidate_revision: &str,
    tier: SimulationGateTier,
    changes_path: &Path,
    diff_unavailable: bool,
    output: &Path,
) -> Result<(), CliError> {
    let impact_policy = crate::ChangeImpactPolicy::from_json(
        &read_file(impact_policy_path).map_err(CliError::Io)?,
    )?;
    let coverage_policy_bytes = read_file(coverage_policy_path).map_err(CliError::Io)?;
    CoveragePolicy::from_json(&coverage_policy_bytes)?;
    let coverage_policy_blake3 = blake3::hash(&coverage_policy_bytes).to_hex().to_string();
    let changed_paths: Vec<String> =
        serde_json::from_slice(&read_file(changes_path).map_err(CliError::Io)?)
            .map_err(|error| GateError::Encoding(error.to_string()))?;
    let selection = GateSelection::build(
        &impact_policy,
        &coverage_policy_blake3,
        base_revision,
        candidate_revision,
        tier,
        &changed_paths,
        !diff_unavailable,
    )?;
    if let Some(parent) = absolutize(output)?.parent() {
        fs::create_dir_all(parent).map_err(CliError::Io)?;
    }
    write_immutable(output, &selection.to_canonical_json()?)?;
    println!(
        "status=gate_selected mode={:?} runs={} output={}",
        selection.mode,
        selection.total_runs(),
        output.display()
    );
    Ok(())
}
