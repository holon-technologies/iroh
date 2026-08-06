//! Immutable identity run artifacts and source-bound exact replay.

use std::path::Path;

use krikos_runtime::{RootSeed, TraceEvent};
use serde::{Deserialize, Serialize};

use crate::{
    ArtifactStore, ReplayIdentity, RunManifest, bounded_io::read_file, normalized_trace_json,
};

use super::{
    IdentityFailedRunRecord, IdentityFailureConfirmation, IdentityFailureReport,
    IdentityFailureSignature, IdentityMinimizationResult, IdentityMinimizer,
    IdentityRejectedRunRecord, IdentityRejectionEvidence, IdentityRunOutcome, IdentityRunRecord,
    IdentityRunReport, IdentityScenario, IdentityScenarioRunner,
    corpus::MAX_IDENTITY_MINIMIZATION_ATTEMPTS, verify_identity_failure_artifacts,
};

const IDENTITY_REJECTION_ARTIFACT_SCHEMA_VERSION: u16 = 1;

/// Immutable artifact writer for one successful identity simulation.
#[derive(Debug)]
pub struct IdentityArtifactBundle<'a> {
    /// Canonical input scenario.
    pub scenario: &'a IdentityScenario,
    /// Source, configuration, seed, and dependency identity.
    pub manifest: &'a RunManifest,
    /// Successful report and raw trace produced by the manifest seed.
    pub record: &'a IdentityRunRecord,
}

impl IdentityArtifactBundle<'_> {
    /// Writes the manifest, input, semantic report, and both trace representations immutably.
    pub fn write(&self, store: &ArtifactStore) -> Result<(), IdentityReplayError> {
        self.validate_binding()?;
        store
            .write_manifest("manifest.json", self.manifest)
            .map_err(|error| IdentityReplayError::Artifact(error.to_string()))?;
        store
            .write_atomic("scenario.json", &self.scenario.to_canonical_json()?)
            .map_err(|error| IdentityReplayError::Artifact(error.to_string()))?;
        store
            .write_atomic(
                "identity-report.json",
                &canonical_report(&self.record.report)?,
            )
            .map_err(|error| IdentityReplayError::Artifact(error.to_string()))?;
        store
            .write_raw_trace("trace.raw.jsonl", &self.record.trace)
            .map_err(|error| IdentityReplayError::Artifact(error.to_string()))?;
        store
            .write_trace("trace.jsonl", &self.record.trace)
            .map_err(|error| IdentityReplayError::Artifact(error.to_string()))?;
        Ok(())
    }

    fn validate_binding(&self) -> Result<(), IdentityReplayError> {
        self.manifest
            .validate()
            .map_err(|error| IdentityReplayError::Manifest(error.to_string()))?;
        if self.manifest.root_seed != encode_seed(self.record.root_seed) {
            return Err(IdentityReplayError::SeedMismatch);
        }
        if self.manifest.scenario_id != self.scenario.id()
            || self.manifest.scenario_hash != scenario_digest(self.scenario)?
        {
            return Err(IdentityReplayError::ScenarioMismatch);
        }
        Ok(())
    }
}

/// Versioned terminal evidence for one correct fail-closed model rejection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityRejectionReport {
    /// Artifact schema version for expected-rejection evidence.
    pub schema_version: u16,
    /// Hex-encoded behavioral root seed used by the rejected run.
    pub root_seed: String,
    /// Exact declared rejection that matched the model terminal.
    pub evidence: IdentityRejectionEvidence,
    /// Deterministic post-rejection state, scheduler, task, and invariant evidence.
    pub report: IdentityRunReport,
}

/// Immutable artifact writer for one expected identity model rejection.
#[derive(Debug)]
pub struct IdentityRejectionArtifactBundle<'a> {
    /// Canonical input scenario.
    pub scenario: &'a IdentityScenario,
    /// Source, configuration, seed, and dependency identity.
    pub manifest: &'a RunManifest,
    /// Expected-rejection report and raw trace produced by the manifest seed.
    pub record: &'a IdentityRejectedRunRecord,
}

impl IdentityRejectionArtifactBundle<'_> {
    /// Writes an explicitly classified, exactly replayable non-product terminal.
    pub fn write(&self, store: &ArtifactStore) -> Result<(), IdentityReplayError> {
        self.validate_binding()?;
        let rejection = IdentityRejectionReport {
            schema_version: IDENTITY_REJECTION_ARTIFACT_SCHEMA_VERSION,
            root_seed: encode_seed(self.record.root_seed),
            evidence: self.record.evidence.clone(),
            report: self.record.report.clone(),
        };
        store
            .write_manifest("manifest.json", self.manifest)
            .map_err(|error| IdentityReplayError::Artifact(error.to_string()))?;
        store
            .write_atomic("scenario.json", &self.scenario.to_canonical_json()?)
            .map_err(|error| IdentityReplayError::Artifact(error.to_string()))?;
        store
            .write_atomic(
                "identity-rejection-report.json",
                &canonical_value(&rejection)?,
            )
            .map_err(|error| IdentityReplayError::Artifact(error.to_string()))?;
        store
            .write_raw_trace("trace.raw.jsonl", &self.record.trace)
            .map_err(|error| IdentityReplayError::Artifact(error.to_string()))?;
        store
            .write_trace("trace.jsonl", &self.record.trace)
            .map_err(|error| IdentityReplayError::Artifact(error.to_string()))?;
        Ok(())
    }

    fn validate_binding(&self) -> Result<(), IdentityReplayError> {
        self.manifest
            .validate()
            .map_err(|error| IdentityReplayError::Manifest(error.to_string()))?;
        if self.manifest.root_seed != encode_seed(self.record.root_seed) {
            return Err(IdentityReplayError::SeedMismatch);
        }
        if self.manifest.scenario_id != self.scenario.id()
            || self.manifest.scenario_hash != scenario_digest(self.scenario)?
            || self.record.report.scenario_id != self.scenario.id()
        {
            return Err(IdentityReplayError::ScenarioMismatch);
        }
        Ok(())
    }
}

/// Re-executes a recorded identity run and requires report and raw trace byte equality.
pub fn replay_identity_artifacts(
    root: &Path,
    current: &ReplayIdentity,
) -> Result<IdentityRunRecord, IdentityReplayError> {
    let manifest = RunManifest::from_json(&read_file(root.join("manifest.json"))?)
        .map_err(|error| IdentityReplayError::Manifest(error.to_string()))?;
    manifest
        .check_compatible(current)
        .map_err(|error| IdentityReplayError::Compatibility(error.to_string()))?;
    let scenario = IdentityScenario::from_json(&read_file(root.join("scenario.json"))?)?;
    if manifest.scenario_id != scenario.id()
        || manifest.scenario_hash != scenario_digest(&scenario)?
    {
        return Err(IdentityReplayError::ScenarioMismatch);
    }
    let seed = decode_seed(&manifest.root_seed)?;
    let actual = match IdentityScenarioRunner::run_detailed(&scenario, RootSeed::new(seed))? {
        IdentityRunOutcome::Success(record) => record,
        IdentityRunOutcome::ExpectedRejection(_) => {
            return Err(IdentityReplayError::UnexpectedExpectedRejection);
        }
        IdentityRunOutcome::Failed(_) => {
            return Err(IdentityReplayError::UnexpectedProductFailure);
        }
    };
    let expected_report = read_file(root.join("identity-report.json"))?;
    let actual_report = canonical_report(&actual.report)?;
    if expected_report != actual_report {
        return Err(IdentityReplayError::ReportDivergence);
    }
    let expected_raw = read_file(root.join("trace.raw.jsonl"))?;
    if expected_raw != raw_trace_bytes(&actual.trace)? {
        return Err(IdentityReplayError::RawTraceDivergence);
    }
    let expected_normalized = read_file(root.join("trace.jsonl"))?;
    if expected_normalized != normalized_trace_bytes(&actual.trace)? {
        return Err(IdentityReplayError::NormalizedTraceDivergence);
    }
    Ok(actual)
}

/// Re-executes a correct model rejection and requires its explicit terminal, report, and traces.
pub fn replay_identity_rejection_artifacts(
    root: &Path,
    current: &ReplayIdentity,
) -> Result<IdentityRejectedRunRecord, IdentityReplayError> {
    let manifest = RunManifest::from_json(&read_file(root.join("manifest.json"))?)
        .map_err(|error| IdentityReplayError::Manifest(error.to_string()))?;
    manifest
        .check_compatible(current)
        .map_err(|error| IdentityReplayError::Compatibility(error.to_string()))?;
    let scenario = IdentityScenario::from_json(&read_file(root.join("scenario.json"))?)?;
    if manifest.scenario_id != scenario.id()
        || manifest.scenario_hash != scenario_digest(&scenario)?
    {
        return Err(IdentityReplayError::ScenarioMismatch);
    }
    let seed = decode_seed(&manifest.root_seed)?;
    let actual = match IdentityScenarioRunner::run_detailed(&scenario, RootSeed::new(seed))? {
        IdentityRunOutcome::ExpectedRejection(record) => record,
        IdentityRunOutcome::Success(_) => {
            return Err(IdentityReplayError::ExpectedRejectionDisappeared);
        }
        IdentityRunOutcome::Failed(_) => {
            return Err(IdentityReplayError::ExpectedRejectionBecameFailure);
        }
    };
    let persisted_report = read_file(root.join("identity-rejection-report.json"))?;
    let _: IdentityRejectionReport = serde_json::from_slice(&persisted_report)
        .map_err(|error| IdentityReplayError::Encoding(error.to_string()))?;
    let reconstructed_report = IdentityRejectionReport {
        schema_version: IDENTITY_REJECTION_ARTIFACT_SCHEMA_VERSION,
        root_seed: encode_seed(actual.root_seed),
        evidence: actual.evidence.clone(),
        report: actual.report.clone(),
    };
    if persisted_report != canonical_value(&reconstructed_report)? {
        return Err(IdentityReplayError::RejectionReportDivergence);
    }
    if read_file(root.join("trace.raw.jsonl"))? != raw_trace_bytes(&actual.trace)? {
        return Err(IdentityReplayError::RawTraceDivergence);
    }
    if read_file(root.join("trace.jsonl"))? != normalized_trace_bytes(&actual.trace)? {
        return Err(IdentityReplayError::NormalizedTraceDivergence);
    }
    Ok(actual)
}

/// Re-executes one committed minimized failure and requires exact terminal evidence and traces.
pub fn replay_identity_failure_artifacts(
    root: &Path,
    current: &ReplayIdentity,
) -> Result<IdentityFailedRunRecord, IdentityReplayError> {
    verify_identity_failure_artifacts(root)?;
    let manifest = RunManifest::from_json(&read_file(root.join("manifest.json"))?)
        .map_err(|error| IdentityReplayError::Manifest(error.to_string()))?;
    manifest
        .check_compatible(current)
        .map_err(|error| IdentityReplayError::Compatibility(error.to_string()))?;
    let minimized_scenario = IdentityScenario::from_json(&read_file(root.join("scenario.json"))?)?;
    let recorded_minimized =
        IdentityScenario::from_json(&read_file(root.join("failure-minimized.json"))?)?;
    let original_scenario =
        IdentityScenario::from_json(&read_file(root.join("failure-original.json"))?)?;
    if manifest.scenario_id != minimized_scenario.id()
        || manifest.scenario_hash != scenario_digest(&minimized_scenario)?
        || recorded_minimized != minimized_scenario
        || original_scenario.id() != minimized_scenario.id()
    {
        return Err(IdentityReplayError::ScenarioMismatch);
    }
    let expected_signature =
        IdentityFailureSignature::from_json(&read_file(root.join("failure-signature.json"))?)?;
    let confirmation: IdentityFailureConfirmation =
        serde_json::from_slice(&read_file(root.join("failure-confirmation.json"))?)
            .map_err(|error| IdentityReplayError::Encoding(error.to_string()))?;
    let minimization: IdentityMinimizationResult =
        serde_json::from_slice(&read_file(root.join("failure-minimization.json"))?)
            .map_err(|error| IdentityReplayError::Encoding(error.to_string()))?;
    let seed = decode_seed(&manifest.root_seed)?;
    let original = replay_failed_scenario(&original_scenario, seed)?;
    let original_confirmation = replay_failed_scenario(&original_scenario, seed)?;
    let minimized = replay_failed_scenario(&minimized_scenario, seed)?;
    let minimized_confirmation = replay_failed_scenario(&minimized_scenario, seed)?;
    if original != original_confirmation || minimized != minimized_confirmation {
        return Err(IdentityReplayError::FailureConfirmationDivergence);
    }
    if original.signature()? != expected_signature || minimized.signature()? != expected_signature {
        return Err(IdentityReplayError::FailureSignatureDivergence);
    }
    let expected_original_report: IdentityFailureReport = serde_json::from_slice(&read_file(
        root.join("identity-failure-original-report.json"),
    )?)
    .map_err(|error| IdentityReplayError::Encoding(error.to_string()))?;
    if expected_original_report.root_seed != manifest.root_seed
        || expected_original_report.evidence != original.evidence
        || expected_original_report.report != original.report
    {
        return Err(IdentityReplayError::FailureReportDivergence);
    }
    let expected_minimized_report: IdentityFailureReport =
        serde_json::from_slice(&read_file(root.join("identity-failure-report.json"))?)
            .map_err(|error| IdentityReplayError::Encoding(error.to_string()))?;
    if expected_minimized_report.root_seed != manifest.root_seed
        || expected_minimized_report.evidence != minimized.evidence
        || expected_minimized_report.report != minimized.report
    {
        return Err(IdentityReplayError::FailureReportDivergence);
    }
    let original_raw = raw_trace_bytes(&original.trace)?;
    if read_file(root.join("trace-original.raw.jsonl"))? != original_raw {
        return Err(IdentityReplayError::RawTraceDivergence);
    }
    let original_normalized = normalized_trace_bytes(&original.trace)?;
    if read_file(root.join("trace-original.jsonl"))? != original_normalized {
        return Err(IdentityReplayError::NormalizedTraceDivergence);
    }
    let minimized_raw = raw_trace_bytes(&minimized.trace)?;
    if read_file(root.join("trace.raw.jsonl"))? != minimized_raw {
        return Err(IdentityReplayError::RawTraceDivergence);
    }
    let minimized_normalized = normalized_trace_bytes(&minimized.trace)?;
    if read_file(root.join("trace.jsonl"))? != minimized_normalized {
        return Err(IdentityReplayError::NormalizedTraceDivergence);
    }
    if confirmation.signature != expected_signature
        || confirmation.root_seed != manifest.root_seed
        || confirmation.original_scenario_digest != scenario_digest(&original_scenario)?
        || confirmation.minimized_scenario_digest != scenario_digest(&minimized_scenario)?
        || confirmation.original_report_digest
            != blake3_digest(&canonical_report(&original.report)?)
        || confirmation.original_raw_trace_digest != blake3_digest(&original_raw)
        || confirmation.original_normalized_trace_digest != blake3_digest(&original_normalized)
        || confirmation.minimized_report_digest
            != blake3_digest(&canonical_report(&minimized.report)?)
        || confirmation.minimized_raw_trace_digest != blake3_digest(&minimized_raw)
        || confirmation.minimized_normalized_trace_digest != blake3_digest(&minimized_normalized)
        || confirmation.original_confirmations != 2
        || confirmation.minimized_confirmations != 2
        || minimization.signature != expected_signature
        || minimization.scenario != minimized_scenario
    {
        return Err(IdentityReplayError::FailureConfirmationDivergence);
    }
    let replay_budget = if minimization.exhausted {
        u64::try_from(minimization.attempts.len())
            .map_err(|_| IdentityReplayError::FailureConfirmationDivergence)?
    } else {
        MAX_IDENTITY_MINIMIZATION_ATTEMPTS
    };
    if replay_budget == 0 {
        return Err(IdentityReplayError::FailureConfirmationDivergence);
    }
    let mut evaluator = |candidate: &IdentityScenario| match IdentityScenarioRunner::run_detailed(
        candidate,
        RootSeed::new(seed),
    )
    .map_err(|error| error.to_string())?
    {
        IdentityRunOutcome::Success(_) => Ok(None),
        IdentityRunOutcome::ExpectedRejection(_) => Ok(None),
        IdentityRunOutcome::Failed(failure) => failure
            .signature()
            .map(Some)
            .map_err(|error| error.to_string()),
    };
    let reconstructed = IdentityMinimizer::new(replay_budget)?.minimize(
        original_scenario,
        expected_signature,
        &mut evaluator,
    )?;
    if reconstructed != minimization {
        return Err(IdentityReplayError::FailureConfirmationDivergence);
    }
    Ok(minimized)
}

fn replay_failed_scenario(
    scenario: &IdentityScenario,
    seed: [u8; 32],
) -> Result<IdentityFailedRunRecord, IdentityReplayError> {
    match IdentityScenarioRunner::run_detailed(scenario, RootSeed::new(seed))? {
        IdentityRunOutcome::Success(_) => Err(IdentityReplayError::FailureDisappeared),
        IdentityRunOutcome::ExpectedRejection(_) => {
            Err(IdentityReplayError::FailureBecameExpectedRejection)
        }
        IdentityRunOutcome::Failed(failure) => Ok(failure),
    }
}

fn scenario_digest(scenario: &IdentityScenario) -> Result<String, IdentityReplayError> {
    Ok(blake3::hash(&scenario.to_canonical_json()?)
        .to_hex()
        .to_string())
}

fn canonical_report(report: &IdentityRunReport) -> Result<Vec<u8>, IdentityReplayError> {
    canonical_value(report)
}

fn canonical_value(value: &impl Serialize) -> Result<Vec<u8>, IdentityReplayError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| IdentityReplayError::Encoding(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn raw_trace_bytes(trace: &[TraceEvent]) -> Result<Vec<u8>, IdentityReplayError> {
    let mut bytes = Vec::new();
    for event in trace {
        bytes.extend(
            serde_json::to_vec(event)
                .map_err(|error| IdentityReplayError::Encoding(error.to_string()))?,
        );
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn normalized_trace_bytes(trace: &[TraceEvent]) -> Result<Vec<u8>, IdentityReplayError> {
    let mut bytes = Vec::new();
    for event in trace {
        bytes.extend(
            normalized_trace_json(event)
                .map_err(|error| IdentityReplayError::Encoding(error.to_string()))?,
        );
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn blake3_digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn encode_seed(seed: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in seed {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_seed(value: &str) -> Result<[u8; 32], IdentityReplayError> {
    if value.len() != 64 {
        return Err(IdentityReplayError::InvalidSeed);
    }
    let mut seed = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_nibble(pair[0]).ok_or(IdentityReplayError::InvalidSeed)?;
        let low = decode_nibble(pair[1]).ok_or(IdentityReplayError::InvalidSeed)?;
        seed[index] = high
            .checked_mul(16)
            .and_then(|value| value.checked_add(low))
            .ok_or(IdentityReplayError::InvalidSeed)?;
    }
    Ok(seed)
}

const fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

/// Artifact binding or exact replay failure.
#[derive(Debug, thiserror::Error)]
pub enum IdentityReplayError {
    #[error("identity artifact I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("identity artifact write failed: {0}")]
    Artifact(String),
    #[error("identity manifest is invalid: {0}")]
    Manifest(String),
    #[error("identity replay compatibility failed: {0}")]
    Compatibility(String),
    #[error("identity scenario binding does not match the manifest")]
    ScenarioMismatch,
    #[error("identity root seed does not match the manifest")]
    SeedMismatch,
    #[error("identity root seed is not lowercase 32-byte hexadecimal")]
    InvalidSeed,
    #[error("identity replay report diverged")]
    ReportDivergence,
    #[error("identity replay raw trace diverged")]
    RawTraceDivergence,
    #[error("identity replay normalized trace diverged")]
    NormalizedTraceDivergence,
    /// A success artifact replay reached a correctly declared model rejection.
    #[error("identity success replay reached an expected model rejection")]
    UnexpectedExpectedRejection,
    /// A success artifact replay reached a product failure.
    #[error("identity success replay reached a product failure")]
    UnexpectedProductFailure,
    /// An expected-rejection artifact replay completed successfully.
    #[error("identity replay expected a model rejection, but the scenario succeeded")]
    ExpectedRejectionDisappeared,
    /// An expected-rejection artifact replay reached a product failure.
    #[error(
        "identity replay expected a model rejection, but the scenario reached a product failure"
    )]
    ExpectedRejectionBecameFailure,
    /// Expected-rejection evidence no longer matches its persisted report.
    #[error("identity replay expected-rejection report diverged")]
    RejectionReportDivergence,
    #[error("identity replay expected a failure, but the minimized scenario succeeded")]
    FailureDisappeared,
    /// A product-failure artifact replay became a correctly declared model rejection.
    #[error("identity replay expected a product failure, but reached an expected model rejection")]
    FailureBecameExpectedRejection,
    #[error("identity replay failure signature diverged")]
    FailureSignatureDivergence,
    #[error("identity replay failed terminal report diverged")]
    FailureReportDivergence,
    #[error("identity replay failure confirmation or minimization evidence diverged")]
    FailureConfirmationDivergence,
    #[error("identity replay encoding failed: {0}")]
    Encoding(String),
    #[error(transparent)]
    Scenario(#[from] super::IdentityScenarioError),
    #[error(transparent)]
    Corpus(#[from] super::IdentityCorpusError),
}
