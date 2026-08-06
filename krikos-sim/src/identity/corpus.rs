//! Strict recorded identity corpus and signature-preserving failure minimization.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};

use krikos_runtime::{RootSeed, TraceEvent};
use serde::{Deserialize, Serialize};

use super::{
    IdentityCoverage, IdentityFailedRunRecord, IdentityRunOutcome, IdentityRunReport,
    IdentityScenario, IdentityScenarioError, IdentityScenarioRunner,
};
use crate::{ArtifactStore, RunManifest, bounded_io::read_file, normalized_trace_json};

/// Strict identity corpus manifest schema.
pub const IDENTITY_CORPUS_SCHEMA_VERSION: u16 = 2;
const MAX_IDENTITY_CORPUS_ENTRIES: usize = 32;
pub(crate) const MAX_IDENTITY_MINIMIZATION_ATTEMPTS: u64 = 1_024;
const IDENTITY_FAILURE_ARTIFACT_SCHEMA_VERSION: u16 = 2;

/// Expected terminal state of a permanent reviewed identity regression.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "terminal", rename_all = "snake_case", deny_unknown_fields)]
pub enum IdentityCorpusExpectation {
    /// The scenario must complete without a model or invariant failure.
    Success,
    /// The pre-fix regression seed must reproduce one exact failure identity.
    ExpectedFailure { signature: IdentityFailureSignature },
}

/// Source-bound evidence required before a failure candidate may be marked reviewed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityCorpusPromotionEvidence {
    /// Digest of the committed failure-artifact index used during review.
    pub artifact_index_digest: String,
    /// Exact source revision on which the failure was replay-confirmed.
    pub source_revision: String,
    /// Human-review issue or audit reference.
    pub issue: String,
    /// The same-seed minimized terminal was replay-confirmed.
    pub replay_confirmed: bool,
    /// Every accepted reduction retained the exact signature.
    pub signature_preserving: bool,
}

/// One reviewed, recorded-seed identity regression entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityCorpusEntry {
    /// Stable ID equal to the scenario ID.
    pub id: String,
    /// One immediate JSON file in the corpus root.
    pub scenario_file: String,
    /// Lowercase 32-byte hexadecimal root seed.
    pub seed: String,
    /// Whether this entry succeeds now or intentionally preserves a pre-fix terminal.
    pub expectation: IdentityCorpusExpectation,
    /// Source-bound evidence for expected-failure promotions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promotion: Option<IdentityCorpusPromotionEvidence>,
    /// Human-reviewed permanent entry marker.
    pub reviewed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct IdentityCorpusManifest {
    schema_version: u16,
    entries: Vec<IdentityCorpusEntry>,
}

/// Loaded scenario plus its reviewed metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedIdentityCorpusEntry {
    /// Recorded metadata.
    pub metadata: IdentityCorpusEntry,
    /// Strict parsed scenario.
    pub scenario: IdentityScenario,
}

/// Strict corpus whose aggregate action inventory covers every Lane A requirement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityCorpus {
    entries: Vec<LoadedIdentityCorpusEntry>,
    coverage: IdentityCoverage,
}

impl IdentityCorpus {
    /// Loads only the manifest and its exact declared immediate scenario files.
    pub fn load(root: &Path) -> Result<Self, IdentityCorpusError> {
        let files = collect_files(root)?;
        let manifest: IdentityCorpusManifest =
            serde_json::from_slice(&read_file(root.join("manifest.json"))?)
                .map_err(|error| IdentityCorpusError::Encoding(error.to_string()))?;
        if manifest.schema_version != IDENTITY_CORPUS_SCHEMA_VERSION
            || manifest.entries.is_empty()
            || manifest.entries.len() > MAX_IDENTITY_CORPUS_ENTRIES
        {
            return Err(IdentityCorpusError::InvalidManifest);
        }
        let mut expected_files = BTreeSet::from(["manifest.json".to_owned()]);
        let mut ids = BTreeSet::new();
        let mut seeds = BTreeSet::new();
        let mut entries = Vec::with_capacity(manifest.entries.len());
        let mut coverage = IdentityCoverage::default();
        for metadata in manifest.entries {
            if metadata.validate().is_err()
                || !ids.insert(metadata.id.clone())
                || !seeds.insert(metadata.seed.clone())
            {
                return Err(IdentityCorpusError::InvalidEntry(metadata.id));
            }
            decode_seed(&metadata.seed)
                .map_err(|_| IdentityCorpusError::InvalidSeed(metadata.id.clone()))?;
            if !expected_files.insert(metadata.scenario_file.clone()) {
                return Err(IdentityCorpusError::InvalidEntry(metadata.id));
            }
            let scenario =
                IdentityScenario::from_json(&read_file(root.join(&metadata.scenario_file))?)?;
            if scenario.id() != metadata.id {
                return Err(IdentityCorpusError::IdMismatch {
                    metadata: metadata.id,
                    scenario: scenario.id().to_owned(),
                });
            }
            coverage.include(IdentityCoverage::from_scenario(&scenario));
            entries.push(LoadedIdentityCorpusEntry { metadata, scenario });
        }
        if files != expected_files {
            return Err(IdentityCorpusError::UnenumeratedFiles);
        }
        if !coverage.covers_lane_a() {
            return Err(IdentityCorpusError::IncompleteCoverage(coverage));
        }
        entries.sort_by(|left, right| left.metadata.id.cmp(&right.metadata.id));
        Ok(Self { entries, coverage })
    }

    /// Stable reviewed entries.
    pub fn entries(&self) -> &[LoadedIdentityCorpusEntry] {
        &self.entries
    }

    /// Aggregate coverage proven by the strict loader.
    pub const fn coverage(&self) -> IdentityCoverage {
        self.coverage
    }

    /// Replays every entry under its independent recorded seed.
    pub fn test(&self) -> Result<Vec<IdentityCorpusReport>, IdentityCorpusError> {
        let mut reports = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let seed = decode_seed(&entry.metadata.seed)
                .map_err(|_| IdentityCorpusError::InvalidSeed(entry.metadata.id.clone()))?;
            let outcome =
                IdentityScenarioRunner::run_detailed(&entry.scenario, RootSeed::new(seed))?;
            let (report, failure) = match outcome {
                IdentityRunOutcome::Success(record) => (record.report, None),
                IdentityRunOutcome::ExpectedRejection(_) => {
                    return Err(IdentityCorpusError::UnexpectedExpectedRejection(
                        entry.metadata.id.clone(),
                    ));
                }
                IdentityRunOutcome::Failed(record) => {
                    let signature = record.signature()?;
                    (record.report, Some(signature))
                }
            };
            let matched = match (&entry.metadata.expectation, &failure) {
                (IdentityCorpusExpectation::Success, None) => true,
                (
                    IdentityCorpusExpectation::ExpectedFailure {
                        signature: expected,
                    },
                    Some(actual),
                ) => expected == actual,
                _ => false,
            };
            if !matched {
                return Err(IdentityCorpusError::TerminalMismatch(
                    entry.metadata.id.clone(),
                ));
            }
            if !report
                .invariants
                .all_checked_at_each_step(entry.scenario.actions().len())
            {
                return Err(IdentityCorpusError::InvariantAccounting(
                    entry.metadata.id.clone(),
                ));
            }
            reports.push(IdentityCorpusReport {
                id: entry.metadata.id.clone(),
                report,
                failure,
            });
        }
        Ok(reports)
    }
}

/// Successful replay evidence for one corpus entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityCorpusReport {
    /// Stable entry identity.
    pub id: String,
    /// Exact deterministic run report.
    pub report: IdentityRunReport,
    /// Exact expected-failure identity, absent for a successful terminal.
    pub failure: Option<IdentityFailureSignature>,
}

impl IdentityCorpusEntry {
    fn validate(&self) -> Result<(), IdentityCorpusError> {
        if !self.reviewed
            || self.id.is_empty()
            || !valid_filename(&self.scenario_file)
            || decode_seed(&self.seed).is_err()
        {
            return Err(IdentityCorpusError::InvalidEntry(self.id.clone()));
        }
        match (&self.expectation, &self.promotion) {
            (IdentityCorpusExpectation::Success, None) => Ok(()),
            (IdentityCorpusExpectation::ExpectedFailure { signature }, Some(promotion))
                if signature.validate().is_ok() && promotion.is_valid() =>
            {
                Ok(())
            }
            _ => Err(IdentityCorpusError::InvalidEntry(self.id.clone())),
        }
    }
}

impl IdentityCorpusPromotionEvidence {
    fn is_valid(&self) -> bool {
        valid_digest(&self.artifact_index_digest)
            && valid_revision(&self.source_revision)
            && !self.issue.trim().is_empty()
            && self.issue.len() <= 512
            && self.replay_confirmed
            && self.signature_preserving
    }
}

/// Stable confirmed product-failure identity accepted by the reducer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityFailureSignature {
    /// Bounded normalized failure class.
    pub class: String,
    /// Lowercase Blake3 evidence digest.
    pub evidence_digest: String,
}

impl IdentityFailureSignature {
    /// Creates a signature from bounded evidence without retaining sensitive bytes.
    pub fn new(class: impl Into<String>, evidence: &[u8]) -> Result<Self, IdentityCorpusError> {
        let class = class.into();
        let signature = Self {
            class,
            evidence_digest: blake3::hash(evidence).to_hex().to_string(),
        };
        signature.validate()?;
        Ok(signature)
    }

    /// Parses one strict stable failure identity.
    pub fn from_json(bytes: &[u8]) -> Result<Self, IdentityCorpusError> {
        let signature: Self = serde_json::from_slice(bytes)
            .map_err(|error| IdentityCorpusError::Encoding(error.to_string()))?;
        signature.validate()?;
        Ok(signature)
    }

    fn validate(&self) -> Result<(), IdentityCorpusError> {
        if self.class.is_empty()
            || self.class.len() > 128
            || !self.class.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b':' | b'_' | b'-')
            })
            || !valid_digest(&self.evidence_digest)
        {
            return Err(IdentityCorpusError::InvalidSignature);
        }
        Ok(())
    }

    /// Derives the exact stable signature of a real failed simulator run.
    pub fn from_failed_run(failure: &IdentityFailedRunRecord) -> Result<Self, IdentityCorpusError> {
        Self::new(
            failure.evidence.class.as_str(),
            failure.evidence.detail.as_bytes(),
        )
    }
}

impl IdentityFailedRunRecord {
    /// Derives the exact stable signature used for confirmation, reduction, and replay.
    pub fn signature(&self) -> Result<IdentityFailureSignature, IdentityCorpusError> {
        IdentityFailureSignature::from_failed_run(self)
    }
}

/// One deterministic action-deletion attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityMinimizationAttempt {
    pub ordinal: u64,
    pub removed_action: String,
    pub candidate_digest: String,
    pub accepted: bool,
    pub observed_signature: Option<IdentityFailureSignature>,
}

/// Best signature-preserving scenario and bounded attempt history.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityMinimizationResult {
    pub scenario: IdentityScenario,
    pub signature: IdentityFailureSignature,
    pub attempts: Vec<IdentityMinimizationAttempt>,
    pub exhausted: bool,
}

/// Bounded deterministic identity scenario reducer.
#[derive(Clone, Copy, Debug)]
pub struct IdentityMinimizer {
    max_attempts: u64,
}

impl IdentityMinimizer {
    /// Creates a nonzero, hard-bounded reducer.
    pub fn new(max_attempts: u64) -> Result<Self, IdentityCorpusError> {
        if max_attempts == 0 || max_attempts > MAX_IDENTITY_MINIMIZATION_ATTEMPTS {
            return Err(IdentityCorpusError::InvalidMinimizationBudget);
        }
        Ok(Self { max_attempts })
    }

    /// Deletes actions only when the evaluator returns the exact confirmed signature.
    pub fn minimize<F>(
        self,
        scenario: IdentityScenario,
        signature: IdentityFailureSignature,
        evaluator: &mut F,
    ) -> Result<IdentityMinimizationResult, IdentityCorpusError>
    where
        F: FnMut(&IdentityScenario) -> Result<Option<IdentityFailureSignature>, String>,
    {
        if evaluator(&scenario).map_err(IdentityCorpusError::Evaluator)? != Some(signature.clone())
        {
            return Err(IdentityCorpusError::InputSignatureMismatch);
        }
        let mut best = scenario;
        let mut attempts = Vec::new();
        let mut index = best.actions().len();
        let mut exhausted = false;
        while index > 0 {
            if u64::try_from(attempts.len()).map_err(|_| IdentityCorpusError::ArithmeticOverflow)?
                >= self.max_attempts
            {
                exhausted = true;
                break;
            }
            index -= 1;
            if best.actions().len() == 1 {
                break;
            }
            let removed = best.actions()[index].id().to_owned();
            let mut actions = best.actions().to_vec();
            actions.remove(index);
            let candidate = IdentityScenario::new(best.id().to_owned(), actions)?;
            let digest = blake3::hash(&candidate.to_canonical_json()?)
                .to_hex()
                .to_string();
            let observed = evaluator(&candidate).map_err(IdentityCorpusError::Evaluator)?;
            let accepted = observed.as_ref() == Some(&signature);
            let ordinal = u64::try_from(attempts.len())
                .map_err(|_| IdentityCorpusError::ArithmeticOverflow)?;
            attempts.push(IdentityMinimizationAttempt {
                ordinal,
                removed_action: removed,
                candidate_digest: digest,
                accepted,
                observed_signature: observed,
            });
            if accepted {
                best = candidate;
                index = index.min(best.actions().len());
            }
        }
        Ok(IdentityMinimizationResult {
            scenario: best,
            signature,
            attempts,
            exhausted,
        })
    }
}

/// Same-seed exact confirmation of both the original and minimized terminal failure.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityFailureConfirmation {
    pub signature: IdentityFailureSignature,
    pub root_seed: String,
    pub original_scenario_digest: String,
    pub minimized_scenario_digest: String,
    pub original_report_digest: String,
    pub original_raw_trace_digest: String,
    pub original_normalized_trace_digest: String,
    pub minimized_report_digest: String,
    pub minimized_raw_trace_digest: String,
    pub minimized_normalized_trace_digest: String,
    pub original_confirmations: u8,
    pub minimized_confirmations: u8,
}

impl IdentityFailureConfirmation {
    /// Requires two byte-exact real-run confirmations for each terminal candidate.
    pub fn new(
        original_scenario: &IdentityScenario,
        minimized_scenario: &IdentityScenario,
        original_first: &IdentityFailedRunRecord,
        original_second: &IdentityFailedRunRecord,
        minimized_first: &IdentityFailedRunRecord,
        minimized_second: &IdentityFailedRunRecord,
    ) -> Result<Self, IdentityCorpusError> {
        require_exact_failed_run_pair(original_first, original_second)?;
        require_exact_failed_run_pair(minimized_first, minimized_second)?;
        let signature = original_first.signature()?;
        if minimized_first.signature()? != signature
            || original_first.root_seed != minimized_first.root_seed
            || original_scenario.id() != minimized_scenario.id()
            || original_first.report.scenario_id != original_scenario.id()
            || minimized_first.report.scenario_id != minimized_scenario.id()
        {
            return Err(IdentityCorpusError::ConfirmationMismatch);
        }
        Ok(Self {
            signature,
            root_seed: encode_seed(original_first.root_seed),
            original_scenario_digest: digest(&original_scenario.to_canonical_json()?),
            minimized_scenario_digest: digest(&minimized_scenario.to_canonical_json()?),
            original_report_digest: digest(&canonical_json(&original_first.report)?),
            original_raw_trace_digest: digest(&raw_trace_bytes(&original_first.trace)?),
            original_normalized_trace_digest: digest(&normalized_trace_bytes(
                &original_first.trace,
            )?),
            minimized_report_digest: digest(&canonical_json(&minimized_first.report)?),
            minimized_raw_trace_digest: digest(&raw_trace_bytes(&minimized_first.trace)?),
            minimized_normalized_trace_digest: digest(&normalized_trace_bytes(
                &minimized_first.trace,
            )?),
            original_confirmations: 2,
            minimized_confirmations: 2,
        })
    }
}

/// Serialized terminal evidence retained beside the minimized scenario and traces.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityFailureReport {
    pub root_seed: String,
    pub evidence: super::IdentityFailureEvidence,
    pub report: IdentityRunReport,
}

/// Integrity commit marker written last for one immutable identity failure bundle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityFailureArtifactIndex {
    pub schema_version: u16,
    pub files: BTreeMap<String, String>,
}

/// Immutable persistence inputs for one replay-confirmed minimized identity failure.
#[derive(Debug)]
pub struct IdentityFailureArtifactBundle<'a> {
    pub original: &'a IdentityScenario,
    pub minimized: &'a IdentityMinimizationResult,
    pub manifest: &'a RunManifest,
    pub original_failure: &'a IdentityFailedRunRecord,
    pub minimized_failure: &'a IdentityFailedRunRecord,
    pub confirmation: &'a IdentityFailureConfirmation,
}

impl IdentityFailureArtifactBundle<'_> {
    /// Publishes all source-bound evidence and writes the integrity index last.
    pub fn write(
        &self,
        store: &ArtifactStore,
    ) -> Result<IdentityFailureArtifactIndex, IdentityCorpusError> {
        self.validate_binding()?;
        let scenario = self.minimized.scenario.to_canonical_json()?;
        let original_report = IdentityFailureReport {
            root_seed: encode_seed(self.original_failure.root_seed),
            evidence: self.original_failure.evidence.clone(),
            report: self.original_failure.report.clone(),
        };
        let minimized_report = IdentityFailureReport {
            root_seed: encode_seed(self.minimized_failure.root_seed),
            evidence: self.minimized_failure.evidence.clone(),
            report: self.minimized_failure.report.clone(),
        };
        let manifest = self
            .manifest
            .to_canonical_json()
            .map_err(|error| IdentityCorpusError::Encoding(error.to_string()))?;
        let mut files = BTreeMap::new();
        for (name, bytes) in [
            ("manifest.json", manifest),
            ("scenario.json", scenario.clone()),
            ("failure-original.json", self.original.to_canonical_json()?),
            ("failure-minimized.json", scenario),
            (
                "failure-signature.json",
                canonical_json(&self.minimized.signature)?,
            ),
            ("failure-minimization.json", canonical_json(self.minimized)?),
            (
                "failure-confirmation.json",
                canonical_json(self.confirmation)?,
            ),
            (
                "identity-failure-original-report.json",
                canonical_json(&original_report)?,
            ),
            (
                "identity-failure-report.json",
                canonical_json(&minimized_report)?,
            ),
            (
                "trace-original.raw.jsonl",
                raw_trace_bytes(&self.original_failure.trace)?,
            ),
            (
                "trace-original.jsonl",
                normalized_trace_bytes(&self.original_failure.trace)?,
            ),
            (
                "trace.raw.jsonl",
                raw_trace_bytes(&self.minimized_failure.trace)?,
            ),
            (
                "trace.jsonl",
                normalized_trace_bytes(&self.minimized_failure.trace)?,
            ),
        ] {
            write_indexed(store, &mut files, name, &bytes)?;
        }
        let index = IdentityFailureArtifactIndex {
            schema_version: IDENTITY_FAILURE_ARTIFACT_SCHEMA_VERSION,
            files,
        };
        store
            .write_atomic("failure-artifacts.json", &canonical_json(&index)?)
            .map_err(|error| IdentityCorpusError::Artifact(error.to_string()))?;
        Ok(index)
    }

    fn validate_binding(&self) -> Result<(), IdentityCorpusError> {
        self.manifest
            .validate()
            .map_err(|error| IdentityCorpusError::Manifest(error.to_string()))?;
        self.minimized.signature.validate()?;
        let minimized_bytes = self.minimized.scenario.to_canonical_json()?;
        if self.original.id() != self.minimized.scenario.id()
            || self.original_failure.report.scenario_id != self.original.id()
            || self.minimized_failure.report.scenario_id != self.minimized.scenario.id()
            || self.manifest.scenario_id != self.minimized.scenario.id()
            || self.manifest.scenario_hash != digest(&minimized_bytes)
            || self.manifest.root_seed != encode_seed(self.original_failure.root_seed)
            || self.manifest.root_seed != encode_seed(self.minimized_failure.root_seed)
            || self.original_failure.signature()? != self.minimized.signature
            || self.minimized_failure.signature()? != self.minimized.signature
            || self.confirmation.signature != self.minimized.signature
            || self.confirmation.root_seed != self.manifest.root_seed
            || self.confirmation.original_scenario_digest
                != digest(&self.original.to_canonical_json()?)
            || self.confirmation.minimized_scenario_digest != digest(&minimized_bytes)
            || self.confirmation.original_report_digest
                != digest(&canonical_json(&self.original_failure.report)?)
            || self.confirmation.original_raw_trace_digest
                != digest(&raw_trace_bytes(&self.original_failure.trace)?)
            || self.confirmation.original_normalized_trace_digest
                != digest(&normalized_trace_bytes(&self.original_failure.trace)?)
            || self.confirmation.minimized_report_digest
                != digest(&canonical_json(&self.minimized_failure.report)?)
            || self.confirmation.minimized_raw_trace_digest
                != digest(&raw_trace_bytes(&self.minimized_failure.trace)?)
            || self.confirmation.minimized_normalized_trace_digest
                != digest(&normalized_trace_bytes(&self.minimized_failure.trace)?)
            || self.confirmation.original_confirmations != 2
            || self.confirmation.minimized_confirmations != 2
            || self.minimized.attempts.iter().any(|attempt| {
                attempt.accepted
                    && attempt.observed_signature.as_ref() != Some(&self.minimized.signature)
            })
        {
            return Err(IdentityCorpusError::ArtifactBindingMismatch);
        }
        Ok(())
    }
}

/// Verifies the exact committed file set and every immutable artifact digest.
pub fn verify_identity_failure_artifacts(
    root: &Path,
) -> Result<IdentityFailureArtifactIndex, IdentityCorpusError> {
    let index_bytes = read_file(root.join("failure-artifacts.json"))?;
    let index: IdentityFailureArtifactIndex = serde_json::from_slice(&index_bytes)
        .map_err(|error| IdentityCorpusError::Encoding(error.to_string()))?;
    if index.schema_version != IDENTITY_FAILURE_ARTIFACT_SCHEMA_VERSION {
        return Err(IdentityCorpusError::InvalidArtifactIndex);
    }
    let required = BTreeSet::from([
        "failure-confirmation.json".to_owned(),
        "failure-minimization.json".to_owned(),
        "failure-minimized.json".to_owned(),
        "failure-original.json".to_owned(),
        "failure-signature.json".to_owned(),
        "identity-failure-original-report.json".to_owned(),
        "identity-failure-report.json".to_owned(),
        "manifest.json".to_owned(),
        "scenario.json".to_owned(),
        "trace-original.jsonl".to_owned(),
        "trace-original.raw.jsonl".to_owned(),
        "trace.jsonl".to_owned(),
        "trace.raw.jsonl".to_owned(),
    ]);
    if index.files.len() != required.len()
        || !index.files.keys().all(|name| required.contains(name))
    {
        return Err(IdentityCorpusError::InvalidArtifactIndex);
    }
    let mut actual = collect_files(root)?;
    if !actual.remove("failure-artifacts.json") || actual != required {
        return Err(IdentityCorpusError::UnenumeratedFiles);
    }
    for (name, expected) in &index.files {
        if !valid_digest(expected) || digest(&read_file(root.join(name))?) != *expected {
            return Err(IdentityCorpusError::ArtifactDigestMismatch(name.clone()));
        }
    }
    Ok(index)
}

/// Writes an unreviewed, replay-confirmed candidate for explicit human corpus promotion.
pub fn write_identity_promotion_candidate(
    failure_root: &Path,
    store: &ArtifactStore,
    issue: impl Into<String>,
) -> Result<IdentityCorpusEntry, IdentityCorpusError> {
    let issue = issue.into();
    let index = verify_identity_failure_artifacts(failure_root)?;
    let manifest = RunManifest::from_json(&read_file(failure_root.join("manifest.json"))?)
        .map_err(|error| IdentityCorpusError::Manifest(error.to_string()))?;
    let scenario = IdentityScenario::from_json(&read_file(failure_root.join("scenario.json"))?)?;
    let signature = IdentityFailureSignature::from_json(&read_file(
        failure_root.join("failure-signature.json"),
    )?)?;
    let promotion = IdentityCorpusPromotionEvidence {
        artifact_index_digest: digest(&canonical_json(&index)?),
        source_revision: manifest.source.revision.clone(),
        issue,
        replay_confirmed: true,
        signature_preserving: true,
    };
    if !promotion.is_valid()
        || manifest.scenario_id != scenario.id()
        || manifest.scenario_hash != digest(&scenario.to_canonical_json()?)
    {
        return Err(IdentityCorpusError::ArtifactBindingMismatch);
    }
    let entry = IdentityCorpusEntry {
        id: scenario.id().to_owned(),
        scenario_file: "scenario.json".to_owned(),
        seed: manifest.root_seed,
        expectation: IdentityCorpusExpectation::ExpectedFailure { signature },
        promotion: Some(promotion),
        reviewed: false,
    };
    store
        .write_atomic("scenario.json", &scenario.to_canonical_json()?)
        .map_err(|error| IdentityCorpusError::Artifact(error.to_string()))?;
    store
        .write_atomic("entry.json", &canonical_json(&entry)?)
        .map_err(|error| IdentityCorpusError::Artifact(error.to_string()))?;
    Ok(entry)
}

fn write_indexed(
    store: &ArtifactStore,
    files: &mut BTreeMap<String, String>,
    name: &str,
    bytes: &[u8],
) -> Result<(), IdentityCorpusError> {
    store
        .write_atomic(name, bytes)
        .map_err(|error| IdentityCorpusError::Artifact(error.to_string()))?;
    files.insert(name.to_owned(), digest(bytes));
    Ok(())
}

fn require_exact_failed_run_pair(
    first: &IdentityFailedRunRecord,
    second: &IdentityFailedRunRecord,
) -> Result<(), IdentityCorpusError> {
    if first != second || first.signature()? != second.signature()? {
        return Err(IdentityCorpusError::ConfirmationMismatch);
    }
    Ok(())
}

fn canonical_json(value: &(impl Serialize + ?Sized)) -> Result<Vec<u8>, IdentityCorpusError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| IdentityCorpusError::Encoding(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn raw_trace_bytes(trace: &[TraceEvent]) -> Result<Vec<u8>, IdentityCorpusError> {
    let mut bytes = Vec::new();
    for event in trace {
        bytes.extend(
            serde_json::to_vec(event)
                .map_err(|error| IdentityCorpusError::Encoding(error.to_string()))?,
        );
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn normalized_trace_bytes(trace: &[TraceEvent]) -> Result<Vec<u8>, IdentityCorpusError> {
    let mut bytes = Vec::new();
    for event in trace {
        bytes.extend(
            normalized_trace_json(event)
                .map_err(|error| IdentityCorpusError::Encoding(error.to_string()))?,
        );
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> String {
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

fn collect_files(root: &Path) -> Result<BTreeSet<String>, IdentityCorpusError> {
    let mut files = BTreeSet::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() || files.len() > MAX_IDENTITY_CORPUS_ENTRIES {
            return Err(IdentityCorpusError::UnenumeratedFiles);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| IdentityCorpusError::UnenumeratedFiles)?;
        files.insert(name);
    }
    Ok(files)
}

fn valid_filename(value: &str) -> bool {
    let path = PathBuf::from(value);
    let mut components = path.components();
    matches!(components.next(), Some(Component::Normal(_)))
        && components.next().is_none()
        && value.ends_with(".json")
        && value != "manifest.json"
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_revision(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_seed(value: &str) -> Result<[u8; 32], ()> {
    if value.len() != 64 {
        return Err(());
    }
    let mut seed = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = nibble(pair[0]).ok_or(())?;
        let low = nibble(pair[1]).ok_or(())?;
        seed[index] = high
            .checked_mul(16)
            .and_then(|high| high.checked_add(low))
            .ok_or(())?;
    }
    Ok(seed)
}

const fn nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

/// Strict corpus, reduction, or failure-persistence error.
#[derive(Debug, thiserror::Error)]
pub enum IdentityCorpusError {
    #[error("identity corpus I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("identity corpus encoding failed: {0}")]
    Encoding(String),
    #[error("identity corpus manifest is invalid")]
    InvalidManifest,
    #[error("identity corpus entry {0} is invalid or unreviewed")]
    InvalidEntry(String),
    #[error("identity corpus seed for {0} is invalid or duplicated")]
    InvalidSeed(String),
    #[error("identity corpus entry {metadata} names scenario {scenario}")]
    IdMismatch { metadata: String, scenario: String },
    #[error("identity corpus contains an undeclared or missing file")]
    UnenumeratedFiles,
    #[error("identity corpus does not cover the complete Lane A matrix: {0:?}")]
    IncompleteCoverage(IdentityCoverage),
    #[error("identity corpus invariant counters are incomplete for {0}")]
    InvariantAccounting(String),
    #[error("identity corpus terminal did not match the reviewed expectation for {0}")]
    TerminalMismatch(String),
    /// A corpus entry reached an expected-rejection terminal not represented by corpus metadata.
    #[error("identity corpus entry {0} reached an undeclared expected model rejection")]
    UnexpectedExpectedRejection(String),
    #[error("identity failure signature is invalid")]
    InvalidSignature,
    #[error("identity minimization budget is invalid")]
    InvalidMinimizationBudget,
    #[error("identity minimizer input does not reproduce the exact signature")]
    InputSignatureMismatch,
    #[error("identity minimizer evaluator failed: {0}")]
    Evaluator(String),
    #[error("identity minimizer arithmetic overflow")]
    ArithmeticOverflow,
    #[error("identity failure artifact write failed: {0}")]
    Artifact(String),
    #[error("identity failure manifest is invalid: {0}")]
    Manifest(String),
    #[error("identity failure confirmations are not byte exact")]
    ConfirmationMismatch,
    #[error("identity failure artifact binding is inconsistent")]
    ArtifactBindingMismatch,
    #[error("identity failure artifact index is invalid")]
    InvalidArtifactIndex,
    #[error("identity failure artifact digest mismatch for {0}")]
    ArtifactDigestMismatch(String),
    #[error(transparent)]
    Scenario(#[from] IdentityScenarioError),
}
