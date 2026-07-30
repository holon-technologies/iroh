//! Strict engineering-service policy for deterministic simulation tiers.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    CryptoMode, DeterminismGrade, MANIFEST_SCHEMA_VERSION, SCENARIO_SCHEMA_VERSION,
    TraceComparisonMode,
};

pub const OPERATIONS_POLICY_SCHEMA_VERSION: u16 = 7;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationsPolicy {
    pub schema_version: u16,
    pub owner: String,
    pub failure_triage_slo_hours: u16,
    pub automation: AutomationPolicy,
    pub gate_runtime_slo: GateRuntimeSloPolicy,
    pub tiers: Vec<SimulationTierPolicy>,
    pub daily_soak: DailySoakPolicy,
    pub replay: ReplayPolicy,
    pub corpus: CorpusPolicy,
    pub release: ReleasePolicy,
    pub swarm: SwarmPolicy,
    pub parity: ParityPolicy,
}

/// Cross-workflow rules that prevent retries or status propagation from hiding evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationPolicy {
    pub maximum_retry_attempts: u8,
    pub shutdown_on_timeout: bool,
    pub publish_evidence_before_status: bool,
}

/// Bounded hosted-history audit for pull-request and main simulation wall time.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GateRuntimeSloPolicy {
    pub workflow: String,
    pub sample_size: usize,
    pub percentile: u8,
    pub pull_request_maximum_minutes: u16,
    pub main_maximum_minutes: u16,
    pub maximum_candidate_runs_per_tier: usize,
    pub maximum_jobs_per_run: usize,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulationTier {
    PullRequest,
    Main,
    Nightly,
    Weekly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SimulationTierPolicy {
    pub tier: SimulationTier,
    pub maximum_campaign_runs: u64,
    pub maximum_wall_minutes: u16,
    pub workers: usize,
    pub artifact_retention_days: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DailySoakPolicy {
    pub runner: String,
    pub workflow_concurrency: u8,
    pub epochs: u8,
    pub epoch_wall_minutes: u16,
    pub maximum_total_wall_minutes: u16,
    pub fresh_process_per_epoch: bool,
    pub lanes: usize,
    pub workers: usize,
    pub batch_runs: u64,
    pub maximum_total_runs: u64,
    pub maximum_failure_artifacts: u16,
    pub maximum_artifact_bytes: u64,
    pub artifact_retention_days: u16,
    pub retain_success_traces: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayPolicy {
    pub exact_source_required: bool,
    pub manifest_schema: u16,
    pub scenario_schema: u16,
    pub trace_schema: u16,
    pub compatibility_window_days: u16,
    pub accepted_new_run_grades: Vec<DeterminismGrade>,
    pub crypto_modes: Vec<CryptoMode>,
    pub trace_comparison_modes: Vec<TraceComparisonMode>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusPolicy {
    pub review_required: bool,
    pub provenance_required: bool,
    pub issue_required_for_failures: bool,
    pub metadata_schema: u16,
    pub typed_promotion_evidence_required: bool,
    pub reopen_invalid_closure: bool,
    pub required_closure_checks: Vec<String>,
    pub maximum_pending_days: u16,
}

/// Bounded evidence queried before any release build or publication work begins.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePolicy {
    pub required_same_revision_checks: Vec<String>,
    pub maximum_open_product_failures: usize,
    pub parity_workflow: String,
    pub maximum_parity_age_hours: u16,
    pub maximum_check_runs: usize,
    pub maximum_issue_results: usize,
    pub maximum_parity_runs: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmPolicy {
    pub schema: u16,
    pub maximum_choices: usize,
    pub maximum_options_per_choice: usize,
    pub pull_request_runs: u64,
    pub nightly_runs: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ParityPolicy {
    pub fixture_schema: u16,
    pub maximum_evidence_age_hours: u16,
    pub skips_fail_strict_comparison: bool,
}

impl OperationsPolicy {
    pub fn from_json(bytes: &[u8]) -> Result<Self, OperationsPolicyError> {
        let policy: Self = serde_json::from_slice(bytes)
            .map_err(|error| OperationsPolicyError::Json(error.to_string()))?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn to_canonical_json(&self) -> Result<Vec<u8>, OperationsPolicyError> {
        self.validate()?;
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| OperationsPolicyError::Json(error.to_string()))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn validate(&self) -> Result<(), OperationsPolicyError> {
        if self.schema_version != OPERATIONS_POLICY_SCHEMA_VERSION {
            return Err(OperationsPolicyError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        if self.owner.trim().is_empty()
            || self.failure_triage_slo_hours == 0
            || self.failure_triage_slo_hours > 168
        {
            return Err(OperationsPolicyError::InvalidServiceIdentity);
        }
        if self.automation.maximum_retry_attempts != 0
            || !self.automation.shutdown_on_timeout
            || !self.automation.publish_evidence_before_status
        {
            return Err(OperationsPolicyError::UnsafeAutomationPolicy);
        }
        if self.gate_runtime_slo.workflow != "ci.yml"
            || self.gate_runtime_slo.sample_size != 20
            || self.gate_runtime_slo.percentile != 95
            || self.gate_runtime_slo.pull_request_maximum_minutes != 15
            || self.gate_runtime_slo.main_maximum_minutes != 30
            || self.gate_runtime_slo.maximum_candidate_runs_per_tier != 40
            || self.gate_runtime_slo.maximum_jobs_per_run != 100
        {
            return Err(OperationsPolicyError::UnsafeGateRuntimeSloPolicy);
        }
        let expected = [
            SimulationTier::PullRequest,
            SimulationTier::Main,
            SimulationTier::Nightly,
            SimulationTier::Weekly,
        ];
        if self.tiers.len() != expected.len()
            || self.tiers.iter().map(|tier| tier.tier).ne(expected)
        {
            return Err(OperationsPolicyError::NonCanonicalTiers);
        }
        let mut previous_runs = 0;
        for tier in &self.tiers {
            if tier.maximum_campaign_runs == 0
                || tier.maximum_campaign_runs < previous_runs
                || tier.maximum_wall_minutes == 0
                || tier.workers == 0
                || tier.artifact_retention_days == 0
            {
                return Err(OperationsPolicyError::InvalidTier(tier.tier));
            }
            previous_runs = tier.maximum_campaign_runs;
        }
        if self.daily_soak.runner != "ubuntu-latest"
            || self.daily_soak.workflow_concurrency != 1
            || self.daily_soak.epochs != 8
            || self.daily_soak.epoch_wall_minutes != 30
            || self.daily_soak.maximum_total_wall_minutes != 240
            || !self.daily_soak.fresh_process_per_epoch
            || self.daily_soak.lanes != 12
            || self.daily_soak.workers != 4
            || self.daily_soak.batch_runs != 64
            || self.daily_soak.maximum_total_runs != 1_000_000
            || self.daily_soak.maximum_failure_artifacts != 16
            || self.daily_soak.maximum_artifact_bytes != 256 * 1_024 * 1_024
            || self.daily_soak.artifact_retention_days != 14
            || self.daily_soak.retain_success_traces
        {
            return Err(OperationsPolicyError::UnsafeDailySoakPolicy);
        }
        if !self.replay.exact_source_required
            || self.replay.manifest_schema != MANIFEST_SCHEMA_VERSION
            || self.replay.scenario_schema != SCENARIO_SCHEMA_VERSION
            || self.replay.trace_schema != krikos_runtime::TRACE_SCHEMA_VERSION
            || self.replay.compatibility_window_days == 0
            || self.replay.accepted_new_run_grades
                != [
                    DeterminismGrade::FullyDeterministic,
                    DeterminismGrade::SemanticallyDeterministic,
                ]
            || self.replay.crypto_modes
                != [
                    CryptoMode::DeterministicTest,
                    CryptoMode::ProductionProvider,
                ]
            || self.replay.trace_comparison_modes
                != [TraceComparisonMode::Raw, TraceComparisonMode::Semantic]
        {
            return Err(OperationsPolicyError::UnsafeReplayPolicy);
        }
        if !self.corpus.review_required
            || !self.corpus.provenance_required
            || !self.corpus.issue_required_for_failures
            || self.corpus.metadata_schema != crate::CORPUS_SCHEMA_VERSION
            || !self.corpus.typed_promotion_evidence_required
            || !self.corpus.reopen_invalid_closure
            || self.corpus.required_closure_checks
                != [
                    "Deterministic simulation change gate",
                    "Deterministic simulation contracts and corpus",
                ]
            || self.corpus.maximum_pending_days == 0
        {
            return Err(OperationsPolicyError::UnsafeCorpusPolicy);
        }
        if self.release.required_same_revision_checks
            != [
                "Deterministic simulation change gate",
                "Deterministic simulation contracts and corpus",
                "netsim-release / Netsim",
            ]
            || self.release.maximum_open_product_failures != 0
            || self.release.parity_workflow != "patchbay-hosted-smoke.yml"
            || self.release.maximum_parity_age_hours != self.parity.maximum_evidence_age_hours
            || self.release.maximum_check_runs != 100
            || self.release.maximum_issue_results != 100
            || self.release.maximum_parity_runs != 8
        {
            return Err(OperationsPolicyError::UnsafeReleasePolicy);
        }
        if self.swarm.schema != crate::SWARM_SCHEMA_VERSION
            || self.swarm.maximum_choices == 0
            || self.swarm.maximum_choices > 128
            || self.swarm.maximum_options_per_choice == 0
            || self.swarm.maximum_options_per_choice > 128
            || self.swarm.pull_request_runs == 0
            || self.swarm.nightly_runs < self.swarm.pull_request_runs
            || self.swarm.nightly_runs > self.tiers[2].maximum_campaign_runs
        {
            return Err(OperationsPolicyError::UnsafeSwarmPolicy);
        }
        if self.parity.fixture_schema != crate::PARITY_FIXTURE_SCHEMA_VERSION
            || self.parity.maximum_evidence_age_hours == 0
            || self.parity.maximum_evidence_age_hours > 31 * 24
            || !self.parity.skips_fail_strict_comparison
        {
            return Err(OperationsPolicyError::UnsafeParityPolicy);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationsPolicyError {
    Json(String),
    UnsupportedSchema(u16),
    InvalidServiceIdentity,
    UnsafeAutomationPolicy,
    UnsafeGateRuntimeSloPolicy,
    NonCanonicalTiers,
    InvalidTier(SimulationTier),
    UnsafeReplayPolicy,
    UnsafeCorpusPolicy,
    UnsafeReleasePolicy,
    UnsafeSwarmPolicy,
    UnsafeParityPolicy,
    UnsafeDailySoakPolicy,
}

impl fmt::Display for OperationsPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for OperationsPolicyError {}
