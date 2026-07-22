//! Strict engineering-service policy for deterministic simulation tiers.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    CryptoMode, DeterminismGrade, MANIFEST_SCHEMA_VERSION, SCENARIO_SCHEMA_VERSION,
    TraceComparisonMode,
};

pub const OPERATIONS_POLICY_SCHEMA_VERSION: u16 = 2;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationsPolicy {
    pub schema_version: u16,
    pub owner: String,
    pub failure_triage_slo_hours: u16,
    pub tiers: Vec<SimulationTierPolicy>,
    pub replay: ReplayPolicy,
    pub corpus: CorpusPolicy,
    pub swarm: SwarmPolicy,
    pub parity: ParityPolicy,
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
    pub maximum_pending_days: u16,
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
        if !self.replay.exact_source_required
            || self.replay.manifest_schema != MANIFEST_SCHEMA_VERSION
            || self.replay.scenario_schema != SCENARIO_SCHEMA_VERSION
            || self.replay.trace_schema != iroh_runtime::TRACE_SCHEMA_VERSION
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
            || self.corpus.maximum_pending_days == 0
        {
            return Err(OperationsPolicyError::UnsafeCorpusPolicy);
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
    NonCanonicalTiers,
    InvalidTier(SimulationTier),
    UnsafeReplayPolicy,
    UnsafeCorpusPolicy,
    UnsafeSwarmPolicy,
    UnsafeParityPolicy,
}

impl fmt::Display for OperationsPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for OperationsPolicyError {}
