//! Bounded deterministic soak scheduling and progress accounting.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    CampaignConfig, CampaignError, CampaignRunner, CampaignTerminal, FailureSignature, Scenario,
};

/// Current soak-summary schema.
pub const SOAK_SCHEMA_VERSION: u16 = 2;
/// Longest supported wall budget, kept below GitHub's six-hour job limit.
pub const MAX_SOAK_WALL_MILLIS: u64 = 6 * 60 * 60 * 1_000;
/// Maximum parallel workers in one soak process.
pub const MAX_SOAK_JOBS: usize = 64;
/// Maximum scenarios dispatched between deadline checks and checkpoints.
pub const MAX_SOAK_BATCH_RUNS: u64 = 4_096;
/// Maximum scenarios executed by one soak process.
pub const MAX_SOAK_RUNS: u64 = 1_000_000;
/// Maximum independently rotating scenario lanes.
pub const MAX_SOAK_LANES: usize = 32;
/// Number of fresh processes in one daily seed window.
pub const SOAK_EPOCHS_PER_WINDOW: u8 = 8;

/// Cryptography provider selected by one strict plan lane.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SoakCryptoLane {
    DeterministicTest,
    ProductionProvider,
}

/// One immutable plan lane.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SoakPlanLane {
    pub id: String,
    pub swarm: PathBuf,
    pub swarm_blake3: String,
    pub crypto: SoakCryptoLane,
}

/// Strict, versioned collection of deterministic soak lanes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SoakPlan {
    pub schema_version: u16,
    pub id: String,
    pub coverage_policy: PathBuf,
    pub coverage_policy_blake3: String,
    pub lanes: Vec<SoakPlanLane>,
}

impl SoakPlan {
    pub fn from_json(bytes: &[u8]) -> Result<Self, SoakPlanError> {
        let plan: Self = serde_json::from_slice(bytes)
            .map_err(|error| SoakPlanError::Encoding(error.to_string()))?;
        plan.validate()?;
        Ok(plan)
    }

    fn validate(&self) -> Result<(), SoakPlanError> {
        if self.schema_version != SOAK_SCHEMA_VERSION {
            return Err(SoakPlanError::UnsupportedSchema(self.schema_version));
        }
        if self.id.is_empty() || self.id.len() > 128 {
            return Err(SoakPlanError::InvalidPlanId);
        }
        if !is_workspace_relative_path(&self.coverage_policy) {
            return Err(SoakPlanError::InvalidCoveragePolicyPath(
                self.coverage_policy.clone(),
            ));
        }
        if !is_lower_hex_digest(&self.coverage_policy_blake3) {
            return Err(SoakPlanError::InvalidCoveragePolicyDigest);
        }
        if self.lanes.is_empty() || self.lanes.len() > MAX_SOAK_LANES {
            return Err(SoakPlanError::InvalidLaneCount(self.lanes.len()));
        }
        if self
            .lanes
            .windows(2)
            .any(|lanes| lanes[0].id >= lanes[1].id)
        {
            return Err(SoakPlanError::NonCanonicalLaneOrder);
        }

        let mut lane_ids = BTreeSet::new();
        let mut lane_inputs = BTreeSet::new();
        for lane in &self.lanes {
            if lane.id.is_empty() || lane.id.len() > 128 {
                return Err(SoakPlanError::InvalidLaneId(lane.id.clone()));
            }
            if !lane_ids.insert(&lane.id) {
                return Err(SoakPlanError::DuplicateLaneId(lane.id.clone()));
            }
            if !is_workspace_relative_path(&lane.swarm) {
                return Err(SoakPlanError::InvalidSwarmPath(lane.swarm.clone()));
            }
            if !is_lower_hex_digest(&lane.swarm_blake3) {
                return Err(SoakPlanError::InvalidSwarmDigest(lane.id.clone()));
            }
            if !lane_inputs.insert((&lane.swarm, lane.crypto)) {
                return Err(SoakPlanError::DuplicateLaneInput(lane.id.clone()));
            }
        }
        Ok(())
    }
}

fn is_workspace_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Reserves a non-overlapping one-million-seed lane window.
pub fn derive_soak_seed_start(
    seed_window: u64,
    epoch: u8,
    lane_index: usize,
) -> Result<u64, SoakPlanError> {
    if epoch >= SOAK_EPOCHS_PER_WINDOW {
        return Err(SoakPlanError::InvalidEpoch(epoch));
    }
    if lane_index >= MAX_SOAK_LANES {
        return Err(SoakPlanError::InvalidLaneIndex(lane_index));
    }
    let lane_index =
        u64::try_from(lane_index).map_err(|_| SoakPlanError::InvalidLaneIndex(lane_index))?;
    let lane_count = u64::try_from(MAX_SOAK_LANES).expect("the hard lane bound always fits in u64");
    seed_window
        .checked_mul(u64::from(SOAK_EPOCHS_PER_WINDOW))
        .and_then(|value| value.checked_add(u64::from(epoch)))
        .and_then(|value| value.checked_mul(lane_count))
        .and_then(|value| value.checked_add(lane_index))
        .and_then(|value| value.checked_mul(MAX_SOAK_RUNS))
        .ok_or(SoakPlanError::SeedWindowOverflow)
}

/// One immutable half-open seed reservation for a policy revision and soak lane.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SeedLease {
    pub schema_version: u16,
    pub policy_blake3: String,
    pub plan_blake3: String,
    pub lane_id: String,
    pub seed_window: u64,
    pub epoch: u8,
    pub lane_index: usize,
    pub seed_start: u64,
    pub seed_end_exclusive: u64,
    pub consumed_runs: u64,
}

impl SeedLease {
    /// Reserves the complete hard-bounded lane block, independent of a run's smaller work budget.
    pub fn reserve(
        policy_blake3: &str,
        plan_blake3: &str,
        lane_id: &str,
        seed_window: u64,
        epoch: u8,
        lane_index: usize,
    ) -> Result<Self, SeedLeaseError> {
        if !is_lower_hex_digest(policy_blake3) {
            return Err(SeedLeaseError::InvalidPolicyDigest);
        }
        if !is_lower_hex_digest(plan_blake3) {
            return Err(SeedLeaseError::InvalidPlanDigest);
        }
        if lane_id.is_empty() || lane_id.len() > 128 {
            return Err(SeedLeaseError::InvalidLaneId);
        }
        let seed_start =
            derive_soak_seed_start(seed_window, epoch, lane_index).map_err(SeedLeaseError::Plan)?;
        let seed_end_exclusive = seed_start
            .checked_add(MAX_SOAK_RUNS)
            .ok_or(SeedLeaseError::RangeOverflow)?;
        Ok(Self {
            schema_version: SOAK_SCHEMA_VERSION,
            policy_blake3: policy_blake3.to_owned(),
            plan_blake3: plan_blake3.to_owned(),
            lane_id: lane_id.to_owned(),
            seed_window,
            epoch,
            lane_index,
            seed_start,
            seed_end_exclusive,
            consumed_runs: 0,
        })
    }

    /// Records actual consumption while preserving the immutable reservation.
    pub fn with_consumed_runs(mut self, consumed_runs: u64) -> Result<Self, SeedLeaseError> {
        let reserved = self
            .seed_end_exclusive
            .checked_sub(self.seed_start)
            .ok_or(SeedLeaseError::RangeOverflow)?;
        if consumed_runs > reserved {
            return Err(SeedLeaseError::ConsumptionExceedsReservation {
                consumed: consumed_runs,
                reserved,
            });
        }
        self.consumed_runs = consumed_runs;
        Ok(self)
    }

    /// Returns whether two leases reuse seed ordinals under the same coverage policy revision.
    pub fn overlaps(&self, other: &Self) -> bool {
        self.policy_blake3 == other.policy_blake3
            && self.seed_start < other.seed_end_exclusive
            && other.seed_start < self.seed_end_exclusive
    }
}

/// Typed seed-reservation construction and accounting failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SeedLeaseError {
    InvalidPolicyDigest,
    InvalidPlanDigest,
    InvalidLaneId,
    Plan(SoakPlanError),
    RangeOverflow,
    ConsumptionExceedsReservation { consumed: u64, reserved: u64 },
}

impl fmt::Display for SeedLeaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SeedLeaseError {}

/// Strict plan parsing and deterministic seed-window errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SoakPlanError {
    Encoding(String),
    UnsupportedSchema(u16),
    InvalidPlanId,
    InvalidCoveragePolicyPath(PathBuf),
    InvalidCoveragePolicyDigest,
    InvalidLaneCount(usize),
    NonCanonicalLaneOrder,
    InvalidLaneId(String),
    DuplicateLaneId(String),
    InvalidSwarmPath(PathBuf),
    InvalidSwarmDigest(String),
    DuplicateLaneInput(String),
    InvalidEpoch(u8),
    InvalidLaneIndex(usize),
    SeedWindowOverflow,
}

impl fmt::Display for SoakPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SoakPlanError {}

/// Validated execution limits for one fresh soak process.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SoakConfig {
    pub wall_budget_millis: u64,
    pub jobs: usize,
    pub batch_runs: u64,
    pub max_runs: u64,
}

/// One canonical scenario and its next deterministic seed.
#[derive(Clone, Debug)]
pub struct SoakLane {
    pub id: String,
    pub scenario: Scenario,
    pub seed_start: u64,
}

/// Why a completed soak process stopped.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SoakStopReason {
    Running,
    WallBudget,
    RunBudget,
}

/// Bounded counters and next replay seed for one lane.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SoakLaneSummary {
    pub id: String,
    pub next_seed: u64,
    pub completed_runs: u64,
    pub successful_runs: u64,
    pub failed_runs: u64,
    pub errored_runs: u64,
    pub worker_panics: u64,
}

/// One normalized failure class deduplicated across lanes and batches.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UniqueSoakFailure {
    pub signature: FailureSignature,
    pub first_lane_id: String,
    pub first_seed: u64,
    pub occurrences: u64,
}

/// Atomic checkpoint payload for a bounded soak process.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SoakSummary {
    pub schema_version: u16,
    pub config: SoakConfig,
    pub stop_reason: SoakStopReason,
    pub elapsed_millis: u64,
    pub completed_runs: u64,
    pub successful_runs: u64,
    pub failed_runs: u64,
    pub errored_runs: u64,
    pub worker_panics: u64,
    pub lanes: Vec<SoakLaneSummary>,
    pub unique_failures: Vec<UniqueSoakFailure>,
}

impl SoakSummary {
    fn new(config: SoakConfig, lanes: &[SoakLane], elapsed_millis: u64) -> Self {
        Self {
            schema_version: SOAK_SCHEMA_VERSION,
            config,
            stop_reason: SoakStopReason::Running,
            elapsed_millis,
            completed_runs: 0,
            successful_runs: 0,
            failed_runs: 0,
            errored_runs: 0,
            worker_panics: 0,
            lanes: lanes
                .iter()
                .map(|lane| SoakLaneSummary {
                    id: lane.id.clone(),
                    next_seed: lane.seed_start,
                    completed_runs: 0,
                    successful_runs: 0,
                    failed_runs: 0,
                    errored_runs: 0,
                    worker_panics: 0,
                })
                .collect(),
            unique_failures: Vec::new(),
        }
    }
}

/// Fixed-batch runner for deterministic, checkpointed long soaks.
#[derive(Clone, Copy, Debug)]
pub struct SoakRunner;

impl SoakRunner {
    pub fn run<E, T, C>(
        config: SoakConfig,
        lanes: Vec<SoakLane>,
        elapsed_millis: T,
        mut checkpoint: C,
        executor: E,
    ) -> Result<SoakSummary, SoakError>
    where
        E: Fn(&str, u64, &Scenario) -> Result<CampaignTerminal, String> + Sync,
        T: Fn() -> u64,
        C: FnMut(&SoakSummary) -> Result<(), String>,
    {
        validate(config, &lanes)?;

        let mut last_elapsed = elapsed_millis();
        let mut summary = SoakSummary::new(config, &lanes, last_elapsed);
        if last_elapsed >= config.wall_budget_millis {
            summary.stop_reason = SoakStopReason::WallBudget;
            return Ok(summary);
        }

        let mut unique_failures = BTreeMap::<String, UniqueSoakFailure>::new();
        let mut lane_index = 0_usize;
        loop {
            let pre_batch_elapsed = elapsed_millis();
            if pre_batch_elapsed < last_elapsed {
                return Err(SoakError::ElapsedTimeRegressed {
                    previous: last_elapsed,
                    current: pre_batch_elapsed,
                });
            }
            last_elapsed = pre_batch_elapsed;
            if pre_batch_elapsed >= config.wall_budget_millis {
                summary.stop_reason = SoakStopReason::WallBudget;
                summary.elapsed_millis = pre_batch_elapsed;
                return Ok(summary);
            }

            let remaining_runs = config
                .max_runs
                .checked_sub(summary.completed_runs)
                .ok_or(SoakError::CounterOverflow)?;
            if remaining_runs == 0 {
                summary.stop_reason = SoakStopReason::RunBudget;
                return Ok(summary);
            }
            let batch_runs = config.batch_runs.min(remaining_runs);
            let seed_start = summary.lanes[lane_index].next_seed;
            let seed_end_exclusive = seed_start
                .checked_add(batch_runs)
                .ok_or(SoakError::SeedOverflow)?;
            let lane = &lanes[lane_index];
            let campaign = CampaignRunner::run(
                CampaignConfig {
                    seed_start,
                    seed_end_exclusive,
                    jobs: config.jobs,
                    fail_fast: false,
                    max_runs: batch_runs,
                },
                &lane.scenario,
                &|seed, scenario| executor(&lane.id, seed, scenario),
            )
            .map_err(SoakError::Campaign)?;

            account_campaign(
                &mut summary,
                lane_index,
                campaign.results,
                &mut unique_failures,
            )?;
            summary.lanes[lane_index].next_seed = seed_end_exclusive;
            summary.unique_failures = unique_failures.values().cloned().collect();

            let post_batch_elapsed = elapsed_millis();
            if post_batch_elapsed < last_elapsed {
                return Err(SoakError::ElapsedTimeRegressed {
                    previous: last_elapsed,
                    current: post_batch_elapsed,
                });
            }
            last_elapsed = post_batch_elapsed;
            summary.elapsed_millis = post_batch_elapsed;
            summary.stop_reason = if summary.completed_runs >= config.max_runs {
                SoakStopReason::RunBudget
            } else if post_batch_elapsed >= config.wall_budget_millis {
                SoakStopReason::WallBudget
            } else {
                SoakStopReason::Running
            };
            checkpoint(&summary).map_err(SoakError::Checkpoint)?;
            if summary.stop_reason != SoakStopReason::Running {
                return Ok(summary);
            }
            lane_index = lane_index
                .checked_add(1)
                .ok_or(SoakError::CounterOverflow)?
                % lanes.len();
        }
    }
}

fn validate(config: SoakConfig, lanes: &[SoakLane]) -> Result<(), SoakError> {
    if config.wall_budget_millis == 0 {
        return Err(SoakError::ZeroWallBudget);
    }
    if config.wall_budget_millis > MAX_SOAK_WALL_MILLIS {
        return Err(SoakError::WallBudgetExceeded);
    }
    if config.jobs == 0 {
        return Err(SoakError::ZeroJobs);
    }
    if config.jobs > MAX_SOAK_JOBS {
        return Err(SoakError::JobBudgetExceeded);
    }
    if config.batch_runs == 0 {
        return Err(SoakError::ZeroBatchRuns);
    }
    if config.batch_runs > MAX_SOAK_BATCH_RUNS {
        return Err(SoakError::BatchBudgetExceeded);
    }
    if config.max_runs == 0 {
        return Err(SoakError::ZeroRunBudget);
    }
    if config.max_runs > MAX_SOAK_RUNS {
        return Err(SoakError::RunBudgetExceeded);
    }
    if lanes.is_empty() {
        return Err(SoakError::NoLanes);
    }
    if lanes.len() > MAX_SOAK_LANES {
        return Err(SoakError::LaneBudgetExceeded);
    }

    let mut lane_ids = BTreeMap::<&str, ()>::new();
    for lane in lanes {
        if lane.id.is_empty() || lane.id.len() > 128 {
            return Err(SoakError::InvalidLaneId(lane.id.clone()));
        }
        if lane_ids.insert(&lane.id, ()).is_some() {
            return Err(SoakError::DuplicateLane(lane.id.clone()));
        }
    }
    Ok(())
}

fn account_campaign(
    summary: &mut SoakSummary,
    lane_index: usize,
    results: Vec<crate::CampaignRunResult>,
    unique_failures: &mut BTreeMap<String, UniqueSoakFailure>,
) -> Result<(), SoakError> {
    for result in results {
        checked_increment(&mut summary.completed_runs)?;
        checked_increment(&mut summary.lanes[lane_index].completed_runs)?;
        match result.terminal {
            Some(CampaignTerminal::Success) => {
                checked_increment(&mut summary.successful_runs)?;
                checked_increment(&mut summary.lanes[lane_index].successful_runs)?;
            }
            Some(CampaignTerminal::Failure(signature)) => {
                checked_increment(&mut summary.failed_runs)?;
                checked_increment(&mut summary.lanes[lane_index].failed_runs)?;
                let key = blake3::hash(
                    &signature
                        .to_canonical_json()
                        .map_err(|error| SoakError::Encoding(error.to_string()))?,
                )
                .to_hex()
                .to_string();
                let failure = unique_failures
                    .entry(key)
                    .or_insert_with(|| UniqueSoakFailure {
                        signature,
                        first_lane_id: summary.lanes[lane_index].id.clone(),
                        first_seed: result.seed,
                        occurrences: 0,
                    });
                checked_increment(&mut failure.occurrences)?;
            }
            None => {
                checked_increment(&mut summary.errored_runs)?;
                checked_increment(&mut summary.lanes[lane_index].errored_runs)?;
                if result.worker_panic {
                    checked_increment(&mut summary.worker_panics)?;
                    checked_increment(&mut summary.lanes[lane_index].worker_panics)?;
                }
            }
        }
    }
    Ok(())
}

fn checked_increment(value: &mut u64) -> Result<(), SoakError> {
    *value = value.checked_add(1).ok_or(SoakError::CounterOverflow)?;
    Ok(())
}

/// Typed fail-closed errors for invalid soak configuration or accounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SoakError {
    ZeroWallBudget,
    WallBudgetExceeded,
    ZeroJobs,
    JobBudgetExceeded,
    ZeroBatchRuns,
    BatchBudgetExceeded,
    ZeroRunBudget,
    RunBudgetExceeded,
    NoLanes,
    LaneBudgetExceeded,
    InvalidLaneId(String),
    DuplicateLane(String),
    SeedOverflow,
    CounterOverflow,
    ElapsedTimeRegressed { previous: u64, current: u64 },
    Campaign(CampaignError),
    Encoding(String),
    Checkpoint(String),
}

impl fmt::Display for SoakError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SoakError {}
