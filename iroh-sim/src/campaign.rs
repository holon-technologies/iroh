//! Bounded deterministic seed campaigns with batch-stable parallel execution.

use std::{collections::BTreeMap, fmt, panic::AssertUnwindSafe, thread};

use serde::{Deserialize, Serialize};

use crate::{FailureSignature, Scenario, ScenarioInventory};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignConfig {
    pub seed_start: u64,
    pub seed_end_exclusive: u64,
    pub jobs: usize,
    pub fail_fast: bool,
    pub max_runs: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "terminal", rename_all = "snake_case")]
pub enum CampaignTerminal {
    Success,
    Failure(FailureSignature),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignRunResult {
    pub seed: u64,
    pub terminal: Option<CampaignTerminal>,
    pub error: Option<String>,
    pub worker_panic: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UniqueCampaignFailure {
    pub signature: FailureSignature,
    pub first_seed: u64,
    pub occurrences: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignSummary {
    pub config: CampaignConfig,
    pub template_inventory: ScenarioInventory,
    pub results: Vec<CampaignRunResult>,
    pub unique_failures: Vec<UniqueCampaignFailure>,
    pub stopped_early: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct CampaignRunner;

impl CampaignRunner {
    /// Runs fixed-size seed batches; batch boundaries make fail-fast deterministic.
    pub fn run<F>(
        config: CampaignConfig,
        scenario: &Scenario,
        executor: &F,
    ) -> Result<CampaignSummary, CampaignError>
    where
        F: Fn(u64, &Scenario) -> Result<CampaignTerminal, String> + Sync,
    {
        if config.seed_start >= config.seed_end_exclusive {
            return Err(CampaignError::InvalidRange);
        }
        if config.jobs == 0 {
            return Err(CampaignError::ZeroJobs);
        }
        let runs = config.seed_end_exclusive - config.seed_start;
        if runs > config.max_runs || config.max_runs == 0 {
            return Err(CampaignError::RunBudget {
                requested: runs,
                maximum: config.max_runs,
            });
        }
        let jobs = config.jobs.min(runs as usize);
        let mut results = Vec::with_capacity(runs as usize);
        let mut next = config.seed_start;
        let mut stopped_early = false;
        while next < config.seed_end_exclusive {
            let end = next
                .saturating_add(jobs as u64)
                .min(config.seed_end_exclusive);
            let batch = thread::scope(|scope| {
                let handles = (next..end)
                    .map(|seed| {
                        scope.spawn(move || {
                            match std::panic::catch_unwind(AssertUnwindSafe(|| {
                                executor(seed, scenario)
                            })) {
                                Ok(Ok(terminal)) => CampaignRunResult {
                                    seed,
                                    terminal: Some(terminal),
                                    error: None,
                                    worker_panic: false,
                                },
                                Ok(Err(error)) => CampaignRunResult {
                                    seed,
                                    terminal: None,
                                    error: Some(error),
                                    worker_panic: false,
                                },
                                Err(_) => CampaignRunResult {
                                    seed,
                                    terminal: None,
                                    error: Some("worker panic".to_owned()),
                                    worker_panic: true,
                                },
                            }
                        })
                    })
                    .collect::<Vec<_>>();
                handles
                    .into_iter()
                    .map(|handle| handle.join().expect("worker panic is caught"))
                    .collect::<Vec<_>>()
            });
            let batch_failed = batch.iter().any(|result| {
                result.error.is_some()
                    || matches!(result.terminal, Some(CampaignTerminal::Failure(_)))
            });
            results.extend(batch);
            next = end;
            if config.fail_fast && batch_failed && next < config.seed_end_exclusive {
                stopped_early = true;
                break;
            }
        }
        let mut unique = BTreeMap::<String, UniqueCampaignFailure>::new();
        for result in &results {
            let Some(CampaignTerminal::Failure(signature)) = &result.terminal else {
                continue;
            };
            let key = blake3::hash(
                &signature
                    .to_canonical_json()
                    .map_err(|error| CampaignError::Encoding(error.to_string()))?,
            )
            .to_hex()
            .to_string();
            let failure = unique.entry(key).or_insert_with(|| UniqueCampaignFailure {
                signature: signature.clone(),
                first_seed: result.seed,
                occurrences: 0,
            });
            failure.occurrences = failure
                .occurrences
                .checked_add(1)
                .ok_or(CampaignError::OccurrenceOverflow)?;
        }
        Ok(CampaignSummary {
            config,
            template_inventory: ScenarioInventory::from_scenario(scenario),
            results,
            unique_failures: unique.into_values().collect(),
            stopped_early,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CampaignError {
    InvalidRange,
    ZeroJobs,
    RunBudget { requested: u64, maximum: u64 },
    OccurrenceOverflow,
    Encoding(String),
}

impl fmt::Display for CampaignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CampaignError {}
