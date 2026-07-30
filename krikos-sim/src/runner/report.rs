use super::*;

/// Stable terminal class for a completed declarative run.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerTerminal {
    Success,
    ExpectedFailure,
}

/// Canonical terminal report used by replay, minimization, and cross-backend comparison.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioReport {
    pub scenario_id: String,
    pub terminal: RunnerTerminal,
    pub actions_completed: u64,
    pub virtual_time_nanos: u64,
    pub observations: Vec<Observation>,
    pub invariants: InvariantSnapshot,
    pub model: ReferenceModelSnapshot,
    pub resources: ResourceLedgerSnapshot,
    #[serde(default)]
    pub scheduler: Option<KernelSchedulerSnapshot>,
    #[serde(default)]
    pub tasks: Vec<KernelTaskSnapshot>,
}

/// Diagnostic state retained when a run reaches a typed failure terminal.
#[derive(Debug)]
pub struct ScenarioFailureReport {
    pub error: RunnerError,
    pub virtual_time_nanos: u64,
    pub observations: Vec<Observation>,
    pub invariants: InvariantSnapshot,
    pub model: ReferenceModelSnapshot,
    pub resources: ResourceLedgerSnapshot,
    pub scheduler: Option<KernelSchedulerSnapshot>,
    pub tasks: Vec<KernelTaskSnapshot>,
}

impl ScenarioFailureReport {
    /// Discards diagnostics and returns the original typed runner failure.
    pub fn into_error(self) -> RunnerError {
        self.error
    }
}
