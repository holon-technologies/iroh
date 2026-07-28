//! Backends, runners, campaigns, and minimization.

pub use crate::{
    backend::{
        BackendError, DeterministicBackend, DeterministicBackendConfig, EndpointEnvironmentError,
    },
    campaign::{
        CampaignConfig, CampaignError, CampaignRunResult, CampaignRunner, CampaignSummary,
        CampaignTerminal, UniqueCampaignFailure,
    },
    kernel_driver::{KernelDriver, KernelDriverError},
    minimize::{
        MinimizationAttempt, MinimizationConfig, MinimizationError, MinimizationOutcome,
        MinimizationResult, Minimizer,
    },
    runner::{
        DeterministicScenarioBackend, ReferenceModel, ReferenceModelSnapshot, RunnerError,
        RunnerTerminal, ScenarioBackend, ScenarioFailureReport, ScenarioReport, ScenarioRunner,
    },
};
