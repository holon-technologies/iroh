//! Independent account-control model and deterministic identity simulation lane.

mod adapter;
mod corpus;
mod formal;
mod model;
mod replay;
mod scenario;

pub use adapter::{
    DifferentialCoverage, DifferentialError, DifferentialHistoryReport,
    DifferentialProductionEvidence, DifferentialSnapshot, DifferentialStep,
    run_differential_history,
};
pub use corpus::{
    IDENTITY_CORPUS_SCHEMA_VERSION, IdentityCorpus, IdentityCorpusEntry, IdentityCorpusError,
    IdentityCorpusExpectation, IdentityCorpusPromotionEvidence, IdentityCorpusReport,
    IdentityFailureArtifactBundle, IdentityFailureArtifactIndex, IdentityFailureConfirmation,
    IdentityFailureReport, IdentityFailureSignature, IdentityMinimizationAttempt,
    IdentityMinimizationResult, IdentityMinimizer, LoadedIdentityCorpusEntry,
    verify_identity_failure_artifacts, write_identity_promotion_candidate,
};
pub use formal::{
    FormalCheckError, FormalCheckReport, FormalMutation, FormalProperty, FormalPropertyEvidence,
    FormalViolation, MAX_FORMAL_STATES, MAX_FORMAL_TRANSITIONS, check_account_control_model,
    check_formal_mutation,
};
pub use model::{
    AccountControlModel, AccountModelSnapshot, ApplyDisposition, ControllerId, DeviceId,
    DeviceLifecycle, EventId, ForkResolution, IdentityEvent, IdentityOperation, MigrationState,
    ModelController, ModelError, ModelPolicy, RecoveryPlan,
};
pub use replay::{
    IdentityArtifactBundle, IdentityRejectionArtifactBundle, IdentityRejectionReport,
    IdentityReplayError, replay_identity_artifacts, replay_identity_failure_artifacts,
    replay_identity_rejection_artifacts,
};
pub use scenario::{
    ExpectedModelRejection, ForkScenarioOperation, IDENTITY_SCENARIO_SCHEMA_VERSION,
    IdentityAction, IdentityActionExpectation, IdentityCoverage, IdentityDeliveryFault,
    IdentityDeliveryReport, IdentityEnvironmentSnapshot, IdentityFailedRunRecord,
    IdentityFailureClass, IdentityFailureEvidence, IdentityRejectedRunRecord,
    IdentityRejectionClass, IdentityRejectionEvidence, IdentityReplicaSnapshot, IdentityRunOutcome,
    IdentityRunRecord, IdentityRunReport, IdentityScenario, IdentityScenarioAction,
    IdentityScenarioError, IdentityScenarioRunner, IdentityStepReport, MAX_IDENTITY_ACTIONS,
    MAX_IDENTITY_SCENARIO_BYTES, MigrationPhase, RecoveryController, Section36Counters,
    Section36Mutation,
};
