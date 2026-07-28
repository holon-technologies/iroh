//! Deterministic simulation artifacts, replay contracts, and command surface.
#![forbid(unsafe_code)]

mod artifact;
mod backend;
mod bounded_io;
mod campaign;
pub mod cli;
mod corpus;
mod coverage;
mod deterministic_crypto;
mod discovery;
mod dns;
mod failure;
mod gate;
mod invariant;
mod inventory;
mod kernel;
mod kernel_driver;
mod ledger;
mod manifest;
mod minimize;
mod monitor;
mod nat;
mod network;
mod observation;
#[path = "operations.rs"]
mod operations_policy;
mod parity;
mod parity_catalog;
mod portmap;
mod relay;
mod runner;
mod scenario;
mod scenario_model;
mod soak;
mod swarm;
mod trace;

pub mod engine;
pub mod evidence;
pub mod execution;
pub mod model;
#[path = "operations_api.rs"]
pub mod operations;

#[allow(unused_imports)]
pub(crate) use artifact::{ArtifactError, ArtifactStore, ArtifactTraceWriter};
#[allow(unused_imports)]
pub(crate) use backend::{
    BackendError, DeterministicBackend, DeterministicBackendConfig, EndpointEnvironmentError,
};
#[allow(unused_imports)]
pub(crate) use campaign::{
    CampaignConfig, CampaignError, CampaignRunResult, CampaignRunner, CampaignSummary,
    CampaignTerminal, UniqueCampaignFailure,
};
#[allow(unused_imports)]
pub(crate) use corpus::{
    CORPUS_SCHEMA_VERSION, Corpus, CorpusEntry, CorpusError, CorpusExpectation, CorpusMetadata,
    CorpusMinimizationEvidence, CorpusPromotionEvidence, CorpusReplayEvidence, CorpusReport,
    CorpusReviewState,
};
#[allow(unused_imports)]
pub(crate) use coverage::{
    BehaviorTransition, COVERAGE_POLICY_SCHEMA_VERSION, COVERAGE_REPORT_SCHEMA_VERSION,
    CoverageBucket, CoverageCombination, CoverageCount, CoverageDimensionPolicy,
    CoverageDisposition, CoverageDomainBinding, CoverageDomainPolicy, CoverageError,
    CoverageEvidence, CoverageHigherOrder, CoverageLane, CoverageLanePolicy, CoverageLedger,
    CoverageObligations, CoverageObservation, CoveragePair, CoveragePhase, CoveragePolicy,
    CoverageReport, CoverageSelection, CoverageValuePolicy, IndividualObligation, KnownCoverageGap,
    OracleCoverage, PairwiseObligation, PhaseObligation, TransitionCoverage,
};
#[allow(unused_imports)]
pub(crate) use discovery::{DeterministicDiscovery, DiscoveryError, DiscoveryRecordSnapshot};
#[allow(unused_imports)]
pub(crate) use dns::DeterministicDnsRuntime;
#[allow(unused_imports)]
pub(crate) use failure::{
    FAILURE_ARTIFACT_SCHEMA_VERSION, FAILURE_SIGNATURE_SCHEMA_VERSION, FailureArtifactBundle,
    FailureArtifactIndex, FailureError, FailureReplayError, FailureSignature,
    OPERATIONAL_OUTCOME_SCHEMA_VERSION, OperationalOutcome, OperationalOutcomeClass,
    OperationalOutcomeError, TerminalFailureClass, compare_failure_replay,
    verify_failure_artifacts,
};
#[allow(unused_imports)]
pub(crate) use gate::{
    CHANGE_IMPACT_POLICY_SCHEMA_VERSION, ChangeImpactMapping, ChangeImpactPolicy, GateDomain,
    GateError, GateSelection, GateSelectionMode, GateTierPolicy, GateWork, GateWorkKind,
    SimulationGateTier,
};
#[allow(unused_imports)]
pub(crate) use invariant::{
    InvariantClass, InvariantError, InvariantFailure, InvariantRegistry, InvariantSnapshot,
    InvariantTransition,
};
#[allow(unused_imports)]
pub(crate) use inventory::ScenarioInventory;
#[allow(unused_imports)]
pub(crate) use kernel::{
    EventClass, EventId, Kernel, KernelConfig, KernelError, KernelExecutor, KernelResourceLimits,
    KernelRun, KernelSchedulerSnapshot, KernelStep, KernelTaskSnapshot, Quiescence, ScheduledEvent,
    VirtualClock, VirtualWallClock,
};
#[allow(unused_imports)]
pub(crate) use kernel_driver::{KernelDriver, KernelDriverError};
#[allow(unused_imports)]
pub(crate) use ledger::{
    LedgerError, ResourceCount, ResourceKind, ResourceLedger, ResourceLedgerSnapshot, ResourceToken,
};
#[allow(unused_imports)]
pub(crate) use manifest::{
    BackendCapabilities, CompatibilityError, CryptoMode, DeterminismGrade, MANIFEST_SCHEMA_VERSION,
    ManifestError, ReplayIdentity, RunBudgets, RunManifest, SIMULATOR_VERSION, SourceIdentity,
    TraceComparisonMode,
};
#[allow(unused_imports)]
pub(crate) use minimize::{
    MinimizationAttempt, MinimizationConfig, MinimizationError, MinimizationOutcome,
    MinimizationResult, Minimizer,
};
#[allow(unused_imports)]
pub(crate) use monitor::StaticNetworkMonitor;
#[allow(unused_imports)]
pub(crate) use nat::{
    Firewall, FirewallAction, FirewallConfig, FirewallConnectionState, FirewallDecision,
    FirewallDirection, FirewallPacket, FirewallProtocol, FirewallRule, NatConfig, NatError,
    NatFilteringBehavior, NatInbound, NatMappingBehavior, NatMappingSnapshot, NatOutbound,
    NatPortMapping, NatTable,
};
#[allow(unused_imports)]
pub(crate) use network::{
    HostConnectivity, IpCidr, LinkConfig, NetworkConfig, NetworkError, SyntheticNetwork,
};
#[allow(unused_imports)]
pub(crate) use observation::{
    ConnectionId, ConnectionState, EndpointId, EndpointState, OBSERVATION_SCHEMA_VERSION,
    Observation, ObservationError, ObservationKind, OperationId, PacketId, PathId, PayloadDigest,
    StreamId,
};
#[allow(unused_imports)]
pub(crate) use operations_policy::{
    AutomationPolicy, CorpusPolicy, DailySoakPolicy, GateRuntimeSloPolicy,
    OPERATIONS_POLICY_SCHEMA_VERSION, OperationsPolicy, OperationsPolicyError, ParityPolicy,
    ReleasePolicy, ReplayPolicy, SimulationTier, SimulationTierPolicy, SwarmPolicy,
};
#[allow(unused_imports)]
pub(crate) use parity::{
    PARITY_FIXTURE_SCHEMA_VERSION, PATCHBAY_RECEIPT_SCHEMA_VERSION, ParityBackend,
    ParityComparison, ParityComparisonStatus, ParityError, ParityEvidence, ParityFixture,
    ParityFixtureResult, PatchbayReceipt, SemanticDimension, SemanticOutcome, SemanticTerminal,
    compare_parity_fixtures, compare_parity_fixtures_at, compare_semantic_outcomes,
    deterministic_semantic_outcome,
};
#[allow(unused_imports)]
pub(crate) use parity_catalog::{
    CanonicalParityCase, CanonicalParityScenario, canonical_patchbay_scenarios,
};
#[allow(unused_imports)]
pub(crate) use portmap::DeterministicPortMapper;
#[allow(unused_imports)]
pub(crate) use relay::{
    RelayAdmissionDecision, RelayCoverage, RelayEnvironment, RelayEnvironmentError,
    RelayRouteDecision, RelayRoutingOracle,
};
#[allow(unused_imports)]
pub(crate) use runner::{
    DeterministicScenarioBackend, ReferenceModel, ReferenceModelSnapshot, RunnerError,
    RunnerTerminal, ScenarioBackend, ScenarioFailureReport, ScenarioReport, ScenarioRunner,
};
#[allow(unused_imports)]
pub(crate) use scenario::{
    STAGE2_SCENARIO_SCHEMA_VERSION, ScenarioError, ScenarioHarness, ScenarioObservation,
    Stage2Scenario,
};
#[allow(unused_imports)]
pub(crate) use scenario_model::{
    ActionSchedule, ActionSpec, AllowedTerminal, CompletionPolicy, DiscoveryProviderSpec,
    DiscoveryRecordState, EndpointSpec, FairnessAssumption, FaultRule, FirewallRuleSpec,
    FirewallSpec, GeneratorConfig, HostSpec, InterfaceSpec, InvariantName, InvariantSpec, IpFamily,
    LinkSpec, NatSpec, ObservationTrigger, PacketFault, PayloadSpec, RelayImpairmentSpec,
    RelayProtocolVersion, RelaySpec, SCENARIO_SCHEMA_VERSION, Scenario, ScenarioAction,
    ScenarioBudgets, ScenarioBuilder, ScenarioGenerator, ScenarioMetadata, ScenarioModelError,
    ScenarioOperation, ScenarioRequirements, ScenarioResourceLimits, ScenarioTopology,
};
#[allow(unused_imports)]
pub(crate) use soak::{
    MAX_SOAK_BATCH_RUNS, MAX_SOAK_JOBS, MAX_SOAK_LANES, MAX_SOAK_RUNS, MAX_SOAK_WALL_MILLIS,
    SOAK_EPOCHS_PER_WINDOW, SOAK_SCHEMA_VERSION, SeedLease, SeedLeaseError, SoakConfig,
    SoakCryptoLane, SoakError, SoakLane, SoakLaneSummary, SoakPlan, SoakPlanError, SoakPlanLane,
    SoakRunner, SoakStopReason, SoakSummary, UniqueSoakFailure, derive_soak_seed_start,
};
#[allow(unused_imports)]
pub(crate) use swarm::{
    ReferencedSwarmSpec, SWARM_SCHEMA_VERSION, SafetyLivenessPhases, SwarmChoice, SwarmError,
    SwarmMutation, SwarmOption, SwarmSelectedChoice, SwarmSelection, SwarmSpec, SwarmTemplate,
};
#[allow(unused_imports)]
pub(crate) use trace::{
    DEFAULT_MAX_TRACE_BUFFER_EVENTS, TraceBuffer, TraceBufferError, TraceDivergence,
    TraceNormalizationError, first_trace_divergence, normalized_trace_json,
};
