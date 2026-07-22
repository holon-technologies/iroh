//! Deterministic simulation artifacts, replay contracts, and command surface.
#![forbid(unsafe_code)]

mod artifact;
mod backend;
mod campaign;
pub mod cli;
mod corpus;
mod discovery;
mod dns;
mod failure;
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
mod operations;
mod parity;
mod parity_catalog;
mod portmap;
mod relay;
mod runner;
mod scenario;
mod scenario_model;
mod swarm;
mod trace;

pub use artifact::{ArtifactError, ArtifactStore, ArtifactTraceWriter};
pub use backend::{BackendError, DeterministicBackend, DeterministicBackendConfig};
pub use campaign::{
    CampaignConfig, CampaignError, CampaignRunResult, CampaignRunner, CampaignSummary,
    CampaignTerminal, UniqueCampaignFailure,
};
pub use corpus::{
    CORPUS_SCHEMA_VERSION, Corpus, CorpusEntry, CorpusError, CorpusExpectation, CorpusMetadata,
    CorpusReport, CorpusReviewState,
};
pub use discovery::{DeterministicDiscovery, DiscoveryError, DiscoveryRecordSnapshot};
pub use dns::DeterministicDnsRuntime;
pub use failure::{
    FAILURE_ARTIFACT_SCHEMA_VERSION, FAILURE_SIGNATURE_SCHEMA_VERSION, FailureArtifactBundle,
    FailureArtifactIndex, FailureError, FailureReplayError, FailureSignature, TerminalFailureClass,
    compare_failure_replay, verify_failure_artifacts,
};
pub use invariant::{
    InvariantClass, InvariantError, InvariantFailure, InvariantRegistry, InvariantSnapshot,
    InvariantTransition,
};
pub use inventory::ScenarioInventory;
pub use kernel::{
    EventClass, EventId, Kernel, KernelConfig, KernelError, KernelExecutor, KernelRun,
    KernelSchedulerSnapshot, KernelStep, KernelTaskSnapshot, Quiescence, ScheduledEvent,
    VirtualClock, VirtualWallClock,
};
pub use kernel_driver::{KernelDriver, KernelDriverError};
pub use ledger::{
    LedgerError, ResourceCount, ResourceKind, ResourceLedger, ResourceLedgerSnapshot, ResourceToken,
};
pub use manifest::{
    BackendCapabilities, CompatibilityError, CryptoMode, DeterminismGrade, MANIFEST_SCHEMA_VERSION,
    ManifestError, ReplayIdentity, RunBudgets, RunManifest, SIMULATOR_VERSION, SourceIdentity,
    TraceComparisonMode,
};
pub use minimize::{
    MinimizationAttempt, MinimizationConfig, MinimizationError, MinimizationOutcome,
    MinimizationResult, Minimizer,
};
pub use monitor::StaticNetworkMonitor;
pub use nat::{
    Firewall, FirewallAction, FirewallConfig, FirewallConnectionState, FirewallDecision,
    FirewallDirection, FirewallPacket, FirewallProtocol, FirewallRule, NatConfig, NatError,
    NatFilteringBehavior, NatInbound, NatMappingBehavior, NatMappingSnapshot, NatOutbound,
    NatPortMapping, NatTable,
};
pub use network::{
    HostConnectivity, IpCidr, LinkConfig, NetworkConfig, NetworkError, SyntheticNetwork,
};
pub use observation::{
    ConnectionId, ConnectionState, EndpointId, EndpointState, OBSERVATION_SCHEMA_VERSION,
    Observation, ObservationError, ObservationKind, OperationId, PacketId, PathId, PayloadDigest,
    StreamId,
};
pub use operations::{
    CorpusPolicy, OPERATIONS_POLICY_SCHEMA_VERSION, OperationsPolicy, OperationsPolicyError,
    ParityPolicy, ReplayPolicy, SimulationTier, SimulationTierPolicy, SwarmPolicy,
};
pub use parity::{
    PARITY_FIXTURE_SCHEMA_VERSION, PATCHBAY_RECEIPT_SCHEMA_VERSION, ParityBackend,
    ParityComparison, ParityComparisonStatus, ParityError, ParityEvidence, ParityFixture,
    ParityFixtureResult, PatchbayReceipt, SemanticDimension, SemanticOutcome, SemanticTerminal,
    compare_parity_fixtures, compare_parity_fixtures_at, compare_semantic_outcomes,
    deterministic_semantic_outcome,
};
pub use parity_catalog::{
    CanonicalParityCase, CanonicalParityScenario, canonical_patchbay_scenarios,
};
pub use portmap::DeterministicPortMapper;
pub use relay::{
    RelayAdmissionDecision, RelayCoverage, RelayEnvironment, RelayEnvironmentError,
    RelayRouteDecision, RelayRoutingOracle,
};
pub use runner::{
    DeterministicScenarioBackend, ReferenceModel, ReferenceModelSnapshot, RunnerError,
    RunnerTerminal, ScenarioBackend, ScenarioFailureReport, ScenarioReport, ScenarioRunner,
};
pub use scenario::{
    STAGE2_SCENARIO_SCHEMA_VERSION, ScenarioError, ScenarioHarness, ScenarioObservation,
    Stage2Scenario,
};
pub use scenario_model::{
    ActionSchedule, ActionSpec, AllowedTerminal, CompletionPolicy, DiscoveryProviderSpec,
    DiscoveryRecordState, EndpointSpec, FairnessAssumption, FaultRule, FirewallRuleSpec,
    FirewallSpec, GeneratorConfig, HostSpec, InterfaceSpec, InvariantName, InvariantSpec, IpFamily,
    LinkSpec, NatSpec, ObservationTrigger, PacketFault, PayloadSpec, RelayImpairmentSpec,
    RelayProtocolVersion, RelaySpec, SCENARIO_SCHEMA_VERSION, Scenario, ScenarioAction,
    ScenarioBudgets, ScenarioBuilder, ScenarioGenerator, ScenarioMetadata, ScenarioModelError,
    ScenarioOperation, ScenarioRequirements, ScenarioTopology,
};
pub use swarm::{
    ReferencedSwarmSpec, SWARM_SCHEMA_VERSION, SafetyLivenessPhases, SwarmChoice, SwarmError,
    SwarmMutation, SwarmOption, SwarmSelectedChoice, SwarmSelection, SwarmSpec, SwarmTemplate,
};
pub use trace::{
    TraceBuffer, TraceDivergence, TraceNormalizationError, first_trace_divergence,
    normalized_trace_json,
};
