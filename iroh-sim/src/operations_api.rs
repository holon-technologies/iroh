//! Gate, soak, swarm, and operations policy types.

pub use crate::{
    gate::{
        CHANGE_IMPACT_POLICY_SCHEMA_VERSION, ChangeImpactMapping, ChangeImpactPolicy, GateDomain,
        GateError, GateSelection, GateSelectionMode, GateTierPolicy, GateWork, GateWorkKind,
        SimulationGateTier,
    },
    operations_policy::{
        AutomationPolicy, CorpusPolicy, DailySoakPolicy, GateRuntimeSloPolicy,
        OPERATIONS_POLICY_SCHEMA_VERSION, OperationsPolicy, OperationsPolicyError, ParityPolicy,
        ReleasePolicy, ReplayPolicy, SimulationTier, SimulationTierPolicy, SwarmPolicy,
    },
    soak::{
        MAX_SOAK_BATCH_RUNS, MAX_SOAK_JOBS, MAX_SOAK_LANES, MAX_SOAK_RUNS, MAX_SOAK_WALL_MILLIS,
        SOAK_EPOCHS_PER_WINDOW, SOAK_SCHEMA_VERSION, SeedLease, SeedLeaseError, SoakConfig,
        SoakCryptoLane, SoakError, SoakLane, SoakLaneSummary, SoakPlan, SoakPlanError,
        SoakPlanLane, SoakRunner, SoakStopReason, SoakSummary, UniqueSoakFailure,
        derive_soak_seed_start,
    },
    swarm::{
        ReferencedSwarmSpec, SWARM_SCHEMA_VERSION, SafetyLivenessPhases, SwarmChoice, SwarmError,
        SwarmMutation, SwarmOption, SwarmSelectedChoice, SwarmSelection, SwarmSpec, SwarmTemplate,
    },
};
