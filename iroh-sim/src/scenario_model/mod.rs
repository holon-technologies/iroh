//! Canonical declarative scenario schema shared by generation, replay, minimization, and corpus.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use iroh_runtime::{DecisionSource, RootSeed, SeededDecisionSource};
use serde::{Deserialize, Serialize};

use crate::RunBudgets;

/// Current canonical declarative scenario schema.
pub const SCENARIO_SCHEMA_VERSION: u16 = 3;
const SCENARIO_V2_SCHEMA_VERSION: u16 = 2;
const MAX_ITEMS: usize = 10_000;
const MAX_TEXT: usize = 1_024;

mod builder;
mod generator;
mod migration;
mod schema;
mod validation;

pub use builder::ScenarioBuilder;
pub use generator::{GeneratorConfig, ScenarioGenerator};
pub use schema::*;
use schema::{ScenarioBudgetsV2, validate_observation_reference};
pub use validation::ScenarioModelError;
use validation::*;

/// One canonical, backend-independent simulation scenario.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    /// Schema version.
    pub schema_version: u16,
    /// Stable human and corpus identity.
    pub metadata: ScenarioMetadata,
    /// Capabilities that must be supplied by a backend.
    pub requirements: ScenarioRequirements,
    /// Hard execution and representation bounds.
    pub budgets: ScenarioBudgets,
    /// Hosts, interfaces, and links.
    pub topology: ScenarioTopology,
    /// Production endpoints to construct.
    pub endpoints: Vec<EndpointSpec>,
    /// Declarative operations.
    pub actions: Vec<ActionSpec>,
    /// Environment fault policies.
    pub fault_rules: Vec<FaultRule>,
    /// Assumptions under which bounded liveness is meaningful.
    pub fairness: Vec<FairnessAssumption>,
    /// Completion and shutdown policy.
    pub completion: CompletionPolicy,
    /// Terminal states accepted by this scenario.
    pub allowed_terminals: Vec<AllowedTerminal>,
    /// Continuously enabled invariants.
    pub invariants: Vec<InvariantSpec>,
}
