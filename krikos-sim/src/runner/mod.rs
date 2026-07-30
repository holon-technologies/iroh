//! Declarative scenario execution against production Iroh over the deterministic backend.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime},
};

use krikos::{
    Endpoint, EndpointAddr, NetReportConfig, RelayMap, RelayMode, RelayUrl, SecretKey,
    endpoint::{Connection, PortmapperConfig, presets},
    simulation::SimulationCryptoMaterial,
};
use krikos_runtime::{
    ClockError, ClockSleep, ClockTimeout, RootSeed, TimeoutError, TraceContext, TraceEventKind,
    TraceRecordError, TraceSink, UnsafeTestOnly,
};
use serde::{Deserialize, Serialize};

use crate::{
    ActionSchedule, ActionSpec, AllowedTerminal, BackendCapabilities, CompletionPolicy,
    ConnectionId, ConnectionState, DeterministicBackend, DeterministicBackendConfig,
    DeterministicDiscovery, DiscoveryRecordState, EndpointId, EndpointSpec, EndpointState,
    EventClass, FaultRule, FirewallConfig, FirewallRule, InvariantError, InvariantFailure,
    InvariantName, InvariantRegistry, InvariantSnapshot, InvariantTransition, IpCidr, KernelConfig,
    KernelResourceLimits, KernelSchedulerSnapshot, KernelTaskSnapshot, LinkConfig, LinkSpec,
    NatConfig, NatSpec, NetworkConfig, Observation, ObservationKind, ObservationTrigger,
    OperationId, PacketFault, PathId, PayloadDigest, RelayEnvironment, ResourceKind,
    ResourceLedgerSnapshot, ResourceToken, Scenario, ScenarioAction, ScenarioRequirements,
    StreamId,
};

const ALPN: &[u8] = b"iroh-sim/declarative/2";

mod backend;
mod error;
mod orchestration;
mod reference;
mod report;

pub use backend::DeterministicScenarioBackend;
use backend::{ALL_RESOURCE_KINDS, action_kind, check_capabilities, resource_limit};
pub use error::RunnerError;
use orchestration::BackendFuture;
pub use orchestration::{ScenarioBackend, ScenarioRunner};
pub use reference::{ReferenceModel, ReferenceModelSnapshot};
pub use report::{RunnerTerminal, ScenarioFailureReport, ScenarioReport};
#[cfg(test)]
mod tests;
