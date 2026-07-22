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

use iroh::{
    Endpoint, EndpointAddr, NetReportConfig, RelayMap, RelayMode, RelayUrl, SecretKey,
    endpoint::{Connection, PortmapperConfig, presets},
    simulation::SimulationCryptoMaterial,
};
use iroh_runtime::{
    RootSeed, TraceContext, TraceEventKind, TraceRecordError, TraceSink, UnsafeTestOnly,
};
use serde::{Deserialize, Serialize};

use crate::{
    ActionSchedule, ActionSpec, AllowedTerminal, BackendCapabilities, CompletionPolicy,
    ConnectionId, ConnectionState, DeterministicBackend, DeterministicBackendConfig,
    DeterministicDiscovery, DiscoveryRecordState, EndpointId, EndpointSpec, EndpointState,
    EventClass, FaultRule, FirewallConfig, FirewallRule, InvariantError, InvariantFailure,
    InvariantName, InvariantRegistry, InvariantSnapshot, InvariantTransition, IpCidr, KernelConfig,
    KernelSchedulerSnapshot, KernelTaskSnapshot, LinkConfig, LinkSpec, NatConfig, NatSpec,
    NetworkConfig, Observation, ObservationKind, ObservationTrigger, OperationId, PacketFault,
    PathId, PayloadDigest, RelayEnvironment, ResourceKind, ResourceLedgerSnapshot, ResourceToken,
    Scenario, ScenarioAction, ScenarioRequirements, StreamId,
};

const ALPN: &[u8] = b"iroh-sim/declarative/2";
type BackendFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, RunnerError>> + 'a>>;

/// Backend contract used by the canonical scenario runner.
pub trait ScenarioBackend: fmt::Debug {
    fn capabilities(&self) -> BackendCapabilities;
    fn prepare<'a>(&'a mut self, scenario: &'a Scenario) -> BackendFuture<'a, ()>;
    fn execute<'a>(&'a mut self, action: &'a ActionSpec)
    -> BackendFuture<'a, Vec<ObservationKind>>;
    fn advance_to(&mut self, deadline_nanos: u64) -> BackendFuture<'_, ()>;
    fn shutdown(&mut self) -> BackendFuture<'_, Vec<ObservationKind>>;
    fn virtual_time_nanos(&self) -> Result<u64, RunnerError>;
    fn resource_snapshot(&self) -> ResourceLedgerSnapshot;
    fn scheduler_snapshot(&self) -> Option<KernelSchedulerSnapshot> {
        None
    }
    fn task_ownership_snapshot(&self) -> Vec<KernelTaskSnapshot> {
        Vec::new()
    }
    fn trace(&self, context: TraceContext, event: TraceEventKind) -> Result<(), RunnerError>;
}

/// Canonical deterministic runner and its continuous model/invariant state.
#[derive(Debug)]
pub struct ScenarioRunner<B = DeterministicScenarioBackend> {
    scenario: Scenario,
    backend: B,
    model: ReferenceModel,
    invariants: InvariantRegistry,
    next_observation: u64,
    observations: Vec<Observation>,
    completed_actions: BTreeSet<String>,
    satisfied_invariants: BTreeSet<InvariantName>,
}

impl ScenarioRunner<DeterministicScenarioBackend> {
    /// Creates the Stage 3 deterministic production-code backend.
    pub fn deterministic(
        scenario: Scenario,
        root_seed: RootSeed,
        wall_epoch: SystemTime,
        trace: Arc<dyn TraceSink>,
    ) -> Result<Self, RunnerError> {
        Self::with_crypto_mode(
            scenario,
            root_seed,
            wall_epoch,
            trace,
            iroh::simulation::SimulationCryptoMode::DeterministicTest,
        )
    }

    /// Creates the deterministic backend with an explicit simulation cryptography lane.
    pub fn with_crypto_mode(
        scenario: Scenario,
        root_seed: RootSeed,
        wall_epoch: SystemTime,
        trace: Arc<dyn TraceSink>,
        crypto_mode: iroh::simulation::SimulationCryptoMode,
    ) -> Result<Self, RunnerError> {
        scenario
            .validate()
            .map_err(|error| RunnerError::Scenario(error.to_string()))?;
        let backend = DeterministicScenarioBackend::new(
            &scenario,
            root_seed,
            wall_epoch,
            trace,
            crypto_mode,
        )?;
        Self::new(scenario, backend)
    }
}

impl<B: ScenarioBackend> ScenarioRunner<B> {
    /// Creates a runner after checking exact capability compatibility.
    pub fn new(scenario: Scenario, backend: B) -> Result<Self, RunnerError> {
        scenario
            .validate()
            .map_err(|error| RunnerError::Scenario(error.to_string()))?;
        check_capabilities(&scenario.requirements, &backend.capabilities())?;
        let model = ReferenceModel::new(&scenario)?;
        let invariants = InvariantRegistry::from_scenario(&scenario)?;
        Ok(Self {
            scenario,
            backend,
            model,
            invariants,
            next_observation: 1,
            observations: Vec::new(),
            completed_actions: BTreeSet::new(),
            satisfied_invariants: BTreeSet::new(),
        })
    }

    /// Executes all actions, continuously checks invariants, and always performs bounded cleanup.
    pub async fn run(self) -> Result<ScenarioReport, RunnerError> {
        self.run_detailed()
            .await
            .map_err(ScenarioFailureReport::into_error)
    }

    /// Executes while retaining observations, invariant state, and resources on failure.
    pub async fn run_detailed(mut self) -> Result<ScenarioReport, ScenarioFailureReport> {
        let execution = self.execute_all().await;
        let cleanup = self.backend.shutdown().await;
        if let Err(primary) = execution {
            let error = match cleanup {
                Ok(_) => primary,
                Err(cleanup) => RunnerError::CleanupAfterFailure {
                    primary: primary.to_string(),
                    cleanup: cleanup.to_string(),
                },
            };
            return Err(self.failure_report(error));
        }
        let cleanup_observations = match cleanup {
            Ok(observations) => observations,
            Err(error) => return Err(self.failure_report(error)),
        };
        if let Err(error) = self
            .model
            .apply_terminal_observations(&cleanup_observations)
        {
            return Err(self.failure_report(error));
        }
        if let Err(error) = self.ingest_observations(None, cleanup_observations) {
            return Err(self.failure_report(error));
        }
        let virtual_time_nanos = match self.backend.virtual_time_nanos() {
            Ok(value) => value,
            Err(error) => return Err(self.failure_report(error)),
        };
        let invariants = match self
            .invariants
            .finish(virtual_time_nanos, self.next_observation.saturating_sub(1))
        {
            Ok(snapshot) => snapshot,
            Err(error) => return Err(self.failure_report(error.into())),
        };
        let resources = self.backend.resource_snapshot();
        if !resources.is_empty() {
            return Err(self.failure_report(RunnerError::ResourceLeak(resources)));
        }
        if !self
            .scenario
            .allowed_terminals
            .contains(&AllowedTerminal::Success)
        {
            return Err(self.failure_report(RunnerError::TerminalNotAllowed("success")));
        }
        Ok(ScenarioReport {
            scenario_id: self.scenario.metadata.id.clone(),
            terminal: RunnerTerminal::Success,
            actions_completed: u64::try_from(self.completed_actions.len())
                .map_err(|_| self.failure_report(RunnerError::ObservationOverflow))?,
            virtual_time_nanos,
            observations: self.observations,
            invariants,
            model: self.model.snapshot(),
            resources,
            scheduler: self.backend.scheduler_snapshot(),
            tasks: self.backend.task_ownership_snapshot(),
        })
    }

    fn failure_report(&self, error: RunnerError) -> ScenarioFailureReport {
        ScenarioFailureReport {
            error,
            virtual_time_nanos: self.backend.virtual_time_nanos().unwrap_or_default(),
            observations: self.observations.clone(),
            invariants: self.invariants.snapshot(),
            model: self.model.snapshot(),
            resources: self.backend.resource_snapshot(),
            scheduler: self.backend.scheduler_snapshot(),
            tasks: self.backend.task_ownership_snapshot(),
        }
    }

    async fn execute_all(&mut self) -> Result<(), RunnerError> {
        self.backend.prepare(&self.scenario).await?;
        let mut pending = self.scenario.actions.clone();
        while !pending.is_empty() {
            if let CompletionPolicy::Observation { trigger, .. } = &self.scenario.completion
                && self.observation_triggered(trigger)
            {
                return Ok(());
            }
            let now = self.backend.virtual_time_nanos()?;
            let ready = pending
                .iter()
                .enumerate()
                .filter(|(_, action)| self.action_ready(action, now))
                .min_by(|(_, left), (_, right)| left.id.cmp(&right.id))
                .map(|(index, _)| index);
            let Some(index) = ready else {
                if let Some(deadline) = pending
                    .iter()
                    .filter_map(|action| action.schedule.deadline_nanos())
                    .filter(|deadline| *deadline > now)
                    .min()
                {
                    self.invariants
                        .check_before_time_advance(deadline, self.next_observation)?;
                    self.backend.advance_to(deadline).await?;
                    continue;
                }
                return Err(RunnerError::TriggerStall(
                    pending.iter().map(|action| action.id.clone()).collect(),
                ));
            };
            let action = pending.remove(index);
            self.execute_one(&action).await?;
            self.completed_actions.insert(action.id);
        }
        Ok(())
    }

    fn action_ready(&self, action: &ActionSpec, now: u64) -> bool {
        match &action.schedule {
            ActionSchedule::At { nanos } => *nanos <= now,
            ActionSchedule::AfterAction { action } => self.completed_actions.contains(action),
            ActionSchedule::AfterObservation { observation } => {
                self.observation_triggered(observation)
            }
        }
    }

    fn observation_triggered(&self, trigger: &ObservationTrigger) -> bool {
        match trigger {
            ObservationTrigger::EndpointState { endpoint, state } => {
                self.observations.iter().any(|observation| {
                    matches!(
                        &observation.kind,
                        ObservationKind::EndpointState { endpoint: observed, to, .. }
                            if observed.as_str() == endpoint && state == &format!("{to:?}").to_ascii_lowercase()
                    )
                })
            }
            ObservationTrigger::ConnectionState { connection, state } => {
                self.observations.iter().any(|observation| {
                    matches!(
                        &observation.kind,
                        ObservationKind::ConnectionState { connection: observed, to, .. }
                            if observed.as_str() == connection && state == &format!("{to:?}").to_ascii_lowercase()
                    )
                })
            }
            ObservationTrigger::InvariantSatisfied { invariant } => {
                self.satisfied_invariants.contains(invariant)
            }
        }
    }

    async fn execute_one(&mut self, action: &ActionSpec) -> Result<(), RunnerError> {
        let operation = OperationId::new(&action.id)?;
        let mut context = TraceContext {
            operation: Some(action.id.clone()),
            ..TraceContext::default()
        };
        self.backend.trace(
            context.clone(),
            TraceEventKind::OperationStarted {
                action: action_kind(&action.action).to_owned(),
            },
        )?;
        self.ingest_one(
            Some(operation.clone()),
            ObservationKind::OperationStarted {
                operation: operation.clone(),
            },
        )?;
        if let ScenarioAction::AdvanceTime { by_nanos } = action.action {
            let target = self
                .backend
                .virtual_time_nanos()?
                .checked_add(by_nanos)
                .ok_or(RunnerError::TimelineOverflow)?;
            self.invariants
                .check_before_time_advance(target, self.next_observation)?;
        }
        let observations = self.backend.execute(action).await?;
        match &action.action {
            ScenarioAction::Partition { .. } => self
                .invariants
                .set_fairness(crate::FairnessAssumption::ReachableNetwork, false),
            ScenarioAction::Heal { .. } => self
                .invariants
                .set_fairness(crate::FairnessAssumption::ReachableNetwork, true),
            _ => {}
        }
        self.ingest_observations(Some(operation.clone()), observations.clone())?;
        self.model.validate_action_outcome(action, &observations)?;
        self.ingest_one(
            Some(operation.clone()),
            ObservationKind::OperationCompleted {
                operation,
                outcome: "ok".to_owned(),
            },
        )?;
        context.operation = Some(action.id.clone());
        self.backend.trace(
            context,
            TraceEventKind::OperationCompleted {
                outcome: "ok".to_owned(),
            },
        )?;
        Ok(())
    }

    fn ingest_observations(
        &mut self,
        operation: Option<OperationId>,
        observations: Vec<ObservationKind>,
    ) -> Result<(), RunnerError> {
        for observation in observations {
            self.ingest_one(operation.clone(), observation)?;
        }
        self.ingest_resource_observations(operation)
    }

    fn ingest_resource_observations(
        &mut self,
        operation: Option<OperationId>,
    ) -> Result<(), RunnerError> {
        let snapshot = self.backend.resource_snapshot();
        for kind in ALL_RESOURCE_KINDS {
            self.ingest_one(
                operation.clone(),
                ObservationKind::Resource {
                    kind,
                    current: snapshot.current(kind),
                    limit: resource_limit(&self.scenario, kind),
                },
            )?;
        }
        Ok(())
    }

    fn ingest_one(
        &mut self,
        operation: Option<OperationId>,
        kind: ObservationKind,
    ) -> Result<(), RunnerError> {
        let sequence = self.next_observation;
        self.next_observation = self
            .next_observation
            .checked_add(1)
            .ok_or(RunnerError::ObservationOverflow)?;
        let mut observation = Observation::new(sequence, self.backend.virtual_time_nanos()?, kind);
        observation.caused_by = operation;
        self.trace_observation(&observation)?;
        match self.invariants.observe(observation.clone()) {
            Ok(transitions) => {
                self.trace_invariant_transitions(transitions)?;
            }
            Err(InvariantError::Failure(failure)) => {
                self.trace_invariant_failure(&failure)?;
                return Err(RunnerError::Invariant(failure));
            }
            Err(error) => return Err(RunnerError::InvariantEngine(error)),
        }
        self.observations.push(observation);
        Ok(())
    }

    fn trace_observation(&self, observation: &Observation) -> Result<(), RunnerError> {
        let mut context = TraceContext {
            operation: observation
                .caused_by
                .as_ref()
                .map(|operation| operation.to_string()),
            ..TraceContext::default()
        };
        let event = match &observation.kind {
            ObservationKind::OperationStarted { .. }
            | ObservationKind::OperationCompleted { .. } => {
                return Ok(());
            }
            ObservationKind::EndpointState { endpoint, from, to } => {
                context.endpoint = Some(endpoint.to_string());
                TraceEventKind::StateTransition {
                    component: "endpoint".to_owned(),
                    from: format!("{from:?}").to_ascii_lowercase(),
                    to: format!("{to:?}").to_ascii_lowercase(),
                }
            }
            ObservationKind::ConnectionState {
                connection,
                owner,
                from,
                to,
                ..
            } => {
                context.connection = Some(connection.to_string());
                context.endpoint = Some(owner.to_string());
                TraceEventKind::StateTransition {
                    component: "connection".to_owned(),
                    from: format!("{from:?}").to_ascii_lowercase(),
                    to: format!("{to:?}").to_ascii_lowercase(),
                }
            }
            ObservationKind::Delivery {
                connection,
                stream,
                sequence,
                source,
                destination,
                expected,
                actual,
                ..
            } => {
                context.connection = Some(connection.to_string());
                context.stream = stream.as_ref().map(ToString::to_string);
                TraceEventKind::ApplicationDelivery {
                    sequence: *sequence,
                    source: source.to_string(),
                    destination: destination.to_string(),
                    expected_hash: expected.as_str().to_owned(),
                    actual_hash: actual.as_str().to_owned(),
                }
            }
            ObservationKind::Resource {
                kind,
                current,
                limit,
            } => TraceEventKind::StateTransition {
                component: format!("resource/{kind:?}").to_ascii_lowercase(),
                from: current.to_string(),
                to: format!("current={current},limit={limit}"),
            },
            ObservationKind::InterfaceState {
                host,
                interface,
                up,
            } => {
                context.interface = Some(format!("{host}/{interface}"));
                TraceEventKind::StateTransition {
                    component: "interface".to_owned(),
                    from: (!up).to_string(),
                    to: up.to_string(),
                }
            }
            ObservationKind::InterfaceAddress {
                host,
                interface,
                address,
                present,
            } => {
                context.interface = Some(format!("{host}/{interface}"));
                TraceEventKind::StateTransition {
                    component: format!("interface_address/{address}"),
                    from: (!present).to_string(),
                    to: present.to_string(),
                }
            }
            ObservationKind::HostPower { host, sleeping } => TraceEventKind::StateTransition {
                component: format!("host_power/{host}"),
                from: (!sleeping).to_string(),
                to: sleeping.to_string(),
            },
            ObservationKind::RouteState {
                host,
                route,
                active,
            } => TraceEventKind::StateTransition {
                component: format!("route/{host}/{route}"),
                from: (!active).to_string(),
                to: active.to_string(),
            },
            ObservationKind::PortMappingState {
                endpoint,
                active,
                external,
            } => {
                context.endpoint = Some(endpoint.to_string());
                TraceEventKind::StateTransition {
                    component: "port_mapping".to_owned(),
                    from: (!active).to_string(),
                    to: external.clone().unwrap_or_else(|| "inactive".to_owned()),
                }
            }
            ObservationKind::DiscoveryRecordState {
                provider,
                record,
                endpoint,
                state,
                ..
            } => {
                context.discovery = Some(provider.clone());
                context.endpoint = Some(endpoint.to_string());
                TraceEventKind::StateTransition {
                    component: format!("discovery_record/{record}"),
                    from: "previous".to_owned(),
                    to: state.clone(),
                }
            }
            ObservationKind::RelayState {
                relay,
                online,
                generation,
                sessions,
            } => {
                context.relay = Some(relay.clone());
                TraceEventKind::StateTransition {
                    component: format!("relay/generation/{generation}/sessions/{sessions}"),
                    from: (!online).to_string(),
                    to: online.to_string(),
                }
            }
            ObservationKind::RelayCoverage {
                relay,
                connect_attempts,
                authenticated_sessions,
                forwarded_packets,
                dropped_packets,
            } => {
                context.relay = Some(relay.clone());
                TraceEventKind::StateTransition {
                    component: "relay/production_coverage".to_owned(),
                    from: "unobserved".to_owned(),
                    to: format!(
                        "connect_attempts={connect_attempts},authenticated_sessions={authenticated_sessions},forwarded_packets={forwarded_packets},dropped_packets={dropped_packets}"
                    ),
                }
            }
            ObservationKind::PathState {
                connection,
                path,
                active,
            } => {
                context.connection = Some(connection.to_string());
                if path.as_str().starts_with("relay") {
                    context.relay = Some(path.to_string());
                }
                TraceEventKind::StateTransition {
                    component: format!("path/{path}"),
                    from: (!active).to_string(),
                    to: active.to_string(),
                }
            }
            ObservationKind::Marker { name, .. } => TraceEventKind::StateTransition {
                component: format!("marker/{name}"),
                from: "absent".to_owned(),
                to: "observed".to_owned(),
            },
        };
        self.backend.trace(context, event)
    }

    fn trace_invariant_transitions(
        &mut self,
        transitions: Vec<InvariantTransition>,
    ) -> Result<(), RunnerError> {
        for transition in transitions {
            match transition {
                InvariantTransition::Registered {
                    invariant,
                    obligation,
                    deadline_nanos,
                    event_deadline,
                } => self.backend.trace(
                    TraceContext {
                        invariant: Some(format!("{invariant:?}").to_ascii_lowercase()),
                        ..TraceContext::default()
                    },
                    TraceEventKind::InvariantRegistered {
                        obligation,
                        deadline_nanos,
                        event_deadline,
                    },
                )?,
                InvariantTransition::Satisfied {
                    invariant,
                    obligation,
                } => {
                    self.satisfied_invariants.insert(invariant);
                    self.backend.trace(
                        TraceContext {
                            invariant: Some(format!("{invariant:?}").to_ascii_lowercase()),
                            ..TraceContext::default()
                        },
                        TraceEventKind::InvariantSatisfied { obligation },
                    )?;
                }
            }
        }
        Ok(())
    }

    fn trace_invariant_failure(&self, failure: &InvariantFailure) -> Result<(), RunnerError> {
        let evidence = serde_json::to_vec(failure)
            .map_err(|error| RunnerError::Encoding(error.to_string()))?;
        self.backend.trace(
            TraceContext {
                invariant: Some(format!("{:?}", failure.name).to_ascii_lowercase()),
                ..TraceContext::default()
            },
            TraceEventKind::InvariantFailed {
                class: format!("{:?}", failure.class).to_ascii_lowercase(),
                evidence_digest: blake3::hash(&evidence).to_hex().to_string(),
            },
        )
    }
}

/// Pure action/outcome model that does not reproduce protocol timing or packet internals.
#[derive(Clone, Debug)]
pub struct ReferenceModel {
    endpoints: BTreeMap<String, EndpointState>,
    connections: BTreeMap<String, ConnectionState>,
}

/// Stable pure-model state retained in successful and failing terminal reports.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceModelSnapshot {
    pub endpoints: BTreeMap<String, EndpointState>,
    pub connections: BTreeMap<String, ConnectionState>,
}

impl ReferenceModel {
    pub fn new(scenario: &Scenario) -> Result<Self, RunnerError> {
        scenario
            .validate()
            .map_err(|error| RunnerError::Scenario(error.to_string()))?;
        Ok(Self {
            endpoints: scenario
                .endpoints
                .iter()
                .map(|endpoint| (endpoint.id.clone(), EndpointState::Created))
                .collect(),
            connections: BTreeMap::new(),
        })
    }

    pub fn validate_action_outcome(
        &mut self,
        action: &ActionSpec,
        observations: &[ObservationKind],
    ) -> Result<(), RunnerError> {
        match &action.action {
            ScenarioAction::StartEndpoint { endpoint } => {
                self.require_endpoint(endpoint, EndpointState::Created)?;
                expect_endpoint(
                    observations,
                    endpoint,
                    EndpointState::Created,
                    EndpointState::Running,
                )?;
                self.endpoints
                    .insert(endpoint.clone(), EndpointState::Running);
            }
            ScenarioAction::StopEndpoint { endpoint } => {
                self.require_endpoint(endpoint, EndpointState::Running)?;
                if observations.len() != 2
                    || !matches!(&observations[0], ObservationKind::EndpointState { endpoint: observed, from: EndpointState::Running, to: EndpointState::Stopping } if observed.as_str() == endpoint)
                    || !matches!(&observations[1], ObservationKind::EndpointState { endpoint: observed, from: EndpointState::Stopping, to: EndpointState::Stopped } if observed.as_str() == endpoint)
                {
                    return model_mismatch(
                        action,
                        "running->stopping->stopped endpoint observations",
                        observations,
                    );
                }
                self.endpoints
                    .insert(endpoint.clone(), EndpointState::Stopped);
            }
            ScenarioAction::Connect {
                client,
                server,
                connection,
            } => {
                self.require_endpoint(client, EndpointState::Running)?;
                self.require_endpoint(server, EndpointState::Running)?;
                if self.connections.contains_key(connection)
                    || observations.len() != 2
                    || !matches!(&observations[0], ObservationKind::ConnectionState { connection: observed, from: ConnectionState::Created, to: ConnectionState::Dialing, .. } if observed.as_str() == connection)
                    || !matches!(&observations[1], ObservationKind::ConnectionState { connection: observed, from: ConnectionState::Dialing, to: ConnectionState::Connected, .. } if observed.as_str() == connection)
                {
                    return model_mismatch(
                        action,
                        "created->dialing->connected connection observations",
                        observations,
                    );
                }
                self.connections
                    .insert(connection.clone(), ConnectionState::Connected);
            }
            ScenarioAction::StreamRoundTrip {
                connection,
                payload,
            }
            | ScenarioAction::DatagramRoundTrip {
                connection,
                payload,
            } => {
                self.require_connection(connection, ConnectionState::Connected)?;
                let deliveries = observations
                    .iter()
                    .filter(|observation| matches!(observation, ObservationKind::Delivery { .. }))
                    .collect::<Vec<_>>();
                if deliveries.len() != 2
                    || deliveries.iter().any(|observation| {
                        !matches!(observation, ObservationKind::Delivery { connection: observed, expected, actual, .. }
                            if observed.as_str() == connection && expected == actual)
                    })
                    || observations.iter().any(|observation| {
                        !matches!(observation,
                            ObservationKind::Delivery { .. }
                            | ObservationKind::PathState { active: true, .. }
                            | ObservationKind::RelayCoverage { .. })
                    })
                {
                    return model_mismatch(action, "two byte-identical delivery observations", observations);
                }
                let expected =
                    PayloadDigest::from_bytes(&vec![payload.fill; payload.bytes as usize]);
                if deliveries.iter().any(|observation| {
                    !matches!(observation, ObservationKind::Delivery { expected: observed, .. } if observed == &expected)
                }) {
                    return model_mismatch(action, "delivery digest matching the declared payload", observations);
                }
            }
            ScenarioAction::CloseConnection { connection } => {
                self.require_connection(connection, ConnectionState::Connected)?;
                if observations.len() != 2
                    || !matches!(&observations[0], ObservationKind::ConnectionState { connection: observed, from: ConnectionState::Connected, to: ConnectionState::Closing, .. } if observed.as_str() == connection)
                    || !matches!(&observations[1], ObservationKind::ConnectionState { connection: observed, from: ConnectionState::Closing, to: ConnectionState::Closed, .. } if observed.as_str() == connection)
                {
                    return model_mismatch(
                        action,
                        "connected->closing->closed observations",
                        observations,
                    );
                }
                self.connections
                    .insert(connection.clone(), ConnectionState::Closed);
            }
            ScenarioAction::Partition { .. }
            | ScenarioAction::Heal { .. }
            | ScenarioAction::SetLink { .. }
            | ScenarioAction::AdvanceTime { .. }
            | ScenarioAction::ExpectFailure { .. }
            | ScenarioAction::NatChange { .. } => {
                if !observations.is_empty() {
                    return model_mismatch(action, "no component observation", observations);
                }
            }
            ScenarioAction::InterfaceChange {
                host,
                interface,
                up,
            } => {
                if !matches!(observations, [ObservationKind::InterfaceState {
                    host: observed_host,
                    interface: observed_interface,
                    up: observed_up,
                }] if observed_host == host && observed_interface == interface && observed_up == up)
                {
                    return model_mismatch(
                        action,
                        "matching interface-state observation",
                        observations,
                    );
                }
            }
            ScenarioAction::AddressChange {
                host,
                interface,
                address,
                present,
            } => {
                if !matches!(observations, [ObservationKind::InterfaceAddress {
                    host: observed_host,
                    interface: observed_interface,
                    address: observed_address,
                    present: observed_present,
                }] if observed_host == host && observed_interface == interface
                    && observed_address == address && observed_present == present)
                {
                    return model_mismatch(
                        action,
                        "matching interface-address observation",
                        observations,
                    );
                }
            }
            ScenarioAction::HostSleep { host, sleeping } => {
                if !matches!(observations, [ObservationKind::HostPower {
                    host: observed_host,
                    sleeping: observed_sleeping,
                }] if observed_host == host && observed_sleeping == sleeping)
                {
                    return model_mismatch(action, "matching host-power observation", observations);
                }
            }
            ScenarioAction::RouteChange {
                host,
                route,
                active,
                ..
            } => {
                if !matches!(observations, [ObservationKind::RouteState {
                    host: observed_host,
                    route: observed_route,
                    active: observed_active,
                }] if observed_host == host && observed_route == route && observed_active == active)
                {
                    return model_mismatch(
                        action,
                        "matching route-state observation",
                        observations,
                    );
                }
            }
            ScenarioAction::PortMap { endpoint, active } => {
                if !matches!(observations, [ObservationKind::PortMappingState {
                    endpoint: observed_endpoint,
                    active: observed_active,
                    external,
                }] if observed_endpoint.as_str() == endpoint && observed_active == active
                    && (!active || external.is_some()))
                {
                    return model_mismatch(
                        action,
                        "matching port-mapping observation",
                        observations,
                    );
                }
            }
            ScenarioAction::DiscoveryUpdate {
                provider,
                record,
                endpoint,
                addresses,
                state,
                ..
            } => {
                let expected_state = format!("{state:?}").to_ascii_lowercase();
                if !matches!(observations, [ObservationKind::DiscoveryRecordState {
                    provider: observed_provider,
                    record: observed_record,
                    endpoint: observed_endpoint,
                    state: observed_state,
                    addresses: observed_addresses,
                    ..
                }] if observed_provider == provider
                    && observed_record == record
                    && observed_endpoint.as_str() == endpoint
                    && observed_state == &expected_state
                    && (state != &DiscoveryRecordState::Published
                        || observed_addresses == addresses))
                {
                    return model_mismatch(
                        action,
                        "matching discovery-record observation",
                        observations,
                    );
                }
            }
            ScenarioAction::RelayLifecycle { relay, online } => {
                if !matches!(observations, [ObservationKind::RelayState {
                    relay: observed_relay,
                    online: observed_online,
                    ..
                }] if observed_relay == relay && observed_online == online)
                {
                    return model_mismatch(
                        action,
                        "matching relay-state observation",
                        observations,
                    );
                }
            }
        }
        Ok(())
    }

    pub fn snapshot(&self) -> ReferenceModelSnapshot {
        ReferenceModelSnapshot {
            endpoints: self.endpoints.clone(),
            connections: self.connections.clone(),
        }
    }

    fn apply_terminal_observations(
        &mut self,
        observations: &[ObservationKind],
    ) -> Result<(), RunnerError> {
        for observation in observations {
            match observation {
                ObservationKind::EndpointState { endpoint, from, to } => {
                    self.require_endpoint(endpoint.as_str(), *from)?;
                    self.endpoints.insert(endpoint.to_string(), *to);
                }
                ObservationKind::ConnectionState {
                    connection,
                    from,
                    to,
                    ..
                } => {
                    self.require_connection(connection.as_str(), *from)?;
                    self.connections.insert(connection.to_string(), *to);
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn require_endpoint(&self, endpoint: &str, expected: EndpointState) -> Result<(), RunnerError> {
        let actual = self.endpoints.get(endpoint).copied();
        if actual == Some(expected) {
            Ok(())
        } else {
            Err(RunnerError::ModelState {
                entity: endpoint.to_owned(),
                expected: format!("{expected:?}"),
                actual: format!("{actual:?}"),
            })
        }
    }

    fn require_connection(
        &self,
        connection: &str,
        expected: ConnectionState,
    ) -> Result<(), RunnerError> {
        let actual = self.connections.get(connection).copied();
        if actual == Some(expected) {
            Ok(())
        } else {
            Err(RunnerError::ModelState {
                entity: connection.to_owned(),
                expected: format!("{expected:?}"),
                actual: format!("{actual:?}"),
            })
        }
    }
}

fn expect_endpoint(
    observations: &[ObservationKind],
    endpoint: &str,
    from: EndpointState,
    to: EndpointState,
) -> Result<(), RunnerError> {
    if observations.len() == 1
        && matches!(&observations[0], ObservationKind::EndpointState { endpoint: observed, from: actual_from, to: actual_to }
            if observed.as_str() == endpoint && *actual_from == from && *actual_to == to)
    {
        Ok(())
    } else {
        Err(RunnerError::ModelMismatch {
            action: endpoint.to_owned(),
            expected: format!("{from:?}->{to:?}"),
            actual: format!("{observations:?}"),
        })
    }
}

fn model_mismatch<T>(
    action: &ActionSpec,
    expected: &str,
    observations: &[ObservationKind],
) -> Result<T, RunnerError> {
    Err(RunnerError::ModelMismatch {
        action: action.id.clone(),
        expected: expected.to_owned(),
        actual: format!("{observations:?}"),
    })
}

/// Production-endpoint implementation of [`ScenarioBackend`] using the deterministic kernel.
pub struct DeterministicScenarioBackend {
    backend: DeterministicBackend,
    capabilities: BackendCapabilities,
    endpoints: BTreeMap<String, RunningEndpoint>,
    connections: BTreeMap<String, ConnectionPair>,
    specs: BTreeMap<String, EndpointSpec>,
    discovery: BTreeMap<String, DeterministicDiscovery>,
    relay: Option<RelayEnvironment>,
    relay_urls: BTreeMap<String, RelayUrl>,
    relay_resources: Vec<ResourceToken>,
    use_discovery: bool,
}

impl fmt::Debug for DeterministicScenarioBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeterministicScenarioBackend")
            .field("backend", &self.backend)
            .field("endpoints", &self.endpoints.keys().collect::<Vec<_>>())
            .field("connections", &self.connections.keys().collect::<Vec<_>>())
            .finish()
    }
}

struct RunningEndpoint {
    endpoint: Endpoint,
    bind: SocketAddr,
}

struct ConnectionPair {
    client: Connection,
    server: Connection,
    client_endpoint: String,
    server_endpoint: String,
    _resource: ResourceToken,
}

impl DeterministicScenarioBackend {
    fn new(
        scenario: &Scenario,
        root_seed: RootSeed,
        wall_epoch: SystemTime,
        trace: Arc<dyn TraceSink>,
        crypto_mode: iroh::simulation::SimulationCryptoMode,
    ) -> Result<Self, RunnerError> {
        let budgets = scenario.run_budgets();
        let backend = DeterministicBackend::new(
            DeterministicBackendConfig {
                root_seed,
                wall_epoch,
                kernel: KernelConfig {
                    max_events: budgets.max_events,
                    max_virtual_time: Duration::from_nanos(budgets.max_virtual_time_nanos),
                    max_tasks: budgets.max_tasks,
                },
                network: NetworkConfig {
                    max_packets: budgets.max_packets,
                    ephemeral_port_start: 40_000,
                },
                max_driver_turns: budgets.max_events.saturating_mul(8).max(1_000),
                crypto_mode,
            },
            trace,
        )?;
        let mut capabilities = backend.capabilities();
        capabilities.nat = !scenario.topology.nats.is_empty();
        capabilities.discovery = !scenario.topology.discovery.is_empty();
        capabilities.relay = !scenario.topology.relays.is_empty();
        capabilities.mobility = true;
        let discovery = scenario
            .topology
            .discovery
            .iter()
            .map(|provider| {
                Ok((
                    provider.id.clone(),
                    DeterministicDiscovery::new(
                        &provider.id,
                        provider.max_records,
                        backend.kernel().clone(),
                        backend.runtime_context().clone(),
                    )?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, RunnerError>>()?;
        let relay = (!scenario.topology.relays.is_empty())
            .then(|| {
                RelayEnvironment::new_with_runtime(
                    &scenario.topology.relays,
                    &scenario.topology.relay_impairments,
                    backend.runtime_context().clone(),
                )
            })
            .transpose()
            .map_err(|error| RunnerError::Scenario(error.to_string()))?;
        let relay_urls = scenario
            .topology
            .relays
            .iter()
            .map(|spec| {
                spec.url
                    .parse::<RelayUrl>()
                    .map(|url| (spec.id.clone(), url))
                    .map_err(|_| RunnerError::Scenario(format!("invalid relay URL {:?}", spec.url)))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let relay_resources = scenario
            .topology
            .relays
            .iter()
            .map(|_| backend.kernel().acquire_resource(ResourceKind::Relay, None))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            backend,
            capabilities,
            endpoints: BTreeMap::new(),
            connections: BTreeMap::new(),
            discovery,
            relay,
            relay_urls,
            relay_resources,
            use_discovery: scenario.requirements.discovery,
            specs: scenario
                .endpoints
                .iter()
                .cloned()
                .map(|spec| (spec.id.clone(), spec))
                .collect(),
        })
    }

    async fn bind_endpoint(&self, spec: &EndpointSpec) -> Result<Endpoint, RunnerError> {
        let secret = derive_material("iroh-sim endpoint identity v1", spec.identity_ordinal);
        let token = derive_material("iroh-sim token material v1", spec.identity_ordinal);
        let reset = derive_material("iroh-sim reset material v1", spec.identity_ordinal);
        let mut environment = self
            .backend
            .endpoint_environment(&spec.host, SimulationCryptoMaterial::new(token, reset))?;
        if let Some(relay) = &self.relay {
            environment = environment.with_relay_connector(Arc::new(relay.clone()));
        }
        if let Some(relay) = &spec.relay {
            let url = self
                .relay_urls
                .get(relay)
                .cloned()
                .ok_or_else(|| RunnerError::MissingRuntimeEntity(relay.clone()))?;
            environment = environment.with_preferred_relay(url);
        }
        let bind: SocketAddr = spec
            .bind
            .parse()
            .map_err(|_| RunnerError::Scenario(format!("invalid bind {:?}", spec.bind)))?;
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&secret))
            .alpns(vec![ALPN.to_vec()])
            .clear_ip_transports()
            .portmapper_config(PortmapperConfig::Disabled)
            .net_report_config(NetReportConfig::minimal())
            .simulation_environment_for_test(environment, UnsafeTestOnly::acknowledge());
        if spec.direct {
            builder = builder
                .bind_addr(bind)
                .map_err(|error| RunnerError::Endpoint(error.to_string()))?;
        }
        if self.relay.is_some() {
            builder = builder.relay_mode(RelayMode::Custom(RelayMap::from_iter(
                self.relay_urls.values().cloned(),
            )));
        }
        for provider in self.discovery.values() {
            builder = builder.address_lookup(provider.clone());
        }
        builder
            .bind()
            .await
            .map_err(|error| RunnerError::Endpoint(error.to_string()))
    }

    async fn connect(
        &mut self,
        action: &ScenarioAction,
    ) -> Result<Vec<ObservationKind>, RunnerError> {
        let ScenarioAction::Connect {
            client,
            server,
            connection,
        } = action
        else {
            unreachable!();
        };
        let client_endpoint = self
            .endpoints
            .get(client)
            .ok_or_else(|| RunnerError::MissingRuntimeEntity(client.clone()))?;
        let server_endpoint = self
            .endpoints
            .get(server)
            .ok_or_else(|| RunnerError::MissingRuntimeEntity(server.clone()))?;
        let server_id = server_endpoint.endpoint.id();
        let server_bind = server_endpoint.bind;
        let server_spec = self
            .specs
            .get(server)
            .expect("running endpoint has a validated specification");
        let mut server_address = EndpointAddr::new(server_id);
        if server_spec.direct && !self.use_discovery {
            server_address = server_address.with_ip_addr(server_bind);
        }
        if let Some(relay) = &server_spec.relay {
            server_address = server_address.with_relay_url(
                self.relay_urls
                    .get(relay)
                    .cloned()
                    .expect("validated endpoint relay"),
            );
        }
        let client_ep = client_endpoint.endpoint.clone();
        let server_ep = server_endpoint.endpoint.clone();
        let server_operation = async move {
            let incoming = server_ep
                .accept()
                .await
                .ok_or_else(|| "server endpoint closed".to_owned())?;
            incoming.await.map_err(|error| error.to_string())
        };
        let client_operation = async move {
            client_ep
                .connect(server_address, ALPN)
                .await
                .map_err(|error| error.to_string())
        };
        let (server_connection, client_connection) = self
            .backend
            .driver()
            .drive(async move {
                let (server, client) = tokio::join!(server_operation, client_operation);
                Ok::<_, String>((server?, client?))
            })
            .await??;
        let resource = self
            .backend
            .kernel()
            .acquire_resource(ResourceKind::Connection, None)?;
        let peer_identity = self
            .endpoints
            .get(server)
            .expect("server endpoint remains live")
            .endpoint
            .id()
            .to_string();
        self.connections.insert(
            connection.clone(),
            ConnectionPair {
                client: client_connection,
                server: server_connection,
                client_endpoint: client.clone(),
                server_endpoint: server.clone(),
                _resource: resource,
            },
        );
        Ok(vec![
            ObservationKind::ConnectionState {
                connection: ConnectionId::new(connection)?,
                owner: EndpointId::new(client)?,
                peer_identity: None,
                from: ConnectionState::Created,
                to: ConnectionState::Dialing,
            },
            ObservationKind::ConnectionState {
                connection: ConnectionId::new(connection)?,
                owner: EndpointId::new(client)?,
                peer_identity: Some(peer_identity),
                from: ConnectionState::Dialing,
                to: ConnectionState::Connected,
            },
        ])
    }

    async fn exchange(
        &mut self,
        action_id: &str,
        connection_id: &str,
        payload_bytes: u64,
        fill: u8,
        datagram: bool,
    ) -> Result<Vec<ObservationKind>, RunnerError> {
        let pair = self
            .connections
            .get(connection_id)
            .ok_or_else(|| RunnerError::MissingRuntimeEntity(connection_id.to_owned()))?;
        let client = pair.client.clone();
        let server = pair.server.clone();
        let source = EndpointId::new(&pair.client_endpoint)?;
        let destination = EndpointId::new(&pair.server_endpoint)?;
        let payload_len =
            usize::try_from(payload_bytes).map_err(|_| RunnerError::PayloadOverflow)?;
        let payload = vec![fill; payload_len];
        let expected = PayloadDigest::from_bytes(&payload);
        let relay_before = self
            .relay
            .as_ref()
            .map(RelayEnvironment::coverage)
            .unwrap_or_default();
        let _stream_resource = self
            .backend
            .kernel()
            .acquire_resource(ResourceKind::Stream, None)?;
        let exchange = if datagram {
            let server_operation = async move {
                let received = server
                    .read_datagram()
                    .await
                    .map_err(|error| error.to_string())?;
                server
                    .send_datagram(received.clone())
                    .map_err(|error| error.to_string())?;
                Ok::<_, String>(received.to_vec())
            };
            let client_operation = async move {
                client
                    .send_datagram(payload.into())
                    .map_err(|error| error.to_string())?;
                client
                    .read_datagram()
                    .await
                    .map(|bytes| bytes.to_vec())
                    .map_err(|error| error.to_string())
            };
            self.backend
                .driver()
                .drive(async move {
                    let (server, client) = tokio::join!(server_operation, client_operation);
                    Ok::<_, String>((server?, client?))
                })
                .await??
        } else {
            let server_operation = async move {
                let (mut send, mut receive) = server
                    .accept_bi()
                    .await
                    .map_err(|error| error.to_string())?;
                let received = receive
                    .read_to_end(payload_len.saturating_add(1))
                    .await
                    .map_err(|error| error.to_string())?;
                send.write_all(&received)
                    .await
                    .map_err(|error| error.to_string())?;
                send.finish().map_err(|error| error.to_string())?;
                Ok::<_, String>(received)
            };
            let client_operation = async move {
                let (mut send, mut receive) =
                    client.open_bi().await.map_err(|error| error.to_string())?;
                send.write_all(&payload)
                    .await
                    .map_err(|error| error.to_string())?;
                send.finish().map_err(|error| error.to_string())?;
                receive
                    .read_to_end(payload_len.saturating_add(1))
                    .await
                    .map_err(|error| error.to_string())
            };
            self.backend
                .driver()
                .drive(async move {
                    let (server, client) = tokio::join!(server_operation, client_operation);
                    Ok::<_, String>((server?, client?))
                })
                .await??
        };
        let stream = (!datagram)
            .then(|| StreamId::new(format!("{connection_id}/{action_id}")))
            .transpose()?;
        let relay_after = self
            .relay
            .as_ref()
            .map(RelayEnvironment::coverage)
            .unwrap_or_default();
        let routed_relay = relay_after.iter().find(|(relay, coverage)| {
            coverage.forwarded_packets
                > relay_before
                    .get(*relay)
                    .map_or(0, |before| before.forwarded_packets)
        });
        let selected_path = pair
            .client
            .paths()
            .iter()
            .find(|path| path.is_selected())
            .map(|path| (path.is_relay(), path.is_ip()));
        let path = PathId::new(if selected_path.is_some_and(|(relay, _)| relay) {
            "relay"
        } else if selected_path.is_some_and(|(_, ip)| ip) || routed_relay.is_none() {
            let server_bind = self
                .specs
                .get(&pair.server_endpoint)
                .and_then(|spec| spec.bind.parse::<SocketAddr>().ok())
                .ok_or_else(|| RunnerError::MissingRuntimeEntity(pair.server_endpoint.clone()))?;
            if server_bind.is_ipv4() {
                "direct_ipv4"
            } else {
                "direct_ipv6"
            }
        } else {
            "relay"
        })?;
        let mut observations = vec![ObservationKind::PathState {
            connection: ConnectionId::new(connection_id)?,
            path: path.clone(),
            active: true,
        }];
        if path.as_str() == "relay"
            && let Some((relay, coverage)) = routed_relay
        {
            observations.push(ObservationKind::RelayCoverage {
                relay: relay.clone(),
                connect_attempts: coverage.connect_attempts,
                authenticated_sessions: coverage.authenticated_sessions,
                forwarded_packets: coverage.forwarded_packets,
                dropped_packets: coverage.dropped_packets,
            });
        }
        observations.extend([
            ObservationKind::Delivery {
                connection: ConnectionId::new(connection_id)?,
                stream: stream.clone(),
                sequence: 0,
                source: source.clone(),
                destination: destination.clone(),
                intended_destination: destination.clone(),
                expected: expected.clone(),
                actual: PayloadDigest::from_bytes(&exchange.0),
            },
            ObservationKind::Delivery {
                connection: ConnectionId::new(connection_id)?,
                stream,
                sequence: 1,
                source: destination,
                destination: source.clone(),
                intended_destination: source,
                expected,
                actual: PayloadDigest::from_bytes(&exchange.1),
            },
        ]);
        Ok(observations)
    }

    async fn close_connection(
        &mut self,
        connection: &str,
    ) -> Result<Vec<ObservationKind>, RunnerError> {
        let pair = self
            .connections
            .remove(connection)
            .ok_or_else(|| RunnerError::MissingRuntimeEntity(connection.to_owned()))?;
        pair.client.close(0u32.into(), b"scenario close");
        pair.server.close(0u32.into(), b"scenario close");
        self.backend
            .driver()
            .drive(async { tokio::join!(pair.client.closed(), pair.server.closed()) })
            .await?;
        let owner = EndpointId::new(&pair.client_endpoint)?;
        drop(pair);
        Ok(vec![
            ObservationKind::ConnectionState {
                connection: ConnectionId::new(connection)?,
                owner: owner.clone(),
                peer_identity: None,
                from: ConnectionState::Connected,
                to: ConnectionState::Closing,
            },
            ObservationKind::ConnectionState {
                connection: ConnectionId::new(connection)?,
                owner,
                peer_identity: None,
                from: ConnectionState::Closing,
                to: ConnectionState::Closed,
            },
        ])
    }

    async fn stop_endpoint(&mut self, endpoint: &str) -> Result<Vec<ObservationKind>, RunnerError> {
        let running = self
            .endpoints
            .remove(endpoint)
            .ok_or_else(|| RunnerError::MissingRuntimeEntity(endpoint.to_owned()))?;
        self.backend
            .driver()
            .drive(running.endpoint.close())
            .await?;
        drop(running);
        Ok(vec![
            ObservationKind::EndpointState {
                endpoint: EndpointId::new(endpoint)?,
                from: EndpointState::Running,
                to: EndpointState::Stopping,
            },
            ObservationKind::EndpointState {
                endpoint: EndpointId::new(endpoint)?,
                from: EndpointState::Stopping,
                to: EndpointState::Stopped,
            },
        ])
    }
}

impl ScenarioBackend for DeterministicScenarioBackend {
    fn capabilities(&self) -> BackendCapabilities {
        self.capabilities.clone()
    }

    fn prepare<'a>(&'a mut self, scenario: &'a Scenario) -> BackendFuture<'a, ()> {
        Box::pin(async move {
            let network = self.backend.network();
            for host in &scenario.topology.hosts {
                network.add_host(&host.id)?;
            }
            for link in &scenario.topology.links {
                network.add_link(
                    &link.id,
                    link_config(link, &scenario.fault_rules, scenario)?,
                )?;
            }
            for host in &scenario.topology.hosts {
                for interface in &host.interfaces {
                    let addresses = interface
                        .addresses
                        .iter()
                        .map(|address| parse_cidr(address))
                        .collect::<Result<Vec<_>, _>>()?;
                    network.add_interface(&host.id, &interface.id, &interface.link, addresses)?;
                }
            }
            let mut remaining = scenario.topology.nats.iter().collect::<Vec<_>>();
            let mut installed = BTreeSet::new();
            while !remaining.is_empty() {
                let index = remaining
                    .iter()
                    .position(|nat| {
                        nat.upstream_nat
                            .as_ref()
                            .is_none_or(|upstream| installed.contains(upstream))
                    })
                    .ok_or_else(|| RunnerError::Scenario("cyclic NAT chain".to_owned()))?;
                let nat = remaining.remove(index);
                if let Some(firewall) = &nat.firewall {
                    let config = FirewallConfig {
                        id: firewall.id.clone(),
                        rules: firewall
                            .rules
                            .iter()
                            .map(|rule| {
                                Ok(FirewallRule {
                                    id: rule.id.clone(),
                                    protocol: rule.protocol,
                                    direction: rule.direction,
                                    source: rule.source.as_deref().map(parse_cidr).transpose()?,
                                    destination: rule
                                        .destination
                                        .as_deref()
                                        .map(parse_cidr)
                                        .transpose()?,
                                    source_ports: rule.source_ports,
                                    destination_ports: rule.destination_ports,
                                    connection_state: rule.connection_state,
                                    action: rule.action,
                                })
                            })
                            .collect::<Result<Vec<_>, RunnerError>>()?,
                        default_action: firewall.default_action,
                    };
                    if let Some(upstream) = &nat.upstream_nat {
                        network.add_chained_nat_with_firewall(
                            &nat.inside_host,
                            upstream,
                            nat_config(nat)?,
                            config,
                        )?;
                    } else {
                        network.add_nat_with_firewall(
                            &nat.inside_host,
                            nat_config(nat)?,
                            config,
                        )?;
                    }
                } else if let Some(upstream) = &nat.upstream_nat {
                    network.add_chained_nat(&nat.inside_host, upstream, nat_config(nat)?)?;
                } else {
                    network.add_nat(&nat.inside_host, nat_config(nat)?)?;
                }
                installed.insert(nat.id.clone());
            }
            Ok(())
        })
    }

    fn execute<'a>(
        &'a mut self,
        action: &'a ActionSpec,
    ) -> BackendFuture<'a, Vec<ObservationKind>> {
        Box::pin(async move {
            match &action.action {
                ScenarioAction::StartEndpoint { endpoint } => {
                    let spec = self
                        .specs
                        .get(endpoint)
                        .cloned()
                        .ok_or_else(|| RunnerError::MissingRuntimeEntity(endpoint.clone()))?;
                    let bound = self.bind_endpoint(&spec).await?;
                    self.endpoints.insert(
                        endpoint.clone(),
                        RunningEndpoint {
                            endpoint: bound,
                            bind: spec.bind.parse().expect("validated scenario bind"),
                        },
                    );
                    Ok(vec![ObservationKind::EndpointState {
                        endpoint: EndpointId::new(endpoint)?,
                        from: EndpointState::Created,
                        to: EndpointState::Running,
                    }])
                }
                ScenarioAction::StopEndpoint { endpoint } => self.stop_endpoint(endpoint).await,
                action @ ScenarioAction::Connect { .. } => self.connect(action).await,
                ScenarioAction::StreamRoundTrip {
                    connection,
                    payload,
                } => {
                    self.exchange(&action.id, connection, payload.bytes, payload.fill, false)
                        .await
                }
                ScenarioAction::DatagramRoundTrip {
                    connection,
                    payload,
                } => {
                    self.exchange(&action.id, connection, payload.bytes, payload.fill, true)
                        .await
                }
                ScenarioAction::CloseConnection { connection } => {
                    self.close_connection(connection).await
                }
                ScenarioAction::Partition { link, from, to } => {
                    self.backend.network().set_partition(link, from, to, true)?;
                    Ok(Vec::new())
                }
                ScenarioAction::Heal { link, from, to } => {
                    self.backend
                        .network()
                        .set_partition(link, from, to, false)?;
                    Ok(Vec::new())
                }
                ScenarioAction::SetLink {
                    link,
                    latency_nanos,
                    mtu,
                } => {
                    self.backend.network().update_link(
                        link,
                        latency_nanos.map(Duration::from_nanos),
                        *mtu,
                    )?;
                    Ok(Vec::new())
                }
                ScenarioAction::AdvanceTime { by_nanos } => {
                    let target = self
                        .virtual_time_nanos()?
                        .checked_add(*by_nanos)
                        .ok_or(RunnerError::TimelineOverflow)?;
                    self.advance_to(target).await?;
                    Ok(Vec::new())
                }
                ScenarioAction::ExpectFailure { .. } => Ok(Vec::new()),
                ScenarioAction::NatChange {
                    nat,
                    public_ip,
                    preserve_ports,
                } => {
                    let public_ip: Ipv4Addr = public_ip.parse().map_err(|_| {
                        RunnerError::Scenario(format!("invalid NAT address {public_ip:?}"))
                    })?;
                    self.backend.rebind_nat(nat, public_ip, *preserve_ports)?;
                    Ok(Vec::new())
                }
                ScenarioAction::PortMap { endpoint, active } => {
                    let host = self
                        .specs
                        .get(endpoint)
                        .ok_or_else(|| RunnerError::MissingRuntimeEntity(endpoint.clone()))?
                        .host
                        .clone();
                    let external = self.backend.set_port_mapping(&host, *active)?;
                    self.backend.driver().drive_one().await?;
                    Ok(vec![ObservationKind::PortMappingState {
                        endpoint: EndpointId::new(endpoint)?,
                        active: *active,
                        external: external.map(|address| address.to_string()),
                    }])
                }
                ScenarioAction::DiscoveryUpdate {
                    provider,
                    record,
                    endpoint,
                    addresses,
                    delay_nanos,
                    ttl_nanos,
                    state,
                } => {
                    let spec = self
                        .specs
                        .get(endpoint)
                        .ok_or_else(|| RunnerError::MissingRuntimeEntity(endpoint.clone()))?;
                    let endpoint_id = self
                        .endpoints
                        .get(endpoint)
                        .map(|running| running.endpoint.id())
                        .unwrap_or_else(|| {
                            SecretKey::from_bytes(&derive_material(
                                "iroh-sim endpoint identity v1",
                                spec.identity_ordinal,
                            ))
                            .public()
                        });
                    let provider_state = self
                        .discovery
                        .get(provider)
                        .ok_or_else(|| RunnerError::MissingRuntimeEntity(provider.clone()))?;
                    let snapshot = match state {
                        DiscoveryRecordState::Published | DiscoveryRecordState::Failed => {
                            let addresses = addresses
                                .iter()
                                .map(|address| {
                                    address.parse::<SocketAddr>().map_err(|_| {
                                        RunnerError::Scenario(format!(
                                            "invalid discovery address {address:?}"
                                        ))
                                    })
                                })
                                .collect::<Result<Vec<_>, _>>()?;
                            provider_state.publish(
                                record,
                                endpoint,
                                endpoint_id,
                                addresses,
                                *delay_nanos,
                                *ttl_nanos,
                                state == &DiscoveryRecordState::Failed,
                            )?
                        }
                        DiscoveryRecordState::Withdrawn => {
                            provider_state.withdraw(record, endpoint)?
                        }
                    };
                    Ok(vec![ObservationKind::DiscoveryRecordState {
                        provider: provider.clone(),
                        record: record.clone(),
                        endpoint: EndpointId::new(endpoint)?,
                        state: format!("{state:?}").to_ascii_lowercase(),
                        addresses: snapshot.addresses.iter().map(ToString::to_string).collect(),
                        available_nanos: snapshot.available_nanos,
                        expires_nanos: snapshot.expires_nanos,
                    }])
                }
                ScenarioAction::InterfaceChange {
                    host,
                    interface,
                    up,
                } => {
                    self.backend.set_interface_up(host, interface, *up)?;
                    self.backend.driver().drive_one().await?;
                    Ok(vec![ObservationKind::InterfaceState {
                        host: host.clone(),
                        interface: interface.clone(),
                        up: *up,
                    }])
                }
                ScenarioAction::AddressChange {
                    host,
                    interface,
                    address,
                    present,
                } => {
                    self.backend.set_interface_address(
                        host,
                        interface,
                        parse_cidr(address)?,
                        *present,
                    )?;
                    self.backend.driver().drive_one().await?;
                    Ok(vec![ObservationKind::InterfaceAddress {
                        host: host.clone(),
                        interface: interface.clone(),
                        address: address.clone(),
                        present: *present,
                    }])
                }
                ScenarioAction::HostSleep { host, sleeping } => {
                    self.backend.set_host_sleeping(host, *sleeping)?;
                    self.backend.driver().drive_one().await?;
                    Ok(vec![ObservationKind::HostPower {
                        host: host.clone(),
                        sleeping: *sleeping,
                    }])
                }
                ScenarioAction::RouteChange {
                    host,
                    route,
                    destination,
                    interface,
                    next_hop,
                    active,
                } => {
                    self.backend.set_route(
                        host,
                        route,
                        parse_cidr(destination)?,
                        interface,
                        next_hop.as_deref(),
                        *active,
                    )?;
                    self.backend.driver().drive_one().await?;
                    Ok(vec![ObservationKind::RouteState {
                        host: host.clone(),
                        route: route.clone(),
                        active: *active,
                    }])
                }
                ScenarioAction::RelayLifecycle { relay, online } => {
                    let environment = self
                        .relay
                        .as_ref()
                        .ok_or_else(|| RunnerError::MissingRuntimeEntity(relay.clone()))?;
                    let lifecycle_environment = environment.clone();
                    let lifecycle_relay = relay.clone();
                    let lifecycle_online = *online;
                    self.backend
                        .driver()
                        .drive(async move {
                            lifecycle_environment
                                .set_online(&lifecycle_relay, lifecycle_online)
                                .await
                        })
                        .await
                        .map_err(RunnerError::Driver)?
                        .map_err(|error| RunnerError::Endpoint(error.to_string()))?;
                    let generation = environment
                        .generation(relay)
                        .map_err(|error| RunnerError::Endpoint(error.to_string()))?;
                    let sessions = environment
                        .session_count(relay)
                        .map_err(|error| RunnerError::Endpoint(error.to_string()))?;
                    Ok(vec![ObservationKind::RelayState {
                        relay: relay.clone(),
                        online: *online,
                        generation,
                        sessions: u64::try_from(sessions)
                            .map_err(|_| RunnerError::ObservationOverflow)?,
                    }])
                }
            }
        })
    }

    fn advance_to(&mut self, deadline_nanos: u64) -> BackendFuture<'_, ()> {
        Box::pin(async move {
            let kernel = self.backend.kernel().clone();
            kernel.schedule_at(
                Duration::from_nanos(deadline_nanos),
                EventClass::Infrastructure,
                || Ok(()),
            )?;
            self.backend
                .driver()
                .drive_until(|| kernel.now() >= Duration::from_nanos(deadline_nanos))
                .await?;
            Ok(())
        })
    }

    fn shutdown(&mut self) -> BackendFuture<'_, Vec<ObservationKind>> {
        Box::pin(async move {
            let mut observations = Vec::new();
            let connections = std::mem::take(&mut self.connections);
            for (id, pair) in connections {
                pair.client.close(0u32.into(), b"scenario shutdown");
                pair.server.close(0u32.into(), b"scenario shutdown");
                self.backend
                    .driver()
                    .drive(async { tokio::join!(pair.client.closed(), pair.server.closed()) })
                    .await?;
                observations.extend([
                    ObservationKind::ConnectionState {
                        connection: ConnectionId::new(&id)?,
                        owner: EndpointId::new(&pair.client_endpoint)?,
                        peer_identity: None,
                        from: ConnectionState::Connected,
                        to: ConnectionState::Closing,
                    },
                    ObservationKind::ConnectionState {
                        connection: ConnectionId::new(&id)?,
                        owner: EndpointId::new(&pair.client_endpoint)?,
                        peer_identity: None,
                        from: ConnectionState::Closing,
                        to: ConnectionState::Closed,
                    },
                ]);
            }
            let endpoints = std::mem::take(&mut self.endpoints);
            for (id, running) in endpoints {
                self.backend
                    .driver()
                    .drive(running.endpoint.close())
                    .await?;
                observations.extend([
                    ObservationKind::EndpointState {
                        endpoint: EndpointId::new(&id)?,
                        from: EndpointState::Running,
                        to: EndpointState::Stopping,
                    },
                    ObservationKind::EndpointState {
                        endpoint: EndpointId::new(&id)?,
                        from: EndpointState::Stopping,
                        to: EndpointState::Stopped,
                    },
                ]);
            }
            self.backend.network().clear_nats()?;
            for provider in self.discovery.values() {
                provider.clear()?;
            }
            if let Some(relay) = &self.relay {
                self.backend.driver().drive(relay.shutdown()).await?;
            }
            self.relay_resources.clear();
            self.backend
                .driver()
                .drive_until(|| self.backend.kernel().ledger().is_empty())
                .await?;
            Ok(observations)
        })
    }

    fn virtual_time_nanos(&self) -> Result<u64, RunnerError> {
        u64::try_from(self.backend.kernel().now().as_nanos())
            .map_err(|_| RunnerError::TimelineOverflow)
    }

    fn resource_snapshot(&self) -> ResourceLedgerSnapshot {
        self.backend.kernel().ledger()
    }

    fn scheduler_snapshot(&self) -> Option<KernelSchedulerSnapshot> {
        Some(self.backend.kernel().scheduler_snapshot())
    }

    fn task_ownership_snapshot(&self) -> Vec<KernelTaskSnapshot> {
        self.backend.kernel().task_ownership_snapshot()
    }

    fn trace(&self, context: TraceContext, event: TraceEventKind) -> Result<(), RunnerError> {
        self.backend.runtime_context().trace().record(
            self.virtual_time_nanos()?,
            context,
            event,
        )?;
        Ok(())
    }
}

fn check_capabilities(
    required: &ScenarioRequirements,
    actual: &BackendCapabilities,
) -> Result<(), RunnerError> {
    let mut missing = Vec::new();
    if required.controlled_runtime && !actual.controlled_runtime {
        missing.push("controlled_runtime");
    }
    if required.virtual_time && !actual.virtual_time {
        missing.push("virtual_time");
    }
    if required.synthetic_ip && !actual.synthetic_ip {
        missing.push("synthetic_ip");
    }
    if required.nat && !actual.nat {
        missing.push("nat");
    }
    if required.relay && !actual.relay {
        missing.push("relay");
    }
    if required.discovery && !actual.discovery {
        missing.push("discovery");
    }
    if required.mobility && !actual.mobility {
        missing.push("mobility");
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(RunnerError::UnsupportedCapabilities(missing))
    }
}

fn link_config(
    link: &LinkSpec,
    faults: &[FaultRule],
    scenario: &Scenario,
) -> Result<LinkConfig, RunnerError> {
    let mut config = LinkConfig {
        latency: Duration::from_nanos(link.latency_nanos),
        bits_per_second: link.bits_per_second,
        mtu: link.mtu,
        queue_packets: link.queue_packets,
        ..LinkConfig::default()
    };
    for rule in faults.iter().filter(|rule| rule.link == link.id) {
        if rule.start_nanos != 0
            || rule.end_nanos != scenario.budgets.max_virtual_time_nanos
            || rule.max_applications != u64::MAX
        {
            return Err(RunnerError::UnsupportedFaultRule(rule.id.clone()));
        }
        match rule.effect {
            PacketFault::Loss => config.loss_per_million = rule.probability_per_million,
            PacketFault::Duplication => {
                config.duplicate_per_million = rule.probability_per_million;
            }
            PacketFault::Corruption => {
                config.corrupt_per_million = rule.probability_per_million;
            }
            PacketFault::Reorder => config.reorder_window = Duration::from_millis(5),
            PacketFault::Delay | PacketFault::MtuReduction => {
                return Err(RunnerError::UnsupportedFaultRule(rule.id.clone()));
            }
        }
    }
    Ok(config)
}

fn nat_config(nat: &NatSpec) -> Result<NatConfig, RunnerError> {
    Ok(NatConfig {
        id: nat.id.clone(),
        public_ip: nat.public_ip.parse().map_err(|_| {
            RunnerError::Scenario(format!("invalid NAT address {:?}", nat.public_ip))
        })?,
        port_start: nat.port_start,
        port_end: nat.port_end,
        mapping_behavior: nat.mapping_behavior,
        filtering_behavior: nat.filtering_behavior,
        mapping_ttl: Duration::from_nanos(nat.mapping_ttl_nanos),
        hairpin: nat.hairpin,
        max_mappings: nat.max_mappings,
    })
}

fn parse_cidr(value: &str) -> Result<IpCidr, RunnerError> {
    let (ip, prefix) = value
        .split_once('/')
        .ok_or_else(|| RunnerError::Scenario(format!("invalid CIDR {value:?}")))?;
    let ip: IpAddr = ip
        .parse()
        .map_err(|_| RunnerError::Scenario(format!("invalid CIDR {value:?}")))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| RunnerError::Scenario(format!("invalid CIDR {value:?}")))?;
    Ok(IpCidr::new(ip, prefix)?)
}

fn derive_material(context: &str, ordinal: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(&ordinal.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn action_kind(action: &ScenarioAction) -> &'static str {
    match action {
        ScenarioAction::StartEndpoint { .. } => "start_endpoint",
        ScenarioAction::StopEndpoint { .. } => "stop_endpoint",
        ScenarioAction::Connect { .. } => "connect",
        ScenarioAction::StreamRoundTrip { .. } => "stream_round_trip",
        ScenarioAction::DatagramRoundTrip { .. } => "datagram_round_trip",
        ScenarioAction::CloseConnection { .. } => "close_connection",
        ScenarioAction::Partition { .. } => "partition",
        ScenarioAction::Heal { .. } => "heal",
        ScenarioAction::SetLink { .. } => "set_link",
        ScenarioAction::AdvanceTime { .. } => "advance_time",
        ScenarioAction::ExpectFailure { .. } => "expect_failure",
        ScenarioAction::NatChange { .. } => "nat_change",
        ScenarioAction::PortMap { .. } => "port_map",
        ScenarioAction::RelayLifecycle { .. } => "relay_lifecycle",
        ScenarioAction::DiscoveryUpdate { .. } => "discovery_update",
        ScenarioAction::InterfaceChange { .. } => "interface_change",
        ScenarioAction::AddressChange { .. } => "address_change",
        ScenarioAction::HostSleep { .. } => "host_sleep",
        ScenarioAction::RouteChange { .. } => "route_change",
    }
}

const ALL_RESOURCE_KINDS: [ResourceKind; 10] = [
    ResourceKind::Task,
    ResourceKind::Timer,
    ResourceKind::Socket,
    ResourceKind::QueuedPacket,
    ResourceKind::Connection,
    ResourceKind::Stream,
    ResourceKind::Mapping,
    ResourceKind::DiscoveryRecord,
    ResourceKind::Relay,
    ResourceKind::TraceBuffer,
];

fn resource_limit(scenario: &Scenario, kind: ResourceKind) -> u64 {
    match kind {
        ResourceKind::Task => scenario.budgets.max_tasks,
        ResourceKind::QueuedPacket => scenario.budgets.max_packets,
        ResourceKind::TraceBuffer => scenario.budgets.max_trace_events,
        ResourceKind::Socket
        | ResourceKind::Connection
        | ResourceKind::Stream
        | ResourceKind::Mapping
        | ResourceKind::DiscoveryRecord
        | ResourceKind::Relay
        | ResourceKind::Timer => scenario.budgets.max_actions.max(1),
    }
}

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

/// Declarative model, backend, action, invariant, or cleanup failure.
#[derive(Debug)]
pub enum RunnerError {
    Scenario(String),
    UnsupportedCapabilities(Vec<&'static str>),
    UnsupportedAction(&'static str),
    UnsupportedFaultRule(String),
    MissingRuntimeEntity(String),
    TriggerStall(Vec<String>),
    ModelState {
        entity: String,
        expected: String,
        actual: String,
    },
    ModelMismatch {
        action: String,
        expected: String,
        actual: String,
    },
    Endpoint(String),
    Operation(String),
    Invariant(InvariantFailure),
    InvariantEngine(InvariantError),
    ResourceLeak(ResourceLedgerSnapshot),
    TerminalNotAllowed(&'static str),
    CleanupAfterFailure {
        primary: String,
        cleanup: String,
    },
    TimelineOverflow,
    ObservationOverflow,
    PayloadOverflow,
    Encoding(String),
    Backend(crate::BackendError),
    Network(crate::NetworkError),
    Driver(crate::KernelDriverError),
    Kernel(crate::KernelError),
    Ledger(crate::LedgerError),
    Trace(TraceRecordError),
    Observation(crate::ObservationError),
    Discovery(crate::DiscoveryError),
}

impl fmt::Display for RunnerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scenario(error) => write!(f, "scenario is invalid: {error}"),
            Self::UnsupportedCapabilities(values) => {
                write!(f, "backend lacks capabilities: {}", values.join(","))
            }
            Self::UnsupportedAction(value) => write!(f, "backend does not support action {value}"),
            Self::UnsupportedFaultRule(value) => {
                write!(f, "backend does not support fault rule {value:?}")
            }
            Self::MissingRuntimeEntity(value) => write!(f, "runtime entity {value:?} is not live"),
            Self::TriggerStall(values) => {
                write!(f, "scenario triggers stalled: {}", values.join(","))
            }
            Self::ModelState {
                entity,
                expected,
                actual,
            } => write!(
                f,
                "model state mismatch for {entity:?}: expected {expected}, got {actual}"
            ),
            Self::ModelMismatch {
                action,
                expected,
                actual,
            } => write!(
                f,
                "model outcome mismatch for {action:?}: expected {expected}, got {actual}"
            ),
            Self::Endpoint(error) => write!(f, "endpoint operation failed: {error}"),
            Self::Operation(error) => write!(f, "application operation failed: {error}"),
            Self::Invariant(failure) => write!(f, "invariant {:?} failed", failure.name),
            Self::InvariantEngine(error) => write!(f, "invariant engine failed: {error}"),
            Self::ResourceLeak(snapshot) => write!(f, "scenario leaked resources: {snapshot:?}"),
            Self::TerminalNotAllowed(terminal) => {
                write!(f, "scenario terminal {terminal:?} is not allowed")
            }
            Self::CleanupAfterFailure { primary, cleanup } => write!(
                f,
                "scenario failed ({primary}) and cleanup failed ({cleanup})"
            ),
            Self::TimelineOverflow => f.write_str("scenario timeline overflow"),
            Self::ObservationOverflow => f.write_str("scenario observation sequence overflow"),
            Self::PayloadOverflow => f.write_str("scenario payload does not fit memory size"),
            Self::Encoding(error) => write!(f, "scenario artifact encoding failed: {error}"),
            Self::Backend(error) => error.fmt(f),
            Self::Network(error) => error.fmt(f),
            Self::Driver(error) => error.fmt(f),
            Self::Kernel(error) => error.fmt(f),
            Self::Ledger(error) => error.fmt(f),
            Self::Trace(error) => error.fmt(f),
            Self::Observation(error) => error.fmt(f),
            Self::Discovery(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for RunnerError {}

macro_rules! from_error {
    ($source:ty, $variant:ident) => {
        impl From<$source> for RunnerError {
            fn from(value: $source) -> Self {
                Self::$variant(value)
            }
        }
    };
}

from_error!(crate::BackendError, Backend);
from_error!(crate::NetworkError, Network);
from_error!(crate::KernelDriverError, Driver);
from_error!(crate::KernelError, Kernel);
from_error!(crate::LedgerError, Ledger);
from_error!(TraceRecordError, Trace);
from_error!(crate::ObservationError, Observation);
from_error!(crate::DiscoveryError, Discovery);

impl From<InvariantError> for RunnerError {
    fn from(value: InvariantError) -> Self {
        match value {
            InvariantError::Failure(failure) => Self::Invariant(failure),
            other => Self::InvariantEngine(other),
        }
    }
}

impl From<String> for RunnerError {
    fn from(value: String) -> Self {
        Self::Operation(value)
    }
}
