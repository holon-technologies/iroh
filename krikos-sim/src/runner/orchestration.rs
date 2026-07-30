use super::*;

pub(super) type BackendFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, RunnerError>> + 'a>>;

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
            krikos::simulation::SimulationCryptoMode::DeterministicTest,
        )
    }

    /// Creates the deterministic backend with an explicit simulation cryptography lane.
    pub fn with_crypto_mode(
        scenario: Scenario,
        root_seed: RootSeed,
        wall_epoch: SystemTime,
        trace: Arc<dyn TraceSink>,
        crypto_mode: krikos::simulation::SimulationCryptoMode,
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
        let advance_by = match action.action {
            ScenarioAction::AdvanceTime { by_nanos } => Some(by_nanos),
            ScenarioAction::Sleep { duration_nanos } => Some(duration_nanos),
            ScenarioAction::AssertNoDatagram { duration_nanos, .. } => Some(duration_nanos),
            _ => None,
        };
        if let Some(by_nanos) = advance_by {
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
