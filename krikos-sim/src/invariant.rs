//! Deterministically ordered continuous safety, liveness, and cleanup invariants.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    ConnectionId, ConnectionState, EndpointId, EndpointState, FairnessAssumption, InvariantName,
    InvariantSpec, Observation, ObservationError, ObservationKind, ResourceKind, Scenario,
    StreamId,
};

/// Invariant evaluation class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantClass {
    Safety,
    BoundedLiveness,
    Cleanup,
}

/// Structured, stable evidence for the first invariant failure.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvariantFailure {
    pub name: InvariantName,
    pub class: InvariantClass,
    pub observation_sequence: u64,
    pub virtual_time_nanos: u64,
    pub entities: Vec<String>,
    pub evidence: BTreeMap<String, String>,
}

/// Observable obligation transition for trace/report integration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InvariantTransition {
    Registered {
        invariant: InvariantName,
        obligation: String,
        deadline_nanos: u64,
        event_deadline: u64,
    },
    Satisfied {
        invariant: InvariantName,
        obligation: String,
    },
}

/// Terminal invariant state stored with run artifacts.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvariantSnapshot {
    pub observations: u64,
    pub active_obligations: Vec<String>,
    pub resources: BTreeMap<ResourceKind, u64>,
}

#[derive(Clone, Debug)]
struct Obligation {
    connection: ConnectionId,
    deadline_nanos: u64,
    event_deadline: u64,
    fairness: Vec<FairnessAssumption>,
}

/// Continuous invariant registry. It observes state but has no mutation capability.
#[derive(Clone, Debug)]
pub struct InvariantRegistry {
    enabled: BTreeMap<InvariantName, InvariantSpec>,
    max_obligations: u64,
    last_sequence: u64,
    last_virtual_time: u64,
    peer_identities: BTreeMap<ConnectionId, String>,
    endpoint_states: BTreeMap<EndpointId, EndpointState>,
    connection_states: BTreeMap<ConnectionId, ConnectionState>,
    stream_next: BTreeMap<StreamId, u64>,
    resources: BTreeMap<ResourceKind, u64>,
    obligations: BTreeMap<String, Obligation>,
    fairness: BTreeMap<FairnessAssumption, bool>,
    relay_connections: BTreeSet<ConnectionId>,
    failure: Option<InvariantFailure>,
}

impl InvariantRegistry {
    /// Builds a registry from the scenario's validated invariant and fairness declarations.
    pub fn from_scenario(scenario: &Scenario) -> Result<Self, InvariantError> {
        scenario
            .validate()
            .map_err(|error| InvariantError::Configuration(error.to_string()))?;
        let enabled = scenario
            .invariants
            .iter()
            .cloned()
            .map(|spec| (spec.name, spec))
            .collect();
        let fairness = scenario
            .fairness
            .iter()
            .copied()
            .map(|assumption| (assumption, true))
            .collect();
        Ok(Self {
            enabled,
            max_obligations: scenario.budgets.max_obligations,
            last_sequence: 0,
            last_virtual_time: 0,
            peer_identities: BTreeMap::new(),
            endpoint_states: BTreeMap::new(),
            connection_states: BTreeMap::new(),
            stream_next: BTreeMap::new(),
            resources: BTreeMap::new(),
            obligations: BTreeMap::new(),
            fairness,
            relay_connections: BTreeSet::new(),
            failure: None,
        })
    }

    /// Changes a declared fairness fact as the environment becomes reachable/unreachable.
    pub fn set_fairness(&mut self, assumption: FairnessAssumption, satisfied: bool) {
        self.fairness.insert(assumption, satisfied);
    }

    /// Evaluates every enabled matching invariant in stable name order.
    pub fn observe(
        &mut self,
        observation: Observation,
    ) -> Result<Vec<InvariantTransition>, InvariantError> {
        if let Some(failure) = &self.failure {
            return Err(InvariantError::AlreadyFailed(failure.clone()));
        }
        observation
            .validate()
            .map_err(InvariantError::Observation)?;
        if observation.sequence <= self.last_sequence
            || observation.virtual_time_nanos < self.last_virtual_time
        {
            return Err(InvariantError::NonMonotonicObservation);
        }

        let mut transitions = Vec::new();
        let names: Vec<_> = self.enabled.keys().copied().collect();
        for name in names {
            match name {
                InvariantName::AuthenticationIdentity => {
                    self.check_authentication(&observation)?;
                }
                InvariantName::DeliveryIntegrity => self.check_delivery_integrity(&observation)?,
                InvariantName::DeliveryOrdering => self.check_delivery_ordering(&observation)?,
                InvariantName::MonotonicLifecycle => self.check_lifecycle(&observation)?,
                InvariantName::ResourceCeiling => self.check_resource_ceiling(&observation)?,
                InvariantName::ReachableConnectLiveness => {
                    transitions.extend(self.update_connect_liveness(&observation)?);
                }
                InvariantName::ResourceCleanup => {}
                InvariantName::RelayRouting => self.check_relay_routing(&observation)?,
            }
        }
        if let ObservationKind::Resource { kind, current, .. } = observation.kind {
            self.resources.insert(kind, current);
        }
        self.last_sequence = observation.sequence;
        self.last_virtual_time = observation.virtual_time_nanos;
        self.expire_obligations(observation.virtual_time_nanos, observation.sequence)?;
        Ok(transitions)
    }

    /// Checks obligations before the kernel advances to a later deadline.
    pub fn check_before_time_advance(
        &mut self,
        target_virtual_time_nanos: u64,
        event_count: u64,
    ) -> Result<(), InvariantError> {
        if target_virtual_time_nanos < self.last_virtual_time || event_count < self.last_sequence {
            return Err(InvariantError::NonMonotonicObservation);
        }
        self.expire_obligations(target_virtual_time_nanos, event_count)
    }

    /// Runs terminal bounded-liveness and cleanup checks and returns the stable snapshot.
    pub fn finish(
        &mut self,
        virtual_time_nanos: u64,
        event_count: u64,
    ) -> Result<InvariantSnapshot, InvariantError> {
        self.check_before_time_advance(virtual_time_nanos, event_count)?;
        if self.enabled.contains_key(&InvariantName::ResourceCleanup) {
            let live: Vec<_> = self
                .resources
                .iter()
                .filter(|(_, current)| **current != 0)
                .map(|(kind, current)| (format!("{kind:?}"), *current))
                .collect();
            if !live.is_empty() {
                let evidence = live
                    .iter()
                    .map(|(kind, current)| (kind.clone(), current.to_string()))
                    .collect();
                return self.fail(InvariantFailure {
                    name: InvariantName::ResourceCleanup,
                    class: InvariantClass::Cleanup,
                    observation_sequence: event_count,
                    virtual_time_nanos,
                    entities: live.into_iter().map(|(kind, _)| kind).collect(),
                    evidence,
                });
            }
        }
        Ok(self.snapshot())
    }

    /// Returns the current observation, obligation, and resource state.
    pub fn snapshot(&self) -> InvariantSnapshot {
        InvariantSnapshot {
            observations: self.last_sequence,
            active_obligations: self.obligations.keys().cloned().collect(),
            resources: self.resources.clone(),
        }
    }

    fn check_authentication(&mut self, observation: &Observation) -> Result<(), InvariantError> {
        let ObservationKind::ConnectionState {
            connection,
            peer_identity: Some(identity),
            ..
        } = &observation.kind
        else {
            return Ok(());
        };
        if let Some(previous) = self.peer_identities.get(connection)
            && previous != identity
        {
            return self.fail(InvariantFailure {
                name: InvariantName::AuthenticationIdentity,
                class: InvariantClass::Safety,
                observation_sequence: observation.sequence,
                virtual_time_nanos: observation.virtual_time_nanos,
                entities: vec![connection.to_string()],
                evidence: BTreeMap::from([
                    ("previous_identity".to_owned(), previous.clone()),
                    ("observed_identity".to_owned(), identity.clone()),
                ]),
            });
        }
        self.peer_identities
            .entry(connection.clone())
            .or_insert_with(|| identity.clone());
        Ok(())
    }

    fn check_delivery_integrity(
        &mut self,
        observation: &Observation,
    ) -> Result<(), InvariantError> {
        let ObservationKind::Delivery {
            connection,
            destination,
            intended_destination,
            expected,
            actual,
            ..
        } = &observation.kind
        else {
            return Ok(());
        };
        let misdelivery = destination != intended_destination;
        let corruption = expected != actual;
        if misdelivery || corruption {
            return self.fail(InvariantFailure {
                name: InvariantName::DeliveryIntegrity,
                class: InvariantClass::Safety,
                observation_sequence: observation.sequence,
                virtual_time_nanos: observation.virtual_time_nanos,
                entities: vec![connection.to_string(), destination.to_string()],
                evidence: BTreeMap::from([
                    ("misdelivery".to_owned(), misdelivery.to_string()),
                    ("corruption".to_owned(), corruption.to_string()),
                    ("expected_hash".to_owned(), expected.as_str().to_owned()),
                    ("actual_hash".to_owned(), actual.as_str().to_owned()),
                ]),
            });
        }
        Ok(())
    }

    fn check_delivery_ordering(&mut self, observation: &Observation) -> Result<(), InvariantError> {
        let ObservationKind::Delivery {
            stream: Some(stream),
            sequence,
            ..
        } = &observation.kind
        else {
            return Ok(());
        };
        let expected = self.stream_next.get(stream).copied().unwrap_or(0);
        if *sequence != expected {
            return self.fail(InvariantFailure {
                name: InvariantName::DeliveryOrdering,
                class: InvariantClass::Safety,
                observation_sequence: observation.sequence,
                virtual_time_nanos: observation.virtual_time_nanos,
                entities: vec![stream.to_string()],
                evidence: BTreeMap::from([
                    ("expected_sequence".to_owned(), expected.to_string()),
                    ("observed_sequence".to_owned(), sequence.to_string()),
                ]),
            });
        }
        self.stream_next.insert(
            stream.clone(),
            expected
                .checked_add(1)
                .ok_or(InvariantError::SequenceOverflow)?,
        );
        Ok(())
    }

    fn check_lifecycle(&mut self, observation: &Observation) -> Result<(), InvariantError> {
        match &observation.kind {
            ObservationKind::EndpointState { endpoint, from, to } => {
                let tracked = self.endpoint_states.get(endpoint).copied().unwrap_or(*from);
                if tracked != *from || !valid_endpoint_transition(*from, *to) {
                    return self.lifecycle_failure(
                        observation,
                        endpoint.to_string(),
                        format!("{from:?}"),
                        format!("{to:?}"),
                    );
                }
                self.endpoint_states.insert(endpoint.clone(), *to);
            }
            ObservationKind::ConnectionState {
                connection,
                from,
                to,
                ..
            } => {
                let tracked = self
                    .connection_states
                    .get(connection)
                    .copied()
                    .unwrap_or(*from);
                if tracked != *from || !valid_connection_transition(*from, *to) {
                    return self.lifecycle_failure(
                        observation,
                        connection.to_string(),
                        format!("{from:?}"),
                        format!("{to:?}"),
                    );
                }
                self.connection_states.insert(connection.clone(), *to);
            }
            _ => {}
        }
        Ok(())
    }

    fn check_relay_routing(&mut self, observation: &Observation) -> Result<(), InvariantError> {
        match &observation.kind {
            ObservationKind::PathState {
                connection,
                path,
                active,
            } if path.as_str().starts_with("relay") => {
                if *active {
                    self.relay_connections.insert(connection.clone());
                } else {
                    self.relay_connections.remove(connection);
                }
            }
            ObservationKind::Delivery {
                connection,
                source,
                destination,
                intended_destination,
                ..
            } if self.relay_connections.contains(connection)
                && (destination != intended_destination || source == destination) =>
            {
                return self.fail(InvariantFailure {
                    name: InvariantName::RelayRouting,
                    class: InvariantClass::Safety,
                    observation_sequence: observation.sequence,
                    virtual_time_nanos: observation.virtual_time_nanos,
                    entities: vec![connection.to_string()],
                    evidence: BTreeMap::from([
                        ("source".to_owned(), source.to_string()),
                        ("destination".to_owned(), destination.to_string()),
                        (
                            "intended_destination".to_owned(),
                            intended_destination.to_string(),
                        ),
                    ]),
                });
            }
            ObservationKind::RelayState {
                relay,
                online: false,
                sessions,
                ..
            } if *sessions != 0 => {
                return self.fail(InvariantFailure {
                    name: InvariantName::RelayRouting,
                    class: InvariantClass::Safety,
                    observation_sequence: observation.sequence,
                    virtual_time_nanos: observation.virtual_time_nanos,
                    entities: vec![relay.clone()],
                    evidence: BTreeMap::from([(
                        "offline_sessions".to_owned(),
                        sessions.to_string(),
                    )]),
                });
            }
            _ => {}
        }
        Ok(())
    }

    fn lifecycle_failure(
        &mut self,
        observation: &Observation,
        entity: String,
        from: String,
        to: String,
    ) -> Result<(), InvariantError> {
        self.fail(InvariantFailure {
            name: InvariantName::MonotonicLifecycle,
            class: InvariantClass::Safety,
            observation_sequence: observation.sequence,
            virtual_time_nanos: observation.virtual_time_nanos,
            entities: vec![entity],
            evidence: BTreeMap::from([("from".to_owned(), from), ("to".to_owned(), to)]),
        })
    }

    fn check_resource_ceiling(&mut self, observation: &Observation) -> Result<(), InvariantError> {
        let ObservationKind::Resource {
            kind,
            current,
            limit,
        } = observation.kind
        else {
            return Ok(());
        };
        if current > limit {
            return self.fail(InvariantFailure {
                name: InvariantName::ResourceCeiling,
                class: InvariantClass::Safety,
                observation_sequence: observation.sequence,
                virtual_time_nanos: observation.virtual_time_nanos,
                entities: vec![format!("{kind:?}")],
                evidence: BTreeMap::from([
                    ("current".to_owned(), current.to_string()),
                    ("limit".to_owned(), limit.to_string()),
                ]),
            });
        }
        Ok(())
    }

    fn update_connect_liveness(
        &mut self,
        observation: &Observation,
    ) -> Result<Vec<InvariantTransition>, InvariantError> {
        let ObservationKind::ConnectionState { connection, to, .. } = &observation.kind else {
            return Ok(Vec::new());
        };
        let key = format!("connect/{connection}");
        match to {
            ConnectionState::Dialing => {
                if self.obligations.contains_key(&key) {
                    return Err(InvariantError::DuplicateObligation(key));
                }
                if self.obligations.len() as u64 >= self.max_obligations {
                    return Err(InvariantError::ObligationLimit {
                        limit: self.max_obligations,
                    });
                }
                let spec = self
                    .enabled
                    .get(&InvariantName::ReachableConnectLiveness)
                    .expect("enabled invariant has a spec");
                let deadline_nanos = observation
                    .virtual_time_nanos
                    .checked_add(spec.deadline_nanos.expect("validated liveness deadline"))
                    .ok_or(InvariantError::DeadlineOverflow)?;
                let event_deadline = observation
                    .sequence
                    .checked_add(spec.max_events.expect("validated liveness event bound"))
                    .ok_or(InvariantError::DeadlineOverflow)?;
                self.obligations.insert(
                    key.clone(),
                    Obligation {
                        connection: connection.clone(),
                        deadline_nanos,
                        event_deadline,
                        fairness: vec![
                            FairnessAssumption::FifoProgress,
                            FairnessAssumption::ReachableNetwork,
                        ],
                    },
                );
                Ok(vec![InvariantTransition::Registered {
                    invariant: InvariantName::ReachableConnectLiveness,
                    obligation: key,
                    deadline_nanos,
                    event_deadline,
                }])
            }
            ConnectionState::Connected => {
                if self.obligations.remove(&key).is_some() {
                    Ok(vec![InvariantTransition::Satisfied {
                        invariant: InvariantName::ReachableConnectLiveness,
                        obligation: key,
                    }])
                } else {
                    Ok(Vec::new())
                }
            }
            _ => Ok(Vec::new()),
        }
    }

    fn expire_obligations(
        &mut self,
        virtual_time_nanos: u64,
        event_count: u64,
    ) -> Result<(), InvariantError> {
        let expired = self.obligations.iter().find(|(_, obligation)| {
            obligation
                .fairness
                .iter()
                .all(|assumption| self.fairness.get(assumption).copied().unwrap_or(false))
                && (virtual_time_nanos > obligation.deadline_nanos
                    || event_count > obligation.event_deadline)
        });
        let Some((key, obligation)) = expired else {
            return Ok(());
        };
        let key = key.clone();
        let connection = obligation.connection.clone();
        let deadline_nanos = obligation.deadline_nanos;
        let event_deadline = obligation.event_deadline;
        self.fail(InvariantFailure {
            name: InvariantName::ReachableConnectLiveness,
            class: InvariantClass::BoundedLiveness,
            observation_sequence: event_count,
            virtual_time_nanos,
            entities: vec![connection.to_string()],
            evidence: BTreeMap::from([
                ("obligation".to_owned(), key),
                ("deadline_nanos".to_owned(), deadline_nanos.to_string()),
                ("event_deadline".to_owned(), event_deadline.to_string()),
            ]),
        })
    }

    fn fail<T>(&mut self, failure: InvariantFailure) -> Result<T, InvariantError> {
        self.failure = Some(failure.clone());
        Err(InvariantError::Failure(failure))
    }
}

fn valid_endpoint_transition(from: EndpointState, to: EndpointState) -> bool {
    from == to
        || matches!(
            (from, to),
            (
                EndpointState::Created,
                EndpointState::Running | EndpointState::Failed
            ) | (
                EndpointState::Running,
                EndpointState::Stopping | EndpointState::Failed
            ) | (
                EndpointState::Stopping,
                EndpointState::Stopped | EndpointState::Failed
            ) | (EndpointState::Failed, EndpointState::Stopped)
        )
}

fn valid_connection_transition(from: ConnectionState, to: ConnectionState) -> bool {
    from == to
        || matches!(
            (from, to),
            (ConnectionState::Created, ConnectionState::Dialing)
                | (
                    ConnectionState::Dialing,
                    ConnectionState::Connected | ConnectionState::Failed | ConnectionState::Closed
                )
                | (
                    ConnectionState::Connected,
                    ConnectionState::Closing | ConnectionState::Failed
                )
                | (
                    ConnectionState::Closing,
                    ConnectionState::Closed | ConnectionState::Failed
                )
                | (ConnectionState::Failed, ConnectionState::Closed)
        )
}

/// Invalid observation stream, registry limit, or invariant failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvariantError {
    Configuration(String),
    Observation(ObservationError),
    NonMonotonicObservation,
    DuplicateObligation(String),
    ObligationLimit { limit: u64 },
    DeadlineOverflow,
    SequenceOverflow,
    Failure(InvariantFailure),
    AlreadyFailed(InvariantFailure),
}

impl std::fmt::Display for InvariantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration(error) => write!(f, "invariant configuration failed: {error}"),
            Self::Observation(error) => write!(f, "invalid observation: {error}"),
            Self::NonMonotonicObservation => {
                f.write_str("observation sequence/time is not monotonic")
            }
            Self::DuplicateObligation(value) => {
                write!(f, "duplicate liveness obligation {value:?}")
            }
            Self::ObligationLimit { limit } => {
                write!(f, "liveness obligation limit {limit} exceeded")
            }
            Self::DeadlineOverflow => f.write_str("liveness deadline overflow"),
            Self::SequenceOverflow => f.write_str("delivery sequence overflow"),
            Self::Failure(failure) => write!(f, "invariant {:?} failed", failure.name),
            Self::AlreadyFailed(failure) => {
                write!(f, "invariant {:?} already failed", failure.name)
            }
        }
    }
}

impl std::error::Error for InvariantError {}
