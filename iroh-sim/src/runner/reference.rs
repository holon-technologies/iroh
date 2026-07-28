use super::*;

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
                let payload_len = usize::try_from(payload.bytes)
                    .expect("validated scenario payload size fits in usize");
                let expected = PayloadDigest::from_bytes(&vec![payload.fill; payload_len]);
                if deliveries.iter().any(|observation| {
                    !matches!(observation, ObservationKind::Delivery { expected: observed, .. } if observed == &expected)
                }) {
                    return model_mismatch(action, "delivery digest matching the declared payload", observations);
                }
            }
            ScenarioAction::SendDatagram { connection, .. }
            | ScenarioAction::AssertNoDatagram { connection, .. } => {
                self.require_connection(connection, ConnectionState::Connected)?;
                if !observations.is_empty() {
                    return model_mismatch(action, "no component observation", observations);
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
            | ScenarioAction::Sleep { .. }
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

    pub(super) fn apply_terminal_observations(
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

pub(super) fn expect_endpoint(
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

pub(super) fn model_mismatch<T>(
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
