use super::*;

/// Rust construction path that produces the same canonical representation as files/generation.
#[derive(Clone, Debug)]
pub struct ScenarioBuilder {
    scenario: Scenario,
}

impl ScenarioBuilder {
    /// Constructs the standard two-endpoint direct-IP echo scenario.
    pub fn direct_ip_echo(
        id: impl Into<String>,
        family: IpFamily,
        operation: ScenarioOperation,
    ) -> Result<Self, ScenarioModelError> {
        let id = id.into();
        validate_id("scenario", &id)?;
        let (client_cidr, server_cidr, client_bind, server_bind) = match family {
            IpFamily::Ipv4 => (
                "192.0.2.1/24",
                "192.0.2.2/24",
                "192.0.2.1:31001",
                "192.0.2.2:31002",
            ),
            IpFamily::Ipv6 => (
                "2001:db8::1/64",
                "2001:db8::2/64",
                "[2001:db8::1]:31001",
                "[2001:db8::2]:31002",
            ),
        };
        let exchange = match operation {
            ScenarioOperation::Stream => ScenarioAction::StreamRoundTrip {
                connection: "c1".to_owned(),
                payload: PayloadSpec {
                    bytes: 28,
                    fill: 165,
                },
            },
            ScenarioOperation::Datagram => ScenarioAction::DatagramRoundTrip {
                connection: "c1".to_owned(),
                payload: PayloadSpec {
                    bytes: 28,
                    fill: 165,
                },
            },
        };
        let at = || ActionSchedule::At { nanos: 0 };
        Ok(Self {
            scenario: Scenario {
                schema_version: SCENARIO_SCHEMA_VERSION,
                metadata: ScenarioMetadata {
                    id,
                    description: format!(
                        "Production QUIC {} echo over one synthetic {} link",
                        match operation {
                            ScenarioOperation::Stream => "stream",
                            ScenarioOperation::Datagram => "datagram",
                        },
                        match family {
                            IpFamily::Ipv4 => "IPv4",
                            IpFamily::Ipv6 => "IPv6",
                        }
                    ),
                    tags: vec!["direct-ip".to_owned(), "stage3".to_owned()],
                },
                requirements: ScenarioRequirements {
                    controlled_runtime: true,
                    virtual_time: true,
                    synthetic_ip: true,
                    ..ScenarioRequirements::default()
                },
                budgets: ScenarioBudgets {
                    max_events: 100_000,
                    max_virtual_time_nanos: 60_000_000_000,
                    max_tasks: 1_024,
                    max_packets: 10_000,
                    max_obligations: 1_024,
                    max_actions: 64,
                    max_payload_bytes: 1_048_576,
                    resources: ScenarioResourceLimits {
                        max_scheduled_events: 100_000,
                        max_trace_events: 200_000,
                        max_timers: 100_000,
                        max_sockets: 100_000,
                        max_connections: 64,
                        max_streams: 64,
                        max_relays: 1,
                    },
                },
                topology: ScenarioTopology {
                    hosts: vec![
                        HostSpec {
                            id: "client".to_owned(),
                            interfaces: vec![InterfaceSpec {
                                id: "eth0".to_owned(),
                                link: "lan".to_owned(),
                                addresses: vec![client_cidr.to_owned()],
                            }],
                        },
                        HostSpec {
                            id: "server".to_owned(),
                            interfaces: vec![InterfaceSpec {
                                id: "eth0".to_owned(),
                                link: "lan".to_owned(),
                                addresses: vec![server_cidr.to_owned()],
                            }],
                        },
                    ],
                    links: vec![LinkSpec {
                        id: "lan".to_owned(),
                        latency_nanos: 1_000_000,
                        bits_per_second: 1_000_000_000,
                        mtu: 1_500,
                        queue_packets: 1_024,
                    }],
                    nats: Vec::new(),
                    discovery: Vec::new(),
                    relays: Vec::new(),
                    relay_impairments: Vec::new(),
                },
                endpoints: vec![
                    EndpointSpec {
                        id: "client".to_owned(),
                        host: "client".to_owned(),
                        bind: client_bind.to_owned(),
                        identity_ordinal: 1,
                        direct: true,
                        relay: None,
                    },
                    EndpointSpec {
                        id: "server".to_owned(),
                        host: "server".to_owned(),
                        bind: server_bind.to_owned(),
                        identity_ordinal: 2,
                        direct: true,
                        relay: None,
                    },
                ],
                actions: vec![
                    action(
                        "01-start-client",
                        at(),
                        ScenarioAction::StartEndpoint {
                            endpoint: "client".to_owned(),
                        },
                    ),
                    action(
                        "02-start-server",
                        at(),
                        ScenarioAction::StartEndpoint {
                            endpoint: "server".to_owned(),
                        },
                    ),
                    action(
                        "03-connect",
                        at(),
                        ScenarioAction::Connect {
                            client: "client".to_owned(),
                            server: "server".to_owned(),
                            connection: "c1".to_owned(),
                        },
                    ),
                    action("04-stream", at(), exchange),
                    action(
                        "05-close",
                        at(),
                        ScenarioAction::CloseConnection {
                            connection: "c1".to_owned(),
                        },
                    ),
                    action(
                        "06-stop-client",
                        at(),
                        ScenarioAction::StopEndpoint {
                            endpoint: "client".to_owned(),
                        },
                    ),
                    action(
                        "07-stop-server",
                        at(),
                        ScenarioAction::StopEndpoint {
                            endpoint: "server".to_owned(),
                        },
                    ),
                ],
                fault_rules: Vec::new(),
                fairness: vec![
                    FairnessAssumption::FifoProgress,
                    FairnessAssumption::ReachableNetwork,
                ],
                completion: CompletionPolicy::AllActions {
                    shutdown_deadline_nanos: 60_000_000_000,
                },
                allowed_terminals: vec![AllowedTerminal::Success],
                invariants: vec![
                    invariant(InvariantName::AuthenticationIdentity, None, None),
                    invariant(InvariantName::DeliveryIntegrity, None, None),
                    invariant(InvariantName::MonotonicLifecycle, None, None),
                    invariant(
                        InvariantName::ResourceCleanup,
                        Some(60_000_000_000),
                        Some(100_000),
                    ),
                ],
            },
        })
    }

    /// Returns mutable canonical data for deliberate builder customization.
    pub fn scenario_mut(&mut self) -> &mut Scenario {
        &mut self.scenario
    }

    /// Normalizes and validates the completed scenario.
    pub fn build(self) -> Result<Scenario, ScenarioModelError> {
        self.scenario.normalized()
    }
}

fn action(id: &str, schedule: ActionSchedule, action: ScenarioAction) -> ActionSpec {
    ActionSpec {
        id: id.to_owned(),
        schedule,
        action,
    }
}

fn invariant(
    name: InvariantName,
    deadline_nanos: Option<u64>,
    max_events: Option<u64>,
) -> InvariantSpec {
    InvariantSpec {
        name,
        deadline_nanos,
        max_events,
    }
}
