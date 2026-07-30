use super::*;

/// Production-endpoint implementation of [`ScenarioBackend`] using the deterministic kernel.
pub struct DeterministicScenarioBackend {
    pub(super) backend: DeterministicBackend,
    capabilities: BackendCapabilities,
    endpoints: BTreeMap<String, RunningEndpoint>,
    pub(super) connections: BTreeMap<String, ConnectionPair>,
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

pub(super) struct ConnectionPair {
    client: Connection,
    server: Connection,
    client_endpoint: String,
    server_endpoint: String,
    _resource: ResourceToken,
}

impl DeterministicScenarioBackend {
    pub(super) fn new(
        scenario: &Scenario,
        root_seed: RootSeed,
        wall_epoch: SystemTime,
        trace: Arc<dyn TraceSink>,
        crypto_mode: krikos::simulation::SimulationCryptoMode,
    ) -> Result<Self, RunnerError> {
        let budgets = scenario.run_budgets();
        let backend = DeterministicBackend::new(
            DeterministicBackendConfig {
                root_seed,
                wall_epoch,
                kernel: KernelConfig {
                    max_events: budgets.max_events,
                    max_scheduled_events: scenario.budgets.resources.max_scheduled_events,
                    max_virtual_time: Duration::from_nanos(budgets.max_virtual_time_nanos),
                    max_tasks: budgets.max_tasks,
                    max_trace_events: scenario.budgets.resources.max_trace_events,
                    resource_limits: scenario_kernel_resource_limits(scenario),
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
        Ok(Self {
            backend,
            capabilities,
            endpoints: BTreeMap::new(),
            connections: BTreeMap::new(),
            discovery,
            relay: None,
            relay_urls,
            relay_resources: Vec::new(),
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
        let secret = derive_material("krikos-sim endpoint identity v1", spec.identity_ordinal);
        let token = derive_material("krikos-sim token material v1", spec.identity_ordinal);
        let reset = derive_material("krikos-sim reset material v1", spec.identity_ordinal);
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
        builder.bind().await.map_err(|error| {
            ledger_error_from_bind(&error)
                .map(RunnerError::Ledger)
                .unwrap_or_else(|| RunnerError::Endpoint(error.to_string()))
        })
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
        let resource = self
            .backend
            .kernel()
            .acquire_resource(ResourceKind::Connection, None)?;
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

fn initialize_relays(
    backend: &DeterministicBackend,
    scenario: &Scenario,
) -> Result<(Option<RelayEnvironment>, Vec<ResourceToken>), RunnerError> {
    let resources = scenario
        .topology
        .relays
        .iter()
        .map(|_| backend.kernel().acquire_resource(ResourceKind::Relay, None))
        .collect::<Result<Vec<_>, _>>()?;
    let environment = (!scenario.topology.relays.is_empty())
        .then(|| {
            RelayEnvironment::new_with_runtime(
                &scenario.topology.relays,
                &scenario.topology.relay_impairments,
                backend.runtime_context().clone(),
            )
        })
        .transpose()
        .map_err(|error| RunnerError::Scenario(error.to_string()))?;
    Ok((environment, resources))
}

impl ScenarioBackend for DeterministicScenarioBackend {
    fn capabilities(&self) -> BackendCapabilities {
        self.capabilities.clone()
    }

    fn prepare<'a>(&'a mut self, scenario: &'a Scenario) -> BackendFuture<'a, ()> {
        Box::pin(async move {
            let (relay, relay_resources) = initialize_relays(&self.backend, scenario)?;
            self.relay = relay;
            self.relay_resources = relay_resources;
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
                ScenarioAction::SendDatagram {
                    connection,
                    payload,
                } => {
                    let pair = self
                        .connections
                        .get(connection)
                        .ok_or_else(|| RunnerError::MissingRuntimeEntity(connection.to_owned()))?;
                    let payload_len =
                        usize::try_from(payload.bytes).map_err(|_| RunnerError::PayloadOverflow)?;
                    pair.client
                        .send_datagram(vec![payload.fill; payload_len].into())
                        .map_err(|error| RunnerError::Operation(error.to_string()))?;
                    Ok(Vec::new())
                }
                ScenarioAction::AssertNoDatagram {
                    connection,
                    duration_nanos,
                } => {
                    let pair = self
                        .connections
                        .get(connection)
                        .ok_or_else(|| RunnerError::MissingRuntimeEntity(connection.to_owned()))?;
                    let receive = ClockTimeout::after(
                        self.backend.runtime_context().clock(),
                        Duration::from_nanos(*duration_nanos),
                        pair.server.read_datagram(),
                    )?;
                    match self.backend.driver().drive(receive).await? {
                        Err(TimeoutError::Elapsed) => Ok(Vec::new()),
                        Err(TimeoutError::Clock(error)) => Err(RunnerError::Clock(error)),
                        Ok(Ok(payload)) => Err(RunnerError::Operation(format!(
                            "unexpected datagram delivery on {connection:?}: {} bytes",
                            payload.len()
                        ))),
                        Ok(Err(error)) => Err(RunnerError::Operation(format!(
                            "datagram absence check failed on {connection:?}: {error}"
                        ))),
                    }
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
                ScenarioAction::Sleep { duration_nanos } => {
                    let sleep = ClockSleep::after(
                        self.backend.runtime_context().clock(),
                        Duration::from_nanos(*duration_nanos),
                    )?;
                    self.backend.driver().drive(sleep).await??;
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
                                "krikos-sim endpoint identity v1",
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

pub(super) fn check_capabilities(
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
            PacketFault::Reorder => {
                if rule.probability_per_million > 0 {
                    config.reorder_window = Duration::from_millis(5);
                }
            }
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

pub(super) fn derive_material(context: &str, ordinal: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(&ordinal.to_le_bytes());
    *hasher.finalize().as_bytes()
}

pub(super) fn action_kind(action: &ScenarioAction) -> &'static str {
    match action {
        ScenarioAction::StartEndpoint { .. } => "start_endpoint",
        ScenarioAction::StopEndpoint { .. } => "stop_endpoint",
        ScenarioAction::Connect { .. } => "connect",
        ScenarioAction::StreamRoundTrip { .. } => "stream_round_trip",
        ScenarioAction::DatagramRoundTrip { .. } => "datagram_round_trip",
        ScenarioAction::SendDatagram { .. } => "send_datagram",
        ScenarioAction::AssertNoDatagram { .. } => "assert_no_datagram",
        ScenarioAction::CloseConnection { .. } => "close_connection",
        ScenarioAction::Partition { .. } => "partition",
        ScenarioAction::Heal { .. } => "heal",
        ScenarioAction::SetLink { .. } => "set_link",
        ScenarioAction::AdvanceTime { .. } => "advance_time",
        ScenarioAction::Sleep { .. } => "sleep",
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

pub(super) const ALL_RESOURCE_KINDS: [ResourceKind; 10] = [
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

pub(super) fn resource_limit(scenario: &Scenario, kind: ResourceKind) -> u64 {
    let resources = scenario.budgets.resources;
    match kind {
        ResourceKind::Task => scenario.budgets.max_tasks,
        ResourceKind::QueuedPacket => scenario.budgets.max_packets,
        ResourceKind::TraceBuffer => scenario.budgets.resources.max_trace_events,
        ResourceKind::Timer => resources.max_timers,
        ResourceKind::Socket => resources.max_sockets,
        ResourceKind::Connection => resources.max_connections,
        ResourceKind::Stream => resources.max_streams,
        ResourceKind::Relay => resources.max_relays,
        ResourceKind::Mapping | ResourceKind::DiscoveryRecord => {
            scenario.budgets.max_actions.max(1)
        }
    }
}

pub(super) fn scenario_kernel_resource_limits(scenario: &Scenario) -> KernelResourceLimits {
    let resources = scenario.budgets.resources;
    KernelResourceLimits {
        max_timers: resources.max_timers,
        max_sockets: resources.max_sockets,
        max_connections: resources.max_connections,
        max_streams: resources.max_streams,
        max_relays: resources.max_relays,
    }
}

pub(super) fn ledger_error_in_source_chain(
    error: &(dyn std::error::Error + 'static),
) -> Option<crate::LedgerError> {
    let mut current = Some(error);
    while let Some(source) = current {
        if let Some(error) = source.downcast_ref::<crate::LedgerError>() {
            return Some(*error);
        }
        if let Some(crate::NetworkError::Ledger(error)) =
            source.downcast_ref::<crate::NetworkError>()
        {
            return Some(*error);
        }
        current = source.source();
    }
    None
}

pub(super) fn ledger_error_from_bind(
    error: &krikos::endpoint::BindError,
) -> Option<crate::LedgerError> {
    match error {
        krikos::endpoint::BindError::Sockets { source, .. } => source
            .get_ref()
            .and_then(|source| ledger_error_in_source_chain(source))
            .or_else(|| ledger_error_in_source_chain(source)),
        _ => ledger_error_in_source_chain(error),
    }
}
