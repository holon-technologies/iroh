use super::*;

/// Human-facing scenario identity and tags.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioMetadata {
    pub id: String,
    pub description: String,
    pub tags: Vec<String>,
}

/// Capabilities required for sound execution.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioRequirements {
    pub controlled_runtime: bool,
    pub virtual_time: bool,
    pub synthetic_ip: bool,
    pub nat: bool,
    pub relay: bool,
    pub discovery: bool,
    pub mobility: bool,
}

/// Hard scenario and runner bounds.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioBudgets {
    pub max_events: u64,
    pub max_virtual_time_nanos: u64,
    pub max_tasks: u64,
    pub max_packets: u64,
    pub max_obligations: u64,
    pub max_actions: u64,
    pub max_payload_bytes: u64,
    pub resources: ScenarioResourceLimits,
}

impl ScenarioBudgets {
    pub(super) fn validate(&self) -> Result<(), ScenarioModelError> {
        if self.max_events == 0
            || self.max_virtual_time_nanos == 0
            || self.max_tasks == 0
            || self.max_packets == 0
            || self.max_obligations == 0
            || self.max_actions == 0
            || self.max_payload_bytes == 0
            || usize::try_from(self.max_payload_bytes).is_err()
            || self.max_actions > u64::try_from(MAX_ITEMS).expect("MAX_ITEMS fits in u64")
        {
            return Err(ScenarioModelError::InvalidBudgets);
        }
        self.resources.validate()
    }
}

/// Hard admission ceilings for deterministic kernel resources.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioResourceLimits {
    pub max_scheduled_events: u64,
    pub max_trace_events: u64,
    pub max_timers: u64,
    pub max_sockets: u64,
    pub max_connections: u64,
    pub max_streams: u64,
    pub max_relays: u64,
}

impl ScenarioResourceLimits {
    pub(super) fn validate(self) -> Result<(), ScenarioModelError> {
        if self.max_scheduled_events == 0
            || self.max_trace_events == 0
            || self.max_trace_events > 10_000_000
        {
            return Err(ScenarioModelError::InvalidBudgets);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ScenarioBudgetsV2 {
    pub(super) max_events: u64,
    pub(super) max_virtual_time_nanos: u64,
    pub(super) max_tasks: u64,
    pub(super) max_packets: u64,
    pub(super) max_trace_events: u64,
    pub(super) max_obligations: u64,
    pub(super) max_actions: u64,
    pub(super) max_payload_bytes: u64,
}

/// Network topology supported by the Stage 3 deterministic backend.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioTopology {
    pub hosts: Vec<HostSpec>,
    pub links: Vec<LinkSpec>,
    #[serde(default)]
    pub nats: Vec<NatSpec>,
    #[serde(default)]
    pub discovery: Vec<DiscoveryProviderSpec>,
    #[serde(default)]
    pub relays: Vec<RelaySpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_impairments: Vec<RelayImpairmentSpec>,
}

/// Relay protocol version negotiated by a deterministic relay service.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayProtocolVersion {
    V1,
    #[default]
    V2,
}

/// One bounded production relay service available to deterministic endpoints.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelaySpec {
    pub id: String,
    pub url: String,
    pub online: bool,
    pub max_sessions: u64,
    pub byte_capacity: usize,
    pub protocol_version: RelayProtocolVersion,
}

impl RelaySpec {
    pub(super) fn validate(&self) -> Result<(), ScenarioModelError> {
        validate_id("relay", &self.id)?;
        let url = self
            .url
            .parse::<iroh::RelayUrl>()
            .map_err(|_| ScenarioModelError::InvalidRelay(self.id.clone()))?;
        if !matches!(url.scheme(), "http" | "https" | "ws" | "wss")
            || self.max_sessions == 0
            || self.byte_capacity == 0
            || self.byte_capacity > 16 * 1024 * 1024
        {
            return Err(ScenarioModelError::InvalidRelay(self.id.clone()));
        }
        Ok(())
    }
}

/// Optional bounded deterministic faults applied around a production relay service.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelayImpairmentSpec {
    pub relay: String,
    #[serde(default)]
    pub connection_delay_nanos: u64,
    #[serde(default)]
    pub reject_connect_attempts: Vec<u64>,
    #[serde(default)]
    pub drop_every_nth_packet: Option<u64>,
    #[serde(default)]
    pub client_rx_bytes_per_second: Option<u32>,
    #[serde(default)]
    pub client_rx_max_burst_bytes: Option<u32>,
}

impl RelayImpairmentSpec {
    pub(super) fn validate(&self) -> Result<(), ScenarioModelError> {
        validate_id("relay", &self.relay)?;
        if self.connection_delay_nanos > 60_000_000_000
            || self.reject_connect_attempts.len() > MAX_ITEMS
            || self.reject_connect_attempts.contains(&0)
            || !is_unique(&self.reject_connect_attempts)
            || self.drop_every_nth_packet == Some(0)
            || self.client_rx_bytes_per_second == Some(0)
            || self.client_rx_max_burst_bytes == Some(0)
            || (self.client_rx_max_burst_bytes.is_some()
                && self.client_rx_bytes_per_second.is_none())
        {
            return Err(ScenarioModelError::InvalidRelay(self.relay.clone()));
        }
        Ok(())
    }
}

/// One bounded deterministic address-lookup provider.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryProviderSpec {
    pub id: String,
    pub max_records: u64,
}

impl DiscoveryProviderSpec {
    pub(super) fn validate(&self) -> Result<(), ScenarioModelError> {
        validate_id("discovery_provider", &self.id)?;
        if self.max_records == 0 {
            return Err(ScenarioModelError::InvalidDiscovery(self.id.clone()));
        }
        Ok(())
    }
}

/// Record mutation applied to a deterministic discovery provider.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryRecordState {
    Published,
    Failed,
    Withdrawn,
}

/// One stateful IPv4 gateway attached to an inside host.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NatSpec {
    pub id: String,
    pub inside_host: String,
    #[serde(default)]
    pub upstream_nat: Option<String>,
    pub public_ip: String,
    pub port_start: u16,
    pub port_end: u16,
    pub mapping_behavior: crate::NatMappingBehavior,
    pub filtering_behavior: crate::NatFilteringBehavior,
    pub mapping_ttl_nanos: u64,
    pub hairpin: bool,
    pub max_mappings: u64,
    pub firewall: Option<FirewallSpec>,
}

/// Ordered stateful firewall policy attached to a NAT.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallSpec {
    pub id: String,
    pub rules: Vec<FirewallRuleSpec>,
    pub default_action: crate::FirewallAction,
}

/// Serializable firewall rule using canonical CIDR strings and inclusive ports.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallRuleSpec {
    pub id: String,
    pub protocol: crate::FirewallProtocol,
    pub direction: Option<crate::FirewallDirection>,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub source_ports: Option<(u16, u16)>,
    pub destination_ports: Option<(u16, u16)>,
    pub connection_state: crate::FirewallConnectionState,
    pub action: crate::FirewallAction,
}

impl NatSpec {
    pub(super) fn validate(&self, hosts: &BTreeSet<&str>) -> Result<(), ScenarioModelError> {
        validate_id("nat", &self.id)?;
        require_reference(hosts, &self.inside_host, ScenarioModelError::UnknownHost)?;
        let public: Ipv4Addr = self
            .public_ip
            .parse()
            .map_err(|_| ScenarioModelError::InvalidNat(self.id.clone()))?;
        if public.is_unspecified()
            || public.is_multicast()
            || self.port_start == 0
            || self.port_start > self.port_end
            || self.mapping_ttl_nanos == 0
            || self.max_mappings == 0
        {
            return Err(ScenarioModelError::InvalidNat(self.id.clone()));
        }
        if let Some(firewall) = &self.firewall {
            firewall.validate()?;
        }
        Ok(())
    }
}

impl FirewallSpec {
    pub(super) fn validate(&self) -> Result<(), ScenarioModelError> {
        validate_id("firewall", &self.id)?;
        if self.rules.len() > MAX_ITEMS {
            return Err(ScenarioModelError::InvalidFirewall(self.id.clone()));
        }
        let _ = unique_ids(
            "firewall_rule",
            self.rules.iter().map(|rule| rule.id.as_str()),
        )?;
        for rule in &self.rules {
            for cidr in [&rule.source, &rule.destination].into_iter().flatten() {
                let (address, _) = parse_cidr(cidr)?;
                if !address.is_ipv4() {
                    return Err(ScenarioModelError::InvalidFirewall(self.id.clone()));
                }
            }
            if rule
                .source_ports
                .is_some_and(|(start, end)| start == 0 || start > end)
                || rule
                    .destination_ports
                    .is_some_and(|(start, end)| start == 0 || start > end)
            {
                return Err(ScenarioModelError::InvalidFirewall(self.id.clone()));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostSpec {
    pub id: String,
    pub interfaces: Vec<InterfaceSpec>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceSpec {
    pub id: String,
    pub link: String,
    pub addresses: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinkSpec {
    pub id: String,
    pub latency_nanos: u64,
    pub bits_per_second: u64,
    pub mtu: usize,
    pub queue_packets: u64,
}

impl LinkSpec {
    pub(super) fn validate(&self) -> Result<(), ScenarioModelError> {
        validate_id("link", &self.id)?;
        if self.bits_per_second == 0 || self.mtu == 0 || self.queue_packets == 0 {
            return Err(ScenarioModelError::InvalidLink(self.id.clone()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointSpec {
    pub id: String,
    pub host: String,
    pub bind: String,
    pub identity_ordinal: u64,
    #[serde(default = "default_true")]
    pub direct: bool,
    #[serde(default)]
    pub relay: Option<String>,
}

/// One stable scheduled or triggered action.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSpec {
    pub id: String,
    pub schedule: ActionSchedule,
    pub action: ScenarioAction,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActionSchedule {
    At { nanos: u64 },
    AfterAction { action: String },
    AfterObservation { observation: ObservationTrigger },
}

impl ActionSchedule {
    pub const fn deadline_nanos(&self) -> Option<u64> {
        match self {
            Self::At { nanos } => Some(*nanos),
            Self::AfterAction { .. } | Self::AfterObservation { .. } => None,
        }
    }

    pub(super) fn validate(
        &self,
        own_id: &str,
        actions: &BTreeSet<&str>,
        max_virtual_time: u64,
    ) -> Result<(), ScenarioModelError> {
        match self {
            Self::At { nanos } if *nanos <= max_virtual_time => Ok(()),
            Self::At { .. } => Err(ScenarioModelError::ActionAfterBudget(own_id.to_owned())),
            Self::AfterAction { action }
                if actions.contains(action.as_str()) && action.as_str() < own_id =>
            {
                Ok(())
            }
            Self::AfterAction { action } => Err(ScenarioModelError::InvalidTrigger(action.clone())),
            Self::AfterObservation { observation } => observation.validate(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservationTrigger {
    EndpointState { endpoint: String, state: String },
    ConnectionState { connection: String, state: String },
    InvariantSatisfied { invariant: InvariantName },
}

impl ObservationTrigger {
    pub(super) fn validate(&self) -> Result<(), ScenarioModelError> {
        match self {
            Self::EndpointState { endpoint, state } => {
                validate_id("endpoint", endpoint)?;
                validate_id("state", state)
            }
            Self::ConnectionState { connection, state } => {
                validate_id("connection", connection)?;
                validate_id("state", state)
            }
            Self::InvariantSatisfied { .. } => Ok(()),
        }
    }
}

pub(super) fn validate_observation_reference(
    trigger: &ObservationTrigger,
    endpoints: &BTreeSet<&str>,
    connections: &BTreeSet<&str>,
    invariants: &BTreeSet<InvariantName>,
) -> Result<(), ScenarioModelError> {
    match trigger {
        ObservationTrigger::EndpointState { endpoint, state } => {
            require_reference(endpoints, endpoint, ScenarioModelError::UnknownEndpoint)?;
            if !matches!(
                state.as_str(),
                "created" | "running" | "stopping" | "stopped" | "failed"
            ) {
                return Err(ScenarioModelError::InvalidTrigger(state.clone()));
            }
        }
        ObservationTrigger::ConnectionState { connection, state } => {
            require_reference(
                connections,
                connection,
                ScenarioModelError::UnknownConnection,
            )?;
            if !matches!(
                state.as_str(),
                "created" | "dialing" | "connected" | "closing" | "closed" | "failed"
            ) {
                return Err(ScenarioModelError::InvalidTrigger(state.clone()));
            }
        }
        ObservationTrigger::InvariantSatisfied { invariant } => {
            if !invariants.contains(invariant) {
                return Err(ScenarioModelError::InvalidTrigger(format!("{invariant:?}")));
            }
        }
    }
    Ok(())
}

/// Declarative action vocabulary. Later-stage actions parse explicitly but require capabilities.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScenarioAction {
    StartEndpoint {
        endpoint: String,
    },
    StopEndpoint {
        endpoint: String,
    },
    Connect {
        client: String,
        server: String,
        connection: String,
    },
    StreamRoundTrip {
        connection: String,
        payload: PayloadSpec,
    },
    DatagramRoundTrip {
        connection: String,
        payload: PayloadSpec,
    },
    SendDatagram {
        connection: String,
        payload: PayloadSpec,
    },
    AssertNoDatagram {
        connection: String,
        duration_nanos: u64,
    },
    CloseConnection {
        connection: String,
    },
    Partition {
        link: String,
        from: String,
        to: String,
    },
    Heal {
        link: String,
        from: String,
        to: String,
    },
    SetLink {
        link: String,
        latency_nanos: Option<u64>,
        mtu: Option<usize>,
    },
    AdvanceTime {
        by_nanos: u64,
    },
    Sleep {
        duration_nanos: u64,
    },
    ExpectFailure {
        class: String,
    },
    NatChange {
        nat: String,
        public_ip: String,
        preserve_ports: bool,
    },
    PortMap {
        endpoint: String,
        active: bool,
    },
    RelayLifecycle {
        relay: String,
        online: bool,
    },
    DiscoveryUpdate {
        provider: String,
        record: String,
        endpoint: String,
        addresses: Vec<String>,
        delay_nanos: u64,
        ttl_nanos: u64,
        state: DiscoveryRecordState,
    },
    InterfaceChange {
        host: String,
        interface: String,
        up: bool,
    },
    AddressChange {
        host: String,
        interface: String,
        address: String,
        present: bool,
    },
    HostSleep {
        host: String,
        sleeping: bool,
    },
    RouteChange {
        host: String,
        route: String,
        destination: String,
        interface: String,
        next_hop: Option<String>,
        active: bool,
    },
}

impl ScenarioAction {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn validate(
        &self,
        requirements: &ScenarioRequirements,
        endpoints: &BTreeSet<&str>,
        connections: &BTreeSet<&str>,
        hosts: &BTreeSet<&str>,
        links: &BTreeSet<&str>,
        nats: &BTreeSet<&str>,
        relays: &BTreeSet<&str>,
        discovery: &BTreeSet<&str>,
        interfaces: &BTreeSet<String>,
        max_payload: u64,
        max_virtual_time: u64,
    ) -> Result<(), ScenarioModelError> {
        match self {
            Self::StartEndpoint { endpoint } | Self::StopEndpoint { endpoint } => {
                require_reference(endpoints, endpoint, ScenarioModelError::UnknownEndpoint)
            }
            Self::Connect {
                client,
                server,
                connection,
            } => {
                require_reference(endpoints, client, ScenarioModelError::UnknownEndpoint)?;
                require_reference(endpoints, server, ScenarioModelError::UnknownEndpoint)?;
                validate_id("connection", connection)
            }
            Self::StreamRoundTrip {
                connection,
                payload,
            }
            | Self::DatagramRoundTrip {
                connection,
                payload,
            }
            | Self::SendDatagram {
                connection,
                payload,
            } => {
                require_reference(
                    connections,
                    connection,
                    ScenarioModelError::UnknownConnection,
                )?;
                payload.validate(max_payload)
            }
            Self::AssertNoDatagram {
                connection,
                duration_nanos,
            } => {
                require_reference(
                    connections,
                    connection,
                    ScenarioModelError::UnknownConnection,
                )?;
                if *duration_nanos == 0 || *duration_nanos > max_virtual_time {
                    return Err(ScenarioModelError::InvalidAction("assert_no_datagram"));
                }
                Ok(())
            }
            Self::CloseConnection { connection } => require_reference(
                connections,
                connection,
                ScenarioModelError::UnknownConnection,
            ),
            Self::Partition { link, from, to } | Self::Heal { link, from, to } => {
                require_reference(links, link, ScenarioModelError::UnknownLink)?;
                require_reference(hosts, from, ScenarioModelError::UnknownHost)?;
                require_reference(hosts, to, ScenarioModelError::UnknownHost)
            }
            Self::SetLink {
                link,
                latency_nanos: _,
                mtu,
            } => {
                require_reference(links, link, ScenarioModelError::UnknownLink)?;
                if matches!(mtu, Some(0)) {
                    return Err(ScenarioModelError::InvalidLink(link.clone()));
                }
                Ok(())
            }
            Self::AdvanceTime { by_nanos } if *by_nanos > 0 => Ok(()),
            Self::AdvanceTime { .. } => Err(ScenarioModelError::InvalidAction("advance_time")),
            Self::Sleep { duration_nanos }
                if *duration_nanos > 0 && *duration_nanos <= max_virtual_time =>
            {
                Ok(())
            }
            Self::Sleep { .. } => Err(ScenarioModelError::InvalidAction("sleep")),
            Self::ExpectFailure { class } => validate_id("failure_class", class),
            Self::NatChange {
                nat,
                public_ip,
                preserve_ports: _,
            } => {
                require_capability(requirements.nat, "nat")?;
                require_reference(nats, nat, ScenarioModelError::UnknownNat)?;
                let public: Ipv4Addr = public_ip
                    .parse()
                    .map_err(|_| ScenarioModelError::InvalidNat(nat.clone()))?;
                if public.is_unspecified() || public.is_multicast() {
                    return Err(ScenarioModelError::InvalidNat(nat.clone()));
                }
                Ok(())
            }
            Self::PortMap { endpoint, .. } => {
                require_capability(requirements.nat, "nat")?;
                require_reference(endpoints, endpoint, ScenarioModelError::UnknownEndpoint)
            }
            Self::RelayLifecycle { relay, .. } => {
                require_capability(requirements.relay, "relay")?;
                require_reference(relays, relay, ScenarioModelError::UnknownRelay)
            }
            Self::DiscoveryUpdate {
                provider,
                record,
                endpoint,
                addresses,
                delay_nanos,
                ttl_nanos,
                state,
            } => {
                require_capability(requirements.discovery, "discovery")?;
                require_reference(discovery, provider, ScenarioModelError::UnknownDiscovery)?;
                validate_id("discovery_record", record)?;
                require_reference(endpoints, endpoint, ScenarioModelError::UnknownEndpoint)?;
                match state {
                    DiscoveryRecordState::Published => {
                        if addresses.is_empty() || *ttl_nanos == 0 {
                            return Err(ScenarioModelError::InvalidDiscovery(record.clone()));
                        }
                        for address in addresses {
                            let address: SocketAddr = address.parse().map_err(|_| {
                                ScenarioModelError::InvalidDiscovery(record.clone())
                            })?;
                            if address.port() == 0 {
                                return Err(ScenarioModelError::InvalidDiscovery(record.clone()));
                            }
                        }
                    }
                    DiscoveryRecordState::Failed => {
                        if !addresses.is_empty() || *ttl_nanos == 0 {
                            return Err(ScenarioModelError::InvalidDiscovery(record.clone()));
                        }
                    }
                    DiscoveryRecordState::Withdrawn => {
                        if !addresses.is_empty() || *delay_nanos != 0 || *ttl_nanos != 0 {
                            return Err(ScenarioModelError::InvalidDiscovery(record.clone()));
                        }
                    }
                }
                Ok(())
            }
            Self::InterfaceChange {
                host, interface, ..
            }
            | Self::AddressChange {
                host, interface, ..
            } => {
                require_capability(requirements.mobility, "mobility")?;
                require_reference(hosts, host, ScenarioModelError::UnknownHost)?;
                validate_id("interface", interface)?;
                if !interfaces.contains(&format!("{host}/{interface}")) {
                    return Err(ScenarioModelError::UnknownInterface {
                        host: host.clone(),
                        interface: interface.clone(),
                    });
                }
                if let Self::AddressChange { address, .. } = self {
                    parse_cidr(address)?;
                }
                Ok(())
            }
            Self::HostSleep { host, .. } => {
                require_capability(requirements.mobility, "mobility")?;
                require_reference(hosts, host, ScenarioModelError::UnknownHost)
            }
            Self::RouteChange {
                host,
                route,
                destination,
                interface,
                next_hop,
                ..
            } => {
                require_capability(requirements.mobility, "mobility")?;
                require_reference(hosts, host, ScenarioModelError::UnknownHost)?;
                validate_id("route", route)?;
                parse_cidr(destination)?;
                if !interfaces.contains(&format!("{host}/{interface}")) {
                    return Err(ScenarioModelError::UnknownInterface {
                        host: host.clone(),
                        interface: interface.clone(),
                    });
                }
                if let Some(next_hop) = next_hop {
                    require_reference(hosts, next_hop, ScenarioModelError::UnknownHost)?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadSpec {
    pub bytes: u64,
    pub fill: u8,
}

impl PayloadSpec {
    pub(super) fn validate(&self, max_payload: u64) -> Result<(), ScenarioModelError> {
        if self.bytes == 0 || self.bytes > max_payload {
            return Err(ScenarioModelError::InvalidPayload(self.bytes));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FaultRule {
    pub id: String,
    pub link: String,
    pub effect: PacketFault,
    pub probability_per_million: u32,
    pub start_nanos: u64,
    pub end_nanos: u64,
    pub max_applications: u64,
}

impl FaultRule {
    pub(super) fn validate(
        &self,
        links: &BTreeSet<&str>,
        max_virtual_time: u64,
    ) -> Result<(), ScenarioModelError> {
        validate_id("fault_rule", &self.id)?;
        require_reference(links, &self.link, ScenarioModelError::UnknownLink)?;
        if self.probability_per_million > 1_000_000
            || self.start_nanos > self.end_nanos
            || self.end_nanos > max_virtual_time
            || self.max_applications == 0
        {
            return Err(ScenarioModelError::InvalidFaultRule(self.id.clone()));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketFault {
    Loss,
    Duplication,
    Corruption,
    Reorder,
    Delay,
    MtuReduction,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FairnessAssumption {
    FifoProgress,
    ReachableNetwork,
    EventualTimerDelivery,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompletionPolicy {
    AllActions {
        shutdown_deadline_nanos: u64,
    },
    Observation {
        trigger: ObservationTrigger,
        shutdown_deadline_nanos: u64,
    },
}

impl CompletionPolicy {
    pub(super) fn validate(&self, max_virtual_time: u64) -> Result<(), ScenarioModelError> {
        let deadline = match self {
            Self::AllActions {
                shutdown_deadline_nanos,
            }
            | Self::Observation {
                shutdown_deadline_nanos,
                ..
            } => *shutdown_deadline_nanos,
        };
        if deadline == 0 || deadline > max_virtual_time {
            return Err(ScenarioModelError::InvalidCompletion);
        }
        if let Self::Observation { trigger, .. } = self {
            trigger.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowedTerminal {
    Success,
    ExpectedFailure,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvariantSpec {
    pub name: InvariantName,
    pub deadline_nanos: Option<u64>,
    pub max_events: Option<u64>,
}

impl InvariantSpec {
    pub(super) fn validate(&self, budgets: &ScenarioBudgets) -> Result<(), ScenarioModelError> {
        if self
            .deadline_nanos
            .is_some_and(|value| value == 0 || value > budgets.max_virtual_time_nanos)
            || self
                .max_events
                .is_some_and(|value| value == 0 || value > budgets.max_events)
        {
            return Err(ScenarioModelError::InvalidInvariant(self.name));
        }
        if matches!(self.name, InvariantName::ReachableConnectLiveness)
            && (self.deadline_nanos.is_none() || self.max_events.is_none())
        {
            return Err(ScenarioModelError::InvalidInvariant(self.name));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantName {
    AuthenticationIdentity,
    DeliveryIntegrity,
    DeliveryOrdering,
    MonotonicLifecycle,
    ResourceCeiling,
    ResourceCleanup,
    ReachableConnectLiveness,
    RelayRouting,
}

/// Address family used by canonical direct-IP builders.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpFamily {
    Ipv4,
    Ipv6,
}

/// Production application operation used by canonical echo builders.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScenarioOperation {
    Stream,
    Datagram,
}
