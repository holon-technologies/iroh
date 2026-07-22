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
pub const SCENARIO_SCHEMA_VERSION: u16 = 2;
const MAX_ITEMS: usize = 10_000;
const MAX_TEXT: usize = 1_024;

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

impl Scenario {
    /// Parses the current schema or explicitly migrates a supported Stage 2 document.
    pub fn from_versioned_json(bytes: &[u8]) -> Result<Self, ScenarioModelError> {
        #[derive(Deserialize)]
        struct VersionProbe {
            schema_version: u16,
        }

        let probe: VersionProbe = serde_json::from_slice(bytes)
            .map_err(|error| ScenarioModelError::Json(error.to_string()))?;
        match probe.schema_version {
            SCENARIO_SCHEMA_VERSION => Self::from_json(bytes),
            crate::STAGE2_SCENARIO_SCHEMA_VERSION => {
                let legacy = crate::Stage2Scenario::from_json(bytes)
                    .map_err(|error| ScenarioModelError::Legacy(error.to_string()))?;
                Self::from_stage2(legacy)
            }
            version => Err(ScenarioModelError::UnsupportedSchema(version)),
        }
    }

    /// Strictly parses, normalizes, and validates a v2 JSON scenario.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ScenarioModelError> {
        let scenario: Self = serde_json::from_slice(bytes)
            .map_err(|error| ScenarioModelError::Json(error.to_string()))?;
        scenario.normalized()
    }

    /// Returns stable pretty JSON after canonical normalization and validation.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, ScenarioModelError> {
        let scenario = self.clone().normalized()?;
        let mut bytes = serde_json::to_vec_pretty(&scenario)
            .map_err(|error| ScenarioModelError::Json(error.to_string()))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Returns a normalized and validated copy.
    pub fn normalized(mut self) -> Result<Self, ScenarioModelError> {
        self.metadata.tags.sort();
        self.topology
            .hosts
            .sort_by(|left, right| left.id.cmp(&right.id));
        for host in &mut self.topology.hosts {
            host.interfaces
                .sort_by(|left, right| left.id.cmp(&right.id));
            for interface in &mut host.interfaces {
                interface.addresses.sort();
            }
        }
        self.topology
            .links
            .sort_by(|left, right| left.id.cmp(&right.id));
        self.topology
            .nats
            .sort_by(|left, right| left.id.cmp(&right.id));
        self.topology
            .discovery
            .sort_by(|left, right| left.id.cmp(&right.id));
        self.topology
            .relays
            .sort_by(|left, right| left.id.cmp(&right.id));
        self.topology
            .relay_impairments
            .sort_by(|left, right| left.relay.cmp(&right.relay));
        for impairment in &mut self.topology.relay_impairments {
            impairment.reject_connect_attempts.sort_unstable();
            impairment.reject_connect_attempts.dedup();
        }
        self.endpoints.sort_by(|left, right| left.id.cmp(&right.id));
        self.actions.sort_by(|left, right| left.id.cmp(&right.id));
        for action in &mut self.actions {
            if let ScenarioAction::DiscoveryUpdate { addresses, .. } = &mut action.action {
                addresses.sort();
                addresses.dedup();
            }
        }
        self.fault_rules
            .sort_by(|left, right| left.id.cmp(&right.id));
        self.fairness.sort();
        self.allowed_terminals.sort();
        self.invariants
            .sort_by(|left, right| left.name.cmp(&right.name));
        self.validate()?;
        Ok(self)
    }

    /// Validates references, capabilities, ordering-independent semantics, and hard bounds.
    pub fn validate(&self) -> Result<(), ScenarioModelError> {
        if self.schema_version != SCENARIO_SCHEMA_VERSION {
            return Err(ScenarioModelError::UnsupportedSchema(self.schema_version));
        }
        validate_id("scenario", &self.metadata.id)?;
        if self.metadata.description.len() > MAX_TEXT
            || looks_like_host_path(&self.metadata.description)
        {
            return Err(ScenarioModelError::InvalidMetadata);
        }
        for tag in &self.metadata.tags {
            validate_id("tag", tag)?;
        }
        self.budgets.validate()?;
        if self.actions.len() > self.budgets.max_actions as usize || self.actions.len() > MAX_ITEMS
        {
            return Err(ScenarioModelError::TooManyActions);
        }
        if self.topology.hosts.len() > MAX_ITEMS
            || self.topology.links.len() > MAX_ITEMS
            || self.topology.nats.len() > MAX_ITEMS
            || self.topology.discovery.len() > MAX_ITEMS
            || self.topology.relays.len() > MAX_ITEMS
            || self.topology.relay_impairments.len() > MAX_ITEMS
            || self.endpoints.len() > MAX_ITEMS
            || self.fault_rules.len() > MAX_ITEMS
            || self.invariants.len() > MAX_ITEMS
        {
            return Err(ScenarioModelError::TooManyItems);
        }
        if self.allowed_terminals.is_empty() {
            return Err(ScenarioModelError::NoAllowedTerminal);
        }
        if !is_unique(&self.fairness) || !is_unique(&self.allowed_terminals) {
            return Err(ScenarioModelError::DuplicateId("canonical set"));
        }

        let links = unique_ids(
            "link",
            self.topology.links.iter().map(|link| link.id.as_str()),
        )?;
        for link in &self.topology.links {
            link.validate()?;
        }
        let hosts = unique_ids(
            "host",
            self.topology.hosts.iter().map(|host| host.id.as_str()),
        )?;
        let mut addresses = BTreeSet::new();
        let mut host_networks = BTreeMap::<&str, Vec<(IpAddr, u8)>>::new();
        let mut interfaces = BTreeSet::new();
        for host in &self.topology.hosts {
            let _ = unique_ids(
                "interface",
                host.interfaces
                    .iter()
                    .map(|interface| interface.id.as_str()),
            )?;
            if host.interfaces.is_empty() {
                return Err(ScenarioModelError::HostWithoutInterface(host.id.clone()));
            }
            for interface in &host.interfaces {
                interfaces.insert(format!("{}/{}", host.id, interface.id));
                if !links.contains(interface.link.as_str()) {
                    return Err(ScenarioModelError::UnknownLink(interface.link.clone()));
                }
                if interface.addresses.is_empty() {
                    return Err(ScenarioModelError::InterfaceWithoutAddress(format!(
                        "{}/{}",
                        host.id, interface.id
                    )));
                }
                for address in &interface.addresses {
                    let (ip, prefix) = parse_cidr(address)?;
                    if !addresses.insert(ip) {
                        return Err(ScenarioModelError::DuplicateAddress(ip));
                    }
                    host_networks
                        .entry(&host.id)
                        .or_default()
                        .push((ip, prefix));
                }
            }
        }

        let endpoint_ids = unique_ids(
            "endpoint",
            self.endpoints.iter().map(|endpoint| endpoint.id.as_str()),
        )?;
        let mut endpoint_addresses = BTreeSet::new();
        for endpoint in &self.endpoints {
            if !hosts.contains(endpoint.host.as_str()) {
                return Err(ScenarioModelError::UnknownHost(endpoint.host.clone()));
            }
            if endpoint.identity_ordinal == 0 {
                return Err(ScenarioModelError::InvalidIdentityOrdinal(
                    endpoint.id.clone(),
                ));
            }
            let bind: SocketAddr = endpoint
                .bind
                .parse()
                .map_err(|_| ScenarioModelError::InvalidSocket(endpoint.bind.clone()))?;
            if bind.port() == 0 || !endpoint_addresses.insert(bind) {
                return Err(ScenarioModelError::InvalidSocket(endpoint.bind.clone()));
            }
            if !bind.ip().is_unspecified()
                && !host_networks
                    .get(endpoint.host.as_str())
                    .is_some_and(|networks| {
                        networks
                            .iter()
                            .any(|(network, prefix)| cidr_contains(*network, *prefix, bind.ip()))
                    })
            {
                return Err(ScenarioModelError::EndpointAddressNotOwned {
                    endpoint: endpoint.id.clone(),
                    address: bind.ip(),
                });
            }
        }

        let nat_ids = unique_ids("nat", self.topology.nats.iter().map(|nat| nat.id.as_str()))?;
        let mut nat_public_ips = BTreeSet::new();
        for nat in &self.topology.nats {
            nat.validate(&hosts)?;
            if let Some(upstream) = &nat.upstream_nat {
                require_reference(&nat_ids, upstream, ScenarioModelError::UnknownNat)?;
                if upstream == &nat.id {
                    return Err(ScenarioModelError::InvalidNat(nat.id.clone()));
                }
                let upstream_host = self
                    .topology
                    .nats
                    .iter()
                    .find(|candidate| candidate.id == *upstream)
                    .expect("validated NAT reference")
                    .inside_host
                    .as_str();
                if upstream_host != nat.inside_host {
                    return Err(ScenarioModelError::InvalidNat(nat.id.clone()));
                }
            }
            let public: Ipv4Addr = nat
                .public_ip
                .parse()
                .map_err(|_| ScenarioModelError::InvalidNat(nat.id.clone()))?;
            if !nat_public_ips.insert(public) || addresses.contains(&IpAddr::V4(public)) {
                return Err(ScenarioModelError::DuplicateAddress(IpAddr::V4(public)));
            }
        }
        if !self.topology.nats.is_empty() && !self.requirements.nat {
            return Err(ScenarioModelError::MissingCapability("nat"));
        }
        validate_nat_chains(&self.topology.nats)?;

        let discovery = unique_ids(
            "discovery_provider",
            self.topology
                .discovery
                .iter()
                .map(|provider| provider.id.as_str()),
        )?;
        for provider in &self.topology.discovery {
            provider.validate()?;
        }
        if !self.topology.discovery.is_empty() && !self.requirements.discovery {
            return Err(ScenarioModelError::MissingCapability("discovery"));
        }

        let relays = unique_ids(
            "relay",
            self.topology.relays.iter().map(|relay| relay.id.as_str()),
        )?;
        let mut relay_urls = BTreeSet::new();
        for relay in &self.topology.relays {
            relay.validate()?;
            if !relay_urls.insert(relay.url.as_str()) {
                return Err(ScenarioModelError::InvalidRelay(relay.id.clone()));
            }
        }
        let impaired_relays = unique_ids(
            "relay_impairment",
            self.topology
                .relay_impairments
                .iter()
                .map(|impairment| impairment.relay.as_str()),
        )?;
        for impairment in &self.topology.relay_impairments {
            require_reference(&relays, &impairment.relay, ScenarioModelError::UnknownRelay)?;
            impairment.validate()?;
        }
        debug_assert_eq!(impaired_relays.len(), self.topology.relay_impairments.len());
        if !self.topology.relays.is_empty() && !self.requirements.relay {
            return Err(ScenarioModelError::MissingCapability("relay"));
        }
        for endpoint in &self.endpoints {
            if let Some(relay) = &endpoint.relay {
                require_reference(&relays, relay, ScenarioModelError::UnknownRelay)?;
            }
            if !endpoint.direct && endpoint.relay.is_none() {
                return Err(ScenarioModelError::InvalidEndpointPath(endpoint.id.clone()));
            }
        }

        let action_ids = unique_ids(
            "action",
            self.actions.iter().map(|action| action.id.as_str()),
        )?;
        let connections: BTreeSet<&str> = self
            .actions
            .iter()
            .filter_map(|action| match &action.action {
                ScenarioAction::Connect { connection, .. } => Some(connection.as_str()),
                _ => None,
            })
            .collect();
        if connections.len()
            != self
                .actions
                .iter()
                .filter(|action| matches!(action.action, ScenarioAction::Connect { .. }))
                .count()
        {
            return Err(ScenarioModelError::DuplicateId("connection"));
        }
        let mut invariant_names = BTreeSet::new();
        for invariant in &self.invariants {
            if !invariant_names.insert(invariant.name) {
                return Err(ScenarioModelError::DuplicateId("invariant"));
            }
            invariant.validate(&self.budgets)?;
        }
        for action in &self.actions {
            validate_id("action", &action.id)?;
            action.schedule.validate(
                &action.id,
                &action_ids,
                self.budgets.max_virtual_time_nanos,
            )?;
            action.action.validate(
                &self.requirements,
                &endpoint_ids,
                &connections,
                &hosts,
                &links,
                &nat_ids,
                &relays,
                &discovery,
                &interfaces,
                self.budgets.max_payload_bytes,
            )?;
            if let ActionSchedule::AfterObservation { observation } = &action.schedule {
                validate_observation_reference(
                    observation,
                    &endpoint_ids,
                    &connections,
                    &invariant_names,
                )?;
            }
        }

        let _ = unique_ids(
            "fault_rule",
            self.fault_rules.iter().map(|rule| rule.id.as_str()),
        )?;
        for rule in &self.fault_rules {
            rule.validate(&links, self.budgets.max_virtual_time_nanos)?;
        }
        self.completion
            .validate(self.budgets.max_virtual_time_nanos)?;
        if let CompletionPolicy::Observation { trigger, .. } = &self.completion {
            validate_observation_reference(trigger, &endpoint_ids, &connections, &invariant_names)?;
        }
        Ok(())
    }

    /// Returns the kernel/network subset of the scenario budgets.
    pub const fn run_budgets(&self) -> RunBudgets {
        RunBudgets {
            max_events: self.budgets.max_events,
            max_virtual_time_nanos: self.budgets.max_virtual_time_nanos,
            max_tasks: self.budgets.max_tasks,
            max_packets: self.budgets.max_packets,
        }
    }

    fn from_stage2(legacy: crate::Stage2Scenario) -> Result<Self, ScenarioModelError> {
        let family = if legacy.id.contains("ipv6") {
            IpFamily::Ipv6
        } else {
            IpFamily::Ipv4
        };
        let operation = if legacy.id.ends_with("datagram") {
            ScenarioOperation::Datagram
        } else {
            ScenarioOperation::Stream
        };
        let mut builder = ScenarioBuilder::direct_ip_echo(&legacy.id, family, operation)?;
        let scenario = builder.scenario_mut();
        scenario.metadata.tags.push("migrated-v1".to_owned());
        let fault = if legacy.id.ends_with("-loss") {
            Some(PacketFault::Loss)
        } else if legacy.id.ends_with("-corruption") {
            Some(PacketFault::Corruption)
        } else {
            None
        };
        if let Some(effect) = fault {
            scenario.fault_rules.push(FaultRule {
                id: "stage2-packet-fault".to_owned(),
                link: "lan".to_owned(),
                effect,
                probability_per_million: 250_000,
                start_nanos: 0,
                end_nanos: scenario.budgets.max_virtual_time_nanos,
                max_applications: u64::MAX,
            });
            scenario
                .allowed_terminals
                .push(AllowedTerminal::ExpectedFailure);
        }
        builder.build()
    }
}

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
    pub max_trace_events: u64,
    pub max_obligations: u64,
    pub max_actions: u64,
    pub max_payload_bytes: u64,
}

impl ScenarioBudgets {
    fn validate(&self) -> Result<(), ScenarioModelError> {
        if self.max_events == 0
            || self.max_virtual_time_nanos == 0
            || self.max_tasks == 0
            || self.max_packets == 0
            || self.max_trace_events == 0
            || self.max_obligations == 0
            || self.max_actions == 0
            || self.max_payload_bytes == 0
            || self.max_actions as usize > MAX_ITEMS
            || self.max_trace_events > 10_000_000
        {
            return Err(ScenarioModelError::InvalidBudgets);
        }
        Ok(())
    }
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
    fn validate(&self) -> Result<(), ScenarioModelError> {
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
    fn validate(&self) -> Result<(), ScenarioModelError> {
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
    fn validate(&self) -> Result<(), ScenarioModelError> {
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
    fn validate(&self, hosts: &BTreeSet<&str>) -> Result<(), ScenarioModelError> {
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
    fn validate(&self) -> Result<(), ScenarioModelError> {
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
    fn validate(&self) -> Result<(), ScenarioModelError> {
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

    fn validate(
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
    fn validate(&self) -> Result<(), ScenarioModelError> {
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

fn validate_observation_reference(
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
    fn validate(
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
            } => {
                require_reference(
                    connections,
                    connection,
                    ScenarioModelError::UnknownConnection,
                )?;
                payload.validate(max_payload)
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
    fn validate(&self, max_payload: u64) -> Result<(), ScenarioModelError> {
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
    fn validate(
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
    fn validate(&self, max_virtual_time: u64) -> Result<(), ScenarioModelError> {
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
    fn validate(&self, budgets: &ScenarioBudgets) -> Result<(), ScenarioModelError> {
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
                    max_trace_events: 200_000,
                    max_obligations: 1_024,
                    max_actions: 64,
                    max_payload_bytes: 1_048_576,
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

/// Bounds for deterministic generated scenarios.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratorConfig {
    pub max_actions: u64,
    pub max_payload_bytes: u64,
    pub max_virtual_time: Duration,
}

/// Domain-separated canonical scenario generator.
#[derive(Clone, Debug)]
pub struct ScenarioGenerator {
    root_seed: RootSeed,
    config: GeneratorConfig,
}

impl ScenarioGenerator {
    pub const fn new(root_seed: RootSeed, config: GeneratorConfig) -> Self {
        Self { root_seed, config }
    }

    pub fn generate(&self, id: &str) -> Result<Scenario, ScenarioModelError> {
        if self.config.max_actions < 7
            || self.config.max_actions as usize > MAX_ITEMS
            || self.config.max_payload_bytes == 0
            || self.config.max_virtual_time.is_zero()
        {
            return Err(ScenarioModelError::InvalidGeneratorConfig);
        }
        let source = SeededDecisionSource::new(self.root_seed);
        let mut stream = source
            .stream("scenario/generator")
            .map_err(|error| ScenarioModelError::Generation(error.to_string()))?;
        let family = if stream
            .boolean(1, 2)
            .map_err(|error| ScenarioModelError::Generation(error.to_string()))?
        {
            IpFamily::Ipv6
        } else {
            IpFamily::Ipv4
        };
        let operation = if stream
            .boolean(1, 2)
            .map_err(|error| ScenarioModelError::Generation(error.to_string()))?
        {
            ScenarioOperation::Datagram
        } else {
            ScenarioOperation::Stream
        };
        let mut builder = ScenarioBuilder::direct_ip_echo(id, family, operation)?;
        let scenario = builder.scenario_mut();
        scenario.budgets.max_actions = self.config.max_actions;
        scenario.budgets.max_payload_bytes = self.config.max_payload_bytes;
        scenario.budgets.max_virtual_time_nanos = duration_nanos(self.config.max_virtual_time)?;
        scenario.completion = CompletionPolicy::AllActions {
            shutdown_deadline_nanos: scenario.budgets.max_virtual_time_nanos,
        };
        if let Some(cleanup) = scenario
            .invariants
            .iter_mut()
            .find(|item| item.name == InvariantName::ResourceCleanup)
        {
            cleanup.deadline_nanos = Some(scenario.budgets.max_virtual_time_nanos);
        }
        let payload_bytes = stream
            .range_u64(1..self.config.max_payload_bytes.saturating_add(1))
            .map_err(|error| ScenarioModelError::Generation(error.to_string()))?;
        if let ScenarioAction::StreamRoundTrip { payload, .. }
        | ScenarioAction::DatagramRoundTrip { payload, .. } = &mut scenario.actions[3].action
        {
            payload.bytes = payload_bytes;
            payload.fill = stream
                .range_u64(0..256)
                .map_err(|error| ScenarioModelError::Generation(error.to_string()))?
                as u8;
        }
        let fault = stream
            .range_u64(0..3)
            .map_err(|error| ScenarioModelError::Generation(error.to_string()))?;
        if fault != 0 {
            scenario.fault_rules.push(FaultRule {
                id: "packet-fault".to_owned(),
                link: "lan".to_owned(),
                effect: if fault == 1 {
                    PacketFault::Loss
                } else {
                    PacketFault::Corruption
                },
                probability_per_million: 100_000,
                start_nanos: 0,
                end_nanos: scenario.budgets.max_virtual_time_nanos,
                max_applications: u64::MAX,
            });
            scenario
                .allowed_terminals
                .push(AllowedTerminal::ExpectedFailure);
        }
        builder.build()
    }
}

fn duration_nanos(duration: Duration) -> Result<u64, ScenarioModelError> {
    u64::try_from(duration.as_nanos()).map_err(|_| ScenarioModelError::DurationOverflow)
}

const fn default_true() -> bool {
    true
}

fn unique_ids<'a>(
    kind: &'static str,
    values: impl IntoIterator<Item = &'a str>,
) -> Result<BTreeSet<&'a str>, ScenarioModelError> {
    let mut result = BTreeSet::new();
    for value in values {
        validate_id(kind, value)?;
        if !result.insert(value) {
            return Err(ScenarioModelError::DuplicateId(kind));
        }
    }
    Ok(result)
}

fn require_reference(
    values: &BTreeSet<&str>,
    value: &str,
    error: fn(String) -> ScenarioModelError,
) -> Result<(), ScenarioModelError> {
    if values.contains(value) {
        Ok(())
    } else {
        Err(error(value.to_owned()))
    }
}

fn require_capability(enabled: bool, name: &'static str) -> Result<(), ScenarioModelError> {
    if enabled {
        Ok(())
    } else {
        Err(ScenarioModelError::MissingCapability(name))
    }
}

fn validate_nat_chains(nats: &[NatSpec]) -> Result<(), ScenarioModelError> {
    let upstreams = nats
        .iter()
        .map(|nat| (nat.id.as_str(), nat.upstream_nat.as_deref()))
        .collect::<BTreeMap<_, _>>();
    for nat in nats {
        let mut seen = BTreeSet::new();
        let mut current = Some(nat.id.as_str());
        while let Some(id) = current {
            if !seen.insert(id) {
                return Err(ScenarioModelError::InvalidNat(nat.id.clone()));
            }
            current = upstreams.get(id).copied().flatten();
        }
    }

    let referenced = nats
        .iter()
        .filter_map(|nat| nat.upstream_nat.as_deref())
        .collect::<BTreeSet<_>>();
    let mut roots = BTreeMap::<&str, usize>::new();
    for nat in nats
        .iter()
        .filter(|nat| !referenced.contains(nat.id.as_str()))
    {
        let count = roots.entry(nat.inside_host.as_str()).or_default();
        *count += 1;
        if *count > 1 {
            return Err(ScenarioModelError::InvalidNat(nat.id.clone()));
        }
    }
    Ok(())
}

fn validate_id(kind: &'static str, value: &str) -> Result<(), ScenarioModelError> {
    if value.is_empty()
        || value.len() > 128
        || value.split('/').any(|segment| {
            segment.is_empty()
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        return Err(ScenarioModelError::InvalidId {
            kind,
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn parse_cidr(value: &str) -> Result<(IpAddr, u8), ScenarioModelError> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| ScenarioModelError::InvalidCidr(value.to_owned()))?;
    let address: IpAddr = address
        .parse()
        .map_err(|_| ScenarioModelError::InvalidCidr(value.to_owned()))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| ScenarioModelError::InvalidCidr(value.to_owned()))?;
    let maximum = if address.is_ipv4() { 32 } else { 128 };
    if prefix > maximum {
        return Err(ScenarioModelError::InvalidCidr(value.to_owned()));
    }
    Ok((address, prefix))
}

fn cidr_contains(network: IpAddr, prefix: u8, address: IpAddr) -> bool {
    match (network, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(network) & mask == u32::from(address) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(address)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(network) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}

fn looks_like_host_path(value: &str) -> bool {
    std::path::Path::new(value).is_absolute()
        || value.starts_with("~/")
        || (value.len() >= 3
            && value.as_bytes()[1] == b':'
            && matches!(value.as_bytes()[2], b'/' | b'\\'))
}

fn is_unique<T: Ord>(values: &[T]) -> bool {
    let mut seen = BTreeSet::new();
    values.iter().all(|value| seen.insert(value))
}

/// Strict schema, reference, capability, generation, or canonicalization failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScenarioModelError {
    Json(String),
    UnsupportedSchema(u16),
    InvalidMetadata,
    InvalidBudgets,
    TooManyActions,
    TooManyItems,
    NoAllowedTerminal,
    InvalidId { kind: &'static str, value: String },
    DuplicateId(&'static str),
    UnknownLink(String),
    UnknownHost(String),
    UnknownEndpoint(String),
    UnknownConnection(String),
    UnknownNat(String),
    UnknownRelay(String),
    UnknownDiscovery(String),
    UnknownInterface { host: String, interface: String },
    HostWithoutInterface(String),
    InterfaceWithoutAddress(String),
    DuplicateAddress(IpAddr),
    InvalidCidr(String),
    InvalidSocket(String),
    EndpointAddressNotOwned { endpoint: String, address: IpAddr },
    InvalidIdentityOrdinal(String),
    InvalidEndpointPath(String),
    InvalidLink(String),
    InvalidNat(String),
    InvalidRelay(String),
    InvalidFirewall(String),
    InvalidDiscovery(String),
    InvalidTrigger(String),
    ActionAfterBudget(String),
    InvalidAction(&'static str),
    InvalidPayload(u64),
    MissingCapability(&'static str),
    InvalidFaultRule(String),
    InvalidCompletion,
    InvalidInvariant(InvariantName),
    InvalidGeneratorConfig,
    Generation(String),
    Legacy(String),
    DurationOverflow,
}

impl fmt::Display for ScenarioModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(f, "scenario JSON is invalid: {error}"),
            Self::UnsupportedSchema(version) => write!(f, "unsupported scenario schema {version}"),
            Self::InvalidMetadata => f.write_str("scenario metadata is invalid"),
            Self::InvalidBudgets => f.write_str("scenario budgets are invalid"),
            Self::TooManyActions => f.write_str("scenario action limit exceeded"),
            Self::TooManyItems => f.write_str("scenario item limit exceeded"),
            Self::NoAllowedTerminal => f.write_str("scenario has no allowed terminal state"),
            Self::InvalidId { kind, value } => write!(f, "invalid {kind} ID {value:?}"),
            Self::DuplicateId(kind) => write!(f, "duplicate {kind} ID"),
            Self::UnknownLink(value) => write!(f, "unknown link {value:?}"),
            Self::UnknownHost(value) => write!(f, "unknown host {value:?}"),
            Self::UnknownEndpoint(value) => write!(f, "unknown endpoint {value:?}"),
            Self::UnknownConnection(value) => write!(f, "unknown connection {value:?}"),
            Self::UnknownNat(value) => write!(f, "unknown NAT {value:?}"),
            Self::UnknownRelay(value) => write!(f, "unknown relay {value:?}"),
            Self::UnknownDiscovery(value) => {
                write!(f, "unknown discovery provider {value:?}")
            }
            Self::UnknownInterface { host, interface } => {
                write!(f, "unknown interface {host:?}/{interface:?}")
            }
            Self::HostWithoutInterface(value) => write!(f, "host {value:?} has no interface"),
            Self::InterfaceWithoutAddress(value) => write!(f, "interface {value:?} has no address"),
            Self::DuplicateAddress(value) => write!(f, "duplicate interface address {value}"),
            Self::InvalidCidr(value) => write!(f, "invalid interface CIDR {value:?}"),
            Self::InvalidSocket(value) => write!(f, "invalid endpoint socket {value:?}"),
            Self::EndpointAddressNotOwned { endpoint, address } => {
                write!(f, "endpoint {endpoint:?} host does not own {address}")
            }
            Self::InvalidIdentityOrdinal(value) => {
                write!(f, "endpoint {value:?} identity ordinal must be nonzero")
            }
            Self::InvalidEndpointPath(value) => {
                write!(f, "endpoint {value:?} has no direct or relay path")
            }
            Self::InvalidLink(value) => write!(f, "invalid link {value:?}"),
            Self::InvalidNat(value) => write!(f, "invalid NAT {value:?}"),
            Self::InvalidRelay(value) => write!(f, "invalid relay {value:?}"),
            Self::InvalidFirewall(value) => write!(f, "invalid firewall {value:?}"),
            Self::InvalidDiscovery(value) => write!(f, "invalid discovery record {value:?}"),
            Self::InvalidTrigger(value) => write!(f, "invalid action trigger {value:?}"),
            Self::ActionAfterBudget(value) => {
                write!(f, "action {value:?} exceeds virtual-time budget")
            }
            Self::InvalidAction(value) => write!(f, "invalid {value} action"),
            Self::InvalidPayload(value) => write!(f, "invalid payload size {value}"),
            Self::MissingCapability(value) => {
                write!(f, "scenario action requires {value} capability")
            }
            Self::InvalidFaultRule(value) => write!(f, "invalid fault rule {value:?}"),
            Self::InvalidCompletion => f.write_str("invalid completion policy"),
            Self::InvalidInvariant(value) => write!(f, "invalid invariant bounds for {value:?}"),
            Self::InvalidGeneratorConfig => f.write_str("invalid scenario generator bounds"),
            Self::Generation(error) => write!(f, "scenario generation failed: {error}"),
            Self::Legacy(error) => write!(f, "legacy scenario migration failed: {error}"),
            Self::DurationOverflow => f.write_str("scenario duration does not fit nanoseconds"),
        }
    }
}

impl std::error::Error for ScenarioModelError {}
