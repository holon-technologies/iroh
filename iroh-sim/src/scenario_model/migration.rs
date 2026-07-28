use super::*;

impl Scenario {
    /// Parses the current schema or explicitly migrates a supported older document.
    pub fn from_versioned_json(bytes: &[u8]) -> Result<Self, ScenarioModelError> {
        #[derive(Deserialize)]
        struct VersionProbe {
            schema_version: u16,
        }

        let probe: VersionProbe = serde_json::from_slice(bytes)
            .map_err(|error| ScenarioModelError::Json(error.to_string()))?;
        match probe.schema_version {
            SCENARIO_SCHEMA_VERSION => Self::from_json(bytes),
            SCENARIO_V2_SCHEMA_VERSION => {
                let scenario: ScenarioV2 = serde_json::from_slice(bytes)
                    .map_err(|error| ScenarioModelError::Json(error.to_string()))?;
                scenario.migrate()
            }
            crate::STAGE2_SCENARIO_SCHEMA_VERSION => {
                let legacy = crate::Stage2Scenario::from_json(bytes)
                    .map_err(|error| ScenarioModelError::Legacy(error.to_string()))?;
                Self::from_stage2(legacy)
            }
            version => Err(ScenarioModelError::UnsupportedSchema(version)),
        }
    }

    /// Strictly parses, normalizes, and validates a current-version JSON scenario.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ScenarioModelError> {
        #[derive(Deserialize)]
        struct VersionProbe {
            schema_version: u16,
        }

        let probe: VersionProbe = serde_json::from_slice(bytes)
            .map_err(|error| ScenarioModelError::Json(error.to_string()))?;
        if probe.schema_version != SCENARIO_SCHEMA_VERSION {
            return Err(ScenarioModelError::UnsupportedSchema(probe.schema_version));
        }
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
        self.invariants.sort_by_key(|invariant| invariant.name);
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
        let action_count = u64::try_from(self.actions.len()).unwrap_or(u64::MAX);
        if action_count > self.budgets.max_actions || self.actions.len() > MAX_ITEMS {
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
                self.budgets.max_virtual_time_nanos,
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

/// Strict decoder for the previous declarative schema.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScenarioV2 {
    schema_version: u16,
    metadata: ScenarioMetadata,
    requirements: ScenarioRequirements,
    budgets: ScenarioBudgetsV2,
    topology: ScenarioTopology,
    endpoints: Vec<EndpointSpec>,
    actions: Vec<ActionSpec>,
    fault_rules: Vec<FaultRule>,
    fairness: Vec<FairnessAssumption>,
    completion: CompletionPolicy,
    allowed_terminals: Vec<AllowedTerminal>,
    invariants: Vec<InvariantSpec>,
}

impl ScenarioV2 {
    fn migrate(self) -> Result<Scenario, ScenarioModelError> {
        if self.schema_version != SCENARIO_V2_SCHEMA_VERSION {
            return Err(ScenarioModelError::UnsupportedSchema(self.schema_version));
        }
        let max_relays = u64::try_from(self.topology.relays.len())
            .unwrap_or(u64::MAX)
            .max(1);
        let ScenarioBudgetsV2 {
            max_events,
            max_virtual_time_nanos,
            max_tasks,
            max_packets,
            max_trace_events,
            max_obligations,
            max_actions,
            max_payload_bytes,
        } = self.budgets;
        Scenario {
            schema_version: SCENARIO_SCHEMA_VERSION,
            metadata: self.metadata,
            requirements: self.requirements,
            budgets: ScenarioBudgets {
                max_events,
                max_virtual_time_nanos,
                max_tasks,
                max_packets,
                max_obligations,
                max_actions,
                max_payload_bytes,
                resources: ScenarioResourceLimits {
                    max_scheduled_events: max_events,
                    max_trace_events,
                    max_timers: max_events,
                    max_sockets: max_events,
                    max_connections: max_actions,
                    max_streams: max_actions,
                    max_relays,
                },
            },
            topology: self.topology,
            endpoints: self.endpoints,
            actions: self.actions,
            fault_rules: self.fault_rules,
            fairness: self.fairness,
            completion: self.completion,
            allowed_terminals: self.allowed_terminals,
            invariants: self.invariants,
        }
        .normalized()
    }
}
