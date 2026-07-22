//! Deterministic stateful IPv4 NAT mapping and filtering model.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use iroh_runtime::{DecisionStream, RuntimeContext, TraceContext, TraceEventKind};
use serde::{Deserialize, Serialize};

use crate::{IpCidr, Kernel, LedgerError, ResourceKind, ResourceToken, ScheduledEvent};

/// Outbound mapping-key behavior.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NatMappingBehavior {
    EndpointIndependent,
    AddressDependent,
    AddressAndPortDependent,
}

/// Inbound filtering behavior for remotes learned through outbound traffic.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NatFilteringBehavior {
    EndpointIndependent,
    AddressDependent,
    AddressAndPortDependent,
}

/// Packet direction at a modeled firewall.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallDirection {
    Inbound,
    Outbound,
}

/// Network protocol predicate. The current synthetic socket boundary carries UDP.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallProtocol {
    Any,
    Udp,
}

/// Stable firewall terminal decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallAction {
    Allow,
    Drop,
    Reject,
}

/// Optional state predicate on a rule.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallConnectionState {
    Any,
    New,
    Established,
}

/// One ordered UDP firewall rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirewallRule {
    pub id: String,
    pub protocol: FirewallProtocol,
    pub direction: Option<FirewallDirection>,
    pub source: Option<IpCidr>,
    pub destination: Option<IpCidr>,
    pub source_ports: Option<(u16, u16)>,
    pub destination_ports: Option<(u16, u16)>,
    pub connection_state: FirewallConnectionState,
    pub action: FirewallAction,
}

/// Ordered firewall configuration and default policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirewallConfig {
    pub id: String,
    pub rules: Vec<FirewallRule>,
    pub default_action: FirewallAction,
}

/// One tuple to evaluate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirewallPacket {
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

/// Rule/default decision with pre-decision connection state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirewallDecision {
    pub rule: String,
    pub action: FirewallAction,
    pub established: bool,
}

/// Deterministic ordered stateful UDP firewall.
#[derive(Debug)]
pub struct Firewall {
    context: Arc<RuntimeContext>,
    config: FirewallConfig,
    established_inbound: BTreeSet<(SocketAddr, SocketAddr)>,
}

impl Firewall {
    pub fn new(context: Arc<RuntimeContext>, config: FirewallConfig) -> Result<Self, NatError> {
        validate_firewall(&config)?;
        Ok(Self {
            context,
            config,
            established_inbound: BTreeSet::new(),
        })
    }

    pub fn evaluate(
        &mut self,
        direction: FirewallDirection,
        packet: FirewallPacket,
    ) -> Result<FirewallDecision, NatError> {
        let decision = self.evaluate_uncommitted(direction, packet)?;
        if decision.action == FirewallAction::Allow && direction == FirewallDirection::Outbound {
            self.commit_outbound(packet);
        }
        Ok(decision)
    }

    /// Evaluates and traces a rule without mutating connection-tracking state.
    pub fn evaluate_uncommitted(
        &self,
        direction: FirewallDirection,
        packet: FirewallPacket,
    ) -> Result<FirewallDecision, NatError> {
        let established = match direction {
            FirewallDirection::Inbound => self
                .established_inbound
                .contains(&(packet.source, packet.destination)),
            FirewallDirection::Outbound => false,
        };
        let matched = self.config.rules.iter().find(|rule| {
            matches!(rule.protocol, FirewallProtocol::Any | FirewallProtocol::Udp)
                && rule.direction.is_none_or(|value| value == direction)
                && rule
                    .source
                    .is_none_or(|value| value.contains(packet.source.ip()))
                && rule
                    .destination
                    .is_none_or(|value| value.contains(packet.destination.ip()))
                && rule
                    .source_ports
                    .is_none_or(|(start, end)| (start..=end).contains(&packet.source.port()))
                && rule
                    .destination_ports
                    .is_none_or(|(start, end)| (start..=end).contains(&packet.destination.port()))
                && match rule.connection_state {
                    FirewallConnectionState::Any => true,
                    FirewallConnectionState::New => !established,
                    FirewallConnectionState::Established => established,
                }
        });
        let (rule, action) = matched.map_or_else(
            || ("default".to_owned(), self.config.default_action),
            |rule| (rule.id.clone(), rule.action),
        );
        self.context.trace().record(
            self.context.clock().elapsed_nanos()?,
            TraceContext {
                firewall: Some(self.config.id.clone()),
                ..TraceContext::default()
            },
            TraceEventKind::FirewallDecision {
                rule: rule.clone(),
                action: format!("{action:?}").to_ascii_lowercase(),
                direction: format!("{direction:?}").to_ascii_lowercase(),
            },
        )?;
        Ok(FirewallDecision {
            rule,
            action,
            established,
        })
    }

    /// Commits an allowed outbound flow after packet admission succeeds.
    pub fn commit_outbound(&mut self, packet: FirewallPacket) {
        self.established_inbound
            .insert((packet.destination, packet.source));
    }

    pub fn clear_state(&mut self) {
        self.established_inbound.clear();
    }
}

/// Strict gateway policy and resource bounds.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NatConfig {
    pub id: String,
    pub public_ip: Ipv4Addr,
    pub port_start: u16,
    pub port_end: u16,
    pub mapping_behavior: NatMappingBehavior,
    pub filtering_behavior: NatFilteringBehavior,
    pub mapping_ttl: Duration,
    pub hairpin: bool,
    pub max_mappings: u64,
}

/// Stable externally inspectable mapping state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NatMappingSnapshot {
    pub id: String,
    pub internal: SocketAddr,
    pub external: SocketAddr,
    pub expires_nanos: u64,
    #[serde(default)]
    pub port_mapping: bool,
    pub allowed_addresses: Vec<IpAddr>,
    pub allowed_endpoints: Vec<SocketAddr>,
}

/// Result of outbound translation, including optional hairpin delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NatOutbound {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub mapping: String,
    pub expires_nanos: u64,
    pub created: bool,
    pub hairpin_target: Option<SocketAddr>,
}

/// Result of inbound translation, including the refreshed mapping deadline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NatInbound {
    pub destination: SocketAddr,
    pub mapping: String,
    pub expires_nanos: u64,
}

/// Simulator-owned port-mapping lease installed in a NAT table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NatPortMapping {
    pub mapping: String,
    pub internal: SocketAddr,
    pub external: SocketAddr,
    pub expires_nanos: u64,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct MappingKey {
    internal: SocketAddr,
    remote_address: Option<IpAddr>,
    remote_endpoint: Option<SocketAddr>,
}

struct Mapping {
    id: String,
    internal: SocketAddr,
    external: SocketAddr,
    expires_nanos: u64,
    port_mapping: bool,
    allowed_addresses: BTreeSet<IpAddr>,
    allowed_endpoints: BTreeSet<SocketAddr>,
    expiry_event: Option<ScheduledEvent>,
    _resource: ResourceToken,
}

/// Single-gateway state machine. Multiple instances may be chained for double NAT/CGNAT.
pub struct NatTable {
    kernel: Kernel,
    context: Arc<RuntimeContext>,
    config: NatConfig,
    mappings: BTreeMap<MappingKey, Mapping>,
    by_external: BTreeMap<SocketAddr, MappingKey>,
    port_decisions: Box<dyn DecisionStream>,
    next_mapping: u64,
}

impl fmt::Debug for NatTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NatTable")
            .field("config", &self.config)
            .field("mappings", &self.mappings.len())
            .finish()
    }
}

impl NatTable {
    pub fn new(
        kernel: Kernel,
        context: Arc<RuntimeContext>,
        config: NatConfig,
    ) -> Result<Self, NatError> {
        validate_config(&config)?;
        let port_decisions = context
            .decisions()
            .stream(&format!("network/nat/{}/external-port", config.id))?;
        Ok(Self {
            kernel,
            context,
            config,
            mappings: BTreeMap::new(),
            by_external: BTreeMap::new(),
            port_decisions,
            next_mapping: 0,
        })
    }

    pub fn config(&self) -> &NatConfig {
        &self.config
    }

    pub fn translate_outbound(
        &mut self,
        now_nanos: u64,
        internal: SocketAddr,
        destination: SocketAddr,
    ) -> Result<NatOutbound, NatError> {
        self.translate_outbound_traced(now_nanos, internal, destination, None)
    }

    /// Translates outbound traffic and correlates all translation events to a packet identity.
    pub fn translate_outbound_for_packet(
        &mut self,
        now_nanos: u64,
        internal: SocketAddr,
        destination: SocketAddr,
        packet: u64,
    ) -> Result<NatOutbound, NatError> {
        self.translate_outbound_traced(now_nanos, internal, destination, Some(packet))
    }

    fn translate_outbound_traced(
        &mut self,
        now_nanos: u64,
        internal: SocketAddr,
        destination: SocketAddr,
        packet: Option<u64>,
    ) -> Result<NatOutbound, NatError> {
        require_ipv4(internal)?;
        require_ipv4(destination)?;
        self.expire(now_nanos)?;
        if destination.ip() == IpAddr::V4(self.config.public_ip) && !self.config.hairpin {
            self.trace_translation(
                "hairpin",
                internal,
                destination,
                None,
                None,
                "dropped:hairpin_disabled",
                packet,
            )?;
            return Err(NatError::HairpinDisabled);
        }
        let key = self
            .mappings
            .iter()
            .find_map(|(key, mapping)| {
                (mapping.port_mapping && mapping.internal == internal).then(|| key.clone())
            })
            .unwrap_or_else(|| mapping_key(self.config.mapping_behavior, internal, destination));
        let expires = expiry(now_nanos, self.config.mapping_ttl)?;
        let created = !self.mappings.contains_key(&key);
        if created {
            if self.mappings.len() as u64 >= self.config.max_mappings {
                return Err(NatError::MappingLimit(self.config.max_mappings));
            }
            let external = self.allocate_external()?;
            self.next_mapping = self
                .next_mapping
                .checked_add(1)
                .ok_or(NatError::MappingIdExhausted)?;
            let id = format!("{}/mapping/{}", self.config.id, self.next_mapping);
            let resource = self
                .kernel
                .acquire_resource(ResourceKind::Mapping, Some(self.config.max_mappings))?;
            self.by_external.insert(external, key.clone());
            self.mappings.insert(
                key.clone(),
                Mapping {
                    id,
                    internal,
                    external,
                    expires_nanos: expires,
                    port_mapping: false,
                    allowed_addresses: BTreeSet::new(),
                    allowed_endpoints: BTreeSet::new(),
                    expiry_event: None,
                    _resource: resource,
                },
            );
        }
        let mapping = self.mappings.get_mut(&key).expect("mapping exists");
        mapping.expires_nanos = expires;
        match self.config.filtering_behavior {
            NatFilteringBehavior::EndpointIndependent => {}
            NatFilteringBehavior::AddressDependent => {
                mapping.allowed_addresses.insert(destination.ip());
            }
            NatFilteringBehavior::AddressAndPortDependent => {
                mapping.allowed_endpoints.insert(destination);
            }
        }
        let external = mapping.external;
        let mapping_id = mapping.id.clone();
        self.trace_mapping(if created { "created" } else { "reused" }, &key)?;

        let hairpin_target = if destination.ip() == IpAddr::V4(self.config.public_ip) {
            Some(self.translate_inbound_inner(now_nanos, destination, external, true, packet)?)
        } else {
            None
        };
        self.trace_translation(
            if hairpin_target.is_some() {
                "hairpin"
            } else {
                "outbound"
            },
            internal,
            destination,
            Some(external),
            hairpin_target.or(Some(destination)),
            "translated",
            packet,
        )?;
        Ok(NatOutbound {
            source: external,
            destination: hairpin_target.unwrap_or(destination),
            mapping: mapping_id,
            expires_nanos: expires,
            created,
            hairpin_target,
        })
    }

    pub fn translate_inbound(
        &mut self,
        now_nanos: u64,
        external_destination: SocketAddr,
        remote_source: SocketAddr,
    ) -> Result<SocketAddr, NatError> {
        self.translate_inbound_detailed(now_nanos, external_destination, remote_source)
            .map(|translated| translated.destination)
    }

    /// Translates inbound traffic and returns the mapping identity and refreshed expiry.
    pub fn translate_inbound_detailed(
        &mut self,
        now_nanos: u64,
        external_destination: SocketAddr,
        remote_source: SocketAddr,
    ) -> Result<NatInbound, NatError> {
        self.translate_inbound_detailed_traced(now_nanos, external_destination, remote_source, None)
    }

    /// Translates inbound traffic and correlates translation events to a packet identity.
    pub fn translate_inbound_for_packet(
        &mut self,
        now_nanos: u64,
        external_destination: SocketAddr,
        remote_source: SocketAddr,
        packet: u64,
    ) -> Result<NatInbound, NatError> {
        self.translate_inbound_detailed_traced(
            now_nanos,
            external_destination,
            remote_source,
            Some(packet),
        )
    }

    fn translate_inbound_detailed_traced(
        &mut self,
        now_nanos: u64,
        external_destination: SocketAddr,
        remote_source: SocketAddr,
        packet: Option<u64>,
    ) -> Result<NatInbound, NatError> {
        self.translate_inbound_inner(
            now_nanos,
            external_destination,
            remote_source,
            false,
            packet,
        )?;
        let key = self
            .by_external
            .get(&external_destination)
            .expect("successful translation retains its mapping");
        let mapping = self.mappings.get(key).expect("indexes remain consistent");
        Ok(NatInbound {
            destination: mapping.internal,
            mapping: mapping.id.clone(),
            expires_nanos: mapping.expires_nanos,
        })
    }

    /// Replaces the cancellable expiry owner for the named mapping.
    pub fn install_expiry_event(
        &mut self,
        mapping_id: &str,
        expires_nanos: u64,
        event: ScheduledEvent,
    ) -> Result<(), NatError> {
        let mapping = self
            .mappings
            .values_mut()
            .find(|mapping| mapping.id == mapping_id)
            .ok_or_else(|| NatError::UnknownMapping(mapping_id.to_owned()))?;
        if mapping.expires_nanos != expires_nanos {
            return Err(NatError::StaleExpiry {
                mapping: mapping_id.to_owned(),
                expected: mapping.expires_nanos,
                actual: expires_nanos,
            });
        }
        mapping.expiry_event = Some(event);
        Ok(())
    }

    fn translate_inbound_inner(
        &mut self,
        now_nanos: u64,
        external_destination: SocketAddr,
        remote_source: SocketAddr,
        hairpin: bool,
        packet: Option<u64>,
    ) -> Result<SocketAddr, NatError> {
        require_ipv4(external_destination)?;
        require_ipv4(remote_source)?;
        self.expire(now_nanos)?;
        let key = self
            .by_external
            .get(&external_destination)
            .cloned()
            .ok_or(NatError::NoMapping(external_destination))?;
        let mapping = self.mappings.get_mut(&key).expect("index is consistent");
        let allowed = mapping.port_mapping
            || match self.config.filtering_behavior {
                NatFilteringBehavior::EndpointIndependent => true,
                NatFilteringBehavior::AddressDependent => {
                    mapping.allowed_addresses.contains(&remote_source.ip())
                }
                NatFilteringBehavior::AddressAndPortDependent => {
                    mapping.allowed_endpoints.contains(&remote_source)
                }
            };
        if !allowed {
            self.trace_translation(
                if hairpin { "hairpin" } else { "inbound" },
                remote_source,
                external_destination,
                None,
                None,
                "dropped:filtered",
                packet,
            )?;
            return Err(NatError::Filtered(remote_source));
        }
        mapping.expires_nanos = expiry(now_nanos, self.config.mapping_ttl)?;
        let internal = mapping.internal;
        self.trace_translation(
            if hairpin { "hairpin" } else { "inbound" },
            remote_source,
            external_destination,
            Some(remote_source),
            Some(internal),
            "translated",
            packet,
        )?;
        Ok(internal)
    }

    pub fn expire(&mut self, now_nanos: u64) -> Result<Vec<String>, NatError> {
        let keys = self
            .mappings
            .iter()
            .filter(|(_, mapping)| now_nanos >= mapping.expires_nanos)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        let mut expired = Vec::with_capacity(keys.len());
        for key in keys {
            let mapping = self.mappings.remove(&key).expect("key was collected");
            self.by_external.remove(&mapping.external);
            self.trace_mapping_values("expired", &mapping)?;
            expired.push(mapping.id);
        }
        Ok(expired)
    }

    pub fn rebind(
        &mut self,
        now_nanos: u64,
        public_ip: Ipv4Addr,
        preserve_ports: bool,
    ) -> Result<(), NatError> {
        self.expire(now_nanos)?;
        if public_ip.is_unspecified() || public_ip.is_multicast() {
            return Err(NatError::InvalidConfig);
        }
        if preserve_ports {
            self.by_external.clear();
            let keys = self.mappings.keys().cloned().collect::<Vec<_>>();
            for key in keys {
                let mapping = self.mappings.get_mut(&key).expect("key exists");
                mapping.external.set_ip(IpAddr::V4(public_ip));
                self.by_external.insert(mapping.external, key.clone());
                self.trace_mapping("rebound", &key)?;
            }
        } else {
            let mappings = std::mem::take(&mut self.mappings);
            self.by_external.clear();
            for (_, mapping) in mappings {
                self.trace_mapping_values("removed", &mapping)?;
            }
        }
        self.config.public_ip = public_ip;
        Ok(())
    }

    pub fn snapshot(&self) -> Vec<NatMappingSnapshot> {
        self.mappings
            .values()
            .map(|mapping| NatMappingSnapshot {
                id: mapping.id.clone(),
                internal: mapping.internal,
                external: mapping.external,
                expires_nanos: mapping.expires_nanos,
                port_mapping: mapping.port_mapping,
                allowed_addresses: mapping.allowed_addresses.iter().copied().collect(),
                allowed_endpoints: mapping.allowed_endpoints.iter().copied().collect(),
            })
            .collect()
    }

    /// Installs or renews an endpoint-independent inbound UDP port mapping.
    pub fn procure_port_mapping(
        &mut self,
        now_nanos: u64,
        internal: SocketAddr,
    ) -> Result<NatPortMapping, NatError> {
        require_ipv4(internal)?;
        self.expire(now_nanos)?;
        let expires_nanos = expiry(now_nanos, self.config.mapping_ttl)?;
        let existing = self.mappings.iter().find_map(|(key, mapping)| {
            (mapping.port_mapping && mapping.internal == internal).then(|| key.clone())
        });
        let (key, transition) = if let Some(key) = existing {
            (key, "renewed")
        } else {
            if self.mappings.len() as u64 >= self.config.max_mappings {
                return Err(NatError::MappingLimit(self.config.max_mappings));
            }
            let key = MappingKey {
                internal,
                remote_address: None,
                remote_endpoint: None,
            };
            if self.mappings.contains_key(&key) {
                return Err(NatError::PortMappingConflict(internal));
            }
            let external = self.allocate_external()?;
            self.next_mapping = self
                .next_mapping
                .checked_add(1)
                .ok_or(NatError::MappingIdExhausted)?;
            let id = format!("{}/port-map/{}", self.config.id, self.next_mapping);
            let resource = self
                .kernel
                .acquire_resource(ResourceKind::Mapping, Some(self.config.max_mappings))?;
            self.by_external.insert(external, key.clone());
            self.mappings.insert(
                key.clone(),
                Mapping {
                    id,
                    internal,
                    external,
                    expires_nanos,
                    port_mapping: true,
                    allowed_addresses: BTreeSet::new(),
                    allowed_endpoints: BTreeSet::new(),
                    expiry_event: None,
                    _resource: resource,
                },
            );
            (key, "created")
        };
        let mapping = self.mappings.get_mut(&key).expect("mapping exists");
        mapping.expires_nanos = expires_nanos;
        let result = NatPortMapping {
            mapping: mapping.id.clone(),
            internal: mapping.internal,
            external: mapping.external,
            expires_nanos,
        };
        self.trace_mapping(transition, &key)?;
        Ok(result)
    }

    /// Removes one explicit port mapping; dynamic mappings are not affected.
    pub fn remove_port_mapping(&mut self, mapping_id: &str) -> Result<bool, NatError> {
        let key = self.mappings.iter().find_map(|(key, mapping)| {
            (mapping.port_mapping && mapping.id == mapping_id).then(|| key.clone())
        });
        let Some(key) = key else {
            return Ok(false);
        };
        let mapping = self.mappings.remove(&key).expect("mapping key exists");
        self.by_external.remove(&mapping.external);
        self.trace_mapping_values("removed", &mapping)?;
        Ok(true)
    }

    /// Rolls back a newly-created dynamic mapping during packet-admission failure.
    ///
    /// Explicit port mappings and previously-existing dynamic mappings are never removed by this
    /// operation. Dropping the mapping also cancels its owned expiry event and releases its ledger
    /// token.
    pub fn rollback_dynamic_mapping(&mut self, mapping_id: &str) -> Result<bool, NatError> {
        let key = self.mappings.iter().find_map(|(key, mapping)| {
            (!mapping.port_mapping && mapping.id == mapping_id).then(|| key.clone())
        });
        let Some(key) = key else {
            return Ok(false);
        };
        let mapping = self.mappings.remove(&key).expect("mapping key exists");
        self.by_external.remove(&mapping.external);
        self.trace_mapping_values("rolled_back", &mapping)?;
        Ok(true)
    }

    /// Removes every mapping and releases its resource ownership.
    pub fn clear(&mut self) -> Result<Vec<String>, NatError> {
        let mappings = std::mem::take(&mut self.mappings);
        self.by_external.clear();
        let mut removed = Vec::with_capacity(mappings.len());
        for (_, mapping) in mappings {
            self.trace_mapping_values("removed", &mapping)?;
            removed.push(mapping.id);
        }
        Ok(removed)
    }

    fn allocate_external(&mut self) -> Result<SocketAddr, NatError> {
        let slots = u64::from(self.config.port_end - self.config.port_start) + 1;
        let offset = self.port_decisions.range_u64(0..slots)?;
        for attempt in 0..slots {
            let ordinal = (offset + attempt) % slots;
            let port = self.config.port_start + ordinal as u16;
            let candidate = SocketAddr::new(IpAddr::V4(self.config.public_ip), port);
            if !self.by_external.contains_key(&candidate) {
                return Ok(candidate);
            }
        }
        Err(NatError::PortExhausted)
    }

    fn trace_mapping(&self, transition: &str, key: &MappingKey) -> Result<(), NatError> {
        self.trace_mapping_values(
            transition,
            self.mappings.get(key).expect("mapping exists for trace"),
        )
    }

    fn trace_mapping_values(&self, transition: &str, mapping: &Mapping) -> Result<(), NatError> {
        self.context.trace().record(
            self.context.clock().elapsed_nanos()?,
            TraceContext {
                nat: Some(self.config.id.clone()),
                ..TraceContext::default()
            },
            TraceEventKind::NatMapping {
                mapping: mapping.id.clone(),
                transition: transition.to_owned(),
                internal: mapping.internal.to_string(),
                external: mapping.external.to_string(),
                expires_nanos: mapping.expires_nanos,
            },
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn trace_translation(
        &self,
        direction: &str,
        original_source: SocketAddr,
        original_destination: SocketAddr,
        translated_source: Option<SocketAddr>,
        translated_destination: Option<SocketAddr>,
        outcome: &str,
        packet: Option<u64>,
    ) -> Result<(), NatError> {
        self.context.trace().record(
            self.context.clock().elapsed_nanos()?,
            TraceContext {
                nat: Some(self.config.id.clone()),
                packet: packet.map(|packet| packet.to_string()),
                ..TraceContext::default()
            },
            TraceEventKind::NatTranslation {
                direction: direction.to_owned(),
                original_source: original_source.to_string(),
                original_destination: original_destination.to_string(),
                translated_source: translated_source.map(|value| value.to_string()),
                translated_destination: translated_destination.map(|value| value.to_string()),
                outcome: outcome.to_owned(),
            },
        )?;
        Ok(())
    }
}

fn mapping_key(
    behavior: NatMappingBehavior,
    internal: SocketAddr,
    remote: SocketAddr,
) -> MappingKey {
    match behavior {
        NatMappingBehavior::EndpointIndependent => MappingKey {
            internal,
            remote_address: None,
            remote_endpoint: None,
        },
        NatMappingBehavior::AddressDependent => MappingKey {
            internal,
            remote_address: Some(remote.ip()),
            remote_endpoint: None,
        },
        NatMappingBehavior::AddressAndPortDependent => MappingKey {
            internal,
            remote_address: None,
            remote_endpoint: Some(remote),
        },
    }
}

fn expiry(now: u64, ttl: Duration) -> Result<u64, NatError> {
    now.checked_add(u64::try_from(ttl.as_nanos()).map_err(|_| NatError::TimelineOverflow)?)
        .ok_or(NatError::TimelineOverflow)
}

fn require_ipv4(address: SocketAddr) -> Result<(), NatError> {
    if address.is_ipv4() {
        Ok(())
    } else {
        Err(NatError::UnsupportedFamily(address))
    }
}

fn validate_config(config: &NatConfig) -> Result<(), NatError> {
    if config.id.is_empty()
        || config.id.len() > 64
        || !config
            .id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || config.public_ip.is_unspecified()
        || config.public_ip.is_multicast()
        || config.port_start == 0
        || config.port_start > config.port_end
        || config.mapping_ttl.is_zero()
        || config.max_mappings == 0
    {
        Err(NatError::InvalidConfig)
    } else {
        Ok(())
    }
}

fn validate_firewall(config: &FirewallConfig) -> Result<(), NatError> {
    if config.id.is_empty() || config.rules.len() > 10_000 {
        return Err(NatError::InvalidFirewall);
    }
    let mut ids = BTreeSet::new();
    for rule in &config.rules {
        if rule.id.is_empty()
            || !ids.insert(rule.id.as_str())
            || rule
                .source_ports
                .is_some_and(|(start, end)| start == 0 || start > end)
            || rule
                .destination_ports
                .is_some_and(|(start, end)| start == 0 || start > end)
        {
            return Err(NatError::InvalidFirewall);
        }
    }
    Ok(())
}

/// Invalid policy, translation, allocation, expiry, or trace outcome.
#[derive(Debug)]
pub enum NatError {
    InvalidConfig,
    InvalidFirewall,
    UnsupportedFamily(SocketAddr),
    MappingLimit(u64),
    MappingIdExhausted,
    UnknownMapping(String),
    StaleExpiry {
        mapping: String,
        expected: u64,
        actual: u64,
    },
    PortExhausted,
    NoMapping(SocketAddr),
    Filtered(SocketAddr),
    HairpinDisabled,
    PortMappingConflict(SocketAddr),
    TimelineOverflow,
    Decision(iroh_runtime::DecisionError),
    Ledger(LedgerError),
    Clock(iroh_runtime::ClockError),
    Trace(iroh_runtime::TraceRecordError),
}

impl fmt::Display for NatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for NatError {}

impl From<iroh_runtime::DecisionError> for NatError {
    fn from(value: iroh_runtime::DecisionError) -> Self {
        Self::Decision(value)
    }
}
impl From<LedgerError> for NatError {
    fn from(value: LedgerError) -> Self {
        Self::Ledger(value)
    }
}
impl From<iroh_runtime::ClockError> for NatError {
    fn from(value: iroh_runtime::ClockError) -> Self {
        Self::Clock(value)
    }
}
impl From<iroh_runtime::TraceRecordError> for NatError {
    fn from(value: iroh_runtime::TraceRecordError) -> Self {
        Self::Trace(value)
    }
}
