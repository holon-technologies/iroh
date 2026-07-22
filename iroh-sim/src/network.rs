//! Deterministic in-memory IPv4/IPv6 UDP network used by production Iroh transports.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroUsize,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll, Waker},
    time::Duration,
};

use iroh::simulation::{IpSocket, IpSocketFactory, IpSocketSender};
use iroh_runtime::{
    DecisionError, DecisionStream, RuntimeContext, TraceContext, TraceEventKind, TraceRecordError,
};

use crate::{
    EventClass, Firewall, FirewallAction, FirewallConfig, FirewallDirection, FirewallPacket,
    Kernel, KernelError, LedgerError, NatConfig, NatError, NatMappingSnapshot, NatTable,
    ResourceKind, ResourceToken,
};

const PROBABILITY_DENOMINATOR: u64 = 1_000_000;

/// Global bounds and deterministic ephemeral-port policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkConfig {
    /// Maximum simultaneously queued packet copies.
    pub max_packets: u64,
    /// First port considered for deterministic ephemeral allocation.
    pub ephemeral_port_start: u16,
}

/// Directional characteristics and packet-fault policy of one link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkConfig {
    /// One-way propagation latency.
    pub latency: Duration,
    /// Directional serialization capacity.
    pub bits_per_second: u64,
    /// Maximum UDP payload accepted by the modeled link.
    pub mtu: usize,
    /// Maximum packet copies simultaneously retained on this link.
    pub queue_packets: u64,
    /// Independent deterministic packet-loss probability.
    pub loss_per_million: u32,
    /// Independent deterministic duplication probability.
    pub duplicate_per_million: u32,
    /// Independent deterministic corruption probability.
    pub corrupt_per_million: u32,
    /// Maximum additional deterministic reordering delay.
    pub reorder_window: Duration,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            latency: Duration::from_millis(1),
            bits_per_second: 1_000_000_000,
            mtu: 65_535,
            queue_packets: 1_024,
            loss_per_million: 0,
            duplicate_per_million: 0,
            corrupt_per_million: 0,
            reorder_window: Duration::ZERO,
        }
    }
}

/// Canonical IP network used by interfaces and routes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct IpCidr {
    address: IpAddr,
    network: IpAddr,
    prefix: u8,
}

/// Stable host connectivity summary used to update production network monitors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostConnectivity {
    pub have_v4: bool,
    pub have_v6: bool,
    pub have_default_route: bool,
}

impl IpCidr {
    /// Creates a canonical network by masking host bits from `address`.
    pub fn new(address: IpAddr, prefix: u8) -> Result<Self, NetworkError> {
        let network = match address {
            IpAddr::V4(address) if prefix <= 32 => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask))
            }
            IpAddr::V6(address) if prefix <= 128 => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask))
            }
            _ => return Err(NetworkError::InvalidPrefix { address, prefix }),
        };
        Ok(Self {
            address,
            network,
            prefix,
        })
    }

    /// Returns whether `address` belongs to this network.
    pub fn contains(self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                u32::from(network) == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                u128::from(network) == u128::from(address) & mask
            }
            _ => false,
        }
    }

    /// Returns the prefix length.
    pub const fn prefix(self) -> u8 {
        self.prefix
    }

    fn same_network(self, other: Self) -> bool {
        self.network == other.network && self.prefix == other.prefix
    }
}

/// Cloneable topology and socket factory owner.
#[derive(Clone)]
pub struct SyntheticNetwork {
    inner: Arc<NetworkInner>,
}

impl fmt::Debug for SyntheticNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self
            .inner
            .state
            .lock()
            .expect("synthetic network lock poisoned");
        f.debug_struct("SyntheticNetwork")
            .field("hosts", &state.hosts.keys().collect::<Vec<_>>())
            .field("links", &state.links.keys().collect::<Vec<_>>())
            .field("bound_sockets", &state.sockets.len())
            .finish()
    }
}

impl SyntheticNetwork {
    /// Creates an empty network sharing one kernel, decision source, clock, and trace recorder.
    pub fn new(
        kernel: Kernel,
        context: Arc<RuntimeContext>,
        config: NetworkConfig,
    ) -> Result<Self, NetworkError> {
        if config.max_packets == 0 || config.ephemeral_port_start == 0 {
            return Err(NetworkError::InvalidConfig);
        }
        Ok(Self {
            inner: Arc::new(NetworkInner {
                kernel,
                context,
                config,
                send_gate: Mutex::new(()),
                state: Mutex::new(NetworkState::default()),
            }),
        })
    }

    /// Updates future packet latency and/or MTU for an existing link.
    pub fn update_link(
        &self,
        link: &str,
        latency: Option<Duration>,
        mtu: Option<usize>,
    ) -> Result<(), NetworkError> {
        if matches!(mtu, Some(0)) {
            return Err(NetworkError::InvalidConfig);
        }
        let mut state = self
            .inner
            .state
            .lock()
            .expect("synthetic network lock poisoned");
        let link_state = state
            .links
            .get_mut(link)
            .ok_or_else(|| NetworkError::UnknownLink(link.to_owned()))?;
        if let Some(latency) = latency {
            link_state.config.latency = latency;
        }
        if let Some(mtu) = mtu {
            link_state.config.mtu = mtu;
        }
        Ok(())
    }

    /// Adds one named host.
    pub fn add_host(&self, host: impl Into<String>) -> Result<(), NetworkError> {
        let host = validate_name("host", host.into())?;
        let mut state = self
            .inner
            .state
            .lock()
            .expect("synthetic network lock poisoned");
        if state.hosts.contains_key(&host) {
            return Err(NetworkError::DuplicateHost(host));
        }
        state.hosts.insert(
            host,
            HostState {
                next_ephemeral: self.inner.config.ephemeral_port_start,
                ..HostState::default()
            },
        );
        Ok(())
    }

    /// Adds one link before attaching interfaces.
    pub fn add_link(
        &self,
        link: impl Into<String>,
        config: LinkConfig,
    ) -> Result<(), NetworkError> {
        validate_link_config(config)?;
        let link = validate_name("link", link.into())?;
        let decisions = FaultDecisions::new(&self.inner.context, &link)?;
        let mut state = self
            .inner
            .state
            .lock()
            .expect("synthetic network lock poisoned");
        if state.links.contains_key(&link) {
            return Err(NetworkError::DuplicateLink(link));
        }
        state.links.insert(
            link,
            LinkState {
                config,
                decisions,
                ..LinkState::default()
            },
        );
        Ok(())
    }

    /// Adds one host interface with one or more family-specific addresses.
    pub fn add_interface(
        &self,
        host: &str,
        interface: impl Into<String>,
        link: &str,
        addresses: impl IntoIterator<Item = IpCidr>,
    ) -> Result<(), NetworkError> {
        let interface = validate_name("interface", interface.into())?;
        let addresses: Vec<_> = addresses.into_iter().collect();
        if addresses.is_empty() {
            return Err(NetworkError::InterfaceHasNoAddress);
        }
        let mut state = self
            .inner
            .state
            .lock()
            .expect("synthetic network lock poisoned");
        if !state.links.contains_key(link) {
            return Err(NetworkError::UnknownLink(link.to_owned()));
        }
        for address in &addresses {
            let ip = interface_address(*address);
            if state.hosts.values().any(|host| {
                host.interfaces
                    .values()
                    .flat_map(|interface| &interface.addresses)
                    .any(|existing| interface_address(*existing) == ip)
            }) {
                return Err(NetworkError::DuplicateAddress(ip));
            }
        }
        let existing_host = state
            .hosts
            .get(host)
            .ok_or_else(|| NetworkError::UnknownHost(host.to_owned()))?;
        if let Some(destination) = addresses.iter().copied().find(|address| {
            existing_host
                .interfaces
                .values()
                .flat_map(|interface| &interface.addresses)
                .any(|existing| existing.same_network(*address))
        }) {
            return Err(NetworkError::AmbiguousRoute {
                host: host.to_owned(),
                destination,
            });
        }
        let host_state = state.hosts.get_mut(host).expect("host checked above");
        if host_state.interfaces.contains_key(&interface) {
            return Err(NetworkError::DuplicateInterface {
                host: host.to_owned(),
                interface,
            });
        }
        host_state.interfaces.insert(
            interface.clone(),
            InterfaceState {
                link: link.to_owned(),
                addresses,
                up: true,
            },
        );
        state
            .links
            .get_mut(link)
            .expect("link checked above")
            .members
            .insert((host.to_owned(), interface));
        Ok(())
    }

    /// Adds an explicit route, rejecting an equal destination prefix on the same host.
    pub fn add_route(
        &self,
        host: &str,
        route: impl Into<String>,
        destination: IpCidr,
        interface: &str,
        next_hop: Option<&str>,
    ) -> Result<(), NetworkError> {
        let route = validate_name("route", route.into())?;
        let mut state = self
            .inner
            .state
            .lock()
            .expect("synthetic network lock poisoned");
        let host_state = state
            .hosts
            .get(host)
            .ok_or_else(|| NetworkError::UnknownHost(host.to_owned()))?;
        let interface_state =
            host_state
                .interfaces
                .get(interface)
                .ok_or_else(|| NetworkError::UnknownInterface {
                    host: host.to_owned(),
                    interface: interface.to_owned(),
                })?;
        if host_state
            .routes
            .values()
            .any(|existing| existing.destination.same_network(destination))
            || host_state
                .interfaces
                .values()
                .flat_map(|interface| &interface.addresses)
                .any(|existing| existing.same_network(destination))
        {
            return Err(NetworkError::AmbiguousRoute {
                host: host.to_owned(),
                destination,
            });
        }
        if let Some(next_hop) = next_hop {
            let link = state
                .links
                .get(&interface_state.link)
                .expect("interface link exists");
            if !link.members.iter().any(|(member, _)| member == next_hop) {
                return Err(NetworkError::InvalidNextHop {
                    host: host.to_owned(),
                    next_hop: next_hop.to_owned(),
                });
            }
        }
        state
            .hosts
            .get_mut(host)
            .expect("host checked above")
            .routes
            .insert(
                route,
                RouteState {
                    destination,
                    interface: interface.to_owned(),
                    next_hop: next_hop.map(str::to_owned),
                },
            );
        Ok(())
    }

    /// Removes one explicit route while leaving connected routes unchanged.
    pub fn remove_route(&self, host: &str, route: &str) -> Result<(), NetworkError> {
        let removed = self
            .inner
            .state
            .lock()
            .expect("synthetic network lock poisoned")
            .hosts
            .get_mut(host)
            .ok_or_else(|| NetworkError::UnknownHost(host.to_owned()))?
            .routes
            .remove(route);
        if removed.is_none() {
            return Err(NetworkError::UnknownRoute {
                host: host.to_owned(),
                route: route.to_owned(),
            });
        }
        Ok(())
    }

    /// Enables or heals one directional link partition.
    pub fn set_partition(
        &self,
        link: &str,
        from_host: &str,
        to_host: &str,
        partitioned: bool,
    ) -> Result<(), NetworkError> {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("synthetic network lock poisoned");
        let link_state = state
            .links
            .get_mut(link)
            .ok_or_else(|| NetworkError::UnknownLink(link.to_owned()))?;
        let pair = (from_host.to_owned(), to_host.to_owned());
        if partitioned {
            link_state.partitions.insert(pair);
        } else {
            link_state.partitions.remove(&pair);
        }
        Ok(())
    }

    /// Changes one interface's administrative state and emits a typed environment trace.
    pub fn set_interface_up(
        &self,
        host: &str,
        interface: &str,
        up: bool,
    ) -> Result<(), NetworkError> {
        let addresses = {
            let mut state = self
                .inner
                .state
                .lock()
                .expect("synthetic network lock poisoned");
            let interface_state = state
                .hosts
                .get_mut(host)
                .ok_or_else(|| NetworkError::UnknownHost(host.to_owned()))?
                .interfaces
                .get_mut(interface)
                .ok_or_else(|| NetworkError::UnknownInterface {
                    host: host.to_owned(),
                    interface: interface.to_owned(),
                })?;
            interface_state.up = up;
            interface_state
                .addresses
                .iter()
                .map(|address| format!("{}/{}", interface_address(*address), address.prefix()))
                .collect()
        };
        self.inner.context.trace().record(
            self.inner.context.clock().elapsed_nanos()?,
            TraceContext {
                interface: Some(format!("{host}/{interface}")),
                ..TraceContext::default()
            },
            TraceEventKind::InterfaceState {
                host: host.to_owned(),
                up,
                addresses,
            },
        )?;
        Ok(())
    }

    /// Adds or removes one exact configured interface address.
    pub fn set_interface_address(
        &self,
        host: &str,
        interface: &str,
        address: IpCidr,
        present: bool,
    ) -> Result<(), NetworkError> {
        let canonical = format!("{}/{}", interface_address(address), address.prefix());
        {
            let mut state = self
                .inner
                .state
                .lock()
                .expect("synthetic network lock poisoned");
            if present
                && state.hosts.values().any(|host| {
                    host.interfaces
                        .values()
                        .flat_map(|interface| &interface.addresses)
                        .any(|existing| interface_address(*existing) == interface_address(address))
                })
            {
                return Err(NetworkError::DuplicateAddress(interface_address(address)));
            }
            let interface_state = state
                .hosts
                .get_mut(host)
                .ok_or_else(|| NetworkError::UnknownHost(host.to_owned()))?
                .interfaces
                .get_mut(interface)
                .ok_or_else(|| NetworkError::UnknownInterface {
                    host: host.to_owned(),
                    interface: interface.to_owned(),
                })?;
            if present {
                interface_state.addresses.push(address);
                interface_state.addresses.sort();
            } else {
                let before = interface_state.addresses.len();
                interface_state
                    .addresses
                    .retain(|existing| *existing != address);
                if interface_state.addresses.len() == before {
                    return Err(NetworkError::AddressNotOwned {
                        host: host.to_owned(),
                        address: interface_address(address),
                    });
                }
            }
        }
        self.inner.context.trace().record(
            self.inner.context.clock().elapsed_nanos()?,
            TraceContext {
                interface: Some(format!("{host}/{interface}")),
                ..TraceContext::default()
            },
            TraceEventKind::InterfaceAddress {
                host: host.to_owned(),
                address: canonical,
                present,
            },
        )?;
        Ok(())
    }

    /// Suspends all currently-up interfaces or restores the exact saved set.
    pub fn set_host_sleeping(&self, host: &str, sleeping: bool) -> Result<(), NetworkError> {
        {
            let mut state = self
                .inner
                .state
                .lock()
                .expect("synthetic network lock poisoned");
            let host_state = state
                .hosts
                .get_mut(host)
                .ok_or_else(|| NetworkError::UnknownHost(host.to_owned()))?;
            if sleeping && !host_state.sleeping {
                host_state.resume_interfaces = host_state
                    .interfaces
                    .iter()
                    .filter(|(_, interface)| interface.up)
                    .map(|(id, _)| id.clone())
                    .collect();
                for interface in host_state.interfaces.values_mut() {
                    interface.up = false;
                }
                host_state.sleeping = true;
            } else if !sleeping && host_state.sleeping {
                for (id, interface) in &mut host_state.interfaces {
                    interface.up = host_state.resume_interfaces.contains(id);
                }
                host_state.resume_interfaces.clear();
                host_state.sleeping = false;
            }
        }
        self.inner.context.trace().record(
            self.inner.context.clock().elapsed_nanos()?,
            TraceContext::default(),
            TraceEventKind::HostPower {
                host: host.to_owned(),
                sleeping,
            },
        )?;
        Ok(())
    }

    /// Returns family/default-route availability for the up interfaces on a host.
    pub fn host_connectivity(&self, host: &str) -> Result<HostConnectivity, NetworkError> {
        let state = self
            .inner
            .state
            .lock()
            .expect("synthetic network lock poisoned");
        let host = state
            .hosts
            .get(host)
            .ok_or_else(|| NetworkError::UnknownHost(host.to_owned()))?;
        let mut have_v4 = false;
        let mut have_v6 = false;
        for address in host
            .interfaces
            .values()
            .filter(|interface| interface.up)
            .flat_map(|interface| &interface.addresses)
        {
            have_v4 |= interface_address(*address).is_ipv4();
            have_v6 |= interface_address(*address).is_ipv6();
        }
        let have_default_route = host.routes.values().any(|route| {
            route.destination.prefix() == 0
                && host
                    .interfaces
                    .get(&route.interface)
                    .is_some_and(|interface| interface.up)
        }) || host.interfaces.values().any(|interface| interface.up);
        Ok(HostConnectivity {
            have_v4,
            have_v6,
            have_default_route,
        })
    }

    /// Creates a socket factory whose binds belong to `host`.
    pub fn socket_factory(&self, host: &str) -> Result<Arc<dyn IpSocketFactory>, NetworkError> {
        if !self
            .inner
            .state
            .lock()
            .expect("synthetic network lock poisoned")
            .hosts
            .contains_key(host)
        {
            return Err(NetworkError::UnknownHost(host.to_owned()));
        }
        Ok(Arc::new(SyntheticIpSocketFactory {
            host: host.to_owned(),
            network: self.inner.clone(),
        }))
    }

    /// Attaches one stateful IPv4 NAT to all outbound/inbound traffic for `inside_host`.
    pub fn add_nat(&self, inside_host: &str, config: NatConfig) -> Result<(), NetworkError> {
        self.add_nat_inner(inside_host, None, config, None)
    }

    /// Attaches a NAT whose translated traffic traverses `upstream_nat` next.
    pub fn add_chained_nat(
        &self,
        inside_host: &str,
        upstream_nat: &str,
        config: NatConfig,
    ) -> Result<(), NetworkError> {
        self.add_nat_inner(inside_host, Some(upstream_nat), config, None)
    }

    /// Attaches one stateful IPv4 NAT and ordered firewall to `inside_host`.
    pub fn add_nat_with_firewall(
        &self,
        inside_host: &str,
        config: NatConfig,
        firewall: FirewallConfig,
    ) -> Result<(), NetworkError> {
        self.add_nat_inner(inside_host, None, config, Some(firewall))
    }

    /// Attaches a chained NAT and ordered firewall.
    pub fn add_chained_nat_with_firewall(
        &self,
        inside_host: &str,
        upstream_nat: &str,
        config: NatConfig,
        firewall: FirewallConfig,
    ) -> Result<(), NetworkError> {
        self.add_nat_inner(inside_host, Some(upstream_nat), config, Some(firewall))
    }

    fn add_nat_inner(
        &self,
        inside_host: &str,
        upstream_nat: Option<&str>,
        config: NatConfig,
        firewall: Option<FirewallConfig>,
    ) -> Result<(), NetworkError> {
        let id = config.id.clone();
        let public_ip = config.public_ip;
        let table = NatTable::new(
            self.inner.kernel.clone(),
            self.inner.context.clone(),
            config,
        )?;
        let firewall = firewall
            .map(|config| Firewall::new(self.inner.context.clone(), config))
            .transpose()?;
        let mut state = self
            .inner
            .state
            .lock()
            .expect("synthetic network lock poisoned");
        if !state.hosts.contains_key(inside_host) {
            return Err(NetworkError::UnknownHost(inside_host.to_owned()));
        }
        if state.nats.contains_key(&id) {
            return Err(NetworkError::DuplicateNat(id));
        }
        if let Some(upstream) = upstream_nat {
            let upstream = state
                .nats
                .get(upstream)
                .ok_or_else(|| NetworkError::UnknownNat(upstream.to_owned()))?;
            if upstream.inside_host != inside_host {
                return Err(NetworkError::InvalidNatChain(id));
            }
        }
        let public = IpAddr::V4(public_ip);
        if state.hosts.values().any(|host| host_owns_ip(host, public))
            || state
                .nats
                .values()
                .any(|nat| nat.table.config().public_ip == public_ip)
        {
            return Err(NetworkError::DuplicateAddress(public));
        }
        state.nats.insert(
            id,
            AttachedNat {
                inside_host: inside_host.to_owned(),
                upstream_nat: upstream_nat.map(str::to_owned),
                table,
                firewall,
            },
        );
        Ok(())
    }

    /// Returns stable mapping state for one attached gateway.
    pub fn nat_snapshot(&self, nat: &str) -> Result<Vec<NatMappingSnapshot>, NetworkError> {
        self.inner
            .state
            .lock()
            .expect("synthetic network lock poisoned")
            .nats
            .get(nat)
            .map(|nat| nat.table.snapshot())
            .ok_or_else(|| NetworkError::UnknownNat(nat.to_owned()))
    }

    /// Returns the first gateway traversed by outbound traffic for `host`.
    pub fn host_nat(&self, host: &str) -> Result<Option<String>, NetworkError> {
        let state = self
            .inner
            .state
            .lock()
            .expect("synthetic network lock poisoned");
        Ok(outbound_nat_chain(&state, host)?.into_iter().next())
    }

    /// Installs or renews a NAT port mapping for one host-local UDP port.
    pub fn procure_port_mapping(
        &self,
        host: &str,
        nat: &str,
        local_port: u16,
    ) -> Result<crate::NatPortMapping, NetworkError> {
        if local_port == 0 {
            return Err(NetworkError::InvalidConfig);
        }
        let now = duration_nanos(self.inner.kernel.now())?;
        let mut state = self
            .inner
            .state
            .lock()
            .expect("synthetic network lock poisoned");
        let internal_ip = state
            .hosts
            .get(host)
            .ok_or_else(|| NetworkError::UnknownHost(host.to_owned()))?
            .interfaces
            .values()
            .filter(|interface| interface.up)
            .flat_map(|interface| &interface.addresses)
            .map(|address| interface_address(*address))
            .find(IpAddr::is_ipv4)
            .ok_or_else(|| NetworkError::NoSourceAddress {
                host: host.to_owned(),
            })?;
        let attached = state
            .nats
            .get_mut(nat)
            .ok_or_else(|| NetworkError::UnknownNat(nat.to_owned()))?;
        if attached.inside_host != host {
            return Err(NetworkError::InvalidNatChain(nat.to_owned()));
        }
        let mapping = attached
            .table
            .procure_port_mapping(now, SocketAddr::new(internal_ip, local_port))?;
        let expiry = self
            .inner
            .nat_expiry_event(nat, &mapping.mapping, mapping.expires_nanos)?;
        attached
            .table
            .install_expiry_event(&mapping.mapping, mapping.expires_nanos, expiry)?;
        Ok(mapping)
    }

    /// Removes a previously installed explicit port mapping.
    pub fn release_port_mapping(&self, nat: &str, mapping: &str) -> Result<bool, NetworkError> {
        self.inner
            .state
            .lock()
            .expect("synthetic network lock poisoned")
            .nats
            .get_mut(nat)
            .ok_or_else(|| NetworkError::UnknownNat(nat.to_owned()))?
            .table
            .remove_port_mapping(mapping)
            .map_err(NetworkError::from)
    }

    /// Changes a gateway public address and chooses mapping preservation semantics.
    pub fn rebind_nat(
        &self,
        nat: &str,
        public_ip: Ipv4Addr,
        preserve_ports: bool,
    ) -> Result<(), NetworkError> {
        let now = duration_nanos(self.inner.kernel.now())?;
        let mut state = self
            .inner
            .state
            .lock()
            .expect("synthetic network lock poisoned");
        if state
            .nats
            .iter()
            .any(|(id, value)| id != nat && value.table.config().public_ip == public_ip)
            || state
                .hosts
                .values()
                .any(|host| host_owns_ip(host, IpAddr::V4(public_ip)))
        {
            return Err(NetworkError::DuplicateAddress(IpAddr::V4(public_ip)));
        }
        state
            .nats
            .get_mut(nat)
            .ok_or_else(|| NetworkError::UnknownNat(nat.to_owned()))?
            .table
            .rebind(now, public_ip, preserve_ports)?;
        Ok(())
    }

    /// Clears all dynamic gateway and firewall state during bounded shutdown.
    pub fn clear_nats(&self) -> Result<(), NetworkError> {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("synthetic network lock poisoned");
        if let Some(error) = state.deferred_error.take() {
            return Err(NetworkError::Deferred(error));
        }
        for nat in state.nats.values_mut() {
            nat.table.clear()?;
            if let Some(firewall) = &mut nat.firewall {
                firewall.clear_state();
            }
        }
        Ok(())
    }
}

struct NetworkInner {
    kernel: Kernel,
    context: Arc<RuntimeContext>,
    config: NetworkConfig,
    send_gate: Mutex<()>,
    state: Mutex<NetworkState>,
}

impl fmt::Debug for NetworkInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkInner")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct NetworkState {
    hosts: BTreeMap<String, HostState>,
    links: BTreeMap<String, LinkState>,
    sockets: BTreeMap<SocketKey, Weak<SyntheticIpSocket>>,
    nats: BTreeMap<String, AttachedNat>,
    deferred_error: Option<String>,
    next_packet_id: u64,
}

struct AttachedNat {
    inside_host: String,
    upstream_nat: Option<String>,
    table: NatTable,
    firewall: Option<Firewall>,
}

#[derive(Default)]
struct HostState {
    interfaces: BTreeMap<String, InterfaceState>,
    routes: BTreeMap<String, RouteState>,
    next_ephemeral: u16,
    sleeping: bool,
    resume_interfaces: BTreeSet<String>,
}

struct InterfaceState {
    link: String,
    addresses: Vec<IpCidr>,
    up: bool,
}

struct RouteState {
    destination: IpCidr,
    interface: String,
    next_hop: Option<String>,
}

#[derive(Default)]
struct LinkState {
    config: LinkConfig,
    members: BTreeSet<(String, String)>,
    partitions: BTreeSet<(String, String)>,
    next_available_nanos: u64,
    queued_packets: u64,
    decisions: FaultDecisions,
}

#[derive(Default)]
struct FaultDecisions {
    loss: Option<Box<dyn DecisionStream>>,
    duplicate: Option<Box<dyn DecisionStream>>,
    corrupt: Option<Box<dyn DecisionStream>>,
    reorder: Option<Box<dyn DecisionStream>>,
}

impl FaultDecisions {
    fn new(context: &RuntimeContext, link: &str) -> Result<Self, NetworkError> {
        let decisions = context.decisions();
        Ok(Self {
            loss: Some(decisions.stream(&format!("network/link/{link}/loss"))?),
            duplicate: Some(decisions.stream(&format!("network/link/{link}/duplicate"))?),
            corrupt: Some(decisions.stream(&format!("network/link/{link}/corrupt"))?),
            reorder: Some(decisions.stream(&format!("network/link/{link}/reorder"))?),
        })
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SocketKey {
    host: String,
    address: SocketAddr,
}

#[derive(Debug)]
struct SyntheticIpSocketFactory {
    host: String,
    network: Arc<NetworkInner>,
}

impl IpSocketFactory for SyntheticIpSocketFactory {
    fn bind(&self, requested: SocketAddr) -> io::Result<Arc<dyn IpSocket>> {
        self.network
            .bind_socket(&self.host, requested)
            .map(|socket| socket as Arc<dyn IpSocket>)
            .map_err(NetworkError::into_io)
    }
}

#[derive(Debug)]
struct SyntheticIpSocket {
    host: String,
    requested: SocketAddr,
    address: Mutex<SocketAddr>,
    receive: Mutex<ReceiveState>,
    network: Arc<NetworkInner>,
    self_ref: Weak<SyntheticIpSocket>,
    _resource: ResourceToken,
}

#[derive(Debug, Default)]
struct ReceiveState {
    datagrams: VecDeque<Datagram>,
    waker: Option<Waker>,
}

#[derive(Debug)]
struct Datagram {
    source: SocketAddr,
    destination: SocketAddr,
    ecn: Option<noq_udp::EcnCodepoint>,
    payload: Vec<u8>,
}

struct QueuedBatch {
    network: Weak<NetworkInner>,
    links: Vec<String>,
    copies: u64,
    _resources: Vec<ResourceToken>,
}

struct NatAdmission {
    network: Weak<NetworkInner>,
    created: Vec<(String, String)>,
    committed: bool,
}

impl NatAdmission {
    fn new(network: &Arc<NetworkInner>, created: Vec<(String, String)>) -> Self {
        Self {
            network: Arc::downgrade(network),
            created,
            committed: false,
        }
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for NatAdmission {
    fn drop(&mut self) {
        if self.committed || self.created.is_empty() {
            return;
        }
        let Some(network) = self.network.upgrade() else {
            return;
        };
        let mut state = network
            .state
            .lock()
            .expect("synthetic network lock poisoned");
        if let Err(error) = rollback_created_nat_mappings(&mut state, &self.created) {
            state.deferred_error = Some(error.to_string());
        }
    }
}

impl Drop for QueuedBatch {
    fn drop(&mut self) {
        let Some(network) = self.network.upgrade() else {
            return;
        };
        let mut state = network
            .state
            .lock()
            .expect("synthetic network lock poisoned");
        for link in &self.links {
            if let Some(link) = state.links.get_mut(link) {
                link.queued_packets = link.queued_packets.saturating_sub(self.copies);
            }
        }
    }
}

impl IpSocket for SyntheticIpSocket {
    fn create_sender(self: Arc<Self>) -> Pin<Box<dyn IpSocketSender>> {
        Box::pin(SyntheticIpSocketSender { socket: self })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.len() != metas.len() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "receive buffers and metadata lengths differ",
            )));
        }
        let mut receive = self
            .receive
            .lock()
            .expect("synthetic receive lock poisoned");
        let mut count = 0;
        while count < bufs.len() {
            let Some(datagram) = receive.datagrams.front() else {
                break;
            };
            if bufs[count].len() < datagram.payload.len() {
                if count == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "receive buffer is smaller than datagram",
                    )));
                }
                break;
            }
            let datagram = receive.datagrams.pop_front().expect("front exists");
            bufs[count][..datagram.payload.len()].copy_from_slice(&datagram.payload);
            let meta = &mut metas[count];
            meta.addr = datagram.source;
            meta.len = datagram.payload.len();
            meta.stride = datagram.payload.len();
            meta.ecn = datagram.ecn;
            meta.dst_ip = Some(datagram.destination.ip());
            meta.interface_index = None;
            meta.timestamp = None;
            count += 1;
        }
        if count > 0 {
            Poll::Ready(Ok(count))
        } else {
            if receive
                .waker
                .as_ref()
                .is_none_or(|waker| !waker.will_wake(cx.waker()))
            {
                receive.waker = Some(cx.waker().clone());
            }
            Poll::Pending
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(*self.address.lock().expect("synthetic socket lock poisoned"))
    }

    fn rebind(&self) -> io::Result<()> {
        self.network
            .rebind_socket(self)
            .map_err(NetworkError::into_io)
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

impl Drop for SyntheticIpSocket {
    fn drop(&mut self) {
        let address = *self.address.lock().expect("synthetic socket lock poisoned");
        let mut state = self
            .network
            .state
            .lock()
            .expect("synthetic network lock poisoned");
        state.sockets.remove(&SocketKey {
            host: self.host.clone(),
            address,
        });
    }
}

#[derive(Debug)]
struct SyntheticIpSocketSender {
    socket: Arc<SyntheticIpSocket>,
}

impl IpSocketSender for SyntheticIpSocketSender {
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &noq_udp::Transmit<'_>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let segment_size = transmit.segment_size.unwrap_or(transmit.contents.len());
        if segment_size == 0 && !transmit.contents.is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero UDP segment size",
            )));
        }
        let chunks: Vec<&[u8]> = if transmit.contents.is_empty() {
            vec![transmit.contents]
        } else {
            transmit.contents.chunks(segment_size).collect()
        };
        for payload in chunks {
            if let Err(error) = self.socket.network.send(
                &self.socket,
                transmit.destination,
                transmit.src_ip,
                transmit.ecn,
                payload,
            ) {
                return Poll::Ready(Err(error.into_io()));
            }
        }
        Poll::Ready(Ok(()))
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        NonZeroUsize::new(64).expect("nonzero constant")
    }
}

impl NetworkInner {
    fn bind_socket(
        self: &Arc<Self>,
        host: &str,
        requested: SocketAddr,
    ) -> Result<Arc<SyntheticIpSocket>, NetworkError> {
        let resource = self.kernel.acquire_resource(ResourceKind::Socket, None)?;
        let mut state = self.state.lock().expect("synthetic network lock poisoned");
        validate_bind_address(&state, host, requested)?;
        let address = allocate_bound_address(&mut state, host, requested)?;
        ensure_port_available(&mut state, host, address)?;
        let socket = Arc::new_cyclic(|self_ref| SyntheticIpSocket {
            host: host.to_owned(),
            requested,
            address: Mutex::new(address),
            receive: Mutex::new(ReceiveState::default()),
            network: self.clone(),
            self_ref: self_ref.clone(),
            _resource: resource,
        });
        state.sockets.insert(
            SocketKey {
                host: host.to_owned(),
                address,
            },
            Arc::downgrade(&socket),
        );
        Ok(socket)
    }

    fn rebind_socket(&self, socket: &SyntheticIpSocket) -> Result<(), NetworkError> {
        let old = *socket
            .address
            .lock()
            .expect("synthetic socket lock poisoned");
        let mut state = self.state.lock().expect("synthetic network lock poisoned");
        state.sockets.remove(&SocketKey {
            host: socket.host.clone(),
            address: old,
        });
        let address = match allocate_bound_address(&mut state, &socket.host, socket.requested) {
            Ok(address) => address,
            Err(error) => {
                state.sockets.insert(
                    SocketKey {
                        host: socket.host.clone(),
                        address: old,
                    },
                    socket.self_ref.clone(),
                );
                return Err(error);
            }
        };
        ensure_port_available(&mut state, &socket.host, address)?;
        *socket
            .address
            .lock()
            .expect("synthetic socket lock poisoned") = address;
        // The caller owns the only stable Arc used here; delivery falls back to wildcard lookup
        // until a sender/receiver clone causes the registry to be refreshed by `send`.
        state.sockets.insert(
            SocketKey {
                host: socket.host.clone(),
                address,
            },
            socket.self_ref.clone(),
        );
        Ok(())
    }

    fn send(
        self: &Arc<Self>,
        socket: &Arc<SyntheticIpSocket>,
        destination: SocketAddr,
        requested_source: Option<IpAddr>,
        ecn: Option<noq_udp::EcnCodepoint>,
        payload: &[u8],
    ) -> Result<(), NetworkError> {
        let _send_guard = self
            .send_gate
            .lock()
            .expect("synthetic send gate lock poisoned");
        let bound = *socket
            .address
            .lock()
            .expect("synthetic socket lock poisoned");
        let now_nanos = duration_nanos(self.kernel.now())?;
        let mut state = self.state.lock().expect("synthetic network lock poisoned");
        state.sockets.insert(
            SocketKey {
                host: socket.host.clone(),
                address: bound,
            },
            Arc::downgrade(socket),
        );
        let packet = allocate_packet_id(&mut state)?;
        let initial_path = match route(&state, &socket.host, destination.ip()) {
            Ok(path) => path,
            Err(error) => {
                drop(state);
                self.trace_packet_outcome(packet, route_rejection(&error))?;
                return Err(error);
            }
        };
        let source_ip =
            match select_source(&state, &socket.host, bound, requested_source, &initial_path) {
                Ok(source) => source,
                Err(error) => {
                    drop(state);
                    self.trace_packet_outcome(packet, source_rejection(&error))?;
                    return Err(error);
                }
            };
        if let Some((link, mtu)) = initial_path.hops.iter().find_map(|hop| {
            let link = state.links.get(&hop.link).expect("route link exists");
            (payload.len() > link.config.mtu).then(|| (hop.link.clone(), link.config.mtu))
        }) {
            drop(state);
            self.trace_packet_outcome(packet, "rejected:mtu")?;
            return Err(NetworkError::MtuExceeded {
                link,
                mtu,
                length: payload.len(),
            });
        }
        let logical_source = SocketAddr::new(source_ip, bound.port());
        let nat_chain = outbound_nat_chain(&state, &socket.host)?;
        let mut created_mappings = Vec::new();
        let mut allowed_firewall_flows = Vec::new();
        let mut source = logical_source;
        let mut wire_destination = destination;
        for nat in nat_chain {
            let attached = state
                .nats
                .get_mut(&nat)
                .expect("attached NAT remains present");
            if let Some(firewall) = &mut attached.firewall {
                let firewall_packet = FirewallPacket {
                    source,
                    destination: wire_destination,
                };
                let decision = match firewall
                    .evaluate_uncommitted(FirewallDirection::Outbound, firewall_packet)
                {
                    Ok(decision) => decision,
                    Err(error) => {
                        rollback_created_nat_mappings(&mut state, &created_mappings)?;
                        return Err(error.into());
                    }
                };
                match decision.action {
                    FirewallAction::Allow => {
                        allowed_firewall_flows.push((nat.clone(), firewall_packet));
                    }
                    FirewallAction::Drop => {
                        commit_firewall_flows(&mut state, &allowed_firewall_flows);
                        drop(state);
                        self.trace_packet_outcome(packet, "dropped:firewall")?;
                        return Ok(());
                    }
                    FirewallAction::Reject => {
                        rollback_created_nat_mappings(&mut state, &created_mappings)?;
                        drop(state);
                        self.trace_packet_outcome(packet, "rejected:firewall")?;
                        return Err(NetworkError::FirewallRejected(decision.rule));
                    }
                }
            }
            match attached.table.translate_outbound_for_packet(
                now_nanos,
                source,
                wire_destination,
                packet,
            ) {
                Ok(translated) => {
                    if translated.created {
                        created_mappings.push((nat.clone(), translated.mapping.clone()));
                    }
                    let expiry = match self.nat_expiry_event(
                        &nat,
                        &translated.mapping,
                        translated.expires_nanos,
                    ) {
                        Ok(expiry) => expiry,
                        Err(error) => {
                            rollback_created_nat_mappings(&mut state, &created_mappings)?;
                            return Err(error);
                        }
                    };
                    if let Err(error) = attached.table.install_expiry_event(
                        &translated.mapping,
                        translated.expires_nanos,
                        expiry,
                    ) {
                        rollback_created_nat_mappings(&mut state, &created_mappings)?;
                        return Err(error.into());
                    }
                    source = translated.source;
                    wire_destination = translated.destination;
                    if translated.hairpin_target.is_some() {
                        break;
                    }
                }
                Err(error) => {
                    drop(state);
                    self.trace_packet_outcome(packet, "dropped:nat")?;
                    return Err(error.into());
                }
            }
        }
        let path = match route(&state, &socket.host, wire_destination.ip()) {
            Ok(path) => path,
            Err(error) => {
                rollback_created_nat_mappings(&mut state, &created_mappings)?;
                drop(state);
                self.trace_packet_outcome(packet, route_rejection(&error))?;
                return Err(error);
            }
        };
        drop(state);
        let mut nat_admission = NatAdmission::new(self, created_mappings);
        self.trace_packet_created(
            packet,
            logical_source,
            destination,
            source,
            wire_destination,
            payload,
        )?;

        let mut state = self.state.lock().expect("synthetic network lock poisoned");
        let mut deadline = now_nanos;
        let mut duplicate = false;
        let mut corrupt = false;
        let mut reordered_by = 0u64;
        let mut link_ids = Vec::new();
        let mut hop_schedules = Vec::new();
        let mut timeline_updates = BTreeMap::<String, (u64, u64)>::new();
        for hop in &path.hops {
            let link = state.links.get_mut(&hop.link).expect("route link exists");
            if payload.len() > link.config.mtu {
                let mtu = link.config.mtu;
                drop(state);
                self.trace_packet_outcome(packet, "rejected:mtu")?;
                return Err(NetworkError::MtuExceeded {
                    link: hop.link.clone(),
                    mtu,
                    length: payload.len(),
                });
            }
            if link
                .partitions
                .contains(&(hop.from.clone(), hop.to.clone()))
            {
                commit_firewall_flows(&mut state, &allowed_firewall_flows);
                nat_admission.commit();
                drop(state);
                self.trace_packet_outcome(packet, "dropped:partition")?;
                return Ok(());
            }
            if link.queued_packets >= link.config.queue_packets {
                commit_firewall_flows(&mut state, &allowed_firewall_flows);
                nat_admission.commit();
                drop(state);
                self.trace_packet_outcome(packet, "dropped:queue_overflow")?;
                return Ok(());
            }
            if fault_boolean(
                link.decisions.loss.as_deref_mut().expect("loss stream"),
                link.config.loss_per_million,
            )? {
                commit_firewall_flows(&mut state, &allowed_firewall_flows);
                nat_admission.commit();
                drop(state);
                self.trace_fault(packet, &format!("link/{}/loss", hop.link), "drop")?;
                self.trace_packet_outcome(packet, "dropped:loss")?;
                return Ok(());
            }
            duplicate |= fault_boolean(
                link.decisions
                    .duplicate
                    .as_deref_mut()
                    .expect("duplicate stream"),
                link.config.duplicate_per_million,
            )?;
            corrupt |= fault_boolean(
                link.decisions
                    .corrupt
                    .as_deref_mut()
                    .expect("corrupt stream"),
                link.config.corrupt_per_million,
            )?;
            let reorder_window = duration_nanos(link.config.reorder_window)?;
            if reorder_window > 0 {
                reordered_by = reordered_by
                    .checked_add(
                        link.decisions
                            .reorder
                            .as_deref_mut()
                            .expect("reorder stream")
                            .range_u64(0..reorder_window.saturating_add(1))?,
                    )
                    .ok_or(NetworkError::TimelineOverflow)?;
            }
            let serialization = serialization_nanos(payload.len(), link.config.bits_per_second)?;
            let next_available = timeline_updates
                .get(&hop.link)
                .map_or(link.next_available_nanos, |(_, planned)| *planned);
            let start = deadline.max(next_available);
            let serialized = start
                .checked_add(serialization)
                .ok_or(NetworkError::TimelineOverflow)?;
            timeline_updates
                .entry(hop.link.clone())
                .and_modify(|(_, planned)| *planned = serialized)
                .or_insert((link.next_available_nanos, serialized));
            deadline = serialized
                .checked_add(duration_nanos(link.config.latency)?)
                .ok_or(NetworkError::TimelineOverflow)?;
            link_ids.push(hop.link.clone());
            hop_schedules.push((hop.link.clone(), hop.from.clone(), hop.to.clone(), deadline));
        }
        deadline = deadline
            .checked_add(reordered_by)
            .ok_or(NetworkError::TimelineOverflow)?;
        let copies = if duplicate { 2 } else { 1 };
        for link_id in &link_ids {
            let link = state.links.get(link_id).expect("route link exists");
            let reserved = link
                .queued_packets
                .checked_add(copies)
                .ok_or(NetworkError::ResourceOverflow)?;
            if reserved > link.config.queue_packets {
                commit_firewall_flows(&mut state, &allowed_firewall_flows);
                nat_admission.commit();
                drop(state);
                self.trace_packet_outcome(packet, "dropped:queue_overflow")?;
                return Ok(());
            }
        }
        drop(state);

        let mut resources = Vec::with_capacity(copies as usize);
        for _ in 0..copies {
            match self
                .kernel
                .acquire_resource(ResourceKind::QueuedPacket, Some(self.config.max_packets))
            {
                Ok(resource) => resources.push(resource),
                Err(error) => {
                    self.trace_packet_outcome(packet, "rejected:packet_limit")?;
                    return Err(error.into());
                }
            }
        }

        let mut state = self.state.lock().expect("synthetic network lock poisoned");
        for link_id in &link_ids {
            let link = state.links.get(link_id).expect("route link exists");
            let reserved = link
                .queued_packets
                .checked_add(copies)
                .ok_or(NetworkError::ResourceOverflow)?;
            if reserved > link.config.queue_packets {
                commit_firewall_flows(&mut state, &allowed_firewall_flows);
                nat_admission.commit();
                drop(state);
                self.trace_packet_outcome(packet, "dropped:queue_overflow")?;
                return Ok(());
            }
        }
        for link_id in &link_ids {
            let link = state.links.get_mut(link_id).expect("route link exists");
            link.queued_packets = link
                .queued_packets
                .checked_add(copies)
                .ok_or(NetworkError::ResourceOverflow)?;
        }
        for (link_id, (observed, planned)) in &timeline_updates {
            let link = state.links.get_mut(link_id).expect("route link exists");
            debug_assert_eq!(link.next_available_nanos, *observed);
            link.next_available_nanos = *planned;
        }
        drop(state);

        let reservation = QueuedBatch {
            network: Arc::downgrade(self),
            links: link_ids,
            copies,
            _resources: resources,
        };
        for (link, from, to, deadline_nanos) in &hop_schedules {
            self.trace_packet_hop(packet, link, from, to, *deadline_nanos)?;
        }

        let mut bytes = payload.to_vec();
        if corrupt && !bytes.is_empty() {
            bytes[0] ^= 0x01;
            self.trace_fault(packet, "network/corruption", "flip-first-bit")?;
        }
        if duplicate {
            self.trace_fault(packet, "network/duplication", "two-copies")?;
        }
        if reordered_by > 0 {
            self.trace_fault(
                packet,
                "network/reorder",
                &format!("delay:{reordered_by}ns"),
            )?;
        }
        let mut deliveries = vec![(packet, bytes.clone())];
        if duplicate {
            let duplicate_packet = {
                let mut state = self.state.lock().expect("synthetic network lock poisoned");
                allocate_packet_id(&mut state)?
            };
            self.trace_packet_created(
                duplicate_packet,
                logical_source,
                destination,
                source,
                wire_destination,
                &bytes,
            )?;
            for (link, from, to, deadline_nanos) in &hop_schedules {
                self.trace_packet_hop(duplicate_packet, link, from, to, *deadline_nanos)?;
            }
            deliveries.push((duplicate_packet, bytes));
            self.trace_packet_outcome(duplicate_packet, "scheduled")?;
        }
        self.schedule_delivery(
            deadline,
            path.destination_host,
            source,
            wire_destination,
            ecn,
            deliveries,
            reservation,
        )?;
        let mut state = self.state.lock().expect("synthetic network lock poisoned");
        commit_firewall_flows(&mut state, &allowed_firewall_flows);
        drop(state);
        nat_admission.commit();
        self.trace_packet_outcome(packet, "scheduled")?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn schedule_delivery(
        self: &Arc<Self>,
        deadline_nanos: u64,
        destination_host: String,
        source: SocketAddr,
        destination: SocketAddr,
        ecn: Option<noq_udp::EcnCodepoint>,
        deliveries: Vec<(u64, Vec<u8>)>,
        reservation: QueuedBatch,
    ) -> Result<(), NetworkError> {
        let network = Arc::downgrade(self);
        self.kernel.schedule_at(
            Duration::from_nanos(deadline_nanos),
            EventClass::Network,
            move || {
                if let Some(network) = network.upgrade() {
                    for (packet, payload) in deliveries {
                        network.deliver(
                            packet,
                            destination_host.clone(),
                            Datagram {
                                source,
                                destination,
                                ecn,
                                payload,
                            },
                        );
                    }
                }
                drop(reservation);
                Ok(())
            },
        )?;
        Ok(())
    }

    fn deliver(self: &Arc<Self>, packet: u64, destination_host: String, mut datagram: Datagram) {
        let socket = {
            let mut state = self.state.lock().expect("synthetic network lock poisoned");
            loop {
                let inbound_nat = state.nats.iter().find_map(|(id, nat)| {
                    (nat.inside_host == destination_host
                        && datagram.destination.ip() == IpAddr::V4(nat.table.config().public_ip))
                    .then(|| id.clone())
                });
                let Some(nat) = inbound_nat else {
                    break;
                };
                let now = duration_nanos(self.kernel.now()).unwrap_or(u64::MAX);
                let attached = state
                    .nats
                    .get_mut(&nat)
                    .expect("inbound NAT remains present");
                match attached.table.translate_inbound_for_packet(
                    now,
                    datagram.destination,
                    datagram.source,
                    packet,
                ) {
                    Ok(translated) => {
                        datagram.destination = translated.destination;
                        let expiry = self
                            .nat_expiry_event(&nat, &translated.mapping, translated.expires_nanos)
                            .and_then(|event| {
                                attached
                                    .table
                                    .install_expiry_event(
                                        &translated.mapping,
                                        translated.expires_nanos,
                                        event,
                                    )
                                    .map_err(NetworkError::from)
                            });
                        if let Err(error) = expiry {
                            state.deferred_error = Some(error.to_string());
                            drop(state);
                            let _ = self.trace_packet_outcome(packet, "dropped:nat_expiry");
                            return;
                        }
                        if let Some(firewall) = &mut attached.firewall {
                            let decision = firewall.evaluate(
                                FirewallDirection::Inbound,
                                FirewallPacket {
                                    source: datagram.source,
                                    destination: translated.destination,
                                },
                            );
                            if !matches!(
                                decision,
                                Ok(crate::FirewallDecision {
                                    action: FirewallAction::Allow,
                                    ..
                                })
                            ) {
                                drop(state);
                                let _ = self.trace_packet_outcome(packet, "dropped:firewall");
                                return;
                            }
                        }
                    }
                    Err(_) => {
                        drop(state);
                        let _ = self.trace_packet_outcome(packet, "dropped:nat_filter");
                        return;
                    }
                }
            }
            lookup_socket(&mut state, &destination_host, datagram.destination)
        };
        match socket {
            Some(socket) => {
                let waker = {
                    let mut receive = socket
                        .receive
                        .lock()
                        .expect("synthetic receive lock poisoned");
                    receive.datagrams.push_back(datagram);
                    receive.waker.take()
                };
                if let Some(waker) = waker {
                    waker.wake();
                }
                let _ = self.trace_packet_outcome(packet, "delivered");
            }
            None => {
                let _ = self.trace_packet_outcome(packet, "dropped:no_socket");
            }
        }
    }

    fn nat_expiry_event(
        self: &Arc<Self>,
        nat: &str,
        mapping: &str,
        deadline_nanos: u64,
    ) -> Result<crate::ScheduledEvent, NetworkError> {
        let network = Arc::downgrade(self);
        let nat = nat.to_owned();
        let mapping = mapping.to_owned();
        let (_, event) = self.kernel.schedule_cancellable_at(
            Duration::from_nanos(deadline_nanos),
            EventClass::Infrastructure,
            move || {
                let Some(network) = network.upgrade() else {
                    return Ok(());
                };
                let mut state = network
                    .state
                    .lock()
                    .expect("synthetic network lock poisoned");
                let Some(attached) = state.nats.get_mut(&nat) else {
                    return Ok(());
                };
                if let Err(error) = attached.table.expire(deadline_nanos) {
                    state.deferred_error =
                        Some(format!("NAT expiry failed for {nat}/{mapping}: {error}"));
                }
                Ok(())
            },
        )?;
        Ok(event)
    }

    fn trace_packet_created(
        &self,
        packet: u64,
        original_source: SocketAddr,
        original_destination: SocketAddr,
        wire_source: SocketAddr,
        wire_destination: SocketAddr,
        payload: &[u8],
    ) -> Result<(), NetworkError> {
        self.context.trace().record(
            self.context.clock().elapsed_nanos()?,
            packet_context(packet),
            TraceEventKind::PacketCreated {
                source: wire_source.to_string(),
                destination: wire_destination.to_string(),
                original_source: original_source.to_string(),
                original_destination: original_destination.to_string(),
                length: u64::try_from(payload.len()).map_err(|_| NetworkError::ResourceOverflow)?,
                payload_hash: blake3::hash(payload).to_hex().to_string(),
            },
        )?;
        Ok(())
    }

    fn trace_packet_outcome(&self, packet: u64, outcome: &str) -> Result<(), NetworkError> {
        self.context.trace().record(
            self.context.clock().elapsed_nanos()?,
            packet_context(packet),
            TraceEventKind::PacketOutcome {
                outcome: outcome.to_owned(),
            },
        )?;
        Ok(())
    }

    fn trace_packet_hop(
        &self,
        packet: u64,
        link: &str,
        from: &str,
        to: &str,
        deadline_nanos: u64,
    ) -> Result<(), NetworkError> {
        self.context.trace().record(
            self.context.clock().elapsed_nanos()?,
            packet_context(packet),
            TraceEventKind::PacketHopScheduled {
                link: link.to_owned(),
                from: from.to_owned(),
                to: to.to_owned(),
                deadline_nanos,
            },
        )?;
        Ok(())
    }

    fn trace_fault(&self, packet: u64, rule: &str, outcome: &str) -> Result<(), NetworkError> {
        self.context.trace().record(
            self.context.clock().elapsed_nanos()?,
            packet_context(packet),
            TraceEventKind::FaultInjected {
                rule: rule.to_owned(),
                outcome: outcome.to_owned(),
            },
        )?;
        Ok(())
    }
}

#[derive(Debug)]
struct RoutePath {
    destination_host: String,
    first_interface: Option<String>,
    hops: Vec<RouteHop>,
}

#[derive(Debug)]
struct RouteHop {
    link: String,
    from: String,
    to: String,
}

fn outbound_nat_chain(state: &NetworkState, host: &str) -> Result<Vec<String>, NetworkError> {
    let attached = state
        .nats
        .iter()
        .filter(|(_, nat)| nat.inside_host == host)
        .map(|(id, _)| id.as_str())
        .collect::<BTreeSet<_>>();
    if attached.is_empty() {
        return Ok(Vec::new());
    }
    let referenced = state
        .nats
        .values()
        .filter(|nat| nat.inside_host == host)
        .filter_map(|nat| nat.upstream_nat.as_deref())
        .collect::<BTreeSet<_>>();
    let roots = attached
        .difference(&referenced)
        .copied()
        .collect::<Vec<_>>();
    if roots.len() != 1 {
        return Err(NetworkError::InvalidNatChain(host.to_owned()));
    }
    let mut chain = Vec::new();
    let mut seen = BTreeSet::new();
    let mut current = Some(roots[0]);
    while let Some(id) = current {
        if !seen.insert(id) {
            return Err(NetworkError::InvalidNatChain(host.to_owned()));
        }
        chain.push(id.to_owned());
        current = state
            .nats
            .get(id)
            .expect("chain entry exists")
            .upstream_nat
            .as_deref();
    }
    if chain.len() != attached.len() {
        return Err(NetworkError::InvalidNatChain(host.to_owned()));
    }
    Ok(chain)
}

fn route(
    state: &NetworkState,
    source: &str,
    destination: IpAddr,
) -> Result<RoutePath, NetworkError> {
    let destination_host = state
        .hosts
        .iter()
        .find_map(|(host, state)| host_owns_ip(state, destination).then(|| host.clone()))
        .or_else(|| {
            state.nats.values().find_map(|nat| {
                (destination == IpAddr::V4(nat.table.config().public_ip))
                    .then(|| nat.inside_host.clone())
            })
        })
        .ok_or(NetworkError::NoRoute { destination })?;
    if destination_host == source {
        return Ok(RoutePath {
            destination_host,
            first_interface: None,
            hops: Vec::new(),
        });
    }
    let mut current = source.to_owned();
    let mut visited = BTreeSet::new();
    let mut hops = Vec::new();
    let mut first_interface = None;
    while current != destination_host {
        if !visited.insert(current.clone()) {
            return Err(NetworkError::RouteLoop { host: current });
        }
        let host = state
            .hosts
            .get(&current)
            .ok_or_else(|| NetworkError::UnknownHost(current.clone()))?;
        let candidate = select_route(host, destination)?;
        let interface = host.interfaces.get(&candidate.interface).ok_or_else(|| {
            NetworkError::UnknownInterface {
                host: current.clone(),
                interface: candidate.interface.clone(),
            }
        })?;
        if !interface.up {
            return Err(NetworkError::InterfaceDown {
                host: current,
                interface: candidate.interface,
            });
        }
        first_interface.get_or_insert_with(|| candidate.interface.clone());
        let link = state
            .links
            .get(&interface.link)
            .expect("interface link exists");
        let next = match candidate.next_hop {
            Some(next) => next,
            None if link
                .members
                .iter()
                .any(|(host, _)| host == &destination_host) =>
            {
                destination_host.clone()
            }
            None => link
                .members
                .iter()
                .filter_map(|(host_id, interface_id)| {
                    let host = state.hosts.get(host_id)?;
                    let interface = host.interfaces.get(interface_id)?;
                    interface
                        .addresses
                        .iter()
                        .any(|cidr| cidr.contains(destination))
                        .then(|| host_id.clone())
                })
                .next()
                .ok_or(NetworkError::NoRoute { destination })?,
        };
        hops.push(RouteHop {
            link: interface.link.clone(),
            from: current,
            to: next.clone(),
        });
        current = next;
    }
    Ok(RoutePath {
        destination_host,
        first_interface,
        hops,
    })
}

#[derive(Clone)]
struct SelectedRoute {
    prefix: u8,
    interface: String,
    next_hop: Option<String>,
}

fn select_route(host: &HostState, destination: IpAddr) -> Result<SelectedRoute, NetworkError> {
    let mut candidates = Vec::new();
    for (interface_id, interface) in &host.interfaces {
        if !interface.up {
            continue;
        }
        for cidr in &interface.addresses {
            if cidr.contains(destination) {
                candidates.push(SelectedRoute {
                    prefix: cidr.prefix(),
                    interface: interface_id.clone(),
                    next_hop: None,
                });
            }
        }
    }
    for route in host.routes.values() {
        if route.destination.contains(destination) {
            candidates.push(SelectedRoute {
                prefix: route.destination.prefix(),
                interface: route.interface.clone(),
                next_hop: route.next_hop.clone(),
            });
        }
    }
    candidates
        .into_iter()
        .max_by_key(|candidate| candidate.prefix)
        .ok_or(NetworkError::NoRoute { destination })
}

fn select_source(
    state: &NetworkState,
    host_id: &str,
    bound: SocketAddr,
    requested: Option<IpAddr>,
    path: &RoutePath,
) -> Result<IpAddr, NetworkError> {
    let host = state
        .hosts
        .get(host_id)
        .ok_or_else(|| NetworkError::UnknownHost(host_id.to_owned()))?;
    let desired = requested
        .filter(|ip| !ip.is_unspecified())
        .or_else(|| (!bound.ip().is_unspecified()).then_some(bound.ip()));
    if let Some(desired) = desired {
        if !host_owns_ip(host, desired) || desired.is_ipv4() != bound.is_ipv4() {
            return Err(NetworkError::InvalidSource(desired));
        }
        return Ok(desired);
    }
    let interface = path
        .first_interface
        .as_ref()
        .and_then(|interface| host.interfaces.get(interface))
        .or_else(|| host.interfaces.values().find(|interface| interface.up))
        .ok_or_else(|| NetworkError::NoSourceAddress {
            host: host_id.to_owned(),
        })?;
    interface
        .addresses
        .iter()
        .map(|cidr| interface_address(*cidr))
        .find(|ip| ip.is_ipv4() == bound.is_ipv4())
        .ok_or_else(|| NetworkError::NoSourceAddress {
            host: host_id.to_owned(),
        })
}

fn route_rejection(error: &NetworkError) -> &'static str {
    match error {
        NetworkError::NoRoute { .. } => "rejected:no_route",
        NetworkError::RouteLoop { .. } => "rejected:route_loop",
        NetworkError::InterfaceDown { .. } => "rejected:interface_down",
        _ => "rejected:routing",
    }
}

fn source_rejection(error: &NetworkError) -> &'static str {
    match error {
        NetworkError::InvalidSource(_) => "rejected:invalid_source",
        NetworkError::NoSourceAddress { .. } => "rejected:no_source_address",
        _ => "rejected:source_selection",
    }
}

fn validate_bind_address(
    state: &NetworkState,
    host: &str,
    requested: SocketAddr,
) -> Result<(), NetworkError> {
    let host_state = state
        .hosts
        .get(host)
        .ok_or_else(|| NetworkError::UnknownHost(host.to_owned()))?;
    if !requested.ip().is_unspecified() && !host_owns_ip(host_state, requested.ip()) {
        return Err(NetworkError::AddressNotOwned {
            host: host.to_owned(),
            address: requested.ip(),
        });
    }
    Ok(())
}

fn allocate_bound_address(
    state: &mut NetworkState,
    host: &str,
    requested: SocketAddr,
) -> Result<SocketAddr, NetworkError> {
    if requested.port() != 0 {
        return Ok(requested);
    }
    loop {
        let port = {
            let host_state = state
                .hosts
                .get_mut(host)
                .ok_or_else(|| NetworkError::UnknownHost(host.to_owned()))?;
            let port = host_state.next_ephemeral;
            host_state.next_ephemeral = host_state.next_ephemeral.checked_add(1).ok_or(
                NetworkError::EphemeralPortsExhausted {
                    host: host.to_owned(),
                },
            )?;
            port
        };
        let candidate = SocketAddr::new(requested.ip(), port);
        if port_available(state, host, candidate) {
            return Ok(candidate);
        }
    }
}

fn ensure_port_available(
    state: &mut NetworkState,
    host: &str,
    address: SocketAddr,
) -> Result<(), NetworkError> {
    state.sockets.retain(|_, socket| socket.strong_count() > 0);
    if port_available(state, host, address) {
        Ok(())
    } else {
        Err(NetworkError::AddressInUse(address))
    }
}

fn port_available(state: &NetworkState, host: &str, address: SocketAddr) -> bool {
    state.sockets.keys().all(|key| {
        key.host != host
            || key.address.port() != address.port()
            || key.address.is_ipv4() != address.is_ipv4()
            || (!key.address.ip().is_unspecified()
                && !address.ip().is_unspecified()
                && key.address.ip() != address.ip())
    })
}

fn lookup_socket(
    state: &mut NetworkState,
    host: &str,
    destination: SocketAddr,
) -> Option<Arc<SyntheticIpSocket>> {
    state.sockets.retain(|_, socket| socket.strong_count() > 0);
    let exact = state
        .sockets
        .get(&SocketKey {
            host: host.to_owned(),
            address: destination,
        })
        .and_then(Weak::upgrade);
    exact.or_else(|| {
        let wildcard = SocketAddr::new(
            if destination.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            },
            destination.port(),
        );
        state
            .sockets
            .get(&SocketKey {
                host: host.to_owned(),
                address: wildcard,
            })
            .and_then(Weak::upgrade)
    })
}

fn host_owns_ip(host: &HostState, address: IpAddr) -> bool {
    host.interfaces
        .values()
        .flat_map(|interface| &interface.addresses)
        .any(|cidr| interface_address(*cidr) == address)
}

fn interface_address(cidr: IpCidr) -> IpAddr {
    cidr.address
}

fn allocate_packet_id(state: &mut NetworkState) -> Result<u64, NetworkError> {
    state.next_packet_id = state
        .next_packet_id
        .checked_add(1)
        .ok_or(NetworkError::PacketIdExhausted)?;
    Ok(state.next_packet_id)
}

fn fault_boolean(stream: &mut dyn DecisionStream, probability: u32) -> Result<bool, NetworkError> {
    Ok(stream.boolean(u64::from(probability), PROBABILITY_DENOMINATOR)?)
}

fn serialization_nanos(length: usize, bits_per_second: u64) -> Result<u64, NetworkError> {
    let bits = u128::try_from(length)
        .map_err(|_| NetworkError::TimelineOverflow)?
        .checked_mul(8)
        .ok_or(NetworkError::TimelineOverflow)?;
    let numerator = bits
        .checked_mul(1_000_000_000)
        .ok_or(NetworkError::TimelineOverflow)?;
    let denominator = u128::from(bits_per_second);
    let nanos = numerator
        .checked_add(denominator - 1)
        .ok_or(NetworkError::TimelineOverflow)?
        / denominator;
    u64::try_from(nanos).map_err(|_| NetworkError::TimelineOverflow)
}

fn duration_nanos(duration: Duration) -> Result<u64, NetworkError> {
    u64::try_from(duration.as_nanos()).map_err(|_| NetworkError::TimelineOverflow)
}

fn packet_context(packet: u64) -> TraceContext {
    TraceContext {
        packet: Some(packet.to_string()),
        ..TraceContext::default()
    }
}

fn validate_name(kind: &'static str, value: String) -> Result<String, NetworkError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Err(NetworkError::InvalidName { kind, value })
    } else {
        Ok(value)
    }
}

fn validate_link_config(config: LinkConfig) -> Result<(), NetworkError> {
    if config.bits_per_second == 0
        || config.mtu == 0
        || config.queue_packets == 0
        || config.loss_per_million > PROBABILITY_DENOMINATOR as u32
        || config.duplicate_per_million > PROBABILITY_DENOMINATOR as u32
        || config.corrupt_per_million > PROBABILITY_DENOMINATOR as u32
    {
        Err(NetworkError::InvalidLinkConfig)
    } else {
        Ok(())
    }
}

fn rollback_created_nat_mappings(
    state: &mut NetworkState,
    created: &[(String, String)],
) -> Result<(), NetworkError> {
    for (nat, mapping) in created.iter().rev() {
        if let Some(attached) = state.nats.get_mut(nat) {
            attached.table.rollback_dynamic_mapping(mapping)?;
        }
    }
    Ok(())
}

fn commit_firewall_flows(state: &mut NetworkState, flows: &[(String, FirewallPacket)]) {
    for (nat, packet) in flows {
        if let Some(firewall) = state
            .nats
            .get_mut(nat)
            .and_then(|attached| attached.firewall.as_mut())
        {
            firewall.commit_outbound(*packet);
        }
    }
}

/// Invalid topology, deterministic decision, socket operation, or network bound.
#[derive(Debug)]
pub enum NetworkError {
    /// Global configuration is invalid.
    InvalidConfig,
    /// Link configuration is invalid.
    InvalidLinkConfig,
    /// A topology identifier is not canonical.
    InvalidName { kind: &'static str, value: String },
    /// CIDR prefix is invalid for its family.
    InvalidPrefix { address: IpAddr, prefix: u8 },
    /// Host already exists.
    DuplicateHost(String),
    /// Link already exists.
    DuplicateLink(String),
    /// NAT identity already exists.
    DuplicateNat(String),
    /// Host does not exist.
    UnknownHost(String),
    /// Link does not exist.
    UnknownLink(String),
    /// NAT does not exist.
    UnknownNat(String),
    /// Host interface does not exist.
    UnknownInterface { host: String, interface: String },
    /// Explicit route does not exist.
    UnknownRoute { host: String, route: String },
    /// Host has no installed simulator port mapper.
    UnknownPortMapper(String),
    /// Simulator port-mapping capability failed.
    PortMapping(String),
    /// Host interface already exists.
    DuplicateInterface { host: String, interface: String },
    /// Interface must own at least one address.
    InterfaceHasNoAddress,
    /// Address is already assigned to another interface.
    DuplicateAddress(IpAddr),
    /// Explicit route duplicates an equal destination prefix.
    AmbiguousRoute { host: String, destination: IpCidr },
    /// Explicit next hop does not share the selected link.
    InvalidNextHop { host: String, next_hop: String },
    /// No destination route exists.
    NoRoute { destination: IpAddr },
    /// Routing revisited a host.
    RouteLoop { host: String },
    /// Selected interface is down.
    InterfaceDown { host: String, interface: String },
    /// Requested source is not owned by the sending host/family.
    InvalidSource(IpAddr),
    /// No suitable source address exists.
    NoSourceAddress { host: String },
    /// An ordered firewall rule actively rejected an outbound packet.
    FirewallRejected(String),
    /// Bind address is not assigned to this host.
    AddressNotOwned { host: String, address: IpAddr },
    /// Socket address conflicts with an existing bind.
    AddressInUse(SocketAddr),
    /// No ephemeral ports remain.
    EphemeralPortsExhausted { host: String },
    /// Packet exceeds a link MTU.
    MtuExceeded {
        link: String,
        mtu: usize,
        length: usize,
    },
    /// Stable packet IDs are exhausted.
    PacketIdExhausted,
    /// Integer timeline arithmetic overflowed.
    TimelineOverflow,
    /// A resource count overflowed.
    ResourceOverflow,
    /// A deterministic decision failed.
    Decision(DecisionError),
    /// A structured trace failed.
    Trace(TraceRecordError),
    /// Virtual clock failed.
    Clock(iroh_runtime::ClockError),
    /// Kernel rejected scheduling.
    Kernel(KernelError),
    /// Resource ledger rejected ownership.
    Ledger(LedgerError),
    /// Stateful translation/filtering rejected the operation.
    Nat(NatError),
    /// NAT chain placement is cyclic, ambiguous, or crosses unsupported host boundaries.
    InvalidNatChain(String),
    /// An asynchronous environment callback failed and was surfaced at the next boundary.
    Deferred(String),
}

impl NetworkError {
    fn into_io(self) -> io::Error {
        let kind = match self {
            Self::MtuExceeded { .. } | Self::InvalidSource(_) => io::ErrorKind::InvalidInput,
            Self::AddressInUse(_) => io::ErrorKind::AddrInUse,
            Self::AddressNotOwned { .. } => io::ErrorKind::AddrNotAvailable,
            Self::NoRoute { .. } | Self::InterfaceDown { .. } => io::ErrorKind::NetworkUnreachable,
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, self)
    }
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "synthetic network error: {self:?}")
    }
}

impl std::error::Error for NetworkError {}

impl From<DecisionError> for NetworkError {
    fn from(value: DecisionError) -> Self {
        Self::Decision(value)
    }
}

impl From<TraceRecordError> for NetworkError {
    fn from(value: TraceRecordError) -> Self {
        Self::Trace(value)
    }
}

impl From<iroh_runtime::ClockError> for NetworkError {
    fn from(value: iroh_runtime::ClockError) -> Self {
        Self::Clock(value)
    }
}

impl From<KernelError> for NetworkError {
    fn from(value: KernelError) -> Self {
        Self::Kernel(value)
    }
}

impl From<LedgerError> for NetworkError {
    fn from(value: LedgerError) -> Self {
        Self::Ledger(value)
    }
}

impl From<NatError> for NetworkError {
    fn from(value: NatError) -> Self {
        Self::Nat(value)
    }
}
