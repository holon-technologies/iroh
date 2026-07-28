//! Deterministic kernel, network, NAT, relay, and discovery primitives.

pub use crate::{
    discovery::{DeterministicDiscovery, DiscoveryError, DiscoveryRecordSnapshot},
    dns::DeterministicDnsRuntime,
    kernel::{
        EventClass, EventId, Kernel, KernelConfig, KernelError, KernelExecutor,
        KernelResourceLimits, KernelRun, KernelSchedulerSnapshot, KernelStep, KernelTaskSnapshot,
        Quiescence, ScheduledEvent, VirtualClock, VirtualWallClock,
    },
    ledger::{
        LedgerError, ResourceCount, ResourceKind, ResourceLedger, ResourceLedgerSnapshot,
        ResourceToken,
    },
    monitor::StaticNetworkMonitor,
    nat::{
        Firewall, FirewallAction, FirewallConfig, FirewallConnectionState, FirewallDecision,
        FirewallDirection, FirewallPacket, FirewallProtocol, FirewallRule, NatConfig, NatError,
        NatFilteringBehavior, NatInbound, NatMappingBehavior, NatMappingSnapshot, NatOutbound,
        NatPortMapping, NatTable,
    },
    network::{
        HostConnectivity, IpCidr, LinkConfig, NetworkConfig, NetworkError, SyntheticNetwork,
    },
    portmap::DeterministicPortMapper,
    relay::{
        RelayAdmissionDecision, RelayCoverage, RelayEnvironment, RelayEnvironmentError,
        RelayRouteDecision, RelayRoutingOracle,
    },
};
