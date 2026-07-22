//! Coherent Stage 2 backend construction and capability classification.

use std::{
    collections::BTreeMap,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::SystemTime,
};

use iroh::simulation::{SimulationCryptoMaterial, SimulationCryptoMode, SimulationEnvironment};
use iroh_runtime::{RootSeed, RuntimeContext, TraceSink};

use crate::{
    BackendCapabilities, CryptoMode, DeterminismGrade, DeterministicPortMapper, Kernel,
    KernelConfig, KernelDriver, KernelDriverError, NetworkConfig, NetworkError,
    StaticNetworkMonitor, SyntheticNetwork, TraceComparisonMode,
};

/// Complete construction inputs for the Stage 2 direct-IP backend.
#[derive(Clone, Debug)]
pub struct DeterministicBackendConfig {
    /// Root of all named behavioral decision streams.
    pub root_seed: RootSeed,
    /// Deterministic wall-clock epoch.
    pub wall_epoch: SystemTime,
    /// Kernel bounds.
    pub kernel: KernelConfig,
    /// Synthetic network bounds and ephemeral-port policy.
    pub network: NetworkConfig,
    /// Hard root-poll/kernel-step watchdog.
    pub max_driver_turns: u64,
    /// TLS provider mode used by simulator endpoints.
    pub crypto_mode: SimulationCryptoMode,
}

/// One kernel, decision namespace, synthetic network, and honest capability declaration.
#[derive(Clone, Debug)]
pub struct DeterministicBackend {
    kernel: Kernel,
    context: Arc<RuntimeContext>,
    network: SyntheticNetwork,
    driver: KernelDriver,
    monitors: Arc<Mutex<BTreeMap<String, MonitorEntry>>>,
    port_mappers: Arc<Mutex<BTreeMap<String, Arc<DeterministicPortMapper>>>>,
    crypto_mode: SimulationCryptoMode,
}

#[derive(Debug)]
struct MonitorEntry {
    monitor: Arc<StaticNetworkMonitor>,
    change_bit: bool,
}

impl DeterministicBackend {
    /// Creates an empty topology backed by the deterministic kernel driver.
    pub fn new(
        config: DeterministicBackendConfig,
        trace: Arc<dyn TraceSink>,
    ) -> Result<Self, BackendError> {
        let kernel = Kernel::new(config.kernel, trace)?;
        let context = Arc::new(kernel.runtime_context(config.root_seed, config.wall_epoch));
        let network = SyntheticNetwork::new(kernel.clone(), context.clone(), config.network)?;
        let driver = KernelDriver::new(kernel.clone(), config.max_driver_turns)?;
        Ok(Self {
            kernel,
            context,
            network,
            driver,
            monitors: Arc::new(Mutex::new(BTreeMap::new())),
            port_mappers: Arc::new(Mutex::new(BTreeMap::new())),
            crypto_mode: config.crypto_mode,
        })
    }

    /// Returns the deterministic kernel.
    pub fn kernel(&self) -> &Kernel {
        &self.kernel
    }

    /// Returns the topology and synthetic socket owner.
    pub fn network(&self) -> &SyntheticNetwork {
        &self.network
    }

    /// Returns the kernel-owned root-operation driver.
    pub fn driver(&self) -> &KernelDriver {
        &self.driver
    }

    /// Returns the shared runtime context for runner-level structured observations.
    pub fn runtime_context(&self) -> &Arc<RuntimeContext> {
        &self.context
    }

    /// Builds an endpoint environment for one configured synthetic host.
    pub fn endpoint_environment(
        &self,
        host: &str,
        crypto: SimulationCryptoMaterial,
    ) -> Result<SimulationEnvironment, NetworkError> {
        let connectivity = self.network.host_connectivity(host)?;
        let monitor = {
            let mut monitors = self
                .monitors
                .lock()
                .expect("simulation monitor lock poisoned");
            monitors
                .entry(host.to_owned())
                .or_insert_with(|| MonitorEntry {
                    monitor: Arc::new(StaticNetworkMonitor::new(monitor_state(
                        connectivity.clone(),
                        false,
                    ))),
                    change_bit: false,
                })
                .monitor
                .clone()
        };
        let mut environment = SimulationEnvironment::new(
            self.context.clone(),
            self.network.socket_factory(host)?,
            monitor,
            crypto,
        );
        if self.crypto_mode == SimulationCryptoMode::DeterministicTest {
            environment = environment.with_deterministic_test_tls(
                iroh_relay::tls::default_provider(),
                derive_crypto_seed(self.context.root_seed(), host),
                &format!("endpoint/{host}"),
            );
        }
        if let Some(nat) = self.network.host_nat(host)? {
            let mapper = self
                .port_mappers
                .lock()
                .expect("simulation port mapper lock poisoned")
                .entry(host.to_owned())
                .or_insert_with(|| {
                    Arc::new(DeterministicPortMapper::new(
                        format!("{host}/port-mapper"),
                        host,
                        nat,
                        self.kernel.clone(),
                        self.network.clone(),
                    ))
                })
                .clone();
            environment = environment.with_port_mapper(mapper);
        }
        Ok(environment)
    }

    /// Mutates synthetic routing state and publishes the same change to production observers.
    pub fn set_interface_up(
        &self,
        host: &str,
        interface: &str,
        up: bool,
    ) -> Result<(), NetworkError> {
        self.network.set_interface_up(host, interface, up)?;
        self.publish_monitor(host)
    }

    /// Mutates one interface address and publishes the resulting production monitor state.
    pub fn set_interface_address(
        &self,
        host: &str,
        interface: &str,
        address: crate::IpCidr,
        present: bool,
    ) -> Result<(), NetworkError> {
        self.network
            .set_interface_address(host, interface, address, present)?;
        self.publish_monitor(host)
    }

    /// Suspends or resumes a host and publishes the resulting production monitor state.
    pub fn set_host_sleeping(&self, host: &str, sleeping: bool) -> Result<(), NetworkError> {
        self.network.set_host_sleeping(host, sleeping)?;
        self.publish_monitor(host)
    }

    /// Adds or removes an explicit route and publishes the resulting monitor state.
    #[allow(clippy::too_many_arguments)]
    pub fn set_route(
        &self,
        host: &str,
        route: &str,
        destination: crate::IpCidr,
        interface: &str,
        next_hop: Option<&str>,
        active: bool,
    ) -> Result<(), NetworkError> {
        if active {
            self.network
                .add_route(host, route, destination, interface, next_hop)?;
        } else {
            self.network.remove_route(host, route)?;
        }
        self.publish_monitor(host)
    }

    /// Activates or withdraws the simulator-owned production port-mapping capability.
    pub fn set_port_mapping(
        &self,
        host: &str,
        active: bool,
    ) -> Result<Option<std::net::SocketAddrV4>, NetworkError> {
        let mapper = self
            .port_mappers
            .lock()
            .expect("simulation port mapper lock poisoned")
            .get(host)
            .cloned()
            .ok_or_else(|| NetworkError::UnknownPortMapper(host.to_owned()))?;
        if active {
            mapper.activate();
        } else {
            iroh::simulation::PortMapper::deactivate(mapper.as_ref());
        }
        if let Some(error) = mapper.take_error() {
            return Err(NetworkError::PortMapping(error));
        }
        Ok(mapper.external_address())
    }

    /// Rebinds a NAT and republishes preserved leases through production port-map watchers.
    pub fn rebind_nat(
        &self,
        nat: &str,
        public_ip: Ipv4Addr,
        preserve_ports: bool,
    ) -> Result<(), NetworkError> {
        self.network.rebind_nat(nat, public_ip, preserve_ports)?;
        for mapper in self
            .port_mappers
            .lock()
            .expect("simulation port mapper lock poisoned")
            .values()
            .filter(|mapper| mapper.nat_id() == nat)
        {
            mapper.refresh();
            if let Some(error) = mapper.take_error() {
                return Err(NetworkError::PortMapping(error));
            }
        }
        Ok(())
    }

    fn publish_monitor(&self, host: &str) -> Result<(), NetworkError> {
        let connectivity = self.network.host_connectivity(host)?;
        if let Some(entry) = self
            .monitors
            .lock()
            .expect("simulation monitor lock poisoned")
            .get_mut(host)
        {
            entry.change_bit = !entry.change_bit;
            entry
                .monitor
                .set_state(monitor_state(connectivity, entry.change_bit));
        }
        Ok(())
    }

    /// Capabilities derived from the installed backend rather than scenario claims.
    pub const fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::deterministic_kernel()
    }

    /// Grade derived from the cryptography implementation actually installed by this backend.
    pub const fn determinism_grade(&self) -> DeterminismGrade {
        match self.crypto_mode {
            SimulationCryptoMode::DeterministicTest => DeterminismGrade::FullyDeterministic,
            SimulationCryptoMode::ProductionProvider => DeterminismGrade::SemanticallyDeterministic,
        }
    }

    /// Manifest cryptography mode derived from the installed endpoint environment.
    pub const fn crypto_mode(&self) -> CryptoMode {
        match self.crypto_mode {
            SimulationCryptoMode::DeterministicTest => CryptoMode::DeterministicTest,
            SimulationCryptoMode::ProductionProvider => CryptoMode::ProductionProvider,
        }
    }

    /// Immutable replay comparison required by this backend mode.
    pub const fn trace_comparison(&self) -> TraceComparisonMode {
        match self.crypto_mode {
            SimulationCryptoMode::DeterministicTest => TraceComparisonMode::Raw,
            SimulationCryptoMode::ProductionProvider => TraceComparisonMode::Semantic,
        }
    }

    /// Sorted fidelity substitutions used by this backend mode.
    pub fn fidelity_exceptions(&self) -> Vec<String> {
        match self.crypto_mode {
            SimulationCryptoMode::DeterministicTest => {
                vec!["deterministic_test_crypto".to_owned()]
            }
            SimulationCryptoMode::ProductionProvider => Vec::new(),
        }
    }

    /// Sorted uncontrolled boundaries observed for this backend mode.
    pub fn escapes(&self) -> Vec<String> {
        match self.crypto_mode {
            SimulationCryptoMode::DeterministicTest => Vec::new(),
            SimulationCryptoMode::ProductionProvider => {
                vec!["production_crypto_entropy".to_owned()]
            }
        }
    }
}

fn derive_crypto_seed(root: RootSeed, host: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("iroh-sim deterministic TLS endpoint seed v1");
    hasher.update(root.as_bytes());
    hasher.update(&(host.len() as u32).to_le_bytes());
    hasher.update(host.as_bytes());
    *hasher.finalize().as_bytes()
}

fn monitor_state(
    connectivity: crate::HostConnectivity,
    change_bit: bool,
) -> netwatch::netmon::State {
    let mut state = netwatch::netmon::State::fake();
    state.have_v4 = connectivity.have_v4;
    state.have_v6 = connectivity.have_v6;
    // netwatch does not expose constructors for synthetic interface records. Toggling this
    // observable bit publishes administrative switches whose family availability is unchanged;
    // exact routing and source selection still come from the synthetic topology.
    state.is_expensive = change_bit;
    if !connectivity.have_default_route {
        state.default_route_interface = None;
    }
    state
}

/// Stage 2 backend construction failed before scenario execution.
#[derive(Debug)]
pub enum BackendError {
    /// Kernel configuration or initialization failed.
    Kernel(crate::KernelError),
    /// Network configuration was invalid.
    Network(NetworkError),
    /// Kernel root-driver configuration was invalid.
    Driver(KernelDriverError),
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kernel(error) => write!(f, "backend kernel construction failed: {error}"),
            Self::Network(error) => write!(f, "backend network construction failed: {error}"),
            Self::Driver(error) => write!(f, "backend driver construction failed: {error}"),
        }
    }
}

impl std::error::Error for BackendError {}

impl From<crate::KernelError> for BackendError {
    fn from(value: crate::KernelError) -> Self {
        Self::Kernel(value)
    }
}

impl From<NetworkError> for BackendError {
    fn from(value: NetworkError) -> Self {
        Self::Network(value)
    }
}

impl From<KernelDriverError> for BackendError {
    fn from(value: KernelDriverError) -> Self {
        Self::Driver(value)
    }
}
