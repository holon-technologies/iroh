//! Strict Stage 2 named scenarios running production Iroh endpoints over synthetic IP.

use std::{fmt, net::SocketAddr, sync::Arc, time::Duration};

use iroh::{
    Endpoint, EndpointAddr, NetReportConfig, SecretKey,
    endpoint::{PortmapperConfig, presets},
    simulation::SimulationCryptoMaterial,
};
use iroh_runtime::{
    RootSeed, TraceEvent, TraceEventKind, TraceSink, TraceSinkError, UnsafeTestOnly,
};
use serde::{Deserialize, Serialize};

use crate::{
    DeterministicBackend, DeterministicBackendConfig, IpCidr, KernelConfig, LinkConfig,
    NetworkConfig, ResourceKind, ResourceLedgerSnapshot, RunBudgets, TraceBuffer,
};

/// Current strict schema for Stage 2 scenario files.
pub const STAGE2_SCENARIO_SCHEMA_VERSION: u16 = 1;
const ALPN: &[u8] = b"iroh-sim/scenario/1";

/// Supported handwritten Stage 2 scenario descriptor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2Scenario {
    /// Scenario schema version.
    pub schema_version: u16,
    /// Stable built-in scenario identity.
    pub id: String,
}

impl Stage2Scenario {
    /// Parses and validates a strict scenario document.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ScenarioError> {
        let scenario: Self = serde_json::from_slice(bytes)
            .map_err(|error| ScenarioError::Json(error.to_string()))?;
        scenario.validate()?;
        Ok(scenario)
    }

    /// Returns canonical bytes used for manifest identity.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, ScenarioError> {
        self.validate()?;
        let mut bytes =
            serde_json::to_vec(self).map_err(|error| ScenarioError::Json(error.to_string()))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Rejects unknown schemas and capabilities not present in Stage 2.
    pub fn validate(&self) -> Result<(), ScenarioError> {
        if self.schema_version != STAGE2_SCENARIO_SCHEMA_VERSION {
            return Err(ScenarioError::UnsupportedSchema(self.schema_version));
        }
        match self.id.as_str() {
            "direct-ip/ipv4-stream"
            | "direct-ip/ipv4-stream-loss"
            | "direct-ip/ipv4-stream-corruption"
            | "direct-ip/ipv6-stream"
            | "direct-ip/ipv6-datagram" => Ok(()),
            _ => Err(ScenarioError::UnsupportedScenario(self.id.clone())),
        }
    }
}

/// Prepared run whose manifest capabilities come from the installed backend.
#[derive(Debug)]
pub struct ScenarioHarness {
    scenario: Stage2Scenario,
    backend: DeterministicBackend,
    trace: TraceBuffer,
}

impl ScenarioHarness {
    /// Creates a bounded scenario backend without running endpoint behavior yet.
    pub fn new(
        scenario: Stage2Scenario,
        root_seed: RootSeed,
        wall_epoch: std::time::SystemTime,
        budgets: &RunBudgets,
    ) -> Result<Self, ScenarioError> {
        Self::new_inner(
            scenario,
            root_seed,
            wall_epoch,
            budgets,
            None,
            iroh::simulation::SimulationCryptoMode::DeterministicTest,
        )
    }

    /// Creates a bounded scenario backend with an explicit cryptography lane.
    pub fn new_with_crypto_mode(
        scenario: Stage2Scenario,
        root_seed: RootSeed,
        wall_epoch: std::time::SystemTime,
        budgets: &RunBudgets,
        crypto_mode: iroh::simulation::SimulationCryptoMode,
    ) -> Result<Self, ScenarioError> {
        Self::new_inner(scenario, root_seed, wall_epoch, budgets, None, crypto_mode)
    }

    /// Creates a backend that also streams every retained event to `secondary_trace`.
    pub fn new_with_trace_sink(
        scenario: Stage2Scenario,
        root_seed: RootSeed,
        wall_epoch: std::time::SystemTime,
        budgets: &RunBudgets,
        secondary_trace: Arc<dyn TraceSink>,
    ) -> Result<Self, ScenarioError> {
        Self::new_inner(
            scenario,
            root_seed,
            wall_epoch,
            budgets,
            Some(secondary_trace),
            iroh::simulation::SimulationCryptoMode::DeterministicTest,
        )
    }

    /// Creates a backend with an explicit cryptography lane and secondary trace sink.
    pub fn new_with_crypto_mode_and_trace_sink(
        scenario: Stage2Scenario,
        root_seed: RootSeed,
        wall_epoch: std::time::SystemTime,
        budgets: &RunBudgets,
        secondary_trace: Arc<dyn TraceSink>,
        crypto_mode: iroh::simulation::SimulationCryptoMode,
    ) -> Result<Self, ScenarioError> {
        Self::new_inner(
            scenario,
            root_seed,
            wall_epoch,
            budgets,
            Some(secondary_trace),
            crypto_mode,
        )
    }

    fn new_inner(
        scenario: Stage2Scenario,
        root_seed: RootSeed,
        wall_epoch: std::time::SystemTime,
        budgets: &RunBudgets,
        secondary_trace: Option<Arc<dyn TraceSink>>,
        crypto_mode: iroh::simulation::SimulationCryptoMode,
    ) -> Result<Self, ScenarioError> {
        scenario.validate()?;
        let trace = TraceBuffer::default();
        let backend = DeterministicBackend::new(
            DeterministicBackendConfig {
                root_seed,
                wall_epoch,
                kernel: KernelConfig {
                    max_events: budgets.max_events,
                    max_virtual_time: Duration::from_nanos(budgets.max_virtual_time_nanos),
                    max_tasks: budgets.max_tasks,
                },
                network: NetworkConfig {
                    max_packets: budgets.max_packets,
                    ephemeral_port_start: 40_000,
                },
                max_driver_turns: budgets.max_events.saturating_mul(8).max(1_000),
                crypto_mode,
            },
            Arc::new(RetainedTrace {
                buffer: trace.clone(),
                secondary: secondary_trace,
            }),
        )?;
        Ok(Self {
            scenario,
            backend,
            trace,
        })
    }

    /// Returns the installed backend for manifest classification.
    pub fn backend(&self) -> &DeterministicBackend {
        &self.backend
    }

    /// Executes the selected production endpoint operation and reconciles all Stage 2 resources.
    pub async fn run(&self) -> Result<ScenarioObservation, ScenarioError> {
        match self.scenario.id.as_str() {
            "direct-ip/ipv4-stream" => {
                self.run_pair(
                    false,
                    Operation::Stream,
                    LinkConfig::default(),
                    None,
                    ExpectedExchange::Success,
                )
                .await
            }
            "direct-ip/ipv4-stream-loss" => {
                self.run_pair(
                    false,
                    Operation::Stream,
                    LinkConfig {
                        loss_per_million: 250_000,
                        ..LinkConfig::default()
                    },
                    Some("link/lan/loss"),
                    ExpectedExchange::Success,
                )
                .await
            }
            "direct-ip/ipv4-stream-corruption" => {
                self.run_pair(
                    false,
                    Operation::Stream,
                    LinkConfig {
                        corrupt_per_million: 250_000,
                        ..LinkConfig::default()
                    },
                    Some("network/corruption"),
                    ExpectedExchange::FailureContaining("authentication failed"),
                )
                .await
            }
            "direct-ip/ipv6-stream" => {
                self.run_pair(
                    true,
                    Operation::Stream,
                    LinkConfig::default(),
                    None,
                    ExpectedExchange::Success,
                )
                .await
            }
            "direct-ip/ipv6-datagram" => {
                self.run_pair(
                    true,
                    Operation::Datagram,
                    LinkConfig::default(),
                    None,
                    ExpectedExchange::Success,
                )
                .await
            }
            _ => Err(ScenarioError::UnsupportedScenario(self.scenario.id.clone())),
        }
    }

    /// Returns all raw events emitted so far.
    pub fn trace(&self) -> Vec<TraceEvent> {
        self.trace.events()
    }

    async fn run_pair(
        &self,
        ipv6: bool,
        operation: Operation,
        link: LinkConfig,
        expected_fault: Option<&str>,
        expected_exchange: ExpectedExchange,
    ) -> Result<ScenarioObservation, ScenarioError> {
        let network = self.backend.network();
        network.add_host("client")?;
        network.add_host("server")?;
        network.add_link("lan", link)?;
        let (client_ip, server_ip, prefix, client_addr, server_addr) = addresses(ipv6);
        network.add_interface("client", "eth0", "lan", [IpCidr::new(client_ip, prefix)?])?;
        network.add_interface("server", "eth0", "lan", [IpCidr::new(server_ip, prefix)?])?;
        let client = self.bind_endpoint("client", client_addr, [1; 32]).await?;
        let server = self.bind_endpoint("server", server_addr, [2; 32]).await?;
        let payload = b"iroh-stage2-production-path";

        let server_id = server.id();
        let server_operation = {
            let server = server.clone();
            async move {
                let incoming = server
                    .accept()
                    .await
                    .ok_or_else(|| "server endpoint closed".to_owned())?;
                let connection = incoming.await.map_err(|error| error.to_string())?;
                let received = match operation {
                    Operation::Stream => {
                        let (mut send, mut receive) = connection
                            .accept_bi()
                            .await
                            .map_err(|error| error.to_string())?;
                        let received = receive
                            .read_to_end(4_096)
                            .await
                            .map_err(|error| error.to_string())?;
                        send.write_all(&received)
                            .await
                            .map_err(|error| error.to_string())?;
                        send.finish().map_err(|error| error.to_string())?;
                        received
                    }
                    Operation::Datagram => {
                        let received = connection
                            .read_datagram()
                            .await
                            .map_err(|error| error.to_string())?;
                        connection
                            .send_datagram(received.clone())
                            .map_err(|error| error.to_string())?;
                        received.to_vec()
                    }
                };
                connection.closed().await;
                Ok::<_, String>(received)
            }
        };
        let client_operation = {
            let client = client.clone();
            async move {
                let connection = client
                    .connect(EndpointAddr::new(server_id).with_ip_addr(server_addr), ALPN)
                    .await
                    .map_err(|error| error.to_string())?;
                let echoed = match operation {
                    Operation::Stream => {
                        let (mut send, mut receive) = connection
                            .open_bi()
                            .await
                            .map_err(|error| error.to_string())?;
                        send.write_all(payload)
                            .await
                            .map_err(|error| error.to_string())?;
                        send.finish().map_err(|error| error.to_string())?;
                        receive
                            .read_to_end(4_096)
                            .await
                            .map_err(|error| error.to_string())?
                    }
                    Operation::Datagram => {
                        connection
                            .send_datagram(payload.as_slice().into())
                            .map_err(|error| error.to_string())?;
                        connection
                            .read_datagram()
                            .await
                            .map_err(|error| error.to_string())?
                            .to_vec()
                    }
                };
                connection.close(0u32.into(), b"complete");
                Ok::<_, String>(echoed)
            }
        };
        let exchange = self
            .backend
            .driver()
            .drive(async move {
                let (server, client) = tokio::join!(server_operation, client_operation);
                Ok::<_, String>((server?, client?))
            })
            .await
            .map_err(ScenarioError::Driver)
            .and_then(|result| result.map_err(ScenarioError::Operation));

        self.backend
            .driver()
            .drive(async { tokio::join!(client.close(), server.close()) })
            .await?;
        drop(client);
        drop(server);
        self.backend
            .driver()
            .drive_until(|| self.backend.kernel().ledger().is_empty())
            .await?;
        let ledger = self.backend.kernel().ledger();
        if !ledger.is_empty() {
            return Err(ScenarioError::ResourceLeak(ledger));
        }
        if let Some(expected_rule) = expected_fault {
            let observed = self.trace.events().into_iter().any(|event| {
                matches!(
                    event.event,
                    TraceEventKind::FaultInjected { ref rule, .. } if rule == expected_rule
                )
            });
            if !observed {
                return Err(ScenarioError::ExpectedFaultNotObserved(
                    expected_rule.to_owned(),
                ));
            }
        }
        match (expected_exchange, exchange) {
            (ExpectedExchange::Success, Ok(exchange)) => {
                if exchange.0 != payload || exchange.1 != payload {
                    return Err(ScenarioError::DataMismatch);
                }
            }
            (ExpectedExchange::Success, Err(error)) => return Err(error),
            (ExpectedExchange::FailureContaining(expected), Err(error))
                if error.to_string().contains(expected) => {}
            (ExpectedExchange::FailureContaining(expected), Err(error)) => {
                return Err(ScenarioError::ExpectedFailureMismatch {
                    expected: expected.to_owned(),
                    actual: error.to_string(),
                });
            }
            (ExpectedExchange::FailureContaining(expected), Ok(_)) => {
                return Err(ScenarioError::ExpectedFailureNotObserved(
                    expected.to_owned(),
                ));
            }
        }
        Ok(ScenarioObservation {
            virtual_time: self.backend.kernel().now(),
            events: u64::try_from(self.trace.events().len())
                .map_err(|_| ScenarioError::ObservationOverflow)?,
            packet_high_water: ledger.high_water(ResourceKind::QueuedPacket),
        })
    }

    async fn bind_endpoint(
        &self,
        host: &str,
        address: SocketAddr,
        secret: [u8; 32],
    ) -> Result<Endpoint, ScenarioError> {
        let environment = self.backend.endpoint_environment(
            host,
            SimulationCryptoMaterial::new(secret, [secret[0].wrapping_add(1); 32]),
        )?;
        Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&secret))
            .alpns(vec![ALPN.to_vec()])
            .clear_ip_transports()
            .bind_addr(address)
            .map_err(|error| ScenarioError::Endpoint(error.to_string()))?
            .portmapper_config(PortmapperConfig::Disabled)
            .net_report_config(NetReportConfig::minimal())
            .simulation_environment_for_test(environment, UnsafeTestOnly::acknowledge())
            .bind()
            .await
            .map_err(|error| ScenarioError::Endpoint(error.to_string()))
    }
}

#[derive(Debug)]
struct RetainedTrace {
    buffer: TraceBuffer,
    secondary: Option<Arc<dyn TraceSink>>,
}

impl TraceSink for RetainedTrace {
    fn record(&self, event: TraceEvent) -> Result<(), TraceSinkError> {
        self.buffer.record(event.clone())?;
        if let Some(secondary) = &self.secondary {
            secondary.record(event)?;
        }
        Ok(())
    }
}

fn addresses(
    ipv6: bool,
) -> (
    std::net::IpAddr,
    std::net::IpAddr,
    u8,
    SocketAddr,
    SocketAddr,
) {
    if ipv6 {
        (
            "2001:db8::1".parse().expect("constant IP"),
            "2001:db8::2".parse().expect("constant IP"),
            64,
            "[2001:db8::1]:31001".parse().expect("constant socket"),
            "[2001:db8::2]:31002".parse().expect("constant socket"),
        )
    } else {
        (
            "192.0.2.1".parse().expect("constant IP"),
            "192.0.2.2".parse().expect("constant IP"),
            24,
            "192.0.2.1:31001".parse().expect("constant socket"),
            "192.0.2.2:31002".parse().expect("constant socket"),
        )
    }
}

#[derive(Clone, Copy)]
enum Operation {
    Stream,
    Datagram,
}

#[derive(Clone, Copy)]
enum ExpectedExchange {
    Success,
    FailureContaining(&'static str),
}

/// Stable terminal observations from a successful Stage 2 scenario.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScenarioObservation {
    pub virtual_time: Duration,
    pub events: u64,
    pub packet_high_water: u64,
}

/// Strict input, backend, endpoint, driver, or invariant failure.
#[derive(Debug)]
pub enum ScenarioError {
    Json(String),
    UnsupportedSchema(u16),
    UnsupportedScenario(String),
    Backend(crate::BackendError),
    Network(crate::NetworkError),
    Driver(crate::KernelDriverError),
    Operation(String),
    Endpoint(String),
    DataMismatch,
    ResourceLeak(ResourceLedgerSnapshot),
    ExpectedFaultNotObserved(String),
    ExpectedFailureNotObserved(String),
    ExpectedFailureMismatch { expected: String, actual: String },
    ObservationOverflow,
}

impl fmt::Display for ScenarioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(f, "scenario JSON is invalid: {error}"),
            Self::UnsupportedSchema(version) => write!(f, "unsupported scenario schema {version}"),
            Self::UnsupportedScenario(id) => write!(f, "unsupported Stage 2 scenario {id:?}"),
            Self::Backend(error) => write!(f, "scenario backend failed: {error}"),
            Self::Network(error) => write!(f, "scenario network failed: {error}"),
            Self::Driver(error) => write!(f, "scenario kernel driver failed: {error}"),
            Self::Operation(error) => write!(f, "scenario operation failed: {error}"),
            Self::Endpoint(error) => write!(f, "scenario endpoint failed: {error}"),
            Self::DataMismatch => f.write_str("scenario application data mismatch"),
            Self::ResourceLeak(ledger) => write!(f, "scenario resource leak: {ledger:?}"),
            Self::ExpectedFaultNotObserved(rule) => {
                write!(f, "scenario expected fault rule {rule:?} was not observed")
            }
            Self::ExpectedFailureNotObserved(expected) => {
                write!(
                    f,
                    "scenario expected failure containing {expected:?} was not observed"
                )
            }
            Self::ExpectedFailureMismatch { expected, actual } => write!(
                f,
                "scenario expected failure containing {expected:?}, got {actual:?}"
            ),
            Self::ObservationOverflow => f.write_str("scenario observation count overflow"),
        }
    }
}

impl std::error::Error for ScenarioError {}

impl From<crate::BackendError> for ScenarioError {
    fn from(value: crate::BackendError) -> Self {
        Self::Backend(value)
    }
}

impl From<crate::NetworkError> for ScenarioError {
    fn from(value: crate::NetworkError) -> Self {
        Self::Network(value)
    }
}

impl From<crate::KernelDriverError> for ScenarioError {
    fn from(value: crate::KernelDriverError) -> Self {
        Self::Driver(value)
    }
}

impl From<String> for ScenarioError {
    fn from(value: String) -> Self {
        Self::Operation(value)
    }
}
