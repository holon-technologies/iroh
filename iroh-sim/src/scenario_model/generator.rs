use super::*;

/// Bounds for deterministic generated scenarios.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratorConfig {
    pub max_actions: u64,
    pub max_payload_bytes: u64,
    pub max_virtual_time: Duration,
}

/// Leaves headroom for QUIC packet metadata within its minimum 1,200-byte UDP payload.
const MAX_GENERATED_DATAGRAM_PAYLOAD_BYTES: u64 = 1_024;

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
            || self.config.max_actions > u64::try_from(MAX_ITEMS).expect("MAX_ITEMS fits in u64")
            || self.config.max_payload_bytes == 0
            || usize::try_from(self.config.max_payload_bytes).is_err()
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
        scenario.budgets.resources.max_connections = self.config.max_actions;
        scenario.budgets.resources.max_streams = self.config.max_actions;
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
        let payload_limit = match operation {
            ScenarioOperation::Stream => self.config.max_payload_bytes,
            ScenarioOperation::Datagram => self
                .config
                .max_payload_bytes
                .min(MAX_GENERATED_DATAGRAM_PAYLOAD_BYTES),
        };
        let payload_bytes = stream
            .range_u64(1..payload_limit.saturating_add(1))
            .map_err(|error| ScenarioModelError::Generation(error.to_string()))?;
        if let ScenarioAction::StreamRoundTrip { payload, .. }
        | ScenarioAction::DatagramRoundTrip { payload, .. } = &mut scenario.actions[3].action
        {
            payload.bytes = payload_bytes;
            payload.fill = u8::try_from(
                stream
                    .range_u64(0..256)
                    .map_err(|error| ScenarioModelError::Generation(error.to_string()))?,
            )
            .expect("the generated fill byte is drawn from the u8 range");
        }
        let fault = stream
            .range_u64(0..3)
            .map_err(|error| ScenarioModelError::Generation(error.to_string()))?;
        if operation == ScenarioOperation::Stream && fault != 0 {
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
