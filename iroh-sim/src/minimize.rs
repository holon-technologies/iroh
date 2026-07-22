//! Deterministic signature-preserving minimization of canonical scenarios.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    ActionSchedule, CompletionPolicy, DiscoveryRecordState, FailureSignature,
    FirewallConnectionState, NatFilteringBehavior, NatMappingBehavior, Scenario, ScenarioAction,
    ScenarioModelError,
};

/// Hard attempt bound for one minimization invocation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizationConfig {
    pub max_attempts: u64,
}

impl Default for MinimizationConfig {
    fn default() -> Self {
        Self {
            max_attempts: 10_000,
        }
    }
}

/// Stable reason a candidate was retained or rejected.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MinimizationOutcome {
    Accepted,
    Invalid,
    Duplicate,
    NotSmaller,
    FailureDisappeared,
    DifferentSignature,
    EvaluatorError,
}

/// One ordered transformation record suitable for `minimize.jsonl`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizationAttempt {
    pub ordinal: u64,
    pub transformation: String,
    pub candidate_digest: String,
    pub canonical_bytes: u64,
    pub outcome: MinimizationOutcome,
    pub accepted: bool,
    pub detail: Option<String>,
}

/// Best known candidate and the complete deterministic attempt history.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizationResult {
    pub scenario: Scenario,
    pub signature: FailureSignature,
    pub original_bytes: u64,
    pub minimized_bytes: u64,
    pub exhausted: bool,
    pub attempts: Vec<MinimizationAttempt>,
}

/// Canonical reducer. Candidate execution is supplied by the caller.
#[derive(Clone, Copy, Debug)]
pub struct Minimizer {
    config: MinimizationConfig,
}

impl Minimizer {
    pub fn new(config: MinimizationConfig) -> Self {
        Self { config }
    }

    /// Reduces `scenario` while accepting only the exact expected signature.
    pub fn minimize<F>(
        &self,
        scenario: Scenario,
        expected: FailureSignature,
        evaluator: &mut F,
    ) -> Result<MinimizationResult, MinimizationError>
    where
        F: FnMut(&Scenario) -> Result<Option<FailureSignature>, String>,
    {
        self.minimize_with_observer(scenario, expected, evaluator, &mut |_attempt, _accepted| {
            Ok(())
        })
    }

    /// Reduces while durably observable attempt/progress callbacks run in attempt order.
    pub fn minimize_with_observer<F, O>(
        &self,
        scenario: Scenario,
        expected: FailureSignature,
        evaluator: &mut F,
        observer: &mut O,
    ) -> Result<MinimizationResult, MinimizationError>
    where
        F: FnMut(&Scenario) -> Result<Option<FailureSignature>, String>,
        O: FnMut(&MinimizationAttempt, Option<&Scenario>) -> Result<(), String>,
    {
        if self.config.max_attempts == 0 {
            return Err(MinimizationError::ZeroAttemptBudget);
        }
        let scenario = scenario.normalized().map_err(MinimizationError::Scenario)?;
        match evaluator(&scenario).map_err(MinimizationError::Evaluator)? {
            None => return Err(MinimizationError::InputDoesNotFail),
            Some(actual) if actual != expected => {
                return Err(MinimizationError::InputSignatureMismatch { expected, actual });
            }
            Some(_) => {}
        }
        let original_bytes = canonical_len(&scenario)?;
        let mut context = Context {
            best: scenario,
            expected: expected.clone(),
            config: self.config,
            attempts: Vec::new(),
            seen: BTreeSet::new(),
            evaluator,
            observer,
            exhausted: false,
        };
        context
            .seen
            .insert(canonical_digest(&context.best).map_err(MinimizationError::Scenario)?);

        context.reduce_metadata()?;
        context.ddmin_actions()?;
        context.ddmin_faults()?;
        context.ddmin_firewall_rules()?;
        context.remove_relay_impairments()?;
        context.remove_discovery_providers()?;
        context.remove_nats()?;
        context.remove_relays()?;
        context.remove_interfaces()?;
        context.remove_unused_endpoints()?;
        context.remove_unused_hosts()?;
        context.remove_unused_links()?;
        context.reduce_scalars()?;
        context.reduce_budgets()?;

        let minimized_bytes = canonical_len(&context.best)?;
        Ok(MinimizationResult {
            scenario: context.best,
            signature: expected,
            original_bytes,
            minimized_bytes,
            exhausted: context.exhausted,
            attempts: context.attempts,
        })
    }
}

type ProgressObserver<'a> =
    dyn FnMut(&MinimizationAttempt, Option<&Scenario>) -> Result<(), String> + 'a;

struct Context<'a, F> {
    best: Scenario,
    expected: FailureSignature,
    config: MinimizationConfig,
    attempts: Vec<MinimizationAttempt>,
    seen: BTreeSet<String>,
    evaluator: &'a mut F,
    observer: &'a mut ProgressObserver<'a>,
    exhausted: bool,
}

impl<F> Context<'_, F>
where
    F: FnMut(&Scenario) -> Result<Option<FailureSignature>, String>,
{
    fn reduce_metadata(&mut self) -> Result<(), MinimizationError> {
        let mut candidate = self.best.clone();
        candidate.metadata.description.clear();
        candidate.metadata.tags.clear();
        self.try_candidate("metadata/clear", candidate)?;
        Ok(())
    }

    fn ddmin_actions(&mut self) -> Result<(), MinimizationError> {
        let mut granularity = 2usize;
        loop {
            let len = self.best.actions.len();
            if len == 0 || self.exhausted {
                break;
            }
            let chunk = len.div_ceil(granularity);
            let mut accepted = false;
            let mut start = 0usize;
            while start < len && !self.exhausted {
                let end = (start + chunk).min(len);
                let mut candidate = self.best.clone();
                let removed = candidate.actions[start..end]
                    .iter()
                    .map(|action| action.id.as_str())
                    .collect::<Vec<_>>()
                    .join(",");
                candidate.actions.drain(start..end);
                if self.try_candidate(&format!("actions/delete/{removed}"), candidate)? {
                    granularity = granularity.saturating_sub(1).max(2);
                    accepted = true;
                    break;
                }
                start = end;
            }
            if accepted {
                continue;
            }
            if granularity >= len {
                break;
            }
            granularity = (granularity * 2).min(len);
        }
        Ok(())
    }

    fn ddmin_faults(&mut self) -> Result<(), MinimizationError> {
        let mut index = self.best.fault_rules.len();
        while index > 0 && !self.exhausted {
            index -= 1;
            let mut candidate = self.best.clone();
            let id = candidate.fault_rules[index].id.clone();
            candidate.fault_rules.remove(index);
            self.try_candidate(&format!("faults/delete/{id}"), candidate)?;
            index = index.min(self.best.fault_rules.len());
        }
        Ok(())
    }

    fn ddmin_firewall_rules(&mut self) -> Result<(), MinimizationError> {
        let mut nat_index = 0usize;
        while nat_index < self.best.topology.nats.len() && !self.exhausted {
            let mut rule_index = self.best.topology.nats[nat_index]
                .firewall
                .as_ref()
                .map_or(0, |firewall| firewall.rules.len());
            while rule_index > 0 && !self.exhausted {
                rule_index -= 1;
                let mut candidate = self.best.clone();
                let nat_id = candidate.topology.nats[nat_index].id.clone();
                let firewall = candidate.topology.nats[nat_index]
                    .firewall
                    .as_mut()
                    .expect("rule count came from firewall");
                let rule_id = firewall.rules[rule_index].id.clone();
                firewall.rules.remove(rule_index);
                self.try_candidate(
                    &format!("firewall-rules/delete/{nat_id}/{rule_id}"),
                    candidate,
                )?;
                rule_index = rule_index.min(
                    self.best.topology.nats[nat_index]
                        .firewall
                        .as_ref()
                        .map_or(0, |firewall| firewall.rules.len()),
                );
            }
            nat_index += 1;
        }
        Ok(())
    }

    fn remove_discovery_providers(&mut self) -> Result<(), MinimizationError> {
        let mut index = self.best.topology.discovery.len();
        while index > 0 && !self.exhausted {
            index -= 1;
            let mut candidate = self.best.clone();
            let id = candidate.topology.discovery[index].id.clone();
            candidate.topology.discovery.remove(index);
            self.try_candidate(&format!("discovery-providers/delete/{id}"), candidate)?;
            index = index.min(self.best.topology.discovery.len());
        }
        Ok(())
    }

    fn remove_nats(&mut self) -> Result<(), MinimizationError> {
        let mut index = self.best.topology.nats.len();
        while index > 0 && !self.exhausted {
            index -= 1;
            let mut candidate = self.best.clone();
            let id = candidate.topology.nats[index].id.clone();
            candidate.topology.nats.remove(index);
            self.try_candidate(&format!("nats/delete/{id}"), candidate)?;
            index = index.min(self.best.topology.nats.len());
        }
        Ok(())
    }

    fn remove_relays(&mut self) -> Result<(), MinimizationError> {
        let mut index = self.best.topology.relays.len();
        while index > 0 && !self.exhausted {
            index -= 1;
            let mut candidate = self.best.clone();
            let id = candidate.topology.relays[index].id.clone();
            candidate.topology.relays.remove(index);
            candidate
                .topology
                .relay_impairments
                .retain(|impairment| impairment.relay != id);
            candidate.actions.retain(|action| {
                !matches!(&action.action, ScenarioAction::RelayLifecycle { relay, .. } if relay == &id)
            });
            for endpoint in &mut candidate.endpoints {
                if endpoint.relay.as_deref() == Some(id.as_str()) && endpoint.direct {
                    endpoint.relay = None;
                }
            }
            if candidate.topology.relays.is_empty() {
                candidate.requirements.relay = false;
                candidate
                    .invariants
                    .retain(|invariant| invariant.name != crate::InvariantName::RelayRouting);
            }
            self.try_candidate(&format!("relays/delete/{id}"), candidate)?;
            index = index.min(self.best.topology.relays.len());
        }
        Ok(())
    }

    fn remove_relay_impairments(&mut self) -> Result<(), MinimizationError> {
        let mut index = self.best.topology.relay_impairments.len();
        while index > 0 && !self.exhausted {
            index -= 1;
            let mut candidate = self.best.clone();
            let relay = candidate.topology.relay_impairments[index].relay.clone();
            candidate.topology.relay_impairments.remove(index);
            self.try_candidate(&format!("relay-impairments/delete/{relay}"), candidate)?;
            index = index.min(self.best.topology.relay_impairments.len());
        }
        Ok(())
    }

    fn remove_interfaces(&mut self) -> Result<(), MinimizationError> {
        let mut host_index = 0usize;
        while host_index < self.best.topology.hosts.len() && !self.exhausted {
            let mut interface_index = self.best.topology.hosts[host_index].interfaces.len();
            while interface_index > 0 && !self.exhausted {
                interface_index -= 1;
                let mut candidate = self.best.clone();
                let host_id = candidate.topology.hosts[host_index].id.clone();
                let interface_id = candidate.topology.hosts[host_index].interfaces[interface_index]
                    .id
                    .clone();
                candidate.topology.hosts[host_index]
                    .interfaces
                    .remove(interface_index);
                self.try_candidate(
                    &format!("interfaces/delete/{host_id}/{interface_id}"),
                    candidate,
                )?;
                interface_index =
                    interface_index.min(self.best.topology.hosts[host_index].interfaces.len());
            }
            host_index += 1;
        }
        Ok(())
    }

    fn remove_unused_endpoints(&mut self) -> Result<(), MinimizationError> {
        let mut index = self.best.endpoints.len();
        while index > 0 && !self.exhausted {
            index -= 1;
            let mut candidate = self.best.clone();
            let id = candidate.endpoints[index].id.clone();
            candidate.endpoints.remove(index);
            self.try_candidate(&format!("endpoints/delete/{id}"), candidate)?;
            index = index.min(self.best.endpoints.len());
        }
        Ok(())
    }

    fn remove_unused_hosts(&mut self) -> Result<(), MinimizationError> {
        let mut index = self.best.topology.hosts.len();
        while index > 0 && !self.exhausted {
            index -= 1;
            let mut candidate = self.best.clone();
            let id = candidate.topology.hosts[index].id.clone();
            candidate.topology.hosts.remove(index);
            self.try_candidate(&format!("hosts/delete/{id}"), candidate)?;
            index = index.min(self.best.topology.hosts.len());
        }
        Ok(())
    }

    fn remove_unused_links(&mut self) -> Result<(), MinimizationError> {
        let mut index = self.best.topology.links.len();
        while index > 0 && !self.exhausted {
            index -= 1;
            let mut candidate = self.best.clone();
            let id = candidate.topology.links[index].id.clone();
            candidate.topology.links.remove(index);
            self.try_candidate(&format!("links/delete/{id}"), candidate)?;
            index = index.min(self.best.topology.links.len());
        }
        Ok(())
    }

    fn reduce_scalars(&mut self) -> Result<(), MinimizationError> {
        for index in 0..self.best.actions.len() {
            if self.exhausted {
                return Ok(());
            }
            let mut candidate = self.best.clone();
            let id = candidate.actions[index].id.clone();
            let changed = match &mut candidate.actions[index].action {
                ScenarioAction::StreamRoundTrip { payload, .. }
                | ScenarioAction::DatagramRoundTrip { payload, .. } => {
                    let changed = payload.bytes != 1 || payload.fill != 0;
                    payload.bytes = 1;
                    payload.fill = 0;
                    changed
                }
                ScenarioAction::AdvanceTime { by_nanos } => {
                    let changed = *by_nanos != 1;
                    *by_nanos = 1;
                    changed
                }
                ScenarioAction::SetLink {
                    latency_nanos, mtu, ..
                } => {
                    let changed = *latency_nanos != Some(0) || *mtu != Some(1);
                    *latency_nanos = Some(0);
                    *mtu = Some(1);
                    changed
                }
                ScenarioAction::NatChange { preserve_ports, .. } => {
                    let changed = *preserve_ports;
                    *preserve_ports = false;
                    changed
                }
                ScenarioAction::DiscoveryUpdate {
                    addresses,
                    delay_nanos,
                    ttl_nanos,
                    state,
                    ..
                } => {
                    let mut changed = *delay_nanos != 0;
                    *delay_nanos = 0;
                    match state {
                        DiscoveryRecordState::Published => {
                            changed |= addresses.len() > 1 || *ttl_nanos != 1;
                            addresses.truncate(1);
                            *ttl_nanos = 1;
                        }
                        DiscoveryRecordState::Failed => {
                            changed |= *ttl_nanos != 1;
                            *ttl_nanos = 1;
                        }
                        DiscoveryRecordState::Withdrawn => {}
                    }
                    changed
                }
                ScenarioAction::RouteChange { next_hop, .. } => next_hop.take().is_some(),
                _ => false,
            };
            if changed {
                self.try_candidate(&format!("action/scalar/{id}"), candidate)?;
            }
        }
        for index in 0..self.best.actions.len() {
            let mut candidate = self.best.clone();
            let id = candidate.actions[index].id.clone();
            let changed = match &mut candidate.actions[index].schedule {
                ActionSchedule::At { nanos } => {
                    let changed = *nanos != 0;
                    *nanos = 0;
                    changed
                }
                _ => false,
            };
            if changed {
                self.try_candidate(&format!("schedule/zero/{id}"), candidate)?;
            }
        }
        for index in 0..self.best.fault_rules.len() {
            let mut candidate = self.best.clone();
            let id = candidate.fault_rules[index].id.clone();
            let rule = &mut candidate.fault_rules[index];
            rule.probability_per_million = 0;
            rule.end_nanos = rule.start_nanos;
            rule.max_applications = 1;
            self.try_candidate(&format!("fault/scalar/{id}"), candidate)?;
        }
        for index in 0..self.best.topology.links.len() {
            let mut candidate = self.best.clone();
            let id = candidate.topology.links[index].id.clone();
            let link = &mut candidate.topology.links[index];
            link.latency_nanos = 0;
            link.bits_per_second = 1;
            link.mtu = 1;
            link.queue_packets = 1;
            self.try_candidate(&format!("link/scalar/{id}"), candidate)?;
        }
        for index in 0..self.best.topology.nats.len() {
            let mut candidate = self.best.clone();
            let id = candidate.topology.nats[index].id.clone();
            let nat = &mut candidate.topology.nats[index];
            nat.port_end = nat.port_start;
            nat.mapping_behavior = NatMappingBehavior::EndpointIndependent;
            nat.filtering_behavior = NatFilteringBehavior::EndpointIndependent;
            nat.mapping_ttl_nanos = 1;
            nat.hairpin = false;
            nat.max_mappings = 1;
            self.try_candidate(&format!("nat/scalar/{id}"), candidate)?;

            if self.best.topology.nats[index].firewall.is_some() {
                let mut candidate = self.best.clone();
                let firewall = candidate.topology.nats[index]
                    .firewall
                    .as_mut()
                    .expect("checked firewall presence");
                for rule in &mut firewall.rules {
                    rule.source = None;
                    rule.destination = None;
                    rule.source_ports = None;
                    rule.destination_ports = None;
                    rule.connection_state = FirewallConnectionState::Any;
                }
                self.try_candidate(&format!("firewall/scalar/{id}"), candidate)?;
            }
        }
        for index in 0..self.best.topology.discovery.len() {
            let mut candidate = self.best.clone();
            let id = candidate.topology.discovery[index].id.clone();
            candidate.topology.discovery[index].max_records = 1;
            self.try_candidate(&format!("discovery-provider/scalar/{id}"), candidate)?;
        }
        for index in 0..self.best.topology.relays.len() {
            let mut candidate = self.best.clone();
            let id = candidate.topology.relays[index].id.clone();
            let relay = &mut candidate.topology.relays[index];
            relay.max_sessions = 1;
            relay.byte_capacity = 1;
            relay.protocol_version = crate::RelayProtocolVersion::V1;
            self.try_candidate(&format!("relay/scalar/{id}"), candidate)?;
        }
        for index in 0..self.best.topology.relay_impairments.len() {
            let relay = self.best.topology.relay_impairments[index].relay.clone();

            let mut candidate = self.best.clone();
            candidate.topology.relay_impairments[index].connection_delay_nanos = 0;
            self.try_candidate(&format!("relay-impairment/delay/{relay}"), candidate)?;

            let mut candidate = self.best.clone();
            candidate.topology.relay_impairments[index]
                .reject_connect_attempts
                .truncate(1);
            self.try_candidate(&format!("relay-impairment/rejections/{relay}"), candidate)?;

            if self.best.topology.relay_impairments[index]
                .drop_every_nth_packet
                .is_some()
            {
                let mut candidate = self.best.clone();
                candidate.topology.relay_impairments[index].drop_every_nth_packet = Some(1);
                self.try_candidate(&format!("relay-impairment/drop/{relay}"), candidate)?;
            }

            if self.best.topology.relay_impairments[index]
                .client_rx_bytes_per_second
                .is_some()
            {
                let mut candidate = self.best.clone();
                let impairment = &mut candidate.topology.relay_impairments[index];
                impairment.client_rx_bytes_per_second = Some(1);
                impairment.client_rx_max_burst_bytes = None;
                self.try_candidate(&format!("relay-impairment/rate/{relay}"), candidate)?;
            }
        }
        for host_index in 0..self.best.topology.hosts.len() {
            for interface_index in 0..self.best.topology.hosts[host_index].interfaces.len() {
                let mut candidate = self.best.clone();
                let host = candidate.topology.hosts[host_index].id.clone();
                let interface =
                    &mut candidate.topology.hosts[host_index].interfaces[interface_index];
                let id = interface.id.clone();
                interface.addresses.truncate(1);
                self.try_candidate(&format!("interface/scalar/{host}/{id}"), candidate)?;
            }
        }
        for index in 0..self.best.endpoints.len() {
            let mut candidate = self.best.clone();
            let id = candidate.endpoints[index].id.clone();
            candidate.endpoints[index].identity_ordinal = 0;
            self.try_candidate(&format!("endpoint/ordinal/{id}"), candidate)?;
        }
        let mut candidate = self.best.clone();
        match &mut candidate.completion {
            CompletionPolicy::AllActions {
                shutdown_deadline_nanos,
            }
            | CompletionPolicy::Observation {
                shutdown_deadline_nanos,
                ..
            } => *shutdown_deadline_nanos = 1,
        }
        self.try_candidate("completion/deadline", candidate)?;
        Ok(())
    }

    fn reduce_budgets(&mut self) -> Result<(), MinimizationError> {
        let mut candidate = self.best.clone();
        candidate.budgets.max_actions = candidate.actions.len().max(1) as u64;
        candidate.budgets.max_payload_bytes = candidate
            .actions
            .iter()
            .filter_map(|action| match &action.action {
                ScenarioAction::StreamRoundTrip { payload, .. }
                | ScenarioAction::DatagramRoundTrip { payload, .. } => Some(payload.bytes),
                _ => None,
            })
            .max()
            .unwrap_or(1);
        self.try_candidate("budgets/tighten-representation", candidate)?;
        Ok(())
    }

    fn try_candidate(
        &mut self,
        transformation: &str,
        candidate: Scenario,
    ) -> Result<bool, MinimizationError> {
        if self.attempts.len() as u64 >= self.config.max_attempts {
            self.exhausted = true;
            return Ok(false);
        }
        let ordinal = self.attempts.len() as u64 + 1;
        let normalized = match candidate.normalized() {
            Ok(value) => value,
            Err(error) => {
                self.attempts.push(MinimizationAttempt {
                    ordinal,
                    transformation: transformation.to_owned(),
                    candidate_digest: blake3::hash(error.to_string().as_bytes())
                        .to_hex()
                        .to_string(),
                    canonical_bytes: 0,
                    outcome: MinimizationOutcome::Invalid,
                    accepted: false,
                    detail: Some(error.to_string()),
                });
                (self.observer)(self.attempts.last().expect("attempt was pushed"), None)
                    .map_err(MinimizationError::Progress)?;
                return Ok(false);
            }
        };
        let bytes = normalized
            .to_canonical_json()
            .map_err(MinimizationError::Scenario)?;
        let digest = blake3::hash(&bytes).to_hex().to_string();
        let canonical_bytes = bytes.len() as u64;
        let best_bytes = canonical_len(&self.best)?;
        let (outcome, detail, accepted) = if !self.seen.insert(digest.clone()) {
            (MinimizationOutcome::Duplicate, None, false)
        } else if canonical_bytes >= best_bytes {
            (MinimizationOutcome::NotSmaller, None, false)
        } else {
            match (self.evaluator)(&normalized) {
                Ok(Some(signature)) if signature == self.expected => {
                    (MinimizationOutcome::Accepted, None, true)
                }
                Ok(Some(signature)) => (
                    MinimizationOutcome::DifferentSignature,
                    Some(signature.causal_suffix_digest),
                    false,
                ),
                Ok(None) => (MinimizationOutcome::FailureDisappeared, None, false),
                Err(error) => (MinimizationOutcome::EvaluatorError, Some(error), false),
            }
        };
        self.attempts.push(MinimizationAttempt {
            ordinal,
            transformation: transformation.to_owned(),
            candidate_digest: digest,
            canonical_bytes,
            outcome,
            accepted,
            detail,
        });
        if accepted {
            self.best = normalized;
        }
        (self.observer)(
            self.attempts.last().expect("attempt was pushed"),
            accepted.then_some(&self.best),
        )
        .map_err(MinimizationError::Progress)?;
        Ok(accepted)
    }
}

fn canonical_len(scenario: &Scenario) -> Result<u64, MinimizationError> {
    u64::try_from(
        scenario
            .to_canonical_json()
            .map_err(MinimizationError::Scenario)?
            .len(),
    )
    .map_err(|_| MinimizationError::SizeOverflow)
}

fn canonical_digest(scenario: &Scenario) -> Result<String, ScenarioModelError> {
    Ok(blake3::hash(&scenario.to_canonical_json()?)
        .to_hex()
        .to_string())
}

/// Input, evaluation, or bound failure before a best result can be returned.
#[derive(Debug)]
pub enum MinimizationError {
    ZeroAttemptBudget,
    InputDoesNotFail,
    InputSignatureMismatch {
        expected: FailureSignature,
        actual: FailureSignature,
    },
    Evaluator(String),
    Progress(String),
    Scenario(ScenarioModelError),
    SizeOverflow,
}

impl fmt::Display for MinimizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroAttemptBudget => f.write_str("minimizer attempt budget must be nonzero"),
            Self::InputDoesNotFail => f.write_str("minimizer input does not fail"),
            Self::InputSignatureMismatch { .. } => {
                f.write_str("minimizer input has a different failure signature")
            }
            Self::Evaluator(error) => write!(f, "minimizer evaluator failed: {error}"),
            Self::Progress(error) => write!(f, "minimizer progress write failed: {error}"),
            Self::Scenario(error) => error.fmt(f),
            Self::SizeOverflow => f.write_str("canonical scenario size overflow"),
        }
    }
}

impl std::error::Error for MinimizationError {}
