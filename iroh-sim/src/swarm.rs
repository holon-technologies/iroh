//! Strict bounded swarm templates and deterministic scenario materialization.

use std::{collections::BTreeSet, fmt};

use iroh_runtime::{DecisionSource, RootSeed, SeededDecisionSource};
use serde::{Deserialize, Serialize};

use crate::{
    ActionSchedule, DiscoveryRecordState, FairnessAssumption, InvariantName, NatFilteringBehavior,
    NatMappingBehavior, RelayImpairmentSpec, Scenario, ScenarioAction, ScenarioModelError,
};

/// Current independently versioned swarm schema.
pub const SWARM_SCHEMA_VERSION: u16 = 1;
const MAX_CHOICES: usize = 128;
const MAX_OPTIONS_PER_CHOICE: usize = 128;
const MAX_TOTAL_WEIGHT: u64 = 1_000_000;
const MAX_COSCHEDULED_ACTIONS: usize = 128;
const MAX_RELAY_CONNECTION_DELAY_NANOS: u64 = 60_000_000_000;
const MAX_BASE_PATH_BYTES: usize = 1_024;

/// A bounded set of independent weighted choices over one canonical base scenario.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmSpec {
    pub schema_version: u16,
    pub id: String,
    pub base: Scenario,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safety_liveness: Option<SafetyLivenessPhases>,
    pub choices: Vec<SwarmChoice>,
}

/// A compact swarm template bound to a canonical workspace-relative scenario.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReferencedSwarmSpec {
    pub schema_version: u16,
    pub id: String,
    pub base_path: String,
    pub base_blake3: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safety_liveness: Option<SafetyLivenessPhases>,
    pub choices: Vec<SwarmChoice>,
}

/// Either a self-contained swarm or a digest-bound referenced template.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum SwarmTemplate {
    Embedded(Box<SwarmSpec>),
    Referenced(ReferencedSwarmSpec),
}

/// An explicit adversarial-safety to recovery-and-liveness transition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyLivenessPhases {
    /// The action after which the environment is intentionally unavailable.
    pub safety_action: String,
    /// The matching recovery action that begins the fair liveness phase.
    pub recovery_action: String,
    /// A connect action ordered after recovery and covered by the liveness invariant.
    pub liveness_probe_action: String,
}

/// One named materialization dimension.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmChoice {
    pub id: String,
    pub options: Vec<SwarmOption>,
}

/// One weighted mutation within a choice.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmOption {
    pub id: String,
    pub weight: u32,
    pub mutation: SwarmMutation,
}

/// Bounded mutations supported by swarm schema v1.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SwarmMutation {
    PayloadBytes {
        action: String,
        bytes: u64,
    },
    LinkLatencyNanos {
        link: String,
        nanos: u64,
    },
    LinkMtu {
        link: String,
        mtu: usize,
    },
    FaultProbabilityPerMillion {
        rule: String,
        probability: u32,
    },
    RelayOnline {
        relay: String,
        online: bool,
    },
    NatBehavior {
        nat: String,
        mapping: NatMappingBehavior,
        filtering: NatFilteringBehavior,
    },
    DiscoveryTiming {
        action: String,
        delay_nanos: u64,
        ttl_nanos: u64,
        state: DiscoveryRecordState,
    },
    ActionAtNanos {
        action: String,
        nanos: u64,
    },
    RelayImpairment {
        relay: String,
        connection_delay_nanos: u64,
        drop_every_nth_packet: Option<u64>,
    },
    CoSchedule {
        actions: Vec<String>,
        nanos: u64,
    },
}

/// Every choice made while producing a scenario.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmSelection {
    pub schema_version: u16,
    pub swarm_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safety_liveness: Option<SafetyLivenessPhases>,
    pub choices: Vec<SwarmSelectedChoice>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmSelectedChoice {
    pub choice_id: String,
    pub option_id: String,
}

impl SwarmSpec {
    pub fn from_json(bytes: &[u8]) -> Result<Self, SwarmError> {
        let spec: Self =
            serde_json::from_slice(bytes).map_err(|error| SwarmError::Json(error.to_string()))?;
        spec.validate()?;
        Ok(spec)
    }

    pub fn to_canonical_json(&self) -> Result<Vec<u8>, SwarmError> {
        self.validate()?;
        let mut bytes =
            serde_json::to_vec_pretty(self).map_err(|error| SwarmError::Json(error.to_string()))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn validate(&self) -> Result<(), SwarmError> {
        if self.schema_version != SWARM_SCHEMA_VERSION {
            return Err(SwarmError::UnsupportedSchema(self.schema_version));
        }
        validate_id(&self.id)?;
        if self.choices.is_empty() || self.choices.len() > MAX_CHOICES {
            return Err(SwarmError::InvalidBounds);
        }
        if self
            .base
            .clone()
            .normalized()
            .map_err(SwarmError::Scenario)?
            != self.base
        {
            return Err(SwarmError::NonCanonical);
        }
        if let Some(phases) = &self.safety_liveness {
            validate_safety_liveness(&self.base, phases)?;
        }
        let mut previous_choice = None;
        for choice in &self.choices {
            validate_id(&choice.id)?;
            if previous_choice.is_some_and(|previous| previous >= choice.id.as_str())
                || choice.options.is_empty()
                || choice.options.len() > MAX_OPTIONS_PER_CHOICE
            {
                return Err(SwarmError::NonCanonical);
            }
            previous_choice = Some(choice.id.as_str());
            let mut previous_option = None;
            let mut total_weight = 0u64;
            for option in &choice.options {
                validate_id(&option.id)?;
                if previous_option.is_some_and(|previous| previous >= option.id.as_str())
                    || option.weight == 0
                {
                    return Err(SwarmError::NonCanonical);
                }
                previous_option = Some(option.id.as_str());
                total_weight = total_weight
                    .checked_add(u64::from(option.weight))
                    .ok_or(SwarmError::InvalidBounds)?;
                validate_mutation(&self.base, &option.mutation)?;
            }
            if total_weight > MAX_TOTAL_WEIGHT {
                return Err(SwarmError::InvalidBounds);
            }
        }
        Ok(())
    }

    /// Materializes a scenario from a seed used only for swarm selection.
    pub fn materialize(
        &self,
        materialization_seed: RootSeed,
    ) -> Result<(Scenario, SwarmSelection), SwarmError> {
        self.validate()?;
        let source = SeededDecisionSource::new(materialization_seed);
        let mut scenario = self.base.clone();
        let mut selected = Vec::with_capacity(self.choices.len());
        for choice in &self.choices {
            let mut stream = source
                .stream(&format!("swarm/{}/choice/{}", self.id, choice.id))
                .map_err(|error| SwarmError::Decision(error.to_string()))?;
            let total = choice
                .options
                .iter()
                .map(|item| u64::from(item.weight))
                .sum();
            let draw = stream
                .range_u64(0..total)
                .map_err(|error| SwarmError::Decision(error.to_string()))?;
            let mut cursor = 0u64;
            let option = choice
                .options
                .iter()
                .find(|option| {
                    cursor += u64::from(option.weight);
                    draw < cursor
                })
                .expect("validated positive weights cover the draw range");
            apply_mutation(&mut scenario, &option.mutation)?;
            selected.push(SwarmSelectedChoice {
                choice_id: choice.id.clone(),
                option_id: option.id.clone(),
            });
        }
        scenario.metadata.id = format!("{}/materialized", self.base.metadata.id);
        scenario.metadata.tags.push(format!("swarm-{}", self.id));
        if self.safety_liveness.is_some() {
            scenario.metadata.tags.push("safety-liveness".to_owned());
        }
        let scenario = scenario.normalized().map_err(SwarmError::Scenario)?;
        Ok((
            scenario,
            SwarmSelection {
                schema_version: SWARM_SCHEMA_VERSION,
                swarm_id: self.id.clone(),
                safety_liveness: self.safety_liveness.clone(),
                choices: selected,
            },
        ))
    }
}

impl SafetyLivenessPhases {
    fn validate_identity(&self) -> Result<(), SwarmError> {
        validate_id(&self.safety_action)?;
        validate_id(&self.recovery_action)?;
        validate_id(&self.liveness_probe_action)?;
        if self.safety_action == self.recovery_action
            || self.safety_action == self.liveness_probe_action
            || self.recovery_action == self.liveness_probe_action
        {
            return Err(SwarmError::InvalidSafetyLiveness);
        }
        Ok(())
    }
}

fn validate_safety_liveness(
    base: &Scenario,
    phases: &SafetyLivenessPhases,
) -> Result<(), SwarmError> {
    phases.validate_identity()?;
    let safety = find_action(base, &phases.safety_action)?;
    let recovery = find_action(base, &phases.recovery_action)?;
    let probe = find_action(base, &phases.liveness_probe_action)?;
    if !matching_recovery(&safety.action, &recovery.action)
        || !action_depends_on(base, &phases.recovery_action, &phases.safety_action)
        || !matches!(probe.action, ScenarioAction::Connect { .. })
        || !action_depends_on(base, &phases.liveness_probe_action, &phases.recovery_action)
    {
        return Err(SwarmError::InvalidSafetyLiveness);
    }
    let fairness_is_explicit = [
        FairnessAssumption::FifoProgress,
        FairnessAssumption::ReachableNetwork,
    ]
    .into_iter()
    .all(|assumption| base.fairness.contains(&assumption));
    let bounded_liveness_is_enabled = base.invariants.iter().any(|invariant| {
        invariant.name == InvariantName::ReachableConnectLiveness
            && invariant.deadline_nanos.is_some()
            && invariant.max_events.is_some()
    });
    let safety_is_enabled = base.invariants.iter().any(|invariant| {
        matches!(
            invariant.name,
            InvariantName::AuthenticationIdentity
                | InvariantName::DeliveryIntegrity
                | InvariantName::DeliveryOrdering
                | InvariantName::MonotonicLifecycle
                | InvariantName::ResourceCeiling
                | InvariantName::RelayRouting
        )
    });
    if !fairness_is_explicit || !bounded_liveness_is_enabled || !safety_is_enabled {
        return Err(SwarmError::InvalidSafetyLiveness);
    }
    Ok(())
}

fn find_action<'a>(base: &'a Scenario, id: &str) -> Result<&'a crate::ActionSpec, SwarmError> {
    base.actions
        .iter()
        .find(|action| action.id == id)
        .ok_or_else(|| SwarmError::Dangling(id.to_owned()))
}

fn action_depends_on(base: &Scenario, action: &str, prerequisite: &str) -> bool {
    let mut current = action;
    for _ in 0..base.actions.len() {
        let Ok(spec) = find_action(base, current) else {
            return false;
        };
        let ActionSchedule::AfterAction { action: parent } = &spec.schedule else {
            return false;
        };
        if parent == prerequisite {
            return true;
        }
        current = parent;
    }
    false
}

fn matching_recovery(safety: &ScenarioAction, recovery: &ScenarioAction) -> bool {
    match (safety, recovery) {
        (
            ScenarioAction::Partition { link, from, to },
            ScenarioAction::Heal {
                link: recovered_link,
                from: recovered_from,
                to: recovered_to,
            },
        ) => link == recovered_link && from == recovered_from && to == recovered_to,
        (
            ScenarioAction::RelayLifecycle {
                relay,
                online: false,
            },
            ScenarioAction::RelayLifecycle {
                relay: recovered_relay,
                online: true,
            },
        ) => relay == recovered_relay,
        (
            ScenarioAction::InterfaceChange {
                host,
                interface,
                up: false,
            },
            ScenarioAction::InterfaceChange {
                host: recovered_host,
                interface: recovered_interface,
                up: true,
            },
        ) => host == recovered_host && interface == recovered_interface,
        (
            ScenarioAction::HostSleep {
                host,
                sleeping: true,
            },
            ScenarioAction::HostSleep {
                host: recovered_host,
                sleeping: false,
            },
        ) => host == recovered_host,
        (
            ScenarioAction::AddressChange {
                host,
                interface,
                address,
                present: false,
            },
            ScenarioAction::AddressChange {
                host: recovered_host,
                interface: recovered_interface,
                address: recovered_address,
                present: true,
            },
        ) => {
            host == recovered_host
                && interface == recovered_interface
                && address == recovered_address
        }
        (
            ScenarioAction::RouteChange {
                host,
                route,
                active: false,
                ..
            },
            ScenarioAction::RouteChange {
                host: recovered_host,
                route: recovered_route,
                active: true,
                ..
            },
        ) => host == recovered_host && route == recovered_route,
        _ => false,
    }
}

impl ReferencedSwarmSpec {
    /// Validates the source identity and bounded choice structure.
    pub fn validate(&self) -> Result<(), SwarmError> {
        if self.schema_version != SWARM_SCHEMA_VERSION {
            return Err(SwarmError::UnsupportedSchema(self.schema_version));
        }
        validate_id(&self.id)?;
        validate_base_path(&self.base_path)?;
        validate_digest(&self.base_blake3)?;
        if let Some(phases) = &self.safety_liveness {
            phases.validate_identity()?;
        }
        validate_choice_structure(&self.choices)
    }

    /// Returns stable pretty JSON after validating the reference.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, SwarmError> {
        self.validate()?;
        let mut bytes =
            serde_json::to_vec_pretty(self).map_err(|error| SwarmError::Json(error.to_string()))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Resolves the reference from caller-supplied bytes after verifying identity and form.
    pub fn resolve(&self, base_bytes: &[u8]) -> Result<SwarmSpec, SwarmError> {
        self.validate()?;
        let observed = blake3::hash(base_bytes).to_hex().to_string();
        if observed != self.base_blake3 {
            return Err(SwarmError::BaseDigestMismatch);
        }
        let base = Scenario::from_json(base_bytes).map_err(SwarmError::Scenario)?;
        let spec = SwarmSpec {
            schema_version: self.schema_version,
            id: self.id.clone(),
            base,
            safety_liveness: self.safety_liveness.clone(),
            choices: self.choices.clone(),
        };
        spec.validate()?;
        Ok(spec)
    }
}

impl SwarmTemplate {
    /// Strictly parses either supported template representation.
    pub fn from_json(bytes: &[u8]) -> Result<Self, SwarmError> {
        let template: Self =
            serde_json::from_slice(bytes).map_err(|error| SwarmError::Json(error.to_string()))?;
        match &template {
            Self::Embedded(spec) => spec.validate()?,
            Self::Referenced(spec) => spec.validate()?,
        }
        Ok(template)
    }

    /// Returns the referenced base path, if this is a compact template.
    pub fn base_path(&self) -> Option<&str> {
        match self {
            Self::Embedded(_) => None,
            Self::Referenced(spec) => Some(&spec.base_path),
        }
    }

    /// Resolves to the self-contained execution form.
    pub fn resolve(&self, base_bytes: &[u8]) -> Result<SwarmSpec, SwarmError> {
        match self {
            Self::Embedded(spec) => Ok(spec.as_ref().clone()),
            Self::Referenced(spec) => spec.resolve(base_bytes),
        }
    }
}

fn validate_choice_structure(choices: &[SwarmChoice]) -> Result<(), SwarmError> {
    if choices.is_empty() || choices.len() > MAX_CHOICES {
        return Err(SwarmError::InvalidBounds);
    }
    let mut previous_choice = None;
    for choice in choices {
        validate_id(&choice.id)?;
        if previous_choice.is_some_and(|previous| previous >= choice.id.as_str())
            || choice.options.is_empty()
            || choice.options.len() > MAX_OPTIONS_PER_CHOICE
        {
            return Err(SwarmError::NonCanonical);
        }
        previous_choice = Some(choice.id.as_str());
        let mut previous_option = None;
        let mut total_weight = 0u64;
        for option in &choice.options {
            validate_id(&option.id)?;
            if previous_option.is_some_and(|previous| previous >= option.id.as_str())
                || option.weight == 0
            {
                return Err(SwarmError::NonCanonical);
            }
            previous_option = Some(option.id.as_str());
            total_weight = total_weight
                .checked_add(u64::from(option.weight))
                .ok_or(SwarmError::InvalidBounds)?;
        }
        if total_weight > MAX_TOTAL_WEIGHT {
            return Err(SwarmError::InvalidBounds);
        }
    }
    Ok(())
}

fn validate_base_path(value: &str) -> Result<(), SwarmError> {
    let valid_bytes = !value.is_empty()
        && value.len() <= MAX_BASE_PATH_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'));
    let segments_are_normal = value
        .split('/')
        .all(|segment| !segment.is_empty() && !matches!(segment, "." | ".."));
    let is_workspace_scenario = value.starts_with("iroh-sim/") && value.ends_with(".json");
    (valid_bytes && segments_are_normal && is_workspace_scenario)
        .then_some(())
        .ok_or(SwarmError::InvalidBasePath)
}

fn validate_digest(value: &str) -> Result<(), SwarmError> {
    (value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some(())
    .ok_or(SwarmError::InvalidDigest)
}

fn validate_mutation(base: &Scenario, mutation: &SwarmMutation) -> Result<(), SwarmError> {
    match mutation {
        SwarmMutation::PayloadBytes { action, bytes } => {
            if *bytes == 0 || *bytes > base.budgets.max_payload_bytes {
                return Err(SwarmError::InvalidBounds);
            }
            let found = base.actions.iter().any(|item| {
                item.id == *action
                    && matches!(
                        item.action,
                        ScenarioAction::StreamRoundTrip { .. }
                            | ScenarioAction::DatagramRoundTrip { .. }
                    )
            });
            found
                .then_some(())
                .ok_or_else(|| SwarmError::Dangling(action.clone()))
        }
        SwarmMutation::LinkLatencyNanos { link, nanos } => {
            if *nanos > base.budgets.max_virtual_time_nanos {
                return Err(SwarmError::InvalidBounds);
            }
            base.topology
                .links
                .iter()
                .any(|item| item.id == *link)
                .then_some(())
                .ok_or_else(|| SwarmError::Dangling(link.clone()))
        }
        SwarmMutation::LinkMtu { link, mtu } => {
            if !(576..=65_535).contains(mtu) {
                return Err(SwarmError::InvalidBounds);
            }
            base.topology
                .links
                .iter()
                .any(|item| item.id == *link)
                .then_some(())
                .ok_or_else(|| SwarmError::Dangling(link.clone()))
        }
        SwarmMutation::FaultProbabilityPerMillion { rule, probability } => {
            if *probability > 1_000_000 {
                return Err(SwarmError::InvalidBounds);
            }
            base.fault_rules
                .iter()
                .any(|item| item.id == *rule)
                .then_some(())
                .ok_or_else(|| SwarmError::Dangling(rule.clone()))
        }
        SwarmMutation::RelayOnline { relay, .. } => base
            .topology
            .relays
            .iter()
            .any(|item| item.id == *relay)
            .then_some(())
            .ok_or_else(|| SwarmError::Dangling(relay.clone())),
        SwarmMutation::NatBehavior { nat, .. } => base
            .topology
            .nats
            .iter()
            .any(|item| item.id == *nat)
            .then_some(())
            .ok_or_else(|| SwarmError::Dangling(nat.clone())),
        SwarmMutation::DiscoveryTiming {
            action,
            delay_nanos,
            ttl_nanos,
            state,
        } => {
            if *delay_nanos > base.budgets.max_virtual_time_nanos
                || *ttl_nanos > base.budgets.max_virtual_time_nanos
            {
                return Err(SwarmError::InvalidBounds);
            }
            let item = base
                .actions
                .iter()
                .find(|item| item.id == *action)
                .ok_or_else(|| SwarmError::Dangling(action.clone()))?;
            let ScenarioAction::DiscoveryUpdate { addresses, .. } = &item.action else {
                return Err(SwarmError::Dangling(action.clone()));
            };
            let valid_state = match state {
                DiscoveryRecordState::Published => !addresses.is_empty() && *ttl_nanos > 0,
                DiscoveryRecordState::Failed => addresses.is_empty() && *ttl_nanos > 0,
                DiscoveryRecordState::Withdrawn => {
                    addresses.is_empty() && *delay_nanos == 0 && *ttl_nanos == 0
                }
            };
            valid_state.then_some(()).ok_or(SwarmError::InvalidBounds)
        }
        SwarmMutation::ActionAtNanos { action, nanos } => {
            if *nanos > base.budgets.max_virtual_time_nanos {
                return Err(SwarmError::InvalidBounds);
            }
            base.actions
                .iter()
                .any(|item| item.id == *action)
                .then_some(())
                .ok_or_else(|| SwarmError::Dangling(action.clone()))
        }
        SwarmMutation::RelayImpairment {
            relay,
            connection_delay_nanos,
            drop_every_nth_packet,
        } => {
            if *connection_delay_nanos > MAX_RELAY_CONNECTION_DELAY_NANOS
                || *drop_every_nth_packet == Some(0)
            {
                return Err(SwarmError::InvalidBounds);
            }
            base.topology
                .relays
                .iter()
                .any(|item| item.id == *relay)
                .then_some(())
                .ok_or_else(|| SwarmError::Dangling(relay.clone()))
        }
        SwarmMutation::CoSchedule { actions, nanos } => {
            if actions.is_empty()
                || actions.len() > MAX_COSCHEDULED_ACTIONS
                || *nanos > base.budgets.max_virtual_time_nanos
            {
                return Err(SwarmError::InvalidBounds);
            }
            let unique: BTreeSet<&str> = actions.iter().map(String::as_str).collect();
            if unique.len() != actions.len() || !actions.windows(2).all(|pair| pair[0] < pair[1]) {
                return Err(SwarmError::NonCanonical);
            }
            actions.iter().try_for_each(|action| {
                base.actions
                    .iter()
                    .any(|item| item.id == *action)
                    .then_some(())
                    .ok_or_else(|| SwarmError::Dangling(action.clone()))
            })
        }
    }
}

fn apply_mutation(scenario: &mut Scenario, mutation: &SwarmMutation) -> Result<(), SwarmError> {
    validate_mutation(scenario, mutation)?;
    match mutation {
        SwarmMutation::PayloadBytes { action, bytes } => {
            let item = scenario
                .actions
                .iter_mut()
                .find(|item| item.id == *action)
                .unwrap();
            match &mut item.action {
                ScenarioAction::StreamRoundTrip { payload, .. }
                | ScenarioAction::DatagramRoundTrip { payload, .. } => payload.bytes = *bytes,
                _ => unreachable!("validated payload action"),
            }
        }
        SwarmMutation::LinkLatencyNanos { link, nanos } => {
            scenario
                .topology
                .links
                .iter_mut()
                .find(|item| item.id == *link)
                .unwrap()
                .latency_nanos = *nanos;
        }
        SwarmMutation::LinkMtu { link, mtu } => {
            scenario
                .topology
                .links
                .iter_mut()
                .find(|item| item.id == *link)
                .unwrap()
                .mtu = *mtu;
        }
        SwarmMutation::FaultProbabilityPerMillion { rule, probability } => {
            scenario
                .fault_rules
                .iter_mut()
                .find(|item| item.id == *rule)
                .unwrap()
                .probability_per_million = *probability;
        }
        SwarmMutation::RelayOnline { relay, online } => {
            scenario
                .topology
                .relays
                .iter_mut()
                .find(|item| item.id == *relay)
                .expect("validated relay-online mutation must reference an existing relay")
                .online = *online;
        }
        SwarmMutation::NatBehavior {
            nat,
            mapping,
            filtering,
        } => {
            let item = scenario
                .topology
                .nats
                .iter_mut()
                .find(|item| item.id == *nat)
                .expect("validated NAT-behavior mutation must reference an existing NAT");
            item.mapping_behavior = *mapping;
            item.filtering_behavior = *filtering;
        }
        SwarmMutation::DiscoveryTiming {
            action,
            delay_nanos,
            ttl_nanos,
            state,
        } => {
            let item = scenario
                .actions
                .iter_mut()
                .find(|item| item.id == *action)
                .expect("validated discovery mutation must reference an existing action");
            let ScenarioAction::DiscoveryUpdate {
                delay_nanos: current_delay,
                ttl_nanos: current_ttl,
                state: current_state,
                ..
            } = &mut item.action
            else {
                unreachable!("validated discovery mutation must target a discovery action");
            };
            *current_delay = *delay_nanos;
            *current_ttl = *ttl_nanos;
            *current_state = *state;
        }
        SwarmMutation::ActionAtNanos { action, nanos } => {
            scenario
                .actions
                .iter_mut()
                .find(|item| item.id == *action)
                .expect("validated action-time mutation must reference an existing action")
                .schedule = ActionSchedule::At { nanos: *nanos };
        }
        SwarmMutation::RelayImpairment {
            relay,
            connection_delay_nanos,
            drop_every_nth_packet,
        } => {
            let impairment = match scenario
                .topology
                .relay_impairments
                .iter_mut()
                .find(|item| item.relay == *relay)
            {
                Some(impairment) => impairment,
                None => {
                    scenario
                        .topology
                        .relay_impairments
                        .push(RelayImpairmentSpec {
                            relay: relay.clone(),
                            ..RelayImpairmentSpec::default()
                        });
                    scenario
                        .topology
                        .relay_impairments
                        .last_mut()
                        .expect("a relay impairment was just appended")
                }
            };
            impairment.connection_delay_nanos = *connection_delay_nanos;
            impairment.drop_every_nth_packet = *drop_every_nth_packet;
        }
        SwarmMutation::CoSchedule { actions, nanos } => {
            for item in &mut scenario.actions {
                if actions
                    .binary_search_by(|action| action.as_str().cmp(item.id.as_str()))
                    .is_ok()
                {
                    item.schedule = ActionSchedule::At { nanos: *nanos };
                }
            }
        }
    }
    Ok(())
}

fn validate_id(value: &str) -> Result<(), SwarmError> {
    let allowed = value.len() <= 128
        && !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'/'));
    allowed.then_some(()).ok_or(SwarmError::InvalidIdentity)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SwarmError {
    Json(String),
    UnsupportedSchema(u16),
    InvalidIdentity,
    InvalidBounds,
    NonCanonical,
    Dangling(String),
    Decision(String),
    Scenario(ScenarioModelError),
    InvalidBasePath,
    InvalidDigest,
    BaseDigestMismatch,
    InvalidSafetyLiveness,
}

impl fmt::Display for SwarmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SwarmError {}
