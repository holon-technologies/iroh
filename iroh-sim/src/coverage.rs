//! Versioned simulation-coverage policy, observations, and deterministic accounting.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};

use crate::{
    ConnectionState, CryptoMode, EndpointState, InvariantName, Observation, ObservationKind,
    ResourceKind, SWARM_SCHEMA_VERSION, Scenario, SwarmSelection, SwarmSpec,
};

/// Current machine-readable coverage-policy schema.
pub const COVERAGE_POLICY_SCHEMA_VERSION: u16 = 2;
/// Current durable coverage report schema.
pub const COVERAGE_REPORT_SCHEMA_VERSION: u16 = 2;

const MAX_ID_BYTES: usize = 128;
const MAX_REASON_BYTES: usize = 1_024;
const MAX_POLICY_DOMAINS: usize = 64;
const MAX_POLICY_PROVIDERS: usize = 8;
const MAX_POLICY_LANES: usize = 16;
const MAX_POLICY_DIMENSIONS: usize = 64;
const MAX_VALUES_PER_DIMENSION: usize = 256;
const MAX_EVIDENCE_PER_VALUE: usize = 16;
const MAX_KNOWN_GAPS: usize = 1_024;
const MAX_HIGHER_ORDER_PER_DOMAIN: usize = 256;
const MAX_HIGHER_ORDER_WIDTH: usize = 8;
const MAX_ROLLING_WINDOW_DAYS: u16 = 30;
const MAX_WALL_MINUTES: u16 = 6 * 60;
const MAX_RUNS_PER_DOMAIN: u64 = 1_000_000;
const MAX_LEDGER_RUNS: u64 = 1_000_000_000;
const MAX_LEDGER_BUCKETS: usize = 100_000;

/// Operational lane that owns a coverage obligation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageLane {
    PullRequest,
    Main,
    Continuous,
    Nightly,
    Weekly,
    Reality,
}

/// Expansion rule for individual swarm choices.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IndividualObligation {
    AllOptions,
}

/// Expansion rule for pairs of independently selected swarm choices.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PairwiseObligation {
    AllCrossChoicePairs,
}

/// Explicit execution bounds for one coverage lane.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageLanePolicy {
    pub lane: CoverageLane,
    pub maximum_runs_per_domain: u64,
    pub maximum_wall_minutes: u16,
}

/// How one declared network-mode value is expected to receive evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageDisposition {
    Continuous,
    PermanentRegression,
    Reality,
    KnownGap,
}

/// Typed source that proves or explicitly defers one network-mode value.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CoverageEvidence {
    Provider {
        provider: CryptoMode,
    },
    SwarmOption {
        domain: String,
        choice_id: String,
        option_id: String,
    },
    BehaviorTransition {
        domain: String,
        transition: BehaviorTransition,
    },
    PermanentCase {
        id: String,
    },
    RealityCase {
        id: String,
    },
    KnownGap {
        id: String,
    },
}

/// One supported, permanently gated, realistically checked, or explicitly missing value.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageValuePolicy {
    pub id: String,
    pub disposition: CoverageDisposition,
    pub owners: Vec<CoverageLane>,
    pub evidence: Vec<CoverageEvidence>,
}

/// A stable named testing dimension with an exhaustive declared value inventory.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageDimensionPolicy {
    pub id: String,
    pub values: Vec<CoverageValuePolicy>,
}

/// One selected value within a swarm choice.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageSelection {
    pub choice_id: String,
    pub option_id: String,
}

/// One explicitly required higher-order configuration.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageCombination {
    pub selections: Vec<CoverageSelection>,
}

/// Coverage obligations for one simulator domain and its bound swarm.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageDomainPolicy {
    pub id: String,
    pub swarm_id: String,
    pub individual_obligation: IndividualObligation,
    pub pairwise_obligation: PairwiseObligation,
    pub higher_order: Vec<CoverageCombination>,
    pub owners: Vec<CoverageLane>,
}

/// A named unsupported or not-yet-modeled obligation that must remain visible.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KnownCoverageGap {
    pub id: String,
    pub dimension: String,
    pub reason: String,
}

/// Strict policy defining simulator coverage obligations and lane ownership.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoveragePolicy {
    pub schema_version: u16,
    pub id: String,
    pub rolling_window_days: u16,
    pub providers: Vec<CryptoMode>,
    pub lanes: Vec<CoverageLanePolicy>,
    pub dimensions: Vec<CoverageDimensionPolicy>,
    pub domains: Vec<CoverageDomainPolicy>,
    pub known_gaps: Vec<KnownCoverageGap>,
}

impl CoveragePolicy {
    /// Parses and structurally validates a strict coverage policy.
    pub fn from_json(bytes: &[u8]) -> Result<Self, CoverageError> {
        let policy: Self = serde_json::from_slice(bytes)
            .map_err(|error| CoverageError::Encoding(error.to_string()))?;
        policy.validate()?;
        Ok(policy)
    }

    /// Returns canonical pretty JSON after validation.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, CoverageError> {
        self.validate()?;
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| CoverageError::Encoding(error.to_string()))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Expands the policy against exact loaded swarm definitions.
    pub fn obligations(
        &self,
        swarms: &BTreeMap<String, SwarmSpec>,
    ) -> Result<CoverageObligations, CoverageError> {
        self.validate()?;
        let canonical = self.to_canonical_json()?;
        let policy_blake3 = blake3::hash(&canonical).to_hex().to_string();
        let mut bindings = Vec::with_capacity(self.domains.len());
        let mut individuals = BTreeSet::new();
        let mut pairs = BTreeSet::new();
        let mut higher_order = BTreeSet::new();
        let mut oracles = BTreeSet::new();
        let mut phases = BTreeSet::new();
        let mut transitions = BTreeSet::new();

        for domain in &self.domains {
            let swarm = swarms
                .get(&domain.swarm_id)
                .ok_or_else(|| CoverageError::UnknownSwarm(domain.swarm_id.clone()))?;
            swarm
                .validate()
                .map_err(|error| CoverageError::InvalidSwarm(error.to_string()))?;
            if swarm.id != domain.swarm_id {
                return Err(CoverageError::SwarmIdentityMismatch {
                    expected: domain.swarm_id.clone(),
                    actual: swarm.id.clone(),
                });
            }
            validate_higher_order(domain, swarm)?;
            bindings.push(CoverageDomainBinding {
                domain: domain.id.clone(),
                swarm_id: domain.swarm_id.clone(),
            });

            for provider in &self.providers {
                for choice in &swarm.choices {
                    for option in &choice.options {
                        individuals.insert(CoverageBucket {
                            domain: domain.id.clone(),
                            provider: *provider,
                            choice_id: choice.id.clone(),
                            option_id: option.id.clone(),
                        });
                    }
                }
                for first_index in 0..swarm.choices.len() {
                    for second_index in (first_index + 1)..swarm.choices.len() {
                        let first = &swarm.choices[first_index];
                        let second = &swarm.choices[second_index];
                        for first_option in &first.options {
                            for second_option in &second.options {
                                pairs.insert(CoveragePair {
                                    first: CoverageBucket {
                                        domain: domain.id.clone(),
                                        provider: *provider,
                                        choice_id: first.id.clone(),
                                        option_id: first_option.id.clone(),
                                    },
                                    second: CoverageBucket {
                                        domain: domain.id.clone(),
                                        provider: *provider,
                                        choice_id: second.id.clone(),
                                        option_id: second_option.id.clone(),
                                    },
                                });
                            }
                        }
                    }
                }
                for combination in &domain.higher_order {
                    higher_order.insert(CoverageHigherOrder {
                        domain: domain.id.clone(),
                        provider: *provider,
                        selections: combination.selections.clone(),
                    });
                }
                for invariant in &swarm.base.invariants {
                    oracles.insert(OracleCoverage {
                        domain: domain.id.clone(),
                        provider: *provider,
                        invariant: invariant.name,
                    });
                }
                if swarm.safety_liveness.is_some() {
                    for phase in [
                        CoveragePhase::SafetyFault,
                        CoveragePhase::Recovery,
                        CoveragePhase::LivenessProbe,
                    ] {
                        phases.insert(PhaseObligation {
                            domain: domain.id.clone(),
                            provider: *provider,
                            phase,
                        });
                    }
                }
            }
        }
        for dimension in &self.dimensions {
            for value in &dimension.values {
                for evidence in &value.evidence {
                    match evidence {
                        CoverageEvidence::Provider { .. }
                        | CoverageEvidence::PermanentCase { .. }
                        | CoverageEvidence::RealityCase { .. }
                        | CoverageEvidence::KnownGap { .. } => {}
                        CoverageEvidence::SwarmOption {
                            domain,
                            choice_id,
                            option_id,
                        } => {
                            let domain_policy = self
                                .domains
                                .iter()
                                .find(|candidate| candidate.id == *domain)
                                .expect("policy validation resolves evidence domains");
                            let swarm = swarms.get(&domain_policy.swarm_id).ok_or_else(|| {
                                CoverageError::UnknownSwarm(domain_policy.swarm_id.clone())
                            })?;
                            validate_swarm_option(swarm, choice_id, option_id)?;
                        }
                        CoverageEvidence::BehaviorTransition { domain, transition } => {
                            for provider in &self.providers {
                                transitions.insert(TransitionCoverage {
                                    domain: domain.clone(),
                                    provider: *provider,
                                    transition: transition.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }
        let total = individuals
            .len()
            .checked_add(pairs.len())
            .and_then(|value| value.checked_add(higher_order.len()))
            .and_then(|value| value.checked_add(oracles.len()))
            .and_then(|value| value.checked_add(phases.len()))
            .and_then(|value| value.checked_add(transitions.len()))
            .ok_or(CoverageError::TooManyObligations)?;
        if total > MAX_LEDGER_BUCKETS {
            return Err(CoverageError::TooManyObligations);
        }

        Ok(CoverageObligations {
            schema_version: COVERAGE_POLICY_SCHEMA_VERSION,
            policy_id: self.id.clone(),
            policy_blake3,
            rolling_window_days: self.rolling_window_days,
            dimensions: self.dimensions.clone(),
            bindings,
            individuals: individuals.into_iter().collect(),
            pairs: pairs.into_iter().collect(),
            higher_order: higher_order.into_iter().collect(),
            transitions: transitions.into_iter().collect(),
            oracles: oracles.into_iter().collect(),
            phases: phases.into_iter().collect(),
            known_gaps: self.known_gaps.clone(),
        })
    }

    fn validate(&self) -> Result<(), CoverageError> {
        if self.schema_version != COVERAGE_POLICY_SCHEMA_VERSION {
            return Err(CoverageError::UnsupportedSchema(self.schema_version));
        }
        validate_id("policy", &self.id)?;
        if self.rolling_window_days == 0 || self.rolling_window_days > MAX_ROLLING_WINDOW_DAYS {
            return Err(CoverageError::InvalidRollingWindow(
                self.rolling_window_days,
            ));
        }
        if self.providers.is_empty()
            || self.providers.len() > MAX_POLICY_PROVIDERS
            || !strictly_increasing(&self.providers)
        {
            return Err(CoverageError::NonCanonicalProviders);
        }
        if self.lanes.is_empty()
            || self.lanes.len() > MAX_POLICY_LANES
            || !self
                .lanes
                .windows(2)
                .all(|pair| pair[0].lane < pair[1].lane)
        {
            return Err(CoverageError::NonCanonicalLanes);
        }
        let lane_ids = self
            .lanes
            .iter()
            .map(|lane| lane.lane)
            .collect::<BTreeSet<_>>();
        for lane in &self.lanes {
            if lane.maximum_runs_per_domain == 0
                || lane.maximum_runs_per_domain > MAX_RUNS_PER_DOMAIN
                || lane.maximum_wall_minutes == 0
                || lane.maximum_wall_minutes > MAX_WALL_MINUTES
            {
                return Err(CoverageError::InvalidLaneBounds(lane.lane));
            }
        }
        if self.domains.is_empty()
            || self.domains.len() > MAX_POLICY_DOMAINS
            || !self.domains.windows(2).all(|pair| pair[0].id < pair[1].id)
        {
            return Err(CoverageError::NonCanonicalDomains);
        }
        for domain in &self.domains {
            validate_id("domain", &domain.id)?;
            validate_id("swarm", &domain.swarm_id)?;
            if domain.owners.is_empty()
                || !strictly_increasing(&domain.owners)
                || domain.owners.iter().any(|owner| !lane_ids.contains(owner))
            {
                return Err(CoverageError::InvalidOwners(domain.id.clone()));
            }
            if domain.higher_order.len() > MAX_HIGHER_ORDER_PER_DOMAIN
                || !strictly_increasing(&domain.higher_order)
            {
                return Err(CoverageError::NonCanonicalHigherOrder(domain.id.clone()));
            }
            for combination in &domain.higher_order {
                if combination.selections.len() < 3
                    || combination.selections.len() > MAX_HIGHER_ORDER_WIDTH
                    || !strictly_increasing(&combination.selections)
                {
                    return Err(CoverageError::NonCanonicalHigherOrder(domain.id.clone()));
                }
                for selection in &combination.selections {
                    validate_id("choice", &selection.choice_id)?;
                    validate_id("option", &selection.option_id)?;
                }
            }
        }
        if self.known_gaps.len() > MAX_KNOWN_GAPS
            || !self
                .known_gaps
                .windows(2)
                .all(|pair| pair[0].id < pair[1].id)
        {
            return Err(CoverageError::NonCanonicalKnownGaps);
        }
        for gap in &self.known_gaps {
            validate_id("gap", &gap.id)?;
            validate_id("dimension", &gap.dimension)?;
            if gap.reason.is_empty() || gap.reason.len() > MAX_REASON_BYTES {
                return Err(CoverageError::InvalidGapReason(gap.id.clone()));
            }
        }
        self.validate_dimensions(&lane_ids)?;
        Ok(())
    }

    fn validate_dimensions(&self, lane_ids: &BTreeSet<CoverageLane>) -> Result<(), CoverageError> {
        if self.dimensions.is_empty()
            || self.dimensions.len() > MAX_POLICY_DIMENSIONS
            || !self
                .dimensions
                .windows(2)
                .all(|pair| pair[0].id < pair[1].id)
        {
            return Err(CoverageError::NonCanonicalDimensions);
        }
        let domain_ids = self
            .domains
            .iter()
            .map(|domain| domain.id.as_str())
            .collect::<BTreeSet<_>>();
        let gaps = self
            .known_gaps
            .iter()
            .map(|gap| (gap.id.as_str(), gap.dimension.as_str()))
            .collect::<BTreeMap<_, _>>();
        let mut referenced_gaps = BTreeSet::new();

        for dimension in &self.dimensions {
            validate_id("dimension", &dimension.id)?;
            if dimension.values.is_empty()
                || dimension.values.len() > MAX_VALUES_PER_DIMENSION
                || !dimension
                    .values
                    .windows(2)
                    .all(|pair| pair[0].id < pair[1].id)
            {
                return Err(CoverageError::NonCanonicalDimensionValues(
                    dimension.id.clone(),
                ));
            }
            for value in &dimension.values {
                validate_id("coverage value", &value.id)?;
                if value.owners.is_empty()
                    || !strictly_increasing(&value.owners)
                    || value.owners.iter().any(|owner| !lane_ids.contains(owner))
                    || value.evidence.is_empty()
                    || value.evidence.len() > MAX_EVIDENCE_PER_VALUE
                    || !strictly_increasing(&value.evidence)
                {
                    return Err(CoverageError::InvalidValueEvidence {
                        dimension: dimension.id.clone(),
                        value: value.id.clone(),
                    });
                }
                validate_evidence_disposition(dimension, value)?;
                for evidence in &value.evidence {
                    match evidence {
                        CoverageEvidence::Provider { provider } => {
                            if !self.providers.contains(provider) {
                                return Err(CoverageError::UnexpectedProvider {
                                    domain: dimension.id.clone(),
                                    provider: *provider,
                                });
                            }
                        }
                        CoverageEvidence::SwarmOption {
                            domain,
                            choice_id,
                            option_id,
                        } => {
                            validate_id("domain", domain)?;
                            validate_id("choice", choice_id)?;
                            validate_id("option", option_id)?;
                            if !domain_ids.contains(domain.as_str()) {
                                return Err(CoverageError::UnknownDomain(domain.clone()));
                            }
                        }
                        CoverageEvidence::BehaviorTransition { domain, transition } => {
                            validate_id("domain", domain)?;
                            if !domain_ids.contains(domain.as_str()) {
                                return Err(CoverageError::UnknownDomain(domain.clone()));
                            }
                            validate_behavior_transition(transition)?;
                        }
                        CoverageEvidence::PermanentCase { id }
                        | CoverageEvidence::RealityCase { id } => {
                            validate_id("evidence case", id)?;
                        }
                        CoverageEvidence::KnownGap { id } => {
                            validate_id("gap", id)?;
                            let Some(gap_dimension) = gaps.get(id.as_str()) else {
                                return Err(CoverageError::UnknownKnownGap(id.clone()));
                            };
                            if *gap_dimension != dimension.id {
                                return Err(CoverageError::KnownGapDimensionMismatch {
                                    gap: id.clone(),
                                    expected: (*gap_dimension).to_owned(),
                                    actual: dimension.id.clone(),
                                });
                            }
                            if !referenced_gaps.insert(id.as_str()) {
                                return Err(CoverageError::DuplicateKnownGapReference(id.clone()));
                            }
                        }
                    }
                }
            }
        }
        if let Some(gap) = self
            .known_gaps
            .iter()
            .find(|gap| !referenced_gaps.contains(gap.id.as_str()))
        {
            return Err(CoverageError::UnreferencedKnownGap(gap.id.clone()));
        }
        Ok(())
    }
}

fn validate_evidence_disposition(
    dimension: &CoverageDimensionPolicy,
    value: &CoverageValuePolicy,
) -> Result<(), CoverageError> {
    let valid = match value.disposition {
        CoverageDisposition::Continuous => {
            value.owners.contains(&CoverageLane::Continuous)
                && value.evidence.iter().all(|evidence| {
                    matches!(
                        evidence,
                        CoverageEvidence::Provider { .. }
                            | CoverageEvidence::SwarmOption { .. }
                            | CoverageEvidence::BehaviorTransition { .. }
                    )
                })
        }
        CoverageDisposition::PermanentRegression => {
            value.owners.contains(&CoverageLane::PullRequest)
                && value
                    .evidence
                    .iter()
                    .all(|evidence| matches!(evidence, CoverageEvidence::PermanentCase { .. }))
        }
        CoverageDisposition::Reality => {
            value.owners.contains(&CoverageLane::Reality)
                && value
                    .evidence
                    .iter()
                    .all(|evidence| matches!(evidence, CoverageEvidence::RealityCase { .. }))
        }
        CoverageDisposition::KnownGap => {
            value.evidence.len() == 1
                && matches!(value.evidence[0], CoverageEvidence::KnownGap { .. })
        }
    };
    if !valid {
        return Err(CoverageError::InvalidValueEvidence {
            dimension: dimension.id.clone(),
            value: value.id.clone(),
        });
    }
    Ok(())
}

fn validate_behavior_transition(transition: &BehaviorTransition) -> Result<(), CoverageError> {
    match transition {
        BehaviorTransition::Endpoint { from, to } if from == to => {
            Err(CoverageError::InvalidBehaviorTransition)
        }
        BehaviorTransition::Connection { from, to } if from == to => {
            Err(CoverageError::InvalidBehaviorTransition)
        }
        _ => Ok(()),
    }
}

fn validate_higher_order(
    domain: &CoverageDomainPolicy,
    swarm: &SwarmSpec,
) -> Result<(), CoverageError> {
    let choices = swarm
        .choices
        .iter()
        .map(|choice| {
            (
                choice.id.as_str(),
                choice
                    .options
                    .iter()
                    .map(|option| option.id.as_str())
                    .collect::<BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for combination in &domain.higher_order {
        for selection in &combination.selections {
            let options = choices.get(selection.choice_id.as_str()).ok_or_else(|| {
                CoverageError::UnknownChoice {
                    swarm: swarm.id.clone(),
                    choice: selection.choice_id.clone(),
                }
            })?;
            if !options.contains(selection.option_id.as_str()) {
                return Err(CoverageError::UnknownOption {
                    swarm: swarm.id.clone(),
                    choice: selection.choice_id.clone(),
                    option: selection.option_id.clone(),
                });
            }
        }
    }
    Ok(())
}

fn validate_swarm_option(
    swarm: &SwarmSpec,
    choice_id: &str,
    option_id: &str,
) -> Result<(), CoverageError> {
    let Some(choice) = swarm.choices.iter().find(|choice| choice.id == choice_id) else {
        return Err(CoverageError::UnknownChoice {
            swarm: swarm.id.clone(),
            choice: choice_id.to_owned(),
        });
    };
    if !choice.options.iter().any(|option| option.id == option_id) {
        return Err(CoverageError::UnknownOption {
            swarm: swarm.id.clone(),
            choice: choice_id.to_owned(),
            option: option_id.to_owned(),
        });
    }
    Ok(())
}

fn strictly_increasing<T: Ord>(items: &[T]) -> bool {
    items.windows(2).all(|pair| pair[0] < pair[1])
}

fn validate_id(kind: &'static str, value: &str) -> Result<(), CoverageError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || value.split('/').any(|segment| {
            segment.is_empty()
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        Err(CoverageError::InvalidId {
            kind,
            value: value.to_owned(),
        })
    } else {
        Ok(())
    }
}

/// A checked domain-to-swarm binding included in durable obligations.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageDomainBinding {
    pub domain: String,
    pub swarm_id: String,
}

/// One provider-qualified swarm option.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageBucket {
    pub domain: String,
    pub provider: CryptoMode,
    pub choice_id: String,
    pub option_id: String,
}

/// One provider-qualified pair of choices observed in the same run.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoveragePair {
    pub first: CoverageBucket,
    pub second: CoverageBucket,
}

/// One provider-qualified explicitly selected higher-order obligation.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageHigherOrder {
    pub domain: String,
    pub provider: CryptoMode,
    pub selections: Vec<CoverageSelection>,
}

/// One provider-qualified invariant oracle obligation.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OracleCoverage {
    pub domain: String,
    pub provider: CryptoMode,
    pub invariant: InvariantName,
}

/// Ordered phases in a safety-to-recovery simulation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoveragePhase {
    SafetyFault,
    Recovery,
    LivenessProbe,
}

/// One provider-qualified phase obligation.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseObligation {
    pub domain: String,
    pub provider: CryptoMode,
    pub phase: CoveragePhase,
}

/// Fully expanded and digest-bound coverage obligations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageObligations {
    pub schema_version: u16,
    pub policy_id: String,
    pub policy_blake3: String,
    pub rolling_window_days: u16,
    pub dimensions: Vec<CoverageDimensionPolicy>,
    pub bindings: Vec<CoverageDomainBinding>,
    pub individuals: Vec<CoverageBucket>,
    pub pairs: Vec<CoveragePair>,
    pub higher_order: Vec<CoverageHigherOrder>,
    pub transitions: Vec<TransitionCoverage>,
    pub oracles: Vec<OracleCoverage>,
    pub phases: Vec<PhaseObligation>,
    pub known_gaps: Vec<KnownCoverageGap>,
}

impl CoverageObligations {
    /// Validates that an operational lane uses the policy-bound swarm and provider for its domain.
    pub fn validate_binding(
        &self,
        domain: &str,
        swarm_id: &str,
        provider: CryptoMode,
    ) -> Result<(), CoverageError> {
        let binding = self
            .bindings
            .iter()
            .find(|binding| binding.domain == domain)
            .ok_or_else(|| CoverageError::UnknownDomain(domain.to_owned()))?;
        if binding.swarm_id != swarm_id {
            return Err(CoverageError::SwarmIdentityMismatch {
                expected: binding.swarm_id.clone(),
                actual: swarm_id.to_owned(),
            });
        }
        if !self
            .individuals
            .iter()
            .any(|bucket| bucket.domain == domain && bucket.provider == provider)
        {
            return Err(CoverageError::UnexpectedProvider {
                domain: domain.to_owned(),
                provider,
            });
        }
        Ok(())
    }
}

/// Stable state-transition vocabulary. Dynamic entity IDs and payloads are intentionally absent.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "transition", rename_all = "snake_case")]
pub enum BehaviorTransition {
    Endpoint {
        from: EndpointState,
        to: EndpointState,
    },
    Connection {
        from: ConnectionState,
        to: ConnectionState,
    },
    Interface {
        up: bool,
    },
    InterfaceAddress {
        present: bool,
    },
    HostPower {
        sleeping: bool,
    },
    Route {
        active: bool,
    },
    PortMapping {
        active: bool,
    },
    DiscoveryRecord,
    Relay {
        online: bool,
    },
    Path {
        active: bool,
    },
    Resource {
        kind: ResourceKind,
    },
}

/// One domain- and provider-qualified required or observed behavioral transition.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionCoverage {
    pub domain: String,
    pub provider: CryptoMode,
    pub transition: BehaviorTransition,
}

/// Coverage extracted from one deterministic run without external effects.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageObservation {
    pub domain: String,
    pub swarm_id: String,
    pub provider: CryptoMode,
    pub individuals: Vec<CoverageBucket>,
    pub pairs: Vec<CoveragePair>,
    pub transitions: Vec<BehaviorTransition>,
    pub oracles: Vec<InvariantName>,
    pub phases: Vec<CoveragePhase>,
}

impl CoverageObservation {
    /// Extracts bounded configuration and behavioral coverage from a completed or failed run.
    pub fn from_run(
        domain: &str,
        provider: CryptoMode,
        selection: &SwarmSelection,
        scenario: &Scenario,
        observations: &[Observation],
    ) -> Result<Self, CoverageError> {
        validate_id("domain", domain)?;
        validate_id("swarm", &selection.swarm_id)?;
        if selection.schema_version != SWARM_SCHEMA_VERSION {
            return Err(CoverageError::UnsupportedSwarmSelectionSchema(
                selection.schema_version,
            ));
        }
        if selection.choices.is_empty()
            || selection.choices.len() > MAX_LEDGER_BUCKETS
            || !selection
                .choices
                .windows(2)
                .all(|pair| pair[0].choice_id < pair[1].choice_id)
        {
            return Err(CoverageError::NonCanonicalSelection);
        }

        let mut individuals = Vec::with_capacity(selection.choices.len());
        for selected in &selection.choices {
            validate_id("choice", &selected.choice_id)?;
            validate_id("option", &selected.option_id)?;
            individuals.push(CoverageBucket {
                domain: domain.to_owned(),
                provider,
                choice_id: selected.choice_id.clone(),
                option_id: selected.option_id.clone(),
            });
        }
        let pair_capacity = individuals
            .len()
            .checked_mul(individuals.len().saturating_sub(1))
            .and_then(|value| value.checked_div(2))
            .ok_or(CoverageError::TooManyObservations)?;
        if pair_capacity > MAX_LEDGER_BUCKETS {
            return Err(CoverageError::TooManyObservations);
        }
        let mut pairs = Vec::with_capacity(pair_capacity);
        for first_index in 0..individuals.len() {
            for second_index in (first_index + 1)..individuals.len() {
                pairs.push(CoveragePair {
                    first: individuals[first_index].clone(),
                    second: individuals[second_index].clone(),
                });
            }
        }

        let mut transitions = BTreeSet::new();
        let mut completed_operations = BTreeSet::new();
        for observation in observations {
            observation
                .validate()
                .map_err(|error| CoverageError::InvalidObservation(error.to_string()))?;
            match &observation.kind {
                ObservationKind::OperationCompleted { operation, .. } => {
                    completed_operations.insert(operation.as_str());
                }
                ObservationKind::EndpointState { from, to, .. } => {
                    transitions.insert(BehaviorTransition::Endpoint {
                        from: *from,
                        to: *to,
                    });
                }
                ObservationKind::ConnectionState { from, to, .. } => {
                    transitions.insert(BehaviorTransition::Connection {
                        from: *from,
                        to: *to,
                    });
                }
                ObservationKind::InterfaceState { up, .. } => {
                    transitions.insert(BehaviorTransition::Interface { up: *up });
                }
                ObservationKind::InterfaceAddress { present, .. } => {
                    transitions.insert(BehaviorTransition::InterfaceAddress { present: *present });
                }
                ObservationKind::HostPower { sleeping, .. } => {
                    transitions.insert(BehaviorTransition::HostPower {
                        sleeping: *sleeping,
                    });
                }
                ObservationKind::RouteState { active, .. } => {
                    transitions.insert(BehaviorTransition::Route { active: *active });
                }
                ObservationKind::PortMappingState { active, .. } => {
                    transitions.insert(BehaviorTransition::PortMapping { active: *active });
                }
                ObservationKind::DiscoveryRecordState { .. } => {
                    transitions.insert(BehaviorTransition::DiscoveryRecord);
                }
                ObservationKind::RelayState { online, .. } => {
                    transitions.insert(BehaviorTransition::Relay { online: *online });
                }
                ObservationKind::PathState { active, .. } => {
                    transitions.insert(BehaviorTransition::Path { active: *active });
                }
                ObservationKind::Resource { kind, .. } => {
                    transitions.insert(BehaviorTransition::Resource { kind: *kind });
                }
                ObservationKind::OperationStarted { .. }
                | ObservationKind::Delivery { .. }
                | ObservationKind::RelayCoverage { .. }
                | ObservationKind::Marker { .. } => {}
            }
        }
        if transitions.len() > MAX_LEDGER_BUCKETS {
            return Err(CoverageError::TooManyObservations);
        }
        let oracles = scenario
            .invariants
            .iter()
            .map(|invariant| invariant.name)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut phases = Vec::new();
        if let Some(expected) = &selection.safety_liveness {
            validate_id("safety action", &expected.safety_action)?;
            validate_id("recovery action", &expected.recovery_action)?;
            validate_id("liveness probe action", &expected.liveness_probe_action)?;
            let safety_completed = completed_operations.contains(expected.safety_action.as_str());
            let recovery_completed =
                completed_operations.contains(expected.recovery_action.as_str());
            let probe_completed =
                completed_operations.contains(expected.liveness_probe_action.as_str());
            if (recovery_completed && !safety_completed) || (probe_completed && !recovery_completed)
            {
                return Err(CoverageError::InvalidPhaseOrder);
            }
            if safety_completed {
                phases.push(CoveragePhase::SafetyFault);
            }
            if recovery_completed {
                phases.push(CoveragePhase::Recovery);
            }
            if probe_completed {
                phases.push(CoveragePhase::LivenessProbe);
            }
        }
        Ok(Self {
            domain: domain.to_owned(),
            swarm_id: selection.swarm_id.clone(),
            provider,
            individuals,
            pairs,
            transitions: transitions.into_iter().collect(),
            oracles,
            phases,
        })
    }
}

/// One sorted observed bucket and its checked occurrence count.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageCount<T> {
    pub bucket: T,
    pub occurrences: u64,
}

/// Durable deterministic coverage report and uncovered obligations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageReport {
    pub schema_version: u16,
    pub policy_id: String,
    pub policy_blake3: String,
    pub rolling_window_days: u16,
    pub completed_runs: u64,
    pub observed_individuals: Vec<CoverageCount<CoverageBucket>>,
    pub missing_individuals: Vec<CoverageBucket>,
    pub observed_pairs: Vec<CoverageCount<CoveragePair>>,
    pub missing_pairs: Vec<CoveragePair>,
    pub observed_higher_order: Vec<CoverageCount<CoverageHigherOrder>>,
    pub missing_higher_order: Vec<CoverageHigherOrder>,
    pub observed_transitions: Vec<CoverageCount<TransitionCoverage>>,
    pub missing_transitions: Vec<TransitionCoverage>,
    pub observed_oracles: Vec<CoverageCount<OracleCoverage>>,
    pub missing_oracles: Vec<OracleCoverage>,
    pub observed_phases: Vec<CoverageCount<PhaseObligation>>,
    pub missing_phases: Vec<PhaseObligation>,
    pub known_gaps: Vec<KnownCoverageGap>,
}

/// Pure bounded accumulator for one policy revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageLedger {
    obligations: CoverageObligations,
    completed_runs: u64,
    individuals: BTreeMap<CoverageBucket, u64>,
    pairs: BTreeMap<CoveragePair, u64>,
    higher_order: BTreeMap<CoverageHigherOrder, u64>,
    transitions: BTreeMap<TransitionCoverage, u64>,
    oracles: BTreeMap<OracleCoverage, u64>,
    phases: BTreeMap<PhaseObligation, u64>,
}

impl CoverageLedger {
    pub fn new(obligations: CoverageObligations) -> Self {
        Self {
            obligations,
            completed_runs: 0,
            individuals: BTreeMap::new(),
            pairs: BTreeMap::new(),
            higher_order: BTreeMap::new(),
            transitions: BTreeMap::new(),
            oracles: BTreeMap::new(),
            phases: BTreeMap::new(),
        }
    }

    /// Applies one run observation after validating its exact policy binding.
    pub fn observe(&mut self, observation: &CoverageObservation) -> Result<(), CoverageError> {
        if !strictly_increasing(&observation.individuals)
            || !strictly_increasing(&observation.pairs)
            || !strictly_increasing(&observation.transitions)
            || !strictly_increasing(&observation.oracles)
            || !strictly_increasing(&observation.phases)
        {
            return Err(CoverageError::NonCanonicalObservation);
        }
        let binding = self
            .obligations
            .bindings
            .iter()
            .find(|binding| binding.domain == observation.domain)
            .ok_or_else(|| CoverageError::UnknownDomain(observation.domain.clone()))?;
        if binding.swarm_id != observation.swarm_id {
            return Err(CoverageError::SwarmIdentityMismatch {
                expected: binding.swarm_id.clone(),
                actual: observation.swarm_id.clone(),
            });
        }
        let required_individuals = self.obligations.individuals.iter().collect::<BTreeSet<_>>();
        for bucket in &observation.individuals {
            if !required_individuals.contains(bucket) {
                return Err(CoverageError::UnexpectedIndividual(bucket.clone()));
            }
        }
        let required_pairs = self.obligations.pairs.iter().collect::<BTreeSet<_>>();
        for pair in &observation.pairs {
            if !required_pairs.contains(pair) {
                return Err(CoverageError::UnexpectedPair(Box::new(pair.clone())));
            }
        }
        let selected = observation
            .individuals
            .iter()
            .map(|bucket| CoverageSelection {
                choice_id: bucket.choice_id.clone(),
                option_id: bucket.option_id.clone(),
            })
            .collect::<BTreeSet<_>>();
        let mut higher_order = Vec::new();
        for required in &self.obligations.higher_order {
            if required.domain == observation.domain
                && required.provider == observation.provider
                && required
                    .selections
                    .iter()
                    .all(|selection| selected.contains(selection))
            {
                higher_order.push(required.clone());
            }
        }
        let required_oracles = self.obligations.oracles.iter().collect::<BTreeSet<_>>();
        let mut oracles = Vec::with_capacity(observation.oracles.len());
        for invariant in &observation.oracles {
            let oracle = OracleCoverage {
                domain: observation.domain.clone(),
                provider: observation.provider,
                invariant: *invariant,
            };
            if !required_oracles.contains(&oracle) {
                return Err(CoverageError::UnexpectedOracle(oracle));
            }
            oracles.push(oracle);
        }
        let required_phases = self.obligations.phases.iter().collect::<BTreeSet<_>>();
        let mut phases = Vec::with_capacity(observation.phases.len());
        for phase in &observation.phases {
            let obligation = PhaseObligation {
                domain: observation.domain.clone(),
                provider: observation.provider,
                phase: *phase,
            };
            if !required_phases.contains(&obligation) {
                return Err(CoverageError::UnexpectedPhase(obligation));
            }
            phases.push(obligation);
        }
        let transitions = observation
            .transitions
            .iter()
            .map(|transition| TransitionCoverage {
                domain: observation.domain.clone(),
                provider: observation.provider,
                transition: transition.clone(),
            })
            .collect::<Vec<_>>();

        let next_completed_runs = checked_increment(self.completed_runs)?;
        check_increment_map(&self.individuals, &observation.individuals)?;
        check_increment_map(&self.pairs, &observation.pairs)?;
        check_increment_map(&self.higher_order, &higher_order)?;
        check_increment_map(&self.transitions, &transitions)?;
        check_increment_map(&self.oracles, &oracles)?;
        check_increment_map(&self.phases, &phases)?;

        self.completed_runs = next_completed_runs;
        apply_increment_map(&mut self.individuals, &observation.individuals);
        apply_increment_map(&mut self.pairs, &observation.pairs);
        apply_increment_map(&mut self.higher_order, &higher_order);
        apply_increment_map(&mut self.transitions, &transitions);
        apply_increment_map(&mut self.oracles, &oracles);
        apply_increment_map(&mut self.phases, &phases);
        Ok(())
    }

    /// Deterministically combines a compatible partial ledger.
    pub fn merge(&mut self, other: &Self) -> Result<(), CoverageError> {
        if self.obligations != other.obligations {
            return Err(CoverageError::PolicyMismatch);
        }
        let next_completed_runs = checked_add(self.completed_runs, other.completed_runs)?;
        check_merge_map(&self.individuals, &other.individuals)?;
        check_merge_map(&self.pairs, &other.pairs)?;
        check_merge_map(&self.higher_order, &other.higher_order)?;
        check_merge_map(&self.transitions, &other.transitions)?;
        check_merge_map(&self.oracles, &other.oracles)?;
        check_merge_map(&self.phases, &other.phases)?;

        self.completed_runs = next_completed_runs;
        apply_merge_map(&mut self.individuals, &other.individuals);
        apply_merge_map(&mut self.pairs, &other.pairs);
        apply_merge_map(&mut self.higher_order, &other.higher_order);
        apply_merge_map(&mut self.transitions, &other.transitions);
        apply_merge_map(&mut self.oracles, &other.oracles);
        apply_merge_map(&mut self.phases, &other.phases);
        Ok(())
    }

    /// Produces a stable report with every missing obligation made explicit.
    pub fn report(&self) -> CoverageReport {
        CoverageReport {
            schema_version: COVERAGE_REPORT_SCHEMA_VERSION,
            policy_id: self.obligations.policy_id.clone(),
            policy_blake3: self.obligations.policy_blake3.clone(),
            rolling_window_days: self.obligations.rolling_window_days,
            completed_runs: self.completed_runs,
            observed_individuals: counts(&self.individuals),
            missing_individuals: missing(&self.obligations.individuals, &self.individuals),
            observed_pairs: counts(&self.pairs),
            missing_pairs: missing(&self.obligations.pairs, &self.pairs),
            observed_higher_order: counts(&self.higher_order),
            missing_higher_order: missing(&self.obligations.higher_order, &self.higher_order),
            observed_transitions: counts(&self.transitions),
            missing_transitions: missing(&self.obligations.transitions, &self.transitions),
            observed_oracles: counts(&self.oracles),
            missing_oracles: missing(&self.obligations.oracles, &self.oracles),
            observed_phases: counts(&self.phases),
            missing_phases: missing(&self.obligations.phases, &self.phases),
            known_gaps: self.obligations.known_gaps.clone(),
        }
    }
}

fn checked_increment(value: u64) -> Result<u64, CoverageError> {
    checked_add(value, 1)
}

fn checked_add(left: u64, right: u64) -> Result<u64, CoverageError> {
    left.checked_add(right)
        .filter(|value| *value <= MAX_LEDGER_RUNS)
        .ok_or(CoverageError::CounterOverflow)
}

fn check_increment_map<T: Ord>(map: &BTreeMap<T, u64>, keys: &[T]) -> Result<(), CoverageError> {
    let new_keys = keys.iter().filter(|key| !map.contains_key(*key)).count();
    if map
        .len()
        .checked_add(new_keys)
        .is_none_or(|length| length > MAX_LEDGER_BUCKETS)
    {
        return Err(CoverageError::TooManyObservations);
    }
    for key in keys {
        let current = map.get(key).copied().unwrap_or_default();
        let _ = checked_increment(current)?;
    }
    Ok(())
}

fn apply_increment_map<T: Clone + Ord>(map: &mut BTreeMap<T, u64>, keys: &[T]) {
    for key in keys {
        let count = map.entry(key.clone()).or_default();
        *count = count
            .checked_add(1)
            .expect("coverage increment was checked before mutation");
    }
}

fn check_merge_map<T: Ord>(
    destination: &BTreeMap<T, u64>,
    source: &BTreeMap<T, u64>,
) -> Result<(), CoverageError> {
    let new_keys = source
        .keys()
        .filter(|bucket| !destination.contains_key(*bucket))
        .count();
    if destination
        .len()
        .checked_add(new_keys)
        .is_none_or(|length| length > MAX_LEDGER_BUCKETS)
    {
        return Err(CoverageError::TooManyObservations);
    }
    for (bucket, occurrences) in source {
        let current = destination.get(bucket).copied().unwrap_or_default();
        let _ = checked_add(current, *occurrences)?;
    }
    Ok(())
}

fn apply_merge_map<T: Clone + Ord>(destination: &mut BTreeMap<T, u64>, source: &BTreeMap<T, u64>) {
    for (bucket, occurrences) in source {
        let current = destination.entry(bucket.clone()).or_default();
        *current = current
            .checked_add(*occurrences)
            .expect("coverage merge was checked before mutation");
    }
}

fn counts<T: Clone + Ord>(map: &BTreeMap<T, u64>) -> Vec<CoverageCount<T>> {
    map.iter()
        .map(|(bucket, occurrences)| CoverageCount {
            bucket: bucket.clone(),
            occurrences: *occurrences,
        })
        .collect()
}

fn missing<T: Clone + Ord>(required: &[T], observed: &BTreeMap<T, u64>) -> Vec<T> {
    required
        .iter()
        .filter(|bucket| !observed.contains_key(*bucket))
        .cloned()
        .collect()
}

/// Typed fail-closed coverage-policy and accounting errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoverageError {
    Encoding(String),
    UnsupportedSchema(u16),
    UnsupportedSwarmSelectionSchema(u16),
    InvalidId {
        kind: &'static str,
        value: String,
    },
    InvalidRollingWindow(u16),
    NonCanonicalProviders,
    NonCanonicalLanes,
    NonCanonicalDimensions,
    NonCanonicalDimensionValues(String),
    InvalidValueEvidence {
        dimension: String,
        value: String,
    },
    InvalidLaneBounds(CoverageLane),
    NonCanonicalDomains,
    InvalidOwners(String),
    NonCanonicalHigherOrder(String),
    NonCanonicalKnownGaps,
    InvalidGapReason(String),
    UnknownKnownGap(String),
    DuplicateKnownGapReference(String),
    UnreferencedKnownGap(String),
    KnownGapDimensionMismatch {
        gap: String,
        expected: String,
        actual: String,
    },
    InvalidBehaviorTransition,
    UnknownSwarm(String),
    InvalidSwarm(String),
    SwarmIdentityMismatch {
        expected: String,
        actual: String,
    },
    UnknownChoice {
        swarm: String,
        choice: String,
    },
    UnknownOption {
        swarm: String,
        choice: String,
        option: String,
    },
    TooManyObligations,
    TooManyObservations,
    NonCanonicalSelection,
    NonCanonicalObservation,
    InvalidPhaseOrder,
    InvalidObservation(String),
    UnknownDomain(String),
    UnexpectedProvider {
        domain: String,
        provider: CryptoMode,
    },
    UnexpectedIndividual(CoverageBucket),
    UnexpectedPair(Box<CoveragePair>),
    UnexpectedOracle(OracleCoverage),
    UnexpectedPhase(PhaseObligation),
    PolicyMismatch,
    CounterOverflow,
}

impl fmt::Display for CoverageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CoverageError {}
