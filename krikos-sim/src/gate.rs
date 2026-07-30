//! Deterministic change-impact selection for pull-request and main simulation gates.

use std::{
    collections::BTreeSet,
    fmt,
    path::{Path, PathBuf},
};

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::CryptoMode;

pub const CHANGE_IMPACT_POLICY_SCHEMA_VERSION: u16 = 1;
pub const GATE_SELECTION_SCHEMA_VERSION: u16 = 1;
const MAX_DOMAINS: usize = 32;
const MAX_MAPPINGS: usize = 256;
const MAX_TIERS: usize = 2;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeImpactPolicy {
    pub schema_version: u16,
    pub policy_id: String,
    pub maximum_changed_paths: usize,
    pub domains: Vec<GateDomain>,
    pub ignored_prefixes: Vec<String>,
    pub global_prefixes: Vec<String>,
    pub mappings: Vec<ChangeImpactMapping>,
    pub tiers: Vec<GateTierPolicy>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GateDomain {
    pub id: String,
    pub swarm: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeImpactMapping {
    pub prefix: String,
    pub domains: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum SimulationGateTier {
    PullRequest,
    Main,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GateTierPolicy {
    pub tier: SimulationGateTier,
    pub targeted_runs_per_lane: u8,
    pub maximum_total_runs: usize,
}

impl ChangeImpactPolicy {
    pub fn from_json(bytes: &[u8]) -> Result<Self, GateError> {
        let policy: Self = serde_json::from_slice(bytes)
            .map_err(|error| GateError::Encoding(error.to_string()))?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn to_canonical_json(&self) -> Result<Vec<u8>, GateError> {
        self.validate()?;
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| GateError::Encoding(error.to_string()))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn blake3(&self) -> Result<String, GateError> {
        Ok(blake3::hash(&self.to_canonical_json()?)
            .to_hex()
            .to_string())
    }

    fn validate(&self) -> Result<(), GateError> {
        if self.schema_version != CHANGE_IMPACT_POLICY_SCHEMA_VERSION {
            return Err(GateError::UnsupportedPolicySchema(self.schema_version));
        }
        if self.policy_id.is_empty() || self.policy_id.len() > 128 {
            return Err(GateError::InvalidPolicyId);
        }
        if self.maximum_changed_paths == 0 || self.maximum_changed_paths > 4_096 {
            return Err(GateError::InvalidChangedPathBound(
                self.maximum_changed_paths,
            ));
        }
        if self.domains.is_empty() || self.domains.len() > MAX_DOMAINS {
            return Err(GateError::InvalidDomainCount(self.domains.len()));
        }
        if self
            .domains
            .windows(2)
            .any(|domains| domains[0].id >= domains[1].id)
        {
            return Err(GateError::NonCanonicalDomains);
        }
        let domain_ids = self
            .domains
            .iter()
            .map(|domain| domain.id.as_str())
            .collect::<BTreeSet<_>>();
        for domain in &self.domains {
            if !valid_identifier(&domain.id) || !valid_relative_path(&domain.swarm) {
                return Err(GateError::InvalidDomain(domain.id.clone()));
            }
        }
        validate_prefixes(&self.ignored_prefixes)?;
        validate_prefixes(&self.global_prefixes)?;
        if self.mappings.is_empty() || self.mappings.len() > MAX_MAPPINGS {
            return Err(GateError::InvalidMappingCount(self.mappings.len()));
        }
        if self
            .mappings
            .windows(2)
            .any(|mappings| mappings[0].prefix >= mappings[1].prefix)
        {
            return Err(GateError::NonCanonicalMappings);
        }
        for mapping in &self.mappings {
            if !valid_prefix(&mapping.prefix)
                || mapping.domains.is_empty()
                || mapping
                    .domains
                    .windows(2)
                    .any(|domains| domains[0] >= domains[1])
                || mapping
                    .domains
                    .iter()
                    .any(|domain| !domain_ids.contains(domain.as_str()))
            {
                return Err(GateError::InvalidMapping(mapping.prefix.clone()));
            }
        }
        if self.tiers.len() != MAX_TIERS
            || self.tiers[0].tier != SimulationGateTier::PullRequest
            || self.tiers[1].tier != SimulationGateTier::Main
        {
            return Err(GateError::NonCanonicalTiers);
        }
        let universal_runs = self
            .domains
            .len()
            .checked_mul(2)
            .ok_or(GateError::RunBoundOverflow)?;
        for tier in &self.tiers {
            if tier.targeted_runs_per_lane == 0
                || tier.maximum_total_runs < universal_runs
                || tier.maximum_total_runs > 256
            {
                return Err(GateError::InvalidTier(tier.tier));
            }
            let worst_case = self
                .domains
                .len()
                .checked_mul(2)
                .and_then(|lanes| lanes.checked_mul(usize::from(tier.targeted_runs_per_lane)))
                .and_then(|targeted| targeted.checked_add(universal_runs))
                .ok_or(GateError::RunBoundOverflow)?;
            if worst_case > tier.maximum_total_runs {
                return Err(GateError::InvalidTier(tier.tier));
            }
        }
        Ok(())
    }

    fn tier(&self, tier: SimulationGateTier) -> &GateTierPolicy {
        &self.tiers[match tier {
            SimulationGateTier::PullRequest => 0,
            SimulationGateTier::Main => 1,
        }]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateSelectionMode {
    Mapped,
    GlobalFallback,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateWorkKind {
    Universal,
    Targeted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GateWork {
    pub kind: GateWorkKind,
    pub domain: String,
    pub lane: String,
    pub swarm: PathBuf,
    pub crypto: CryptoMode,
    pub ordinal: u8,
    pub seed_blake3: String,
    pub seed_range: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GateSelection {
    pub schema_version: u16,
    pub impact_policy_id: String,
    pub impact_policy_blake3: String,
    pub coverage_policy_blake3: String,
    pub tier: SimulationGateTier,
    pub base_revision: Option<String>,
    pub candidate_revision: String,
    pub mode: GateSelectionMode,
    pub changed_paths: Vec<String>,
    pub impacted_domains: Vec<String>,
    pub maximum_total_runs: usize,
    pub universal: Vec<GateWork>,
    pub targeted: Vec<GateWork>,
}

impl GateSelection {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        policy: &ChangeImpactPolicy,
        coverage_policy_blake3: &str,
        base_revision: Option<&str>,
        candidate_revision: &str,
        tier: SimulationGateTier,
        changed_paths: &[String],
        diff_available: bool,
    ) -> Result<Self, GateError> {
        policy.validate()?;
        validate_digest(coverage_policy_blake3)?;
        validate_revision(candidate_revision)?;
        if let Some(base_revision) = base_revision {
            validate_revision(base_revision)?;
        }
        if changed_paths.len() > policy.maximum_changed_paths {
            return Err(GateError::ChangedPathBoundExceeded(changed_paths.len()));
        }
        for path in changed_paths {
            if !valid_relative_path(&PathBuf::from(path)) {
                return Err(GateError::InvalidChangedPath(path.clone()));
            }
        }

        let mut canonical_paths = changed_paths.to_vec();
        canonical_paths.sort();
        canonical_paths.dedup();
        let identical_revision = base_revision == Some(candidate_revision);
        let all_domains = policy
            .domains
            .iter()
            .map(|domain| domain.id.clone())
            .collect::<BTreeSet<_>>();
        let mut impacted = BTreeSet::new();
        let mut global_fallback = !diff_available && !identical_revision;

        if !global_fallback && !identical_revision {
            for path in &canonical_paths {
                if policy
                    .ignored_prefixes
                    .iter()
                    .any(|prefix| path.starts_with(prefix))
                {
                    continue;
                }
                if policy
                    .global_prefixes
                    .iter()
                    .any(|prefix| path.starts_with(prefix))
                {
                    global_fallback = true;
                    break;
                }
                let mut matched = false;
                for mapping in &policy.mappings {
                    if path.starts_with(&mapping.prefix) {
                        matched = true;
                        impacted.extend(mapping.domains.iter().cloned());
                    }
                }
                if !matched {
                    global_fallback = true;
                    break;
                }
            }
        }
        if global_fallback {
            impacted = all_domains;
        }

        let impact_policy_blake3 = policy.blake3()?;
        let universal = build_work(
            policy,
            &impact_policy_blake3,
            coverage_policy_blake3,
            candidate_revision,
            GateWorkKind::Universal,
            policy.domains.iter().map(|domain| domain.id.as_str()),
            1,
        )?;
        let tier_policy = policy.tier(tier);
        let targeted = build_work(
            policy,
            &impact_policy_blake3,
            coverage_policy_blake3,
            candidate_revision,
            GateWorkKind::Targeted,
            impacted.iter().map(String::as_str),
            tier_policy.targeted_runs_per_lane,
        )?;
        let total_runs = universal
            .len()
            .checked_add(targeted.len())
            .ok_or(GateError::RunBoundOverflow)?;
        if total_runs > tier_policy.maximum_total_runs {
            return Err(GateError::SelectedRunBoundExceeded {
                selected: total_runs,
                maximum: tier_policy.maximum_total_runs,
            });
        }

        Ok(Self {
            schema_version: GATE_SELECTION_SCHEMA_VERSION,
            impact_policy_id: policy.policy_id.clone(),
            impact_policy_blake3,
            coverage_policy_blake3: coverage_policy_blake3.to_owned(),
            tier,
            base_revision: base_revision.map(ToOwned::to_owned),
            candidate_revision: candidate_revision.to_owned(),
            mode: if global_fallback {
                GateSelectionMode::GlobalFallback
            } else {
                GateSelectionMode::Mapped
            },
            changed_paths: canonical_paths,
            impacted_domains: impacted.into_iter().collect(),
            maximum_total_runs: tier_policy.maximum_total_runs,
            universal,
            targeted,
        })
    }

    pub fn total_runs(&self) -> usize {
        self.universal.len() + self.targeted.len()
    }

    pub fn to_canonical_json(&self) -> Result<Vec<u8>, GateError> {
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| GateError::Encoding(error.to_string()))?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

#[allow(clippy::too_many_arguments)]
fn build_work<'a>(
    policy: &ChangeImpactPolicy,
    impact_policy_blake3: &str,
    coverage_policy_blake3: &str,
    candidate_revision: &str,
    kind: GateWorkKind,
    domains: impl Iterator<Item = &'a str>,
    runs_per_lane: u8,
) -> Result<Vec<GateWork>, GateError> {
    let mut work = Vec::new();
    for domain_id in domains {
        let domain = policy
            .domains
            .iter()
            .find(|candidate| candidate.id == domain_id)
            .ok_or_else(|| GateError::InvalidDomain(domain_id.to_owned()))?;
        for crypto in [
            CryptoMode::DeterministicTest,
            CryptoMode::ProductionProvider,
        ] {
            let provider = match crypto {
                CryptoMode::DeterministicTest => "deterministic-test",
                CryptoMode::ProductionProvider => "production-provider",
            };
            for ordinal in 0..runs_per_lane {
                let lane = format!("{domain_id}/{provider}");
                let mut hasher =
                    blake3::Hasher::new_derive_key("krikos-sim deterministic change gate seed v1");
                for part in [
                    impact_policy_blake3,
                    coverage_policy_blake3,
                    candidate_revision,
                    match kind {
                        GateWorkKind::Universal => "universal",
                        GateWorkKind::Targeted => "targeted",
                    },
                    lane.as_str(),
                    &ordinal.to_string(),
                ] {
                    hasher.update(part.as_bytes());
                    hasher.update(&[0]);
                }
                let seed_hash = hasher.finalize();
                let seed = u64::from_le_bytes(
                    seed_hash.as_bytes()[..8]
                        .try_into()
                        .expect("an eight-byte digest prefix has a fixed length"),
                );
                let seed = seed % (u64::MAX - 1);
                work.push(GateWork {
                    kind,
                    domain: domain_id.to_owned(),
                    lane,
                    swarm: domain.swarm.clone(),
                    crypto,
                    ordinal,
                    seed_blake3: seed_hash.to_hex().to_string(),
                    seed_range: format!("{seed}..{}", seed + 1),
                });
            }
        }
    }
    Ok(work)
}

fn validate_prefixes(prefixes: &[String]) -> Result<(), GateError> {
    if prefixes.is_empty()
        || prefixes.len() > MAX_MAPPINGS
        || prefixes.windows(2).any(|values| values[0] >= values[1])
    {
        return Err(GateError::NonCanonicalPrefixes);
    }
    if let Some(prefix) = prefixes.iter().find(|prefix| !valid_prefix(prefix)) {
        return Err(GateError::InvalidPrefix(prefix.clone()));
    }
    Ok(())
}

fn valid_prefix(prefix: &str) -> bool {
    valid_relative_path(&PathBuf::from(prefix))
}

fn valid_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn validate_digest(value: &str) -> Result<(), GateError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(GateError::InvalidCoveragePolicyDigest);
    }
    Ok(())
}

fn validate_revision(value: &str) -> Result<(), GateError> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(GateError::InvalidRevision(value.to_owned()));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GateError {
    Encoding(String),
    UnsupportedPolicySchema(u16),
    InvalidPolicyId,
    InvalidChangedPathBound(usize),
    InvalidDomainCount(usize),
    NonCanonicalDomains,
    InvalidDomain(String),
    NonCanonicalPrefixes,
    InvalidPrefix(String),
    InvalidMappingCount(usize),
    NonCanonicalMappings,
    InvalidMapping(String),
    NonCanonicalTiers,
    InvalidTier(SimulationGateTier),
    InvalidCoveragePolicyDigest,
    InvalidRevision(String),
    ChangedPathBoundExceeded(usize),
    InvalidChangedPath(String),
    RunBoundOverflow,
    SelectedRunBoundExceeded { selected: usize, maximum: usize },
}

impl fmt::Display for GateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for GateError {}
