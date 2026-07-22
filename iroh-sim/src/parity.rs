//! Backend-neutral semantic outcomes and strict Patchbay result fixtures.
//!
//! Packet timing and implementation-private event identities intentionally do not enter this
//! schema.  A parity comparison answers whether two backends observed the same externally useful
//! behavior, while retaining NAT/firewall/mobility evidence for diagnosis.

use std::{collections::BTreeMap, fmt};

use iroh_runtime::{TraceEvent, TraceEventKind};
use serde::{Deserialize, Serialize};

use crate::{ConnectionState, ObservationKind, RunnerTerminal, ScenarioReport};

/// Current strict fixture schema for results imported from realistic backends.
pub const PARITY_FIXTURE_SCHEMA_VERSION: u16 = 2;
/// Current strict receipt schema emitted by the privileged Patchbay test adapter.
pub const PATCHBAY_RECEIPT_SCHEMA_VERSION: u16 = 1;
const MAX_EVIDENCE_VALIDITY_SECS: u64 = 31 * 24 * 60 * 60;
const MAX_FUTURE_SKEW_SECS: u64 = 300;
const MAX_RECEIPT_OBSERVATIONS: u64 = 1_000_000;
const MAX_SELECTED_PATHS: usize = 16;

/// Backend that produced a semantic fixture.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParityBackend {
    Deterministic,
    ProductionLocal,
    Patchbay,
}

/// Stable terminal classes shared by deterministic and realistic backends.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticTerminal {
    Success,
    ExpectedFailure,
    InvariantFailure,
    ResourceLeak,
    Timeout,
    SetupFailure,
}

/// Semantic dimensions which may be compared independently of event timing.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticDimension {
    Terminal,
    Authentication,
    Delivery,
    Nat,
    Firewall,
    Mobility,
    Relay,
    Path,
}

/// Backend-independent externally meaningful run outcome.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticOutcome {
    pub terminal: SemanticTerminal,
    /// Connections which reached `connected` with an authenticated peer identity.
    pub authenticated_connections: u64,
    /// Application deliveries for which expected and observed payload digests match.
    pub intact_deliveries: u64,
    /// Application deliveries whose digests differ.
    pub corrupt_deliveries: u64,
    /// NAT lifecycle transition counts, keyed as `nat/transition`.
    pub nat_transitions: BTreeMap<String, u64>,
    /// Firewall decision counts, keyed as `firewall/direction/action`.
    pub firewall_decisions: BTreeMap<String, u64>,
    /// Mobility transition counts, keyed by stable semantic transition.
    pub mobility_transitions: BTreeMap<String, u64>,
    /// Relay lifecycle transition counts, keyed by stable semantic transition.
    #[serde(default)]
    pub relay_transitions: BTreeMap<String, u64>,
    /// Ordered selected-path classes (`relay`, `direct_ipv4`, or `direct_ipv6`).
    pub selected_paths: Vec<String>,
}

impl SemanticOutcome {
    /// Minimal successful result useful to import a Patchbay assertion-only test result.
    pub fn successful(authenticated_connections: u64, intact_deliveries: u64) -> Self {
        Self {
            terminal: SemanticTerminal::Success,
            authenticated_connections,
            intact_deliveries,
            corrupt_deliveries: 0,
            nat_transitions: BTreeMap::new(),
            firewall_decisions: BTreeMap::new(),
            mobility_transitions: BTreeMap::new(),
            relay_transitions: BTreeMap::new(),
            selected_paths: Vec::new(),
        }
    }
}

/// Strict result envelope imported from a backend-specific test execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ParityFixture {
    pub schema_version: u16,
    pub case_id: String,
    pub backend: ParityBackend,
    /// Test or adapter revision which produced this fixture; never an ambient host path.
    pub source_revision: String,
    /// Immutable execution identity and bounded freshness window.
    pub evidence: ParityEvidence,
    /// Sorted unique semantic capabilities asserted by this result.
    pub capabilities: Vec<SemanticDimension>,
    /// Sorted unique dimensions actually observed during this execution.
    pub observed_dimensions: Vec<SemanticDimension>,
    pub result: ParityFixtureResult,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ParityEvidence {
    pub run_id: String,
    pub scenario_hash: String,
    pub observed_at_unix_secs: u64,
    pub valid_for_secs: u64,
}

/// Minimal backend-neutral observations emitted only after a Patchbay test succeeds.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PatchbayReceipt {
    pub schema_version: u16,
    pub case_id: String,
    pub test_id: String,
    pub authenticated_connections: u64,
    pub successful_exchanges: u64,
    pub corrupt_exchanges: u64,
    pub selected_paths: Vec<String>,
}

impl PatchbayReceipt {
    pub fn from_json(bytes: &[u8]) -> Result<Self, ParityError> {
        let receipt: Self =
            serde_json::from_slice(bytes).map_err(|error| ParityError::Json(error.to_string()))?;
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn to_canonical_json(&self) -> Result<Vec<u8>, ParityError> {
        self.validate()?;
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| ParityError::Json(error.to_string()))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn validate(&self) -> Result<(), ParityError> {
        if self.schema_version != PATCHBAY_RECEIPT_SCHEMA_VERSION {
            return Err(ParityError::UnsupportedReceiptSchema(self.schema_version));
        }
        validate_identity("case_id", &self.case_id)?;
        validate_identity("test_id", &self.test_id)?;
        if self.authenticated_connections == 0
            || self.authenticated_connections > MAX_RECEIPT_OBSERVATIONS
            || self.successful_exchanges == 0
            || self.successful_exchanges > MAX_RECEIPT_OBSERVATIONS
            || self.corrupt_exchanges > MAX_RECEIPT_OBSERVATIONS
            || self.selected_paths.len() > MAX_SELECTED_PATHS
        {
            return Err(ParityError::InvalidReceipt);
        }
        let mut unique_paths = self.selected_paths.clone();
        unique_paths.sort();
        unique_paths.dedup();
        if unique_paths.len() != self.selected_paths.len() {
            return Err(ParityError::InvalidReceipt);
        }
        validate_outcome(&SemanticOutcome {
            terminal: SemanticTerminal::Success,
            authenticated_connections: self.authenticated_connections,
            intact_deliveries: self.successful_exchanges,
            corrupt_deliveries: self.corrupt_exchanges,
            nat_transitions: BTreeMap::new(),
            firewall_decisions: BTreeMap::new(),
            mobility_transitions: BTreeMap::new(),
            relay_transitions: BTreeMap::new(),
            selected_paths: self.selected_paths.clone(),
        })
    }

    /// Converts observed receipt data to immutable parity evidence.
    pub fn to_fixture(
        &self,
        source_revision: &str,
        scenario_hash: String,
        observed_at_unix_secs: u64,
    ) -> Result<ParityFixture, ParityError> {
        self.validate()?;
        let canonical = self.to_canonical_json()?;
        let mut run_hasher = blake3::Hasher::new_derive_key("iroh-sim patchbay evidence run id v1");
        run_hasher.update(source_revision.as_bytes());
        run_hasher.update(scenario_hash.as_bytes());
        run_hasher.update(&canonical);
        let mut capabilities = vec![
            SemanticDimension::Terminal,
            SemanticDimension::Authentication,
            SemanticDimension::Delivery,
        ];
        if !self.selected_paths.is_empty() {
            capabilities.push(SemanticDimension::Path);
        }
        let fixture = ParityFixture {
            schema_version: PARITY_FIXTURE_SCHEMA_VERSION,
            case_id: self.case_id.clone(),
            backend: ParityBackend::Patchbay,
            source_revision: source_revision.to_owned(),
            evidence: ParityEvidence {
                run_id: run_hasher.finalize().to_hex().to_string(),
                scenario_hash,
                observed_at_unix_secs,
                valid_for_secs: 30 * 24 * 60 * 60,
            },
            observed_dimensions: capabilities.clone(),
            capabilities,
            result: ParityFixtureResult::Completed {
                outcome: SemanticOutcome {
                    terminal: SemanticTerminal::Success,
                    authenticated_connections: self.authenticated_connections,
                    intact_deliveries: self.successful_exchanges,
                    corrupt_deliveries: self.corrupt_exchanges,
                    nat_transitions: BTreeMap::new(),
                    firewall_decisions: BTreeMap::new(),
                    mobility_transitions: BTreeMap::new(),
                    relay_transitions: BTreeMap::new(),
                    selected_paths: self.selected_paths.clone(),
                },
            },
        };
        fixture.validate()?;
        Ok(fixture)
    }
}

/// A backend either completed the case or explicitly skipped unsupported semantics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ParityFixtureResult {
    Completed {
        outcome: SemanticOutcome,
    },
    Skipped {
        missing_capabilities: Vec<SemanticDimension>,
        reason: String,
    },
}

impl ParityFixture {
    pub fn from_json(bytes: &[u8]) -> Result<Self, ParityError> {
        let fixture: Self =
            serde_json::from_slice(bytes).map_err(|error| ParityError::Json(error.to_string()))?;
        fixture.validate()?;
        Ok(fixture)
    }

    pub fn to_canonical_json(&self) -> Result<Vec<u8>, ParityError> {
        self.validate()?;
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| ParityError::Json(error.to_string()))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn validate(&self) -> Result<(), ParityError> {
        if self.schema_version != PARITY_FIXTURE_SCHEMA_VERSION {
            return Err(ParityError::UnsupportedSchema(self.schema_version));
        }
        validate_identity("case_id", &self.case_id)?;
        if self.source_revision.is_empty() || self.source_revision.len() > 256 {
            return Err(ParityError::InvalidIdentity("source_revision"));
        }
        validate_identity("run_id", &self.evidence.run_id)?;
        validate_hex("scenario_hash", &self.evidence.scenario_hash, 64)?;
        if self.evidence.observed_at_unix_secs == 0
            || self.evidence.valid_for_secs == 0
            || self.evidence.valid_for_secs > MAX_EVIDENCE_VALIDITY_SECS
        {
            return Err(ParityError::InvalidEvidence);
        }
        require_sorted_unique("capabilities", &self.capabilities)?;
        require_sorted_unique("observed_dimensions", &self.observed_dimensions)?;
        if self.observed_dimensions.is_empty()
            || self
                .observed_dimensions
                .iter()
                .any(|dimension| !self.capabilities.contains(dimension))
        {
            return Err(ParityError::FalseCapability);
        }
        match &self.result {
            ParityFixtureResult::Completed { outcome } => {
                if self.observed_dimensions != self.capabilities {
                    return Err(ParityError::FalseCapability);
                }
                validate_outcome(outcome)
            }
            ParityFixtureResult::Skipped {
                missing_capabilities,
                reason,
            } => {
                require_sorted_unique("missing_capabilities", missing_capabilities)?;
                if missing_capabilities.is_empty() || reason.is_empty() || reason.len() > 1_024 {
                    return Err(ParityError::InvalidSkip);
                }
                if missing_capabilities
                    .iter()
                    .any(|capability| self.capabilities.contains(capability))
                {
                    return Err(ParityError::InvalidSkip);
                }
                Ok(())
            }
        }
    }

    pub fn validate_fresh_at(&self, now_unix_secs: u64) -> Result<(), ParityError> {
        self.validate()?;
        if self.evidence.observed_at_unix_secs > now_unix_secs.saturating_add(MAX_FUTURE_SKEW_SECS)
        {
            return Err(ParityError::FutureEvidence);
        }
        let expires = self
            .evidence
            .observed_at_unix_secs
            .checked_add(self.evidence.valid_for_secs)
            .ok_or(ParityError::InvalidEvidence)?;
        if now_unix_secs > expires {
            return Err(ParityError::StaleEvidence);
        }
        Ok(())
    }
}

/// Result of comparing only dimensions supported and agreed by both backends.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ParityComparison {
    pub status: ParityComparisonStatus,
    pub compared: Vec<SemanticDimension>,
    pub differences: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParityComparisonStatus {
    Match,
    Difference,
    Skipped,
}

/// Projects a deterministic report and trace onto the backend-independent schema.
pub fn deterministic_semantic_outcome(
    report: &ScenarioReport,
    trace: &[TraceEvent],
) -> SemanticOutcome {
    let mut outcome = SemanticOutcome {
        terminal: match report.terminal {
            RunnerTerminal::Success => SemanticTerminal::Success,
            RunnerTerminal::ExpectedFailure => SemanticTerminal::ExpectedFailure,
        },
        authenticated_connections: 0,
        intact_deliveries: 0,
        corrupt_deliveries: 0,
        nat_transitions: BTreeMap::new(),
        firewall_decisions: BTreeMap::new(),
        mobility_transitions: BTreeMap::new(),
        relay_transitions: BTreeMap::new(),
        selected_paths: Vec::new(),
    };

    for observation in &report.observations {
        match &observation.kind {
            ObservationKind::ConnectionState {
                to: ConnectionState::Connected,
                peer_identity: Some(_),
                ..
            } => outcome.authenticated_connections += 1,
            ObservationKind::Delivery {
                expected, actual, ..
            } if expected == actual => outcome.intact_deliveries += 1,
            ObservationKind::Delivery { .. } => outcome.corrupt_deliveries += 1,
            ObservationKind::PathState {
                path, active: true, ..
            } => {
                let path = path.to_string();
                if !outcome.selected_paths.contains(&path) {
                    outcome.selected_paths.push(path);
                }
            }
            ObservationKind::RelayState { online, .. } => increment(
                &mut outcome.relay_transitions,
                if *online {
                    "relay/online"
                } else {
                    "relay/offline"
                },
            ),
            ObservationKind::InterfaceState { up, .. } => increment(
                &mut outcome.mobility_transitions,
                if *up {
                    "interface/up"
                } else {
                    "interface/down"
                },
            ),
            ObservationKind::InterfaceAddress { present, .. } => increment(
                &mut outcome.mobility_transitions,
                if *present {
                    "address/added"
                } else {
                    "address/removed"
                },
            ),
            ObservationKind::HostPower { sleeping, .. } => increment(
                &mut outcome.mobility_transitions,
                if *sleeping {
                    "host/asleep"
                } else {
                    "host/resumed"
                },
            ),
            ObservationKind::RouteState { active, .. } => increment(
                &mut outcome.mobility_transitions,
                if *active {
                    "route/active"
                } else {
                    "route/inactive"
                },
            ),
            ObservationKind::PortMappingState { active, .. } => increment(
                &mut outcome.nat_transitions,
                if *active {
                    "port_mapping/active"
                } else {
                    "port_mapping/inactive"
                },
            ),
            _ => {}
        }
    }

    for event in trace {
        match &event.event {
            TraceEventKind::NatMapping { transition, .. } => increment(
                &mut outcome.nat_transitions,
                &format!(
                    "{}/{}",
                    event.context.nat.as_deref().unwrap_or("unknown"),
                    transition
                ),
            ),
            TraceEventKind::FirewallDecision {
                action, direction, ..
            } => increment(
                &mut outcome.firewall_decisions,
                &format!(
                    "{}/{direction}/{action}",
                    event.context.firewall.as_deref().unwrap_or("unknown")
                ),
            ),
            _ => {}
        }
    }
    outcome
}

/// Compares selected semantic dimensions; virtual timestamps and packet scheduling are absent by
/// construction.
pub fn compare_semantic_outcomes(
    expected: &SemanticOutcome,
    actual: &SemanticOutcome,
    dimensions: &[SemanticDimension],
) -> Result<ParityComparison, ParityError> {
    require_sorted_unique("dimensions", dimensions)?;
    if dimensions.is_empty() {
        return Ok(ParityComparison {
            status: ParityComparisonStatus::Skipped,
            compared: Vec::new(),
            differences: vec!["no common semantic dimensions".to_owned()],
        });
    }
    let mut differences = Vec::new();
    for dimension in dimensions {
        let equal = match dimension {
            SemanticDimension::Terminal => expected.terminal == actual.terminal,
            SemanticDimension::Authentication => {
                expected.authenticated_connections == actual.authenticated_connections
            }
            SemanticDimension::Delivery => {
                (expected.intact_deliveries > 0) == (actual.intact_deliveries > 0)
                    && (expected.corrupt_deliveries == 0) == (actual.corrupt_deliveries == 0)
            }
            SemanticDimension::Nat => expected.nat_transitions == actual.nat_transitions,
            SemanticDimension::Firewall => expected.firewall_decisions == actual.firewall_decisions,
            SemanticDimension::Mobility => {
                expected.mobility_transitions == actual.mobility_transitions
            }
            SemanticDimension::Relay => expected.relay_transitions == actual.relay_transitions,
            SemanticDimension::Path => expected.selected_paths == actual.selected_paths,
        };
        if !equal {
            differences.push(format!("{dimension:?}").to_ascii_lowercase());
        }
    }
    Ok(ParityComparison {
        status: if differences.is_empty() {
            ParityComparisonStatus::Match
        } else {
            ParityComparisonStatus::Difference
        },
        compared: dimensions.to_vec(),
        differences,
    })
}

/// Compares two backend fixtures for the same canonical case.
///
/// Only capabilities declared by both completed fixtures are compared. A backend-declared skip
/// remains a skip and never becomes a match. This lets privileged Patchbay and platform jobs
/// publish partial evidence without silently approximating unsupported scenario actions.
pub fn compare_parity_fixtures(
    expected: &ParityFixture,
    actual: &ParityFixture,
) -> Result<ParityComparison, ParityError> {
    expected.validate()?;
    actual.validate()?;
    if expected.case_id != actual.case_id {
        return Err(ParityError::MismatchedCase {
            expected: expected.case_id.clone(),
            actual: actual.case_id.clone(),
        });
    }
    if expected.evidence.scenario_hash != actual.evidence.scenario_hash {
        return Err(ParityError::MismatchedScenario {
            expected: expected.evidence.scenario_hash.clone(),
            actual: actual.evidence.scenario_hash.clone(),
        });
    }
    let common = expected
        .capabilities
        .iter()
        .filter(|dimension| actual.capabilities.contains(dimension))
        .copied()
        .collect::<Vec<_>>();
    let (expected_outcome, actual_outcome) = match (&expected.result, &actual.result) {
        (
            ParityFixtureResult::Completed { outcome: expected },
            ParityFixtureResult::Completed { outcome: actual },
        ) => (expected, actual),
        _ => {
            return Ok(ParityComparison {
                status: ParityComparisonStatus::Skipped,
                compared: common,
                differences: vec!["one or more backends declared a capability skip".to_owned()],
            });
        }
    };
    compare_semantic_outcomes(expected_outcome, actual_outcome, &common)
}

/// Freshness-enforcing fixture comparison used by operational automation.
pub fn compare_parity_fixtures_at(
    expected: &ParityFixture,
    actual: &ParityFixture,
    now_unix_secs: u64,
) -> Result<ParityComparison, ParityError> {
    expected.validate_fresh_at(now_unix_secs)?;
    actual.validate_fresh_at(now_unix_secs)?;
    compare_parity_fixtures(expected, actual)
}

fn increment(counts: &mut BTreeMap<String, u64>, key: &str) {
    *counts.entry(key.to_owned()).or_default() += 1;
}

fn validate_outcome(outcome: &SemanticOutcome) -> Result<(), ParityError> {
    for path in &outcome.selected_paths {
        if !matches!(path.as_str(), "relay" | "direct_ipv4" | "direct_ipv6") {
            return Err(ParityError::InvalidPath(path.clone()));
        }
    }
    for key in outcome
        .nat_transitions
        .keys()
        .chain(outcome.firewall_decisions.keys())
        .chain(outcome.mobility_transitions.keys())
        .chain(outcome.relay_transitions.keys())
    {
        validate_identity("semantic_key", key)?;
    }
    Ok(())
}

fn validate_identity(field: &'static str, value: &str) -> Result<(), ParityError> {
    if value.is_empty()
        || value.len() > 256
        || value.split('/').any(|segment| {
            segment.is_empty()
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        Err(ParityError::InvalidIdentity(field))
    } else {
        Ok(())
    }
}

fn validate_hex(field: &'static str, value: &str, width: usize) -> Result<(), ParityError> {
    if value.len() == width
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ParityError::InvalidIdentity(field))
    }
}

fn require_sorted_unique<T: Ord>(field: &'static str, values: &[T]) -> Result<(), ParityError> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        Err(ParityError::NonCanonicalList(field))
    } else {
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ParityError {
    Json(String),
    UnsupportedSchema(u16),
    UnsupportedReceiptSchema(u16),
    InvalidIdentity(&'static str),
    NonCanonicalList(&'static str),
    InvalidSkip,
    InvalidEvidence,
    InvalidReceipt,
    FalseCapability,
    StaleEvidence,
    FutureEvidence,
    InvalidPath(String),
    MismatchedCase { expected: String, actual: String },
    MismatchedScenario { expected: String, actual: String },
}

impl fmt::Display for ParityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ParityError {}
