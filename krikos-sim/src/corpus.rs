//! Strict versioned permanent regression corpus.

use std::{
    collections::BTreeSet,
    ffi::OsString,
    fmt, fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    FailureSignature, SCENARIO_SCHEMA_VERSION, SIMULATOR_VERSION, Scenario, ScenarioInventory,
    bounded_io::read_file,
};

pub const CORPUS_SCHEMA_VERSION: u16 = 2;
const MAX_CORPUS_ENTRIES: usize = 4_096;
const FILES_PER_CORPUS_ENTRY: usize = 2;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorpusReviewState {
    Pending,
    Reviewed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorpusReplayEvidence {
    ConfirmedExact,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorpusMinimizationEvidence {
    SignaturePreserving,
}

/// Immutable evidence required when a discovered GitHub issue is promoted into the corpus.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusPromotionEvidence {
    pub signature_digest: String,
    pub minimized_scenario_sha256: String,
    pub source_revision: String,
    pub workflow_run_id: u64,
    pub replay: CorpusReplayEvidence,
    pub minimization: CorpusMinimizationEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "terminal", rename_all = "snake_case", deny_unknown_fields)]
pub enum CorpusExpectation {
    Success,
    ExpectedFailure { signature: FailureSignature },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusMetadata {
    pub schema_version: u16,
    pub id: String,
    pub scenario_file: String,
    pub seed: String,
    pub expectation: CorpusExpectation,
    pub provenance: String,
    pub issue: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promotion: Option<CorpusPromotionEvidence>,
    pub minimum_scenario_schema: u16,
    pub maximum_scenario_schema: u16,
    pub minimum_simulator_version: String,
    pub maximum_simulator_version: Option<String>,
    pub review_state: CorpusReviewState,
    /// Exact behavior-domain counts reviewed with this corpus entry.
    pub inventory: ScenarioInventory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorpusEntry {
    pub metadata: CorpusMetadata,
    pub scenario: Scenario,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Corpus {
    entries: Vec<CorpusEntry>,
}

impl Corpus {
    /// Loads every immediate entry directory and rejects all unenumerated files.
    pub fn load(root: &Path) -> Result<Self, CorpusError> {
        let directories = collect_entry_directories(root, MAX_CORPUS_ENTRIES)?;
        let mut ids = BTreeSet::new();
        let mut entries = Vec::new();
        for directory in directories {
            let files = collect_entry_files(&directory, FILES_PER_CORPUS_ENTRY)?;
            let expected = BTreeSet::from(["metadata.json".into(), "scenario.json".into()]);
            if files != expected {
                return Err(CorpusError::Unenumerated(directory));
            }
            let metadata: CorpusMetadata = serde_json::from_slice(
                &read_file(directory.join("metadata.json")).map_err(CorpusError::Io)?,
            )
            .map_err(|error| CorpusError::Json(error.to_string()))?;
            metadata.validate()?;
            let directory_id = directory
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| {
                    CorpusError::InvalidMetadata("entry path is not UTF-8".to_owned())
                })?;
            if metadata.id != directory_id {
                return Err(CorpusError::IdDirectoryMismatch {
                    id: metadata.id,
                    directory: directory_id.to_owned(),
                });
            }
            if !ids.insert(metadata.id.clone()) {
                return Err(CorpusError::DuplicateId(metadata.id));
            }
            let scenario = Scenario::from_json(
                &read_file(directory.join(&metadata.scenario_file)).map_err(CorpusError::Io)?,
            )
            .map_err(|error| CorpusError::Scenario(error.to_string()))?;
            let actual_inventory = ScenarioInventory::from_scenario(&scenario);
            if metadata.inventory != actual_inventory {
                return Err(CorpusError::InventoryMismatch {
                    id: metadata.id.clone(),
                    expected: Box::new(metadata.inventory.clone()),
                    actual: Box::new(actual_inventory),
                });
            }
            entries.push(CorpusEntry { metadata, scenario });
        }
        if entries.is_empty() {
            return Err(CorpusError::Empty);
        }
        Ok(Self { entries })
    }

    pub fn entries(&self) -> &[CorpusEntry] {
        &self.entries
    }

    /// Executes entries in stable ID order and enforces their declared terminal/signature.
    pub fn test<F>(&self, mut evaluator: F) -> Result<Vec<CorpusReport>, CorpusError>
    where
        F: FnMut(&CorpusEntry) -> Result<Option<FailureSignature>, String>,
    {
        let mut reports = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let actual = evaluator(entry).map_err(|error| CorpusError::Execution {
                id: entry.metadata.id.clone(),
                error,
            })?;
            let matched = match (&entry.metadata.expectation, &actual) {
                (CorpusExpectation::Success, None) => true,
                (
                    CorpusExpectation::ExpectedFailure {
                        signature: expected,
                    },
                    Some(actual),
                ) => expected == actual,
                _ => false,
            };
            if !matched {
                return Err(CorpusError::ExpectationMismatch(entry.metadata.id.clone()));
            }
            reports.push(CorpusReport {
                id: entry.metadata.id.clone(),
                matched,
            });
        }
        Ok(reports)
    }
}

fn collect_entry_directories(root: &Path, maximum: usize) -> Result<Vec<PathBuf>, CorpusError> {
    let mut directories = Vec::new();
    for entry in fs::read_dir(root).map_err(CorpusError::Io)? {
        let entry = entry.map_err(CorpusError::Io)?;
        if !entry.file_type().map_err(CorpusError::Io)?.is_dir() {
            return Err(CorpusError::Unenumerated(entry.path()));
        }
        if directories.len() >= maximum {
            return Err(CorpusError::InvalidMetadata(format!(
                "corpus exceeds {maximum} entries"
            )));
        }
        directories.push(entry.path());
    }
    directories.sort();
    Ok(directories)
}

fn collect_entry_files(
    directory: &Path,
    maximum: usize,
) -> Result<BTreeSet<OsString>, CorpusError> {
    let mut files = BTreeSet::new();
    for entry in fs::read_dir(directory).map_err(CorpusError::Io)? {
        let entry = entry.map_err(CorpusError::Io)?;
        if files.len() >= maximum {
            return Err(CorpusError::Unenumerated(directory.to_path_buf()));
        }
        files.insert(entry.file_name());
    }
    Ok(files)
}

impl CorpusMetadata {
    fn validate(&self) -> Result<(), CorpusError> {
        if self.schema_version != CORPUS_SCHEMA_VERSION
            || self.id.is_empty()
            || self.scenario_file != "scenario.json"
            || self.provenance.is_empty()
            || self.minimum_simulator_version.is_empty()
            || !self.issue.as_ref().is_some_and(|issue| !issue.is_empty())
        {
            return Err(CorpusError::InvalidMetadata(self.id.clone()));
        }
        let issue = self
            .issue
            .as_deref()
            .expect("metadata validation requires issue evidence");
        let github_issue = is_github_issue_url(issue);
        match (github_issue, &self.promotion) {
            (true, Some(promotion)) if promotion.is_valid() => {}
            (false, None) if is_historical_issue_reference(issue) => {}
            _ => return Err(CorpusError::InvalidPromotion(self.id.clone())),
        }
        if self.seed.len() != 64
            || !self
                .seed
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(CorpusError::InvalidSeed(self.id.clone()));
        }
        if self.minimum_scenario_schema > SCENARIO_SCHEMA_VERSION
            || self.maximum_scenario_schema < SCENARIO_SCHEMA_VERSION
            || self.minimum_scenario_schema > self.maximum_scenario_schema
        {
            return Err(CorpusError::Incompatible(self.id.clone()));
        }
        self.validate_simulator_version_range(SIMULATOR_VERSION)?;
        if let CorpusExpectation::ExpectedFailure { signature } = &self.expectation {
            let canonical_signature = signature
                .to_canonical_json()
                .map_err(|error| CorpusError::InvalidMetadata(error.to_string()))?;
            if self.promotion.as_ref().is_some_and(|promotion| {
                blake3::hash(&canonical_signature).to_hex().as_str()
                    == promotion.signature_digest.as_str()
            }) {
                return Err(CorpusError::InvalidPromotion(self.id.clone()));
            }
        }
        Ok(())
    }

    /// Checks `[minimum_simulator_version, maximum_simulator_version]` against
    /// `simulator_version` using numeric per-component comparison, not string
    /// comparison. String comparison sorts "1.0.10" below "1.0.9", so a
    /// naive `>` here can be wrong in either direction once any component
    /// reaches two digits.
    ///
    /// Both sides fail CLOSED on a version string that cannot be parsed as
    /// `MAJOR.MINOR.PATCH`: an unparseable `minimum_simulator_version` is
    /// never treated as satisfied, and an unparseable
    /// `maximum_simulator_version` is never treated as un-exceeded. The
    /// previous string comparison instead had an ambient failure mode on
    /// the maximum side (a wrong `>` result there *admits* an incompatible
    /// corpus entry rather than rejecting a compatible one), which is the
    /// direction that actually matters: silently running a scenario the
    /// simulator no longer supports is worse than the reverse.
    ///
    /// Takes `simulator_version` as a parameter (rather than reading
    /// `SIMULATOR_VERSION` directly) so tests can exercise the double-digit
    /// comparison case end to end without depending on this crate's own
    /// `Cargo.toml` version.
    fn validate_simulator_version_range(
        &self,
        simulator_version: &str,
    ) -> Result<(), CorpusError> {
        let minimum_satisfied = match compare_simulator_versions(
            &self.minimum_simulator_version,
            simulator_version,
        ) {
            Some(order) => order != std::cmp::Ordering::Greater,
            None => false, // unparseable minimum: never treat as satisfied
        };
        let maximum_satisfied = match &self.maximum_simulator_version {
            None => true,
            Some(maximum) => {
                match compare_simulator_versions(simulator_version, maximum) {
                    Some(order) => order != std::cmp::Ordering::Greater,
                    None => false, // unparseable maximum: never treat as satisfied
                }
            }
        };
        if minimum_satisfied && maximum_satisfied {
            Ok(())
        } else {
            Err(CorpusError::Incompatible(self.id.clone()))
        }
    }
}

/// Parses a `MAJOR.MINOR.PATCH` version string into numeric components.
/// Returns `None` for anything else (missing/extra components, non-numeric
/// components, pre-release/build metadata suffixes) so callers can fail
/// closed on malformed input instead of silently guessing via string
/// comparison.
fn parse_simulator_version(value: &str) -> Option<(u64, u64, u64)> {
    let mut parts = value.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next()?.parse::<u64>().ok()?;
    let patch = parts.next()?.parse::<u64>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// Compares two `MAJOR.MINOR.PATCH` version strings numerically,
/// component by component. Returns `None` if either fails to parse.
fn compare_simulator_versions(left: &str, right: &str) -> Option<std::cmp::Ordering> {
    Some(parse_simulator_version(left)?.cmp(&parse_simulator_version(right)?))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorpusReport {
    pub id: String,
    pub matched: bool,
}

#[derive(Debug)]
pub enum CorpusError {
    Io(std::io::Error),
    Json(String),
    Scenario(String),
    Empty,
    Unenumerated(std::path::PathBuf),
    DuplicateId(String),
    IdDirectoryMismatch {
        id: String,
        directory: String,
    },
    InvalidMetadata(String),
    InvalidPromotion(String),
    InvalidSeed(String),
    Incompatible(String),
    InventoryMismatch {
        id: String,
        expected: Box<ScenarioInventory>,
        actual: Box<ScenarioInventory>,
    },
    Execution {
        id: String,
        error: String,
    },
    ExpectationMismatch(String),
}

impl CorpusPromotionEvidence {
    fn is_valid(&self) -> bool {
        is_lower_hex(&self.signature_digest, 64)
            && is_lower_hex(&self.minimized_scenario_sha256, 64)
            && is_lower_hex(&self.source_revision, 40)
            && self.workflow_run_id > 0
    }
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_historical_issue_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn is_github_issue_url(value: &str) -> bool {
    let Some(path) = value.strip_prefix("https://github.com/") else {
        return false;
    };
    let parts = path.split('/').collect::<Vec<_>>();
    parts.len() == 4
        && is_github_path_component(parts[0])
        && is_github_path_component(parts[1])
        && parts[2] == "issues"
        && parts[3]
            .parse::<u64>()
            .is_ok_and(|issue_number| issue_number > 0)
}

fn is_github_path_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

impl fmt::Display for CorpusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CorpusError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_metadata() -> CorpusMetadata {
        CorpusMetadata {
            schema_version: CORPUS_SCHEMA_VERSION,
            id: "regression".to_owned(),
            scenario_file: "scenario.json".to_owned(),
            seed: "1".repeat(64),
            expectation: CorpusExpectation::Success,
            provenance: "reviewed regression".to_owned(),
            issue: Some("historical-regression".to_owned()),
            promotion: None,
            minimum_scenario_schema: SCENARIO_SCHEMA_VERSION,
            maximum_scenario_schema: SCENARIO_SCHEMA_VERSION,
            minimum_simulator_version: SIMULATOR_VERSION.to_owned(),
            maximum_simulator_version: None,
            review_state: CorpusReviewState::Reviewed,
            inventory: ScenarioInventory::default(),
        }
    }

    #[test]
    fn github_issue_requires_typed_promotion_evidence() {
        let mut metadata = valid_metadata();
        metadata.issue = Some("https://github.com/holon-technologies/iroh/issues/42".to_owned());
        assert!(matches!(
            metadata.validate(),
            Err(CorpusError::InvalidPromotion(_))
        ));

        metadata.promotion = Some(CorpusPromotionEvidence {
            signature_digest: "2".repeat(64),
            minimized_scenario_sha256: "3".repeat(64),
            source_revision: "4".repeat(40),
            workflow_run_id: 42,
            replay: CorpusReplayEvidence::ConfirmedExact,
            minimization: CorpusMinimizationEvidence::SignaturePreserving,
        });
        metadata.validate().expect("typed promotion evidence");

        let original_signature = FailureSignature {
            schema_version: crate::FAILURE_SIGNATURE_SCHEMA_VERSION,
            invariant: None,
            entities: Vec::new(),
            terminal_class: crate::TerminalFailureClass::InvariantSafety,
            causal_event_count: 0,
            causal_suffix_digest: "5".repeat(64),
        };
        let original_digest = blake3::hash(
            &original_signature
                .to_canonical_json()
                .expect("valid original signature"),
        )
        .to_hex()
        .to_string();
        metadata.expectation = CorpusExpectation::ExpectedFailure {
            signature: original_signature,
        };
        metadata
            .promotion
            .as_mut()
            .expect("GitHub promotion evidence")
            .signature_digest = original_digest;
        assert!(matches!(
            metadata.validate(),
            Err(CorpusError::InvalidPromotion(_))
        ));

        metadata.expectation = CorpusExpectation::Success;

        metadata.issue = Some("historical-regression".to_owned());
        assert!(matches!(
            metadata.validate(),
            Err(CorpusError::InvalidPromotion(_))
        ));
    }

    #[test]
    fn corpus_directory_scan_rejects_before_exceeding_the_limit() {
        let root = tempfile::tempdir().expect("temporary corpus");
        std::fs::create_dir(root.path().join("a")).expect("first corpus entry");
        std::fs::create_dir(root.path().join("b")).expect("second corpus entry");

        let error = collect_entry_directories(root.path(), 1)
            .expect_err("the second entry must exceed the injected limit");

        assert!(matches!(error, CorpusError::InvalidMetadata(_)));
    }

    #[test]
    fn corpus_file_scan_rejects_the_first_unexpected_file() {
        let root = tempfile::tempdir().expect("temporary corpus entry");
        std::fs::write(root.path().join("metadata.json"), b"{}").expect("metadata fixture");
        std::fs::write(root.path().join("scenario.json"), b"{}").expect("scenario fixture");
        std::fs::write(root.path().join("unexpected.json"), b"{}").expect("unexpected fixture");

        let error = collect_entry_files(root.path(), 2)
            .expect_err("the third file must exceed the injected limit");

        assert!(matches!(error, CorpusError::Unenumerated(_)));
    }

    #[test]
    fn simulator_version_comparison_is_numeric_not_lexicographic() {
        use std::cmp::Ordering;

        // Lexicographically, "1.0.10" < "1.0.9" (the '1' byte loses to the
        // '9' byte at the first differing position), which is backwards:
        // 1.0.10 is the newer patch release. A real per-component
        // comparison must get both directions right.
        assert_eq!(
            compare_simulator_versions("1.0.10", "1.0.9"),
            Some(Ordering::Greater)
        );
        assert_eq!(
            compare_simulator_versions("1.0.9", "1.0.10"),
            Some(Ordering::Less)
        );
        assert_eq!(
            compare_simulator_versions("1.0.9", "1.0.9"),
            Some(Ordering::Equal)
        );

        assert_eq!(parse_simulator_version("1.0.10"), Some((1, 0, 10)));
        assert_eq!(parse_simulator_version("1.0"), None);
        assert_eq!(parse_simulator_version("1.0.10.1"), None);
        assert_eq!(parse_simulator_version("1.0.x"), None);
    }

    #[test]
    fn minimum_simulator_version_double_digit_floor_is_enforced_numerically() {
        let mut metadata = valid_metadata();
        // A lexicographic ">" would read "1.0.10" > "1.0.9" as false (the
        // '1' byte loses to the '9' byte), so the old check would have
        // wrongly treated simulator 1.0.9 as satisfying this floor. It
        // does not: 1.0.10 is numerically newer than 1.0.9.
        metadata.minimum_simulator_version = "1.0.10".to_owned();
        metadata.maximum_simulator_version = None;

        assert!(matches!(
            metadata.validate_simulator_version_range("1.0.9"),
            Err(CorpusError::Incompatible(_))
        ));
        metadata
            .validate_simulator_version_range("1.0.10")
            .expect("simulator at exactly the floor satisfies it");
        metadata
            .validate_simulator_version_range("1.0.11")
            .expect("simulator above the floor satisfies it");
    }

    #[test]
    fn maximum_simulator_version_double_digit_ceiling_is_enforced_numerically_and_fails_closed() {
        // This is the direction that fails OPEN under lexicographic
        // comparison: "1.0.10" > "1.0.9" is lexicographically false, so
        // the old check would have let simulator 1.0.10 run against a
        // corpus entry capped at maximum 1.0.9 -- admitting an
        // incompatible entry instead of rejecting it.
        let mut metadata = valid_metadata();
        metadata.minimum_simulator_version = "1.0.0".to_owned();
        metadata.maximum_simulator_version = Some("1.0.9".to_owned());

        assert!(matches!(
            metadata.validate_simulator_version_range("1.0.10"),
            Err(CorpusError::Incompatible(_))
        ));
        metadata
            .validate_simulator_version_range("1.0.9")
            .expect("simulator at exactly the ceiling satisfies it");
        metadata
            .validate_simulator_version_range("1.0.8")
            .expect("simulator below the ceiling satisfies it");
    }

    #[test]
    fn malformed_simulator_version_bounds_fail_closed() {
        let mut metadata = valid_metadata();
        metadata.minimum_simulator_version = "not-a-version".to_owned();
        metadata.maximum_simulator_version = None;
        assert!(matches!(
            metadata.validate_simulator_version_range("1.0.0"),
            Err(CorpusError::Incompatible(_))
        ));

        let mut metadata = valid_metadata();
        metadata.minimum_simulator_version = "1.0.0".to_owned();
        metadata.maximum_simulator_version = Some("not-a-version".to_owned());
        assert!(matches!(
            metadata.validate_simulator_version_range("1.0.0"),
            Err(CorpusError::Incompatible(_))
        ));
    }
}
