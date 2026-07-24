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

pub const CORPUS_SCHEMA_VERSION: u16 = 1;
const MAX_CORPUS_ENTRIES: usize = 4_096;
const FILES_PER_CORPUS_ENTRY: usize = 2;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorpusReviewState {
    Pending,
    Reviewed,
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
            || self.issue.as_ref().is_some_and(String::is_empty)
        {
            return Err(CorpusError::InvalidMetadata(self.id.clone()));
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
            || self.minimum_simulator_version.as_str() > SIMULATOR_VERSION
            || self
                .maximum_simulator_version
                .as_ref()
                .is_some_and(|maximum| SIMULATOR_VERSION > maximum.as_str())
        {
            return Err(CorpusError::Incompatible(self.id.clone()));
        }
        if let CorpusExpectation::ExpectedFailure { signature } = &self.expectation {
            signature
                .to_canonical_json()
                .map_err(|error| CorpusError::InvalidMetadata(error.to_string()))?;
        }
        Ok(())
    }
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

impl fmt::Display for CorpusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CorpusError {}

#[cfg(test)]
mod tests {
    use super::*;

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
}
