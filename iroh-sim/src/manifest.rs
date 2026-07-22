//! Strict, versioned run identity and replay compatibility.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};

/// Current run-manifest schema.
pub const MANIFEST_SCHEMA_VERSION: u16 = 3;
/// Simulator implementation version written into new manifests.
pub const SIMULATOR_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Exact source tree identity of a run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    /// Source-control revision.
    pub revision: String,
    /// Digest of tracked and untracked changes, absent for a clean tree.
    pub dirty_digest: Option<String>,
}

/// Backend capabilities that determine which scenario actions are sound.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendCapabilities {
    /// Runtime capabilities are injected and traced.
    pub controlled_runtime: bool,
    /// Virtual monotonic time is complete for supported paths.
    pub virtual_time: bool,
    /// Synthetic direct IP sockets are available.
    pub synthetic_ip: bool,
    /// NAT behavior is simulator-owned.
    pub nat: bool,
    /// Production relay sessions run on synthetic streams.
    pub relay: bool,
    /// Discovery inputs and time are simulator-owned.
    pub discovery: bool,
    /// Interface and route changes are simulator-owned.
    #[serde(default)]
    pub mobility: bool,
}

impl BackendCapabilities {
    /// Stage 1 capability set: controlled runtime identity with known OS escapes.
    pub const fn stage1_tokio() -> Self {
        Self {
            controlled_runtime: true,
            virtual_time: false,
            synthetic_ip: false,
            nat: false,
            relay: false,
            discovery: false,
            mobility: false,
        }
    }

    /// Deterministic kernel capability set with virtual time and synthetic IP.
    pub const fn deterministic_kernel() -> Self {
        Self {
            controlled_runtime: true,
            virtual_time: true,
            synthetic_ip: true,
            nat: false,
            relay: false,
            discovery: false,
            mobility: false,
        }
    }
}

/// Hard bounds that turn stalls and growth into reproducible outcomes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunBudgets {
    /// Maximum structured events.
    pub max_events: u64,
    /// Maximum virtual duration.
    pub max_virtual_time_nanos: u64,
    /// Maximum simultaneously owned tasks.
    pub max_tasks: u64,
    /// Maximum packets created by the network model.
    pub max_packets: u64,
}

/// Honest determinism classification for an artifact.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeterminismGrade {
    /// Runtime identity and observations are controlled, but OS/environment escapes remain.
    ControlledRuntime,
    /// Every supported behavior-affecting capability is simulator-owned.
    FullyDeterministic,
    /// All non-cryptographic behavior is deterministic; opaque production ciphertext is compared
    /// semantically.
    SemanticallyDeterministic,
    /// The run intentionally uses a realistic nondeterministic backend.
    RealEnvironment,
}

/// Cryptography lane used by one simulator run.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoMode {
    /// Run-owned deterministic entropy and deterministic X25519 for byte replay.
    DeterministicTest,
    /// The normal configured production cryptography provider and OS entropy.
    ProductionProvider,
}

/// Immutable trace comparison contract selected by the manifest.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceComparisonMode {
    /// Compare every serialized event field, including encrypted packet hashes.
    Raw,
    /// Normalize only documented opaque fields before comparison.
    Semantic,
}

/// Complete identity required to reproduce or reject a run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunManifest {
    /// Manifest schema version.
    pub schema_version: u16,
    /// Simulator implementation version.
    pub simulator_version: String,
    /// Exact source identity.
    pub source: SourceIdentity,
    /// Lowercase 32-byte hexadecimal behavioral root seed.
    pub root_seed: String,
    /// Stable scenario name.
    pub scenario_id: String,
    /// Digest of normalized scenario input.
    pub scenario_hash: String,
    /// Stable key-sorted configuration.
    pub normalized_config: BTreeMap<String, String>,
    /// Sorted enabled features.
    pub features: Vec<String>,
    /// Deterministic wall-clock epoch.
    pub wall_clock_epoch_secs: u64,
    /// Backend capability declaration.
    pub backend: BackendCapabilities,
    /// Run bounds.
    pub budgets: RunBudgets,
    /// Scheduler policy identifier.
    pub scheduling_profile: String,
    /// Fault policy identifier.
    pub fault_profile: String,
    /// Lowercase hexadecimal Cargo.lock digest.
    pub lockfile_digest: String,
    /// Cryptography lane installed for this run.
    pub crypto_mode: CryptoMode,
    /// Immutable replay comparison policy.
    pub trace_comparison: TraceComparisonMode,
    /// Sorted test substitutions that reduce production fidelity without becoming escapes.
    pub fidelity_exceptions: Vec<String>,
    /// Claimed determinism level.
    pub determinism_grade: DeterminismGrade,
    /// Explicit uncontrolled boundaries used by this run.
    pub escapes: Vec<String>,
    /// Marks construction paths that must never be selected by normal production builders.
    pub unsafe_test_only: bool,
}

impl RunManifest {
    /// Parses and validates a strict JSON manifest.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ManifestError> {
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|error| ManifestError::Json(error.to_string()))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Encodes stable pretty JSON after validation.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, ManifestError> {
        self.validate()?;
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| ManifestError::Json(error.to_string()))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Validates schema, normalized identity fields, bounds, and path hygiene.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(ManifestError::UnsupportedSchema(self.schema_version));
        }
        if self.simulator_version.is_empty()
            || self.source.revision.is_empty()
            || self.scenario_id.is_empty()
            || self.scheduling_profile.is_empty()
            || self.fault_profile.is_empty()
        {
            return Err(ManifestError::EmptyIdentity);
        }
        validate_hex("root_seed", &self.root_seed, 64)?;
        validate_hex("scenario_hash", &self.scenario_hash, 64)?;
        validate_hex("lockfile_digest", &self.lockfile_digest, 64)?;
        if let Some(digest) = &self.source.dirty_digest {
            validate_hex("dirty_digest", digest, 64)?;
        }
        if self.budgets.max_events == 0
            || self.budgets.max_virtual_time_nanos == 0
            || self.budgets.max_tasks == 0
            || self.budgets.max_packets == 0
        {
            return Err(ManifestError::ZeroBudget);
        }
        if !is_sorted_unique(&self.features)
            || !is_sorted_unique(&self.escapes)
            || !is_sorted_unique(&self.fidelity_exceptions)
        {
            return Err(ManifestError::NonCanonicalList);
        }
        if self
            .escapes
            .iter()
            .chain(&self.fidelity_exceptions)
            .chain(self.normalized_config.values())
            .any(|value| looks_like_host_path(value))
        {
            return Err(ManifestError::HostPath);
        }
        let deterministic_test = self.determinism_grade == DeterminismGrade::FullyDeterministic
            && self.crypto_mode == CryptoMode::DeterministicTest
            && self.trace_comparison == TraceComparisonMode::Raw
            && self.escapes.is_empty()
            && self.fidelity_exceptions == ["deterministic_test_crypto"];
        let production_crypto = self.determinism_grade
            == DeterminismGrade::SemanticallyDeterministic
            && self.crypto_mode == CryptoMode::ProductionProvider
            && self.trace_comparison == TraceComparisonMode::Semantic
            && self.escapes == ["production_crypto_entropy"]
            && self.fidelity_exceptions.is_empty();
        let realistic = self.determinism_grade == DeterminismGrade::RealEnvironment;
        if (!deterministic_test && !production_crypto && !realistic)
            || ((deterministic_test || production_crypto)
                && (!self.backend.virtual_time || !self.backend.synthetic_ip))
        {
            return Err(ManifestError::InvalidDeterminismGrade);
        }
        Ok(())
    }

    /// Captures the fields that must match before replay begins.
    pub fn replay_identity(&self) -> ReplayIdentity {
        ReplayIdentity {
            schema_version: self.schema_version,
            simulator_version: self.simulator_version.clone(),
            source: self.source.clone(),
            scenario_hash: self.scenario_hash.clone(),
            normalized_config: self.normalized_config.clone(),
            features: self.features.clone(),
            lockfile_digest: self.lockfile_digest.clone(),
        }
    }

    /// Rejects replay under a silently different implementation or input identity.
    pub fn check_compatible(&self, current: &ReplayIdentity) -> Result<(), CompatibilityError> {
        let expected = self.replay_identity();
        if expected.schema_version != current.schema_version {
            return Err(CompatibilityError::ManifestSchema);
        }
        if expected.simulator_version != current.simulator_version {
            return Err(CompatibilityError::SimulatorVersion);
        }
        if expected.source.revision != current.source.revision {
            return Err(CompatibilityError::SourceRevision);
        }
        if expected.source.dirty_digest != current.source.dirty_digest {
            return Err(CompatibilityError::DirtyTree);
        }
        if expected.scenario_hash != current.scenario_hash {
            return Err(CompatibilityError::Scenario);
        }
        if expected.normalized_config != current.normalized_config
            || expected.features != current.features
        {
            return Err(CompatibilityError::Configuration);
        }
        if expected.lockfile_digest != current.lockfile_digest {
            return Err(CompatibilityError::Lockfile);
        }
        Ok(())
    }
}

/// Current environment identity compared before replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayIdentity {
    /// Manifest schema.
    pub schema_version: u16,
    /// Simulator version.
    pub simulator_version: String,
    /// Source identity.
    pub source: SourceIdentity,
    /// Normalized scenario digest.
    pub scenario_hash: String,
    /// Normalized configuration.
    pub normalized_config: BTreeMap<String, String>,
    /// Enabled features.
    pub features: Vec<String>,
    /// Dependency lock digest.
    pub lockfile_digest: String,
}

fn validate_hex(field: &'static str, value: &str, length: usize) -> Result<(), ManifestError> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ManifestError::InvalidHex(field));
    }
    Ok(())
}

fn is_sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn looks_like_host_path(value: &str) -> bool {
    std::path::Path::new(value).is_absolute()
        || value.starts_with("~/")
        || (value.len() >= 3
            && value.as_bytes()[1] == b':'
            && matches!(value.as_bytes()[2], b'/' | b'\\'))
}

/// Invalid or non-canonical run manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestError {
    /// JSON could not be decoded or encoded.
    Json(String),
    /// Schema is not supported by this source revision.
    UnsupportedSchema(u16),
    /// A required identity field is empty.
    EmptyIdentity,
    /// A named digest or seed is malformed.
    InvalidHex(&'static str),
    /// At least one hard run budget is zero.
    ZeroBudget,
    /// A normalized list is not sorted and unique.
    NonCanonicalList,
    /// Host-specific path data would make artifacts non-portable or sensitive.
    HostPath,
    /// A fully deterministic grade contradicts backend capabilities or escapes.
    InvalidDeterminismGrade,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(f, "manifest JSON is invalid: {error}"),
            Self::UnsupportedSchema(version) => write!(f, "unsupported manifest schema {version}"),
            Self::EmptyIdentity => f.write_str("manifest contains an empty identity field"),
            Self::InvalidHex(field) => write!(f, "manifest field {field} is not canonical hex"),
            Self::ZeroBudget => f.write_str("manifest run budgets must be nonzero"),
            Self::NonCanonicalList => f.write_str("manifest lists must be sorted and unique"),
            Self::HostPath => f.write_str("manifest contains a host-specific path"),
            Self::InvalidDeterminismGrade => {
                f.write_str("determinism grade contradicts capabilities")
            }
        }
    }
}

impl std::error::Error for ManifestError {}

/// Exact replay identity mismatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityError {
    /// Manifest schema differs.
    ManifestSchema,
    /// Simulator implementation differs.
    SimulatorVersion,
    /// Source revision differs.
    SourceRevision,
    /// Dirty-tree identity differs.
    DirtyTree,
    /// Scenario input differs.
    Scenario,
    /// Feature or normalized configuration differs.
    Configuration,
    /// Dependency lockfile differs.
    Lockfile,
}

impl fmt::Display for CompatibilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ManifestSchema => "manifest schema mismatch",
            Self::SimulatorVersion => "simulator version mismatch",
            Self::SourceRevision => "source revision mismatch",
            Self::DirtyTree => "dirty source digest mismatch",
            Self::Scenario => "scenario hash mismatch",
            Self::Configuration => "normalized configuration mismatch",
            Self::Lockfile => "dependency lockfile mismatch",
        };
        f.write_str(message)
    }
}

impl std::error::Error for CompatibilityError {}
