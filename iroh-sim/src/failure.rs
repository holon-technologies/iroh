//! Stable failure identities, immutable diagnostic bundles, and replay comparison.

use std::{collections::BTreeMap, fmt, fs, path::Path};

use iroh_runtime::{TraceEvent, TraceEventKind, TraceSequence};
use serde::{Deserialize, Serialize};

use crate::{
    ArtifactError, ArtifactStore, InvariantClass, InvariantName, InvariantSnapshot,
    KernelSchedulerSnapshot, KernelTaskSnapshot, Observation, ReferenceModelSnapshot,
    ResourceLedgerSnapshot, RunnerError, Scenario, ScenarioInventory, first_trace_divergence,
    normalized_trace_json,
};

/// Current normalized failure-signature schema.
pub const FAILURE_SIGNATURE_SCHEMA_VERSION: u16 = 1;
/// Current failure-artifact index schema.
pub const FAILURE_ARTIFACT_SCHEMA_VERSION: u16 = 3;
const MAX_CAUSAL_SUFFIX_EVENTS: usize = 256;

/// Typed terminal class used for signature matching rather than display text.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalFailureClass {
    InvariantSafety,
    InvariantBoundedLiveness,
    InvariantCleanup,
    ModelState,
    ModelMismatch,
    Action,
    TriggerStall,
    UnsupportedCapability,
    UnsupportedAction,
    UnsupportedFault,
    MissingEntity,
    ResourceLeak,
    Cleanup,
    KernelLimit,
    BridgeWatchdog,
    Trace,
    ArtifactEncoding,
    TimelineOverflow,
    ObservationOverflow,
}

impl TerminalFailureClass {
    /// Stable wire spelling included in diagnostics and corpus metadata.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvariantSafety => "invariant/safety",
            Self::InvariantBoundedLiveness => "invariant/bounded_liveness",
            Self::InvariantCleanup => "invariant/cleanup",
            Self::ModelState => "model/state",
            Self::ModelMismatch => "model/mismatch",
            Self::Action => "action",
            Self::TriggerStall => "trigger_stall",
            Self::UnsupportedCapability => "unsupported/capability",
            Self::UnsupportedAction => "unsupported/action",
            Self::UnsupportedFault => "unsupported/fault",
            Self::MissingEntity => "missing_entity",
            Self::ResourceLeak => "resource_leak",
            Self::Cleanup => "cleanup",
            Self::KernelLimit => "kernel_limit",
            Self::BridgeWatchdog => "bridge_watchdog",
            Self::Trace => "trace",
            Self::ArtifactEncoding => "artifact_encoding",
            Self::TimelineOverflow => "timeline_overflow",
            Self::ObservationOverflow => "observation_overflow",
        }
    }
}

/// Versioned normalized identity of one reproducible failure.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FailureSignature {
    pub schema_version: u16,
    pub invariant: Option<InvariantName>,
    pub entities: Vec<String>,
    pub terminal_class: TerminalFailureClass,
    pub causal_event_count: u16,
    pub causal_suffix_digest: String,
}

impl FailureSignature {
    /// Derives a signature from typed failure data and a bounded causal trace suffix.
    pub fn from_runner_error(
        error: &RunnerError,
        trace: &[TraceEvent],
        max_suffix_events: usize,
    ) -> Result<Self, FailureError> {
        if max_suffix_events == 0 || max_suffix_events > MAX_CAUSAL_SUFFIX_EVENTS {
            return Err(FailureError::InvalidSuffixBound(max_suffix_events));
        }
        let (terminal_class, invariant, mut entities) = classify(error);
        entities.sort();
        entities.dedup();
        let suffix = causal_suffix(error, trace, max_suffix_events);
        let mut bytes = Vec::new();
        for event in &suffix {
            bytes.extend(
                normalized_trace_json(event)
                    .map_err(|error| FailureError::Encoding(error.to_string()))?,
            );
            bytes.push(b'\n');
        }
        Ok(Self {
            schema_version: FAILURE_SIGNATURE_SCHEMA_VERSION,
            invariant,
            entities,
            terminal_class,
            causal_event_count: u16::try_from(suffix.len())
                .expect("causal suffix hard bound fits u16"),
            causal_suffix_digest: blake3::hash(&bytes).to_hex().to_string(),
        })
    }

    /// Parses and validates a strict signature document.
    pub fn from_json(bytes: &[u8]) -> Result<Self, FailureError> {
        let signature: Self = serde_json::from_slice(bytes)
            .map_err(|error| FailureError::Encoding(error.to_string()))?;
        signature.validate()?;
        Ok(signature)
    }

    /// Encodes stable pretty JSON.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, FailureError> {
        self.validate()?;
        canonical_json(self)
    }

    fn validate(&self) -> Result<(), FailureError> {
        if self.schema_version != FAILURE_SIGNATURE_SCHEMA_VERSION {
            return Err(FailureError::UnsupportedSignatureSchema(
                self.schema_version,
            ));
        }
        if self.causal_event_count as usize > MAX_CAUSAL_SUFFIX_EVENTS
            || self.entities.windows(2).any(|pair| pair[0] >= pair[1])
            || !is_digest(&self.causal_suffix_digest)
        {
            return Err(FailureError::InvalidSignature);
        }
        Ok(())
    }
}

fn classify(error: &RunnerError) -> (TerminalFailureClass, Option<InvariantName>, Vec<String>) {
    match error {
        RunnerError::Invariant(failure) => (
            match failure.class {
                InvariantClass::Safety => TerminalFailureClass::InvariantSafety,
                InvariantClass::BoundedLiveness => TerminalFailureClass::InvariantBoundedLiveness,
                InvariantClass::Cleanup => TerminalFailureClass::InvariantCleanup,
            },
            Some(failure.name),
            failure.entities.clone(),
        ),
        RunnerError::InvariantEngine(_) => (TerminalFailureClass::Action, None, Vec::new()),
        RunnerError::ModelState { entity, .. } => {
            (TerminalFailureClass::ModelState, None, vec![entity.clone()])
        }
        RunnerError::ModelMismatch { action, .. } => (
            TerminalFailureClass::ModelMismatch,
            None,
            vec![action.clone()],
        ),
        RunnerError::TriggerStall(actions) => {
            (TerminalFailureClass::TriggerStall, None, actions.clone())
        }
        RunnerError::UnsupportedCapabilities(capabilities) => (
            TerminalFailureClass::UnsupportedCapability,
            None,
            capabilities.iter().map(ToString::to_string).collect(),
        ),
        RunnerError::UnsupportedAction(action) => (
            TerminalFailureClass::UnsupportedAction,
            None,
            vec![(*action).to_owned()],
        ),
        RunnerError::UnsupportedFaultRule(rule) => (
            TerminalFailureClass::UnsupportedFault,
            None,
            vec![rule.clone()],
        ),
        RunnerError::MissingRuntimeEntity(entity) => (
            TerminalFailureClass::MissingEntity,
            None,
            vec![entity.clone()],
        ),
        RunnerError::ResourceLeak(_) | RunnerError::Ledger(_) => {
            (TerminalFailureClass::ResourceLeak, None, Vec::new())
        }
        RunnerError::TerminalNotAllowed(terminal) => (
            TerminalFailureClass::Action,
            None,
            vec![(*terminal).to_owned()],
        ),
        RunnerError::CleanupAfterFailure { .. } => {
            (TerminalFailureClass::Cleanup, None, Vec::new())
        }
        RunnerError::Kernel(_) | RunnerError::Network(_) => {
            (TerminalFailureClass::KernelLimit, None, Vec::new())
        }
        RunnerError::Driver(_) => (TerminalFailureClass::BridgeWatchdog, None, Vec::new()),
        RunnerError::Trace(_) => (TerminalFailureClass::Trace, None, Vec::new()),
        RunnerError::Encoding(_) => (TerminalFailureClass::ArtifactEncoding, None, Vec::new()),
        RunnerError::TimelineOverflow => (TerminalFailureClass::TimelineOverflow, None, Vec::new()),
        RunnerError::ObservationOverflow | RunnerError::PayloadOverflow => {
            (TerminalFailureClass::ObservationOverflow, None, Vec::new())
        }
        RunnerError::Scenario(_)
        | RunnerError::Endpoint(_)
        | RunnerError::Operation(_)
        | RunnerError::Backend(_)
        | RunnerError::Discovery(_)
        | RunnerError::Observation(_) => (TerminalFailureClass::Action, None, Vec::new()),
    }
}

fn causal_suffix<'a>(
    error: &RunnerError,
    trace: &'a [TraceEvent],
    limit: usize,
) -> Vec<&'a TraceEvent> {
    let failure_invariant = match error {
        RunnerError::Invariant(failure) => Some(format!("{:?}", failure.name).to_ascii_lowercase()),
        _ => None,
    };
    let terminal = trace
        .iter()
        .rev()
        .find(|event| {
            failure_invariant.as_ref().is_some_and(|name| {
                event.context.invariant.as_ref() == Some(name)
                    && matches!(event.event, TraceEventKind::InvariantFailed { .. })
            })
        })
        .or_else(|| trace.last());
    let Some(mut current) = terminal else {
        return Vec::new();
    };
    let by_sequence: BTreeMap<TraceSequence, &TraceEvent> =
        trace.iter().map(|event| (event.sequence, event)).collect();
    let mut suffix = Vec::new();
    loop {
        suffix.push(current);
        if suffix.len() == limit {
            break;
        }
        let Some(parent) = current.causal_parent else {
            if suffix.len() == 1 {
                return trace
                    .iter()
                    .rev()
                    .take(limit)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
            }
            break;
        };
        let Some(parent_event) = by_sequence.get(&parent) else {
            break;
        };
        current = parent_event;
    }
    suffix.reverse();
    suffix
}

/// Immutable artifact index written last as the bundle commit marker.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FailureArtifactIndex {
    pub schema_version: u16,
    pub files: BTreeMap<String, String>,
    pub trace_chunks: u64,
    pub events_per_chunk: u64,
}

/// Inputs required to persist one failing run.
#[derive(Debug)]
pub struct FailureArtifactBundle<'a> {
    pub scenario: &'a Scenario,
    pub error: &'a RunnerError,
    pub signature: &'a FailureSignature,
    pub invariants: &'a InvariantSnapshot,
    pub resources: &'a ResourceLedgerSnapshot,
    pub model: Option<&'a ReferenceModelSnapshot>,
    pub observations: Option<&'a [Observation]>,
    pub virtual_time_nanos: Option<u64>,
    pub scheduler: Option<&'a KernelSchedulerSnapshot>,
    pub tasks: Option<&'a [KernelTaskSnapshot]>,
    pub trace: &'a [TraceEvent],
    pub events_per_chunk: usize,
}

impl FailureArtifactBundle<'_> {
    /// Writes every immutable file and publishes the integrity index last.
    pub fn write(&self, store: &ArtifactStore) -> Result<FailureArtifactIndex, FailureError> {
        if self.events_per_chunk == 0 {
            return Err(FailureError::InvalidChunkSize);
        }
        self.signature.validate()?;
        let scenario = self
            .scenario
            .to_canonical_json()
            .map_err(|error| FailureError::Encoding(error.to_string()))?;
        let terminal = canonical_json(&TerminalFailureReport {
            terminal_class: self.signature.terminal_class,
            error: self.error.to_string(),
            signature_digest: blake3::hash(&self.signature.to_canonical_json()?)
                .to_hex()
                .to_string(),
            model: self.model,
            observations: self.observations,
            virtual_time_nanos: self.virtual_time_nanos,
        })?;
        let signature = self.signature.to_canonical_json()?;
        let invariants = canonical_json(self.invariants)?;
        let resources = canonical_json(self.resources)?;
        let scheduler = canonical_json(&self.scheduler)?;
        let tasks = canonical_json(&self.tasks)?;
        let inventory = canonical_json(&ScenarioInventory::from_scenario(self.scenario))?;
        let trace = normalized_trace_bytes(self.trace)?;
        let raw_trace = raw_trace_bytes(self.trace)?;
        let decisions = decision_prefix_bytes(self.trace)?;
        let mut files = BTreeMap::new();
        for (name, bytes) in [
            ("scenario.json", scenario),
            ("terminal-report.json", terminal),
            ("invariant-snapshot.json", invariants),
            ("failure-signature.json", signature),
            ("resource-snapshot.json", resources),
            ("scheduler-snapshot.json", scheduler),
            ("task-ownership.json", tasks),
            ("scenario-inventory.json", inventory),
            ("decision-prefix.jsonl", decisions),
            ("trace.jsonl", trace),
            ("trace.raw.jsonl", raw_trace),
        ] {
            write_indexed(store, &mut files, name, &bytes)?;
        }
        let mut trace_chunks = 0u64;
        for (ordinal, chunk) in self.trace.chunks(self.events_per_chunk).enumerate() {
            let name = format!("trace.chunk.{ordinal:08}.jsonl");
            let bytes = normalized_trace_bytes(chunk)?;
            write_indexed(store, &mut files, &name, &bytes)?;
            trace_chunks = trace_chunks
                .checked_add(1)
                .ok_or(FailureError::ChunkCountOverflow)?;
        }
        let index = FailureArtifactIndex {
            schema_version: FAILURE_ARTIFACT_SCHEMA_VERSION,
            files,
            trace_chunks,
            events_per_chunk: u64::try_from(self.events_per_chunk)
                .map_err(|_| FailureError::InvalidChunkSize)?,
        };
        store.write_atomic("failure-artifacts.json", &canonical_json(&index)?)?;
        Ok(index)
    }
}

#[derive(Serialize)]
struct TerminalFailureReport<'a> {
    terminal_class: TerminalFailureClass,
    error: String,
    signature_digest: String,
    model: Option<&'a ReferenceModelSnapshot>,
    observations: Option<&'a [Observation]>,
    virtual_time_nanos: Option<u64>,
}

fn write_indexed(
    store: &ArtifactStore,
    files: &mut BTreeMap<String, String>,
    name: &str,
    bytes: &[u8],
) -> Result<(), FailureError> {
    let destination = store.root().join(name);
    if destination.exists() {
        let existing = fs::read(&destination)
            .map_err(|error| FailureError::Artifact(ArtifactError::Io(error)))?;
        if existing != bytes {
            return Err(FailureError::Artifact(ArtifactError::AlreadyExists(
                destination,
            )));
        }
    } else {
        store.write_atomic(name, bytes)?;
    }
    files.insert(name.to_owned(), blake3::hash(bytes).to_hex().to_string());
    Ok(())
}

/// Verifies the committed file set, contiguous chunks, final newline, and file digests.
pub fn verify_failure_artifacts(root: &Path) -> Result<FailureArtifactIndex, FailureReplayError> {
    let index_path = root.join("failure-artifacts.json");
    let index: FailureArtifactIndex = serde_json::from_slice(
        &fs::read(&index_path).map_err(|_| FailureReplayError::MissingIndex)?,
    )
    .map_err(|error| FailureReplayError::InvalidIndex(error.to_string()))?;
    if index.schema_version != FAILURE_ARTIFACT_SCHEMA_VERSION || index.events_per_chunk == 0 {
        return Err(FailureReplayError::InvalidIndex(
            "unsupported schema or zero chunk size".to_owned(),
        ));
    }
    for ordinal in 0..index.trace_chunks {
        let name = format!("trace.chunk.{ordinal:08}.jsonl");
        let bytes =
            fs::read(root.join(&name)).map_err(|_| FailureReplayError::MissingChunk { ordinal })?;
        if bytes.last() != Some(&b'\n') {
            return Err(FailureReplayError::TruncatedChunk { ordinal });
        }
        verify_digest(&index, &name, &bytes)?;
    }
    for (name, expected) in &index.files {
        if name.starts_with("trace.chunk.") {
            continue;
        }
        let bytes = fs::read(root.join(name))
            .map_err(|_| FailureReplayError::MissingArtifact { name: name.clone() })?;
        let actual = blake3::hash(&bytes).to_hex().to_string();
        if &actual != expected {
            return Err(match name.as_str() {
                "scenario.json" => FailureReplayError::ScenarioManifestDisagreement,
                "failure-signature.json" => FailureReplayError::SignatureArtifactMismatch,
                _ => FailureReplayError::ArtifactDigestMismatch { name: name.clone() },
            });
        }
    }
    Ok(index)
}

fn verify_digest(
    index: &FailureArtifactIndex,
    name: &str,
    bytes: &[u8],
) -> Result<(), FailureReplayError> {
    let Some(expected) = index.files.get(name) else {
        return Err(FailureReplayError::UnindexedChunk {
            name: name.to_owned(),
        });
    };
    if blake3::hash(bytes).to_hex().as_str() != expected {
        return Err(FailureReplayError::ArtifactDigestMismatch {
            name: name.to_owned(),
        });
    }
    Ok(())
}

/// Compares terminal identity before the full trace to preserve useful error classification.
pub fn compare_failure_replay(
    expected_signature: &FailureSignature,
    actual_signature: Option<&FailureSignature>,
    expected_trace: &[TraceEvent],
    actual_trace: &[TraceEvent],
) -> Result<(), FailureReplayError> {
    let actual_signature = actual_signature.ok_or(FailureReplayError::FailureDisappeared)?;
    if expected_signature != actual_signature {
        return Err(FailureReplayError::DifferentFailure {
            expected: expected_signature.clone(),
            actual: actual_signature.clone(),
        });
    }
    if let Some(divergence) = first_trace_divergence(expected_trace, actual_trace)
        .map_err(|error| FailureReplayError::Trace(error.to_string()))?
    {
        return Err(FailureReplayError::TraceDivergence {
            sequence: u64::try_from(divergence.index)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        });
    }
    Ok(())
}

fn canonical_json<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, FailureError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| FailureError::Encoding(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn normalized_trace_bytes(trace: &[TraceEvent]) -> Result<Vec<u8>, FailureError> {
    let mut bytes = Vec::new();
    for event in trace {
        bytes.extend(
            normalized_trace_json(event)
                .map_err(|error| FailureError::Encoding(error.to_string()))?,
        );
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn raw_trace_bytes(trace: &[TraceEvent]) -> Result<Vec<u8>, FailureError> {
    let mut bytes = Vec::new();
    for event in trace {
        bytes.extend(
            serde_json::to_vec(event).map_err(|error| FailureError::Encoding(error.to_string()))?,
        );
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn decision_prefix_bytes(trace: &[TraceEvent]) -> Result<Vec<u8>, FailureError> {
    raw_trace_bytes(
        &trace
            .iter()
            .filter(|event| matches!(event.event, TraceEventKind::Decision { .. }))
            .cloned()
            .collect::<Vec<_>>(),
    )
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Failure signature or bundle construction error.
#[derive(Debug)]
pub enum FailureError {
    InvalidSuffixBound(usize),
    UnsupportedSignatureSchema(u16),
    InvalidSignature,
    InvalidChunkSize,
    ChunkCountOverflow,
    Encoding(String),
    Artifact(ArtifactError),
}

impl fmt::Display for FailureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSuffixBound(value) => write!(f, "invalid causal suffix bound {value}"),
            Self::UnsupportedSignatureSchema(value) => {
                write!(f, "unsupported failure signature schema {value}")
            }
            Self::InvalidSignature => f.write_str("failure signature is not canonical"),
            Self::InvalidChunkSize => f.write_str("failure trace chunk size must be nonzero"),
            Self::ChunkCountOverflow => f.write_str("failure trace chunk count overflow"),
            Self::Encoding(error) => write!(f, "failure artifact encoding failed: {error}"),
            Self::Artifact(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for FailureError {}

impl From<ArtifactError> for FailureError {
    fn from(value: ArtifactError) -> Self {
        Self::Artifact(value)
    }
}

/// Artifact-integrity or semantic failure replay mismatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FailureReplayError {
    MissingIndex,
    InvalidIndex(String),
    MissingArtifact {
        name: String,
    },
    MissingChunk {
        ordinal: u64,
    },
    TruncatedChunk {
        ordinal: u64,
    },
    UnindexedChunk {
        name: String,
    },
    ArtifactDigestMismatch {
        name: String,
    },
    ScenarioManifestDisagreement,
    SignatureArtifactMismatch,
    FailureDisappeared,
    DifferentFailure {
        expected: FailureSignature,
        actual: FailureSignature,
    },
    TraceDivergence {
        sequence: u64,
    },
    Trace(String),
}

impl fmt::Display for FailureReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for FailureReplayError {}
