//! Atomic writes into an explicit artifact directory.

use std::{
    ffi::OsStr,
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use iroh_runtime::{TraceEvent, TraceSink, TraceSinkError};

use crate::{RunManifest, normalized_trace_json};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

/// Explicit root for run manifests and trace chunks.
#[derive(Clone, Debug)]
pub struct ArtifactStore {
    root: PathBuf,
}

/// Trace sink that publishes bounded, immutable raw and normalized prefix chunks.
///
/// Completed chunks survive a harness crash. Call [`Self::flush`] at normal termination to
/// publish the final partial chunk; the CLI also writes convenient aggregate trace files.
#[derive(Clone, Debug)]
pub struct ArtifactTraceWriter {
    inner: Arc<ArtifactTraceWriterInner>,
}

#[derive(Debug)]
struct ArtifactTraceWriterInner {
    store: ArtifactStore,
    events_per_chunk: usize,
    state: Mutex<TraceChunkState>,
}

#[derive(Debug, Default)]
struct TraceChunkState {
    ordinal: u64,
    events: Vec<TraceEvent>,
}

impl ArtifactTraceWriter {
    /// Creates a writer that publishes after `events_per_chunk` observations.
    pub fn new(store: ArtifactStore, events_per_chunk: usize) -> Result<Self, ArtifactError> {
        if events_per_chunk == 0 {
            return Err(ArtifactError::InvalidChunkSize);
        }
        Ok(Self {
            inner: Arc::new(ArtifactTraceWriterInner {
                store,
                events_per_chunk,
                state: Mutex::new(TraceChunkState {
                    events: Vec::with_capacity(events_per_chunk),
                    ..TraceChunkState::default()
                }),
            }),
        })
    }

    /// Atomically publishes any retained partial prefix chunk.
    pub fn flush(&self) -> Result<(), ArtifactError> {
        let mut state = self.inner.state.lock().expect("trace chunk lock poisoned");
        self.publish_locked(&mut state)
    }

    fn publish_locked(&self, state: &mut TraceChunkState) -> Result<(), ArtifactError> {
        if state.events.is_empty() {
            return Ok(());
        }
        let ordinal = state.ordinal;
        self.inner.store.write_raw_trace(
            &format!("trace.raw.chunk.{ordinal:08}.jsonl"),
            &state.events,
        )?;
        self.inner
            .store
            .write_trace(&format!("trace.chunk.{ordinal:08}.jsonl"), &state.events)?;
        state.events.clear();
        state.ordinal = state
            .ordinal
            .checked_add(1)
            .ok_or(ArtifactError::ChunkOrdinalExhausted)?;
        Ok(())
    }
}

impl TraceSink for ArtifactTraceWriter {
    fn record(&self, event: TraceEvent) -> Result<(), TraceSinkError> {
        let mut state = self.inner.state.lock().expect("trace chunk lock poisoned");
        state.events.push(event);
        if state.events.len() >= self.inner.events_per_chunk {
            self.publish_locked(&mut state)
                .map_err(|error| TraceSinkError::new(error.to_string()))?;
        }
        Ok(())
    }
}

impl ArtifactStore {
    /// Creates or opens an absolute artifact directory.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, ArtifactError> {
        let root = root.as_ref();
        if !root.is_absolute() {
            return Err(ArtifactError::InvalidRoot);
        }
        fs::create_dir_all(root).map_err(ArtifactError::Io)?;
        let root = root.canonicalize().map_err(ArtifactError::Io)?;
        Ok(Self { root })
    }

    /// Returns the canonical explicit artifact root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Writes a validated manifest without replacing an existing artifact.
    pub fn write_manifest(
        &self,
        name: &str,
        manifest: &RunManifest,
    ) -> Result<PathBuf, ArtifactError> {
        let bytes = manifest
            .to_canonical_json()
            .map_err(|error| ArtifactError::Encoding(error.to_string()))?;
        self.write_atomic(name, &bytes)
    }

    /// Writes newline-delimited normalized trace events atomically.
    pub fn write_trace<'a>(
        &self,
        name: &str,
        events: impl IntoIterator<Item = &'a TraceEvent>,
    ) -> Result<PathBuf, ArtifactError> {
        let mut bytes = Vec::new();
        for event in events {
            bytes.extend(
                normalized_trace_json(event)
                    .map_err(|error| ArtifactError::Encoding(error.to_string()))?,
            );
            bytes.push(b'\n');
        }
        self.write_atomic(name, &bytes)
    }

    /// Writes newline-delimited raw trace events for forensic packet-hash inspection.
    pub fn write_raw_trace<'a>(
        &self,
        name: &str,
        events: impl IntoIterator<Item = &'a TraceEvent>,
    ) -> Result<PathBuf, ArtifactError> {
        let mut bytes = Vec::new();
        for event in events {
            bytes.extend(
                serde_json::to_vec(event)
                    .map_err(|error| ArtifactError::Encoding(error.to_string()))?,
            );
            bytes.push(b'\n');
        }
        self.write_atomic(name, &bytes)
    }

    pub(crate) fn write_atomic(&self, name: &str, bytes: &[u8]) -> Result<PathBuf, ArtifactError> {
        validate_name(name)?;
        let destination = self.root.join(name);
        if destination.exists() {
            return Err(ArtifactError::AlreadyExists(destination));
        }
        let ordinal = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let temporary = self
            .root
            .join(format!(".{name}.tmp.{}.{}", std::process::id(), ordinal));
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .map_err(ArtifactError::Io)?;
            file.write_all(bytes).map_err(ArtifactError::Io)?;
            file.sync_all().map_err(ArtifactError::Io)?;
            fs::rename(&temporary, &destination).map_err(ArtifactError::Io)?;
            Ok(destination.clone())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

fn validate_name(name: &str) -> Result<(), ArtifactError> {
    let path = Path::new(name);
    let mut components = path.components();
    let valid = matches!(components.next(), Some(Component::Normal(part)) if part != OsStr::new(""))
        && components.next().is_none();
    if !valid {
        return Err(ArtifactError::InvalidName(name.to_owned()));
    }
    Ok(())
}

/// Artifact storage failure.
#[derive(Debug)]
pub enum ArtifactError {
    /// Artifact roots must be explicit absolute paths.
    InvalidRoot,
    /// Artifact names must be one normal path component.
    InvalidName(String),
    /// Artifacts are immutable once published.
    AlreadyExists(PathBuf),
    /// Trace chunk sizes must be positive.
    InvalidChunkSize,
    /// The immutable trace chunk namespace was exhausted.
    ChunkOrdinalExhausted,
    /// Encoding or normalization failed.
    Encoding(String),
    /// Filesystem operation failed.
    Io(std::io::Error),
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRoot => f.write_str("artifact root must be an absolute path"),
            Self::InvalidName(name) => write!(f, "invalid artifact name {name:?}"),
            Self::AlreadyExists(path) => write!(f, "artifact already exists: {}", path.display()),
            Self::InvalidChunkSize => f.write_str("trace chunk size must be nonzero"),
            Self::ChunkOrdinalExhausted => f.write_str("trace chunk ordinal exhausted"),
            Self::Encoding(error) => write!(f, "artifact encoding failed: {error}"),
            Self::Io(error) => write!(f, "artifact I/O failed: {error}"),
        }
    }
}

impl std::error::Error for ArtifactError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
