//! Domain-separated deterministic behavioral decisions.

use std::{fmt, ops::Range, sync::Arc};

use rand::{Rng, RngExt, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};

use crate::{
    Clock, ClockError, DecisionId, IdAllocator, TraceContext, TraceEventKind, TraceRecordError,
    TraceRecorder,
};

const DERIVATION_CONTEXT: &str = "iroh-runtime behavioral decision stream v1";
const MAX_PATH_LEN: usize = 256;

/// Root seed identifying all behavioral decisions in one simulation run.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RootSeed([u8; 32]);

impl RootSeed {
    /// Creates a root seed from explicit bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Creates a production seed from operating-system-backed randomness.
    ///
    /// This seed controls behavioral choices only and is not cryptographic key material.
    pub fn random() -> Self {
        let mut bytes = [0; 32];
        rand::rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Returns the seed bytes used by run manifests and replay.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Validated semantic name of an independent decision stream.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DecisionPath(String);

impl DecisionPath {
    /// Validates a slash-separated semantic path.
    pub fn new(path: impl Into<String>) -> Result<Self, DecisionError> {
        let path = path.into();
        if path.is_empty()
            || path.len() > MAX_PATH_LEN
            || path
                .split('/')
                .any(|segment| segment.is_empty() || !segment.bytes().all(valid_path_byte))
        {
            return Err(DecisionError::InvalidPath(path));
        }
        Ok(Self(path))
    }

    /// Returns the normalized path.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DecisionPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

fn valid_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

/// Creates independent behavioral decision streams.
pub trait DecisionSource: fmt::Debug + Send + Sync + 'static {
    /// Opens a stream at its initial draw index.
    fn stream(&self, path: &str) -> Result<Box<dyn DecisionStream>, DecisionError>;
}

/// Stateful decisions within one semantic path.
pub trait DecisionStream: fmt::Debug + Send + 'static {
    /// Semantic stream path.
    fn path(&self) -> &DecisionPath;

    /// Index that will be assigned to the next successful draw.
    fn draw_index(&self) -> u64;

    /// Draws an unconstrained integer.
    fn next_u64(&mut self) -> Result<u64, DecisionError>;

    /// Draws uniformly from a non-empty half-open range.
    fn range_u64(&mut self, range: Range<u64>) -> Result<u64, DecisionError>;

    /// Returns true with probability `numerator / denominator`.
    fn boolean(&mut self, numerator: u64, denominator: u64) -> Result<bool, DecisionError>;

    /// Fills bytes as one recorded semantic draw.
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), DecisionError>;
}

/// Observes every successful behavioral draw.
pub trait DecisionObserver: fmt::Debug + Send + Sync + 'static {
    /// Records one selected value.
    fn record(
        &self,
        path: &DecisionPath,
        draw_index: u64,
        selected: &str,
    ) -> Result<(), DecisionError>;
}

/// Observer used when structured tracing is disabled.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopDecisionObserver;

impl DecisionObserver for NoopDecisionObserver {
    fn record(
        &self,
        _path: &DecisionPath,
        _draw_index: u64,
        _selected: &str,
    ) -> Result<(), DecisionError> {
        Ok(())
    }
}

/// Observer that emits decisions into the global structured trace.
#[derive(Debug)]
pub struct TraceDecisionObserver {
    ids: IdAllocator<DecisionId>,
    clock: Arc<dyn Clock>,
    trace: Arc<TraceRecorder>,
}

impl TraceDecisionObserver {
    /// Creates an observer sharing the runtime clock and recorder.
    pub fn new(clock: Arc<dyn Clock>, trace: Arc<TraceRecorder>) -> Self {
        Self {
            ids: IdAllocator::default(),
            clock,
            trace,
        }
    }
}

impl DecisionObserver for TraceDecisionObserver {
    fn record(
        &self,
        path: &DecisionPath,
        draw_index: u64,
        selected: &str,
    ) -> Result<(), DecisionError> {
        let decision = self
            .ids
            .allocate()
            .map_err(|_| DecisionError::IdExhausted)?;
        self.trace
            .record(
                self.clock.elapsed_nanos()?,
                TraceContext::default(),
                TraceEventKind::Decision {
                    decision,
                    path: path.as_str().to_owned(),
                    draw_index,
                    selected: selected.to_owned(),
                },
            )
            .map(|_| ())
            .map_err(Into::into)
    }
}

/// Blake3-domain-separated source backed by pinned ChaCha8 streams.
#[derive(Debug)]
pub struct SeededDecisionSource {
    root: RootSeed,
    observer: Arc<dyn DecisionObserver>,
}

impl SeededDecisionSource {
    /// Creates a source with disabled structured tracing.
    pub fn new(root: RootSeed) -> Self {
        Self::with_observer(root, Arc::new(NoopDecisionObserver))
    }

    /// Creates a source with an explicit draw observer.
    pub fn with_observer(root: RootSeed, observer: Arc<dyn DecisionObserver>) -> Self {
        Self { root, observer }
    }

    /// Returns the replay root seed.
    pub const fn root_seed(&self) -> RootSeed {
        self.root
    }
}

impl DecisionSource for SeededDecisionSource {
    fn stream(&self, path: &str) -> Result<Box<dyn DecisionStream>, DecisionError> {
        let path = DecisionPath::new(path)?;
        let seed = derive_stream_seed(self.root, &path);
        Ok(Box::new(SeededDecisionStream {
            rng: ChaCha8Rng::from_seed(seed),
            path,
            draw_index: 0,
            observer: self.observer.clone(),
        }))
    }
}

#[derive(Debug)]
struct SeededDecisionStream {
    rng: ChaCha8Rng,
    path: DecisionPath,
    draw_index: u64,
    observer: Arc<dyn DecisionObserver>,
}

impl SeededDecisionStream {
    fn record(&mut self, selected: &str) -> Result<(), DecisionError> {
        let next = self
            .draw_index
            .checked_add(1)
            .ok_or(DecisionError::DrawIndexExhausted)?;
        self.observer
            .record(&self.path, self.draw_index, selected)?;
        self.draw_index = next;
        Ok(())
    }
}

impl DecisionStream for SeededDecisionStream {
    fn path(&self) -> &DecisionPath {
        &self.path
    }

    fn draw_index(&self) -> u64 {
        self.draw_index
    }

    fn next_u64(&mut self) -> Result<u64, DecisionError> {
        let value = self.rng.next_u64();
        self.record(&value.to_string())?;
        Ok(value)
    }

    fn range_u64(&mut self, range: Range<u64>) -> Result<u64, DecisionError> {
        if range.is_empty() {
            return Err(DecisionError::InvalidRange);
        }
        let value = self.rng.random_range(range);
        self.record(&value.to_string())?;
        Ok(value)
    }

    fn boolean(&mut self, numerator: u64, denominator: u64) -> Result<bool, DecisionError> {
        if denominator == 0 || numerator > denominator {
            return Err(DecisionError::InvalidProbability);
        }
        let value = self.rng.random_range(0..denominator) < numerator;
        self.record(if value { "true" } else { "false" })?;
        Ok(value)
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), DecisionError> {
        self.rng.fill_bytes(destination);
        let selected = encode_hex(destination);
        self.record(&selected)
    }
}

fn derive_stream_seed(root: RootSeed, path: &DecisionPath) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(DERIVATION_CONTEXT);
    hasher.update(root.as_bytes());
    hasher.update(&(path.as_str().len() as u32).to_le_bytes());
    hasher.update(path.as_str().as_bytes());
    *hasher.finalize().as_bytes()
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

/// Invalid configuration or failed observation of a behavioral decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecisionError {
    /// The semantic path is empty, too long, or contains invalid segments.
    InvalidPath(String),
    /// A half-open integer range is empty.
    InvalidRange,
    /// A probability denominator is zero or its numerator is larger.
    InvalidProbability,
    /// A stream cannot assign another draw index.
    DrawIndexExhausted,
    /// Stable decision IDs are exhausted.
    IdExhausted,
    /// The runtime clock failed while tracing the decision.
    Clock(ClockError),
    /// The trace recorder rejected the decision observation.
    Trace(TraceRecordError),
}

impl fmt::Display for DecisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath(path) => write!(f, "invalid decision path: {path:?}"),
            Self::InvalidRange => f.write_str("decision range must be non-empty"),
            Self::InvalidProbability => f.write_str("invalid decision probability"),
            Self::DrawIndexExhausted => f.write_str("decision draw index exhausted"),
            Self::IdExhausted => f.write_str("decision identifier space exhausted"),
            Self::Clock(err) => write!(f, "decision clock failed: {err}"),
            Self::Trace(err) => write!(f, "decision trace failed: {err}"),
        }
    }
}

impl std::error::Error for DecisionError {}

impl From<ClockError> for DecisionError {
    fn from(value: ClockError) -> Self {
        Self::Clock(value)
    }
}

impl From<TraceRecordError> for DecisionError {
    fn from(value: TraceRecordError) -> Self {
        Self::Trace(value)
    }
}
