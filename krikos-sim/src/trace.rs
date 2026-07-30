//! Host-independent trace normalization.

use std::{
    fmt,
    sync::{Arc, Mutex},
};

use krikos_runtime::{TraceEvent, TraceSink, TraceSinkError};

/// Absolute safety ceiling used when callers do not request a smaller trace buffer.
pub const DEFAULT_MAX_TRACE_BUFFER_EVENTS: u64 = 10_000_000;

/// In-memory structured trace sink used by deterministic runners and tests.
#[derive(Clone, Debug)]
pub struct TraceBuffer {
    inner: Arc<Mutex<Vec<TraceEvent>>>,
    max_events: usize,
}

impl TraceBuffer {
    /// Creates an in-memory sink that retains at most `max_events` observations.
    pub fn new(max_events: u64) -> Result<Self, TraceBufferError> {
        let max_events = usize::try_from(max_events)
            .map_err(|_| TraceBufferError::InvalidLimit { limit: max_events })?;
        if max_events == 0 {
            return Err(TraceBufferError::InvalidLimit { limit: 0 });
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(Vec::new())),
            max_events,
        })
    }

    /// Returns a stable snapshot of retained events.
    pub fn events(&self) -> Vec<TraceEvent> {
        self.inner
            .lock()
            .expect("trace buffer lock poisoned")
            .clone()
    }

    /// Removes and returns all retained events.
    pub fn take(&self) -> Vec<TraceEvent> {
        std::mem::take(&mut *self.inner.lock().expect("trace buffer lock poisoned"))
    }
}

impl Default for TraceBuffer {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_TRACE_BUFFER_EVENTS)
            .expect("default trace buffer limit is nonzero and fits usize")
    }
}

impl TraceSink for TraceBuffer {
    fn record(&self, event: TraceEvent) -> Result<(), TraceSinkError> {
        let mut events = self.inner.lock().expect("trace buffer lock poisoned");
        if events.len() >= self.max_events {
            return Err(TraceSinkError::new(format!(
                "trace buffer event limit {} exceeded",
                self.max_events
            )));
        }
        events.push(event);
        Ok(())
    }
}

/// Invalid trace-buffer construction input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceBufferError {
    /// The requested maximum is zero or cannot fit the host collection index.
    InvalidLimit {
        /// Rejected maximum event count.
        limit: u64,
    },
}

impl fmt::Display for TraceBufferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { limit } => {
                write!(f, "trace buffer event limit {limit} is invalid")
            }
        }
    }
}

impl std::error::Error for TraceBufferError {}

/// Admission wrapper that bounds all events sent to an arbitrary trace sink.
#[derive(Debug)]
pub(crate) struct BoundedTraceSink {
    sink: Arc<dyn TraceSink>,
    max_events: u64,
    admitted: Mutex<u64>,
}

impl BoundedTraceSink {
    pub(crate) fn new(sink: Arc<dyn TraceSink>, max_events: u64) -> Self {
        assert!(
            max_events > 0,
            "validated trace event limit must be nonzero"
        );
        Self {
            sink,
            max_events,
            admitted: Mutex::new(0),
        }
    }
}

impl TraceSink for BoundedTraceSink {
    fn record(&self, event: TraceEvent) -> Result<(), TraceSinkError> {
        {
            let mut admitted = self
                .admitted
                .lock()
                .expect("bounded trace sink lock poisoned");
            if *admitted >= self.max_events {
                return Err(TraceSinkError::new(format!(
                    "trace event limit {} exceeded",
                    self.max_events
                )));
            }
            *admitted = admitted
                .checked_add(1)
                .expect("admitted trace count below configured u64 limit");
        }
        self.sink.record(event)
    }
}

/// Serializes one trace event after removing host paths and opaque packet-byte entropy.
///
/// Raw traces retain packet payload hashes for forensic comparison. Normalized replay compares
/// packet identity, endpoints, length, timing, and outcome while deliberately excluding the hash:
/// production TLS ciphertext changes with secure cryptographic entropy even when behavior is the
/// same.
pub fn normalized_trace_json(event: &TraceEvent) -> Result<Vec<u8>, TraceNormalizationError> {
    let mut value =
        serde_json::to_value(event).map_err(|error| TraceNormalizationError(error.to_string()))?;
    normalize(&mut value);
    serde_json::to_vec(&value).map_err(|error| TraceNormalizationError(error.to_string()))
}

/// Returns the first normalized event mismatch, including a missing event on either side.
pub fn first_trace_divergence(
    expected: &[TraceEvent],
    actual: &[TraceEvent],
) -> Result<Option<TraceDivergence>, TraceNormalizationError> {
    let length = expected.len().max(actual.len());
    for index in 0..length {
        let expected_event = expected.get(index).map(normalized_trace_json).transpose()?;
        let actual_event = actual.get(index).map(normalized_trace_json).transpose()?;
        if expected_event != actual_event {
            return Ok(Some(TraceDivergence {
                index,
                expected: expected_event,
                actual: actual_event,
            }));
        }
    }
    Ok(None)
}

/// First event at which replay diverges from its recorded trace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceDivergence {
    /// Zero-based event index.
    pub index: usize,
    /// Expected normalized JSON, absent when replay emitted an extra event.
    pub expected: Option<Vec<u8>>,
    /// Actual normalized JSON, absent when replay stopped early.
    pub actual: Option<Vec<u8>>,
}

fn normalize(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(values) => values.iter_mut().for_each(normalize),
        serde_json::Value::Object(values) => {
            if values.get("kind").and_then(serde_json::Value::as_str) == Some("packet_created")
                && let Some(payload_hash) = values.get_mut("payload_hash")
            {
                *payload_hash = serde_json::Value::String("<opaque-packet-payload>".to_owned());
            }
            values.values_mut().for_each(normalize);
        }
        serde_json::Value::String(text) if looks_like_host_path(text) => {
            *text = "<redacted-host-path>".to_owned();
        }
        _ => {}
    }
}

fn looks_like_host_path(value: &str) -> bool {
    std::path::Path::new(value).is_absolute()
        || value.starts_with("~/")
        || (value.len() >= 3
            && value.as_bytes()[1] == b':'
            && matches!(value.as_bytes()[2], b'/' | b'\\'))
}

/// A trace event could not be normalized or serialized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceNormalizationError(String);

impl fmt::Display for TraceNormalizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "trace normalization failed: {}", self.0)
    }
}

impl std::error::Error for TraceNormalizationError {}
