//! Host-independent trace normalization.

use std::{
    fmt,
    sync::{Arc, Mutex},
};

use iroh_runtime::{TraceEvent, TraceSink, TraceSinkError};

/// In-memory structured trace sink used by deterministic runners and tests.
#[derive(Clone, Debug, Default)]
pub struct TraceBuffer(Arc<Mutex<Vec<TraceEvent>>>);

impl TraceBuffer {
    /// Returns a stable snapshot of retained events.
    pub fn events(&self) -> Vec<TraceEvent> {
        self.0.lock().expect("trace buffer lock poisoned").clone()
    }

    /// Removes and returns all retained events.
    pub fn take(&self) -> Vec<TraceEvent> {
        std::mem::take(&mut *self.0.lock().expect("trace buffer lock poisoned"))
    }
}

impl TraceSink for TraceBuffer {
    fn record(&self, event: TraceEvent) -> Result<(), TraceSinkError> {
        self.0
            .lock()
            .expect("trace buffer lock poisoned")
            .push(event);
        Ok(())
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
