//! Versioned structured runtime observations.

use std::{
    fmt,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};

use crate::{DecisionId, TaskId, TimerId, TraceSequence};

/// Current trace event schema version.
pub const TRACE_SCHEMA_VERSION: u16 = 2;

/// Semantic role of a runtime-owned task.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    /// A Noq protocol task.
    Noq,
    /// The endpoint socket actor.
    SocketActor,
    /// An address discovery task.
    Discovery,
    /// A network report task.
    NetReport,
    /// An application protocol handler.
    Protocol,
    /// A relay client or server task.
    Relay,
    /// Another explicitly named task role.
    Other(String),
}

/// Stable task identity and ownership metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaskMetadata {
    /// Stable task ID.
    pub id: TaskId,
    /// Stable parent task, absent for a runtime root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<TaskId>,
    /// Creation ordinal within the parent or root task group.
    pub child_ordinal: u64,
    /// Semantic task role.
    pub kind: TaskKind,
    /// Stable human-readable name.
    pub name: String,
}

/// Typed entity references attached to an observation.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TraceContext {
    /// Scenario operation identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    /// Runtime task.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<TaskId>,
    /// Endpoint identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Connection identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<String>,
    /// Stream identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<String>,
    /// Packet identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet: Option<String>,
    /// Relay identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    /// NAT identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nat: Option<String>,
    /// Firewall identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firewall: Option<String>,
    /// Discovery provider identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery: Option<String>,
    /// Interface identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Invariant identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invariant: Option<String>,
}

/// A structured runtime observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TraceEvent {
    /// Event schema version.
    pub schema_version: u16,
    /// Global event sequence.
    pub sequence: TraceSequence,
    /// Optional causal predecessor in the same global trace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causal_parent: Option<TraceSequence>,
    /// Optional behavioral decision responsible for this event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<DecisionId>,
    /// Nanoseconds elapsed on the run's virtual monotonic timeline.
    pub virtual_time_nanos: u64,
    /// Related runtime/protocol entities.
    pub context: TraceContext,
    /// Event payload.
    pub event: TraceEventKind,
}

impl TraceEvent {
    /// Creates an event using the current schema version.
    pub fn new(
        sequence: TraceSequence,
        virtual_time_nanos: u64,
        context: TraceContext,
        event: TraceEventKind,
    ) -> Self {
        Self {
            schema_version: TRACE_SCHEMA_VERSION,
            sequence,
            causal_parent: None,
            decision: None,
            virtual_time_nanos,
            context,
            event,
        }
    }

    /// Attaches a stable causal predecessor.
    pub const fn with_causal_parent(mut self, parent: TraceSequence) -> Self {
        self.causal_parent = Some(parent);
        self
    }

    /// Attaches the behavioral decision that selected this event.
    pub const fn with_decision(mut self, decision: DecisionId) -> Self {
        self.decision = Some(decision);
        self
    }
}

/// Versioned runtime event payloads.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TraceEventKind {
    /// A declarative scenario operation began execution.
    OperationStarted {
        /// Stable action kind.
        action: String,
    },
    /// A declarative scenario operation reached a terminal outcome.
    OperationCompleted {
        /// Normalized success or error class.
        outcome: String,
    },
    /// A task was accepted for execution.
    TaskSpawned {
        /// Task identity and ownership.
        metadata: TaskMetadata,
    },
    /// The kernel selected one task from the current causal ready wave.
    TaskScheduled {
        /// Selected task identity and ownership.
        selected: TaskMetadata,
        /// Stable identities of every task eligible in the causal ready wave.
        ready: Vec<TaskMetadata>,
        /// Whether the fairness bound constrained the legal set.
        fairness_forced: bool,
    },
    /// A task completed normally.
    TaskCompleted {
        /// Completed task.
        task: TaskId,
    },
    /// A task stopped because its group was cancelled.
    TaskCancelled {
        /// Cancelled task.
        task: TaskId,
    },
    /// A task panicked while being polled.
    TaskPanicked {
        /// Panicked task.
        task: TaskId,
    },
    /// A task was rejected because its task group was closed.
    TaskRejected {
        /// Rejected task identity and ownership.
        metadata: TaskMetadata,
    },
    /// A timer was created.
    TimerCreated {
        /// Timer identity.
        timer: TimerId,
        /// Deadline on the run-relative timeline.
        deadline_nanos: u64,
    },
    /// A timer deadline was changed.
    TimerReset {
        /// Timer identity.
        timer: TimerId,
        /// New deadline on the run-relative timeline.
        deadline_nanos: u64,
    },
    /// A timer fired.
    TimerFired {
        /// Timer identity.
        timer: TimerId,
    },
    /// A pending timer was dropped.
    TimerDropped {
        /// Timer identity.
        timer: TimerId,
    },
    /// A behavioral decision was made.
    Decision {
        /// Decision identity.
        decision: DecisionId,
        /// Semantic decision stream.
        path: String,
        /// Draw index within the stream.
        draw_index: u64,
        /// Normalized selected value or alternative.
        selected: String,
    },
    /// A component changed externally observable state.
    StateTransition {
        /// Component kind/name.
        component: String,
        /// Previous state.
        from: String,
        /// New state.
        to: String,
    },
    /// A simulator fault rule changed the environment.
    FaultInjected {
        /// Stable scenario fault-rule ID.
        rule: String,
        /// Normalized outcome.
        outcome: String,
    },
    /// A stateful NAT mapping changed lifecycle state.
    NatMapping {
        /// Stable mapping identity.
        mapping: String,
        /// `created`, `reused`, `expired`, `removed`, or `rebound`.
        transition: String,
        /// Canonical internal socket tuple.
        internal: String,
        /// Canonical external socket tuple.
        external: String,
        /// Mapping expiry on the virtual timeline.
        expires_nanos: u64,
    },
    /// A NAT translated or filtered one packet tuple.
    NatTranslation {
        /// `outbound`, `inbound`, or `hairpin`.
        direction: String,
        /// Tuple before translation.
        original_source: String,
        /// Tuple before translation.
        original_destination: String,
        /// Tuple after translation when allowed.
        translated_source: Option<String>,
        /// Tuple after translation when allowed.
        translated_destination: Option<String>,
        /// Stable allow/drop classification.
        outcome: String,
    },
    /// A modeled firewall made an ordered rule decision.
    FirewallDecision {
        /// Stable rule identity or `default`.
        rule: String,
        /// `allow`, `drop`, or `reject`.
        action: String,
        /// Packet direction at the firewall.
        direction: String,
    },
    /// A deterministic discovery record changed state or produced a lookup result.
    DiscoveryRecord {
        /// Stable scenario record identity.
        record: String,
        /// `published`, `failed`, `withdrawn`, `expired`, `resolved`, or `stale_suppressed`.
        transition: String,
        /// Scenario endpoint identity associated with the record.
        endpoint: String,
        /// Canonically ordered socket addresses.
        addresses: Vec<String>,
        /// Earliest virtual time at which resolution may produce the record.
        available_nanos: u64,
        /// Exclusive virtual expiry boundary.
        expires_nanos: u64,
    },
    /// A synthetic host interface changed administrative state.
    InterfaceState {
        /// Host that owns the interface.
        host: String,
        /// Whether the interface is now available for routing.
        up: bool,
        /// Canonical configured addresses retained by the interface.
        addresses: Vec<String>,
    },
    /// A configured address was added to or removed from an interface.
    InterfaceAddress {
        host: String,
        address: String,
        present: bool,
    },
    /// A synthetic host entered sleep or resumed its retained interface state.
    HostPower { host: String, sleeping: bool },
    /// A synthetic IP packet entered the network model.
    PacketCreated {
        /// Canonical source socket address after outbound translation.
        source: String,
        /// Canonical destination socket address after outbound/hairpin translation.
        destination: String,
        /// Canonical source socket address before translation.
        original_source: String,
        /// Canonical destination socket address before translation.
        original_destination: String,
        /// Datagram payload length.
        length: u64,
        /// Lowercase Blake3 digest; payload bytes are not retained in the trace.
        payload_hash: String,
    },
    /// One routed hop reserved link capacity for a synthetic packet.
    PacketHopScheduled {
        /// Stable link identity.
        link: String,
        /// Source host for this directed hop.
        from: String,
        /// Destination host for this directed hop.
        to: String,
        /// Run-relative deadline after this hop's serialization and latency.
        deadline_nanos: u64,
    },
    /// A synthetic packet reached one terminal or scheduled state.
    PacketOutcome {
        /// Stable normalized outcome such as `scheduled`, `delivered`, or `dropped:partition`.
        outcome: String,
    },
    /// Production application bytes were observed at the scenario boundary.
    ApplicationDelivery {
        /// Per-stream or per-datagram application sequence.
        sequence: u64,
        /// Logical source endpoint.
        source: String,
        /// Logical destination endpoint.
        destination: String,
        /// Expected application-payload digest.
        expected_hash: String,
        /// Observed application-payload digest.
        actual_hash: String,
    },
    /// A bounded-liveness obligation was registered.
    InvariantRegistered {
        /// Stable obligation identity.
        obligation: String,
        /// Run-relative virtual deadline.
        deadline_nanos: u64,
        /// Global event-count deadline.
        event_deadline: u64,
    },
    /// A bounded-liveness obligation was satisfied.
    InvariantSatisfied {
        /// Stable obligation identity.
        obligation: String,
    },
    /// A safety, liveness, or cleanup invariant failed.
    InvariantFailed {
        /// Stable invariant class.
        class: String,
        /// Blake3 digest of canonical structured evidence.
        evidence_digest: String,
    },
}

/// Receives structured trace observations.
pub trait TraceSink: fmt::Debug + Send + Sync + 'static {
    /// Records one observation.
    fn record(&self, event: TraceEvent) -> Result<(), TraceSinkError>;
}

/// Assigns one global sequence space to events sent to a trace sink.
#[derive(Debug)]
pub struct TraceRecorder {
    sequences: crate::IdAllocator<TraceSequence>,
    sink: Arc<dyn TraceSink>,
    failure: Mutex<Option<TraceRecordError>>,
}

impl TraceRecorder {
    /// Creates a recorder for `sink`.
    pub fn new(sink: Arc<dyn TraceSink>) -> Self {
        Self {
            sequences: crate::IdAllocator::default(),
            sink,
            failure: Mutex::new(None),
        }
    }

    /// Assigns a sequence number and records one event.
    pub fn record(
        &self,
        virtual_time_nanos: u64,
        context: TraceContext,
        event: TraceEventKind,
    ) -> Result<TraceSequence, TraceRecordError> {
        let result: Result<TraceSequence, TraceRecordError> = (|| {
            let sequence = self
                .sequences
                .allocate()
                .map_err(|_| TraceRecordError::IdExhausted)?;
            self.sink
                .record(TraceEvent::new(
                    sequence,
                    virtual_time_nanos,
                    context,
                    event,
                ))
                .map_err(TraceRecordError::Sink)?;
            Ok(sequence)
        })();
        if let Err(error) = &result {
            self.latch(error.clone());
        }
        result
    }

    /// Takes the first trace failure that has not yet been handled.
    pub fn take_failure(&self) -> Option<TraceRecordError> {
        self.failure
            .lock()
            .expect("trace failure lock poisoned")
            .take()
    }

    fn latch(&self, error: TraceRecordError) {
        let mut failure = self.failure.lock().expect("trace failure lock poisoned");
        if failure.is_none() {
            *failure = Some(error);
        }
    }
}

/// Failure while assigning or retaining a trace event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TraceRecordError {
    /// The global trace sequence was exhausted.
    IdExhausted,
    /// The configured sink rejected the event.
    Sink(TraceSinkError),
}

impl fmt::Display for TraceRecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdExhausted => f.write_str("trace sequence space exhausted"),
            Self::Sink(err) => write!(f, "trace sink failed: {err}"),
        }
    }
}

impl std::error::Error for TraceRecordError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sink(err) => Some(err),
            Self::IdExhausted => None,
        }
    }
}

/// Infallible sink used by the production runtime when tracing is disabled.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopTraceSink;

impl TraceSink for NoopTraceSink {
    #[inline]
    fn record(&self, _event: TraceEvent) -> Result<(), TraceSinkError> {
        Ok(())
    }
}

/// A trace sink could not retain an event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceSinkError {
    message: String,
}

impl TraceSinkError {
    /// Creates a redacted trace error.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for TraceSinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(f)
    }
}

impl std::error::Error for TraceSinkError {}
