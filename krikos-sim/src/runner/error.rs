use super::*;

/// Declarative model, backend, action, invariant, or cleanup failure.
#[derive(Debug)]
pub enum RunnerError {
    Scenario(String),
    UnsupportedCapabilities(Vec<&'static str>),
    UnsupportedAction(&'static str),
    UnsupportedFaultRule(String),
    MissingRuntimeEntity(String),
    TriggerStall(Vec<String>),
    ModelState {
        entity: String,
        expected: String,
        actual: String,
    },
    ModelMismatch {
        action: String,
        expected: String,
        actual: String,
    },
    Endpoint(String),
    Operation(String),
    Invariant(InvariantFailure),
    InvariantEngine(InvariantError),
    ResourceLeak(ResourceLedgerSnapshot),
    TerminalNotAllowed(&'static str),
    CleanupAfterFailure {
        primary: String,
        cleanup: String,
    },
    TimelineOverflow,
    ObservationOverflow,
    PayloadOverflow,
    Encoding(String),
    Backend(crate::BackendError),
    EndpointEnvironment(crate::EndpointEnvironmentError),
    Network(crate::NetworkError),
    Driver(crate::KernelDriverError),
    Kernel(crate::KernelError),
    Ledger(crate::LedgerError),
    Clock(ClockError),
    Trace(TraceRecordError),
    Observation(crate::ObservationError),
    Discovery(crate::DiscoveryError),
}

impl fmt::Display for RunnerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scenario(error) => write!(f, "scenario is invalid: {error}"),
            Self::UnsupportedCapabilities(values) => {
                write!(f, "backend lacks capabilities: {}", values.join(","))
            }
            Self::UnsupportedAction(value) => write!(f, "backend does not support action {value}"),
            Self::UnsupportedFaultRule(value) => {
                write!(f, "backend does not support fault rule {value:?}")
            }
            Self::MissingRuntimeEntity(value) => write!(f, "runtime entity {value:?} is not live"),
            Self::TriggerStall(values) => {
                write!(f, "scenario triggers stalled: {}", values.join(","))
            }
            Self::ModelState {
                entity,
                expected,
                actual,
            } => write!(
                f,
                "model state mismatch for {entity:?}: expected {expected}, got {actual}"
            ),
            Self::ModelMismatch {
                action,
                expected,
                actual,
            } => write!(
                f,
                "model outcome mismatch for {action:?}: expected {expected}, got {actual}"
            ),
            Self::Endpoint(error) => write!(f, "endpoint operation failed: {error}"),
            Self::Operation(error) => write!(f, "application operation failed: {error}"),
            Self::Invariant(failure) => write!(f, "invariant {:?} failed", failure.name),
            Self::InvariantEngine(error) => write!(f, "invariant engine failed: {error}"),
            Self::ResourceLeak(snapshot) => write!(f, "scenario leaked resources: {snapshot:?}"),
            Self::TerminalNotAllowed(terminal) => {
                write!(f, "scenario terminal {terminal:?} is not allowed")
            }
            Self::CleanupAfterFailure { primary, cleanup } => write!(
                f,
                "scenario failed ({primary}) and cleanup failed ({cleanup})"
            ),
            Self::TimelineOverflow => f.write_str("scenario timeline overflow"),
            Self::ObservationOverflow => f.write_str("scenario observation sequence overflow"),
            Self::PayloadOverflow => f.write_str("scenario payload does not fit memory size"),
            Self::Encoding(error) => write!(f, "scenario artifact encoding failed: {error}"),
            Self::Backend(error) => error.fmt(f),
            Self::EndpointEnvironment(error) => error.fmt(f),
            Self::Network(error) => error.fmt(f),
            Self::Driver(error) => error.fmt(f),
            Self::Kernel(error) => error.fmt(f),
            Self::Ledger(error) => error.fmt(f),
            Self::Clock(error) => error.fmt(f),
            Self::Trace(error) => error.fmt(f),
            Self::Observation(error) => error.fmt(f),
            Self::Discovery(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for RunnerError {}

macro_rules! from_error {
    ($source:ty, $variant:ident) => {
        impl From<$source> for RunnerError {
            fn from(value: $source) -> Self {
                Self::$variant(value)
            }
        }
    };
}

from_error!(crate::BackendError, Backend);
from_error!(crate::EndpointEnvironmentError, EndpointEnvironment);
from_error!(crate::NetworkError, Network);
from_error!(crate::KernelDriverError, Driver);
from_error!(crate::KernelError, Kernel);
from_error!(crate::LedgerError, Ledger);
from_error!(ClockError, Clock);
from_error!(TraceRecordError, Trace);
from_error!(crate::ObservationError, Observation);
from_error!(crate::DiscoveryError, Discovery);

impl From<InvariantError> for RunnerError {
    fn from(value: InvariantError) -> Self {
        match value {
            InvariantError::Failure(failure) => Self::Invariant(failure),
            other => Self::InvariantEngine(other),
        }
    }
}

impl From<String> for RunnerError {
    fn from(value: String) -> Self {
        Self::Operation(value)
    }
}
