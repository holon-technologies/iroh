use std::{fmt, time::Duration};

/// Invalid framework configuration.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// At least one protocol slot is required.
    #[error("protocol limit must be greater than zero")]
    ZeroProtocolLimit,
    /// TLS ALPN values are non-empty and limited to 255 bytes.
    #[error("ALPN length limit {value} is outside 1..=255")]
    InvalidAlpnLengthLimit { value: usize },
    /// At least one supervisor command slot is required.
    #[error("supervisor command queue capacity must be greater than zero")]
    ZeroCommandQueueCapacity,
    /// Lifecycle timeouts must be finite and bounded.
    #[error("{name} timeout {value:?} is outside the supported range")]
    InvalidTimeout { name: &'static str, value: Duration },
}

/// Failure while constructing a configured application.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BuildError {
    /// Configuration validation failed.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The configured registry exceeds the selected application limits.
    #[error(transparent)]
    Registry(#[from] RegistryError),
    /// Component names are unique within one supervisor.
    #[error("duplicate component name `{name}`")]
    DuplicateComponent { name: String },
    /// Component names are non-empty and bounded.
    #[error("component name must contain 1..=64 bytes")]
    InvalidComponentName,
}

/// Failure while loading or persisting an endpoint identity.
///
/// Errors deliberately omit paths, key bytes, and operating-system error text.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityError {
    /// The requested identity does not exist.
    #[error("identity is missing")]
    Missing,
    /// Creation was requested but an identity already exists.
    #[error("identity already exists")]
    AlreadyExists,
    /// Stored bytes do not contain one valid identity.
    #[error("identity store is corrupt")]
    Corrupt,
    /// The identity file is accessible by users other than its owner.
    #[error("identity store permissions are not private")]
    InsecurePermissions,
    /// The storage capability could not complete an operation.
    #[error("identity store is unavailable during {operation}")]
    Unavailable { operation: &'static str },
}

impl IdentityError {
    /// Creates a redacted storage-availability error.
    #[must_use]
    pub const fn unavailable(operation: &'static str) -> Self {
        Self::Unavailable { operation }
    }
}

/// Invalid protocol registration.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistryError {
    /// Registry bounds themselves were invalid.
    #[error("protocol registry bounds are invalid")]
    InvalidBounds,
    /// Empty ALPN identifiers are invalid.
    #[error("ALPN must not be empty")]
    EmptyAlpn,
    /// The ALPN exceeds the configured byte limit.
    #[error("ALPN length {actual} exceeds limit {limit}")]
    AlpnTooLong { actual: usize, limit: usize },
    /// Each ALPN has exactly one owner.
    #[error("ALPN is already registered")]
    Duplicate { alpn: Vec<u8> },
    /// The registry has reached its configured protocol count.
    #[error("protocol count {actual} exceeds limit {limit}")]
    ProtocolLimit { actual: usize, limit: usize },
}

/// A component-provided failure that is safe to surface to operators.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
#[error("{message}")]
pub struct ComponentError {
    message: String,
}

impl ComponentError {
    /// Creates a component failure from a non-secret operational message.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Phase in which a supervised component failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailurePhase {
    /// Component construction or startup.
    Startup,
    /// The long-running component future.
    Runtime,
    /// Component shutdown or task join.
    Shutdown,
}

impl fmt::Display for FailurePhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Startup => "startup",
            Self::Runtime => "runtime",
            Self::Shutdown => "shutdown",
        })
    }
}

/// Observable component failure with its owner and lifecycle phase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentFailure {
    component: String,
    phase: FailurePhase,
    message: String,
}

impl ComponentFailure {
    pub(crate) fn new(
        component: impl Into<String>,
        phase: FailurePhase,
        error: impl fmt::Display,
    ) -> Self {
        Self {
            component: component.into(),
            phase,
            message: error.to_string(),
        }
    }

    /// Component that owns the failed operation.
    #[must_use]
    pub fn component(&self) -> &str {
        &self.component
    }

    /// Lifecycle phase in which the failure occurred.
    #[must_use]
    pub const fn phase(&self) -> FailurePhase {
        self.phase
    }
}

impl fmt::Display for ComponentFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "component `{}` failed during {}: {}",
            self.component, self.phase, self.message
        )
    }
}

/// Result of draining all application-owned components.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShutdownReport {
    pub(crate) failed: Vec<ComponentFailure>,
    pub(crate) timed_out: Vec<String>,
}

impl ShutdownReport {
    /// Components that returned an error while draining.
    #[must_use]
    pub fn failed(&self) -> &[ComponentFailure] {
        &self.failed
    }

    /// Components that did not finish before the one absolute deadline.
    #[must_use]
    pub fn timed_out(&self) -> &[String] {
        &self.timed_out
    }

    /// Whether all owned work drained successfully.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.failed.is_empty() && self.timed_out.is_empty()
    }
}

/// Atomic application startup failed.
#[derive(Debug, thiserror::Error)]
#[error("application startup failed at `{stage}`")]
pub struct StartupError {
    pub(crate) stage: String,
    pub(crate) failure: ComponentFailure,
    pub(crate) cleanup: ShutdownReport,
}

impl StartupError {
    /// Startup stage that failed.
    #[must_use]
    pub fn stage(&self) -> &str {
        &self.stage
    }

    /// Original startup failure.
    #[must_use]
    pub const fn failure(&self) -> &ComponentFailure {
        &self.failure
    }

    /// Outcome of rolling back components that had already started.
    #[must_use]
    pub const fn cleanup(&self) -> &ShutdownReport {
        &self.cleanup
    }
}

/// Bounded application shutdown did not complete cleanly.
#[derive(Clone, Debug, thiserror::Error)]
#[error("application shutdown was incomplete")]
pub struct ShutdownError {
    pub(crate) report: ShutdownReport,
}

impl ShutdownError {
    /// Full shutdown report.
    #[must_use]
    pub const fn report(&self) -> &ShutdownReport {
        &self.report
    }

    /// Components that exceeded the absolute shutdown deadline.
    #[must_use]
    pub fn timed_out(&self) -> &[String] {
        self.report.timed_out()
    }
}

/// Non-blocking supervisor command could not be queued.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ControlError {
    /// The configured command queue is full.
    #[error("supervisor command queue is saturated")]
    QueueSaturated,
    /// The supervisor is no longer running.
    #[error("supervisor is stopped")]
    Stopped,
}

/// Waiting for a runtime failure ended without a failure.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
#[error("application stopped without a runtime failure")]
pub struct WaitError;
