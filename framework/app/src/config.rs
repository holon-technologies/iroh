use std::time::Duration;

use crate::ConfigError;

const DEFAULT_PROTOCOL_LIMIT: usize = 64;
const DEFAULT_ALPN_LENGTH_LIMIT: usize = 255;
const DEFAULT_COMMAND_QUEUE_CAPACITY: usize = 32;
const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Resource and failure policy for one application lifecycle.
#[derive(Clone, Debug)]
pub struct AppConfig {
    pub(crate) protocol_limit: usize,
    pub(crate) alpn_length_limit: usize,
    pub(crate) command_queue_capacity: usize,
    pub(crate) startup_timeout: Duration,
    pub(crate) shutdown_timeout: Duration,
    pub(crate) fail_fast: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            protocol_limit: DEFAULT_PROTOCOL_LIMIT,
            alpn_length_limit: DEFAULT_ALPN_LENGTH_LIMIT,
            command_queue_capacity: DEFAULT_COMMAND_QUEUE_CAPACITY,
            startup_timeout: DEFAULT_STARTUP_TIMEOUT,
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
            fail_fast: true,
        }
    }
}

impl AppConfig {
    /// Sets the maximum number of registered application protocols.
    #[must_use]
    pub fn with_protocol_limit(mut self, limit: usize) -> Self {
        self.protocol_limit = limit;
        self
    }

    /// Sets the maximum byte length of one ALPN identifier.
    #[must_use]
    pub fn with_alpn_length_limit(mut self, limit: usize) -> Self {
        self.alpn_length_limit = limit;
        self
    }

    /// Sets the bounded supervisor command queue capacity.
    #[must_use]
    pub fn with_command_queue_capacity(mut self, capacity: usize) -> Self {
        self.command_queue_capacity = capacity;
        self
    }

    /// Sets the maximum duration allowed for each startup stage.
    #[must_use]
    pub fn with_startup_timeout(mut self, timeout: Duration) -> Self {
        self.startup_timeout = timeout;
        self
    }

    /// Sets the single absolute deadline shared by shutdown operations.
    #[must_use]
    pub fn with_shutdown_timeout(mut self, timeout: Duration) -> Self {
        self.shutdown_timeout = timeout;
        self
    }

    /// Sets whether a child failure immediately drains the entire application.
    #[must_use]
    pub fn with_fail_fast(mut self, fail_fast: bool) -> Self {
        self.fail_fast = fail_fast;
        self
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if self.protocol_limit == 0 {
            return Err(ConfigError::ZeroProtocolLimit);
        }
        if self.alpn_length_limit == 0 || self.alpn_length_limit > 255 {
            return Err(ConfigError::InvalidAlpnLengthLimit {
                value: self.alpn_length_limit,
            });
        }
        if self.command_queue_capacity == 0 {
            return Err(ConfigError::ZeroCommandQueueCapacity);
        }
        validate_timeout("startup", self.startup_timeout)?;
        validate_timeout("shutdown", self.shutdown_timeout)?;
        Ok(())
    }
}

fn validate_timeout(name: &'static str, value: Duration) -> Result<(), ConfigError> {
    if value.is_zero() || value > MAX_LIFECYCLE_TIMEOUT {
        return Err(ConfigError::InvalidTimeout { name, value });
    }
    Ok(())
}
