use std::{
    num::{NonZeroU32, NonZeroUsize},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};

/// Default maximum number of live tasks owned by one endpoint runtime.
pub const DEFAULT_MAX_LIVE_TASKS: usize = 4_096;
/// Default maximum number of active QUIC connections owned by one endpoint.
pub const DEFAULT_MAX_CONNECTIONS: usize = 2_048;
/// Default maximum number of remote-state actors owned by one endpoint.
pub const DEFAULT_MAX_REMOTE_STATE_ACTORS: usize = 1_024;
/// Default maximum number of active-relay actors owned by one endpoint.
pub const DEFAULT_MAX_ACTIVE_RELAY_ACTORS: usize = 64;

const FIXED_ENDPOINT_TASK_HEADROOM: usize = 64;

/// Finite task, connection, and actor limits for one endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointLimits {
    max_live_tasks: NonZeroUsize,
    max_connections: NonZeroUsize,
    max_remote_state_actors: NonZeroUsize,
    max_active_relay_actors: NonZeroUsize,
}

impl EndpointLimits {
    /// Returns the maximum number of tasks owned by the endpoint runtime group.
    pub const fn max_live_tasks(self) -> NonZeroUsize {
        self.max_live_tasks
    }

    /// Returns the maximum number of active QUIC connections.
    pub const fn max_connections(self) -> NonZeroUsize {
        self.max_connections
    }

    /// Returns the maximum number of remote-state actors.
    pub const fn max_remote_state_actors(self) -> NonZeroUsize {
        self.max_remote_state_actors
    }

    /// Returns the maximum number of active-relay actors.
    pub const fn max_active_relay_actors(self) -> NonZeroUsize {
        self.max_active_relay_actors
    }

    /// Sets the maximum number of tasks owned by the endpoint runtime group.
    pub const fn with_max_live_tasks(mut self, limit: NonZeroUsize) -> Self {
        self.max_live_tasks = limit;
        self
    }

    /// Sets the maximum number of active QUIC connections.
    pub const fn with_max_connections(mut self, limit: NonZeroUsize) -> Self {
        self.max_connections = limit;
        self
    }

    /// Sets the maximum number of remote-state actors.
    pub const fn with_max_remote_state_actors(mut self, limit: NonZeroUsize) -> Self {
        self.max_remote_state_actors = limit;
        self
    }

    /// Sets the maximum number of active-relay actors.
    pub const fn with_max_active_relay_actors(mut self, limit: NonZeroUsize) -> Self {
        self.max_active_relay_actors = limit;
        self
    }

    pub(crate) fn validate(self) -> Result<(), EndpointLimitsValidationError> {
        let required = self
            .max_connections
            .get()
            .checked_add(self.max_remote_state_actors.get())
            .and_then(|value| value.checked_add(self.max_active_relay_actors.get()))
            .and_then(|value| value.checked_add(FIXED_ENDPOINT_TASK_HEADROOM))
            .ok_or(EndpointLimitsValidationError::ArithmeticOverflow)?;
        if self.max_live_tasks.get() < required {
            return Err(EndpointLimitsValidationError::InsufficientTaskCapacity {
                configured: self.max_live_tasks.get(),
                required,
            });
        }
        Ok(())
    }

    pub(crate) fn noq_event_limits(self) -> noq::EventQueueLimits {
        noq::EventQueueLimits::new(
            self.max_connections,
            NonZeroUsize::new(noq::DEFAULT_MAX_PACKET_EVENTS_PER_CONNECTION)
                .expect("Noq default packet-event capacity is nonzero"),
            NonZeroU32::new(noq::DEFAULT_MAX_PACKET_BYTES_PER_ENDPOINT)
                .expect("Noq default packet-byte capacity is nonzero"),
            NonZeroUsize::new(noq::DEFAULT_MAX_CONTROL_EVENTS_PER_ENDPOINT)
                .expect("Noq default control-event capacity is nonzero"),
        )
    }
}

impl Default for EndpointLimits {
    fn default() -> Self {
        Self {
            max_live_tasks: NonZeroUsize::new(DEFAULT_MAX_LIVE_TASKS)
                .expect("default live-task capacity is nonzero"),
            max_connections: NonZeroUsize::new(DEFAULT_MAX_CONNECTIONS)
                .expect("default connection capacity is nonzero"),
            max_remote_state_actors: NonZeroUsize::new(DEFAULT_MAX_REMOTE_STATE_ACTORS)
                .expect("default remote-state actor capacity is nonzero"),
            max_active_relay_actors: NonZeroUsize::new(DEFAULT_MAX_ACTIVE_RELAY_ACTORS)
                .expect("default active-relay actor capacity is nonzero"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EndpointLimitsValidationError {
    ArithmeticOverflow,
    InsufficientTaskCapacity { configured: usize, required: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionError {
    CapacityFull,
    CounterExhausted,
}

/// Point-in-time utilization for one endpoint capacity ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacitySnapshot {
    /// Configured maximum number of live resources.
    pub maximum: usize,
    /// Current number of live resources.
    pub current: usize,
    /// Largest observed number of live resources.
    pub high_water: usize,
    /// Number of rejected admissions.
    pub rejections: u64,
    /// Whether accounting exhausted and latched the ledger closed.
    pub counter_exhausted: bool,
}

/// Point-in-time utilization for the endpoint runtime's live-task capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskCapacitySnapshot {
    /// Configured maximum number of live runtime tasks.
    pub maximum: usize,
    /// Current number of live runtime tasks.
    pub current: usize,
    /// Largest observed number of simultaneously live runtime tasks.
    pub high_water: usize,
    /// Number of rejected task spawns.
    pub rejections: u64,
    /// Whether rejection accounting exhausted and latched the task group closed.
    pub counter_exhausted: bool,
}

#[derive(Debug)]
pub(crate) struct AdmissionLedger {
    maximum: NonZeroUsize,
    current: AtomicUsize,
    high_water: AtomicUsize,
    rejections: AtomicU64,
    failed: AtomicBool,
}

impl AdmissionLedger {
    pub(crate) fn new(maximum: NonZeroUsize) -> Arc<Self> {
        Arc::new(Self {
            maximum,
            current: AtomicUsize::new(0),
            high_water: AtomicUsize::new(0),
            rejections: AtomicU64::new(0),
            failed: AtomicBool::new(false),
        })
    }

    pub(crate) fn try_acquire(self: &Arc<Self>) -> Result<AdmissionPermit, AdmissionError> {
        if self.failed.load(Ordering::Acquire) {
            return Err(AdmissionError::CounterExhausted);
        }
        let previous = self
            .current
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                if current < self.maximum.get() {
                    current.checked_add(1)
                } else {
                    None
                }
            });
        let previous = match previous {
            Ok(previous) => previous,
            Err(_) => {
                self.record_rejection()?;
                return Err(AdmissionError::CapacityFull);
            }
        };
        let current = previous
            .checked_add(1)
            .expect("successful checked admission cannot overflow");
        self.high_water.fetch_max(current, Ordering::AcqRel);
        Ok(AdmissionPermit {
            ledger: self.clone(),
        })
    }

    pub(crate) fn snapshot(&self) -> CapacitySnapshot {
        CapacitySnapshot {
            maximum: self.maximum.get(),
            current: self.current.load(Ordering::Acquire),
            high_water: self.high_water.load(Ordering::Acquire),
            rejections: self.rejections.load(Ordering::Acquire),
            counter_exhausted: self.failed.load(Ordering::Acquire),
        }
    }

    fn record_rejection(&self) -> Result<(), AdmissionError> {
        self.rejections
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map(|_| ())
            .map_err(|_| {
                self.failed.store(true, Ordering::Release);
                AdmissionError::CounterExhausted
            })
    }
}

#[derive(Debug)]
pub(crate) struct AdmissionPermit {
    ledger: Arc<AdmissionLedger>,
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        let result =
            self.ledger
                .current
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current.checked_sub(1)
                });
        assert!(
            result.is_ok(),
            "endpoint admission ledger must not underflow"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::{AdmissionError, AdmissionLedger};

    #[test]
    fn admission_ledger_accepts_exact_limit_rejects_next_and_recovers() {
        let ledger = AdmissionLedger::new(NonZeroUsize::new(2).unwrap());
        let first = ledger.try_acquire().unwrap();
        let second = ledger.try_acquire().unwrap();
        assert_eq!(
            ledger.try_acquire().unwrap_err(),
            AdmissionError::CapacityFull
        );
        assert_eq!(ledger.snapshot().current, 2);
        assert_eq!(ledger.snapshot().high_water, 2);
        assert_eq!(ledger.snapshot().rejections, 1);

        drop(first);
        let replacement = ledger.try_acquire().unwrap();
        drop((second, replacement));
        assert_eq!(ledger.snapshot().current, 0);
    }
}
