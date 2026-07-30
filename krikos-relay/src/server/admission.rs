//! Owned relay admission capacity.

use std::sync::{Arc, Mutex};

use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::Instant,
};

use super::AdmissionPolicy;

/// Shared connection and session admission state.
#[derive(Debug)]
pub(super) struct AdmissionControl {
    pending_establishments: Arc<Semaphore>,
    registered_sessions: Arc<Semaphore>,
    max_sessions_per_endpoint: usize,
    max_sent_to_peers_per_endpoint: usize,
    accept_bucket: Mutex<TokenBucket>,
}

impl AdmissionControl {
    pub(super) fn new(policy: AdmissionPolicy) -> Self {
        Self {
            pending_establishments: Arc::new(Semaphore::new(
                policy.max_pending_establishments.get(),
            )),
            registered_sessions: Arc::new(Semaphore::new(policy.max_registered_sessions.get())),
            max_sessions_per_endpoint: policy.max_sessions_per_endpoint.get(),
            max_sent_to_peers_per_endpoint: policy.max_registered_sessions.get(),
            accept_bucket: Mutex::new(TokenBucket::new(
                policy.accept_conn_limit,
                policy.accept_conn_burst.get(),
            )),
        }
    }

    /// Attempts admission without waiting or creating queued work.
    pub(super) fn try_establishment(self: &Arc<Self>) -> EstablishmentAdmission {
        let permit = match self.pending_establishments.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return EstablishmentAdmission::PendingCapacityFull,
        };

        let mut bucket = match self.accept_bucket.lock() {
            Ok(bucket) => bucket,
            Err(poisoned) => poisoned.into_inner(),
        };
        if !bucket.try_take() {
            return EstablishmentAdmission::RateLimited;
        }

        EstablishmentAdmission::Accepted(EstablishmentLease { _permit: permit })
    }

    pub(super) fn try_session(self: &Arc<Self>) -> Option<SessionLease> {
        self.registered_sessions
            .clone()
            .try_acquire_owned()
            .ok()
            .map(|permit| SessionLease { _permit: permit })
    }

    pub(super) fn max_sessions_per_endpoint(&self) -> usize {
        self.max_sessions_per_endpoint
    }

    pub(super) fn max_sent_to_peers_per_endpoint(&self) -> usize {
        self.max_sent_to_peers_per_endpoint
    }
}

/// Result of trying to admit a newly accepted socket.
#[derive(Debug)]
pub(super) enum EstablishmentAdmission {
    Accepted(EstablishmentLease),
    RateLimited,
    PendingCapacityFull,
}

/// Owns one pending-establishment capacity slot.
#[derive(Debug)]
pub(super) struct EstablishmentLease {
    _permit: OwnedSemaphorePermit,
}

/// Owns one registered-session capacity slot.
#[derive(Debug)]
pub(super) struct SessionLease {
    _permit: OwnedSemaphorePermit,
}

#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    rate_per_second: f64,
    burst: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(rate_per_second: f64, burst: usize) -> Self {
        Self {
            tokens: burst as f64,
            rate_per_second,
            burst: burst as f64,
            last_refill: Instant::now(),
        }
    }

    fn try_take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last_refill);
        self.tokens = (self.tokens + elapsed.as_secs_f64() * self.rate_per_second).min(self.burst);
        self.last_refill = now;

        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn control(pending: usize, sessions: usize, rate: f64, burst: usize) -> Arc<AdmissionControl> {
        let limits = crate::server::Limits {
            max_pending_establishments: pending,
            max_registered_sessions: sessions,
            accept_conn_limit: Some(rate),
            accept_conn_burst: Some(burst),
            ..crate::server::Limits::default()
        };
        let policy = AdmissionPolicy::try_from(&limits).expect("test policy is valid");
        Arc::new(AdmissionControl::new(policy))
    }

    #[tokio::test(start_paused = true)]
    async fn token_bucket_enforces_burst_and_refills() {
        let mut bucket = TokenBucket::new(2.0, 2);
        assert!(bucket.try_take());
        assert!(bucket.try_take());
        assert!(!bucket.try_take());

        tokio::time::advance(std::time::Duration::from_millis(500)).await;
        assert!(bucket.try_take());
        assert!(!bucket.try_take());
    }

    #[test]
    fn establishment_capacity_is_non_blocking_and_owned() {
        let control = control(1, 1, 100.0, 100);
        let lease = match control.try_establishment() {
            EstablishmentAdmission::Accepted(lease) => lease,
            outcome => panic!("first establishment should be accepted, got {outcome:?}"),
        };
        assert!(matches!(
            control.try_establishment(),
            EstablishmentAdmission::PendingCapacityFull
        ));

        drop(lease);
        assert!(matches!(
            control.try_establishment(),
            EstablishmentAdmission::Accepted(_)
        ));
    }

    #[test]
    fn connection_rate_limit_rejects_after_burst() {
        let control = control(3, 1, 1.0, 2);
        assert!(matches!(
            control.try_establishment(),
            EstablishmentAdmission::Accepted(_)
        ));
        assert!(matches!(
            control.try_establishment(),
            EstablishmentAdmission::Accepted(_)
        ));
        assert!(matches!(
            control.try_establishment(),
            EstablishmentAdmission::RateLimited
        ));
    }

    #[test]
    fn session_capacity_is_released_with_lease() {
        let control = control(1, 1, 100.0, 100);
        let lease = control.try_session().expect("first session is admitted");
        assert!(control.try_session().is_none());
        drop(lease);
        assert!(control.try_session().is_some());
    }

    proptest! {
        #[test]
        fn owned_session_leases_preserve_capacity(
            limit in 1usize..64,
            operations in prop::collection::vec(any::<bool>(), 0..512),
        ) {
            let control = control(1, limit, 100.0, 100);
            let mut leases = Vec::new();

            for acquire in operations {
                if acquire {
                    if let Some(lease) = control.try_session() {
                        leases.push(lease);
                    }
                } else {
                    leases.pop();
                }
                prop_assert_eq!(
                    leases.len() + control.registered_sessions.available_permits(),
                    limit,
                );
            }
        }
    }
}
