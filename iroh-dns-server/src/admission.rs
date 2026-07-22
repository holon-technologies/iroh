//! Owned, non-blocking HTTP admission capacity.

use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{config::IngressPolicy, metrics::Metrics};

#[derive(Debug)]
pub(crate) struct AdmissionControl {
    connections: Arc<Semaphore>,
    requests: Arc<Semaphore>,
    accept_bucket: Mutex<TokenBucket>,
    metrics: Arc<Metrics>,
}

impl AdmissionControl {
    pub(crate) fn new(policy: IngressPolicy, metrics: Arc<Metrics>, now: Instant) -> Self {
        Self {
            connections: Arc::new(Semaphore::new(policy.max_http_connections.get())),
            requests: Arc::new(Semaphore::new(policy.max_http_requests.get())),
            accept_bucket: Mutex::new(TokenBucket::new(
                policy.http_accept_rate_per_second,
                policy.http_accept_burst.get(),
                now,
            )),
            metrics,
        }
    }

    pub(crate) fn try_connection(&self, now: Instant) -> ConnectionAdmission {
        let permit = match self.connections.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                self.metrics.http_connections_rejected_capacity.inc();
                return ConnectionAdmission::CapacityFull;
            }
        };
        let mut bucket = match self.accept_bucket.lock() {
            Ok(bucket) => bucket,
            Err(poisoned) => poisoned.into_inner(),
        };
        if !bucket.try_take(now) {
            self.metrics.http_connections_rejected_rate.inc();
            return ConnectionAdmission::RateLimited;
        }
        self.metrics.http_connections_active.inc();
        ConnectionAdmission::Accepted(HttpConnectionLease {
            _permit: permit,
            metrics: self.metrics.clone(),
        })
    }

    pub(crate) fn try_request(&self) -> RequestAdmission {
        match self.requests.clone().try_acquire_owned() {
            Ok(permit) => {
                self.metrics.http_requests_active.inc();
                RequestAdmission::Accepted(HttpRequestLease {
                    _permit: permit,
                    metrics: self.metrics.clone(),
                })
            }
            Err(_) => {
                self.metrics.http_requests_rejected_capacity.inc();
                RequestAdmission::CapacityFull
            }
        }
    }
}

#[derive(Debug)]
pub(crate) enum ConnectionAdmission {
    Accepted(HttpConnectionLease),
    RateLimited,
    CapacityFull,
}

#[derive(Debug)]
pub(crate) enum RequestAdmission {
    Accepted(HttpRequestLease),
    CapacityFull,
}

#[derive(Debug)]
pub(crate) struct HttpConnectionLease {
    _permit: OwnedSemaphorePermit,
    metrics: Arc<Metrics>,
}

impl Drop for HttpConnectionLease {
    fn drop(&mut self) {
        self.metrics.http_connections_active.dec();
    }
}

#[derive(Debug)]
pub(crate) struct HttpRequestLease {
    _permit: OwnedSemaphorePermit,
    metrics: Arc<Metrics>,
}

impl Drop for HttpRequestLease {
    fn drop(&mut self) {
        self.metrics.http_requests_active.dec();
    }
}

#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    rate_per_second: f64,
    burst: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(rate_per_second: f64, burst: usize, now: Instant) -> Self {
        Self {
            tokens: burst as f64,
            rate_per_second,
            burst: burst as f64,
            last_refill: now,
        }
    }

    fn try_take(&mut self, now: Instant) -> bool {
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
    #![allow(
        clippy::field_reassign_with_default,
        reason = "test cases mutate one limit at a time"
    )]

    use std::{sync::Arc, time::Instant};

    use crate::{
        config::{IngressPolicy, LimitsConfig},
        metrics::Metrics,
    };

    use super::*;

    fn policy(connection_limit: usize, request_limit: usize) -> IngressPolicy {
        let mut config = LimitsConfig::default();
        config.max_http_connections = connection_limit;
        config.max_http_requests = request_limit;
        IngressPolicy::try_from(&config).expect("test ingress policy is valid")
    }

    #[test]
    fn connection_admission_never_waits_and_releases_capacity() {
        let admission =
            AdmissionControl::new(policy(1, 1), Arc::new(Metrics::default()), Instant::now());
        let first = admission.try_connection(Instant::now());
        assert!(matches!(first, ConnectionAdmission::Accepted(_)));
        assert!(matches!(
            admission.try_connection(Instant::now()),
            ConnectionAdmission::CapacityFull
        ));
        drop(first);
        assert!(matches!(
            admission.try_connection(Instant::now()),
            ConnectionAdmission::Accepted(_)
        ));
    }

    #[test]
    fn request_admission_never_waits_and_releases_capacity() {
        let admission =
            AdmissionControl::new(policy(1, 1), Arc::new(Metrics::default()), Instant::now());
        let first = admission.try_request();
        assert!(matches!(first, RequestAdmission::Accepted(_)));
        assert!(matches!(
            admission.try_request(),
            RequestAdmission::CapacityFull
        ));
        drop(first);
        assert!(matches!(
            admission.try_request(),
            RequestAdmission::Accepted(_)
        ));
    }
}
