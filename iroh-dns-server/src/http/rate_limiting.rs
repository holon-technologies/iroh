use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Instant,
};

use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use ipnet::IpNet;
use lru::LruCache;
use serde::{Deserialize, Serialize};

use crate::{config::IngressPolicy, metrics::Metrics};

/// Rate limiting strategy for the HTTP server.
#[derive(Debug, Deserialize, Default, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum RateLimitConfig {
    /// Disables only the per-IP policy; global admission limits remain active.
    Disabled,
    /// Rate limits by the connection's peer IP address.
    #[default]
    Simple,
    /// Walks `X-Forwarded-For` from right to left when the peer belongs to an
    /// explicitly trusted proxy CIDR.
    ///
    /// The first address outside the trusted proxy chain identifies the client.
    /// Missing, malformed, or ambiguous headers fail closed to the peer address.
    Smart,
}

impl Default for &RateLimitConfig {
    fn default() -> Self {
        &RateLimitConfig::Simple
    }
}

#[derive(Debug)]
pub(super) struct RateLimiter {
    mode: RateLimitConfig,
    trusted_proxies: Vec<IpNet>,
    entries: Mutex<LruCache<IpAddr, Bucket>>,
    metrics: Arc<Metrics>,
}

impl RateLimiter {
    fn new(mode: RateLimitConfig, policy: &IngressPolicy, metrics: Arc<Metrics>) -> Self {
        Self {
            mode,
            trusted_proxies: policy.trusted_proxy_cidrs.clone(),
            entries: Mutex::new(LruCache::new(policy.max_rate_limit_entries)),
            metrics,
        }
    }

    fn check(&self, peer: SocketAddr, headers: &HeaderMap, now: Instant) -> bool {
        let key = self.client_ip(peer, headers);
        let mut entries = match self.entries.lock() {
            Ok(entries) => entries,
            Err(poisoned) => poisoned.into_inner(),
        };
        let allowed = match entries.get_mut(&key) {
            Some(bucket) => bucket.try_take(now),
            None => {
                let mut bucket = Bucket::new(now);
                let allowed = bucket.try_take(now);
                entries.put(key, bucket);
                allowed
            }
        };
        self.metrics
            .http_rate_limit_entries
            .set(i64::try_from(entries.len()).unwrap_or(i64::MAX));
        if !allowed {
            self.metrics.http_requests_rejected_rate.inc();
        }
        allowed
    }

    fn client_ip(&self, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
        if self.mode != RateLimitConfig::Smart || !self.is_trusted_proxy(peer.ip()) {
            return peer.ip();
        }

        let mut forwarded_values = headers.get_all("x-forwarded-for").iter();
        let Some(forwarded) = forwarded_values.next() else {
            return peer.ip();
        };
        if forwarded_values.next().is_some() {
            return peer.ip();
        }
        let Ok(forwarded) = forwarded.to_str() else {
            return peer.ip();
        };

        let mut current = peer.ip();
        for value in forwarded.rsplit(',') {
            if !self.is_trusted_proxy(current) {
                break;
            }
            let Ok(next) = value.trim().parse() else {
                return peer.ip();
            };
            current = next;
        }
        current
    }

    fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        self.trusted_proxies
            .iter()
            .any(|network| network.contains(&ip))
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

/// Construct bounded per-IP state. No maintenance thread is required.
pub(super) fn create(
    config: &RateLimitConfig,
    policy: &IngressPolicy,
    metrics: Arc<Metrics>,
) -> Option<Arc<RateLimiter>> {
    match config {
        RateLimitConfig::Disabled => None,
        mode => Some(Arc::new(RateLimiter::new(*mode, policy, metrics))),
    }
}

pub(super) async fn middleware(
    State(limiter): State<Arc<RateLimiter>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);
    match peer {
        Some(peer) if limiter.check(peer, req.headers(), Instant::now()) => next.run(req).await,
        Some(_) => (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, "1")]).into_response(),
        None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

impl Bucket {
    const BURST: f64 = 2.0;
    const RATE_PER_SECOND: f64 = 4.0;

    fn new(now: Instant) -> Self {
        Self {
            tokens: Self::BURST,
            last_refill: now,
        }
    }

    fn try_take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last_refill);
        self.tokens =
            (self.tokens + elapsed.as_secs_f64() * Self::RATE_PER_SECOND).min(Self::BURST);
        self.last_refill = self.last_refill.max(now);
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
        reason = "test helpers override selected limits"
    )]

    use super::*;
    use crate::{config::LimitsConfig, metrics::Metrics};

    fn policy(capacity: usize, proxies: &[&str]) -> IngressPolicy {
        let mut limits = LimitsConfig::default();
        limits.max_rate_limit_entries = capacity;
        limits.trusted_proxy_cidrs = proxies.iter().map(|value| value.parse().unwrap()).collect();
        IngressPolicy::try_from(&limits).unwrap()
    }

    #[test]
    fn unique_clients_never_grow_state_past_capacity() {
        let limiter = RateLimiter::new(
            RateLimitConfig::Simple,
            &policy(2, &[]),
            Arc::new(Metrics::default()),
        );
        let now = Instant::now();
        for host in 1..=10 {
            assert!(limiter.check(
                SocketAddr::from(([192, 0, 2, host], 80)),
                &HeaderMap::new(),
                now,
            ));
        }
        assert_eq!(limiter.len(), 2);
    }

    #[test]
    fn smart_headers_are_honored_only_for_trusted_peers() {
        let limiter = RateLimiter::new(
            RateLimitConfig::Smart,
            &policy(2, &["127.0.0.0/8"]),
            Arc::new(Metrics::default()),
        );
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
        assert_eq!(
            limiter.client_ip(SocketAddr::from(([127, 0, 0, 1], 80)), &headers),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            limiter.client_ip(SocketAddr::from(([198, 51, 100, 4], 80)), &headers),
            "198.51.100.4".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn smart_mode_ignores_client_spoofed_forwarded_prefixes() {
        let limiter = RateLimiter::new(
            RateLimitConfig::Smart,
            &policy(2, &["127.0.0.0/8"]),
            Arc::new(Metrics::default()),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.99, 203.0.113.7".parse().unwrap(),
        );

        assert_eq!(
            limiter.client_ip(SocketAddr::from(([127, 0, 0, 1], 80)), &headers),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
    }
}
