//! Timer and retry-jitter capabilities used by DNS behavior.

use std::{fmt, future::Future, sync::Arc};

use n0_error::StackError;
use n0_future::{StreamExt, boxed::BoxFuture, time};

use crate::error::StaggeredError;

/// Percent of total delay to jitter. 20 means +/- 20% of delay.
const MAX_JITTER_PERCENT: u64 = 20;

/// Timer and retry-jitter capabilities used by DNS timeout and stagger behavior.
///
/// Normal constructors install the Tokio/OS-random implementation. Deterministic environments
/// may inject a virtual timer and seeded jitter source without replacing DNS parsing or lookup
/// aggregation logic.
pub trait DnsRuntime: fmt::Debug + Send + Sync + 'static {
    /// Sleeps for one behavioral deadline.
    fn sleep(&self, duration: time::Duration) -> BoxFuture<()>;

    /// Returns the delay for one configured retry stagger in milliseconds.
    fn stagger_delay(&self, delay_ms: u64) -> time::Duration;
}

#[derive(Debug, Default)]
pub(crate) struct ProductionDnsRuntime;

impl DnsRuntime for ProductionDnsRuntime {
    fn sleep(&self, duration: time::Duration) -> BoxFuture<()> {
        Box::pin(time::sleep(duration))
    }

    fn stagger_delay(&self, delay_ms: u64) -> time::Duration {
        add_jitter(delay_ms)
    }
}

/// Staggers calls using the provided bounded delay list.
pub(crate) async fn stagger_call<
    T,
    E: StackError + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, E>>,
>(
    runtime: Arc<dyn DnsRuntime>,
    call: F,
    delays_ms: &[u64],
) -> Result<T, StaggeredError<E>> {
    let capacity = delays_ms.len().saturating_add(1);
    let mut calls = n0_future::FuturesUnorderedBounded::new(capacity);
    for delay in std::iter::once(&0u64).chain(delays_ms) {
        let delay = runtime.stagger_delay(*delay);
        let runtime = runtime.clone();
        let future = call();
        calls.push(async move {
            runtime.sleep(delay).await;
            future.await
        });
    }

    let mut errors = Vec::with_capacity(capacity);
    while let Some(result) = calls.next().await {
        match result {
            Ok(value) => return Ok(value),
            Err(error) => errors.push(error),
        }
    }

    Err(StaggeredError::new(errors))
}

pub(crate) fn add_jitter(delay_ms: u64) -> time::Duration {
    jittered_delay(delay_ms, rand::random())
}

/// Applies a deterministic ±20% jitter draw without overflow or an empty modulo domain.
pub(crate) fn jittered_delay(delay_ms: u64, draw: u64) -> time::Duration {
    if delay_ms == 0 {
        return time::Duration::ZERO;
    }

    let radius = delay_ms
        .saturating_mul(MAX_JITTER_PERCENT)
        .checked_div(100)
        .unwrap_or(0)
        .max(1);
    let width = radius.saturating_mul(2).saturating_add(1);
    let offset = draw % width;
    time::Duration::from_millis(delay_ms.saturating_sub(radius).saturating_add(offset))
}
