//! Seeded DNS timeout and retry-stagger capabilities for production `DnsResolver` logic.

use std::{
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};

use iroh::dns::DnsRuntime;
use iroh_runtime::DecisionStream;
use n0_future::boxed::BoxFuture;
use tokio::sync::oneshot;

use crate::{EventClass, Kernel, ScheduledEvent};

const MAX_JITTER_PERCENT: u64 = 20;

/// Kernel-backed timer and domain-separated jitter source for DNS behavior.
#[derive(Clone)]
pub struct DeterministicDnsRuntime {
    inner: Arc<DnsRuntimeInner>,
}

struct DnsRuntimeInner {
    kernel: Kernel,
    jitter: Mutex<Box<dyn DecisionStream>>,
    failure: Mutex<Option<String>>,
}

impl fmt::Debug for DeterministicDnsRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeterministicDnsRuntime")
            .field("kernel", &self.inner.kernel)
            .finish_non_exhaustive()
    }
}

impl DeterministicDnsRuntime {
    pub fn new(kernel: Kernel, jitter: Box<dyn DecisionStream>) -> Self {
        Self {
            inner: Arc::new(DnsRuntimeInner {
                kernel,
                jitter: Mutex::new(jitter),
                failure: Mutex::new(None),
            }),
        }
    }

    /// Returns and clears a deferred scheduling or decision failure.
    pub fn take_error(&self) -> Option<String> {
        self.inner
            .failure
            .lock()
            .expect("DNS runtime failure lock poisoned")
            .take()
    }
}

impl DnsRuntime for DeterministicDnsRuntime {
    fn sleep(&self, duration: Duration) -> BoxFuture<()> {
        let (sender, receiver) = oneshot::channel();
        let deadline = self.inner.kernel.now().checked_add(duration);
        let scheduled = deadline.and_then(|deadline| {
            self.inner
                .kernel
                .schedule_cancellable_at(deadline, EventClass::Infrastructure, move || {
                    let _ = sender.send(());
                    Ok(())
                })
                .ok()
        });
        if scheduled.is_none() {
            self.inner
                .failure
                .lock()
                .expect("DNS runtime failure lock poisoned")
                .replace("DNS timer could not be scheduled".to_owned());
        }
        Box::pin(DnsSleep {
            receiver,
            event: scheduled.map(|(_, event)| event),
        })
    }

    fn stagger_delay(&self, delay_ms: u64) -> Duration {
        if delay_ms == 0 {
            return Duration::ZERO;
        }
        let width = delay_ms.saturating_mul(MAX_JITTER_PERCENT * 2) / 100;
        if width == 0 {
            return Duration::from_millis(delay_ms);
        }
        let jitter = self
            .inner
            .jitter
            .lock()
            .expect("DNS jitter lock poisoned")
            .range_u64(0..width);
        match jitter {
            Ok(jitter) => {
                Duration::from_millis(delay_ms.saturating_sub(width / 2).saturating_add(jitter))
            }
            Err(error) => {
                self.inner
                    .failure
                    .lock()
                    .expect("DNS runtime failure lock poisoned")
                    .replace(error.to_string());
                Duration::from_millis(delay_ms)
            }
        }
    }
}

struct DnsSleep {
    receiver: oneshot::Receiver<()>,
    event: Option<ScheduledEvent>,
}

impl std::future::Future for DnsSleep {
    type Output = ();

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        match std::pin::Pin::new(&mut self.receiver).poll(cx) {
            std::task::Poll::Ready(_) => {
                self.event = None;
                std::task::Poll::Ready(())
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}
