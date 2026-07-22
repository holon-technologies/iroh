use std::{pin::Pin, sync::Arc};

use iroh_base::EndpointId;
#[cfg(not(wasm_browser))]
use iroh_runtime::{OwnedTaskHandle, RuntimeContext, SpawnError, TaskGroup, TaskKind};

/// Adapts the shared wall clock to Noq's token-validity clock.
#[cfg(not(wasm_browser))]
#[derive(Debug)]
pub(crate) struct NoqWallClock(Arc<dyn iroh_runtime::WallClock>);

#[cfg(not(wasm_browser))]
impl NoqWallClock {
    pub(crate) fn new(clock: Arc<dyn iroh_runtime::WallClock>) -> Self {
        Self(clock)
    }
}

#[cfg(not(wasm_browser))]
impl noq_proto::TimeSource for NoqWallClock {
    fn now(&self) -> std::time::SystemTime {
        self.0.now_system()
    }
}

#[derive(Debug)]
pub(crate) struct Runtime {
    id: EndpointId,
    #[cfg(not(wasm_browser))]
    context: Arc<RuntimeContext>,
    #[cfg(not(wasm_browser))]
    tasks: Arc<dyn TaskGroup>,
    #[cfg(not(wasm_browser))]
    failure: Arc<std::sync::Mutex<Option<String>>>,
}

impl Runtime {
    /// Create a new [`Runtime`] that manages shutting down tasks properly,
    /// whether gracefully or un-gracefully.
    #[cfg(not(wasm_browser))]
    pub(crate) fn new(id: EndpointId, context: Arc<RuntimeContext>) -> Self {
        let tasks = context.executor().new_group(None);
        Self {
            id,
            context,
            tasks,
            failure: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    #[cfg(wasm_browser)]
    pub(crate) fn new(id: EndpointId) -> Self {
        Self { id }
    }

    /// Shutdown the runtime gracefully.
    ///
    /// Closes the task tracker and waits for all spawned tasks to finish naturally.
    #[cfg(not(wasm_browser))]
    pub(crate) async fn shutdown(&self) {
        self.abort();
        if let Err(error) = self.tasks.join().await {
            self.latch_failure(error.to_string());
        }
    }

    /// Shutdown the runtime ASAP, not waiting for any graceful closing of tasks.
    #[cfg(not(wasm_browser))]
    pub(crate) fn abort(&self) {
        self.tasks.cancel();
        self.tasks.close();
    }

    #[cfg(not(wasm_browser))]
    pub(crate) fn latch_failure(&self, error: String) {
        latch_failure(&self.failure, error);
    }

    #[cfg(not(wasm_browser))]
    pub(crate) fn context(&self) -> &Arc<RuntimeContext> {
        &self.context
    }

    pub(crate) const fn id(&self) -> EndpointId {
        self.id
    }

    #[cfg(all(test, not(wasm_browser)))]
    pub(crate) fn task_snapshot(&self) -> iroh_runtime::TaskGroupSnapshot {
        self.tasks.snapshot()
    }

    #[cfg(not(wasm_browser))]
    pub(crate) fn spawn_owned(
        &self,
        kind: TaskKind,
        name: &str,
        future: Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>,
    ) -> Result<OwnedTaskHandle, SpawnError> {
        self.tasks.spawn_owned(kind, name, future)
    }

    #[cfg(not(wasm_browser))]
    pub(crate) fn spawn(
        &self,
        kind: TaskKind,
        name: &str,
        future: Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>,
    ) -> Result<iroh_runtime::TaskId, SpawnError> {
        match self.tasks.spawn(kind, name, future) {
            Ok(id) => Ok(id),
            Err(error) => {
                self.latch_failure(error.to_string());
                Err(error)
            }
        }
    }

    /// No-op on wasm. There is no task tracker to close or wait on.
    #[cfg(wasm_browser)]
    pub(crate) async fn shutdown(&self) {}

    /// No-op on wasm. There is no task tracker or cancellation to perform.
    #[cfg(wasm_browser)]
    pub(crate) fn abort(&self) {}
}

#[cfg(not(wasm_browser))]
pub(crate) type RuntimeInterval = iroh_runtime::ClockInterval;

#[cfg(not(wasm_browser))]
pub(crate) type RuntimeSleep = iroh_runtime::ClockSleep;

#[cfg(not(wasm_browser))]
pub(crate) type RuntimeTimeout<F> = iroh_runtime::ClockTimeout<F>;

impl noq::Runtime for Runtime {
    #[cfg(not(wasm_browser))]
    fn new_timer(&self, i: std::time::Instant) -> Pin<Box<dyn noq::AsyncTimer>> {
        match self.context.clock().new_timer(i) {
            Ok(timer) => Box::pin(NoqTimer {
                timer: Some(timer),
                failure: self.failure.clone(),
            }),
            Err(error) => {
                self.latch_failure(error.to_string());
                Box::pin(NoqTimer {
                    timer: None,
                    failure: self.failure.clone(),
                })
            }
        }
    }

    #[cfg(wasm_browser)]
    fn new_timer(&self, deadline: n0_future::time::Instant) -> Pin<Box<dyn noq::AsyncTimer>> {
        Box::pin(web::Timer(n0_future::time::sleep_until(deadline)))
    }

    #[cfg(not(wasm_browser))]
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        // Do not allow spawning more tasks if the runtime should be closed.
        if self.tasks.is_closed() {
            tracing::debug!(me = %self.id.fmt_short(), "runtime closed, dropping spawned task");
            return;
        }

        use tracing::{Instrument, trace_span};

        let span = trace_span!("runtime", me = %self.id.fmt_short());
        if let Err(error) = self
            .spawn_owned(TaskKind::Noq, "noq", Box::pin(future.instrument(span)))
            .map(OwnedTaskHandle::detach)
        {
            tracing::debug!(me = %self.id.fmt_short(), %error, "runtime rejected noq task");
            self.latch_failure(error.to_string());
        }
    }

    #[cfg(wasm_browser)]
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        wasm_bindgen_futures::spawn_local(future);
    }

    // We're not actually using this function in iroh
    #[cfg(not(wasm_browser))]
    fn wrap_udp_socket(
        &self,
        t: std::net::UdpSocket,
    ) -> std::io::Result<Box<dyn noq::AsyncUdpSocket>> {
        noq::TokioRuntime.wrap_udp_socket(t)
    }

    #[cfg(not(wasm_browser))]
    fn now(&self) -> std::time::Instant {
        self.context.clock().now()
    }
}

#[cfg(not(wasm_browser))]
#[derive(Debug)]
struct NoqTimer {
    timer: Option<Pin<Box<dyn iroh_runtime::Timer>>>,
    failure: Arc<std::sync::Mutex<Option<String>>>,
}

#[cfg(not(wasm_browser))]
impl noq::AsyncTimer for NoqTimer {
    fn reset(mut self: Pin<&mut Self>, deadline: std::time::Instant) {
        let Some(timer) = self.timer.as_mut() else {
            return;
        };
        if let Err(error) = timer.as_mut().reset(deadline) {
            latch_failure(&self.failure, error.to_string());
            self.timer = None;
        }
    }

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        let Some(timer) = self.timer.as_mut() else {
            return std::task::Poll::Ready(());
        };
        match timer.as_mut().poll(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(()),
            std::task::Poll::Ready(Err(error)) => {
                latch_failure(&self.failure, error.to_string());
                self.timer = None;
                std::task::Poll::Ready(())
            }
        }
    }
}

#[cfg(not(wasm_browser))]
fn latch_failure(failure: &std::sync::Mutex<Option<String>>, error: String) {
    let mut failure = failure.lock().expect("runtime failure lock poisoned");
    if failure.is_none() {
        *failure = Some(error);
    }
}

#[cfg(wasm_browser)]
mod web {
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    };

    use n0_future::time;

    #[derive(Debug)]
    pub(crate) struct Timer(pub(crate) time::Sleep);

    impl noq::AsyncTimer for Timer {
        fn reset(mut self: Pin<&mut Self>, deadline: time::Instant) {
            Pin::new(&mut self.0).reset(deadline)
        }

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            Pin::new(&mut self.0).poll(cx)
        }
    }
}

#[cfg(all(test, not(wasm_browser)))]
mod tests {
    use std::{
        future::Future,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll, Waker},
        time::{Duration, SystemTime},
    };

    use iroh_base::SecretKey;
    use tokio::sync::oneshot;

    use super::Runtime;

    fn runtime() -> Runtime {
        Runtime::new(
            SecretKey::from_bytes(&[42; 32]).public(),
            Arc::new(iroh_runtime::RuntimeContext::production(Arc::new(
                iroh_runtime::NoopTraceSink,
            ))),
        )
    }

    #[test]
    fn noq_wall_clock_delegates_to_runtime_context_clock() {
        let expected = SystemTime::UNIX_EPOCH + Duration::from_secs(1_234_567);
        let source = super::NoqWallClock::new(Arc::new(FixedWallClock(expected)));

        assert_eq!(noq_proto::TimeSource::now(&source), expected);
    }

    #[tokio::test]
    async fn spawned_task_runs_to_completion() {
        let runtime = runtime();
        let (send, recv) = oneshot::channel();

        noq::Runtime::spawn(
            &runtime,
            Box::pin(async move {
                send.send(()).expect("receiver remains alive");
            }),
        );

        recv.await.expect("spawned task sends completion");
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_cancels_and_waits_for_tracked_tasks() {
        let runtime = runtime();
        let dropped = Arc::new(AtomicBool::new(false));
        let task_dropped = dropped.clone();
        let (started_send, started_recv) = oneshot::channel();

        noq::Runtime::spawn(
            &runtime,
            Box::pin(async move {
                let _drop_guard = DropFlag(task_dropped);
                started_send.send(()).expect("receiver remains alive");
                std::future::pending::<()>().await;
            }),
        );

        started_recv.await.expect("spawned task starts");
        runtime.shutdown().await;

        assert!(
            dropped.load(Ordering::SeqCst),
            "shutdown must not return before the cancelled task is dropped"
        );
    }

    #[tokio::test]
    async fn spawn_after_abort_drops_future_without_polling() {
        let runtime = runtime();
        let polled = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));

        runtime.abort();
        noq::Runtime::spawn(
            &runtime,
            Box::pin(ProbeFuture {
                polled: polled.clone(),
                dropped: dropped.clone(),
            }),
        );

        assert!(!polled.load(Ordering::SeqCst));
        assert!(dropped.load(Ordering::SeqCst));
        runtime.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn timer_can_be_reset_to_an_earlier_deadline() {
        let runtime = runtime();
        let start = noq::Runtime::now(&runtime);
        let mut timer = noq::Runtime::new_timer(&runtime, start + Duration::from_secs(60));
        timer.as_mut().reset(start + Duration::from_secs(5));

        assert!(matches!(poll_timer(&mut timer), Poll::Pending));
        tokio::time::advance(Duration::from_secs(4)).await;
        assert!(matches!(poll_timer(&mut timer), Poll::Pending));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(poll_timer(&mut timer), Poll::Ready(())));

        runtime.shutdown().await;
    }

    fn poll_timer(timer: &mut Pin<Box<dyn noq::AsyncTimer>>) -> Poll<()> {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        timer.as_mut().poll(&mut cx)
    }

    struct DropFlag(Arc<AtomicBool>);

    #[derive(Debug)]
    struct FixedWallClock(SystemTime);

    impl iroh_runtime::WallClock for FixedWallClock {
        fn now_system(&self) -> SystemTime {
            self.0
        }
    }

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    struct ProbeFuture {
        polled: Arc<AtomicBool>,
        dropped: Arc<AtomicBool>,
    }

    impl Future for ProbeFuture {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.polled.store(true, Ordering::SeqCst);
            Poll::Pending
        }
    }

    impl Drop for ProbeFuture {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }
}
