//! Injectable monotonic and wall-clock capabilities.

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    fmt,
    future::Future,
    num::NonZeroU64,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub use std::time::{Instant, SystemTime};
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub use web_time::{Instant, SystemTime};

use crate::{IdExhausted, TraceRecordError, TraceSinkError};

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
static NEXT_CLOCK_DOMAIN: AtomicU64 = AtomicU64::new(1);

/// Process-local identity of one coherent monotonic clock domain.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ClockDomain(NonZeroU64);

impl ClockDomain {
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    /// Allocates a process-local identity for a new monotonic clock domain.
    ///
    /// Domain values are coherence guards only. They are deliberately excluded from
    /// portable traces and replay artifacts.
    pub fn fresh() -> Self {
        let value = NEXT_CLOCK_DOMAIN.fetch_add(1, Ordering::Relaxed);
        let value = NonZeroU64::new(value).expect("clock domain identity space exhausted");
        Self(value)
    }
}

/// A resettable timer driven by a [`Clock`].
pub trait Timer: fmt::Debug + Send + 'static {
    /// Returns the stable timer identity.
    fn id(&self) -> crate::TimerId;

    /// Returns the current deadline.
    fn deadline(&self) -> Instant;

    /// Changes the deadline.
    fn reset(self: Pin<&mut Self>, deadline: Instant) -> Result<(), ClockError>;

    /// Polls for timer completion.
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), ClockError>>;
}

/// Monotonic time and timer creation for one clock domain.
pub trait Clock: fmt::Debug + Send + Sync + 'static {
    /// Returns the identity shared with executors and timers using this clock.
    fn domain(&self) -> ClockDomain;

    /// Returns the current monotonic time.
    fn now(&self) -> Instant;

    /// Creates a resettable timer.
    fn new_timer(&self, deadline: Instant) -> Result<Pin<Box<dyn Timer>>, ClockError>;

    /// Returns elapsed nanoseconds on this clock's run-relative timeline.
    fn elapsed_nanos(&self) -> Result<u64, ClockError>;

    /// Takes a deferred clock failure, such as an error observed while dropping a timer.
    fn take_failure(&self) -> Option<ClockError> {
        None
    }
}

/// Calendar time used for certificate and record validity.
pub trait WallClock: fmt::Debug + Send + Sync + 'static {
    /// Returns current wall-clock time.
    fn now_system(&self) -> SystemTime;
}

/// A one-shot future driven exclusively by an injected [`Clock`].
#[derive(Debug)]
pub struct ClockSleep {
    timer: Pin<Box<dyn Timer>>,
}

impl ClockSleep {
    /// Creates a sleep for an absolute deadline in `clock`'s domain.
    pub fn new(clock: Arc<dyn Clock>, deadline: Instant) -> Result<Self, ClockError> {
        Ok(Self {
            timer: clock.new_timer(deadline)?,
        })
    }

    /// Creates a sleep relative to the clock's current instant.
    pub fn after(clock: Arc<dyn Clock>, duration: Duration) -> Result<Self, ClockError> {
        let deadline = clock
            .now()
            .checked_add(duration)
            .ok_or(ClockError::TimelineOverflow)?;
        Self::new(clock, deadline)
    }

    /// Returns the stable identity of the underlying timer.
    pub fn timer_id(&self) -> crate::TimerId {
        self.timer.id()
    }

    /// Returns the current absolute deadline.
    pub fn deadline(&self) -> Instant {
        self.timer.deadline()
    }

    /// Changes the deadline without replacing the underlying timer identity.
    pub fn reset(&mut self, deadline: Instant) -> Result<(), ClockError> {
        self.timer.as_mut().reset(deadline)
    }
}

impl Future for ClockSleep {
    type Output = Result<(), ClockError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.timer.as_mut().poll(cx)
    }
}

/// A periodic timer driven exclusively by an injected [`Clock`].
#[derive(Debug)]
pub struct ClockInterval {
    clock: Arc<dyn Clock>,
    sleep: ClockSleep,
    next: Instant,
    period: Duration,
}

impl ClockInterval {
    /// Starts an interval after `initial_delay` and retains its original cadence.
    pub fn new(
        clock: Arc<dyn Clock>,
        initial_delay: Duration,
        period: Duration,
    ) -> Result<Self, ClockError> {
        if period.is_zero() {
            return Err(ClockError::InvalidPeriod);
        }
        let next = clock
            .now()
            .checked_add(initial_delay)
            .ok_or(ClockError::TimelineOverflow)?;
        let sleep = ClockSleep::new(clock.clone(), next)?;
        Ok(Self {
            clock,
            sleep,
            next,
            period,
        })
    }

    /// Waits for and returns the scheduled instant of the next tick.
    ///
    /// Cadence is advanced from the prior scheduled instant. If multiple periods elapsed, later
    /// calls complete immediately until the interval catches up, matching Tokio's burst behavior.
    pub async fn tick(&mut self) -> Result<Instant, ClockError> {
        (&mut self.sleep).await?;
        let fired = self.next;
        self.next = self
            .next
            .checked_add(self.period)
            .ok_or(ClockError::TimelineOverflow)?;
        self.sleep.reset(self.next)?;
        Ok(fired)
    }

    /// Restarts the cadence one full period from the clock's current instant.
    pub fn reset(&mut self) -> Result<(), ClockError> {
        self.next = self
            .clock
            .now()
            .checked_add(self.period)
            .ok_or(ClockError::TimelineOverflow)?;
        self.sleep.reset(self.next)
    }
}

/// Failure returned by a clock-backed timeout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TimeoutError {
    /// The injected deadline elapsed before the inner future completed.
    Elapsed,
    /// The injected clock failed.
    Clock(ClockError),
}

impl fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Elapsed => f.write_str("runtime deadline elapsed"),
            Self::Clock(error) => write!(f, "runtime timeout clock failed: {error}"),
        }
    }
}

impl std::error::Error for TimeoutError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Elapsed => None,
            Self::Clock(error) => Some(error),
        }
    }
}

/// Races a future against one deadline from an injected [`Clock`].
#[derive(Debug)]
pub struct ClockTimeout<F> {
    future: Pin<Box<F>>,
    sleep: ClockSleep,
}

impl<F> ClockTimeout<F> {
    /// Creates a timeout at an absolute deadline.
    pub fn new(clock: Arc<dyn Clock>, deadline: Instant, future: F) -> Result<Self, ClockError> {
        Ok(Self {
            future: Box::pin(future),
            sleep: ClockSleep::new(clock, deadline)?,
        })
    }

    /// Creates a timeout relative to the injected clock's current instant.
    pub fn after(clock: Arc<dyn Clock>, duration: Duration, future: F) -> Result<Self, ClockError> {
        let deadline = clock
            .now()
            .checked_add(duration)
            .ok_or(ClockError::TimelineOverflow)?;
        Self::new(clock, deadline, future)
    }
}

impl<F: Future> Future for ClockTimeout<F> {
    type Output = Result<F::Output, TimeoutError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();
        if let Poll::Ready(output) = this.future.as_mut().poll(cx) {
            return Poll::Ready(Ok(output));
        }
        match Pin::new(&mut this.sleep).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Err(TimeoutError::Elapsed)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(TimeoutError::Clock(error))),
        }
    }
}

/// Production wall clock backed by the operating system.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemWallClock;

impl WallClock for SystemWallClock {
    fn now_system(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Monotonic clock or timer failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClockError {
    /// A stable timer or trace sequence ID could not be allocated.
    IdExhausted,
    /// A timestamp cannot be represented by the trace schema.
    TimelineOverflow,
    /// The clock backend is no longer available.
    BackendUnavailable,
    /// A clock-owned resource counter cannot be represented.
    ResourceCounterOverflow,
    /// A periodic timer was configured with a zero period.
    InvalidPeriod,
    /// The trace sink rejected a timer observation.
    Trace(TraceSinkError),
    /// The shared trace recorder could not assign or retain an event.
    Recorder(TraceRecordError),
}

impl fmt::Display for ClockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdExhausted => f.write_str("runtime clock identifier space exhausted"),
            Self::TimelineOverflow => f.write_str("runtime clock exceeds trace timeline range"),
            Self::BackendUnavailable => f.write_str("runtime clock backend is unavailable"),
            Self::ResourceCounterOverflow => f.write_str("runtime clock resource counter overflow"),
            Self::InvalidPeriod => f.write_str("runtime interval period must be nonzero"),
            Self::Trace(err) => write!(f, "runtime clock trace failed: {err}"),
            Self::Recorder(err) => write!(f, "runtime clock trace failed: {err}"),
        }
    }
}

impl std::error::Error for ClockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Trace(err) => Some(err),
            Self::Recorder(err) => Some(err),
            _ => None,
        }
    }
}

impl From<IdExhausted> for ClockError {
    fn from(_: IdExhausted) -> Self {
        Self::IdExhausted
    }
}

impl From<TraceSinkError> for ClockError {
    fn from(value: TraceSinkError) -> Self {
        Self::Trace(value)
    }
}

impl From<TraceRecordError> for ClockError {
    fn from(value: TraceRecordError) -> Self {
        Self::Recorder(value)
    }
}

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
mod tokio_clock {
    use std::{
        future::Future,
        sync::{Arc, Mutex},
    };

    use super::*;
    use crate::{
        IdAllocator, NoopTraceSink, TimerId, TraceContext, TraceEventKind, TraceRecorder, TraceSink,
    };

    /// Production monotonic clock backed by Tokio time.
    #[derive(Clone, Debug)]
    pub struct TokioClock {
        inner: Arc<Inner>,
    }

    #[derive(Debug)]
    struct Inner {
        domain: ClockDomain,
        origin: Instant,
        timers: IdAllocator<TimerId>,
        recorder: Arc<TraceRecorder>,
        failure: Mutex<Option<ClockError>>,
    }

    impl Default for TokioClock {
        fn default() -> Self {
            Self::new(Arc::new(NoopTraceSink))
        }
    }

    impl TokioClock {
        /// Creates a Tokio clock whose lifecycle events are sent to `trace`.
        pub fn new(trace: Arc<dyn TraceSink>) -> Self {
            Self::with_recorder(Arc::new(TraceRecorder::new(trace)))
        }

        /// Creates a Tokio clock using a shared global trace recorder.
        pub fn with_recorder(recorder: Arc<TraceRecorder>) -> Self {
            Self {
                inner: Arc::new(Inner {
                    domain: ClockDomain::fresh(),
                    origin: tokio::time::Instant::now().into_std(),
                    timers: IdAllocator::default(),
                    recorder,
                    failure: Mutex::new(None),
                }),
            }
        }
    }

    impl Clock for TokioClock {
        fn domain(&self) -> ClockDomain {
            self.inner.domain
        }

        fn now(&self) -> Instant {
            tokio::time::Instant::now().into_std()
        }

        fn new_timer(&self, deadline: Instant) -> Result<Pin<Box<dyn Timer>>, ClockError> {
            let id = self.inner.timers.allocate()?;
            self.inner.record(TraceEventKind::TimerCreated {
                timer: id,
                deadline_nanos: self.inner.relative_nanos(deadline)?,
            })?;
            Ok(Box::pin(TokioTimer {
                id,
                deadline,
                sleep: Box::pin(tokio::time::sleep_until(deadline.into())),
                inner: self.inner.clone(),
                completed: false,
            }))
        }

        fn elapsed_nanos(&self) -> Result<u64, ClockError> {
            self.inner.relative_nanos(self.now())
        }

        fn take_failure(&self) -> Option<ClockError> {
            self.inner
                .failure
                .lock()
                .expect("clock failure lock poisoned")
                .take()
        }
    }

    impl Inner {
        fn relative_nanos(&self, instant: Instant) -> Result<u64, ClockError> {
            let nanos = instant
                .checked_duration_since(self.origin)
                .unwrap_or_default()
                .as_nanos();
            u64::try_from(nanos).map_err(|_| ClockError::TimelineOverflow)
        }

        fn record(&self, event: TraceEventKind) -> Result<(), ClockError> {
            let virtual_time_nanos = self.relative_nanos(self.now())?;
            self.recorder
                .record(virtual_time_nanos, TraceContext::default(), event)
                .map(|_| ())
                .map_err(Into::into)
        }

        fn now(&self) -> Instant {
            tokio::time::Instant::now().into_std()
        }

        fn latch(&self, error: ClockError) {
            let mut failure = self.failure.lock().expect("clock failure lock poisoned");
            if failure.is_none() {
                *failure = Some(error);
            }
        }
    }

    #[derive(Debug)]
    struct TokioTimer {
        id: TimerId,
        deadline: Instant,
        sleep: Pin<Box<tokio::time::Sleep>>,
        inner: Arc<Inner>,
        completed: bool,
    }

    impl Timer for TokioTimer {
        fn id(&self) -> TimerId {
            self.id
        }

        fn deadline(&self) -> Instant {
            self.deadline
        }

        fn reset(mut self: Pin<&mut Self>, deadline: Instant) -> Result<(), ClockError> {
            self.deadline = deadline;
            self.completed = false;
            self.sleep.as_mut().reset(deadline.into());
            self.inner.record(TraceEventKind::TimerReset {
                timer: self.id,
                deadline_nanos: self.inner.relative_nanos(deadline)?,
            })
        }

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), ClockError>> {
            if self.completed {
                return Poll::Ready(Ok(()));
            }
            if self.sleep.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.completed = true;
            Poll::Ready(
                self.inner
                    .record(TraceEventKind::TimerFired { timer: self.id }),
            )
        }
    }

    impl Drop for TokioTimer {
        fn drop(&mut self) {
            if !self.completed
                && let Err(error) = self
                    .inner
                    .record(TraceEventKind::TimerDropped { timer: self.id })
            {
                self.inner.latch(error);
            }
        }
    }
}

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub use tokio_clock::TokioClock;

#[cfg(all(test, not(all(target_family = "wasm", target_os = "unknown"))))]
mod tests {
    use std::{sync::Arc, time::Duration};

    use super::{Clock, ClockInterval, ClockSleep, ClockTimeout, TimeoutError, TokioClock};

    fn clock() -> Arc<dyn Clock> {
        Arc::new(TokioClock::default())
    }

    #[tokio::test(start_paused = true)]
    async fn clock_sleep_can_be_reset_without_replacing_its_identity() {
        let clock = clock();
        let start = clock.now();
        let mut sleep = ClockSleep::new(clock.clone(), start + Duration::from_secs(60)).unwrap();
        let timer = sleep.timer_id();

        sleep.reset(start + Duration::from_secs(5)).unwrap();
        tokio::time::advance(Duration::from_secs(5)).await;

        (&mut sleep).await.unwrap();
        assert_eq!(sleep.timer_id(), timer);
    }

    #[tokio::test(start_paused = true)]
    async fn clock_interval_retains_cadence_and_bursts_missed_ticks() {
        let clock = clock();
        let mut interval =
            ClockInterval::new(clock, Duration::from_secs(2), Duration::from_secs(3)).unwrap();

        tokio::time::advance(Duration::from_secs(8)).await;
        let first = interval.tick().await.unwrap();
        let second = interval.tick().await.unwrap();
        let third = interval.tick().await.unwrap();

        assert_eq!(second.duration_since(first), Duration::from_secs(3));
        assert_eq!(third.duration_since(second), Duration::from_secs(3));
    }

    #[tokio::test(start_paused = true)]
    async fn clock_timeout_distinguishes_inner_completion_from_elapsed_deadline() {
        let completed = ClockTimeout::after(clock(), Duration::from_secs(5), async { 7_u8 })
            .unwrap()
            .await;
        assert_eq!(completed, Ok(7));

        let timeout = ClockTimeout::after(clock(), Duration::from_secs(5), async {
            std::future::pending::<()>().await
        })
        .unwrap();
        tokio::pin!(timeout);
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(timeout.await, Err(TimeoutError::Elapsed));
    }
}
