//! Coherent runtime capability bundles.

use std::{fmt, sync::Arc};

use crate::{
    Clock, DecisionSource, Executor, RootSeed, SeededDecisionSource, SystemWallClock, TokioClock,
    TokioExecutor, TraceDecisionObserver, TraceRecorder, TraceSink, WallClock,
};

/// One coherent set of runtime capabilities for an Iroh endpoint.
///
/// Keeping these capabilities together prevents production and simulation code from
/// accidentally mixing clock domains, identity spaces, decision seeds, or trace sequences.
#[derive(Clone, Debug)]
pub struct RuntimeContext {
    root_seed: RootSeed,
    clock: Arc<dyn Clock>,
    wall_clock: Arc<dyn WallClock>,
    executor: Arc<dyn Executor>,
    decisions: Arc<dyn DecisionSource>,
    trace: Arc<TraceRecorder>,
}

/// Explicit acknowledgement that a non-production runtime is test infrastructure.
///
/// Normal endpoint builders never construct or select this marker implicitly.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UnsafeTestOnly;

impl UnsafeTestOnly {
    /// Acknowledges that an explicitly injected context is not a production default.
    pub const fn acknowledge() -> Self {
        Self
    }
}

impl RuntimeContext {
    /// Creates the production Tokio capability bundle with an explicit behavioral seed.
    pub fn tokio(root_seed: RootSeed, sink: Arc<dyn TraceSink>) -> Self {
        let trace = Arc::new(TraceRecorder::new(sink));
        let clock: Arc<dyn Clock> = Arc::new(TokioClock::with_recorder(trace.clone()));
        let executor: Arc<dyn Executor> =
            Arc::new(TokioExecutor::with_clock(clock.clone(), trace.clone()));
        let decisions: Arc<dyn DecisionSource> = Arc::new(SeededDecisionSource::with_observer(
            root_seed,
            Arc::new(TraceDecisionObserver::new(clock.clone(), trace.clone())),
        ));
        Self::from_parts(
            root_seed,
            clock,
            Arc::new(SystemWallClock),
            executor,
            decisions,
            trace,
        )
        .expect("Tokio executor and clock are constructed from the same domain")
    }

    /// Creates the normal production bundle with an operating-system-backed behavioral seed.
    pub fn production(sink: Arc<dyn TraceSink>) -> Self {
        Self::tokio(RootSeed::random(), sink)
    }

    /// Creates a capability bundle from environment-specific implementations.
    pub fn from_parts(
        root_seed: RootSeed,
        clock: Arc<dyn Clock>,
        wall_clock: Arc<dyn WallClock>,
        executor: Arc<dyn Executor>,
        decisions: Arc<dyn DecisionSource>,
        trace: Arc<TraceRecorder>,
    ) -> Result<Self, RuntimeContextError> {
        if clock.domain() != executor.clock_domain() {
            return Err(RuntimeContextError::ClockDomainMismatch);
        }
        Ok(Self {
            root_seed,
            clock,
            wall_clock,
            executor,
            decisions,
            trace,
        })
    }

    /// Returns the root seed for behavioral decisions and replay manifests.
    pub const fn root_seed(&self) -> RootSeed {
        self.root_seed
    }

    /// Returns the monotonic clock shared by runtime timers and trace timestamps.
    pub fn clock(&self) -> Arc<dyn Clock> {
        self.clock.clone()
    }

    /// Returns the wall clock used for certificate and record validity.
    pub fn wall_clock(&self) -> Arc<dyn WallClock> {
        self.wall_clock.clone()
    }

    /// Returns the structured executor sharing this context's clock and trace.
    pub fn executor(&self) -> Arc<dyn Executor> {
        self.executor.clone()
    }

    /// Returns the domain-separated behavioral decision source.
    pub fn decisions(&self) -> Arc<dyn DecisionSource> {
        self.decisions.clone()
    }

    /// Returns the global trace recorder for this runtime context.
    pub fn trace(&self) -> Arc<TraceRecorder> {
        self.trace.clone()
    }
}

/// Runtime capabilities cannot be composed into one coherent environment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeContextError {
    /// Executor observations and timers use different monotonic clock domains.
    ClockDomainMismatch,
}

impl fmt::Display for RuntimeContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("runtime executor and clock use different monotonic domains")
    }
}

impl std::error::Error for RuntimeContextError {}
