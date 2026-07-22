//! Runtime capabilities shared by Iroh's production and simulation environments.
#![forbid(unsafe_code)]

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
mod context;
mod decision;
mod id;
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
mod task;
mod time;
mod trace;

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub use context::{RuntimeContext, RuntimeContextError, UnsafeTestOnly};
pub use decision::{
    DecisionError, DecisionObserver, DecisionPath, DecisionSource, DecisionStream,
    NoopDecisionObserver, RootSeed, SeededDecisionSource, TraceDecisionObserver,
};
pub use id::{DecisionId, IdAllocator, IdExhausted, TaskId, TimerId, TraceSequence};
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub use task::{
    BoxedTask, Executor, OwnedTaskHandle, SpawnError, TaskCompletion, TaskControl, TaskGroup,
    TaskGroupError, TaskGroupSnapshot, TaskHandleError, TaskOutcome, TokioExecutor,
};
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub use time::TokioClock;
pub use time::{
    Clock, ClockDomain, ClockError, ClockInterval, ClockSleep, ClockTimeout, Instant, SystemTime,
    SystemWallClock, TimeoutError, Timer, WallClock,
};
pub use trace::{
    NoopTraceSink, TRACE_SCHEMA_VERSION, TaskKind, TaskMetadata, TraceContext, TraceEvent,
    TraceEventKind, TraceRecordError, TraceRecorder, TraceSink, TraceSinkError,
};
