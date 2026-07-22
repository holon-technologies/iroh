//! Structured task ownership and production Tokio execution.

use std::{
    collections::BTreeMap,
    fmt,
    future::Future,
    panic::AssertUnwindSafe,
    pin::Pin,
    sync::{Arc, Mutex},
};

use futures_util::FutureExt;
use tokio::sync::oneshot;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    Clock, ClockDomain, ClockError, IdAllocator, TaskId, TaskKind, TaskMetadata, TokioClock,
    TraceContext, TraceEventKind, TraceRecordError, TraceRecorder,
};

/// Owned task accepted by an [`Executor`].
pub type BoxedTask = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Creates structured task groups sharing one executor identity space.
pub trait Executor: fmt::Debug + Send + Sync + 'static {
    /// Returns the monotonic clock domain used for task observations.
    fn clock_domain(&self) -> ClockDomain;

    /// Creates a task group whose tasks have `parent` as their causal owner.
    fn new_group(&self, parent: Option<TaskId>) -> Arc<dyn TaskGroup>;
}

/// Owns a set of cancellable runtime tasks.
pub trait TaskGroup: fmt::Debug + Send + Sync + 'static {
    /// Spawns a task with stable role and ownership metadata.
    fn spawn(&self, kind: TaskKind, name: &str, future: BoxedTask) -> Result<TaskId, SpawnError> {
        self.spawn_owned(kind, name, future)
            .map(OwnedTaskHandle::detach)
    }

    /// Spawns a task with an abort-on-drop ownership handle.
    fn spawn_owned(
        &self,
        kind: TaskKind,
        name: &str,
        future: BoxedTask,
    ) -> Result<OwnedTaskHandle, SpawnError>;

    /// Prevents future task creation.
    fn close(&self);

    /// Requests cancellation of all current and future children.
    fn cancel(&self);

    /// Returns whether this group rejects new tasks.
    fn is_closed(&self) -> bool;

    /// Returns stable metadata for currently live tasks.
    fn snapshot(&self) -> TaskGroupSnapshot;

    /// Waits until a closed group has no remaining tasks.
    fn join(&self) -> Pin<Box<dyn Future<Output = Result<(), TaskGroupError>> + Send + '_>>;
}

/// Terminal result of a structured task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskOutcome {
    /// The future returned normally.
    Completed,
    /// The task or its owning group was cancelled.
    Cancelled,
    /// The future panicked and the panic was contained by the executor.
    Panicked,
}

/// Backend-specific cancellation for an owned task.
///
/// Implementations must make [`TaskControl::abort`] idempotent. The simulator implements this
/// contract without depending on Tokio cancellation primitives.
pub trait TaskControl: fmt::Debug + Send + Sync + 'static {
    /// Requests cancellation without waiting for task termination.
    fn abort(&self);
}

/// Backend-owned future that reports one task's terminal outcome.
pub type TaskCompletion =
    Pin<Box<dyn Future<Output = Result<TaskOutcome, TaskHandleError>> + Send + Sync + 'static>>;

/// Abort-on-drop ownership handle for one structured task.
pub struct OwnedTaskHandle {
    id: TaskId,
    control: Arc<dyn TaskControl>,
    completion: Option<TaskCompletion>,
    abort_on_drop: bool,
}

impl fmt::Debug for OwnedTaskHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedTaskHandle")
            .field("id", &self.id)
            .field("control", &self.control)
            .field("has_completion", &self.completion.is_some())
            .field("abort_on_drop", &self.abort_on_drop)
            .finish()
    }
}

impl OwnedTaskHandle {
    /// Constructs a handle from executor-backend cancellation and completion primitives.
    ///
    /// Executor implementations use this after accepting the task into their owned task set.
    pub fn from_backend(
        id: TaskId,
        control: Arc<dyn TaskControl>,
        completion: TaskCompletion,
    ) -> Self {
        Self {
            id,
            control,
            completion: Some(completion),
            abort_on_drop: true,
        }
    }

    /// Returns the stable task identity.
    pub const fn id(&self) -> TaskId {
        self.id
    }

    /// Requests cancellation without waiting for the task to finish.
    pub fn abort(&self) {
        self.control.abort();
    }

    /// Detaches the ownership handle while retaining group ownership.
    pub fn detach(mut self) -> TaskId {
        self.abort_on_drop = false;
        self.completion.take();
        self.id
    }

    /// Waits for the task to terminate without cancelling it.
    pub async fn join(mut self) -> Result<TaskOutcome, TaskHandleError> {
        self.abort_on_drop = false;
        let completion = self
            .completion
            .take()
            .ok_or(TaskHandleError::CompletionUnavailable)?;
        completion.await
    }
}

impl Drop for OwnedTaskHandle {
    fn drop(&mut self) {
        if self.abort_on_drop {
            self.control.abort();
        }
    }
}

#[derive(Debug)]
struct TokioTaskControl(CancellationToken);

impl TaskControl for TokioTaskControl {
    fn abort(&self) {
        self.0.cancel();
    }
}

/// A per-task ownership handle could not observe completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskHandleError {
    /// The executor terminated without publishing a terminal outcome.
    CompletionUnavailable,
}

impl fmt::Display for TaskHandleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("structured task completion is unavailable")
    }
}

impl std::error::Error for TaskHandleError {}

/// Stable task-group state used by diagnostics and resource ledgers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskGroupSnapshot {
    /// Whether new tasks are rejected.
    pub closed: bool,
    /// Whether cancellation has been requested.
    pub cancelled: bool,
    /// Live tasks, ordered by stable task ID.
    pub tasks: Vec<TaskMetadata>,
}

/// Production executor backed by Tokio.
#[derive(Clone, Debug)]
pub struct TokioExecutor {
    ids: Arc<IdAllocator<TaskId>>,
    clock: Arc<dyn Clock>,
    trace: Arc<TraceRecorder>,
}

impl Default for TokioExecutor {
    fn default() -> Self {
        let trace = Arc::new(TraceRecorder::new(Arc::new(crate::NoopTraceSink)));
        Self::new(trace)
    }
}

impl TokioExecutor {
    /// Creates a Tokio executor using the shared trace recorder.
    pub fn new(trace: Arc<TraceRecorder>) -> Self {
        let clock = Arc::new(TokioClock::with_recorder(trace.clone()));
        Self::with_clock(clock, trace)
    }

    /// Creates a Tokio executor with an explicit clock and trace recorder.
    pub fn with_clock(clock: Arc<dyn Clock>, trace: Arc<TraceRecorder>) -> Self {
        Self {
            ids: Arc::new(IdAllocator::default()),
            clock,
            trace,
        }
    }
}

impl Executor for TokioExecutor {
    fn clock_domain(&self) -> ClockDomain {
        self.clock.domain()
    }

    fn new_group(&self, parent: Option<TaskId>) -> Arc<dyn TaskGroup> {
        Arc::new(TokioTaskGroup {
            parent,
            ids: self.ids.clone(),
            clock: self.clock.clone(),
            trace: self.trace.clone(),
            tracker: TaskTracker::new(),
            cancel: CancellationToken::new(),
            state: Arc::new(Mutex::new(GroupState::default())),
            failure: Arc::new(Mutex::new(None)),
        })
    }
}

#[derive(Debug, Default)]
struct GroupState {
    closed: bool,
    next_ordinal: u64,
    tasks: BTreeMap<TaskId, TaskMetadata>,
}

#[derive(Debug)]
struct TokioTaskGroup {
    parent: Option<TaskId>,
    ids: Arc<IdAllocator<TaskId>>,
    clock: Arc<dyn Clock>,
    trace: Arc<TraceRecorder>,
    tracker: TaskTracker,
    cancel: CancellationToken,
    state: Arc<Mutex<GroupState>>,
    failure: Arc<Mutex<Option<TaskGroupError>>>,
}

impl TaskGroup for TokioTaskGroup {
    fn spawn_owned(
        &self,
        kind: TaskKind,
        name: &str,
        future: BoxedTask,
    ) -> Result<OwnedTaskHandle, SpawnError> {
        let id = self.ids.allocate().map_err(|_| SpawnError::IdExhausted)?;
        let mut state = self.state.lock().expect("task group state lock poisoned");
        let child_ordinal = state.next_ordinal;
        state.next_ordinal = state
            .next_ordinal
            .checked_add(1)
            .ok_or(SpawnError::OrdinalExhausted)?;
        let metadata = TaskMetadata {
            id,
            parent: self.parent,
            child_ordinal,
            kind,
            name: name.to_owned(),
        };

        if state.closed {
            drop(state);
            self.observe(
                TraceContext {
                    task: Some(id),
                    ..TraceContext::default()
                },
                TraceEventKind::TaskRejected {
                    metadata: metadata.clone(),
                },
            )?;
            return Err(SpawnError::Closed { metadata });
        }

        state.tasks.insert(id, metadata.clone());
        if let Err(error) = self.observe(
            TraceContext {
                task: Some(id),
                ..TraceContext::default()
            },
            TraceEventKind::TaskSpawned { metadata },
        ) {
            state.tasks.remove(&id);
            return Err(error);
        }

        let state_ref = self.state.clone();
        let failure = self.failure.clone();
        let group_cancel = self.cancel.clone();
        let task_cancel = CancellationToken::new();
        let task_cancelled = task_cancel.clone();
        let (completion_send, completion_recv) = oneshot::channel();
        let clock = self.clock.clone();
        let trace = self.trace.clone();
        self.tracker.spawn(async move {
            let outcome = AssertUnwindSafe(
                group_cancel.run_until_cancelled(task_cancelled.run_until_cancelled(future)),
            )
            .catch_unwind()
            .await;
            let outcome = match outcome {
                Ok(Some(Some(()))) => TaskOutcome::Completed,
                Ok(Some(None) | None) => TaskOutcome::Cancelled,
                Err(_) => TaskOutcome::Panicked,
            };
            let event = match outcome {
                TaskOutcome::Completed => TraceEventKind::TaskCompleted { task: id },
                TaskOutcome::Cancelled => TraceEventKind::TaskCancelled { task: id },
                TaskOutcome::Panicked => TraceEventKind::TaskPanicked { task: id },
            };
            state_ref
                .lock()
                .expect("task group state lock poisoned")
                .tasks
                .remove(&id);
            if let Err(error) = observe(&*clock, &trace, id, event) {
                latch_failure(&failure, error);
            }
            let _ = completion_send.send(outcome);
        });
        drop(state);
        Ok(OwnedTaskHandle::from_backend(
            id,
            Arc::new(TokioTaskControl(task_cancel)),
            Box::pin(async move {
                completion_recv
                    .await
                    .map_err(|_| TaskHandleError::CompletionUnavailable)
            }),
        ))
    }

    fn close(&self) {
        let mut state = self.state.lock().expect("task group state lock poisoned");
        state.closed = true;
        self.tracker.close();
    }

    fn cancel(&self) {
        self.cancel.cancel();
    }

    fn is_closed(&self) -> bool {
        self.state
            .lock()
            .expect("task group state lock poisoned")
            .closed
    }

    fn snapshot(&self) -> TaskGroupSnapshot {
        let state = self.state.lock().expect("task group state lock poisoned");
        TaskGroupSnapshot {
            closed: state.closed,
            cancelled: self.cancel.is_cancelled(),
            tasks: state.tasks.values().cloned().collect(),
        }
    }

    fn join(&self) -> Pin<Box<dyn Future<Output = Result<(), TaskGroupError>> + Send + '_>> {
        Box::pin(async move {
            self.tracker.wait().await;
            match self
                .failure
                .lock()
                .expect("task group failure lock poisoned")
                .take()
            {
                Some(error) => Err(error),
                None => Ok(()),
            }
        })
    }
}

impl TokioTaskGroup {
    fn observe(&self, context: TraceContext, event: TraceEventKind) -> Result<(), SpawnError> {
        let elapsed = self.clock.elapsed_nanos().map_err(SpawnError::Clock)?;
        self.trace
            .record(elapsed, context, event)
            .map(|_| ())
            .map_err(SpawnError::Trace)
    }
}

fn observe(
    clock: &dyn Clock,
    trace: &TraceRecorder,
    task: TaskId,
    event: TraceEventKind,
) -> Result<(), TaskGroupError> {
    let elapsed = clock.elapsed_nanos().map_err(TaskGroupError::Clock)?;
    trace
        .record(
            elapsed,
            TraceContext {
                task: Some(task),
                ..TraceContext::default()
            },
            event,
        )
        .map(|_| ())
        .map_err(TaskGroupError::Trace)
}

fn latch_failure(failure: &Mutex<Option<TaskGroupError>>, error: TaskGroupError) {
    let mut failure = failure.lock().expect("task group failure lock poisoned");
    if failure.is_none() {
        *failure = Some(error);
    }
}

/// A task could not be accepted by its group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SpawnError {
    /// The group is closed and rejected this task.
    Closed {
        /// Identity allocated to the rejected task.
        metadata: TaskMetadata,
    },
    /// Stable task IDs are exhausted.
    IdExhausted,
    /// Per-group child ordinals are exhausted.
    OrdinalExhausted,
    /// The executor backend is no longer available.
    BackendUnavailable,
    /// A structured resource limit rejected the task.
    ResourceLimit {
        /// Stable resource family name.
        resource: &'static str,
        /// Configured maximum.
        limit: u64,
    },
    /// The runtime clock failed while observing the spawn.
    Clock(ClockError),
    /// The trace recorder rejected the spawn observation.
    Trace(TraceRecordError),
}

impl fmt::Display for SpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed { .. } => f.write_str("task group is closed"),
            Self::IdExhausted => f.write_str("task identifier space exhausted"),
            Self::OrdinalExhausted => f.write_str("task child ordinal space exhausted"),
            Self::BackendUnavailable => f.write_str("task executor backend is unavailable"),
            Self::ResourceLimit { resource, limit } => {
                write!(f, "task executor {resource} limit {limit} exceeded")
            }
            Self::Clock(err) => write!(f, "task spawn clock failed: {err}"),
            Self::Trace(err) => write!(f, "task spawn trace failed: {err}"),
        }
    }
}

impl std::error::Error for SpawnError {}

/// A task group could not finish cleanly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskGroupError {
    /// The runtime clock failed while observing task completion.
    Clock(ClockError),
    /// The trace recorder rejected a completion observation.
    Trace(TraceRecordError),
}

impl fmt::Display for TaskGroupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clock(err) => write!(f, "task group clock failed: {err}"),
            Self::Trace(err) => write!(f, "task group trace failed: {err}"),
        }
    }
}

impl std::error::Error for TaskGroupError {}
