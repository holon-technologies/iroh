//! Single-threaded deterministic event, task, and virtual-time kernel.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};

use iroh_runtime::{
    BoxedTask, Clock, ClockDomain, ClockError, DecisionError, DecisionSource, DecisionStream,
    Executor, IdAllocator, OwnedTaskHandle, RootSeed, RuntimeContext, SeededDecisionSource,
    SpawnError, TaskCompletion, TaskControl, TaskGroup, TaskGroupError, TaskGroupSnapshot,
    TaskHandleError, TaskId, TaskKind, TaskMetadata, TaskOutcome, Timer, TimerId, TraceContext,
    TraceDecisionObserver, TraceEventKind, TraceRecordError, TraceRecorder, TraceSink, WallClock,
};

use crate::{LedgerError, ResourceKind, ResourceLedger, ResourceLedgerSnapshot, ResourceToken};

/// Stable identity of one scheduled kernel event.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EventId(u64);

impl EventId {
    /// Returns the numeric run-local identity.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Cancellation owner for one replaceable environment event.
#[derive(Debug)]
pub struct ScheduledEvent {
    live: Arc<AtomicBool>,
}

impl ScheduledEvent {
    /// Prevents the callback from executing. Cancellation is idempotent.
    pub fn cancel(&self) {
        self.live.store(false, Ordering::Release);
    }
}

impl Drop for ScheduledEvent {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Stable ordering class for simultaneous events.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EventClass {
    /// Topology or infrastructure transitions.
    Infrastructure,
    /// Packet/link work.
    Network,
    /// Runtime timer wakeups.
    Timer,
    /// Pure observation work that cannot affect earlier classes.
    Observation,
}

/// Hard bounds for one deterministic kernel run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelConfig {
    /// Maximum task polls plus live scheduled-event executions.
    pub max_events: u64,
    /// Maximum run-relative virtual time.
    pub max_virtual_time: Duration,
    /// Maximum simultaneously live tasks.
    pub max_tasks: u64,
}

/// Why a kernel stopped after exhausting runnable work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Quiescence {
    /// No runtime tasks remain.
    Complete,
    /// Tasks remain but no task is ready and no live event can wake one.
    Stalled {
        /// Number of retained task futures.
        live_tasks: u64,
    },
}

/// Deterministic terminal state and accounting snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelRun {
    /// Completion or stalled quiescence.
    pub quiescence: Quiescence,
    /// Task polls plus live scheduled events executed over the kernel's lifetime.
    pub events_executed: u64,
    /// Final run-relative virtual time.
    pub virtual_time: Duration,
    /// Final current/high-water resource counts.
    pub ledger: ResourceLedgerSnapshot,
    /// Seeded scheduling and fairness accounting.
    pub scheduler: KernelSchedulerSnapshot,
}

/// Stable scheduling-accounting snapshot for diagnostics and artifacts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct KernelSchedulerSnapshot {
    /// Whether a seeded ready-task decision stream was installed.
    pub seeded: bool,
    /// Number of seeded task-selection draws made.
    pub decisions: u64,
    /// Number of selections constrained by the fairness bound.
    pub fairness_forced: u64,
    /// Largest number of other selections observed while a ready task waited.
    pub max_ready_wait: u64,
}

/// One task ever admitted by the kernel and whether it is still live.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct KernelTaskSnapshot {
    /// Runtime task identity, parent, kind, ordinal, and semantic name.
    pub metadata: TaskMetadata,
    /// Whether the task future remains retained by the kernel.
    pub live: bool,
}

/// Result of one deterministic scheduler step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KernelStep {
    /// One task poll or live scheduled event executed.
    Progress,
    /// No work remains runnable on the kernel timeline.
    Idle(KernelRun),
}

/// Controller for one deterministic simulation timeline.
#[derive(Clone)]
pub struct Kernel {
    inner: Arc<KernelInner>,
    clock: Arc<VirtualClock>,
    executor: Arc<KernelExecutor>,
}

impl fmt::Debug for Kernel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.inner.state.lock().expect("kernel state lock poisoned");
        f.debug_struct("Kernel")
            .field("now_nanos", &state.now_nanos)
            .field("ready_tasks", &state.ready.len())
            .field("live_tasks", &state.tasks.len())
            .field("scheduled_events", &state.events.len())
            .finish()
    }
}

impl Kernel {
    /// Creates an empty deterministic kernel and shared trace sequence.
    pub fn new(config: KernelConfig, sink: Arc<dyn TraceSink>) -> Result<Self, KernelError> {
        if config.max_events == 0 || config.max_virtual_time.is_zero() || config.max_tasks == 0 {
            return Err(KernelError::InvalidConfig);
        }
        let max_virtual_time_nanos = duration_nanos(config.max_virtual_time)?;
        let trace = Arc::new(TraceRecorder::new(sink));
        let ledger = ResourceLedger::default();
        let inner = Arc::new(KernelInner {
            config,
            max_virtual_time_nanos,
            trace,
            ledger,
            ready_scheduler: Mutex::new(None),
            state: Mutex::new(KernelState::default()),
        });
        let clock = Arc::new(VirtualClock {
            domain: ClockDomain::fresh(),
            origin: iroh_runtime::Instant::now(),
            timer_ids: IdAllocator::default(),
            inner: Arc::downgrade(&inner),
        });
        let executor = Arc::new(KernelExecutor {
            task_ids: Arc::new(IdAllocator::default()),
            clock: clock.clone(),
            inner: Arc::downgrade(&inner),
        });
        Ok(Self {
            inner,
            clock,
            executor,
        })
    }

    /// Composes this kernel into the shared runtime capability bundle.
    pub fn runtime_context(
        &self,
        root_seed: RootSeed,
        wall_epoch: iroh_runtime::SystemTime,
    ) -> RuntimeContext {
        let clock: Arc<dyn Clock> = self.clock.clone();
        let wall_clock: Arc<dyn WallClock> = Arc::new(VirtualWallClock {
            epoch: wall_epoch,
            inner: Arc::downgrade(&self.inner),
        });
        let executor: Arc<dyn Executor> = self.executor.clone();
        let decisions = Arc::new(SeededDecisionSource::with_observer(
            root_seed,
            Arc::new(TraceDecisionObserver::new(
                clock.clone(),
                self.inner.trace.clone(),
            )),
        ));
        self.inner.install_ready_scheduler(decisions.as_ref());
        RuntimeContext::from_parts(
            root_seed,
            clock,
            wall_clock,
            executor,
            decisions,
            self.inner.trace.clone(),
        )
        .expect("kernel clock and executor share one domain")
    }

    /// Schedules deterministic environment work at an absolute run-relative deadline.
    pub fn schedule_at(
        &self,
        deadline: Duration,
        class: EventClass,
        action: impl FnOnce() -> Result<(), KernelError> + Send + 'static,
    ) -> Result<EventId, KernelError> {
        let deadline_nanos = duration_nanos(deadline)?;
        self.inner.schedule(
            deadline_nanos,
            class,
            EventAction::Callback(Box::new(action)),
        )
    }

    /// Schedules replaceable environment work and returns its cancellation owner.
    ///
    /// Dropped or explicitly cancelled events are removed lazily without consuming an event
    /// budget entry or advancing virtual time.
    pub fn schedule_cancellable_at(
        &self,
        deadline: Duration,
        class: EventClass,
        action: impl FnOnce() -> Result<(), KernelError> + Send + 'static,
    ) -> Result<(EventId, ScheduledEvent), KernelError> {
        let deadline_nanos = duration_nanos(deadline)?;
        let live = Arc::new(AtomicBool::new(true));
        let id = self.inner.schedule(
            deadline_nanos,
            class,
            EventAction::CancellableCallback {
                live: Arc::downgrade(&live),
                action: Box::new(action),
            },
        )?;
        Ok((id, ScheduledEvent { live }))
    }

    /// Drives ready tasks and scheduled events until completion or deterministic stall.
    pub fn run_until_idle(&self) -> Result<KernelRun, KernelError> {
        loop {
            match self.step()? {
                KernelStep::Progress => {}
                KernelStep::Idle(run) => return Ok(run),
            }
        }
    }

    /// Executes at most one ready task poll or live scheduled event.
    ///
    /// One ready task or environment event is selected per call.
    pub fn step(&self) -> Result<KernelStep, KernelError> {
        if self.inner.has_ready() {
            self.reserve_task_poll()?;
            if let Some(task) = self.inner.pop_ready()? {
                self.inner.advance_ready_epoch();
                self.inner.poll_task(task)?;
                return Ok(KernelStep::Progress);
            }
        }

        let Some((key, action)) = self.inner.pop_next_live_event() else {
            return self.idle_step();
        };
        if key.deadline_nanos > self.inner.max_virtual_time_nanos {
            self.inner.reinsert_event(key, action);
            return Err(KernelError::VirtualTimeBudgetExceeded {
                limit_nanos: self.inner.max_virtual_time_nanos,
                next_deadline_nanos: key.deadline_nanos,
            });
        }
        if let Err(error) = self.reserve_step() {
            self.inner.reinsert_event(key, action);
            return Err(error);
        }
        {
            let mut state = self.inner.state.lock().expect("kernel state lock poisoned");
            state.now_nanos = state.now_nanos.max(key.deadline_nanos);
        }
        self.inner.advance_ready_epoch();
        self.inner.execute(action)?;
        Ok(KernelStep::Progress)
    }

    /// Returns current/high-water resource counts.
    pub fn ledger(&self) -> ResourceLedgerSnapshot {
        self.inner.ledger.snapshot()
    }

    /// Returns the kernel executor for scheduler component tests and measurements.
    pub fn executor(&self) -> Arc<KernelExecutor> {
        self.executor.clone()
    }

    /// Returns seeded scheduler and fairness accounting at this instant.
    pub fn scheduler_snapshot(&self) -> KernelSchedulerSnapshot {
        self.inner.scheduler_snapshot()
    }

    /// Returns every task admitted during this run in stable identity order.
    pub fn task_ownership_snapshot(&self) -> Vec<KernelTaskSnapshot> {
        let state = self.inner.state.lock().expect("kernel state lock poisoned");
        state
            .task_history
            .values()
            .cloned()
            .map(|metadata| KernelTaskSnapshot {
                live: state.tasks.contains_key(&metadata.id),
                metadata,
            })
            .collect()
    }

    /// Returns the metadata of tasks currently queued for another poll.
    pub fn ready_task_snapshot(&self) -> Vec<TaskMetadata> {
        let state = self.inner.state.lock().expect("kernel state lock poisoned");
        state
            .ready
            .iter()
            .filter_map(|id| state.task_history.get(id).cloned())
            .collect()
    }

    /// Returns current run-relative virtual time.
    pub fn now(&self) -> Duration {
        Duration::from_nanos(self.inner.now_nanos())
    }

    /// Acquires a simulator-owned resource entry tied to this kernel's ledger.
    pub fn acquire_resource(
        &self,
        kind: ResourceKind,
        limit: Option<u64>,
    ) -> Result<ResourceToken, LedgerError> {
        self.inner.ledger.acquire(kind, limit)
    }

    fn reserve_step(&self) -> Result<(), KernelError> {
        let mut state = self.inner.state.lock().expect("kernel state lock poisoned");
        if state.events_executed >= self.inner.config.max_events {
            return Err(KernelError::EventBudgetExceeded {
                limit: self.inner.config.max_events,
            });
        }
        state.events_executed += 1;
        Ok(())
    }

    fn reserve_task_poll(&self) -> Result<(), KernelError> {
        let mut state = self.inner.state.lock().expect("kernel state lock poisoned");
        if state.events_executed >= self.inner.config.max_events {
            return Err(KernelError::RunnableBudgetExceeded {
                limit: self.inner.config.max_events,
                live_tasks: u64::try_from(state.tasks.len())
                    .map_err(|_| KernelError::ResourceCounterOverflow)?,
                ready_tasks: u64::try_from(state.ready.len())
                    .map_err(|_| KernelError::ResourceCounterOverflow)?,
            });
        }
        state.events_executed += 1;
        Ok(())
    }

    fn idle_step(&self) -> Result<KernelStep, KernelError> {
        let (live_tasks, events_executed, virtual_time) = {
            let state = self.inner.state.lock().expect("kernel state lock poisoned");
            (
                u64::try_from(state.tasks.len())
                    .map_err(|_| KernelError::ResourceCounterOverflow)?,
                state.events_executed,
                Duration::from_nanos(state.now_nanos),
            )
        };
        let quiescence = if live_tasks == 0 {
            Quiescence::Complete
        } else {
            Quiescence::Stalled { live_tasks }
        };
        Ok(KernelStep::Idle(KernelRun {
            quiescence,
            events_executed,
            virtual_time,
            ledger: self.inner.ledger.snapshot(),
            scheduler: self.inner.scheduler_snapshot(),
        }))
    }
}

const MAX_READY_WAIT: u64 = 32;

struct KernelInner {
    config: KernelConfig,
    max_virtual_time_nanos: u64,
    trace: Arc<TraceRecorder>,
    ledger: ResourceLedger,
    ready_scheduler: Mutex<Option<Box<dyn DecisionStream>>>,
    state: Mutex<KernelState>,
}

impl fmt::Debug for KernelInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KernelInner")
            .field("config", &self.config)
            .field("ledger", &self.ledger)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct KernelState {
    now_nanos: u64,
    events_executed: u64,
    next_event_id: u64,
    ready: VecDeque<TaskId>,
    ready_set: BTreeSet<TaskId>,
    ready_epochs: BTreeMap<TaskId, u64>,
    ready_waits: BTreeMap<TaskId, u64>,
    tasks: BTreeMap<TaskId, Arc<TaskCell>>,
    task_history: BTreeMap<TaskId, TaskMetadata>,
    events: BTreeMap<EventKey, EventAction>,
    scheduler_decisions: u64,
    fairness_forced: u64,
    max_ready_wait: u64,
    ready_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct EventKey {
    deadline_nanos: u64,
    class: EventClass,
    id: EventId,
}

enum EventAction {
    Callback(Box<dyn FnOnce() -> Result<(), KernelError> + Send + 'static>),
    CancellableCallback {
        live: Weak<AtomicBool>,
        action: Box<dyn FnOnce() -> Result<(), KernelError> + Send + 'static>,
    },
    Timer {
        timer: Weak<VirtualTimerState>,
        generation: u64,
    },
}

impl EventAction {
    fn is_live(&self) -> bool {
        match self {
            Self::Callback(_) => true,
            Self::CancellableCallback { live, .. } => live
                .upgrade()
                .is_some_and(|live| live.load(Ordering::Acquire)),
            Self::Timer { timer, generation } => timer.upgrade().is_some_and(|timer| {
                let state = timer.state.lock().expect("virtual timer lock poisoned");
                !state.completed && !state.dropped && state.generation == *generation
            }),
        }
    }
}

impl KernelInner {
    fn advance_ready_epoch(&self) {
        let mut state = self.state.lock().expect("kernel state lock poisoned");
        state.ready_epoch = state.ready_epoch.saturating_add(1);
    }

    fn install_ready_scheduler(&self, decisions: &dyn DecisionSource) {
        let mut scheduler = self
            .ready_scheduler
            .lock()
            .expect("kernel ready scheduler lock poisoned");
        if scheduler.is_none() {
            *scheduler = Some(
                decisions
                    .stream("kernel/ready-task")
                    .expect("kernel ready-task decision path is valid"),
            );
        }
    }

    fn scheduler_snapshot(&self) -> KernelSchedulerSnapshot {
        let seeded = self
            .ready_scheduler
            .lock()
            .expect("kernel ready scheduler lock poisoned")
            .is_some();
        let state = self.state.lock().expect("kernel state lock poisoned");
        KernelSchedulerSnapshot {
            seeded,
            decisions: state.scheduler_decisions,
            fairness_forced: state.fairness_forced,
            max_ready_wait: state.max_ready_wait,
        }
    }

    fn now_nanos(&self) -> u64 {
        self.state
            .lock()
            .expect("kernel state lock poisoned")
            .now_nanos
    }

    fn schedule(
        &self,
        deadline_nanos: u64,
        class: EventClass,
        action: EventAction,
    ) -> Result<EventId, KernelError> {
        let mut state = self.state.lock().expect("kernel state lock poisoned");
        let next = state
            .next_event_id
            .checked_add(1)
            .ok_or(KernelError::EventIdExhausted)?;
        state.next_event_id = next;
        let id = EventId(next);
        let key = EventKey {
            deadline_nanos: deadline_nanos.max(state.now_nanos),
            class,
            id,
        };
        state.events.insert(key, action);
        Ok(id)
    }

    fn pop_next_live_event(&self) -> Option<(EventKey, EventAction)> {
        let mut state = self.state.lock().expect("kernel state lock poisoned");
        while let Some((key, action)) = state.events.pop_first() {
            if action.is_live() {
                return Some((key, action));
            }
        }
        None
    }

    fn reinsert_event(&self, key: EventKey, action: EventAction) {
        self.state
            .lock()
            .expect("kernel state lock poisoned")
            .events
            .insert(key, action);
    }

    fn has_ready(&self) -> bool {
        !self
            .state
            .lock()
            .expect("kernel state lock poisoned")
            .ready
            .is_empty()
    }

    fn execute(self: &Arc<Self>, action: EventAction) -> Result<(), KernelError> {
        match action {
            EventAction::Callback(action) => {
                catch_unwind(AssertUnwindSafe(action)).map_err(|_| KernelError::EventPanicked)??
            }
            EventAction::CancellableCallback { live, action } => {
                if let Some(live) = live.upgrade()
                    && live.swap(false, Ordering::AcqRel)
                {
                    catch_unwind(AssertUnwindSafe(action))
                        .map_err(|_| KernelError::EventPanicked)??;
                }
            }
            EventAction::Timer { timer, generation } => {
                if let Some(timer) = timer.upgrade() {
                    let waker = {
                        let mut state = timer.state.lock().expect("virtual timer lock poisoned");
                        if state.completed || state.dropped || state.generation != generation {
                            None
                        } else {
                            state.waker.take()
                        }
                    };
                    if let Some(waker) = waker {
                        waker.wake();
                    }
                }
            }
        }
        Ok(())
    }

    fn enqueue(&self, task: TaskId) {
        let mut state = self.state.lock().expect("kernel state lock poisoned");
        if state.tasks.contains_key(&task) && state.ready_set.insert(task) {
            state.ready.push_back(task);
            let epoch = state.ready_epoch;
            state.ready_epochs.insert(task, epoch);
        }
    }

    fn pop_ready(&self) -> Result<Option<Arc<TaskCell>>, KernelError> {
        let (ready, forced) = {
            let mut state = self.state.lock().expect("kernel state lock poisoned");
            let live = state.tasks.keys().copied().collect::<BTreeSet<_>>();
            state.ready.retain(|id| live.contains(id));
            state.ready_set.retain(|id| live.contains(id));
            state.ready_epochs.retain(|id, _| live.contains(id));
            state.ready_waits.retain(|id, _| live.contains(id));
            let oldest_epoch = state
                .ready
                .iter()
                .filter_map(|id| state.ready_epochs.get(id))
                .copied()
                .min();
            let ready = state
                .ready
                .iter()
                .copied()
                .filter(|id| state.ready_epochs.get(id).copied() == oldest_epoch)
                .collect::<Vec<_>>();
            let forced = ready
                .iter()
                .copied()
                .filter(|id| {
                    state.ready_waits.get(id).copied().unwrap_or_default() >= MAX_READY_WAIT
                })
                .collect::<Vec<_>>();
            (ready, forced)
        };
        if ready.is_empty() {
            return Ok(None);
        }

        let legal = if forced.is_empty() { &ready } else { &forced };
        let legal_ids = legal.to_vec();
        // Draw once per task poll, including singleton ready sets. A fixed draw cadence keeps
        // replay aligned when a compatibility task wakes just before versus just after a kernel
        // turn but does not change the only legal selection.
        let (index, used_decision) = {
            let mut scheduler = self
                .ready_scheduler
                .lock()
                .expect("kernel ready scheduler lock poisoned");
            match scheduler.as_mut() {
                Some(stream) => {
                    let raw = stream.next_u64()?;
                    let len = u64::try_from(legal.len())
                        .map_err(|_| KernelError::ResourceCounterOverflow)?;
                    (
                        usize::try_from(raw % len)
                            .map_err(|_| KernelError::ResourceCounterOverflow)?,
                        true,
                    )
                }
                None => (0, false),
            }
        };
        let selected = legal[index];

        let mut state = self.state.lock().expect("kernel state lock poisoned");
        let Some(index) = state.ready.iter().position(|id| *id == selected) else {
            return Ok(None);
        };
        let id = state
            .ready
            .remove(index)
            .expect("selected ready-task index exists");
        state.ready_set.remove(&id);
        state.ready_epochs.remove(&id);
        state.ready_waits.remove(&id);
        if used_decision {
            state.scheduler_decisions = state.scheduler_decisions.saturating_add(1);
        }
        if !forced.is_empty() {
            state.fairness_forced = state.fairness_forced.saturating_add(1);
        }
        let waiting = ready
            .iter()
            .copied()
            .filter(|waiting_id| *waiting_id != id)
            .collect::<Vec<_>>();
        for waiting_id in waiting {
            let wait = {
                let wait = state.ready_waits.entry(waiting_id).or_default();
                *wait = wait.saturating_add(1);
                *wait
            };
            state.max_ready_wait = state.max_ready_wait.max(wait);
        }
        let task = state.tasks.get(&id).cloned();
        let ready_metadata = legal_ids
            .iter()
            .filter_map(|id| state.task_history.get(id).cloned())
            .collect();
        drop(state);
        if let Some(task) = task.as_ref() {
            self.trace
                .record(
                    self.now_nanos(),
                    TraceContext {
                        task: Some(id),
                        ..TraceContext::default()
                    },
                    TraceEventKind::TaskScheduled {
                        selected: task.metadata.clone(),
                        ready: ready_metadata,
                        fairness_forced: !forced.is_empty(),
                    },
                )
                .map_err(KernelError::Trace)?;
        }
        Ok(task)
    }

    fn poll_task(self: &Arc<Self>, task: Arc<TaskCell>) -> Result<(), KernelError> {
        if task.cancelled.load(Ordering::Acquire) {
            task.future
                .lock()
                .expect("kernel task future lock poisoned")
                .take();
            return self.complete_task(&task, TaskOutcome::Cancelled);
        }

        let mut future = task
            .future
            .lock()
            .expect("kernel task future lock poisoned")
            .take()
            .ok_or(KernelError::TaskFutureUnavailable(task.metadata.id))?;
        let waker = Waker::from(Arc::new(TaskWake {
            task: task.metadata.id,
            kernel: Arc::downgrade(self),
        }));
        let mut cx = Context::from_waker(&waker);
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut task_poll = tokio::task::unconstrained(future.as_mut());
            Pin::new(&mut task_poll).poll(&mut cx)
        }));
        match result {
            Err(_) => self.complete_task(&task, TaskOutcome::Panicked),
            Ok(Poll::Ready(())) => self.complete_task(&task, TaskOutcome::Completed),
            Ok(Poll::Pending) if task.cancelled.load(Ordering::Acquire) => {
                drop(future);
                self.complete_task(&task, TaskOutcome::Cancelled)
            }
            Ok(Poll::Pending) => {
                *task
                    .future
                    .lock()
                    .expect("kernel task future lock poisoned") = Some(future);
                Ok(())
            }
        }
    }

    fn cancel_task(&self, id: TaskId) {
        let task = self
            .state
            .lock()
            .expect("kernel state lock poisoned")
            .tasks
            .get(&id)
            .cloned();
        if let Some(task) = task {
            task.cancelled.store(true, Ordering::Release);
            self.enqueue(id);
        }
    }

    fn complete_task(&self, task: &Arc<TaskCell>, outcome: TaskOutcome) -> Result<(), KernelError> {
        let id = task.metadata.id;
        {
            let mut state = self.state.lock().expect("kernel state lock poisoned");
            state.tasks.remove(&id);
            state.ready_set.remove(&id);
            state.ready_epochs.remove(&id);
            state.ready_waits.remove(&id);
        }
        task.group.task_completed(id);
        task.completion.finish(outcome);
        let event = match outcome {
            TaskOutcome::Completed => TraceEventKind::TaskCompleted { task: id },
            TaskOutcome::Cancelled => TraceEventKind::TaskCancelled { task: id },
            TaskOutcome::Panicked => TraceEventKind::TaskPanicked { task: id },
        };
        self.trace
            .record(
                self.now_nanos(),
                TraceContext {
                    task: Some(id),
                    ..TraceContext::default()
                },
                event,
            )
            .map_err(KernelError::Trace)?;
        Ok(())
    }
}

struct TaskWake {
    task: TaskId,
    kernel: Weak<KernelInner>,
}

impl Wake for TaskWake {
    fn wake(self: Arc<Self>) {
        if let Some(kernel) = self.kernel.upgrade() {
            kernel.enqueue(self.task);
        }
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if let Some(kernel) = self.kernel.upgrade() {
            kernel.enqueue(self.task);
        }
    }
}

struct TaskCell {
    metadata: TaskMetadata,
    future: Mutex<Option<BoxedTask>>,
    cancelled: AtomicBool,
    group: Arc<KernelTaskGroup>,
    completion: Arc<CompletionState>,
    _resource: ResourceToken,
}

impl fmt::Debug for TaskCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskCell")
            .field("metadata", &self.metadata)
            .field("cancelled", &self.cancelled)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct CompletionState {
    state: Mutex<CompletionInner>,
}

#[derive(Debug, Default)]
struct CompletionInner {
    outcome: Option<TaskOutcome>,
    wakers: Vec<Waker>,
}

impl CompletionState {
    fn finish(&self, outcome: TaskOutcome) {
        let wakers = {
            let mut state = self.state.lock().expect("task completion lock poisoned");
            state.outcome = Some(outcome);
            std::mem::take(&mut state.wakers)
        };
        for waker in wakers {
            waker.wake();
        }
    }
}

struct CompletionFuture(Arc<CompletionState>);

impl Future for CompletionFuture {
    type Output = Result<TaskOutcome, TaskHandleError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.0.state.lock().expect("task completion lock poisoned");
        if let Some(outcome) = state.outcome {
            Poll::Ready(Ok(outcome))
        } else {
            if !state.wakers.iter().any(|waker| waker.will_wake(cx.waker())) {
                state.wakers.push(cx.waker().clone());
            }
            Poll::Pending
        }
    }
}

/// Shared executor adapter backed by the deterministic kernel.
#[derive(Clone)]
pub struct KernelExecutor {
    task_ids: Arc<IdAllocator<TaskId>>,
    clock: Arc<VirtualClock>,
    inner: Weak<KernelInner>,
}

impl fmt::Debug for KernelExecutor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KernelExecutor")
            .field("clock_domain", &self.clock.domain)
            .finish_non_exhaustive()
    }
}

impl Executor for KernelExecutor {
    fn clock_domain(&self) -> ClockDomain {
        self.clock.domain
    }

    fn new_group(&self, parent: Option<TaskId>) -> Arc<dyn TaskGroup> {
        let group: Arc<KernelTaskGroup> = Arc::new_cyclic(|self_ref| KernelTaskGroup {
            parent,
            task_ids: self.task_ids.clone(),
            kernel: self.inner.clone(),
            self_ref: self_ref.clone(),
            state: Mutex::new(GroupState::default()),
        });
        group
    }
}

#[derive(Debug, Default)]
struct GroupState {
    closed: bool,
    cancelled: bool,
    next_ordinal: u64,
    tasks: BTreeMap<TaskId, TaskMetadata>,
    join_wakers: Vec<Waker>,
    failure: Option<TaskGroupError>,
}

#[derive(Debug)]
struct KernelTaskGroup {
    parent: Option<TaskId>,
    task_ids: Arc<IdAllocator<TaskId>>,
    kernel: Weak<KernelInner>,
    self_ref: Weak<KernelTaskGroup>,
    state: Mutex<GroupState>,
}

impl KernelTaskGroup {
    fn task_completed(&self, id: TaskId) {
        let wakers = {
            let mut state = self.state.lock().expect("task group state lock poisoned");
            state.tasks.remove(&id);
            if state.tasks.is_empty() {
                std::mem::take(&mut state.join_wakers)
            } else {
                Vec::new()
            }
        };
        for waker in wakers {
            waker.wake();
        }
    }
}

impl TaskGroup for KernelTaskGroup {
    fn spawn_owned(
        &self,
        kind: TaskKind,
        name: &str,
        future: BoxedTask,
    ) -> Result<OwnedTaskHandle, SpawnError> {
        let kernel = self
            .inner_kernel()
            .map_err(|_| SpawnError::BackendUnavailable)?;
        let id = self
            .task_ids
            .allocate()
            .map_err(|_| SpawnError::IdExhausted)?;
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
            kernel
                .trace
                .record(
                    kernel.now_nanos(),
                    TraceContext {
                        task: Some(id),
                        ..TraceContext::default()
                    },
                    TraceEventKind::TaskRejected {
                        metadata: metadata.clone(),
                    },
                )
                .map_err(SpawnError::Trace)?;
            return Err(SpawnError::Closed { metadata });
        }
        let resource = kernel
            .ledger
            .acquire(ResourceKind::Task, Some(kernel.config.max_tasks))
            .map_err(|error| match error {
                LedgerError::LimitExceeded { limit, .. } => SpawnError::ResourceLimit {
                    resource: "tasks",
                    limit,
                },
                LedgerError::Overflow => SpawnError::ResourceLimit {
                    resource: "tasks",
                    limit: u64::MAX,
                },
            })?;
        kernel
            .trace
            .record(
                kernel.now_nanos(),
                TraceContext {
                    task: Some(id),
                    ..TraceContext::default()
                },
                TraceEventKind::TaskSpawned {
                    metadata: metadata.clone(),
                },
            )
            .map_err(SpawnError::Trace)?;
        state.tasks.insert(id, metadata.clone());
        let completion = Arc::new(CompletionState {
            state: Mutex::new(CompletionInner::default()),
        });
        let group = self.arc_self();
        let task = Arc::new(TaskCell {
            metadata: metadata.clone(),
            future: Mutex::new(Some(future)),
            cancelled: AtomicBool::new(state.cancelled),
            group,
            completion: completion.clone(),
            _resource: resource,
        });
        drop(state);
        {
            let mut kernel_state = kernel.state.lock().expect("kernel state lock poisoned");
            kernel_state.task_history.insert(id, metadata.clone());
            kernel_state.tasks.insert(id, task);
            kernel_state.ready_set.insert(id);
            kernel_state.ready.push_back(id);
            let epoch = kernel_state.ready_epoch;
            kernel_state.ready_epochs.insert(id, epoch);
        }
        let control: Arc<dyn TaskControl> = Arc::new(KernelTaskControl {
            task: id,
            kernel: Arc::downgrade(&kernel),
        });
        let completion: TaskCompletion = Box::pin(CompletionFuture(completion));
        Ok(OwnedTaskHandle::from_backend(id, control, completion))
    }

    fn close(&self) {
        self.state
            .lock()
            .expect("task group state lock poisoned")
            .closed = true;
    }

    fn cancel(&self) {
        let tasks = {
            let mut state = self.state.lock().expect("task group state lock poisoned");
            state.cancelled = true;
            state.tasks.keys().copied().collect::<Vec<_>>()
        };
        if let Some(kernel) = self.kernel.upgrade() {
            for task in tasks {
                kernel.cancel_task(task);
            }
        }
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
            cancelled: state.cancelled,
            tasks: state.tasks.values().cloned().collect(),
        }
    }

    fn join(&self) -> Pin<Box<dyn Future<Output = Result<(), TaskGroupError>> + Send + '_>> {
        Box::pin(GroupJoinFuture { group: self })
    }
}

impl KernelTaskGroup {
    fn inner_kernel(&self) -> Result<Arc<KernelInner>, KernelError> {
        self.kernel.upgrade().ok_or(KernelError::KernelDropped)
    }

    fn arc_self(&self) -> Arc<Self> {
        self.self_ref
            .upgrade()
            .expect("kernel task group is alive while spawning")
    }
}

struct GroupJoinFuture<'a> {
    group: &'a KernelTaskGroup,
}

impl Future for GroupJoinFuture<'_> {
    type Output = Result<(), TaskGroupError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self
            .group
            .state
            .lock()
            .expect("task group state lock poisoned");
        if state.closed && state.tasks.is_empty() {
            Poll::Ready(match state.failure.take() {
                Some(error) => Err(error),
                None => Ok(()),
            })
        } else {
            if !state
                .join_wakers
                .iter()
                .any(|waker| waker.will_wake(cx.waker()))
            {
                state.join_wakers.push(cx.waker().clone());
            }
            Poll::Pending
        }
    }
}

#[derive(Debug)]
struct KernelTaskControl {
    task: TaskId,
    kernel: Weak<KernelInner>,
}

impl TaskControl for KernelTaskControl {
    fn abort(&self) {
        if let Some(kernel) = self.kernel.upgrade() {
            kernel.cancel_task(self.task);
        }
    }
}

/// Virtual monotonic clock driven only by the kernel event loop.
#[derive(Debug)]
pub struct VirtualClock {
    domain: ClockDomain,
    origin: iroh_runtime::Instant,
    timer_ids: IdAllocator<TimerId>,
    inner: Weak<KernelInner>,
}

impl Clock for VirtualClock {
    fn domain(&self) -> ClockDomain {
        self.domain
    }

    fn now(&self) -> iroh_runtime::Instant {
        self.origin + Duration::from_nanos(self.elapsed_nanos().unwrap_or_default())
    }

    fn new_timer(
        &self,
        deadline: iroh_runtime::Instant,
    ) -> Result<Pin<Box<dyn Timer>>, ClockError> {
        let kernel = self.inner.upgrade().ok_or(ClockError::BackendUnavailable)?;
        let id = self.timer_ids.allocate()?;
        let deadline_nanos = deadline
            .checked_duration_since(self.origin)
            .map(duration_nanos)
            .transpose()
            .map_err(|_| ClockError::TimelineOverflow)?
            .unwrap_or_default()
            .max(kernel.now_nanos());
        let resource = kernel
            .ledger
            .acquire(ResourceKind::Timer, None)
            .map_err(|_| ClockError::ResourceCounterOverflow)?;
        kernel
            .trace
            .record(
                kernel.now_nanos(),
                TraceContext::default(),
                TraceEventKind::TimerCreated {
                    timer: id,
                    deadline_nanos,
                },
            )
            .map_err(ClockError::Recorder)?;
        let state = Arc::new(VirtualTimerState {
            id,
            kernel: Arc::downgrade(&kernel),
            state: Mutex::new(VirtualTimerInner {
                deadline_nanos,
                generation: 0,
                completed: false,
                dropped: false,
                waker: None,
                resource: Some(resource),
            }),
        });
        kernel
            .schedule(
                deadline_nanos,
                EventClass::Timer,
                EventAction::Timer {
                    timer: Arc::downgrade(&state),
                    generation: 0,
                },
            )
            .map_err(|_| ClockError::TimelineOverflow)?;
        Ok(Box::pin(VirtualTimer {
            state,
            origin: self.origin,
        }))
    }

    fn elapsed_nanos(&self) -> Result<u64, ClockError> {
        self.inner
            .upgrade()
            .map(|kernel| kernel.now_nanos())
            .ok_or(ClockError::BackendUnavailable)
    }
}

#[derive(Debug)]
struct VirtualTimerState {
    id: TimerId,
    kernel: Weak<KernelInner>,
    state: Mutex<VirtualTimerInner>,
}

#[derive(Debug)]
struct VirtualTimerInner {
    deadline_nanos: u64,
    generation: u64,
    completed: bool,
    dropped: bool,
    waker: Option<Waker>,
    resource: Option<ResourceToken>,
}

#[derive(Debug)]
struct VirtualTimer {
    state: Arc<VirtualTimerState>,
    origin: iroh_runtime::Instant,
}

impl Timer for VirtualTimer {
    fn id(&self) -> TimerId {
        self.state.id
    }

    fn deadline(&self) -> iroh_runtime::Instant {
        self.origin
            + Duration::from_nanos(
                self.state
                    .state
                    .lock()
                    .expect("virtual timer lock poisoned")
                    .deadline_nanos,
            )
    }

    fn reset(self: Pin<&mut Self>, deadline: iroh_runtime::Instant) -> Result<(), ClockError> {
        let kernel = self
            .state
            .kernel
            .upgrade()
            .ok_or(ClockError::BackendUnavailable)?;
        let deadline_nanos = deadline
            .checked_duration_since(self.origin)
            .map(duration_nanos)
            .transpose()
            .map_err(|_| ClockError::TimelineOverflow)?
            .unwrap_or_default()
            .max(kernel.now_nanos());
        let generation = {
            let mut state = self
                .state
                .state
                .lock()
                .expect("virtual timer lock poisoned");
            if state.completed {
                state.resource = Some(
                    kernel
                        .ledger
                        .acquire(ResourceKind::Timer, None)
                        .map_err(|_| ClockError::ResourceCounterOverflow)?,
                );
            }
            state.completed = false;
            state.deadline_nanos = deadline_nanos;
            state.generation = state
                .generation
                .checked_add(1)
                .ok_or(ClockError::TimelineOverflow)?;
            state.generation
        };
        kernel
            .trace
            .record(
                kernel.now_nanos(),
                TraceContext::default(),
                TraceEventKind::TimerReset {
                    timer: self.state.id,
                    deadline_nanos,
                },
            )
            .map_err(ClockError::Recorder)?;
        kernel
            .schedule(
                deadline_nanos,
                EventClass::Timer,
                EventAction::Timer {
                    timer: Arc::downgrade(&self.state),
                    generation,
                },
            )
            .map_err(|_| ClockError::TimelineOverflow)?;
        Ok(())
    }

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), ClockError>> {
        let kernel = self
            .state
            .kernel
            .upgrade()
            .ok_or(ClockError::BackendUnavailable)?;
        let now_nanos = kernel.now_nanos();
        let should_fire = {
            let mut state = self
                .state
                .state
                .lock()
                .expect("virtual timer lock poisoned");
            if state.completed {
                return Poll::Ready(Ok(()));
            }
            if now_nanos >= state.deadline_nanos {
                state.completed = true;
                state.waker = None;
                state.resource.take();
                true
            } else {
                if state
                    .waker
                    .as_ref()
                    .is_none_or(|waker| !waker.will_wake(cx.waker()))
                {
                    state.waker = Some(cx.waker().clone());
                }
                false
            }
        };
        if should_fire {
            Poll::Ready(
                kernel
                    .trace
                    .record(
                        kernel.now_nanos(),
                        TraceContext::default(),
                        TraceEventKind::TimerFired {
                            timer: self.state.id,
                        },
                    )
                    .map(|_| ())
                    .map_err(ClockError::Recorder),
            )
        } else {
            Poll::Pending
        }
    }
}

impl Drop for VirtualTimer {
    fn drop(&mut self) {
        let should_record = {
            let mut state = self
                .state
                .state
                .lock()
                .expect("virtual timer lock poisoned");
            if state.completed || state.dropped {
                false
            } else {
                state.dropped = true;
                state.resource.take();
                true
            }
        };
        if should_record && let Some(kernel) = self.state.kernel.upgrade() {
            let _ = kernel.trace.record(
                kernel.now_nanos(),
                TraceContext::default(),
                TraceEventKind::TimerDropped {
                    timer: self.state.id,
                },
            );
        }
    }
}

/// Wall time derived from an explicit epoch and the kernel monotonic timeline.
#[derive(Clone, Debug)]
pub struct VirtualWallClock {
    epoch: iroh_runtime::SystemTime,
    inner: Weak<KernelInner>,
}

impl WallClock for VirtualWallClock {
    fn now_system(&self) -> iroh_runtime::SystemTime {
        let elapsed = self
            .inner
            .upgrade()
            .map(|kernel| kernel.now_nanos())
            .unwrap_or_default();
        self.epoch
            .checked_add(Duration::from_nanos(elapsed))
            .expect("validated virtual time fits SystemTime")
    }
}

fn duration_nanos(duration: Duration) -> Result<u64, KernelError> {
    u64::try_from(duration.as_nanos()).map_err(|_| KernelError::TimelineOverflow)
}

/// Deterministic kernel construction or execution failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KernelError {
    /// One or more configured limits are zero.
    InvalidConfig,
    /// A duration cannot be represented on the run timeline.
    TimelineOverflow,
    /// Stable event identities are exhausted.
    EventIdExhausted,
    /// The owner was dropped while a runtime capability remained.
    KernelDropped,
    /// A task had no future despite still being scheduled.
    TaskFutureUnavailable(TaskId),
    /// A trace event could not be retained.
    Trace(TraceRecordError),
    /// Seeded ready-task selection failed.
    Decision(DecisionError),
    /// A scheduled environment callback panicked.
    EventPanicked,
    /// The maximum number of task polls and event executions was reached.
    EventBudgetExceeded {
        /// Configured maximum.
        limit: u64,
    },
    /// Runnable tasks exhausted the poll budget without reaching quiescence.
    RunnableBudgetExceeded {
        /// Configured maximum.
        limit: u64,
        /// Number of retained task futures.
        live_tasks: u64,
        /// Number of tasks queued for another poll.
        ready_tasks: u64,
    },
    /// The next live event is beyond the configured timeline.
    VirtualTimeBudgetExceeded {
        /// Configured maximum in nanoseconds.
        limit_nanos: u64,
        /// Rejected event deadline in nanoseconds.
        next_deadline_nanos: u64,
    },
    /// A resource count cannot fit the public result schema.
    ResourceCounterOverflow,
    /// A scheduled callback returned a classified failure.
    EventAction(Box<KernelError>),
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig => f.write_str("kernel budgets must be nonzero"),
            Self::TimelineOverflow => f.write_str("kernel timeline cannot represent duration"),
            Self::EventIdExhausted => f.write_str("kernel event identity space exhausted"),
            Self::KernelDropped => f.write_str("deterministic kernel was dropped"),
            Self::TaskFutureUnavailable(task) => {
                write!(f, "kernel task {task} has no pollable future")
            }
            Self::Trace(error) => write!(f, "kernel trace failed: {error}"),
            Self::Decision(error) => write!(f, "kernel scheduling decision failed: {error}"),
            Self::EventPanicked => f.write_str("scheduled kernel event panicked"),
            Self::EventBudgetExceeded { limit } => {
                write!(f, "kernel event budget {limit} exceeded")
            }
            Self::RunnableBudgetExceeded {
                limit,
                live_tasks,
                ready_tasks,
            } => write!(
                f,
                "kernel task-poll budget {limit} exceeded with {live_tasks} live and {ready_tasks} ready tasks (possible livelock)"
            ),
            Self::VirtualTimeBudgetExceeded {
                limit_nanos,
                next_deadline_nanos,
            } => write!(
                f,
                "kernel virtual-time budget {limit_nanos}ns exceeded by event at {next_deadline_nanos}ns"
            ),
            Self::ResourceCounterOverflow => f.write_str("kernel resource count overflow"),
            Self::EventAction(error) => write!(f, "scheduled kernel event failed: {error}"),
        }
    }
}

impl std::error::Error for KernelError {}

impl From<DecisionError> for KernelError {
    fn from(value: DecisionError) -> Self {
        Self::Decision(value)
    }
}
