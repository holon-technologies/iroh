#![cfg(not(all(target_family = "wasm", target_os = "unknown")))]

use std::{
    future::Future,
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use iroh_runtime::{
    Executor, NoopTraceSink, OwnedTaskHandle, SpawnError, TaskControl, TaskGroup,
    TaskGroupCapacitySnapshot, TaskGroupLimits, TaskId, TaskKind, TaskOutcome, TokioExecutor,
    TraceEvent, TraceEventKind, TraceRecorder, TraceSink, TraceSinkError,
};
use tokio::sync::oneshot;

#[tokio::test]
async fn task_group_assigns_parent_and_creation_ordinals() {
    let executor = TokioExecutor::default();
    let parent = TaskId::new(99).unwrap();
    let group = executor.new_group(Some(parent));

    let first = group
        .spawn(TaskKind::Noq, "first", Box::pin(std::future::pending()))
        .unwrap();
    let second = group
        .spawn(TaskKind::Relay, "second", Box::pin(std::future::pending()))
        .unwrap();

    let snapshot = group.snapshot();
    assert_eq!(snapshot.tasks.len(), 2);
    assert_eq!(snapshot.tasks[0].id, first);
    assert_eq!(snapshot.tasks[0].parent, Some(parent));
    assert_eq!(snapshot.tasks[0].child_ordinal, 0);
    assert_eq!(snapshot.tasks[1].id, second);
    assert_eq!(snapshot.tasks[1].child_ordinal, 1);

    group.cancel();
    group.close();
    group.join().await.unwrap();
    assert!(group.snapshot().tasks.is_empty());
}

#[tokio::test]
async fn live_task_limit_rejects_before_polling_or_consuming_identity() {
    let trace = Arc::new(TraceRecorder::new(Arc::new(NoopTraceSink)));
    let limits = TaskGroupLimits::new(NonZeroUsize::new(2).unwrap());
    let executor = TokioExecutor::with_limits(trace, limits);
    let group = executor.new_group(None);
    let first = group
        .spawn_owned(
            TaskKind::Protocol,
            "first",
            Box::pin(std::future::pending()),
        )
        .unwrap();
    let second = group
        .spawn_owned(
            TaskKind::Protocol,
            "second",
            Box::pin(std::future::pending()),
        )
        .unwrap();
    let polled = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));

    let rejected = group.spawn_owned(
        TaskKind::Protocol,
        "rejected",
        Box::pin(ProbeFuture {
            polled: polled.clone(),
            dropped: dropped.clone(),
        }),
    );

    assert!(matches!(
        rejected,
        Err(SpawnError::ResourceLimit {
            resource: "live_tasks",
            limit: 2,
        })
    ));
    assert!(!polled.load(Ordering::SeqCst));
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(
        group.capacity_snapshot(),
        TaskGroupCapacitySnapshot::Reported {
            max_live_tasks: 2,
            live_tasks: 2,
            high_water_live_tasks: 2,
            rejected_spawns: 1,
            counter_exhausted: false,
        }
    );

    first.abort();
    assert_eq!(first.join().await.unwrap(), TaskOutcome::Cancelled);
    let replacement = group
        .spawn_owned(
            TaskKind::Protocol,
            "replacement",
            Box::pin(std::future::pending()),
        )
        .unwrap();
    assert_eq!(replacement.id().get(), second.id().get() + 1);
    assert_eq!(
        group
            .snapshot()
            .tasks
            .iter()
            .find(|task| task.id == replacement.id())
            .unwrap()
            .child_ordinal,
        2
    );

    drop(second);
    drop(replacement);
    group.close();
    group.join().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_admission_never_exceeds_the_live_task_limit() {
    let trace = Arc::new(TraceRecorder::new(Arc::new(NoopTraceSink)));
    let limits = TaskGroupLimits::new(NonZeroUsize::new(2).unwrap());
    let executor = TokioExecutor::with_limits(trace, limits);
    let group = executor.new_group(None);
    let start = Arc::new(tokio::sync::Barrier::new(17));
    let mut attempts = Vec::new();
    for ordinal in 0..16 {
        let group = group.clone();
        let start = start.clone();
        attempts.push(tokio::spawn(async move {
            start.wait().await;
            group.spawn_owned(
                TaskKind::Protocol,
                &format!("candidate-{ordinal}"),
                Box::pin(std::future::pending()),
            )
        }));
    }
    start.wait().await;

    let mut accepted = Vec::new();
    let mut rejected = 0;
    for attempt in attempts {
        match attempt.await.unwrap() {
            Ok(handle) => accepted.push(handle),
            Err(SpawnError::ResourceLimit {
                resource: "live_tasks",
                limit: 2,
            }) => rejected += 1,
            Err(error) => panic!("unexpected concurrent admission error: {error}"),
        }
    }

    assert_eq!(accepted.len(), 2);
    assert_eq!(rejected, 14);
    assert_eq!(
        group.capacity_snapshot(),
        TaskGroupCapacitySnapshot::Reported {
            max_live_tasks: 2,
            live_tasks: 2,
            high_water_live_tasks: 2,
            rejected_spawns: 14,
            counter_exhausted: false,
        }
    );

    drop(accepted);
    group.close();
    group.join().await.unwrap();
}

#[tokio::test]
async fn panicking_task_releases_live_task_capacity() {
    let trace = Arc::new(TraceRecorder::new(Arc::new(NoopTraceSink)));
    let limits = TaskGroupLimits::new(NonZeroUsize::new(1).unwrap());
    let executor = TokioExecutor::with_limits(trace, limits);
    let group = executor.new_group(None);
    let panicking = group
        .spawn_owned(
            TaskKind::Protocol,
            "panicking",
            Box::pin(async { panic!("expected capacity-conservation panic") }),
        )
        .unwrap();

    assert_eq!(panicking.join().await.unwrap(), TaskOutcome::Panicked);
    let replacement = group
        .spawn_owned(
            TaskKind::Protocol,
            "replacement",
            Box::pin(std::future::pending()),
        )
        .expect("panicking task must release its live-task slot");

    drop(replacement);
    group.close();
    group.join().await.unwrap();
}

#[tokio::test]
async fn cancellation_drops_tasks_before_join_returns() {
    let executor = TokioExecutor::default();
    let group = executor.new_group(None);
    let dropped = Arc::new(AtomicBool::new(false));
    let task_dropped = dropped.clone();
    let (started_send, started_recv) = oneshot::channel();

    group
        .spawn(
            TaskKind::SocketActor,
            "socket",
            Box::pin(async move {
                let _guard = DropFlag(task_dropped);
                started_send.send(()).unwrap();
                std::future::pending::<()>().await;
            }),
        )
        .unwrap();

    started_recv.await.unwrap();
    group.cancel();
    group.close();
    group.join().await.unwrap();

    assert!(dropped.load(Ordering::SeqCst));
    assert!(group.snapshot().tasks.is_empty());
}

#[tokio::test]
async fn closed_group_rejects_and_drops_a_future_without_polling() {
    let executor = TokioExecutor::default();
    let group = executor.new_group(None);
    let polled = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    group.close();

    let result = group.spawn(
        TaskKind::Other("test".to_owned()),
        "rejected",
        Box::pin(ProbeFuture {
            polled: polled.clone(),
            dropped: dropped.clone(),
        }),
    );

    assert!(result.is_err());
    assert!(!polled.load(Ordering::SeqCst));
    assert!(dropped.load(Ordering::SeqCst));
    group.join().await.unwrap();
}

#[tokio::test]
async fn task_panics_are_observed_and_do_not_leak_snapshot_entries() {
    let sink = RecordingSink::default();
    let recorder = Arc::new(TraceRecorder::new(Arc::new(sink.clone())));
    let executor = TokioExecutor::new(recorder);
    let group = executor.new_group(None);

    group
        .spawn(
            TaskKind::Protocol,
            "panics",
            Box::pin(async { panic!("expected test panic") }),
        )
        .unwrap();
    group.close();
    group.join().await.unwrap();

    assert!(group.snapshot().tasks.is_empty());
    assert!(
        sink.events()
            .iter()
            .any(|event| matches!(event.event, TraceEventKind::TaskPanicked { .. }))
    );
}

#[tokio::test]
async fn spawn_trace_failure_does_not_leak_a_task_entry() {
    let recorder = Arc::new(TraceRecorder::new(Arc::new(FailingSink)));
    let executor = TokioExecutor::new(recorder);
    let group = executor.new_group(None);
    let dropped = Arc::new(AtomicBool::new(false));

    let result = group.spawn(
        TaskKind::Protocol,
        "unrecordable",
        Box::pin(ProbeFuture {
            polled: Arc::new(AtomicBool::new(false)),
            dropped: dropped.clone(),
        }),
    );

    assert!(result.is_err());
    assert!(dropped.load(Ordering::SeqCst));
    assert!(group.snapshot().tasks.is_empty());
    group.close();
    group.join().await.unwrap();
}

#[tokio::test]
async fn owned_task_handle_cancels_on_drop_and_can_be_joined() {
    let executor = TokioExecutor::default();
    let group = executor.new_group(None);
    let dropped = Arc::new(AtomicBool::new(false));
    let task_dropped = dropped.clone();
    let (started_send, started_recv) = oneshot::channel();

    let handle = group
        .spawn_owned(
            TaskKind::Protocol,
            "owned",
            Box::pin(async move {
                let _guard = DropFlag(task_dropped);
                started_send.send(()).unwrap();
                std::future::pending::<()>().await;
            }),
        )
        .unwrap();
    started_recv.await.unwrap();
    let task_id = handle.id();
    drop(handle);

    group.close();
    group.join().await.unwrap();
    assert!(dropped.load(Ordering::SeqCst));
    assert!(!group.snapshot().tasks.iter().any(|task| task.id == task_id));
}

#[tokio::test]
async fn concurrent_children_complete_before_group_join() {
    let executor = TokioExecutor::default();
    let group = executor.new_group(None);
    let barrier = Arc::new(tokio::sync::Barrier::new(3));

    for name in ["first", "second"] {
        let barrier = barrier.clone();
        group
            .spawn(
                TaskKind::Protocol,
                name,
                Box::pin(async move {
                    barrier.wait().await;
                }),
            )
            .unwrap();
    }
    group.close();
    barrier.wait().await;
    group.join().await.unwrap();

    assert!(group.snapshot().tasks.is_empty());
}

#[test]
fn backend_owned_handle_uses_object_safe_abort_control() {
    let aborted = Arc::new(AtomicBool::new(false));
    let handle = OwnedTaskHandle::from_backend(
        TaskId::new(7).unwrap(),
        Arc::new(FlagControl(aborted.clone())),
        Box::pin(async { Ok(TaskOutcome::Completed) }),
    );

    drop(handle);

    assert!(aborted.load(Ordering::SeqCst));
}

#[derive(Debug)]
struct FlagControl(Arc<AtomicBool>);

impl TaskControl for FlagControl {
    fn abort(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[derive(Clone, Debug, Default)]
struct RecordingSink(Arc<Mutex<Vec<TraceEvent>>>);

impl RecordingSink {
    fn events(&self) -> Vec<TraceEvent> {
        self.0.lock().unwrap().clone()
    }
}

impl TraceSink for RecordingSink {
    fn record(&self, event: TraceEvent) -> Result<(), TraceSinkError> {
        self.0.lock().unwrap().push(event);
        Ok(())
    }
}

#[derive(Debug)]
struct FailingSink;

impl TraceSink for FailingSink {
    fn record(&self, _event: TraceEvent) -> Result<(), TraceSinkError> {
        Err(TraceSinkError::new("expected test failure"))
    }
}

struct DropFlag(Arc<AtomicBool>);

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

#[allow(dead_code)]
fn assert_object_safe(_: Arc<dyn Executor>, _: Arc<dyn TaskGroup>, _: Arc<NoopTraceSink>) {}
