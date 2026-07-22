use std::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, SystemTime},
};

use iroh_runtime::{RootSeed, TaskKind, Timer, TraceEventKind};
use iroh_sim::{
    EventClass, Kernel, KernelConfig, KernelError, Quiescence, ResourceKind, TraceBuffer,
    normalized_trace_json,
};

fn kernel() -> Kernel {
    Kernel::new(
        KernelConfig {
            max_events: 10_000,
            max_virtual_time: Duration::from_secs(60 * 60 * 24 * 30),
            max_tasks: 64,
        },
        Arc::new(TraceBuffer::default()),
    )
    .unwrap()
}

#[test]
fn seeded_ready_tasks_are_selected_without_duplicate_wakes() {
    let trace = TraceBuffer::default();
    let kernel = Kernel::new(
        KernelConfig {
            max_events: 10_000,
            max_virtual_time: Duration::from_secs(60),
            max_tasks: 64,
        },
        Arc::new(trace.clone()),
    )
    .unwrap();
    let context = kernel.runtime_context(
        RootSeed::new([7; 32]),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    );
    let group = context.executor().new_group(None);
    let order = Arc::new(Mutex::new(Vec::new()));

    for id in [1, 2] {
        let order = order.clone();
        group
            .spawn(
                TaskKind::Protocol,
                &format!("task-{id}"),
                Box::pin(async move {
                    YieldOnce::new(id, order).await;
                }),
            )
            .unwrap();
    }
    group.close();

    let run = kernel.run_until_idle().unwrap();

    let mut observed = order.lock().unwrap().clone();
    observed.sort_unstable();
    assert_eq!(observed, [1, 1, 2, 2]);
    assert_eq!(run.quiescence, Quiescence::Complete);
    assert_eq!(run.ledger.current(ResourceKind::Task), 0);
    assert!(run.scheduler.seeded);
    assert!(run.scheduler.decisions > 0);
    assert!(trace.events().iter().any(|event| matches!(
        &event.event,
        TraceEventKind::Decision { path, .. } if path == "kernel/ready-task"
    )));
}

#[test]
fn ready_task_order_is_seed_replayable_and_seed_sensitive() {
    fn execute(seed_byte: u8) -> Vec<u8> {
        let kernel = kernel();
        let context =
            kernel.runtime_context(RootSeed::new([seed_byte; 32]), SystemTime::UNIX_EPOCH);
        let group = context.executor().new_group(None);
        let order = Arc::new(Mutex::new(Vec::new()));
        for id in 0..8 {
            let order = order.clone();
            group
                .spawn(
                    TaskKind::Other("ready-order".into()),
                    &format!("ready-{id}"),
                    Box::pin(async move { order.lock().unwrap().push(id) }),
                )
                .unwrap();
        }
        group.close();
        kernel.run_until_idle().unwrap();
        order.lock().unwrap().clone()
    }

    let baseline = execute(11);
    assert_eq!(baseline, execute(11));
    assert!((12..20).any(|seed| execute(seed) != baseline));
}

#[test]
fn ready_task_fairness_bounds_continuously_self_waking_task() {
    let kernel = kernel();
    let context = kernel.runtime_context(RootSeed::new([23; 32]), SystemTime::UNIX_EPOCH);
    let group = context.executor().new_group(None);
    let order = Arc::new(Mutex::new(Vec::new()));
    let busy_order = order.clone();
    group
        .spawn(
            TaskKind::Other("busy".into()),
            "busy",
            Box::pin(YieldMany::new(1, 100, busy_order)),
        )
        .unwrap();
    let peer_order = order.clone();
    group
        .spawn(
            TaskKind::Other("peer".into()),
            "peer",
            Box::pin(async move { peer_order.lock().unwrap().push(2) }),
        )
        .unwrap();
    group.close();

    let run = kernel.run_until_idle().unwrap();
    let peer_index = order
        .lock()
        .unwrap()
        .iter()
        .position(|id| *id == 2)
        .unwrap();

    assert!(peer_index <= 32, "peer ran at selection {peer_index}");
    assert!(run.scheduler.max_ready_wait <= 32);
}

#[test]
fn task_ownership_snapshot_retains_parent_child_history() {
    let kernel = kernel();
    let context = kernel.runtime_context(RootSeed::new([29; 32]), SystemTime::UNIX_EPOCH);
    let roots = context.executor().new_group(None);
    let root = roots
        .spawn_owned(TaskKind::Protocol, "root", Box::pin(async {}))
        .unwrap();
    let root_id = root.detach();
    roots.close();
    let children = context.executor().new_group(Some(root_id));
    children
        .spawn_owned(TaskKind::Protocol, "child", Box::pin(async {}))
        .unwrap()
        .detach();
    children.close();

    kernel.run_until_idle().unwrap();
    let tasks = kernel.task_ownership_snapshot();

    assert_eq!(tasks.len(), 2);
    assert!(tasks.iter().all(|task| !task.live));
    assert_eq!(
        tasks
            .iter()
            .find(|task| task.metadata.name == "child")
            .unwrap()
            .metadata
            .parent,
        Some(root_id)
    );
}

#[test]
fn runnable_budget_reports_possible_livelock_separately() {
    let kernel = Kernel::new(
        KernelConfig {
            max_events: 3,
            max_virtual_time: Duration::from_secs(1),
            max_tasks: 1,
        },
        Arc::new(TraceBuffer::default()),
    )
    .unwrap();
    let context = kernel.runtime_context(RootSeed::new([31; 32]), SystemTime::UNIX_EPOCH);
    let group = context.executor().new_group(None);
    group
        .spawn(
            TaskKind::Other("livelock".into()),
            "livelock",
            Box::pin(YieldMany::new(
                1,
                u64::MAX,
                Arc::new(Mutex::new(Vec::new())),
            )),
        )
        .unwrap();
    group.close();

    assert!(matches!(
        kernel.run_until_idle(),
        Err(KernelError::RunnableBudgetExceeded {
            limit: 3,
            live_tasks: 1,
            ready_tasks: 1,
        })
    ));
}

#[test]
fn idle_kernel_orders_events_by_deadline_class_then_id() {
    let kernel = kernel();
    let order = Arc::new(Mutex::new(Vec::new()));

    for (deadline, class, label) in [
        (Duration::from_secs(2), EventClass::Network, "late"),
        (Duration::from_secs(1), EventClass::Timer, "timer"),
        (
            Duration::from_secs(1),
            EventClass::Infrastructure,
            "infra-1",
        ),
        (
            Duration::from_secs(1),
            EventClass::Infrastructure,
            "infra-2",
        ),
    ] {
        let order = order.clone();
        kernel
            .schedule_at(deadline, class, move || {
                order.lock().unwrap().push(label);
                Ok(())
            })
            .unwrap();
    }

    let run = kernel.run_until_idle().unwrap();

    assert_eq!(
        *order.lock().unwrap(),
        ["infra-1", "infra-2", "timer", "late"]
    );
    assert_eq!(run.virtual_time, Duration::from_secs(2));
}

#[test]
fn cancelled_environment_event_is_skipped_without_advancing_time() {
    let kernel = kernel();
    let fired = Arc::new(AtomicBool::new(false));
    let observed = fired.clone();
    let (_, event) = kernel
        .schedule_cancellable_at(
            Duration::from_secs(10),
            EventClass::Infrastructure,
            move || {
                observed.store(true, Ordering::Release);
                Ok(())
            },
        )
        .unwrap();

    event.cancel();
    let run = kernel.run_until_idle().unwrap();

    assert!(!fired.load(Ordering::Acquire));
    assert_eq!(run.virtual_time, Duration::ZERO);
    assert_eq!(run.events_executed, 0);
}

#[test]
fn virtual_timer_and_wall_clock_advance_without_sleeping() {
    let kernel = kernel();
    let epoch = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let context = kernel.runtime_context(RootSeed::new([9; 32]), epoch);
    let group = context.executor().new_group(None);
    let clock = context.clock();
    let wall_clock = context.wall_clock();
    let observed = Arc::new(Mutex::new(None));
    let task_observed = observed.clone();
    let task_clock = clock.clone();

    group
        .spawn(
            TaskKind::Other("multi-day-timer".into()),
            "multi-day-timer",
            Box::pin(async move {
                let mut timer = task_clock
                    .new_timer(task_clock.now() + Duration::from_secs(7 * 24 * 60 * 60))
                    .unwrap();
                poll_fn(|cx| timer.as_mut().poll(cx)).await.unwrap();
                *task_observed.lock().unwrap() = Some(task_clock.elapsed_nanos().unwrap());
            }),
        )
        .unwrap();
    group.close();

    let run = kernel.run_until_idle().unwrap();

    assert_eq!(
        *observed.lock().unwrap(),
        Some(Duration::from_secs(7 * 24 * 60 * 60).as_nanos() as u64)
    );
    assert_eq!(
        wall_clock.now_system(),
        epoch + Duration::from_secs(7 * 24 * 60 * 60)
    );
    assert_eq!(run.ledger.current(ResourceKind::Timer), 0);
}

#[test]
fn timer_reset_and_drop_balance_the_ledger() {
    let kernel = kernel();
    let context = kernel.runtime_context(RootSeed::new([1; 32]), SystemTime::UNIX_EPOCH);
    let clock = context.clock();
    let start = clock.now();
    let mut timer = clock.new_timer(start + Duration::from_secs(20)).unwrap();
    timer
        .as_mut()
        .reset(start + Duration::from_secs(10))
        .unwrap();

    assert_eq!(kernel.ledger().current(ResourceKind::Timer), 1);
    drop(timer);
    assert_eq!(kernel.ledger().current(ResourceKind::Timer), 0);

    let run = kernel.run_until_idle().unwrap();
    assert_eq!(
        run.virtual_time,
        Duration::ZERO,
        "stale timer events do not advance time"
    );
}

#[test]
fn owned_handle_abort_cancels_and_drops_the_future() {
    let kernel = kernel();
    let context = kernel.runtime_context(RootSeed::new([2; 32]), SystemTime::UNIX_EPOCH);
    let group = context.executor().new_group(None);
    let dropped = Arc::new(AtomicBool::new(false));
    let task_dropped = dropped.clone();

    let handle = group
        .spawn_owned(
            TaskKind::Protocol,
            "pending",
            Box::pin(async move {
                let _drop = DropFlag(task_dropped);
                std::future::pending::<()>().await;
            }),
        )
        .unwrap();
    kernel
        .schedule_at(Duration::ZERO, EventClass::Infrastructure, move || {
            handle.abort();
            Ok(())
        })
        .unwrap();
    group.close();

    let run = kernel.run_until_idle().unwrap();

    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(run.quiescence, Quiescence::Complete);
    assert!(group.snapshot().tasks.is_empty());
}

#[test]
fn stalled_tasks_and_event_budget_are_distinct_results() {
    let stalled = kernel();
    let context = stalled.runtime_context(RootSeed::new([3; 32]), SystemTime::UNIX_EPOCH);
    let group = context.executor().new_group(None);
    group
        .spawn(
            TaskKind::Other("stalled".into()),
            "stalled",
            Box::pin(std::future::pending()),
        )
        .unwrap();
    group.close();

    let run = stalled.run_until_idle().unwrap();
    assert_eq!(run.quiescence, Quiescence::Stalled { live_tasks: 1 });

    let bounded = Kernel::new(
        KernelConfig {
            max_events: 1,
            max_virtual_time: Duration::from_secs(1),
            max_tasks: 1,
        },
        Arc::new(TraceBuffer::default()),
    )
    .unwrap();
    bounded
        .schedule_at(Duration::ZERO, EventClass::Network, || Ok(()))
        .unwrap();
    bounded
        .schedule_at(Duration::ZERO, EventClass::Network, || Ok(()))
        .unwrap();

    assert!(matches!(
        bounded.run_until_idle(),
        Err(KernelError::EventBudgetExceeded { limit: 1 })
    ));
}

#[test]
fn event_budget_is_cumulative_across_step_and_run_calls() {
    let trace = TraceBuffer::default();
    let kernel = Kernel::new(
        KernelConfig {
            max_events: 2,
            max_virtual_time: Duration::from_secs(1),
            max_tasks: 1,
        },
        Arc::new(trace),
    )
    .unwrap();
    for offset in 1..=3 {
        kernel
            .schedule_at(
                Duration::from_nanos(offset),
                EventClass::Observation,
                || Ok(()),
            )
            .unwrap();
    }

    assert_eq!(kernel.step().unwrap(), iroh_sim::KernelStep::Progress);
    assert_eq!(kernel.step().unwrap(), iroh_sim::KernelStep::Progress);
    assert!(matches!(
        kernel.run_until_idle(),
        Err(KernelError::EventBudgetExceeded { limit: 2 })
    ));
    assert_eq!(kernel.now(), Duration::from_nanos(2));
}

#[test]
fn task_panics_are_contained_and_observed() {
    let trace = TraceBuffer::default();
    let kernel = Kernel::new(
        KernelConfig {
            max_events: 10,
            max_virtual_time: Duration::from_secs(1),
            max_tasks: 1,
        },
        Arc::new(trace.clone()),
    )
    .unwrap();
    let context = kernel.runtime_context(RootSeed::new([4; 32]), SystemTime::UNIX_EPOCH);
    let group = context.executor().new_group(None);
    group
        .spawn(
            TaskKind::Protocol,
            "panic",
            Box::pin(async { panic!("expected kernel test panic") }),
        )
        .unwrap();
    group.close();

    let run = kernel.run_until_idle().unwrap();

    assert_eq!(run.quiescence, Quiescence::Complete);
    assert!(
        trace
            .events()
            .iter()
            .any(|event| { matches!(event.event, TraceEventKind::TaskPanicked { .. }) })
    );
}

#[test]
fn same_seed_kernel_runs_have_byte_identical_normalized_traces() {
    fn execute() -> Vec<Vec<u8>> {
        let trace = TraceBuffer::default();
        let kernel = Kernel::new(
            KernelConfig {
                max_events: 100,
                max_virtual_time: Duration::from_secs(60),
                max_tasks: 4,
            },
            Arc::new(trace.clone()),
        )
        .unwrap();
        let context = kernel.runtime_context(RootSeed::new([5; 32]), SystemTime::UNIX_EPOCH);
        let group = context.executor().new_group(None);
        let clock = context.clock();
        group
            .spawn(
                TaskKind::Noq,
                "golden",
                Box::pin(async move {
                    let mut timer = clock
                        .new_timer(clock.now() + Duration::from_secs(42))
                        .unwrap();
                    poll_fn(|cx| timer.as_mut().poll(cx)).await.unwrap();
                }),
            )
            .unwrap();
        group.close();
        let run = kernel.run_until_idle().unwrap();
        assert!(run.ledger.is_empty());
        trace
            .events()
            .iter()
            .map(|event| normalized_trace_json(event).unwrap())
            .collect()
    }

    assert_eq!(execute(), execute());
}

#[test]
fn virtual_time_budget_rejects_the_next_event_without_advancing() {
    let kernel = Kernel::new(
        KernelConfig {
            max_events: 2,
            max_virtual_time: Duration::from_secs(1),
            max_tasks: 1,
        },
        Arc::new(TraceBuffer::default()),
    )
    .unwrap();
    kernel
        .schedule_at(Duration::from_secs(2), EventClass::Network, || Ok(()))
        .unwrap();

    assert!(matches!(
        kernel.run_until_idle(),
        Err(KernelError::VirtualTimeBudgetExceeded {
            limit_nanos: 1_000_000_000,
            next_deadline_nanos: 2_000_000_000,
        })
    ));
    assert_eq!(kernel.ledger().current(ResourceKind::Task), 0);
}

struct YieldOnce {
    id: u8,
    order: Arc<Mutex<Vec<u8>>>,
    yielded: bool,
}

struct YieldMany {
    id: u8,
    remaining: u64,
    order: Arc<Mutex<Vec<u8>>>,
}

impl YieldMany {
    fn new(id: u8, remaining: u64, order: Arc<Mutex<Vec<u8>>>) -> Self {
        Self {
            id,
            remaining,
            order,
        }
    }
}

impl Future for YieldMany {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.order.lock().unwrap().push(self.id);
        if self.remaining == 0 {
            Poll::Ready(())
        } else {
            self.remaining -= 1;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

impl YieldOnce {
    fn new(id: u8, order: Arc<Mutex<Vec<u8>>>) -> Self {
        Self {
            id,
            order,
            yielded: false,
        }
    }
}

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.order.lock().unwrap().push(self.id);
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[allow(dead_code)]
fn assert_timer_object_safe(_: Pin<Box<dyn Timer>>) {}
