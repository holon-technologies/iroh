use std::{hint::black_box, sync::Arc, time::Duration};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use iroh_runtime::{Executor, RootSeed, TaskKind};
use iroh_sim::{Kernel, KernelConfig, Quiescence, TraceBuffer};

const TASKS: u64 = 256;

fn stage6_scheduler(c: &mut Criterion) {
    let mut group = c.benchmark_group("stage6_ready_scheduler");
    group.throughput(Throughput::Elements(TASKS));
    for seeded in [false, true] {
        group.bench_with_input(
            BenchmarkId::new(
                "complete_ready_tasks",
                if seeded { "seeded" } else { "fifo" },
            ),
            &seeded,
            |b, seeded| b.iter(|| black_box(run_ready_tasks(*seeded))),
        );
    }
    group.finish();
}

fn run_ready_tasks(seeded: bool) -> u64 {
    let kernel = Kernel::new(
        KernelConfig {
            max_events: 10_000,
            max_virtual_time: Duration::from_secs(1),
            max_tasks: TASKS,
        },
        Arc::new(TraceBuffer::default()),
    )
    .unwrap();
    let tasks = if seeded {
        kernel
            .runtime_context(RootSeed::new([0x6a; 32]), std::time::SystemTime::UNIX_EPOCH)
            .executor()
            .new_group(None)
    } else {
        kernel.executor().new_group(None)
    };
    for ordinal in 0..TASKS {
        tasks
            .spawn(
                TaskKind::Other("scheduler-benchmark".into()),
                "ready",
                Box::pin(async move {
                    black_box(ordinal);
                }),
            )
            .unwrap();
    }
    tasks.close();
    let run = kernel.run_until_idle().unwrap();
    assert_eq!(run.quiescence, Quiescence::Complete);
    run.events_executed
}

criterion_group!(benches, stage6_scheduler);
criterion_main!(benches);
