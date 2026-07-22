#![cfg(not(all(target_family = "wasm", target_os = "unknown")))]

use std::{
    future::poll_fn,
    sync::{Arc, Mutex},
    time::Duration,
};

use iroh_runtime::{
    RootSeed, RuntimeContext, TaskKind, TraceContext, TraceEvent, TraceEventKind, TraceSink,
    TraceSinkError,
};
use iroh_sim::normalized_trace_json;

#[tokio::test(start_paused = true)]
async fn repeated_timer_task_lifecycle_has_byte_identical_trace() {
    let first = run_once().await;
    let second = run_once().await;
    assert_eq!(first, second);
}

async fn run_once() -> Vec<u8> {
    let sink = RecordingSink::default();
    let context = RuntimeContext::tokio(RootSeed::new([41; 32]), Arc::new(sink.clone()));

    context
        .decisions()
        .stream("scenario/lifecycle")
        .unwrap()
        .next_u64()
        .unwrap();

    let clock = context.clock();
    let mut timer = clock
        .new_timer(clock.now() + Duration::from_secs(5))
        .unwrap();
    let group = context.executor().new_group(None);
    group
        .spawn(TaskKind::Protocol, "lifecycle", Box::pin(async {}))
        .unwrap();
    group.close();
    group.join().await.unwrap();

    tokio::time::advance(Duration::from_secs(5)).await;
    poll_fn(|cx| timer.as_mut().poll(cx)).await.unwrap();
    drop(timer);

    context
        .trace()
        .record(
            clock.elapsed_nanos().unwrap(),
            TraceContext::default(),
            TraceEventKind::StateTransition {
                component: "endpoint".to_owned(),
                from: "closing".to_owned(),
                to: "closed".to_owned(),
            },
        )
        .unwrap();

    let mut output = Vec::new();
    for event in sink.events() {
        output.extend(normalized_trace_json(&event).unwrap());
        output.push(b'\n');
    }
    output
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
