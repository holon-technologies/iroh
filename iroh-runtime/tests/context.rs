#![cfg(not(all(target_family = "wasm", target_os = "unknown")))]

use std::sync::{Arc, Mutex};

use iroh_runtime::{
    NoopDecisionObserver, NoopTraceSink, RootSeed, RuntimeContext, RuntimeContextError,
    SeededDecisionSource, SystemWallClock, TokioClock, TokioExecutor, TraceEvent, TraceEventKind,
    TraceRecorder, TraceSink, TraceSinkError,
};

#[tokio::test]
async fn tokio_context_shares_one_clock_trace_and_behavioral_seed() {
    let sink = RecordingSink::default();
    let seed = RootSeed::new([19; 32]);
    let context = RuntimeContext::tokio(seed, Arc::new(sink.clone()));

    assert_eq!(context.root_seed(), seed);
    let expected = context
        .decisions()
        .stream("noq/endpoint")
        .unwrap()
        .next_u64()
        .unwrap();
    let replayed = RuntimeContext::tokio(seed, Arc::new(iroh_runtime::NoopTraceSink))
        .decisions()
        .stream("noq/endpoint")
        .unwrap()
        .next_u64()
        .unwrap();
    assert_eq!(expected, replayed);

    let clock = context.clock();
    let timer = clock.new_timer(clock.now()).unwrap();
    drop(timer);

    let events = sink.events();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].sequence.get(), 1);
    assert!(matches!(events[0].event, TraceEventKind::Decision { .. }));
    assert_eq!(events[1].sequence.get(), 2);
    assert!(matches!(
        events[1].event,
        TraceEventKind::TimerCreated { .. }
    ));
    assert_eq!(events[2].sequence.get(), 3);
    assert!(matches!(
        events[2].event,
        TraceEventKind::TimerDropped { .. }
    ));
}

#[test]
fn context_rejects_mixed_clock_and_executor_domains() {
    let trace = Arc::new(TraceRecorder::new(Arc::new(NoopTraceSink)));
    let context_clock = Arc::new(TokioClock::with_recorder(trace.clone()));
    let executor_clock = Arc::new(TokioClock::with_recorder(trace.clone()));
    let executor = Arc::new(TokioExecutor::with_clock(executor_clock, trace.clone()));
    let seed = RootSeed::new([43; 32]);
    let decisions = Arc::new(SeededDecisionSource::with_observer(
        seed,
        Arc::new(NoopDecisionObserver),
    ));

    let result = RuntimeContext::from_parts(
        seed,
        context_clock,
        Arc::new(SystemWallClock),
        executor,
        decisions,
        trace,
    );
    assert!(matches!(
        result,
        Err(RuntimeContextError::ClockDomainMismatch)
    ));
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
