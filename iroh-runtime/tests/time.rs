#![cfg(not(all(target_family = "wasm", target_os = "unknown")))]

use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::{Duration, SystemTime},
};

use iroh_runtime::{
    Clock, ClockDomain, SystemWallClock, Timer, TokioClock, TraceContext, TraceEvent,
    TraceEventKind, TraceRecorder, TraceSink, TraceSinkError, WallClock,
};

#[test]
fn non_tokio_clocks_can_allocate_distinct_domains() {
    assert_ne!(ClockDomain::fresh(), ClockDomain::fresh());
}

#[tokio::test(start_paused = true)]
async fn tokio_timer_uses_the_clock_domain_and_can_reset() {
    let clock = TokioClock::default();
    let start = clock.now();
    let mut timer = clock
        .new_timer(start + Duration::from_secs(60))
        .expect("timer id is available");
    timer
        .as_mut()
        .reset(start + Duration::from_secs(5))
        .expect("reset is traced");

    assert!(matches!(poll_timer(&mut timer), Poll::Pending));
    tokio::time::advance(Duration::from_secs(4)).await;
    assert!(matches!(poll_timer(&mut timer), Poll::Pending));
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(matches!(poll_timer(&mut timer), Poll::Ready(Ok(()))));
}

#[tokio::test(start_paused = true)]
async fn timer_lifecycle_is_observable() {
    let sink = RecordingSink::default();
    let clock = TokioClock::new(Arc::new(sink.clone()));
    let deadline = clock.now() + Duration::from_secs(2);
    let mut timer = clock.new_timer(deadline).unwrap();
    timer
        .as_mut()
        .reset(deadline + Duration::from_secs(1))
        .unwrap();

    tokio::time::advance(Duration::from_secs(3)).await;
    assert!(matches!(poll_timer(&mut timer), Poll::Ready(Ok(()))));
    drop(timer);

    let events = sink.events();
    assert!(matches!(
        events[0].event,
        TraceEventKind::TimerCreated { .. }
    ));
    assert!(matches!(events[1].event, TraceEventKind::TimerReset { .. }));
    assert!(matches!(events[2].event, TraceEventKind::TimerFired { .. }));
    assert_eq!(
        events.len(),
        3,
        "a fired timer is not also reported dropped"
    );
}

#[test]
fn system_wall_clock_delegates_to_system_time() {
    let before = SystemTime::now();
    let observed = SystemWallClock.now_system();
    let after = SystemTime::now();

    assert!(observed >= before);
    assert!(observed <= after);
}

#[tokio::test(start_paused = true)]
async fn clock_and_other_components_share_one_trace_sequence() {
    let sink = RecordingSink::default();
    let recorder = Arc::new(TraceRecorder::new(Arc::new(sink.clone())));
    let clock = TokioClock::with_recorder(recorder.clone());
    let timer = clock
        .new_timer(clock.now() + Duration::from_secs(1))
        .unwrap();
    recorder
        .record(
            clock.elapsed_nanos().unwrap(),
            TraceContext::default(),
            TraceEventKind::StateTransition {
                component: "test".to_owned(),
                from: "before".to_owned(),
                to: "after".to_owned(),
            },
        )
        .unwrap();
    drop(timer);

    let sequences: Vec<_> = sink
        .events()
        .iter()
        .map(|event| event.sequence.get())
        .collect();
    assert_eq!(sequences, [1, 2, 3]);
}

fn poll_timer(timer: &mut Pin<Box<dyn Timer>>) -> Poll<Result<(), iroh_runtime::ClockError>> {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    timer.as_mut().poll(&mut cx)
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
