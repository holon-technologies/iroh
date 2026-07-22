use std::num::NonZeroU64;

use iroh_runtime::{
    IdAllocator, NoopTraceSink, TaskId, TaskKind, TaskMetadata, TraceContext, TraceEvent,
    TraceEventKind, TraceSequence, TraceSink,
};

#[test]
fn trace_event_has_a_stable_json_schema() {
    let task = TaskId::new(7).expect("non-zero task id");
    let event = TraceEvent::new(
        TraceSequence::new(3).expect("non-zero sequence"),
        42,
        TraceContext {
            task: Some(task),
            endpoint: Some("endpoint-a".to_owned()),
            ..TraceContext::default()
        },
        TraceEventKind::TaskSpawned {
            metadata: TaskMetadata {
                id: task,
                parent: None,
                child_ordinal: 0,
                kind: TaskKind::Noq,
                name: "connection-driver".to_owned(),
            },
        },
    );

    let json = serde_json::to_string(&event).expect("trace event serializes");
    assert_eq!(
        json,
        r#"{"schema_version":2,"sequence":3,"virtual_time_nanos":42,"context":{"task":7,"endpoint":"endpoint-a"},"event":{"kind":"task_spawned","metadata":{"id":7,"child_ordinal":0,"kind":"noq","name":"connection-driver"}}}"#
    );
    assert_eq!(
        serde_json::from_str::<TraceEvent>(&json).expect("trace event round trips"),
        event
    );
}

#[test]
fn stable_ids_reject_zero_and_sort_numerically() {
    assert!(TaskId::new(0).is_none());

    let mut ids = [
        TaskId::new(9).unwrap(),
        TaskId::new(2).unwrap(),
        TaskId::new(5).unwrap(),
    ];
    ids.sort();

    assert_eq!(ids.map(TaskId::get), [2, 5, 9]);
}

#[test]
fn id_allocator_reports_exhaustion_without_wrapping() {
    let allocator = IdAllocator::<TaskId>::from_next(NonZeroU64::new(u64::MAX).unwrap());

    assert_eq!(allocator.allocate().unwrap().get(), u64::MAX);
    assert!(allocator.allocate().is_err());
}

#[test]
fn unknown_trace_event_kind_is_rejected() {
    let json = r#"{"schema_version":1,"sequence":1,"virtual_time_nanos":0,"context":{},"event":{"kind":"future_kind"}}"#;
    assert!(serde_json::from_str::<TraceEvent>(json).is_err());
}

#[test]
fn production_noop_trace_sink_cannot_fail() {
    let event = TraceEvent::new(
        TraceSequence::new(1).unwrap(),
        0,
        TraceContext::default(),
        TraceEventKind::TaskCompleted {
            task: TaskId::new(1).unwrap(),
        },
    );

    NoopTraceSink
        .record(event)
        .expect("no-op sink is infallible");
}
