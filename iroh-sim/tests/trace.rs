use std::{
    fs,
    sync::atomic::{AtomicU64, Ordering},
};

use iroh_runtime::{TaskId, TraceContext, TraceEvent, TraceEventKind, TraceSequence, TraceSink};
use iroh_sim::{ArtifactStore, ArtifactTraceWriter, first_trace_divergence, normalized_trace_json};

#[test]
fn trace_normalization_redacts_host_paths_and_is_stable() {
    let event = TraceEvent::new(
        TraceSequence::new(1).unwrap(),
        7,
        TraceContext {
            endpoint: Some("/home/alice/endpoint".to_owned()),
            ..TraceContext::default()
        },
        TraceEventKind::StateTransition {
            component: "endpoint".to_owned(),
            from: "binding".to_owned(),
            to: "ready".to_owned(),
        },
    );

    let first = normalized_trace_json(&event).unwrap();
    let second = normalized_trace_json(&event).unwrap();
    assert_eq!(first, second);
    assert!(
        !String::from_utf8(first.clone())
            .unwrap()
            .contains("/home/alice")
    );
    assert!(
        String::from_utf8(first)
            .unwrap()
            .contains("<redacted-host-path>")
    );
}

#[test]
fn artifact_writes_are_atomic_and_do_not_overwrite() {
    let root = temp_dir();
    let store = ArtifactStore::new(&root).unwrap();
    let event = TraceEvent::new(
        TraceSequence::new(1).unwrap(),
        0,
        TraceContext {
            task: Some(TaskId::new(1).unwrap()),
            ..TraceContext::default()
        },
        TraceEventKind::TaskCompleted {
            task: TaskId::new(1).unwrap(),
        },
    );

    let path = store.write_trace("trace.jsonl", [&event]).unwrap();
    let bytes = fs::read(&path).unwrap();
    assert!(bytes.ends_with(b"\n"));
    assert!(store.write_trace("trace.jsonl", [&event]).is_err());
    assert!(store.write_trace("../escape.jsonl", [&event]).is_err());

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn trace_writer_publishes_immutable_atomic_prefix_chunks() {
    let root = temp_dir();
    let store = ArtifactStore::new(&root).unwrap();
    let writer = ArtifactTraceWriter::new(store, 2).unwrap();

    writer.record(event(1, 0)).unwrap();
    assert!(!root.join("trace.chunk.00000000.jsonl").exists());
    writer.record(event(2, 1)).unwrap();
    assert!(root.join("trace.chunk.00000000.jsonl").is_file());
    assert!(root.join("trace.raw.chunk.00000000.jsonl").is_file());

    writer.record(event(3, 2)).unwrap();
    writer.flush().unwrap();
    assert!(root.join("trace.chunk.00000001.jsonl").is_file());
    let first = fs::read(root.join("trace.chunk.00000000.jsonl")).unwrap();
    let second = fs::read(root.join("trace.chunk.00000001.jsonl")).unwrap();
    assert_eq!(first.iter().filter(|byte| **byte == b'\n').count(), 2);
    assert_eq!(second.iter().filter(|byte| **byte == b'\n').count(), 1);

    assert!(writer.flush().is_ok(), "empty flush is idempotent");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn first_divergence_reports_changed_and_missing_events() {
    let first = event(1, 0);
    let changed = event(1, 9);
    let divergence =
        first_trace_divergence(std::slice::from_ref(&first), std::slice::from_ref(&changed))
            .unwrap()
            .unwrap();
    assert_eq!(divergence.index, 0);
    assert!(divergence.expected.is_some());
    assert!(divergence.actual.is_some());

    let divergence = first_trace_divergence(&[first], &[]).unwrap().unwrap();
    assert_eq!(divergence.index, 0);
    assert!(divergence.expected.is_some());
    assert!(divergence.actual.is_none());
}

#[test]
fn replay_normalization_ignores_opaque_encrypted_packet_bytes() {
    let packet = |payload_hash: &str| {
        TraceEvent::new(
            TraceSequence::new(1).unwrap(),
            0,
            TraceContext {
                packet: Some("1".to_owned()),
                ..TraceContext::default()
            },
            TraceEventKind::PacketCreated {
                source: "192.0.2.1:1".to_owned(),
                destination: "192.0.2.2:2".to_owned(),
                original_source: "192.0.2.1:1".to_owned(),
                original_destination: "192.0.2.2:2".to_owned(),
                length: 1200,
                payload_hash: payload_hash.to_owned(),
            },
        )
    };
    let first = packet(&"a".repeat(64));
    let second = packet(&"b".repeat(64));

    assert_ne!(first, second, "raw trace preserves forensic packet hashes");
    assert_eq!(
        first_trace_divergence(std::slice::from_ref(&first), std::slice::from_ref(&second))
            .unwrap(),
        None,
        "TLS ciphertext entropy is not a behavioral replay divergence"
    );
    let normalized = String::from_utf8(normalized_trace_json(&first).unwrap()).unwrap();
    assert!(normalized.contains("<opaque-packet-payload>"));
    assert!(!normalized.contains(&"a".repeat(64)));
}

fn event(sequence: u64, virtual_time_nanos: u64) -> TraceEvent {
    TraceEvent::new(
        TraceSequence::new(sequence).unwrap(),
        virtual_time_nanos,
        TraceContext::default(),
        TraceEventKind::StateTransition {
            component: "endpoint".to_owned(),
            from: "binding".to_owned(),
            to: "ready".to_owned(),
        },
    )
}

fn temp_dir() -> std::path::PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let path = std::env::temp_dir().join(format!(
        "iroh-sim-trace-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    path
}
