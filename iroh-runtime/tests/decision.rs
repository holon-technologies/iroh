use std::sync::{Arc, Mutex};

use iroh_runtime::{
    DecisionError, DecisionObserver, DecisionPath, DecisionSource, RootSeed, SeededDecisionSource,
};

#[test]
fn identical_root_and_path_replay_the_same_values() {
    let source = SeededDecisionSource::new(RootSeed::new([7; 32]));
    let mut first = source.stream("endpoint/a/noq").unwrap();
    let mut replay = source.stream("endpoint/a/noq").unwrap();

    let values = [
        first.next_u64().unwrap(),
        first.next_u64().unwrap(),
        first.next_u64().unwrap(),
    ];
    let replayed = [
        replay.next_u64().unwrap(),
        replay.next_u64().unwrap(),
        replay.next_u64().unwrap(),
    ];

    assert_eq!(
        values,
        [
            7_477_092_645_240_195_235,
            3_453_525_680_366_875_447,
            15_378_937_191_691_192_511,
        ],
        "update only for an intentional RNG schema change"
    );
    assert_eq!(values, replayed);
    assert_eq!(first.draw_index(), 3);
    assert_eq!(replay.draw_index(), 3);
}

#[test]
fn semantic_paths_isolate_subsystem_draws() {
    let source = SeededDecisionSource::new(RootSeed::new([11; 32]));
    let mut endpoint_before = source.stream("endpoint/a/noq").unwrap();
    let expected = endpoint_before.next_u64().unwrap();

    let mut unrelated = source.stream("relay/r1/reconnect").unwrap();
    for _ in 0..100 {
        unrelated.next_u64().unwrap();
    }

    let mut endpoint_after = source.stream("endpoint/a/noq").unwrap();
    assert_eq!(endpoint_after.next_u64().unwrap(), expected);
}

#[test]
fn decision_path_validation_is_strict() {
    assert!(DecisionPath::new("").is_err());
    assert!(DecisionPath::new("endpoint//noq").is_err());
    assert!(DecisionPath::new("endpoint/with space").is_err());
    assert!(DecisionPath::new("a".repeat(257)).is_err());
    assert_eq!(
        DecisionPath::new("endpoint/a_1/noq.v1").unwrap().as_str(),
        "endpoint/a_1/noq.v1"
    );
}

#[test]
fn invalid_ranges_do_not_consume_a_draw() {
    let source = SeededDecisionSource::new(RootSeed::new([13; 32]));
    let mut stream = source.stream("scenario/range").unwrap();

    assert!(matches!(
        stream.range_u64(5..5),
        Err(DecisionError::InvalidRange)
    ));
    assert_eq!(stream.draw_index(), 0);
    assert!((5..10).contains(&stream.range_u64(5..10).unwrap()));
    assert_eq!(stream.draw_index(), 1);
}

#[test]
fn every_draw_is_reported_with_its_path_and_index() {
    let observer = RecordingObserver::default();
    let source =
        SeededDecisionSource::with_observer(RootSeed::new([17; 32]), Arc::new(observer.clone()));
    let mut stream = source.stream("network/link/a-b").unwrap();

    stream.next_u64().unwrap();
    stream.boolean(1, 3).unwrap();
    let mut bytes = [0; 4];
    stream.fill_bytes(&mut bytes).unwrap();

    assert_eq!(
        observer.records(),
        [
            ("network/link/a-b".to_owned(), 0),
            ("network/link/a-b".to_owned(), 1),
            ("network/link/a-b".to_owned(), 2),
        ]
    );
}

#[derive(Clone, Debug, Default)]
struct RecordingObserver(Arc<Mutex<Vec<(String, u64)>>>);

impl RecordingObserver {
    fn records(&self) -> Vec<(String, u64)> {
        self.0.lock().unwrap().clone()
    }
}

impl DecisionObserver for RecordingObserver {
    fn record(
        &self,
        path: &DecisionPath,
        draw_index: u64,
        _selected: &str,
    ) -> Result<(), DecisionError> {
        self.0
            .lock()
            .unwrap()
            .push((path.as_str().to_owned(), draw_index));
        Ok(())
    }
}
