use std::{
    fs,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::SystemTime,
};

use iroh_runtime::{RootSeed, TraceEventKind};
use iroh_sim::{
    CampaignConfig, CampaignRunner, CampaignTerminal, Corpus, CorpusExpectation, CorpusReviewState,
    FailureSignature, MinimizationConfig, RunnerError, Scenario, ScenarioRunner, TraceBuffer,
    first_trace_divergence,
};

#[test]
fn permanent_corpus_is_strict_enumerated_and_expected_signatures_match() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    let corpus = Corpus::load(&root).unwrap();
    assert!(!corpus.entries().is_empty());
    assert!(
        corpus
            .entries()
            .iter()
            .all(|entry| entry.metadata.review_state == CorpusReviewState::Reviewed)
    );
    let reports = corpus
        .test(|entry| match &entry.metadata.expectation {
            CorpusExpectation::Success => Ok(None),
            CorpusExpectation::ExpectedFailure { signature } => Ok(Some(signature.clone())),
        })
        .unwrap();
    assert!(reports.iter().all(|report| report.matched));

    let copy = temp_dir("corpus-copy");
    copy_dir(&root, &copy);
    fs::write(copy.join("unexpected.json"), b"{}\n").unwrap();
    assert!(Corpus::load(&copy).is_err());
    fs::remove_dir_all(copy).unwrap();
}

#[test]
fn campaign_is_repeatable_ordered_and_worker_count_independent() {
    let scenario = Scenario::from_json(include_bytes!("fixtures/v2-ipv4-stream.json")).unwrap();
    let executions = AtomicU64::new(0);
    let execute = |seed: u64, _scenario: &Scenario| {
        executions.fetch_add(1, Ordering::Relaxed);
        if seed.is_multiple_of(3) {
            Ok(CampaignTerminal::Failure(signature(seed % 2)))
        } else {
            Ok(CampaignTerminal::Success)
        }
    };
    let sequential = CampaignRunner::run(
        CampaignConfig {
            seed_start: 10,
            seed_end_exclusive: 25,
            jobs: 1,
            fail_fast: false,
            max_runs: 100,
        },
        &scenario,
        &execute,
    )
    .unwrap();
    let parallel = CampaignRunner::run(
        CampaignConfig {
            seed_start: 10,
            seed_end_exclusive: 25,
            jobs: 4,
            fail_fast: false,
            max_runs: 100,
        },
        &scenario,
        &execute,
    )
    .unwrap();
    assert_eq!(sequential.results, parallel.results);
    assert_eq!(sequential.unique_failures, parallel.unique_failures);
    assert_eq!(parallel.results.first().unwrap().seed, 10);
    assert_eq!(parallel.results.last().unwrap().seed, 24);

    let stopped = CampaignRunner::run(
        CampaignConfig {
            seed_start: 9,
            seed_end_exclusive: 30,
            jobs: 4,
            fail_fast: true,
            max_runs: 100,
        },
        &scenario,
        &execute,
    )
    .unwrap();
    assert_eq!(stopped.results.len(), 4);
    assert!(stopped.stopped_early);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn reviewed_rare_ready_order_replays_the_production_scheduler_witness() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    let corpus = Corpus::load(&root).unwrap();
    let entry = corpus
        .entries()
        .iter()
        .find(|entry| entry.metadata.id == "stage6-rare-ready-order")
        .expect("reviewed Stage 6 scheduler corpus entry");
    let seed = RootSeed::new(decode_seed(&entry.metadata.seed));

    async fn execute(
        scenario: Scenario,
        seed: RootSeed,
    ) -> (iroh_sim::ScenarioReport, Vec<iroh_runtime::TraceEvent>) {
        let trace = TraceBuffer::default();
        let report = ScenarioRunner::deterministic(
            scenario,
            seed,
            SystemTime::UNIX_EPOCH,
            Arc::new(trace.clone()),
        )
        .unwrap()
        .run()
        .await
        .unwrap();
        (report, trace.events())
    }

    let (first_report, first_trace) = execute(entry.scenario.clone(), seed).await;
    let (second_report, second_trace) = execute(entry.scenario.clone(), seed).await;
    assert_eq!(first_report, second_report);
    assert_eq!(
        first_trace_divergence(&first_trace, &second_trace).unwrap(),
        None
    );
    let scheduler = first_report.scheduler.expect("scheduler snapshot");
    assert!(scheduler.seeded && scheduler.decisions >= 90);
    let (selected, ready) = first_trace
        .iter()
        .find_map(|event| match &event.event {
            TraceEventKind::TaskScheduled {
                selected, ready, ..
            } if ready.len() == 4 => Some((selected, ready)),
            _ => None,
        })
        .expect("four-way ready-order witness");
    assert_eq!(selected.name, "socket-actor");
    assert_eq!(
        ready
            .iter()
            .filter(|task| task.name == "socket-actor")
            .count(),
        2
    );
    assert_eq!(ready.iter().filter(|task| task.name == "noq").count(), 2);
}

#[test]
fn campaign_rejects_invalid_ranges_and_worker_panics_are_classified() {
    let scenario = Scenario::from_json(include_bytes!("fixtures/v2-ipv4-stream.json")).unwrap();
    assert!(
        CampaignRunner::run(
            CampaignConfig {
                seed_start: 2,
                seed_end_exclusive: 2,
                jobs: 1,
                fail_fast: false,
                max_runs: 1,
            },
            &scenario,
            &|_, _| Ok(CampaignTerminal::Success),
        )
        .is_err()
    );
    let summary = CampaignRunner::run(
        CampaignConfig {
            seed_start: 1,
            seed_end_exclusive: 3,
            jobs: 2,
            fail_fast: false,
            max_runs: 2,
        },
        &scenario,
        &|seed, _| {
            if seed == 2 {
                panic!("fixture panic");
            }
            Ok(CampaignTerminal::Success)
        },
    )
    .unwrap();
    assert!(summary.results[1].worker_panic);
}

fn signature(variant: u64) -> FailureSignature {
    FailureSignature::from_runner_error(
        &RunnerError::TriggerStall(vec![format!("cause-{variant}")]),
        &[],
        MinimizationConfig::default().max_attempts.min(4) as usize,
    )
    .unwrap()
}

fn decode_seed(hex: &str) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
    }
    bytes
}

fn temp_dir(label: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("iroh-sim-{label}-{}", std::process::id()));
    if path.exists() {
        fs::remove_dir_all(&path).unwrap();
    }
    fs::create_dir(&path).unwrap();
    path
}

fn copy_dir(source: &std::path::Path, destination: &std::path::Path) {
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            fs::create_dir(&target).unwrap();
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}
