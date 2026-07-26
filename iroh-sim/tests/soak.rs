use std::sync::atomic::{AtomicU64, Ordering};

use iroh_sim::{
    CampaignTerminal, FailureSignature, MinimizationConfig, RunnerError, Scenario, SeedLease,
    SeedLeaseError, SoakConfig, SoakCryptoLane, SoakError, SoakLane, SoakPlan, SoakPlanError,
    SoakRunner, SoakStopReason, derive_soak_seed_start,
};

fn scenario() -> Scenario {
    Scenario::from_json(include_bytes!("fixtures/v2-ipv4-stream.json")).unwrap()
}

fn lane(id: &str, seed_start: u64) -> SoakLane {
    SoakLane {
        id: id.to_owned(),
        scenario: scenario(),
        seed_start,
    }
}

fn signature(variant: u64) -> FailureSignature {
    FailureSignature::from_runner_error(
        &RunnerError::TriggerStall(vec![format!("cause-{variant}")]),
        &[],
        MinimizationConfig::default().max_attempts.min(4) as usize,
    )
    .unwrap()
}

#[test]
fn soak_rotates_lanes_in_fixed_batches_and_accounts_exactly() {
    let checkpoints = AtomicU64::new(0);
    let summary = SoakRunner::run(
        SoakConfig {
            wall_budget_millis: 60_000,
            jobs: 2,
            batch_runs: 2,
            max_runs: 5,
        },
        vec![lane("a", 10), lane("b", 20)],
        || 0,
        |summary| {
            checkpoints.fetch_add(1, Ordering::Relaxed);
            assert_eq!(
                summary.completed_runs,
                summary.successful_runs + summary.failed_runs + summary.errored_runs
            );
            Ok(())
        },
        |_, _, _| Ok(CampaignTerminal::Success),
    )
    .unwrap();

    assert_eq!(summary.stop_reason, SoakStopReason::RunBudget);
    assert_eq!(summary.completed_runs, 5);
    assert_eq!(summary.successful_runs, 5);
    assert_eq!(summary.failed_runs, 0);
    assert_eq!(summary.errored_runs, 0);
    assert_eq!(summary.worker_panics, 0);
    assert_eq!(checkpoints.load(Ordering::Relaxed), 3);
    assert_eq!(summary.lanes[0].id, "a");
    assert_eq!(summary.lanes[0].completed_runs, 3);
    assert_eq!(summary.lanes[0].next_seed, 13);
    assert_eq!(summary.lanes[1].id, "b");
    assert_eq!(summary.lanes[1].completed_runs, 2);
    assert_eq!(summary.lanes[1].next_seed, 22);
}

#[test]
fn soak_stops_at_the_first_batch_boundary_after_the_wall_budget() {
    let elapsed = AtomicU64::new(0);
    let summary = SoakRunner::run(
        SoakConfig {
            wall_budget_millis: 2_000,
            jobs: 2,
            batch_runs: 2,
            max_runs: 100,
        },
        vec![lane("a", 10), lane("b", 20)],
        || elapsed.load(Ordering::Relaxed),
        |_| {
            elapsed.fetch_add(1_000, Ordering::Relaxed);
            Ok(())
        },
        |_, _, _| Ok(CampaignTerminal::Success),
    )
    .unwrap();

    assert_eq!(summary.stop_reason, SoakStopReason::WallBudget);
    assert_eq!(summary.elapsed_millis, 2_000);
    assert_eq!(summary.completed_runs, 4);
    assert_eq!(summary.lanes[0].completed_runs, 2);
    assert_eq!(summary.lanes[1].completed_runs, 2);
}

#[test]
fn soak_deduplicates_failures_and_counts_errors_and_panics() {
    let summary = SoakRunner::run(
        SoakConfig {
            wall_budget_millis: 60_000,
            jobs: 4,
            batch_runs: 4,
            max_runs: 4,
        },
        vec![lane("a", 10)],
        || 0,
        |_| Ok(()),
        |_, seed, _| match seed {
            10 | 11 => Ok(CampaignTerminal::Failure(signature(1))),
            12 => Err("fixture error".to_owned()),
            13 => panic!("fixture panic"),
            _ => unreachable!(),
        },
    )
    .unwrap();

    assert_eq!(summary.completed_runs, 4);
    assert_eq!(summary.failed_runs, 2);
    assert_eq!(summary.errored_runs, 2);
    assert_eq!(summary.worker_panics, 1);
    assert_eq!(summary.unique_failures.len(), 1);
    assert_eq!(summary.unique_failures[0].first_lane_id, "a");
    assert_eq!(summary.unique_failures[0].first_seed, 10);
    assert_eq!(summary.unique_failures[0].occurrences, 2);
}

#[test]
fn soak_rejects_invalid_bounds_lanes_overflow_and_checkpoint_failure() {
    let zero_wall = SoakRunner::run(
        SoakConfig {
            wall_budget_millis: 0,
            jobs: 1,
            batch_runs: 1,
            max_runs: 1,
        },
        vec![lane("a", 0)],
        || 0,
        |_| Ok(()),
        |_, _, _| Ok(CampaignTerminal::Success),
    );
    assert_eq!(zero_wall, Err(SoakError::ZeroWallBudget));

    let duplicate_lanes = SoakRunner::run(
        SoakConfig {
            wall_budget_millis: 1,
            jobs: 1,
            batch_runs: 1,
            max_runs: 1,
        },
        vec![lane("a", 0), lane("a", 1)],
        || 0,
        |_| Ok(()),
        |_, _, _| Ok(CampaignTerminal::Success),
    );
    assert_eq!(
        duplicate_lanes,
        Err(SoakError::DuplicateLane("a".to_owned()))
    );

    let seed_overflow = SoakRunner::run(
        SoakConfig {
            wall_budget_millis: 1,
            jobs: 1,
            batch_runs: 1,
            max_runs: 1,
        },
        vec![lane("a", u64::MAX)],
        || 0,
        |_| Ok(()),
        |_, _, _| Ok(CampaignTerminal::Success),
    );
    assert_eq!(seed_overflow, Err(SoakError::SeedOverflow));

    let checkpoint = SoakRunner::run(
        SoakConfig {
            wall_budget_millis: 1,
            jobs: 1,
            batch_runs: 1,
            max_runs: 1,
        },
        vec![lane("a", 0)],
        || 0,
        |_| Err("disk full".to_owned()),
        |_, _, _| Ok(CampaignTerminal::Success),
    );
    assert_eq!(
        checkpoint,
        Err(SoakError::Checkpoint("disk full".to_owned()))
    );
}

#[test]
fn soak_plan_is_strict_ordered_and_seed_windows_do_not_overlap() {
    let valid = br#"{
      "schema_version": 2,
      "id": "fixture",
      "coverage_policy": "iroh-sim/coverage-policy.json",
      "coverage_policy_blake3": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "lanes": [
        {
          "id": "direct/deterministic-test",
          "swarm": "iroh-sim/swarms/direct-smoke.json",
          "swarm_blake3": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "crypto": "deterministic_test"
        },
        {
          "id": "direct/production-provider",
          "swarm": "iroh-sim/swarms/direct-smoke.json",
          "swarm_blake3": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "crypto": "production_provider"
        }
      ]
    }"#;
    let plan = SoakPlan::from_json(valid).unwrap();
    assert_eq!(plan.lanes[0].crypto, SoakCryptoLane::DeterministicTest);
    assert_eq!(
        derive_soak_seed_start(7, 0, 0).unwrap() + 1_000_000,
        derive_soak_seed_start(7, 0, 1).unwrap()
    );
    assert!(derive_soak_seed_start(7, 0, 31).unwrap() < derive_soak_seed_start(7, 1, 0).unwrap());

    let unknown_field = valid
        .strip_suffix(b"\n    }")
        .unwrap()
        .iter()
        .copied()
        .chain(br#", "unexpected": true }"#.iter().copied())
        .collect::<Vec<_>>();
    assert!(matches!(
        SoakPlan::from_json(&unknown_field),
        Err(SoakPlanError::Encoding(_))
    ));

    let out_of_order = String::from_utf8(valid.to_vec())
        .unwrap()
        .replace("direct/deterministic-test", "z-direct/deterministic-test");
    assert_eq!(
        SoakPlan::from_json(out_of_order.as_bytes()),
        Err(SoakPlanError::NonCanonicalLaneOrder)
    );
}

#[test]
fn seed_leases_are_policy_bound_disjoint_and_consumption_bounded() {
    let first = SeedLease::reserve(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "direct/deterministic-test",
        7,
        0,
        0,
    )
    .unwrap();
    let second = SeedLease::reserve(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "direct/production-provider",
        7,
        0,
        1,
    )
    .unwrap();

    assert!(!first.overlaps(&second));
    assert_eq!(first.seed_end_exclusive - first.seed_start, 1_000_000);
    assert_eq!(
        first.clone().with_consumed_runs(10).unwrap().consumed_runs,
        10
    );
    assert_eq!(
        first.with_consumed_runs(1_000_001),
        Err(SeedLeaseError::ConsumptionExceedsReservation {
            consumed: 1_000_001,
            reserved: 1_000_000,
        })
    );
}
