use iroh_sim::{DeterminismGrade, OperationsPolicy, OperationsPolicyError};

#[test]
fn checked_operations_policy_is_canonical_and_safe() {
    let bytes = include_bytes!("../operations-policy.json");
    let policy = OperationsPolicy::from_json(bytes).unwrap();
    assert_eq!(policy.to_canonical_json().unwrap(), bytes);
    assert!(policy.replay.exact_source_required);
    assert_eq!(
        policy.replay.accepted_new_run_grades,
        [
            DeterminismGrade::FullyDeterministic,
            DeterminismGrade::SemanticallyDeterministic
        ]
    );
    assert_eq!(policy.tiers.last().unwrap().maximum_campaign_runs, 1024);
    assert_eq!(policy.daily_soak.workflow_concurrency, 1);
    assert_eq!(policy.daily_soak.epochs, 8);
    assert_eq!(policy.daily_soak.epoch_wall_minutes, 30);
    assert_eq!(policy.daily_soak.maximum_total_runs, 1_000_000);
    assert_eq!(policy.daily_soak.maximum_failure_artifacts, 16);
    assert_eq!(
        policy.daily_soak.maximum_artifact_bytes,
        256 * 1_024 * 1_024
    );
}

#[test]
fn operations_policy_rejects_nonmonotonic_tiers_and_unsafe_replay() {
    let policy = OperationsPolicy::from_json(include_bytes!("../operations-policy.json")).unwrap();

    let mut nonmonotonic = policy.clone();
    nonmonotonic.tiers[2].maximum_campaign_runs = 1;
    assert!(matches!(
        nonmonotonic.validate(),
        Err(OperationsPolicyError::InvalidTier(_))
    ));

    let mut unsafe_replay = policy.clone();
    unsafe_replay.replay.exact_source_required = false;
    assert_eq!(
        unsafe_replay.validate(),
        Err(OperationsPolicyError::UnsafeReplayPolicy)
    );

    let mut legacy_grade = policy;
    legacy_grade.replay.accepted_new_run_grades = vec![DeterminismGrade::ControlledRuntime];
    assert_eq!(
        legacy_grade.validate(),
        Err(OperationsPolicyError::UnsafeReplayPolicy)
    );
}

#[test]
fn operations_policy_rejects_relaxed_daily_soak_bounds() {
    let policy = OperationsPolicy::from_json(include_bytes!("../operations-policy.json")).unwrap();

    for unsafe_policy in [
        {
            let mut candidate = policy.clone();
            candidate.daily_soak.workflow_concurrency = 2;
            candidate
        },
        {
            let mut candidate = policy.clone();
            candidate.daily_soak.workers = 8;
            candidate
        },
        {
            let mut candidate = policy.clone();
            candidate.daily_soak.maximum_artifact_bytes += 1;
            candidate
        },
        {
            let mut candidate = policy.clone();
            candidate.daily_soak.retain_success_traces = true;
            candidate
        },
    ] {
        assert_eq!(
            unsafe_policy.validate(),
            Err(OperationsPolicyError::UnsafeDailySoakPolicy)
        );
    }
}
