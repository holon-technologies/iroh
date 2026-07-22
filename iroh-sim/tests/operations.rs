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
