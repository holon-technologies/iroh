mod support;

use support::{DeterminismGrade, OperationsPolicy, OperationsPolicyError};

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
    assert_eq!(policy.tiers[0].maximum_campaign_runs, 24);
    assert_eq!(policy.tiers[0].maximum_wall_minutes, 15);
    assert_eq!(policy.tiers[1].maximum_campaign_runs, 64);
    assert_eq!(policy.tiers[1].maximum_wall_minutes, 30);
    assert_eq!(policy.daily_soak.workflow_concurrency, 1);
    assert_eq!(policy.daily_soak.epochs, 8);
    assert_eq!(policy.daily_soak.epoch_wall_minutes, 30);
    assert_eq!(policy.daily_soak.maximum_total_runs, 1_000_000);
    assert_eq!(policy.daily_soak.maximum_failure_artifacts, 16);
    assert!(policy.corpus.issue_required_for_failures);
    assert_eq!(policy.corpus.metadata_schema, 2);
    assert!(policy.corpus.typed_promotion_evidence_required);
    assert!(policy.corpus.reopen_invalid_closure);
    assert_eq!(
        policy.corpus.required_closure_checks,
        [
            "Deterministic simulation change gate",
            "Deterministic simulation contracts and corpus"
        ]
    );
    assert_eq!(
        policy.release.required_same_revision_checks,
        [
            "Deterministic simulation change gate",
            "Deterministic simulation contracts and corpus",
            "netsim-release / Netsim"
        ]
    );
    assert_eq!(policy.release.maximum_open_product_failures, 0);
    assert_eq!(policy.release.maximum_check_runs, 100);
    assert_eq!(policy.release.maximum_issue_results, 100);
    assert_eq!(policy.release.maximum_parity_runs, 8);
    assert_eq!(policy.release.parity_workflow, "patchbay-hosted-smoke.yml");
    assert_eq!(
        policy.release.maximum_parity_age_hours,
        policy.parity.maximum_evidence_age_hours
    );
    assert_eq!(policy.gate_runtime_slo.workflow, "ci.yml");
    assert_eq!(policy.gate_runtime_slo.sample_size, 20);
    assert_eq!(policy.gate_runtime_slo.percentile, 95);
    assert_eq!(policy.gate_runtime_slo.pull_request_maximum_minutes, 15);
    assert_eq!(policy.gate_runtime_slo.main_maximum_minutes, 30);
    assert_eq!(policy.gate_runtime_slo.maximum_candidate_runs_per_tier, 40);
    assert_eq!(policy.gate_runtime_slo.maximum_jobs_per_run, 100);
    assert_eq!(policy.automation.maximum_retry_attempts, 0);
    assert!(policy.automation.shutdown_on_timeout);
    assert!(policy.automation.publish_evidence_before_status);
    assert_eq!(
        policy.daily_soak.maximum_artifact_bytes,
        256 * 1_024 * 1_024
    );
}

#[test]
fn operations_policy_rejects_hidden_retries_or_unbounded_shutdown() {
    let policy = OperationsPolicy::from_json(include_bytes!("../operations-policy.json")).unwrap();

    for unsafe_policy in [
        {
            let mut candidate = policy.clone();
            candidate.automation.maximum_retry_attempts = 1;
            candidate
        },
        {
            let mut candidate = policy.clone();
            candidate.automation.shutdown_on_timeout = false;
            candidate
        },
        {
            let mut candidate = policy;
            candidate.automation.publish_evidence_before_status = false;
            candidate
        },
    ] {
        assert_eq!(
            unsafe_policy.validate(),
            Err(OperationsPolicyError::UnsafeAutomationPolicy)
        );
    }
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

#[test]
fn operations_policy_rejects_weak_corpus_closure_rules() {
    let policy = OperationsPolicy::from_json(include_bytes!("../operations-policy.json")).unwrap();

    for unsafe_policy in [
        {
            let mut candidate = policy.clone();
            candidate.corpus.typed_promotion_evidence_required = false;
            candidate
        },
        {
            let mut candidate = policy.clone();
            candidate.corpus.reopen_invalid_closure = false;
            candidate
        },
        {
            let mut candidate = policy.clone();
            candidate.corpus.required_closure_checks.pop();
            candidate
        },
        {
            let mut candidate = policy;
            candidate.corpus.metadata_schema -= 1;
            candidate
        },
    ] {
        assert_eq!(
            unsafe_policy.validate(),
            Err(OperationsPolicyError::UnsafeCorpusPolicy)
        );
    }
}

#[test]
fn operations_policy_rejects_weak_release_evidence_rules() {
    let policy = OperationsPolicy::from_json(include_bytes!("../operations-policy.json")).unwrap();

    for unsafe_policy in [
        {
            let mut candidate = policy.clone();
            candidate.release.required_same_revision_checks.pop();
            candidate
        },
        {
            let mut candidate = policy.clone();
            candidate.release.maximum_open_product_failures = 1;
            candidate
        },
        {
            let mut candidate = policy.clone();
            candidate.release.maximum_parity_age_hours += 1;
            candidate
        },
        {
            let mut candidate = policy;
            candidate.release.maximum_check_runs += 1;
            candidate
        },
    ] {
        assert_eq!(
            unsafe_policy.validate(),
            Err(OperationsPolicyError::UnsafeReleasePolicy)
        );
    }
}

#[test]
fn operations_policy_rejects_weak_gate_runtime_slo_rules() {
    let policy = OperationsPolicy::from_json(include_bytes!("../operations-policy.json")).unwrap();

    for unsafe_policy in [
        {
            let mut candidate = policy.clone();
            candidate.gate_runtime_slo.sample_size -= 1;
            candidate
        },
        {
            let mut candidate = policy.clone();
            candidate.gate_runtime_slo.percentile -= 1;
            candidate
        },
        {
            let mut candidate = policy.clone();
            candidate.gate_runtime_slo.pull_request_maximum_minutes += 1;
            candidate
        },
        {
            let mut candidate = policy;
            candidate.gate_runtime_slo.maximum_candidate_runs_per_tier += 1;
            candidate
        },
    ] {
        assert_eq!(
            unsafe_policy.validate(),
            Err(OperationsPolicyError::UnsafeGateRuntimeSloPolicy)
        );
    }
}
