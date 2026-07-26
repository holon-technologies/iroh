use iroh_sim::{ChangeImpactPolicy, GateSelection, GateSelectionMode, SimulationGateTier};

const COVERAGE_POLICY_BLAKE3: &str =
    "03cedfb477850423191b22663090d6d49bc8a4276b56c16ec018c6567e36a9a0";
const BASE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CANDIDATE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn policy() -> ChangeImpactPolicy {
    ChangeImpactPolicy::from_json(include_bytes!("../change-impact-policy.json")).unwrap()
}

#[test]
fn checked_change_impact_policy_is_canonical_and_bounded() {
    let bytes = include_bytes!("../change-impact-policy.json");
    let policy = ChangeImpactPolicy::from_json(bytes).unwrap();
    assert_eq!(policy.to_canonical_json().unwrap(), bytes);
    assert_eq!(policy.domains.len(), 6);
    assert_eq!(policy.tiers[0].maximum_total_runs, 24);
    assert_eq!(policy.tiers[1].maximum_total_runs, 64);
}

#[test]
fn selection_is_stable_and_universal_canary_is_independent_of_impact() {
    let first = GateSelection::build(
        &policy(),
        COVERAGE_POLICY_BLAKE3,
        Some(BASE),
        CANDIDATE,
        SimulationGateTier::PullRequest,
        &["docs/testing/simulation.md".to_owned()],
        true,
    )
    .unwrap();
    let second = GateSelection::build(
        &policy(),
        COVERAGE_POLICY_BLAKE3,
        Some(BASE),
        CANDIDATE,
        SimulationGateTier::PullRequest,
        &["docs/testing/simulation.md".to_owned()],
        true,
    )
    .unwrap();

    assert_eq!(first, second);
    assert_eq!(first.universal.len(), 12);
    assert!(first.targeted.is_empty());
    assert_eq!(
        first.to_canonical_json().unwrap(),
        second.to_canonical_json().unwrap()
    );
}

#[test]
fn mapped_changes_select_only_owned_domains_for_both_providers() {
    let selection = GateSelection::build(
        &policy(),
        COVERAGE_POLICY_BLAKE3,
        Some(BASE),
        CANDIDATE,
        SimulationGateTier::PullRequest,
        &["iroh/src/discovery/pkarr.rs".to_owned()],
        true,
    )
    .unwrap();

    assert_eq!(selection.mode, GateSelectionMode::Mapped);
    assert_eq!(selection.impacted_domains, ["discovery"]);
    assert_eq!(selection.targeted.len(), 2);
    assert!(
        selection
            .targeted
            .iter()
            .all(|work| work.domain == "discovery")
    );
}

#[test]
fn unknown_or_unavailable_diff_falls_back_to_every_domain() {
    for (paths, diff_available) in [
        (vec!["new-crate/src/lib.rs".to_owned()], true),
        (Vec::new(), false),
    ] {
        let selection = GateSelection::build(
            &policy(),
            COVERAGE_POLICY_BLAKE3,
            Some(BASE),
            CANDIDATE,
            SimulationGateTier::PullRequest,
            &paths,
            diff_available,
        )
        .unwrap();
        assert_eq!(selection.mode, GateSelectionMode::GlobalFallback);
        assert_eq!(selection.impacted_domains.len(), 6);
        assert_eq!(selection.targeted.len(), 12);
        assert_eq!(selection.total_runs(), 24);
    }
}

#[test]
fn identical_revisions_have_no_targeted_work_but_keep_canaries() {
    let selection = GateSelection::build(
        &policy(),
        COVERAGE_POLICY_BLAKE3,
        Some(CANDIDATE),
        CANDIDATE,
        SimulationGateTier::Main,
        &[],
        true,
    )
    .unwrap();

    assert_eq!(selection.mode, GateSelectionMode::Mapped);
    assert!(selection.impacted_domains.is_empty());
    assert_eq!(selection.universal.len(), 12);
    assert!(selection.targeted.is_empty());
}
