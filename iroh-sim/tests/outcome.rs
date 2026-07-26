use iroh_sim::{OPERATIONAL_OUTCOME_SCHEMA_VERSION, OperationalOutcome, OperationalOutcomeClass};

#[test]
fn operational_outcomes_have_distinct_automation_semantics() {
    let product =
        OperationalOutcome::new(OperationalOutcomeClass::ProductCorrectness, "signature-a")
            .unwrap();
    assert!(product.issue_eligible());
    assert!(product.requires_exact_replay());

    for class in [
        OperationalOutcomeClass::Infrastructure,
        OperationalOutcomeClass::ExpectedResourceExhaustion,
        OperationalOutcomeClass::Determinism,
        OperationalOutcomeClass::Performance,
    ] {
        let outcome = OperationalOutcome::new(class, "typed evidence").unwrap();
        assert!(!outcome.issue_eligible());
    }
}

#[test]
fn operational_outcome_rejects_empty_or_unbounded_evidence() {
    assert!(OperationalOutcome::new(OperationalOutcomeClass::Infrastructure, "").is_err());
    assert!(
        OperationalOutcome::new(OperationalOutcomeClass::Infrastructure, "x".repeat(4_097),)
            .is_err()
    );
}

#[test]
fn operational_outcome_has_a_strict_versioned_wire_contract() {
    let outcome = OperationalOutcome::new(
        OperationalOutcomeClass::ProductCorrectness,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .unwrap();
    let encoded = outcome.to_canonical_json().unwrap();
    let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();

    assert_eq!(value["schema_version"], OPERATIONAL_OUTCOME_SCHEMA_VERSION);
    assert_eq!(value["class"], "product_correctness");
    assert_eq!(OperationalOutcome::from_json(&encoded).unwrap(), outcome);

    let mut malformed = value;
    malformed["schema_version"] = serde_json::json!(u16::MAX);
    assert!(
        OperationalOutcome::from_json(&serde_json::to_vec(&malformed).unwrap()).is_err(),
        "unknown operational-outcome schemas must fail closed"
    );
}
