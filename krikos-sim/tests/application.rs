use krikos_sim::model::{
    ApplicationError, ApplicationModel, ApplicationModelConfig, ApplicationOperation,
    ApplicationScenario, Capability, DeliveryFault, DocumentId, NodeId,
};
use proptest::prelude::*;

fn node(value: &str) -> NodeId {
    NodeId::new(value).unwrap()
}

fn document(value: &str) -> DocumentId {
    DocumentId::new(value).unwrap()
}

fn scenario(operations: Vec<ApplicationOperation>) -> ApplicationScenario {
    ApplicationScenario {
        seed: 42,
        candidate_sha: "0123456789abcdef".to_owned(),
        artifact_version: 1,
        operations,
    }
}

#[test]
fn authorized_histories_converge_after_partition_duplicate_and_reorder() {
    let alice = node("alice");
    let bob = node("bob");
    let notes = document("notes");
    let mut model = ApplicationModel::new(ApplicationModelConfig::default()).unwrap();
    let run = model
        .run(&scenario(vec![
            ApplicationOperation::StartNode {
                node: alice.clone(),
            },
            ApplicationOperation::StartNode { node: bob.clone() },
            ApplicationOperation::CreateDocument {
                node: alice.clone(),
                document: notes.clone(),
            },
            ApplicationOperation::AddBlob {
                node: alice.clone(),
                bytes: b"one".to_vec(),
            },
            ApplicationOperation::Write {
                node: alice.clone(),
                document: notes.clone(),
                key: b"note".to_vec(),
                blob: ApplicationModel::hash(b"one"),
            },
            ApplicationOperation::Share {
                from: alice.clone(),
                to: bob.clone(),
                document: notes.clone(),
                capability: Capability::Read,
            },
            ApplicationOperation::Partition {
                left: alice.clone(),
                right: bob.clone(),
            },
            ApplicationOperation::DuplicateNext,
            ApplicationOperation::ReorderNext,
            ApplicationOperation::Synchronize {
                left: alice.clone(),
                right: bob.clone(),
                document: notes.clone(),
            },
            ApplicationOperation::Heal {
                left: alice.clone(),
                right: bob.clone(),
            },
            ApplicationOperation::DeliverAll,
        ]))
        .unwrap();

    assert_eq!(run.seed, 42);
    assert_eq!(run.candidate_sha, "0123456789abcdef");
    assert!(run.trace.len() <= ApplicationModelConfig::default().max_trace_events);
    model.assert_invariants().unwrap();
    assert_eq!(
        model.entry(&alice, &notes, b"note"),
        model.entry(&bob, &notes, b"note")
    );
    assert_eq!(
        model.blob(&bob, ApplicationModel::hash(b"one")),
        Some(&b"one"[..])
    );
}

#[test]
fn read_capability_cannot_escalate_and_disk_failure_preserves_state() {
    let alice = node("alice");
    let bob = node("bob");
    let notes = document("notes");
    let mut model = ApplicationModel::new(ApplicationModelConfig::default()).unwrap();
    model
        .run(&scenario(vec![
            ApplicationOperation::StartNode {
                node: alice.clone(),
            },
            ApplicationOperation::StartNode { node: bob.clone() },
            ApplicationOperation::CreateDocument {
                node: alice.clone(),
                document: notes.clone(),
            },
            ApplicationOperation::Share {
                from: alice,
                to: bob.clone(),
                document: notes.clone(),
                capability: Capability::Read,
            },
            ApplicationOperation::DeliverAll,
        ]))
        .unwrap();

    let before = model.snapshot();
    assert_eq!(
        model.apply(ApplicationOperation::Write {
            node: bob.clone(),
            document: notes.clone(),
            key: b"forbidden".to_vec(),
            blob: ApplicationModel::hash(b"missing"),
        }),
        Err(ApplicationError::WriteCapabilityRequired)
    );
    assert_eq!(before, model.snapshot());

    model
        .apply(ApplicationOperation::SetStorageFault {
            node: bob.clone(),
            enabled: true,
        })
        .unwrap();
    let before_faulted_add = model.snapshot();
    assert_eq!(
        model.apply(ApplicationOperation::AddBlob {
            node: bob,
            bytes: b"must-not-commit".to_vec(),
        }),
        Err(ApplicationError::StorageUnavailable)
    );
    assert_eq!(before_faulted_add, model.snapshot());
}

#[test]
fn restart_retains_identity_and_gc_only_collects_unreachable_content() {
    let alice = node("alice");
    let notes = document("notes");
    let live = ApplicationModel::hash(b"live");
    let garbage = ApplicationModel::hash(b"garbage");
    let mut model = ApplicationModel::new(ApplicationModelConfig::default()).unwrap();
    model
        .run(&scenario(vec![
            ApplicationOperation::StartNode {
                node: alice.clone(),
            },
            ApplicationOperation::CreateDocument {
                node: alice.clone(),
                document: notes.clone(),
            },
            ApplicationOperation::AddBlob {
                node: alice.clone(),
                bytes: b"live".to_vec(),
            },
            ApplicationOperation::AddBlob {
                node: alice.clone(),
                bytes: b"garbage".to_vec(),
            },
            ApplicationOperation::Write {
                node: alice.clone(),
                document: notes,
                key: b"note".to_vec(),
                blob: live,
            },
        ]))
        .unwrap();
    let identity = model.identity(&alice).unwrap().to_owned();

    model
        .apply(ApplicationOperation::StopNode {
            node: alice.clone(),
        })
        .unwrap();
    model
        .apply(ApplicationOperation::RestartNode {
            node: alice.clone(),
        })
        .unwrap();
    model
        .apply(ApplicationOperation::CollectGarbage {
            node: alice.clone(),
        })
        .unwrap();

    assert_eq!(model.identity(&alice), Some(identity.as_str()));
    assert!(model.blob(&alice, live).is_some());
    assert!(model.blob(&alice, garbage).is_none());
    model.assert_invariants().unwrap();
}

#[test]
fn delivery_and_trace_bounds_fail_closed() {
    let config = ApplicationModelConfig {
        max_pending_messages: 1,
        max_trace_events: 2,
        ..ApplicationModelConfig::default()
    };
    let alice = node("alice");
    let bob = node("bob");
    let mut model = ApplicationModel::new(config).unwrap();
    model
        .apply(ApplicationOperation::StartNode {
            node: alice.clone(),
        })
        .unwrap();
    model
        .apply(ApplicationOperation::StartNode { node: bob.clone() })
        .unwrap();
    assert_eq!(
        model.apply(ApplicationOperation::SetDeliveryFault {
            fault: DeliveryFault::Drop,
        }),
        Err(ApplicationError::TraceLimit)
    );
}

#[test]
fn conflicting_authorized_writes_converge_deterministically() {
    let alice = node("alice");
    let bob = node("bob");
    let notes = document("notes");
    let mut model = ApplicationModel::new(ApplicationModelConfig::default()).unwrap();
    for operation in [
        ApplicationOperation::StartNode {
            node: alice.clone(),
        },
        ApplicationOperation::StartNode { node: bob.clone() },
        ApplicationOperation::CreateDocument {
            node: alice.clone(),
            document: notes.clone(),
        },
        ApplicationOperation::Share {
            from: alice.clone(),
            to: bob.clone(),
            document: notes.clone(),
            capability: Capability::Write,
        },
        ApplicationOperation::DeliverAll,
        ApplicationOperation::AddBlob {
            node: alice.clone(),
            bytes: b"alice".to_vec(),
        },
        ApplicationOperation::AddBlob {
            node: bob.clone(),
            bytes: b"bob".to_vec(),
        },
        ApplicationOperation::Write {
            node: alice.clone(),
            document: notes.clone(),
            key: b"same-key".to_vec(),
            blob: ApplicationModel::hash(b"alice"),
        },
        ApplicationOperation::Write {
            node: bob.clone(),
            document: notes.clone(),
            key: b"same-key".to_vec(),
            blob: ApplicationModel::hash(b"bob"),
        },
        ApplicationOperation::Synchronize {
            left: alice.clone(),
            right: bob.clone(),
            document: notes.clone(),
        },
        ApplicationOperation::DeliverAll,
    ] {
        model.apply(operation).unwrap();
    }

    assert_eq!(
        model.entry(&alice, &notes, b"same-key"),
        model.entry(&bob, &notes, b"same-key")
    );
    let winning_hash = model
        .entry(&alice, &notes, b"same-key")
        .expect("entry exists")
        .blob;
    assert_eq!(
        model.blob(&alice, winning_hash),
        model.blob(&bob, winning_hash)
    );
    model.assert_invariants().unwrap();
}

#[test]
fn missing_blob_and_interrupted_sync_are_recoverable() {
    let alice = node("alice");
    let bob = node("bob");
    let notes = document("notes");
    let missing = ApplicationModel::hash(b"not-stored");
    let mut model = ApplicationModel::new(ApplicationModelConfig::default()).unwrap();
    for operation in [
        ApplicationOperation::StartNode {
            node: alice.clone(),
        },
        ApplicationOperation::StartNode { node: bob.clone() },
        ApplicationOperation::CreateDocument {
            node: alice.clone(),
            document: notes.clone(),
        },
    ] {
        model.apply(operation).unwrap();
    }
    let before_fetch = model.snapshot();
    assert_eq!(
        model.apply(ApplicationOperation::FetchBlob {
            from: alice.clone(),
            to: bob.clone(),
            blob: missing,
        }),
        Err(ApplicationError::BlobMissing)
    );
    assert_eq!(before_fetch, model.snapshot());

    for operation in [
        ApplicationOperation::AddBlob {
            node: alice.clone(),
            bytes: b"after-restart".to_vec(),
        },
        ApplicationOperation::Write {
            node: alice.clone(),
            document: notes.clone(),
            key: b"note".to_vec(),
            blob: ApplicationModel::hash(b"after-restart"),
        },
        ApplicationOperation::Share {
            from: alice.clone(),
            to: bob.clone(),
            document: notes.clone(),
            capability: Capability::Read,
        },
        ApplicationOperation::Partition {
            left: alice.clone(),
            right: bob.clone(),
        },
        ApplicationOperation::DeliverAll,
        ApplicationOperation::StopNode { node: bob.clone() },
        ApplicationOperation::RestartNode { node: bob.clone() },
        ApplicationOperation::Heal {
            left: alice.clone(),
            right: bob.clone(),
        },
        ApplicationOperation::DeliverAll,
    ] {
        model.apply(operation).unwrap();
    }
    assert_eq!(
        model.blob(&bob, ApplicationModel::hash(b"after-restart")),
        Some(&b"after-restart"[..])
    );
}

#[test]
fn checked_fixture_replays_with_identity_metadata() {
    let scenario: ApplicationScenario = serde_json::from_slice(include_bytes!(
        "fixtures/application-partition-restart.json"
    ))
    .unwrap();
    let mut model = ApplicationModel::new(ApplicationModelConfig::default()).unwrap();
    let run = model.run(&scenario).unwrap();
    assert_eq!(run.seed, 7_771);
    assert_eq!(run.artifact_version, 1);
    assert_eq!(run.trace.len(), scenario.operations.len());
    model.assert_invariants().unwrap();
}

proptest! {
    #[test]
    fn randomized_fault_sequences_are_atomic_and_bounded(choices in prop::collection::vec(any::<u8>(), 0..256)) {
        let alice = node("alice");
        let bob = node("bob");
        let notes = document("notes");
        let mut model = ApplicationModel::new(ApplicationModelConfig::default()).unwrap();
        for operation in [
            ApplicationOperation::StartNode { node: alice.clone() },
            ApplicationOperation::StartNode { node: bob.clone() },
            ApplicationOperation::CreateDocument {
                node: alice.clone(),
                document: notes.clone(),
            },
            ApplicationOperation::Share {
                from: alice.clone(),
                to: bob.clone(),
                document: notes.clone(),
                capability: Capability::Read,
            },
            ApplicationOperation::DeliverAll,
        ] {
            model.apply(operation).unwrap();
        }

        for choice in choices {
            let operation = match choice % 12 {
                0 => ApplicationOperation::AddBlob {
                    node: alice.clone(),
                    bytes: vec![choice],
                },
                1 => ApplicationOperation::Write {
                    node: alice.clone(),
                    document: notes.clone(),
                    key: vec![b'k', choice],
                    blob: ApplicationModel::hash(&[choice]),
                },
                2 => ApplicationOperation::Partition {
                    left: alice.clone(),
                    right: bob.clone(),
                },
                3 => ApplicationOperation::Heal {
                    left: alice.clone(),
                    right: bob.clone(),
                },
                4 => ApplicationOperation::Synchronize {
                    left: alice.clone(),
                    right: bob.clone(),
                    document: notes.clone(),
                },
                5 => ApplicationOperation::DeliverAll,
                6 => ApplicationOperation::DuplicateNext,
                7 => ApplicationOperation::ReorderNext,
                8 => ApplicationOperation::DropNext,
                9 => ApplicationOperation::SetStorageFault {
                    node: bob.clone(),
                    enabled: choice & 1 == 0,
                },
                10 => ApplicationOperation::CollectGarbage {
                    node: alice.clone(),
                },
                _ => ApplicationOperation::Migrate {
                    node: alice.clone(),
                    target_schema: 1,
                },
            };
            let before = model.snapshot();
            if model.apply(operation).is_err() {
                prop_assert_eq!(before, model.snapshot());
            }
            model.assert_invariants().unwrap();
        }
    }
}
