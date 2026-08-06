use krikos_identity::{
    AccountId, AccountOperation, AdmissionEvidence, AlgorithmSignature, CanonicalWire,
    CheckpointId, ControllerApprovalBody, ControllerApprovals, ControllerId, ControllerKeyId,
    CryptoSuiteId, Digest, Epoch, EventBody, EventId, EventPredecessors, Extensions,
    FreshnessEvidence, HashAlgorithm, IdentityError, KeyedSignature, ProposalId, ProviderPolicy,
    ProviderPolicyId, ProviderPolicyVersion, Sequence, SignedControllerApproval, Timestamp,
};

fn typed_id<T: CanonicalWire>(fill: u8) -> T {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [fill; 32]);
    T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
}

fn body() -> EventBody {
    EventBody::new(
        typed_id::<AccountId>(1),
        Sequence::new(1),
        Epoch::new(1),
        EventPredecessors::genesis(typed_id(2)),
        AccountOperation::ChangeProviderPolicy(
            ProviderPolicy::local_only(ProviderPolicyVersion::new(1), Extensions::default())
                .unwrap(),
        ),
        Timestamp::from_unix_millis(3),
        [4; 16],
        Extensions::default(),
    )
    .unwrap()
}

#[test]
fn event_body_intent_and_admitted_event_have_distinct_stable_domains() {
    let body = body();
    let proposal_id = body.proposal_id().unwrap();
    let checkpoint_id = typed_id::<CheckpointId>(5);
    let evidence = AdmissionEvidence::new(
        proposal_id,
        checkpoint_id,
        typed_id::<ProviderPolicyId>(6),
        FreshnessEvidence::local_known(checkpoint_id),
        krikos_identity::DelayEvidence::none(),
        Extensions::default(),
    )
    .unwrap();
    let event_id = evidence.event_id_for_body(&body).unwrap();
    assert_eq!(
        hex::encode(body.to_canonical_bytes().unwrap()),
        "010101010101010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020c0101010000030404040404040404040404040404040400"
    );
    assert_eq!(
        proposal_id.to_string(),
        "b3:e70c3c5bb4f72daaa52f5f4ad31e7c4dee4e94f1cafd40563c51a92ababa2da0"
    );
    assert_eq!(
        event_id.to_string(),
        "b3:b35f2d617ddaff7c1833c33098da212cc47a52dc06453a4fa7f1bcb0be59b4ff"
    );
    assert_ne!(proposal_id.as_digest(), event_id.as_digest());
    assert_eq!(body.operation().kind().code(), 12);
    assert_eq!(
        EventBody::from_canonical_bytes(&body.to_canonical_bytes().unwrap()).unwrap(),
        body
    );
}

#[test]
fn event_predecessor_heads_are_complete_sorted_and_unique() {
    let first = typed_id::<EventId>(1);
    let second = typed_id::<EventId>(2);
    let heads = EventPredecessors::events(vec![second, first]).unwrap();
    assert_eq!(heads.event_heads().unwrap(), &[first, second]);
    assert!(matches!(
        EventPredecessors::events(vec![]),
        Err(IdentityError::EmptyCollection { .. })
    ));
    assert!(matches!(
        EventPredecessors::events(vec![first, first]),
        Err(IdentityError::DuplicateElement { .. })
    ));
    let unsorted = postcard::to_stdvec(&(2_u16, vec![second, first])).unwrap();
    assert!(matches!(
        EventPredecessors::from_canonical_bytes(&unsorted),
        Err(IdentityError::NonCanonical)
    ));
}

#[test]
fn event_operation_registry_rejects_reserved_and_unknown_codes() {
    let operation = AccountOperation::ChangeProviderPolicy(
        ProviderPolicy::local_only(ProviderPolicyVersion::new(1), Extensions::default()).unwrap(),
    );
    let bytes = operation.to_canonical_bytes().unwrap();
    assert_eq!(bytes[0], 12);
    assert_eq!(
        AccountOperation::from_canonical_bytes(&bytes).unwrap(),
        operation
    );
    assert!(matches!(
        AccountOperation::from_canonical_bytes(&[23]),
        Err(IdentityError::ReservedCodepoint { code: 23, .. })
    ));
    assert!(matches!(
        AccountOperation::from_canonical_bytes(&[24]),
        Err(IdentityError::UnsupportedCodepoint { code: 24, .. })
    ));
}

#[test]
fn authorized_event_binds_body_admission_and_every_approval() {
    let body = body();
    let proposal_id = body.proposal_id().unwrap();
    let checkpoint_id = typed_id::<CheckpointId>(5);
    let provider_policy_id = typed_id::<ProviderPolicyId>(6);
    let evidence = AdmissionEvidence::new(
        proposal_id,
        checkpoint_id,
        provider_policy_id,
        FreshnessEvidence::local_known(checkpoint_id),
        krikos_identity::DelayEvidence::none(),
        Extensions::default(),
    )
    .unwrap();
    let evidence_id = evidence.admission_evidence_id().unwrap();
    let event_id = evidence.event_id_for_body(&body).unwrap();
    let approval = SignedControllerApproval::new(
        ControllerApprovalBody::event(
            typed_id::<ControllerId>(7),
            event_id,
            evidence_id,
            Extensions::default(),
        )
        .unwrap(),
        vec![KeyedSignature::new(
            typed_id::<CryptoSuiteId>(8),
            typed_id::<ControllerKeyId>(9),
            AlgorithmSignature::new(1, vec![10; 64]).unwrap(),
        )],
    )
    .unwrap();
    let approvals = ControllerApprovals::new(vec![approval]).unwrap();
    let authorized =
        krikos_identity::AuthorizedEvent::new(body.clone(), evidence, approvals).unwrap();
    assert_eq!(authorized.event_id().unwrap(), event_id);
    assert_eq!(
        krikos_identity::AuthorizedEvent::from_canonical_bytes(
            &authorized.to_canonical_bytes().unwrap()
        )
        .unwrap(),
        authorized
    );

    let wrong_event = typed_id::<EventId>(11);
    let wrong_evidence = AdmissionEvidence::new(
        typed_id::<ProposalId>(12),
        checkpoint_id,
        provider_policy_id,
        FreshnessEvidence::local_known(checkpoint_id),
        krikos_identity::DelayEvidence::none(),
        Extensions::default(),
    )
    .unwrap();
    let wrong_approval = SignedControllerApproval::new(
        ControllerApprovalBody::event(
            typed_id::<ControllerId>(7),
            wrong_event,
            wrong_evidence.admission_evidence_id().unwrap(),
            Extensions::default(),
        )
        .unwrap(),
        vec![KeyedSignature::new(
            typed_id::<CryptoSuiteId>(8),
            typed_id::<ControllerKeyId>(9),
            AlgorithmSignature::new(1, vec![10; 64]).unwrap(),
        )],
    )
    .unwrap();
    assert!(matches!(
        krikos_identity::AuthorizedEvent::new(
            body,
            wrong_evidence,
            ControllerApprovals::new(vec![wrong_approval]).unwrap(),
        ),
        Err(IdentityError::InvalidRelationship { .. })
    ));
}
