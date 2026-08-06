use krikos_identity::{
    AccountId, AdmissionEvidence, AdmissionEvidenceId, AlgorithmSignature, CanonicalWire,
    CheckpointId, ControllerApprovalBody, ControllerApprovals, ControllerId, ControllerKeyId,
    CryptoSuiteId, DelayEvidence, Digest, EventId, EventIntentApprovalBody, EventIntentApprovals,
    Extension, Extensions, FreshnessEvidence, HashAlgorithm, IdentityError, InclusionReceipt,
    KeyedSignature, ProposalId, ProtocolSignature, ProviderHeadBody, ProviderId,
    ProviderKeyVersion, ProviderLogEntryBody, ProviderLogId, ProviderLogSubject, ProviderPolicyId,
    ProviderQuorum, ProviderReceipts, SignedControllerApproval, SignedEventIntentApproval,
    SignedProviderHead, Timestamp,
};

fn typed_id<T: CanonicalWire>(fill: u8) -> T {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [fill; 32]);
    T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
}

fn unknown_critical_extensions() -> Extensions {
    Extensions::new(vec![Extension::new(65_535, true, vec![1]).unwrap()]).unwrap()
}

#[test]
fn approval_constructors_reject_unknown_critical_extensions() {
    assert!(matches!(
        EventIntentApprovalBody::new(typed_id(1), typed_id(2), unknown_critical_extensions(),),
        Err(IdentityError::UnknownCriticalExtension { code: 65_535 })
    ));
    assert!(matches!(
        ControllerApprovalBody::event(
            typed_id(1),
            typed_id(2),
            typed_id(3),
            unknown_critical_extensions(),
        ),
        Err(IdentityError::UnknownCriticalExtension { code: 65_535 })
    ));
    assert!(matches!(
        ControllerApprovalBody::checkpoint(typed_id(1), typed_id(2), unknown_critical_extensions(),),
        Err(IdentityError::UnknownCriticalExtension { code: 65_535 })
    ));
}

fn intent_receipt(
    provider_fill: u8,
    account_id: AccountId,
    proposal_id: ProposalId,
    observed_at: u64,
) -> InclusionReceipt {
    let provider_id = typed_id::<ProviderId>(provider_fill);
    let log_id = typed_id::<ProviderLogId>(provider_fill.wrapping_add(32));
    let entry = ProviderLogEntryBody::new(
        provider_id,
        log_id,
        account_id,
        ProviderLogSubject::EventIntent(proposal_id),
        Timestamp::from_unix_millis(observed_at),
        Extensions::default(),
    )
    .unwrap();
    let head = ProviderHeadBody::new(
        provider_id,
        log_id,
        ProviderKeyVersion::GENESIS,
        1,
        Digest::new(HashAlgorithm::Blake3_256, [provider_fill; 32]),
        Timestamp::from_unix_millis(observed_at + 1),
        Extensions::default(),
    )
    .unwrap();
    InclusionReceipt::new(
        entry,
        0,
        vec![],
        SignedProviderHead::new(head, ProtocolSignature::ed25519([provider_fill; 64])),
    )
    .unwrap()
}

#[test]
fn admission_and_approval_ids_exclude_signature_subsets() {
    let proposal_id: ProposalId = typed_id(1);
    let event_id: EventId = typed_id(2);
    let evidence = AdmissionEvidence::new(
        proposal_id,
        typed_id::<CheckpointId>(3),
        typed_id::<ProviderPolicyId>(4),
        FreshnessEvidence::local_known(typed_id(3)),
        DelayEvidence::none(),
        Extensions::default(),
    )
    .unwrap();
    let evidence_id: AdmissionEvidenceId = evidence.admission_evidence_id().unwrap();
    assert_eq!(
        hex::encode(evidence.to_canonical_bytes().unwrap()),
        "01010101010101010101010101010101010101010101010101010101010101010101010303030303030303030303030303030303030303030303030303030303030303010404040404040404040404040404040404040404040404040404040404040404010103030303030303030303030303030303030303030303030303030303030303030000"
    );
    assert_eq!(
        evidence_id.to_string(),
        "b3:dfbcc98e0ebe7d270a8d5095f4ca78ca5d566daf20b96563692f15189b682f40"
    );
    let body = ControllerApprovalBody::event(
        typed_id::<ControllerId>(5),
        event_id,
        evidence_id,
        Extensions::default(),
    )
    .unwrap();
    let approval_id = body.controller_approval_id().unwrap();
    assert_eq!(
        approval_id.to_string(),
        "b3:1b5ed735ed22133d37a57ab444766ce2ed29f1b7e3e37375f52ddaf34b1f43b4"
    );
    let one_signature = SignedControllerApproval::new(
        body.clone(),
        vec![KeyedSignature::new(
            typed_id::<CryptoSuiteId>(6),
            typed_id::<ControllerKeyId>(7),
            AlgorithmSignature::new(1, vec![8; 64]).unwrap(),
        )],
    )
    .unwrap();
    let two_signatures = SignedControllerApproval::new(
        body.clone(),
        vec![
            KeyedSignature::new(
                typed_id::<CryptoSuiteId>(6),
                typed_id::<ControllerKeyId>(7),
                AlgorithmSignature::new(1, vec![8; 64]).unwrap(),
            ),
            KeyedSignature::new(
                typed_id::<CryptoSuiteId>(9),
                typed_id::<ControllerKeyId>(10),
                AlgorithmSignature::new(2, vec![11; 96]).unwrap(),
            ),
        ],
    )
    .unwrap();

    assert_eq!(
        one_signature.merge(&two_signatures).unwrap(),
        two_signatures
    );
    assert_eq!(
        ControllerApprovals::new(vec![one_signature.clone()])
            .unwrap()
            .merge(&ControllerApprovals::new(vec![two_signatures.clone()]).unwrap())
            .unwrap()
            .as_slice(),
        std::slice::from_ref(&two_signatures)
    );
    let conflicting = SignedControllerApproval::new(
        body,
        vec![KeyedSignature::new(
            typed_id::<CryptoSuiteId>(6),
            typed_id::<ControllerKeyId>(7),
            AlgorithmSignature::new(1, vec![12; 64]).unwrap(),
        )],
    )
    .unwrap();
    assert!(matches!(
        one_signature.merge(&conflicting),
        Err(IdentityError::InvalidSignature)
    ));

    assert_ne!(
        one_signature.to_canonical_bytes().unwrap(),
        two_signatures.to_canonical_bytes().unwrap()
    );
    assert_eq!(
        one_signature.body().controller_approval_id().unwrap(),
        approval_id
    );
    assert_eq!(
        two_signatures.body().controller_approval_id().unwrap(),
        approval_id
    );
}

#[test]
fn admission_evidence_fuzz_seed_tracks_the_v1_wire() {
    let seed = include_bytes!("../../../fuzz/corpus/identity_schema/admission-evidence-v1");
    let (&selector, payload) = seed.split_first().unwrap();
    assert_eq!(selector, 43);
    let evidence = AdmissionEvidence::from_canonical_bytes(payload).unwrap();
    assert_eq!(evidence.to_canonical_bytes().unwrap(), payload);
}

#[test]
fn delayed_evidence_freezes_the_quorum_th_earliest_observation() {
    let account_id = typed_id::<AccountId>(20);
    let proposal_id = typed_id::<ProposalId>(21);
    let intent_body = EventIntentApprovalBody::new(
        typed_id::<ControllerId>(22),
        proposal_id,
        Extensions::default(),
    )
    .unwrap();
    let intent = SignedEventIntentApproval::new(
        intent_body,
        vec![KeyedSignature::new(
            typed_id::<CryptoSuiteId>(23),
            typed_id::<ControllerKeyId>(24),
            AlgorithmSignature::new(1, vec![25; 64]).unwrap(),
        )],
    )
    .unwrap();
    let approvals = EventIntentApprovals::new(vec![intent]).unwrap();
    let receipts = ProviderReceipts::new(vec![
        intent_receipt(3, account_id, proposal_id, 300),
        intent_receipt(1, account_id, proposal_id, 100),
        intent_receipt(2, account_id, proposal_id, 200),
    ])
    .unwrap();
    let evidence = DelayEvidence::provider_quorum(
        typed_id::<ProviderPolicyId>(26),
        ProviderQuorum::new(2).unwrap(),
        approvals.clone(),
        receipts.clone(),
    )
    .unwrap();
    assert_eq!(
        evidence.observed_at(),
        Some(Timestamp::from_unix_millis(200))
    );
    assert_eq!(
        DelayEvidence::from_canonical_bytes(&evidence.to_canonical_bytes().unwrap()).unwrap(),
        evidence
    );
    assert!(matches!(
        DelayEvidence::provider_quorum(
            typed_id::<ProviderPolicyId>(26),
            ProviderQuorum::new(4).unwrap(),
            approvals,
            receipts,
        ),
        Err(krikos_identity::IdentityError::UnsatisfiableThreshold)
    ));
}
