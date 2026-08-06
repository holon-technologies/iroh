use krikos_base::SecretKey;
use krikos_identity::{
    AccountGenesis, AccountOperation, AccountState, AlgorithmSignature, CanonicalWire,
    ControlPolicy, ControllerClass, ControllerDescriptor, ControllerKeyId, ControllerScope,
    ControllerSelector, ControllerThreshold, ControllerWeight, CryptoSuiteDescriptor, Digest,
    DurationMillis, EventBody, EventIntentApprovalBody, EventIntentApprovals, EventPredecessors,
    Extensions, FreshnessRequirement, HashAlgorithm, IdentityError, KeyedSignature,
    MemoryTransparencyLog, OperationKind, PolicyRule, ProtocolSignature, ProviderDescriptor,
    ProviderHeadSigner, ProviderLogId, ProviderLogSubject, ProviderPolicy, ProviderPolicyVersion,
    ProviderQuorum, RecoveryAuthority, RecoveryPolicy, RecoveryPolicyVersion, RequiredWeight,
    SignedEventIntentApproval, SigningPublicKey, Timestamp, verify_event_intent_admission,
};

fn typed_id<T: CanonicalWire>(fill: u8) -> T {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [fill; 32]);
    T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
}

fn controller(secret: &SecretKey) -> ControllerDescriptor {
    ControllerDescriptor::new(
        SigningPublicKey::ed25519(*secret.public().as_bytes()).unwrap(),
        ControllerClass::PersonalDevice,
        ControllerWeight::new(1).unwrap(),
        ControllerScope::all_v1_operations(),
        Extensions::default(),
    )
    .unwrap()
}

fn intent_approval(
    controller_id: krikos_identity::ControllerId,
    proposal_id: krikos_identity::ProposalId,
    signer: &SecretKey,
) -> SignedEventIntentApproval {
    let body =
        EventIntentApprovalBody::new(controller_id, proposal_id, Extensions::default()).unwrap();
    let signing_key = SigningPublicKey::ed25519(*signer.public().as_bytes()).unwrap();
    let signature = signer.sign(&body.to_canonical_bytes().unwrap());
    SignedEventIntentApproval::new(
        body,
        vec![KeyedSignature::new(
            CryptoSuiteDescriptor::v1()
                .unwrap()
                .crypto_suite_id()
                .unwrap(),
            ControllerKeyId::for_signing_key(&signing_key).unwrap(),
            AlgorithmSignature::new(1, signature.to_bytes().to_vec()).unwrap(),
        )],
    )
    .unwrap()
}

struct Signer(SecretKey);

impl ProviderHeadSigner for Signer {
    fn sign_provider_head(&self, message: &[u8]) -> Result<ProtocolSignature, IdentityError> {
        Ok(ProtocolSignature::ed25519(self.0.sign(message).to_bytes()))
    }
}

#[test]
fn provider_appends_only_exact_pre_state_threshold_approved_delayed_intent() {
    let first_secret = SecretKey::from_bytes(&[0x91; 32]);
    let second_secret = SecretKey::from_bytes(&[0x92; 32]);
    let first = controller(&first_secret);
    let second = controller(&second_secret);
    let policy = ControlPolicy::new(
        vec![
            PolicyRule::new(
                OperationKind::AddController,
                RequiredWeight::new(2).unwrap(),
                ControllerSelector::any_active(),
                FreshnessRequirement::latest_known(),
                Some(DurationMillis::new(10)),
                Extensions::default(),
            )
            .unwrap(),
        ],
        Extensions::default(),
    )
    .unwrap();
    let recovery = RecoveryPolicy::new(
        RecoveryPolicyVersion::GENESIS,
        RecoveryAuthority::controller_threshold(ControllerThreshold::new(
            ControllerSelector::any_active(),
            RequiredWeight::new(1).unwrap(),
        )),
        DurationMillis::new(10),
        DurationMillis::new(100),
        Extensions::default(),
    )
    .unwrap();
    let provider_secret = SecretKey::from_bytes(&[0x93; 32]);
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*provider_secret.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let provider_policy = ProviderPolicy::replicated(
        ProviderPolicyVersion::GENESIS,
        vec![provider.clone()],
        ProviderQuorum::new(1).unwrap(),
        ProviderQuorum::new(1).unwrap(),
        DurationMillis::new(1_000),
        Extensions::default(),
    )
    .unwrap();
    let genesis = AccountGenesis::new(
        [0x94; 32],
        Timestamp::from_unix_millis(1),
        policy,
        vec![first, second],
        recovery,
        provider_policy,
        Extensions::default(),
    )
    .unwrap();
    let state = AccountState::from_genesis(&genesis).unwrap();
    let operation =
        AccountOperation::AddController(controller(&SecretKey::from_bytes(&[0x95; 32])));
    let body = EventBody::new(
        state.account_id(),
        state.sequence().checked_next().unwrap(),
        state.expected_epoch_for(&operation).unwrap(),
        EventPredecessors::genesis(state.genesis_anchor()),
        operation,
        Timestamp::from_unix_millis(2),
        [0x96; 16],
        Extensions::default(),
    )
    .unwrap();
    let proposal_id = body.proposal_id().unwrap();
    let first_id = state
        .active_controllers()
        .iter()
        .find(|entry| entry.signing_key().as_bytes() == first_secret.public().as_bytes())
        .unwrap()
        .id();
    let second_id = state
        .active_controllers()
        .iter()
        .find(|entry| entry.signing_key().as_bytes() == second_secret.public().as_bytes())
        .unwrap()
        .id();
    let first_approval = intent_approval(first_id, proposal_id, &first_secret);
    let second_approval = intent_approval(second_id, proposal_id, &second_secret);
    let approvals =
        EventIntentApprovals::new(vec![first_approval.clone(), second_approval]).unwrap();
    let before = state.clone();
    let admission = verify_event_intent_admission(&state, &body, &approvals).unwrap();
    assert_eq!(state, before);
    assert_eq!(admission.account_id(), state.account_id());
    assert_eq!(
        admission.subject(),
        ProviderLogSubject::EventIntent(proposal_id)
    );

    let mut log = MemoryTransparencyLog::new(provider.clone(), typed_id::<ProviderLogId>(0x97));
    let receipt = log
        .append(
            admission.clone(),
            Timestamp::from_unix_millis(10),
            &Signer(provider_secret),
        )
        .unwrap();
    receipt.verify(&provider).unwrap();
    assert_eq!(receipt.entry().subject(), admission.subject());

    let insufficient = EventIntentApprovals::new(vec![first_approval]).unwrap();
    assert_eq!(
        verify_event_intent_admission(&state, &body, &insufficient),
        Err(IdentityError::AuthorizationDenied)
    );
    let forged = EventIntentApprovals::new(vec![
        intent_approval(first_id, proposal_id, &SecretKey::from_bytes(&[0x98; 32])),
        intent_approval(second_id, proposal_id, &second_secret),
    ])
    .unwrap();
    assert_eq!(
        verify_event_intent_admission(&state, &body, &forged),
        Err(IdentityError::InvalidSignature)
    );
    let wrong_proposal = typed_id::<krikos_identity::ProposalId>(0x99);
    let unrelated = EventIntentApprovals::new(vec![
        intent_approval(first_id, wrong_proposal, &first_secret),
        intent_approval(second_id, wrong_proposal, &second_secret),
    ])
    .unwrap();
    assert!(matches!(
        verify_event_intent_admission(&state, &body, &unrelated),
        Err(IdentityError::InvalidRelationship { .. })
    ));
}
