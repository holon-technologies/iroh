use krikos_identity::{
    AccountId, ApplicationId, AuthorizationContext, CanonicalWire, CapabilityAction,
    CapabilityDenialReason, CapabilityDeviceStatus, CapabilityGrant, CapabilityGrantId,
    CapabilityNamespace, CapabilityProof, CapabilityRequest, CapabilityStateView, CheckpointId,
    DelegationBody, DelegationChain, DelegationDepth, DelegationId, DelegationPermission,
    DelegationSignatureStatus, DelegationSignatureVerifier, DeviceId, Digest, Epoch, Extensions,
    HashAlgorithm, IdentityError, ProtocolSignature, ResourcePath, ResourceSelector,
    SignedDelegation, Timestamp, evaluate_capability,
};
use proptest::prelude::*;

fn digest(seed: u8) -> Digest {
    Digest::new(HashAlgorithm::Blake3_256, [seed; 32])
}

fn account_id(seed: u8) -> AccountId {
    AccountId::from_canonical_bytes(&digest(seed).to_canonical_bytes().unwrap()).unwrap()
}

fn checkpoint_id(seed: u8) -> CheckpointId {
    CheckpointId::from_canonical_bytes(&digest(seed).to_canonical_bytes().unwrap()).unwrap()
}

fn device_id(seed: u8) -> DeviceId {
    DeviceId::from_canonical_bytes(&digest(seed).to_canonical_bytes().unwrap()).unwrap()
}

fn context(epoch: u64, checkpoint_seed: u8) -> AuthorizationContext {
    AuthorizationContext::new(
        account_id(1),
        Epoch::new(epoch),
        checkpoint_id(checkpoint_seed),
    )
}

fn path(segments: &[&[u8]]) -> ResourcePath {
    ResourcePath::new(segments.iter().map(|segment| segment.to_vec()).collect()).unwrap()
}

fn grant(
    resource: ResourceSelector,
    constraints: Vec<krikos_identity::CapabilityConstraint>,
    delegation: DelegationPermission,
    expires_at: Option<Timestamp>,
) -> CapabilityGrant {
    CapabilityGrant::new(
        CapabilityNamespace::new("krikos.database").unwrap(),
        CapabilityAction::new("write").unwrap(),
        resource,
        constraints,
        delegation,
        expires_at,
        Extensions::default(),
    )
    .unwrap()
}

fn request(
    authorization_context: AuthorizationContext,
    device_id: DeviceId,
    resource: ResourcePath,
    evaluated_at: u64,
) -> CapabilityRequest {
    CapabilityRequest::new(
        authorization_context,
        ApplicationId::new(digest(90)),
        device_id,
        CapabilityNamespace::new("krikos.database").unwrap(),
        CapabilityAction::new("write").unwrap(),
        resource,
        Timestamp::from_unix_millis(evaluated_at),
    )
}

#[derive(Debug)]
struct TestState {
    authorization_context: AuthorizationContext,
    statuses: Vec<(DeviceId, CapabilityDeviceStatus)>,
    root_holder: DeviceId,
    root_grants: Vec<CapabilityGrant>,
    revoked_grants: Vec<CapabilityGrantId>,
    revoked_delegations: Vec<DelegationId>,
    recognized_contexts: Vec<AuthorizationContext>,
    context_lineage: Vec<(AuthorizationContext, AuthorizationContext)>,
    context_times: Vec<(AuthorizationContext, Timestamp)>,
    historical_statuses: Vec<(DeviceId, AuthorizationContext, CapabilityDeviceStatus)>,
    historical_holdings: Vec<(DeviceId, CapabilityGrantId, AuthorizationContext)>,
}

impl TestState {
    fn active(
        authorization_context: AuthorizationContext,
        device_id: DeviceId,
        root_grants: Vec<CapabilityGrant>,
    ) -> Self {
        Self {
            authorization_context,
            statuses: vec![(device_id, CapabilityDeviceStatus::Active)],
            root_holder: device_id,
            root_grants,
            revoked_grants: Vec::new(),
            revoked_delegations: Vec::new(),
            recognized_contexts: vec![authorization_context],
            context_lineage: Vec::new(),
            context_times: Vec::new(),
            historical_statuses: Vec::new(),
            historical_holdings: Vec::new(),
        }
    }

    fn record_chain_history(&mut self, chain: &DelegationChain) {
        let root_context = chain.root().authorization_context();
        if !self.recognized_contexts.contains(&root_context) {
            self.recognized_contexts.push(root_context);
        }
        let mut parent_grant_id = chain.root().grant().capability_grant_id().unwrap();
        self.context_lineage
            .push((root_context, self.authorization_context));
        let root_time = chain
            .links()
            .first()
            .map_or(Timestamp::from_unix_millis(0), |link| {
                link.body().issued_at()
            });
        if !self
            .context_times
            .iter()
            .any(|(context, _)| *context == root_context)
        {
            self.context_times.push((root_context, root_time));
        }
        self.historical_statuses.push((
            chain.root().holder(),
            root_context,
            CapabilityDeviceStatus::Active,
        ));
        self.historical_holdings
            .push((chain.root().holder(), parent_grant_id, root_context));
        let mut previous_context = root_context;
        for link in chain.links() {
            let body = link.body();
            let context = body.authorization_context();
            if !self.recognized_contexts.contains(&context) {
                self.recognized_contexts.push(context);
            }
            self.context_lineage.push((previous_context, context));
            self.context_lineage
                .push((context, self.authorization_context));
            if !self
                .context_times
                .iter()
                .any(|(candidate, _)| *candidate == context)
            {
                self.context_times.push((context, body.issued_at()));
            }
            self.historical_statuses
                .push((body.issuer(), context, CapabilityDeviceStatus::Active));
            self.historical_holdings
                .push((body.issuer(), parent_grant_id, context));
            parent_grant_id = body.child_grant().capability_grant_id().unwrap();
            previous_context = context;
        }
    }
}

impl CapabilityStateView for TestState {
    fn authorization_context(&self) -> AuthorizationContext {
        self.authorization_context
    }

    fn device_status(&self, device_id: DeviceId) -> CapabilityDeviceStatus {
        self.statuses
            .iter()
            .find_map(|(candidate, status)| (*candidate == device_id).then_some(*status))
            .unwrap_or(CapabilityDeviceStatus::Unknown)
    }

    fn root_grants(&self, holder: DeviceId) -> &[CapabilityGrant] {
        if holder == self.root_holder {
            &self.root_grants
        } else {
            &[]
        }
    }

    fn is_grant_revoked(&self, grant_id: CapabilityGrantId) -> bool {
        self.revoked_grants.contains(&grant_id)
    }

    fn is_delegation_revoked(&self, delegation_id: DelegationId) -> bool {
        self.revoked_delegations.contains(&delegation_id)
    }

    fn recognizes_authorization_context(&self, context: AuthorizationContext) -> bool {
        self.recognized_contexts.contains(&context)
    }

    fn authorization_context_precedes_or_equals(
        &self,
        ancestor: AuthorizationContext,
        descendant: AuthorizationContext,
    ) -> bool {
        self.recognized_contexts.contains(&ancestor)
            && self.recognized_contexts.contains(&descendant)
            && ancestor.account_id() == descendant.account_id()
            && (ancestor == descendant || self.context_lineage.contains(&(ancestor, descendant)))
    }

    fn authorization_context_timestamp(&self, context: AuthorizationContext) -> Option<Timestamp> {
        self.context_times
            .iter()
            .find_map(|(candidate, timestamp)| (*candidate == context).then_some(*timestamp))
    }

    fn device_status_at(
        &self,
        device_id: DeviceId,
        context: AuthorizationContext,
    ) -> CapabilityDeviceStatus {
        self.historical_statuses
            .iter()
            .find_map(|(candidate, candidate_context, status)| {
                (*candidate == device_id && *candidate_context == context).then_some(*status)
            })
            .unwrap_or(CapabilityDeviceStatus::Unknown)
    }

    fn held_grant_at(
        &self,
        holder: DeviceId,
        grant_id: CapabilityGrantId,
        context: AuthorizationContext,
    ) -> bool {
        self.historical_holdings
            .contains(&(holder, grant_id, context))
    }
}

#[derive(Debug, Clone, Copy)]
struct TestSignatures(DelegationSignatureStatus);

impl DelegationSignatureVerifier for TestSignatures {
    fn verify_delegation(&self, _delegation: &SignedDelegation) -> DelegationSignatureStatus {
        self.0
    }
}

const VERIFIED_SIGNATURES: TestSignatures = TestSignatures(DelegationSignatureStatus::Verified);

#[test]
fn default_deny_records_the_exact_checkpoint_and_epoch_basis() {
    let device = device_id(1);
    let basis = context(7, 7);
    let state = TestState::active(basis, device, Vec::new());
    let request = request(basis, device, path(&[b"collection", b"blue"]), 100);

    let decision = evaluate_capability(
        &request,
        CapabilityProof::Direct,
        &state,
        &VERIFIED_SIGNATURES,
    );

    assert!(!decision.is_allowed());
    assert_eq!(
        decision.denial_reason(),
        Some(CapabilityDenialReason::NoMatchingGrant)
    );
    assert_eq!(decision.checkpoint_id(), basis.checkpoint_id());
    assert_eq!(decision.epoch(), basis.epoch());
    assert_eq!(decision.application_id(), ApplicationId::new(digest(90)));
}

#[test]
fn exact_and_prefix_selectors_match_only_complete_resource_segments() {
    let device = device_id(2);
    let basis = context(2, 2);
    let exact = grant(
        ResourceSelector::exact(path(&[b"collection", b"blue"])).unwrap(),
        Vec::new(),
        DelegationPermission::NotDelegable,
        None,
    );
    let exact_id = exact.capability_grant_id().unwrap();
    let exact_state = TestState::active(basis, device, vec![exact]);

    let exact_decision = evaluate_capability(
        &request(basis, device, path(&[b"collection", b"blue"]), 1),
        CapabilityProof::Direct,
        &exact_state,
        &VERIFIED_SIGNATURES,
    );
    assert!(exact_decision.is_allowed());
    assert_eq!(exact_decision.grant_id(), Some(exact_id));
    assert_eq!(exact_decision.delegation_id(), None);

    let exact_child = evaluate_capability(
        &request(basis, device, path(&[b"collection", b"blue", b"record"]), 1),
        CapabilityProof::Direct,
        &exact_state,
        &VERIFIED_SIGNATURES,
    );
    assert_eq!(
        exact_child.denial_reason(),
        Some(CapabilityDenialReason::ResourceNotGranted)
    );

    let prefix = grant(
        ResourceSelector::prefix(path(&[b"collection", b"blue"])).unwrap(),
        Vec::new(),
        DelegationPermission::NotDelegable,
        None,
    );
    let prefix_state = TestState::active(basis, device, vec![prefix]);
    let prefix_child = evaluate_capability(
        &request(basis, device, path(&[b"collection", b"blue", b"record"]), 1),
        CapabilityProof::Direct,
        &prefix_state,
        &VERIFIED_SIGNATURES,
    );
    assert!(prefix_child.is_allowed());

    let partial_segment = evaluate_capability(
        &request(basis, device, path(&[b"collection", b"bluebird"]), 1),
        CapabilityProof::Direct,
        &prefix_state,
        &VERIFIED_SIGNATURES,
    );
    assert_eq!(
        partial_segment.denial_reason(),
        Some(CapabilityDenialReason::ResourceNotGranted)
    );
}

#[test]
fn namespace_and_action_matching_is_exact() {
    let device = device_id(4);
    let basis = context(2, 2);
    let state = TestState::active(
        basis,
        device,
        vec![grant(
            ResourceSelector::exact(path(&[b"record"])).unwrap(),
            Vec::new(),
            DelegationPermission::NotDelegable,
            None,
        )],
    );
    let different_namespace = CapabilityRequest::new(
        basis,
        ApplicationId::new(digest(90)),
        device,
        CapabilityNamespace::new("krikos.database.extra").unwrap(),
        CapabilityAction::new("write").unwrap(),
        path(&[b"record"]),
        Timestamp::from_unix_millis(1),
    );
    assert_eq!(
        evaluate_capability(
            &different_namespace,
            CapabilityProof::Direct,
            &state,
            &VERIFIED_SIGNATURES,
        )
        .denial_reason(),
        Some(CapabilityDenialReason::NamespaceNotGranted)
    );

    let different_action = CapabilityRequest::new(
        basis,
        ApplicationId::new(digest(90)),
        device,
        CapabilityNamespace::new("krikos.database").unwrap(),
        CapabilityAction::new("write-all").unwrap(),
        path(&[b"record"]),
        Timestamp::from_unix_millis(1),
    );
    assert_eq!(
        evaluate_capability(
            &different_action,
            CapabilityProof::Direct,
            &state,
            &VERIFIED_SIGNATURES,
        )
        .denial_reason(),
        Some(CapabilityDenialReason::ActionNotGranted)
    );
}

#[test]
fn constraints_are_conjunctive_and_expiration_is_an_exclusive_bound() {
    use krikos_identity::CapabilityConstraint::{
        AccountEpochAtLeast, AccountEpochAtMost, ValidFrom,
    };

    let device = device_id(3);
    let constrained = grant(
        ResourceSelector::exact(path(&[b"record"])).unwrap(),
        vec![
            AccountEpochAtLeast(Epoch::new(2)),
            AccountEpochAtMost(Epoch::new(4)),
            ValidFrom(Timestamp::from_unix_millis(100)),
        ],
        DelegationPermission::NotDelegable,
        Some(Timestamp::from_unix_millis(200)),
    );

    let valid_basis = context(3, 3);
    let valid_state = TestState::active(valid_basis, device, vec![constrained.clone()]);
    assert!(
        evaluate_capability(
            &request(valid_basis, device, path(&[b"record"]), 100),
            CapabilityProof::Direct,
            &valid_state,
            &VERIFIED_SIGNATURES,
        )
        .is_allowed()
    );

    let early_basis = context(1, 1);
    let early_state = TestState::active(early_basis, device, vec![constrained.clone()]);
    assert_eq!(
        evaluate_capability(
            &request(early_basis, device, path(&[b"record"]), 100),
            CapabilityProof::Direct,
            &early_state,
            &VERIFIED_SIGNATURES,
        )
        .denial_reason(),
        Some(CapabilityDenialReason::ConstraintUnsatisfied)
    );

    assert_eq!(
        evaluate_capability(
            &request(valid_basis, device, path(&[b"record"]), 99),
            CapabilityProof::Direct,
            &valid_state,
            &VERIFIED_SIGNATURES,
        )
        .denial_reason(),
        Some(CapabilityDenialReason::ConstraintUnsatisfied)
    );
    assert_eq!(
        evaluate_capability(
            &request(valid_basis, device, path(&[b"record"]), 200),
            CapabilityProof::Direct,
            &valid_state,
            &VERIFIED_SIGNATURES,
        )
        .denial_reason(),
        Some(CapabilityDenialReason::GrantExpired)
    );
}

#[test]
fn delegation_must_narrow_and_remains_revocable_through_every_parent() {
    let root_device = device_id(10);
    let leaf_device = device_id(11);
    let basis = context(5, 5);
    let root_grant = grant(
        ResourceSelector::prefix(path(&[b"collection"])).unwrap(),
        Vec::new(),
        DelegationPermission::delegable(DelegationDepth::new(1).unwrap()),
        Some(Timestamp::from_unix_millis(300)),
    );
    let child_grant = grant(
        ResourceSelector::exact(path(&[b"collection", b"blue"])).unwrap(),
        Vec::new(),
        DelegationPermission::NotDelegable,
        Some(Timestamp::from_unix_millis(250)),
    );
    let link = SignedDelegation::new(
        DelegationBody::new(
            root_grant.capability_grant_id().unwrap(),
            child_grant,
            root_device,
            leaf_device,
            basis,
            Timestamp::from_unix_millis(10),
            [7; 16],
            Extensions::default(),
        )
        .unwrap(),
        ProtocolSignature::ed25519([7; 64]),
    );
    let chain = DelegationChain::new(
        krikos_identity::CapabilityRoot::new(
            basis,
            root_device,
            root_grant.clone(),
            Extensions::default(),
        )
        .unwrap(),
        vec![link.clone()],
    )
    .unwrap();
    let mut state = TestState::active(basis, root_device, vec![root_grant.clone()]);
    state
        .statuses
        .push((leaf_device, CapabilityDeviceStatus::Active));
    state.record_chain_history(&chain);
    let delegated_request = request(basis, leaf_device, path(&[b"collection", b"blue"]), 100);

    let delegated_decision = evaluate_capability(
        &delegated_request,
        CapabilityProof::Delegated(&chain),
        &state,
        &VERIFIED_SIGNATURES,
    );
    assert!(delegated_decision.is_allowed());
    assert_eq!(
        delegated_decision.delegation_id(),
        Some(link.delegation_id().unwrap())
    );

    state
        .revoked_grants
        .push(root_grant.capability_grant_id().unwrap());
    assert_eq!(
        evaluate_capability(
            &delegated_request,
            CapabilityProof::Delegated(&chain),
            &state,
            &VERIFIED_SIGNATURES,
        )
        .denial_reason(),
        Some(CapabilityDenialReason::ParentGrantRevoked)
    );
    state.revoked_grants.clear();
    state
        .revoked_delegations
        .push(link.delegation_id().unwrap());
    assert_eq!(
        evaluate_capability(
            &delegated_request,
            CapabilityProof::Delegated(&chain),
            &state,
            &VERIFIED_SIGNATURES,
        )
        .denial_reason(),
        Some(CapabilityDenialReason::DelegationRevoked)
    );

    let broader_child = grant(
        ResourceSelector::prefix(path(&[b"other"])).unwrap(),
        Vec::new(),
        DelegationPermission::NotDelegable,
        Some(Timestamp::from_unix_millis(250)),
    );
    let broader_link = SignedDelegation::new(
        DelegationBody::new(
            root_grant.capability_grant_id().unwrap(),
            broader_child,
            root_device,
            leaf_device,
            basis,
            Timestamp::from_unix_millis(10),
            [8; 16],
            Extensions::default(),
        )
        .unwrap(),
        ProtocolSignature::ed25519([8; 64]),
    );
    assert!(matches!(
        DelegationChain::new(chain.root().clone(), vec![broader_link]),
        Err(IdentityError::InvalidDelegation { .. })
    ));
}

#[test]
fn stale_checkpoint_or_epoch_is_denied_before_grant_evaluation() {
    let device = device_id(20);
    let current = context(4, 4);
    let allowed_grant = grant(
        ResourceSelector::exact(path(&[b"record"])).unwrap(),
        Vec::new(),
        DelegationPermission::NotDelegable,
        None,
    );
    let state = TestState::active(current, device, vec![allowed_grant]);

    let stale_epoch = request(context(3, 4), device, path(&[b"record"]), 1);
    assert_eq!(
        evaluate_capability(
            &stale_epoch,
            CapabilityProof::Direct,
            &state,
            &VERIFIED_SIGNATURES,
        )
        .denial_reason(),
        Some(CapabilityDenialReason::EpochMismatch)
    );

    let stale_checkpoint = request(context(4, 3), device, path(&[b"record"]), 1);
    assert_eq!(
        evaluate_capability(
            &stale_checkpoint,
            CapabilityProof::Direct,
            &state,
            &VERIFIED_SIGNATURES,
        )
        .denial_reason(),
        Some(CapabilityDenialReason::CheckpointMismatch)
    );
}

#[test]
fn unknown_suspended_and_revoked_devices_are_default_denied() {
    let device = device_id(30);
    let basis = context(8, 8);
    let allowed_grant = grant(
        ResourceSelector::exact(path(&[b"record"])).unwrap(),
        Vec::new(),
        DelegationPermission::NotDelegable,
        None,
    );
    let request = request(basis, device, path(&[b"record"]), 1);

    for (status, expected) in [
        (
            CapabilityDeviceStatus::Unknown,
            CapabilityDenialReason::UnknownDevice,
        ),
        (
            CapabilityDeviceStatus::Suspended,
            CapabilityDenialReason::DeviceSuspended,
        ),
        (
            CapabilityDeviceStatus::Revoked,
            CapabilityDenialReason::DeviceRevoked,
        ),
    ] {
        let mut state = TestState::active(basis, device, vec![allowed_grant.clone()]);
        state.statuses = vec![(device, status)];
        assert_eq!(
            evaluate_capability(
                &request,
                CapabilityProof::Direct,
                &state,
                &VERIFIED_SIGNATURES,
            )
            .denial_reason(),
            Some(expected)
        );
    }
}

#[test]
fn delegation_requires_a_real_signature_verification_result() {
    let root_device = device_id(40);
    let leaf_device = device_id(41);
    let basis = context(9, 9);
    let root_grant = grant(
        ResourceSelector::prefix(path(&[b"collection"])).unwrap(),
        Vec::new(),
        DelegationPermission::delegable(DelegationDepth::new(1).unwrap()),
        None,
    );
    let child_grant = grant(
        ResourceSelector::exact(path(&[b"collection", b"blue"])).unwrap(),
        Vec::new(),
        DelegationPermission::NotDelegable,
        None,
    );
    let link = SignedDelegation::new(
        DelegationBody::new(
            root_grant.capability_grant_id().unwrap(),
            child_grant,
            root_device,
            leaf_device,
            basis,
            Timestamp::from_unix_millis(1),
            [1; 16],
            Extensions::default(),
        )
        .unwrap(),
        ProtocolSignature::ed25519([1; 64]),
    );
    let chain = DelegationChain::new(
        krikos_identity::CapabilityRoot::new(
            basis,
            root_device,
            root_grant.clone(),
            Extensions::default(),
        )
        .unwrap(),
        vec![link],
    )
    .unwrap();
    let mut state = TestState::active(basis, root_device, vec![root_grant]);
    state
        .statuses
        .push((leaf_device, CapabilityDeviceStatus::Active));
    state.record_chain_history(&chain);
    let capability_request = request(basis, leaf_device, path(&[b"collection", b"blue"]), 10);

    for (signature_status, expected) in [
        (
            DelegationSignatureStatus::Unavailable,
            CapabilityDenialReason::SignatureVerificationUnavailable,
        ),
        (
            DelegationSignatureStatus::Invalid,
            CapabilityDenialReason::InvalidDelegationSignature,
        ),
    ] {
        assert_eq!(
            evaluate_capability(
                &capability_request,
                CapabilityProof::Delegated(&chain),
                &state,
                &TestSignatures(signature_status),
            )
            .denial_reason(),
            Some(expected)
        );
    }

    let request_before_issuance = request(basis, leaf_device, path(&[b"collection", b"blue"]), 0);
    assert_eq!(
        evaluate_capability(
            &request_before_issuance,
            CapabilityProof::Delegated(&chain),
            &state,
            &VERIFIED_SIGNATURES,
        )
        .denial_reason(),
        Some(CapabilityDenialReason::DelegationNotYetValid)
    );

    state.recognized_contexts.clear();
    assert_eq!(
        evaluate_capability(
            &capability_request,
            CapabilityProof::Delegated(&chain),
            &state,
            &VERIFIED_SIGNATURES,
        )
        .denial_reason(),
        Some(CapabilityDenialReason::UnrecognizedAuthorizationContext)
    );
}

#[test]
fn delegation_requires_historical_grant_possession_and_an_active_issuer() {
    let root_device = device_id(50);
    let leaf_device = device_id(51);
    let root_context = context(4, 4);
    let basis = context(5, 5);
    let root_grant = grant(
        ResourceSelector::prefix(path(&[b"collection"])).unwrap(),
        Vec::new(),
        DelegationPermission::delegable(DelegationDepth::new(1).unwrap()),
        None,
    );
    let child_grant = grant(
        ResourceSelector::exact(path(&[b"collection", b"blue"])).unwrap(),
        Vec::new(),
        DelegationPermission::NotDelegable,
        None,
    );
    let link = SignedDelegation::new(
        DelegationBody::new(
            root_grant.capability_grant_id().unwrap(),
            child_grant,
            root_device,
            leaf_device,
            basis,
            Timestamp::from_unix_millis(10),
            [2; 16],
            Extensions::default(),
        )
        .unwrap(),
        ProtocolSignature::ed25519([2; 64]),
    );
    let chain = DelegationChain::new(
        krikos_identity::CapabilityRoot::new(
            root_context,
            root_device,
            root_grant.clone(),
            Extensions::default(),
        )
        .unwrap(),
        vec![link],
    )
    .unwrap();
    let root_grant_id = root_grant.capability_grant_id().unwrap();
    let capability_request = request(basis, leaf_device, path(&[b"collection", b"blue"]), 20);
    let mut state = TestState::active(basis, root_device, vec![root_grant]);
    state
        .statuses
        .push((leaf_device, CapabilityDeviceStatus::Active));
    state.recognized_contexts.push(root_context);
    state.context_lineage.push((root_context, basis));
    state
        .context_times
        .push((root_context, Timestamp::from_unix_millis(0)));
    state
        .context_times
        .push((basis, Timestamp::from_unix_millis(10)));
    state
        .historical_statuses
        .push((root_device, root_context, CapabilityDeviceStatus::Active));
    state
        .historical_holdings
        .push((root_device, root_grant_id, root_context));
    state
        .historical_statuses
        .push((root_device, basis, CapabilityDeviceStatus::Active));

    assert_eq!(
        evaluate_capability(
            &capability_request,
            CapabilityProof::Delegated(&chain),
            &state,
            &VERIFIED_SIGNATURES,
        )
        .denial_reason(),
        Some(CapabilityDenialReason::ParentGrantNotHeldAtIssuance)
    );

    state.historical_statuses[1].2 = CapabilityDeviceStatus::Suspended;
    state
        .historical_holdings
        .push((root_device, root_grant_id, basis));
    assert_eq!(
        evaluate_capability(
            &capability_request,
            CapabilityProof::Delegated(&chain),
            &state,
            &VERIFIED_SIGNATURES,
        )
        .denial_reason(),
        Some(CapabilityDenialReason::IssuerNotActiveAtIssuance)
    );
}

#[test]
fn delegation_rejects_a_parent_expired_at_issuance() {
    let root_device = device_id(52);
    let leaf_device = device_id(53);
    let root_context = context(4, 4);
    let basis = context(5, 5);
    let root_grant = grant(
        ResourceSelector::prefix(path(&[b"collection"])).unwrap(),
        Vec::new(),
        DelegationPermission::delegable(DelegationDepth::new(1).unwrap()),
        Some(Timestamp::from_unix_millis(50)),
    );
    let child_grant = grant(
        ResourceSelector::exact(path(&[b"collection", b"blue"])).unwrap(),
        Vec::new(),
        DelegationPermission::NotDelegable,
        Some(Timestamp::from_unix_millis(40)),
    );
    let link = SignedDelegation::new(
        DelegationBody::new(
            root_grant.capability_grant_id().unwrap(),
            child_grant,
            root_device,
            leaf_device,
            basis,
            Timestamp::from_unix_millis(60),
            [3; 16],
            Extensions::default(),
        )
        .unwrap(),
        ProtocolSignature::ed25519([3; 64]),
    );
    let chain = DelegationChain::new(
        krikos_identity::CapabilityRoot::new(
            root_context,
            root_device,
            root_grant.clone(),
            Extensions::default(),
        )
        .unwrap(),
        vec![link],
    )
    .unwrap();
    let mut state = TestState::active(basis, root_device, vec![root_grant]);
    state
        .statuses
        .push((leaf_device, CapabilityDeviceStatus::Active));
    state.record_chain_history(&chain);
    state
        .context_times
        .iter_mut()
        .find(|(context, _)| *context == root_context)
        .unwrap()
        .1 = Timestamp::from_unix_millis(10);

    assert_eq!(
        evaluate_capability(
            &request(basis, leaf_device, path(&[b"collection", b"blue"]), 100,),
            CapabilityProof::Delegated(&chain),
            &state,
            &VERIFIED_SIGNATURES,
        )
        .denial_reason(),
        Some(CapabilityDenialReason::ParentGrantInvalidAtIssuance)
    );
}

#[test]
fn delegation_cannot_be_presigned_at_a_zero_step_context_before_parent_epoch() {
    let root_device = device_id(54);
    let leaf_device = device_id(55);
    let issuance_context = context(1, 1);
    let current_context = context(3, 3);
    let minimum_epoch = krikos_identity::CapabilityConstraint::AccountEpochAtLeast(Epoch::new(2));
    let root_grant = grant(
        ResourceSelector::prefix(path(&[b"collection"])).unwrap(),
        vec![minimum_epoch],
        DelegationPermission::delegable(DelegationDepth::new(1).unwrap()),
        None,
    );
    let child_grant = grant(
        ResourceSelector::exact(path(&[b"collection", b"blue"])).unwrap(),
        vec![minimum_epoch],
        DelegationPermission::NotDelegable,
        None,
    );
    let link = SignedDelegation::new(
        DelegationBody::new(
            root_grant.capability_grant_id().unwrap(),
            child_grant,
            root_device,
            leaf_device,
            issuance_context,
            Timestamp::from_unix_millis(10),
            [6; 16],
            Extensions::default(),
        )
        .unwrap(),
        ProtocolSignature::ed25519([6; 64]),
    );
    let chain = DelegationChain::new(
        krikos_identity::CapabilityRoot::new(
            issuance_context,
            root_device,
            root_grant.clone(),
            Extensions::default(),
        )
        .unwrap(),
        vec![link],
    )
    .unwrap();
    let mut state = TestState::active(current_context, root_device, vec![root_grant]);
    state
        .statuses
        .push((leaf_device, CapabilityDeviceStatus::Active));
    state.record_chain_history(&chain);

    assert_eq!(
        evaluate_capability(
            &request(
                current_context,
                leaf_device,
                path(&[b"collection", b"blue"]),
                20,
            ),
            CapabilityProof::Delegated(&chain),
            &state,
            &VERIFIED_SIGNATURES,
        )
        .denial_reason(),
        Some(CapabilityDenialReason::RootGrantInvalidAtContext)
    );
}

#[test]
fn delegation_contexts_cannot_roll_back_between_links() {
    let root_device = device_id(60);
    let middle_device = device_id(61);
    let leaf_device = device_id(62);
    let root_context = context(1, 1);
    let forward_context = context(3, 3);
    let rollback_context = context(2, 2);
    let current_context = context(4, 4);
    let root_grant = grant(
        ResourceSelector::prefix(path(&[b"collection"])).unwrap(),
        Vec::new(),
        DelegationPermission::delegable(DelegationDepth::new(2).unwrap()),
        None,
    );
    let middle_grant = grant(
        ResourceSelector::prefix(path(&[b"collection", b"blue"])).unwrap(),
        Vec::new(),
        DelegationPermission::delegable(DelegationDepth::new(1).unwrap()),
        None,
    );
    let leaf_grant = grant(
        ResourceSelector::exact(path(&[b"collection", b"blue", b"record"])).unwrap(),
        Vec::new(),
        DelegationPermission::NotDelegable,
        None,
    );
    let first = SignedDelegation::new(
        DelegationBody::new(
            root_grant.capability_grant_id().unwrap(),
            middle_grant.clone(),
            root_device,
            middle_device,
            forward_context,
            Timestamp::from_unix_millis(10),
            [4; 16],
            Extensions::default(),
        )
        .unwrap(),
        ProtocolSignature::ed25519([4; 64]),
    );
    let second = SignedDelegation::new(
        DelegationBody::new(
            middle_grant.capability_grant_id().unwrap(),
            leaf_grant,
            middle_device,
            leaf_device,
            rollback_context,
            Timestamp::from_unix_millis(20),
            [5; 16],
            Extensions::default(),
        )
        .unwrap(),
        ProtocolSignature::ed25519([5; 64]),
    );
    let chain = DelegationChain::new(
        krikos_identity::CapabilityRoot::new(
            root_context,
            root_device,
            root_grant.clone(),
            Extensions::default(),
        )
        .unwrap(),
        vec![first, second],
    )
    .unwrap();
    let mut state = TestState::active(current_context, root_device, vec![root_grant]);
    state.statuses.extend([
        (middle_device, CapabilityDeviceStatus::Active),
        (leaf_device, CapabilityDeviceStatus::Active),
    ]);
    state
        .recognized_contexts
        .extend([root_context, forward_context, rollback_context]);
    state.record_chain_history(&chain);

    assert_eq!(
        evaluate_capability(
            &request(
                current_context,
                leaf_device,
                path(&[b"collection", b"blue", b"record"]),
                30,
            ),
            CapabilityProof::Delegated(&chain),
            &state,
            &VERIFIED_SIGNATURES,
        )
        .denial_reason(),
        Some(CapabilityDenialReason::AuthorizationContextRollback)
    );
}

#[test]
fn delegated_root_requires_historical_active_possession_and_context_time_validity() {
    let root_device = device_id(56);
    let leaf_device = device_id(57);
    let old_context = context(1, 1);
    let current_context = context(3, 3);
    let valid_from =
        krikos_identity::CapabilityConstraint::ValidFrom(Timestamp::from_unix_millis(50));
    let root_grant = grant(
        ResourceSelector::prefix(path(&[b"collection"])).unwrap(),
        vec![valid_from],
        DelegationPermission::delegable(DelegationDepth::new(1).unwrap()),
        None,
    );
    let child_grant = grant(
        ResourceSelector::exact(path(&[b"collection", b"blue"])).unwrap(),
        vec![valid_from],
        DelegationPermission::NotDelegable,
        None,
    );
    let link = SignedDelegation::new(
        DelegationBody::new(
            root_grant.capability_grant_id().unwrap(),
            child_grant,
            root_device,
            leaf_device,
            current_context,
            Timestamp::from_unix_millis(60),
            [9; 16],
            Extensions::default(),
        )
        .unwrap(),
        ProtocolSignature::ed25519([9; 64]),
    );
    let chain = DelegationChain::new(
        krikos_identity::CapabilityRoot::new(
            old_context,
            root_device,
            root_grant.clone(),
            Extensions::default(),
        )
        .unwrap(),
        vec![link],
    )
    .unwrap();
    let root_grant_id = root_grant.capability_grant_id().unwrap();
    let mut state = TestState::active(current_context, root_device, vec![root_grant]);
    state
        .statuses
        .push((leaf_device, CapabilityDeviceStatus::Active));
    state.recognized_contexts.push(old_context);
    state.context_lineage.push((old_context, current_context));
    state
        .context_times
        .push((old_context, Timestamp::from_unix_millis(60)));

    let capability_request = request(
        current_context,
        leaf_device,
        path(&[b"collection", b"blue"]),
        100,
    );
    assert_eq!(
        evaluate_capability(
            &capability_request,
            CapabilityProof::Delegated(&chain),
            &state,
            &VERIFIED_SIGNATURES,
        )
        .denial_reason(),
        Some(CapabilityDenialReason::RootGrantNotHeldAtContext)
    );

    state
        .historical_holdings
        .push((root_device, root_grant_id, old_context));
    state
        .historical_statuses
        .push((root_device, old_context, CapabilityDeviceStatus::Suspended));
    assert_eq!(
        evaluate_capability(
            &capability_request,
            CapabilityProof::Delegated(&chain),
            &state,
            &VERIFIED_SIGNATURES,
        )
        .denial_reason(),
        Some(CapabilityDenialReason::RootHolderNotActiveAtContext)
    );

    state.historical_statuses[0].2 = CapabilityDeviceStatus::Active;
    state.context_times[0].1 = Timestamp::from_unix_millis(40);
    assert_eq!(
        evaluate_capability(
            &capability_request,
            CapabilityProof::Delegated(&chain),
            &state,
            &VERIFIED_SIGNATURES,
        )
        .denial_reason(),
        Some(CapabilityDenialReason::RootGrantInvalidAtContext)
    );
}

#[test]
fn same_epoch_descendant_context_is_accepted_but_a_sibling_is_denied() {
    let root_device = device_id(58);
    let leaf_device = device_id(59);
    let root_context = AuthorizationContext::new(account_id(1), Epoch::new(5), checkpoint_id(1));
    let descendant_context =
        AuthorizationContext::new(account_id(1), Epoch::new(5), checkpoint_id(2));
    let current_context = AuthorizationContext::new(account_id(1), Epoch::new(5), checkpoint_id(3));
    let root_grant = grant(
        ResourceSelector::prefix(path(&[b"collection"])).unwrap(),
        Vec::new(),
        DelegationPermission::delegable(DelegationDepth::new(1).unwrap()),
        None,
    );
    let child_grant = grant(
        ResourceSelector::exact(path(&[b"collection", b"blue"])).unwrap(),
        Vec::new(),
        DelegationPermission::NotDelegable,
        None,
    );
    let link = SignedDelegation::new(
        DelegationBody::new(
            root_grant.capability_grant_id().unwrap(),
            child_grant,
            root_device,
            leaf_device,
            descendant_context,
            Timestamp::from_unix_millis(10),
            [10; 16],
            Extensions::default(),
        )
        .unwrap(),
        ProtocolSignature::ed25519([10; 64]),
    );
    let chain = DelegationChain::new(
        krikos_identity::CapabilityRoot::new(
            root_context,
            root_device,
            root_grant.clone(),
            Extensions::default(),
        )
        .unwrap(),
        vec![link],
    )
    .unwrap();
    let mut state = TestState::active(current_context, root_device, vec![root_grant]);
    state
        .statuses
        .push((leaf_device, CapabilityDeviceStatus::Active));
    state.record_chain_history(&chain);
    let capability_request = request(
        current_context,
        leaf_device,
        path(&[b"collection", b"blue"]),
        20,
    );

    assert!(
        evaluate_capability(
            &capability_request,
            CapabilityProof::Delegated(&chain),
            &state,
            &VERIFIED_SIGNATURES,
        )
        .is_allowed()
    );

    state
        .context_lineage
        .retain(|pair| *pair != (root_context, descendant_context));
    assert_eq!(
        evaluate_capability(
            &capability_request,
            CapabilityProof::Delegated(&chain),
            &state,
            &VERIFIED_SIGNATURES,
        )
        .denial_reason(),
        Some(CapabilityDenialReason::AuthorizationContextRollback)
    );
}

fn same_epoch_temporal_fixture(
    first_issued_at: u64,
    second_issued_at: u64,
) -> (DelegationChain, TestState, CapabilityRequest) {
    let root_device = device_id(60);
    let middle_device = device_id(61);
    let leaf_device = device_id(62);
    let root_context = context(5, 20);
    let first_context = context(5, 21);
    let second_context = context(5, 22);
    let current_context = context(5, 23);
    let root_grant = grant(
        ResourceSelector::prefix(path(&[b"collection"])).unwrap(),
        Vec::new(),
        DelegationPermission::delegable(DelegationDepth::new(2).unwrap()),
        Some(Timestamp::from_unix_millis(200)),
    );
    let middle_grant = grant(
        ResourceSelector::prefix(path(&[b"collection", b"blue"])).unwrap(),
        Vec::new(),
        DelegationPermission::delegable(DelegationDepth::new(1).unwrap()),
        Some(Timestamp::from_unix_millis(190)),
    );
    let leaf_grant = grant(
        ResourceSelector::exact(path(&[b"collection", b"blue", b"record"])).unwrap(),
        Vec::new(),
        DelegationPermission::NotDelegable,
        Some(Timestamp::from_unix_millis(180)),
    );
    let first = SignedDelegation::new(
        DelegationBody::new(
            root_grant.capability_grant_id().unwrap(),
            middle_grant.clone(),
            root_device,
            middle_device,
            first_context,
            Timestamp::from_unix_millis(first_issued_at),
            [11; 16],
            Extensions::default(),
        )
        .unwrap(),
        ProtocolSignature::ed25519([11; 64]),
    );
    let second = SignedDelegation::new(
        DelegationBody::new(
            middle_grant.capability_grant_id().unwrap(),
            leaf_grant,
            middle_device,
            leaf_device,
            second_context,
            Timestamp::from_unix_millis(second_issued_at),
            [12; 16],
            Extensions::default(),
        )
        .unwrap(),
        ProtocolSignature::ed25519([12; 64]),
    );
    let chain = DelegationChain::new(
        krikos_identity::CapabilityRoot::new(
            root_context,
            root_device,
            root_grant.clone(),
            Extensions::default(),
        )
        .unwrap(),
        vec![first, second],
    )
    .unwrap();
    let mut state = TestState::active(current_context, root_device, vec![root_grant]);
    state.statuses.extend([
        (middle_device, CapabilityDeviceStatus::Active),
        (leaf_device, CapabilityDeviceStatus::Active),
    ]);
    state.record_chain_history(&chain);
    let capability_request = request(
        current_context,
        leaf_device,
        path(&[b"collection", b"blue", b"record"]),
        100,
    );
    (chain, state, capability_request)
}

#[test]
fn delegation_requires_an_authenticated_timestamp_for_every_link_context() {
    for missing_index in 0..2 {
        let (chain, mut state, capability_request) = same_epoch_temporal_fixture(10, 20);
        assert!(
            evaluate_capability(
                &capability_request,
                CapabilityProof::Delegated(&chain),
                &state,
                &VERIFIED_SIGNATURES,
            )
            .is_allowed(),
            "same-epoch temporal fixture must be valid before fault injection"
        );
        let missing_context = chain.links()[missing_index].body().authorization_context();
        state
            .context_times
            .retain(|(context, _)| *context != missing_context);

        assert_eq!(
            evaluate_capability(
                &capability_request,
                CapabilityProof::Delegated(&chain),
                &state,
                &VERIFIED_SIGNATURES,
            )
            .denial_reason(),
            Some(CapabilityDenialReason::DelegationContextTimestampUnavailable),
            "delegation link {missing_index} did not fail with the typed missing-time reason"
        );
    }
}

#[test]
fn same_epoch_context_time_cannot_postdate_claimed_issuance() {
    let (chain, mut state, capability_request) = same_epoch_temporal_fixture(10, 20);
    let first_context = chain.links()[0].body().authorization_context();
    state
        .context_times
        .iter_mut()
        .find(|(context, _)| *context == first_context)
        .unwrap()
        .1 = Timestamp::from_unix_millis(11);

    assert_eq!(
        evaluate_capability(
            &capability_request,
            CapabilityProof::Delegated(&chain),
            &state,
            &VERIFIED_SIGNATURES,
        )
        .denial_reason(),
        Some(CapabilityDenialReason::DelegationIssuedBeforeContext)
    );
}

#[test]
fn same_epoch_delegation_issuance_times_cannot_roll_back() {
    let (chain, state, capability_request) = same_epoch_temporal_fixture(20, 19);

    assert_eq!(
        evaluate_capability(
            &capability_request,
            CapabilityProof::Delegated(&chain),
            &state,
            &VERIFIED_SIGNATURES,
        )
        .denial_reason(),
        Some(CapabilityDenialReason::DelegationIssuanceRollback)
    );
}

#[test]
fn root_context_time_cannot_postdate_first_delegation_issuance() {
    let (chain, mut state, capability_request) = same_epoch_temporal_fixture(10, 20);
    let root_context = chain.root().authorization_context();
    state
        .context_times
        .iter_mut()
        .find(|(context, _)| *context == root_context)
        .unwrap()
        .1 = Timestamp::from_unix_millis(11);

    assert_eq!(
        evaluate_capability(
            &capability_request,
            CapabilityProof::Delegated(&chain),
            &state,
            &VERIFIED_SIGNATURES,
        )
        .denial_reason(),
        Some(CapabilityDenialReason::DelegationIssuanceRollback)
    );
}

#[derive(Debug)]
struct MultiHopFixture {
    chain: DelegationChain,
    state: TestState,
    request: CapabilityRequest,
    grant_ids: Vec<CapabilityGrantId>,
    delegation_ids: Vec<DelegationId>,
}

fn multi_hop_fixture(context_steps: &[u8]) -> MultiHopFixture {
    assert!(
        (2..=4).contains(&context_steps.len()),
        "property fixture delegation depth must remain in 2..=4"
    );
    assert!(
        context_steps.iter().all(|step| (1..=2).contains(step)),
        "property fixture context steps must remain in 1..=2"
    );
    let link_count = context_steps.len();
    let root_device = device_id(70);
    let root_context = context(1, 1);
    let mut resource_segments = vec![b"collection".to_vec()];
    let root_depth = u8::try_from(link_count).unwrap();
    let root_grant = CapabilityGrant::new(
        CapabilityNamespace::new("krikos.database").unwrap(),
        CapabilityAction::new("write").unwrap(),
        ResourceSelector::prefix(ResourcePath::new(resource_segments.clone()).unwrap()).unwrap(),
        vec![
            krikos_identity::CapabilityConstraint::AccountEpochAtLeast(Epoch::new(1)),
            krikos_identity::CapabilityConstraint::AccountEpochAtMost(Epoch::new(100)),
            krikos_identity::CapabilityConstraint::ValidFrom(Timestamp::from_unix_millis(1)),
        ],
        DelegationPermission::delegable(DelegationDepth::new(root_depth).unwrap()),
        Some(Timestamp::from_unix_millis(1_000)),
        Extensions::default(),
    )
    .unwrap();
    let root = krikos_identity::CapabilityRoot::new(
        root_context,
        root_device,
        root_grant.clone(),
        Extensions::default(),
    )
    .unwrap();

    let mut links = Vec::with_capacity(link_count);
    let mut grant_ids = vec![root_grant.capability_grant_id().unwrap()];
    let mut delegation_ids = Vec::with_capacity(link_count);
    let mut parent_grant = root_grant.clone();
    let mut issuer = root_device;
    let mut previous_context = root_context;

    for (index, context_step) in context_steps.iter().copied().enumerate() {
        let ordinal = u64::try_from(index).unwrap().checked_add(1).unwrap();
        resource_segments.push(vec![u8::try_from(index).unwrap()]);
        let links_remaining = link_count
            .checked_sub(index)
            .unwrap()
            .checked_sub(1)
            .unwrap();
        let delegation = if links_remaining == 0 {
            DelegationPermission::NotDelegable
        } else {
            DelegationPermission::delegable(
                DelegationDepth::new(u8::try_from(links_remaining).unwrap()).unwrap(),
            )
        };
        let selector = if links_remaining == 0 {
            ResourceSelector::exact(ResourcePath::new(resource_segments.clone()).unwrap()).unwrap()
        } else {
            ResourceSelector::prefix(ResourcePath::new(resource_segments.clone()).unwrap()).unwrap()
        };
        let child_grant = CapabilityGrant::new(
            CapabilityNamespace::new("krikos.database").unwrap(),
            CapabilityAction::new("write").unwrap(),
            selector,
            vec![
                krikos_identity::CapabilityConstraint::AccountEpochAtLeast(Epoch::new(
                    1_u64.checked_add(ordinal).unwrap(),
                )),
                krikos_identity::CapabilityConstraint::AccountEpochAtMost(Epoch::new(
                    100_u64.checked_sub(ordinal).unwrap(),
                )),
                krikos_identity::CapabilityConstraint::ValidFrom(Timestamp::from_unix_millis(
                    1_u64.checked_add(ordinal).unwrap(),
                )),
            ],
            delegation,
            Some(Timestamp::from_unix_millis(
                1_000_u64
                    .checked_sub(ordinal.checked_mul(10).unwrap())
                    .unwrap(),
            )),
            Extensions::default(),
        )
        .unwrap();
        let next_epoch = Epoch::new(
            previous_context
                .epoch()
                .get()
                .checked_add(u64::from(context_step))
                .unwrap(),
        );
        let issuance_context = AuthorizationContext::new(
            account_id(1),
            next_epoch,
            checkpoint_id(u8::try_from(next_epoch.get()).unwrap()),
        );
        let subject = device_id(
            u8::try_from(70_usize.checked_add(index).unwrap().checked_add(1).unwrap()).unwrap(),
        );
        let body = DelegationBody::new(
            parent_grant.capability_grant_id().unwrap(),
            child_grant.clone(),
            issuer,
            subject,
            issuance_context,
            Timestamp::from_unix_millis(100_u64.checked_add(ordinal).unwrap()),
            [u8::try_from(index).unwrap(); 16],
            Extensions::default(),
        )
        .unwrap();
        let link = SignedDelegation::new(
            body,
            ProtocolSignature::ed25519([u8::try_from(index).unwrap(); 64]),
        );
        grant_ids.push(child_grant.capability_grant_id().unwrap());
        delegation_ids.push(link.delegation_id().unwrap());
        links.push(link);
        parent_grant = child_grant;
        issuer = subject;
        previous_context = issuance_context;
    }

    let chain = DelegationChain::new(root, links).unwrap();
    let current_epoch = previous_context.epoch().checked_next().unwrap();
    let current_context = AuthorizationContext::new(
        account_id(1),
        current_epoch,
        checkpoint_id(u8::try_from(current_epoch.get()).unwrap()),
    );
    let leaf_device = chain.leaf_holder();
    let mut state = TestState::active(current_context, root_device, vec![root_grant]);
    for seed in 1..=link_count {
        state.statuses.push((
            device_id(u8::try_from(70_usize.checked_add(seed).unwrap()).unwrap()),
            CapabilityDeviceStatus::Active,
        ));
    }
    state.record_chain_history(&chain);
    let request = request(
        current_context,
        leaf_device,
        ResourcePath::new(resource_segments).unwrap(),
        500,
    );

    MultiHopFixture {
        chain,
        state,
        request,
        grant_ids,
        delegation_ids,
    }
}

fn broadened_chain(dimension: u8) -> Result<DelegationChain, IdentityError> {
    let basis = context(6, 6);
    let root_device = device_id(80);
    let leaf_device = device_id(81);
    let root_grant = CapabilityGrant::new(
        CapabilityNamespace::new("krikos.database").unwrap(),
        CapabilityAction::new("write").unwrap(),
        ResourceSelector::prefix(path(&[b"collection", b"blue"])).unwrap(),
        vec![
            krikos_identity::CapabilityConstraint::AccountEpochAtLeast(Epoch::new(5)),
            krikos_identity::CapabilityConstraint::AccountEpochAtMost(Epoch::new(10)),
            krikos_identity::CapabilityConstraint::ValidFrom(Timestamp::from_unix_millis(50)),
        ],
        DelegationPermission::delegable(DelegationDepth::new(2).unwrap()),
        Some(Timestamp::from_unix_millis(200)),
        Extensions::default(),
    )
    .unwrap();

    let namespace = if dimension == 0 {
        CapabilityNamespace::new("krikos.other").unwrap()
    } else {
        CapabilityNamespace::new("krikos.database").unwrap()
    };
    let action = if dimension == 1 {
        CapabilityAction::new("read").unwrap()
    } else {
        CapabilityAction::new("write").unwrap()
    };
    let selector = if dimension == 2 {
        ResourceSelector::prefix(path(&[b"collection"])).unwrap()
    } else {
        ResourceSelector::exact(path(&[b"collection", b"blue", b"record"])).unwrap()
    };
    let minimum_epoch = if dimension == 3 { 4 } else { 6 };
    let maximum_epoch = if dimension == 4 { 11 } else { 9 };
    let valid_from = if dimension == 5 { 40 } else { 60 };
    let expiration = if dimension == 6 { 210 } else { 190 };
    let delegation = if dimension == 7 {
        DelegationPermission::delegable(DelegationDepth::new(2).unwrap())
    } else {
        DelegationPermission::delegable(DelegationDepth::new(1).unwrap())
    };
    let child_grant = CapabilityGrant::new(
        namespace,
        action,
        selector,
        vec![
            krikos_identity::CapabilityConstraint::AccountEpochAtLeast(Epoch::new(minimum_epoch)),
            krikos_identity::CapabilityConstraint::AccountEpochAtMost(Epoch::new(maximum_epoch)),
            krikos_identity::CapabilityConstraint::ValidFrom(Timestamp::from_unix_millis(
                valid_from,
            )),
        ],
        delegation,
        Some(Timestamp::from_unix_millis(expiration)),
        Extensions::default(),
    )
    .unwrap();
    let link = SignedDelegation::new(
        DelegationBody::new(
            root_grant.capability_grant_id().unwrap(),
            child_grant,
            root_device,
            leaf_device,
            basis,
            Timestamp::from_unix_millis(100),
            [dimension; 16],
            Extensions::default(),
        )
        .unwrap(),
        ProtocolSignature::ed25519([dimension; 64]),
    );
    DelegationChain::new(
        krikos_identity::CapabilityRoot::new(basis, root_device, root_grant, Extensions::default())
            .unwrap(),
        vec![link],
    )
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn multi_hop_all_dimension_narrowing_with_monotonic_contexts_is_authorized(
        context_steps in prop::collection::vec(1_u8..=2, 2..5),
    ) {
        let fixture = multi_hop_fixture(&context_steps);
        let decision = evaluate_capability(
            &fixture.request,
            CapabilityProof::Delegated(&fixture.chain),
            &fixture.state,
            &VERIFIED_SIGNATURES,
        );
        prop_assert!(decision.is_allowed());
    }

    #[test]
    fn broadening_any_capability_dimension_is_rejected(dimension in 0_u8..8) {
        let rejected = matches!(
            broadened_chain(dimension),
            Err(IdentityError::InvalidDelegation { .. })
        );
        prop_assert!(rejected, "broadening dimension {dimension} was accepted");
    }

    #[test]
    fn revoking_any_grant_or_link_in_a_multi_hop_chain_denies(
        context_steps in prop::collection::vec(1_u8..=2, 2..5),
        selector in any::<u8>(),
    ) {
        let mut fixture = multi_hop_fixture(&context_steps);
        let revocable_count = fixture
            .grant_ids
            .len()
            .checked_add(fixture.delegation_ids.len())
            .unwrap();
        let selected = usize::from(selector) % revocable_count;
        if let Some(grant_id) = fixture.grant_ids.get(selected) {
            fixture.state.revoked_grants.push(*grant_id);
        } else {
            let link_index = selected.checked_sub(fixture.grant_ids.len()).unwrap();
            fixture
                .state
                .revoked_delegations
                .push(*fixture.delegation_ids.get(link_index).unwrap());
        }

        let decision = evaluate_capability(
            &fixture.request,
            CapabilityProof::Delegated(&fixture.chain),
            &fixture.state,
            &VERIFIED_SIGNATURES,
        );
        prop_assert!(!decision.is_allowed());
        prop_assert!(matches!(
            decision.denial_reason(),
            Some(
                CapabilityDenialReason::GrantRevoked
                    | CapabilityDenialReason::ParentGrantRevoked
                    | CapabilityDenialReason::DelegationRevoked
            )
        ));
    }
}
