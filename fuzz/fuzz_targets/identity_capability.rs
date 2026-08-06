#![no_main]

use krikos_identity::{
    AccountId, ApplicationId, AuthorizationContext, CanonicalWire, CapabilityAction,
    CapabilityDenialReason, CapabilityDeviceStatus, CapabilityGrant, CapabilityGrantId,
    CapabilityNamespace, CapabilityProof, CapabilityRequest, CapabilityStateView, CheckpointId,
    DelegationBody, DelegationChain, DelegationDepth, DelegationId, DelegationPermission,
    DelegationSignatureStatus, DelegationSignatureVerifier, DeviceId, Digest, Epoch, Extensions,
    HashAlgorithm, ProtocolSignature, ResourcePath, ResourceSelector, SignedDelegation, Timestamp,
    evaluate_capability,
    limits::{MAX_CAPABILITIES_PER_DEVICE, MAX_DELEGATION_DEPTH},
};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_INPUT_BYTES: usize = 64;

#[derive(Debug, Default, Clone, Copy)]
struct InjectedFaults {
    invalid_signature: bool,
    revoked_authority: bool,
    missing_possession: bool,
    inactive_authority: bool,
    missing_lineage: bool,
    sibling_context: bool,
    missing_context_timestamp: bool,
    context_time_backdating: bool,
    issuance_time_rollback: bool,
    future_issuance: bool,
    request_basis_mismatch: bool,
    scope_mismatch: bool,
    request_after_expiry: bool,
    oversized_state_view: bool,
}

impl InjectedFaults {
    fn requires_denial(self) -> bool {
        self.invalid_signature
            || self.revoked_authority
            || self.missing_possession
            || self.inactive_authority
            || self.missing_lineage
            || self.sibling_context
            || self.missing_context_timestamp
            || self.context_time_backdating
            || self.issuance_time_rollback
            || self.future_issuance
            || self.request_basis_mismatch
            || self.scope_mismatch
            || self.request_after_expiry
            || self.oversized_state_view
    }
}

#[derive(Debug)]
struct FuzzState {
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

impl CapabilityStateView for FuzzState {
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
        ancestor.account_id() == descendant.account_id()
            && self.recognized_contexts.contains(&ancestor)
            && self.recognized_contexts.contains(&descendant)
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
struct FuzzSignatures(DelegationSignatureStatus);

impl DelegationSignatureVerifier for FuzzSignatures {
    fn verify_delegation(&self, _delegation: &SignedDelegation) -> DelegationSignatureStatus {
        self.0
    }
}

fn byte(input: &[u8], index: usize) -> u8 {
    input.get(index).copied().unwrap_or(0)
}

fn digest(seed: u8) -> Digest {
    Digest::new(HashAlgorithm::Blake3_256, [seed; 32])
}

fn account_id(seed: u8) -> Option<AccountId> {
    let encoded = digest(seed).to_canonical_bytes().ok()?;
    AccountId::from_canonical_bytes(&encoded).ok()
}

fn checkpoint_id(seed: u8) -> Option<CheckpointId> {
    let encoded = digest(seed).to_canonical_bytes().ok()?;
    CheckpointId::from_canonical_bytes(&encoded).ok()
}

fn device_id(seed: u8) -> Option<DeviceId> {
    let encoded = digest(seed).to_canonical_bytes().ok()?;
    DeviceId::from_canonical_bytes(&encoded).ok()
}

fn context(account_id: AccountId, epoch: u64, checkpoint_seed: u8) -> Option<AuthorizationContext> {
    Some(AuthorizationContext::new(
        account_id,
        Epoch::new(epoch),
        checkpoint_id(checkpoint_seed)?,
    ))
}

fn replace_context_timestamp(
    state: &mut FuzzState,
    context: AuthorizationContext,
    timestamp: Timestamp,
) {
    if let Some((_, stored_timestamp)) = state
        .context_times
        .iter_mut()
        .find(|(candidate, _)| *candidate == context)
    {
        *stored_timestamp = timestamp;
    }
}

fn replace_device_status(
    state: &mut FuzzState,
    device_id: DeviceId,
    status: CapabilityDeviceStatus,
) {
    if let Some((_, stored_status)) = state
        .statuses
        .iter_mut()
        .find(|(candidate, _)| *candidate == device_id)
    {
        *stored_status = status;
    }
}

fn drive(input: &[u8]) -> Option<()> {
    let account_id = account_id(1)?;
    let application_id = ApplicationId::new(digest(2));
    let root_holder = device_id(10)?;
    let root_context = context(account_id, 1, 1)?;
    let current_context = context(account_id, 64, 64)?;
    let depth = 1_usize.checked_add(usize::from(byte(input, 0)) % MAX_DELEGATION_DEPTH)?;
    let root_depth = DelegationDepth::new(u8::try_from(depth).ok()?).ok()?;
    let namespace = CapabilityNamespace::new("krikos.database").ok()?;
    let action = CapabilityAction::new("write").ok()?;
    let mut segments = vec![b"collection".to_vec()];
    let root_grant = CapabilityGrant::new(
        namespace.clone(),
        action.clone(),
        ResourceSelector::prefix(ResourcePath::new(segments.clone()).ok()?).ok()?,
        vec![
            krikos_identity::CapabilityConstraint::AccountEpochAtLeast(Epoch::new(1)),
            krikos_identity::CapabilityConstraint::AccountEpochAtMost(Epoch::new(64)),
            krikos_identity::CapabilityConstraint::ValidFrom(Timestamp::from_unix_millis(0)),
        ],
        DelegationPermission::delegable(root_depth),
        Some(Timestamp::from_unix_millis(1_000)),
        Extensions::default(),
    )
    .ok()?;
    let root = krikos_identity::CapabilityRoot::new(
        root_context,
        root_holder,
        root_grant.clone(),
        Extensions::default(),
    )
    .ok()?;

    let mut links = Vec::with_capacity(depth);
    let mut grant_ids = vec![root_grant.capability_grant_id().ok()?];
    let mut delegation_ids = Vec::with_capacity(depth);
    let mut contexts = vec![root_context];
    let mut holders = vec![root_holder];
    let mut parent = root_grant.clone();
    let mut issuer = root_holder;
    let mut previous_context = root_context;
    let mut previous_issued_at = Timestamp::from_unix_millis(0);
    let context_fault_index = usize::from(byte(input, 1)) % depth;
    let same_epoch_context_requested = byte(input, 2) & 1 != 0;
    let future_issuance_requested = byte(input, 3) & 1 != 0;
    let missing_lineage_requested = byte(input, 4) & 1 != 0;
    let issuance_rollback_index = if depth > 1 && byte(input, 20) & 1 != 0 {
        Some(1_usize.checked_add(usize::from(byte(input, 1)) % depth.checked_sub(1)?)?)
    } else {
        None
    };
    let mut issuance_rollback_injected = false;

    for index in 0..depth {
        segments.push(vec![u8::try_from(index).ok()?]);
        let remaining = depth.checked_sub(index)?.checked_sub(1)?;
        let delegation = if remaining == 0 {
            DelegationPermission::NotDelegable
        } else {
            DelegationPermission::delegable(
                DelegationDepth::new(u8::try_from(remaining).ok()?).ok()?,
            )
        };
        let selector = if remaining == 0 {
            ResourceSelector::exact(ResourcePath::new(segments.clone()).ok()?).ok()?
        } else {
            ResourceSelector::prefix(ResourcePath::new(segments.clone()).ok()?).ok()?
        };
        let ordinal = u64::try_from(index).ok()?.checked_add(1)?;
        let child = CapabilityGrant::new(
            namespace.clone(),
            action.clone(),
            selector,
            vec![
                krikos_identity::CapabilityConstraint::AccountEpochAtLeast(Epoch::new(1)),
                krikos_identity::CapabilityConstraint::AccountEpochAtMost(Epoch::new(64)),
                krikos_identity::CapabilityConstraint::ValidFrom(Timestamp::from_unix_millis(0)),
            ],
            delegation,
            Some(Timestamp::from_unix_millis(1_000_u64.checked_sub(ordinal)?)),
            Extensions::default(),
        )
        .ok()?;
        let normal_epoch = previous_context.epoch().get().checked_add(1)?;
        let link_context = if index == context_fault_index && same_epoch_context_requested {
            context(
                account_id,
                previous_context.epoch().get(),
                u8::try_from(index.checked_add(100)?).ok()?,
            )?
        } else {
            context(
                account_id,
                normal_epoch,
                u8::try_from(index.checked_add(2)?).ok()?,
            )?
        };
        let subject = device_id(u8::try_from(index.checked_add(11)?).ok()?)?;
        let future_issuance = index == context_fault_index && future_issuance_requested;
        let issuance_rollback = issuance_rollback_index == Some(index) && !future_issuance;
        let issued_at = if future_issuance {
            Timestamp::from_unix_millis(2_000)
        } else if issuance_rollback {
            issuance_rollback_injected = true;
            Timestamp::from_unix_millis(previous_issued_at.as_unix_millis().checked_sub(1)?)
        } else {
            Timestamp::from_unix_millis(10_u64.checked_add(ordinal)?)
        };
        let body = DelegationBody::new(
            parent.capability_grant_id().ok()?,
            child.clone(),
            issuer,
            subject,
            link_context,
            issued_at,
            [u8::try_from(index).ok()?; 16],
            Extensions::default(),
        )
        .ok()?;
        let link = SignedDelegation::new(
            body,
            ProtocolSignature::ed25519([u8::try_from(index).ok()?; 64]),
        );
        grant_ids.push(child.capability_grant_id().ok()?);
        delegation_ids.push(link.delegation_id().ok()?);
        contexts.push(link_context);
        holders.push(subject);
        links.push(link);
        parent = child;
        issuer = subject;
        previous_context = link_context;
        previous_issued_at = issued_at;
    }
    let chain = DelegationChain::new(root, links).ok()?;

    let mut state = FuzzState {
        authorization_context: current_context,
        statuses: holders
            .iter()
            .copied()
            .map(|holder| (holder, CapabilityDeviceStatus::Active))
            .collect(),
        root_holder,
        root_grants: vec![root_grant.clone()],
        revoked_grants: Vec::new(),
        revoked_delegations: Vec::new(),
        recognized_contexts: contexts.clone(),
        context_lineage: Vec::new(),
        context_times: Vec::new(),
        historical_statuses: Vec::new(),
        historical_holdings: Vec::new(),
    };
    state.recognized_contexts.push(current_context);
    for (index, context) in contexts.iter().enumerate() {
        state.context_lineage.push((*context, current_context));
        let timestamp = if index == 0 {
            Timestamp::from_unix_millis(0)
        } else {
            chain.links().get(index.checked_sub(1)?)?.body().issued_at()
        };
        state.context_times.push((*context, timestamp));
    }
    for index in 0..depth {
        let ancestor = *contexts.get(index)?;
        let descendant = *contexts.get(index.checked_add(1)?)?;
        if index != context_fault_index || !missing_lineage_requested {
            state.context_lineage.push((ancestor, descendant));
        }
        let holder = *holders.get(index)?;
        let status = if index == context_fault_index && byte(input, 5) & 1 != 0 {
            CapabilityDeviceStatus::Suspended
        } else {
            CapabilityDeviceStatus::Active
        };
        state.historical_statuses.push((holder, descendant, status));
        if index != context_fault_index || byte(input, 6) & 1 == 0 {
            state
                .historical_holdings
                .push((holder, *grant_ids.get(index)?, descendant));
        }
    }
    let root_status = if byte(input, 7) & 1 == 0 {
        CapabilityDeviceStatus::Active
    } else {
        CapabilityDeviceStatus::Suspended
    };
    state
        .historical_statuses
        .push((root_holder, root_context, root_status));
    if byte(input, 8) & 1 == 0 {
        state
            .historical_holdings
            .push((root_holder, *grant_ids.first()?, root_context));
    }
    let root_timestamp_missing = byte(input, 9) & 1 != 0;
    let root_issuance_rollback = !root_timestamp_missing && byte(input, 9) & 2 != 0;
    if root_timestamp_missing {
        state
            .context_times
            .retain(|(context, _)| *context != root_context);
    } else if root_issuance_rollback {
        let first_issued_at = chain.links().first()?.body().issued_at();
        replace_context_timestamp(
            &mut state,
            root_context,
            Timestamp::from_unix_millis(first_issued_at.as_unix_millis().checked_add(1)?),
        );
    }

    let selected_link = chain.links().get(context_fault_index)?;
    let selected_link_context = selected_link.body().authorization_context();
    let link_timestamp_missing = byte(input, 18) & 1 != 0;
    let context_time_backdating = !link_timestamp_missing && byte(input, 19) & 1 != 0;
    if link_timestamp_missing {
        state
            .context_times
            .retain(|(context, _)| *context != selected_link_context);
    } else if context_time_backdating {
        replace_context_timestamp(
            &mut state,
            selected_link_context,
            Timestamp::from_unix_millis(
                selected_link
                    .body()
                    .issued_at()
                    .as_unix_millis()
                    .checked_add(1)?,
            ),
        );
    }

    let oversized_state_view = byte(input, 21) & 1 != 0;
    if oversized_state_view {
        state
            .root_grants
            .resize(MAX_CAPABILITIES_PER_DEVICE.checked_add(1)?, root_grant);
    }

    let direct = byte(input, 12) & 1 == 0;
    let revocation_index = usize::from(byte(input, 10));
    let mut revoked_authority = false;
    if byte(input, 11) & 1 != 0 {
        if byte(input, 11) & 2 == 0 {
            let selected_index = revocation_index % grant_ids.len();
            state.revoked_grants.push(*grant_ids.get(selected_index)?);
            revoked_authority = !direct || selected_index == 0;
        } else {
            state
                .revoked_delegations
                .push(*delegation_ids.get(revocation_index % delegation_ids.len())?);
            revoked_authority = !direct;
        }
    }

    let requesting_device = if direct {
        root_holder
    } else {
        chain.leaf_holder()
    };
    if byte(input, 13) & 1 != 0 {
        let status = if byte(input, 13) & 2 == 0 {
            CapabilityDeviceStatus::Suspended
        } else {
            CapabilityDeviceStatus::Revoked
        };
        replace_device_status(&mut state, requesting_device, status);
    }
    let request_context = if byte(input, 14) & 1 != 0 {
        context(account_id, 63, 63)?
    } else if byte(input, 14) & 2 != 0 {
        context(account_id, 64, 63)?
    } else {
        current_context
    };
    let request_namespace = if byte(input, 15) & 1 == 0 {
        namespace
    } else {
        CapabilityNamespace::new("krikos.other").ok()?
    };
    let request_action = if byte(input, 15) & 2 == 0 {
        action
    } else {
        CapabilityAction::new("read").ok()?
    };
    let request_path = if byte(input, 15) & 4 == 0 {
        if direct {
            ResourcePath::new(vec![b"collection".to_vec()]).ok()?
        } else {
            ResourcePath::new(segments).ok()?
        }
    } else {
        ResourcePath::new(vec![b"other".to_vec()]).ok()?
    };
    let evaluated_at = if byte(input, 16) & 1 == 0 {
        Timestamp::from_unix_millis(500)
    } else {
        Timestamp::from_unix_millis(2_000)
    };
    let request = CapabilityRequest::new(
        request_context,
        application_id,
        requesting_device,
        request_namespace,
        request_action,
        request_path,
        evaluated_at,
    );
    let signature_status = match byte(input, 17) % 3 {
        0 => DelegationSignatureStatus::Verified,
        1 => DelegationSignatureStatus::Invalid,
        _ => DelegationSignatureStatus::Unavailable,
    };
    let delegated = !direct;
    let faults = InjectedFaults {
        invalid_signature: delegated && signature_status != DelegationSignatureStatus::Verified,
        revoked_authority,
        missing_possession: delegated && (byte(input, 6) & 1 != 0 || byte(input, 8) & 1 != 0),
        inactive_authority: byte(input, 13) & 1 != 0
            || (delegated && (byte(input, 5) & 1 != 0 || byte(input, 7) & 1 != 0)),
        missing_lineage: delegated && missing_lineage_requested,
        sibling_context: delegated && same_epoch_context_requested && missing_lineage_requested,
        missing_context_timestamp: delegated && (root_timestamp_missing || link_timestamp_missing),
        context_time_backdating: delegated && context_time_backdating,
        issuance_time_rollback: delegated && (root_issuance_rollback || issuance_rollback_injected),
        future_issuance: delegated && future_issuance_requested,
        request_basis_mismatch: request_context != current_context,
        scope_mismatch: byte(input, 15) & 7 != 0,
        request_after_expiry: byte(input, 16) & 1 != 0,
        oversized_state_view,
    };
    let proof = if direct {
        CapabilityProof::Direct
    } else {
        CapabilityProof::Delegated(&chain)
    };
    let decision = evaluate_capability(&request, proof, &state, &FuzzSignatures(signature_status));
    assert_eq!(decision.checkpoint_id(), request_context.checkpoint_id());
    assert_eq!(decision.epoch(), request_context.epoch());
    assert_eq!(decision.is_allowed(), decision.denial_reason().is_none());
    if oversized_state_view
        && request_context == current_context
        && state.device_status(requesting_device) == CapabilityDeviceStatus::Active
    {
        assert_eq!(
            decision.denial_reason(),
            Some(CapabilityDenialReason::StateViewLimitExceeded),
            "over-limit root grant slice must fail at the evaluator bound"
        );
    }
    if faults.requires_denial() {
        assert!(
            !decision.is_allowed(),
            "fault-injected capability proof was authorized: {faults:?}"
        );
    }
    if delegated && !faults.requires_denial() {
        assert!(
            decision.is_allowed(),
            "pristine delegated capability proof was denied: {:?}",
            decision.denial_reason()
        );
    }
    if decision.is_allowed() {
        assert!(decision.grant_id().is_some());
    }
    Some(())
}

fuzz_target!(|input: &[u8]| {
    if input.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }
    let _ = drive(input);
});
