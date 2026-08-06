//! Deterministic, default-deny capability and delegation evaluation.

use crate::{
    AccountId, ApplicationId, AuthorizationContext, CapabilityAction, CapabilityConstraint,
    CapabilityGrant, CapabilityGrantId, CapabilityNamespace, CheckpointId, DelegationChain,
    DelegationId, DelegationPermission, DeviceId, Epoch, ResourcePath, ResourceSelector,
    SignedDelegation, Timestamp,
    limits::{MAX_CAPABILITIES_PER_DEVICE, MAX_DELEGATION_DEPTH},
};

/// Current lifecycle status of a device in the supplied authorization projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CapabilityDeviceStatus {
    /// The device does not exist in the supplied projection.
    Unknown,
    /// The device is currently authorized to exercise capabilities.
    Active,
    /// The device is temporarily unable to exercise capabilities.
    Suspended,
    /// The device is permanently unable to exercise capabilities.
    Revoked,
}

/// Result of checking a delegation signature at the caller-owned cryptographic boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DelegationSignatureStatus {
    /// The signature was cryptographically verified with the issuer key valid for its context.
    Verified,
    /// Cryptographic verification completed and rejected the signature.
    Invalid,
    /// Verification could not be performed with the available keys or algorithms.
    Unavailable,
}

/// Cryptographic verification seam required for every delegated capability link.
///
/// The capability evaluator intentionally owns no key lookup, clock, or mutable state. An
/// implementation must resolve the issuer key that was valid at the delegation body's explicit
/// authorization context and verify the signature over that exact canonical body. Returning
/// [`DelegationSignatureStatus::Unavailable`] is fail-closed.
pub trait DelegationSignatureVerifier {
    /// Verify one signed delegation without inferring authority from the signature alone.
    fn verify_delegation(&self, delegation: &SignedDelegation) -> DelegationSignatureStatus;
}

/// Read-only authorization facts consumed by capability evaluation.
///
/// Implementations are trusted projections of already-validated account history. They must not
/// perform network or wall-clock access. Returned root-grant slices are peer-controlled protocol
/// state and are therefore re-bounded by the evaluator.
pub trait CapabilityStateView {
    /// Exact current account/checkpoint/epoch basis represented by this view.
    fn authorization_context(&self) -> AuthorizationContext;

    /// Current status of the named device, or [`CapabilityDeviceStatus::Unknown`].
    fn device_status(&self, device_id: DeviceId) -> CapabilityDeviceStatus;

    /// Currently installed root grants for the named device.
    fn root_grants(&self, holder: DeviceId) -> &[CapabilityGrant];

    /// Whether account state has revoked this grant identifier.
    fn is_grant_revoked(&self, grant_id: CapabilityGrantId) -> bool;

    /// Whether account state has revoked this exact delegation link.
    fn is_delegation_revoked(&self, delegation_id: DelegationId) -> bool;

    /// Whether a historical authorization context is an authenticated context on the accepted
    /// lineage represented by this view.
    fn recognizes_authorization_context(&self, context: AuthorizationContext) -> bool;

    /// Whether `ancestor` and `descendant` have authenticated predecessor lineage in this view.
    /// Equal contexts must return `true`.
    fn authorization_context_precedes_or_equals(
        &self,
        ancestor: AuthorizationContext,
        descendant: AuthorizationContext,
    ) -> bool;

    /// Authenticated wall-clock time carried by or proven for this historical context.
    fn authorization_context_timestamp(&self, context: AuthorizationContext) -> Option<Timestamp>;

    /// Historical lifecycle status authenticated at an accepted authorization context.
    fn device_status_at(
        &self,
        device_id: DeviceId,
        context: AuthorizationContext,
    ) -> CapabilityDeviceStatus;

    /// Whether the device held this exact grant at the authenticated historical context.
    fn held_grant_at(
        &self,
        holder: DeviceId,
        grant_id: CapabilityGrantId,
        context: AuthorizationContext,
    ) -> bool;
}

/// One bounded capability request evaluated at an explicit authorization basis and time.
///
/// Namespace, action, and resource bounds are enforced by their validated schema types before a
/// request can exist. The application identifier is retained in the decision for audit binding;
/// v1 capability grants select applications through their exact namespace rather than by digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRequest {
    authorization_context: AuthorizationContext,
    application_id: ApplicationId,
    device_id: DeviceId,
    namespace: CapabilityNamespace,
    action: CapabilityAction,
    resource: ResourcePath,
    evaluated_at: Timestamp,
}

impl CapabilityRequest {
    /// Construct a request entirely from already-bounded domain values.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        authorization_context: AuthorizationContext,
        application_id: ApplicationId,
        device_id: DeviceId,
        namespace: CapabilityNamespace,
        action: CapabilityAction,
        resource: ResourcePath,
        evaluated_at: Timestamp,
    ) -> Self {
        Self {
            authorization_context,
            application_id,
            device_id,
            namespace,
            action,
            resource,
            evaluated_at,
        }
    }

    /// Explicit account/checkpoint/epoch basis requested by the caller.
    pub const fn authorization_context(&self) -> AuthorizationContext {
        self.authorization_context
    }

    /// Account named by the request basis.
    pub const fn account_id(&self) -> AccountId {
        self.authorization_context.account_id()
    }

    /// Application interpreting the authorized operation.
    pub const fn application_id(&self) -> ApplicationId {
        self.application_id
    }

    /// Device attempting to exercise authority.
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Exact requested capability namespace.
    pub const fn namespace(&self) -> &CapabilityNamespace {
        &self.namespace
    }

    /// Exact requested capability action.
    pub const fn action(&self) -> &CapabilityAction {
        &self.action
    }

    /// Requested structured resource path.
    pub const fn resource(&self) -> &ResourcePath {
        &self.resource
    }

    /// Explicit evaluation time supplied by the caller's effect boundary.
    pub const fn evaluated_at(&self) -> Timestamp {
        self.evaluated_at
    }
}

/// Evidence path by which a request claims a capability.
#[derive(Debug, Clone, Copy)]
pub enum CapabilityProof<'a> {
    /// Match a root grant installed directly for the requesting device.
    Direct,
    /// Match the leaf of this complete, parent-to-child delegation chain.
    Delegated(&'a DelegationChain),
}

/// Stable reason that a capability request was denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CapabilityDenialReason {
    /// The request and supplied state view name different accounts.
    AccountMismatch,
    /// The request epoch differs from the supplied state view's exact epoch.
    EpochMismatch,
    /// The request checkpoint differs from the supplied state view's exact checkpoint.
    CheckpointMismatch,
    /// No such device exists in the supplied state view.
    UnknownDevice,
    /// The requesting device is suspended.
    DeviceSuspended,
    /// The requesting device is terminally revoked.
    DeviceRevoked,
    /// A state-view collection exceeded its protocol maximum.
    StateViewLimitExceeded,
    /// No root grant was installed for the requested proof.
    NoMatchingGrant,
    /// Candidate grants did not contain the exact requested namespace.
    NamespaceNotGranted,
    /// Candidate grants did not contain the exact requested action.
    ActionNotGranted,
    /// Candidate selectors did not contain the complete requested resource path.
    ResourceNotGranted,
    /// At least one typed conjunctive grant constraint was not satisfied.
    ConstraintUnsatisfied,
    /// The otherwise matching grant reached its exclusive expiration bound.
    GrantExpired,
    /// The otherwise matching leaf or direct grant has been revoked.
    GrantRevoked,
    /// A parent grant in a delegation chain has been revoked.
    ParentGrantRevoked,
    /// A delegation link has been revoked.
    DelegationRevoked,
    /// A chain was malformed, cyclic, out of order, or did not strictly narrow authority.
    InvalidDelegationChain,
    /// A chain context is not an authenticated accepted context in the supplied state view.
    UnrecognizedAuthorizationContext,
    /// A delegation was issued after the request's explicit evaluation time.
    DelegationNotYetValid,
    /// A later link names an authorization context preceding its parent link's context.
    AuthorizationContextRollback,
    /// The issuer was not active at the exact context claimed by the delegation body.
    IssuerNotActiveAtIssuance,
    /// The issuer did not hold the exact parent grant at the claimed issuance context.
    ParentGrantNotHeldAtIssuance,
    /// The parent grant's epoch, valid-from, or expiry rules failed at issuance.
    ParentGrantInvalidAtIssuance,
    /// The root holder did not hold the root grant at the root's historical context.
    RootGrantNotHeldAtContext,
    /// The root holder was not active at the root's historical context.
    RootHolderNotActiveAtContext,
    /// The root context has no authenticated timestamp in the supplied state view.
    RootContextTimestampUnavailable,
    /// The root grant's epoch, valid-from, or expiry rules failed at its historical context.
    RootGrantInvalidAtContext,
    /// A delegation context has no authenticated timestamp in the supplied state view.
    DelegationContextTimestampUnavailable,
    /// A delegation claims issuance before its authenticated authorization-context timestamp.
    DelegationIssuedBeforeContext,
    /// Delegation issuance time moved backward from the root context or preceding link.
    DelegationIssuanceRollback,
    /// Cryptographic verification rejected a delegation signature.
    InvalidDelegationSignature,
    /// Required delegation signature verification was unavailable.
    SignatureVerificationUnavailable,
    /// A content identifier could not be derived from validated evidence.
    InvalidCapabilityEvidence,
}

/// Default-deny result bound to the request's exact checkpoint and epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityDecision {
    authorization_context: AuthorizationContext,
    application_id: ApplicationId,
    device_id: DeviceId,
    outcome: CapabilityOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CapabilityOutcome {
    Allowed {
        grant_id: CapabilityGrantId,
        delegation_id: Option<DelegationId>,
    },
    Denied(CapabilityDenialReason),
}

impl CapabilityDecision {
    fn allowed(
        request: &CapabilityRequest,
        grant_id: CapabilityGrantId,
        delegation_id: Option<DelegationId>,
    ) -> Self {
        Self {
            authorization_context: request.authorization_context(),
            application_id: request.application_id(),
            device_id: request.device_id(),
            outcome: CapabilityOutcome::Allowed {
                grant_id,
                delegation_id,
            },
        }
    }

    fn denied(request: &CapabilityRequest, reason: CapabilityDenialReason) -> Self {
        Self {
            authorization_context: request.authorization_context(),
            application_id: request.application_id(),
            device_id: request.device_id(),
            outcome: CapabilityOutcome::Denied(reason),
        }
    }

    /// Whether the request was authorized.
    pub const fn is_allowed(self) -> bool {
        matches!(self.outcome, CapabilityOutcome::Allowed { .. })
    }

    /// Denial reason, or `None` for an authorized request.
    pub const fn denial_reason(self) -> Option<CapabilityDenialReason> {
        match self.outcome {
            CapabilityOutcome::Allowed { .. } => None,
            CapabilityOutcome::Denied(reason) => Some(reason),
        }
    }

    /// Exact request checkpoint on which this decision is based.
    pub const fn checkpoint_id(self) -> CheckpointId {
        self.authorization_context.checkpoint_id()
    }

    /// Exact request epoch on which this decision is based.
    pub const fn epoch(self) -> Epoch {
        self.authorization_context.epoch()
    }

    /// Account named by the decision basis.
    pub const fn account_id(self) -> AccountId {
        self.authorization_context.account_id()
    }

    /// Application retained as part of the decision's audit context.
    pub const fn application_id(self) -> ApplicationId {
        self.application_id
    }

    /// Device whose request produced this decision.
    pub const fn device_id(self) -> DeviceId {
        self.device_id
    }

    /// Grant identifier authorizing the request, or `None` when denied.
    pub const fn grant_id(self) -> Option<CapabilityGrantId> {
        match self.outcome {
            CapabilityOutcome::Allowed { grant_id, .. } => Some(grant_id),
            CapabilityOutcome::Denied(_) => None,
        }
    }

    /// Final delegation identifier, or `None` for direct grants and denials.
    pub const fn delegation_id(self) -> Option<DelegationId> {
        match self.outcome {
            CapabilityOutcome::Allowed { delegation_id, .. } => delegation_id,
            CapabilityOutcome::Denied(_) => None,
        }
    }
}

/// Evaluate one request deterministically against an immutable state view.
///
/// The evaluator is default-deny and performs no clock, storage, key lookup, or network access.
/// Delegated proofs require every signature verifier result to be explicitly `Verified`.
pub fn evaluate_capability(
    request: &CapabilityRequest,
    proof: CapabilityProof<'_>,
    state: &impl CapabilityStateView,
    signatures: &impl DelegationSignatureVerifier,
) -> CapabilityDecision {
    if let Some(reason) = validate_current_context(request, state) {
        return CapabilityDecision::denied(request, reason);
    }
    if let Some(reason) = validate_device_status(state.device_status(request.device_id())) {
        return CapabilityDecision::denied(request, reason);
    }

    match proof {
        CapabilityProof::Direct => evaluate_direct(request, state),
        CapabilityProof::Delegated(chain) => evaluate_delegated(request, chain, state, signatures),
    }
}

fn validate_current_context(
    request: &CapabilityRequest,
    state: &impl CapabilityStateView,
) -> Option<CapabilityDenialReason> {
    let requested = request.authorization_context();
    let current = state.authorization_context();
    if requested.account_id() != current.account_id() {
        return Some(CapabilityDenialReason::AccountMismatch);
    }
    if requested.epoch() != current.epoch() {
        return Some(CapabilityDenialReason::EpochMismatch);
    }
    if requested.checkpoint_id() != current.checkpoint_id() {
        return Some(CapabilityDenialReason::CheckpointMismatch);
    }
    None
}

fn validate_device_status(status: CapabilityDeviceStatus) -> Option<CapabilityDenialReason> {
    match status {
        CapabilityDeviceStatus::Active => None,
        CapabilityDeviceStatus::Unknown => Some(CapabilityDenialReason::UnknownDevice),
        CapabilityDeviceStatus::Suspended => Some(CapabilityDenialReason::DeviceSuspended),
        CapabilityDeviceStatus::Revoked => Some(CapabilityDenialReason::DeviceRevoked),
    }
}

fn evaluate_direct(
    request: &CapabilityRequest,
    state: &impl CapabilityStateView,
) -> CapabilityDecision {
    let grants = state.root_grants(request.device_id());
    if grants.len() > MAX_CAPABILITIES_PER_DEVICE {
        return CapabilityDecision::denied(request, CapabilityDenialReason::StateViewLimitExceeded);
    }

    let mut best_denial = CapabilityDenialReason::NoMatchingGrant;
    for grant in grants {
        let grant_id = match grant.capability_grant_id() {
            Ok(grant_id) => grant_id,
            Err(_) => {
                return CapabilityDecision::denied(
                    request,
                    CapabilityDenialReason::InvalidCapabilityEvidence,
                );
            }
        };
        let mismatch = match grant_mismatch(grant, request) {
            Some(reason) => reason,
            None if state.is_grant_revoked(grant_id) => CapabilityDenialReason::GrantRevoked,
            None => return CapabilityDecision::allowed(request, grant_id, None),
        };
        if mismatch_priority(mismatch) > mismatch_priority(best_denial) {
            best_denial = mismatch;
        }
    }
    CapabilityDecision::denied(request, best_denial)
}

fn evaluate_delegated(
    request: &CapabilityRequest,
    chain: &DelegationChain,
    state: &impl CapabilityStateView,
    signatures: &impl DelegationSignatureVerifier,
) -> CapabilityDecision {
    let links = chain.links();
    if links.is_empty() || links.len() > MAX_DELEGATION_DEPTH {
        return CapabilityDecision::denied(request, CapabilityDenialReason::InvalidDelegationChain);
    }

    let root = chain.root();
    if !context_is_usable(root.authorization_context(), request, state) {
        return CapabilityDecision::denied(
            request,
            CapabilityDenialReason::UnrecognizedAuthorizationContext,
        );
    }
    if let Some(reason) = validate_device_status(state.device_status(root.holder())) {
        return CapabilityDecision::denied(request, reason);
    }

    let root_grants = state.root_grants(root.holder());
    if root_grants.len() > MAX_CAPABILITIES_PER_DEVICE {
        return CapabilityDecision::denied(request, CapabilityDenialReason::StateViewLimitExceeded);
    }
    let root_grant_id = match root.grant().capability_grant_id() {
        Ok(grant_id) => grant_id,
        Err(_) => {
            return CapabilityDecision::denied(
                request,
                CapabilityDenialReason::InvalidCapabilityEvidence,
            );
        }
    };
    let mut root_is_installed = false;
    for grant in root_grants {
        let installed_grant_id = match grant.capability_grant_id() {
            Ok(grant_id) => grant_id,
            Err(_) => {
                return CapabilityDecision::denied(
                    request,
                    CapabilityDenialReason::InvalidCapabilityEvidence,
                );
            }
        };
        root_is_installed |= installed_grant_id == root_grant_id;
    }
    if !root_is_installed {
        return CapabilityDecision::denied(request, CapabilityDenialReason::NoMatchingGrant);
    }
    if state.is_grant_revoked(root_grant_id) {
        return CapabilityDecision::denied(request, CapabilityDenialReason::ParentGrantRevoked);
    }
    if !state.held_grant_at(root.holder(), root_grant_id, root.authorization_context()) {
        return CapabilityDecision::denied(
            request,
            CapabilityDenialReason::RootGrantNotHeldAtContext,
        );
    }
    if state.device_status_at(root.holder(), root.authorization_context())
        != CapabilityDeviceStatus::Active
    {
        return CapabilityDecision::denied(
            request,
            CapabilityDenialReason::RootHolderNotActiveAtContext,
        );
    }
    let root_context_time =
        match state.authorization_context_timestamp(root.authorization_context()) {
            Some(timestamp) => timestamp,
            None => {
                return CapabilityDecision::denied(
                    request,
                    CapabilityDenialReason::RootContextTimestampUnavailable,
                );
            }
        };
    if !grant_is_valid_at(
        root.grant(),
        root.authorization_context().epoch(),
        root_context_time,
    ) {
        return CapabilityDecision::denied(
            request,
            CapabilityDenialReason::RootGrantInvalidAtContext,
        );
    }

    let mut current_holder = root.holder();
    let mut current_grant = root.grant();
    let mut current_grant_id = root_grant_id;
    let mut previous_context = root.authorization_context();
    let mut previous_issued_at = root_context_time;
    let mut last_delegation_id = None;
    let mut seen_devices = Vec::with_capacity(links.len().saturating_add(1));
    let mut seen_grants = Vec::with_capacity(links.len().saturating_add(1));
    let mut seen_delegations = Vec::with_capacity(links.len());
    seen_devices.push(current_holder);
    seen_grants.push(current_grant_id);

    for (index, link) in links.iter().enumerate() {
        let body = link.body();
        if body.issuer() != current_holder || body.parent_grant_id() != current_grant_id {
            return CapabilityDecision::denied(
                request,
                CapabilityDenialReason::InvalidDelegationChain,
            );
        }
        if !context_is_usable(body.authorization_context(), request, state) {
            return CapabilityDecision::denied(
                request,
                CapabilityDenialReason::UnrecognizedAuthorizationContext,
            );
        }
        if !contexts_are_monotonic(previous_context, body.authorization_context())
            || !state.authorization_context_precedes_or_equals(
                previous_context,
                body.authorization_context(),
            )
        {
            return CapabilityDecision::denied(
                request,
                CapabilityDenialReason::AuthorizationContextRollback,
            );
        }
        let context_timestamp =
            match state.authorization_context_timestamp(body.authorization_context()) {
                Some(timestamp) => timestamp,
                None => {
                    return CapabilityDecision::denied(
                        request,
                        CapabilityDenialReason::DelegationContextTimestampUnavailable,
                    );
                }
            };
        if context_timestamp > body.issued_at() {
            return CapabilityDecision::denied(
                request,
                CapabilityDenialReason::DelegationIssuedBeforeContext,
            );
        }
        if previous_issued_at > body.issued_at() {
            return CapabilityDecision::denied(
                request,
                CapabilityDenialReason::DelegationIssuanceRollback,
            );
        }
        if state.device_status_at(body.issuer(), body.authorization_context())
            != CapabilityDeviceStatus::Active
        {
            return CapabilityDecision::denied(
                request,
                CapabilityDenialReason::IssuerNotActiveAtIssuance,
            );
        }
        if !state.held_grant_at(
            body.issuer(),
            current_grant_id,
            body.authorization_context(),
        ) {
            return CapabilityDecision::denied(
                request,
                CapabilityDenialReason::ParentGrantNotHeldAtIssuance,
            );
        }
        if !grant_is_valid_at(
            current_grant,
            body.authorization_context().epoch(),
            body.issued_at(),
        ) {
            return CapabilityDecision::denied(
                request,
                CapabilityDenialReason::ParentGrantInvalidAtIssuance,
            );
        }
        if state.is_grant_revoked(current_grant_id) {
            return CapabilityDecision::denied(request, CapabilityDenialReason::ParentGrantRevoked);
        }
        if seen_devices.contains(&body.subject()) {
            return CapabilityDecision::denied(
                request,
                CapabilityDenialReason::InvalidDelegationChain,
            );
        }
        if let Some(reason) = validate_device_status(state.device_status(body.subject())) {
            return CapabilityDecision::denied(request, reason);
        }
        if !is_strict_narrowing(current_grant, body.child_grant()) {
            return CapabilityDecision::denied(
                request,
                CapabilityDenialReason::InvalidDelegationChain,
            );
        }

        let child_grant_id = match body.child_grant().capability_grant_id() {
            Ok(grant_id) => grant_id,
            Err(_) => {
                return CapabilityDecision::denied(
                    request,
                    CapabilityDenialReason::InvalidCapabilityEvidence,
                );
            }
        };
        let delegation_id = match link.delegation_id() {
            Ok(delegation_id) => delegation_id,
            Err(_) => {
                return CapabilityDecision::denied(
                    request,
                    CapabilityDenialReason::InvalidCapabilityEvidence,
                );
            }
        };
        if seen_grants.contains(&child_grant_id) || seen_delegations.contains(&delegation_id) {
            return CapabilityDecision::denied(
                request,
                CapabilityDenialReason::InvalidDelegationChain,
            );
        }
        if state.is_delegation_revoked(delegation_id) {
            return CapabilityDecision::denied(request, CapabilityDenialReason::DelegationRevoked);
        }
        match signatures.verify_delegation(link) {
            DelegationSignatureStatus::Verified => {}
            DelegationSignatureStatus::Invalid => {
                return CapabilityDecision::denied(
                    request,
                    CapabilityDenialReason::InvalidDelegationSignature,
                );
            }
            DelegationSignatureStatus::Unavailable => {
                return CapabilityDecision::denied(
                    request,
                    CapabilityDenialReason::SignatureVerificationUnavailable,
                );
            }
        }

        let is_leaf = index.checked_add(1) == Some(links.len());
        if state.is_grant_revoked(child_grant_id) {
            let reason = if is_leaf {
                CapabilityDenialReason::GrantRevoked
            } else {
                CapabilityDenialReason::ParentGrantRevoked
            };
            return CapabilityDecision::denied(request, reason);
        }

        seen_devices.push(body.subject());
        seen_grants.push(child_grant_id);
        seen_delegations.push(delegation_id);
        current_holder = body.subject();
        current_grant = body.child_grant();
        current_grant_id = child_grant_id;
        previous_context = body.authorization_context();
        previous_issued_at = body.issued_at();
        last_delegation_id = Some(delegation_id);
    }

    if previous_issued_at > request.evaluated_at() {
        return CapabilityDecision::denied(request, CapabilityDenialReason::DelegationNotYetValid);
    }
    if current_holder != request.device_id() || chain.leaf_holder() != request.device_id() {
        return CapabilityDecision::denied(request, CapabilityDenialReason::InvalidDelegationChain);
    }
    if let Some(reason) = grant_mismatch(current_grant, request) {
        return CapabilityDecision::denied(request, reason);
    }
    CapabilityDecision::allowed(request, current_grant_id, last_delegation_id)
}

fn context_is_usable(
    context: AuthorizationContext,
    request: &CapabilityRequest,
    state: &impl CapabilityStateView,
) -> bool {
    context.account_id() == request.account_id()
        && contexts_are_monotonic(context, request.authorization_context())
        && state.recognizes_authorization_context(context)
        && state.authorization_context_precedes_or_equals(context, request.authorization_context())
}

fn contexts_are_monotonic(
    ancestor: AuthorizationContext,
    descendant: AuthorizationContext,
) -> bool {
    if ancestor.account_id() != descendant.account_id() || ancestor.epoch() > descendant.epoch() {
        return false;
    }
    ancestor.epoch() <= descendant.epoch()
}

fn grant_mismatch(
    grant: &CapabilityGrant,
    request: &CapabilityRequest,
) -> Option<CapabilityDenialReason> {
    if grant.namespace() != request.namespace() {
        return Some(CapabilityDenialReason::NamespaceNotGranted);
    }
    if grant.action() != request.action() {
        return Some(CapabilityDenialReason::ActionNotGranted);
    }
    if !selector_contains(grant.resource(), request.resource()) {
        return Some(CapabilityDenialReason::ResourceNotGranted);
    }
    if !constraints_hold(
        grant.constraints(),
        request.authorization_context().epoch(),
        request.evaluated_at(),
    ) {
        return Some(CapabilityDenialReason::ConstraintUnsatisfied);
    }
    if grant
        .expires_at()
        .is_some_and(|expires_at| request.evaluated_at() >= expires_at)
    {
        return Some(CapabilityDenialReason::GrantExpired);
    }
    None
}

fn selector_contains(selector: &ResourceSelector, resource: &ResourcePath) -> bool {
    match selector {
        ResourceSelector::Exact(expected) => expected == resource,
        ResourceSelector::Prefix(prefix) => path_starts_with(resource, prefix),
    }
}

fn path_starts_with(path: &ResourcePath, prefix: &ResourcePath) -> bool {
    path.segments().len() >= prefix.segments().len()
        && path
            .segments()
            .iter()
            .zip(prefix.segments())
            .all(|(segment, prefix_segment)| segment == prefix_segment)
}

fn constraints_hold(
    constraints: &[CapabilityConstraint],
    epoch: Epoch,
    evaluated_at: Timestamp,
) -> bool {
    constraints.iter().all(|constraint| match constraint {
        CapabilityConstraint::AccountEpochAtLeast(minimum) => epoch >= *minimum,
        CapabilityConstraint::AccountEpochAtMost(maximum) => epoch <= *maximum,
        CapabilityConstraint::ValidFrom(valid_from) => evaluated_at >= *valid_from,
    })
}

fn grant_is_valid_at(grant: &CapabilityGrant, epoch: Epoch, evaluated_at: Timestamp) -> bool {
    constraints_hold(grant.constraints(), epoch, evaluated_at)
        && grant
            .expires_at()
            .is_none_or(|expires_at| evaluated_at < expires_at)
}

fn is_strict_narrowing(parent: &CapabilityGrant, child: &CapabilityGrant) -> bool {
    if parent.namespace() != child.namespace() || parent.action() != child.action() {
        return false;
    }

    let resource_strict = match resource_narrowing(parent.resource(), child.resource()) {
        Some(strict) => strict,
        None => return false,
    };
    let constraint_strict = match constraint_narrowing(parent.constraints(), child.constraints()) {
        Some(strict) => strict,
        None => return false,
    };
    let expiration_strict = match expiration_narrowing(parent.expires_at(), child.expires_at()) {
        Some(strict) => strict,
        None => return false,
    };
    let permission_strict = match permission_narrowing(parent.delegation(), child.delegation()) {
        Some(strict) => strict,
        None => return false,
    };

    resource_strict || constraint_strict || expiration_strict || permission_strict
}

fn resource_narrowing(parent: &ResourceSelector, child: &ResourceSelector) -> Option<bool> {
    match (parent, child) {
        (ResourceSelector::Exact(parent), ResourceSelector::Exact(child)) if parent == child => {
            Some(false)
        }
        (ResourceSelector::Prefix(parent), ResourceSelector::Prefix(child))
            if path_starts_with(child, parent) =>
        {
            Some(parent != child)
        }
        (ResourceSelector::Prefix(parent), ResourceSelector::Exact(child))
            if path_starts_with(child, parent) =>
        {
            Some(true)
        }
        _ => None,
    }
}

fn constraint_narrowing(
    parent: &[CapabilityConstraint],
    child: &[CapabilityConstraint],
) -> Option<bool> {
    let mut strict = false;
    for code in 1..=3 {
        let parent_value = constraint_value(parent, code);
        let child_value = constraint_value(child, code);
        match (code, parent_value, child_value) {
            (_, Some(_), None) => return None,
            (1 | 3, Some(parent_value), Some(child_value)) if child_value >= parent_value => {
                strict |= child_value > parent_value;
            }
            (2, Some(parent_value), Some(child_value)) if child_value <= parent_value => {
                strict |= child_value < parent_value;
            }
            (_, None, Some(_)) => strict = true,
            (_, None, None) => {}
            _ => return None,
        }
    }
    Some(strict)
}

fn constraint_value(constraints: &[CapabilityConstraint], code: u16) -> Option<u64> {
    constraints.iter().find_map(|constraint| match constraint {
        CapabilityConstraint::AccountEpochAtLeast(epoch) if code == 1 => Some(epoch.get()),
        CapabilityConstraint::AccountEpochAtMost(epoch) if code == 2 => Some(epoch.get()),
        CapabilityConstraint::ValidFrom(timestamp) if code == 3 => Some(timestamp.as_unix_millis()),
        _ => None,
    })
}

fn expiration_narrowing(parent: Option<Timestamp>, child: Option<Timestamp>) -> Option<bool> {
    match (parent, child) {
        (None, None) => Some(false),
        (None, Some(_)) => Some(true),
        (Some(_), None) => None,
        (Some(parent), Some(child)) if child <= parent => Some(child < parent),
        (Some(_), Some(_)) => None,
    }
}

fn permission_narrowing(parent: DelegationPermission, child: DelegationPermission) -> Option<bool> {
    match (parent.remaining(), child.remaining()) {
        (None, _) => None,
        (Some(_), None) => Some(true),
        (Some(parent), Some(child)) if child.get() < parent.get() => Some(true),
        (Some(_), Some(_)) => None,
    }
}

const fn mismatch_priority(reason: CapabilityDenialReason) -> u8 {
    match reason {
        CapabilityDenialReason::NoMatchingGrant => 0,
        CapabilityDenialReason::NamespaceNotGranted => 1,
        CapabilityDenialReason::ActionNotGranted => 2,
        CapabilityDenialReason::ResourceNotGranted => 3,
        CapabilityDenialReason::ConstraintUnsatisfied => 4,
        CapabilityDenialReason::GrantExpired => 5,
        CapabilityDenialReason::GrantRevoked => 6,
        _ => 0,
    }
}
