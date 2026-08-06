//! Pure account-control reference model.
//!
//! This module deliberately has no dependency on the production identity implementation. It
//! models public authority state and transition rules independently so differential tests can
//! detect shared mistakes.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Maximum controllers retained by one reference-model account.
pub const MAX_MODEL_CONTROLLERS: usize = 16;
/// Maximum devices retained by one reference-model account.
pub const MAX_MODEL_DEVICES: usize = 64;
/// Maximum accepted events retained by one bounded model history.
pub const MAX_MODEL_EVENTS: usize = 256;
/// Maximum competing heads accepted by one bounded fork descriptor.
pub const MAX_MODEL_FORK_HEADS: usize = 8;

/// Stable model-owned controller identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ControllerId(u16);

impl ControllerId {
    /// Creates a run-local controller identity.
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the numeric identity.
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Stable model-owned device identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DeviceId(u16);

impl DeviceId {
    /// Creates a run-local device identity.
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the numeric identity.
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Stable model-owned event identity. Zero is the genesis predecessor anchor.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct EventId(u64);

impl EventId {
    /// Creates an event or genesis-anchor identity.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric identity.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Public controller record used by the independent model.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelController {
    id: ControllerId,
    weight: u16,
}

impl ModelController {
    /// Creates a controller with nonzero identity and weight.
    pub fn new(id: ControllerId, weight: u16) -> Result<Self, ModelError> {
        if id.get() == 0 {
            return Err(ModelError::ZeroIdentifier("controller"));
        }
        if weight == 0 {
            return Err(ModelError::ZeroWeight);
        }
        Ok(Self { id, weight })
    }

    /// Controller identity.
    pub const fn id(&self) -> ControllerId {
        self.id
    }

    /// Controller authorization weight.
    pub const fn weight(&self) -> u16 {
        self.weight
    }
}

/// Weighted policy evaluated against the complete pre-transition controller state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelPolicy {
    required_weight: u16,
}

impl ModelPolicy {
    /// Creates a nonzero weighted threshold.
    pub fn new(required_weight: u16) -> Result<Self, ModelError> {
        if required_weight == 0 {
            return Err(ModelError::ZeroWeight);
        }
        Ok(Self { required_weight })
    }

    /// Weight required under this policy.
    pub const fn required_weight(self) -> u16 {
        self.required_weight
    }
}

/// Model device lifecycle. Revocation is permanent.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceLifecycle {
    /// Device may receive current-epoch group keys.
    Active,
    /// Device is permanently tombstoned.
    Revoked,
}

/// Simplified protocol-signature migration state.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationState {
    /// One current signature suite.
    #[default]
    Stable,
    /// A new suite is staged and cross-signing is required.
    Pending,
    /// Old and new suites are both required.
    Dual,
    /// Only the replacement suite remains authoritative.
    Complete,
}

/// Recovery result that replaces account authority exactly.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPlan {
    controllers: Vec<ModelController>,
    policy: ModelPolicy,
}

impl RecoveryPlan {
    /// Creates a bounded, distinct, threshold-satisfying replacement authority set.
    pub fn new(
        mut controllers: Vec<ModelController>,
        policy: ModelPolicy,
    ) -> Result<Self, ModelError> {
        normalize_controllers(&mut controllers)?;
        validate_controller_set(&controllers, policy)?;
        Ok(Self {
            controllers,
            policy,
        })
    }

    /// Exact replacement controllers.
    pub fn controllers(&self) -> &[ModelController] {
        &self.controllers
    }

    /// Exact replacement policy.
    pub const fn policy(&self) -> ModelPolicy {
        self.policy
    }
}

/// Closed operation set exercised by the independent model and formal checker.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IdentityOperation {
    /// Add one independently weighted controller.
    AddController(ModelController),
    /// Permanently revoke one controller.
    RevokeController(ControllerId),
    /// Replace the weighted policy.
    ChangePolicy(ModelPolicy),
    /// Authorize a new independently identified device.
    AuthorizeDevice(DeviceId),
    /// Permanently revoke a device.
    RevokeDevice(DeviceId),
    /// Replace authority through the separate recovery authorization path.
    Recover(RecoveryPlan),
    /// Stage recovery evidence without replacing authority yet.
    BeginRecovery,
    /// Stage a replacement signature suite.
    BeginMigration,
    /// Enter dual-signature migration.
    ActivateMigration,
    /// Retire the previous signature suite.
    CompleteMigration,
    /// Rotate the group key to exactly the currently active devices.
    RotateGroupKey,
}

impl IdentityOperation {
    /// Return the exact v1 post-operation epoch for an account event.
    ///
    /// Migration begin is the bounded model's only non-advancing event. Group-key rotation remains
    /// an advancing operation when represented as a scenario event; the differential adapter uses
    /// [`AccountControlModel::rotate_group_key`] for the production implementation's out-of-band
    /// application-key rotation.
    pub fn resulting_epoch(&self, current_epoch: u64) -> Result<u64, ModelError> {
        if matches!(self, Self::BeginMigration) {
            Ok(current_epoch)
        } else {
            current_epoch
                .checked_add(1)
                .ok_or(ModelError::ArithmeticOverflow("event epoch"))
        }
    }
}

/// One model transition and its explicit prior-authority approvals.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityEvent {
    id: EventId,
    predecessor: EventId,
    sequence: u64,
    resulting_epoch: u64,
    approvals: Vec<ControllerId>,
    operation: IdentityOperation,
}

impl IdentityEvent {
    /// Creates one bounded canonical event.
    pub fn new(
        id: EventId,
        predecessor: EventId,
        sequence: u64,
        resulting_epoch: u64,
        mut approvals: Vec<ControllerId>,
        operation: IdentityOperation,
    ) -> Result<Self, ModelError> {
        if id.get() == 0 || id == predecessor {
            return Err(ModelError::ZeroOrSelfEventId);
        }
        if sequence == 0
            || (resulting_epoch == 0 && !matches!(operation, IdentityOperation::BeginMigration))
        {
            return Err(ModelError::InvalidSequence);
        }
        approvals.sort_unstable();
        if approvals.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ModelError::DuplicateApproval);
        }
        if approvals.iter().any(|controller| controller.get() == 0) {
            return Err(ModelError::ZeroIdentifier("approval controller"));
        }
        Ok(Self {
            id,
            predecessor,
            sequence,
            resulting_epoch,
            approvals,
            operation,
        })
    }

    /// Event identity.
    pub const fn id(&self) -> EventId {
        self.id
    }

    /// Exact unique predecessor claimed by this event.
    pub const fn predecessor(&self) -> EventId {
        self.predecessor
    }

    /// Claimed next sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Claimed next epoch.
    pub const fn resulting_epoch(&self) -> u64 {
        self.resulting_epoch
    }

    /// Sorted distinct controller approvals.
    pub fn approvals(&self) -> &[ControllerId] {
        &self.approvals
    }

    /// Requested account-control operation.
    pub const fn operation(&self) -> &IdentityOperation {
        &self.operation
    }
}

/// Explicit choose-one-branch fork resolution authorized by the common pre-fork authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForkResolution {
    id: EventId,
    heads: Vec<EventId>,
    selected_head: EventId,
    sequence: u64,
    resulting_epoch: u64,
    approvals: Vec<ControllerId>,
    revoked_controllers: Vec<ControllerId>,
    revoked_devices: Vec<DeviceId>,
}

impl ForkResolution {
    /// Creates a canonical resolution that consumes every current head.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: EventId,
        mut heads: Vec<EventId>,
        selected_head: EventId,
        sequence: u64,
        resulting_epoch: u64,
        mut approvals: Vec<ControllerId>,
        mut revoked_controllers: Vec<ControllerId>,
        mut revoked_devices: Vec<DeviceId>,
    ) -> Result<Self, ModelError> {
        if id.get() == 0 || sequence == 0 || resulting_epoch == 0 {
            return Err(ModelError::InvalidForkResolution);
        }
        heads.sort_unstable();
        approvals.sort_unstable();
        revoked_controllers.sort_unstable();
        revoked_devices.sort_unstable();
        if heads.len() < 2
            || heads.len() > MAX_MODEL_FORK_HEADS
            || heads.windows(2).any(|pair| pair[0] == pair[1])
            || heads.iter().any(|head| head.get() == 0 || *head == id)
            || heads.binary_search(&selected_head).is_err()
            || approvals.windows(2).any(|pair| pair[0] == pair[1])
            || revoked_controllers
                .windows(2)
                .any(|pair| pair[0] == pair[1])
            || revoked_devices.windows(2).any(|pair| pair[0] == pair[1])
            || approvals.iter().any(|controller| controller.get() == 0)
            || revoked_controllers
                .iter()
                .any(|controller| controller.get() == 0)
            || revoked_devices.iter().any(|device| device.get() == 0)
        {
            return Err(ModelError::InvalidForkResolution);
        }
        Ok(Self {
            id,
            heads,
            selected_head,
            sequence,
            resulting_epoch,
            approvals,
            revoked_controllers,
            revoked_devices,
        })
    }

    /// Resolution event identity.
    pub const fn id(&self) -> EventId {
        self.id
    }

    /// Complete sorted fork-head set consumed by this resolution.
    pub fn heads(&self) -> &[EventId] {
        &self.heads
    }

    /// Branch selected by the resolution.
    pub const fn selected_head(&self) -> EventId {
        self.selected_head
    }
}

/// Whether an event advanced the selected branch, replayed, or exposed a fork.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyDisposition {
    /// Linear state advanced once.
    Applied,
    /// Exact already-retained event was idempotently replayed.
    Replay,
    /// A valid sibling branch was retained and the account became forked.
    ForkDetected,
}

/// Stable observable state for differential comparison and replay artifacts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountModelSnapshot {
    /// Stable account identity.
    pub account_id: [u8; 32],
    /// Selected linear sequence before any explicit fork resolution.
    pub sequence: u64,
    /// Selected linear security epoch.
    pub epoch: u64,
    /// Sorted current branch heads.
    pub heads: Vec<EventId>,
    /// Whether more than one valid branch is retained.
    pub forked: bool,
    /// Sorted active controllers.
    pub active_controllers: Vec<ModelController>,
    /// Permanent controller tombstones.
    pub revoked_controllers: Vec<ControllerId>,
    /// Complete sorted device lifecycle map.
    pub devices: BTreeMap<DeviceId, DeviceLifecycle>,
    /// Current weighted policy.
    pub policy: ModelPolicy,
    /// Signature-suite migration state.
    pub migration: MigrationState,
    /// Monotonic group-key generation.
    pub group_key_generation: u64,
    /// Exact active-device recipients of the latest rotation.
    pub group_key_recipients: Vec<DeviceId>,
}

#[derive(Clone, Debug)]
struct AuthorityView {
    sequence: u64,
    epoch: u64,
    controllers: BTreeMap<ControllerId, ModelController>,
    revoked_controllers: BTreeSet<ControllerId>,
    devices: BTreeMap<DeviceId, DeviceLifecycle>,
    policy: ModelPolicy,
    migration: MigrationState,
    group_key_generation: u64,
    group_key_recipients: BTreeSet<DeviceId>,
}

impl AuthorityView {
    fn apply_operation(&mut self, operation: &IdentityOperation) -> Result<(), ModelError> {
        match operation {
            IdentityOperation::AddController(controller) => self.add_controller(controller.clone()),
            IdentityOperation::RevokeController(id) => self.revoke_controller(*id),
            IdentityOperation::ChangePolicy(policy) => self.change_policy(*policy),
            IdentityOperation::AuthorizeDevice(id) => self.authorize_device(*id),
            IdentityOperation::RevokeDevice(id) => self.revoke_device(*id),
            IdentityOperation::Recover(_) => Err(ModelError::RecoveryAuthorizationRequired),
            IdentityOperation::BeginRecovery => Ok(()),
            IdentityOperation::BeginMigration => {
                if self.migration != MigrationState::Stable {
                    return Err(ModelError::InvalidMigration);
                }
                self.migration = MigrationState::Pending;
                Ok(())
            }
            IdentityOperation::ActivateMigration => {
                if self.migration != MigrationState::Pending {
                    return Err(ModelError::InvalidMigration);
                }
                self.migration = MigrationState::Dual;
                Ok(())
            }
            IdentityOperation::CompleteMigration => {
                if self.migration != MigrationState::Dual {
                    return Err(ModelError::InvalidMigration);
                }
                self.migration = MigrationState::Complete;
                Ok(())
            }
            IdentityOperation::RotateGroupKey => {
                self.group_key_generation = self
                    .group_key_generation
                    .checked_add(1)
                    .ok_or(ModelError::ArithmeticOverflow("group-key generation"))?;
                self.group_key_recipients = self
                    .devices
                    .iter()
                    .filter_map(|(id, lifecycle)| {
                        (*lifecycle == DeviceLifecycle::Active).then_some(*id)
                    })
                    .collect();
                Ok(())
            }
        }
    }

    fn add_controller(&mut self, controller: ModelController) -> Result<(), ModelError> {
        if self.controllers.len() >= MAX_MODEL_CONTROLLERS {
            return Err(ModelError::LimitExceeded("controllers"));
        }
        if self.controllers.contains_key(&controller.id())
            || self.revoked_controllers.contains(&controller.id())
        {
            return Err(ModelError::ControllerAlreadyKnown(controller.id()));
        }
        self.controllers.insert(controller.id(), controller);
        Ok(())
    }

    fn revoke_controller(&mut self, id: ControllerId) -> Result<(), ModelError> {
        let controller = self
            .controllers
            .remove(&id)
            .ok_or(ModelError::UnknownController(id))?;
        let remaining_weight = total_weight(self.controllers.values())?;
        if remaining_weight < self.policy.required_weight() {
            self.controllers.insert(id, controller);
            return Err(ModelError::UnsatisfiedPolicy {
                available: remaining_weight,
                required: self.policy.required_weight(),
            });
        }
        self.revoked_controllers.insert(id);
        Ok(())
    }

    fn change_policy(&mut self, policy: ModelPolicy) -> Result<(), ModelError> {
        let available = total_weight(self.controllers.values())?;
        if available < policy.required_weight() {
            return Err(ModelError::UnsatisfiedPolicy {
                available,
                required: policy.required_weight(),
            });
        }
        self.policy = policy;
        Ok(())
    }

    fn authorize_device(&mut self, id: DeviceId) -> Result<(), ModelError> {
        if id.get() == 0 {
            return Err(ModelError::ZeroIdentifier("device"));
        }
        if self.devices.len() >= MAX_MODEL_DEVICES {
            return Err(ModelError::LimitExceeded("devices"));
        }
        if self.devices.contains_key(&id) {
            return Err(ModelError::DeviceAlreadyKnown(id));
        }
        self.devices.insert(id, DeviceLifecycle::Active);
        Ok(())
    }

    fn revoke_device(&mut self, id: DeviceId) -> Result<(), ModelError> {
        match self.devices.get_mut(&id) {
            Some(lifecycle @ DeviceLifecycle::Active) => {
                *lifecycle = DeviceLifecycle::Revoked;
                self.group_key_recipients.remove(&id);
                Ok(())
            }
            Some(DeviceLifecycle::Revoked) => Err(ModelError::DeviceAlreadyKnown(id)),
            None => Err(ModelError::UnknownDevice(id)),
        }
    }

    fn authorize(&self, approvals: &[ControllerId]) -> Result<(), ModelError> {
        let mut total = 0_u16;
        for approval in approvals {
            if self.revoked_controllers.contains(approval) {
                return Err(ModelError::RevokedController(*approval));
            }
            let controller = self
                .controllers
                .get(approval)
                .ok_or(ModelError::UnknownController(*approval))?;
            total = total
                .checked_add(controller.weight())
                .ok_or(ModelError::ArithmeticOverflow("approval weight"))?;
        }
        if total < self.policy.required_weight() {
            return Err(ModelError::InsufficientWeight {
                actual: total,
                required: self.policy.required_weight(),
            });
        }
        Ok(())
    }

    fn recover(&mut self, plan: &RecoveryPlan) -> Result<(), ModelError> {
        let replacement = plan
            .controllers()
            .iter()
            .map(|controller| (controller.id(), controller.clone()))
            .collect::<BTreeMap<_, _>>();
        for old in self.controllers.keys() {
            if !replacement.contains_key(old) {
                self.revoked_controllers.insert(*old);
            }
        }
        if replacement
            .keys()
            .any(|id| self.revoked_controllers.contains(id))
        {
            return Err(ModelError::RecoveryReintroducesRevokedController);
        }
        self.controllers = replacement;
        self.policy = plan.policy();
        self.migration = MigrationState::Stable;
        for lifecycle in self.devices.values_mut() {
            *lifecycle = DeviceLifecycle::Revoked;
        }
        self.group_key_recipients.clear();
        Ok(())
    }

    fn apply_resolution_revocations(
        &mut self,
        controllers: &[ControllerId],
        devices: &[DeviceId],
    ) -> Result<(), ModelError> {
        for id in controllers {
            if self.revoked_controllers.contains(id) {
                continue;
            }
            self.controllers
                .remove(id)
                .ok_or(ModelError::UnknownController(*id))?;
            self.revoked_controllers.insert(*id);
        }
        validate_controller_set(
            &self.controllers.values().cloned().collect::<Vec<_>>(),
            self.policy,
        )?;
        for id in devices {
            match self.devices.get_mut(id) {
                Some(lifecycle) => *lifecycle = DeviceLifecycle::Revoked,
                None => return Err(ModelError::UnknownDevice(*id)),
            }
            self.group_key_recipients.remove(id);
        }
        Ok(())
    }
}

/// Executable independent account-control state machine.
#[derive(Clone, Debug)]
pub struct AccountControlModel {
    account_id: [u8; 32],
    current_head: EventId,
    heads: BTreeSet<EventId>,
    forked: bool,
    selected: AuthorityView,
    fork_common: Option<AuthorityView>,
    views: BTreeMap<EventId, AuthorityView>,
    events: BTreeMap<EventId, IdentityEvent>,
    resolutions: BTreeMap<EventId, ForkResolution>,
}

impl AccountControlModel {
    /// Creates a genesis model with a stable account identity and satisfiable authority.
    pub fn new(
        account_id: [u8; 32],
        mut controllers: Vec<ModelController>,
        policy: ModelPolicy,
    ) -> Result<Self, ModelError> {
        normalize_controllers(&mut controllers)?;
        validate_controller_set(&controllers, policy)?;
        let selected = AuthorityView {
            sequence: 0,
            epoch: 0,
            controllers: controllers
                .into_iter()
                .map(|controller| (controller.id(), controller))
                .collect(),
            revoked_controllers: BTreeSet::new(),
            devices: BTreeMap::new(),
            policy,
            migration: MigrationState::Stable,
            group_key_generation: 0,
            group_key_recipients: BTreeSet::new(),
        };
        let genesis = EventId::new(0);
        Ok(Self {
            account_id,
            current_head: genesis,
            heads: BTreeSet::new(),
            forked: false,
            fork_common: None,
            views: BTreeMap::from([(genesis, selected.clone())]),
            selected,
            events: BTreeMap::new(),
            resolutions: BTreeMap::new(),
        })
    }

    /// Applies an ordinary prior-policy-authorized transition atomically.
    pub fn apply(&mut self, event: &IdentityEvent) -> Result<ApplyDisposition, ModelError> {
        self.apply_internal(event, false)
    }

    /// Applies an event through the separate recovery authorization path.
    pub fn apply_recovery(
        &mut self,
        event: &IdentityEvent,
    ) -> Result<ApplyDisposition, ModelError> {
        self.apply_internal(event, true)
    }

    /// Rotate application group-key material without adding an account-log event.
    ///
    /// Production performs the actual wrap generation as an effect bound to an already accepted
    /// account revision. This method keeps that out-of-band operation from inventing an extra
    /// sequence, epoch, head, or predecessor in differential histories.
    pub fn rotate_group_key(&mut self) -> Result<(), ModelError> {
        if self.forked {
            return Err(ModelError::ForkedState);
        }
        self.selected
            .apply_operation(&IdentityOperation::RotateGroupKey)?;
        if let Some(view) = self.views.get_mut(&self.current_head) {
            *view = self.selected.clone();
        } else {
            return Err(ModelError::UnknownPredecessor(self.current_head));
        }
        Ok(())
    }

    fn apply_internal(
        &mut self,
        event: &IdentityEvent,
        recovery_authorized: bool,
    ) -> Result<ApplyDisposition, ModelError> {
        if let Some(retained) = self.events.get(&event.id()) {
            return if retained == event {
                Ok(ApplyDisposition::Replay)
            } else {
                Err(ModelError::DuplicateEventId(event.id()))
            };
        }
        if self.resolutions.contains_key(&event.id()) {
            return Err(ModelError::DuplicateEventId(event.id()));
        }
        if self
            .events
            .len()
            .checked_add(self.resolutions.len())
            .ok_or(ModelError::ArithmeticOverflow("retained event count"))?
            >= MAX_MODEL_EVENTS
        {
            return Err(ModelError::LimitExceeded("events"));
        }
        if self.forked {
            return Err(ModelError::ForkedState);
        }
        let parent = self
            .views
            .get(&event.predecessor())
            .cloned()
            .ok_or(ModelError::UnknownPredecessor(event.predecessor()))?;
        validate_next_position(&parent, event)?;

        let mut candidate = parent.clone();
        match event.operation() {
            IdentityOperation::Recover(plan) if recovery_authorized => {
                if !event.approvals().is_empty() {
                    return Err(ModelError::RecoveryHasControllerApprovals);
                }
                candidate.recover(plan)?;
            }
            IdentityOperation::Recover(_) => return Err(ModelError::RecoveryAuthorizationRequired),
            _ if recovery_authorized => return Err(ModelError::RecoveryOperationRequired),
            operation => {
                parent.authorize(event.approvals())?;
                candidate.apply_operation(operation)?;
            }
        }
        candidate.sequence = event.sequence();
        candidate.epoch = event.resulting_epoch();

        if event.predecessor() != self.current_head {
            self.events.insert(event.id(), event.clone());
            self.views.insert(event.id(), candidate);
            if self.heads.is_empty() {
                self.heads.insert(self.current_head);
            }
            self.heads.insert(event.id());
            self.selected = parent.clone();
            self.selected.sequence = event.sequence();
            self.fork_common = Some(parent);
            self.forked = true;
            return Ok(ApplyDisposition::ForkDetected);
        }

        self.events.insert(event.id(), event.clone());
        self.views.insert(event.id(), candidate.clone());
        self.selected = candidate;
        self.current_head = event.id();
        self.heads.clear();
        self.heads.insert(event.id());
        Ok(ApplyDisposition::Applied)
    }

    /// Resolves the exact retained fork without silently merging branch state.
    pub fn resolve_fork(
        &mut self,
        resolution: &ForkResolution,
    ) -> Result<ApplyDisposition, ModelError> {
        if let Some(retained) = self.resolutions.get(&resolution.id) {
            return if retained == resolution {
                Ok(ApplyDisposition::Replay)
            } else {
                Err(ModelError::DuplicateEventId(resolution.id))
            };
        }
        if self.events.contains_key(&resolution.id) {
            return Err(ModelError::DuplicateEventId(resolution.id));
        }
        if !self.forked
            || resolution.heads.as_slice() != self.heads.iter().copied().collect::<Vec<_>>()
        {
            return Err(ModelError::InvalidForkResolution);
        }
        let common = self
            .fork_common
            .as_ref()
            .ok_or(ModelError::InvalidForkResolution)?;
        common.authorize(&resolution.approvals)?;
        let maximum_sequence = resolution
            .heads
            .iter()
            .map(|head| self.views.get(head).map(|view| view.sequence))
            .collect::<Option<Vec<_>>>()
            .ok_or(ModelError::InvalidForkResolution)?
            .into_iter()
            .max()
            .ok_or(ModelError::InvalidForkResolution)?;
        let maximum_epoch = resolution
            .heads
            .iter()
            .map(|head| self.views.get(head).map(|view| view.epoch))
            .collect::<Option<Vec<_>>>()
            .ok_or(ModelError::InvalidForkResolution)?
            .into_iter()
            .max()
            .ok_or(ModelError::InvalidForkResolution)?;
        if maximum_sequence.checked_add(1) != Some(resolution.sequence)
            || maximum_epoch.checked_add(1) != Some(resolution.resulting_epoch)
        {
            return Err(ModelError::InvalidSequence);
        }
        let mut candidate = self
            .views
            .get(&resolution.selected_head)
            .cloned()
            .ok_or(ModelError::InvalidForkResolution)?;
        candidate.apply_resolution_revocations(
            &resolution.revoked_controllers,
            &resolution.revoked_devices,
        )?;
        candidate.sequence = resolution.sequence;
        candidate.epoch = resolution.resulting_epoch;

        self.resolutions.insert(resolution.id, resolution.clone());
        self.views.insert(resolution.id, candidate.clone());
        self.selected = candidate;
        self.current_head = resolution.id;
        self.heads.clear();
        self.heads.insert(resolution.id);
        self.forked = false;
        self.fork_common = None;
        Ok(ApplyDisposition::Applied)
    }

    /// Returns a stable snapshot without exposing transition internals.
    pub fn snapshot(&self) -> AccountModelSnapshot {
        AccountModelSnapshot {
            account_id: self.account_id,
            sequence: self.selected.sequence,
            epoch: self.selected.epoch,
            heads: self.heads.iter().copied().collect(),
            forked: self.forked,
            active_controllers: self.selected.controllers.values().cloned().collect(),
            revoked_controllers: self.selected.revoked_controllers.iter().copied().collect(),
            devices: self.selected.devices.clone(),
            policy: self.selected.policy,
            migration: self.selected.migration,
            group_key_generation: self.selected.group_key_generation,
            group_key_recipients: self.selected.group_key_recipients.iter().copied().collect(),
        }
    }

    /// Return normalized current head labels and their exact predecessor label sets.
    pub fn canonical_head_predecessors(&self) -> BTreeMap<u64, Vec<u64>> {
        self.heads
            .iter()
            .map(|head| {
                let mut predecessors = if let Some(event) = self.events.get(head) {
                    vec![event.predecessor().get()]
                } else if let Some(resolution) = self.resolutions.get(head) {
                    resolution
                        .heads
                        .iter()
                        .map(|predecessor| predecessor.get())
                        .collect()
                } else {
                    Vec::new()
                };
                predecessors.sort_unstable();
                (head.get(), predecessors)
            })
            .collect()
    }
}

fn validate_next_position(view: &AuthorityView, event: &IdentityEvent) -> Result<(), ModelError> {
    let expected_sequence = view
        .sequence
        .checked_add(1)
        .ok_or(ModelError::ArithmeticOverflow("event sequence"))?;
    let expected_epoch = event.operation().resulting_epoch(view.epoch)?;
    if event.sequence() != expected_sequence || event.resulting_epoch() != expected_epoch {
        return Err(ModelError::InvalidSequence);
    }
    Ok(())
}

fn normalize_controllers(controllers: &mut [ModelController]) -> Result<(), ModelError> {
    if controllers.is_empty() || controllers.len() > MAX_MODEL_CONTROLLERS {
        return Err(ModelError::LimitExceeded("controllers"));
    }
    controllers.sort_unstable_by_key(ModelController::id);
    if controllers
        .windows(2)
        .any(|pair| pair[0].id() == pair[1].id())
    {
        return Err(ModelError::DuplicateController);
    }
    Ok(())
}

fn validate_controller_set(
    controllers: &[ModelController],
    policy: ModelPolicy,
) -> Result<(), ModelError> {
    let available = total_weight(controllers.iter())?;
    if available < policy.required_weight() {
        return Err(ModelError::UnsatisfiedPolicy {
            available,
            required: policy.required_weight(),
        });
    }
    Ok(())
}

fn total_weight<'a>(
    controllers: impl IntoIterator<Item = &'a ModelController>,
) -> Result<u16, ModelError> {
    controllers
        .into_iter()
        .try_fold(0_u16, |total, controller| {
            total
                .checked_add(controller.weight())
                .ok_or(ModelError::ArithmeticOverflow("controller weight"))
        })
}

/// Typed model validation or transition failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ModelError {
    /// A model identifier that reserves zero received zero.
    #[error("{0} identity must be nonzero")]
    ZeroIdentifier(&'static str),
    /// Controller or policy weights must be nonzero.
    #[error("controller and policy weights must be nonzero")]
    ZeroWeight,
    /// Event zero is reserved and an event cannot name itself as predecessor.
    #[error("event identity must be nonzero and distinct from its predecessor")]
    ZeroOrSelfEventId,
    /// Sequence or operation-specific v1 epoch did not match the named predecessor.
    #[error("event sequence or operation-specific v1 epoch is invalid")]
    InvalidSequence,
    /// A controller appeared twice in a canonical controller set.
    #[error("controller set contains a duplicate")]
    DuplicateController,
    /// A controller approval appeared twice.
    #[error("controller approvals contain a duplicate")]
    DuplicateApproval,
    /// A bounded collection reached its hard limit.
    #[error("model {0} limit exceeded")]
    LimitExceeded(&'static str),
    /// Checked arithmetic could not represent the result.
    #[error("model {0} arithmetic overflow")]
    ArithmeticOverflow(&'static str),
    /// Approval weight was insufficient under the prior policy.
    #[error("approval weight {actual} is below required weight {required}")]
    InsufficientWeight { actual: u16, required: u16 },
    /// A new policy or controller removal would make authority unsatisfiable.
    #[error("available weight {available} is below policy requirement {required}")]
    UnsatisfiedPolicy { available: u16, required: u16 },
    /// A revoked controller attempted to approve future state.
    #[error("revoked controller {0:?} cannot authorize future state")]
    RevokedController(ControllerId),
    /// An unknown controller was referenced.
    #[error("unknown controller {0:?}")]
    UnknownController(ControllerId),
    /// A controller ID is already active or tombstoned.
    #[error("controller {0:?} is already known")]
    ControllerAlreadyKnown(ControllerId),
    /// An unknown device was referenced.
    #[error("unknown device {0:?}")]
    UnknownDevice(DeviceId),
    /// A device ID is already active or tombstoned.
    #[error("device {0:?} is already known")]
    DeviceAlreadyKnown(DeviceId),
    /// The event names no retained predecessor.
    #[error("unknown predecessor {0:?}")]
    UnknownPredecessor(EventId),
    /// An event ID was reused for different bytes.
    #[error("event identity {0:?} was reused")]
    DuplicateEventId(EventId),
    /// Ordinary transitions fail closed after conflict detection.
    #[error("account is forked and requires explicit resolution")]
    ForkedState,
    /// A recovery event was submitted through ordinary controller authorization.
    #[error("recovery requires the separate recovery authorization path")]
    RecoveryAuthorizationRequired,
    /// The recovery path was used for a non-recovery operation.
    #[error("recovery authorization can apply only a recovery operation")]
    RecoveryOperationRequired,
    /// Recovery authority is distinct from controller approvals.
    #[error("recovery event cannot carry ordinary controller approvals")]
    RecoveryHasControllerApprovals,
    /// Recovery attempted to reactivate a permanent tombstone.
    #[error("recovery cannot reintroduce a revoked controller")]
    RecoveryReintroducesRevokedController,
    /// Signature-suite migration phases were applied out of order.
    #[error("invalid signature-suite migration transition")]
    InvalidMigration,
    /// Fork resolution did not exactly consume and select from the retained conflict.
    #[error("invalid fork resolution")]
    InvalidForkResolution,
}
