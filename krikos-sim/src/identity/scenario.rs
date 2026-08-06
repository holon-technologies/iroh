//! Kernel-owned deterministic identity scenarios and Section 36 invariant accounting.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use krikos_runtime::{ClockSleep, RootSeed, TaskKind, TraceContext, TraceEvent, TraceEventKind};
use serde::{Deserialize, Serialize};

use crate::{
    Kernel, KernelConfig, KernelResourceLimits, KernelSchedulerSnapshot, KernelTaskSnapshot,
    Quiescence, TraceBuffer,
};

use super::{
    AccountControlModel, AccountModelSnapshot, ControllerId, DeviceId, DeviceLifecycle, EventId,
    ForkResolution, IdentityEvent, IdentityOperation, ModelController, ModelError, ModelPolicy,
    RecoveryPlan,
    model::{MAX_MODEL_CONTROLLERS, MAX_MODEL_DEVICES, MAX_MODEL_FORK_HEADS},
};

/// Strict identity-scenario schema version.
pub const IDENTITY_SCENARIO_SCHEMA_VERSION: u16 = 1;
/// Hard encoded-byte bound for one identity scenario.
pub const MAX_IDENTITY_SCENARIO_BYTES: usize = 4 * 1024 * 1024;
/// Hard action bound for one identity scenario.
pub const MAX_IDENTITY_ACTIONS: usize = 256;
const MAX_IDENTITY_TEXT_BYTES: usize = 128;
const MAX_IDENTITY_VIRTUAL_NANOS: u64 = 60_000_000_000;
const MAX_IDENTITY_DELIVERIES: usize = 256;
const MAX_IDENTITY_REPLICAS: usize = 4;
const MAX_IDENTITY_PROVIDER_OBSERVATIONS: usize = 16;

/// One weighted replacement controller in a recovery action.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryController {
    /// Run-local controller identity.
    pub controller: u16,
    /// Nonzero authority weight.
    pub weight: u16,
}

/// Delivery behaviors exercised without granting the transport authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityDeliveryFault {
    /// Delivery is deferred on virtual time.
    Delay,
    /// Concurrent deliveries may arrive in seeded scheduler order.
    Reorder,
    /// A queued delivery is omitted.
    Loss,
    /// An already delivered event is replayed.
    Duplicate,
}

/// Operations permitted on sibling fork proposals.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ForkScenarioOperation {
    /// Add one controller on this branch.
    AddController { controller: u16, weight: u16 },
    /// Authorize one device on this branch.
    AuthorizeDevice { device: u16 },
    /// Change the threshold on this branch.
    ChangePolicy { required_weight: u16 },
}

/// Explicit migration phase used by high-level scenarios.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPhase {
    /// Stage the replacement suite.
    Begin,
    /// Enter dual-signature authority.
    Activate,
    /// Retire the previous suite.
    Complete,
}

/// Stable externally triggerable model-rejection discriminants permitted in scenario expectations.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedModelRejection {
    /// Prior-policy approvals carry less weight than the retained threshold.
    InsufficientWeight,
    /// A permanently revoked controller attempted to approve a transition.
    RevokedController,
    /// An approval or operation target names no active controller.
    UnknownController,
    /// A controller-add operation reuses an active or tombstoned identity.
    ControllerAlreadyKnown,
    /// A policy or removal would leave insufficient active authority.
    UnsatisfiedPolicy,
    /// A controller-add operation reaches the bounded controller capacity.
    ControllerLimitExceeded,
    /// A device-authorization operation reaches the bounded device capacity.
    DeviceLimitExceeded,
    /// An account transition reaches the bounded retained-event capacity.
    EventLimitExceeded,
    /// A device operation or resolution names no known device.
    UnknownDevice,
    /// A device operation reuses an active or revoked identity.
    DeviceAlreadyKnown,
    /// Recovery attempts to reactivate a permanently revoked controller.
    RecoveryReintroducesRevokedController,
    /// A signature-suite migration phase is applied out of order.
    InvalidMigration,
    /// A resolution does not exactly consume and select from the retained fork.
    InvalidForkResolution,
}

impl ExpectedModelRejection {
    fn from_model_error(error: &ModelError) -> Option<Self> {
        match error {
            ModelError::InsufficientWeight { .. } => Some(Self::InsufficientWeight),
            ModelError::RevokedController(_) => Some(Self::RevokedController),
            ModelError::UnknownController(_) => Some(Self::UnknownController),
            ModelError::ControllerAlreadyKnown(_) => Some(Self::ControllerAlreadyKnown),
            ModelError::UnsatisfiedPolicy { .. } => Some(Self::UnsatisfiedPolicy),
            ModelError::LimitExceeded("controllers") => Some(Self::ControllerLimitExceeded),
            ModelError::LimitExceeded("devices") => Some(Self::DeviceLimitExceeded),
            ModelError::LimitExceeded("events") => Some(Self::EventLimitExceeded),
            ModelError::UnknownDevice(_) => Some(Self::UnknownDevice),
            ModelError::DeviceAlreadyKnown(_) => Some(Self::DeviceAlreadyKnown),
            ModelError::RecoveryReintroducesRevokedController => {
                Some(Self::RecoveryReintroducesRevokedController)
            }
            ModelError::InvalidMigration => Some(Self::InvalidMigration),
            ModelError::InvalidForkResolution => Some(Self::InvalidForkResolution),
            ModelError::ZeroIdentifier(_)
            | ModelError::ZeroWeight
            | ModelError::ZeroOrSelfEventId
            | ModelError::InvalidSequence
            | ModelError::DuplicateController
            | ModelError::DuplicateApproval
            | ModelError::ArithmeticOverflow(_)
            | ModelError::LimitExceeded(_)
            | ModelError::DuplicateEventId(_)
            | ModelError::UnknownPredecessor(_)
            | ModelError::ForkedState
            | ModelError::RecoveryAuthorizationRequired
            | ModelError::RecoveryOperationRequired
            | ModelError::RecoveryHasControllerApprovals => None,
        }
    }

    /// Stable spelling committed by canonical scenarios and replay evidence.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InsufficientWeight => "insufficient_weight",
            Self::RevokedController => "revoked_controller",
            Self::UnknownController => "unknown_controller",
            Self::ControllerAlreadyKnown => "controller_already_known",
            Self::UnsatisfiedPolicy => "unsatisfied_policy",
            Self::ControllerLimitExceeded => "controller_limit_exceeded",
            Self::DeviceLimitExceeded => "device_limit_exceeded",
            Self::EventLimitExceeded => "event_limit_exceeded",
            Self::UnknownDevice => "unknown_device",
            Self::DeviceAlreadyKnown => "device_already_known",
            Self::RecoveryReintroducesRevokedController => {
                "recovery_reintroduces_revoked_controller"
            }
            Self::InvalidMigration => "invalid_migration",
            Self::InvalidForkResolution => "invalid_fork_resolution",
        }
    }
}

/// Per-action terminal contract. Success remains the backwards-compatible default.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "terminal", rename_all = "snake_case", deny_unknown_fields)]
pub enum IdentityActionExpectation {
    /// The action must complete successfully; this is omitted from canonical JSON.
    #[default]
    Success,
    /// The action must fail closed with exactly the declared model discriminant.
    ModelRejection {
        /// Exact externally triggerable model rejection required by this action.
        rejection: ExpectedModelRejection,
    },
}

impl IdentityActionExpectation {
    fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }

    const fn expected_model_rejection(self) -> Option<ExpectedModelRejection> {
        match self {
            Self::Success => None,
            Self::ModelRejection { rejection } => Some(rejection),
        }
    }
}

/// Closed action vocabulary for identity hardening scenarios.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IdentityScenarioAction {
    /// Partition identity replicas.
    Partition,
    /// Heal all modeled network partitions.
    Heal,
    /// Exercise one delivery impairment.
    DeliveryFault { fault: IdentityDeliveryFault },
    /// Add an ordinary account controller.
    AddController {
        controller: u16,
        weight: u16,
        approvals: Vec<u16>,
    },
    /// Change the control threshold.
    ChangePolicy {
        required_weight: u16,
        approvals: Vec<u16>,
    },
    /// Authorize an independently keyed device.
    AuthorizeDevice { device: u16, approvals: Vec<u16> },
    /// Permanently revoke one device.
    RevokeDevice { device: u16, approvals: Vec<u16> },
    /// Permanently revoke one controller.
    RevokeController {
        controller: u16,
        approvals: Vec<u16>,
    },
    /// Submit one sibling proposal; co-timed siblings run in seeded scheduler order.
    ForkProposal {
        fork: String,
        branch: String,
        approvals: Vec<u16>,
        operation: ForkScenarioOperation,
    },
    /// Explicitly choose one retained fork branch.
    ResolveFork {
        fork: String,
        selected_branch: String,
        approvals: Vec<u16>,
        revoked_controllers: Vec<u16>,
        revoked_devices: Vec<u16>,
    },
    /// Crash one non-authoritative replica.
    Crash { replica: u16 },
    /// Reopen one replica, optionally without its cached projection.
    Reopen { replica: u16, storage_loss: bool },
    /// Make configured provider evidence unavailable.
    ProviderOutage,
    /// Restore provider availability and a consistent view.
    ProviderRestore,
    /// Present inconsistent provider views without mutating authority.
    ProviderEquivocation,
    /// Probe a freshness-sensitive action, which must fail closed when evidence is unsafe.
    SensitiveProbe,
    /// Replace account authority through the distinct recovery path.
    Recover {
        controllers: Vec<RecoveryController>,
        required_weight: u16,
    },
    /// Advance one signature-suite migration phase.
    Migration {
        phase: MigrationPhase,
        approvals: Vec<u16>,
    },
    /// Rotate group keys to exactly active devices.
    RotateGroupKey { approvals: Vec<u16> },
    /// Durably publish one pending revocation proof.
    PublishRevocation { subject: String },
    /// Validate against and retain an exact offline sequence/epoch basis.
    OfflineValidate,
    /// Create a social edge with no account-control authority.
    SocialRelationship,
    /// Simulator-only evidence fault used to prove one Section 36 oracle and failure workflow.
    Section36Fault { mutation: Section36Mutation },
}

/// One scheduled action with a stable identity and absolute virtual deadline.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityAction {
    id: String,
    at_nanos: u64,
    action: IdentityScenarioAction,
    #[serde(default, skip_serializing_if = "IdentityActionExpectation::is_success")]
    expectation: IdentityActionExpectation,
}

impl IdentityAction {
    /// Creates one bounded action.
    pub fn new(
        id: impl Into<String>,
        at_nanos: u64,
        action: IdentityScenarioAction,
    ) -> Result<Self, IdentityScenarioError> {
        let action = Self {
            id: id.into(),
            at_nanos,
            action,
            expectation: IdentityActionExpectation::Success,
        };
        action.validate()?;
        Ok(action)
    }

    /// Stable action identity used by minimization and diagnostics.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Declares one exact model rejection as the action's expected fail-closed terminal.
    pub fn expect_model_rejection(
        mut self,
        rejection: ExpectedModelRejection,
    ) -> Result<Self, IdentityScenarioError> {
        self.expectation = IdentityActionExpectation::ModelRejection { rejection };
        self.validate()?;
        Ok(self)
    }

    fn validate(&self) -> Result<(), IdentityScenarioError> {
        validate_text(&self.id)?;
        if self.at_nanos > MAX_IDENTITY_VIRTUAL_NANOS {
            return Err(IdentityScenarioError::InvalidVirtualTime(self.at_nanos));
        }
        for text in action_text_fields(&self.action) {
            validate_text(text)?;
        }
        validate_action_semantics(&self.id, &self.action)?;
        validate_action_expectation(&self.id, &self.action, self.expectation)?;
        Ok(())
    }
}

/// Strict, canonical deterministic identity scenario.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityScenario {
    schema_version: u16,
    id: String,
    actions: Vec<IdentityAction>,
}

impl IdentityScenario {
    /// Creates and validates a scenario.
    pub fn new(
        id: impl Into<String>,
        actions: Vec<IdentityAction>,
    ) -> Result<Self, IdentityScenarioError> {
        let scenario = Self {
            schema_version: IDENTITY_SCENARIO_SCHEMA_VERSION,
            id: id.into(),
            actions,
        };
        scenario.validate()?;
        Ok(scenario)
    }

    /// Parses strict JSON and validates all bounds and identities.
    pub fn from_json(bytes: &[u8]) -> Result<Self, IdentityScenarioError> {
        if bytes.len() > MAX_IDENTITY_SCENARIO_BYTES {
            return Err(IdentityScenarioError::InputTooLarge {
                actual: bytes.len(),
                maximum: MAX_IDENTITY_SCENARIO_BYTES,
            });
        }
        let scenario: Self = serde_json::from_slice(bytes)
            .map_err(|error| IdentityScenarioError::Encoding(error.to_string()))?;
        scenario.validate()?;
        Ok(scenario)
    }

    /// Encodes canonical pretty JSON with one final newline.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, IdentityScenarioError> {
        self.validate()?;
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| IdentityScenarioError::Encoding(error.to_string()))?;
        bytes.push(b'\n');
        if bytes.len() > MAX_IDENTITY_SCENARIO_BYTES {
            return Err(IdentityScenarioError::InputTooLarge {
                actual: bytes.len(),
                maximum: MAX_IDENTITY_SCENARIO_BYTES,
            });
        }
        Ok(bytes)
    }

    /// Stable scenario identity.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Actions in declaration order.
    pub fn actions(&self) -> &[IdentityAction] {
        &self.actions
    }

    /// Validates schema, bounds, action IDs, and semantic references.
    pub fn validate(&self) -> Result<(), IdentityScenarioError> {
        if self.schema_version != IDENTITY_SCENARIO_SCHEMA_VERSION {
            return Err(IdentityScenarioError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        validate_text(&self.id)?;
        if self.actions.is_empty() || self.actions.len() > MAX_IDENTITY_ACTIONS {
            return Err(IdentityScenarioError::InvalidActionCount(
                self.actions.len(),
            ));
        }
        let mut ids = BTreeSet::new();
        let mut forks = BTreeMap::<&str, BTreeSet<&str>>::new();
        let mut replicas = BTreeSet::new();
        let mut provider_observations = 0_usize;
        for action in &self.actions {
            action.validate()?;
            if !ids.insert(action.id.as_str()) {
                return Err(IdentityScenarioError::DuplicateAction(action.id.clone()));
            }
            match &action.action {
                IdentityScenarioAction::ForkProposal { fork, branch, .. } => {
                    let branches = forks.entry(fork).or_default();
                    if !branches.insert(branch) || branches.len() > MAX_MODEL_FORK_HEADS {
                        return Err(invalid_action(
                            &action.id,
                            "fork branches must be unique and within the retained-head bound",
                        ));
                    }
                }
                IdentityScenarioAction::Crash { replica }
                | IdentityScenarioAction::Reopen { replica, .. } => {
                    replicas.insert(*replica);
                    if replicas.len() > MAX_IDENTITY_REPLICAS {
                        return Err(invalid_action(
                            &action.id,
                            "scenario exceeds the replica bound",
                        ));
                    }
                }
                IdentityScenarioAction::ProviderOutage
                | IdentityScenarioAction::ProviderRestore
                | IdentityScenarioAction::ProviderEquivocation => {
                    provider_observations = provider_observations
                        .checked_add(1)
                        .ok_or(IdentityScenarioError::ArithmeticOverflow)?;
                    if provider_observations > MAX_IDENTITY_PROVIDER_OBSERVATIONS {
                        return Err(invalid_action(
                            &action.id,
                            "scenario exceeds the provider-observation bound",
                        ));
                    }
                }
                _ => {}
            }
        }
        for action in &self.actions {
            if let IdentityScenarioAction::ResolveFork {
                fork,
                selected_branch,
                ..
            } = &action.action
                && forks
                    .get(fork.as_str())
                    .is_none_or(|branches| !branches.contains(selected_branch.as_str()))
            {
                return Err(invalid_action(
                    &action.id,
                    "fork resolution must select a declared branch",
                ));
            }
        }
        Ok(())
    }
}

/// Required Lane A behavior coverage, derived solely from executed actions.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityCoverage {
    pub partition: bool,
    pub heal: bool,
    pub delay: bool,
    pub reorder: bool,
    pub loss: bool,
    pub duplicate: bool,
    pub fork: bool,
    pub fork_resolution: bool,
    pub crash: bool,
    pub reopen: bool,
    pub storage_loss: bool,
    pub provider_outage: bool,
    pub provider_equivocation: bool,
    pub recovery: bool,
    pub controller_revocation: bool,
    pub device_revocation: bool,
    pub migration_begin: bool,
    pub migration_activate: bool,
    pub migration_complete: bool,
    pub group_key_rotation: bool,
}

impl IdentityCoverage {
    /// Returns whether every required deterministic hardening behavior was exercised.
    pub const fn covers_lane_a(self) -> bool {
        self.partition
            && self.heal
            && self.delay
            && self.reorder
            && self.loss
            && self.duplicate
            && self.fork
            && self.fork_resolution
            && self.crash
            && self.reopen
            && self.storage_loss
            && self.provider_outage
            && self.provider_equivocation
            && self.recovery
            && self.controller_revocation
            && self.device_revocation
            && self.migration_begin
            && self.migration_activate
            && self.migration_complete
            && self.group_key_rotation
    }

    /// Derives declared coverage without executing the scenario.
    pub fn from_scenario(scenario: &IdentityScenario) -> Self {
        let mut coverage = Self::default();
        for action in scenario.actions() {
            coverage.observe(&action.action);
        }
        coverage
    }

    /// Union used by strict corpus coverage validation.
    pub fn include(&mut self, other: Self) {
        self.partition |= other.partition;
        self.heal |= other.heal;
        self.delay |= other.delay;
        self.reorder |= other.reorder;
        self.loss |= other.loss;
        self.duplicate |= other.duplicate;
        self.fork |= other.fork;
        self.fork_resolution |= other.fork_resolution;
        self.crash |= other.crash;
        self.reopen |= other.reopen;
        self.storage_loss |= other.storage_loss;
        self.provider_outage |= other.provider_outage;
        self.provider_equivocation |= other.provider_equivocation;
        self.recovery |= other.recovery;
        self.controller_revocation |= other.controller_revocation;
        self.device_revocation |= other.device_revocation;
        self.migration_begin |= other.migration_begin;
        self.migration_activate |= other.migration_activate;
        self.migration_complete |= other.migration_complete;
        self.group_key_rotation |= other.group_key_rotation;
    }
}

/// Per-invariant evaluation counters emitted after every action.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Section36Counters {
    pub account_is_not_device: u64,
    pub no_ordinary_private_key_replication: u64,
    pub device_independently_revocable: u64,
    pub prior_policy_authorization: u64,
    pub stable_account_identity: u64,
    pub provider_cannot_create_state: u64,
    pub social_no_implicit_authority: u64,
    pub published_revocation_discoverability: u64,
    pub offline_validation_has_basis: u64,
    pub sensitive_actions_fail_closed: u64,
    pub revoked_device_excluded_from_group_keys: u64,
    pub conflicts_detected_not_merged: u64,
}

impl Section36Counters {
    /// Every Section 36 invariant must be evaluated once per executed action.
    pub fn all_checked_at_each_step(self, steps: usize) -> bool {
        let Ok(expected) = u64::try_from(steps) else {
            return false;
        };
        [
            self.account_is_not_device,
            self.no_ordinary_private_key_replication,
            self.device_independently_revocable,
            self.prior_policy_authorization,
            self.stable_account_identity,
            self.provider_cannot_create_state,
            self.social_no_implicit_authority,
            self.published_revocation_discoverability,
            self.offline_validation_has_basis,
            self.sensitive_actions_fail_closed,
            self.revoked_device_excluded_from_group_keys,
            self.conflicts_detected_not_merged,
        ]
        .into_iter()
        .all(|count| count == expected && count > 0)
    }
}

/// Deliberate observation mutation used to prove each Section 36 oracle is live.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Section36Mutation {
    AccountIsDevice,
    OrdinaryPrivateKeyReplication,
    DeviceNotIndependentlyRevocable,
    PriorPolicyBypass,
    AccountIdentityChanged,
    ProviderCreatedState,
    SocialRelationshipCreatedAuthority,
    PublishedRevocationUndiscoverable,
    OfflineValidationWithoutBasis,
    SensitiveActionDidNotFailClosed,
    RevokedDeviceReceivedGroupKey,
    ConflictSilentlyMerged,
}

/// One post-action state and invariant observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityStepReport {
    pub action_id: String,
    pub outcome: String,
    pub state: AccountModelSnapshot,
    pub environment: IdentityEnvironmentSnapshot,
}

/// Simulator-owned delivery evidence for partition and transport-fault actions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityDeliveryReport {
    pub pending: Vec<u64>,
    pub delivered: Vec<u64>,
    pub delayed: u64,
    pub reordered: u64,
    pub dropped: u64,
    pub duplicate_deliveries: u64,
}

/// One non-authoritative replica's deterministic storage/lifecycle observation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityReplicaSnapshot {
    pub replica: u16,
    pub crashed: bool,
    pub has_projection: bool,
}

/// Simulator-owned transport, provider, and replica facts after one action.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityEnvironmentSnapshot {
    pub partitioned: bool,
    pub provider_available: bool,
    pub provider_consistent: bool,
    pub replicas: Vec<IdentityReplicaSnapshot>,
    pub delivery: IdentityDeliveryReport,
}

/// Deterministic terminal report, including scheduler and task ownership evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityRunReport {
    pub schema_version: u16,
    pub scenario_id: String,
    pub steps: Vec<IdentityStepReport>,
    pub final_state: AccountModelSnapshot,
    pub coverage: IdentityCoverage,
    pub invariants: Section36Counters,
    pub delivery: IdentityDeliveryReport,
    pub scheduler: KernelSchedulerSnapshot,
    pub tasks: Vec<KernelTaskSnapshot>,
    pub events_executed: u64,
    pub virtual_time_nanos: u64,
}

/// Complete in-memory record used for byte-exact replay and immutable artifacts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityRunRecord {
    /// Behavioral root seed required for exact replay.
    pub root_seed: [u8; 32],
    /// Stable semantic report.
    pub report: IdentityRunReport,
    /// Raw structured runtime trace.
    pub trace: Vec<TraceEvent>,
}

/// Stable class for a deterministic product failure observed inside a scenario task.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityFailureClass {
    /// An unmarked, mismatched, or internally invalid model transition failed.
    Model,
    /// A scenario action violated its declared transition contract.
    Execution,
    /// A Section 36 postcondition failed.
    Invariant,
    /// Checked arithmetic exhausted a declared bound.
    Arithmetic,
    /// The deterministic runtime or trace recorder failed.
    Runtime,
}

impl IdentityFailureClass {
    /// Stable spelling committed by failure signatures and regression metadata.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Model => "model",
            Self::Execution => "execution",
            Self::Invariant => "invariant",
            Self::Arithmetic => "arithmetic",
            Self::Runtime => "runtime",
        }
    }
}

/// Stable non-product terminal class for a correctly rejected protocol transition.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityRejectionClass {
    /// The independent account-control model rejected an invalid transition atomically.
    Model,
}

impl IdentityRejectionClass {
    /// Stable spelling committed by expected-rejection replay artifacts.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Model => "model",
        }
    }
}

/// Bounded, typed evidence for a correct fail-closed protocol rejection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityRejectionEvidence {
    /// Stable expected-rejection class.
    pub class: IdentityRejectionClass,
    /// Exact action-declared model-rejection discriminant that matched.
    pub rejection: ExpectedModelRejection,
    /// Deterministic model evidence explaining why the transition was rejected.
    pub detail: String,
}

impl IdentityRejectionEvidence {
    fn new(rejection: ExpectedModelRejection, error: &IdentityScenarioError) -> Self {
        Self {
            class: IdentityRejectionClass::Model,
            rejection,
            detail: error.to_string(),
        }
    }
}

/// Bounded, typed evidence used to derive one exact failure identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityFailureEvidence {
    /// Stable terminal class.
    pub class: IdentityFailureClass,
    /// Deterministic error evidence produced by the model or invariant oracle.
    pub detail: String,
}

impl IdentityFailureEvidence {
    fn from_error(error: &IdentityScenarioError) -> Self {
        let class = match error {
            IdentityScenarioError::Model(_) => IdentityFailureClass::Model,
            IdentityScenarioError::ExpectedRejection(_) | IdentityScenarioError::Execution(_) => {
                IdentityFailureClass::Execution
            }
            IdentityScenarioError::Invariant(_) => IdentityFailureClass::Invariant,
            IdentityScenarioError::ArithmeticOverflow => IdentityFailureClass::Arithmetic,
            IdentityScenarioError::Runtime(_) => IdentityFailureClass::Runtime,
            IdentityScenarioError::UnsupportedSchema(_)
            | IdentityScenarioError::InputTooLarge { .. }
            | IdentityScenarioError::InvalidText(_)
            | IdentityScenarioError::InvalidActionCount(_)
            | IdentityScenarioError::DuplicateAction(_)
            | IdentityScenarioError::InvalidVirtualTime(_)
            | IdentityScenarioError::InvalidAction { .. }
            | IdentityScenarioError::Encoding(_) => IdentityFailureClass::Execution,
        };
        Self {
            class,
            detail: error.to_string(),
        }
    }
}

/// Complete partial state and trace retained when a deterministic product failure occurs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityFailedRunRecord {
    /// Behavioral root seed required for confirmation and replay.
    pub root_seed: [u8; 32],
    /// Stable typed terminal evidence.
    pub evidence: IdentityFailureEvidence,
    /// State, scheduler, task, and invariant observations captured at termination.
    pub report: IdentityRunReport,
    /// Raw structured runtime trace captured at termination.
    pub trace: Vec<TraceEvent>,
}

/// Complete deterministic record for a correct fail-closed model rejection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityRejectedRunRecord {
    /// Behavioral root seed required for exact replay.
    pub root_seed: [u8; 32],
    /// Stable typed expected-rejection evidence.
    pub evidence: IdentityRejectionEvidence,
    /// State, scheduler, task, and invariant observations captured after all owned tasks finish.
    pub report: IdentityRunReport,
    /// Raw structured runtime trace captured for exact replay.
    pub trace: Vec<TraceEvent>,
}

/// Detailed terminal result that preserves failed-run evidence instead of discarding it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityRunOutcome {
    /// Every scheduled action completed without a model or invariant failure.
    Success(IdentityRunRecord),
    /// A semantically valid scenario action was correctly rejected by the account-control model.
    ExpectedRejection(IdentityRejectedRunRecord),
    /// A deterministic product failure completed with a replayable partial record.
    Failed(IdentityFailedRunRecord),
}

/// Executes identity actions through the real seeded deterministic kernel.
#[derive(Clone, Copy, Debug)]
pub struct IdentityScenarioRunner;

impl IdentityScenarioRunner {
    /// Runs one validated scenario with all actions owned by structured kernel tasks.
    pub fn run(
        scenario: &IdentityScenario,
        seed: RootSeed,
    ) -> Result<IdentityRunRecord, IdentityScenarioError> {
        match Self::run_detailed(scenario, seed)? {
            IdentityRunOutcome::Success(record) => Ok(record),
            IdentityRunOutcome::ExpectedRejection(rejection) => Err(
                IdentityScenarioError::ExpectedRejection(rejection.evidence.detail),
            ),
            IdentityRunOutcome::Failed(failure) => Err(IdentityScenarioError::Execution(format!(
                "{}: {}",
                failure.evidence.class.as_str(),
                failure.evidence.detail
            ))),
        }
    }

    /// Runs one scenario while retaining a complete deterministic terminal record on failure.
    pub fn run_detailed(
        scenario: &IdentityScenario,
        seed: RootSeed,
    ) -> Result<IdentityRunOutcome, IdentityScenarioError> {
        Self::run_configured(scenario, seed, None)
    }

    /// Executes the real kernel while injecting one bounded oracle counterexample.
    pub fn run_with_invariant_mutation(
        scenario: &IdentityScenario,
        seed: RootSeed,
        mutation: Section36Mutation,
    ) -> Result<IdentityRunOutcome, IdentityScenarioError> {
        Self::run_configured(scenario, seed, Some(mutation))
    }

    fn run_configured(
        scenario: &IdentityScenario,
        seed: RootSeed,
        mutation: Option<Section36Mutation>,
    ) -> Result<IdentityRunOutcome, IdentityScenarioError> {
        scenario.validate()?;
        let trace = Arc::new(
            TraceBuffer::new(10_000)
                .map_err(|error| IdentityScenarioError::Runtime(error.to_string()))?,
        );
        let kernel = Kernel::new(
            KernelConfig {
                max_events: 10_000,
                max_scheduled_events: 2_048,
                max_virtual_time: Duration::from_nanos(MAX_IDENTITY_VIRTUAL_NANOS),
                max_tasks: 512,
                max_trace_events: 10_000,
                resource_limits: KernelResourceLimits::uniform(512),
            },
            trace.clone(),
        )
        .map_err(|error| IdentityScenarioError::Runtime(error.to_string()))?;
        let context = kernel.runtime_context(seed, krikos_runtime::SystemTime::UNIX_EPOCH);
        let group = context.executor().new_group(None);
        let world = Arc::new(Mutex::new(ScenarioWorld::new(mutation)?));

        for scheduled in scenario.actions.iter().cloned() {
            let clock = context.clock();
            let recorder = context.trace();
            let world = world.clone();
            let task_name = format!("identity/{}", scheduled.id);
            group
                .spawn(
                    TaskKind::Other("identity_action".to_owned()),
                    &task_name,
                    Box::pin(async move {
                        let sleep = ClockSleep::after(
                            clock.clone(),
                            Duration::from_nanos(scheduled.at_nanos),
                        );
                        let sleep_result = match sleep {
                            Ok(sleep) => sleep.await.map_err(|error| error.to_string()),
                            Err(error) => Err(error.to_string()),
                        };
                        if let Err(error) = sleep_result {
                            record_task_failure(&world, format!("virtual clock: {error}"));
                            return;
                        }
                        let now = clock.elapsed_nanos().unwrap_or(scheduled.at_nanos);
                        if let Err(error) = recorder.record(
                            now,
                            TraceContext {
                                operation: Some(scheduled.id.clone()),
                                ..TraceContext::default()
                            },
                            TraceEventKind::OperationStarted {
                                action: action_name(&scheduled.action).to_owned(),
                            },
                        ) {
                            record_task_failure(&world, format!("trace: {error}"));
                            return;
                        }

                        let (outcome, invariant_names) = execute_scheduled(&world, &scheduled);
                        for invariant in invariant_names {
                            if let Err(error) = recorder.record(
                                now,
                                TraceContext {
                                    operation: Some(scheduled.id.clone()),
                                    invariant: Some(invariant.clone()),
                                    ..TraceContext::default()
                                },
                                TraceEventKind::InvariantSatisfied {
                                    obligation: invariant,
                                },
                            ) {
                                record_task_failure(&world, format!("trace: {error}"));
                                return;
                            }
                        }
                        if let Err(error) = recorder.record(
                            now,
                            TraceContext {
                                operation: Some(scheduled.id),
                                ..TraceContext::default()
                            },
                            TraceEventKind::OperationCompleted { outcome },
                        ) {
                            record_task_failure(&world, format!("trace: {error}"));
                        }
                    }),
                )
                .map_err(|error| IdentityScenarioError::Runtime(error.to_string()))?;
        }
        group.close();
        let run = kernel
            .run_until_idle()
            .map_err(|error| IdentityScenarioError::Runtime(error.to_string()))?;
        if run.quiescence != Quiescence::Complete {
            return Err(IdentityScenarioError::Runtime(format!(
                "identity tasks did not complete: {:?}",
                run.quiescence
            )));
        }
        let world = world
            .lock()
            .map_err(|_| IdentityScenarioError::Runtime("identity world lock poisoned".into()))?;
        let report = IdentityRunReport {
            schema_version: IDENTITY_SCENARIO_SCHEMA_VERSION,
            scenario_id: scenario.id.clone(),
            steps: world.steps.clone(),
            final_state: world.model.snapshot(),
            coverage: world.coverage,
            invariants: world.invariants,
            delivery: world.delivery.clone(),
            scheduler: run.scheduler,
            tasks: kernel.task_ownership_snapshot(),
            events_executed: run.events_executed,
            virtual_time_nanos: u64::try_from(run.virtual_time.as_nanos()).map_err(|_| {
                IdentityScenarioError::Runtime("virtual time does not fit u64".into())
            })?,
        };
        let trace = trace.events();
        let root_seed = *seed.as_bytes();
        Ok(if let Some(evidence) = &world.failure {
            IdentityRunOutcome::Failed(IdentityFailedRunRecord {
                root_seed,
                evidence: evidence.clone(),
                report,
                trace,
            })
        } else if let Some(evidence) = &world.rejection {
            IdentityRunOutcome::ExpectedRejection(IdentityRejectedRunRecord {
                root_seed,
                evidence: evidence.clone(),
                report,
                trace,
            })
        } else {
            IdentityRunOutcome::Success(IdentityRunRecord {
                root_seed,
                report,
                trace,
            })
        })
    }
}

#[derive(Clone, Debug)]
struct ForkBase {
    predecessor: EventId,
    sequence: u64,
    epoch: u64,
    branches: BTreeMap<String, EventId>,
}

#[derive(Clone, Debug)]
struct ReplicaState {
    crashed: bool,
    has_projection: bool,
}

impl Default for ReplicaState {
    fn default() -> Self {
        Self {
            crashed: false,
            has_projection: true,
        }
    }
}

#[derive(Debug)]
struct ScenarioWorld {
    model: AccountControlModel,
    next_event: u64,
    fork_bases: BTreeMap<String, ForkBase>,
    replicas: BTreeMap<u16, ReplicaState>,
    delivery: IdentityDeliveryReport,
    partitioned: bool,
    provider_available: bool,
    provider_consistent: bool,
    pending_revocations: BTreeSet<String>,
    durable_revocations: BTreeSet<String>,
    externally_discoverable: BTreeSet<String>,
    coverage: IdentityCoverage,
    invariants: Section36Counters,
    steps: Vec<IdentityStepReport>,
    rejection: Option<IdentityRejectionEvidence>,
    failure: Option<IdentityFailureEvidence>,
    invariant_mutation: Option<Section36Mutation>,
}

#[derive(Debug)]
struct Section36Observation {
    after: AccountModelSnapshot,
    action: IdentityScenarioAction,
    action_succeeded: bool,
    outcome: String,
    durable_revocations: BTreeSet<String>,
    externally_discoverable: BTreeSet<String>,
    ordinary_private_key_recipients: BTreeSet<DeviceId>,
    account_modeled_as_device: bool,
}

impl Section36Observation {
    fn apply_mutation(
        &mut self,
        mutation: Section36Mutation,
        before: &AccountModelSnapshot,
        before_environment: &IdentityEnvironmentSnapshot,
    ) -> Result<bool, IdentityScenarioError> {
        let applied = match mutation {
            Section36Mutation::AccountIsDevice => {
                self.account_modeled_as_device = true;
                true
            }
            Section36Mutation::OrdinaryPrivateKeyReplication => {
                self.ordinary_private_key_recipients
                    .insert(DeviceId::new(1));
                true
            }
            Section36Mutation::DeviceNotIndependentlyRevocable => {
                let IdentityScenarioAction::RevokeDevice { device, .. } = &self.action else {
                    return Ok(false);
                };
                if !self.action_succeeded {
                    return Ok(false);
                }
                self.after
                    .devices
                    .insert(DeviceId::new(*device), DeviceLifecycle::Active);
                true
            }
            Section36Mutation::PriorPolicyBypass => {
                self.action_succeeded && clear_action_approvals(&mut self.action)
            }
            Section36Mutation::AccountIdentityChanged => {
                self.after.account_id = [0x22_u8; 32];
                true
            }
            Section36Mutation::ProviderCreatedState => {
                if !matches!(
                    &self.action,
                    IdentityScenarioAction::ProviderOutage
                        | IdentityScenarioAction::ProviderRestore
                        | IdentityScenarioAction::ProviderEquivocation
                ) {
                    return Ok(false);
                }
                self.after.sequence = self
                    .after
                    .sequence
                    .checked_add(1)
                    .ok_or(IdentityScenarioError::ArithmeticOverflow)?;
                true
            }
            Section36Mutation::SocialRelationshipCreatedAuthority => {
                if !matches!(&self.action, IdentityScenarioAction::SocialRelationship) {
                    return Ok(false);
                }
                self.after.sequence = self
                    .after
                    .sequence
                    .checked_add(1)
                    .ok_or(IdentityScenarioError::ArithmeticOverflow)?;
                true
            }
            Section36Mutation::PublishedRevocationUndiscoverable => {
                let IdentityScenarioAction::PublishRevocation { subject } = &self.action else {
                    return Ok(false);
                };
                if !self.action_succeeded {
                    return Ok(false);
                }
                self.durable_revocations.remove(subject);
                true
            }
            Section36Mutation::OfflineValidationWithoutBasis => {
                if !matches!(&self.action, IdentityScenarioAction::OfflineValidate) {
                    return Ok(false);
                }
                self.outcome = if before.forked {
                    "basis:mutated".into()
                } else {
                    "no_basis".into()
                };
                true
            }
            Section36Mutation::SensitiveActionDidNotFailClosed => {
                let sensitive_is_unsafe = !before_environment.provider_available
                    || !before_environment.provider_consistent
                    || before.forked;
                if !matches!(&self.action, IdentityScenarioAction::SensitiveProbe)
                    || !sensitive_is_unsafe
                {
                    return Ok(false);
                }
                self.outcome = "allowed".into();
                true
            }
            Section36Mutation::RevokedDeviceReceivedGroupKey => {
                let IdentityScenarioAction::RevokeDevice { device, .. } = &self.action else {
                    return Ok(false);
                };
                if !self.action_succeeded {
                    return Ok(false);
                }
                let target = DeviceId::new(*device);
                if let Err(index) = self.after.group_key_recipients.binary_search(&target) {
                    self.after.group_key_recipients.insert(index, target);
                }
                true
            }
            Section36Mutation::ConflictSilentlyMerged => {
                if !self.after.forked || self.outcome != "forkdetected" {
                    return Ok(false);
                }
                self.after.forked = false;
                self.after.heads.truncate(1);
                true
            }
        };
        Ok(applied)
    }
}

impl ScenarioWorld {
    fn new(invariant_mutation: Option<Section36Mutation>) -> Result<Self, IdentityScenarioError> {
        let controllers = vec![
            ModelController::new(ControllerId::new(1), 1)?,
            ModelController::new(ControllerId::new(2), 1)?,
        ];
        Ok(Self {
            model: AccountControlModel::new([0x11; 32], controllers, ModelPolicy::new(1)?)?,
            next_event: 1,
            fork_bases: BTreeMap::new(),
            replicas: BTreeMap::from([(1, ReplicaState::default())]),
            delivery: IdentityDeliveryReport {
                pending: vec![1, 2, 3, 4],
                delivered: Vec::new(),
                delayed: 0,
                reordered: 0,
                dropped: 0,
                duplicate_deliveries: 0,
            },
            partitioned: false,
            provider_available: true,
            provider_consistent: true,
            pending_revocations: BTreeSet::new(),
            durable_revocations: BTreeSet::new(),
            externally_discoverable: BTreeSet::new(),
            coverage: IdentityCoverage::default(),
            invariants: Section36Counters::default(),
            steps: Vec::new(),
            rejection: None,
            failure: None,
            invariant_mutation,
        })
    }

    fn allocate_event(&mut self) -> Result<EventId, IdentityScenarioError> {
        let id = self.next_event;
        self.next_event = self
            .next_event
            .checked_add(1)
            .ok_or(IdentityScenarioError::ArithmeticOverflow)?;
        Ok(EventId::new(id))
    }

    fn environment_snapshot(&self) -> IdentityEnvironmentSnapshot {
        IdentityEnvironmentSnapshot {
            partitioned: self.partitioned,
            provider_available: self.provider_available,
            provider_consistent: self.provider_consistent,
            replicas: self
                .replicas
                .iter()
                .map(|(replica, state)| IdentityReplicaSnapshot {
                    replica: *replica,
                    crashed: state.crashed,
                    has_projection: state.has_projection,
                })
                .collect(),
            delivery: self.delivery.clone(),
        }
    }

    fn current_position(&self) -> Result<(EventId, u64, u64), IdentityScenarioError> {
        let snapshot = self.model.snapshot();
        let predecessor = match snapshot.heads.as_slice() {
            [] if snapshot.sequence == 0 => EventId::new(0),
            [head] if !snapshot.forked => *head,
            _ => return Err(IdentityScenarioError::Execution("account is forked".into())),
        };
        Ok((predecessor, snapshot.sequence, snapshot.epoch))
    }

    fn apply_ordinary(
        &mut self,
        operation: IdentityOperation,
        approvals: &[u16],
    ) -> Result<String, IdentityScenarioError> {
        let (predecessor, sequence, epoch) = self.current_position()?;
        let resulting_epoch = operation.resulting_epoch(epoch)?;
        let event = IdentityEvent::new(
            self.allocate_event()?,
            predecessor,
            sequence
                .checked_add(1)
                .ok_or(IdentityScenarioError::ArithmeticOverflow)?,
            resulting_epoch,
            controller_ids(approvals),
            operation,
        )?;
        let disposition = self.model.apply(&event)?;
        Ok(format!("{disposition:?}").to_ascii_lowercase())
    }

    fn apply_recovery(
        &mut self,
        controllers: &[RecoveryController],
        required_weight: u16,
    ) -> Result<String, IdentityScenarioError> {
        if !self.provider_available || !self.provider_consistent {
            return Err(IdentityScenarioError::Execution(
                "recovery evidence unavailable or inconsistent".into(),
            ));
        }
        let plan = RecoveryPlan::new(
            controllers
                .iter()
                .map(|controller| {
                    ModelController::new(
                        ControllerId::new(controller.controller),
                        controller.weight,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?,
            ModelPolicy::new(required_weight)?,
        )?;
        let (predecessor, sequence, epoch) = self.current_position()?;
        let event = IdentityEvent::new(
            self.allocate_event()?,
            predecessor,
            sequence
                .checked_add(1)
                .ok_or(IdentityScenarioError::ArithmeticOverflow)?,
            epoch
                .checked_add(1)
                .ok_or(IdentityScenarioError::ArithmeticOverflow)?,
            Vec::new(),
            IdentityOperation::Recover(plan),
        )?;
        let disposition = self.model.apply_recovery(&event)?;
        Ok(format!("{disposition:?}").to_ascii_lowercase())
    }

    fn propose_fork(
        &mut self,
        fork: &str,
        branch: &str,
        approvals: &[u16],
        operation: &ForkScenarioOperation,
    ) -> Result<String, IdentityScenarioError> {
        let position = self.current_position();
        if !self.fork_bases.contains_key(fork) {
            let (predecessor, sequence, epoch) = position?;
            self.fork_bases.insert(
                fork.to_owned(),
                ForkBase {
                    predecessor,
                    sequence,
                    epoch,
                    branches: BTreeMap::new(),
                },
            );
        }
        let base = self
            .fork_bases
            .get(fork)
            .cloned()
            .ok_or_else(|| IdentityScenarioError::Execution("missing fork base".into()))?;
        if base.branches.contains_key(branch) {
            return Err(IdentityScenarioError::Execution(
                "duplicate fork branch".into(),
            ));
        }
        let event_id = self.allocate_event()?;
        let event = IdentityEvent::new(
            event_id,
            base.predecessor,
            base.sequence
                .checked_add(1)
                .ok_or(IdentityScenarioError::ArithmeticOverflow)?,
            base.epoch
                .checked_add(1)
                .ok_or(IdentityScenarioError::ArithmeticOverflow)?,
            controller_ids(approvals),
            fork_operation(operation)?,
        )?;
        let disposition = self.model.apply(&event)?;
        self.fork_bases
            .get_mut(fork)
            .ok_or_else(|| IdentityScenarioError::Execution("missing fork base".into()))?
            .branches
            .insert(branch.to_owned(), event_id);
        Ok(format!("{disposition:?}").to_ascii_lowercase())
    }

    fn resolve_fork(
        &mut self,
        fork: &str,
        selected_branch: &str,
        approvals: &[u16],
        revoked_controllers: &[u16],
        revoked_devices: &[u16],
    ) -> Result<String, IdentityScenarioError> {
        let base = self
            .fork_bases
            .get(fork)
            .cloned()
            .ok_or_else(|| IdentityScenarioError::Execution("unknown fork".into()))?;
        let selected_head = *base
            .branches
            .get(selected_branch)
            .ok_or_else(|| IdentityScenarioError::Execution("unknown fork branch".into()))?;
        let heads = self.model.snapshot().heads;
        let resolution = ForkResolution::new(
            self.allocate_event()?,
            heads,
            selected_head,
            base.sequence
                .checked_add(2)
                .ok_or(IdentityScenarioError::ArithmeticOverflow)?,
            base.epoch
                .checked_add(2)
                .ok_or(IdentityScenarioError::ArithmeticOverflow)?,
            controller_ids(approvals),
            controller_ids(revoked_controllers),
            revoked_devices.iter().copied().map(DeviceId::new).collect(),
        )?;
        let disposition = self.model.resolve_fork(&resolution)?;
        Ok(format!("{disposition:?}").to_ascii_lowercase())
    }

    fn check_invariants(
        &mut self,
        before: &AccountModelSnapshot,
        before_environment: &IdentityEnvironmentSnapshot,
        action: &IdentityScenarioAction,
        action_succeeded: bool,
        outcome: &str,
    ) -> Result<Vec<String>, IdentityScenarioError> {
        let mut observation = Section36Observation {
            after: self.model.snapshot(),
            action: action.clone(),
            action_succeeded,
            outcome: outcome.to_owned(),
            durable_revocations: self.durable_revocations.clone(),
            externally_discoverable: self.externally_discoverable.clone(),
            ordinary_private_key_recipients: BTreeSet::new(),
            account_modeled_as_device: false,
        };
        if let Some(mutation) = self.invariant_mutation
            && observation.apply_mutation(mutation, before, before_environment)?
        {
            self.invariant_mutation = None;
        }
        let after = &observation.after;
        let action = &observation.action;
        let outcome = observation.outcome.as_str();
        let active_devices = after
            .devices
            .iter()
            .filter_map(|(id, lifecycle)| (*lifecycle == DeviceLifecycle::Active).then_some(*id))
            .collect::<BTreeSet<_>>();
        let recipients = after
            .group_key_recipients
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let action_is_secret_free = observation.ordinary_private_key_recipients.is_empty();
        let device_revocation_is_independent = match action {
            IdentityScenarioAction::RevokeDevice { device, .. } if action_succeeded => {
                let target = DeviceId::new(*device);
                after.devices.get(&target) == Some(&DeviceLifecycle::Revoked)
                    && before.devices.iter().all(|(id, lifecycle)| {
                        *id == target || after.devices.get(id) == Some(lifecycle)
                    })
            }
            _ => after.devices.keys().all(|device| device.get() != 0),
        };
        let prior_policy_authorized = !action_succeeded
            || action_approvals(action)
                .is_none_or(|approvals| approvals_satisfy_prior_policy(before, approvals));
        let provider_action = matches!(
            action,
            IdentityScenarioAction::ProviderOutage
                | IdentityScenarioAction::ProviderRestore
                | IdentityScenarioAction::ProviderEquivocation
        );
        let publication_is_discoverable = observation
            .externally_discoverable
            .is_subset(&observation.durable_revocations)
            && match action {
                IdentityScenarioAction::PublishRevocation { subject } if action_succeeded => {
                    observation.durable_revocations.contains(subject)
                        && observation.externally_discoverable.contains(subject)
                }
                _ => true,
            };
        let offline_basis_is_valid = match action {
            IdentityScenarioAction::OfflineValidate => {
                let expected = if before.forked {
                    "no_basis".to_owned()
                } else {
                    format!("basis:{}/{}", before.sequence, before.epoch)
                };
                outcome == expected
            }
            _ => true,
        };
        let sensitive_is_unsafe = !before_environment.provider_available
            || !before_environment.provider_consistent
            || before.forked;
        let sensitive_failed_closed = !matches!(action, IdentityScenarioAction::SensitiveProbe)
            || !sensitive_is_unsafe
            || (outcome == "failed_closed" && before == after);
        let conflict_shape_is_consistent = after.forked == (after.heads.len() > 1);
        let newly_visible_conflict_was_reported =
            before.forked || !after.forked || outcome == "forkdetected";
        let reported_conflict_is_retained = outcome != "forkdetected" || after.forked;
        let prior_conflict_was_not_silently_merged = !before.forked
            || if matches!(action, IdentityScenarioAction::ResolveFork { .. }) && action_succeeded {
                !after.forked && after.heads.len() == 1
            } else {
                after.forked
                    && before
                        .heads
                        .iter()
                        .all(|head| after.heads.binary_search(head).is_ok())
            };
        let conflicts_detected = conflict_shape_is_consistent
            && newly_visible_conflict_was_reported
            && reported_conflict_is_retained
            && prior_conflict_was_not_silently_merged;
        let results = [
            (
                "account_is_not_device",
                !observation.account_modeled_as_device
                    && after.account_id != [0_u8; 32]
                    && after.devices.keys().all(|device| device.get() != 0),
            ),
            ("no_ordinary_private_key_replication", action_is_secret_free),
            (
                "device_independently_revocable",
                device_revocation_is_independent,
            ),
            ("prior_policy_authorization", prior_policy_authorized),
            (
                "stable_account_identity",
                before.account_id == after.account_id,
            ),
            (
                "provider_cannot_create_state",
                !provider_action || before == after,
            ),
            (
                "social_no_implicit_authority",
                !matches!(action, IdentityScenarioAction::SocialRelationship) || before == after,
            ),
            (
                "published_revocation_discoverability",
                publication_is_discoverable,
            ),
            ("offline_validation_has_basis", offline_basis_is_valid),
            ("sensitive_actions_fail_closed", sensitive_failed_closed),
            (
                "revoked_device_excluded_from_group_keys",
                recipients.is_subset(&active_devices),
            ),
            ("conflicts_detected_not_merged", conflicts_detected),
        ];

        increment_counter(&mut self.invariants.account_is_not_device)?;
        increment_counter(&mut self.invariants.no_ordinary_private_key_replication)?;
        increment_counter(&mut self.invariants.device_independently_revocable)?;
        increment_counter(&mut self.invariants.prior_policy_authorization)?;
        increment_counter(&mut self.invariants.stable_account_identity)?;
        increment_counter(&mut self.invariants.provider_cannot_create_state)?;
        increment_counter(&mut self.invariants.social_no_implicit_authority)?;
        increment_counter(&mut self.invariants.published_revocation_discoverability)?;
        increment_counter(&mut self.invariants.offline_validation_has_basis)?;
        increment_counter(&mut self.invariants.sensitive_actions_fail_closed)?;
        increment_counter(&mut self.invariants.revoked_device_excluded_from_group_keys)?;
        increment_counter(&mut self.invariants.conflicts_detected_not_merged)?;

        if let Some((name, _)) = results.iter().find(|(_, satisfied)| !satisfied) {
            return Err(IdentityScenarioError::Invariant((*name).to_owned()));
        }
        Ok(results
            .into_iter()
            .map(|(name, _)| format!("section36/{name}"))
            .collect())
    }

    fn record_expected_rejection(
        &mut self,
        rejection: ExpectedModelRejection,
        error: &IdentityScenarioError,
    ) {
        if self.rejection.is_none() {
            self.rejection = Some(IdentityRejectionEvidence::new(rejection, error));
        }
    }

    fn record_product_error(&mut self, error: &IdentityScenarioError) {
        if self.failure.is_none() {
            self.failure = Some(IdentityFailureEvidence::from_error(error));
        }
    }
}

fn execute_scheduled(
    world: &Arc<Mutex<ScenarioWorld>>,
    scheduled: &IdentityAction,
) -> (String, Vec<String>) {
    let mut world = match world.lock() {
        Ok(world) => world,
        Err(_) => return ("error:poisoned".into(), Vec::new()),
    };
    world.coverage.observe(&scheduled.action);
    let before = world.model.snapshot();
    let before_environment = world.environment_snapshot();
    let result = execute_action(&mut world, &scheduled.action);
    let action_succeeded = result.is_ok();
    let expected_rejection = scheduled.expectation.expected_model_rejection();
    let outcome = match result {
        Ok(outcome) => match expected_rejection {
            None => outcome,
            Some(expected) => {
                let error = IdentityScenarioError::Execution(format!(
                    "action {} expected model rejection {} but succeeded",
                    scheduled.id,
                    expected.as_str()
                ));
                let detail = error.to_string();
                world.record_product_error(&error);
                format!("error:{detail}")
            }
        },
        Err(IdentityScenarioError::Model(model_error)) => {
            let actual_rejection = ExpectedModelRejection::from_model_error(&model_error);
            let error = IdentityScenarioError::Model(model_error);
            if let Some(rejection) = actual_rejection
                && expected_rejection == Some(rejection)
            {
                world.record_expected_rejection(rejection, &error);
                format!("expected_rejection:{}", rejection.as_str())
            } else {
                let detail = error.to_string();
                world.record_product_error(&error);
                format!("error:{detail}")
            }
        }
        Err(error) => {
            let detail = error.to_string();
            world.record_product_error(&error);
            format!("error:{detail}")
        }
    };
    let invariant_names = match world.check_invariants(
        &before,
        &before_environment,
        &scheduled.action,
        action_succeeded,
        &outcome,
    ) {
        Ok(names) => names,
        Err(error) => {
            world.record_product_error(&error);
            Vec::new()
        }
    };
    let state = world.model.snapshot();
    let environment = world.environment_snapshot();
    world.steps.push(IdentityStepReport {
        action_id: scheduled.id.clone(),
        outcome: outcome.clone(),
        state,
        environment,
    });
    (outcome, invariant_names)
}

fn execute_action(
    world: &mut ScenarioWorld,
    action: &IdentityScenarioAction,
) -> Result<String, IdentityScenarioError> {
    match action {
        IdentityScenarioAction::Partition => {
            world.partitioned = true;
            Ok("partitioned".into())
        }
        IdentityScenarioAction::Heal => {
            world.partitioned = false;
            let pending = std::mem::take(&mut world.delivery.pending);
            world.delivery.delivered.extend(pending);
            Ok("healed".into())
        }
        IdentityScenarioAction::DeliveryFault { fault } => match fault {
            IdentityDeliveryFault::Delay => {
                if world.delivery.pending.is_empty() {
                    return Err(IdentityScenarioError::Execution(
                        "delay fault has no pending delivery".into(),
                    ));
                }
                world.delivery.pending.rotate_left(1);
                world.delivery.delayed = checked_increment(world.delivery.delayed)?;
                Ok("fault:delay".into())
            }
            IdentityDeliveryFault::Reorder => {
                if world.delivery.pending.len() < 2 {
                    return Err(IdentityScenarioError::Execution(
                        "reorder fault needs two pending deliveries".into(),
                    ));
                }
                world.delivery.pending.swap(0, 1);
                world.delivery.reordered = checked_increment(world.delivery.reordered)?;
                Ok("fault:reorder".into())
            }
            IdentityDeliveryFault::Loss => {
                if world.delivery.pending.is_empty() {
                    return Err(IdentityScenarioError::Execution(
                        "loss fault has no pending delivery".into(),
                    ));
                }
                world.delivery.pending.remove(0);
                world.delivery.dropped = checked_increment(world.delivery.dropped)?;
                Ok("fault:loss".into())
            }
            IdentityDeliveryFault::Duplicate => {
                if world.delivery.pending.is_empty()
                    || world.delivery.pending.len() >= MAX_IDENTITY_DELIVERIES
                {
                    return Err(IdentityScenarioError::Execution(
                        "duplicate fault exceeded the pending-delivery bound".into(),
                    ));
                }
                let duplicate = world.delivery.pending[0];
                world.delivery.pending.insert(1, duplicate);
                world.delivery.duplicate_deliveries =
                    checked_increment(world.delivery.duplicate_deliveries)?;
                Ok("fault:duplicate".into())
            }
        },
        IdentityScenarioAction::AddController {
            controller,
            weight,
            approvals,
        } => world.apply_ordinary(
            IdentityOperation::AddController(ModelController::new(
                ControllerId::new(*controller),
                *weight,
            )?),
            approvals,
        ),
        IdentityScenarioAction::ChangePolicy {
            required_weight,
            approvals,
        } => world.apply_ordinary(
            IdentityOperation::ChangePolicy(ModelPolicy::new(*required_weight)?),
            approvals,
        ),
        IdentityScenarioAction::AuthorizeDevice { device, approvals } => world.apply_ordinary(
            IdentityOperation::AuthorizeDevice(DeviceId::new(*device)),
            approvals,
        ),
        IdentityScenarioAction::RevokeDevice { device, approvals } => {
            let outcome = world.apply_ordinary(
                IdentityOperation::RevokeDevice(DeviceId::new(*device)),
                approvals,
            )?;
            world.pending_revocations.insert(format!("device:{device}"));
            Ok(outcome)
        }
        IdentityScenarioAction::RevokeController {
            controller,
            approvals,
        } => {
            let outcome = world.apply_ordinary(
                IdentityOperation::RevokeController(ControllerId::new(*controller)),
                approvals,
            )?;
            world
                .pending_revocations
                .insert(format!("controller:{controller}"));
            Ok(outcome)
        }
        IdentityScenarioAction::ForkProposal {
            fork,
            branch,
            approvals,
            operation,
        } => world.propose_fork(fork, branch, approvals, operation),
        IdentityScenarioAction::ResolveFork {
            fork,
            selected_branch,
            approvals,
            revoked_controllers,
            revoked_devices,
        } => world.resolve_fork(
            fork,
            selected_branch,
            approvals,
            revoked_controllers,
            revoked_devices,
        ),
        IdentityScenarioAction::Crash { replica } => {
            let replica = world.replicas.entry(*replica).or_default();
            replica.crashed = true;
            Ok("crashed".into())
        }
        IdentityScenarioAction::Reopen {
            replica,
            storage_loss,
        } => {
            let replica = world.replicas.entry(*replica).or_default();
            replica.crashed = false;
            if *storage_loss {
                replica.has_projection = false;
            }
            Ok("reopened".into())
        }
        IdentityScenarioAction::ProviderOutage => {
            world.provider_available = false;
            Ok("provider_unavailable".into())
        }
        IdentityScenarioAction::ProviderRestore => {
            world.provider_available = true;
            world.provider_consistent = true;
            Ok("provider_restored".into())
        }
        IdentityScenarioAction::ProviderEquivocation => {
            world.provider_consistent = false;
            Ok("equivocation_detected".into())
        }
        IdentityScenarioAction::SensitiveProbe => {
            if !world.provider_available
                || !world.provider_consistent
                || world.model.snapshot().forked
            {
                Ok("failed_closed".into())
            } else {
                Ok("admissible".into())
            }
        }
        IdentityScenarioAction::Recover {
            controllers,
            required_weight,
        } => world.apply_recovery(controllers, *required_weight),
        IdentityScenarioAction::Migration { phase, approvals } => {
            let operation = match phase {
                MigrationPhase::Begin => IdentityOperation::BeginMigration,
                MigrationPhase::Activate => IdentityOperation::ActivateMigration,
                MigrationPhase::Complete => IdentityOperation::CompleteMigration,
            };
            world.apply_ordinary(operation, approvals)
        }
        IdentityScenarioAction::RotateGroupKey { approvals } => {
            world.apply_ordinary(IdentityOperation::RotateGroupKey, approvals)
        }
        IdentityScenarioAction::PublishRevocation { subject } => {
            if !world.pending_revocations.contains(subject) {
                return Err(IdentityScenarioError::Execution(format!(
                    "revocation {subject} is not pending"
                )));
            }
            world.durable_revocations.insert(subject.clone());
            world.externally_discoverable.insert(subject.clone());
            Ok("durably_published".into())
        }
        IdentityScenarioAction::OfflineValidate => {
            let state = world.model.snapshot();
            if state.forked {
                Ok("no_basis".into())
            } else {
                Ok(format!("basis:{}/{}", state.sequence, state.epoch))
            }
        }
        IdentityScenarioAction::SocialRelationship => Ok("no_authority".into()),
        IdentityScenarioAction::Section36Fault { mutation } => {
            world.invariant_mutation = Some(*mutation);
            Ok("fault_injected".into())
        }
    }
}

impl IdentityCoverage {
    fn observe(&mut self, action: &IdentityScenarioAction) {
        match action {
            IdentityScenarioAction::Partition => self.partition = true,
            IdentityScenarioAction::Heal => self.heal = true,
            IdentityScenarioAction::DeliveryFault { fault } => match fault {
                IdentityDeliveryFault::Delay => self.delay = true,
                IdentityDeliveryFault::Reorder => self.reorder = true,
                IdentityDeliveryFault::Loss => self.loss = true,
                IdentityDeliveryFault::Duplicate => self.duplicate = true,
            },
            IdentityScenarioAction::ForkProposal { .. } => self.fork = true,
            IdentityScenarioAction::ResolveFork { .. } => self.fork_resolution = true,
            IdentityScenarioAction::Crash { .. } => self.crash = true,
            IdentityScenarioAction::Reopen { storage_loss, .. } => {
                self.reopen = true;
                self.storage_loss |= *storage_loss;
            }
            IdentityScenarioAction::ProviderOutage => self.provider_outage = true,
            IdentityScenarioAction::ProviderEquivocation => self.provider_equivocation = true,
            IdentityScenarioAction::Recover { .. } => self.recovery = true,
            IdentityScenarioAction::RevokeController { .. } => self.controller_revocation = true,
            IdentityScenarioAction::RevokeDevice { .. } => self.device_revocation = true,
            IdentityScenarioAction::Migration { phase, .. } => match phase {
                MigrationPhase::Begin => self.migration_begin = true,
                MigrationPhase::Activate => self.migration_activate = true,
                MigrationPhase::Complete => self.migration_complete = true,
            },
            IdentityScenarioAction::RotateGroupKey { .. } => self.group_key_rotation = true,
            IdentityScenarioAction::AddController { .. }
            | IdentityScenarioAction::ChangePolicy { .. }
            | IdentityScenarioAction::AuthorizeDevice { .. }
            | IdentityScenarioAction::ProviderRestore
            | IdentityScenarioAction::SensitiveProbe
            | IdentityScenarioAction::PublishRevocation { .. }
            | IdentityScenarioAction::OfflineValidate
            | IdentityScenarioAction::SocialRelationship
            | IdentityScenarioAction::Section36Fault { .. } => {}
        }
    }
}

fn fork_operation(
    operation: &ForkScenarioOperation,
) -> Result<IdentityOperation, IdentityScenarioError> {
    Ok(match operation {
        ForkScenarioOperation::AddController { controller, weight } => {
            IdentityOperation::AddController(ModelController::new(
                ControllerId::new(*controller),
                *weight,
            )?)
        }
        ForkScenarioOperation::AuthorizeDevice { device } => {
            IdentityOperation::AuthorizeDevice(DeviceId::new(*device))
        }
        ForkScenarioOperation::ChangePolicy { required_weight } => {
            IdentityOperation::ChangePolicy(ModelPolicy::new(*required_weight)?)
        }
    })
}

fn controller_ids(ids: &[u16]) -> Vec<ControllerId> {
    ids.iter().copied().map(ControllerId::new).collect()
}

fn checked_increment(value: u64) -> Result<u64, IdentityScenarioError> {
    value
        .checked_add(1)
        .ok_or(IdentityScenarioError::ArithmeticOverflow)
}

fn increment_counter(value: &mut u64) -> Result<(), IdentityScenarioError> {
    *value = checked_increment(*value)?;
    Ok(())
}

fn validate_text(value: &str) -> Result<(), IdentityScenarioError> {
    if value.is_empty()
        || value.len() > MAX_IDENTITY_TEXT_BYTES
        || value.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b':' | b'.' | b'_' | b'-'))
        })
    {
        return Err(IdentityScenarioError::InvalidText(value.to_owned()));
    }
    Ok(())
}

fn validate_action_semantics(
    action_id: &str,
    action: &IdentityScenarioAction,
) -> Result<(), IdentityScenarioError> {
    let valid_controller = |controller: u16| controller != 0;
    let valid_device = |device: u16| device != 0;
    match action {
        IdentityScenarioAction::AddController {
            controller,
            weight,
            approvals,
        } => {
            if !valid_controller(*controller) || *weight == 0 {
                return Err(invalid_action(
                    action_id,
                    "controller identity and weight must be nonzero",
                ));
            }
            validate_bounded_ids(action_id, approvals, MAX_MODEL_CONTROLLERS, "approvals")?;
        }
        IdentityScenarioAction::ChangePolicy {
            required_weight,
            approvals,
        } => {
            if *required_weight == 0 {
                return Err(invalid_action(
                    action_id,
                    "required policy weight must be nonzero",
                ));
            }
            validate_bounded_ids(action_id, approvals, MAX_MODEL_CONTROLLERS, "approvals")?;
        }
        IdentityScenarioAction::AuthorizeDevice { device, approvals }
        | IdentityScenarioAction::RevokeDevice { device, approvals } => {
            if !valid_device(*device) {
                return Err(invalid_action(action_id, "device identity must be nonzero"));
            }
            validate_bounded_ids(action_id, approvals, MAX_MODEL_CONTROLLERS, "approvals")?;
        }
        IdentityScenarioAction::RevokeController {
            controller,
            approvals,
        } => {
            if !valid_controller(*controller) {
                return Err(invalid_action(
                    action_id,
                    "controller identity must be nonzero",
                ));
            }
            validate_bounded_ids(action_id, approvals, MAX_MODEL_CONTROLLERS, "approvals")?;
        }
        IdentityScenarioAction::ForkProposal {
            approvals,
            operation,
            ..
        } => {
            validate_bounded_ids(action_id, approvals, MAX_MODEL_CONTROLLERS, "approvals")?;
            match operation {
                ForkScenarioOperation::AddController { controller, weight } => {
                    if !valid_controller(*controller) || *weight == 0 {
                        return Err(invalid_action(
                            action_id,
                            "fork controller identity and weight must be nonzero",
                        ));
                    }
                }
                ForkScenarioOperation::AuthorizeDevice { device } => {
                    if !valid_device(*device) {
                        return Err(invalid_action(
                            action_id,
                            "fork device identity must be nonzero",
                        ));
                    }
                }
                ForkScenarioOperation::ChangePolicy { required_weight } => {
                    if *required_weight == 0 {
                        return Err(invalid_action(
                            action_id,
                            "fork policy weight must be nonzero",
                        ));
                    }
                }
            }
        }
        IdentityScenarioAction::ResolveFork {
            approvals,
            revoked_controllers,
            revoked_devices,
            ..
        } => {
            validate_bounded_ids(action_id, approvals, MAX_MODEL_CONTROLLERS, "approvals")?;
            validate_bounded_ids(
                action_id,
                revoked_controllers,
                MAX_MODEL_CONTROLLERS,
                "revoked controllers",
            )?;
            validate_bounded_ids(
                action_id,
                revoked_devices,
                MAX_MODEL_DEVICES,
                "revoked devices",
            )?;
        }
        IdentityScenarioAction::Crash { replica }
        | IdentityScenarioAction::Reopen { replica, .. } => {
            if *replica == 0 {
                return Err(invalid_action(
                    action_id,
                    "replica identity must be nonzero",
                ));
            }
        }
        IdentityScenarioAction::Recover {
            controllers,
            required_weight,
        } => {
            if controllers.is_empty()
                || controllers.len() > MAX_MODEL_CONTROLLERS
                || *required_weight == 0
            {
                return Err(invalid_action(
                    action_id,
                    "recovery authority and threshold must be nonempty and bounded",
                ));
            }
            let mut seen = BTreeSet::new();
            let mut total_weight = 0_u16;
            for controller in controllers {
                if !valid_controller(controller.controller)
                    || controller.weight == 0
                    || !seen.insert(controller.controller)
                {
                    return Err(invalid_action(
                        action_id,
                        "recovery controllers must be unique with nonzero identities and weights",
                    ));
                }
                total_weight = total_weight.checked_add(controller.weight).ok_or_else(|| {
                    invalid_action(
                        action_id,
                        "recovery authority weight exceeds model representation",
                    )
                })?;
            }
            if *required_weight > total_weight {
                return Err(invalid_action(
                    action_id,
                    "recovery threshold exceeds declared authority weight",
                ));
            }
        }
        IdentityScenarioAction::Migration { approvals, .. }
        | IdentityScenarioAction::RotateGroupKey { approvals } => {
            validate_bounded_ids(action_id, approvals, MAX_MODEL_CONTROLLERS, "approvals")?;
        }
        IdentityScenarioAction::Partition
        | IdentityScenarioAction::Heal
        | IdentityScenarioAction::DeliveryFault { .. }
        | IdentityScenarioAction::ProviderOutage
        | IdentityScenarioAction::ProviderRestore
        | IdentityScenarioAction::ProviderEquivocation
        | IdentityScenarioAction::SensitiveProbe
        | IdentityScenarioAction::PublishRevocation { .. }
        | IdentityScenarioAction::OfflineValidate
        | IdentityScenarioAction::SocialRelationship
        | IdentityScenarioAction::Section36Fault { .. } => {}
    }
    Ok(())
}

fn validate_action_expectation(
    action_id: &str,
    action: &IdentityScenarioAction,
    expectation: IdentityActionExpectation,
) -> Result<(), IdentityScenarioError> {
    let Some(rejection) = expectation.expected_model_rejection() else {
        return Ok(());
    };
    let prior_policy_action = action_approvals(action).is_some();
    let adds_controller = matches!(
        action,
        IdentityScenarioAction::AddController { .. }
            | IdentityScenarioAction::ForkProposal {
                operation: ForkScenarioOperation::AddController { .. },
                ..
            }
    );
    let authorizes_device = matches!(
        action,
        IdentityScenarioAction::AuthorizeDevice { .. }
            | IdentityScenarioAction::ForkProposal {
                operation: ForkScenarioOperation::AuthorizeDevice { .. },
                ..
            }
    );
    let permitted = match rejection {
        ExpectedModelRejection::InsufficientWeight | ExpectedModelRejection::RevokedController => {
            prior_policy_action
        }
        ExpectedModelRejection::UnknownController => {
            prior_policy_action
                || matches!(
                    action,
                    IdentityScenarioAction::RevokeController { .. }
                        | IdentityScenarioAction::ResolveFork { .. }
                )
        }
        ExpectedModelRejection::ControllerAlreadyKnown
        | ExpectedModelRejection::ControllerLimitExceeded => adds_controller,
        ExpectedModelRejection::UnsatisfiedPolicy => matches!(
            action,
            IdentityScenarioAction::ChangePolicy { .. }
                | IdentityScenarioAction::RevokeController { .. }
                | IdentityScenarioAction::ResolveFork { .. }
                | IdentityScenarioAction::Recover { .. }
        ),
        ExpectedModelRejection::DeviceLimitExceeded => authorizes_device,
        ExpectedModelRejection::EventLimitExceeded => matches!(
            action,
            IdentityScenarioAction::AddController { .. }
                | IdentityScenarioAction::ChangePolicy { .. }
                | IdentityScenarioAction::AuthorizeDevice { .. }
                | IdentityScenarioAction::RevokeDevice { .. }
                | IdentityScenarioAction::RevokeController { .. }
                | IdentityScenarioAction::ForkProposal { .. }
                | IdentityScenarioAction::Recover { .. }
                | IdentityScenarioAction::Migration { .. }
                | IdentityScenarioAction::RotateGroupKey { .. }
        ),
        ExpectedModelRejection::UnknownDevice => matches!(
            action,
            IdentityScenarioAction::RevokeDevice { .. }
                | IdentityScenarioAction::ResolveFork { .. }
        ),
        ExpectedModelRejection::DeviceAlreadyKnown => {
            authorizes_device || matches!(action, IdentityScenarioAction::RevokeDevice { .. })
        }
        ExpectedModelRejection::RecoveryReintroducesRevokedController => {
            matches!(action, IdentityScenarioAction::Recover { .. })
        }
        ExpectedModelRejection::InvalidMigration => {
            matches!(action, IdentityScenarioAction::Migration { .. })
        }
        ExpectedModelRejection::InvalidForkResolution => {
            matches!(action, IdentityScenarioAction::ResolveFork { .. })
        }
    };
    if !permitted {
        return Err(invalid_action(
            action_id,
            "model-rejection expectation is not valid for this action kind",
        ));
    }
    Ok(())
}

fn validate_bounded_ids(
    action_id: &str,
    values: &[u16],
    maximum: usize,
    field: &'static str,
) -> Result<(), IdentityScenarioError> {
    if values.len() > maximum {
        return Err(invalid_action(
            action_id,
            match field {
                "approvals" => "approvals must be unique, nonzero, and bounded",
                "revoked controllers" => "revoked controllers must be unique, nonzero, and bounded",
                "revoked devices" => "revoked devices must be unique, nonzero, and bounded",
                _ => "identity list must be unique, nonzero, and bounded",
            },
        ));
    }
    let unique = values.iter().copied().collect::<BTreeSet<_>>();
    if unique.len() != values.len() || unique.contains(&0) {
        return Err(invalid_action(
            action_id,
            match field {
                "approvals" => "approvals must be unique, nonzero, and bounded",
                "revoked controllers" => "revoked controllers must be unique, nonzero, and bounded",
                "revoked devices" => "revoked devices must be unique, nonzero, and bounded",
                _ => "identity list must be unique, nonzero, and bounded",
            },
        ));
    }
    Ok(())
}

fn invalid_action(action_id: &str, reason: &'static str) -> IdentityScenarioError {
    IdentityScenarioError::InvalidAction {
        action: action_id.to_owned(),
        reason,
    }
}

fn action_text_fields(action: &IdentityScenarioAction) -> Vec<&str> {
    match action {
        IdentityScenarioAction::ForkProposal { fork, branch, .. } => vec![fork, branch],
        IdentityScenarioAction::ResolveFork {
            fork,
            selected_branch,
            ..
        } => vec![fork, selected_branch],
        IdentityScenarioAction::PublishRevocation { subject } => vec![subject],
        _ => Vec::new(),
    }
}

fn action_name(action: &IdentityScenarioAction) -> &'static str {
    match action {
        IdentityScenarioAction::Partition => "partition",
        IdentityScenarioAction::Heal => "heal",
        IdentityScenarioAction::DeliveryFault { .. } => "delivery_fault",
        IdentityScenarioAction::AddController { .. } => "add_controller",
        IdentityScenarioAction::ChangePolicy { .. } => "change_policy",
        IdentityScenarioAction::AuthorizeDevice { .. } => "authorize_device",
        IdentityScenarioAction::RevokeDevice { .. } => "revoke_device",
        IdentityScenarioAction::RevokeController { .. } => "revoke_controller",
        IdentityScenarioAction::ForkProposal { .. } => "fork_proposal",
        IdentityScenarioAction::ResolveFork { .. } => "resolve_fork",
        IdentityScenarioAction::Crash { .. } => "crash",
        IdentityScenarioAction::Reopen { .. } => "reopen",
        IdentityScenarioAction::ProviderOutage => "provider_outage",
        IdentityScenarioAction::ProviderRestore => "provider_restore",
        IdentityScenarioAction::ProviderEquivocation => "provider_equivocation",
        IdentityScenarioAction::SensitiveProbe => "sensitive_probe",
        IdentityScenarioAction::Recover { .. } => "recover",
        IdentityScenarioAction::Migration { .. } => "migration",
        IdentityScenarioAction::RotateGroupKey { .. } => "rotate_group_key",
        IdentityScenarioAction::PublishRevocation { .. } => "publish_revocation",
        IdentityScenarioAction::OfflineValidate => "offline_validate",
        IdentityScenarioAction::SocialRelationship => "social_relationship",
        IdentityScenarioAction::Section36Fault { .. } => "section36_fault",
    }
}

fn action_approvals(action: &IdentityScenarioAction) -> Option<&[u16]> {
    match action {
        IdentityScenarioAction::AddController { approvals, .. }
        | IdentityScenarioAction::ChangePolicy { approvals, .. }
        | IdentityScenarioAction::AuthorizeDevice { approvals, .. }
        | IdentityScenarioAction::RevokeDevice { approvals, .. }
        | IdentityScenarioAction::RevokeController { approvals, .. }
        | IdentityScenarioAction::ForkProposal { approvals, .. }
        | IdentityScenarioAction::ResolveFork { approvals, .. }
        | IdentityScenarioAction::Migration { approvals, .. }
        | IdentityScenarioAction::RotateGroupKey { approvals } => Some(approvals),
        IdentityScenarioAction::Partition
        | IdentityScenarioAction::Heal
        | IdentityScenarioAction::DeliveryFault { .. }
        | IdentityScenarioAction::Crash { .. }
        | IdentityScenarioAction::Reopen { .. }
        | IdentityScenarioAction::ProviderOutage
        | IdentityScenarioAction::ProviderRestore
        | IdentityScenarioAction::ProviderEquivocation
        | IdentityScenarioAction::SensitiveProbe
        | IdentityScenarioAction::Recover { .. }
        | IdentityScenarioAction::PublishRevocation { .. }
        | IdentityScenarioAction::OfflineValidate
        | IdentityScenarioAction::SocialRelationship
        | IdentityScenarioAction::Section36Fault { .. } => None,
    }
}

fn clear_action_approvals(action: &mut IdentityScenarioAction) -> bool {
    let approvals = match action {
        IdentityScenarioAction::AddController { approvals, .. }
        | IdentityScenarioAction::ChangePolicy { approvals, .. }
        | IdentityScenarioAction::AuthorizeDevice { approvals, .. }
        | IdentityScenarioAction::RevokeDevice { approvals, .. }
        | IdentityScenarioAction::RevokeController { approvals, .. }
        | IdentityScenarioAction::ForkProposal { approvals, .. }
        | IdentityScenarioAction::ResolveFork { approvals, .. }
        | IdentityScenarioAction::Migration { approvals, .. }
        | IdentityScenarioAction::RotateGroupKey { approvals } => approvals,
        IdentityScenarioAction::Partition
        | IdentityScenarioAction::Heal
        | IdentityScenarioAction::DeliveryFault { .. }
        | IdentityScenarioAction::Crash { .. }
        | IdentityScenarioAction::Reopen { .. }
        | IdentityScenarioAction::ProviderOutage
        | IdentityScenarioAction::ProviderRestore
        | IdentityScenarioAction::ProviderEquivocation
        | IdentityScenarioAction::SensitiveProbe
        | IdentityScenarioAction::Recover { .. }
        | IdentityScenarioAction::PublishRevocation { .. }
        | IdentityScenarioAction::OfflineValidate
        | IdentityScenarioAction::SocialRelationship
        | IdentityScenarioAction::Section36Fault { .. } => return false,
    };
    if approvals.is_empty() {
        return false;
    }
    approvals.clear();
    true
}

fn approvals_satisfy_prior_policy(before: &AccountModelSnapshot, approvals: &[u16]) -> bool {
    let mut seen = BTreeSet::new();
    let mut weight = 0_u64;
    for approval in approvals {
        let id = ControllerId::new(*approval);
        if !seen.insert(id) {
            return false;
        }
        let Some(controller) = before
            .active_controllers
            .iter()
            .find(|controller| controller.id() == id)
        else {
            return false;
        };
        let Some(next) = weight.checked_add(u64::from(controller.weight())) else {
            return false;
        };
        weight = next;
    }
    weight >= u64::from(before.policy.required_weight())
}

fn record_task_failure(world: &Arc<Mutex<ScenarioWorld>>, error: String) {
    if let Ok(mut world) = world.lock()
        && world.failure.is_none()
    {
        world.failure = Some(IdentityFailureEvidence {
            class: IdentityFailureClass::Runtime,
            detail: error,
        });
    }
}

/// Invalid scenario input, model transition, invariant, or deterministic runtime failure.
#[derive(Debug, thiserror::Error)]
pub enum IdentityScenarioError {
    #[error("unsupported identity scenario schema {0}")]
    UnsupportedSchema(u16),
    #[error("identity scenario input has {actual} bytes; maximum is {maximum}")]
    InputTooLarge { actual: usize, maximum: usize },
    #[error("invalid identity scenario text {0:?}")]
    InvalidText(String),
    #[error("identity action count {0} is outside the bounded range")]
    InvalidActionCount(usize),
    #[error("duplicate identity action {0}")]
    DuplicateAction(String),
    #[error("identity action virtual time {0} exceeds the hard bound")]
    InvalidVirtualTime(u64),
    #[error("identity action {action:?} is invalid: {reason}")]
    InvalidAction {
        action: String,
        reason: &'static str,
    },
    #[error("identity scenario encoding failed: {0}")]
    Encoding(String),
    #[error("identity model failed: {0}")]
    Model(#[from] ModelError),
    /// A correctly declared model rejection reached the non-detailed runner API.
    #[error("identity scenario reached an expected rejection: {0}")]
    ExpectedRejection(String),
    #[error("identity scenario execution failed: {0}")]
    Execution(String),
    #[error("Section 36 invariant failed: {0}")]
    Invariant(String),
    #[error("identity scenario arithmetic overflow")]
    ArithmeticOverflow,
    #[error("identity deterministic runtime failed: {0}")]
    Runtime(String),
}
