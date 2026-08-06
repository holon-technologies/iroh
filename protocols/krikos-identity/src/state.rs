//! Pure deterministic account-state projection.

use serde::Serialize;

use crate::{
    AccountGenesis, AccountId, AccountOperation, AdmissionEvidence, AdmissionEvidenceId,
    AlgorithmPublicKey, AuthorizedEvent, BlindedMetadataCommitment, CanonicalWire, CapabilityGrant,
    ControlPolicy, ControlPolicyId, ControllerDescriptor, ControllerId, ControllerKeyId,
    CryptoMigrationBody, CryptoSuiteDescriptor, CryptoSuiteId, DeviceClass, DeviceDescriptor,
    DeviceId, Epoch, EventId, ForkCommonAncestor, FreshnessRequirement, GenesisAnchor,
    IdentityError, ProposalId, ProtocolMajor, ProtocolUpgrade, ProviderPolicy, ProviderPolicyId,
    ProviderQuorum, ProviderReceipts, RecoveryId, RecoveryPolicy, RecoveryPolicyId,
    RecoveryProposal, RetireAccount, Sequence, SigningPublicKey, Timestamp,
    limits::{
        MAX_CONTROLLERS, MAX_DEVICES, MAX_FORK_EVIDENCE_BYTES, MAX_FORK_HEADS,
        MAX_HISTORY_PAGE_BYTES, MAX_HISTORY_PAGE_EVENTS,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PendingRecoveryObservation {
    admission_evidence_id: AdmissionEvidenceId,
    provider_policy_id: ProviderPolicyId,
    required_quorum: ProviderQuorum,
    observed_at: Timestamp,
    delay_deadline: Timestamp,
    lifetime_deadline: Timestamp,
    receipts: ProviderReceipts,
}

impl PendingRecoveryObservation {
    fn from_admission(
        evidence: &AdmissionEvidence,
        recovery_policy: &RecoveryPolicy,
    ) -> Result<Self, IdentityError> {
        let delay = evidence.delay();
        let provider_policy_id = delay
            .provider_policy_id()
            .ok_or(IdentityError::FreshnessUnavailable)?;
        let required_quorum = delay
            .required_quorum()
            .ok_or(IdentityError::FreshnessUnavailable)?;
        let observed_at = delay
            .observed_at()
            .ok_or(IdentityError::FreshnessUnavailable)?;
        let receipts = delay
            .provider_receipts()
            .ok_or(IdentityError::FreshnessUnavailable)?
            .clone();
        Ok(Self {
            admission_evidence_id: evidence.admission_evidence_id()?,
            provider_policy_id,
            required_quorum,
            observed_at,
            delay_deadline: observed_at.checked_add(recovery_policy.delay())?,
            lifetime_deadline: observed_at.checked_add(recovery_policy.lifetime())?,
            receipts,
        })
    }

    fn matches_completion_anchor(&self, anchor: &crate::RecoveryDelayAnchor) -> bool {
        self.provider_policy_id == anchor.provider_policy_id()
            && self.required_quorum == anchor.required_quorum()
            && self.observed_at == anchor.observed_at()
            && receipt_entries_match(&self.receipts, anchor.receipts())
    }
}

fn receipt_entries_match(begin: &ProviderReceipts, completion: &ProviderReceipts) -> bool {
    begin.as_slice().len() == completion.as_slice().len()
        && begin
            .as_slice()
            .iter()
            .zip(completion.as_slice())
            .all(|(begin, completion)| {
                begin.provider_id() == completion.provider_id()
                    && begin.entry() == completion.entry()
                    && begin.leaf_index() == completion.leaf_index()
            })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerificationKey {
    pub(crate) crypto_suite_id: CryptoSuiteId,
    pub(crate) controller_key_id: ControllerKeyId,
    pub(crate) algorithm_code: u16,
    pub(crate) public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PendingRecovery {
    recovery_id: RecoveryId,
    proposal: RecoveryProposal,
    pre_recovery_control_policy_id: ControlPolicyId,
    begin_event_id: EventId,
    begin_proposal_id: ProposalId,
    begin_observation: PendingRecoveryObservation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct MigrationKey {
    controller_id: ControllerId,
    key: AlgorithmPublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RetiredCryptoSuite {
    suite_id: CryptoSuiteId,
    retired_at: Epoch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct StableCrypto {
    suite: CryptoSuiteDescriptor,
    migrated_keys: Vec<MigrationKey>,
    retired_suites: Vec<RetiredCryptoSuite>,
    key_tombstones: Vec<AlgorithmPublicKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
enum CryptoProjection {
    Stable(StableCrypto),
    Candidate {
        previous: StableCrypto,
        migration: CryptoMigrationBody,
        begin_event_id: EventId,
    },
    Dual {
        previous: StableCrypto,
        migration: CryptoMigrationBody,
        begin_event_id: EventId,
        activation_event_id: EventId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
enum RetirementProjection {
    Account(RetireAccount),
    CryptoMigration {
        migration_id: crate::CryptoMigrationId,
        successor_account_id: AccountId,
        retired_at: Epoch,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LineageEntry {
    pre_state: Box<AccountState>,
    authority_state: Option<Box<AccountState>>,
    expected_epoch: Epoch,
    event: AuthorizedEvent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForkBranch {
    transitions: Vec<LineageEntry>,
    projected_state: AccountState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForkProjection {
    common_state: Box<AccountState>,
    common_ancestor: ForkCommonAncestor,
    conflict_sequence: Sequence,
    conflict_predecessors: crate::EventPredecessors,
    branches: Vec<ForkBranch>,
}

/// Projection lifecycle, including the unresolved-fork state that cannot be checkpointed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionLifecycle {
    /// Ordinary active account authority.
    Active,
    /// One authoritative recovery is pending.
    RecoveryPending,
    /// Multiple valid control-event branches are retained without a selected winner.
    Forked,
    /// A candidate controller-signature suite is staged.
    MigrationPending,
    /// Both old and candidate controller-signature suites are required.
    MigrationDual,
    /// A future protocol major was authorized and this v1 implementation is read-only.
    UpgradePending,
    /// Terminal account retirement.
    Retired,
}

/// Immutable controller projection entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProjectedController {
    id: ControllerId,
    descriptor: ControllerDescriptor,
}

impl ProjectedController {
    /// Stable controller identifier.
    pub const fn id(&self) -> ControllerId {
        self.id
    }

    /// Controller descriptor active at this projection revision.
    pub const fn descriptor(&self) -> &ControllerDescriptor {
        &self.descriptor
    }

    /// Active controller signing key.
    pub const fn signing_key(&self) -> SigningPublicKey {
        self.descriptor.signing_key()
    }
}

/// Device lifecycle retained by the projection, including permanent tombstones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ProjectedDeviceLifecycle {
    /// Device is authorized.
    Active,
    /// Device is temporarily disabled.
    Suspended,
    /// Device identifier is permanently revoked.
    Revoked,
}

/// Bounded projected device entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProjectedDevice {
    id: DeviceId,
    descriptor: DeviceDescriptor,
    device_class: DeviceClass,
    metadata_commitment: Option<BlindedMetadataCommitment>,
    capabilities: Vec<CapabilityGrant>,
    authorization_epoch: Epoch,
    lifecycle: ProjectedDeviceLifecycle,
}

impl ProjectedDevice {
    /// Stable device identifier.
    pub const fn id(&self) -> DeviceId {
        self.id
    }

    /// Current device lifecycle.
    pub const fn lifecycle(&self) -> ProjectedDeviceLifecycle {
        self.lifecycle
    }

    /// Independently keyed public device descriptor.
    pub const fn descriptor(&self) -> &DeviceDescriptor {
        &self.descriptor
    }

    /// Device authorization class.
    pub const fn device_class(&self) -> DeviceClass {
        self.device_class
    }

    /// Current blinded private-metadata commitment.
    pub const fn metadata_commitment(&self) -> Option<BlindedMetadataCommitment> {
        self.metadata_commitment
    }

    /// Current sorted capability grants.
    pub fn capabilities(&self) -> &[CapabilityGrant] {
        &self.capabilities
    }

    /// Epoch at which the current authorization became valid.
    pub const fn authorization_epoch(&self) -> Epoch {
        self.authorization_epoch
    }
}

/// Stable disposition of one projection input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyDisposition {
    /// A new linear transition was applied.
    Applied,
    /// The identical admitted event was already projected.
    Replay,
    /// Additional approvals for the same body and admission evidence were retained.
    ApprovalsMerged,
    /// A distinct valid event identity sharing the same predecessor was retained as fork evidence.
    ForkDetected,
}

/// Deterministic, idempotently keyed work requested by a successful transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionEffect {
    /// Publish the exact authorized event.
    PublishAccountEvent {
        /// Stable body-and-admission event key.
        event_id: EventId,
    },
    /// Rotate protected application group keys after an epoch-changing transition.
    RotateGroupKeys {
        /// Stable transition key.
        event_id: EventId,
        /// New account epoch for recipient selection.
        epoch: Epoch,
    },
    /// Notify local consumers of a projected account change.
    NotifyAccountChanged {
        /// Stable transition key.
        event_id: EventId,
    },
    /// Notify local consumers that multiple control branches are retained.
    NotifyForkDetected {
        /// Stable key of the newly observed branch.
        event_id: EventId,
    },
}

/// Owned compare-and-swap token covering one account and its complete sorted head set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRevision {
    account_id: AccountId,
    heads: Vec<EventId>,
}

impl AccountRevision {
    pub(crate) fn from_frozen_heads(
        account_id: AccountId,
        heads: Vec<EventId>,
    ) -> Result<Self, IdentityError> {
        if heads.len() > crate::limits::MAX_FORK_HEADS {
            return Err(IdentityError::limit(
                "account revision heads",
                heads.len(),
                crate::limits::MAX_FORK_HEADS,
            ));
        }
        for pair in heads.windows(2) {
            if pair[0] == pair[1] {
                return Err(IdentityError::DuplicateElement {
                    resource: "account revision heads",
                });
            }
            if pair[0] > pair[1] {
                return Err(IdentityError::NonCanonical);
            }
        }
        Ok(Self { account_id, heads })
    }

    /// Stable account whose revision is named.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Complete sorted head set used by atomic state-store compare-and-swap.
    pub fn heads(&self) -> &[EventId] {
        &self.heads
    }
}

/// Pure result of one successful projection attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOutcome {
    disposition: ApplyDisposition,
    event_id: EventId,
    effects: Vec<ProjectionEffect>,
}

impl ApplyOutcome {
    /// Whether the input applied, replayed, merged approvals, or opened a fork.
    pub const fn disposition(&self) -> ApplyDisposition {
        self.disposition
    }

    /// Stable ID of the supplied admitted event.
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    /// Bounded deterministic effects; executing them is outside the projection.
    pub fn effects(&self) -> &[ProjectionEffect] {
        &self.effects
    }
}

/// Deterministic, bounded projection of one account's authoritative state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountState {
    account_id: AccountId,
    genesis_anchor: GenesisAnchor,
    protocol_major: ProtocolMajor,
    sequence: Sequence,
    epoch: Epoch,
    heads: Vec<EventId>,
    active_controllers: Vec<ProjectedController>,
    revoked_controllers: Vec<ProjectedController>,
    devices: Vec<ProjectedDevice>,
    control_policy: ControlPolicy,
    control_policy_id: ControlPolicyId,
    recovery_policy: RecoveryPolicy,
    recovery_policy_id: RecoveryPolicyId,
    provider_policy: ProviderPolicy,
    provider_policy_id: ProviderPolicyId,
    pending_recovery: Option<PendingRecovery>,
    crypto: CryptoProjection,
    upgrade: Option<ProtocolUpgrade>,
    retirement: Option<RetirementProjection>,
    lifecycle: ProjectionLifecycle,
    lineage: Vec<LineageEntry>,
    lineage_bytes: usize,
    historical_state_required_through: Option<Sequence>,
    fork: Option<ForkProjection>,
}

#[derive(Serialize)]
struct CanonicalProjectionView<'a> {
    account_id: AccountId,
    genesis_anchor: GenesisAnchor,
    protocol_major: ProtocolMajor,
    sequence: Sequence,
    epoch: Epoch,
    heads: &'a [EventId],
    active_controllers: &'a [ProjectedController],
    revoked_controllers: &'a [ProjectedController],
    devices: &'a [ProjectedDevice],
    control_policy: &'a ControlPolicy,
    control_policy_id: ControlPolicyId,
    recovery_policy: &'a RecoveryPolicy,
    recovery_policy_id: RecoveryPolicyId,
    provider_policy: &'a ProviderPolicy,
    provider_policy_id: ProviderPolicyId,
    pending_recovery: &'a Option<PendingRecovery>,
    crypto: &'a CryptoProjection,
    upgrade: &'a Option<ProtocolUpgrade>,
    retirement: &'a Option<RetirementProjection>,
    lifecycle_code: u16,
}

#[derive(Serialize)]
struct StableCryptoStateMaterial<'a> {
    current_suite_id: CryptoSuiteId,
    migrated_keys: &'a [MigrationKey],
    retired_suites: &'a [RetiredCryptoSuite],
    key_tombstones: &'a [AlgorithmPublicKey],
}

#[derive(Serialize)]
enum CryptoStateMaterial<'a> {
    Stable(StableCryptoStateMaterial<'a>),
    Candidate {
        previous: StableCryptoStateMaterial<'a>,
        migration_id: crate::CryptoMigrationId,
        candidate_suite_id: CryptoSuiteId,
        begin_event_id: EventId,
    },
    Dual {
        previous: StableCryptoStateMaterial<'a>,
        migration_id: crate::CryptoMigrationId,
        candidate_suite_id: CryptoSuiteId,
        begin_event_id: EventId,
        activation_event_id: EventId,
    },
}

#[derive(Serialize)]
struct CheckpointStateMaterial<'a> {
    account_id: AccountId,
    genesis_anchor: GenesisAnchor,
    protocol_major: ProtocolMajor,
    sequence: Sequence,
    epoch: Epoch,
    heads: &'a [EventId],
    control_policy_id: ControlPolicyId,
    recovery_policy_id: RecoveryPolicyId,
    provider_policy_id: ProviderPolicyId,
    pending_recovery: &'a Option<PendingRecovery>,
    crypto_state_id: crate::CryptoStateId,
    lifecycle_code: u16,
    upgrade: &'a Option<ProtocolUpgrade>,
    retirement: &'a Option<RetirementProjection>,
}

impl AccountState {
    /// Project the canonical genesis object without clocks, storage, or I/O.
    pub fn from_genesis(genesis: &AccountGenesis) -> Result<Self, IdentityError> {
        let active_controllers = genesis
            .initial_controllers()
            .iter()
            .map(|descriptor| {
                Ok(ProjectedController {
                    id: descriptor.id()?,
                    descriptor: descriptor.clone(),
                })
            })
            .collect::<Result<Vec<_>, IdentityError>>()?;
        Ok(Self {
            account_id: genesis.account_id()?,
            genesis_anchor: genesis.genesis_anchor()?,
            protocol_major: ProtocolMajor::new(1)?,
            sequence: Sequence::GENESIS,
            epoch: Epoch::GENESIS,
            heads: Vec::new(),
            active_controllers,
            revoked_controllers: Vec::new(),
            devices: Vec::new(),
            control_policy: genesis.initial_policy().clone(),
            control_policy_id: genesis.initial_policy().id()?,
            recovery_policy: genesis.initial_recovery_policy().clone(),
            recovery_policy_id: genesis.initial_recovery_policy().id()?,
            provider_policy: genesis.initial_provider_policy().clone(),
            provider_policy_id: genesis.initial_provider_policy().id()?,
            pending_recovery: None,
            crypto: CryptoProjection::Stable(StableCrypto {
                suite: CryptoSuiteDescriptor::v1()?,
                migrated_keys: Vec::new(),
                retired_suites: Vec::new(),
                key_tombstones: Vec::new(),
            }),
            upgrade: None,
            retirement: None,
            lifecycle: ProjectionLifecycle::Active,
            lineage: Vec::new(),
            lineage_bytes: 0,
            historical_state_required_through: None,
            fork: None,
        })
    }

    /// Validate and atomically apply one authorized event.
    pub fn validate_and_apply(
        &mut self,
        event: &AuthorizedEvent,
    ) -> Result<ApplyOutcome, IdentityError> {
        let mut staged = self.clone();
        let outcome = staged.validate_and_apply_inner(event)?;
        *self = staged;
        Ok(outcome)
    }

    /// Apply a possible conflict whose pre-state was evicted from the bounded memory cache.
    ///
    /// `accepted_event` and `historical_pre_state` must come from the account's authenticated
    /// durable lineage. This method revalidates both the accepted and incoming bodies from that
    /// exact pre-state before opening a fork; storage integration remains responsible for proving
    /// that the accepted event belongs to the durable lineage selected by this projection.
    pub(crate) fn validate_and_apply_historical_conflict(
        &mut self,
        historical_pre_state: &AccountState,
        accepted_path: &[AuthorizedEvent],
        incoming_event: &AuthorizedEvent,
    ) -> Result<ApplyOutcome, IdentityError> {
        let accepted_event = accepted_path
            .first()
            .ok_or(IdentityError::StorageCorruption)?;
        let sequence = incoming_event.body().sequence();
        if self
            .historical_state_required_through
            .is_none_or(|through| sequence > through)
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "historical conflict cache boundary",
            });
        }
        if historical_pre_state.account_id() != self.account_id
            || historical_pre_state.genesis_anchor() != self.genesis_anchor
        {
            return Err(IdentityError::AccountMismatch);
        }
        if accepted_event.body().sequence() != sequence
            || accepted_event.body().predecessors() != incoming_event.body().predecessors()
            || accepted_event.event_id()? == incoming_event.event_id()?
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "historical conflict event pair",
            });
        }
        let accepted_expected_epoch =
            expected_epoch(historical_pre_state, accepted_event.body().operation())?;
        crate::verifier::validate_event(
            historical_pre_state,
            historical_pre_state,
            accepted_event,
            accepted_expected_epoch,
        )?;
        let incoming_epoch =
            expected_epoch(historical_pre_state, incoming_event.body().operation())?;
        crate::verifier::validate_event(
            historical_pre_state,
            historical_pre_state,
            incoming_event,
            incoming_epoch,
        )?;

        let mut accepted_projection = historical_pre_state.detached_snapshot();
        let mut accepted_transitions = Vec::new();
        let mut accepted_path_bytes = 0_usize;
        for accepted in accepted_path {
            let pre_state = accepted_projection.detached_snapshot();
            let accepted_epoch = expected_epoch(&pre_state, accepted.body().operation())?;
            crate::verifier::validate_event(&pre_state, &pre_state, accepted, accepted_epoch)?;
            accepted_projection.apply_new_linear(accepted, accepted.event_id()?)?;
            let transition = LineageEntry {
                pre_state: Box::new(pre_state),
                authority_state: None,
                expected_epoch: accepted_epoch,
                event: accepted.clone(),
            };
            checked_evidence_add(
                &mut accepted_path_bytes,
                lineage_entry_evidence_bytes(&transition)?,
            )?;
            if accepted_path_bytes > MAX_FORK_EVIDENCE_BYTES {
                return Err(IdentityError::limit(
                    "account fork evidence bytes",
                    accepted_path_bytes,
                    MAX_FORK_EVIDENCE_BYTES,
                ));
            }
            accepted_transitions.push(transition);
        }
        let mut authenticated_tip = accepted_projection.detached_snapshot();
        authenticated_tip.historical_state_required_through = None;
        let mut current_tip = self.detached_snapshot();
        current_tip.historical_state_required_through = None;
        if authenticated_tip != current_tip {
            return Err(IdentityError::StorageCorruption);
        }

        let mut staged = self.clone();
        let outcome = staged.open_fork(
            incoming_event,
            incoming_event.event_id()?,
            LineageEntry {
                pre_state: Box::new(historical_pre_state.detached_snapshot()),
                authority_state: None,
                expected_epoch: accepted_expected_epoch,
                event: accepted_event.clone(),
            },
            Some(accepted_transitions),
        )?;
        *self = staged;
        Ok(outcome)
    }

    /// Stable account identifier.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Genesis predecessor anchor.
    pub const fn genesis_anchor(&self) -> GenesisAnchor {
        self.genesis_anchor
    }

    /// Projected account-event sequence.
    pub const fn sequence(&self) -> Sequence {
        self.sequence
    }

    /// Projected security epoch.
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Complete sorted current head set.
    pub fn heads(&self) -> &[EventId] {
        &self.heads
    }

    /// Canonically sorted active controllers.
    pub fn active_controllers(&self) -> &[ProjectedController] {
        &self.active_controllers
    }

    /// Canonically sorted permanently revoked controller tombstones.
    pub fn revoked_controllers(&self) -> &[ProjectedController] {
        &self.revoked_controllers
    }

    /// Canonically sorted device entries, including tombstones.
    pub fn devices(&self) -> &[ProjectedDevice] {
        &self.devices
    }

    /// Current control policy.
    pub const fn control_policy(&self) -> &ControlPolicy {
        &self.control_policy
    }

    /// Current canonical control-policy ID.
    pub const fn control_policy_id(&self) -> ControlPolicyId {
        self.control_policy_id
    }

    /// Current recovery policy.
    pub const fn recovery_policy(&self) -> &RecoveryPolicy {
        &self.recovery_policy
    }

    /// Current canonical recovery-policy ID.
    pub const fn recovery_policy_id(&self) -> RecoveryPolicyId {
        self.recovery_policy_id
    }

    /// Current provider policy.
    pub const fn provider_policy(&self) -> &ProviderPolicy {
        &self.provider_policy
    }

    /// Current canonical provider-policy ID.
    pub const fn provider_policy_id(&self) -> ProviderPolicyId {
        self.provider_policy_id
    }

    /// Current projection lifecycle.
    pub const fn lifecycle(&self) -> ProjectionLifecycle {
        self.lifecycle
    }

    /// Return an owned deterministic revision token for atomic store compare-and-swap.
    pub fn revision_token(&self) -> AccountRevision {
        AccountRevision {
            account_id: self.account_id,
            heads: self.heads.clone(),
        }
    }

    /// Domain-separated commitment to the complete projected cryptographic state.
    pub(crate) fn crypto_state_id(&self) -> Result<crate::CryptoStateId, IdentityError> {
        let material = match &self.crypto {
            CryptoProjection::Stable(stable) => {
                CryptoStateMaterial::Stable(stable_crypto_state_material(stable)?)
            }
            CryptoProjection::Candidate {
                previous,
                migration,
                begin_event_id,
            } => CryptoStateMaterial::Candidate {
                previous: stable_crypto_state_material(previous)?,
                migration_id: migration.crypto_migration_id()?,
                candidate_suite_id: migration.to_suite().crypto_suite_id()?,
                begin_event_id: *begin_event_id,
            },
            CryptoProjection::Dual {
                previous,
                migration,
                begin_event_id,
                activation_event_id,
            } => CryptoStateMaterial::Dual {
                previous: stable_crypto_state_material(previous)?,
                migration_id: migration.crypto_migration_id()?,
                candidate_suite_id: migration.to_suite().crypto_suite_id()?,
                begin_event_id: *begin_event_id,
                activation_event_id: *activation_event_id,
            },
        };
        let bytes = crate::codec::encode_wire(&material)?;
        Ok(crate::CryptoStateId::from_digest(crate::types::hash_bytes(
            crate::types::HashDomain::CryptoState,
            &bytes,
        )))
    }

    /// Canonical cache-free material committed by checkpoint state leaves.
    pub(crate) fn checkpoint_state_material(&self) -> Result<Vec<u8>, IdentityError> {
        if self.fork.is_some() || self.lifecycle == ProjectionLifecycle::Forked {
            return Err(IdentityError::AccountForked);
        }
        crate::codec::encode_wire(&CheckpointStateMaterial {
            account_id: self.account_id,
            genesis_anchor: self.genesis_anchor,
            protocol_major: self.protocol_major,
            sequence: self.sequence,
            epoch: self.epoch,
            heads: &self.heads,
            control_policy_id: self.control_policy_id,
            recovery_policy_id: self.recovery_policy_id,
            provider_policy_id: self.provider_policy_id,
            pending_recovery: &self.pending_recovery,
            crypto_state_id: self.crypto_state_id()?,
            lifecycle_code: projection_lifecycle_code(self.lifecycle),
            upgrade: &self.upgrade,
            retirement: &self.retirement,
        })
    }

    /// Frozen v1 epoch rule by operation kind; `None` means code 20 depends on its mode.
    pub const fn operation_kind_advances_epoch(kind: crate::OperationKind) -> Option<bool> {
        match kind {
            crate::OperationKind::UpdateDeviceMetadata
            | crate::OperationKind::BeginCryptoMigration => Some(false),
            crate::OperationKind::RetireCryptoSuite => None,
            crate::OperationKind::AuthorizeDevice
            | crate::OperationKind::UpdateDeviceAuthorization
            | crate::OperationKind::SuspendDevice
            | crate::OperationKind::ReinstateDevice
            | crate::OperationKind::RevokeDevice
            | crate::OperationKind::RotateDeviceKeys
            | crate::OperationKind::AddController
            | crate::OperationKind::RemoveController
            | crate::OperationKind::ChangeControlPolicy
            | crate::OperationKind::ChangeRecoveryPolicy
            | crate::OperationKind::ChangeProviderPolicy
            | crate::OperationKind::BeginRecovery
            | crate::OperationKind::VetoRecovery
            | crate::OperationKind::CancelRecovery
            | crate::OperationKind::FinalizeRecovery
            | crate::OperationKind::ResolveFork
            | crate::OperationKind::ActivateCryptoMigration
            | crate::OperationKind::UpgradeProtocol
            | crate::OperationKind::RetireAccount => Some(true),
        }
    }

    /// Exact resulting epoch required for an operation in this pre-state.
    pub fn expected_epoch_for(&self, operation: &AccountOperation) -> Result<Epoch, IdentityError> {
        expected_epoch(self, operation)
    }

    fn validate_and_apply_inner(
        &mut self,
        event: &AuthorizedEvent,
    ) -> Result<ApplyOutcome, IdentityError> {
        let event_id = event.event_id()?;
        if let Some(outcome) = self.try_replay(event, event_id)? {
            return Ok(outcome);
        }
        if self.fork.is_some() {
            return self.apply_while_forked(event, event_id);
        }
        if let Some(conflict) = self.find_lineage_conflict(event, event_id)? {
            return self.open_fork(event, event_id, conflict, None);
        }
        if event.body().account_id() == self.account_id
            && self
                .historical_state_required_through
                .is_some_and(|through| event.body().sequence() <= through)
        {
            return Err(IdentityError::HistoricalStateRequired {
                sequence: event.body().sequence().get(),
            });
        }
        self.apply_new_linear(event, event_id)
    }

    fn try_replay(
        &mut self,
        event: &AuthorizedEvent,
        event_id: EventId,
    ) -> Result<Option<ApplyOutcome>, IdentityError> {
        if let Some(index) = self
            .lineage
            .iter()
            .position(|entry| entry.event.event_id() == Ok(event_id))
        {
            let changed = {
                let entry = &mut self.lineage[index];
                crate::verifier::validate_event(
                    &entry.pre_state,
                    entry.authority_state.as_deref().unwrap_or(&entry.pre_state),
                    event,
                    entry.expected_epoch,
                )?;
                let merged = merge_event_evidence(&entry.event, event)?;
                if merged != entry.event {
                    entry.event = merged;
                    true
                } else {
                    false
                }
            };
            let disposition = if changed {
                self.normalize_lineage_bound()?;
                ApplyDisposition::ApprovalsMerged
            } else {
                ApplyDisposition::Replay
            };
            return Ok(Some(ApplyOutcome {
                disposition,
                event_id,
                effects: Vec::new(),
            }));
        }

        let fork_transitions = self.fork.as_ref().map_or_else(Vec::new, |fork| {
            fork.branches
                .iter()
                .enumerate()
                .flat_map(|(branch_index, branch)| {
                    branch.transitions.iter().enumerate().filter_map(
                        move |(transition_index, transition)| {
                            (transition.event.event_id() == Ok(event_id))
                                .then_some((branch_index, transition_index))
                        },
                    )
                })
                .collect::<Vec<_>>()
        });
        if !fork_transitions.is_empty() {
            let fork = self.fork.as_ref().ok_or(IdentityError::StorageCorruption)?;
            let mut merged = event.clone();
            for (branch_index, transition_index) in &fork_transitions {
                let transition = &fork.branches[*branch_index].transitions[*transition_index];
                crate::verifier::validate_event(
                    &transition.pre_state,
                    transition
                        .authority_state
                        .as_deref()
                        .unwrap_or(&transition.pre_state),
                    event,
                    transition.expected_epoch,
                )?;
                merged = merge_event_evidence(&transition.event, &merged)?;
            }
            let fork = self.fork.as_mut().ok_or(IdentityError::StorageCorruption)?;
            let changed = fork_transitions
                .iter()
                .any(|(branch_index, transition_index)| {
                    fork.branches[*branch_index].transitions[*transition_index].event != merged
                });
            let disposition = if changed {
                for (branch_index, transition_index) in fork_transitions {
                    fork.branches[branch_index].transitions[transition_index].event =
                        merged.clone();
                }
                validate_fork_evidence_bound(&fork.common_state, &fork.branches)?;
                ApplyDisposition::ApprovalsMerged
            } else {
                ApplyDisposition::Replay
            };
            return Ok(Some(ApplyOutcome {
                disposition,
                event_id,
                effects: Vec::new(),
            }));
        }
        Ok(None)
    }

    fn find_lineage_conflict(
        &self,
        event: &AuthorizedEvent,
        event_id: EventId,
    ) -> Result<Option<LineageEntry>, IdentityError> {
        for entry in self.lineage.iter().rev() {
            if entry.event.event_id()? != event_id
                && entry.event.body().account_id() == event.body().account_id()
                && entry.event.body().sequence() == event.body().sequence()
                && entry.event.body().predecessors() == event.body().predecessors()
            {
                return Ok(Some(entry.clone()));
            }
        }
        Ok(None)
    }

    fn apply_new_linear(
        &mut self,
        event: &AuthorizedEvent,
        event_id: EventId,
    ) -> Result<ApplyOutcome, IdentityError> {
        self.validate_lifecycle_gate(event.body().operation())?;
        let expected_epoch = expected_epoch(self, event.body().operation())?;
        let validated = crate::verifier::validate_event(self, self, event, expected_epoch)?;

        let pre_state = self.detached_snapshot();
        self.apply_operation(event, event_id, validated.provider_authority_time())?;
        self.sequence = event.body().sequence();
        self.epoch = event.body().resulting_epoch();
        self.heads.clear();
        self.heads.push(event_id);
        self.retain_lineage_entry(LineageEntry {
            pre_state: Box::new(pre_state.clone()),
            authority_state: None,
            expected_epoch,
            event: event.clone(),
        })?;
        self.fork = None;

        Ok(ApplyOutcome {
            disposition: ApplyDisposition::Applied,
            event_id,
            effects: transition_effects(
                event_id,
                self.epoch,
                operation_changes_epoch(event.body().operation()),
            ),
        })
    }

    fn open_fork(
        &mut self,
        event: &AuthorizedEvent,
        event_id: EventId,
        conflict: LineageEntry,
        authenticated_left_path: Option<Vec<LineageEntry>>,
    ) -> Result<ApplyOutcome, IdentityError> {
        if conflict.pre_state.fork.is_some()
            && matches!(event.body().operation(), AccountOperation::ResolveFork(_))
        {
            return self.open_resolution_fork(event, event_id, &conflict);
        }
        let common_state = conflict.pre_state.detached_snapshot();
        let expected_epoch = expected_epoch(&common_state, event.body().operation())?;
        crate::verifier::validate_event(&common_state, &common_state, event, expected_epoch)?;

        let left_state = self.detached_snapshot();
        let conflict_id = conflict.event.event_id()?;
        let left_start = self
            .lineage
            .iter()
            .position(|transition| transition.event.event_id() == Ok(conflict_id));
        let left_transitions = match authenticated_left_path {
            Some(path) => path,
            None => {
                let index = left_start.ok_or(IdentityError::HistoricalStateRequired {
                    sequence: conflict.event.body().sequence().get(),
                })?;
                self.lineage[index..].to_vec()
            }
        };
        let mut right_state = common_state.detached_snapshot();
        right_state.apply_new_linear(event, event_id)?;
        let right_transition = right_state
            .lineage
            .last()
            .ok_or(IdentityError::StorageCorruption)?;
        let right_state = right_state.detached_snapshot();
        let mut branches = vec![
            ForkBranch {
                transitions: left_transitions,
                projected_state: left_state,
            },
            ForkBranch {
                transitions: vec![LineageEntry {
                    pre_state: right_transition.pre_state.clone(),
                    authority_state: right_transition.authority_state.clone(),
                    expected_epoch: right_transition.expected_epoch,
                    event: right_transition.event.clone(),
                }],
                projected_state: right_state,
            },
        ];
        sort_fork_branches(&mut branches)?;
        validate_fork_evidence_bound(&common_state, &branches)?;

        *self = common_state.detached_snapshot();
        self.sequence = branches
            .iter()
            .map(|branch| branch.projected_state.sequence())
            .max()
            .ok_or(IdentityError::StorageCorruption)?;
        self.heads = fork_head_ids(&branches)?;
        self.lifecycle = ProjectionLifecycle::Forked;
        let common_ancestor = if common_state.sequence() == Sequence::GENESIS {
            ForkCommonAncestor::Genesis(common_state.genesis_anchor())
        } else {
            let [ancestor] = common_state.heads() else {
                return Err(IdentityError::StorageCorruption);
            };
            ForkCommonAncestor::Event(*ancestor)
        };
        self.fork = Some(ForkProjection {
            common_state: Box::new(common_state),
            common_ancestor,
            conflict_sequence: event.body().sequence(),
            conflict_predecessors: event.body().predecessors().clone(),
            branches,
        });

        Ok(ApplyOutcome {
            disposition: ApplyDisposition::ForkDetected,
            event_id,
            effects: vec![
                ProjectionEffect::PublishAccountEvent { event_id },
                ProjectionEffect::NotifyForkDetected { event_id },
            ],
        })
    }

    fn open_resolution_fork(
        &mut self,
        event: &AuthorizedEvent,
        event_id: EventId,
        conflict: &LineageEntry,
    ) -> Result<ApplyOutcome, IdentityError> {
        let unresolved_pre_state = conflict.pre_state.as_ref();
        let original_fork = unresolved_pre_state
            .fork
            .as_ref()
            .ok_or(IdentityError::StorageCorruption)?;
        let common_state = original_fork.common_state.detached_snapshot();
        let left_state = self.detached_snapshot();
        let conflict_id = conflict.event.event_id()?;
        let left_start = self
            .lineage
            .iter()
            .position(|transition| transition.event.event_id() == Ok(conflict_id))
            .ok_or(IdentityError::StorageCorruption)?;
        let left_transitions = self.lineage[left_start..].to_vec();
        let mut right_state = unresolved_pre_state.clone();
        right_state.apply_fork_resolution(event, event_id)?;
        let right_transition = right_state
            .lineage
            .last()
            .ok_or(IdentityError::StorageCorruption)?;
        let right_state = right_state.detached_snapshot();
        let mut branches = vec![
            ForkBranch {
                transitions: left_transitions,
                projected_state: left_state,
            },
            ForkBranch {
                transitions: vec![LineageEntry {
                    pre_state: right_transition.pre_state.clone(),
                    authority_state: right_transition.authority_state.clone(),
                    expected_epoch: right_transition.expected_epoch,
                    event: right_transition.event.clone(),
                }],
                projected_state: right_state,
            },
        ];
        sort_fork_branches(&mut branches)?;
        validate_fork_evidence_bound(&common_state, &branches)?;

        *self = common_state.detached_snapshot();
        self.sequence = branches
            .iter()
            .map(|branch| branch.projected_state.sequence())
            .max()
            .ok_or(IdentityError::StorageCorruption)?;
        self.heads = fork_head_ids(&branches)?;
        self.lifecycle = ProjectionLifecycle::Forked;
        self.fork = Some(ForkProjection {
            common_state: Box::new(common_state),
            common_ancestor: original_fork.common_ancestor,
            conflict_sequence: event.body().sequence(),
            conflict_predecessors: event.body().predecessors().clone(),
            branches,
        });
        Ok(ApplyOutcome {
            disposition: ApplyDisposition::ForkDetected,
            event_id,
            effects: vec![
                ProjectionEffect::PublishAccountEvent { event_id },
                ProjectionEffect::NotifyForkDetected { event_id },
            ],
        })
    }

    fn apply_while_forked(
        &mut self,
        event: &AuthorizedEvent,
        event_id: EventId,
    ) -> Result<ApplyOutcome, IdentityError> {
        if matches!(event.body().operation(), AccountOperation::ResolveFork(_))
            && event.body().predecessors().event_heads() == Some(self.heads())
        {
            return self.apply_fork_resolution(event, event_id);
        }

        let mut fork = self
            .fork
            .as_ref()
            .ok_or(IdentityError::StorageCorruption)?
            .clone();
        if fork.branches.len() < 2 {
            return Err(IdentityError::StorageCorruption);
        }

        let parent_index = fork.branches.iter().position(|branch| {
            branch.projected_state.sequence().checked_next().ok() == Some(event.body().sequence())
                && event.body().predecessors().event_heads() == Some(branch.projected_state.heads())
        });
        if let Some(parent_index) = parent_index {
            let (transition, projected_state) = project_transition(
                &fork.branches[parent_index].projected_state,
                event,
                event_id,
            )?;
            fork.branches[parent_index].transitions.push(transition);
            fork.branches[parent_index].projected_state = projected_state;
        } else {
            let conflict = fork
                .branches
                .iter()
                .enumerate()
                .find_map(|(branch_index, branch)| {
                    branch
                        .transitions
                        .iter()
                        .enumerate()
                        .find(|(_, transition)| {
                            transition.event.body().sequence() == event.body().sequence()
                                && transition.event.body().predecessors()
                                    == event.body().predecessors()
                        })
                        .map(|(transition_index, transition)| {
                            (branch_index, transition_index, transition.clone())
                        })
                })
                .ok_or(IdentityError::AccountForked)?;
            if fork.branches.len() >= MAX_FORK_HEADS {
                return Err(IdentityError::limit(
                    "account fork heads",
                    fork.branches.len().saturating_add(1),
                    MAX_FORK_HEADS,
                ));
            }
            let (branch_index, transition_index, conflicting_transition) = conflict;
            let (incoming_transition, projected_state) =
                project_transition(&conflicting_transition.pre_state, event, event_id)?;
            let mut transitions =
                fork.branches[branch_index].transitions[..transition_index].to_vec();
            transitions.push(incoming_transition);
            fork.branches.push(ForkBranch {
                transitions,
                projected_state,
            });
        }
        sort_fork_branches(&mut fork.branches)?;
        validate_fork_evidence_bound(&fork.common_state, &fork.branches)?;
        self.sequence = fork
            .branches
            .iter()
            .map(|branch| branch.projected_state.sequence())
            .max()
            .ok_or(IdentityError::StorageCorruption)?;
        self.heads = fork_head_ids(&fork.branches)?;
        self.fork = Some(fork);
        Ok(ApplyOutcome {
            disposition: ApplyDisposition::ForkDetected,
            event_id,
            effects: vec![
                ProjectionEffect::PublishAccountEvent { event_id },
                ProjectionEffect::NotifyForkDetected { event_id },
            ],
        })
    }

    fn detached_snapshot(&self) -> Self {
        let mut snapshot = self.clone();
        snapshot.lineage.clear();
        snapshot.lineage_bytes = 0;
        snapshot.fork = None;
        snapshot
    }

    fn retain_lineage_entry(&mut self, entry: LineageEntry) -> Result<(), IdentityError> {
        let entry_bytes = lineage_entry_evidence_bytes(&entry)?;
        while !self.lineage.is_empty()
            && (self.lineage.len() >= MAX_HISTORY_PAGE_EVENTS
                || self.lineage_bytes.checked_add(entry_bytes).ok_or(
                    IdentityError::ArithmeticOverflow {
                        resource: "account lineage bytes",
                    },
                )? > MAX_HISTORY_PAGE_BYTES)
        {
            let removed = self.lineage.remove(0);
            let removed_bytes = lineage_entry_evidence_bytes(&removed)?;
            self.lineage_bytes = self
                .lineage_bytes
                .checked_sub(removed_bytes)
                .ok_or(IdentityError::StorageCorruption)?;
            self.historical_state_required_through = Some(removed.event.body().sequence());
        }
        if entry_bytes > MAX_HISTORY_PAGE_BYTES {
            self.historical_state_required_through = Some(entry.event.body().sequence());
            return Ok(());
        }
        self.lineage_bytes = self.lineage_bytes.checked_add(entry_bytes).ok_or(
            IdentityError::ArithmeticOverflow {
                resource: "account lineage bytes",
            },
        )?;
        self.lineage.push(entry);
        Ok(())
    }

    fn normalize_lineage_bound(&mut self) -> Result<(), IdentityError> {
        self.lineage_bytes = 0;
        let entries = std::mem::take(&mut self.lineage);
        for entry in entries {
            self.retain_lineage_entry(entry)?;
        }
        Ok(())
    }

    fn validate_lifecycle_gate(&self, operation: &AccountOperation) -> Result<(), IdentityError> {
        match self.lifecycle {
            ProjectionLifecycle::Active => Ok(()),
            ProjectionLifecycle::RecoveryPending
                if matches!(
                    operation,
                    AccountOperation::VetoRecovery(_)
                        | AccountOperation::CancelRecovery(_)
                        | AccountOperation::FinalizeRecovery(_)
                ) =>
            {
                Ok(())
            }
            ProjectionLifecycle::RecoveryPending => Err(IdentityError::RecoveryPending),
            ProjectionLifecycle::MigrationPending
                if matches!(
                    operation,
                    AccountOperation::ActivateCryptoMigration(_)
                        | AccountOperation::RetireCryptoSuite(_)
                ) =>
            {
                Ok(())
            }
            ProjectionLifecycle::MigrationDual
                if matches!(operation, AccountOperation::RetireCryptoSuite(_)) =>
            {
                Ok(())
            }
            ProjectionLifecycle::MigrationPending | ProjectionLifecycle::MigrationDual => {
                Err(IdentityError::InvalidRelationship {
                    resource: "cryptographic migration phase operation",
                })
            }
            ProjectionLifecycle::UpgradePending => Err(IdentityError::UnsupportedVersion {
                version: self.protocol_major.get(),
            }),
            ProjectionLifecycle::Retired => Err(IdentityError::AccountRetired),
            ProjectionLifecycle::Forked => Err(IdentityError::AccountForked),
        }
    }

    fn apply_operation(
        &mut self,
        event: &AuthorizedEvent,
        event_id: EventId,
        provider_authority_time: Option<Timestamp>,
    ) -> Result<(), IdentityError> {
        match event.body().operation() {
            AccountOperation::AuthorizeDevice(authorization) => {
                self.authorize_device(authorization, event.body().resulting_epoch())
            }
            AccountOperation::UpdateDeviceAuthorization(update) => {
                self.update_device_authorization(update, event.body().resulting_epoch())
            }
            AccountOperation::UpdateDeviceMetadata(update) => {
                let device = self.device_mut(update.device_id())?;
                device.metadata_commitment = update.metadata_commitment();
                Ok(())
            }
            AccountOperation::SuspendDevice(suspend) => {
                let device = self.device_mut(suspend.device_id())?;
                match device.lifecycle {
                    ProjectedDeviceLifecycle::Active => {
                        device.lifecycle = ProjectedDeviceLifecycle::Suspended;
                        Ok(())
                    }
                    ProjectedDeviceLifecycle::Suspended => Err(IdentityError::DeviceSuspended),
                    ProjectedDeviceLifecycle::Revoked => Err(IdentityError::DeviceRevoked),
                }
            }
            AccountOperation::ReinstateDevice(reinstate) => {
                let device = self.device_mut(reinstate.device_id())?;
                match device.lifecycle {
                    ProjectedDeviceLifecycle::Suspended => {
                        device.lifecycle = ProjectedDeviceLifecycle::Active;
                        Ok(())
                    }
                    ProjectedDeviceLifecycle::Active => Err(IdentityError::InvalidRelationship {
                        resource: "reinstate active device",
                    }),
                    ProjectedDeviceLifecycle::Revoked => Err(IdentityError::DeviceRevoked),
                }
            }
            AccountOperation::RevokeDevice(revoke) => {
                let device = self.device_mut(revoke.device_id())?;
                if device.lifecycle == ProjectedDeviceLifecycle::Revoked {
                    return Err(IdentityError::DeviceRevoked);
                }
                device.lifecycle = ProjectedDeviceLifecycle::Revoked;
                Ok(())
            }
            AccountOperation::RotateDeviceKeys(rotation) => {
                let old = self.device_mut(rotation.old_device_id())?;
                if old.lifecycle == ProjectedDeviceLifecycle::Revoked {
                    return Err(IdentityError::DeviceRevoked);
                }
                old.lifecycle = ProjectedDeviceLifecycle::Revoked;
                self.authorize_device(rotation.new_authorization(), event.body().resulting_epoch())
            }
            AccountOperation::AddController(descriptor) => self.add_controller(descriptor),
            AccountOperation::RemoveController(controller_id) => {
                self.remove_controller(*controller_id)
            }
            AccountOperation::ChangeControlPolicy(policy) => {
                policy.validate_satisfiable(&self.active_controller_descriptors())?;
                self.control_policy_id = policy.id()?;
                self.control_policy = policy.clone();
                Ok(())
            }
            AccountOperation::ChangeRecoveryPolicy(policy) => {
                if policy.policy_version()
                    != self.recovery_policy.policy_version().checked_next()?
                {
                    return Err(IdentityError::PolicyVersionMismatch);
                }
                policy.validate_controller_authority(&self.active_controller_descriptors())?;
                self.recovery_policy_id = policy.id()?;
                self.recovery_policy = policy.clone();
                Ok(())
            }
            AccountOperation::ChangeProviderPolicy(policy) => {
                if policy.policy_version()
                    != self.provider_policy.policy_version().checked_next()?
                {
                    return Err(IdentityError::PolicyVersionMismatch);
                }
                self.provider_policy_id = policy.id()?;
                self.provider_policy = policy.clone();
                Ok(())
            }
            AccountOperation::BeginRecovery(begin) => self.begin_recovery(
                begin,
                event.admission_evidence(),
                event_id,
                event.body().proposal_id()?,
            ),
            AccountOperation::VetoRecovery(veto) => self.veto_recovery(veto),
            AccountOperation::CancelRecovery(cancel) => self.cancel_recovery(cancel),
            AccountOperation::FinalizeRecovery(finalize) => {
                self.finalize_recovery(finalize, provider_authority_time)
            }
            AccountOperation::ResolveFork(_) => Err(IdentityError::InvalidPredecessor),
            AccountOperation::BeginCryptoMigration(begin) => {
                self.begin_crypto_migration(begin, event_id)
            }
            AccountOperation::ActivateCryptoMigration(activate) => {
                self.activate_crypto_migration(activate, event_id)
            }
            AccountOperation::RetireCryptoSuite(retire) => {
                self.retire_crypto_suite(retire, event.body().resulting_epoch())
            }
            AccountOperation::UpgradeProtocol(upgrade) => {
                if upgrade.from_major() != self.protocol_major {
                    return Err(IdentityError::UnsupportedVersion {
                        version: upgrade.from_major().get(),
                    });
                }
                self.protocol_major = upgrade.to_major();
                self.upgrade = Some(upgrade.clone());
                self.lifecycle = ProjectionLifecycle::UpgradePending;
                Ok(())
            }
            AccountOperation::RetireAccount(retire) => {
                self.retirement = Some(RetirementProjection::Account(retire.clone()));
                self.lifecycle = ProjectionLifecycle::Retired;
                Ok(())
            }
        }
    }

    fn apply_fork_resolution(
        &mut self,
        event: &AuthorizedEvent,
        event_id: EventId,
    ) -> Result<ApplyOutcome, IdentityError> {
        let AccountOperation::ResolveFork(resolution) = event.body().operation() else {
            return Err(IdentityError::AccountForked);
        };
        let fork = self
            .fork
            .as_ref()
            .ok_or(IdentityError::StorageCorruption)?
            .clone();
        if resolution.fork().account_id() != self.account_id {
            return Err(IdentityError::AccountMismatch);
        }
        if resolution.fork().heads() != self.heads
            || resolution.fork().common_ancestor() != fork.common_ancestor
        {
            return Err(IdentityError::InvalidPredecessor);
        }
        let selected = fork
            .branches
            .iter()
            .find(|branch| fork_branch_event_id(branch) == Ok(resolution.selected_head()))
            .ok_or(IdentityError::InvalidPredecessor)?;
        let maximum_branch_epoch = fork
            .branches
            .iter()
            .map(|branch| branch.projected_state.epoch())
            .max()
            .ok_or(IdentityError::StorageCorruption)?;
        let expected_epoch = maximum_branch_epoch.checked_next()?;
        crate::verifier::validate_event(self, &fork.common_state, event, expected_epoch)?;

        let mut pre_state = self.clone();
        pre_state.lineage.clear();
        pre_state.lineage_bytes = 0;
        let mut resolved = selected.projected_state.detached_snapshot();
        for controller_id in resolution.revoked_controllers() {
            resolved.revoke_controller_for_resolution(*controller_id)?;
        }
        for device_id in resolution.revoked_devices() {
            let device = resolved.device_mut(*device_id)?;
            device.lifecycle = ProjectedDeviceLifecycle::Revoked;
        }
        if resolved.active_controllers.is_empty() {
            return Err(IdentityError::UnsatisfiableThreshold);
        }
        let descriptors = resolved.active_controller_descriptors();
        resolved.control_policy.validate_satisfiable(&descriptors)?;
        resolved
            .recovery_policy
            .validate_controller_authority(&descriptors)?;
        resolved.sequence = event.body().sequence();
        resolved.epoch = event.body().resulting_epoch();
        resolved.heads = vec![event_id];
        resolved.retain_lineage_entry(LineageEntry {
            pre_state: Box::new(pre_state),
            authority_state: Some(Box::new(fork.common_state.detached_snapshot())),
            expected_epoch,
            event: event.clone(),
        })?;
        resolved.fork = None;
        *self = resolved;

        Ok(ApplyOutcome {
            disposition: ApplyDisposition::Applied,
            event_id,
            effects: transition_effects(event_id, self.epoch, true),
        })
    }

    fn revoke_controller_for_resolution(
        &mut self,
        controller_id: ControllerId,
    ) -> Result<(), IdentityError> {
        if self.revoked_controller(controller_id).is_some() {
            return Ok(());
        }
        let index = self
            .active_controllers
            .binary_search_by_key(&controller_id, ProjectedController::id)
            .map_err(|_| IdentityError::UnknownController)?;
        let controller = self.active_controllers.remove(index);
        let insert_at = match self
            .revoked_controllers
            .binary_search_by_key(&controller_id, ProjectedController::id)
        {
            Ok(_) => return Err(IdentityError::StorageCorruption),
            Err(index) => index,
        };
        self.revoked_controllers.insert(insert_at, controller);
        Ok(())
    }

    fn authorize_device(
        &mut self,
        authorization: &crate::DeviceAuthorization,
        resulting_epoch: Epoch,
    ) -> Result<(), IdentityError> {
        if authorization.authorization_epoch() != resulting_epoch {
            return Err(IdentityError::InvalidEpoch);
        }
        let device_id = authorization.device_id();
        match self
            .devices
            .binary_search_by_key(&device_id, ProjectedDevice::id)
        {
            Ok(index) if self.devices[index].lifecycle == ProjectedDeviceLifecycle::Revoked => {
                return Err(IdentityError::DeviceRevoked);
            }
            Ok(_) => {
                return Err(IdentityError::InvalidRelationship {
                    resource: "duplicate active device authorization",
                });
            }
            Err(index) => {
                self.validate_new_device_descriptor(authorization.descriptor())?;
                if self.devices.len() >= MAX_DEVICES {
                    return Err(IdentityError::limit(
                        "projected devices",
                        self.devices.len().saturating_add(1),
                        MAX_DEVICES,
                    ));
                }
                self.devices.insert(
                    index,
                    ProjectedDevice {
                        id: device_id,
                        descriptor: authorization.descriptor().clone(),
                        device_class: authorization.device_class(),
                        metadata_commitment: authorization.metadata_commitment(),
                        capabilities: authorization.capabilities().to_vec(),
                        authorization_epoch: authorization.authorization_epoch(),
                        lifecycle: ProjectedDeviceLifecycle::Active,
                    },
                );
            }
        }
        Ok(())
    }

    fn validate_new_device_descriptor(
        &self,
        descriptor: &crate::DeviceDescriptor,
    ) -> Result<(), IdentityError> {
        if self
            .devices
            .iter()
            .any(|device| device_descriptors_reuse_key(device.descriptor(), descriptor))
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "retained device public-key reuse",
            });
        }
        if self
            .active_controllers
            .iter()
            .chain(&self.revoked_controllers)
            .any(|controller| {
                device_descriptor_reuses_controller_key(descriptor, controller.signing_key())
            })
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "controller/device public-key role separation",
            });
        }
        let application_key = descriptor.application_signing_key();
        let agreement_key = descriptor.agreement_key();
        let endpoint_key = descriptor.endpoint_key().as_signing_key();
        let descriptor_keys = [
            application_key.as_bytes().as_slice(),
            agreement_key.as_bytes().as_slice(),
            endpoint_key.as_bytes().as_slice(),
        ];
        if descriptor_keys
            .iter()
            .any(|key| self.crypto_retains_key_material(key))
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "device/cryptographic key tombstone separation",
            });
        }
        Ok(())
    }

    fn update_device_authorization(
        &mut self,
        update: &crate::DeviceAuthorizationUpdate,
        resulting_epoch: Epoch,
    ) -> Result<(), IdentityError> {
        if update.authorization_epoch() != resulting_epoch {
            return Err(IdentityError::InvalidEpoch);
        }
        let device = self.device_mut(update.device_id())?;
        if device.lifecycle == ProjectedDeviceLifecycle::Revoked {
            return Err(IdentityError::DeviceRevoked);
        }
        device.device_class = update.device_class();
        device.capabilities = update.capabilities().to_vec();
        device.authorization_epoch = update.authorization_epoch();
        Ok(())
    }

    fn device_mut(&mut self, device_id: DeviceId) -> Result<&mut ProjectedDevice, IdentityError> {
        let index = self
            .devices
            .binary_search_by_key(&device_id, ProjectedDevice::id)
            .map_err(|_| IdentityError::DeviceNotAuthorized)?;
        Ok(&mut self.devices[index])
    }

    fn add_controller(&mut self, descriptor: &ControllerDescriptor) -> Result<(), IdentityError> {
        let controller_id = descriptor.id()?;
        if self.crypto_retains_key_material(descriptor.signing_key().as_bytes()) {
            return Err(IdentityError::DuplicateSigningKey);
        }
        let migrated_key = match &self.crypto {
            CryptoProjection::Stable(stable)
                if stable.suite != CryptoSuiteDescriptor::v1()?
                    || !stable.migrated_keys.is_empty() =>
            {
                let algorithm_code = stable.suite.signature_algorithm_code();
                if algorithm_code != crate::SignatureAlgorithm::Ed25519.code() {
                    return Err(IdentityError::UnsupportedPolicyFeature {
                        feature: "post-migration controller enrollment for non-Ed25519 suites",
                    });
                }
                let key = AlgorithmPublicKey::new(
                    algorithm_code,
                    descriptor.signing_key().as_bytes().to_vec(),
                )?;
                if stable.migrated_keys.iter().any(|retained| {
                    retained.key.algorithm_code() == key.algorithm_code()
                        && retained.key.as_bytes() == key.as_bytes()
                }) {
                    return Err(IdentityError::DuplicateSigningKey);
                }
                Some(key)
            }
            CryptoProjection::Stable(_) => None,
            CryptoProjection::Candidate { .. } | CryptoProjection::Dual { .. } => {
                return Err(IdentityError::InvalidRelationship {
                    resource: "controller enrollment cryptographic migration phase",
                });
            }
        };
        if self.revoked_controller(controller_id).is_some() {
            return Err(IdentityError::RevokedController);
        }
        if self.active_controller(controller_id).is_some() {
            return Err(IdentityError::InvalidRelationship {
                resource: "duplicate active controller",
            });
        }
        if self
            .active_controllers
            .iter()
            .chain(&self.revoked_controllers)
            .any(|controller| controller.signing_key() == descriptor.signing_key())
        {
            return Err(IdentityError::DuplicateSigningKey);
        }
        if self.devices.iter().any(|device| {
            device_descriptor_reuses_controller_key(device.descriptor(), descriptor.signing_key())
        }) {
            return Err(IdentityError::InvalidRelationship {
                resource: "controller/device public-key role separation",
            });
        }
        let retained_count = self
            .active_controllers
            .len()
            .checked_add(self.revoked_controllers.len())
            .and_then(|value| value.checked_add(1))
            .ok_or(IdentityError::ArithmeticOverflow {
                resource: "projected controller count",
            })?;
        if retained_count > MAX_CONTROLLERS {
            return Err(IdentityError::limit(
                "projected controllers",
                retained_count,
                MAX_CONTROLLERS,
            ));
        }
        let index = match self
            .active_controllers
            .binary_search_by_key(&controller_id, ProjectedController::id)
        {
            Ok(_) => return Err(IdentityError::StorageCorruption),
            Err(index) => index,
        };
        self.active_controllers.insert(
            index,
            ProjectedController {
                id: controller_id,
                descriptor: descriptor.clone(),
            },
        );
        if let Some(key) = migrated_key {
            let CryptoProjection::Stable(stable) = &mut self.crypto else {
                return Err(IdentityError::StorageCorruption);
            };
            let key_index = match stable
                .migrated_keys
                .binary_search_by_key(&controller_id, |retained| retained.controller_id)
            {
                Ok(_) => return Err(IdentityError::StorageCorruption),
                Err(key_index) => key_index,
            };
            stable
                .migrated_keys
                .insert(key_index, MigrationKey { controller_id, key });
        }
        Ok(())
    }

    fn crypto_retains_key_material(&self, candidate: &[u8]) -> bool {
        let stable_reuses = |stable: &StableCrypto| {
            stable
                .migrated_keys
                .iter()
                .any(|retained| retained.key.as_bytes() == candidate)
                || stable
                    .key_tombstones
                    .iter()
                    .any(|retired| retired.as_bytes() == candidate)
        };
        match &self.crypto {
            CryptoProjection::Stable(stable) => stable_reuses(stable),
            CryptoProjection::Candidate {
                previous,
                migration,
                ..
            }
            | CryptoProjection::Dual {
                previous,
                migration,
                ..
            } => {
                stable_reuses(previous)
                    || migration
                        .bindings()
                        .iter()
                        .any(|binding| binding.new_signing_key().as_bytes() == candidate)
            }
        }
    }

    fn remove_controller(&mut self, controller_id: ControllerId) -> Result<(), IdentityError> {
        if self.revoked_controller(controller_id).is_some() {
            return Err(IdentityError::RevokedController);
        }
        let index = self
            .active_controllers
            .binary_search_by_key(&controller_id, ProjectedController::id)
            .map_err(|_| IdentityError::UnknownController)?;
        let removed = self.active_controllers.remove(index);
        if self.active_controllers.is_empty() {
            return Err(IdentityError::UnsatisfiableThreshold);
        }
        let descriptors = self.active_controller_descriptors();
        self.control_policy.validate_satisfiable(&descriptors)?;
        self.recovery_policy
            .validate_controller_authority(&descriptors)?;
        let revoked_index = match self
            .revoked_controllers
            .binary_search_by_key(&controller_id, ProjectedController::id)
        {
            Ok(_) => return Err(IdentityError::StorageCorruption),
            Err(index) => index,
        };
        self.revoked_controllers.insert(revoked_index, removed);
        // A migrated signing key remains retained under its revoked controller identifier.
        // This is a permanent key tombstone and also keeps the sorted active-key projection
        // stable for every controller that remains active.
        Ok(())
    }

    fn active_controller_descriptors(&self) -> Vec<ControllerDescriptor> {
        self.active_controllers
            .iter()
            .map(|controller| controller.descriptor.clone())
            .collect()
    }

    fn begin_recovery(
        &mut self,
        begin: &crate::BeginRecovery,
        admission_evidence: &AdmissionEvidence,
        event_id: EventId,
        begin_proposal_id: ProposalId,
    ) -> Result<(), IdentityError> {
        self.require_v1_recovery_crypto()?;
        if self.pending_recovery.is_some() || !begin.requires_vacant_recovery_slot() {
            return Err(IdentityError::RecoveryPending);
        }
        let plan = begin.proposal().plan();
        let current_head = self
            .heads
            .first()
            .copied()
            .ok_or(IdentityError::InvalidPredecessor)?;
        if plan.account_id() != self.account_id {
            return Err(IdentityError::AccountMismatch);
        }
        if plan.prior_event_head() != current_head {
            return Err(IdentityError::InvalidPredecessor);
        }
        if plan.recovery_policy_id() != self.recovery_policy_id
            || plan.recovery_policy_version() != self.recovery_policy.policy_version()
            || begin.threshold_evidence().recovery_policy_id() != self.recovery_policy_id
            || begin.threshold_evidence().recovery_policy_version()
                != self.recovery_policy.policy_version()
        {
            return Err(IdentityError::PolicyVersionMismatch);
        }
        self.pending_recovery = Some(PendingRecovery {
            recovery_id: begin.recovery_id(),
            proposal: begin.proposal().clone(),
            pre_recovery_control_policy_id: self.control_policy_id,
            begin_event_id: event_id,
            begin_proposal_id,
            begin_observation: PendingRecoveryObservation::from_admission(
                admission_evidence,
                &self.recovery_policy,
            )?,
        });
        self.lifecycle = ProjectionLifecycle::RecoveryPending;
        Ok(())
    }

    fn veto_recovery(&mut self, veto: &crate::VetoRecovery) -> Result<(), IdentityError> {
        let pending = self
            .pending_recovery
            .as_ref()
            .ok_or(IdentityError::InvalidRelationship {
                resource: "veto without pending recovery",
            })?;
        if veto.expected_pending_recovery() != pending.recovery_id {
            return Err(IdentityError::InvalidRelationship {
                resource: "veto pending recovery compare-and-set",
            });
        }
        if veto.pre_recovery_control_policy_id() != pending.pre_recovery_control_policy_id {
            return Err(IdentityError::PolicyVersionMismatch);
        }
        self.pending_recovery = None;
        self.lifecycle = ProjectionLifecycle::Active;
        Ok(())
    }

    fn cancel_recovery(&mut self, cancel: &crate::CancelRecovery) -> Result<(), IdentityError> {
        let pending = self
            .pending_recovery
            .as_ref()
            .ok_or(IdentityError::InvalidRelationship {
                resource: "cancel without pending recovery",
            })?;
        if cancel.expected_pending_recovery() != pending.recovery_id {
            return Err(IdentityError::InvalidRelationship {
                resource: "cancel pending recovery compare-and-set",
            });
        }
        if cancel.threshold_evidence().recovery_policy_id() != self.recovery_policy_id
            || cancel.threshold_evidence().recovery_policy_version()
                != self.recovery_policy.policy_version()
        {
            return Err(IdentityError::PolicyVersionMismatch);
        }
        self.pending_recovery = None;
        self.lifecycle = ProjectionLifecycle::Active;
        Ok(())
    }

    fn finalize_recovery(
        &mut self,
        finalize: &crate::FinalizeRecovery,
        provider_authority_time: Option<Timestamp>,
    ) -> Result<(), IdentityError> {
        self.require_v1_recovery_crypto()?;
        let pending = self
            .pending_recovery
            .as_ref()
            .ok_or(IdentityError::InvalidRelationship {
                resource: "finalize without pending recovery",
            })?
            .clone();
        if let Some(begin_transition) = self
            .lineage
            .iter()
            .find(|entry| entry.event.event_id() == Ok(pending.begin_event_id))
            && begin_transition
                .event
                .admission_evidence()
                .admission_evidence_id()?
                != pending.begin_observation.admission_evidence_id
        {
            return Err(IdentityError::StorageCorruption);
        }
        if finalize.expected_pending_recovery() != pending.recovery_id {
            return Err(IdentityError::InvalidRelationship {
                resource: "finalize pending recovery compare-and-set",
            });
        }
        let anchor = finalize.delay_anchor();
        if anchor.account_id() != self.account_id || anchor.recovery_id() != pending.recovery_id {
            return Err(IdentityError::AccountMismatch);
        }
        if anchor.begin_proposal_id() != pending.begin_proposal_id {
            return Err(IdentityError::InvalidRelationship {
                resource: "recovery begin proposal delay anchor",
            });
        }
        if pending.begin_observation.provider_policy_id != self.provider_policy_id {
            return Err(IdentityError::StorageCorruption);
        }
        if anchor.provider_policy_id() != self.provider_policy_id {
            return Err(IdentityError::PolicyVersionMismatch);
        }
        let replicated_provider_policy = match self.provider_policy.mode() {
            crate::ProviderMode::LocalOnly => return Err(IdentityError::FreshnessUnavailable),
            crate::ProviderMode::Replicated(policy) => policy,
        };
        let finalize_rule = self
            .control_policy
            .rule_for(crate::OperationKind::FinalizeRecovery)
            .ok_or(IdentityError::AuthorizationDenied)?;
        let freshness_quorum = match finalize_rule.freshness() {
            FreshnessRequirement::LatestKnown => 0,
            FreshnessRequirement::ProviderQuorum(requirement) => {
                usize::from(requirement.required().get())
            }
        };
        let minimum_required = usize::from(replicated_provider_policy.sufficient_threshold().get())
            .max(freshness_quorum);
        if usize::from(anchor.required_quorum().get()) < minimum_required {
            return Err(IdentityError::FreshnessUnavailable);
        }
        if !pending.begin_observation.matches_completion_anchor(anchor) {
            return Err(IdentityError::InvalidRelationship {
                resource: "recovery begin observation binding",
            });
        }
        let required = usize::from(anchor.required_quorum().get());
        let mut configured_receipts = Vec::new();
        for receipt in anchor.receipts().as_slice() {
            if receipt.entry().account_id() != self.account_id {
                return Err(IdentityError::AccountMismatch);
            }
            if receipt.entry().subject()
                != crate::ProviderLogSubject::EventIntent(pending.begin_proposal_id)
            {
                return Err(IdentityError::InvalidRelationship {
                    resource: "recovery delay receipt subject",
                });
            }
            let Some(provider) = crate::verifier::configured_provider(
                replicated_provider_policy.providers(),
                receipt.provider_id(),
            )?
            else {
                continue;
            };
            receipt.verify(provider)?;
            configured_receipts.push(receipt);
        }
        if configured_receipts.len() < required {
            return Err(IdentityError::FreshnessUnavailable);
        }
        let mut configured_observations = configured_receipts
            .iter()
            .map(|receipt| receipt.entry().observed_at())
            .collect::<Vec<_>>();
        configured_observations.sort_unstable();
        if configured_observations[required - 1] != anchor.observed_at() {
            return Err(IdentityError::InvalidRelationship {
                resource: "configured-provider recovery delay observation anchor",
            });
        }
        let delay_deadline = pending.begin_observation.delay_deadline;
        let mut completion_times = configured_receipts
            .iter()
            .map(|receipt| receipt.signed_head().body().observed_at())
            .filter(|observed_at| *observed_at >= delay_deadline)
            .collect::<Vec<_>>();
        if completion_times.len() < required {
            return Err(IdentityError::DelayNotElapsed);
        }
        completion_times.sort_unstable();
        let nested_authority_time = completion_times[required - 1];
        let provider_authority_time = provider_authority_time
            .map_or(nested_authority_time, |outer| {
                outer.max(nested_authority_time)
            });
        let lifetime_deadline = pending.begin_observation.lifetime_deadline;
        let plan = pending.proposal.plan();
        if provider_authority_time > lifetime_deadline
            || provider_authority_time > plan.expires_at()
        {
            return Err(IdentityError::StaleEvidence);
        }

        self.install_recovery_plan(plan)?;
        self.pending_recovery = None;
        self.lifecycle = ProjectionLifecycle::Active;
        Ok(())
    }

    pub(crate) fn require_v1_recovery_crypto(&self) -> Result<(), IdentityError> {
        match &self.crypto {
            CryptoProjection::Stable(stable)
                if stable.suite == CryptoSuiteDescriptor::v1()?
                    && stable.migrated_keys.is_empty() =>
            {
                Ok(())
            }
            CryptoProjection::Stable(_)
            | CryptoProjection::Candidate { .. }
            | CryptoProjection::Dual { .. } => Err(IdentityError::UnsupportedPolicyFeature {
                feature: "recovery under a migrated cryptographic suite",
            }),
        }
    }

    fn install_recovery_plan(
        &mut self,
        plan: &crate::RecoveryAuthorityPlan,
    ) -> Result<(), IdentityError> {
        for descriptor in plan.replacement_controllers() {
            let identifier = descriptor.id()?;
            if self.revoked_controller(identifier).is_some() {
                return Err(IdentityError::RevokedController);
            }
            if self.active_controllers.iter().any(|controller| {
                controller.id() != identifier
                    && controller.signing_key() == descriptor.signing_key()
            }) {
                return Err(IdentityError::DuplicateSigningKey);
            }
            if self
                .revoked_controllers
                .iter()
                .any(|controller| controller.signing_key() == descriptor.signing_key())
            {
                return Err(IdentityError::DuplicateSigningKey);
            }
            if self.devices.iter().any(|device| {
                device_descriptor_reuses_controller_key(
                    device.descriptor(),
                    descriptor.signing_key(),
                )
            }) {
                return Err(IdentityError::InvalidRelationship {
                    resource: "controller/device public-key role separation",
                });
            }
        }

        let replacement_ids = plan
            .replacement_controllers()
            .iter()
            .map(ControllerDescriptor::id)
            .collect::<Result<Vec<_>, IdentityError>>()?;
        let removed = self
            .active_controllers
            .iter()
            .filter(|controller| replacement_ids.binary_search(&controller.id()).is_err())
            .cloned()
            .collect::<Vec<_>>();
        for controller in removed {
            let index = match self
                .revoked_controllers
                .binary_search_by_key(&controller.id(), ProjectedController::id)
            {
                Ok(_) => return Err(IdentityError::StorageCorruption),
                Err(index) => index,
            };
            self.revoked_controllers.insert(index, controller);
        }
        let retained_count = plan
            .replacement_controllers()
            .len()
            .checked_add(self.revoked_controllers.len())
            .ok_or(IdentityError::ArithmeticOverflow {
                resource: "recovery controller tombstones",
            })?;
        if retained_count > MAX_CONTROLLERS {
            return Err(IdentityError::limit(
                "recovery controller tombstones",
                retained_count,
                MAX_CONTROLLERS,
            ));
        }
        self.active_controllers = plan
            .replacement_controllers()
            .iter()
            .map(|descriptor| {
                Ok(ProjectedController {
                    id: descriptor.id()?,
                    descriptor: descriptor.clone(),
                })
            })
            .collect::<Result<Vec<_>, IdentityError>>()?;

        for retained in plan.retained_devices() {
            let index = self
                .devices
                .binary_search_by_key(retained, ProjectedDevice::id)
                .map_err(|_| IdentityError::DeviceNotAuthorized)?;
            if self.devices[index].lifecycle == ProjectedDeviceLifecycle::Revoked {
                return Err(IdentityError::DeviceRevoked);
            }
        }
        for device in &mut self.devices {
            if device.lifecycle != ProjectedDeviceLifecycle::Revoked
                && plan.retained_devices().binary_search(&device.id()).is_err()
            {
                device.lifecycle = ProjectedDeviceLifecycle::Revoked;
            }
        }

        self.control_policy = plan.replacement_control_policy().clone();
        self.control_policy_id = self.control_policy.id()?;
        self.recovery_policy = plan.replacement_recovery_policy().clone();
        self.recovery_policy_id = self.recovery_policy.id()?;
        Ok(())
    }

    fn begin_crypto_migration(
        &mut self,
        begin: &crate::BeginCryptoMigration,
        event_id: EventId,
    ) -> Result<(), IdentityError> {
        let CryptoProjection::Stable(previous) = &self.crypto else {
            return Err(IdentityError::InvalidRelationship {
                resource: "nested cryptographic migration",
            });
        };
        let previous = previous.clone();
        let migration = begin.migration();
        let migration_id = migration.crypto_migration_id()?;
        if migration.account_id() != self.account_id {
            return Err(IdentityError::AccountMismatch);
        }
        if migration.from_suite_id() != previous.suite.crypto_suite_id()? {
            return Err(IdentityError::InvalidRelationship {
                resource: "migration active suite",
            });
        }
        let candidate_suite_id = migration.to_suite().crypto_suite_id()?;
        if previous
            .retired_suites
            .iter()
            .any(|retired| retired.suite_id == candidate_suite_id)
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "retired cryptographic suite reuse",
            });
        }
        let retiring_keys = stable_suite_keys(
            &previous,
            &self.active_controllers,
            &self.revoked_controllers,
        )?;
        let projected_tombstones = previous
            .key_tombstones
            .len()
            .checked_add(retiring_keys.len())
            .ok_or(IdentityError::ArithmeticOverflow {
                resource: "cryptographic key tombstones",
            })?;
        if projected_tombstones > MAX_HISTORY_PAGE_EVENTS {
            return Err(IdentityError::limit(
                "cryptographic key tombstones",
                projected_tombstones,
                MAX_HISTORY_PAGE_EVENTS,
            ));
        }
        if previous.retired_suites.len() >= MAX_HISTORY_PAGE_EVENTS {
            return Err(IdentityError::limit(
                "retired cryptographic suites",
                previous.retired_suites.len().saturating_add(1),
                MAX_HISTORY_PAGE_EVENTS,
            ));
        }
        if migration.bindings().len() != self.active_controllers.len()
            || begin.proofs().as_slice().len() != self.active_controllers.len()
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "complete controller migration binding set",
            });
        }
        let signed_message = migration_id.to_canonical_bytes()?;
        for ((controller, binding), proof) in self
            .active_controllers
            .iter()
            .zip(migration.bindings())
            .zip(begin.proofs().as_slice())
        {
            if binding.controller_id() != controller.id()
                || proof.controller_id() != controller.id()
                || proof.migration_id() != migration_id
            {
                return Err(IdentityError::InvalidRelationship {
                    resource: "migration controller proof coverage",
                });
            }
            if migration_key_reuses_retained_material(
                binding.new_signing_key(),
                &previous,
                &self.active_controllers,
                &self.revoked_controllers,
                &self.devices,
            ) {
                return Err(IdentityError::DuplicateSigningKey);
            }
            let current_keys = self.verification_keys(controller.id())?;
            if current_keys.len() != 1 || binding.old_key_id() != current_keys[0].controller_key_id
            {
                return Err(IdentityError::InvalidRelationship {
                    resource: "migration old controller key",
                });
            }
            crate::verifier::verify_algorithm_signature(
                current_keys[0].algorithm_code,
                &current_keys[0].public_key,
                proof.old_key_signature(),
                &signed_message,
            )?;
            crate::verifier::verify_algorithm_signature(
                binding.new_signing_key().algorithm_code(),
                binding.new_signing_key().as_bytes(),
                proof.new_key_signature(),
                &signed_message,
            )?;
        }
        self.crypto = CryptoProjection::Candidate {
            previous,
            migration: migration.clone(),
            begin_event_id: event_id,
        };
        self.lifecycle = ProjectionLifecycle::MigrationPending;
        Ok(())
    }

    fn activate_crypto_migration(
        &mut self,
        activate: &crate::ActivateCryptoMigration,
        event_id: EventId,
    ) -> Result<(), IdentityError> {
        let CryptoProjection::Candidate {
            previous,
            migration,
            begin_event_id,
        } = self.crypto.clone()
        else {
            return Err(IdentityError::InvalidRelationship {
                resource: "activate without candidate migration",
            });
        };
        if activate.migration_id() != migration.crypto_migration_id()?
            || activate.begin_event_id() != begin_event_id
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "activate migration compare-and-set",
            });
        }
        self.crypto = CryptoProjection::Dual {
            previous,
            migration,
            begin_event_id,
            activation_event_id: event_id,
        };
        self.lifecycle = ProjectionLifecycle::MigrationDual;
        Ok(())
    }

    fn retire_crypto_suite(
        &mut self,
        retire: &crate::RetireCryptoSuite,
        resulting_epoch: Epoch,
    ) -> Result<(), IdentityError> {
        match (self.crypto.clone(), retire.mode()) {
            (
                CryptoProjection::Candidate {
                    previous,
                    migration,
                    begin_event_id,
                },
                crate::RetireCryptoSuiteMode::AbortCandidate,
            ) => {
                if retire.migration_id() != migration.crypto_migration_id()?
                    || retire.phase_event_id() != begin_event_id
                    || retire.successor_account_id().is_some()
                {
                    return Err(IdentityError::InvalidRelationship {
                        resource: "abort candidate migration compare-and-set",
                    });
                }
                self.crypto = CryptoProjection::Stable(previous);
                self.lifecycle = ProjectionLifecycle::Active;
                Ok(())
            }
            (
                CryptoProjection::Dual {
                    previous,
                    migration,
                    activation_event_id,
                    ..
                },
                crate::RetireCryptoSuiteMode::RetirePrevious,
            ) => {
                if retire.migration_id() != migration.crypto_migration_id()?
                    || retire.phase_event_id() != activation_event_id
                    || retire.successor_account_id() != migration.successor_account_id()
                {
                    return Err(IdentityError::InvalidRelationship {
                        resource: "retire previous suite compare-and-set",
                    });
                }
                let migrated_keys = migration
                    .bindings()
                    .iter()
                    .map(|binding| MigrationKey {
                        controller_id: binding.controller_id(),
                        key: binding.new_signing_key().clone(),
                    })
                    .collect();
                let mut retired_suites = previous.retired_suites.clone();
                retired_suites.push(RetiredCryptoSuite {
                    suite_id: previous.suite.crypto_suite_id()?,
                    retired_at: resulting_epoch,
                });
                let mut key_tombstones = previous.key_tombstones.clone();
                key_tombstones.extend(stable_suite_keys(
                    &previous,
                    &self.active_controllers,
                    &self.revoked_controllers,
                )?);
                key_tombstones.sort_unstable_by(|left, right| {
                    left.algorithm_code()
                        .cmp(&right.algorithm_code())
                        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
                });
                key_tombstones.dedup_by(|left, right| {
                    left.algorithm_code() == right.algorithm_code()
                        && left.as_bytes() == right.as_bytes()
                });
                self.crypto = CryptoProjection::Stable(StableCrypto {
                    suite: migration.to_suite().clone(),
                    migrated_keys,
                    retired_suites,
                    key_tombstones,
                });
                self.lifecycle = if retire.successor_account_id().is_some() {
                    self.retirement = Some(RetirementProjection::CryptoMigration {
                        migration_id: retire.migration_id(),
                        successor_account_id: retire
                            .successor_account_id()
                            .ok_or(IdentityError::StorageCorruption)?,
                        retired_at: resulting_epoch,
                    });
                    ProjectionLifecycle::Retired
                } else {
                    ProjectionLifecycle::Active
                };
                Ok(())
            }
            _ => Err(IdentityError::InvalidRelationship {
                resource: "cryptographic suite retirement phase",
            }),
        }
    }

    pub(crate) fn active_controller(
        &self,
        controller_id: ControllerId,
    ) -> Option<&ProjectedController> {
        self.active_controllers
            .binary_search_by_key(&controller_id, ProjectedController::id)
            .ok()
            .map(|index| &self.active_controllers[index])
    }

    pub(crate) fn revoked_controller(
        &self,
        controller_id: ControllerId,
    ) -> Option<&ProjectedController> {
        self.revoked_controllers
            .binary_search_by_key(&controller_id, ProjectedController::id)
            .ok()
            .map(|index| &self.revoked_controllers[index])
    }

    pub(crate) fn verification_keys(
        &self,
        controller_id: ControllerId,
    ) -> Result<Vec<VerificationKey>, IdentityError> {
        let controller = self
            .active_controller(controller_id)
            .ok_or(IdentityError::UnknownController)?;
        match &self.crypto {
            CryptoProjection::Stable(stable)
            | CryptoProjection::Candidate {
                previous: stable, ..
            } => stable_verification_keys(stable, controller),
            CryptoProjection::Dual {
                previous,
                migration,
                ..
            } => {
                let mut keys = stable_verification_keys(previous, controller)?;
                let binding = migration
                    .bindings()
                    .binary_search_by_key(&controller_id, |binding| binding.controller_id())
                    .ok()
                    .map(|index| &migration.bindings()[index])
                    .ok_or(IdentityError::InvalidRelationship {
                        resource: "dual migration controller binding",
                    })?;
                keys.push(VerificationKey {
                    crypto_suite_id: migration.to_suite().crypto_suite_id()?,
                    controller_key_id: ControllerKeyId::for_algorithm_key(
                        binding.new_signing_key(),
                    )?,
                    algorithm_code: binding.new_signing_key().algorithm_code(),
                    public_key: binding.new_signing_key().as_bytes().to_vec(),
                });
                keys.sort_unstable_by_key(|key| (key.crypto_suite_id, key.controller_key_id));
                Ok(keys)
            }
        }
    }
}

fn stable_verification_keys(
    stable: &StableCrypto,
    controller: &ProjectedController,
) -> Result<Vec<VerificationKey>, IdentityError> {
    if stable.migrated_keys.is_empty() {
        let signing_key = controller.signing_key();
        return Ok(vec![VerificationKey {
            crypto_suite_id: stable.suite.crypto_suite_id()?,
            controller_key_id: ControllerKeyId::for_signing_key(&signing_key)?,
            algorithm_code: crate::SignatureAlgorithm::Ed25519.code(),
            public_key: signing_key.as_bytes().to_vec(),
        }]);
    }
    let migrated = stable
        .migrated_keys
        .binary_search_by_key(&controller.id(), |key| key.controller_id)
        .ok()
        .map(|index| &stable.migrated_keys[index])
        .ok_or(IdentityError::InvalidRelationship {
            resource: "migrated controller verification key",
        })?;
    Ok(vec![VerificationKey {
        crypto_suite_id: stable.suite.crypto_suite_id()?,
        controller_key_id: ControllerKeyId::for_algorithm_key(&migrated.key)?,
        algorithm_code: migrated.key.algorithm_code(),
        public_key: migrated.key.as_bytes().to_vec(),
    }])
}

fn stable_crypto_state_material(
    stable: &StableCrypto,
) -> Result<StableCryptoStateMaterial<'_>, IdentityError> {
    Ok(StableCryptoStateMaterial {
        current_suite_id: stable.suite.crypto_suite_id()?,
        migrated_keys: &stable.migrated_keys,
        retired_suites: &stable.retired_suites,
        key_tombstones: &stable.key_tombstones,
    })
}

fn stable_suite_keys(
    stable: &StableCrypto,
    active: &[ProjectedController],
    revoked: &[ProjectedController],
) -> Result<Vec<AlgorithmPublicKey>, IdentityError> {
    if !stable.migrated_keys.is_empty() {
        return Ok(stable
            .migrated_keys
            .iter()
            .map(|retained| retained.key.clone())
            .collect());
    }
    active
        .iter()
        .chain(revoked)
        .map(|controller| {
            AlgorithmPublicKey::new(
                stable.suite.signature_algorithm_code(),
                controller.signing_key().as_bytes().to_vec(),
            )
        })
        .collect()
}

fn migration_key_reuses_retained_material(
    candidate: &AlgorithmPublicKey,
    stable: &StableCrypto,
    active: &[ProjectedController],
    revoked: &[ProjectedController],
    devices: &[ProjectedDevice],
) -> bool {
    stable
        .migrated_keys
        .iter()
        .any(|retained| retained.key.as_bytes() == candidate.as_bytes())
        || stable
            .key_tombstones
            .iter()
            .any(|retired| retired.as_bytes() == candidate.as_bytes())
        || active
            .iter()
            .chain(revoked)
            .any(|controller| controller.signing_key().as_bytes() == candidate.as_bytes())
        || devices.iter().any(|device| {
            let descriptor = device.descriptor();
            descriptor.application_signing_key().as_bytes() == candidate.as_bytes()
                || descriptor.agreement_key().as_bytes() == candidate.as_bytes()
                || descriptor.endpoint_key().as_signing_key().as_bytes() == candidate.as_bytes()
        })
}

fn device_descriptors_reuse_key(
    left: &crate::DeviceDescriptor,
    right: &crate::DeviceDescriptor,
) -> bool {
    let left_application = left.application_signing_key();
    let left_agreement = left.agreement_key();
    let left_endpoint = left.endpoint_key().as_signing_key();
    let right_application = right.application_signing_key();
    let right_agreement = right.agreement_key();
    let right_endpoint = right.endpoint_key().as_signing_key();
    let left_keys = [
        left_application.as_bytes(),
        left_agreement.as_bytes(),
        left_endpoint.as_bytes(),
    ];
    let right_keys = [
        right_application.as_bytes(),
        right_agreement.as_bytes(),
        right_endpoint.as_bytes(),
    ];
    left_keys
        .iter()
        .any(|left_key| right_keys.iter().any(|right_key| left_key == right_key))
}

fn device_descriptor_reuses_controller_key(
    descriptor: &crate::DeviceDescriptor,
    controller_key: SigningPublicKey,
) -> bool {
    descriptor.application_signing_key() == controller_key
        || descriptor.agreement_key().as_bytes() == controller_key.as_bytes()
        || descriptor.endpoint_key().as_signing_key() == controller_key
}

fn operation_changes_epoch(operation: &AccountOperation) -> bool {
    match AccountState::operation_kind_advances_epoch(operation.kind()) {
        Some(changes_epoch) => changes_epoch,
        None => matches!(
            operation,
            AccountOperation::RetireCryptoSuite(retire)
                if retire.mode() == crate::RetireCryptoSuiteMode::RetirePrevious
        ),
    }
}

fn expected_epoch(
    state: &AccountState,
    operation: &AccountOperation,
) -> Result<Epoch, IdentityError> {
    if operation_changes_epoch(operation) {
        state.epoch.checked_next()
    } else {
        Ok(state.epoch)
    }
}

fn transition_effects(
    event_id: EventId,
    epoch: Epoch,
    changes_epoch: bool,
) -> Vec<ProjectionEffect> {
    let mut effects = Vec::with_capacity(if changes_epoch { 3 } else { 2 });
    effects.push(ProjectionEffect::PublishAccountEvent { event_id });
    if changes_epoch {
        effects.push(ProjectionEffect::RotateGroupKeys { event_id, epoch });
    }
    effects.push(ProjectionEffect::NotifyAccountChanged { event_id });
    effects
}

fn merge_event_evidence(
    retained: &AuthorizedEvent,
    incoming: &AuthorizedEvent,
) -> Result<AuthorizedEvent, IdentityError> {
    if retained.body() != incoming.body()
        || retained.admission_evidence() != incoming.admission_evidence()
    {
        return Err(IdentityError::InvalidIdentifier {
            resource: "admitted event identity",
        });
    }
    let approvals = retained.approvals().merge(incoming.approvals())?;
    if &approvals == retained.approvals() {
        return Ok(retained.clone());
    }
    AuthorizedEvent::new(
        retained.body().clone(),
        retained.admission_evidence().clone(),
        approvals,
    )
}

fn project_transition(
    pre_state: &AccountState,
    event: &AuthorizedEvent,
    event_id: EventId,
) -> Result<(LineageEntry, AccountState), IdentityError> {
    let mut projected = pre_state.clone();
    projected.lineage.clear();
    projected.lineage_bytes = 0;
    if projected.fork.is_some()
        && matches!(event.body().operation(), AccountOperation::ResolveFork(_))
    {
        projected.apply_fork_resolution(event, event_id)?;
    } else {
        projected.fork = None;
        projected.apply_new_linear(event, event_id)?;
    }
    let transition = projected
        .lineage
        .last()
        .ok_or(IdentityError::StorageCorruption)?;
    let transition = LineageEntry {
        pre_state: transition.pre_state.clone(),
        authority_state: transition.authority_state.clone(),
        expected_epoch: transition.expected_epoch,
        event: transition.event.clone(),
    };
    Ok((transition, projected.detached_snapshot()))
}

fn projection_lifecycle_code(lifecycle: ProjectionLifecycle) -> u16 {
    match lifecycle {
        ProjectionLifecycle::Active => 1,
        ProjectionLifecycle::RecoveryPending => 2,
        ProjectionLifecycle::Forked => 3,
        ProjectionLifecycle::MigrationPending => 4,
        ProjectionLifecycle::MigrationDual => 5,
        ProjectionLifecycle::UpgradePending => 6,
        ProjectionLifecycle::Retired => 7,
    }
}

fn semantic_projection_bytes(state: &AccountState) -> Result<usize, IdentityError> {
    crate::codec::encode_wire(&CanonicalProjectionView {
        account_id: state.account_id,
        genesis_anchor: state.genesis_anchor,
        protocol_major: state.protocol_major,
        sequence: state.sequence,
        epoch: state.epoch,
        heads: &state.heads,
        active_controllers: &state.active_controllers,
        revoked_controllers: &state.revoked_controllers,
        devices: &state.devices,
        control_policy: &state.control_policy,
        control_policy_id: state.control_policy_id,
        recovery_policy: &state.recovery_policy,
        recovery_policy_id: state.recovery_policy_id,
        provider_policy: &state.provider_policy,
        provider_policy_id: state.provider_policy_id,
        pending_recovery: &state.pending_recovery,
        crypto: &state.crypto,
        upgrade: &state.upgrade,
        retirement: &state.retirement,
        lifecycle_code: projection_lifecycle_code(state.lifecycle),
    })
    .map(|bytes| bytes.len())
}

fn checked_evidence_add(total: &mut usize, amount: usize) -> Result<(), IdentityError> {
    *total = total
        .checked_add(amount)
        .ok_or(IdentityError::ArithmeticOverflow {
            resource: "account projection evidence bytes",
        })?;
    Ok(())
}

fn lineage_entry_evidence_bytes(entry: &LineageEntry) -> Result<usize, IdentityError> {
    let mut total = entry.event.to_canonical_bytes()?.len();
    checked_evidence_add(
        &mut total,
        account_state_evidence_bytes(&entry.pre_state, 0)?,
    )?;
    if let Some(authority) = &entry.authority_state {
        checked_evidence_add(&mut total, account_state_evidence_bytes(authority, 0)?)?;
    }
    Ok(total)
}

fn account_state_evidence_bytes(
    state: &AccountState,
    depth: usize,
) -> Result<usize, IdentityError> {
    if depth > MAX_HISTORY_PAGE_EVENTS {
        return Err(IdentityError::limit(
            "nested account projection evidence",
            depth,
            MAX_HISTORY_PAGE_EVENTS,
        ));
    }
    let mut total = semantic_projection_bytes(state)?;
    if let Some(fork) = &state.fork {
        checked_evidence_add(
            &mut total,
            account_state_evidence_bytes(&fork.common_state, depth.saturating_add(1))?,
        )?;
        checked_evidence_add(&mut total, fork.common_ancestor.to_canonical_bytes()?.len())?;
        checked_evidence_add(
            &mut total,
            fork.conflict_predecessors.to_canonical_bytes()?.len(),
        )?;
        for branch in &fork.branches {
            checked_evidence_add(
                &mut total,
                account_state_evidence_bytes(&branch.projected_state, depth.saturating_add(1))?,
            )?;
            for transition in &branch.transitions {
                checked_evidence_add(&mut total, transition.event.to_canonical_bytes()?.len())?;
                checked_evidence_add(
                    &mut total,
                    account_state_evidence_bytes(&transition.pre_state, depth.saturating_add(1))?,
                )?;
                if let Some(authority) = &transition.authority_state {
                    checked_evidence_add(
                        &mut total,
                        account_state_evidence_bytes(authority, depth.saturating_add(1))?,
                    )?;
                }
            }
        }
    }
    Ok(total)
}

fn sort_fork_branches(branches: &mut Vec<ForkBranch>) -> Result<(), IdentityError> {
    let mut identified = Vec::with_capacity(branches.len());
    for branch in branches.drain(..) {
        identified.push((fork_branch_event_id(&branch)?, branch));
    }
    identified.sort_unstable_by_key(|(event_id, _)| *event_id);
    branches.extend(identified.into_iter().map(|(_, branch)| branch));
    Ok(())
}

fn fork_head_ids(branches: &[ForkBranch]) -> Result<Vec<EventId>, IdentityError> {
    branches.iter().map(fork_branch_event_id).collect()
}

fn fork_branch_event_id(branch: &ForkBranch) -> Result<EventId, IdentityError> {
    branch
        .transitions
        .last()
        .ok_or(IdentityError::StorageCorruption)?
        .event
        .event_id()
}

fn validate_fork_evidence_bound(
    common_state: &AccountState,
    branches: &[ForkBranch],
) -> Result<(), IdentityError> {
    let mut total = account_state_evidence_bytes(common_state, 0)?;
    for branch in branches {
        checked_evidence_add(
            &mut total,
            account_state_evidence_bytes(&branch.projected_state, 0)?,
        )?;
        for transition in &branch.transitions {
            checked_evidence_add(&mut total, lineage_entry_evidence_bytes(transition)?)?;
        }
    }
    if total > MAX_FORK_EVIDENCE_BYTES {
        return Err(IdentityError::limit(
            "account fork evidence bytes",
            total,
            MAX_FORK_EVIDENCE_BYTES,
        ));
    }
    Ok(())
}
