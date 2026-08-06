//! Durable, idempotent operational-effect substep journals.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard},
};

use crate::{
    AccountId, AccountSnapshot, AccountStore, AuthorizedEvent, CheckpointBody,
    CheckpointCommitReceipt, EffectFailure, EffectId, EffectRecord, EffectStatus, Epoch,
    GroupKeyRotation, IdentityError, InclusionReceipt, LeaseId, ProjectionEffect,
    ProviderCheckpointBundle, ProviderDescriptor, ProviderId, ProviderLogSubject, ProviderMode,
    ProviderPolicy, PublicationBatch, PublicationStage, PublicationTracker, SignedCheckpoint,
    StoreFuture, StoredGroupKeyRotation, Timestamp, TransparencyClient, VerifiedCheckpoint,
    build_checkpoint_body,
    limits::{MAX_RETRIES, MAX_TRANSPARENCY_PROVIDERS},
    merkle::MerkleConsistencyProof,
    publish_checkpoint_concurrently,
    store::derive_effect_id,
    verify_checkpoint, verify_provider_head_progression,
};

const MAX_OPERATION_AUDIT_RECORDS: usize = 256;

#[cfg(feature = "provider-store")]
mod redb;

#[cfg(feature = "provider-store")]
pub use redb::RedbOperationalEffectStore;

/// Durable operational phase for one stable Task 6 effect identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OperationalEffectPhase {
    /// Task 6 effect is exclusively claimed by one lease.
    Claimed,
    /// Deterministic checkpoint body has been built for the exact event effect.
    CheckpointDraft,
    /// Checkpoint authorization has been verified and durably journaled.
    CheckpointAuthorized,
    /// At least one configured provider receipt has been verified.
    Published,
    /// The authenticated provider policy's sufficient publication threshold was reached.
    Replicated,
    /// A sufficient threshold was later re-observed with exact consistency evidence.
    Observed,
    /// Revision-bound group-key rotation was durably committed by Task 6.
    RotationCommitted,
    /// Peer notification completed idempotently.
    PeersNotified,
    /// Retryable failure was scheduled without overstating publication progress.
    RetryScheduled,
    /// Permanent failure is retained for operator action.
    TerminalFailure,
    /// Task 6 effect completion and every required operational substep reconciled.
    Completed,
}

fn valid_phase_transition(current: OperationalEffectPhase, next: OperationalEffectPhase) -> bool {
    if current == next {
        return !matches!(
            current,
            OperationalEffectPhase::TerminalFailure | OperationalEffectPhase::Completed
        );
    }
    match current {
        OperationalEffectPhase::Claimed => matches!(
            next,
            OperationalEffectPhase::CheckpointDraft
                | OperationalEffectPhase::RotationCommitted
                | OperationalEffectPhase::PeersNotified
                | OperationalEffectPhase::RetryScheduled
                | OperationalEffectPhase::TerminalFailure
        ),
        OperationalEffectPhase::CheckpointDraft => matches!(
            next,
            OperationalEffectPhase::CheckpointAuthorized
                | OperationalEffectPhase::RetryScheduled
                | OperationalEffectPhase::TerminalFailure
        ),
        OperationalEffectPhase::CheckpointAuthorized => matches!(
            next,
            OperationalEffectPhase::Published
                | OperationalEffectPhase::Replicated
                | OperationalEffectPhase::Observed
                | OperationalEffectPhase::RetryScheduled
                | OperationalEffectPhase::TerminalFailure
                | OperationalEffectPhase::Completed
        ),
        OperationalEffectPhase::Published => matches!(
            next,
            OperationalEffectPhase::Replicated
                | OperationalEffectPhase::Observed
                | OperationalEffectPhase::RetryScheduled
                | OperationalEffectPhase::TerminalFailure
        ),
        OperationalEffectPhase::Replicated => matches!(
            next,
            OperationalEffectPhase::Observed
                | OperationalEffectPhase::RetryScheduled
                | OperationalEffectPhase::TerminalFailure
        ),
        OperationalEffectPhase::Observed
        | OperationalEffectPhase::RotationCommitted
        | OperationalEffectPhase::PeersNotified => matches!(
            next,
            OperationalEffectPhase::Completed
                | OperationalEffectPhase::RetryScheduled
                | OperationalEffectPhase::TerminalFailure
        ),
        OperationalEffectPhase::RetryScheduled => matches!(
            next,
            OperationalEffectPhase::Claimed
                | OperationalEffectPhase::CheckpointDraft
                | OperationalEffectPhase::CheckpointAuthorized
                | OperationalEffectPhase::Published
                | OperationalEffectPhase::Replicated
                | OperationalEffectPhase::Observed
                | OperationalEffectPhase::RotationCommitted
                | OperationalEffectPhase::PeersNotified
                | OperationalEffectPhase::TerminalFailure
        ),
        OperationalEffectPhase::TerminalFailure | OperationalEffectPhase::Completed => false,
    }
}

/// One private-safe terminal or progression audit marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationalAuditRecord {
    sequence: u64,
    phase: OperationalEffectPhase,
    recorded_at: Timestamp,
}

impl OperationalAuditRecord {
    /// Monotonic one-based audit sequence within this effect.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Durable phase reached at this audit point.
    pub const fn phase(self) -> OperationalEffectPhase {
        self.phase
    }

    /// Explicit caller-supplied audit time.
    pub const fn recorded_at(self) -> Timestamp {
        self.recorded_at
    }
}

/// Exact publication plus optional later observation retained for one configured provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalProviderReceipt {
    provider: ProviderDescriptor,
    publication: InclusionReceipt,
    observation: Option<(InclusionReceipt, MerkleConsistencyProof)>,
}

impl OperationalProviderReceipt {
    /// Configured provider descriptor authenticating both receipts.
    pub const fn provider(&self) -> &ProviderDescriptor {
        &self.provider
    }

    /// Stable provider identifier used for canonical sorting and deduplication.
    pub fn provider_id(&self) -> Result<ProviderId, IdentityError> {
        self.provider.id()
    }

    /// Original verified checkpoint publication receipt.
    pub const fn publication(&self) -> &InclusionReceipt {
        &self.publication
    }

    /// Later verified observation and its exact append-only proof, when retained.
    pub const fn observation(&self) -> Option<(&InclusionReceipt, &MerkleConsistencyProof)> {
        match &self.observation {
            Some((receipt, proof)) => Some((receipt, proof)),
            None => None,
        }
    }

    fn validate(&self) -> Result<(), IdentityError> {
        if self.provider.id()? != self.publication.provider_id() {
            return Err(IdentityError::InvalidRelationship {
                resource: "operational publication provider",
            });
        }
        self.publication.verify(&self.provider)?;
        if let Some((observation, proof)) = &self.observation {
            observation.verify(&self.provider)?;
            if observation.entry() != self.publication.entry()
                || observation.leaf_index() != self.publication.leaf_index()
            {
                return Err(IdentityError::InvalidRelationship {
                    resource: "operational observation publication leaf",
                });
            }
            verify_provider_head_progression(
                &self.provider,
                self.publication.signed_head(),
                observation.signed_head(),
                proof,
            )?;
        }
        Ok(())
    }
}

/// Complete durable operational journal state for one Task 6 effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalEffectRecord {
    revision: u64,
    effect_id: EffectId,
    account_id: AccountId,
    effect: ProjectionEffect,
    lease_id: LeaseId,
    phase: OperationalEffectPhase,
    checkpoint_body: Option<CheckpointBody>,
    checkpoint: Option<SignedCheckpoint>,
    publication_policy: Option<ProviderPolicy>,
    provider_receipts: Vec<OperationalProviderReceipt>,
    rotation_epoch: Option<Epoch>,
    attempt_count: u8,
    last_failure: Option<EffectFailure>,
    audit: Vec<OperationalAuditRecord>,
}

impl OperationalEffectRecord {
    /// Compare-and-swap revision of this operational substep journal.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Stable Task 6 effect identifier.
    pub const fn effect_id(&self) -> EffectId {
        self.effect_id
    }

    /// Account owning this effect; never use this field as a telemetry label.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Exact deterministic Task 6 effect description.
    pub const fn effect(&self) -> ProjectionEffect {
        self.effect
    }

    /// Task 6 lease that owns this execution attempt.
    pub const fn lease_id(&self) -> LeaseId {
        self.lease_id
    }

    /// Current durable operational phase.
    pub const fn phase(&self) -> OperationalEffectPhase {
        self.phase
    }

    /// Deterministic checkpoint body retained before authorization.
    pub const fn checkpoint_body(&self) -> Option<&CheckpointBody> {
        self.checkpoint_body.as_ref()
    }

    /// Verified signed checkpoint retained for publication reconciliation.
    pub const fn checkpoint(&self) -> Option<&SignedCheckpoint> {
        self.checkpoint.as_ref()
    }

    /// Exact checkpoint-bound provider policy used to validate durable publication progress.
    pub const fn publication_policy(&self) -> Option<&ProviderPolicy> {
        self.publication_policy.as_ref()
    }

    /// Canonically sorted distinct-provider receipt journals.
    pub fn provider_receipts(&self) -> &[OperationalProviderReceipt] {
        &self.provider_receipts
    }

    /// Number of Task 6 execution attempts reflected by this record.
    pub const fn attempt_count(&self) -> u8 {
        self.attempt_count
    }

    /// Most recent stable Task 6 failure class.
    pub const fn last_failure(&self) -> Option<EffectFailure> {
        self.last_failure
    }

    /// Complete bounded phase audit trail.
    pub fn audit(&self) -> &[OperationalAuditRecord] {
        &self.audit
    }

    fn validate(&self) -> Result<(), IdentityError> {
        if derive_effect_id(self.account_id, self.effect)? != self.effect_id
            || self.attempt_count == 0
            || self.attempt_count > MAX_RETRIES
            || self.audit.is_empty()
            || self.audit.len() > MAX_OPERATION_AUDIT_RECORDS
            || self.revision
                != u64::try_from(self.audit.len()).map_err(|_| {
                    IdentityError::ArithmeticOverflow {
                        resource: "operational effect audit revision",
                    }
                })?
        {
            return Err(IdentityError::StorageCorruption);
        }
        for (index, audit) in self.audit.iter().enumerate() {
            let sequence = u64::try_from(index)
                .map_err(|_| IdentityError::ArithmeticOverflow {
                    resource: "operational effect audit sequence",
                })?
                .checked_add(1)
                .ok_or(IdentityError::ArithmeticOverflow {
                    resource: "operational effect audit sequence",
                })?;
            if audit.sequence != sequence {
                return Err(IdentityError::StorageCorruption);
            }
            if index == 0 && audit.phase != OperationalEffectPhase::Claimed {
                return Err(IdentityError::StorageCorruption);
            }
            if index > 0 && !valid_phase_transition(self.audit[index - 1].phase, audit.phase) {
                return Err(IdentityError::StorageCorruption);
            }
        }
        if self.audit.last().map(|audit| audit.phase) != Some(self.phase)
            || self.provider_receipts.len() > MAX_TRANSPARENCY_PROVIDERS
        {
            return Err(IdentityError::StorageCorruption);
        }
        let mut previous_provider = None;
        for retained in &self.provider_receipts {
            retained.validate()?;
            let provider_id = retained.provider.id()?;
            if previous_provider.is_some_and(|previous| previous >= provider_id) {
                return Err(IdentityError::StorageCorruption);
            }
            previous_provider = Some(provider_id);
        }
        match self.effect {
            ProjectionEffect::PublishAccountEvent { event_id } => {
                if self.rotation_epoch.is_some()
                    || self.checkpoint_body.as_ref().is_some_and(|body| {
                        body.account_id() != self.account_id || body.event_head() != event_id
                    })
                    || self.checkpoint.as_ref().is_some_and(|checkpoint| {
                        checkpoint.body().account_id() != self.account_id
                            || checkpoint.body().event_head() != event_id
                    })
                    || matches!(
                        self.phase,
                        OperationalEffectPhase::RotationCommitted
                            | OperationalEffectPhase::PeersNotified
                    )
                {
                    return Err(IdentityError::StorageCorruption);
                }
                if let (Some(body), Some(checkpoint)) = (&self.checkpoint_body, &self.checkpoint)
                    && checkpoint.body() != body
                {
                    return Err(IdentityError::StorageCorruption);
                }
                let evidence_phase = self.validate_publication_evidence()?;
                let sufficient = match self.phase {
                    OperationalEffectPhase::CheckpointDraft => self.checkpoint_body.is_some(),
                    OperationalEffectPhase::CheckpointAuthorized => self.checkpoint.is_some(),
                    OperationalEffectPhase::Published => {
                        evidence_phase >= PublicationStage::Published
                    }
                    OperationalEffectPhase::Replicated => {
                        evidence_phase >= PublicationStage::Replicated
                    }
                    OperationalEffectPhase::Observed => {
                        evidence_phase >= PublicationStage::Observed
                    }
                    OperationalEffectPhase::Completed => {
                        self.publish_completion_evidence_sufficient()?
                    }
                    OperationalEffectPhase::Claimed
                    | OperationalEffectPhase::RetryScheduled
                    | OperationalEffectPhase::TerminalFailure => true,
                    OperationalEffectPhase::RotationCommitted
                    | OperationalEffectPhase::PeersNotified => false,
                };
                if !sufficient {
                    return Err(IdentityError::StorageCorruption);
                }
            }
            ProjectionEffect::RotateGroupKeys { epoch, .. } => {
                if self.checkpoint_body.is_some()
                    || self.checkpoint.is_some()
                    || self.publication_policy.is_some()
                    || !self.provider_receipts.is_empty()
                    || self
                        .rotation_epoch
                        .is_some_and(|retained| retained != epoch)
                    || matches!(
                        self.phase,
                        OperationalEffectPhase::CheckpointDraft
                            | OperationalEffectPhase::CheckpointAuthorized
                            | OperationalEffectPhase::Published
                            | OperationalEffectPhase::Replicated
                            | OperationalEffectPhase::Observed
                            | OperationalEffectPhase::PeersNotified
                    )
                    || matches!(
                        self.phase,
                        OperationalEffectPhase::RotationCommitted
                            | OperationalEffectPhase::Completed
                    ) && self.rotation_epoch.is_none()
                {
                    return Err(IdentityError::StorageCorruption);
                }
            }
            ProjectionEffect::NotifyAccountChanged { .. }
            | ProjectionEffect::NotifyForkDetected { .. } => {
                if self.checkpoint_body.is_some()
                    || self.checkpoint.is_some()
                    || self.publication_policy.is_some()
                    || !self.provider_receipts.is_empty()
                    || self.rotation_epoch.is_some()
                    || matches!(
                        self.phase,
                        OperationalEffectPhase::CheckpointDraft
                            | OperationalEffectPhase::CheckpointAuthorized
                            | OperationalEffectPhase::Published
                            | OperationalEffectPhase::Replicated
                            | OperationalEffectPhase::Observed
                            | OperationalEffectPhase::RotationCommitted
                    )
                {
                    return Err(IdentityError::StorageCorruption);
                }
            }
        }
        Ok(())
    }

    fn validate_publication_evidence(&self) -> Result<PublicationStage, IdentityError> {
        let Some(policy) = &self.publication_policy else {
            if self.provider_receipts.is_empty() && self.checkpoint.is_none() {
                return Ok(PublicationStage::Draft);
            }
            return Err(IdentityError::StorageCorruption);
        };
        let checkpoint = self
            .checkpoint
            .as_ref()
            .ok_or(IdentityError::StorageCorruption)?;
        if policy.id()? != checkpoint.body().provider_policy_id() {
            return Err(IdentityError::StorageCorruption);
        }
        let ProviderMode::Replicated(replicated) = policy.mode() else {
            if self.provider_receipts.is_empty() {
                return Ok(PublicationStage::Authorized);
            }
            return Err(IdentityError::StorageCorruption);
        };
        for retained in &self.provider_receipts {
            let provider_id = retained.provider.id()?;
            let configured = replicated
                .providers()
                .iter()
                .find(|provider| provider.id() == Ok(provider_id))
                .ok_or(IdentityError::StorageCorruption)?;
            if configured != &retained.provider {
                return Err(IdentityError::StorageCorruption);
            }
        }
        let threshold = usize::from(replicated.sufficient_threshold().get());
        let observed = self
            .provider_receipts
            .iter()
            .filter(|retained| retained.observation.is_some())
            .count();
        Ok(if observed >= threshold {
            PublicationStage::Observed
        } else if self.provider_receipts.len() >= threshold {
            PublicationStage::Replicated
        } else if self.provider_receipts.is_empty() {
            PublicationStage::Authorized
        } else {
            PublicationStage::Published
        })
    }

    fn publish_completion_evidence_sufficient(&self) -> Result<bool, IdentityError> {
        let stage = self.validate_publication_evidence()?;
        let policy = self
            .publication_policy
            .as_ref()
            .ok_or(IdentityError::StorageCorruption)?;
        Ok(match policy.mode() {
            ProviderMode::LocalOnly => stage == PublicationStage::Authorized,
            ProviderMode::Replicated(_) => stage == PublicationStage::Observed,
        })
    }

    fn completion_prerequisite_satisfied(&self) -> Result<bool, IdentityError> {
        match self.effect {
            ProjectionEffect::PublishAccountEvent { .. } => {
                if self.checkpoint.is_none() || self.publication_policy.is_none() {
                    return Ok(false);
                }
                self.publish_completion_evidence_sufficient()
            }
            ProjectionEffect::RotateGroupKeys { .. } => {
                Ok(self.phase == OperationalEffectPhase::RotationCommitted)
            }
            ProjectionEffect::NotifyAccountChanged { .. }
            | ProjectionEffect::NotifyForkDetected { .. } => {
                Ok(self.phase == OperationalEffectPhase::PeersNotified)
            }
        }
    }

    fn resumable_phase(&self) -> Result<OperationalEffectPhase, IdentityError> {
        match self.effect {
            ProjectionEffect::PublishAccountEvent { .. } => {
                let stage = self.validate_publication_evidence()?;
                Ok(match stage {
                    PublicationStage::Observed => OperationalEffectPhase::Observed,
                    PublicationStage::Replicated => OperationalEffectPhase::Replicated,
                    PublicationStage::Published => OperationalEffectPhase::Published,
                    PublicationStage::Authorized => OperationalEffectPhase::CheckpointAuthorized,
                    PublicationStage::Draft if self.checkpoint_body.is_some() => {
                        OperationalEffectPhase::CheckpointDraft
                    }
                    PublicationStage::Draft => OperationalEffectPhase::Claimed,
                })
            }
            ProjectionEffect::RotateGroupKeys { .. } if self.rotation_epoch.is_some() => {
                Ok(OperationalEffectPhase::RotationCommitted)
            }
            ProjectionEffect::NotifyAccountChanged { .. }
            | ProjectionEffect::NotifyForkDetected { .. }
                if self
                    .audit
                    .iter()
                    .any(|audit| audit.phase == OperationalEffectPhase::PeersNotified) =>
            {
                Ok(OperationalEffectPhase::PeersNotified)
            }
            ProjectionEffect::RotateGroupKeys { .. }
            | ProjectionEffect::NotifyAccountChanged { .. }
            | ProjectionEffect::NotifyForkDetected { .. } => Ok(OperationalEffectPhase::Claimed),
        }
    }
}

const fn checkpoint_phase_rank(phase: OperationalEffectPhase) -> Option<u8> {
    match phase {
        OperationalEffectPhase::Claimed => Some(0),
        OperationalEffectPhase::CheckpointDraft => Some(1),
        OperationalEffectPhase::CheckpointAuthorized => Some(2),
        OperationalEffectPhase::Published => Some(3),
        OperationalEffectPhase::Replicated => Some(4),
        OperationalEffectPhase::Observed => Some(5),
        OperationalEffectPhase::Completed => Some(6),
        OperationalEffectPhase::RotationCommitted
        | OperationalEffectPhase::PeersNotified
        | OperationalEffectPhase::RetryScheduled
        | OperationalEffectPhase::TerminalFailure => None,
    }
}

fn retain_checkpoint_phase(
    current: OperationalEffectPhase,
    candidate: OperationalEffectPhase,
) -> OperationalEffectPhase {
    match (
        checkpoint_phase_rank(current),
        checkpoint_phase_rank(candidate),
    ) {
        (Some(current_rank), Some(candidate_rank)) if current_rank >= candidate_rank => current,
        _ => candidate,
    }
}

/// Atomic persistence contract for operational effect substeps.
pub trait OperationalEffectStore: Clone + Send + Sync {
    /// Load one stable effect journal, distinguishing absence from corruption.
    fn load(&self, effect_id: EffectId) -> Result<Option<OperationalEffectRecord>, IdentityError>;

    /// Create or replace one journal under an exact optional revision CAS.
    fn compare_and_store(
        &self,
        effect_id: EffectId,
        expected_revision: Option<u64>,
        next: OperationalEffectRecord,
    ) -> Result<(), IdentityError>;
}

/// In-memory atomic operational effect store.
#[derive(Debug, Clone, Default)]
pub struct MemoryOperationalEffectStore {
    records: Arc<Mutex<BTreeMap<EffectId, OperationalEffectRecord>>>,
}

impl MemoryOperationalEffectStore {
    /// Create an empty in-memory operational journal.
    pub fn new() -> Self {
        Self::default()
    }

    /// Aggregate private-safe operational counters without identifier labels.
    pub fn metrics(&self) -> Result<OperationalMetricsSnapshot, IdentityError> {
        let records = self.lock_records()?;
        Ok(OperationalMetricsSnapshot::from_records(records.values()))
    }

    fn lock_records(
        &self,
    ) -> Result<MutexGuard<'_, BTreeMap<EffectId, OperationalEffectRecord>>, IdentityError> {
        self.records
            .lock()
            .map_err(|_| IdentityError::StorageCorruption)
    }
}

impl OperationalEffectStore for MemoryOperationalEffectStore {
    fn load(&self, effect_id: EffectId) -> Result<Option<OperationalEffectRecord>, IdentityError> {
        let record = self.lock_records()?.get(&effect_id).cloned();
        if let Some(retained) = &record {
            retained.validate()?;
        }
        Ok(record)
    }

    fn compare_and_store(
        &self,
        effect_id: EffectId,
        expected_revision: Option<u64>,
        next: OperationalEffectRecord,
    ) -> Result<(), IdentityError> {
        next.validate()?;
        if next.effect_id != effect_id {
            return Err(IdentityError::InvalidRelationship {
                resource: "operational effect identifier",
            });
        }
        let mut records = self.lock_records()?;
        let retained_revision = records
            .get(&effect_id)
            .map(OperationalEffectRecord::revision);
        if retained_revision != expected_revision {
            return Err(IdentityError::StaleRevision);
        }
        records.insert(effect_id, next);
        Ok(())
    }
}

/// Runtime-independent coordinator for crash-reconcilable operational substeps.
#[derive(Debug, Clone)]
pub struct OperationalEffectJournal<S> {
    store: S,
}

impl<S: OperationalEffectStore> OperationalEffectJournal<S> {
    /// Attach the coordinator to one atomic journal implementation.
    pub const fn new(store: S) -> Self {
        Self { store }
    }

    /// Idempotently begin journaling one exclusively claimed Task 6 effect.
    pub fn begin(
        &self,
        effect: &EffectRecord,
        recorded_at: Timestamp,
    ) -> Result<OperationalEffectRecord, IdentityError> {
        if effect.status() != EffectStatus::Claimed {
            return Err(IdentityError::InvalidRelationship {
                resource: "operational effect claim lifecycle",
            });
        }
        let lease_id = effect
            .execution_lease_id()
            .ok_or(IdentityError::InvalidRelationship {
                resource: "operational effect claim lease",
            })?;
        for _ in 0..=MAX_RETRIES {
            let Some(mut retained) = self.store.load(effect.id())? else {
                let record = OperationalEffectRecord {
                    revision: 1,
                    effect_id: effect.id(),
                    account_id: effect.account_id(),
                    effect: effect.effect(),
                    lease_id,
                    phase: OperationalEffectPhase::Claimed,
                    checkpoint_body: None,
                    checkpoint: None,
                    publication_policy: None,
                    provider_receipts: Vec::new(),
                    rotation_epoch: None,
                    attempt_count: effect.attempt_count(),
                    last_failure: effect.last_failure(),
                    audit: vec![OperationalAuditRecord {
                        sequence: 1,
                        phase: OperationalEffectPhase::Claimed,
                        recorded_at,
                    }],
                };
                match self
                    .store
                    .compare_and_store(effect.id(), None, record.clone())
                {
                    Ok(()) => return Ok(record),
                    Err(IdentityError::StaleRevision) => continue,
                    Err(error) => return Err(error),
                }
            };
            if retained.account_id != effect.account_id() || retained.effect != effect.effect() {
                return Err(IdentityError::InvalidRelationship {
                    resource: "operational effect claimed retry",
                });
            }
            if retained.lease_id == lease_id {
                if retained.attempt_count != effect.attempt_count()
                    || retained.last_failure != effect.last_failure()
                {
                    return Err(IdentityError::InvalidRelationship {
                        resource: "operational effect claimed attempt",
                    });
                }
                return Ok(retained);
            }
            let expected_attempt =
                retained
                    .attempt_count
                    .checked_add(1)
                    .ok_or(IdentityError::ArithmeticOverflow {
                        resource: "operational effect attempt count",
                    })?;
            if effect.attempt_count() != expected_attempt
                || effect.last_failure() != retained.last_failure
                || matches!(
                    retained.phase,
                    OperationalEffectPhase::Completed | OperationalEffectPhase::TerminalFailure
                )
            {
                return Err(IdentityError::InvalidRelationship {
                    resource: "operational effect claimed retry",
                });
            }
            if retained.audit.len() == MAX_OPERATION_AUDIT_RECORDS {
                return Err(IdentityError::limit(
                    "operational effect audit records",
                    retained.audit.len().saturating_add(1),
                    MAX_OPERATION_AUDIT_RECORDS,
                ));
            }
            let expected_revision = retained.revision;
            let revision =
                expected_revision
                    .checked_add(1)
                    .ok_or(IdentityError::ArithmeticOverflow {
                        resource: "operational effect journal revision",
                    })?;
            let next_phase = if retained.phase == OperationalEffectPhase::RetryScheduled {
                retained.resumable_phase()?
            } else {
                retained.phase
            };
            retained.revision = revision;
            retained.lease_id = lease_id;
            retained.phase = next_phase;
            retained.attempt_count = effect.attempt_count();
            retained.last_failure = effect.last_failure();
            retained.audit.push(OperationalAuditRecord {
                sequence: revision,
                phase: next_phase,
                recorded_at,
            });
            match self.store.compare_and_store(
                effect.id(),
                Some(expected_revision),
                retained.clone(),
            ) {
                Ok(()) => return Ok(retained),
                Err(IdentityError::StaleRevision) => continue,
                Err(error) => return Err(error),
            }
        }
        Err(IdentityError::ResourceBusy)
    }

    /// Retain the deterministic checkpoint body before authorization or provider publication.
    pub fn record_checkpoint_draft(
        &self,
        effect_id: EffectId,
        body: CheckpointBody,
        recorded_at: Timestamp,
    ) -> Result<OperationalEffectRecord, IdentityError> {
        self.update(effect_id, recorded_at, |record| {
            let ProjectionEffect::PublishAccountEvent { event_id } = record.effect else {
                return Err(IdentityError::InvalidRelationship {
                    resource: "checkpoint draft effect kind",
                });
            };
            if body.account_id() != record.account_id || body.event_head() != event_id {
                return Err(IdentityError::InvalidRelationship {
                    resource: "checkpoint draft effect subject",
                });
            }
            if record
                .checkpoint_body
                .as_ref()
                .is_some_and(|retained| retained != &body)
            {
                return Err(IdentityError::InvalidProof);
            }
            record.checkpoint_body = Some(body.clone());
            Ok(retain_checkpoint_phase(
                record.phase,
                OperationalEffectPhase::CheckpointDraft,
            ))
        })
    }

    /// Retain one verified checkpoint before its revision-bound Task 6 store commit.
    pub fn record_checkpoint_authorized(
        &self,
        effect_id: EffectId,
        checkpoint: &VerifiedCheckpoint,
        provider_policy: &ProviderPolicy,
        recorded_at: Timestamp,
    ) -> Result<OperationalEffectRecord, IdentityError> {
        self.update(effect_id, recorded_at, |record| {
            let body = checkpoint.checkpoint().body();
            if record.checkpoint_body.as_ref() != Some(body) {
                return Err(IdentityError::InvalidRelationship {
                    resource: "authorized checkpoint draft",
                });
            }
            if provider_policy.id()? != body.provider_policy_id()
                || record
                    .publication_policy
                    .as_ref()
                    .is_some_and(|retained| retained != provider_policy)
            {
                return Err(IdentityError::PolicyVersionMismatch);
            }
            record.checkpoint = Some(match record.checkpoint.as_ref() {
                Some(retained) => retained.merge(checkpoint.checkpoint())?,
                None => checkpoint.checkpoint().clone(),
            });
            record.publication_policy = Some(provider_policy.clone());
            Ok(retain_checkpoint_phase(
                record.phase,
                OperationalEffectPhase::CheckpointAuthorized,
            ))
        })
    }

    /// Journal exact tracker-verified publication receipts without overstating threshold stage.
    pub fn record_publications(
        &self,
        effect_id: EffectId,
        tracker: &PublicationTracker,
        recorded_at: Timestamp,
    ) -> Result<OperationalEffectRecord, IdentityError> {
        self.update(effect_id, recorded_at, |record| {
            validate_tracker_subject(record, tracker)?;
            if record
                .publication_policy
                .as_ref()
                .is_some_and(|retained| retained != tracker.provider_policy())
            {
                return Err(IdentityError::PolicyVersionMismatch);
            }
            record.publication_policy = Some(tracker.provider_policy().clone());
            if tracker.stage() == PublicationStage::Draft {
                return Err(IdentityError::InvalidRelationship {
                    resource: "operational publication before authorization",
                });
            }
            for publication in tracker.publication_receipts() {
                let provider = tracker
                    .configured_providers()
                    .iter()
                    .find(|provider| provider.id() == Ok(publication.provider_id()))
                    .cloned()
                    .ok_or(IdentityError::StorageCorruption)?;
                let candidate = OperationalProviderReceipt {
                    provider,
                    publication: publication.clone(),
                    observation: None,
                };
                candidate.validate()?;
                if let Some(retained) = record
                    .provider_receipts
                    .iter()
                    .find(|retained| retained.provider.id() == candidate.provider.id())
                {
                    if retained.publication == candidate.publication {
                        continue;
                    }
                    if retained.publication.entry().log_id()
                        == candidate.publication.entry().log_id()
                        && retained.publication.signed_head().body().tree_size()
                            == candidate.publication.signed_head().body().tree_size()
                        && retained.publication.signed_head().body().tree_root()
                            != candidate.publication.signed_head().body().tree_root()
                    {
                        return Err(IdentityError::ProviderEquivocation);
                    }
                    // Re-publication at a later leaf is valid availability evidence, but the
                    // first durable baseline remains authoritative for later observations.
                    continue;
                }
                record.provider_receipts.push(candidate);
            }
            record
                .provider_receipts
                .sort_unstable_by_key(|retained| retained.provider.id().ok());
            let phase = match record.validate_publication_evidence()? {
                PublicationStage::Draft => OperationalEffectPhase::CheckpointDraft,
                PublicationStage::Authorized => OperationalEffectPhase::CheckpointAuthorized,
                PublicationStage::Published => OperationalEffectPhase::Published,
                PublicationStage::Replicated => OperationalEffectPhase::Replicated,
                PublicationStage::Observed => OperationalEffectPhase::Observed,
            };
            Ok(retain_checkpoint_phase(record.phase, phase))
        })
    }

    /// Journal one exact later observation and its consistency proof after tracker verification.
    pub fn record_observation(
        &self,
        effect_id: EffectId,
        tracker: &PublicationTracker,
        receipt: InclusionReceipt,
        proof: MerkleConsistencyProof,
        recorded_at: Timestamp,
    ) -> Result<OperationalEffectRecord, IdentityError> {
        self.update(effect_id, recorded_at, |record| {
            validate_tracker_subject(record, tracker)?;
            if record.publication_policy.as_ref() != Some(tracker.provider_policy()) {
                return Err(IdentityError::PolicyVersionMismatch);
            }
            if !tracker
                .observation_receipts()
                .iter()
                .any(|retained| retained == &receipt)
            {
                return Err(IdentityError::InvalidRelationship {
                    resource: "operational unverified observation",
                });
            }
            let retained = record
                .provider_receipts
                .iter_mut()
                .find(|retained| retained.provider.id() == Ok(receipt.provider_id()))
                .ok_or(IdentityError::InvalidRelationship {
                    resource: "operational observation before publication",
                })?;
            let candidate = OperationalProviderReceipt {
                provider: retained.provider.clone(),
                publication: retained.publication.clone(),
                observation: Some((receipt.clone(), proof.clone())),
            };
            candidate.validate()?;
            if let (Some(prior), Some(next)) = (&retained.observation, &candidate.observation)
                && prior != next
            {
                return Err(IdentityError::InvalidProof);
            }
            *retained = candidate;
            let phase = match record.validate_publication_evidence()? {
                PublicationStage::Draft | PublicationStage::Authorized => {
                    return Err(IdentityError::InvalidRelationship {
                        resource: "operational observation publication stage",
                    });
                }
                PublicationStage::Published => OperationalEffectPhase::Published,
                PublicationStage::Replicated => OperationalEffectPhase::Replicated,
                PublicationStage::Observed => OperationalEffectPhase::Observed,
            };
            Ok(retain_checkpoint_phase(record.phase, phase))
        })
    }

    /// Reconcile a revision-bound Task 6 group-key rotation completion.
    pub fn record_rotation_committed(
        &self,
        effect_id: EffectId,
        rotation: &StoredGroupKeyRotation,
        recorded_at: Timestamp,
    ) -> Result<OperationalEffectRecord, IdentityError> {
        self.update(effect_id, recorded_at, |record| {
            let ProjectionEffect::RotateGroupKeys { epoch, .. } = record.effect else {
                return Err(IdentityError::InvalidRelationship {
                    resource: "operational rotation effect kind",
                });
            };
            if rotation.account_id() != record.account_id
                || rotation.authorizing_account_epoch() != epoch
            {
                return Err(IdentityError::InvalidRelationship {
                    resource: "operational rotation effect subject",
                });
            }
            record.rotation_epoch = Some(epoch);
            Ok(OperationalEffectPhase::RotationCommitted)
        })
    }

    /// Retain completion of one idempotent peer-notification effect.
    pub fn record_peers_notified(
        &self,
        effect_id: EffectId,
        recorded_at: Timestamp,
    ) -> Result<OperationalEffectRecord, IdentityError> {
        self.update(effect_id, recorded_at, |record| match record.effect {
            ProjectionEffect::NotifyAccountChanged { .. }
            | ProjectionEffect::NotifyForkDetected { .. } => {
                Ok(OperationalEffectPhase::PeersNotified)
            }
            _ => Err(IdentityError::InvalidRelationship {
                resource: "operational notification effect kind",
            }),
        })
    }

    /// Reconcile Task 6 completion only after the effect-specific terminal prerequisite.
    pub fn record_completed(
        &self,
        effect_id: EffectId,
        recorded_at: Timestamp,
    ) -> Result<OperationalEffectRecord, IdentityError> {
        self.update(effect_id, recorded_at, |record| {
            let ready = record.completion_prerequisite_satisfied()?;
            if !ready && record.phase != OperationalEffectPhase::Completed {
                return Err(IdentityError::InvalidRelationship {
                    resource: "operational completion prerequisite",
                });
            }
            Ok(OperationalEffectPhase::Completed)
        })
    }

    /// Retain a retryable or permanent failure without changing prior publication evidence.
    pub fn record_failure(
        &self,
        effect_id: EffectId,
        attempt_count: u8,
        failure: EffectFailure,
        recorded_at: Timestamp,
    ) -> Result<OperationalEffectRecord, IdentityError> {
        self.update(effect_id, recorded_at, |record| {
            if attempt_count == 0 || attempt_count > MAX_RETRIES {
                return Err(IdentityError::limit(
                    "operational effect attempts",
                    usize::from(attempt_count),
                    usize::from(MAX_RETRIES),
                ));
            }
            if attempt_count != record.attempt_count {
                return Err(IdentityError::InvalidRelationship {
                    resource: "operational failure attempt",
                });
            }
            record.attempt_count = attempt_count;
            record.last_failure = Some(failure);
            Ok(match failure {
                EffectFailure::Transient(_) if attempt_count < MAX_RETRIES => {
                    OperationalEffectPhase::RetryScheduled
                }
                EffectFailure::Transient(_) | EffectFailure::Permanent(_) => {
                    OperationalEffectPhase::TerminalFailure
                }
            })
        })
    }

    /// Load one durable operational record.
    pub fn load(
        &self,
        effect_id: EffectId,
    ) -> Result<Option<OperationalEffectRecord>, IdentityError> {
        self.store.load(effect_id)
    }

    fn update(
        &self,
        effect_id: EffectId,
        recorded_at: Timestamp,
        mut update: impl FnMut(
            &mut OperationalEffectRecord,
        ) -> Result<OperationalEffectPhase, IdentityError>,
    ) -> Result<OperationalEffectRecord, IdentityError> {
        for _ in 0..=MAX_RETRIES {
            let mut record =
                self.store
                    .load(effect_id)?
                    .ok_or(IdentityError::InvalidRelationship {
                        resource: "operational effect journal",
                    })?;
            let original = record.clone();
            let expected_revision = record.revision;
            let next_phase = update(&mut record)?;
            if record == original && original.phase == next_phase {
                return Ok(original);
            }
            if !valid_phase_transition(original.phase, next_phase) {
                return Err(IdentityError::InvalidRelationship {
                    resource: "operational effect phase transition",
                });
            }
            if record.audit.len() == MAX_OPERATION_AUDIT_RECORDS {
                return Err(IdentityError::limit(
                    "operational effect audit records",
                    record.audit.len().saturating_add(1),
                    MAX_OPERATION_AUDIT_RECORDS,
                ));
            }
            let revision =
                expected_revision
                    .checked_add(1)
                    .ok_or(IdentityError::ArithmeticOverflow {
                        resource: "operational effect journal revision",
                    })?;
            record.revision = revision;
            record.phase = next_phase;
            record.audit.push(OperationalAuditRecord {
                sequence: revision,
                phase: next_phase,
                recorded_at,
            });
            match self
                .store
                .compare_and_store(effect_id, Some(expected_revision), record.clone())
            {
                Ok(()) => return Ok(record),
                Err(IdentityError::StaleRevision) => continue,
                Err(error) => return Err(error),
            }
        }
        Err(IdentityError::ResourceBusy)
    }
}

/// External signing boundary for the exact deterministic checkpoint body built by the driver.
pub trait OperationalCheckpointAuthorizer: Send + Sync {
    /// Authorize the exact supplied body without rebuilding or mutating it.
    fn authorize<'a>(&'a self, body: &'a CheckpointBody) -> StoreFuture<'a, SignedCheckpoint>;
}

/// External deterministic group-key rotation boundary.
pub trait OperationalGroupKeyRotator: Send + Sync {
    /// Produce the exact revision-bound rotation artifact for one claimed effect.
    fn rotate<'a>(
        &'a self,
        effect: &'a EffectRecord,
        snapshot: &'a AccountSnapshot,
    ) -> StoreFuture<'a, GroupKeyRotation>;
}

/// External idempotent peer-notification boundary.
pub trait OperationalPeerNotifier: Send + Sync {
    /// Notify peers of the exact claimed effect; implementations own bounded transport deadlines.
    fn notify<'a>(&'a self, effect: &'a EffectRecord) -> StoreFuture<'a, ()>;
}

/// Verified checkpoint plus its revision-bound durable store commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalCheckpointCommit {
    checkpoint: VerifiedCheckpoint,
    receipt: CheckpointCommitReceipt,
}

impl OperationalCheckpointCommit {
    /// Opaque checkpoint reverified against the exact account projection.
    pub const fn checkpoint(&self) -> &VerifiedCheckpoint {
        &self.checkpoint
    }

    /// Atomic Task 6 checkpoint-journal commit receipt.
    pub const fn receipt(&self) -> &CheckpointCommitReceipt {
        &self.receipt
    }
}

/// Exact deterministic inputs for checkpoint build, authorization, and store reconciliation.
#[derive(Debug, Clone, Copy)]
pub struct OperationalCheckpointBuild<'a> {
    effect_id: EffectId,
    snapshot: &'a AccountSnapshot,
    issued_at: Timestamp,
    transition_event: Option<&'a AuthorizedEvent>,
    draft_recorded_at: Timestamp,
    authorized_recorded_at: Timestamp,
}

impl<'a> OperationalCheckpointBuild<'a> {
    /// Bind all checkpoint substeps to one exact Task 6 effect and account revision.
    pub const fn new(
        effect_id: EffectId,
        snapshot: &'a AccountSnapshot,
        issued_at: Timestamp,
        transition_event: Option<&'a AuthorizedEvent>,
        draft_recorded_at: Timestamp,
        authorized_recorded_at: Timestamp,
    ) -> Self {
        Self {
            effect_id,
            snapshot,
            issued_at,
            transition_event,
            draft_recorded_at,
            authorized_recorded_at,
        }
    }
}

/// Build, journal, authorize, verify, and revision-bind one checkpoint idempotently.
pub async fn build_authorize_and_commit_checkpoint<A, J, H>(
    account_store: &A,
    journal: &OperationalEffectJournal<J>,
    authorizer: &H,
    build: OperationalCheckpointBuild<'_>,
) -> Result<OperationalCheckpointCommit, IdentityError>
where
    A: AccountStore + ?Sized,
    J: OperationalEffectStore,
    H: OperationalCheckpointAuthorizer + ?Sized,
{
    let body = build_checkpoint_body(build.snapshot.state(), build.issued_at)?;
    journal.record_checkpoint_draft(build.effect_id, body.clone(), build.draft_recorded_at)?;
    let retained = journal.load(build.effect_id)?;
    let verified = if let Some(checkpoint) =
        retained.and_then(|record| record.checkpoint().cloned())
    {
        verify_checkpoint(build.snapshot.state(), &checkpoint, build.transition_event)?
    } else {
        let signed = authorizer.authorize(&body).await?;
        let verified = verify_checkpoint(build.snapshot.state(), &signed, build.transition_event)?;
        let record = journal.record_checkpoint_authorized(
            build.effect_id,
            &verified,
            build.snapshot.state().provider_policy(),
            build.authorized_recorded_at,
        )?;
        let checkpoint = record
            .checkpoint()
            .ok_or(IdentityError::StorageCorruption)?;
        verify_checkpoint(build.snapshot.state(), checkpoint, build.transition_event)?
    };
    let receipt = account_store
        .commit_checkpoint(build.snapshot.revision().clone(), verified.clone())
        .await?;
    let committed = receipt
        .snapshot()
        .checkpoints()
        .iter()
        .find(|checkpoint| {
            checkpoint
                .checkpoint_id()
                .is_ok_and(|id| id == verified.checkpoint_id())
        })
        .ok_or(IdentityError::StorageCorruption)?;
    let committed = verify_checkpoint(build.snapshot.state(), committed, build.transition_event)?;
    let record = journal.record_checkpoint_authorized(
        build.effect_id,
        &committed,
        build.snapshot.state().provider_policy(),
        build.authorized_recorded_at,
    )?;
    let checkpoint = record
        .checkpoint()
        .ok_or(IdentityError::StorageCorruption)?;
    let verified = verify_checkpoint(build.snapshot.state(), checkpoint, build.transition_event)?;
    Ok(OperationalCheckpointCommit {
        checkpoint: verified,
        receipt,
    })
}

/// Publish concurrently, then journal only the exact tracker-verified receipts and honest stage.
pub async fn publish_and_journal_checkpoint<J>(
    journal: &OperationalEffectJournal<J>,
    effect_id: EffectId,
    tracker: &mut PublicationTracker,
    checkpoint: &ProviderCheckpointBundle,
    clients: &[&dyn TransparencyClient],
    recorded_at: Timestamp,
) -> Result<PublicationBatch, IdentityError>
where
    J: OperationalEffectStore,
{
    let batch = publish_checkpoint_concurrently(tracker, checkpoint, clients).await?;
    journal.record_publications(effect_id, tracker, recorded_at)?;
    Ok(batch)
}

/// Produce and atomically commit a revision-bound group rotation, then reconcile its journal.
pub async fn rotate_and_journal_group_keys<A, J, R>(
    account_store: &A,
    journal: &OperationalEffectJournal<J>,
    effect: &EffectRecord,
    snapshot: &AccountSnapshot,
    rotator: &R,
    completed_at: Timestamp,
) -> Result<StoredGroupKeyRotation, IdentityError>
where
    A: AccountStore + ?Sized,
    J: OperationalEffectStore,
    R: OperationalGroupKeyRotator + ?Sized,
{
    let lease_id = effect
        .execution_lease_id()
        .ok_or(IdentityError::InvalidRelationship {
            resource: "operational rotation lease",
        })?;
    let rotation = rotator.rotate(effect, snapshot).await?;
    let stored = account_store
        .commit_group_key_rotation(effect.id(), lease_id, rotation, completed_at)
        .await?;
    journal.record_rotation_committed(effect.id(), &stored, completed_at)?;
    journal.record_completed(effect.id(), completed_at)?;
    Ok(stored)
}

/// Notify peers, complete Task 6 idempotently, and reconcile the terminal journal record.
pub async fn notify_and_complete_effect<A, J, N>(
    account_store: &A,
    journal: &OperationalEffectJournal<J>,
    effect: &EffectRecord,
    notifier: &N,
    completed_at: Timestamp,
) -> Result<(), IdentityError>
where
    A: AccountStore + ?Sized,
    J: OperationalEffectStore,
    N: OperationalPeerNotifier + ?Sized,
{
    let lease_id = effect
        .execution_lease_id()
        .ok_or(IdentityError::InvalidRelationship {
            resource: "operational notification lease",
        })?;
    notifier.notify(effect).await?;
    journal.record_peers_notified(effect.id(), completed_at)?;
    account_store
        .complete_effect(effect.account_id(), effect.id(), lease_id, completed_at)
        .await?;
    journal.record_completed(effect.id(), completed_at)?;
    Ok(())
}

/// Complete any phase-ready Task 6 effect and reconcile the journal after crashes.
pub async fn complete_ready_effect<A, J>(
    account_store: &A,
    journal: &OperationalEffectJournal<J>,
    effect: &EffectRecord,
    completed_at: Timestamp,
) -> Result<(), IdentityError>
where
    A: AccountStore + ?Sized,
    J: OperationalEffectStore,
{
    let operational = journal
        .load(effect.id())?
        .ok_or(IdentityError::InvalidRelationship {
            resource: "operational completion journal",
        })?;
    let lease_id = effect
        .execution_lease_id()
        .ok_or(IdentityError::InvalidRelationship {
            resource: "operational completion lease",
        })?;
    if operational.account_id != effect.account_id()
        || operational.effect != effect.effect()
        || operational.lease_id != lease_id
    {
        return Err(IdentityError::InvalidRelationship {
            resource: "operational completion effect",
        });
    }
    if !operational.completion_prerequisite_satisfied()? {
        return Err(IdentityError::InvalidRelationship {
            resource: "operational completion prerequisite",
        });
    }
    account_store
        .complete_effect(effect.account_id(), effect.id(), lease_id, completed_at)
        .await?;
    journal.record_completed(effect.id(), completed_at)?;
    Ok(())
}

/// Aggregate-only operational counters safe for metric labels and dashboards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OperationalMetricsSnapshot {
    pending: u64,
    completed: u64,
    retry_scheduled: u64,
    terminal_failures: u64,
    publication_shortfalls: u64,
}

impl OperationalMetricsSnapshot {
    /// Effects not yet terminal.
    pub const fn pending(self) -> u64 {
        self.pending
    }

    /// Successfully reconciled effects.
    pub const fn completed(self) -> u64 {
        self.completed
    }

    /// Effects awaiting a bounded retry.
    pub const fn retry_scheduled(self) -> u64 {
        self.retry_scheduled
    }

    /// Effects retained for terminal operator action.
    pub const fn terminal_failures(self) -> u64 {
        self.terminal_failures
    }

    /// Authorized or partially published checkpoints below observation completion.
    pub const fn publication_shortfalls(self) -> u64 {
        self.publication_shortfalls
    }

    fn from_records<'a>(records: impl Iterator<Item = &'a OperationalEffectRecord>) -> Self {
        let mut metrics = Self::default();
        for record in records {
            match record.phase {
                OperationalEffectPhase::Completed => metrics.completed += 1,
                OperationalEffectPhase::RetryScheduled => {
                    metrics.pending += 1;
                    metrics.retry_scheduled += 1;
                }
                OperationalEffectPhase::TerminalFailure => metrics.terminal_failures += 1,
                OperationalEffectPhase::CheckpointAuthorized => {
                    metrics.pending += 1;
                    if !record
                        .publication_policy
                        .as_ref()
                        .is_some_and(|policy| matches!(policy.mode(), ProviderMode::LocalOnly))
                    {
                        metrics.publication_shortfalls += 1;
                    }
                }
                OperationalEffectPhase::Published | OperationalEffectPhase::Replicated => {
                    metrics.pending += 1;
                    metrics.publication_shortfalls += 1;
                }
                _ => metrics.pending += 1,
            }
        }
        metrics
    }
}

fn validate_tracker_subject(
    record: &OperationalEffectRecord,
    tracker: &PublicationTracker,
) -> Result<(), IdentityError> {
    let checkpoint = record
        .checkpoint
        .as_ref()
        .ok_or(IdentityError::InvalidRelationship {
            resource: "operational publication checkpoint",
        })?;
    if tracker.account_id() != record.account_id
        || tracker.checkpoint_id() != checkpoint.checkpoint_id()?
        || tracker.provider_policy_id() != checkpoint.body().provider_policy_id()
        || tracker.provider_policy().id()? != tracker.provider_policy_id()
    {
        return Err(IdentityError::InvalidRelationship {
            resource: "operational publication tracker subject",
        });
    }
    for receipt in tracker.publication_receipts() {
        if receipt.entry().account_id() != record.account_id
            || receipt.entry().subject() != ProviderLogSubject::Checkpoint(tracker.checkpoint_id())
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "operational publication receipt subject",
            });
        }
    }
    Ok(())
}
