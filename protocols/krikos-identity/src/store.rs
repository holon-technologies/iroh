//! Atomic identity source-record persistence and durable effect contracts.

#[cfg(feature = "fs-store")]
mod redb;

use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
};

#[cfg(feature = "fs-store")]
pub use redb::RedbAccountStore;
use serde::Serialize;

use crate::{
    AccountGenesis, AccountId, AccountRevision, AccountState, ApplicationId, ApplyDisposition,
    ApplyOutcome, AuthorizedEvent, CanonicalWire, CheckpointId, Epoch, EventAuthorizationId,
    EventId, GroupId, GroupKeyEpoch, GroupKeyRotation, IdentityError, ProjectionEffect,
    ProjectionLifecycle, RecipientKeyWraps, Sequence, SignedCheckpoint, Timestamp,
    VerifiedCheckpoint,
    limits::{
        IDENTITY_QUEUE_CAPACITY, MAX_HISTORY_PAGE_BYTES, MAX_HISTORY_PAGE_EVENTS, MAX_RETRIES,
    },
};

pub(crate) const MAX_STORED_CHECKPOINTS: usize = 65_536;

/// Owned future returned by store contracts without imposing an async runtime.
pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, IdentityError>> + Send + 'a>>;

/// Canonical evidence that multiple valid bodies share an account pre-state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkEvidenceRecord {
    sequence: Sequence,
    heads: Vec<EventId>,
}

/// Stable identifier of one deterministic projection effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EffectId([u8; 32]);

impl EffectId {
    /// Exact domain-separated effect digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[cfg(feature = "provider-store")]
    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Caller-generated nonzero identifier for one exclusive effect lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LeaseId([u8; 16]);

impl LeaseId {
    /// Validate a nonzero, unpredictable lease identifier.
    pub fn new(bytes: [u8; 16]) -> Result<Self, IdentityError> {
        if bytes == [0; 16] {
            return Err(IdentityError::ZeroValue {
                resource: "effect lease identifier",
            });
        }
        Ok(Self(bytes))
    }

    /// Exact lease bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Typed executor failure retained in the durable outbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectFailure {
    /// A retryable executor or dependency failure.
    Transient(u16),
    /// A non-retryable effect failure retained for operator action.
    Permanent(u16),
}

impl EffectFailure {
    /// Construct a retryable nonzero stable failure code.
    pub fn transient(code: u16) -> Result<Self, IdentityError> {
        if code == 0 {
            return Err(IdentityError::ZeroValue {
                resource: "effect failure code",
            });
        }
        Ok(Self::Transient(code))
    }

    /// Construct a terminal nonzero stable failure code.
    pub fn permanent(code: u16) -> Result<Self, IdentityError> {
        if code == 0 {
            return Err(IdentityError::ZeroValue {
                resource: "effect failure code",
            });
        }
        Ok(Self::Permanent(code))
    }
}

/// Explicit bounded request to claim ready or lease-expired effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimEffects {
    now: Timestamp,
    leased_until: Timestamp,
    lease_id: LeaseId,
    limit: usize,
}

impl ClaimEffects {
    /// Validate a claim request without consulting wall-clock time.
    pub fn new(
        now: Timestamp,
        leased_until: Timestamp,
        lease_id: LeaseId,
        limit: usize,
    ) -> Result<Self, IdentityError> {
        if leased_until <= now {
            return Err(IdentityError::InvalidRelationship {
                resource: "effect lease time range",
            });
        }
        if limit == 0 || limit > IDENTITY_QUEUE_CAPACITY {
            return Err(IdentityError::limit(
                "effect claim batch",
                limit,
                IDENTITY_QUEUE_CAPACITY,
            ));
        }
        Ok(Self {
            now,
            leased_until,
            lease_id,
            limit,
        })
    }

    /// Explicit claim-evaluation time.
    pub const fn now(self) -> Timestamp {
        self.now
    }

    /// Exclusive lease expiry.
    pub const fn leased_until(self) -> Timestamp {
        self.leased_until
    }

    /// Idempotency and ownership token for this claim.
    pub const fn lease_id(self) -> LeaseId {
        self.lease_id
    }

    /// Maximum effects returned by this claim.
    pub const fn limit(self) -> usize {
        self.limit
    }
}

/// Durable outer lifecycle of one effect-outbox record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectStatus {
    /// Ready to be claimed at its explicit retry time.
    Pending,
    /// Exclusively leased to one effect executor.
    Claimed,
    /// Successfully completed and retained for audit/idempotency.
    Completed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingEffect {
    Scheduled(Timestamp),
    Exhausted(Timestamp),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EffectState {
    Pending(PendingEffect),
    Claimed {
        lease_id: LeaseId,
        leased_until: Timestamp,
    },
    Completed {
        lease_id: LeaseId,
        completed_at: Timestamp,
    },
}

/// Durable idempotently keyed projection effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectRecord {
    id: EffectId,
    account_id: AccountId,
    effect: ProjectionEffect,
    state: EffectState,
    attempt_count: u8,
    last_failure: Option<EffectFailure>,
}

/// Persisted public portion of one successfully committed group-key rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredGroupKeyRotation {
    account_id: AccountId,
    application_id: ApplicationId,
    group_id: GroupId,
    authorizing_account_epoch: Epoch,
    group_key_epoch: GroupKeyEpoch,
    revision_heads: Vec<EventId>,
    recipient_key_wraps: RecipientKeyWraps,
}

impl StoredGroupKeyRotation {
    /// Account owning the group.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Application owning the group.
    pub const fn application_id(&self) -> ApplicationId {
        self.application_id
    }

    /// Application-defined group.
    pub const fn group_id(&self) -> GroupId {
        self.group_id
    }

    /// Account epoch used to select recipients.
    pub const fn authorizing_account_epoch(&self) -> Epoch {
        self.authorizing_account_epoch
    }

    /// Persisted application group-key epoch.
    pub const fn group_key_epoch(&self) -> GroupKeyEpoch {
        self.group_key_epoch
    }

    /// Exact account revision heads revalidated at commit time.
    pub fn revision_heads(&self) -> &[EventId] {
        &self.revision_heads
    }

    /// Complete canonical recipient wraps.
    pub const fn recipient_key_wraps(&self) -> &RecipientKeyWraps {
        &self.recipient_key_wraps
    }
}

impl EffectRecord {
    /// Stable body-derived effect identifier.
    pub const fn id(&self) -> EffectId {
        self.id
    }

    /// Account whose deterministic transition requested this effect.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Exact deterministic work description.
    pub const fn effect(&self) -> ProjectionEffect {
        self.effect
    }

    /// Current durable lifecycle.
    pub const fn status(&self) -> EffectStatus {
        match self.state {
            EffectState::Pending(_) => EffectStatus::Pending,
            EffectState::Claimed { .. } => EffectStatus::Claimed,
            EffectState::Completed { .. } => EffectStatus::Completed,
        }
    }

    /// Number of exclusive executions attempted so far.
    pub const fn attempt_count(&self) -> u8 {
        self.attempt_count
    }

    /// Most recent typed executor failure, if any.
    pub const fn last_failure(&self) -> Option<EffectFailure> {
        self.last_failure
    }

    /// Whether the bounded retry budget has been exhausted.
    pub const fn retry_exhausted(&self) -> bool {
        matches!(
            self.state,
            EffectState::Pending(PendingEffect::Exhausted(_))
        )
    }

    /// Lease that owns the current claimed or completed execution, when applicable.
    pub const fn execution_lease_id(&self) -> Option<LeaseId> {
        match self.state {
            EffectState::Claimed { lease_id, .. } | EffectState::Completed { lease_id, .. } => {
                Some(lease_id)
            }
            EffectState::Pending(_) => None,
        }
    }
}

impl ForkEvidenceRecord {
    /// Conflicting sequence represented by this record.
    pub const fn sequence(&self) -> Sequence {
        self.sequence
    }

    /// Complete sorted conflicting head set.
    pub fn heads(&self) -> &[EventId] {
        &self.heads
    }
}

/// Authenticated account source records plus their reconstructed current projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSnapshot {
    genesis: AccountGenesis,
    state: AccountState,
    revision: AccountRevision,
    events: Vec<AuthorizedEvent>,
    checkpoints: Vec<SignedCheckpoint>,
    fork_evidence: Vec<ForkEvidenceRecord>,
    outbox: Vec<EffectRecord>,
    group_key_rotations: Vec<StoredGroupKeyRotation>,
    checkpoint_count: u64,
}

/// One bounded checkpoint-journal record in durable insertion order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckpointJournalRecord {
    cursor: u64,
    checkpoint_id: CheckpointId,
    checkpoint: SignedCheckpoint,
    transition_event: Option<AuthorizedEvent>,
}

impl CheckpointJournalRecord {
    /// Stable insertion cursor for bounded history continuation.
    pub const fn cursor(&self) -> u64 {
        self.cursor
    }

    /// Stable body-only checkpoint identifier.
    pub const fn checkpoint_id(&self) -> CheckpointId {
        self.checkpoint_id
    }

    /// Canonical signed checkpoint envelope.
    pub const fn checkpoint(&self) -> &SignedCheckpoint {
        &self.checkpoint
    }

    /// Retained destructive transition required by transition-derived authorization.
    pub const fn transition_event(&self) -> Option<&AuthorizedEvent> {
        self.transition_event.as_ref()
    }
}

/// Bounded page of authenticated durable checkpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointJournalPage {
    records: Vec<CheckpointJournalRecord>,
    next_cursor: Option<u64>,
}

impl CheckpointJournalPage {
    /// Authenticated checkpoint records in durable insertion order.
    pub fn records(&self) -> &[CheckpointJournalRecord] {
        &self.records
    }

    /// Exclusive journal cursor for the next bounded request.
    pub const fn next_cursor(&self) -> Option<u64> {
        self.next_cursor
    }
}

/// One canonical account event at its stable position in a frozen source revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EventHistoryRecord {
    cursor: u64,
    event: AuthorizedEvent,
}

impl EventHistoryRecord {
    /// Zero-based position in the deterministic history of the frozen revision.
    pub const fn cursor(&self) -> u64 {
        self.cursor
    }

    /// Canonical event envelope, with all durably retained compatible approvals merged.
    pub const fn event(&self) -> &AuthorizedEvent {
        &self.event
    }
}

/// Bounded page of authenticated events from one exact complete source-head set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventHistoryPage {
    source_revision: AccountRevision,
    records: Vec<EventHistoryRecord>,
    next_cursor: Option<EventHistoryCursor>,
}

impl EventHistoryPage {
    /// Exact account and complete sorted heads that freeze this history view.
    pub const fn source_revision(&self) -> &AccountRevision {
        &self.source_revision
    }

    /// Deterministically ordered authenticated event records.
    pub fn records(&self) -> &[EventHistoryRecord] {
        &self.records
    }

    /// Opaque continuation bound to this exact frozen revision and deterministic ordering.
    pub const fn next_cursor(&self) -> Option<&EventHistoryCursor> {
        self.next_cursor.as_ref()
    }
}

/// Opaque event-history continuation bound to one exact frozen source revision.
///
/// Public callers can retain and replay a cursor returned by [`EventHistoryPage`], but cannot
/// construct or alter its position. Network sync may reconstruct it only after verifying the
/// keyed [`crate::SyncCursor`] that authenticates the same revision and position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventHistoryCursor {
    source_revision: AccountRevision,
    position: u64,
}

impl EventHistoryCursor {
    pub(crate) const fn from_verified_sync(
        source_revision: AccountRevision,
        position: u64,
    ) -> Self {
        Self {
            source_revision,
            position,
        }
    }

    /// Exact account and complete sorted heads to which this cursor is bound.
    pub const fn source_revision(&self) -> &AccountRevision {
        &self.source_revision
    }

    /// Stable zero-based position last delivered from the frozen history.
    pub const fn position(&self) -> u64 {
        self.position
    }
}

/// Result of one revision-bound idempotent checkpoint commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointCommitReceipt {
    checkpoint_id: CheckpointId,
    snapshot: AccountSnapshot,
}

impl CheckpointCommitReceipt {
    /// Stable body-only checkpoint identifier committed by this transaction.
    pub const fn checkpoint_id(&self) -> CheckpointId {
        self.checkpoint_id
    }

    /// Complete post-transaction account snapshot with a bounded recent checkpoint view.
    pub const fn snapshot(&self) -> &AccountSnapshot {
        &self.snapshot
    }
}

impl AccountSnapshot {
    /// Canonical account genesis source record.
    pub const fn genesis(&self) -> &AccountGenesis {
        &self.genesis
    }

    /// Projection reconstructed from authenticated source records.
    pub const fn state(&self) -> &AccountState {
        &self.state
    }

    /// Exact complete revision token of the reconstructed projection.
    pub fn revision(&self) -> &AccountRevision {
        &self.revision
    }

    /// Canonical retained event envelopes in deterministic replay order.
    pub fn events(&self) -> &[AuthorizedEvent] {
        &self.events
    }

    /// Most recent bounded canonical signed checkpoints.
    pub fn checkpoints(&self) -> &[SignedCheckpoint] {
        &self.checkpoints
    }

    /// Total number of durable checkpoints available through bounded journal pagination.
    pub const fn checkpoint_count(&self) -> u64 {
        self.checkpoint_count
    }

    /// Derived bounded evidence for every unresolved fork.
    pub fn fork_evidence(&self) -> &[ForkEvidenceRecord] {
        &self.fork_evidence
    }

    /// Complete stable effect outbox, including completed audit records.
    pub fn outbox(&self) -> &[EffectRecord] {
        &self.outbox
    }

    /// Latest committed rotation for every protected application group.
    pub fn group_key_rotations(&self) -> &[StoredGroupKeyRotation] {
        &self.group_key_rotations
    }
}

/// Result of one atomic event/source/effect commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitReceipt {
    outcome: ApplyOutcome,
    snapshot: AccountSnapshot,
}

/// Result of one atomic bounded multi-event reconciliation commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchCommitReceipt {
    outcomes: Vec<ApplyOutcome>,
    snapshot: AccountSnapshot,
}

impl BatchCommitReceipt {
    /// One pure projection result for every supplied envelope after deterministic ordering.
    pub fn outcomes(&self) -> &[ApplyOutcome] {
        &self.outcomes
    }

    /// Complete post-transaction account snapshot.
    pub const fn snapshot(&self) -> &AccountSnapshot {
        &self.snapshot
    }
}

impl CommitReceipt {
    /// Pure projection disposition and generated effects.
    pub const fn outcome(&self) -> &ApplyOutcome {
        &self.outcome
    }

    /// Complete post-transaction account snapshot.
    pub const fn snapshot(&self) -> &AccountSnapshot {
        &self.snapshot
    }
}

#[derive(Debug, Clone)]
struct StoredAccount {
    genesis: AccountGenesis,
    events: BTreeMap<EventAuthorizationId, AuthorizedEvent>,
    event_journal: Vec<EventId>,
    outbox: BTreeMap<EffectId, EffectRecord>,
    group_key_rotations: BTreeMap<(ApplicationId, GroupId), StoredGroupKeyRotation>,
    checkpoints: BTreeMap<CheckpointId, StoredCheckpoint>,
    checkpoint_journal: Vec<CheckpointId>,
    projection: AccountState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredCheckpoint {
    pub(crate) checkpoint: SignedCheckpoint,
    pub(crate) transition_event: Option<AuthorizedEvent>,
}

impl StoredAccount {
    fn snapshot(&self) -> Result<AccountSnapshot, IdentityError> {
        let state = self.projection.clone();
        if state.account_id() != self.genesis.account_id()? {
            return Err(IdentityError::StorageCorruption);
        }
        let ordered_events = self.events_in_journal_order()?;
        let revision = state.revision_token();
        let fork_evidence = if state.lifecycle() == ProjectionLifecycle::Forked {
            vec![ForkEvidenceRecord {
                sequence: state.sequence(),
                heads: state.heads().to_vec(),
            }]
        } else {
            Vec::new()
        };
        if self.checkpoints.len() != self.checkpoint_journal.len()
            || self.checkpoints.len() > MAX_STORED_CHECKPOINTS
        {
            return Err(IdentityError::StorageCorruption);
        }
        let recent_start = self
            .checkpoint_journal
            .len()
            .saturating_sub(MAX_HISTORY_PAGE_EVENTS);
        let checkpoints = self.checkpoint_journal[recent_start..]
            .iter()
            .map(|checkpoint_id| {
                self.checkpoints
                    .get(checkpoint_id)
                    .map(|record| record.checkpoint.clone())
                    .ok_or(IdentityError::StorageCorruption)
            })
            .collect::<Result<Vec<_>, IdentityError>>()?;
        let checkpoint_count = u64::try_from(self.checkpoint_journal.len()).map_err(|_| {
            IdentityError::ArithmeticOverflow {
                resource: "checkpoint journal count",
            }
        })?;
        Ok(AccountSnapshot {
            genesis: self.genesis.clone(),
            state,
            revision,
            events: ordered_events,
            checkpoints,
            fork_evidence,
            outbox: self.outbox.values().cloned().collect(),
            group_key_rotations: self.group_key_rotations.values().cloned().collect(),
            checkpoint_count,
        })
    }

    #[cfg(feature = "fs-store")]
    fn rebuild_projection_and_effects(
        &self,
    ) -> Result<(AccountState, BTreeMap<EffectId, ProjectionEffect>), IdentityError> {
        let mut state = AccountState::from_genesis(&self.genesis)?;
        let account_id = state.account_id();
        let mut required_effects = BTreeMap::new();
        let ordered_events = self.events_in_journal_order()?;
        for event in &ordered_events {
            let outcome = match state.validate_and_apply(event) {
                Ok(outcome) => outcome,
                Err(IdentityError::HistoricalStateRequired { .. }) => self
                    .apply_authenticated_historical_conflict(&mut state, event)
                    .map_err(|_| IdentityError::StorageCorruption)?,
                Err(_) => return Err(IdentityError::StorageCorruption),
            };
            for effect in outcome.effects() {
                let id = derive_effect_id(account_id, *effect)?;
                if required_effects.insert(id, *effect).is_some() {
                    return Err(IdentityError::StorageCorruption);
                }
            }
        }
        Ok((state, required_effects))
    }

    fn events_in_journal_order(&self) -> Result<Vec<AuthorizedEvent>, IdentityError> {
        let mut seen = std::collections::BTreeSet::new();
        let mut ordered = Vec::with_capacity(self.events.len());
        for event_id in &self.event_journal {
            if !seen.insert(*event_id) {
                return Err(IdentityError::StorageCorruption);
            }
            let mut envelopes = self
                .events
                .values()
                .filter_map(|event| match event.event_id() {
                    Ok(candidate) if candidate == *event_id => Some(
                        event
                            .event_authorization_id()
                            .map(|authorization_id| (authorization_id, event.clone())),
                    ),
                    Ok(_) => None,
                    Err(error) => Some(Err(error)),
                })
                .collect::<Result<Vec<_>, IdentityError>>()?;
            if envelopes.is_empty() {
                return Err(IdentityError::StorageCorruption);
            }
            envelopes.sort_unstable_by_key(|(authorization_id, _)| *authorization_id);
            ordered.extend(envelopes.into_iter().map(|(_, event)| event));
        }
        if ordered.len() != self.events.len() {
            return Err(IdentityError::StorageCorruption);
        }
        Ok(ordered)
    }

    fn insert_event(&mut self, event: AuthorizedEvent) -> Result<(), IdentityError> {
        let event_id = event.event_id()?;
        let authorization_id = event.event_authorization_id()?;
        if self.events.contains_key(&authorization_id) {
            return Ok(());
        }
        if !self
            .events
            .values()
            .any(|retained| retained.event_id() == Ok(event_id))
        {
            self.event_journal.push(event_id);
        }
        self.events.insert(authorization_id, event);
        Ok(())
    }

    fn apply_authenticated_historical_conflict(
        &self,
        state: &mut AccountState,
        incoming: &AuthorizedEvent,
    ) -> Result<ApplyOutcome, IdentityError> {
        let current_ancestors = self.ancestor_closure(state.heads())?;
        let incoming_id = incoming.event_id()?;
        let mut accepted = self
            .events
            .values()
            .filter_map(|candidate| {
                let candidate_id = candidate.event_id().ok()?;
                (candidate_id != incoming_id
                    && current_ancestors.contains(&candidate_id)
                    && candidate.body().sequence() == incoming.body().sequence()
                    && candidate.body().predecessors() == incoming.body().predecessors())
                .then_some((candidate_id, candidate))
            })
            .collect::<Vec<_>>();
        accepted.sort_unstable_by_key(|(event_id, _)| *event_id);
        let (accepted_id, _) = accepted
            .first()
            .copied()
            .ok_or(IdentityError::StorageCorruption)?;
        let accepted_path = self.authenticated_linear_path(state.heads(), accepted_id)?;
        let historical_pre_state = self.reconstruct_pre_state(incoming)?;
        state.validate_and_apply_historical_conflict(
            &historical_pre_state,
            &accepted_path,
            incoming,
        )
    }

    fn authenticated_linear_path(
        &self,
        current_heads: &[EventId],
        accepted_id: EventId,
    ) -> Result<Vec<AuthorizedEvent>, IdentityError> {
        let [current_head] = current_heads else {
            return Err(IdentityError::StorageCorruption);
        };
        let mut cursor = *current_head;
        let mut reversed = Vec::new();
        loop {
            if reversed.len() >= self.event_journal.len() {
                return Err(IdentityError::StorageCorruption);
            }
            let event = self.canonical_envelope(cursor)?;
            reversed.push(event.clone());
            if cursor == accepted_id {
                break;
            }
            let [predecessor] = event
                .body()
                .predecessors()
                .event_heads()
                .ok_or(IdentityError::StorageCorruption)?
            else {
                return Err(IdentityError::StorageCorruption);
            };
            cursor = *predecessor;
        }
        reversed.reverse();
        Ok(reversed)
    }

    fn reconstruct_pre_state(
        &self,
        incoming: &AuthorizedEvent,
    ) -> Result<AccountState, IdentityError> {
        if let Some(anchor) = incoming.body().predecessors().genesis_anchor() {
            if anchor != self.genesis.genesis_anchor()? {
                return Err(IdentityError::StorageCorruption);
            }
            return AccountState::from_genesis(&self.genesis);
        }
        let heads = incoming
            .body()
            .predecessors()
            .event_heads()
            .ok_or(IdentityError::StorageCorruption)?;
        let closure = self.ancestor_closure(heads)?;
        let mut bodies = closure
            .iter()
            .map(|event_id| {
                let event = self.canonical_envelope(*event_id)?;
                Ok((event.body().sequence(), *event_id, event))
            })
            .collect::<Result<Vec<_>, IdentityError>>()?;
        bodies.sort_unstable_by_key(|(sequence, event_id, _)| (*sequence, *event_id));
        let mut state = AccountState::from_genesis(&self.genesis)?;
        for (_, _, event) in bodies {
            state
                .validate_and_apply(event)
                .map_err(|_| IdentityError::StorageCorruption)?;
        }
        if state.heads() != heads {
            return Err(IdentityError::StorageCorruption);
        }
        Ok(state)
    }

    fn ancestor_closure(
        &self,
        heads: &[EventId],
    ) -> Result<std::collections::BTreeSet<EventId>, IdentityError> {
        let mut closure = std::collections::BTreeSet::new();
        let mut pending = heads.to_vec();
        while let Some(event_id) = pending.pop() {
            if !closure.insert(event_id) {
                continue;
            }
            if closure.len() > self.event_journal.len() {
                return Err(IdentityError::StorageCorruption);
            }
            let event = self.canonical_envelope(event_id)?;
            if let Some(predecessors) = event.body().predecessors().event_heads() {
                pending.extend_from_slice(predecessors);
            } else if event.body().predecessors().genesis_anchor()
                != Some(self.genesis.genesis_anchor()?)
            {
                return Err(IdentityError::StorageCorruption);
            }
        }
        Ok(closure)
    }

    fn canonical_envelope(&self, event_id: EventId) -> Result<&AuthorizedEvent, IdentityError> {
        self.events
            .iter()
            .filter_map(|(authorization_id, event)| {
                (event.event_id() == Ok(event_id)).then_some((*authorization_id, event))
            })
            .min_by_key(|(authorization_id, _)| *authorization_id)
            .map(|(_, event)| event)
            .ok_or(IdentityError::StorageCorruption)
    }

    #[cfg(feature = "fs-store")]
    fn state_at_event_head(&self, event_head: EventId) -> Result<AccountState, IdentityError> {
        let closure = self.ancestor_closure(&[event_head])?;
        let mut events = closure
            .iter()
            .map(|event_id| {
                let event = self.canonical_envelope(*event_id)?;
                Ok((event.body().sequence(), *event_id, event))
            })
            .collect::<Result<Vec<_>, IdentityError>>()?;
        events.sort_unstable_by_key(|(sequence, event_id, _)| (*sequence, *event_id));
        let mut state = AccountState::from_genesis(&self.genesis)?;
        for (_, _, event) in events {
            state
                .validate_and_apply(event)
                .map_err(|_| IdentityError::StorageCorruption)?;
        }
        if state.heads() != [event_head] {
            return Err(IdentityError::StorageCorruption);
        }
        Ok(state)
    }

    #[cfg(feature = "fs-store")]
    fn validate_checkpoint_journal(&self) -> Result<(), IdentityError> {
        if self.checkpoints.len() != self.checkpoint_journal.len()
            || self.checkpoints.len() > MAX_STORED_CHECKPOINTS
        {
            return Err(IdentityError::StorageCorruption);
        }
        let mut seen = std::collections::BTreeSet::new();
        for checkpoint_id in &self.checkpoint_journal {
            if !seen.insert(*checkpoint_id) {
                return Err(IdentityError::StorageCorruption);
            }
            let retained = self
                .checkpoints
                .get(checkpoint_id)
                .ok_or(IdentityError::StorageCorruption)?;
            if retained.checkpoint.checkpoint_id()? != *checkpoint_id {
                return Err(IdentityError::StorageCorruption);
            }
            let state = self.state_at_event_head(retained.checkpoint.body().event_head())?;
            let verified = crate::verify_checkpoint(
                &state,
                &retained.checkpoint,
                retained.transition_event.as_ref(),
            )
            .map_err(|_| IdentityError::StorageCorruption)?;
            if verified.checkpoint() != &retained.checkpoint
                || verified.transition_event() != retained.transition_event.as_ref()
            {
                return Err(IdentityError::StorageCorruption);
            }
        }
        Ok(())
    }

    fn commit_checkpoint(
        &mut self,
        expected_revision: &AccountRevision,
        checkpoint: VerifiedCheckpoint,
    ) -> Result<CheckpointCommitReceipt, IdentityError> {
        let current = self.projection.revision_token();
        if &current != expected_revision {
            return Err(IdentityError::StaleRevision);
        }
        if checkpoint.checkpoint().body().account_id() != self.projection.account_id() {
            return Err(IdentityError::AccountMismatch);
        }
        let reverified = crate::verify_checkpoint(
            &self.projection,
            checkpoint.checkpoint(),
            checkpoint.transition_event(),
        )?;
        if reverified != checkpoint {
            return Err(IdentityError::InvalidProof);
        }
        let checkpoint_id = checkpoint.checkpoint_id();
        let retained = StoredCheckpoint {
            checkpoint: checkpoint.checkpoint().clone(),
            transition_event: checkpoint.transition_event().cloned(),
        };
        if let Some(existing) = self.checkpoints.get_mut(&checkpoint_id) {
            if existing.transition_event != retained.transition_event {
                return Err(IdentityError::InvalidRelationship {
                    resource: "checkpoint transition witness",
                });
            }
            let merged = existing.checkpoint.merge(&retained.checkpoint)?;
            let reverified = crate::verify_checkpoint(
                &self.projection,
                &merged,
                existing.transition_event.as_ref(),
            )?;
            if reverified.checkpoint() != &merged
                || reverified.transition_event() != existing.transition_event.as_ref()
            {
                return Err(IdentityError::InvalidProof);
            }
            existing.checkpoint = merged;
            return Ok(CheckpointCommitReceipt {
                checkpoint_id,
                snapshot: self.snapshot()?,
            });
        }
        if self.checkpoints.len() == MAX_STORED_CHECKPOINTS {
            return Err(IdentityError::limit(
                "stored checkpoint journal",
                self.checkpoints.len().saturating_add(1),
                MAX_STORED_CHECKPOINTS,
            ));
        }
        self.checkpoints.insert(checkpoint_id, retained);
        self.checkpoint_journal.push(checkpoint_id);
        Ok(CheckpointCommitReceipt {
            checkpoint_id,
            snapshot: self.snapshot()?,
        })
    }

    fn checkpoint_history(
        &self,
        after_cursor: Option<u64>,
        maximum_records: usize,
        maximum_bytes: usize,
    ) -> Result<CheckpointJournalPage, IdentityError> {
        if maximum_records == 0 || maximum_records > MAX_HISTORY_PAGE_EVENTS {
            return Err(IdentityError::limit(
                "checkpoint history records",
                maximum_records,
                MAX_HISTORY_PAGE_EVENTS,
            ));
        }
        if maximum_bytes == 0 || maximum_bytes > MAX_HISTORY_PAGE_BYTES {
            return Err(IdentityError::limit(
                "checkpoint history bytes",
                maximum_bytes,
                MAX_HISTORY_PAGE_BYTES,
            ));
        }
        let start = match after_cursor {
            None => 0,
            Some(cursor) => usize::try_from(cursor)
                .map_err(|_| IdentityError::ArithmeticOverflow {
                    resource: "checkpoint history cursor",
                })?
                .checked_add(1)
                .ok_or(IdentityError::ArithmeticOverflow {
                    resource: "checkpoint history cursor",
                })?,
        };
        if start > self.checkpoint_journal.len() {
            return Err(IdentityError::InvalidRelationship {
                resource: "checkpoint history cursor",
            });
        }
        let mut records = Vec::new();
        let mut next_cursor = None;
        for (index, checkpoint_id) in self.checkpoint_journal.iter().enumerate().skip(start) {
            if records.len() == maximum_records {
                next_cursor = records.last().map(CheckpointJournalRecord::cursor);
                break;
            }
            let retained = self
                .checkpoints
                .get(checkpoint_id)
                .ok_or(IdentityError::StorageCorruption)?;
            let cursor = u64::try_from(index).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "checkpoint history cursor",
            })?;
            records.push(CheckpointJournalRecord {
                cursor,
                checkpoint_id: *checkpoint_id,
                checkpoint: retained.checkpoint.clone(),
                transition_event: retained.transition_event.clone(),
            });
            let encoded = crate::codec::encode_wire(&(records.as_slice(), Some(cursor)))?;
            if encoded.len() > maximum_bytes {
                records.pop();
                if records.is_empty() {
                    return Err(IdentityError::limit(
                        "checkpoint history bytes",
                        encoded.len(),
                        maximum_bytes,
                    ));
                }
                next_cursor = records.last().map(CheckpointJournalRecord::cursor);
                break;
            }
        }
        Ok(CheckpointJournalPage {
            records,
            next_cursor,
        })
    }

    fn event_history(
        &self,
        source_revision: &AccountRevision,
        after_cursor: Option<EventHistoryCursor>,
        maximum_records: usize,
        maximum_bytes: usize,
    ) -> Result<EventHistoryPage, IdentityError> {
        if source_revision.account_id() != self.genesis.account_id()? {
            return Err(IdentityError::AccountMismatch);
        }
        if maximum_records == 0 || maximum_records > MAX_HISTORY_PAGE_EVENTS {
            return Err(IdentityError::limit(
                "account event-history records",
                maximum_records,
                MAX_HISTORY_PAGE_EVENTS,
            ));
        }
        if maximum_bytes == 0 || maximum_bytes > MAX_HISTORY_PAGE_BYTES {
            return Err(IdentityError::limit(
                "account event-history bytes",
                maximum_bytes,
                MAX_HISTORY_PAGE_BYTES,
            ));
        }

        for head in source_revision.heads() {
            if !self
                .events
                .values()
                .any(|event| event.event_id() == Ok(*head))
            {
                return Err(IdentityError::InvalidRelationship {
                    resource: "account event-history source revision",
                });
            }
        }
        let closure = self.ancestor_closure(source_revision.heads())?;
        let mut by_event_id = BTreeMap::<EventId, AuthorizedEvent>::new();
        for event in self.events.values() {
            let event_id = event.event_id()?;
            if !closure.contains(&event_id) {
                continue;
            }
            match by_event_id.entry(event_id) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(event.clone());
                }
                std::collections::btree_map::Entry::Occupied(mut slot) => {
                    let retained = slot.get();
                    if retained.body() != event.body()
                        || retained.admission_evidence() != event.admission_evidence()
                    {
                        return Err(IdentityError::StorageCorruption);
                    }
                    let approvals = retained.approvals().merge(event.approvals())?;
                    let merged = AuthorizedEvent::new(
                        retained.body().clone(),
                        retained.admission_evidence().clone(),
                        approvals,
                    )?;
                    slot.insert(merged);
                }
            }
        }
        if by_event_id.len() != closure.len() {
            return Err(IdentityError::StorageCorruption);
        }
        let mut events = by_event_id.into_iter().collect::<Vec<_>>();
        events.sort_unstable_by_key(|(event_id, event)| (event.body().sequence(), *event_id));

        let start = match after_cursor {
            None => 0,
            Some(cursor) => {
                if cursor.source_revision != *source_revision {
                    return Err(IdentityError::InvalidRelationship {
                        resource: "account event-history cursor revision",
                    });
                }
                usize::try_from(cursor.position)
                    .map_err(|_| IdentityError::ArithmeticOverflow {
                        resource: "account event-history cursor",
                    })?
                    .checked_add(1)
                    .ok_or(IdentityError::ArithmeticOverflow {
                        resource: "account event-history cursor",
                    })?
            }
        };
        if start > events.len() {
            return Err(IdentityError::InvalidRelationship {
                resource: "account event-history cursor",
            });
        }

        let mut records = Vec::<EventHistoryRecord>::new();
        let mut next_cursor = None::<EventHistoryCursor>;
        for (index, (_, event)) in events.into_iter().enumerate().skip(start) {
            if records.len() == maximum_records {
                next_cursor = records.last().map(|record| {
                    EventHistoryCursor::from_verified_sync(source_revision.clone(), record.cursor())
                });
                break;
            }
            let cursor = u64::try_from(index).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "account event-history cursor",
            })?;
            records.push(EventHistoryRecord { cursor, event });
            let encoded = crate::codec::encode_wire(&(
                source_revision.account_id(),
                source_revision.heads(),
                records.as_slice(),
                Some(cursor),
            ))?;
            if encoded.len() > maximum_bytes {
                records.pop();
                if records.is_empty() {
                    return Err(IdentityError::limit(
                        "account event-history bytes",
                        encoded.len(),
                        maximum_bytes,
                    ));
                }
                next_cursor = records.last().map(|record| {
                    EventHistoryCursor::from_verified_sync(source_revision.clone(), record.cursor())
                });
                break;
            }
        }
        Ok(EventHistoryPage {
            source_revision: source_revision.clone(),
            records,
            next_cursor,
        })
    }

    fn commit_event(
        &mut self,
        expected_revision: &AccountRevision,
        event: AuthorizedEvent,
    ) -> Result<CommitReceipt, IdentityError> {
        let account_id = expected_revision.account_id();
        if event.body().account_id() != account_id {
            return Err(IdentityError::AccountMismatch);
        }
        let current_snapshot = self.snapshot()?;
        let revision_matches = current_snapshot.revision() == expected_revision;
        let mut staged_state = current_snapshot.state().clone();
        let outcome = match staged_state.validate_and_apply(&event) {
            Ok(outcome) => outcome,
            Err(IdentityError::HistoricalStateRequired { .. }) => {
                self.apply_authenticated_historical_conflict(&mut staged_state, &event)?
            }
            Err(error) => return Err(error),
        };
        if !revision_matches
            && !matches!(
                outcome.disposition(),
                ApplyDisposition::Replay
                    | ApplyDisposition::ApprovalsMerged
                    | ApplyDisposition::ForkDetected
            )
        {
            return Err(IdentityError::StaleRevision);
        }
        self.insert_event(event)?;
        insert_effects(&mut self.outbox, account_id, outcome.effects())?;
        self.projection = staged_state.clone();
        let snapshot = self.snapshot()?;
        if snapshot.revision() != &staged_state.revision_token() {
            return Err(IdentityError::StorageCorruption);
        }
        Ok(CommitReceipt { outcome, snapshot })
    }

    fn commit_events(
        &mut self,
        expected_revision: &AccountRevision,
        events: Vec<AuthorizedEvent>,
    ) -> Result<BatchCommitReceipt, IdentityError> {
        if events.len() > crate::limits::MAX_EVENTS_PER_SYNC_BATCH {
            return Err(IdentityError::limit(
                "atomic event batch",
                events.len(),
                crate::limits::MAX_EVENTS_PER_SYNC_BATCH,
            ));
        }
        let account_id = expected_revision.account_id();
        let ordered_events = canonical_event_order(events)?;
        let current_snapshot = self.snapshot()?;
        if current_snapshot.revision() != expected_revision {
            return Err(IdentityError::StaleRevision);
        }
        let mut staged_state = current_snapshot.state().clone();
        let mut outcomes = Vec::with_capacity(ordered_events.len());
        for event in ordered_events {
            if event.body().account_id() != account_id {
                return Err(IdentityError::AccountMismatch);
            }
            let outcome = match staged_state.validate_and_apply(&event) {
                Ok(outcome) => outcome,
                Err(IdentityError::HistoricalStateRequired { .. }) => {
                    self.apply_authenticated_historical_conflict(&mut staged_state, &event)?
                }
                Err(error) => return Err(error),
            };
            self.insert_event(event)?;
            insert_effects(&mut self.outbox, account_id, outcome.effects())?;
            outcomes.push(outcome);
        }
        self.projection = staged_state.clone();
        let snapshot = self.snapshot()?;
        if snapshot.revision() != &staged_state.revision_token() {
            return Err(IdentityError::StorageCorruption);
        }
        Ok(BatchCommitReceipt { outcomes, snapshot })
    }

    fn claim_effects(&mut self, request: ClaimEffects) -> Result<Vec<EffectRecord>, IdentityError> {
        let already_claimed = self
            .outbox
            .values()
            .filter(|record| {
                matches!(
                    record.state,
                    EffectState::Claimed { lease_id, .. } if lease_id == request.lease_id
                )
            })
            .take(request.limit)
            .cloned()
            .collect::<Vec<_>>();
        if !already_claimed.is_empty() {
            return Ok(already_claimed);
        }

        let mut claimed = Vec::with_capacity(request.limit);
        for record in self.outbox.values_mut() {
            if claimed.len() == request.limit {
                break;
            }
            let eligible = match record.state {
                EffectState::Pending(PendingEffect::Scheduled(retry_at)) => retry_at <= request.now,
                EffectState::Claimed { leased_until, .. } => leased_until <= request.now,
                EffectState::Pending(PendingEffect::Exhausted(_))
                | EffectState::Completed { .. } => false,
            };
            if !eligible {
                continue;
            }
            if record.attempt_count >= MAX_RETRIES {
                record.state = EffectState::Pending(PendingEffect::Exhausted(request.now));
                continue;
            }
            record.attempt_count =
                record
                    .attempt_count
                    .checked_add(1)
                    .ok_or(IdentityError::ArithmeticOverflow {
                        resource: "effect attempt count",
                    })?;
            record.state = EffectState::Claimed {
                lease_id: request.lease_id,
                leased_until: request.leased_until,
            };
            claimed.push(record.clone());
        }
        Ok(claimed)
    }

    fn complete_effect(
        &mut self,
        effect_id: EffectId,
        lease_id: LeaseId,
        completed_at: Timestamp,
    ) -> Result<(), IdentityError> {
        let record = self
            .outbox
            .get_mut(&effect_id)
            .ok_or(IdentityError::InvalidRelationship {
                resource: "unknown effect record",
            })?;
        match record.state {
            EffectState::Claimed {
                lease_id: owner, ..
            } if owner == lease_id => {
                record.state = EffectState::Completed {
                    lease_id,
                    completed_at,
                };
                Ok(())
            }
            EffectState::Completed {
                lease_id: owner, ..
            } if owner == lease_id => Ok(()),
            EffectState::Pending(_)
            | EffectState::Claimed { .. }
            | EffectState::Completed { .. } => Err(IdentityError::InvalidRelationship {
                resource: "effect completion lease ownership",
            }),
        }
    }

    fn retry_effect(
        &mut self,
        effect_id: EffectId,
        lease_id: LeaseId,
        retry_at: Timestamp,
        failure: EffectFailure,
    ) -> Result<bool, IdentityError> {
        let record = self
            .outbox
            .get_mut(&effect_id)
            .ok_or(IdentityError::InvalidRelationship {
                resource: "unknown effect record",
            })?;
        let EffectState::Claimed {
            lease_id: owner, ..
        } = record.state
        else {
            return Err(IdentityError::InvalidRelationship {
                resource: "effect retry lifecycle",
            });
        };
        if owner != lease_id {
            return Err(IdentityError::InvalidRelationship {
                resource: "effect retry lease ownership",
            });
        }
        record.last_failure = Some(failure);
        let exhausted =
            record.attempt_count >= MAX_RETRIES || matches!(failure, EffectFailure::Permanent(_));
        record.state = if exhausted {
            EffectState::Pending(PendingEffect::Exhausted(retry_at))
        } else {
            EffectState::Pending(PendingEffect::Scheduled(retry_at))
        };
        Ok(exhausted)
    }

    fn commit_group_key_rotation(
        &mut self,
        effect_id: EffectId,
        lease_id: LeaseId,
        rotation: GroupKeyRotation,
        completed_at: Timestamp,
    ) -> Result<StoredGroupKeyRotation, IdentityError> {
        rotation.validate_current_revision(&self.projection)?;
        let effect = self
            .outbox
            .get(&effect_id)
            .ok_or(IdentityError::InvalidRelationship {
                resource: "group rotation effect",
            })?;
        let ProjectionEffect::RotateGroupKeys { epoch, .. } = effect.effect else {
            return Err(IdentityError::InvalidRelationship {
                resource: "group rotation effect kind",
            });
        };
        if epoch != rotation.authorizing_account_epoch() {
            return Err(IdentityError::InvalidEpoch);
        }
        match effect.state {
            EffectState::Claimed {
                lease_id: owner, ..
            }
            | EffectState::Completed {
                lease_id: owner, ..
            } if owner == lease_id => {}
            _ => {
                return Err(IdentityError::InvalidRelationship {
                    resource: "group rotation effect lease",
                });
            }
        }
        let record = StoredGroupKeyRotation {
            account_id: rotation.account_id(),
            application_id: rotation.application_id(),
            group_id: rotation.group_id(),
            authorizing_account_epoch: rotation.authorizing_account_epoch(),
            group_key_epoch: rotation.group_key_epoch(),
            revision_heads: rotation.account_revision().heads().to_vec(),
            recipient_key_wraps: rotation.recipient_key_wraps().clone(),
        };
        let key = (record.application_id, record.group_id);
        if let Some(previous) = self.group_key_rotations.get(&key) {
            if previous == &record {
                let previous = previous.clone();
                self.complete_effect(effect_id, lease_id, completed_at)?;
                return Ok(previous);
            }
            if previous.group_key_epoch >= record.group_key_epoch {
                return Err(IdentityError::StaleRevision);
            }
        }
        self.group_key_rotations.insert(key, record.clone());
        self.complete_effect(effect_id, lease_id, completed_at)?;
        Ok(record)
    }

    fn authorize_protected_write(
        &self,
        expected_revision: &AccountRevision,
        application_id: ApplicationId,
        group_id: GroupId,
    ) -> Result<(), IdentityError> {
        if &self.projection.revision_token() != expected_revision {
            return Err(IdentityError::StaleRevision);
        }
        let current_epoch = self.projection.epoch();
        let mut rotation_required = false;
        for effect in self.outbox.values() {
            if let ProjectionEffect::RotateGroupKeys { epoch, .. } = effect.effect
                && epoch == current_epoch
            {
                rotation_required = true;
                if effect.status() != EffectStatus::Completed {
                    return Err(IdentityError::ProtectedWritesBlocked);
                }
            }
        }
        if !rotation_required {
            return Ok(());
        }
        let rotation = self
            .group_key_rotations
            .get(&(application_id, group_id))
            .ok_or(IdentityError::ProtectedWritesBlocked)?;
        if rotation.authorizing_account_epoch != current_epoch {
            return Err(IdentityError::ProtectedWritesBlocked);
        }
        Ok(())
    }
}

/// Async-capable atomic account source-record store.
pub trait AccountStore: Send + Sync {
    /// Create a previously absent account from canonical genesis.
    fn create_account(&self, genesis: AccountGenesis) -> StoreFuture<'_, AccountSnapshot>;

    /// Load an account, distinguishing absence from authenticated-storage corruption.
    fn load_account(&self, account_id: AccountId) -> StoreFuture<'_, Option<AccountSnapshot>>;

    /// Validate and atomically commit one event under an exact complete revision CAS.
    fn commit_event(
        &self,
        expected_revision: AccountRevision,
        event: AuthorizedEvent,
    ) -> StoreFuture<'_, CommitReceipt>;

    /// Atomically validate and commit a bounded set of reordered or duplicate event envelopes.
    fn commit_events(
        &self,
        expected_revision: AccountRevision,
        events: Vec<AuthorizedEvent>,
    ) -> StoreFuture<'_, BatchCommitReceipt>;

    /// Verify and atomically retain one checkpoint under the exact current account revision.
    fn commit_checkpoint(
        &self,
        expected_revision: AccountRevision,
        checkpoint: VerifiedCheckpoint,
    ) -> StoreFuture<'_, CheckpointCommitReceipt>;

    /// Return one bounded authenticated page from the durable checkpoint journal.
    fn checkpoint_history(
        &self,
        account_id: AccountId,
        after_cursor: Option<u64>,
        maximum_records: usize,
        maximum_bytes: usize,
    ) -> StoreFuture<'_, CheckpointJournalPage>;

    /// Return one bounded deterministic event page frozen to an exact complete source revision.
    fn event_history(
        &self,
        source_revision: AccountRevision,
        after_cursor: Option<EventHistoryCursor>,
        maximum_records: usize,
        maximum_bytes: usize,
    ) -> StoreFuture<'_, EventHistoryPage>;

    /// Atomically claim a bounded batch of ready or expired effects.
    fn claim_effects(
        &self,
        account_id: AccountId,
        request: ClaimEffects,
    ) -> StoreFuture<'_, Vec<EffectRecord>>;

    /// Mark a claimed effect completed, idempotently under the same lease.
    fn complete_effect(
        &self,
        account_id: AccountId,
        effect_id: EffectId,
        lease_id: LeaseId,
        completed_at: Timestamp,
    ) -> StoreFuture<'_, ()>;

    /// Return a claimed effect to an explicit retry time and retain its typed failure.
    fn retry_effect(
        &self,
        account_id: AccountId,
        effect_id: EffectId,
        lease_id: LeaseId,
        retry_at: Timestamp,
        failure: EffectFailure,
    ) -> StoreFuture<'_, ()>;

    /// Persist one revision-bound rotation and complete its claimed mandatory effect atomically.
    fn commit_group_key_rotation(
        &self,
        effect_id: EffectId,
        lease_id: LeaseId,
        rotation: GroupKeyRotation,
        completed_at: Timestamp,
    ) -> StoreFuture<'_, StoredGroupKeyRotation>;

    /// Gate a protected write on the exact revision and completed current-epoch rotation.
    fn authorize_protected_write(
        &self,
        expected_revision: AccountRevision,
        application_id: ApplicationId,
        group_id: GroupId,
    ) -> StoreFuture<'_, ()>;
}

/// In-memory atomic store used by local-only deployments and conformance tests.
#[derive(Debug, Clone, Default)]
pub struct MemoryAccountStore {
    accounts: Arc<Mutex<BTreeMap<AccountId, StoredAccount>>>,
}

impl MemoryAccountStore {
    /// Create an empty in-memory account store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock_accounts(
        &self,
    ) -> Result<MutexGuard<'_, BTreeMap<AccountId, StoredAccount>>, IdentityError> {
        self.accounts
            .lock()
            .map_err(|_| IdentityError::StorageCorruption)
    }
}

impl AccountStore for MemoryAccountStore {
    fn create_account(&self, genesis: AccountGenesis) -> StoreFuture<'_, AccountSnapshot> {
        Box::pin(async move {
            let account_id = genesis.account_id()?;
            let mut accounts = self.lock_accounts()?;
            if accounts.contains_key(&account_id) {
                return Err(IdentityError::InvalidRelationship {
                    resource: "account store duplicate genesis",
                });
            }
            let stored = StoredAccount {
                projection: AccountState::from_genesis(&genesis)?,
                genesis,
                events: BTreeMap::new(),
                event_journal: Vec::new(),
                outbox: BTreeMap::new(),
                group_key_rotations: BTreeMap::new(),
                checkpoints: BTreeMap::new(),
                checkpoint_journal: Vec::new(),
            };
            let snapshot = stored.snapshot()?;
            accounts.insert(account_id, stored);
            Ok(snapshot)
        })
    }

    fn load_account(&self, account_id: AccountId) -> StoreFuture<'_, Option<AccountSnapshot>> {
        Box::pin(async move {
            let accounts = self.lock_accounts()?;
            accounts
                .get(&account_id)
                .map(StoredAccount::snapshot)
                .transpose()
        })
    }

    fn commit_event(
        &self,
        expected_revision: AccountRevision,
        event: AuthorizedEvent,
    ) -> StoreFuture<'_, CommitReceipt> {
        Box::pin(async move {
            let account_id = expected_revision.account_id();
            let mut accounts = self.lock_accounts()?;
            let current = accounts
                .get(&account_id)
                .ok_or(IdentityError::InvalidRelationship {
                    resource: "account store missing account",
                })?;
            let mut staged = current.clone();
            let receipt = staged.commit_event(&expected_revision, event)?;
            accounts.insert(account_id, staged);
            Ok(receipt)
        })
    }

    fn commit_events(
        &self,
        expected_revision: AccountRevision,
        events: Vec<AuthorizedEvent>,
    ) -> StoreFuture<'_, BatchCommitReceipt> {
        Box::pin(async move {
            let account_id = expected_revision.account_id();
            let mut accounts = self.lock_accounts()?;
            let current = accounts
                .get(&account_id)
                .ok_or(IdentityError::InvalidRelationship {
                    resource: "account store missing account",
                })?;
            let mut staged = current.clone();
            let receipt = staged.commit_events(&expected_revision, events)?;
            accounts.insert(account_id, staged);
            Ok(receipt)
        })
    }

    fn commit_checkpoint(
        &self,
        expected_revision: AccountRevision,
        checkpoint: VerifiedCheckpoint,
    ) -> StoreFuture<'_, CheckpointCommitReceipt> {
        Box::pin(async move {
            let account_id = expected_revision.account_id();
            let mut accounts = self.lock_accounts()?;
            let account =
                accounts
                    .get_mut(&account_id)
                    .ok_or(IdentityError::InvalidRelationship {
                        resource: "account store missing account",
                    })?;
            let mut staged = account.clone();
            let receipt = staged.commit_checkpoint(&expected_revision, checkpoint)?;
            *account = staged;
            Ok(receipt)
        })
    }

    fn checkpoint_history(
        &self,
        account_id: AccountId,
        after_cursor: Option<u64>,
        maximum_records: usize,
        maximum_bytes: usize,
    ) -> StoreFuture<'_, CheckpointJournalPage> {
        Box::pin(async move {
            let accounts = self.lock_accounts()?;
            let account = accounts
                .get(&account_id)
                .ok_or(IdentityError::InvalidRelationship {
                    resource: "account store missing account",
                })?;
            account.checkpoint_history(after_cursor, maximum_records, maximum_bytes)
        })
    }

    fn event_history(
        &self,
        source_revision: AccountRevision,
        after_cursor: Option<EventHistoryCursor>,
        maximum_records: usize,
        maximum_bytes: usize,
    ) -> StoreFuture<'_, EventHistoryPage> {
        Box::pin(async move {
            let accounts = self.lock_accounts()?;
            let account = accounts.get(&source_revision.account_id()).ok_or(
                IdentityError::InvalidRelationship {
                    resource: "account store missing account",
                },
            )?;
            account.event_history(
                &source_revision,
                after_cursor,
                maximum_records,
                maximum_bytes,
            )
        })
    }

    fn claim_effects(
        &self,
        account_id: AccountId,
        request: ClaimEffects,
    ) -> StoreFuture<'_, Vec<EffectRecord>> {
        Box::pin(async move {
            let mut accounts = self.lock_accounts()?;
            let account =
                accounts
                    .get_mut(&account_id)
                    .ok_or(IdentityError::InvalidRelationship {
                        resource: "account store missing account",
                    })?;

            account.claim_effects(request)
        })
    }

    fn complete_effect(
        &self,
        account_id: AccountId,
        effect_id: EffectId,
        lease_id: LeaseId,
        completed_at: Timestamp,
    ) -> StoreFuture<'_, ()> {
        Box::pin(async move {
            let mut accounts = self.lock_accounts()?;
            let account =
                accounts
                    .get_mut(&account_id)
                    .ok_or(IdentityError::InvalidRelationship {
                        resource: "account store missing account",
                    })?;
            account.complete_effect(effect_id, lease_id, completed_at)
        })
    }

    fn retry_effect(
        &self,
        account_id: AccountId,
        effect_id: EffectId,
        lease_id: LeaseId,
        retry_at: Timestamp,
        failure: EffectFailure,
    ) -> StoreFuture<'_, ()> {
        Box::pin(async move {
            let mut accounts = self.lock_accounts()?;
            let account =
                accounts
                    .get_mut(&account_id)
                    .ok_or(IdentityError::InvalidRelationship {
                        resource: "account store missing account",
                    })?;
            let exhausted = account.retry_effect(effect_id, lease_id, retry_at, failure)?;
            if exhausted {
                return Err(IdentityError::RetryExhausted);
            }
            Ok(())
        })
    }

    fn commit_group_key_rotation(
        &self,
        effect_id: EffectId,
        lease_id: LeaseId,
        rotation: GroupKeyRotation,
        completed_at: Timestamp,
    ) -> StoreFuture<'_, StoredGroupKeyRotation> {
        Box::pin(async move {
            let account_id = rotation.account_id();
            let mut accounts = self.lock_accounts()?;
            let current = accounts
                .get(&account_id)
                .ok_or(IdentityError::InvalidRelationship {
                    resource: "account store missing account",
                })?;
            let mut staged = current.clone();
            let record =
                staged.commit_group_key_rotation(effect_id, lease_id, rotation, completed_at)?;
            accounts.insert(account_id, staged);
            Ok(record)
        })
    }

    fn authorize_protected_write(
        &self,
        expected_revision: AccountRevision,
        application_id: ApplicationId,
        group_id: GroupId,
    ) -> StoreFuture<'_, ()> {
        Box::pin(async move {
            let accounts = self.lock_accounts()?;
            let account = accounts.get(&expected_revision.account_id()).ok_or(
                IdentityError::InvalidRelationship {
                    resource: "account store missing account",
                },
            )?;
            account.authorize_protected_write(&expected_revision, application_id, group_id)
        })
    }
}

pub(crate) fn derive_effect_id(
    account_id: AccountId,
    effect: ProjectionEffect,
) -> Result<EffectId, IdentityError> {
    let mut hasher = blake3::Hasher::new_derive_key("KRIKOS-ID/projection-effect/v1");
    hasher.update(&account_id.to_canonical_bytes()?);
    match effect {
        ProjectionEffect::PublishAccountEvent { event_id } => {
            hasher.update(&1_u16.to_be_bytes());
            hasher.update(&event_id.to_canonical_bytes()?);
        }
        ProjectionEffect::RotateGroupKeys { event_id, epoch } => {
            hasher.update(&2_u16.to_be_bytes());
            hasher.update(&event_id.to_canonical_bytes()?);
            hasher.update(&epoch.get().to_be_bytes());
        }
        ProjectionEffect::NotifyAccountChanged { event_id } => {
            hasher.update(&3_u16.to_be_bytes());
            hasher.update(&event_id.to_canonical_bytes()?);
        }
        ProjectionEffect::NotifyForkDetected { event_id } => {
            hasher.update(&4_u16.to_be_bytes());
            hasher.update(&event_id.to_canonical_bytes()?);
        }
    }
    Ok(EffectId(*hasher.finalize().as_bytes()))
}

fn canonical_event_order(
    events: Vec<AuthorizedEvent>,
) -> Result<Vec<AuthorizedEvent>, IdentityError> {
    let mut keyed = events
        .into_iter()
        .map(|event| {
            Ok((
                event.body().sequence(),
                event.event_id()?,
                event.event_authorization_id()?,
                event,
            ))
        })
        .collect::<Result<Vec<_>, IdentityError>>()?;
    keyed.sort_unstable_by_key(|(sequence, event_id, authorization_id, _)| {
        (*sequence, *event_id, *authorization_id)
    });
    Ok(keyed.into_iter().map(|(_, _, _, event)| event).collect())
}

fn insert_effects(
    outbox: &mut BTreeMap<EffectId, EffectRecord>,
    account_id: AccountId,
    effects: &[ProjectionEffect],
) -> Result<(), IdentityError> {
    for effect in effects {
        let id = derive_effect_id(account_id, *effect)?;
        outbox.entry(id).or_insert(EffectRecord {
            id,
            account_id,
            effect: *effect,
            state: EffectState::Pending(PendingEffect::Scheduled(Timestamp::from_unix_millis(0))),
            attempt_count: 0,
            last_failure: None,
        });
    }
    Ok(())
}
