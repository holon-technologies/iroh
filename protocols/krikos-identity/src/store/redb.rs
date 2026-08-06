//! Optional redb-backed canonical source-record store.

use std::{path::Path, sync::Arc};

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use super::{
    AccountSnapshot, AccountStore, BatchCommitReceipt, CheckpointCommitReceipt,
    CheckpointJournalPage, ClaimEffects, CommitReceipt, EffectFailure, EffectId, EffectRecord,
    EffectState, LeaseId, MAX_STORED_CHECKPOINTS, PendingEffect, StoreFuture, StoredAccount,
    StoredCheckpoint, StoredGroupKeyRotation, derive_effect_id,
};
use crate::{
    AccountGenesis, AccountId, AccountRevision, ApplicationId, AuthorizedEvent, CanonicalWire,
    EventId, GroupId, GroupKeyEpoch, GroupKeyRotation, IdentityError, ProjectionEffect,
    RecipientKeyWraps, SignedCheckpoint, Timestamp, VerifiedCheckpoint,
    codec::{decode_wire, encode_wire},
    limits::{MAX_FORK_HEADS, MAX_RETRIES},
    schema::BoundedVec,
};

const ACCOUNT_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("krikos-identity-accounts-v1");
const MAX_STORED_EVENT_ENVELOPES: usize = 65_536;
const MAX_STORED_EFFECTS: usize = MAX_STORED_EVENT_ENVELOPES * 4;
const MAX_ACCOUNT_RECORD_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredAccountWire {
    version: u16,
    genesis: AccountGenesis,
    events: BoundedVec<AuthorizedEvent, MAX_STORED_EVENT_ENVELOPES>,
    event_journal: BoundedVec<EventId, MAX_STORED_EVENT_ENVELOPES>,
    effects: BoundedVec<EffectWire, MAX_STORED_EFFECTS>,
    rotations: BoundedVec<RotationWire, MAX_STORED_EVENT_ENVELOPES>,
    checkpoints: BoundedVec<StoredCheckpointWire, MAX_STORED_CHECKPOINTS>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredCheckpointWire {
    checkpoint: SignedCheckpoint,
    transition_event: Option<AuthorizedEvent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct EffectWire {
    id: [u8; 32],
    account_id: AccountId,
    effect_code: u16,
    event_id: EventId,
    epoch: Option<crate::Epoch>,
    state_code: u16,
    state_at: Timestamp,
    lease_id: Option<[u8; 16]>,
    attempt_count: u8,
    failure: Option<(u16, u16)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RotationWire {
    application_id: ApplicationId,
    group_id: GroupId,
    authorizing_account_epoch: crate::Epoch,
    group_key_epoch: GroupKeyEpoch,
    revision_heads: BoundedVec<EventId, MAX_FORK_HEADS>,
    recipient_key_wraps: RecipientKeyWraps,
}

impl StoredAccountWire {
    fn from_stored(stored: &StoredAccount) -> Result<Self, IdentityError> {
        Ok(Self {
            version: 2,
            genesis: stored.genesis.clone(),
            events: BoundedVec::new(
                "stored account event envelopes",
                stored.events.values().cloned().collect(),
            )?,
            event_journal: BoundedVec::new(
                "stored account event journal",
                stored.event_journal.clone(),
            )?,
            effects: BoundedVec::new(
                "stored account effects",
                stored
                    .outbox
                    .values()
                    .map(EffectWire::from_record)
                    .collect::<Result<Vec<_>, IdentityError>>()?,
            )?,
            rotations: BoundedVec::new(
                "stored group key rotations",
                stored
                    .group_key_rotations
                    .values()
                    .map(RotationWire::from_record)
                    .collect::<Result<Vec<_>, IdentityError>>()?,
            )?,
            checkpoints: BoundedVec::new(
                "stored account checkpoints",
                stored
                    .checkpoint_journal
                    .iter()
                    .map(|checkpoint_id| {
                        stored
                            .checkpoints
                            .get(checkpoint_id)
                            .map(|record| StoredCheckpointWire {
                                checkpoint: record.checkpoint.clone(),
                                transition_event: record.transition_event.clone(),
                            })
                            .ok_or(IdentityError::StorageCorruption)
                    })
                    .collect::<Result<Vec<_>, IdentityError>>()?,
            )?,
        })
    }

    fn into_stored(self, expected_account_id: AccountId) -> Result<StoredAccount, IdentityError> {
        if self.version != 2 || self.genesis.account_id()? != expected_account_id {
            return Err(IdentityError::StorageCorruption);
        }
        let mut events = std::collections::BTreeMap::new();
        for event in self.events.into_vec() {
            if event.body().account_id() != expected_account_id {
                return Err(IdentityError::StorageCorruption);
            }
            let authorization_id = event.event_authorization_id()?;
            if events.insert(authorization_id, event).is_some() {
                return Err(IdentityError::StorageCorruption);
            }
        }
        let mut outbox = std::collections::BTreeMap::new();
        for wire in self.effects.into_vec() {
            let record = wire.into_record(expected_account_id)?;
            if outbox.insert(record.id, record).is_some() {
                return Err(IdentityError::StorageCorruption);
            }
        }
        let mut group_key_rotations = std::collections::BTreeMap::new();
        for wire in self.rotations.into_vec() {
            let record = wire.into_record(expected_account_id)?;
            let key = (record.application_id, record.group_id);
            if group_key_rotations.insert(key, record).is_some() {
                return Err(IdentityError::StorageCorruption);
            }
        }
        let mut checkpoints = std::collections::BTreeMap::new();
        let mut checkpoint_journal = Vec::new();
        for wire in self.checkpoints.into_vec() {
            if wire.checkpoint.body().account_id() != expected_account_id {
                return Err(IdentityError::StorageCorruption);
            }
            let checkpoint_id = wire.checkpoint.checkpoint_id()?;
            let retained = StoredCheckpoint {
                checkpoint: wire.checkpoint,
                transition_event: wire.transition_event,
            };
            if checkpoints.insert(checkpoint_id, retained).is_some() {
                return Err(IdentityError::StorageCorruption);
            }
            checkpoint_journal.push(checkpoint_id);
        }
        let mut stored = StoredAccount {
            projection: crate::AccountState::from_genesis(&self.genesis)?,
            genesis: self.genesis,
            events,
            event_journal: self.event_journal.into_vec(),
            outbox,
            group_key_rotations,
            checkpoints,
            checkpoint_journal,
        };
        let (projection, required_effects) = stored.rebuild_projection_and_effects()?;
        if required_effects.len() != stored.outbox.len()
            || required_effects.iter().any(|(id, effect)| {
                stored
                    .outbox
                    .get(id)
                    .is_none_or(|record| record.effect != *effect)
            })
        {
            return Err(IdentityError::StorageCorruption);
        }
        stored.projection = projection;
        stored.validate_checkpoint_journal()?;
        let _ = stored.snapshot()?;
        Ok(stored)
    }
}

impl RotationWire {
    fn from_record(record: &StoredGroupKeyRotation) -> Result<Self, IdentityError> {
        Ok(Self {
            application_id: record.application_id,
            group_id: record.group_id,
            authorizing_account_epoch: record.authorizing_account_epoch,
            group_key_epoch: record.group_key_epoch,
            revision_heads: BoundedVec::new(
                "stored group rotation revision heads",
                record.revision_heads.clone(),
            )?,
            recipient_key_wraps: record.recipient_key_wraps.clone(),
        })
    }

    fn into_record(self, account_id: AccountId) -> Result<StoredGroupKeyRotation, IdentityError> {
        for wrap in self.recipient_key_wraps.as_slice() {
            let header = wrap.header();
            if header.account_id() != account_id
                || header.application_id() != self.application_id
                || header.group_id() != self.group_id
                || header.authorizing_account_epoch() != self.authorizing_account_epoch
                || header.group_key_epoch() != self.group_key_epoch
            {
                return Err(IdentityError::StorageCorruption);
            }
        }
        Ok(StoredGroupKeyRotation {
            account_id,
            application_id: self.application_id,
            group_id: self.group_id,
            authorizing_account_epoch: self.authorizing_account_epoch,
            group_key_epoch: self.group_key_epoch,
            revision_heads: self.revision_heads.into_vec(),
            recipient_key_wraps: self.recipient_key_wraps,
        })
    }
}

impl EffectWire {
    fn from_record(record: &EffectRecord) -> Result<Self, IdentityError> {
        let (effect_code, event_id, epoch) = match record.effect {
            ProjectionEffect::PublishAccountEvent { event_id } => (1, event_id, None),
            ProjectionEffect::RotateGroupKeys { event_id, epoch } => (2, event_id, Some(epoch)),
            ProjectionEffect::NotifyAccountChanged { event_id } => (3, event_id, None),
            ProjectionEffect::NotifyForkDetected { event_id } => (4, event_id, None),
        };
        let (state_code, state_at, lease_id) = match record.state {
            EffectState::Pending(PendingEffect::Scheduled(at)) => (1, at, None),
            EffectState::Pending(PendingEffect::Exhausted(at)) => (2, at, None),
            EffectState::Claimed {
                lease_id,
                leased_until,
            } => (3, leased_until, Some(*lease_id.as_bytes())),
            EffectState::Completed {
                lease_id,
                completed_at,
            } => (4, completed_at, Some(*lease_id.as_bytes())),
        };
        let failure = record.last_failure.map(|failure| match failure {
            EffectFailure::Transient(code) => (1, code),
            EffectFailure::Permanent(code) => (2, code),
        });
        Ok(Self {
            id: *record.id.as_bytes(),
            account_id: record.account_id,
            effect_code,
            event_id,
            epoch,
            state_code,
            state_at,
            lease_id,
            attempt_count: record.attempt_count,
            failure,
        })
    }

    fn into_record(self, expected_account_id: AccountId) -> Result<EffectRecord, IdentityError> {
        if self.account_id != expected_account_id || self.attempt_count > MAX_RETRIES {
            return Err(IdentityError::StorageCorruption);
        }
        let effect = match (self.effect_code, self.epoch) {
            (1, None) => ProjectionEffect::PublishAccountEvent {
                event_id: self.event_id,
            },
            (2, Some(epoch)) => ProjectionEffect::RotateGroupKeys {
                event_id: self.event_id,
                epoch,
            },
            (3, None) => ProjectionEffect::NotifyAccountChanged {
                event_id: self.event_id,
            },
            (4, None) => ProjectionEffect::NotifyForkDetected {
                event_id: self.event_id,
            },
            _ => return Err(IdentityError::StorageCorruption),
        };
        let state = match (self.state_code, self.lease_id) {
            (1, None) => EffectState::Pending(PendingEffect::Scheduled(self.state_at)),
            (2, None) => EffectState::Pending(PendingEffect::Exhausted(self.state_at)),
            (3, Some(lease)) => EffectState::Claimed {
                lease_id: LeaseId::new(lease).map_err(|_| IdentityError::StorageCorruption)?,
                leased_until: self.state_at,
            },
            (4, Some(lease)) => EffectState::Completed {
                lease_id: LeaseId::new(lease).map_err(|_| IdentityError::StorageCorruption)?,
                completed_at: self.state_at,
            },
            _ => return Err(IdentityError::StorageCorruption),
        };
        let last_failure = match self.failure {
            None => None,
            Some((1, code)) => {
                Some(EffectFailure::transient(code).map_err(|_| IdentityError::StorageCorruption)?)
            }
            Some((2, code)) => {
                Some(EffectFailure::permanent(code).map_err(|_| IdentityError::StorageCorruption)?)
            }
            Some(_) => return Err(IdentityError::StorageCorruption),
        };
        let id = EffectId(self.id);
        if derive_effect_id(expected_account_id, effect)? != id {
            return Err(IdentityError::StorageCorruption);
        }
        Ok(EffectRecord {
            id,
            account_id: expected_account_id,
            effect,
            state,
            attempt_count: self.attempt_count,
            last_failure,
        })
    }
}

/// redb-backed atomic canonical source-record store.
#[derive(Debug, Clone)]
pub struct RedbAccountStore {
    database: Arc<Database>,
}

impl RedbAccountStore {
    /// Open or create a database and authenticate every retained account projection.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let path = path.as_ref();
        crate::redb_guard::validate_existing_redb_file(path)?;
        let database = Database::create(path).map_err(|_| IdentityError::StorageCorruption)?;
        {
            let write = database
                .begin_write()
                .map_err(|_| IdentityError::StorageCorruption)?;
            let _ = write
                .open_table(ACCOUNT_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            write
                .commit()
                .map_err(|_| IdentityError::StorageCorruption)?;
        }
        let store = Self {
            database: Arc::new(database),
        };
        store.validate_all()?;
        Ok(store)
    }

    fn validate_all(&self) -> Result<(), IdentityError> {
        let read = self
            .database
            .begin_read()
            .map_err(|_| IdentityError::StorageCorruption)?;
        let table = read
            .open_table(ACCOUNT_TABLE)
            .map_err(|_| IdentityError::StorageCorruption)?;
        let iterator = table.iter().map_err(|_| IdentityError::StorageCorruption)?;
        for entry in iterator {
            let (key, value) = entry.map_err(|_| IdentityError::StorageCorruption)?;
            let account_id = AccountId::from_canonical_bytes(key.value())
                .map_err(|_| IdentityError::StorageCorruption)?;
            let _ = decode_stored(account_id, value.value())?;
        }
        Ok(())
    }

    fn load_sync(&self, account_id: AccountId) -> Result<Option<StoredAccount>, IdentityError> {
        let key = account_id.to_canonical_bytes()?;
        let read = self
            .database
            .begin_read()
            .map_err(|_| IdentityError::StorageCorruption)?;
        let table = read
            .open_table(ACCOUNT_TABLE)
            .map_err(|_| IdentityError::StorageCorruption)?;
        table
            .get(key.as_slice())
            .map_err(|_| IdentityError::StorageCorruption)?
            .map(|value| decode_stored(account_id, value.value()))
            .transpose()
    }

    fn write_stored(
        table: &mut redb::Table<'_, &[u8], &[u8]>,
        account_id: AccountId,
        stored: &StoredAccount,
    ) -> Result<(), IdentityError> {
        let key = account_id.to_canonical_bytes()?;
        let bytes = encode_stored(stored)?;
        table
            .insert(key.as_slice(), bytes.as_slice())
            .map_err(|_| IdentityError::StorageCorruption)?;
        Ok(())
    }
}

impl AccountStore for RedbAccountStore {
    fn create_account(&self, genesis: AccountGenesis) -> StoreFuture<'_, AccountSnapshot> {
        Box::pin(async move {
            let account_id = genesis.account_id()?;
            let write = self
                .database
                .begin_write()
                .map_err(|_| IdentityError::StorageCorruption)?;
            {
                let mut table = write
                    .open_table(ACCOUNT_TABLE)
                    .map_err(|_| IdentityError::StorageCorruption)?;
                let key = account_id.to_canonical_bytes()?;
                if table
                    .get(key.as_slice())
                    .map_err(|_| IdentityError::StorageCorruption)?
                    .is_some()
                {
                    return Err(IdentityError::InvalidRelationship {
                        resource: "account store duplicate genesis",
                    });
                }
                let stored = StoredAccount {
                    projection: crate::AccountState::from_genesis(&genesis)?,
                    genesis,
                    events: std::collections::BTreeMap::new(),
                    event_journal: Vec::new(),
                    outbox: std::collections::BTreeMap::new(),
                    group_key_rotations: std::collections::BTreeMap::new(),
                    checkpoints: std::collections::BTreeMap::new(),
                    checkpoint_journal: Vec::new(),
                };
                let snapshot = stored.snapshot()?;
                Self::write_stored(&mut table, account_id, &stored)?;
                drop(table);
                write
                    .commit()
                    .map_err(|_| IdentityError::StorageCorruption)?;
                Ok(snapshot)
            }
        })
    }

    fn load_account(&self, account_id: AccountId) -> StoreFuture<'_, Option<AccountSnapshot>> {
        Box::pin(async move {
            self.load_sync(account_id)?
                .map(|stored| stored.snapshot())
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
            let write = self
                .database
                .begin_write()
                .map_err(|_| IdentityError::StorageCorruption)?;
            let receipt;
            {
                let mut table = write
                    .open_table(ACCOUNT_TABLE)
                    .map_err(|_| IdentityError::StorageCorruption)?;
                let key = account_id.to_canonical_bytes()?;
                let value = table
                    .get(key.as_slice())
                    .map_err(|_| IdentityError::StorageCorruption)?
                    .ok_or(IdentityError::InvalidRelationship {
                        resource: "account store missing account",
                    })?;
                let mut stored = decode_stored(account_id, value.value())?;
                drop(value);
                receipt = stored.commit_event(&expected_revision, event)?;
                Self::write_stored(&mut table, account_id, &stored)?;
            }
            write
                .commit()
                .map_err(|_| IdentityError::StorageCorruption)?;
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
            let write = self
                .database
                .begin_write()
                .map_err(|_| IdentityError::StorageCorruption)?;
            let receipt;
            {
                let mut table = write
                    .open_table(ACCOUNT_TABLE)
                    .map_err(|_| IdentityError::StorageCorruption)?;
                let key = account_id.to_canonical_bytes()?;
                let value = table
                    .get(key.as_slice())
                    .map_err(|_| IdentityError::StorageCorruption)?
                    .ok_or(IdentityError::InvalidRelationship {
                        resource: "account store missing account",
                    })?;
                let mut stored = decode_stored(account_id, value.value())?;
                drop(value);
                receipt = stored.commit_events(&expected_revision, events)?;
                Self::write_stored(&mut table, account_id, &stored)?;
            }
            write
                .commit()
                .map_err(|_| IdentityError::StorageCorruption)?;
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
            self.update_account(account_id, |stored| {
                stored.commit_checkpoint(&expected_revision, checkpoint)
            })
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
            let stored = self
                .load_sync(account_id)?
                .ok_or(IdentityError::InvalidRelationship {
                    resource: "account store missing account",
                })?;
            stored.checkpoint_history(after_cursor, maximum_records, maximum_bytes)
        })
    }

    fn event_history(
        &self,
        source_revision: AccountRevision,
        after_cursor: Option<super::EventHistoryCursor>,
        maximum_records: usize,
        maximum_bytes: usize,
    ) -> StoreFuture<'_, super::EventHistoryPage> {
        Box::pin(async move {
            let stored = self.load_sync(source_revision.account_id())?.ok_or(
                IdentityError::InvalidRelationship {
                    resource: "account store missing account",
                },
            )?;
            stored.event_history(
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
        Box::pin(
            async move { self.update_account(account_id, |stored| stored.claim_effects(request)) },
        )
    }

    fn complete_effect(
        &self,
        account_id: AccountId,
        effect_id: EffectId,
        lease_id: LeaseId,
        completed_at: Timestamp,
    ) -> StoreFuture<'_, ()> {
        Box::pin(async move {
            self.update_account(account_id, |stored| {
                stored.complete_effect(effect_id, lease_id, completed_at)
            })
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
            let exhausted = self.update_account(account_id, |stored| {
                stored.retry_effect(effect_id, lease_id, retry_at, failure)
            })?;
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
            self.update_account(account_id, |stored| {
                stored.commit_group_key_rotation(effect_id, lease_id, rotation, completed_at)
            })
        })
    }

    fn authorize_protected_write(
        &self,
        expected_revision: AccountRevision,
        application_id: ApplicationId,
        group_id: GroupId,
    ) -> StoreFuture<'_, ()> {
        Box::pin(async move {
            let stored = self.load_sync(expected_revision.account_id())?.ok_or(
                IdentityError::InvalidRelationship {
                    resource: "account store missing account",
                },
            )?;
            stored.authorize_protected_write(&expected_revision, application_id, group_id)
        })
    }
}

impl RedbAccountStore {
    fn update_account<T>(
        &self,
        account_id: AccountId,
        update: impl FnOnce(&mut StoredAccount) -> Result<T, IdentityError>,
    ) -> Result<T, IdentityError> {
        let write = self
            .database
            .begin_write()
            .map_err(|_| IdentityError::StorageCorruption)?;
        let output;
        {
            let mut table = write
                .open_table(ACCOUNT_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            let key = account_id.to_canonical_bytes()?;
            let value = table
                .get(key.as_slice())
                .map_err(|_| IdentityError::StorageCorruption)?
                .ok_or(IdentityError::InvalidRelationship {
                    resource: "account store missing account",
                })?;
            let mut stored = decode_stored(account_id, value.value())?;
            drop(value);
            output = update(&mut stored)?;
            Self::write_stored(&mut table, account_id, &stored)?;
        }
        write
            .commit()
            .map_err(|_| IdentityError::StorageCorruption)?;
        Ok(output)
    }
}

fn encode_stored(stored: &StoredAccount) -> Result<Vec<u8>, IdentityError> {
    let wire = StoredAccountWire::from_stored(stored)?;
    let bytes = encode_wire(&wire)?;
    if bytes.len() > MAX_ACCOUNT_RECORD_BYTES {
        return Err(IdentityError::limit(
            "stored account source bytes",
            bytes.len(),
            MAX_ACCOUNT_RECORD_BYTES,
        ));
    }
    Ok(bytes)
}

fn decode_stored(account_id: AccountId, bytes: &[u8]) -> Result<StoredAccount, IdentityError> {
    if bytes.len() > MAX_ACCOUNT_RECORD_BYTES {
        return Err(IdentityError::StorageCorruption);
    }
    let wire =
        decode_wire::<StoredAccountWire>(bytes).map_err(|_| IdentityError::StorageCorruption)?;
    wire.into_stored(account_id)
        .map_err(|_| IdentityError::StorageCorruption)
}
