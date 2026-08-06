//! Redb persistence for Task 6 operational effect substeps.

use std::{path::Path, sync::Arc};

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use super::{
    MAX_OPERATION_AUDIT_RECORDS, OperationalAuditRecord, OperationalEffectPhase,
    OperationalEffectRecord, OperationalEffectStore, OperationalMetricsSnapshot,
    OperationalProviderReceipt,
};
use crate::{
    AccountId, CheckpointBody, EffectFailure, EffectId, Epoch, EventId, IdentityError,
    InclusionReceipt, LeaseId, ProjectionEffect, ProviderDescriptor, ProviderPolicy,
    SignedCheckpoint, Timestamp,
    codec::{decode_wire, encode_wire},
    limits::{MAX_RETRIES, MAX_TRANSPARENCY_PROVIDERS},
    merkle::MerkleConsistencyProof,
    schema::BoundedVec,
};

const OPERATION_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("krikos-operational-effects-v1");
const OPERATION_VERSION: u16 = 2;
const MAX_OPERATION_RECORD_BYTES: usize = 32 * 1024 * 1024;
const MAX_OPERATION_RECORDS: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProviderReceiptWire {
    provider: ProviderDescriptor,
    publication: InclusionReceipt,
    observation: Option<(InclusionReceipt, MerkleConsistencyProof)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct AuditWire {
    sequence: u64,
    phase_code: u16,
    recorded_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OperationWire {
    version: u16,
    revision: u64,
    effect_id: [u8; 32],
    account_id: AccountId,
    effect_code: u16,
    event_id: EventId,
    effect_epoch: Option<Epoch>,
    lease_id: [u8; 16],
    phase_code: u16,
    checkpoint_body: Option<CheckpointBody>,
    checkpoint: Option<SignedCheckpoint>,
    publication_policy: Option<ProviderPolicy>,
    provider_receipts: BoundedVec<ProviderReceiptWire, MAX_TRANSPARENCY_PROVIDERS>,
    rotation_epoch: Option<Epoch>,
    attempt_count: u8,
    last_failure: Option<(u16, u16)>,
    audit: BoundedVec<AuditWire, MAX_OPERATION_AUDIT_RECORDS>,
}

impl OperationWire {
    fn from_record(record: &OperationalEffectRecord) -> Result<Self, IdentityError> {
        record.validate()?;
        let (effect_code, event_id, effect_epoch) = match record.effect {
            ProjectionEffect::PublishAccountEvent { event_id } => (1, event_id, None),
            ProjectionEffect::RotateGroupKeys { event_id, epoch } => (2, event_id, Some(epoch)),
            ProjectionEffect::NotifyAccountChanged { event_id } => (3, event_id, None),
            ProjectionEffect::NotifyForkDetected { event_id } => (4, event_id, None),
        };
        let last_failure = record.last_failure.map(|failure| match failure {
            EffectFailure::Transient(code) => (1, code),
            EffectFailure::Permanent(code) => (2, code),
        });
        Ok(Self {
            version: OPERATION_VERSION,
            revision: record.revision,
            effect_id: *record.effect_id.as_bytes(),
            account_id: record.account_id,
            effect_code,
            event_id,
            effect_epoch,
            lease_id: *record.lease_id.as_bytes(),
            phase_code: phase_code(record.phase),
            checkpoint_body: record.checkpoint_body.clone(),
            checkpoint: record.checkpoint.clone(),
            publication_policy: record.publication_policy.clone(),
            provider_receipts: BoundedVec::new(
                "stored operational provider receipts",
                record
                    .provider_receipts
                    .iter()
                    .map(|receipt| ProviderReceiptWire {
                        provider: receipt.provider.clone(),
                        publication: receipt.publication.clone(),
                        observation: receipt.observation.clone(),
                    })
                    .collect(),
            )?,
            rotation_epoch: record.rotation_epoch,
            attempt_count: record.attempt_count,
            last_failure,
            audit: BoundedVec::new(
                "stored operational audit records",
                record
                    .audit
                    .iter()
                    .map(|audit| AuditWire {
                        sequence: audit.sequence,
                        phase_code: phase_code(audit.phase),
                        recorded_at: audit.recorded_at,
                    })
                    .collect(),
            )?,
        })
    }

    fn into_record(self) -> Result<OperationalEffectRecord, IdentityError> {
        if self.version != OPERATION_VERSION
            || self.attempt_count == 0
            || self.attempt_count > MAX_RETRIES
        {
            return Err(IdentityError::StorageCorruption);
        }
        let effect = match (self.effect_code, self.effect_epoch) {
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
        let last_failure = match self.last_failure {
            None => None,
            Some((1, code)) => {
                Some(EffectFailure::transient(code).map_err(|_| IdentityError::StorageCorruption)?)
            }
            Some((2, code)) => {
                Some(EffectFailure::permanent(code).map_err(|_| IdentityError::StorageCorruption)?)
            }
            Some(_) => return Err(IdentityError::StorageCorruption),
        };
        let record = OperationalEffectRecord {
            revision: self.revision,
            effect_id: EffectId::from_bytes(self.effect_id),
            account_id: self.account_id,
            effect,
            lease_id: LeaseId::new(self.lease_id).map_err(|_| IdentityError::StorageCorruption)?,
            phase: decode_phase(self.phase_code)?,
            checkpoint_body: self.checkpoint_body,
            checkpoint: self.checkpoint,
            publication_policy: self.publication_policy,
            provider_receipts: self
                .provider_receipts
                .into_vec()
                .into_iter()
                .map(|wire| {
                    Ok(OperationalProviderReceipt {
                        provider: wire.provider,
                        publication: wire.publication,
                        observation: wire.observation,
                    })
                })
                .collect::<Result<Vec<_>, IdentityError>>()?,
            rotation_epoch: self.rotation_epoch,
            attempt_count: self.attempt_count,
            last_failure,
            audit: self
                .audit
                .into_vec()
                .into_iter()
                .map(|wire| {
                    Ok(OperationalAuditRecord {
                        sequence: wire.sequence,
                        phase: decode_phase(wire.phase_code)?,
                        recorded_at: wire.recorded_at,
                    })
                })
                .collect::<Result<Vec<_>, IdentityError>>()?,
        };
        record.validate()?;
        Ok(record)
    }
}

/// Redb-backed atomic operational effect journal keyed by Task 6 stable effect IDs.
#[derive(Debug, Clone)]
pub struct RedbOperationalEffectStore {
    database: Arc<Database>,
}

impl RedbOperationalEffectStore {
    /// Open or create an operational journal and authenticate every retained substep record.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let path = path.as_ref();
        crate::redb_guard::validate_existing_redb_file(path)?;
        let database = Database::create(path).map_err(|_| IdentityError::StorageCorruption)?;
        {
            let write = database
                .begin_write()
                .map_err(|_| IdentityError::StorageCorruption)?;
            let _ = write
                .open_table(OPERATION_TABLE)
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

    /// Aggregate private-safe metrics without using any durable identifier as a label.
    pub fn metrics(&self) -> Result<OperationalMetricsSnapshot, IdentityError> {
        let records = self.load_all()?;
        Ok(OperationalMetricsSnapshot::from_records(records.iter()))
    }

    fn validate_all(&self) -> Result<(), IdentityError> {
        let records = self.load_all()?;
        if records.len() > MAX_OPERATION_RECORDS {
            return Err(IdentityError::StorageCorruption);
        }
        Ok(())
    }

    fn load_all(&self) -> Result<Vec<OperationalEffectRecord>, IdentityError> {
        let read = self
            .database
            .begin_read()
            .map_err(|_| IdentityError::StorageCorruption)?;
        let table = read
            .open_table(OPERATION_TABLE)
            .map_err(|_| IdentityError::StorageCorruption)?;
        let mut records = Vec::new();
        for entry in table.iter().map_err(|_| IdentityError::StorageCorruption)? {
            let (key, value) = entry.map_err(|_| IdentityError::StorageCorruption)?;
            let key: [u8; 32] = key
                .value()
                .try_into()
                .map_err(|_| IdentityError::StorageCorruption)?;
            let record = decode_record(value.value())?;
            if record.effect_id != EffectId::from_bytes(key) {
                return Err(IdentityError::StorageCorruption);
            }
            records.push(record);
            if records.len() > MAX_OPERATION_RECORDS {
                return Err(IdentityError::StorageCorruption);
            }
        }
        Ok(records)
    }
}

impl OperationalEffectStore for RedbOperationalEffectStore {
    fn load(&self, effect_id: EffectId) -> Result<Option<OperationalEffectRecord>, IdentityError> {
        let read = self
            .database
            .begin_read()
            .map_err(|_| IdentityError::StorageCorruption)?;
        let table = read
            .open_table(OPERATION_TABLE)
            .map_err(|_| IdentityError::StorageCorruption)?;
        table
            .get(effect_id.as_bytes().as_slice())
            .map_err(|_| IdentityError::StorageCorruption)?
            .map(|value| decode_record(value.value()))
            .transpose()
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
        let write = self
            .database
            .begin_write()
            .map_err(|_| IdentityError::StorageCorruption)?;
        {
            let mut table = write
                .open_table(OPERATION_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            let retained = table
                .get(effect_id.as_bytes().as_slice())
                .map_err(|_| IdentityError::StorageCorruption)?
                .map(|value| decode_record(value.value()))
                .transpose()?;
            if retained.as_ref().map(OperationalEffectRecord::revision) != expected_revision {
                return Err(IdentityError::StaleRevision);
            }
            if retained.is_none() {
                let count = table
                    .iter()
                    .map_err(|_| IdentityError::StorageCorruption)?
                    .count();
                if count >= MAX_OPERATION_RECORDS {
                    return Err(IdentityError::limit(
                        "stored operational effects",
                        count.saturating_add(1),
                        MAX_OPERATION_RECORDS,
                    ));
                }
            }
            let bytes = encode_record(&next)?;
            table
                .insert(effect_id.as_bytes().as_slice(), bytes.as_slice())
                .map_err(|_| IdentityError::StorageCorruption)?;
        }
        write.commit().map_err(|_| IdentityError::StorageCorruption)
    }
}

fn encode_record(record: &OperationalEffectRecord) -> Result<Vec<u8>, IdentityError> {
    let bytes = encode_wire(&OperationWire::from_record(record)?)
        .map_err(|_| IdentityError::StorageCorruption)?;
    if bytes.len() > MAX_OPERATION_RECORD_BYTES {
        return Err(IdentityError::limit(
            "stored operational effect bytes",
            bytes.len(),
            MAX_OPERATION_RECORD_BYTES,
        ));
    }
    Ok(bytes)
}

fn decode_record(bytes: &[u8]) -> Result<OperationalEffectRecord, IdentityError> {
    if bytes.len() > MAX_OPERATION_RECORD_BYTES {
        return Err(IdentityError::StorageCorruption);
    }
    decode_wire::<OperationWire>(bytes)
        .map_err(|_| IdentityError::StorageCorruption)?
        .into_record()
        .map_err(|_| IdentityError::StorageCorruption)
}

const fn phase_code(phase: OperationalEffectPhase) -> u16 {
    match phase {
        OperationalEffectPhase::Claimed => 1,
        OperationalEffectPhase::CheckpointDraft => 2,
        OperationalEffectPhase::CheckpointAuthorized => 3,
        OperationalEffectPhase::Published => 4,
        OperationalEffectPhase::Replicated => 5,
        OperationalEffectPhase::Observed => 6,
        OperationalEffectPhase::RotationCommitted => 7,
        OperationalEffectPhase::PeersNotified => 8,
        OperationalEffectPhase::RetryScheduled => 9,
        OperationalEffectPhase::TerminalFailure => 10,
        OperationalEffectPhase::Completed => 11,
    }
}

fn decode_phase(code: u16) -> Result<OperationalEffectPhase, IdentityError> {
    match code {
        1 => Ok(OperationalEffectPhase::Claimed),
        2 => Ok(OperationalEffectPhase::CheckpointDraft),
        3 => Ok(OperationalEffectPhase::CheckpointAuthorized),
        4 => Ok(OperationalEffectPhase::Published),
        5 => Ok(OperationalEffectPhase::Replicated),
        6 => Ok(OperationalEffectPhase::Observed),
        7 => Ok(OperationalEffectPhase::RotationCommitted),
        8 => Ok(OperationalEffectPhase::PeersNotified),
        9 => Ok(OperationalEffectPhase::RetryScheduled),
        10 => Ok(OperationalEffectPhase::TerminalFailure),
        11 => Ok(OperationalEffectPhase::Completed),
        _ => Err(IdentityError::StorageCorruption),
    }
}
