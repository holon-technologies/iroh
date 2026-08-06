//! Redb persistence for provider audit journals.

#[cfg(test)]
use std::cell::Cell;
use std::{
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};

use redb::{
    Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle,
};
use serde::{Deserialize, Serialize};

use super::{
    MAX_PROVIDER_AUDIT_RECORDS, ProviderAuditAppend, ProviderAuditCursor, ProviderAuditRecord,
    ProviderAuditSnapshot, ProviderAuditStatus, ProviderAuditStore, apply_audit_append,
    validate_audit_successor,
};
use crate::{
    IdentityError, ProviderDescriptor, ProviderEquivocationEvidence, ProviderHeadAuditDisposition,
    ProviderLogId, SignedProviderHead,
    codec::{decode_wire, encode_wire},
    merkle::MerkleConsistencyProof,
    provider::interchange::ProviderAuditPortableAccounting,
};

const LEGACY_AUDIT_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("krikos-provider-audit-v1");
const AUDIT_METADATA_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("krikos-provider-audit-metadata-v2");
const AUDIT_RECORD_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("krikos-provider-audit-records-v2");
const AUDIT_METADATA_KEY: &[u8] = b"journal";
const AUDIT_VERSION: u16 = 2;
const MAX_AUDIT_METADATA_BYTES: usize = 64 * 1024;
const MAX_AUDIT_RECORD_BYTES: usize = 4 * 1024 * 1024;

#[cfg(test)]
thread_local! {
    static STORED_AUDIT_RECORD_DECODING_COUNT: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
fn reset_stored_audit_record_decoding_count() {
    STORED_AUDIT_RECORD_DECODING_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
fn stored_audit_record_decoding_count() -> usize {
    STORED_AUDIT_RECORD_DECODING_COUNT.with(Cell::get)
}

fn record_stored_audit_record_decoding() {
    #[cfg(test)]
    STORED_AUDIT_RECORD_DECODING_COUNT.with(|count| count.set(count.get().saturating_add(1)));
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AuditRecordWire {
    sequence: u64,
    head: SignedProviderHead,
    consistency_proof: Option<MerkleConsistencyProof>,
    status_code: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AuditMetadataWire {
    version: u16,
    revision: u64,
    provider: ProviderDescriptor,
    log_id: ProviderLogId,
    latest_head: Option<SignedProviderHead>,
    equivocation: Option<ProviderEquivocationEvidence>,
}

#[derive(Debug)]
struct CachedAuditState {
    snapshot: ProviderAuditSnapshot,
    portable_accounting: ProviderAuditPortableAccounting,
}

impl AuditRecordWire {
    fn from_record(record: &ProviderAuditRecord) -> Self {
        let status_code = match record.status {
            ProviderAuditStatus::Accepted(ProviderHeadAuditDisposition::FirstObserved) => 1,
            ProviderAuditStatus::Accepted(ProviderHeadAuditDisposition::TreeAdvanced) => 2,
            ProviderAuditStatus::Accepted(ProviderHeadAuditDisposition::HeadRefreshed) => 3,
            ProviderAuditStatus::Accepted(ProviderHeadAuditDisposition::Replay) => 4,
            ProviderAuditStatus::Rollback => 5,
            ProviderAuditStatus::Equivocation => 6,
        };
        Self {
            sequence: record.sequence,
            head: record.head.clone(),
            consistency_proof: record.consistency_proof.clone(),
            status_code,
        }
    }

    fn into_record(self) -> Result<ProviderAuditRecord, IdentityError> {
        let status = match self.status_code {
            1 => ProviderAuditStatus::Accepted(ProviderHeadAuditDisposition::FirstObserved),
            2 => ProviderAuditStatus::Accepted(ProviderHeadAuditDisposition::TreeAdvanced),
            3 => ProviderAuditStatus::Accepted(ProviderHeadAuditDisposition::HeadRefreshed),
            4 => ProviderAuditStatus::Accepted(ProviderHeadAuditDisposition::Replay),
            5 => ProviderAuditStatus::Rollback,
            6 => ProviderAuditStatus::Equivocation,
            _ => return Err(IdentityError::StorageCorruption),
        };
        Ok(ProviderAuditRecord {
            sequence: self.sequence,
            head: self.head,
            consistency_proof: self.consistency_proof,
            status,
        })
    }
}

impl AuditMetadataWire {
    fn empty(provider: ProviderDescriptor, log_id: ProviderLogId) -> Self {
        Self {
            version: AUDIT_VERSION,
            revision: 0,
            provider,
            log_id,
            latest_head: None,
            equivocation: None,
        }
    }

    fn from_snapshot(snapshot: &ProviderAuditSnapshot) -> Self {
        Self {
            version: AUDIT_VERSION,
            revision: snapshot.revision,
            provider: snapshot.provider.clone(),
            log_id: snapshot.log_id,
            latest_head: snapshot.latest_head.clone(),
            equivocation: snapshot.equivocation.clone(),
        }
    }

    fn after_append(retained: &ProviderAuditSnapshot, append: &ProviderAuditAppend) -> Self {
        Self {
            version: AUDIT_VERSION,
            revision: append.record.sequence,
            provider: retained.provider.clone(),
            log_id: retained.log_id,
            latest_head: append.latest_head.clone(),
            equivocation: append.equivocation.clone(),
        }
    }
}

/// Redb-backed atomic provider audit journal.
#[derive(Debug, Clone)]
pub struct RedbProviderAuditStore {
    database: Arc<Database>,
    provider: ProviderDescriptor,
    log_id: ProviderLogId,
    cache: Arc<Mutex<CachedAuditState>>,
}

impl RedbProviderAuditStore {
    /// Open or create one exact provider/log audit generation and authenticate its complete journal.
    pub fn open(
        path: impl AsRef<Path>,
        provider: ProviderDescriptor,
        log_id: ProviderLogId,
    ) -> Result<Self, IdentityError> {
        let path = path.as_ref();
        crate::redb_guard::validate_existing_redb_file(path)?;
        let database = Database::create(path).map_err(|_| IdentityError::StorageCorruption)?;
        let write = database
            .begin_write()
            .map_err(|_| IdentityError::StorageCorruption)?;
        if write
            .list_tables()
            .map_err(|_| IdentityError::StorageCorruption)?
            .any(|table| table.name() == LEGACY_AUDIT_TABLE.name())
        {
            return Err(IdentityError::StorageCorruption);
        }
        let metadata_exists = {
            let metadata = write
                .open_table(AUDIT_METADATA_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            metadata
                .get(AUDIT_METADATA_KEY)
                .map_err(|_| IdentityError::StorageCorruption)?
                .is_some()
        };
        if !metadata_exists {
            let records = write
                .open_table(AUDIT_RECORD_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            if !records
                .is_empty()
                .map_err(|_| IdentityError::StorageCorruption)?
            {
                return Err(IdentityError::StorageCorruption);
            }
            drop(records);
            let metadata = AuditMetadataWire::empty(provider.clone(), log_id);
            let bytes = encode_metadata(&metadata)?;
            let mut table = write
                .open_table(AUDIT_METADATA_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            table
                .insert(AUDIT_METADATA_KEY, bytes.as_slice())
                .map_err(|_| IdentityError::StorageCorruption)?;
        }
        {
            let _records = write
                .open_table(AUDIT_RECORD_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
        }
        write
            .commit()
            .map_err(|_| IdentityError::StorageCorruption)?;

        let cached = load_authoritative(&database)?;
        if cached.snapshot.provider != provider || cached.snapshot.log_id != log_id {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider audit generation",
            });
        }
        Ok(Self {
            database: Arc::new(database),
            provider,
            log_id,
            cache: Arc::new(Mutex::new(cached)),
        })
    }

    /// Load and fully reauthenticate the complete current durable audit state.
    pub fn snapshot(&self) -> Result<ProviderAuditSnapshot, IdentityError> {
        self.load()
    }

    fn lock_cache(&self) -> Result<MutexGuard<'_, CachedAuditState>, IdentityError> {
        self.cache
            .lock()
            .map_err(|_| IdentityError::StorageCorruption)
    }

    fn refresh_cache(&self) -> Result<CachedAuditState, IdentityError> {
        let refreshed = load_authoritative(&self.database)?;
        if refreshed.snapshot.provider != self.provider || refreshed.snapshot.log_id != self.log_id
        {
            return Err(IdentityError::StorageCorruption);
        }
        Ok(refreshed)
    }
}

impl ProviderAuditStore for RedbProviderAuditStore {
    fn load(&self) -> Result<ProviderAuditSnapshot, IdentityError> {
        let refreshed = self.refresh_cache()?;
        let snapshot = refreshed.snapshot.clone();
        *self.lock_cache()? = refreshed;
        Ok(snapshot)
    }

    fn load_cursor(&self) -> Result<ProviderAuditCursor, IdentityError> {
        Ok(ProviderAuditCursor::from_trusted_snapshot(
            &self.lock_cache()?.snapshot,
        ))
    }

    fn compare_and_append(
        &self,
        expected_revision: u64,
        append: ProviderAuditAppend,
    ) -> Result<(), IdentityError> {
        let mut cached = self.lock_cache()?;
        if cached.snapshot.revision != expected_revision {
            return Err(IdentityError::StaleRevision);
        }
        validate_audit_successor(&cached.snapshot, &append)?;
        let next_accounting = cached
            .portable_accounting
            .with_appended_record(&append.record)?;
        let record_bytes = encode_record(&append.record)?;
        let next_metadata = AuditMetadataWire::after_append(&cached.snapshot, &append);
        let metadata_bytes = encode_metadata(&next_metadata)?;
        let write = self
            .database
            .begin_write()
            .map_err(|_| IdentityError::StorageCorruption)?;
        let durable_metadata = {
            let metadata = write
                .open_table(AUDIT_METADATA_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            let value = metadata
                .get(AUDIT_METADATA_KEY)
                .map_err(|_| IdentityError::StorageCorruption)?
                .ok_or(IdentityError::StorageCorruption)?;
            decode_metadata(value.value())?
        };
        if durable_metadata.revision != expected_revision {
            drop(write);
            *cached = self.refresh_cache()?;
            return Err(IdentityError::StaleRevision);
        }
        if durable_metadata != AuditMetadataWire::from_snapshot(&cached.snapshot) {
            return Err(IdentityError::StorageCorruption);
        }
        {
            let mut records = write
                .open_table(AUDIT_RECORD_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            if records
                .get(append.record.sequence)
                .map_err(|_| IdentityError::StorageCorruption)?
                .is_some()
            {
                return Err(IdentityError::StorageCorruption);
            }
            records
                .insert(append.record.sequence, record_bytes.as_slice())
                .map_err(|_| IdentityError::StorageCorruption)?;
        }
        {
            let mut metadata = write
                .open_table(AUDIT_METADATA_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            metadata
                .insert(AUDIT_METADATA_KEY, metadata_bytes.as_slice())
                .map_err(|_| IdentityError::StorageCorruption)?;
        }
        write
            .commit()
            .map_err(|_| IdentityError::StorageCorruption)?;
        apply_audit_append(&mut cached.snapshot, append);
        cached.portable_accounting = next_accounting;
        Ok(())
    }
}

fn load_authoritative(database: &Database) -> Result<CachedAuditState, IdentityError> {
    let read = database
        .begin_read()
        .map_err(|_| IdentityError::StorageCorruption)?;
    let metadata = {
        let table = read
            .open_table(AUDIT_METADATA_TABLE)
            .map_err(|_| IdentityError::StorageCorruption)?;
        let value = table
            .get(AUDIT_METADATA_KEY)
            .map_err(|_| IdentityError::StorageCorruption)?
            .ok_or(IdentityError::StorageCorruption)?;
        decode_metadata(value.value())?
    };
    let maximum_revision = u64::try_from(MAX_PROVIDER_AUDIT_RECORDS).map_err(|_| {
        IdentityError::ArithmeticOverflow {
            resource: "stored provider audit record limit",
        }
    })?;
    if metadata.version != AUDIT_VERSION || metadata.revision > maximum_revision {
        return Err(IdentityError::StorageCorruption);
    }
    let capacity =
        usize::try_from(metadata.revision).map_err(|_| IdentityError::ArithmeticOverflow {
            resource: "stored provider audit record allocation",
        })?;
    let table = read
        .open_table(AUDIT_RECORD_TABLE)
        .map_err(|_| IdentityError::StorageCorruption)?;
    let mut records = Vec::with_capacity(capacity);
    let mut expected_sequence = 1_u64;
    for result in table.iter().map_err(|_| IdentityError::StorageCorruption)? {
        let (key, value) = result.map_err(|_| IdentityError::StorageCorruption)?;
        if expected_sequence > metadata.revision || expected_sequence > maximum_revision {
            return Err(IdentityError::StorageCorruption);
        }
        if key.value() != expected_sequence {
            return Err(IdentityError::StorageCorruption);
        }
        let record = decode_record(value.value())?;
        if record.sequence != expected_sequence {
            return Err(IdentityError::StorageCorruption);
        }
        records.push(record);
        expected_sequence =
            expected_sequence
                .checked_add(1)
                .ok_or(IdentityError::ArithmeticOverflow {
                    resource: "stored provider audit record sequence",
                })?;
    }
    if u64::try_from(records.len()).map_err(|_| IdentityError::ArithmeticOverflow {
        resource: "stored provider audit record count",
    })? != metadata.revision
    {
        return Err(IdentityError::StorageCorruption);
    }
    let snapshot = ProviderAuditSnapshot {
        revision: metadata.revision,
        provider: metadata.provider,
        log_id: metadata.log_id,
        latest_head: metadata.latest_head,
        equivocation: metadata.equivocation,
        records,
    };
    snapshot.validate_cached()?;
    let portable_accounting = ProviderAuditPortableAccounting::from_snapshot(&snapshot)?;
    Ok(CachedAuditState {
        snapshot,
        portable_accounting,
    })
}

fn encode_metadata(metadata: &AuditMetadataWire) -> Result<Vec<u8>, IdentityError> {
    let bytes = encode_wire(metadata).map_err(|_| IdentityError::StorageCorruption)?;
    if bytes.len() > MAX_AUDIT_METADATA_BYTES {
        return Err(IdentityError::limit(
            "stored provider audit metadata bytes",
            bytes.len(),
            MAX_AUDIT_METADATA_BYTES,
        ));
    }
    Ok(bytes)
}

fn decode_metadata(bytes: &[u8]) -> Result<AuditMetadataWire, IdentityError> {
    if bytes.len() > MAX_AUDIT_METADATA_BYTES {
        return Err(IdentityError::StorageCorruption);
    }
    let metadata: AuditMetadataWire =
        decode_wire(bytes).map_err(|_| IdentityError::StorageCorruption)?;
    if metadata.version != AUDIT_VERSION {
        return Err(IdentityError::StorageCorruption);
    }
    Ok(metadata)
}

fn encode_record(record: &ProviderAuditRecord) -> Result<Vec<u8>, IdentityError> {
    let bytes = encode_wire(&AuditRecordWire::from_record(record))
        .map_err(|_| IdentityError::StorageCorruption)?;
    if bytes.len() > MAX_AUDIT_RECORD_BYTES {
        return Err(IdentityError::limit(
            "stored provider audit record bytes",
            bytes.len(),
            MAX_AUDIT_RECORD_BYTES,
        ));
    }
    Ok(bytes)
}

fn decode_record(bytes: &[u8]) -> Result<ProviderAuditRecord, IdentityError> {
    record_stored_audit_record_decoding();
    if bytes.len() > MAX_AUDIT_RECORD_BYTES {
        return Err(IdentityError::StorageCorruption);
    }
    decode_wire::<AuditRecordWire>(bytes)
        .map_err(|_| IdentityError::StorageCorruption)?
        .into_record()
}

#[cfg(test)]
mod tests {
    use krikos_base::SecretKey;
    use redb::ReadableTableMetadata;

    use super::*;
    use crate::{
        CanonicalWire, Digest, DurableProviderAuditor, Extensions, HashAlgorithm,
        ProtocolSignature, ProviderHeadBody, ProviderKeyVersion, SigningPublicKey, Timestamp,
    };

    fn typed_id<T: CanonicalWire>(fill: u8) -> T {
        let digest = Digest::new(HashAlgorithm::Blake3_256, [fill; 32]);
        T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
    }

    fn provider(signer: &SecretKey) -> ProviderDescriptor {
        ProviderDescriptor::new(
            SigningPublicKey::ed25519(*signer.public().as_bytes()).unwrap(),
            Extensions::default(),
        )
        .unwrap()
    }

    fn signed_head(
        provider: &ProviderDescriptor,
        log_id: ProviderLogId,
        root_fill: u8,
        observed_at: u64,
        signer: &SecretKey,
    ) -> SignedProviderHead {
        let body = ProviderHeadBody::new(
            provider.id().unwrap(),
            log_id,
            ProviderKeyVersion::GENESIS,
            1,
            Digest::new(HashAlgorithm::Blake3_256, [root_fill; 32]),
            Timestamp::from_unix_millis(observed_at),
            Extensions::default(),
        )
        .unwrap();
        let signature =
            ProtocolSignature::ed25519(signer.sign(&body.signing_bytes().unwrap()).to_bytes());
        SignedProviderHead::new(body, signature)
    }

    fn first_append(head: SignedProviderHead) -> ProviderAuditAppend {
        ProviderAuditAppend {
            record: ProviderAuditRecord {
                sequence: 1,
                head: head.clone(),
                consistency_proof: None,
                status: ProviderAuditStatus::Accepted(ProviderHeadAuditDisposition::FirstObserved),
            },
            latest_head: Some(head),
            equivocation: None,
        }
    }

    #[test]
    fn rejects_legacy_v1_monolithic_journal() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("legacy-audit.redb");
        {
            let database = Database::create(&path).unwrap();
            let write = database.begin_write().unwrap();
            {
                let mut table = write.open_table(LEGACY_AUDIT_TABLE).unwrap();
                table
                    .insert(b"journal".as_slice(), b"v1".as_slice())
                    .unwrap();
            }
            write.commit().unwrap();
        }
        let signer = SecretKey::from_bytes(&[0x41; 32]);
        let provider = provider(&signer);
        let log_id = typed_id::<ProviderLogId>(0x42);

        assert!(matches!(
            RedbProviderAuditStore::open(path, provider, log_id),
            Err(IdentityError::StorageCorruption)
        ));
    }

    #[test]
    fn rejects_an_extra_record_before_decoding_it() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("extra-audit-record.redb");
        let signer = SecretKey::from_bytes(&[0x43; 32]);
        let provider = provider(&signer);
        let log_id = typed_id::<ProviderLogId>(0x44);
        drop(RedbProviderAuditStore::open(&path, provider.clone(), log_id).unwrap());
        {
            let database = Database::create(&path).unwrap();
            let write = database.begin_write().unwrap();
            {
                let mut table = write.open_table(AUDIT_RECORD_TABLE).unwrap();
                table.insert(1, b"not-a-record".as_slice()).unwrap();
            }
            write.commit().unwrap();
        }
        reset_stored_audit_record_decoding_count();

        assert!(matches!(
            RedbProviderAuditStore::open(path, provider, log_id),
            Err(IdentityError::StorageCorruption)
        ));
        assert_eq!(stored_audit_record_decoding_count(), 0);
    }

    #[test]
    fn rejects_a_noncontiguous_record_table() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gapped-audit-record.redb");
        let signer = SecretKey::from_bytes(&[0x45; 32]);
        let provider = provider(&signer);
        let log_id = typed_id::<ProviderLogId>(0x46);
        drop(RedbProviderAuditStore::open(&path, provider.clone(), log_id).unwrap());
        {
            let database = Database::create(&path).unwrap();
            let write = database.begin_write().unwrap();
            {
                let metadata = AuditMetadataWire {
                    version: AUDIT_VERSION,
                    revision: 2,
                    provider: provider.clone(),
                    log_id,
                    latest_head: None,
                    equivocation: None,
                };
                let bytes = encode_metadata(&metadata).unwrap();
                let mut table = write.open_table(AUDIT_METADATA_TABLE).unwrap();
                table.insert(AUDIT_METADATA_KEY, bytes.as_slice()).unwrap();
            }
            {
                let mut table = write.open_table(AUDIT_RECORD_TABLE).unwrap();
                table.insert(2, b"not-a-record".as_slice()).unwrap();
            }
            write.commit().unwrap();
        }
        reset_stored_audit_record_decoding_count();

        assert!(matches!(
            RedbProviderAuditStore::open(path, provider, log_id),
            Err(IdentityError::StorageCorruption)
        ));
        assert_eq!(stored_audit_record_decoding_count(), 0);
    }

    #[test]
    fn stale_cas_refreshes_cache_without_partially_appending() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("stale-cas-audit.redb");
        let signer = SecretKey::from_bytes(&[0x47; 32]);
        let provider = provider(&signer);
        let log_id = typed_id::<ProviderLogId>(0x48);
        let first = RedbProviderAuditStore::open(&path, provider.clone(), log_id).unwrap();
        let stale = RedbProviderAuditStore {
            database: Arc::clone(&first.database),
            provider: provider.clone(),
            log_id,
            cache: Arc::new(Mutex::new(load_authoritative(&first.database).unwrap())),
        };
        let durable_head = signed_head(&provider, log_id, 0x49, 1, &signer);
        first
            .compare_and_append(0, first_append(durable_head.clone()))
            .unwrap();
        let rejected_head = signed_head(&provider, log_id, 0x49, 2, &signer);

        assert_eq!(
            stale.compare_and_append(0, first_append(rejected_head)),
            Err(IdentityError::StaleRevision)
        );
        let refreshed = stale.load_cursor().unwrap();
        assert_eq!(refreshed.revision(), 1);
        assert_eq!(refreshed.latest_head(), Some(&durable_head));
        let read = first.database.begin_read().unwrap();
        let records = read.open_table(AUDIT_RECORD_TABLE).unwrap();
        assert_eq!(records.len().unwrap(), 1);
        assert!(records.get(1).unwrap().is_some());
        assert!(records.get(2).unwrap().is_none());
        let metadata = read.open_table(AUDIT_METADATA_TABLE).unwrap();
        let value = metadata.get(AUDIT_METADATA_KEY).unwrap().unwrap();
        assert_eq!(decode_metadata(value.value()).unwrap().revision, 1);
    }

    #[test]
    fn cross_reopen_257_appends_do_not_rescan_prior_records() {
        const FIRST_BATCH: u64 = 129;
        const OBSERVATION_COUNT: u64 = 257;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("linear-audit.redb");
        let signer = SecretKey::from_bytes(&[0x4a; 32]);
        let provider = provider(&signer);
        let log_id = typed_id::<ProviderLogId>(0x4b);
        {
            let store = RedbProviderAuditStore::open(&path, provider.clone(), log_id).unwrap();
            let auditor = DurableProviderAuditor::new(store);
            for index in 0..FIRST_BATCH {
                auditor
                    .observe(
                        signed_head(&provider, log_id, 0x4c, index + 1, &signer),
                        None,
                    )
                    .unwrap();
            }
        }

        crate::provider::interchange::reset_portable_audit_record_encoding_count();
        reset_stored_audit_record_decoding_count();
        let store = RedbProviderAuditStore::open(&path, provider.clone(), log_id).unwrap();
        let auditor = DurableProviderAuditor::new(store.clone());
        for index in FIRST_BATCH..OBSERVATION_COUNT {
            auditor
                .observe(
                    signed_head(&provider, log_id, 0x4c, index + 1, &signer),
                    None,
                )
                .unwrap();
        }

        assert_eq!(store.load_cursor().unwrap().revision(), OBSERVATION_COUNT);
        assert_eq!(
            crate::provider::interchange::portable_audit_record_encoding_count(),
            usize::try_from(OBSERVATION_COUNT).unwrap(),
            "reopen recounts once and each later append encodes only its new record"
        );
        assert_eq!(
            stored_audit_record_decoding_count(),
            usize::try_from(FIRST_BATCH).unwrap(),
            "later appends must not decode any retained record"
        );
        let read = store.database.begin_read().unwrap();
        let records = read.open_table(AUDIT_RECORD_TABLE).unwrap();
        assert_eq!(records.len().unwrap(), OBSERVATION_COUNT);
    }
}
