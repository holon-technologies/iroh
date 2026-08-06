//! Production one-time pairing nonce stores.

use std::collections::BTreeMap;
#[cfg(feature = "fs-store")]
use std::{path::Path, sync::Arc};

use crate::{
    IdentityError, PairingNonceKey, PairingNonceStore, Timestamp,
    limits::MAX_PAIRING_NONCE_TOMBSTONES,
};

use super::NonceConsumeResult;

#[cfg(feature = "fs-store")]
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

#[cfg(feature = "fs-store")]
const PAIRING_NONCE_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("krikos-pairing-nonce-tombstones-v1");

/// In-memory production nonce store for ephemeral deployments and tests.
///
/// Tombstones are never removed. At the visible capacity limit this store denies new pairing
/// consumption rather than weakening replay protection.
#[derive(Debug, Default)]
pub struct MemoryPairingNonceStore {
    tombstones: BTreeMap<PairingNonceKey, Timestamp>,
}

impl MemoryPairingNonceStore {
    /// Construct an empty non-revivable tombstone store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of durably modeled consumed ticket tombstones.
    pub fn len(&self) -> usize {
        self.tombstones.len()
    }

    /// Whether no ticket has been consumed.
    pub fn is_empty(&self) -> bool {
        self.tombstones.is_empty()
    }
}

impl PairingNonceStore for MemoryPairingNonceStore {
    type Error = IdentityError;

    fn is_consumed(&mut self, key: PairingNonceKey) -> Result<bool, Self::Error> {
        Ok(self.tombstones.contains_key(&key))
    }

    fn consume_atomically(
        &mut self,
        key: PairingNonceKey,
        expires_at: Timestamp,
    ) -> Result<NonceConsumeResult, Self::Error> {
        if self.tombstones.contains_key(&key) {
            return Ok(NonceConsumeResult::AlreadyConsumed);
        }
        if self.tombstones.len() >= MAX_PAIRING_NONCE_TOMBSTONES {
            return Err(IdentityError::limit(
                "pairing nonce tombstones",
                self.tombstones.len().saturating_add(1),
                MAX_PAIRING_NONCE_TOMBSTONES,
            ));
        }
        self.tombstones.insert(key, expires_at);
        Ok(NonceConsumeResult::Consumed)
    }
}

/// Redb-backed pairing nonce store whose committed tombstones never become valid tickets again.
#[cfg(feature = "fs-store")]
#[derive(Debug, Clone)]
pub struct RedbPairingNonceStore {
    database: Arc<Database>,
}

#[cfg(feature = "fs-store")]
impl RedbPairingNonceStore {
    /// Open or create a crash-safe pairing tombstone store.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let path = path.as_ref();
        crate::redb_guard::validate_existing_redb_file(path)?;
        let database = Database::create(path).map_err(|_| IdentityError::StorageCorruption)?;
        let write = database
            .begin_write()
            .map_err(|_| IdentityError::StorageCorruption)?;
        let _ = write
            .open_table(PAIRING_NONCE_TABLE)
            .map_err(|_| IdentityError::StorageCorruption)?;
        write
            .commit()
            .map_err(|_| IdentityError::StorageCorruption)?;
        Ok(Self {
            database: Arc::new(database),
        })
    }

    fn key(key: PairingNonceKey) -> Result<Vec<u8>, IdentityError> {
        crate::codec::encode_wire(&(key.account_id, key.ticket_id, key.nonce))
    }
}

#[cfg(feature = "fs-store")]
impl PairingNonceStore for RedbPairingNonceStore {
    type Error = IdentityError;

    fn is_consumed(&mut self, key: PairingNonceKey) -> Result<bool, Self::Error> {
        let key = Self::key(key)?;
        let read = self
            .database
            .begin_read()
            .map_err(|_| IdentityError::StorageCorruption)?;
        let table = read
            .open_table(PAIRING_NONCE_TABLE)
            .map_err(|_| IdentityError::StorageCorruption)?;
        match table
            .get(key.as_slice())
            .map_err(|_| IdentityError::StorageCorruption)?
        {
            None => Ok(false),
            Some(value) if value.value().len() == 8 => Ok(true),
            Some(_) => Err(IdentityError::StorageCorruption),
        }
    }

    fn consume_atomically(
        &mut self,
        key: PairingNonceKey,
        expires_at: Timestamp,
    ) -> Result<NonceConsumeResult, Self::Error> {
        let key = Self::key(key)?;
        let write = self
            .database
            .begin_write()
            .map_err(|_| IdentityError::StorageCorruption)?;
        let result = {
            let mut table = write
                .open_table(PAIRING_NONCE_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            let existing = table
                .get(key.as_slice())
                .map_err(|_| IdentityError::StorageCorruption)?
                .map(|value| value.value().len());
            match existing {
                Some(8) => Ok(NonceConsumeResult::AlreadyConsumed),
                Some(_) => Err(IdentityError::StorageCorruption),
                None => {
                    let count = table
                        .iter()
                        .map_err(|_| IdentityError::StorageCorruption)?
                        .count();
                    if count >= MAX_PAIRING_NONCE_TOMBSTONES {
                        return Err(IdentityError::limit(
                            "pairing nonce tombstones",
                            count.saturating_add(1),
                            MAX_PAIRING_NONCE_TOMBSTONES,
                        ));
                    }
                    table
                        .insert(
                            key.as_slice(),
                            expires_at.as_unix_millis().to_be_bytes().as_slice(),
                        )
                        .map_err(|_| IdentityError::StorageCorruption)?;
                    Ok(NonceConsumeResult::Consumed)
                }
            }
        }?;
        write
            .commit()
            .map_err(|_| IdentityError::StorageCorruption)?;
        Ok(result)
    }
}
