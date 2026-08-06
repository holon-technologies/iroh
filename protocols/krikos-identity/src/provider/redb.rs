//! Optional redb-backed provider generation with durable prepare/sign/commit sequencing.

use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use super::{
    MAX_PROVIDER_COMPACTION_MANIFESTS, MemoryProviderStore, ProviderAccountHistoryPage,
    ProviderAppendPermit, ProviderCheckpointBundleWire, ProviderCheckpointIndex,
    ProviderCompactionAuthorization, ProviderCompactionManifest, ProviderGenerationExport,
    ProviderGenerationPayload, ProviderGenerationSnapshot, ProviderGenerationState,
    ProviderRecoveryExport, ProviderRetentionClass, ProviderRetentionInventory,
    ProviderRetentionItem,
};
use crate::{
    AccountId, CheckpointId, Digest, Epoch, EventId, Extensions, IdentityError, InclusionReceipt,
    ProtocolSignature, ProviderAuditArtifact, ProviderAuditArtifactKind, ProviderCheckpointBundle,
    ProviderDescriptor, ProviderHeadBody, ProviderHeadSigner, ProviderKeyVersion,
    ProviderLogEntryBody, ProviderLogId, Sequence, SignedProviderHead, Timestamp,
    codec::{decode_wire, encode_wire},
    limits::{MAX_FORK_HEADS, MAX_MERKLE_LOG_LEAVES},
    merkle::{AppendOnlyMerkleLog, MerkleConsistencyProof},
    schema::{BoundedBytes, BoundedVec},
};

const COMMITTED_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("krikos-provider-generation-v1");
const PREPARED_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("krikos-provider-prepared-v1");
const ACTIVE_KEY: &[u8] = b"active";
const PREPARED_KEY: &[u8] = b"append";
const STORE_VERSION: u16 = 7;
const MAX_STORED_PROVIDER_ENTRIES: usize = 65_536;
const MAX_STORED_PROVIDER_NODES: usize = MAX_STORED_PROVIDER_ENTRIES * 2;
const MAX_STORED_PROVIDER_BYTES: usize = 512 * 1024 * 1024;
const MAX_STORED_PROVIDER_AUDIT_BYTES: usize = 256 * 1024 * 1024;
const MAX_FRONTIER_NODES: usize = u64::BITS as usize;
const PREPARED_OWNER_TOKEN_FORMAT_VERSION: u16 = 1;
const PREPARED_OWNER_TOKEN_DOMAIN: &[u8] = b"KRIKOS-ID/provider-prepared-owner/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AccountIndexWire {
    account_id: AccountId,
    leaf_indices: BoundedVec<u64, MAX_STORED_PROVIDER_ENTRIES>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct FrontierNodeWire {
    level: u8,
    root: Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct MerkleNodeWire {
    start: u64,
    size: u64,
    root: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProviderCheckpointIndexWire {
    account_id: AccountId,
    greatest_sequence: Sequence,
    greatest_epoch: Epoch,
    current_checkpoint_id: Option<CheckpointId>,
    projection_heads: BoundedVec<EventId, MAX_FORK_HEADS>,
    forked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GenerationMaterialWire {
    entries: BoundedVec<ProviderLogEntryBody, MAX_STORED_PROVIDER_ENTRIES>,
    leaf_hashes: BoundedVec<Digest, MAX_STORED_PROVIDER_ENTRIES>,
    account_index: BoundedVec<AccountIndexWire, MAX_STORED_PROVIDER_ENTRIES>,
    frontier: BoundedVec<FrontierNodeWire, MAX_FRONTIER_NODES>,
    nodes: BoundedVec<MerkleNodeWire, MAX_STORED_PROVIDER_NODES>,
    checkpoint_bundles: BoundedVec<ProviderCheckpointBundleWire, MAX_STORED_PROVIDER_ENTRIES>,
    checkpoint_index: BoundedVec<ProviderCheckpointIndexWire, MAX_STORED_PROVIDER_ENTRIES>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredProviderWire {
    version: u16,
    provider: ProviderDescriptor,
    log_id: ProviderLogId,
    key_version: ProviderKeyVersion,
    latest_head: Option<SignedProviderHead>,
    compaction_manifests: BoundedVec<ProviderCompactionManifest, MAX_PROVIDER_COMPACTION_MANIFESTS>,
    payload: ProviderPayloadWire,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum ProviderPayloadWire {
    Active {
        material: GenerationMaterialWire,
        receipts: BoundedVec<InclusionReceipt, MAX_STORED_PROVIDER_ENTRIES>,
    },
    Sealed(Box<SealedProviderWire>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RetainedProviderRecordWire {
    leaf_index: u64,
    entry: ProviderLogEntryBody,
    receipt: InclusionReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SealedProviderWire {
    leaf_hashes: BoundedVec<Digest, MAX_STORED_PROVIDER_ENTRIES>,
    frontier: BoundedVec<FrontierNodeWire, MAX_FRONTIER_NODES>,
    nodes: BoundedVec<MerkleNodeWire, MAX_STORED_PROVIDER_NODES>,
    retained_records: BoundedVec<RetainedProviderRecordWire, MAX_STORED_PROVIDER_ENTRIES>,
    checkpoint_bundles: BoundedVec<ProviderCheckpointBundleWire, MAX_STORED_PROVIDER_ENTRIES>,
    checkpoint_index: BoundedVec<ProviderCheckpointIndexWire, MAX_STORED_PROVIDER_ENTRIES>,
    manifest: Option<ProviderCompactionManifest>,
    inventory: Option<ProviderRetentionInventoryWire>,
    audit_snapshot: Option<BoundedBytes<MAX_STORED_PROVIDER_AUDIT_BYTES>>,
    audit_artifacts: BoundedVec<ProviderAuditArtifactWire, MAX_STORED_PROVIDER_ENTRIES>,
    archive_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProviderRetentionItemWire {
    leaf_index: u64,
    class_code: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProviderAuditArtifactWire {
    sequence: u64,
    kind_code: u16,
    accepted_head: SignedProviderHead,
    observed_head: SignedProviderHead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProviderRetentionInventoryWire {
    tree_size: u64,
    items: BoundedVec<ProviderRetentionItemWire, MAX_STORED_PROVIDER_ENTRIES>,
    audit_artifacts: BoundedVec<ProviderAuditArtifactWire, MAX_STORED_PROVIDER_ENTRIES>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PreparedAppendWire {
    version: u16,
    owner_token: [u8; 32],
    base_tree_size: u64,
    base_tree_root: Digest,
    requested_observed_at: Timestamp,
    leaf_index: u64,
    material: GenerationMaterialWire,
    stage: PreparedAppendStage,
}

/// Durable append state.  Once a signer may have seen the exact head body, the
/// append can no longer be cancelled or replaced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum PreparedAppendStage {
    /// Candidate material exists, but no external signer has been invoked.
    Prepared,
    /// The exact head body was durably bound before invoking the signer.
    Signing { body: ProviderHeadBody },
    /// A verified signature was durably captured and awaits atomic promotion.
    Signed { head: SignedProviderHead },
}

#[derive(Serialize)]
struct PreparedOwnerTokenPreimage<'a> {
    format_version: u16,
    base_root: Digest,
    base_size: u64,
    material: &'a GenerationMaterialWire,
    leaf_index: u64,
    observed_at: Timestamp,
}

impl PreparedAppendWire {
    fn signing_body(&self) -> Result<&ProviderHeadBody, IdentityError> {
        match &self.stage {
            PreparedAppendStage::Signing { body } => Ok(body),
            PreparedAppendStage::Prepared | PreparedAppendStage::Signed { .. } => {
                Err(IdentityError::ResourceBusy)
            }
        }
    }

    fn signed_head(&self) -> Result<&SignedProviderHead, IdentityError> {
        match &self.stage {
            PreparedAppendStage::Signed { head } => Ok(head),
            PreparedAppendStage::Prepared | PreparedAppendStage::Signing { .. } => {
                Err(IdentityError::ResourceBusy)
            }
        }
    }
}

impl ProviderCheckpointBundleWire {
    fn from_retained(retained: &super::RetainedCheckpointMaterial) -> Result<Self, IdentityError> {
        Ok(Self {
            genesis: retained.genesis.clone(),
            prior_checkpoint_id: retained.prior_checkpoint_id,
            events: BoundedVec::new(
                "stored retained checkpoint lineage events",
                retained.events.clone(),
            )?,
            checkpoint: retained.checkpoint.clone(),
            transition_event: retained.transition_event.clone(),
        })
    }

    fn into_retained(self) -> super::RetainedCheckpointMaterial {
        super::RetainedCheckpointMaterial {
            genesis: self.genesis,
            prior_checkpoint_id: self.prior_checkpoint_id,
            events: self.events.into_vec(),
            checkpoint: self.checkpoint,
            transition_event: self.transition_event,
        }
    }
}

impl ProviderCheckpointIndexWire {
    fn from_index(index: &ProviderCheckpointIndex) -> Result<Self, IdentityError> {
        Ok(Self {
            account_id: index.account_id,
            greatest_sequence: index.greatest_sequence,
            greatest_epoch: index.greatest_epoch,
            current_checkpoint_id: index.current_checkpoint_id,
            projection_heads: BoundedVec::new(
                "stored provider checkpoint projection heads",
                index.projection_heads.clone(),
            )?,
            forked: index.forked,
        })
    }

    fn as_index(&self) -> ProviderCheckpointIndex {
        ProviderCheckpointIndex {
            account_id: self.account_id,
            greatest_sequence: self.greatest_sequence,
            greatest_epoch: self.greatest_epoch,
            current_checkpoint_id: self.current_checkpoint_id,
            projection_heads: self.projection_heads.as_slice().to_vec(),
            forked: self.forked,
        }
    }
}

impl RetainedProviderRecordWire {
    fn from_record(record: &super::RetainedProviderRecord) -> Self {
        Self {
            leaf_index: record.leaf_index,
            entry: record.entry.clone(),
            receipt: record.receipt.clone(),
        }
    }
}

impl ProviderAuditArtifactWire {
    fn from_artifact(artifact: &ProviderAuditArtifact) -> Self {
        Self {
            sequence: artifact.sequence(),
            kind_code: artifact.kind().code(),
            accepted_head: artifact.accepted_head().clone(),
            observed_head: artifact.observed_head().clone(),
        }
    }

    fn into_artifact(self) -> Result<ProviderAuditArtifact, IdentityError> {
        ProviderAuditArtifact::new(
            self.sequence,
            ProviderAuditArtifactKind::from_code(self.kind_code)?,
            self.accepted_head,
            self.observed_head,
        )
        .map_err(|_| IdentityError::StorageCorruption)
    }
}

impl ProviderRetentionInventoryWire {
    fn from_inventory(inventory: &ProviderRetentionInventory) -> Result<Self, IdentityError> {
        Ok(Self {
            tree_size: inventory.tree_size(),
            items: BoundedVec::new(
                "stored provider retention items",
                inventory
                    .items()
                    .iter()
                    .map(|item| ProviderRetentionItemWire {
                        leaf_index: item.leaf_index(),
                        class_code: item.class().code(),
                    })
                    .collect(),
            )?,
            audit_artifacts: BoundedVec::new(
                "stored provider retention audit artifacts",
                inventory
                    .audit_artifacts()
                    .iter()
                    .map(ProviderAuditArtifactWire::from_artifact)
                    .collect(),
            )?,
        })
    }

    fn into_inventory(self) -> Result<ProviderRetentionInventory, IdentityError> {
        let items = self
            .items
            .into_vec()
            .into_iter()
            .map(|item| {
                ProviderRetentionItem::new(
                    item.leaf_index,
                    ProviderRetentionClass::from_code(item.class_code)?,
                )
            })
            .collect::<Result<Vec<_>, IdentityError>>()?;
        let artifacts = self
            .audit_artifacts
            .into_vec()
            .into_iter()
            .map(ProviderAuditArtifactWire::into_artifact)
            .collect::<Result<Vec<_>, IdentityError>>()?;
        ProviderRetentionInventory::with_audit_artifacts(self.tree_size, items, artifacts)
            .map_err(|_| IdentityError::StorageCorruption)
    }
}

impl SealedProviderWire {
    fn from_payload(
        payload: &super::SealedProviderPayload,
        leaf_hashes: &[Digest],
    ) -> Result<Self, IdentityError> {
        let checkpoint_bundles = if payload.archive_complete {
            payload
                .checkpoint_bundles
                .iter()
                .map(ProviderCheckpointBundleWire::from_bundle)
                .collect::<Result<Vec<_>, IdentityError>>()?
        } else {
            payload
                .retained_checkpoint_evidence
                .iter()
                .map(ProviderCheckpointBundleWire::from_retained)
                .collect::<Result<Vec<_>, IdentityError>>()?
        };
        Ok(Self {
            leaf_hashes: BoundedVec::new(
                "stored sealed provider leaf hashes",
                leaf_hashes.to_vec(),
            )?,
            frontier: BoundedVec::new(
                "stored sealed provider Merkle frontier",
                build_frontier(leaf_hashes)?,
            )?,
            nodes: BoundedVec::new(
                "stored sealed provider Merkle nodes",
                build_nodes(leaf_hashes)?,
            )?,
            retained_records: BoundedVec::new(
                "stored sealed provider retained records",
                payload
                    .retained_records
                    .iter()
                    .map(RetainedProviderRecordWire::from_record)
                    .collect(),
            )?,
            checkpoint_bundles: BoundedVec::new(
                "stored sealed provider checkpoint bundles",
                checkpoint_bundles,
            )?,
            checkpoint_index: BoundedVec::new(
                "stored sealed provider checkpoint index",
                payload
                    .checkpoint_index
                    .iter()
                    .map(ProviderCheckpointIndexWire::from_index)
                    .collect::<Result<Vec<_>, IdentityError>>()?,
            )?,
            manifest: payload.manifest.clone(),
            inventory: payload
                .inventory
                .as_ref()
                .map(ProviderRetentionInventoryWire::from_inventory)
                .transpose()?,
            audit_snapshot: payload
                .audit_snapshot
                .as_ref()
                .map(crate::audit::encode_provider_audit_snapshot)
                .transpose()?
                .map(|bytes| BoundedBytes::new("stored provider archive audit snapshot", bytes))
                .transpose()?,
            audit_artifacts: BoundedVec::new(
                "stored sealed provider audit artifacts",
                payload
                    .audit_artifacts
                    .iter()
                    .map(ProviderAuditArtifactWire::from_artifact)
                    .collect(),
            )?,
            archive_complete: payload.archive_complete,
        })
    }

    fn into_parts(self) -> Result<(Vec<Digest>, super::SealedProviderPayload), IdentityError> {
        if self.frontier.as_slice() != build_frontier(self.leaf_hashes.as_slice())?
            || self.nodes.as_slice() != build_nodes(self.leaf_hashes.as_slice())?
        {
            return Err(IdentityError::StorageCorruption);
        }
        let (checkpoint_bundles, retained_checkpoint_evidence) = if self.archive_complete {
            (
                decode_checkpoint_bundles(self.checkpoint_bundles.as_slice())?,
                Vec::new(),
            )
        } else {
            (
                Vec::new(),
                self.checkpoint_bundles
                    .into_vec()
                    .into_iter()
                    .map(ProviderCheckpointBundleWire::into_retained)
                    .collect(),
            )
        };
        let checkpoint_index = self
            .checkpoint_index
            .as_slice()
            .iter()
            .map(ProviderCheckpointIndexWire::as_index)
            .collect::<Vec<_>>();
        let mut retained_records = Vec::with_capacity(self.retained_records.len());
        for wire in self.retained_records.into_vec() {
            retained_records.push(super::RetainedProviderRecord {
                leaf_index: wire.leaf_index,
                entry: wire.entry,
                receipt: wire.receipt,
            });
        }
        let inventory = self
            .inventory
            .map(ProviderRetentionInventoryWire::into_inventory)
            .transpose()?;
        let audit_snapshot = self
            .audit_snapshot
            .map(|bytes| crate::audit::decode_provider_audit_snapshot(bytes.as_slice()))
            .transpose()?;
        let audit_artifacts = self
            .audit_artifacts
            .into_vec()
            .into_iter()
            .map(ProviderAuditArtifactWire::into_artifact)
            .collect::<Result<Vec<_>, IdentityError>>()?;
        Ok((
            self.leaf_hashes.into_vec(),
            super::SealedProviderPayload {
                retained_records,
                checkpoint_bundles,
                retained_checkpoint_evidence,
                checkpoint_index,
                manifest: self.manifest,
                inventory,
                audit_snapshot,
                audit_artifacts,
                archive_complete: self.archive_complete,
            },
        ))
    }
}

fn decode_checkpoint_bundles(
    wires: &[ProviderCheckpointBundleWire],
) -> Result<Vec<ProviderCheckpointBundle>, IdentityError> {
    super::decode_provider_checkpoint_bundle_wires(wires)
        .map_err(|_| IdentityError::StorageCorruption)
}

impl GenerationMaterialWire {
    fn from_parts(
        entries: &[ProviderLogEntryBody],
        leaf_hashes: &[Digest],
        checkpoint_bundles: &[ProviderCheckpointBundle],
    ) -> Result<Self, IdentityError> {
        if entries.len() > MAX_STORED_PROVIDER_ENTRIES {
            return Err(IdentityError::limit(
                "stored provider generation entries",
                entries.len(),
                MAX_STORED_PROVIDER_ENTRIES,
            ));
        }
        if entries.len() != leaf_hashes.len() {
            return Err(IdentityError::StorageCorruption);
        }
        let checkpoint_index = super::rebuild_checkpoint_index(entries, checkpoint_bundles)?;
        Ok(Self {
            entries: BoundedVec::new("stored provider entries", entries.to_vec())?,
            leaf_hashes: BoundedVec::new("stored provider leaf hashes", leaf_hashes.to_vec())?,
            account_index: BoundedVec::new(
                "stored provider account index",
                build_account_index(entries)?,
            )?,
            frontier: BoundedVec::new(
                "stored provider Merkle frontier",
                build_frontier(leaf_hashes)?,
            )?,
            nodes: BoundedVec::new("stored provider Merkle nodes", build_nodes(leaf_hashes)?)?,
            checkpoint_bundles: BoundedVec::new(
                "stored provider checkpoint bundles",
                checkpoint_bundles
                    .iter()
                    .map(ProviderCheckpointBundleWire::from_bundle)
                    .collect::<Result<Vec<_>, IdentityError>>()?,
            )?,
            checkpoint_index: BoundedVec::new(
                "stored provider checkpoint index",
                checkpoint_index
                    .iter()
                    .map(ProviderCheckpointIndexWire::from_index)
                    .collect::<Result<Vec<_>, IdentityError>>()?,
            )?,
        })
    }

    fn validate(
        &self,
        provider: &ProviderDescriptor,
        log_id: ProviderLogId,
    ) -> Result<(), IdentityError> {
        if self.entries.len() != self.leaf_hashes.len() {
            return Err(IdentityError::StorageCorruption);
        }
        let provider_id = provider.id()?;
        for (entry, leaf_hash) in self
            .entries
            .as_slice()
            .iter()
            .zip(self.leaf_hashes.as_slice())
        {
            if entry.provider_id() != provider_id
                || entry.log_id() != log_id
                || entry.merkle_leaf_hash()? != *leaf_hash
            {
                return Err(IdentityError::StorageCorruption);
            }
        }
        let checkpoint_bundles = decode_checkpoint_bundles(self.checkpoint_bundles.as_slice())?;
        let checkpoint_index =
            super::rebuild_checkpoint_index(self.entries.as_slice(), &checkpoint_bundles)?;
        if self.account_index.as_slice() != build_account_index(self.entries.as_slice())?
            || self.frontier.as_slice() != build_frontier(self.leaf_hashes.as_slice())?
            || self.nodes.as_slice() != build_nodes(self.leaf_hashes.as_slice())?
            || self.checkpoint_index.as_slice()
                != checkpoint_index
                    .iter()
                    .map(ProviderCheckpointIndexWire::from_index)
                    .collect::<Result<Vec<_>, IdentityError>>()?
        {
            return Err(IdentityError::StorageCorruption);
        }
        Ok(())
    }
}

impl StoredProviderWire {
    fn from_state(state: &ProviderGenerationState) -> Result<Self, IdentityError> {
        state.validate_cached()?;
        let payload = match &state.payload {
            super::ProviderGenerationPayload::Active(payload) => ProviderPayloadWire::Active {
                material: GenerationMaterialWire::from_parts(
                    &payload.entries,
                    &state.leaf_hashes,
                    &payload.checkpoint_bundles,
                )?,
                receipts: BoundedVec::new("stored provider receipts", payload.receipts.clone())?,
            },
            super::ProviderGenerationPayload::Sealed(payload) => {
                ProviderPayloadWire::Sealed(Box::new(SealedProviderWire::from_payload(
                    payload,
                    &state.leaf_hashes,
                )?))
            }
        };
        Ok(Self {
            version: STORE_VERSION,
            provider: state.provider.clone(),
            log_id: state.log_id,
            key_version: state.key_version,
            latest_head: state.latest_head.clone(),
            compaction_manifests: BoundedVec::new(
                "stored provider compaction manifests",
                state.compaction_manifests.clone(),
            )?,
            payload,
        })
    }

    fn into_state(self) -> Result<ProviderGenerationState, IdentityError> {
        self.into_state_with_portable_validation(true)
    }

    fn into_state_cached(self) -> Result<ProviderGenerationState, IdentityError> {
        self.into_state_with_portable_validation(false)
    }

    fn into_state_with_portable_validation(
        self,
        validate_portable_bytes: bool,
    ) -> Result<ProviderGenerationState, IdentityError> {
        if self.version != STORE_VERSION || self.key_version != ProviderKeyVersion::GENESIS {
            return Err(IdentityError::StorageCorruption);
        }
        let (leaf_hashes, payload) = match self.payload {
            ProviderPayloadWire::Active { material, receipts } => {
                material.validate(&self.provider, self.log_id)?;
                let checkpoint_bundles =
                    decode_checkpoint_bundles(material.checkpoint_bundles.as_slice())?;
                let checkpoint_index = material
                    .checkpoint_index
                    .as_slice()
                    .iter()
                    .map(ProviderCheckpointIndexWire::as_index)
                    .collect();
                let leaf_hashes = material.leaf_hashes.into_vec();
                (
                    leaf_hashes,
                    super::ProviderGenerationPayload::Active(super::ActiveProviderPayload {
                        entries: material.entries.into_vec(),
                        receipts: receipts.into_vec(),
                        checkpoint_bundles,
                        checkpoint_index,
                    }),
                )
            }
            ProviderPayloadWire::Sealed(sealed) => {
                let (leaf_hashes, sealed) = (*sealed).into_parts()?;
                (
                    leaf_hashes,
                    super::ProviderGenerationPayload::Sealed(Box::new(sealed)),
                )
            }
        };
        let state = ProviderGenerationState {
            provider: self.provider,
            log_id: self.log_id,
            key_version: self.key_version,
            leaf_hashes,
            latest_head: self.latest_head,
            compaction_manifests: self.compaction_manifests.into_vec(),
            payload,
        };
        if validate_portable_bytes {
            state.validate()?;
        } else {
            state.validate_cached()?;
        }
        Ok(state)
    }
}

/// Redb-backed provider store with an explicit crash-recoverable signing boundary.
#[derive(Debug, Clone)]
pub struct RedbProviderStore {
    database: Arc<Database>,
    provider: ProviderDescriptor,
    log_id: ProviderLogId,
    key_version: ProviderKeyVersion,
    portable_accounting: Arc<Mutex<super::interchange::ProviderGenerationPortableAccounting>>,
}

impl RedbProviderStore {
    /// Open or create one exact provider/log/key generation and authenticate all durable indices.
    pub fn open(
        path: impl AsRef<Path>,
        provider: ProviderDescriptor,
        log_id: ProviderLogId,
        key_version: ProviderKeyVersion,
    ) -> Result<Self, IdentityError> {
        if key_version != ProviderKeyVersion::GENESIS {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider signing-key generation",
            });
        }
        let path = path.as_ref();
        crate::redb_guard::validate_existing_redb_file(path)?;
        let database = Database::create(path).map_err(|_| IdentityError::StorageCorruption)?;
        let requested = ProviderGenerationState {
            provider: provider.clone(),
            log_id,
            key_version,
            leaf_hashes: Vec::new(),
            latest_head: None,
            compaction_manifests: Vec::new(),
            payload: super::ProviderGenerationPayload::Active(super::ActiveProviderPayload {
                entries: Vec::new(),
                receipts: Vec::new(),
                checkpoint_bundles: Vec::new(),
                checkpoint_index: Vec::new(),
            }),
        };
        let write = database
            .begin_write()
            .map_err(|_| IdentityError::StorageCorruption)?;
        let stored = {
            let mut table = write
                .open_table(COMMITTED_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            let existing = table
                .get(ACTIVE_KEY)
                .map_err(|_| IdentityError::StorageCorruption)?
                .map(|value| decode_state(value.value()))
                .transpose()?;
            match existing {
                Some(state) => state,
                None => {
                    let bytes = encode_state(&requested)?;
                    table
                        .insert(ACTIVE_KEY, bytes.as_slice())
                        .map_err(|_| IdentityError::StorageCorruption)?;
                    requested
                }
            }
        };
        if stored.provider != provider
            || stored.log_id != log_id
            || stored.key_version != key_version
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider store generation",
            });
        }
        let portable_accounting = portable_accounting_for_committed_state(&stored)?;
        // Ensure read-only recovery can distinguish an empty pending slot from a missing table.
        {
            let _prepared = write
                .open_table(PREPARED_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
        }
        write
            .commit()
            .map_err(|_| IdentityError::StorageCorruption)?;
        let store = Self {
            database: Arc::new(database),
            provider,
            log_id,
            key_version,
            portable_accounting: Arc::new(Mutex::new(portable_accounting)),
        };
        store.recover_prepared_append()?;
        Ok(store)
    }

    /// Restore a complete composite recovery export as an immutable redb archive.
    ///
    /// Repeating the restore with the exact same archive is idempotent. Existing different state
    /// or any prepared append is never overwritten.
    pub fn restore_recovery(
        path: impl AsRef<Path>,
        recovery: ProviderRecoveryExport,
    ) -> Result<Self, IdentityError> {
        let state = super::recovery_archive_state(recovery)?;
        let portable_accounting = portable_accounting_for_committed_state(&state)?;
        let provider = state.provider.clone();
        let log_id = state.log_id;
        let key_version = state.key_version;
        let path = path.as_ref();
        crate::redb_guard::validate_existing_redb_file(path)?;
        let database = Database::create(path).map_err(|_| IdentityError::StorageCorruption)?;
        let write = database
            .begin_write()
            .map_err(|_| IdentityError::StorageCorruption)?;
        {
            let prepared = write
                .open_table(PREPARED_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            if prepared
                .get(PREPARED_KEY)
                .map_err(|_| IdentityError::StorageCorruption)?
                .is_some()
            {
                return Err(IdentityError::ResourceBusy);
            }
        }
        {
            let mut table = write
                .open_table(COMMITTED_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            let existing = {
                let value = table
                    .get(ACTIVE_KEY)
                    .map_err(|_| IdentityError::StorageCorruption)?;
                value
                    .map(|retained| decode_state(retained.value()))
                    .transpose()?
            };
            match existing {
                Some(existing) if existing != state => {
                    return Err(IdentityError::InvalidRelationship {
                        resource: "provider recovery archive destination",
                    });
                }
                Some(_) => {}
                None => {
                    let bytes = encode_state(&state)?;
                    table
                        .insert(ACTIVE_KEY, bytes.as_slice())
                        .map_err(|_| IdentityError::StorageCorruption)?;
                }
            }
        }
        write
            .commit()
            .map_err(|_| IdentityError::StorageCorruption)?;
        Ok(Self {
            database: Arc::new(database),
            provider,
            log_id,
            key_version,
            portable_accounting: Arc::new(Mutex::new(portable_accounting)),
        })
    }

    /// Return the complete authenticated summary of the committed generation.
    pub fn snapshot(&self) -> Result<ProviderGenerationSnapshot, IdentityError> {
        self.memory_view()?.snapshot()
    }

    /// Return this store's exact immutable provider/log/key address.
    pub fn generation_route(&self) -> Result<super::ProviderGenerationRoute, IdentityError> {
        super::ProviderGenerationRoute::new(&self.provider, self.log_id, self.key_version)
    }

    /// Serve the unique current checkpoint bundle, failing closed after retained conflict.
    pub fn latest_checkpoint_bundle(
        &self,
        account_id: AccountId,
    ) -> Result<Option<ProviderCheckpointBundle>, IdentityError> {
        self.memory_view()?.latest_checkpoint_bundle(account_id)
    }

    /// Fetch one exact retained checkpoint branch with its authenticated provider inclusion.
    pub fn checkpoint_bundle(
        &self,
        account_id: AccountId,
        checkpoint_id: CheckpointId,
    ) -> Result<Option<crate::PublishedCheckpoint>, IdentityError> {
        self.memory_view()?
            .checkpoint_bundle(account_id, checkpoint_id)
    }

    /// Fetch one bounded target-to-genesis lineage page from an explicit retained branch.
    pub fn checkpoint_lineage_page(
        &self,
        account_id: AccountId,
        start_checkpoint_id: CheckpointId,
        maximum_records: usize,
        maximum_bytes: usize,
    ) -> Result<Option<crate::ProviderCheckpointLineagePage>, IdentityError> {
        self.memory_view()?.checkpoint_lineage_page(
            account_id,
            start_checkpoint_id,
            maximum_records,
            maximum_bytes,
        )
    }

    /// Fetch raw locally retained checkpoint evidence without minting an append capability.
    pub fn retained_checkpoint_evidence(
        &self,
        account_id: AccountId,
        checkpoint_id: CheckpointId,
    ) -> Result<Option<super::ProviderRetainedCheckpointEvidence>, IdentityError> {
        self.memory_view()?
            .retained_checkpoint_evidence(account_id, checkpoint_id)
    }

    /// Fetch the unique current raw checkpoint evidence from a locally sealed generation.
    pub fn latest_retained_checkpoint_evidence(
        &self,
        account_id: AccountId,
    ) -> Result<Option<super::ProviderRetainedCheckpointEvidence>, IdentityError> {
        self.memory_view()?
            .latest_retained_checkpoint_evidence(account_id)
    }

    /// Return all non-leaf rollback/equivocation artifacts retained by a sealed generation.
    pub fn retained_audit_artifacts(&self) -> Result<Vec<ProviderAuditArtifact>, IdentityError> {
        self.memory_view()?.retained_audit_artifacts()
    }

    /// Append through durable prepare, signing-intent, signed-candidate, and visibility stages.
    pub fn append<S: ProviderHeadSigner + ?Sized>(
        &self,
        permit: ProviderAppendPermit,
        observed_at: Timestamp,
        signer: &S,
    ) -> Result<InclusionReceipt, IdentityError> {
        let prepared = self.prepare_append(permit, observed_at)?;
        let signing = self.begin_signing(prepared)?;
        let signed = self.sign_and_persist(signing, signer)?;
        self.promote_signed_prepared(signed)
    }

    /// Resume an append whose signer may already have observed the exact bound head body.
    ///
    /// A retained signing candidate is never replaced: every retry signs the same body. A
    /// durably signed candidate is promoted without another signing call.
    pub fn resume_append<S: ProviderHeadSigner + ?Sized>(
        &self,
        signer: &S,
    ) -> Result<InclusionReceipt, IdentityError> {
        if matches!(
            self.load_state()?.payload,
            super::ProviderGenerationPayload::Sealed(_)
        ) {
            return Err(IdentityError::ProviderArchiveRequired);
        }
        let prepared = self.load_prepared()?.ok_or(IdentityError::ResourceBusy)?;
        match &prepared.stage {
            PreparedAppendStage::Prepared => Err(IdentityError::ResourceBusy),
            PreparedAppendStage::Signing { .. } => {
                let signed = self.sign_and_persist(prepared, signer)?;
                self.promote_signed_prepared(signed)
            }
            PreparedAppendStage::Signed { .. } => self.promote_signed_prepared(prepared),
        }
    }

    /// Cancel only a candidate for which no signer was ever invoked.
    pub fn cancel_prepared_append(&self) -> Result<(), IdentityError> {
        if matches!(
            self.load_state()?.payload,
            super::ProviderGenerationPayload::Sealed(_)
        ) {
            return Err(IdentityError::ProviderArchiveRequired);
        }
        let write = self
            .database
            .begin_write()
            .map_err(|_| IdentityError::StorageCorruption)?;
        let removable = {
            let table = write
                .open_table(PREPARED_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            table
                .get(PREPARED_KEY)
                .map_err(|_| IdentityError::StorageCorruption)?
                .map(|value| decode_prepared(value.value()))
                .transpose()?
                .is_some_and(|prepared| matches!(prepared.stage, PreparedAppendStage::Prepared))
        };
        if !removable {
            return Err(IdentityError::ResourceBusy);
        }
        {
            let mut table = write
                .open_table(PREPARED_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            let _ = table
                .remove(PREPARED_KEY)
                .map_err(|_| IdentityError::StorageCorruption)?;
        }
        write.commit().map_err(|_| IdentityError::StorageCorruption)
    }

    /// Return a bounded account-filtered page from the durable account index.
    pub fn account_history(
        &self,
        account_id: AccountId,
        after_cursor: Option<u64>,
        maximum_records: usize,
        maximum_bytes: usize,
    ) -> Result<ProviderAccountHistoryPage, IdentityError> {
        self.memory_view()?.account_history(
            account_id,
            after_cursor,
            maximum_records,
            maximum_bytes,
        )
    }

    /// Export one complete generation after reauthenticating every durable component.
    pub fn export_generation(&self) -> Result<ProviderGenerationExport, IdentityError> {
        self.memory_view()?.export_generation()
    }

    /// Re-export the complete generation and audit journal from an immutable archive.
    pub fn archived_recovery_export(&self) -> Result<ProviderRecoveryExport, IdentityError> {
        self.memory_view()?.archived_recovery_export()
    }

    /// Return the complete audit history retained by an immutable archive.
    pub fn archived_audit_snapshot(&self) -> Result<crate::ProviderAuditSnapshot, IdentityError> {
        self.memory_view()?.archived_audit_snapshot()
    }

    /// Return every verified compaction manifest durably retained in this provider database.
    pub fn compaction_manifests(&self) -> Result<Vec<ProviderCompactionManifest>, IdentityError> {
        let state = self.load_state()?;
        state.validate_cached()?;
        Ok(state.compaction_manifests)
    }

    /// Atomically reverify and persist a compaction manifest before external release workflows.
    pub fn record_compaction_manifest(
        &self,
        authorization: &ProviderCompactionAuthorization,
        mirror: &ProviderRecoveryExport,
        inventory: &ProviderRetentionInventory,
    ) -> Result<ProviderCompactionManifest, IdentityError> {
        let mut portable_accounting = self.lock_portable_accounting()?;
        let write = self
            .database
            .begin_write()
            .map_err(|_| IdentityError::StorageCorruption)?;
        let manifest = authorization.manifest().clone();
        let mut next_portable_accounting = None;
        {
            let mut table = write
                .open_table(COMMITTED_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            let mut state = {
                let value = table
                    .get(ACTIVE_KEY)
                    .map_err(|_| IdentityError::StorageCorruption)?
                    .ok_or(IdentityError::StorageCorruption)?;
                decode_state_cached(value.value())?
            };
            if matches!(state.payload, ProviderGenerationPayload::Sealed(_)) {
                return Err(IdentityError::ProviderArchiveRequired);
            }
            if !state.compaction_manifests.contains(&manifest) {
                let mut generation = state.export()?;
                generation
                    .compaction_manifests
                    .retain(|candidate| candidate != &manifest);
                if &generation != mirror.generation() {
                    return Err(IdentityError::InvalidProof);
                }
                authorization.manifest().verify(mirror, mirror, inventory)?;
                if state.compaction_manifests.len() == MAX_PROVIDER_COMPACTION_MANIFESTS {
                    return Err(IdentityError::limit(
                        "provider compaction manifests",
                        state.compaction_manifests.len().saturating_add(1),
                        MAX_PROVIDER_COMPACTION_MANIFESTS,
                    ));
                }
                next_portable_accounting =
                    Some((*portable_accounting).with_appended_compaction_manifest(&manifest)?);
                state.compaction_manifests.push(manifest.clone());
                state.validate_cached()?;
                let bytes = encode_state(&state)?;
                table
                    .insert(ACTIVE_KEY, bytes.as_slice())
                    .map_err(|_| IdentityError::StorageCorruption)?;
            }
        }
        write
            .commit()
            .map_err(|_| IdentityError::StorageCorruption)?;
        if let Some(accounting) = next_portable_accounting {
            *portable_accounting = accounting;
        }
        Ok(manifest)
    }

    /// Atomically and irreversibly replace active material with manifest-required retained state.
    ///
    /// The exact same verified mirror/inventory replay is idempotent. A pending append prevents
    /// sealing so no prepared or already-signed candidate can cross the release boundary.
    pub fn seal_after_verified_mirror(
        &self,
        authorization: &ProviderCompactionAuthorization,
        mirror: &ProviderRecoveryExport,
        inventory: &ProviderRetentionInventory,
    ) -> Result<usize, IdentityError> {
        let write = self
            .database
            .begin_write()
            .map_err(|_| IdentityError::StorageCorruption)?;
        {
            let table = write
                .open_table(PREPARED_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            if table
                .get(PREPARED_KEY)
                .map_err(|_| IdentityError::StorageCorruption)?
                .is_some()
            {
                return Err(IdentityError::ResourceBusy);
            }
        }
        let released = {
            let mut table = write
                .open_table(COMMITTED_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            let mut state = {
                let value = table
                    .get(ACTIVE_KEY)
                    .map_err(|_| IdentityError::StorageCorruption)?
                    .ok_or(IdentityError::StorageCorruption)?;
                decode_state_cached(value.value())?
            };
            let released =
                super::seal_generation_state(&mut state, authorization, mirror, inventory)?;
            let bytes = encode_state(&state)?;
            table
                .insert(ACTIVE_KEY, bytes.as_slice())
                .map_err(|_| IdentityError::StorageCorruption)?;
            released
        };
        write
            .commit()
            .map_err(|_| IdentityError::StorageCorruption)?;
        Ok(released)
    }

    /// Serve consistency evidence between any two retained exact prefixes.
    pub fn consistency_proof(
        &self,
        old_size: u64,
        new_size: u64,
    ) -> Result<MerkleConsistencyProof, IdentityError> {
        self.memory_view()?.consistency_proof(old_size, new_size)
    }

    fn prepare_append(
        &self,
        permit: ProviderAppendPermit,
        observed_at: Timestamp,
    ) -> Result<PreparedAppendWire, IdentityError> {
        let ProviderAppendPermit { admission, request } = permit;
        request.validate_for(&admission)?;
        let _charged_bytes = request.encoded_bytes();
        admission.validate_observed_at(observed_at)?;
        let checkpoint_bundle = admission.checkpoint_bundle().cloned();
        if let Some(bundle) = checkpoint_bundle.as_ref() {
            super::interchange::validate_checkpoint_bundle_interchange_item(bundle)?;
        }
        let portable_accounting = self.lock_portable_accounting()?;
        let write = self
            .database
            .begin_write()
            .map_err(|_| IdentityError::StorageCorruption)?;
        {
            let prepared = write
                .open_table(PREPARED_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            if prepared
                .get(PREPARED_KEY)
                .map_err(|_| IdentityError::StorageCorruption)?
                .is_some()
            {
                return Err(IdentityError::ResourceBusy);
            }
        }
        let state = {
            let table = write
                .open_table(COMMITTED_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            let value = table
                .get(ACTIVE_KEY)
                .map_err(|_| IdentityError::StorageCorruption)?
                .ok_or(IdentityError::StorageCorruption)?;
            decode_state_cached(value.value())?
        };
        if state.provider != self.provider
            || state.log_id != self.log_id
            || state.key_version != self.key_version
        {
            return Err(IdentityError::StorageCorruption);
        }
        if state
            .latest_head
            .as_ref()
            .is_some_and(|head| observed_at < head.body().observed_at())
        {
            return Err(IdentityError::ProviderRollback);
        }
        let base_tree = state.tree()?;
        let mut entries = state.active()?.entries.clone();
        let mut leaf_hashes = state.leaf_hashes.clone();
        let mut checkpoint_bundles = state.active()?.checkpoint_bundles.clone();
        let duplicate_index = entries.iter().position(|entry| {
            entry.account_id() == admission.account_id() && entry.subject() == admission.subject()
        });
        let duplicate_bundle_merge = if let Some(index) = duplicate_index {
            super::merge_duplicate_bundle(&state, index, checkpoint_bundle.as_ref())?
        } else if let Some(bundle) = checkpoint_bundle.as_ref() {
            super::validate_checkpoint_admission(&state, bundle)?;
            None
        } else {
            None
        };
        if let Some((index, merged)) = duplicate_bundle_merge {
            super::interchange::validate_checkpoint_bundle_interchange_item(&merged)?;
            let retained = checkpoint_bundles
                .get_mut(index)
                .ok_or(IdentityError::StorageCorruption)?;
            *retained = merged;
        }
        let leaf_index = match duplicate_index {
            Some(index) => u64::try_from(index).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "stored provider duplicate index",
            })?,
            None => {
                if entries.len() == MAX_STORED_PROVIDER_ENTRIES
                    || entries.len() == MAX_MERKLE_LOG_LEAVES
                {
                    return Err(IdentityError::limit(
                        "stored provider generation entries",
                        entries.len().saturating_add(1),
                        MAX_STORED_PROVIDER_ENTRIES,
                    ));
                }
                let entry = ProviderLogEntryBody::new(
                    self.provider.id()?,
                    self.log_id,
                    admission.account_id(),
                    admission.subject(),
                    observed_at,
                    Extensions::default(),
                )?;
                let index = u64::try_from(entries.len()).map_err(|_| {
                    IdentityError::ArithmeticOverflow {
                        resource: "stored provider append index",
                    }
                })?;
                leaf_hashes.push(entry.merkle_leaf_hash()?);
                entries.push(entry);
                if let Some(bundle) = checkpoint_bundle {
                    checkpoint_bundles.push(bundle);
                }
                index
            }
        };
        let material =
            GenerationMaterialWire::from_parts(&entries, &leaf_hashes, &checkpoint_bundles)?;
        let base_tree_size = base_tree.tree_size()?;
        let base_tree_root = base_tree.root()?;
        let owner_token = prepared_owner_token(
            base_tree_root,
            base_tree_size,
            &material,
            leaf_index,
            observed_at,
        )?;
        let prepared = PreparedAppendWire {
            version: STORE_VERSION,
            owner_token,
            base_tree_size,
            base_tree_root,
            requested_observed_at: observed_at,
            leaf_index,
            material,
            stage: PreparedAppendStage::Prepared,
        };
        self.preflight_prepared_candidate(&prepared, &state, &portable_accounting)?;
        let bytes = encode_prepared(&prepared)?;
        {
            let mut table = write
                .open_table(PREPARED_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            table
                .insert(PREPARED_KEY, bytes.as_slice())
                .map_err(|_| IdentityError::StorageCorruption)?;
        }
        write
            .commit()
            .map_err(|_| IdentityError::StorageCorruption)?;
        Ok(prepared)
    }

    fn begin_signing(
        &self,
        prepared: PreparedAppendWire,
    ) -> Result<PreparedAppendWire, IdentityError> {
        if !matches!(prepared.stage, PreparedAppendStage::Prepared) {
            return Err(IdentityError::ResourceBusy);
        }
        let body = self.prepared_head_body(&prepared)?;
        let signing = PreparedAppendWire {
            stage: PreparedAppendStage::Signing { body },
            ..prepared.clone()
        };
        self.replace_prepared(&prepared, &signing)?;
        Ok(signing)
    }

    fn sign_and_persist<S: ProviderHeadSigner + ?Sized>(
        &self,
        signing: PreparedAppendWire,
        signer: &S,
    ) -> Result<PreparedAppendWire, IdentityError> {
        let body = signing.signing_body()?.clone();
        let signature = signer.sign_provider_head(&body.signing_bytes()?)?;
        let head = SignedProviderHead::new(body, signature);
        self.persist_signed_prepared(signing, head)
    }

    fn persist_signed_prepared(
        &self,
        signing: PreparedAppendWire,
        head: SignedProviderHead,
    ) -> Result<PreparedAppendWire, IdentityError> {
        let body = signing.signing_body()?;
        if head.body() != body {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider signed candidate body",
            });
        }
        head.verify(&self.provider)?;
        let signed = PreparedAppendWire {
            stage: PreparedAppendStage::Signed { head },
            ..signing.clone()
        };
        self.replace_prepared(&signing, &signed)?;
        Ok(signed)
    }

    fn promote_signed_prepared(
        &self,
        prepared: PreparedAppendWire,
    ) -> Result<InclusionReceipt, IdentityError> {
        let head = prepared.signed_head()?.clone();
        let mut portable_accounting = self.lock_portable_accounting()?;
        let write = self
            .database
            .begin_write()
            .map_err(|_| IdentityError::StorageCorruption)?;
        let mut state = {
            let table = write
                .open_table(COMMITTED_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            let value = table
                .get(ACTIVE_KEY)
                .map_err(|_| IdentityError::StorageCorruption)?
                .ok_or(IdentityError::StorageCorruption)?;
            decode_state_cached(value.value())?
        };
        let durable_prepared = {
            let table = write
                .open_table(PREPARED_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            let value = table
                .get(PREPARED_KEY)
                .map_err(|_| IdentityError::StorageCorruption)?
                .ok_or(IdentityError::ResourceBusy)?;
            decode_prepared(value.value())?
        };
        if durable_prepared != prepared {
            return Err(IdentityError::ResourceBusy);
        }
        let next_portable_accounting =
            self.validate_prepared_against_state(&prepared, &state, &portable_accounting)?;
        let base_tree = state.tree()?;
        if base_tree.tree_size()? != prepared.base_tree_size
            || base_tree.root()? != prepared.base_tree_root
            || head.body().observed_at() != prepared.requested_observed_at
        {
            return Err(IdentityError::ResourceBusy);
        }
        let candidate_tree = AppendOnlyMerkleLog::from_leaf_hashes(
            prepared.material.leaf_hashes.as_slice().to_vec(),
        )?;
        if head.body().tree_size() != candidate_tree.tree_size()?
            || head.body().tree_root() != candidate_tree.root()?
        {
            return Err(IdentityError::InvalidProof);
        }
        let entry_index = usize::try_from(prepared.leaf_index).map_err(|_| {
            IdentityError::ArithmeticOverflow {
                resource: "stored provider receipt index",
            }
        })?;
        let entry = prepared
            .material
            .entries
            .as_slice()
            .get(entry_index)
            .cloned()
            .ok_or(IdentityError::StorageCorruption)?;
        let receipt = InclusionReceipt::new(
            entry,
            prepared.leaf_index,
            candidate_tree
                .inclusion_proof(prepared.leaf_index)?
                .audit_path()
                .to_vec(),
            head.clone(),
        )?;
        receipt.verify(&self.provider)?;

        state.active_mut()?.entries = prepared.material.entries.into_vec();
        state.leaf_hashes = prepared.material.leaf_hashes.into_vec();
        state.active_mut()?.checkpoint_bundles =
            decode_checkpoint_bundles(prepared.material.checkpoint_bundles.as_slice())?;
        state.active_mut()?.checkpoint_index = prepared
            .material
            .checkpoint_index
            .into_vec()
            .iter()
            .map(ProviderCheckpointIndexWire::as_index)
            .collect();
        state.latest_head = Some(head);
        if entry_index < state.active()?.receipts.len() {
            state.active_mut()?.receipts[entry_index] = receipt.clone();
        } else if entry_index == state.active()?.receipts.len() {
            state.active_mut()?.receipts.push(receipt.clone());
        } else {
            return Err(IdentityError::StorageCorruption);
        }
        state.validate_cached()?;
        let bytes = encode_state(&state)?;
        {
            let mut table = write
                .open_table(COMMITTED_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            table
                .insert(ACTIVE_KEY, bytes.as_slice())
                .map_err(|_| IdentityError::StorageCorruption)?;
        }
        {
            let mut table = write
                .open_table(PREPARED_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            let _ = table
                .remove(PREPARED_KEY)
                .map_err(|_| IdentityError::StorageCorruption)?;
        }
        write
            .commit()
            .map_err(|_| IdentityError::StorageCorruption)?;
        *portable_accounting = next_portable_accounting;
        Ok(receipt)
    }

    fn replace_prepared(
        &self,
        expected: &PreparedAppendWire,
        replacement: &PreparedAppendWire,
    ) -> Result<(), IdentityError> {
        let portable_accounting = self.lock_portable_accounting()?;
        let write = self
            .database
            .begin_write()
            .map_err(|_| IdentityError::StorageCorruption)?;
        let state = {
            let table = write
                .open_table(COMMITTED_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            let value = table
                .get(ACTIVE_KEY)
                .map_err(|_| IdentityError::StorageCorruption)?
                .ok_or(IdentityError::StorageCorruption)?;
            decode_state_cached(value.value())?
        };
        self.validate_prepared_against_state(expected, &state, &portable_accounting)?;
        let matches = {
            let table = write
                .open_table(PREPARED_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            table
                .get(PREPARED_KEY)
                .map_err(|_| IdentityError::StorageCorruption)?
                .map(|value| decode_prepared(value.value()))
                .transpose()?
                .is_some_and(|prepared| prepared == *expected)
        };
        if !matches {
            return Err(IdentityError::ResourceBusy);
        }
        let bytes = encode_prepared(replacement)?;
        {
            let mut table = write
                .open_table(PREPARED_TABLE)
                .map_err(|_| IdentityError::StorageCorruption)?;
            table
                .insert(PREPARED_KEY, bytes.as_slice())
                .map_err(|_| IdentityError::StorageCorruption)?;
        }
        write.commit().map_err(|_| IdentityError::StorageCorruption)
    }

    fn prepared_head_body(
        &self,
        prepared: &PreparedAppendWire,
    ) -> Result<ProviderHeadBody, IdentityError> {
        let tree = AppendOnlyMerkleLog::from_leaf_hashes(
            prepared.material.leaf_hashes.as_slice().to_vec(),
        )?;
        ProviderHeadBody::new(
            self.provider.id()?,
            self.log_id,
            self.key_version,
            tree.tree_size()?,
            tree.root()?,
            prepared.requested_observed_at,
            Extensions::default(),
        )
    }

    fn preflight_prepared_candidate(
        &self,
        prepared: &PreparedAppendWire,
        state: &ProviderGenerationState,
        base_accounting: &super::interchange::ProviderGenerationPortableAccounting,
    ) -> Result<super::interchange::ProviderGenerationPortableAccounting, IdentityError> {
        let active = state.active()?;
        let candidate_entries = prepared.material.entries.as_slice();
        let candidate_leaf_hashes = prepared.material.leaf_hashes.as_slice();
        let candidate_bundles =
            decode_checkpoint_bundles(prepared.material.checkpoint_bundles.as_slice())?;
        let entry_index = usize::try_from(prepared.leaf_index).map_err(|_| {
            IdentityError::ArithmeticOverflow {
                resource: "stored provider portable preflight entry index",
            }
        })?;
        let candidate_tree = AppendOnlyMerkleLog::from_leaf_hashes(candidate_leaf_hashes.to_vec())?;
        let placeholder_head = SignedProviderHead::new(
            self.prepared_head_body(prepared)?,
            ProtocolSignature::ed25519([0; 64]),
        );
        let candidate_entry = candidate_entries
            .get(entry_index)
            .cloned()
            .ok_or(IdentityError::StorageCorruption)?;
        let placeholder_receipt = InclusionReceipt::new(
            candidate_entry,
            prepared.leaf_index,
            candidate_tree
                .inclusion_proof(prepared.leaf_index)?
                .audit_path()
                .to_vec(),
            placeholder_head,
        )?;

        let mut next = *base_accounting;
        if entry_index == active.entries.len() {
            let expected_len =
                active
                    .entries
                    .len()
                    .checked_add(1)
                    .ok_or(IdentityError::ArithmeticOverflow {
                        resource: "stored provider portable candidate entries",
                    })?;
            if candidate_entries.len() != expected_len
                || candidate_leaf_hashes.len() != expected_len
                || candidate_entries[..entry_index] != active.entries
                || candidate_leaf_hashes[..entry_index] != state.leaf_hashes
            {
                return Err(IdentityError::StorageCorruption);
            }
            next = next
                .with_appended_entry(&candidate_entries[entry_index])?
                .with_appended_leaf_hash(&candidate_leaf_hashes[entry_index])?
                .with_appended_receipt(&placeholder_receipt)?;
            if candidate_bundles != active.checkpoint_bundles {
                let expected_bundle_len = active.checkpoint_bundles.len().checked_add(1).ok_or(
                    IdentityError::ArithmeticOverflow {
                        resource: "stored provider portable candidate checkpoint bundles",
                    },
                )?;
                if candidate_bundles.len() != expected_bundle_len
                    || candidate_bundles[..active.checkpoint_bundles.len()]
                        != active.checkpoint_bundles
                {
                    return Err(IdentityError::StorageCorruption);
                }
                next = next.with_appended_checkpoint_bundle(
                    candidate_bundles
                        .last()
                        .ok_or(IdentityError::StorageCorruption)?,
                )?;
            }
            return Ok(next);
        }

        if entry_index >= active.entries.len()
            || candidate_entries != active.entries
            || candidate_leaf_hashes != state.leaf_hashes
            || candidate_bundles.len() != active.checkpoint_bundles.len()
        {
            return Err(IdentityError::StorageCorruption);
        }
        let previous_receipt = active
            .receipts
            .get(entry_index)
            .ok_or(IdentityError::StorageCorruption)?;
        next = next.with_replaced_receipt(previous_receipt, &placeholder_receipt)?;
        let mut changed_bundle = None;
        for (index, (previous, candidate)) in active
            .checkpoint_bundles
            .iter()
            .zip(&candidate_bundles)
            .enumerate()
        {
            if previous != candidate {
                if changed_bundle.is_some() {
                    return Err(IdentityError::StorageCorruption);
                }
                changed_bundle = Some((index, previous, candidate));
            }
        }
        if let Some((_index, previous, candidate)) = changed_bundle {
            next = next.with_replaced_checkpoint_bundle(previous, candidate)?;
        }
        Ok(next)
    }

    fn validate_prepared_against_state(
        &self,
        prepared: &PreparedAppendWire,
        state: &ProviderGenerationState,
        base_accounting: &super::interchange::ProviderGenerationPortableAccounting,
    ) -> Result<super::interchange::ProviderGenerationPortableAccounting, IdentityError> {
        if prepared.version != STORE_VERSION
            || prepared.owner_token
                != prepared_owner_token(
                    prepared.base_tree_root,
                    prepared.base_tree_size,
                    &prepared.material,
                    prepared.leaf_index,
                    prepared.requested_observed_at,
                )?
        {
            return Err(IdentityError::StorageCorruption);
        }
        prepared.material.validate(&self.provider, self.log_id)?;
        let base_tree = state.tree()?;
        if state.provider != self.provider
            || state.log_id != self.log_id
            || state.key_version != self.key_version
            || base_tree.tree_size()? != prepared.base_tree_size
            || base_tree.root()? != prepared.base_tree_root
        {
            return Err(IdentityError::StorageCorruption);
        }
        match &prepared.stage {
            PreparedAppendStage::Prepared => {}
            PreparedAppendStage::Signing { body } => {
                if body != &self.prepared_head_body(prepared)? {
                    return Err(IdentityError::StorageCorruption);
                }
            }
            PreparedAppendStage::Signed { head } => {
                if head.body() != &self.prepared_head_body(prepared)? {
                    return Err(IdentityError::StorageCorruption);
                }
                head.verify(&self.provider)
                    .map_err(|_| IdentityError::StorageCorruption)?;
            }
        }
        self.preflight_prepared_candidate(prepared, state, base_accounting)
    }

    fn load_prepared(&self) -> Result<Option<PreparedAppendWire>, IdentityError> {
        let read = self
            .database
            .begin_read()
            .map_err(|_| IdentityError::StorageCorruption)?;
        let table = read
            .open_table(PREPARED_TABLE)
            .map_err(|_| IdentityError::StorageCorruption)?;
        table
            .get(PREPARED_KEY)
            .map_err(|_| IdentityError::StorageCorruption)?
            .map(|value| decode_prepared(value.value()))
            .transpose()
    }

    fn recover_prepared_append(&self) -> Result<(), IdentityError> {
        let Some(prepared) = self.load_prepared()? else {
            return Ok(());
        };
        let state = self.load_state()?;
        if matches!(state.payload, super::ProviderGenerationPayload::Sealed(_)) {
            return Err(IdentityError::StorageCorruption);
        }
        {
            let portable_accounting = self.lock_portable_accounting()?;
            self.validate_prepared_against_state(&prepared, &state, &portable_accounting)?;
        }
        match &prepared.stage {
            PreparedAppendStage::Prepared | PreparedAppendStage::Signing { .. } => Ok(()),
            PreparedAppendStage::Signed { .. } => {
                self.promote_signed_prepared(prepared).map(|_| ())
            }
        }
    }

    fn load_state(&self) -> Result<ProviderGenerationState, IdentityError> {
        let read = self
            .database
            .begin_read()
            .map_err(|_| IdentityError::StorageCorruption)?;
        let table = read
            .open_table(COMMITTED_TABLE)
            .map_err(|_| IdentityError::StorageCorruption)?;
        let value = table
            .get(ACTIVE_KEY)
            .map_err(|_| IdentityError::StorageCorruption)?
            .ok_or(IdentityError::StorageCorruption)?;
        let state = decode_state_cached(value.value())?;
        if state.provider != self.provider
            || state.log_id != self.log_id
            || state.key_version != self.key_version
        {
            return Err(IdentityError::StorageCorruption);
        }
        Ok(state)
    }

    fn lock_portable_accounting(
        &self,
    ) -> Result<
        MutexGuard<'_, super::interchange::ProviderGenerationPortableAccounting>,
        IdentityError,
    > {
        self.portable_accounting
            .lock()
            .map_err(|_| IdentityError::StorageCorruption)
    }

    fn memory_view(&self) -> Result<MemoryProviderStore, IdentityError> {
        Ok(MemoryProviderStore {
            state: Arc::new(Mutex::new(self.load_state()?)),
            portable_accounting: Arc::clone(&self.portable_accounting),
        })
    }
}

impl super::AddressedProviderGeneration for RedbProviderStore {
    fn generation_route(&self) -> Result<super::ProviderGenerationRoute, IdentityError> {
        Self::generation_route(self)
    }
}

fn encode_state(state: &ProviderGenerationState) -> Result<Vec<u8>, IdentityError> {
    encode_bounded(&StoredProviderWire::from_state(state)?)
}

fn portable_accounting_for_committed_state(
    state: &ProviderGenerationState,
) -> Result<super::interchange::ProviderGenerationPortableAccounting, IdentityError> {
    match &state.payload {
        ProviderGenerationPayload::Sealed(sealed) if !sealed.archive_complete => {
            // A locally sealed generation deliberately has no complete portable export and is
            // irreversibly read-only. Mutation paths reject the sealed payload before consulting
            // this cache; the zero value is therefore an explicit non-mutable sentinel.
            Ok(super::interchange::ProviderGenerationPortableAccounting::empty())
        }
        ProviderGenerationPayload::Active(_) | ProviderGenerationPayload::Sealed(_) => {
            super::interchange::ProviderGenerationPortableAccounting::from_export(&state.export()?)
        }
    }
}

fn decode_state(bytes: &[u8]) -> Result<ProviderGenerationState, IdentityError> {
    decode_bounded::<StoredProviderWire>(bytes)?.into_state()
}

fn decode_state_cached(bytes: &[u8]) -> Result<ProviderGenerationState, IdentityError> {
    decode_bounded::<StoredProviderWire>(bytes)?.into_state_cached()
}

fn encode_prepared(prepared: &PreparedAppendWire) -> Result<Vec<u8>, IdentityError> {
    encode_bounded(prepared)
}

fn decode_prepared(bytes: &[u8]) -> Result<PreparedAppendWire, IdentityError> {
    let prepared = decode_bounded::<PreparedAppendWire>(bytes)?;
    if prepared.version != STORE_VERSION {
        return Err(IdentityError::StorageCorruption);
    }
    Ok(prepared)
}

fn encode_bounded<T: Serialize>(value: &T) -> Result<Vec<u8>, IdentityError> {
    let bytes = encode_wire(value).map_err(|_| IdentityError::StorageCorruption)?;
    if bytes.len() > MAX_STORED_PROVIDER_BYTES {
        return Err(IdentityError::limit(
            "stored provider generation bytes",
            bytes.len(),
            MAX_STORED_PROVIDER_BYTES,
        ));
    }
    Ok(bytes)
}

fn decode_bounded<T>(bytes: &[u8]) -> Result<T, IdentityError>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    if bytes.len() > MAX_STORED_PROVIDER_BYTES {
        return Err(IdentityError::StorageCorruption);
    }
    decode_wire(bytes).map_err(|_| IdentityError::StorageCorruption)
}

fn build_account_index(
    entries: &[ProviderLogEntryBody],
) -> Result<Vec<AccountIndexWire>, IdentityError> {
    let mut index = BTreeMap::<AccountId, Vec<u64>>::new();
    for (position, entry) in entries.iter().enumerate() {
        let leaf_index =
            u64::try_from(position).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "stored provider account index",
            })?;
        index
            .entry(entry.account_id())
            .or_default()
            .push(leaf_index);
    }
    index
        .into_iter()
        .map(|(account_id, leaf_indices)| {
            Ok(AccountIndexWire {
                account_id,
                leaf_indices: BoundedVec::new(
                    "stored provider account leaf indices",
                    leaf_indices,
                )?,
            })
        })
        .collect()
}

fn build_frontier(leaf_hashes: &[Digest]) -> Result<Vec<FrontierNodeWire>, IdentityError> {
    let mut frontier = Vec::new();
    let mut cursor = 0_usize;
    let mut remaining = leaf_hashes.len();
    while remaining != 0 {
        let level_u32 = usize::BITS
            .checked_sub(remaining.leading_zeros())
            .and_then(|bits| bits.checked_sub(1))
            .ok_or(IdentityError::ArithmeticOverflow {
                resource: "stored provider frontier level",
            })?;
        let level = u8::try_from(level_u32).map_err(|_| IdentityError::ArithmeticOverflow {
            resource: "stored provider frontier level",
        })?;
        let size =
            1_usize
                .checked_shl(u32::from(level))
                .ok_or(IdentityError::ArithmeticOverflow {
                    resource: "stored provider frontier size",
                })?;
        let end = cursor
            .checked_add(size)
            .ok_or(IdentityError::ArithmeticOverflow {
                resource: "stored provider frontier range",
            })?;
        let root =
            AppendOnlyMerkleLog::from_leaf_hashes(leaf_hashes[cursor..end].to_vec())?.root()?;
        frontier.push(FrontierNodeWire { level, root });
        cursor = end;
        remaining -= size;
    }
    Ok(frontier)
}

fn build_nodes(leaf_hashes: &[Digest]) -> Result<Vec<MerkleNodeWire>, IdentityError> {
    let mut nodes = Vec::with_capacity(leaf_hashes.len().saturating_mul(2));
    for (index, leaf_hash) in leaf_hashes.iter().copied().enumerate() {
        nodes.push(MerkleNodeWire {
            start: u64::try_from(index).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "stored provider Merkle node start",
            })?,
            size: 1,
            root: leaf_hash,
        });
        let mut size = 1_usize;
        let end = index
            .checked_add(1)
            .ok_or(IdentityError::ArithmeticOverflow {
                resource: "stored provider Merkle node range",
            })?;
        while end % size.saturating_mul(2) == 0 {
            size = size
                .checked_mul(2)
                .ok_or(IdentityError::ArithmeticOverflow {
                    resource: "stored provider Merkle node size",
                })?;
            let start = end
                .checked_sub(size)
                .ok_or(IdentityError::ArithmeticOverflow {
                    resource: "stored provider Merkle node range",
                })?;
            let root =
                AppendOnlyMerkleLog::from_leaf_hashes(leaf_hashes[start..end].to_vec())?.root()?;
            nodes.push(MerkleNodeWire {
                start: u64::try_from(start).map_err(|_| IdentityError::ArithmeticOverflow {
                    resource: "stored provider Merkle node start",
                })?,
                size: u64::try_from(size).map_err(|_| IdentityError::ArithmeticOverflow {
                    resource: "stored provider Merkle node size",
                })?,
                root,
            });
        }
    }
    if nodes.len() > MAX_STORED_PROVIDER_NODES {
        return Err(IdentityError::limit(
            "stored provider Merkle nodes",
            nodes.len(),
            MAX_STORED_PROVIDER_NODES,
        ));
    }
    Ok(nodes)
}

fn prepared_owner_token(
    base_root: Digest,
    base_size: u64,
    material: &GenerationMaterialWire,
    leaf_index: u64,
    observed_at: Timestamp,
) -> Result<[u8; 32], IdentityError> {
    let preimage = encode_wire(&PreparedOwnerTokenPreimage {
        format_version: PREPARED_OWNER_TOKEN_FORMAT_VERSION,
        base_root,
        base_size,
        material,
        leaf_index,
        observed_at,
    })
    .map_err(|_| IdentityError::StorageCorruption)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(PREPARED_OWNER_TOKEN_DOMAIN);
    hasher.update(&[0]);
    hasher.update(&preimage);
    Ok(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use krikos_base::SecretKey;

    use super::*;
    use crate::{
        CanonicalWire, DurableProviderAuditor, HashAlgorithm, MemoryProviderAuditStore, ProposalId,
        ProtocolSignature, ProviderAdmissionRequest, ProviderAppendPermit, ProviderLogAdmission,
        ProviderRecoveryExport, SigningPublicKey,
    };

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct ManifestRangeMirror {
        start: u64,
        end_exclusive: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct ManifestMirror {
        format_version: u16,
        provider_id: crate::ProviderId,
        log_id: ProviderLogId,
        key_version: ProviderKeyVersion,
        source_tree_size: u64,
        source_tree_root: Digest,
        archive_commitment: Digest,
        generation_commitment: Digest,
        audit_commitment: Digest,
        audit_artifact_commitment: Digest,
        inventory_commitment: Digest,
        retained_evidence_commitment: Digest,
        retained_ranges: Vec<ManifestRangeMirror>,
    }

    struct Signer(SecretKey);

    impl ProviderHeadSigner for Signer {
        fn sign_provider_head(&self, message: &[u8]) -> Result<ProtocolSignature, IdentityError> {
            Ok(ProtocolSignature::ed25519(self.0.sign(message).to_bytes()))
        }
    }

    fn typed_id<T: CanonicalWire>(fill: u8) -> T {
        let digest = Digest::new(HashAlgorithm::Blake3_256, [fill; 32]);
        T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
    }

    fn sealed_guardian_wire() -> StoredProviderWire {
        let signer = Signer(SecretKey::from_bytes(&[0x91; 32]));
        let provider = ProviderDescriptor::new(
            SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
            Extensions::default(),
        )
        .unwrap();
        let log_id = typed_id::<ProviderLogId>(0x92);
        let store = MemoryProviderStore::new(provider.clone(), log_id, ProviderKeyVersion::GENESIS)
            .unwrap();
        for (account_fill, proposal_fill, observed_at) in
            [(0x93, 0x94, 90_u64), (0x95, 0x96, 91_u64)]
        {
            let admission = ProviderLogAdmission::guardian_recovery_intent(
                typed_id::<AccountId>(account_fill),
                typed_id::<ProposalId>(proposal_fill),
                Timestamp::from_unix_millis(observed_at),
            );
            let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
            store
                .append(
                    ProviderAppendPermit { admission, request },
                    Timestamp::from_unix_millis(observed_at),
                    &signer,
                )
                .unwrap();
        }
        let generation = store.export_generation().unwrap();
        let audit_store = MemoryProviderAuditStore::new(provider, log_id);
        let auditor = DurableProviderAuditor::new(audit_store.clone());
        auditor
            .observe(generation.latest_head().unwrap().clone(), None)
            .unwrap();
        let recovery =
            ProviderRecoveryExport::new(generation, audit_store.snapshot().unwrap()).unwrap();
        let inventory = crate::derive_provider_retention_inventory(&recovery).unwrap();
        let authorization =
            crate::verify_provider_compaction(&recovery, &recovery, &inventory).unwrap();
        store
            .seal_after_verified_mirror(&authorization, &recovery, &inventory)
            .unwrap();
        StoredProviderWire::from_state(&store.lock_state().unwrap()).unwrap()
    }

    fn active_guardian_wire() -> StoredProviderWire {
        let signer = Signer(SecretKey::from_bytes(&[0x97; 32]));
        let provider = ProviderDescriptor::new(
            SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
            Extensions::default(),
        )
        .unwrap();
        let log_id = typed_id::<ProviderLogId>(0x98);
        let store =
            MemoryProviderStore::new(provider, log_id, ProviderKeyVersion::GENESIS).unwrap();
        let observed_at = Timestamp::from_unix_millis(92);
        let admission = ProviderLogAdmission::guardian_recovery_intent(
            typed_id::<AccountId>(0x99),
            typed_id::<ProposalId>(0x9a),
            observed_at,
        );
        let request = ProviderAdmissionRequest::for_admission(&admission).unwrap();
        store
            .append(
                ProviderAppendPermit { admission, request },
                observed_at,
                &signer,
            )
            .unwrap();
        StoredProviderWire::from_state(&store.lock_state().unwrap()).unwrap()
    }

    fn mutate_manifest(wire: &mut StoredProviderWire, mutate: impl FnOnce(&mut ManifestMirror)) {
        let ProviderPayloadWire::Sealed(sealed) = &mut wire.payload else {
            panic!("sealed test fixture");
        };
        let manifest = sealed.manifest.as_ref().unwrap();
        let mut mirror: ManifestMirror = decode_wire(&encode_wire(manifest).unwrap()).unwrap();
        mutate(&mut mirror);
        sealed.manifest = Some(
            decode_wire(&encode_wire(&mirror).unwrap())
                .expect("mutated manifest remains structurally decodable"),
        );
    }

    fn assert_wire_corruption(wire: StoredProviderWire) {
        assert_eq!(wire.into_state(), Err(IdentityError::StorageCorruption));
    }

    #[test]
    fn sealed_wire_reopen_recomputes_manifest_inventory_ranges_and_state_kind() {
        let wire = sealed_guardian_wire();
        wire.clone().into_state().unwrap();
        let changed = Digest::new(HashAlgorithm::Blake3_256, [0xee; 32]);

        macro_rules! assert_manifest_field_corruption {
            ($field:ident) => {{
                let mut corrupt = wire.clone();
                mutate_manifest(&mut corrupt, |manifest| manifest.$field = changed);
                assert_wire_corruption(corrupt);
            }};
        }
        assert_manifest_field_corruption!(archive_commitment);
        assert_manifest_field_corruption!(generation_commitment);
        assert_manifest_field_corruption!(audit_commitment);
        assert_manifest_field_corruption!(audit_artifact_commitment);
        assert_manifest_field_corruption!(inventory_commitment);
        assert_manifest_field_corruption!(retained_evidence_commitment);

        let mut corrupt_range = wire.clone();
        mutate_manifest(&mut corrupt_range, |manifest| {
            manifest.retained_ranges[0].end_exclusive =
                manifest.retained_ranges[0].end_exclusive.saturating_sub(1);
        });
        assert_wire_corruption(corrupt_range);

        let mut corrupt_inventory = wire.clone();
        let ProviderPayloadWire::Sealed(sealed) = &mut corrupt_inventory.payload else {
            panic!("sealed test fixture");
        };
        let inventory = sealed.inventory.as_mut().unwrap();
        let mut items = inventory.items.clone().into_vec();
        items[0].class_code = ProviderRetentionClass::ProviderRotation.code();
        inventory.items = BoundedVec::new("test changed retention inventory", items).unwrap();
        assert_wire_corruption(corrupt_inventory);

        let mut corrupt_kind = wire;
        let ProviderPayloadWire::Sealed(sealed) = &mut corrupt_kind.payload else {
            panic!("sealed test fixture");
        };
        sealed.archive_complete = true;
        assert_wire_corruption(corrupt_kind);
    }

    #[test]
    fn active_wire_rejects_entry_head_key_receipt_and_truncation_faults() {
        let wire = active_guardian_wire();
        wire.clone().into_state().unwrap();

        let mut corrupt_entry = wire.clone();
        let ProviderPayloadWire::Active { material, .. } = &mut corrupt_entry.payload else {
            panic!("active test fixture");
        };
        let mut entries = material.entries.clone().into_vec();
        let entry = &entries[0];
        entries[0] = ProviderLogEntryBody::new(
            entry.provider_id(),
            entry.log_id(),
            entry.account_id(),
            entry.subject(),
            Timestamp::from_unix_millis(entry.observed_at().as_unix_millis().saturating_add(1)),
            Extensions::default(),
        )
        .unwrap();
        material.entries = BoundedVec::new("test corrupt provider entry", entries).unwrap();
        assert_wire_corruption(corrupt_entry);

        let mut corrupt_head = wire.clone();
        corrupt_head.latest_head = None;
        assert_wire_corruption(corrupt_head);

        let mut corrupt_key = wire.clone();
        corrupt_key.key_version = ProviderKeyVersion::GENESIS.checked_next().unwrap();
        assert_wire_corruption(corrupt_key);

        let mut corrupt_receipt = wire.clone();
        let ProviderPayloadWire::Active { receipts, .. } = &mut corrupt_receipt.payload else {
            panic!("active test fixture");
        };
        *receipts = BoundedVec::new("test corrupt provider receipts", Vec::new()).unwrap();
        assert_wire_corruption(corrupt_receipt);

        let bytes = encode_bounded(&wire).unwrap();
        for truncated_length in [0, 1, bytes.len() / 2, bytes.len() - 1] {
            assert_eq!(
                decode_state(&bytes[..truncated_length]),
                Err(IdentityError::StorageCorruption)
            );
        }
    }

    #[test]
    fn material_validation_rejects_each_persisted_derived_component() {
        let signer = Signer(SecretKey::from_bytes(&[0xc1; 32]));
        let provider = ProviderDescriptor::new(
            SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
            Extensions::default(),
        )
        .unwrap();
        let log_id = typed_id::<ProviderLogId>(0xc2);
        let entry = ProviderLogEntryBody::new(
            provider.id().unwrap(),
            log_id,
            typed_id::<AccountId>(0xc3),
            crate::ProviderLogSubject::EventIntent(typed_id::<ProposalId>(0xc4)),
            Timestamp::from_unix_millis(70),
            Extensions::default(),
        )
        .unwrap();
        let leaf_hash = entry.merkle_leaf_hash().unwrap();
        let material = GenerationMaterialWire::from_parts(&[entry], &[leaf_hash], &[]).unwrap();
        material.validate(&provider, log_id).unwrap();
        assert_eq!(material.account_index.len(), 1);
        assert_eq!(material.frontier.len(), 1);
        assert_eq!(material.nodes.len(), 1);

        let mut corrupt_index = material.clone();
        corrupt_index.account_index =
            BoundedVec::new("test corrupt account index", Vec::new()).unwrap();
        assert_eq!(
            corrupt_index.validate(&provider, log_id),
            Err(IdentityError::StorageCorruption)
        );

        let mut corrupt_frontier = material.clone();
        corrupt_frontier.frontier = BoundedVec::new("test corrupt frontier", Vec::new()).unwrap();
        assert_eq!(
            corrupt_frontier.validate(&provider, log_id),
            Err(IdentityError::StorageCorruption)
        );

        let mut corrupt_nodes = material.clone();
        corrupt_nodes.nodes = BoundedVec::new("test corrupt nodes", Vec::new()).unwrap();
        assert_eq!(
            corrupt_nodes.validate(&provider, log_id),
            Err(IdentityError::StorageCorruption)
        );

        let mut corrupt_leaf = material;
        corrupt_leaf.leaf_hashes = BoundedVec::new(
            "test corrupt leaf hash",
            vec![Digest::new(HashAlgorithm::Blake3_256, [0xff; 32])],
        )
        .unwrap();
        assert_eq!(
            corrupt_leaf.validate(&provider, log_id),
            Err(IdentityError::StorageCorruption)
        );
    }

    #[test]
    fn prepared_owner_token_uses_a_versioned_canonical_domain_preimage() {
        let material = GenerationMaterialWire::from_parts(&[], &[], &[]).unwrap();
        let base_root = Digest::new(HashAlgorithm::Blake3_256, [0xa5; 32]);
        let base_size = 0_u64;
        let leaf_index = 0_u64;
        let observed_at = Timestamp::from_unix_millis(73);
        let canonical_preimage = encode_wire(&(
            1_u16,
            base_root,
            base_size,
            &material,
            leaf_index,
            observed_at,
        ))
        .unwrap();
        let mut expected_hasher = blake3::Hasher::new();
        expected_hasher.update(b"KRIKOS-ID/provider-prepared-owner/v1");
        expected_hasher.update(&[0]);
        expected_hasher.update(&canonical_preimage);
        let expected = *expected_hasher.finalize().as_bytes();

        let actual =
            prepared_owner_token(base_root, base_size, &material, leaf_index, observed_at).unwrap();
        assert_eq!(actual, expected);

        let material_bytes = encode_wire(&material).unwrap();
        let mut legacy_hasher = blake3::Hasher::new();
        legacy_hasher.update(b"KRIKOS-ID/provider-prepared-owner/v2");
        legacy_hasher.update(base_root.as_bytes());
        legacy_hasher.update(&base_size.to_le_bytes());
        legacy_hasher.update(&u64::try_from(material_bytes.len()).unwrap().to_le_bytes());
        legacy_hasher.update(&material_bytes);
        legacy_hasher.update(&leaf_index.to_le_bytes());
        legacy_hasher.update(&observed_at.as_unix_millis().to_le_bytes());
        assert_ne!(actual, *legacy_hasher.finalize().as_bytes());
    }

    #[test]
    fn transient_store_version_six_is_rejected_explicitly() {
        let mut wire = active_guardian_wire();
        wire.version = 6;
        assert_wire_corruption(wire);
    }

    #[test]
    fn transient_prepared_version_six_is_rejected_explicitly() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("provider-prepared-version.redb");
        let signer = Signer(SecretKey::from_bytes(&[0xaa; 32]));
        let provider = ProviderDescriptor::new(
            SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
            Extensions::default(),
        )
        .unwrap();
        let log_id = typed_id::<ProviderLogId>(0xab);
        let observed_at = Timestamp::from_unix_millis(74);
        let store =
            RedbProviderStore::open(&path, provider, log_id, ProviderKeyVersion::GENESIS).unwrap();
        let mut prepared = store
            .prepare_append(
                ProviderAppendPermit {
                    admission: ProviderLogAdmission::guardian_recovery_intent(
                        typed_id::<AccountId>(0xac),
                        typed_id::<ProposalId>(0xad),
                        observed_at,
                    ),
                    request: ProviderAdmissionRequest::new(128).unwrap(),
                },
                observed_at,
            )
            .unwrap();
        prepared.version = 6;
        assert_eq!(
            decode_prepared(&encode_bounded(&prepared).unwrap()),
            Err(IdentityError::StorageCorruption)
        );
    }

    #[test]
    fn reopen_rejects_multi_entry_prepared_candidate_without_partial_commit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("provider-prepared-multi-entry.redb");
        let signer = Signer(SecretKey::from_bytes(&[0xae; 32]));
        let provider = ProviderDescriptor::new(
            SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
            Extensions::default(),
        )
        .unwrap();
        let log_id = typed_id::<ProviderLogId>(0xaf);
        let observed_at = Timestamp::from_unix_millis(75);
        {
            let store = RedbProviderStore::open(
                &path,
                provider.clone(),
                log_id,
                ProviderKeyVersion::GENESIS,
            )
            .unwrap();
            let mut prepared = store
                .prepare_append(
                    ProviderAppendPermit {
                        admission: ProviderLogAdmission::guardian_recovery_intent(
                            typed_id::<AccountId>(0xb0),
                            typed_id::<ProposalId>(0xb1),
                            observed_at,
                        ),
                        request: ProviderAdmissionRequest::new(128).unwrap(),
                    },
                    observed_at,
                )
                .unwrap();
            let mut entries = prepared.material.entries.as_slice().to_vec();
            let second = ProviderLogEntryBody::new(
                provider.id().unwrap(),
                log_id,
                typed_id::<AccountId>(0xb2),
                crate::ProviderLogSubject::EventIntent(typed_id::<ProposalId>(0xb3)),
                observed_at,
                Extensions::default(),
            )
            .unwrap();
            let mut leaf_hashes = prepared.material.leaf_hashes.as_slice().to_vec();
            leaf_hashes.push(second.merkle_leaf_hash().unwrap());
            entries.push(second);
            prepared.material =
                GenerationMaterialWire::from_parts(&entries, &leaf_hashes, &[]).unwrap();
            prepared.owner_token = prepared_owner_token(
                prepared.base_tree_root,
                prepared.base_tree_size,
                &prepared.material,
                prepared.leaf_index,
                prepared.requested_observed_at,
            )
            .unwrap();
            let bytes = encode_prepared(&prepared).unwrap();
            let write = store.database.begin_write().unwrap();
            {
                let mut table = write.open_table(PREPARED_TABLE).unwrap();
                table.insert(PREPARED_KEY, bytes.as_slice()).unwrap();
            }
            write.commit().unwrap();
            assert_eq!(store.snapshot().unwrap().tree_size(), 0);
        }

        assert!(matches!(
            RedbProviderStore::open(&path, provider, log_id, ProviderKeyVersion::GENESIS,),
            Err(IdentityError::StorageCorruption)
        ));
        let database = Database::create(&path).unwrap();
        let read = database.begin_read().unwrap();
        let table = read.open_table(COMMITTED_TABLE).unwrap();
        let state = decode_state(table.get(ACTIVE_KEY).unwrap().unwrap().value()).unwrap();
        assert_eq!(state.snapshot().unwrap().tree_size(), 0);
    }

    #[test]
    fn exact_guardian_observation_time_is_checked_before_redb_prepare() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("provider.redb");
        let signer = Signer(SecretKey::from_bytes(&[0xb1; 32]));
        let provider = ProviderDescriptor::new(
            SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
            Extensions::default(),
        )
        .unwrap();
        let log_id = typed_id::<ProviderLogId>(0xb2);
        let admission = ProviderLogAdmission::guardian_recovery_intent(
            typed_id::<AccountId>(0xb3),
            typed_id::<ProposalId>(0xb4),
            Timestamp::from_unix_millis(60),
        );
        let request = ProviderAdmissionRequest::new(128).unwrap();
        {
            let store = RedbProviderStore::open(
                &path,
                provider.clone(),
                log_id,
                ProviderKeyVersion::GENESIS,
            )
            .unwrap();
            let permit = ProviderAppendPermit {
                admission: admission.clone(),
                request,
            };
            assert_eq!(
                store.append(permit, Timestamp::from_unix_millis(61), &signer),
                Err(IdentityError::InvalidRelationship {
                    resource: "provider admission observation time",
                })
            );
            assert_eq!(store.snapshot().unwrap().tree_size(), 0);
        }
        let reopened =
            RedbProviderStore::open(&path, provider, log_id, ProviderKeyVersion::GENESIS).unwrap();
        assert_eq!(reopened.snapshot().unwrap().tree_size(), 0);
        reopened
            .append(
                ProviderAppendPermit { admission, request },
                Timestamp::from_unix_millis(60),
                &signer,
            )
            .unwrap();
        assert_eq!(reopened.snapshot().unwrap().tree_size(), 1);
    }

    #[test]
    fn reopen_promotes_a_durably_signed_candidate_without_reinvoking_signer() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("provider.redb");
        let signer = Signer(SecretKey::from_bytes(&[0xd1; 32]));
        let provider = ProviderDescriptor::new(
            SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
            Extensions::default(),
        )
        .unwrap();
        let log_id = typed_id::<ProviderLogId>(0xd2);
        let observed_at = Timestamp::from_unix_millis(80);
        let admission = ProviderLogAdmission::guardian_recovery_intent(
            typed_id::<AccountId>(0xd3),
            typed_id::<ProposalId>(0xd4),
            observed_at,
        );
        {
            let store = RedbProviderStore::open(
                &path,
                provider.clone(),
                log_id,
                ProviderKeyVersion::GENESIS,
            )
            .unwrap();
            let prepared = store
                .prepare_append(
                    ProviderAppendPermit {
                        admission,
                        request: ProviderAdmissionRequest::new(128).unwrap(),
                    },
                    observed_at,
                )
                .unwrap();
            let signing = store.begin_signing(prepared).unwrap();
            let body = signing.signing_body().unwrap().clone();
            let signature = signer
                .sign_provider_head(&body.signing_bytes().unwrap())
                .unwrap();
            store
                .persist_signed_prepared(signing, SignedProviderHead::new(body, signature))
                .unwrap();
        }
        let reopened =
            RedbProviderStore::open(&path, provider, log_id, ProviderKeyVersion::GENESIS).unwrap();
        assert_eq!(reopened.snapshot().unwrap().tree_size(), 1);
    }

    #[test]
    fn reopen_retains_unstarted_candidate_until_explicit_cancellation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("provider.redb");
        let signer = Signer(SecretKey::from_bytes(&[0xe1; 32]));
        let provider = ProviderDescriptor::new(
            SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
            Extensions::default(),
        )
        .unwrap();
        let log_id = typed_id::<ProviderLogId>(0xe2);
        let observed_at = Timestamp::from_unix_millis(81);
        {
            let store = RedbProviderStore::open(
                &path,
                provider.clone(),
                log_id,
                ProviderKeyVersion::GENESIS,
            )
            .unwrap();
            store
                .prepare_append(
                    ProviderAppendPermit {
                        admission: ProviderLogAdmission::guardian_recovery_intent(
                            typed_id::<AccountId>(0xe3),
                            typed_id::<ProposalId>(0xe4),
                            observed_at,
                        ),
                        request: ProviderAdmissionRequest::new(128).unwrap(),
                    },
                    observed_at,
                )
                .unwrap();
            super::super::interchange::reset_portable_item_encoding_count();
        }
        let reopened =
            RedbProviderStore::open(&path, provider, log_id, ProviderKeyVersion::GENESIS).unwrap();
        assert_eq!(
            super::super::interchange::portable_item_encoding_count(),
            3,
            "reopen must rerun the exact prepared entry/leaf/receipt portability preflight"
        );
        assert!(matches!(
            reopened.load_prepared().unwrap().unwrap().stage,
            PreparedAppendStage::Prepared
        ));
        assert_eq!(reopened.snapshot().unwrap().tree_size(), 0);
        reopened.cancel_prepared_append().unwrap();
        assert!(reopened.load_prepared().unwrap().is_none());
    }

    #[test]
    fn signing_candidate_survives_signer_failure_and_wrong_signer_retry() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("provider.redb");
        let signer = Signer(SecretKey::from_bytes(&[0xf1; 32]));
        let wrong_signer = Signer(SecretKey::from_bytes(&[0xf2; 32]));
        let provider = ProviderDescriptor::new(
            SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
            Extensions::default(),
        )
        .unwrap();
        let log_id = typed_id::<ProviderLogId>(0xf3);
        let observed_at = Timestamp::from_unix_millis(82);
        let expected_body = {
            let store = RedbProviderStore::open(
                &path,
                provider.clone(),
                log_id,
                ProviderKeyVersion::GENESIS,
            )
            .unwrap();
            let prepared = store
                .prepare_append(
                    ProviderAppendPermit {
                        admission: ProviderLogAdmission::guardian_recovery_intent(
                            typed_id::<AccountId>(0xf4),
                            typed_id::<ProposalId>(0xf5),
                            observed_at,
                        ),
                        request: ProviderAdmissionRequest::new(128).unwrap(),
                    },
                    observed_at,
                )
                .unwrap();
            store
                .begin_signing(prepared)
                .unwrap()
                .signing_body()
                .unwrap()
                .clone()
        };
        let reopened =
            RedbProviderStore::open(&path, provider, log_id, ProviderKeyVersion::GENESIS).unwrap();
        assert!(reopened.resume_append(&wrong_signer).is_err());
        let retained = reopened.load_prepared().unwrap().unwrap();
        assert_eq!(retained.signing_body().unwrap(), &expected_body);
        assert!(matches!(
            retained.stage,
            PreparedAppendStage::Signing { .. }
        ));
        assert_eq!(reopened.resume_append(&signer).unwrap().leaf_index(), 0);
        assert_eq!(reopened.snapshot().unwrap().tree_size(), 1);
    }

    #[test]
    fn signer_return_before_signed_persistence_recovers_from_bound_signing_candidate() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("provider.redb");
        let signer = Signer(SecretKey::from_bytes(&[0xa1; 32]));
        let provider = ProviderDescriptor::new(
            SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
            Extensions::default(),
        )
        .unwrap();
        let log_id = typed_id::<ProviderLogId>(0xa2);
        let observed_at = Timestamp::from_unix_millis(83);
        {
            let store = RedbProviderStore::open(
                &path,
                provider.clone(),
                log_id,
                ProviderKeyVersion::GENESIS,
            )
            .unwrap();
            let prepared = store
                .prepare_append(
                    ProviderAppendPermit {
                        admission: ProviderLogAdmission::guardian_recovery_intent(
                            typed_id::<AccountId>(0xa3),
                            typed_id::<ProposalId>(0xa4),
                            observed_at,
                        ),
                        request: ProviderAdmissionRequest::new(128).unwrap(),
                    },
                    observed_at,
                )
                .unwrap();
            let signing = store.begin_signing(prepared).unwrap();
            let _externally_obtained_but_unpublished_signature = signer
                .sign_provider_head(&signing.signing_body().unwrap().signing_bytes().unwrap())
                .unwrap();
            // Simulate process death after the signer returned but before the signed candidate
            // transaction. The durable Signing record binds the only valid retry body.
        }
        let reopened =
            RedbProviderStore::open(&path, provider, log_id, ProviderKeyVersion::GENESIS).unwrap();
        assert_eq!(reopened.resume_append(&signer).unwrap().leaf_index(), 0);
        assert_eq!(reopened.snapshot().unwrap().tree_size(), 1);
    }
}
