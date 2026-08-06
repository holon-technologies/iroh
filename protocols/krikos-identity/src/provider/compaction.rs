//! Verified provider compaction manifests and retention inventories.

use serde::{Deserialize, Serialize};

use super::{
    MemoryProviderStore, ProviderGenerationExport, ProviderRecoveryExport,
    provider_audit_artifact_commitment, provider_commitment, provider_recovery_commitment,
    rebuild_checkpoint_index, retained_provider_evidence_commitment,
};
use crate::{
    AccountGenesis, AuthorizedEvent, CheckpointId, Digest, HashAlgorithm, IdentityError,
    InclusionReceipt, OperationKind, ProviderAuditArtifact, ProviderDescriptor, ProviderId,
    ProviderKeyVersion, ProviderLogEntryBody, ProviderLogId, ProviderLogSubject, SignedCheckpoint,
    SignedProviderHead,
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
    limits::MAX_MERKLE_LOG_LEAVES,
    schema::BoundedVec,
};

const MAX_PROVIDER_AUDIT_ARTIFACTS: usize = 65_536;
const MAX_PROVIDER_COMPACTION_MANIFEST_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROVIDER_WIRE_RETAINED_RANGES: usize = 4_096;
const PROVIDER_GENERATION_EXPORT_COMMITMENT_DOMAIN: &[u8] =
    b"KRIKOS-ID/provider-generation-export/v1";
const PROVIDER_RETENTION_INVENTORY_COMMITMENT_DOMAIN: &[u8] =
    b"KRIKOS-ID/provider-retention-inventory/v1";

#[derive(Serialize)]
struct ProviderCheckpointBundleCommitmentWire<'a> {
    genesis: Option<&'a AccountGenesis>,
    prior_checkpoint_id: Option<CheckpointId>,
    events: &'a [AuthorizedEvent],
    checkpoint: &'a SignedCheckpoint,
    transition_event: Option<&'a AuthorizedEvent>,
}

#[derive(Serialize)]
struct ProviderGenerationExportCommitmentWire<'a> {
    format_version: u16,
    provider: &'a ProviderDescriptor,
    log_id: ProviderLogId,
    key_version: ProviderKeyVersion,
    entries: &'a [ProviderLogEntryBody],
    leaf_hashes: &'a [Digest],
    latest_head: Option<&'a SignedProviderHead>,
    receipts: &'a [InclusionReceipt],
    checkpoint_bundles: Vec<ProviderCheckpointBundleCommitmentWire<'a>>,
    compaction_manifests: &'a [ProviderCompactionManifest],
}

#[derive(Serialize)]
struct ProviderRetentionItemCommitmentWire {
    leaf_index: u64,
    class_code: u16,
}

#[derive(Serialize)]
struct ProviderRetentionInventoryCommitmentWire {
    format_version: u16,
    tree_size: u64,
    items: Vec<ProviderRetentionItemCommitmentWire>,
    audit_artifact_commitments: Vec<Digest>,
}

/// Evidence class explaining why a provider-log leaf must remain available after compaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProviderRetentionClass {
    /// Current checkpoint tip, or every branch while the account remains forked.
    CheckpointLineage,
    /// Controller removal or retirement tombstone.
    ControllerTombstone,
    /// Device revocation or replacement tombstone.
    DeviceTombstone,
    /// Evidence belonging to an unresolved account fork.
    UnresolvedFork,
    /// Pending, dual, retired, or aborted cryptographic migration evidence.
    CryptoMigration,
    /// Pending or completed recovery lineage.
    Recovery,
    /// Provider signing-key or log-generation rotation evidence.
    ProviderRotation,
    /// Known signed provider equivocation evidence.
    Equivocation,
}

impl ProviderRetentionClass {
    pub(crate) const fn code(self) -> u16 {
        match self {
            Self::CheckpointLineage => 1,
            Self::ControllerTombstone => 2,
            Self::DeviceTombstone => 3,
            Self::UnresolvedFork => 4,
            Self::CryptoMigration => 5,
            Self::Recovery => 6,
            Self::ProviderRotation => 7,
            Self::Equivocation => 8,
        }
    }

    #[cfg(feature = "provider-store")]
    pub(crate) fn from_code(code: u16) -> Result<Self, IdentityError> {
        match code {
            1 => Ok(Self::CheckpointLineage),
            2 => Ok(Self::ControllerTombstone),
            3 => Ok(Self::DeviceTombstone),
            4 => Ok(Self::UnresolvedFork),
            5 => Ok(Self::CryptoMigration),
            6 => Ok(Self::Recovery),
            7 => Ok(Self::ProviderRotation),
            8 => Ok(Self::Equivocation),
            _ => Err(IdentityError::StorageCorruption),
        }
    }
}

/// One exact leaf required by an authenticated retention class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderRetentionItem {
    leaf_index: u64,
    class: ProviderRetentionClass,
}

impl ProviderRetentionItem {
    /// Name one bounded provider-wide leaf and its retention reason.
    pub fn new(leaf_index: u64, class: ProviderRetentionClass) -> Result<Self, IdentityError> {
        let index = usize::try_from(leaf_index).map_err(|_| IdentityError::LimitExceeded {
            resource: "provider retention leaf index",
            actual: usize::MAX,
            maximum: MAX_MERKLE_LOG_LEAVES,
        })?;
        if index >= MAX_MERKLE_LOG_LEAVES {
            return Err(IdentityError::limit(
                "provider retention leaf index",
                index.saturating_add(1),
                MAX_MERKLE_LOG_LEAVES,
            ));
        }
        Ok(Self { leaf_index, class })
    }

    /// Provider-wide zero-based leaf index.
    pub const fn leaf_index(self) -> u64 {
        self.leaf_index
    }

    /// Authenticated reason this leaf remains retained.
    pub const fn class(self) -> ProviderRetentionClass {
        self.class
    }
}

/// Complete sorted retention inventory for one exact source tree size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRetentionInventory {
    tree_size: u64,
    items: Vec<ProviderRetentionItem>,
    audit_artifacts: Vec<ProviderAuditArtifact>,
}

impl ProviderRetentionInventory {
    /// Validate, sort, and deduplicate the caller's complete retained-evidence inventory.
    pub fn new(tree_size: u64, items: Vec<ProviderRetentionItem>) -> Result<Self, IdentityError> {
        Self::with_audit_artifacts(tree_size, items, Vec::new())
    }

    /// Validate all leaf reasons and sorted non-leaf rollback/equivocation artifacts.
    pub fn with_audit_artifacts(
        tree_size: u64,
        mut items: Vec<ProviderRetentionItem>,
        mut audit_artifacts: Vec<ProviderAuditArtifact>,
    ) -> Result<Self, IdentityError> {
        if tree_size > MAX_MERKLE_LOG_LEAVES as u64 {
            return Err(IdentityError::limit(
                "provider compaction tree size",
                usize::try_from(tree_size).unwrap_or(usize::MAX),
                MAX_MERKLE_LOG_LEAVES,
            ));
        }
        items.sort_unstable();
        if items.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(IdentityError::DuplicateElement {
                resource: "provider retention inventory",
            });
        }
        if items.iter().any(|item| item.leaf_index >= tree_size) {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider retention leaf/tree size",
            });
        }
        if audit_artifacts.len() > MAX_PROVIDER_AUDIT_ARTIFACTS {
            return Err(IdentityError::limit(
                "provider retained audit artifacts",
                audit_artifacts.len(),
                MAX_PROVIDER_AUDIT_ARTIFACTS,
            ));
        }
        audit_artifacts.sort_unstable_by_key(|artifact| (artifact.sequence(), artifact.kind()));
        if audit_artifacts.windows(2).any(|pair| {
            pair[0].sequence() == pair[1].sequence() && pair[0].kind() == pair[1].kind()
        }) {
            return Err(IdentityError::DuplicateElement {
                resource: "provider retained audit artifacts",
            });
        }
        Ok(Self {
            tree_size,
            items,
            audit_artifacts,
        })
    }

    /// Exact source tree size governed by this inventory.
    pub const fn tree_size(&self) -> u64 {
        self.tree_size
    }

    /// Sorted unique retained leaf/reason pairs.
    pub fn items(&self) -> &[ProviderRetentionItem] {
        &self.items
    }

    /// Sorted exact rollback/equivocation evidence retained outside the provider leaf tree.
    pub fn audit_artifacts(&self) -> &[ProviderAuditArtifact] {
        &self.audit_artifacts
    }
}

/// One contiguous half-open provider leaf range retained locally after compaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRetainedRange {
    start: u64,
    end_exclusive: u64,
}

impl ProviderRetainedRange {
    /// First retained provider-wide leaf index.
    pub const fn start(self) -> u64 {
        self.start
    }

    /// First provider-wide leaf index outside this retained range.
    pub const fn end_exclusive(self) -> u64 {
        self.end_exclusive
    }
}

/// Authenticated manifest that must verify before any logical provider material is released.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCompactionManifest {
    format_version: u16,
    provider_id: ProviderId,
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
    retained_ranges: Vec<ProviderRetainedRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProviderCompactionManifestWire {
    format_version: u16,
    provider_id: ProviderId,
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
    retained_ranges: BoundedVec<ProviderRetainedRange, MAX_PROVIDER_WIRE_RETAINED_RANGES>,
}

impl ProviderCompactionManifest {
    /// Version of the compaction manifest format.
    pub const fn format_version(&self) -> u16 {
        self.format_version
    }

    /// Provider generation authenticated by this manifest.
    pub const fn provider_id(&self) -> ProviderId {
        self.provider_id
    }

    /// Exact provider log generation authenticated by this manifest.
    pub const fn log_id(&self) -> ProviderLogId {
        self.log_id
    }

    /// Exact provider key generation authenticated by this manifest.
    pub const fn key_version(&self) -> ProviderKeyVersion {
        self.key_version
    }

    /// Complete pre-compaction tree size.
    pub const fn source_tree_size(&self) -> u64 {
        self.source_tree_size
    }

    /// Complete pre-compaction tree root.
    pub const fn source_tree_root(&self) -> Digest {
        self.source_tree_root
    }

    /// Exact full-mirror archive commitment.
    pub const fn archive_commitment(&self) -> Digest {
        self.archive_commitment
    }

    /// Exact complete provider-generation component commitment.
    pub const fn generation_commitment(&self) -> Digest {
        self.generation_commitment
    }

    /// Exact complete audit-journal component commitment.
    pub const fn audit_commitment(&self) -> Digest {
        self.audit_commitment
    }

    /// Exact sorted rollback/equivocation artifact-set commitment.
    pub const fn audit_artifact_commitment(&self) -> Digest {
        self.audit_artifact_commitment
    }

    /// Exact complete retention-inventory commitment.
    pub const fn inventory_commitment(&self) -> Digest {
        self.inventory_commitment
    }

    /// Exact commitment of retained records, raw checkpoint material, projection index, and artifacts.
    pub const fn retained_evidence_commitment(&self) -> Digest {
        self.retained_evidence_commitment
    }

    /// Coalesced local leaf ranges required by the retention inventory.
    pub fn retained_ranges(&self) -> &[ProviderRetainedRange] {
        &self.retained_ranges
    }

    pub(super) fn validate_wire(&self) -> Result<(), IdentityError> {
        let source_tree_size =
            usize::try_from(self.source_tree_size).map_err(|_| IdentityError::LimitExceeded {
                resource: "provider compaction source tree size",
                actual: usize::MAX,
                maximum: MAX_MERKLE_LOG_LEAVES,
            })?;
        if self.format_version != 1 {
            return Err(IdentityError::UnsupportedVersion {
                version: self.format_version,
            });
        }
        if source_tree_size > MAX_MERKLE_LOG_LEAVES {
            return Err(IdentityError::limit(
                "provider compaction source tree size",
                source_tree_size,
                MAX_MERKLE_LOG_LEAVES,
            ));
        }
        let digests = [
            self.source_tree_root,
            self.archive_commitment,
            self.generation_commitment,
            self.audit_commitment,
            self.audit_artifact_commitment,
            self.inventory_commitment,
            self.retained_evidence_commitment,
        ];
        if digests
            .iter()
            .any(|digest| digest.algorithm() != HashAlgorithm::Blake3_256)
            || self.archive_commitment
                != provider_recovery_commitment(
                    self.generation_commitment,
                    self.audit_commitment,
                    self.audit_artifact_commitment,
                )?
        {
            return Err(IdentityError::InvalidProof);
        }
        let mut previous_end = 0_u64;
        for range in &self.retained_ranges {
            if range.start >= range.end_exclusive
                || range.end_exclusive > self.source_tree_size
                || range.start < previous_end
            {
                return Err(IdentityError::InvalidRelationship {
                    resource: "provider compaction retained ranges",
                });
            }
            previous_end = range.end_exclusive;
        }
        Ok(())
    }

    pub(super) fn retained_leaf_indices(&self) -> Result<Vec<u64>, IdentityError> {
        let mut indices = Vec::new();
        for range in &self.retained_ranges {
            let length = range
                .end_exclusive
                .checked_sub(range.start)
                .ok_or(IdentityError::StorageCorruption)?;
            let length = usize::try_from(length).map_err(|_| IdentityError::StorageCorruption)?;
            if indices.len().saturating_add(length) > MAX_MERKLE_LOG_LEAVES {
                return Err(IdentityError::StorageCorruption);
            }
            indices.extend(range.start..range.end_exclusive);
        }
        Ok(indices)
    }

    /// Reverify the source, exact mirror, and inventory against this manifest.
    pub fn verify(
        &self,
        source: &ProviderRecoveryExport,
        mirror: &ProviderRecoveryExport,
        inventory: &ProviderRetentionInventory,
    ) -> Result<(), IdentityError> {
        let expected = build_manifest(source, mirror, inventory)?;
        if &expected != self {
            return Err(IdentityError::InvalidProof);
        }
        Ok(())
    }

    pub(super) fn validate_generation(
        &self,
        provider_id: ProviderId,
        log_id: ProviderLogId,
        key_version: ProviderKeyVersion,
        leaf_hashes: &[Digest],
    ) -> Result<(), IdentityError> {
        let source_len =
            usize::try_from(self.source_tree_size).map_err(|_| IdentityError::StorageCorruption)?;
        if source_len > leaf_hashes.len() {
            return Err(IdentityError::StorageCorruption);
        }
        let source_root = crate::merkle::AppendOnlyMerkleLog::from_leaf_hashes(
            leaf_hashes[..source_len].to_vec(),
        )?
        .root()?;
        if self.format_version != 1
            || self.provider_id != provider_id
            || self.log_id != log_id
            || self.key_version != key_version
            || self.source_tree_root != source_root
            || self.archive_commitment
                != provider_recovery_commitment(
                    self.generation_commitment,
                    self.audit_commitment,
                    self.audit_artifact_commitment,
                )?
            || self.archive_commitment.algorithm() != HashAlgorithm::Blake3_256
            || self.generation_commitment.algorithm() != HashAlgorithm::Blake3_256
            || self.audit_commitment.algorithm() != HashAlgorithm::Blake3_256
            || self.audit_artifact_commitment.algorithm() != HashAlgorithm::Blake3_256
            || self.inventory_commitment.algorithm() != HashAlgorithm::Blake3_256
            || self.retained_evidence_commitment.algorithm() != HashAlgorithm::Blake3_256
        {
            return Err(IdentityError::StorageCorruption);
        }
        let mut previous_end = 0;
        for range in &self.retained_ranges {
            if range.start >= range.end_exclusive
                || range.end_exclusive > self.source_tree_size
                || range.start < previous_end
            {
                return Err(IdentityError::StorageCorruption);
            }
            previous_end = range.end_exclusive;
        }
        Ok(())
    }

    pub(super) fn validate_sealed_evidence(
        &self,
        inventory: &ProviderRetentionInventory,
        retained_evidence_commitment: Digest,
    ) -> Result<(), IdentityError> {
        if self.inventory_commitment != inventory_commitment(inventory)?
            || self.audit_artifact_commitment
                != provider_audit_artifact_commitment(inventory.audit_artifacts())?
            || self.retained_evidence_commitment != retained_evidence_commitment
        {
            return Err(IdentityError::StorageCorruption);
        }
        if self.retained_ranges != retained_ranges(inventory)? {
            return Err(IdentityError::StorageCorruption);
        }
        Ok(())
    }
}

impl ProviderCompactionManifestWire {
    fn from_manifest(manifest: &ProviderCompactionManifest) -> Result<Self, IdentityError> {
        manifest.validate_wire()?;
        Ok(Self {
            format_version: manifest.format_version,
            provider_id: manifest.provider_id,
            log_id: manifest.log_id,
            key_version: manifest.key_version,
            source_tree_size: manifest.source_tree_size,
            source_tree_root: manifest.source_tree_root,
            archive_commitment: manifest.archive_commitment,
            generation_commitment: manifest.generation_commitment,
            audit_commitment: manifest.audit_commitment,
            audit_artifact_commitment: manifest.audit_artifact_commitment,
            inventory_commitment: manifest.inventory_commitment,
            retained_evidence_commitment: manifest.retained_evidence_commitment,
            retained_ranges: BoundedVec::new(
                "provider compaction retained ranges",
                manifest.retained_ranges.clone(),
            )?,
        })
    }

    fn into_manifest(self) -> Result<ProviderCompactionManifest, IdentityError> {
        let manifest = ProviderCompactionManifest {
            format_version: self.format_version,
            provider_id: self.provider_id,
            log_id: self.log_id,
            key_version: self.key_version,
            source_tree_size: self.source_tree_size,
            source_tree_root: self.source_tree_root,
            archive_commitment: self.archive_commitment,
            generation_commitment: self.generation_commitment,
            audit_commitment: self.audit_commitment,
            audit_artifact_commitment: self.audit_artifact_commitment,
            inventory_commitment: self.inventory_commitment,
            retained_evidence_commitment: self.retained_evidence_commitment,
            retained_ranges: self.retained_ranges.into_vec(),
        };
        manifest.validate_wire()?;
        Ok(manifest)
    }
}

impl CanonicalCodec for ProviderCompactionManifest {
    const RESOURCE: &'static str = "provider compaction manifest bytes";
    const MAX_ENCODED_BYTES: usize = MAX_PROVIDER_COMPACTION_MANIFEST_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(&ProviderCompactionManifestWire::from_manifest(self)?)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire::<ProviderCompactionManifestWire>(bytes)?.into_manifest()
    }
}

/// Opaque proof that a compaction source, exact full mirror, and inventory all verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderCompactionAuthorization {
    manifest: ProviderCompactionManifest,
}

impl ProviderCompactionAuthorization {
    /// Verified manifest that must be durably recorded before release.
    pub const fn manifest(&self) -> &ProviderCompactionManifest {
        &self.manifest
    }
}

/// Verify an exact full mirror and retention inventory before authorizing compaction.
pub fn verify_provider_compaction(
    source: &ProviderRecoveryExport,
    mirror: &ProviderRecoveryExport,
    inventory: &ProviderRetentionInventory,
) -> Result<ProviderCompactionAuthorization, IdentityError> {
    Ok(ProviderCompactionAuthorization {
        manifest: build_manifest(source, mirror, inventory)?,
    })
}

/// Derive the semantic minimum leaf/reason inventory from authenticated generation state.
///
/// The unique current checkpoint tip remains locally queryable; a fork retains every known branch.
/// Additional destructive/migration/recovery/rotation classes are derived from verified checkpoint
/// events, while complete ancestry remains in the exact recovery archive. Callers may retain more,
/// but cannot omit or relabel these mandatory items.
pub fn derive_provider_retention_inventory(
    source: &ProviderRecoveryExport,
) -> Result<ProviderRetentionInventory, IdentityError> {
    source.validate()?;
    let generation = source.generation();
    let source_store = MemoryProviderStore::restore_generation(generation.clone())?;
    let snapshot = source_store.snapshot()?;
    let checkpoint_index =
        rebuild_checkpoint_index(&generation.entries, &generation.checkpoint_bundles)?;
    let mut required_lineage = std::collections::BTreeSet::new();
    for index in &checkpoint_index {
        if index.forked {
            for bundle in &generation.checkpoint_bundles {
                let checkpoint = bundle.verified_checkpoint();
                if checkpoint.checkpoint().body().account_id() == index.account_id {
                    required_lineage.insert(checkpoint.checkpoint_id());
                }
            }
        } else if let Some(checkpoint_id) = index.current_checkpoint_id {
            // The current tip remains locally queryable. Its older ancestry is recoverable from
            // the exact verified archive and deliberately releasable after sealing.
            required_lineage.insert(checkpoint_id);
        }
    }
    let mut items = Vec::new();
    for (index, entry) in generation.entries.iter().enumerate() {
        let leaf_index = u64::try_from(index).map_err(|_| IdentityError::ArithmeticOverflow {
            resource: "provider mandatory retention leaf index",
        })?;
        match entry.subject() {
            ProviderLogSubject::EventIntent(_) => {
                items.push(ProviderRetentionItem::new(
                    leaf_index,
                    ProviderRetentionClass::Recovery,
                )?);
            }
            ProviderLogSubject::Checkpoint(checkpoint_id) => {
                if required_lineage.contains(&checkpoint_id) {
                    items.push(ProviderRetentionItem::new(
                        leaf_index,
                        ProviderRetentionClass::CheckpointLineage,
                    )?);
                }
                if checkpoint_index
                    .iter()
                    .any(|retained| retained.account_id == entry.account_id() && retained.forked)
                {
                    items.push(ProviderRetentionItem::new(
                        leaf_index,
                        ProviderRetentionClass::UnresolvedFork,
                    )?);
                }
                let bundle = generation
                    .checkpoint_bundles
                    .iter()
                    .find(|bundle| {
                        let checkpoint = bundle.verified_checkpoint();
                        checkpoint.checkpoint().body().account_id() == entry.account_id()
                            && checkpoint.checkpoint_id() == checkpoint_id
                    })
                    .ok_or(IdentityError::StorageCorruption)?;
                for event in bundle.events() {
                    add_operation_retention_items(
                        &mut items,
                        leaf_index,
                        event.body().operation().kind(),
                    )?;
                }
            }
        }
    }
    items.sort_unstable();
    items.dedup();
    ProviderRetentionInventory::with_audit_artifacts(
        snapshot.tree_size(),
        items,
        source.artifacts().to_vec(),
    )
}

fn build_manifest(
    source: &ProviderRecoveryExport,
    mirror: &ProviderRecoveryExport,
    inventory: &ProviderRetentionInventory,
) -> Result<ProviderCompactionManifest, IdentityError> {
    source.validate()?;
    mirror.validate()?;
    let source_store = MemoryProviderStore::restore_generation(source.generation().clone())?;
    let mirror_store = MemoryProviderStore::restore_generation(mirror.generation().clone())?;
    let source_snapshot = source_store.snapshot()?;
    if source != mirror || source_snapshot != mirror_store.snapshot()? {
        return Err(IdentityError::InvalidProof);
    }
    if inventory.tree_size != source_snapshot.tree_size() {
        return Err(IdentityError::InvalidRelationship {
            resource: "provider compaction inventory tree size",
        });
    }
    let mandatory = derive_provider_retention_inventory(source)?;
    if mandatory
        .items
        .iter()
        .any(|required| !inventory.items.contains(required))
    {
        return Err(IdentityError::InvalidRelationship {
            resource: "provider compaction mandatory retention inventory",
        });
    }
    if inventory.audit_artifacts != mandatory.audit_artifacts {
        return Err(IdentityError::InvalidRelationship {
            resource: "provider compaction mandatory audit artifacts",
        });
    }
    for artifact in &inventory.audit_artifacts {
        artifact.verify(source.generation().provider(), source.generation().log_id())?;
    }
    let retained_evidence_commitment =
        retained_provider_evidence_commitment(source.generation(), inventory)?;
    Ok(ProviderCompactionManifest {
        format_version: 1,
        provider_id: source.generation().provider.id()?,
        log_id: source.generation().log_id,
        key_version: source.generation().key_version,
        source_tree_size: source_snapshot.tree_size(),
        source_tree_root: source_snapshot.tree_root(),
        archive_commitment: mirror.recovery_commitment(),
        generation_commitment: mirror.generation_commitment(),
        audit_commitment: mirror.audit_commitment(),
        audit_artifact_commitment: mirror.artifact_commitment(),
        inventory_commitment: inventory_commitment(inventory)?,
        retained_evidence_commitment,
        retained_ranges: retained_ranges(inventory)?,
    })
}

fn add_operation_retention_items(
    items: &mut Vec<ProviderRetentionItem>,
    leaf_index: u64,
    operation: OperationKind,
) -> Result<(), IdentityError> {
    let mut retain = |class| {
        items.push(ProviderRetentionItem::new(leaf_index, class)?);
        Ok::<(), IdentityError>(())
    };
    match operation {
        OperationKind::RemoveController => retain(ProviderRetentionClass::ControllerTombstone)?,
        OperationKind::RevokeDevice | OperationKind::RotateDeviceKeys => {
            retain(ProviderRetentionClass::DeviceTombstone)?;
        }
        OperationKind::ResolveFork => {
            retain(ProviderRetentionClass::UnresolvedFork)?;
            retain(ProviderRetentionClass::ControllerTombstone)?;
            retain(ProviderRetentionClass::DeviceTombstone)?;
        }
        OperationKind::BeginCryptoMigration
        | OperationKind::ActivateCryptoMigration
        | OperationKind::RetireCryptoSuite
        | OperationKind::UpgradeProtocol => retain(ProviderRetentionClass::CryptoMigration)?,
        OperationKind::ChangeRecoveryPolicy
        | OperationKind::BeginRecovery
        | OperationKind::VetoRecovery
        | OperationKind::CancelRecovery => retain(ProviderRetentionClass::Recovery)?,
        OperationKind::FinalizeRecovery => {
            retain(ProviderRetentionClass::Recovery)?;
            retain(ProviderRetentionClass::ControllerTombstone)?;
            retain(ProviderRetentionClass::DeviceTombstone)?;
        }
        OperationKind::ChangeProviderPolicy => retain(ProviderRetentionClass::ProviderRotation)?,
        OperationKind::RetireAccount => {
            retain(ProviderRetentionClass::ControllerTombstone)?;
            retain(ProviderRetentionClass::DeviceTombstone)?;
        }
        OperationKind::AuthorizeDevice
        | OperationKind::UpdateDeviceAuthorization
        | OperationKind::UpdateDeviceMetadata
        | OperationKind::SuspendDevice
        | OperationKind::ReinstateDevice
        | OperationKind::AddController
        | OperationKind::ChangeControlPolicy => {}
    }
    Ok(())
}

fn retained_ranges(
    inventory: &ProviderRetentionInventory,
) -> Result<Vec<ProviderRetainedRange>, IdentityError> {
    let mut indices = inventory
        .items
        .iter()
        .map(|item| item.leaf_index)
        .collect::<Vec<_>>();
    indices.sort_unstable();
    indices.dedup();
    let mut ranges = Vec::<ProviderRetainedRange>::new();
    for index in indices {
        match ranges.last_mut() {
            Some(range) if range.end_exclusive == index => {
                range.end_exclusive =
                    index
                        .checked_add(1)
                        .ok_or(IdentityError::ArithmeticOverflow {
                            resource: "provider retained range",
                        })?;
            }
            _ => ranges.push(ProviderRetainedRange {
                start: index,
                end_exclusive: index
                    .checked_add(1)
                    .ok_or(IdentityError::ArithmeticOverflow {
                        resource: "provider retained range",
                    })?,
            }),
        }
    }
    Ok(ranges)
}

pub(super) fn provider_generation_export_commitment(
    export: &ProviderGenerationExport,
) -> Result<Digest, IdentityError> {
    let checkpoint_bundles = export
        .checkpoint_bundles
        .iter()
        .map(|bundle| {
            let checkpoint = bundle.verified_checkpoint();
            ProviderCheckpointBundleCommitmentWire {
                genesis: bundle.genesis(),
                prior_checkpoint_id: bundle.prior_checkpoint_id(),
                events: bundle.events(),
                checkpoint: checkpoint.checkpoint(),
                transition_event: checkpoint.transition_event(),
            }
        })
        .collect();
    provider_commitment(
        PROVIDER_GENERATION_EXPORT_COMMITMENT_DOMAIN,
        &ProviderGenerationExportCommitmentWire {
            format_version: 1,
            provider: &export.provider,
            log_id: export.log_id,
            key_version: export.key_version,
            entries: &export.entries,
            leaf_hashes: &export.leaf_hashes,
            latest_head: export.latest_head.as_ref(),
            receipts: &export.receipts,
            checkpoint_bundles,
            // A newly built manifest commits the exact pre-manifest export, avoiding
            // self-reference. Later exports bind every already-durable manifest.
            compaction_manifests: &export.compaction_manifests,
        },
    )
}

fn inventory_commitment(inventory: &ProviderRetentionInventory) -> Result<Digest, IdentityError> {
    provider_commitment(
        PROVIDER_RETENTION_INVENTORY_COMMITMENT_DOMAIN,
        &ProviderRetentionInventoryCommitmentWire {
            format_version: 1,
            tree_size: inventory.tree_size,
            items: inventory
                .items
                .iter()
                .map(|item| ProviderRetentionItemCommitmentWire {
                    leaf_index: item.leaf_index,
                    class_code: item.class.code(),
                })
                .collect(),
            audit_artifact_commitments: inventory
                .audit_artifacts
                .iter()
                .map(ProviderAuditArtifact::commitment)
                .collect::<Result<Vec<_>, _>>()?,
        },
    )
}

#[cfg(test)]
mod tests {
    use krikos_base::SecretKey;

    use super::*;
    use crate::{
        AccountGenesis, AuthorizedEvent, CanonicalWire, CheckpointId, Extensions, InclusionReceipt,
        ProtocolSignature, ProviderAuditArtifactKind, ProviderCheckpointBundle, ProviderHeadBody,
        ProviderLogEntryBody, SignedCheckpoint, SignedProviderHead, SigningPublicKey, Timestamp,
    };

    #[derive(serde::Serialize)]
    struct AuditArtifactCommitmentMirror<'a> {
        format_version: u16,
        sequence: u64,
        kind_code: u16,
        accepted_head: &'a SignedProviderHead,
        observed_head: &'a SignedProviderHead,
    }

    #[derive(serde::Serialize)]
    struct CheckpointBundleCommitmentMirror<'a> {
        genesis: Option<&'a AccountGenesis>,
        prior_checkpoint_id: Option<CheckpointId>,
        events: &'a [AuthorizedEvent],
        checkpoint: &'a SignedCheckpoint,
        transition_event: Option<&'a AuthorizedEvent>,
    }

    #[derive(serde::Serialize)]
    struct GenerationExportCommitmentMirror<'a> {
        format_version: u16,
        provider: &'a crate::ProviderDescriptor,
        log_id: ProviderLogId,
        key_version: ProviderKeyVersion,
        entries: &'a [ProviderLogEntryBody],
        leaf_hashes: &'a [Digest],
        latest_head: Option<&'a SignedProviderHead>,
        receipts: &'a [InclusionReceipt],
        checkpoint_bundles: Vec<CheckpointBundleCommitmentMirror<'a>>,
        compaction_manifests: &'a [ProviderCompactionManifest],
    }

    #[derive(serde::Serialize)]
    struct RetentionItemCommitmentMirror {
        leaf_index: u64,
        class_code: u16,
    }

    #[derive(serde::Serialize)]
    struct RetentionInventoryCommitmentMirror<'a> {
        format_version: u16,
        tree_size: u64,
        items: Vec<RetentionItemCommitmentMirror>,
        audit_artifact_commitments: &'a [Digest],
    }

    fn raw_commitment<T: serde::Serialize>(domain: &[u8], value: &T) -> Digest {
        let bytes = postcard::to_stdvec(value).unwrap();
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        hasher.update(&[0]);
        hasher.update(&bytes);
        Digest::new(HashAlgorithm::Blake3_256, *hasher.finalize().as_bytes())
    }

    fn typed_id<T: CanonicalWire>(fill: u8) -> T {
        let digest = Digest::new(HashAlgorithm::Blake3_256, [fill; 32]);
        T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
    }

    fn unsigned_head(
        provider: &ProviderDescriptor,
        log_id: ProviderLogId,
        root_fill: u8,
        observed_at: u64,
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
        SignedProviderHead::new(body, ProtocolSignature::ed25519([root_fill; 64]))
    }

    #[test]
    fn provider_compaction_roots_use_versioned_canonical_preimages() {
        let signer = SecretKey::from_bytes(&[0x41; 32]);
        let provider = crate::ProviderDescriptor::new(
            SigningPublicKey::ed25519(*signer.public().as_bytes()).unwrap(),
            Extensions::default(),
        )
        .unwrap();
        let log_id = typed_id::<ProviderLogId>(0x42);
        let export = ProviderGenerationExport {
            provider: provider.clone(),
            log_id,
            key_version: ProviderKeyVersion::GENESIS,
            entries: Vec::new(),
            leaf_hashes: Vec::new(),
            latest_head: None,
            receipts: Vec::new(),
            checkpoint_bundles: Vec::<ProviderCheckpointBundle>::new(),
            compaction_manifests: Vec::new(),
        };
        let expected_generation = raw_commitment(
            b"KRIKOS-ID/provider-generation-export/v1",
            &GenerationExportCommitmentMirror {
                format_version: 1,
                provider: &export.provider,
                log_id: export.log_id,
                key_version: export.key_version,
                entries: &export.entries,
                leaf_hashes: &export.leaf_hashes,
                latest_head: export.latest_head.as_ref(),
                receipts: &export.receipts,
                checkpoint_bundles: Vec::new(),
                compaction_manifests: &export.compaction_manifests,
            },
        );
        assert_eq!(
            provider_generation_export_commitment(&export).unwrap(),
            expected_generation
        );

        let artifact = ProviderAuditArtifact::new(
            1,
            ProviderAuditArtifactKind::Equivocation,
            unsigned_head(&provider, log_id, 0x43, 100),
            unsigned_head(&provider, log_id, 0x44, 101),
        )
        .unwrap();
        let inventory = ProviderRetentionInventory::with_audit_artifacts(
            1,
            vec![ProviderRetentionItem::new(0, ProviderRetentionClass::ProviderRotation).unwrap()],
            vec![artifact.clone()],
        )
        .unwrap();
        let expected_artifact = raw_commitment(
            b"KRIKOS-ID/provider-audit-artifact/v1",
            &AuditArtifactCommitmentMirror {
                format_version: 1,
                sequence: artifact.sequence(),
                kind_code: 2,
                accepted_head: artifact.accepted_head(),
                observed_head: artifact.observed_head(),
            },
        );
        let expected_inventory = raw_commitment(
            b"KRIKOS-ID/provider-retention-inventory/v1",
            &RetentionInventoryCommitmentMirror {
                format_version: 1,
                tree_size: inventory.tree_size(),
                items: vec![RetentionItemCommitmentMirror {
                    leaf_index: 0,
                    class_code: 7,
                }],
                audit_artifact_commitments: &[expected_artifact],
            },
        );
        assert_eq!(
            inventory_commitment(&inventory).unwrap(),
            expected_inventory
        );
    }
}
