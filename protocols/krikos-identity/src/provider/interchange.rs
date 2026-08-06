//! Bounded, versioned streaming interchange for complete provider recovery archives.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[cfg(test)]
use std::cell::Cell;

use super::{
    MAX_PROVIDER_COMPACTION_MANIFESTS, MemoryProviderStore, ProviderCheckpointBundleWire,
    ProviderGenerationExport, ProviderGenerationSnapshot, ProviderRecoveryExport,
    provider_audit_artifact_commitment,
};
use crate::{
    CanonicalWire, Digest, HashAlgorithm, IdentityError, InclusionReceipt,
    ProviderCompactionManifest, ProviderDescriptor, ProviderEquivocationEvidence, ProviderId,
    ProviderKeyVersion, ProviderLogEntryBody, ProviderLogId, SignedProviderHead,
    audit::{
        MAX_PROVIDER_AUDIT_RECORDS, ProviderAuditRecord, ProviderAuditRecordWire,
        ProviderAuditSnapshot, provider_audit_snapshot_from_wire_records,
    },
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
    limits::{MAX_HISTORY_PAGE_EVENTS, MAX_MERKLE_LOG_LEAVES},
    schema::{BoundedBytes, BoundedVec},
};

/// Maximum decoded items carried by one public provider interchange chunk.
pub const MAX_PROVIDER_EXPORT_CHUNK_ITEMS: usize = MAX_HISTORY_PAGE_EVENTS;
/// Maximum canonical bytes accepted by any public provider interchange chunk decoder.
pub const MAX_PROVIDER_EXPORT_CHUNK_BYTES: usize = 4 * 1024 * 1024;
/// Maximum aggregate canonical item bytes retained for one portable generation.
pub const MAX_PROVIDER_PORTABLE_GENERATION_BYTES: usize = 512 * 1024 * 1024;
/// Maximum aggregate canonical audit-record bytes retained for one portable journal.
pub const MAX_PROVIDER_PORTABLE_AUDIT_BYTES: usize = 256 * 1024 * 1024;

#[cfg(test)]
thread_local! {
    static PORTABLE_ITEM_ENCODING_COUNT: Cell<usize> = const { Cell::new(0) };
    static PORTABLE_AUDIT_RECORD_ENCODING_COUNT: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
pub(super) fn reset_portable_item_encoding_count() {
    PORTABLE_ITEM_ENCODING_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(super) fn portable_item_encoding_count() -> usize {
    PORTABLE_ITEM_ENCODING_COUNT.with(Cell::get)
}

fn record_portable_item_encoding() {
    #[cfg(test)]
    PORTABLE_ITEM_ENCODING_COUNT.with(|count| count.set(count.get().saturating_add(1)));
}

#[cfg(test)]
pub(crate) fn reset_portable_audit_record_encoding_count() {
    PORTABLE_AUDIT_RECORD_ENCODING_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn portable_audit_record_encoding_count() -> usize {
    PORTABLE_AUDIT_RECORD_ENCODING_COUNT.with(Cell::get)
}

fn record_portable_audit_record_encoding() {
    #[cfg(test)]
    PORTABLE_AUDIT_RECORD_ENCODING_COUNT.with(|count| count.set(count.get().saturating_add(1)));
}

/// Maximum canonical bytes carried by one unsplit provider interchange item.
pub const MAX_PROVIDER_EXPORT_ITEM_BYTES: usize = MAX_PROVIDER_EXPORT_CHUNK_BYTES - 4 * 1024;
const MAX_PROVIDER_EXPORT_CHUNK_PAYLOAD_BYTES: usize = MAX_PROVIDER_EXPORT_CHUNK_BYTES - 2 * 1024;
const MAX_PROVIDER_EXPORT_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_PROVIDER_RECOVERY_MANIFEST_BYTES: usize = 128 * 1024;
const MAX_PROVIDER_GENERATION_COMPONENTS: usize = 5;
const MAX_PROVIDER_EXPORT_CHUNKS: usize = 65_536;

const GENERATION_CHUNK_DOMAIN: &[u8] = b"KRIKOS-ID/provider-generation-chunk/v1";
const GENERATION_CHUNK_LIST_DOMAIN: &[u8] = b"KRIKOS-ID/provider-generation-chunk-list/v1";
const GENERATION_MANIFEST_DOMAIN: &[u8] = b"KRIKOS-ID/provider-generation-manifest/v1";
const AUDIT_CHUNK_DOMAIN: &[u8] = b"KRIKOS-ID/provider-audit-chunk/v1";
const AUDIT_CHUNK_LIST_DOMAIN: &[u8] = b"KRIKOS-ID/provider-audit-chunk-list/v1";
const AUDIT_MANIFEST_DOMAIN: &[u8] = b"KRIKOS-ID/provider-audit-manifest/v1";
const RECOVERY_MANIFEST_DOMAIN: &[u8] = b"KRIKOS-ID/provider-recovery-manifest/v1";

/// Closed component registry for generation export chunks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProviderExportComponent {
    /// Canonical provider log entry bodies.
    Entries,
    /// Domain-separated leaf hashes parallel to the entries.
    LeafHashes,
    /// Inclusion receipts parallel to the entries.
    Receipts,
    /// Complete retained checkpoint authority bundles.
    CheckpointBundles,
    /// Verified compaction manifests recorded on the generation.
    CompactionManifests,
}

impl ProviderExportComponent {
    /// Stable unsigned wire codepoint.
    pub const fn code(self) -> u16 {
        match self {
            Self::Entries => 1,
            Self::LeafHashes => 2,
            Self::Receipts => 3,
            Self::CheckpointBundles => 4,
            Self::CompactionManifests => 5,
        }
    }

    fn from_code(code: u16) -> Result<Self, IdentityError> {
        match code {
            1 => Ok(Self::Entries),
            2 => Ok(Self::LeafHashes),
            3 => Ok(Self::Receipts),
            4 => Ok(Self::CheckpointBundles),
            5 => Ok(Self::CompactionManifests),
            _ => Err(IdentityError::UnsupportedCodepoint {
                registry: "provider export component",
                code,
            }),
        }
    }

    const fn ordered() -> [Self; MAX_PROVIDER_GENERATION_COMPONENTS] {
        [
            Self::Entries,
            Self::LeafHashes,
            Self::Receipts,
            Self::CheckpointBundles,
            Self::CompactionManifests,
        ]
    }
}

impl CanonicalCodec for ProviderExportComponent {
    const RESOURCE: &'static str = "provider export component bytes";
    const MAX_ENCODED_BYTES: usize = 8;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(&(1_u16, self.code()))
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        let (format_version, code): (u16, u16) = decode_wire(bytes)?;
        require_version(format_version)?;
        Self::from_code(code)
    }
}

/// Exact count/byte/list commitment for one ordered generation component stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderExportComponentDescriptor {
    format_version: u16,
    component_code: u16,
    item_count: u64,
    chunk_count: u32,
    total_payload_bytes: u64,
    chunk_list_commitment: Digest,
}

impl ProviderExportComponentDescriptor {
    /// Component described by this record.
    pub fn component(&self) -> Result<ProviderExportComponent, IdentityError> {
        ProviderExportComponent::from_code(self.component_code)
    }

    /// Exact number of canonical items in the stream.
    pub const fn item_count(&self) -> u64 {
        self.item_count
    }

    /// Exact number of bounded chunks in the stream.
    pub const fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    /// Sum of the exact canonical item byte lengths in the stream.
    pub const fn total_payload_bytes(&self) -> u64 {
        self.total_payload_bytes
    }

    /// Ordered-list commitment over every chunk commitment.
    pub const fn chunk_list_commitment(&self) -> Digest {
        self.chunk_list_commitment
    }

    fn validate(&self) -> Result<(), IdentityError> {
        require_version(self.format_version)?;
        let component = self.component()?;
        let item_limit = component_item_limit(component);
        let item_count =
            usize::try_from(self.item_count).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "provider export descriptor item count",
            })?;
        let chunk_count =
            usize::try_from(self.chunk_count).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "provider export descriptor chunk count",
            })?;
        let minimum_chunk_count = item_count.div_ceil(MAX_PROVIDER_EXPORT_CHUNK_ITEMS);
        if item_count > item_limit {
            return Err(IdentityError::limit(
                "provider export descriptor items",
                item_count,
                item_limit,
            ));
        }
        if chunk_count > MAX_PROVIDER_EXPORT_CHUNKS
            || (item_count == 0) != (chunk_count == 0)
            || chunk_count < minimum_chunk_count
            || chunk_count > item_count
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider export descriptor chunk count",
            });
        }
        if item_count == 0 {
            if self.total_payload_bytes != 0
                || self.chunk_list_commitment
                    != ordered_chunk_list_commitment(
                        GENERATION_CHUNK_LIST_DOMAIN,
                        component.code(),
                        &[],
                    )?
            {
                return Err(IdentityError::InvalidRelationship {
                    resource: "empty provider export component descriptor",
                });
            }
        } else if self.total_payload_bytes == 0 {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider export component payload bytes",
            });
        }
        if self.total_payload_bytes
            > u64::try_from(MAX_PROVIDER_PORTABLE_GENERATION_BYTES).map_err(|_| {
                IdentityError::ArithmeticOverflow {
                    resource: "portable generation byte limit",
                }
            })?
            || self.chunk_list_commitment.algorithm() != HashAlgorithm::Blake3_256
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider export descriptor commitment",
            });
        }
        Ok(())
    }
}

impl CanonicalCodec for ProviderExportComponentDescriptor {
    const RESOURCE: &'static str = "provider export component descriptor bytes";
    const MAX_ENCODED_BYTES: usize = 128;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        self.validate()?;
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        let value: Self = decode_wire(bytes)?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProviderCheckpointBundleItemWire {
    format_version: u16,
    bundle: ProviderCheckpointBundleWire,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProviderAuditRecordItemWire {
    format_version: u16,
    record: ProviderAuditRecordWire,
}

#[derive(Serialize)]
struct ProviderGenerationChunkCommitmentWire<'a> {
    format_version: u16,
    provider_id: ProviderId,
    log_id: ProviderLogId,
    key_version: ProviderKeyVersion,
    generation_commitment: Digest,
    component_code: u16,
    ordinal: u32,
    start_index: u64,
    end_index: u64,
    item_payload_bytes: u64,
    payload: &'a [u8],
}

#[derive(Serialize)]
struct ProviderAuditChunkCommitmentWire<'a> {
    format_version: u16,
    provider_id: ProviderId,
    log_id: ProviderLogId,
    audit_commitment: Digest,
    ordinal: u32,
    start_sequence: u64,
    end_sequence: u64,
    item_payload_bytes: u64,
    payload: &'a [u8],
}

#[derive(Serialize)]
struct ProviderChunkListCommitmentWire<'a> {
    format_version: u16,
    component_code: u16,
    chunk_count: u32,
    commitments: &'a [Digest],
}

type ChunkItems =
    BoundedVec<BoundedBytes<MAX_PROVIDER_EXPORT_ITEM_BYTES>, MAX_PROVIDER_EXPORT_CHUNK_ITEMS>;

/// One independently bounded ordered slice of a generation component stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderGenerationExportChunk {
    format_version: u16,
    provider_id: ProviderId,
    log_id: ProviderLogId,
    key_version: ProviderKeyVersion,
    generation_commitment: Digest,
    component_code: u16,
    ordinal: u32,
    start_index: u64,
    end_index: u64,
    item_payload_bytes: u64,
    payload: BoundedBytes<MAX_PROVIDER_EXPORT_CHUNK_PAYLOAD_BYTES>,
}

/// One independently bounded ordered slice of an audit journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderAuditExportChunk {
    format_version: u16,
    provider_id: ProviderId,
    log_id: ProviderLogId,
    audit_commitment: Digest,
    ordinal: u32,
    start_sequence: u64,
    end_sequence: u64,
    item_payload_bytes: u64,
    payload: BoundedBytes<MAX_PROVIDER_EXPORT_CHUNK_PAYLOAD_BYTES>,
}

impl ProviderGenerationExportChunk {
    /// Provider identity routing this chunk.
    pub const fn provider_id(&self) -> ProviderId {
        self.provider_id
    }

    /// Provider log generation routing this chunk.
    pub const fn log_id(&self) -> ProviderLogId {
        self.log_id
    }

    /// Provider signing-key generation routing this chunk.
    pub const fn key_version(&self) -> ProviderKeyVersion {
        self.key_version
    }

    /// Authoritative aggregate commitment binding this chunk.
    pub const fn generation_commitment(&self) -> Digest {
        self.generation_commitment
    }

    /// Component carried by this chunk.
    pub fn component(&self) -> Result<ProviderExportComponent, IdentityError> {
        ProviderExportComponent::from_code(self.component_code)
    }

    /// Zero-based ordinal inside the component stream.
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    /// Inclusive item offset inside the complete component stream.
    pub const fn start_index(&self) -> u64 {
        self.start_index
    }

    /// Exclusive item offset inside the complete component stream.
    pub const fn end_index(&self) -> u64 {
        self.end_index
    }

    /// Sum of the canonical item byte lengths in this chunk.
    pub const fn item_payload_bytes(&self) -> u64 {
        self.item_payload_bytes
    }

    /// Domain-separated commitment over the exact route, range, and payload fields.
    pub fn commitment(&self) -> Result<Digest, IdentityError> {
        self.validate()?;
        domain_commitment(
            GENERATION_CHUNK_DOMAIN,
            &ProviderGenerationChunkCommitmentWire {
                format_version: 1,
                provider_id: self.provider_id,
                log_id: self.log_id,
                key_version: self.key_version,
                generation_commitment: self.generation_commitment,
                component_code: self.component_code,
                ordinal: self.ordinal,
                start_index: self.start_index,
                end_index: self.end_index,
                item_payload_bytes: self.item_payload_bytes,
                payload: self.payload.as_slice(),
            },
        )
    }

    fn item_bytes(&self) -> Result<Vec<Vec<u8>>, IdentityError> {
        decode_chunk_items(self.payload.as_slice())
    }

    fn validate(&self) -> Result<(), IdentityError> {
        require_version(self.format_version)?;
        let component = self.component()?;
        if self.key_version != ProviderKeyVersion::GENESIS
            || self.generation_commitment.algorithm() != HashAlgorithm::Blake3_256
            || self.start_index >= self.end_index
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider generation export chunk header",
            });
        }
        let items = self.item_bytes()?;
        let expected_count = self.end_index.checked_sub(self.start_index).ok_or(
            IdentityError::ArithmeticOverflow {
                resource: "provider generation export chunk range",
            },
        )?;
        if u64::try_from(items.len()).map_err(|_| IdentityError::ArithmeticOverflow {
            resource: "provider generation export chunk items",
        })? != expected_count
            || canonical_item_bytes(&items)? != self.item_payload_bytes
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider generation export chunk payload accounting",
            });
        }
        for item in &items {
            validate_generation_item(component, item)?;
        }
        Ok(())
    }
}

impl CanonicalCodec for ProviderGenerationExportChunk {
    const RESOURCE: &'static str = "provider generation export chunk bytes";
    const MAX_ENCODED_BYTES: usize = MAX_PROVIDER_EXPORT_CHUNK_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        self.validate()?;
        let bytes = encode_wire(self)?;
        check_chunk_size(bytes)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() > MAX_PROVIDER_EXPORT_CHUNK_BYTES {
            return Err(IdentityError::limit(
                Self::RESOURCE,
                bytes.len(),
                MAX_PROVIDER_EXPORT_CHUNK_BYTES,
            ));
        }
        let value: Self = decode_wire(bytes)?;
        value.validate()?;
        Ok(value)
    }
}

impl ProviderAuditExportChunk {
    /// Provider identity routing this chunk.
    pub const fn provider_id(&self) -> ProviderId {
        self.provider_id
    }

    /// Provider log generation routing this chunk.
    pub const fn log_id(&self) -> ProviderLogId {
        self.log_id
    }

    /// Authoritative audit-journal commitment binding this chunk.
    pub const fn audit_commitment(&self) -> Digest {
        self.audit_commitment
    }

    /// Zero-based ordinal inside the audit-record stream.
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    /// Inclusive one-based journal sequence.
    pub const fn start_sequence(&self) -> u64 {
        self.start_sequence
    }

    /// Exclusive one-based journal sequence bound.
    pub const fn end_sequence(&self) -> u64 {
        self.end_sequence
    }

    /// Sum of the canonical audit-record item byte lengths in this chunk.
    pub const fn item_payload_bytes(&self) -> u64 {
        self.item_payload_bytes
    }

    /// Domain-separated commitment over the exact journal route, range, and payload fields.
    pub fn commitment(&self) -> Result<Digest, IdentityError> {
        self.validate()?;
        domain_commitment(
            AUDIT_CHUNK_DOMAIN,
            &ProviderAuditChunkCommitmentWire {
                format_version: 1,
                provider_id: self.provider_id,
                log_id: self.log_id,
                audit_commitment: self.audit_commitment,
                ordinal: self.ordinal,
                start_sequence: self.start_sequence,
                end_sequence: self.end_sequence,
                item_payload_bytes: self.item_payload_bytes,
                payload: self.payload.as_slice(),
            },
        )
    }

    fn item_bytes(&self) -> Result<Vec<Vec<u8>>, IdentityError> {
        decode_chunk_items(self.payload.as_slice())
    }

    fn validate(&self) -> Result<(), IdentityError> {
        require_version(self.format_version)?;
        if self.audit_commitment.algorithm() != HashAlgorithm::Blake3_256
            || self.start_sequence == 0
            || self.start_sequence >= self.end_sequence
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider audit export chunk header",
            });
        }
        let items = self.item_bytes()?;
        let expected_count = self.end_sequence.checked_sub(self.start_sequence).ok_or(
            IdentityError::ArithmeticOverflow {
                resource: "provider audit export chunk range",
            },
        )?;
        if u64::try_from(items.len()).map_err(|_| IdentityError::ArithmeticOverflow {
            resource: "provider audit export chunk items",
        })? != expected_count
            || canonical_item_bytes(&items)? != self.item_payload_bytes
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider audit export chunk payload accounting",
            });
        }
        for item in &items {
            decode_audit_record_item(item)?;
        }
        Ok(())
    }
}

impl CanonicalCodec for ProviderAuditExportChunk {
    const RESOURCE: &'static str = "provider audit export chunk bytes";
    const MAX_ENCODED_BYTES: usize = MAX_PROVIDER_EXPORT_CHUNK_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        self.validate()?;
        let bytes = encode_wire(self)?;
        check_chunk_size(bytes)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() > MAX_PROVIDER_EXPORT_CHUNK_BYTES {
            return Err(IdentityError::limit(
                Self::RESOURCE,
                bytes.len(),
                MAX_PROVIDER_EXPORT_CHUNK_BYTES,
            ));
        }
        let value: Self = decode_wire(bytes)?;
        value.validate()?;
        Ok(value)
    }
}

/// Small authenticated index for every component chunk of one complete generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderGenerationExportManifest {
    format_version: u16,
    provider: ProviderDescriptor,
    log_id: ProviderLogId,
    key_version: ProviderKeyVersion,
    tree_size: u64,
    tree_root: Digest,
    latest_head: Option<SignedProviderHead>,
    generation_commitment: Digest,
    total_payload_bytes: u64,
    components: BoundedVec<ProviderExportComponentDescriptor, MAX_PROVIDER_GENERATION_COMPONENTS>,
}

/// Small authenticated index for every chunk of one complete audit journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderAuditExportManifest {
    format_version: u16,
    provider: ProviderDescriptor,
    log_id: ProviderLogId,
    latest_head: Option<SignedProviderHead>,
    equivocation: Option<ProviderEquivocationEvidence>,
    record_count: u64,
    chunk_count: u32,
    total_payload_bytes: u64,
    audit_commitment: Digest,
    artifact_count: u64,
    artifact_commitment: Digest,
    chunk_list_commitment: Digest,
}

/// Canonical recovery entry point binding exact generation and audit interchange manifests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRecoveryExportManifest {
    format_version: u16,
    generation: ProviderGenerationExportManifest,
    audit: ProviderAuditExportManifest,
    generation_manifest_commitment: Digest,
    audit_manifest_commitment: Digest,
    generation_commitment: Digest,
    audit_commitment: Digest,
    artifact_commitment: Digest,
    recovery_commitment: Digest,
}

impl ProviderGenerationExportManifest {
    /// Provider descriptor authenticating this generation.
    pub const fn provider(&self) -> &ProviderDescriptor {
        &self.provider
    }

    /// Exact log generation.
    pub const fn log_id(&self) -> ProviderLogId {
        self.log_id
    }

    /// Exact provider signing-key generation.
    pub const fn key_version(&self) -> ProviderKeyVersion {
        self.key_version
    }

    /// Complete Merkle tree size.
    pub const fn tree_size(&self) -> u64 {
        self.tree_size
    }

    /// Complete Merkle tree root.
    pub const fn tree_root(&self) -> Digest {
        self.tree_root
    }

    /// Latest authenticated provider head.
    pub const fn latest_head(&self) -> Option<&SignedProviderHead> {
        self.latest_head.as_ref()
    }

    /// Authoritative full-generation commitment.
    pub const fn generation_commitment(&self) -> Digest {
        self.generation_commitment
    }

    /// Exact sum of canonical item bytes across all component streams.
    pub const fn total_payload_bytes(&self) -> u64 {
        self.total_payload_bytes
    }

    /// Fixed component descriptors in ascending codepoint order.
    pub fn components(&self) -> &[ProviderExportComponentDescriptor] {
        self.components.as_slice()
    }

    /// Descriptor for one exact component stream.
    pub fn descriptor(
        &self,
        component: ProviderExportComponent,
    ) -> Result<&ProviderExportComponentDescriptor, IdentityError> {
        self.components
            .as_slice()
            .iter()
            .find(|descriptor| descriptor.component_code == component.code())
            .ok_or(IdentityError::InvalidRelationship {
                resource: "provider generation manifest component coverage",
            })
    }

    /// Domain-separated commitment to the exact canonical manifest bytes.
    pub fn commitment(&self) -> Result<Digest, IdentityError> {
        self.validate()?;
        domain_commitment(GENERATION_MANIFEST_DOMAIN, self)
    }

    fn validate(&self) -> Result<(), IdentityError> {
        require_version(self.format_version)?;
        if self.key_version != ProviderKeyVersion::GENESIS
            || self.tree_size
                > u64::try_from(MAX_MERKLE_LOG_LEAVES).map_err(|_| {
                    IdentityError::ArithmeticOverflow {
                        resource: "provider Merkle tree limit",
                    }
                })?
            || self.tree_root.algorithm() != HashAlgorithm::Blake3_256
            || self.generation_commitment.algorithm() != HashAlgorithm::Blake3_256
            || self.total_payload_bytes
                > u64::try_from(MAX_PROVIDER_PORTABLE_GENERATION_BYTES).map_err(|_| {
                    IdentityError::ArithmeticOverflow {
                        resource: "portable generation byte limit",
                    }
                })?
            || self.components.len() != MAX_PROVIDER_GENERATION_COMPONENTS
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider generation export manifest",
            });
        }
        let provider_id = self.provider.id()?;
        match (&self.latest_head, self.tree_size) {
            (None, 0) if self.tree_root == crate::merkle::empty_merkle_root() => {}
            (Some(head), size) if size != 0 => {
                head.verify(&self.provider)?;
                if head.body().provider_id() != provider_id
                    || head.body().log_id() != self.log_id
                    || head.body().key_version() != self.key_version
                    || head.body().tree_size() != self.tree_size
                    || head.body().tree_root() != self.tree_root
                {
                    return Err(IdentityError::InvalidRelationship {
                        resource: "provider generation manifest latest head",
                    });
                }
            }
            _ => {
                return Err(IdentityError::InvalidRelationship {
                    resource: "provider generation manifest empty state",
                });
            }
        }
        let mut total_payload_bytes = 0_u64;
        let mut total_chunk_count = 0_usize;
        for (expected, descriptor) in ProviderExportComponent::ordered()
            .into_iter()
            .zip(self.components.as_slice())
        {
            descriptor.validate()?;
            if descriptor.component()? != expected {
                return Err(IdentityError::NonCanonical);
            }
            total_payload_bytes = total_payload_bytes
                .checked_add(descriptor.total_payload_bytes)
                .ok_or(IdentityError::ArithmeticOverflow {
                    resource: "provider generation manifest total bytes",
                })?;
            total_chunk_count = total_chunk_count
                .checked_add(usize::try_from(descriptor.chunk_count).map_err(|_| {
                    IdentityError::ArithmeticOverflow {
                        resource: "provider generation manifest total chunks",
                    }
                })?)
                .ok_or(IdentityError::ArithmeticOverflow {
                    resource: "provider generation manifest total chunks",
                })?;
        }
        if total_payload_bytes != self.total_payload_bytes
            || total_chunk_count > MAX_PROVIDER_EXPORT_CHUNKS
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider generation manifest aggregate accounting",
            });
        }
        let entries = self.descriptor(ProviderExportComponent::Entries)?;
        let leaves = self.descriptor(ProviderExportComponent::LeafHashes)?;
        let receipts = self.descriptor(ProviderExportComponent::Receipts)?;
        let checkpoint_bundles = self.descriptor(ProviderExportComponent::CheckpointBundles)?;
        if entries.item_count != self.tree_size
            || leaves.item_count != self.tree_size
            || receipts.item_count != self.tree_size
            || checkpoint_bundles.item_count > self.tree_size
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider generation manifest parallel streams",
            });
        }
        Ok(())
    }
}

impl CanonicalCodec for ProviderGenerationExportManifest {
    const RESOURCE: &'static str = "provider generation export manifest bytes";
    const MAX_ENCODED_BYTES: usize = MAX_PROVIDER_EXPORT_MANIFEST_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        self.validate()?;
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        let value: Self = decode_wire(bytes)?;
        value.validate()?;
        Ok(value)
    }
}

impl ProviderAuditExportManifest {
    /// Provider descriptor authenticating this journal.
    pub const fn provider(&self) -> &ProviderDescriptor {
        &self.provider
    }

    /// Exact log generation audited by this journal.
    pub const fn log_id(&self) -> ProviderLogId {
        self.log_id
    }

    /// Latest accepted authenticated provider head.
    pub const fn latest_head(&self) -> Option<&SignedProviderHead> {
        self.latest_head.as_ref()
    }

    /// First retained same-size conflicting-head evidence, if any.
    pub const fn equivocation_evidence(&self) -> Option<&ProviderEquivocationEvidence> {
        self.equivocation.as_ref()
    }

    /// Exact number of audit records.
    pub const fn record_count(&self) -> u64 {
        self.record_count
    }

    /// Exact number of bounded audit chunks.
    pub const fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    /// Sum of exact canonical audit-record item bytes.
    pub const fn total_payload_bytes(&self) -> u64 {
        self.total_payload_bytes
    }

    /// Authoritative complete audit-journal commitment.
    pub const fn audit_commitment(&self) -> Digest {
        self.audit_commitment
    }

    /// Authoritative sorted audit-artifact commitment.
    pub const fn artifact_commitment(&self) -> Digest {
        self.artifact_commitment
    }

    /// Exact number of derived rollback/equivocation artifacts.
    pub const fn artifact_count(&self) -> u64 {
        self.artifact_count
    }

    /// Ordered-list commitment over every audit chunk commitment.
    pub const fn chunk_list_commitment(&self) -> Digest {
        self.chunk_list_commitment
    }

    /// Domain-separated commitment to the exact canonical manifest bytes.
    pub fn commitment(&self) -> Result<Digest, IdentityError> {
        self.validate()?;
        domain_commitment(AUDIT_MANIFEST_DOMAIN, self)
    }

    fn validate(&self) -> Result<(), IdentityError> {
        require_version(self.format_version)?;
        let record_count =
            usize::try_from(self.record_count).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "provider audit manifest record count",
            })?;
        let chunk_count =
            usize::try_from(self.chunk_count).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "provider audit manifest chunk count",
            })?;
        let minimum_chunk_count = record_count.div_ceil(MAX_PROVIDER_EXPORT_CHUNK_ITEMS);
        if record_count > MAX_PROVIDER_AUDIT_RECORDS
            || chunk_count > MAX_PROVIDER_EXPORT_CHUNKS
            || (record_count == 0) != (chunk_count == 0)
            || chunk_count < minimum_chunk_count
            || chunk_count > record_count
            || self.total_payload_bytes
                > u64::try_from(MAX_PROVIDER_PORTABLE_AUDIT_BYTES).map_err(|_| {
                    IdentityError::ArithmeticOverflow {
                        resource: "portable audit byte limit",
                    }
                })?
            || [
                self.audit_commitment,
                self.artifact_commitment,
                self.chunk_list_commitment,
            ]
            .iter()
            .any(|digest| digest.algorithm() != HashAlgorithm::Blake3_256)
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider audit export manifest",
            });
        }
        if record_count == 0 {
            let empty_snapshot = provider_audit_snapshot_from_wire_records(
                self.provider.clone(),
                self.log_id,
                None,
                None,
                Vec::new(),
            )?;
            if self.latest_head.is_some()
                || self.equivocation.is_some()
                || self.artifact_count != 0
                || self.total_payload_bytes != 0
                || self.audit_commitment != empty_snapshot.commitment()?
                || self.artifact_commitment != provider_audit_artifact_commitment(&[])?
                || self.chunk_list_commitment
                    != ordered_chunk_list_commitment(AUDIT_CHUNK_LIST_DOMAIN, 0, &[])?
            {
                return Err(IdentityError::InvalidRelationship {
                    resource: "empty provider audit export manifest",
                });
            }
        } else if self.latest_head.is_none()
            || self.total_payload_bytes == 0
            || self.artifact_count > self.record_count
            || (self.equivocation.is_some() && self.artifact_count == 0)
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider audit export manifest record accounting",
            });
        }
        let provider_id = self.provider.id()?;
        if let Some(head) = &self.latest_head {
            head.verify(&self.provider)?;
            if head.body().provider_id() != provider_id || head.body().log_id() != self.log_id {
                return Err(IdentityError::InvalidRelationship {
                    resource: "provider audit manifest latest head",
                });
            }
        }
        if let Some(evidence) = &self.equivocation {
            evidence.verify(&self.provider)?;
            if evidence.first().body().provider_id() != provider_id
                || evidence.second().body().provider_id() != provider_id
                || evidence.first().body().log_id() != self.log_id
                || evidence.second().body().log_id() != self.log_id
            {
                return Err(IdentityError::InvalidRelationship {
                    resource: "provider audit manifest equivocation route",
                });
            }
        }
        Ok(())
    }
}

impl CanonicalCodec for ProviderAuditExportManifest {
    const RESOURCE: &'static str = "provider audit export manifest bytes";
    const MAX_ENCODED_BYTES: usize = MAX_PROVIDER_EXPORT_MANIFEST_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        self.validate()?;
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        let value: Self = decode_wire(bytes)?;
        value.validate()?;
        Ok(value)
    }
}

impl ProviderRecoveryExportManifest {
    /// Complete generation chunk index.
    pub const fn generation(&self) -> &ProviderGenerationExportManifest {
        &self.generation
    }

    /// Complete audit-journal chunk index.
    pub const fn audit(&self) -> &ProviderAuditExportManifest {
        &self.audit
    }

    /// Composite authoritative recovery commitment.
    pub const fn recovery_commitment(&self) -> Digest {
        self.recovery_commitment
    }

    /// Commitment to the exact embedded generation manifest.
    pub const fn generation_manifest_commitment(&self) -> Digest {
        self.generation_manifest_commitment
    }

    /// Commitment to the exact embedded audit manifest.
    pub const fn audit_manifest_commitment(&self) -> Digest {
        self.audit_manifest_commitment
    }

    /// Authoritative generation aggregate commitment.
    pub const fn generation_commitment(&self) -> Digest {
        self.generation_commitment
    }

    /// Authoritative audit aggregate commitment.
    pub const fn audit_commitment(&self) -> Digest {
        self.audit_commitment
    }

    /// Authoritative derived-artifact aggregate commitment.
    pub const fn artifact_commitment(&self) -> Digest {
        self.artifact_commitment
    }

    /// Domain-separated commitment to the exact canonical recovery manifest bytes.
    pub fn commitment(&self) -> Result<Digest, IdentityError> {
        self.validate()?;
        domain_commitment(RECOVERY_MANIFEST_DOMAIN, self)
    }

    /// Bind two fully assembled aggregates through the authoritative recovery constructor.
    pub fn finish(
        &self,
        generation: ProviderGenerationExport,
        audit: ProviderAuditSnapshot,
    ) -> Result<ProviderRecoveryExport, IdentityError> {
        self.validate()?;
        if generation.provider() != self.generation.provider()
            || generation.log_id() != self.generation.log_id()
            || audit.provider() != self.audit.provider()
            || audit.log_id() != self.audit.log_id()
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider recovery manifest assembled route",
            });
        }
        let recovery = ProviderRecoveryExport::new(generation, audit)?;
        if recovery.generation_commitment() != self.generation_commitment
            || recovery.audit_commitment() != self.audit_commitment
            || recovery.artifact_commitment() != self.artifact_commitment
            || recovery.recovery_commitment() != self.recovery_commitment
        {
            return Err(IdentityError::InvalidProof);
        }
        Ok(recovery)
    }

    fn validate(&self) -> Result<(), IdentityError> {
        require_version(self.format_version)?;
        self.generation.validate()?;
        self.audit.validate()?;
        if self.generation.provider != self.audit.provider
            || self.generation.log_id != self.audit.log_id
            || self.generation.latest_head.as_ref() != self.audit.latest_head.as_ref()
            || self.generation_manifest_commitment != self.generation.commitment()?
            || self.audit_manifest_commitment != self.audit.commitment()?
            || self.generation_commitment != self.generation.generation_commitment
            || self.audit_commitment != self.audit.audit_commitment
            || self.artifact_commitment != self.audit.artifact_commitment
            || [
                self.generation_manifest_commitment,
                self.audit_manifest_commitment,
                self.generation_commitment,
                self.audit_commitment,
                self.artifact_commitment,
                self.recovery_commitment,
            ]
            .iter()
            .any(|digest| digest.algorithm() != HashAlgorithm::Blake3_256)
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider recovery export manifest",
            });
        }
        let expected_recovery = super::provider_recovery_commitment(
            self.generation_commitment,
            self.audit_commitment,
            self.artifact_commitment,
        )?;
        if self.recovery_commitment != expected_recovery {
            return Err(IdentityError::InvalidProof);
        }
        Ok(())
    }
}

impl CanonicalCodec for ProviderRecoveryExportManifest {
    const RESOURCE: &'static str = "provider recovery export manifest bytes";
    const MAX_ENCODED_BYTES: usize = MAX_PROVIDER_RECOVERY_MANIFEST_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        self.validate()?;
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        let value: Self = decode_wire(bytes)?;
        value.validate()?;
        Ok(value)
    }
}

/// Bounded out-of-order assembler for one generation manifest.
#[derive(Debug)]
pub struct ProviderGenerationExportAssembler {
    manifest: ProviderGenerationExportManifest,
    pending: BTreeMap<(u16, u32), ProviderGenerationExportChunk>,
    retained_payload_bytes: u64,
}

/// Bounded out-of-order assembler for one audit manifest.
#[derive(Debug)]
pub struct ProviderAuditExportAssembler {
    manifest: ProviderAuditExportManifest,
    pending: BTreeMap<u32, ProviderAuditExportChunk>,
    retained_payload_bytes: u64,
}

impl ProviderGenerationExportAssembler {
    /// Start an assembler only after validating all aggregate count and byte commitments.
    pub fn new(manifest: ProviderGenerationExportManifest) -> Result<Self, IdentityError> {
        manifest.validate()?;
        Ok(Self {
            manifest,
            pending: BTreeMap::new(),
            retained_payload_bytes: 0,
        })
    }

    /// Insert one chunk. Exact replay is idempotent; a conflicting ordinal fails closed.
    pub fn insert(&mut self, chunk: ProviderGenerationExportChunk) -> Result<bool, IdentityError> {
        chunk.validate()?;
        if chunk.provider_id != self.manifest.provider.id()?
            || chunk.log_id != self.manifest.log_id
            || chunk.key_version != self.manifest.key_version
            || chunk.generation_commitment != self.manifest.generation_commitment
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider generation chunk manifest binding",
            });
        }
        let component = chunk.component()?;
        let descriptor = self.manifest.descriptor(component)?;
        if chunk.ordinal >= descriptor.chunk_count || chunk.end_index > descriptor.item_count {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider generation chunk descriptor range",
            });
        }
        let key = (component.code(), chunk.ordinal);
        if let Some(retained) = self.pending.get(&key) {
            return if retained == &chunk {
                Ok(false)
            } else {
                Err(IdentityError::DuplicateElement {
                    resource: "provider generation chunk ordinal",
                })
            };
        }
        let next_payload_bytes = self
            .retained_payload_bytes
            .checked_add(chunk.item_payload_bytes)
            .ok_or(IdentityError::ArithmeticOverflow {
                resource: "provider generation assembler retained bytes",
            })?;
        if next_payload_bytes > self.manifest.total_payload_bytes
            || next_payload_bytes
                > u64::try_from(MAX_PROVIDER_PORTABLE_GENERATION_BYTES).map_err(|_| {
                    IdentityError::ArithmeticOverflow {
                        resource: "portable generation byte limit",
                    }
                })?
        {
            return Err(IdentityError::limit(
                "provider generation assembler retained bytes",
                usize::try_from(next_payload_bytes).unwrap_or(usize::MAX),
                MAX_PROVIDER_PORTABLE_GENERATION_BYTES,
            ));
        }
        self.pending.insert(key, chunk);
        self.retained_payload_bytes = next_payload_bytes;
        Ok(true)
    }

    /// Finish only after every committed component range is present exactly once.
    pub fn finish(self) -> Result<ProviderGenerationExport, IdentityError> {
        let expected_chunks =
            self.manifest
                .components
                .as_slice()
                .iter()
                .try_fold(0_usize, |total, descriptor| {
                    total
                        .checked_add(usize::try_from(descriptor.chunk_count).map_err(|_| {
                            IdentityError::ArithmeticOverflow {
                                resource: "provider generation expected chunks",
                            }
                        })?)
                        .ok_or(IdentityError::ArithmeticOverflow {
                            resource: "provider generation expected chunks",
                        })
                })?;
        if self.pending.len() != expected_chunks
            || self.retained_payload_bytes != self.manifest.total_payload_bytes
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "incomplete provider generation export",
            });
        }

        let entries = decode_generation_component::<ProviderLogEntryBody>(
            &self.manifest,
            &self.pending,
            ProviderExportComponent::Entries,
        )?;
        let leaf_hashes = decode_generation_component::<Digest>(
            &self.manifest,
            &self.pending,
            ProviderExportComponent::LeafHashes,
        )?;
        let receipts = decode_generation_component::<InclusionReceipt>(
            &self.manifest,
            &self.pending,
            ProviderExportComponent::Receipts,
        )?;
        let checkpoint_bundles = decode_checkpoint_bundle_component(&self.manifest, &self.pending)?;
        let compaction_manifests = decode_generation_component::<ProviderCompactionManifest>(
            &self.manifest,
            &self.pending,
            ProviderExportComponent::CompactionManifests,
        )?;
        let export = ProviderGenerationExport {
            provider: self.manifest.provider.clone(),
            log_id: self.manifest.log_id,
            key_version: self.manifest.key_version,
            entries,
            leaf_hashes,
            latest_head: self.manifest.latest_head.clone(),
            receipts,
            checkpoint_bundles,
            compaction_manifests,
        };
        let restored = MemoryProviderStore::restore_generation(export)?;
        let (rebuilt, snapshot) = restored.export_and_snapshot_from_validated_state()?;
        let (manifest, _) = rebuilt.interchange_parts_validated(&snapshot)?;
        if manifest != self.manifest {
            return Err(IdentityError::InvalidProof);
        }
        Ok(rebuilt)
    }
}

impl ProviderAuditExportAssembler {
    /// Start an assembler only after validating all aggregate count and byte commitments.
    pub fn new(manifest: ProviderAuditExportManifest) -> Result<Self, IdentityError> {
        manifest.validate()?;
        Ok(Self {
            manifest,
            pending: BTreeMap::new(),
            retained_payload_bytes: 0,
        })
    }

    /// Insert one chunk. Exact replay is idempotent; a conflicting ordinal fails closed.
    pub fn insert(&mut self, chunk: ProviderAuditExportChunk) -> Result<bool, IdentityError> {
        chunk.validate()?;
        if chunk.provider_id != self.manifest.provider.id()?
            || chunk.log_id != self.manifest.log_id
            || chunk.audit_commitment != self.manifest.audit_commitment
            || chunk.ordinal >= self.manifest.chunk_count
            || chunk.end_sequence > self.manifest.record_count.saturating_add(1)
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider audit chunk manifest binding",
            });
        }
        if let Some(retained) = self.pending.get(&chunk.ordinal) {
            return if retained == &chunk {
                Ok(false)
            } else {
                Err(IdentityError::DuplicateElement {
                    resource: "provider audit chunk ordinal",
                })
            };
        }
        let next_payload_bytes = self
            .retained_payload_bytes
            .checked_add(chunk.item_payload_bytes)
            .ok_or(IdentityError::ArithmeticOverflow {
                resource: "provider audit assembler retained bytes",
            })?;
        if next_payload_bytes > self.manifest.total_payload_bytes
            || next_payload_bytes
                > u64::try_from(MAX_PROVIDER_PORTABLE_AUDIT_BYTES).map_err(|_| {
                    IdentityError::ArithmeticOverflow {
                        resource: "portable audit byte limit",
                    }
                })?
        {
            return Err(IdentityError::limit(
                "provider audit assembler retained bytes",
                usize::try_from(next_payload_bytes).unwrap_or(usize::MAX),
                MAX_PROVIDER_PORTABLE_AUDIT_BYTES,
            ));
        }
        self.retained_payload_bytes = next_payload_bytes;
        self.pending.insert(chunk.ordinal, chunk);
        Ok(true)
    }

    /// Finish only after every committed journal range is present exactly once.
    pub fn finish(self) -> Result<ProviderAuditSnapshot, IdentityError> {
        if self.pending.len()
            != usize::try_from(self.manifest.chunk_count).map_err(|_| {
                IdentityError::ArithmeticOverflow {
                    resource: "provider audit expected chunks",
                }
            })?
            || self.retained_payload_bytes != self.manifest.total_payload_bytes
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "incomplete provider audit export",
            });
        }
        let mut expected_sequence = 1_u64;
        let mut commitments = Vec::with_capacity(self.pending.len());
        let mut records =
            Vec::with_capacity(usize::try_from(self.manifest.record_count).map_err(|_| {
                IdentityError::ArithmeticOverflow {
                    resource: "provider audit record allocation",
                }
            })?);
        for ordinal in 0..self.manifest.chunk_count {
            let chunk = self
                .pending
                .get(&ordinal)
                .ok_or(IdentityError::InvalidRelationship {
                    resource: "provider audit chunk ordinal gap",
                })?;
            if chunk.start_sequence != expected_sequence {
                return Err(IdentityError::InvalidRelationship {
                    resource: "provider audit chunk range gap or overlap",
                });
            }
            expected_sequence = chunk.end_sequence;
            commitments.push(chunk.commitment()?);
            records.extend(
                chunk
                    .item_bytes()?
                    .into_iter()
                    .map(|bytes| decode_audit_record_item(&bytes))
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
        if expected_sequence != self.manifest.record_count.saturating_add(1)
            || ordered_chunk_list_commitment(AUDIT_CHUNK_LIST_DOMAIN, 0, &commitments)?
                != self.manifest.chunk_list_commitment
        {
            return Err(IdentityError::InvalidProof);
        }
        let snapshot = provider_audit_snapshot_from_wire_records(
            self.manifest.provider.clone(),
            self.manifest.log_id,
            self.manifest.latest_head.clone(),
            self.manifest.equivocation.clone(),
            records,
        )?;
        if snapshot.commitment_validated()? != self.manifest.audit_commitment {
            return Err(IdentityError::InvalidProof);
        }
        let artifacts = snapshot.artifacts_validated()?;
        if u64::try_from(artifacts.len()).map_err(|_| IdentityError::ArithmeticOverflow {
            resource: "provider audit artifact count",
        })? != self.manifest.artifact_count
            || provider_audit_artifact_commitment(&artifacts)? != self.manifest.artifact_commitment
        {
            return Err(IdentityError::InvalidProof);
        }
        Ok(snapshot)
    }
}

impl ProviderGenerationExport {
    /// Build the small canonical manifest and independently bounded component chunks.
    pub fn interchange_parts(
        &self,
    ) -> Result<
        (
            ProviderGenerationExportManifest,
            Vec<ProviderGenerationExportChunk>,
        ),
        IdentityError,
    > {
        let store = MemoryProviderStore::restore_generation(self.clone())?;
        let (restored, snapshot) = store.export_and_snapshot_from_validated_state()?;
        if &restored != self {
            return Err(IdentityError::InvalidProof);
        }
        restored.interchange_parts_validated(&snapshot)
    }

    fn interchange_parts_validated(
        &self,
        snapshot: &ProviderGenerationSnapshot,
    ) -> Result<
        (
            ProviderGenerationExportManifest,
            Vec<ProviderGenerationExportChunk>,
        ),
        IdentityError,
    > {
        let generation_commitment = super::compaction::provider_generation_export_commitment(self)?;
        let provider_id = self.provider.id()?;
        let mut all_chunks = Vec::new();
        let mut descriptors = Vec::with_capacity(MAX_PROVIDER_GENERATION_COMPONENTS);

        for component in ProviderExportComponent::ordered() {
            let items = encode_generation_component_items(self, component)?;
            let chunks = build_generation_chunks(
                provider_id,
                self.log_id,
                self.key_version,
                generation_commitment,
                component,
                items,
            )?;
            let item_count = chunks.iter().try_fold(0_u64, |total, chunk| {
                total
                    .checked_add(chunk.end_index.checked_sub(chunk.start_index).ok_or(
                        IdentityError::ArithmeticOverflow {
                            resource: "provider generation component chunk range",
                        },
                    )?)
                    .ok_or(IdentityError::ArithmeticOverflow {
                        resource: "provider generation component items",
                    })
            })?;
            let total_payload_bytes = chunks.iter().try_fold(0_u64, |total, chunk| {
                total.checked_add(chunk.item_payload_bytes).ok_or(
                    IdentityError::ArithmeticOverflow {
                        resource: "provider generation component bytes",
                    },
                )
            })?;
            let commitments = chunks
                .iter()
                .map(ProviderGenerationExportChunk::commitment)
                .collect::<Result<Vec<_>, _>>()?;
            descriptors.push(ProviderExportComponentDescriptor {
                format_version: 1,
                component_code: component.code(),
                item_count,
                chunk_count: u32::try_from(chunks.len()).map_err(|_| {
                    IdentityError::ArithmeticOverflow {
                        resource: "provider generation component chunks",
                    }
                })?,
                total_payload_bytes,
                chunk_list_commitment: ordered_chunk_list_commitment(
                    GENERATION_CHUNK_LIST_DOMAIN,
                    component.code(),
                    &commitments,
                )?,
            });
            all_chunks.extend(chunks);
        }
        let total_payload_bytes = descriptors.iter().try_fold(0_u64, |total, descriptor| {
            total.checked_add(descriptor.total_payload_bytes).ok_or(
                IdentityError::ArithmeticOverflow {
                    resource: "provider generation manifest bytes",
                },
            )
        })?;
        if total_payload_bytes
            > u64::try_from(MAX_PROVIDER_PORTABLE_GENERATION_BYTES).map_err(|_| {
                IdentityError::ArithmeticOverflow {
                    resource: "portable generation byte limit",
                }
            })?
        {
            return Err(IdentityError::limit(
                "portable provider generation bytes",
                usize::try_from(total_payload_bytes).unwrap_or(usize::MAX),
                MAX_PROVIDER_PORTABLE_GENERATION_BYTES,
            ));
        }
        let manifest = ProviderGenerationExportManifest {
            format_version: 1,
            provider: self.provider.clone(),
            log_id: self.log_id,
            key_version: self.key_version,
            tree_size: snapshot.tree_size(),
            tree_root: snapshot.tree_root(),
            latest_head: self.latest_head.clone(),
            generation_commitment,
            total_payload_bytes,
            components: BoundedVec::new("provider generation component descriptors", descriptors)?,
        };
        manifest.to_canonical_bytes()?;
        Ok((manifest, all_chunks))
    }
}

impl ProviderAuditSnapshot {
    /// Build the small canonical manifest and independently bounded journal chunks.
    pub fn interchange_parts(
        &self,
    ) -> Result<(ProviderAuditExportManifest, Vec<ProviderAuditExportChunk>), IdentityError> {
        self.validate()?;
        self.interchange_parts_validated()
    }

    fn interchange_parts_validated(
        &self,
    ) -> Result<(ProviderAuditExportManifest, Vec<ProviderAuditExportChunk>), IdentityError> {
        let audit_commitment = self.commitment_validated()?;
        let artifacts = self.artifacts_validated()?;
        let artifact_commitment = provider_audit_artifact_commitment(&artifacts)?;
        let item_bytes = self
            .records()
            .iter()
            .map(|record| {
                encode_wire(&ProviderAuditRecordItemWire {
                    format_version: 1,
                    record: ProviderAuditRecordWire::from_record(record),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let chunks = build_audit_chunks(
            self.provider().id()?,
            self.log_id(),
            audit_commitment,
            item_bytes,
        )?;
        let total_payload_bytes = chunks.iter().try_fold(0_u64, |total, chunk| {
            total
                .checked_add(chunk.item_payload_bytes)
                .ok_or(IdentityError::ArithmeticOverflow {
                    resource: "provider audit manifest bytes",
                })
        })?;
        if total_payload_bytes
            > u64::try_from(MAX_PROVIDER_PORTABLE_AUDIT_BYTES).map_err(|_| {
                IdentityError::ArithmeticOverflow {
                    resource: "portable audit byte limit",
                }
            })?
        {
            return Err(IdentityError::limit(
                "portable provider audit bytes",
                usize::try_from(total_payload_bytes).unwrap_or(usize::MAX),
                MAX_PROVIDER_PORTABLE_AUDIT_BYTES,
            ));
        }
        let commitments = chunks
            .iter()
            .map(ProviderAuditExportChunk::commitment)
            .collect::<Result<Vec<_>, _>>()?;
        let manifest = ProviderAuditExportManifest {
            format_version: 1,
            provider: self.provider().clone(),
            log_id: self.log_id(),
            latest_head: self.latest_head().cloned(),
            equivocation: self.equivocation_evidence().cloned(),
            record_count: u64::try_from(self.records().len()).map_err(|_| {
                IdentityError::ArithmeticOverflow {
                    resource: "provider audit manifest records",
                }
            })?,
            chunk_count: u32::try_from(chunks.len()).map_err(|_| {
                IdentityError::ArithmeticOverflow {
                    resource: "provider audit manifest chunks",
                }
            })?,
            total_payload_bytes,
            audit_commitment,
            artifact_count: u64::try_from(artifacts.len()).map_err(|_| {
                IdentityError::ArithmeticOverflow {
                    resource: "provider audit manifest artifacts",
                }
            })?,
            artifact_commitment,
            chunk_list_commitment: ordered_chunk_list_commitment(
                AUDIT_CHUNK_LIST_DOMAIN,
                0,
                &commitments,
            )?,
        };
        manifest.to_canonical_bytes()?;
        Ok((manifest, chunks))
    }
}

impl ProviderRecoveryExport {
    /// Build the recovery manifest plus all independently bounded generation and audit chunks.
    pub fn interchange_parts(
        &self,
    ) -> Result<
        (
            ProviderRecoveryExportManifest,
            Vec<ProviderGenerationExportChunk>,
            Vec<ProviderAuditExportChunk>,
        ),
        IdentityError,
    > {
        let generation_snapshot = self.validate_with_generation_snapshot()?;
        let (generation, generation_chunks) = self
            .generation()
            .interchange_parts_validated(&generation_snapshot)?;
        let (audit, audit_chunks) = self.audit().interchange_parts_validated()?;
        let manifest = ProviderRecoveryExportManifest {
            format_version: 1,
            generation_manifest_commitment: generation.commitment()?,
            audit_manifest_commitment: audit.commitment()?,
            generation_commitment: self.generation_commitment(),
            audit_commitment: self.audit_commitment(),
            artifact_commitment: self.artifact_commitment(),
            recovery_commitment: self.recovery_commitment(),
            generation,
            audit,
        };
        manifest.to_canonical_bytes()?;
        Ok((manifest, generation_chunks, audit_chunks))
    }
}

fn build_generation_chunks(
    provider_id: ProviderId,
    log_id: ProviderLogId,
    key_version: ProviderKeyVersion,
    generation_commitment: Digest,
    component: ProviderExportComponent,
    items: Vec<Vec<u8>>,
) -> Result<Vec<ProviderGenerationExportChunk>, IdentityError> {
    let groups = chunk_item_groups(items)?;
    let mut start_index = 0_u64;
    let mut chunks = Vec::with_capacity(groups.len());
    for (ordinal, group) in groups.into_iter().enumerate() {
        let item_count =
            u64::try_from(group.len()).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "provider generation chunk item count",
            })?;
        let end_index =
            start_index
                .checked_add(item_count)
                .ok_or(IdentityError::ArithmeticOverflow {
                    resource: "provider generation chunk end",
                })?;
        let item_payload_bytes = canonical_item_bytes(&group)?;
        let payload = encode_chunk_items(group)?;
        let chunk = ProviderGenerationExportChunk {
            format_version: 1,
            provider_id,
            log_id,
            key_version,
            generation_commitment,
            component_code: component.code(),
            ordinal: u32::try_from(ordinal).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "provider generation chunk ordinal",
            })?,
            start_index,
            end_index,
            item_payload_bytes,
            payload: BoundedBytes::new("provider generation chunk payload", payload)?,
        };
        chunk.to_canonical_bytes()?;
        chunks.push(chunk);
        start_index = end_index;
    }
    Ok(chunks)
}

fn build_audit_chunks(
    provider_id: ProviderId,
    log_id: ProviderLogId,
    audit_commitment: Digest,
    items: Vec<Vec<u8>>,
) -> Result<Vec<ProviderAuditExportChunk>, IdentityError> {
    let groups = chunk_item_groups(items)?;
    let mut start_sequence = 1_u64;
    let mut chunks = Vec::with_capacity(groups.len());
    for (ordinal, group) in groups.into_iter().enumerate() {
        let item_count =
            u64::try_from(group.len()).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "provider audit chunk item count",
            })?;
        let end_sequence =
            start_sequence
                .checked_add(item_count)
                .ok_or(IdentityError::ArithmeticOverflow {
                    resource: "provider audit chunk end sequence",
                })?;
        let item_payload_bytes = canonical_item_bytes(&group)?;
        let payload = encode_chunk_items(group)?;
        let chunk = ProviderAuditExportChunk {
            format_version: 1,
            provider_id,
            log_id,
            audit_commitment,
            ordinal: u32::try_from(ordinal).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "provider audit chunk ordinal",
            })?,
            start_sequence,
            end_sequence,
            item_payload_bytes,
            payload: BoundedBytes::new("provider audit chunk payload", payload)?,
        };
        chunk.to_canonical_bytes()?;
        chunks.push(chunk);
        start_sequence = end_sequence;
    }
    Ok(chunks)
}

fn encode_generation_component_items(
    export: &ProviderGenerationExport,
    component: ProviderExportComponent,
) -> Result<Vec<Vec<u8>>, IdentityError> {
    match component {
        ProviderExportComponent::Entries => export
            .entries
            .iter()
            .map(|entry| entry.to_canonical_bytes())
            .collect(),
        ProviderExportComponent::LeafHashes => export
            .leaf_hashes
            .iter()
            .map(|leaf_hash| leaf_hash.to_canonical_bytes())
            .collect(),
        ProviderExportComponent::Receipts => export
            .receipts
            .iter()
            .map(|receipt| receipt.to_canonical_bytes())
            .collect(),
        ProviderExportComponent::CheckpointBundles => export
            .checkpoint_bundles
            .iter()
            .map(|bundle| {
                encode_wire(&ProviderCheckpointBundleItemWire {
                    format_version: 1,
                    bundle: ProviderCheckpointBundleWire::from_bundle(bundle)?,
                })
            })
            .collect(),
        ProviderExportComponent::CompactionManifests => export
            .compaction_manifests
            .iter()
            .map(|manifest| manifest.to_canonical_bytes())
            .collect(),
    }
}

pub(super) fn validate_checkpoint_bundle_interchange_item(
    bundle: &crate::ProviderCheckpointBundle,
) -> Result<(), IdentityError> {
    checkpoint_bundle_item_bytes(bundle).and_then(validate_single_item_bytes)
}

pub(super) fn validate_generation_interchange_bounds(
    export: &ProviderGenerationExport,
) -> Result<(), IdentityError> {
    ProviderGenerationPortableAccounting::from_export(export).map(|_| ())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PortableComponentAccounting {
    items: usize,
    bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProviderGenerationPortableAccounting {
    entries: PortableComponentAccounting,
    leaf_hashes: PortableComponentAccounting,
    receipts: PortableComponentAccounting,
    checkpoint_bundles: PortableComponentAccounting,
    compaction_manifests: PortableComponentAccounting,
    total_bytes: usize,
}

impl ProviderGenerationPortableAccounting {
    pub(super) const fn empty() -> Self {
        let empty = PortableComponentAccounting { items: 0, bytes: 0 };
        Self {
            entries: empty,
            leaf_hashes: empty,
            receipts: empty,
            checkpoint_bundles: empty,
            compaction_manifests: empty,
            total_bytes: 0,
        }
    }

    pub(super) fn from_export(export: &ProviderGenerationExport) -> Result<Self, IdentityError> {
        let mut accounting = Self::empty();
        for entry in &export.entries {
            accounting = accounting.with_appended_entry(entry)?;
        }
        for leaf_hash in &export.leaf_hashes {
            accounting = accounting.with_appended_leaf_hash(leaf_hash)?;
        }
        for receipt in &export.receipts {
            accounting = accounting.with_appended_receipt(receipt)?;
        }
        for bundle in &export.checkpoint_bundles {
            accounting = accounting.with_appended_checkpoint_bundle(bundle)?;
        }
        for manifest in &export.compaction_manifests {
            accounting = accounting.with_appended_compaction_manifest(manifest)?;
        }
        Ok(accounting)
    }

    pub(super) fn with_appended_entry(
        self,
        entry: &ProviderLogEntryBody,
    ) -> Result<Self, IdentityError> {
        self.with_appended_bytes(
            ProviderExportComponent::Entries,
            encoded_canonical_item_len(entry)?,
        )
    }

    pub(super) fn with_appended_leaf_hash(self, leaf_hash: &Digest) -> Result<Self, IdentityError> {
        self.with_appended_bytes(
            ProviderExportComponent::LeafHashes,
            encoded_canonical_item_len(leaf_hash)?,
        )
    }

    pub(super) fn with_appended_receipt(
        self,
        receipt: &InclusionReceipt,
    ) -> Result<Self, IdentityError> {
        self.with_appended_bytes(
            ProviderExportComponent::Receipts,
            encoded_canonical_item_len(receipt)?,
        )
    }

    pub(super) fn with_replaced_receipt(
        self,
        old: &InclusionReceipt,
        new: &InclusionReceipt,
    ) -> Result<Self, IdentityError> {
        self.with_replaced_bytes(
            ProviderExportComponent::Receipts,
            encoded_canonical_item_len(old)?,
            encoded_canonical_item_len(new)?,
        )
    }

    pub(super) fn with_appended_checkpoint_bundle(
        self,
        bundle: &crate::ProviderCheckpointBundle,
    ) -> Result<Self, IdentityError> {
        self.with_appended_bytes(
            ProviderExportComponent::CheckpointBundles,
            checkpoint_bundle_item_bytes(bundle)?,
        )
    }

    pub(super) fn with_replaced_checkpoint_bundle(
        self,
        old: &crate::ProviderCheckpointBundle,
        new: &crate::ProviderCheckpointBundle,
    ) -> Result<Self, IdentityError> {
        self.with_replaced_bytes(
            ProviderExportComponent::CheckpointBundles,
            checkpoint_bundle_item_bytes(old)?,
            checkpoint_bundle_item_bytes(new)?,
        )
    }

    pub(super) fn with_appended_compaction_manifest(
        self,
        manifest: &ProviderCompactionManifest,
    ) -> Result<Self, IdentityError> {
        self.with_appended_bytes(
            ProviderExportComponent::CompactionManifests,
            encoded_canonical_item_len(manifest)?,
        )
    }

    fn with_appended_bytes(
        mut self,
        component: ProviderExportComponent,
        item_bytes: usize,
    ) -> Result<Self, IdentityError> {
        validate_single_item_bytes(item_bytes)?;
        let item_limit = component_item_limit(component);
        let component_accounting = self.component_mut(component);
        let next_items =
            component_accounting
                .items
                .checked_add(1)
                .ok_or(IdentityError::ArithmeticOverflow {
                    resource: "portable provider generation component items",
                })?;
        if next_items > item_limit {
            return Err(IdentityError::limit(
                "portable provider generation component items",
                next_items,
                item_limit,
            ));
        }
        component_accounting.bytes = component_accounting.bytes.checked_add(item_bytes).ok_or(
            IdentityError::ArithmeticOverflow {
                resource: "portable provider generation component bytes",
            },
        )?;
        component_accounting.items = next_items;
        self.total_bytes = checked_portable_total_add(self.total_bytes, item_bytes)?;
        Ok(self)
    }

    fn with_replaced_bytes(
        mut self,
        component: ProviderExportComponent,
        old_item_bytes: usize,
        new_item_bytes: usize,
    ) -> Result<Self, IdentityError> {
        validate_single_item_bytes(old_item_bytes)?;
        validate_single_item_bytes(new_item_bytes)?;
        let component_accounting = self.component_mut(component);
        if component_accounting.items == 0 {
            return Err(IdentityError::StorageCorruption);
        }
        component_accounting.bytes = component_accounting
            .bytes
            .checked_sub(old_item_bytes)
            .and_then(|bytes| bytes.checked_add(new_item_bytes))
            .ok_or(IdentityError::StorageCorruption)?;
        self.total_bytes = self
            .total_bytes
            .checked_sub(old_item_bytes)
            .ok_or(IdentityError::StorageCorruption)?;
        self.total_bytes = checked_portable_total_add(self.total_bytes, new_item_bytes)?;
        Ok(self)
    }

    fn component_mut(
        &mut self,
        component: ProviderExportComponent,
    ) -> &mut PortableComponentAccounting {
        match component {
            ProviderExportComponent::Entries => &mut self.entries,
            ProviderExportComponent::LeafHashes => &mut self.leaf_hashes,
            ProviderExportComponent::Receipts => &mut self.receipts,
            ProviderExportComponent::CheckpointBundles => &mut self.checkpoint_bundles,
            ProviderExportComponent::CompactionManifests => &mut self.compaction_manifests,
        }
    }
}

fn encoded_canonical_item_len<T: CanonicalWire>(item: &T) -> Result<usize, IdentityError> {
    record_portable_item_encoding();
    item.to_canonical_bytes().map(|bytes| bytes.len())
}

fn checkpoint_bundle_item_bytes(
    bundle: &crate::ProviderCheckpointBundle,
) -> Result<usize, IdentityError> {
    record_portable_item_encoding();
    encode_wire(&ProviderCheckpointBundleItemWire {
        format_version: 1,
        bundle: ProviderCheckpointBundleWire::from_bundle(bundle)?,
    })
    .map(|bytes| bytes.len())
}

fn checked_portable_total_add(total: usize, item_bytes: usize) -> Result<usize, IdentityError> {
    let next_total = total
        .checked_add(item_bytes)
        .ok_or(IdentityError::ArithmeticOverflow {
            resource: "portable provider generation bytes",
        })?;
    if next_total > MAX_PROVIDER_PORTABLE_GENERATION_BYTES {
        return Err(IdentityError::limit(
            "portable provider generation bytes",
            next_total,
            MAX_PROVIDER_PORTABLE_GENERATION_BYTES,
        ));
    }
    Ok(next_total)
}

pub(crate) fn validate_audit_interchange_bounds(
    snapshot: &ProviderAuditSnapshot,
) -> Result<(), IdentityError> {
    ProviderAuditPortableAccounting::from_snapshot(snapshot).map(|_| ())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProviderAuditPortableAccounting {
    records: usize,
    total_bytes: usize,
}

impl ProviderAuditPortableAccounting {
    pub(crate) const fn empty() -> Self {
        Self {
            records: 0,
            total_bytes: 0,
        }
    }

    pub(crate) fn from_snapshot(snapshot: &ProviderAuditSnapshot) -> Result<Self, IdentityError> {
        let mut accounting = Self::empty();
        for record in snapshot.records() {
            accounting = accounting.with_appended_record(record)?;
        }
        Ok(accounting)
    }

    pub(crate) fn with_appended_record(
        self,
        record: &ProviderAuditRecord,
    ) -> Result<Self, IdentityError> {
        let next_records =
            self.records
                .checked_add(1)
                .ok_or(IdentityError::ArithmeticOverflow {
                    resource: "portable provider audit records",
                })?;
        if next_records > MAX_PROVIDER_AUDIT_RECORDS {
            return Err(IdentityError::limit(
                "portable provider audit records",
                next_records,
                MAX_PROVIDER_AUDIT_RECORDS,
            ));
        }
        let record_bytes = audit_record_item_bytes(record)?;
        validate_single_item_bytes(record_bytes)?;
        let total_bytes = self.total_bytes.checked_add(record_bytes).ok_or(
            IdentityError::ArithmeticOverflow {
                resource: "portable provider audit bytes",
            },
        )?;
        if total_bytes > MAX_PROVIDER_PORTABLE_AUDIT_BYTES {
            return Err(IdentityError::limit(
                "portable provider audit bytes",
                total_bytes,
                MAX_PROVIDER_PORTABLE_AUDIT_BYTES,
            ));
        }
        Ok(Self {
            records: next_records,
            total_bytes,
        })
    }
}

fn audit_record_item_bytes(record: &ProviderAuditRecord) -> Result<usize, IdentityError> {
    record_portable_audit_record_encoding();
    encode_wire(&ProviderAuditRecordItemWire {
        format_version: 1,
        record: ProviderAuditRecordWire::from_record(record),
    })
    .map(|bytes| bytes.len())
}

fn validate_single_item_bytes(item_bytes: usize) -> Result<(), IdentityError> {
    if item_bytes > MAX_PROVIDER_EXPORT_ITEM_BYTES {
        return Err(IdentityError::limit(
            "provider export single canonical item bytes",
            item_bytes,
            MAX_PROVIDER_EXPORT_ITEM_BYTES,
        ));
    }
    Ok(())
}

fn validate_generation_item(
    component: ProviderExportComponent,
    bytes: &[u8],
) -> Result<(), IdentityError> {
    match component {
        ProviderExportComponent::Entries => {
            ProviderLogEntryBody::from_canonical_bytes(bytes).map(|_| ())
        }
        ProviderExportComponent::LeafHashes => Digest::from_canonical_bytes(bytes).map(|_| ()),
        ProviderExportComponent::Receipts => {
            InclusionReceipt::from_canonical_bytes(bytes).map(|_| ())
        }
        ProviderExportComponent::CheckpointBundles => {
            decode_checkpoint_bundle_item(bytes).map(|_| ())
        }
        ProviderExportComponent::CompactionManifests => {
            ProviderCompactionManifest::from_canonical_bytes(bytes).map(|_| ())
        }
    }
}

fn decode_checkpoint_bundle_item(
    bytes: &[u8],
) -> Result<ProviderCheckpointBundleWire, IdentityError> {
    let item: ProviderCheckpointBundleItemWire = decode_wire(bytes)?;
    require_version(item.format_version)?;
    item.bundle.validate_interchange_shape()?;
    Ok(item.bundle)
}

fn decode_audit_record_item(bytes: &[u8]) -> Result<ProviderAuditRecordWire, IdentityError> {
    let item: ProviderAuditRecordItemWire = decode_wire(bytes)?;
    require_version(item.format_version)?;
    item.record.clone().into_record()?;
    Ok(item.record)
}

fn chunk_item_groups(items: Vec<Vec<u8>>) -> Result<Vec<Vec<Vec<u8>>>, IdentityError> {
    let mut groups = Vec::<Vec<Vec<u8>>>::new();
    let mut current = Vec::<Vec<u8>>::new();
    let mut current_bytes = 0_usize;
    for item in items {
        validate_single_item_bytes(item.len())?;
        let next_bytes =
            current_bytes
                .checked_add(item.len())
                .ok_or(IdentityError::ArithmeticOverflow {
                    resource: "provider export chunk item bytes",
                })?;
        if !current.is_empty()
            && (current.len() == MAX_PROVIDER_EXPORT_CHUNK_ITEMS
                || next_bytes > MAX_PROVIDER_EXPORT_CHUNK_PAYLOAD_BYTES.saturating_sub(1024))
        {
            groups.push(std::mem::take(&mut current));
            current_bytes = 0;
        }
        current_bytes =
            current_bytes
                .checked_add(item.len())
                .ok_or(IdentityError::ArithmeticOverflow {
                    resource: "provider export chunk item bytes",
                })?;
        current.push(item);
    }
    if !current.is_empty() {
        groups.push(current);
    }
    if groups.len() > MAX_PROVIDER_EXPORT_CHUNKS {
        return Err(IdentityError::limit(
            "provider export chunks",
            groups.len(),
            MAX_PROVIDER_EXPORT_CHUNKS,
        ));
    }
    Ok(groups)
}

fn encode_chunk_items(items: Vec<Vec<u8>>) -> Result<Vec<u8>, IdentityError> {
    let items = items
        .into_iter()
        .map(|item| BoundedBytes::new("provider export canonical item", item))
        .collect::<Result<Vec<_>, _>>()?;
    encode_wire(&ChunkItems::new("provider export chunk items", items)?)
}

fn decode_chunk_items(bytes: &[u8]) -> Result<Vec<Vec<u8>>, IdentityError> {
    Ok(decode_wire::<ChunkItems>(bytes)?
        .into_vec()
        .into_iter()
        .map(BoundedBytes::into_vec)
        .collect())
}

fn canonical_item_bytes(items: &[Vec<u8>]) -> Result<u64, IdentityError> {
    items.iter().try_fold(0_u64, |total, item| {
        total
            .checked_add(u64::try_from(item.len()).map_err(|_| {
                IdentityError::ArithmeticOverflow {
                    resource: "provider export canonical item bytes",
                }
            })?)
            .ok_or(IdentityError::ArithmeticOverflow {
                resource: "provider export canonical payload bytes",
            })
    })
}

fn decode_generation_component<T: CanonicalWire>(
    manifest: &ProviderGenerationExportManifest,
    pending: &BTreeMap<(u16, u32), ProviderGenerationExportChunk>,
    component: ProviderExportComponent,
) -> Result<Vec<T>, IdentityError> {
    let descriptor = manifest.descriptor(component)?;
    let capacity =
        usize::try_from(descriptor.item_count).map_err(|_| IdentityError::ArithmeticOverflow {
            resource: "provider generation component allocation",
        })?;
    let mut values = Vec::with_capacity(capacity);
    let mut expected_start = 0_u64;
    let mut commitments =
        Vec::with_capacity(usize::try_from(descriptor.chunk_count).map_err(|_| {
            IdentityError::ArithmeticOverflow {
                resource: "provider generation chunk commitment allocation",
            }
        })?);
    for ordinal in 0..descriptor.chunk_count {
        let chunk = pending.get(&(component.code(), ordinal)).ok_or(
            IdentityError::InvalidRelationship {
                resource: "provider generation chunk ordinal gap",
            },
        )?;
        if chunk.start_index != expected_start {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider generation chunk range gap or overlap",
            });
        }
        expected_start = chunk.end_index;
        commitments.push(chunk.commitment()?);
        values.extend(
            chunk
                .item_bytes()?
                .into_iter()
                .map(|bytes| T::from_canonical_bytes(&bytes))
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    validate_component_finish(descriptor, expected_start, component, &commitments)?;
    Ok(values)
}

fn decode_checkpoint_bundle_component(
    manifest: &ProviderGenerationExportManifest,
    pending: &BTreeMap<(u16, u32), ProviderGenerationExportChunk>,
) -> Result<Vec<crate::ProviderCheckpointBundle>, IdentityError> {
    let component = ProviderExportComponent::CheckpointBundles;
    let descriptor = manifest.descriptor(component)?;
    let mut wires = Vec::with_capacity(usize::try_from(descriptor.item_count).map_err(|_| {
        IdentityError::ArithmeticOverflow {
            resource: "provider checkpoint bundle allocation",
        }
    })?);
    let mut expected_start = 0_u64;
    let mut commitments = Vec::new();
    for ordinal in 0..descriptor.chunk_count {
        let chunk = pending.get(&(component.code(), ordinal)).ok_or(
            IdentityError::InvalidRelationship {
                resource: "provider checkpoint bundle chunk gap",
            },
        )?;
        if chunk.start_index != expected_start {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider checkpoint bundle chunk range gap or overlap",
            });
        }
        expected_start = chunk.end_index;
        commitments.push(chunk.commitment()?);
        wires.extend(
            chunk
                .item_bytes()?
                .into_iter()
                .map(|bytes| decode_checkpoint_bundle_item(&bytes))
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    validate_component_finish(descriptor, expected_start, component, &commitments)?;
    super::decode_provider_checkpoint_bundle_wires(&wires)
}

fn validate_component_finish(
    descriptor: &ProviderExportComponentDescriptor,
    expected_end: u64,
    component: ProviderExportComponent,
    commitments: &[Digest],
) -> Result<(), IdentityError> {
    if expected_end != descriptor.item_count
        || ordered_chunk_list_commitment(
            GENERATION_CHUNK_LIST_DOMAIN,
            component.code(),
            commitments,
        )? != descriptor.chunk_list_commitment
    {
        return Err(IdentityError::InvalidProof);
    }
    Ok(())
}

fn component_item_limit(component: ProviderExportComponent) -> usize {
    match component {
        ProviderExportComponent::Entries
        | ProviderExportComponent::LeafHashes
        | ProviderExportComponent::Receipts
        | ProviderExportComponent::CheckpointBundles => MAX_MERKLE_LOG_LEAVES,
        ProviderExportComponent::CompactionManifests => MAX_PROVIDER_COMPACTION_MANIFESTS,
    }
}

fn require_version(format_version: u16) -> Result<(), IdentityError> {
    if format_version != 1 {
        return Err(IdentityError::UnsupportedVersion {
            version: format_version,
        });
    }
    Ok(())
}

fn check_chunk_size(bytes: Vec<u8>) -> Result<Vec<u8>, IdentityError> {
    if bytes.len() > MAX_PROVIDER_EXPORT_CHUNK_BYTES {
        return Err(IdentityError::limit(
            "provider interchange chunk bytes",
            bytes.len(),
            MAX_PROVIDER_EXPORT_CHUNK_BYTES,
        ));
    }
    Ok(bytes)
}

fn domain_commitment<T: Serialize>(domain: &[u8], value: &T) -> Result<Digest, IdentityError> {
    let bytes = encode_wire(value)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(&bytes);
    Ok(Digest::new(
        HashAlgorithm::Blake3_256,
        *hasher.finalize().as_bytes(),
    ))
}

fn ordered_chunk_list_commitment(
    domain: &[u8],
    component_code: u16,
    commitments: &[Digest],
) -> Result<Digest, IdentityError> {
    let chunk_count =
        u32::try_from(commitments.len()).map_err(|_| IdentityError::ArithmeticOverflow {
            resource: "provider chunk-list commitment count",
        })?;
    for commitment in commitments {
        if commitment.algorithm() != HashAlgorithm::Blake3_256 {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider chunk-list digest algorithm",
            });
        }
    }
    domain_commitment(
        domain,
        &ProviderChunkListCommitmentWire {
            format_version: 1,
            component_code,
            chunk_count,
            commitments,
        },
    )
}
