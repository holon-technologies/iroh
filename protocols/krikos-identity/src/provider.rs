//! Crash-safe provider-log state machines and bounded proof-serving contracts.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard},
};

#[cfg(test)]
use std::cell::Cell;

use serde::{Deserialize, Serialize};

use crate::{
    AccountGenesis, AccountId, AccountState, ApplyDisposition, AuthorizedEvent, CheckpointId,
    CheckpointTransitionKind, Digest, Epoch, EventId, Extensions, IdentityError, InclusionReceipt,
    ProjectionLifecycle, ProviderAuditArtifact, ProviderAuditSnapshot, ProviderCheckpointBundle,
    ProviderCheckpointLineagePage, ProviderDescriptor, ProviderHeadBody, ProviderHeadSigner,
    ProviderId, ProviderKeyVersion, ProviderLogAdmission, ProviderLogEntryBody, ProviderLogId,
    ProviderLogSubject, ProviderPolicy, PublishedCheckpoint, Sequence, SignedCheckpoint,
    SignedProviderHead, Timestamp, VerifiedCheckpoint, build_checkpoint_body,
    build_provider_checkpoint_bundle_from_genesis, build_provider_checkpoint_bundle_from_prior,
    limits::{MAX_HISTORY_PAGE_EVENTS, MAX_MERKLE_LOG_LEAVES, MAX_PROVIDER_ACCOUNT_RESPONSE_BYTES},
    merkle::{AppendOnlyMerkleLog, MerkleConsistencyProof},
    schema::BoundedVec,
};

const MAX_PROVIDER_COMPACTION_MANIFESTS: usize = 256;

#[cfg(test)]
thread_local! {
    static PROVIDER_GENERATION_VALIDATION_COUNT: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
fn reset_provider_generation_validation_count() {
    PROVIDER_GENERATION_VALIDATION_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
fn provider_generation_validation_count() -> usize {
    PROVIDER_GENERATION_VALIDATION_COUNT.with(Cell::get)
}

fn record_provider_generation_validation() {
    #[cfg(test)]
    PROVIDER_GENERATION_VALIDATION_COUNT.with(|count| count.set(count.get().saturating_add(1)));
}

struct ProviderCommitmentFlavor {
    hasher: blake3::Hasher,
}

impl ProviderCommitmentFlavor {
    fn new(domain: &[u8]) -> Self {
        assert!(
            domain.is_ascii(),
            "provider commitment domain must contain only ASCII bytes"
        );
        assert!(
            domain.ends_with(b"/v1"),
            "provider commitment domain must name its v1 schema"
        );
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        hasher.update(&[0]);
        Self { hasher }
    }
}

impl postcard::ser_flavors::Flavor for ProviderCommitmentFlavor {
    type Output = blake3::Hash;

    fn try_push(&mut self, data: u8) -> postcard::Result<()> {
        self.hasher.update(&[data]);
        Ok(())
    }

    fn try_extend(&mut self, data: &[u8]) -> postcard::Result<()> {
        self.hasher.update(data);
        Ok(())
    }

    fn finalize(self) -> postcard::Result<Self::Output> {
        Ok(self.hasher.finalize())
    }
}

pub(crate) fn provider_commitment<T: Serialize + ?Sized>(
    domain: &[u8],
    value: &T,
) -> Result<Digest, IdentityError> {
    let hash = postcard::serialize_with_flavor::<T, ProviderCommitmentFlavor, blake3::Hash>(
        value,
        ProviderCommitmentFlavor::new(domain),
    )
    .map_err(|_| IdentityError::InvalidEncoding)?;
    Ok(Digest::new(
        crate::HashAlgorithm::Blake3_256,
        *hash.as_bytes(),
    ))
}

#[cfg(feature = "provider-store")]
mod redb;

mod anchor;
mod compaction;
pub(crate) mod interchange;

pub use anchor::{
    OpaqueProviderAnchorCommitment, ProviderAnchor, ProviderAnchorEvidence, ProviderAnchorStatus,
};
pub use compaction::{
    ProviderCompactionAuthorization, ProviderCompactionManifest, ProviderRetainedRange,
    ProviderRetentionClass, ProviderRetentionInventory, ProviderRetentionItem,
    derive_provider_retention_inventory, verify_provider_compaction,
};
pub use interchange::{
    MAX_PROVIDER_EXPORT_CHUNK_BYTES, MAX_PROVIDER_EXPORT_CHUNK_ITEMS,
    MAX_PROVIDER_EXPORT_ITEM_BYTES, MAX_PROVIDER_PORTABLE_AUDIT_BYTES,
    MAX_PROVIDER_PORTABLE_GENERATION_BYTES, ProviderAuditExportAssembler, ProviderAuditExportChunk,
    ProviderAuditExportManifest, ProviderExportComponent, ProviderExportComponentDescriptor,
    ProviderGenerationExportAssembler, ProviderGenerationExportChunk,
    ProviderGenerationExportManifest, ProviderRecoveryExportManifest,
};

#[cfg(feature = "provider-store")]
pub use redb::RedbProviderStore;

/// Bounded request metadata evaluated by provider availability controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderAdmissionRequest {
    encoded_bytes: usize,
}

impl ProviderAdmissionRequest {
    /// Describe a caller-computed append size, rechecked against the actual admission on use.
    pub fn new(encoded_bytes: usize) -> Result<Self, IdentityError> {
        if encoded_bytes == 0 || encoded_bytes > MAX_PROVIDER_ACCOUNT_RESPONSE_BYTES {
            return Err(IdentityError::limit(
                "provider append request bytes",
                encoded_bytes,
                MAX_PROVIDER_ACCOUNT_RESPONSE_BYTES,
            ));
        }
        Ok(Self { encoded_bytes })
    }

    /// Compute the checked encoded size of the exact opaque admission payload.
    pub fn for_admission(admission: &ProviderLogAdmission) -> Result<Self, IdentityError> {
        Self::new(encoded_admission_bytes(admission)?)
    }

    /// Canonical byte size charged to the provider's bounded admission policy.
    pub const fn encoded_bytes(self) -> usize {
        self.encoded_bytes
    }

    fn validate_for(self, admission: &ProviderLogAdmission) -> Result<(), IdentityError> {
        let required = encoded_admission_bytes(admission)?;
        if self.encoded_bytes < required {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider append request byte undercharge",
            });
        }
        Ok(())
    }
}

/// Provider-local availability control, which can deny but never grant protocol authority.
pub trait ProviderAdmissionControl {
    /// Apply bounded abuse and capacity controls to an already verified protocol admission.
    fn check(
        &self,
        admission: ProviderLogAdmission,
        request: ProviderAdmissionRequest,
    ) -> Result<(), IdentityError>;
}

/// One-shot capability to append an already verified provider-log admission.
#[derive(Debug, PartialEq, Eq)]
pub struct ProviderAppendPermit {
    admission: ProviderLogAdmission,
    request: ProviderAdmissionRequest,
}

/// Apply availability controls without allowing them to manufacture provider-log authority.
pub fn authorize_provider_append<C: ProviderAdmissionControl + ?Sized>(
    admission: ProviderLogAdmission,
    request: ProviderAdmissionRequest,
    control: &C,
) -> Result<ProviderAppendPermit, IdentityError> {
    request.validate_for(&admission)?;
    control.check(admission.clone(), request)?;
    Ok(ProviderAppendPermit { admission, request })
}

/// Immutable state summary for one explicit provider log and signing-key generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderGenerationSnapshot {
    provider: ProviderDescriptor,
    log_id: ProviderLogId,
    key_version: ProviderKeyVersion,
    tree_size: u64,
    tree_root: Digest,
    latest_head: Option<SignedProviderHead>,
}

/// Exact address of one independently persisted provider-log generation.
///
/// No component is inferred: key rotation creates a new provider ID and every log rollover uses a
/// new log ID, while signing-key version remains explicit inside that exact pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderGenerationRoute {
    provider_id: ProviderId,
    log_id: ProviderLogId,
    key_version: ProviderKeyVersion,
}

impl ProviderGenerationRoute {
    /// Bind an authenticated provider descriptor to one explicit log/key generation.
    pub fn new(
        provider: &ProviderDescriptor,
        log_id: ProviderLogId,
        key_version: ProviderKeyVersion,
    ) -> Result<Self, IdentityError> {
        Ok(Self {
            provider_id: provider.id()?,
            log_id,
            key_version,
        })
    }

    /// Exact provider identity component.
    pub const fn provider_id(self) -> ProviderId {
        self.provider_id
    }

    /// Exact provider log-generation component.
    pub const fn log_id(self) -> ProviderLogId {
        self.log_id
    }

    /// Exact provider signing-key generation component.
    pub const fn key_version(self) -> ProviderKeyVersion {
        self.key_version
    }
}

/// Store capability required by the exact multi-generation registry.
pub trait AddressedProviderGeneration {
    /// Return this store's immutable generation address.
    fn generation_route(&self) -> Result<ProviderGenerationRoute, IdentityError>;
}

/// Exact-address registry for independently active, sealed, or archived generations.
///
/// The registry intentionally exposes no implicit current/latest winner. Callers must supply the
/// complete route, and account-policy routing additionally rejects provider IDs not named by that
/// exact policy revision.
#[derive(Debug, Clone)]
pub struct ProviderGenerationRegistry<S> {
    generations: BTreeMap<ProviderGenerationRoute, S>,
}

impl<S> Default for ProviderGenerationRegistry<S> {
    fn default() -> Self {
        Self {
            generations: BTreeMap::new(),
        }
    }
}

impl<S: AddressedProviderGeneration> ProviderGenerationRegistry<S> {
    /// Create an empty exact-address registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert one store under its authenticated immutable address.
    pub fn insert(&mut self, store: S) -> Result<ProviderGenerationRoute, IdentityError> {
        let route = store.generation_route()?;
        if self.generations.contains_key(&route) {
            return Err(IdentityError::DuplicateElement {
                resource: "provider generation route",
            });
        }
        self.generations.insert(route, store);
        Ok(route)
    }

    /// Resolve only an exact provider/log/key address.
    pub fn get(&self, route: ProviderGenerationRoute) -> Option<&S> {
        self.generations.get(&route)
    }

    /// Require one exact route, rejecting any missing or cross-generation address.
    pub fn require(&self, route: ProviderGenerationRoute) -> Result<&S, IdentityError> {
        self.get(route).ok_or(IdentityError::InvalidRelationship {
            resource: "provider generation route",
        })
    }

    /// Resolve an exact route only when its provider ID is named by the account policy.
    pub fn for_policy(
        &self,
        policy: &ProviderPolicy,
        route: ProviderGenerationRoute,
    ) -> Result<&S, IdentityError> {
        let configured = policy
            .providers()
            .ok_or(IdentityError::InvalidRelationship {
                resource: "provider generation account policy",
            })?;
        if !configured
            .iter()
            .any(|provider| provider.id().is_ok_and(|id| id == route.provider_id))
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider generation account policy",
            });
        }
        self.require(route)
    }

    /// Number of independently addressed generations.
    pub fn len(&self) -> usize {
        self.generations.len()
    }

    /// Whether no generation has been registered.
    pub fn is_empty(&self) -> bool {
        self.generations.is_empty()
    }
}

impl ProviderGenerationSnapshot {
    /// Provider descriptor authenticating the generation.
    pub const fn provider(&self) -> &ProviderDescriptor {
        &self.provider
    }

    /// Explicit provider-log generation identifier.
    pub const fn log_id(&self) -> ProviderLogId {
        self.log_id
    }

    /// Explicit provider signing-key generation.
    pub const fn key_version(&self) -> ProviderKeyVersion {
        self.key_version
    }

    /// Number of committed leaves.
    pub const fn tree_size(&self) -> u64 {
        self.tree_size
    }

    /// Merkle root for exactly [`Self::tree_size`].
    pub const fn tree_root(&self) -> Digest {
        self.tree_root
    }

    /// Latest authenticated head issued for this generation.
    pub const fn latest_head(&self) -> Option<&SignedProviderHead> {
        self.latest_head.as_ref()
    }
}

/// One provider-wide append index and canonical entry returned by durable history queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderAccountHistoryRecord {
    leaf_index: u64,
    entry: ProviderLogEntryBody,
}

impl ProviderAccountHistoryRecord {
    /// Provider-wide zero-based append index.
    pub const fn leaf_index(&self) -> u64 {
        self.leaf_index
    }

    /// Canonical entry committed at this index.
    pub const fn entry(&self) -> &ProviderLogEntryBody {
        &self.entry
    }
}

/// Bounded account-filtered page retaining a provider-wide continuation cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAccountHistoryPage {
    records: Vec<ProviderAccountHistoryRecord>,
    next_cursor: Option<u64>,
}

impl ProviderAccountHistoryPage {
    /// Matching entries in provider-wide append order.
    pub fn records(&self) -> &[ProviderAccountHistoryRecord] {
        &self.records
    }

    /// Exclusive provider-wide cursor for the next request, if more data remains.
    pub const fn next_cursor(&self) -> Option<u64> {
        self.next_cursor
    }
}

/// Raw retained checkpoint proof held by a locally sealed generation.
///
/// Older continuation state may have moved exclusively to the verified recovery archive, so this
/// type deliberately does not expose [`ProviderCheckpointBundle::provider_log_admission`]. A
/// caller must verify the proof from a trusted account state or retrieve the complete archive
/// before treating its checkpoint authorization as authoritative.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRetainedCheckpointEvidence {
    material: RetainedCheckpointMaterial,
    receipt: InclusionReceipt,
}

impl ProviderRetainedCheckpointEvidence {
    /// Genesis anchor when this retained link remains independently replayable.
    pub fn genesis(&self) -> Option<&AccountGenesis> {
        self.material.genesis.as_ref()
    }

    /// Prior checkpoint required to verify a compacted continuation link.
    pub const fn prior_checkpoint_id(&self) -> Option<CheckpointId> {
        self.material.prior_checkpoint_id
    }

    /// Exact bounded advancing event chain retained for this link.
    pub fn events(&self) -> &[AuthorizedEvent] {
        &self.material.events
    }

    /// Structurally validated signed checkpoint whose authority still requires replay.
    pub const fn checkpoint(&self) -> &SignedCheckpoint {
        &self.material.checkpoint
    }

    /// Destructive transition evidence, when carried by the signed checkpoint.
    pub const fn transition_event(&self) -> Option<&AuthorizedEvent> {
        self.material.transition_event.as_ref()
    }

    /// Provider-authenticated inclusion of this checkpoint ID at its original leaf index.
    pub const fn receipt(&self) -> &InclusionReceipt {
        &self.receipt
    }
}

/// Complete bounded export of one provider-log generation for verified mirroring and recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderGenerationExport {
    provider: ProviderDescriptor,
    log_id: ProviderLogId,
    key_version: ProviderKeyVersion,
    entries: Vec<ProviderLogEntryBody>,
    leaf_hashes: Vec<Digest>,
    latest_head: Option<SignedProviderHead>,
    receipts: Vec<InclusionReceipt>,
    checkpoint_bundles: Vec<ProviderCheckpointBundle>,
    compaction_manifests: Vec<ProviderCompactionManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProviderCheckpointBundleWire {
    genesis: Option<AccountGenesis>,
    prior_checkpoint_id: Option<CheckpointId>,
    events: BoundedVec<AuthorizedEvent, MAX_HISTORY_PAGE_EVENTS>,
    checkpoint: SignedCheckpoint,
    transition_event: Option<AuthorizedEvent>,
}

impl ProviderGenerationExport {
    /// Provider descriptor authenticating this exported generation.
    pub const fn provider(&self) -> &ProviderDescriptor {
        &self.provider
    }

    /// Explicit log generation carried by the export.
    pub const fn log_id(&self) -> ProviderLogId {
        self.log_id
    }

    /// Explicit signing-key generation carried by the export.
    pub const fn key_version(&self) -> ProviderKeyVersion {
        self.key_version
    }

    /// Canonical provider entries in append order.
    pub fn entries(&self) -> &[ProviderLogEntryBody] {
        &self.entries
    }

    /// Domain-separated leaf hashes in append order.
    pub fn leaf_hashes(&self) -> &[Digest] {
        &self.leaf_hashes
    }

    /// Latest authenticated head included in the export.
    pub const fn latest_head(&self) -> Option<&SignedProviderHead> {
        self.latest_head.as_ref()
    }

    /// Latest durable inclusion receipt retained for each committed leaf.
    pub fn receipts(&self) -> &[InclusionReceipt] {
        &self.receipts
    }

    /// Complete provider-served checkpoint authorization and lineage material in append order.
    pub fn checkpoint_bundles(&self) -> &[ProviderCheckpointBundle] {
        &self.checkpoint_bundles
    }

    /// Verified compaction manifests durably recorded for this exact generation state.
    pub fn compaction_manifests(&self) -> &[ProviderCompactionManifest] {
        &self.compaction_manifests
    }
}

impl ProviderCheckpointBundleWire {
    fn from_bundle(bundle: &ProviderCheckpointBundle) -> Result<Self, IdentityError> {
        Ok(Self {
            genesis: bundle.genesis().cloned(),
            prior_checkpoint_id: bundle.prior_checkpoint_id(),
            events: BoundedVec::new(
                "provider generation checkpoint lineage events",
                bundle.events().to_vec(),
            )?,
            checkpoint: bundle.verified_checkpoint().checkpoint().clone(),
            transition_event: bundle.verified_checkpoint().transition_event().cloned(),
        })
    }

    fn validate_interchange_shape(&self) -> Result<(), IdentityError> {
        match (&self.genesis, self.prior_checkpoint_id) {
            (Some(genesis), None) => build_provider_checkpoint_bundle_from_genesis(
                genesis,
                self.events.as_slice(),
                &self.checkpoint,
                self.transition_event.as_ref(),
            )
            .map(|_| ()),
            (None, Some(_)) => {
                let account_id = self.checkpoint.body().account_id();
                if self
                    .events
                    .as_slice()
                    .iter()
                    .any(|event| event.body().account_id() != account_id)
                    || self
                        .transition_event
                        .as_ref()
                        .is_some_and(|event| event.body().account_id() != account_id)
                {
                    return Err(IdentityError::InvalidRelationship {
                        resource: "provider generation checkpoint continuation account",
                    });
                }
                Ok(())
            }
            (Some(_), Some(_)) | (None, None) => Err(IdentityError::InvalidRelationship {
                resource: "provider generation checkpoint lineage",
            }),
        }
    }
}

fn decode_provider_checkpoint_bundle_wires(
    wires: &[ProviderCheckpointBundleWire],
) -> Result<Vec<ProviderCheckpointBundle>, IdentityError> {
    let mut lineage = BTreeMap::<CheckpointId, (VerifiedCheckpoint, AccountState)>::new();
    let mut bundles = Vec::with_capacity(wires.len());
    for wire in wires {
        wire.validate_interchange_shape()?;
        let (bundle, base_state) = match (&wire.genesis, wire.prior_checkpoint_id) {
            (Some(genesis), None) => (
                build_provider_checkpoint_bundle_from_genesis(
                    genesis,
                    wire.events.as_slice(),
                    &wire.checkpoint,
                    wire.transition_event.as_ref(),
                )?,
                AccountState::from_genesis(genesis)?,
            ),
            (None, Some(prior_checkpoint_id)) => {
                let (prior, prior_state) = lineage
                    .get(&prior_checkpoint_id)
                    .filter(|(prior, _)| {
                        prior.checkpoint().body().account_id()
                            == wire.checkpoint.body().account_id()
                    })
                    .ok_or(IdentityError::InvalidRelationship {
                        resource: "provider generation checkpoint prior lineage",
                    })?;
                (
                    build_provider_checkpoint_bundle_from_prior(
                        prior_state,
                        prior,
                        wire.events.as_slice(),
                        &wire.checkpoint,
                        wire.transition_event.as_ref(),
                    )?,
                    prior_state.clone(),
                )
            }
            (Some(_), Some(_)) | (None, None) => {
                return Err(IdentityError::InvalidRelationship {
                    resource: "provider generation checkpoint lineage",
                });
            }
        };
        let (projected, _) = project_bundle_state(base_state, &bundle)?;
        let verified = bundle.verified_checkpoint().clone();
        if lineage
            .insert(verified.checkpoint_id(), (verified, projected))
            .is_some()
        {
            return Err(IdentityError::DuplicateElement {
                resource: "provider generation checkpoint lineage",
            });
        }
        bundles.push(bundle);
    }
    Ok(bundles)
}

/// Validated full recovery archive binding one exact generation to its complete audit journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRecoveryExport {
    generation: ProviderGenerationExport,
    audit: ProviderAuditSnapshot,
    artifacts: Vec<ProviderAuditArtifact>,
    generation_commitment: Digest,
    audit_commitment: Digest,
    artifact_commitment: Digest,
    recovery_commitment: Digest,
}

impl ProviderRecoveryExport {
    /// Validate and bind a complete generation to the audit snapshot for the exact same head.
    pub fn new(
        generation: ProviderGenerationExport,
        audit: ProviderAuditSnapshot,
    ) -> Result<Self, IdentityError> {
        Self::build_validated(generation, audit).map(|(recovery, _)| recovery)
    }

    fn build_validated(
        generation: ProviderGenerationExport,
        audit: ProviderAuditSnapshot,
    ) -> Result<(Self, ProviderGenerationSnapshot), IdentityError> {
        let restored = MemoryProviderStore::restore_generation(generation.clone())?;
        let (_, snapshot) = restored.export_and_snapshot_from_validated_state()?;
        audit.validate()?;
        if audit.provider() != generation.provider()
            || audit.log_id() != generation.log_id()
            || audit.latest_head() != snapshot.latest_head()
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider recovery generation audit binding",
            });
        }
        let artifacts = audit.artifacts_validated()?;
        for artifact in &artifacts {
            artifact.verify(generation.provider(), generation.log_id())?;
        }
        let generation_commitment = compaction::provider_generation_export_commitment(&generation)?;
        let audit_commitment = audit.commitment_validated()?;
        let artifact_commitment = provider_audit_artifact_commitment(&artifacts)?;
        let recovery_commitment = provider_recovery_commitment(
            generation_commitment,
            audit_commitment,
            artifact_commitment,
        )?;
        Ok((
            Self {
                generation,
                audit,
                artifacts,
                generation_commitment,
                audit_commitment,
                artifact_commitment,
                recovery_commitment,
            },
            snapshot,
        ))
    }

    /// Complete authenticated provider generation payload.
    pub const fn generation(&self) -> &ProviderGenerationExport {
        &self.generation
    }

    /// Complete validated audit history, including accepted and rejected observations.
    pub const fn audit(&self) -> &ProviderAuditSnapshot {
        &self.audit
    }

    /// Sorted first-class rollback/equivocation artifacts derived from the audit history.
    pub fn artifacts(&self) -> &[ProviderAuditArtifact] {
        &self.artifacts
    }

    /// Exact full generation commitment.
    pub const fn generation_commitment(&self) -> Digest {
        self.generation_commitment
    }

    /// Exact full audit-journal commitment.
    pub const fn audit_commitment(&self) -> Digest {
        self.audit_commitment
    }

    /// Exact sorted non-leaf audit-artifact commitment.
    pub const fn artifact_commitment(&self) -> Digest {
        self.artifact_commitment
    }

    /// Composite recovery commitment binding generation, audit journal, and artifacts.
    pub const fn recovery_commitment(&self) -> Digest {
        self.recovery_commitment
    }

    fn validate(&self) -> Result<(), IdentityError> {
        self.validate_with_generation_snapshot().map(|_| ())
    }

    fn validate_with_generation_snapshot(
        &self,
    ) -> Result<ProviderGenerationSnapshot, IdentityError> {
        let (rebuilt, snapshot) =
            Self::build_validated(self.generation.clone(), self.audit.clone())?;
        if &rebuilt != self {
            return Err(IdentityError::InvalidProof);
        }
        Ok(snapshot)
    }
}

const PROVIDER_AUDIT_ARTIFACT_SET_COMMITMENT_DOMAIN: &[u8] =
    b"KRIKOS-ID/provider-audit-artifacts/v1";
const PROVIDER_RECOVERY_EXPORT_COMMITMENT_DOMAIN: &[u8] = b"KRIKOS-ID/provider-recovery-export/v1";
const PROVIDER_RETAINED_EVIDENCE_COMMITMENT_DOMAIN: &[u8] =
    b"KRIKOS-ID/provider-retained-evidence/v1";

#[derive(Serialize)]
struct ProviderAuditArtifactSetCommitmentWire<'a> {
    format_version: u16,
    artifact_commitments: &'a [Digest],
}

#[derive(Serialize)]
struct ProviderRecoveryExportCommitmentWire {
    format_version: u16,
    generation_commitment: Digest,
    audit_commitment: Digest,
    artifact_commitment: Digest,
}

fn provider_audit_artifact_commitment(
    artifacts: &[ProviderAuditArtifact],
) -> Result<Digest, IdentityError> {
    let artifact_commitments = artifacts
        .iter()
        .map(ProviderAuditArtifact::commitment)
        .collect::<Result<Vec<_>, _>>()?;
    provider_commitment(
        PROVIDER_AUDIT_ARTIFACT_SET_COMMITMENT_DOMAIN,
        &ProviderAuditArtifactSetCommitmentWire {
            format_version: 1,
            artifact_commitments: &artifact_commitments,
        },
    )
}

fn provider_recovery_commitment(
    generation: Digest,
    audit: Digest,
    artifacts: Digest,
) -> Result<Digest, IdentityError> {
    provider_commitment(
        PROVIDER_RECOVERY_EXPORT_COMMITMENT_DOMAIN,
        &ProviderRecoveryExportCommitmentWire {
            format_version: 1,
            generation_commitment: generation,
            audit_commitment: audit,
            artifact_commitment: artifacts,
        },
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProviderCheckpointIndex {
    pub(crate) account_id: AccountId,
    pub(crate) greatest_sequence: Sequence,
    pub(crate) greatest_epoch: Epoch,
    pub(crate) current_checkpoint_id: Option<CheckpointId>,
    pub(crate) projection_heads: Vec<EventId>,
    pub(crate) forked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderGenerationState {
    provider: ProviderDescriptor,
    log_id: ProviderLogId,
    key_version: ProviderKeyVersion,
    leaf_hashes: Vec<Digest>,
    latest_head: Option<SignedProviderHead>,
    compaction_manifests: Vec<ProviderCompactionManifest>,
    payload: ProviderGenerationPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProviderGenerationPayload {
    Active(ActiveProviderPayload),
    Sealed(Box<SealedProviderPayload>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveProviderPayload {
    entries: Vec<ProviderLogEntryBody>,
    receipts: Vec<InclusionReceipt>,
    checkpoint_bundles: Vec<ProviderCheckpointBundle>,
    checkpoint_index: Vec<ProviderCheckpointIndex>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RetainedProviderRecord {
    leaf_index: u64,
    entry: ProviderLogEntryBody,
    receipt: InclusionReceipt,
}

#[derive(Serialize)]
struct RetainedProviderRecordCommitmentWire<'a> {
    leaf_index: u64,
    entry: &'a ProviderLogEntryBody,
    receipt: &'a InclusionReceipt,
}

struct DerivedRetainedProviderMaterial {
    records: Vec<RetainedProviderRecord>,
    checkpoint_evidence: Vec<RetainedCheckpointMaterial>,
    checkpoint_index: Vec<ProviderCheckpointIndex>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RetainedCheckpointMaterial {
    pub(crate) genesis: Option<AccountGenesis>,
    pub(crate) prior_checkpoint_id: Option<CheckpointId>,
    pub(crate) events: Vec<AuthorizedEvent>,
    pub(crate) checkpoint: SignedCheckpoint,
    pub(crate) transition_event: Option<AuthorizedEvent>,
}

#[derive(Serialize)]
struct RetainedCheckpointMaterialCommitmentWire<'a> {
    genesis: Option<&'a AccountGenesis>,
    prior_checkpoint_id: Option<CheckpointId>,
    events: &'a [AuthorizedEvent],
    checkpoint: &'a SignedCheckpoint,
    transition_event: Option<&'a AuthorizedEvent>,
}

#[derive(Serialize)]
struct ProviderCheckpointIndexCommitmentWire<'a> {
    account_id: AccountId,
    greatest_sequence: Sequence,
    greatest_epoch: Epoch,
    current_checkpoint_id: Option<CheckpointId>,
    projection_heads: &'a [EventId],
    forked: bool,
}

#[derive(Serialize)]
struct RetainedProviderEvidenceCommitmentWire<'a> {
    format_version: u16,
    records: Vec<RetainedProviderRecordCommitmentWire<'a>>,
    checkpoint_evidence: Vec<RetainedCheckpointMaterialCommitmentWire<'a>>,
    checkpoint_index: Vec<ProviderCheckpointIndexCommitmentWire<'a>>,
    audit_artifact_commitment: Digest,
}

impl RetainedCheckpointMaterial {
    fn from_bundle(bundle: &ProviderCheckpointBundle) -> Self {
        let verified = bundle.verified_checkpoint();
        Self {
            genesis: bundle.genesis().cloned(),
            prior_checkpoint_id: bundle.prior_checkpoint_id(),
            events: bundle.events().to_vec(),
            checkpoint: verified.checkpoint().clone(),
            transition_event: verified.transition_event().cloned(),
        }
    }

    fn checkpoint_id(&self) -> Result<CheckpointId, IdentityError> {
        self.checkpoint.checkpoint_id()
    }

    fn validate_structure(&self) -> Result<(), IdentityError> {
        match (&self.genesis, self.prior_checkpoint_id) {
            (Some(genesis), None) => {
                build_provider_checkpoint_bundle_from_genesis(
                    genesis,
                    &self.events,
                    &self.checkpoint,
                    self.transition_event.as_ref(),
                )?;
                return Ok(());
            }
            (None, Some(_)) => {}
            (Some(_), Some(_)) | (None, None) => {
                return Err(IdentityError::InvalidRelationship {
                    resource: "retained checkpoint continuation anchor",
                });
            }
        }
        if self.events.len() > MAX_HISTORY_PAGE_EVENTS
            || self
                .events
                .iter()
                .any(|event| event.body().account_id() != self.checkpoint.body().account_id())
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "retained checkpoint continuation events",
            });
        }
        let encoded_events = crate::codec::encode_wire(&self.events)?;
        if encoded_events.len() > crate::limits::MAX_HISTORY_PAGE_BYTES {
            return Err(IdentityError::limit(
                "retained checkpoint continuation bytes",
                encoded_events.len(),
                crate::limits::MAX_HISTORY_PAGE_BYTES,
            ));
        }
        if let Some(last) = self.events.last()
            && (last.event_id()? != self.checkpoint.body().event_head()
                || last.body().sequence() != self.checkpoint.body().sequence()
                || last.body().resulting_epoch() != self.checkpoint.body().account_epoch())
        {
            return Err(IdentityError::InvalidProof);
        }
        match self.checkpoint.authorization().controller_approvals() {
            Some(approvals) => {
                if approvals.as_slice().is_empty() || self.transition_event.is_some() {
                    return Err(IdentityError::InvalidProof);
                }
            }
            None => {
                let witness = self
                    .checkpoint
                    .authorization()
                    .transition_witness()
                    .ok_or(IdentityError::InvalidProof)?;
                let event = self
                    .transition_event
                    .as_ref()
                    .ok_or(IdentityError::InvalidProof)?;
                let operation_matches = matches!(
                    (witness.transition_kind(), event.body().operation()),
                    (
                        CheckpointTransitionKind::FinalizeRecovery,
                        crate::AccountOperation::FinalizeRecovery(_)
                    ) | (
                        CheckpointTransitionKind::RetireAccount,
                        crate::AccountOperation::RetireAccount(_)
                    )
                );
                if !operation_matches
                    || witness.event_id() != event.event_id()?
                    || witness.event_authorization_id() != event.event_authorization_id()?
                    || witness.event_id() != self.checkpoint.body().event_head()
                {
                    return Err(IdentityError::InvalidProof);
                }
            }
        }
        self.checkpoint_id()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SealedProviderPayload {
    retained_records: Vec<RetainedProviderRecord>,
    checkpoint_bundles: Vec<ProviderCheckpointBundle>,
    retained_checkpoint_evidence: Vec<RetainedCheckpointMaterial>,
    checkpoint_index: Vec<ProviderCheckpointIndex>,
    manifest: Option<ProviderCompactionManifest>,
    inventory: Option<ProviderRetentionInventory>,
    audit_snapshot: Option<ProviderAuditSnapshot>,
    audit_artifacts: Vec<ProviderAuditArtifact>,
    archive_complete: bool,
}

impl ProviderGenerationState {
    fn active(&self) -> Result<&ActiveProviderPayload, IdentityError> {
        match &self.payload {
            ProviderGenerationPayload::Active(payload) => Ok(payload),
            ProviderGenerationPayload::Sealed(_) => Err(IdentityError::ProviderArchiveRequired),
        }
    }

    fn active_mut(&mut self) -> Result<&mut ActiveProviderPayload, IdentityError> {
        match &mut self.payload {
            ProviderGenerationPayload::Active(payload) => Ok(payload),
            ProviderGenerationPayload::Sealed(_) => Err(IdentityError::ProviderArchiveRequired),
        }
    }

    fn tree(&self) -> Result<AppendOnlyMerkleLog, IdentityError> {
        AppendOnlyMerkleLog::from_leaf_hashes(self.leaf_hashes.clone())
    }

    fn snapshot(&self) -> Result<ProviderGenerationSnapshot, IdentityError> {
        let tree = self.tree()?;
        Ok(ProviderGenerationSnapshot {
            provider: self.provider.clone(),
            log_id: self.log_id,
            key_version: self.key_version,
            tree_size: tree.tree_size()?,
            tree_root: tree.root()?,
            latest_head: self.latest_head.clone(),
        })
    }

    fn export(&self) -> Result<ProviderGenerationExport, IdentityError> {
        let (entries, receipts, checkpoint_bundles) = match &self.payload {
            ProviderGenerationPayload::Active(payload) => (
                payload.entries.clone(),
                payload.receipts.clone(),
                payload.checkpoint_bundles.clone(),
            ),
            ProviderGenerationPayload::Sealed(payload) if payload.archive_complete => (
                payload
                    .retained_records
                    .iter()
                    .map(|record| record.entry.clone())
                    .collect(),
                payload
                    .retained_records
                    .iter()
                    .map(|record| record.receipt.clone())
                    .collect(),
                payload.checkpoint_bundles.clone(),
            ),
            ProviderGenerationPayload::Sealed(_) => {
                return Err(IdentityError::ProviderArchiveRequired);
            }
        };
        Ok(ProviderGenerationExport {
            provider: self.provider.clone(),
            log_id: self.log_id,
            key_version: self.key_version,
            entries,
            leaf_hashes: self.leaf_hashes.clone(),
            latest_head: self.latest_head.clone(),
            receipts,
            checkpoint_bundles,
            compaction_manifests: self.compaction_manifests.clone(),
        })
    }

    fn validate(&self) -> Result<(), IdentityError> {
        self.validate_inner(true)
    }

    fn validate_cached(&self) -> Result<(), IdentityError> {
        self.validate_inner(false)
    }

    fn validate_inner(&self, validate_portable_bytes: bool) -> Result<(), IdentityError> {
        record_provider_generation_validation();
        if self.key_version != ProviderKeyVersion::GENESIS
            || self.leaf_hashes.len() > MAX_MERKLE_LOG_LEAVES
            || self.compaction_manifests.len() > MAX_PROVIDER_COMPACTION_MANIFESTS
        {
            return Err(IdentityError::StorageCorruption);
        }
        let provider_id = self.provider.id()?;
        match &self.payload {
            ProviderGenerationPayload::Active(payload) => {
                if payload.entries.len() != self.leaf_hashes.len()
                    || payload.entries.len() != payload.receipts.len()
                {
                    return Err(IdentityError::StorageCorruption);
                }
                let rebuilt_checkpoint_index =
                    rebuild_checkpoint_index(&payload.entries, &payload.checkpoint_bundles)?;
                if payload.checkpoint_index != rebuilt_checkpoint_index {
                    return Err(IdentityError::StorageCorruption);
                }
                for (index, receipt) in payload.receipts.iter().enumerate() {
                    let leaf_index =
                        u64::try_from(index).map_err(|_| IdentityError::ArithmeticOverflow {
                            resource: "provider receipt validation index",
                        })?;
                    validate_retained_record(
                        &self.provider,
                        self.log_id,
                        &self.leaf_hashes,
                        &RetainedProviderRecord {
                            leaf_index,
                            entry: payload.entries[index].clone(),
                            receipt: receipt.clone(),
                        },
                    )?;
                }
            }
            ProviderGenerationPayload::Sealed(sealed) => {
                for artifact in &sealed.audit_artifacts {
                    artifact
                        .verify(&self.provider, self.log_id)
                        .map_err(|_| IdentityError::StorageCorruption)?;
                }
                let mut previous_index = None;
                for record in &sealed.retained_records {
                    if previous_index.is_some_and(|previous| previous >= record.leaf_index) {
                        return Err(IdentityError::StorageCorruption);
                    }
                    previous_index = Some(record.leaf_index);
                    validate_retained_record(
                        &self.provider,
                        self.log_id,
                        &self.leaf_hashes,
                        record,
                    )?;
                    if let ProviderLogSubject::Checkpoint(checkpoint_id) = record.entry.subject() {
                        let matches = if sealed.archive_complete {
                            sealed
                                .checkpoint_bundles
                                .iter()
                                .filter(|bundle| {
                                    let checkpoint = bundle.verified_checkpoint();
                                    checkpoint.checkpoint().body().account_id()
                                        == record.entry.account_id()
                                        && checkpoint.checkpoint_id() == checkpoint_id
                                })
                                .count()
                        } else {
                            sealed
                                .retained_checkpoint_evidence
                                .iter()
                                .filter(|evidence| {
                                    evidence.checkpoint.body().account_id()
                                        == record.entry.account_id()
                                        && evidence.checkpoint_id() == Ok(checkpoint_id)
                                })
                                .count()
                        };
                        if matches != 1 {
                            return Err(IdentityError::StorageCorruption);
                        }
                    }
                }
                let retained_checkpoint_count = sealed
                    .retained_records
                    .iter()
                    .filter(|record| {
                        matches!(record.entry.subject(), ProviderLogSubject::Checkpoint(_))
                    })
                    .count();
                let stored_checkpoint_count = if sealed.archive_complete {
                    sealed.checkpoint_bundles.len()
                } else {
                    sealed.retained_checkpoint_evidence.len()
                };
                if retained_checkpoint_count != stored_checkpoint_count {
                    return Err(IdentityError::StorageCorruption);
                }
                let mut previous_account = None;
                for index in &sealed.checkpoint_index {
                    if previous_account.is_some_and(|account| account >= index.account_id)
                        || !sealed
                            .retained_records
                            .iter()
                            .any(|record| record.entry.account_id() == index.account_id)
                        || (!index.forked
                            && !sealed.retained_records.iter().any(|record| {
                                record.entry.account_id() == index.account_id
                                    && index.current_checkpoint_id.is_some_and(|checkpoint_id| {
                                        record.entry.subject()
                                            == ProviderLogSubject::Checkpoint(checkpoint_id)
                                    })
                            }))
                    {
                        return Err(IdentityError::StorageCorruption);
                    }
                    previous_account = Some(index.account_id);
                }
                let expected_indices = if sealed.archive_complete {
                    (0..self.leaf_hashes.len())
                        .map(|index| {
                            u64::try_from(index).map_err(|_| IdentityError::ArithmeticOverflow {
                                resource: "provider sealed archive index",
                            })
                        })
                        .collect::<Result<Vec<_>, IdentityError>>()?
                } else {
                    sealed
                        .manifest
                        .as_ref()
                        .ok_or(IdentityError::StorageCorruption)?
                        .retained_leaf_indices()?
                };
                if sealed
                    .retained_records
                    .iter()
                    .map(|record| record.leaf_index)
                    .ne(expected_indices)
                {
                    return Err(IdentityError::StorageCorruption);
                }
                if sealed.archive_complete {
                    if sealed.manifest.is_some()
                        || sealed.inventory.is_some()
                        || !sealed.retained_checkpoint_evidence.is_empty()
                    {
                        return Err(IdentityError::StorageCorruption);
                    }
                    let audit = sealed
                        .audit_snapshot
                        .as_ref()
                        .ok_or(IdentityError::StorageCorruption)?;
                    audit
                        .validate()
                        .map_err(|_| IdentityError::StorageCorruption)?;
                    if audit.provider() != &self.provider
                        || audit.log_id() != self.log_id
                        || audit.latest_head() != self.latest_head.as_ref()
                        || audit
                            .artifacts_validated()
                            .map_err(|_| IdentityError::StorageCorruption)?
                            != sealed.audit_artifacts
                    {
                        return Err(IdentityError::StorageCorruption);
                    }
                    let entries = sealed
                        .retained_records
                        .iter()
                        .map(|record| record.entry.clone())
                        .collect::<Vec<_>>();
                    let rebuilt = rebuild_checkpoint_index(&entries, &sealed.checkpoint_bundles)?;
                    if rebuilt != sealed.checkpoint_index {
                        return Err(IdentityError::StorageCorruption);
                    }
                } else {
                    if !sealed.checkpoint_bundles.is_empty() || sealed.audit_snapshot.is_some() {
                        return Err(IdentityError::StorageCorruption);
                    }
                    for evidence in &sealed.retained_checkpoint_evidence {
                        evidence
                            .validate_structure()
                            .map_err(|_| IdentityError::StorageCorruption)?;
                    }
                    let manifest = sealed
                        .manifest
                        .as_ref()
                        .ok_or(IdentityError::StorageCorruption)?;
                    let inventory = sealed
                        .inventory
                        .as_ref()
                        .ok_or(IdentityError::StorageCorruption)?;
                    if !self.compaction_manifests.contains(manifest)
                        || inventory.audit_artifacts() != sealed.audit_artifacts
                    {
                        return Err(IdentityError::StorageCorruption);
                    }
                    let retained_commitment = retained_provider_payload_commitment(
                        &sealed.retained_records,
                        &sealed.retained_checkpoint_evidence,
                        &sealed.checkpoint_index,
                        &sealed.audit_artifacts,
                    )?;
                    manifest.validate_sealed_evidence(inventory, retained_commitment)?;
                }
            }
        }
        for (index, stored_hash) in self.leaf_hashes.iter().enumerate() {
            if let ProviderGenerationPayload::Active(payload) = &self.payload
                && payload.entries[index].merkle_leaf_hash()? != *stored_hash
            {
                return Err(IdentityError::StorageCorruption);
            }
        }
        let tree = self.tree()?;
        for manifest in &self.compaction_manifests {
            manifest.validate_generation(
                provider_id,
                self.log_id,
                self.key_version,
                &self.leaf_hashes,
            )?;
        }
        if validate_portable_bytes
            && (matches!(&self.payload, ProviderGenerationPayload::Active(_))
                || matches!(
                    &self.payload,
                    ProviderGenerationPayload::Sealed(sealed) if sealed.archive_complete
                ))
        {
            interchange::validate_generation_interchange_bounds(&self.export()?)?;
        }
        match (&self.latest_head, self.leaf_hashes.is_empty()) {
            (None, true) => Ok(()),
            (None, false) | (Some(_), true) => Err(IdentityError::StorageCorruption),
            (Some(head), false) => {
                head.verify(&self.provider)
                    .map_err(|_| IdentityError::StorageCorruption)?;
                if head.body().log_id() != self.log_id
                    || head.body().key_version() != self.key_version
                    || head.body().tree_size() != tree.tree_size()?
                    || head.body().tree_root() != tree.root()?
                {
                    return Err(IdentityError::StorageCorruption);
                }
                Ok(())
            }
        }
    }
}

fn validate_retained_record(
    provider: &ProviderDescriptor,
    log_id: ProviderLogId,
    leaf_hashes: &[Digest],
    record: &RetainedProviderRecord,
) -> Result<(), IdentityError> {
    let index = usize::try_from(record.leaf_index).map_err(|_| IdentityError::StorageCorruption)?;
    let stored_hash = leaf_hashes
        .get(index)
        .copied()
        .ok_or(IdentityError::StorageCorruption)?;
    if record.entry.provider_id() != provider.id()?
        || record.entry.log_id() != log_id
        || record.entry.merkle_leaf_hash()? != stored_hash
        || record.receipt.leaf_index() != record.leaf_index
        || record.receipt.entry() != &record.entry
    {
        return Err(IdentityError::StorageCorruption);
    }
    record
        .receipt
        .verify(provider)
        .map_err(|_| IdentityError::StorageCorruption)
}

fn derive_retained_provider_material(
    generation: &ProviderGenerationExport,
    inventory: &ProviderRetentionInventory,
) -> Result<DerivedRetainedProviderMaterial, IdentityError> {
    if inventory.tree_size()
        != u64::try_from(generation.entries.len()).map_err(|_| {
            IdentityError::ArithmeticOverflow {
                resource: "provider retained generation tree size",
            }
        })?
    {
        return Err(IdentityError::InvalidRelationship {
            resource: "provider retained inventory generation",
        });
    }
    let mut indices = inventory
        .items()
        .iter()
        .map(|item| item.leaf_index())
        .collect::<Vec<_>>();
    indices.sort_unstable();
    indices.dedup();
    let mut retained_records = Vec::with_capacity(indices.len());
    let mut retained_checkpoint_evidence = Vec::new();
    let mut retained_accounts = std::collections::BTreeSet::new();
    for leaf_index in indices {
        let index = usize::try_from(leaf_index).map_err(|_| IdentityError::StorageCorruption)?;
        let entry = generation
            .entries
            .get(index)
            .cloned()
            .ok_or(IdentityError::StorageCorruption)?;
        let receipt = generation
            .receipts
            .get(index)
            .cloned()
            .ok_or(IdentityError::StorageCorruption)?;
        if let ProviderLogSubject::Checkpoint(checkpoint_id) = entry.subject() {
            let bundle = generation
                .checkpoint_bundles
                .iter()
                .find(|bundle| {
                    let checkpoint = bundle.verified_checkpoint();
                    checkpoint.checkpoint().body().account_id() == entry.account_id()
                        && checkpoint.checkpoint_id() == checkpoint_id
                })
                .cloned()
                .ok_or(IdentityError::StorageCorruption)?;
            retained_checkpoint_evidence.push(RetainedCheckpointMaterial::from_bundle(&bundle));
            retained_accounts.insert(entry.account_id());
        }
        retained_records.push(RetainedProviderRecord {
            leaf_index,
            entry,
            receipt,
        });
    }
    let checkpoint_index =
        rebuild_checkpoint_index(&generation.entries, &generation.checkpoint_bundles)?
            .into_iter()
            .filter(|index| retained_accounts.contains(&index.account_id))
            .collect::<Vec<_>>();
    Ok(DerivedRetainedProviderMaterial {
        records: retained_records,
        checkpoint_evidence: retained_checkpoint_evidence,
        checkpoint_index,
    })
}

pub(super) fn retained_provider_evidence_commitment(
    generation: &ProviderGenerationExport,
    inventory: &ProviderRetentionInventory,
) -> Result<Digest, IdentityError> {
    let retained = derive_retained_provider_material(generation, inventory)?;
    retained_provider_payload_commitment(
        &retained.records,
        &retained.checkpoint_evidence,
        &retained.checkpoint_index,
        inventory.audit_artifacts(),
    )
}

fn retained_provider_payload_commitment(
    records: &[RetainedProviderRecord],
    evidence: &[RetainedCheckpointMaterial],
    checkpoint_index: &[ProviderCheckpointIndex],
    artifacts: &[ProviderAuditArtifact],
) -> Result<Digest, IdentityError> {
    provider_commitment(
        PROVIDER_RETAINED_EVIDENCE_COMMITMENT_DOMAIN,
        &RetainedProviderEvidenceCommitmentWire {
            format_version: 1,
            records: records
                .iter()
                .map(|record| RetainedProviderRecordCommitmentWire {
                    leaf_index: record.leaf_index,
                    entry: &record.entry,
                    receipt: &record.receipt,
                })
                .collect(),
            checkpoint_evidence: evidence
                .iter()
                .map(|retained| RetainedCheckpointMaterialCommitmentWire {
                    genesis: retained.genesis.as_ref(),
                    prior_checkpoint_id: retained.prior_checkpoint_id,
                    events: &retained.events,
                    checkpoint: &retained.checkpoint,
                    transition_event: retained.transition_event.as_ref(),
                })
                .collect(),
            checkpoint_index: checkpoint_index
                .iter()
                .map(|index| ProviderCheckpointIndexCommitmentWire {
                    account_id: index.account_id,
                    greatest_sequence: index.greatest_sequence,
                    greatest_epoch: index.greatest_epoch,
                    current_checkpoint_id: index.current_checkpoint_id,
                    projection_heads: &index.projection_heads,
                    forked: index.forked,
                })
                .collect(),
            audit_artifact_commitment: provider_audit_artifact_commitment(artifacts)?,
        },
    )
}

/// Thread-safe in-memory implementation of the durable provider transaction contract.
#[derive(Debug, Clone)]
pub struct MemoryProviderStore {
    state: Arc<Mutex<ProviderGenerationState>>,
    portable_accounting: Arc<Mutex<interchange::ProviderGenerationPortableAccounting>>,
}

impl MemoryProviderStore {
    /// Construct an empty store for one explicit provider/log/key generation.
    pub fn new(
        provider: ProviderDescriptor,
        log_id: ProviderLogId,
        key_version: ProviderKeyVersion,
    ) -> Result<Self, IdentityError> {
        if key_version != ProviderKeyVersion::GENESIS {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider signing-key generation",
            });
        }
        Ok(Self {
            state: Arc::new(Mutex::new(ProviderGenerationState {
                provider,
                log_id,
                key_version,
                leaf_hashes: Vec::new(),
                latest_head: None,
                compaction_manifests: Vec::new(),
                payload: ProviderGenerationPayload::Active(ActiveProviderPayload {
                    entries: Vec::new(),
                    receipts: Vec::new(),
                    checkpoint_bundles: Vec::new(),
                    checkpoint_index: Vec::new(),
                }),
            })),
            portable_accounting: Arc::new(Mutex::new(
                interchange::ProviderGenerationPortableAccounting::empty(),
            )),
        })
    }

    /// Return this store's exact immutable provider/log/key address.
    pub fn generation_route(&self) -> Result<ProviderGenerationRoute, IdentityError> {
        let state = self.lock_state()?;
        ProviderGenerationRoute::new(&state.provider, state.log_id, state.key_version)
    }

    /// Return an authenticated summary of the currently committed generation.
    pub fn snapshot(&self) -> Result<ProviderGenerationSnapshot, IdentityError> {
        self.lock_state()?.snapshot()
    }

    pub(super) fn export_and_snapshot_from_validated_state(
        &self,
    ) -> Result<(ProviderGenerationExport, ProviderGenerationSnapshot), IdentityError> {
        let state = self.lock_state()?;
        Ok((state.export()?, state.snapshot()?))
    }

    /// Serve the unique current checkpoint bundle, failing closed after any retained fork.
    pub fn latest_checkpoint_bundle(
        &self,
        account_id: AccountId,
    ) -> Result<Option<ProviderCheckpointBundle>, IdentityError> {
        let state = self.lock_state()?;
        state.validate_cached()?;
        Ok(latest_checkpoint_bundle(&state, account_id)?.cloned())
    }

    /// Fetch one exact retained checkpoint branch with its authenticated provider inclusion.
    pub fn checkpoint_bundle(
        &self,
        account_id: AccountId,
        checkpoint_id: CheckpointId,
    ) -> Result<Option<PublishedCheckpoint>, IdentityError> {
        let state = self.lock_state()?;
        state.validate_cached()?;
        published_checkpoint_for(&state, account_id, checkpoint_id)
    }

    /// Fetch one bounded target-to-genesis lineage page from an explicit retained branch.
    pub fn checkpoint_lineage_page(
        &self,
        account_id: AccountId,
        start_checkpoint_id: CheckpointId,
        maximum_records: usize,
        maximum_bytes: usize,
    ) -> Result<Option<ProviderCheckpointLineagePage>, IdentityError> {
        let state = self.lock_state()?;
        state.validate_cached()?;
        checkpoint_lineage_page_for(
            &state,
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
    ) -> Result<Option<ProviderRetainedCheckpointEvidence>, IdentityError> {
        let state = self.lock_state()?;
        state.validate_cached()?;
        retained_checkpoint_evidence_for(&state, account_id, checkpoint_id)
    }

    /// Fetch the unique current raw checkpoint evidence from a locally sealed generation.
    pub fn latest_retained_checkpoint_evidence(
        &self,
        account_id: AccountId,
    ) -> Result<Option<ProviderRetainedCheckpointEvidence>, IdentityError> {
        let state = self.lock_state()?;
        state.validate_cached()?;
        let ProviderGenerationPayload::Sealed(sealed) = &state.payload else {
            return Ok(None);
        };
        if sealed.archive_complete {
            return Ok(None);
        }
        let Some(index) = sealed
            .checkpoint_index
            .iter()
            .find(|index| index.account_id == account_id)
        else {
            return Ok(None);
        };
        if index.forked {
            return Err(IdentityError::AccountForked);
        }
        let checkpoint_id = index
            .current_checkpoint_id
            .ok_or(IdentityError::StorageCorruption)?;
        retained_checkpoint_evidence_for(&state, account_id, checkpoint_id)
    }

    /// Return all non-leaf rollback/equivocation artifacts retained by a sealed generation.
    pub fn retained_audit_artifacts(&self) -> Result<Vec<ProviderAuditArtifact>, IdentityError> {
        let state = self.lock_state()?;
        state.validate_cached()?;
        match &state.payload {
            ProviderGenerationPayload::Active(_) => Ok(Vec::new()),
            ProviderGenerationPayload::Sealed(sealed) => Ok(sealed.audit_artifacts.clone()),
        }
    }

    /// Return every retained checkpoint bundle in provider append order.
    pub fn checkpoint_bundles(&self) -> Result<Vec<ProviderCheckpointBundle>, IdentityError> {
        let state = self.lock_state()?;
        state.validate_cached()?;
        match &state.payload {
            ProviderGenerationPayload::Active(active) => Ok(active.checkpoint_bundles.clone()),
            ProviderGenerationPayload::Sealed(sealed) if sealed.archive_complete => {
                Ok(sealed.checkpoint_bundles.clone())
            }
            ProviderGenerationPayload::Sealed(_) => Err(IdentityError::ProviderArchiveRequired),
        }
    }

    /// Return every verified compaction manifest durably recorded for this generation.
    pub fn compaction_manifests(&self) -> Result<Vec<ProviderCompactionManifest>, IdentityError> {
        let state = self.lock_state()?;
        state.validate_cached()?;
        Ok(state.compaction_manifests.clone())
    }

    /// Reverify and durably retain a compaction manifest before any external release workflow.
    pub fn record_compaction_manifest(
        &self,
        authorization: &ProviderCompactionAuthorization,
        mirror: &ProviderRecoveryExport,
        inventory: &ProviderRetentionInventory,
    ) -> Result<ProviderCompactionManifest, IdentityError> {
        let mut state = self.lock_state()?;
        let mut portable_accounting = self.lock_portable_accounting()?;
        state.validate_cached()?;
        if matches!(state.payload, ProviderGenerationPayload::Sealed(_)) {
            return Err(IdentityError::ProviderArchiveRequired);
        }
        let manifest = authorization.manifest().clone();
        if state.compaction_manifests.contains(&manifest) {
            return Ok(manifest);
        }
        let mut source = state.export()?;
        source
            .compaction_manifests
            .retain(|candidate| candidate != &manifest);
        if &source != mirror.generation() {
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
        let mut staged = state.clone();
        staged.compaction_manifests.push(manifest.clone());
        staged.validate_cached()?;
        let staged_accounting =
            (*portable_accounting).with_appended_compaction_manifest(&manifest)?;
        *state = staged;
        *portable_accounting = staged_accounting;
        Ok(manifest)
    }

    /// Irreversibly seal this generation after an exact verified full-mirror comparison.
    ///
    /// Sealing retains only inventory-mandated original-index records locally. The mirror is the
    /// sole complete archive; sealed generations never accept additional appends.
    pub fn seal_after_verified_mirror(
        &self,
        authorization: &ProviderCompactionAuthorization,
        mirror: &ProviderRecoveryExport,
        inventory: &ProviderRetentionInventory,
    ) -> Result<usize, IdentityError> {
        let mut state = self.lock_state()?;
        seal_generation_state(&mut state, authorization, mirror, inventory)
    }

    /// Atomically append or re-observe one admitted subject and issue an inclusion receipt.
    pub fn append<S: ProviderHeadSigner + ?Sized>(
        &self,
        permit: ProviderAppendPermit,
        observed_at: Timestamp,
        signer: &S,
    ) -> Result<InclusionReceipt, IdentityError> {
        let ProviderAppendPermit { admission, request } = permit;
        request.validate_for(&admission)?;
        let _charged_bytes = request.encoded_bytes();
        admission.validate_observed_at(observed_at)?;
        let checkpoint_bundle = admission.checkpoint_bundle().cloned();
        if let Some(bundle) = checkpoint_bundle.as_ref() {
            interchange::validate_checkpoint_bundle_interchange_item(bundle)?;
        }
        let mut state = self.lock_state()?;
        let mut portable_accounting = self.lock_portable_accounting()?;
        if matches!(state.payload, ProviderGenerationPayload::Sealed(_)) {
            return Err(IdentityError::ProviderArchiveRequired);
        }
        if state
            .latest_head
            .as_ref()
            .is_some_and(|head| observed_at < head.body().observed_at())
        {
            return Err(IdentityError::ProviderRollback);
        }

        let duplicate_index = state.active()?.entries.iter().position(|entry| {
            entry.account_id() == admission.account_id() && entry.subject() == admission.subject()
        });
        let duplicate_bundle_merge = if let Some(index) = duplicate_index {
            merge_duplicate_bundle(&state, index, checkpoint_bundle.as_ref())?
        } else if let Some(bundle) = checkpoint_bundle.as_ref() {
            validate_checkpoint_admission(&state, bundle)?;
            None
        } else {
            None
        };
        let mut staged_entries = state.active()?.entries.clone();
        let mut staged_tree = state.tree()?;
        let mut staged_checkpoint_bundles = state.active()?.checkpoint_bundles.clone();
        let mut staged_accounting = *portable_accounting;
        if let Some((index, merged)) = duplicate_bundle_merge {
            interchange::validate_checkpoint_bundle_interchange_item(&merged)?;
            let retained = staged_checkpoint_bundles
                .get_mut(index)
                .ok_or(IdentityError::StorageCorruption)?;
            staged_accounting =
                staged_accounting.with_replaced_checkpoint_bundle(retained, &merged)?;
            *retained = merged;
        }
        let leaf_index = match duplicate_index {
            Some(index) => u64::try_from(index).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "provider log duplicate index",
            })?,
            None => {
                if staged_entries.len() == MAX_MERKLE_LOG_LEAVES {
                    return Err(IdentityError::limit(
                        "provider log entries",
                        staged_entries.len().saturating_add(1),
                        MAX_MERKLE_LOG_LEAVES,
                    ));
                }
                let entry = ProviderLogEntryBody::new(
                    state.provider.id()?,
                    state.log_id,
                    admission.account_id(),
                    admission.subject(),
                    observed_at,
                    Extensions::default(),
                )?;
                let index = staged_tree.append(entry.merkle_leaf_hash()?)?;
                staged_entries.push(entry);
                if let Some(bundle) = checkpoint_bundle.clone() {
                    staged_checkpoint_bundles.push(bundle);
                }
                index
            }
        };
        let staged_checkpoint_index =
            rebuild_checkpoint_index(&staged_entries, &staged_checkpoint_bundles)?;

        let head_body = ProviderHeadBody::new(
            state.provider.id()?,
            state.log_id,
            state.key_version,
            staged_tree.tree_size()?,
            staged_tree.root()?,
            observed_at,
            Extensions::default(),
        )?;
        let signature = signer.sign_provider_head(&head_body.signing_bytes()?)?;
        let signed_head = SignedProviderHead::new(head_body, signature);
        signed_head.verify(&state.provider)?;
        let entry_index =
            usize::try_from(leaf_index).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "provider log receipt index",
            })?;
        let entry = staged_entries
            .get(entry_index)
            .cloned()
            .ok_or(IdentityError::StorageCorruption)?;
        let receipt = InclusionReceipt::new(
            entry,
            leaf_index,
            staged_tree
                .inclusion_proof(leaf_index)?
                .audit_path()
                .to_vec(),
            signed_head.clone(),
        )?;
        receipt.verify(&state.provider)?;

        let mut staged_receipts = state.active()?.receipts.clone();
        match duplicate_index {
            Some(index) => {
                let previous = state
                    .active()?
                    .receipts
                    .get(index)
                    .ok_or(IdentityError::StorageCorruption)?;
                staged_accounting = staged_accounting.with_replaced_receipt(previous, &receipt)?;
                let retained = staged_receipts
                    .get_mut(index)
                    .ok_or(IdentityError::StorageCorruption)?;
                *retained = receipt.clone();
            }
            None => {
                let appended_entry = staged_entries
                    .last()
                    .ok_or(IdentityError::StorageCorruption)?;
                let appended_leaf_hash = staged_tree
                    .leaf_hashes()
                    .last()
                    .ok_or(IdentityError::StorageCorruption)?;
                staged_accounting = staged_accounting
                    .with_appended_entry(appended_entry)?
                    .with_appended_leaf_hash(appended_leaf_hash)?
                    .with_appended_receipt(&receipt)?;
                if checkpoint_bundle.is_some() {
                    let appended_bundle = staged_checkpoint_bundles
                        .last()
                        .ok_or(IdentityError::StorageCorruption)?;
                    staged_accounting =
                        staged_accounting.with_appended_checkpoint_bundle(appended_bundle)?;
                }
                staged_receipts.push(receipt.clone());
            }
        }

        state.active_mut()?.entries = staged_entries;
        state.leaf_hashes = staged_tree.leaf_hashes().to_vec();
        state.latest_head = Some(signed_head);
        state.active_mut()?.checkpoint_bundles = staged_checkpoint_bundles;
        state.active_mut()?.checkpoint_index = staged_checkpoint_index;
        state.active_mut()?.receipts = staged_receipts;
        *portable_accounting = staged_accounting;
        Ok(receipt)
    }

    /// Return a bounded account-filtered page with a provider-wide continuation cursor.
    pub fn account_history(
        &self,
        account_id: AccountId,
        after_cursor: Option<u64>,
        maximum_records: usize,
        maximum_bytes: usize,
    ) -> Result<ProviderAccountHistoryPage, IdentityError> {
        if maximum_records == 0 || maximum_records > MAX_HISTORY_PAGE_EVENTS {
            return Err(IdentityError::limit(
                "provider account-history records",
                maximum_records,
                MAX_HISTORY_PAGE_EVENTS,
            ));
        }
        if maximum_bytes == 0 || maximum_bytes > MAX_PROVIDER_ACCOUNT_RESPONSE_BYTES {
            return Err(IdentityError::limit(
                "provider account-history bytes",
                maximum_bytes,
                MAX_PROVIDER_ACCOUNT_RESPONSE_BYTES,
            ));
        }
        let state = self.lock_state()?;
        state.validate_cached()?;
        let entries = match &state.payload {
            ProviderGenerationPayload::Active(active) => active.entries.clone(),
            ProviderGenerationPayload::Sealed(sealed) if sealed.archive_complete => sealed
                .retained_records
                .iter()
                .map(|record| record.entry.clone())
                .collect(),
            ProviderGenerationPayload::Sealed(_) => {
                return Err(IdentityError::ProviderArchiveRequired);
            }
        };
        let start = match after_cursor {
            None => 0,
            Some(cursor) => usize::try_from(cursor)
                .map_err(|_| IdentityError::ArithmeticOverflow {
                    resource: "provider account-history cursor",
                })?
                .checked_add(1)
                .ok_or(IdentityError::ArithmeticOverflow {
                    resource: "provider account-history cursor",
                })?,
        };
        if start > entries.len() {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider account-history cursor",
            });
        }

        let mut records = Vec::new();
        let mut cursor = after_cursor;
        let mut exhausted = true;
        for (index, entry) in entries.iter().enumerate().skip(start) {
            if entry.account_id() == account_id {
                if records.len() == maximum_records {
                    exhausted = false;
                    break;
                }
                let leaf_index =
                    u64::try_from(index).map_err(|_| IdentityError::ArithmeticOverflow {
                        resource: "provider account-history leaf index",
                    })?;
                records.push(ProviderAccountHistoryRecord {
                    leaf_index,
                    entry: entry.clone(),
                });
                let encoded = crate::codec::encode_wire(&(records.as_slice(), Some(leaf_index)))?;
                if encoded.len() > maximum_bytes {
                    records.pop();
                    if records.is_empty() {
                        return Err(IdentityError::limit(
                            "provider account-history bytes",
                            encoded.len(),
                            maximum_bytes,
                        ));
                    }
                    exhausted = false;
                    break;
                }
            }
            cursor = Some(
                u64::try_from(index).map_err(|_| IdentityError::ArithmeticOverflow {
                    resource: "provider account-history cursor",
                })?,
            );
        }
        Ok(ProviderAccountHistoryPage {
            records,
            next_cursor: if exhausted { None } else { cursor },
        })
    }

    /// Produce a complete bounded export suitable for verified recovery or mirroring.
    pub fn export_generation(&self) -> Result<ProviderGenerationExport, IdentityError> {
        let state = self.lock_state()?;
        state.validate_cached()?;
        state.export()
    }

    /// Bind this complete active generation or recovery archive to an exact audit snapshot.
    pub fn export_recovery(
        &self,
        audit: ProviderAuditSnapshot,
    ) -> Result<ProviderRecoveryExport, IdentityError> {
        ProviderRecoveryExport::new(self.export_generation()?, audit)
    }

    /// Re-export the complete generation and audit journal from a restored immutable archive.
    pub fn archived_recovery_export(&self) -> Result<ProviderRecoveryExport, IdentityError> {
        let state = self.lock_state()?;
        state.validate_cached()?;
        let ProviderGenerationPayload::Sealed(sealed) = &state.payload else {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider recovery archive state",
            });
        };
        if !sealed.archive_complete {
            return Err(IdentityError::ProviderArchiveRequired);
        }
        let audit = sealed
            .audit_snapshot
            .clone()
            .ok_or(IdentityError::StorageCorruption)?;
        ProviderRecoveryExport::new(state.export()?, audit)
    }

    /// Return the complete audit history retained by a restored immutable archive.
    pub fn archived_audit_snapshot(&self) -> Result<ProviderAuditSnapshot, IdentityError> {
        let state = self.lock_state()?;
        state.validate_cached()?;
        match &state.payload {
            ProviderGenerationPayload::Sealed(sealed) if sealed.archive_complete => sealed
                .audit_snapshot
                .clone()
                .ok_or(IdentityError::StorageCorruption),
            ProviderGenerationPayload::Sealed(_) => Err(IdentityError::ProviderArchiveRequired),
            ProviderGenerationPayload::Active(_) => Err(IdentityError::InvalidRelationship {
                resource: "provider recovery archive state",
            }),
        }
    }

    /// Restore only after validating the complete export against its authenticated head.
    pub fn restore_generation(export: ProviderGenerationExport) -> Result<Self, IdentityError> {
        let portable_accounting =
            interchange::ProviderGenerationPortableAccounting::from_export(&export)?;
        let state = ProviderGenerationState {
            provider: export.provider,
            log_id: export.log_id,
            key_version: export.key_version,
            leaf_hashes: export.leaf_hashes,
            latest_head: export.latest_head,
            compaction_manifests: export.compaction_manifests,
            payload: ProviderGenerationPayload::Active(ActiveProviderPayload {
                entries: export.entries,
                receipts: export.receipts,
                checkpoint_bundles: export.checkpoint_bundles,
                checkpoint_index: Vec::new(),
            }),
        };
        let checkpoint_index = rebuild_checkpoint_index(
            &state.active()?.entries,
            &state.active()?.checkpoint_bundles,
        )?;
        let mut state = state;
        state.active_mut()?.checkpoint_index = checkpoint_index;
        state.validate()?;
        Ok(Self {
            state: Arc::new(Mutex::new(state)),
            portable_accounting: Arc::new(Mutex::new(portable_accounting)),
        })
    }

    /// Restore a complete recovery export as an immutable local archive.
    pub fn restore_recovery(recovery: ProviderRecoveryExport) -> Result<Self, IdentityError> {
        let state = recovery_archive_state(recovery)?;
        let portable_accounting =
            interchange::ProviderGenerationPortableAccounting::from_export(&state.export()?)?;
        Ok(Self {
            state: Arc::new(Mutex::new(state)),
            portable_accounting: Arc::new(Mutex::new(portable_accounting)),
        })
    }

    /// Serve consistency evidence for an exact historical prefix and requested later prefix.
    pub fn consistency_proof(
        &self,
        old_size: u64,
        new_size: u64,
    ) -> Result<MerkleConsistencyProof, IdentityError> {
        if old_size > new_size {
            return Err(IdentityError::InvalidProof);
        }
        let state = self.lock_state()?;
        let new_len = usize::try_from(new_size).map_err(|_| IdentityError::ArithmeticOverflow {
            resource: "provider consistency tree size",
        })?;
        if new_len > state.leaf_hashes.len() {
            return Err(IdentityError::InvalidProof);
        }
        AppendOnlyMerkleLog::from_leaf_hashes(state.leaf_hashes[..new_len].to_vec())?
            .consistency_proof(old_size)
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, ProviderGenerationState>, IdentityError> {
        self.state
            .lock()
            .map_err(|_| IdentityError::StorageCorruption)
    }

    fn lock_portable_accounting(
        &self,
    ) -> Result<MutexGuard<'_, interchange::ProviderGenerationPortableAccounting>, IdentityError>
    {
        self.portable_accounting
            .lock()
            .map_err(|_| IdentityError::StorageCorruption)
    }
}

impl AddressedProviderGeneration for MemoryProviderStore {
    fn generation_route(&self) -> Result<ProviderGenerationRoute, IdentityError> {
        Self::generation_route(self)
    }
}

fn recovery_archive_state(
    recovery: ProviderRecoveryExport,
) -> Result<ProviderGenerationState, IdentityError> {
    recovery.validate()?;
    let ProviderRecoveryExport {
        generation,
        audit,
        artifacts,
        ..
    } = recovery;
    let checkpoint_index =
        rebuild_checkpoint_index(&generation.entries, &generation.checkpoint_bundles)?;
    let mut retained_records = Vec::with_capacity(generation.entries.len());
    for (index, (entry, receipt)) in generation
        .entries
        .into_iter()
        .zip(generation.receipts)
        .enumerate()
    {
        retained_records.push(RetainedProviderRecord {
            leaf_index: u64::try_from(index).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "provider recovery archive leaf index",
            })?,
            entry,
            receipt,
        });
    }
    let state = ProviderGenerationState {
        provider: generation.provider,
        log_id: generation.log_id,
        key_version: generation.key_version,
        leaf_hashes: generation.leaf_hashes,
        latest_head: generation.latest_head,
        compaction_manifests: generation.compaction_manifests,
        payload: ProviderGenerationPayload::Sealed(Box::new(SealedProviderPayload {
            retained_records,
            checkpoint_bundles: generation.checkpoint_bundles,
            retained_checkpoint_evidence: Vec::new(),
            checkpoint_index,
            manifest: None,
            inventory: None,
            audit_snapshot: Some(audit),
            audit_artifacts: artifacts,
            archive_complete: true,
        })),
    };
    state.validate()?;
    Ok(state)
}

fn seal_generation_state(
    state: &mut ProviderGenerationState,
    authorization: &ProviderCompactionAuthorization,
    mirror: &ProviderRecoveryExport,
    inventory: &ProviderRetentionInventory,
) -> Result<usize, IdentityError> {
    state.validate()?;
    if let ProviderGenerationPayload::Sealed(sealed) = &state.payload {
        if sealed.archive_complete {
            return Err(IdentityError::ProviderArchiveRequired);
        }
        if sealed.manifest.as_ref() != Some(authorization.manifest())
            || sealed.inventory.as_ref() != Some(inventory)
        {
            return Err(IdentityError::InvalidProof);
        }
        authorization.manifest().verify(mirror, mirror, inventory)?;
        let retained = sealed.retained_records.len();
        let source_size = usize::try_from(authorization.manifest().source_tree_size())
            .map_err(|_| IdentityError::StorageCorruption)?;
        return source_size
            .checked_sub(retained)
            .ok_or(IdentityError::StorageCorruption);
    }
    let mut source = state.export()?;
    source
        .compaction_manifests
        .retain(|candidate| candidate != authorization.manifest());
    if &source != mirror.generation() {
        return Err(IdentityError::InvalidProof);
    }
    authorization.manifest().verify(mirror, mirror, inventory)?;
    let retained = derive_retained_provider_material(mirror.generation(), inventory)?;
    let released = source
        .entries
        .len()
        .checked_sub(retained.records.len())
        .ok_or(IdentityError::StorageCorruption)?;
    let manifest = authorization.manifest().clone();
    let mut staged = state.clone();
    if !staged.compaction_manifests.contains(&manifest) {
        if staged.compaction_manifests.len() == MAX_PROVIDER_COMPACTION_MANIFESTS {
            return Err(IdentityError::limit(
                "provider compaction manifests",
                staged.compaction_manifests.len().saturating_add(1),
                MAX_PROVIDER_COMPACTION_MANIFESTS,
            ));
        }
        staged.compaction_manifests.push(manifest.clone());
    }
    staged.payload = ProviderGenerationPayload::Sealed(Box::new(SealedProviderPayload {
        retained_records: retained.records,
        checkpoint_bundles: Vec::new(),
        retained_checkpoint_evidence: retained.checkpoint_evidence,
        checkpoint_index: retained.checkpoint_index,
        manifest: Some(manifest),
        inventory: Some(inventory.clone()),
        audit_snapshot: None,
        audit_artifacts: inventory.audit_artifacts().to_vec(),
        archive_complete: false,
    }));
    staged.validate()?;
    *state = staged;
    Ok(released)
}

fn encoded_admission_bytes(admission: &ProviderLogAdmission) -> Result<usize, IdentityError> {
    let bytes = match admission.checkpoint_bundle() {
        Some(bundle) => {
            let checkpoint = bundle.verified_checkpoint();
            crate::codec::encode_wire(&(
                admission.account_id(),
                admission.subject(),
                bundle.genesis(),
                bundle.prior_checkpoint_id(),
                bundle.events(),
                checkpoint.checkpoint(),
                checkpoint.transition_event(),
            ))?
        }
        None => crate::codec::encode_wire(&(admission.account_id(), admission.subject()))?,
    };
    if bytes.len() > MAX_PROVIDER_ACCOUNT_RESPONSE_BYTES {
        return Err(IdentityError::limit(
            "provider append admission bytes",
            bytes.len(),
            MAX_PROVIDER_ACCOUNT_RESPONSE_BYTES,
        ));
    }
    Ok(bytes.len())
}

fn merge_duplicate_bundle(
    state: &ProviderGenerationState,
    entry_index: usize,
    candidate: Option<&ProviderCheckpointBundle>,
) -> Result<Option<(usize, ProviderCheckpointBundle)>, IdentityError> {
    let entry = state
        .active()?
        .entries
        .get(entry_index)
        .ok_or(IdentityError::StorageCorruption)?;
    match (entry.subject(), candidate) {
        (ProviderLogSubject::Checkpoint(checkpoint_id), Some(candidate)) => {
            let (bundle_index, retained) = state
                .active()?
                .checkpoint_bundles
                .iter()
                .enumerate()
                .find(|bundle| {
                    let checkpoint = bundle.1.verified_checkpoint();
                    checkpoint.checkpoint().body().account_id() == entry.account_id()
                        && checkpoint.checkpoint_id() == checkpoint_id
                })
                .ok_or(IdentityError::StorageCorruption)?;
            let merged = retained.merge_approval_evidence(candidate)?;
            Ok(Some((bundle_index, merged)))
        }
        (ProviderLogSubject::Checkpoint(_), None)
        | (ProviderLogSubject::EventIntent(_), Some(_)) => {
            Err(IdentityError::InvalidRelationship {
                resource: "provider duplicate admission material",
            })
        }
        (ProviderLogSubject::EventIntent(_), None) => Ok(None),
    }
}

fn validate_checkpoint_admission(
    state: &ProviderGenerationState,
    bundle: &ProviderCheckpointBundle,
) -> Result<(), IdentityError> {
    let checkpoint = bundle.verified_checkpoint();
    let body = checkpoint.checkpoint().body();
    if let Some(prior_checkpoint_id) = bundle.prior_checkpoint_id() {
        let prior_retained = state.active()?.checkpoint_bundles.iter().any(|candidate| {
            let prior = candidate.verified_checkpoint();
            prior.checkpoint().body().account_id() == body.account_id()
                && prior.checkpoint_id() == prior_checkpoint_id
        });
        if !prior_retained {
            return Err(IdentityError::InvalidProof);
        }
    }
    if let Some(index) = state
        .active()?
        .checkpoint_index
        .iter()
        .find(|index| index.account_id == body.account_id())
        && (body.sequence() < index.greatest_sequence
            || body.account_epoch() < index.greatest_epoch)
    {
        return Err(IdentityError::ProviderRollback);
    }
    Ok(())
}

fn latest_checkpoint_bundle(
    state: &ProviderGenerationState,
    account_id: AccountId,
) -> Result<Option<&ProviderCheckpointBundle>, IdentityError> {
    match &state.payload {
        ProviderGenerationPayload::Active(payload) => select_current_checkpoint_bundle(
            &payload.checkpoint_index,
            &payload.checkpoint_bundles,
            account_id,
        ),
        ProviderGenerationPayload::Sealed(payload) if payload.archive_complete => {
            select_current_checkpoint_bundle(
                &payload.checkpoint_index,
                &payload.checkpoint_bundles,
                account_id,
            )
        }
        ProviderGenerationPayload::Sealed(_) => Err(IdentityError::ProviderArchiveRequired),
    }
}

fn published_checkpoint_for(
    state: &ProviderGenerationState,
    account_id: AccountId,
    checkpoint_id: CheckpointId,
) -> Result<Option<PublishedCheckpoint>, IdentityError> {
    if let ProviderGenerationPayload::Sealed(sealed) = &state.payload {
        if !sealed.archive_complete {
            return Err(IdentityError::ProviderArchiveRequired);
        }
        let mut matches = sealed.retained_records.iter().filter(|record| {
            record.entry.account_id() == account_id
                && record.entry.subject() == ProviderLogSubject::Checkpoint(checkpoint_id)
        });
        let Some(record) = matches.next() else {
            return Err(IdentityError::ProviderArchiveRequired);
        };
        if matches.next().is_some() {
            return Err(IdentityError::StorageCorruption);
        }
        let bundle = sealed
            .checkpoint_bundles
            .iter()
            .find(|bundle| {
                let checkpoint = bundle.verified_checkpoint();
                checkpoint.checkpoint().body().account_id() == account_id
                    && checkpoint.checkpoint_id() == checkpoint_id
            })
            .cloned()
            .ok_or(IdentityError::StorageCorruption)?;
        return PublishedCheckpoint::new(bundle, record.receipt.clone(), &state.provider).map(Some);
    }
    let mut bundle_matches = state.active()?.checkpoint_bundles.iter().filter(|bundle| {
        let checkpoint = bundle.verified_checkpoint();
        checkpoint.checkpoint().body().account_id() == account_id
            && checkpoint.checkpoint_id() == checkpoint_id
    });
    let Some(bundle) = bundle_matches.next() else {
        return Ok(None);
    };
    if bundle_matches.next().is_some() {
        return Err(IdentityError::StorageCorruption);
    }
    let mut entry_matches = state
        .active()?
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            entry.account_id() == account_id
                && entry.subject() == ProviderLogSubject::Checkpoint(checkpoint_id)
        });
    let (entry_index, _) = entry_matches
        .next()
        .ok_or(IdentityError::StorageCorruption)?;
    if entry_matches.next().is_some() {
        return Err(IdentityError::StorageCorruption);
    }
    let receipt = state
        .active()?
        .receipts
        .get(entry_index)
        .cloned()
        .ok_or(IdentityError::StorageCorruption)?;
    PublishedCheckpoint::new(bundle.clone(), receipt, &state.provider).map(Some)
}

fn retained_checkpoint_evidence_for(
    state: &ProviderGenerationState,
    account_id: AccountId,
    checkpoint_id: CheckpointId,
) -> Result<Option<ProviderRetainedCheckpointEvidence>, IdentityError> {
    let ProviderGenerationPayload::Sealed(sealed) = &state.payload else {
        return Ok(None);
    };
    if sealed.archive_complete {
        return Ok(None);
    }
    let mut matches = sealed.retained_records.iter().filter(|record| {
        record.entry.account_id() == account_id
            && record.entry.subject() == ProviderLogSubject::Checkpoint(checkpoint_id)
    });
    let Some(record) = matches.next() else {
        return Err(IdentityError::ProviderArchiveRequired);
    };
    if matches.next().is_some() {
        return Err(IdentityError::StorageCorruption);
    }
    let mut evidence = sealed
        .retained_checkpoint_evidence
        .iter()
        .filter(|evidence| {
            evidence.checkpoint.body().account_id() == account_id
                && evidence.checkpoint_id() == Ok(checkpoint_id)
        });
    let material = evidence
        .next()
        .cloned()
        .ok_or(IdentityError::StorageCorruption)?;
    if evidence.next().is_some() {
        return Err(IdentityError::StorageCorruption);
    }
    Ok(Some(ProviderRetainedCheckpointEvidence {
        material,
        receipt: record.receipt.clone(),
    }))
}

fn checkpoint_lineage_page_for(
    state: &ProviderGenerationState,
    account_id: AccountId,
    start_checkpoint_id: CheckpointId,
    maximum_records: usize,
    maximum_bytes: usize,
) -> Result<Option<ProviderCheckpointLineagePage>, IdentityError> {
    if maximum_records == 0 || maximum_bytes == 0 {
        return Err(IdentityError::limit(
            "provider checkpoint-lineage page",
            0,
            1,
        ));
    }
    let record_limit = maximum_records.min(MAX_HISTORY_PAGE_EVENTS);
    let byte_limit = maximum_bytes.min(MAX_PROVIDER_ACCOUNT_RESPONSE_BYTES);
    let Some(first) = published_checkpoint_for(state, account_id, start_checkpoint_id)? else {
        return Ok(None);
    };
    let mut checkpoints = Vec::new();
    let mut total_bytes = 0_usize;
    let mut current = Some(first);
    let mut seen = std::collections::BTreeSet::new();
    while let Some(checkpoint) = current {
        let checkpoint_id = checkpoint.bundle().verified_checkpoint().checkpoint_id();
        if !seen.insert(checkpoint_id) {
            return Err(IdentityError::InvalidProof);
        }
        let encoded_bytes = crate::publication::encoded_published_checkpoint_bytes(&checkpoint)?;
        let next_total =
            total_bytes
                .checked_add(encoded_bytes)
                .ok_or(IdentityError::ArithmeticOverflow {
                    resource: "provider checkpoint-lineage bytes",
                })?;
        if checkpoints.len() == record_limit || next_total > byte_limit {
            if checkpoints.is_empty() {
                return Err(IdentityError::limit(
                    "provider checkpoint-lineage bytes",
                    encoded_bytes,
                    byte_limit,
                ));
            }
            let next_prior_checkpoint_id = checkpoints
                .last()
                .and_then(|retained: &PublishedCheckpoint| retained.bundle().prior_checkpoint_id());
            return ProviderCheckpointLineagePage::new(
                account_id,
                start_checkpoint_id,
                checkpoints,
                next_prior_checkpoint_id,
                &state.provider,
                state.log_id,
            )
            .map(Some);
        }
        total_bytes = next_total;
        let prior_checkpoint_id = checkpoint.bundle().prior_checkpoint_id();
        checkpoints.push(checkpoint);
        current = match prior_checkpoint_id {
            None => None,
            Some(prior_checkpoint_id) => {
                published_checkpoint_for(state, account_id, prior_checkpoint_id)?
                    .ok_or(IdentityError::InvalidProof)
                    .map(Some)?
            }
        };
    }
    ProviderCheckpointLineagePage::new(
        account_id,
        start_checkpoint_id,
        checkpoints,
        None,
        &state.provider,
        state.log_id,
    )
    .map(Some)
}

fn select_current_checkpoint_bundle<'a>(
    checkpoint_index: &[ProviderCheckpointIndex],
    bundles: &'a [ProviderCheckpointBundle],
    account_id: AccountId,
) -> Result<Option<&'a ProviderCheckpointBundle>, IdentityError> {
    let Some(index) = checkpoint_index
        .iter()
        .find(|index| index.account_id == account_id)
    else {
        return Ok(None);
    };
    if index.forked {
        return Err(IdentityError::AccountForked);
    }
    let checkpoint_id = index
        .current_checkpoint_id
        .ok_or(IdentityError::StorageCorruption)?;
    bundles
        .iter()
        .rev()
        .find(|bundle| {
            let checkpoint = bundle.verified_checkpoint();
            checkpoint.checkpoint().body().account_id() == account_id
                && checkpoint.checkpoint_id() == checkpoint_id
        })
        .map(Some)
        .ok_or(IdentityError::StorageCorruption)
}

/// Rebuild and reverify the exact per-account monotonic checkpoint index.
pub(crate) fn rebuild_checkpoint_index(
    entries: &[ProviderLogEntryBody],
    bundles: &[ProviderCheckpointBundle],
) -> Result<Vec<ProviderCheckpointIndex>, IdentityError> {
    let mut lineage = BTreeMap::<CheckpointId, (VerifiedCheckpoint, AccountState)>::new();
    for bundle in bundles {
        let verified = bundle.verified_checkpoint();
        let body = verified.checkpoint().body();
        let base_state = match (bundle.genesis(), bundle.prior_checkpoint_id()) {
            (Some(genesis), None) => AccountState::from_genesis(genesis)?,
            (None, Some(prior_checkpoint_id)) => lineage
                .get(&prior_checkpoint_id)
                .filter(|(prior, _)| prior.checkpoint().body().account_id() == body.account_id())
                .map(|(_, state)| state.clone())
                .ok_or(IdentityError::StorageCorruption)?,
            (Some(_), Some(_)) | (None, None) => return Err(IdentityError::StorageCorruption),
        };
        let (projected, _) = project_bundle_state(base_state, bundle)?;
        let rebuilt = match (bundle.genesis(), bundle.prior_checkpoint_id()) {
            (Some(genesis), None) => build_provider_checkpoint_bundle_from_genesis(
                genesis,
                bundle.events(),
                verified.checkpoint(),
                verified.transition_event(),
            ),
            (None, Some(prior_checkpoint_id)) => {
                let (prior, prior_state) = lineage
                    .get(&prior_checkpoint_id)
                    .ok_or(IdentityError::StorageCorruption)?;
                build_provider_checkpoint_bundle_from_prior(
                    prior_state,
                    prior,
                    bundle.events(),
                    verified.checkpoint(),
                    verified.transition_event(),
                )
            }
            (Some(_), Some(_)) | (None, None) => return Err(IdentityError::StorageCorruption),
        }
        .map_err(|_| IdentityError::StorageCorruption)?;
        if &rebuilt != bundle
            || lineage
                .insert(verified.checkpoint_id(), (verified.clone(), projected))
                .is_some()
        {
            return Err(IdentityError::StorageCorruption);
        }
    }

    let checkpoint_entries = entries
        .iter()
        .filter_map(|entry| match entry.subject() {
            ProviderLogSubject::Checkpoint(checkpoint_id) => {
                Some((entry.account_id(), checkpoint_id))
            }
            ProviderLogSubject::EventIntent(_) => None,
        })
        .collect::<Vec<_>>();
    if checkpoint_entries.len() != bundles.len()
        || checkpoint_entries
            .iter()
            .any(|(account_id, checkpoint_id)| {
                !bundles.iter().any(|bundle| {
                    let checkpoint = bundle.verified_checkpoint();
                    checkpoint.checkpoint().body().account_id() == *account_id
                        && checkpoint.checkpoint_id() == *checkpoint_id
                })
            })
    {
        return Err(IdentityError::StorageCorruption);
    }
    rebuild_account_projections(bundles)
}

fn rebuild_account_projections(
    bundles: &[ProviderCheckpointBundle],
) -> Result<Vec<ProviderCheckpointIndex>, IdentityError> {
    let mut geneses = BTreeMap::<AccountId, AccountGenesis>::new();
    let mut events = BTreeMap::<AccountId, BTreeMap<EventId, AuthorizedEvent>>::new();
    let mut counters = BTreeMap::<AccountId, (Sequence, Epoch)>::new();
    for bundle in bundles {
        let checkpoint = bundle.verified_checkpoint();
        let body = checkpoint.checkpoint().body();
        let account_id = body.account_id();
        if let Some(genesis) = bundle.genesis() {
            match geneses.get(&account_id) {
                Some(retained) if retained != genesis => {
                    return Err(IdentityError::StorageCorruption);
                }
                Some(_) => {}
                None => {
                    geneses.insert(account_id, genesis.clone());
                }
            }
        }
        let account_events = events.entry(account_id).or_default();
        for event in bundle.events() {
            let event_id = event.event_id()?;
            match account_events.get(&event_id) {
                Some(retained) if retained.body() != event.body() => {
                    return Err(IdentityError::StorageCorruption);
                }
                Some(_) => {}
                None => {
                    account_events.insert(event_id, event.clone());
                }
            }
        }
        match counters.get_mut(&account_id) {
            Some((greatest_sequence, greatest_epoch)) => {
                if body.sequence() < *greatest_sequence || body.account_epoch() < *greatest_epoch {
                    return Err(IdentityError::StorageCorruption);
                }
                *greatest_sequence = (*greatest_sequence).max(body.sequence());
                *greatest_epoch = (*greatest_epoch).max(body.account_epoch());
            }
            None => {
                counters.insert(account_id, (body.sequence(), body.account_epoch()));
            }
        }
    }

    let mut index = Vec::with_capacity(counters.len());
    for (account_id, (greatest_sequence, greatest_epoch)) in counters {
        let genesis = geneses
            .get(&account_id)
            .ok_or(IdentityError::StorageCorruption)?;
        let mut state = AccountState::from_genesis(genesis)?;
        let mut ordered = events
            .remove(&account_id)
            .unwrap_or_default()
            .into_iter()
            .map(|(event_id, event)| (event.body().sequence(), event_id, event))
            .collect::<Vec<_>>();
        ordered.sort_unstable_by_key(|(sequence, event_id, _)| (*sequence, *event_id));
        for (_, _, event) in ordered {
            match state.validate_and_apply(&event)?.disposition() {
                ApplyDisposition::Applied | ApplyDisposition::ForkDetected => {}
                ApplyDisposition::Replay | ApplyDisposition::ApprovalsMerged => {
                    return Err(IdentityError::StorageCorruption);
                }
            }
        }
        let forked = state.lifecycle() == ProjectionLifecycle::Forked;
        let current_checkpoint_id = if forked {
            None
        } else {
            bundles
                .iter()
                .rev()
                .filter(|bundle| {
                    bundle
                        .verified_checkpoint()
                        .checkpoint()
                        .body()
                        .account_id()
                        == account_id
                })
                .find_map(|bundle| {
                    let checkpoint = bundle.verified_checkpoint();
                    let body = checkpoint.checkpoint().body();
                    match build_checkpoint_body(&state, body.issued_at()) {
                        Ok(expected) if expected == *body => Some(checkpoint.checkpoint_id()),
                        Ok(_) | Err(_) => None,
                    }
                })
                .ok_or(IdentityError::StorageCorruption)?
                .into()
        };
        index.push(ProviderCheckpointIndex {
            account_id,
            greatest_sequence,
            greatest_epoch,
            current_checkpoint_id,
            projection_heads: state.heads().to_vec(),
            forked,
        });
    }
    Ok(index)
}

/// Select one current provider-served checkpoint using the shared fork/lineage semantics.
pub(crate) fn current_checkpoint_bundle<'a>(
    entries: &[ProviderLogEntryBody],
    bundles: &'a [ProviderCheckpointBundle],
    account_id: AccountId,
) -> Result<Option<&'a ProviderCheckpointBundle>, IdentityError> {
    let checkpoint_index = rebuild_checkpoint_index(entries, bundles)?;
    select_current_checkpoint_bundle(&checkpoint_index, bundles, account_id)
}

fn project_bundle_state(
    mut state: AccountState,
    bundle: &ProviderCheckpointBundle,
) -> Result<(AccountState, bool), IdentityError> {
    let mut observed_fork = false;
    for event in bundle.events() {
        match state.validate_and_apply(event)?.disposition() {
            ApplyDisposition::Applied => {}
            ApplyDisposition::ForkDetected => observed_fork = true,
            ApplyDisposition::Replay | ApplyDisposition::ApprovalsMerged => {
                return Err(IdentityError::InvalidRelationship {
                    resource: "provider checkpoint advancing event chain",
                });
            }
        }
    }
    if state.lifecycle() == ProjectionLifecycle::Forked {
        return Err(IdentityError::AccountForked);
    }
    Ok((state, observed_fork))
}

#[cfg(test)]
mod tests {
    use krikos_base::SecretKey;

    use super::*;
    use crate::{
        CanonicalWire, HashAlgorithm, ProposalId, ProtocolSignature, ProviderAuditArtifactKind,
        ProviderHeadAuditDisposition, SigningPublicKey,
        audit::{DurableProviderAuditor, MemoryProviderAuditStore},
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
    struct AuditArtifactSetCommitmentMirror<'a> {
        format_version: u16,
        artifact_commitments: &'a [Digest],
    }

    #[derive(serde::Serialize)]
    struct RecoveryCommitmentMirror {
        format_version: u16,
        generation_commitment: Digest,
        audit_commitment: Digest,
        artifact_commitment: Digest,
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

    fn raw_commitment<T: serde::Serialize>(domain: &[u8], value: &T) -> Digest {
        let bytes = postcard::to_stdvec(value).unwrap();
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        hasher.update(&[0]);
        hasher.update(&bytes);
        Digest::new(HashAlgorithm::Blake3_256, *hasher.finalize().as_bytes())
    }

    fn indexed_id<T: CanonicalWire>(domain: u8, index: u16) -> T {
        let mut bytes = [domain; 32];
        bytes[..2].copy_from_slice(&index.to_le_bytes());
        let digest = Digest::new(HashAlgorithm::Blake3_256, bytes);
        T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
    }

    #[test]
    fn repeated_appends_encode_only_the_changed_portable_items() {
        const APPEND_COUNT: u16 = 257;

        let signer = Signer(SecretKey::from_bytes(&[0xb1; 32]));
        let provider = ProviderDescriptor::new(
            SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
            Extensions::default(),
        )
        .unwrap();
        let store = MemoryProviderStore::new(
            provider,
            typed_id::<ProviderLogId>(0xb2),
            ProviderKeyVersion::GENESIS,
        )
        .unwrap();
        interchange::reset_portable_item_encoding_count();

        for index in 0..APPEND_COUNT {
            let observed_at = Timestamp::from_unix_millis(100);
            let admission = ProviderLogAdmission::guardian_recovery_intent(
                indexed_id::<AccountId>(0xb3, index),
                indexed_id::<ProposalId>(0xb4, index),
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
        }

        assert_eq!(
            interchange::portable_item_encoding_count(),
            usize::from(APPEND_COUNT) * 3,
            "each append must encode only its new entry, leaf hash, and receipt"
        );
    }

    #[test]
    fn archive_boundaries_replay_each_full_state_once() {
        let signer = Signer(SecretKey::from_bytes(&[0xb5; 32]));
        let provider = ProviderDescriptor::new(
            SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
            Extensions::default(),
        )
        .unwrap();
        let log_id = typed_id::<ProviderLogId>(0xb6);
        let store = MemoryProviderStore::new(provider.clone(), log_id, ProviderKeyVersion::GENESIS)
            .unwrap();
        let observed_at = Timestamp::from_unix_millis(700);
        let admission = ProviderLogAdmission::guardian_recovery_intent(
            typed_id::<AccountId>(0xb7),
            typed_id::<ProposalId>(0xb8),
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
        let generation = store.export_generation().unwrap();
        let audit_store = MemoryProviderAuditStore::new(provider, log_id);
        DurableProviderAuditor::new(audit_store.clone())
            .observe(generation.latest_head().unwrap().clone(), None)
            .unwrap();
        let audit = audit_store.snapshot().unwrap();

        reset_provider_generation_validation_count();
        crate::audit::reset_provider_audit_validation_count();
        let recovery = ProviderRecoveryExport::new(generation.clone(), audit.clone()).unwrap();
        assert_eq!(provider_generation_validation_count(), 1);
        assert_eq!(crate::audit::provider_audit_validation_count(), 1);

        reset_provider_generation_validation_count();
        let (generation_manifest, generation_chunks) = generation.interchange_parts().unwrap();
        assert_eq!(provider_generation_validation_count(), 1);
        let mut generation_assembler =
            ProviderGenerationExportAssembler::new(generation_manifest).unwrap();
        for chunk in generation_chunks {
            generation_assembler.insert(chunk).unwrap();
        }
        reset_provider_generation_validation_count();
        assert_eq!(generation_assembler.finish().unwrap(), generation);
        assert_eq!(provider_generation_validation_count(), 1);

        crate::audit::reset_provider_audit_validation_count();
        let (audit_manifest, audit_chunks) = audit.interchange_parts().unwrap();
        assert_eq!(crate::audit::provider_audit_validation_count(), 1);
        let mut audit_assembler = ProviderAuditExportAssembler::new(audit_manifest).unwrap();
        for chunk in audit_chunks {
            audit_assembler.insert(chunk).unwrap();
        }
        crate::audit::reset_provider_audit_validation_count();
        assert_eq!(audit_assembler.finish().unwrap(), audit);
        assert_eq!(crate::audit::provider_audit_validation_count(), 1);

        reset_provider_generation_validation_count();
        crate::audit::reset_provider_audit_validation_count();
        recovery.interchange_parts().unwrap();
        assert_eq!(provider_generation_validation_count(), 1);
        assert_eq!(crate::audit::provider_audit_validation_count(), 1);
    }

    #[test]
    fn exact_guardian_observation_time_is_checked_before_memory_staging() {
        let signer = Signer(SecretKey::from_bytes(&[0xa1; 32]));
        let provider = ProviderDescriptor::new(
            SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
            Extensions::default(),
        )
        .unwrap();
        let store = MemoryProviderStore::new(
            provider,
            typed_id::<ProviderLogId>(0xa2),
            ProviderKeyVersion::GENESIS,
        )
        .unwrap();
        let admission = ProviderLogAdmission::guardian_recovery_intent(
            typed_id::<AccountId>(0xa3),
            typed_id::<ProposalId>(0xa4),
            Timestamp::from_unix_millis(50),
        );
        let request = ProviderAdmissionRequest::new(128).unwrap();
        let wrong = ProviderAppendPermit {
            admission: admission.clone(),
            request,
        };
        assert_eq!(
            store.append(wrong, Timestamp::from_unix_millis(51), &signer),
            Err(IdentityError::InvalidRelationship {
                resource: "provider admission observation time",
            })
        );
        assert_eq!(store.snapshot().unwrap().tree_size(), 0);

        let exact = ProviderAppendPermit { admission, request };
        store
            .append(exact, Timestamp::from_unix_millis(50), &signer)
            .unwrap();
        assert_eq!(store.snapshot().unwrap().tree_size(), 1);
    }

    #[test]
    fn provider_aggregate_commitments_use_versioned_canonical_preimages() {
        let signer = Signer(SecretKey::from_bytes(&[0xc1; 32]));
        let provider = ProviderDescriptor::new(
            SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
            Extensions::default(),
        )
        .unwrap();
        let log_id = typed_id::<ProviderLogId>(0xc2);
        let store = MemoryProviderStore::new(provider.clone(), log_id, ProviderKeyVersion::GENESIS)
            .unwrap();
        let observed_at = Timestamp::from_unix_millis(500);
        let admission = ProviderLogAdmission::guardian_recovery_intent(
            typed_id::<AccountId>(0xc3),
            typed_id::<ProposalId>(0xc4),
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
        let generation = store.export_generation().unwrap();
        let accepted = generation.latest_head().unwrap().clone();
        let conflict_body = ProviderHeadBody::new(
            provider.id().unwrap(),
            log_id,
            ProviderKeyVersion::GENESIS,
            accepted.body().tree_size(),
            Digest::new(HashAlgorithm::Blake3_256, [0xc5; 32]),
            Timestamp::from_unix_millis(501),
            Extensions::default(),
        )
        .unwrap();
        let conflict_signature = signer
            .sign_provider_head(&conflict_body.signing_bytes().unwrap())
            .unwrap();
        let conflict = SignedProviderHead::new(conflict_body, conflict_signature);
        let audit_store = MemoryProviderAuditStore::new(provider, log_id);
        let auditor = DurableProviderAuditor::new(audit_store.clone());
        assert_eq!(
            auditor.observe(accepted, None),
            Ok(ProviderHeadAuditDisposition::FirstObserved)
        );
        assert_eq!(
            auditor.observe(conflict, None),
            Err(IdentityError::ProviderEquivocation)
        );
        let recovery =
            ProviderRecoveryExport::new(generation.clone(), audit_store.snapshot().unwrap())
                .unwrap();
        assert_eq!(recovery.artifacts().len(), 1);
        assert_eq!(
            recovery.artifacts()[0].kind(),
            ProviderAuditArtifactKind::Equivocation
        );

        let artifact_commitments = recovery
            .artifacts()
            .iter()
            .map(|artifact| {
                raw_commitment(
                    b"KRIKOS-ID/provider-audit-artifact/v1",
                    &AuditArtifactCommitmentMirror {
                        format_version: 1,
                        sequence: artifact.sequence(),
                        kind_code: 2,
                        accepted_head: artifact.accepted_head(),
                        observed_head: artifact.observed_head(),
                    },
                )
            })
            .collect::<Vec<_>>();
        let expected_artifacts = raw_commitment(
            b"KRIKOS-ID/provider-audit-artifacts/v1",
            &AuditArtifactSetCommitmentMirror {
                format_version: 1,
                artifact_commitments: &artifact_commitments,
            },
        );
        assert_eq!(
            provider_audit_artifact_commitment(recovery.artifacts()).unwrap(),
            expected_artifacts
        );
        assert_eq!(recovery.artifact_commitment(), expected_artifacts);

        let expected_recovery = raw_commitment(
            b"KRIKOS-ID/provider-recovery-export/v1",
            &RecoveryCommitmentMirror {
                format_version: 1,
                generation_commitment: recovery.generation_commitment(),
                audit_commitment: recovery.audit_commitment(),
                artifact_commitment: expected_artifacts,
            },
        );
        assert_eq!(recovery.recovery_commitment(), expected_recovery);
    }
}
