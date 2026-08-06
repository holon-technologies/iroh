//! Durable, generation-scoped provider-head auditing.

use std::sync::{Arc, Mutex, MutexGuard};

#[cfg(test)]
use std::cell::Cell;

use serde::{Deserialize, Serialize};

use crate::{
    Digest, IdentityError, ProviderDescriptor, ProviderEquivocationEvidence,
    ProviderHeadAuditDisposition, ProviderHeadAuditor, ProviderLogId, SignedProviderHead,
    limits::MAX_RETRIES, merkle::MerkleConsistencyProof,
};

#[cfg(feature = "provider-store")]
use crate::{
    codec::{decode_wire, encode_wire},
    schema::BoundedVec,
};

#[cfg(feature = "provider-store")]
mod redb;

#[cfg(feature = "provider-store")]
pub use redb::RedbProviderAuditStore;

pub(crate) const MAX_PROVIDER_AUDIT_RECORDS: usize = 65_536;
#[cfg(feature = "provider-store")]
const MAX_STORED_PROVIDER_AUDIT_BYTES: usize = 256 * 1024 * 1024;
const PROVIDER_AUDIT_ARTIFACT_COMMITMENT_DOMAIN: &[u8] = b"KRIKOS-ID/provider-audit-artifact/v1";
const PROVIDER_AUDIT_SNAPSHOT_COMMITMENT_DOMAIN: &[u8] = b"KRIKOS-ID/provider-audit-snapshot/v1";

#[cfg(test)]
thread_local! {
    static PROVIDER_AUDIT_VALIDATION_COUNT: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_provider_audit_validation_count() {
    PROVIDER_AUDIT_VALIDATION_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn provider_audit_validation_count() -> usize {
    PROVIDER_AUDIT_VALIDATION_COUNT.with(Cell::get)
}

fn record_provider_audit_validation() {
    #[cfg(test)]
    PROVIDER_AUDIT_VALIDATION_COUNT.with(|count| count.set(count.get().saturating_add(1)));
}

#[cfg(feature = "provider-store")]
pub(crate) fn encode_provider_audit_snapshot(
    snapshot: &ProviderAuditSnapshot,
) -> Result<Vec<u8>, IdentityError> {
    let bytes = encode_wire(&ProviderAuditSnapshotStorageWire::from_snapshot(snapshot)?)?;
    if bytes.len() > MAX_STORED_PROVIDER_AUDIT_BYTES {
        return Err(IdentityError::limit(
            "stored provider audit snapshot bytes",
            bytes.len(),
            MAX_STORED_PROVIDER_AUDIT_BYTES,
        ));
    }
    Ok(bytes)
}

#[cfg(feature = "provider-store")]
pub(crate) fn decode_provider_audit_snapshot(
    bytes: &[u8],
) -> Result<ProviderAuditSnapshot, IdentityError> {
    if bytes.len() > MAX_STORED_PROVIDER_AUDIT_BYTES {
        return Err(IdentityError::limit(
            "stored provider audit snapshot bytes",
            bytes.len(),
            MAX_STORED_PROVIDER_AUDIT_BYTES,
        ));
    }
    decode_wire::<ProviderAuditSnapshotStorageWire>(bytes)?.into_snapshot()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProviderAuditRecordWire {
    sequence: u64,
    head: SignedProviderHead,
    consistency_proof: Option<MerkleConsistencyProof>,
    status_code: u16,
}

#[cfg(feature = "provider-store")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProviderAuditSnapshotStorageWire {
    format_version: u16,
    revision: u64,
    provider: ProviderDescriptor,
    log_id: ProviderLogId,
    latest_head: Option<SignedProviderHead>,
    equivocation: Option<ProviderEquivocationEvidence>,
    records: BoundedVec<ProviderAuditRecordWire, MAX_PROVIDER_AUDIT_RECORDS>,
}

/// Authenticated outcome durably retained for one provider-head observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderAuditStatus {
    /// The head was accepted by the append-only single-generation auditor.
    Accepted(ProviderHeadAuditDisposition),
    /// The authenticated head moved backwards in size or provider observation time.
    Rollback,
    /// The authenticated head conflicts at the same size with a retained root.
    Equivocation,
}

/// Authenticated non-leaf attack class retained independently of provider log entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProviderAuditArtifactKind {
    /// A signed head moved backwards in tree size or provider observation time.
    Rollback,
    /// Two signed heads committed different roots for one exact tree size.
    Equivocation,
}

impl ProviderAuditArtifactKind {
    pub(crate) const fn code(self) -> u16 {
        match self {
            Self::Rollback => 1,
            Self::Equivocation => 2,
        }
    }

    #[cfg(feature = "provider-store")]
    pub(crate) fn from_code(code: u16) -> Result<Self, IdentityError> {
        match code {
            1 => Ok(Self::Rollback),
            2 => Ok(Self::Equivocation),
            _ => Err(IdentityError::StorageCorruption),
        }
    }
}

/// One bounded, independently re-verifiable rollback or equivocation artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAuditArtifact {
    sequence: u64,
    kind: ProviderAuditArtifactKind,
    accepted_head: SignedProviderHead,
    observed_head: SignedProviderHead,
}

#[derive(Serialize)]
struct ProviderAuditArtifactCommitmentWire<'a> {
    format_version: u16,
    sequence: u64,
    kind_code: u16,
    accepted_head: &'a SignedProviderHead,
    observed_head: &'a SignedProviderHead,
}

impl ProviderAuditArtifact {
    pub(crate) fn new(
        sequence: u64,
        kind: ProviderAuditArtifactKind,
        accepted_head: SignedProviderHead,
        observed_head: SignedProviderHead,
    ) -> Result<Self, IdentityError> {
        if sequence == 0
            || accepted_head.body().provider_id() != observed_head.body().provider_id()
            || accepted_head.body().log_id() != observed_head.body().log_id()
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider audit artifact generation",
            });
        }
        let is_equivocation = accepted_head.body().tree_size() == observed_head.body().tree_size()
            && accepted_head.body().tree_root() != observed_head.body().tree_root();
        let is_rollback = !is_equivocation
            && (observed_head.body().tree_size() < accepted_head.body().tree_size()
                || observed_head.body().observed_at() < accepted_head.body().observed_at());
        if !matches!(
            (kind, is_rollback, is_equivocation),
            (ProviderAuditArtifactKind::Rollback, true, false)
                | (ProviderAuditArtifactKind::Equivocation, false, true)
        ) {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider audit artifact classification",
            });
        }
        Ok(Self {
            sequence,
            kind,
            accepted_head,
            observed_head,
        })
    }

    /// One-based sequence of the corresponding durable audit record.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Stable attack classification.
    pub const fn kind(&self) -> ProviderAuditArtifactKind {
        self.kind
    }

    /// Last accepted head against which the attack was authenticated.
    pub const fn accepted_head(&self) -> &SignedProviderHead {
        &self.accepted_head
    }

    /// Signed head that proved rollback or equivocation.
    pub const fn observed_head(&self) -> &SignedProviderHead {
        &self.observed_head
    }

    /// Domain-separated exact artifact commitment used by retention manifests.
    pub fn commitment(&self) -> Result<Digest, IdentityError> {
        crate::provider::provider_commitment(
            PROVIDER_AUDIT_ARTIFACT_COMMITMENT_DOMAIN,
            &ProviderAuditArtifactCommitmentWire {
                format_version: 1,
                sequence: self.sequence,
                kind_code: self.kind.code(),
                accepted_head: &self.accepted_head,
                observed_head: &self.observed_head,
            },
        )
    }

    pub(crate) fn verify(
        &self,
        provider: &ProviderDescriptor,
        log_id: ProviderLogId,
    ) -> Result<(), IdentityError> {
        self.accepted_head.verify(provider)?;
        self.observed_head.verify(provider)?;
        if self.accepted_head.body().log_id() != log_id {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider audit artifact log generation",
            });
        }
        Self::new(
            self.sequence,
            self.kind,
            self.accepted_head.clone(),
            self.observed_head.clone(),
        )
        .map(|_| ())
    }
}

/// One append-only durable provider audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAuditRecord {
    sequence: u64,
    head: SignedProviderHead,
    consistency_proof: Option<MerkleConsistencyProof>,
    status: ProviderAuditStatus,
}

impl ProviderAuditRecord {
    /// Monotonic one-based journal sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Exact authenticated head supplied to the auditor.
    pub const fn head(&self) -> &SignedProviderHead {
        &self.head
    }

    /// Exact consistency evidence supplied with this observation, when required.
    pub const fn consistency_proof(&self) -> Option<&MerkleConsistencyProof> {
        self.consistency_proof.as_ref()
    }

    /// Verified audit outcome retained for this head.
    pub const fn status(&self) -> ProviderAuditStatus {
        self.status
    }
}

/// Complete durable state for one explicit provider-log generation auditor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAuditSnapshot {
    revision: u64,
    provider: ProviderDescriptor,
    log_id: ProviderLogId,
    latest_head: Option<SignedProviderHead>,
    equivocation: Option<ProviderEquivocationEvidence>,
    records: Vec<ProviderAuditRecord>,
}

#[derive(Serialize)]
struct ProviderAuditRecordCommitmentWire<'a> {
    sequence: u64,
    head: &'a SignedProviderHead,
    consistency_proof: Option<&'a MerkleConsistencyProof>,
    status_code: u16,
}

#[derive(Serialize)]
struct ProviderAuditSnapshotCommitmentWire<'a> {
    format_version: u16,
    revision: u64,
    provider: &'a ProviderDescriptor,
    log_id: ProviderLogId,
    latest_head: Option<&'a SignedProviderHead>,
    equivocation: Option<&'a ProviderEquivocationEvidence>,
    records: Vec<ProviderAuditRecordCommitmentWire<'a>>,
}

impl ProviderAuditSnapshot {
    /// Monotonic journal revision used for compare-and-swap persistence.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Provider descriptor authenticating every retained head.
    pub const fn provider(&self) -> &ProviderDescriptor {
        &self.provider
    }

    /// Explicit log generation; this journal never rolls over implicitly.
    pub const fn log_id(&self) -> ProviderLogId {
        self.log_id
    }

    /// Latest accepted authenticated head.
    pub const fn latest_head(&self) -> Option<&SignedProviderHead> {
        self.latest_head.as_ref()
    }

    /// First retained same-size/different-root evidence, after which auditing fails closed.
    pub const fn equivocation_evidence(&self) -> Option<&ProviderEquivocationEvidence> {
        self.equivocation.as_ref()
    }

    /// Append-only authenticated audit records.
    pub fn records(&self) -> &[ProviderAuditRecord] {
        &self.records
    }

    /// Sorted authenticated rollback/equivocation artifacts derived from the full journal.
    pub fn artifacts(&self) -> Result<Vec<ProviderAuditArtifact>, IdentityError> {
        self.validate()?;
        self.artifacts_validated()
    }

    pub(crate) fn artifacts_validated(&self) -> Result<Vec<ProviderAuditArtifact>, IdentityError> {
        let mut latest = None::<SignedProviderHead>;
        let mut artifacts = Vec::new();
        for record in &self.records {
            match record.status {
                ProviderAuditStatus::Accepted(_) => latest = Some(record.head.clone()),
                ProviderAuditStatus::Rollback => {
                    let accepted = latest.clone().ok_or(IdentityError::StorageCorruption)?;
                    artifacts.push(ProviderAuditArtifact::new(
                        record.sequence,
                        ProviderAuditArtifactKind::Rollback,
                        accepted,
                        record.head.clone(),
                    )?);
                }
                ProviderAuditStatus::Equivocation => {
                    let accepted = latest.clone().ok_or(IdentityError::StorageCorruption)?;
                    artifacts.push(ProviderAuditArtifact::new(
                        record.sequence,
                        ProviderAuditArtifactKind::Equivocation,
                        accepted,
                        record.head.clone(),
                    )?);
                }
            }
        }
        artifacts.sort_unstable_by_key(|artifact| (artifact.sequence, artifact.kind.code()));
        if artifacts
            .windows(2)
            .any(|pair| pair[0].sequence == pair[1].sequence && pair[0].kind == pair[1].kind)
        {
            return Err(IdentityError::StorageCorruption);
        }
        Ok(artifacts)
    }

    pub(crate) fn validate(&self) -> Result<(), IdentityError> {
        self.validate_inner(true)
    }

    #[cfg(feature = "provider-store")]
    pub(crate) fn validate_cached(&self) -> Result<(), IdentityError> {
        self.validate_inner(false)
    }

    fn validate_inner(&self, validate_portable_bytes: bool) -> Result<(), IdentityError> {
        record_provider_audit_validation();
        if self.records.len() > MAX_PROVIDER_AUDIT_RECORDS
            || self.revision
                != u64::try_from(self.records.len()).map_err(|_| {
                    IdentityError::ArithmeticOverflow {
                        resource: "provider audit journal revision",
                    }
                })?
        {
            return Err(IdentityError::StorageCorruption);
        }
        let mut auditor = ProviderHeadAuditor::new(self.provider.clone(), self.log_id);
        for (index, record) in self.records.iter().enumerate() {
            let expected = u64::try_from(index)
                .map_err(|_| IdentityError::ArithmeticOverflow {
                    resource: "provider audit record sequence",
                })?
                .checked_add(1)
                .ok_or(IdentityError::ArithmeticOverflow {
                    resource: "provider audit record sequence",
                })?;
            if record.sequence != expected || record.head.body().log_id() != self.log_id {
                return Err(IdentityError::StorageCorruption);
            }
            let actual = auditor.observe(record.head.clone(), record.consistency_proof.as_ref());
            let matches = match (record.status, actual) {
                (ProviderAuditStatus::Accepted(expected), Ok(actual)) => expected == actual,
                (ProviderAuditStatus::Rollback, Err(IdentityError::ProviderRollback))
                | (ProviderAuditStatus::Equivocation, Err(IdentityError::ProviderEquivocation)) => {
                    true
                }
                _ => false,
            };
            if !matches {
                return Err(IdentityError::StorageCorruption);
            }
        }
        if let Some(head) = &self.latest_head {
            head.verify(&self.provider)
                .map_err(|_| IdentityError::StorageCorruption)?;
            if head.body().log_id() != self.log_id {
                return Err(IdentityError::StorageCorruption);
            }
        }
        if let Some(evidence) = &self.equivocation {
            evidence
                .verify(&self.provider)
                .map_err(|_| IdentityError::StorageCorruption)?;
        }
        if auditor.latest_head() != self.latest_head.as_ref()
            || auditor.equivocation_evidence() != self.equivocation.as_ref()
        {
            return Err(IdentityError::StorageCorruption);
        }
        if validate_portable_bytes {
            crate::provider::interchange::validate_audit_interchange_bounds(self)?;
        }
        Ok(())
    }

    pub(crate) fn commitment(&self) -> Result<Digest, IdentityError> {
        self.validate()?;
        self.commitment_validated()
    }

    pub(crate) fn commitment_validated(&self) -> Result<Digest, IdentityError> {
        crate::provider::provider_commitment(
            PROVIDER_AUDIT_SNAPSHOT_COMMITMENT_DOMAIN,
            &ProviderAuditSnapshotCommitmentWire {
                format_version: 1,
                revision: self.revision,
                provider: &self.provider,
                log_id: self.log_id,
                latest_head: self.latest_head.as_ref(),
                equivocation: self.equivocation.as_ref(),
                records: self
                    .records
                    .iter()
                    .map(|record| ProviderAuditRecordCommitmentWire {
                        sequence: record.sequence,
                        head: &record.head,
                        consistency_proof: record.consistency_proof.as_ref(),
                        status_code: audit_status_code(record.status),
                    })
                    .collect(),
            },
        )
    }
}

impl ProviderAuditRecordWire {
    pub(crate) fn from_record(record: &ProviderAuditRecord) -> Self {
        Self {
            sequence: record.sequence,
            head: record.head.clone(),
            consistency_proof: record.consistency_proof.clone(),
            status_code: audit_status_code(record.status),
        }
    }

    pub(crate) fn into_record(self) -> Result<ProviderAuditRecord, IdentityError> {
        let status = match self.status_code {
            1 => ProviderAuditStatus::Accepted(ProviderHeadAuditDisposition::FirstObserved),
            2 => ProviderAuditStatus::Accepted(ProviderHeadAuditDisposition::TreeAdvanced),
            3 => ProviderAuditStatus::Accepted(ProviderHeadAuditDisposition::HeadRefreshed),
            4 => ProviderAuditStatus::Accepted(ProviderHeadAuditDisposition::Replay),
            5 => ProviderAuditStatus::Rollback,
            6 => ProviderAuditStatus::Equivocation,
            code => {
                return Err(IdentityError::UnsupportedCodepoint {
                    registry: "provider audit status",
                    code,
                });
            }
        };
        Ok(ProviderAuditRecord {
            sequence: self.sequence,
            head: self.head,
            consistency_proof: self.consistency_proof,
            status,
        })
    }
}

#[cfg(feature = "provider-store")]
impl ProviderAuditSnapshotStorageWire {
    fn from_snapshot(snapshot: &ProviderAuditSnapshot) -> Result<Self, IdentityError> {
        snapshot.validate()?;
        Ok(Self {
            format_version: 1,
            revision: snapshot.revision,
            provider: snapshot.provider.clone(),
            log_id: snapshot.log_id,
            latest_head: snapshot.latest_head.clone(),
            equivocation: snapshot.equivocation.clone(),
            records: BoundedVec::new(
                "stored provider audit records",
                snapshot
                    .records
                    .iter()
                    .map(ProviderAuditRecordWire::from_record)
                    .collect(),
            )?,
        })
    }

    fn into_snapshot(self) -> Result<ProviderAuditSnapshot, IdentityError> {
        if self.format_version != 1 {
            return Err(IdentityError::UnsupportedVersion {
                version: self.format_version,
            });
        }
        if self.revision
            != u64::try_from(self.records.len()).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "stored provider audit revision",
            })?
        {
            return Err(IdentityError::StorageCorruption);
        }
        provider_audit_snapshot_from_wire_records(
            self.provider,
            self.log_id,
            self.latest_head,
            self.equivocation,
            self.records.into_vec(),
        )
    }
}

pub(crate) fn provider_audit_snapshot_from_wire_records(
    provider: ProviderDescriptor,
    log_id: ProviderLogId,
    latest_head: Option<SignedProviderHead>,
    equivocation: Option<ProviderEquivocationEvidence>,
    records: Vec<ProviderAuditRecordWire>,
) -> Result<ProviderAuditSnapshot, IdentityError> {
    let revision = u64::try_from(records.len()).map_err(|_| IdentityError::ArithmeticOverflow {
        resource: "provider audit interchange revision",
    })?;
    let snapshot = ProviderAuditSnapshot {
        revision,
        provider,
        log_id,
        latest_head,
        equivocation,
        records: records
            .into_iter()
            .map(ProviderAuditRecordWire::into_record)
            .collect::<Result<Vec<_>, _>>()?,
    };
    snapshot.validate()?;
    Ok(snapshot)
}

const fn audit_status_code(status: ProviderAuditStatus) -> u16 {
    match status {
        ProviderAuditStatus::Accepted(ProviderHeadAuditDisposition::FirstObserved) => 1,
        ProviderAuditStatus::Accepted(ProviderHeadAuditDisposition::TreeAdvanced) => 2,
        ProviderAuditStatus::Accepted(ProviderHeadAuditDisposition::HeadRefreshed) => 3,
        ProviderAuditStatus::Accepted(ProviderHeadAuditDisposition::Replay) => 4,
        ProviderAuditStatus::Rollback => 5,
        ProviderAuditStatus::Equivocation => 6,
    }
}

/// Authenticated constant-size cursor used by the durable auditor's append hot path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAuditCursor {
    revision: u64,
    provider: ProviderDescriptor,
    log_id: ProviderLogId,
    latest_head: Option<SignedProviderHead>,
    equivocation: Option<ProviderEquivocationEvidence>,
}

impl ProviderAuditCursor {
    /// Build an authenticated cursor without materializing the complete retained journal.
    ///
    /// Store implementations with normalized metadata can use this constructor after loading
    /// their constant-size cursor fields. It verifies the record bound, head signatures, log
    /// generation, and terminal-equivocation relationships.
    pub fn from_authenticated_parts(
        revision: u64,
        provider: ProviderDescriptor,
        log_id: ProviderLogId,
        latest_head: Option<SignedProviderHead>,
        equivocation: Option<ProviderEquivocationEvidence>,
    ) -> Result<Self, IdentityError> {
        let maximum_revision = u64::try_from(MAX_PROVIDER_AUDIT_RECORDS).map_err(|_| {
            IdentityError::ArithmeticOverflow {
                resource: "provider audit cursor revision limit",
            }
        })?;
        if revision > maximum_revision
            || (revision == 0) != latest_head.is_none()
            || (equivocation.is_some() && revision < 2)
        {
            return Err(IdentityError::StorageCorruption);
        }
        if let Some(head) = &latest_head {
            head.verify(&provider)?;
            if head.body().log_id() != log_id {
                return Err(IdentityError::InvalidRelationship {
                    resource: "provider audit cursor log generation",
                });
            }
        }
        if let Some(evidence) = &equivocation {
            evidence.verify(&provider)?;
            if evidence.first().body().log_id() != log_id
                || evidence.second().body().log_id() != log_id
                || latest_head.as_ref() != Some(evidence.first())
            {
                return Err(IdentityError::InvalidRelationship {
                    resource: "provider audit cursor equivocation",
                });
            }
        }
        Ok(Self {
            revision,
            provider,
            log_id,
            latest_head,
            equivocation,
        })
    }

    /// Build a cursor from a complete snapshot after authenticating the journal.
    pub fn from_snapshot(snapshot: &ProviderAuditSnapshot) -> Result<Self, IdentityError> {
        snapshot.validate()?;
        Ok(Self::from_trusted_snapshot(snapshot))
    }

    pub(crate) fn from_trusted_snapshot(snapshot: &ProviderAuditSnapshot) -> Self {
        Self {
            revision: snapshot.revision,
            provider: snapshot.provider.clone(),
            log_id: snapshot.log_id,
            latest_head: snapshot.latest_head.clone(),
            equivocation: snapshot.equivocation.clone(),
        }
    }

    /// Current durable journal revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Provider authenticating this audit generation.
    pub const fn provider(&self) -> &ProviderDescriptor {
        &self.provider
    }

    /// Exact provider-log generation.
    pub const fn log_id(&self) -> ProviderLogId {
        self.log_id
    }

    /// Latest accepted authenticated head.
    pub const fn latest_head(&self) -> Option<&SignedProviderHead> {
        self.latest_head.as_ref()
    }

    /// Terminal equivocation evidence, when retained.
    pub const fn equivocation_evidence(&self) -> Option<&ProviderEquivocationEvidence> {
        self.equivocation.as_ref()
    }
}

/// Exact single-record successor requested by [`ProviderAuditStore::compare_and_append`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAuditAppend {
    record: ProviderAuditRecord,
    latest_head: Option<SignedProviderHead>,
    equivocation: Option<ProviderEquivocationEvidence>,
}

impl ProviderAuditAppend {
    /// Exact one-based record being appended.
    pub const fn record(&self) -> &ProviderAuditRecord {
        &self.record
    }

    /// Latest accepted head after applying [`Self::record`].
    pub const fn latest_head(&self) -> Option<&SignedProviderHead> {
        self.latest_head.as_ref()
    }

    /// Terminal evidence after applying [`Self::record`].
    pub const fn equivocation_evidence(&self) -> Option<&ProviderEquivocationEvidence> {
        self.equivocation.as_ref()
    }
}

/// Atomic persistence contract used by the runtime-independent durable auditor.
pub trait ProviderAuditStore: Clone + Send + Sync {
    /// Load the complete journal for explicit snapshot, export, or recovery work.
    fn load(&self) -> Result<ProviderAuditSnapshot, IdentityError>;

    /// Load the authenticated constant-size current cursor without cloning prior records.
    fn load_cursor(&self) -> Result<ProviderAuditCursor, IdentityError>;

    /// Append exactly one validated successor if the revision is still `expected_revision`.
    fn compare_and_append(
        &self,
        expected_revision: u64,
        append: ProviderAuditAppend,
    ) -> Result<(), IdentityError>;
}

#[derive(Debug)]
struct MemoryProviderAuditState {
    snapshot: ProviderAuditSnapshot,
    portable_accounting: crate::provider::interchange::ProviderAuditPortableAccounting,
}

/// In-memory atomic implementation of [`ProviderAuditStore`].
#[derive(Debug, Clone)]
pub struct MemoryProviderAuditStore {
    state: Arc<Mutex<MemoryProviderAuditState>>,
}

impl MemoryProviderAuditStore {
    /// Create an empty journal for one exact provider/log generation.
    pub fn new(provider: ProviderDescriptor, log_id: ProviderLogId) -> Self {
        Self {
            state: Arc::new(Mutex::new(MemoryProviderAuditState {
                snapshot: ProviderAuditSnapshot {
                    revision: 0,
                    provider,
                    log_id,
                    latest_head: None,
                    equivocation: None,
                    records: Vec::new(),
                },
                portable_accounting:
                    crate::provider::interchange::ProviderAuditPortableAccounting::empty(),
            })),
        }
    }

    /// Load the complete current audit snapshot.
    pub fn snapshot(&self) -> Result<ProviderAuditSnapshot, IdentityError> {
        self.load()
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, MemoryProviderAuditState>, IdentityError> {
        self.state
            .lock()
            .map_err(|_| IdentityError::StorageCorruption)
    }
}

impl ProviderAuditStore for MemoryProviderAuditStore {
    fn load(&self) -> Result<ProviderAuditSnapshot, IdentityError> {
        let snapshot = self.lock_state()?.snapshot.clone();
        snapshot.validate()?;
        Ok(snapshot)
    }

    fn load_cursor(&self) -> Result<ProviderAuditCursor, IdentityError> {
        Ok(ProviderAuditCursor::from_trusted_snapshot(
            &self.lock_state()?.snapshot,
        ))
    }

    fn compare_and_append(
        &self,
        expected_revision: u64,
        append: ProviderAuditAppend,
    ) -> Result<(), IdentityError> {
        let mut retained = self.lock_state()?;
        if retained.snapshot.revision != expected_revision {
            return Err(IdentityError::StaleRevision);
        }
        validate_audit_successor(&retained.snapshot, &append)?;
        let next_accounting = retained
            .portable_accounting
            .with_appended_record(&append.record)?;
        apply_audit_append(&mut retained.snapshot, append);
        retained.portable_accounting = next_accounting;
        Ok(())
    }
}

fn validate_audit_successor(
    retained: &ProviderAuditSnapshot,
    append: &ProviderAuditAppend,
) -> Result<(), IdentityError> {
    if retained.equivocation.is_some() {
        return Err(IdentityError::ProviderEquivocation);
    }
    let expected_sequence =
        retained
            .revision
            .checked_add(1)
            .ok_or(IdentityError::ArithmeticOverflow {
                resource: "provider audit successor sequence",
            })?;
    if append.record.sequence != expected_sequence
        || append.record.head.body().log_id() != retained.log_id
    {
        return Err(IdentityError::StorageCorruption);
    }
    let mut auditor = ProviderHeadAuditor::new(retained.provider.clone(), retained.log_id);
    if let Some(latest) = &retained.latest_head
        && auditor.observe(latest.clone(), None)? != ProviderHeadAuditDisposition::FirstObserved
    {
        return Err(IdentityError::StorageCorruption);
    }
    let actual = auditor.observe(
        append.record.head.clone(),
        append.record.consistency_proof.as_ref(),
    );
    let status_matches = match (append.record.status, actual) {
        (ProviderAuditStatus::Accepted(expected), Ok(actual)) => expected == actual,
        (ProviderAuditStatus::Rollback, Err(IdentityError::ProviderRollback))
        | (ProviderAuditStatus::Equivocation, Err(IdentityError::ProviderEquivocation)) => true,
        _ => false,
    };
    if !status_matches
        || auditor.latest_head() != append.latest_head.as_ref()
        || auditor.equivocation_evidence() != append.equivocation.as_ref()
    {
        return Err(IdentityError::StorageCorruption);
    }
    Ok(())
}

fn apply_audit_append(snapshot: &mut ProviderAuditSnapshot, append: ProviderAuditAppend) {
    snapshot.revision = append.record.sequence;
    snapshot.records.push(append.record);
    snapshot.latest_head = append.latest_head;
    snapshot.equivocation = append.equivocation;
}

/// Generation-scoped auditor that persists accepted heads and authenticated attacks before return.
#[derive(Debug, Clone)]
pub struct DurableProviderAuditor<S> {
    store: S,
}

impl<S: ProviderAuditStore> DurableProviderAuditor<S> {
    /// Attach the auditor state machine to an atomic persistence implementation.
    pub const fn new(store: S) -> Self {
        Self { store }
    }

    /// Verify and durably retain one observation without trusting the observed provider.
    pub fn observe(
        &self,
        head: SignedProviderHead,
        consistency_proof: Option<&MerkleConsistencyProof>,
    ) -> Result<ProviderHeadAuditDisposition, IdentityError> {
        for _ in 0..=MAX_RETRIES {
            let cursor = self.store.load_cursor()?;
            if cursor.equivocation.is_some() {
                return Err(IdentityError::ProviderEquivocation);
            }
            let mut auditor = ProviderHeadAuditor::new(cursor.provider.clone(), cursor.log_id);
            if let Some(latest) = &cursor.latest_head {
                let seeded = auditor.observe(latest.clone(), None)?;
                if seeded != ProviderHeadAuditDisposition::FirstObserved {
                    return Err(IdentityError::StorageCorruption);
                }
            }
            let result = auditor.observe(head.clone(), consistency_proof);
            let status = match &result {
                Ok(disposition) => ProviderAuditStatus::Accepted(*disposition),
                Err(IdentityError::ProviderRollback) => ProviderAuditStatus::Rollback,
                Err(IdentityError::ProviderEquivocation) => ProviderAuditStatus::Equivocation,
                Err(error) => return Err(error.clone()),
            };
            let retained_records = usize::try_from(cursor.revision).map_err(|_| {
                IdentityError::ArithmeticOverflow {
                    resource: "provider audit retained records",
                }
            })?;
            if retained_records >= MAX_PROVIDER_AUDIT_RECORDS {
                return Err(IdentityError::limit(
                    "provider audit records",
                    retained_records.saturating_add(1),
                    MAX_PROVIDER_AUDIT_RECORDS,
                ));
            }
            let next_revision =
                cursor
                    .revision
                    .checked_add(1)
                    .ok_or(IdentityError::ArithmeticOverflow {
                        resource: "provider audit revision",
                    })?;
            let append = ProviderAuditAppend {
                record: ProviderAuditRecord {
                    sequence: next_revision,
                    head: head.clone(),
                    consistency_proof: consistency_proof.cloned(),
                    status,
                },
                latest_head: auditor.latest_head().cloned(),
                equivocation: auditor.equivocation_evidence().cloned(),
            };
            match self.store.compare_and_append(cursor.revision, append) {
                Ok(()) => return result,
                Err(IdentityError::StaleRevision) => continue,
                Err(error) => return Err(error),
            }
        }
        Err(IdentityError::ResourceBusy)
    }

    /// Load the complete durable journal through the configured persistence boundary.
    pub fn snapshot(&self) -> Result<ProviderAuditSnapshot, IdentityError> {
        self.store.load()
    }
}

#[cfg(test)]
mod tests {
    use krikos_base::SecretKey;

    use super::*;
    use crate::{
        CanonicalWire, Extensions, HashAlgorithm, ProtocolSignature, ProviderHeadBody,
        ProviderKeyVersion, SigningPublicKey, Timestamp,
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
    struct AuditRecordCommitmentMirror<'a> {
        sequence: u64,
        head: &'a SignedProviderHead,
        consistency_proof: Option<&'a MerkleConsistencyProof>,
        status_code: u16,
    }

    #[derive(serde::Serialize)]
    struct AuditSnapshotCommitmentMirror<'a> {
        format_version: u16,
        revision: u64,
        provider: &'a ProviderDescriptor,
        log_id: ProviderLogId,
        latest_head: Option<&'a SignedProviderHead>,
        equivocation: Option<&'a ProviderEquivocationEvidence>,
        records: Vec<AuditRecordCommitmentMirror<'a>>,
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

    #[test]
    fn repeated_memory_audit_appends_encode_only_the_new_record() {
        const OBSERVATION_COUNT: u64 = 257;

        let signer = SecretKey::from_bytes(&[0x21; 32]);
        let provider = ProviderDescriptor::new(
            SigningPublicKey::ed25519(*signer.public().as_bytes()).unwrap(),
            Extensions::default(),
        )
        .unwrap();
        let log_id = typed_id::<ProviderLogId>(0x22);
        let store = MemoryProviderAuditStore::new(provider.clone(), log_id);
        let auditor = DurableProviderAuditor::new(store);
        crate::provider::interchange::reset_portable_audit_record_encoding_count();

        for index in 0..OBSERVATION_COUNT {
            auditor
                .observe(
                    signed_head(&provider, log_id, 0x23, index + 1, &signer),
                    None,
                )
                .unwrap();
        }

        assert_eq!(
            crate::provider::interchange::portable_audit_record_encoding_count(),
            usize::try_from(OBSERVATION_COUNT).unwrap(),
            "each audit append must encode only its new record"
        );
    }

    #[test]
    fn provider_audit_commitments_use_versioned_canonical_preimages() {
        let signer = SecretKey::from_bytes(&[0x31; 32]);
        let provider = ProviderDescriptor::new(
            SigningPublicKey::ed25519(*signer.public().as_bytes()).unwrap(),
            Extensions::default(),
        )
        .unwrap();
        let log_id = typed_id::<ProviderLogId>(0x32);
        let accepted = signed_head(&provider, log_id, 0x33, 100, &signer);
        let conflict = signed_head(&provider, log_id, 0x34, 101, &signer);
        let store = MemoryProviderAuditStore::new(provider.clone(), log_id);
        let auditor = DurableProviderAuditor::new(store.clone());
        assert_eq!(
            auditor.observe(accepted.clone(), None),
            Ok(ProviderHeadAuditDisposition::FirstObserved)
        );
        assert_eq!(
            auditor.observe(conflict.clone(), None),
            Err(IdentityError::ProviderEquivocation)
        );

        let snapshot = store.snapshot().unwrap();
        let artifacts = snapshot.artifacts().unwrap();
        let artifact = artifacts.first().unwrap();
        assert_eq!(artifact.kind(), ProviderAuditArtifactKind::Equivocation);
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
        assert_eq!(artifact.commitment().unwrap(), expected_artifact);

        let records = snapshot.records();
        assert_eq!(records.len(), 2);
        let expected_snapshot = raw_commitment(
            b"KRIKOS-ID/provider-audit-snapshot/v1",
            &AuditSnapshotCommitmentMirror {
                format_version: 1,
                revision: snapshot.revision(),
                provider: snapshot.provider(),
                log_id: snapshot.log_id(),
                latest_head: snapshot.latest_head(),
                equivocation: snapshot.equivocation_evidence(),
                records: vec![
                    AuditRecordCommitmentMirror {
                        sequence: records[0].sequence(),
                        head: records[0].head(),
                        consistency_proof: records[0].consistency_proof(),
                        status_code: 1,
                    },
                    AuditRecordCommitmentMirror {
                        sequence: records[1].sequence(),
                        head: records[1].head(),
                        consistency_proof: records[1].consistency_proof(),
                        status_code: 6,
                    },
                ],
            },
        );
        assert_eq!(snapshot.commitment().unwrap(), expected_snapshot);
    }
}
