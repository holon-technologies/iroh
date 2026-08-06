//! Bounded in-memory provider-log generation and proof serving.

use crate::{
    AccountId, Extensions, IdentityError, InclusionReceipt, ProtocolSignature, ProviderDescriptor,
    ProviderEquivocationEvidence, ProviderHeadBody, ProviderKeyVersion, ProviderLogEntryBody,
    ProviderLogId, ProviderLogSubject, SignedProviderHead, Timestamp,
    limits::{MAX_HISTORY_PAGE_EVENTS, MAX_MERKLE_LOG_LEAVES, MAX_PROVIDER_ACCOUNT_RESPONSE_BYTES},
    merkle::{AppendOnlyMerkleLog, MerkleConsistencyProof},
};
use serde::Serialize;

/// Signing boundary used by a provider log without exposing key storage to the log engine.
pub trait ProviderHeadSigner {
    /// Produce a signature for the exact domain-separated message returned by
    /// [`ProviderHeadBody::signing_bytes`].
    ///
    /// Implementations must not publish the signature or a signed head as an
    /// externally visible provider observation. The store durably records and
    /// verifies the signed candidate before it promotes or exposes it.
    fn sign_provider_head(&self, message: &[u8]) -> Result<ProtocolSignature, IdentityError>;
}

/// Accepted observation class produced by a provider-log auditor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderHeadAuditDisposition {
    /// First authenticated head accepted as this auditor's explicit generation anchor.
    FirstObserved,
    /// A larger tree was verified append-only from the retained head.
    TreeAdvanced,
    /// The same tree was signed again at a later provider observation time.
    HeadRefreshed,
    /// The exact authenticated head was already retained.
    Replay,
}

/// Stateful single-generation auditor that rejects rollback and durably retains equivocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderHeadAuditor {
    provider: ProviderDescriptor,
    log_id: ProviderLogId,
    latest: Option<SignedProviderHead>,
    equivocation: Option<ProviderEquivocationEvidence>,
}

impl ProviderHeadAuditor {
    /// Start auditing one explicitly selected provider/log generation boundary.
    pub const fn new(provider: ProviderDescriptor, log_id: ProviderLogId) -> Self {
        Self {
            provider,
            log_id,
            latest: None,
            equivocation: None,
        }
    }

    /// Provider descriptor whose exact key authenticates this audit stream.
    pub const fn provider(&self) -> &ProviderDescriptor {
        &self.provider
    }

    /// Explicit log generation; changing it requires construction of a new auditor.
    pub const fn log_id(&self) -> ProviderLogId {
        self.log_id
    }

    /// Latest accepted authenticated head, if any.
    pub const fn latest_head(&self) -> Option<&SignedProviderHead> {
        self.latest.as_ref()
    }

    /// First retained same-size/different-root proof, after which this auditor fails closed.
    pub const fn equivocation_evidence(&self) -> Option<&ProviderEquivocationEvidence> {
        self.equivocation.as_ref()
    }

    /// Verify and retain one signed head without crossing an implicit key or log rotation.
    pub fn observe(
        &mut self,
        head: SignedProviderHead,
        consistency_proof: Option<&MerkleConsistencyProof>,
    ) -> Result<ProviderHeadAuditDisposition, IdentityError> {
        if self.equivocation.is_some() {
            return Err(IdentityError::ProviderEquivocation);
        }
        head.verify(&self.provider)?;
        if head.body().log_id() != self.log_id {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider auditor log generation",
            });
        }
        let Some(previous) = self.latest.as_ref() else {
            self.latest = Some(head);
            return Ok(ProviderHeadAuditDisposition::FirstObserved);
        };
        if head == *previous {
            return Ok(ProviderHeadAuditDisposition::Replay);
        }
        if head.body().tree_size() == previous.body().tree_size()
            && head.body().tree_root() != previous.body().tree_root()
        {
            self.equivocation = Some(ProviderEquivocationEvidence::new(
                &self.provider,
                previous.clone(),
                head,
            )?);
            return Err(IdentityError::ProviderEquivocation);
        }
        if head.body().tree_size() < previous.body().tree_size()
            || head.body().observed_at() < previous.body().observed_at()
        {
            return Err(IdentityError::ProviderRollback);
        }
        if head.body().tree_size() == previous.body().tree_size() {
            if let Some(proof) = consistency_proof {
                crate::verify_provider_head_progression(&self.provider, previous, &head, proof)?;
            }
            self.latest = Some(head);
            return Ok(ProviderHeadAuditDisposition::HeadRefreshed);
        }
        crate::verify_provider_head_progression(
            &self.provider,
            previous,
            &head,
            consistency_proof.ok_or(IdentityError::InvalidProof)?,
        )?;
        self.latest = Some(head);
        Ok(ProviderHeadAuditDisposition::TreeAdvanced)
    }
}

/// Opaque proof that an account checkpoint or proposal intent passed provider admission.
///
/// Constructors remain crate-private: checkpoint and intent verification create this token only
/// after evaluating the applicable authenticated account pre-state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderLogAdmission {
    account_id: AccountId,
    subject: ProviderLogSubject,
    required_observed_at: Option<Timestamp>,
    checkpoint_bundle: Option<crate::ProviderCheckpointBundle>,
}

impl ProviderLogAdmission {
    pub(crate) fn checkpoint(bundle: crate::ProviderCheckpointBundle) -> Self {
        let checkpoint = bundle.verified_checkpoint();
        Self {
            account_id: checkpoint.checkpoint().body().account_id(),
            subject: ProviderLogSubject::Checkpoint(checkpoint.checkpoint_id()),
            required_observed_at: None,
            checkpoint_bundle: Some(bundle),
        }
    }

    pub(crate) const fn event_intent(
        account_id: AccountId,
        proposal_id: crate::ProposalId,
    ) -> Self {
        Self {
            account_id,
            subject: ProviderLogSubject::EventIntent(proposal_id),
            required_observed_at: None,
            checkpoint_bundle: None,
        }
    }

    pub(crate) const fn guardian_recovery_intent(
        account_id: AccountId,
        proposal_id: crate::ProposalId,
        observed_at: Timestamp,
    ) -> Self {
        Self {
            account_id,
            subject: ProviderLogSubject::EventIntent(proposal_id),
            required_observed_at: Some(observed_at),
            checkpoint_bundle: None,
        }
    }

    pub(crate) fn validate_observed_at(&self, observed_at: Timestamp) -> Result<(), IdentityError> {
        if self
            .required_observed_at
            .is_some_and(|required| required != observed_at)
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider admission observation time",
            });
        }
        Ok(())
    }

    pub(crate) const fn checkpoint_bundle(&self) -> Option<&crate::ProviderCheckpointBundle> {
        self.checkpoint_bundle.as_ref()
    }

    /// Account whose verified object may be appended.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Exact checkpoint or threshold-approved proposal intent admitted by the verifier.
    pub const fn subject(&self) -> ProviderLogSubject {
        self.subject
    }
}

/// Verify a delayed proposal intent under its exact authenticated pre-state.
///
/// The returned opaque token is the only public route for appending an event-intent leaf. It binds
/// the next sequence, complete predecessor set, resulting epoch, proposal ID, applicable delayed
/// rule, controller scopes, cryptographic signatures, and the applicable control or recovery
/// threshold before any provider observation can start the delay.
pub fn verify_event_intent_admission(
    pre_state: &crate::AccountState,
    body: &crate::EventBody,
    approvals: &crate::EventIntentApprovals,
) -> Result<ProviderLogAdmission, IdentityError> {
    let verified = crate::verifier::verify_event_intent(pre_state, body, approvals)?;
    Ok(ProviderLogAdmission::event_intent(
        verified.account_id(),
        verified.proposal_id(),
    ))
}

/// Verify guardian recovery authority at one exact provider observation time.
///
/// Unlike controller intent admission, guardian authority is embedded in the recovery body and no
/// unrelated controller-intent approval set is accepted. The returned one-shot capability is bound
/// to `observed_at`; provider append rejects any substituted observation time before mutation. The
/// eventual account event still requires quorum receipts and re-verifies guardian validity at the
/// authenticated quorum authority time.
pub fn verify_guardian_recovery_intent_admission(
    pre_state: &crate::AccountState,
    body: &crate::EventBody,
    observed_at: Timestamp,
) -> Result<ProviderLogAdmission, IdentityError> {
    let verified = crate::verifier::verify_guardian_recovery_intent(pre_state, body, observed_at)?;
    Ok(ProviderLogAdmission::guardian_recovery_intent(
        verified.account_id(),
        verified.proposal_id(),
        observed_at,
    ))
}

/// One provider-wide append index and its canonical entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderHistoryRecord {
    leaf_index: u64,
    entry: ProviderLogEntryBody,
}

impl ProviderHistoryRecord {
    /// Provider-wide zero-based append index.
    pub const fn leaf_index(&self) -> u64 {
        self.leaf_index
    }

    /// Canonical provider-log entry at this index.
    pub const fn entry(&self) -> &ProviderLogEntryBody {
        &self.entry
    }
}

/// Bounded account-filtered page from one provider-wide log generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderHistoryPage {
    records: Vec<ProviderHistoryRecord>,
    next_cursor: Option<u64>,
}

impl ProviderHistoryPage {
    /// Matching records in provider append order.
    pub fn records(&self) -> &[ProviderHistoryRecord] {
        &self.records
    }

    /// Exclusive provider-wide cursor to supply on the next request, if more log data remains.
    pub const fn next_cursor(&self) -> Option<u64> {
        self.next_cursor
    }
}

/// Atomic bounded provider-wide append-only generation suitable for deterministic tests and local use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryTransparencyLog {
    provider: ProviderDescriptor,
    log_id: ProviderLogId,
    entries: Vec<ProviderLogEntryBody>,
    checkpoint_bundles: Vec<crate::ProviderCheckpointBundle>,
    tree: AppendOnlyMerkleLog,
    latest_head: Option<SignedProviderHead>,
}

impl MemoryTransparencyLog {
    /// Construct an empty provider-wide generation for one exact descriptor and log ID.
    pub const fn new(provider: ProviderDescriptor, log_id: ProviderLogId) -> Self {
        Self {
            provider,
            log_id,
            entries: Vec::new(),
            checkpoint_bundles: Vec::new(),
            tree: AppendOnlyMerkleLog::new(),
            latest_head: None,
        }
    }

    /// Configured provider descriptor whose key authenticates every head.
    pub const fn provider(&self) -> &ProviderDescriptor {
        &self.provider
    }

    /// Versioned provider-wide log generation.
    pub const fn log_id(&self) -> ProviderLogId {
        self.log_id
    }

    /// Current tree size.
    pub fn tree_size(&self) -> Result<u64, IdentityError> {
        self.tree.tree_size()
    }

    /// Current Merkle root, including the distinct empty-tree domain.
    pub fn tree_root(&self) -> Result<crate::Digest, IdentityError> {
        self.tree.root()
    }

    /// Most recently signed head, if this generation has emitted one.
    pub const fn latest_head(&self) -> Option<&SignedProviderHead> {
        self.latest_head.as_ref()
    }

    /// Serve the unique current retained checkpoint bundle under reverified fork semantics.
    pub fn latest_checkpoint_bundle(
        &self,
        account_id: AccountId,
    ) -> Result<Option<&crate::ProviderCheckpointBundle>, IdentityError> {
        crate::provider::current_checkpoint_bundle(
            &self.entries,
            &self.checkpoint_bundles,
            account_id,
        )
    }

    /// Atomically append one already-verified admission and return exact inclusion evidence.
    ///
    /// Repeating an admitted `(account, subject)` does not append another leaf. It returns a fresh
    /// receipt under the current tree head, preserving idempotency across publication retries.
    pub fn append<S: ProviderHeadSigner + ?Sized>(
        &mut self,
        admission: ProviderLogAdmission,
        observed_at: Timestamp,
        signer: &S,
    ) -> Result<InclusionReceipt, IdentityError> {
        admission.validate_observed_at(observed_at)?;
        let checkpoint_bundle = admission.checkpoint_bundle().cloned();
        if let Some(index) = self.entries.iter().position(|entry| {
            entry.account_id() == admission.account_id() && entry.subject() == admission.subject()
        }) {
            self.validate_duplicate_bundle(index, checkpoint_bundle.as_ref())?;
            let index = u64::try_from(index).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "provider log duplicate index",
            })?;
            return self.observe(index, observed_at, signer);
        }
        if self.entries.len() == MAX_MERKLE_LOG_LEAVES {
            return Err(IdentityError::limit(
                "provider log entries",
                self.entries.len().saturating_add(1),
                MAX_MERKLE_LOG_LEAVES,
            ));
        }
        self.validate_observation_time(observed_at)?;
        if let Some(bundle) = checkpoint_bundle.as_ref() {
            self.validate_checkpoint_bundle(bundle)?;
        }
        let entry = ProviderLogEntryBody::new(
            self.provider.id()?,
            self.log_id,
            admission.account_id(),
            admission.subject(),
            observed_at,
            Extensions::default(),
        )?;
        let mut staged_entries = self.entries.clone();
        staged_entries.push(entry.clone());
        let mut staged_checkpoint_bundles = self.checkpoint_bundles.clone();
        if let Some(bundle) = checkpoint_bundle {
            staged_checkpoint_bundles.push(bundle);
        }
        crate::provider::rebuild_checkpoint_index(&staged_entries, &staged_checkpoint_bundles)?;
        let mut staged_tree = self.tree.clone();
        let leaf_index = staged_tree.append(entry.merkle_leaf_hash()?)?;
        let signed_head = self.sign_head(&staged_tree, observed_at, signer)?;
        let receipt = InclusionReceipt::new(
            entry.clone(),
            leaf_index,
            staged_tree
                .inclusion_proof(leaf_index)?
                .audit_path()
                .to_vec(),
            signed_head.clone(),
        )?;
        receipt.verify(&self.provider)?;

        self.entries = staged_entries;
        self.checkpoint_bundles = staged_checkpoint_bundles;
        self.tree = staged_tree;
        self.latest_head = Some(signed_head);
        Ok(receipt)
    }

    /// Issue a later authenticated receipt for an existing leaf without appending.
    pub fn observe<S: ProviderHeadSigner + ?Sized>(
        &mut self,
        leaf_index: u64,
        observed_at: Timestamp,
        signer: &S,
    ) -> Result<InclusionReceipt, IdentityError> {
        self.validate_observation_time(observed_at)?;
        let index = usize::try_from(leaf_index).map_err(|_| IdentityError::ArithmeticOverflow {
            resource: "provider log observation index",
        })?;
        let entry = self
            .entries
            .get(index)
            .cloned()
            .ok_or(IdentityError::InvalidProof)?;
        let signed_head = self.sign_head(&self.tree, observed_at, signer)?;
        let proof = self.tree.inclusion_proof(leaf_index)?;
        let receipt = InclusionReceipt::new(
            entry,
            leaf_index,
            proof.audit_path().to_vec(),
            signed_head.clone(),
        )?;
        receipt.verify(&self.provider)?;
        self.latest_head = Some(signed_head);
        Ok(receipt)
    }

    /// Serve an exact append-only proof from an earlier prefix to the current tree.
    pub fn consistency_proof(
        &self,
        old_size: u64,
    ) -> Result<MerkleConsistencyProof, IdentityError> {
        self.tree.consistency_proof(old_size)
    }

    /// Return a bounded account-filtered page while retaining a provider-wide resume cursor.
    pub fn account_history(
        &self,
        account_id: AccountId,
        after_cursor: Option<u64>,
        maximum_records: usize,
        maximum_bytes: usize,
    ) -> Result<ProviderHistoryPage, IdentityError> {
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
        let start = match after_cursor {
            None => 0_usize,
            Some(cursor) => usize::try_from(cursor)
                .map_err(|_| IdentityError::ArithmeticOverflow {
                    resource: "provider account-history cursor",
                })?
                .checked_add(1)
                .ok_or(IdentityError::ArithmeticOverflow {
                    resource: "provider account-history cursor",
                })?,
        };
        if start > self.entries.len() {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider account-history cursor",
            });
        }

        let mut records = Vec::new();
        let mut cursor = after_cursor;
        let mut exhausted = true;
        for (index, entry) in self.entries.iter().enumerate().skip(start) {
            if entry.account_id() == account_id {
                if records.len() == maximum_records {
                    exhausted = false;
                    break;
                }
                let leaf_index =
                    u64::try_from(index).map_err(|_| IdentityError::ArithmeticOverflow {
                        resource: "provider account-history leaf index",
                    })?;
                records.push(ProviderHistoryRecord {
                    leaf_index,
                    entry: entry.clone(),
                });
                // Include the leaf index, vector framing, and the larger `Some(cursor)`
                // continuation shape in the exact page-size decision.
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
        let next_cursor = if exhausted { None } else { cursor };
        Ok(ProviderHistoryPage {
            records,
            next_cursor,
        })
    }

    fn sign_head<S: ProviderHeadSigner + ?Sized>(
        &self,
        tree: &AppendOnlyMerkleLog,
        observed_at: Timestamp,
        signer: &S,
    ) -> Result<SignedProviderHead, IdentityError> {
        let body = ProviderHeadBody::new(
            self.provider.id()?,
            self.log_id,
            ProviderKeyVersion::GENESIS,
            tree.tree_size()?,
            tree.root()?,
            observed_at,
            Extensions::default(),
        )?;
        let signature = signer.sign_provider_head(&body.signing_bytes()?)?;
        let signed = SignedProviderHead::new(body, signature);
        signed.verify(&self.provider)?;
        Ok(signed)
    }

    fn validate_observation_time(&self, observed_at: Timestamp) -> Result<(), IdentityError> {
        if self
            .latest_head
            .as_ref()
            .is_some_and(|head| observed_at < head.body().observed_at())
        {
            return Err(IdentityError::ProviderRollback);
        }
        Ok(())
    }

    fn validate_checkpoint_bundle(
        &self,
        bundle: &crate::ProviderCheckpointBundle,
    ) -> Result<(), IdentityError> {
        let checkpoint = bundle.verified_checkpoint();
        let body = checkpoint.checkpoint().body();
        if let Some(prior_checkpoint_id) = bundle.prior_checkpoint_id() {
            let prior_retained = self.checkpoint_bundles.iter().any(|candidate| {
                let candidate_checkpoint = candidate.verified_checkpoint();
                candidate_checkpoint.checkpoint().body().account_id() == body.account_id()
                    && candidate_checkpoint.checkpoint_id() == prior_checkpoint_id
            });
            if !prior_retained {
                return Err(IdentityError::InvalidProof);
            }
        }

        let mut greatest_sequence: Option<crate::Sequence> = None;
        let mut greatest_epoch: Option<crate::Epoch> = None;
        for retained in &self.checkpoint_bundles {
            let retained_body = retained.verified_checkpoint().checkpoint().body();
            if retained_body.account_id() != body.account_id() {
                continue;
            }
            greatest_sequence = Some(
                greatest_sequence.map_or(retained_body.sequence(), |sequence| {
                    sequence.max(retained_body.sequence())
                }),
            );
            greatest_epoch = Some(
                greatest_epoch.map_or(retained_body.account_epoch(), |epoch| {
                    epoch.max(retained_body.account_epoch())
                }),
            );
        }
        if greatest_sequence.is_some_and(|sequence| body.sequence() < sequence)
            || greatest_epoch.is_some_and(|epoch| body.account_epoch() < epoch)
        {
            return Err(IdentityError::ProviderRollback);
        }
        Ok(())
    }

    fn validate_duplicate_bundle(
        &self,
        entry_index: usize,
        candidate: Option<&crate::ProviderCheckpointBundle>,
    ) -> Result<(), IdentityError> {
        let entry = self
            .entries
            .get(entry_index)
            .ok_or(IdentityError::StorageCorruption)?;
        match (entry.subject(), candidate) {
            (ProviderLogSubject::Checkpoint(checkpoint_id), Some(candidate)) => {
                let retained = self
                    .checkpoint_bundles
                    .iter()
                    .find(|bundle| {
                        let checkpoint = bundle.verified_checkpoint();
                        checkpoint.checkpoint().body().account_id() == entry.account_id()
                            && checkpoint.checkpoint_id() == checkpoint_id
                    })
                    .ok_or(IdentityError::StorageCorruption)?;
                if retained != candidate {
                    return Err(IdentityError::InvalidProof);
                }
                Ok(())
            }
            (ProviderLogSubject::Checkpoint(_), None)
            | (ProviderLogSubject::EventIntent(_), Some(_)) => {
                Err(IdentityError::InvalidRelationship {
                    resource: "provider duplicate admission material",
                })
            }
            (ProviderLogSubject::EventIntent(_), None) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use krikos_base::SecretKey;

    use super::*;
    use crate::{
        CanonicalWire, Digest, HashAlgorithm, ProviderId, SigningPublicKey,
        verify_provider_head_progression,
    };

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

    fn fixture() -> (MemoryTransparencyLog, Signer) {
        let signer = Signer(SecretKey::from_bytes(&[0x61; 32]));
        let provider = ProviderDescriptor::new(
            SigningPublicKey::ed25519(*signer.0.public().as_bytes()).unwrap(),
            Extensions::default(),
        )
        .unwrap();
        (
            MemoryTransparencyLog::new(provider, typed_id::<ProviderLogId>(0x62)),
            signer,
        )
    }

    #[test]
    fn append_observe_and_consistency_are_atomic_and_authenticated() {
        let (mut log, signer) = fixture();
        let first = ProviderLogAdmission::event_intent(
            typed_id::<AccountId>(0x63),
            typed_id::<crate::ProposalId>(0x64),
        );
        let first_receipt = log
            .append(first.clone(), Timestamp::from_unix_millis(10), &signer)
            .unwrap();
        let first_head = first_receipt.signed_head().clone();
        let second = ProviderLogAdmission::event_intent(
            typed_id::<AccountId>(0x65),
            typed_id::<crate::ProposalId>(0x66),
        );
        log.append(second, Timestamp::from_unix_millis(11), &signer)
            .unwrap();
        let observed = log
            .observe(0, Timestamp::from_unix_millis(12), &signer)
            .unwrap();
        verify_provider_head_progression(
            log.provider(),
            &first_head,
            observed.signed_head(),
            &log.consistency_proof(1).unwrap(),
        )
        .unwrap();
        assert_eq!(log.tree_size().unwrap(), 2);
        assert_eq!(observed.entry(), first_receipt.entry());

        let replay = log
            .append(first, Timestamp::from_unix_millis(13), &signer)
            .unwrap();
        assert_eq!(log.tree_size().unwrap(), 2);
        assert_eq!(replay.leaf_index(), 0);
        let before = log.clone();
        assert_eq!(
            log.observe(0, Timestamp::from_unix_millis(9), &signer),
            Err(IdentityError::ProviderRollback)
        );
        assert_eq!(log, before);
    }

    #[test]
    fn invalid_signer_and_bounded_history_fail_without_partial_append() {
        let (mut log, signer) = fixture();
        let account = typed_id::<AccountId>(0x67);
        let admission =
            ProviderLogAdmission::event_intent(account, typed_id::<crate::ProposalId>(0x68));
        let wrong = Signer(SecretKey::from_bytes(&[0x69; 32]));
        let before = log.clone();
        assert_eq!(
            log.append(admission.clone(), Timestamp::from_unix_millis(10), &wrong),
            Err(IdentityError::InvalidSignature)
        );
        assert_eq!(log, before);

        log.append(admission.clone(), Timestamp::from_unix_millis(10), &signer)
            .unwrap();
        log.append(
            ProviderLogAdmission::event_intent(account, typed_id::<crate::ProposalId>(0x6a)),
            Timestamp::from_unix_millis(11),
            &signer,
        )
        .unwrap();
        let page = log
            .account_history(account, None, 1, MAX_PROVIDER_ACCOUNT_RESPONSE_BYTES)
            .unwrap();
        assert_eq!(page.records().len(), 1);
        assert!(page.next_cursor().is_some());
        let second_page = log
            .account_history(
                account,
                page.next_cursor(),
                1,
                MAX_PROVIDER_ACCOUNT_RESPONSE_BYTES,
            )
            .unwrap();
        assert_eq!(second_page.records().len(), 1);
        assert_eq!(second_page.next_cursor(), None);
        let _: ProviderId = log.provider().id().unwrap();
    }
}
