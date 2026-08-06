//! Monotonic local publication-state tracking for provider-replicated checkpoints.

use std::task::Poll;

use crate::{
    AccountId, CheckpointId, IdentityError, InclusionReceipt, ProviderCheckpointBundle,
    ProviderDescriptor, ProviderId, ProviderLogId, ProviderLogSubject, ProviderMode,
    ProviderPolicy, ProviderPolicyId, ProviderQuorum, StoreFuture, VerifiedCheckpoint,
    limits::{
        MAX_HISTORY_PAGE_EVENTS, MAX_PROVIDER_ACCOUNT_RESPONSE_BYTES, MAX_TRANSPARENCY_PROVIDERS,
    },
    merkle::MerkleConsistencyProof,
    verify_provider_head_progression,
};

/// Provider-served checkpoint authority material paired with its authenticated log inclusion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedCheckpoint {
    bundle: ProviderCheckpointBundle,
    receipt: InclusionReceipt,
}

impl PublishedCheckpoint {
    /// Verify a provider receipt and bind it to the exact retained lineage checkpoint leaf.
    pub fn new(
        bundle: ProviderCheckpointBundle,
        receipt: InclusionReceipt,
        provider: &ProviderDescriptor,
    ) -> Result<Self, IdentityError> {
        let checkpoint = Self { bundle, receipt };
        checkpoint.validate_for_provider(provider)?;
        Ok(checkpoint)
    }

    fn validate_for_provider(&self, provider: &ProviderDescriptor) -> Result<(), IdentityError> {
        let checkpoint = self.bundle.verified_checkpoint();
        let body = checkpoint.checkpoint().body();
        if self.receipt.entry().account_id() != body.account_id()
            || self.receipt.entry().subject()
                != ProviderLogSubject::Checkpoint(checkpoint.checkpoint_id())
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "published checkpoint receipt subject",
            });
        }
        self.receipt.verify(provider)
    }

    /// Complete bounded authority lineage needed to replay and verify the checkpoint.
    pub const fn bundle(&self) -> &ProviderCheckpointBundle {
        &self.bundle
    }

    /// Authenticated provider-log inclusion for the exact bundled checkpoint ID.
    pub const fn receipt(&self) -> &InclusionReceipt {
        &self.receipt
    }
}

pub(crate) fn encoded_published_checkpoint_bytes(
    checkpoint: &PublishedCheckpoint,
) -> Result<usize, IdentityError> {
    let bundle = checkpoint.bundle();
    let verified = bundle.verified_checkpoint();
    Ok(crate::codec::encode_wire(&(
        bundle.genesis(),
        bundle.prior_checkpoint_id(),
        bundle.events(),
        verified.checkpoint(),
        verified.transition_event(),
        checkpoint.receipt(),
    ))?
    .len())
}

/// One bounded target-to-genesis page of authenticated provider-retained checkpoint lineage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderCheckpointLineagePage {
    checkpoints: Vec<PublishedCheckpoint>,
    next_prior_checkpoint_id: Option<CheckpointId>,
}

impl ProviderCheckpointLineagePage {
    /// Construct and authenticate one exact retained lineage page.
    pub fn new(
        account_id: AccountId,
        start_checkpoint_id: CheckpointId,
        checkpoints: Vec<PublishedCheckpoint>,
        next_prior_checkpoint_id: Option<CheckpointId>,
        provider: &ProviderDescriptor,
        log_id: ProviderLogId,
    ) -> Result<Self, IdentityError> {
        if checkpoints.len() > MAX_HISTORY_PAGE_EVENTS {
            return Err(IdentityError::limit(
                "provider checkpoint lineage records",
                checkpoints.len(),
                MAX_HISTORY_PAGE_EVENTS,
            ));
        }
        let first = checkpoints
            .first()
            .ok_or(IdentityError::InvalidRelationship {
                resource: "provider checkpoint lineage page",
            })?;
        if first.bundle().verified_checkpoint().checkpoint_id() != start_checkpoint_id {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider checkpoint lineage start",
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut encoded_bytes = 0_usize;
        for checkpoint in &checkpoints {
            let bundle = checkpoint.bundle();
            let verified = bundle.verified_checkpoint();
            let body = verified.checkpoint().body();
            if body.account_id() != account_id
                || checkpoint.receipt().entry().account_id() != account_id
                || checkpoint.receipt().signed_head().body().log_id() != log_id
                || !seen.insert(verified.checkpoint_id())
            {
                return Err(IdentityError::InvalidProof);
            }
            checkpoint.validate_for_provider(provider)?;
            encoded_bytes = encoded_bytes
                .checked_add(encoded_published_checkpoint_bytes(checkpoint)?)
                .ok_or(IdentityError::ArithmeticOverflow {
                    resource: "provider checkpoint lineage bytes",
                })?;
            if encoded_bytes > MAX_PROVIDER_ACCOUNT_RESPONSE_BYTES {
                return Err(IdentityError::limit(
                    "provider checkpoint lineage bytes",
                    encoded_bytes,
                    MAX_PROVIDER_ACCOUNT_RESPONSE_BYTES,
                ));
            }
        }
        for pair in checkpoints.windows(2) {
            if pair[0].bundle().prior_checkpoint_id()
                != Some(pair[1].bundle().verified_checkpoint().checkpoint_id())
            {
                return Err(IdentityError::InvalidProof);
            }
        }
        if checkpoints
            .last()
            .and_then(|checkpoint| checkpoint.bundle().prior_checkpoint_id())
            != next_prior_checkpoint_id
        {
            return Err(IdentityError::InvalidProof);
        }
        Ok(Self {
            checkpoints,
            next_prior_checkpoint_id,
        })
    }

    /// Authenticated checkpoint links in target-to-genesis order.
    pub fn checkpoints(&self) -> &[PublishedCheckpoint] {
        &self.checkpoints
    }

    /// Required prior checkpoint for the next page, or `None` at genesis.
    pub const fn next_prior_checkpoint_id(&self) -> Option<CheckpointId> {
        self.next_prior_checkpoint_id
    }
}

/// Runtime-independent client for one configured transparency provider.
///
/// Implementations own transport deadlines and must preserve timeout, rate-limit, and outage as
/// the distinct [`IdentityError`] variants intended for those conditions.
pub trait TransparencyClient: Send + Sync {
    /// Provider represented by this client.
    fn provider_id(&self) -> ProviderId;

    /// Submit one fully verified checkpoint and its bounded replayable authority lineage.
    fn publish_checkpoint<'a>(
        &'a self,
        checkpoint: &'a ProviderCheckpointBundle,
    ) -> StoreFuture<'a, InclusionReceipt>;

    /// Fetch this provider's latest replayable checkpoint and inclusion for an account.
    fn latest_checkpoint(
        &self,
        account_id: AccountId,
    ) -> StoreFuture<'_, Option<PublishedCheckpoint>>;

    /// Fetch one exact retained checkpoint branch and its authenticated provider inclusion.
    fn fetch_checkpoint_bundle(
        &self,
        account_id: AccountId,
        checkpoint_id: CheckpointId,
    ) -> StoreFuture<'_, Option<PublishedCheckpoint>>;

    /// Fetch one bounded target-to-genesis lineage page starting at an exact retained checkpoint.
    fn fetch_checkpoint_lineage_page(
        &self,
        account_id: AccountId,
        start_checkpoint_id: CheckpointId,
        maximum_records: usize,
        maximum_bytes: usize,
    ) -> StoreFuture<'_, Option<ProviderCheckpointLineagePage>>;

    /// Fetch an exact consistency proof within one explicitly named log generation.
    fn consistency_proof(
        &self,
        log_id: ProviderLogId,
        old_size: u64,
        new_size: u64,
    ) -> StoreFuture<'_, MerkleConsistencyProof>;
}

/// Result of one configured provider's attempt in a concurrent publication batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderPublicationOutcome {
    provider_id: ProviderId,
    result: Result<(), IdentityError>,
}

impl ProviderPublicationOutcome {
    /// Configured provider attempted by this result.
    pub const fn provider_id(&self) -> ProviderId {
        self.provider_id
    }

    /// Success or the exact transport/verification/admission failure class.
    pub const fn result(&self) -> &Result<(), IdentityError> {
        &self.result
    }
}

/// Complete configured-provider result set for one bounded concurrent publication attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationBatch {
    outcomes: Vec<ProviderPublicationOutcome>,
    stage: PublicationStage,
}

impl PublicationBatch {
    /// Outcomes in canonical configured-provider order, including unavailable missing clients.
    pub fn outcomes(&self) -> &[ProviderPublicationOutcome] {
        &self.outcomes
    }

    /// Monotonic publication stage after applying every valid receipt in this batch.
    pub const fn stage(&self) -> PublicationStage {
        self.stage
    }
}

/// Externally meaningful checkpoint publication stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PublicationStage {
    /// A deterministic checkpoint body exists but has not been authorized.
    Draft,
    /// Account authorization has been verified.
    Authorized,
    /// At least one configured provider returned a verified inclusion receipt.
    Published,
    /// The account policy's sufficient distinct-provider threshold was reached.
    Replicated,
    /// A sufficient threshold later re-observed the same inclusions under verified heads.
    Observed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderPublication {
    provider: ProviderDescriptor,
    publication: InclusionReceipt,
    observation: Option<InclusionReceipt>,
}

/// Idempotent, monotonic publication journal for one exact checkpoint and provider policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationTracker {
    account_id: AccountId,
    checkpoint_id: CheckpointId,
    provider_policy_id: ProviderPolicyId,
    policy: ProviderPolicy,
    providers: Vec<ProviderDescriptor>,
    sufficient_threshold: ProviderQuorum,
    preferred_replication: ProviderQuorum,
    authorized: bool,
    publications: Vec<ProviderPublication>,
    journal_publications: Vec<InclusionReceipt>,
    journal_observations: Vec<InclusionReceipt>,
}

impl PublicationTracker {
    /// Create a draft for one exact checkpoint under an authenticated replicated policy.
    pub fn new(
        account_id: AccountId,
        checkpoint_id: CheckpointId,
        provider_policy_id: ProviderPolicyId,
        policy: &ProviderPolicy,
    ) -> Result<Self, IdentityError> {
        if policy.id()? != provider_policy_id {
            return Err(IdentityError::PolicyVersionMismatch);
        }
        let replicated = match policy.mode() {
            ProviderMode::LocalOnly => return Err(IdentityError::FreshnessUnavailable),
            ProviderMode::Replicated(replicated) => replicated,
        };
        Ok(Self {
            account_id,
            checkpoint_id,
            provider_policy_id,
            policy: policy.clone(),
            providers: replicated.providers().to_vec(),
            sufficient_threshold: replicated.sufficient_threshold(),
            preferred_replication: replicated.preferred_replication(),
            authorized: false,
            publications: Vec::new(),
            journal_publications: Vec::new(),
            journal_observations: Vec::new(),
        })
    }

    /// Exact account being published.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Exact checkpoint being published.
    pub const fn checkpoint_id(&self) -> CheckpointId {
        self.checkpoint_id
    }

    /// Authenticated provider-policy revision governing this journal.
    pub const fn provider_policy_id(&self) -> ProviderPolicyId {
        self.provider_policy_id
    }

    /// Exact authenticated provider policy governing every retained receipt and threshold.
    pub const fn provider_policy(&self) -> &ProviderPolicy {
        &self.policy
    }

    /// Exact sorted configured provider descriptors used to authenticate journal receipts.
    pub fn configured_providers(&self) -> &[ProviderDescriptor] {
        &self.providers
    }

    /// Current monotonic externally meaningful stage.
    pub fn stage(&self) -> PublicationStage {
        let observed = self
            .publications
            .iter()
            .filter(|publication| publication.observation.is_some())
            .count();
        if observed >= usize::from(self.sufficient_threshold.get()) {
            return PublicationStage::Observed;
        }
        if self.publications.len() >= usize::from(self.sufficient_threshold.get()) {
            return PublicationStage::Replicated;
        }
        if !self.publications.is_empty() {
            return PublicationStage::Published;
        }
        if self.authorized {
            PublicationStage::Authorized
        } else {
            PublicationStage::Draft
        }
    }

    /// Record verification of the exact checkpoint and governing provider policy.
    ///
    /// Repeating this with the same verified checkpoint is idempotent. Callers cannot advance a
    /// draft by merely asserting that some unrelated checkpoint was authorized.
    pub fn mark_authorized(
        &mut self,
        checkpoint: &VerifiedCheckpoint,
    ) -> Result<(), IdentityError> {
        let body = checkpoint.checkpoint().body();
        if body.account_id() != self.account_id
            || checkpoint.checkpoint_id() != self.checkpoint_id
            || body.provider_policy_id() != self.provider_policy_id
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "publication checkpoint authorization",
            });
        }
        self.authorized = true;
        Ok(())
    }

    /// Count distinct configured providers with verified publication receipts.
    pub const fn published_provider_count(&self) -> usize {
        self.publications.len()
    }

    /// Exact sorted publication receipts retained for durable audit-journal reconciliation.
    pub fn publication_receipts(&self) -> &[InclusionReceipt] {
        &self.journal_publications
    }

    /// Exact sorted later-observation receipts retained for durable audit-journal reconciliation.
    pub fn observation_receipts(&self) -> &[InclusionReceipt] {
        &self.journal_observations
    }

    /// Whether the policy's preferred (possibly stricter) replication count was reached.
    pub fn preferred_replication_reached(&self) -> bool {
        self.publications.len() >= usize::from(self.preferred_replication.get())
    }

    /// Record one verified configured-provider inclusion, deduplicated by provider ID.
    pub fn record_publication(&mut self, receipt: InclusionReceipt) -> Result<(), IdentityError> {
        if !self.authorized {
            return Err(IdentityError::InvalidRelationship {
                resource: "publication receipt before account authorization",
            });
        }
        let provider = self.validate_receipt(&receipt)?.clone();
        let provider_id = receipt.provider_id();
        match self.publication_index(provider_id)? {
            Ok(index) => {
                let retained = &self.publications[index].publication;
                if retained == &receipt {
                    return Ok(());
                }
                if retained.entry().log_id() == receipt.entry().log_id()
                    && retained.signed_head().body().tree_size()
                        == receipt.signed_head().body().tree_size()
                    && retained.signed_head().body().tree_root()
                        != receipt.signed_head().body().tree_root()
                {
                    return Err(IdentityError::ProviderEquivocation);
                }
                // A retry may append the same checkpoint again. It is valid availability
                // evidence but must not create another provider vote or replace the stable
                // publication baseline used for later observation.
                Ok(())
            }
            Err(index) => {
                self.journal_publications.insert(index, receipt.clone());
                self.publications.insert(
                    index,
                    ProviderPublication {
                        provider,
                        publication: receipt,
                        observation: None,
                    },
                );
                Ok(())
            }
        }
    }

    /// Record a later verified head that still includes the exact originally published leaf.
    pub fn record_observation(
        &mut self,
        receipt: InclusionReceipt,
        consistency_proof: &MerkleConsistencyProof,
    ) -> Result<(), IdentityError> {
        let provider = self.validate_receipt(&receipt)?.clone();
        let index = self
            .publication_index(receipt.provider_id())?
            .map_err(|_| IdentityError::InvalidRelationship {
                resource: "checkpoint observation before provider publication",
            })?;
        let publication = &self.publications[index].publication;
        if receipt.entry() != publication.entry()
            || receipt.leaf_index() != publication.leaf_index()
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "checkpoint observation publication leaf",
            });
        }
        if receipt.signed_head().body().observed_at()
            <= publication.signed_head().body().observed_at()
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "checkpoint observation must be later than submission",
            });
        }
        verify_provider_head_progression(
            &provider,
            publication.signed_head(),
            receipt.signed_head(),
            consistency_proof,
        )?;
        match &self.publications[index].observation {
            Some(retained) if retained == &receipt => Ok(()),
            Some(retained)
                if retained.signed_head().body().observed_at()
                    >= receipt.signed_head().body().observed_at() =>
            {
                Ok(())
            }
            _ => {
                self.publications[index].observation = Some(receipt.clone());
                match self
                    .journal_observations
                    .binary_search_by_key(&receipt.provider_id(), InclusionReceipt::provider_id)
                {
                    Ok(retained_index) => self.journal_observations[retained_index] = receipt,
                    Err(insert_index) => self.journal_observations.insert(insert_index, receipt),
                }
                Ok(())
            }
        }
    }

    fn validate_receipt(
        &self,
        receipt: &InclusionReceipt,
    ) -> Result<&ProviderDescriptor, IdentityError> {
        if receipt.entry().account_id() != self.account_id
            || receipt.entry().subject() != ProviderLogSubject::Checkpoint(self.checkpoint_id)
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "checkpoint publication receipt subject",
            });
        }
        let provider = self
            .providers
            .iter()
            .find(|provider| provider.id() == Ok(receipt.provider_id()))
            .ok_or(IdentityError::FreshnessUnavailable)?;
        receipt.verify(provider)?;
        Ok(provider)
    }

    fn publication_index(
        &self,
        provider_id: ProviderId,
    ) -> Result<Result<usize, usize>, IdentityError> {
        let mut low = 0_usize;
        let mut high = self.publications.len();
        while low < high {
            let middle = low + (high - low) / 2;
            let middle_id = self.publications[middle].provider.id()?;
            if middle_id < provider_id {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        if self
            .publications
            .get(low)
            .is_some_and(|publication| publication.provider.id() == Ok(provider_id))
        {
            Ok(Ok(low))
        } else {
            Ok(Err(low))
        }
    }
}

/// Concurrently publish the exact verified checkpoint to every configured provider client.
///
/// Client futures are all created before polling begins and are polled as one bounded set. A
/// missing configured client is reported as [`IdentityError::ProviderUnavailable`]. Individual
/// provider failures do not discard valid receipts returned by other providers and cannot advance
/// the tracker beyond the threshold actually verified.
pub async fn publish_checkpoint_concurrently(
    tracker: &mut PublicationTracker,
    checkpoint: &ProviderCheckpointBundle,
    clients: &[&dyn TransparencyClient],
) -> Result<PublicationBatch, IdentityError> {
    if clients.len() > MAX_TRANSPARENCY_PROVIDERS {
        return Err(IdentityError::limit(
            "transparency publication clients",
            clients.len(),
            MAX_TRANSPARENCY_PROVIDERS,
        ));
    }
    let mut client_ids = clients
        .iter()
        .map(|client| client.provider_id())
        .collect::<Vec<_>>();
    client_ids.sort_unstable();
    if client_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(IdentityError::DuplicateElement {
            resource: "transparency publication clients",
        });
    }
    if client_ids.iter().any(|provider_id| {
        !tracker
            .providers
            .iter()
            .any(|provider| provider.id() == Ok(*provider_id))
    }) {
        return Err(IdentityError::InvalidRelationship {
            resource: "transparency publication configured client",
        });
    }

    tracker.mark_authorized(checkpoint.verified_checkpoint())?;
    let mut pending = Vec::new();
    let mut results = tracker
        .providers
        .iter()
        .map(|provider| {
            Ok::<_, IdentityError>((provider.id()?, Err(IdentityError::ProviderUnavailable)))
        })
        .collect::<Result<Vec<_>, _>>()?;
    for (index, provider) in tracker.providers.iter().enumerate() {
        let provider_id = provider.id()?;
        if let Some(client) = clients
            .iter()
            .find(|client| client.provider_id() == provider_id)
        {
            pending.push((index, client.publish_checkpoint(checkpoint)));
        }
    }
    for (index, result) in join_publications(pending).await {
        results[index].1 = result;
    }

    let mut outcomes = Vec::with_capacity(results.len());
    for (provider_id, result) in results {
        let result = match result {
            Ok(receipt) => tracker.record_publication(receipt),
            Err(error) => Err(error),
        };
        outcomes.push(ProviderPublicationOutcome {
            provider_id,
            result,
        });
    }
    Ok(PublicationBatch {
        outcomes,
        stage: tracker.stage(),
    })
}

async fn join_publications<'a>(
    tasks: Vec<(usize, StoreFuture<'a, InclusionReceipt>)>,
) -> Vec<(usize, Result<InclusionReceipt, IdentityError>)> {
    let task_count = tasks.len();
    let mut remaining = task_count;
    let mut tasks = tasks
        .into_iter()
        .map(|(index, future)| (index, Some(future)))
        .collect::<Vec<_>>();
    let mut completed = Vec::with_capacity(task_count);
    std::future::poll_fn(move |context| {
        for (index, slot) in &mut tasks {
            let Some(future) = slot.as_mut() else {
                continue;
            };
            if let Poll::Ready(result) = future.as_mut().poll(context) {
                completed.push((*index, result));
                *slot = None;
                remaining -= 1;
            }
        }
        if remaining == 0 {
            Poll::Ready(std::mem::take(&mut completed))
        } else {
            Poll::Pending
        }
    })
    .await
}
