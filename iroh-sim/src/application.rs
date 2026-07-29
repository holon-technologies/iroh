//! Deterministic reference model for the local-first application bundle.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

const MAX_MODEL_NODES: usize = 256;
const MAX_MODEL_ITEMS: usize = 65_536;
const MAX_MODEL_BLOB_BYTES: usize = 16 * 1024 * 1024;
const CURRENT_STORAGE_SCHEMA: u32 = 1;

/// Stable node identifier used by the application model.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct NodeId(String);

impl NodeId {
    /// Creates a bounded model node identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, ApplicationError> {
        let value = value.into();
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable document identifier used by the application model.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DocumentId(String);

impl DocumentId {
    /// Creates a bounded model document identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, ApplicationError> {
        let value = value.into();
        validate_identifier(&value)?;
        Ok(Self(value))
    }
}

/// Content identity in the deterministic model.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct BlobHash([u8; 32]);

/// Document authority held by one replica.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// May receive and read entries, but cannot author them.
    Read,
    /// May receive, read, and author entries.
    Write,
}

impl Capability {
    const fn permits(self, requested: Self) -> bool {
        matches!(
            (self, requested),
            (Self::Write, _) | (Self::Read, Self::Read)
        )
    }
}

/// One-shot delivery impairment applied to the next enqueued synchronization message.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryFault {
    /// Suppress the message.
    Drop,
    /// Enqueue the same message twice.
    Duplicate,
    /// Put the message at the front of the delivery queue.
    Reorder,
}

/// Hard limits for deterministic application scenarios.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationModelConfig {
    pub max_nodes: usize,
    pub max_documents_per_node: usize,
    pub max_blobs_per_node: usize,
    pub max_entries_per_document: usize,
    pub max_pending_messages: usize,
    pub max_trace_events: usize,
    pub max_blob_bytes: usize,
}

impl Default for ApplicationModelConfig {
    fn default() -> Self {
        Self {
            max_nodes: 16,
            max_documents_per_node: 64,
            max_blobs_per_node: 256,
            max_entries_per_document: 512,
            max_pending_messages: 1_024,
            max_trace_events: 4_096,
            max_blob_bytes: 1024 * 1024,
        }
    }
}

impl ApplicationModelConfig {
    fn validate(self) -> Result<(), ApplicationError> {
        let item_bounds = [
            self.max_documents_per_node,
            self.max_blobs_per_node,
            self.max_entries_per_document,
            self.max_pending_messages,
            self.max_trace_events,
        ];
        if self.max_nodes == 0
            || self.max_nodes > MAX_MODEL_NODES
            || item_bounds
                .into_iter()
                .any(|bound| bound == 0 || bound > MAX_MODEL_ITEMS)
            || self.max_blob_bytes == 0
            || self.max_blob_bytes > MAX_MODEL_BLOB_BYTES
        {
            return Err(ApplicationError::InvalidBounds);
        }
        Ok(())
    }
}

/// Deterministic application operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum ApplicationOperation {
    StartNode {
        node: NodeId,
    },
    StopNode {
        node: NodeId,
    },
    RestartNode {
        node: NodeId,
    },
    Shutdown {
        node: NodeId,
    },
    CreateDocument {
        node: NodeId,
        document: DocumentId,
    },
    AddBlob {
        node: NodeId,
        bytes: Vec<u8>,
    },
    Write {
        node: NodeId,
        document: DocumentId,
        key: Vec<u8>,
        blob: BlobHash,
    },
    Share {
        from: NodeId,
        to: NodeId,
        document: DocumentId,
        capability: Capability,
    },
    FetchBlob {
        from: NodeId,
        to: NodeId,
        blob: BlobHash,
    },
    Synchronize {
        left: NodeId,
        right: NodeId,
        document: DocumentId,
    },
    CollectGarbage {
        node: NodeId,
    },
    Partition {
        left: NodeId,
        right: NodeId,
    },
    Heal {
        left: NodeId,
        right: NodeId,
    },
    SetDeliveryFault {
        fault: DeliveryFault,
    },
    DuplicateNext,
    ReorderNext,
    DropNext,
    DeliverAll,
    SetStorageFault {
        node: NodeId,
        enabled: bool,
    },
    Migrate {
        node: NodeId,
        target_schema: u32,
    },
}

/// Replayable application scenario identity and ordered operations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationScenario {
    pub seed: u64,
    pub candidate_sha: String,
    pub artifact_version: u32,
    pub operations: Vec<ApplicationOperation>,
}

/// One deterministic operation record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationTraceEvent {
    pub sequence: u64,
    pub operation: ApplicationOperation,
}

/// Successful replay evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationRun {
    pub seed: u64,
    pub candidate_sha: String,
    pub artifact_version: u32,
    pub trace: Vec<ApplicationTraceEvent>,
}

/// Materialized entry used to compare replicas.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentEntry {
    pub author: NodeId,
    pub revision: u64,
    pub blob: BlobHash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DocumentReplica {
    capability: Capability,
    entries: BTreeMap<Vec<u8>, DocumentEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NodeState {
    identity: String,
    running: bool,
    storage_fault: bool,
    storage_schema: u32,
    documents: BTreeMap<DocumentId, DocumentReplica>,
    blobs: BTreeMap<BlobHash, Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SyncMessage {
    from: NodeId,
    to: NodeId,
    document: DocumentId,
    grant: Option<Capability>,
    entries: BTreeMap<Vec<u8>, DocumentEntry>,
    blobs: BTreeMap<BlobHash, Vec<u8>>,
}

/// Comparable model state for atomicity assertions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationSnapshot {
    nodes: BTreeMap<NodeId, NodeState>,
    partitions: BTreeSet<(NodeId, NodeId)>,
    pending: VecDeque<SyncMessage>,
    delivery_faults: BTreeSet<DeliveryFault>,
    revision: u64,
}

/// Deterministic application model failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ApplicationError {
    #[error("application model bounds are invalid")]
    InvalidBounds,
    #[error("identifier is empty, too long, or contains unsupported characters")]
    InvalidIdentifier,
    #[error("candidate SHA or artifact version is invalid")]
    InvalidScenarioIdentity,
    #[error("operation trace limit reached")]
    TraceLimit,
    #[error("node limit reached")]
    NodeLimit,
    #[error("node already exists")]
    NodeAlreadyExists,
    #[error("node was not found")]
    NodeNotFound,
    #[error("node is not running")]
    NodeNotRunning,
    #[error("node is already running")]
    NodeAlreadyRunning,
    #[error("document was not found")]
    DocumentNotFound,
    #[error("document already exists")]
    DocumentAlreadyExists,
    #[error("document limit reached")]
    DocumentLimit,
    #[error("entry key is empty or exceeds its bound")]
    InvalidEntryKey,
    #[error("entry limit reached")]
    EntryLimit,
    #[error("write capability is required")]
    WriteCapabilityRequired,
    #[error("requested capability exceeds the sharer's authority")]
    CapabilityEscalation,
    #[error("blob exceeds its byte bound")]
    BlobTooLarge,
    #[error("blob limit reached")]
    BlobLimit,
    #[error("blob is missing")]
    BlobMissing,
    #[error("storage is unavailable")]
    StorageUnavailable,
    #[error("nodes are partitioned")]
    Partitioned,
    #[error("pending delivery limit reached")]
    PendingMessageLimit,
    #[error("unsupported storage schema")]
    UnsupportedStorageSchema,
    #[error("model invariant failed: {0}")]
    Invariant(&'static str),
}

/// Bounded deterministic reference model for framework and protocol behavior.
#[derive(Debug)]
pub struct ApplicationModel {
    config: ApplicationModelConfig,
    nodes: BTreeMap<NodeId, NodeState>,
    partitions: BTreeSet<(NodeId, NodeId)>,
    pending: VecDeque<SyncMessage>,
    delivery_faults: BTreeSet<DeliveryFault>,
    trace: Vec<ApplicationTraceEvent>,
    revision: u64,
}

impl ApplicationModel {
    /// Creates an empty model after validating every resource ceiling.
    pub fn new(config: ApplicationModelConfig) -> Result<Self, ApplicationError> {
        config.validate()?;
        Ok(Self {
            config,
            nodes: BTreeMap::new(),
            partitions: BTreeSet::new(),
            pending: VecDeque::new(),
            delivery_faults: BTreeSet::new(),
            trace: Vec::new(),
            revision: 0,
        })
    }

    /// Computes the same kind of content identity used by the model's blob store.
    #[must_use]
    pub fn hash(bytes: &[u8]) -> BlobHash {
        BlobHash(*blake3::hash(bytes).as_bytes())
    }

    /// Runs an ordered scenario and returns replay identity plus the bounded trace.
    pub fn run(
        &mut self,
        scenario: &ApplicationScenario,
    ) -> Result<ApplicationRun, ApplicationError> {
        if scenario.artifact_version == 0
            || scenario.candidate_sha.is_empty()
            || scenario.candidate_sha.len() > 128
            || scenario.operations.len() > self.config.max_trace_events
        {
            return Err(ApplicationError::InvalidScenarioIdentity);
        }
        let trace_start = self.trace.len();
        for operation in &scenario.operations {
            self.apply(operation.clone())?;
        }
        self.assert_invariants()?;
        Ok(ApplicationRun {
            seed: scenario.seed,
            candidate_sha: scenario.candidate_sha.clone(),
            artifact_version: scenario.artifact_version,
            trace: self.trace[trace_start..].to_vec(),
        })
    }

    /// Applies one operation atomically or leaves model state unchanged.
    pub fn apply(&mut self, operation: ApplicationOperation) -> Result<(), ApplicationError> {
        if self.trace.len() >= self.config.max_trace_events {
            return Err(ApplicationError::TraceLimit);
        }
        let mut next = self.snapshot();
        apply_to_snapshot(&self.config, &mut next, &operation)?;
        self.nodes = next.nodes;
        self.partitions = next.partitions;
        self.pending = next.pending;
        self.delivery_faults = next.delivery_faults;
        self.revision = next.revision;
        self.trace.push(ApplicationTraceEvent {
            sequence: u64::try_from(self.trace.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1),
            operation,
        });
        Ok(())
    }

    /// Returns a comparable durable/network snapshot, excluding diagnostic trace state.
    #[must_use]
    pub fn snapshot(&self) -> ApplicationSnapshot {
        ApplicationSnapshot {
            nodes: self.nodes.clone(),
            partitions: self.partitions.clone(),
            pending: self.pending.clone(),
            delivery_faults: self.delivery_faults.clone(),
            revision: self.revision,
        }
    }

    /// Returns the stable identity for a known node.
    #[must_use]
    pub fn identity(&self, node: &NodeId) -> Option<&str> {
        self.nodes.get(node).map(|state| state.identity.as_str())
    }

    /// Returns one materialized document entry.
    #[must_use]
    pub fn entry(
        &self,
        node: &NodeId,
        document: &DocumentId,
        key: &[u8],
    ) -> Option<&DocumentEntry> {
        self.nodes
            .get(node)?
            .documents
            .get(document)?
            .entries
            .get(key)
    }

    /// Returns verified bytes for one local blob.
    #[must_use]
    pub fn blob(&self, node: &NodeId, hash: BlobHash) -> Option<&[u8]> {
        self.nodes.get(node)?.blobs.get(&hash).map(Vec::as_slice)
    }

    /// Checks identity, hash, capability, and resource invariants over current state.
    pub fn assert_invariants(&self) -> Result<(), ApplicationError> {
        if self.nodes.len() > self.config.max_nodes
            || self.pending.len() > self.config.max_pending_messages
            || self.trace.len() > self.config.max_trace_events
        {
            return Err(ApplicationError::Invariant("resource bound"));
        }
        for (node_id, node) in &self.nodes {
            if node.identity != identity_for(node_id) {
                return Err(ApplicationError::Invariant("stable identity"));
            }
            if node.documents.len() > self.config.max_documents_per_node
                || node.blobs.len() > self.config.max_blobs_per_node
            {
                return Err(ApplicationError::Invariant("per-node resource bound"));
            }
            for (hash, bytes) in &node.blobs {
                if *hash != Self::hash(bytes) || bytes.len() > self.config.max_blob_bytes {
                    return Err(ApplicationError::Invariant("blob hash matches bytes"));
                }
            }
            if node
                .documents
                .values()
                .any(|document| document.entries.len() > self.config.max_entries_per_document)
            {
                return Err(ApplicationError::Invariant("document entry bound"));
            }
        }
        Ok(())
    }
}

fn apply_to_snapshot(
    config: &ApplicationModelConfig,
    state: &mut ApplicationSnapshot,
    operation: &ApplicationOperation,
) -> Result<(), ApplicationError> {
    match operation {
        ApplicationOperation::StartNode { node } => {
            if state.nodes.contains_key(node) {
                return Err(ApplicationError::NodeAlreadyExists);
            }
            if state.nodes.len() >= config.max_nodes {
                return Err(ApplicationError::NodeLimit);
            }
            state.nodes.insert(
                node.clone(),
                NodeState {
                    identity: identity_for(node),
                    running: true,
                    storage_fault: false,
                    storage_schema: CURRENT_STORAGE_SCHEMA,
                    documents: BTreeMap::new(),
                    blobs: BTreeMap::new(),
                },
            );
        }
        ApplicationOperation::StopNode { node } | ApplicationOperation::Shutdown { node } => {
            running_node_mut(state, node)?.running = false;
        }
        ApplicationOperation::RestartNode { node } => {
            let node = state
                .nodes
                .get_mut(node)
                .ok_or(ApplicationError::NodeNotFound)?;
            if node.running {
                return Err(ApplicationError::NodeAlreadyRunning);
            }
            node.running = true;
        }
        ApplicationOperation::CreateDocument { node, document } => {
            let node = writable_node_mut(state, node)?;
            if node.documents.contains_key(document) {
                return Err(ApplicationError::DocumentAlreadyExists);
            }
            if node.documents.len() >= config.max_documents_per_node {
                return Err(ApplicationError::DocumentLimit);
            }
            node.documents.insert(
                document.clone(),
                DocumentReplica {
                    capability: Capability::Write,
                    entries: BTreeMap::new(),
                },
            );
        }
        ApplicationOperation::AddBlob { node, bytes } => {
            if bytes.len() > config.max_blob_bytes {
                return Err(ApplicationError::BlobTooLarge);
            }
            let hash = ApplicationModel::hash(bytes);
            let node = writable_node_mut(state, node)?;
            if !node.blobs.contains_key(&hash) && node.blobs.len() >= config.max_blobs_per_node {
                return Err(ApplicationError::BlobLimit);
            }
            node.blobs.insert(hash, bytes.clone());
        }
        ApplicationOperation::Write {
            node,
            document,
            key,
            blob,
        } => {
            if key.is_empty() || key.len() > 1024 {
                return Err(ApplicationError::InvalidEntryKey);
            }
            let next_revision = state.revision.saturating_add(1);
            let node_state = writable_node_mut(state, node)?;
            let replica = node_state
                .documents
                .get_mut(document)
                .ok_or(ApplicationError::DocumentNotFound)?;
            if replica.capability != Capability::Write {
                return Err(ApplicationError::WriteCapabilityRequired);
            }
            if !replica.entries.contains_key(key)
                && replica.entries.len() >= config.max_entries_per_document
            {
                return Err(ApplicationError::EntryLimit);
            }
            replica.entries.insert(
                key.clone(),
                DocumentEntry {
                    author: node.clone(),
                    revision: next_revision,
                    blob: *blob,
                },
            );
            state.revision = next_revision;
        }
        ApplicationOperation::Share {
            from,
            to,
            document,
            capability,
        } => {
            require_connected_nodes(state, from, to)?;
            let source = running_node(state, from)?;
            let replica = source
                .documents
                .get(document)
                .ok_or(ApplicationError::DocumentNotFound)?;
            if !replica.capability.permits(*capability) {
                return Err(ApplicationError::CapabilityEscalation);
            }
            let message = message_from(source, from, to, document, Some(*capability))?;
            enqueue(config, state, message)?;
        }
        ApplicationOperation::FetchBlob { from, to, blob } => {
            require_connected_nodes(state, from, to)?;
            let bytes = running_node(state, from)?
                .blobs
                .get(blob)
                .ok_or(ApplicationError::BlobMissing)?
                .clone();
            let destination = writable_node_mut(state, to)?;
            if !destination.blobs.contains_key(blob)
                && destination.blobs.len() >= config.max_blobs_per_node
            {
                return Err(ApplicationError::BlobLimit);
            }
            destination.blobs.insert(*blob, bytes);
        }
        ApplicationOperation::Synchronize {
            left,
            right,
            document,
        } => {
            running_node(state, left)?;
            running_node(state, right)?;
            let mut messages = Vec::with_capacity(2);
            if running_node(state, left)?.documents.contains_key(document) {
                messages.push(message_from(
                    running_node(state, left)?,
                    left,
                    right,
                    document,
                    None,
                )?);
            }
            if running_node(state, right)?.documents.contains_key(document) {
                messages.push(message_from(
                    running_node(state, right)?,
                    right,
                    left,
                    document,
                    None,
                )?);
            }
            if messages.is_empty() {
                return Err(ApplicationError::DocumentNotFound);
            }
            for message in messages {
                enqueue(config, state, message)?;
            }
        }
        ApplicationOperation::CollectGarbage { node } => {
            let node = writable_node_mut(state, node)?;
            let reachable: BTreeSet<_> = node
                .documents
                .values()
                .flat_map(|replica| replica.entries.values().map(|entry| entry.blob))
                .collect();
            node.blobs.retain(|hash, _| reachable.contains(hash));
        }
        ApplicationOperation::Partition { left, right } => {
            running_node(state, left)?;
            running_node(state, right)?;
            state.partitions.insert(pair(left, right));
        }
        ApplicationOperation::Heal { left, right } => {
            running_node(state, left)?;
            running_node(state, right)?;
            state.partitions.remove(&pair(left, right));
        }
        ApplicationOperation::SetDeliveryFault { fault } => {
            state.delivery_faults.insert(*fault);
        }
        ApplicationOperation::DuplicateNext => {
            state.delivery_faults.insert(DeliveryFault::Duplicate);
        }
        ApplicationOperation::ReorderNext => {
            state.delivery_faults.insert(DeliveryFault::Reorder);
        }
        ApplicationOperation::DropNext => {
            state.delivery_faults.insert(DeliveryFault::Drop);
        }
        ApplicationOperation::DeliverAll => deliver_all(config, state)?,
        ApplicationOperation::SetStorageFault { node, enabled } => {
            running_node_mut(state, node)?.storage_fault = *enabled;
        }
        ApplicationOperation::Migrate {
            node,
            target_schema,
        } => {
            if *target_schema == 0 || *target_schema > CURRENT_STORAGE_SCHEMA {
                return Err(ApplicationError::UnsupportedStorageSchema);
            }
            let node = writable_node_mut(state, node)?;
            if *target_schema < node.storage_schema {
                return Err(ApplicationError::UnsupportedStorageSchema);
            }
            node.storage_schema = *target_schema;
        }
    }
    Ok(())
}

fn enqueue(
    config: &ApplicationModelConfig,
    state: &mut ApplicationSnapshot,
    message: SyncMessage,
) -> Result<(), ApplicationError> {
    let drop = state.delivery_faults.remove(&DeliveryFault::Drop);
    let duplicate = state.delivery_faults.remove(&DeliveryFault::Duplicate);
    let reorder = state.delivery_faults.remove(&DeliveryFault::Reorder);
    if drop {
        return Ok(());
    }
    let count = if duplicate { 2 } else { 1 };
    if state.pending.len().saturating_add(count) > config.max_pending_messages {
        return Err(ApplicationError::PendingMessageLimit);
    }
    for _ in 0..count {
        if reorder {
            state.pending.push_front(message.clone());
        } else {
            state.pending.push_back(message.clone());
        }
    }
    Ok(())
}

fn deliver_all(
    config: &ApplicationModelConfig,
    state: &mut ApplicationSnapshot,
) -> Result<(), ApplicationError> {
    let attempts = state.pending.len();
    for _ in 0..attempts {
        let message = state
            .pending
            .pop_front()
            .expect("attempt count was derived from pending messages");
        if state.partitions.contains(&pair(&message.from, &message.to)) {
            state.pending.push_back(message);
            continue;
        }
        if message.grant.is_none()
            && !running_node(state, &message.to)?
                .documents
                .contains_key(&message.document)
        {
            state.pending.push_back(message);
            continue;
        }
        let destination = writable_node_mut(state, &message.to)?;
        let replica = match destination.documents.get_mut(&message.document) {
            Some(replica) => {
                if let Some(grant) = message.grant
                    && replica.capability == Capability::Read
                    && grant == Capability::Write
                {
                    replica.capability = Capability::Write;
                }
                replica
            }
            None => {
                if destination.documents.len() >= config.max_documents_per_node {
                    return Err(ApplicationError::DocumentLimit);
                }
                let capability = message.grant.ok_or(ApplicationError::DocumentNotFound)?;
                destination.documents.insert(
                    message.document.clone(),
                    DocumentReplica {
                        capability,
                        entries: BTreeMap::new(),
                    },
                );
                destination
                    .documents
                    .get_mut(&message.document)
                    .expect("document was just inserted")
            }
        };
        for (key, incoming) in message.entries {
            if !replica.entries.contains_key(&key)
                && replica.entries.len() >= config.max_entries_per_document
            {
                return Err(ApplicationError::EntryLimit);
            }
            let replace = replica.entries.get(&key).is_none_or(|current| {
                (incoming.revision, &incoming.author) > (current.revision, &current.author)
            });
            if replace {
                replica.entries.insert(key, incoming);
            }
        }
        for (hash, bytes) in message.blobs {
            if destination.blobs.contains_key(&hash) {
                continue;
            }
            if destination.blobs.len() >= config.max_blobs_per_node {
                return Err(ApplicationError::BlobLimit);
            }
            if ApplicationModel::hash(&bytes) != hash {
                return Err(ApplicationError::Invariant(
                    "delivered blob hash matches bytes",
                ));
            }
            destination.blobs.insert(hash, bytes);
        }
    }
    Ok(())
}

fn message_from(
    source: &NodeState,
    from: &NodeId,
    to: &NodeId,
    document: &DocumentId,
    grant: Option<Capability>,
) -> Result<SyncMessage, ApplicationError> {
    let replica = source
        .documents
        .get(document)
        .ok_or(ApplicationError::DocumentNotFound)?;
    let blobs = replica
        .entries
        .values()
        .filter_map(|entry| {
            source
                .blobs
                .get(&entry.blob)
                .map(|bytes| (entry.blob, bytes.clone()))
        })
        .collect();
    Ok(SyncMessage {
        from: from.clone(),
        to: to.clone(),
        document: document.clone(),
        grant,
        entries: replica.entries.clone(),
        blobs,
    })
}

fn running_node<'a>(
    state: &'a ApplicationSnapshot,
    node: &NodeId,
) -> Result<&'a NodeState, ApplicationError> {
    let node = state
        .nodes
        .get(node)
        .ok_or(ApplicationError::NodeNotFound)?;
    if !node.running {
        return Err(ApplicationError::NodeNotRunning);
    }
    Ok(node)
}

fn running_node_mut<'a>(
    state: &'a mut ApplicationSnapshot,
    node: &NodeId,
) -> Result<&'a mut NodeState, ApplicationError> {
    let node = state
        .nodes
        .get_mut(node)
        .ok_or(ApplicationError::NodeNotFound)?;
    if !node.running {
        return Err(ApplicationError::NodeNotRunning);
    }
    Ok(node)
}

fn writable_node_mut<'a>(
    state: &'a mut ApplicationSnapshot,
    node: &NodeId,
) -> Result<&'a mut NodeState, ApplicationError> {
    let node = running_node_mut(state, node)?;
    if node.storage_fault {
        return Err(ApplicationError::StorageUnavailable);
    }
    Ok(node)
}

fn require_connected_nodes(
    state: &ApplicationSnapshot,
    left: &NodeId,
    right: &NodeId,
) -> Result<(), ApplicationError> {
    running_node(state, left)?;
    running_node(state, right)?;
    if state.partitions.contains(&pair(left, right)) {
        return Err(ApplicationError::Partitioned);
    }
    Ok(())
}

fn pair(left: &NodeId, right: &NodeId) -> (NodeId, NodeId) {
    if left <= right {
        (left.clone(), right.clone())
    } else {
        (right.clone(), left.clone())
    }
}

fn identity_for(node: &NodeId) -> String {
    blake3::hash(node.as_str().as_bytes()).to_hex().to_string()
}

fn validate_identifier(value: &str) -> Result<(), ApplicationError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ApplicationError::InvalidIdentifier);
    }
    Ok(())
}
