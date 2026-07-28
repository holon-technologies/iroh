//! Resource limits enforced at document protocol and actor boundaries.

use std::time::Duration;

/// Largest accepted encoded sync frame.
pub const MAX_SYNC_MESSAGE_SIZE: usize = 4 * 1024 * 1024;
/// Maximum reconciliation parts accepted in one sync message.
pub const MAX_SYNC_MESSAGE_PARTS: usize = 1024;
/// Maximum signed entries accepted in one sync message.
pub const MAX_ENTRIES_PER_SYNC_MESSAGE: usize = 2048;
/// Maximum encoded bytes accepted for one document ticket.
pub const MAX_TICKET_BYTES: usize = 512 * 1024;
/// Maximum peers accepted in one document ticket or start-sync request.
pub const MAX_PEERS_PER_DOCUMENT: usize = 256;
/// Maximum simultaneously active document gossip subscriptions.
pub const MAX_ACTIVE_DOCUMENTS: usize = 1024;
/// Maximum simultaneous inbound and outbound reconciliation sessions.
pub const MAX_LIVE_SYNC_SESSIONS: usize = 256;
/// Maximum subscribers retained for one document.
pub const MAX_SUBSCRIBERS_PER_DOCUMENT: usize = 256;
/// Maximum unresolved or downloading content hashes retained globally.
pub const MAX_PENDING_CONTENT_HASHES: usize = 16_384;
/// Maximum content hashes retained for one document.
pub const MAX_PENDING_CONTENT_HASHES_PER_DOCUMENT: usize = 4096;

/// Capacity of the storage actor's command queue.
pub const STORE_ACTION_QUEUE_CAPACITY: usize = 1024;
/// Capacity of the live-sync actor's command queue.
pub const LIVE_ACTOR_QUEUE_CAPACITY: usize = 64;
/// Capacity of each public event subscription queue.
pub const SUBSCRIPTION_QUEUE_CAPACITY: usize = 256;
/// Capacity of the internal replica-event queue.
pub const REPLICA_EVENT_QUEUE_CAPACITY: usize = 1024;
/// Capacity of the local RPC actor queue.
pub const RPC_ACTOR_QUEUE_CAPACITY: usize = 64;
/// Capacity of the GC protection response queue.
pub const GC_PROTECTION_QUEUE_CAPACITY: usize = 64;

/// Maximum age of an open database write transaction.
pub const MAX_DATABASE_COMMIT_DELAY: Duration = Duration::from_millis(500);
/// Time allowed for graceful engine shutdown.
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// A document protocol input exceeded a named resource limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{resource} contains {actual} items or bytes, maximum is {maximum}")]
pub struct LimitError {
    /// Name of the bounded resource.
    pub resource: &'static str,
    /// Observed size.
    pub actual: usize,
    /// Maximum accepted size.
    pub maximum: usize,
}

impl LimitError {
    pub(crate) fn new(resource: &'static str, actual: usize, maximum: usize) -> Self {
        Self {
            resource,
            actual,
            maximum,
        }
    }
}

const _: () = {
    assert!(MAX_SYNC_MESSAGE_SIZE > 0);
    assert!(MAX_SYNC_MESSAGE_PARTS > 0);
    assert!(MAX_ENTRIES_PER_SYNC_MESSAGE >= MAX_SYNC_MESSAGE_PARTS);
    assert!(MAX_TICKET_BYTES >= MAX_SYNC_MESSAGE_SIZE / 8);
    assert!(MAX_PEERS_PER_DOCUMENT > 0);
    assert!(MAX_ACTIVE_DOCUMENTS >= MAX_LIVE_SYNC_SESSIONS);
    assert!(MAX_SUBSCRIBERS_PER_DOCUMENT > 0);
    assert!(MAX_PENDING_CONTENT_HASHES >= MAX_PENDING_CONTENT_HASHES_PER_DOCUMENT);
    assert!(STORE_ACTION_QUEUE_CAPACITY > 0);
    assert!(LIVE_ACTOR_QUEUE_CAPACITY > 0);
    assert!(SUBSCRIPTION_QUEUE_CAPACITY > 0);
    assert!(REPLICA_EVENT_QUEUE_CAPACITY > 0);
    assert!(RPC_ACTOR_QUEUE_CAPACITY > 0);
    assert!(GC_PROTECTION_QUEUE_CAPACITY > 0);
};
