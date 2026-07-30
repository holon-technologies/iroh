//! Resource limits enforced by the gossip protocol and network adapter.

use std::time::Duration;

/// Largest accepted encoded gossip frame.
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;
/// Largest configured HyParView active view.
pub const MAX_ACTIVE_VIEW_CAPACITY: usize = 64;
/// Largest configured HyParView passive view.
pub const MAX_PASSIVE_VIEW_CAPACITY: usize = 1024;
/// Largest peer list accepted in a shuffle message.
pub const MAX_SHUFFLE_PEERS: usize = 128;
/// Maximum topics joined by one gossip actor.
pub const MAX_TOPICS: usize = 1024;
/// Maximum bootstrap peers accepted in one API command.
pub const MAX_BOOTSTRAP_PEERS: usize = 256;
/// Maximum subscription buffer requested through the API.
pub const MAX_SUBSCRIPTION_CAPACITY: usize = 65_536;
/// Maximum missing messages tracked for Plumtree recovery.
pub const MAX_PENDING_MESSAGES: usize = 8192;
/// Maximum peers tried while recovering one missing message.
pub const MAX_GRAFT_RETRIES: usize = 8;
/// Maximum message identifiers accepted in one `IHave` message.
pub const MAX_IHAVE_ENTRIES: usize = 1024;
/// Maximum duplicate identifiers retained per topic.
pub const MAX_DUPLICATE_CACHE_ENTRIES: usize = 16_384;
/// Maximum payloads retained for graft replies per topic.
pub const MAX_CACHED_MESSAGES: usize = 4096;
/// Maximum lazy announcements queued for one peer.
pub const MAX_LAZY_QUEUE_PER_PEER: usize = 1024;
/// Maximum messages queued while dialing one peer.
pub const MAX_PENDING_SENDS_PER_PEER: usize = 256;
/// Maximum simultaneous connection tasks owned by one actor.
pub const MAX_CONCURRENT_CONNECTION_HANDLERS: usize = 256;
/// Maximum simultaneous inbound topic streams on one connection.
pub const MAX_STREAMS_PER_CONNECTION: usize = 1024;
/// Maximum simultaneous outbound dials owned by one actor.
pub const MAX_CONCURRENT_DIALS: usize = 256;
/// Maximum live topic subscriptions owned by one actor.
pub const MAX_SUBSCRIPTIONS: usize = 4096;
/// Time allowed for graceful actor shutdown.
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
/// Portion of shutdown reserved for sending topic disconnect messages.
pub const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(4);

/// A protocol configuration exceeds a resource limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigError {
    field: &'static str,
    value: usize,
    min: usize,
    max: usize,
}

impl ConfigError {
    pub(crate) fn new(field: &'static str, value: usize, min: usize, max: usize) -> Self {
        Self {
            field,
            value,
            min,
            max,
        }
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} must be in {}..={}, got {}",
            self.field, self.min, self.max, self.value
        )
    }
}

impl std::error::Error for ConfigError {}
