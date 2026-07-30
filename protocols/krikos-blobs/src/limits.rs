//! Resource limits used at protocol, actor, and RPC admission boundaries.

use std::time::Duration;

/// Maximum number of provider connections handled concurrently by one protocol handler.
pub const MAX_CONCURRENT_PROVIDER_CONNECTIONS: usize = 128;
/// Maximum number of long-running operations owned by one store actor.
pub const MAX_CONCURRENT_STORE_TASKS: usize = 128;
/// Maximum number of imports that may perform storage work concurrently.
pub const MAX_CONCURRENT_IMPORTS: usize = 8;
/// Maximum number of downloads executed concurrently by one downloader actor.
pub const MAX_CONCURRENT_DOWNLOADS: usize = 32;
/// Maximum number of concurrent child downloads used to split a multi-blob request.
pub const MAX_CONCURRENT_SPLIT_DOWNLOADS: usize = 32;

/// Capacity of a store's public command queue.
pub const STORE_COMMAND_QUEUE_CAPACITY: usize = 100;
/// Capacity of the file store's database command queue.
pub const DATABASE_COMMAND_QUEUE_CAPACITY: usize = 100;
/// Capacity of the downloader's public command queue.
pub const DOWNLOADER_COMMAND_QUEUE_CAPACITY: usize = 32;
/// Capacity of progress queues returned to API callers.
pub const PROGRESS_QUEUE_CAPACITY: usize = 64;
/// Capacity of internal progress fan-in queues.
pub const INTERNAL_PROGRESS_QUEUE_CAPACITY: usize = 32;
/// Capacity of each child-download progress queue.
pub const CHILD_PROGRESS_QUEUE_CAPACITY: usize = 16;
/// Capacity used for streaming import request and response channels.
pub const IMPORT_STREAM_QUEUE_CAPACITY: usize = 32;
/// Capacity used for single-response streams.
pub const SINGLE_RESPONSE_QUEUE_CAPACITY: usize = 1;

/// Maximum time a protocol handler waits for graceful store shutdown.
pub const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

const _: () = {
    assert!(MAX_CONCURRENT_PROVIDER_CONNECTIONS > 0);
    assert!(MAX_CONCURRENT_STORE_TASKS > 0);
    assert!(MAX_CONCURRENT_IMPORTS > 0);
    assert!(MAX_CONCURRENT_IMPORTS <= MAX_CONCURRENT_STORE_TASKS);
    assert!(MAX_CONCURRENT_DOWNLOADS > 0);
    assert!(MAX_CONCURRENT_SPLIT_DOWNLOADS > 0);
    assert!(STORE_COMMAND_QUEUE_CAPACITY >= MAX_CONCURRENT_DOWNLOADS);
    assert!(DATABASE_COMMAND_QUEUE_CAPACITY > 0);
    assert!(DOWNLOADER_COMMAND_QUEUE_CAPACITY > 0);
    assert!(PROGRESS_QUEUE_CAPACITY > 0);
    assert!(INTERNAL_PROGRESS_QUEUE_CAPACITY > 0);
    assert!(CHILD_PROGRESS_QUEUE_CAPACITY > 0);
    assert!(IMPORT_STREAM_QUEUE_CAPACITY > 0);
    assert!(SINGLE_RESPONSE_QUEUE_CAPACITY > 0);
};
