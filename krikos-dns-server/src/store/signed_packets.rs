use std::{
    future::Future,
    num::NonZeroUsize,
    panic::AssertUnwindSafe,
    path::Path,
    result,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, SystemTime},
};

use krikos_dns::pkarr::{SignedPacket, Timestamp};
use n0_error::{Result, StackResultExt, StdResultExt, anyerr, stack_error};
use redb::{Database, MultimapTableDefinition, ReadableDatabase, ReadableTable, TableDefinition};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use crate::{metrics::Metrics, util::PublicKeyBytes};

type SignedPacketsKey = [u8; 32];

const SIGNED_PACKETS_TABLE: TableDefinition<&SignedPacketsKey, &[u8]> =
    TableDefinition::new("signed-packets-1");
const UPDATE_TIME_TABLE: MultimapTableDefinition<[u8; 8], SignedPacketsKey> =
    MultimapTableDefinition::new("update-time-1");

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
enum StoreCorruptionError {
    #[error("stored packet is invalid in both current and legacy layouts")]
    InvalidPacket,
    #[error("stored packet public key does not match its table key")]
    PacketKeyMismatch,
    #[error("update-time index contains an invalid public key")]
    InvalidIndexKey,
}

const STORE_HEALTH_READY: u8 = 0;
const STORE_HEALTH_CORRUPT: u8 = 1;
const STORE_HEALTH_BACKGROUND_FAILURE: u8 = 2;

#[derive(Debug, Default)]
struct StoreHealth {
    state: AtomicU8,
}

impl StoreHealth {
    fn latch(&self, state: u8) {
        let _ = self.state.compare_exchange(
            STORE_HEALTH_READY,
            state,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn is_ready(&self) -> bool {
        self.state.load(Ordering::Acquire) == STORE_HEALTH_READY
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreWorker {
    Write,
    Eviction,
}

impl std::fmt::Display for StoreWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Write => f.write_str("packet-store-actor"),
            Self::Eviction => f.write_str("packet-store-evict"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ThreadOutcome {
    Running {
        worker: StoreWorker,
    },
    Completed,
    Failed {
        worker: StoreWorker,
        cause: Arc<str>,
    },
    Panicked {
        worker: StoreWorker,
        cause: Arc<str>,
    },
    CompletionSignalLost {
        worker: StoreWorker,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StoreShutdownError {
    WorkerFailed {
        worker: StoreWorker,
        cause: Arc<str>,
    },
    WorkerPanicked {
        worker: StoreWorker,
        cause: Arc<str>,
    },
    CompletionSignalLost {
        worker: StoreWorker,
    },
    JoinPanicked {
        worker: StoreWorker,
    },
}

impl std::fmt::Display for StoreShutdownError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WorkerFailed { worker, cause } => {
                write!(f, "{worker} failed: {cause}")
            }
            Self::WorkerPanicked { worker, cause } => {
                write!(f, "{worker} panicked: {cause}")
            }
            Self::CompletionSignalLost { worker } => {
                write!(f, "{worker} exited without reporting completion")
            }
            Self::JoinPanicked { worker } => {
                write!(f, "{worker} panicked after reporting completion")
            }
        }
    }
}

impl std::error::Error for StoreShutdownError {}

#[derive(Debug)]
pub(super) struct SignedPacketStore {
    send: mpsc::Sender<Message>,
    cancel: CancellationToken,
    health: Arc<StoreHealth>,
    write_thread: IoThread,
    evict_thread: IoThread,
}

impl Drop for SignedPacketStore {
    fn drop(&mut self) {
        // cancel the actor
        self.cancel.cancel();
        // after cancellation, the two threads will be joined
    }
}

#[derive(derive_more::Debug)]
enum Message {
    Upsert {
        packet: SignedPacket,
        res: oneshot::Sender<bool>,
    },
    Get {
        key: PublicKeyBytes,
        res: oneshot::Sender<Option<SignedPacket>>,
    },
    #[cfg(test)]
    Remove {
        key: PublicKeyBytes,
        res: oneshot::Sender<bool>,
    },
    Snapshot {
        #[debug(skip)]
        res: oneshot::Sender<Snapshot>,
    },
    CheckExpired {
        time: Timestamp,
        key: PublicKeyBytes,
    },
}

struct Actor {
    db: Database,
    recv: PeekableReceiver<Message>,
    cancel: CancellationToken,
    options: Options,
    metrics: Arc<Metrics>,
    health: Arc<StoreHealth>,
}

/// Configuration for the signed-packet store.
///
/// Controls how incoming packets are batched into write transactions and how
/// long packets are retained before the eviction task removes them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Options {
    /// Maximum number of packets to process in a single write transaction.
    pub(crate) max_batch_size: NonZeroUsize,
    /// Maximum time to keep a write transaction open.
    pub(crate) max_batch_time: NonZeroDuration,
    /// Time to keep packets in the store before eviction.
    pub(crate) eviction: NonZeroDuration,
    /// Pause between eviction checks.
    pub(crate) eviction_interval: NonZeroDuration,
}

/// A duration proven to be nonzero at the configuration boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NonZeroDuration(Duration);

impl NonZeroDuration {
    pub(crate) fn new(value: Duration) -> Option<Self> {
        (!value.is_zero()).then_some(Self(value))
    }

    pub(crate) fn get(self) -> Duration {
        self.0
    }
}

impl Default for Options {
    fn default() -> Self {
        Self {
            // 64k packets
            max_batch_size: NonZeroUsize::new(1024 * 64)
                .expect("default store batch size is nonzero"),
            // this means we lose at most 1 second of data in case of a crash
            max_batch_time: NonZeroDuration::new(Duration::from_secs(1))
                .expect("default store batch time is nonzero"),
            // 7 days
            eviction: NonZeroDuration::new(Duration::from_secs(3600 * 24 * 7))
                .expect("default store eviction age is nonzero"),
            // eviction can run frequently since it does not do a full scan
            eviction_interval: NonZeroDuration::new(Duration::from_secs(10))
                .expect("default store eviction interval is nonzero"),
        }
    }
}

impl Actor {
    async fn run(mut self) -> Result<()> {
        self.run0().await
    }

    async fn run0(&mut self) -> Result<()> {
        loop {
            let msg = tokio::select! {
                _ = self.cancel.cancelled() => return Ok(()),
                msg = self.recv.recv() => {
                    let Some(msg) = msg else {
                        return Ok(());
                    };
                    msg
                }
            };
            // if we get a snapshot message here we don't need to do a write transaction
            let msg = if let Message::Snapshot { res } = msg {
                let snapshot = Snapshot::new(&self.db)?;
                res.send(snapshot).ok();
                continue;
            } else {
                msg
            };
            trace!("batch");
            if self.recv.push_back(msg).is_err() {
                return Err(anyerr!("packet store receiver push-back slot is occupied"));
            }
            let transaction = self.db.begin_write().anyerr()?;
            let mut tables = Tables::new(&transaction).anyerr()?;
            let timeout = tokio::time::sleep(self.options.max_batch_time.get());
            tokio::pin!(timeout);
            for _ in 0..self.options.max_batch_size.get() {
                tokio::select! {
                    _ = self.cancel.cancelled() => {
                        drop(tables);
                        transaction.commit().anyerr()?;
                        return Ok(());
                    }
                    _ = &mut timeout => break,
                    Some(msg) = self.recv.recv() => self.handle_message(msg, &mut tables)?,
                }
            }
            drop(tables);
            transaction.commit().anyerr()?;
        }
    }

    fn handle_message(&self, msg: Message, tables: &mut Tables) -> Result<()> {
        match msg {
            Message::Get { key, res } => match self.get_packet(&tables.signed_packets, &key) {
                Ok(packet) => {
                    trace!("get {key}: {}", packet.is_some());
                    res.send(packet).ok();
                }
                Err(err) => {
                    warn!("get {key} failed: {err:#}");
                    return Err(err).context(format!("get packet for {key} failed"));
                }
            },
            Message::Upsert { packet, res } => {
                let key = PublicKeyBytes::from_signed_packet(&packet);
                trace!("upsert {}", key);
                let replaced = match self.get_packet(&tables.signed_packets, &key)? {
                    Some(existing) => {
                        if existing.more_recent_than(&packet) {
                            res.send(false).ok();
                            return Ok(());
                        } else {
                            // remove the old packet from the update time index
                            tables
                                .update_time
                                .remove(&existing.timestamp().to_be_bytes(), key.as_bytes())
                                .anyerr()?;
                            true
                        }
                    }
                    _ => false,
                };
                let value = serialize(&packet);
                tables
                    .signed_packets
                    .insert(key.as_bytes(), &value[..])
                    .anyerr()?;
                tables
                    .update_time
                    .insert(&packet.timestamp().to_be_bytes(), key.as_bytes())
                    .anyerr()?;
                if replaced {
                    self.metrics.store_packets_updated.inc();
                } else {
                    self.metrics.store_packets_inserted.inc();
                }
                res.send(true).ok();
            }
            #[cfg(test)]
            Message::Remove { key, res } => {
                trace!("remove {}", key);
                let updated = match tables.signed_packets.remove(key.as_bytes()).anyerr()? {
                    Some(row) => {
                        let packet = deserialize_for_key(row.value(), &key)?;
                        tables
                            .update_time
                            .remove(&packet.timestamp().to_be_bytes(), key.as_bytes())
                            .anyerr()?;
                        self.metrics.store_packets_removed.inc();
                        true
                    }
                    _ => false,
                };
                res.send(updated).ok();
            }
            Message::Snapshot { res } => {
                trace!("snapshot");
                res.send(Snapshot::new(&self.db)?).ok();
            }
            Message::CheckExpired { key, time } => {
                trace!("check expired {} at {}", key, fmt_time(time));
                match self.get_packet(&tables.signed_packets, &key)? {
                    Some(packet) => {
                        let expiry_us = u64::try_from(self.options.eviction.get().as_micros())
                            .unwrap_or(u64::MAX);
                        let expired = Timestamp::from_micros(
                            Timestamp::now().as_micros().saturating_sub(expiry_us),
                        );
                        if packet.timestamp() < expired {
                            tables
                                .update_time
                                .remove(&time.to_be_bytes(), key.as_bytes())
                                .anyerr()?;
                            let _ = tables.signed_packets.remove(key.as_bytes()).anyerr()?;
                            self.metrics.store_packets_expired.inc();
                            debug!("removed expired packet {key}");
                        } else {
                            debug!(
                                "packet {key} is no longer expired, removing obsolete expiry entry"
                            );
                            tables
                                .update_time
                                .remove(&time.to_be_bytes(), key.as_bytes())
                                .anyerr()?;
                        }
                    }
                    None => {
                        debug!("expired packet {key} not found, remove from expiry table");
                        tables
                            .update_time
                            .remove(&time.to_be_bytes(), key.as_bytes())
                            .anyerr()?;
                    }
                }
            }
        }
        Ok(())
    }

    fn get_packet(
        &self,
        table: &impl ReadableTable<&'static SignedPacketsKey, &'static [u8]>,
        key: &PublicKeyBytes,
    ) -> Result<Option<SignedPacket>> {
        let Some(row) = table
            .get(key.as_ref())
            .std_context("database fetch failed")?
        else {
            return Ok(None);
        };
        match deserialize_for_key(row.value(), key) {
            Ok(packet) => Ok(Some(packet)),
            Err(error) => {
                self.metrics.store_corrupt_rows.inc();
                self.health.latch(STORE_HEALTH_CORRUPT);
                Err(error.into())
            }
        }
    }
}

fn fmt_time(t: Timestamp) -> String {
    let duration = std::time::Duration::from_micros(t.as_micros());
    humantime::format_rfc3339_micros(SystemTime::UNIX_EPOCH + duration).to_string()
}

/// A struct similar to [`redb::Table`] but for all tables that make up the
/// signed packet store.
struct Tables<'a> {
    pub signed_packets: redb::Table<'a, &'static SignedPacketsKey, &'static [u8]>,
    pub update_time: redb::MultimapTable<'a, [u8; 8], SignedPacketsKey>,
}

impl<'txn> Tables<'txn> {
    fn new(tx: &'txn redb::WriteTransaction) -> result::Result<Self, redb::TableError> {
        Ok(Self {
            signed_packets: tx.open_table(SIGNED_PACKETS_TABLE)?,
            update_time: tx.open_multimap_table(UPDATE_TIME_TABLE)?,
        })
    }
}

struct Snapshot {
    #[allow(dead_code)]
    pub signed_packets: redb::ReadOnlyTable<&'static SignedPacketsKey, &'static [u8]>,
    pub update_time: redb::ReadOnlyMultimapTable<[u8; 8], SignedPacketsKey>,
}

impl Snapshot {
    fn new(db: &Database) -> Result<Self> {
        let tx = db.begin_read().anyerr()?;
        Ok(Self {
            signed_packets: tx.open_table(SIGNED_PACKETS_TABLE).anyerr()?,
            update_time: tx.open_multimap_table(UPDATE_TIME_TABLE).anyerr()?,
        })
    }
}

impl SignedPacketStore {
    pub(crate) fn persistent(
        path: impl AsRef<Path>,
        options: Options,
        metrics: Arc<Metrics>,
    ) -> Result<Self> {
        let path = path.as_ref();
        info!("loading packet database from {}", path.to_string_lossy());
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_std_context(|_| {
                format!(
                    "failed to create database directory at {}",
                    path.to_string_lossy()
                )
            })?;
        }
        let db = Database::builder()
            .create(path)
            .std_context("failed to open packet database")?;
        Self::open(db, options, metrics)
    }

    #[cfg(test)]
    pub(crate) fn in_memory(options: Options, metrics: Arc<Metrics>) -> Result<Self> {
        info!("using in-memory packet database");
        let db = Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .anyerr()?;
        Self::open(db, options, metrics)
    }

    pub(crate) fn open(db: Database, options: Options, metrics: Arc<Metrics>) -> Result<Self> {
        // create tables
        let write_tx = db.begin_write().anyerr()?;
        let _ = Tables::new(&write_tx).anyerr()?;
        write_tx.commit().anyerr()?;
        let (send, recv) = mpsc::channel(1024);
        let send2 = send.clone();
        let cancel = CancellationToken::new();
        let cancel2 = cancel.clone();
        let cancel3 = cancel.clone();
        let health = Arc::new(StoreHealth::default());
        let actor = Actor {
            db,
            recv: PeekableReceiver::new(recv),
            cancel: cancel2,
            options,
            metrics: metrics.clone(),
            health: health.clone(),
        };
        // start an io thread and donate it to the tokio runtime so we can do blocking IO
        // inside the thread despite being in a tokio runtime
        let write_thread = IoThread::new(
            StoreWorker::Write,
            cancel.clone(),
            health.clone(),
            metrics.clone(),
            move || actor.run(),
        )?;
        let evict_thread = IoThread::new(
            StoreWorker::Eviction,
            cancel.clone(),
            health.clone(),
            metrics,
            move || evict_task(send2, options, cancel3),
        )?;
        Ok(Self {
            send,
            cancel,
            health,
            write_thread,
            evict_thread,
        })
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.health.is_ready()
    }

    pub(crate) async fn upsert(&self, packet: SignedPacket) -> Result<bool> {
        let (tx, rx) = oneshot::channel();
        self.send
            .send(Message::Upsert { packet, res: tx })
            .await
            .anyerr()?;
        rx.await.anyerr()
    }

    pub(crate) async fn get(&self, key: &PublicKeyBytes) -> Result<Option<SignedPacket>> {
        let (tx, rx) = oneshot::channel();
        self.send
            .send(Message::Get { key: *key, res: tx })
            .await
            .anyerr()?;
        rx.await.anyerr()
    }

    pub(crate) fn start_shutdown(&self) {
        self.cancel.cancel();
    }

    pub(super) async fn shutdown(&self) -> std::result::Result<(), StoreShutdownError> {
        self.start_shutdown();
        let (write_outcome, evict_outcome) =
            tokio::join!(self.write_thread.wait(), self.evict_thread.wait());

        self.write_thread.join_finished()?;
        self.evict_thread.join_finished()?;
        outcome_result(write_outcome)?;
        outcome_result(evict_outcome)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn remove(&self, key: &PublicKeyBytes) -> Result<bool> {
        let (tx, rx) = oneshot::channel();
        self.send
            .send(Message::Remove { key: *key, res: tx })
            .await
            .anyerr()?;
        rx.await.anyerr()
    }
}

/// Serialize a signed packet for storage: `<8 bytes last_seen><packet bytes>`.
fn serialize(packet: &SignedPacket) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + packet.as_bytes().len());
    out.extend_from_slice(&Timestamp::now().to_be_bytes());
    out.extend_from_slice(packet.as_bytes());
    out
}

/// Deserialize a signed packet from storage format.
///
/// Handles backwards compatibility with older storage formats that didn't include
/// the `last_seen` prefix.
fn deserialize(data: &[u8]) -> std::result::Result<SignedPacket, StoreCorruptionError> {
    // Try parsing as <8 bytes last_seen><packet> (pkarr v3 format)
    if data.len() >= 8
        && let Ok(packet) = SignedPacket::from_bytes(&data[8..])
    {
        return Ok(packet);
    }
    // Fall back to raw packet bytes (pre-v0.35 format without last_seen prefix)
    SignedPacket::from_bytes(data).map_err(|_| n0_error::e!(StoreCorruptionError::InvalidPacket))
}

fn deserialize_for_key(
    data: &[u8],
    key: &PublicKeyBytes,
) -> std::result::Result<SignedPacket, StoreCorruptionError> {
    let packet = deserialize(data)?;
    if packet.public_key().as_bytes() != key.as_bytes() {
        return Err(n0_error::e!(StoreCorruptionError::PacketKeyMismatch));
    }
    Ok(packet)
}

async fn evict_task(
    send: mpsc::Sender<Message>,
    options: Options,
    cancel: CancellationToken,
) -> Result<()> {
    let cancel2 = cancel.clone();
    let result = cancel2
        .run_until_cancelled(async move {
            info!("starting evict task");
            evict_task_inner(send, options).await
        })
        .await;
    match result {
        Some(result) => {
            // A worker finishing for any reason stops its peer.
            cancel.cancel();
            result
        }
        None => Ok(()),
    }
}

/// Periodically check for expired packets and remove them.
async fn evict_task_inner(send: mpsc::Sender<Message>, options: Options) -> Result<()> {
    let expiry_us = u64::try_from(options.eviction.get().as_micros()).unwrap_or(u64::MAX);
    loop {
        let (tx, rx) = oneshot::channel();
        let _ = send.send(Message::Snapshot { res: tx }).await.ok();
        // if we can't get the snapshot we exit the loop, main actor dead
        let snapshot = rx.await.std_context("failed to get snapshot")?;

        let expired =
            Timestamp::from_micros(Timestamp::now().as_micros().saturating_sub(expiry_us));
        trace!("evicting packets older than {}", fmt_time(expired));
        // if getting the range fails we exit the loop and shut down
        // if individual reads fail we log the error and limp on
        for item in snapshot
            .update_time
            .range(..expired.to_be_bytes())
            .anyerr()?
        {
            let (time, keys) = match item {
                Ok(v) => v,
                Err(e) => {
                    error!("failed to read update_time row {:?}", e);
                    continue;
                }
            };
            let time = Timestamp::from_be_bytes(time.value());
            trace!("evicting expired packets at {}", fmt_time(time));
            for item in keys {
                let key = match item {
                    Ok(v) => v,
                    Err(e) => {
                        error!(
                            "failed to read update_time item at {}: {:?}",
                            fmt_time(time),
                            e
                        );
                        continue;
                    }
                };
                let key = PublicKeyBytes::try_from(key.value())
                    .map_err(|_| n0_error::e!(StoreCorruptionError::InvalidIndexKey))?;

                debug!("evicting expired packet {} {}", fmt_time(time), key);
                send.send(Message::CheckExpired { time, key })
                    .await
                    .anyerr()?;
            }
        }
        // sleep for the eviction interval so we don't constantly check
        tokio::time::sleep(options.eviction_interval.get()).await;
    }
}

/// An io thread that drives a future to completion on the current tokio runtime
///
/// Inside the future, blocking IO can be done without blocking one of the tokio
/// pool threads.
#[derive(Debug)]
struct IoThread {
    worker: StoreWorker,
    handle: Mutex<Option<std::thread::JoinHandle<()>>>,
    outcome: watch::Receiver<ThreadOutcome>,
}

impl IoThread {
    /// Spawn a new io thread.
    ///
    /// Calling this function requires that the current thread is running in a
    /// tokio runtime. It is up to the caller to make sure the future exits,
    /// e.g. by using a cancellation token. Otherwise, drop will block.
    fn new<F, Fut>(
        worker: StoreWorker,
        cancel: CancellationToken,
        health: Arc<StoreHealth>,
        metrics: Arc<Metrics>,
        f: F,
    ) -> Result<Self>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<()>>,
    {
        let rt = tokio::runtime::Handle::try_current().std_context("get tokio handle")?;
        let (outcome_tx, outcome) = watch::channel(ThreadOutcome::Running { worker });
        let handle = std::thread::Builder::new()
            .name(worker.to_string())
            .spawn(move || {
                let outcome = match std::panic::catch_unwind(AssertUnwindSafe(|| rt.block_on(f())))
                {
                    Ok(Ok(())) => ThreadOutcome::Completed,
                    Ok(Err(error)) => ThreadOutcome::Failed {
                        worker,
                        cause: format!("{error:#}").into(),
                    },
                    Err(payload) => ThreadOutcome::Panicked {
                        worker,
                        cause: panic_message(payload).into(),
                    },
                };
                if !matches!(outcome, ThreadOutcome::Completed) {
                    error!(%worker, ?outcome, "packet store worker failed");
                    metrics.store_background_failures.inc();
                    health.latch(STORE_HEALTH_BACKGROUND_FAILURE);
                    cancel.cancel();
                }
                let _ = outcome_tx.send(outcome);
            })
            .std_context("failed to spawn thread")?;
        Ok(Self {
            worker,
            handle: Mutex::new(Some(handle)),
            outcome,
        })
    }

    async fn wait(&self) -> ThreadOutcome {
        let mut outcome = self.outcome.clone();
        if !matches!(*outcome.borrow(), ThreadOutcome::Running { .. }) {
            return outcome.borrow().clone();
        }
        if outcome.changed().await.is_err() {
            return ThreadOutcome::CompletionSignalLost {
                worker: self.worker,
            };
        }
        outcome.borrow().clone()
    }

    fn join_finished(&self) -> std::result::Result<(), StoreShutdownError> {
        let handle = self
            .handle
            .lock()
            .expect("packet-store thread handle mutex must not be poisoned")
            .take();
        let Some(handle) = handle else {
            return Ok(());
        };
        handle.join().map_err(|_| StoreShutdownError::JoinPanicked {
            worker: self.worker,
        })
    }
}

impl Drop for IoThread {
    fn drop(&mut self) {
        let handle = self
            .handle
            .get_mut()
            .expect("packet-store thread handle mutex must not be poisoned")
            .take();
        if let Some(handle) = handle {
            // Dropping a native join handle detaches the worker. Normal shutdown
            // must observe and join it explicitly; a destructor must never make
            // an async shutdown deadline unbounded.
            drop(handle);
        }
    }
}

fn outcome_result(outcome: ThreadOutcome) -> std::result::Result<(), StoreShutdownError> {
    match outcome {
        ThreadOutcome::Completed => Ok(()),
        ThreadOutcome::Failed { worker, cause } => {
            Err(StoreShutdownError::WorkerFailed { worker, cause })
        }
        ThreadOutcome::Panicked { worker, cause } => {
            Err(StoreShutdownError::WorkerPanicked { worker, cause })
        }
        ThreadOutcome::Running { worker } | ThreadOutcome::CompletionSignalLost { worker } => {
            Err(StoreShutdownError::CompletionSignalLost { worker })
        }
    }
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

/// A wrapper for a tokio mpsc receiver that allows peeking at the next message.
#[derive(Debug)]
struct PeekableReceiver<T> {
    msg: Option<T>,
    recv: tokio::sync::mpsc::Receiver<T>,
}

#[allow(dead_code)]
impl<T> PeekableReceiver<T> {
    fn new(recv: tokio::sync::mpsc::Receiver<T>) -> Self {
        Self { msg: None, recv }
    }

    /// Receive the next message.
    ///
    /// Will block if there are no messages.
    /// Returns None only if there are no more messages (sender is dropped).
    async fn recv(&mut self) -> Option<T> {
        if let Some(msg) = self.msg.take() {
            return Some(msg);
        }
        self.recv.recv().await
    }

    /// Push back a message. This will only work if there is room for it.
    /// Otherwise, it will fail and return the message.
    fn push_back(&mut self, msg: T) -> std::result::Result<(), T> {
        if self.msg.is_none() {
            self.msg = Some(msg);
            Ok(())
        } else {
            Err(msg)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::mpsc as std_mpsc,
        time::{Duration, Instant},
    };

    use krikos_base::SecretKey;

    use super::*;

    fn test_signed_packet() -> SignedPacket {
        let secret_key = SecretKey::generate();
        SignedPacket::from_txt_strings(&secret_key, "_iroh", ["relay=https://example.com"], 30)
            .expect("valid packet")
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let packet = test_signed_packet();
        let serialized = serialize(&packet);
        let deserialized = deserialize(&serialized).expect("roundtrip should succeed");
        assert_eq!(packet.as_bytes(), deserialized.as_bytes());
    }

    #[test]
    fn deserialize_old_format_without_last_seen_prefix() {
        // Pre-v0.35 format: raw SignedPacket bytes without the 8-byte last_seen prefix
        let packet = test_signed_packet();
        let old_format = packet.as_bytes().to_vec();
        let deserialized = deserialize(&old_format).expect("old format should be readable");
        assert_eq!(packet.as_bytes(), deserialized.as_bytes());
    }

    #[test]
    fn deserialize_rejects_truncated_and_signature_invalid_rows() {
        assert!(matches!(
            deserialize(&[0_u8; 16]),
            Err(StoreCorruptionError::InvalidPacket { .. })
        ));

        let packet = test_signed_packet();
        let mut serialized = serialize(&packet);
        serialized[8 + 40] ^= 1;
        assert!(matches!(
            deserialize(&serialized),
            Err(StoreCorruptionError::InvalidPacket { .. })
        ));
    }

    #[test]
    fn deserialize_rejects_packet_table_key_mismatch() {
        let packet = test_signed_packet();
        let other_packet = test_signed_packet();
        let other_key = PublicKeyBytes::from_signed_packet(&other_packet);

        assert!(matches!(
            deserialize_for_key(&serialize(&packet), &other_key),
            Err(StoreCorruptionError::PacketKeyMismatch { .. })
        ));
    }

    #[test]
    fn public_key_bytes_reject_invalid_database_keys() {
        let invalid = (0_u8..=u8::MAX)
            .map(|byte| [byte; 32])
            .find(|bytes| krikos_base::PublicKey::from_bytes(bytes).is_err())
            .expect("the Ed25519 compressed-point domain contains invalid encodings");
        assert!(PublicKeyBytes::try_from(invalid).is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dropping_io_thread_does_not_wait_for_worker_completion() {
        const WORKER_DELAY: Duration = Duration::from_millis(500);
        const MAX_DROP_TIME: Duration = Duration::from_millis(100);

        let (started_tx, started_rx) = std_mpsc::sync_channel(1);
        let (release_tx, release_rx) = std_mpsc::sync_channel(1);
        let (completed_tx, completed_rx) = std_mpsc::sync_channel(1);
        let io_thread = IoThread::new(
            StoreWorker::Write,
            CancellationToken::new(),
            Arc::new(StoreHealth::default()),
            Arc::new(Metrics::default()),
            move || async move {
                started_tx
                    .send(())
                    .expect("test worker start receiver must remain live");
                release_rx
                    .recv()
                    .expect("test worker release sender must remain live");
                completed_tx
                    .send(())
                    .expect("test worker completion receiver must remain live");
                Ok(())
            },
        )
        .expect("test I/O thread must start");
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("test I/O thread must report startup");

        let release_thread = std::thread::spawn(move || {
            std::thread::sleep(WORKER_DELAY);
            release_tx
                .send(())
                .expect("test I/O thread must remain live until released");
        });
        let drop_started = Instant::now();
        drop(io_thread);
        let drop_elapsed = drop_started.elapsed();

        release_thread
            .join()
            .expect("test release thread must not panic");
        completed_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("detached test I/O thread must finish after release");
        assert!(
            drop_elapsed < MAX_DROP_TIME,
            "dropping an I/O thread handle must not wait for worker completion: \
             elapsed={drop_elapsed:?}, maximum={MAX_DROP_TIME:?}"
        );
    }

    #[tokio::test]
    async fn idle_store_shutdown_is_explicit_bounded_and_idempotent() {
        const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(1);

        let store = SignedPacketStore::in_memory(Options::default(), Arc::new(Metrics::default()))
            .expect("in-memory store");

        tokio::time::timeout(SHUTDOWN_DEADLINE, store.shutdown())
            .await
            .expect("idle store shutdown must finish before its parent deadline")
            .expect("idle store workers must report clean completion");
        assert!(
            store
                .write_thread
                .handle
                .lock()
                .expect("write-thread handle mutex must remain healthy")
                .is_none(),
            "clean shutdown must join the write thread"
        );
        assert!(
            store
                .evict_thread
                .handle
                .lock()
                .expect("eviction-thread handle mutex must remain healthy")
                .is_none(),
            "clean shutdown must join the eviction thread"
        );
        tokio::time::timeout(SHUTDOWN_DEADLINE, store.shutdown())
            .await
            .expect("repeated store shutdown must finish before its parent deadline")
            .expect("repeated store shutdown must preserve clean completion");
    }

    #[tokio::test]
    async fn io_thread_failure_is_typed_and_latches_store_health() {
        let cancel = CancellationToken::new();
        let health = Arc::new(StoreHealth::default());
        let metrics = Arc::new(Metrics::default());
        let io_thread = IoThread::new(
            StoreWorker::Eviction,
            cancel.clone(),
            health.clone(),
            metrics.clone(),
            || async { Err(anyerr!("injected eviction failure")) },
        )
        .expect("test I/O thread must start");

        let outcome = io_thread.wait().await;
        io_thread
            .join_finished()
            .expect("failed worker must still join without panicking");
        assert!(matches!(
            outcome_result(outcome),
            Err(StoreShutdownError::WorkerFailed {
                worker: StoreWorker::Eviction,
                ref cause,
            }) if cause.contains("injected eviction failure")
        ));
        assert!(cancel.is_cancelled(), "worker failure must cancel its peer");
        assert!(!health.is_ready(), "worker failure must latch store health");
        assert_eq!(
            metrics.store_background_failures.get(),
            1,
            "worker failure must be observable in bounded metrics"
        );
    }

    #[tokio::test]
    async fn io_thread_panic_is_typed_and_latches_store_health() {
        let cancel = CancellationToken::new();
        let health = Arc::new(StoreHealth::default());
        let metrics = Arc::new(Metrics::default());
        let io_thread = IoThread::new(
            StoreWorker::Write,
            cancel.clone(),
            health.clone(),
            metrics.clone(),
            || async {
                panic!("injected write panic");
                #[allow(unreachable_code)]
                Ok(())
            },
        )
        .expect("test I/O thread must start");

        let outcome = io_thread.wait().await;
        io_thread
            .join_finished()
            .expect("caught worker panic must still join cleanly");
        assert!(matches!(
            outcome_result(outcome),
            Err(StoreShutdownError::WorkerPanicked {
                worker: StoreWorker::Write,
                ref cause,
            }) if cause.contains("injected write panic")
        ));
        assert!(cancel.is_cancelled(), "worker panic must cancel its peer");
        assert!(!health.is_ready(), "worker panic must latch store health");
        assert_eq!(
            metrics.store_background_failures.get(),
            1,
            "worker panic must be observable in bounded metrics"
        );
    }

    #[tokio::test]
    async fn remove_in_memory() {
        let store = SignedPacketStore::in_memory(Options::default(), Arc::new(Metrics::default()))
            .expect("in-memory store");
        let packet = test_signed_packet();
        let key = PublicKeyBytes::from_signed_packet(&packet);

        assert!(store.upsert(packet.clone()).await.expect("upsert"));
        assert!(store.get(&key).await.expect("get").is_some());

        assert!(store.remove(&key).await.expect("remove existing"));
        assert!(store.get(&key).await.expect("get after remove").is_none());

        assert!(!store.remove(&key).await.expect("remove missing"));
    }
}
