//! Simulator resource accounting with current and high-water observations.

use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex, Weak},
};

use serde::{Deserialize, Serialize};

/// Resource families whose lifetime is owned by a simulator run.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// Runtime task futures.
    Task,
    /// Live resettable timers.
    Timer,
    /// Bound synthetic UDP sockets.
    Socket,
    /// Packets retained by a network queue or scheduled delivery.
    QueuedPacket,
    /// Live production or modeled connections.
    Connection,
    /// Live production or modeled application streams.
    Stream,
    /// Live NAT or port-mapping entries.
    Mapping,
    /// Retained discovery records.
    DiscoveryRecord,
    /// Live simulator-owned production relay services.
    Relay,
    /// Buffered trace events awaiting durable publication.
    TraceBuffer,
}

/// Current and maximum simultaneous use of one resource family.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceCount {
    /// Currently live resources.
    pub current: u64,
    /// Maximum `current` value observed during the run.
    pub high_water: u64,
}

/// Immutable resource-ledger view stored in run results and diagnostics.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceLedgerSnapshot {
    counts: BTreeMap<ResourceKind, ResourceCount>,
}

impl ResourceLedgerSnapshot {
    /// Returns the live count for `kind`.
    pub fn current(&self, kind: ResourceKind) -> u64 {
        self.counts.get(&kind).copied().unwrap_or_default().current
    }

    /// Returns the high-water count for `kind`.
    pub fn high_water(&self, kind: ResourceKind) -> u64 {
        self.counts
            .get(&kind)
            .copied()
            .unwrap_or_default()
            .high_water
    }

    /// Returns whether every tracked resource has been released.
    pub fn is_empty(&self) -> bool {
        self.counts.values().all(|count| count.current == 0)
    }
}

/// Mutable resource ledger shared by kernel components.
#[derive(Clone, Debug, Default)]
pub struct ResourceLedger {
    inner: Arc<Mutex<BTreeMap<ResourceKind, ResourceCount>>>,
}

impl ResourceLedger {
    /// Acquires one resource token, optionally enforcing a simultaneous-use limit.
    pub fn acquire(
        &self,
        kind: ResourceKind,
        limit: Option<u64>,
    ) -> Result<ResourceToken, LedgerError> {
        let mut counts = self.inner.lock().expect("resource ledger lock poisoned");
        let count = counts.entry(kind).or_default();
        let next = count.current.checked_add(1).ok_or(LedgerError::Overflow)?;
        if let Some(limit) = limit
            && next > limit
        {
            return Err(LedgerError::LimitExceeded { kind, limit });
        }
        count.current = next;
        count.high_water = count.high_water.max(next);
        Ok(ResourceToken {
            kind,
            ledger: Arc::downgrade(&self.inner),
            released: false,
        })
    }

    /// Returns an immutable snapshot.
    pub fn snapshot(&self) -> ResourceLedgerSnapshot {
        ResourceLedgerSnapshot {
            counts: self
                .inner
                .lock()
                .expect("resource ledger lock poisoned")
                .clone(),
        }
    }
}

/// RAII ownership of one ledger entry.
pub struct ResourceToken {
    kind: ResourceKind,
    ledger: Weak<Mutex<BTreeMap<ResourceKind, ResourceCount>>>,
    released: bool,
}

impl fmt::Debug for ResourceToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourceToken")
            .field("kind", &self.kind)
            .field("released", &self.released)
            .finish()
    }
}

impl ResourceToken {
    /// Releases the resource now. Dropping an unreleased token has the same effect.
    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        let Some(ledger) = self.ledger.upgrade() else {
            return;
        };
        let mut counts = ledger.lock().expect("resource ledger lock poisoned");
        let count = counts
            .get_mut(&self.kind)
            .expect("resource token has a matching ledger entry");
        count.current = count
            .current
            .checked_sub(1)
            .expect("resource token is released exactly once");
    }
}

impl Drop for ResourceToken {
    fn drop(&mut self) {
        self.release_inner();
    }
}

/// Resource accounting could not accept a new object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerError {
    /// A counter cannot be represented.
    Overflow,
    /// A configured simultaneous-use bound was reached.
    LimitExceeded {
        /// Resource family.
        kind: ResourceKind,
        /// Configured maximum.
        limit: u64,
    },
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overflow => f.write_str("simulator resource counter overflow"),
            Self::LimitExceeded { kind, limit } => {
                write!(f, "simulator {kind:?} resource limit {limit} exceeded")
            }
        }
    }
}

impl std::error::Error for LedgerError {}
