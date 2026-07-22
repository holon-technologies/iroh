//! Bounded virtual-time address lookup providers consumed by production Iroh discovery logic.

use std::{
    collections::BTreeMap,
    fmt, io,
    net::SocketAddr,
    sync::{Arc, Mutex, Weak},
    time::{Duration, SystemTime},
};

use iroh::{
    EndpointId,
    address_lookup::{AddressLookup, Error, Item},
    endpoint_info::EndpointInfo,
};
use iroh_runtime::{RuntimeContext, TraceContext, TraceEventKind};
use n0_future::{StreamExt, boxed::BoxStream, stream};
use tokio::sync::oneshot;

use crate::{EventClass, Kernel, ResourceKind, ResourceToken, ScheduledEvent};

const PROVENANCE: &str = "deterministic-simulation";

/// Stable state returned after applying one discovery mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryRecordSnapshot {
    pub provider: String,
    pub record: String,
    pub endpoint: String,
    pub addresses: Vec<SocketAddr>,
    pub failed: bool,
    pub available_nanos: u64,
    pub expires_nanos: u64,
}

/// One simulator-owned address lookup provider with bounded retained records.
#[derive(Clone)]
pub struct DeterministicDiscovery {
    inner: Arc<DiscoveryInner>,
}

struct DiscoveryInner {
    id: String,
    max_records: u64,
    kernel: Kernel,
    context: Arc<RuntimeContext>,
    state: Mutex<DiscoveryState>,
}

#[derive(Default)]
struct DiscoveryState {
    records: BTreeMap<String, DiscoveryRecord>,
    next_generation: u64,
    deferred_error: Option<String>,
}

struct DiscoveryRecord {
    endpoint_name: String,
    endpoint_id: EndpointId,
    addresses: Vec<SocketAddr>,
    failed: bool,
    available_nanos: u64,
    expires_nanos: u64,
    last_updated_micros: u64,
    generation: u64,
    _expiry: ScheduledEvent,
    _resource: ResourceToken,
}

#[derive(Clone)]
struct ResolutionCandidate {
    record: String,
    endpoint_name: String,
    endpoint_id: EndpointId,
    addresses: Vec<SocketAddr>,
    failed: bool,
    available_nanos: u64,
    expires_nanos: u64,
    last_updated_micros: u64,
    generation: u64,
}

struct ScheduledResolution {
    receiver: oneshot::Receiver<Option<Result<Item, Error>>>,
    _event: Option<ScheduledEvent>,
}

impl fmt::Debug for DeterministicDiscovery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.inner.state.lock().expect("discovery lock poisoned");
        f.debug_struct("DeterministicDiscovery")
            .field("id", &self.inner.id)
            .field("records", &state.records.len())
            .finish()
    }
}

impl DeterministicDiscovery {
    pub fn new(
        id: impl Into<String>,
        max_records: u64,
        kernel: Kernel,
        context: Arc<RuntimeContext>,
    ) -> Result<Self, DiscoveryError> {
        if max_records == 0 {
            return Err(DiscoveryError("record bound must be nonzero".to_owned()));
        }
        Ok(Self {
            inner: Arc::new(DiscoveryInner {
                id: id.into(),
                max_records,
                kernel,
                context,
                state: Mutex::new(DiscoveryState::default()),
            }),
        })
    }

    pub fn id(&self) -> &str {
        &self.inner.id
    }

    #[allow(clippy::too_many_arguments)]
    pub fn publish(
        &self,
        record: &str,
        endpoint_name: &str,
        endpoint_id: EndpointId,
        mut addresses: Vec<SocketAddr>,
        delay_nanos: u64,
        ttl_nanos: u64,
        failed: bool,
    ) -> Result<DiscoveryRecordSnapshot, DiscoveryError> {
        if ttl_nanos == 0 || (!failed && addresses.is_empty()) || (failed && !addresses.is_empty())
        {
            return Err(DiscoveryError("invalid discovery record".to_owned()));
        }
        addresses.sort();
        addresses.dedup();
        let now = nanos(self.inner.kernel.now())?;
        let available_nanos = now
            .checked_add(delay_nanos)
            .ok_or_else(|| DiscoveryError("discovery availability overflow".to_owned()))?;
        let expires_nanos = now
            .checked_add(ttl_nanos)
            .ok_or_else(|| DiscoveryError("discovery expiry overflow".to_owned()))?;
        let resource = self
            .inner
            .kernel
            .acquire_resource(ResourceKind::DiscoveryRecord, Some(self.inner.max_records))
            .map_err(|error| DiscoveryError(error.to_string()))?;
        let generation = {
            let mut state = self.inner.state.lock().expect("discovery lock poisoned");
            state.next_generation = state
                .next_generation
                .checked_add(1)
                .ok_or_else(|| DiscoveryError("discovery generation exhausted".to_owned()))?;
            state.next_generation
        };
        let weak = Arc::downgrade(&self.inner);
        let record_id = record.to_owned();
        let (_, expiry) = self
            .inner
            .kernel
            .schedule_cancellable_at(
                Duration::from_nanos(expires_nanos),
                EventClass::Infrastructure,
                move || {
                    expire_record(&weak, &record_id, generation);
                    Ok(())
                },
            )
            .map_err(|error| DiscoveryError(error.to_string()))?;
        let last_updated_micros = self
            .inner
            .context
            .wall_clock()
            .now_system()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| DiscoveryError("wall clock precedes unix epoch".to_owned()))?
            .as_micros()
            .try_into()
            .map_err(|_| DiscoveryError("wall clock does not fit microseconds".to_owned()))?;
        let value = DiscoveryRecord {
            endpoint_name: endpoint_name.to_owned(),
            endpoint_id,
            addresses: addresses.clone(),
            failed,
            available_nanos,
            expires_nanos,
            last_updated_micros,
            generation,
            _expiry: expiry,
            _resource: resource,
        };
        self.inner
            .state
            .lock()
            .expect("discovery lock poisoned")
            .records
            .insert(record.to_owned(), value);
        let snapshot = DiscoveryRecordSnapshot {
            provider: self.inner.id.clone(),
            record: record.to_owned(),
            endpoint: endpoint_name.to_owned(),
            addresses,
            failed,
            available_nanos,
            expires_nanos,
        };
        self.inner
            .trace(&snapshot, if failed { "failed" } else { "published" })?;
        Ok(snapshot)
    }

    pub fn withdraw(
        &self,
        record: &str,
        endpoint_name: &str,
    ) -> Result<DiscoveryRecordSnapshot, DiscoveryError> {
        let now = nanos(self.inner.kernel.now())?;
        let removed = self
            .inner
            .state
            .lock()
            .expect("discovery lock poisoned")
            .records
            .remove(record);
        let snapshot = removed.map_or_else(
            || DiscoveryRecordSnapshot {
                provider: self.inner.id.clone(),
                record: record.to_owned(),
                endpoint: endpoint_name.to_owned(),
                addresses: Vec::new(),
                failed: false,
                available_nanos: now,
                expires_nanos: now,
            },
            |value| DiscoveryRecordSnapshot {
                provider: self.inner.id.clone(),
                record: record.to_owned(),
                endpoint: value.endpoint_name,
                addresses: value.addresses,
                failed: value.failed,
                available_nanos: value.available_nanos,
                expires_nanos: value.expires_nanos,
            },
        );
        self.inner.trace(&snapshot, "withdrawn")?;
        Ok(snapshot)
    }

    pub fn snapshots(&self) -> Vec<DiscoveryRecordSnapshot> {
        let state = self.inner.state.lock().expect("discovery lock poisoned");
        state
            .records
            .iter()
            .map(|(id, value)| DiscoveryRecordSnapshot {
                provider: self.inner.id.clone(),
                record: id.clone(),
                endpoint: value.endpoint_name.clone(),
                addresses: value.addresses.clone(),
                failed: value.failed,
                available_nanos: value.available_nanos,
                expires_nanos: value.expires_nanos,
            })
            .collect()
    }

    pub fn clear(&self) -> Result<(), DiscoveryError> {
        let error = {
            let mut state = self.inner.state.lock().expect("discovery lock poisoned");
            state.records.clear();
            state.deferred_error.take()
        };
        if let Some(error) = error {
            Err(DiscoveryError(error))
        } else {
            Ok(())
        }
    }
}

impl AddressLookup for DeterministicDiscovery {
    fn resolve(&self, endpoint_id: EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
        let mut candidates = self
            .inner
            .state
            .lock()
            .expect("discovery lock poisoned")
            .records
            .iter()
            .filter(|(_, record)| record.endpoint_id == endpoint_id)
            .map(|(id, record)| ResolutionCandidate {
                record: id.clone(),
                endpoint_name: record.endpoint_name.clone(),
                endpoint_id: record.endpoint_id,
                addresses: record.addresses.clone(),
                failed: record.failed,
                available_nanos: record.available_nanos,
                expires_nanos: record.expires_nanos,
                last_updated_micros: record.last_updated_micros,
                generation: record.generation,
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            (left.available_nanos, &left.record).cmp(&(right.available_nanos, &right.record))
        });
        let scheduled = candidates
            .into_iter()
            .map(|candidate| {
                let (sender, receiver) = oneshot::channel();
                let inner = self.inner.clone();
                let deadline = candidate.available_nanos;
                let scheduled = self.inner.kernel.schedule_cancellable_at(
                    Duration::from_nanos(deadline),
                    EventClass::Infrastructure,
                    move || {
                        let value = resolve_candidate(&inner, &candidate);
                        let _ = sender.send(value);
                        Ok(())
                    },
                );
                match scheduled {
                    Ok((_, event)) => ScheduledResolution {
                        receiver,
                        _event: Some(event),
                    },
                    Err(error) => {
                        self.inner
                            .state
                            .lock()
                            .expect("discovery lock poisoned")
                            .deferred_error = Some(error.to_string());
                        ScheduledResolution {
                            receiver,
                            _event: None,
                        }
                    }
                }
            })
            .collect::<Vec<_>>();
        let values = stream::iter(scheduled)
            .then(|scheduled| async move {
                let ScheduledResolution { receiver, _event } = scheduled;
                let value = receiver.await.ok().flatten();
                drop(_event);
                value
            })
            .filter_map(|value| value)
            .boxed();
        Some(values)
    }
}

fn resolve_candidate(
    inner: &DiscoveryInner,
    candidate: &ResolutionCandidate,
) -> Option<Result<Item, Error>> {
    let now = nanos(inner.kernel.now()).unwrap_or(u64::MAX);
    let current = inner
        .state
        .lock()
        .expect("discovery lock poisoned")
        .records
        .get(&candidate.record)
        .is_some_and(|record| {
            record.generation == candidate.generation && now < candidate.expires_nanos
        });
    if !current {
        inner.trace_candidate(candidate, "stale_suppressed");
        return None;
    }
    if candidate.failed {
        inner.trace_candidate(candidate, "failed");
        return Some(Err(Error::from_err(
            PROVENANCE,
            io::Error::other(format!(
                "provider {} record {} failed",
                inner.id, candidate.record
            )),
        )));
    }
    inner.trace_candidate(candidate, "resolved");
    Some(Ok(Item::new(
        EndpointInfo::new(candidate.endpoint_id).with_ip_addrs(candidate.addresses.clone()),
        PROVENANCE,
        Some(candidate.last_updated_micros),
    )))
}

impl DiscoveryInner {
    fn trace(
        &self,
        snapshot: &DiscoveryRecordSnapshot,
        transition: &str,
    ) -> Result<(), DiscoveryError> {
        self.context
            .trace()
            .record(
                self.context
                    .clock()
                    .elapsed_nanos()
                    .map_err(|error| DiscoveryError(format!("discovery clock failed: {error}")))?,
                TraceContext {
                    discovery: Some(self.id.clone()),
                    ..TraceContext::default()
                },
                TraceEventKind::DiscoveryRecord {
                    record: snapshot.record.clone(),
                    transition: transition.to_owned(),
                    endpoint: snapshot.endpoint.clone(),
                    addresses: snapshot.addresses.iter().map(ToString::to_string).collect(),
                    available_nanos: snapshot.available_nanos,
                    expires_nanos: snapshot.expires_nanos,
                },
            )
            .map_err(|error| DiscoveryError(error.to_string()))?;
        Ok(())
    }

    fn trace_candidate(&self, candidate: &ResolutionCandidate, transition: &str) {
        let snapshot = DiscoveryRecordSnapshot {
            provider: self.id.clone(),
            record: candidate.record.clone(),
            endpoint: candidate.endpoint_name.clone(),
            addresses: candidate.addresses.clone(),
            failed: candidate.failed,
            available_nanos: candidate.available_nanos,
            expires_nanos: candidate.expires_nanos,
        };
        if let Err(error) = self.trace(&snapshot, transition) {
            self.state
                .lock()
                .expect("discovery lock poisoned")
                .deferred_error = Some(error.to_string());
        }
    }
}

fn expire_record(inner: &Weak<DiscoveryInner>, record: &str, generation: u64) {
    let Some(inner) = inner.upgrade() else {
        return;
    };
    let expired = {
        let mut state = inner.state.lock().expect("discovery lock poisoned");
        let matches = state
            .records
            .get(record)
            .is_some_and(|value| value.generation == generation);
        matches.then(|| {
            state
                .records
                .remove(record)
                .expect("record remains present")
        })
    };
    if let Some(value) = expired {
        let snapshot = DiscoveryRecordSnapshot {
            provider: inner.id.clone(),
            record: record.to_owned(),
            endpoint: value.endpoint_name,
            addresses: value.addresses,
            failed: value.failed,
            available_nanos: value.available_nanos,
            expires_nanos: value.expires_nanos,
        };
        if let Err(error) = inner.trace(&snapshot, "expired") {
            inner
                .state
                .lock()
                .expect("discovery lock poisoned")
                .deferred_error = Some(error.to_string());
        }
    }
}

fn nanos(duration: Duration) -> Result<u64, DiscoveryError> {
    duration
        .as_nanos()
        .try_into()
        .map_err(|_| DiscoveryError("virtual time does not fit nanoseconds".to_owned()))
}

/// Deterministic provider configuration, resource, clock, or trace failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryError(String);

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for DiscoveryError {}
