//! The state kept for each network path to a remote endpoint.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};

#[cfg(not(wasm_browser))]
use iroh_runtime::Instant;
use n0_error::e;
#[cfg(wasm_browser)]
use n0_future::time::Instant;
use rustc_hash::FxHashMap;
use tokio::sync::oneshot;
use tracing::trace;

use super::{Source, TransportAddrInfo, TransportAddrUsage};
use crate::{address_lookup::AddressLookupFailed, metrics::SocketMetrics, socket::transports};

/// Maximum number of non-relay paths we keep around per endpoint.
pub(super) const MAX_NON_RELAY_PATHS: usize = 30;
/// Maximum number of relay paths retained per endpoint.
pub(super) const MAX_RELAY_PATHS: usize = 4;
/// Maximum number of custom transport paths retained per endpoint.
pub(super) const MAX_CUSTOM_PATHS: usize = 8;
/// Maximum number of paths retained per endpoint across all transports.
pub(super) const MAX_PATHS: usize = MAX_NON_RELAY_PATHS + MAX_RELAY_PATHS;
/// Maximum candidates consumed from one insertion call or one source.
const MAX_CANDIDATES_PER_SOURCE: usize = 30;
/// Maximum distinct source identities retained for one remote endpoint.
const MAX_DISTINCT_SOURCES: usize = 16;
/// Maximum source attributions retained for one path.
const MAX_SOURCES_PER_PATH: usize = 8;
/// Maximum unresolved callers retained while address lookup is in flight.
const MAX_PENDING_RESOLVE_REQUESTS: usize = 32;

/// Maximum number of inactive non-relay paths we keep around per endpoint.
///
/// These are paths that at one point been opened and are now closed.
#[cfg(test)]
pub(super) const MAX_INACTIVE_NON_RELAY_PATHS: usize = 10;

/// Map of all paths that we are aware of for a remote endpoint.
///
/// Also stores a list of resolve requests which are triggered once at least one path is known,
/// or once this struct is notified of a failed Address Lookup run.
#[derive(Debug)]
pub(super) struct RemotePathState {
    /// All possible paths we are aware of.
    ///
    /// These paths might be entirely impossible to use, since they are added by Address Lookup
    /// mechanisms. The are only potentially usable.
    paths: FxHashMap<transports::Addr, PathState>,
    /// Pending resolve requests from [`Self::resolve_remote`].
    pending_resolve_requests: VecDeque<oneshot::Sender<Result<(), AddressLookupFailed>>>,
    metrics: Arc<SocketMetrics>,
    next_admission_sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PathLimit {
    CandidatesPerCall,
    CandidatesPerSource,
    DistinctSources,
    SourcesPerPath,
    Total,
    Relay,
    NonRelay,
    Custom,
    Protected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PathAdmissionOutcome {
    Inserted,
    Updated,
    Evicted { limit: PathLimit },
    Rejected { limit: PathLimit },
}

#[derive(Debug, Clone, Copy)]
enum PathTransportKind {
    Ip,
    Relay,
    Custom,
}

/// Describes the usability of this path, i.e. whether it has ever been opened,
/// when it was closed, or if it has never been usable.
#[derive(Debug, Default)]
pub(super) enum PathStatus {
    /// This path is open and active.
    Open,
    /// This path was once opened, but was abandoned at the given [`Instant`].
    Inactive(Instant),
    /// This path was never usable (we attempted holepunching and it didn't work).
    Unusable,
    /// We have not yet attempted holepunching, or holepunching is currently in
    /// progress, so we do not know the usability of this path.
    #[default]
    Unknown,
}

impl RemotePathState {
    pub(super) fn new(metrics: Arc<SocketMetrics>) -> Self {
        Self {
            paths: Default::default(),
            pending_resolve_requests: Default::default(),
            metrics,
            next_admission_sequence: 0,
        }
    }

    pub(super) fn to_remote_addrs(&self) -> Vec<TransportAddrInfo> {
        self.paths
            .iter()
            .flat_map(|(addr, state)| {
                let usage = match state.status {
                    PathStatus::Open => TransportAddrUsage::Active,
                    PathStatus::Inactive(_) | PathStatus::Unusable | PathStatus::Unknown => {
                        TransportAddrUsage::Inactive
                    }
                };
                Some(TransportAddrInfo {
                    addr: addr.clone().into(),
                    usage,
                })
            })
            .collect()
    }

    /// Insert a new address of an open path into our list of paths.
    ///
    /// This will emit pending resolve requests and trigger pruning paths.
    pub(super) fn insert_open_path(
        &mut self,
        addr: transports::Addr,
        source: Source,
        now: Instant,
    ) -> PathAdmissionOutcome {
        let transport_kind = match &addr {
            transports::Addr::Ip(_) => PathTransportKind::Ip,
            transports::Addr::Relay(_, _) => PathTransportKind::Relay,
            transports::Addr::Custom(_) => PathTransportKind::Custom,
        };
        let outcome = self.insert_candidate(addr, source, now, PathStatus::Open);
        if !matches!(outcome, PathAdmissionOutcome::Rejected { .. }) {
            match transport_kind {
                PathTransportKind::Ip => self.metrics.transport_ip_paths_added.inc(),
                PathTransportKind::Relay => self.metrics.transport_relay_paths_added.inc(),
                PathTransportKind::Custom => self.metrics.transport_custom_paths_added.inc(),
            };
            self.emit_pending_resolve_requests(None);
        }
        outcome
    }

    /// Mark a path as abandoned.
    ///
    /// If this path does not exist, it does nothing to the
    /// `RemotePathState`
    pub(super) fn abandoned_path(&mut self, addr: &transports::Addr, now: Instant) {
        if let Some(state) = self.paths.get_mut(addr) {
            if matches!(state.status, PathStatus::Open) {
                match addr {
                    transports::Addr::Ip(_) => self.metrics.transport_ip_paths_removed.inc(),
                    transports::Addr::Relay(_, _) => {
                        self.metrics.transport_relay_paths_removed.inc()
                    }
                    transports::Addr::Custom(_) => {
                        self.metrics.transport_custom_paths_removed.inc()
                    }
                };
            }
            match state.status {
                PathStatus::Open | PathStatus::Inactive(_) => {
                    state.status = PathStatus::Inactive(now);
                }
                PathStatus::Unusable | PathStatus::Unknown => {
                    state.status = PathStatus::Unusable;
                }
            }
        }
    }

    /// Inserts multiple addresses of unknown status into our list of potential paths.
    ///
    /// If this caused the path set to transition from empty to non-empty, any
    /// pending resolve requests are woken with `Ok(())`. Inserts that add no
    /// new paths (empty iterator, or only duplicates) are a no-op: waking
    /// pending requests while the path set is still empty would send a bogus
    /// `AddressLookupFailed::NoResults` while an address lookup is in flight.
    pub(super) fn insert_multiple(
        &mut self,
        addrs: impl Iterator<Item = transports::Addr>,
        source: Source,
        now: Instant,
    ) -> Vec<PathAdmissionOutcome> {
        let was_empty = self.paths.is_empty();
        let mut outcomes = Vec::with_capacity(MAX_CANDIDATES_PER_SOURCE);
        for (index, addr) in addrs.enumerate() {
            if index >= MAX_CANDIDATES_PER_SOURCE {
                self.metrics.path_candidates_rejected.inc();
                outcomes.push(PathAdmissionOutcome::Rejected {
                    limit: PathLimit::CandidatesPerCall,
                });
                break;
            }
            outcomes.push(self.insert_candidate(addr, source.clone(), now, PathStatus::Unknown));
        }
        trace!("added addressing information");
        if was_empty && !self.paths.is_empty() {
            self.emit_pending_resolve_requests(None);
        }
        outcomes
    }

    /// Sends back on `tx` once a possible path to the remote is known.
    ///
    /// If there already is a known path, `Ok(())` is returned immediately. Otherwise an
    /// address lookup is performed and the result is sent back once that
    /// completes. [`AddressLookupFailed`] is sent if there are no known paths.
    pub(super) fn resolve_remote(&mut self, tx: oneshot::Sender<Result<(), AddressLookupFailed>>) {
        if !self.paths.is_empty() {
            tx.send(Ok(())).ok();
        } else if self.pending_resolve_requests.len() >= MAX_PENDING_RESOLVE_REQUESTS {
            self.metrics.pending_resolve_requests_rejected.inc();
            tx.send(Err(e!(AddressLookupFailed::ResolveCapacityFull {
                maximum: MAX_PENDING_RESOLVE_REQUESTS,
            })))
            .ok();
        } else {
            self.pending_resolve_requests.push_back(tx);
        }
    }

    /// Returns `true` if there are any queued resolve requests from [`Self::resolve_remote`].
    pub(super) fn resolve_requests_is_empty(&self) -> bool {
        self.pending_resolve_requests.is_empty()
    }

    /// Notifies that a Address Lookup run has finished.
    ///
    /// This will emit pending resolve requests.
    pub(super) fn address_lookup_finished(&mut self, result: Result<(), AddressLookupFailed>) {
        self.emit_pending_resolve_requests(result.err());
    }

    /// Returns an iterator over the addresses of all paths.
    pub(super) fn addrs(&self) -> impl Iterator<Item = &transports::Addr> {
        self.paths.keys()
    }

    /// Returns whether this stores any addresses.
    pub(super) fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    /// Replies to all pending resolve requests.
    ///
    /// This is a no-op if no requests are queued. Replies `Ok` if we have any known paths,
    /// otherwise with the provided `address_lookup_error` or with [`AddressLookupFailed::NoResults`].
    fn emit_pending_resolve_requests(&mut self, address_lookup_error: Option<AddressLookupFailed>) {
        if self.pending_resolve_requests.is_empty() {
            return;
        }
        let result = match (self.paths.is_empty(), address_lookup_error) {
            (false, _) => Ok(()),
            (true, Some(err)) => Err(err),
            (true, None) => Err(e!(AddressLookupFailed::NoResults { errors: Vec::new() })),
        };
        for tx in self.pending_resolve_requests.drain(..) {
            tx.send(result.clone()).ok();
        }
    }

    fn insert_candidate(
        &mut self,
        addr: transports::Addr,
        source: Source,
        now: Instant,
        status: PathStatus,
    ) -> PathAdmissionOutcome {
        if let Some(existing) = self.paths.get(&addr) {
            let adds_attribution = !existing.sources.contains_key(&source);
            let attribution_limit =
                if adds_attribution && existing.sources.len() >= MAX_SOURCES_PER_PATH {
                    Some(PathLimit::SourcesPerPath)
                } else if adds_attribution
                    && self
                        .paths
                        .values()
                        .filter(|state| state.sources.contains_key(&source))
                        .count()
                        >= MAX_CANDIDATES_PER_SOURCE
                {
                    Some(PathLimit::CandidatesPerSource)
                } else if adds_attribution
                    && !self
                        .paths
                        .values()
                        .any(|state| state.sources.contains_key(&source))
                    && self.distinct_source_count() >= MAX_DISTINCT_SOURCES
                {
                    Some(PathLimit::DistinctSources)
                } else {
                    None
                };
            if let Some(limit) = attribution_limit {
                if matches!(status, PathStatus::Open) {
                    let existing = self
                        .paths
                        .get_mut(&addr)
                        .expect("existing path must remain present during an open transition");
                    existing.status = PathStatus::Open;
                    return PathAdmissionOutcome::Updated;
                }
                self.metrics.path_candidates_rejected.inc();
                return PathAdmissionOutcome::Rejected { limit };
            }
            let Some(existing) = self.paths.get_mut(&addr) else {
                return PathAdmissionOutcome::Rejected {
                    limit: PathLimit::Protected,
                };
            };
            existing.sources.insert(source, now);
            if matches!(status, PathStatus::Open) {
                existing.status = PathStatus::Open;
            }
            return PathAdmissionOutcome::Updated;
        }

        let paths_for_source = self
            .paths
            .values()
            .filter(|state| state.sources.contains_key(&source))
            .count();
        if paths_for_source >= MAX_CANDIDATES_PER_SOURCE {
            self.metrics.path_candidates_rejected.inc();
            return PathAdmissionOutcome::Rejected {
                limit: PathLimit::CandidatesPerSource,
            };
        }
        let source_is_known = self
            .paths
            .values()
            .any(|state| state.sources.contains_key(&source));
        if !source_is_known && self.distinct_source_count() >= MAX_DISTINCT_SOURCES {
            self.metrics.path_candidates_rejected.inc();
            return PathAdmissionOutcome::Rejected {
                limit: PathLimit::DistinctSources,
            };
        }

        let admission_sequence = self.next_admission_sequence;
        self.next_admission_sequence = self.next_admission_sequence.saturating_add(1);
        let state = PathState {
            sources: HashMap::from([(source, now)]),
            status,
            admission_sequence,
        };

        let violated = violated_limit(&self.paths, &addr);
        if let Some(limit) = violated {
            let candidate = worst_evictable_path(&self.paths, limit);
            let Some(candidate) = candidate else {
                self.metrics.path_candidates_rejected.inc();
                return PathAdmissionOutcome::Rejected {
                    limit: PathLimit::Protected,
                };
            };
            let candidate_state = &self.paths[&candidate];
            if retention_cmp(&addr, &state, &candidate, candidate_state).is_le() {
                self.metrics.path_candidates_rejected.inc();
                return PathAdmissionOutcome::Rejected { limit };
            }
            self.paths.remove(&candidate);
            self.metrics.path_candidates_evicted.inc();
            self.paths.insert(addr, state);
            return PathAdmissionOutcome::Evicted { limit };
        }

        self.paths.insert(addr, state);
        PathAdmissionOutcome::Inserted
    }

    fn distinct_source_count(&self) -> usize {
        self.paths
            .values()
            .flat_map(|state| state.sources.keys())
            .collect::<HashSet<_>>()
            .len()
    }
}

/// The state of a single path to the remote endpoint.
///
/// Each path is identified by the destination [`transports::Addr`] and they are stored in
/// the [`RemotePathState`] map in [`RemoteStateActor`].
///
/// [`RemoteStateActor`]: super::RemoteStateActor
#[derive(Debug, Default)]
pub(super) struct PathState {
    /// How we learned about this path, and when.
    ///
    /// We keep track of only the latest [`Instant`] for each [`Source`], keeping the size
    /// of the map of sources down to one entry per type of source.
    pub(super) sources: HashMap<Source, Instant>,
    /// The usability status of this path.
    pub(super) status: PathStatus,
    /// Stable order assigned when this path was first admitted.
    admission_sequence: u64,
}

/// Prunes the non-relay paths in the paths HashMap.
///
/// Only prunes if the number of non-relay paths is above [`MAX_NON_RELAY_PATHS`].
///
/// Keeps paths that are open or of unknown status.
///
/// Always prunes paths that have unsuccessfully holepunched.
///
/// Keeps [`MAX_INACTIVE_NON_RELAY_PATHS`] of the most recently closed paths
/// that are not currently being used but have successfully been
/// holepunched previously.
///
/// This all ensures that:
///
/// - We do not have unbounded growth of paths.
/// - If we have many paths for this remote, we prune the paths that cannot hole punch.
/// - We do not prune holepunched paths that are currently not in use too quickly. For example, if a large number of untested paths are added at once, we will not immediately prune all of the unused, but valid, paths at once.
#[cfg(test)]
fn prune_non_relay_paths(paths: &mut FxHashMap<transports::Addr, PathState>) -> usize {
    let initial_len = paths.len();
    // if the total number of paths is less than the max, bail early
    if paths.len() < MAX_NON_RELAY_PATHS {
        prune_to_hard_limits(paths);
        return initial_len.saturating_sub(paths.len());
    }

    let primary_paths: Vec<_> = paths.iter().filter(|(addr, _)| !addr.is_relay()).collect();

    // if the total number of non-relay paths is less than the max, bail early
    if primary_paths.len() < MAX_NON_RELAY_PATHS {
        prune_to_hard_limits(paths);
        return initial_len.saturating_sub(paths.len());
    }

    // paths that were opened at one point but have previously been closed
    let mut inactive = Vec::with_capacity(primary_paths.len());
    // paths where we attempted hole punching but it not successful
    let mut failed = Vec::with_capacity(primary_paths.len());

    for (addr, state) in primary_paths {
        match state.status {
            PathStatus::Inactive(t) => {
                // paths where holepunching succeeded at one point, but the path was closed.
                inactive.push((addr.clone(), t));
            }
            PathStatus::Unusable => {
                // paths where holepunching has been attempted and failed.
                failed.push(addr.clone());
            }
            _ => {
                // ignore paths that are open or the status is unknown
            }
        }
    }

    failed.sort();

    // All paths are bad, don't prune all of them.
    //
    // This implies that `inactive` is empty.
    if failed.len() == paths.len() {
        // leave the max number of non-relay paths
        failed.truncate(paths.len().saturating_sub(MAX_NON_RELAY_PATHS));
    }

    // sort the potentially prunable from most recently closed to least recently closed
    inactive.sort_by(|(addr_a, time_a), (addr_b, time_b)| {
        time_b.cmp(time_a).then_with(|| addr_a.cmp(addr_b))
    });

    // Prune the "oldest" closed paths.
    let old_inactive =
        inactive.split_off(inactive.len().saturating_sub(MAX_INACTIVE_NON_RELAY_PATHS));

    // collect all the paths that should be pruned
    let must_prune: HashSet<_> = failed
        .into_iter()
        .chain(old_inactive.into_iter().map(|(addr, _)| addr))
        .collect();

    paths.retain(|addr, _| !must_prune.contains(addr));
    prune_to_hard_limits(paths);
    initial_len.saturating_sub(paths.len())
}

#[cfg(test)]
fn prune_to_hard_limits(paths: &mut FxHashMap<transports::Addr, PathState>) {
    while let Some(limit) = current_violated_limit(paths) {
        let Some(candidate) = worst_evictable_path(paths, limit) else {
            break;
        };
        paths.remove(&candidate);
    }
}

#[cfg(test)]
fn current_violated_limit(paths: &FxHashMap<transports::Addr, PathState>) -> Option<PathLimit> {
    let relay = paths.keys().filter(|addr| addr.is_relay()).count();
    let custom = paths
        .keys()
        .filter(|addr| matches!(addr, transports::Addr::Custom(_)))
        .count();
    let non_relay = paths.len().saturating_sub(relay);
    if relay > MAX_RELAY_PATHS {
        Some(PathLimit::Relay)
    } else if custom > MAX_CUSTOM_PATHS {
        Some(PathLimit::Custom)
    } else if non_relay > MAX_NON_RELAY_PATHS {
        Some(PathLimit::NonRelay)
    } else if paths.len() > MAX_PATHS {
        Some(PathLimit::Total)
    } else {
        None
    }
}

fn violated_limit(
    paths: &FxHashMap<transports::Addr, PathState>,
    new_addr: &transports::Addr,
) -> Option<PathLimit> {
    let relay = paths.keys().filter(|addr| addr.is_relay()).count();
    let custom = paths
        .keys()
        .filter(|addr| matches!(addr, transports::Addr::Custom(_)))
        .count();
    let new_is_relay = new_addr.is_relay();
    let new_is_custom = matches!(new_addr, transports::Addr::Custom(_));
    let non_relay = paths.len().saturating_sub(relay);
    if new_is_relay && relay >= MAX_RELAY_PATHS {
        Some(PathLimit::Relay)
    } else if new_is_custom && custom >= MAX_CUSTOM_PATHS {
        Some(PathLimit::Custom)
    } else if !new_is_relay && non_relay >= MAX_NON_RELAY_PATHS {
        Some(PathLimit::NonRelay)
    } else if paths.len() >= MAX_PATHS {
        Some(PathLimit::Total)
    } else {
        None
    }
}

fn worst_evictable_path(
    paths: &FxHashMap<transports::Addr, PathState>,
    limit: PathLimit,
) -> Option<transports::Addr> {
    paths
        .iter()
        .filter(|(addr, state)| {
            !matches!(state.status, PathStatus::Open)
                && match limit {
                    PathLimit::Relay => addr.is_relay(),
                    PathLimit::Custom => matches!(addr, transports::Addr::Custom(_)),
                    PathLimit::NonRelay => !addr.is_relay(),
                    PathLimit::Total => true,
                    _ => false,
                }
        })
        .min_by(|(addr_a, state_a), (addr_b, state_b)| {
            retention_cmp(addr_a, state_a, addr_b, state_b)
        })
        .map(|(addr, _)| addr.clone())
}

fn retention_cmp(
    addr_a: &transports::Addr,
    state_a: &PathState,
    addr_b: &transports::Addr,
    state_b: &PathState,
) -> std::cmp::Ordering {
    status_rank(&state_a.status)
        .cmp(&status_rank(&state_b.status))
        .then_with(|| status_freshness(state_a).cmp(&status_freshness(state_b)))
        .then_with(|| source_rank(state_a).cmp(&source_rank(state_b)))
        .then_with(|| source_freshness(state_a).cmp(&source_freshness(state_b)))
        .then_with(|| state_b.admission_sequence.cmp(&state_a.admission_sequence))
        .then_with(|| addr_b.cmp(addr_a))
}

fn status_freshness(state: &PathState) -> Option<Instant> {
    match state.status {
        PathStatus::Inactive(instant) => Some(instant),
        PathStatus::Open | PathStatus::Unusable | PathStatus::Unknown => None,
    }
}

fn status_rank(status: &PathStatus) -> u8 {
    match status {
        PathStatus::Open => 4,
        PathStatus::Inactive(_) => 3,
        PathStatus::Unknown => 2,
        PathStatus::Unusable => 1,
    }
}

fn source_rank(state: &PathState) -> u8 {
    state
        .sources
        .keys()
        .map(|source| match source {
            Source::Connection => 3,
            Source::App => 2,
            Source::AddressLookup { .. } => 1,
        })
        .max()
        .unwrap_or(0)
}

fn source_freshness(state: &PathState) -> Option<Instant> {
    state.sources.values().copied().max()
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        time::Duration,
    };

    use iroh_base::{CustomAddr, RelayUrl, SecretKey};
    use rand::{RngExt, SeedableRng};

    use super::*;

    fn ip_addr(port: u16) -> transports::Addr {
        transports::Addr::Ip(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into())
    }

    fn relay_addr(seed: u8) -> transports::Addr {
        let relay_url: RelayUrl = url::Url::parse("https://localhost")
            .expect("test relay URL is valid")
            .into();
        let endpoint_id = SecretKey::from_bytes(&[seed; 32]).public();
        transports::Addr::Relay(relay_url, endpoint_id)
    }

    fn assert_path_bounds(state: &RemotePathState) {
        let relay_count = state.paths.keys().filter(|addr| addr.is_relay()).count();
        let custom_count = state
            .paths
            .keys()
            .filter(|addr| matches!(addr, transports::Addr::Custom(_)))
            .count();
        assert!(state.paths.len() <= MAX_PATHS);
        assert!(relay_count <= MAX_RELAY_PATHS);
        assert!(state.paths.len().saturating_sub(relay_count) <= MAX_NON_RELAY_PATHS);
        assert!(custom_count <= MAX_CUSTOM_PATHS);

        let sources = state
            .paths
            .values()
            .flat_map(|path| path.sources.keys())
            .collect::<HashSet<_>>();
        assert!(sources.len() <= MAX_DISTINCT_SOURCES);
        assert!(
            state
                .paths
                .values()
                .all(|path| path.sources.len() <= MAX_SOURCES_PER_PATH)
        );
        for source in sources {
            assert!(
                state
                    .paths
                    .values()
                    .filter(|path| path.sources.contains_key(source))
                    .count()
                    <= MAX_CANDIDATES_PER_SOURCE
            );
        }
    }

    fn path_state_inactive(closed: Instant) -> PathState {
        PathState {
            sources: HashMap::new(),
            status: PathStatus::Inactive(closed),
            admission_sequence: 0,
        }
    }

    fn path_state_unusable() -> PathState {
        PathState {
            sources: HashMap::new(),
            status: PathStatus::Unusable,
            admission_sequence: 0,
        }
    }

    #[test]
    fn test_prune_under_max_paths() {
        let mut paths = FxHashMap::default();
        for i in 0..20 {
            paths.insert(ip_addr(i), PathState::default());
        }

        prune_non_relay_paths(&mut paths);
        assert_eq!(
            20,
            paths.len(),
            "should not prune when under MAX_NON_RELAY_PATHS"
        );
    }

    #[test]
    fn test_prune_at_max_paths_no_prunable() {
        let mut paths = FxHashMap::default();
        // All paths are active (never abandoned), so none should be pruned
        for i in 0..MAX_NON_RELAY_PATHS {
            paths.insert(ip_addr(i as u16), PathState::default());
        }

        prune_non_relay_paths(&mut paths);
        assert_eq!(
            MAX_NON_RELAY_PATHS,
            paths.len(),
            "should not prune active paths"
        );
    }

    #[test]
    fn test_prune_failed_holepunch() {
        let mut paths = FxHashMap::default();

        // Add 20 active paths
        for i in 0..20 {
            paths.insert(ip_addr(i), PathState::default());
        }

        // Add 15 failed holepunch paths (must_prune)
        for i in 20..35 {
            paths.insert(ip_addr(i), path_state_unusable());
        }

        prune_non_relay_paths(&mut paths);

        // All failed holepunch paths should be pruned
        assert_eq!(20, paths.len());
        for i in 0..20 {
            assert!(paths.contains_key(&ip_addr(i)));
        }
        for i in 20..35 {
            assert!(!paths.contains_key(&ip_addr(i)));
        }
    }

    #[test]
    fn test_prune_keeps_most_recent_inactive() {
        let mut paths = FxHashMap::default();
        let now = Instant::now();

        // Add 15 active paths
        for i in 0..15 {
            paths.insert(ip_addr(i), PathState::default());
        }

        // Add 20 inactive paths with different abandon times
        // Ports 15-34, with port 34 being most recently abandoned
        for i in 0..20 {
            let abandoned_time = now - Duration::from_secs((20 - i) as u64);
            paths.insert(ip_addr(15 + i as u16), path_state_inactive(abandoned_time));
        }

        assert_eq!(35, paths.len());
        prune_non_relay_paths(&mut paths);

        // Should keep 15 active + 10 most recently abandoned
        assert_eq!(25, paths.len());

        // Active paths should remain
        for i in 0..15 {
            assert!(paths.contains_key(&ip_addr(i)));
        }

        // Most recently abandoned (ports 25-34) should remain
        for i in 25..35 {
            assert!(paths.contains_key(&ip_addr(i)), "port {} should be kept", i);
        }

        // Oldest abandoned (ports 15-24) should be pruned
        for i in 15..25 {
            assert!(
                !paths.contains_key(&ip_addr(i)),
                "port {} should be pruned",
                i
            );
        }
    }

    #[test]
    fn test_prune_mixed_must_and_can_prune() {
        let mut paths = FxHashMap::default();
        let now = Instant::now();

        // Add 15 active paths
        for i in 0..15 {
            paths.insert(ip_addr(i), PathState::default());
        }

        // Add 5 failed holepunch paths
        for i in 15..20 {
            paths.insert(ip_addr(i), path_state_unusable());
        }

        // Add 15 usable but abandoned paths
        for i in 0..15 {
            let abandoned_time = now - Duration::from_secs((15 - i) as u64);
            paths.insert(ip_addr(20 + i as u16), path_state_inactive(abandoned_time));
        }

        assert_eq!(35, paths.len());
        prune_non_relay_paths(&mut paths);

        // Remove all failed paths -> down to 30
        // Keep MAX_INACTIVE_NON_RELAY_PATHS, eg remove 5 usable but abandoned paths -> down to 20
        assert_eq!(20, paths.len());

        // Active paths should remain
        for i in 0..15 {
            assert!(paths.contains_key(&ip_addr(i)));
        }

        // Failed holepunch should be pruned
        for i in 15..20 {
            assert!(!paths.contains_key(&ip_addr(i)));
        }

        // Most recently abandoned (ports 30-34) should remain
        for i in 30..35 {
            assert!(paths.contains_key(&ip_addr(i)), "port {} should be kept", i);
        }
    }

    #[test]
    fn test_prune_enforces_total_and_relay_limits() {
        let mut paths = FxHashMap::default();

        // Add 25 IP paths (under MAX_NON_RELAY_PATHS)
        for i in 0..25 {
            paths.insert(ip_addr(i), path_state_unusable());
        }

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let relay_url: RelayUrl = url::Url::parse("https://localhost")
            .expect("should be valid url")
            .into();
        // Add 10 relay addresses
        for _ in 0..10 {
            let id = SecretKey::from_bytes(&rng.random()).public();
            let relay_addr = transports::Addr::Relay(relay_url.clone(), id);
            paths.insert(relay_addr, PathState::default());
        }

        assert_eq!(35, paths.len()); // 25 IP + 10 relay
        prune_non_relay_paths(&mut paths);

        assert!(paths.len() <= 34, "total retained paths must be bounded");
        assert!(
            paths.keys().filter(|addr| addr.is_relay()).count() <= 4,
            "relay paths must be independently bounded"
        );
    }

    #[test]
    fn insert_multiple_bounds_unknown_and_custom_paths() {
        let mut state = RemotePathState::new(Default::default());
        state.insert_multiple(
            (0..40).map(ip_addr),
            Source::AddressLookup {
                name: "unknown-flood".to_string(),
            },
            Instant::now(),
        );
        assert!(state.paths.len() <= MAX_NON_RELAY_PATHS);

        let custom = (0..20).map(|id| {
            transports::Addr::Custom(CustomAddr::try_from_parts(id, &[id as u8]).unwrap())
        });
        state.insert_multiple(custom, Source::App, Instant::now());
        assert!(
            state
                .paths
                .keys()
                .filter(|addr| matches!(addr, transports::Addr::Custom(_)))
                .count()
                <= 8
        );
        assert!(state.paths.len() <= 34);
    }

    #[test]
    fn protected_open_paths_reject_the_new_candidate() {
        let mut state = RemotePathState::new(Default::default());
        for port in 0..MAX_NON_RELAY_PATHS as u16 {
            assert!(matches!(
                state.insert_open_path(ip_addr(port), Source::Connection, Instant::now()),
                PathAdmissionOutcome::Inserted
            ));
        }

        let rejected = ip_addr(50_000);
        let outcomes =
            state.insert_multiple([rejected.clone()].into_iter(), Source::App, Instant::now());
        assert_eq!(
            outcomes,
            vec![PathAdmissionOutcome::Rejected {
                limit: PathLimit::Protected
            }]
        );
        assert_eq!(state.paths.len(), MAX_NON_RELAY_PATHS);
        assert!(!state.paths.contains_key(&rejected));
    }

    #[test]
    fn opening_an_existing_path_overrides_attribution_pressure() {
        let mut state = RemotePathState::new(Default::default());
        let now = Instant::now();
        let addr = ip_addr(42);
        for index in 0..MAX_SOURCES_PER_PATH {
            state.insert_multiple(
                [addr.clone()].into_iter(),
                Source::AddressLookup {
                    name: format!("lookup-{index}"),
                },
                now,
            );
        }
        assert!(matches!(
            state.paths.get(&addr).map(|state| &state.status),
            Some(PathStatus::Unknown)
        ));

        assert_eq!(
            state.insert_open_path(addr.clone(), Source::Connection, now),
            PathAdmissionOutcome::Updated
        );
        assert!(matches!(
            state.paths.get(&addr).map(|state| &state.status),
            Some(PathStatus::Open)
        ));
        assert_path_bounds(&state);
    }

    #[test]
    fn explicit_application_path_evicts_lookup_path_deterministically() {
        let mut state = RemotePathState::new(Default::default());
        state.insert_multiple(
            (0..MAX_NON_RELAY_PATHS as u16).map(ip_addr),
            Source::AddressLookup {
                name: "lookup".to_string(),
            },
            Instant::now(),
        );
        let app_addr = ip_addr(55_000);
        let outcomes =
            state.insert_multiple([app_addr.clone()].into_iter(), Source::App, Instant::now());
        assert_eq!(
            outcomes,
            vec![PathAdmissionOutcome::Evicted {
                limit: PathLimit::NonRelay
            }]
        );
        assert!(state.paths.contains_key(&app_addr));
        assert_eq!(state.paths.len(), MAX_NON_RELAY_PATHS);
    }

    #[test]
    fn duplicate_updates_cannot_bypass_candidates_per_source() {
        let mut state = RemotePathState::new(Default::default());
        let now = Instant::now();
        let mut addrs = (0..MAX_NON_RELAY_PATHS as u16)
            .map(ip_addr)
            .collect::<Vec<_>>();
        addrs.extend((1..=MAX_RELAY_PATHS as u8).map(relay_addr));
        for addr in &addrs {
            state.insert_open_path(addr.clone(), Source::Connection, now);
        }

        let source = Source::AddressLookup {
            name: "one-source".to_string(),
        };
        for addr in addrs.iter().take(MAX_CANDIDATES_PER_SOURCE) {
            assert_eq!(
                state.insert_multiple([addr.clone()].into_iter(), source.clone(), now),
                vec![PathAdmissionOutcome::Updated]
            );
        }
        assert_eq!(
            state.insert_multiple(
                [addrs[MAX_CANDIDATES_PER_SOURCE].clone()].into_iter(),
                source,
                now,
            ),
            vec![PathAdmissionOutcome::Rejected {
                limit: PathLimit::CandidatesPerSource,
            }]
        );
    }

    #[test]
    fn duplicate_updates_cannot_bypass_distinct_source_limit() {
        let mut state = RemotePathState::new(Default::default());
        let now = Instant::now();
        let addrs = (0..MAX_NON_RELAY_PATHS as u16)
            .map(ip_addr)
            .collect::<Vec<_>>();
        state.insert_multiple(addrs.iter().cloned(), Source::App, now);

        for (index, addr) in addrs.iter().enumerate().take(MAX_DISTINCT_SOURCES - 1) {
            let source = Source::AddressLookup {
                name: format!("source-{index}"),
            };
            assert_eq!(
                state.insert_multiple([addr.clone()].into_iter(), source, now),
                vec![PathAdmissionOutcome::Updated]
            );
        }

        let rejected_source = Source::AddressLookup {
            name: "source-overflow".to_string(),
        };
        assert_eq!(
            state.insert_multiple(
                [addrs[MAX_DISTINCT_SOURCES].clone()].into_iter(),
                rejected_source,
                now,
            ),
            vec![PathAdmissionOutcome::Rejected {
                limit: PathLimit::DistinctSources,
            }]
        );
    }

    #[test]
    fn seeded_transitions_preserve_bounds_and_replay_deterministically() {
        for seed in 0..32_u64 {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
            let mut first = RemotePathState::new(Default::default());
            let mut replay = RemotePathState::new(Default::default());
            let now = Instant::now();

            for step in 0..256_u64 {
                let addr = match rng.random_range(0..3) {
                    0 => ip_addr(rng.random_range(1..=u16::MAX)),
                    1 => transports::Addr::Custom(
                        CustomAddr::try_from_parts(step, &step.to_le_bytes())
                            .expect("generated custom address is bounded"),
                    ),
                    _ => relay_addr(rng.random_range(1..=u8::MAX)),
                };
                let source = match rng.random_range(0..3) {
                    0 => Source::Connection,
                    1 => Source::App,
                    _ => Source::AddressLookup {
                        name: format!("lookup-{}", rng.random_range(0..32)),
                    },
                };
                match rng.random_range(0..3) {
                    0 => {
                        first.insert_open_path(addr.clone(), source.clone(), now);
                        replay.insert_open_path(addr, source, now);
                    }
                    1 => {
                        first.insert_multiple([addr.clone()].into_iter(), source.clone(), now);
                        replay.insert_multiple([addr].into_iter(), source, now);
                    }
                    _ => {
                        first.abandoned_path(&addr, now);
                        replay.abandoned_path(&addr, now);
                    }
                }

                assert_path_bounds(&first);
                assert_path_bounds(&replay);
                let mut first_addrs = first.paths.keys().cloned().collect::<Vec<_>>();
                let mut replay_addrs = replay.paths.keys().cloned().collect::<Vec<_>>();
                first_addrs.sort();
                replay_addrs.sort();
                assert_eq!(first_addrs, replay_addrs);
            }
        }
    }

    #[test]
    fn test_prune_preserves_never_dialed() {
        let mut paths = FxHashMap::default();

        // Add 20 never-dialed paths (PathStatus::Unknown)
        for i in 0..20 {
            paths.insert(ip_addr(i), PathState::default());
        }

        // Add 15 failed paths to trigger pruning
        for i in 20..35 {
            paths.insert(ip_addr(i), path_state_unusable());
        }

        prune_non_relay_paths(&mut paths);

        // Never-dialed paths should be preserved
        for i in 0..20 {
            assert!(paths.contains_key(&ip_addr(i)));
        }
    }

    #[test]
    fn test_prune_all_paths_failed() {
        let mut paths = FxHashMap::default();

        // Add 40 failed holepunch paths (all paths have failed)
        for i in 0..40 {
            paths.insert(ip_addr(i), path_state_unusable());
        }

        assert_eq!(40, paths.len());
        prune_non_relay_paths(&mut paths);

        // Should keep MAX_NON_RELAY_PATHS instead of pruning everything
        // This prevents catastrophic loss of all path information
        assert_eq!(
            MAX_NON_RELAY_PATHS,
            paths.len(),
            "should keep MAX_NON_RELAY_PATHS when all paths failed"
        );
    }

    #[test]
    fn test_insert_open_path() {
        let mut state = RemotePathState::new(Default::default());
        let addr = ip_addr(1000);
        let source = Source::Connection;

        assert!(state.is_empty());

        state.insert_open_path(addr.clone(), source.clone(), Instant::now());

        assert!(!state.is_empty());
        assert!(state.paths.contains_key(&addr));
        let path = &state.paths[&addr];
        assert!(matches!(path.status, PathStatus::Open));
        assert_eq!(path.sources.len(), 1);
        assert!(path.sources.contains_key(&source));
    }

    #[test]
    fn test_abandoned_path() {
        let metrics = Arc::new(SocketMetrics::default());
        let mut state = RemotePathState::new(metrics.clone());

        // Test: Open goes to Inactive
        let addr_open = ip_addr(1000);
        state.insert_open_path(addr_open.clone(), Source::Connection, Instant::now());
        assert!(matches!(state.paths[&addr_open].status, PathStatus::Open));
        assert_eq!(metrics.transport_ip_paths_added.get(), 1);

        state.abandoned_path(&addr_open, Instant::now());
        assert!(matches!(
            state.paths[&addr_open].status,
            PathStatus::Inactive(_)
        ));
        assert_eq!(metrics.transport_ip_paths_added.get(), 1);
        assert_eq!(metrics.transport_ip_paths_removed.get(), 1);

        // Test: Inactive stays Inactive
        state.abandoned_path(&addr_open, Instant::now());
        assert!(matches!(
            state.paths[&addr_open].status,
            PathStatus::Inactive(_)
        ));
        assert_eq!(metrics.transport_ip_paths_added.get(), 1);
        assert_eq!(metrics.transport_ip_paths_removed.get(), 1);

        // Test: Unknown goes to Unusable
        let addr_unknown = ip_addr(2000);
        state.insert_multiple(
            [addr_unknown.clone()].into_iter(),
            Source::Connection,
            Instant::now(),
        );
        assert!(matches!(
            state.paths[&addr_unknown].status,
            PathStatus::Unknown
        ));
        assert_eq!(metrics.transport_ip_paths_added.get(), 1);
        assert_eq!(metrics.transport_ip_paths_removed.get(), 1);

        state.abandoned_path(&addr_unknown, Instant::now());
        assert!(matches!(
            state.paths[&addr_unknown].status,
            PathStatus::Unusable
        ));
        assert_eq!(metrics.transport_ip_paths_added.get(), 1);
        assert_eq!(metrics.transport_ip_paths_removed.get(), 1);

        // Test: Unusable stays Unusable
        state.abandoned_path(&addr_unknown, Instant::now());
        assert!(matches!(
            state.paths[&addr_unknown].status,
            PathStatus::Unusable
        ));
        assert_eq!(metrics.transport_ip_paths_added.get(), 1);
        assert_eq!(metrics.transport_ip_paths_removed.get(), 1);

        // Test: Unusable can go to open
        state.insert_open_path(addr_unknown.clone(), Source::Connection, Instant::now());
        assert!(matches!(
            state.paths[&addr_unknown].status,
            PathStatus::Open
        ));
        assert_eq!(metrics.transport_ip_paths_added.get(), 2);
        assert_eq!(metrics.transport_ip_paths_removed.get(), 1);
    }

    /// An empty `insert_multiple` must not drain pending resolve requests.
    ///
    /// This reproduces the race where multiple concurrent `connect_with_opts`
    /// calls send `ResolveRemote` messages with empty addrs. The first pushes
    /// a tx, then the second's `insert_multiple([])` used to drain that tx
    /// with `NoResults { errors: [] }`, even though an address lookup was
    /// still in flight and would shortly have resolved it.
    #[test]
    fn empty_insert_does_not_drain_pending() {
        let metrics = Arc::new(SocketMetrics::default());
        let mut state = RemotePathState::new(metrics);

        let (tx, mut rx) = oneshot::channel();
        state.resolve_remote(tx);

        // Second concurrent resolve arrives with empty addrs (no app-provided
        // addresses) while address lookup is still running.
        state.insert_multiple(std::iter::empty(), Source::App, Instant::now());

        assert!(
            rx.try_recv().is_err(),
            "pending tx must stay pending while paths are empty and lookup is in flight"
        );

        // When real addresses arrive, the tx resolves Ok.
        state.insert_multiple([ip_addr(4242)].into_iter(), Source::App, Instant::now());
        let resolved = rx.try_recv().expect("tx should have been woken");
        assert!(resolved.is_ok(), "expected Ok once a path was added");
    }

    /// `address_lookup_finished(Ok(()))` drains pending requests with `NoResults` when no paths are known.
    ///
    /// This is the "lookup done but nothing was found" signal and it must
    /// still reach callers.
    #[test]
    fn address_lookup_finished_empty_emits_no_results() {
        let metrics = Arc::new(SocketMetrics::default());
        let mut state = RemotePathState::new(metrics);

        let (tx, mut rx) = oneshot::channel();
        state.resolve_remote(tx);

        state.address_lookup_finished(Ok(()));

        let resolved = rx.try_recv().expect("tx should have been woken");
        assert!(matches!(
            resolved,
            Err(AddressLookupFailed::NoResults { .. })
        ));
    }

    #[test]
    fn pending_resolve_requests_are_bounded_with_typed_backpressure() {
        let metrics = Arc::new(SocketMetrics::default());
        let mut state = RemotePathState::new(metrics.clone());
        let mut pending = Vec::new();
        for _ in 0..MAX_PENDING_RESOLVE_REQUESTS {
            let (tx, rx) = oneshot::channel();
            state.resolve_remote(tx);
            pending.push(rx);
        }
        let (rejected_tx, mut rejected_rx) = oneshot::channel();
        state.resolve_remote(rejected_tx);

        assert!(matches!(
            rejected_rx.try_recv(),
            Ok(Err(AddressLookupFailed::ResolveCapacityFull { maximum, .. }))
                if maximum == MAX_PENDING_RESOLVE_REQUESTS
        ));
        assert_eq!(
            state.pending_resolve_requests.len(),
            MAX_PENDING_RESOLVE_REQUESTS
        );
        assert_eq!(metrics.pending_resolve_requests_rejected.get(), 1);
        assert!(
            pending
                .iter_mut()
                .all(|receiver| receiver.try_recv().is_err())
        );
    }
}
