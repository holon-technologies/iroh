//! Pkarr packet store used to resolve DNS queries.

use std::{collections::BTreeMap, num::NonZeroUsize, path::Path, sync::Arc, time::Duration};

use hickory_server::proto::{
    ProtoError,
    rr::{Name, RecordSet, RecordType, RrKey},
};
use krikos_dns::pkarr::{SignedPacket, SignedPacketVerifyError, Timestamp};
use lru::LruCache;
use mainline::{Dht, DhtBuilder, MutableItem};
use n0_error::{Result, StdResultExt};
pub(crate) use signed_packets::{NonZeroDuration, Options, StoreShutdownError};
use tokio::sync::Mutex;
use tracing::{debug, trace, warn};
use ttl_cache::TtlCache;

use self::signed_packets::SignedPacketStore;
use crate::{
    config::BootstrapOption,
    metrics::Metrics,
    util::{PublicKeyBytes, signed_packet_to_hickory_records_without_origin},
};

mod signed_packets;

/// Cache up to 1 million pkarr zones by default
const DEFAULT_CACHE_CAPACITY: usize = 1024 * 1024;
/// Default TTL for DHT cache entries
const DHT_CACHE_TTL: Duration = Duration::from_secs(300);

/// Where a new pkarr packet comes from
pub(crate) enum PacketSource {
    /// Received via HTTPS relay PUT
    PkarrPublish,
}

/// A store for pkarr signed packets.
///
/// Packets are stored in the persistent `SignedPacketStore`, and cached on-demand in an in-memory LRU
/// cache used for resolving DNS queries.
#[derive(Debug, Clone)]
pub(crate) struct ZoneStore {
    cache: Arc<Mutex<ZoneCache>>,
    store: Arc<SignedPacketStore>,
    dht: Option<Dht>,
    metrics: Arc<Metrics>,
}

impl ZoneStore {
    /// Returns whether persistent storage is ready to serve all rows.
    pub(crate) fn is_ready(&self) -> bool {
        self.store.is_ready()
    }

    /// Signals both persistent-store workers to stop.
    pub(crate) fn start_shutdown(&self) {
        self.store.start_shutdown();
    }

    /// Cancels and joins both persistent-store workers.
    pub(crate) async fn shutdown(&self) -> std::result::Result<(), StoreShutdownError> {
        self.start_shutdown();
        self.store.shutdown().await
    }

    /// Create a persistent store
    pub(crate) fn persistent(
        path: impl AsRef<Path>,
        options: Options,
        metrics: Arc<Metrics>,
    ) -> Result<Self> {
        let packet_store = SignedPacketStore::persistent(path, options, metrics.clone())?;
        Ok(Self::new(packet_store, metrics))
    }

    /// Create an in-memory store.
    #[cfg(test)]
    pub(crate) fn in_memory(options: Options, metrics: Arc<Metrics>) -> Result<Self> {
        let packet_store = SignedPacketStore::in_memory(options, metrics.clone())?;
        Ok(Self::new(packet_store, metrics))
    }

    /// Configure a mainline DHT client for resolution of packets as a fallback.
    ///
    /// This will be used only as a fallback if there is no local info available.
    ///
    /// Optionally set custom bootstrap nodes. If `bootstrap` is empty it will use the default
    /// mainline bootstrap nodes.
    pub(crate) fn with_mainline_fallback(self, bootstrap: BootstrapOption) -> Result<Self> {
        let mut builder = DhtBuilder::default();
        if let BootstrapOption::Custom(ref nodes) = bootstrap {
            builder.bootstrap(nodes);
        }
        let dht = finish_mainline_build(builder.build())?;
        Ok(Self {
            dht: Some(dht),
            ..self
        })
    }

    /// Create a new zone store.
    fn new(store: SignedPacketStore, metrics: Arc<Metrics>) -> Self {
        let zone_cache = ZoneCache::new(DEFAULT_CACHE_CAPACITY, metrics.clone());
        Self {
            store: Arc::new(store),
            cache: Arc::new(Mutex::new(zone_cache)),
            dht: None,
            metrics,
        }
    }

    /// Resolve a DNS query.
    #[tracing::instrument("resolve", skip_all, fields(pubkey=%pubkey,name=%name,typ=%record_type))]
    pub(crate) async fn resolve(
        &self,
        pubkey: &PublicKeyBytes,
        name: &Name,
        record_type: RecordType,
    ) -> Result<Option<Arc<RecordSet>>> {
        trace!("store resolve");

        // Check cache first (short lock scope)
        {
            let mut cache = self.cache.lock().await;
            if let Some(rset) = cache.resolve(pubkey, name, record_type) {
                debug!(
                    len = rset.records_without_rrsigs().count(),
                    "resolved from cache"
                );
                return Ok(Some(rset));
            }
        }

        // Check persistent store
        if let Some(packet) = self.store.get(pubkey).await? {
            trace!(packet_timestamp = ?packet.timestamp(), "store hit");
            let mut cache = self.cache.lock().await;
            let result = cache.insert_and_resolve(&packet, name, record_type);
            return match result {
                Ok(Some(rset)) => {
                    debug!(
                        len = rset.records_without_rrsigs().count(),
                        "resolved from store"
                    );
                    Ok(Some(rset))
                }
                Ok(None) => {
                    debug!("resolved to zone, but no matching records in zone");
                    Ok(None)
                }
                Err(err) => {
                    warn!("failed to retrieve zone after inserting in cache: {err:#?}");
                    Err(err)
                }
            };
        };

        if let Some(dht) = self.dht.as_ref() {
            debug!("DHT resolve {}", pubkey.to_z32());
            let maybe_item = dht
                .clone()
                .as_async()
                .get_mutable_most_recent(pubkey.as_bytes(), None)
                .await;
            match maybe_item {
                // Keep the rejection distinguishable from a plain miss: a packet that
                // was returned but does not verify against the key we asked for is the
                // observable trace of an attempt to poison this resolver, and it is the
                // only signal the verification produces.
                Some(item) => match mutable_item_to_signed_packet(&item, pubkey) {
                    Ok(packet) => {
                        debug!("DHT resolve successful {:?}", packet);
                        return self.cache.lock().await.insert_and_resolve_dht(
                            &packet,
                            name,
                            record_type,
                        );
                    }
                    Err(err) => {
                        self.metrics.dht_packets_rejected.inc();
                        warn!(
                            pubkey = %pubkey.to_z32(),
                            "DHT returned a packet that does not verify against the requested key: {err:#}"
                        );
                    }
                },
                None => debug!("DHT resolve failed"),
            }
        }
        Ok(None)
    }

    /// Get the latest signed packet for a pubkey.
    // allow unused async: this will be async soon.
    #[allow(clippy::unused_async)]
    pub(crate) async fn get_signed_packet(
        &self,
        pubkey: &PublicKeyBytes,
    ) -> Result<Option<SignedPacket>> {
        self.store.get(pubkey).await
    }

    /// Insert a signed packet into the cache and the store.
    ///
    /// Returns whether this produced an update, i.e. whether the packet is the newest for its
    /// pubkey.
    // allow unused async: this will be async soon.
    #[allow(clippy::unused_async)]
    pub(crate) async fn insert(
        &self,
        signed_packet: SignedPacket,
        _source: PacketSource,
    ) -> Result<bool> {
        let pubkey = PublicKeyBytes::from_signed_packet(&signed_packet);
        if self.store.upsert(signed_packet).await? {
            self.metrics.pkarr_publish_update.inc();
            self.cache.lock().await.remove(&pubkey);
            Ok(true)
        } else {
            self.metrics.pkarr_publish_noop.inc();
            Ok(false)
        }
    }
}

fn finish_mainline_build(result: std::io::Result<Dht>) -> Result<Dht> {
    result.anyerr()
}

/// Convert a mainline [`MutableItem`] to a [`SignedPacket`], for the key we asked for.
///
/// `expected` is the key the lookup was issued for, and the packet is verified against
/// it. This binding cannot be left to `mainline`: it checks a mutable item's signature
/// against the key carried in the *response* and then stores the queried target
/// verbatim, so all it establishes is that some key signed the value. Without the check
/// here, any DHT node could answer a lookup with a packet signed under a key it
/// controls, and those records would be re-served under the queried name.
fn mutable_item_to_signed_packet(
    item: &MutableItem,
    expected: &PublicKeyBytes,
) -> Result<SignedPacket, SignedPacketVerifyError> {
    let timestamp = u64::try_from(item.seq()).map_err(|_| {
        n0_error::e!(SignedPacketVerifyError::InvalidTimestamp {
            timestamp: item.seq(),
        })
    })?;
    // Built from `expected` rather than `item.key()`, so a packet signed by any other
    // key fails signature verification instead of being silently re-attributed.
    SignedPacket::from_parts(
        expected.as_bytes(),
        item.signature(),
        Timestamp::from_micros(timestamp),
        item.value(),
    )
}

#[derive(derive_more::Debug)]
struct ZoneCache {
    /// Cache for explicitly added entries
    cache: LruCache<PublicKeyBytes, CachedZone>,
    /// Cache for DHT entries, this must have a finite TTL
    /// so we don't cache stale entries indefinitely.
    #[debug("dht_cache")]
    dht_cache: TtlCache<PublicKeyBytes, CachedZone>,
    #[debug("metrics")]
    metrics: Arc<Metrics>,
}

impl ZoneCache {
    fn new(cap: usize, metrics: Arc<Metrics>) -> Self {
        let cache = LruCache::new(NonZeroUsize::new(cap).expect("capacity must be larger than 0"));
        let dht_cache = TtlCache::new(cap);
        Self {
            cache,
            dht_cache,
            metrics,
        }
    }

    fn resolve(
        &mut self,
        pubkey: &PublicKeyBytes,
        name: &Name,
        record_type: RecordType,
    ) -> Option<Arc<RecordSet>> {
        let zone = if let Some(zone) = self.cache.get(pubkey) {
            trace!("cache hit {}", pubkey.to_z32());
            zone
        } else {
            let zone = self.dht_cache.get(pubkey)?;
            trace!("dht cache hit {}", pubkey.to_z32());
            zone
        };
        zone.resolve(name, record_type)
    }

    fn insert_and_resolve(
        &mut self,
        signed_packet: &SignedPacket,
        name: &Name,
        record_type: RecordType,
    ) -> Result<Option<Arc<RecordSet>>> {
        let pubkey = PublicKeyBytes::from_signed_packet(signed_packet);
        self.insert(signed_packet)?;
        Ok(self.resolve(&pubkey, name, record_type))
    }

    fn insert_and_resolve_dht(
        &mut self,
        signed_packet: &SignedPacket,
        name: &Name,
        record_type: RecordType,
    ) -> Result<Option<Arc<RecordSet>>> {
        let pubkey = PublicKeyBytes::from_signed_packet(signed_packet);
        let zone = CachedZone::from_signed_packet(signed_packet).anyerr()?;
        let res = zone.resolve(name, record_type);
        self.dht_cache.insert(pubkey, zone, DHT_CACHE_TTL);
        self.metrics
            .cache_zones_dht
            .set(i64::try_from(self.dht_cache.iter().count()).unwrap_or(i64::MAX));
        Ok(res)
    }

    fn insert(&mut self, signed_packet: &SignedPacket) -> Result<()> {
        let pubkey = PublicKeyBytes::from_signed_packet(signed_packet);
        if self
            .cache
            .peek(&pubkey)
            .map(|old| old.is_newer_than(signed_packet))
            .unwrap_or(false)
        {
            trace!("insert skip: cached is newer");
            Ok(())
        } else {
            self.cache.put(
                pubkey,
                CachedZone::from_signed_packet(signed_packet).anyerr()?,
            );
            self.metrics
                .cache_zones
                .set(i64::try_from(self.cache.len()).unwrap_or(i64::MAX));
            trace!("inserted into cache");
            Ok(())
        }
    }

    fn remove(&mut self, pubkey: &PublicKeyBytes) {
        self.cache.pop(pubkey);
        self.dht_cache.remove(pubkey);
        self.metrics
            .cache_zones
            .set(i64::try_from(self.cache.len()).unwrap_or(i64::MAX));
        self.metrics
            .cache_zones_dht
            .set(i64::try_from(self.dht_cache.iter().count()).unwrap_or(i64::MAX));
    }
}

#[derive(Debug)]
struct CachedZone {
    timestamp: Timestamp,
    records: BTreeMap<RrKey, Arc<RecordSet>>,
}

impl CachedZone {
    fn from_signed_packet(signed_packet: &SignedPacket) -> Result<Self, ProtoError> {
        let (_label, records) =
            signed_packet_to_hickory_records_without_origin(signed_packet, |_| true)?;
        Ok(Self {
            records,
            timestamp: signed_packet.timestamp(),
        })
    }

    fn is_newer_than(&self, signed_packet: &SignedPacket) -> bool {
        self.timestamp > signed_packet.timestamp()
    }

    fn resolve(&self, name: &Name, record_type: RecordType) -> Option<Arc<RecordSet>> {
        trace!(name=%name, typ=%record_type, "resolve in zone");
        let key = RrKey::new(name.into(), record_type);
        self.records.get(&key).cloned()
    }
}

#[cfg(test)]
mod tests {
    use krikos::{RelayUrl, SecretKey, endpoint_info::EndpointInfo};
    use n0_tracing_test::traced_test;
    use rand::{CryptoRng, RngExt, SeedableRng};

    use super::*;

    #[tokio::test]
    #[traced_test]
    async fn store_eviction() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0);
        let options = Options {
            eviction: NonZeroDuration::new(Duration::from_millis(100))
                .expect("test eviction age is nonzero"),
            eviction_interval: NonZeroDuration::new(Duration::from_millis(100))
                .expect("test eviction interval is nonzero"),
            max_batch_time: NonZeroDuration::new(Duration::from_millis(100))
                .expect("test batch time is nonzero"),
            ..Default::default()
        };
        let store = ZoneStore::in_memory(options, Default::default())?;
        let signed_packet = random_signed_packet(&mut rng)?;
        let key = PublicKeyBytes::from_signed_packet(&signed_packet);

        store
            .insert(signed_packet, PacketSource::PkarrPublish)
            .await?;

        tokio::time::sleep(Duration::from_secs(1)).await;
        let mut evicted = false;
        for _ in 0..10 {
            if store.get_signed_packet(&key).await?.is_none() {
                evicted = true;
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        store.shutdown().await.anyerr()?;
        assert!(evicted, "store did not evict packet");
        Ok(())
    }

    /// A DHT response must be bound to the key we asked for.
    ///
    /// `mainline` verifies a mutable item's signature against the key carried in the
    /// response, not against the queried target, and stores the target verbatim — so
    /// "signed by somebody" is all it guarantees. Any DHT node can therefore answer a
    /// lookup for one key with a packet correctly signed under a key it controls. Were
    /// that accepted, its records would be re-served under the queried name, which is
    /// exactly the binding pkarr exists to provide.
    #[test]
    fn dht_item_signed_by_another_key_is_rejected() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(1);
        // A perfectly valid packet — just not the one that was asked for.
        let attacker_packet = random_signed_packet(&mut rng)?;
        let attacker_key = PublicKeyBytes::from_signed_packet(&attacker_packet);
        // pkarr carries the packet timestamp as the BEP-0044 sequence number.
        let item = MutableItem::new_signed_unchecked(
            *attacker_key.as_bytes(),
            attacker_packet.signature().to_bytes(),
            attacker_packet.encoded_packet(),
            i64::try_from(attacker_packet.timestamp().as_micros())
                .expect("pkarr timestamp fits in a mainline sequence number"),
            None,
        );

        // Resolved under the key that actually signed it: accepted.
        mutable_item_to_signed_packet(&item, &attacker_key)
            .expect("a packet signed by the key we asked for must be accepted");

        // Resolved under someone else's key: refused.
        let victim = PublicKeyBytes::from_signed_packet(&random_signed_packet(&mut rng)?);
        mutable_item_to_signed_packet(&item, &victim)
            .expect_err("a packet signed by an unrelated key must be refused");
        Ok(())
    }

    #[test]
    fn mainline_construction_failure_is_reported() {
        let error = finish_mainline_build(Err(std::io::Error::other(
            "synthetic DHT thread spawn failure",
        )))
        .expect_err("DHT construction failure must remain an operating error");

        assert!(
            error
                .to_string()
                .contains("synthetic DHT thread spawn failure")
        );
    }

    #[test]
    fn negative_mainline_sequence_is_rejected() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(2);
        let key = PublicKeyBytes::from_signed_packet(&random_signed_packet(&mut rng)?);
        let item = MutableItem::new_signed_unchecked(*key.as_bytes(), [0; 64], &[], -1, None);

        let error = mutable_item_to_signed_packet(&item, &key)
            .expect_err("negative mainline sequence must not wrap into a timestamp");

        assert!(matches!(
            error,
            SignedPacketVerifyError::InvalidTimestamp { timestamp: -1, .. }
        ));
        Ok(())
    }

    fn random_signed_packet<R: CryptoRng + ?Sized>(rng: &mut R) -> Result<SignedPacket> {
        let secret_key = SecretKey::from_bytes(&rng.random());
        let relay_url: RelayUrl = "https://relay.example.".parse()?;
        let endpoint_info = EndpointInfo::new(secret_key.public()).with_relay_url(relay_url);
        let packet = endpoint_info.to_pkarr_signed_packet(&secret_key, 30)?;
        Ok(packet)
    }
}
