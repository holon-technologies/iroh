//! Metrics exposed by the server.

use iroh_metrics::{Counter, Gauge, MetricsGroup};

/// Counters exposed by iroh-dns-server.
#[derive(Debug, Default, MetricsGroup)]
#[metrics(name = "dns_server")]
#[non_exhaustive]
pub struct Metrics {
    /// Number of pkarr relay puts that updated the stored packet.
    pub pkarr_publish_update: Counter,
    /// Number of pkarr relay puts that did not change the stored packet.
    pub pkarr_publish_noop: Counter,
    /// Total number of DNS requests across all transports.
    pub dns_requests: Counter,
    /// Number of DNS requests received over UDP.
    pub dns_requests_udp: Counter,
    /// Number of DNS requests received over HTTPS (DoH).
    pub dns_requests_https: Counter,
    /// Current number of admitted UDP DNS request tasks.
    pub dns_udp_requests_active: Gauge,
    /// Number of UDP DNS requests dropped because request capacity was full.
    pub dns_udp_requests_rejected: Counter,
    /// Current number of admitted DNS TCP connection tasks.
    pub dns_tcp_connections_active: Gauge,
    /// Number of DNS TCP connections closed because connection capacity was full.
    pub dns_tcp_connections_rejected: Counter,
    /// Number of DNS lookups that returned at least one answer.
    pub dns_lookup_success: Counter,
    /// Number of DNS lookups that returned no answers.
    pub dns_lookup_notfound: Counter,
    /// Number of DNS lookups that failed with an error.
    pub dns_lookup_error: Counter,
    /// Number of HTTP requests served.
    pub http_requests: Counter,
    /// Number of HTTP requests that returned a 2xx status code.
    pub http_requests_success: Counter,
    /// Number of HTTP requests that returned a non-2xx status code.
    pub http_requests_error: Counter,
    /// Cumulative duration of all HTTP requests, in milliseconds.
    pub http_requests_duration_ms: Counter,
    /// Current number of admitted HTTP and HTTPS connections.
    pub http_connections_active: Gauge,
    /// Number of HTTP(S) connections rejected because capacity was full.
    pub http_connections_rejected_capacity: Counter,
    /// Number of HTTP(S) connections rejected by the global accept rate.
    pub http_connections_rejected_rate: Counter,
    /// Current number of admitted HTTP requests.
    pub http_requests_active: Gauge,
    /// Number of HTTP requests rejected because request capacity was full.
    pub http_requests_rejected_capacity: Counter,
    /// Number of HTTP requests rejected by the per-IP rate policy.
    pub http_requests_rejected_rate: Counter,
    /// Current bounded per-IP rate-limit entry count.
    pub http_rate_limit_entries: Gauge,
    /// Number of signed packets newly inserted into the store.
    pub store_packets_inserted: Counter,
    /// Number of signed packets removed from the store.
    ///
    /// Currently always at 0 because the removal API is not used.
    pub store_packets_removed: Counter,
    /// Number of times an existing signed packet was replaced by a newer one.
    pub store_packets_updated: Counter,
    /// Number of signed packets removed by the eviction task.
    pub store_packets_expired: Counter,
    /// Number of corrupt persistent rows detected.
    pub store_corrupt_rows: Counter,
    /// Number of packet-store actor or eviction failures.
    pub store_background_failures: Counter,
    /// Current number of zones in the main cache
    pub cache_zones: Gauge,
    /// Current number of zones in the DHT cache
    pub cache_zones_dht: Gauge,
}

impl hickory_server::server::AdmissionObserver for Metrics {
    fn admitted(&self, kind: hickory_server::server::AdmissionKind) {
        match kind {
            hickory_server::server::AdmissionKind::UdpRequest => {
                self.dns_udp_requests_active.inc();
            }
            hickory_server::server::AdmissionKind::TcpConnection => {
                self.dns_tcp_connections_active.inc();
            }
        }
    }

    fn released(&self, kind: hickory_server::server::AdmissionKind) {
        match kind {
            hickory_server::server::AdmissionKind::UdpRequest => {
                self.dns_udp_requests_active.dec();
            }
            hickory_server::server::AdmissionKind::TcpConnection => {
                self.dns_tcp_connections_active.dec();
            }
        }
    }

    fn rejected(&self, rejection: hickory_server::server::AdmissionRejection) {
        match rejection {
            hickory_server::server::AdmissionRejection::UdpRequestCapacity => {
                self.dns_udp_requests_rejected.inc();
            }
            hickory_server::server::AdmissionRejection::TcpConnectionCapacity => {
                self.dns_tcp_connections_rejected.inc();
            }
        }
    }
}
