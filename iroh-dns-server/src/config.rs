//! Configuration for the [`Server`].
//!
//! [`Config`] is the entry point. It is usually loaded from a TOML file via [`Config::load`].
//!
//! [`Server`]: crate::Server

use std::{
    env, fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::{NonZeroU32, NonZeroUsize},
    path::{Path, PathBuf},
    time::Duration,
};

use ipnet::IpNet;
use n0_error::{Result, StdResultExt};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::store::{NonZeroDuration, Options};
pub use crate::{
    dns::DnsConfig,
    http::{CertMode, HttpConfig, HttpsConfig, RateLimitConfig},
};

const DEFAULT_METRICS_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9117);

/// Top-level configuration for the server.
///
/// Usually loaded from a TOML file via [`Self::load`]. The [`Default`] impl
/// produces a config suitable for local development and testing.
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Config {
    /// Configuration for the HTTP listener.
    ///
    /// When `None`, no HTTP listener is started.
    pub http: Option<HttpConfig>,
    /// Configuration for the HTTPS listener.
    ///
    /// When `None`, no HTTPS listener is started.
    pub https: Option<HttpsConfig>,
    /// Configuration for the DNS listener.
    pub dns: DnsConfig,
    /// Configuration for the metrics server.
    ///
    /// When `None`, the metrics server binds to a default address. To disable
    /// the metrics server entirely, use [`MetricsConfig::disabled`].
    pub metrics: Option<MetricsConfig>,

    /// Configuration for the mainline DHT fallback.
    ///
    /// When `None` or disabled, packets that are not present in the local store
    /// are not looked up on the mainline DHT.
    pub mainline: Option<MainlineConfig>,

    /// Configuration for the signed-packet zone store.
    ///
    /// When `None`, the defaults from [`StoreConfig::default`] are used.
    pub zone_store: Option<StoreConfig>,

    /// Rate limit applied to `PUT /pkarr` requests.
    #[serde(default)]
    pub pkarr_put_rate_limit: RateLimitConfig,

    /// Hard process resource limits.
    ///
    /// Omitted fields use finite production defaults. Per-IP rate limiting may be disabled, but
    /// these global limits are always enforced.
    #[serde(default)]
    pub limits: LimitsConfig,

    /// Location where the server stores its data.
    ///
    /// When `None`, [`Self::data_dir`] falls back to the `IROH_DNS_DATA_DIR`
    /// environment variable, then to the platform's standard data directory.
    pub data_dir: Option<PathBuf>,
}

const DEFAULT_MAX_DNS_UDP_REQUESTS: usize = 1_024;
const DEFAULT_MAX_DNS_TCP_CONNECTIONS: usize = 256;
const DEFAULT_MAX_HTTP_CONNECTIONS: usize = 512;
const DEFAULT_MAX_HTTP_REQUESTS: usize = 1_024;
const DEFAULT_MAX_HTTP2_STREAMS_PER_CONNECTION: u32 = 32;
const DEFAULT_HTTP_ACCEPT_RATE_PER_SECOND: f64 = 200.0;
const DEFAULT_HTTP_ACCEPT_BURST: usize = 400;
const DEFAULT_MAX_RATE_LIMIT_ENTRIES: usize = 4_096;
const DEFAULT_MAX_HTTP_BODY_BYTES: usize = 65_535;
const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_STORE_BATCH_SIZE: usize = 65_536;

/// Hard process resource limits for DNS and HTTP ingress.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
#[non_exhaustive]
pub struct LimitsConfig {
    /// Maximum DNS UDP requests executing concurrently.
    pub max_dns_udp_requests: usize,
    /// Maximum accepted DNS TCP connections.
    pub max_dns_tcp_connections: usize,
    /// Maximum accepted HTTP and HTTPS connections, combined.
    pub max_http_connections: usize,
    /// Maximum HTTP requests executing concurrently.
    pub max_http_requests: usize,
    /// Maximum concurrent HTTP/2 streams on one connection.
    pub max_http2_streams_per_connection: u32,
    /// Global HTTP(S) accept rate in connections per second.
    pub http_accept_rate_per_second: Option<f64>,
    /// Global HTTP(S) accept burst.
    pub http_accept_burst: Option<usize>,
    /// Maximum retained per-IP rate-limit entries.
    pub max_rate_limit_entries: usize,
    /// Networks whose forwarding headers are trusted in `smart` rate-limit mode.
    pub trusted_proxy_cidrs: Vec<IpNet>,
    /// Maximum general HTTP request body size.
    pub max_http_body_bytes: usize,
    /// Graceful server shutdown deadline.
    #[serde(with = "humantime_serde")]
    pub shutdown_timeout: Duration,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_dns_udp_requests: DEFAULT_MAX_DNS_UDP_REQUESTS,
            max_dns_tcp_connections: DEFAULT_MAX_DNS_TCP_CONNECTIONS,
            max_http_connections: DEFAULT_MAX_HTTP_CONNECTIONS,
            max_http_requests: DEFAULT_MAX_HTTP_REQUESTS,
            max_http2_streams_per_connection: DEFAULT_MAX_HTTP2_STREAMS_PER_CONNECTION,
            http_accept_rate_per_second: Some(DEFAULT_HTTP_ACCEPT_RATE_PER_SECOND),
            http_accept_burst: Some(DEFAULT_HTTP_ACCEPT_BURST),
            max_rate_limit_entries: DEFAULT_MAX_RATE_LIMIT_ENTRIES,
            trusted_proxy_cidrs: Vec::new(),
            max_http_body_bytes: DEFAULT_MAX_HTTP_BODY_BYTES,
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
        }
    }
}

/// Invalid DNS-server configuration.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum ConfigError {
    /// A required nonzero value was zero.
    Zero {
        /// Configuration field.
        field: &'static str,
    },
    /// A semaphore-backed capacity exceeds Tokio's supported maximum.
    CapacityTooLarge {
        /// Configuration field.
        field: &'static str,
        /// Supplied capacity.
        value: usize,
        /// Largest supported capacity.
        maximum: usize,
    },
    /// A rate is non-finite or not positive.
    InvalidRate {
        /// Configuration field.
        field: &'static str,
        /// Supplied rate.
        value: f64,
    },
    /// A rate and burst were not configured together.
    IncompleteRateLimit {
        /// Rate field.
        rate_field: &'static str,
        /// Burst field.
        burst_field: &'static str,
    },
    /// The store batch size exceeds the supported transaction bound.
    StoreBatchTooLarge {
        /// Supplied batch size.
        value: usize,
        /// Largest supported batch size.
        maximum: usize,
    },
    /// Smart client-IP extraction was enabled without a trusted proxy network.
    SmartRateLimitWithoutTrustedProxy,
    /// Neither an HTTP nor HTTPS listener was configured.
    MissingHttpTransport,
    /// HTTPS was configured without any certificate domains.
    HttpsDomainsEmpty,
    /// Manual TLS supports exactly one certificate domain.
    ManualTlsDomainCount {
        /// Supplied domain count.
        count: usize,
    },
    /// Let's Encrypt TLS was configured without a contact address.
    LetsEncryptContactRequired,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero { field } => write!(f, "{field} must be greater than zero"),
            Self::CapacityTooLarge {
                field,
                value,
                maximum,
            } => write!(
                f,
                "{field} value {value} exceeds supported maximum {maximum}"
            ),
            Self::InvalidRate { field, value } => {
                write!(
                    f,
                    "{field} must be finite and greater than zero, got {value}"
                )
            }
            Self::IncompleteRateLimit {
                rate_field,
                burst_field,
            } => write!(
                f,
                "{rate_field} and {burst_field} must be configured together"
            ),
            Self::StoreBatchTooLarge { value, maximum } => write!(
                f,
                "max_batch_size value {value} exceeds supported maximum {maximum}"
            ),
            Self::SmartRateLimitWithoutTrustedProxy => write!(
                f,
                "pkarr_put_rate_limit = smart requires limits.trusted_proxy_cidrs"
            ),
            Self::MissingHttpTransport => {
                write!(f, "either http or https config is required")
            }
            Self::HttpsDomainsEmpty => {
                write!(f, "https.domains must contain at least one domain")
            }
            Self::ManualTlsDomainCount { count } => {
                write!(f, "manual TLS requires exactly one domain, got {count}")
            }
            Self::LetsEncryptContactRequired => {
                write!(f, "https.letsencrypt_contact is required for Let's Encrypt")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Validated ingress policy used by runtime components.
#[derive(Debug, Clone)]
pub(crate) struct IngressPolicy {
    pub(crate) max_dns_udp_requests: NonZeroUsize,
    pub(crate) max_dns_tcp_connections: NonZeroUsize,
    pub(crate) max_http_connections: NonZeroUsize,
    pub(crate) max_http_requests: NonZeroUsize,
    pub(crate) max_http2_streams_per_connection: NonZeroU32,
    pub(crate) http_accept_rate_per_second: f64,
    pub(crate) http_accept_burst: NonZeroUsize,
    pub(crate) max_rate_limit_entries: NonZeroUsize,
    pub(crate) trusted_proxy_cidrs: Vec<IpNet>,
    pub(crate) max_http_body_bytes: NonZeroUsize,
    pub(crate) shutdown_timeout: Duration,
}

impl TryFrom<&LimitsConfig> for IngressPolicy {
    type Error = ConfigError;

    fn try_from(config: &LimitsConfig) -> std::result::Result<Self, Self::Error> {
        fn semaphore_capacity(
            field: &'static str,
            value: usize,
        ) -> std::result::Result<NonZeroUsize, ConfigError> {
            let value = NonZeroUsize::new(value).ok_or(ConfigError::Zero { field })?;
            if value.get() > tokio::sync::Semaphore::MAX_PERMITS {
                return Err(ConfigError::CapacityTooLarge {
                    field,
                    value: value.get(),
                    maximum: tokio::sync::Semaphore::MAX_PERMITS,
                });
            }
            Ok(value)
        }

        let (http_accept_rate_per_second, http_accept_burst) =
            match (config.http_accept_rate_per_second, config.http_accept_burst) {
                (Some(rate), Some(burst)) => {
                    if !rate.is_finite() || rate <= 0.0 {
                        return Err(ConfigError::InvalidRate {
                            field: "limits.http_accept_rate_per_second",
                            value: rate,
                        });
                    }
                    let burst = NonZeroUsize::new(burst).ok_or(ConfigError::Zero {
                        field: "limits.http_accept_burst",
                    })?;
                    (rate, burst)
                }
                (None, None) => (
                    DEFAULT_HTTP_ACCEPT_RATE_PER_SECOND,
                    NonZeroUsize::new(DEFAULT_HTTP_ACCEPT_BURST)
                        .expect("default HTTP accept burst is nonzero"),
                ),
                (Some(_), None) | (None, Some(_)) => {
                    return Err(ConfigError::IncompleteRateLimit {
                        rate_field: "limits.http_accept_rate_per_second",
                        burst_field: "limits.http_accept_burst",
                    });
                }
            };

        let max_http2_streams_per_connection =
            NonZeroU32::new(config.max_http2_streams_per_connection).ok_or(ConfigError::Zero {
                field: "limits.max_http2_streams_per_connection",
            })?;
        let max_rate_limit_entries =
            NonZeroUsize::new(config.max_rate_limit_entries).ok_or(ConfigError::Zero {
                field: "limits.max_rate_limit_entries",
            })?;
        let max_http_body_bytes =
            NonZeroUsize::new(config.max_http_body_bytes).ok_or(ConfigError::Zero {
                field: "limits.max_http_body_bytes",
            })?;
        if config.shutdown_timeout.is_zero() {
            return Err(ConfigError::Zero {
                field: "limits.shutdown_timeout",
            });
        }

        Ok(Self {
            max_dns_udp_requests: semaphore_capacity(
                "limits.max_dns_udp_requests",
                config.max_dns_udp_requests,
            )?,
            max_dns_tcp_connections: semaphore_capacity(
                "limits.max_dns_tcp_connections",
                config.max_dns_tcp_connections,
            )?,
            max_http_connections: semaphore_capacity(
                "limits.max_http_connections",
                config.max_http_connections,
            )?,
            max_http_requests: semaphore_capacity(
                "limits.max_http_requests",
                config.max_http_requests,
            )?,
            max_http2_streams_per_connection,
            http_accept_rate_per_second,
            http_accept_burst,
            max_rate_limit_entries,
            trusted_proxy_cidrs: config.trusted_proxy_cidrs.clone(),
            max_http_body_bytes,
            shutdown_timeout: config.shutdown_timeout,
        })
    }
}

/// Configuration for the signed-packet store.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[non_exhaustive]
pub struct StoreConfig {
    /// Maximum number of packets processed in a single write transaction.
    pub max_batch_size: usize,

    /// Maximum time a write transaction stays open before it is committed.
    ///
    /// Bounds how much data can be lost on a crash.
    #[serde(with = "humantime_serde")]
    pub max_batch_time: Duration,

    /// Time a packet is retained in the store before it becomes eligible for eviction.
    #[serde(with = "humantime_serde")]
    pub eviction: Duration,

    /// Interval between runs of the eviction task.
    #[serde(with = "humantime_serde")]
    pub eviction_interval: Duration,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Options::default().into()
    }
}

impl From<Options> for StoreConfig {
    fn from(value: Options) -> Self {
        Self {
            max_batch_size: value.max_batch_size.get(),
            max_batch_time: value.max_batch_time.get(),
            eviction: value.eviction.get(),
            eviction_interval: value.eviction_interval.get(),
        }
    }
}

impl TryFrom<&StoreConfig> for Options {
    type Error = ConfigError;

    fn try_from(value: &StoreConfig) -> std::result::Result<Self, Self::Error> {
        if value.max_batch_size == 0 {
            return Err(ConfigError::Zero {
                field: "zone_store.max_batch_size",
            });
        }
        if value.max_batch_size > MAX_STORE_BATCH_SIZE {
            return Err(ConfigError::StoreBatchTooLarge {
                value: value.max_batch_size,
                maximum: MAX_STORE_BATCH_SIZE,
            });
        }
        for (field, duration) in [
            ("zone_store.max_batch_time", value.max_batch_time),
            ("zone_store.eviction", value.eviction),
            ("zone_store.eviction_interval", value.eviction_interval),
        ] {
            if duration.is_zero() {
                return Err(ConfigError::Zero { field });
            }
        }

        Ok(Self {
            max_batch_size: NonZeroUsize::new(value.max_batch_size)
                .expect("store batch size was validated as nonzero"),
            max_batch_time: NonZeroDuration::new(value.max_batch_time)
                .expect("store batch time was validated as nonzero"),
            eviction: NonZeroDuration::new(value.eviction)
                .expect("store eviction age was validated as nonzero"),
            eviction_interval: NonZeroDuration::new(value.eviction_interval)
                .expect("store eviction interval was validated as nonzero"),
        })
    }
}

impl TryFrom<StoreConfig> for Options {
    type Error = ConfigError;

    fn try_from(value: StoreConfig) -> std::result::Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

/// Configuration validated before any process resource is opened.
#[derive(Debug)]
pub(crate) struct ValidatedConfig {
    pub(crate) config: Config,
    pub(crate) ingress: IngressPolicy,
    pub(crate) store_options: Options,
}

impl TryFrom<Config> for ValidatedConfig {
    type Error = ConfigError;

    fn try_from(config: Config) -> std::result::Result<Self, Self::Error> {
        validate_http_transport(&config)?;
        let ingress = IngressPolicy::try_from(&config.limits)?;
        validate_rate_limit(&config.pkarr_put_rate_limit, &ingress)?;
        let store_options = match config.zone_store.as_ref() {
            Some(store) => Options::try_from(store)?,
            None => Options::default(),
        };
        Ok(Self {
            config,
            ingress,
            store_options,
        })
    }
}

impl Config {
    /// Validates structural transport settings and all resource and store limits without I/O.
    pub fn validate(&self) -> std::result::Result<(), ConfigError> {
        validate_http_transport(self)?;
        let ingress = IngressPolicy::try_from(&self.limits)?;
        validate_rate_limit(&self.pkarr_put_rate_limit, &ingress)?;
        if let Some(store) = self.zone_store.as_ref() {
            Options::try_from(store)?;
        }
        Ok(())
    }
}

fn validate_http_transport(config: &Config) -> std::result::Result<(), ConfigError> {
    if config.http.is_none() && config.https.is_none() {
        return Err(ConfigError::MissingHttpTransport);
    }
    let Some(https) = config.https.as_ref() else {
        return Ok(());
    };
    if https.domains.is_empty() {
        return Err(ConfigError::HttpsDomainsEmpty);
    }
    match https.cert_mode {
        CertMode::Manual if https.domains.len() != 1 => Err(ConfigError::ManualTlsDomainCount {
            count: https.domains.len(),
        }),
        CertMode::LetsEncrypt
            if https
                .letsencrypt_contact
                .as_deref()
                .is_none_or(|contact| contact.trim().is_empty()) =>
        {
            Err(ConfigError::LetsEncryptContactRequired)
        }
        CertMode::Manual | CertMode::LetsEncrypt | CertMode::SelfSigned => Ok(()),
    }
}

fn validate_rate_limit(
    config: &RateLimitConfig,
    ingress: &IngressPolicy,
) -> std::result::Result<(), ConfigError> {
    if matches!(config, RateLimitConfig::Smart) && ingress.trusted_proxy_cidrs.is_empty() {
        return Err(ConfigError::SmartRateLimitWithoutTrustedProxy);
    }
    Ok(())
}

/// Configuration for the metrics server.
///
/// The metrics server exposes [`Metrics`] as [Prometheus]-format counters over a
/// plain HTTP endpoint. It carries no authentication, so the bind address should
/// be kept on a trusted network.
///
/// [`Metrics`]: crate::Metrics
/// [Prometheus]: https://prometheus.io/docs/instrumenting/exposition_formats/
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MetricsConfig {
    /// Disables the metrics server when set to `true`.
    pub disabled: bool,
    /// Address to bind the metrics server to.
    ///
    /// When `None` and the server is enabled, binds to `127.0.0.1:9117`.
    pub bind_addr: Option<SocketAddr>,
}

impl MetricsConfig {
    /// Returns a [`MetricsConfig`] with the metrics server disabled.
    pub fn disabled() -> Self {
        Self {
            disabled: true,
            bind_addr: None,
        }
    }
}

/// Configuration for the mainline DHT fallback.
///
/// When enabled, the server looks up signed packets on the BitTorrent mainline
/// DHT for keys that are not present in the local store.
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MainlineConfig {
    /// Enables the mainline DHT fallback when set to `true`.
    pub enabled: bool,
    /// Custom bootstrap nodes for the mainline DHT.
    ///
    /// Addresses must be formatted as `domain:port` or `ipv4:port`. When `None`
    /// or empty, the default BitTorrent mainline bootstrap nodes defined by
    /// pkarr are used.
    pub bootstrap: Option<Vec<String>>,
}

/// Bootstrap nodes for mainline DHT resolution.
#[derive(Debug, Serialize, Deserialize, Default)]
pub(crate) enum BootstrapOption {
    /// The default bootstrap nodes defined by pkarr.
    #[default]
    Default,
    /// A custom set of bootstrap addresses (`domain:port` or `ipv4:port`).
    Custom(Vec<String>),
}

#[allow(clippy::derivable_impls)]
impl Default for MainlineConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bootstrap: None,
        }
    }
}

impl Config {
    /// Loads a [`Config`] from a TOML file at `path`.
    pub async fn load(path: impl AsRef<Path>) -> Result<Config> {
        info!(
            "loading config file from {}",
            path.as_ref().to_string_lossy()
        );
        let s = tokio::fs::read_to_string(path.as_ref())
            .await
            .with_std_context(|_| format!("failed to read {}", path.as_ref().to_string_lossy()))?;
        let config: Config = toml::from_str(&s).anyerr()?;
        Ok(config)
    }

    /// Returns the data directory where the server stores its state.
    ///
    /// Resolution order:
    /// 1. The [`Self::data_dir`] field, if set.
    /// 2. The `IROH_DNS_DATA_DIR` environment variable.
    /// 3. An `iroh-dns` subdirectory of the platform's standard data directory,
    ///    as reported by `dirs_next::data_dir`.
    pub fn data_dir(&self) -> Result<PathBuf> {
        let dir = if let Some(dir) = &self.data_dir {
            dir.clone()
        } else if let Some(val) = env::var_os("IROH_DNS_DATA_DIR") {
            PathBuf::from(val)
        } else {
            let path = dirs_next::data_dir()
                .std_context("operating environment provides no directory for application data")?;

            path.join("iroh-dns")
        };
        Ok(dir)
    }

    /// Returns the path to the signed-packet store database file.
    ///
    /// The path is `<data_dir>/signed-packets-1.db`, where `<data_dir>` is
    /// resolved by [`Self::data_dir`].
    pub fn signed_packet_store_path(&self) -> Result<PathBuf> {
        Ok(self.data_dir()?.join("signed-packets-1.db"))
    }

    /// Get the address where the metrics server should be bound, if set.
    pub(crate) fn metrics_addr(&self) -> Option<SocketAddr> {
        match &self.metrics {
            None => Some(DEFAULT_METRICS_ADDR),
            Some(conf) => match conf.disabled {
                true => None,
                false => Some(conf.bind_addr.unwrap_or(DEFAULT_METRICS_ADDR)),
            },
        }
    }

    pub(crate) fn mainline_enabled(&self) -> Option<BootstrapOption> {
        match self.mainline.as_ref() {
            None => None,
            Some(MainlineConfig { enabled: false, .. }) => None,
            Some(MainlineConfig {
                bootstrap: Some(bootstrap),
                ..
            }) => Some(BootstrapOption::Custom(bootstrap.clone())),
            Some(MainlineConfig {
                bootstrap: None, ..
            }) => Some(BootstrapOption::Default),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            http: Some(HttpConfig {
                port: 8080,
                bind_addr: None,
            }),
            https: Some(HttpsConfig {
                port: 8443,
                bind_addr: None,
                domains: vec!["localhost".to_string()],
                cert_mode: CertMode::SelfSigned,
                letsencrypt_contact: None,
                letsencrypt_prod: None,
            }),
            dns: DnsConfig {
                port: 5300,
                bind_addr: None,
                origins: vec!["irohdns.example.".to_string(), ".".to_string()],

                default_soa: "irohdns.example hostmaster.irohdns.example 0 10800 3600 604800 3600"
                    .to_string(),
                default_ttl: 900,

                rr_a: Some(Ipv4Addr::LOCALHOST),
                rr_aaaa: None,
                rr_ns: Some("ns1.irohdns.example.".to_string()),
            },
            zone_store: None,
            metrics: None,
            mainline: None,
            pkarr_put_rate_limit: RateLimitConfig::default(),
            limits: LimitsConfig::default(),
            data_dir: None,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::field_reassign_with_default,
        reason = "validation tests mutate one invalid field at a time"
    )]

    use super::*;

    #[test]
    fn existing_example_configs_validate_with_finite_defaults() {
        for source in [
            include_str!("../config.dev.toml"),
            include_str!("../config.prod.toml"),
        ] {
            let config: Config = toml::from_str(source).expect("example config parses");
            config.validate().expect("example config validates");
            let policy = IngressPolicy::try_from(&config.limits).expect("limits validate");
            assert_eq!(policy.max_dns_udp_requests.get(), 1_024);
            assert_eq!(policy.max_dns_tcp_connections.get(), 256);
            assert_eq!(policy.max_http_connections.get(), 512);
            assert_eq!(policy.max_http_requests.get(), 1_024);
            assert_eq!(policy.max_http2_streams_per_connection.get(), 32);
            assert_eq!(policy.max_rate_limit_entries.get(), 4_096);
            assert_eq!(policy.max_http_body_bytes.get(), 65_535);
            assert_eq!(policy.shutdown_timeout, Duration::from_secs(20));
        }
    }

    #[test]
    fn validation_rejects_zero_store_batch_size() {
        let mut config = Config::default();
        config.zone_store = Some(StoreConfig {
            max_batch_size: 0,
            ..StoreConfig::default()
        });

        assert!(config.validate().is_err());
    }

    #[test]
    fn validation_rejects_store_batch_above_transaction_bound() {
        let mut config = Config::default();
        config.zone_store = Some(StoreConfig {
            max_batch_size: MAX_STORE_BATCH_SIZE + 1,
            ..StoreConfig::default()
        });

        assert_eq!(
            config.validate(),
            Err(ConfigError::StoreBatchTooLarge {
                value: MAX_STORE_BATCH_SIZE + 1,
                maximum: MAX_STORE_BATCH_SIZE,
            })
        );
    }

    #[test]
    fn validation_rejects_zero_store_durations() {
        for field in ["max_batch_time", "eviction", "eviction_interval"] {
            let mut store = StoreConfig::default();
            match field {
                "max_batch_time" => store.max_batch_time = Duration::ZERO,
                "eviction" => store.eviction = Duration::ZERO,
                "eviction_interval" => store.eviction_interval = Duration::ZERO,
                _ => unreachable!("test field list is exhaustive"),
            }
            let mut config = Config::default();
            config.zone_store = Some(store);
            assert!(
                matches!(config.validate(), Err(ConfigError::Zero { .. })),
                "{field} should be rejected"
            );
        }
    }

    #[test]
    fn validation_rejects_invalid_ingress_domains() {
        let mut cases = Vec::new();

        let mut zero_udp = LimitsConfig::default();
        zero_udp.max_dns_udp_requests = 0;
        cases.push(zero_udp);

        let mut excessive_tcp = LimitsConfig::default();
        excessive_tcp.max_dns_tcp_connections = tokio::sync::Semaphore::MAX_PERMITS + 1;
        cases.push(excessive_tcp);

        let mut zero_h2 = LimitsConfig::default();
        zero_h2.max_http2_streams_per_connection = 0;
        cases.push(zero_h2);

        let mut invalid_rate = LimitsConfig::default();
        invalid_rate.http_accept_rate_per_second = Some(f64::NAN);
        cases.push(invalid_rate);

        let mut incomplete_rate = LimitsConfig::default();
        incomplete_rate.http_accept_burst = None;
        cases.push(incomplete_rate);

        let mut zero_shutdown = LimitsConfig::default();
        zero_shutdown.shutdown_timeout = Duration::ZERO;
        cases.push(zero_shutdown);

        for limits in cases {
            assert!(IngressPolicy::try_from(&limits).is_err());
        }
    }

    #[test]
    fn smart_rate_limit_requires_an_explicit_trusted_proxy() {
        let mut config = Config::default();
        config.pkarr_put_rate_limit = RateLimitConfig::Smart;
        assert_eq!(
            config.validate(),
            Err(ConfigError::SmartRateLimitWithoutTrustedProxy)
        );
        config.limits.trusted_proxy_cidrs = vec!["127.0.0.0/8".parse().unwrap()];
        config.validate().expect("trusted smart mode validates");
    }

    #[test]
    fn validation_rejects_invalid_http_and_tls_structure() {
        let mut missing_transport = Config::default();
        missing_transport.http = None;
        missing_transport.https = None;
        assert_eq!(
            missing_transport.validate(),
            Err(ConfigError::MissingHttpTransport)
        );

        let mut missing_contact = Config::default();
        let https = missing_contact
            .https
            .as_mut()
            .expect("default HTTPS config");
        https.cert_mode = CertMode::LetsEncrypt;
        https.letsencrypt_contact = None;
        assert_eq!(
            missing_contact.validate(),
            Err(ConfigError::LetsEncryptContactRequired)
        );

        let mut manual_domains = Config::default();
        let https = manual_domains.https.as_mut().expect("default HTTPS config");
        https.cert_mode = CertMode::Manual;
        https.domains = vec!["one.example".to_string(), "two.example".to_string()];
        assert_eq!(
            manual_domains.validate(),
            Err(ConfigError::ManualTlsDomainCount { count: 2 })
        );

        let mut empty_domains = Config::default();
        empty_domains
            .https
            .as_mut()
            .expect("default HTTPS config")
            .domains
            .clear();
        assert_eq!(
            empty_domains.validate(),
            Err(ConfigError::HttpsDomainsEmpty)
        );
    }

    #[test]
    fn validation_performs_no_filesystem_side_effects() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let data_dir = temp.path().join("must-not-be-created");
        let mut config = Config::default();
        config.data_dir = Some(data_dir.clone());
        config.limits.max_http_connections = 0;

        assert!(config.validate().is_err());
        assert!(!data_dir.exists());
    }
}
