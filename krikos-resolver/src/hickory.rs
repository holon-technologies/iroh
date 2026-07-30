//! Hickory-backed production resolver construction.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use hickory_resolver::{
    TokioResolver,
    config::{ConnectionConfig, ResolverConfig, ResolverOpts},
    net::runtime::TokioRuntimeProvider,
    proto::rr::RData,
};
use n0_error::{AnyError, StdResultExt, e};
use n0_future::{boxed::BoxFuture, time::Duration};
use tracing::warn;

use crate::{
    dns::{BoxIter, DnsResolver, Resolver, TxtRecordData},
    error::{BuildError, DnsError},
};

/// Builder for [`DnsResolver`].
#[derive(Debug, Clone, Default)]
pub struct Builder {
    use_system_defaults: bool,
    nameservers: Vec<(SocketAddr, DnsProtocol)>,
    #[cfg(with_crypto_provider)]
    tls_client_config: Option<rustls::ClientConfig>,
}

/// Protocols over which DNS records can be resolved.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum DnsProtocol {
    /// DNS over UDP.
    #[default]
    Udp,
    /// DNS over TCP.
    Tcp,
    /// DNS over TLS, as defined in [RFC 7858].
    ///
    /// [RFC 7858]: https://www.rfc-editor.org/rfc/rfc7858.html
    #[cfg(with_crypto_provider)]
    Tls,
    /// DNS over HTTPS, as defined in [RFC 8484].
    ///
    /// [RFC 8484]: https://www.rfc-editor.org/rfc/rfc8484.html
    #[cfg(with_crypto_provider)]
    Https,
}

impl DnsProtocol {
    #[cfg_attr(
        not(with_crypto_provider),
        expect(unused_variables, reason = "unused when TLS is disabled in DNS")
    )]
    fn to_hickory(self, ip: IpAddr) -> ConnectionConfig {
        match self {
            Self::Udp => ConnectionConfig::udp(),
            Self::Tcp => ConnectionConfig::tcp(),
            #[cfg(with_crypto_provider)]
            Self::Tls => ConnectionConfig::tls(Arc::from(ip.to_string())),
            #[cfg(with_crypto_provider)]
            Self::Https => ConnectionConfig::https(Arc::from(ip.to_string()), None),
        }
    }
}

impl Builder {
    /// Makes the builder respect the host system's DNS configuration.
    ///
    /// If reading system configuration fails, the resolver uses Google's public nameservers.
    pub fn with_system_defaults(mut self) -> Self {
        self.use_system_defaults = true;
        self
    }

    /// Adds a single nameserver.
    pub fn with_nameserver(mut self, addr: SocketAddr, protocol: DnsProtocol) -> Self {
        self.nameservers.push((addr, protocol));
        self
    }

    /// Adds a list of nameservers.
    pub fn with_nameservers(
        mut self,
        nameservers: impl IntoIterator<Item = (SocketAddr, DnsProtocol)>,
    ) -> Self {
        self.nameservers.extend(nameservers);
        self
    }

    /// Sets a custom TLS verification config for encrypted DNS transports.
    #[cfg(with_crypto_provider)]
    pub fn tls_client_config(mut self, client_config: rustls::ClientConfig) -> Self {
        self.tls_client_config = Some(client_config);
        self
    }

    /// Builds the DNS resolver.
    pub fn build(self) -> Result<DnsResolver, BuildError> {
        Ok(DnsResolver::custom(HickoryResolver::new(self)?))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HickoryResolver {
    resolver: TokioResolver,
    builder: Builder,
}

impl HickoryResolver {
    pub(crate) fn new(builder: Builder) -> Result<Self, BuildError> {
        let resolver = Self::build_resolver(&builder)?;
        Ok(Self { resolver, builder })
    }

    fn build_resolver(builder: &Builder) -> Result<TokioResolver, BuildError> {
        let (mut config, mut options) = if builder.use_system_defaults {
            match Self::system_config() {
                Ok(values) => values,
                Err(reason) => {
                    warn!(%reason, "failed to read system DNS config; using Google fallback");
                    (
                        ResolverConfig::udp_and_tcp(&hickory_resolver::config::GOOGLE),
                        ResolverOpts::default(),
                    )
                }
            }
        } else {
            (ResolverConfig::default(), ResolverOpts::default())
        };

        for (address, protocol) in &builder.nameservers {
            let mut transport = protocol.to_hickory(address.ip());
            transport.port = address.port();
            let nameserver = hickory_resolver::config::NameServerConfig::new(
                address.ip(),
                false,
                vec![transport],
            );
            config.add_name_server(nameserver);
        }

        options.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4thenIpv6;
        options.negative_max_ttl = Some(Duration::ZERO);

        let mut hickory_builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        *hickory_builder.options_mut() = options;

        #[cfg(with_crypto_provider)]
        if let Some(client_config) = builder.tls_client_config.clone() {
            hickory_builder = hickory_builder.with_tls_config(client_config);
        }

        hickory_builder
            .build()
            .map_err(|error| e!(BuildError::Hickory, error))
    }

    fn system_config() -> Result<(ResolverConfig, ResolverOpts), hickory_resolver::net::NetError> {
        #[cfg(target_os = "android")]
        let (system_config, options) = crate::android::read_system_conf()?;
        #[cfg(not(target_os = "android"))]
        let (system_config, options) = hickory_resolver::system_conf::read_system_conf()?;

        let mut config = ResolverConfig::default();
        if let Some(name) = system_config.domain() {
            config.set_domain(name.clone());
        }
        for name in system_config.search() {
            config.add_search(name.clone());
        }
        for nameserver in system_config.name_servers() {
            if !WINDOWS_BAD_SITE_LOCAL_DNS_SERVERS.contains(&nameserver.ip) {
                config.add_name_server(nameserver.clone());
            }
        }
        Ok((config, options))
    }
}

impl Resolver for HickoryResolver {
    fn lookup_ipv4(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>, DnsError>> {
        let resolver = self.resolver.clone();
        Box::pin(async move {
            let lookup = resolver.ipv4_lookup(host).await.anyerr()?;
            let addresses =
                lookup
                    .answers()
                    .to_vec()
                    .into_iter()
                    .filter_map(|record| match &record.data {
                        RData::A(address) => Some(address.0),
                        _ => None,
                    });
            Ok(Box::new(addresses) as BoxIter<Ipv4Addr>)
        })
    }

    fn lookup_ipv6(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>, DnsError>> {
        let resolver = self.resolver.clone();
        Box::pin(async move {
            let lookup = resolver.ipv6_lookup(host).await.anyerr()?;
            let addresses =
                lookup
                    .answers()
                    .to_vec()
                    .into_iter()
                    .filter_map(|record| match &record.data {
                        RData::AAAA(address) => Some(address.0),
                        _ => None,
                    });
            Ok(Box::new(addresses) as BoxIter<Ipv6Addr>)
        })
    }

    fn lookup_txt(&self, host: String) -> BoxFuture<Result<BoxIter<TxtRecordData>, DnsError>> {
        let resolver = self.resolver.clone();
        Box::pin(async move {
            let lookup = resolver.txt_lookup(host).await.anyerr()?;
            let records = lookup
                .answers()
                .to_vec()
                .into_iter()
                .filter_map(|record| match &record.data {
                    RData::TXT(data) => Some(TxtRecordData::from(data.txt_data.to_vec())),
                    _ => None,
                });
            Ok(Box::new(records) as BoxIter<TxtRecordData>)
        })
    }

    fn clear_cache(&self) {
        self.resolver.clear_cache()
    }

    fn reset(&self) -> Box<dyn Resolver> {
        match Self::new(self.builder.clone()) {
            Ok(resolver) => Box::new(resolver),
            Err(error) => {
                warn!(%error, "failed to rebuild DNS resolver; retaining previous resolver");
                Box::new(self.clone())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct UnavailableResolver {
    reason: Arc<str>,
}

impl UnavailableResolver {
    pub(crate) fn new(reason: String) -> Self {
        Self {
            reason: Arc::from(reason),
        }
    }

    fn error<T>(&self) -> Result<T, DnsError> {
        Err(e!(
            DnsError::Resolve,
            AnyError::from_string(self.reason.to_string())
        ))
    }
}

impl Resolver for UnavailableResolver {
    fn lookup_ipv4(&self, _host: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>, DnsError>> {
        let resolver = self.clone();
        Box::pin(async move { resolver.error() })
    }

    fn lookup_ipv6(&self, _host: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>, DnsError>> {
        let resolver = self.clone();
        Box::pin(async move { resolver.error() })
    }

    fn lookup_txt(&self, _host: String) -> BoxFuture<Result<BoxIter<TxtRecordData>, DnsError>> {
        let resolver = self.clone();
        Box::pin(async move { resolver.error() })
    }

    fn clear_cache(&self) {}

    fn reset(&self) -> Box<dyn Resolver> {
        Box::new(self.clone())
    }
}

/// Deprecated IPv6 site-local anycast addresses still configured by Windows.
const WINDOWS_BAD_SITE_LOCAL_DNS_SERVERS: [IpAddr; 3] = [
    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 2)),
    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 3)),
];
