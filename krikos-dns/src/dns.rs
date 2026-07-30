//! Endpoint-aware DNS discovery.
//!
//! Generic host, address, and TXT resolution lives in [`krikos_resolver`]. This module composes
//! that service with Krikos endpoint-record parsing.

use krikos_base::EndpointId;
use krikos_resolver::{DNS_TIMEOUT, DnsResolver, StaggeredError};
use n0_error::stack_error;

use crate::{attrs::ParseError, endpoint_info::EndpointInfo};

/// The endpoint lookup DNS origin used by the public production infrastructure.
pub const N0_DNS_ENDPOINT_ORIGIN_PROD: &str = "dns.iroh.link.";

/// The endpoint lookup DNS origin used by staging infrastructure.
pub const N0_DNS_ENDPOINT_ORIGIN_STAGING: &str = "staging-dns.iroh.link.";

/// Errors returned by endpoint-aware DNS lookups.
#[allow(missing_docs)]
#[stack_error(derive, add_meta, from_sources)]
#[non_exhaustive]
pub enum LookupError {
    #[error("Malformed TXT endpoint record")]
    ParseError { source: ParseError },
    #[error("Failed to resolve endpoint TXT record")]
    LookupFailed { source: krikos_resolver::DnsError },
}

/// DNS service that resolves and parses Krikos endpoint records.
#[derive(Debug, Clone)]
pub struct EndpointDnsResolver {
    resolver: DnsResolver,
}

impl EndpointDnsResolver {
    /// Composes endpoint-record resolution with a generic DNS resolver.
    pub fn new(resolver: DnsResolver) -> Self {
        Self { resolver }
    }

    /// Returns the generic DNS resolver used by this service.
    pub fn resolver(&self) -> &DnsResolver {
        &self.resolver
    }

    /// Consumes this service and returns its generic DNS resolver.
    pub fn into_resolver(self) -> DnsResolver {
        self.resolver
    }

    /// Looks up endpoint information by endpoint identifier and origin domain.
    pub async fn lookup_by_id(
        &self,
        endpoint_id: &EndpointId,
        origin: &str,
    ) -> Result<EndpointInfo, LookupError> {
        let name = format!("_iroh.{}.{}", endpoint_id.to_z32(), origin);
        self.lookup_name(name).await
    }

    /// Looks up endpoint information by DNS name.
    pub async fn lookup_by_domain_name(&self, name: &str) -> Result<EndpointInfo, LookupError> {
        let name = if name.starts_with("_iroh.") {
            name.to_owned()
        } else {
            format!("_iroh.{name}")
        };
        self.lookup_name(name).await
    }

    /// Looks up endpoint information by endpoint identifier using staggered attempts.
    pub async fn lookup_by_id_staggered(
        &self,
        endpoint_id: &EndpointId,
        origin: &str,
        delays_ms: &[u64],
    ) -> Result<EndpointInfo, StaggeredError<LookupError>> {
        self.resolver
            .stagger(|| self.lookup_by_id(endpoint_id, origin), delays_ms)
            .await
    }

    /// Looks up endpoint information by DNS name using staggered attempts.
    pub async fn lookup_by_domain_name_staggered(
        &self,
        name: &str,
        delays_ms: &[u64],
    ) -> Result<EndpointInfo, StaggeredError<LookupError>> {
        self.resolver
            .stagger(|| self.lookup_by_domain_name(name), delays_ms)
            .await
    }

    async fn lookup_name(&self, name: String) -> Result<EndpointInfo, LookupError> {
        let records = self.resolver.lookup_txt(name.clone(), DNS_TIMEOUT).await?;
        Ok(EndpointInfo::from_txt_lookup(name, records)?)
    }
}

impl Default for EndpointDnsResolver {
    fn default() -> Self {
        Self::new(DnsResolver::new())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use krikos_base::SecretKey;
    use krikos_resolver::{BoxIter, DnsError, Resolver, TxtRecordData};
    use n0_future::boxed::BoxFuture;

    use super::*;

    #[derive(Debug, Clone)]
    struct FixedTxtResolver;

    impl Resolver for FixedTxtResolver {
        fn lookup_ipv4(&self, _host: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>, DnsError>> {
            Box::pin(async { Ok(Box::new(std::iter::empty()) as BoxIter<_>) })
        }

        fn lookup_ipv6(&self, _host: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>, DnsError>> {
            Box::pin(async { Ok(Box::new(std::iter::empty()) as BoxIter<_>) })
        }

        fn lookup_txt(&self, _host: String) -> BoxFuture<Result<BoxIter<TxtRecordData>, DnsError>> {
            let record = TxtRecordData::from(vec![
                b"relay=https://relay.example/".to_vec().into_boxed_slice(),
            ]);
            Box::pin(async move { Ok(Box::new(std::iter::once(record)) as BoxIter<_>) })
        }

        fn clear_cache(&self) {}

        fn reset(&self) -> Box<dyn Resolver> {
            Box::new(self.clone())
        }
    }

    #[tokio::test]
    async fn endpoint_lookup_is_composed_over_generic_txt_resolution() {
        let endpoint_id = SecretKey::from_bytes(&[7; 32]).public();
        let resolver = EndpointDnsResolver::new(DnsResolver::custom(FixedTxtResolver));

        let info = resolver
            .lookup_by_id(&endpoint_id, "example.test.")
            .await
            .unwrap();

        assert_eq!(info.endpoint_id, endpoint_id);
        assert_eq!(
            info.relay_urls().next().map(ToString::to_string).as_deref(),
            Some("https://relay.example/")
        );
    }
}
