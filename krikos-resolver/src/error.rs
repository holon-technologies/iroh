//! Typed resolver errors.

use n0_error::{AnyError, StackError, stack_error};

/// Potential errors related to DNS operations.
#[allow(missing_docs)]
#[stack_error(derive, add_meta, from_sources, std_sources)]
#[non_exhaustive]
pub enum DnsError {
    #[error("Request timed out")]
    Timeout {},
    #[error("No response")]
    NoResponse {},
    #[error("Resolve failed, IPv4: {ipv4}, IPv6: {ipv6}")]
    ResolveBoth {
        ipv4: Box<DnsError>,
        ipv6: Box<DnsError>,
    },
    #[error("Missing host")]
    MissingHost {},
    #[error("Failed to resolve")]
    Resolve { source: AnyError },
    #[error("Invalid DNS response")]
    InvalidResponse {},
}

/// Error constructing a DNS resolver from caller-supplied configuration.
#[allow(missing_docs)]
#[stack_error(derive, add_meta, from_sources, std_sources)]
#[non_exhaustive]
pub enum BuildError {
    #[error("Failed to build the Hickory DNS resolver")]
    Hickory {
        #[error(std_err)]
        source: hickory_resolver::net::NetError,
    },
}

/// Error returned when a staggered call fails.
#[stack_error(derive, add_meta)]
#[error("no calls succeeded: [{}]", errors.iter().map(|e| e.to_string()).collect::<Vec<_>>().join(""))]
pub struct StaggeredError<E: n0_error::StackError + 'static> {
    pub(crate) errors: Vec<E>,
}

impl<E: StackError + 'static> StaggeredError<E> {
    /// Returns an iterator over all encountered errors.
    pub fn iter(&self) -> impl Iterator<Item = &E> {
        self.errors.iter()
    }
}
