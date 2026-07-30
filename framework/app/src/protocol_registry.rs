use std::collections::BTreeMap;

use krikos::protocol::{AcceptError, DynProtocolHandler, ProtocolHandler};

use crate::RegistryError;

/// A bounded, uniquely keyed set of application protocol handlers.
#[derive(Debug)]
pub struct ProtocolRegistry {
    protocol_limit: usize,
    alpn_length_limit: usize,
    handlers: BTreeMap<Vec<u8>, Box<dyn DynProtocolHandler>>,
}

impl ProtocolRegistry {
    /// Creates a registry with explicit protocol-count and ALPN-byte bounds.
    pub fn new(protocol_limit: usize, alpn_length_limit: usize) -> Result<Self, RegistryError> {
        if protocol_limit == 0 || alpn_length_limit == 0 || alpn_length_limit > 255 {
            return Err(RegistryError::InvalidBounds);
        }
        Ok(Self {
            protocol_limit,
            alpn_length_limit,
            handlers: BTreeMap::new(),
        })
    }

    /// Registers one concrete Krikos protocol handler.
    pub fn register<H>(&mut self, alpn: impl AsRef<[u8]>, handler: H) -> Result<(), RegistryError>
    where
        H: ProtocolHandler,
    {
        self.register_boxed(alpn.as_ref(), handler.into())
    }

    /// Registers an already type-erased Krikos protocol handler.
    pub fn register_dyn(
        &mut self,
        alpn: impl AsRef<[u8]>,
        handler: Box<dyn DynProtocolHandler>,
    ) -> Result<(), RegistryError> {
        self.register_boxed(alpn.as_ref(), handler)
    }

    /// Registers a rejecting marker handler, useful for planning and registry validation.
    ///
    /// Standard bundles replace markers with concrete handlers before exposing a router.
    pub fn register_marker(
        &mut self,
        alpn: impl AsRef<[u8]>,
        name: &'static str,
    ) -> Result<(), RegistryError> {
        self.register(alpn, MarkerHandler(name))
    }

    /// Number of registered protocols.
    #[must_use]
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Whether no protocol is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// Registered ALPN values in deterministic byte order.
    pub fn alpns(&self) -> impl Iterator<Item = &[u8]> {
        self.handlers.keys().map(Vec::as_slice)
    }

    pub(crate) fn ensure_within(
        &self,
        protocol_limit: usize,
        alpn_length_limit: usize,
    ) -> Result<(), RegistryError> {
        if self.handlers.len() > protocol_limit {
            return Err(RegistryError::ProtocolLimit {
                actual: self.handlers.len(),
                limit: protocol_limit,
            });
        }
        if let Some(alpn) = self
            .handlers
            .keys()
            .find(|alpn| alpn.len() > alpn_length_limit)
        {
            return Err(RegistryError::AlpnTooLong {
                actual: alpn.len(),
                limit: alpn_length_limit,
            });
        }
        Ok(())
    }

    /// Consumes the registry into deterministic router registrations.
    pub fn into_handlers(self) -> impl Iterator<Item = (Vec<u8>, Box<dyn DynProtocolHandler>)> {
        self.handlers.into_iter()
    }

    fn register_boxed(
        &mut self,
        alpn: &[u8],
        handler: Box<dyn DynProtocolHandler>,
    ) -> Result<(), RegistryError> {
        if alpn.is_empty() {
            return Err(RegistryError::EmptyAlpn);
        }
        if alpn.len() > self.alpn_length_limit {
            return Err(RegistryError::AlpnTooLong {
                actual: alpn.len(),
                limit: self.alpn_length_limit,
            });
        }
        if self.handlers.contains_key(alpn) {
            return Err(RegistryError::Duplicate {
                alpn: alpn.to_vec(),
            });
        }
        if self.handlers.len() >= self.protocol_limit {
            return Err(RegistryError::ProtocolLimit {
                actual: self.handlers.len().saturating_add(1),
                limit: self.protocol_limit,
            });
        }
        self.handlers.insert(alpn.to_vec(), handler);
        Ok(())
    }
}

#[derive(Debug)]
struct MarkerHandler(&'static str);

impl ProtocolHandler for MarkerHandler {
    async fn accept(&self, _connection: krikos::endpoint::Connection) -> Result<(), AcceptError> {
        Err(AcceptError::from_err(std::io::Error::other(format!(
            "protocol marker `{}` cannot accept connections",
            self.0
        ))))
    }
}
