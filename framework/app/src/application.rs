use std::{fmt, sync::Arc};

use krikos::{Endpoint, EndpointId};
use krikos_blobs::api::Store as BlobsStore;
use krikos_docs::api::DocsApi;
use krikos_gossip::net::Gossip;

use crate::{DataRoot, Health, RunningApp, ShutdownError, ShutdownReport};

/// Low-cardinality standard-bundle metrics snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplicationMetrics {
    pub(crate) protocol_count: usize,
    pub(crate) component_count: usize,
}

impl ApplicationMetrics {
    /// Number of registered ALPN protocols.
    #[must_use]
    pub const fn protocol_count(&self) -> usize {
        self.protocol_count
    }

    /// Number of standard runtime components.
    #[must_use]
    pub const fn component_count(&self) -> usize {
        self.component_count
    }
}

/// Aggregate framework and component health.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationHealth {
    lifecycle: Health,
}

impl ApplicationHealth {
    /// Lifecycle supervisor health.
    #[must_use]
    pub const fn lifecycle(&self) -> &Health {
        &self.lifecycle
    }
}

/// Running standard local-first application bundle.
#[derive(Clone)]
pub struct Application {
    pub(crate) running: RunningApp,
    pub(crate) endpoint: Endpoint,
    pub(crate) blobs: BlobsStore,
    pub(crate) docs: DocsApi,
    pub(crate) gossip: Gossip,
    pub(crate) data_root: Option<DataRoot>,
    pub(crate) alpns: Arc<Vec<Vec<u8>>>,
    pub(crate) metrics: ApplicationMetrics,
}

impl fmt::Debug for Application {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Application")
            .field("endpoint_id", &self.endpoint.id())
            .field("health", &self.running.health())
            .field("metrics", &self.metrics)
            .finish_non_exhaustive()
    }
}

impl Application {
    /// Endpoint identity.
    #[must_use]
    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// Read-only endpoint handle.
    #[must_use]
    pub const fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Blob storage and download capability.
    #[must_use]
    pub const fn blobs(&self) -> &BlobsStore {
        &self.blobs
    }

    /// Documents capability.
    #[must_use]
    pub const fn docs(&self) -> &DocsApi {
        &self.docs
    }

    /// Gossip capability.
    #[must_use]
    pub const fn gossip(&self) -> &Gossip {
        &self.gossip
    }

    /// Persistent data root, or `None` for explicitly ephemeral applications.
    #[must_use]
    pub const fn data_root(&self) -> Option<&DataRoot> {
        self.data_root.as_ref()
    }

    /// Aggregate health without peer-controlled labels.
    #[must_use]
    pub fn health(&self) -> ApplicationHealth {
        ApplicationHealth {
            lifecycle: self.running.health(),
        }
    }

    /// Low-cardinality component metrics.
    #[must_use]
    pub const fn metrics(&self) -> ApplicationMetrics {
        self.metrics
    }

    /// Registered ALPN values.
    pub fn registered_alpns(&self) -> impl Iterator<Item = &[u8]> {
        self.alpns.iter().map(Vec::as_slice)
    }

    /// Idempotently drains router, protocols, endpoint, stores, and data-root lease.
    pub async fn shutdown(&self) -> Result<ShutdownReport, ShutdownError> {
        self.running.shutdown().await
    }
}
