use std::{
    fmt,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use krikos::{
    Endpoint, RelayMap, RelayMode,
    endpoint::presets,
    protocol::{ProtocolHandler, Router},
    tls::CaTlsConfig,
};
use krikos_blobs::{BlobsProtocol, api::Store as BlobsStore};
use krikos_docs::protocol::Docs;
use krikos_gossip::net::Gossip;

#[cfg(feature = "identity")]
use crate::identity_protocol::{
    IDENTITY_PROTOCOL_COUNT, IdentityProtocolComponent, is_identity_alpn,
};
use crate::{
    AppBuilder, AppConfig, Application, ApplicationMetrics, Component, ComponentContext,
    ComponentError, ComponentFuture, DataRoot, FileIdentityStore, IdentityPolicy, IdentityStore,
    MemoryIdentityStore, ProtocolRegistry, RegistryError, StandardStartError, StandardStartStage,
    StartedComponent, data_root::DataRootLease, identity::resolve_identity,
};

const STANDARD_PROTOCOL_COUNT: usize = 3;
const STANDARD_COMPONENT_COUNT: usize = 5;

/// Entry point for constructing the standard local-first bundle.
#[derive(Debug)]
pub struct StandardBundle;

impl StandardBundle {
    /// Creates an explicitly ephemeral, memory-backed bundle.
    #[must_use]
    pub fn ephemeral() -> StandardBundleBuilder {
        StandardBundleBuilder::new(Storage::Ephemeral)
    }

    /// Creates a persistent bundle rooted at one versioned application directory.
    #[must_use]
    pub fn persistent(path: impl AsRef<Path>) -> StandardBundleBuilder {
        StandardBundleBuilder::new(Storage::Persistent(path.as_ref().to_path_buf()))
    }
}

#[derive(Debug)]
enum Storage {
    Ephemeral,
    Persistent(PathBuf),
}

#[derive(Clone, Debug)]
enum NetworkProfile {
    SharedInfrastructure,
    LocalOnly,
    CustomRelay(RelayMap),
}

/// Builder for one endpoint, blobs, gossip, docs, router, and supervisor bundle.
#[derive(Debug)]
pub struct StandardBundleBuilder {
    storage: Storage,
    network: NetworkProfile,
    bind_addr: Option<SocketAddr>,
    ca_tls_config: Option<CaTlsConfig>,
    config: AppConfig,
    custom_protocols: ProtocolRegistry,
    #[cfg(feature = "identity")]
    identity_protocols: Option<IdentityProtocolComponent>,
}

impl StandardBundleBuilder {
    fn new(storage: Storage) -> Self {
        let config = AppConfig::default();
        let custom_protocols =
            ProtocolRegistry::new(config.protocol_limit, config.alpn_length_limit)
                .expect("default application protocol bounds are valid");
        Self {
            storage,
            network: NetworkProfile::SharedInfrastructure,
            bind_addr: None,
            ca_tls_config: None,
            config,
            custom_protocols,
            #[cfg(feature = "identity")]
            identity_protocols: None,
        }
    }

    /// Uses no discovery or relay infrastructure; intended for local tests and isolated networks.
    #[must_use]
    pub fn local_only(mut self) -> Self {
        self.network = NetworkProfile::LocalOnly;
        self
    }

    /// Uses the supplied compatible relay map instead of the default shared infrastructure.
    ///
    /// This is useful for private infrastructure and for verifying relay-only behavior. The relay
    /// protocol remains compatible with the frozen upstream v1.0.3 baseline.
    #[must_use]
    pub fn relay_map(mut self, relay_map: RelayMap) -> Self {
        self.network = NetworkProfile::CustomRelay(relay_map);
        self
    }

    /// Replaces lifecycle bounds and failure policy.
    #[must_use]
    pub fn config(mut self, config: AppConfig) -> Self {
        self.config = config;
        self
    }

    /// Restricts the endpoint to a specific local IP socket.
    #[must_use]
    pub fn bind_addr(mut self, address: SocketAddr) -> Self {
        self.bind_addr = Some(address);
        self
    }

    /// Replaces relay HTTPS certificate verification configuration.
    ///
    /// Production applications should provide trusted roots. Skipping verification is intended
    /// only for isolated test relays with ephemeral self-signed certificates.
    #[must_use]
    pub fn tls_ca_config(mut self, config: CaTlsConfig) -> Self {
        self.ca_tls_config = Some(config);
        self
    }

    /// Registers one bounded custom ALPN handler without modifying framework internals.
    pub fn protocol<H>(mut self, alpn: impl AsRef<[u8]>, handler: H) -> Result<Self, RegistryError>
    where
        H: ProtocolHandler,
    {
        let alpn = alpn.as_ref();
        if is_standard_alpn(alpn) {
            return Err(RegistryError::Duplicate {
                alpn: alpn.to_vec(),
            });
        }
        self.custom_protocols.register(alpn, handler)?;
        Ok(self)
    }

    /// Installs the six account-identity handlers on the bundle's already-resolved endpoint.
    ///
    /// The supplied account component does not load, replace, or persist the endpoint secret.
    #[cfg(feature = "identity")]
    #[must_use]
    pub fn identity_protocols(mut self, component: IdentityProtocolComponent) -> Self {
        self.identity_protocols = Some(component);
        self
    }

    /// Starts stores and networking in dependency order and publishes only a complete handle.
    pub async fn start(self) -> Result<Application, StandardStartError> {
        self.validate_protocols()?;
        let (data_root, lease, identity_store): (
            Option<DataRoot>,
            Option<DataRootLease>,
            Arc<dyn IdentityStore>,
        ) = match &self.storage {
            Storage::Ephemeral => (
                None,
                None,
                Arc::new(MemoryIdentityStore::new()) as Arc<dyn IdentityStore>,
            ),
            Storage::Persistent(path) => {
                let data_root = DataRoot::open(path).map_err(|_| {
                    StandardStartError::new(
                        StandardStartStage::DataRoot,
                        "data-root validation failed",
                    )
                })?;
                let lease = data_root.acquire().map_err(|_| {
                    StandardStartError::new(
                        StandardStartStage::DataRoot,
                        "data-root lock acquisition failed",
                    )
                })?;
                let identity = Arc::new(FileIdentityStore::new(data_root.identity_path()))
                    as Arc<dyn IdentityStore>;
                (Some(data_root), Some(lease), identity)
            }
        };

        let identity = resolve_identity(&*identity_store, IdentityPolicy::LoadOrCreate)
            .await
            .map_err(|_| {
                StandardStartError::new(StandardStartStage::Identity, "identity resolution failed")
            })?;
        let lifecycle_identity = Arc::new(MemoryIdentityStore::new());
        lifecycle_identity
            .create(identity.clone())
            .await
            .map_err(|_| {
                StandardStartError::new(StandardStartStage::Identity, "identity handoff failed")
            })?;

        let blobs = match &data_root {
            Some(data_root) => {
                let store = krikos_blobs::store::fs::FsStore::load(data_root.blobs_path())
                    .await
                    .map_err(|_| {
                        StandardStartError::new(
                            StandardStartStage::Blobs,
                            "blob store failed to open",
                        )
                    })?;
                (*store).clone()
            }
            None => {
                let store = krikos_blobs::store::mem::MemStore::new();
                (*store).clone()
            }
        };

        let endpoint =
            match bind_endpoint(self.network, self.bind_addr, self.ca_tls_config, identity).await {
                Ok(endpoint) => endpoint,
                Err(error) => {
                    let _ = blobs.shutdown().await;
                    return Err(error);
                }
            };
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let docs_builder = match &data_root {
            Some(data_root) => Docs::persistent(data_root.docs_path()),
            None => Docs::memory(),
        };
        let docs = match docs_builder
            .spawn(endpoint.clone(), blobs.clone(), gossip.clone())
            .await
        {
            Ok(docs) => docs,
            Err(_) => {
                cleanup_without_router(&endpoint, &blobs, &gossip, None).await;
                return Err(StandardStartError::new(
                    StandardStartStage::Docs,
                    "documents store or engine failed to start",
                ));
            }
        };

        let mut protocols =
            ProtocolRegistry::new(self.config.protocol_limit, self.config.alpn_length_limit)
                .map_err(|_| {
                    StandardStartError::new(
                        StandardStartStage::ProtocolRegistry,
                        "protocol bounds are invalid",
                    )
                })?;
        let registry_result = register_all_protocols(
            &mut protocols,
            &blobs,
            &gossip,
            &docs,
            self.custom_protocols,
            #[cfg(feature = "identity")]
            self.identity_protocols,
            #[cfg(feature = "identity")]
            &endpoint,
        );
        if registry_result.is_err() {
            cleanup_without_router(&endpoint, &blobs, &gossip, Some(&docs)).await;
            return Err(StandardStartError::new(
                StandardStartStage::ProtocolRegistry,
                "protocol registration failed",
            ));
        }
        let alpns = Arc::new(protocols.alpns().map(<[u8]>::to_vec).collect::<Vec<_>>());
        let mut router_builder = Router::builder(endpoint.clone());
        for (alpn, handler) in protocols.into_handlers() {
            router_builder = router_builder.accept(alpn, handler);
        }
        let router = router_builder.spawn();
        let docs_api = docs.api().clone();
        let runtime = StandardRuntime {
            router: Mutex::new(Some(router)),
            lease: Mutex::new(lease),
        };
        let running = AppBuilder::new(lifecycle_identity)
            .config(self.config)
            .identity_policy(IdentityPolicy::LoadOnly)
            .component(runtime)
            .build()
            .map_err(|_| {
                StandardStartError::new(
                    StandardStartStage::Lifecycle,
                    "lifecycle validation failed",
                )
            })?
            .start()
            .await
            .map_err(|_| {
                StandardStartError::new(
                    StandardStartStage::Lifecycle,
                    "lifecycle publication failed",
                )
            })?;

        Ok(Application {
            running,
            endpoint,
            blobs,
            docs: docs_api,
            gossip,
            data_root,
            metrics: ApplicationMetrics {
                protocol_count: alpns.len(),
                component_count: STANDARD_COMPONENT_COUNT,
            },
            alpns,
        })
    }

    fn validate_protocols(&self) -> Result<(), StandardStartError> {
        self.config.validate().map_err(|_| {
            StandardStartError::new(
                StandardStartStage::ProtocolRegistry,
                "application configuration is invalid",
            )
        })?;
        let standard_total = self
            .custom_protocols
            .len()
            .checked_add(STANDARD_PROTOCOL_COUNT)
            .ok_or_else(|| {
                StandardStartError::new(
                    StandardStartStage::ProtocolRegistry,
                    "protocol count overflowed",
                )
            })?;
        #[cfg(feature = "identity")]
        let total = if self.identity_protocols.is_some() {
            standard_total
                .checked_add(IDENTITY_PROTOCOL_COUNT)
                .ok_or_else(|| {
                    StandardStartError::new(
                        StandardStartStage::ProtocolRegistry,
                        "identity protocol count overflowed",
                    )
                })?
        } else {
            standard_total
        };
        #[cfg(not(feature = "identity"))]
        let total = standard_total;
        if total > self.config.protocol_limit {
            return Err(StandardStartError::new(
                StandardStartStage::ProtocolRegistry,
                "standard and custom protocols exceed the configured limit",
            ));
        }
        self.custom_protocols
            .ensure_within(self.config.protocol_limit, self.config.alpn_length_limit)
            .map_err(|_| {
                StandardStartError::new(
                    StandardStartStage::ProtocolRegistry,
                    "custom protocol registry exceeds application bounds",
                )
            })
    }
}

fn register_all_protocols(
    protocols: &mut ProtocolRegistry,
    blobs: &BlobsStore,
    gossip: &Gossip,
    docs: &Docs,
    custom: ProtocolRegistry,
    #[cfg(feature = "identity")] identity: Option<IdentityProtocolComponent>,
    #[cfg(feature = "identity")] endpoint: &Endpoint,
) -> Result<(), RegistryError> {
    protocols.register(krikos_blobs::ALPN, BlobsProtocol::new(blobs, None))?;
    protocols.register(krikos_gossip::ALPN, gossip.clone())?;
    protocols.register(krikos_docs::ALPN, docs.clone())?;
    #[cfg(feature = "identity")]
    if let Some(identity) = identity {
        identity.register(endpoint, protocols)?;
    }
    for (alpn, handler) in custom.into_handlers() {
        protocols.register_dyn(alpn, handler)?;
    }
    Ok(())
}

async fn bind_endpoint(
    profile: NetworkProfile,
    bind_addr: Option<SocketAddr>,
    ca_tls_config: Option<CaTlsConfig>,
    identity: krikos_base::SecretKey,
) -> Result<Endpoint, StandardStartError> {
    let mut builder = match profile {
        NetworkProfile::SharedInfrastructure => Endpoint::builder(presets::N0),
        NetworkProfile::LocalOnly => Endpoint::builder(presets::Minimal),
        NetworkProfile::CustomRelay(relay_map) => {
            Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Custom(relay_map))
        }
    }
    .secret_key(identity);
    if let Some(ca_tls_config) = ca_tls_config {
        builder = builder.ca_tls_config(ca_tls_config);
    }
    if let Some(bind_addr) = bind_addr {
        builder = builder.bind_addr(bind_addr).map_err(|_| {
            StandardStartError::new(
                StandardStartStage::Endpoint,
                "endpoint bind address is invalid",
            )
        })?;
    }
    builder
        .bind()
        .await
        .map_err(|_| StandardStartError::new(StandardStartStage::Endpoint, "endpoint bind failed"))
}

async fn cleanup_without_router(
    endpoint: &Endpoint,
    blobs: &BlobsStore,
    gossip: &Gossip,
    docs: Option<&Docs>,
) {
    if let Some(docs) = docs {
        ProtocolHandler::shutdown(docs).await;
    }
    let _ = gossip.shutdown().await;
    let _ = blobs.shutdown().await;
    endpoint.close().await;
}

fn is_standard_alpn(alpn: &[u8]) -> bool {
    alpn == krikos_blobs::ALPN || alpn == krikos_docs::ALPN || alpn == krikos_gossip::ALPN || {
        #[cfg(feature = "identity")]
        {
            is_identity_alpn(alpn)
        }
        #[cfg(not(feature = "identity"))]
        {
            false
        }
    }
}

#[derive(Debug)]
struct StandardRuntime {
    router: Mutex<Option<Router>>,
    lease: Mutex<Option<DataRootLease>>,
}

impl Component for StandardRuntime {
    fn name(&self) -> &str {
        "standard-bundle"
    }

    fn start(
        &self,
        context: ComponentContext,
    ) -> ComponentFuture<Result<StartedComponent, ComponentError>> {
        let router = self
            .router
            .lock()
            .map_err(|_| ComponentError::new("router ownership lock failed"))
            .and_then(|mut router| {
                router
                    .take()
                    .ok_or_else(|| ComponentError::new("router already started"))
            });
        let lease = self
            .lease
            .lock()
            .map_err(|_| ComponentError::new("data-root lease lock failed"))
            .map(|mut lease| lease.take());
        Box::pin(async move {
            let router = router?;
            let lease = lease?;
            let run = async move {
                context.cancelled().await;
                Ok(())
            };
            let shutdown = move || async move {
                let result = router
                    .shutdown()
                    .await
                    .map_err(|_| ComponentError::new("router task failed during shutdown"));
                drop(lease);
                result
            };
            Ok(StartedComponent::new(run, shutdown))
        })
    }
}

impl fmt::Display for NetworkProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SharedInfrastructure => "shared-infrastructure",
            Self::LocalOnly => "local-only",
            Self::CustomRelay(_) => "custom-relay",
        })
    }
}
