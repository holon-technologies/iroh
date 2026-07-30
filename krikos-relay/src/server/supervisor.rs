use derive_more::Debug;

use super::*;

/// A running Relay + QAD server.
///
/// This is a full Relay server, including QAD, Relay and various associated HTTP services.
///
/// Dropping this will stop the server.
#[derive(Debug)]
pub struct Server {
    /// The address of the HTTP server, if configured.
    http_addr: Option<SocketAddr>,
    /// The address of the HTTPS server, if the relay server is using TLS.
    ///
    /// If the Relay server is not using TLS then it is served from the
    /// [`Server::http_addr`].
    https_addr: Option<SocketAddr>,
    /// The address of the QUIC server, if configured.
    quic_addr: Option<SocketAddr>,
    /// Handle to the relay server.
    relay_handle: Option<http_server::ServerHandle>,
    /// Handle to the relay service for runtime control.
    relay_service: Option<http_server::RelayService>,
    /// Handle to the quic server.
    quic_handle: Option<QuicServerHandle>,
    /// The main task running the server.
    supervisor: AbortOnDropHandle<Result<(), SupervisorError>>,
    metrics: RelayMetrics,
    metrics_server: Option<metrics_server::MetricsServer>,
}

/// Server spawn errors
#[allow(missing_docs)]
#[stack_error(derive, add_meta, std_sources)]
#[non_exhaustive]
pub enum SpawnError {
    #[error("Unable to get local address")]
    LocalAddr { source: std::io::Error },
    #[error("Failed to bind QAD listener")]
    QuicSpawn { source: QuicSpawnError },
    #[error("Failed to parse TLS header")]
    TlsHeaderParse { source: InvalidHeaderValue },
    #[error("Failed to bind TcpListener")]
    BindTlsListener { source: std::io::Error },
    #[error("Failed to build ACME client TLS config")]
    AcmeClientTlsConfig {
        #[error(std_err)]
        source: std::io::Error,
    },
    #[error("No local address")]
    NoLocalAddr { source: std::io::Error },
    #[error("Failed to bind server socket to {addr}")]
    BindTcpListener {
        source: std::io::Error,
        addr: SocketAddr,
    },
    #[error("Error starting metrics server")]
    Metrics {
        #[error(std_err)]
        source: std::io::Error,
    },
    #[error("Invalid relay admission policy")]
    AdmissionPolicy { source: AdmissionPolicyError },
}

/// Server task errors
#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum SupervisorError {
    #[error("Acme event stream finished")]
    AcmeEventStreamFinished {},
    #[error(transparent)]
    JoinError {
        #[error(from, std_err)]
        source: JoinError,
    },
    #[error("No relay services are enabled")]
    NoRelayServicesEnabled {},
    #[error("Task cancelled")]
    TaskCancelled {},
}

impl Server {
    /// Starts the server.
    pub async fn spawn(config: ServerConfig) -> Result<Self, SpawnError> {
        let mut tasks = JoinSet::new();

        let relay_config = config
            .relay
            .map(|relay| {
                AdmissionPolicy::try_from(&relay.limits)
                    .map(|policy| (relay, policy))
                    .map_err(|err| e!(SpawnError::AdmissionPolicy, err))
            })
            .transpose()?;

        let metrics = RelayMetrics::default();

        #[cfg(not(feature = "metrics"))]
        let metrics_server = None;

        #[cfg(feature = "metrics")]
        let metrics_server = if let Some(addr) = config.metrics_addr {
            debug!("Starting metrics server");
            let mut registry = iroh_metrics::Registry::default();
            registry.register_all(&metrics);
            let server = metrics_server::MetricsServer::spawn(addr, Arc::new(registry))
                .await
                .map_err(|err| e!(SpawnError::Metrics, err))?;
            Some(server)
        } else {
            None
        };

        let (relay_server, http_addr, tls_config) = match relay_config {
            Some((relay_config, admission_policy)) => {
                debug!("Starting Relay server");
                let captive_portal_capacity = admission_policy.max_pending_establishments;
                let mut headers = HeaderMap::new();
                for (name, value) in TLS_HEADERS.iter() {
                    headers.insert(
                        *name,
                        value
                            .parse()
                            .map_err(|err| e!(SpawnError::TlsHeaderParse, err))?,
                    );
                }
                let relay_bind_addr = match relay_config.tls {
                    Some(ref tls) => tls.https_bind_addr,
                    None => relay_config.http_bind_addr,
                };
                let key_cache_capacity = relay_config
                    .key_cache_capacity
                    .unwrap_or(DEFAULT_KEY_CACHE_CAPACITY);
                let mut builder = http_server::ServerBuilder::new(relay_bind_addr)
                    .admission_policy(admission_policy)
                    .metrics(metrics.server.clone())
                    .headers(headers)
                    .key_cache_capacity(key_cache_capacity)
                    .access(relay_config.access)
                    .request_handler(Method::GET, "/", Box::new(root_handler))
                    .request_handler(Method::GET, "/index.html", Box::new(root_handler))
                    .request_handler(Method::GET, RELAY_PROBE_PATH, Box::new(probe_handler))
                    .request_handler(Method::GET, "/robots.txt", Box::new(robots_handler))
                    .request_handler(Method::GET, "/healthz", Box::new(healthz_handler));
                if let Some(cfg) = relay_config.limits.client_rx {
                    builder = builder.client_rx_ratelimit(cfg);
                }
                let (http_addr, tls_config) = match relay_config.tls {
                    Some(tls_config) => {
                        let server_tls_config = match tls_config.cert {
                            #[cfg(feature = "server-acme")]
                            CertConfig::LetsEncrypt {
                                acme_config,
                                server_config_builder,
                            } => {
                                let cache = acme_config.cache_path.map(BoundedAcmeCache::new);
                                let crypto_provider =
                                    server_config_builder.crypto_provider().clone();
                                let client_tls_config = acme_config
                                    .tls_config
                                    .client_config(crypto_provider.clone())
                                    .map_err(|err| e!(SpawnError::AcmeClientTlsConfig, err))?;
                                let config = tokio_rustls_acme::AcmeConfig::new_with_client_config(
                                    acme_config.domains,
                                    Arc::new(client_tls_config),
                                )
                                .contact(acme_config.contact)
                                .directory(acme_config.directory_url)
                                .cache_option(cache);
                                let mut state = config.state();
                                let resolver = state.resolver().clone();
                                let challenge_config =
                                    state.challenge_rustls_config_with_provider(crypto_provider);
                                let server_config =
                                    server_config_builder.with_cert_resolver(resolver);
                                let acceptor =
                                    http_server::TlsAcceptor::LetsEncrypt { challenge_config };
                                tasks.spawn(
                                    async move {
                                        while let Some(event) = state.next().await {
                                            match event {
                                                Ok(ok) => debug!("acme event: {ok:?}"),
                                                Err(err) => error!("error: {err:?}"),
                                            }
                                        }
                                        Err(e!(SupervisorError::AcmeEventStreamFinished))
                                    }
                                    .instrument(info_span!("acme")),
                                );
                                http_server::TlsConfig {
                                    config: Arc::new(server_config),
                                    acceptor,
                                }
                            }
                            CertConfig::Manual { server_config } => {
                                let server_config = Arc::new(server_config);
                                let acceptor =
                                    tokio_rustls::TlsAcceptor::from(server_config.clone());
                                let acceptor = http_server::TlsAcceptor::Manual(acceptor);
                                http_server::TlsConfig {
                                    config: server_config,
                                    acceptor,
                                }
                            }
                        };
                        builder = builder.tls_config(Some(server_tls_config.clone()));

                        // Some services always need to be served over HTTP without TLS.  Run
                        // these standalone.
                        let http_listener = TcpListener::bind(&relay_config.http_bind_addr)
                            .await
                            .map_err(|err| e!(SpawnError::BindTlsListener, err))?;
                        let http_addr = http_listener
                            .local_addr()
                            .map_err(|err| e!(SpawnError::NoLocalAddr, err))?;
                        let captive_metrics = metrics.server.clone();
                        tasks.spawn(
                            async move {
                                run_captive_portal_service(
                                    http_listener,
                                    captive_portal_capacity,
                                    captive_metrics,
                                )
                                .await;
                                Ok(())
                            }
                            .instrument(info_span!("http-service", addr = %http_addr)),
                        );
                        (Some(http_addr), Some(server_tls_config))
                    }
                    None => {
                        // If running Relay without TLS add the plain HTTP server directly
                        // to the Relay server.
                        builder = builder.request_handler(
                            Method::GET,
                            "/generate_204",
                            Box::new(serve_no_content_handler),
                        );
                        (None, None)
                    }
                };
                let relay_server = builder.spawn().await?;
                (Some(relay_server), http_addr, tls_config)
            }
            None => (None, None, None),
        };
        // If http_addr is Some then relay_server is serving HTTPS.  If http_addr is None
        // relay_server is serving HTTP, including the /generate_204 service.
        let relay_addr = relay_server.as_ref().map(|srv| srv.addr());
        let relay_handle = relay_server.as_ref().map(|srv| srv.handle());
        let relay_service = relay_server.as_ref().map(|srv| srv.service().clone());

        let quic_server = match config.quic {
            Some(quic_config) => {
                debug!("Starting QUIC server {}", quic_config.bind_addr);
                let server_config = quic_config
                    .server_config
                    .or(tls_config.map(|config| (*config.config).clone()))
                    .ok_or_else(|| {
                        e!(SpawnError::QuicSpawn, e!(QuicSpawnError::TlsNotConfigured))
                    })?;
                Some(
                    QuicServer::spawn(
                        quic_config.bind_addr,
                        server_config,
                        quic_config.max_connections,
                        metrics.server.clone(),
                    )
                    .map_err(|err| e!(SpawnError::QuicSpawn, err))?,
                )
            }
            None => None,
        };
        let quic_addr = quic_server.as_ref().map(|srv| srv.bind_addr());
        let quic_handle = quic_server.as_ref().map(|srv| srv.handle());

        let task = tokio::spawn(relay_supervisor(tasks, relay_server, quic_server));

        Ok(Self {
            http_addr: http_addr.or(relay_addr),
            https_addr: http_addr.and(relay_addr),
            quic_addr,
            relay_handle,
            relay_service,
            quic_handle,
            supervisor: AbortOnDropHandle::new(task),
            metrics,
            metrics_server,
        })
    }

    /// Requests graceful shutdown.
    ///
    /// Returns once all server tasks have stopped.
    pub async fn shutdown(self) -> Result<(), SupervisorError> {
        // Only the Relay server and QUIC server need shutting down, the supervisor will abort the tasks in
        // the JoinSet when the server terminates.
        if let Some(handle) = self.relay_handle {
            handle.shutdown();
        }
        if let Some(handle) = self.quic_handle {
            handle.shutdown();
        }
        if let Some(server) = self.metrics_server {
            server.shutdown().await;
        }
        self.supervisor.await?
    }

    /// Waits for the server's supervisor task to finish.
    ///
    /// Returns the exit result of the supervisor task. Unlike [`Self::shutdown`], this does
    /// *not* request shutdown, it only waits for the server to terminate on its own (for
    /// example, after an internal error or because the supervisor was aborted from
    /// elsewhere). The outer [`JoinError`] is only produced if the supervisor task itself
    /// panics or is aborted.
    pub async fn join(&mut self) -> Result<Result<(), SupervisorError>, JoinError> {
        (&mut self.supervisor).await
    }

    /// The socket address the HTTPS server is listening on.
    pub fn https_addr(&self) -> Option<SocketAddr> {
        self.https_addr
    }

    /// The socket address the HTTP server is listening on.
    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http_addr
    }

    /// The socket address the QUIC server is listening on.
    pub fn quic_addr(&self) -> Option<SocketAddr> {
        self.quic_addr
    }

    /// Get the server's https [`RelayUrl`].
    ///
    /// This uses [`Self::https_addr`] so it's mostly useful for local development.
    #[cfg(feature = "test-utils")]
    pub fn https_url(&self) -> Option<RelayUrl> {
        self.https_addr.map(|addr| {
            url::Url::parse(&format!("https://{addr}"))
                .expect("valid url")
                .into()
        })
    }

    /// Get the server's http [`RelayUrl`].
    ///
    /// This uses [`Self::http_addr`] so it's mostly useful for local development.
    #[cfg(feature = "test-utils")]
    pub fn http_url(&self) -> Option<RelayUrl> {
        self.http_addr.map(|addr| {
            url::Url::parse(&format!("http://{addr}"))
                .expect("valid url")
                .into()
        })
    }

    /// Returns the metrics collected in the relay server.
    pub fn metrics(&self) -> &RelayMetrics {
        &self.metrics
    }

    /// Returns a handle to the embedded [`RelayService`] for runtime control.
    pub fn relay_service(&self) -> Option<&RelayService> {
        self.relay_service.as_ref()
    }
}

/// Supervisor for the relay server tasks.
///
/// As soon as one of the tasks exits, all other tasks are stopped and the server stops.
/// The supervisor finishes once all tasks are finished.
#[instrument(skip_all)]
async fn relay_supervisor(
    mut tasks: JoinSet<Result<(), SupervisorError>>,
    mut relay_http_server: Option<http_server::Server>,
    mut quic_server: Option<QuicServer>,
) -> Result<(), SupervisorError> {
    let quic_enabled = quic_server.is_some();
    let mut quic_fut = match quic_server {
        Some(ref mut server) => n0_future::Either::Left(server.task_handle()),
        None => n0_future::Either::Right(n0_future::future::pending()),
    };
    let relay_enabled = relay_http_server.is_some();
    let mut relay_fut = match relay_http_server {
        Some(ref mut server) => n0_future::Either::Left(server.task_handle()),
        None => n0_future::Either::Right(n0_future::future::pending()),
    };
    let res = tokio::select! {
        biased;
        Some(ret) = tasks.join_next() => ret,
        ret = &mut quic_fut, if quic_enabled => ret.map(Ok),
        ret = &mut relay_fut, if relay_enabled => ret.map(Ok),
        else => Ok(Err(e!(SupervisorError::NoRelayServicesEnabled))),
    };
    let ret = match res {
        Ok(Ok(())) => {
            debug!("Task exited");
            Ok(())
        }
        Ok(Err(err)) => {
            error!(%err, "Task failed");
            Err(err)
        }
        Err(err) => {
            if let Ok(panic) = err.try_into_panic() {
                error!("Task panicked");
                std::panic::resume_unwind(panic);
            }
            debug!("Task cancelled");
            Err(e!(SupervisorError::TaskCancelled))
        }
    };

    // Ensure the HTTP server terminated, there is no harm in calling this after it is
    // already shut down.
    if let Some(server) = relay_http_server {
        server.shutdown();
    }

    // Ensure the QUIC server is closed
    if let Some(server) = quic_server {
        server.shutdown().await;
    }

    // Stop all remaining tasks
    tasks.shutdown().await;

    ret
}
