//! A fully-fledged krikos-relay server over HTTP or HTTPS.
//!
//! This module provides an API to run a full fledged krikos-relay server.  It is primarily
//! used by the `krikos-relay` binary in this crate.  It can be used to run a relay server in
//! other locations however.
//!
//! This code is fully written in a form of structured-concurrency: every spawned task is
//! always attached to a handle and when the handle is dropped the tasks abort.  So tasks
//! can not outlive their handle.  It is also always possible to await for completion of a
//! task.  Some tasks additionally have a method to do graceful shutdown.
//!
//! The relay server hosts the following services:
//!
//! - HTTPS `/relay`: The main URL endpoint to which clients connect and sends traffic over.
//! - HTTPS `/ping`: Used for net_report probes.
//! - HTTPS `/generate_204`: Used for net_report probes.

#[cfg(feature = "server-acme")]
use std::path::PathBuf;
use std::{
    borrow::Cow,
    future::Future,
    net::SocketAddr,
    num::{NonZeroU32, NonZeroUsize},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use http::{
    HeaderMap, HeaderValue, Method, Request, Response, StatusCode,
    header::{AUTHORIZATION, InvalidHeaderValue},
    response::Builder as ResponseBuilder,
};
use http_body_util::Full;
use hyper::body::Incoming;
use krikos_base::EndpointId;
#[cfg(feature = "test-utils")]
use krikos_base::RelayUrl;
use n0_error::{e, stack_error};
#[cfg(feature = "server-acme")]
use n0_future::StreamExt;
use n0_future::task::AbortOnDropHandle;
#[cfg(feature = "server-acme")]
use rustls::server::WantsServerCert;
use serde::Serialize;
use tokio::{
    net::TcpListener,
    task::{JoinError, JoinSet},
};
#[cfg(feature = "server-acme")]
use tokio_rustls_acme::acme::{LETS_ENCRYPT_PRODUCTION_DIRECTORY, LETS_ENCRYPT_STAGING_DIRECTORY};
use tracing::{Instrument, debug, error, info, info_span, instrument};

use self::http_server::{BytesBody, HyperError, HyperResult};
#[cfg(feature = "server-acme")]
use crate::tls::CaTlsConfig;
use crate::{
    defaults::DEFAULT_KEY_CACHE_CAPACITY,
    http::{AUTH_TOKEN_URL_QUERY_PARAM, ProtocolVersion, RELAY_PROBE_PATH},
    quic::server::{QuicServer, QuicSpawnError, ServerHandle as QuicServerHandle},
};

mod certs;
mod config;
mod limits;
mod routes;
mod supervisor;

#[cfg(feature = "server-acme")]
pub use certs::AcmeConfig;
pub use certs::CertConfig;
pub use config::{
    Access, AccessControl, AllowAll, ClientRateLimit, ClientRequest, ConnectionId,
    DynAccessControl, OnDisconnectGuard, QuicConfig, RelayConfig, ServerConfig, TlsConfig,
};
use limits::AdmissionPolicy;
pub use limits::{
    AdmissionPolicyError, DEFAULT_ACCEPT_CONN_BURST, DEFAULT_ACCEPT_CONN_LIMIT, Limits,
};
#[cfg(test)]
use routes::{CaptivePortalAdmission, NO_CONTENT_CHALLENGE_HEADER, NO_CONTENT_RESPONSE_HEADER};
use routes::{
    TLS_HEADERS, healthz_handler, probe_handler, robots_handler, root_handler,
    run_captive_portal_service, serve_no_content_handler,
};
pub use supervisor::{Server, SpawnError, SupervisorError};

#[cfg(feature = "server-acme")]
mod acme_cache;
mod admission;
pub mod client;
pub mod clients;
pub mod http_server;
mod metrics;
mod metrics_server;
pub(crate) mod resolver;
pub mod streams;
#[cfg(all(feature = "test-utils", with_crypto_provider))]
pub mod testing;

#[cfg(feature = "server-acme")]
pub use self::acme_cache::BoundedAcmeCache;
pub use self::{
    http_server::{Handlers, RelayService},
    metrics::{Metrics, RelayMetrics},
    resolver::{DEFAULT_CERT_RELOAD_INTERVAL, reloading_resolver},
};

#[cfg(test)]
mod tests;
