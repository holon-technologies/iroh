//! Low-level HTTP server components for embedding the relay service.
//!
//! This module provides [`RelayService`] which can be used to embed relay functionality
//! into an existing HTTP server. It handles individual connections and provides
//! the core relay protocol implementation.
//!
//! For a complete relay server implementation, see the parent [`server`](super) module.

use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use http::{
    header::{CONNECTION, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL, SEC_WEBSOCKET_VERSION},
    response::Builder as ResponseBuilder,
};
use hyper::{
    HeaderMap, Method, Request, Response, StatusCode,
    body::Incoming,
    header::{HeaderValue, SEC_WEBSOCKET_ACCEPT, UPGRADE},
    service::Service,
    upgrade::Upgraded,
};
use n0_error::{e, ensure, stack_error};
use n0_future::MaybeFuture;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Notify, watch},
};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{Instrument, debug, error, info, info_span, trace, warn};

use super::{
    AdmissionPolicy, AllowAll, ClientRequest, DynAccessControl, SpawnError,
    admission::{AdmissionControl, EstablishmentAdmission, EstablishmentLease},
    clients::{Clients, RegisterError},
    streams::InvalidBucketConfig,
};
use crate::{
    KeyCache,
    defaults::{DEFAULT_KEY_CACHE_CAPACITY, timeouts::SERVER_WRITE_TIMEOUT},
    http::{
        CLIENT_AUTH_HEADER, ProtocolVersion, RELAY_PATH, SUPPORTED_WEBSOCKET_VERSION,
        WEBSOCKET_UPGRADE_PROTOCOL,
    },
    protos::{
        handshake,
        relay::MAX_FRAME_SIZE,
        streams::{BytesStreamSink, WsBytesFramed},
    },
    server::{
        ClientRateLimit,
        client::Config,
        metrics::Metrics,
        streams::{MaybeTlsStream, RateLimited, RelayedStream},
    },
};

mod connection;
mod listener;
mod service;
mod upgrade;

#[cfg(feature = "test-utils")]
pub use connection::InMemoryConnectError;
pub use connection::{AcceptError, ConnectionHandlerError, ServeConnectionError};
use connection::{clearable_timeout, downcast_upgrade, release_establishment_lease};
pub use listener::TlsConfig;
pub(super) use listener::{Server, ServerBuilder, ServerHandle};
#[cfg(feature = "test-utils")]
pub use service::RelayServiceRuntime;
pub(super) use service::TlsAcceptor;
pub use service::{Handlers, RelayService, RelayServiceWithNotify};
use upgrade::{ESTABLISH_TIMEOUT, RelayUpgradeReqError};

/// Boxed HTTP response body produced by [`RelayServiceWithNotify`].
pub type BytesBody = Box<
    dyn 'static + Send + Unpin + hyper::body::Body<Data = hyper::body::Bytes, Error = Infallible>,
>;
/// Boxed error type returned from [`RelayServiceWithNotify`]'s [`hyper::service::Service`] impl.
pub type HyperError = Box<dyn std::error::Error + Send + Sync>;
/// Result alias for HTTP responses produced by [`RelayServiceWithNotify`].
pub type HyperResult<T> = std::result::Result<T, HyperError>;
pub(super) type HyperHandler = Box<
    dyn Fn(Request<Incoming>, ResponseBuilder) -> HyperResult<Response<BytesBody>>
        + Send
        + Sync
        + 'static,
>;

/// Creates a new [`BytesBody`] with given content.
fn body_full(content: impl Into<hyper::body::Bytes>) -> BytesBody {
    Box::new(http_body_util::Full::new(content.into()))
}

#[cfg(test)]
mod tests;
