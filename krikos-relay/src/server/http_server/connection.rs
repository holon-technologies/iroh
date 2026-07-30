use super::*;

#[allow(clippy::result_large_err)]
pub(super) fn downcast_upgrade(
    upgraded: Upgraded,
) -> Result<(MaybeTlsStream, Bytes), ConnectionHandlerError> {
    match upgraded.downcast::<hyper_util::rt::TokioIo<MaybeTlsStream>>() {
        Ok(parts) => Ok((parts.io.into_inner(), parts.read_buf)),
        Err(_) => Err(e!(ConnectionHandlerError::DowncastUpgrade)),
    }
}

/// Errors when attempting to upgrade and
#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum ServeConnectionError {
    #[error("TLS[acme] handshake")]
    #[cfg(feature = "server-acme")]
    TlsHandshake {
        #[error(std_err)]
        source: std::io::Error,
    },
    #[error("TLS[acme] serve connection")]
    ServeConnection {
        #[error(std_err)]
        source: hyper::Error,
    },
    #[error("TLS[manual] accept")]
    ManualAccept {
        #[error(std_err)]
        source: std::io::Error,
    },
    #[error("TLS[acme] accept")]
    #[cfg(feature = "server-acme")]
    LetsEncryptAccept {
        #[error(std_err)]
        source: std::io::Error,
    },
    #[error("HTTPS connection")]
    Https {
        #[error(std_err)]
        source: hyper::Error,
    },
    #[error("HTTP connection")]
    Http {
        #[error(std_err)]
        source: hyper::Error,
    },
    #[error("Connection did not reach established state within timeout")]
    EstablishTimeout,
}

/// Server accept errors.
#[allow(missing_docs)]
#[stack_error(derive, add_meta, from_sources)]
#[non_exhaustive]
pub enum AcceptError {
    #[error(transparent)]
    Handshake { source: handshake::Error },
    #[error("rate limiting misconfigured")]
    RateLimitingMisconfigured { source: InvalidBucketConfig },
    #[error("relay client runtime rejected the actor")]
    Runtime {
        #[error(std_err)]
        source: krikos_runtime::SpawnError,
    },
    #[error("global relay session capacity is full")]
    GlobalSessionFull {},
    #[error("relay session capacity for the endpoint is full")]
    EndpointSessionFull {},
}

/// Failure while establishing a production relay session on an in-memory transport.
#[doc(hidden)]
#[cfg(feature = "test-utils")]
#[allow(missing_docs)]
#[stack_error(derive, add_meta, from_sources)]
#[non_exhaustive]
pub enum InMemoryConnectError {
    #[error("relay client session setup failed")]
    Client { source: crate::client::ConnectError },
    #[error("relay server session setup failed")]
    Server { source: AcceptError },
}

/// Server connection errors, includes errors that can happen on `accept`.
#[allow(missing_docs)]
#[stack_error(derive, add_meta, from_sources)]
#[non_exhaustive]
pub enum ConnectionHandlerError {
    #[error(transparent)]
    Accept { source: AcceptError },
    #[error("Could not downcast the upgraded connection to MaybeTlsStream")]
    DowncastUpgrade {},
    #[error("Cannot deal with buffered data yet: {buf:?}")]
    BufferNotEmpty { buf: Bytes },
}

/// Requires a future to complete before the specified duration elapses, unless the timeout is cleared.
///
/// If the future completes before the duration has elapsed, then the completed value is returned.
/// Otherwise, an error is returned and the future is canceled.
///
/// If `clear_timeout` is triggered, the timeout is cleared and the future is always run to completion.
pub(super) async fn clearable_timeout<F: Future>(
    timeout: Duration,
    clear_timeout: Arc<Notify>,
    establishment_lease: Arc<Mutex<Option<EstablishmentLease>>>,
    fut: F,
) -> Result<F::Output, Elapsed> {
    tokio::pin!(fut);
    let timeout = MaybeFuture::Some(tokio::time::sleep(timeout));
    tokio::pin!(timeout);
    loop {
        tokio::select! {
            biased;
            res = &mut fut => {
                return Ok(res);
            }
            _ = clear_timeout.notified() => {
                release_establishment_lease(&establishment_lease);
                timeout.as_mut().set_none();
            },
            _ = &mut timeout => {
                return Err(Elapsed);
            }
        }
    }
}

pub(super) fn release_establishment_lease(lease: &Mutex<Option<EstablishmentLease>>) {
    let mut lease = match lease.lock() {
        Ok(lease) => lease,
        Err(poisoned) => poisoned.into_inner(),
    };
    drop(lease.take());
}

#[stack_error(derive)]
#[error("Timeout elapsed")]
pub(super) struct Elapsed;
