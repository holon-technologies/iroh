use std::{convert::Infallible, io, net::SocketAddr, num::NonZeroU32, sync::Arc, time::Instant};

use axum::Router;
use axum_server::accept::Accept;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use tokio::{net::TcpListener, task::JoinSet};
use tokio_util::sync::CancellationToken;
use tower_service::Service;
use tracing::{debug, warn};

use crate::admission::{AdmissionControl, ConnectionAdmission};

use super::tls::TlsAcceptor;

/// Serve all connections accepted by `listener` while enforcing global admission limits.
///
/// Admission happens synchronously in the accept loop, before a per-connection task is
/// created. The returned future owns and observes every connection task it creates.
pub(super) async fn serve_listener(
    listener: TcpListener,
    app: Router,
    tls_acceptor: Option<TlsAcceptor>,
    admission: Arc<AdmissionControl>,
    max_http2_streams: NonZeroU32,
    cancel: CancellationToken,
) -> io::Result<()> {
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http2()
        .max_concurrent_streams(max_http2_streams.get());
    let builder = Arc::new(builder);
    let mut connections = JoinSet::new();

    'accept: loop {
        tokio::select! {
            () = cancel.cancelled() => break 'accept,
            accepted = listener.accept() => {
                let (stream, peer_addr) = accepted?;
                let lease = match admission.try_connection(Instant::now()) {
                    ConnectionAdmission::Accepted(lease) => lease,
                    ConnectionAdmission::RateLimited => {
                        debug!(%peer_addr, "rejecting rate-limited HTTP connection");
                        continue;
                    }
                    ConnectionAdmission::CapacityFull => {
                        debug!(%peer_addr, "rejecting HTTP connection at capacity");
                        continue;
                    }
                };

                let mut make_service = app
                    .clone()
                    .into_make_service_with_connect_info::<SocketAddr>();
                let service = unwrap_infallible(make_service.call(peer_addr).await);
                let builder = builder.clone();
                let tls_acceptor = tls_acceptor.clone();
                let cancel = cancel.clone();
                connections.spawn(async move {
                    let _lease = lease;
                    if let Some(acceptor) = tls_acceptor {
                        let (stream, service) = acceptor.accept(stream, service).await?;
                        let connection = builder
                            .serve_connection_with_upgrades(
                                TokioIo::new(stream),
                                TowerToHyperService::new(service),
                            );
                        tokio::pin!(connection);
                        tokio::select! {
                            result = &mut connection => result.map_err(io::Error::other),
                            () = cancel.cancelled() => {
                                connection.as_mut().graceful_shutdown();
                                connection.await.map_err(io::Error::other)
                            }
                        }
                    } else {
                        let connection = builder
                            .serve_connection_with_upgrades(
                                TokioIo::new(stream),
                                TowerToHyperService::new(service),
                            );
                        tokio::pin!(connection);
                        tokio::select! {
                            result = &mut connection => result.map_err(io::Error::other),
                            () = cancel.cancelled() => {
                                connection.as_mut().graceful_shutdown();
                                connection.await.map_err(io::Error::other)
                            }
                        }
                    }
                });
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                match completed {
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err(error))) => debug!(?error, "HTTP connection ended with an error"),
                    Some(Err(error)) if error.is_cancelled() => {}
                    Some(Err(error)) => {
                        warn!(?error, "HTTP connection task panicked");
                        return Err(io::Error::other(error));
                    }
                    None => {}
                }
            }
        }
    }

    while let Some(completed) = connections.join_next().await {
        match completed {
            Ok(Ok(())) => {}
            Ok(Err(error)) => debug!(?error, "HTTP connection ended during shutdown"),
            Err(error) if error.is_cancelled() => {}
            Err(error) => return Err(io::Error::other(error)),
        }
    }
    Ok(())
}

fn unwrap_infallible<T>(result: Result<T, Infallible>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => match error {},
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::field_reassign_with_default,
        reason = "the saturation fixture overrides one limit"
    )]

    use std::{sync::Arc, time::Duration};

    use axum::Router;
    use tokio::{net::TcpListener, time::timeout};

    use crate::{
        admission::AdmissionControl,
        config::{IngressPolicy, LimitsConfig},
        metrics::Metrics,
    };

    use super::*;

    #[tokio::test]
    async fn listener_rejects_connections_before_spawning_past_capacity() {
        let mut limits = LimitsConfig::default();
        limits.max_http_connections = 1;
        let policy = IngressPolicy::try_from(&limits).expect("test policy is valid");
        let metrics = Arc::new(Metrics::default());
        let admission = Arc::new(AdmissionControl::new(
            policy.clone(),
            metrics.clone(),
            Instant::now(),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let task = tokio::spawn(serve_listener(
            listener,
            Router::new(),
            None,
            admission,
            policy.max_http2_streams_per_connection,
            cancel.clone(),
        ));

        let first = tokio::net::TcpStream::connect(addr).await.unwrap();
        timeout(Duration::from_secs(2), async {
            while metrics.http_connections_active.get() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first connection should be admitted");

        let mut rejected = Vec::new();
        for _ in 0..10 {
            rejected.push(tokio::net::TcpStream::connect(addr).await.unwrap());
        }
        timeout(Duration::from_secs(2), async {
            while metrics.http_connections_rejected_capacity.get() != 10 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("second connection should be rejected");
        assert_eq!(metrics.http_connections_active.get(), 1);

        drop(rejected);
        drop(first);
        timeout(Duration::from_secs(2), async {
            while metrics.http_connections_active.get() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropping the admitted connection should release capacity");

        let recovered = tokio::net::TcpStream::connect(addr).await.unwrap();
        timeout(Duration::from_secs(2), async {
            while metrics.http_connections_active.get() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("listener should recover after overload");
        assert_eq!(metrics.http_connections_rejected_capacity.get(), 10);

        drop(recovered);
        cancel.cancel();
        timeout(Duration::from_secs(2), task)
            .await
            .expect("listener should shut down within its test budget")
            .expect("listener task should not panic")
            .expect("listener shutdown should succeed");
    }
}
