//! Provider-neutral HTTP endpoint for relay metrics.

use std::{convert::Infallible, net::SocketAddr, sync::Arc};

use http_body_util::Full;
use hyper::{Request, Response, body::Bytes, service::service_fn};
use iroh_metrics::{MetricsSource, Registry};
use tokio::{net::TcpListener, task::JoinSet};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{debug, error, info};

/// HTTP server exposing a registry in OpenMetrics text format.
#[derive(Debug)]
pub(super) struct MetricsServer {
    cancel: CancellationToken,
    task: AbortOnDropHandle<()>,
}

impl MetricsServer {
    pub(super) async fn spawn(addr: SocketAddr, registry: Arc<Registry>) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        info!(%local_addr, "metrics server listening");

        let cancel = CancellationToken::new();
        let task = tokio::spawn(run(listener, registry, cancel.clone()));
        Ok(Self {
            cancel,
            task: AbortOnDropHandle::new(task),
        })
    }

    pub(super) async fn shutdown(self) {
        self.cancel.cancel();
        let _ = self.task.await;
    }
}

async fn run(listener: TcpListener, registry: Arc<Registry>, cancel: CancellationToken) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            result = listener.accept() => match result {
                Ok((stream, _)) => {
                    connections.spawn(serve(stream, registry.clone(), cancel.clone()));
                }
                Err(error) => {
                    error!(%error, "metrics server accept failed");
                    break;
                }
            },
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    debug!(%error, "metrics connection task failed");
                }
            }
        }
    }

    while let Some(result) = connections.join_next().await {
        if let Err(error) = result {
            debug!(%error, "metrics connection task failed during shutdown");
        }
    }
}

async fn serve(stream: tokio::net::TcpStream, registry: Arc<Registry>, cancel: CancellationToken) {
    let service = service_fn(move |_request: Request<hyper::body::Incoming>| {
        let registry = registry.clone();
        async move {
            let response = match registry.encode_openmetrics_to_string() {
                Ok(content) => Response::builder()
                    .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
                    .body(Full::new(Bytes::from(content)))
                    .expect("static metrics response is valid"),
                Err(error) => Response::builder()
                    .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::new(Bytes::from(error.to_string())))
                    .expect("static metrics error response is valid"),
            };
            Ok::<_, Infallible>(response)
        }
    });
    let connection = hyper::server::conn::http1::Builder::new()
        .serve_connection(hyper_util::rt::TokioIo::new(stream), service);
    let mut connection = std::pin::pin!(connection);
    tokio::select! {
        result = connection.as_mut() => {
            if let Err(error) = result {
                debug!(%error, "metrics HTTP connection failed");
            }
        }
        () = cancel.cancelled() => {
            connection.as_mut().graceful_shutdown();
            if let Err(error) = connection.await {
                debug!(%error, "metrics HTTP connection failed during shutdown");
            }
        }
    }
}
