use derive_more::Debug;

use super::*;

pub(super) const NO_CONTENT_CHALLENGE_HEADER: &str = "X-Iroh-Challenge";
pub(super) const NO_CONTENT_RESPONSE_HEADER: &str = "X-Iroh-Response";
const NOTFOUND: &[u8] = b"Not Found";
const ROBOTS_TXT: &[u8] = b"User-agent: *\nDisallow: /\n";
const INDEX: &[u8] = br#"<html><body>
<h1>Iroh Relay</h1>
<p>
  This is an <a href="https://iroh.computer/">Iroh</a> Relay server.
</p>
"#;
pub(super) const TLS_HEADERS: [(&str, &str); 2] = [
    (
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains",
    ),
    (
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'self'; block-all-mixed-content; plugin-types 'none'",
    ),
];

/// Creates a new [`BytesBody`] with no content.
fn body_empty() -> BytesBody {
    Box::new(http_body_util::Full::new(hyper::body::Bytes::new()))
}

pub(super) fn root_handler(
    _r: Request<Incoming>,
    response: ResponseBuilder,
) -> HyperResult<Response<BytesBody>> {
    let body: BytesBody = Box::new(Full::from(INDEX));
    response
        .status(StatusCode::OK)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(body)
        .map_err(|err| Box::new(err) as HyperError)
}

/// HTTP latency queries
pub(super) fn probe_handler(
    _r: Request<Incoming>,
    response: ResponseBuilder,
) -> HyperResult<Response<BytesBody>> {
    response
        .status(StatusCode::OK)
        .header("Access-Control-Allow-Origin", "*")
        .body(body_empty())
        .map_err(|err| Box::new(err) as HyperError)
}

pub(super) fn robots_handler(
    _r: Request<Incoming>,
    response: ResponseBuilder,
) -> HyperResult<Response<BytesBody>> {
    let body: BytesBody = Box::new(Full::from(ROBOTS_TXT));
    response
        .status(StatusCode::OK)
        .body(body)
        .map_err(|err| Box::new(err) as HyperError)
}

/// For captive portal detection.
pub(super) fn serve_no_content_handler<B: hyper::body::Body>(
    r: Request<B>,
    mut response: ResponseBuilder,
) -> HyperResult<Response<BytesBody>> {
    let check = |c: &HeaderValue| {
        !c.is_empty() && c.len() < 64 && c.as_bytes().iter().all(|c| is_challenge_char(*c as char))
    };

    if let Some(challenge) = r.headers().get(NO_CONTENT_CHALLENGE_HEADER)
        && check(challenge)
    {
        response = response.header(
            NO_CONTENT_RESPONSE_HEADER,
            format!("response {}", challenge.to_str()?),
        );
    }

    response
        .status(StatusCode::NO_CONTENT)
        .body(body_empty())
        .map_err(|err| Box::new(err) as HyperError)
}

fn is_challenge_char(c: char) -> bool {
    // Semi-randomly chosen as a limited set of valid characters
    c.is_ascii_lowercase()
        || c.is_ascii_uppercase()
        || c.is_ascii_digit()
        || c == '.'
        || c == '-'
        || c == '_'
}

/// Health check response
#[derive(Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
    git_hash: &'static str,
}

pub(super) fn healthz_handler(
    _r: Request<Incoming>,
    response: ResponseBuilder,
) -> HyperResult<Response<BytesBody>> {
    let health = Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        git_hash: "unknown",
    };
    let body = serde_json::to_string(&health).unwrap_or_else(|_| r#"{"status":"error"}"#.into());
    let body: BytesBody = Box::new(Full::from(body));
    response
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(body)
        .map_err(|err| Box::new(err) as HyperError)
}

/// This is a future that never returns, drop it to cancel/abort.
#[derive(Clone, Debug)]
pub(super) struct CaptivePortalAdmission {
    slots: Arc<tokio::sync::Semaphore>,
}

impl CaptivePortalAdmission {
    pub(super) fn new(capacity: NonZeroUsize) -> Self {
        Self {
            slots: Arc::new(tokio::sync::Semaphore::new(capacity.get())),
        }
    }

    pub(super) fn try_acquire(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.slots.clone().try_acquire_owned().ok()
    }
}

pub(super) async fn run_captive_portal_service(
    http_listener: TcpListener,
    capacity: NonZeroUsize,
    metrics: Arc<Metrics>,
) {
    info!("serving");

    // If this future is cancelled, this is dropped and all tasks are aborted.
    let mut tasks = JoinSet::new();
    let admission = CaptivePortalAdmission::new(capacity);

    loop {
        tokio::select! {
            biased;

            Some(res) = tasks.join_next() => {
                if let Err(err) = res
                    && err.is_panic()
                {
                    panic!("task panicked: {err:#?}");
                }
            }

            res = http_listener.accept() => {
                match res {
                    Ok((stream, peer_addr)) => {
                        let Some(permit) = admission.try_acquire() else {
                            metrics.captive_portal_admission_full.inc();
                            debug!(%peer_addr, "rejecting captive-portal connection: capacity full");
                            continue;
                        };
                        debug!(%peer_addr, "Connection opened",);
                        let handler = CaptivePortalService;

                        tasks.spawn(async move {
                            let _permit = permit;
                            let stream = crate::server::streams::MaybeTlsStream::Plain(stream);
                            let stream = hyper_util::rt::TokioIo::new(stream);
                            if let Err(err) = hyper::server::conn::http1::Builder::new()
                                .serve_connection(stream, handler)
                                .with_upgrades()
                                .await
                            {
                                error!("Failed to serve connection: {err:?}");
                            }
                        });
                    }
                    Err(err) => {
                        error!(
                            "[CaptivePortalService] failed to accept connection: {:#?}",
                            err
                        );
                    }
                }
            }
        }
    }
}

#[derive(Clone)]
struct CaptivePortalService;

impl hyper::service::Service<Request<Incoming>> for CaptivePortalService {
    type Response = Response<BytesBody>;
    type Error = HyperError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        match (req.method(), req.uri().path()) {
            // Captive Portal checker
            (&Method::GET, "/generate_204") => {
                Box::pin(async move { serve_no_content_handler(req, Response::builder()) })
            }
            _ => {
                // Return 404 not found response.
                let body: BytesBody = Box::new(Full::from(NOTFOUND));
                let r = Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(body)
                    .map_err(|err| Box::new(err) as HyperError);
                Box::pin(async move { r })
            }
        }
    }
}
