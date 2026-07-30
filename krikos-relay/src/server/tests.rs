use std::{net::Ipv4Addr, num::NonZeroUsize, sync::Arc, time::Duration};

use http::StatusCode;
use krikos_base::{EndpointId, RelayUrl, SecretKey};
use krikos_resolver::DnsResolver;
use n0_error::{Result, StackResultExt, StdResultExt};
use n0_future::{SinkExt, StreamExt};
use n0_tracing_test::traced_test;
use rand::{RngExt, SeedableRng};
use tracing::{info, instrument};
use url::Url;

use super::{
    Access, AccessControl, CaptivePortalAdmission, ClientRequest, NO_CONTENT_CHALLENGE_HEADER,
    NO_CONTENT_RESPONSE_HEADER, RelayConfig, Server, ServerConfig, SpawnError,
};
use crate::{
    client::{ClientBuilder, ConnectError},
    protos::{
        handshake,
        relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg},
    },
    test_utils::static_resolver,
    tls::{self, CaTlsConfig, default_provider},
};

/// An [`AccessControl`] backed by a closure, for tests.
#[derive(derive_more::Debug)]
struct TestAccess(#[debug("access fn")] Box<dyn Fn(&ClientRequest) -> Access + Send + Sync>);

impl AccessControl for TestAccess {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        (self.0)(request)
    }
}

async fn spawn_local_relay() -> std::result::Result<Server, SpawnError> {
    let mut relay = RelayConfig::new((Ipv4Addr::LOCALHOST, 0));
    relay.key_cache_capacity = Some(1024);
    Server::spawn(ServerConfig {
        relay: Some(relay),
        quic: None,
        metrics_addr: None,
    })
    .await
}

#[instrument]
async fn try_send_recv(
    client_a: &mut crate::client::Client,
    client_b: &mut crate::client::Client,
    b_key: EndpointId,
    msg: Datagrams,
) -> Result<RelayToClientMsg> {
    // try resend 10 times
    for _ in 0..10 {
        client_a
            .send(ClientToRelayMsg::Datagrams {
                dst_endpoint_id: b_key,
                datagrams: msg.clone(),
            })
            .await?;
        let Ok(res) = tokio::time::timeout(Duration::from_millis(500), client_b.next()).await
        else {
            continue;
        };
        let res = res.expect("stream finished")?;
        return Ok(res);
    }
    panic!("failed to send and recv message");
}

fn dns_resolver() -> DnsResolver {
    DnsResolver::new()
}

fn provider_config() -> rustls::ClientConfig {
    rustls::ClientConfig::builder_with_provider(default_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth()
}

#[tokio::test]
#[traced_test]
async fn test_no_services() {
    let mut server = Server::spawn(ServerConfig::default()).await.unwrap();
    let res = tokio::time::timeout(Duration::from_secs(5), server.join())
        .await
        .expect("timeout, server not finished")
        .expect("server task JoinError");
    assert!(res.is_err());
}

#[tokio::test]
#[traced_test]
async fn test_conflicting_bind() {
    let mut relay = RelayConfig::new((Ipv4Addr::LOCALHOST, 1234));
    relay.key_cache_capacity = Some(1024);
    let res = Server::spawn(ServerConfig {
        relay: Some(relay),
        quic: None,
        metrics_addr: Some((Ipv4Addr::LOCALHOST, 1234).into()),
    })
    .await;
    assert!(res.is_err()); // AddrInUse
}

#[tokio::test]
async fn invalid_admission_rate_limits_are_rejected_before_bind() {
    let invalid_limits = [
        (Some(200.0), None, "missing burst"),
        (None, Some(400), "missing rate"),
        (Some(f64::NAN), Some(400), "NaN rate"),
        (Some(f64::INFINITY), Some(400), "infinite rate"),
        (Some(f64::NEG_INFINITY), Some(400), "negative infinite rate"),
        (Some(0.0), Some(400), "zero rate"),
        (Some(-1.0), Some(400), "negative rate"),
        (Some(200.0), Some(0), "zero burst"),
    ];

    for (accept_conn_limit, accept_conn_burst, case) in invalid_limits {
        let mut relay = RelayConfig::new((Ipv4Addr::LOCALHOST, 0));
        relay.limits.accept_conn_limit = accept_conn_limit;
        relay.limits.accept_conn_burst = accept_conn_burst;

        let result = Server::spawn(ServerConfig {
            relay: Some(relay),
            quic: None,
            metrics_addr: None,
        })
        .await;

        assert!(
            matches!(result, Err(SpawnError::AdmissionPolicy { .. })),
            "{case} must fail startup with a typed admission error"
        );
    }
}

#[tokio::test]
async fn zero_admission_capacities_are_rejected_before_bind() {
    for case in [
        "max_pending_establishments",
        "max_registered_sessions",
        "max_sessions_per_endpoint",
    ] {
        let mut relay = RelayConfig::new((Ipv4Addr::LOCALHOST, 0));
        match case {
            "max_pending_establishments" => relay.limits.max_pending_establishments = 0,
            "max_registered_sessions" => relay.limits.max_registered_sessions = 0,
            "max_sessions_per_endpoint" => relay.limits.max_sessions_per_endpoint = 0,
            _ => unreachable!("test table contains only known capacity fields"),
        }

        let result = Server::spawn(ServerConfig {
            relay: Some(relay),
            quic: None,
            metrics_addr: None,
        })
        .await;

        assert!(
            matches!(result, Err(SpawnError::AdmissionPolicy { .. })),
            "{case}=0 must fail startup with a typed admission error"
        );
    }
}

#[tokio::test]
async fn unsupported_semaphore_capacities_are_rejected_before_bind() {
    for case in ["max_pending_establishments", "max_registered_sessions"] {
        let mut relay = RelayConfig::new((Ipv4Addr::LOCALHOST, 0));
        match case {
            "max_pending_establishments" => {
                relay.limits.max_pending_establishments = usize::MAX;
            }
            "max_registered_sessions" => {
                relay.limits.max_registered_sessions = usize::MAX;
            }
            _ => unreachable!("test table contains only semaphore capacity fields"),
        }

        let result = Server::spawn(ServerConfig {
            relay: Some(relay),
            quic: None,
            metrics_addr: None,
        })
        .await;
        assert!(
            matches!(result, Err(SpawnError::AdmissionPolicy { .. })),
            "{case} above Tokio's supported maximum must return a typed error"
        );
    }
}

#[tokio::test]
#[traced_test]
async fn test_root_handler() {
    let server = spawn_local_relay().await.unwrap();
    let url = format!("http://{}", server.http_addr().unwrap());

    let client = reqwest::Client::builder()
        .use_preconfigured_tls(provider_config())
        .build()
        .unwrap();
    let response = client.get(&url).send().await.unwrap();
    assert_eq!(response.status(), 200);
    let body = response.text().await.unwrap();
    assert!(body.contains("Krikos Relay"));
}

#[tokio::test]
#[traced_test]
async fn test_captive_portal_service() {
    let server = spawn_local_relay().await.unwrap();
    let url = format!("http://{}/generate_204", server.http_addr().unwrap());
    let challenge = "123az__.";

    let client = reqwest::Client::builder()
        .use_preconfigured_tls(provider_config())
        .build()
        .unwrap();
    let response = client
        .get(&url)
        .header(NO_CONTENT_CHALLENGE_HEADER, challenge)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let header = response.headers().get(NO_CONTENT_RESPONSE_HEADER).unwrap();
    assert_eq!(header.to_str().unwrap(), format!("response {challenge}"));
    let body = response.text().await.unwrap();
    assert!(body.is_empty());
}

#[test]
fn captive_portal_admission_limit_is_exact_and_recovers() {
    let capacity = NonZeroUsize::new(2).unwrap();
    let admission = CaptivePortalAdmission::new(capacity);

    let first = admission.try_acquire().expect("first slot");
    let _second = admission.try_acquire().expect("second slot");
    assert!(admission.try_acquire().is_none(), "third slot must reject");

    drop(first);
    assert!(
        admission.try_acquire().is_some(),
        "released capacity must be reusable"
    );
}

#[tokio::test]
#[traced_test]
async fn test_relay_clients() -> Result<()> {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
    let server = spawn_local_relay().await?;

    let relay_url = format!("http://{}", server.http_addr().unwrap());
    let relay_url: RelayUrl = relay_url.parse()?;

    let client_config = CaTlsConfig::default()
        .client_config(default_provider())
        .unwrap();

    // set up client a
    let a_secret_key = SecretKey::from_bytes(&rng.random());
    let a_key = a_secret_key.public();
    let resolver = dns_resolver();
    info!("client a build & connect");
    let mut client_a = ClientBuilder::new(relay_url.clone(), a_secret_key, resolver.clone())
        .tls_client_config(client_config.clone())
        .connect()
        .await?;

    // set up client b
    let b_secret_key = SecretKey::from_bytes(&rng.random());
    let b_key = b_secret_key.public();
    info!("client b build & connect");
    let mut client_b = ClientBuilder::new(relay_url.clone(), b_secret_key, resolver.clone())
        .tls_client_config(client_config)
        .connect()
        .await?;

    info!("sending a -> b");

    // send message from a to b
    let msg = Datagrams::from("hello, b");
    let res = try_send_recv(&mut client_a, &mut client_b, b_key, msg.clone()).await?;
    let RelayToClientMsg::Datagrams {
        remote_endpoint_id,
        datagrams,
    } = res
    else {
        panic!("client_b received unexpected message {res:?}");
    };

    assert_eq!(a_key, remote_endpoint_id);
    assert_eq!(msg, datagrams);

    info!("sending b -> a");
    // send message from b to a
    let msg = Datagrams::from("howdy, a");
    let res = try_send_recv(&mut client_b, &mut client_a, a_key, msg.clone()).await?;

    let RelayToClientMsg::Datagrams {
        remote_endpoint_id,
        datagrams,
    } = res
    else {
        panic!("client_a received unexpected message {res:?}");
    };

    assert_eq!(b_key, remote_endpoint_id);
    assert_eq!(msg, datagrams);

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_relay_access_control() -> Result<()> {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
    let current_span = tracing::info_span!("this is a test");
    let _guard = current_span.enter();

    let client_config = CaTlsConfig::default()
        .client_config(default_provider())
        .unwrap();

    let a_secret_key = SecretKey::from_bytes(&rng.random());
    let a_key = a_secret_key.public();

    let mut relay = RelayConfig::new((Ipv4Addr::LOCALHOST, 0));
    relay.key_cache_capacity = Some(1024);
    relay.access = Arc::new(TestAccess(Box::new(move |request| {
        let endpoint_id = request.endpoint_id();
        info!("checking {}", endpoint_id);
        // reject endpoint a
        if endpoint_id == a_key {
            Access::Deny { reason: None }
        } else {
            Access::Allow
        }
    })));
    let server = Server::spawn(ServerConfig {
        relay: Some(relay),
        quic: None,
        metrics_addr: None,
    })
    .await?;

    let relay_url = format!("http://{}", server.http_addr().unwrap());
    let relay_url: RelayUrl = relay_url.parse()?;

    // set up client a
    let resolver = dns_resolver();
    let result = ClientBuilder::new(relay_url.clone(), a_secret_key, resolver)
        .tls_client_config(client_config.clone())
        .connect()
        .await;

    assert!(
        matches!(result, Err(ConnectError::Handshake { source: handshake::Error::ServerDeniedAuth { reason, .. }, .. }) if reason == "not authorized")
    );

    // test that another client has access

    // set up client b
    let b_secret_key = SecretKey::from_bytes(&rng.random());
    let b_key = b_secret_key.public();

    let resolver = dns_resolver();
    let mut client_b = ClientBuilder::new(relay_url.clone(), b_secret_key, resolver)
        .tls_client_config(client_config.clone())
        .connect()
        .await?;

    // set up client c
    let c_secret_key = SecretKey::from_bytes(&rng.random());
    let c_key = c_secret_key.public();

    let resolver = dns_resolver();
    let mut client_c = ClientBuilder::new(relay_url.clone(), c_secret_key, resolver)
        .tls_client_config(client_config)
        .connect()
        .await?;

    // send message from b to c
    let msg = Datagrams::from("hello, c");
    let res = try_send_recv(&mut client_b, &mut client_c, c_key, msg.clone()).await?;

    if let RelayToClientMsg::Datagrams {
        remote_endpoint_id,
        datagrams,
    } = res
    {
        assert_eq!(b_key, remote_endpoint_id);
        assert_eq!(msg, datagrams);
    } else {
        panic!("client_c received unexpected message {res:?}");
    }

    Ok(())
}

/// Verifies that [`ClientBuilder::auth_token`] forwards a token to the
/// relay so the [`AccessControl::on_connect`] hook can read it via
/// [`ClientRequest::auth_token`].
#[tokio::test]
#[traced_test]
async fn test_relay_client_auth_token_forwarded() -> Result<()> {
    const TOKEN: &str = "secret-token";

    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
    let client_config = CaTlsConfig::default()
        .client_config(default_provider())
        .unwrap();

    let mut relay = RelayConfig::new((Ipv4Addr::LOCALHOST, 0));
    relay.key_cache_capacity = Some(1024);
    relay.access = Arc::new(TestAccess(Box::new(move |request| {
        if request.auth_token().as_deref() == Some(TOKEN) {
            Access::Allow
        } else {
            Access::Deny { reason: None }
        }
    })));
    let server = Server::spawn(ServerConfig {
        relay: Some(relay),
        quic: None,
        metrics_addr: None,
    })
    .await?;

    let relay_url = format!("http://{}", server.http_addr().unwrap());
    let relay_url: RelayUrl = relay_url.parse()?;

    // No query param: denied.
    let secret_key = SecretKey::from_bytes(&rng.random());
    let result = ClientBuilder::new(relay_url.clone(), secret_key, dns_resolver())
        .tls_client_config(client_config.clone())
        .connect()
        .await;
    assert!(matches!(
        result,
        Err(ConnectError::Handshake { source: handshake::Error::ServerDeniedAuth { reason, .. }, .. })
            if reason == "not authorized"
    ));

    // Wrong token: denied.
    let secret_key = SecretKey::from_bytes(&rng.random());
    let result = ClientBuilder::new(relay_url.clone(), secret_key, dns_resolver())
        .tls_client_config(client_config.clone())
        .auth_token("wrong-token")
        .connect()
        .await;
    assert!(matches!(
        result,
        Err(ConnectError::Handshake { source: handshake::Error::ServerDeniedAuth { reason, .. }, .. })
            if reason == "not authorized"
    ));

    // Correct token: connection succeeds.
    let secret_key = SecretKey::from_bytes(&rng.random());
    let _client = ClientBuilder::new(relay_url, secret_key, dns_resolver())
        .tls_client_config(client_config)
        .auth_token(TOKEN)
        .connect()
        .await?;

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_relay_clients_full() -> Result<()> {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
    let server = spawn_local_relay().await.unwrap();
    let relay_url = format!("http://{}", server.http_addr().unwrap());
    let relay_url: RelayUrl = relay_url.parse().unwrap();

    let client_config = CaTlsConfig::default()
        .client_config(default_provider())
        .unwrap();

    // set up client a
    let a_secret_key = SecretKey::from_bytes(&rng.random());
    let resolver = dns_resolver();
    let mut client_a = ClientBuilder::new(relay_url.clone(), a_secret_key, resolver.clone())
        .tls_client_config(client_config.clone())
        .connect()
        .await?;

    // set up client b
    let b_secret_key = SecretKey::from_bytes(&rng.random());
    let b_key = b_secret_key.public();
    let _client_b = ClientBuilder::new(relay_url.clone(), b_secret_key, resolver.clone())
        .tls_client_config(client_config)
        .connect()
        .await?;

    // send messages from a to b, without b receiving anything.
    // we should still keep succeeding to send, even if the packet won't be forwarded
    // by the relay server because the server's send queue for b fills up.
    let msg = Datagrams::from("hello, b");
    for _i in 0..1000 {
        client_a
            .send(ClientToRelayMsg::Datagrams {
                dst_endpoint_id: b_key,
                datagrams: msg.clone(),
            })
            .await?;
    }
    Ok(())
}

/// Regression test: A relay client that prefers IPv6 falls back to IPv4
/// when the advertised IPv6 address is unreachable.
#[tokio::test]
#[traced_test]
async fn test_relay_client_falls_back_to_ipv4() -> Result {
    // A relay reachable only over IPv4.
    let config = ServerConfig {
        relay: Some(RelayConfig::new((Ipv4Addr::LOCALHOST, 0))),
        ..Default::default()
    };
    let server = Server::spawn(config).await?;
    let addr = server.http_addr().expect("http relay address");

    // Resolves to both the real IPv4 address and an unreachable IPv6 address.
    let resolver = static_resolver(
        vec![Ipv4Addr::LOCALHOST],
        vec!["2001:db8::dead".parse().expect("valid IPv6")],
    );
    let url: Url = format!("http://relay.test:{}", addr.port())
        .parse()
        .expect("valid relay url");

    let client = ClientBuilder::new(url, SecretKey::generate(), resolver)
        .tls_client_config(tls::make_dangerous_client_config())
        // Force IPv6 preference
        .address_family_selector(|| true);

    tokio::time::timeout(Duration::from_secs(10), client.connect())
        .await
        .with_std_context(|_| "relay connect timed out")?
        .context("relay connect")?;

    server.shutdown().await.context("relay server shutdown")?;
    Ok(())
}
