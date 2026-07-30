use std::sync::Arc;

use krikos_base::{PublicKey, SecretKey};
use krikos_resolver::DnsResolver;
use n0_error::{Result, StdResultExt, bail_any};
use n0_future::{SinkExt, StreamExt};
use n0_tracing_test::traced_test;
use rand::{RngExt, SeedableRng};
use reqwest::Url;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::info;

use super::*;
use crate::{
    client::{Client, ClientBuilder, ConnectError, conn::Conn},
    protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg},
    tls::{CaTlsConfig, default_provider},
};

pub(crate) fn make_tls_config() -> TlsConfig {
    let subject_alt_names = vec!["localhost".to_string()];

    let cert = rcgen::generate_simple_self_signed(subject_alt_names).unwrap();
    let rustls_certificate = cert.cert.der().clone();
    let rustls_key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let config = rustls::ServerConfig::builder_with_provider(default_provider())
        .with_safe_default_protocol_versions()
        .expect("protocols supported by selected provider")
        .with_no_client_auth()
        .with_single_cert(vec![(rustls_certificate)], rustls_key.into())
        .expect("cert is right");

    TlsConfig::new(Arc::new(config))
}

#[tokio::test]
#[traced_test]
async fn test_http_clients_and_server() -> Result {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

    let a_key = SecretKey::from_bytes(&rng.random());
    let b_key = SecretKey::from_bytes(&rng.random());

    // start server
    let server = ServerBuilder::new("127.0.0.1:0".parse().unwrap())
        .spawn()
        .await?;

    let addr = server.addr();

    // get dial info
    let port = addr.port();
    let addr = if let std::net::IpAddr::V4(ipv4_addr) = addr.ip() {
        ipv4_addr
    } else {
        bail_any!("cannot get ipv4 addr from socket addr {addr:?}");
    };

    info!("addr: {addr}:{port}");
    let relay_addr: Url = format!("http://{addr}:{port}").parse().unwrap();

    // create clients
    let (a_key, mut client_a) = create_test_client(a_key, relay_addr.clone()).await?;
    info!("created client {a_key:?}");
    let (b_key, mut client_b) = create_test_client(b_key, relay_addr).await?;
    info!("created client {b_key:?}");

    info!("ping a");
    client_a.send(ClientToRelayMsg::Ping([1u8; 8])).await?;
    let pong = client_a.next().await.expect("eos")?;
    assert!(matches!(pong, RelayToClientMsg::Pong { .. }));

    info!("ping b");
    client_b.send(ClientToRelayMsg::Ping([2u8; 8])).await?;
    let pong = client_b.next().await.expect("eos")?;
    assert!(matches!(pong, RelayToClientMsg::Pong { .. }));

    info!("sending message from a to b");
    let msg = Datagrams::from(b"hi there, client b!");
    client_a
        .send(ClientToRelayMsg::Datagrams {
            dst_endpoint_id: b_key,
            datagrams: msg.clone(),
        })
        .await?;
    info!("waiting for message from a on b");
    let (got_key, got_msg) =
        process_msg(client_b.next().await).expect("expected message from client_a");
    assert_eq!(a_key, got_key);
    assert_eq!(msg, got_msg);

    info!("sending message from b to a");
    let msg = Datagrams::from(b"right back at ya, client b!");
    client_b
        .send(ClientToRelayMsg::Datagrams {
            dst_endpoint_id: a_key,
            datagrams: msg.clone(),
        })
        .await?;
    info!("waiting for message b on a");
    let (got_key, got_msg) =
        process_msg(client_a.next().await).expect("expected message from client_b");
    assert_eq!(b_key, got_key);
    assert_eq!(msg, got_msg);

    // Close before shutting down, otherwise we'll try to send close frames on broken pipes
    client_a.close().await?;
    client_b.close().await?;
    server.shutdown();

    Ok(())
}

async fn create_test_client(
    key: SecretKey,
    server_url: Url,
) -> Result<(PublicKey, Client), ConnectError> {
    let public_key = key.public();
    let client = ClientBuilder::new(server_url, key, DnsResolver::new()).tls_client_config(
        CaTlsConfig::insecure_skip_verify()
            .client_config(default_provider())
            .expect("infallible"),
    );
    let client = client.connect().await?;

    Ok((public_key, client))
}

fn process_msg(
    msg: Option<Result<RelayToClientMsg, crate::client::RecvError>>,
) -> Option<(PublicKey, Datagrams)> {
    match msg {
        Some(Err(e)) => {
            info!("client `recv` error {e}");
            None
        }
        Some(Ok(msg)) => {
            info!("got message on: {msg:?}");
            if let RelayToClientMsg::Datagrams {
                remote_endpoint_id: source,
                datagrams,
            } = msg
            {
                Some((source, datagrams))
            } else {
                None
            }
        }
        None => {
            info!("client end of stream");
            None
        }
    }
}

#[tokio::test]
#[traced_test]
async fn test_subprotocol_negotiation_picks_latest() -> Result {
    let server = ServerBuilder::new("127.0.0.1:0".parse().unwrap())
        .spawn()
        .await?;
    let addr = server.addr();

    for offered in [
        "iroh-relay-v2,iroh-relay-v1",
        "iroh-relay-v1,iroh-relay-v2",
        "baz, iroh-relay-v1, iroh-relay-v2, boo",
        "foo, iroh-relay-v2, bar",
    ] {
        let ws_uri = format!("ws://{addr}{RELAY_PATH}");
        let (_stream, response) = tokio_websockets::ClientBuilder::new()
            .uri(&ws_uri)
            .expect("valid websocket URI")
            .add_header(
                SEC_WEBSOCKET_PROTOCOL,
                HeaderValue::from_str(offered).expect("valid subprotocol header value"),
            )
            .expect("header accepted by websocket client")
            .connect()
            .await
            .expect("websocket upgrade succeeds");
        let negotiated = response
            .headers()
            .get(SEC_WEBSOCKET_PROTOCOL)
            .expect("Sec-WebSocket-Protocol response header is present");
        assert_eq!(negotiated, "iroh-relay-v2", "offered={offered}");
    }

    server.shutdown();
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_https_clients_and_server() -> Result {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

    let a_key = SecretKey::from_bytes(&rng.random());
    let b_key = SecretKey::from_bytes(&rng.random());

    // create tls_config
    let tls_config = make_tls_config();

    // start server
    let mut server = ServerBuilder::new("127.0.0.1:0".parse().unwrap())
        .tls_config(Some(tls_config))
        .spawn()
        .await?;

    let addr = server.addr();

    // get dial info
    let port = addr.port();
    let addr = if let std::net::IpAddr::V4(ipv4_addr) = addr.ip() {
        ipv4_addr
    } else {
        bail_any!("cannot get ipv4 addr from socket addr {addr:?}");
    };

    info!("Relay listening on: {addr}:{port}");

    let url: Url = format!("https://localhost:{port}").parse().unwrap();

    // create clients
    let (a_key, mut client_a) = create_test_client(a_key, url.clone()).await?;
    info!("created client {a_key:?}");
    let (b_key, mut client_b) = create_test_client(b_key, url).await?;
    info!("created client {b_key:?}");

    info!("ping a");
    client_a.send(ClientToRelayMsg::Ping([1u8; 8])).await?;
    let pong = client_a.next().await.expect("eos")?;
    assert!(matches!(pong, RelayToClientMsg::Pong { .. }));

    info!("ping b");
    client_b.send(ClientToRelayMsg::Ping([2u8; 8])).await?;
    let pong = client_b.next().await.expect("eos")?;
    assert!(matches!(pong, RelayToClientMsg::Pong { .. }));

    info!("sending message from a to b");
    let msg = Datagrams::from(b"hi there, client b!");
    client_a
        .send(ClientToRelayMsg::Datagrams {
            dst_endpoint_id: b_key,
            datagrams: msg.clone(),
        })
        .await?;
    info!("waiting for message from a on b");
    let (got_key, got_msg) =
        process_msg(client_b.next().await).expect("expected message from client_a");
    assert_eq!(a_key, got_key);
    assert_eq!(msg, got_msg);

    info!("sending message from b to a");
    let msg = Datagrams::from(b"right back at ya, client b!");
    client_b
        .send(ClientToRelayMsg::Datagrams {
            dst_endpoint_id: a_key,
            datagrams: msg.clone(),
        })
        .await?;
    info!("waiting for message b on a");
    let (got_key, got_msg) =
        process_msg(client_a.next().await).expect("expected message from client_b");
    assert_eq!(b_key, got_key);
    assert_eq!(msg, got_msg);

    // Close before shutting down, otherwise we'll try to send close frames on broken pipes
    client_a.close().await?;
    client_b.close().await?;
    server.shutdown();
    server.task_handle().await.std_context("join")?;

    Ok(())
}

async fn make_test_client(client: tokio::io::DuplexStream, key: &SecretKey) -> Result<Conn> {
    let client = crate::client::streams::MaybeTlsStream::Test(client);
    let client = tokio_websockets::ClientBuilder::new().take_over(client);
    let client = Conn::new(client, KeyCache::test(), key, Default::default()).await?;
    Ok(client)
}

#[tokio::test]
#[traced_test]
async fn test_server_basic() -> Result {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

    info!("Create the server.");
    let metrics = Arc::new(Metrics::default());
    let service = RelayService::new(
        Default::default(),
        Default::default(),
        None,
        KeyCache::test(),
        Arc::new(crate::server::AllowAll),
        metrics.clone(),
    );

    info!("Create client A and connect it to the server.");
    let key_a = SecretKey::from_bytes(&rng.random());
    let public_key_a = key_a.public();
    let (client_a, rw_a) = tokio::io::duplex(10);
    let s = service.clone();
    let handler_task = tokio::spawn(async move {
        s.0.accept(
            MaybeTlsStream::Test(rw_a),
            Request::new(()).into_parts().0,
            Default::default(),
        )
        .await
    });
    let mut client_a = make_test_client(client_a, &key_a).await?;
    handler_task.await.std_context("join")??;

    info!("Create client B and connect it to the server.");
    let key_b = SecretKey::from_bytes(&rng.random());
    let public_key_b = key_b.public();
    let (client_b, rw_b) = tokio::io::duplex(10);
    let s = service.clone();
    let handler_task = tokio::spawn(async move {
        s.0.accept(
            MaybeTlsStream::Test(rw_b),
            Request::new(()).into_parts().0,
            Default::default(),
        )
        .await
    });
    let mut client_b = make_test_client(client_b, &key_b).await?;
    handler_task.await.std_context("join")??;

    info!("Send message from A to B.");
    let msg = Datagrams::from(b"hello client b!!");
    client_a
        .send(ClientToRelayMsg::Datagrams {
            dst_endpoint_id: public_key_b,
            datagrams: msg.clone(),
        })
        .await?;
    match client_b.next().await.unwrap()? {
        RelayToClientMsg::Datagrams {
            remote_endpoint_id,
            datagrams,
        } => {
            assert_eq!(public_key_a, remote_endpoint_id);
            assert_eq!(msg, datagrams);
        }
        msg => {
            bail_any!("expected ReceivedDatagrams msg, got {msg:?}");
        }
    }

    info!("Send message from B to A.");
    let msg = Datagrams::from(b"nice to meet you client a!!");
    client_b
        .send(ClientToRelayMsg::Datagrams {
            dst_endpoint_id: public_key_a,
            datagrams: msg.clone(),
        })
        .await?;
    match client_a.next().await.unwrap()? {
        RelayToClientMsg::Datagrams {
            remote_endpoint_id,
            datagrams,
        } => {
            assert_eq!(public_key_b, remote_endpoint_id);
            assert_eq!(msg, datagrams);
        }
        msg => {
            bail_any!("expected ReceivedDatagrams msg, got {msg:?}");
        }
    }

    info!("Close the server and clients");
    service.shutdown().await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    info!("Fail to send message from A to B.");
    let res = client_a
        .send(ClientToRelayMsg::Datagrams {
            dst_endpoint_id: public_key_b,
            datagrams: Datagrams::from(b"try to send"),
        })
        .await;
    assert!(res.is_err());
    assert!(client_b.next().await.is_none());

    drop(client_a);
    drop(client_b);

    service.shutdown().await;

    assert_eq!(metrics.accepts.get(), metrics.disconnects.get());

    Ok(())
}

#[tokio::test]
async fn test_server_replace_client() -> Result {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

    info!("Create the server.");
    let service = RelayService::new(
        Default::default(),
        Default::default(),
        None,
        KeyCache::test(),
        Arc::new(crate::server::AllowAll),
        Default::default(),
    );

    info!("Create client A and connect it to the server.");
    let key_a = SecretKey::from_bytes(&rng.random());
    let public_key_a = key_a.public();
    let (client_a, rw_a) = tokio::io::duplex(10);
    let s = service.clone();
    let handler_task = tokio::spawn(async move {
        s.0.accept(
            MaybeTlsStream::Test(rw_a),
            Request::new(()).into_parts().0,
            Default::default(),
        )
        .await
    });
    let mut client_a = make_test_client(client_a, &key_a).await?;
    handler_task.await.std_context("join")??;

    info!("Create client B and connect it to the server.");
    let key_b = SecretKey::from_bytes(&rng.random());
    let public_key_b = key_b.public();
    let (client_b, rw_b) = tokio::io::duplex(10);
    let s = service.clone();
    let handler_task = tokio::spawn(async move {
        s.0.accept(
            MaybeTlsStream::Test(rw_b),
            Request::new(()).into_parts().0,
            Default::default(),
        )
        .await
    });
    let mut client_b = make_test_client(client_b, &key_b).await?;
    handler_task.await.std_context("join")??;

    info!("Send message from A to B.");
    let msg = Datagrams::from(b"hello client b!!");
    client_a
        .send(ClientToRelayMsg::Datagrams {
            dst_endpoint_id: public_key_b,
            datagrams: msg.clone(),
        })
        .await?;
    match client_b.next().await.expect("eos")? {
        RelayToClientMsg::Datagrams {
            remote_endpoint_id,
            datagrams,
        } => {
            assert_eq!(public_key_a, remote_endpoint_id);
            assert_eq!(msg, datagrams);
        }
        msg => {
            bail_any!("expected ReceivedDatagrams msg, got {msg:?}");
        }
    }

    info!("Send message from B to A.");
    let msg = Datagrams::from(b"nice to meet you client a!!");
    client_b
        .send(ClientToRelayMsg::Datagrams {
            dst_endpoint_id: public_key_a,
            datagrams: msg.clone(),
        })
        .await?;
    match client_a.next().await.expect("eos")? {
        RelayToClientMsg::Datagrams {
            remote_endpoint_id,
            datagrams,
        } => {
            assert_eq!(public_key_b, remote_endpoint_id);
            assert_eq!(msg, datagrams);
        }
        msg => {
            bail_any!("expected ReceivedDatagrams msg, got {msg:?}");
        }
    }

    info!("Create client B and connect it to the server");
    let (new_client_b, new_rw_b) = tokio::io::duplex(10);
    let s = service.clone();
    let handler_task = tokio::spawn(async move {
        s.0.accept(
            MaybeTlsStream::Test(new_rw_b),
            Request::new(()).into_parts().0,
            Default::default(),
        )
        .await
    });
    let mut new_client_b = make_test_client(new_client_b, &key_b).await?;
    handler_task.await.std_context("join")??;

    // assert!(client_b.recv().await.is_err());

    info!("Send message from A to B.");
    let msg = Datagrams::from(b"are you still there, b?!");
    client_a
        .send(ClientToRelayMsg::Datagrams {
            dst_endpoint_id: public_key_b,
            datagrams: msg.clone(),
        })
        .await?;
    match new_client_b.next().await.expect("eos")? {
        RelayToClientMsg::Datagrams {
            remote_endpoint_id,
            datagrams,
        } => {
            assert_eq!(public_key_a, remote_endpoint_id);
            assert_eq!(msg, datagrams);
        }
        msg => {
            bail_any!("expected ReceivedDatagrams msg, got {msg:?}");
        }
    }

    info!("Send message from B to A.");
    let msg = Datagrams::from(b"just had a spot of trouble but I'm back now,a!!");
    new_client_b
        .send(ClientToRelayMsg::Datagrams {
            dst_endpoint_id: public_key_a,
            datagrams: msg.clone(),
        })
        .await?;
    match client_a.next().await.expect("eos")? {
        RelayToClientMsg::Datagrams {
            remote_endpoint_id,
            datagrams,
        } => {
            assert_eq!(public_key_b, remote_endpoint_id);
            assert_eq!(msg, datagrams);
        }
        msg => {
            bail_any!("expected ReceivedDatagrams msg, got {msg:?}");
        }
    }

    info!("Close the server and clients");
    service.shutdown().await;

    info!("Sending message from A to B fails");
    let res = client_a
        .send(ClientToRelayMsg::Datagrams {
            dst_endpoint_id: public_key_b,
            datagrams: Datagrams::from(b"try to send"),
        })
        .await;
    assert!(res.is_err());
    assert!(new_client_b.next().await.is_none());
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_establish_timeout() -> Result {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42u64);

    // Start server with a very short establish timeout.
    let server = ServerBuilder::new("127.0.0.1:0".parse().unwrap())
        .establish_timeout(Duration::from_millis(500))
        .spawn()
        .await?;

    let addr = server.addr();
    let port = addr.port();
    let addr = if let std::net::IpAddr::V4(ipv4_addr) = addr.ip() {
        ipv4_addr
    } else {
        bail_any!("cannot get ipv4 addr from socket addr {addr:?}");
    };
    let relay_url: Url = format!("http://{addr}:{port}").parse().unwrap();

    // 1. A lingering connection that never upgrades should be aborted by the timeout.
    info!("opening lingering TCP connection (no upgrade)");
    let mut lingering = TcpStream::connect(format!("{addr}:{port}")).await?;
    // Write a partial HTTP request but never complete the upgrade.
    lingering
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
        .await?;
    // Wait for the server to abort this connection.
    let mut buf = [0u8; 1];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let read = tokio::time::timeout_at(deadline, lingering.read(&mut buf)).await;
    // The server should close the connection, resulting in a read of 0 bytes or an error.
    match read {
        Ok(Ok(0)) => info!("lingering connection closed by server (EOF)"),
        Ok(Err(e)) => info!("lingering connection closed by server (error: {e})"),
        other => bail_any!("expected lingering connection to be closed, got {other:?}"),
    }

    // 2. A properly established client should NOT be aborted by the timeout.
    info!("connecting a proper relay client");
    let key = SecretKey::from_bytes(&rng.random());
    let (_, mut client) = create_test_client(key, relay_url).await?;

    // Wait longer than the establish timeout to prove the connection survives.
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Ping should still work.
    client.send(ClientToRelayMsg::Ping([7u8; 8])).await?;
    let pong = client.next().await.expect("expected pong")?;
    assert!(matches!(pong, RelayToClientMsg::Pong { .. }));
    info!("established connection survived past the timeout");

    client.close().await?;
    server.shutdown();
    Ok(())
}

#[tokio::test]
async fn pending_establishment_limit_rejects_without_spawning() -> Result {
    let limits = crate::server::Limits {
        accept_conn_limit: Some(10_000.0),
        accept_conn_burst: Some(100),
        max_pending_establishments: 2,
        ..crate::server::Limits::default()
    };
    let policy = AdmissionPolicy::try_from(&limits)?;
    let server = ServerBuilder::new("127.0.0.1:0".parse().expect("valid test address"))
        .admission_policy(policy)
        .spawn()
        .await?;
    let metrics = server.service().0.metrics.clone();

    let mut first = TcpStream::connect(server.addr()).await?;
    first
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
        .await?;
    let mut second = TcpStream::connect(server.addr()).await?;
    second
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
        .await?;

    tokio::time::timeout(Duration::from_secs(1), async {
        while metrics.http_connections.get() != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .std_context("two pending connections were not admitted")?;

    let mut rejected = TcpStream::connect(server.addr()).await?;
    tokio::time::timeout(Duration::from_secs(1), async {
        while metrics.admission_pending_full.get() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .std_context("full pending capacity was not observed")?;

    let mut byte = [0_u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), rejected.read(&mut byte))
            .await
            .std_context("rejected socket remained open")??,
        0,
        "rejected socket must close immediately"
    );
    assert_eq!(
        metrics.http_connections.get(),
        2,
        "rejected socket must not spawn a connection task"
    );

    drop(first);
    drop(second);
    server.shutdown();
    Ok(())
}
