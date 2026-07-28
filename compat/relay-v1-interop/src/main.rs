//! Bidirectional process-level relay interoperability with upstream Iroh v1.0.3.
#![forbid(unsafe_code)]

use std::{net::Ipv4Addr, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
};

const IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HTTP_HEAD_BYTES: usize = 64 * 1024;
const CLIENTS_PER_RUN: usize = 2;
const CURRENT_PAYLOAD: &[u8] = b"current-to-v1";
const V1_PAYLOAD: &[u8] = b"v1-to-current";

#[derive(Clone, Copy, Debug)]
enum ForcedVersion {
    V1,
    V2,
}

impl ForcedVersion {
    fn subprotocol(self) -> &'static str {
        match self {
            Self::V1 => "iroh-relay-v1",
            Self::V2 => "iroh-relay-v2",
        }
    }

    fn key_byte(self) -> u8 {
        match self {
            Self::V1 => 31,
            Self::V2 => 41,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let provider = iroh_relay_current::tls::default_provider();
    let _ = provider.as_ref().clone().install_default();

    current_server_with_mixed_clients().await?;
    v1_server_with_mixed_clients().await?;
    println!("relay interoperability with upstream v1.0.3 passed in both directions");
    Ok(())
}

async fn current_server_with_mixed_clients() -> Result<()> {
    let mut config = iroh_relay_current::server::ServerConfig::default();
    config.relay = Some(iroh_relay_current::server::RelayConfig::new((
        Ipv4Addr::LOCALHOST,
        0,
    )));
    let server = iroh_relay_current::server::Server::spawn(config)
        .await
        .context("spawn current relay server")?;
    let addr = server
        .http_addr()
        .context("current relay server did not expose an HTTP address")?;

    for version in [ForcedVersion::V1, ForcedVersion::V2] {
        exercise_current_and_v1_clients(addr, version).await?;
    }
    server
        .shutdown()
        .await
        .context("shutdown current relay server")?;
    Ok(())
}

async fn v1_server_with_mixed_clients() -> Result<()> {
    let mut config = iroh_relay_v1::server::ServerConfig::default();
    config.relay = Some(iroh_relay_v1::server::RelayConfig::new((
        Ipv4Addr::LOCALHOST,
        0,
    )));
    let server = iroh_relay_v1::server::Server::spawn(config)
        .await
        .context("spawn upstream v1.0.3 relay server")?;
    let addr = server
        .http_addr()
        .context("upstream v1.0.3 relay server did not expose an HTTP address")?;

    for version in [ForcedVersion::V1, ForcedVersion::V2] {
        exercise_current_and_v1_clients(addr, version).await?;
    }
    server
        .shutdown()
        .await
        .context("shutdown upstream v1.0.3 relay server")?;
    Ok(())
}

async fn exercise_current_and_v1_clients(
    server_addr: std::net::SocketAddr,
    version: ForcedVersion,
) -> Result<()> {
    let proxy = VersionProxy::spawn(server_addr, version).await?;
    let current_secret = iroh_base_current::SecretKey::from_bytes(&[version.key_byte(); 32]);
    let v1_key_byte = version
        .key_byte()
        .checked_add(1)
        .context("fixed compatibility key byte overflowed")?;
    let v1_secret = iroh_base_v1::SecretKey::from_bytes(&[v1_key_byte; 32]);

    let current_url: iroh_base_current::RelayUrl =
        url::Url::parse(&format!("http://{}", proxy.addr()))?.into();
    let v1_url: iroh_base_v1::RelayUrl =
        url::Url::parse(&format!("http://{}", proxy.addr()))?.into();

    let mut current_client = iroh_relay_current::client::ClientBuilder::new(
        current_url,
        current_secret.clone(),
        iroh_resolver_current::DnsResolver::new(),
    )
    .tls_client_config(iroh_relay_current::tls::make_dangerous_client_config())
    .connect()
    .await
    .context("connect current client")?;

    let mut v1_client = iroh_relay_v1::client::ClientBuilder::new(
        v1_url,
        v1_secret.clone(),
        iroh_dns_v1::dns::DnsResolver::new(),
    )
    .tls_client_config(iroh_relay_v1::tls::make_dangerous_client_config())
    .connect()
    .await
    .context("connect upstream v1.0.3 client")?;

    let v1_endpoint_for_current =
        iroh_base_current::EndpointId::from_bytes(v1_secret.public().as_bytes())
            .context("translate v1 endpoint id to current type")?;
    current_client
        .send(
            iroh_relay_current::protos::relay::ClientToRelayMsg::Datagrams {
                dst_endpoint_id: v1_endpoint_for_current,
                datagrams: iroh_relay_current::protos::relay::Datagrams::from(CURRENT_PAYLOAD),
            },
        )
        .await
        .context("send current client datagram")?;

    let v1_received = tokio::time::timeout(IO_TIMEOUT, v1_client.next())
        .await
        .context("timed out waiting for current-to-v1 datagram")?
        .context("v1 client stream ended before receiving current datagram")?
        .context("v1 client failed receiving current datagram")?;
    match v1_received {
        iroh_relay_v1::protos::relay::RelayToClientMsg::Datagrams { datagrams, .. }
            if datagrams.contents.as_ref() == CURRENT_PAYLOAD => {}
        other => bail!("unexpected current-to-v1 relay message: {other:?}"),
    }

    let current_endpoint_for_v1 =
        iroh_base_v1::EndpointId::from_bytes(current_secret.public().as_bytes())
            .context("translate current endpoint id to v1 type")?;
    v1_client
        .send(iroh_relay_v1::protos::relay::ClientToRelayMsg::Datagrams {
            dst_endpoint_id: current_endpoint_for_v1,
            datagrams: iroh_relay_v1::protos::relay::Datagrams::from(Bytes::from_static(
                V1_PAYLOAD,
            )),
        })
        .await
        .context("send v1 client datagram")?;

    let current_received = tokio::time::timeout(IO_TIMEOUT, current_client.next())
        .await
        .context("timed out waiting for v1-to-current datagram")?
        .context("current client stream ended before receiving v1 datagram")?
        .context("current client failed receiving v1 datagram")?;
    match current_received {
        iroh_relay_current::protos::relay::RelayToClientMsg::Datagrams { datagrams, .. }
            if datagrams.contents.as_ref() == V1_PAYLOAD => {}
        other => bail!("unexpected v1-to-current relay message: {other:?}"),
    }

    drop(current_client);
    drop(v1_client);
    proxy.join().await?;
    Ok(())
}

#[derive(Debug)]
struct VersionProxy {
    addr: std::net::SocketAddr,
    task: tokio::task::JoinHandle<Result<()>>,
}

impl VersionProxy {
    async fn spawn(target: std::net::SocketAddr, version: ForcedVersion) -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .context("bind compatibility version proxy")?;
        let addr = listener
            .local_addr()
            .context("read compatibility version proxy address")?;
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            for _ in 0..CLIENTS_PER_RUN {
                let (client, _) = tokio::time::timeout(IO_TIMEOUT, listener.accept())
                    .await
                    .context("timed out accepting compatibility proxy connection")?
                    .context("accept compatibility proxy connection")?;
                connections.spawn(proxy_connection(client, target, version));
            }
            while let Some(result) = connections.join_next().await {
                result.context("compatibility proxy connection task panicked")??;
            }
            Ok(())
        });
        Ok(Self { addr, task })
    }

    fn addr(&self) -> std::net::SocketAddr {
        self.addr
    }

    async fn join(self) -> Result<()> {
        tokio::time::timeout(IO_TIMEOUT, self.task)
            .await
            .context("timed out stopping compatibility version proxy")?
            .context("compatibility version proxy task panicked")??;
        Ok(())
    }
}

async fn proxy_connection(
    mut client: TcpStream,
    target: std::net::SocketAddr,
    version: ForcedVersion,
) -> Result<()> {
    let mut server = TcpStream::connect(target)
        .await
        .context("connect compatibility proxy to relay server")?;

    let (request, request_tail) = read_http_head(&mut client).await?;
    let request = force_subprotocol(&request, version)?;
    server
        .write_all(&request)
        .await
        .context("forward rewritten compatibility upgrade request")?;
    server
        .write_all(&request_tail)
        .await
        .context("forward bytes following compatibility upgrade request")?;

    let (response, response_tail) = read_http_head(&mut server).await?;
    assert_selected_subprotocol(&response, version)?;
    client
        .write_all(&response)
        .await
        .context("forward compatibility upgrade response")?;
    client
        .write_all(&response_tail)
        .await
        .context("forward bytes following compatibility upgrade response")?;

    tokio::io::copy_bidirectional(&mut client, &mut server)
        .await
        .context("proxy relay WebSocket stream")?;
    Ok(())
}

async fn read_http_head(stream: &mut (impl AsyncRead + Unpin)) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let read = tokio::time::timeout(IO_TIMEOUT, stream.read(&mut chunk))
            .await
            .context("timed out reading compatibility HTTP head")?
            .context("read compatibility HTTP head")?;
        ensure!(read != 0, "connection ended before compatibility HTTP head");
        let next_len = head
            .len()
            .checked_add(read)
            .context("compatibility HTTP head length overflowed")?;
        ensure!(
            next_len <= MAX_HTTP_HEAD_BYTES,
            "compatibility HTTP head exceeded {MAX_HTTP_HEAD_BYTES} bytes"
        );
        head.extend_from_slice(&chunk[..read]);
        if let Some(index) = head.windows(4).position(|window| window == b"\r\n\r\n") {
            let tail = head.split_off(index + 4);
            return Ok((head, tail));
        }
    }
}

fn force_subprotocol(request: &[u8], version: ForcedVersion) -> Result<Vec<u8>> {
    let request =
        std::str::from_utf8(request).context("compatibility request head was not UTF-8")?;
    let mut rewritten = String::with_capacity(request.len());
    let mut replaced = false;
    for line in request.split_inclusive("\r\n") {
        if line
            .to_ascii_lowercase()
            .starts_with("sec-websocket-protocol:")
        {
            rewritten.push_str("Sec-WebSocket-Protocol: ");
            rewritten.push_str(version.subprotocol());
            rewritten.push_str("\r\n");
            replaced = true;
        } else {
            rewritten.push_str(line);
        }
    }
    ensure!(replaced, "client omitted relay WebSocket protocol offer");
    Ok(rewritten.into_bytes())
}

fn assert_selected_subprotocol(response: &[u8], version: ForcedVersion) -> Result<()> {
    let response = std::str::from_utf8(response).context("compatibility response was not UTF-8")?;
    let expected = format!("sec-websocket-protocol: {}", version.subprotocol());
    ensure!(
        response
            .lines()
            .any(|line| line.trim().eq_ignore_ascii_case(&expected)),
        "relay did not select forced protocol {}; response was {response:?}",
        version.subprotocol()
    );
    Ok(())
}
