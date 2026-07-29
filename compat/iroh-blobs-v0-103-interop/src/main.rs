//! Process-level transfer checks between the upstream v0.103 and local v2 blob stacks.

use std::{future::Future, str::FromStr, time::Duration};

use anyhow::{Context, Result, ensure};
use iroh_v1::{
    EndpointAddr as EndpointAddrV1, EndpointId as EndpointIdV1, TransportAddr as TransportAddrV1,
};
use iroh_v2::{EndpointAddr as EndpointAddrV2, EndpointId as EndpointIdV2};

const PAYLOAD: &[u8] = b"iroh-blobs v0.103.0 <-> holon iroh v2 interoperability";
const PHASE_TIMEOUT: Duration = Duration::from_secs(15);

async fn phase<T>(name: &'static str, future: impl Future<Output = Result<T>>) -> Result<T> {
    eprintln!("interop: {name}");
    tokio::time::timeout(PHASE_TIMEOUT, future)
        .await
        .with_context(|| format!("{name} timed out after {PHASE_TIMEOUT:?}"))?
}

fn v1_to_v2(addr: EndpointAddrV1) -> Result<EndpointAddrV2> {
    let id = EndpointIdV2::from_str(&addr.id.to_string()).context("parse v1 endpoint id as v2")?;
    let mut converted = EndpointAddrV2::new(id);
    for socket in addr.ip_addrs().copied() {
        converted = converted.with_ip_addr(socket);
    }
    ensure!(
        converted.ip_addrs().next().is_some(),
        "v1 provider did not advertise a direct address"
    );
    Ok(converted)
}

fn v2_to_v1(addr: EndpointAddrV2) -> Result<EndpointAddrV1> {
    let id = EndpointIdV1::from_str(&addr.id.to_string()).context("parse v2 endpoint id as v1")?;
    let direct_addresses = addr.ip_addrs().copied().collect::<Vec<_>>();
    ensure!(
        !direct_addresses.is_empty(),
        "v2 provider did not advertise a direct address"
    );
    Ok(EndpointAddrV1::from_parts(
        id,
        direct_addresses.into_iter().map(TransportAddrV1::Ip),
    ))
}

async fn current_client_reads_baseline_provider() -> Result<()> {
    eprintln!("interop: current client -> baseline provider");
    let store = iroh_blobs_v1::store::mem::MemStore::new();
    let tag = store.add_slice(PAYLOAD).await?;
    let endpoint = iroh_v1::Endpoint::bind(iroh_v1::endpoint::presets::Minimal).await?;
    let router = iroh_v1::protocol::Router::builder(endpoint)
        .accept(
            iroh_blobs_v1::ALPN,
            iroh_blobs_v1::BlobsProtocol::new(&store, None),
        )
        .spawn();

    let client = iroh_v2::Endpoint::bind(iroh_v2::endpoint::presets::Minimal).await?;
    let provider = v1_to_v2(router.endpoint().addr())?;
    eprintln!("interop: baseline provider {provider:?}");
    let connection = phase("v2 connect to v0.103", async {
        Ok(client.connect(provider, iroh_blobs_v2::ALPN).await?)
    })
    .await?;
    let hash = iroh_blobs_v2::Hash::from_str(&tag.hash.to_string())?;
    let received = phase("v2 get from v0.103", async {
        Ok(iroh_blobs_v2::get::request::get_blob(connection, hash).await?)
    })
    .await?;
    ensure!(
        received.as_ref() == PAYLOAD,
        "v2 client received different bytes"
    );

    router.shutdown().await?;
    client.close().await;
    Ok(())
}

async fn baseline_client_reads_current_provider() -> Result<()> {
    eprintln!("interop: baseline client -> current provider");
    let store = iroh_blobs_v2::store::mem::MemStore::new();
    let tag = store.add_slice(PAYLOAD).await?;
    let endpoint = iroh_v2::Endpoint::bind(iroh_v2::endpoint::presets::Minimal).await?;
    let router = iroh_v2::protocol::Router::builder(endpoint)
        .accept(
            iroh_blobs_v2::ALPN,
            iroh_blobs_v2::BlobsProtocol::new(&store, None),
        )
        .spawn();

    let client = iroh_v1::Endpoint::bind(iroh_v1::endpoint::presets::Minimal).await?;
    let provider = v2_to_v1(router.endpoint().addr())?;
    eprintln!("interop: current provider {provider:?}");
    let connection = phase("v0.103 connect to v2", async {
        Ok(client.connect(provider, iroh_blobs_v1::ALPN).await?)
    })
    .await?;
    let hash = iroh_blobs_v1::Hash::from_str(&tag.hash.to_string())?;
    let received = phase("v0.103 get from v2", async {
        Ok(iroh_blobs_v1::get::request::get_blob(connection, hash).await?)
    })
    .await?;
    ensure!(
        received.as_ref() == PAYLOAD,
        "v0.103 client received different bytes"
    );

    router.shutdown().await?;
    client.close().await;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    current_client_reads_baseline_provider().await?;
    baseline_client_reads_current_provider().await?;
    println!("iroh-blobs v0.103.0/current bidirectional transfer passed");
    Ok(())
}
