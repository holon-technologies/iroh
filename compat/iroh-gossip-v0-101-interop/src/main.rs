//! Live protocol checks between upstream gossip v0.101 and the local v2 port.

use std::{str::FromStr, time::Duration};

use anyhow::{Context, Result, ensure};
use iroh_v1::{
    EndpointAddr as EndpointAddrV1, EndpointId as EndpointIdV1, TransportAddr as TransportAddrV1,
};
use iroh_v2::{EndpointAddr as EndpointAddrV2, EndpointId as EndpointIdV2};
use n0_future::StreamExt;

const CURRENT_PAYLOAD: &[u8] = b"gossip from holon iroh v2";
const BASELINE_PAYLOAD: &[u8] = b"gossip from upstream v0.101";
const PHASE_TIMEOUT: Duration = Duration::from_secs(15);

fn v1_to_v2(addr: EndpointAddrV1) -> Result<EndpointAddrV2> {
    let id = EndpointIdV2::from_str(&addr.id.to_string()).context("parse v1 endpoint id as v2")?;
    let mut converted = EndpointAddrV2::new(id);
    for socket in addr.ip_addrs().copied() {
        converted = converted.with_ip_addr(socket);
    }
    ensure!(
        converted.ip_addrs().next().is_some(),
        "v1 node did not advertise a direct address"
    );
    Ok(converted)
}

fn v2_to_v1(addr: EndpointAddrV2) -> Result<EndpointAddrV1> {
    let id = EndpointIdV1::from_str(&addr.id.to_string()).context("parse v2 endpoint id as v1")?;
    let direct_addresses = addr.ip_addrs().copied().collect::<Vec<_>>();
    ensure!(
        !direct_addresses.is_empty(),
        "v2 node did not advertise a direct address"
    );
    Ok(EndpointAddrV1::from_parts(
        id,
        direct_addresses.into_iter().map(TransportAddrV1::Ip),
    ))
}

async fn run() -> Result<()> {
    let endpoint_v1 = iroh_v1::Endpoint::bind(iroh_v1::endpoint::presets::Minimal).await?;
    let gossip_v1 = iroh_gossip_v1::net::Gossip::builder().spawn(endpoint_v1.clone());
    let router_v1 = iroh_v1::protocol::Router::builder(endpoint_v1)
        .accept(iroh_gossip_v1::ALPN, gossip_v1.clone())
        .spawn();

    let endpoint_v2 = iroh_v2::Endpoint::bind(iroh_v2::endpoint::presets::Minimal).await?;
    let gossip_v2 = iroh_gossip_v2::net::Gossip::builder().spawn(endpoint_v2.clone());
    let router_v2 = iroh_v2::protocol::Router::builder(endpoint_v2)
        .accept(iroh_gossip_v2::ALPN, gossip_v2.clone())
        .spawn();

    ensure!(
        iroh_gossip_v1::ALPN == iroh_gossip_v2::ALPN,
        "gossip ALPN changed"
    );

    let v1_addr = router_v1.endpoint().addr();
    let v2_addr = router_v2.endpoint().addr();
    let v1_id_for_v2 = EndpointIdV2::from_str(&v1_addr.id.to_string())?;

    let lookup_v2 = iroh_v2::address_lookup::memory::MemoryLookup::new();
    lookup_v2.add_endpoint_info(v1_to_v2(v1_addr)?);
    router_v2.endpoint().address_lookup()?.add(lookup_v2);

    let lookup_v1 = iroh_v1::address_lookup::memory::MemoryLookup::new();
    lookup_v1.add_endpoint_info(v2_to_v1(v2_addr)?);
    router_v1.endpoint().address_lookup()?.add(lookup_v1);

    let topic_bytes = [0x42_u8; 32];
    let mut topic_v1 = gossip_v1
        .subscribe(iroh_gossip_v1::TopicId::from(topic_bytes), Vec::new())
        .await?;
    let mut topic_v2 = gossip_v2
        .subscribe(
            iroh_gossip_v2::TopicId::from(topic_bytes),
            vec![v1_id_for_v2],
        )
        .await?;

    tokio::time::timeout(PHASE_TIMEOUT, async {
        let (v1, v2) = tokio::join!(topic_v1.joined(), topic_v2.joined());
        v1?;
        v2?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("mixed-version mesh formation timed out")??;

    topic_v2.broadcast(CURRENT_PAYLOAD.to_vec().into()).await?;
    let event = tokio::time::timeout(PHASE_TIMEOUT, topic_v1.next())
        .await
        .context("v0.101 receive timed out")?
        .context("v0.101 topic closed")??;
    match event {
        iroh_gossip_v1::api::Event::Received(message) => {
            ensure!(message.content.as_ref() == CURRENT_PAYLOAD);
        }
        other => anyhow::bail!("v0.101 received unexpected event: {other:?}"),
    }

    topic_v1.broadcast(BASELINE_PAYLOAD.to_vec().into()).await?;
    let event = tokio::time::timeout(PHASE_TIMEOUT, topic_v2.next())
        .await
        .context("v2 receive timed out")?
        .context("v2 topic closed")??;
    match event {
        iroh_gossip_v2::api::Event::Received(message) => {
            ensure!(message.content.as_ref() == BASELINE_PAYLOAD);
        }
        other => anyhow::bail!("v2 received unexpected event: {other:?}"),
    }

    drop(topic_v1);
    drop(topic_v2);
    router_v1.shutdown().await?;
    router_v2.shutdown().await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    run().await?;
    println!("iroh-gossip v0.101.0/current bidirectional broadcast passed");
    Ok(())
}
