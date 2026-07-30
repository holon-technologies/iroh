use krikos::{Endpoint, endpoint::presets, protocol::Router};
use krikos_blobs::{ALPN as BLOBS_ALPN, BlobsProtocol, store::mem::MemStore};
use krikos_docs::{ALPN as DOCS_ALPN, protocol::Docs};
use krikos_gossip::{ALPN as GOSSIP_ALPN, net::Gossip};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // create an krikos endpoint that includes the standard address lookup mechanisms
    // we've built at number0
    let endpoint = Endpoint::bind(presets::N0).await?;

    // build the blobs protocol
    let blobs = MemStore::default();

    // build the gossip protocol
    let gossip = Gossip::builder().spawn(endpoint.clone());

    // build the docs protocol
    let docs = Docs::memory()
        .spawn(endpoint.clone(), (*blobs).clone(), gossip.clone())
        .await?;

    // create a router builder, we will add the
    // protocols to this builder and then spawn
    // the router
    let builder = Router::builder(endpoint.clone());

    // setup router
    let _router = builder
        .accept(BLOBS_ALPN, BlobsProtocol::new(&blobs, None))
        .accept(GOSSIP_ALPN, gossip)
        .accept(DOCS_ALPN, docs)
        .spawn();

    // do fun stuff with docs!
    Ok(())
}
