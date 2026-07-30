mod support;

use krikos::{RelayUrl, SecretKey, endpoint_info::EndpointInfo};
use krikos_dns::dns::EndpointDnsResolver;
use mainline::{DhtBuilder, MutableItem, Testnet};
use n0_error::{Result, StdResultExt};
use n0_tracing_test::traced_test;
use rand::{RngExt, SeedableRng};
use support::{spawn_server, test_resolver};

#[tokio::test]
#[traced_test]
#[ignore = "manual mainline testnet coverage; run with `cargo test -p krikos-dns-server --test mainline -- --ignored`"]
async fn integration_mainline() -> Result {
    let dir = tempfile::tempdir()?;
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0);

    let testnet = Testnet::new_async(5).await.anyerr()?;
    let bootstrap = testnet.bootstrap.clone();
    let server = spawn_server(dir.path(), Some(bootstrap.clone())).await?;

    let origin = "krikosdns.example.";
    let secret_key = SecretKey::from_bytes(&rng.random());
    let endpoint_id = secret_key.public();
    let relay_url: RelayUrl = "https://relay.example.".parse()?;
    let endpoint_info = EndpointInfo::new(endpoint_id).with_relay_url(relay_url.clone());
    let signed_packet = endpoint_info.to_pkarr_signed_packet(&secret_key, 30)?;

    let mut dht_builder = DhtBuilder::default();
    dht_builder.bootstrap(&bootstrap);
    let dht = dht_builder.build().anyerr()?;
    let item = MutableItem::new_signed_unchecked(
        *secret_key.public().as_bytes(),
        signed_packet.signature().to_bytes(),
        signed_packet.encoded_packet(),
        i64::try_from(signed_packet.timestamp().as_micros())
            .expect("current pkarr timestamp fits in mainline sequence"),
        None,
    );
    dht.clone()
        .as_async()
        .put_mutable(item, None)
        .await
        .anyerr()?;

    let resolver = test_resolver(server.dns_addr());
    let resolved = EndpointDnsResolver::new(resolver)
        .lookup_by_id(&endpoint_id, origin)
        .await?;
    assert_eq!(resolved.endpoint_id, endpoint_id);
    assert_eq!(resolved.relay_urls().next(), Some(&relay_url));

    server.shutdown().await?;
    Ok(())
}
