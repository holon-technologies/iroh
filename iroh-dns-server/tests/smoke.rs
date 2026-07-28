mod support;

use iroh::{
    RelayUrl, SecretKey,
    address_lookup::PkarrRelayClient,
    endpoint_info::EndpointInfo,
    tls::{CaTlsConfig, default_provider},
};
use iroh_dns::dns::EndpointDnsResolver;
use iroh_resolver::DnsResolver;
use n0_error::Result;
use n0_tracing_test::traced_test;
use rand::{RngExt, SeedableRng};
use support::{http_url, spawn_server, test_resolver};

#[tokio::test]
#[traced_test]
async fn integration_smoke() -> Result {
    let dir = tempfile::tempdir()?;
    let server = spawn_server(dir.path(), None).await?;
    let pkarr_relay = {
        let mut url = http_url(&server);
        url.set_path("/pkarr");
        url
    };

    let origin = "irohdns.example.";
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0);
    let secret_key = SecretKey::from_bytes(&rng.random());
    let endpoint_id = secret_key.public();
    let tls_config = CaTlsConfig::default()
        .client_config(default_provider())
        .expect("default test TLS configuration is valid");
    let pkarr = PkarrRelayClient::new(pkarr_relay, tls_config, DnsResolver::default())?;
    let relay_url: RelayUrl = "https://relay.example.".parse()?;
    let endpoint_info = EndpointInfo::new(endpoint_id).with_relay_url(relay_url.clone());
    let signed_packet = endpoint_info.to_pkarr_signed_packet(&secret_key, 30)?;

    pkarr.publish(&signed_packet).await?;

    let resolver = test_resolver(server.dns_addr());
    let resolved = EndpointDnsResolver::new(resolver)
        .lookup_by_id(&endpoint_id, origin)
        .await?;
    assert_eq!(resolved.endpoint_id, endpoint_id);
    assert_eq!(resolved.relay_urls().next(), Some(&relay_url));

    server.shutdown().await?;
    Ok(())
}
