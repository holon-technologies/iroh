mod support;

use std::net::{Ipv4Addr, Ipv6Addr};

use iroh::{
    SecretKey,
    address_lookup::PkarrRelayClient,
    tls::{CaTlsConfig, default_provider},
};
use iroh_dns::pkarr::SignedPacket;
use iroh_resolver::DnsResolver;
use n0_error::{Result, StdResultExt};
use n0_tracing_test::traced_test;
use simple_dns::{CLASS, Name as DnsName, Packet, ResourceRecord, rdata};
use support::{DNS_TIMEOUT, http_url, spawn_server, test_resolver};

#[tokio::test]
#[traced_test]
async fn pkarr_publish_dns_resolve() -> Result {
    let dir = tempfile::tempdir()?;
    let server = spawn_server(dir.path(), None).await?;
    let pkarr_relay_url = {
        let mut url = http_url(&server);
        url.set_path("/pkarr");
        url
    };

    let secret_key = SecretKey::generate();
    let origin = secret_key.public().to_z32();

    let mut packet = Packet::new_reply(0);
    packet.answers.push(ResourceRecord::new(
        DnsName::new_unchecked(&origin).into_owned(),
        CLASS::IN,
        30,
        rdata::RData::TXT("hi0".try_into().expect("valid TXT record")),
    ));
    packet.answers.push(ResourceRecord::new(
        DnsName::new_unchecked(&format!("_hello.{origin}")).into_owned(),
        CLASS::IN,
        30,
        rdata::RData::TXT("hi1".try_into().expect("valid TXT record")),
    ));
    packet.answers.push(ResourceRecord::new(
        DnsName::new_unchecked(&format!("_hello.world.{origin}")).into_owned(),
        CLASS::IN,
        30,
        rdata::RData::TXT("hi2".try_into().expect("valid TXT record")),
    ));
    packet.answers.push(ResourceRecord::new(
        DnsName::new_unchecked(&format!("multiple.{origin}")).into_owned(),
        CLASS::IN,
        30,
        rdata::RData::TXT("hi3".try_into().expect("valid TXT record")),
    ));
    packet.answers.push(ResourceRecord::new(
        DnsName::new_unchecked(&format!("multiple.{origin}")).into_owned(),
        CLASS::IN,
        30,
        rdata::RData::TXT("hi4".try_into().expect("valid TXT record")),
    ));
    packet.answers.push(ResourceRecord::new(
        DnsName::new_unchecked(&origin).into_owned(),
        CLASS::IN,
        30,
        rdata::RData::A(Ipv4Addr::LOCALHOST.into()),
    ));
    packet.answers.push(ResourceRecord::new(
        DnsName::new_unchecked(&format!("foo.bar.baz.{origin}")).into_owned(),
        CLASS::IN,
        30,
        rdata::RData::AAAA(Ipv6Addr::LOCALHOST.into()),
    ));

    let encoded = packet.build_bytes_vec_compressed().anyerr()?;
    let timestamp = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time follows Unix epoch")
            .as_micros(),
    )
    .expect("test system time fits in pkarr timestamp");
    let signable = {
        let mut bytes = format!("3:seqi{}e1:v{}:", timestamp, encoded.len()).into_bytes();
        bytes.extend(&encoded);
        bytes
    };
    let signature = secret_key.sign(&signable);
    let mut raw = Vec::with_capacity(104 + encoded.len());
    raw.extend_from_slice(secret_key.public().as_bytes());
    raw.extend_from_slice(&signature.to_bytes());
    raw.extend_from_slice(&timestamp.to_be_bytes());
    raw.extend_from_slice(&encoded);
    let signed_packet = SignedPacket::from_bytes(&raw).anyerr()?;

    let tls_config = CaTlsConfig::default()
        .client_config(default_provider())
        .expect("default test TLS configuration is valid");
    let pkarr_client = PkarrRelayClient::new(pkarr_relay_url, tls_config, DnsResolver::default())?;
    pkarr_client.publish(&signed_packet).await?;

    use hickory_server::proto::rr::Name;
    let resolver = test_resolver(server.dns_addr());

    let name = Name::from_utf8(format!("{origin}.")).anyerr()?;
    let records = resolver
        .lookup_txt(name, DNS_TIMEOUT)
        .await?
        .map(|text| text.to_string())
        .collect::<Vec<_>>();
    assert_eq!(records, ["hi0"]);

    let name = Name::from_utf8(format!("_hello.{origin}.")).anyerr()?;
    let records = resolver
        .lookup_txt(name, DNS_TIMEOUT)
        .await?
        .map(|text| text.to_string())
        .collect::<Vec<_>>();
    assert_eq!(records, ["hi1"]);

    let name = Name::from_utf8(format!("_hello.world.{origin}.")).anyerr()?;
    let records = resolver
        .lookup_txt(name, DNS_TIMEOUT)
        .await?
        .map(|text| text.to_string())
        .collect::<Vec<_>>();
    assert_eq!(records, ["hi2"]);

    let name = Name::from_utf8(format!("multiple.{origin}.")).anyerr()?;
    let records = resolver
        .lookup_txt(name, DNS_TIMEOUT)
        .await?
        .map(|text| text.to_string())
        .collect::<Vec<_>>();
    assert_eq!(records, ["hi3", "hi4"]);

    let name = Name::from_utf8(format!("{origin}.")).anyerr()?;
    let records = resolver
        .lookup_ipv4(name, DNS_TIMEOUT)
        .await?
        .collect::<Vec<_>>();
    assert_eq!(records, [Ipv4Addr::LOCALHOST]);

    let name = Name::from_utf8(format!("foo.bar.baz.{origin}.")).anyerr()?;
    let records = resolver
        .lookup_ipv6(name, DNS_TIMEOUT)
        .await?
        .collect::<Vec<_>>();
    assert_eq!(records, [Ipv6Addr::LOCALHOST]);

    server.shutdown().await?;
    Ok(())
}
