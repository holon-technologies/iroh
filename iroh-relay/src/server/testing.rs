//! Exposes functions to quickly configure a server suitable for testing.
use std::{net::Ipv4Addr, sync::Arc};

use super::{AllowAll, CertConfig, QuicConfig, RelayConfig, ServerConfig, TlsConfig};

/// Creates a [`rustls::ServerConfig`] and certificates suitable for testing.
///
/// - Uses a self signed certificate valid for the `"localhost"` and `"127.0.0.1"` domains.
pub fn self_signed_tls_certs_and_config() -> (
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::ServerConfig,
) {
    let cert = rcgen::generate_simple_self_signed(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ])
    .expect("valid");
    let rustls_cert = cert.cert.der();
    let private_key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let private_key = rustls::pki_types::PrivateKeyDer::from(private_key);
    let certs = vec![rustls_cert.clone()];
    let server_config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocols supported by ring")
    .with_no_client_auth();

    let server_config = server_config
        .with_single_cert(certs.clone(), private_key)
        .expect("valid");
    (certs, server_config)
}

/// Creates a [`TlsConfig`] suitable for testing.
///
/// - Uses a self signed certificate valid for the `"localhost"` and `"127.0.0.1"` domains.
/// - Configures https to be served on an OS assigned port on ipv4.
pub fn tls_config() -> TlsConfig {
    let (_certs, server_config) = self_signed_tls_certs_and_config();
    TlsConfig {
        cert: CertConfig::Manual { server_config },
        https_bind_addr: (Ipv4Addr::LOCALHOST, 0).into(),
    }
}

/// Creates a [`RelayConfig`] suitable for testing.
///
/// - Binds http to an OS assigned port on ipv4.
/// - Uses [`tls_config`] to enable TLS.
/// - Uses default limits.
pub fn relay_config() -> RelayConfig {
    RelayConfig {
        http_bind_addr: (Ipv4Addr::LOCALHOST, 0).into(),
        tls: Some(tls_config()),
        limits: Default::default(),
        key_cache_capacity: Some(1024),
        access: Arc::new(AllowAll),
    }
}

/// Creates a [`QuicConfig`] suitable for testing.
///
/// - Binds to an OS assigned port on ipv4
/// - Uses [`self_signed_tls_certs_and_config`] to create tls certificates
pub fn quic_config() -> QuicConfig {
    let (_, server_config) = self_signed_tls_certs_and_config();
    QuicConfig {
        bind_addr: (Ipv4Addr::UNSPECIFIED, 0).into(),
        server_config: Some(server_config),
    }
}

/// Creates a [`ServerConfig`] suitable for testing.
///
/// - Relaying is enabled using [`relay_config`]
/// - QUIC addr discovery is disabled.
/// - Metrics are not enabled.
pub fn server_config() -> ServerConfig {
    ServerConfig {
        relay: Some(relay_config()),
        quic: Some(quic_config()),
        #[cfg(feature = "metrics")]
        metrics_addr: None,
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use iroh_base::{RelayUrl, SecretKey};
    use iroh_dns::dns::DnsResolver;
    use n0_error::Result;
    use n0_future::{SinkExt, StreamExt};

    use super::*;
    use crate::{
        KeyCache,
        client::ClientBuilder,
        http::ProtocolVersion,
        protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg, Status},
        server::{Metrics, http_server::RelayService},
    };

    fn relay_service() -> RelayService {
        RelayService::new(
            Default::default(),
            Default::default(),
            None,
            KeyCache::new(32),
            Arc::new(AllowAll),
            Arc::new(Metrics::default()),
        )
    }

    fn client_builder(url: &RelayUrl, key: SecretKey) -> ClientBuilder {
        ClientBuilder::new(url.clone(), key, DnsResolver::new())
    }

    #[tokio::test]
    async fn in_memory_session_runs_production_authentication_and_routing() -> Result {
        let relay = relay_service();
        let url = RelayUrl::from_str("https://relay-1.invalid")?;
        let a_key = SecretKey::from_bytes(&[1; 32]);
        let b_key = SecretKey::from_bytes(&[2; 32]);
        let a_id = a_key.public();
        let b_id = b_key.public();

        let mut a = relay
            .connect_in_memory(&client_builder(&url, a_key), ProtocolVersion::V2, 64 * 1024)
            .await?;
        let mut b = relay
            .connect_in_memory(&client_builder(&url, b_key), ProtocolVersion::V2, 64 * 1024)
            .await?;

        let payload = Datagrams::from(b"authenticated production relay frame");
        a.send(ClientToRelayMsg::Datagrams {
            dst_endpoint_id: b_id,
            datagrams: payload.clone(),
        })
        .await?;

        assert_eq!(
            b.next().await.transpose()?,
            Some(RelayToClientMsg::Datagrams {
                remote_endpoint_id: a_id,
                datagrams: payload,
            })
        );

        relay.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn in_memory_session_preserves_protocol_version_compatibility() -> Result {
        let relay = relay_service();
        let url = RelayUrl::from_str("https://relay-1.invalid")?;
        let key = SecretKey::from_bytes(&[3; 32]);
        let mut client = relay
            .connect_in_memory(&client_builder(&url, key), ProtocolVersion::V1, 8 * 1024)
            .await?;

        let ping = [9; 8];
        client.send(ClientToRelayMsg::Ping(ping)).await?;
        assert_eq!(
            client.next().await.transpose()?,
            Some(RelayToClientMsg::Pong(ping))
        );

        relay.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn in_memory_session_drops_unknown_destinations_without_poisoning_the_session() -> Result
    {
        let relay = relay_service();
        let url = RelayUrl::from_str("https://relay-1.invalid")?;
        let mut client = relay
            .connect_in_memory(
                &client_builder(&url, SecretKey::from_bytes(&[4; 32])),
                ProtocolVersion::V2,
                8 * 1024,
            )
            .await?;

        client
            .send(ClientToRelayMsg::Datagrams {
                dst_endpoint_id: SecretKey::from_bytes(&[5; 32]).public(),
                datagrams: Datagrams::from(b"must be isolated"),
            })
            .await?;
        let ping = [6; 8];
        client.send(ClientToRelayMsg::Ping(ping)).await?;
        assert_eq!(
            client.next().await.transpose()?,
            Some(RelayToClientMsg::Pong(ping))
        );

        relay.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn in_memory_duplicate_identity_promotes_the_newest_session() -> Result {
        let relay = relay_service();
        let url = RelayUrl::from_str("https://relay-1.invalid")?;
        let duplicate_key = SecretKey::from_bytes(&[7; 32]);
        let duplicate_id = duplicate_key.public();
        let sender_key = SecretKey::from_bytes(&[8; 32]);
        let sender_id = sender_key.public();
        let mut first = relay
            .connect_in_memory(
                &client_builder(&url, duplicate_key.clone()),
                ProtocolVersion::V2,
                16 * 1024,
            )
            .await?;
        let mut second = relay
            .connect_in_memory(
                &client_builder(&url, duplicate_key),
                ProtocolVersion::V2,
                16 * 1024,
            )
            .await?;
        let mut sender = relay
            .connect_in_memory(
                &client_builder(&url, sender_key),
                ProtocolVersion::V2,
                16 * 1024,
            )
            .await?;

        assert_eq!(
            first.next().await.transpose()?,
            Some(RelayToClientMsg::Status(Status::SameEndpointIdConnected))
        );
        let payload = Datagrams::from(b"newest session only");
        sender
            .send(ClientToRelayMsg::Datagrams {
                dst_endpoint_id: duplicate_id,
                datagrams: payload.clone(),
            })
            .await?;
        assert_eq!(
            second.next().await.transpose()?,
            Some(RelayToClientMsg::Datagrams {
                remote_endpoint_id: sender_id,
                datagrams: payload,
            })
        );

        relay.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn in_memory_shutdown_closes_sessions_and_registry_entries() -> Result {
        let relay = relay_service();
        let url = RelayUrl::from_str("https://relay-1.invalid")?;
        let mut client = relay
            .connect_in_memory(
                &client_builder(&url, SecretKey::from_bytes(&[9; 32])),
                ProtocolVersion::V2,
                8 * 1024,
            )
            .await?;
        assert_eq!(relay.clients().connection_count(), 1);

        relay.shutdown().await;
        assert_eq!(relay.clients().connection_count(), 0);
        assert!(client.next().await.is_none());
        Ok(())
    }
}
