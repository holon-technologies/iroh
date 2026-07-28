#![allow(dead_code)]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    time::Duration,
};

use iroh_dns_server::{
    Server,
    config::{Config, MainlineConfig, MetricsConfig},
};
use iroh_resolver::DnsResolver;
use n0_error::Result;
use url::Url;

pub const DNS_TIMEOUT: Duration = Duration::from_secs(2);

pub async fn spawn_server(
    data_dir: &Path,
    mainline_bootstrap: Option<Vec<String>>,
) -> Result<Server> {
    let mut config = Config::default();
    config.dns.port = 0;
    config.dns.bind_addr = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let http = config.http.as_mut().expect("default HTTP listener");
    http.port = 0;
    http.bind_addr = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
    config.https = None;
    config.metrics = Some(MetricsConfig::disabled());
    config.data_dir = Some(data_dir.to_owned());
    if let Some(bootstrap) = mainline_bootstrap {
        let mut mainline = MainlineConfig::default();
        mainline.enabled = true;
        mainline.bootstrap = Some(bootstrap);
        config.mainline = Some(mainline);
    }
    Server::bind(config).await
}

pub fn http_url(server: &Server) -> Url {
    let address = server.http_addr().expect("HTTP listener is bound");
    format!("http://{address}")
        .parse()
        .expect("bound HTTP address forms a URL")
}

pub fn test_resolver(nameserver: SocketAddr) -> DnsResolver {
    DnsResolver::with_nameserver(nameserver)
}
