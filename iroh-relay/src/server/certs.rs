use derive_more::Debug;

#[cfg(feature = "server-acme")]
use super::*;

/// TLS certificate configuration.
#[derive(Debug)]
#[non_exhaustive]
pub enum CertConfig {
    /// Use Let's Encrypt.
    #[cfg(feature = "server-acme")]
    LetsEncrypt {
        /// Configuration for the ACME client.
        acme_config: AcmeConfig,
        /// Builder for the [`rustls::ServerConfig`].
        ///
        /// The ACME resolver will be injected when starting the server.
        server_config_builder: rustls::ConfigBuilder<rustls::ServerConfig, WantsServerCert>,
    },
    /// Use a TLS key and certificate chain that can be reloaded.
    Manual {
        /// The [`rustls::ServerConfig`] to use.
        ///
        /// This needs to have the certificates or a certificate loader, it will be used by the server as-is.
        server_config: rustls::ServerConfig,
    },
}

/// Configuration for the ACME client.
#[cfg(feature = "server-acme")]
#[derive(Debug, Clone)]
pub struct AcmeConfig {
    pub(crate) directory_url: String,
    pub(crate) domains: Vec<String>,
    pub(crate) contact: Vec<String>,
    pub(crate) cache_path: Option<PathBuf>,
    pub(crate) tls_config: CaTlsConfig,
}

#[cfg(feature = "server-acme")]
impl AcmeConfig {
    /// Creates a new [`AcmeConfig`] with a ACME directory URL.
    pub fn new(directory_url: String) -> Self {
        Self {
            directory_url,
            domains: Vec::new(),
            contact: Vec::new(),
            cache_path: None,
            tls_config: CaTlsConfig::default(),
        }
    }

    /// Creates a new [`AcmeConfig`] with the Let's Encrypt directory URL.
    pub fn letsencrypt(production: bool) -> Self {
        let url = if production {
            LETS_ENCRYPT_PRODUCTION_DIRECTORY
        } else {
            LETS_ENCRYPT_STAGING_DIRECTORY
        };
        Self::new(url.to_string())
    }

    /// Provides the list of domains for which certificates should be obtained.
    pub fn domains(mut self, domains: Vec<String>) -> Self {
        self.domains = domains;
        self
    }

    /// Provides a list of contacts for the account.
    ///
    /// Note that email addresses must include a `mailto:` prefix.
    pub fn contact(mut self, contact: Vec<String>) -> Self {
        self.contact = contact;
        self
    }

    /// Sets the directory where to cache certificates.
    ///
    /// If not called certificates will not be cached.
    pub fn cache_path(mut self, path: PathBuf) -> Self {
        self.cache_path = Some(path);
        self
    }

    /// Sets the [`CaTlsConfig`] used to verify the ACME server's TLS certificate.
    ///
    /// Defaults to [`CaTlsConfig::embedded`]. Set a config with extra roots when targeting
    /// an ACME server whose certificate is not signed by a publicly trusted CA, such as a
    /// local test server.
    pub fn tls_config(mut self, tls_config: CaTlsConfig) -> Self {
        self.tls_config = tls_config;
        self
    }
}
