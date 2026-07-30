use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use n0_error::{AnyError, StdResultExt};
use n0_future::{
    task::{self, AbortOnDropHandle},
    time::{self, Duration},
};
use reloadable_state::Reloadable;
use rustls::{
    crypto::CryptoProvider,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use rustls_cert_file_reader::{ReadCerts, ReadKey};
use rustls_cert_reloadable_resolver::{CertifiedKeyLoader, key_provider::Dyn};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

/// The default certificate reload interval.
pub const DEFAULT_CERT_RELOAD_INTERVAL: Duration = Duration::from_secs(60 * 60 * 24);
const MAX_RELOAD_TLS_FILE_BYTES: usize = 1024 * 1024;
const MAX_RELOAD_TLS_FILE_READ_BYTES: u64 = 1024 * 1024 + 1;

#[derive(Debug)]
struct BoundedPemFileReader {
    path: PathBuf,
}

impl BoundedPemFileReader {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl ReadCerts for BoundedPemFileReader {
    type Error = io::Error;

    async fn read_certs(
        &self,
    ) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, Self::Error> {
        let bytes = read_reload_file(&self.path).await?;
        rustls_cert_file_reader::pem::parse_certs(&mut io::Cursor::new(bytes))
    }
}

impl ReadKey for BoundedPemFileReader {
    type Error = io::Error;

    async fn read_key(&self) -> Result<rustls::pki_types::PrivateKeyDer<'static>, Self::Error> {
        let bytes = read_reload_file(&self.path).await?;
        rustls_cert_file_reader::pem::parse_key(&mut io::Cursor::new(bytes))
    }
}

async fn read_reload_file(path: &Path) -> io::Result<Vec<u8>> {
    let file = tokio::fs::File::open(path).await?;
    let capacity = usize::try_from(
        file.metadata()
            .await?
            .len()
            .min(MAX_RELOAD_TLS_FILE_READ_BYTES),
    )
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "TLS file length is invalid"))?;
    let mut reader = file.take(MAX_RELOAD_TLS_FILE_READ_BYTES);
    let mut bytes = Vec::with_capacity(capacity);
    reader.read_to_end(&mut bytes).await?;
    if bytes.len() > MAX_RELOAD_TLS_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "TLS reload file {} exceeds {MAX_RELOAD_TLS_FILE_BYTES} bytes",
                path.display()
            ),
        ));
    }
    Ok(bytes)
}

/// Builds a [`ResolvesServerCert`] that reloads its certificate and key from disk on an interval.
///
/// Loads the PEM-encoded certificate chain from `cert_path` and the PEM-encoded private key
/// from `key_path` using `crypto_provider`'s key provider, then spawns a background task that
/// re-reads both files every `interval`. The returned resolver hands the most recently loaded
/// `CertifiedKey` to rustls for each TLS handshake, so certificate rotation takes effect without
/// restarting the server. See [`DEFAULT_CERT_RELOAD_INTERVAL`] for a sensible default.
///
/// The reload task is tied to the returned `Arc` and is aborted when the last reference is
/// dropped. Reload failures on the interval are silently ignored; the previously loaded
/// certificate remains in use.
///
/// # Errors
///
/// Returns an error if the initial certificate or key load fails (for example, the files do not
/// exist, cannot be read, or cannot be parsed as PEM).
pub async fn reloading_resolver(
    crypto_provider: &CryptoProvider,
    cert_path: PathBuf,
    key_path: PathBuf,
    interval: std::time::Duration,
) -> Result<Arc<dyn ResolvesServerCert>, AnyError> {
    let key_reader = BoundedPemFileReader::new(key_path);
    let certs_reader = BoundedPemFileReader::new(cert_path);
    let loader = CertifiedKeyLoader {
        key_provider: Dyn(crypto_provider.key_provider),
        key_reader,
        certs_reader,
    };
    let resolver = ReloadingResolver::init(loader, interval)
        .await
        .std_context("cert loading")?;
    Ok(Arc::new(resolver))
}

/// A Certificate resolver that reloads the certificate every interval
#[derive(Debug)]
struct ReloadingResolver<Loader: Send + 'static> {
    /// The inner reloadable value.
    reloadable: Arc<Reloadable<CertifiedKey, Loader>>,
    /// The handle to the task that reloads the certificate.
    _handle: AbortOnDropHandle<()>,
}

impl<Loader> ReloadingResolver<Loader>
where
    Loader: Send + reloadable_state::core::Loader<Value = CertifiedKey> + 'static,
{
    /// Perform the initial load and construct the [`ReloadingResolver`].
    async fn init(loader: Loader, interval: Duration) -> Result<Self, Loader::Error> {
        let (reloadable, _) = Reloadable::init_load(loader).await?;
        let reloadable = Arc::new(reloadable);

        let cancel_token = CancellationToken::new();

        // Spawn a task to reload the certificate every interval.
        let _reloadable = reloadable.clone();
        let _cancel_token = cancel_token.clone();
        let _handle = task::spawn(async move {
            let mut interval = time::interval(interval);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let _ = _reloadable.reload().await;
                        tracing::info!("Reloaded the certificate");
                    },
                    _ = _cancel_token.cancelled() => {
                        tracing::trace!("shutting down");
                        break;
                    }
                }
            }
        });
        let _handle = AbortOnDropHandle::new(_handle);

        Ok(Self {
            reloadable,
            _handle,
        })
    }
}

impl<Loader> ResolvesServerCert for ReloadingResolver<Loader>
where
    Loader: reloadable_state::core::Loader<Value = CertifiedKey>,
    Loader: Send,
    Loader: std::fmt::Debug,
{
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.reloadable.get())
    }
}

impl<Loader: Send> std::ops::Deref for ReloadingResolver<Loader> {
    type Target = Reloadable<CertifiedKey, Loader>;

    fn deref(&self) -> &Self::Target {
        &self.reloadable
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[tokio::test]
    async fn reload_file_read_rejects_the_first_byte_over_the_limit() {
        let mut file = tempfile::NamedTempFile::new().expect("temporary TLS reload file");
        file.write_all(&vec![b' '; MAX_RELOAD_TLS_FILE_BYTES + 1])
            .expect("write oversized TLS reload file");

        let error = read_reload_file(file.path())
            .await
            .expect_err("oversized reload input must be rejected before parsing");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds 1048576 bytes"));
    }
}
