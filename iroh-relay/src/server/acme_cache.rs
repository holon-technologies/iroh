use std::{
    io,
    path::{Path, PathBuf},
};

use async_trait::async_trait;
use data_encoding::BASE64URL_NOPAD;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio_rustls_acme::{AccountCache, CertCache};

/// Maximum size of one cached ACME account or certificate.
const MAX_ACME_CACHE_FILE_BYTES: usize = 1024 * 1024;
const MAX_ACME_CACHE_FILE_READ_BYTES: u64 = 1024 * 1024 + 1;

/// Filesystem-backed ACME cache with an explicit per-file input and output limit.
#[derive(Clone, Debug)]
pub struct BoundedAcmeCache {
    root: PathBuf,
}

impl BoundedAcmeCache {
    /// Creates a bounded cache rooted at `directory`.
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            root: directory.into(),
        }
    }

    fn cert_path(&self, domains: &[String], directory_url: &str) -> PathBuf {
        self.root
            .join(cache_file_name("cached_cert_", domains, directory_url))
    }

    fn account_path(&self, contact: &[String], directory_url: &str) -> PathBuf {
        self.root
            .join(cache_file_name("cached_account_", contact, directory_url))
    }

    async fn read_if_exists(&self, path: &Path) -> io::Result<Option<Vec<u8>>> {
        let file = match tokio::fs::File::open(path).await {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let capacity = usize::try_from(
            file.metadata()
                .await?
                .len()
                .min(MAX_ACME_CACHE_FILE_READ_BYTES),
        )
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ACME file length is invalid"))?;
        let mut reader = file.take(MAX_ACME_CACHE_FILE_READ_BYTES);
        let mut bytes = Vec::with_capacity(capacity);
        reader.read_to_end(&mut bytes).await?;
        if bytes.len() > MAX_ACME_CACHE_FILE_BYTES {
            return Err(oversized_error(path, bytes.len()));
        }
        Ok(Some(bytes))
    }

    async fn write(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > MAX_ACME_CACHE_FILE_BYTES {
            return Err(oversized_error(path, bytes.len()));
        }
        tokio::fs::create_dir_all(&self.root).await?;
        tokio::fs::write(path, bytes).await
    }
}

#[async_trait]
impl CertCache for BoundedAcmeCache {
    type EC = io::Error;

    async fn load_cert(
        &self,
        domains: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EC> {
        self.read_if_exists(&self.cert_path(domains, directory_url))
            .await
    }

    async fn store_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        cert: &[u8],
    ) -> Result<(), Self::EC> {
        self.write(&self.cert_path(domains, directory_url), cert)
            .await
    }
}

#[async_trait]
impl AccountCache for BoundedAcmeCache {
    type EA = io::Error;

    async fn load_account(
        &self,
        contact: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EA> {
        self.read_if_exists(&self.account_path(contact, directory_url))
            .await
    }

    async fn store_account(
        &self,
        contact: &[String],
        directory_url: &str,
        account: &[u8],
    ) -> Result<(), Self::EA> {
        self.write(&self.account_path(contact, directory_url), account)
            .await
    }
}

fn cache_file_name(prefix: &str, identifiers: &[String], directory_url: &str) -> String {
    let mut digest = Sha256::new();
    for identifier in identifiers {
        digest.update(identifier.as_bytes());
        digest.update([0]);
    }
    digest.update(directory_url.as_bytes());
    format!(
        "{prefix}{}",
        BASE64URL_NOPAD.encode(digest.finalize().as_ref())
    )
}

fn oversized_error(path: &Path, actual: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "ACME cache file {} is {actual} bytes and exceeds {MAX_ACME_CACHE_FILE_BYTES} bytes",
            path.display()
        ),
    )
}

#[cfg(test)]
mod tests {
    use tokio_rustls_acme::caches::DirCache;

    use super::*;

    #[tokio::test]
    async fn cache_uses_upstream_file_names_and_accepts_the_exact_limit() {
        let directory = tempfile::tempdir().expect("temporary ACME cache");
        let cache = BoundedAcmeCache::new(directory.path().to_path_buf());
        let upstream = DirCache::new(directory.path().to_path_buf());
        let domains = ["example.com".to_owned()];
        let contact = ["mailto:test@example.com".to_owned()];
        let directory_url = "https://acme.invalid";
        let exact_limit = vec![7_u8; MAX_ACME_CACHE_FILE_BYTES];

        upstream
            .store_cert(&domains, directory_url, &exact_limit)
            .await
            .expect("store through upstream cache");
        assert_eq!(
            cache
                .load_cert(&domains, directory_url)
                .await
                .expect("load through bounded cache"),
            Some(exact_limit.clone())
        );

        cache
            .store_account(&contact, directory_url, &exact_limit)
            .await
            .expect("store through bounded cache");
        assert_eq!(
            upstream
                .load_account(&contact, directory_url)
                .await
                .expect("load through upstream cache"),
            Some(exact_limit)
        );
    }

    #[tokio::test]
    async fn cache_rejects_the_first_byte_over_the_limit_on_store_and_load() {
        let directory = tempfile::tempdir().expect("temporary ACME cache");
        let cache = BoundedAcmeCache::new(directory.path().to_path_buf());
        let oversized = vec![0_u8; MAX_ACME_CACHE_FILE_BYTES + 1];

        let store_error = cache
            .store_cert(
                &["example.com".to_owned()],
                "https://acme.invalid",
                &oversized,
            )
            .await
            .expect_err("oversized certificate cache write must be rejected");
        assert_eq!(store_error.kind(), std::io::ErrorKind::InvalidData);

        let account_path = cache.account_path(
            &["mailto:test@example.com".to_owned()],
            "https://acme.invalid",
        );
        std::fs::write(&account_path, oversized).expect("oversized cache fixture");
        let load_error = cache
            .load_account(
                &["mailto:test@example.com".to_owned()],
                "https://acme.invalid",
            )
            .await
            .expect_err("oversized account cache read must be rejected");
        assert_eq!(load_error.kind(), std::io::ErrorKind::InvalidData);
    }
}
