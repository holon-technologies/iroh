#[cfg(unix)]
use std::fs::File;
use std::{
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use serde::{Deserialize, Serialize};

use crate::DataRootError;

const SCHEMA_VERSION: u32 = 1;
const FRAMEWORK_ID: &str = "iroh-app";
const MANIFEST_NAME: &str = "manifest.json";
const LOCK_NAME: &str = ".iroh-app.lock";
const IDENTITY_NAME: &str = "identity.key";
const BLOBS_DIR: &str = "blobs";
const DOCS_DIR: &str = "docs";
const MAX_MANIFEST_SIZE: usize = 64 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    schema_version: u32,
    framework: String,
}

/// Validated versioned application data root.
#[derive(Clone)]
pub struct DataRoot {
    root: Arc<PathBuf>,
    manifest: Manifest,
}

impl fmt::Debug for DataRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataRoot")
            .field("schema_version", &self.manifest.schema_version)
            .finish_non_exhaustive()
    }
}

impl DataRoot {
    /// Validates or initializes a data root without exposing a network endpoint.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DataRootError> {
        let root = path.as_ref();
        if root.exists() && !root.is_dir() {
            return Err(DataRootError::NotDirectory);
        }
        fs::create_dir_all(root).map_err(|_| DataRootError::Unavailable {
            operation: "create-root",
        })?;
        let manifest_path = root.join(MANIFEST_NAME);
        let manifest = if manifest_path.exists() {
            read_manifest(&manifest_path)?
        } else {
            let manifest = Manifest {
                schema_version: SCHEMA_VERSION,
                framework: FRAMEWORK_ID.to_owned(),
            };
            write_manifest(&manifest_path, &manifest)?;
            manifest
        };
        validate_manifest(&manifest)?;
        fs::create_dir_all(root.join(BLOBS_DIR)).map_err(|_| DataRootError::Unavailable {
            operation: "create-blobs-directory",
        })?;
        fs::create_dir_all(root.join(DOCS_DIR)).map_err(|_| DataRootError::Unavailable {
            operation: "create-docs-directory",
        })?;
        Ok(Self {
            root: Arc::new(root.to_path_buf()),
            manifest,
        })
    }

    /// Data-root schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.manifest.schema_version
    }

    /// Root directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.root
    }

    /// Protected endpoint identity path.
    #[must_use]
    pub fn identity_path(&self) -> PathBuf {
        self.root.join(IDENTITY_NAME)
    }

    /// Blob store directory.
    #[must_use]
    pub fn blobs_path(&self) -> PathBuf {
        self.root.join(BLOBS_DIR)
    }

    /// Documents store directory.
    #[must_use]
    pub fn docs_path(&self) -> PathBuf {
        self.root.join(DOCS_DIR)
    }

    pub(crate) fn acquire(&self) -> Result<DataRootLease, DataRootError> {
        let lock_path = self.root.join(LOCK_NAME);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&lock_path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    DataRootError::Locked
                } else {
                    DataRootError::Unavailable {
                        operation: "acquire-lock",
                    }
                }
            })?;
        writeln!(file, "{}", std::process::id()).map_err(|_| DataRootError::Unavailable {
            operation: "write-lock",
        })?;
        file.sync_all().map_err(|_| DataRootError::Unavailable {
            operation: "sync-lock",
        })?;
        Ok(DataRootLease { lock_path })
    }
}

pub(crate) struct DataRootLease {
    lock_path: PathBuf,
}

impl fmt::Debug for DataRootLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DataRootLease(..)")
    }
}

impl Drop for DataRootLease {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

fn read_manifest(path: &Path) -> Result<Manifest, DataRootError> {
    let metadata = fs::metadata(path).map_err(|_| DataRootError::Unavailable {
        operation: "read-manifest-metadata",
    })?;
    let size = usize::try_from(metadata.len()).map_err(|_| DataRootError::ManifestTooLarge {
        limit: MAX_MANIFEST_SIZE,
    })?;
    if size > MAX_MANIFEST_SIZE {
        return Err(DataRootError::ManifestTooLarge {
            limit: MAX_MANIFEST_SIZE,
        });
    }
    let bytes = fs::read(path).map_err(|_| DataRootError::Unavailable {
        operation: "read-manifest",
    })?;
    validate_manifest_bytes(&bytes)
}

pub(crate) fn validate_manifest_bytes(bytes: &[u8]) -> Result<Manifest, DataRootError> {
    if bytes.len() > MAX_MANIFEST_SIZE {
        return Err(DataRootError::ManifestTooLarge {
            limit: MAX_MANIFEST_SIZE,
        });
    }
    let manifest = serde_json::from_slice(bytes).map_err(|_| DataRootError::InvalidManifest)?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn validate_manifest(manifest: &Manifest) -> Result<(), DataRootError> {
    if manifest.schema_version != SCHEMA_VERSION {
        return Err(DataRootError::UnsupportedSchema {
            found: manifest.schema_version,
            expected: SCHEMA_VERSION,
        });
    }
    if manifest.framework != FRAMEWORK_ID {
        return Err(DataRootError::InvalidManifest);
    }
    Ok(())
}

fn write_manifest(path: &Path, manifest: &Manifest) -> Result<(), DataRootError> {
    let bytes = serde_json::to_vec_pretty(manifest).map_err(|_| DataRootError::InvalidManifest)?;
    let parent = path.parent().ok_or(DataRootError::Unavailable {
        operation: "create-manifest",
    })?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(".manifest-{}-{sequence}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)
        .map_err(|_| DataRootError::Unavailable {
            operation: "create-manifest",
        })?;
    let result = (|| {
        file.write_all(&bytes)
            .map_err(|_| DataRootError::Unavailable {
                operation: "write-manifest",
            })?;
        file.sync_all().map_err(|_| DataRootError::Unavailable {
            operation: "sync-manifest",
        })?;
        fs::rename(&temp, path).map_err(|_| DataRootError::Unavailable {
            operation: "publish-manifest",
        })?;
        sync_directory(parent);
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

#[cfg(unix)]
fn sync_directory(path: &Path) {
    if let Ok(directory) = File::open(path) {
        let _ = directory.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) {}
