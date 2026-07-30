use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use krikos_base::SecretKey;

use crate::{ComponentFuture, IdentityError};

static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Explicit behavior when resolving an application's endpoint identity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum IdentityPolicy {
    /// Require an existing identity and never create one.
    LoadOnly,
    /// Require the store to be empty and create a new identity.
    CreateOnly,
    /// Load an existing identity or atomically create one.
    #[default]
    LoadOrCreate,
}

/// Capability for loading and atomically persisting endpoint identity material.
pub trait IdentityStore: fmt::Debug + Send + Sync + 'static {
    /// Loads the identity, returning `None` when the store is empty.
    fn load(&self) -> ComponentFuture<Result<Option<SecretKey>, IdentityError>>;

    /// Atomically publishes a new identity without replacing an existing value.
    fn create(&self, identity: SecretKey) -> ComponentFuture<Result<(), IdentityError>>;

    /// Atomically replaces the stored identity.
    fn replace(&self, identity: SecretKey) -> ComponentFuture<Result<(), IdentityError>>;
}

/// Process-local identity storage for ephemeral applications and tests.
#[derive(Debug, Default)]
pub struct MemoryIdentityStore {
    identity: Mutex<Option<[u8; 32]>>,
}

impl MemoryIdentityStore {
    /// Creates an empty memory identity store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            identity: Mutex::new(None),
        }
    }
}

impl IdentityStore for MemoryIdentityStore {
    fn load(&self) -> ComponentFuture<Result<Option<SecretKey>, IdentityError>> {
        let result = self
            .identity
            .lock()
            .map_err(|_| IdentityError::unavailable("load"))
            .map(|identity| identity.as_ref().map(SecretKey::from_bytes));
        Box::pin(async move { result })
    }

    fn create(&self, identity: SecretKey) -> ComponentFuture<Result<(), IdentityError>> {
        let result = self
            .identity
            .lock()
            .map_err(|_| IdentityError::unavailable("create"))
            .and_then(|mut stored| {
                if stored.is_some() {
                    return Err(IdentityError::AlreadyExists);
                }
                *stored = Some(identity.to_bytes());
                Ok(())
            });
        Box::pin(async move { result })
    }

    fn replace(&self, identity: SecretKey) -> ComponentFuture<Result<(), IdentityError>> {
        let result = self
            .identity
            .lock()
            .map_err(|_| IdentityError::unavailable("replace"))
            .map(|mut stored| *stored = Some(identity.to_bytes()));
        Box::pin(async move { result })
    }
}

/// Protected file-backed identity storage.
#[derive(Clone)]
pub struct FileIdentityStore {
    path: Arc<PathBuf>,
}

impl FileIdentityStore {
    /// Uses `path` as the protected 32-byte endpoint identity file.
    #[must_use]
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: Arc::new(path.as_ref().to_path_buf()),
        }
    }
}

impl fmt::Debug for FileIdentityStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FileIdentityStore(..)")
    }
}

impl IdentityStore for FileIdentityStore {
    fn load(&self) -> ComponentFuture<Result<Option<SecretKey>, IdentityError>> {
        let path = self.path.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || load_file(&path))
                .await
                .map_err(|_| IdentityError::unavailable("load"))?
        })
    }

    fn create(&self, identity: SecretKey) -> ComponentFuture<Result<(), IdentityError>> {
        let path = self.path.clone();
        let bytes = identity.to_bytes();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || create_file(&path, &bytes))
                .await
                .map_err(|_| IdentityError::unavailable("create"))?
        })
    }

    fn replace(&self, identity: SecretKey) -> ComponentFuture<Result<(), IdentityError>> {
        let path = self.path.clone();
        let bytes = identity.to_bytes();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || replace_file(&path, &bytes))
                .await
                .map_err(|_| IdentityError::unavailable("replace"))?
        })
    }
}

pub(crate) async fn resolve_identity(
    store: &dyn IdentityStore,
    policy: IdentityPolicy,
) -> Result<SecretKey, IdentityError> {
    match policy {
        IdentityPolicy::LoadOnly => store.load().await?.ok_or(IdentityError::Missing),
        IdentityPolicy::CreateOnly => {
            let identity = SecretKey::generate();
            store.create(identity.clone()).await?;
            Ok(identity)
        }
        IdentityPolicy::LoadOrCreate => {
            if let Some(identity) = store.load().await? {
                return Ok(identity);
            }
            let identity = SecretKey::generate();
            match store.create(identity.clone()).await {
                Ok(()) => Ok(identity),
                Err(IdentityError::AlreadyExists) => {
                    store.load().await?.ok_or(IdentityError::Missing)
                }
                Err(error) => Err(error),
            }
        }
    }
}

fn load_file(path: &Path) -> Result<Option<SecretKey>, IdentityError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(IdentityError::unavailable("load")),
    };
    let metadata = file
        .metadata()
        .map_err(|_| IdentityError::unavailable("load"))?;
    if metadata.len() != 32 {
        return Err(IdentityError::Corrupt);
    }
    ensure_private_permissions(&metadata)?;
    let mut bytes = [0_u8; 32];
    file.read_exact(&mut bytes)
        .map_err(|_| IdentityError::Corrupt)?;
    Ok(Some(SecretKey::from_bytes(&bytes)))
}

fn create_file(path: &Path, bytes: &[u8; 32]) -> Result<(), IdentityError> {
    let temp = write_temporary(path, bytes, "create")?;
    let result = fs::hard_link(&temp, path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            IdentityError::AlreadyExists
        } else {
            IdentityError::unavailable("create")
        }
    });
    let _ = fs::remove_file(&temp);
    result?;
    sync_parent(path);
    Ok(())
}

fn replace_file(path: &Path, bytes: &[u8; 32]) -> Result<(), IdentityError> {
    let temp = write_temporary(path, bytes, "replace")?;
    let result = fs::rename(&temp, path).map_err(|_| IdentityError::unavailable("replace"));
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result?;
    sync_parent(path);
    Ok(())
}

fn write_temporary(
    path: &Path,
    bytes: &[u8; 32],
    operation: &'static str,
) -> Result<PathBuf, IdentityError> {
    let parent = path.parent().ok_or(IdentityError::unavailable(operation))?;
    fs::create_dir_all(parent).map_err(|_| IdentityError::unavailable(operation))?;
    let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(
        ".iroh-identity-{}-{sequence}.tmp",
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    set_private_create_mode(&mut options);
    let mut file = options
        .open(&temp)
        .map_err(|_| IdentityError::unavailable(operation))?;
    if file.write_all(bytes).is_err() || file.sync_all().is_err() {
        let _ = fs::remove_file(&temp);
        return Err(IdentityError::unavailable(operation));
    }
    Ok(temp)
}

#[cfg(unix)]
fn set_private_create_mode(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_private_create_mode(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn ensure_private_permissions(metadata: &fs::Metadata) -> Result<(), IdentityError> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(IdentityError::InsecurePermissions);
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_permissions(_metadata: &fs::Metadata) -> Result<(), IdentityError> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) {
    if let Some(parent) = path.parent()
        && let Ok(directory) = File::open(parent)
    {
        let _ = directory.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) {}
