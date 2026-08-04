use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

use atomic_write_file::AtomicWriteFile;
use uuid::Uuid;

use crate::{app_state::keyring_service, secret_store::SecretStore};

use super::{RecoveryBlobStore, RecoveryKeyStore};

const KEY_PREFIX: &str = "core-call-recovery-v1";
const FILE_PREFIX: &str = "call-";
const FILE_SUFFIX: &str = ".recovery";

#[derive(Clone, Copy)]
pub(super) struct PlatformRecoveryKeyStore;

impl RecoveryKeyStore for PlatformRecoveryKeyStore {
    fn load(&self, call_id: Uuid) -> Result<Option<String>, String> {
        SecretStore::shared(keyring_service()).load(&key_name(call_id))
    }

    fn store(&self, call_id: Uuid, secret: &str) -> Result<(), String> {
        let store = SecretStore::shared(keyring_service());
        let name = key_name(call_id);
        store.store(&name, secret)?;
        match store.load(&name)? {
            Some(value) if value == secret => Ok(()),
            _ => Err("call recovery keyring read-back verification failed".into()),
        }
    }

    fn delete(&self, call_id: Uuid) -> Result<(), String> {
        SecretStore::shared(keyring_service()).delete(&key_name(call_id))
    }
}

#[derive(Clone)]
pub(super) struct PlatformRecoveryBlobStore {
    root: PathBuf,
}

impl PlatformRecoveryBlobStore {
    pub(super) fn new(app_data_dir: &Path) -> Result<Self, String> {
        if !app_data_dir.is_absolute() {
            return Err("call recovery requires an absolute app-data directory".into());
        }
        let root = app_data_dir.join("core-call-recovery");
        ensure_restricted_directory(&root)?;
        Ok(Self { root })
    }

    fn path(&self, call_id: Uuid) -> Result<PathBuf, String> {
        if call_id.get_version_num() != 4 {
            return Err("call recovery identifier must be UUIDv4".into());
        }
        Ok(self.root.join(format!(
            "{FILE_PREFIX}{}{FILE_SUFFIX}",
            call_id.hyphenated()
        )))
    }
}

impl RecoveryBlobStore for PlatformRecoveryBlobStore {
    fn load(&self, call_id: Uuid) -> Result<Option<Vec<u8>>, String> {
        let path = self.path(call_id)?;
        reject_symlink(&path)?;
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("read call recovery file: {error}")),
        }
    }

    fn write(&self, call_id: Uuid, bytes: &[u8]) -> Result<(), String> {
        ensure_restricted_directory(&self.root)?;
        let path = self.path(call_id)?;
        reject_symlink(&path)?;
        let mut file = AtomicWriteFile::open(&path)
            .map_err(|error| format!("open call recovery atomic file: {error}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|error| format!("restrict call recovery file: {error}"))?;
        }
        file.write_all(bytes)
            .map_err(|error| format!("write call recovery file: {error}"))?;
        file.commit()
            .map_err(|error| format!("commit call recovery file: {error}"))?;
        let verified =
            fs::read(&path).map_err(|error| format!("verify call recovery file: {error}"))?;
        if verified != bytes {
            let _ = fs::remove_file(&path);
            return Err("call recovery file read-back verification failed".into());
        }
        Ok(())
    }

    fn delete(&self, call_id: Uuid) -> Result<(), String> {
        let path = self.path(call_id)?;
        reject_symlink(&path)?;
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("remove call recovery ciphertext: {error}")),
        }
    }

    fn list_call_ids(&self) -> Result<Vec<Uuid>, String> {
        ensure_restricted_directory(&self.root)?;
        let mut ids = Vec::new();
        for entry in fs::read_dir(&self.root)
            .map_err(|error| format!("list call recovery directory: {error}"))?
        {
            let entry = entry.map_err(|error| format!("read call recovery entry: {error}"))?;
            if entry
                .file_type()
                .map_err(|error| format!("read call recovery entry type: {error}"))?
                .is_symlink()
            {
                return Err("call recovery directory contains a symbolic link".into());
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Some(raw) = name
                .strip_prefix(FILE_PREFIX)
                .and_then(|value| value.strip_suffix(FILE_SUFFIX))
            else {
                continue;
            };
            let Ok(id) = Uuid::parse_str(raw) else {
                continue;
            };
            if id.get_version_num() == 4 && id.hyphenated().to_string() == raw {
                ids.push(id);
            }
        }
        Ok(ids)
    }
}

fn key_name(call_id: Uuid) -> String {
    format!("{KEY_PREFIX}-{}", call_id.hyphenated())
}

fn reject_symlink(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err("call recovery path must not be a symbolic link".into())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("inspect call recovery path: {error}")),
    }
}

fn ensure_restricted_directory(path: &Path) -> Result<(), String> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("call recovery root must be a real directory".into());
        }
    }
    fs::create_dir_all(path).map_err(|error| format!("create call recovery directory: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("restrict call recovery directory: {error}"))?;
    }
    Ok(())
}
