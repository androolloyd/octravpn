//! A private, exclusively owned download workspace. Cached certificates and
//! file prefixes are hints only; each invocation rechecks independent trust.
use super::{
    download::{Candidate, Source},
    read_limited,
};
use anyhow::{ensure, Context, Result};
use octra_node_protocol::state_sync::manifest::{self, Trust};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

pub(super) struct Workspace {
    root: PathBuf,
    _lock: fs::File,
    last_manifest: Mutex<Option<Vec<u8>>>,
}
#[derive(Clone)]
pub(super) struct Cache {
    root: PathBuf,
    _workspace: Arc<Workspace>,
}
impl Cache {
    pub(super) fn path(&self) -> &Path {
        &self.root
    }
}
impl Workspace {
    #[cfg(test)]
    pub(super) fn test_cache(self: &Arc<Self>) -> Result<Cache> {
        let root = self.root.join("0".repeat(64));
        directory(&root)?;
        Ok(Cache {
            root,
            _workspace: self.clone(),
        })
    }
    #[allow(clippy::verbose_bit_mask)] // The octal mask directly expresses private Unix permission bits.
    pub(super) fn open(destination: &Path, identity: &octra_exex::ChainIdentity) -> Result<Self> {
        let binding = serde_json::to_vec(&(destination, identity))?;
        let root = destination
            .parent()
            .context("snapshot destination parent missing")?
            .join(format!(
                ".octra-sync-{}",
                hex::encode(Sha256::digest(binding))
            ));
        directory(&root)?;
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(
                rustix::fs::OFlags::NOFOLLOW.bits() as i32
                    | rustix::fs::OFlags::NONBLOCK.bits() as i32,
            );
        }
        let lock = options.open(root.join("lock"))?;
        let meta = lock.metadata()?;
        ensure!(
            meta.is_file(),
            "snapshot workspace lock must be a regular file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            ensure!(
                meta.permissions().mode() & 0o077 == 0 && meta.nlink() == 1,
                "snapshot workspace lock must be private and have one link"
            );
            rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
                .context("snapshot download workspace is already in use")?;
        }
        #[cfg(not(unix))]
        anyhow::bail!("snapshot resume locking requires Unix");
        fs::File::open(&root)?.sync_all()?;
        Ok(Self {
            root,
            _lock: lock,
            last_manifest: Mutex::new(None),
        })
    }
    pub(super) fn path(&self) -> &Path {
        &self.root
    }
    pub(super) fn candidate(
        &self,
        trust: &Trust<'_>,
        sources: &[Source],
        now: i64,
    ) -> Result<Option<Candidate>> {
        let path = self.root.join("resume.certificate.json");
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            other => {
                other?;
            }
        }
        let raw = read_limited(&path, manifest::MANIFEST_LIMIT)?;
        // Revoked, expired or differently configured authority cannot be reused.
        let Ok(certificate) = trust.verify(&raw, now) else {
            return Ok(None);
        };
        *self
            .last_manifest
            .lock()
            .map_err(|_| anyhow::anyhow!("snapshot workspace state is poisoned"))? =
            Some(certificate.draft().manifest_hash.clone());
        Ok(Some(Candidate {
            raw,
            certificate,
            sources: sources.to_vec(),
        }))
    }
    pub(super) fn remember(self: &Arc<Self>, candidate: &Candidate) -> Result<Cache> {
        let hash = std::str::from_utf8(&candidate.certificate.draft().manifest_hash)?;
        ensure!(
            super::lower_hash(hash.as_bytes()),
            "invalid snapshot cache identity"
        );
        let root = self.root.join(hash);
        directory(&root)?;
        let mut previous = self
            .last_manifest
            .lock()
            .map_err(|_| anyhow::anyhow!("snapshot workspace state is poisoned"))?;
        // Retain the active and immediately preceding download, bounding stale
        // data across source rotations. Directory names never grant authority.
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name
                .to_str()
                .filter(|name| super::lower_hash(name.as_bytes()))
            else {
                continue;
            };
            if name == hash || previous.as_deref() == Some(name.as_bytes()) {
                continue;
            }
            ensure!(
                entry.file_type()?.is_dir(),
                "snapshot cache entry must be a directory"
            );
            fs::remove_dir_all(entry.path())?;
        }
        let mut staged = tempfile::NamedTempFile::new_in(&self.root)?;
        staged.write_all(&candidate.raw)?;
        staged.as_file().sync_all()?;
        staged.persist(self.root.join("resume.certificate.json"))?;
        fs::File::open(&self.root)?.sync_all()?;
        *previous = Some(hash.as_bytes().to_vec());
        Ok(Cache {
            root,
            _workspace: self.clone(),
        })
    }
}

#[allow(clippy::verbose_bit_mask)] // The octal mask directly expresses private Unix permission bits.
pub(super) fn directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => {
            fs::File::open(path.parent().context("cache directory parent missing")?)?.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error.into()),
    }
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir(),
        "snapshot workspace must be a directory, not a link"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            meta.permissions().mode() & 0o077 == 0,
            "snapshot workspace must be private"
        );
    }
    Ok(())
}

pub(super) fn parents(root: &Path, path: &Path) -> Result<()> {
    let relative = path.strip_prefix(root)?;
    let mut current = root.to_path_buf();
    for part in relative.components() {
        ensure!(
            matches!(part, std::path::Component::Normal(_)),
            "unsafe cache directory component"
        );
        current.push(part);
        directory(&current)?;
    }
    Ok(())
}
