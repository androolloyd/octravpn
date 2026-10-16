//! A private owned archive. Pruning walks pinned directory descriptors and
//! never follows a replaced directory, symlink or unknown ownership marker.
use super::{
    bootstrap, ensure, manifest, now, package, Config, Context, Digest, Path, PathBuf, Result,
    Sha256,
};
use octra_node_protocol::state_sync::{cycle, lease};
#[cfg(unix)]
use rustix::fs::{self as unix, AtFlags, Mode, OFlags};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::{self, File},
    io::{Read, Write},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
const OWNER: &str = ".octra-owner.json";
const WRITER: &[u8] = b"octra-sync-archive-1\n";
static SERIAL: AtomicU64 = AtomicU64::new(0);
#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Owner {
    version: u8,
    archive: String,
    snapshot: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Removal {
    owner: Owner,
    name: String,
    device: u64,
    inode: u64,
}
pub(super) struct Archive {
    pub root: PathBuf,
    directory: File,
    pointer_parent: File,
    pointer_name: String,
    binding: String,
    _lock: File,
}
fn private(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            ensure!(meta.is_dir(), "snapshot archive path is not a directory");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                ensure!(
                    meta.permissions().mode() & 0o022 == 0,
                    "snapshot archive directory is writable by others"
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().context("snapshot archive parent missing")?;
            private(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new().mode(0o700).create(path)?;
            }
            #[cfg(not(unix))]
            fs::create_dir(path)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
#[cfg(unix)]
fn open_directory(path: &Path) -> Result<File> {
    Ok(unix::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?
    .into())
}
#[cfg(not(unix))]
fn open_directory(_: &Path) -> Result<File> {
    anyhow::bail!("safe snapshot publication requires Unix")
}
#[cfg(unix)]
fn read_at(parent: &File, name: &str, limit: usize) -> Result<Option<Vec<u8>>> {
    let opened = unix::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    );
    let file: File = match opened {
        Ok(file) => file.into(),
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() <= limit as u64,
        "invalid or oversized snapshot archive artifact"
    );
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit,
        "snapshot archive artifact grew past limit"
    );
    Ok(Some(bytes))
}
#[cfg(not(unix))]
fn read_at(_: &File, _: &str, _: usize) -> Result<Option<Vec<u8>>> {
    anyhow::bail!("safe snapshot publication requires Unix")
}
#[cfg(unix)]
fn write_at(parent: &File, name: &str, bytes: &[u8], replace: bool) -> Result<()> {
    let stage = format!(
        ".publish-{}-{}",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed)
    );
    let mut file: File = unix::openat(
        parent,
        stage.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?
    .into();
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        if replace {
            unix::renameat(parent, stage.as_str(), parent, name)?;
        } else {
            unix::renameat_with(
                parent,
                stage.as_str(),
                parent,
                name,
                unix::RenameFlags::NOREPLACE,
            )?;
        }
        parent.sync_all()?;
        Ok(())
    })();
    let _ = unix::unlinkat(parent, stage.as_str(), AtFlags::empty());
    result
}
#[cfg(not(unix))]
fn write_at(_: &File, _: &str, _: &[u8], _: bool) -> Result<()> {
    anyhow::bail!("safe snapshot publication requires Unix")
}
impl Archive {
    #[allow(clippy::verbose_bit_mask)] // The octal mask directly expresses private Unix permission bits.
    pub(super) fn open(config: &Config) -> Result<Self> {
        private(&config.root)?;
        let directory = open_directory(&config.root)?;
        #[cfg(unix)]
        let lock: File = unix::openat(
            &directory,
            ".archive.lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?
        .into();
        #[cfg(not(unix))]
        let lock = directory.try_clone()?;
        ensure!(
            lock.metadata()?.is_file(),
            "snapshot archive lock is not a regular file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            ensure!(
                lock.metadata()?.nlink() == 1 && lock.metadata()?.permissions().mode() & 0o077 == 0,
                "snapshot archive lock must be private and unlinked elsewhere"
            );
            unix::flock(&lock, unix::FlockOperation::NonBlockingLockExclusive)
                .context("snapshot archive already in use")?;
        }
        let binding = hex::encode(Sha256::digest(serde_json::to_vec(&config.network)?));
        let raw = serde_json::to_vec(&Owner {
            version: 1,
            archive: binding.clone(),
            snapshot: String::new(),
        })?;
        match read_at(&directory, OWNER, 4096)? {
            Some(existing) => ensure!(
                serde_json::from_slice::<Owner>(&existing)?
                    == serde_json::from_slice::<Owner>(&raw)?,
                "snapshot archive authority differs"
            ),
            None => write_at(&directory, OWNER, &raw, false)?,
        }
        let parent = config
            .certificate
            .parent()
            .context("snapshot certificate parent missing")?;
        private(parent)?;
        let pointer_parent = open_directory(parent)?;
        let pointer_name = config
            .certificate
            .file_name()
            .and_then(|x| x.to_str())
            .context("snapshot certificate name is not UTF-8")?
            .to_owned();
        let archive = Self {
            root: config.root.clone(),
            directory,
            pointer_parent,
            pointer_name,
            binding,
            _lock: lock,
        };
        archive.recover_removals()?;
        Ok(archive)
    }
    pub(super) fn current(&self) -> Result<Option<Vec<u8>>> {
        read_at(
            &self.pointer_parent,
            &self.pointer_name,
            manifest::MANIFEST_LIMIT,
        )
    }
    pub(super) fn path(&self, id: &str) -> Result<PathBuf> {
        ensure!(valid_id(id), "snapshot id is invalid");
        Ok(self.root.join(id))
    }
    fn owner(&self, id: &str) -> Owner {
        Owner {
            version: 1,
            archive: self.binding.clone(),
            snapshot: id.to_owned(),
        }
    }
    #[cfg(unix)]
    fn owned(&self, name: &str, id: &str) -> Result<File> {
        ensure!(
            valid_id(id) && (name == id || name == format!("{id}.next")),
            "snapshot archive name is invalid"
        );
        let file: File = unix::openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?
        .into();
        let raw = read_at(&file, OWNER, 4096)?.context("snapshot archive ownership is unknown")?;
        ensure!(
            serde_json::from_slice::<Owner>(&raw)? == self.owner(id),
            "snapshot archive ownership differs"
        );
        Ok(file)
    }
    #[cfg(not(unix))]
    fn owned(&self, _: &str, _: &str) -> Result<File> {
        anyhow::bail!("safe snapshot publication requires Unix")
    }
    pub(super) fn stage(&self, id: &str) -> Result<PathBuf> {
        self.path(id)?;
        let name = format!("{id}.next");
        match fs::symlink_metadata(self.root.join(&name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
            Ok(_) => self.remove(&name, id, true)?,
        }
        let temporary = tempfile::Builder::new()
            .prefix(".octra-stage-")
            .tempdir_in(&self.root)?;
        let file = open_directory(temporary.path())?;
        write_at(&file, OWNER, &serde_json::to_vec(&self.owner(id))?, false)?;
        write_at(&file, ".writer", WRITER, false)?;
        #[cfg(unix)]
        {
            unix::renameat_with(
                unix::CWD,
                temporary.path(),
                &self.directory,
                name.as_str(),
                unix::RenameFlags::NOREPLACE,
            )?;
            self.directory.sync_all()?;
        }
        Ok(self.root.join(name))
    }
    pub(super) fn complete(&self, id: &str, raw: &[u8]) -> Result<()> {
        let file = self.owned(&format!("{id}.next"), id)?;
        let ready = read_at(
            &file,
            "HEAD.json",
            octra_node_protocol::state_sync::head::MAX_BYTES,
        )?
        .context("prepared HEAD missing")?;
        write_at(&file, ".ready.json", &ready, false)?;
        write_at(&file, ".certificate.json", raw, false)
    }
    pub(super) fn publish(&self, config: &Config, id: &str, raw: &[u8]) -> Result<()> {
        let authority = bootstrap::Authority::new(config.network.clone())?;
        let certificate = authority.trust().verify(raw, now()?)?;
        ensure!(
            certificate.draft().manifest.snapshot_id == id.as_bytes(),
            "snapshot publication id differs"
        );
        // A previous pointer may be expired, but must still authenticate to the
        // same independently supplied authority before it can be replaced.
        if let Some(previous) = self.current()? {
            let previous = authority.trust().verify_persisted(&previous)?;
            ensure!(
                previous.draft().checkpoint.epoch <= certificate.draft().checkpoint.epoch,
                "snapshot publication would move backwards"
            );
        }
        let stage = format!("{id}.next");
        let file = self.owned(&stage, id)?;
        ensure!(
            read_at(&file, ".writer", 128)?.as_deref() == Some(WRITER),
            "snapshot stage ownership is unknown"
        );
        ensure!(
            read_at(&file, ".certificate.json", manifest::MANIFEST_LIMIT)?.as_deref() == Some(raw),
            "snapshot stage certificate differs"
        );
        #[cfg(unix)]
        {
            match unix::renameat_with(
                &self.directory,
                stage.as_str(),
                &self.directory,
                id,
                unix::RenameFlags::NOREPLACE,
            ) {
                Ok(()) => (),
                Err(error) if error == rustix::io::Errno::EXIST => {
                    let existing = self.owned(id, id)?;
                    ensure!(
                        read_at(&existing, ".certificate.json", manifest::MANIFEST_LIMIT)?
                            .as_deref()
                            == Some(raw),
                        "existing snapshot differs"
                    );
                    // The new stage was fully hashed/restored before signing.
                    // Exchange atomically repairs an owned same-certificate
                    // package without ever exposing a missing current path.
                    // The old payload remains an owned retryable stage until
                    // durable GC completes, including across a process crash.
                    unix::renameat_with(
                        &self.directory,
                        stage.as_str(),
                        &self.directory,
                        id,
                        unix::RenameFlags::EXCHANGE,
                    )?;
                    self.directory.sync_all()?;
                    self.remove(&stage, id, false)?;
                }
                Err(error) => return Err(error.into()),
            }
            self.directory.sync_all()?;
        }
        // Native placement: archived certificate first, live certificate last.
        // Failed preparation/signing never changes this current pointer.
        write_at(&self.pointer_parent, &self.pointer_name, raw, true)
    }
    pub(super) fn load(&self, config: &Config) -> Result<Option<i64>> {
        let Some(raw) = self.current()? else {
            return Ok(None);
        };
        let authority = bootstrap::Authority::new(config.network.clone())?;
        let certificate = authority.trust().verify_persisted(&raw)?;
        if !certificate.certificate().fresh(now()?) {
            return Ok(None);
        }
        let id = std::str::from_utf8(&certificate.draft().manifest.snapshot_id)?;
        let owned = self.owned(id, id)?;
        ensure!(
            read_at(&owned, ".certificate.json", manifest::MANIFEST_LIMIT)?.as_deref()
                == Some(raw.as_slice()),
            "archived native certificate differs from current publication"
        );
        let verified = package::verify(&authority, &self.path(id)?, config.limits)?;
        ensure!(
            verified.raw == raw,
            "current snapshot certificate differs from package"
        );
        Ok(Some(certificate.draft().checkpoint.epoch))
    }
    pub(super) fn retain(&self, config: &Config, retain: usize) -> Result<Vec<String>> {
        let Some(current) = self.current()? else {
            return Ok(Vec::new());
        };
        let authority = bootstrap::Authority::new(config.network.clone())?;
        let certificate = authority.trust().verify(&current, now()?)?;
        let current_id = &certificate.draft().manifest.snapshot_id;
        let mut snapshots = Vec::new();
        let mut leases = Vec::new();
        let mut stages = Vec::new();
        let mut errors = Vec::new();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
        for name in names(&self.directory)? {
            let Ok(name) = String::from_utf8(name) else {
                continue;
            };
            if let Some(id) = name.strip_suffix(".next").filter(|id| valid_id(id)) {
                stages.push((name.clone(), id.to_owned()));
                continue;
            }
            if !valid_id(&name) {
                continue;
            }
            let file = match self.owned(&name, &name) {
                Ok(value) => value,
                Err(error) => {
                    errors.push(format!("{name}: {error}"));
                    continue;
                }
            };
            let Some(raw) = read_at(&file, ".certificate.json", manifest::MANIFEST_LIMIT)? else {
                continue;
            };
            let verified = match authority.trust().verify_persisted(&raw) {
                Ok(value) => value,
                Err(error) => {
                    errors.push(format!("{name}: {error}"));
                    continue;
                }
            };
            if verified.draft().manifest.snapshot_id != name.as_bytes() {
                errors.push(format!("{name}: snapshot id differs"));
                continue;
            }
            snapshots.push((name.as_bytes().to_vec(), verified.draft().checkpoint.epoch));
            #[cfg(unix)]
            {
                if let (Some(published_at), Some(modified)) = (
                    modified_at(&file, ".certificate.json")?,
                    modified_at(&file, "download.lease")?,
                ) {
                    if lease::active(timestamp, published_at, modified) {
                        leases.push(lease::Lease {
                            snapshot_id: name.as_bytes().to_vec(),
                            last_seen: modified,
                        });
                    }
                }
            }
        }
        let leased = lease::retained(&leases)
            .into_iter()
            .collect::<BTreeSet<_>>();
        let remove = cycle::retention_plan(retain, current_id, &snapshots);
        ensure!(
            self.current()?.as_deref() == Some(&current),
            "current snapshot certificate changed before retention"
        );
        for id in remove.into_iter().filter(|id| !leased.contains(id)) {
            let id = String::from_utf8(id)?;
            if let Err(error) = self.remove(&id, &id, false) {
                errors.push(format!("{id}: {error}"));
            }
        }
        for (name, id) in stages {
            if let Err(error) = self.remove(&name, &id, true) {
                errors.push(format!("{name}: {error}"));
            }
        }
        Ok(errors)
    }
    fn remove(&self, name: &str, id: &str, stage: bool) -> Result<()> {
        let file = self.owned(name, id)?;
        if stage {
            ensure!(
                read_at(&file, ".writer", 128)?.as_deref() == Some(WRITER),
                "snapshot stage ownership is unknown"
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let tomb = format!(
                ".remove-{id}-{}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::Relaxed)
            );
            let intent = format!("{tomb}.json");
            let meta = file.metadata()?;
            let removal = Removal {
                owner: self.owner(id),
                name: tomb.clone(),
                device: meta.dev(),
                inode: meta.ino(),
            };
            // The fsynced intent binds exactly one inode before rename. If a
            // crash interrupts unlinking, ownership survives outside the tree.
            write_at(
                &self.directory,
                &intent,
                &serde_json::to_vec(&removal)?,
                false,
            )?;
            if let Err(error) = unix::renameat_with(
                &self.directory,
                name,
                &self.directory,
                tomb.as_str(),
                unix::RenameFlags::NOREPLACE,
            ) {
                let _ = unix::unlinkat(&self.directory, intent.as_str(), AtFlags::empty());
                return Err(error.into());
            }
            self.directory.sync_all()?;
            self.finish_removal(&intent, &removal)?;
        }
        Ok(())
    }
    #[allow(clippy::case_sensitive_file_extension_comparisons)] // Owned journal filenames use an exact lowercase suffix, not user file types.
    fn recover_removals(&self) -> Result<()> {
        for name in names(&self.directory)? {
            let Ok(name) = String::from_utf8(name) else {
                continue;
            };
            if !name.starts_with(".remove-") || !name.ends_with(".json") {
                continue;
            }
            let raw = read_at(&self.directory, &name, 4096)?
                .context("snapshot removal intent missing")?;
            let removal: Removal = serde_json::from_slice(&raw)?;
            ensure!(
                removal.owner == self.owner(&removal.owner.snapshot)
                    && valid_id(&removal.owner.snapshot)
                    && removal
                        .name
                        .starts_with(&format!(".remove-{}-", removal.owner.snapshot))
                    && removal.name.bytes().all(|b| b.is_ascii_hexdigit()
                        || b == b'-'
                        || b == b'.'
                        || b == b'r'
                        || b == b'm'
                        || b == b'o'
                        || b == b'v')
                    && name == format!("{}.json", removal.name),
                "snapshot removal intent ownership differs"
            );
            self.finish_removal(&name, &removal)?;
        }
        Ok(())
    }
    #[cfg(unix)]
    fn finish_removal(&self, intent: &str, removal: &Removal) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let file = unix::openat(
            &self.directory,
            removal.name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        );
        let file: File = match file {
            Ok(file) => file.into(),
            Err(error) if error == rustix::io::Errno::NOENT => {
                // Intent-before-rename or already-completed deletion. The original
                // named snapshot remains untouched if rename never occurred.
                unix::unlinkat(&self.directory, intent, AtFlags::empty())?;
                self.directory.sync_all()?;
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        let meta = file.metadata()?;
        ensure!(
            meta.dev() == removal.device && meta.ino() == removal.inode,
            "snapshot removal inode differs"
        );
        let mut budget = manifest::FILE_LIMIT * 4 + 64;
        remove_contents(&file, 0, &mut budget)?;
        unix::unlinkat(&self.directory, removal.name.as_str(), AtFlags::REMOVEDIR)?;
        unix::unlinkat(&self.directory, intent, AtFlags::empty())?;
        self.directory.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    fn finish_removal(&self, _: &str, _: &Removal) -> Result<()> {
        anyhow::bail!("safe snapshot publication requires Unix")
    }
}
pub(super) fn valid_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[cfg(unix)]
fn names(directory: &File) -> Result<Vec<Vec<u8>>> {
    let mut names = Vec::new();
    for entry in unix::Dir::read_from(directory)? {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        ensure!(
            names.len() < manifest::FILE_LIMIT * 4 + 64,
            "snapshot archive entry limit exceeded"
        );
        names.push(name.to_vec());
    }
    Ok(names)
}
#[cfg(not(unix))]
fn names(_: &File) -> Result<Vec<Vec<u8>>> {
    anyhow::bail!("safe snapshot publication requires Unix")
}
#[cfg(unix)]
fn remove_contents(directory: &File, depth: usize, budget: &mut usize) -> Result<()> {
    ensure!(depth < 16, "snapshot directory nesting limit exceeded");
    for name in names(directory)? {
        ensure!(*budget > 0, "snapshot removal entry limit exceeded");
        *budget -= 1;
        let name = CString::new(name)?;
        let stat = unix::statat(directory, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW)?;
        match unix::FileType::from_raw_mode(stat.st_mode) {
            unix::FileType::Directory => {
                let child: File = unix::openat(
                    directory,
                    name.as_c_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?
                .into();
                remove_contents(&child, depth + 1, budget)?;
                unix::unlinkat(directory, name.as_c_str(), AtFlags::REMOVEDIR)?;
            }
            unix::FileType::RegularFile | unix::FileType::Symlink => {
                unix::unlinkat(directory, name.as_c_str(), AtFlags::empty())?;
            }
            _ => anyhow::bail!("snapshot removal encountered special file"),
        }
    }
    directory.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn modified_at(parent: &File, name: &str) -> Result<Option<f64>> {
    let descriptor = unix::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    );
    let file: File = match descriptor {
        Ok(value) => value.into(),
        Err(error) if error == rustix::io::Errno::NOENT || error == rustix::io::Errno::LOOP => {
            return Ok(None)
        }
        Err(error) => return Err(error.into()),
    };
    if !file.metadata()?.is_file() {
        return Ok(None);
    }
    Ok(file
        .metadata()?
        .modified()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|value| value.as_secs_f64()))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::snapshot_export::Limits;
    #[test]
    fn interrupted_owned_tombstone_recovers_by_exact_inode_but_foreign_inode_is_preserved() {
        use octra_exex::{ChainIdentity, StateRoot};
        use std::os::unix::fs::MetadataExt;
        let directory = tempfile::tempdir().unwrap();
        let config = Config {
            network: bootstrap::Network {
                identity: ChainIdentity::genesis("gc-fixture", StateRoot([0; 32])),
                config_hash: "ab".repeat(32),
                validators: Vec::new(),
                exporters: Vec::new(),
                minimum_epoch: 0,
                migration_root: None,
            },
            source: directory.path().to_owned(),
            root: directory.path().join("archive"),
            certificate: directory.path().join("current/certificate.json"),
            force: false,
            limits: Limits::default(),
        };
        let archive = Archive::open(&config).unwrap();
        let id = "a".repeat(64);
        let stage = archive.stage(&id).unwrap();
        fs::write(stage.join("payload"), b"partly removed").unwrap();
        let file = archive.owned(&format!("{id}.next"), &id).unwrap();
        let meta = file.metadata().unwrap();
        let tomb = format!(".remove-{id}-1-0");
        let intent = format!("{tomb}.json");
        let removal = Removal {
            owner: archive.owner(&id),
            name: tomb.clone(),
            device: meta.dev(),
            inode: meta.ino(),
        };
        write_at(
            &archive.directory,
            &intent,
            &serde_json::to_vec(&removal).unwrap(),
            false,
        )
        .unwrap();
        unix::renameat(
            &archive.directory,
            format!("{id}.next").as_str(),
            &archive.directory,
            tomb.as_str(),
        )
        .unwrap();
        fs::remove_file(config.root.join(&tomb).join(OWNER)).unwrap();
        drop(archive);
        let restarted = Archive::open(&config).unwrap();
        assert!(!config.root.join(&tomb).exists());
        assert!(!config.root.join(&intent).exists());
        let id = "b".repeat(64);
        let foreign_tomb = format!(".remove-{id}-1-0");
        fs::create_dir(config.root.join(&foreign_tomb)).unwrap();
        fs::write(config.root.join(&foreign_tomb).join("keep"), b"foreign").unwrap();
        let forged = Removal {
            owner: restarted.owner(&id),
            name: foreign_tomb.clone(),
            device: meta.dev(),
            inode: meta.ino().checked_add(1_000_000).unwrap(),
        };
        write_at(
            &restarted.directory,
            &format!("{foreign_tomb}.json"),
            &serde_json::to_vec(&forged).unwrap(),
            false,
        )
        .unwrap();
        drop(restarted);
        assert!(Archive::open(&config).is_err());
        assert!(config.root.join(&foreign_tomb).join("keep").exists());
    }
}
