use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(super) const NAMES: [&str; 3] = ["settle_state.bin", "arm_net.bin", "client_receipts.bin"];
const MAX_SOURCE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pin {
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
}

pub(super) struct Snapshot {
    pub directory: PathBuf,
    pub files: Vec<Vec<u8>>,
    pub pins: Vec<Pin>,
}

impl Snapshot {
    pub(super) fn read(directory: &Path) -> Result<Self> {
        let mut files = Vec::new();
        let mut pins = Vec::new();
        let mut remaining = MAX_SOURCE_BYTES;
        for name in NAMES {
            let path = directory.join(name);
            let bytes = read_optional(&path, remaining)?;
            remaining = remaining
                .checked_sub(bytes.len())
                .ok_or_else(|| anyhow!("legacy snapshot byte limit exceeded"))?;
            pins.push(Pin {
                name: name.to_owned(),
                bytes: bytes.len() as u64,
                sha256: hex::encode(Sha256::digest(&bytes)),
            });
            files.push(bytes);
        }
        Ok(Self {
            directory: directory.to_owned(),
            files,
            pins,
        })
    }

    pub(super) fn has_data(&self) -> bool {
        self.files.iter().any(|file| !file.is_empty())
    }
}

pub(super) fn read_optional(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("{} must be a regular file", path.display());
    }
    if metadata.len() > limit as u64 {
        bail!("{} exceeds the snapshot byte limit", path.display());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    let file = options
        .open(path)
        .with_context(|| format!("read {}", path.display()))?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() != metadata.len() {
        bail!("{} changed during snapshot opening", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
            bail!(
                "{} changed identity during snapshot opening",
                path.display()
            );
        }
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit || bytes.len() as u64 != metadata.len() {
        bail!(
            "{} changed during snapshot reading or exceeds its byte limit",
            path.display()
        );
    }
    Ok(bytes)
}

/// Publish one complete copied directory with an atomic rename. No source
/// file is opened for writing, migrated, truncated, renamed or removed.
pub(super) fn install(source: &Snapshot, destination: &Path, manifest: &[u8]) -> Result<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow!("migration destination has no parent"))?;
    fs::create_dir_all(parent)?;
    let lock_path = parent.join(".migration.lock");
    let _lock = Lock::acquire(&lock_path)?;
    if destination.try_exists()? {
        bail!("migration destination already exists; refusing to merge or replace it");
    }
    let mut nonce = [0; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let staging_path = parent.join(format!(".migration-{}", hex::encode(nonce)));
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&staging_path)?;
    let mut staging = Staging(Some(staging_path.clone()));
    for (name, bytes) in NAMES.into_iter().zip(&source.files) {
        write_new(&staging_path.join(name), bytes)?;
    }
    write_new(&staging_path.join("migration.json"), manifest)?;
    sync_directory(&staging_path)?;
    if Snapshot::read(&source.directory)?.pins != source.pins {
        bail!("legacy source changed after inspection; stop its writer and inspect again");
    }
    if destination.try_exists()? {
        bail!("migration destination appeared during preparation");
    }
    publish_directory(&staging_path, destination).context("publish complete migrated store")?;
    staging.0 = None;
    sync_directory(parent)?;
    Ok(())
}

fn publish_directory(source: &Path, destination: &Path) -> Result<()> {
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    {
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            source,
            rustix::fs::CWD,
            destination,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
    {
        let _ = (source, destination);
        bail!("atomic settlement migration publication is unsupported on this platform")
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

struct Lock(PathBuf);
impl Lock {
    fn acquire(path: &Path) -> Result<Self> {
        write_new(path, b"OctraVPN settlement migration\n").context(
            "migration lock unavailable; a writer or incomplete migration needs inspection",
        )?;
        Ok(Self(path.to_owned()))
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
struct Staging(Option<PathBuf>);
impl Drop for Staging {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_dir_all(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(root: &Path) -> Snapshot {
        fs::create_dir_all(root).unwrap();
        for (index, name) in NAMES.into_iter().enumerate() {
            fs::write(root.join(name), vec![index as u8 + 1; index + 3]).unwrap();
        }
        Snapshot::read(root).unwrap()
    }
    #[test]
    fn migration_preserves_originals_and_publishes_complete_private_copy_once() {
        let root = tempfile::tempdir().unwrap();
        let snapshot = source(&root.path().join("legacy"));
        let destination = root.path().join("scoped/wallet");
        install(&snapshot, &destination, b"authenticated-manifest-fixture").unwrap();
        assert_eq!(
            Snapshot::read(&snapshot.directory).unwrap().pins,
            snapshot.pins
        );
        assert_eq!(Snapshot::read(&destination).unwrap().pins, snapshot.pins);
        assert_eq!(
            fs::read(destination.join("migration.json")).unwrap(),
            b"authenticated-manifest-fixture"
        );
        assert!(install(&snapshot, &destination, b"replacement").is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
                0o700
            );
            for name in NAMES {
                assert_eq!(
                    fs::metadata(destination.join(name))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
        }
    }
    #[test]
    fn changed_source_never_publishes_a_stale_snapshot() {
        let root = tempfile::tempdir().unwrap();
        let snapshot = source(&root.path().join("legacy"));
        fs::write(
            snapshot.directory.join(NAMES[0]),
            b"concurrent-source-change",
        )
        .unwrap();
        let destination = root.path().join("scoped/wallet");
        assert!(install(&snapshot, &destination, b"manifest").is_err());
        assert!(!destination.exists());
        assert_eq!(
            fs::read(snapshot.directory.join(NAMES[0])).unwrap(),
            b"concurrent-source-change"
        );
        assert_eq!(
            fs::read_dir(destination.parent().unwrap()).unwrap().count(),
            0,
            "staging directory and lock must be cleaned up"
        );
    }
    #[test]
    fn legacy_input_is_bounded_and_regular() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("record");
        assert!(read_optional(&path, 3).unwrap().is_empty());
        fs::write(&path, b"four").unwrap();
        assert!(read_optional(&path, 3).is_err());
        assert_eq!(read_optional(&path, 4).unwrap(), b"four");
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(read_optional(&path, 100).is_err());
        #[cfg(unix)]
        {
            fs::remove_dir(&path).unwrap();
            std::os::unix::fs::symlink(root.path().join("missing"), &path).unwrap();
            assert!(read_optional(&path, 100).is_err());
        }
    }
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    #[test]
    fn atomic_publish_refuses_even_an_empty_existing_destination() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("staging");
        let destination = root.path().join("destination");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("retained"), b"candidate").unwrap();
        fs::create_dir(&destination).unwrap();
        assert!(publish_directory(&source, &destination).is_err());
        assert_eq!(fs::read(source.join("retained")).unwrap(), b"candidate");
        assert_eq!(fs::read_dir(&destination).unwrap().count(), 0);
    }
}
