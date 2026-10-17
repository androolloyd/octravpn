//! Private single-writer snapshots. Missing/replaced state is never recreated
//! during a live journal lease; failed writes stop the owning Journal handle.
use anyhow::{bail, ensure, Context, Result};
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use super::OpenMode;

const STATE: &str = "state.json";
const LOCK: &str = "writer.lock";
const MAGIC: &[u8] = b"Octranet client payment journal v1\n";
const MAX_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    modified: i64,
    #[cfg(unix)]
    modified_ns: i64,
    length: u64,
}
fn stamp(metadata: &Metadata) -> Stamp {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    Stamp {
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        #[cfg(unix)]
        modified: metadata.mtime(),
        #[cfg(unix)]
        modified_ns: metadata.mtime_nsec(),
        length: metadata.len(),
    }
}

#[cfg(unix)]
#[allow(clippy::verbose_bit_mask)] // Octal masks describe private Unix permissions directly.
fn private(metadata: &Metadata, owner: Option<&Metadata>, directory: bool) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    ensure!(
        metadata.is_dir() == directory && metadata.is_file() != directory,
        "payment journal path has wrong file type"
    );
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "payment journal paths must be owner-only"
    );
    if let Some(owner) = owner {
        ensure!(
            metadata.uid() == owner.uid(),
            "payment journal file owner differs from its directory"
        );
    }
    if !directory {
        ensure!(
            metadata.nlink() == 1,
            "payment journal file must not have another hard link"
        );
    }
    Ok(())
}
#[cfg(not(unix))]
fn private(_: &Metadata, _: Option<&Metadata>, _: bool) -> Result<()> {
    bail!("client payment journal requires private host ACL verification on this platform")
}

fn options(write: bool, create: bool, directory: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(write).create_new(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK;
        if directory {
            flags |= rustix::fs::OFlags::DIRECTORY;
        }
        options.mode(0o600).custom_flags(flags.bits() as i32);
    }
    #[cfg(not(unix))]
    let _ = directory;
    options
}

pub(super) struct Store {
    path: PathBuf,
    directory: File,
    directory_identity: Stamp,
    lock: File,
    lock_identity: Stamp,
    state_identity: Option<Stamp>,
}
impl Store {
    pub(super) fn open(path: &Path, mode: OpenMode) -> Result<Self> {
        if mode == OpenMode::Create {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(path).context("fresh payment journal requires a new directory; refusing existing or incomplete state")?;
        }
        let directory = options(false, false, true)
            .open(path)
            .context("open private payment journal directory")?;
        let metadata = directory.metadata()?;
        private(&metadata, None, true)?;
        let mut lock = options(true, mode == OpenMode::Create, false)
            .open(path.join(LOCK))
            .context("payment journal lease missing or unavailable; refusing reset")?;
        private(&lock.metadata()?, Some(&metadata), false)?;
        lock.try_lock()
            .map_err(|error| anyhow::anyhow!("payment journal already has a writer: {error}"))?;
        if mode == OpenMode::Create {
            lock.write_all(MAGIC)?;
            lock.sync_all()?;
            directory.sync_all()?;
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            options(false, false, true).open(parent)?.sync_all()?;
        } else {
            let mut magic = Vec::new();
            (&lock)
                .take(MAGIC.len() as u64 + 1)
                .read_to_end(&mut magic)?;
            ensure!(magic == MAGIC, "payment journal lease marker differs");
        }
        let lock_identity = stamp(&lock.metadata()?);
        Ok(Self {
            path: path.to_owned(),
            directory_identity: stamp(&metadata),
            directory,
            lock,
            lock_identity,
            state_identity: None,
        })
    }

    fn paths(&self) -> Result<Metadata> {
        let directory = fs::symlink_metadata(&self.path)?;
        private(&directory, None, true)?;
        let current = stamp(&directory);
        // Directory length/mtime change on each atomic state publication.
        #[cfg(unix)]
        ensure!(
            current.device == self.directory_identity.device
                && current.inode == self.directory_identity.inode,
            "payment journal directory was replaced"
        );
        #[cfg(not(unix))]
        let _ = current;
        let lock = fs::symlink_metadata(self.path.join(LOCK))?;
        private(&lock, Some(&directory), false)?;
        ensure!(
            stamp(&lock) == self.lock_identity,
            "payment journal lease was replaced"
        );
        ensure!(
            stamp(&self.lock.metadata()?) == self.lock_identity,
            "payment journal lease changed"
        );
        Ok(directory)
    }

    pub(super) fn check(&self) -> Result<()> {
        let directory = self.paths()?;
        let expected = self
            .state_identity
            .context("payment journal has no committed state")?;
        let current = fs::symlink_metadata(self.path.join(STATE))
            .context("payment journal state missing; refusing a live-plan reset")?;
        private(&current, Some(&directory), false)?;
        ensure!(
            stamp(&current) == expected,
            "payment journal state was changed or replaced"
        );
        Ok(())
    }

    pub(super) fn read(&mut self) -> Result<Vec<u8>> {
        let directory = self.paths()?;
        let mut file = options(false, false, false)
            .open(self.path.join(STATE))
            .context("payment journal state missing; refusing a live-plan reset")?;
        let metadata = file.metadata()?;
        private(&metadata, Some(&directory), false)?;
        ensure!(
            metadata.len() <= MAX_BYTES as u64,
            "payment journal state exceeds bound"
        );
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == metadata.len() && bytes.len() <= MAX_BYTES,
            "payment journal state changed while reading"
        );
        ensure!(
            stamp(&file.metadata()?) == stamp(&metadata),
            "payment journal state changed while reading"
        );
        self.state_identity = Some(stamp(&metadata));
        Ok(bytes)
    }

    pub(super) fn commit(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() <= MAX_BYTES,
            "payment journal state exceeds bound"
        );
        let directory = self.paths()?;
        let destination = self.path.join(STATE);
        match (self.state_identity, fs::symlink_metadata(&destination)) {
            (None, Err(error)) if error.kind() == std::io::ErrorKind::NotFound => (),
            (Some(expected), Ok(current)) => {
                private(&current, Some(&directory), false)?;
                ensure!(
                    stamp(&current) == expected,
                    "payment journal state was changed or replaced"
                );
            }
            (None, Ok(_)) => bail!("payment journal state already exists; refusing reset"),
            (_, Err(error)) => {
                return Err(error)
                    .context("payment journal state missing or unavailable; refusing reset")
            }
        }
        let mut temporary = tempfile::NamedTempFile::new_in(&self.path)?;
        private(&temporary.as_file().metadata()?, Some(&directory), false)?;
        temporary.write_all(bytes)?;
        temporary.as_file().sync_all()?;
        self.paths()?;
        let installed = if self.state_identity.is_none() {
            temporary
                .persist_noclobber(&destination)
                .map_err(|error| error.error)?
        } else {
            temporary
                .persist(&destination)
                .map_err(|error| error.error)?
        };
        self.directory.sync_all()?;
        let metadata = installed.metadata()?;
        private(&metadata, Some(&directory), false)?;
        self.state_identity = Some(stamp(&metadata));
        self.paths()?;
        Ok(())
    }
}
