use super::{Binding, Credit};
use anyhow::Result;
#[cfg(unix)]
use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use sha2::{Digest, Sha256};
use std::path::Path;
#[cfg(unix)]
use std::{
    fs::File,
    io::{Read, Write},
};

#[cfg(unix)]
const MAX_BYTES: u64 = 131_072;
#[cfg(unix)]
const VERSION: u8 = 1;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub binding: Binding,
    pub tariff_hash: String,
    pub budget_ou: u64,
    pub committed: Vec<u64>,
    pub redeemed: Vec<u64>,
    pub uncertain: Vec<u64>,
    pub pending: Vec<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect: Option<octravpn_core::payments::SignedConnect>,
    #[serde(default, skip_serializing_if = "Credit::is_unlimited")]
    pub credit: Credit,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorizations: Vec<Option<octravpn_core::payments::SignedUsage>>,
}
#[cfg(unix)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u8,
    record: Record,
    sha256: String,
}

#[cfg(unix)]
pub(super) struct Disk {
    directory: File,
    _lease: File,
    #[cfg(test)]
    fail_next: std::sync::atomic::AtomicBool,
}
#[cfg(not(unix))]
pub(super) struct Disk;
impl Disk {
    pub(super) fn open(path: &Path) -> Result<(Self, Option<Record>)> {
        Self::open_mode(path, true)
    }
    pub(super) fn resume(path: &Path) -> Result<(Self, Option<Record>)> {
        Self::open_mode(path, false)
    }
    #[cfg(not(unix))]
    fn open_mode(_: &Path, _: bool) -> Result<(Self, Option<Record>)> {
        anyhow::bail!("durable payment metering requires Unix writer locking")
    }
    #[cfg(unix)]
    #[expect(
        clippy::verbose_bit_mask,
        reason = "Explicit POSIX private-file permission masks."
    )]
    fn open_mode(path: &Path, create: bool) -> Result<(Self, Option<Record>)> {
        use rustix::fs::{flock, open, openat, unlinkat, AtFlags, FlockOperation, Mode, OFlags};
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "meter directory must be a real directory"
            ),
            Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::DirBuilder::new().mode(0o700).create(path)?;
            }
            Err(error) => return Err(error.into()),
        }
        let directory: File = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?
        .into();
        ensure!(
            directory.metadata()?.permissions().mode() & 0o077 == 0,
            "meter directory must be private"
        );
        let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let (lease, created): (File, bool) = if create {
            match openat(
                &directory,
                "meter.lock",
                flags | OFlags::CREATE | OFlags::EXCL,
                Mode::from_bits_truncate(0o600),
            ) {
                Ok(file) => (file.into(), true),
                Err(rustix::io::Errno::EXIST) => (
                    openat(&directory, "meter.lock", flags, Mode::empty())?.into(),
                    false,
                ),
                Err(error) => return Err(error.into()),
            }
        } else {
            (
                openat(&directory, "meter.lock", flags, Mode::empty())?.into(),
                false,
            )
        };
        let metadata = lease.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.permissions().mode() & 0o077 == 0
                && metadata.nlink() == 1
                && metadata.uid() == directory.metadata()?.uid(),
            "meter lease must be a private regular file"
        );
        flock(&lease, FlockOperation::NonBlockingLockExclusive)
            .context("payment meter already in use")?;
        let saved = match openat(
            &directory,
            "meter.json",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(file) => {
                if created {
                    // Do not turn a refused missing-lease recovery into a valid
                    // new lease on the next attempt while an old writer lives.
                    unlinkat(&directory, "meter.lock", AtFlags::empty())?;
                    anyhow::bail!("existing meter journal lost its writer lease file");
                }
                let mut file: File = file.into();
                let metadata = file.metadata()?;
                ensure!(
                    metadata.is_file()
                        && metadata.permissions().mode() & 0o077 == 0
                        && metadata.nlink() == 1
                        && metadata.uid() == directory.metadata()?.uid()
                        && metadata.len() <= MAX_BYTES,
                    "meter journal must be a bounded private regular file"
                );
                let mut raw = Vec::new();
                Read::by_ref(&mut file)
                    .take(MAX_BYTES + 1)
                    .read_to_end(&mut raw)?;
                ensure!(
                    u64::try_from(raw.len())? <= MAX_BYTES,
                    "meter journal exceeds byte bound"
                );
                let envelope: Envelope =
                    serde_json::from_slice(&raw).context("invalid meter journal")?;
                ensure!(
                    envelope.version == VERSION,
                    "unsupported meter journal version"
                );
                ensure!(
                    hex::encode(Sha256::digest(serde_json::to_vec(&envelope.record)?))
                        == envelope.sha256,
                    "meter journal checksum differs"
                );
                Some(envelope.record)
            }
            Err(rustix::io::Errno::NOENT) => {
                ensure!(
                    created,
                    "existing meter journal is missing; refusing counter reset"
                );
                None
            }
            Err(error) => return Err(error.into()),
        };
        Ok((
            Self {
                directory,
                _lease: lease,
                #[cfg(test)]
                fail_next: std::sync::atomic::AtomicBool::new(false),
            },
            saved,
        ))
    }
    #[cfg(not(unix))]
    pub(super) fn persist(&self, _: &Record) -> Result<()> {
        anyhow::bail!("durable payment metering requires Unix writer locking")
    }
    #[cfg(unix)]
    pub(super) fn persist(&self, record: &Record) -> Result<()> {
        #[cfg(test)]
        ensure!(
            !self
                .fail_next
                .swap(false, std::sync::atomic::Ordering::AcqRel),
            "injected journal write failure"
        );
        let sha256 = hex::encode(Sha256::digest(serde_json::to_vec(record)?));
        let raw = serde_json::to_vec(&Envelope {
            version: VERSION,
            record: record.clone(),
            sha256,
        })?;
        ensure!(
            u64::try_from(raw.len())? <= MAX_BYTES,
            "meter journal exceeds byte bound"
        );
        let mut temporary = Temporary::new(&self.directory)?;
        temporary.file.write_all(&raw)?;
        temporary.file.sync_all()?;
        temporary.replace()?;
        self.directory.sync_all()?;
        Ok(())
    }
    #[cfg(all(test, unix))]
    pub(super) fn fail_next_write(&self) {
        self.fail_next
            .store(true, std::sync::atomic::Ordering::Release);
    }
}

// Directory-relative IO remains pinned to the opened private directory even if
// an ancestor or its name is replaced. No rename follows a mutable path string.
#[cfg(unix)]
struct Temporary<'a> {
    directory: &'a File,
    name: String,
    file: File,
    renamed: bool,
}
#[cfg(unix)]
impl<'a> Temporary<'a> {
    fn new(directory: &'a File) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let name = format!(".meter-{:032x}.tmp", rand::random::<u128>());
        let file: File = rustix::fs::openat(
            directory,
            name.as_str(),
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_bits_truncate(0o600),
        )?
        .into();
        let temporary = Self {
            directory,
            name,
            file,
            renamed: false,
        };
        ensure!(
            temporary.file.metadata()?.uid() == directory.metadata()?.uid(),
            "meter directory is not owned by the running user"
        );
        Ok(temporary)
    }
    fn replace(&mut self) -> Result<()> {
        rustix::fs::renameat(
            self.directory,
            self.name.as_str(),
            self.directory,
            "meter.json",
        )
        .context("atomic meter journal replacement")?;
        self.renamed = true;
        Ok(())
    }
}
#[cfg(unix)]
impl Drop for Temporary<'_> {
    fn drop(&mut self) {
        if !self.renamed {
            let _ = rustix::fs::unlinkat(
                self.directory,
                self.name.as_str(),
                rustix::fs::AtFlags::empty(),
            );
        }
    }
}
