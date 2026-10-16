// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Scoped safe access to a privately owned native LMDB environment. The two
//! unsafe operations are confined to opening and resizing an unpublished owner.
use heed::{types::Bytes, Database, Env, EnvOpenOptions, RoTxn, RwTxn, WithoutTls};
use std::{fmt, fs::File, path::Path};
type Map = Database<Bytes, Bytes>;
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Database(heed::Error),
    Policy(String),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => e.fmt(f),
            Self::Database(e) => e.fmt(f),
            Self::Policy(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<heed::Error> for Error {
    fn from(error: heed::Error) -> Self {
        Self::Database(error)
    }
}
pub type Result<T> = std::result::Result<T, Error>;

pub struct Store {
    // Field order closes the environment before releasing directory ownership.
    env: Env<WithoutTls>,
    maps: [Map; 4],
    page: usize,
    _owner: File,
}
pub struct Read<'a, 'env> {
    maps: &'env [Map; 4],
    txn: &'a RoTxn<'env>,
}
pub struct Write<'env> {
    maps: &'env [Map; 4],
    txn: RwTxn<'env>,
}
impl Store {
    pub fn open(
        path: &Path,
        names: [&str; 4],
        initial_bytes: usize,
        map_limit: impl FnOnce(usize) -> std::result::Result<usize, String>,
    ) -> Result<Self> {
        let owner = private_owner(path)?;
        // SAFETY: the directory is private, non-symlinked and exclusively held
        // by a directory flock shared with the native node. No environment or
        // transaction escapes this owner. Application code never writes mapped
        // files, truncates them, changes flags or resizes a published environment.
        let env = unsafe {
            EnvOpenOptions::new()
                .read_txn_without_tls()
                .max_dbs(4)
                .map_size(initial_bytes)
                .open(path)?
        };
        let page = env.stat().page_size as usize;
        let bytes = map_limit(page).map_err(Error::Policy)?;
        // SAFETY: no transaction has been created and this environment has no
        // clones. The same directory ownership guard excludes other openers.
        unsafe {
            env.resize(bytes)?;
        }
        if env.info().map_size != bytes {
            return Err(Error::Policy("compute history map exceeds limit".into()));
        }
        let mut txn = env.write_txn()?;
        let maps = [
            env.create_database(&mut txn, Some(names[0]))?,
            env.create_database(&mut txn, Some(names[1]))?,
            env.create_database(&mut txn, Some(names[2]))?,
            env.create_database(&mut txn, Some(names[3]))?,
        ];
        txn.commit()?;
        owner.sync_all()?;
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(Self {
            env,
            maps,
            page,
            _owner: owner,
        })
    }
    pub fn page_size(&self) -> usize {
        self.page
    }
    pub fn read<T, E: From<Error>>(
        &self,
        read: impl FnOnce(Read<'_, '_>) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E> {
        let txn = self.env.read_txn().map_err(Error::from).map_err(E::from)?;
        let result = read(Read {
            maps: &self.maps,
            txn: &txn,
        })?;
        txn.commit().map_err(Error::from).map_err(E::from)?;
        Ok(result)
    }
    pub fn write<T, E: From<Error>>(
        &self,
        change: impl FnOnce(&mut Write<'_>) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E> {
        let txn = self.env.write_txn().map_err(Error::from).map_err(E::from)?;
        let mut write = Write {
            maps: &self.maps,
            txn,
        };
        let result = change(&mut write)?;
        write.txn.commit().map_err(Error::from).map_err(E::from)?;
        Ok(result)
    }
}
impl Read<'_, '_> {
    pub fn get(&self, map: usize, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.maps[map].get(self.txn, key)?.map(<[u8]>::to_vec))
    }
    pub fn count(&self, map: usize) -> Result<u64> {
        Ok(self.maps[map].len(self.txn)?)
    }
    /// Returns at most limit+1 entries so callers can detect a corrupt capacity.
    pub fn prefix(
        &self,
        map: usize,
        prefix: &[u8],
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.maps[map]
            .prefix_iter(self.txn, prefix)?
            .take(limit.saturating_add(1))
            .map(|row| {
                row.map(|(key, value)| (key.to_vec(), value.to_vec()))
                    .map_err(Error::from)
            })
            .collect()
    }
    pub fn live_bytes(&self) -> Result<u64> {
        self.maps.iter().try_fold(0_u64, |total, map| {
            let stat = map.stat(self.txn)?;
            Ok(total
                + (stat.branch_pages + stat.leaf_pages + stat.overflow_pages) as u64
                    * u64::from(stat.page_size))
        })
    }
    /// Seek to an inclusive cursor and copy at most limit+1 matching rows. The
    /// extra row is the next durable cursor, never part of the current batch.
    pub fn batch(
        &self,
        map: usize,
        start: &[u8],
        prefix: &[u8],
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        use std::ops::Bound::{Included, Unbounded};
        let range = (Included(start), Unbounded);
        let mut out = Vec::new();
        for row in self.maps[map]
            .range(self.txn, &range)?
            .take(limit.saturating_add(1))
        {
            let (key, value) = row?;
            if !key.starts_with(prefix) {
                break;
            }
            out.push((key.to_vec(), value.to_vec()));
        }
        Ok(out)
    }
    pub fn find<T, E: From<Error>>(
        &self,
        map: usize,
        prefix: &[u8],
        mut visit: impl FnMut(&[u8], &[u8]) -> std::result::Result<Option<T>, E>,
    ) -> std::result::Result<Option<T>, E> {
        let rows = self.maps[map]
            .prefix_iter(self.txn, prefix)
            .map_err(Error::from)
            .map_err(E::from)?;
        for row in rows {
            let (key, value) = row.map_err(Error::from).map_err(E::from)?;
            if let Some(value) = visit(key, value)? {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }
}
impl Write<'_> {
    pub fn view(&self) -> Read<'_, '_> {
        Read {
            maps: self.maps,
            txn: &self.txn,
        }
    }
    pub fn get(&self, map: usize, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.view().get(map, key)
    }
    pub fn put(&mut self, map: usize, key: &[u8], value: &[u8]) -> Result<()> {
        self.maps[map].put(&mut self.txn, key, value)?;
        Ok(())
    }
    pub fn remove(&mut self, map: usize, key: &[u8]) -> Result<bool> {
        Ok(self.maps[map].delete(&mut self.txn, key)?)
    }
    pub fn count(&self, map: usize) -> Result<u64> {
        self.view().count(map)
    }
    pub fn prefix(
        &self,
        map: usize,
        prefix: &[u8],
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.view().prefix(map, prefix, limit)
    }
    pub fn live_bytes(&self) -> Result<u64> {
        self.view().live_bytes()
    }
}
#[cfg(unix)]
fn private_owner(path: &Path) -> Result<File> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    let mut create = std::fs::DirBuilder::new();
    create.mode(0o700);
    match create.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let before = std::fs::symlink_metadata(path)?;
    let uid = rustix::process::geteuid().as_raw();
    if !before.is_dir() || before.uid() != uid || before.mode() & 0o077 != 0 {
        return Err(Error::Policy(
            "compute history directory permissions".into(),
        ));
    }
    let flags =
        rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
    let owner = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags.bits() as i32)
        .open(path)?;
    let actual = owner.metadata()?;
    if actual.dev() != before.dev() || actual.ino() != before.ino() {
        return Err(Error::Policy("compute history directory changed".into()));
    }
    rustix::fs::flock(&owner, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(std::io::Error::from)?;
    for name in ["data.mdb", "lock.mdb"] {
        match std::fs::symlink_metadata(path.join(name)) {
            Ok(metadata) if !metadata.is_file() || metadata.uid() != uid => {
                return Err(Error::Policy("compute history file ownership".into()))
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(owner)
}
#[cfg(not(unix))]
fn private_owner(_path: &Path) -> Result<File> {
    Err(Error::Policy(
        "native compute history requires Unix directory ownership".into(),
    ))
}
