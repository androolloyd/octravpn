//! Native durable local exit intents. File permissions, inode identity, POSIX
//! advisory locking and directory fsync protect the operator's duty switch.
use octra_node_protocol::{
    oce1::Error,
    validator::intent::{Identity, Intent},
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
pub struct Control {
    directory: PathBuf,
    busy: Arc<tokio::sync::Mutex<()>>,
}
impl Control {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            directory: data_dir.join("validator-control"),
            busy: Arc::new(tokio::sync::Mutex::new(())),
        }
    }
}
#[cfg(unix)]
mod unix {
    use super::{Control, Error, Identity, Intent, Path};
    use rustix::fs::{fcntl_lock, FlockOperation};
    use std::{
        fs::{self, File, Metadata, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    };
    /// Keeps local exit intent exclusion active through asynchronous admission.
    pub struct DutyGuard {
        file: File,
        _busy: tokio::sync::OwnedMutexGuard<()>,
    }
    impl Drop for DutyGuard {
        fn drop(&mut self) {
            let _ = fcntl_lock(&self.file, FlockOperation::Unlock);
        }
    }
    fn failure(context: &str, e: impl std::fmt::Display) -> Error {
        format!("{context}: {e}").into()
    }
    fn inspect(path: &Path) -> Result<Option<Metadata>, Error> {
        match fs::symlink_metadata(path) {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(failure("validator control read failed", e)),
        }
    }
    // Keep the explicit native private-file permission mask.
    #[allow(clippy::verbose_bit_mask)]
    fn protected(meta: &Metadata, directory: bool) -> bool {
        (if directory {
            meta.is_dir()
        } else {
            meta.is_file()
        }) && meta.uid() == rustix::process::getuid().as_raw()
            && meta.mode() & 0o077 == 0
    }
    fn same(a: &Metadata, b: &Metadata) -> bool {
        a.ino() == b.ino() && a.dev() == b.dev()
    }
    fn sync(path: &Path) -> Result<(), Error> {
        File::open(path)
            .and_then(|f| f.sync_all())
            .map_err(|e| failure("validator control sync failed", e))
    }
    impl Control {
        fn directory(&self) -> Result<bool, Error> {
            match inspect(&self.directory)? {
                None => Ok(false),
                Some(v) if protected(&v, true) => Ok(true),
                _ => Err("validator control directory is not private".into()),
            }
        }
        fn lock_status(&self) -> Result<(), Error> {
            match inspect(&self.directory.join("lock"))? {
                None => Ok(()),
                Some(v) if protected(&v, false) && v.mode() & 0o600 == 0o600 => Ok(()),
                _ => Err("validator control lock must be private and writable".into()),
            }
        }
        fn prepare(&self) -> Result<(), Error> {
            if self.directory()? {
                return Ok(());
            }
            match fs::DirBuilder::new().mode(0o700).create(&self.directory) {
                Ok(()) => sync(
                    self.directory
                        .parent()
                        .ok_or("validator control parent unavailable")?,
                ),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if self.directory()? {
                        Ok(())
                    } else {
                        Err("validator control directory disappeared".into())
                    }
                }
                Err(e) => Err(failure("validator control create failed", e)),
            }
        }
        fn acquire(&self) -> Result<DutyGuard, Error> {
            let busy = self
                .busy
                .clone()
                .try_lock_owned()
                .map_err(|_| Error::from("validator control is busy"))?;
            self.prepare()?;
            let path = self.directory.join("lock");
            let prior = inspect(&path)?;
            if prior.as_ref().is_some_and(|m| !protected(m, false)) {
                return Err("validator control file is not private".into());
            }
            let mut options = OpenOptions::new();
            options
                .read(true)
                .write(true)
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
            if prior.is_none() {
                options.create_new(true);
            }
            let file = options
                .open(&path)
                .map_err(|e| failure("validator control open failed", e))?;
            let current = file
                .metadata()
                .map_err(|e| failure("validator control open failed", e))?;
            let linked = fs::symlink_metadata(&path)
                .map_err(|e| failure("validator control open failed", e))?;
            if !protected(&current, false) || !protected(&linked, false) || !same(&current, &linked)
            {
                return Err("validator control file changed".into());
            }
            fcntl_lock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|e| {
                if e == rustix::io::Errno::AGAIN || e == rustix::io::Errno::ACCESS {
                    Error::from("validator control is busy")
                } else {
                    failure("validator control failed", e)
                }
            })?;
            Ok(DutyGuard { file, _busy: busy })
        }
        fn locked<T>(&self, action: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
            let _lease = self.acquire()?;
            action()
        }
        pub fn duty_guard(&self, identity: &Identity) -> Result<DutyGuard, Error> {
            let lease = self.acquire()?;
            if self.status(identity)?.is_some() {
                return Err("validator exit intent pauses duty".into());
            }
            Ok(lease)
        }
        fn load(&self) -> Result<Option<Intent>, Error> {
            if !self.directory()? {
                return Ok(None);
            }
            self.lock_status()?;
            let path = self.directory.join("exit.json");
            let Some(prior) = inspect(&path)? else {
                return Ok(None);
            };
            if !protected(&prior, false) || prior.len() > 4096 {
                return Err("invalid validator exit intent file".into());
            }
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(&path)
                .map_err(|e| failure("validator exit intent read failed", e))?;
            let current = file
                .metadata()
                .map_err(|e| failure("validator exit intent read failed", e))?;
            if !protected(&current, false) || !same(&prior, &current) || current.len() > 4096 {
                return Err("validator exit intent file changed".into());
            }
            let mut raw = Vec::with_capacity(current.len() as usize);
            Read::by_ref(&mut file)
                .take(current.len())
                .read_to_end(&mut raw)
                .map_err(|e| failure("validator exit intent read failed", e))?;
            if raw.len() != current.len() as usize {
                return Err("validator exit intent file changed".into());
            }
            Intent::decode(&raw).map(Some)
        }
        pub fn status(&self, identity: &Identity) -> Result<Option<String>, Error> {
            let Some(value) = self.load()? else {
                return Ok(None);
            };
            if value.applies(identity)? {
                value.id().map(Some)
            } else {
                Ok(None)
            }
        }
        fn write(&self, value: &Intent) -> Result<(), Error> {
            let path = self.directory.join("exit.json");
            let next = self.directory.join("exit.next");
            if let Some(prior) = inspect(&next)? {
                if !protected(&prior, false) {
                    return Err("invalid validator exit staging file".into());
                }
                fs::remove_file(&next)
                    .map_err(|e| failure("validator exit intent write failed", e))?;
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(&next)
                .map_err(|e| failure("validator exit intent write failed", e))?;
            file.write_all(&value.encode())
                .and_then(|()| file.sync_all())
                .map_err(|e| failure("validator exit intent write failed", e))?;
            fs::rename(next, path).map_err(|e| failure("validator exit intent write failed", e))?;
            sync(&self.directory)
        }
        // Preserve the native owned-input and typed diagnostic interface.
        #[allow(clippy::needless_pass_by_value)]
        pub fn request(&self, identity: Identity, privkey: &[u8]) -> Result<String, Error> {
            let value = Intent::create(identity.clone(), privkey)?;
            self.locked(|| {
                if let Some(id) = self.status(&identity)? {
                    sync(&self.directory)?;
                    Ok(id)
                } else {
                    self.write(&value)?;
                    value.id()
                }
            })
        }
        pub fn cancel(&self, identity: &Identity, privkey: &[u8]) -> Result<(), Error> {
            Intent::create(identity.clone(), privkey)?;
            self.locked(|| {
                if let Some(value) = self.load()? {
                    value.applies(identity)?;
                    fs::remove_file(self.directory.join("exit.json"))
                        .map_err(|e| failure("validator exit intent write failed", e))?;
                    sync(&self.directory)?;
                }
                Ok(())
            })
        }
        pub fn guard<T>(
            &self,
            identity: &Identity,
            action: impl FnOnce() -> Result<T, Error>,
        ) -> Result<T, Error> {
            self.locked(|| {
                if self.status(identity)?.is_some() {
                    Err("validator exit intent pauses duty".into())
                } else {
                    action()
                }
            })
        }
    }
}
#[cfg(unix)]
pub use unix::DutyGuard;
#[cfg(not(unix))]
pub struct DutyGuard;
#[cfg(not(unix))]
impl Control {
    pub fn duty_guard(&self, _: &Identity) -> Result<DutyGuard, Error> {
        Err("validator control requires POSIX filesystem semantics".into())
    }
    pub fn status(&self, _: &Identity) -> Result<Option<String>, Error> {
        Err("validator control requires POSIX filesystem semantics".into())
    }
    pub fn request(&self, _: Identity, _: &[u8]) -> Result<String, Error> {
        Err("validator control requires POSIX filesystem semantics".into())
    }
    pub fn cancel(&self, _: &Identity, _: &[u8]) -> Result<(), Error> {
        Err("validator control requires POSIX filesystem semantics".into())
    }
    pub fn guard<T>(&self, _: &Identity, _: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        Err("validator control requires POSIX filesystem semantics".into())
    }
}
