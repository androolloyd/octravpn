//! Bounded native certificate acquisition using immutable launch trust.
use anyhow::{ensure, Result};
use octra_node_protocol::{consensus::ValidatorSet, state_sync::manifest};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{oneshot, Mutex as AsyncMutex, Notify, Semaphore};

#[derive(Clone)]
struct Trust {
    validators: ValidatorSet,
    exporters: ValidatorSet,
    chain: Vec<u8>,
    config: Vec<u8>,
}
#[derive(Clone, Debug)]
pub(super) enum Error {
    Busy,
    Expired,
    Stopped,
    Invalid(String),
}
impl Error {
    pub(super) fn reason(&self) -> &str {
        match self {
            Self::Busy => "state sync verification busy",
            Self::Expired => "state sync verification expired",
            Self::Stopped => "state sync verification stopped",
            Self::Invalid(s) => s,
        }
    }
    pub(super) fn retryable(&self) -> bool {
        !matches!(self, Self::Invalid(_))
    }
}
pub(super) struct Loaded {
    pub raw: Vec<u8>,
    pub certificate: manifest::VerifiedCertificate,
}
struct Entry {
    hash: [u8; 32],
    checked: Instant,
    value: std::result::Result<manifest::VerifiedCertificate, String>,
    size: usize,
}
pub(super) struct Service {
    trust: std::result::Result<Trust, String>,
    capacity: Arc<Semaphore>,
    serial: Arc<AsyncMutex<()>>,
    entries: Mutex<VecDeque<Entry>>,
    open: AtomicBool,
    stop: Notify,
}
fn trimmed(raw: &[u8]) -> &[u8] {
    raw.trim_ascii()
}
impl Service {
    pub(super) fn new(chain: Vec<u8>, get: impl Fn(&str) -> Option<Vec<u8>>) -> Arc<Self> {
        let parse = |name, missing| -> std::result::Result<ValidatorSet, String> {
            let raw = get(name).ok_or_else(|| String::from(missing))?;
            let entries = raw
                .split(|b| *b == b',')
                .map(trimmed)
                .filter(|v| !v.is_empty())
                .map(<[u8]>::to_vec)
                .collect::<Vec<_>>();
            manifest::signer_set(&entries).map_err(|e| e.to_string())
        };
        let trust = (|| {
            let validators = parse(
                "OCTRA_VALIDATORS",
                "state sync validators are not configured",
            )?;
            let exporters = parse(
                "OCTRA_STATE_SYNC_EXPORTERS",
                "state sync exporters are not configured",
            )?;
            let config = get("OCTRA_CONSENSUS_CONFIG_HASH")
                .ok_or_else(|| String::from("state sync config hash is not configured"))?;
            let config = trimmed(&config);
            let config = if config.len() == 32 {
                hex::encode(config).into_bytes()
            } else {
                config.to_vec()
            };
            if !super::lower_hex(&config) {
                return Err("consensus config hash has invalid encoding".into());
            }
            Ok(Trust {
                validators,
                exporters,
                chain,
                config,
            })
        })();
        Arc::new(Self {
            trust,
            capacity: Arc::new(Semaphore::new(8)),
            serial: Arc::new(AsyncMutex::new(())),
            entries: Mutex::new(VecDeque::new()),
            open: AtomicBool::new(true),
            stop: Notify::new(),
        })
    }
    pub(super) fn shutdown(&self) {
        self.open.store(false, Ordering::Release);
        self.capacity.close();
        if let Ok(mut entries) = self.entries.lock() {
            entries.clear();
        }
        self.stop.notify_waiters();
    }
    fn checked(
        &self,
        raw: &[u8],
        cancelled: &AtomicBool,
    ) -> std::result::Result<manifest::VerifiedCertificate, String> {
        let trust = self.trust.as_ref().map_err(Clone::clone)?;
        let hash: [u8; 32] = Sha256::digest(raw).into();
        let now = Instant::now();
        if let Ok(mut entries) = self.entries.lock() {
            if let Some(index) = entries.iter().position(|e| {
                e.hash == hash
                    && (e.value.is_ok() || now.duration_since(e.checked) <= Duration::from_secs(5))
            }) {
                let entry = entries.remove(index).expect("located entry");
                let value = entry.value.clone();
                entries.push_front(entry);
                return value;
            }
        }
        let value = manifest::Trust {
            validators: &trust.validators,
            exporters: &trust.exporters,
            chain_id: &trust.chain,
            config_hash: &trust.config,
            minimum_epoch: 0,
        }
        .verify_persisted(raw)
        .map_err(|e| match e.to_string().as_str() {
            "manifest chain id mismatch" => "state sync certificate chain mismatch".into(),
            "manifest config hash mismatch" => "state sync certificate config mismatch".into(),
            _ => e.to_string(),
        });
        // Cache charging covers decoded structures as well as the encoded input;
        // an otherwise valid large certificate remains usable without caching.
        let size = if value.is_ok() {
            raw.len().saturating_mul(8).saturating_add(4096)
        } else {
            512 + value.as_ref().err().map_or(0, String::len)
        };
        if size <= 64 * 1024 * 1024
            && !cancelled.load(Ordering::Acquire)
            && self.open.load(Ordering::Acquire)
        {
            if let Ok(mut entries) = self.entries.lock() {
                entries.retain(|e| e.hash != hash);
                entries.push_front(Entry {
                    hash,
                    checked: now,
                    value: value.clone(),
                    size,
                });
                let mut total = 0usize;
                let mut keep = 0;
                for entry in entries.iter().take(64) {
                    if total.saturating_add(entry.size) > 64 * 1024 * 1024 {
                        break;
                    }
                    total += entry.size;
                    keep += 1;
                }
                entries.truncate(keep);
            }
        }
        value
    }
    fn blocking_load(
        &self,
        path: &Path,
        cancelled: &AtomicBool,
    ) -> std::result::Result<Loaded, Error> {
        let raw = read(path).map_err(Error::Invalid)?;
        let certificate = self.checked(&raw, cancelled).map_err(Error::Invalid)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::Invalid(e.to_string()))?
            .as_secs() as i64;
        if !certificate.certificate().fresh(now) {
            return Err(Error::Invalid(
                "state sync certificate is outside its validity window".into(),
            ));
        }
        Ok(Loaded { raw, certificate })
    }
    pub(super) async fn load(
        self: &Arc<Self>,
        path: PathBuf,
    ) -> std::result::Result<Loaded, Error> {
        if !self.open.load(Ordering::Acquire) {
            return Err(Error::Stopped);
        }
        if let Err(reason) = &self.trust {
            return Err(Error::Invalid(reason.clone()));
        }
        let permit = self.capacity.clone().try_acquire_owned().map_err(|_| {
            if self.open.load(Ordering::Acquire) {
                Error::Busy
            } else {
                Error::Stopped
            }
        })?;
        let service = self.clone();
        let (mut reply, result) = oneshot::channel();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        tokio::spawn(async move {
            let stopped = service.stop.notified();
            tokio::pin!(stopped);
            stopped.as_mut().enable();
            if !service.open.load(Ordering::Acquire) {
                let _ = reply.send(Err(Error::Stopped));
                return;
            }
            let guard = tokio::select! {
                guard=service.serial.clone().lock_owned()=>guard,
                ()=reply.closed()=>return,
                ()=tokio::time::sleep_until(deadline)=>{let _=reply.send(Err(Error::Expired));return;},
                ()=&mut stopped=>{let _=reply.send(Err(Error::Stopped));return;},
            };
            if !service.open.load(Ordering::Acquire) {
                let _ = reply.send(Err(Error::Stopped));
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                let _ = reply.send(Err(Error::Expired));
                return;
            }
            let owned = service.clone();
            let cancelled = Arc::new(AtomicBool::new(false));
            let cancellation = cancelled.clone();
            let mut worker = tokio::task::spawn_blocking(move || {
                let (_permit, _guard) = (permit, guard);
                owned.blocking_load(&path, &cancellation)
            });
            let value = tokio::select! {
                value=&mut worker=>value.unwrap_or_else(|_|Err(Error::Invalid("state sync certificate verification failed".into()))),
                ()=reply.closed()=>{cancelled.store(true,Ordering::Release);return;},
                ()=tokio::time::sleep_until(deadline)=>{let _=reply.send(Err(Error::Expired));return;},
                ()=&mut stopped=>{let _=reply.send(Err(Error::Stopped));return;},
            };
            let value = if !service.open.load(Ordering::Acquire) {
                Err(Error::Stopped)
            } else if tokio::time::Instant::now() >= deadline {
                Err(Error::Expired)
            } else {
                value
            };
            let _ = reply.send(value);
        });
        result.await.unwrap_or(Err(Error::Stopped))
    }
}

fn read(path: &Path) -> std::result::Result<Vec<u8>, String> {
    use std::io::Read;
    let failed = || String::from("state sync certificate read failed");
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    let mut file = options.open(path).map_err(|_| failed())?;
    let before = file.metadata().map_err(|_| failed())?;
    if !before.is_file() {
        return Err("state sync certificate is not a file".into());
    }
    if before.len() > manifest::MANIFEST_LIMIT as u64 {
        return Err("state sync certificate exceeds size limit".into());
    }
    let mut raw = vec![0; before.len() as usize];
    file.read_exact(&mut raw).map_err(|_| failed())?;
    let after = file.metadata().map_err(|_| failed())?;
    let at_path = std::fs::symlink_metadata(path).map_err(|_| failed())?;
    let same = |a: &std::fs::Metadata, b: &std::fs::Metadata| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            a.is_file()
                && b.is_file()
                && a.dev() == b.dev()
                && a.ino() == b.ino()
                && a.len() == b.len()
                && a.mtime() == b.mtime()
                && a.mtime_nsec() == b.mtime_nsec()
                && a.ctime() == b.ctime()
                && a.ctime_nsec() == b.ctime_nsec()
        }
        #[cfg(not(unix))]
        {
            a.is_file()
                && b.is_file()
                && a.len() == b.len()
                && a.modified().ok() == b.modified().ok()
        }
    };
    if same(&before, &after) && same(&before, &at_path) {
        Ok(raw)
    } else {
        Err("state sync certificate changed during read".into())
    }
}

/// Walk each component relative to one directory descriptor. Certificates never
/// authorize following symlinks outside the retained snapshot directory.
pub(super) fn open(root: &Path, name: &[u8]) -> Result<std::fs::File> {
    ensure!(manifest::valid_path(name), "invalid snapshot relative path");
    #[cfg(unix)]
    {
        use rustix::fs::{open, openat, Mode, OFlags};
        use std::os::unix::ffi::OsStrExt;
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut directory = open(root, flags, Mode::empty())?;
        let mut parts = name.split(|b| *b == b'/').peekable();
        while let Some(part) = parts.next() {
            let part = std::ffi::OsStr::from_bytes(part);
            if parts.peek().is_some() {
                directory = openat(&directory, part, flags, Mode::empty())?;
            } else {
                let file: std::fs::File = openat(
                    &directory,
                    part,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                    Mode::empty(),
                )?
                .into();
                ensure!(
                    file.metadata()?.is_file(),
                    "snapshot artifact is not a regular file"
                );
                return Ok(file);
            }
        }
        anyhow::bail!("snapshot path is empty")
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        anyhow::bail!("safe snapshot file access requires Unix")
    }
}
