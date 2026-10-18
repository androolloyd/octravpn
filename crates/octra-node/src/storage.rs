//! Atomic, fsynced local artifacts. Existing content-addressed records must agree.
use anyhow::{ensure, Result};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};
static SERIAL: AtomicU64 = AtomicU64::new(0);
pub(crate) fn publish(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("record has no parent"))?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    fs::create_dir_all(parent)?;
    let staging = parent.join(format!(
        ".{}.{}.staged",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&staging)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        match fs::hard_link(&staging, path) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let meta = fs::symlink_metadata(path)?;
                ensure!(
                    meta.is_file() && meta.len() == bytes.len() as u64 && fs::read(path)? == bytes,
                    "durable record differs: {}",
                    path.display()
                );
            }
            Err(e) => return Err(e.into()),
        }
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    drop(file);
    let _ = fs::remove_file(staging);
    result
}
