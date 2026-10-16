//! Content-addressed public PVAC blobs. This capability never accepts arbitrary
//! filenames and never supplies authority independently of the canonical tree.
use crate::{execution::Error, state_batch::Snapshot};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
pub trait Source: Send + Sync + 'static {
    fn get(&self, hash: &[u8]) -> Result<Option<Vec<u8>>, Error>;
}
/// Transport bound for canonical stored blobs, separate from the native 5MB
/// incoming registration envelope. The crypto decoder bounds expanded images.
pub const MAX_BLOB_BYTES: usize = 64 * 1024 * 1024;
pub struct Files(pub PathBuf);
impl Files {
    /// Persist immutable public material before a speculative tree binds its
    /// hash. An aborted epoch may leave an unreachable blob; it cannot change
    /// the registered key. Backend metadata is bound to that same blob hash.
    pub fn persist(&self, blob: &[u8]) -> Result<(), Error> {
        if blob.len() > MAX_BLOB_BYTES {
            return Err(Error("pvac blob exceeds file transport limit".into()));
        }
        let hash = hex::encode(Sha256::digest(blob));
        let directory = self.0.join("blobs");
        fs::create_dir_all(&directory).map_err(|e| Error(e.to_string()))?;
        immutable(&directory.join(format!("{hash}.pk")), blob)?;
        immutable(
            &directory.join(format!("{hash}.kat")),
            hex::encode(octra_hfhe::seeded_rng::aes_kat()).as_bytes(),
        )?;
        for path in [&directory, &self.0] {
            fs::File::open(path)
                .and_then(|file| file.sync_all())
                .map_err(|e| Error(e.to_string()))?;
        }
        if let Some(parent) = self.0.parent() {
            let parent = if parent.as_os_str().is_empty() {
                Path::new(".")
            } else {
                parent
            };
            fs::File::open(parent)
                .and_then(|file| file.sync_all())
                .map_err(|e| Error(e.to_string()))?;
        }
        Ok(())
    }
}
fn immutable(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let mut temporary = tempfile::NamedTempFile::new_in(
        path.parent()
            .ok_or_else(|| Error("pvac directory missing".into()))?,
    )
    .map_err(|e| Error(e.to_string()))?;
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|e| Error(e.to_string()))?;
    match temporary.persist_noclobber(path) {
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut options = fs::OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(
                    (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
                );
            }
            let file = options.open(path).map_err(|e| Error(e.to_string()))?;
            let metadata = file.metadata().map_err(|e| Error(e.to_string()))?;
            if !metadata.is_file() || metadata.len() != bytes.len() as u64 {
                return Err(Error("pvac immutable file differs".into()));
            }
            let mut current = Vec::new();
            (&file)
                .take(bytes.len() as u64 + 1)
                .read_to_end(&mut current)
                .map_err(|e| Error(e.to_string()))?;
            if current != bytes {
                return Err(Error("pvac immutable file differs".into()));
            }
            file.sync_all().map_err(|e| Error(e.to_string()))
        }
        Err(error) => Err(Error(error.error.to_string())),
    }
}
pub fn valid_hash(hash: &[u8]) -> bool {
    hash.len() == 64
        && hash
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}
impl Source for Files {
    fn get(&self, hash: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        if !valid_hash(hash) {
            return Err(Error("invalid pvac blob hash".into()));
        }
        let path = self.0.join("blobs").join(format!(
            "{}.pk",
            std::str::from_utf8(hash).expect("hexadecimal hash")
        ));
        let before = match fs::symlink_metadata(&path) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error(e.to_string())),
        };
        if !before.is_file() || before.len() > MAX_BLOB_BYTES as u64 {
            return Err(Error("pvac blob must be a bounded regular file".into()));
        }
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            );
        }
        let file = options.open(path).map_err(|e| Error(e.to_string()))?;
        let after = file.metadata().map_err(|e| Error(e.to_string()))?;
        if !after.is_file() || after.len() > MAX_BLOB_BYTES as u64 {
            return Err(Error("pvac blob identity changed".into()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if before.dev() != after.dev() || before.ino() != after.ino() {
                return Err(Error("pvac blob identity changed".into()));
            }
        }
        let mut bytes = Vec::new();
        file.take(MAX_BLOB_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| Error(e.to_string()))?;
        if bytes.len() > MAX_BLOB_BYTES || hex::encode(Sha256::digest(&bytes)).as_bytes() != hash {
            return Err(Error("pvac blob hash mismatch".into()));
        }
        Ok(Some(bytes))
    }
}
pub fn bound(
    source: Option<&Arc<dyn Source>>,
    state: &Snapshot,
    address: &[u8],
) -> Result<Option<Arc<[u8]>>, Error> {
    let Some(hash) = state
        .get(&[b"pvac_hashes", address])
        .filter(|h| *h != b"none")
    else {
        return Ok(None);
    };
    let source = source.ok_or_else(|| Error("PVAC public key source is unavailable".into()))?;
    let raw = source
        .get(hash)?
        .ok_or_else(|| Error("pvac blob unavailable".into()))?;
    if hex::encode(Sha256::digest(&raw)).as_bytes() != hash {
        return Err(Error("pvac blob hash mismatch".into()));
    }
    Ok(Some(raw.into()))
}
