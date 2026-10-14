// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Fsynced native journal publication. OS diagnostics are operational, not wire data.
use super::{Bytes, Error};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
static SERIAL: AtomicU64 = AtomicU64::new(0);
#[allow(clippy::needless_pass_by_value)] // Adapter for Result::map_err.
pub(super) fn io_error(error: std::io::Error) -> Error {
    format!("journal I/O: {error}").into()
}
pub(super) fn sync_directory(path: &Path) -> Result<(), Error> {
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(io_error)
}
pub(super) fn directory(path: &Path, label: &str) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => Ok(()),
        Ok(_) => Err(format!("{label} path is not a directory").into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            builder.mode(0o700);
            match builder.create(path) {
                Ok(()) => {
                    sync_directory(path.parent().unwrap_or_else(|| Path::new(".")))?;
                    sync_directory(path)
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => directory(path, label),
                Err(e) => Err(io_error(e)),
            }
        }
        Err(e) => Err(io_error(e)),
    }
}
pub(super) fn regular(path: &Path, max: u64, label: &str) -> Result<Bytes, Error> {
    let meta = fs::symlink_metadata(path).map_err(io_error)?;
    if !meta.is_file() {
        return Err(format!("{label} is not regular").into());
    }
    if meta.len() == 0 || meta.len() > max {
        return Err(format!("{label} size is invalid").into());
    }
    let mut bytes = vec![0; meta.len() as usize];
    File::open(path)
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(io_error)?;
    Ok(bytes)
}
fn stage(record: &Path) -> Result<(PathBuf, File), Error> {
    for _ in 0..1024 {
        let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
        let mut name = record.as_os_str().to_owned();
        name.push(format!(".{}.{serial}.staged", std::process::id()));
        let path = PathBuf::from(name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&path) {
            Ok(f) => return Ok((path, f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io_error(e)),
        }
    }
    Err("vote log staged record limit exceeded".into())
}
pub(super) fn publish(
    directory: &Path,
    record: &Path,
    wire: &[u8],
    exclusive: bool,
) -> Result<bool, Error> {
    let (path, mut file) = stage(record)?;
    let result = (|| {
        file.write_all(wire)
            .and_then(|()| file.sync_all())
            .map_err(io_error)?;
        drop(file);
        let published = if exclusive {
            match fs::hard_link(&path, record) {
                Ok(()) => true,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
                Err(e) => return Err(io_error(e)),
            }
        } else {
            fs::rename(&path, record).map_err(io_error)?;
            true
        };
        if exclusive {
            let _ = fs::remove_file(&path);
        }
        sync_directory(directory)?;
        Ok(published)
    })();
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}
pub(super) fn failure(error: &Error) -> Error {
    let mut out = b"Failure(\"".to_vec();
    for b in error.as_bytes() {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            b'\x08' => out.extend_from_slice(b"\\b"),
            32..=126 => out.push(*b),
            _ => out.extend_from_slice(format!("\\{b:03}").as_bytes()),
        }
    }
    out.extend_from_slice(b"\")");
    Error::new(out)
}
pub(super) fn names(path: &Path, suffix: &str) -> Result<Vec<PathBuf>, Error> {
    fs::read_dir(path)
        .map_err(io_error)?
        .filter_map(|entry| match entry {
            Err(e) => Some(Err(io_error(e))),
            Ok(e) => {
                let p = e.path();
                if p.as_os_str()
                    .as_encoded_bytes()
                    .ends_with(suffix.as_bytes())
                {
                    Some(Ok(p))
                } else {
                    None
                }
            }
        })
        .collect()
}
