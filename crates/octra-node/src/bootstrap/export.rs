//! Native snapshot interchange from a reauthenticated retained checkpoint suffix.
//!
//! `prepare` writes an unsigned package using an explicitly supplied finalized
//! anchor. `assemble` verifies the files and configured signing authority before
//! publishing a native certificate. `serve` exposes only that completed package.
//! The standalone `ledger` operation remains an image-only interchange API.
mod cli;
mod codec;
pub(crate) mod package;
mod serve;
use super::Authority;
use anyhow::{ensure, Context, Result};
pub use cli::Commands;
use octra_node_runtime::ledger_image::{self, Limits, Written};
pub use package::{assemble, prepare, Assemble, PackageReport, Prepare};
use serde::Serialize;
pub use serve::serve;
use std::{
    fs,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

#[derive(Debug, Serialize)]
pub struct Report {
    pub file: PathBuf,
    pub chain_id: String,
    pub epoch: u64,
    pub state_root: String,
    pub commit: String,
    #[serde(flatten)]
    pub ledger: Written,
}

/// Produces a ledger image only. Exporter/checkpoint signatures are separate
/// authority; writing an image does not make it an admissible network snapshot.
pub async fn ledger(
    authority: &Authority,
    directory: &Path,
    target: &Path,
    limits: Limits,
) -> Result<Report> {
    let parent = target
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent).context("ledger output parent must exist")?;
    let target = parent.join(target.file_name().context("ledger output has no name")?);
    match fs::symlink_metadata(&target) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Ok(_) => anyhow::bail!("ledger image target already exists"),
        Err(error) => return Err(error.into()),
    }
    let store = authority.reopen(directory).await?;
    let head = store.head().await?;
    let state = store.reader().snapshot_at(&head).await?;
    store.close().await;
    let chain_id = authority.network().identity.chain_id.clone();
    tokio::task::spawn_blocking(move || {
        let mut staged = tempfile::NamedTempFile::new_in(&parent)?;
        let ledger = {
            let mut output = BufWriter::with_capacity(4 * 1024 * 1024, staged.as_file_mut());
            let written = ledger_image::write(&state, &mut output, limits)?;
            output.flush()?;
            written
        };
        ensure!(
            ledger.root == head.ledger_root,
            "export differs from retained ledger root"
        );
        ensure!(
            staged.as_file().metadata()?.len() == ledger.bytes,
            "export length differs"
        );
        staged.as_file().sync_all()?;
        staged.persist_noclobber(&target)?;
        fs::File::open(&parent)?.sync_all()?;
        Ok(Report {
            file: target,
            chain_id,
            epoch: head.cursor.epoch.0,
            state_root: hex::encode(head.cursor.state_root.0),
            commit: head.irmin_commit,
            ledger,
        })
    })
    .await?
}
