//! Explicit stopped-store maintenance. Native physical reads require a pinned
//! native executable; current canonical SQLite state is inspected in Rust.
use crate::native_tools::{
    Bounds, NativeBackend, NativeBackendOptions, NativeDirectoryOwner, NativeTool, Policy,
};
use anyhow::{ensure, Context, Result};
use clap::Args;
use octra_node_protocol::consensus::journal::JournalOwner;
use octra_node_runtime::canonical::OfflineStore;
use std::{
    ffi::OsString,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

mod fhe;
mod vote_floor;
pub use vote_floor::VoteFloor;

#[derive(Args)]
pub struct CheckStore {
    /// Existing stopped data directory, as for the native check_store tool.
    #[arg(allow_hyphen_values = true)]
    pub directory: PathBuf,
    #[command(flatten)]
    pub storage: Storage,
}
#[derive(Args)]
pub struct FheAudit {
    /// Existing stopped data directory, as for the native fhe_audit tool.
    #[arg(allow_hyphen_values = true)]
    pub directory: PathBuf,
    #[command(flatten)]
    pub storage: Storage,
}
#[derive(Args)]
pub struct Storage {
    /// Inspect current canonical.sqlite in Rust; never open the native backend.
    #[arg(long, conflicts_with_all = ["backend", "backend_sha256", "backend_certificate"])]
    pub canonical: bool,
    /// Exact unchanged native physical utility, selected explicitly.
    #[arg(long, required_unless_present = "canonical")]
    pub backend: Option<PathBuf>,
    #[arg(long, required_unless_present = "canonical")]
    pub backend_sha256: Option<String>,
    /// Authenticated adopted-source/build/executable certificate.
    #[arg(long, required_unless_present = "canonical")]
    pub backend_certificate: Option<PathBuf>,
}
impl Storage {
    fn native(&self, tool: NativeTool) -> Result<NativeBackend> {
        NativeBackend::verified(
            tool,
            &NativeBackendOptions {
                executable: self.backend.clone().context("native backend is required")?,
                sha256: self
                    .backend_sha256
                    .clone()
                    .context("native backend SHA256 is required")?,
                certificate: self
                    .backend_certificate
                    .clone()
                    .context("native build certificate is required")?,
            },
        )
    }
}

pub(super) fn directory(path: &Path) -> Result<PathBuf> {
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_dir(),
        "data directory is missing or linked"
    );
    Ok(path.canonicalize()?)
}
pub(super) fn existing_file(path: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_file(),
        "input is missing or not regular"
    );
    Ok(())
}
pub(super) fn native_layout(path: &Path, chain: bool) -> Result<()> {
    ensure!(
        !path.join("canonical.sqlite").try_exists()?,
        "native tool refuses current canonical storage"
    );
    ensure!(
        fs::symlink_metadata(path.join("irmin_store"))?
            .file_type()
            .is_dir(),
        "native store is missing or linked"
    );
    if chain {
        ensure!(
            fs::symlink_metadata(path.join("chaindata"))?
                .file_type()
                .is_dir(),
            "native chaindata is missing or linked"
        );
    }
    Ok(())
}
pub(super) struct CanonicalOwner {
    _writer: fs::File,
    journal: JournalOwner,
}
pub(super) fn canonical_owner(directory: &Path) -> Result<CanonicalOwner> {
    ensure!(
        !directory.join("irmin_store").try_exists()?
            && !directory.join("chaindata").try_exists()?,
        "canonical tool refuses native storage"
    );
    let database = directory.join("canonical.sqlite");
    existing_file(&database)?;
    let writer = crate::single::writer_lock(&database)?;
    let journal = JournalOwner::open(directory)?;
    Ok(CanonicalOwner {
        _writer: writer,
        journal,
    })
}
fn forward(output: &std::process::Output) -> Result<i32> {
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&output.stdout)?;
    stdout.flush()?;
    let mut stderr = std::io::stderr().lock();
    stderr.write_all(&output.stderr)?;
    stderr.flush()?;
    output.status.code().context("native tool exited by signal")
}
impl CheckStore {
    pub async fn run(&self) -> Result<i32> {
        let path = directory(&self.directory)?;
        if !self.storage.canonical {
            native_layout(&path, true)?;
            let backend = self.storage.native(NativeTool::CheckStore)?;
            let output = backend
                .run(
                    vec![OsString::from(path)],
                    Policy::ReadOnly,
                    (),
                    Bounds::default(),
                )
                .await?;
            return forward(&output);
        }
        let _owner = canonical_owner(&path)?;
        let store = OfflineStore::open(&path.join("canonical.sqlite")).await?;
        println!(
            "event = store_check status = verified action = stay epoch = {} readonly = true backend = canonical_sqlite",
            store.head().cursor.epoch.0
        );
        store.close().await;
        Ok(0)
    }
}
impl FheAudit {
    pub async fn run(&self) -> Result<i32> {
        let path = directory(&self.directory)?;
        if !self.storage.canonical {
            native_layout(&path, false)?;
            let backend = self.storage.native(NativeTool::FheAudit)?;
            let output = backend
                .run(
                    vec![OsString::from(path)],
                    Policy::ReadOnly,
                    (),
                    Bounds::default(),
                )
                .await?;
            return forward(&output);
        }
        let _owner = canonical_owner(&path)?;
        let store = OfflineStore::open(&path.join("canonical.sqlite")).await?;
        let result = fhe::audit(store.head(), store.state());
        store.close().await;
        result
    }
}
