//! Offline resume of a locally trusted, already staged native storage repair.
//! Modern canonical history is never a backend of this compatibility command.
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Args;
use octra_node_protocol::{
    fork_repair::{self, Finality, Finish, Plan},
    state_sync::head::Head,
};
use serde_json::{json, Value};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};
mod process;
const MAX: u64 = 1_048_576;
const UPSTREAM: &str = "7f9be4489870645cfcc95439638cde40f5da9f50";
#[derive(Args)]
pub struct Options {
    /// Stopped native directory containing a durably staged fork_repair.json.
    #[arg(long)]
    pub directory: PathBuf,
    /// Trusted chain identity; the local repair marker does not grant authority.
    #[arg(long)]
    pub chain_id: String,
    /// Pinned native-format compatibility executable.
    #[arg(long)]
    pub backend: PathBuf,
    #[arg(long)]
    pub backend_sha256: String,
}
impl Options {
    pub fn run(&self) -> Result<()> {
        println!("{}", serde_json::to_string_pretty(&resume(self)?)?);
        Ok(())
    }
}
fn regular(path: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_file(),
        "legacy input is not a regular file: {}",
        path.display()
    );
    Ok(())
}
fn read(path: &Path) -> Result<Vec<u8>> {
    regular(path)?;
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX, "legacy input exceeds bound");
    Ok(bytes)
}
fn layout(path: &Path) -> Result<PathBuf> {
    let path = path.canonicalize()?;
    for name in ["canonical.sqlite", "canonical.sqlite-wal", "exex.db"] {
        match fs::symlink_metadata(path.join(name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
            Ok(_) => bail!("legacy repair refuses modern canonical storage"),
        }
    }
    for name in ["chaindata", "irmin_store"] {
        ensure!(
            fs::symlink_metadata(path.join(name))?.file_type().is_dir(),
            "native store directory is missing or linked"
        );
    }
    Ok(path)
}
pub fn resume(options: &Options) -> Result<Value> {
    ensure!(
        !options.chain_id.is_empty() && options.chain_id.len() <= 1024,
        "invalid chain identity"
    );
    let directory = layout(&options.directory)?;
    let original =
        Plan::parse(&read(&directory.join("fork_repair.json"))?).map_err(anyhow::Error::msg)?;
    let mut backend = Backend::open(options, &directory)?;
    let selected = backend
        .read_plan()
        .map_err(anyhow::Error::msg)?
        .context("staged native repair is missing")?;
    ensure!(
        selected == original,
        "native repair plan changed before ownership"
    );
    backend.request(&json!({"op":"preflight"}))?;
    let store = backend
        .request(&json!({"op":"store"}))?
        .as_i64()
        .context("store resume is idle")?;
    ensure!(
        store == selected.head.epoch_id,
        "store resumed a different target"
    );
    let chain = backend
        .request(&json!({"op":"chain"}))?
        .as_i64()
        .context("chain resume is idle")?;
    ensure!(chain == store, "chaindata resumed a different target");
    backend.request(&json!({"op":"verify"}))?;
    let outcome = fork_repair::finish(&mut backend).map_err(anyhow::Error::msg)?;
    let Finish::Resumed {
        target,
        head,
        dropped,
    } = outcome
    else {
        bail!("finality resume is idle")
    };
    ensure!(
        target == store && head == store,
        "finality resumed a different target"
    );
    let actual = backend
        .head()
        .map_err(anyhow::Error::msg)?
        .context("repaired HEAD is missing")?;
    ensure!(
        actual == selected.head,
        "repaired HEAD differs from staged target"
    );
    backend.close()?;
    ensure!(
        !directory.join("fork_repair.json").try_exists()?,
        "repair marker was not retired"
    );
    Ok(
        json!({"format":"octra-legacy-repair-resume-v1","upstream":UPSTREAM,"target":target,"head":head,"dropped_finality":dropped,"store":store,"chaindata":chain,"backend_sha256":options.backend_sha256,"automatic_selection":false,"all_rust_physical_backend":false}),
    )
}
struct Entry {
    value: Value,
    root: Vec<u8>,
    txid_hi: i64,
}
struct Backend {
    session: process::Session,
}
impl Backend {
    fn open(options: &Options, directory: &Path) -> Result<Self> {
        let session = process::Session::open(
            &options.backend,
            &options.backend_sha256,
            directory,
            &options.chain_id,
        )?;
        let mut backend = Self { session };
        let greeting = backend.session.receive()?;
        ensure!(
            greeting["protocol"] == "octra-legacy-repair-v1"
                && greeting["upstream"] == UPSTREAM
                && greeting["chain_id"] == options.chain_id,
            "native backend identity differs"
        );
        Ok(backend)
    }
    fn request(&mut self, value: &Value) -> Result<Value> {
        self.session.request(value)
    }
    fn close(&mut self) -> Result<()> {
        self.session.close()
    }
}
fn native<T>(result: Result<T>) -> fork_repair::Result<T> {
    result.map_err(|error| error.to_string().into())
}
impl Finality for Backend {
    type Entry = Entry;
    fn read_plan(&mut self) -> fork_repair::Result<Option<Plan>> {
        native((|| {
            let value = self.request(&json!({"op":"read_plan"}))?;
            Ok(Some(
                Plan::parse(
                    &STANDARD.decode(value.as_str().context("native plan is not base64 text")?)?,
                )
                .map_err(anyhow::Error::msg)?,
            ))
        })())
    }
    fn head(&mut self) -> fork_repair::Result<Option<Head>> {
        native((|| {
            let value = self.request(&json!({"op":"head"}))?;
            Ok(Some(
                fork_repair::parse_head(
                    &STANDARD.decode(value.as_str().context("native HEAD is not base64 text")?)?,
                )
                .map_err(anyhow::Error::msg)?,
            ))
        })())
    }
    fn finality_at(&mut self, epoch: i64) -> fork_repair::Result<Option<Entry>> {
        native((|| {
            let value = self.request(&json!({"op":"finality","epoch":epoch}))?;
            if value.is_null() {
                return Ok(None);
            }
            let root = STANDARD.decode(
                value["root"]
                    .as_str()
                    .context("native finality root missing")?,
            )?;
            let txid_hi = value["txid_hi"]
                .as_str()
                .context("native finality txid missing")?
                .parse()?;
            let value = Value::String(
                value["wire"]
                    .as_str()
                    .context("native finality record missing")?
                    .to_owned(),
            );
            Ok(Some(Entry {
                value,
                root,
                txid_hi,
            }))
        })())
    }
    fn entry_root<'a>(&self, entry: &'a Entry) -> &'a [u8] {
        &entry.root
    }
    fn entry_txid_hi(&self, entry: &Entry) -> i64 {
        entry.txid_hi
    }
    fn journal_committed(&mut self) -> fork_repair::Result<bool> {
        native(
            self.request(&json!({"op":"journal_committed"}))
                .and_then(|value| value.as_bool().context("native journal flag missing")),
        )
    }
    fn committed_for(&mut self, entry: &Entry) -> fork_repair::Result<()> {
        native(
            self.request(&json!({"op":"committed_for","entry":entry.value}))
                .map(|_| ()),
        )
    }
    fn rewind_journal(&mut self, entry: &Entry) -> fork_repair::Result<()> {
        native(
            self.request(&json!({"op":"rewind_journal","entry":entry.value}))
                .map(|_| ()),
        )
    }
    fn drop_after(&mut self, target: i64) -> fork_repair::Result<i64> {
        native(
            self.request(&json!({"op":"drop_after","target":target}))
                .and_then(|value| {
                    value
                        .as_i64()
                        .context("native finality trim result missing")
                }),
        )
    }
    fn clear(&mut self) -> fork_repair::Result<()> {
        native(self.request(&json!({"op":"clear"})).map(|_| ()))
    }
}

#[cfg(test)]
mod tests;
