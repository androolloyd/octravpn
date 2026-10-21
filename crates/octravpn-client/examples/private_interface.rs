//! One explicitly funded private interface for SDK qualification. Routing and
//! financial consent belong to the embedding host. This never buys traffic.
use anyhow::{ensure, Context, Result};
use clap::Parser;
use octravpn_client::{
    AcceptedPrivatePlan, JournalMode, PrivatePaymentClient, PrivatePaymentOptions,
};
use octravpn_core::KeyPair;
use std::{
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

#[derive(Parser)]
struct Options {
    #[arg(long)]
    plan: PathBuf,
    #[arg(long)]
    receipt_key: PathBuf,
    #[arg(long)]
    journal: PathBuf,
    #[arg(long)]
    ready: PathBuf,
    #[arg(long)]
    result: PathBuf,
    #[arg(long)]
    resume: bool,
    #[arg(long, default_value = "octraprobe")]
    interface: String,
}
#[expect(
    clippy::verbose_bit_mask,
    reason = "Explicit private POSIX permission mask"
)]
fn read(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let file: std::fs::File = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?
    .into();
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.permissions().mode() & 0o077 == 0
            && meta.len() <= maximum,
        "expected bounded private regular input with one link"
    );
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(
        u64::try_from(bytes.len())? <= maximum,
        "private input grew past bound"
    );
    Ok(bytes)
}
fn save(path: &Path, value: &serde_json::Value) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&serde_json::to_vec(value)?)?;
    file.sync_all()?;
    std::fs::File::open(path.parent().context("output parent missing")?)?.sync_all()?;
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    let options = Options::parse();
    ensure!(
        !options.ready.exists() && !options.result.exists(),
        "retain previous observations; use new output paths"
    );
    let plan: AcceptedPrivatePlan = serde_json::from_slice(&read(&options.plan, 131_072)?)?;
    let key = Zeroizing::new(read(&options.receipt_key, 32)?);
    let key = KeyPair::from_secret_bytes(key.as_slice().try_into()?);
    let client = PrivatePaymentClient::open(PrivatePaymentOptions {
        plan,
        journal: options.journal,
        receipt_key: Arc::new(key),
        interface_name: options.interface,
        mode: if options.resume {
            JournalMode::Resume
        } else {
            JournalMode::Create
        },
    })
    .await?;
    let interface = client.interface();
    save(
        &options.ready,
        &serde_json::json!({"interface":interface.name,"address":interface.address.to_string(),"mtu":interface.mtu,"purchases_submitted":0}),
    )?;
    let summary = Box::pin(client.run(async {
        tokio::signal::ctrl_c().await?;
        Ok(())
    }))
    .await?;
    save(
        &options.result,
        &serde_json::json!({"confirmed_bytes":summary.confirmed_bytes,"held_bytes":summary.held_bytes,"authorized_bytes":summary.authorized_bytes,"purchases_submitted":0}),
    )
}
