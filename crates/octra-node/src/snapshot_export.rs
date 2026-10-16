//! Automatic native snapshot publication. Scheduling and leases are local
//! operations; only independently trusted finality can authorize an export.
mod archive;
mod chain;
use crate::{
    bootstrap::{self, export::package},
    Host, Node,
};
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use octra_node_protocol::{
    consensus::profile::Settings,
    state_sync::{cycle, manifest},
};
use octra_node_runtime::ledger_image::Limits;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;

/// Explicit local resource bounds. Raising these does not change admissible
/// state, exporter selection, checkpoint trust or consensus rules.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    pub max_bytes: u64,
    pub max_records: u64,
    pub max_string_bytes: u64,
}
impl Default for LimitsConfig {
    fn default() -> Self {
        let value = Limits::default();
        Self {
            max_bytes: value.bytes,
            max_records: value.records,
            max_string_bytes: value.string_bytes,
        }
    }
}
#[derive(Clone)]
pub(crate) struct Config {
    network: bootstrap::Network,
    source: PathBuf,
    root: PathBuf,
    certificate: PathBuf,
    force: bool,
    limits: Limits,
}
impl Config {
    pub(crate) fn capture(
        network: bootstrap::Network,
        source: PathBuf,
        settings: &Settings,
        publisher: bool,
        limits: LimitsConfig,
    ) -> Result<Self> {
        bootstrap::Authority::new(network.clone())?;
        let forced_env = cycle::publisher_override(settings.get("OCTRA_STATE_SYNC_FORCE_PUBLISH"))?;
        let force = publisher || forced_env;
        let path = |name: &str, default: PathBuf, trim: bool| {
            let raw = settings
                .get(name)
                .filter(|raw| !raw.trim_ascii().is_empty());
            raw.map_or(default, |raw| {
                os_path(if trim { raw.trim_ascii() } else { raw })
            })
        };
        let certificate = path(
            "OCTRA_STATE_SYNC_CERT",
            source.join("state_sync/certificate.json"),
            true,
        );
        let root = path(
            "OCTRA_STATE_SYNC_SNAPSHOT_DIR",
            source.join("state_sync_snapshots"),
            false,
        );
        let absolute = |path: PathBuf| -> Result<PathBuf> {
            Ok(if path.is_absolute() {
                path
            } else {
                std::env::current_dir()?.join(path)
            })
        };
        let certificate = absolute(certificate)?;
        let root = absolute(root)?;
        let name = certificate
            .file_name()
            .and_then(|name| name.to_str())
            .context("snapshot certificate name is not UTF-8")?;
        ensure!(
            name != ".archive.lock"
                && name != ".octra-owner.json"
                && !name.starts_with(".remove-")
                && !name.starts_with(".publish-"),
            "snapshot certificate uses a reserved archive name"
        );
        ensure!(
            limits.max_bytes > 0 && limits.max_records > 0 && limits.max_string_bytes > 0,
            "snapshot export limits must be positive"
        );
        Ok(Self {
            network,
            source,
            root,
            certificate,
            force,
            limits: Limits {
                bytes: limits.max_bytes,
                records: limits.max_records,
                string_bytes: limits.max_string_bytes,
            },
        })
    }
    fn role(&self, key: &SigningKey) -> Result<()> {
        let authority = bootstrap::Authority::new(self.network.clone())?;
        let public = STANDARD.encode(key.verifying_key().as_bytes());
        let address = octra_node_protocol::transaction::address_from_public_key(public.as_bytes());
        cycle::exporter_wallet(
            self.force,
            authority.trust().exporters,
            &address,
            public.as_bytes(),
        )?;
        Ok(())
    }
}
fn os_path(raw: &[u8]) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        PathBuf::from(std::ffi::OsStr::from_bytes(raw))
    }
    #[cfg(not(unix))]
    PathBuf::from(String::from_utf8_lossy(raw).as_ref())
}
fn now() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?)
}
fn read_optional(path: &Path, limit: usize) -> Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
        Ok(_) => Ok(Some(bootstrap::read_limited(path, limit)?)),
    }
}
struct Cancel(Arc<AtomicBool>);
impl Drop for Cancel {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
fn active<A: Host>(node: &Node<A>, cancel: &AtomicBool) -> Result<()> {
    ensure!(
        !cancel.load(Ordering::Acquire),
        "snapshot publisher stopped"
    );
    node.snapshot()
        .context("snapshot publication suspended during recovery")?;
    Ok(())
}
async fn capture<A: Host>(
    node: Arc<Node<A>>,
    config: Config,
    archive: Arc<archive::Archive>,
    key: SigningKey,
    target: i64,
    cancel: Arc<AtomicBool>,
) -> Result<i64> {
    active(&node, &cancel)?;
    config.role(&key)?;
    let latest = i64::try_from(node.head().await?.cursor.epoch.0)?;
    let candidates = if latest > target {
        vec![latest, target]
    } else {
        vec![target]
    };
    let authority = bootstrap::Authority::new(config.network.clone())?;
    let mut last = None;
    let mut captured = None;
    for epoch in candidates {
        let prepared = async {
            let head = node
                .store
                .reader()
                .head_for_epoch(u64::try_from(epoch)?)
                .await?;
            let anchor = chain::build(&node, &config, &head).await?;
            package::capture(&authority, &node.store, &config.source, head, anchor).await
        }
        .await;
        match prepared {
            Ok(value) => {
                captured = Some(value);
                break;
            }
            Err(error) => last = Some(error),
        }
    }
    let captured = captured.with_context(|| {
        format!(
            "state sync capture unavailable: {}",
            last.map_or_else(|| "no retained head".into(), |error| error.to_string())
        )
    })?;
    active(&node, &cancel)?;
    let id = captured.snapshot_id()?;
    let owned = archive.clone();
    let image = config.clone();
    let signature = key.clone();
    let publication = tokio::task::spawn_blocking(move || {
        let stage = owned.stage(&id)?;
        let report = package::prepare_capture(
            &image.source,
            &stage,
            captured,
            16 * 1024 * 1024,
            image.limits,
        )?;
        let raw = package::sign_capture(
            &bootstrap::Authority::new(image.network.clone())?,
            &stage,
            &signature,
            image.limits,
        )?;
        owned.complete(&id, &raw)?;
        Ok::<_, anyhow::Error>((id, raw, report.epoch))
    })
    .await??;
    active(&node, &cancel)?;
    config.role(&key)?;
    let (id, raw, epoch) = publication;
    // The owned physical worker retains both the archive lease and cancellation
    // flag even if the awaiting service is aborted while fsync is running.
    tokio::task::spawn_blocking(move || {
        active(&node, &cancel)?;
        config.role(&key)?;
        archive.publish(&config, &id, &raw)?;
        Ok::<_, anyhow::Error>(epoch)
    })
    .await?
}

fn load_published(archive: &archive::Archive, config: &Config) -> Result<Option<i64>> {
    match archive.load(config) {
        Ok(published) => Ok(published),
        Err(error) => {
            // A failed old payload is a cache miss, never new trust. An invalid
            // or foreign live pointer must still refuse automatic replacement.
            if let Some(raw) = archive.current()? {
                bootstrap::Authority::new(config.network.clone())?
                    .trust()
                    .verify_persisted(&raw)?;
            }
            eprintln!("state sync previous package unavailable: {error}");
            Ok(None)
        }
    }
}
pub(crate) async fn run<A: Host>(
    node: Arc<Node<A>>,
    config: Config,
    key: SigningKey,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    let cancelled = Arc::new(AtomicBool::new(false));
    let _cancel = Cancel(cancelled.clone());
    let mut archive = None;
    let mut state = cycle::Cycle::new(None);
    loop {
        if *stop.borrow() {
            return Ok(());
        }
        let delay = if let Err(error) = config.role(&key) {
            eprintln!("state sync publisher dormant: {error}");
            Duration::from_secs(cycle::ROLE_RETRY_SECONDS)
        } else {
            if archive.is_none() {
                let captured = config.clone();
                let opened = tokio::task::spawn_blocking(move || {
                    let archive = archive::Archive::open(&captured)?;
                    let published = load_published(&archive, &captured)?;
                    Ok::<_, anyhow::Error>((Arc::new(archive), published))
                })
                .await?;
                match opened {
                    Ok((opened, published)) => {
                        archive = Some(opened);
                        state = cycle::Cycle::new(published);
                    }
                    Err(error) => eprintln!("state sync archive unavailable: {error}"),
                }
            }
            if let Some(archive) = &archive {
                if let Err(error) = tick(
                    node.clone(),
                    &config,
                    archive.clone(),
                    &key,
                    &mut state,
                    cancelled.clone(),
                )
                .await
                {
                    eprintln!("state sync cycle failed: {error}");
                }
            }
            Duration::from_secs(cycle::POLL_SECONDS)
        };
        tokio::select! {_=stop.wait_for(|value|*value)=>return Ok(()),()=tokio::time::sleep(delay)=>()}
    }
}
async fn tick<A: Host>(
    node: Arc<Node<A>>,
    config: &Config,
    archive: Arc<archive::Archive>,
    key: &SigningKey,
    state: &mut cycle::Cycle,
    cancel: Arc<AtomicBool>,
) -> Result<()> {
    active(&node, &cancel)?;
    let epoch = i64::try_from(node.head().await?.cursor.epoch.0)?;
    let minimum =
        octra_node_protocol::rules::profile_epochs(config.network.identity.chain_id.as_bytes())
            .into_iter()
            .filter(|activation| *activation <= epoch)
            .max()
            .unwrap_or(0);
    let event = if minimum == 0 {
        cycle::Event::Finalized(epoch)
    } else {
        cycle::Event::FinalizedAfter { epoch, minimum }
    };
    let (next, effects) = state.step(cycle::Policy::default(), event)?;
    *state = next;
    for effect in effects {
        if let cycle::Effect::Capture(target) = effect {
            let outcome = match capture(
                node.clone(),
                config.clone(),
                archive.clone(),
                key.clone(),
                target,
                cancel.clone(),
            )
            .await
            {
                Ok(published) => {
                    eprintln!("state sync capture complete: target={target} epoch={published}");
                    cycle::Outcome::Published(published)
                }
                Err(error) => {
                    eprintln!("state sync capture failed: target={target} reason={error}");
                    cycle::Outcome::Failed
                }
            };
            let (next, completed) = state.step(
                cycle::Policy::default(),
                cycle::Event::Completed {
                    epoch: target,
                    outcome,
                },
            )?;
            *state = next;
            for effect in completed {
                if let cycle::Effect::Retain(retain) = effect {
                    let config = config.clone();
                    let archive = archive.clone();
                    let errors =
                        tokio::task::spawn_blocking(move || archive.retain(&config, retain))
                            .await??;
                    for error in errors {
                        eprintln!("state sync retention failed: {error}");
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
