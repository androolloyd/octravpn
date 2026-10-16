//! One-process VPN service. The consensus host supplies committed admission;
//! this service owns sockets and durable receipt files, not validator state.
use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use octravpn_core::{
    bounded::BoundedMap, receipt::ReceiptContext, receipt_journal::ReceiptJournal,
    receipt_vault::ReceiptVault, sig::KeyPair,
};
use tokio::{net::TcpListener, sync::watch};
use x25519_dalek::StaticSecret;

use crate::{
    admission::SessionAuthority,
    control::{ControlState, NodeMetrics},
    onion::OnionRouter,
    tunnel::{Server, ADMISSION_LEASE},
};

pub use crate::tunnel::ip::Config as IpTunnelConfig;

/// Successful completion means the ordinary operator claim is included in
/// canonical application state. Queue acceptance is insufficient.
#[async_trait::async_trait]
pub trait ReceiptSettlement: Send + Sync {
    /// Authorize receipt handback when the original funded session no longer
    /// admits traffic. Implementations must verify the opening against
    /// authenticated canonical history, even if a claim record is already
    /// saved. The default refuses this privileged retry path.
    async fn authorize_retry(
        &self,
        _receipt: &octravpn_core::receipt::SignedReceipt,
        _announcement: &octravpn_core::control::AnnounceSessionRequest,
    ) -> Result<()> {
        anyhow::bail!("receipt retry opening verification unavailable")
    }

    async fn confirm(
        &self,
        receipt: octravpn_core::receipt::SignedReceipt,
        announcement: octravpn_core::control::AnnounceSessionRequest,
    ) -> Result<()>;
}

/// Add the exact supported wire transport to the canonical policy before
/// publication. Native embedded service currently uses `Wireguard`.
pub fn advertise_transport(
    mut policy: octravpn_core::v3_policy::OperatorPolicy,
    transport: octravpn_tun::amnezia::WireTransport,
) -> Result<octravpn_core::v3_policy::OperatorPolicy> {
    transport
        .config()
        .map_err(|error| anyhow::anyhow!("invalid advertised transport: {error}"))?;
    policy
        .unknown
        .insert("transport".into(), serde_json::to_value(transport)?);
    Ok(policy)
}

pub struct Config {
    pub control_listen: SocketAddr,
    pub tunnel_listen: SocketAddr,
    pub data_dir: PathBuf,
    pub receipt_key: Arc<KeyPair>,
    pub wireguard_secret: StaticSecret,
    pub receipt_context: ReceiptContext,
}

pub struct EmbeddedVpn {
    control: TcpListener,
    state: Arc<ControlState>,
    tunnel: Arc<Server>,
    // Keep the exclusive writer lock until every receipt handle is dropped.
    _lock: Arc<std::fs::File>,
}

impl EmbeddedVpn {
    pub fn with_settlement(mut self, publisher: Arc<dyn ReceiptSettlement>) -> Self {
        Arc::make_mut(&mut self.state).receipt_settlement = Some(publisher);
        self
    }
    /// Bind both services before returning. Admission starts empty on every
    /// restart; the authority must finish canonical replay before granting it.
    pub async fn bind(config: Config, authority: Arc<dyn SessionAuthority>) -> Result<Self> {
        Self::bind_with_ip_tunnel(config, authority, None).await
    }

    pub async fn bind_with_ip_tunnel(
        config: Config,
        authority: Arc<dyn SessionAuthority>,
        ip_tunnel: Option<IpTunnelConfig>,
    ) -> Result<Self> {
        let ip_tunnel = ip_tunnel.map(|tunnel| tunnel.with_directory(&config.data_dir));
        let directory = config.data_dir.clone();
        let identity = Identity {
            version: 1,
            receipt_key: config.receipt_key.public,
            wireguard_key: x25519_dalek::PublicKey::from(&config.wireguard_secret).to_bytes(),
            context: config.receipt_context.clone(),
        };
        let (lock, journal, totals, vault) = tokio::task::spawn_blocking(move || -> Result<_> {
            std::fs::create_dir_all(&directory)?;
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true).create(true).truncate(false);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let lock = options.open(directory.join("vpn.lock"))?;
            #[cfg(unix)]
            rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
                .context("VPN receipt directory already in use")?;
            #[cfg(not(unix))]
            anyhow::bail!("embedded VPN writer locking requires a supported Unix host");
            check_identity(&directory, &identity)?;
            let lock = Arc::new(lock);
            let journal = Arc::new(ReceiptJournal::open(
                directory.join("receipt-sequence.bin"),
            )?);
            journal.set_fsync_policy(octravpn_core::receipt_journal::FsyncPolicy::EveryWrite);
            let totals = Arc::new(ReceiptJournal::open(directory.join("receipt-bytes.bin"))?);
            totals.set_fsync_policy(octravpn_core::receipt_journal::FsyncPolicy::EveryWrite);
            let vault = Arc::new(ReceiptVault::open(directory.join("receipt-vault.bin"))?);
            journal.retain_writer_guard(lock.clone());
            totals.retain_writer_guard(lock.clone());
            vault.retain_writer_guard(lock.clone());
            Ok((lock, journal, totals, vault))
        })
        .await??;
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(
            crate::control::state::CONTROL_SESSIONS_CAP,
            ADMISSION_LEASE,
        ));
        let metrics = Arc::new(NodeMetrics::default());
        metrics.started_at_unix.store(
            octravpn_core::util::now_unix_secs(),
            std::sync::atomic::Ordering::Relaxed,
        );
        let mut state = ControlState::with_metrics(
            config.receipt_key,
            router.clone(),
            allowlist.clone(),
            metrics.clone(),
            Arc::new(config.receipt_context),
            journal,
        )
        .with_receipt_totals(totals)
        .with_receipt_vault(vault);
        state.native_authority = Some(authority);
        state.writer_guard = Some(lock.clone());
        let tunnel = Arc::new(
            Server::bind(
                config.tunnel_listen,
                config.wireguard_secret,
                router,
                allowlist,
            )
            .await?
            .with_ip_tunnel(ip_tunnel)
            .await?
            .with_metrics(metrics),
        );
        let control = TcpListener::bind(config.control_listen).await?;
        Ok(Self {
            control,
            state: Arc::new(state),
            tunnel,
            _lock: lock,
        })
    }

    pub fn control_addr(&self) -> Result<SocketAddr> {
        Ok(self.control.local_addr()?)
    }
    pub fn tunnel_addr(&self) -> SocketAddr {
        self.tunnel.local_addr()
    }

    /// Stop packet processing immediately and drain HTTP requests. If cancelled
    /// during a write, receipt handles retain the writer lock until they finish.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let Self {
            control,
            state,
            tunnel,
            _lock,
        } = self;
        let (stop, mut stopped) = watch::channel(false);
        let guard = StopGuard {
            signal: stop,
            revocation: state.native_stop.clone(),
        };
        let mut server = Box::pin(std::future::IntoFuture::into_future(
            axum::serve(
                control,
                state
                    .clone()
                    .router_axum()
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                let _ = stopped.wait_for(|value| *value).await;
            }),
        ));
        let mut tunnel = Box::pin(tunnel.run());
        let mut sweeper = Box::pin(crate::control::run_sweeper(state));
        let mut control_finished = false;
        let result = tokio::select! {
            result = &mut server => { control_finished = true; result.context("VPN control server") },
            result = &mut tunnel => result.context("VPN tunnel server"),
            () = &mut sweeper => anyhow::bail!("VPN sweeper stopped"),
            () = async {
                while !*shutdown.borrow_and_update() {
                    if shutdown.changed().await.is_err() { break; }
                }
            } => Ok(()),
        };
        guard.stop();
        drop(tunnel);
        drop(sweeper);
        if !control_finished {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), &mut server).await;
        }
        result
    }
}

struct StopGuard {
    signal: watch::Sender<bool>,
    revocation: crate::admission::Revocation,
}
impl StopGuard {
    fn stop(&self) {
        self.revocation.revoke();
        self.signal.send_replace(true);
    }
}
impl Drop for StopGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    version: u32,
    receipt_key: octravpn_core::sig::PublicKey,
    wireguard_key: [u8; 32],
    context: ReceiptContext,
}

fn check_identity(directory: &std::path::Path, expected: &Identity) -> Result<()> {
    let path = directory.join("vpn-identity.json");
    if path.exists() {
        let stored: Identity = serde_json::from_slice(&std::fs::read(&path)?)?;
        anyhow::ensure!(
            &stored == expected,
            "VPN receipt directory identity differs"
        );
        return Ok(());
    }
    for name in [
        "receipt-sequence.bin",
        "receipt-bytes.bin",
        "receipt-vault.bin",
    ] {
        anyhow::ensure!(
            !directory.join(name).exists(),
            "cannot adopt an unbound VPN receipt directory"
        );
    }
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    serde_json::to_writer(temporary.as_file_mut(), expected)?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(path)?;
    std::fs::File::open(directory)?.sync_all()?;
    Ok(())
}
