use super::{Authority, Connection, Registry, Settlement};
use crate::{
    embedded::IpTunnelConfig,
    onion::OnionRouter,
    tunnel::{Server, ADMISSION_LEASE},
};
use anyhow::{ensure, Context, Result};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use octravpn_core::{
    bounded::BoundedMap,
    payments::{SignedConnect, SignedStatus, SignedUsage, Status},
    KeyPair,
};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    net::TcpListener,
    sync::{watch, Semaphore},
};
use x25519_dalek::{PublicKey, StaticSecret};

pub struct Config {
    pub control_listen: SocketAddr,
    pub tunnel_listen: SocketAddr,
    pub data_dir: PathBuf,
    /// Actual offer payee key, not the legacy derived receipt identity.
    pub operator_key: Arc<KeyPair>,
    pub wireguard_secret: StaticSecret,
    pub ip_tunnel: IpTunnelConfig,
    /// Explicit operator risk between payer acknowledgements. This is a
    /// bounded postpaid window, not a proof of delivery or guaranteed payment.
    pub credit: crate::payment_meter::Credit,
}

struct Control {
    registry: Arc<Registry>,
    settlement: Arc<dyn Settlement>,
    operator: Arc<KeyPair>,
    wireguard: [u8; 32],
    slots: Arc<Semaphore>,
}

pub struct Service {
    listener: TcpListener,
    control: Arc<Control>,
    tunnel: Arc<Server>,
}
impl Service {
    pub async fn bind(
        config: Config,
        authority: Arc<dyn Authority>,
        settlement: Arc<dyn Settlement>,
    ) -> Result<Self> {
        ensure!(
            config.credit.max_unacknowledged_bytes < u64::MAX
                && config.credit.max_unacknowledged_ou < u64::MAX,
            "production payment service requires explicit bounded postpaid credit"
        );
        let wireguard = PublicKey::from(&config.wireguard_secret).to_bytes();
        let identity =
            serde_json::to_vec(&(1_u8, config.operator_key.public, wireguard, config.credit))?;
        let root = config.data_dir.clone();
        let writer =
            tokio::task::spawn_blocking(move || open_directory(&root, &identity)).await??;
        let registry = Arc::new(Registry::new(
            config.data_dir.clone(),
            authority,
            Arc::new(writer),
            config.credit,
        ));
        // Payment mode has no legacy announcement, UDP-proxy, receipt or mesh
        // admission routes. The shared transport selects only this registry.
        let tunnel = Server::bind(
            config.tunnel_listen,
            config.wireguard_secret,
            Arc::new(OnionRouter::new()),
            Arc::new(BoundedMap::new(1, ADMISSION_LEASE)),
        )
        .await?
        .with_payments(registry.clone())
        .with_ip_tunnel(Some(config.ip_tunnel.with_directory(&config.data_dir)))
        .await?;
        let listener = TcpListener::bind(config.control_listen).await?;
        Ok(Self {
            listener,
            tunnel: Arc::new(tunnel),
            control: Arc::new(Control {
                registry,
                settlement,
                operator: config.operator_key,
                wireguard,
                slots: Arc::new(Semaphore::new(32)),
            }),
        })
    }
    pub fn control_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }
    pub fn tunnel_addr(&self) -> SocketAddr {
        self.tunnel.local_addr()
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let registry = self.control.registry.clone();
        let stop_guard = Stop(registry.clone());
        let app = router(self.control);
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move {
            axum::serve(self.listener, app)
                .await
                .map_err(anyhow::Error::from)
        });
        tasks.spawn(async move { self.tunnel.run().await });
        let mut updates = registry.authority.updates();
        tasks.spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                tokio::select! {
                    _ = interval.tick() => {},
                    () = async { if let Some(updates) = &mut updates {
                        if updates.changed().await.is_err() { std::future::pending::<()>().await; }
                    } else { std::future::pending::<()>().await; } } => {},
                }
                registry.refresh().await;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        });
        let outcome = tokio::select! {
            () = async { while !*shutdown.borrow_and_update() && shutdown.changed().await.is_ok() {} } => Ok(()),
            stopped = tasks.join_next() => match stopped {
                Some(Ok(Err(error))) => Err(error),
                Some(Err(error)) => Err(error.into()),
                _ => Err(anyhow::anyhow!("paid VPN worker stopped unexpectedly")),
            }
        };
        stop_guard.0.stop.revoke();
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        outcome
    }
}
struct Stop(Arc<Registry>);
impl Drop for Stop {
    fn drop(&mut self) {
        self.0.stop.revoke();
    }
}

fn router(control: Arc<Control>) -> Router {
    Router::new()
        .route("/payments/connect", post(connect))
        .route("/payments/status", post(connect))
        .route("/payments/usage", post(usage))
        .layer(DefaultBodyLimit::max(131_072))
        .with_state(control)
}

type HttpError = (StatusCode, &'static str);
async fn connect(
    State(state): State<Arc<Control>>,
    Json(request): Json<SignedConnect>,
) -> std::result::Result<Json<SignedStatus>, HttpError> {
    let _slot = state
        .slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| (StatusCode::TOO_MANY_REQUESTS, "control capacity exhausted"))?;
    let result = async {
        let connection = state.registry.connect(request).await?;
        status(&state, &connection)
    }
    .await;
    result.map(Json).map_err(|error| {
        tracing::debug!(%error, "paid connection refused");
        (StatusCode::FORBIDDEN, "paid connection unavailable")
    })
}
fn status(control: &Control, connection: &Connection) -> Result<SignedStatus> {
    let grant = connection.grant.read();
    let grant = grant.as_ref().context("paid plan suspended")?;
    ensure!(
        !connection.stop.is_revoked() && grant.admissible && grant.guard.live(),
        "paid plan revoked"
    );
    let snapshot = connection.meter.snapshot()?;
    SignedStatus::sign(
        Status {
            binding: grant.binding.clone(),
            connect_sequence: connection.request.request.sequence,
            client_wireguard_key: connection.request.request.wireguard_key,
            server_wireguard_key: control.wireguard,
            tariff: grant.tariff.clone(),
            original_budget_ou: grant.original_budget_ou,
            remaining_ou: grant.remaining_ou,
            committed_totals: snapshot.committed_totals,
            redeemed_totals: grant.redeemed_totals.clone(),
            canonical_ms: grant.canonical_ms,
            claim_deadline_ms: grant.claim_deadline_ms.unwrap_or(u64::MAX),
        },
        &control.operator,
    )
    .map_err(Into::into)
}
async fn usage(
    State(state): State<Arc<Control>>,
    Json(usage): Json<SignedUsage>,
) -> std::result::Result<Json<serde_json::Value>, HttpError> {
    let _slot = state
        .slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| (StatusCode::TOO_MANY_REQUESTS, "control capacity exhausted"))?;
    let result = async {
        let meter = state.registry.usage(&usage).await?;
        state.settlement.confirm(usage.clone()).await?;
        // Credit resumes only after its cumulative charge is canonically paid.
        // Same-charge rounding/free-class acknowledgements are durable locally;
        // they cannot authorize a larger economic claim by themselves.
        meter.accept_usage(usage).await
    }
    .await;
    result
        .map(|()| Json(serde_json::json!({"canonical":true})))
        .map_err(|error| {
            tracing::debug!(%error, "paid settlement refused");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "canonical settlement unavailable",
            )
        })
}

#[cfg(not(unix))]
fn open_directory(_: &Path, _: &[u8]) -> Result<std::fs::File> {
    anyhow::bail!("paid VPN directory locking requires Unix")
}
#[cfg(unix)]
#[expect(
    clippy::verbose_bit_mask,
    reason = "Explicit private POSIX permission mask."
)]
fn open_directory(path: &Path, identity: &[u8]) -> Result<std::fs::File> {
    use rustix::fs::{flock, open, openat, FlockOperation, Mode, OFlags};
    use std::{
        fs::{DirBuilder, File},
        io::{Read, Write},
        os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    };
    let fresh = match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error.into()),
    };
    let directory: File = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?
    .into();
    let owner = directory.metadata()?;
    ensure!(
        owner.permissions().mode() & 0o077 == 0,
        "paid VPN directory must be private"
    );
    let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let writer: File = openat(
        &directory,
        "payments.lock",
        flags
            | if fresh {
                OFlags::CREATE | OFlags::EXCL
            } else {
                OFlags::empty()
            },
        Mode::from_bits_truncate(0o600),
    )?
    .into();
    let meta = writer.metadata()?;
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.uid() == owner.uid()
            && meta.permissions().mode() & 0o077 == 0,
        "paid VPN writer lease must be private and regular"
    );
    flock(&writer, FlockOperation::NonBlockingLockExclusive)
        .context("paid VPN directory already in use")?;
    let mut file: File = openat(
        &directory,
        "payments-identity.json",
        flags
            | if fresh {
                OFlags::CREATE | OFlags::EXCL
            } else {
                OFlags::empty()
            },
        Mode::from_bits_truncate(0o600),
    )?
    .into();
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.uid() == owner.uid()
            && meta.permissions().mode() & 0o077 == 0
            && meta.len() <= 4096,
        "paid VPN identity must be private, regular and bounded"
    );
    if fresh {
        file.write_all(identity)?;
        file.sync_all()?;
        directory.sync_all()?;
    } else {
        let mut stored = Vec::new();
        file.take(4097).read_to_end(&mut stored)?;
        ensure!(stored == identity, "paid VPN directory identity differs");
    }
    Ok(writer)
}

#[cfg(all(test, unix))]
#[path = "tests.rs"]
mod tests;
