use super::{Authority, Connection, Funds, Mode, PrivatePurchases, Registry, Settlement};
use crate::{
    embedded::IpTunnelConfig,
    onion::OnionRouter,
    tunnel::{Server, ADMISSION_LEASE},
};
use anyhow::{ensure, Context, Result};
use axum::{
    extract::{DefaultBodyLimit, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use octravpn_core::{
    bounded::BoundedMap,
    payments::{
        ShieldedStatus, SignedConnect, SignedPrivateReply, SignedPrivateRequest,
        SignedShieldedStatus, SignedStatus, SignedUsage, Status,
    },
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
    /// An exit uses a TUN; a control/transport-only host may omit it. With no
    /// TUN there is no kernel internet forwarding path.
    pub ip_tunnel: Option<IpTunnelConfig>,
}

struct Control {
    registry: Arc<Registry>,
    settlement: Arc<dyn Settlement>,
    operator: Arc<KeyPair>,
    wireguard: [u8; 32],
    slots: Arc<Semaphore>,
    purchases: Option<Arc<dyn PrivatePurchases>>,
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
            authority.mode() == Mode::Public,
            "public service requires public channel accounting"
        );
        Self::bind_mode(config, authority, settlement, None).await
    }
    pub async fn bind_private(
        config: Config,
        authority: Arc<dyn Authority>,
        settlement: Arc<dyn Settlement>,
        meter_key: octravpn_core::sealed::Key,
    ) -> Result<Self> {
        ensure!(
            authority.mode() == Mode::Public,
            "encrypted public service requires channel accounting"
        );
        Self::bind_mode(config, authority, settlement, Some(meter_key)).await
    }
    /// Private HTTP is loopback-only behind the host's authenticated TLS
    /// transport. The public channel routes are absent from this service.
    pub async fn bind_shielded(
        config: Config,
        authority: Arc<dyn Authority>,
        settlement: Arc<dyn Settlement>,
        meter_key: octravpn_core::sealed::Key,
    ) -> Result<Self> {
        ensure!(
            authority.mode() == Mode::Shielded,
            "shielded service requires private accounting"
        );
        ensure!(
            config.control_listen.ip().is_loopback(),
            "private control requires loopback behind authenticated TLS"
        );
        Self::bind_mode(config, authority, settlement, Some(meter_key)).await
    }
    async fn bind_mode(
        config: Config,
        authority: Arc<dyn Authority>,
        settlement: Arc<dyn Settlement>,
        meter_key: Option<octravpn_core::sealed::Key>,
    ) -> Result<Self> {
        let wireguard = PublicKey::from(&config.wireguard_secret).to_bytes();
        let identity = serde_json::to_vec(&(2_u8, config.operator_key.public, wireguard))?;
        let root = config.data_dir.clone();
        let writer =
            tokio::task::spawn_blocking(move || open_directory(&root, &identity)).await??;
        let mut registry = Registry::new(config.data_dir.clone(), authority, Arc::new(writer));
        registry.meter_key = meter_key;
        let registry = Arc::new(registry);
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
        .with_ip_tunnel(
            config
                .ip_tunnel
                .map(|tunnel| tunnel.with_directory(&config.data_dir)),
        )
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
                purchases: None,
            }),
        })
    }
    /// Attach an explicitly configured stock exit before starting any workers.
    pub fn with_stock_exit(self, exit: Arc<crate::stock::Exit>) -> Result<Self> {
        self.control.registry.attach_stock(exit)?;
        Ok(self)
    }
    pub fn with_private_purchases(mut self, purchases: Arc<dyn PrivatePurchases>) -> Result<Self> {
        ensure!(
            self.control.registry.authority.mode() == Mode::Shielded,
            "private purchases require shielded service"
        );
        Arc::get_mut(&mut self.control)
            .context("payment service already shared")?
            .purchases = Some(purchases);
        Ok(self)
    }
    pub fn control_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }
    pub fn tunnel_addr(&self) -> SocketAddr {
        self.tunnel.local_addr()
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let registry = self.control.registry.clone();
        let (signal, stopped) = watch::channel(false);
        let mut tasks = tokio::task::JoinSet::new();
        let stop_guard = Stop {
            registry: registry.clone(),
            signal,
        };
        let app = router(self.control).layer(middleware::from_fn_with_state(
            stopped.clone(),
            bounded_control,
        ));
        tasks.spawn(async move {
            axum::serve(self.listener, app)
                .with_graceful_shutdown(stopping(stopped))
                .await
                .map_err(anyhow::Error::from)
        });
        let tunnel_addr = self.tunnel.local_addr();
        let mut workers = vec![tasks.spawn(async move { self.tunnel.run().await })];
        if let Some(exit) = registry.stock_exit() {
            workers.push(tasks.spawn(exit.run_relay(tunnel_addr)));
        }
        let mut updates = registry.authority.updates();
        workers.push(tasks.spawn(async move {
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
        }));
        let outcome = tokio::select! {
            () = async { while !*shutdown.borrow_and_update() && shutdown.changed().await.is_ok() {} } => Ok(()),
            stopped = tasks.join_next() => match stopped {
                Some(Ok(Err(error))) => Err(error),
                Some(Err(error)) => Err(error.into()),
                _ => Err(anyhow::anyhow!("paid VPN worker stopped unexpectedly")),
            }
        };
        stop_guard.stop();
        for worker in workers {
            worker.abort();
        }
        // Keep driving the HTTP acceptor while it closes idle connections and
        // cancels pending bodies/handlers. Aborting it first strands Router
        // clones (and their wallet/writer leases) in keep-alive tasks.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while tasks.join_next().await.is_some() {}
        })
        .await;
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        outcome
    }
}
struct Stop {
    registry: Arc<Registry>,
    signal: watch::Sender<bool>,
}
impl Stop {
    fn stop(&self) {
        self.registry.stop.revoke();
        self.signal.send_replace(true);
    }
}
impl Drop for Stop {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn stopping(mut stopped: watch::Receiver<bool>) {
    while !*stopped.borrow_and_update() && stopped.changed().await.is_ok() {}
}
async fn bounded_control(
    State(stopped): State<watch::Receiver<bool>>,
    request: Request,
    next: Next,
) -> Response {
    tokio::select! {
        biased;
        ()=stopping(stopped)=>(StatusCode::SERVICE_UNAVAILABLE,"payment service stopped").into_response(),
        response=tokio::time::timeout(std::time::Duration::from_secs(60),next.run(request))=>{
            response.unwrap_or_else(|_| (StatusCode::REQUEST_TIMEOUT,"payment control deadline exceeded").into_response())
        }
    }
}

fn router(control: Arc<Control>) -> Router {
    let app = if control.registry.authority.mode() == Mode::Shielded {
        Router::new()
            .route("/shielded/connect", post(shielded_connect))
            .route("/shielded/status", post(shielded_connect))
            .route("/shielded/stock/connect", post(shielded_stock_connect))
            .route("/shielded/usage", post(usage))
    } else {
        Router::new()
            .route("/payments/connect", post(connect))
            .route("/payments/status", post(connect))
            .route("/payments/stock/connect", post(stock_connect))
            .route("/payments/usage", post(usage))
    };
    let app = if control.purchases.is_some() {
        app.route("/shielded/purchase", post(private_purchase))
    } else {
        app
    };
    app.layer(DefaultBodyLimit::max(131_072))
        .with_state(control)
}

type HttpError = (StatusCode, &'static str);
async fn private_purchase(
    State(state): State<Arc<Control>>,
    Json(request): Json<SignedPrivateRequest>,
) -> std::result::Result<Json<SignedPrivateReply>, HttpError> {
    let _slot = state
        .slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| (StatusCode::TOO_MANY_REQUESTS, "control capacity exhausted"))?;
    async {
        request.verify()?;
        ensure!(
            request.request.target.operator == state.operator.public,
            "private operator differs"
        );
        let payload = state
            .purchases
            .as_ref()
            .context("private purchases unavailable")?
            .execute(request.clone(), &state.operator)
            .await?;
        SignedPrivateReply::sign(&request, &payload, &state.operator).map_err(anyhow::Error::from)
    }
    .await
    .map(Json)
    .map_err(|error: anyhow::Error| {
        // Request IDs, note locations and private invoices must not reach logs.
        private_error(&error, "private purchase unavailable")
    })
}
fn private_error(error: &anyhow::Error, message: &'static str) -> HttpError {
    let status = if error.is::<octravpn_core::payments::Unavailable>() {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::FORBIDDEN
    };
    (status, message)
}
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
        status(&state, &connection).await
    }
    .await;
    result.map(Json).map_err(|error| {
        tracing::debug!(%error, "paid connection refused");
        (StatusCode::FORBIDDEN, "paid connection unavailable")
    })
}
async fn stock_connect(
    State(state): State<Arc<Control>>,
    Json(request): Json<SignedConnect>,
) -> std::result::Result<Json<SignedStatus>, HttpError> {
    let _slot = state
        .slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| (StatusCode::TOO_MANY_REQUESTS, "control capacity exhausted"))?;
    async {
        let connection = state.registry.connect_mode(request, true).await?;
        status(&state, &connection).await
    }
    .await
    .map(Json)
    .map_err(|error: anyhow::Error| {
        tracing::debug!(%error,"stock paid connection refused");
        (StatusCode::FORBIDDEN, "stock paid connection unavailable")
    })
}
async fn status(control: &Control, connection: &Connection) -> Result<SignedStatus> {
    let meter = connection.meter.clone();
    let (sequence, snapshot) =
        tokio::task::spawn_blocking(move || meter.service_snapshot()).await??;
    let grant = connection.grant.read();
    let grant = grant.as_ref().context("paid plan suspended")?;
    ensure!(
        !connection.stop.is_revoked()
            && connection.stock_live()
            && connection
                .meter
                .transport_is_current(&connection.request, &connection.transport)
            && grant.admissible
            && grant.guard.live(),
        "paid plan revoked"
    );
    let Funds::Channel {
        original_budget_ou,
        remaining_ou,
        claim_deadline_ms,
    } = grant.funds
    else {
        anyhow::bail!("private funds cannot be presented as public channel OCT");
    };
    SignedStatus::sign_with_receipts(
        Status {
            binding: grant.binding.clone(),
            connect_sequence: connection.request.request.sequence,
            client_wireguard_key: connection.request.request.wireguard_key,
            server_wireguard_key: control.wireguard,
            tariff: grant.tariff.clone(),
            original_budget_ou,
            remaining_ou,
            committed_totals: snapshot.committed_totals,
            redeemed_totals: grant.redeemed_totals.clone(),
            canonical_ms: grant.canonical_ms,
            claim_deadline_ms: claim_deadline_ms.unwrap_or(u64::MAX),
        },
        &control.operator,
        grant.operator_generation,
        sequence,
    )
    .map_err(Into::into)
}
async fn shielded_connect(
    State(state): State<Arc<Control>>,
    Json(request): Json<SignedConnect>,
) -> std::result::Result<Json<SignedShieldedStatus>, HttpError> {
    shielded_connect_mode(state, request, false).await
}
async fn shielded_stock_connect(
    State(state): State<Arc<Control>>,
    Json(request): Json<SignedConnect>,
) -> std::result::Result<Json<SignedShieldedStatus>, HttpError> {
    shielded_connect_mode(state, request, true).await
}
async fn shielded_connect_mode(
    state: Arc<Control>,
    request: SignedConnect,
    stock: bool,
) -> std::result::Result<Json<SignedShieldedStatus>, HttpError> {
    let _slot = state
        .slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| (StatusCode::TOO_MANY_REQUESTS, "control capacity exhausted"))?;
    async {
        let connection = state.registry.connect_mode(request, stock).await?;
        let meter = connection.meter.clone();
        let (sequence, snapshot) =
            tokio::task::spawn_blocking(move || meter.service_snapshot()).await??;
        let grant = connection.grant.read();
        let grant = grant.as_ref().ok_or_else(|| {
            octravpn_core::payments::Unavailable::new("private payment suspended")
        })?;
        ensure!(
            !connection.stop.is_revoked()
                && connection.stock_live()
                && connection
                    .meter
                    .transport_is_current(&connection.request, &connection.transport)
                && grant.admissible,
            "private connection revoked"
        );
        if !grant.guard.live() {
            return Err(octravpn_core::payments::Unavailable::new(
                "private publication unavailable",
            )
            .into());
        }
        let Funds::Shielded {
            quote_ceiling_ou,
            paid_ou,
        } = grant.funds
        else {
            anyhow::bail!("public channel accounting cannot satisfy private status");
        };
        let held = snapshot
            .uncertain_totals
            .iter()
            .zip(&snapshot.pending_totals)
            .map(|(uncertain, pending)| {
                uncertain
                    .checked_add(*pending)
                    .context("private held counter overflow")
            })
            .collect::<Result<Vec<_>>>()?;
        let mut result = None;
        grant.guard.current(&mut || {
            result = Some(SignedShieldedStatus::sign(
                ShieldedStatus {
                    connection: connection.request.request.clone(),
                    server_wireguard_key: state.wireguard,
                    tariff: grant.tariff.clone(),
                    operator_generation: grant.operator_generation,
                    quote_ceiling_ou,
                    paid_ou,
                    purchased_totals: grant.redeemed_totals.clone(),
                    committed_totals: snapshot.committed_totals.clone(),
                    held_totals: held.clone(),
                    canonical_ms: grant.canonical_ms,
                    service_sequence: sequence,
                },
                &state.operator,
            )?);
            Ok(())
        })?;
        result.context("private status was not signed")
    }
    .await
    .map(Json)
    .map_err(|error: anyhow::Error| private_error(&error, "shielded connection unavailable"))
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
        state.registry.confirm_usage(&meter, usage).await
    }
    .await;
    result
        .map(|()| {
            Json(if state.registry.authority.mode() == Mode::Shielded {
                serde_json::json!({"prepaid":true})
            } else {
                serde_json::json!({"canonical":true})
            })
        })
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
