//! An explicitly accepted payment plan. The operator status signature binds
//! transport and counters; the plan file must come from confirmed chain state.
//! Operator clock progress is a bounded liveness check, not independent chain
//! proof. Canonical admission remains the pinned native node's responsibility.
use crate::{
    payments::{Journal, OpenMode, Reservation},
    wireguard,
};
use anyhow::{ensure, Context, Result};
use octravpn_core::{
    ip_tunnel,
    payments::{Direction, PlanBinding, SignedConnect, SignedStatus, Tariff},
};
use octravpn_tun::{amnezia::WireTransport, Tun, TunAddress, TunConfig};
use parking_lot::Mutex;
use serde::Deserialize;
use std::{
    io::Read as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    binding: PlanBinding,
    tariff: Tariff,
    original_budget_ou: u64,
    control_url: String,
    wireguard_endpoint: String,
}

const STATUS_MAX_AGE: Duration = Duration::from_secs(120);

struct Freshness {
    canonical_ms: u64,
    deadline: tokio::time::Instant,
}
impl Freshness {
    fn new(canonical_ms: u64) -> Self {
        Self {
            canonical_ms,
            deadline: tokio::time::Instant::now() + STATUS_MAX_AGE,
        }
    }
    fn observe(&mut self, canonical_ms: u64) -> Result<()> {
        ensure!(
            tokio::time::Instant::now() < self.deadline,
            "operator canonical clock stopped advancing"
        );
        ensure!(
            canonical_ms >= self.canonical_ms,
            "operator canonical clock regressed"
        );
        if canonical_ms > self.canonical_ms {
            self.canonical_ms = canonical_ms;
            self.deadline = tokio::time::Instant::now() + STATUS_MAX_AGE;
        }
        Ok(())
    }
}

pub(crate) async fn run(
    plan_path: &Path,
    journal_path: PathBuf,
    receipt_key: &str,
    name: &str,
    resume: bool,
) -> Result<()> {
    let mut raw = Vec::new();
    std::fs::File::open(plan_path)?
        .take(131_073)
        .read_to_end(&mut raw)?;
    ensure!(raw.len() <= 131_072, "accepted plan exceeds byte bound");
    let plan: Plan = serde_json::from_slice(&raw)?;
    plan.binding.validate()?;
    ensure!(
        plan.tariff.hash_hex()? == plan.binding.manifest_hash,
        "accepted plan tariff differs"
    );
    wireguard::validate_endpoint(&plan.wireguard_endpoint)?;
    let mut origin = reqwest::Url::parse(&plan.control_url)?;
    ensure!(
        origin.username().is_empty()
            && origin.password().is_none()
            && origin.query().is_none()
            && origin.fragment().is_none()
            && origin.path() == "/",
        "control URL must be a plain origin"
    );
    let local = matches!(origin.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    ensure!(
        origin.scheme() == "https" || (origin.scheme() == "http" && local),
        "control requires HTTPS or loopback HTTP"
    );
    origin.set_path("/");
    let key = Arc::new(crate::wallet::load_keypair(receipt_key)?);
    let wg = wireguard::public_key(&key);
    let session = plan.binding.session_id()?;
    let binding = plan.binding.clone();
    let tariff = plan.tariff.clone();
    let journal_key = key.clone();
    let budget = plan.original_budget_ou;
    let journal = Arc::new(Mutex::new(
        tokio::task::spawn_blocking(move || {
            Journal::open(
                &journal_path,
                binding,
                tariff,
                budget,
                journal_key,
                if resume {
                    OpenMode::Resume
                } else {
                    OpenMode::Create
                },
            )
        })
        .await??,
    ));
    let connect = {
        let journal = journal.clone();
        tokio::task::spawn_blocking(move || {
            let mut journal = journal.lock();
            tracing::info!(plan = journal.binding().plan, local_bytes = ?journal.totals(),
                uncertain_bytes = ?journal.uncertain_totals(),
                authorized_bytes = ?journal.authorized_totals(), remaining_ou = journal.remaining_ou()?,
                "restored accepted payment plan");
            journal.connect(wg)
        }).await??
    };
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(60))
        .no_proxy()
        .build()?;
    let initial = status(&client, &origin, &connect, &plan).await?;
    let mut tunnel = wireguard::Tunnel::connect(
        session.clone(),
        &key,
        &plan.wireguard_endpoint,
        initial.status.server_wireguard_key,
        None,
        WireTransport::default(),
    )
    .await?;
    ensure!(
        !name.is_empty()
            && name.len() <= 15
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "invalid TUN name"
    );
    let assigned = ip_tunnel::address(&session, &wg);
    let name = name.to_owned();
    let device = tokio::task::spawn_blocking(move || {
        Tun::open(&TunConfig {
            name,
            address: TunAddress::new(assigned, 32),
            mtu: ip_tunnel::MTU as u16,
            up_at_open: true,
        })
    })
    .await??;
    eprintln!(
        "Octranet interface {} address {}; provision explicit routes to paid destinations",
        device.name(),
        assigned
    );
    let (stop_control, shutdown) = tokio::sync::watch::channel(false);
    let mut control = tokio::spawn(control_loop(
        client,
        origin,
        connect,
        plan,
        journal.clone(),
        initial,
        shutdown,
    ));
    let mut control_joined = false;
    let mut health = tokio::time::interval(Duration::from_millis(250));
    health.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut packet = vec![0; ip_tunnel::MTU + 1];
    let outcome = async {
        loop {
            tokio::select! {
                result = &mut control => {
                    control_joined = true;
                    result.context("payment control worker failed")??;
                    anyhow::bail!("payment control worker stopped");
                },
                signal = tokio::signal::ctrl_c() => { signal?; return Ok(()); },
                _ = health.tick() => { tunnel.ensure_available()?; },
                length = device.recv(&mut packet) => {
                    let length = length?;
                    let raw = packet[..length].to_vec();
                    if ip_tunnel::validate_outbound(&raw, assigned).is_err() { continue; }
                    let reservation = reserve(&journal, raw.clone(), Direction::Outbound).await?;
                    if tunnel.send_confirmed(&ip_tunnel::encode(&raw)?).await? {
                        finish(&journal, reservation, true).await?;
                    } else {
                        finish(&journal, reservation, false).await?;
                    }
                    tunnel.ensure_available()?;
                },
                body = tunnel.recv() => {
                    let body = body?;
                    let raw = ip_tunnel::decode(&body)?.to_vec();
                    ip_tunnel::validate_inbound(&raw, assigned)?;
                    let reservation = reserve(&journal, raw.clone(), Direction::Inbound).await?;
                    let length = device.send(&raw).await?;
                    ensure!(length == raw.len(), "partial client TUN write");
                    finish(&journal, reservation, true).await?;
                },
            }
        }
    }
    .await;
    stop_control.send_replace(true);
    let stopped = if control_joined {
        Ok(())
    } else {
        control
            .await
            .context("payment control worker failed")
            .and_then(|result| result)
    };
    outcome.and(stopped)
}

/// One bounded control worker. HTTP finality waits never hold the journal lock
/// or pause WireGuard/TUN processing. Cancelling a request leaves already
/// persisted signed receipts available for a later --resume retry.
async fn control_loop(
    client: reqwest::Client,
    origin: reqwest::Url,
    connect: SignedConnect,
    plan: Plan,
    journal: Arc<Mutex<Journal>>,
    initial: SignedStatus,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut freshness = Freshness::new(initial.status.canonical_ms);
    // At most one receipt batch can wait for canonical settlement. Status
    // polling remains independent even when all traffic classes need claims.
    // Dropping the set aborts its HTTP wait; durable receipts survive retry.
    let mut batches = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = shutdown.wait_for(|stopped| *stopped) => return Ok(()),
            () = tokio::time::sleep_until(freshness.deadline) => anyhow::bail!("operator canonical clock stopped advancing"),
            result = batches.join_next(), if !batches.is_empty() => {
                result.context("settlement batch missing")?.context("settlement batch failed")??;
                continue;
            },
            _ = interval.tick() => (),
        }
        let poll = status(&client, &origin, &connect, &plan);
        tokio::pin!(poll);
        let view = loop {
            tokio::select! {
                biased;
                _ = shutdown.wait_for(|stopped| *stopped) => return Ok(()),
                () = tokio::time::sleep_until(freshness.deadline) => anyhow::bail!("operator canonical clock stopped advancing"),
                result = batches.join_next(), if !batches.is_empty() => {
                    result.context("settlement batch missing")?.context("settlement batch failed")??;
                },
                view = &mut poll => break view?,
            }
        };
        ensure!(
            view.status.server_wireguard_key == initial.status.server_wireguard_key,
            "operator WireGuard identity changed during connection"
        );
        freshness.observe(view.status.canonical_ms)?;
        if batches.is_empty() {
            batches.spawn(settle_batch(
                client.clone(),
                origin.clone(),
                journal.clone(),
                view.status.committed_totals,
            ));
        }
    }
}

async fn settle_batch(
    client: reqwest::Client,
    origin: reqwest::Url,
    journal: Arc<Mutex<Journal>>,
    operator_totals: Vec<u64>,
) -> Result<()> {
    let receipts =
        tokio::task::spawn_blocking(move || journal.lock().receipts(&operator_totals)).await??;
    for receipt in receipts {
        let result = client
            .post(origin.join("payments/usage")?)
            .json(&receipt)
            .send()
            .await?;
        ensure!(
            result.status().is_success(),
            "canonical payment unavailable; reconnect with --resume"
        );
        ensure!(
            result.content_length().is_none_or(|n| n <= 1024),
            "settlement response exceeds bound"
        );
    }
    Ok(())
}

async fn reserve(
    journal: &Arc<Mutex<Journal>>,
    raw: Vec<u8>,
    direction: Direction,
) -> Result<Reservation> {
    let journal = journal.clone();
    tokio::task::spawn_blocking(move || journal.lock().reserve(&raw, direction)).await?
}
async fn finish(
    journal: &Arc<Mutex<Journal>>,
    reservation: Reservation,
    confirmed: bool,
) -> Result<()> {
    let journal = journal.clone();
    tokio::task::spawn_blocking(move || {
        if confirmed {
            journal.lock().confirm(reservation)
        } else {
            journal.lock().cancel(reservation)
        }
    })
    .await?
}
async fn status(
    client: &reqwest::Client,
    origin: &reqwest::Url,
    connect: &SignedConnect,
    plan: &Plan,
) -> Result<SignedStatus> {
    let mut response = client
        .post(origin.join("payments/connect")?)
        .json(connect)
        .send()
        .await?
        .error_for_status()?;
    let mut raw = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            raw.len().saturating_add(chunk.len()) <= 131_072,
            "operator status exceeds byte bound"
        );
        raw.extend_from_slice(&chunk);
    }
    let signed: SignedStatus = serde_json::from_slice(&raw).context("invalid operator status")?;
    signed.verify()?;
    ensure!(
        signed.status.binding == plan.binding
            && signed.status.tariff == plan.tariff
            && signed.status.original_budget_ou == plan.original_budget_ou
            && signed.status.connect_sequence == connect.request.sequence
            && signed.status.client_wireguard_key == connect.request.wireguard_key,
        "operator status differs from accepted plan"
    );
    Ok(signed)
}

#[cfg(test)]
mod tests;
