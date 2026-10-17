//! An explicitly accepted prepaid plan. The operator status signature binds
//! transport and counters; the plan file must come from confirmed chain state.
//! Operator clock progress is a bounded liveness check, not independent chain
//! proof. Canonical admission remains the pinned native node's responsibility.
use crate::{
    payments::{validate_purchase, Journal, OpenMode, PrepaidExhausted, Reservation},
    wireguard,
};
use anyhow::{ensure, Context, Result};
use octravpn_core::{
    ip_tunnel,
    payments::{Direction, PlanBinding, SignedConnect, SignedStatus, Tariff},
};
use octravpn_tun::{amnezia::WireTransport, Tun, TunAddress, TunConfig};
use serde::Deserialize;

mod accounting;
use accounting::Accounting;
use std::{
    io::Read as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

const STATUS_MAX_AGE: Duration = Duration::from_secs(120);

#[derive(Debug)]
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
    fn ensure_live(&self) -> Result<()> {
        ensure!(
            tokio::time::Instant::now() < self.deadline,
            "operator canonical clock stopped advancing"
        );
        Ok(())
    }
    fn observe(&mut self, canonical_ms: u64) -> Result<()> {
        self.ensure_live()?;
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

#[derive(Debug)]
struct Observation {
    signed: SignedStatus,
    freshness: Freshness,
}
impl Observation {
    fn new(signed: SignedStatus) -> Self {
        Self {
            freshness: Freshness::new(signed.status.canonical_ms),
            signed,
        }
    }
}

/// A plan accepted from independently confirmed chain facts. Parsing this data
/// validates its shape; it does not prove chain finality or authorize traffic.
/// Targets and prices stay fixed for this journal. Quote replacement, channel
/// withdrawals and new earnings never consent to another purchase.
#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub binding: PlanBinding,
    pub tariff: Tariff,
    pub original_budget_ou: u64,
    /// Explicit finite cumulative byte purchase in immutable tariff order.
    pub prepaid_bytes: Vec<u64>,
    pub control_url: String,
    pub wireguard_endpoint: String,
}
impl Plan {
    pub fn load(path: &Path) -> Result<Self> {
        let mut raw = Vec::new();
        std::fs::File::open(path)?
            .take(131_073)
            .read_to_end(&mut raw)?;
        ensure!(raw.len() <= 131_072, "accepted plan exceeds byte bound");
        let plan: Self = serde_json::from_slice(&raw)?;
        plan.origin()?;
        Ok(plan)
    }

    fn origin(&self) -> Result<reqwest::Url> {
        self.binding.validate()?;
        ensure!(self.original_budget_ou > 0, "zero original plan budget");
        validate_purchase(&self.tariff, self.original_budget_ou, &self.prepaid_bytes)?;
        ensure!(
            self.tariff.hash_hex()? == self.binding.manifest_hash,
            "accepted plan tariff differs"
        );
        wireguard::validate_endpoint(&self.wireguard_endpoint)?;
        let origin = reqwest::Url::parse(&self.control_url)?;
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
        Ok(origin)
    }
}

/// Startup inputs. Creation requires a genuinely new journal directory; resume
/// requires the original intact journal. No route or process signal is changed.
pub struct Options {
    pub plan: Plan,
    pub journal: PathBuf,
    pub receipt_key: Arc<octravpn_core::KeyPair>,
    pub interface_name: String,
    pub mode: OpenMode,
}

/// The actual opened interface. The host provisions its routes explicitly.
#[derive(Clone, Debug)]
pub struct Interface {
    pub name: String,
    pub address: std::net::Ipv4Addr,
    pub mtu: u16,
}

/// Local journal counters in accepted tariff order. Confirmed local IO does
/// not prove delivery; signed authorization does not prove canonical payment.
#[derive(Clone, Debug)]
pub struct Summary {
    pub confirmed_bytes: Vec<u64>,
    /// Uncertain and interrupted handoffs, held against purchased bytes.
    pub held_bytes: Vec<u64>,
    /// Durable cumulative purchase caps, independent of delivery counters.
    pub authorized_bytes: Vec<u64>,
    /// Original budget less authorized purchases; zero does not exhaust bytes.
    /// This is not the channel's currently withdrawable OCT balance.
    pub remaining_ou: u64,
}

/// One owned paid connection. Opening authenticates the operator and creates
/// its interface. Running consumes it and accepts the caller's shutdown future.
/// Dropping a cancelled run aborts its control tasks; already-started journal
/// writes finish with the writer lease held. Preserve that journal for resume.
pub struct Client {
    plan: Plan,
    journal: Accounting,
    origin: reqwest::Url,
    connect: SignedConnect,
    http: reqwest::Client,
    initial: Observation,
    tunnel: wireguard::Tunnel,
    device: Tun,
    interface: Interface,
}
impl Client {
    pub async fn open(options: Options) -> Result<Self> {
        let Options {
            plan,
            journal: path,
            receipt_key: key,
            interface_name: name,
            mode,
        } = options;
        let origin = plan.origin()?;
        ensure!(
            !name.is_empty()
                && name.len() <= 15
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
            "invalid TUN name"
        );
        let wg = wireguard::public_key(&key);
        let session = plan.binding.session_id()?;
        let binding = plan.binding.clone();
        let tariff = plan.tariff.clone();
        let journal_key = key.clone();
        let budget = plan.original_budget_ou;
        let prepaid = plan.prepaid_bytes.clone();
        let journal = Accounting::new(
            tokio::task::spawn_blocking(move || {
                Journal::open(&path, binding, tariff, budget, prepaid, journal_key, mode)
            })
            .await??,
        );
        let connect = journal.with(move |journal| {
            tracing::info!(plan = journal.binding().plan, local_bytes = ?journal.totals(),
                uncertain_bytes = ?journal.uncertain_totals(), authorized_bytes = ?journal.authorized_totals(),
                remaining_ou = journal.remaining_ou()?, "restored accepted payment plan");
            journal.connect(wg)
        }).await?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(60))
            .no_proxy()
            .build()?;
        let initial = Observation::new(status(&http, &origin, &connect, &plan).await?);
        // A control connection is allowed before payment. No WireGuard/TUN
        // payload path is opened until the exact purchases are canonical.
        let initial = prepay(&http, &origin, &connect, &plan, &journal, initial).await?;
        let tunnel = wireguard::Tunnel::connect(
            session.clone(),
            &key,
            &plan.wireguard_endpoint,
            initial.signed.status.server_wireguard_key,
            None,
            WireTransport::default(),
        )
        .await?;
        let assigned = ip_tunnel::address(&session, &wg);
        let device = tokio::task::spawn_blocking(move || {
            Tun::open(&TunConfig {
                name,
                address: TunAddress::new(assigned, 32),
                mtu: ip_tunnel::MTU as u16,
                up_at_open: true,
            })
        })
        .await??;
        let interface = Interface {
            name: device.name().to_owned(),
            address: assigned,
            mtu: ip_tunnel::MTU as u16,
        };
        Ok(Self {
            plan,
            journal,
            origin,
            connect,
            http,
            initial,
            tunnel,
            device,
            interface,
        })
    }

    pub const fn interface(&self) -> &Interface {
        &self.interface
    }

    pub async fn run(
        self,
        shutdown: impl std::future::Future<Output = Result<()>>,
    ) -> Result<Summary> {
        let Self {
            plan,
            journal,
            origin,
            connect,
            http,
            initial,
            mut tunnel,
            device,
            interface,
        } = self;
        initial.freshness.ensure_live()?;
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let control = control_loop(http, origin, connect, plan, initial, stopped);
        let accounting = journal.clone();
        let driver = async move {
            let assigned = interface.address;
            let mut health = tokio::time::interval(Duration::from_millis(250));
            health.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut packet = vec![0; ip_tunnel::MTU + 1];
            loop {
                tokio::select! {
                    _ = health.tick() => { tunnel.ensure_available()?; },
                    length = device.recv(&mut packet) => {
                        let length = length?;
                        let raw = packet[..length].to_vec();
                        if ip_tunnel::validate_outbound(&raw, assigned).is_err() { continue; }
                        let Some(reservation) = reserve(&accounting, raw.clone(), Direction::Outbound).await? else {continue;};
                        if tunnel.send_confirmed(&ip_tunnel::encode(&raw)?).await? {
                            finish(&accounting, reservation, true).await?;
                        } else {
                            finish(&accounting, reservation, false).await?;
                        }
                        tunnel.ensure_available()?;
                    },
                    body = tunnel.recv() => {
                        let body = body?;
                        let raw = ip_tunnel::decode(&body)?.to_vec();
                        ip_tunnel::validate_inbound(&raw, assigned)?;
                        let Some(reservation) = reserve(&accounting, raw.clone(), Direction::Inbound).await? else {continue;};
                        let length = device.send(&raw).await?;
                        ensure!(length == raw.len(), "partial client TUN write");
                        finish(&accounting, reservation, true).await?;
                    },
                }
            }
        };
        supervise(journal, driver, control, stop, shutdown).await
    }
}

// Race shutdown and control failure against the whole driver, including its
// nested packet IO/fsync awaits. Cancelling a handoff never releases exposure.
async fn supervise(
    journal: Accounting,
    driver: impl std::future::Future<Output = Result<()>>,
    control: impl std::future::Future<Output = Result<()>> + Send + 'static,
    stop: tokio::sync::watch::Sender<bool>,
    shutdown: impl std::future::Future<Output = Result<()>>,
) -> Result<Summary> {
    let mut workers = tokio::task::JoinSet::new();
    workers.spawn(control);
    let outcome = {
        tokio::pin!(driver);
        tokio::pin!(shutdown);
        tokio::select! {
            biased;
            signal = &mut shutdown => signal,
            result = workers.join_next() => {
                result.context("payment control worker missing")
                    .and_then(|result| result.context("payment control worker failed"))
                    .and_then(|result| result)
                    .and_then(|()| Err(anyhow::anyhow!("payment control worker stopped")))
            },
            result = &mut driver => result,
        }
    };
    stop.send_replace(true);
    let mut stopped = Ok(());
    while let Some(result) = workers.join_next().await {
        if let Err(error) = result
            .context("payment control worker failed")
            .and_then(|result| result)
        {
            stopped = Err(error);
        }
    }
    let idle = journal.wait_idle().await;
    let summary = journal
        .with(|journal| {
            Ok(Summary {
                confirmed_bytes: journal.totals().to_vec(),
                held_bytes: journal.held_totals()?,
                authorized_bytes: journal.authorized_totals().to_vec(),
                remaining_ou: journal.remaining_ou()?,
            })
        })
        .await;
    outcome.and(stopped).and(idle).and(summary)
}

/// Bounded authenticated status monitoring after the purchase barrier. Operator
/// delivery counters cannot create new payment authorizations.
async fn control_loop(
    client: reqwest::Client,
    origin: reqwest::Url,
    connect: SignedConnect,
    plan: Plan,
    initial: Observation,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let Observation {
        signed: initial,
        mut freshness,
    } = initial;
    freshness.ensure_live()?;
    ensure!(
        purchased(&initial, &plan),
        "canonical prepaid capacity missing"
    );
    loop {
        tokio::select! {
            biased;
            _ = shutdown.wait_for(|stopped| *stopped) => return Ok(()),
            () = tokio::time::sleep_until(freshness.deadline) => anyhow::bail!("operator canonical clock stopped advancing"),
            _ = interval.tick() => (),
        }
        let poll = status(&client, &origin, &connect, &plan);
        tokio::pin!(poll);
        let view = tokio::select! {
            biased;
            _ = shutdown.wait_for(|stopped| *stopped) => return Ok(()),
            () = tokio::time::sleep_until(freshness.deadline) => anyhow::bail!("operator canonical clock stopped advancing"),
            view = &mut poll => view?,
        };
        ensure!(
            view.status.server_wireguard_key == initial.status.server_wireguard_key,
            "operator WireGuard identity changed during connection"
        );
        freshness.observe(view.status.canonical_ms)?;
        ensure!(
            purchased(&view, &plan),
            "canonical prepaid capacity regressed"
        );
    }
}

fn purchased(view: &SignedStatus, plan: &Plan) -> bool {
    view.status.redeemed_totals.len() == plan.prepaid_bytes.len()
        && view
            .status
            .redeemed_totals
            .iter()
            .zip(&plan.prepaid_bytes)
            .all(|(canonical, target)| canonical >= target)
}

/// Keep status polling independent of at most one bounded purchase batch. Only
/// an authenticated canonical class floor opens the data path, including when
/// the original OCT allocation was fully spent buying the allowance.
async fn prepay(
    client: &reqwest::Client,
    origin: &reqwest::Url,
    connect: &SignedConnect,
    plan: &Plan,
    journal: &Accounting,
    initial: Observation,
) -> Result<Observation> {
    let receipts = journal.with(Journal::purchases).await?;
    initial.freshness.ensure_live()?;
    if purchased(&initial.signed, plan) {
        return Ok(initial);
    }
    let mut batches = tokio::task::JoinSet::new();
    batches.spawn(settle_batch(client.clone(), origin.clone(), receipts));
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let Observation {
        mut signed,
        mut freshness,
    } = initial;
    // Every tariff has at most 32 classes and each HTTP operation times out.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60 * 32 + 120);
    loop {
        tokio::select! {
            biased;
            () = tokio::time::sleep_until(freshness.deadline) => anyhow::bail!("operator canonical clock stopped advancing"),
            () = tokio::time::sleep_until(deadline) => anyhow::bail!("canonical prepaid purchase deadline exceeded"),
            result = batches.join_next(), if !batches.is_empty() => {
                result.context("purchase batch missing")?.context("purchase batch failed")??;
            },
            _ = interval.tick() => {
                let view = tokio::time::timeout_at(freshness.deadline.min(deadline), status(client, origin, connect, plan)).await??;
                ensure!(view.status.server_wireguard_key == signed.status.server_wireguard_key,
                    "operator WireGuard identity changed during purchase");
                freshness.observe(view.status.canonical_ms)?;
                signed = view;
                if purchased(&signed, plan) {
                    return Ok(Observation { signed, freshness });
                }
            },
        }
    }
}

async fn settle_batch(
    client: reqwest::Client,
    origin: reqwest::Url,
    receipts: Vec<octravpn_core::payments::SignedUsage>,
) -> Result<()> {
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
        let mut result = result;
        let mut bytes = 0_usize;
        while let Some(chunk) = result.chunk().await? {
            bytes = bytes
                .checked_add(chunk.len())
                .context("purchase response size overflow")?;
            ensure!(bytes <= 1024, "settlement response exceeds bound");
        }
    }
    Ok(())
}

async fn reserve(
    journal: &Accounting,
    raw: Vec<u8>,
    direction: Direction,
) -> Result<Option<Reservation>> {
    match journal
        .with(move |journal| journal.reserve(&raw, direction))
        .await
    {
        Ok(reservation) => Ok(Some(reservation)),
        Err(error) if error.is::<PrepaidExhausted>() => Ok(None),
        Err(error) => Err(error),
    }
}
async fn finish(journal: &Accounting, reservation: Reservation, confirmed: bool) -> Result<()> {
    journal
        .with(move |journal| {
            if confirmed {
                journal.confirm(reservation)
            } else {
                journal.cancel(reservation)
            }
        })
        .await
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
