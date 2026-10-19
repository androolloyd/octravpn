//! Explicit nested prepaid connections. Each operator terminates its own
//! authenticated, canonically purchased session. An entry bills encrypted UDP
//! carriage to the next operator; only the exit observes the web destination.
//!
//! Linux only: a single exclusive policy-route lease arms IPv4/IPv6 blockers
//! before payment. Only entry control and peer IPs are direct management
//! exceptions. Downstream control and peer IPs travel through the preceding
//! paid tunnel, with /32 blocking fallbacks. Personal 100.64/10 uses existing
//! host policy.
//! An error, cancellation or crash retains the blockers; clean caller-requested
//! shutdown closes every hop before deliberately restoring ordinary routes.
//!
//! This IPv4/no-fragment profile conservatively allows standard WG padding and
//! reduces the final MTU to 1075 (two hops) or 867 (three). TCP uses that TUN's MSS. Oversized UDP returns are refused, not
//! fragmented or promised delivered. Purchases are finite and final; exhaustion
//! drops packets and never buys capacity or changes an accepted tariff.
use crate::{
    paid_routes::{CompositeRouteGuard, PaidRouteGuard},
    payment_runner::{Pins, Prepared},
    PaymentOptions, PaymentSummary,
};
use anyhow::{ensure, Context, Result};
use octravpn_core::ip_tunnel;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read as _,
    net::{Ipv4Addr, SocketAddrV4},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

mod journal;
mod mtu;
#[cfg(test)]
mod tests;

/// On-disk explicit consent. Relative paths resolve against this file, never
/// against a server-supplied path. No key bytes are stored in this document.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoutePlan {
    pub journal: PathBuf,
    pub hops: Vec<HopPlan>,
    /// The current custody Circle is public. A caller requesting shielded
    /// settlement must fail before reading keys, opening journals or routing.
    #[serde(default)]
    pub payment_privacy: PaymentPrivacy,
    #[serde(default)]
    pub bootstrap_privacy: BootstrapPrivacy,
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentPrivacy {
    #[default]
    Public,
    ShieldedRequired,
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapPrivacy {
    #[default]
    SystemDns,
    PinnedIps,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HopPlan {
    pub plan: crate::AcceptedPlan,
    pub journal: PathBuf,
    pub receipt_key: PathBuf,
    pub interface_name: String,
    #[serde(default)]
    pub wireguard_pin: Option<SocketAddrV4>,
    #[serde(default)]
    pub control_pin: Option<SocketAddrV4>,
}
impl RoutePlan {
    pub fn load(path: &Path) -> Result<Self> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(524_289)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 524_288, "accepted route exceeds byte bound");
        let mut route: Self = serde_json::from_slice(&bytes)?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        route.journal = absolute(&parent.join(&route.journal))?;
        for hop in &mut route.hops {
            hop.journal = absolute(&parent.join(&hop.journal))?;
            hop.receipt_key = absolute(&parent.join(&hop.receipt_key))?;
        }
        Ok(route)
    }
    pub fn options(self, mode: crate::JournalMode) -> Result<Options> {
        ensure!(
            self.payment_privacy == PaymentPrivacy::Public,
            "shielded route settlement is unavailable: the current Circle exposes payer, plan and purchases"
        );
        ensure!(
            (2..=octravpn_core::onion::MAX_HOPS).contains(&self.hops.len()),
            "a composite route requires two or three hops"
        );
        let mut hops = Vec::new();
        let mut pins = Vec::new();
        for hop in self.hops {
            let pin = match (hop.wireguard_pin, hop.control_pin) {
                (Some(wireguard), Some(control)) => Some(RoutePins { wireguard, control }),
                (None, None) if self.bootstrap_privacy == BootstrapPrivacy::SystemDns => None,
                _ => anyhow::bail!("private bootstrap requires both operator IP pins at every hop"),
            };
            let secret = hop
                .receipt_key
                .to_str()
                .context("receipt key path is not UTF-8")?;
            hops.push(PaymentOptions {
                plan: hop.plan,
                journal: hop.journal,
                receipt_key: Arc::new(crate::wallet::load_keypair(secret)?),
                interface_name: hop.interface_name,
                mode,
            });
            pins.push(pin);
        }
        Ok(Options {
            journal: self.journal,
            hops,
            pins,
            mode,
        })
    }
}

/// Every hop requires its own explicitly accepted plan/key/journal. Reordering
/// hops or changing an endpoint/target on resume is refused by the aggregate
/// journal. Crash recovery never recreates missing individual state.
pub struct Options {
    pub journal: PathBuf,
    pub hops: Vec<PaymentOptions>,
    /// A complete per-hop pin avoids all operator hostname lookups.
    pub pins: Vec<Option<RoutePins>>,
    pub mode: crate::JournalMode,
}

/// Explicitly accepted network addresses; TLS and WireGuard still authenticate
/// the operator's original hostname/key rather than trusting the IP alone.
#[derive(Clone, Copy, Debug)]
pub struct RoutePins {
    pub wireguard: SocketAddrV4,
    pub control: SocketAddrV4,
}

/// Owned bounded route and live hop tasks. Opening installs host routes; unlike
/// PaymentClient, this opt-in service deliberately owns a global Linux lease.
pub struct Client {
    workers: tokio::task::JoinSet<(usize, Result<PaymentSummary>)>,
    stop: tokio::sync::watch::Sender<bool>,
    routes: CompositeRouteGuard,
    journal: journal::Lease,
    interfaces: Vec<crate::Interface>,
}
impl Client {
    pub async fn open(mut options: Options) -> Result<Self> {
        validate(&options)?;
        let mtus = mtu::route_mtus(options.hops.len())?;
        let mut pins = Vec::new();
        for (hop, accepted) in options.hops.iter().zip(&options.pins) {
            pins.push(if let Some(pin) = accepted {
                Pins {
                    wireguard: pin.wireguard,
                    control: pin.control,
                }
            } else {
                Pins {
                    wireguard: PaidRouteGuard::resolve_public_peer(&hop.plan.wireguard_endpoint)
                        .await?,
                    control: resolve_control(&hop.plan.origin()?).await?,
                }
            });
        }
        validate_pins(&pins)?;
        let journal = journal::Lease::open(&options, &pins, &mtus)?;
        let entry = pins[0].wireguard;
        let controls = pins.iter().map(|pin| pin.control).collect::<Vec<_>>();
        let peers = pins[1..]
            .iter()
            .map(|pin| pin.wireguard)
            .collect::<Vec<_>>();
        let names = options
            .hops
            .iter()
            .map(|hop| hop.interface_name.clone())
            .collect::<Vec<_>>();
        let routes = tokio::task::spawn_blocking(move || {
            CompositeRouteGuard::arm(entry, &controls, &peers, &names)
        })
        .await??;
        // Prepare *all* journals before any status/claim/WireGuard request. A
        // partial local setup failure cannot have spent any hop's purchase.
        let mut prepared = Vec::new();
        for ((hop, pin), mtu) in options.hops.drain(..).zip(pins.iter().copied()).zip(mtus) {
            prepared.push(Prepared::new(hop, Some(pin), mtu).await?);
        }
        let (stop, _) = tokio::sync::watch::channel(false);
        let mut client = Self {
            workers: tokio::task::JoinSet::new(),
            stop,
            routes,
            journal,
            interfaces: Vec::new(),
        };
        for (index, prepared) in prepared.into_iter().enumerate() {
            client.journal.check().await?;
            if let Some(previous) = client.interfaces.last().cloned() {
                client
                    .routes
                    .next(&previous, pins[index].wireguard, pins[index].control)?;
            }
            let connection = if client.workers.is_empty() {
                prepared.open().await?
            } else {
                tokio::select! {
                    biased;
                    failed = client.workers.join_next() => return Err(worker_failure(failed)),
                    opened = prepared.open() => opened?,
                }
            };
            client.interfaces.push(connection.interface().clone());
            let mut stop = client.stop.subscribe();
            client.workers.spawn(async move {
                let result = Box::pin(connection.run(async {
                    stop.wait_for(|stopped| *stopped).await?;
                    Ok(())
                }))
                .await;
                (index, result)
            });
        }
        client.journal.check().await?;
        client
            .routes
            .finish(client.interfaces.last().context("route exit missing")?)?;
        Ok(client)
    }

    pub fn interfaces(&self) -> &[crate::Interface] {
        &self.interfaces
    }

    /// Only a successful explicit shutdown releases host routes. Errors and
    /// future cancellation leave the kernel blockers for deliberate recovery.
    pub async fn run(
        mut self,
        shutdown: impl std::future::Future<Output = Result<()>>,
    ) -> Result<Vec<PaymentSummary>> {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tokio::pin!(shutdown);
        let outcome = loop {
            tokio::select! {
                biased;
                signal = &mut shutdown => break signal,
                failure = self.workers.join_next() => break Err(worker_failure(failure)),
                _ = interval.tick() => { if let Err(error) = self.journal.check().await { break Err(error); } },
            }
        };
        self.stop.send_replace(true);
        let mut summaries = Vec::new();
        let mut failure = None;
        while let Some(result) = self.workers.join_next().await {
            match result {
                Ok((index, Ok(summary))) => summaries.push((index, summary)),
                Ok((_, Err(error))) => {
                    failure.get_or_insert(error);
                }
                Err(error) => {
                    failure.get_or_insert(error.into());
                }
            }
        }
        outcome?;
        if let Some(error) = failure {
            return Err(error);
        }
        ensure!(
            summaries.len() == self.interfaces.len(),
            "a route hop stopped before shutdown"
        );
        self.routes.disconnect()?;
        summaries.sort_by_key(|(index, _)| *index);
        Ok(summaries.into_iter().map(|(_, summary)| summary).collect())
    }
}

fn worker_failure(
    result: Option<Result<(usize, Result<PaymentSummary>), tokio::task::JoinError>>,
) -> anyhow::Error {
    match result {
        Some(Ok((index, Err(error)))) => {
            error.context(format!("paid route hop {index} failed; blockers retained"))
        }
        Some(Ok((index, Ok(_)))) => {
            anyhow::anyhow!("paid route hop {index} stopped unexpectedly; blockers retained")
        }
        Some(Err(error)) => error.into(),
        None => anyhow::anyhow!("paid route workers missing; blockers retained"),
    }
}
fn absolute(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .context("journal/key path has no final component")?;
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(parent.canonicalize()?.join(name))
}
fn validate(options: &Options) -> Result<()> {
    ensure!(
        (2..=octravpn_core::onion::MAX_HOPS).contains(&options.hops.len()),
        "a composite route requires two or three hops"
    );
    ensure!(
        options.pins.len() == options.hops.len(),
        "composite route pin count differs from hop count"
    );
    let mut paths = BTreeSet::from([absolute(&options.journal)?]);
    let mut names = BTreeSet::new();
    let mut sessions = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for (hop, accepted) in options.hops.iter().zip(&options.pins) {
        let origin = hop.plan.origin()?;
        if let Some(pin) = accepted {
            validate_route_pin(&hop.plan, &origin, *pin)?;
        }
        ensure!(
            hop.mode == options.mode,
            "mixed journal create/resume modes are forbidden"
        );
        ensure!(
            hop.journal.is_absolute() && options.journal.is_absolute(),
            "route journal paths must be absolute"
        );
        ensure!(
            paths.insert(absolute(&hop.journal)?),
            "duplicate route journal path"
        );
        let name = &hop.interface_name;
        ensure!(
            !name.is_empty()
                && name.len() <= 15
                && name != "tailscale0"
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                && names.insert(name.clone()),
            "invalid or duplicate composite TUN name"
        );
        let session = hop.plan.binding.session_id()?;
        let wg = crate::wireguard::public_key(&hop.receipt_key);
        ensure!(
            sessions.insert(*session.as_bytes()) && keys.insert(wg),
            "route hops require independent sessions and receipt keys"
        );
        ensure!(
            addresses.insert(ip_tunnel::address(&session, &wg)),
            "route session IPv4 address collision"
        );
    }
    Ok(())
}
fn validate_route_pin(
    plan: &crate::AcceptedPlan,
    origin: &reqwest::Url,
    pin: RoutePins,
) -> Result<()> {
    ensure!(
        ip_tunnel::public_ipv4(*pin.wireguard.ip()) && pin.wireguard.port() != 0,
        "WireGuard pin requires a public IPv4 endpoint"
    );
    let raw = plan
        .wireguard_endpoint
        .trim()
        .strip_prefix("wg://")
        .unwrap_or(plan.wireguard_endpoint.trim());
    let endpoint = reqwest::Url::parse(&format!("udp://{raw}"))?;
    ensure!(
        endpoint.port() == Some(pin.wireguard.port()),
        "WireGuard pin port differs from accepted endpoint"
    );
    if let Some(host) = endpoint
        .host_str()
        .and_then(|host| host.parse::<Ipv4Addr>().ok())
    {
        ensure!(
            host == *pin.wireguard.ip(),
            "WireGuard pin IP differs from accepted endpoint"
        );
    }
    ensure!(
        origin.port_or_known_default() == Some(pin.control.port()),
        "control pin port differs from accepted origin"
    );
    let local = matches!(origin.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    ensure!(
        (local && pin.control.ip().is_loopback())
            || (!local && ip_tunnel::public_ipv4(*pin.control.ip())),
        "control pin address differs from accepted origin policy"
    );
    if let Some(host) = origin
        .host_str()
        .and_then(|host| host.parse::<Ipv4Addr>().ok())
    {
        ensure!(
            host == *pin.control.ip(),
            "control pin IP differs from accepted origin"
        );
    }
    Ok(())
}
fn validate_pins(pins: &[Pins]) -> Result<()> {
    let mut owners = BTreeMap::new();
    for (index, pin) in pins.iter().enumerate() {
        for ip in [*pin.wireguard.ip(), *pin.control.ip()] {
            if ip.is_loopback() {
                continue;
            }
            ensure!(
                owners.insert(ip, index).is_none_or(|owner| owner == index),
                "two route hops share an endpoint IP"
            );
        }
    }
    Ok(())
}
async fn resolve_control(origin: &reqwest::Url) -> Result<SocketAddrV4> {
    let host = origin.host_str().context("control URL host missing")?;
    let port = origin
        .port_or_known_default()
        .context("control URL port missing")?;
    if matches!(host, "localhost" | "127.0.0.1") {
        return Ok(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    }
    let addresses = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .context("control DNS timed out")??;
    addresses
        .filter_map(|address| {
            if let std::net::SocketAddr::V4(peer) = address {
                Some(peer)
            } else {
                None
            }
        })
        .find(|peer| ip_tunnel::public_ipv4(*peer.ip()))
        .context("control origin has no public IPv4 endpoint")
}
