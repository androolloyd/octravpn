//! Paid-plan admission shared by the native host and WireGuard transport.
//! Only the host can mint a canonical guard. HTTP input supplies signatures,
//! never funding facts, traffic classes or a forwarding capability.
use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use octravpn_core::{
    payments::{PlanBinding, SignedConnect, SignedUsage, Tariff},
    session::SessionId,
    PublicKey,
};
use parking_lot::RwLock;
use std::{collections::HashMap, path::PathBuf, sync::Arc};

use crate::{admission::Revocation, payment_meter::Meter};
mod service;
pub use service::{Config, Service};

/// `current` holds the host's publication guard through one nonblocking IO
/// operation. It must not await, write a journal, or perform proof work.
pub trait Guard: Send + Sync {
    fn live(&self) -> bool;
    fn current(&self, action: &mut dyn FnMut() -> Result<()>) -> Result<()>;
}

pub struct Grant {
    pub binding: PlanBinding,
    pub receipt_key: PublicKey,
    pub tariff: Tariff,
    pub original_budget_ou: u64,
    pub remaining_ou: u64,
    /// Authenticated cumulative prepaid byte entitlements, per class.
    pub redeemed_totals: Vec<u64>,
    pub canonical_ms: u64,
    pub claim_deadline_ms: Option<u64>,
    /// Eligibility in the authenticated immutable state. Lease expiry and
    /// publication revocation belong to `guard`, never this retirement fact.
    pub admissible: bool,
    pub guard: Arc<dyn Guard>,
}

#[async_trait]
pub trait Authority: Send + Sync {
    fn updates(&self) -> Option<tokio::sync::watch::Receiver<()>> {
        None
    }
    async fn plan(&self, binding: &PlanBinding) -> Result<Grant>;
    /// Receipt recovery may outlive public tariff visibility. Hosts retaining
    /// authenticated terms can override this read; it must never be used for
    /// admission or refresh. Settlement still rechecks the live claim window.
    async fn claim_plan(&self, binding: &PlanBinding) -> Result<Grant> {
        self.plan(binding).await
    }
}

#[async_trait]
pub trait Settlement: Send + Sync {
    /// Return only once authenticated canonical purchased bytes cover the
    /// exact cumulative authorization, including zero-rate and rounded-price
    /// classes. Pool acknowledgements never qualify; durably queue before
    /// submitting a new purchase transaction.
    async fn confirm(&self, usage: SignedUsage) -> Result<()>;
}

pub(crate) struct Connection {
    pub(crate) request: SignedConnect,
    pub(crate) session: SessionId,
    pub(crate) meter: Arc<Meter>,
    grant: RwLock<Option<Grant>>,
    stop: Revocation,
    transport: crate::stock::Transport,
    stock: Option<Arc<crate::stock::Exit>>,
}
impl Connection {
    pub(crate) fn live(&self) -> bool {
        !self.stop.is_revoked()
            && self.stock_live()
            && self
                .meter
                .transport_is_current(&self.request, &self.transport)
            && self
                .grant
                .read()
                .as_ref()
                .is_some_and(|g| g.admissible && g.guard.live())
    }
    pub(crate) fn current(&self, action: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        ensure!(!self.stop.is_revoked(), "paid VPN stopped");
        let grant = self.grant.read();
        let grant = grant.as_ref().context("paid plan suspended")?;
        ensure!(grant.admissible && grant.guard.live(), "paid plan revoked");
        ensure!(
            self.meter
                .transport_is_current(&self.request, &self.transport),
            "paid connection rotated"
        );
        ensure!(self.stock_live(), "stock registration changed");
        grant.guard.current(&mut || match &self.transport {
            crate::stock::Transport::Framed => action(),
            crate::stock::Transport::Stock(registration) => self
                .stock
                .as_ref()
                .context("stock exit missing")?
                .with_registration(registration, action),
        })
    }
    fn stock_live(&self) -> bool {
        match &self.transport {
            crate::stock::Transport::Framed => true,
            crate::stock::Transport::Stock(registration) => self
                .stock
                .as_ref()
                .is_some_and(|exit| exit.current(registration)),
        }
    }
    pub(crate) fn stock_exit(&self) -> Option<&Arc<crate::stock::Exit>> {
        self.stock.as_ref()
    }
    pub(crate) fn stock_registration(&self) -> Option<&crate::stock::Registration> {
        if let crate::stock::Transport::Stock(registration) = &self.transport {
            Some(registration)
        } else {
            None
        }
    }
    fn invalidate(&self) {
        *self.grant.write() = None;
    }

    pub(crate) async fn handoff(
        &self,
        ticket: crate::payment_meter::Ticket,
        expected: usize,
        mut send: impl FnMut() -> std::io::Result<usize>,
    ) -> Result<()> {
        let mut result = None;
        let guarded = self.current(&mut || {
            result = Some(send());
            Ok(())
        });
        match (guarded, result) {
            (Ok(()), Some(Ok(length))) if length == expected => {
                ticket.commit().await?;
                Ok(())
            }
            (_, Some(Ok(_))) => anyhow::bail!("partial paid packet write; capacity retained"),
            (guarded, result) => {
                // No kernel handoff took place. Release only this definitely
                // unsent reservation. A cancelled future instead drops it.
                ticket.cancel().await?;
                guarded?;
                Err(result
                    .context("packet handoff missing")?
                    .unwrap_err()
                    .into())
            }
        }
    }
}

pub(crate) struct Registry {
    root: PathBuf,
    authority: Arc<dyn Authority>,
    serial: tokio::sync::Mutex<()>,
    connections: RwLock<HashMap<[u8; 32], Arc<Connection>>>,
    meters: RwLock<HashMap<SessionId, Arc<Meter>>>,
    pub(crate) stop: Revocation,
    stock: RwLock<Option<Arc<crate::stock::Exit>>>,
    // Held by every in-flight control operation and tunnel connection.
    _writer: Arc<std::fs::File>,
}
const MAX_PLANS: usize = 4096;

impl Registry {
    fn new(root: PathBuf, authority: Arc<dyn Authority>, writer: Arc<std::fs::File>) -> Self {
        Self {
            root,
            authority,
            serial: tokio::sync::Mutex::new(()),
            connections: RwLock::new(HashMap::new()),
            meters: RwLock::new(HashMap::new()),
            stop: Revocation::default(),
            stock: RwLock::new(None),
            _writer: writer,
        }
    }
    pub(crate) fn get(&self, key: &[u8; 32]) -> Option<Arc<Connection>> {
        self.connections.read().get(key).cloned()
    }
    fn check_binding(grant: &Grant, request: &SignedConnect) -> Result<()> {
        ensure!(
            grant.binding == request.request.binding && grant.receipt_key == request.receipt_key,
            "canonical connection binding differs"
        );
        ensure!(
            grant.binding.manifest_hash == grant.tariff.hash_hex()?,
            "paid tariff differs"
        );
        Ok(())
    }
    fn check_meter(grant: &Grant, meter: &Meter) -> Result<()> {
        ensure!(
            meter.binding() == &grant.binding
                && meter.tariff() == &grant.tariff
                && meter.budget_ou() == grant.original_budget_ou,
            "paid immutable plan changed"
        );
        Ok(())
    }
    fn check(grant: &Grant, request: &SignedConnect) -> Result<()> {
        Self::check_binding(grant, request)?;
        ensure!(
            grant.admissible && grant.guard.live(),
            "paid plan unavailable"
        );
        Ok(())
    }
    pub(crate) fn attach_stock(&self, exit: Arc<crate::stock::Exit>) -> Result<()> {
        ensure!(
            self.connections.read().is_empty() && self.meters.read().is_empty(),
            "stock mode must attach before admission"
        );
        let mut stock = self.stock.write();
        ensure!(stock.is_none(), "stock exit already attached");
        *stock = Some(exit);
        Ok(())
    }
    pub(crate) fn stock_source(&self, address: &std::net::SocketAddr) -> Option<[u8; 32]> {
        self.stock
            .read()
            .as_ref()
            .and_then(|exit| exit.sources.lock().get(address).copied())
    }
    pub(crate) fn stock_exit(&self) -> Option<Arc<crate::stock::Exit>> {
        if self.stop.is_revoked() {
            return None;
        }
        self.stock.read().clone()
    }
    pub(crate) fn stock_peer(&self, key: &[u8; 32]) -> Option<Arc<crate::stock::Peer>> {
        if self.stop.is_revoked() {
            return None;
        }
        self.stock.read().as_ref()?.peer(key)
    }
    async fn connect(&self, request: SignedConnect) -> Result<Arc<Connection>> {
        self.connect_mode(request, false).await
    }
    async fn connect_mode(
        &self,
        request: SignedConnect,
        raw_stock: bool,
    ) -> Result<Arc<Connection>> {
        if raw_stock {
            request.verify_stock()?;
        } else {
            request.verify()?;
        }
        let _serial = self.serial.lock().await;
        ensure!(!self.stop.is_revoked(), "paid VPN stopped");
        let grant = self.authority.plan(&request.request.binding).await?;
        Self::check(&grant, &request)?;
        let session = grant.binding.session_id()?;
        let key = request.request.wireguard_key;
        let stock = self.stock.read().clone();
        let transport = if raw_stock {
            crate::stock::Transport::Stock(
                stock
                    .as_ref()
                    .context("stock exit not configured")?
                    .registration(&key)?,
            )
        } else {
            crate::stock::Transport::Framed
        };
        if let Some(previous) = self.get(&key) {
            ensure!(
                previous.session == session,
                "WG key already belongs to another plan"
            );
        }
        // Cache one writer per immutable plan, including reconnects and key
        // rotations. Capacity exhaustion never evicts a live meter journal.
        let existing = self.meters.read().get(&session).cloned();
        let meter = if let Some(meter) = existing {
            Self::check_meter(&grant, &meter)?;
            meter.reconcile(grant.redeemed_totals.clone()).await?;
            meter
        } else {
            // No live connection or in-flight reservation can be evicted. Its
            // durable journal remains and is mandatory when the plan returns.
            self.meters
                .write()
                .retain(|_, meter| Arc::strong_count(meter) > 1);
            ensure!(
                self.meters.read().len() < MAX_PLANS,
                "paid plan capacity exhausted"
            );
            let meter = Meter::open(
                self.root.join(hex::encode(session.as_bytes())),
                grant.binding.clone(),
                grant.tariff.clone(),
                grant.original_budget_ou,
                grant.redeemed_totals.clone(),
            )
            .await?;
            self.meters.write().insert(session.clone(), meter.clone());
            meter
        };
        meter.check_transport(&request, &transport)?;
        // Revoke before any cancellable durable rotation. A dropped HTTP task
        // cannot leave the previous connection active behind a newer watermark.
        for previous in self
            .connections
            .read()
            .values()
            .filter(|previous| previous.session == session)
        {
            previous.invalidate();
        }
        meter
            .connect_transport(request.clone(), transport.clone())
            .await?;
        Self::check(&grant, &request)?;
        if let crate::stock::Transport::Stock(registration) = &transport {
            ensure!(
                stock.as_ref().is_some_and(|s| s.current(registration)),
                "stock registration changed during connect"
            );
        }
        // Identical retries preserve transport identity and buffered packets.
        if let Some(previous) = self.get(&key) {
            if previous.request == request && previous.transport == transport {
                *previous.grant.write() = Some(grant);
                return Ok(previous);
            }
        }
        let connection = Arc::new(Connection {
            request,
            session: session.clone(),
            meter,
            grant: RwLock::new(Some(grant)),
            stop: self.stop.clone(),
            transport,
            stock,
        });
        let mut connections = self.connections.write();
        connections.retain(|_, previous| {
            if previous.session == session {
                previous.invalidate();
                false
            } else {
                true
            }
        });
        ensure!(
            connections.len() < MAX_PLANS,
            "paid connection capacity exhausted"
        );
        connections.insert(key, connection.clone());
        Ok(connection)
    }
    async fn refresh(&self) {
        let _serial = self.serial.lock().await;
        let connections: Vec<_> = self.connections.read().values().cloned().collect();
        for connection in connections {
            let Ok(grant) = self
                .authority
                .plan(&connection.request.request.binding)
                .await
            else {
                // A publication gap suspends forwarding, but preserving
                // this Arc lets the next current view restore its routes.
                connection.invalidate();
                continue;
            };
            if Self::check_binding(&grant, &connection.request).is_err() {
                connection.invalidate();
                continue;
            }
            if !grant.admissible {
                // Only a successfully authenticated plan can retire identity.
                // Revoked/stale leases by themselves never establish closure.
                connection.invalidate();
                self.connections
                    .write()
                    .remove(&connection.request.request.wireguard_key);
                continue;
            }
            let result = async {
                Self::check(&grant, &connection.request)?;
                Self::check_meter(&grant, &connection.meter)?;
                ensure!(
                    connection.meter.connect_is_current(&connection.request),
                    "connection watermark changed"
                );
                connection
                    .meter
                    .reconcile(grant.redeemed_totals.clone())
                    .await?;
                Self::check(&grant, &connection.request)?;
                Ok::<_, anyhow::Error>(grant)
            }
            .await;
            *connection.grant.write() = result.ok();
        }
    }
    async fn confirm_usage(&self, meter: &Arc<Meter>, usage: SignedUsage) -> Result<()> {
        let _serial = self.serial.lock().await;
        ensure!(!self.stop.is_revoked(), "paid VPN stopped");
        let grant = self.authority.claim_plan(&usage.usage.binding()).await?;
        Self::check_meter(&grant, meter)?;
        ensure!(
            grant.receipt_key == usage.receipt_key && grant.guard.live(),
            "canonical purchase lease or key differs"
        );
        let floor = grant
            .redeemed_totals
            .get(usize::from(usage.usage.traffic_class))
            .context("purchase class missing")?;
        ensure!(
            *floor >= usage.usage.total_bytes,
            "canonical purchased bytes do not cover authorization"
        );
        meter.reconcile(grant.redeemed_totals.clone()).await?;
        ensure!(grant.guard.live(), "canonical purchase publication changed");
        meter.accept_usage(usage).await?;
        ensure!(grant.guard.live(), "canonical purchase publication changed");
        Ok(())
    }
    async fn usage(&self, usage: &SignedUsage) -> Result<Arc<Meter>> {
        usage.verify()?;
        let binding = usage.usage.binding();
        let session = binding.session_id()?;
        let cached = self.meters.read().get(&session).cloned();
        let meter = if let Some(meter) = cached {
            meter
        } else {
            // Serialize recovery with admission and other recovery requests.
            // Exit/stop closes transport, not the operator's claim window.
            let _serial = self.serial.lock().await;
            let cached = self.meters.read().get(&session).cloned();
            if let Some(meter) = cached {
                meter
            } else {
                let grant = self.authority.claim_plan(&binding).await?;
                ensure!(
                    grant.binding == binding && grant.receipt_key == usage.receipt_key,
                    "canonical usage binding or key differs"
                );
                ensure!(
                    grant.binding.manifest_hash == grant.tariff.hash_hex()?,
                    "paid tariff differs"
                );
                ensure!(grant.guard.live(), "canonical payment lease revoked");
                self.meters
                    .write()
                    .retain(|_, meter| Arc::strong_count(meter) > 1);
                ensure!(
                    self.meters.read().len() < MAX_PLANS,
                    "paid plan capacity exhausted"
                );
                let meter = Meter::resume(
                    self.root.join(hex::encode(session.as_bytes())),
                    grant.binding.clone(),
                    grant.tariff,
                    grant.original_budget_ou,
                    grant.redeemed_totals,
                )
                .await?;
                ensure!(grant.guard.live(), "canonical payment lease revoked");
                meter.check_usage(usage)?;
                self.meters.write().insert(session, meter.clone());
                meter
            }
        };
        meter.check_usage(usage)?;
        // Native settlement rechecks receipt key, claim window, payer and
        // immutable deployment against its current canonical snapshot.
        Ok(meter)
    }
}
