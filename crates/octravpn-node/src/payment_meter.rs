//! Durable capacity reservations for one immutable payment plan.
//!
//! Reserve before forwarding, commit only after a successful send. A crash can
//! leave reserved capacity uncertain; it must never become billable delivery.
//! This deliberately fsyncs the packet journal and does not claim line-rate IO.
use anyhow::{ensure, Context, Result};
use octravpn_core::payments::{Budget, Direction, SignedConnect, SignedUsage, Tariff};
#[cfg(test)]
use octravpn_core::{payments::Deployment, Address};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

mod storage;
use storage::{Disk, Record};

const MAX_PENDING: usize = 1024;

pub use octravpn_core::payments::PlanBinding as Binding;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    /// Actual confirmed delivery only; purchased bytes never imply delivery.
    pub committed_totals: Vec<u64>,
    pub purchased_totals: Vec<u64>,
    pub uncertain_totals: Vec<u64>,
    pub pending_totals: Vec<u64>,
    pub committed_charge_ou: u64,
    pub capacity_charge_ou: u64,
    pub remaining_ou: u64,
}

struct State {
    record: Record,
    capacity: Budget,
    pending: BTreeMap<u64, (usize, u64)>,
    next_ticket: u64,
}

pub struct Meter {
    binding: Binding,
    tariff: Tariff,
    budget_ou: u64,
    disk: Disk,
    writer: Mutex<State>,
    published: RwLock<Snapshot>,
    current_connect: RwLock<Option<SignedConnect>>,
    receipts: RwLock<Vec<SignedUsage>>,
    transport: RwLock<crate::stock::Transport>,
    connect_pending: AtomicBool,
    failed: AtomicBool,
}

/// Private reservation identity prevents forging, cloning or double commit.
/// Dropping it conservatively holds uncertain capacity without billing it:
/// cancellation may race a successful send. Only an explicit cancel confirms
/// that forwarding did not happen and releases the reservation.
pub struct Ticket {
    meter: Arc<Meter>,
    id: Option<u64>,
}

fn sum(record: &Record) -> Result<Vec<u64>> {
    ensure!(
        record.committed.len() == record.uncertain.len()
            && record.committed.len() == record.pending.len(),
        "meter counter shape differs"
    );
    record
        .committed
        .iter()
        .zip(&record.uncertain)
        .zip(&record.pending)
        .map(|((&committed, &uncertain), &pending)| {
            committed
                .checked_add(uncertain)
                .and_then(|n| n.checked_add(pending))
                .context("meter byte counter overflow")
        })
        .collect()
}
fn snapshot(record: &Record, capacity: &Budget, tariff: &Tariff) -> Result<Snapshot> {
    Ok(Snapshot {
        committed_totals: record.committed.clone(),
        purchased_totals: record.purchased.clone(),
        uncertain_totals: record.uncertain.clone(),
        pending_totals: record.pending.clone(),
        committed_charge_ou: tariff.total_charge(&record.committed)?,
        capacity_charge_ou: capacity.total_charge_ou(),
        remaining_ou: record
            .budget_ou
            .checked_sub(tariff.total_charge(&record.purchased)?)
            .context("purchased charge exceeds plan budget")?,
    })
}

fn check_prepaid(record: &Record, capacity: &Budget, tariff: &Tariff) -> Result<()> {
    ensure!(
        capacity.totals().len() == record.purchased.len(),
        "meter purchase shape differs"
    );
    ensure!(
        tariff.total_charge(&record.purchased)? <= record.budget_ou,
        "purchased tariff charge exceeds plan budget"
    );
    ensure!(
        capacity
            .totals()
            .iter()
            .zip(&record.purchased)
            .all(|(used, paid)| used <= paid),
        "prepaid traffic bytes exhausted"
    );
    Ok(())
}
fn check_previous(previous: Option<&SignedConnect>, connect: &SignedConnect) -> Result<()> {
    if let Some(previous) = previous {
        ensure!(
            previous.receipt_key == connect.receipt_key,
            "connection receipt key differs"
        );
        ensure!(
            previous == connect || connect.request.sequence > previous.request.sequence,
            "connection replay or conflicting sequence"
        );
    }
    Ok(())
}

impl Meter {
    /// Canonical floors are cumulative purchased bytes, never delivery. Keep
    /// this journal for the plan lifetime: reconnect cannot reset consumption.
    pub async fn open(
        directory: PathBuf,
        binding: Binding,
        tariff: Tariff,
        original_budget_ou: u64,
        canonical_totals: Vec<u64>,
    ) -> Result<Arc<Self>> {
        Self::open_mode(
            directory,
            binding,
            tariff,
            original_budget_ou,
            canonical_totals,
            false,
        )
        .await
    }

    /// Existing-only recovery creates no directory, lease or empty journal.
    pub async fn resume(
        directory: PathBuf,
        binding: Binding,
        tariff: Tariff,
        original_budget_ou: u64,
        canonical_totals: Vec<u64>,
    ) -> Result<Arc<Self>> {
        Self::open_mode(
            directory,
            binding,
            tariff,
            original_budget_ou,
            canonical_totals,
            true,
        )
        .await
    }

    async fn open_mode(
        directory: PathBuf,
        binding: Binding,
        tariff: Tariff,
        original_budget_ou: u64,
        canonical_totals: Vec<u64>,
        existing_only: bool,
    ) -> Result<Arc<Self>> {
        tokio::task::spawn_blocking(move || {
            Self::open_sync(
                &directory,
                binding,
                tariff,
                original_budget_ou,
                &canonical_totals,
                existing_only,
            )
        })
        .await?
    }
    fn open_sync(
        directory: &Path,
        binding: Binding,
        tariff: Tariff,
        budget_ou: u64,
        canonical: &[u64],
        existing_only: bool,
    ) -> Result<Arc<Self>> {
        binding.validate()?;
        let tariff_hash = tariff.hash_hex()?;
        ensure!(
            binding.manifest_hash == tariff_hash,
            "meter tariff does not match accepted manifest"
        );
        Budget::new(tariff.clone(), budget_ou, canonical.to_vec())?;
        let (disk, saved) = if existing_only {
            Disk::resume(directory)?
        } else {
            Disk::open(directory)?
        };
        ensure!(
            !existing_only || saved.is_some(),
            "no existing payment delivery journal"
        );
        let mut record = match saved {
            Some(record) => {
                ensure!(
                    record.binding == binding
                        && record.tariff_hash == tariff_hash
                        && record.budget_ou == budget_ou,
                    "meter plan binding or budget differs"
                );
                ensure!(
                    record.purchased.len() == canonical.len()
                        && record.committed.len() == canonical.len(),
                    "meter canonical counter shape differs"
                );
                let capacity = Budget::new(tariff.clone(), budget_ou, sum(&record)?)?;
                check_prepaid(&record, &capacity, &tariff)?;
                record
            }
            None => Record {
                binding: binding.clone(),
                tariff_hash,
                budget_ou,
                committed: vec![0; canonical.len()],
                purchased: canonical.to_vec(),
                uncertain: vec![0; canonical.len()],
                pending: vec![0; canonical.len()],
                connect: None,
                transport: crate::stock::Transport::Framed,
                authorizations: vec![None; canonical.len()],
            },
        };
        ensure!(
            record.authorizations.len() == canonical.len(),
            "meter authorization shape differs"
        );
        if let Some(connect) = &record.connect {
            match &record.transport {
                crate::stock::Transport::Framed => connect.verify()?,
                crate::stock::Transport::Stock(_) => connect.verify_stock()?,
            }
            ensure!(
                connect.request.binding == binding,
                "stored connection binding differs"
            );
            if let crate::stock::Transport::Stock(registration) = &record.transport {
                ensure!(
                    registration.node_key == connect.request.wireguard_key,
                    "stored stock key differs"
                );
            }
        }
        for (class, usage) in record.authorizations.iter().enumerate() {
            if let Some(usage) = usage {
                usage.verify()?;
                ensure!(
                    usage.usage.binding() == binding
                        && usize::from(usage.usage.traffic_class) == class,
                    "stored usage binding or class differs"
                );
                ensure!(
                    record
                        .connect
                        .as_ref()
                        .is_some_and(|c| c.receipt_key == usage.receipt_key),
                    "stored usage receipt key differs"
                );
                ensure!(
                    usage.usage.total_bytes <= record.purchased[class],
                    "stored authorization exceeds canonical purchase"
                );
            }
        }
        for (class, &floor) in canonical.iter().enumerate() {
            ensure!(
                floor >= record.purchased[class],
                "meter canonical purchase moved backwards"
            );
            record.purchased[class] = floor;
            // A purchase never proves that a previously handed-off packet was
            // received. Recover pending IO as permanently held uncertainty.
            record.uncertain[class] = record.uncertain[class]
                .checked_add(record.pending[class])
                .context("meter uncertain overflow")?;
            record.pending[class] = 0;
        }
        let capacity = Budget::new(tariff.clone(), budget_ou, sum(&record)?)?;
        check_prepaid(&record, &capacity, &tariff)?;
        disk.persist(&record)?;
        let published = snapshot(&record, &capacity, &tariff)?;
        let current_connect = record.connect.clone();
        let transport = record.transport.clone();
        let receipts = record.authorizations.iter().flatten().cloned().collect();
        Ok(Arc::new(Self {
            binding,
            tariff,
            budget_ou,
            disk,
            writer: Mutex::new(State {
                record,
                capacity,
                pending: BTreeMap::new(),
                next_ticket: 1,
            }),
            published: RwLock::new(published),
            current_connect: RwLock::new(current_connect),
            receipts: RwLock::new(receipts),
            transport: RwLock::new(transport),
            connect_pending: AtomicBool::new(false),
            failed: AtomicBool::new(false),
        }))
    }
    pub fn binding(&self) -> &Binding {
        &self.binding
    }
    pub fn budget_ou(&self) -> u64 {
        self.budget_ou
    }
    pub fn tariff(&self) -> &Tariff {
        &self.tariff
    }
    pub fn snapshot(&self) -> Result<Snapshot> {
        self.available()?;
        let result = self.published.read().clone();
        self.available()?;
        Ok(result)
    }

    pub fn connect_is_current(&self, connect: &SignedConnect) -> bool {
        !self.failed.load(Ordering::Acquire)
            && !self.connect_pending.load(Ordering::Acquire)
            && self.current_connect.read().as_ref() == Some(connect)
            && !self.connect_pending.load(Ordering::Acquire)
            && !self.failed.load(Ordering::Acquire)
    }

    /// Reject public replays before the host suspends an existing connection.
    pub fn check_connect(&self, connect: &SignedConnect) -> Result<()> {
        self.check_connect_mode(connect, false)
    }
    fn check_connect_mode(&self, connect: &SignedConnect, stock: bool) -> Result<()> {
        self.available()?;
        if stock {
            connect.verify_stock()?;
        } else {
            connect.verify()?;
        }
        ensure!(
            connect.request.binding == self.binding,
            "connection plan differs"
        );
        ensure!(
            !self.connect_pending.load(Ordering::Acquire),
            "connection rotation pending"
        );
        check_previous(self.current_connect.read().as_ref(), connect)?;
        ensure!(
            !self.connect_pending.load(Ordering::Acquire),
            "connection rotation pending"
        );
        self.available()
    }

    pub(crate) fn check_transport(
        &self,
        connect: &SignedConnect,
        transport: &crate::stock::Transport,
    ) -> Result<()> {
        self.check_connect_mode(
            connect,
            matches!(transport, crate::stock::Transport::Stock(_)),
        )?;
        if let crate::stock::Transport::Stock(registration) = transport {
            ensure!(
                registration.node_key == connect.request.wireguard_key,
                "stock framing key differs"
            );
        }
        if self
            .current_connect
            .read()
            .as_ref()
            .is_some_and(|old| old.request.sequence == connect.request.sequence)
        {
            ensure!(
                *self.transport.read() == *transport,
                "connection framing or registration differs; signed rotation required"
            );
        }
        Ok(())
    }
    pub(crate) fn transport_is_current(
        &self,
        connect: &SignedConnect,
        transport: &crate::stock::Transport,
    ) -> bool {
        self.connect_is_current(connect)
            && *self.transport.read() == *transport
            && self.connect_is_current(connect)
    }

    /// Highest durable payer authorization per class, for settlement recovery.
    pub fn authorizations(&self) -> Result<Vec<SignedUsage>> {
        self.available()?;
        let result = self.receipts.read().clone();
        self.available()?;
        Ok(result)
    }

    /// Authenticate a purchase within the original plan budget, before delivery.
    /// Previously covered cumulative
    /// authorizations remain valid retries regardless of their sequence.
    pub fn check_usage(&self, usage: &SignedUsage) -> Result<()> {
        self.available()?;
        usage.verify()?;
        ensure!(usage.usage.binding() == self.binding, "usage plan differs");
        ensure!(
            self.current_connect
                .read()
                .as_ref()
                .is_some_and(|c| c.receipt_key == usage.receipt_key),
            "usage receipt key differs from current connection"
        );
        let mut purchased = self.snapshot()?.purchased_totals;
        let floor = purchased
            .get_mut(usize::from(usage.usage.traffic_class))
            .context("usage class missing")?;
        *floor = (*floor).max(usage.usage.total_bytes);
        ensure!(
            self.tariff.total_charge(&purchased)? <= self.budget_ou,
            "purchase exceeds original plan budget"
        );
        self.available()
    }

    /// Record a purchase authorization only after its exact canonical byte floor
    /// was authenticated and reconciled. A signature never grants capacity.
    pub async fn accept_usage(self: &Arc<Self>, usage: SignedUsage) -> Result<()> {
        self.check_usage(&usage)?;
        let meter = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut state = meter.writer.lock();
            meter.available()?;
            ensure!(
                state
                    .record
                    .connect
                    .as_ref()
                    .is_some_and(|c| c.receipt_key == usage.receipt_key),
                "usage receipt key differs from current connection"
            );
            let class = usize::from(usage.usage.traffic_class);
            let purchased = state
                .record
                .purchased
                .get(class)
                .context("usage class missing")?;
            ensure!(
                usage.usage.total_bytes <= *purchased,
                "authorization exceeds canonical purchase"
            );
            if let Some(previous) = &state.record.authorizations[class] {
                // AML settles the greatest cumulative byte authorization.
                // A higher sequence cannot revoke a larger earlier receipt.
                if usage.usage.total_bytes <= previous.usage.total_bytes {
                    return Ok(());
                }
            }
            let mut record = state.record.clone();
            record.authorizations[class] = Some(usage);
            meter.persist(&record)?;
            state.record = record;
            *meter.receipts.write() = state
                .record
                .authorizations
                .iter()
                .flatten()
                .cloned()
                .collect();
            Ok(())
        })
        .await?
    }
    /// Persist the receipt-key-authorized connection watermark before exposing
    /// its WG identity. An identical retry is idempotent; older keys cannot be
    /// reactivated after rotation or restart.
    pub async fn connect(self: &Arc<Self>, connect: SignedConnect) -> Result<()> {
        self.connect_transport(connect, crate::stock::Transport::Framed)
            .await
    }
    pub(crate) async fn connect_transport(
        self: &Arc<Self>,
        connect: SignedConnect,
        transport: crate::stock::Transport,
    ) -> Result<()> {
        self.check_transport(&connect, &transport)?;
        if self.transport_is_current(&connect, &transport) {
            return Ok(());
        }
        ensure!(
            self.connect_pending
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            "connection rotation pending"
        );
        let meter = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut state = meter.writer.lock();
            meter.available()?;
            if let Err(error) = check_previous(state.record.connect.as_ref(), &connect) {
                // A competing completed rotation can make a precheck stale.
                // No write occurred: keep that newer published identity.
                meter.connect_pending.store(false, Ordering::Release);
                return Err(error);
            }
            let mut record = state.record.clone();
            if state
                .record
                .connect
                .as_ref()
                .is_some_and(|old| old.request.sequence == connect.request.sequence)
            {
                ensure!(
                    state.record.transport == transport,
                    "connection transport changed"
                );
            }
            record.connect = Some(connect.clone());
            record.transport = transport.clone();
            meter.persist(&record)?;
            state.record = record;
            *meter.transport.write() = transport;
            *meter.current_connect.write() = Some(connect);
            meter.connect_pending.store(false, Ordering::Release);
            Ok(())
        })
        .await?
    }

    /// Reconcile authenticated cumulative purchased bytes without resetting
    /// outstanding packet reservations or releasing uncertain capacity.
    pub async fn reconcile(self: &Arc<Self>, canonical: Vec<u64>) -> Result<()> {
        let meter = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut state = meter.writer.lock();
            meter.available()?;
            ensure!(
                canonical.len() == state.record.purchased.len(),
                "canonical class shape differs"
            );
            let mut record = state.record.clone();
            for (class, floor) in canonical.into_iter().enumerate() {
                ensure!(
                    floor >= record.purchased[class],
                    "canonical purchase regressed"
                );
                record.purchased[class] = floor;
            }
            check_prepaid(&record, &state.capacity, &meter.tariff)?;
            if record.purchased != state.record.purchased {
                meter.persist(&record)?;
                state.record = record;
                meter.publish(&state)?;
            }
            Ok(())
        })
        .await?
    }
    fn available(&self) -> Result<()> {
        ensure!(
            !self.failed.load(Ordering::Acquire),
            "meter unavailable after persistence failure"
        );
        Ok(())
    }
    fn publish(&self, state: &State) -> Result<()> {
        *self.published.write() = snapshot(&state.record, &state.capacity, &self.tariff)?;
        Ok(())
    }
    fn persist(&self, record: &Record) -> Result<()> {
        if let Err(error) = self.disk.persist(record) {
            self.failed.store(true, Ordering::Release);
            return Err(error);
        }
        Ok(())
    }
    pub async fn reserve(self: &Arc<Self>, packet: &[u8], direction: Direction) -> Result<Ticket> {
        self.available()?;
        let class = self.tariff.classify_ipv4(packet, direction)?;
        self.reserve_class(class, u64::try_from(packet.len())?)
            .await
    }
    /// For callers that already validated and classified an observable packet.
    /// Peer input must never select a cheaper class directly.
    pub async fn reserve_class(self: &Arc<Self>, class: u8, bytes: u64) -> Result<Ticket> {
        let meter = self.clone();
        tokio::task::spawn_blocking(move || meter.reserve_sync(class, bytes)).await?
    }
    fn reserve_sync(self: &Arc<Self>, class: u8, bytes: u64) -> Result<Ticket> {
        self.available()?;
        ensure!(bytes > 0, "empty meter reservation");
        let mut state = self.writer.lock();
        self.available()?;
        ensure!(
            state.pending.len() < MAX_PENDING,
            "meter pending capacity exhausted"
        );
        let id = state.next_ticket;
        let next = id
            .checked_add(1)
            .context("meter ticket counter exhausted")?;
        let index = usize::from(class);
        let next_pending = state
            .record
            .pending
            .get(index)
            .ok_or(octravpn_core::payments::Error::UnknownClass(class))?
            .checked_add(bytes)
            .context("meter pending overflow")?;
        let mut capacity = state.capacity.clone();
        capacity.reserve(class, bytes)?;
        let mut record = state.record.clone();
        record.pending[index] = next_pending;
        check_prepaid(&record, &capacity, &self.tariff)?;
        self.persist(&record)?;
        state.record = record;
        state.capacity = capacity;
        state.pending.insert(id, (index, bytes));
        state.next_ticket = next;
        self.publish(&state)?;
        Ok(Ticket {
            meter: self.clone(),
            id: Some(id),
        })
    }
    fn commit_sync(&self, id: u64) -> Result<Snapshot> {
        let mut state = self.writer.lock();
        self.available()?;
        let &(class, bytes) = state
            .pending
            .get(&id)
            .context("meter reservation not found")?;
        let mut record = state.record.clone();
        record.pending[class] = record.pending[class]
            .checked_sub(bytes)
            .context("meter pending underflow")?;
        record.committed[class] = record.committed[class]
            .checked_add(bytes)
            .context("meter committed overflow")?;
        self.persist(&record)?;
        state.record = record;
        state.pending.remove(&id);
        self.publish(&state)?;
        self.snapshot()
    }
    fn cancel_sync(&self, id: u64) -> Result<()> {
        let mut state = self.writer.lock();
        self.available()?;
        let &(class, bytes) = state
            .pending
            .get(&id)
            .context("meter reservation not found")?;
        let mut record = state.record.clone();
        record.pending[class] = record.pending[class]
            .checked_sub(bytes)
            .context("meter pending underflow")?;
        let capacity = Budget::new(self.tariff.clone(), self.budget_ou, sum(&record)?)?;
        self.persist(&record)?;
        state.record = record;
        state.capacity = capacity;
        state.pending.remove(&id);
        self.publish(&state)
    }
    fn abandon_sync(&self, id: u64) -> Result<()> {
        let mut state = self.writer.lock();
        self.available()?;
        let &(class, bytes) = state
            .pending
            .get(&id)
            .context("meter reservation not found")?;
        let mut record = state.record.clone();
        record.pending[class] = record.pending[class]
            .checked_sub(bytes)
            .context("meter pending underflow")?;
        record.uncertain[class] = record.uncertain[class]
            .checked_add(bytes)
            .context("meter uncertain overflow")?;
        // Pending and uncertain capacity have the same liability, and neither
        // is exposed as confirmed delivery to a receipt signer.
        self.persist(&record)?;
        state.record = record;
        state.pending.remove(&id);
        self.publish(&state)
    }
}

impl Ticket {
    /// Invoke only after the packet was successfully forwarded. A commit error
    /// poisons further admission; the durable pre-send pending record protects
    /// capacity on restart even when confirmed delivery could not be persisted.
    pub async fn commit(mut self) -> Result<Snapshot> {
        let id = self.id.take().context("meter ticket already completed")?;
        let meter = self.meter.clone();
        tokio::task::spawn_blocking(move || meter.commit_sync(id)).await?
    }
    /// Release capacity only when the caller knows the packet was not sent.
    /// Cancellation with an unknown send outcome must drop the ticket instead.
    pub async fn cancel(mut self) -> Result<()> {
        let id = self.id.take().context("meter ticket already completed")?;
        let meter = self.meter.clone();
        tokio::task::spawn_blocking(move || meter.cancel_sync(id)).await?
    }
}
impl Drop for Ticket {
    fn drop(&mut self) {
        let Some(id) = self.id.take() else {
            return;
        };
        let meter = self.meter.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn_blocking(move || {
                let _ = meter.abandon_sync(id);
            });
        } else {
            let _ = meter.abandon_sync(id);
        }
    }
}

#[cfg(all(test, unix))]
mod tests;
