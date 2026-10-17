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
use serde::{Deserialize, Serialize};
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

/// Operator's explicit maximum postpaid exposure before another authorization.
/// Limits include pending and uncertain sends, across every traffic class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credit {
    pub max_unacknowledged_bytes: u64,
    pub max_unacknowledged_ou: u64,
}
impl Credit {
    /// Component/testing policy. Production hosts must choose bounded credit.
    pub const UNLIMITED: Self = Self {
        max_unacknowledged_bytes: u64::MAX,
        max_unacknowledged_ou: u64::MAX,
    };
    fn is_unlimited(&self) -> bool {
        *self == Self::UNLIMITED
    }
}
impl Default for Credit {
    fn default() -> Self {
        Self::UNLIMITED
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    /// Includes authenticated canonical redemption floors, never uncertain IO.
    pub committed_totals: Vec<u64>,
    pub redeemed_totals: Vec<u64>,
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
        redeemed_totals: record.redeemed.clone(),
        uncertain_totals: record.uncertain.clone(),
        pending_totals: record.pending.clone(),
        committed_charge_ou: tariff.total_charge(&record.committed)?,
        capacity_charge_ou: capacity.total_charge_ou(),
        remaining_ou: capacity.remaining_ou(),
    })
}

fn authorized(record: &Record) -> Result<Vec<u64>> {
    ensure!(
        record.authorizations.len() == record.redeemed.len(),
        "meter authorization shape differs"
    );
    Ok(record
        .authorizations
        .iter()
        .zip(&record.redeemed)
        .map(|(usage, redeemed)| {
            usage
                .as_ref()
                .map_or(*redeemed, |u| (*redeemed).max(u.usage.total_bytes))
        })
        .collect())
}
fn check_credit(record: &Record, capacity: &Budget, tariff: &Tariff) -> Result<()> {
    let authorized = authorized(record)?;
    let unacknowledged = capacity.totals().iter().zip(&authorized).try_fold(
        0_u128,
        |sum, (total, authorized)| -> Result<u128> {
            Ok(sum
                + u128::from(
                    total
                        .checked_sub(*authorized)
                        .context("authorized bytes exceed meter capacity")?,
                ))
        },
    )?;
    let unacknowledged_ou = capacity
        .total_charge_ou()
        .checked_sub(tariff.total_charge(&authorized)?)
        .context("authorized charge exceeds meter capacity")?;
    ensure!(
        record.credit.is_unlimited()
            || unacknowledged <= u128::from(record.credit.max_unacknowledged_bytes),
        "unacknowledged traffic byte credit exhausted"
    );
    ensure!(
        unacknowledged_ou <= record.credit.max_unacknowledged_ou,
        "unacknowledged traffic payment credit exhausted"
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
    /// The host supplies only authenticated, same-generation canonical floors.
    /// Original budget includes amounts already redeemed, not just the current
    /// on-chain remainder. Never delete this directory while a plan can reopen.
    pub async fn open(
        directory: PathBuf,
        binding: Binding,
        tariff: Tariff,
        original_budget_ou: u64,
        canonical_totals: Vec<u64>,
    ) -> Result<Arc<Self>> {
        Self::open_with_credit(
            directory,
            binding,
            tariff,
            original_budget_ou,
            canonical_totals,
            Credit::UNLIMITED,
        )
        .await
    }

    /// Production hosts set and persist their maximum unacknowledged exposure.
    pub async fn open_with_credit(
        directory: PathBuf,
        binding: Binding,
        tariff: Tariff,
        original_budget_ou: u64,
        canonical_totals: Vec<u64>,
        credit: Credit,
    ) -> Result<Arc<Self>> {
        Self::open_mode(
            directory,
            binding,
            tariff,
            original_budget_ou,
            canonical_totals,
            credit,
            false,
        )
        .await
    }

    /// Recover an existing delivery journal for settlement without creating
    /// a directory, writer lease or empty accounting record when absent.
    pub async fn resume_with_credit(
        directory: PathBuf,
        binding: Binding,
        tariff: Tariff,
        original_budget_ou: u64,
        canonical_totals: Vec<u64>,
        credit: Credit,
    ) -> Result<Arc<Self>> {
        Self::open_mode(
            directory,
            binding,
            tariff,
            original_budget_ou,
            canonical_totals,
            credit,
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
        credit: Credit,
        existing_only: bool,
    ) -> Result<Arc<Self>> {
        tokio::task::spawn_blocking(move || {
            Self::open_sync(
                &directory,
                binding,
                tariff,
                original_budget_ou,
                &canonical_totals,
                credit,
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
        credit: Credit,
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
                        && record.budget_ou == budget_ou
                        && record.credit == credit,
                    "meter plan binding, budget or credit differs"
                );
                ensure!(
                    record.redeemed.len() == canonical.len()
                        && record.committed.len() == canonical.len(),
                    "meter canonical counter shape differs"
                );
                Budget::new(tariff.clone(), budget_ou, sum(&record)?)?;
                record
            }
            None => Record {
                binding: binding.clone(),
                tariff_hash,
                budget_ou,
                committed: canonical.to_vec(),
                redeemed: canonical.to_vec(),
                uncertain: vec![0; canonical.len()],
                pending: vec![0; canonical.len()],
                connect: None,
                credit,
                authorizations: vec![None; canonical.len()],
            },
        };
        if record.authorizations.is_empty() {
            record.authorizations.resize(canonical.len(), None);
        }
        ensure!(
            record.authorizations.len() == canonical.len(),
            "meter authorization shape differs"
        );
        if let Some(connect) = &record.connect {
            connect.verify()?;
            ensure!(
                connect.request.binding == binding,
                "stored connection binding differs"
            );
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
                    usage.usage.total_bytes <= record.committed[class],
                    "stored authorization exceeds delivery"
                );
            }
        }
        let prior_capacity = sum(&record)?;
        for (class, &floor) in canonical.iter().enumerate() {
            ensure!(
                floor >= record.redeemed[class]
                    && record.redeemed[class] <= record.committed[class],
                "meter canonical counter moved backwards"
            );
            record.committed[class] = record.committed[class].max(floor);
            record.redeemed[class] = floor;
            // A canonical receipt can resolve some prior uncertain usage.
            record.uncertain[class] = prior_capacity[class].saturating_sub(record.committed[class]);
            record.pending[class] = 0;
        }
        let capacity = Budget::new(tariff.clone(), budget_ou, sum(&record)?)?;
        check_credit(&record, &capacity, &tariff)?;
        disk.persist(&record)?;
        let published = snapshot(&record, &capacity, &tariff)?;
        let current_connect = record.connect.clone();
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
            connect_pending: AtomicBool::new(false),
            failed: AtomicBool::new(false),
        }))
    }
    pub fn binding(&self) -> &Binding {
        &self.binding
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
        self.available()?;
        connect.verify()?;
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

    /// Highest durable payer authorization per class, for settlement recovery.
    pub fn authorizations(&self) -> Result<Vec<SignedUsage>> {
        self.available()?;
        let result = self.receipts.read().clone();
        self.available()?;
        Ok(result)
    }

    /// Authentication and delivery preflight. Previously covered cumulative
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
        let snapshot = self.snapshot()?;
        let committed = snapshot
            .committed_totals
            .get(usize::from(usage.usage.traffic_class))
            .context("usage class missing")?;
        ensure!(
            usage.usage.total_bytes <= *committed,
            "authorization exceeds confirmed delivery"
        );
        self.available()
    }

    /// The host invokes this only after the cumulative authorized charge is
    /// covered by canonical paid OU. A signature alone does not grant credit.
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
            let committed = state
                .record
                .committed
                .get(class)
                .context("usage class missing")?;
            ensure!(
                usage.usage.total_bytes <= *committed,
                "authorization exceeds confirmed delivery"
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
            ensure!(
                meter.tariff.total_charge(&authorized(&record)?)? <= meter.budget_ou,
                "authorized tariff charge exceeds plan budget"
            );
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
        self.check_connect(&connect)?;
        if self.connect_is_current(&connect) {
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
            record.connect = Some(connect.clone());
            meter.persist(&record)?;
            state.record = record;
            *meter.current_connect.write() = Some(connect);
            meter.connect_pending.store(false, Ordering::Release);
            Ok(())
        })
        .await?
    }

    /// Reconcile authenticated cumulative redemption floors without resetting
    /// outstanding packet reservations or releasing uncertain capacity.
    pub async fn reconcile(self: &Arc<Self>, canonical: Vec<u64>) -> Result<()> {
        let meter = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut state = meter.writer.lock();
            meter.available()?;
            ensure!(
                canonical.len() == state.record.redeemed.len(),
                "canonical class shape differs"
            );
            let mut record = state.record.clone();
            for (class, floor) in canonical.into_iter().enumerate() {
                ensure!(
                    floor >= record.redeemed[class],
                    "canonical redemption regressed"
                );
                // A live process only accepts claims for its committed usage.
                // Recovery of an external claim requires reopening the journal.
                ensure!(
                    floor <= record.committed[class],
                    "canonical usage exceeds local delivery"
                );
                record.redeemed[class] = floor;
            }
            if record.redeemed != state.record.redeemed {
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
        check_credit(&record, &capacity, &self.tariff)?;
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
