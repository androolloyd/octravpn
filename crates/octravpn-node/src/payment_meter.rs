//! Durable capacity reservations for one immutable payment plan.
//!
//! Reserve before forwarding, commit only after a successful send. A crash can
//! leave reserved capacity uncertain; it must never become billable delivery.
//! This deliberately fsyncs the packet journal and does not claim line-rate IO.
use anyhow::{ensure, Context, Result};
use octravpn_core::{
    payments::{Budget, Deployment, Direction, Tariff, Usage},
    Address,
};
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub deployment: Deployment,
    #[serde(with = "address")]
    pub payer: Address,
    pub generation: u64,
    pub plan: u64,
    pub offer: u64,
    pub manifest_hash: String,
}
impl Binding {
    fn validate(&self) -> Result<()> {
        Usage {
            deployment: self.deployment.clone(),
            payer: self.payer.clone(),
            generation: self.generation,
            plan: self.plan,
            offer: self.offer,
            manifest_hash: self.manifest_hash.clone(),
            traffic_class: 0,
            sequence: 1,
            total_bytes: 0,
        }
        .validate()?;
        Ok(())
    }
}
mod address {
    use octravpn_core::{parse_native_address, Address};
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};
    pub(super) fn serialize<S: Serializer>(
        value: &Address,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value.display())
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Address, D::Error> {
        parse_native_address(&String::deserialize(deserializer)?).map_err(D::Error::custom)
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
        tokio::task::spawn_blocking(move || {
            Self::open_sync(
                &directory,
                binding,
                tariff,
                original_budget_ou,
                &canonical_totals,
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
    ) -> Result<Arc<Self>> {
        binding.validate()?;
        let tariff_hash = tariff.hash_hex()?;
        ensure!(
            binding.manifest_hash == tariff_hash,
            "meter tariff does not match accepted manifest"
        );
        Budget::new(tariff.clone(), budget_ou, canonical.to_vec())?;
        let (disk, saved) = Disk::open(directory)?;
        let mut record = match saved {
            Some(record) => {
                ensure!(
                    record.binding == binding
                        && record.tariff_hash == tariff_hash
                        && record.budget_ou == budget_ou,
                    "meter plan binding or budget differs"
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
            },
        };
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
        disk.persist(&record)?;
        let published = snapshot(&record, &capacity, &tariff)?;
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
        state.capacity.reserve(class, bytes)?;
        let mut record = state.record.clone();
        record.pending[index] = next_pending;
        self.persist(&record)?;
        state.record = record;
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
