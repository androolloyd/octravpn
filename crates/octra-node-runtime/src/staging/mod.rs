// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native pending-transaction queue and block selection. Admission (authentication,
//! release rules and preverification) belongs to the host and must precede use.
//! Clock and canonical account reads are explicit; indexes retain native ordering.
mod index;
pub mod intake;
pub mod preview;
use index::{Eviction, Recent, Selection};
use num_bigint::BigInt;
use num_traits::{Signed, Zero};
use octra_node_protocol::{
    duty,
    transaction::{Nonce, OpType, RuleMode, Transaction},
    transaction_policy,
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
};

pub const MAX_OU: u64 = 10_000_000_000;
pub const MAX_TRANSACTIONS: usize = 100_000;
pub const TTL: f64 = 600.;
pub const MAX_DROPS: usize = 10_000;
type ViewKey = (Vec<u8>, Nonce, Vec<u8>);
type Lookup<'a> = &'a dyn Fn(&[u8]) -> Option<(BigInt, Nonce)>;
type Confirmed<'a> = &'a dyn Fn(&[u8]) -> Option<Nonce>;

#[derive(Clone, Debug)]
pub struct Limits {
    pub ou: BigInt,
    pub transactions: i64,
    pub stealth_minimum: BigInt,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            ou: MAX_OU.into(),
            transactions: MAX_TRANSACTIONS as i64,
            stealth_minimum: 5000.into(),
        }
    }
}
#[derive(Clone, Debug)]
pub struct Entry {
    pub tx: Transaction,
    pub cost: BigInt,
    pub added_at: f64,
    pub hash: Vec<u8>,
    key: Vec<u8>,
}
impl Entry {
    fn view_key(&self) -> ViewKey {
        (self.tx.from.clone(), self.tx.nonce, self.hash.clone())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    Evicted,
    Expired,
}
#[derive(Clone, Debug)]
pub struct DropRecord {
    pub hash: Vec<u8>,
    pub from: Vec<u8>,
    pub to: Vec<u8>,
    pub nonce: Nonce,
    pub ou: BigInt,
    pub operation: OpType,
    pub reason: DropReason,
    pub detail: String,
    pub timestamp: f64,
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum QueueState {
    Ready { expires_at: f64 },
    WaitNonce { expected: Nonce, expires_at: f64 },
    NonceUsed { confirmed: Nonce, expires_at: f64 },
}
#[derive(Default, Debug)]
pub struct Pool {
    entries: BTreeMap<Vec<u8>, Arc<Entry>>,
    hashes: BTreeMap<Vec<u8>, Arc<Entry>>,
    view: BTreeMap<ViewKey, Arc<Entry>>,
    eviction: BTreeSet<Eviction>,
    recent: BTreeSet<Recent>,
    total: BigInt,
    balances: BTreeMap<Vec<u8>, BigInt>,
    nonces: BTreeMap<Vec<u8>, Nonce>,
    preview: preview::State,
    held: BTreeMap<Vec<u8>, i64>,
    drops: BTreeMap<Vec<u8>, DropRecord>,
}
pub fn public_cost(tx: &Transaction) -> BigInt {
    match tx.op_type {
        OpType::Decrypt | OpType::Claim | OpType::Stealth | OpType::Private => tx.ou.clone(),
        _ => &tx.amount + &tx.ou,
    }
}
fn key(tx: &Transaction) -> Vec<u8> {
    let mut key = tx.from.clone();
    key.extend(tx.nonce.get().to_string().as_bytes());
    key
}
impl Pool {
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn total_ou(&self) -> &BigInt {
        &self.total
    }
    pub fn find(&self, hash: &[u8]) -> Option<&Transaction> {
        self.hashes.get(hash).map(|e| &e.tx)
    }
    pub fn all(&self) -> impl Iterator<Item = &Transaction> {
        self.view.values().map(|e| &e.tx)
    }
    pub fn sample(&self, limit: usize) -> impl Iterator<Item = &Entry> {
        self.view.values().take(limit).map(AsRef::as_ref)
    }
    pub fn recent(&self, limit: usize) -> impl Iterator<Item = &Entry> {
        self.recent.iter().take(limit).map(|e| e.0.as_ref())
    }
    pub fn virtual_balance(&self, sender: &[u8]) -> Option<&BigInt> {
        self.balances.get(sender)
    }
    pub fn expected_nonce(&self, sender: &[u8]) -> Nonce {
        self.nonces
            .get(sender)
            .copied()
            .unwrap_or_default()
            .successor()
    }
    pub fn drops(&self) -> impl Iterator<Item = &DropRecord> {
        self.drops.values()
    }
    pub fn dropped(&self, hash: &[u8]) -> Option<&DropRecord> {
        self.drops.get(hash)
    }
    pub fn cleanup_dropped(&mut self, now: f64) {
        self.drops.retain(|_, d| {
            (now - d.timestamp).partial_cmp(&TTL) != Some(std::cmp::Ordering::Greater)
        });
    }
    /// As in native Tx_staging.clear, epoch refusals and drop history survive.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.hashes.clear();
        self.view.clear();
        self.eviction.clear();
        self.recent.clear();
        self.balances.clear();
        self.nonces.clear();
        self.held.clear();
        self.total = BigInt::zero();
    }
    pub fn preview(&mut self, message: preview::Message) -> Result<(), &'static str> {
        let result = self.preview.step(MAX_TRANSACTIONS, &message);
        match message {
            preview::Message::Hold { head, hash, .. } if result.is_ok() => {
                if self.hashes.contains_key(&hash) {
                    self.held.insert(hash, head);
                }
            }
            preview::Message::Check(_, hash) | preview::Message::Ready(_, hash)
                if self.held.get(&hash) == Some(&self.preview.head) =>
            {
                return Err("preview refused in this epoch");
            }
            _ => {}
        }
        result
    }
    fn sender_entries<'a>(&'a self, sender: &'a [u8]) -> impl Iterator<Item = &'a Arc<Entry>> {
        self.view
            .range((sender.to_vec(), Nonce::MIN, Vec::new())..)
            .take_while(move |((address, _, _), _)| address.as_slice() == sender)
            .map(|(_, e)| e)
    }
    fn has_pending(&self, sender: &[u8]) -> bool {
        self.sender_entries(sender).next().is_some()
    }
    pub fn first_missing_nonce(&self, sender: &[u8], confirmed: Nonce) -> Nonce {
        let mut expected = confirmed.successor();
        for entry in self.sender_entries(sender) {
            if entry.tx.nonce == expected {
                expected = expected.successor();
            } else if entry.tx.nonce > expected {
                break;
            }
        }
        expected
    }
    pub fn pending_nonce(&self, sender: &[u8], confirmed: Nonce) -> Nonce {
        self.sender_entries(sender)
            .fold(confirmed, |n, e| n.max(e.tx.nonce))
    }
    pub fn duty_nonce(&self, sender: &[u8], confirmed: Nonce) -> Option<Nonce> {
        if confirmed.get() < 0 || confirmed == Nonce::MAX {
            return None;
        }
        let next = confirmed.successor();
        (!self.sender_entries(sender).any(|e| e.tx.nonce == next)).then_some(next)
    }
    pub fn queue_state(&self, hash: &[u8], confirmed: Nonce) -> Option<QueueState> {
        let entry = self.hashes.get(hash)?;
        let expires_at = entry.added_at + TTL;
        Some(if entry.tx.nonce <= confirmed {
            QueueState::NonceUsed {
                confirmed,
                expires_at,
            }
        } else {
            let expected = self.first_missing_nonce(&entry.tx.from, confirmed);
            if expected < entry.tx.nonce {
                QueueState::WaitNonce {
                    expected,
                    expires_at,
                }
            } else {
                QueueState::Ready { expires_at }
            }
        })
    }
    fn initialize(&mut self, sender: &[u8], lookup: Lookup<'_>) -> Result<(), &'static str> {
        if !self.has_pending(sender) {
            let (balance, nonce) = lookup(sender).unwrap_or_default();
            self.balances.insert(sender.to_vec(), balance);
            self.nonces.insert(sender.to_vec(), nonce);
            Ok(())
        } else if self.balances.contains_key(sender) && self.nonces.contains_key(sender) {
            Ok(())
        } else {
            Err("staging sender state is inconsistent")
        }
    }
    fn affordable(&self, sender: &[u8], cost: &BigInt) -> bool {
        self.balances.get(sender).is_some_and(|b| b >= cost)
    }
    /// Correct the native cache after canonical debits or credits. Keep the raw
    /// queue transition available for pinned parity; live intake refreshes before
    /// admission so removing a committed reservation cannot inflate spendable funds.
    pub(crate) fn refresh_balance(&mut self, sender: &[u8], confirmed: BigInt) {
        if self.has_pending(sender)
            && self.balances.contains_key(sender)
            && self.nonces.contains_key(sender)
        {
            let reserved: BigInt = self
                .sender_entries(sender)
                .map(|e| public_cost(&e.tx))
                .sum();
            self.balances.insert(sender.to_vec(), confirmed - reserved);
        }
    }
    fn insert(&mut self, tx: Transaction, cost: BigInt, hash: Vec<u8>, now: f64) {
        *self.balances.get_mut(&tx.from).expect("initialized sender") -= public_cost(&tx);
        self.nonces
            .entry(tx.from.clone())
            .and_modify(|n| *n = (*n).max(tx.nonce));
        self.total += &cost;
        let entry = Arc::new(Entry {
            key: key(&tx),
            tx,
            cost,
            hash,
            added_at: now,
        });
        self.entries.insert(entry.key.clone(), entry.clone());
        self.hashes.insert(entry.hash.clone(), entry.clone());
        self.view.insert(entry.view_key(), entry.clone());
        self.eviction.insert(Eviction(entry.clone()));
        self.recent.insert(Recent(entry));
    }
    fn evict(&mut self, entry: &Arc<Entry>) {
        self.entries.remove(&entry.key);
        self.hashes.remove(&entry.hash);
        self.held.remove(&entry.hash);
        self.view.remove(&entry.view_key());
        self.eviction.remove(&Eviction(entry.clone()));
        self.recent.remove(&Recent(entry.clone()));
        self.total -= &entry.cost;
        *self
            .balances
            .get_mut(&entry.tx.from)
            .expect("initialized sender") += public_cost(&entry.tx);
    }
    fn record_drop(
        &mut self,
        entry: &Entry,
        reason: DropReason,
        detail: &'static str,
        expiry_detail: Option<String>,
        now: f64,
    ) -> DropRecord {
        // Native Hashtbl iteration breaks equal-time ties arbitrarily. This local
        // diagnostic cache uses hash order; it never affects selection or state.
        if self.drops.len() >= MAX_DROPS {
            let oldest = self
                .drops
                .iter()
                .reduce(|a, b| if b.1.timestamp < a.1.timestamp { b } else { a })
                .map(|(h, _)| h.clone());
            if let Some(hash) = oldest {
                self.drops.remove(&hash);
            }
        }
        let record = DropRecord {
            hash: entry.hash.clone(),
            from: entry.tx.from.clone(),
            to: entry.tx.to.clone(),
            nonce: entry.tx.nonce,
            ou: entry.tx.ou.clone(),
            operation: entry.tx.op_type,
            reason,
            detail: expiry_detail.unwrap_or_else(|| detail.into()),
            timestamp: now,
        };
        self.drops.insert(record.hash.clone(), record.clone());
        record
    }
    pub fn add(
        &mut self,
        tx: Transaction,
        limits: &Limits,
        head: Option<i64>,
        lookup: Lookup<'_>,
        clock: &dyn Fn() -> f64,
    ) -> Result<Vec<DropRecord>, String> {
        let hash = hex::encode(tx.hash().map_err(|e| e.to_string())?).into_bytes();
        self.preview(preview::Message::Check(head, hash.clone()))?;
        let cost = transaction_policy::ou_cost(&tx, &limits.stealth_minimum);
        let total_cost = public_cost(&tx);
        self.initialize(&tx.from, lookup)?;
        let base = lookup(&tx.from).unwrap_or_default().1;
        let threshold = (base.get().wrapping_add(1000) << 1) >> 1;
        if !limits.ou.is_positive() || limits.transactions <= 0 {
            return Err("staging limits must be positive".into());
        }
        if tx.nonce <= base {
            return Err("nonce too low (already used)".into());
        }
        if tx.nonce.get() > threshold {
            return Err("nonce too far ahead".into());
        }
        if cost > limits.ou {
            return Err("transaction too large for staging capacity".into());
        }
        let mut drops = Vec::new();
        if let Some(old) = self.entries.get(&key(&tx)).cloned() {
            if &tx.ou * &old.cost * 100 < &old.tx.ou * &cost * 110 {
                return Err("duplicate nonce (fee rate bump < 10%)".into());
            }
            let next = &self.total - &old.cost + &cost;
            let delta = &total_cost - public_cost(&old.tx);
            if next > limits.ou || self.len() as i64 > limits.transactions {
                return Err("staging full (insufficient evictable capacity)".into());
            }
            if delta.is_positive() && !self.affordable(&tx.from, &delta) {
                return Err("insufficient balance for replacement".into());
            }
            self.evict(&old);
            drops.push(self.record_drop(
                &old,
                DropReason::Evicted,
                "replaced by higher fee-rate",
                None,
                clock(),
            ));
        } else {
            if !self.affordable(&tx.from, &total_cost) {
                return Err("insufficient balance (including pending)".into());
            }
            if &self.total + &cost > limits.ou || self.len() as i64 >= limits.transactions {
                let deficit = (&self.total + &cost - &limits.ou).max(BigInt::zero());
                let count_deficit = (self.len() as i64 + 1 - limits.transactions).max(0);
                let candidate = self
                    .eviction
                    .first()
                    .filter(|e| {
                        count_deficit <= 1
                            && e.0.cost >= deficit
                            && &tx.ou * &e.0.cost > &e.0.tx.ou * &cost
                    })
                    .map(|e| e.0.clone())
                    .ok_or("staging full (insufficient evictable capacity)")?;
                self.evict(&candidate);
                drops.push(self.record_drop(
                    &candidate,
                    DropReason::Evicted,
                    "outbid by higher fee-rate",
                    None,
                    clock(),
                ));
                let dependents: Vec<_> = self
                    .sender_entries(&candidate.tx.from)
                    .filter(|e| e.tx.nonce > candidate.tx.nonce)
                    .cloned()
                    .collect();
                for entry in dependents {
                    self.evict(&entry);
                    drops.push(self.record_drop(
                        &entry,
                        DropReason::Evicted,
                        "nonce gap from eviction",
                        None,
                        clock(),
                    ));
                }
            }
        }
        self.insert(tx, cost, hash, clock());
        Ok(drops)
    }
    fn select(
        &self,
        capacity: &BigInt,
        confirmed: Option<Confirmed<'_>>,
        accept: &dyn Fn(&Transaction) -> bool,
    ) -> Vec<Arc<Entry>> {
        let mut queues: BTreeMap<Vec<u8>, VecDeque<Arc<Entry>>> = BTreeMap::new();
        for e in self.view.values() {
            queues
                .entry(e.tx.from.clone())
                .or_default()
                .push_back(e.clone());
        }
        if let Some(confirmed) = confirmed {
            for (sender, queue) in &mut queues {
                let Some(mut expected) = confirmed(sender)
                    .filter(|n| n.get() >= 0 && *n != Nonce::MAX)
                    .map(Nonce::successor)
                else {
                    queue.clear();
                    continue;
                };
                let mut ready = VecDeque::new();
                for e in queue.iter().filter(|e| accept(&e.tx)) {
                    if e.tx.nonce < expected {
                        continue;
                    }
                    if e.tx.nonce > expected {
                        break;
                    }
                    ready.push_back(e.clone());
                    if expected == Nonce::MAX {
                        break;
                    }
                    expected = expected.successor();
                }
                *queue = ready;
            }
        }
        let mut heads: BTreeSet<_> = queues
            .values()
            .filter_map(|q| q.front().cloned().map(Selection))
            .collect();
        let mut used = BigInt::zero();
        let mut batch = Vec::new();
        while let Some(Selection(entry)) = heads.pop_first() {
            let queue = queues.get_mut(&entry.tx.from).expect("selection sender");
            if &used + &entry.cost > *capacity {
                queue.clear();
                continue;
            }
            used += &entry.cost;
            batch.push(entry);
            queue.pop_front();
            if let Some(next) = queue.front() {
                heads.insert(Selection(next.clone()));
            }
        }
        batch
    }
    pub fn epoch(&self, capacity: &BigInt) -> Vec<Arc<Entry>> {
        self.select(capacity, None, &|_| true)
    }
    pub fn ready_epoch(
        &self,
        capacity: &BigInt,
        confirmed: Confirmed<'_>,
        accept: &dyn Fn(&Transaction) -> bool,
    ) -> Vec<Arc<Entry>> {
        self.select(capacity, Some(confirmed), accept)
    }
    pub fn remove(&mut self, hash: &[u8]) -> bool {
        let Some(entry) = self.hashes.get(hash).cloned() else {
            return false;
        };
        self.evict(&entry);
        true
    }
    fn clear_virtual(&mut self, touched: BTreeSet<Vec<u8>>) {
        for sender in touched {
            if !self.has_pending(&sender) {
                self.balances.remove(&sender);
                self.nonces.remove(&sender);
            }
        }
    }
    pub fn remove_processed(&mut self, hashes: &[Vec<u8>]) {
        let mut touched = BTreeSet::new();
        for hash in hashes {
            if let Some(e) = self.hashes.get(hash) {
                touched.insert(e.tx.from.clone());
            }
            self.remove(hash);
        }
        self.clear_virtual(touched);
    }
    pub fn drop_preview(&mut self, hash: &[u8], now: f64) -> Option<DropRecord> {
        let entry = self.hashes.get(hash)?.clone();
        self.remove_processed(&[hash.to_vec()]);
        Some(self.record_drop(&entry, DropReason::Evicted, "preview rejected", None, now))
    }
    pub fn expire_duty(
        &mut self,
        sender: Option<&[u8]>,
        head: Option<i64>,
        mode: RuleMode,
        clock: &dyn Fn() -> f64,
    ) -> Vec<DropRecord> {
        let expired: Vec<_> = self
            .view
            .values()
            .filter(|e| sender.is_none_or(|s| e.tx.from == s) && duty::expired(&e.tx, head, mode))
            .cloned()
            .collect();
        let drops = expired
            .iter()
            .map(|e| {
                self.record_drop(
                    e,
                    DropReason::Expired,
                    "validator ready head has expired",
                    None,
                    clock(),
                )
            })
            .collect();
        self.remove_processed(&expired.iter().map(|e| e.hash.clone()).collect::<Vec<_>>());
        drops
    }
    pub fn expire_old(
        &mut self,
        confirmed: Confirmed<'_>,
        clock: &dyn Fn() -> f64,
    ) -> Vec<DropRecord> {
        let now = clock();
        // Native expiry output follows Hashtbl iteration, not consensus ordering.
        let expired: Vec<_> = self
            .entries
            .values()
            .filter(|e| now - e.added_at > TTL)
            .cloned()
            .collect();
        let mut touched = BTreeSet::new();
        let mut confirmed_cache = BTreeMap::new();
        let mut drops = Vec::new();
        for entry in expired {
            touched.insert(entry.tx.from.clone());
            self.evict(&entry);
            let nonce = confirmed_cache
                .entry(entry.tx.from.clone())
                .or_insert_with(|| confirmed(&entry.tx.from));
            let detail = nonce.map(|n| expiry_reason(n, entry.tx.nonce));
            drops.push(self.record_drop(
                &entry,
                DropReason::Expired,
                "TTL exceeded: transaction was not included",
                detail,
                clock(),
            ));
        }
        self.clear_virtual(touched);
        drops
    }
    pub fn usage_percent(&self) -> BigInt {
        &self.total * 100 / MAX_OU
    }
    pub fn min_relay_fee(&self, tx: &Transaction, minimum: &BigInt) -> BigInt {
        let usage = self.usage_percent();
        let base = transaction_policy::ou_cost(tx, minimum);
        if usage < 80.into() {
            base
        } else if usage < 95.into() {
            base * 2
        } else {
            base * 5
        }
    }
    pub fn stats(&self) -> BTreeMap<Vec<u8>, (usize, BigInt)> {
        let mut stats = BTreeMap::new();
        for tx in self.all() {
            let (count, total) = stats.entry(tx.from.clone()).or_insert((0, BigInt::zero()));
            *count += 1;
            *total += public_cost(tx);
        }
        stats
    }
}
pub fn expiry_reason(confirmed: Nonce, received: Nonce) -> String {
    let gap = received.get().wrapping_sub(confirmed.get());
    if gap > 1 {
        format!(
            "TTL exceeded: waiting for nonce {} before nonce {}",
            confirmed.successor().get(),
            received.get()
        )
    } else if gap <= 0 {
        format!(
            "TTL exceeded: nonce {} was already consumed at {}",
            received.get(),
            confirmed.get()
        )
    } else {
        "TTL exceeded: transaction was not included".into()
    }
}
