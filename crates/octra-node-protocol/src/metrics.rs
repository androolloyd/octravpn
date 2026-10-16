// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Local native metrics. These observations reset at process startup and never
//! enter a state root or certificate.
use crate::{
    light_rpc::json::{array, number, object, string},
    native_table::Table,
    oce1::Error,
    transaction::Transaction,
    transaction_policy,
};
use num_bigint::BigInt;
use num_traits::Zero;
pub const ADDRESS_LIMIT: usize = 4096;
#[derive(Clone, Debug, Default)]
pub struct Record {
    pub from: Vec<u8>,
    pub to: Vec<u8>,
    pub amount: BigInt,
    pub fee: BigInt,
}
impl Record {
    pub fn of_transaction(tx: &Transaction, stealth_minimum: &BigInt) -> Self {
        Self {
            from: tx.from.clone(),
            to: tx.to.clone(),
            amount: tx.amount.clone(),
            fee: transaction_policy::ou_cost(tx, stealth_minimum),
        }
    }
}
#[derive(Clone, Debug, Default)]
pub struct Epoch {
    pub transactions: Vec<Record>,
    pub duration: f64,
}
#[derive(Clone, Debug)]
pub struct Address {
    pub sent_count: i64,
    pub received_count: i64,
    pub total_sent: BigInt,
    pub total_received: BigInt,
    pub last_active: f64,
}
impl Address {
    fn new(now: f64) -> Self {
        Self {
            sent_count: 0,
            received_count: 0,
            total_sent: BigInt::zero(),
            total_received: BigInt::zero(),
            last_active: now,
        }
    }
    fn volume(&self) -> BigInt {
        &self.total_sent + &self.total_received
    }
}
#[derive(Clone, Debug)]
pub struct Stats {
    pub total_txs: i64,
    pub total_volume: BigInt,
    pub total_fees: BigInt,
    pub avg_tx_time: f64,
    pub peak_tps: f64,
    pub last_epoch_txs: i64,
    pub last_epoch_time: f64,
    addresses: Table<Address>,
    top: Vec<Vec<u8>>,
}
impl Default for Stats {
    fn default() -> Self {
        Self {
            total_txs: 0,
            total_volume: BigInt::zero(),
            total_fees: BigInt::zero(),
            avg_tx_time: 0.,
            peak_tps: 0.,
            last_epoch_txs: 0,
            last_epoch_time: 0.,
            addresses: Table::new(1000),
            top: vec![],
        }
    }
}
fn add(value: i64) -> i64 {
    value.wrapping_add(1).wrapping_shl(1) >> 1
}
pub fn format_balance(amount: &BigInt) -> String {
    let units: BigInt = amount / 1_000_000;
    let remainder: BigInt = amount % 1_000_000;
    if remainder.is_zero() {
        units.to_string()
    } else {
        format!("{units}.{remainder:06}")
    }
}
impl Stats {
    pub fn tracked_count(&self) -> usize {
        self.addresses.values().len()
    }
    fn update_address(&mut self, address: &[u8], sender: bool, amount: &BigInt, now: f64) {
        let mut stat = self
            .addresses
            .get(address)
            .cloned()
            .unwrap_or_else(|| Address::new(now));
        if self.addresses.get(address).is_none() && self.tracked_count() >= ADDRESS_LIMIT {
            let evict = self
                .addresses
                .keys()
                .find(|key| !self.top.iter().any(|v| v.as_slice() == *key))
                .map(<[u8]>::to_vec);
            if let Some(evict) = evict {
                self.addresses.remove(&evict);
            }
        }
        stat.last_active = now;
        if sender {
            stat.sent_count = add(stat.sent_count);
            stat.total_sent += amount;
        } else {
            stat.received_count = add(stat.received_count);
            stat.total_received += amount;
        }
        self.addresses.replace(address.to_vec(), stat);
        self.top.retain(|known| known != address);
        self.top.push(address.to_vec());
        self.top.sort_by(|a, b| {
            self.addresses
                .get(b)
                .expect("ranked address")
                .volume()
                .cmp(&self.addresses.get(a).expect("ranked address").volume())
                .then_with(|| a.cmp(b))
        });
        self.top.truncate(10);
    }
    pub fn record(&mut self, tx: &Record, mut now: impl FnMut() -> f64) {
        self.total_txs = add(self.total_txs);
        self.total_volume += &tx.amount;
        self.total_fees += &tx.fee;
        self.update_address(&tx.from, true, &tx.amount, now());
        self.update_address(&tx.to, false, &tx.amount, now());
    }
    pub fn record_tx(
        &mut self,
        tx: &Transaction,
        stealth_minimum: &BigInt,
        now: impl FnMut() -> f64,
    ) {
        self.record(&Record::of_transaction(tx, stealth_minimum), now);
    }
    // Match the native integer-to-float projection and rounding exactly.
    #[allow(clippy::cast_precision_loss)]
    pub fn record_epoch_complete(&mut self, count: i64, duration: f64) {
        self.last_epoch_txs = count;
        self.last_epoch_time = duration;
        if count > 0 && duration > 0. {
            let tps = count as f64 / duration;
            if tps > self.peak_tps {
                self.peak_tps = tps;
            }
        }
    }
    pub fn observe(&mut self, epoch: &Epoch, mut now: impl FnMut() -> f64) {
        for tx in &epoch.transactions {
            self.record(tx, &mut now);
        }
        self.record_epoch_complete(epoch.transactions.len() as i64, epoch.duration);
    }
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        let float = |v| {
            crate::transaction::native_float(v)
                .map(String::into_bytes)
                .map_err(|e| Error::from(e.to_string()))
        };
        let addresses = self
            .top
            .iter()
            .map(|addr| {
                let stat = self
                    .addresses
                    .get(addr)
                    .ok_or("ranked metric address unavailable")?;
                Ok(object(&[
                    ("address", string(addr)),
                    ("sent_count", number(stat.sent_count)),
                    ("received_count", number(stat.received_count)),
                    ("total_sent", string(format_balance(&stat.total_sent))),
                    (
                        "total_received",
                        string(format_balance(&stat.total_received)),
                    ),
                    ("total_volume", string(format_balance(&stat.volume()))),
                    ("last_active", float(stat.last_active)?),
                ]))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(object(&[
            ("total_transactions", number(self.total_txs)),
            ("total_volume", string(format_balance(&self.total_volume))),
            (
                "total_fees_collected",
                string(format_balance(&self.total_fees)),
            ),
            ("average_tx_time", float(self.avg_tx_time)?),
            ("peak_tps", float(self.peak_tps)?),
            ("last_epoch_txs", number(self.last_epoch_txs)),
            ("last_epoch_duration", float(self.last_epoch_time)?),
            ("top_addresses", array(addresses)),
        ]))
    }
}
