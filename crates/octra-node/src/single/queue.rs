use crate::executor::Native;
use anyhow::{ensure, Context, Result};
use octra_node_protocol::{
    native_json::Document,
    single::Preverify,
    state::Ledger,
    transaction::{Nonce, OpType, Transaction},
};
use octra_node_runtime::{
    account_store, admission,
    execution_rules::Bound,
    single_private,
    staging::{intake, Pool, PreviewState, MAX_TRANSACTIONS},
    state_batch::{Snapshot, StateBatch},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
const MAX_FRAME: usize = 128 * 1024 * 1024;
#[derive(Clone)]
pub(super) struct State {
    pub pool: Pool,
    pub deferred: single_private::Deferred,
    pub cache: BTreeMap<String, Preverify>,
    pub ready: BTreeMap<String, single_private::CacheBinding>,
    cache_times: octra_node_protocol::native_table::Table<f64>,
    pub kats: BTreeMap<Vec<u8>, Vec<u8>>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            pool: Pool::default(),
            deferred: single_private::Deferred::default(),
            cache: BTreeMap::new(),
            ready: BTreeMap::new(),
            cache_times: octra_node_protocol::native_table::Table::new(100),
            kats: BTreeMap::new(),
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    entries: Vec<Entry>,
    preview: PreviewState,
    deferred: single_private::Deferred,
    kats: Vec<(Vec<u8>, Vec<u8>)>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    raw: Vec<u8>,
    added_at: f64,
}
struct Effects;
impl intake::Host for Effects {
    fn preverify(&mut self, tx: &Transaction, _: &Pool) -> std::result::Result<(), String> {
        match octra_node_runtime::crypto_payload::encrypted_payload_ok(tx) {
            Ok(true) => Ok(()),
            Ok(false) => Err("malformed or oversized encrypted_data".into()),
            Err(e) => Err(format!("pre_verify_unavailable reason = {e}")),
        }
    }
    fn save_drops(&mut self, _: &[octra_node_runtime::staging::DropRecord]) {}
    fn invalidate(&mut self, _: &[u8]) {}
    fn changed(&mut self, _: &Pool) {}
    fn accepted(&mut self, _: &Transaction, _: &Pool) {}
}
impl State {
    pub(super) fn empty() -> Result<Vec<u8>> {
        Self::default().encode()
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>> {
        let saved = Saved {
            entries: self
                .pool
                .sample(MAX_TRANSACTIONS + 1)
                .map(|e| {
                    Ok(Entry {
                        raw: e.tx.to_json_bytes()?,
                        added_at: e.added_at,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            preview: self.pool.preview_state(),
            deferred: self.deferred.clone(),
            kats: self
                .kats
                .iter()
                .map(|(a, v)| (a.clone(), v.clone()))
                .collect(),
        };
        let raw = serde_json::to_vec(&saved)?;
        ensure!(
            raw.len() <= MAX_FRAME,
            "Single queue frame exceeds local limit"
        );
        Ok(raw)
    }
    pub(super) fn restore(
        raw: &[u8],
        state: &StateBatch,
        epoch: i64,
        minimum: &num_bigint::BigInt,
    ) -> Result<Self> {
        ensure!(
            raw.len() <= MAX_FRAME,
            "Single queue frame exceeds local limit"
        );
        let saved: Saved = serde_json::from_slice(raw)?;
        ensure!(
            saved.entries.len() <= MAX_TRANSACTIONS,
            "Single queue count exceeds local limit"
        );
        let ledger = account_store::ledger(state)?;
        let mut result = Self::default();
        for entry in saved.entries {
            ensure!(
                entry.added_at.is_finite() && entry.added_at >= 0.,
                "Single queue timestamp invalid"
            );
            let tx = Transaction::from_document(&Document::parse(&entry.raw)?)?;
            let account = ledger
                .account(&tx.from)
                .context("Single recovered sender missing")?;
            admission::signature(&tx, account.public_key.as_deref())?;
            admission::payload(
                &tx,
                octra_node_protocol::transaction_payload::Limits::default(),
            )?;
            // Authenticated queue bytes carry no proof authority. Nonces/balance/cost and
            // every transaction signature are checked afresh against the same head.
            result
                .pool
                .add(
                    tx,
                    &octra_node_runtime::staging::Limits {
                        stealth_minimum: minimum.clone(),
                        ..Default::default()
                    },
                    Some(epoch),
                    &|a| ledger.account(a).map(|a| (a.balance.clone(), a.nonce)),
                    &|| entry.added_at,
                )
                .map_err(anyhow::Error::msg)?;
        }
        result
            .pool
            .restore_preview(saved.preview, epoch)
            .map_err(anyhow::Error::msg)?;
        for (hash, count) in &saved.deferred.counts {
            ensure!(
                *count >= -(1_i64 << 62)
                    && *count < (1_i64 << 62)
                    && result.pool.find(hash.as_bytes()).is_some(),
                "Single deferred recovery differs"
            );
        }
        result.deferred = saved.deferred;
        for (address, kat) in saved.kats {
            ensure!(
                result.kats.insert(address, kat).is_none(),
                "duplicate Single KAT recovery entry"
            );
        }
        Ok(result)
    }
    pub(super) fn submit(
        &mut self,
        _native: &Native,
        _state: &Snapshot,
        tx: &Transaction,
        ledger: &Ledger,
        rules: &intake::Rules,
        _context: &Bound,
        _epoch: i64,
        now: f64,
        drift: f64,
        pending: usize,
    ) -> Result<Vec<u8>> {
        let rpc = intake::Rpc {
            now,
            max_drift: drift,
            observer: false,
            preverify_capacity: pending
                < usize::try_from(
                    octra_node_protocol::resource_lanes::PREVERIFY_SPECULATIVE_QUEUE,
                )?,
            preverify_pending: Nonce::new(i64::try_from(pending)?)?,
            preverify_maximum: Nonce::new(
                octra_node_protocol::resource_lanes::PREVERIFY_SPECULATIVE_QUEUE,
            )?,
            nonce_window: Nonce::new(32)?,
        };
        let hash = intake::submit(
            &mut self.pool,
            tx,
            ledger,
            rules,
            &rpc,
            &mut Effects,
            &|| now,
        )?;

        Ok(hash)
    }
    pub(super) fn pending(&mut self, hash: &str, now: f64, maximum: usize) {
        let (drop, _) = octra_node_protocol::single::cache_hard_cap(maximum, &self.entries());
        self.drop_cache(&drop);
        self.ready.remove(hash);
        self.cache.insert(hash.to_owned(), Preverify::Pending);
        self.cache_times.replace(hash.as_bytes().to_vec(), now);
    }
    pub(super) fn retire(&mut self, hash: &[u8]) {
        self.drop_cache(&[hash.to_vec()]);
        self.deferred
            .counts
            .remove(std::str::from_utf8(hash).unwrap_or_default());
    }
    fn entries(&self) -> Vec<octra_node_protocol::single::CacheEntry> {
        let mut rows = self
            .cache_times
            .iter()
            .map(|(key, time)| octra_node_protocol::single::CacheEntry {
                key: key.to_vec(),
                timestamp: *time,
                pending: matches!(
                    self.cache.get(std::str::from_utf8(key).unwrap_or_default()),
                    Some(Preverify::Pending)
                ),
            })
            .collect::<Vec<_>>();
        rows.reverse();
        rows
    }
    fn drop_cache(&mut self, keys: &[Vec<u8>]) {
        for key in keys {
            if let Ok(hash) = std::str::from_utf8(key) {
                self.cache.remove(hash);
                self.ready.remove(hash);
            }
            self.cache_times.remove(key);
        }
    }
    pub(super) fn prune(&mut self, now: f64, ttl: f64, maximum: usize) {
        let plan = octra_node_protocol::single::cache_prune(now, ttl, maximum, &self.entries());
        self.drop_cache(&plan.expired);
        self.drop_cache(&plan.overflow);
    }
    pub(super) fn cleanup(
        &mut self,
        processed: &[Vec<u8>],
        state: &Snapshot,
        now: f64,
        minimum: &num_bigint::BigInt,
    ) -> Result<()> {
        self.pool.remove_processed(processed);
        let batch = StateBatch::from_snapshot(state.clone());
        let ledger = account_store::ledger(&batch)?;
        self.pool
            .expire_old(&|address| ledger.account(address).map(|a| a.nonce), &|| now);
        self.pool.cleanup_dropped(now);
        let low = self
            .pool
            .all()
            .filter(|tx| tx.op_type == OpType::Stealth && &tx.ou < minimum)
            .map(|tx| tx.hash().map(|hash| hex::encode(hash).into_bytes()))
            .collect::<Result<Vec<_>, _>>()?;
        self.pool.remove_processed(&low);
        let retired = self
            .cache_times
            .iter()
            .filter(|(hash, _)| self.pool.find(hash).is_none())
            .map(|(hash, _)| hash.to_vec())
            .collect::<Vec<_>>();
        self.drop_cache(&retired);
        self.cache
            .retain(|hash, _| self.pool.find(hash.as_bytes()).is_some());
        self.ready
            .retain(|hash, _| self.pool.find(hash.as_bytes()).is_some());
        self.deferred
            .counts
            .retain(|hash, _| self.pool.find(hash.as_bytes()).is_some());
        Ok(())
    }
}
