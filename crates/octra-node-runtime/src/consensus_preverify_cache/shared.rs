use super::{Error, Result};
use octra_node_protocol::transaction::Transaction;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct State {
    entries: BTreeMap<Vec<u8>, (Transaction, usize)>,
    fifo: VecDeque<Vec<u8>>,
    bytes: usize,
}
struct Inner {
    state: Mutex<State>,
    capacity: usize,
    byte_limit: usize,
}
/// The native `share/find_shared` transaction cache. Immutable transaction
/// values replace OCaml string interning; neither GC identity nor weak-table
/// timing is a Rust protocol promise. Count/byte eviction and lifetime match.
#[derive(Clone)]
pub struct Shared(Arc<Inner>);
impl Default for Shared {
    fn default() -> Self {
        Self::new(1024, 32 * 1024 * 1024)
    }
}
impl Shared {
    pub fn new(capacity: usize, byte_limit: usize) -> Self {
        Self(Arc::new(Inner {
            state: Mutex::new(State::default()),
            capacity: capacity.max(1),
            byte_limit: byte_limit.max(1),
        }))
    }
    /// Retained hashes, in input order (including duplicates), are safe to
    /// announce only after the caller's complete native proposal admission.
    pub fn share(&self, txs: &[Transaction]) -> Result<Vec<Vec<u8>>> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| Error("shared transaction cache poisoned".into()))?;
        let mut hashes = Vec::with_capacity(txs.len());
        for tx in txs {
            let hash = hex::encode(tx.hash().map_err(|e| Error(e.to_string()))?).into_bytes();
            if !state.entries.contains_key(&hash) {
                let bytes = tx.to_json_bytes().map_err(|e| Error(e.to_string()))?.len();
                if bytes <= self.0.byte_limit {
                    state.bytes = state
                        .bytes
                        .checked_add(bytes)
                        .ok_or_else(|| Error("shared transaction cache size overflow".into()))?;
                    state.entries.insert(hash.clone(), (tx.clone(), bytes));
                    state.fifo.push_back(hash.clone());
                    while state.entries.len() > self.0.capacity || state.bytes > self.0.byte_limit {
                        let Some(old) = state.fifo.pop_front() else {
                            break;
                        };
                        if let Some((_, bytes)) = state.entries.remove(&old) {
                            state.bytes -= bytes;
                        }
                    }
                }
            }
            hashes.push(hash);
        }
        Ok(hashes
            .into_iter()
            .filter(|hash| state.entries.contains_key(hash))
            .collect())
    }
    pub fn find(&self, hash: &[u8]) -> Result<Option<Transaction>> {
        Ok(self
            .0
            .state
            .lock()
            .map_err(|_| Error("shared transaction cache poisoned".into()))?
            .entries
            .get(hash)
            .map(|(tx, _)| tx.clone()))
    }
    pub fn contains(&self, hash: &[u8]) -> Result<bool> {
        Ok(self
            .0
            .state
            .lock()
            .map_err(|_| Error("shared transaction cache poisoned".into()))?
            .entries
            .contains_key(hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus_preverify_cache::{tests::tx, Cache};
    fn hash(tx: &Transaction) -> Vec<u8> {
        hex::encode(tx.hash().unwrap()).into_bytes()
    }
    #[test]
    fn duplicate_announcements_do_not_refresh_fifo_and_root_does_not_clear_transactions() {
        let shared = Shared::new(2, usize::MAX);
        let first = tx(1);
        let second = tx(2);
        let third = tx(3);
        assert_eq!(
            shared
                .share(&[first.clone(), second.clone(), first.clone()])
                .unwrap(),
            [hash(&first), hash(&second), hash(&first)]
        );
        shared.share(std::slice::from_ref(&first)).unwrap();
        shared.share(std::slice::from_ref(&third)).unwrap();
        assert!(shared.find(&hash(&first)).unwrap().is_none());
        assert_eq!(shared.find(&hash(&second)).unwrap(), Some(second));
        assert_eq!(shared.find(&hash(&third)).unwrap(), Some(third));
        let cache = Cache::new(0, 0);
        cache.select(b"before", ()).unwrap();
        cache.shared().share(std::slice::from_ref(&first)).unwrap();
        cache.select(b"after", ()).unwrap();
        assert_eq!(cache.shared().find(&hash(&first)).unwrap(), Some(first));
    }
    #[test]
    fn exact_and_oversized_native_transaction_bytes() {
        let tx = tx(1);
        let bytes = tx.to_json_bytes().unwrap().len();
        let exact = Shared::new(0, bytes);
        let short = Shared::new(1, bytes - 1);
        assert_eq!(exact.share(std::slice::from_ref(&tx)).unwrap(), [hash(&tx)]);
        assert!(short.share(std::slice::from_ref(&tx)).unwrap().is_empty());
        assert!(short.find(&hash(&tx)).unwrap().is_none());
    }
}
