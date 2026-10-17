//! Validated account statistics for immutable committed snapshots.
//!
//! The first read of an account root still loads and validates every account,
//! including packed ciphertext parts. Repeated reads of that exact subtree
//! retain only its counts and public supply; no ledger or old tree is cached.
use crate::{
    account_store,
    state_batch::{Snapshot, StateBatch},
};
use num_bigint::BigInt;
use octra_node_protocol::{irmin::Hash, transaction::Error};
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub struct Summary {
    accounts: usize,
    active_accounts: usize,
    total_supply: BigInt,
}
impl Summary {
    pub const fn accounts(&self) -> usize {
        self.accounts
    }
    pub const fn active_accounts(&self) -> usize {
        self.active_accounts
    }
    pub fn total_supply(&self) -> &BigInt {
        &self.total_supply
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Root {
    Missing,
    Tree(Hash),
    Contents(Hash),
}
impl Root {
    fn of(state: &Snapshot) -> Result<Self, Error> {
        let Some(hash) = state
            .hash_at(&[b"accounts"])
            .map_err(|error| Error(error.to_string()))?
        else {
            return Ok(Self::Missing);
        };
        Ok(if state.get(&[b"accounts"]).is_some() {
            Self::Contents(hash)
        } else {
            Self::Tree(hash)
        })
    }
}

/// One completed summary and at most one cold account load per cache. Waiting
/// callers cannot amplify packed-cipher reconstruction for the same root.
#[derive(Default)]
pub struct Cache {
    current: Mutex<Option<(Root, Arc<Summary>)>>,
}
impl Cache {
    pub fn get(&self, state: &Snapshot) -> Result<Arc<Summary>, Error> {
        let root = Root::of(state)?;
        let mut current = self
            .current
            .lock()
            .map_err(|_| Error("account summary unavailable".into()))?;
        if let Some((cached, summary)) = &*current {
            if *cached == root {
                return Ok(summary.clone());
            }
        }
        // Do not publish a summary until all native account and cipher-format
        // validation has succeeded. A rejected root cannot replace good data.
        let ledger = account_store::ledger(&StateBatch::from_snapshot(state.clone()))?;
        let summary = Arc::new(Summary {
            accounts: ledger.accounts().len(),
            active_accounts: ledger.active_accounts(),
            total_supply: ledger.total_supply().clone(),
        });
        *current = Some((root, summary.clone()));
        Ok(summary)
    }
}

#[cfg(test)]
mod tests;
