//! Receipt store. The control-plane HTTP server is the primary writer
//! (it co-signs and stashes the latest dual-signed receipt per session).
//! This module exposes a thin wrapper consumed by the hub for
//! settlement/diagnostic paths.
//!
//! Equivocation is *prevented* in the control-plane handler: it refuses
//! to co-sign two different `bytes_used` for the same `(session, seq)`.
//! Equivocation is *detected and slashable* on chain via
//! `slash_double_sign` if the node operator ever bypasses this guard.

use std::{collections::HashMap, sync::Arc};

use octravpn_core::{receipt::SignedReceipt, session::SessionId};
use parking_lot::RwLock;

#[derive(Default)]
pub struct ReceiptStore {
    inner: RwLock<HashMap<SessionId, SignedReceipt>>,
}

pub type SharedStore = Arc<ReceiptStore>;

impl ReceiptStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&self, sr: SignedReceipt) {
        let id = sr.receipt.session_id.clone();
        self.inner.write().insert(id, sr);
    }

    pub fn get(&self, id: &SessionId) -> Option<SignedReceipt> {
        self.inner.read().get(id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use octravpn_core::{receipt::Receipt, sig::KeyPair};

    #[test]
    fn put_get_round_trip() {
        let store = ReceiptStore::new();
        let id = SessionId([1u8; 32]);
        let r = Receipt {
            session_id: id.clone(),
            seq: 1,
            bytes_used: 100,
            blind: [0u8; 32],
        };
        let sr = SignedReceipt::build(r, &KeyPair::generate(), &KeyPair::generate());
        store.put(sr.clone());
        let got = store.get(&id).unwrap();
        assert_eq!(got.receipt.bytes_used, 100);
    }
}
