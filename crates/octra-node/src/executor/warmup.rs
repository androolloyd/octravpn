//! Speculative admission starts local proof artifacts, never bound receipts.
use std::sync::Arc;

pub(super) use super::artifact_pool::{Lane, Priority};
pub(super) type Warmups = super::artifact_pool::Pool<super::proofs::Artifact>;

/// A warmup owns only its captured sender account. It cannot masquerade as a
/// loaded Ledger or expose unrelated account/global supply operations.
pub(super) struct SenderAccount<'a> {
    address: &'a [u8],
    account: Option<octra_node_protocol::state::Account>,
}
impl<'a> SenderAccount<'a> {
    pub(super) fn load(
        state: &octra_node_runtime::state_batch::Snapshot,
        address: &'a [u8],
    ) -> Result<Self, octra_node_protocol::transaction::Error> {
        use octra_node_protocol::{state, transaction::Error};
        use octra_node_runtime::{account_store, state_batch::StateBatch};
        let mut account = account_store::load(&StateBatch::from_snapshot(state.clone()), address)?;
        if let Some(account) = &mut account {
            // Match the complete ledger's loaded-account normalization and
            // prefix refusal, without computing global supply or constructing a
            // partial Ledger. Authoritative execution still loads every account.
            if account.encrypted_balance.as_deref() == Some(b"0") {
                account.encrypted_balance = None;
            } else if !state::valid_cipher(account.encrypted_balance.as_deref()) {
                return Err(Error(
                    "ledger cipher format unsupported; run fhe_audit on a data copy".into(),
                ));
            }
        }
        Ok(Self { address, account })
    }
}
impl octra_node_runtime::private_balance::AccountView for SenderAccount<'_> {
    fn account(&self, address: &[u8]) -> Option<&octra_node_protocol::state::Account> {
        if address == self.address {
            self.account.as_ref()
        } else {
            None
        }
    }
}

impl super::Native {
    pub(crate) async fn shutdown_preverification(&self) {
        if let Some(warmups) = self.warmups.clone() {
            // The protected blocking owner joins/reaps every crypto job before
            // releasing the manager, even if its async caller is cancelled.
            let _ = tokio::task::spawn_blocking(move || warmups.shutdown()).await;
        }
    }

    pub(super) fn warm_pending(
        &self,
        admission: &Arc<crate::proposal::Admission>,
        pending: &super::Pending,
        tx: &octra_node_protocol::transaction::Transaction,
        _rules: &octra_node_runtime::consensus_bundle::Rules,
    ) {
        let Some(warmups) = &self.warmups else {
            return;
        };
        warmups.retain(|hash| {
            pending
                .ingress_read(|pool| pool.find(hash).is_some())
                .is_ok_and(|live| live.unwrap_or(true))
        });
        let draft = admission.draft();
        let epoch = draft.context().header().epoch_id;
        let policy = self.private_policy(draft.context().rules(), epoch);
        let Some(lane) = super::proofs::artifact_lane(tx, policy) else {
            return;
        };
        let Ok(hash) = tx.hash().map(|hash| hex::encode(hash).into_bytes()) else {
            return;
        };
        // The captured source may become old while this public proof runs.
        // Keep the artifact across unrelated heads; required preparation binds
        // it to freshly selected source/policy and creates its own receipt.
        warmups.offer(
            hash,
            lane,
            self.artifact_work(draft.state().clone(), tx.clone(), epoch, policy),
        );
    }
}

#[cfg(test)]
mod account_view_tests;
