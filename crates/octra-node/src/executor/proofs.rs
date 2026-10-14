//! Local proof checks. Received receipts never enter this preparation path.
use super::Native;
use anyhow::{ensure, Result};
use num_bigint::BigInt;
use octra_node_protocol::{
    preverify_commit::{self, Gate},
    preverify_receipt::{self, Binding, Receipt, State},
    resource_lanes::{self, Lane},
    state::Ledger,
    transaction::{OpType, Transaction},
};
use octra_node_runtime::{
    preverify_batch::{Checked, Kind},
    private_balance,
    state_batch::Snapshot,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn receipt(tx: &Transaction, binding: Binding, minimum: &BigInt) -> Result<Receipt> {
    let input = binding.input_hash(tx).map_err(anyhow::Error::msg)?;
    let output = binding.output_hash(tx, b"ok").map_err(anyhow::Error::msg)?;
    Receipt::for_tx(tx, binding, input, output, true, vec![], minimum).map_err(anyhow::Error::msg)
}
pub(super) fn select(receipts: &[Receipt], txs: &[Transaction]) -> Result<Vec<Receipt>> {
    txs.iter()
        .filter_map(|tx| match tx.hash() {
            Ok(hash) => receipts
                .iter()
                .find(|r| r.tx_hash == hex::encode(hash).as_bytes())
                .cloned()
                .map(Ok),
            Err(e) => Some(Err(e.into())),
        })
        .collect()
}
pub(super) fn check_work(txs: &[Transaction], minimum: &BigInt) -> Result<()> {
    let mut hashes = BTreeSet::new();
    for tx in txs {
        let hash = tx.hash()?;
        ensure!(hashes.insert(hash), "duplicate_tx:{}", hex::encode(hash));
    }
    let mut used = BTreeMap::new();
    for tx in txs {
        let lane = Lane::of(tx.op_type);
        Gate::reserve(
            &mut used,
            lane,
            &resource_lanes::work(tx, minimum).map_err(anyhow::Error::msg)?,
            &lane.budget(),
        )?;
    }
    Ok(())
}
fn skip(kind: Kind, reason: impl Into<Vec<u8>>) -> Checked {
    Checked::Skip {
        kind,
        reason: reason.into(),
    }
}
impl Native {
    pub(super) fn proposal_proofs(
        &self,
        parent: &octra_node_runtime::canonical::Head,
        state: &Snapshot,
        bound: &octra_node_runtime::execution_rules::Bound,
        inputs: &[Transaction],
        rules: &octra_node_runtime::consensus_bundle::Rules,
    ) -> Result<Vec<Receipt>, super::ProposalError> {
        use super::proposal::{invalid, unavailable};
        let batch = self.prepare_proofs(parent, state, bound, inputs, rules)?;
        let hashes = inputs
            .iter()
            .map(Transaction::hash)
            .collect::<Result<Vec<_>, _>>()
            .map_err(unavailable)?;
        let ready = batch
            .ready
            .iter()
            .map(|r| hashes[r.index])
            .collect::<Vec<_>>();
        if ready != hashes || !batch.skipped.is_empty() {
            return Err(if batch.may_retry(inputs).map_err(unavailable)? {
                unavailable("preverify_unavailable")
            } else {
                invalid("local_preverify_mismatch")
            });
        }
        Ok(batch.ready.into_iter().filter_map(|r| r.receipt).collect())
    }

    pub(super) fn prepare_proofs(
        &self,
        parent: &octra_node_runtime::canonical::Head,
        state: &Snapshot,
        bound: &octra_node_runtime::execution_rules::Bound,
        inputs: &[Transaction],
        rules: &octra_node_runtime::consensus_bundle::Rules,
    ) -> Result<octra_node_runtime::preverify_batch::Batch, super::ProposalError> {
        use super::proposal::unavailable;
        use octra_node_runtime::{account_store, preverify_batch, state_batch::StateBatch};
        let ledger = account_store::ledger(&StateBatch::from_snapshot(state.clone()))
            .map_err(unavailable)?;
        let epoch = i64::try_from(parent.cursor.epoch.0 + 1).map_err(unavailable)?;
        preverify_batch::prepare(inputs, true, &rules.stealth_minimum, |tx| {
            Ok(self.prove(
                tx,
                &ledger,
                state,
                parent.ledger_root.as_bytes(),
                self.private_profile(bound, epoch),
                &rules.stealth_minimum,
            ))
        })
        .map_err(unavailable)
    }

    pub(super) fn prove(
        &self,
        tx: &Transaction,
        ledger: &Ledger,
        state: &Snapshot,
        root: &[u8],
        profile: private_balance::Profile,
        minimum: &BigInt,
    ) -> Checked {
        if !preverify_commit::managed(tx) {
            return Checked::Ready(None);
        }
        if !matches!(tx.op_type, OpType::Encrypt | OpType::Decrypt) {
            return skip(Kind::Unavailable, b"private_preverify_pending".to_vec());
        }
        let hash = state
            .get(&[b"pvac_hashes", &tx.from])
            .filter(|h| *h != b"none");
        let plan = private_balance::verify_with_key(ledger, tx, profile, || {
            let Some(hash) = hash else {
                return Ok(None);
            };
            let blob = self
                .key_blob(hash)
                .map_err(|e| private_balance::Error::Unavailable(e.0))?
                .ok_or_else(|| {
                    private_balance::Error::Unavailable("pvac blob unavailable".into())
                })?;
            if hex::encode(Sha256::digest(&blob)).as_bytes() != hash {
                return Err(private_balance::Error::Unavailable(
                    "pvac blob hash mismatch".into(),
                ));
            }
            Ok(Some(blob))
        });
        let plan = match plan {
            Ok(plan) => plan,
            Err(private_balance::Error::Rejected(failure)) => {
                return skip(Kind::Invalid, failure.reason)
            }
            Err(private_balance::Error::Unavailable(_)) => {
                return skip(Kind::Unavailable, b"private_preverify_pending".to_vec());
            }
        };
        let Some(hash) = hash else {
            return skip(Kind::Invalid, b"pvac_key_not_consensus_bound".to_vec());
        };
        let binding = Binding::Private(State {
            pre_state_hash: preverify_receipt::state_hash(root),
            source_cipher_hash: hex::encode(Sha256::digest(plan.current_cipher())).into_bytes(),
            pvac_key_hash: hash.to_vec(),
            transition_hash: Some(plan.transition_hash().into_bytes()),
        });
        match receipt(tx, binding, minimum) {
            Ok(receipt) => Checked::Ready(Some(Box::new(receipt))),
            Err(error) => skip(Kind::Invalid, error.to_string().into_bytes()),
        }
    }
}
