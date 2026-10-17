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
    consensus_preverify_cache::Purpose,
    preverify_batch::{Checked, Kind},
    private_balance,
    state_batch::Snapshot,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// A cache belongs to one immutable Native configuration. Also bind the full
/// freshly selected epoch authority and every policy consumed by prove().
/// Proposal contexts carry that authority separately from their uncertified Bound.
#[derive(PartialEq)]
pub(super) struct ProofBinding {
    validators: octra_node_protocol::consensus::ValidatorSet,
    required: bool,
    crypto_active: bool,
    minimum: BigInt,
    selected_minimum: BigInt,
    selected_crypto_active: bool,
    fields: octra_node_protocol::transaction::RuleMode,
    strict: bool,
    math: octra_hfhe::scalar::ScalarRule,
    result: octra_node_runtime::private_crypto::ResultPolicy,
    owner: octra_node_protocol::transaction::RuleMode,
    cipher: octra_node_protocol::transaction::RuleMode,
}
impl ProofBinding {
    fn new(
        authority: &octra_node_runtime::finality::EpochRules,
        policy: octra_node_runtime::private_key::Policy,
        rules: &octra_node_runtime::consensus_bundle::Rules,
    ) -> Self {
        let octra_node_runtime::finality::EpochRules {
            validators,
            receipts,
            ..
        } = authority;
        let octra_node_runtime::finality::ReceiptRules {
            required,
            crypto_active,
            stealth_minimum,
        } = receipts;
        let octra_node_runtime::private_key::Policy {
            balance,
            owner,
            cipher,
        } = policy;
        let private_balance::Profile {
            fields,
            strict,
            math,
            result,
        } = balance;
        Self {
            validators: validators.clone(),
            required: *required,
            crypto_active: *crypto_active,
            minimum: stealth_minimum.clone(),
            selected_minimum: rules.stealth_minimum.clone(),
            selected_crypto_active: rules.crypto_active,
            fields,
            strict,
            math,
            result,
            owner,
            cipher,
        }
    }
}

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
    pub(crate) fn share_transactions(&self, txs: &[Transaction]) -> Result<Vec<Vec<u8>>> {
        self.proof_cache.shared().share(txs).map_err(Into::into)
    }
    /// Cache lookup only; retained transaction bytes grant no admission authority.
    pub fn shared_transaction(&self, hash: &[u8]) -> Result<Option<Transaction>> {
        self.proof_cache.shared().find(hash).map_err(Into::into)
    }
    pub(crate) fn shared_transactions(
        &self,
    ) -> octra_node_runtime::consensus_preverify_cache::Shared {
        self.proof_cache.shared().clone()
    }
    pub(super) fn proposal_proofs(
        &self,
        parent: &octra_node_runtime::canonical::Head,
        state: &Snapshot,
        context: (
            &octra_node_runtime::execution_rules::Bound,
            &octra_node_runtime::finality::EpochRules,
        ),
        inputs: &[Transaction],
        rules: &octra_node_runtime::consensus_bundle::Rules,
        purpose: Purpose,
    ) -> Result<Vec<Receipt>, super::ProposalError> {
        use super::proposal::{invalid, unavailable};
        let batch = self.prepare_proofs(parent, state, context, inputs, rules, purpose)?;
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
        context: (
            &octra_node_runtime::execution_rules::Bound,
            &octra_node_runtime::finality::EpochRules,
        ),
        inputs: &[Transaction],
        rules: &octra_node_runtime::consensus_bundle::Rules,
        purpose: Purpose,
    ) -> Result<octra_node_runtime::preverify_batch::Batch, super::ProposalError> {
        use super::proposal::unavailable;
        use octra_node_runtime::{account_store, preverify_batch, state_batch::StateBatch};
        let ledger = account_store::ledger(&StateBatch::from_snapshot(state.clone()))
            .map_err(unavailable)?;
        let epoch = i64::try_from(parent.cursor.epoch.0 + 1).map_err(unavailable)?;
        let (bound, authority) = context;
        let policy = self.private_policy(bound, epoch);
        let scope = self
            .proof_cache
            .select(
                parent.ledger_root.as_bytes(),
                ProofBinding::new(authority, policy, rules),
            )
            .map_err(unavailable)?;
        preverify_batch::prepare(inputs, true, &rules.stealth_minimum, |tx| {
            self.proof_cache.run(&scope, epoch, purpose, tx, || {
                Ok(self.prove(
                    tx,
                    &ledger,
                    state,
                    parent.ledger_root.as_bytes(),
                    epoch,
                    policy,
                    &rules.stealth_minimum,
                ))
            })
        })
        .map_err(unavailable)
    }

    pub(super) fn prove(
        &self,
        tx: &Transaction,
        ledger: &Ledger,
        state: &Snapshot,
        root: &[u8],
        epoch: i64,
        policy: octra_node_runtime::private_key::Policy,
        minimum: &BigInt,
    ) -> Checked {
        let _crypto = self.runtime.crypto_scope(
            false,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );
        if !preverify_commit::managed(tx) {
            return Checked::Ready(None);
        }
        match tx.op_type {
            OpType::Private => return skip(Kind::Invalid, b"private_disabled".to_vec()),
            OpType::Recrypt => return skip(Kind::Invalid, b"recrypt_disabled".to_vec()),
            _ => (),
        }
        if matches!(
            tx.op_type,
            OpType::CircleBalanceCellPut | OpType::CircleRegisterCellPut
        ) {
            return self.prove_cell(tx, ledger, state, root, epoch, policy.balance, minimum);
        }
        if !matches!(
            tx.op_type,
            OpType::Encrypt | OpType::Decrypt | OpType::Stealth | OpType::Claim | OpType::KeySwitch
        ) {
            return skip(Kind::Unavailable, b"private_preverify_pending".to_vec());
        }
        let hash = state
            .get(&[b"pvac_hashes", &tx.from])
            .filter(|h| *h != b"none");
        let key = || {
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
        };
        let profile = policy.balance;
        let verified = if tx.op_type == OpType::KeySwitch {
            octra_node_runtime::private_key::verify(
                ledger,
                tx,
                policy,
                epoch,
                self.config.migration.as_deref(),
                key,
            )
            .map(|plan| (plan.current_cipher().to_vec(), plan.transition_hash()))
        } else if matches!(tx.op_type, OpType::Stealth | OpType::Claim) {
            octra_node_runtime::private_transfer::verify(
                ledger,
                &octra_node_runtime::state_batch::StateBatch::from_snapshot(state.clone()),
                tx,
                profile,
                key,
            )
            .map(|plan| (plan.current_cipher().to_vec(), plan.transition_hash()))
        } else {
            private_balance::verify_with_key(ledger, tx, profile, key)
                .map(|plan| (plan.current_cipher().to_vec(), plan.transition_hash()))
        };
        let (current, transition_hash) = match verified {
            Ok(plan) => plan,
            Err(private_balance::Error::Rejected(failure)) => {
                return skip(
                    Kind::Invalid,
                    failure.preverify_reason.unwrap_or(failure.reason),
                )
            }
            Err(private_balance::Error::Unavailable(_)) => {
                return skip(Kind::Unavailable, b"private_preverify_pending".to_vec());
            }
        };
        let hash = match hash {
            Some(hash) => hash,
            None if tx.op_type == OpType::KeySwitch => &[b'0'; 64],
            None => return skip(Kind::Invalid, b"pvac_key_not_consensus_bound".to_vec()),
        };
        let binding = Binding::Private(State {
            pre_state_hash: preverify_receipt::state_hash(root),
            source_cipher_hash: hex::encode(Sha256::digest(current)).into_bytes(),
            pvac_key_hash: hash.to_vec(),
            transition_hash: Some(transition_hash.into_bytes()),
        });
        match receipt(tx, binding, minimum) {
            Ok(receipt) => Checked::Ready(Some(Box::new(receipt))),
            Err(error) => skip(Kind::Invalid, error.to_string().into_bytes()),
        }
    }
    fn prove_cell(
        &self,
        tx: &Transaction,
        ledger: &Ledger,
        state: &Snapshot,
        root: &[u8],
        epoch: i64,
        profile: private_balance::Profile,
        minimum: &BigInt,
    ) -> Checked {
        use octra_node_runtime::circle_cell::{self, Error};
        // Source binding precedes the cell callback in the adopted worker.
        let Some(encoded) = tx.encrypted_data.as_deref() else {
            return skip(
                Kind::Invalid,
                b"circle cell ciphertext is required".to_vec(),
            );
        };
        let cipher = match octra_node_protocol::transaction::decode_base64(encoded) {
            Ok(raw) if !raw.is_empty() => raw,
            _ => return skip(Kind::Invalid, b"circle cell ciphertext is invalid".to_vec()),
        };
        let Some(hash) = state
            .get(&[b"pvac_hashes", &tx.from])
            .filter(|hash| *hash != b"none")
        else {
            return skip(Kind::Invalid, b"pvac_key_not_consensus_bound".to_vec());
        };
        let plan = match circle_cell::preverify(
            &self.runtime,
            tx,
            ledger,
            state,
            epoch,
            profile.strict,
            profile.math,
        ) {
            Ok(plan) => plan,
            Err(Error::Rejected(reason)) => return skip(Kind::Invalid, reason),
            Err(Error::Unavailable(_)) => {
                return skip(Kind::Unavailable, b"circle_cell_preverify_pending".to_vec())
            }
        };
        let binding = Binding::Private(State {
            pre_state_hash: preverify_receipt::state_hash(root),
            source_cipher_hash: hex::encode(Sha256::digest(cipher)).into_bytes(),
            pvac_key_hash: hash.to_vec(),
            transition_hash: Some(plan.transition_hash().as_bytes().to_vec()),
        });
        match receipt(tx, binding, minimum) {
            Ok(receipt) => Checked::Ready(Some(Box::new(receipt))),
            Err(error) => skip(Kind::Invalid, error.to_string().into_bytes()),
        }
    }
}

#[cfg(test)]
mod tests;
