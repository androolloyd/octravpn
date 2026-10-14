use super::proofs::{check_work, receipt, select};
use super::Native;
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_exex::native_history::{ArchiveProof, NativeTransaction};
use octra_hfhe::scalar::ScalarRule;
use octra_node_protocol::{
    consensus::EpochHeader,
    preverify_commit::Gate,
    transaction::{OpType, RuleMode},
    transaction_policy,
};
use octra_node_protocol::{
    consensus::ValidatorSet, epoch_rewards::Attribution, transaction::Transaction,
};
use octra_node_runtime::{
    account_store,
    canonical::Head,
    circle_transaction,
    consensus_bundle::Rules,
    epoch_execution::{self, Effect},
    execution::{Error, OperationHost, Route},
    execution_rules::Bound,
    private_balance,
    private_crypto::ResultPolicy,
    private_epoch, validator_epoch, validator_transaction,
};
use octra_node_runtime::{
    preverify_state,
    state_batch::{Snapshot, StateBatch},
};
use std::collections::BTreeMap;

pub(super) struct Stage<'a> {
    pub parent: &'a Head,
    pub state: StateBatch,
    pub header: &'a EpochHeader,
    pub context: &'a Bound,
    pub rules: &'a Rules,
    pub validators: &'a ValidatorSet,
    pub reward: &'a Attribution,
    pub transactions: &'a [Transaction],
    pub gate: &'a Gate,
    pub capture: bool,
}
pub(super) struct Staged {
    pub state: Snapshot,
    pub transactions: Vec<NativeTransaction>,
    pub artifacts: epoch_execution::Artifacts,
    pub gate: Gate,
}
impl Native {
    pub(super) fn stage(
        &self,
        request: Stage<'_>,
        roots: &BTreeMap<i64, Option<Vec<u8>>>,
    ) -> Result<Staged> {
        let Stage {
            parent,
            mut state,
            header,
            context,
            rules,
            validators,
            reward,
            transactions,
            gate,
            capture,
        } = request;
        let config = &self.config;
        let epoch = header.epoch_id;
        ensure!(
            hex::encode(state.published_root()?) == parent.ledger_root,
            "execution snapshot differs from canonical parent"
        );
        let mut ledger = account_store::ledger(&state)?;
        let keys = validators
            .validators
            .iter()
            .map(|v| (v.address.clone(), STANDARD.encode(&v.pubkey).into_bytes()))
            .collect::<Vec<_>>();
        let members = keys
            .iter()
            .map(|(address, _)| address.clone())
            .collect::<Vec<_>>();
        if capture {
            check_work(transactions, &rules.stealth_minimum)?;
            let ordinary = transactions
                .iter()
                .filter(|tx| tx.op_type != OpType::CircleCall)
                .cloned()
                .collect::<Vec<_>>();
            preverify_state::check(
                gate,
                &ordinary,
                rules.crypto_active,
                &rules.stealth_minimum,
                parent.ledger_root.as_bytes(),
                &ledger,
                &state.snapshot(),
            )?;
        }
        let previous = hex::encode(parent.cursor.state_root.0);
        let mut calls = circle_transaction::Calls::new(
            &self.runtime,
            context.circle,
            epoch,
            header.ts,
            previous.as_bytes(),
            if capture {
                circle_transaction::Verification::Capture
            } else {
                circle_transaction::Verification::Consume {
                    root: parent.ledger_root.as_bytes(),
                    gate,
                }
            },
        );
        let mut private = private_epoch::Epoch::new(
            self.private_profile(context, epoch),
            config.max_fhe,
            Some(gate),
        );
        let root_at = |head| roots.get(&head).cloned().flatten();
        let mut validators = validator_transaction::Host {
            chain: &header.chain_id,
            epoch,
            policy: &config.validators,
            fold: context.fold.clone(),
            ready: validator_transaction::ReadyEnvironment {
                prev_state_root: previous.as_bytes(),
                max_lag: config.ready_max_lag,
                root_at: Some(&root_at),
            },
        };
        let committed = state.snapshot();
        state.begin()?;
        let request = epoch_execution::Request {
            validators: validator_epoch::Request {
                chain: &header.chain_id,
                epoch,
                policy: &config.validators,
                legacy_members: &members,
                previous_root: previous.as_bytes(),
                committed_head: Some(&committed),
            },
            envelope: rules.envelope,
            sender_key_activation: config.sender_key_activation,
            preverification: (!capture).then_some(epoch_execution::Preverification {
                gate,
                crypto_active: rules.crypto_active,
                minimum: &rules.stealth_minimum,
            }),
            emission: &config.emission,
            reward,
            validator_keys: &keys,
        };
        let executed = epoch_execution::execute(
            &request,
            &context.fold,
            transactions,
            &mut ledger,
            &mut state,
            |tx, ledger, state| {
                if transaction_policy::is_validator(tx.op_type) {
                    return Effect::from_completion(
                        tx,
                        validators.execute(Route::Validator, tx, ledger, state)?,
                    );
                }
                match tx.op_type {
                    OpType::Standard | OpType::Op01Burn => {
                        epoch_execution::public(tx, ledger, state)
                    }
                    OpType::Encrypt
                    | OpType::Decrypt
                    | OpType::Stealth
                    | OpType::Claim
                    | OpType::KeySwitch => {
                        private.process(tx, ledger, state, |hash| self.key_blob(hash))
                    }
                    OpType::CircleCall | OpType::CircleDeploy | OpType::CircleProgramUpdate => {
                        calls.process(tx, ledger, state)
                    }
                    _ => Err(Error(format!(
                        "execution host unavailable for {}",
                        tx.op_type.as_str()
                    ))),
                }
            },
        )?;
        let archived = executed
            .artifacts
            .confirmed
            .iter()
            .enumerate()
            .map(|(offset, (input, _))| {
                let tx = &transactions[*input];
                let hash = hex::encode(tx.hash()?);
                let identity = tx.identity_bytes()?;
                Ok(NativeTransaction {
                    txid: parent
                        .txid_hi
                        .checked_add(
                            i64::try_from(offset)?
                                .checked_add(1)
                                .context("transaction index exhausted")?,
                        )
                        .context("transaction index exhausted")?,
                    hash: hash.clone(),
                    identity: identity.clone(),
                    transaction: identity,
                    proof: ArchiveProof::Exact,
                    receipt: calls.receipts().get(&hash).cloned(),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let mut captured = gate.receipts.clone();
        if capture {
            // Only invoked Circle operations with a native binding produce a
            // receipt. A confirmed Circle must always have one.
            for tx in transactions
                .iter()
                .filter(|tx| tx.op_type == OpType::CircleCall)
            {
                let hash = hex::encode(tx.hash()?);
                if let Some(binding) = calls.bindings().get(&hash) {
                    captured.push(receipt(
                        tx,
                        octra_node_protocol::preverify_receipt::Binding::Circle(
                            binding.at_snapshot(parent.ledger_root.as_bytes()),
                        ),
                        &rules.stealth_minimum,
                    )?);
                } else if executed
                    .artifacts
                    .confirmed
                    .iter()
                    .any(|(i, _)| &transactions[*i] == tx)
                {
                    anyhow::bail!("circle receipt capture missing");
                }
            }
        }
        let gate = Gate {
            receipts: select(&captured, transactions)?,
        };
        if capture {
            let checked = transactions
                .iter()
                .filter(|tx| tx.op_type != OpType::CircleCall || gate.receipt(tx).is_ok())
                .cloned()
                .collect::<Vec<_>>();
            gate.check(&checked, rules.crypto_active, &rules.stealth_minimum)?;
        }
        Ok(Staged {
            state: state.snapshot(),
            transactions: archived,
            artifacts: executed.artifacts,
            gate,
        })
    }
    pub(super) fn private_profile(&self, context: &Bound, epoch: i64) -> private_balance::Profile {
        let fold = context.fold.context();
        private_balance::Profile {
            fields: context.private_payload,
            strict: fold.standard_mode == RuleMode::Active,
            math: if fold.math {
                ScalarRule::Wide
            } else {
                ScalarRule::Prior
            },
            result: if epoch >= self.config.private_result_activation {
                ResultPolicy::Recoverable
            } else {
                ResultPolicy::Legacy
            },
        }
    }
}
