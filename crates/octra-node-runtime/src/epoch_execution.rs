//! Native BFT epoch ordering and coupled transaction/epoch savepoints. Operations
//! execute against one rule fold; only the canonical publisher can commit effects.
use crate::{
    account_store, epoch_footer,
    execution::{self, Completion, Error},
    preverify_state,
    state_batch::StateBatch,
    validator_epoch,
    validator_transaction::EpochFold,
};
use num_bigint::BigInt;
use octra_node_protocol::{
    epoch_rewards::Attribution,
    preverify_commit::Gate,
    state::Ledger,
    transaction::{self, OpType, RuleMode, Transaction},
    transaction_outcome,
};

pub struct Preverification<'a> {
    pub gate: &'a Gate,
    pub crypto_active: bool,
    pub minimum: &'a BigInt,
}
pub struct Request<'a> {
    pub validators: validator_epoch::Request<'a>,
    pub envelope: transaction_outcome::Rules,
    pub sender_key_activation: Option<i64>,
    pub preverification: Option<Preverification<'a>>,
    pub emission: &'a epoch_footer::Policy,
    pub reward: &'a Attribution,
    pub validator_keys: &'a [(Vec<u8>, Vec<u8>)],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub error_type: Vec<u8>,
    pub reason: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    Confirmed(BigInt),
    RejectedAfterFee { fee: BigInt, refusal: Refusal },
    Rejected(Refusal),
}
impl Effect {
    /// Adapt a native VM/validator completion. BFT has no deferred or sender-loop
    /// nonce outcome: unsupported execution aborts instead of inventing one.
    pub fn from_completion(tx: &Transaction, completion: Completion) -> Result<Self, Error> {
        match completion {
            Completion::Confirmed { .. } => Ok(Self::Confirmed(tx.ou.clone())),
            Completion::Rejected(rejection) => {
                let refusal = Refusal {
                    error_type: rejection.tag.into_bytes(),
                    reason: rejection.reason,
                };
                Ok(if rejection.persist_state {
                    Self::RejectedAfterFee {
                        fee: tx.ou.clone(),
                        refusal,
                    }
                } else {
                    Self::Rejected(refusal)
                })
            }
            Completion::Deferred { .. } => Err(Error("BFT operation deferred".into())),
        }
    }
}
#[derive(Clone)]
pub struct Rejected {
    pub input_index: usize,
    pub refusal: Refusal,
    pub charged: bool,
}
#[derive(Clone, Default)]
pub struct Artifacts {
    /// Input index and canonical position (including rejected candidates).
    pub confirmed: Vec<(usize, usize)>,
    pub rejected: Vec<Rejected>,
    pub confirmed_fees: BigInt,
    pub transaction_count: usize,
}
pub struct Executed {
    pub root: octra_node_protocol::irmin::Hash,
    pub artifacts: Artifacts,
    pub validators: validator_epoch::Advanced,
    pub footer: epoch_footer::Footer,
}
fn error(value: impl std::fmt::Display) -> Error {
    Error(value.to_string())
}
/// Public money operations shared with the sender path. All other operation
/// families require their real execution host, including private transfers.
pub fn public(
    tx: &Transaction,
    ledger: &mut Ledger,
    state: &mut StateBatch,
) -> Result<Effect, Error> {
    if tx.op_type == OpType::Standard {
        // Epoch_exec debits amount + OU then credits amount. The legacy ledger
        // transfer helper additionally checks fee sign; network shape admission
        // belongs before this low-level transition, as it does in the native node.
        let refuse = |tag: &[u8], reason: String| {
            Effect::Rejected(Refusal {
                error_type: tag.to_vec(),
                reason: reason.into_bytes(),
            })
        };
        if let Err(e) = ledger.debit(&tx.from, &(&tx.amount + &tx.ou), tx.nonce, None) {
            return Ok(refuse(b"insufficient_balance", e.0));
        }
        if ledger.account(&tx.to).is_none() {
            let _ = ledger.add_account(&tx.to, 0.into(), None);
        }
        return Ok(match ledger.credit(&tx.to, &tx.amount, None) {
            Ok(()) => Effect::Confirmed(tx.ou.clone()),
            Err(e) => refuse(b"supply_violation", e.0),
        });
    }
    if !matches!(tx.op_type, OpType::Standard | OpType::Op01Burn) {
        return Err(Error("BFT operation requires an execution host".into()));
    }
    Effect::from_completion(tx, execution::apply_public(tx, ledger, state)?)
}

/// Execute a whole epoch into an already-active speculative batch. The caller
/// owns operation-local auxiliary artifacts and must discard them on failure.
pub fn execute(
    request: &Request<'_>,
    fold: &impl EpochFold,
    transactions: &[Transaction],
    ledger: &mut Ledger,
    state: &mut StateBatch,
    process: impl FnMut(&Transaction, &mut Ledger, &mut StateBatch) -> Result<Effect, Error>,
) -> Result<Executed, Error> {
    execute_checked(request, fold, transactions, ledger, state, process, |_| {
        Ok(())
    })
}

pub(crate) fn execute_checked(
    request: &Request<'_>,
    fold: &impl EpochFold,
    transactions: &[Transaction],
    ledger: &mut Ledger,
    state: &mut StateBatch,
    mut process: impl FnMut(&Transaction, &mut Ledger, &mut StateBatch) -> Result<Effect, Error>,
    verify: impl FnOnce(&Executed) -> Result<(), Error>,
) -> Result<Executed, Error> {
    let envelope = request.envelope;
    transaction::check_compute(envelope.compute, envelope.settle, transactions)
        .and_then(|()| transaction::check_envelopes(envelope.envelope, transactions))
        .map_err(|e| Error(format!("transaction envelope: {e}")))?;
    ledger.clear_spent_nonces();
    if let Some(preverification) = &request.preverification {
        // Ledger.hash is the full committed Irmin tree hash. The validator
        // environment's previous root may instead include the consensus index.
        let root = hex::encode(state.published_root().map_err(error)?);
        preverify_state::check(
            preverification.gate,
            transactions,
            preverification.crypto_active,
            preverification.minimum,
            root.as_bytes(),
            ledger,
            &state.snapshot(),
        )
        .map_err(|e| Error(format!("preverify_commit_gate:{e}")))?;
    }
    let mut ordered = transactions
        .iter()
        .enumerate()
        .map(|(index, tx)| {
            tx.hash()
                .map(|hash| (tx.from.as_slice(), tx.nonce, hash, index))
                .map_err(error)
        })
        .collect::<Result<Vec<_>, _>>()?;
    ordered.sort_by(|a, b| (a.0, a.1, a.2).cmp(&(b.0, b.1, b.2)));
    let saved = state.save().map_err(error)?;
    let depth = ledger.journal_depth();
    ledger.begin_journal();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let epoch = request.validators.epoch;
        let context = fold
            .resolve(epoch, state)
            .map_err(|e| Error(format!("validator set fold rule rejected: {e}")))?;
        let mut artifacts = Artifacts {
            transaction_count: transactions.len(),
            ..Artifacts::default()
        };
        for (position, (_, _, _, index)) in ordered.into_iter().enumerate() {
            let tx = &transactions[index];
            let saved = state.save().map_err(error)?;
            ledger.begin_journal();
            let effect = process(tx, ledger, state)?;
            match effect {
                Effect::Confirmed(fee) => {
                    if request
                        .sender_key_activation
                        .is_some_and(|activation| epoch >= activation)
                        && ledger
                            .account(&tx.from)
                            .is_none_or(|account| account.public_key.is_none())
                    {
                        if let Some(key) = &tx.public_key {
                            ledger.register_public_key(&tx.from, key.clone());
                        }
                    }
                    ledger.commit_journal().map_err(error)?;
                    artifacts.confirmed.push((index, position));
                    artifacts.confirmed_fees += fee;
                }
                Effect::RejectedAfterFee { fee, refusal } => {
                    ledger.commit_journal().map_err(error)?;
                    let charged = context.vm_bytes == RuleMode::Active
                        && matches!(
                            tx.op_type,
                            OpType::ComputeFund | OpType::ComputeReturn | OpType::ComputeSettle
                        );
                    artifacts.rejected.push(Rejected {
                        input_index: index,
                        refusal,
                        charged,
                    });
                    artifacts.confirmed_fees += fee;
                }
                Effect::Rejected(refusal) => {
                    ledger.abort_journal();
                    state.restore(saved).map_err(error)?;
                    artifacts.rejected.push(Rejected {
                        input_index: index,
                        refusal,
                        charged: false,
                    });
                }
            }
        }
        let validators = validator_epoch::advance(&request.validators, fold, state)?;
        let footer = epoch_footer::apply(
            request.emission,
            &epoch_footer::Request {
                epoch,
                reward: request.reward,
                validator_keys: request.validator_keys,
                confirmed_fees: artifacts.confirmed_fees.clone(),
            },
            ledger,
            state,
        )
        .map_err(error)?;
        account_store::flush_dirty(ledger, state, context.account_mode).map_err(error)?;
        let root = state.root().map_err(error)?;
        let executed = Executed {
            root,
            artifacts,
            validators,
            footer,
        };
        verify(&executed)?;
        ledger.commit_journal().map_err(error)?;
        Ok(executed)
    }));
    if !matches!(result, Ok(Ok(_))) {
        while ledger.journal_depth() > depth {
            ledger.abort_journal();
        }
        state.restore(saved).map_err(error)?;
    }
    ledger.clear_spent_nonces();
    match result {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
