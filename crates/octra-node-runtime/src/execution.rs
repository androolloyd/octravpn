//! Native sender grouping, nonce progression, dispatch and transaction savepoints.
//! The caller supplies transactions already checked against the epoch's rule fold.
//! Every non-public operation requires a real host; host failures abort execution.
use crate::state_batch::StateBatch;
use num_bigint::BigInt;
use num_traits::Signed;
use octra_node_protocol::{
    state::{Ledger, TransferError},
    transaction::{Nonce, OpType, Transaction},
};
use std::collections::BTreeMap;
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Error(pub String);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Public,
    CircleOperation,
    VirtualMachine,
    Encrypt,
    Decrypt,
    KeySwitch,
    Stealth,
    Claim,
    Validator,
    Compute,
    Upgrade,
}
pub fn route(tx: &Transaction) -> Route {
    use OpType::{
        CircleAssetPut, CircleAssetPutEncrypted, CircleBalanceCellPut, CircleCall, CircleDeploy,
        CircleHfhePolicyPut, CircleIngressCommit, CircleKeyErase, CircleKeyExtend, CircleKeyGrant,
        CircleKeyPolicyPut, CircleKeyRevoke, CircleOutboxOpen, CircleProgramUpdate,
        CircleRegisterCellPut, CircleRelayCancel, CircleRelayClaim, CircleSealedSlotPut,
        CircleSlotPolicyPut, CircleStateDescriptorPut, CircleTransportPolicyPut, Claim,
        ComputeFund, ComputeReturn, ComputeSettle, ContractCall, ContractDeploy, ContractUpgrade,
        Decrypt, Encrypt, KeySwitch, MultiExec, Op01Burn, Private, ProgramDeploy, ProgramExec,
        Recrypt, Standard, Stealth, ValidatorBond, ValidatorEvidence, ValidatorExit,
        ValidatorReady, ValidatorSetUpdate, ValidatorWithdraw,
    };
    match tx.op_type {
        CircleDeploy
        | CircleProgramUpdate
        | CircleAssetPut
        | CircleAssetPutEncrypted
        | CircleSealedSlotPut
        | CircleSlotPolicyPut
        | CircleStateDescriptorPut
        | CircleBalanceCellPut
        | CircleRegisterCellPut
        | CircleTransportPolicyPut
        | CircleHfhePolicyPut
        | CircleKeyPolicyPut
        | CircleKeyGrant
        | CircleKeyExtend
        | CircleKeyRevoke
        | CircleKeyErase
        | CircleOutboxOpen
        | CircleRelayClaim
        | CircleRelayCancel
        | CircleIngressCommit => Route::CircleOperation,
        CircleCall | ContractDeploy | ProgramDeploy | ContractCall | ProgramExec | MultiExec => {
            Route::VirtualMachine
        }
        Encrypt if tx.from == tx.to => Route::Encrypt,
        Decrypt if tx.from == tx.to => Route::Decrypt,
        KeySwitch if tx.from == tx.to => Route::KeySwitch,
        Encrypt | Decrypt | KeySwitch | Recrypt | Standard | Op01Burn | Private => Route::Public,
        Stealth => Route::Stealth,
        Claim => Route::Claim,
        ValidatorSetUpdate | ValidatorReady | ValidatorBond | ValidatorExit | ValidatorWithdraw
        | ValidatorEvidence => Route::Validator,
        ComputeFund | ComputeReturn | ComputeSettle => Route::Compute,
        ContractUpgrade => Route::Upgrade,
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejection {
    pub tag: String,
    /// Native OCaml strings may contain arbitrary bytes, including VM output.
    pub reason: Vec<u8>,
    pub notify_reason: Option<Vec<u8>>,
    pub consume_nonce: bool,
    pub persist_state: bool,
}
impl Rejection {
    fn new(tag: &str, reason: &str) -> Self {
        Self {
            tag: tag.into(),
            reason: reason.into(),
            notify_reason: Some(reason.into()),
            consume_nonce: false,
            persist_state: false,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Completion {
    Confirmed { created_account: Option<Vec<u8>> },
    Rejected(Rejection),
    Deferred { consume_nonce: bool },
}
impl Completion {
    fn consumes_nonce(&self) -> bool {
        match self {
            Self::Confirmed { .. } => true,
            Self::Rejected(value) => value.consume_nonce,
            Self::Deferred { consume_nonce } => *consume_nonce,
        }
    }
    fn persists(&self) -> bool {
        matches!(self, Self::Confirmed { .. })
            || matches!(self,Self::Rejected(value)if value.persist_state)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Completed(Completion),
    NonceMismatch { expected: Nonce, got: Nonce },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Executed {
    pub input_index: usize,
    pub outcome: Outcome,
}
pub trait OperationHost {
    fn execute(
        &mut self,
        route: Route,
        tx: &Transaction,
        ledger: &mut Ledger,
        store: &mut StateBatch,
    ) -> Result<Completion, Error>;
}
/// Grouping reverses each input sender list before stable nonce sorting, matching
/// native Hashtbl prepending even when historical rules permit duplicate nonces.
pub fn group(transactions: &[Transaction]) -> Vec<Vec<usize>> {
    let mut by_sender: BTreeMap<&[u8], Vec<usize>> = BTreeMap::new();
    for (index, tx) in transactions.iter().enumerate() {
        by_sender.entry(&tx.from).or_default().push(index);
    }
    by_sender
        .into_values()
        .map(|mut values| {
            values.reverse();
            values.sort_by_key(|index| transactions[*index].nonce);
            values
        })
        .collect()
}
fn reject(tag: &str, reason: &str) -> Completion {
    Completion::Rejected(Rejection::new(tag, reason))
}
pub(crate) fn apply_public(
    tx: &Transaction,
    ledger: &mut Ledger,
    store: &mut StateBatch,
) -> Result<Completion, Error> {
    match tx.op_type {
        OpType::Standard => {
            let created_account = ledger.account(&tx.to).is_none().then(|| tx.to.clone());
            Ok(
                match ledger.transfer(&tx.from, &tx.to, &tx.amount, &tx.ou, tx.nonce) {
                    Ok(()) => Completion::Confirmed { created_account },
                    Err(TransferError::DebitRejected(reason)) => {
                        reject("insufficient_balance", reason)
                    }
                    Err(TransferError::CreditRejected(reason)) => {
                        reject("supply_violation", reason)
                    }
                },
            )
        }
        OpType::Op01Burn => {
            const AUTHORITY: &[u8] = b"oct7xCozDD9JEsbeVpo5C7HXp2BJbKqfmNUHmDDCCTtWcGb";
            let reason = if tx.from != AUTHORITY {
                Some("op01_burn: restricted to mining pool authority")
            } else if tx.from != tx.to {
                Some("op01_burn: must be self-transaction (from equals to)")
            } else if !tx.amount.is_positive() {
                Some("op01_burn: amount must be positive")
            } else if store.get(&[b"meta", b"op01_2026_burn_executed"]) == Some(b"true") {
                Some("op01_burn: already executed (one-shot ceremony)")
            } else {
                None
            };
            if let Some(reason) = reason {
                return Ok(reject("op01_burn_rejected", reason));
            }
            if let Err(error) = ledger.debit(&tx.from, &tx.amount, tx.nonce, None) {
                return Ok(reject("op01_burn_rejected", &error.0));
            }
            store
                .set(&[b"meta", b"op01_2026_burn_executed"], b"true".to_vec())
                .map_err(|e| Error(e.to_string()))?;
            Ok(Completion::Confirmed {
                created_account: None,
            })
        }
        OpType::Private => Ok(reject(
            "deprecated",
            "PrivateOp is disabled — use StealthOp V5",
        )),
        OpType::Recrypt => Ok(reject("deprecated", "RecryptOp is disabled")),
        OpType::Encrypt | OpType::Decrypt | OpType::KeySwitch => {
            let mut rejection = Rejection::new(
                "self_only_operation",
                "encrypt/decrypt/key_switch must have from == to",
            );
            rejection.notify_reason =
                Some("EncryptOp/DecryptOp/KeySwitch must have from == to".into());
            Ok(Completion::Rejected(rejection))
        }
        _ => Err(Error("public dispatch invariant violated".into())),
    }
}
/// Execute all supplied sender batches atomically. A host failure or unwind restores
/// the entire application attempt, preventing a caller from publishing partial
/// effects after the native equivalent would require restart from committed state.
pub fn execute_checked<H: OperationHost>(
    transactions: &[Transaction],
    ledger: &mut Ledger,
    store: &mut StateBatch,
    host: &mut H,
) -> Result<Vec<Executed>, Error> {
    let depth = ledger.journal_depth();
    ledger.begin_journal();
    let saved = match store.save() {
        Ok(saved) => saved,
        Err(error) => {
            ledger.abort_journal();
            return Err(Error(error.to_string()));
        }
    };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        execute_inner(transactions, ledger, store, host)
    }));
    match outcome {
        Ok(Ok(events)) => {
            ledger.commit_journal().map_err(|e| Error(e.to_string()))?;
            Ok(events)
        }
        failure => {
            while ledger.journal_depth() > depth {
                ledger.abort_journal();
            }
            store.restore(saved).map_err(|e| Error(e.to_string()))?;
            match failure {
                Ok(Err(error)) => Err(error),
                Err(panic) => std::panic::resume_unwind(panic),
                Ok(Ok(_)) => unreachable!(),
            }
        }
    }
}

/// Savepoint commits accepted or explicitly charged rejection state, and rolls
/// back ledger and object-tree effects on refusal or operational failure.
fn execute_inner<H: OperationHost>(
    transactions: &[Transaction],
    ledger: &mut Ledger,
    store: &mut StateBatch,
    host: &mut H,
) -> Result<Vec<Executed>, Error> {
    let mut executed = Vec::new();
    for sender in group(transactions) {
        let Some(&first) = sender.first() else {
            continue;
        };
        let mut expected = ledger
            .account(&transactions[first].from)
            .map_or(Nonce::new(1).expect("one"), |a| a.nonce.successor());
        for index in sender {
            let tx = &transactions[index];
            if tx.nonce != expected {
                executed.push(Executed {
                    input_index: index,
                    outcome: Outcome::NonceMismatch {
                        expected,
                        got: tx.nonce,
                    },
                });
                continue;
            }
            ledger.begin_journal();
            let savepoint = match store.save() {
                Ok(savepoint) => savepoint,
                Err(error) => {
                    ledger.abort_journal();
                    return Err(Error(error.to_string()));
                }
            };
            let route = route(tx);
            let result = if route == Route::Public {
                apply_public(tx, ledger, store)
            } else {
                host.execute(route, tx, ledger, store)
            };
            match result {
                Ok(completion) => {
                    if completion.persists() {
                        ledger.commit_journal().map_err(|e| Error(e.to_string()))?;
                    } else {
                        ledger.abort_journal();
                        store.restore(savepoint).map_err(|e| Error(e.to_string()))?;
                    }
                    if completion.consumes_nonce() {
                        expected = expected.successor();
                    }
                    executed.push(Executed {
                        input_index: index,
                        outcome: Outcome::Completed(completion),
                    });
                }
                Err(error) => {
                    ledger.abort_journal();
                    store.restore(savepoint).map_err(|e| Error(e.to_string()))?;
                    return Err(error);
                }
            }
        }
    }
    Ok(executed)
}
/// Native confirmation accounting records declared OU for every confirmed tx.
pub fn confirmed_fees(transactions: &[Transaction], executed: &[Executed]) -> BigInt {
    executed
        .iter()
        .filter(|event| {
            matches!(
                event.outcome,
                Outcome::Completed(Completion::Confirmed { .. })
            )
        })
        .map(|event| &transactions[event.input_index].ou)
        .sum()
}
