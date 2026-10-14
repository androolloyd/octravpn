//! Circle transitions shared by sender and BFT epoch execution.
//! Inputs must already pass epoch admission and signature/rule checks. This host
//! stages fee, value, stable storage and receipts; it never publishes an epoch.
use std::collections::BTreeMap;

use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive, Zero};
use octra_node_protocol::{
    native_json::{Document, Value},
    state::Ledger,
    transaction::{json_string, native_float, OpType, Transaction},
};

use crate::{
    circle::{CircleRuntime, WasmProfile, WasmRules},
    circle_call::{self, Context, VmReceipt},
    circle_receipt::ReceiptBudget,
    execution::{self, Completion, Error, Executed, OperationHost, Rejection, Route},
    state_batch::StateBatch,
};

#[derive(Clone, Copy)]
pub struct Rules {
    pub wasm: WasmRules,
    pub manifest: WasmProfile,
    pub update_policy: bool,
    /// Native VmBytes mode controls inspection and the outer receipt budget.
    pub inspect: bool,
    pub storage_proof: bool,
    pub fhe_work: bool,
}

pub struct Batch {
    pub outcomes: Vec<Executed>,
    /// Auxiliary native VM receipts keyed by transaction hash. These are not
    /// the consensus outcome/preverification receipts in the epoch header.
    pub receipts: BTreeMap<String, Vec<u8>>,
    pub fees: BigInt,
    pub bindings: BTreeMap<String, circle_call::Binding>,
}
#[derive(Clone, Copy)]
pub enum Verification<'a> {
    Direct,
    Capture,
    Consume {
        root: &'a [u8],
        gate: &'a octra_node_protocol::preverify_commit::Gate,
    },
}

/// A fresh internal host owns all auxiliary effects for the batch. If any
/// operation is unavailable, the sender loop restores state/ledger and these
/// unpublished receipts and fee totals are dropped together.
pub fn execute(
    runtime: &CircleRuntime,
    rules: Rules,
    epoch: i64,
    receipt_time: f64,
    transactions: &[Transaction],
    ledger: &mut Ledger,
    state: &mut StateBatch,
) -> Result<Batch, Error> {
    execute_verified(
        runtime,
        rules,
        epoch,
        receipt_time,
        transactions,
        ledger,
        state,
        Verification::Direct,
    )
}

#[allow(clippy::too_many_arguments)] // Explicit execution state and receipt binding.
pub fn execute_verified(
    runtime: &CircleRuntime,
    rules: Rules,
    epoch: i64,
    receipt_time: f64,
    transactions: &[Transaction],
    ledger: &mut Ledger,
    state: &mut StateBatch,
    verification: Verification<'_>,
) -> Result<Batch, Error> {
    let parent_root = hex::encode(state.root().map_err(operational)?);
    let mut host = Calls::new(
        runtime,
        rules,
        epoch,
        receipt_time,
        parent_root.as_bytes(),
        verification,
    );
    let outcomes = execution::execute_checked(transactions, ledger, state, &mut host)?;
    Ok(Batch {
        fees: execution::confirmed_fees(transactions, &outcomes) + host.charged_fees,
        outcomes,
        receipts: host.receipts,
        bindings: host.bindings,
    })
}

/// One speculative execution attempt. Discard it when the surrounding epoch
/// fails; auxiliary receipts have no authority until canonical publication.
pub struct Calls<'a> {
    runtime: &'a CircleRuntime,
    rules: Rules,
    epoch: i64,
    receipt_time: f64,
    parent_root: Vec<u8>,
    receipts: BTreeMap<String, Vec<u8>>,
    charged_fees: BigInt,
    bindings: BTreeMap<String, circle_call::Binding>,
    verification: Verification<'a>,
}
fn operational(error: impl std::fmt::Display) -> Error {
    Error(error.to_string())
}
fn rejection(
    tag: &str,
    reason: impl AsRef<[u8]>,
    notify: Option<&str>,
    consume: bool,
    persist: bool,
) -> Completion {
    Completion::Rejected(Rejection {
        tag: tag.into(),
        reason: reason.as_ref().to_vec(),
        notify_reason: notify.map(|value| value.as_bytes().to_vec()),
        consume_nonce: consume,
        persist_state: persist,
    })
}
fn text(raw: &[u8]) -> Result<&str, Error> {
    std::str::from_utf8(raw).map_err(|_| operational("authenticated caller is not UTF-8"))
}
fn limit(ou: &BigInt) -> i64 {
    ou.to_i64()
        .filter(|n| (-(1i64 << 62)..(1i64 << 62)).contains(n))
        .unwrap_or(1_000_000)
        .max(1_000_000)
}
impl<'a> Calls<'a> {
    pub fn new(
        runtime: &'a CircleRuntime,
        rules: Rules,
        epoch: i64,
        receipt_time: f64,
        parent_root: &[u8],
        verification: Verification<'a>,
    ) -> Self {
        Self {
            runtime,
            rules,
            epoch,
            receipt_time,
            parent_root: parent_root.to_vec(),
            verification,
            receipts: BTreeMap::new(),
            charged_fees: BigInt::zero(),
            bindings: BTreeMap::new(),
        }
    }
    pub fn receipts(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.receipts
    }
    pub fn bindings(&self) -> &BTreeMap<String, circle_call::Binding> {
        &self.bindings
    }
    pub fn process(
        &mut self,
        tx: &Transaction,
        ledger: &mut Ledger,
        state: &mut StateBatch,
    ) -> Result<crate::epoch_execution::Effect, Error> {
        crate::epoch_execution::Effect::from_completion(
            tx,
            self.execute(execution::route(tx), tx, ledger, state)?,
        )
    }
    fn charged(&mut self, tx: &Transaction, tag: &str, reason: &[u8]) -> Completion {
        self.charged_fees += &tx.ou;
        rejection(tag, reason, None, true, true)
    }
}
impl OperationHost for Calls<'_> {
    fn execute(
        &mut self,
        route: Route,
        tx: &Transaction,
        ledger: &mut Ledger,
        state: &mut StateBatch,
    ) -> Result<Completion, Error> {
        if route == Route::CircleOperation
            && matches!(
                tx.op_type,
                OpType::CircleDeploy | OpType::CircleProgramUpdate
            )
        {
            return crate::circle_code::execute(self.runtime, self.rules, tx, ledger, state);
        }
        if route != Route::VirtualMachine || tx.op_type != OpType::CircleCall {
            return Err(operational(
                "operation requires an unavailable execution host",
            ));
        }
        // The fee debits the base ledger, outside the VM's staged value effects.
        // Ordinary VM failure retains it; malformed/missing input follows the
        // native outer savepoint policy and rolls it back instead.
        if let Err(error) = ledger.debit(&tx.from, &tx.ou, tx.nonce, None) {
            return Ok(rejection(
                "insufficient_balance",
                &error.0,
                None,
                false,
                false,
            ));
        }
        let (Some(method), Some(params)) = (&tx.encrypted_data, &tx.message) else {
            return Ok(rejection(
                "malformed_transaction",
                "invalid circle call format",
                Some("Invalid circle call format"),
                false,
                false,
            ));
        };
        // Native JSON exception text is not yet qualified. Abort operationally
        // rather than charging an invented circle_call_exception outcome.
        let parsed = Document::parse(params)
            .map_err(|e| operational(format!("Circle parameter parsing unavailable: {e}")))?;
        let params = if matches!(parsed.root(), Value::List(_)) {
            parsed
        } else {
            Document::parse(b"[]").map_err(operational)?
        };
        if tx.amount.is_positive()
            && ledger
                .account(&tx.from)
                .is_none_or(|a| a.balance < tx.amount)
        {
            return Ok(rejection(
                "insufficient_balance",
                "insufficient balance for circle value",
                Some("Insufficient balance for value"),
                true,
                false,
            ));
        }
        let hash = hex::encode(tx.hash().map_err(operational)?);
        let context = Context {
            caller: text(&tx.from)?.into(),
            tx_hash: hash.clone(),
            epoch: self.epoch,
            epoch_time_ms: octra_node_protocol::consensus::policy::time_of_seconds(
                self.receipt_time,
            )
            .unwrap_or(0),
            tree_hash: self.parent_root.clone(),
            node_id: tx.to.clone(),
            depth: 0,
            limit: limit(&tx.ou),
            profile: self.rules.wasm,
            manifest: self.rules.manifest,
            inspect: self.rules.inspect,
            update_policy: self.rules.update_policy,
            hfhe_strict: self.rules.storage_proof,
            storage_proof: self.rules.storage_proof,
            fhe_work: self.rules.fhe_work,
        };
        let expected = match self.verification {
            Verification::Consume { root, gate } => {
                let receipt = gate.receipt(tx).map_err(operational)?;
                let octra_node_protocol::preverify_receipt::Binding::Circle(binding) =
                    &receipt.binding
                else {
                    return Err(operational("circle_receipt_binding_missing"));
                };
                if binding.snapshot_hash != octra_node_protocol::preverify_receipt::state_hash(root)
                {
                    return Err(operational("circle_receipt_state_mismatch"));
                }
                Some((root, binding))
            }
            _ => None,
        };
        let mode = match (self.verification, expected) {
            (_, Some((_, binding))) => circle_call::ReceiptMode::Consume(&binding.transcript),
            (Verification::Capture, _) => circle_call::ReceiptMode::Capture,
            _ => circle_call::ReceiptMode::Direct,
        };
        let saved_effects = state.save().map_err(operational)?;
        let mut journal = crate::circle_journal::Journal::new(self.runtime, ledger, state);
        if tx.amount.is_positive()
            && !journal
                .values
                .transfer(ledger, &tx.from, &tx.to, &tx.amount)
        {
            return Err(operational(
                "Circle value journal disagrees with admitted balance",
            ));
        }
        let call = journal
            .execute(
                &tx.to,
                method,
                &params,
                &context,
                &tx.amount,
                mode,
                self.rules.inspect.then_some(&mut ReceiptBudget::default()),
            )
            .map_err(|e| operational(format!("Circle execution unavailable: {e:?}")))?;
        let values = journal.values;
        if let Some((root, expected)) = expected {
            if call
                .binding()
                .map(|binding| binding.at_snapshot(root))
                .as_ref()
                != Some(expected)
            {
                return Err(operational("circle_receipt_binding_mismatch"));
            }
        }
        if let Some(binding) = call.binding() {
            self.bindings.insert(hash.clone(), binding.clone());
        }
        let receipt = call.receipt();
        self.receipts.insert(
            hash,
            receipt_json(&tx.to, method, receipt, self.epoch, self.receipt_time)?,
        );
        if !receipt.success {
            let reason = receipt
                .events
                .iter()
                .find_map(|event| {
                    (event.topic == b"Require")
                        .then(|| event.values.first())
                        .flatten()
                })
                .map_or_else(
                    || {
                        receipt
                            .error
                            .clone()
                            .unwrap_or_else(|| b"execution reverted".to_vec())
                    },
                    |reason| [b"execution reverted [".as_slice(), reason, b"]"].concat(),
                );
            state.restore(saved_effects).map_err(operational)?;
            return Ok(self.charged(tx, "circle_call_failed", &reason));
        }
        match call.apply(state) {
            Ok(_) => (),
            Err(octra_node_protocol::circle_wasm::Error::Rejected(reason)) => {
                state.restore(saved_effects).map_err(operational)?;
                return Ok(self.charged(tx, "circle_call_commit_failed", &reason));
            }
            Err(error) => {
                return Err(operational(format!(
                    "Circle effect commit unavailable: {error:?}"
                )))
            }
        }
        values.commit(ledger)?;
        Ok(Completion::Confirmed {
            created_account: None,
        })
    }
}

fn receipt_json(
    target: &[u8],
    method: &[u8],
    receipt: &VmReceipt,
    epoch: i64,
    now: f64,
) -> Result<Vec<u8>, Error> {
    let mut out = b"{\"contract\":".to_vec();
    json_string(&mut out, target);
    out.extend_from_slice(b",\"method\":");
    json_string(&mut out, method);
    out.extend_from_slice(if receipt.success {
        b",\"success\":true"
    } else {
        b",\"success\":false"
    });
    out.extend_from_slice(format!(",\"effort\":{},\"events\":[", receipt.effort).as_bytes());
    for (i, event) in receipt.events.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(b"{\"contract\":");
        json_string(&mut out, &event.contract);
        out.extend_from_slice(format!(",\"depth\":{},\"event\":", event.depth).as_bytes());
        json_string(&mut out, &event.topic);
        out.extend_from_slice(b",\"values\":[");
        for (index, value) in event.values.iter().enumerate() {
            if index > 0 {
                out.push(b',');
            }
            json_string(&mut out, value);
        }
        out.extend_from_slice(b"]}");
    }
    out.extend_from_slice(b"],\"error\":");
    match &receipt.error {
        Some(error) => json_string(&mut out, error),
        None => out.extend_from_slice(b"null"),
    }
    out.extend_from_slice(
        format!(
            ",\"epoch\":{epoch},\"ts\":{}}}",
            native_float(now).map_err(operational)?
        )
        .as_bytes(),
    );
    Ok(out)
}
