// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native deploy, call, multi-exec and upgrade transactions. The sender/BFT
//! executor owns their outer ledger/tree savepoint and canonical publication.
use crate::{
    circle::CircleRuntime,
    circle_call::Context,
    circle_journal::Journal,
    circle_receipt::ReceiptBudget,
    circle_transaction::Rules,
    execution::{Completion, Error, OperationHost, Rejection, Route},
    program::{self, artifact::SourceRules, receipt, Artifact},
    state_batch::StateBatch,
};
use num_bigint::BigInt;
use num_traits::{Signed, Zero};
use octra_node_protocol::{
    contract,
    native_json::{Document, ReadMode, Value},
    program_upgrade, resource_lanes,
    state::Ledger,
    transaction::{decode_base64, OpType, Transaction},
};
use std::collections::{btree_map::Entry, BTreeMap};
mod plan;

pub struct Calls<'a> {
    runtime: &'a CircleRuntime,
    rules: Rules,
    source: SourceRules,
    epoch: i64,
    time: f64,
    parent_root: Vec<u8>,
    max_calls: usize,
    receipts: BTreeMap<String, Vec<u8>>,
}
fn operational(error: impl std::fmt::Display) -> Error {
    Error(error.to_string())
}
fn reject(
    tag: &str,
    reason: impl AsRef<[u8]>,
    notify: Option<&[u8]>,
    consume: bool,
    persist: bool,
) -> Completion {
    Completion::Rejected(Rejection {
        tag: tag.into(),
        reason: reason.as_ref().to_vec(),
        notify_reason: notify.map(<[u8]>::to_vec),
        consume_nonce: consume,
        persist_state: persist,
    })
}
fn charged(tag: &str, reason: impl AsRef<[u8]>) -> Completion {
    reject(tag, reason, None, true, true)
}
fn debit(tx: &Transaction, ledger: &mut Ledger) -> Option<Completion> {
    ledger
        .debit(&tx.from, &tx.ou, tx.nonce, None)
        .err()
        .map(|error| reject("insufficient_balance", error.0, None, false, false))
}
// Preserve the native owned-input and typed diagnostic interface.
#[allow(clippy::needless_pass_by_value)]
fn host(error: octra_node_protocol::circle_wasm::Error) -> Error {
    operational(format!("Program execution unavailable: {error:?}"))
}
impl<'a> Calls<'a> {
    pub fn new(
        runtime: &'a CircleRuntime,
        rules: Rules,
        source: SourceRules,
        epoch: i64,
        time: f64,
        parent_root: &[u8],
        max_calls: usize,
    ) -> Result<Self, Error> {
        if !(1..=64).contains(&max_calls) {
            return Err(operational("multi-exec call limit outside native bounds"));
        }
        Ok(Self {
            runtime,
            rules,
            source,
            epoch,
            time,
            parent_root: parent_root.to_vec(),
            max_calls,
            receipts: BTreeMap::new(),
        })
    }
    pub fn receipts(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.receipts
    }
    pub fn process(
        &mut self,
        tx: &Transaction,
        ledger: &mut Ledger,
        state: &mut StateBatch,
    ) -> Result<crate::epoch_execution::Effect, Error> {
        crate::epoch_execution::Effect::from_completion(
            tx,
            self.execute(crate::execution::route(tx), tx, ledger, state)?,
        )
    }
    fn context(&self, tx: &Transaction) -> Result<Context, Error> {
        Ok(Context {
            caller: std::str::from_utf8(&tx.from).map_err(operational)?.into(),
            tx_hash: hex::encode(tx.hash().map_err(operational)?),
            epoch: self.epoch,
            epoch_time_ms: octra_node_protocol::consensus::policy::time_of_seconds(self.time)
                .unwrap_or(0),
            tree_hash: self.parent_root.clone(),
            node_id: tx.to.clone(),
            depth: 0,
            limit: resource_lanes::vm_limit(&tx.ou),
            profile: self.rules.wasm,
            manifest: self.rules.manifest,
            inspect: self.rules.inspect,
            update_policy: self.rules.update_policy,
            hfhe_strict: self.rules.storage_proof,
            hfhe_scope: None,
            storage_proof: self.rules.storage_proof,
            fhe_work: self.rules.fhe_work,
            object_cost: self.rules.object_cost,
        })
    }
    fn save(&mut self, tx: &Transaction, raw: Vec<u8>) -> Result<(), Error> {
        let hash = hex::encode(tx.hash().map_err(operational)?);
        match self.receipts.entry(hash) {
            Entry::Vacant(entry) => {
                entry.insert(raw);
                Ok(())
            }
            Entry::Occupied(entry) => Err(operational(format!(
                "duplicate VM receipt for {}",
                entry.key()
            ))),
        }
    }
    fn deploy(
        &mut self,
        tx: &Transaction,
        ledger: &mut Ledger,
        state: &mut StateBatch,
    ) -> Result<Completion, Error> {
        let Some(account) = ledger.account(&tx.from) else {
            return Ok(reject(
                "sender_not_found",
                "sender account does not exist",
                Some(b"Sender not found"),
                false,
                false,
            ));
        };
        if account.balance < tx.ou {
            return Ok(reject(
                "insufficient_balance",
                "insufficient balance for deploy fee",
                Some(b"Insufficient balance"),
                false,
                false,
            ));
        }
        if let Some(result) = debit(tx, ledger) {
            return Ok(result);
        }
        let source = tx.op_type == OpType::ProgramDeploy;
        let artifact = if source {
            let Some(encoded) = &tx.encrypted_data else {
                return Ok(charged(
                    "program_deploy_rejected",
                    "Program package missing",
                ));
            };
            match Artifact::source(encoded, self.source) {
                Ok(artifact) => artifact,
                Err(program::Error::Rejected(reason)) => {
                    return Ok(charged("program_deploy_rejected", reason))
                }
                Err(error) => return Err(operational(error)),
            }
        } else {
            let Some(encoded) = &tx.encrypted_data else {
                return Ok(reject(
                    "missing_bytecode",
                    "no bytecode in transaction",
                    Some(b"Missing bytecode"),
                    true,
                    false,
                ));
            };
            let Ok(raw) = decode_base64(encoded) else {
                return Ok(charged(
                    "contract_deploy_failed",
                    "Program deploy input failed",
                ));
            };
            match Artifact::binary(&raw, self.rules.storage_proof, self.runtime.program_keys()) {
                Ok(artifact) => artifact,
                Err(program::Error::Rejected(reason)) => {
                    let notify = [b"Invalid bytecode: ".as_slice(), &reason].concat();
                    return Ok(reject(
                        "invalid_bytecode",
                        reason,
                        Some(&notify),
                        false,
                        false,
                    ));
                }
                Err(error) => return Err(operational(error)),
            }
        };
        let expected = contract::address(artifact.raw(), &tx.from, tx.nonce.get());
        if expected != tx.to {
            return Ok(if source {
                charged(
                    "program_address_mismatch",
                    "Program address does not match source package",
                )
            } else {
                reject(
                    "contract_address_mismatch",
                    "expected address does not match",
                    Some(b"Contract address mismatch"),
                    false,
                    false,
                )
            });
        }
        let params = plan::params(tx.message.as_deref(), true)?
            .map_err(|_| operational("forgiving deploy parser returned a diagnostic"))?;
        let context = self.context(tx)?;
        let saved = state.save().map_err(operational)?;
        let mut journal = Journal::new(self.runtime, ledger, state);
        journal.fhe_memory = self.rules.fhe_work.then(Default::default);
        let deployed = journal
            .deploy_program(
                &artifact,
                &context,
                tx.nonce.get(),
                &params,
                self.rules.inspect.then_some(&mut ReceiptBudget::default()),
            )
            .map_err(host)?;
        let values = journal.values;
        let programs = journal.programs;
        self.save(
            tx,
            receipt::direct(
                &deployed.address,
                b"constructor",
                &deployed.receipt,
                source,
                self.epoch,
                self.time,
            )
            .map_err(operational)?,
        )?;
        if !deployed.receipt.success {
            state.restore(saved).map_err(operational)?;
            return Ok(charged(
                "constructor_failed",
                receipt::revert(&deployed.receipt, true),
            ));
        }
        programs.stage(state).map_err(operational)?;
        if ledger.account(&deployed.address).is_none() {
            ledger
                .add_account(&deployed.address, BigInt::zero(), None)
                .map_err(operational)?;
        }
        values.commit(ledger)?;
        Ok(Completion::Confirmed {
            created_account: None,
        })
    }
    fn call(
        &mut self,
        tx: &Transaction,
        ledger: &mut Ledger,
        state: &mut StateBatch,
    ) -> Result<Completion, Error> {
        if let Some(result) = debit(tx, ledger) {
            return Ok(result);
        }
        let (Some(method), Some(raw)) = (&tx.encrypted_data, &tx.message) else {
            return Ok(reject(
                "malformed_transaction",
                "invalid contract call format",
                Some(b"Invalid contract call format"),
                true,
                false,
            ));
        };
        let params = match plan::params(Some(raw), false)? {
            Ok(params) => params,
            Err(exception) => return Ok(charged("program_exec_exception", exception)),
        };
        if tx.amount.is_positive()
            && ledger
                .account(&tx.from)
                .is_none_or(|account| account.balance < tx.amount)
        {
            return Ok(reject(
                "insufficient_balance",
                "insufficient balance for contract value",
                Some(b"Insufficient balance for value"),
                true,
                false,
            ));
        }
        let context = self.context(tx)?;
        let saved = state.save().map_err(operational)?;
        let mut journal = Journal::new(self.runtime, ledger, state);
        journal.fhe_memory = self.rules.fhe_work.then(Default::default);
        if tx.amount.is_positive() && !journal.transfer(&tx.from, &tx.to, &tx.amount) {
            return Err(operational(
                "Program value journal disagrees with admitted balance",
            ));
        }
        let result = journal
            .run_program(
                &tx.to,
                method,
                &params,
                &tx.amount,
                &context,
                self.rules.inspect.then_some(&mut ReceiptBudget::default()),
            )
            .map_err(host)?;
        let values = journal.values;
        let programs = journal.programs;
        self.save(
            tx,
            receipt::direct(&tx.to, method, &result, true, self.epoch, self.time)
                .map_err(operational)?,
        )?;
        if !result.success {
            state.restore(saved).map_err(operational)?;
            return Ok(charged(
                "program_exec_failed",
                receipt::revert(&result, false),
            ));
        }
        programs.stage(state).map_err(operational)?;
        values.commit(ledger)?;
        Ok(Completion::Confirmed {
            created_account: None,
        })
    }
    // Keep the operation on the exclusive native execution/actor interface.
    #[allow(clippy::needless_pass_by_ref_mut)]
    fn upgrade(
        &mut self,
        tx: &Transaction,
        ledger: &mut Ledger,
        state: &mut StateBatch,
    ) -> Result<Completion, Error> {
        if let Some(result) = debit(tx, ledger) {
            return Ok(result);
        }
        let payload = match program_upgrade::parse(tx) {
            Ok(payload) => payload,
            Err(program_upgrade::Error::Rejected(reason)) => {
                return Ok(charged("program_upgrade_rejected", reason))
            }
            Err(error) => return Err(operational(error)),
        };
        let mut journal = program::Journal::default();
        match program::upgrade::stage(
            &mut journal,
            &state.snapshot(),
            self.runtime.program_keys(),
            self.rules.storage_proof,
            &tx.to,
            &tx.from,
            &payload,
        ) {
            Ok(_) => (),
            Err(program::Error::Rejected(reason)) => {
                return Ok(charged("program_upgrade_rejected", reason))
            }
            Err(error) => return Err(operational(error)),
        }
        journal.stage(state).map_err(operational)?;
        Ok(Completion::Confirmed {
            created_account: None,
        })
    }
    fn multi(
        &mut self,
        tx: &Transaction,
        ledger: &mut Ledger,
        state: &mut StateBatch,
    ) -> Result<Completion, Error> {
        let malformed = |reason| reject("malformed_transaction", reason, None, false, false);
        let Some(raw) = &tx.message else {
            return Ok(malformed(b"multi_exec requires calls payload".to_vec()));
        };
        let calls = match plan::multi(raw, self.max_calls)? {
            Ok(calls) => calls,
            Err(reason) => return Ok(malformed(reason)),
        };
        if let Some(result) = debit(tx, ledger) {
            return Ok(result);
        }
        let context = self.context(tx)?;
        let saved = state.save().map_err(operational)?;
        let mut journal = Journal::new(self.runtime, ledger, state);
        journal.fhe_memory = self.rules.fhe_work.then(Default::default);
        let mut trace = receipt::Trace::default();
        let mut error = None;
        let mut budget = self.rules.inspect.then(ReceiptBudget::default);
        for (index, call) in calls.into_iter().enumerate() {
            if trace.effort >= context.limit {
                error = Some(b"effort limit exceeded".to_vec());
                break;
            }
            if call.amount.is_positive() && journal.balance(&tx.from) < call.amount {
                error = Some(b"insufficient balance for program value".to_vec());
                break;
            }
            if call.amount.is_positive() && !journal.transfer(&tx.from, &call.target, &call.amount)
            {
                return Err(operational(
                    "multi-exec value journal disagrees with admitted balance",
                ));
            }
            let ctx = Context {
                limit: (context.limit - trace.effort).max(1),
                ..context.clone()
            };
            let result = journal
                .run_program(
                    &call.target,
                    &call.method,
                    &call.params,
                    &call.amount,
                    &ctx,
                    budget.as_mut(),
                )
                .map_err(host)?;
            error = trace.add(index, &call.target, &call.method, &call.amount, result);
            if error.is_some() {
                break;
            }
        }
        let values = journal.values;
        let programs = journal.programs;
        self.save(
            tx,
            trace
                .encode(error.as_deref(), self.epoch, self.time)
                .map_err(operational)?,
        )?;
        if let Some(error) = error {
            state.restore(saved).map_err(operational)?;
            return Ok(charged("multi_exec_failed", error));
        }
        programs.stage(state).map_err(operational)?;
        values.commit(ledger)?;
        Ok(Completion::Confirmed {
            created_account: None,
        })
    }
}
impl OperationHost for Calls<'_> {
    fn execute(
        &mut self,
        _route: Route,
        tx: &Transaction,
        ledger: &mut Ledger,
        state: &mut StateBatch,
    ) -> Result<Completion, Error> {
        let _crypto = self.runtime.crypto_scope(
            false,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );
        match tx.op_type {
            OpType::ContractDeploy | OpType::ProgramDeploy => self.deploy(tx, ledger, state),
            OpType::ContractCall | OpType::ProgramExec => self.call(tx, ledger, state),
            OpType::ContractUpgrade => self.upgrade(tx, ledger, state),
            OpType::MultiExec => self.multi(tx, ledger, state),
            _ => Err(operational("operation is not a Program transition")),
        }
    }
}
