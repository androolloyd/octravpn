// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native OCTB dispatcher and execution within the shared Circle journal.
use super::{
    binding, charge, load_call_storage, rejected, unavailable, Call, Context, Event, ReceiptMode,
    StorageLoad, VmReceipt,
};
use crate::circle_octb::{self, dispatcher};
use crate::{
    circle::CircleRuntime, circle_receipt::ReceiptBudget, circle_store, state_batch::Snapshot,
};
use crate::{circle_effects::Effects, circle_journal::Journal, octb as vm};
use num_bigint::BigInt;
use octra_node_protocol::{
    circle_program::{self, Deploy},
    circle_storage::{self, StorageTable},
    circle_wasm::{
        receipt::{Spawn, SpawnOwner},
        Error,
    },
    native_json::Document,
};
use vm::Value;

struct Host<'a, 'b, 'c> {
    journal: Option<&'a mut Journal<'b>>,
    calls: bool,
    context: &'c Context,
    before: &'c StorageTable,
    circle: &'c [u8],
    spawns: Vec<Spawn>,
    runtime: &'c CircleRuntime,
    snapshot: &'c Snapshot,
    fhe_policy: crate::circle_fhe::Policy,
}
impl vm::Host for Host<'_, '_, '_> {
    fn fhe_capability(&self, cap: vm::FheCapability) -> Result<bool, vm::Unavailable> {
        Ok(self.fhe_policy.allows(cap))
    }
    fn fhe_key(&mut self, address: &[u8]) -> Result<Option<vm::FheKeySource>, vm::Unavailable> {
        if !self.fhe_policy.key(address) {
            return Ok(None);
        }
        self.runtime
            .public_key(self.snapshot, address)
            .map(|key| key.map(vm::FheKeySource::Bytes))
            .map_err(|e| vm::Unavailable(e.to_string()))
    }
    fn groth16(
        &mut self,
        key: &[u8],
        proof: &[u8],
        inputs: &[u8],
    ) -> Result<bool, vm::Unavailable> {
        Ok(crate::groth16::verify(key, proof, inputs))
    }
    fn spawn(
        &mut self,
        request: vm::SpawnRequest<'_>,
        _storage: &mut StorageTable,
        _budget: Option<&mut octra_node_protocol::octb::work::Budget>,
    ) -> Result<Option<vm::Spawned>, vm::Unavailable> {
        if request.parent != self.circle
            || self.context.tx_hash.is_empty()
            || self.spawns.len() >= 4
        {
            return Ok(None);
        }
        let [Value::String(owner)] = request.params else {
            return Ok(None);
        };
        let mode = match owner.as_ref() {
            b"caller" => SpawnOwner::Caller,
            b"parent" => SpawnOwner::Parent,
            _ => return Ok(None),
        };
        if request.code.len() > 2_097_152 {
            return Ok(None);
        }
        let document = match Document::parse(request.code) {
            Ok(value) => value,
            Err(octra_node_protocol::native_json::Error::Syntax(_)) => return Ok(None),
            Err(error) => return Err(vm::Unavailable(error.to_string())),
        };
        let Ok(payload) = Deploy::from_document(&document) else {
            return Ok(None);
        };
        match crate::circle_code::prepare(&payload) {
            Ok(_) => (),
            Err(crate::circle_code::Failure::Refused(_)) => return Ok(None),
            Err(crate::circle_code::Failure::Unavailable(error)) => {
                return Err(vm::Unavailable(error.0))
            }
        }
        // Circle spawn indices count successful effects, independently of the
        // legacy contract's storage nonce and any inner storage rollback.
        let nonce = self.spawns.len() as i64;
        let address = circle_program::spawn_id(
            self.circle,
            self.context.caller.as_bytes(),
            self.context.tx_hash.as_bytes(),
            nonce,
            owner,
            request.code,
        );
        self.spawns.push(Spawn {
            circle_id: address.clone(),
            owner: mode,
            nonce,
            payload_json: request.code.to_vec(),
        });
        Ok(Some(vm::Spawned {
            address,
            effort: 0,
            events: vec![],
        }))
    }
    fn call(
        &mut self,
        request: vm::CallRequest<'_>,
        storage: &mut StorageTable,
        budget: Option<&mut octra_node_protocol::octb::work::Budget>,
    ) -> Result<Option<vm::Subcall>, vm::Unavailable> {
        if !self.calls {
            return Ok(None);
        }
        let result = (|| {
            let journal = self
                .journal
                .as_deref_mut()
                .ok_or_else(|| unavailable("OCTB cross-call requires an authenticated journal"))?;
            let cost =
                circle_store::storage_effort(self.before) + circle_store::storage_effort(storage);
            let spent = charge(0, &cost, request.limit)
                .ok_or_else(|| rejected("circle storage effort exceeds limit"))?;
            circle_storage::validate_delta(self.before, storage, true).map_err(|e| {
                rejected([b"circle reserved key write: ".as_slice(), &e.key].concat())
            })?;
            journal.stage(request.caller, storage.clone());
            let params = nested_parameters(request.params)?;
            let memory = std::mem::replace(&mut journal.fhe_memory, request.fhe_memory.clone());
            let result = ReceiptBudget::with_work(budget, |budget| {
                journal.nested(
                    request.caller,
                    request.target,
                    request.method,
                    &params,
                    self.context,
                    request.limit - spent,
                    budget,
                )
            });
            journal.fhe_memory = memory;
            let (response, effort, events) = result?;
            *storage = journal
                .storage(request.caller)
                .ok_or_else(|| unavailable("OCTB caller storage missing after subcall"))?;
            Ok(vm::Subcall {
                response,
                effort: spent + effort,
                events: events
                    .into_iter()
                    .map(|e| vm::Event {
                        contract: e.contract,
                        depth: e.depth,
                        name: e.topic,
                        values: e.values.into_iter().map(Value::string).collect(),
                    })
                    .collect(),
            })
        })();
        match result {
            Ok(value) => Ok(Some(value)),
            Err(Error::Rejected(_)) => Ok(None),
            Err(Error::Unavailable(reason)) => Err(vm::Unavailable(
                String::from_utf8_lossy(&reason).into_owned(),
            )),
        }
    }
    fn balance(&mut self, address: &[u8]) -> Result<BigInt, vm::Unavailable> {
        self.journal
            .as_ref()
            .map(|j| j.balance(address))
            .ok_or_else(|| {
                vm::Unavailable("OCTB balance requires an authenticated value journal".into())
            })
    }
    fn transfer(
        &mut self,
        from: &[u8],
        to: &[u8],
        amount: &BigInt,
    ) -> Result<bool, vm::Unavailable> {
        if !self.calls {
            return Ok(false);
        }
        self.journal
            .as_mut()
            .map(|j| j.transfer(from, to, amount))
            .ok_or_else(|| {
                vm::Unavailable("OCTB transfer requires an authenticated value journal".into())
            })
    }
}

fn nested_parameters(params: &[Value]) -> Result<Document, Error> {
    use octra_node_protocol::transaction::json_string;
    let mut out = vec![b'['];
    for (index, value) in params.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        match value {
            Value::Int(v) | Value::U64(v) | Value::U128(v) | Value::U256(v) => {
                out.extend_from_slice(v.to_string().as_bytes());
            }
            Value::Bool(true) => out.extend_from_slice(b"true"),
            Value::Bool(false) => out.extend_from_slice(b"false"),
            Value::Capability(_) | Value::Cipher(_) | Value::PublicKey(_) => {
                out.extend_from_slice(b"null");
            }
            value => json_string(&mut out, &value.text()),
        }
    }
    out.push(b']');
    Document::parse(&out).map_err(|e| unavailable(e.to_string()))
}

pub(super) fn execute(
    runtime: &CircleRuntime,
    state: &Snapshot,
    circle: &[u8],
    method: &[u8],
    params: &Document,
    ctx: &Context,
    info: &circle_store::Info,
    decoded: &[u8],
    value: &BigInt,
    mode: ReceiptMode<'_>,
    mut budget: Option<&mut ReceiptBudget>,
    mut journal: Option<&mut Journal<'_>>,
) -> Result<Call, Error> {
    let fail = |error, effort| Call::failed(runtime, state, circle, ctx, error, effort);
    let admitted = match runtime.admit_program(decoded, ctx.storage_proof) {
        Ok(code) => code,
        Err(error) if error.is_operational() => return Err(unavailable(error.to_string())),
        Err(error) => {
            return Ok(fail(
                format!("invalid circle bytecode: {error}").into_bytes(),
                0,
            ))
        }
    };
    // The native OCTB limit is not subject to the WASM twenty-million cap.
    let limit = ctx.limit;
    let priced = ctx.profile.proof_exec;
    let (before, spent) = match load_call_storage(state, circle, priced, limit, &mut journal)? {
        StorageLoad::Ready(storage, spent) => (storage, spent),
        StorageLoad::Failed(reason, effort) => return Ok(fail(reason, effort)),
    };
    let fixed = vm::fix_jumps(admitted.code());
    let Some(entry) = dispatcher(&fixed, method) else {
        return Ok(fail(b"method not found".to_vec(), 0));
    };
    let calls =
        priced && state.get(&[b"circles", circle, b"call_code"]) == Some(info.code_hash.as_slice());
    let values = match circle_octb::runtime_parameters(&admitted, &fixed, method, params) {
        Ok(values) => values,
        Err(Error::Rejected(reason)) => return Ok(fail(reason, 0)),
        Err(e) => return Err(e),
    };
    let mut machine = vm::Machine::new(
        vm::Context {
            caller: ctx.caller.as_bytes().to_vec(),
            origin: ctx.caller.as_bytes().to_vec(),
            address: circle.to_vec(),
            value: value.clone(),
            epoch: ctx.epoch,
            epoch_time_ms: ctx.epoch_time_ms,
            tree_hash: ctx.tree_hash.clone(),
            node_id: ctx.node_id.clone(),
            tx_hash: ctx.tx_hash.as_bytes().to_vec(),
            depth: ctx.depth,
        },
        vm::Options {
            limit: limit - spent,
            integer_work: ctx.storage_proof,
            fhe_work: ctx.fhe_work,
            object_cost: ctx.object_cost,
            proof_exec: ctx.profile.proof_exec,
            math: ctx.profile.math,
            point_ops: ctx.storage_proof,
            async_exec: true,
            strict: admitted.facts().is_some(),
            storage_kinds: circle_octb::storage_kinds(&admitted, calls),
            fhe_memory: journal.as_deref().and_then(|j| j.fhe_memory.clone()),
            ..vm::Options::default()
        },
        before.clone(),
    );
    machine.pc = entry;
    circle_octb::seed_values(&mut machine, method, values);
    // Parameter slots do not enlarge native memory.size.
    let mut fhe_policy = crate::circle_fhe::Policy::scoped(
        state,
        circle,
        &info.owner,
        ctx.caller.as_bytes(),
        ctx.epoch,
        ctx.hfhe_scope.as_ref(),
    )
    .map_err(|error| unavailable(error.to_string()))?;
    if !priced && !matches!(mode, ReceiptMode::Direct) {
        fhe_policy = fhe_policy.without_verifiers();
    }
    let mut host = Host {
        journal: journal.as_deref_mut(),
        calls,
        context: ctx,
        before: &before,
        circle,
        spawns: vec![],
        runtime,
        snapshot: state,
        fhe_policy,
    };
    let success = machine
        .run(&fixed, &mut host, budget.as_mut().map(|b| &mut b.work))
        .map_err(|e| unavailable(e.0))?;
    let spawns = host.spawns;
    let work = if priced {
        BigInt::from(spent)
            + if success {
                circle_store::storage_effort(&machine.storage)
                    + circle_store::write_effort(&machine.storage)
            } else {
                BigInt::from(0)
            }
    } else {
        BigInt::from(0)
    };
    let receipt = match charge(
        machine.effort,
        &work,
        if priced { limit } else { (1i64 << 62) - 1 },
    ) {
        Some(effort) => VmReceipt {
            success,
            response: success.then(|| machine.regs[0].clone()),
            effort,
            events: machine
                .events
                .into_iter()
                .map(|e| Event {
                    contract: e.contract,
                    depth: e.depth,
                    topic: e.name,
                    values: e.values.iter().map(|v| v.text().into_owned()).collect(),
                })
                .collect(),
            error: (!success).then(|| b"execution reverted".to_vec()),
        },
        None => fail(b"circle storage effort exceeds limit".to_vec(), limit).receipt,
    };
    if priced {
        if let Some(journal) = journal.as_deref_mut() {
            journal.stage(circle, machine.storage.clone());
        }
    }
    Ok(Call {
        runtime: runtime.clone(),
        context: ctx.clone(),
        receipt,
        effects: Some(Effects {
            storage: machine.storage,
            spawns,
            assets: vec![],
            encrypted_assets: vec![],
        }),
        before,
        snapshot: journal
            .as_ref()
            .map_or_else(|| state.clone(), |j| j.snapshot()),
        circle: circle.to_vec(),
        proof_active: ctx.storage_proof,
        binding: Some(binding(info, ctx, b"[]", vec![])),
    })
}
