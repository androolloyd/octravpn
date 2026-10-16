// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Legacy Programs participate in the same Circle/value invocation journal.
use super::{
    rejected, unavailable, BigInt, Context, Document, Error, Event, Journal, ReceiptBudget,
    Snapshot, StorageTable, ToPrimitive, VmValue, Zero,
};
use crate::{octb as vm, program as contracts};
use contracts::execute::{self, Environment, Invocation};
use octra_node_protocol::octb::work::Budget;

fn effect(error: contracts::Error) -> Error {
    match error {
        contracts::Error::Rejected(reason) => Error::Rejected(reason),
        contracts::Error::Unavailable(reason) => Error::Unavailable(reason.into_bytes()),
    }
}
fn vm_context(ctx: &Context, address: &[u8]) -> vm::Context {
    vm::Context {
        caller: ctx.caller.as_bytes().to_vec(),
        origin: ctx.caller.as_bytes().to_vec(),
        address: address.to_vec(),
        value: BigInt::zero(),
        epoch: ctx.epoch,
        epoch_time_ms: ctx.epoch_time_ms,
        tree_hash: ctx.tree_hash.clone(),
        node_id: ctx.node_id.clone(),
        tx_hash: ctx.tx_hash.as_bytes().to_vec(),
        depth: ctx.depth,
    }
}
fn options(
    ctx: &Context,
    memory: Option<octra_node_protocol::octb::fhe_work::Memory>,
) -> vm::Options {
    vm::Options {
        limit: ctx.limit,
        integer_work: ctx.storage_proof,
        fhe_work: ctx.fhe_work,
        object_cost: ctx.object_cost,
        proof_exec: ctx.profile.proof_exec,
        math: ctx.profile.math,
        point_ops: ctx.storage_proof,
        async_exec: true,
        fhe_memory: memory,
        ..vm::Options::default()
    }
}
fn events(values: Vec<vm::Event>) -> Vec<Event> {
    values
        .into_iter()
        .map(|event| Event {
            contract: event.contract,
            depth: event.depth,
            topic: event.name,
            values: event
                .values
                .iter()
                .map(|value| value.text().into_owned())
                .collect(),
        })
        .collect()
}
fn vm_events(values: Vec<Event>) -> Vec<vm::Event> {
    values
        .into_iter()
        .map(|event| vm::Event {
            contract: event.contract,
            depth: event.depth,
            name: event.topic,
            values: event.values.into_iter().map(vm::Value::string).collect(),
        })
        .collect()
}
struct Host<'a, 'b> {
    journal: &'a mut Journal<'b>,
    context: Context,
}
impl Environment for Host<'_, '_> {
    fn state(&self) -> Snapshot {
        self.journal.snapshot()
    }
    fn programs(&self) -> &contracts::Journal {
        &self.journal.programs
    }
    fn programs_mut(&mut self) -> &mut contracts::Journal {
        &mut self.journal.programs
    }
    fn trusted_program_keys(&self) -> &octra_node_protocol::program_trust::Keys {
        self.journal.runtime.program_keys()
    }
}
impl vm::Host for Host<'_, '_> {
    fn fhe_key(&mut self, address: &[u8]) -> Result<Option<vm::FheKeySource>, vm::Unavailable> {
        self.journal
            .runtime
            .public_key(&self.journal.snapshot(), address)
            .map(|key| key.map(vm::FheKeySource::Bytes))
            .map_err(|error| vm::Unavailable(error.to_string()))
    }
    fn groth16(
        &mut self,
        key: &[u8],
        proof: &[u8],
        inputs: &[u8],
    ) -> Result<bool, vm::Unavailable> {
        Ok(crate::groth16::verify(key, proof, inputs))
    }
    fn cap_live(&mut self, _cap: &vm::Capability) -> Result<bool, vm::Unavailable> {
        Ok(false)
    }
    fn balance(&mut self, address: &[u8]) -> Result<BigInt, vm::Unavailable> {
        Ok(self.journal.balance(address))
    }
    fn transfer(
        &mut self,
        from: &[u8],
        to: &[u8],
        amount: &BigInt,
    ) -> Result<bool, vm::Unavailable> {
        Ok(self.journal.transfer(from, to, amount))
    }
    fn call(
        &mut self,
        request: vm::CallRequest<'_>,
        storage: &mut StorageTable,
        budget: Option<&mut Budget>,
    ) -> Result<Option<vm::Subcall>, vm::Unavailable> {
        // Native program storage is aliased with its journal. Publish the live
        // caller image to the overlay before a reentrant child, then reload it.
        let staged = self.journal.programs.storage(request.caller).is_some();
        if staged {
            self.journal
                .programs
                .set_storage(request.caller, storage.clone());
        }
        let result = (|| {
            let params = contracts::input::nested(request.params, self.context.profile.proof_exec)
                .map_err(effect)?;
            let memory =
                std::mem::replace(&mut self.journal.fhe_memory, request.fhe_memory.clone());
            let result = ReceiptBudget::with_work(budget, |budget| {
                self.journal.nested(
                    request.caller,
                    request.target,
                    request.method,
                    &params,
                    &self.context,
                    request.limit,
                    budget,
                )
            });
            self.journal.fhe_memory = memory;
            let (response, effort, events) = result?;
            if staged {
                *storage = self
                    .journal
                    .programs
                    .storage(request.caller)
                    .cloned()
                    .ok_or_else(|| unavailable("Program caller storage missing after subcall"))?;
            }
            Ok(vm::Subcall {
                response,
                effort,
                events: vm_events(events),
            })
        })();
        host_result(result)
    }
    fn spawn(
        &mut self,
        request: vm::SpawnRequest<'_>,
        storage: &mut StorageTable,
        budget: Option<&mut Budget>,
    ) -> Result<Option<vm::Spawned>, vm::Unavailable> {
        let parent = request.parent;
        let staged = self.journal.programs.storage(parent).is_some();
        if staged {
            self.journal.programs.set_storage(parent, storage.clone());
        }
        let memory = std::mem::replace(&mut self.journal.fhe_memory, request.fhe_memory.clone());
        let result = self.journal.program_spawn(&self.context, request, budget);
        self.journal.fhe_memory = memory;
        let result = result.and_then(|result| {
            if staged {
                *storage = self
                    .journal
                    .programs
                    .storage(parent)
                    .cloned()
                    .ok_or_else(|| unavailable("Program caller storage missing after spawn"))?;
            }
            Ok(result)
        });
        host_result(result)
    }
}
fn host_result<T>(result: Result<T, Error>) -> Result<Option<T>, vm::Unavailable> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(Error::Rejected(_)) => Ok(None),
        Err(Error::Unavailable(reason)) => Err(vm::Unavailable(
            String::from_utf8_lossy(&reason).into_owned(),
        )),
    }
}
impl Journal<'_> {
    pub(crate) fn run_program(
        &mut self,
        target: &[u8],
        method: &[u8],
        params: &Document,
        amount: &BigInt,
        ctx: &Context,
        budget: Option<&mut ReceiptBudget>,
    ) -> Result<execute::Receipt, Error> {
        let mut context = vm_context(ctx, target);
        context.value.clone_from(amount);
        let invocation = Invocation {
            context,
            options: options(ctx, self.fhe_memory.clone()),
            method,
            params,
        };
        let mut host = Host {
            journal: self,
            context: ctx.clone(),
        };
        execute::call(&mut host, invocation, budget.map(|budget| &mut budget.work)).map_err(effect)
    }
    pub(crate) fn deploy_program(
        &mut self,
        artifact: &contracts::Artifact,
        ctx: &Context,
        nonce: i64,
        params: &Document,
        budget: Option<&mut ReceiptBudget>,
    ) -> Result<execute::Deployed, Error> {
        let context = vm_context(ctx, b"");
        let options = options(ctx, self.fhe_memory.clone());
        let mut host = Host {
            journal: self,
            context: ctx.clone(),
        };
        execute::deploy(
            &mut host,
            artifact,
            context,
            options,
            b"CUSTOM",
            nonce,
            params,
            budget.map(|budget| &mut budget.work),
        )
        .map_err(effect)
    }
    pub(super) fn program_call(
        &mut self,
        caller: &[u8],
        target: &[u8],
        method: &[u8],
        params: &Document,
        ctx: &Context,
        fuel: i64,
        budget: Option<&mut ReceiptBudget>,
    ) -> Result<(VmValue, i64, Vec<Event>), Error> {
        let ctx = Context {
            caller: std::str::from_utf8(caller).map_err(unavailable)?.into(),
            depth: ctx.depth + 1,
            node_id: if ctx.profile.proof_exec {
                target.to_vec()
            } else {
                ctx.node_id.clone()
            },
            limit: fuel,
            ..ctx.clone()
        };
        let receipt = self.run_program(target, method, params, &BigInt::zero(), &ctx, budget)?;
        let response = receipt.value().map_err(rejected)?;
        Ok((response, receipt.effort, events(receipt.events)))
    }
    // Preserve the native owned-input and typed diagnostic interface.
    #[allow(clippy::needless_pass_by_value)]
    fn program_spawn(
        &mut self,
        ctx: &Context,
        request: vm::SpawnRequest<'_>,
        budget: Option<&mut Budget>,
    ) -> Result<vm::Spawned, Error> {
        let work = if ctx.profile.proof_exec {
            self.program_effort() + BigInt::from(self.values.deltas.len()) * 32
        } else {
            BigInt::zero()
        };
        let spent = work
            .to_i64()
            .filter(|cost| *cost >= 0 && *cost <= request.limit)
            .ok_or_else(|| rejected("call journal effort exceeds limit"))?;
        let values = self.values.clone();
        let programs = self.programs.snapshot();
        let saved = self.state.save().map_err(unavailable)?;
        let result = (|| {
            let artifact = contracts::Artifact::binary(
                request.code,
                ctx.storage_proof,
                self.runtime.program_keys(),
            )
            .map_err(effect)?;
            let ctx = Context {
                caller: std::str::from_utf8(request.parent)
                    .map_err(unavailable)?
                    .into(),
                depth: ctx.depth + 1,
                limit: request.limit - spent,
                ..ctx.clone()
            };
            let context = vm_context(&ctx, request.parent);
            let options = options(&ctx, self.fhe_memory.clone());
            let mut host = Host {
                journal: self,
                context: ctx,
            };
            let deployed = execute::spawn(
                &mut host,
                &artifact,
                context,
                options,
                request.nonce,
                request.params,
                budget,
            )
            .map_err(effect)?;
            let effort = spent
                .checked_add(deployed.receipt.effort)
                .filter(|effort| !host.context.profile.proof_exec || *effort <= request.limit)
                .ok_or_else(|| rejected("spawn effort exceeds limit"))?;
            Ok(vm::Spawned {
                address: deployed.address,
                effort,
                events: deployed.receipt.events,
            })
        })();
        if result.is_err() {
            self.values = values;
            self.programs.restore(programs);
            self.state.restore(saved).map_err(unavailable)?;
        }
        result
    }
}
