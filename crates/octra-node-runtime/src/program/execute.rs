// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native constructor and dispatcher execution over admitted artifacts.
//! The environment owns cross-call/value effects and the outer savepoint.
use super::{input, journal, store, Artifact, Error, Journal, Result};
use crate::{circle_octb, octb as vm, state_batch::Snapshot};
use base64::{engine::general_purpose::STANDARD, Engine};
use num_traits::{ToPrimitive, Zero};
use octra_node_protocol::{
    circle_storage::StorageTable,
    contract,
    native_json::{Document, Value as Json},
    octb::{work::Budget, Instruction},
    program_trust::Keys,
};
use sha2::{Digest, Sha256};

pub trait Environment: vm::Host {
    fn state(&self) -> Snapshot;
    fn programs(&self) -> &Journal;
    fn programs_mut(&mut self) -> &mut Journal;
    fn trusted_program_keys(&self) -> &Keys;
}
#[derive(Clone, Debug)]
pub struct Receipt {
    pub success: bool,
    pub return_value: Option<vm::Value>,
    pub effort: i64,
    pub events: Vec<vm::Event>,
    pub error: Option<Vec<u8>>,
    pub storage_writes: usize,
}
impl Receipt {
    pub fn failed(reason: impl AsRef<[u8]>) -> Self {
        Self {
            success: false,
            return_value: None,
            effort: 0,
            events: vec![],
            error: Some(reason.as_ref().to_vec()),
            storage_writes: 0,
        }
    }
    pub fn value(&self) -> std::result::Result<vm::Value, Vec<u8>> {
        if self.success {
            Ok(self.return_value.clone().unwrap_or(vm::Value::Bool(true)))
        } else {
            let reason = self.error.as_deref().unwrap_or(b"execution failed");
            Err(reason[..reason.len().min(256)].to_vec())
        }
    }
}
pub struct Deployed {
    pub address: Vec<u8>,
    pub receipt: Receipt,
}
fn bound_options(mut options: vm::Options, artifact: &Artifact) -> vm::Options {
    options.strict = artifact.admitted().facts().is_some();
    options.storage_kinds = input::storage_kinds(artifact.admitted());
    options
}
fn seed(machine: &mut vm::Machine, constructor: bool, method: &[u8], params: Vec<vm::Value>) {
    machine.memory.insert(
        999,
        vm::Value::string(if constructor {
            b"constructor".to_vec()
        } else {
            b"call".to_vec()
        }),
    );
    machine
        .memory
        .insert(1000, vm::Value::string(method.to_vec()));
    for (index, value) in params.into_iter().enumerate() {
        machine.memory.insert(1001 + index as i64, value);
    }
}
fn run(
    env: &mut impl Environment,
    machine: &mut vm::Machine,
    code: &[Instruction],
    constructor: bool,
    budget: Option<&mut Budget>,
) -> Result<Receipt> {
    let success = machine.run(code, env, budget).map_err(Error::unavailable)? && !machine.reverted;
    Ok(Receipt {
        success,
        return_value: (!constructor && success).then(|| machine.regs[0].clone()),
        effort: machine.effort,
        events: machine.events.clone(),
        error: (!success).then(|| {
            if constructor {
                b"constructor failed".to_vec()
            } else {
                b"execution reverted".to_vec()
            }
        }),
        storage_writes: machine.storage_writes(),
    })
}
fn stage_deploy(
    env: &mut impl Environment,
    artifact: &Artifact,
    context: &vm::Context,
    ctype: &[u8],
    storage: StorageTable,
) {
    env.programs_mut().add_deploy(journal::Deploy {
        meta: store::Meta {
            address: context.address.clone(),
            code_hash: hex::encode(Sha256::digest(artifact.raw())).into_bytes(),
            version: artifact.version().to_vec(),
            owner: context.caller.clone(),
            ctype: ctype.to_vec(),
            admission: artifact.admission().to_vec(),
        },
        bytecode: STANDARD.encode(artifact.raw()).into_bytes(),
        storage,
    });
}
pub fn deploy(
    env: &mut impl Environment,
    artifact: &Artifact,
    mut context: vm::Context,
    mut options: vm::Options,
    ctype: &[u8],
    nonce: i64,
    params: &Document,
    budget: Option<&mut Budget>,
) -> Result<Deployed> {
    let address = contract::address(artifact.raw(), &context.caller, nonce);
    if let Err(error) = artifact.admitted().check_standard(options.point_ops) {
        return if error.is_operational() {
            Err(error.into())
        } else {
            Ok(Deployed {
                address,
                receipt: Receipt::failed(error.to_string()),
            })
        };
    }
    if store::exists(&env.state(), &address) || env.programs().find_deploy(&address).is_some() {
        return Ok(Deployed {
            address,
            receipt: Receipt {
                success: true,
                error: None,
                ..Receipt::failed(b"")
            },
        });
    }
    let values = match input::parse(artifact.admitted(), 0, params) {
        Ok(values) => values,
        Err(Error::Rejected(reason)) => {
            return Ok(Deployed {
                address,
                receipt: Receipt::failed(reason),
            })
        }
        Err(error) => return Err(error),
    };
    context.address.clone_from(&address);
    context.origin = context.caller.clone();
    context.value = num_bigint::BigInt::zero();
    context.depth = 0;
    options.limit = 1_000_000;
    options.is_view = false;
    let mut machine = vm::Machine::new(
        context.clone(),
        bound_options(options, artifact),
        StorageTable::new(100),
    );
    seed(&mut machine, true, b"constructor", values);
    let receipt = run(
        env,
        &mut machine,
        &vm::fix_jumps(artifact.admitted().code()),
        true,
        budget,
    )?;
    if receipt.success {
        stage_deploy(env, artifact, &context, ctype, machine.storage);
    }
    Ok(Deployed { address, receipt })
}
pub fn spawn(
    env: &mut impl Environment,
    artifact: &Artifact,
    mut context: vm::Context,
    mut options: vm::Options,
    nonce: i64,
    params: &[vm::Value],
    budget: Option<&mut Budget>,
) -> Result<Deployed> {
    if artifact.admission() != b"binary" {
        return Err(Error::unavailable("native spawn requires binary admission"));
    }
    artifact.admitted().check_standard(options.point_ops)?;
    let address = contract::address(artifact.raw(), &context.caller, nonce);
    if store::exists(&env.state(), &address) || env.programs().find_deploy(&address).is_some() {
        return Err(Error::rejected(
            [b"collision: ".as_slice(), &address].concat(),
        ));
    }
    input::validate(artifact.admitted(), 0, params)?;
    context.address.clone_from(&address);
    context.origin = context.caller.clone();
    context.value = num_bigint::BigInt::zero();
    if !options.fhe_work && budget.is_none() {
        context.depth = 0;
    }
    options.is_view = false;
    let mut machine = vm::Machine::new(
        context.clone(),
        bound_options(options, artifact),
        StorageTable::new(100),
    );
    seed(&mut machine, true, b"constructor", params.to_vec());
    let receipt = run(
        env,
        &mut machine,
        &vm::fix_jumps(artifact.admitted().code()),
        true,
        budget,
    )?;
    if !receipt.success {
        return Err(Error::rejected("constructor failed"));
    }
    stage_deploy(env, artifact, &context, b"CUSTOM", machine.storage);
    Ok(Deployed { address, receipt })
}
pub struct Invocation<'a> {
    pub context: vm::Context,
    pub options: vm::Options,
    pub method: &'a [u8],
    pub params: &'a Document,
}
// Preserve the ordered native tuple/borrowed-field projection API.
#[allow(clippy::type_complexity)]
fn prepare(
    artifact: &Artifact,
    method: &[u8],
    params: &Document,
) -> Result<std::result::Result<(Vec<Instruction>, Vec<vm::Value>), Receipt>> {
    let fixed = vm::fix_jumps(artifact.admitted().code());
    let count = match params.root() {
        Json::List(values) => values.len(),
        _ => 0,
    };
    if let Some(arity) = circle_octb::arity(&fixed, method) {
        if arity != count {
            return Ok(Err(Receipt::failed(
                [
                    b"arity mismatch: ".as_slice(),
                    method,
                    format!(" expects {arity} args, got {count}").as_bytes(),
                ]
                .concat(),
            )));
        }
    }
    let Some(target) = circle_octb::method_target(&fixed, method) else {
        return Ok(Err(Receipt::failed("method not found")));
    };
    match input::parse(artifact.admitted(), target, params) {
        Ok(values) => Ok(Ok((fixed, values))),
        Err(Error::Rejected(reason)) => Ok(Err(Receipt::failed(reason))),
        Err(error) => Err(error),
    }
}
pub fn call(
    env: &mut impl Environment,
    invocation: Invocation<'_>,
    budget: Option<&mut Budget>,
) -> Result<Receipt> {
    let Invocation {
        mut context,
        mut options,
        method,
        params,
    } = invocation;
    let spent = if options.proof_exec {
        match env
            .programs()
            .snapshot_effort()
            .to_i64()
            .filter(|cost| *cost >= 0 && *cost <= options.limit)
        {
            Some(cost) => cost,
            None => {
                return Ok(Receipt {
                    effort: options.limit,
                    ..Receipt::failed("call journal effort exceeds limit")
                })
            }
        }
    } else {
        0
    };
    options.limit -= spent;
    let state = env.state();
    let Some(artifact) = Artifact::load(
        &state,
        env.programs(),
        &context.address,
        options.point_ops,
        env.trusted_program_keys(),
    )?
    else {
        return Ok(Receipt::failed("bytecode not found"));
    };
    let (fixed, values) = match prepare(&artifact, method, params)? {
        Ok(value) => value,
        Err(receipt) => return Ok(receipt),
    };
    let saved = (options.proof_exec || options.async_exec).then(|| env.programs().snapshot());
    let storage = env
        .programs_mut()
        .checkout(&context.address, || {
            store::storage(&state, &context.address)
        })
        .clone();
    let address = context.address.clone();
    context.origin.clone_from(&context.caller);
    options.is_view = false;
    let restore_refusal = options.proof_exec;
    let mut machine = vm::Machine::new(context, bound_options(options, &artifact), storage);
    seed(&mut machine, false, method, values);
    if let Some(entry) = circle_octb::dispatcher(&fixed, method) {
        machine.pc = entry;
    }
    match run(env, &mut machine, &fixed, false, budget) {
        Ok(mut receipt) => {
            if !receipt.success && restore_refusal {
                if let Some(saved) = saved {
                    env.programs_mut().restore(saved);
                }
            } else {
                env.programs_mut().set_storage(&address, machine.storage);
            }
            receipt.effort += spent;
            Ok(receipt)
        }
        Err(error) => {
            if let Some(saved) = saved {
                env.programs_mut().restore(saved);
            }
            Err(error)
        }
    }
}
