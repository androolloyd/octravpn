// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Snapshot-bound Circle updates. The transaction driver supplies the
//! authenticated context; no HTTP/app parameters can construct a commit directly.
use crate::{
    circle::{CircleRuntime, WasmProfile, WasmRules, MAX_INPUT_BYTES},
    circle_reads,
    circle_receipt::{self, ReceiptBudget},
    circle_store,
    octb::Value,
    state_batch::{Snapshot, StateBatch},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use octra_node_protocol::{
    circle_storage::{self, StorageTable},
    circle_wasm::{self, codec, public_read, transcript, Error, Execution},
    native_json::Document,
    transaction::decode_base64,
};
use serde_json::json;
use sha2::{Digest, Sha256};
mod octb;

/// Supplied by admitted transaction execution, after epoch rule selection.
#[derive(Clone, Debug)]
pub struct Context {
    pub caller: String,
    pub tx_hash: String,
    pub epoch: i64,
    pub epoch_time_ms: i64,
    /// Authenticated parent state root, before any transaction in this epoch.
    pub tree_hash: Vec<u8>,
    pub node_id: Vec<u8>,
    pub depth: i64,
    pub limit: i64,
    pub profile: WasmRules,
    pub manifest: WasmProfile,
    pub inspect: bool,
    pub update_policy: bool,
    pub hfhe_strict: bool,
    pub storage_proof: bool,
    pub fhe_work: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub contract: Vec<u8>,
    pub depth: i64,
    pub topic: Vec<u8>,
    pub values: Vec<Vec<u8>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmReceipt {
    pub success: bool,
    pub response: Option<Value>,
    pub effort: i64,
    pub events: Vec<Event>,
    pub error: Option<Vec<u8>>,
}
pub struct Call {
    runtime: CircleRuntime,
    context: Context,
    receipt: VmReceipt,
    effects: Option<crate::circle_effects::Effects>,
    before: StorageTable,
    snapshot: Snapshot,
    circle: Vec<u8>,
    proof_active: bool,
    binding: Option<Binding>,
}
/// Native execution binding. Snapshot identity is attached by the transaction
/// preverification host, after it has authenticated the parent ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub circle_id: Vec<u8>,
    pub code_hash: Vec<u8>,
    pub stable_root: Vec<u8>,
    pub public_reads_hash: Vec<u8>,
    pub context_hash: Vec<u8>,
    pub transcript: Vec<transcript::Entry>,
}
impl Binding {
    pub fn at_snapshot(&self, root: &[u8]) -> octra_node_protocol::preverify_receipt::Circle {
        octra_node_protocol::preverify_receipt::Circle {
            snapshot_hash: octra_node_protocol::preverify_receipt::state_hash(root),
            circle_id: self.circle_id.clone(),
            code_hash: self.code_hash.clone(),
            stable_root: self.stable_root.clone(),
            public_reads_hash: self.public_reads_hash.clone(),
            context_hash: self.context_hash.clone(),
            transcript: self.transcript.clone(),
        }
    }
}
#[derive(Clone, Copy)]
pub enum ReceiptMode<'a> {
    Direct,
    Capture,
    Consume(&'a [transcript::Entry]),
}
fn unavailable(s: impl AsRef<[u8]>) -> Error {
    Error::Unavailable(s.as_ref().to_vec())
}
fn rejected(s: impl AsRef<[u8]>) -> Error {
    Error::Rejected(s.as_ref().to_vec())
}
fn engine_error(e: crate::circle::Error) -> Error {
    match e {
        crate::circle::Error::Rejected(s) => rejected(s),
        crate::circle::Error::Unavailable(s) => unavailable(s),
    }
}
fn text(raw: &[u8]) -> Result<&str, Error> {
    std::str::from_utf8(raw).map_err(|_| unavailable("non-UTF-8 Circle engine field"))
}
fn charge(used: i64, cost: &BigInt, limit: i64) -> Option<i64> {
    let cost = cost.to_i64()?;
    if used < 0 || used > limit || cost < 0 || cost > limit - used {
        None
    } else {
        Some(used + cost)
    }
}
impl Call {
    fn failed(
        runtime: &CircleRuntime,
        state: &Snapshot,
        circle: &[u8],
        ctx: &Context,
        error: Vec<u8>,
        effort: i64,
    ) -> Self {
        Self {
            runtime: runtime.clone(),
            context: ctx.clone(),
            receipt: VmReceipt {
                success: false,
                response: None,
                effort,
                events: vec![],
                error: Some(error),
            },
            effects: None,
            before: StorageTable::new(0),
            snapshot: state.clone(),
            circle: circle.to_vec(),
            proof_active: ctx.storage_proof,
            binding: None,
        }
    }
    pub fn binding(&self) -> Option<&Binding> {
        self.binding.as_ref()
    }
    pub fn receipt(&self) -> &VmReceipt {
        &self.receipt
    }
    pub fn storage(&self) -> Option<&StorageTable> {
        self.effects.as_ref().map(|e| &e.storage)
    }

    /// Authorize and stage stable writes. Unsupported effect hosts cause local
    /// unavailability, never a successful receipt with silently discarded effects.
    /// The caller still owns fee processing and the canonical epoch commit.
    pub fn apply(&self, state: &mut StateBatch) -> Result<Vec<u8>, Error> {
        if !state.is_active() {
            return Err(unavailable("Circle effects require an active state batch"));
        }
        if state
            .root()
            .map_err(|_| unavailable("state root unavailable"))?
            != self
                .snapshot
                .root()
                .map_err(|_| unavailable("state root unavailable"))?
        {
            return Err(unavailable("Circle call snapshot changed before apply"));
        }
        let info = circle_store::info(&self.snapshot, &self.circle)
            .map_err(|e| unavailable(e.0))?
            .ok_or_else(|| rejected("circle not found"))?;
        if !self.receipt.success {
            return Err(rejected("circle call failed"));
        }
        let effects = self
            .effects
            .as_ref()
            .ok_or_else(|| unavailable("successful Circle call has no effects"))?;
        circle_storage::validate_delta(&self.before, &effects.storage, self.proof_active).map_err(
            |e| {
                rejected(
                    [
                        b"circle runtime attempted to write reserved stable key ".as_slice(),
                        &e.key,
                        b" under prefix ",
                        &e.detail,
                    ]
                    .concat(),
                )
            },
        )?;
        let prepared = crate::circle_effects::Prepared::check(
            &self.runtime,
            state,
            &info,
            &self.context,
            effects,
        )?;
        circle_store::validate_storage_limits(&effects.storage, info.limits[0], info.limits[2])
            .map_err(|e| rejected(e.0))?;
        let saved = state.save().map_err(|e| unavailable(e.to_string()))?;
        let result = (|| {
            let root = circle_store::save_storage(
                state,
                &self.circle,
                &effects.storage,
                info.limits[0],
                info.limits[2],
            )
            .map_err(|e| unavailable(e.0))?;
            prepared.apply(state, &self.circle, &self.context)?;
            Ok(root)
        })();
        if result.is_err() {
            state
                .restore(saved)
                .map_err(|e| unavailable(e.to_string()))?;
        }
        result
    }
}

pub fn execute(
    runtime: &CircleRuntime,
    state: &Snapshot,
    circle: &[u8],
    method: &[u8],
    params: &Document,
    ctx: &Context,
    budget: Option<&mut ReceiptBudget>,
) -> Result<Call, Error> {
    execute_with_receipt(
        runtime,
        state,
        circle,
        method,
        params,
        ctx,
        ReceiptMode::Direct,
        budget,
    )
}

#[allow(clippy::too_many_arguments)] // Native call context plus transcript mode.
pub fn execute_with_receipt(
    runtime: &CircleRuntime,
    state: &Snapshot,
    circle: &[u8],
    method: &[u8],
    params: &Document,
    ctx: &Context,
    mode: ReceiptMode<'_>,
    budget: Option<&mut ReceiptBudget>,
) -> Result<Call, Error> {
    execute_journalled(
        runtime,
        state,
        circle,
        method,
        params,
        ctx,
        mode,
        budget,
        &BigInt::from(0),
        None,
    )
}

pub(crate) fn execute_journalled(
    runtime: &CircleRuntime,
    state: &Snapshot,
    circle: &[u8],
    method: &[u8],
    params: &Document,
    ctx: &Context,
    mode: ReceiptMode<'_>,
    mut budget: Option<&mut ReceiptBudget>,
    value: &BigInt,
    mut journal: Option<&mut crate::circle_journal::Journal<'_>>,
) -> Result<Call, Error> {
    let priced = ctx.profile.proof_exec;
    let limit = if priced {
        ctx.limit.clamp(0, 20_000_000)
    } else {
        ctx.limit
    };
    let fail = |error, effort| Call::failed(runtime, state, circle, ctx, error, effort);
    let Some(info) = circle_store::info(state, circle).map_err(|e| unavailable(e.0))? else {
        return Ok(fail(b"circle not found".to_vec(), 0));
    };
    let Some(code) = state.get(&[b"circles", circle, b"program", b"code_b64"]) else {
        return Ok(fail(b"circle program not found".to_vec(), 0));
    };
    if code.len() > MAX_INPUT_BYTES {
        return Err(unavailable("Circle program exceeds native input capacity"));
    }
    let decoded = match decode_base64(code) {
        Ok(v) => v,
        Err(e) => {
            return Ok(fail(
                format!("invalid circle code: Invalid_argument(\"{e}\")").into_bytes(),
                0,
            ))
        }
    };
    if hex::encode(Sha256::digest(&decoded)).as_bytes() != info.code_hash {
        return Ok(fail(b"circle code hash mismatch".to_vec(), 0));
    }
    if info.runtime == b"octb" {
        return octb::execute(
            runtime, state, circle, method, params, ctx, &info, &decoded, value, budget, journal,
        );
    }
    let code = text(code)?;
    let description = json!({"action":"describe","is_view":true,"code_b64":code,"execution_profile":ctx.manifest.name(),"float_mode":ctx.profile.wasm_float,"inspect_policy":ctx.inspect});
    let descriptor = match runtime
        .execute(&serde_json::to_vec(&description).map_err(|e| unavailable(e.to_string()))?)
    {
        Ok(v) => v,
        Err(e) => match engine_error(e) {
            Error::Rejected(e) => return Ok(fail(e, 0)),
            e @ Error::Unavailable(_) => return Err(e),
        },
    };
    let methods = match circle_wasm::methods(descriptor.as_ref()) {
        Ok(v) => v,
        Err(Error::Rejected(e)) => {
            return Ok(fail(
                [b"invalid circle wasm manifest: ".as_slice(), &e].concat(),
                0,
            ))
        }
        Err(e) => return Err(e),
    };
    let declarations = match public_read::declarations(descriptor.as_ref()) {
        Ok(v) => v,
        Err(Error::Rejected(e)) => {
            return Ok(fail(
                [b"invalid circle wasm manifest: ".as_slice(), &e].concat(),
                0,
            ))
        }
        Err(e) => return Err(e),
    };
    if circle_wasm::method_execution(&methods, method) == Execution::Compute {
        return Ok(fail(
            b"circle compute method cannot execute as update".to_vec(),
            0,
        ));
    }
    let (before, mut spent) = match load_call_storage(state, circle, priced, limit, &mut journal)? {
        StorageLoad::Ready(storage, spent) => (storage, spent),
        StorageLoad::Failed(reason, effort) => return Ok(fail(reason, effort)),
    };
    if method.starts_with(b"fhe_") {
        return Err(unavailable(
            "authenticated Circle HFHE context is not available",
        ));
    }
    let calls =
        priced && state.get(&[b"circles", circle, b"call_code"]) == Some(info.code_hash.as_slice());
    let request =
        match codec::request_params(params).and_then(|p| codec::encode_request(method, &p)) {
            Ok(v) => v,
            Err(Error::Rejected(e)) => return Ok(fail(e, 0)),
            Err(e) => return Err(e),
        };
    let declarations = declarations
        .into_iter()
        .filter(|d| d.method == method)
        .collect::<Vec<_>>();
    let mut read_spent = 0;
    let reads = match circle_reads::load(
        state,
        ctx.epoch,
        &declarations,
        priced.then_some(limit - spent),
        &mut read_spent,
    ) {
        Ok(v) => v,
        Err(e) => return Ok(fail(e.0, if priced { spent + read_spent } else { 0 })),
    };
    spent = limit.min(spent + reads.effort);
    let fuel = limit - spent;
    if fuel <= 0 {
        return Ok(fail(
            b"wasm public read effort exceeds limit".to_vec(),
            if priced { spent } else { 0 },
        ));
    }
    let storage_pairs = before
        .values()
        .iter()
        .map(|(k, v)| json!({"key_b64":STANDARD.encode(k),"value_b64":STANDARD.encode(v)}))
        .collect::<Vec<_>>();
    let mut input = json!({"action":"execute","code_b64":code,"code_cache_key":hex::encode(Sha256::digest(code.as_bytes())),"execution_profile":"standard","export_name":"octra_update","request_b64":STANDARD.encode(request),"storage_pairs":storage_pairs,"storage_cache_key":null,"caller":ctx.caller,"address":text(circle)?,"tx_hash":ctx.tx_hash,"current_epoch":ctx.epoch,"hfhe_caps":[],"hfhe_pubkeys":[],"hfhe_active_key":null,"hfhe_strict":ctx.hfhe_strict,"hfhe_receipt_mode":"direct","hfhe_receipt_entries":[],"math":ctx.profile.math,"float_mode":ctx.profile.wasm_float,"inspect_policy":ctx.inspect,"fuel_limit":fuel.clamp(0,20_000_000),"is_view":false,"update_policy":ctx.update_policy,"public_reads":circle_reads::engine_reads(&reads).map_err(|e|unavailable(e.0))?,"compute_storage_cache_key":null,"compute_session_scope":null});
    match mode {
        ReceiptMode::Direct => (),
        ReceiptMode::Capture => input["hfhe_receipt_mode"] = json!("capture"),
        ReceiptMode::Consume(entries) => {
            input["hfhe_receipt_mode"] = json!("consume");
            input["hfhe_receipt_entries"] =
                serde_json::from_slice(&transcript::entries_json(entries))
                    .map_err(|e| unavailable(e.to_string()))?;
        }
    }
    if priced {
        input["hfhe_pairs"] = json!(true);
    }
    if calls {
        input["update_policy"] = json!(true);
    }
    // Oversize requests need the native cache/session transport; do not turn a
    // locally missing transport into a consensus-level execution failure.
    if serde_json::to_vec(&input)
        .map_err(|e| unavailable(e.to_string()))?
        .len()
        > MAX_INPUT_BYTES - 4096
    {
        return Err(unavailable(
            "Circle input requires native session transport",
        ));
    }
    let input = serde_json::to_vec(&input).map_err(|e| unavailable(e.to_string()))?;
    let mut nested = Vec::new();
    let execution = if calls {
        runtime.execute_call_effects(&input, &before, |request| {
            let host = journal
                .as_deref_mut()
                .ok_or_else(|| unavailable("nested Circle execution host is not available"))?;
            let reply = host.dispatch(circle, ctx, value, request, budget.as_deref_mut())?;
            if let Some(events) = reply.events {
                nested.push(events);
            }
            Ok(reply.bytes)
        })
    } else {
        runtime.execute_effects(&input, &before)
    };
    let effects = match execution {
        Ok(v) => v,
        Err(Error::Rejected(e)) => return Ok(fail(e, if priced { limit } else { 0 })),
        Err(e) => return Err(e),
    };
    let response = match effects.response.as_ref() {
        None => None,
        Some(value) => match circle_receipt::vm_scalar(value) {
            Some(value) => Some(value),
            None => {
                return Ok(fail(
                    b"wasm response integer is invalid".to_vec(),
                    if priced {
                        limit.min(spent + effects.effort_used)
                    } else {
                        0
                    },
                ))
            }
        },
    };
    let mut event_effort = Some(spent + effects.effort_used);
    for event in &effects.events {
        if let Some(budget) = budget.as_deref_mut() {
            event_effort = event_effort.and_then(|used| {
                budget.event(circle, ctx.depth, &event.topic, &event.data, used, limit)
            });
        }
    }
    let output = match (event_effort, response.as_ref(), budget) {
        (Some(used), Some(response), Some(budget)) => budget.output(response, used, limit),
        _ => event_effort,
    };
    if priced && effects.success {
        if let Some(journal) = journal.as_deref_mut() {
            journal.stage(circle, effects.storage.clone());
        }
    }
    let work = if priced && effects.success {
        circle_store::storage_effort(&effects.storage)
            + circle_store::write_effort(&effects.storage)
    } else {
        BigInt::from(0)
    };
    let effort = output.and_then(|used| charge(used, &work, limit));
    let receipt = VmReceipt {
        success: effects.success && effort.is_some(),
        response: if output.is_some() {
            response.as_ref().and_then(Value::from_scalar)
        } else {
            None
        },
        effort: effort.unwrap_or(limit),
        events: if event_effort.is_some() {
            crate::circle_journal::merge_events(
                effects
                    .events
                    .iter()
                    .map(|e| Event {
                        contract: circle.to_vec(),
                        depth: ctx.depth,
                        topic: e.topic.clone(),
                        values: vec![e.data.clone()],
                    })
                    .collect(),
                nested,
            )
        } else {
            vec![]
        },
        error: if output.is_none() {
            Some(b"circle receipt effort exceeds limit".to_vec())
        } else if effort.is_none() {
            Some(b"circle storage effort exceeds limit".to_vec())
        } else if effects.success {
            None
        } else {
            Some(
                effects
                    .error
                    .clone()
                    .unwrap_or_else(|| b"execution reverted".to_vec()),
            )
        },
    };
    let mut reads_json = vec![b'['];
    for (index, read) in reads.reads.iter().enumerate() {
        if index > 0 {
            reads_json.push(b',');
        }
        reads_json.extend_from_slice(&read.native_json());
    }
    reads_json.push(b']');
    let binding = binding(&info, ctx, &reads_json, effects.transcript.clone());
    Ok(Call {
        runtime: runtime.clone(),
        context: ctx.clone(),
        receipt,
        effects: Some(effects.into()),
        before,
        snapshot: journal
            .as_ref()
            .map_or_else(|| state.clone(), |j| j.snapshot()),
        circle: circle.to_vec(),
        proof_active: ctx.storage_proof,
        binding: Some(binding),
    })
}
fn hash_json(domain: &[u8], json: &[u8]) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update([0]);
    hash.update(json);
    hex::encode(hash.finalize()).into_bytes()
}

fn binding(
    info: &circle_store::Info,
    ctx: &Context,
    reads_json: &[u8],
    transcript: Vec<transcript::Entry>,
) -> Binding {
    let mut context_json = b"{\"caps\":[],\"pubkeys\":[],\"active_key\":null".to_vec();
    if ctx.profile.math {
        context_json.extend_from_slice(b",\"math\":true");
    }
    if ctx.profile.wasm_float {
        context_json.extend_from_slice(b",\"wasm_float\":\"wasm_float:arith_nan_7fc00000_7ff8000000000000:operand_calls:metered_helpers:v1\"");
    }
    context_json.push(b'}');
    Binding {
        circle_id: info.circle_id.clone(),
        code_hash: info.code_hash.clone(),
        stable_root: info.stable_root.clone(),
        public_reads_hash: hash_json(b"octra:circle_public_reads:v1", reads_json),
        context_hash: hash_json(
            if ctx.hfhe_strict {
                b"octra:circle_hfhe_context:standard:v1"
            } else {
                b"octra:circle_hfhe_context:v1"
            },
            &context_json,
        ),
        transcript,
    }
}

enum StorageLoad {
    Ready(StorageTable, i64),
    Failed(Vec<u8>, i64),
}
fn load_call_storage(
    state: &Snapshot,
    circle: &[u8],
    priced: bool,
    limit: i64,
    journal: &mut Option<&mut crate::circle_journal::Journal<'_>>,
) -> Result<StorageLoad, Error> {
    let mut spent = 0;
    let mut read_charge = |cost: usize| {
        let Some(cost) = i64::try_from(cost).ok() else {
            return false;
        };
        if cost > limit - spent {
            false
        } else {
            spent += cost;
            true
        }
    };
    let read_charge: &mut dyn FnMut(usize) -> bool = &mut read_charge;
    let staged = priced
        .then(|| journal.as_ref().and_then(|j| j.storage(circle)))
        .flatten();
    let storage = staged.map_or_else(
        || circle_store::load_storage(state, circle, priced.then_some(read_charge)),
        Ok,
    );
    let before = match storage {
        Ok(v) => v,
        Err(e)
            if e.0 == b"circle stable entry JSON refused"
                || e.0 == b"circle stable entry integer refused" =>
        {
            return Err(unavailable(e.0))
        }
        Err(e) => return Ok(StorageLoad::Failed(e.0, if priced { limit } else { 0 })),
    };
    if priced {
        if let Some(journal) = journal.as_deref_mut() {
            journal.stage(circle, before.clone());
        }
    }
    let work = if priced {
        circle_store::storage_effort(&before) * 2
    } else {
        BigInt::from(0)
    };
    let Some(next) = charge(spent, &work, if priced { limit } else { (1i64 << 62) - 1 }) else {
        return Ok(StorageLoad::Failed(
            b"circle storage effort exceeds limit".to_vec(),
            limit,
        ));
    };
    Ok(StorageLoad::Ready(before, next))
}
