// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Shared value/storage effects for a native Circle invocation tree.
use crate::{
    circle::{CircleRuntime, WasmProfile},
    circle_call::{self, Call, Context, Event, ReceiptMode},
    circle_receipt::ReceiptBudget,
    circle_store,
    octb::Value as VmValue,
    state_batch::{Snapshot, StateBatch},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive, Zero};
use octra_node_protocol::{
    circle_storage::{self, StorageTable},
    circle_wasm::{codec::Scalar, receipt, Error},
    native_integer::parse_integer,
    native_json::Document,
    state::Ledger,
    transaction::{is_valid_address, json_string},
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

fn unavailable(e: impl std::fmt::Display) -> Error {
    Error::Unavailable(e.to_string().into_bytes())
}
fn rejected(e: impl AsRef<[u8]>) -> Error {
    Error::Rejected(e.as_ref().to_vec())
}

#[derive(Clone, Default)]
pub(crate) struct Values {
    deltas: BTreeMap<Vec<u8>, BigInt>,
    transfers: Vec<(Vec<u8>, Vec<u8>, BigInt)>,
}
impl Values {
    fn balance(&self, ledger: &Ledger, address: &[u8]) -> BigInt {
        ledger
            .account(address)
            .map_or_else(BigInt::zero, |a| a.balance.clone())
            + self.deltas.get(address).cloned().unwrap_or_default()
    }
    pub(crate) fn transfer(
        &mut self,
        ledger: &Ledger,
        from: &[u8],
        to: &[u8],
        amount: &BigInt,
    ) -> bool {
        if !amount.is_positive() || self.balance(ledger, from) < *amount {
            return false;
        }
        *self.deltas.entry(from.to_vec()).or_default() -= amount;
        *self.deltas.entry(to.to_vec()).or_default() += amount;
        self.transfers
            .push((from.to_vec(), to.to_vec(), amount.clone()));
        true
    }
    pub(crate) fn commit(self, ledger: &mut Ledger) -> Result<(), crate::execution::Error> {
        for (from, to, amount) in self.transfers {
            ledger
                .debit_amount_only(&from, &amount)
                .and_then(|()| ledger.credit(&to, &amount, None))
                .map_err(|e| crate::execution::Error(format!("value commit rejected: {e}")))?;
        }
        Ok(())
    }
}

pub(crate) struct Journal<'a> {
    runtime: &'a CircleRuntime,
    ledger: &'a Ledger,
    pub(crate) state: &'a mut StateBatch,
    pub(crate) values: Values,
    circles: BTreeMap<Vec<u8>, StorageTable>,
}
pub(crate) struct Reply {
    pub(crate) bytes: Vec<u8>,
    pub(crate) events: Option<(usize, Vec<Event>)>,
}
impl<'a> Journal<'a> {
    pub(crate) fn new(
        runtime: &'a CircleRuntime,
        ledger: &'a Ledger,
        state: &'a mut StateBatch,
    ) -> Self {
        Self {
            runtime,
            ledger,
            state,
            values: Values::default(),
            circles: BTreeMap::new(),
        }
    }
    pub(crate) fn balance(&self, address: &[u8]) -> BigInt {
        self.values.balance(self.ledger, address)
    }
    pub(crate) fn transfer(&mut self, from: &[u8], to: &[u8], amount: &BigInt) -> bool {
        self.values.transfer(self.ledger, from, to, amount)
    }
    pub(crate) fn snapshot(&self) -> Snapshot {
        self.state.snapshot()
    }
    pub(crate) fn storage(&self, address: &[u8]) -> Option<StorageTable> {
        self.circles.get(address).cloned()
    }
    pub(crate) fn stage(&mut self, address: &[u8], storage: StorageTable) {
        self.circles.insert(address.to_vec(), storage);
    }
    fn program_effort(&self) -> BigInt {
        self.circles
            .values()
            .map(|s| BigInt::from(s.values().len()) + 1)
            .sum::<BigInt>()
            * 32
    }
    pub(crate) fn execute(
        &mut self,
        address: &[u8],
        method: &[u8],
        params: &Document,
        ctx: &Context,
        value: &BigInt,
        mode: ReceiptMode<'_>,
        budget: Option<&mut ReceiptBudget>,
    ) -> Result<Call, Error> {
        circle_call::execute_journalled(
            self.runtime,
            &self.snapshot(),
            address,
            method,
            params,
            ctx,
            mode,
            budget,
            value,
            Some(self),
        )
    }
    pub(crate) fn nested(
        &mut self,
        caller: &[u8],
        target: &[u8],
        method: &[u8],
        params: &Document,
        ctx: &Context,
        fuel: i64,
        budget: Option<&mut ReceiptBudget>,
    ) -> Result<(VmValue, i64, Vec<Event>), Error> {
        let work: BigInt = self.program_effort() + BigInt::from(self.values.deltas.len()) * 32;
        let spent = work
            .to_i64()
            .filter(|cost| *cost <= fuel)
            .ok_or_else(|| rejected("call journal effort exceeds limit"))?;
        let saved = self.state.save().map_err(unavailable)?;
        let values = self.values.clone();
        let circles = self.circles.clone();
        let result = (|| {
            let Some(info) = circle_store::info(&self.snapshot(), target).map_err(unavailable)?
            else {
                // Contract.call_with charges another program snapshot before loading.
                if self.program_effort() > BigInt::from(fuel - spent) {
                    return Err(rejected("call journal effort exceeds limit"));
                }
                if self
                    .state
                    .get(&[b"contracts", target, b"bytecode"])
                    .is_none()
                {
                    return Err(rejected("bytecode not found"));
                }
                return Err(unavailable("OCTB execution host is not available"));
            };
            if self.state.get(&[b"circles", target, b"call_code"])
                != Some(info.code_hash.as_slice())
            {
                return Err(rejected("circle code update required"));
            }
            let ctx = Context {
                caller: std::str::from_utf8(caller).map_err(unavailable)?.into(),
                depth: ctx.depth + 1,
                node_id: if ctx.profile.proof_exec {
                    target.to_vec()
                } else {
                    ctx.node_id.clone()
                },
                limit: fuel - spent,
                update_policy: true,
                manifest: WasmProfile::Manifest,
                ..ctx.clone()
            };
            let call = self.execute(
                target,
                method,
                params,
                &ctx,
                &BigInt::zero(),
                ReceiptMode::Direct,
                budget,
            )?;
            if !call.receipt().success {
                let mut error = call
                    .receipt()
                    .error
                    .clone()
                    .unwrap_or_else(|| b"execution failed".to_vec());
                error.truncate(256);
                return Err(rejected(error));
            }
            call.apply(self.state)?;
            let receipt = call.receipt();
            let effort = spent
                .checked_add(receipt.effort)
                .filter(|v| *v <= fuel)
                .ok_or_else(|| rejected("call effort exceeds limit"))?;
            Ok((
                receipt.response.clone().unwrap_or(VmValue::Bool(true)),
                effort,
                receipt.events.clone(),
            ))
        })();
        if result.is_err() {
            self.values = values;
            self.circles = circles;
            self.state.restore(saved).map_err(unavailable)?;
        }
        result
    }
    pub(crate) fn dispatch(
        &mut self,
        address: &[u8],
        ctx: &Context,
        value: &BigInt,
        raw: &[u8],
        budget: Option<&mut ReceiptBudget>,
    ) -> Result<Reply, Error> {
        let request: Value = serde_json::from_slice(raw).map_err(unavailable)?;
        let id = &request["id"];
        let mut nested = None;
        let result = (|| {
            let fuel = counter(&request["fuel"])?;
            let index = counter(&request["events"])? as usize;
            let params = request["params"]
                .as_array()
                .ok_or_else(|| rejected("circle arguments invalid"))?
                .iter()
                .map(scalar)
                .collect::<Result<Vec<_>, _>>()?;
            let action = operation(&request["method"], &params)?;
            let storage = receipt::decode_storage(
                &serde_json::to_vec(&request["storage_pairs"]).map_err(unavailable)?,
            )?;
            let before = self
                .storage(address)
                .ok_or_else(|| unavailable("Circle journal storage missing"))?;
            let cost =
                circle_store::storage_effort(&before) + circle_store::storage_effort(&storage);
            let spent = cost
                .to_i64()
                .filter(|n| *n <= fuel)
                .ok_or_else(|| rejected("circle storage effort exceeds limit"))?;
            circle_storage::validate_delta(&before, &storage, true).map_err(|e| {
                rejected([b"circle reserved key write: ".as_slice(), &e.key].concat())
            })?;
            self.stage(address, storage);
            let fuel = fuel - spent;
            let (value, effort) = match action {
                Operation::Value => (VmValue::int(value.clone()), 0),
                Operation::Balance => (VmValue::int(self.values.balance(self.ledger, address)), 0),
                Operation::Transfer(target, amount) => {
                    if fuel < 50 {
                        return Err(rejected("circle transfer effort exhausted"));
                    }
                    let success = is_valid_address(target)
                        && !amount.is_negative()
                        && (amount.is_zero()
                            || self.values.transfer(self.ledger, address, target, &amount));
                    (VmValue::Bool(success), 50)
                }
                Operation::Call(target, method, params) => {
                    if ctx.depth >= 8 {
                        return Err(rejected("circle call depth exceeded"));
                    }
                    if !is_valid_address(target) {
                        return Err(rejected("circle address invalid"));
                    }
                    let (value, effort, events) = self.nested(
                        address,
                        target,
                        method,
                        &parameters(params)?,
                        ctx,
                        fuel,
                        budget,
                    )?;
                    nested = Some((index, events));
                    (value, effort)
                }
            };
            let response = response(&value)?;
            let storage = self
                .storage(address)
                .ok_or_else(|| unavailable("Circle journal storage missing"))?;
            let pairs = storage
                .values()
                .iter()
                .map(|(k, v)| json!({"key_b64":STANDARD.encode(k),"value_b64":STANDARD.encode(v)}))
                .collect::<Vec<_>>();
            let reply=serde_json::to_vec(&json!({"id":id,"response_b64":STANDARD.encode(response),"effort":spent+effort,"storage_pairs":pairs})).map_err(unavailable)?;
            if reply.len() > 67_108_864 {
                return Err(rejected("circle reply exceeds limit"));
            }
            Ok(reply)
        })();
        let bytes = match result {
            Ok(bytes) => bytes,
            Err(Error::Rejected(reason)) => {
                serde_json::to_vec(&json!({"id":id,"error":error_text(&reason)}))
                    .map_err(unavailable)?
            }
            Err(error) => return Err(error),
        };
        Ok(Reply {
            bytes,
            events: nested,
        })
    }
}
fn counter(v: &Value) -> Result<i64, Error> {
    v.as_i64()
        .filter(|v| *v >= 0 && *v < (1i64 << 62))
        .ok_or_else(|| rejected("circle counter invalid"))
}
fn scalar(v: &Value) -> Result<Scalar, Error> {
    match (v["tag"].as_str(), &v["value"]) {
        (Some("int"), Value::String(v)) => Ok(Scalar::Integer(
            parse_integer(v.as_bytes())
                .ok_or_else(|| rejected("circle integer invalid"))?
                .to_string()
                .into_bytes(),
        )),
        (Some("string"), Value::String(v)) => Ok(Scalar::String(v.as_bytes().to_vec())),
        (Some("bool"), Value::Bool(v)) => Ok(Scalar::Bool(*v)),
        _ => Err(rejected("circle argument invalid")),
    }
}
enum Operation<'a> {
    Value,
    Balance,
    Transfer(&'a [u8], BigInt),
    Call(&'a [u8], &'a [u8], &'a [Scalar]),
}
fn operation<'a>(method: &Value, params: &'a [Scalar]) -> Result<Operation<'a>, Error> {
    match (method.as_str(), params) {
        (Some("call_value"), []) => Ok(Operation::Value),
        (Some("oct_balance"), []) => Ok(Operation::Balance),
        (Some("oct_transfer"), [Scalar::String(target), Scalar::Integer(amount)]) => Ok(
            Operation::Transfer(target, parse_integer(amount).expect("checked scalar")),
        ),
        (Some("program_call"), [Scalar::String(target), Scalar::String(method), params @ ..]) => {
            Ok(Operation::Call(target, method, params))
        }
        _ => Err(rejected("circle operation invalid")),
    }
}
fn response(value: &VmValue) -> Result<Vec<u8>, Error> {
    let encoded;
    let (tag, bytes): (u8, &[u8]) = match value {
        VmValue::Bool(false) => (1, b""),
        VmValue::Bool(true) => (2, b""),
        VmValue::Int(v) | VmValue::U64(v) | VmValue::U128(v) | VmValue::U256(v) => {
            encoded = v.to_string().into_bytes();
            (3, &encoded)
        }
        VmValue::String(v) | VmValue::Address(v) => (4, v),
        VmValue::Bytes(v) | VmValue::Bytes32(v) => {
            encoded = STANDARD.encode(v).into_bytes();
            (4, &encoded)
        }
        _ => return Err(rejected("circle result type invalid")),
    };
    if bytes.len() > 2_097_152 - 10 {
        return Err(rejected("circle response exceeds limit"));
    }
    let mut out = b"OCWS1".to_vec();
    out.push(tag);
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(out)
}
fn parameters(values: &[Scalar]) -> Result<Document, Error> {
    let mut json = vec![b'['];
    for (i, value) in values.iter().enumerate() {
        if i > 0 {
            json.push(b',');
        }
        match value {
            Scalar::Bool(true) => json.extend_from_slice(b"true"),
            Scalar::Bool(false) => json.extend_from_slice(b"false"),
            Scalar::Integer(v) => json.extend_from_slice(v),
            Scalar::String(v) => json_string(&mut json, v),
            Scalar::Null => json.extend_from_slice(b"null"),
        }
    }
    json.push(b']');
    Document::parse(&json).map_err(unavailable)
}
fn error_text(raw: &[u8]) -> String {
    let mut result = String::new();
    let mut bytes = raw;
    while !bytes.is_empty() && result.len() < 256 {
        match std::str::from_utf8(bytes) {
            Ok(valid) => {
                for c in valid.chars() {
                    if result.len() + c.len_utf8() > 256 {
                        return result;
                    }
                    result.push(c);
                }
                break;
            }
            Err(e) => {
                let valid = std::str::from_utf8(&bytes[..e.valid_up_to()]).expect("valid prefix");
                for c in valid.chars() {
                    if result.len() + c.len_utf8() > 256 {
                        return result;
                    }
                    result.push(c);
                }
                if result.len() == 256 {
                    break;
                }
                result.push('?');
                bytes = &bytes[e.valid_up_to() + 1..];
            }
        }
    }
    result
}

pub(crate) fn merge_events(own: Vec<Event>, mut nested: Vec<(usize, Vec<Event>)>) -> Vec<Event> {
    let mut result = Vec::new();
    for (index, event) in own.into_iter().enumerate() {
        for (at, events) in &mut nested {
            if *at == index {
                result.append(events);
            }
        }
        result.push(event);
    }
    for (_, mut events) in nested {
        result.append(&mut events);
    }
    result
}
