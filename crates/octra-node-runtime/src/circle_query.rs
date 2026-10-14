// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! OCTB views over one immutable tree, including native legacy-contract subviews.
use crate::{
    circle_call::{Event, VmReceipt},
    circle_octb, circle_store,
    circle_view::Profile,
    octb::{self, Value},
    state_batch::Snapshot,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigInt;
use octra_node_protocol::{
    account_pack,
    circle_storage::StorageTable,
    circle_wasm::Error,
    native_json::{Document, Value as Json},
    octb::{admission, work::Budget},
    transaction::{decode_base64, json_string, RuleMode},
};
use sha2::{Digest, Sha256};

fn unavailable(reason: impl std::fmt::Display) -> Error {
    Error::Unavailable(reason.to_string().into_bytes())
}
fn rejected(reason: impl AsRef<[u8]>) -> Error {
    Error::Rejected(reason.as_ref().to_vec())
}
fn failed(reason: Vec<u8>) -> VmReceipt {
    VmReceipt {
        success: false,
        response: None,
        effort: 0,
        events: vec![],
        error: Some(reason),
    }
}
pub(crate) fn admit(raw: &[u8], point_ops: bool) -> Result<admission::Admitted, Error> {
    if raw.starts_with(b"OCPG") {
        return Err(unavailable(
            "OCTB Program certificate admission host is not available",
        ));
    }
    admission::decode(raw, point_ops).map_err(|e| rejected(format!("invalid circle bytecode: {e}")))
}

pub struct Query<'a> {
    state: &'a Snapshot,
    profile: &'a Profile,
    root: Vec<u8>,
}
impl<'a> Query<'a> {
    pub fn new(state: &'a Snapshot, profile: &'a Profile) -> Result<Self, Error> {
        Ok(Self {
            state,
            profile,
            root: hex::encode(state.root().map_err(unavailable)?).into_bytes(),
        })
    }
    /// No mutable store is accepted; view effects can never reach publication.
    pub fn circle(
        &self,
        circle: &[u8],
        method: &[u8],
        params: &Document,
        caller: &[u8],
        limit: i64,
    ) -> Result<VmReceipt, Error> {
        let result = (|| {
            let info = circle_store::info(self.state, circle)
                .map_err(unavailable)?
                .ok_or_else(|| rejected("circle not found"))?;
            if info.runtime != b"octb" {
                return Err(unavailable("query requires the WASM view host"));
            }
            let encoded = self
                .state
                .get(&[b"circles", circle, b"program", b"code_b64"])
                .ok_or_else(|| rejected("circle program not found"))?;
            let raw = decode_base64(encoded)
                .map_err(|e| rejected(format!("invalid circle code: Invalid_argument(\"{e}\")")))?;
            if hex::encode(Sha256::digest(&raw)).as_bytes() != info.code_hash {
                return Err(rejected("circle code hash mismatch"));
            }
            let code = admit(&raw, self.profile.point_ops)?;
            let storage =
                circle_store::load_storage(self.state, circle, None).map_err(|e| rejected(e.0))?;
            let calls = self.profile.proof_exec == RuleMode::Active
                && self.state.get(&[b"circles", circle, b"call_code"])
                    == Some(info.code_hash.as_slice());
            self.run(
                &code,
                storage,
                method,
                params,
                caller,
                circle,
                0,
                limit,
                calls,
                false,
                &mut Budget::default(),
            )
        })();
        match result {
            Err(Error::Rejected(reason)) => Ok(failed(reason)),
            result => result,
        }
    }
    #[allow(clippy::too_many_arguments)] // Native call state and shared budget are explicit.
    fn run(
        &self,
        code: &admission::Admitted,
        storage: StorageTable,
        method: &[u8],
        params: &Document,
        caller: &[u8],
        address: &[u8],
        depth: i64,
        limit: i64,
        calls: bool,
        contract: bool,
        budget: &mut Budget,
    ) -> Result<VmReceipt, Error> {
        let fixed = octb::fix_jumps(code.code());
        if contract {
            let count = match params.root() {
                Json::List(ids) => ids.len(),
                _ => 0,
            };
            if let Some(arity) = circle_octb::arity(&fixed, method).filter(|arity| *arity != count)
            {
                return Err(rejected(
                    [
                        b"arity mismatch: ".as_slice(),
                        method,
                        format!(" expects {arity} args, got {count}").as_bytes(),
                    ]
                    .concat(),
                ));
            }
        }
        let entry =
            circle_octb::dispatcher(&fixed, method).ok_or_else(|| rejected("method not found"))?;
        let mut machine = octb::Machine::new(
            octb::Context {
                caller: caller.to_vec(),
                origin: caller.to_vec(),
                address: address.to_vec(),
                epoch: self.profile.epoch,
                tree_hash: self.root.clone(),
                depth,
                ..octb::Context::default()
            },
            octb::Options {
                limit,
                integer_work: self.profile.int_work,
                fhe_work: self.profile.fhe_work == RuleMode::Active,
                proof_exec: self.profile.proof_exec == RuleMode::Active,
                math: self.profile.math,
                point_ops: self.profile.point_ops,
                is_view: true,
                async_exec: true,
                ..octb::Options::default()
            },
            storage,
        );
        machine.pc = entry;
        circle_octb::seed(&mut machine, method, params)?;
        let success = machine
            .run(
                &fixed,
                &mut Host {
                    query: self,
                    calls,
                    depth,
                },
                Some(budget),
            )
            .map_err(unavailable)?;
        Ok(VmReceipt {
            success,
            response: success.then(|| machine.regs[0].clone()),
            effort: machine.effort,
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
        })
    }
    fn contract(
        &self,
        request: &octb::CallRequest<'_>,
        depth: i64,
        budget: &mut Budget,
    ) -> Result<VmReceipt, Error> {
        let encoded = self
            .state
            .get(&[b"contracts", request.target, b"bytecode"])
            .ok_or_else(|| rejected("bytecode not found"))?;
        if let Some(raw) = self.state.get(&[b"contracts", request.target, b"meta"]) {
            if let Ok(doc) = Document::parse(raw) {
                let valid = [b"address".as_slice(), b"code_hash", b"version", b"owner"]
                    .iter()
                    .all(|key| matches!(doc.field(doc.root(), key), Some(Json::String(_))));
                if valid
                    && matches!(doc.field(doc.root(), b"admission"), Some(Json::String(v)) if v == b"source")
                {
                    return Err(unavailable(
                        "Program source admission host is not available",
                    ));
                }
            }
        }
        let raw = decode_base64(encoded).map_err(|_| rejected("bytecode not found"))?;
        let code = admit(&raw, self.profile.point_ops).map_err(|e| match e {
            Error::Rejected(_) => rejected("bytecode not found"),
            other @ Error::Unavailable(_) => other,
        })?;
        let mut storage = StorageTable::new(100);
        for key in self
            .state
            .child_names(&[b"contracts", request.target, b"storage"])
        {
            if let Some(value) = self
                .state
                .get(&[b"contracts", request.target, b"storage", key])
            {
                storage.replace(key.to_vec(), value.to_vec());
            }
        }
        let params = parameters(request.params, self.profile.proof_exec == RuleMode::Active)?;
        self.run(
            &code,
            storage,
            request.method,
            &params,
            request.caller,
            request.target,
            depth,
            request.limit.min(10_000_000),
            true,
            true,
            budget,
        )
    }
}
struct Host<'a, 'b> {
    query: &'a Query<'b>,
    calls: bool,
    depth: i64,
}
impl octb::Host for Host<'_, '_> {
    fn groth16(
        &mut self,
        key: &[u8],
        proof: &[u8],
        inputs: &[u8],
    ) -> Result<bool, octb::Unavailable> {
        Ok(crate::groth16::verify(key, proof, inputs))
    }
    fn balance(&mut self, address: &[u8]) -> Result<BigInt, octb::Unavailable> {
        let Some(raw) = self.query.state.get(&[b"accounts", address, b"data"]) else {
            return Ok(0.into());
        };
        match account_pack::data(raw).map_err(|e| octb::Unavailable(e.to_string()))? {
            account_pack::Data::Old(account) | account_pack::Data::Parts(account, _) => {
                Ok(account.balance)
            }
        }
    }
    fn call(
        &mut self,
        request: octb::CallRequest<'_>,
        _storage: &mut StorageTable,
        budget: Option<&mut Budget>,
    ) -> Result<Option<octb::Subcall>, octb::Unavailable> {
        if !self.calls {
            return Ok(None);
        }
        let budget = budget.ok_or_else(|| octb::Unavailable("view byte budget missing".into()))?;
        match self.query.contract(&request, self.depth + 1, budget) {
            Ok(receipt) if receipt.success => Ok(Some(octb::Subcall {
                response: receipt.response.unwrap_or(Value::Bool(true)),
                effort: receipt.effort,
                events: receipt
                    .events
                    .into_iter()
                    .map(|e| octb::Event {
                        contract: e.contract,
                        depth: e.depth,
                        name: e.topic,
                        values: e.values.into_iter().map(Value::string).collect(),
                    })
                    .collect(),
            })),
            Ok(_) | Err(Error::Rejected(_)) => Ok(None),
            Err(Error::Unavailable(reason)) => Err(octb::Unavailable(
                String::from_utf8_lossy(&reason).into_owned(),
            )),
        }
    }
}
fn parameters(values: &[Value], typed: bool) -> Result<Document, Error> {
    let mut out = vec![b'['];
    for (i, value) in values.iter().enumerate() {
        if i != 0 {
            out.push(b',');
        }
        match value {
            Value::Int(v) => out.extend_from_slice(v.to_string().as_bytes()),
            Value::U64(v) | Value::U128(v) | Value::U256(v) if typed => {
                out.extend_from_slice(v.to_string().as_bytes());
            }
            Value::Bool(v) if typed => out.extend_from_slice(if *v { b"true" } else { b"false" }),
            Value::Capability(_) | Value::Cipher(_) | Value::PublicKey(_) if typed => {
                out.extend_from_slice(b"null");
            }
            Value::Bytes(v) | Value::Bytes32(v) if !typed => {
                json_string(&mut out, STANDARD.encode(v).as_bytes());
            }
            value => json_string(&mut out, &value.text()),
        }
    }
    out.push(b']');
    Document::parse(&out).map_err(unavailable)
}
