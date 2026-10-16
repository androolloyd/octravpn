// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Circle views over one immutable tree, including native legacy-contract subviews.
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
    circle_wasm::{Error, Execution},
    native_json::{Document, Value as Json},
    octb::{admission, work::Budget},
    transaction::{decode_base64, json_string, RuleMode},
};
use sha2::{Digest, Sha256};
use std::cell::Cell;
mod wasm;

#[derive(Clone, Copy)]
struct Capabilities<'a> {
    circle: Option<&'a crate::circle_fhe::Policy>,
    verifier: &'a Cell<bool>,
}
impl Capabilities<'_> {
    fn allows(&self, cap: octb::FheCapability) -> bool {
        if let Some(policy) = self.circle {
            return policy.allows(cap);
        }
        match cap {
            octb::FheCapability::VerifyZero
            | octb::FheCapability::VerifyRange
            | octb::FheCapability::VerifyBound => self.verifier.replace(false),
            _ => true,
        }
    }
}

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
pub(crate) fn admit(
    raw: &[u8],
    point_ops: bool,
    keys: Option<&octra_node_protocol::program_trust::Keys>,
) -> Result<admission::Admitted, Error> {
    let admitted = match keys {
        Some(keys) => octra_node_protocol::octb::program::decode_deploy(raw, point_ops, keys),
        None if raw.starts_with(b"OCPG") => {
            octra_node_protocol::octb::program::decode_source(raw, point_ops)
        }
        None => admission::decode(raw, point_ops),
    };
    admitted.map_err(|e| {
        if e.is_operational() {
            unavailable(e)
        } else {
            rejected(format!("invalid circle bytecode: {e}"))
        }
    })
}

pub struct Query<'a> {
    state: &'a Snapshot,
    profile: &'a Profile,
    root: Option<Vec<u8>>,
    keys: octra_node_protocol::program_trust::Keys,
    public_keys: Option<std::sync::Arc<dyn crate::pvac::Source>>,
    scope: Option<crate::circle_scope::Scope>,
    runtime: Option<crate::circle::CircleRuntime>,
    clock: Option<crate::circle_view::Clock>,
}
impl<'a> Query<'a> {
    pub fn new(state: &'a Snapshot, profile: &'a Profile) -> Result<Self, Error> {
        if !(0..(1i64 << 62)).contains(&profile.epoch) {
            return Err(unavailable("view epoch exceeds platform range"));
        }
        Ok(Self {
            state,
            profile,
            root: Some(hex::encode(state.root().map_err(unavailable)?).into_bytes()),
            keys: octra_node_protocol::program_trust::Keys::default(),
            public_keys: None,
            scope: None,
            runtime: None,
            clock: None,
        })
    }
    /// Captures the folded root from sealed canonical provenance. A raw-tree
    /// query instead uses its actual snapshot hash, as native make_view_ctx does.
    pub fn committed(
        assets: &'a crate::circle_assets::CanonicalAssets,
        profile: &'a Profile,
    ) -> Result<Self, Error> {
        let epoch = crate::circle_view::epoch(
            assets.snapshot().get(&[b"meta", b"last_epoch"]),
            crate::circle_view::ReadKind::View,
        )
        .map_err(unavailable)?;
        if profile.epoch != epoch {
            return Err(unavailable(
                "view profile does not match the captured epoch",
            ));
        }
        let mut query = Self::new(assets.snapshot(), profile)?;
        query.root = Some(assets.identity().state_root.as_bytes().to_vec());
        Ok(query)
    }
    pub fn with_program_keys(mut self, keys: &octra_node_protocol::program_trust::Keys) -> Self {
        self.keys = keys.clone();
        self
    }
    pub fn with_runtime(mut self, runtime: &crate::circle::CircleRuntime) -> Self {
        self.keys = runtime.program_keys().clone();
        self.public_keys = runtime.public_keys().cloned();
        self.runtime = Some(runtime.clone());
        self
    }
    pub fn with_clock(mut self, clock: crate::circle_view::Clock) -> Self {
        self.clock = Some(clock);
        self
    }
    /// Trusted local callers may supply a scope; public gateway reads do not.
    pub fn with_scope(mut self, scope: crate::circle_scope::Scope) -> Self {
        self.scope = Some(scope);
        self
    }
    /// Native legacy-program view with one verifier allowance shared by its
    /// invocation tree. The committed admission marker selects reload rules.
    pub fn program(
        &self,
        address: &[u8],
        method: &[u8],
        params: &Document,
        caller: &[u8],
        limit: i64,
    ) -> Result<VmReceipt, Error> {
        let verifier = Cell::new(true);
        match self.legacy(
            address,
            method,
            params,
            caller,
            0,
            limit,
            None,
            &verifier,
            &mut Budget::default(),
        ) {
            Err(Error::Rejected(reason)) => Ok(failed(reason)),
            result => result,
        }
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
        self.execute(Execution::Standard, circle, method, params, caller, limit)
    }
    /// The native compute entry point is explicit; ordinary views never promote
    /// a declared compute method into a larger execution allowance.
    pub fn compute(
        &self,
        circle: &[u8],
        method: &[u8],
        params: &Document,
        caller: &[u8],
        limit: i64,
    ) -> Result<VmReceipt, Error> {
        self.execute(Execution::Compute, circle, method, params, caller, limit)
    }
    fn execute(
        &self,
        execution: Execution,
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
            let encoded = self
                .state
                .get(&[b"circles", circle, b"program", b"code_b64"])
                .ok_or_else(|| rejected("circle program not found"))?;
            if encoded.len() > crate::circle::MAX_INPUT_BYTES {
                return Err(unavailable("Circle program exceeds native input capacity"));
            }
            let raw = decode_base64(encoded)
                .map_err(|e| rejected(format!("invalid circle code: Invalid_argument(\"{e}\")")))?;
            if hex::encode(Sha256::digest(&raw)).as_bytes() != info.code_hash {
                return Err(rejected("circle code hash mismatch"));
            }
            if info.runtime == b"wasm_v1" {
                let runtime = self
                    .runtime
                    .as_ref()
                    .ok_or_else(|| unavailable("query requires the WASM view host"))?;
                return wasm::execute(
                    execution,
                    runtime,
                    self.state,
                    self.profile,
                    &info,
                    encoded,
                    method,
                    params,
                    caller,
                    limit,
                    self.scope.as_ref(),
                    self.root.as_deref(),
                    0,
                    &mut Budget::default(),
                );
            }
            let code = admit(&raw, self.profile.point_ops, Some(&self.keys))?;
            if execution == Execution::Compute {
                return Err(rejected(
                    "circle method is not declared for compute execution",
                ));
            }
            let storage =
                circle_store::load_storage(self.state, circle, None).map_err(|e| rejected(e.0))?;
            let calls = self.profile.proof_exec == RuleMode::Active
                && self.state.get(&[b"circles", circle, b"call_code"])
                    == Some(info.code_hash.as_slice());
            let policy = crate::circle_fhe::Policy::scoped(
                self.state,
                circle,
                &info.owner,
                caller,
                self.profile.epoch,
                self.scope.as_ref(),
            )
            .map_err(unavailable)?;
            let verifier = Cell::new(true);
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
                Capabilities {
                    circle: Some(&policy),
                    verifier: &verifier,
                },
                None,
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
        capabilities: Capabilities<'_>,
        fhe_memory: Option<octra_node_protocol::octb::fhe_work::Memory>,
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
        let values = circle_octb::runtime_parameters(code, &fixed, method, params)?;
        let mut machine = octb::Machine::new(
            octb::Context {
                caller: caller.to_vec(),
                origin: caller.to_vec(),
                address: address.to_vec(),
                epoch: self.profile.epoch,
                tree_hash: self.root.clone().unwrap_or_default(),
                depth,
                ..octb::Context::default()
            },
            octb::Options {
                limit,
                integer_work: self.profile.int_work,
                fhe_work: self.profile.fhe_work == RuleMode::Active,
                object_cost: self.profile.object_cost,
                proof_exec: self.profile.proof_exec == RuleMode::Active,
                math: self.profile.math,
                point_ops: self.profile.point_ops,
                is_view: true,
                async_exec: true,
                strict: code.facts().is_some(),
                storage_kinds: circle_octb::storage_kinds(code, calls),
                fhe_memory,
                ..octb::Options::default()
            },
            storage,
        );
        machine.pc = entry;
        circle_octb::seed_values(&mut machine, method, values);
        let success = machine
            .run(
                &fixed,
                &mut Host {
                    query: self,
                    calls,
                    depth,
                    capabilities,
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
    #[allow(clippy::too_many_arguments)] // Native view context and shared capability/budget.
    fn legacy(
        &self,
        address: &[u8],
        method: &[u8],
        params: &Document,
        caller: &[u8],
        depth: i64,
        limit: i64,
        memory: Option<octra_node_protocol::octb::fhe_work::Memory>,
        verifier: &Cell<bool>,
        budget: &mut Budget,
    ) -> Result<VmReceipt, Error> {
        // The admission marker comes from the authenticated tree, never from
        // view parameters. Native reloads validate source envelopes and facts
        // here; independent source compilation is a deployment requirement.
        let artifact = crate::program::Artifact::load(
            self.state,
            &crate::program::Journal::default(),
            address,
            self.profile.point_ops,
            &self.keys,
        )
        .map_err(|error| match error {
            crate::program::Error::Unavailable(reason) => unavailable(reason),
            crate::program::Error::Rejected(_) => rejected("bytecode not found"),
        })?
        .ok_or_else(|| rejected("bytecode not found"))?;
        let storage = crate::program::store::storage(self.state, address);
        self.run(
            artifact.admitted(),
            storage,
            method,
            params,
            caller,
            address,
            depth,
            limit.clamp(0, 10_000_000),
            true,
            true,
            Capabilities {
                circle: None,
                verifier,
            },
            memory,
            budget,
        )
    }
}
struct Host<'a, 'b> {
    query: &'a Query<'b>,
    calls: bool,
    depth: i64,
    capabilities: Capabilities<'a>,
}
impl octb::Host for Host<'_, '_> {
    fn running(&self) -> bool {
        self.query
            .clock
            .as_ref()
            .is_none_or(crate::circle_view::Clock::running)
    }
    fn cap_live(&mut self, _cap: &octb::Capability) -> Result<bool, octb::Unavailable> {
        Ok(false)
    }
    fn fhe_capability(&self, cap: octb::FheCapability) -> Result<bool, octb::Unavailable> {
        Ok(self.capabilities.allows(cap))
    }
    fn fhe_key(&mut self, address: &[u8]) -> Result<Option<octb::FheKeySource>, octb::Unavailable> {
        if self
            .capabilities
            .circle
            .is_some_and(|policy| !policy.key(address))
        {
            return Ok(None);
        }
        crate::pvac::bound(self.query.public_keys.as_ref(), self.query.state, address)
            .map(|key| key.map(octb::FheKeySource::Bytes))
            .map_err(|e| octb::Unavailable(e.to_string()))
    }
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
        let result = parameters(
            request.params,
            self.query.profile.proof_exec == RuleMode::Active,
        )
        .and_then(|params| {
            self.query.legacy(
                request.target,
                request.method,
                &params,
                request.caller,
                self.depth + 1,
                request.limit,
                request.fhe_memory.clone(),
                self.capabilities.verifier,
                budget,
            )
        });
        match result {
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
