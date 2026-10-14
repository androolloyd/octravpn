// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Circle code transitions within the caller's transaction savepoint.
use crate::{
    circle::{CircleRuntime, WasmProfile, MAX_INPUT_BYTES},
    circle_store,
    circle_transaction::Rules,
    execution::{Completion, Error, Rejection},
    state_batch::StateBatch,
};
use octra_node_protocol::{
    circle_program::{self, Deploy, Refusal, LIMIT_NAMES},
    circle_wasm::{public_read, Error as WasmError},
    native_json::Document,
    octb::admission,
    state::Ledger,
    transaction::{decode_base64, OpType, Transaction},
};
use serde_json::json;
use sha2::{Digest, Sha256};

pub(crate) enum Failure {
    Refused(Refusal),
    Unavailable(Error),
}
impl Failure {
    pub(crate) fn effect(self) -> WasmError {
        match self {
            Self::Refused(e) => WasmError::Rejected(e.reason),
            Self::Unavailable(e) => WasmError::Unavailable(e.0.into_bytes()),
        }
    }
}
impl From<Refusal> for Failure {
    fn from(error: Refusal) -> Self {
        Self::Refused(error)
    }
}
fn unavailable(reason: impl std::fmt::Display) -> Failure {
    Failure::Unavailable(Error(reason.to_string()))
}
fn refused(tag: &'static str, reason: impl Into<Vec<u8>>) -> Failure {
    Refusal::new(tag, reason).into()
}
fn set(state: &mut StateBatch, circle: &[u8], path: &[&[u8]], value: &[u8]) -> Result<(), Failure> {
    let mut key = vec![b"circles".as_slice(), circle];
    key.extend_from_slice(path);
    state.set(&key, value.to_vec()).map_err(unavailable)
}
fn hash(code: &[u8]) -> String {
    if code.is_empty() {
        "0".repeat(64)
    } else {
        hex::encode(Sha256::digest(code))
    }
}
fn debit(tx: &Transaction, ledger: &mut Ledger) -> Result<(), Failure> {
    ledger
        .debit(&tx.from, &tx.ou, tx.nonce, None)
        .map_err(|e| refused("insufficient_balance", e.0.into_bytes()))
}
fn admit_octb(code: &[u8], rules: Rules) -> Result<(), Failure> {
    let invalid = |reason: String| refused("circle_program_invalid", reason.into_bytes());
    let raw =
        decode_base64(code).map_err(|error| invalid(format!("Invalid_argument(\"{error}\")")))?;
    if raw.starts_with(b"OCPG") {
        return Err(unavailable(
            "OCTB Program certificate admission host is not available",
        ));
    }
    admission::decode(&raw, rules.storage_proof)
        .map(|_| ())
        .map_err(|error| invalid(error.to_string()))
}
fn document(tx: &Transaction) -> Result<Document, Failure> {
    let missing = if tx.op_type == OpType::CircleDeploy {
        b"deploy_circle requires message payload".as_slice()
    } else {
        b"circle_program_update requires message payload"
    };
    let raw = tx
        .message
        .as_deref()
        .ok_or_else(|| refused("malformed_transaction", missing))?;
    // The native JSON syntax exception text requires its own qualification.
    // Resource/parser failures must not become an invented consensus refusal.
    Document::parse(raw).map_err(unavailable)
}
fn validate(
    runtime: &CircleRuntime,
    rules: Rules,
    code: &[u8],
    deploy: bool,
) -> Result<(), Failure> {
    let action = if deploy || rules.inspect {
        "describe"
    } else {
        "validate"
    };
    let profile = if rules.manifest == WasmProfile::Manifest {
        "manifest"
    } else {
        "standard"
    };
    let code = std::str::from_utf8(code).map_err(unavailable)?;
    let input = serde_json::to_vec(&json!({"action":action,"code_b64":code,
        "execution_profile":profile,"float_mode":rules.wasm.wasm_float,
        "inspect_policy":rules.inspect}))
    .map_err(unavailable)?;
    if input.len() > MAX_INPUT_BYTES {
        return Err(unavailable(
            "Circle admission requires native large-input transport",
        ));
    }
    let descriptor = runtime.execute(&input).map_err(|error| match error {
        crate::circle::Error::Rejected(reason) => {
            refused("circle_runtime_invalid", reason.into_bytes())
        }
        crate::circle::Error::Unavailable(reason) => unavailable(reason),
    })?;
    if deploy {
        public_read::declarations(descriptor.as_ref()).map_err(|error| match error {
            WasmError::Rejected(reason) => refused("circle_runtime_invalid", reason),
            WasmError::Unavailable(reason) => unavailable(String::from_utf8_lossy(&reason)),
        })?;
    }
    Ok(())
}
fn deploy(
    runtime: &CircleRuntime,
    rules: Rules,
    tx: &Transaction,
    ledger: &mut Ledger,
    state: &mut StateBatch,
) -> Result<(), Failure> {
    let payload = Deploy::from_document(&document(tx)?)?;
    // Consensus_circle_code_admission runs OCTB verification before deriving
    // the address. Never install unchecked bytecode into canonical state.
    if payload.runtime == b"octb" {
        if let Some(code) = &payload.code {
            admit_octb(code, rules)?;
        }
    }
    let circle = payload.id(&tx.from, tx.nonce);
    if tx.to != circle {
        return Err(refused(
            "circle_id_mismatch",
            b"recipient does not match derived circle id",
        ));
    }
    let hash = check_deploy(runtime, rules, state, &circle, &payload)?;
    debit(tx, ledger)?;
    install(
        state,
        &circle,
        &tx.from,
        &hash,
        &payload,
        rules.wasm.proof_exec,
    )
}

pub(crate) fn check_deploy(
    runtime: &CircleRuntime,
    rules: Rules,
    state: &StateBatch,
    circle: &[u8],
    payload: &Deploy,
) -> Result<Vec<u8>, Failure> {
    let code = prepare(payload)?;
    if state.get(&[b"circles", circle, b"runtime"]).is_some() {
        return Err(refused("circle_exists", b"circle already exists"));
    }
    if payload.runtime == b"wasm_v1" {
        let code = payload.code.as_deref().ok_or_else(|| {
            refused(
                "circle_program_missing",
                b"wasm_v1 circles require program code",
            )
        })?;
        validate(runtime, rules, code, true)?;
    }
    Ok(hash(&code).into_bytes())
}

/// Native Circle_deploy.prepare: structural validation precedes runtime admission.
pub(crate) fn prepare(payload: &Deploy) -> Result<Vec<u8>, Failure> {
    let code = payload
        .code
        .as_deref()
        .map(decode_base64)
        .transpose()
        .map_err(|_| refused("malformed_transaction", b"circle deploy input is invalid"))?
        .unwrap_or_default();
    payload.validate_limits()?;
    if code.len() as u64 > payload.limits[3] as u64 {
        return Err(refused(
            "circle_code_too_large",
            b"circle code exceeds declared max_wasm_bytes",
        ));
    }
    if payload.resource == b"sealed_read" && payload.browser != b"native_sealed" {
        return Err(refused(
            "circle_mode_invalid",
            b"sealed_read circles require native_sealed browser mode",
        ));
    }
    Ok(code)
}

pub(crate) fn install(
    state: &mut StateBatch,
    circle: &[u8],
    owner: &[u8],
    hash: &[u8],
    payload: &Deploy,
    calls: bool,
) -> Result<(), Failure> {
    for (key, value) in [
        (b"runtime".as_slice(), payload.runtime.as_slice()),
        (b"version", b"1"),
        (b"owner", owner),
        (b"code_hash", hash),
        (
            b"stable_root",
            b"0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            b"assets_root",
            b"0000000000000000000000000000000000000000000000000000000000000000",
        ),
    ] {
        set(state, circle, &[key], value)?;
    }
    for (path, value) in [
        (
            [b"privacy".as_slice(), b"class".as_slice()],
            payload.privacy.as_slice(),
        ),
        ([b"browser", b"mode"], payload.browser.as_slice()),
        ([b"resources", b"mode"], payload.resource.as_slice()),
    ] {
        set(state, circle, &path, value)?;
    }
    for (key, value) in [
        (b"policy_hash".as_slice(), payload.policy_hash.as_deref()),
        (b"members_root", payload.members_root.as_deref()),
        (b"export_policy", payload.export_policy.as_deref()),
    ] {
        if let Some(value) = value {
            set(state, circle, &[b"privacy", key], value)?;
        } else {
            state
                .remove(&[b"circles", circle, b"privacy", key])
                .map_err(unavailable)?;
        }
    }
    for (key, value) in LIMIT_NAMES.iter().zip(payload.limits) {
        set(
            state,
            circle,
            &[b"limits", key],
            value.to_string().as_bytes(),
        )?;
    }
    if let Some(code) = &payload.code {
        set(state, circle, &[b"program", b"code_b64"], code)?;
    }
    set(state, circle, &[b"assets", b"usage_bytes"], b"0")?;
    if calls {
        set(state, circle, &[b"call_code"], hash)?;
    }
    Ok(())
}
fn update(
    runtime: &CircleRuntime,
    rules: Rules,
    tx: &Transaction,
    ledger: &mut Ledger,
    state: &mut StateBatch,
) -> Result<(), Failure> {
    let code = circle_program::update_code(&document(tx)?)?;
    let info = circle_store::info(&state.snapshot(), &tx.to)
        .map_err(unavailable)?
        .ok_or_else(|| refused("circle_not_found", b"circle does not exist"))?;
    if info.runtime == b"octb" {
        admit_octb(&code, rules)?;
    }
    if info.owner != tx.from {
        return Err(refused(
            "circle_access_denied",
            b"only the owner can update circle code",
        ));
    }
    let raw = decode_base64(&code).map_err(|error| {
        refused(
            "malformed_transaction_exception",
            format!("Invalid_argument(\"{error}\")").into_bytes(),
        )
    })?;
    if raw.len() as i128 > i128::from(info.limits[3]) {
        return Err(refused(
            "circle_code_too_large",
            b"circle code exceeds declared max_wasm_bytes",
        ));
    }
    if info.runtime == b"wasm_v1" {
        validate(runtime, rules, &code, false)?;
    }
    debit(tx, ledger)?;
    let hash = hash(&raw);
    set(
        state,
        &tx.to,
        &[b"version"],
        info.version.wrapping_add(1).to_string().as_bytes(),
    )?;
    set(state, &tx.to, &[b"code_hash"], hash.as_bytes())?;
    set(state, &tx.to, &[b"program", b"code_b64"], &code)?;
    if rules.wasm.proof_exec {
        set(state, &tx.to, &[b"call_code"], hash.as_bytes())?;
    }
    Ok(())
}

pub fn execute(
    runtime: &CircleRuntime,
    rules: Rules,
    tx: &Transaction,
    ledger: &mut Ledger,
    state: &mut StateBatch,
) -> Result<Completion, Error> {
    let result = match tx.op_type {
        OpType::CircleDeploy => deploy(runtime, rules, tx, ledger, state),
        OpType::CircleProgramUpdate => update(runtime, rules, tx, ledger, state),
        _ => Err(unavailable("operation is not a Circle code transition")),
    };
    match result {
        Ok(()) => Ok(Completion::Confirmed {
            created_account: None,
        }),
        Err(Failure::Unavailable(error)) => Err(error),
        Err(Failure::Refused(error)) => Ok(Completion::Rejected(Rejection {
            tag: error.tag.into(),
            reason: error.reason,
            notify_reason: None,
            consume_nonce: false,
            persist_state: false,
        })),
    }
}
