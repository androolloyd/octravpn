// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Read-only WASM execution shared by native clients and public applications.
use super::{rejected, unavailable, Event, VmReceipt};
use crate::{
    circle::CircleRuntime,
    circle_fhe, circle_input, circle_reads,
    circle_scope::Scope,
    circle_store::{self, Info},
    circle_view::Profile,
    octb::Value,
    state_batch::Snapshot,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    circle_wasm::{self, codec, public_read, Error, Execution},
    native_json::Document,
    octb::work::Budget,
};
use serde_json::json;
use sha2::{Digest, Sha256};
fn text(raw: &[u8]) -> Result<&str, Error> {
    std::str::from_utf8(raw).map_err(|_| unavailable("non-UTF-8 Circle engine field"))
}
fn native(error: crate::circle::Error) -> Error {
    match error {
        crate::circle::Error::Rejected(reason) => rejected(reason),
        crate::circle::Error::Unavailable(reason) => unavailable(reason),
    }
}
#[allow(clippy::too_many_arguments)] // One captured view state and explicit host capability.
pub(super) fn execute(
    execution: Execution,
    runtime: &CircleRuntime,
    state: &Snapshot,
    profile: &Profile,
    info: &Info,
    encoded: &[u8],
    method: &[u8],
    params: &Document,
    caller: &[u8],
    limit: i64,
    scope: Option<&Scope>,
    snapshot_root: Option<&[u8]>,
    depth: i64,
    budget: &mut Budget,
) -> Result<VmReceipt, Error> {
    let code = text(encoded)?;
    let mut input = json!({"action":"describe","is_view":true,"float_mode":profile.wasm().wasm_float,"code_b64":code,"execution_profile":"manifest","inspect_policy":true});
    let bytes = serde_json::to_vec(&input).map_err(unavailable)?;
    input.take();
    let description = runtime.execute(&bytes).map_err(native)?;
    let manifest_error = |error| match error {
        Error::Rejected(reason) => {
            rejected([b"invalid circle wasm manifest: ".as_slice(), &reason].concat())
        }
        other @ Error::Unavailable(_) => other,
    };
    let methods = circle_wasm::methods(description.as_ref()).map_err(manifest_error)?;
    let declarations = public_read::declarations(description.as_ref()).map_err(manifest_error)?;
    match (execution, circle_wasm::method_execution(&methods, method)) {
        (Execution::Standard, Execution::Compute) => {
            return Err(rejected("circle compute method requires compute executor"));
        }
        (Execution::Compute, Execution::Standard) => {
            return Err(rejected(
                "circle method is not declared for compute execution",
            ));
        }
        _ => (),
    }
    let storage = match circle_store::load_storage(state, &info.circle_id, None) {
        Ok(storage) => storage,
        Err(reason) => return Ok(failed(reason.0, 0)),
    };
    let (execution_profile, cap) = match execution {
        Execution::Standard => ("standard", 20_000_000),
        Execution::Compute => ("compute", 2_000_000_000),
    };
    let limit = limit.clamp(0, cap);
    let memory = octra_node_protocol::octb::fhe_work::Memory::default();
    let hfhe = circle_fhe::Wasm::prepare(
        runtime,
        state,
        &info.circle_id,
        &info.owner,
        caller,
        method,
        limit,
        true,
        profile.wasm().proof_exec,
        circle_fhe::Context {
            epoch: profile.epoch,
            scope,
            receipt_linked: false,
        },
        Some(&memory),
    )?;
    let request = match codec::request_params(params)
        .and_then(|params| codec::encode_request(method, &params))
    {
        Ok(request) => request,
        Err(Error::Rejected(reason)) => return Ok(failed(reason, hfhe.effort)),
        Err(error) => return Err(error),
    };
    let declarations = declarations
        .into_iter()
        .filter(|d| d.method == method)
        .collect::<Vec<_>>();
    let mut spent = 0;
    let reads = match circle_reads::load_at(
        state,
        profile.epoch,
        &declarations,
        Some(limit - hfhe.effort),
        &mut spent,
        snapshot_root,
    ) {
        Ok(reads) => reads,
        Err(reason) => return Ok(failed(reason.0, hfhe.effort + spent)),
    };
    spent += hfhe.effort;
    let fuel = limit - spent;
    if fuel <= 0 {
        return Ok(failed(
            b"wasm public read effort exceeds limit".to_vec(),
            spent.min(limit),
        ));
    }
    let storage_pairs = storage.values().iter().map(|(key, value)| json!({"key_b64":STANDARD.encode(key),"value_b64":STANDARD.encode(value)})).collect::<Vec<_>>();
    let storage_key = if storage_pairs.is_empty() {
        None
    } else {
        Some(format!(
            "{}:{}",
            text(&info.circle_id)?,
            text(&info.stable_root)?
        ))
    };
    let reads = circle_reads::engine_reads(&reads).map_err(unavailable)?;
    let public = hfhe.public_json()?;
    let caller = text(caller)?;
    let address = text(&info.circle_id)?;
    let mut input = json!({"action":"execute","float_mode":profile.wasm().wasm_float,"inspect_policy":true,"code_cache_key":hex::encode(Sha256::digest(encoded)),"code_b64":code,
        "export_name":"octra_query","request_b64":STANDARD.encode(request),"storage_cache_key":storage_key,"storage_pairs":storage_pairs,"caller":caller,"address":address,
        "tx_hash":"0".repeat(64),"current_epoch":profile.epoch,"hfhe_caps":hfhe.caps,"hfhe_pubkeys":public,"hfhe_active_key":null,"hfhe_strict":true,
        "math":profile.math,"hfhe_receipt_mode":"direct","hfhe_receipt_entries":[],"public_reads":reads,"fuel_limit":fuel,"compute_storage_cache_key":null,
        "compute_session_scope":null,"execution_profile":execution_profile,"is_view":true,"update_policy":false});
    if profile.wasm().proof_exec {
        input["hfhe_pairs"] = json!(true);
    }
    input["hfhe_active_key"] = hfhe.active_json()?;
    let bytes = match circle_input::encode(
        input,
        profile.wasm().proof_exec,
        false,
        hfhe.active_key_id(),
    ) {
        Ok(bytes) => bytes,
        Err(Error::Rejected(reason)) => return Ok(failed(reason, limit)),
        Err(error) => return Err(error),
    };
    let result = match runtime.execute_prepared(&bytes, &storage) {
        Ok(result) => result,
        Err(Error::Rejected(reason) | Error::Unavailable(reason)) => {
            return Ok(failed(reason, limit))
        }
    };
    let used = spent
        .checked_add(result.effort_used)
        .ok_or_else(|| unavailable("view effort overflow"))?;
    let response = match result.response.as_ref() {
        None => None,
        Some(scalar) => match Value::from_scalar(scalar) {
            Some(value) => Some(value),
            None => {
                return Ok(failed(
                    b"wasm response integer is invalid".to_vec(),
                    used.min(limit),
                ))
            }
        },
    };
    let output = response.as_ref().map_or(Some(used), |value| {
        crate::circle_receipt::output_value(budget, value, used, limit)
    });
    let success = result.success && output.is_some();
    let error = if output.is_none() {
        Some(b"circle receipt effort exceeds limit".to_vec())
    } else if result.success {
        None
    } else {
        Some(
            result
                .error
                .unwrap_or_else(|| b"execution reverted".to_vec()),
        )
    };
    Ok(VmReceipt {
        success,
        response: output.and(response),
        effort: output.unwrap_or(limit),
        events: result
            .events
            .into_iter()
            .map(|event| Event {
                contract: info.circle_id.clone(),
                depth,
                topic: event.topic,
                values: vec![event.data],
            })
            .collect(),
        error,
    })
}
fn failed(reason: Vec<u8>, effort: i64) -> VmReceipt {
    VmReceipt {
        success: false,
        response: None,
        effort,
        events: vec![],
        error: Some(reason),
    }
}
