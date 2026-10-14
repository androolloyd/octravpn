// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Public Circle application reads backed by the browser's exact committed tree.
//! Wallet capabilities remain explicit. The caller and activation profile never
//! come from app parameters; updates go through transaction admission separately.
use crate::{
    circle::{CircleRuntime, MAX_INPUT_BYTES},
    circle_assets::CanonicalAssets,
    circle_reads,
    circle_store::{self, Info},
    circle_view,
};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_browser::{
    application::{ApplicationHost, ReadMethod, ReadRequest, ReviewedAction, UnavailableHost},
    AssetResolver, Error, Provenance,
};
use octra_node_protocol::{
    circle_wasm::{
        self,
        codec::{self, Scalar},
        public_read, transcript, Execution, Method,
    },
    native_integer::parse_integer,
    native_json::Document,
    transaction::{decode_base64, json_string},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::Semaphore;

const PUBLIC_CALLER: &str = "oct00000000000000000000000000000000000000000000";
const VIEW_EFFORT: i64 = 20_000_000;

#[derive(Clone)]
pub struct CanonicalApplications {
    assets: CanonicalAssets,
    runtime: CircleRuntime,
    profile: circle_view::Profile,
    wallet: Arc<dyn ApplicationHost>,
    workers: Arc<Semaphore>,
}

fn unavailable(reason: impl std::fmt::Display) -> Error {
    Error::Unavailable(reason.to_string())
}
fn invalid(reason: impl std::fmt::Display) -> Error {
    Error::Invalid(reason.to_string())
}
fn native(error: circle_wasm::Error) -> Error {
    match error {
        circle_wasm::Error::Rejected(e) => invalid(String::from_utf8_lossy(&e)),
        circle_wasm::Error::Unavailable(e) => unavailable(String::from_utf8_lossy(&e)),
    }
}
fn text(raw: &[u8]) -> Result<&str, Error> {
    std::str::from_utf8(raw).map_err(|_| unavailable("non-UTF-8 Circle engine field"))
}

impl CanonicalApplications {
    /// The trusted host supplies rules for the snapshot's next epoch. The node
    /// resolves these through `circle_view::canonical` before enabling views.
    pub fn new(
        assets: CanonicalAssets,
        runtime: CircleRuntime,
        profile: circle_view::Profile,
    ) -> Self {
        Self {
            assets,
            runtime,
            profile,
            wallet: Arc::new(UnavailableHost),
            workers: Arc::new(Semaphore::new(4)),
        }
    }
    /// Wallet services must independently enforce chain, nonce and spending policy.
    pub fn with_wallet(mut self, wallet: Arc<dyn ApplicationHost>) -> Self {
        self.wallet = wallet;
        self
    }
    pub fn provenance(&self) -> Provenance {
        self.assets.provenance()
    }

    fn info(&self, circle: &[u8]) -> Result<Info, Error> {
        let info = circle_store::info(self.assets.snapshot(), circle)
            .map_err(unavailable)?
            .ok_or(Error::NotFound)?;
        if info.privacy != b"public" {
            return Err(Error::Sealed);
        }
        Ok(info)
    }
    fn code(&self, info: &Info) -> Result<Option<(String, Vec<u8>)>, Error> {
        self.check_code_size(info)?;
        let Some(encoded) =
            self.assets
                .snapshot()
                .get(&[b"circles", &info.circle_id, b"program", b"code_b64"])
        else {
            return Ok(None);
        };
        let raw = decode_base64(encoded).map_err(invalid)?;
        if hex::encode(Sha256::digest(&raw)).as_bytes() != info.code_hash {
            return Err(invalid("circle code hash mismatch"));
        }
        Ok(Some((text(encoded)?.to_owned(), raw)))
    }
    fn check_code_size(&self, info: &Info) -> Result<(), Error> {
        // Local view bound applies to both engines before program allocation.
        if self
            .assets
            .snapshot()
            .get(&[b"circles", &info.circle_id, b"program", b"code_b64"])
            .is_some_and(|encoded| encoded.len() > MAX_INPUT_BYTES)
        {
            return Err(Error::TooLarge);
        }
        Ok(())
    }
    fn describe(&self, code: &str) -> Result<(Vec<Method>, Vec<u8>), Error> {
        let mut input = json!({"action":"describe","is_view":true,"float_mode":self.profile.wasm().wasm_float,"code_b64":code,"execution_profile":"manifest","inspect_policy":true});
        let bytes = serde_json::to_vec(&input).map_err(unavailable)?;
        // Drop the duplicated code string before running the native engine.
        input.take();
        let reply = self.runtime.execute(&bytes).map_err(|e| match e {
            crate::circle::Error::Rejected(e) => invalid(e),
            crate::circle::Error::Unavailable(e) => unavailable(e),
        })?;
        let methods = circle_wasm::methods(reply.as_ref()).map_err(native)?;
        Ok((methods, reply.as_ref().to_vec()))
    }
    fn program_info(&self, info: &Info) -> Result<Value, Error> {
        let code = self.code(info)?;
        let methods = if let Some((code, raw)) = &code {
            if info.runtime == b"octb" {
                crate::circle_octb::methods(
                    crate::circle_query::admit(raw, true)
                        .map_err(native)?
                        .code(),
                )
            } else {
                self.describe(code)?.0
            }
        } else {
            vec![]
        };
        let methods=methods.iter().map(|m|Ok(json!({"name":text(&m.name)?,"view":m.view,"execution":match m.execution {Execution::Standard=>"standard",Execution::Compute=>"compute"}}))).collect::<Result<Vec<_>,Error>>()?;
        let limits = circle_store::LIMIT_NAMES
            .iter()
            .zip(info.limits)
            .map(|(key, v)| Ok((text(key)?.to_owned(), json!(v.to_string()))))
            .collect::<Result<serde_json::Map<_, _>, Error>>()?;
        Ok(
            json!({"circle_id":text(&info.circle_id)?,"runtime":text(&info.runtime)?,"version":info.version.to_string(),"owner":text(&info.owner)?,
            "code_hash":text(&info.code_hash)?,"has_program":code.is_some(),"code_bytes":code.as_ref().map_or(0,|(_,raw)|raw.len()),"code_b64":null,
            "methods":methods,"stable_root":text(&info.stable_root)?,"assets_root":text(&info.assets_root)?,"privacy_class":text(&info.privacy)?,
            "browser_mode":text(&info.browser)?,"resource_mode":text(&info.resource)?,"limits":limits}),
        )
    }
    fn view(&self, info: &Info, params: &Value) -> Result<Value, Error> {
        let method = params
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("missing Circle method"))?;
        let args = params
            .get("params")
            .filter(|v| v.is_array())
            .ok_or_else(|| invalid("missing Circle params"))?;
        if info.runtime == b"octb" {
            self.check_code_size(info)?;
            let params =
                Document::parse(&serde_json::to_vec(args).map_err(invalid)?).map_err(invalid)?;
            let query = crate::circle_query::Query::new(self.assets.snapshot(), &self.profile)
                .map_err(native)?;
            let receipt = query
                .circle(
                    &info.circle_id,
                    method.as_bytes(),
                    &params,
                    PUBLIC_CALLER.as_bytes(),
                    VIEW_EFFORT,
                )
                .map_err(native)?;
            if !receipt.success {
                return Err(invalid(String::from_utf8_lossy(
                    receipt.error.as_deref().unwrap_or(b"execution reverted"),
                )));
            }
            return Ok(json!({"result":octb_value(receipt.response.as_ref())?}));
        }
        let (code, _) = self
            .code(info)?
            .ok_or_else(|| invalid("circle program not found"))?;
        let (methods, descriptor) = self.describe(&code)?;
        let declarations = public_read::declarations(&descriptor).map_err(native)?;
        if circle_wasm::method_execution(&methods, method.as_bytes()) == Execution::Compute {
            return Err(invalid("circle compute method requires compute executor"));
        }
        let storage = circle_store::load_storage(self.assets.snapshot(), &info.circle_id, None)
            .map_err(unavailable)?;
        if method.starts_with("fhe_") {
            return Err(unavailable(
                "authenticated Circle HFHE context is not available",
            ));
        }
        let args = Document::parse(&serde_json::to_vec(args).map_err(invalid)?).map_err(invalid)?;
        let request = codec::encode_request(
            method.as_bytes(),
            &codec::request_params(&args).map_err(native)?,
        )
        .map_err(native)?;
        let declarations = declarations
            .into_iter()
            .filter(|d| d.method == method.as_bytes())
            .collect::<Vec<_>>();
        let epoch = circle_view::epoch(
            self.assets.snapshot().get(&[b"meta", b"last_epoch"]),
            circle_view::ReadKind::View,
        )
        .map_err(unavailable)?;
        let mut spent = 0;
        let reads = circle_reads::load(
            self.assets.snapshot(),
            epoch,
            &declarations,
            Some(VIEW_EFFORT),
            &mut spent,
        )
        .map_err(invalid)?;
        let fuel = VIEW_EFFORT - reads.effort;
        if fuel <= 0 {
            return Err(invalid("wasm public read effort exceeds limit"));
        }
        let storage_pairs = storage
            .values()
            .iter()
            .map(|(k, v)| json!({"key_b64":STANDARD.encode(k),"value_b64":STANDARD.encode(v)}))
            .collect::<Vec<_>>();
        let mut input = json!({
            "action":"execute","float_mode":self.profile.wasm().wasm_float,"inspect_policy":true,"code_cache_key":hex::encode(Sha256::digest(code.as_bytes())),"code_b64":code,
            "export_name":"octra_query","request_b64":STANDARD.encode(request),"storage_cache_key":null,"storage_pairs":storage_pairs,
            "caller":PUBLIC_CALLER,"address":text(&info.circle_id)?,"tx_hash":"0".repeat(64),"current_epoch":epoch,
            "hfhe_caps":[],"hfhe_pubkeys":[],"hfhe_active_key":null,"hfhe_strict":true,"math":self.profile.math,
            "hfhe_receipt_mode":"direct","hfhe_receipt_entries":[],"public_reads":circle_reads::engine_reads(&reads).map_err(unavailable)?,
            "fuel_limit":fuel,"compute_storage_cache_key":null,"compute_session_scope":null,"execution_profile":"standard","is_view":true,"update_policy":false,
        });
        if self.profile.wasm().proof_exec {
            input["hfhe_pairs"] = json!(true);
            // Native Active mode reserves enough wire space for a full transcript,
            // measuring a Capture payload before choosing cache-only transport.
            input["hfhe_receipt_mode"] = json!("capture");
            let reserved = transcript::entries_json(&vec![
                transcript::Entry {
                    method: vec![0; 64],
                    request_hash: vec![b'0'; 64],
                    response_hash: vec![b'0'; 64],
                    result: None
                };
                transcript::MAX_ENTRIES
            ])
            .len();
            if native_json_size(&input) > MAX_INPUT_BYTES - reserved + 2 {
                return Err(invalid("input too large"));
            }
            input["hfhe_receipt_mode"] = json!("direct");
        }
        let result = self
            .runtime
            .execute_effects(&serde_json::to_vec(&input).map_err(unavailable)?, &storage)
            .map_err(native)?;
        let value = vm_value(result.response.as_ref())?;
        if !output_fits(
            result.response.as_ref(),
            &value,
            spent + result.effort_used,
            VIEW_EFFORT,
        ) {
            return Err(invalid("circle receipt effort exceeds limit"));
        }
        if !result.success {
            return Err(invalid(String::from_utf8_lossy(
                result.error.as_deref().unwrap_or(b"execution reverted"),
            )));
        }
        // Views never publish storage, assets, events or any other VM effects.
        Ok(json!({"result":value}))
    }
    fn program_read(&self, request: &ReadRequest) -> Result<Value, Error> {
        let kind = match request.method {
            ReadMethod::ProgramInfo => circle_view::ReadKind::Program,
            ReadMethod::ProgramView => circle_view::ReadKind::View,
            _ => return Err(invalid("not a program read")),
        };
        let epoch = circle_view::epoch(self.assets.snapshot().get(&[b"meta", b"last_epoch"]), kind)
            .map_err(unavailable)?;
        if epoch != self.profile.epoch {
            return Err(unavailable(
                "view profile does not match the captured epoch",
            ));
        }
        let info = self.info(request.context.circle_id.as_bytes())?;
        match request.method {
            ReadMethod::ProgramInfo => self.program_info(&info),
            ReadMethod::ProgramView => self.view(&info, &request.params),
            _ => Err(invalid("not a program read")),
        }
    }
}
fn octb_value(value: Option<&crate::octb::Value>) -> Result<Value, Error> {
    value.map_or(Ok(Value::Null), |v| {
        serde_json::from_slice(&v.result_json()).map_err(unavailable)
    })
}
fn vm_value(response: Option<&Scalar>) -> Result<Value, Error> {
    Ok(match response {
        None => Value::Null,
        Some(Scalar::Null) => json!(""),
        Some(Scalar::Bool(v)) => json!(v),
        Some(Scalar::String(v)) => json!(text(v)?),
        Some(Scalar::Integer(v)) => json!(parse_integer(v)
            .ok_or_else(|| invalid("wasm response integer is invalid"))?
            .to_string()),
    })
}
// Native Byte_work.output_work on the fresh RPC byte budget. WASM execution
// has its own meter; only returned scalar allocation is added here.
fn output_fits(response: Option<&Scalar>, value: &Value, mut used: i64, limit: i64) -> bool {
    if response.is_none() {
        return true;
    }
    const EVENT_BYTES: usize = 4_194_304;
    if let Some(Scalar::Integer(raw)) = response {
        let Some(number) = parse_integer(raw) else {
            return false;
        };
        let size = number.bits() / 3 + 2;
        if size > EVENT_BYTES as u64 {
            return false;
        }
        used += size.div_ceil(32) as i64;
    }
    let bytes = match value {
        Value::Bool(true) => b"true".as_slice(),
        Value::Bool(false) => b"false",
        Value::String(v) => v.as_bytes(),
        _ => b"",
    };
    let mut encoded = Vec::new();
    json_string(&mut encoded, bytes);
    let size = encoded.len() + 16;
    size <= EVENT_BYTES && used >= 0 && used <= limit && (size as i64 + 31) / 32 <= limit - used
}
fn native_json_size(value: &Value) -> usize {
    match value {
        Value::String(v) => {
            let mut out = Vec::new();
            json_string(&mut out, v.as_bytes());
            out.len()
        }
        Value::Array(items) => {
            2 + items.len().saturating_sub(1) + items.iter().map(native_json_size).sum::<usize>()
        }
        Value::Object(fields) => {
            2 + fields.len().saturating_sub(1)
                + fields
                    .iter()
                    .map(|(k, v)| native_json_size(&json!(k)) + 1 + native_json_size(v))
                    .sum::<usize>()
        }
        _ => value.to_string().len(),
    }
}
#[async_trait]
impl ApplicationHost for CanonicalApplications {
    async fn read(&self, request: ReadRequest) -> Result<Value, Error> {
        if request.context.provenance != self.provenance() {
            return Err(Error::SnapshotChanged);
        }
        if !matches!(
            request.method,
            ReadMethod::ProgramInfo | ReadMethod::ProgramView
        ) {
            return self.wallet.read(request).await;
        }
        let permit = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| unavailable("circle view busy"))?;
        let host = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            host.program_read(&request)
        })
        .await
        .map_err(unavailable)?
    }
    async fn submit(&self, action: ReviewedAction) -> Result<Value, Error> {
        if action.intent().context.provenance != self.provenance() {
            return Err(Error::SnapshotChanged);
        }
        self.wallet.submit(action).await
    }
}
