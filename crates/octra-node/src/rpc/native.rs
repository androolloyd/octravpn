// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Byte-preserving native JSON-RPC on the existing operator listener.
use super::{
    account_store, Arc, Bytes, Context, Document, IntoResponse, State, StateBatch, StatusCode,
    SystemTime, Transaction, UNIX_EPOCH,
};
use crate::executor::Compiler;
use octra_node_protocol::{
    aml::rpc as compile,
    native_json::Value,
    rpc::{self, Fault, Request},
};
mod chain;
mod epochs;
mod private_account;
mod receipts;
mod records;
mod registration;
mod status;
mod submit;
mod tokens;
mod views;

/// gRPC shares method authority; its protobuf transport applies its own budget.
pub(super) async fn invoke(
    host: &Arc<Context>,
    method: &[u8],
    params: &[u8],
) -> std::result::Result<Vec<u8>, Fault> {
    let mut request = b"{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":".to_vec();
    octra_node_protocol::transaction::json_string(&mut request, method);
    request.extend_from_slice(b",\"params\":");
    request.extend_from_slice(params);
    request.push(b'}');
    let mut parsed = rpc::parse(&request).map_err(|error| match error {
        rpc::Error::Rpc(error) => error,
        rpc::Error::Unavailable(_) => Fault::new(110, b"service unavailable"),
    })?;
    let request = parsed
        .requests
        .pop()
        .ok_or_else(|| Fault::new(110, b"service unavailable"))??;
    dispatch(host.clone(), parsed.document, &request).await
}

async fn dispatch(
    host: Arc<Context>,
    doc: Arc<Document>,
    request: &Request,
) -> std::result::Result<Vec<u8>, Fault> {
    let params = request.params(&doc).cloned().unwrap_or(Value::List(vec![]));
    // These historical private-fixture probes do not add BFT authority or
    // duplicate the native dispatcher used by normal Single clients.
    if host.single.is_some() && request.method == b"octra_head" {
        return serde_json::to_vec(
            &host
                .node
                .head()
                .await
                .map_err(|_| Fault::new(110, b"service unavailable"))?,
        )
        .map_err(|_| Fault::new(110, b"service unavailable"));
    }
    #[cfg(feature = "test-helpers")]
    if let Some(single) = &host.single {
        if request.method == b"single_proof_status" {
            let hash = rpc::require_string(&doc, &params, 0, "hash")?;
            let hash =
                std::str::from_utf8(hash).map_err(|_| Fault::invalid(b"hash must be UTF-8"))?;
            let (status, pending) = single
                .proof_status(hash)
                .map_err(|_| Fault::new(110, b"service unavailable"))?;
            let status = match status {
                Some(octra_node_protocol::single::Preverify::Unavailable(reason)) => {
                    format!("Some(Unavailable({}))", String::from_utf8_lossy(&reason))
                }
                other => format!("{other:?}"),
            };
            return serde_json::to_vec(&serde_json::json!({"status":status,"pending":pending}))
                .map_err(|_| Fault::new(110, b"service unavailable"));
        }
    }

    if let Some(route) = octra_node_runtime::circle_rpc::assets::route(&request.method) {
        let plan = host
            .executor
            .read(move || route.prepare(&doc, &params))
            .await?;
        let snapshot = host
            .node
            .snapshot()
            .map_err(|_| Fault::new(110, b"service unavailable"))?;
        return host
            .executor
            .read(move || plan.read(snapshot.state()))
            .await;
    }
    if let Some((route, authenticated)) =
        octra_node_runtime::circle_rpc::private::find(&request.method)
    {
        if !authenticated {
            return Err(route.deny(&doc, &params));
        }
        let snapshot = host
            .node
            .snapshot()
            .map_err(|_| Fault::new(110, b"service unavailable"))?;
        return host
            .executor
            .read(move || route.read(snapshot.state(), &doc, &params))
            .await;
    }
    match request.method.as_slice() {
        b"epoch_get" | b"epoch_summaries" | b"octra_epochPage" => {
            epochs::read(&host, &request.method, &doc, &params).await
        }
        b"octra_pvacPubkey"
        | b"octra_pvacStatus"
        | b"octra_pvacMigrationStatus"
        | b"octra_encryptedCipher"
        | b"octra_encryptedBalance"
        | b"octra_viewPubkey"
        | b"octra_stealthOutputs"
        | b"octra_stealthOutputsPage"
        | b"octra_stealthOutputsById" => {
            private_account::read(&host, &request.method, doc.clone(), params).await
        }
        b"octra_tokensByAddress" => tokens::read(&host, &doc, &params).await,
        b"contract_saveAbi" | b"octra_programSaveAbi" => Err(tokens::save_abi()),
        b"octra_search"
        | b"epoch_current"
        | b"epoch_list"
        | b"staging_view"
        | b"staging_stats"
        | b"staging_estimateOu" => chain::rest::read(&host, &request.method, doc, params).await,
        b"staging_remove" | b"octra_registerPublicKey" | b"octra_registerPvacPubkey" => {
            registration::write(&host, &request.method, doc.clone(), params).await
        }
        b"octra_submit"
        | b"octra_submitBatch"
        | b"octra_privateTransfer"
        | b"octra_recommendedFee" => submit::write(&host, &request.method, doc, params).await,
        b"octra_balance"
        | b"octra_account"
        | b"octra_nonce"
        | b"octra_publicKey"
        | b"octra_validateAddress"
        | b"octra_supply"
        | b"octra_totalTransactions"
        | b"octra_transaction"
        | b"octra_transactions"
        | b"octra_recentTransactions"
        | b"octra_transactionsByAddress"
        | b"octra_tokenTransfersByAddress"
        | b"octra_rejectedByAddress"
        | b"octra_transactionsByEpoch" => chain::read(&host, &request.method, &doc, &params).await,
        b"node_version"
        | b"node_status"
        | b"node_stats"
        | b"node_metrics"
        | b"octra_runtimeVersion"
        | b"octra_validatorEnrollment"
        | b"octra_validatorViewPubkey"
        | b"octra_epochTags"
        | b"octra_signedRoot"
        | b"octra_accountProof"
        | b"octra_validatorSetProof"
        | b"octra_epochProof"
        | b"octra_consensusPeerStates"
        | b"octra_roundWitness"
        | b"octra_txInclusionProof" => status::read(&host, &request.method, &doc, &params).await,
        b"circle_program"
        | b"octra_circleProgram"
        | b"circle_program_auth"
        | b"octra_circleProgramAuth"
        | b"circle_program_info"
        | b"octra_circleProgramInfo"
        | b"circle_program_info_auth"
        | b"octra_circleProgramInfoAuth" => {
            use octra_node_runtime::{circle_rpc::program::Read, circle_view::ReadKind};
            let authenticated = matches!(
                request.method.as_slice(),
                b"circle_program_auth"
                    | b"octra_circleProgramAuth"
                    | b"circle_program_info_auth"
                    | b"octra_circleProgramInfoAuth"
            );
            let kind = if matches!(
                request.method.as_slice(),
                b"circle_program"
                    | b"octra_circleProgram"
                    | b"circle_program_auth"
                    | b"octra_circleProgramAuth"
            ) {
                Read::Code
            } else {
                Read::Descriptor
            };
            let snapshot = host
                .node
                .snapshot()
                .map_err(|_| Fault::new(110, b"service unavailable"))?;
            let profile = host
                .executor
                .circle_profile(&snapshot, ReadKind::Program)
                .await?;
            let native = host.executor.clone();
            host.executor
                .read(move || {
                    native.circle_program(kind, authenticated, &snapshot, &profile, &doc, &params)
                })
                .await
        }
        b"circle_view" | b"octra_circleView" => views::circle(&host, &doc, &params, false).await,
        b"circle_view_auth" | b"octra_circleViewAuth" => {
            views::circle(&host, &doc, &params, true).await
        }
        b"circle_info" | b"octra_circleInfo" | b"circle_info_auth" | b"octra_circleInfoAuth" => {
            let authenticated = matches!(
                request.method.as_slice(),
                b"circle_info_auth" | b"octra_circleInfoAuth"
            );
            let snapshot = host
                .node
                .snapshot()
                .map_err(|_| Fault::new(110, b"service unavailable"))?;
            host.executor
                .read(move || {
                    octra_node_runtime::circle_rpc::info(
                        snapshot.state(),
                        &doc,
                        &params,
                        authenticated,
                    )
                })
                .await
        }
        b"contract_receipt" | b"octra_programReceipt" => receipts::read(&host, &doc, &params).await,
        b"contract_call" | b"octra_programCall" => views::call(&host, &doc, &params).await,
        b"contract_verify" | b"octra_programVerify" => records::verify(host, doc, params).await,
        b"contract_source" | b"octra_programSource" => records::source(&host, &doc, &params).await,
        b"octra_contractAbi" | b"octra_programAbi" => records::abi(&host, &doc, &params).await,
        b"octra_compileAssembly" => {
            host.executor
                .compile(Compiler::Assembly, 0, doc, params)
                .await
        }
        b"octra_compileAml" | b"octra_compileAmlMulti" => {
            let head = host
                .node
                .head()
                .await
                .map_err(|_| Fault::new(110, b"service unavailable"))?;
            let epoch = i64::try_from(head.cursor.epoch.0)
                .ok()
                .filter(|epoch| *epoch < 1_i64 << 62)
                .ok_or_else(|| Fault::new(110, b"service unavailable"))?;
            let kind = if request.method == b"octra_compileAml" {
                Compiler::Aml
            } else {
                Compiler::Multi
            };
            host.executor.compile(kind, epoch, doc, params).await
        }
        b"octra_computeContractAddress" | b"octra_computeProgramAddress" => {
            // Address derivation is independent of the canonical store and
            // compiler authority, including while the node is catching up.
            host.executor
                .read(move || {
                    compile::compute_address_params(&doc, &params).map_err(|error| match error {
                        compile::Error::Rpc(fault) => fault,
                        compile::Error::Unavailable(_) => Fault::new(110, b"service unavailable"),
                    })
                })
                .await
        }
        b"vm_contract"
        | b"octra_programInfo"
        | b"octra_listContracts"
        | b"octra_listPrograms"
        | b"octra_contractStorage"
        | b"octra_programStorage"
        | b"octra_contractStorageDump"
        | b"octra_programStorageDump"
        | b"octra_contractBytecode"
        | b"octra_programBytecode" => {
            use octra_node_runtime::program::rpc::{self as programs, Read};
            let kind = match request.method.as_slice() {
                b"vm_contract" | b"octra_programInfo" => Read::Info,
                b"octra_listContracts" | b"octra_listPrograms" => Read::List,
                b"octra_contractStorage" | b"octra_programStorage" => Read::Storage,
                b"octra_contractStorageDump" | b"octra_programStorageDump" => Read::StorageDump,
                _ => Read::Bytecode,
            };
            // Disabled dump requests do not depend on the canonical store.
            if matches!(kind, Read::StorageDump) {
                return Err(Fault::new(
                    -32601,
                    b"program storage dump is disabled; query explicit keys",
                ));
            }
            let state = host
                .node
                .snapshot()
                .map_err(|_| Fault::new(110, b"service unavailable"))?
                .state()
                .clone();
            host.executor
                .read(move || programs::read(kind, &state, &doc, &params))
                .await
        }
        _ => Err(Fault::missing(&request.method)),
    }
}
async fn body(host: &Arc<Context>, raw: &[u8]) -> anyhow::Result<Vec<u8>> {
    let parsed = match rpc::parse(raw) {
        Ok(parsed) => parsed,
        Err(rpc::Error::Rpc(fault)) => {
            return Ok(rpc::response(None, None, Err(&fault), rpc::MAX_SINGLE)?)
        }
        Err(rpc::Error::Unavailable(error)) => return Err(error.into()),
    };
    let count = parsed.requests.len().max(1);
    let limit = if parsed.batch {
        rpc::MAX_SINGLE.min(rpc::MAX_BATCH / count)
    } else {
        rpc::MAX_SINGLE
    };
    let mut responses = Vec::new();
    for request in &parsed.requests {
        let encoded = match request {
            Ok(request) => {
                let result = if let Some(route) = super::compute::route(&request.method) {
                    let params = request
                        .params(&parsed.document)
                        .cloned()
                        .unwrap_or(Value::List(vec![]));
                    match super::compute::dispatch(
                        route,
                        host.compute.as_ref(),
                        &parsed.document,
                        &params,
                    )
                    .await
                    {
                        Ok(value) => Ok(value),
                        Err(octra_node_runtime::compute_service::rpc::Error::Rpc(fault)) => {
                            Err(fault)
                        }
                        // Native invariant and allocation exceptions bypass
                        // JSON-RPC refusal construction. Apply the existing
                        // HTTP operational-failure policy to the whole body.
                        Err(error) => return Err(error.into()),
                    }
                } else {
                    dispatch(host.clone(), parsed.document.clone(), request).await
                };
                rpc::response(
                    Some(&parsed.document),
                    Some(request),
                    result.as_ref().map(Vec::as_slice),
                    limit,
                )?
            }
            Err(fault) => rpc::response(None, None, Err(fault), limit)?,
        };
        responses.push(encoded);
    }
    if !parsed.batch {
        return Ok(responses.pop().expect("single RPC has one response"));
    }
    let mut out = vec![b'['];
    for (index, response) in responses.into_iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(&response);
    }
    out.push(b']');
    Ok(out)
}
pub(super) fn request_body(
    raw: std::result::Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> std::result::Result<Bytes, Box<axum::response::Response>> {
    raw.map_err(|error| {
        if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
            Box::new(super::http::rpc_body_limit())
        } else {
            Box::new(error.into_response())
        }
    })
}

pub(super) async fn handle(
    State(host): State<Arc<Context>>,
    raw: std::result::Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> impl IntoResponse {
    let raw = match request_body(raw) {
        Ok(raw) => raw,
        Err(response) => return *response,
    };
    match body(&host, &raw).await {
        Ok(raw) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            raw,
        )
            .into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "RPC resources unavailable").into_response(),
    }
}
