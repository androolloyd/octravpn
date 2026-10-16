// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Provider flows call back into the coordination actor for evidence, durable
//! result admission and publication. They never bypass the actor's funding gate.
use super::{Evidence, Head};
use crate::compute_provider::Provider;
use async_trait::async_trait;
use octra_node_protocol::{
    consensus::ValidatorSet,
    resource_compute::{
        call::Call,
        capability::Capability,
        certificate::Vote,
        message::{self, Offer, Output},
        provider::{self, Execute, Executed, Prepare},
        selection::{self, Commitment, Reveal},
        wire::Message,
        Error, Result,
    },
};
use std::time::Duration;
#[async_trait]
pub trait ProviderHost: Send + Sync {
    fn node(&self) -> &[u8];
    fn validators(&self) -> ValidatorSet;
    fn head(&self) -> Option<Head>;
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>>;
    fn nonce(&self) -> Vec<u8>;
    async fn evidence(&self) -> Result<Evidence>;
    async fn publish(&self, message: Message) -> Result<bool>;
    async fn save_result(&self, call: Call, result: Output) -> Result<bool>;
    async fn sleep(&self, duration: Duration);
}
fn head(host: &dyn ProviderHost) -> Option<Head> {
    host.head()
        .filter(|head| head.epoch >= 0 && head.state_root.len() == 32)
}
fn hex(raw: &[u8]) -> Vec<u8> {
    hex::encode(raw).into_bytes()
}
pub fn prepare_offer(offer: &Offer) -> Prepare {
    Prepare {
        model_epoch: offer.model_epoch,
        model_state_root: hex(&offer.model_state_root),
        circle_id: offer.circle_id.clone(),
        graph_root: hex(&offer.graph_root),
        model_root: hex(&offer.model_root),
        program_root: hex(&offer.program_root),
        executor_root: hex(&offer.executor_root),
    }
}
pub fn prepare_call(call: &Call) -> Prepare {
    let request = &call.request;
    Prepare {
        model_epoch: request.model_epoch,
        model_state_root: hex(&request.model_state_root),
        circle_id: request.circle_id.clone(),
        graph_root: hex(&request.graph_root),
        model_root: hex(&request.model_root),
        program_root: hex(&request.program_root),
        executor_root: hex(&request.executor_root),
    }
}
pub fn execute_call(call: &Call) -> Result<Execute> {
    let request = &call.request;
    Ok(Execute {
        memory_bytes: request
            .limits
            .memory_bytes
            .ok_or_else(|| Error::rejected(b"resource compute caller memory required"))?,
        guest_bytes: request
            .limits
            .guest_bytes
            .ok_or_else(|| Error::rejected(b"resource compute caller pages required"))?,
        fuel_limit: request
            .limits
            .fuel_limit
            .ok_or_else(|| Error::rejected(b"resource compute caller fuel required"))?,
        request_id: hex(&request.id()?),
        session_id: hex(&request.session_id),
        epoch_id: request.epoch_id,
        state_root: hex(&request.state_root),
        model_epoch: request.model_epoch,
        model_state_root: hex(&request.model_state_root),
        circle_id: request.circle_id.clone(),
        graph_root: hex(&request.graph_root),
        model_root: hex(&request.model_root),
        program_root: hex(&request.program_root),
        executor_root: hex(&request.executor_root),
        caller: request.caller.clone(),
        method_name: call.method_name.clone(),
        params_json: call.params_json.clone(),
        program_b64: Vec::new(),
        program_runtime: b"wasm_v1".to_vec(),
        storage: Vec::new(),
        max_output_bytes: request.max_output_bytes,
    })
}
pub fn signed_capability(
    host: &dyn ProviderHost,
    offer: &Offer,
    evidence: &Evidence,
    limits: &provider::Limits,
    epoch: i64,
) -> Result<Capability> {
    let mut value = Capability {
        chain_id: offer.chain_id.clone(),
        observed_epoch: epoch,
        valid_until: offer.expires_epoch,
        validator_set_root: offer.validator_set_root.clone(),
        node_id: host.node().to_vec(),
        circle_id: offer.circle_id.clone(),
        model_epoch: offer.model_epoch,
        model_state_root: offer.model_state_root.clone(),
        graph_root: offer.graph_root.clone(),
        model_root: offer.model_root.clone(),
        program_root: offer.program_root.clone(),
        executor_root: offer.executor_root.clone(),
        evidence_root: evidence.evidence_root.clone(),
        accelerator: limits.accelerator,
        lanes: limits.lanes,
        memory_bytes: limits.memory_bytes,
        max_request_bytes: limits.max_request_bytes,
        max_response_bytes: limits.max_response_bytes,
        signature: vec![0; 64],
    };
    value.signature = host.sign(&value.sign_bytes()?)?;
    Ok(value)
}
pub fn signed_commitment(
    host: &dyn ProviderHost,
    offer: &Offer,
    epoch: i64,
    nonce: &[u8],
) -> Result<Commitment> {
    let mut value = Commitment {
        chain_id: offer.chain_id.clone(),
        offer_id: offer.id()?.to_vec(),
        commit_epoch: epoch,
        node_id: host.node().to_vec(),
        graph_root: offer.graph_root.clone(),
        model_root: offer.model_root.clone(),
        program_root: offer.program_root.clone(),
        executor_root: offer.executor_root.clone(),
        nonce_hash: selection::nonce_hash(nonce).to_vec(),
        signature: vec![0; 64],
    };
    value.signature = host.sign(&value.sign_bytes()?)?;
    Ok(value)
}
pub fn signed_reveal(
    host: &dyn ProviderHost,
    commitment: &Commitment,
    nonce: &[u8],
    evidence_root: &[u8],
    epoch: i64,
) -> Result<Reveal> {
    let mut value = Reveal {
        chain_id: commitment.chain_id.clone(),
        offer_id: commitment.offer_id.clone(),
        commit_epoch: commitment.commit_epoch,
        reveal_epoch: epoch,
        node_id: commitment.node_id.clone(),
        graph_root: commitment.graph_root.clone(),
        model_root: commitment.model_root.clone(),
        program_root: commitment.program_root.clone(),
        executor_root: commitment.executor_root.clone(),
        nonce: nonce.to_vec(),
        evidence_root: evidence_root.to_vec(),
        signature: vec![0; 64],
    };
    value.signature = host.sign(&value.sign_bytes(commitment)?)?;
    Ok(value)
}
pub fn signed_result(host: &dyn ProviderHost, call: &Call, executed: Executed) -> Result<Output> {
    // Provider replies have already passed the provider engine's typed boundary.
    let raw = |value: &[u8]| {
        hex::decode(value)
            .map_err(|_| Error::rejected(b"resource compute provider result hash refused"))
    };
    let mut vote = Vote {
        request_id: call.request.id()?.to_vec(),
        node_id: host.node().to_vec(),
        output_hash: raw(&executed.output_hash)?,
        trace_root: raw(&executed.trace_root)?,
        output_bytes: executed.output_json.len() as i64,
        steps: executed.steps,
        operations: executed.operations,
        signature: vec![0; 64],
    };
    vote.signature = host.sign(&vote.sign_bytes()?)?;
    Ok(Output {
        vote,
        output_json: executed.output_json,
    })
}
/// Background work whose owner must cancel and drain it on service shutdown.
pub async fn candidate(provider: &Provider, host: &dyn ProviderHost, offer: &Offer) -> Result<()> {
    if head(host).is_none_or(|head| head.epoch > offer.expires_epoch) {
        return Ok(());
    }
    let limits = provider.limits();
    if !host.validators().is_validator(host.node())
        || limits.memory_bytes < offer.min_memory_bytes
        || limits.max_request_bytes < offer.request_bytes
        || limits.max_response_bytes < offer.response_bytes
    {
        return Ok(());
    }
    let evidence = host.evidence().await?;
    if evidence.executor_root != offer.executor_root {
        return Ok(());
    }
    provider.prepare(prepare_offer(offer)).await?;
    let Some(current) = head(host).filter(|head| head.epoch <= offer.expires_epoch) else {
        return Ok(());
    };
    let capability = signed_capability(host, offer, &evidence, limits, current.epoch)?;
    let nonce = host.nonce();
    if nonce.is_empty() || nonce.len() > 128 {
        return Ok(());
    }
    let commitment = signed_commitment(host, offer, current.epoch, &nonce)?;
    host.publish(Message::Capability(capability)).await?;
    host.publish(Message::Commitment(commitment.clone()))
        .await?;
    schedule_reveal(
        host,
        offer.expires_epoch,
        &commitment,
        &evidence.evidence_root,
        &nonce,
    )
    .await
}
pub async fn schedule_reveal(
    host: &dyn ProviderHost,
    expires: i64,
    commitment: &Commitment,
    evidence: &[u8],
    nonce: &[u8],
) -> Result<()> {
    loop {
        let Some(current) = head(host).filter(|head| head.epoch <= expires) else {
            return Ok(());
        };
        if current.epoch.wrapping_sub(commitment.commit_epoch) >= message::REVEAL_DELAY {
            host.publish(Message::Reveal(signed_reveal(
                host,
                commitment,
                nonce,
                evidence,
                current.epoch,
            )?))
            .await?;
            return Ok(());
        }
        host.sleep(Duration::from_millis(500)).await;
    }
}
pub async fn execute_selected(
    provider: &Provider,
    host: &dyn ProviderHost,
    call: &Call,
) -> Result<()> {
    provider.prepare(prepare_call(call)).await?;
    let executed = provider.execute(execute_call(call)?).await?;
    let result = signed_result(host, call, executed)?;
    if host.save_result(call.clone(), result.clone()).await? {
        host.publish(Message::Result(result)).await?;
    }
    Ok(())
}
