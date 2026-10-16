// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{invalid_argument, Error, JobStatus, Response, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigInt;
use octra_node_protocol::{
    native_json::{Document, ReadMode},
    resource_compute::{
        certificate::{Certificate, Signer, Vote},
        funding,
        message::CancelAck,
        request::Request,
        selection::{Member, Selection},
        wire::Message,
    },
    transaction::json_string,
};

struct Object(Vec<u8>);
impl Object {
    fn new() -> Self {
        Self(vec![b'{'])
    }
    fn key(&mut self, key: &[u8]) {
        if self.0.len() > 1 {
            self.0.push(b',');
        }
        json_string(&mut self.0, key);
        self.0.push(b':');
    }
    fn string(&mut self, key: &[u8], value: &[u8]) {
        self.key(key);
        json_string(&mut self.0, value);
    }
    fn raw(&mut self, key: &[u8], value: &[u8]) {
        self.key(key);
        self.0.extend_from_slice(value);
    }
    fn int(&mut self, key: &[u8], value: i64) {
        self.raw(key, value.to_string().as_bytes());
    }
    fn int64(&mut self, key: &[u8], value: i64) {
        self.string(key, value.to_string().as_bytes());
    }
    fn hash(&mut self, key: &[u8], value: &[u8]) {
        self.string(key, hex::encode(value).as_bytes());
    }
    fn base64(&mut self, key: &[u8], value: &[u8]) {
        self.string(key, STANDARD.encode(value).as_bytes());
    }
    fn finish(mut self) -> Vec<u8> {
        self.0.push(b'}');
        self.0
    }
}
fn quoted(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    json_string(&mut out, value);
    out
}
fn array(values: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    let mut out = vec![b'['];
    for value in values {
        if out.len() > 1 {
            out.push(b',');
        }
        out.extend_from_slice(&value);
    }
    out.push(b']');
    out
}

fn signer_json(signer: &Signer) -> Vec<u8> {
    let mut out = Object::new();
    out.string(b"node_id", &signer.node_id);
    out.hash(b"vote_id", &signer.vote_id);
    out.string(b"weight", signer.weight.to_string().as_bytes());
    out.finish()
}
fn vote_json(vote: &Vote) -> Vec<u8> {
    let mut out = Object::new();
    out.string(b"node_id", &vote.node_id);
    out.int64(b"operations", vote.operations);
    out.int(b"output_bytes", vote.output_bytes);
    out.hash(b"output_hash", &vote.output_hash);
    out.hash(b"request_id", &vote.request_id);
    out.base64(b"signature", &vote.signature);
    out.int64(b"steps", vote.steps);
    out.hash(b"trace_root", &vote.trace_root);
    out.finish()
}
fn certificate_json(certificate: &Certificate) -> Vec<u8> {
    let mut out = Object::new();
    out.int64(b"operations", certificate.operations);
    out.int(b"output_bytes", certificate.output_bytes);
    out.hash(b"output_hash", &certificate.output_hash);
    out.hash(b"request_id", &certificate.request_id);
    out.hash(b"root", &certificate.root);
    out.string(
        b"signed_weight",
        certificate.signed_weight.to_string().as_bytes(),
    );
    out.raw(
        b"signer_count",
        certificate.signers.len().to_string().as_bytes(),
    );
    out.raw(
        b"signers",
        &array(certificate.signers.iter().map(signer_json)),
    );
    out.int64(b"steps", certificate.steps);
    out.hash(b"trace_root", &certificate.trace_root);
    out.raw(b"votes", &array(certificate.votes.iter().map(vote_json)));
    out.finish()
}
fn request_json(request: &Request) -> Vec<u8> {
    let mut out = Object::new();
    if let Some(value) = request.limits.unit_price {
        out.int64(b"unit_price", value);
    }
    if let Some(value) = request.limits.fee_cap {
        out.int64(b"fee_cap", value);
    }
    if let Some(value) = request.limits.memory_bytes {
        out.int(b"memory_bytes", value);
    }
    if let Some(value) = request.limits.guest_bytes {
        out.int(b"guest_bytes", value);
    }
    if let Some(value) = request.limits.fuel_limit {
        out.int(b"fuel_limit", value);
    }
    out.string(b"caller", &request.caller);
    out.string(b"chain_id", &request.chain_id);
    out.string(b"circle_id", &request.circle_id);
    out.int64(b"epoch_id", request.epoch_id);
    out.hash(b"executor_root", &request.executor_root);
    out.int64(b"expires_epoch", request.expires_epoch);
    out.hash(b"graph_root", &request.graph_root);
    out.int(b"input_bytes", request.input_bytes);
    out.hash(b"input_hash", &request.input_hash);
    out.int(b"max_output_bytes", request.max_output_bytes);
    out.int64(b"model_epoch", request.model_epoch);
    out.hash(b"model_root", &request.model_root);
    out.hash(b"model_state_root", &request.model_state_root);
    out.hash(b"program_root", &request.program_root);
    out.hash(b"selection_root", &request.selection_root);
    out.int64(b"sequence", request.sequence);
    out.hash(b"session_id", &request.session_id);
    out.hash(b"state_root", &request.state_root);
    out.hash(b"validator_set_root", &request.validator_set_root);
    out.finish()
}
fn member_json(member: &Member) -> Vec<u8> {
    let mut out = Object::new();
    out.hash(b"evidence_root", &member.evidence_root);
    out.hash(b"executor_root", &member.executor_root);
    out.hash(b"graph_root", &member.graph_root);
    out.hash(b"model_root", &member.model_root);
    out.string(b"node_id", &member.node_id);
    out.hash(b"program_root", &member.program_root);
    out.hash(b"score", &member.score);
    out.finish()
}
fn selection_json(selection: &Selection) -> Vec<u8> {
    let mut out = Object::new();
    out.hash(b"challenge", &selection.challenge);
    out.raw(
        b"members",
        &array(selection.members.iter().map(member_json)),
    );
    out.hash(b"offer_id", &selection.offer_id);
    out.hash(b"root", &selection.root);
    out.int64(b"target_epoch", selection.target_epoch);
    out.finish()
}
fn output_value(raw: &[u8]) -> Result<Vec<u8>> {
    match Document::parse_native(raw, ReadMode::Safe) {
        Ok(document) => document
            .write(document.root(), false)
            .map_err(|error| Error::Unavailable(error.to_string().into_bytes())),
        // Native output_value catches every parser exception and publishes the
        // original string. The raw output_json field always retains its bytes.
        Err(_) => Ok(quoted(raw)),
    }
}
fn quote(response: &Response) -> Result<Option<Vec<u8>>> {
    let limits = response.request.limits;
    match (limits.unit_price, limits.fee_cap, limits.fuel_limit) {
        (None, None, _) => Ok(None),
        (Some(price), Some(cap), Some(work)) => {
            if price <= 0 || work < 0 || cap < 0 {
                return Err(invalid_argument(b"invalid fee offer"));
            }
            let price = BigInt::from(price);
            let held = &price * BigInt::from(work);
            if held > BigInt::from(cap) {
                return Err(invalid_argument(b"fee cap exceeded"));
            }
            let used = response.certificate.steps;
            if used < 0 || used > work {
                return Err(invalid_argument(b"execution work exceeded"));
            }
            let charged = &price * BigInt::from(used);
            let refund = held - &charged;
            let mut out = Object::new();
            out.string(b"used", charged.to_string().as_bytes());
            out.string(b"unused", refund.to_string().as_bytes());
            Ok(Some(out.finish()))
        }
        _ => Err(invalid_argument(b"resource compute fee terms differ")),
    }
}

pub fn response_json(response: &Response) -> Result<Vec<u8>> {
    let mut out = Object::new();
    if let Some(quote) = quote(response)? {
        out.raw(b"quote", &quote);
    }
    out.raw(b"certificate", &certificate_json(&response.certificate));
    out.raw(b"output", &output_value(&response.output_json)?);
    out.string(b"output_json", &response.output_json);
    out.raw(b"request", &request_json(&response.request));
    out.raw(b"selection", &selection_json(&response.selection));
    out.string(b"status", b"finished");
    Ok(out.finish())
}

pub fn cancel_receipt_json(ack: &CancelAck) -> Result<Vec<u8>> {
    let mut out = Object::new();
    out.string(b"node_id", &ack.node_id);
    out.int64(b"epoch", ack.epoch);
    out.int(b"round", ack.delivery.round);
    out.base64(b"wire", &Message::CancelAck(ack.clone()).encode()?);
    Ok(out.finish())
}
fn receipts_json(receipts: &[CancelAck]) -> Result<Vec<u8>> {
    let encoded = receipts
        .iter()
        .map(cancel_receipt_json)
        .collect::<Result<Vec<_>>>()?;
    Ok(array(encoded))
}

pub(super) fn submitted(job_id: &[u8], node_id: &[u8]) -> Vec<u8> {
    let mut out = Object::new();
    out.string(b"job_id", job_id);
    out.string(b"node_id", node_id);
    out.string(b"status", b"waiting");
    out.finish()
}
pub(super) fn cancelled(cancelled: usize, receipts: &[CancelAck]) -> Result<Vec<u8>> {
    let mut out = Object::new();
    out.raw(b"cancelled_jobs", cancelled.to_string().as_bytes());
    out.string(b"scope", b"local");
    out.string(b"status", b"cancelled");
    out.string(b"receipt_scope", b"session_closed");
    out.raw(b"receipts", &receipts_json(receipts)?);
    Ok(out.finish())
}

/// `job_id` is the raw signed-read job hash, not a pre-encoded hex string.
/// Finished responses deliberately omit job_id, matching the native API.
pub fn status_json(job_id: &[u8], status: &JobStatus) -> Result<Vec<u8>> {
    let mut out = Object::new();
    if let JobStatus::Finished(response) = status {
        return response_json(response);
    }
    out.hash(b"job_id", job_id);
    match status {
        JobStatus::Waiting => out.string(b"status", b"waiting"),
        JobStatus::Funding(header) => {
            out.string(b"status", b"funding");
            out.base64(b"header", &header.encode()?);
            out.string(b"target", funding::escrow());
            match header.request().limits.fee_cap {
                None => out.raw(b"amount", b"null"),
                Some(amount) => out.int64(b"amount", amount),
            }
        }
        JobStatus::Refused(reason) => {
            out.string(b"reason", reason);
            out.string(b"status", b"refused");
        }
        JobStatus::Cancelled(value) => {
            let state: &[u8] = match value.expires {
                None => b"unavailable",
                Some(_) if !value.members.is_empty() && value.missing.is_empty() => b"complete",
                Some(_) => b"partial",
            };
            out.string(b"reason", b"resource compute session cancelled");
            out.string(b"status", b"refused");
            let mut cancellation = Object::new();
            cancellation.string(b"status", state);
            cancellation.string(b"scope", b"session_closed");
            cancellation.hash(b"selection_root", &value.selection_root);
            cancellation.raw(
                b"members",
                &array(value.members.iter().map(|member| quoted(member))),
            );
            cancellation.raw(
                b"missing",
                &array(value.missing.iter().map(|member| quoted(member))),
            );
            match value.expires {
                None => cancellation.raw(b"expires_epoch", b"null"),
                Some(epoch) => cancellation.int64(b"expires_epoch", epoch),
            }
            cancellation.raw(b"receipts", &receipts_json(&value.receipts)?);
            out.raw(b"cancellation", &cancellation.finish());
        }
        JobStatus::Finished(_) => unreachable!("finished response handled before job wrapper"),
    }
    Ok(out.finish())
}
