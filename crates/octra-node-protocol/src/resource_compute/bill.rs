// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Measured work and verified bills. The host must anchor the supplied validator
//! set and input roots before accepting these local verification results.
use super::{
    call::{self, Header},
    certificate::{self, Decision},
    request::Request,
    Error, Result,
};
use crate::{
    consensus::{hash::validator_set_hash, ValidatorSet},
    network::verify_ed25519,
    transaction::{address_from_public_key, is_valid_address},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigInt;
use num_traits::Zero;
mod message;
pub use message::{decode_request, encode_request, fee, PaymentRequest};
pub const MAX_WIRE: usize = 262_144;
pub const MAX_FUEL: i64 = 5_000_000;
pub const MODEL_LIMIT: i64 = 67_108_864;
pub const CONSENSUS_ID: &[u8] = b"signed_reserve_8192:fund_10000:return_1000:signed_pay_expiry:payer:nonce:settle_separate:pay_wire_262144:fuel_5000000:model_67108864:io_16:base_10000:wire_2:state_inputs_65:pin_16:entry_32:fund_lane:paid_refusal:session_replay:paid_epoch:paid_root:record_set:charged_receipt:graph_json";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Complete,
    Stopped(i64),
    Exhausted,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Measured {
    request_id: Vec<u8>,
    output_hash: Vec<u8>,
    output_bytes: i64,
    trace_root: Vec<u8>,
    steps: i64,
    operations: i64,
    outcome: Outcome,
}
impl Measured {
    pub fn request_id(&self) -> &[u8] {
        &self.request_id
    }
    pub fn output_hash(&self) -> &[u8] {
        &self.output_hash
    }
    pub fn output_bytes(&self) -> i64 {
        self.output_bytes
    }
    pub fn trace_root(&self) -> &[u8] {
        &self.trace_root
    }
    pub fn steps(&self) -> i64 {
        self.steps
    }
    pub fn operations(&self) -> i64 {
        self.operations
    }
    pub fn outcome(&self) -> Outcome {
        self.outcome
    }
}
pub fn measure(
    request: &Request,
    output: &[u8],
    trace_root: &[u8],
    steps: i64,
    operations: i64,
    outcome: Outcome,
) -> Result<Measured> {
    let fail = |reason: &[u8]| Error::rejected(reason);
    if !request.shape() {
        return Err(fail(b"compute bill request refused"));
    }
    if output.is_empty() || output.len() as u64 > request.max_output_bytes as u64 {
        return Err(fail(b"compute bill output size refused"));
    }
    if trace_root.len() != 32 || steps <= 0 || operations <= 0 {
        return Err(fail(b"compute bill work refused"));
    }
    if request.limits.fuel_limit.is_none_or(|fuel| steps > fuel) {
        return Err(fail(b"compute bill work exceeds fuel"));
    }
    if matches!(outcome, Outcome::Stopped(code) if code <= 0 || code > i64::from(i32::MAX)) {
        return Err(fail(b"compute bill stop code refused"));
    }
    let stop_output = match outcome {
        Outcome::Complete => None,
        Outcome::Exhausted => Some(b"{\"compute_stop\":\"fuel\"}".to_vec()),
        Outcome::Stopped(code) => Some(format!("{{\"compute_stop\":{code}}}").into_bytes()),
    };
    if stop_output
        .as_ref()
        .is_some_and(|expected| expected != output)
    {
        return Err(fail(b"compute bill stop output differs"));
    }
    Ok(Measured {
        request_id: request.id()?.to_vec(),
        output_hash: call::output_hash(output)?.to_vec(),
        output_bytes: output.len() as i64,
        trace_root: trace_root.to_vec(),
        steps,
        operations,
        outcome,
    })
}
pub fn resource_limits(fuel: Option<i64>, memory: Option<i64>, guest: Option<i64>) -> Result<()> {
    match (fuel, memory, guest) {
        (Some(fuel), Some(memory), Some(guest))
            if (1..=MAX_FUEL).contains(&fuel)
                && memory > 0
                && memory <= MODEL_LIMIT
                && guest > 0
                && guest <= memory =>
        {
            Ok(())
        }
        _ => Err(Error::rejected(b"compute payment resource limits")),
    }
}
pub fn resources(request: &Request) -> Result<()> {
    resource_limits(
        request.limits.fuel_limit,
        request.limits.memory_bytes,
        request.limits.guest_bytes,
    )
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bill {
    header: Header,
    measured: Measured,
    root: Vec<u8>,
    charged: BigInt,
    refund: BigInt,
    payments: Vec<(Vec<u8>, BigInt)>,
}
impl Bill {
    pub fn header(&self) -> &Header {
        &self.header
    }
    pub fn measured(&self) -> &Measured {
        &self.measured
    }
    pub fn root(&self) -> &[u8] {
        &self.root
    }
    pub fn charged(&self) -> &BigInt {
        &self.charged
    }
    pub fn refund(&self) -> &BigInt {
        &self.refund
    }
    pub fn payments(&self) -> &[(Vec<u8>, BigInt)] {
        &self.payments
    }
}
pub fn verify(
    epoch: i64,
    header: &Header,
    validators: &ValidatorSet,
    selected: &[Vec<u8>],
    votes: &[certificate::Vote],
    measured: &Measured,
) -> Result<Bill> {
    let request = header.request();
    let total = selected
        .iter()
        .map(|node| validators.weight(node).cloned().unwrap_or_default())
        .sum::<BigInt>();
    let validator_root =
        validator_set_hash(validators).map_err(|error| Error::Unavailable(error.into_bytes()))?;
    if request.validator_set_root.as_slice() != validator_root.as_slice() {
        return Err(Error::rejected(b"compute bill validator set differs"));
    }
    if measured.request_id.as_slice() != request.id()?.as_slice() {
        return Err(Error::rejected(b"compute bill request differs"));
    }
    if request.caller
        != address_from_public_key(STANDARD.encode(header.caller_public_key()).as_bytes())
        || !verify_ed25519(
            header.caller_public_key(),
            &header.intent()?,
            header.caller_signature(),
        )
    {
        return Err(Error::rejected(b"compute bill caller signature refused"));
    }
    let coordinator = match validators.public_key(header.coordinator()) {
        Some(public) => verify_ed25519(public, &header.sign_bytes()?, header.signature()),
        None => false,
    };
    if !coordinator {
        return Err(Error::rejected(
            b"compute bill coordinator signature refused",
        ));
    }
    let weight_floor = (total * 2) / 3 + 1;
    let decision = certificate::decide(
        &certificate::Policy {
            chain_id: &request.chain_id,
            current_epoch: epoch,
            max_ttl: call::CALL_TTL,
            selected,
            signer_floor: selected.len() as i64 * 2 / 3 + 1,
            weight_floor: &weight_floor,
        },
        request,
        votes,
        |node| validators.weight(node).cloned(),
        |vote| {
            validators.public_key(&vote.node_id).is_some_and(|public| {
                vote.sign_bytes()
                    .is_ok_and(|bytes| verify_ed25519(public, &bytes, &vote.signature))
            })
        },
    )?;
    let certificate = match decision {
        Decision::Rejected(_) => return Err(Error::rejected(b"compute bill certificate refused")),
        Decision::Insufficient => {
            return Err(Error::rejected(b"compute bill certificate missing votes"))
        }
        Decision::Conflicting => {
            return Err(Error::rejected(b"compute bill certificate conflicts"))
        }
        Decision::Agreed(certificate) => certificate,
    };
    if certificate.output_hash != measured.output_hash
        || certificate.output_bytes != measured.output_bytes
        || certificate.trace_root != measured.trace_root
        || certificate.steps != measured.steps
        || certificate.operations != measured.operations
    {
        return Err(Error::rejected(b"compute bill execution differs"));
    }
    let (price, cap) = match (
        request.limits.unit_price,
        request.limits.fee_cap,
        request.limits.fuel_limit,
    ) {
        (Some(price), Some(cap), Some(fuel)) if price > 0 && cap > 0 && measured.steps <= fuel => {
            (price, cap)
        }
        _ => return Err(Error::rejected(b"compute bill terms missing")),
    };
    let charged = BigInt::from(price) * BigInt::from(measured.steps);
    let refund = BigInt::from(cap) - &charged;
    if refund < BigInt::zero() {
        return Err(Error::rejected(b"compute bill exceeds cap"));
    }
    let nodes = certificate
        .signers
        .iter()
        .map(|signer| signer.node_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    if nodes.iter().any(|node| !is_valid_address(node)) {
        return Err(Error::rejected(b"compute bill payee refused"));
    }
    let count = BigInt::from(nodes.len());
    let share = &charged / &count;
    let remainder = &charged % &count;
    let payments = nodes
        .into_iter()
        .enumerate()
        .map(|(index, node)| {
            (
                node,
                if BigInt::from(index) < remainder {
                    &share + 1
                } else {
                    share.clone()
                },
            )
        })
        .collect();
    Ok(Bill {
        header: header.clone(),
        measured: measured.clone(),
        root: certificate.root,
        charged,
        refund,
        payments,
    })
}
