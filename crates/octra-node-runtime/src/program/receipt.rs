// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Receipt_view projections over byte-preserving VM values.
use super::{execute::Receipt, Error, Result};
use crate::octb::Event;
use num_bigint::BigInt;
use octra_node_protocol::transaction::{json_string, native_float};

pub fn revert(receipt: &Receipt, constructor: bool) -> Vec<u8> {
    let prefix: &[u8] = if constructor {
        b"constructor reverted"
    } else {
        b"execution reverted"
    };
    for event in &receipt.events {
        if event.name == b"Require" {
            if let Some(value) = event.values.first() {
                return [prefix, b" [", &value.text(), b"]"].concat();
            }
        }
    }
    receipt.error.clone().unwrap_or_else(|| prefix.to_vec())
}
fn optional(out: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(value) => json_string(out, value),
        None => out.extend_from_slice(b"null"),
    }
}
fn events(out: &mut Vec<u8>, values: &[Event], program: bool) {
    out.push(b'[');
    for (index, event) in values.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.push(b'{');
        if program {
            out.extend_from_slice(b"\"program\":");
            json_string(out, &event.contract);
            out.push(b',');
        }
        out.extend_from_slice(b"\"contract\":");
        json_string(out, &event.contract);
        out.extend_from_slice(format!(",\"depth\":{},\"event\":", event.depth).as_bytes());
        json_string(out, &event.name);
        out.extend_from_slice(b",\"values\":[");
        for (index, value) in event.values.iter().enumerate() {
            if index > 0 {
                out.push(b',');
            }
            json_string(out, &value.text());
        }
        out.extend_from_slice(b"]}");
    }
    out.push(b']');
}
fn tail(out: &mut Vec<u8>, error: Option<&[u8]>, epoch: i64, now: f64) -> Result<()> {
    out.extend_from_slice(b",\"error\":");
    optional(out, error);
    out.extend_from_slice(format!(",\"epoch\":{epoch},\"ts\":").as_bytes());
    out.extend_from_slice(native_float(now).map_err(Error::unavailable)?.as_bytes());
    out.push(b'}');
    Ok(())
}
pub fn direct(
    target: &[u8],
    method: &[u8],
    receipt: &Receipt,
    program: bool,
    epoch: i64,
    now: f64,
) -> Result<Vec<u8>> {
    let mut out = vec![b'{'];
    if program {
        out.extend_from_slice(b"\"program\":");
        json_string(&mut out, target);
        out.push(b',');
    }
    out.extend_from_slice(b"\"contract\":");
    json_string(&mut out, target);
    out.extend_from_slice(b",\"method\":");
    json_string(&mut out, method);
    out.extend_from_slice(
        format!(
            ",\"success\":{},\"effort\":{},\"events\":",
            receipt.success, receipt.effort
        )
        .as_bytes(),
    );
    events(&mut out, &receipt.events, program);
    tail(&mut out, receipt.error.as_deref(), epoch, now)?;
    Ok(out)
}
#[derive(Default)]
pub struct Trace {
    pub effort: i64,
    pub calls: Vec<Vec<u8>>,
    pub events: Vec<Event>,
}
impl Trace {
    pub fn add(
        &mut self,
        index: usize,
        target: &[u8],
        method: &[u8],
        amount: &BigInt,
        receipt: Receipt,
    ) -> Option<Vec<u8>> {
        let mut call = format!("{{\"index\":{index},\"program\":").into_bytes();
        json_string(&mut call, target);
        call.extend_from_slice(b",\"method\":");
        json_string(&mut call, method);
        call.extend_from_slice(b",\"amount\":");
        json_string(&mut call, amount.to_string().as_bytes());
        call.extend_from_slice(
            format!(
                ",\"success\":{},\"effort\":{},\"error\":",
                receipt.success, receipt.effort
            )
            .as_bytes(),
        );
        optional(&mut call, receipt.error.as_deref());
        call.extend_from_slice(b",\"return\":");
        let value = receipt
            .return_value
            .as_ref()
            .map(|value| value.text().into_owned());
        optional(&mut call, value.as_deref());
        call.push(b'}');
        self.calls.push(call);
        self.effort = self.effort.wrapping_add(receipt.effort).wrapping_shl(1) >> 1;
        let error = (!receipt.success).then(|| {
            [
                format!("call {index} failed: ").as_bytes(),
                &revert(&receipt, false),
            ]
            .concat()
        });
        self.events.extend(receipt.events);
        error
    }
    pub fn encode(&self, error: Option<&[u8]>, epoch: i64, now: f64) -> Result<Vec<u8>> {
        let mut out = format!("{{\"program\":\"multi_exec\",\"contract\":\"multi_exec\",\"method\":\"multi_exec\",\"success\":{},\"effort\":{},\"calls\":[", error.is_none(), self.effort).into_bytes();
        for (index, call) in self.calls.iter().enumerate() {
            if index > 0 {
                out.push(b',');
            }
            out.extend_from_slice(call);
        }
        out.extend_from_slice(b"],\"events\":");
        events(&mut out, &self.events, true);
        tail(&mut out, error, epoch, now)?;
        Ok(out)
    }
}
