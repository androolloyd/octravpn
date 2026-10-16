// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native Submit_rpc / Tx_view admission projections and Rest_view fee advice.
//! Queue mutation, account authentication and randomness belong to the host.
use crate::{
    native_integer::{parse_int63, parse_integer},
    native_json::{Document, Value},
    rpc::{self, Fault},
    transaction::{json_string, Nonce, OpType, Transaction},
    transaction_payload, transaction_policy,
};
use num_bigint::BigInt;

pub const MAX_ADMITS: usize = 100;

pub fn decode(doc: &Document, value: &Value) -> Result<Transaction, String> {
    let tx = Transaction::from_value(doc, value).map_err(|error| error.0)?;
    transaction_payload::admit(transaction_payload::Limits::default(), &tx)
        .map_err(|error| error.0)?;
    Ok(tx)
}
pub fn submit(doc: &Document, params: &Value) -> Result<Transaction, Fault> {
    let value =
        rpc::param(doc, params, 0).ok_or_else(|| Fault::invalid(b"missing transaction object"))?;
    decode(doc, value).map_err(|reason| refusal("malformed_transaction", &reason))
}
pub fn batch<'a>(doc: &'a Document, params: &Value) -> Result<&'a [usize], Fault> {
    match rpc::param(doc, params, 0) {
        None => Err(Fault::invalid(b"missing transactions array")),
        Some(Value::List(items)) if items.len() > MAX_ADMITS => Err(Fault::invalid(format!(
            "batch entries = {} limit = {MAX_ADMITS}",
            items.len()
        ))),
        Some(Value::List(items)) => Ok(items),
        _ => Err(Fault::invalid(b"expected array of transactions")),
    }
}
pub fn private_transfer(doc: &Document, params: &Value) -> Result<Transaction, Fault> {
    let Value::List(items) = params else {
        return Err(refusal("malformed_transaction", "expected [tx_json]"));
    };
    match items.first().and_then(|id| doc.get(*id)) {
        Some(value @ Value::Object(_)) => decode(doc, value),
        Some(Value::String(raw)) if items.len() == 1 => match Document::parse(raw) {
            Ok(inner) => decode(&inner, inner.root()),
            Err(_) => Err("Expected JSON object".into()),
        },
        _ => return Err(refusal("malformed_transaction", "expected [tx_json]")),
    }
    .map_err(|reason| refusal("malformed_transaction", &reason))
}
pub fn refusal(tag: &str, reason: &str) -> Fault {
    match tag {
        "sender_not_found" => Fault::new(100, b"sender not found"),
        "invalid_signature" => Fault::new(101, b"invalid signature"),
        "invalid_nonce" => Fault::new(102, b"invalid nonce"),
        "nonce_too_far" => Fault::new(103, b"nonce too far ahead"),
        "insufficient_balance" => Fault::new(104, b"insufficient balance"),
        "duplicate_transaction" => Fault::new(106, b"duplicate transaction").string_data(reason),
        "staging_full" => Fault::new(107, b"staging full"),
        "self_transfer" => Fault::new(108, b"self transfer"),
        "invalid_address" => Fault::new(109, b"invalid address").string_data(reason),
        "pre_verify_busy" | "pre_verify_unavailable" => {
            Fault::new(110, b"service unavailable").string_data(reason)
        }
        "fee_too_low" => Fault::new(113, b"fee too low").string_data(reason),
        "tx_too_large" => Fault::new(114, b"transaction too large").string_data(reason),
        "self_only_operation" => Fault::new(115, b"invalid operation target").string_data(reason),
        "unsupported_operation" => Fault::new(116, b"unsupported operation").string_data(reason),
        "read_only_observer" => Fault::new(117, b"read-only observer").string_data(reason),
        "preview_refused" => Fault::new(118, b"preview refused").string_data(reason),
        _ => Fault::new(105, b"malformed transaction").string_data(reason),
    }
}
pub fn accepted(hash: &[u8], tx: &Transaction, minimum: &BigInt) -> Vec<u8> {
    let mut out = b"{\"tx_hash\":".to_vec();
    json_string(&mut out, hash);
    out.extend_from_slice(
        format!(
            ",\"status\":\"accepted\",\"nonce\":{},\"ou_cost\":",
            tx.nonce.get()
        )
        .as_bytes(),
    );
    json_string(
        &mut out,
        transaction_policy::ou_cost(tx, minimum)
            .to_string()
            .as_bytes(),
    );
    out.push(b'}');
    out
}
pub fn batch_row(hash: Result<&[u8], &str>, nonce: Option<Nonce>) -> Vec<u8> {
    let mut out = Vec::new();
    match (hash, nonce) {
        (Ok(hash), Some(nonce)) => {
            out.extend_from_slice(b"{\"status\":\"accepted\",\"tx_hash\":");
            json_string(&mut out, hash);
            out.extend_from_slice(format!(",\"nonce\":{}}}", nonce.get()).as_bytes());
        }
        (Err(reason), nonce) => {
            out.extend_from_slice(if nonce.is_some() {
                b"{\"status\":\"rejected\",\"reason\":"
            } else {
                b"{\"status\":\"error\",\"reason\":"
            });
            json_string(&mut out, reason.as_bytes());
            if let Some(nonce) = nonce {
                out.extend_from_slice(format!(",\"nonce\":{}", nonce.get()).as_bytes());
            }
            out.push(b'}');
        }
        (Ok(_), None) => unreachable!("accepted native transaction has a nonce"),
    }
    out
}

#[derive(Clone, Debug)]
pub struct Fees {
    pub stealth_minimum: BigInt,
    jitter_min: i64,
    jitter_range: i64,
}
fn word(value: i64) -> i64 {
    value.wrapping_shl(1) >> 1
}
impl Default for Fees {
    fn default() -> Self {
        Self::capture(|_| None)
    }
}
impl Fees {
    /// Capture local settings, never values supplied by an RPC caller.
    pub fn capture(get: impl Fn(&str) -> Option<Vec<u8>>) -> Self {
        let integer = |key, default| get(key).as_deref().and_then(parse_int63).unwrap_or(default);
        let minimum = get("OCTRA_STEALTH_MIN_OU")
            .as_deref()
            .and_then(parse_integer)
            .filter(|value| *value > BigInt::from(0) && *value <= BigInt::from(10_000_000_000_u64))
            .unwrap_or_else(|| 5000.into());
        let min = integer("OCTRA_STEALTH_FEE_JITTER_MIN", 1);
        let max = integer("OCTRA_STEALTH_FEE_JITTER_MAX", 50_000);
        Self {
            stealth_minimum: minimum,
            jitter_min: min,
            jitter_range: word(word(max.wrapping_sub(min)).wrapping_add(1)).max(1),
        }
    }
    pub fn jitter(&self, mut pick: impl FnMut(i64) -> i64) -> i64 {
        word(self.jitter_min.wrapping_add(pick(self.jitter_range)))
    }
    pub fn response(
        &self,
        doc: &Document,
        params: &Value,
        staging_ou: &BigInt,
        staging_size: usize,
        jitter: impl FnMut(i64) -> i64,
    ) -> Vec<u8> {
        let op = match rpc::param(doc, params, 0) {
            Some(Value::String(raw)) => OpType::parse(raw).unwrap_or(OpType::Standard),
            _ => OpType::Standard,
        };
        let hint = match params {
            Value::List(items) if items.len() == 2 => {
                rpc::param(doc, params, 1).and_then(|value| {
                    let value = if matches!(value, Value::Object(_)) {
                        doc.field(value, b"asset_wire_bytes")
                            .or_else(|| doc.field(value, b"encrypted_data_len"))?
                    } else {
                        value
                    };
                    match value {
                        Value::Int(value) => Some(value.get()),
                        Value::IntLiteral(raw) | Value::String(raw) => parse_int63(raw),
                        _ => None,
                    }
                    .filter(|value| *value >= 0)
                })
            }
            _ => None,
        };
        let tx = Transaction {
            from: vec![],
            to: vec![],
            amount: 0.into(),
            nonce: Nonce::default(),
            ou: 0.into(),
            timestamp: 0.,
            signature: vec![],
            public_key: None,
            message: None,
            op_type: op,
            encrypted_data: None,
        };
        let base = match (op, hint) {
            (op, Some(wire)) if transaction_policy::is_asset_body(op) => {
                // The native machine-int arithmetic can wrap for advisory hints.
                let size = word(word(wire.wrapping_add(3)) / 4 * 3);
                let fee = match size {
                    ..=4096 => 5000,
                    4097..=16_384 => 10_000,
                    16_385..=32_768 => 20_000,
                    32_769..=131_072 => 40_000,
                    131_073..=524_288 => 80_000,
                    524_289..=2_097_152 => 160_000,
                    2_097_153..=8_388_608 => 320_000,
                    _ => 640_000,
                };
                BigInt::from(fee)
            }
            (OpType::ProgramDeploy, Some(wire)) => BigInt::from(word(
                200_000_i64.wrapping_add(
                    word(wire.wrapping_add(1023))
                        .wrapping_div(1024)
                        .wrapping_mul(1000),
                ),
            )),
            _ => transaction_policy::ou_cost(&tx, &self.stealth_minimum),
        };
        let usage: BigInt = staging_ou * 100 / BigInt::from(10_000_000_000_u64);
        let minimum: BigInt = &base
            * if usage < 80.into() {
                1
            } else if usage < 95.into() {
                2
            } else {
                5
            };
        let recommended: BigInt = &base
            * if usage < 50.into() {
                1
            } else if usage < 80.into() {
                2
            } else {
                5
            };
        let heavy = matches!(
            op,
            OpType::Stealth
                | OpType::Encrypt
                | OpType::Decrypt
                | OpType::Recrypt
                | OpType::KeySwitch
        );
        let recommended = if heavy {
            recommended.max(self.stealth_minimum.clone()) + self.jitter(jitter)
        } else {
            recommended
        };
        format!("{{\"minimum\":\"{minimum}\",\"base_fee\":\"{base}\",\"recommended\":\"{recommended}\",\"fast\":\"{}\",\"staging_size\":{staging_size},\"staging_ou\":\"{staging_ou}\",\"epoch_capacity\":\"10000000000\",\"usage_pct\":{usage},\"stealth_class\":{heavy}}}", &recommended * 2).into_bytes()
    }
}
