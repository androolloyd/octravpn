// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native Circle deployment payloads and deterministic deployment addresses.
use crate::{
    circles::domain_hash,
    native_integer::parse_int64,
    native_json::{Document, Value},
    transaction::{json_string, Nonce},
};

pub const LIMIT_NAMES: [&[u8]; 4] = [
    b"max_stable_bytes",
    b"max_assets_bytes",
    b"max_inline_value",
    b"max_wasm_bytes",
];
pub const DEFAULT_LIMITS: [i64; 4] = [33_554_432, 33_554_432, 65_536, 33_554_432];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub tag: &'static str,
    pub reason: Vec<u8>,
}
impl Refusal {
    pub fn new(tag: &'static str, reason: impl Into<Vec<u8>>) -> Self {
        Self {
            tag,
            reason: reason.into(),
        }
    }
}
fn malformed(reason: impl Into<Vec<u8>>) -> Refusal {
    Refusal::new("malformed_transaction", reason)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deploy {
    pub runtime: Vec<u8>,
    pub privacy: Vec<u8>,
    pub browser: Vec<u8>,
    pub resource: Vec<u8>,
    pub code: Option<Vec<u8>>,
    pub policy_hash: Option<Vec<u8>>,
    pub members_root: Option<Vec<u8>>,
    pub export_policy: Option<Vec<u8>>,
    pub limits: [i64; 4],
}
fn limits(doc: &Document, value: &Value) -> Result<[i64; 4], Refusal> {
    if !matches!(value, Value::Object(_)) {
        return Err(malformed(b"limits must be a json object"));
    }
    let mut parsed: [Result<i64, Refusal>; 4] = std::array::from_fn(|_| Ok(0));
    // Native tuple evaluation raises integer exceptions before matching its
    // ordinary missing-field errors, including errors in a preceding field.
    for index in (0..4).rev() {
        let key = LIMIT_NAMES[index];
        parsed[index] = match doc.field(value, key) {
            Some(Value::String(raw)) => Ok(parse_int64(raw).ok_or_else(|| {
                Refusal::new(
                    "malformed_transaction_exception",
                    b"Failure(\"Int64.of_string\")",
                )
            })?),
            _ => Err(malformed(
                [b"missing limits field: ".as_slice(), key].concat(),
            )),
        };
    }
    let [a, b, c, d] = parsed;
    Ok([a?, b?, c?, d?])
}
fn known(value: &[u8], allowed: &[&[u8]], label: &[u8]) -> Result<(), Refusal> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(malformed(
            [b"unknown ".as_slice(), label, b": ", value].concat(),
        ))
    }
}
impl Deploy {
    pub fn from_document(doc: &Document) -> Result<Self, Refusal> {
        let root = doc.root();
        if !matches!(root, Value::Object(_)) {
            return Err(malformed(b"deploy payload must be a json object"));
        }
        let required = |key: &[u8]| match doc.field(root, key) {
            Some(Value::String(raw)) => Ok(raw.clone()),
            _ => Err(malformed(
                [b"missing deploy payload field: ".as_slice(), key].concat(),
            )),
        };
        let optional = |key: &[u8]| match doc.field(root, key) {
            Some(Value::String(raw)) => Ok(Some(raw.clone())),
            None | Some(Value::Null) => Ok(None),
            _ => Err(malformed(
                [b"invalid deploy payload field: ".as_slice(), key].concat(),
            )),
        };
        let runtime = required(b"runtime")?;
        let privacy = required(b"privacy_class")?;
        let browser = required(b"browser_mode")?;
        let resource = required(b"resource_mode")?;
        let code = optional(b"code_b64")?;
        let policy_hash = optional(b"policy_hash")?;
        let members_root = optional(b"members_root")?;
        let export_policy = optional(b"export_policy")?;
        let raw = doc
            .field(root, b"limits")
            .ok_or_else(|| malformed(b"missing deploy payload field: limits"))?;
        let parsed = limits(doc, raw);
        if let Err(error) = &parsed {
            if error.tag == "malformed_transaction_exception" {
                return Err(error.clone());
            }
        }
        known(&runtime, &[b"octb", b"wasm_v1"], b"runtime")?;
        known(
            &privacy,
            &[b"public", b"scoped", b"sealed", b"circle"],
            b"privacy class",
        )?;
        known(
            &browser,
            &[b"gateway_allowed", b"native_sealed"],
            b"browser mode",
        )?;
        known(
            &resource,
            &[b"public_resources", b"sealed_read"],
            b"resource mode",
        )?;
        Ok(Self {
            runtime,
            privacy,
            browser,
            resource,
            code,
            policy_hash,
            members_root,
            export_policy,
            limits: parsed?,
        })
    }

    pub fn validate_limits(&self) -> Result<(), Refusal> {
        for ((name, value), cap) in LIMIT_NAMES.iter().zip(self.limits).zip(DEFAULT_LIMITS) {
            if value < 0 || value > cap {
                return Err(Refusal::new(
                    "circle_limits_invalid",
                    [b"circle limit out of range: ".as_slice(), name].concat(),
                ));
            }
        }
        if self.limits[2] > self.limits[0] {
            return Err(Refusal::new(
                "circle_limits_invalid",
                b"circle max_inline_value exceeds max_stable_bytes",
            ));
        }
        Ok(())
    }

    pub fn canonical(&self) -> Vec<u8> {
        let mut out = vec![b'{'];
        for (index, (name, value)) in [
            (b"runtime".as_slice(), Some(self.runtime.as_slice())),
            (b"privacy_class", Some(self.privacy.as_slice())),
            (b"browser_mode", Some(self.browser.as_slice())),
            (b"resource_mode", Some(self.resource.as_slice())),
            (b"code_b64", self.code.as_deref()),
            (b"policy_hash", self.policy_hash.as_deref()),
            (b"members_root", self.members_root.as_deref()),
            (b"export_policy", self.export_policy.as_deref()),
        ]
        .into_iter()
        .enumerate()
        {
            if index > 0 {
                out.push(b',');
            }
            json_string(&mut out, name);
            out.push(b':');
            if let Some(value) = value {
                json_string(&mut out, value);
            } else {
                out.extend_from_slice(b"null");
            }
        }
        out.extend_from_slice(b",\"limits\":{");
        for (index, (name, value)) in LIMIT_NAMES.iter().zip(self.limits).enumerate() {
            if index > 0 {
                out.push(b',');
            }
            json_string(&mut out, name);
            out.push(b':');
            json_string(&mut out, value.to_string().as_bytes());
        }
        out.extend_from_slice(b"}}");
        out
    }

    pub fn id(&self, deployer: &[u8], nonce: Nonce) -> Vec<u8> {
        let payload = domain_hash(b"octra:circle_deploy_payload:v1", &[&self.canonical()]);
        let seed = domain_hash(
            b"octra:circle_deploy_id:v1",
            &[deployer, &nonce.get().to_be_bytes(), payload.as_bytes()],
        );
        address(&seed)
    }
}

fn address(seed: &str) -> Vec<u8> {
    let body = bs58::encode(hex::decode(seed).expect("SHA-256 hex")).into_string();
    let mut address = b"oct".to_vec();
    address.extend(body.as_bytes().iter().copied().cycle().take(44));
    address
}

pub fn spawn_id(
    parent: &[u8],
    caller: &[u8],
    tx_hash: &[u8],
    nonce: i64,
    owner: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    address(&domain_hash(
        b"octra:circle_spawn_id:v1",
        &[
            parent,
            caller,
            tx_hash,
            &nonce.to_be_bytes(),
            owner,
            payload,
        ],
    ))
}

pub fn update_code(doc: &Document) -> Result<Vec<u8>, Refusal> {
    if !matches!(doc.root(), Value::Object(_)) {
        return Err(malformed(b"program update payload must be a json object"));
    }
    match doc.field(doc.root(), b"code_b64") {
        Some(Value::String(raw)) if !raw.is_empty() => Ok(raw.clone()),
        Some(Value::String(_)) => Err(malformed(b"invalid program update payload field: code_b64")),
        _ => Err(malformed(b"missing program update payload field: code_b64")),
    }
}
