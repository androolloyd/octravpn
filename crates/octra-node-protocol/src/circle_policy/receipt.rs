// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! HFHE receipts bind a signature to one policy, caller, key, ciphertext and
//! amount commitment. Canonical hashes sort byte-string field names.
use super::hfhe::{Policy, Receipt};
use crate::{
    native_json::{Document, Value},
    network,
    transaction::{address_from_public_key, decode_base64, json_string},
};
use sha2::{Digest, Sha256};
type Result<T> = std::result::Result<T, Vec<u8>>;
pub const CONTEXT_NAMES: [&[u8]; 9] = [
    b"verb",
    b"proof_kind",
    b"circle_id",
    b"caller_addr",
    b"key_id",
    b"intent_id",
    b"policy_hash",
    b"ciphertext_hash",
    b"amount_commitment_hash",
];
const EXACT_FIELDS: [&[u8]; 13] = [
    b"amount_commitment_hash",
    b"caller_addr",
    b"ciphertext_hash",
    b"circle_id",
    b"intent_id",
    b"key_id",
    b"policy_hash",
    b"proof_kind",
    b"signature",
    b"signer_addr",
    b"signer_pubkey",
    b"verb",
    b"version",
];
pub struct Context<'a> {
    pub circle: &'a [u8],
    pub caller: &'a [u8],
    pub key: &'a [u8],
    pub intent: &'a [u8],
    pub verb: &'a [u8],
    pub proof: &'a [u8],
    pub policy: &'a [u8],
    pub ciphertext: &'a [u8],
    pub amount: &'a [u8],
}
impl Context<'_> {
    pub fn fields(&self) -> [&[u8]; 9] {
        [
            self.verb,
            self.proof,
            self.circle,
            self.caller,
            self.key,
            self.intent,
            self.policy,
            self.ciphertext,
            self.amount,
        ]
    }
}
pub fn sha256(raw: &[u8]) -> Vec<u8> {
    hex::encode(Sha256::digest(raw)).into_bytes()
}
pub fn hash_commitment(encoded: &[u8]) -> Result<Vec<u8>> {
    decode_base64(encoded)
        .ok()
        .filter(|raw| raw.len() == 32)
        .map(|raw| sha256(&raw))
        .ok_or_else(|| b"amount commitment is invalid".to_vec())
}
pub fn frame(domain: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut out = domain.to_vec();
    for field in fields {
        out.push(b'|');
        out.extend_from_slice(field.len().to_string().as_bytes());
        out.push(b':');
        out.extend_from_slice(field);
    }
    out
}
pub fn transport_required(policy: &Policy, proof: super::hfhe::Proof) -> bool {
    proof.receipt_required()
        && (policy.require_transport_binding
            || policy.receipt != Receipt::Detached
            || policy.modes[11].relay_scoped())
}
pub fn verify(
    doc: &Document,
    value: &Value,
    context: &Context<'_>,
    policy: &Policy,
    owner: &[u8],
    relays: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let Value::Object(fields) = value else {
        return Err(b"proof receipt must be an object".to_vec());
    };
    let mut names: Vec<_> = fields.iter().map(|(name, _)| name.as_slice()).collect();
    names.sort_unstable();
    if names.as_slice() != EXACT_FIELDS {
        return Err(b"proof receipt fields are invalid".to_vec());
    }
    let string = |name: &[u8]| -> Result<&[u8]> {
        match doc.field(value, name) {
            Some(Value::String(raw)) => Ok(raw),
            Some(_) => Err([name, b" must be a string"].concat()),
            None => Err([name, b" is required"].concat()),
        }
    };
    let version = string(b"version")?;
    let values = CONTEXT_NAMES
        .iter()
        .map(|name| string(name))
        .collect::<Result<Vec<_>>>()?;
    let signer = string(b"signer_addr")?;
    let encoded_public = string(b"signer_pubkey")?;
    let encoded_signature = string(b"signature")?;
    if values.as_slice() != context.fields() {
        return Err(b"proof receipt context mismatch".to_vec());
    }
    if !policy.modes[11].allows(owner, signer, context.caller, relays) {
        return Err(b"proof receipt signer is not allowed by policy".to_vec());
    }
    let class_allowed = match policy.receipt {
        Receipt::Detached => !policy.require_transport_binding || !relays.is_empty(),
        Receipt::TransportBound => !relays.is_empty(),
        Receipt::RelayWitnessed => relays.iter().any(|id| id == signer),
    };
    if !class_allowed {
        return Err(b"proof receipt transport binding is invalid".to_vec());
    }
    if address_from_public_key(encoded_public) != signer {
        return Err(b"proof receipt signer binding invalid".to_vec());
    }
    let pair = decode_base64(encoded_public)
        .ok()
        .zip(decode_base64(encoded_signature).ok());
    let Some((public, signature)) = pair
        .filter(|(key, sig)| key.len() == 32 && sig.len() == 64 && network::public_key_safe(key))
    else {
        return Err(b"proof receipt signature encoding invalid".to_vec());
    };
    let subject = match version {
        b"octra_circle_hfhe_receipt_v1" => {
            if values.iter().any(|raw| raw.contains(&b'|')) {
                return Err(b"legacy proof receipt context is ambiguous".to_vec());
            }
            let mut parts = vec![b"octra_circle_hfhe_receipt_v1".as_slice()];
            parts.extend(values);
            parts.join(&b'|')
        }
        b"octra_circle_hfhe_receipt_v2" => frame(b"octra_circle_hfhe_receipt_v2", &values),
        _ => return Err(b"invalid proof receipt version".to_vec()),
    };
    if !network::verify_ed25519(&public, &subject, &signature) {
        return Err(b"proof receipt signature verification failed".to_vec());
    }
    let mut canonical = vec![b'{'];
    for (index, name) in names.iter().enumerate() {
        if index != 0 {
            canonical.push(b',');
        }
        json_string(&mut canonical, name);
        canonical.push(b':');
        json_string(&mut canonical, string(name)?);
    }
    canonical.push(b'}');
    Ok(sha256(&canonical))
}
