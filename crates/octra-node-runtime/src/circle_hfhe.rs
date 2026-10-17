// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native Circle HFHE callback policy over the Rust PVAC implementation.
pub(crate) mod preflight;
use crate::{
    circle::{Error, HfheBackend},
    private_crypto::{self, Error as CryptoError},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use num_traits::ToPrimitive;
use octra_hfhe::{
    cipher::Cipher,
    decrypt::{self, DecPolicy},
    encrypt,
    field::Fp,
    keys::{PublicKey, SecretKey},
    proof::{
        generators::pedersen_commit,
        zero::{self, BoundProfile, ZeroProof},
    },
    scalar::{Scalar, ScalarRule},
};
use octra_node_protocol::{native_base64, native_integer, state::MAX_SUPPLY};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Mutex;

/// As upstream, one nonblocking proof lane is shared by Circle executions.
static VERIFIER: Mutex<()> = Mutex::new(());
#[derive(Default)]
pub struct Backend;
type Result<T> = std::result::Result<T, Error>;
fn rejected(reason: impl Into<String>) -> Error {
    Error::Rejected(reason.into())
}
fn exception(_: impl std::fmt::Display) -> Error {
    Error::Unavailable("hfhe backend exception".into())
}
fn crypto(error: CryptoError) -> Error {
    match error {
        CryptoError::Rejected(raw) => rejected(String::from_utf8_lossy(&raw).into_owned()),
        CryptoError::Unavailable(e) => exception(e),
    }
}
fn string<'a>(input: &'a Value, name: &str) -> Result<&'a str> {
    input
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| rejected(format!("missing {name}")))
}
fn boolean(input: &Value, name: &str, default: Option<bool>) -> Result<bool> {
    match input.get(name) {
        None => default.ok_or_else(|| rejected(format!("missing {name}"))),
        Some(Value::Bool(v)) => Ok(*v),
        _ => Err(rejected(format!("invalid {name}"))),
    }
}
fn size(raw: &[u8], max: usize, label: &str) -> Result<()> {
    if raw.is_empty() || raw.len() > max {
        Err(rejected(format!("{label} exceeds resource policy")))
    } else {
        Ok(())
    }
}
fn blob(input: &Value, name: &str, encoded: usize, limit: usize) -> Result<Vec<u8>> {
    let value = string(input, name)?;
    size(value.as_bytes(), encoded, name)?;
    let raw =
        native_base64::decode(value.as_bytes()).map_err(|_| rejected(format!("invalid {name}")))?;
    size(&raw, limit, name)?;
    Ok(raw)
}
fn public(input: &Value) -> Result<PublicKey> {
    private_crypto::load_pubkey(&blob(input, "pubkey_b64", 7 * 1024 * 1024, 5_000_000)?)
        .map_err(crypto)
}
fn secret(input: &Value) -> Result<SecretKey> {
    let raw = zeroize::Zeroizing::new(blob(input, "seckey_b64", 2048, 1024)?);
    SecretKey::from_bytes(&raw).map_err(|e| {
        if e.is_operational() {
            exception(e)
        } else {
            rejected(format!("Failure({:?})", e.0))
        }
    })
}
fn int64(input: &Value, name: &str) -> Result<i64> {
    native_integer::parse_int64(string(input, name)?.as_bytes())
        .ok_or_else(|| rejected(format!("invalid {name}")))
}
fn bytes32(input: &Value, name: &str) -> Result<[u8; 32]> {
    let value = string(input, name)?;
    size(value.as_bytes(), 64, name)?;
    native_base64::decode(value.as_bytes())
        .map_err(|e| rejected(format!("Invalid_argument({:?})", e.to_string())))?
        .try_into()
        .map_err(|_| rejected(format!("{name} must decode to 32 bytes")))
}
fn cipher(raw: &str, cap: bool) -> Result<Cipher> {
    size(raw.as_bytes(), 1024 * 1024, "ciphertext")?;
    private_crypto::decode_cipher(raw.as_bytes(), false, cap).map_err(crypto)
}
// Preserve the native owned-input and typed diagnostic interface.
#[allow(clippy::needless_pass_by_value)]
fn encoded(cipher: Cipher) -> Result<Value> {
    let raw = private_crypto::encode_cipher(&cipher).map_err(crypto)?;
    Ok(Value::String(String::from_utf8(raw).map_err(exception)?))
}
fn proof_result(result: std::result::Result<bool, octra_hfhe::Error>) -> Result<bool> {
    match result {
        Ok(v) => Ok(v),
        Err(e) if e.is_operational() => Err(exception(e)),
        Err(_) => Ok(false),
    }
}
fn verifier_cipher(raw: &str, cap: bool) -> Result<Cipher> {
    if raw.is_empty() || raw.len() > 96 * 1024 {
        return Err(rejected("ciphertext exceeds verifier resource policy"));
    }
    let cipher = cipher(raw, cap)?;
    let shape = cipher.shape().map_err(exception)?;
    if shape.slots != 1
        || shape.constants != 1
        || !(1..=8).contains(&shape.layers)
        || shape.edges > 512
        || !(1..=2).contains(&shape.base_layers)
    {
        return Err(rejected("ciphertext exceeds verifier resource policy"));
    }
    Ok(cipher)
}
fn verify(input: &Value, public: &PublicKey, action: &str, cap: bool, math: bool) -> Result<Value> {
    let raw = string(input, "ciphertext")?;
    let proof = string(input, "proof")?;
    let bound = action != "verify_zero";
    let commitment = if bound {
        Some(string(input, "amount_commitment")?)
    } else {
        None
    };
    let strict = if bound {
        boolean(input, "strict", Some(false))?
    } else {
        false
    };
    let _lane = VERIFIER
        .try_lock()
        .map_err(|_| Error::Unavailable("hfhe verifier busy".into()))?;
    let run = || -> Result<bool> {
        let decoded = verifier_cipher(raw, cap)?;
        size(proof.as_bytes(), 64 * 1024, "proof")?;
        let proof = if action == "verify_range" {
            let raw = proof
                .strip_prefix("rp_v1|")
                .filter(|s| !s.is_empty())
                .ok_or_else(|| rejected("invalid range proof"))?;
            let raw = native_base64::decode(raw.as_bytes())
                .map_err(|_| rejected("invalid range proof"))?;
            ZeroProof::from_bound_range_bytes(&raw).map_err(|e| {
                if e.is_operational() {
                    exception(e)
                } else {
                    rejected("invalid range proof")
                }
            })?
        } else {
            private_crypto::decode_zero_proof(proof.as_bytes()).map_err(crypto)?
        };
        let commitment = commitment
            .map(|value| bytes32(&json!({"amount_commitment":value}), "amount_commitment"))
            .transpose()?;
        if !public.supports_alias_rejection() {
            return Ok(false);
        }
        // The worker receives canonical reserialization, then applies its own
        // strict/cap decoding. Preserve that second boundary from upstream.
        let raw = private_crypto::encode_cipher(&decoded).map_err(crypto)?;
        let decoded =
            private_crypto::decode_cipher(&raw, strict, if bound { strict } else { true })
                .map_err(crypto)?;
        let rule = if math {
            ScalarRule::Wide
        } else {
            ScalarRule::Prior
        };
        if let Some(commitment) = commitment {
            proof_result(zero::verify_bound(
                public,
                &decoded,
                &proof,
                &commitment,
                if action == "verify_range" {
                    BoundProfile::Range
                } else {
                    BoundProfile::Standard
                },
                strict,
                rule,
            ))
        } else {
            proof_result(zero::verify_zero(public, &decoded, &proof, rule))
        }
    };
    match run() {
        Ok(value) => Ok(Value::Bool(value)),
        Err(Error::Rejected(_)) => Ok(Value::Bool(false)),
        Err(e) => Err(e),
    }
}
fn run(input: &Value) -> Result<Value> {
    if !input.is_object() {
        return Err(rejected("invalid payload"));
    }
    let cap = boolean(input, "cap", None)?;
    let math = boolean(input, "math", Some(false))?;
    let pairs = boolean(input, "hfhe_pairs", Some(false))?;
    let action = string(input, "action")?;
    if action == "pedersen_commit" {
        let amount = int64(input, "amount")?;
        let blind = bytes32(input, "blinding_b64")?;
        if amount < 0 {
            return Err(exception("negative amount"));
        }
        return Ok(Value::String(STANDARD.encode(pedersen_commit(
            &Scalar::from_u64(amount as u64),
            &Scalar::from_bytes_raw(&blind),
        ))));
    }
    if !matches!(
        action,
        "encrypt_value_seeded"
            | "encrypt_zero_seeded"
            | "decrypt_value"
            | "cipher_add"
            | "cipher_sub"
            | "cipher_scale"
            | "cipher_add_const"
            | "cipher_sub_const"
            | "commit_cipher"
            | "bound_commitment"
            | "verify_zero"
            | "verify_range"
            | "verify_bound"
    ) {
        return Err(rejected(format!("unsupported action: {action}")));
    }
    let public = public(input)?;
    match action {
        "encrypt_value_seeded" | "encrypt_zero_seeded" => {
            let secret = secret(input)?;
            let amount = if action == "encrypt_value_seeded" {
                Some(int64(input, "amount")?)
            } else {
                None
            };
            let seed = bytes32(input, "seed_b64")?;
            let result = if let Some(amount) = amount {
                if amount < 0 {
                    return Err(exception("negative amount"));
                }
                encrypt::value_seeded(&public, &secret, amount as u64, &seed)
            } else {
                encrypt::zero_seeded(&public, &secret, &seed)
            };
            encoded(result.map_err(exception)?)
        }
        "decrypt_value" => {
            let secret = secret(input)?;
            let cipher = cipher(string(input, "ciphertext")?, cap)?;
            let value = decrypt::value(&public, &secret, &cipher, DecPolicy::Standard)
                .map_err(exception)?;
            Ok(Value::String(
                value
                    .to_i64()
                    .ok_or_else(|| exception("decrypted value out of int64 range"))?
                    .to_string(),
            ))
        }
        "cipher_add" | "cipher_sub" => {
            let left = string(input, "lhs_ciphertext")?;
            let right = string(input, "rhs_ciphertext")?;
            let left = cipher(left, cap)?;
            let right = cipher(right, cap)?;
            if pairs && left.slots() != right.slots() {
                return Err(rejected("hfhe slot count mismatch"));
            }
            if pairs && (!left.compatible_with(&public) || !right.compatible_with(&public)) {
                return Err(rejected("hfhe key shape mismatch"));
            }
            encoded(
                if action == "cipher_add" {
                    left.add(&public, &right)
                } else {
                    left.subtract(&public, &right)
                }
                .map_err(exception)?,
            )
        }
        "cipher_scale" | "cipher_add_const" | "cipher_sub_const" => {
            let raw = string(input, "ciphertext")?;
            let amount = int64(
                input,
                if action == "cipher_scale" {
                    "factor"
                } else {
                    "amount"
                },
            )?;
            let cipher = cipher(raw, cap)?;
            match action {
                "cipher_scale" => encoded(if math {
                    cipher.mul_constant_i64(amount)
                } else {
                    cipher.mul_constant_u64(amount as u64)
                }),
                "cipher_add_const" => {
                    let field = if math && amount < 0 {
                        Fp::from_words(amount.wrapping_sub(1) as u64, i64::MAX as u64)
                    } else {
                        Fp::from_words(amount as u64, 0)
                    };
                    encoded(cipher.add_constant(field, math).map_err(exception)?)
                }
                _ => encoded(
                    if math && amount < 0 {
                        cipher.add_constant(Fp::from_words(amount.wrapping_neg() as u64, 0), math)
                    } else {
                        cipher.subtract_constant(Fp::from_words(amount as u64, 0), math)
                    }
                    .map_err(exception)?,
                ),
            }
        }
        "commit_cipher" | "bound_commitment" => {
            let raw = string(input, "ciphertext")?;
            let amount = if action == "bound_commitment" {
                let value = native_integer::parse_integer(string(input, "amount")?.as_bytes())
                    .filter(|v| v >= &0.into() && v <= &MAX_SUPPLY.into())
                    .ok_or_else(|| rejected("invalid amount"))?;
                Some(
                    value
                        .to_i64()
                        .ok_or_else(|| exception("amount out of int64 range"))?,
                )
            } else {
                None
            };
            size(raw.as_bytes(), 1024 * 1024, "ciphertext")?;
            let cipher = match cipher(raw, cap) {
                Ok(v) => v,
                Err(Error::Rejected(_)) => {
                    return Err(rejected(if amount.is_some() {
                        "bound commitment failed"
                    } else {
                        "commit failed"
                    }))
                }
                Err(e) => return Err(e),
            };
            let commitment = cipher.commitment(&public);
            let commitment = if let Some(amount) = amount {
                Sha256::digest([commitment.as_slice(), &amount.to_le_bytes()].concat()).to_vec()
            } else {
                commitment.to_vec()
            };
            Ok(Value::String(STANDARD.encode(commitment)))
        }
        _ => verify(input, &public, action, cap, math),
    }
}
pub(crate) fn local(input: &Value) -> Value {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let raw = zeroize::Zeroizing::new(serde_json::to_vec(input).map_err(exception)?);
        if raw.is_empty() || raw.len() > 16 * 1024 * 1024 {
            return Err(rejected("hfhe request exceeds resource policy"));
        }
        run(input)
    }))
    .unwrap_or_else(|_| Err(exception("backend panic")));
    match result {
        Ok(value) => json!({"ok":true,"value":value}),
        Err(Error::Rejected(reason)) => json!({"ok":false,"class":"rejected","error":reason}),
        Err(Error::Unavailable(reason)) => {
            json!({"ok":false,"class":"unavailable","error":reason})
        }
    }
}
/// Explicit in-process compatibility backend. Production node execution uses
/// `isolated` and a host-owned invocation scope; this local adapter alone does
/// not supply native cancellation, deadlines or RSS containment.
impl HfheBackend for Backend {
    fn call(&self, input: &Value) -> Result<Value> {
        Ok(local(input))
    }
}
pub struct Isolated {
    pool: std::sync::Arc<crate::crypto_worker::Pool>,
}
impl Backend {
    pub fn isolated(pool: std::sync::Arc<crate::crypto_worker::Pool>) -> Isolated {
        Isolated { pool }
    }
}
impl HfheBackend for Isolated {
    fn call(&self, input: &Value) -> Result<Value> {
        // Keep the native callback error envelope; operational failure must not
        // become a deterministic false proof or successful empty key result.
        match crate::crypto_worker::circle(&self.pool, input) {
            Ok(value) => Ok(value),
            Err(reason) => Ok(json!({"ok":false,"class":"unavailable","error":reason})),
        }
    }
}
