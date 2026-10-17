// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native FheBalance encoding, recovery limits and proof checks. Resource
//! failures stay operational; they must never certify an invalid transaction.
use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use octra_hfhe::{
    cipher::Cipher,
    keys::PublicKey,
    proof::{
        generators::pedersen_commit,
        zero::{self, BoundProfile, ZeroProof},
    },
    scalar::{Scalar, ScalarRule},
};
use octra_node_protocol::transaction::decode_base64;
pub mod isolated;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("private input rejected: {0:?}")]
    Rejected(Vec<u8>),
    #[error("private cryptography unavailable: {0}")]
    Unavailable(#[source] octra_hfhe::Error),
}
impl Error {
    pub(crate) fn rejected(reason: impl AsRef<[u8]>) -> Self {
        Self::Rejected(reason.as_ref().to_vec())
    }
    pub(crate) fn prefix(self, prefix: &[u8]) -> Self {
        match self {
            Self::Rejected(reason) => Self::Rejected([prefix, &reason].concat()),
            other @ Self::Unavailable(_) => other,
        }
    }
}
fn native<T>(result: Result<T, octra_hfhe::Error>) -> Result<T, Error> {
    result.map_err(|error| {
        if error.is_operational() {
            Error::Unavailable(error)
        } else {
            Error::rejected(format!("Failure({:?})", error.0))
        }
    })
}
fn base64(raw: &[u8]) -> Result<Vec<u8>, Error> {
    decode_base64(raw)
        .map_err(|error| Error::rejected(format!("Invalid_argument({:?})", error.to_string())))
}
fn encoded(prefix: &[u8], raw: &[u8]) -> Vec<u8> {
    [prefix, STANDARD.encode(raw).as_bytes()].concat()
}
pub fn decode_cipher(raw: &[u8], strict: bool, cap: bool) -> Result<Cipher, Error> {
    let value = raw
        .strip_prefix(b"hfhe_v1|")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| Error::rejected("not FHE cipher"))?;
    native(Cipher::from_bytes_with_policy(&base64(value)?, strict, cap))
}
pub fn encode_cipher(cipher: &Cipher) -> Result<Vec<u8>, Error> {
    Ok(encoded(
        b"hfhe_v1|",
        &cipher.to_bytes().map_err(Error::Unavailable)?,
    ))
}
pub fn load_pubkey(raw: &[u8]) -> Result<PublicKey, Error> {
    native(PublicKey::from_bytes(raw)).map_err(|e| e.prefix(b"load_pubkey failed: "))
}
pub fn proof_pubkey(raw: &[u8]) -> Result<PublicKey, Error> {
    let public = load_pubkey(raw)?;
    if !public.supports_alias_rejection() {
        return Err(Error::rejected(
            "pvac pubkey proof circuit lacks alias rejection",
        ));
    }
    Ok(public)
}
pub fn decode_zero_proof(raw: &[u8]) -> Result<ZeroProof, Error> {
    let value = raw
        .strip_prefix(b"zkzp_v2|")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| Error::rejected("not a zero proof"))?;
    let bytes = base64(value)?;
    if bytes.len() < 50 {
        return Err(Error::rejected("zero proof too small to be valid"));
    }
    native(ZeroProof::from_raw_bytes(&bytes))
}
pub fn base_layers(raw: &[u8], cap: bool) -> Result<usize, Error> {
    if raw.is_empty() || raw == b"0" {
        return Ok(0);
    }
    native(decode_cipher(raw, false, cap)?.base_layers())
}
pub fn check_private_input(raw: &[u8], cap: bool) -> Result<(), Error> {
    let layers = base_layers(raw, cap)?;
    if layers > 6 {
        return Err(Error::rejected(format!(
            "encrypted balance compact refresh required ({layers} base layers)"
        )));
    }
    Ok(())
}
pub fn check_refresh_source(raw: &[u8], cap: bool) -> Result<(), Error> {
    if base_layers(raw, cap)? > 8 {
        return Err(Error::rejected(
            "encrypted balance refresh source exceeds 8 base layers",
        ));
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultPolicy {
    Legacy,
    Recoverable,
}
fn private_result(cipher: &Cipher, policy: ResultPolicy) -> Result<Vec<u8>, Error> {
    if policy == ResultPolicy::Recoverable {
        let layers = native(cipher.base_layers())
            .map_err(|e| e.prefix(b"encrypted balance result shape failed: "))?;
        if layers > 6 {
            return Err(Error::rejected(format!(
                "encrypted balance result exceeds recoverable limit ({layers} base layers)"
            )));
        }
    }
    match policy {
        ResultPolicy::Legacy => encode_cipher(cipher),
        ResultPolicy::Recoverable => native(cipher.to_bytes())
            .map(|raw| encoded(b"hfhe_v1|", &raw))
            .map_err(|e| e.prefix(b"encrypted balance result shape failed: ")),
    }
}
pub fn balance(
    public: &PublicKey,
    current: &[u8],
    delta: &Cipher,
    withdraw: bool,
    cap: bool,
    policy: ResultPolicy,
) -> Result<Vec<u8>, Error> {
    if current.is_empty() || current == b"0" {
        return if withdraw {
            Err(Error::rejected("no encrypted balance"))
        } else {
            private_result(delta, policy)
        };
    }
    if !current.starts_with(b"hfhe_v1|") || current.len() <= 8 {
        let mut reason = b"legacy cipher format (not hfhe_v1): ".to_vec();
        reason.extend_from_slice(&current[..current.len().min(20)]);
        if current.len() > 20 {
            reason.extend_from_slice(b"...");
        }
        return Err(Error::Rejected(reason));
    }
    let cipher = decode_cipher(current, false, cap).map_err(|e| e.prefix(b"decode current: "))?;
    // The native arithmetic FFI raises here; FheBalance does not turn that
    // exception into a transaction refusal. Preserve that abort boundary.
    let next = (if withdraw {
        cipher.subtract(public, delta)
    } else {
        cipher.add(public, delta)
    })
    .map_err(Error::Unavailable)?;
    private_result(&next, policy)
}
/// The payload fields are borrowed so the native byte strings never need a
/// lossy UTF-8 conversion, including malformed proof/error cases.
pub struct AmountProof<'a> {
    pub cipher: &'a [u8],
    pub proof: &'a [u8],
    pub commitment: &'a [u8],
    pub blinding: &'a [u8],
}
fn bytes32(raw: &[u8], message: &'static str) -> Result<[u8; 32], Error> {
    base64(raw)?
        .try_into()
        .map_err(|_| Error::rejected(message))
}
pub fn verify_amount(
    public: &PublicKey,
    amount: &BigInt,
    payload: &AmountProof<'_>,
    strict: bool,
    math: ScalarRule,
) -> Result<(), Error> {
    let amount = amount
        .to_i64()
        .filter(|value| *value >= 0)
        .ok_or_else(|| Error::rejected("amount out of int64 range"))? as u64;
    let blinding =
        bytes32(payload.blinding, "blinding must be 32 bytes").map_err(encrypt_exception)?;
    let expected = pedersen_commit(
        &Scalar::from_u64(amount),
        &Scalar::from_bytes_raw(&blinding),
    );
    let commitment = bytes32(payload.commitment, "amount_commitment must be 32 bytes")
        .map_err(encrypt_exception)?;
    if expected != commitment {
        return Err(Error::rejected(
            "amount commitment mismatch: pedersen_commit(amount, blinding) != amount_commitment",
        ));
    }
    let cipher =
        decode_cipher(payload.cipher, strict, strict).map_err(|e| e.prefix(b"bad cipher: "))?;
    let proof = decode_zero_proof(payload.proof).map_err(|e| e.prefix(b"bad zero proof: "))?;
    if !cipher.is_wrapped_scalar() {
        return Err(Error::rejected("amount cipher must be a wrapped scalar"));
    }
    if !verified(zero::verify_bound(
        public,
        &cipher,
        &proof,
        &commitment,
        BoundProfile::Standard,
        strict,
        math,
    ))? {
        return Err(Error::rejected("bound zero proof verification failed"));
    }
    Ok(())
}
fn encrypt_exception(error: Error) -> Error {
    match &error {
        Error::Rejected(reason) if reason.starts_with(b"Invalid_argument(") => {
            error.prefix(b"verify_encrypt_proof: ")
        }
        _ => error,
    }
}
fn verified(result: Result<bool, octra_hfhe::Error>) -> Result<bool, Error> {
    match result {
        Ok(value) => Ok(value),
        Err(error) if error.is_operational() => Err(Error::Unavailable(error)),
        Err(_) => Ok(false),
    }
}
pub fn verify_commitment(
    public: &PublicKey,
    encoded: &[u8],
    expected: &[u8],
    cap: bool,
) -> Result<bool, Error> {
    let cipher = match decode_cipher(encoded, false, cap) {
        Ok(cipher) => cipher,
        Err(Error::Rejected(_)) => return Ok(false),
        Err(error) => return Err(error),
    };
    Ok(STANDARD.encode(cipher.commitment(public)).as_bytes() == expected)
}
/// Native claim/send amount binding. Its commitment is a Pedersen amount
/// commitment, distinct from the ciphertext commitment checked above.
pub fn verify_claim(
    public: &PublicKey,
    encoded: &[u8],
    proof: &[u8],
    commitment: &[u8],
    strict: bool,
    math: ScalarRule,
) -> Result<(), Error> {
    verify_claim_profile(
        public,
        encoded,
        proof,
        commitment,
        strict,
        math,
        BoundProfile::Standard,
    )
}
pub(crate) fn verify_claim_profile(
    public: &PublicKey,
    encoded: &[u8],
    proof: &[u8],
    commitment: &[u8],
    strict: bool,
    math: ScalarRule,
    profile: BoundProfile,
) -> Result<(), Error> {
    if profile == BoundProfile::HistoricalMigration && public.supports_alias_rejection() {
        return Err(Error::rejected(
            "historical migration requires a historical proof profile",
        ));
    }
    if profile != BoundProfile::HistoricalMigration && !public.supports_alias_rejection() {
        return Err(Error::rejected(
            "pvac pubkey proof circuit lacks alias rejection",
        ));
    }
    let historical = profile == BoundProfile::HistoricalMigration;
    let cipher = decode_cipher(encoded, strict, strict).map_err(|e| {
        if historical {
            e
        } else {
            e.prefix(b"bad claim cipher: ")
        }
    })?;
    let proof = decode_zero_proof(proof).map_err(|e| {
        if historical {
            e
        } else {
            e.prefix(b"bad zero proof: ")
        }
    })?;
    if historical {
        let commitment = base64(commitment).map_err(|_| Error::rejected("invalid commitment"))?;
        let commitment: [u8; 32] = commitment
            .try_into()
            .map_err(|_| Error::rejected("commitment must be 32 bytes"))?;
        return if verified(zero::verify_bound(
            public,
            &cipher,
            &proof,
            &commitment,
            profile,
            strict,
            math,
        ))? {
            Ok(())
        } else {
            Err(Error::rejected(
                "historical migration proof verification failed",
            ))
        };
    }
    let commitment = bytes32(commitment, "amount_commitment must be 32 bytes").map_err(
        |error| match &error {
            Error::Rejected(reason) if reason.starts_with(b"Invalid_argument(") => {
                error.prefix(b"bad amount_commitment: ")
            }
            _ => error,
        },
    )?;
    if !verified(zero::verify_bound(
        public,
        &cipher,
        &proof,
        &commitment,
        profile,
        strict,
        math,
    ))? {
        return Err(Error::rejected("bound zero proof verification failed"));
    }
    Ok(())
}
pub(crate) fn verify_range_bound(
    public: &PublicKey,
    encoded: &[u8],
    proof: &[u8],
    commitment: &[u8],
    strict: bool,
    math: ScalarRule,
) -> Result<(), Error> {
    if !public.supports_alias_rejection() {
        return Err(Error::rejected(
            "pvac pubkey proof circuit lacks alias rejection",
        ));
    }
    let cipher = decode_cipher(encoded, strict, strict)?;
    let raw = proof
        .strip_prefix(b"rp_v1|")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| Error::rejected("invalid range proof"))?;
    let raw = base64(raw).map_err(|_| Error::rejected("invalid bound range proof"))?;
    let commitment =
        base64(commitment).map_err(|_| Error::rejected("invalid bound range proof"))?;
    let commitment: [u8; 32] = commitment
        .try_into()
        .map_err(|_| Error::rejected("amount commitment must be 32 bytes"))?;
    let proof = match ZeroProof::from_bound_range_bytes(&raw) {
        Ok(proof) => proof,
        Err(error) if error.is_operational() => return Err(Error::Unavailable(error)),
        Err(_) => return Err(Error::rejected("bound range proof verification failed")),
    };
    if !verified(zero::verify_bound(
        public,
        &cipher,
        &proof,
        &commitment,
        BoundProfile::Range,
        strict,
        math,
    ))? {
        return Err(Error::rejected("bound range proof verification failed"));
    }
    Ok(())
}
pub(crate) fn transition_hash(tag: &[u8], fields: &[&[u8]]) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(tag);
    for field in fields {
        hash.update([0]);
        hash.update(hex::encode(Sha256::digest(field)).as_bytes());
    }
    hex::encode(hash.finalize())
}
pub fn verify_range(
    public: &PublicKey,
    cipher: &[u8],
    proof: &[u8],
    strict: bool,
    math: ScalarRule,
) -> Result<bool, Error> {
    let run = || {
        let raw = proof
            .strip_prefix(b"rp_v1|")
            .filter(|v| !v.is_empty())
            .ok_or_else(|| Error::rejected("not a range proof"))?;
        let raw = base64(raw)?;
        let cipher = decode_cipher(cipher, strict, strict)?;
        // The private verifier accepts only bound proofs. Do not parse legacy
        // range payloads that the native FFI rejects before allocation.
        let proof = native(ZeroProof::from_bound_range_bytes(&raw))?;
        verified(zero::verify_embedded_range(
            public, &cipher, &proof, strict, math,
        ))
    };
    match run() {
        Err(Error::Rejected(_)) => Ok(false),
        result => result,
    }
}
