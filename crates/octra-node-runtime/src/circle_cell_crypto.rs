// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native PVAC Circle-cell worker checks, including its narrower resource cap.
use crate::private_crypto::{self as crypto, Error};
use octra_hfhe::{
    proof::zero::{self, BoundProfile, ZeroProof},
    scalar::ScalarRule,
};
use octra_node_protocol::transaction::decode_base64;
#[derive(Clone, Copy)]
pub(crate) enum Kind {
    None,
    Zero,
    BoundZero,
    Range,
}
fn commitment(encoded: &[u8]) -> Result<[u8; 32], Error> {
    decode_base64(encoded)
        .map_err(|_| Error::rejected("invalid commitment"))?
        .try_into()
        .map_err(|_| Error::rejected("commitment must be 32 bytes"))
}
fn verified(value: Result<bool, octra_hfhe::Error>, reason: &'static str) -> Result<(), Error> {
    match value {
        Ok(true) => Ok(()),
        Err(error) if error.is_operational() => Err(Error::Unavailable(error)),
        _ => Err(Error::rejected(reason)),
    }
}
fn proof(encoded: &[u8], bound: bool) -> Result<ZeroProof, Error> {
    crypto::decode_zero_proof(encoded).map_err(|error| match error {
        Error::Rejected(_) => Error::rejected(if bound {
            "invalid bound zero proof"
        } else {
            "invalid zero proof"
        }),
        other @ Error::Unavailable(_) => other,
    })
}
#[allow(clippy::too_many_arguments)] // Exact native worker request fields.
pub(crate) fn verify(
    public: &[u8],
    cipher: &[u8],
    expected: &[u8],
    kind: Kind,
    encoded_proof: &[u8],
    amount: &[u8],
    strict: bool,
    math: ScalarRule,
) -> Result<(), Error> {
    if cipher.is_empty() || cipher.len() > 96 * 1024 {
        return Err(Error::rejected(
            "ciphertext exceeds verifier resource policy",
        ));
    }
    if encoded_proof.len() > 64 * 1024 {
        return Err(Error::rejected("proof exceeds verifier resource policy"));
    }
    let public = crypto::proof_pubkey(public)?;
    let cipher = crypto::decode_cipher(cipher, strict, strict)?;
    let expected = commitment(expected)?;
    let shape = cipher.shape().map_err(Error::Unavailable)?;
    if shape.slots != 1
        || shape.constants != 1
        || !(1..=8).contains(&shape.layers)
        || shape.edges > 512
        || !(1..=2).contains(&shape.base_layers)
    {
        return Err(Error::rejected(
            "ciphertext exceeds verifier resource policy",
        ));
    }
    if cipher.commitment(&public) != expected {
        return Err(Error::rejected("ciphertext commitment mismatch"));
    }
    match kind {
        Kind::None => {
            if encoded_proof.is_empty() && amount.is_empty() {
                Ok(())
            } else {
                Err(Error::rejected("unexpected circle proof fields"))
            }
        }
        Kind::Zero => verified(
            zero::verify_zero(&public, &cipher, &proof(encoded_proof, false)?, math),
            "zero proof verification failed",
        ),
        Kind::BoundZero => {
            let proof = proof(encoded_proof, true)?;
            let amount = commitment(amount)?;
            verified(
                zero::verify_bound(
                    &public,
                    &cipher,
                    &proof,
                    &amount,
                    BoundProfile::Standard,
                    strict,
                    math,
                ),
                "bound zero proof verification failed",
            )
        }
        Kind::Range => {
            let raw = encoded_proof
                .strip_prefix(b"rp_v1|")
                .filter(|raw| !raw.is_empty())
                .ok_or_else(|| Error::rejected("invalid range proof"))?;
            let raw = decode_base64(raw).map_err(|_| Error::rejected("invalid range proof"))?;
            let amount = commitment(amount)?;
            let proof = ZeroProof::from_bound_range_bytes(&raw).map_err(|error| {
                if error.is_operational() {
                    Error::Unavailable(error)
                } else {
                    Error::rejected("bound range proof verification failed")
                }
            })?;
            verified(
                zero::verify_bound(
                    &public,
                    &cipher,
                    &proof,
                    &amount,
                    BoundProfile::Range,
                    strict,
                    math,
                ),
                "bound range proof verification failed",
            )
        }
    }
}
