// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    check,
    classify::{self, Cipher, Key, Route, Status},
    crypto, digest,
    payload::{Migration as M, Payload},
    rejected, Policy, Result,
};
use crate::private_crypto::isolated::PublicKey;
use crate::private_transfer::wrapped;
use num_bigint::BigInt;
use num_traits::Zero;
use octra_hfhe::proof::zero::BoundProfile;
use octra_node_protocol::{
    state_sync::migration::{Admission, Audit, Entry},
    transaction::RuleMode,
};

fn entitlement<'a>(
    admission: Option<&'a Admission>,
    epoch: i64,
    address: &[u8],
    source: &[u8],
) -> Result<&'a Entry> {
    admission
        .ok_or_else(|| rejected("migration entitlement artifact unavailable"))?
        .find(epoch, address, source)
        .map_err(|error| rejected(error.to_string()))
}
fn audit_commitment(entry: &Entry) -> Result<&[u8]> {
    if entry.audit == Audit::Poisoned {
        return Err(rejected(&entry.reason));
    }
    entry.commitment_net.as_deref().ok_or_else(|| {
        rejected("legacy commitment migration requires reconstructable commitment history")
    })
}
fn public_amount(entry: &Entry) -> Result<&BigInt> {
    if !entry.can_public_migrate {
        return Err(rejected(&entry.reason));
    }
    match &entry.public_net {
        Some(amount) if amount > &BigInt::zero() => Ok(amount),
        Some(_) => Err(rejected("legacy public replay produced an empty balance")),
        None => Err(rejected(
            "legacy public replay did not produce a public balance",
        )),
    }
}
fn key_bound(cipher: &[u8], cap: bool, message: &'static str) -> Result<()> {
    if classify::cipher(cipher, cap)?.0 != Cipher::Proven {
        return Err(rejected(message));
    }
    Ok(())
}
fn source_hash(
    payload: &Payload,
    source: &[u8],
    missing: &'static str,
    changed: &'static str,
) -> Result<()> {
    match &payload.source_hash {
        None => Err(rejected(missing)),
        Some(hash) if *hash != digest(source) => Err(rejected(changed)),
        Some(_) => Ok(()),
    }
}
fn refresh(source: &[u8], cap: bool) -> Result<()> {
    check(
        crypto::check_refresh_source(source, cap),
        "key_switch_rejected",
        b"",
        None,
    )
}
fn old_bindings(payload: &Payload) -> bool {
    payload.old_key.is_some() || payload.old_cipher.is_some() || payload.old_proof.is_some()
}
fn claim(
    public: &PublicKey,
    cipher: &[u8],
    proof: &[u8],
    commitment: &[u8],
    policy: Policy,
    kind: BoundProfile,
    prefix: &[u8],
) -> Result<()> {
    check(
        crypto::verify_claim_profile(
            public,
            cipher,
            proof,
            commitment,
            policy.balance.strict,
            policy.balance.math,
            kind,
        ),
        "key_switch_rejected",
        prefix,
        None,
    )
}
fn amount(
    public: &PublicKey,
    payload: &Payload,
    value: &BigInt,
    policy: Policy,
    prefix: &[u8],
) -> Result<()> {
    check(
        crypto::verify_amount(
            public,
            value,
            &crypto::AmountProof {
                cipher: payload.new_cipher.as_deref().expect("prepared cipher"),
                proof: payload.new_proof.as_deref().expect("prepared proof"),
                commitment: payload.commitment.as_deref().expect("prepared commitment"),
                blinding: payload.blinding.as_deref().expect("prepared blinding"),
            },
            policy.balance.strict,
            policy.balance.math,
        ),
        "key_switch_rejected",
        prefix,
        None,
    )
}
fn public_fields(payload: &Payload, cap: bool, reset: bool) -> Result<&[u8]> {
    if reset && old_bindings(payload) {
        return Err(rejected(
            "legacy zero reset must not include old ciphertext binding fields",
        ));
    }
    match (
        &payload.new_cipher,
        &payload.new_proof,
        &payload.commitment,
        &payload.blinding,
    ) {
        (Some(cipher), Some(_), Some(_), Some(_)) => {
            key_bound(
                cipher,
                cap,
                if reset {
                    "legacy zero reset requires a v3 key-bound new cipher"
                } else {
                    "new encrypted balance must be v3 key-bound"
                },
            )?;
            Ok(cipher)
        }
        _ => Err(rejected(if reset {
            "legacy zero reset requires new_cipher, new_zero_proof, amount_commitment and amount_blinding"
        } else {
            "legacy public migration requires new_cipher, new_zero_proof, amount_commitment and amount_blinding"
        })),
    }
}
fn commitment_fields(payload: &Payload, cap: bool) -> Result<&[u8]> {
    match (&payload.new_cipher, &payload.new_proof) {
        (Some(cipher), Some(_)) => {
            if !wrapped(cipher, cap)? {
                return Err(rejected(
                    "legacy commitment migration requires a wrapped scalar new cipher",
                ));
            }
            key_bound(
                cipher,
                cap,
                "legacy commitment migration requires a v3 key-bound new cipher",
            )?;
            Ok(cipher)
        }
        _ => Err(rejected(
            "legacy commitment migration requires new_cipher and new_zero_proof",
        )),
    }
}
fn owner_fields<'a>(
    payload: &'a Payload,
    source: &[u8],
    cap: bool,
) -> Result<(&'a [u8], &'a [u8], &'a [u8])> {
    if old_bindings(payload) {
        return Err(rejected(
            "historical owner migration reads its authorization from finalized history",
        ));
    }
    if payload.blinding.is_some() {
        return Err(rejected(
            "historical owner migration must not disclose amount blinding",
        ));
    }
    source_hash(
        payload,
        source,
        "historical owner migration requires source_cipher_hash",
        "encrypted balance changed before historical owner verification",
    )?;
    refresh(source, cap)?;
    match (&payload.new_cipher, &payload.new_proof, &payload.commitment) {
        (Some(cipher), Some(proof), Some(commitment)) => {
            if !wrapped(cipher, cap)? { return Err(rejected("historical owner migration requires a wrapped scalar new cipher")); }
            Ok((cipher, proof, commitment))
        }
        _ => Err(rejected("historical owner migration requires new cipher, new proof and history-bound amount commitment")),
    }
}
// Preserve the ordered native tuple/borrowed-field projection API.
#[allow(clippy::type_complexity)]
fn cipher_fields<'a>(
    payload: &'a Payload,
    source: &[u8],
    cap: bool,
) -> Result<(&'a [u8], &'a [u8], &'a [u8], &'a [u8])> {
    if payload.old_key.is_some()
        || payload.old_cipher.is_some()
        || payload.blinding.is_some()
        || payload.new_proof.is_some()
    {
        return Err(rejected("cipher migration has unexpected proof fields"));
    }
    source_hash(
        payload,
        source,
        "cipher migration requires source_cipher_hash",
        "encrypted balance changed before cipher migration",
    )?;
    refresh(source, cap)?;
    match (&payload.new_cipher, &payload.old_proof, &payload.range, &payload.commitment) {
        (Some(cipher), Some(old), Some(new), Some(commitment)) if wrapped(cipher, cap)? => Ok((cipher, old, new, commitment)),
        _ => Err(rejected("cipher migration requires scalar new_cipher, old_zero_proof, new_range_proof and amount_commitment")),
    }
}
#[allow(clippy::too_many_arguments)]
pub(super) fn prepare(
    payload: &Payload,
    status: &Status,
    source: &[u8],
    old: Option<&[u8]>,
    public: &PublicKey,
    policy: Policy,
    epoch: i64,
    admission: Option<&Admission>,
    address: &[u8],
    verify: bool,
) -> Result<Option<Vec<u8>>> {
    let cap = policy.balance.strict;
    let history = status.history(policy.cipher == RuleMode::Active);
    let audit = || entitlement(admission, epoch, address, source);
    if payload.migration == M::Cipher {
        let Some(old) =
            old.filter(|_| status.cipher == Cipher::Proven && status.key == Key::Historical)
        else {
            return Err(rejected(
                "cipher migration requires a proven balance and historical registered key",
            ));
        };
        let (cipher, old_proof, new_proof, commitment) = cipher_fields(payload, source, cap)?;
        if verify {
            let old = check(
                crypto::load_pubkey(old),
                "key_switch_rejected",
                b"old encrypted balance proof failed: ",
                None,
            )?;
            claim(
                &old,
                source,
                old_proof,
                commitment,
                policy,
                BoundProfile::HistoricalMigration,
                b"old encrypted balance proof failed: ",
            )?;
            check(
                crypto::verify_range_bound(
                    public,
                    cipher,
                    new_proof,
                    commitment,
                    true,
                    policy.balance.math,
                ),
                "key_switch_rejected",
                b"new encrypted balance range proof failed: ",
                None,
            )?;
        }
        return Ok(Some(cipher.to_vec()));
    }
    if verify && payload.migration == M::Zero && policy.cipher == RuleMode::Active {
        let zero = audit().is_ok_and(|e| {
            e.can_public_migrate && e.public_net.as_ref().is_some_and(BigInt::is_zero)
        });
        if !zero {
            return Err(rejected("zero reset requires verified zero public history"));
        }
    }
    if payload.migration == M::Zero && !history {
        return Err(rejected("legacy zero reset requires a legacy hfhe balance"));
    }
    if status.route == Route::Direct {
        return Ok(None);
    }
    if history {
        let cipher = match payload.migration {
            M::Zero => {
                let cipher = public_fields(payload, cap, true)?;
                if verify { amount(public, payload, &BigInt::zero(), policy, b"legacy zero reset failed: ")?; }
                cipher
            }
            M::Owner => {
                if status.cipher != Cipher::Proven || status.key != Key::Historical {
                    return Err(rejected("historical owner proof requires a key-bound balance and historical registered key"));
                }
                let (cipher, proof, commitment) = owner_fields(payload, source, cap)?;
                if verify {
                    if commitment != audit_commitment(audit()?)? { return Err(rejected("historical owner commitment differs from finalized history")); }
                    claim(public, cipher, proof, commitment, policy, BoundProfile::Standard, b"new encrypted balance proof failed: ")?;
                }
                cipher
            }
            M::Commitment => {
                // The verified history check precedes payload preparation.
                let trusted = if verify { Some(audit_commitment(audit()?)?) } else { None };
                let cipher = commitment_fields(payload, cap)?;
                if let Some(commitment) = trusted {
                    claim(public, cipher, payload.new_proof.as_deref().expect("prepared proof"), commitment, policy,
                        BoundProfile::Standard, b"legacy commitment migration failed: ")?;
                }
                cipher
            }
            M::Rebinding => return Err(rejected("legacy ciphertext rebinding is not statement preserving; use public or commitment history migration")),
            M::Public => {
                let amount_value = if verify { Some(public_amount(audit()?)?) } else { None };
                let cipher = public_fields(payload, cap, false)?;
                if let Some(value) = amount_value { amount(public, payload, value, policy, b"legacy public migration failed: ")?; }
                cipher
            }
            _ => return Err(rejected(&status.reason)),
        };
        return Ok(Some(cipher.to_vec()));
    }
    if status.route != Route::Bound {
        return Err(rejected(&status.reason));
    }
    source_hash(
        payload,
        source,
        "encrypted balance migration requires source_cipher_hash",
        "encrypted balance changed before key switch verification",
    )?;
    refresh(source, cap)?;
    match (old, &payload.new_cipher, &payload.old_proof, &payload.new_proof, &payload.commitment) {
        (Some(old), Some(cipher), Some(old_proof), Some(new_proof), Some(commitment)) => {
            if !wrapped(cipher, cap)? { return Err(rejected("new encrypted balance must be a wrapped scalar")); }
            if verify {
                let old = check(crypto::load_pubkey(old), "key_switch_rejected", b"old encrypted balance proof failed: ", None)?;
                claim(&old, source, old_proof, commitment, policy, BoundProfile::KeySwitchRefresh, b"old encrypted balance proof failed: ")?;
                claim(public, cipher, new_proof, commitment, policy, BoundProfile::Standard, b"new encrypted balance proof failed: ")?;
            }
            Ok(Some(cipher.clone()))
        }
        _ => Err(rejected("encrypted balance migration requires new_cipher, old_zero_proof, new_zero_proof and amount_commitment")),
    }
}
