// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use crate::{
    circle_program::Refusal,
    network,
    state::Ledger,
    transaction::{address_from_public_key, decode_base64, is_valid_address},
};
pub fn signature(
    ledger: &Ledger,
    relay: &[u8],
    signature: &[u8],
    subject: &[u8],
) -> Result<(), Refusal> {
    let error = |tag, reason: &'static [u8]| Refusal::new(tag, reason);
    if !is_valid_address(relay) {
        return Err(error(
            "invalid_circle_relay_id",
            b"relay_id must be a valid octra address",
        ));
    }
    let encoded = ledger
        .account(relay)
        .and_then(|account| account.public_key.as_deref())
        .ok_or_else(|| {
            error(
                "circle_relay_pubkey_missing",
                b"relay_id has no registered public key",
            )
        })?;
    if address_from_public_key(encoded) != relay {
        return Err(error(
            "invalid_circle_relay_id",
            b"relay public key does not match relay_id",
        ));
    }
    let public = decode_base64(encoded).map_err(|_| {
        error(
            "circle_relay_pubkey_invalid",
            b"relay public key is not valid base64",
        )
    })?;
    if !network::public_key_safe(&public) {
        return Err(error(
            "circle_relay_pubkey_invalid",
            b"relay public key is not a valid ed25519 key",
        ));
    }
    let signature = decode_base64(signature).map_err(|_| {
        error(
            "circle_relay_signature_invalid",
            b"relay signature is not valid base64",
        )
    })?;
    if !network::verify_ed25519(&public, subject, &signature) {
        return Err(error(
            "circle_relay_signature_invalid",
            b"relay signature verification failed",
        ));
    }
    Ok(())
}
