// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native Ed25519-to-X25519 view-public-key conversion. This conversion needs
//! only the validator's public key; it never exposes a signing or view secret.
use num_bigint::BigUint;
use num_traits::One;
pub fn public(ed25519: &[u8]) -> Result<[u8; 32], crate::oce1::Error> {
    if ed25519.len() != 32 {
        return Err("Ed25519 pubkey must be 32 bytes".into());
    }
    let mut encoded: [u8; 32] = ed25519.try_into().expect("checked key length");
    encoded[31] &= 127;
    let prime = (BigUint::one() << 255usize) - BigUint::from(19u32);
    let y = BigUint::from_bytes_le(&encoded) % &prime;
    let numerator = (&y + BigUint::one()) % &prime;
    let denominator = (&prime + BigUint::one() - y) % &prime;
    let u = numerator * denominator.modpow(&(&prime - BigUint::from(2u32)), &prime) % prime;
    let bytes = u.to_bytes_le();
    let mut output = [0; 32];
    output[..bytes.len()].copy_from_slice(&bytes);
    Ok(output)
}
