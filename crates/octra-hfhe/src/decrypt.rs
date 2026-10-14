// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native-compatible active, retained and local-source decryption policies.
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    cipher::{Cipher, Layer, RSeed},
    circuit_prf,
    field::Fp,
    keys::{PublicKey, SecretKey},
    lpn, matrix, Error,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DecPolicy {
    #[default]
    Standard,
    NativeLocal,
    LegacyMask,
}

pub fn native_tag(public: &PublicKey, nonce: [u64; 2]) -> u64 {
    let mut hash = Sha256::new();
    hash.update(b"pvac.native.ru.ztag");
    for word in [public.canon_tag, nonce[0], nonce[1]] {
        hash.update(word.to_le_bytes());
    }
    u64::from_le_bytes(hash.finalize()[..8].try_into().unwrap())
}

fn native_source(public: &PublicKey, layer: &Layer) -> bool {
    layer.rule == 0 && layer.seed.ztag == native_tag(public, layer.seed.nonce)
}

pub fn has_native_source(public: &PublicKey, cipher: &Cipher) -> bool {
    cipher
        .layers
        .iter()
        .any(|layer| native_source(public, layer))
}

pub fn native_affine(secret: &SecretKey, tag: u64, nonce: [u64; 2], slot: usize) -> Fp {
    let mut hash = Sha256::new();
    hash.update(b"pvac.native.ru.secret");
    for word in [tag, nonce[0], nonce[1], slot as u64] {
        hash.update(word.to_le_bytes());
    }
    for (index, word) in secret.prf_key.iter().enumerate() {
        hash.update((index as u64).to_le_bytes());
        hash.update(Zeroizing::new(word.to_le_bytes()).as_ref());
    }
    let mut bytes = Zeroizing::new([0; 32]);
    hash.finalize_into((&mut *bytes).into());
    let lo = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let hi = u64::from_le_bytes(bytes[8..16].try_into().unwrap()) & (u64::MAX >> 1);
    let value = Fp::from_words(lo, hi);
    if value == Fp::ZERO {
        Fp::ONE
    } else {
        value
    }
}

pub fn native_masks(
    secret: &SecretKey,
    tag: u64,
    nonce: [u64; 2],
    slots: usize,
) -> Result<Zeroizing<Vec<Fp>>, Error> {
    let mut output = circuit_prf::reserve_fields(slots)?;
    for slot in 0..slots {
        let affine = Zeroizing::new(native_affine(secret, tag, nonce, slot));
        output.push((*affine * *affine + Fp::ONE).inverse());
    }
    Ok(output)
}

fn legacy_masks(
    public: &PublicKey,
    secret: &SecretKey,
    seed: RSeed,
    slots: usize,
) -> Result<Zeroizing<Vec<Fp>>, Error> {
    let mut output = circuit_prf::reserve_fields(slots)?;
    for slot in 0..slots {
        let mut seed = seed;
        if slots != 1 {
            let t = (slot as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            seed.nonce[1] ^= t;
            seed.nonce[0] ^= t.rotate_left(32);
            seed.ztag = matrix::layer_tag(public.canon_tag, seed.nonce);
        }
        output.push(lpn::prf_r(public, secret, seed.ztag, seed.nonce)?);
    }
    Ok(output)
}

pub(crate) fn layer_masks(
    public: &PublicKey,
    secret: &SecretKey,
    cipher: &Cipher,
    policy: DecPolicy,
) -> Result<Vec<Zeroizing<Vec<Fp>>>, Error> {
    // Shape validation requires each product parent to precede its child. This
    // evaluation order preserves the native cache without recursive stack use.
    let mut masks: Vec<Zeroizing<Vec<Fp>>> = Vec::new();
    masks
        .try_reserve_exact(cipher.layers.len())
        .map_err(|_| Error("HFHE allocation unavailable"))?;
    for layer in &cipher.layers {
        let value = if layer.rule == 1 {
            let mut product = circuit_prf::reserve_fields(cipher.slots)?;
            product.extend(
                masks[layer.pa as usize]
                    .iter()
                    .zip(masks[layer.pb as usize].iter())
                    .map(|(&a, &b)| a * b),
            );
            product
        } else if native_source(public, layer) {
            if policy != DecPolicy::NativeLocal {
                return Err(Error("pvac: native source decrypt rejected"));
            }
            native_masks(secret, layer.seed.ztag, layer.seed.nonce, cipher.slots)?
        } else if policy == DecPolicy::LegacyMask || layer.r_pc.is_empty() {
            legacy_masks(public, secret, layer.seed, cipher.slots)?
        } else {
            circuit_prf::slots(
                public,
                secret,
                layer.seed.ztag,
                layer.seed.nonce,
                cipher.slots,
            )?
        };
        masks.push(value);
    }
    Ok(masks)
}

pub fn values(
    public: &PublicKey,
    secret: &SecretKey,
    cipher: &Cipher,
    policy: DecPolicy,
) -> Result<Zeroizing<Vec<Fp>>, Error> {
    if !cipher.compatible_with(public) {
        return Err(Error("pvac: cipher/pubkey mismatch"));
    }
    if policy != DecPolicy::NativeLocal && has_native_source(public, cipher) {
        return Err(Error("pvac: native source decrypt rejected"));
    }
    let mut inverse = layer_masks(public, secret, cipher, policy)?;
    for layer in &mut inverse {
        for mask in layer.iter_mut() {
            *mask = mask.inverse();
        }
    }
    let mut output = circuit_prf::reserve_fields(cipher.slots)?;
    if cipher.c0.is_empty() {
        output.resize(cipher.slots, Fp::ZERO);
    } else {
        output.extend_from_slice(&cipher.c0);
    }
    for edge in &cipher.edges {
        let generator = public.powers[edge.idx as usize];
        for (slot, accumulator) in output.iter_mut().enumerate() {
            let term = edge.weights[slot] * generator * inverse[edge.layer_id as usize][slot];
            *accumulator = if edge.ch == 0 {
                *accumulator + term
            } else {
                *accumulator - term
            };
        }
    }
    Ok(output)
}

pub fn value(
    public: &PublicKey,
    secret: &SecretKey,
    cipher: &Cipher,
    policy: DecPolicy,
) -> Result<Fp, Error> {
    if cipher.slots != 1 {
        return Err(Error("pvac: dec_value: cipher has multi-slot payload; use dec_values for vector decryption or dec_value_slot0 to explicitly coerce"));
    }
    Ok(values(public, secret, cipher, policy)?[0])
}

pub fn value_slot0(
    public: &PublicKey,
    secret: &SecretKey,
    cipher: &Cipher,
    policy: DecPolicy,
) -> Result<Fp, Error> {
    values(public, secret, cipher, policy)?
        .first()
        .copied()
        .ok_or(Error(
            "pvac: dec_value_slot0: cipher decrypts to empty value vector",
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cipher::Edge,
        keys::{keygen_from_seed, BitVec, Params},
    };
    use serde_json::Value;

    #[test]
    fn malformed_objects_preserve_native_decryption_rejection_order() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/decrypt.json")).unwrap();
        let (public, secret) = keygen_from_seed(
            Params {
                m_bits: 65,
                n_bits: 17,
                h_col_weight: 13,
                x_col_weight: 7,
                error_weight: 2,
                lpn_n: 65,
                lpn_t: 129,
                ..Params::default()
            },
            &[0; 32],
        )
        .unwrap();
        for case in fixture["cases"].as_array().unwrap() {
            let kind = case["kind"].as_str().unwrap();
            if !["bad_parent", "bad_sign", "bad_weights", "bad_c0"].contains(&kind) {
                continue;
            }
            let slots = case["slots"].as_u64().unwrap() as usize;
            let mut cipher = Cipher {
                slots,
                layers: vec![Layer::default()],
                edges: vec![Edge {
                    layer_id: 0,
                    idx: 0,
                    ch: 0,
                    weights: vec![Fp::ONE; slots],
                    sigma: BitVec {
                        nbits: 65,
                        words: vec![0; 2],
                    },
                }],
                c0: vec![Fp::ZERO; slots],
            };
            match kind {
                "bad_parent" => cipher.layers.push(Layer {
                    rule: 1,
                    pa: 1,
                    pb: 0,
                    ..Layer::default()
                }),
                "bad_sign" => cipher.edges[0].ch = 2,
                "bad_weights" => cipher.edges[0].weights.clear(),
                "bad_c0" => cipher.c0.push(Fp::ZERO),
                _ => unreachable!(),
            }
            for (index, policy) in [
                DecPolicy::Standard,
                DecPolicy::NativeLocal,
                DecPolicy::LegacyMask,
            ]
            .into_iter()
            .enumerate()
            {
                let expected = &case["expected"]["policies"][index];
                assert_eq!(
                    values(&public, &secret, &cipher, policy)
                        .unwrap_err()
                        .to_string(),
                    expected["values_error"]
                );
                assert_eq!(
                    value(&public, &secret, &cipher, policy)
                        .unwrap_err()
                        .to_string(),
                    expected["value_error"]
                );
                assert_eq!(
                    value_slot0(&public, &secret, &cipher, policy)
                        .unwrap_err()
                        .to_string(),
                    expected["slot0_error"]
                );
            }
        }
    }
}
