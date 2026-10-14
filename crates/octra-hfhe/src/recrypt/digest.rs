// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native recryption domains; deliberately distinct from serialized-key hashes.
use super::hidden::{acc_size, hasher, Digest};
use crate::{
    cipher::Cipher,
    keys::{PublicKey, SecretKey},
    Error,
};
use sha2::Digest as _;
use zeroize::Zeroizing;
pub fn public_key(public: &PublicKey) -> Result<Digest, Error> {
    public
        .validate_shape()
        .map_err(|_| Error("pvac: native runtime pubkey rejected"))?;
    let mut h = hasher(b"pvac.native.runtime.pubkey");
    let params = public.params;
    for word in [
        params.basis as u64,
        params.m_bits as u64,
        params.n_bits as u64,
        params.h_col_weight as u64,
        params.x_col_weight as u64,
        params.error_weight as u64,
        params.edge_budget,
        params.lpn_n as u64,
        params.lpn_t as u64,
        params.lpn_tau_num as u64,
        params.lpn_tau_den as u64,
        params.recrypt_rounds as u64,
        public.canon_tag,
    ] {
        h.update(word.to_le_bytes());
    }
    h.update(public.h_digest);
    h.update(public.omega.to_bytes_le());
    acc_size(&mut h, public.powers.len());
    for value in &public.powers {
        h.update(value.to_bytes_le());
    }
    for permutation in [&public.permutation, &public.inverse] {
        acc_size(&mut h, permutation.len());
        for value in permutation {
            h.update((*value as u64).to_le_bytes());
        }
    }
    Ok(h.finalize().into())
}
pub fn secret_key(public: &PublicKey, secret: &SecretKey) -> Result<Zeroizing<Digest>, Error> {
    let key = public_key(public)?;
    let mut h = hasher(b"pvac.native.runtime.seckey");
    h.update(key);
    for value in &secret.prf_key {
        h.update(value.to_le_bytes());
    }
    acc_size(&mut h, secret.lpn_bits.len());
    for value in &secret.lpn_bits {
        h.update(value.to_le_bytes());
    }
    Ok(Zeroizing::new(h.finalize().into()))
}
pub fn cipher(public: &PublicKey, cipher: &Cipher) -> Result<Digest, Error> {
    if !cipher.compatible_with(public) {
        return Err(Error("pvac: native runtime cipher rejected"));
    }
    let mut h = hasher(b"pvac.native.runtime.cipher");
    h.update(public.canon_tag.to_le_bytes());
    acc_size(&mut h, cipher.slots);
    acc_size(&mut h, cipher.c0.len());
    for value in &cipher.c0 {
        h.update(value.to_bytes_le());
    }
    acc_size(&mut h, cipher.layers.len());
    for layer in &cipher.layers {
        for value in [
            u64::from(layer.rule),
            layer.seed.ztag,
            layer.seed.nonce[0],
            layer.seed.nonce[1],
            u64::from(layer.pa),
            u64::from(layer.pb),
        ] {
            h.update(value.to_le_bytes());
        }
        h.update(layer.r_com);
        acc_size(&mut h, layer.pc.len());
        for point in &layer.pc {
            h.update(point);
        }
    }
    acc_size(&mut h, cipher.edges.len());
    for edge in &cipher.edges {
        for value in [
            u64::from(edge.layer_id),
            u64::from(edge.idx),
            u64::from(edge.ch),
        ] {
            h.update(value.to_le_bytes());
        }
        acc_size(&mut h, edge.weights.len());
        for value in &edge.weights {
            h.update(value.to_bytes_le());
        }
        acc_size(&mut h, edge.sigma.nbits);
        acc_size(&mut h, edge.sigma.words.len());
        for value in &edge.sigma.words {
            h.update(value.to_le_bytes());
        }
    }
    Ok(h.finalize().into())
}
pub fn pair(domain: &[u8], left: &Digest, right: &Digest) -> Digest {
    let mut h = hasher(domain);
    h.update(left);
    h.update(right);
    h.finalize().into()
}
