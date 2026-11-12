// SPDX-License-Identifier: BSD-3-Clause
//! Exact typed public-key transcript digest from PVAC commit.hpp.
use crate::{field::Fp, keys::PublicKey};
use sha2::{Digest, Sha256};

struct KeyHash(Sha256);
impl KeyHash {
    fn word(&mut self, value: u64) {
        self.0.update(value.to_le_bytes());
    }
    fn tag(&mut self, value: &[u8]) {
        self.word(value.len() as u64);
        self.0.update(value);
    }
    fn record(&mut self, name: &[u8], fields: u64) {
        self.tag(b"record");
        self.tag(name);
        self.word(fields);
    }
    fn signed(&mut self, value: i32) {
        self.tag(b"signed");
        self.word(value as i64 as u64);
    }
    fn unsigned(&mut self, value: u64) {
        self.tag(b"unsigned");
        self.word(value);
    }
    fn real(&mut self, value: f64) {
        self.tag(b"real");
        self.word(value.to_bits());
    }
    fn list(&mut self, length: usize) {
        self.tag(b"list");
        self.word(length as u64);
    }
    fn bytes(&mut self, value: &[u8]) {
        self.tag(b"bytes");
        self.word(value.len() as u64);
        self.0.update(value);
    }
    fn field(&mut self, value: Fp) {
        self.record(b"field", 2);
        let (lo, hi) = value.words();
        self.unsigned(lo);
        self.unsigned(hi);
    }
}

/// Includes every typed public-key field, including the key's proof profile.
/// This is deliberately independent of compression and serialization format.
pub fn digest(key: &PublicKey) -> [u8; 32] {
    let mut h = KeyHash(Sha256::new());
    h.tag(b"pvac.proof.public_key.fields");
    h.record(b"public_key", 9);
    let p = key.params;
    h.record(b"params", 17);
    for v in [
        p.basis,
        p.m_bits,
        p.n_bits,
        p.h_col_weight,
        p.x_col_weight,
        p.error_weight,
    ] {
        h.signed(v);
    }
    for v in [p.noise_entropy_bits, p.tuple2_fraction, p.depth_slope_bits] {
        h.real(v);
    }
    h.unsigned(p.edge_budget);
    for v in [p.lpn_n, p.lpn_t, p.lpn_tau_num, p.lpn_tau_den] {
        h.signed(v);
    }
    h.real(p.recrypt_lo);
    h.real(p.recrypt_hi);
    h.signed(p.recrypt_rounds);
    h.unsigned(key.canon_tag);
    h.list(key.h.len());
    for row in &key.h {
        h.record(b"bits", 2);
        h.unsigned(row.nbits as u64);
        h.list(row.words.len());
        for &word in &row.words {
            h.unsigned(word);
        }
    }
    h.record(b"index", 2);
    for row in [&key.permutation, &key.inverse] {
        h.list(row.len());
        for &value in row {
            h.signed(value);
        }
    }
    h.bytes(&key.h_digest);
    h.field(key.omega);
    h.list(key.powers.len());
    for &power in &key.powers {
        h.field(power);
    }
    h.bytes(&key.circuit_commit);
    h.tag(b"profile");
    h.word(u64::from(key.circuit_profile));
    h.0.finalize().into()
}
