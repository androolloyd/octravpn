// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Reusable native recryption keys and production admission profiles.
use super::{
    chosen::{Budget, Policy},
    digest,
    hidden::{acc_bool, acc_size, digest_eq, hasher, Certificate, Digest},
    profile::Kind,
};
use crate::{
    cipher::Cipher,
    decrypt, encrypt,
    keys::{PublicKey, SecretKey},
    proof::r1cs,
    Error,
};
use sha2::Digest as _;
use zeroize::Zeroizing;
pub struct Key {
    pub key: Digest,
    pub domain: Digest,
    pub view: Digest,
    pub encrypted_secret: Vec<Cipher>,
    pub policy: Policy,
    pub budget: Budget,
    pub prf: usize,
    pub lpn: usize,
    pub safe: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admission {
    pub max_terms: usize,
    pub out_terms: usize,
    pub max_slots: usize,
    pub max_queries: usize,
    pub alpha_bits: usize,
    pub row_bits: usize,
}
impl Default for Admission {
    fn default() -> Self {
        Self {
            max_terms: 16,
            out_terms: 2,
            max_slots: 1,
            max_queries: 64,
            alpha_bits: 8,
            row_bits: 8,
        }
    }
}
impl Admission {
    pub fn linear() -> Self {
        Self {
            max_terms: 8,
            max_queries: 32,
            ..Self::default()
        }
    }
    pub fn wide() -> Self {
        Self {
            max_terms: 32,
            out_terms: 4,
            max_queries: 32,
            ..Self::default()
        }
    }
    pub fn vector(slots: usize) -> Self {
        Self {
            max_slots: slots,
            max_queries: 32,
            ..Self::default()
        }
    }
    pub fn production() -> Self {
        Self {
            max_terms: 32,
            out_terms: 4,
            max_slots: 8,
            ..Self::default()
        }
    }
    pub fn production_allowed(self) -> bool {
        let limit = Self::production();
        self.max_terms != 0
            && self.out_terms != 0
            && self.max_slots != 0
            && self.max_queries != 0
            && self.out_terms <= self.max_terms
            && self.max_terms <= limit.max_terms
            && self.out_terms <= limit.out_terms
            && self.max_slots <= limit.max_slots
            && self.max_queries <= limit.max_queries
            && self.alpha_bits <= limit.alpha_bits
            && self.row_bits <= limit.row_bits
    }
    pub fn digest(self) -> Digest {
        let mut h = hasher(b"pvac.native.nat.profile");
        for size in [
            self.max_terms,
            self.out_terms,
            self.max_slots,
            self.max_queries,
            self.alpha_bits,
            self.row_bits,
        ] {
            acc_size(&mut h, size);
        }
        h.finalize().into()
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProductionGate {
    pub admitted: bool,
    pub key: bool,
    pub profile: bool,
    pub budget: bool,
    pub rejects_key: bool,
    pub rejects_profile: bool,
    pub rejects_budget: bool,
    pub rejects_sha_compat: bool,
    pub rejects_underbudget: bool,
    pub rejects_trace_wide: bool,
    pub rejects_output_wide: bool,
    pub rejects_proof_wide: bool,
}
pub fn production_budget() -> Budget {
    Budget {
        max_output_tags: 64,
        ..Budget::default()
    }
}
pub fn production_budget_allowed(budget: Budget) -> bool {
    let limit = production_budget();
    budget.proof == Kind::FieldNative
        && budget.target_bits >= limit.target_bits
        && budget.max_trace_units <= limit.max_trace_units
        && budget.max_output_tags <= limit.max_output_tags
        && budget.max_proof_bytes <= limit.max_proof_bytes
}
pub fn secret_cipher_safe(public: &PublicKey, cipher: &Cipher) -> bool {
    cipher.compatible_with(public)
        && !cipher.layers.is_empty()
        && !decrypt::has_native_source(public, cipher)
        && cipher.layers.iter().all(|layer| {
            layer.rule == 0 && layer.r_pc.len() == cipher.slots && layer.pc.len() == cipher.slots
        })
}
pub fn seed(domain: &Digest, kind: u64, id: u64) -> Zeroizing<Digest> {
    let mut h = hasher(b"pvac.native.rku.seed");
    h.update(domain);
    h.update(kind.to_le_bytes());
    h.update(id.to_le_bytes());
    Zeroizing::new(h.finalize().into())
}
impl Key {
    pub fn new(
        public: &PublicKey,
        secret: &SecretKey,
        queries: usize,
        budget: Budget,
    ) -> Result<Self, Error> {
        let key = digest::public_key(public)?;
        let secret_digest = digest::secret_key(public, secret)?;
        let domain = digest::pair(b"pvac.native.rku.dom", &key, &secret_digest);
        let policy = Policy::reusable(queries);
        let mut encrypted_secret = r1cs::allocate(secret.prf_key.len())?;
        for (index, value) in secret.prf_key.iter().enumerate() {
            let seed = seed(&domain, 1, index as u64);
            encrypted_secret.push(encrypt::value_seeded(public, secret, *value, &seed)?);
        }
        let mut result = Self {
            key,
            domain,
            view: [0; 32],
            encrypted_secret,
            policy,
            budget,
            prf: secret.prf_key.len(),
            lpn: 0,
            safe: policy.admitted(),
        };
        result.view = result.digest(public)?;
        if !result.is_safe(public)? {
            return Err(Error("pvac: reusable recrypt key rejected"));
        }
        Ok(result)
    }
    pub fn digest(&self, public: &PublicKey) -> Result<Digest, Error> {
        let mut h = hasher(b"pvac.native.rku.view");
        h.update(self.key);
        h.update(self.domain);
        for size in [self.prf, self.lpn, self.policy.max_queries] {
            acc_size(&mut h, size);
        }
        for flag in [
            self.policy.reusable,
            self.policy.hidden_output,
            self.policy.statement_bound,
            self.policy.transcript_bound,
            self.policy.material_bound,
            self.policy.no_basis_oracle,
            self.policy.native_backend,
        ] {
            acc_bool(&mut h, flag);
        }
        let cert = match self.policy.certificate {
            Certificate::None => 0,
            Certificate::Native => 1,
            Certificate::Unknown(tag) => tag,
        };
        acc_size(&mut h, cert as usize);
        let proof = match self.budget.proof {
            Kind::None => 0,
            Kind::FieldNative => 1,
            Kind::ShaCompat => 2,
            Kind::Unknown(tag) => tag,
        };
        acc_size(&mut h, proof as usize);
        for size in [
            self.budget.target_bits,
            self.budget.max_trace_units,
            self.budget.max_output_tags,
            self.budget.max_proof_bytes,
            self.encrypted_secret.len(),
        ] {
            acc_size(&mut h, size);
        }
        for cipher in &self.encrypted_secret {
            h.update(digest::cipher(public, cipher)?);
        }
        Ok(h.finalize().into())
    }
    pub fn is_safe(&self, public: &PublicKey) -> Result<bool, Error> {
        if !digest_eq(&self.key, &digest::public_key(public)?)
            || !self.safe
            || !self.policy.admitted()
            || self.prf != 4
            || self.lpn != 0
            || self.encrypted_secret.len() != self.prf
            || !self
                .encrypted_secret
                .iter()
                .all(|cipher| secret_cipher_safe(public, cipher))
        {
            return Ok(false);
        }
        Ok(digest_eq(&self.view, &self.digest(public)?))
    }
    pub fn production_gate(
        &self,
        public: &PublicKey,
        admission: Admission,
    ) -> Result<ProductionGate, Error> {
        let limit = production_budget();
        let mut gate = ProductionGate {
            key: self.is_safe(public)?
                && self.policy.max_queries <= Admission::production().max_queries,
            profile: admission.production_allowed(),
            budget: production_budget_allowed(self.budget),
            rejects_sha_compat: self.budget.proof != Kind::FieldNative,
            rejects_underbudget: self.budget.target_bits < limit.target_bits,
            rejects_trace_wide: self.budget.max_trace_units > limit.max_trace_units,
            rejects_output_wide: self.budget.max_output_tags > limit.max_output_tags,
            rejects_proof_wide: self.budget.max_proof_bytes > limit.max_proof_bytes,
            ..ProductionGate::default()
        };
        gate.rejects_key = !gate.key;
        gate.rejects_profile = !gate.profile;
        gate.rejects_budget = !gate.budget;
        gate.admitted = gate.key && gate.profile && gate.budget;
        Ok(gate)
    }
}
