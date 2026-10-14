// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native hidden-coefficient commitments and admission policy.
use crate::{field::Fp, proof::r1cs, Error};
use sha2::{Digest as _, Sha256};
pub type Digest = [u8; 32];
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Certificate {
    #[default]
    None,
    Native,
    Unknown(u8),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    pub reusable: bool,
    pub visible_output: bool,
    pub statement_bound: bool,
    pub transcript_bound: bool,
    pub certificate: Certificate,
}
impl Default for Profile {
    fn default() -> Self {
        Self {
            reusable: true,
            visible_output: false,
            statement_bound: false,
            transcript_bound: false,
            certificate: Certificate::None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    pub admitted: bool,
    pub rejects_basis_oracle: bool,
    pub needs_native_certificate: bool,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bound {
    pub terms: usize,
    pub alpha_bits: usize,
    pub row_bits: usize,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub sum_bits: usize,
    pub needs_p_correction: bool,
    pub needs_wide_correction: bool,
    pub admitted: bool,
}
#[derive(Clone, Default)]
pub struct Material {
    pub row_tags: Vec<Digest>,
    pub bound: Bound,
}
#[derive(Clone, Default)]
pub struct Statement {
    pub alpha: Vec<Fp>,
    pub bound: Bound,
}
#[derive(Clone, Default)]
pub struct Transcript {
    pub aggregate_tag: Digest,
    pub plan: Plan,
    pub material_digest: Digest,
    pub statement_digest: Digest,
}
pub fn plan(bound: Bound) -> Plan {
    let bits = usize::BITS - bound.terms.saturating_sub(1).leading_zeros();
    let sum_bits = bound
        .alpha_bits
        .wrapping_add(bound.row_bits)
        .wrapping_add(bits as usize);
    Plan {
        sum_bits,
        needs_p_correction: sum_bits >= 127,
        needs_wide_correction: sum_bits >= 252,
        admitted: bound.terms != 0 && bound.alpha_bits <= 127 && bound.row_bits <= 127,
    }
}
pub(crate) fn hasher(domain: &[u8]) -> Sha256 {
    let mut h = Sha256::new();
    h.update(domain);
    h
}
pub(crate) fn acc_size(h: &mut Sha256, size: usize) {
    h.update((size as u64).to_le_bytes());
}
pub(crate) fn acc_bool(h: &mut Sha256, value: bool) {
    acc_size(h, usize::from(value));
}
pub(crate) fn digest_eq(a: &Digest, b: &Digest) -> bool {
    a.iter().zip(b).fold(0_u8, |diff, (a, b)| diff | (a ^ b)) == 0
}
fn acc_bound(h: &mut Sha256, bound: Bound) {
    for size in [bound.terms, bound.alpha_bits, bound.row_bits] {
        acc_size(h, size);
    }
}
impl Material {
    pub fn new(row_tags: &[Digest], bound: Bound) -> Result<Self, Error> {
        if row_tags.is_empty() {
            return Err(Error("pvac: native hidden coefficient material is empty"));
        }
        if row_tags.len() != bound.terms {
            return Err(Error(
                "pvac: native hidden coefficient material bound mismatch",
            ));
        }
        let mut tags = r1cs::allocate(row_tags.len())?;
        tags.extend_from_slice(row_tags);
        Ok(Self {
            row_tags: tags,
            bound,
        })
    }
    pub fn digest(&self) -> Digest {
        let mut h = hasher(b"pvac.native.reset.material");
        acc_bound(&mut h, self.bound);
        acc_size(&mut h, self.row_tags.len());
        for tag in &self.row_tags {
            h.update(tag);
        }
        h.finalize().into()
    }
}
impl Statement {
    pub fn new(alpha: &[Fp], bound: Bound) -> Result<Self, Error> {
        if alpha.is_empty() {
            return Err(Error("pvac: native hidden coefficient statement is empty"));
        }
        if alpha.len() != bound.terms {
            return Err(Error(
                "pvac: native hidden coefficient statement bound mismatch",
            ));
        }
        let mut values = r1cs::allocate(alpha.len())?;
        values.extend_from_slice(alpha);
        Ok(Self {
            alpha: values,
            bound,
        })
    }
    pub fn digest(&self) -> Digest {
        let mut h = hasher(b"pvac.native.reset.statement");
        acc_bound(&mut h, self.bound);
        acc_size(&mut h, self.alpha.len());
        for alpha in &self.alpha {
            h.update(alpha.to_bytes_le());
        }
        h.finalize().into()
    }
}
pub fn decide(profile: Profile) -> Decision {
    let rejects_basis_oracle = !(profile.reusable && profile.visible_output);
    let needs_native_certificate = profile.certificate != Certificate::Native;
    Decision {
        rejects_basis_oracle,
        needs_native_certificate,
        admitted: rejects_basis_oracle
            && !needs_native_certificate
            && profile.statement_bound
            && profile.transcript_bound,
    }
}
pub fn require(profile: Profile) -> Result<(), Error> {
    if decide(profile).admitted {
        Ok(())
    } else {
        Err(Error("pvac: native hidden coefficient profile rejected"))
    }
}
pub fn aggregate_tag(material: &Material, statement: &Statement, plan: Plan) -> Digest {
    let mut h = hasher(b"pvac.native.reset.aggregate");
    h.update(material.digest());
    h.update(statement.digest());
    acc_size(&mut h, plan.sum_bits);
    acc_bool(&mut h, plan.needs_p_correction);
    acc_bool(&mut h, plan.needs_wide_correction);
    h.finalize().into()
}
impl Transcript {
    pub fn new(material: &Material, statement: &Statement) -> Result<Self, Error> {
        if material.row_tags.len() != statement.alpha.len() {
            return Err(Error("pvac: native hidden coefficient shape mismatch"));
        }
        let plan = plan(statement.bound);
        Ok(Self {
            plan,
            material_digest: material.digest(),
            statement_digest: statement.digest(),
            aggregate_tag: aggregate_tag(material, statement, plan),
        })
    }
    pub fn verify(&self, material: &Material, statement: &Statement) -> bool {
        let plan = plan(statement.bound);
        material.row_tags.len() == statement.alpha.len()
            && plan.admitted
            && self.plan == plan
            && digest_eq(&self.material_digest, &material.digest())
            && digest_eq(&self.statement_digest, &statement.digest())
            && digest_eq(
                &self.aggregate_tag,
                &aggregate_tag(material, statement, plan),
            )
    }
}
pub fn public_reset_admitted(profile: Profile, plan: Plan) -> bool {
    decide(profile).admitted && plan.admitted && !plan.needs_wide_correction
}
