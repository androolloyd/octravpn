// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Statement-bound native hidden reset policy, commitments, and resource decisions.
use super::{
    hidden::{self, acc_bool, acc_size, digest_eq, hasher, Certificate, Digest},
    profile,
};
use crate::{field::Fp, proof::r1cs, Error};
use sha2::Digest as _;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    pub reusable: bool,
    pub hidden_output: bool,
    pub statement_bound: bool,
    pub transcript_bound: bool,
    pub material_bound: bool,
    pub no_basis_oracle: bool,
    pub native_backend: bool,
    pub max_queries: usize,
    pub certificate: Certificate,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            reusable: true,
            hidden_output: true,
            statement_bound: false,
            transcript_bound: false,
            material_bound: false,
            no_basis_oracle: false,
            native_backend: false,
            max_queries: 0,
            certificate: Certificate::None,
        }
    }
}
impl Policy {
    pub fn reusable(max_queries: usize) -> Self {
        Self {
            reusable: true,
            hidden_output: true,
            statement_bound: true,
            transcript_bound: true,
            material_bound: true,
            no_basis_oracle: true,
            native_backend: true,
            max_queries,
            certificate: Certificate::Native,
        }
    }
    pub fn admitted(self) -> bool {
        self.reusable
            && self.hidden_output
            && self.statement_bound
            && self.transcript_bound
            && self.material_bound
            && self.no_basis_oracle
            && self.native_backend
            && self.max_queries != 0
            && self.certificate == Certificate::Native
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MaterialKind {
    #[default]
    None,
    HiddenCarrier,
    VisibleCoefficients,
    RawRows,
    Unknown(u8),
}
impl MaterialKind {
    fn tag(self) -> u8 {
        match self {
            Self::None => 0,
            Self::HiddenCarrier => 1,
            Self::VisibleCoefficients => 2,
            Self::RawRows => 3,
            Self::Unknown(tag) => tag,
        }
    }
}
#[derive(Clone, Default)]
pub struct Material {
    pub kind: MaterialKind,
    pub coefficients: hidden::Material,
    pub target_terms: usize,
    pub slots: usize,
    pub reusable: bool,
    pub has_raw_rows: bool,
    pub visible_coefficients: bool,
    pub hides_rows: bool,
    pub no_basis_oracle: bool,
    pub native_backend: bool,
}
#[derive(Clone, Default)]
pub struct Statement {
    pub coefficients: hidden::Statement,
    pub target_terms: usize,
    pub slots: usize,
    pub query: usize,
}
#[derive(Clone)]
pub struct Output {
    pub target_terms: usize,
    pub slots: usize,
    pub coefficient_tags: Vec<Digest>,
    pub material_digest: Digest,
    pub statement_digest: Digest,
    pub output_digest: Digest,
    pub hidden_coefficients: bool,
    pub visible_beta: bool,
}
impl Default for Output {
    fn default() -> Self {
        Self {
            target_terms: 0,
            slots: 0,
            coefficient_tags: vec![],
            material_digest: [0; 32],
            statement_digest: [0; 32],
            output_digest: [0; 32],
            hidden_coefficients: false,
            visible_beta: true,
        }
    }
}
#[derive(Clone, Default)]
pub struct Transcript {
    pub plan: hidden::Plan,
    pub material_digest: Digest,
    pub statement_digest: Digest,
    pub output_digest: Digest,
    pub transcript_digest: Digest,
    pub statement_bound: bool,
    pub material_bound: bool,
    pub hidden_output: bool,
    pub no_basis_oracle: bool,
    pub native_backend: bool,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Decision {
    pub admitted: bool,
    pub policy: bool,
    pub material: bool,
    pub statement: bool,
    pub output: bool,
    pub transcript: bool,
    pub privacy: bool,
    pub rejects_raw: bool,
    pub rejects_visible: bool,
    pub rejects_unbound: bool,
    pub rejects_basis_oracle: bool,
    pub rejects_query_budget: bool,
    pub rejects_wide: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    pub proof: profile::Kind,
    pub target_bits: usize,
    pub max_trace_units: usize,
    pub max_output_tags: usize,
    pub max_proof_bytes: usize,
}
impl Default for Budget {
    fn default() -> Self {
        Self {
            proof: profile::Kind::FieldNative,
            target_bits: 128,
            max_trace_units: 1024,
            max_output_tags: 1 << 16,
            max_proof_bytes: 1 << 20,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReusableDecision {
    pub chosen: Decision,
    pub profile: profile::Profile,
    pub output_digest: Digest,
    pub material_digest: Digest,
    pub statement_digest: Digest,
    pub admitted: bool,
    pub privacy: bool,
    pub proof: bool,
    pub compact: bool,
    pub output: bool,
    pub budget: bool,
    pub rejects_sha_compat: bool,
    pub rejects_noncompact: bool,
    pub rejects_underbudget: bool,
    pub rejects_output_wide: bool,
    pub rejects_proof_wide: bool,
}
impl Material {
    pub fn new(
        coefficients: hidden::Material,
        target_terms: usize,
        slots: usize,
    ) -> Result<Self, Error> {
        if target_terms == 0 || slots == 0 {
            return Err(Error("pvac: native chosen material shape rejected"));
        }
        Ok(Self {
            kind: MaterialKind::HiddenCarrier,
            coefficients,
            target_terms,
            slots,
            reusable: true,
            hides_rows: true,
            no_basis_oracle: true,
            native_backend: true,
            ..Self::default()
        })
    }
    pub fn digest(&self) -> Digest {
        let mut h = hasher(b"pvac.native.reset.chosen.material");
        acc_size(&mut h, self.kind.tag() as usize);
        h.update(self.coefficients.digest());
        acc_size(&mut h, self.target_terms);
        acc_size(&mut h, self.slots);
        for flag in [
            self.reusable,
            self.has_raw_rows,
            self.visible_coefficients,
            self.hides_rows,
            self.no_basis_oracle,
            self.native_backend,
        ] {
            acc_bool(&mut h, flag);
        }
        h.finalize().into()
    }
    pub fn admitted(&self) -> bool {
        self.kind == MaterialKind::HiddenCarrier
            && self.reusable
            && !self.has_raw_rows
            && !self.visible_coefficients
            && self.hides_rows
            && self.no_basis_oracle
            && self.native_backend
            && self.target_terms != 0
            && self.slots != 0
            && self.coefficients.row_tags.len() == self.coefficients.bound.terms
    }
}
impl Statement {
    pub fn new(
        alpha: &[Fp],
        bound: hidden::Bound,
        target_terms: usize,
        slots: usize,
        query: usize,
    ) -> Result<Self, Error> {
        Ok(Self {
            coefficients: hidden::Statement::new(alpha, bound)?,
            target_terms,
            slots,
            query,
        })
    }
    pub fn digest(&self) -> Digest {
        let mut h = hasher(b"pvac.native.reset.chosen.statement");
        h.update(self.coefficients.digest());
        for size in [self.target_terms, self.slots, self.query] {
            acc_size(&mut h, size);
        }
        h.finalize().into()
    }
    pub fn admitted(&self, material: &Material, policy: Policy) -> bool {
        self.coefficients.alpha.len() == material.coefficients.bound.terms
            && self.coefficients.bound == material.coefficients.bound
            && self.target_terms == material.target_terms
            && self.slots == material.slots
            && self.query < policy.max_queries
    }
}
pub fn coefficient_tag(
    material: &Material,
    statement: &Statement,
    target: usize,
    slot: usize,
) -> Digest {
    let mut h = hasher(b"pvac.native.reset.chosen.output.coeff");
    h.update(material.digest());
    h.update(statement.digest());
    acc_size(&mut h, target);
    acc_size(&mut h, slot);
    h.finalize().into()
}
impl Output {
    pub fn new(material: &Material, statement: &Statement) -> Result<Self, Error> {
        if material.target_terms == 0 || material.slots == 0 {
            return Err(Error("pvac: native hidden output material shape rejected"));
        }
        if statement.target_terms != material.target_terms || statement.slots != material.slots {
            return Err(Error("pvac: native hidden output statement shape rejected"));
        }
        let count = statement
            .target_terms
            .checked_mul(statement.slots)
            .ok_or(Error("pvac: native hidden output size rejected"))?;
        let mut coefficient_tags = r1cs::allocate(count)?;
        for target in 0..statement.target_terms {
            for slot in 0..statement.slots {
                coefficient_tags.push(coefficient_tag(material, statement, target, slot));
            }
        }
        let mut out = Self {
            target_terms: statement.target_terms,
            slots: statement.slots,
            coefficient_tags,
            material_digest: material.digest(),
            statement_digest: statement.digest(),
            output_digest: [0; 32],
            hidden_coefficients: true,
            visible_beta: false,
        };
        out.output_digest = out.digest();
        Ok(out)
    }
    pub fn digest(&self) -> Digest {
        let mut h = hasher(b"pvac.native.reset.chosen.output");
        for size in [self.target_terms, self.slots, self.coefficient_tags.len()] {
            acc_size(&mut h, size);
        }
        for tag in &self.coefficient_tags {
            h.update(tag);
        }
        h.update(self.material_digest);
        h.update(self.statement_digest);
        acc_bool(&mut h, self.hidden_coefficients);
        acc_bool(&mut h, self.visible_beta);
        h.finalize().into()
    }
    pub fn admitted(&self, material: &Material, statement: &Statement) -> bool {
        if self.target_terms != material.target_terms
            || self.slots != material.slots
            || !self.hidden_coefficients
            || self.visible_beta
            || !digest_eq(&self.material_digest, &material.digest())
            || !digest_eq(&self.statement_digest, &statement.digest())
        {
            return false;
        }
        // Native divides by slots unchecked here; reject that undefined case.
        if self.slots == 0
            || self.target_terms.checked_mul(self.slots) != Some(self.coefficient_tags.len())
        {
            return false;
        }
        for target in 0..self.target_terms {
            for slot in 0..self.slots {
                if !digest_eq(
                    &self.coefficient_tags[target * self.slots + slot],
                    &coefficient_tag(material, statement, target, slot),
                ) {
                    return false;
                }
            }
        }
        digest_eq(&self.output_digest, &self.digest())
    }
}
impl Transcript {
    pub fn new(material: &Material, statement: &Statement, output: &Output) -> Self {
        let mut transcript = Self {
            plan: hidden::plan(statement.coefficients.bound),
            material_digest: material.digest(),
            statement_digest: statement.digest(),
            output_digest: output.digest(),
            statement_bound: true,
            material_bound: true,
            hidden_output: true,
            no_basis_oracle: true,
            native_backend: true,
            transcript_digest: [0; 32],
        };
        transcript.transcript_digest = transcript.digest();
        transcript
    }
    pub fn digest(&self) -> Digest {
        let mut h = hasher(b"pvac.native.reset.chosen.transcript");
        h.update(self.material_digest);
        h.update(self.statement_digest);
        h.update(self.output_digest);
        acc_size(&mut h, self.plan.sum_bits);
        for flag in [
            self.plan.needs_p_correction,
            self.plan.needs_wide_correction,
            self.plan.admitted,
            self.statement_bound,
            self.material_bound,
            self.hidden_output,
            self.no_basis_oracle,
            self.native_backend,
        ] {
            acc_bool(&mut h, flag);
        }
        h.finalize().into()
    }
}
pub fn decide(
    policy: Policy,
    material: &Material,
    statement: &Statement,
    output: &Output,
    transcript: &Transcript,
) -> Decision {
    let plan = hidden::plan(statement.coefficients.bound);
    let mut d = Decision {
        policy: policy.admitted(),
        material: material.admitted(),
        rejects_raw: material.kind == MaterialKind::RawRows || material.has_raw_rows,
        rejects_visible: material.kind == MaterialKind::VisibleCoefficients
            || material.visible_coefficients
            || output.visible_beta
            || !output.hidden_coefficients,
        rejects_unbound: !policy.statement_bound
            || !policy.transcript_bound
            || !policy.material_bound
            || !transcript.statement_bound
            || !transcript.material_bound
            || !transcript.hidden_output
            || !transcript.native_backend,
        rejects_basis_oracle: !policy.no_basis_oracle
            || !material.no_basis_oracle
            || !material.hides_rows
            || !transcript.no_basis_oracle,
        rejects_query_budget: statement.query >= policy.max_queries,
        rejects_wide: plan.needs_wide_correction,
        ..Decision::default()
    };
    d.statement = d.material && statement.admitted(material, policy);
    d.output = d.statement && output.admitted(material, statement);
    d.privacy = d.policy
        && d.material
        && d.output
        && !d.rejects_raw
        && !d.rejects_visible
        && !d.rejects_unbound
        && !d.rejects_basis_oracle
        && !d.rejects_query_budget
        && !d.rejects_wide;
    d.transcript = d.privacy
        && transcript.plan == plan
        && digest_eq(&transcript.material_digest, &material.digest())
        && digest_eq(&transcript.statement_digest, &statement.digest())
        && digest_eq(&transcript.output_digest, &output.digest())
        && digest_eq(&transcript.transcript_digest, &transcript.digest());
    d.admitted = d.privacy && d.transcript && plan.admitted;
    d
}
pub fn decide_reusable(
    policy: Policy,
    material: &Material,
    statement: &Statement,
    output: &Output,
    transcript: &Transcript,
    budget: Budget,
) -> ReusableDecision {
    let chosen = decide(policy, material, statement, output, transcript);
    let profile = profile::plan(budget.proof, budget.target_bits);
    let mut d = ReusableDecision {
        chosen,
        profile,
        output_digest: output.output_digest,
        material_digest: output.material_digest,
        statement_digest: output.statement_digest,
        privacy: chosen.admitted,
        rejects_sha_compat: budget.proof != profile::Kind::FieldNative,
        rejects_underbudget: !profile.admitted
            || !profile.params.admitted()
            || profile.soundness_bits < budget.target_bits,
        rejects_noncompact: profile.trace_units > budget.max_trace_units,
        rejects_output_wide: output.coefficient_tags.is_empty()
            || output.coefficient_tags.len() > budget.max_output_tags,
        rejects_proof_wide: profile.total_bytes == usize::MAX
            || profile.total_bytes > budget.max_proof_bytes,
        ..ReusableDecision::default()
    };
    d.proof = !d.rejects_sha_compat && !d.rejects_underbudget;
    d.compact = d.proof && !d.rejects_noncompact && !d.rejects_proof_wide;
    d.output =
        d.privacy && output.hidden_coefficients && !output.visible_beta && !d.rejects_output_wide;
    d.budget =
        d.compact && d.output && policy.max_queries != 0 && statement.query < policy.max_queries;
    d.admitted = d.privacy && d.proof && d.compact && d.output && d.budget;
    d
}
