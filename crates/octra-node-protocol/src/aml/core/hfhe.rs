// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_hfhe symbolic term/slot/query admission and production proof accounting.
use super::{
    fhe,
    rule::{Field as RuleField, LOCAL},
    syntax::Name,
    Natural,
};
use num_bigint::BigInt;
use num_traits::Zero;
use std::collections::BTreeMap;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admission {
    id: Natural,
    terms: Natural,
    out: Natural,
    slots: Natural,
    queries: Natural,
    alpha: Natural,
    row: Natural,
}
impl Admission {
    pub fn id(&self) -> Natural {
        self.id
    }
    pub fn terms(&self) -> Natural {
        self.terms
    }
    pub fn output(&self) -> Natural {
        self.out
    }
    pub fn slots(&self) -> Natural {
        self.slots
    }
    pub fn queries(&self) -> Natural {
        self.queries
    }
    pub fn alpha(&self) -> Natural {
        self.alpha
    }
    pub fn row(&self) -> Natural {
        self.row
    }
    pub fn valid(&self) -> bool {
        self.terms.get() > 0
            && self.out.get() > 0
            && self.out <= self.terms
            && self.slots.get() > 0
            && self.queries.get() > 0
            && self.alpha.get() > 0
            && self.row.get() > 0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proof {
    Field,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofPlan {
    rounds: BigInt,
    sound: BigInt,
    commits: BigInt,
    opens: BigInt,
    trace: BigInt,
    commit_bytes: BigInt,
    open_bytes: BigInt,
    trace_bytes: BigInt,
    total: BigInt,
}
impl ProofPlan {
    fn new(bits: &BigInt) -> Self {
        let rounds = div_up(&(bits * 1000), &BigInt::from(584));
        let sound = (&rounds * 584) / 1000;
        let commits = &rounds * 3;
        let opens = rounds.clone();
        let trace = &commits + &opens;
        let bytes = |units: &BigInt| units * 32 + 128;
        let commit_bytes = bytes(&commits);
        let open_bytes = bytes(&opens);
        let trace_bytes = bytes(&trace);
        let total = &commit_bytes + &open_bytes + &trace_bytes;
        Self {
            rounds,
            sound,
            commits,
            opens,
            trace,
            commit_bytes,
            open_bytes,
            trace_bytes,
            total,
        }
    }
    pub fn rounds(&self) -> &BigInt {
        &self.rounds
    }
    pub fn sound(&self) -> &BigInt {
        &self.sound
    }
    pub fn commits(&self) -> &BigInt {
        &self.commits
    }
    pub fn opens(&self) -> &BigInt {
        &self.opens
    }
    pub fn trace(&self) -> &BigInt {
        &self.trace
    }
    pub fn commit_bytes(&self) -> &BigInt {
        &self.commit_bytes
    }
    pub fn open_bytes(&self) -> &BigInt {
        &self.open_bytes
    }
    pub fn trace_bytes(&self) -> &BigInt {
        &self.trace_bytes
    }
    pub fn total(&self) -> &BigInt {
        &self.total
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    proof: Proof,
    bits: BigInt,
    traces: BigInt,
    tags: BigInt,
    bytes: BigInt,
    plan: ProofPlan,
}
impl Certificate {
    pub fn proof(&self) -> Proof {
        self.proof
    }
    pub fn bits(&self) -> &BigInt {
        &self.bits
    }
    pub fn traces(&self) -> &BigInt {
        &self.traces
    }
    pub fn tags(&self) -> &BigInt {
        &self.tags
    }
    pub fn bytes(&self) -> &BigInt {
        &self.bytes
    }
    pub fn plan(&self) -> &ProofPlan {
        &self.plan
    }
    pub fn valid(&self) -> bool {
        self.bits >= BigInt::from(128)
            && self.traces > BigInt::zero()
            && self.tags > BigInt::zero()
            && self.bytes > BigInt::zero()
            && self.plan == ProofPlan::new(&self.bits)
            && self.plan.sound >= self.bits
            && self.plan.trace <= self.traces
            && self.plan.total <= self.bytes
    }
}
fn fixed(value: u32) -> Natural {
    Natural::from_u32(value).expect("fixed HFHE natural")
}
pub fn production() -> Admission {
    Admission {
        id: fixed(1),
        terms: fixed(32),
        out: fixed(4),
        slots: fixed(8),
        queries: fixed(64),
        alpha: fixed(8),
        row: fixed(8),
    }
}
pub fn production_certificate() -> Certificate {
    let bits = BigInt::from(128);
    let plan = ProofPlan::new(&bits);
    Certificate {
        proof: Proof::Field,
        bits,
        traces: BigInt::from(1024),
        tags: BigInt::from(64),
        bytes: BigInt::from(1_048_576),
        plan,
    }
}
fn div_up(value: &BigInt, unit: &BigInt) -> BigInt {
    (value + unit - 1) / unit
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Terms,
    Slots,
    Query,
    Tags,
    Resets,
}
impl Field {
    fn text(self) -> &'static str {
        match self {
            Self::Terms => "terms",
            Self::Slots => "slots",
            Self::Query => "query",
            Self::Tags => "tags",
            Self::Resets => "resets",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    terms: Natural,
    slots: Natural,
    query: Natural,
    tags: Natural,
}
impl Shape {
    pub fn terms(self) -> Natural {
        self.terms
    }
    pub fn slots(self) -> Natural {
        self.slots
    }
    pub fn query(self) -> Natural {
        self.query
    }
    pub fn tags(self) -> Natural {
        self.tags
    }
    pub fn text(self) -> Vec<u8> {
        format!(
            "hfhe[terms={},slots={},query={},tags={}]",
            self.terms.get(),
            self.slots.get(),
            self.query.get(),
            self.tags.get()
        )
        .into_bytes()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    name: Name,
    terms: BigInt,
    slots: BigInt,
    query: BigInt,
}
impl Input {
    pub fn new(name: Name, terms: BigInt, slots: BigInt, query: BigInt) -> Self {
        Self {
            name,
            terms,
            slots,
            query,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Environment(BTreeMap<Name, Shape>);
impl Environment {
    pub fn new(admission: &Admission, inputs: &[Input]) -> Result<Self> {
        let mut out = BTreeMap::new();
        let limit = LOCAL.get(RuleField::Inputs) as usize;
        for (count, input) in inputs.iter().enumerate() {
            if count == limit {
                return Err(Error::InputCount(limit, limit + 1));
            }
            if out.contains_key(&input.name) {
                return Err(Error::InputDuplicate(input.name.text().to_vec()));
            }
            let terms = positive(Field::Terms, &input.terms)?;
            let slots = positive(Field::Slots, &input.slots)?;
            let query = nat(Field::Query, &input.query)?;
            within(Field::Terms, terms, admission.terms)?;
            within(Field::Slots, slots, admission.slots)?;
            if query >= admission.queries {
                return Err(Error::Limit(Field::Query, query, admission.queries));
            }
            out.insert(input.name.clone(), shaped(terms, slots, query)?);
        }
        Ok(Self(out))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    shape: Shape,
    peak: Natural,
    peak_tags: Natural,
    resets: Natural,
}
impl Info {
    pub fn shape(self) -> Shape {
        self.shape
    }
    pub fn peak(self) -> Natural {
        self.peak
    }
    pub fn peak_tags(self) -> Natural {
        self.peak_tags
    }
    pub fn resets(self) -> Natural {
        self.resets
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Natural(Field, BigInt),
    Zero(Field),
    InputDuplicate(Vec<u8>),
    InputCount(usize, usize),
    Free(Vec<u8>),
    Limit(Field, Natural, Natural),
    SlotNeed(Natural, Natural),
    ResetLimit(Natural, Natural),
    CertificateInvalid,
    CertificateLimit(Field, BigInt, BigInt),
    Depth(usize, usize),
    Nodes(usize, usize),
}
pub type Result<T> = std::result::Result<T, Error>;
fn nat(field: Field, raw: &BigInt) -> Result<Natural> {
    Natural::new(raw).ok_or_else(|| Error::Natural(field, raw.clone()))
}
fn positive(field: Field, raw: &BigInt) -> Result<Natural> {
    let value = nat(field, raw)?;
    if value.get() == 0 {
        Err(Error::Zero(field))
    } else {
        Ok(value)
    }
}
fn within(field: Field, value: Natural, limit: Natural) -> Result<Natural> {
    if value <= limit {
        Ok(value)
    } else {
        Err(Error::Limit(field, value, limit))
    }
}
fn add(field: Field, left: Natural, right: Natural) -> Result<Natural> {
    nat(
        field,
        &(BigInt::from(left.get()) + BigInt::from(right.get())),
    )
}
fn multiply(field: Field, left: Natural, right: Natural) -> Result<Natural> {
    nat(
        field,
        &(BigInt::from(left.get()) * BigInt::from(right.get())),
    )
}
fn shaped(terms: Natural, slots: Natural, query: Natural) -> Result<Shape> {
    let tags = multiply(Field::Tags, terms, slots)?;
    Ok(Shape {
        terms,
        slots,
        query,
        tags,
    })
}
enum Task {
    Visit(fhe::TermId),
    Finish(fhe::Term),
}
pub fn check(
    admission: &Admission,
    certificate: &Certificate,
    environment: &Environment,
    terms: &fhe::Terms,
    root: fhe::TermId,
) -> Result<Info> {
    if !certificate.valid() {
        return Err(Error::CertificateInvalid);
    }
    terms.shape(root).map_err(|error| match error {
        fhe::Error::Depth(limit, actual) => Error::Depth(limit, actual),
        fhe::Error::Nodes(limit, actual) => Error::Nodes(limit, actual),
        _ => unreachable!("FHE shape diagnostics"),
    })?;
    let mut pending = vec![Task::Visit(root)];
    let mut values: Vec<Info> = Vec::new();
    while let Some(task) = pending.pop() {
        match task {
            Task::Visit(id) => {
                let term = terms.get(id).clone();
                match &term {
                    fhe::Term::Var(_) => (),
                    fhe::Term::Trim(_, body) | fhe::Term::Recrypt(body) => {
                        pending.push(Task::Finish(term.clone()));
                        pending.push(Task::Visit(*body));
                        continue;
                    }
                    fhe::Term::Add(left, right) | fhe::Term::Mul(left, right) => {
                        pending.push(Task::Finish(term.clone()));
                        pending.push(Task::Visit(*right));
                        pending.push(Task::Visit(*left));
                        continue;
                    }
                }
                pending.push(Task::Finish(term));
            }
            Task::Finish(term) => {
                let info = match term {
                    fhe::Term::Var(name) => {
                        let shape = environment
                            .0
                            .get(&name)
                            .copied()
                            .ok_or_else(|| Error::Free(name.text().to_vec()))?;
                        Info {
                            shape,
                            peak: shape.terms,
                            peak_tags: shape.tags,
                            resets: fixed(0),
                        }
                    }
                    fhe::Term::Trim(..) => values.pop().expect("HFHE trim prior"),
                    fhe::Term::Add(..) | fhe::Term::Mul(..) => {
                        let right = values.pop().expect("HFHE right prior");
                        let left = values.pop().expect("HFHE left prior");
                        if left.shape.slots != right.shape.slots {
                            return Err(Error::SlotNeed(left.shape.slots, right.shape.slots));
                        }
                        let count = if matches!(term, fhe::Term::Add(..)) {
                            add(Field::Terms, left.shape.terms, right.shape.terms)?
                        } else {
                            multiply(Field::Terms, left.shape.terms, right.shape.terms)?
                        };
                        let count = within(Field::Terms, count, admission.terms)?;
                        let query = left.shape.query.max(right.shape.query);
                        let resets = add(Field::Resets, left.resets, right.resets)?;
                        let shape = shaped(count, left.shape.slots, query)?;
                        Info {
                            shape,
                            peak: count.max(left.peak.max(right.peak)),
                            peak_tags: shape.tags.max(left.peak_tags.max(right.peak_tags)),
                            resets,
                        }
                    }
                    fhe::Term::Recrypt(_) => {
                        let prior = values.pop().expect("HFHE reset prior");
                        let query = add(Field::Query, prior.shape.query, fixed(1))?;
                        if query >= admission.queries {
                            return Err(Error::ResetLimit(prior.shape.query, admission.queries));
                        }
                        let resets = add(Field::Resets, prior.resets, fixed(1))?;
                        let shape = shaped(admission.out, prior.shape.slots, query)?;
                        Info {
                            shape,
                            peak: prior.peak.max(admission.out),
                            peak_tags: prior.peak_tags.max(shape.tags),
                            resets,
                        }
                    }
                };
                values.push(info);
            }
        }
    }
    let info = values.pop().expect("HFHE root");
    let actual = BigInt::from(info.shape.tags.get());
    if actual <= certificate.tags {
        Ok(info)
    } else {
        Err(Error::CertificateLimit(
            Field::Tags,
            actual,
            certificate.tags.clone(),
        ))
    }
}
impl Error {
    pub fn text(&self) -> Vec<u8> {
        let raw = match self {
            Self::Natural(field, value) => format!(
                "hfhe natural outside profile field = {} value = {value}",
                field.text()
            )
            .into_bytes(),
            Self::Zero(field) => {
                format!("hfhe field is zero field = {}", field.text()).into_bytes()
            }
            Self::InputDuplicate(name) => [b"duplicate hfhe input = ".as_slice(), name].concat(),
            Self::InputCount(limit, actual) => {
                format!("hfhe input count limit = {limit} actual = {actual}").into_bytes()
            }
            Self::Free(name) => [b"hfhe input is free = ".as_slice(), name].concat(),
            Self::Limit(field, value, limit) => format!(
                "hfhe field exceeds profile field = {} value = {} limit = {}",
                field.text(),
                value.get(),
                limit.get()
            )
            .into_bytes(),
            Self::SlotNeed(left, right) => format!(
                "hfhe slot mismatch left = {} right = {}",
                left.get(),
                right.get()
            )
            .into_bytes(),
            Self::ResetLimit(query, limit) => format!(
                "hfhe reset query exhausted query = {} limit = {}",
                query.get(),
                limit.get()
            )
            .into_bytes(),
            Self::CertificateInvalid => b"hfhe proof profile is invalid".to_vec(),
            Self::CertificateLimit(field, value, limit) => format!(
                "hfhe proof limit exceeded field = {} value = {value} limit = {limit}",
                field.text()
            )
            .into_bytes(),
            Self::Depth(limit, actual) => {
                format!("hfhe term depth limit = {limit} actual = {actual}").into_bytes()
            }
            Self::Nodes(limit, actual) => {
                format!("hfhe term nodes limit = {limit} actual = {actual}").into_bytes()
            }
        };
        super::text::clip(&raw)
    }
}
