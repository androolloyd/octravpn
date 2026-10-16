// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_hpar parameter sealing and staged FHE/HFHE linkage. Static validation
//! selects an explicit parameter set; it does not mint encryption evidence.
use super::{
    entropy, fhe, graph, hfhe,
    rule::{Field, LOCAL},
    Natural,
};
pub use entropy::{Error as EntropyError, Plan as EntropyPlan};
pub use graph::{Config as GraphConfig, Error as GraphError};
use num_bigint::BigInt;
use num_traits::{One, Zero};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParameterSet {
    id: Natural,
    key: Natural,
    field_bits: BigInt,
    basis: BigInt,
    rows: BigInt,
    columns: BigInt,
    h_weight: BigInt,
    x_weight: BigInt,
    e_weight: BigInt,
    edges: BigInt,
    ln: BigInt,
    lt: BigInt,
    tn: BigInt,
    td: BigInt,
    proof: BigInt,
    admission: hfhe::Admission,
    certificate: hfhe::Certificate,
}
impl ParameterSet {
    pub fn id(&self) -> Natural {
        self.id
    }
    pub fn key(&self) -> Natural {
        self.key
    }
    pub fn field_bits(&self) -> &BigInt {
        &self.field_bits
    }
    pub fn basis(&self) -> &BigInt {
        &self.basis
    }
    pub fn rows(&self) -> &BigInt {
        &self.rows
    }
    pub fn columns(&self) -> &BigInt {
        &self.columns
    }
    pub fn h_weight(&self) -> &BigInt {
        &self.h_weight
    }
    pub fn x_weight(&self) -> &BigInt {
        &self.x_weight
    }
    pub fn e_weight(&self) -> &BigInt {
        &self.e_weight
    }
    pub fn edges(&self) -> &BigInt {
        &self.edges
    }
    pub fn ln(&self) -> &BigInt {
        &self.ln
    }
    pub fn lt(&self) -> &BigInt {
        &self.lt
    }
    pub fn tn(&self) -> &BigInt {
        &self.tn
    }
    pub fn td(&self) -> &BigInt {
        &self.td
    }
    pub fn proof(&self) -> &BigInt {
        &self.proof
    }
    pub fn admission(&self) -> &hfhe::Admission {
        &self.admission
    }
    pub fn certificate(&self) -> &hfhe::Certificate {
        &self.certificate
    }
    pub fn valid(&self) -> bool {
        self.id.get() != 0
            && self.key.get() != 0
            && self.key == self.admission.id()
            && self.field_bits == BigInt::from(127)
            && self.basis >= BigInt::from(3)
            && self.basis <= BigInt::from(65_536)
            && self.basis == BigInt::from(entropy::BASIS)
            && ((BigInt::one() << 127_usize) - BigInt::from(2)) % &self.basis == BigInt::zero()
            && self.rows > BigInt::zero()
            && self.columns > BigInt::zero()
            && self.h_weight >= BigInt::zero()
            && self.h_weight <= self.rows
            && self.x_weight >= BigInt::zero()
            && self.x_weight <= self.columns
            && self.e_weight >= BigInt::zero()
            && self.e_weight <= self.rows
            && self.edges > BigInt::zero()
            && self.ln > BigInt::zero()
            && self.lt >= BigInt::from(127)
            && self.tn > BigInt::zero()
            && self.td > BigInt::zero()
            && self.tn <= self.td
            && self.proof == BigInt::from(4)
            && self.admission.valid()
            && self.certificate.valid()
            && self.certificate.tags() <= &self.edges
            && BigInt::from(self.admission.terms().get())
                * BigInt::from(self.admission.slots().get())
                <= self.edges
            && BigInt::from(self.admission.output().get())
                * BigInt::from(self.admission.slots().get())
                <= *self.certificate.tags()
    }
    pub fn seal(self) -> Result<Seal> {
        if self.valid() {
            Ok(Seal(self))
        } else {
            Err(Error::Set)
        }
    }
    pub fn capacities(&self) -> Capacities {
        let words = |bits: &BigInt| div_up(bits, &BigInt::from(64));
        Capacities {
            h_bits: &self.rows * &self.columns,
            h_words: &self.columns * words(&self.rows),
            permutations: &self.rows * 2,
            roots: self.basis.clone(),
            s_words: words(&self.ln),
            y_words: words(&self.lt),
            t_words: words(&(&self.lt + 127)),
            e_words: &self.edges * words(&self.rows),
            evaluations: &self.edges * BigInt::from(self.admission.slots().get()),
        }
    }
}
fn fixed(value: u32) -> Natural {
    Natural::from_u32(value).expect("fixed HFHE parameter natural")
}
pub fn production() -> ParameterSet {
    ParameterSet {
        id: fixed(1),
        key: fixed(1),
        field_bits: BigInt::from(127),
        basis: BigInt::from(337),
        rows: BigInt::from(8192),
        columns: BigInt::from(16384),
        h_weight: BigInt::from(192),
        x_weight: BigInt::from(128),
        e_weight: BigInt::from(128),
        edges: BigInt::from(1_200_000),
        ln: BigInt::from(4096),
        lt: BigInt::from(16384),
        tn: BigInt::one(),
        td: BigInt::from(8),
        proof: BigInt::from(4),
        admission: hfhe::production(),
        certificate: hfhe::production_certificate(),
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seal(ParameterSet);
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Catalog(BTreeMap<Natural, ParameterSet>);
impl Catalog {
    pub fn new(values: &[Seal]) -> Result<Self> {
        let mut ids = BTreeSet::new();
        let mut keys = BTreeMap::new();
        let maximum = LOCAL.get(Field::Inputs) as usize;
        for (count, Seal(set)) in values.iter().enumerate() {
            if count == maximum {
                return Err(Error::CatalogCount(maximum, maximum + 1));
            }
            if !ids.insert(set.id) {
                return Err(Error::CatalogDuplicateId(set.id));
            }
            if keys.insert(set.key, set.clone()).is_some() {
                return Err(Error::CatalogDuplicateKey(set.key));
            }
        }
        Ok(Self(keys))
    }
    pub fn select(&self, key: Natural) -> Result<&ParameterSet> {
        self.0.get(&key).ok_or(Error::NoSet(key))
    }
}
pub fn production_catalog() -> Catalog {
    Catalog::new(&[production().seal().expect("HFHE production set")])
        .expect("HFHE production catalog")
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capacities {
    h_bits: BigInt,
    h_words: BigInt,
    permutations: BigInt,
    roots: BigInt,
    s_words: BigInt,
    y_words: BigInt,
    t_words: BigInt,
    e_words: BigInt,
    evaluations: BigInt,
}
impl Capacities {
    pub fn h_bits(&self) -> &BigInt {
        &self.h_bits
    }
    pub fn h_words(&self) -> &BigInt {
        &self.h_words
    }
    pub fn permutations(&self) -> &BigInt {
        &self.permutations
    }
    pub fn roots(&self) -> &BigInt {
        &self.roots
    }
    pub fn s_words(&self) -> &BigInt {
        &self.s_words
    }
    pub fn y_words(&self) -> &BigInt {
        &self.y_words
    }
    pub fn t_words(&self) -> &BigInt {
        &self.t_words
    }
    pub fn e_words(&self) -> &BigInt {
        &self.e_words
    }
    pub fn evaluations(&self) -> &BigInt {
        &self.evaluations
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    set: ParameterSet,
    parameter: fhe::Parameter,
    fhe: fhe::Info,
    hfhe: hfhe::Info,
    capacities: Capacities,
    graph: GraphConfig,
    entropy: EntropyPlan,
}
impl Link {
    pub fn set(&self) -> &ParameterSet {
        &self.set
    }
    pub fn parameter(&self) -> fhe::Parameter {
        self.parameter
    }
    pub fn fhe(&self) -> &fhe::Info {
        &self.fhe
    }
    pub fn hfhe(&self) -> hfhe::Info {
        self.hfhe
    }
    pub fn capacities(&self) -> &Capacities {
        &self.capacities
    }
    pub fn graph(&self) -> &GraphConfig {
        &self.graph
    }
    pub fn entropy(&self) -> &EntropyPlan {
        &self.entropy
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Set,
    CatalogDuplicateId(Natural),
    CatalogDuplicateKey(Natural),
    CatalogCount(usize, usize),
    NoSet(Natural),
    Fhe(fhe::Error),
    Hfhe(hfhe::Error),
    Graph(GraphError),
    Entropy(EntropyError),
    Key(Natural, Natural),
    Room(Natural, Natural),
}
pub type Result<T> = std::result::Result<T, Error>;
fn div_up(value: &BigInt, unit: &BigInt) -> BigInt {
    (value + unit - 1) / unit
}
fn finish(
    set: &ParameterSet,
    catalog: &fhe::Catalog,
    inputs: &[hfhe::Input],
    terms: &fhe::Terms,
    root: fhe::TermId,
    fhe: fhe::Info,
) -> Result<Link> {
    let parameter = catalog.params(&fhe).map_err(Error::Fhe)?;
    if fhe.typ().key() != set.key {
        return Err(Error::Key(fhe.typ().key(), set.key));
    }
    if parameter.key() != set.key {
        return Err(Error::Key(parameter.key(), set.key));
    }
    if fhe.peak() > parameter.capacity() {
        return Err(Error::Room(fhe.peak(), parameter.capacity()));
    }
    let entropy = entropy::plan(&entropy::production(), fhe.peak()).map_err(Error::Entropy)?;
    let environment = hfhe::Environment::new(&set.admission, inputs).map_err(Error::Hfhe)?;
    let hfhe = hfhe::check(&set.admission, &set.certificate, &environment, terms, root)
        .map_err(Error::Hfhe)?;
    let basis = Natural::new(&set.basis).ok_or(Error::Graph(GraphError::Config))?;
    let sigma = Natural::new(&set.rows).ok_or(Error::Graph(GraphError::Config))?;
    let graph = GraphConfig::new(basis, hfhe.shape().slots(), sigma, set.edges.clone())
        .map_err(Error::Graph)?;
    Ok(Link {
        set: set.clone(),
        parameter,
        fhe,
        hfhe,
        capacities: set.capacities(),
        graph,
        entropy,
    })
}
pub fn check(
    set: &ParameterSet,
    catalog: &fhe::Catalog,
    profile: &fhe::Profile,
    environment: &fhe::Environment,
    inputs: &[hfhe::Input],
    terms: &fhe::Terms,
    root: fhe::TermId,
) -> Result<Link> {
    if !set.valid() {
        return Err(Error::Set);
    }
    let info = fhe::check(profile, environment, terms, root).map_err(Error::Fhe)?;
    finish(set, catalog, inputs, terms, root, info)
}
pub fn check_catalog(
    sets: &Catalog,
    catalog: &fhe::Catalog,
    profile: &fhe::Profile,
    environment: &fhe::Environment,
    inputs: &[hfhe::Input],
    terms: &fhe::Terms,
    root: fhe::TermId,
) -> Result<Link> {
    let info = fhe::check(profile, environment, terms, root).map_err(Error::Fhe)?;
    let set = sets.select(info.typ().key())?;
    finish(set, catalog, inputs, terms, root, info)
}
impl Error {
    pub fn text(&self) -> Vec<u8> {
        let raw = match self {
            Self::Set => b"hfhe parameter set is invalid".to_vec(),
            Self::CatalogDuplicateId(id) => {
                format!("hfhe set id is repeated id = {}", id.get()).into_bytes()
            }
            Self::CatalogDuplicateKey(key) => {
                format!("hfhe set key is repeated key = {}", key.get()).into_bytes()
            }
            Self::CatalogCount(limit, actual) => {
                format!("hfhe set count exceeds profile limit = {limit} actual = {actual}")
                    .into_bytes()
            }
            Self::NoSet(key) => format!("hfhe set is absent key = {}", key.get()).into_bytes(),
            Self::Fhe(error) => error.text(),
            Self::Hfhe(error) => error.text(),
            Self::Graph(error) => error.text(),
            Self::Entropy(error) => error.text(),
            Self::Key(actual, expected) => format!(
                "hfhe parameter key mismatch actual = {} expected = {}",
                actual.get(),
                expected.get()
            )
            .into_bytes(),
            Self::Room(need, capacity) => format!(
                "hfhe parameter room is insufficient required = {} capacity = {}",
                need.get(),
                capacity.get()
            )
            .into_bytes(),
        };
        super::text::clip(&raw)
    }
}
