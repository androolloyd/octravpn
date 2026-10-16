// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_rule identities and activation schedules. These are AML core limits, not
//! an independent node consensus configuration or a replacement network pin.
use num_bigint::{BigInt, Sign};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Field {
    Nat,
    Str,
    Text,
    TypeDepth,
    TypeNodes,
    TermDepth,
    TermNodes,
    Inputs,
    Fuel,
    Name,
    Tag,
}
const FIELDS: [Field; 11] = [
    Field::Nat,
    Field::Str,
    Field::Text,
    Field::TypeDepth,
    Field::TypeNodes,
    Field::TermDepth,
    Field::TermNodes,
    Field::Inputs,
    Field::Fuel,
    Field::Name,
    Field::Tag,
];
impl Field {
    fn text(self) -> &'static str {
        match self {
            Self::Nat => "natural",
            Self::Str => "string",
            Self::Text => "diagnostic",
            Self::TypeDepth => "type depth",
            Self::TypeNodes => "type nodes",
            Self::TermDepth => "term depth",
            Self::TermNodes => "term nodes",
            Self::Inputs => "inputs",
            Self::Fuel => "fuel",
            Self::Name => "name",
            Self::Tag => "data tag",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Limits([i64; 11]);
pub const LOCAL: Limits = Limits([
    1_000_000, 16_777_211, 1024, 256, 4096, 4096, 100_000, 4096, 1_000_000, 64, 12,
]);
impl Limits {
    pub fn new(values: [i64; 11]) -> Result<Self, Error> {
        for (field, value) in FIELDS.into_iter().zip(values) {
            if value <= 0 {
                return Err(Error::Limit(field, value));
            }
        }
        let [nat, string, text, type_depth, type_nodes, term_depth, term_nodes, inputs, fuel, name, tag] =
            values;
        if nat > string
            || text > string
            || type_depth > term_depth
            || type_nodes > term_nodes
            || inputs > term_nodes
            || fuel > nat
            || name > text
            || tag > nat
        {
            return Err(Error::Shape);
        }
        Ok(Self(values))
    }
    pub const fn get(self, field: Field) -> i64 {
        self.0[field as usize]
    }
    pub fn values(self) -> [i64; 11] {
        self.0
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Id {
    version: i64,
    limits: Limits,
}
impl Id {
    pub fn version(&self) -> i64 {
        self.version
    }
    pub fn limits(&self) -> Limits {
        self.limits
    }
    pub fn values(&self) -> Vec<i64> {
        std::iter::once(self.version).chain(self.limits.0).collect()
    }
    pub fn text(&self) -> String {
        let mut out = String::from("aml");
        for value in self.values() {
            out.push(':');
            out.push_str(&value.to_string());
        }
        out
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    id: Id,
    activate: BigInt,
}
impl Rule {
    pub fn new(version: i64, activate: BigInt, limits: Limits) -> Result<Self, Error> {
        let limits = Limits::new(limits.0)?;
        if version <= 0 {
            return Err(Error::Version(version));
        }
        if activate.sign() == Sign::Minus {
            return Err(Error::Epoch(activate));
        }
        Ok(Self {
            id: Id { version, limits },
            activate,
        })
    }
    pub fn id(&self) -> &Id {
        &self.id
    }
    pub fn activate(&self) -> &BigInt {
        &self.activate
    }
    pub fn limits(&self) -> Limits {
        self.id.limits
    }
    pub fn supported(&self) -> bool {
        self.id.limits == LOCAL
    }
}
#[derive(Clone, Debug, Default)]
pub struct Schedule {
    epochs: BTreeMap<BigInt, Rule>,
}
impl Schedule {
    pub fn new(values: impl IntoIterator<Item = Rule>) -> Result<Self, Error> {
        let mut ids = BTreeSet::new();
        let mut epochs = BTreeMap::new();
        let limit = LOCAL.get(Field::Inputs) as usize;
        for (count, rule) in values.into_iter().enumerate() {
            if count == limit {
                return Err(Error::Count(limit, limit + 1));
            }
            if !ids.insert(rule.id.clone()) {
                return Err(Error::DuplicateId(rule.id));
            }
            if epochs.contains_key(&rule.activate) {
                return Err(Error::DuplicateEpoch(rule.activate));
            }
            epochs.insert(rule.activate.clone(), rule);
        }
        Ok(Self { epochs })
    }
    pub fn at(&self, epoch: &BigInt) -> Result<Option<&Rule>, Error> {
        if epoch.sign() == Sign::Minus {
            return Err(Error::Epoch(epoch.clone()));
        }
        Ok(self
            .epochs
            .range(..=epoch.clone())
            .next_back()
            .map(|(_, rule)| rule))
    }
    pub fn select(&self, epoch: &BigInt) -> Result<&Rule, Error> {
        let rule = self
            .at(epoch)?
            .ok_or_else(|| Error::Absent(epoch.clone()))?;
        if rule.supported() {
            Ok(rule)
        } else {
            Err(Error::Unsupported(rule.id.clone()))
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Limit(Field, i64),
    Shape,
    Version(i64),
    Epoch(BigInt),
    Absent(BigInt),
    Unsupported(Id),
    DuplicateId(Id),
    DuplicateEpoch(BigInt),
    Count(usize, usize),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Limit(field, actual) => write!(
                f,
                "rule limit is not positive field = {} actual = {actual}",
                field.text()
            ),
            Self::Shape => f.write_str("rule limit relations are invalid"),
            Self::Version(actual) => write!(f, "rule version is invalid actual = {actual}"),
            Self::Epoch(actual) => write!(f, "rule epoch is negative actual = {actual}"),
            Self::Absent(epoch) => write!(f, "rule is absent epoch = {epoch}"),
            Self::Unsupported(id) => write!(f, "rule is unsupported id = {}", id.text()),
            Self::DuplicateId(id) => write!(f, "rule identifier repeats id = {}", id.text()),
            Self::DuplicateEpoch(epoch) => write!(f, "rule activation repeats epoch = {epoch}"),
            Self::Count(limit, actual) => write!(f, "rule count limit = {limit} actual = {actual}"),
        }
    }
}
impl std::error::Error for Error {}
