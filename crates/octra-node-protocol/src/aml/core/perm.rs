// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_perm capability policy lattice and checked-effect admission. Policies may
//! be narrowed with `cut`; narrowing never grants a previously absent operation.
use super::{
    check, lower,
    rule::{Field, LOCAL},
    syntax::{self, Syntax},
    term::{self, Program, Terms},
    types::Types,
    Atom, Natural,
};
use num_bigint::BigInt;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission {
    Nil,
    Step,
    Close,
    Both,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    UseStep,
    UseClose,
}
impl Permission {
    fn step(self) -> bool {
        matches!(self, Self::Step | Self::Both)
    }
    fn close(self) -> bool {
        matches!(self, Self::Close | Self::Both)
    }
    pub fn le(self, right: Self) -> bool {
        (!self.step() || right.step()) && (!self.close() || right.close())
    }
    pub fn meet(self, right: Self) -> Self {
        match (self.step() && right.step(), self.close() && right.close()) {
            (false, false) => Self::Nil,
            (true, false) => Self::Step,
            (false, true) => Self::Close,
            (true, true) => Self::Both,
        }
    }
    pub fn text(self) -> &'static [u8] {
        match self {
            Self::Nil => b"nil",
            Self::Step => b"step",
            Self::Close => b"close",
            Self::Both => b"both",
        }
    }
    fn has(self, operation: Op) -> bool {
        match operation {
            Op::UseStep => self.step(),
            Op::UseClose => self.close(),
        }
    }
}
impl Op {
    pub fn text(self) -> &'static [u8] {
        match self {
            Self::UseStep => b"step",
            Self::UseClose => b"close",
        }
    }
}
pub fn le(left: Permission, right: Permission) -> bool {
    left.le(right)
}
pub fn meet(left: Permission, right: Permission) -> Permission {
    left.meet(right)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Set(BTreeMap<Natural, Permission>);
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Nat(BigInt),
    Dup(Natural),
    Count(usize, usize),
    CutMiss(Natural),
    Miss(Natural, Op),
    Deny(Natural, Op, Permission),
    Gain(Natural, Permission, Permission),
    Low(lower::Error),
    Check(check::Error),
}
pub type Result<T> = std::result::Result<T, Error>;
impl Error {
    pub fn text(&self, types: &Types) -> Vec<u8> {
        let raw = match self {
            Self::Nat(value) => format!("capability kind outside profile = {value}").into_bytes(),
            Self::Dup(kind) => {
                format!("duplicate capability policy kind = {}", kind.get()).into_bytes()
            }
            Self::Count(limit, actual) => {
                format!("capability policy count limit = {limit} actual = {actual}").into_bytes()
            }
            Self::CutMiss(kind) => {
                format!("capability policy has no kind = {}", kind.get()).into_bytes()
            }
            Self::Miss(kind, operation) => [
                format!(
                    "capability policy missing kind = {} operation = ",
                    kind.get()
                )
                .as_bytes(),
                operation.text(),
            ]
            .concat(),
            Self::Deny(kind, operation, permission) => [
                format!(
                    "capability operation denied kind = {} operation = ",
                    kind.get()
                )
                .as_bytes(),
                operation.text(),
                b" permission = ",
                permission.text(),
            ]
            .concat(),
            Self::Gain(kind, source, target) => [
                format!("capability permission gain kind = {} source = ", kind.get()).as_bytes(),
                source.text(),
                b" target = ",
                target.text(),
            ]
            .concat(),
            Self::Low(error) => error.text(),
            Self::Check(error) => error.text(types),
        };
        super::text::clip(&raw)
    }
}
impl Set {
    fn new_kind(&self, raw: &BigInt) -> Result<Natural> {
        let maximum = LOCAL.get(Field::Inputs) as usize;
        // Native capacity refusal precedes both natural conversion and duplicate
        // detection. A full policy therefore refuses even a duplicate addition.
        if self.0.len() == maximum {
            return Err(Error::Count(maximum, self.0.len() + 1));
        }
        let kind = Natural::new(raw).ok_or_else(|| Error::Nat(raw.clone()))?;
        if self.0.contains_key(&kind) {
            return Err(Error::Dup(kind));
        }
        Ok(kind)
    }
    pub fn from_values(values: &[(BigInt, Permission)]) -> Result<Self> {
        let mut out = Self::default();
        for (raw, permission) in values {
            let kind = out.new_kind(raw)?;
            out.0.insert(kind, *permission);
        }
        Ok(out)
    }
    pub fn add(&self, raw: &BigInt, permission: Permission) -> Result<Self> {
        let kind = self.new_kind(raw)?;
        let mut out = self.clone();
        out.0.insert(kind, permission);
        Ok(out)
    }
    pub fn vals(&self) -> Vec<(Natural, Permission)> {
        self.0
            .iter()
            .map(|(kind, permission)| (*kind, *permission))
            .collect()
    }
    pub fn find(&self, kind: Natural) -> Option<Permission> {
        self.0.get(&kind).copied()
    }
    pub fn cut(&self, raw: &BigInt, target: Permission) -> Result<Self> {
        let kind = Natural::new(raw).ok_or_else(|| Error::Nat(raw.clone()))?;
        let source = self.find(kind).ok_or(Error::CutMiss(kind))?;
        if !target.le(source) {
            return Err(Error::Gain(kind, source, target));
        }
        let mut out = self.clone();
        out.0.insert(kind, target);
        Ok(out)
    }
    fn allow(&self, atom: Atom) -> Result<()> {
        let (kind, operation) = match atom {
            Atom::Write(kind) => (kind, Op::UseStep),
            Atom::Close(kind) => (kind, Op::UseClose),
            Atom::Read(_) | Atom::Emit(_) | Atom::Fail(_) => return Ok(()),
        };
        let permission = self.find(kind).ok_or(Error::Miss(kind, operation))?;
        if permission.has(operation) {
            Ok(())
        } else {
            Err(Error::Deny(kind, operation, permission))
        }
    }
    pub fn check_info<'a>(&self, info: &'a check::Info) -> Result<&'a check::Info> {
        // Effects use the native atom order: Read, Write, Emit, Fail, Close,
        // with ascending natural kinds within each constructor.
        for atom in info.effects() {
            self.allow(*atom)?;
        }
        Ok(info)
    }
    pub fn check(
        &self,
        types: &mut Types,
        terms: &Terms,
        inputs: &[term::Bind],
        root: term::TermId,
    ) -> Result<check::Checked> {
        let checked = check::check_in(types, terms, inputs, root).map_err(Error::Check)?;
        self.check_info(checked.info())?;
        Ok(checked)
    }
    pub fn prog(
        &self,
        syntax: &Syntax,
        types: &mut Types,
        terms: &mut Terms,
        inputs: &[syntax::Bind],
        root: syntax::TermId,
    ) -> Result<(Program, check::Checked)> {
        let program = lower::program(syntax, types, terms, inputs, root).map_err(Error::Low)?;
        let checked = self.check(types, terms, &program.inputs, program.term)?;
        Ok((program, checked))
    }
}
