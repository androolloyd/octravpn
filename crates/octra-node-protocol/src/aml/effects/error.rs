// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Static host-effect diagnostics use the adopted AML spelling and byte names.
use super::core;
use super::{check, Atom, Natural, Origin, Target, TypeId, Types};
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Program,
    Static(check::Error),
    Run(core::eval::Error),
    InputCount(usize, usize),
    BindLimit(usize),
    AtomRepeated(Atom),
    TargetKind(Atom, Target),
    TargetAbsent(Target),
    TargetRepeated(Target),
    TargetType(Target, Vec<u8>),
    BindingAbsent(Atom),
    SiteType(Atom, TypeId, TypeId),
    SitePayload(Atom, TypeId),
    SiteOrigin(Atom, Origin),
    SiteAbsent(Atom),
    SiteLimit(Atom),
    SiteIndex(i64),
    Register(i64),
    PayloadRegisters(Atom, usize, usize),
    ScratchRegisters(Atom, usize, usize),
    RegisterAlias(Atom, i64),
    HostLimit(Atom, usize),
    Trace,
    Payload(Atom),
    Origin(Atom, core::eval::Origin),
    AfterFail(Atom),
    CloseUnavailable(Natural, Natural),
}
impl Error {
    pub fn text(&self, types: &Types) -> Vec<u8> {
        match self {
            Self::Program => b"effect host requires Program".to_vec(),
            Self::Static(error) => [
                b"effect static check failed reason = ".as_slice(),
                &error.text(types),
            ]
            .concat(),
            Self::Run(error) => [
                b"effect evaluation failed reason = ".as_slice(),
                &error.text(types),
            ]
            .concat(),
            Self::InputCount(expected, actual) => {
                format!("effect input count differs expected = {expected} actual = {actual}")
                    .into_bytes()
            }
            Self::BindLimit(actual) => format!(
                "effect binding count limit = {} actual = {actual}",
                core::rule::LOCAL.get(core::rule::Field::TermNodes)
            )
            .into_bytes(),
            Self::AtomRepeated(atom) => [
                b"effect atom is repeated atom = ".as_slice(),
                &core::atom_text(*atom),
            ]
            .concat(),
            Self::TargetKind(atom, target) => [
                b"effect target kind differs atom = ".as_slice(),
                &core::atom_text(*atom),
                b" target = ",
                &target.text(),
            ]
            .concat(),
            Self::TargetAbsent(target) => [
                b"effect target is absent target = ".as_slice(),
                &target.text(),
            ]
            .concat(),
            Self::TargetRepeated(target) => [
                b"effect target is repeated target = ".as_slice(),
                &target.text(),
            ]
            .concat(),
            Self::TargetType(target, typ) => [
                b"effect target type is unsupported target = ".as_slice(),
                &target.text(),
                b" type = ",
                typ,
            ]
            .concat(),
            Self::BindingAbsent(atom) => [
                b"effect binding is absent atom = ".as_slice(),
                &core::atom_text(*atom),
            ]
            .concat(),
            Self::SiteType(atom, expected, actual) => [
                b"effect site type differs atom = ".as_slice(),
                &core::atom_text(*atom),
                b" expected = ",
                &types.text(*expected),
                b" actual = ",
                &types.text(*actual),
            ]
            .concat(),
            Self::SitePayload(atom, typ) => [
                b"effect site payload is unsupported atom = ".as_slice(),
                &core::atom_text(*atom),
                b" type = ",
                &types.text(*typ),
            ]
            .concat(),
            Self::SiteOrigin(atom, _) => [
                b"effect site origin differs atom = ".as_slice(),
                &core::atom_text(*atom),
            ]
            .concat(),
            Self::SiteAbsent(atom) => [
                b"effect action is not proved atom = ".as_slice(),
                &core::atom_text(*atom),
            ]
            .concat(),
            Self::SiteLimit(atom) => [
                b"effect action exceeds proved count atom = ".as_slice(),
                &core::atom_text(*atom),
            ]
            .concat(),
            Self::SiteIndex(index) => {
                format!("effect site index is invalid index = {index}").into_bytes()
            }
            Self::Register(reg) => {
                format!("effect register is invalid register = {reg}").into_bytes()
            }
            Self::PayloadRegisters(atom, expected, actual) => [
                b"effect payload register count differs atom = ".as_slice(),
                &core::atom_text(*atom),
                format!(" expected = {expected} actual = {actual}").as_bytes(),
            ]
            .concat(),
            Self::ScratchRegisters(atom, expected, actual) => [
                b"effect scratch register count differs atom = ".as_slice(),
                &core::atom_text(*atom),
                format!(" expected = {expected} actual = {actual}").as_bytes(),
            ]
            .concat(),
            Self::RegisterAlias(atom, reg) => [
                b"effect register aliases atom = ".as_slice(),
                &core::atom_text(*atom),
                format!(" register = {reg}").as_bytes(),
            ]
            .concat(),
            Self::HostLimit(atom, actual) => [
                b"effect host limit atom = ".as_slice(),
                &core::atom_text(*atom),
                format!(" actual = {actual}").as_bytes(),
            ]
            .concat(),
            Self::Trace => b"effect action trace differs".to_vec(),
            Self::Payload(atom) => [
                b"effect payload differs atom = ".as_slice(),
                &core::atom_text(*atom),
            ]
            .concat(),
            Self::Origin(atom, _) => [
                b"effect origin differs atom = ".as_slice(),
                &core::atom_text(*atom),
            ]
            .concat(),
            Self::AfterFail(atom) => [
                b"effect follows failure atom = ".as_slice(),
                &core::atom_text(*atom),
            ]
            .concat(),
            Self::CloseUnavailable(kind, id) => format!(
                "effect close host is absent identity = {}:{}",
                kind.get(),
                id.get()
            )
            .into_bytes(),
        }
    }
}
