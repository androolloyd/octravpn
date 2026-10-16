// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_res typed sum constructors, distinct from AR1 result artifact transport.
use super::{
    arena::Reference,
    term::{Bind, Term, TermId, Terms},
    types::{Type, TypeId, Types},
};
pub fn typ(types: &mut Types, ok: TypeId, err: TypeId) -> Result<TypeId, Reference> {
    types.insert(Type::Sum(ok, err))
}
pub fn ok(
    types: &Types,
    terms: &mut Terms,
    err: TypeId,
    value: TermId,
) -> Result<TermId, Reference> {
    terms.insert(types, Term::Inl(value, err))
}
pub fn err(
    types: &Types,
    terms: &mut Terms,
    ok: TypeId,
    value: TermId,
) -> Result<TermId, Reference> {
    terms.insert(types, Term::Inr(ok, value))
}
pub fn fold(
    types: &Types,
    terms: &mut Terms,
    value: TermId,
    ok: Bind,
    yes: TermId,
    err: Bind,
    no: TermId,
) -> Result<TermId, Reference> {
    terms.insert(types, Term::Case(value, ok, yes, err, no))
}
