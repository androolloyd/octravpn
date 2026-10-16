// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_scert certificates lower named C_syn programs before rule-selected core
//! certification. This is independent of the Program compiler envelopes.
use super::{bin::Bits, certificate, lower, rule::Schedule, syntax, term::Terms, types::Types};
use num_bigint::BigInt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Lower(lower::Error),
    Cert(certificate::Error),
}
impl Error {
    pub fn text(&self, types: &Types) -> Vec<u8> {
        match self {
            Self::Lower(error) => error.text(),
            Self::Cert(error) => error.text(types),
        }
    }
}
pub fn issue(
    schedule: &Schedule,
    epoch: &BigInt,
    syntax: &syntax::Syntax,
    types: &mut Types,
    terms: &mut Terms,
    inputs: &[syntax::Bind],
    body: syntax::TermId,
) -> Result<Bits, Error> {
    let program = lower::program(syntax, types, terms, inputs, body).map_err(Error::Lower)?;
    certificate::issue(schedule, epoch, types, terms, &program).map_err(Error::Cert)
}
pub fn verify(
    schedule: &Schedule,
    epoch: &BigInt,
    syntax: &syntax::Syntax,
    types: &mut Types,
    terms: &mut Terms,
    inputs: &[syntax::Bind],
    body: syntax::TermId,
    input: &[bool],
) -> bool {
    issue(schedule, epoch, syntax, types, terms, inputs, body)
        .is_ok_and(|exact| exact.as_slice() == input)
}
