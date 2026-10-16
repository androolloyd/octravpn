// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_crypt field simulation and static/dynamic FHE agreement. This evaluator
//! carries field elements, not native HFHE ciphertexts or encryption evidence.
use super::{
    eval::{Value, ValueId, Values},
    fhe,
    field::Field,
    syntax::Name,
    types::{Type, TypeId, Types},
    Natural,
};
use num_bigint::BigInt;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cipher {
    key: Natural,
    remaining: Natural,
    value: Field,
}
impl Cipher {
    pub fn make(key: &BigInt, remaining: &BigInt, value: &BigInt) -> Result<Self> {
        Ok(Self {
            key: nat(fhe::Field::Key, key)?,
            remaining: nat(fhe::Field::Depth, remaining)?,
            value: Field::reduce(value),
        })
    }
    pub fn key(&self) -> Natural {
        self.key
    }
    pub fn remaining(&self) -> Natural {
        self.remaining
    }
    pub fn value(&self) -> &Field {
        &self.value
    }
    pub fn view(&self) -> (Natural, Natural, &Field) {
        (self.key, self.remaining, &self.value)
    }
    pub fn core(&self, types: &mut Types, values: &mut Values) -> (TypeId, ValueId) {
        let typ = types.intern(Type::Enc(self.key, self.remaining));
        let value = values.push(Value::Enc(self.key, self.remaining, self.value.clone()));
        (typ, value)
    }
    fn same(&self, right: &Self) -> bool {
        self.key == right.key && self.remaining == right.remaining
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    name: Name,
    key: BigInt,
    remaining: BigInt,
    value: BigInt,
}
impl Input {
    pub fn new(name: Name, key: BigInt, remaining: BigInt, value: BigInt) -> Self {
        Self {
            name,
            key,
            remaining,
            value,
        }
    }
}
#[derive(Clone, Debug)]
pub struct Environment {
    values: BTreeMap<Name, Cipher>,
    types: fhe::Environment,
}
impl Environment {
    pub fn new(profile: &fhe::Profile, inputs: &[Input]) -> Result<Self> {
        let types = inputs
            .iter()
            .map(|input| {
                fhe::Input::new(
                    input.name.clone(),
                    input.key.clone(),
                    input.remaining.clone(),
                )
            })
            .collect::<Vec<_>>();
        let types = fhe::Environment::new(profile, &types).map_err(Error::Fhe)?;
        let mut values = BTreeMap::new();
        for input in inputs {
            values.insert(
                input.name.clone(),
                Cipher::make(&input.key, &input.remaining, &input.value)?,
            );
        }
        Ok(Self { values, types })
    }
    pub fn types(&self) -> &fhe::Environment {
        &self.types
    }
    pub fn get(&self, name: &Name) -> Option<&Cipher> {
        self.values.get(name)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    info: fhe::Info,
    parameter: fhe::Parameter,
    cipher: Cipher,
}
impl Run {
    pub fn info(&self) -> &fhe::Info {
        &self.info
    }
    pub fn parameter(&self) -> fhe::Parameter {
        self.parameter
    }
    pub fn cipher(&self) -> &Cipher {
        &self.cipher
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Fhe(fhe::Error),
    Free(Vec<u8>),
    Need(Cipher, Cipher),
    MultiplyZero(Natural),
    RecryptNeed(Natural, Natural),
    Type(Cipher, fhe::Enc),
}
pub type Result<T> = std::result::Result<T, Error>;
impl Error {
    pub fn text(&self) -> Vec<u8> {
        match self {
            Self::Fhe(error) => error.text(),
            Self::Free(name) => [b"cipher input is free = ".as_slice(), name].concat(),
            Self::Need(left, right) => format!(
                "cipher types differ left = enc[{},{}] right = enc[{},{}]",
                left.key.get(),
                left.remaining.get(),
                right.key.get(),
                right.remaining.get()
            )
            .into_bytes(),
            Self::MultiplyZero(key) => {
                format!("cipher multiplication depth exhausted key = {}", key.get()).into_bytes()
            }
            Self::RecryptNeed(key, remaining) => format!(
                "cipher reset requires zero depth key = {} remaining = {}",
                key.get(),
                remaining.get()
            )
            .into_bytes(),
            Self::Type(cipher, typ) => [
                format!(
                    "cipher type differs dynamic = enc[{},{}] static = ",
                    cipher.key.get(),
                    cipher.remaining.get()
                )
                .as_bytes(),
                &typ.text(),
            ]
            .concat(),
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.text()))
    }
}
impl std::error::Error for Error {}
fn nat(field: fhe::Field, value: &BigInt) -> Result<Natural> {
    Natural::new(value).ok_or_else(|| Error::Fhe(fhe::Error::Natural(field, value.clone())))
}
enum Task {
    Visit(fhe::TermId),
    Finish(fhe::TermId),
}
fn schedule(tasks: &mut Vec<Task>, terms: &fhe::Terms, id: fhe::TermId) {
    tasks.push(Task::Finish(id));
    match terms.get(id) {
        fhe::Term::Var(_) => (),
        fhe::Term::Trim(_, body) | fhe::Term::Recrypt(body) => tasks.push(Task::Visit(*body)),
        fhe::Term::Add(left, right) | fhe::Term::Mul(left, right) => {
            tasks.push(Task::Visit(*right));
            tasks.push(Task::Visit(*left));
        }
    }
}
pub fn plain(environment: &Environment, terms: &fhe::Terms, root: fhe::TermId) -> Option<Field> {
    let mut tasks = vec![Task::Visit(root)];
    let mut values = Vec::<Field>::new();
    while let Some(task) = tasks.pop() {
        match task {
            Task::Visit(id) => schedule(&mut tasks, terms, id),
            Task::Finish(id) => match terms.get(id) {
                fhe::Term::Var(name) => values.push(environment.values.get(name)?.value.clone()),
                fhe::Term::Trim(..) | fhe::Term::Recrypt(_) => (),
                fhe::Term::Add(..) | fhe::Term::Mul(..) => {
                    let right = values.pop()?;
                    let left = values.pop()?;
                    values.push(if matches!(terms.get(id), fhe::Term::Add(..)) {
                        left.add(&right)
                    } else {
                        left.multiply(&right)
                    });
                }
            },
        }
    }
    values.pop()
}
pub fn eval(
    profile: &fhe::Profile,
    environment: &Environment,
    terms: &fhe::Terms,
    root: fhe::TermId,
) -> Result<Cipher> {
    let mut tasks = vec![Task::Visit(root)];
    let mut values = Vec::<Cipher>::new();
    while let Some(task) = tasks.pop() {
        let id = match task {
            Task::Visit(id) => {
                schedule(&mut tasks, terms, id);
                continue;
            }
            Task::Finish(id) => id,
        };
        match terms.get(id) {
            fhe::Term::Var(name) => values.push(
                environment
                    .values
                    .get(name)
                    .cloned()
                    .ok_or_else(|| Error::Free(name.text().to_vec()))?,
            ),
            fhe::Term::Trim(raw, _) => {
                let prior = values.last_mut().expect("cipher trim input");
                let remaining = nat(fhe::Field::Depth, raw)?;
                if remaining > prior.remaining {
                    return Err(Error::Fhe(fhe::Error::InputDepth(
                        prior.key,
                        remaining,
                        prior.remaining,
                    )));
                }
                profile.full(prior.key).map_err(Error::Fhe)?;
                prior.remaining = remaining;
            }
            fhe::Term::Add(..) | fhe::Term::Mul(..) => {
                let right = values.pop().expect("cipher right input");
                let mut left = values.pop().expect("cipher left input");
                if !left.same(&right) {
                    return Err(Error::Need(left, right));
                }
                let multiply = matches!(terms.get(id), fhe::Term::Mul(..));
                if multiply && left.remaining.get() == 0 {
                    return Err(Error::MultiplyZero(left.key));
                }
                profile.full(left.key).map_err(Error::Fhe)?;
                if multiply {
                    left.remaining = Natural::from_u32(left.remaining.get() - 1)
                        .expect("decremented cipher depth");
                    left.value = left.value.multiply(&right.value);
                } else {
                    left.value = left.value.add(&right.value);
                }
                values.push(left);
            }
            fhe::Term::Recrypt(_) => {
                let prior = values.last_mut().expect("cipher reset input");
                if prior.remaining.get() != 0 {
                    return Err(Error::RecryptNeed(prior.key, prior.remaining));
                }
                prior.remaining = profile.full(prior.key).map_err(Error::Fhe)?;
            }
        }
    }
    Ok(values.pop().expect("cipher root"))
}
pub fn exec(
    profile: &fhe::Profile,
    catalog: &fhe::Catalog,
    environment: &Environment,
    terms: &fhe::Terms,
    root: fhe::TermId,
) -> Result<Run> {
    let info = fhe::check(profile, &environment.types, terms, root).map_err(Error::Fhe)?;
    let parameter = catalog.params(&info).map_err(Error::Fhe)?;
    let cipher = eval(profile, environment, terms, root)?;
    if cipher.key != info.typ().key() || cipher.remaining != info.typ().remaining() {
        return Err(Error::Type(cipher, info.typ()));
    }
    Ok(Run {
        info,
        parameter,
        cipher,
    })
}
