// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Independent C_eval runtime. Static resources, dynamic work and integer-work
//! reservations remain separate, and evaluation does not itself execute hosts.
use super::{
    check,
    limit::Limit,
    rule::{self, Field, LOCAL},
    term::{Bind, Fold, Relation, Term, TermId, Terms},
    types::{Multiplicity, Type, TypeId, Types},
    Atom, Effects, Natural,
};
use crate::octb::work::IntegerOp;
use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive, Zero};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
mod error;
mod input;
mod machine;
mod operations;
mod shape;
mod value;
pub use error::Error;
pub use shape::ShapeError;
pub use value::{int_text, Value, ValueId, Values};
type Result<T> = std::result::Result<T, Error>;
pub fn max_cost() -> BigInt {
    BigInt::from(LOCAL.get(Field::Fuel))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Direct,
    Held(Natural, Natural),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Action {
    atom: Atom,
    payload: ValueId,
    origin: Origin,
}
impl Action {
    pub fn direct(atom: Atom, payload: ValueId) -> Self {
        Self {
            atom,
            payload,
            origin: Origin::Direct,
        }
    }
    pub fn held(atom: Atom, payload: ValueId, kind: Natural, id: Natural) -> Self {
        Self {
            atom,
            payload,
            origin: Origin::Held(kind, id),
        }
    }
    pub fn atom(self) -> Atom {
        self.atom
    }
    pub fn payload(self) -> ValueId {
        self.payload
    }
    pub fn origin(self) -> Origin {
        self.origin
    }
}
pub fn atoms(actions: &[Action]) -> Vec<Atom> {
    actions.iter().map(|action| action.atom).collect()
}
#[derive(Clone, Debug)]
pub struct Output {
    value: ValueId,
    plan: Vec<Atom>,
    actions: Vec<Action>,
    steps: BigInt,
    work: BigInt,
    row: Effects,
    limit: BigInt,
    work_limit: BigInt,
    integer_work: BigInt,
}
impl Output {
    pub fn value(&self) -> ValueId {
        self.value
    }
    pub fn plan(&self) -> &[Atom] {
        &self.plan
    }
    pub fn actions(&self) -> &[Action] {
        &self.actions
    }
    pub fn steps(&self) -> &BigInt {
        &self.steps
    }
    pub fn work(&self) -> &BigInt {
        &self.work
    }
    pub fn row(&self) -> &Effects {
        &self.row
    }
    pub fn limit(&self) -> &BigInt {
        &self.limit
    }
    pub fn work_limit(&self) -> &BigInt {
        &self.work_limit
    }
    pub fn integer_work(&self) -> &BigInt {
        &self.integer_work
    }
}
#[derive(Clone, Copy, Debug)]
struct TraceId(usize);
enum Trace {
    Nil,
    Atom(Action),
    Cat(TraceId, TraceId),
}
struct Traces(Vec<Trace>);
impl Default for Traces {
    fn default() -> Self {
        Self(vec![Trace::Nil])
    }
}
impl Traces {
    fn atom(&mut self, action: Action) -> TraceId {
        let id = TraceId(self.0.len());
        self.0.push(Trace::Atom(action));
        id
    }
    fn cat(&mut self, left: TraceId, right: TraceId) -> TraceId {
        if left.0 == 0 {
            right
        } else if right.0 == 0 {
            left
        } else {
            let id = TraceId(self.0.len());
            self.0.push(Trace::Cat(left, right));
            id
        }
    }
    fn actions(&self, root: TraceId) -> Vec<Action> {
        let mut pending = vec![root];
        let mut out = vec![];
        while let Some(id) = pending.pop() {
            match &self.0[id.0] {
                Trace::Nil => (),
                Trace::Atom(action) => out.push(*action),
                Trace::Cat(left, right) => {
                    pending.push(*right);
                    pending.push(*left);
                }
            }
        }
        out
    }
}
#[derive(Clone)]
struct Done {
    value: ValueId,
    trace: TraceId,
    steps: BigInt,
    work: BigInt,
}
impl Done {
    fn item(value: ValueId) -> Self {
        Self {
            value,
            trace: TraceId(0),
            steps: BigInt::from(1),
            work: BigInt::from(1),
        }
    }
    fn successor(mut self) -> Self {
        self.steps += 1;
        self.work += 1;
        self
    }
}
#[derive(Clone, Default)]
struct Env(Arc<Vec<(Natural, ValueId)>>);
impl Env {
    fn get(&self, id: Natural) -> Result<ValueId> {
        self.0
            .iter()
            .rev()
            .find(|(key, _)| *key == id)
            .map(|(_, value)| *value)
            .ok_or(Error::Missing(id))
    }
    fn bind(&mut self, bind: Bind, value: ValueId) {
        if bind.multiplicity != Multiplicity::Zero {
            Arc::make_mut(&mut self.0).push((bind.id, value));
        }
    }
}
struct Evaluator<'a> {
    types: &'a Types,
    terms: &'a Terms,
    values: &'a mut Values,
    traces: Traces,
    integer_work: BigInt,
}
impl Evaluator<'_> {
    fn sequence(&mut self, left: Done, right: Done, value: ValueId) -> Done {
        Done {
            value,
            trace: self.traces.cat(left.trace, right.trace),
            steps: left.steps + right.steps + 1,
            work: left.work + right.work + 1,
        }
    }
    fn charge(&mut self, cost: BigInt) -> Result<()> {
        let actual = &self.integer_work + cost;
        let maximum = BigInt::from(LOCAL.get(Field::Fuel));
        if actual > maximum {
            Err(Error::Arithmetic(maximum, actual))
        } else {
            self.integer_work = actual;
            Ok(())
        }
    }
    fn integer(
        &mut self,
        op: IntegerOp,
        reject: Error,
        left: &BigInt,
        right: &BigInt,
    ) -> Result<BigInt> {
        let base = match op {
            IntegerOp::Add | IntegerOp::Sub | IntegerOp::Mul => 3,
            _ => 5,
        };
        self.charge(op.cost(true, base, left, right))?;
        op.eval(left, right).ok_or(reject)
    }
}
fn host_length(length: usize) -> Result<Natural> {
    u32::try_from(length)
        .ok()
        .and_then(Natural::from_u32)
        .ok_or(Error::Static(check::Error::Size))
}
pub fn run_in(
    types: &mut Types,
    terms: &Terms,
    values: &mut Values,
    inputs: &[(Bind, ValueId)],
    root: TermId,
    fuel: Option<&BigInt>,
) -> Result<Output> {
    let maximum_inputs = LOCAL.get(Field::Inputs) as usize;
    if inputs.len() > maximum_inputs {
        return Err(Error::Static(check::Error::Inputs(
            maximum_inputs,
            maximum_inputs + 1,
        )));
    }
    let binds: Vec<_> = inputs.iter().map(|(bind, _)| *bind).collect();
    let checked = check::check_in(types, terms, &binds, root).map_err(Error::Static)?;
    let maximum_fuel = BigInt::from(LOCAL.get(Field::Fuel));
    let fuel = fuel.unwrap_or(&maximum_fuel);
    let resources = checked.info().resources();
    if fuel.is_negative() || &resources.steps > fuel {
        return Err(Error::Fuel(fuel.clone(), resources.steps.clone()));
    }
    let env = input::environment(types, values, inputs)?;
    let mut evaluator = Evaluator {
        types,
        terms,
        values,
        traces: Traces::default(),
        integer_work: BigInt::zero(),
    };
    let done = evaluator.evaluate(env, root)?;
    let actions = evaluator.traces.actions(done.trace);
    let plan = atoms(&actions);
    let used: Effects = plan.iter().copied().collect();
    if done.steps > resources.steps {
        return Err(Error::Cost(resources.steps.clone(), done.steps));
    }
    if done.work > resources.work {
        return Err(Error::Work(resources.work.clone(), done.work));
    }
    if !Limit::used(done.steps.clone(), done.work.clone()).le(resources) {
        return Err(Error::Work(resources.work.clone(), done.work));
    }
    if !used.is_subset(checked.info().effects()) {
        return Err(Error::Effects(checked.info().effects().clone(), used));
    }
    Ok(Output {
        value: done.value,
        plan,
        actions,
        steps: done.steps,
        work: done.work,
        row: checked.info().effects().clone(),
        limit: resources.steps.clone(),
        work_limit: resources.work.clone(),
        integer_work: evaluator.integer_work,
    })
}
pub fn run(
    types: &mut Types,
    terms: &Terms,
    values: &mut Values,
    root: TermId,
    fuel: Option<&BigInt>,
) -> Result<Output> {
    run_in(types, terms, values, &[], root, fuel)
}
#[derive(Clone, Debug)]
pub struct Execution {
    rule: rule::Id,
    out: Output,
}
impl Execution {
    pub fn rule(&self) -> &rule::Id {
        &self.rule
    }
    pub fn out(&self) -> &Output {
        &self.out
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleError {
    Rule(rule::Error),
    Run(Error),
}
pub fn run_in_at(
    schedule: &rule::Schedule,
    epoch: &BigInt,
    types: &mut Types,
    terms: &Terms,
    values: &mut Values,
    inputs: &[(Bind, ValueId)],
    root: TermId,
) -> std::result::Result<Execution, RuleError> {
    let rule = schedule.select(epoch).map_err(RuleError::Rule)?;
    let fuel = BigInt::from(rule.limits().get(Field::Fuel));
    let out = run_in(types, terms, values, inputs, root, Some(&fuel)).map_err(RuleError::Run)?;
    Ok(Execution {
        rule: rule.id().clone(),
        out,
    })
}
pub fn run_at(
    schedule: &rule::Schedule,
    epoch: &BigInt,
    types: &mut Types,
    terms: &Terms,
    values: &mut Values,
    root: TermId,
) -> std::result::Result<Execution, RuleError> {
    run_in_at(schedule, epoch, types, terms, values, &[], root)
}
