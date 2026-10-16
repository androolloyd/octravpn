// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Aml_effect runtime host plans preserve quota, origin and failure precedence.
use super::core::eval::{
    self, Action, Origin as RuntimeOrigin, Output, Value as RuntimeValue, ValueId, Values,
};
use super::{Arc, Atom, BigInt, Entry, Error, HostType, Origin, Result, Rollback, Sealed};
use crate::octb::{Instruction as I, Value};
use num_traits::Zero;
use std::borrow::Cow;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scalar {
    Int(Arc<BigInt>),
    Bool(bool),
    String(Arc<[u8]>),
    Bytes(Arc<[u8]>),
    Bytes32(Arc<[u8]>),
}
impl Scalar {
    pub fn text(&self) -> Cow<'_, [u8]> {
        match self {
            Self::Int(value) => Cow::Owned(value.to_string().into_bytes()),
            Self::Bool(true) => Cow::Borrowed(b"true"),
            Self::Bool(false) => Cow::Borrowed(b"false"),
            Self::String(value) | Self::Bytes(value) | Self::Bytes32(value) => Cow::Borrowed(value),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Host {
    Load(Vec<u8>, Scalar),
    Store(Vec<u8>, Scalar),
    Log(Vec<u8>, Vec<Scalar>),
    Reject(Vec<u8>, Vec<Scalar>),
}
#[derive(Clone, Debug)]
pub struct Item {
    action: Action,
    host: Host,
    rollback: Rollback,
    ops: Vec<I>,
    cost: BigInt,
}
impl Item {
    pub fn action(&self) -> Action {
        self.action
    }
    pub fn host(&self) -> &Host {
        &self.host
    }
    pub fn rollback(&self) -> Rollback {
        self.rollback
    }
    pub fn ops(&self) -> &[I] {
        &self.ops
    }
    pub fn cost(&self) -> &BigInt {
        &self.cost
    }
}
#[derive(Clone, Debug)]
pub struct Plan {
    items: Vec<Item>,
    cost: BigInt,
}
impl Plan {
    pub fn items(&self) -> &[Item] {
        &self.items
    }
    pub fn cost(&self) -> &BigInt {
        &self.cost
    }
}
#[derive(Clone, Debug)]
pub struct Prepared {
    out: Output,
    plan: Plan,
}
impl Prepared {
    pub fn out(&self) -> &Output {
        &self.out
    }
    pub fn plan(&self) -> &Plan {
        &self.plan
    }
}
fn scalar(values: &Values, typ: HostType, payload: ValueId) -> Option<Scalar> {
    match (typ, values.get(payload)) {
        (HostType::Int, RuntimeValue::Int(value)) => Some(Scalar::Int(value.clone())),
        (HostType::Bool, RuntimeValue::Bool(value)) => Some(Scalar::Bool(*value)),
        (HostType::Bytes32, RuntimeValue::Bytes(value)) if value.len() == 32 => {
            Some(Scalar::Bytes32(value.clone()))
        }
        _ => None,
    }
}
fn event_values(values: &Values, types: &[HostType], mut payload: ValueId) -> Option<Vec<Scalar>> {
    let mut out = Vec::with_capacity(types.len());
    for (index, typ) in types.iter().enumerate() {
        if index + 1 == types.len() {
            out.push(scalar(values, *typ, payload)?);
        } else {
            let RuntimeValue::Pair(head, rest) = values.get(payload) else {
                return None;
            };
            out.push(scalar(values, *typ, *head)?);
            payload = *rest;
        }
    }
    if types.is_empty() && values.get(payload) != &RuntimeValue::Unit {
        return None;
    }
    Some(out)
}
fn fault_values(values: &Values, payload: ValueId) -> Option<Vec<Scalar>> {
    values.shape(&[payload]).ok()?;
    let mut pending = vec![payload];
    let mut out = vec![];
    while let Some(id) = pending.pop() {
        match values.get(id) {
            RuntimeValue::Unit => (),
            RuntimeValue::Int(value) => out.push(Scalar::Int(value.clone())),
            RuntimeValue::Bool(value) => out.push(Scalar::Bool(*value)),
            RuntimeValue::Bytes(value) => out.push(Scalar::Bytes(value.clone())),
            RuntimeValue::Pair(left, right) => {
                pending.push(*right);
                pending.push(*left);
            }
            _ => return None,
        }
    }
    Some(out)
}
fn origin(action: Action) -> Result<()> {
    match (action.atom(), action.origin()) {
        (Atom::Read(_) | Atom::Write(_) | Atom::Emit(_) | Atom::Fail(_), RuntimeOrigin::Direct) => {
            Ok(())
        }
        (Atom::Write(kind) | Atom::Close(kind), RuntimeOrigin::Held(actual, _))
            if kind == actual =>
        {
            Ok(())
        }
        (atom, origin) => Err(Error::Origin(atom, origin)),
    }
}
fn key(action: Action) -> (Atom, Origin) {
    (
        action.atom(),
        match action.origin() {
            RuntimeOrigin::Direct => Origin::Direct,
            RuntimeOrigin::Held(kind, _) => Origin::Held(kind),
        },
    )
}
fn item(action: Action, host: Host, rollback: Rollback, ops: Vec<I>, dynamic: BigInt) -> Item {
    let cost = ops.iter().fold(dynamic, |cost, op| cost + op.effort_cost());
    Item {
        action,
        host,
        rollback,
        ops,
        cost,
    }
}
impl Sealed {
    // Keep this operation on the shared native checker/host method interface.
    #[allow(clippy::unused_self)]
    fn host_item(&self, values: &Values, action: Action, entry: &Entry) -> Result<Item> {
        let atom = action.atom();
        Ok(match entry {
            Entry::State(name, typ) => {
                let value = scalar(values, *typ, action.payload()).ok_or(Error::Payload(atom))?;
                match atom {
                    Atom::Read(_) => item(
                        action,
                        Host::Load(name.clone(), value),
                        Rollback::Preserve,
                        vec![
                            I::Sload(0, Arc::from(name.as_slice())),
                            I::Eq(1, 0, 2),
                            I::Assert(1),
                        ],
                        BigInt::zero(),
                    ),
                    Atom::Write(_) => {
                        let size = value.text().len();
                        if size > crate::octb::work::Limits::CONSENSUS.value_bytes as usize {
                            return Err(Error::HostLimit(atom, size));
                        }
                        item(
                            action,
                            Host::Store(name.clone(), value),
                            Rollback::Journal,
                            vec![I::Sstore(Arc::from(name.as_slice()), 0)],
                            BigInt::from(size / 32),
                        )
                    }
                    _ => return Err(Error::BindingAbsent(atom)),
                }
            }
            Entry::Event(name, types) => {
                let values =
                    event_values(values, types, action.payload()).ok_or(Error::Payload(atom))?;
                let registers = (0..values.len()).map(|index| index as u8).collect();
                item(
                    action,
                    Host::Log(name.clone(), values),
                    Rollback::Record,
                    vec![I::Emit(Arc::from(name.as_slice()), registers)],
                    BigInt::zero(),
                )
            }
            Entry::Fault(name, code, message) => {
                let values = fault_values(values, action.payload()).ok_or(Error::Payload(atom))?;
                if values.len() > 62 {
                    return Err(Error::HostLimit(atom, values.len() + 2));
                }
                let code = Arc::new(BigInt::from(*code));
                let message: Arc<[u8]> = Arc::from(message.as_slice());
                let mut args = vec![Scalar::Int(code.clone()), Scalar::String(message.clone())];
                args.extend(values);
                let registers = (0..args.len()).map(|index| index as u8).collect();
                let ops = vec![
                    I::Ldi(0, Arc::new(Value::Int(code))),
                    I::Ldi(1, Arc::new(Value::Str(message))),
                    I::Emit([b"Error:".as_slice(), name].concat().into(), registers),
                    I::Revert(),
                ];
                item(
                    action,
                    Host::Reject(name.clone(), args),
                    Rollback::Abort,
                    ops,
                    BigInt::zero(),
                )
            }
        })
    }
    fn plan_actions(&self, values: &mut Values, actions: &[Action]) -> Result<Plan> {
        let mut quotas = self.quotas.clone();
        let mut items = Vec::with_capacity(actions.len());
        let mut cost = BigInt::zero();
        for (index, action) in actions.iter().copied().enumerate() {
            origin(action)?;
            match (action.atom(), action.origin()) {
                (Atom::Close(kind), RuntimeOrigin::Held(_, id)) => {
                    return Err(Error::CloseUnavailable(kind, id))
                }
                (Atom::Close(_), RuntimeOrigin::Direct) => {
                    return Err(Error::Origin(action.atom(), action.origin()))
                }
                _ => (),
            }
            let quota = quotas
                .get_mut(&key(action))
                .ok_or(Error::SiteAbsent(action.atom()))?;
            if !values.typed(&self.types, quota.site.payload(), action.payload()) {
                return Err(Error::Payload(action.atom()));
            }
            if quota.left <= BigInt::zero() {
                return Err(Error::SiteLimit(action.atom()));
            }
            quota.left -= 1;
            let entry = self
                .registry
                .find(action.atom())
                .ok_or(Error::BindingAbsent(action.atom()))?;
            let planned = self.host_item(values, action, entry)?;
            if matches!(action.atom(), Atom::Fail(_)) {
                if let Some(next) = actions.get(index + 1) {
                    return Err(Error::AfterFail(next.atom()));
                }
            }
            cost += &planned.cost;
            items.push(planned);
        }
        if !self.trace(values, actions) {
            return Err(Error::Trace);
        }
        Ok(Plan { items, cost })
    }
    pub fn prepare(&self, values: &mut Values, inputs: &[ValueId]) -> Result<Prepared> {
        let expected = self.program.inputs.len();
        let actual = inputs.len();
        if expected != actual {
            return Err(Error::InputCount(expected, actual));
        }
        let inputs: Vec<_> = self
            .program
            .inputs
            .iter()
            .copied()
            .zip(inputs.iter().copied())
            .collect();
        let mut types = self.types.as_ref().clone();
        let out = eval::run_in(
            &mut types,
            &self.terms,
            values,
            &inputs,
            self.program.term,
            None,
        )
        .map_err(Error::Run)?;
        let plan = self.plan_actions(values, out.actions())?;
        Ok(Prepared { out, plan })
    }
}
