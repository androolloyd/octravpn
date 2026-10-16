// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_eval input validation preserves per-binding limits and global cap identity.
use super::shape::ZeroCache;
use super::{
    host_length, BTreeSet, BigInt, Bind, Env, Error, Field, Natural, Result, Signed, ToPrimitive,
    Type, Types, Value, ValueId, Values, LOCAL,
};
fn input_value(
    types: &Types,
    values: &mut Values,
    binding: Bind,
    root: ValueId,
    caps: &mut BTreeSet<(Natural, Natural)>,
    defaults: &mut ZeroCache,
) -> Result<()> {
    let invalid = || Error::InputType(binding.id, binding.typ);
    let maximum_depth = LOCAL.get(Field::TermDepth) as usize;
    let maximum_nodes = LOCAL.get(Field::TermNodes) as usize;
    let mut pending = vec![(0, binding.typ, root)];
    let mut nodes = 0;
    while let Some((depth, typ, id)) = pending.pop() {
        if depth > maximum_depth {
            return Err(Error::InputDepth(binding.id, maximum_depth, depth));
        }
        if nodes >= maximum_nodes {
            return Err(Error::InputNodes(binding.id, maximum_nodes, nodes + 1));
        }
        let next = depth + 1;
        match (types.get(typ), values.get(id).clone()) {
            (Type::Unit, Value::Unit)
            | (Type::Bool, Value::Bool(_))
            | (Type::Int, Value::Int(_)) => (),
            (Type::Num(..), Value::Int(value)) if types.admits(typ, &value) => (),
            (Type::Bytes(length), Value::Bytes(value))
                if host_length(value.len()).ok() == Some(*length) => {}
            (Type::Vec(length, elem), Value::Vec(items))
                if host_length(items.len()).ok() == Some(*length) =>
            {
                pending.extend(items.iter().rev().map(|item| (next, *elem, *item)));
            }
            (Type::Seq(capacity, elem), Value::Pair(length, vector)) => {
                let (Value::Int(length), Value::Vec(items)) =
                    (values.get(length).clone(), values.get(vector).clone())
                else {
                    return Err(invalid());
                };
                let empty = values
                    .zero_cached(types, *elem, defaults)
                    .ok_or_else(invalid)?;
                if items.len() != capacity.get() as usize
                    || length.is_negative()
                    || *length > BigInt::from(capacity.get())
                {
                    return Err(invalid());
                }
                let used = length.to_usize().expect("bounded input sequence count");
                if items
                    .iter()
                    .enumerate()
                    .any(|(index, value)| index >= used && !values.equal(*value, empty))
                {
                    return Err(invalid());
                }
                pending.extend(items.iter().rev().map(|item| (next, *elem, *item)));
            }
            (Type::Cap(kind), Value::Cap(actual, id)) if *kind == actual => {
                if !caps.insert((*kind, id)) {
                    return Err(Error::CapabilityDuplicate(*kind, id));
                }
            }
            (Type::Enc(key, remaining), Value::Enc(actual_key, actual_remaining, _))
                if *key == actual_key && *remaining == actual_remaining => {}
            (Type::Pair(left_type, right_type), Value::Pair(left, right)) => {
                pending.push((next, *right_type, right));
                pending.push((next, *left_type, left));
            }
            (Type::Sum(left, _), Value::Inl(value)) => pending.push((next, *left, value)),
            (Type::Sum(_, right), Value::Inr(value)) => pending.push((next, *right, value)),
            _ => return Err(invalid()),
        }
        nodes += 1;
    }
    Ok(())
}
pub(super) fn environment(
    types: &Types,
    values: &mut Values,
    inputs: &[(Bind, ValueId)],
) -> Result<Env> {
    let mut env = Env::default();
    let mut caps = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut defaults = ZeroCache::new();
    for (binding, value) in inputs {
        if !ids.insert(binding.id) {
            return Err(Error::Input(binding.id));
        }
        input_value(types, values, *binding, *value, &mut caps, &mut defaults)?;
        env.bind(*binding, *value);
    }
    Ok(env)
}
