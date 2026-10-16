// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_mach stack-shape flow, with explicit frames for scopes and branches.
use super::super::{
    term::Bind,
    types::{Multiplicity, Type, Types},
    Natural,
};
use super::{Code, CodeId, Codes, Operation as Op, Shape, ShapeId, Shapes};
enum Frame {
    Resume(CodeId),
    Keep {
        remainder: Vec<ShapeId>,
        expected: Option<ShapeId>,
        rest: CodeId,
    },
    Branch {
        remainder: Vec<ShapeId>,
        expected: ShapeId,
        no: CodeId,
        rest: CodeId,
    },
}
fn keep(stack: &[ShapeId], remainder: &[ShapeId], expected: Option<ShapeId>) -> bool {
    stack.len() == remainder.len() + 1
        && stack[..remainder.len()] == *remainder
        && expected.is_none_or(|expected| stack.last() == Some(&expected))
}
fn bindings(
    shapes: &mut Shapes,
    types: &Types,
    item: Bind,
    state: Bind,
    elem: ShapeId,
    seed: ShapeId,
) -> bool {
    item.multiplicity != Multiplicity::Zero
        && state.multiplicity != Multiplicity::Zero
        && shapes.from_type(types, item.typ) == Some(elem)
        && shapes.from_type(types, state.typ) == Some(seed)
}
impl Codes {
    /// The end of the vector is the top of the native machine stack.
    pub fn flow(
        &self,
        shapes: &mut Shapes,
        types: &Types,
        mut code: CodeId,
        mut stack: Vec<ShapeId>,
    ) -> Option<Vec<ShapeId>> {
        let mut frames = vec![];
        loop {
            let (op, rest) = match self.get(code) {
                Code::Next(op, rest) => (op, *rest),
                Code::Done => match frames.pop() {
                    None => return Some(stack),
                    Some(Frame::Resume(rest)) => {
                        code = rest;
                        continue;
                    }
                    Some(Frame::Keep {
                        remainder,
                        expected,
                        rest,
                    }) => {
                        if !keep(&stack, &remainder, expected) {
                            return None;
                        }
                        code = rest;
                        continue;
                    }
                    Some(Frame::Branch {
                        remainder,
                        expected,
                        no,
                        rest,
                    }) => {
                        if !keep(&stack, &remainder, Some(expected)) {
                            return None;
                        }
                        frames.push(Frame::Keep {
                            remainder: remainder.clone(),
                            expected: Some(expected),
                            rest,
                        });
                        stack = remainder;
                        code = no;
                        continue;
                    }
                },
            };
            match op {
                Op::Push(_) => stack.push(shapes.intern(Shape::Atom)),
                Op::Void => stack.push(shapes.intern(Shape::Unit)),
                Op::Get(_, form) => stack.push(*form),
                Op::Plus
                | Op::Minus
                | Op::Times
                | Op::Quot
                | Op::Rem
                | Op::Same
                | Op::Different
                | Op::Order(_)
                | Op::Join => {
                    if !matches!(shapes.get(stack.pop()?), Shape::Atom)
                        || !matches!(shapes.get(stack.pop()?), Shape::Atom)
                    {
                        return None;
                    }
                    stack.push(shapes.intern(Shape::Atom));
                }
                Op::Negate | Op::Absolute | Op::Clip(_) | Op::Skip(_) | Op::Wide => {
                    if !matches!(shapes.get(*stack.last()?), Shape::Atom) {
                        return None;
                    }
                }
                Op::Duo => {
                    let right = stack.pop()?;
                    let left = stack.pop()?;
                    stack.push(shapes.intern(Shape::Pair(left, right)));
                }
                Op::First | Op::Second => {
                    let Shape::Pair(left, right) = shapes.get(stack.pop()?).clone() else {
                        return None;
                    };
                    stack.push(if matches!(op, Op::First) { left } else { right });
                }
                Op::Empty(elem) => {
                    stack.push(shapes.intern(Shape::Vec(Natural::from_u32(0)?, *elem)));
                }
                Op::Cons => {
                    let Shape::Vec(length, elem) = shapes.get(stack.pop()?).clone() else {
                        return None;
                    };
                    if stack.pop()? != elem {
                        return None;
                    }
                    stack.push(
                        shapes.intern(Shape::Vec(length.checked_add(Natural::from_u32(1)?)?, elem)),
                    );
                }
                Op::Append => {
                    let Shape::Vec(rn, re) = shapes.get(stack.pop()?).clone() else {
                        return None;
                    };
                    let Shape::Vec(ln, le) = shapes.get(stack.pop()?).clone() else {
                        return None;
                    };
                    if le != re {
                        return None;
                    }
                    stack.push(shapes.intern(Shape::Vec(ln.checked_add(rn)?, le)));
                }
                Op::Pick(index) => {
                    let Shape::Vec(length, elem) = shapes.get(stack.pop()?).clone() else {
                        return None;
                    };
                    if index >= &length {
                        return None;
                    }
                    stack.push(elem);
                }
                Op::Unhead => {
                    let Shape::Vec(length, elem) = shapes.get(stack.pop()?).clone() else {
                        return None;
                    };
                    let tail =
                        shapes.intern(Shape::Vec(length.checked_sub(Natural::from_u32(1)?)?, elem));
                    stack.push(shapes.intern(Shape::Pair(elem, tail)));
                }
                Op::Left | Op::Right => {
                    let payload = stack.pop()?;
                    stack.push(shapes.intern(Shape::Sum(payload)));
                }
                Op::Pack(capacity, typ) => {
                    let Shape::Vec(length, elem) = shapes.get(stack.pop()?).clone() else {
                        return None;
                    };
                    if length > *capacity || shapes.from_type(types, *typ) != Some(elem) {
                        return None;
                    }
                    let atom = shapes.intern(Shape::Atom);
                    let vector = shapes.intern(Shape::Vec(*capacity, elem));
                    stack.push(shapes.intern(Shape::Pair(atom, vector)));
                }
                Op::Fit(typ) => {
                    if !matches!(shapes.get(stack.pop()?), Shape::Atom)
                        || !matches!(types.get(*typ), Type::Num(..))
                        || !types.valid(*typ)
                    {
                        return None;
                    }
                    let atom = shapes.intern(Shape::Atom);
                    stack.push(shapes.intern(Shape::Sum(atom)));
                }
                Op::Close(kind) => {
                    if !matches!(shapes.get(stack.pop()?), Shape::Cap(found) if found == kind) {
                        return None;
                    }
                    stack.push(shapes.intern(Shape::Unit));
                }
                Op::Effect { body, .. } => {
                    // Effect bodies may change the full stack; no scope check.
                    code = *body;
                    frames.push(Frame::Resume(rest));
                    continue;
                }
                Op::Scope(_, body) | Op::Scope2(_, _, body) => {
                    let input = stack.pop()?;
                    if matches!(op, Op::Scope2(..)) && !matches!(shapes.get(input), Shape::Pair(..))
                    {
                        return None;
                    }
                    frames.push(Frame::Keep {
                        remainder: stack.clone(),
                        expected: None,
                        rest,
                    });
                    code = *body;
                    continue;
                }
                Op::Iter {
                    sequence,
                    count,
                    item,
                    state,
                    body,
                } => {
                    let seed = stack.pop()?;
                    let vector = stack.pop()?;
                    let (found, elem) = if *sequence {
                        let Shape::Pair(length, vector) = shapes.get(vector) else {
                            return None;
                        };
                        if !matches!(shapes.get(*length), Shape::Atom) {
                            return None;
                        }
                        let Shape::Vec(capacity, elem) = shapes.get(*vector) else {
                            return None;
                        };
                        (*capacity, *elem)
                    } else {
                        let Shape::Vec(length, elem) = shapes.get(vector) else {
                            return None;
                        };
                        (*length, *elem)
                    };
                    if found != *count || !bindings(shapes, types, *item, *state, elem, seed) {
                        return None;
                    }
                    frames.push(Frame::Keep {
                        remainder: stack.clone(),
                        expected: Some(seed),
                        rest,
                    });
                    code = *body;
                    continue;
                }
                Op::Choice {
                    left,
                    yes,
                    right,
                    no,
                    shape,
                } => {
                    let Shape::Sum(payload) = shapes.get(stack.pop()?).clone() else {
                        return None;
                    };
                    if !bindings(shapes, types, *left, *right, payload, payload) {
                        return None;
                    }
                    frames.push(Frame::Branch {
                        remainder: stack.clone(),
                        expected: *shape,
                        no: *no,
                        rest,
                    });
                    code = *yes;
                    continue;
                }
                Op::Fork { shape, yes, no } => {
                    if !matches!(shapes.get(stack.pop()?), Shape::Atom) {
                        return None;
                    }
                    frames.push(Frame::Branch {
                        remainder: stack.clone(),
                        expected: *shape,
                        no: *no,
                        rest,
                    });
                    code = *yes;
                    continue;
                }
            }
            code = rest;
        }
    }
    pub fn one_shape(&self, shapes: &mut Shapes, types: &Types, code: CodeId) -> Option<ShapeId> {
        let stack = self.flow(shapes, types, code, vec![])?;
        if let [shape] = stack.as_slice() {
            Some(*shape)
        } else {
            None
        }
    }
}
