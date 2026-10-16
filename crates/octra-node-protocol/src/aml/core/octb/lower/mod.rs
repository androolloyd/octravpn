// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_octb register lowering. Explicit frames preserve native branch allocation
//! order and loop expansion without recursively traversing source-owned terms.
use super::super::{
    eval::Values,
    lexer::Span,
    machine::{
        self, Code, CodeId, Codes, Literal, Location, LocationId, LocationTag, Locations,
        Operation as Core, ShapeId, Shapes,
    },
    term::Bind,
    types::{self, Multiplicity, Type, TypeId, Types},
    Atom,
};
use super::{
    seed, Asm, Assembly, Cells, EffectLayout, Error, Generator, Layout, LayoutId, Layouts, Marked,
    Operation as Op,
};
use num_bigint::BigInt;
use std::sync::Arc;
mod branch;
mod fold;
mod linear;
pub struct Machine<'a> {
    pub inputs: &'a [Bind],
    pub codes: &'a Codes,
    pub root: CodeId,
    pub locations: &'a Locations,
    pub location: LocationId,
    pub span: Span,
    pub shapes: &'a Shapes,
}
impl<'a> From<&'a machine::Image> for Machine<'a> {
    fn from(image: &'a machine::Image) -> Self {
        Self {
            inputs: image.inputs(),
            codes: image.codes(),
            root: image.code(),
            locations: image.locations(),
            location: image.location(),
            span: image.span(),
            shapes: image.shapes(),
        }
    }
}
#[derive(Clone, Debug)]
pub struct Plan {
    pub marked: Vec<Marked>,
    pub inputs: Vec<u8>,
    pub results: Vec<u8>,
}
impl Plan {
    pub fn resolve(&self) -> Result<Assembly, Error> {
        super::resolve(&self.marked)
    }
}
struct State {
    env: Cells,
    generator: Generator,
    stack: Vec<LayoutId>,
    seq: Vec<Marked>,
}
struct Context<'a> {
    types: &'a Types,
    values: &'a mut Values,
    layouts: Layouts,
    shapes: Shapes,
}
struct Scope {
    close: Vec<Bind>,
    release: Vec<LayoutId>,
    remainder: Vec<LayoutId>,
    rest: CodeId,
    location: LocationId,
}
enum Frame {
    Scope(Scope),
    Effect {
        index: i64,
        atom: Atom,
        at: Span,
        rest: CodeId,
        location: LocationId,
    },
    BranchNo(branch::Branch),
    BranchYes(branch::Branch, State),
    Fold(fold::Iteration),
}
impl Context<'_> {
    fn push(&mut self, state: &mut State, value: Layout) {
        state.stack.push(self.layouts.push(value));
    }
    // Keep this operation on the shared native checker/host method interface.
    #[allow(clippy::unused_self)]
    fn pop(&self, state: &mut State) -> Result<LayoutId, Error> {
        state.stack.pop().ok_or(Error::Stack)
    }
    fn atom(&self, id: LayoutId) -> Result<u8, Error> {
        if let Layout::Atom(reg) = self.layouts.get(id) {
            Ok(*reg)
        } else {
            Err(Error::Stack)
        }
    }
    fn emit(state: &mut State, at: Span, asm: Asm) {
        state.seq.push(Marked {
            asm,
            at,
            live: state.env.view(),
        });
    }
    fn ops(state: &mut State, at: Span, ops: impl IntoIterator<Item = Op>) {
        for op in ops {
            Self::emit(state, at, Asm::Op(op));
        }
    }
    fn moves(
        &self,
        state: &mut State,
        at: Span,
        source: LayoutId,
        target: LayoutId,
    ) -> Result<(), Error> {
        let moves = self.layouts.copy(source, target).ok_or(Error::Stack)?;
        Self::ops(
            state,
            at,
            moves
                .into_iter()
                .map(|(target, source)| Op::Move(target, source)),
        );
        Ok(())
    }
    fn exact(&self, stack: &[LayoutId], remainder: &[LayoutId]) -> Result<LayoutId, Error> {
        if stack.len() != remainder.len() + 1
            || !stack[..remainder.len()]
                .iter()
                .zip(remainder)
                .all(|(left, right)| self.layouts.same(*left, *right))
        {
            return Err(Error::Stack);
        }
        Ok(*stack.last().expect("one result above remainder"))
    }
    fn open(&mut self, state: &mut State, bind: Bind, value: LayoutId) -> Result<(), Error> {
        state
            .env
            .open(&mut self.shapes, self.types, &self.layouts, bind, value)
            .ok_or(Error::Slot)
    }
    fn finish_scope(&self, state: &mut State, scope: Scope) -> Result<(CodeId, LocationId), Error> {
        self.exact(&state.stack, &scope.remainder)?;
        for bind in scope.close {
            state.env.close(bind).ok_or(Error::Slot)?;
        }
        self.layouts
            .release_all(&scope.release, &mut state.generator);
        Ok((scope.rest, scope.location))
    }
    fn load_value(
        &mut self,
        state: &mut State,
        at: Span,
        typ: TypeId,
        value: super::super::eval::ValueId,
    ) -> Result<LayoutId, Error> {
        let shape = self.shapes.from_type(self.types, typ).ok_or(Error::Stack)?;
        let literals = machine::atoms(self.types, self.values, typ, value).ok_or(Error::Stack)?;
        let layout = self
            .layouts
            .alloc(&self.shapes, shape, &mut state.generator)?;
        let registers = self.layouts.registers(layout);
        if registers.len() != literals.len() {
            return Err(Error::Stack);
        }
        Self::ops(
            state,
            at,
            registers
                .into_iter()
                .zip(literals)
                .map(|(reg, literal)| Op::Load(reg, literal)),
        );
        Ok(layout)
    }
    fn run(
        &mut self,
        state: &mut State,
        codes: &Codes,
        locations: &Locations,
        mut code: CodeId,
        mut location: LocationId,
    ) -> Result<(), Error> {
        let mut frames = vec![];
        loop {
            let node = codes.get(code).clone();
            let mark = locations.get(location).clone();
            let (op, rest, at, branches, bodies, lrest) = match (node, mark) {
                (Code::Done, Location::Done) => {
                    let Some(frame) = frames.pop() else {
                        return Ok(());
                    };
                    (code, location) = match frame {
                        Frame::Scope(scope) => self.finish_scope(state, scope)?,
                        Frame::Effect {
                            index,
                            atom,
                            at,
                            rest,
                            location,
                        } => {
                            let payload = self
                                .layouts
                                .registers(*state.stack.last().ok_or(Error::Stack)?);
                            let scratch = state.generator.scratch(atom)?;
                            Self::emit(
                                state,
                                at,
                                Asm::Apply(EffectLayout {
                                    index,
                                    atom,
                                    payload,
                                    scratch,
                                }),
                            );
                            (rest, location)
                        }
                        Frame::BranchNo(branch) => {
                            let (next, mark, frame) = self.branch_yes(state, branch)?;
                            frames.push(frame);
                            (next, mark)
                        }
                        Frame::BranchYes(branch, no) => self.branch_join(state, branch, no)?,
                        Frame::Fold(iteration) => {
                            let (next, mark, frame) = self.fold_finish(state, iteration)?;
                            if let Some(frame) = frame {
                                frames.push(frame);
                            }
                            (next, mark)
                        }
                    };
                    continue;
                }
                (
                    Code::Next(op, rest),
                    Location::Next {
                        tag,
                        at,
                        branches,
                        bodies,
                        rest: lrest,
                    },
                ) if LocationTag::of(&op) == tag && op.children().len() == bodies.len() => {
                    (op, rest, at, branches, bodies, lrest)
                }
                _ => return Err(Error::Map),
            };
            match &op {
                Core::Scope(bind, body) => {
                    let value = self.pop(state)?;
                    self.open(state, *bind, value)?;
                    frames.push(Frame::Scope(Scope {
                        close: vec![*bind],
                        release: vec![value],
                        remainder: state.stack.clone(),
                        rest,
                        location: lrest,
                    }));
                    code = *body;
                    location = bodies[0];
                    continue;
                }
                Core::Scope2(left, right, body) => {
                    let value = self.pop(state)?;
                    let Layout::Pair(lhs, rhs) = self.layouts.get(value).clone() else {
                        return Err(Error::Stack);
                    };
                    self.open(state, *left, lhs)?;
                    self.open(state, *right, rhs)?;
                    frames.push(Frame::Scope(Scope {
                        close: vec![*right, *left],
                        release: vec![lhs, rhs],
                        remainder: state.stack.clone(),
                        rest,
                        location: lrest,
                    }));
                    code = *body;
                    location = bodies[0];
                    continue;
                }
                Core::Effect { index, atom, body } => {
                    frames.push(Frame::Effect {
                        index: *index,
                        atom: *atom,
                        at,
                        rest,
                        location: lrest,
                    });
                    code = *body;
                    location = bodies[0];
                    continue;
                }
                Core::Fork { shape, yes, no } => {
                    let input = self.pop(state)?;
                    let guard = self.atom(input)?;
                    let (next, mark, frame) = self.branch_start(
                        state,
                        branch::Start {
                            guard,
                            payload: None,
                            shape: *shape,
                            yes: *yes,
                            no: *no,
                            binds: None,
                            rest,
                            lrest,
                            at,
                            branches: branches.ok_or(Error::Map)?,
                            bodies,
                        },
                    )?;
                    frames.push(frame);
                    code = next;
                    location = mark;
                    continue;
                }
                Core::Choice {
                    left,
                    yes,
                    right,
                    no,
                    shape,
                } => {
                    let input = self.pop(state)?;
                    let Layout::Sum(guard, payload) = self.layouts.get(input).clone() else {
                        return Err(Error::Stack);
                    };
                    let (next, mark, frame) = self.branch_start(
                        state,
                        branch::Start {
                            guard,
                            payload: Some(payload),
                            shape: *shape,
                            yes: *yes,
                            no: *no,
                            binds: Some([*left, *right]),
                            rest,
                            lrest,
                            at,
                            branches: branches.ok_or(Error::Map)?,
                            bodies,
                        },
                    )?;
                    frames.push(frame);
                    code = next;
                    location = mark;
                    continue;
                }
                Core::Iter {
                    sequence,
                    count,
                    item,
                    state: bind,
                    body,
                } => {
                    let (next, mark, frame) = self.fold_start(
                        state,
                        fold::Start {
                            sequence: *sequence,
                            count: *count,
                            item: *item,
                            state: *bind,
                            body: *body,
                            lbody: bodies[0],
                            rest,
                            lrest,
                            at,
                        },
                    )?;
                    if let Some(frame) = frame {
                        frames.push(frame);
                    }
                    code = next;
                    location = mark;
                    continue;
                }
                _ => self.linear(state, at, &op)?,
            }
            code = rest;
            location = lrest;
        }
    }
}
#[derive(Clone, Copy)]
enum Mode {
    Image,
    Layouts,
    Effects,
}
pub fn lower(types: &Types, values: &mut Values, machine: Machine<'_>) -> Result<Plan, Error> {
    lower_mode(types, values, machine, Mode::Image)
}
pub(super) fn lower_effect(
    types: &Types,
    values: &mut Values,
    machine: Machine<'_>,
    emit: bool,
) -> Result<Plan, Error> {
    lower_mode(
        types,
        values,
        machine,
        if emit { Mode::Effects } else { Mode::Layouts },
    )
}
// Keep the native owned-input interface and its diagnostic/arena ownership.
#[allow(clippy::needless_pass_by_value)]
fn lower_mode(
    types: &Types,
    values: &mut Values,
    machine: Machine<'_>,
    mode: Mode,
) -> Result<Plan, Error> {
    let mut context = Context {
        types,
        values,
        layouts: Layouts::default(),
        shapes: machine.shapes.clone(),
    };
    let seed = seed(
        &mut context.shapes,
        types,
        &mut context.layouts,
        machine.inputs,
    )?;
    let inputs = seed
        .inputs
        .iter()
        .flat_map(|layout| context.layouts.registers(*layout))
        .collect();
    let mut state = State {
        env: seed.env,
        generator: seed.generator,
        stack: vec![],
        seq: vec![],
    };
    context.run(
        &mut state,
        machine.codes,
        machine.locations,
        machine.root,
        machine.location,
    )?;
    let [result] = state.stack.as_slice() else {
        return Err(if matches!(mode, Mode::Layouts) {
            Error::EffectMap
        } else {
            Error::Stack
        });
    };
    let result = *result;
    if matches!(mode, Mode::Effects) && !matches!(context.layouts.get(result), Layout::Atom(_)) {
        return Err(Error::Stack);
    }
    if !state.env.terminal(machine.inputs) {
        return Err(if matches!(mode, Mode::Layouts) {
            Error::EffectMap
        } else {
            Error::Slot
        });
    }
    if matches!(mode, Mode::Layouts) {
        return Ok(Plan {
            marked: state.seq,
            inputs,
            results: vec![],
        });
    }
    let results = match context.layouts.get(result) {
        Layout::Atom(reg) => {
            let reg = *reg;
            if reg != 0 {
                Context::ops(&mut state, machine.span, [Op::Move(0, reg)]);
            }
            vec![0]
        }
        Layout::Unit => vec![],
        _ => context.layouts.registers(result),
    };
    Context::ops(&mut state, machine.span, [Op::Stop]);
    Ok(Plan {
        marked: state.seq,
        inputs,
        results,
    })
}
