// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::linear::integer;
use super::{
    Arc, Asm, Bind, Cells, CodeId, Context, Error, Frame, Layout, LayoutId, LocationId, Marked,
    Multiplicity, Op, ShapeId, Span, State,
};
pub(super) struct Start {
    pub sequence: bool,
    pub count: super::super::super::Natural,
    pub item: Bind,
    pub state: Bind,
    pub body: CodeId,
    pub lbody: LocationId,
    pub rest: CodeId,
    pub lrest: LocationId,
    pub at: Span,
}
struct Fold {
    start: Start,
    values: Arc<[LayoutId]>,
    index: usize,
    remainder: Vec<LayoutId>,
    state_shape: ShapeId,
    len_reg: Option<u8>,
}
struct Conditional {
    dst: LayoutId,
    guard: u8,
    index_reg: u8,
    yes: u32,
    done: u32,
    env: Cells,
    prefix: Vec<Marked>,
}
pub(super) struct Iteration {
    fold: Fold,
    state_value: LayoutId,
    item_value: LayoutId,
    conditional: Option<Conditional>,
}
fn marked(env: &Cells, at: Span, asm: Asm) -> Marked {
    Marked {
        asm,
        at,
        live: env.view(),
    }
}
impl Context<'_> {
    pub(super) fn fold_start(
        &mut self,
        state: &mut State,
        start: Start,
    ) -> Result<(CodeId, LocationId, Option<Frame>), Error> {
        if start.item.multiplicity == Multiplicity::Zero
            || start.state.multiplicity == Multiplicity::Zero
        {
            return Err(Error::Slot);
        }
        let state_value = self.pop(state)?;
        let input = self.pop(state)?;
        let (len_reg, vector) = if start.sequence {
            let Layout::Pair(length, vector) = self.layouts.get(input) else {
                return Err(Error::Stack);
            };
            (Some(self.atom(*length)?), *vector)
        } else {
            (None, input)
        };
        let Layout::Vec(elem, vector) = self.layouts.get(vector).clone() else {
            return Err(Error::Stack);
        };
        let values = self.layouts.vectors.collect(vector);
        let item_shape = self
            .shapes
            .from_type(self.types, start.item.typ)
            .ok_or(Error::Stack)?;
        let state_shape = self
            .shapes
            .from_type(self.types, start.state.typ)
            .ok_or(Error::Stack)?;
        if values.len() != start.count.get() as usize
            || item_shape != elem
            || !self.layouts.fits(&self.shapes, state_shape, state_value)
            || values
                .iter()
                .any(|value| !self.layouts.fits(&self.shapes, elem, *value))
        {
            return Err(Error::Stack);
        }
        let fold = Fold {
            start,
            values: values.into(),
            index: 0,
            remainder: state.stack.clone(),
            state_shape,
            len_reg,
        };
        self.fold_next(state, fold, state_value)
    }
    fn fold_next(
        &mut self,
        state: &mut State,
        fold: Fold,
        state_value: LayoutId,
    ) -> Result<(CodeId, LocationId, Option<Frame>), Error> {
        let Some(item_value) = fold.values.get(fold.index).copied() else {
            if let Some(reg) = fold.len_reg {
                state.generator.release(reg);
            }
            state.stack = fold.remainder;
            state.stack.push(state_value);
            return Ok((fold.start.rest, fold.start.lrest, None));
        };
        let conditional = if fold.len_reg.is_some() {
            let dst = self
                .layouts
                .alloc(&self.shapes, fold.state_shape, &mut state.generator)?;
            let guard = state.generator.fresh()?;
            let index_reg = state.generator.fresh()?;
            let yes = state.generator.fresh_label()?;
            let done = state.generator.fresh_label()?;
            state.generator.release(guard);
            state.generator.release(index_reg);
            Some(Conditional {
                dst,
                guard,
                index_reg,
                yes,
                done,
                env: state.env.clone(),
                prefix: std::mem::take(&mut state.seq),
            })
        } else {
            None
        };
        self.open(state, fold.start.item, item_value)?;
        self.open(state, fold.start.state, state_value)?;
        state.stack = fold.remainder.clone();
        let next = fold.start.body;
        let location = fold.start.lbody;
        Ok((
            next,
            location,
            Some(Frame::Fold(Iteration {
                fold,
                state_value,
                item_value,
                conditional,
            })),
        ))
    }
    pub(super) fn fold_finish(
        &mut self,
        state: &mut State,
        iteration: Iteration,
    ) -> Result<(CodeId, LocationId, Option<Frame>), Error> {
        let Iteration {
            mut fold,
            state_value,
            item_value,
            conditional,
        } = iteration;
        let next_state = self.exact(&state.stack, &fold.remainder)?;
        state.env.close(fold.start.state).ok_or(Error::Slot)?;
        state.env.close(fold.start.item).ok_or(Error::Slot)?;
        let output = if let Some(mut branch) = conditional {
            if !branch.env.same(&self.layouts, &state.env) {
                return Err(Error::Slot);
            }
            let no_move = self
                .layouts
                .copy(state_value, branch.dst)
                .ok_or(Error::Stack)?;
            let yes_move = self
                .layouts
                .copy(next_state, branch.dst)
                .ok_or(Error::Stack)?;
            let len_reg = fold.len_reg.expect("conditional sequence length");
            let mut live = vec![len_reg];
            live.extend(self.layouts.registers(branch.dst));
            for value in fold
                .values
                .iter()
                .skip(fold.index + 1)
                .chain(fold.remainder.iter())
            {
                live.extend(self.layouts.registers(*value));
            }
            live.extend(branch.env.registers(&self.layouts, true));
            state.generator.available(state.generator.next, &live)?;
            let at = fold.start.at;
            branch.prefix.push(marked(
                &branch.env,
                at,
                Asm::Op(Op::Load(branch.index_reg, integer(fold.index))),
            ));
            branch.prefix.push(marked(
                &branch.env,
                at,
                Asm::Op(Op::Less(branch.guard, branch.index_reg, len_reg)),
            ));
            branch.prefix.push(marked(
                &branch.env,
                at,
                Asm::Branch(branch.guard, branch.yes),
            ));
            branch.prefix.extend(
                no_move
                    .into_iter()
                    .map(|(dst, src)| marked(&branch.env, at, Asm::Op(Op::Move(dst, src)))),
            );
            branch
                .prefix
                .push(marked(&branch.env, at, Asm::Goto(branch.done)));
            branch
                .prefix
                .push(marked(&branch.env, at, Asm::Place(branch.yes)));
            branch.prefix.append(&mut state.seq);
            branch.prefix.extend(
                yes_move
                    .into_iter()
                    .map(|(dst, src)| marked(&state.env, at, Asm::Op(Op::Move(dst, src)))),
            );
            branch
                .prefix
                .push(marked(&branch.env, at, Asm::Place(branch.done)));
            state.env = branch.env;
            state.seq = branch.prefix;
            branch.dst
        } else {
            self.layouts.release(state_value, &mut state.generator);
            self.layouts.release(item_value, &mut state.generator);
            next_state
        };
        fold.index += 1;
        self.fold_next(state, fold, output)
    }
}
