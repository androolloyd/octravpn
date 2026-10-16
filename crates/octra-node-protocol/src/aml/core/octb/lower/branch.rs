// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    Asm, Bind, Cells, CodeId, Context, Error, Frame, Generator, LayoutId, LocationId, Marked,
    ShapeId, Span, State,
};
pub(super) struct Start {
    pub guard: u8,
    pub payload: Option<LayoutId>,
    pub shape: ShapeId,
    pub yes: CodeId,
    pub no: CodeId,
    pub binds: Option<[Bind; 2]>,
    pub rest: CodeId,
    pub lrest: LocationId,
    pub at: Span,
    pub branches: [Span; 2],
    pub bodies: Vec<LocationId>,
}
pub(super) struct Branch {
    start: Start,
    env: Cells,
    generator: Generator,
    remainder: Vec<LayoutId>,
    dst: LayoutId,
    prefix: Vec<Marked>,
    yes_label: u32,
    end_label: u32,
}
fn marked(env: &Cells, at: Span, asm: Asm) -> Marked {
    Marked {
        asm,
        at,
        live: env.view(),
    }
}
impl Context<'_> {
    pub(super) fn branch_start(
        &mut self,
        state: &mut State,
        start: Start,
    ) -> Result<(CodeId, LocationId, Frame), Error> {
        state.generator.release(start.guard);
        let dst = self
            .layouts
            .alloc(&self.shapes, start.shape, &mut state.generator)?;
        let yes_label = state.generator.fresh_label()?;
        let end_label = state.generator.fresh_label()?;
        let branch = Branch {
            env: state.env.clone(),
            generator: state.generator.clone(),
            remainder: state.stack.clone(),
            dst,
            prefix: std::mem::take(&mut state.seq),
            yes_label,
            end_label,
            start,
        };
        if let (Some([_, right]), Some(payload)) = (branch.start.binds, branch.start.payload) {
            self.open(state, right, payload)?;
        }
        Ok((
            branch.start.no,
            branch.start.bodies[1],
            Frame::BranchNo(branch),
        ))
    }
    pub(super) fn branch_yes(
        &mut self,
        state: &mut State,
        branch: Branch,
    ) -> Result<(CodeId, LocationId, Frame), Error> {
        if let Some([_, right]) = branch.start.binds {
            state.env.close(right).ok_or(Error::Slot)?;
        }
        let mut generator = branch.generator.clone();
        generator.label = state.generator.label;
        let yes = State {
            env: branch.env.clone(),
            generator,
            stack: branch.remainder.clone(),
            seq: vec![],
        };
        let no = std::mem::replace(state, yes);
        if let (Some([left, _]), Some(payload)) = (branch.start.binds, branch.start.payload) {
            self.open(state, left, payload)?;
        }
        Ok((
            branch.start.yes,
            branch.start.bodies[0],
            Frame::BranchYes(branch, no),
        ))
    }
    // Keep this operation on the shared native checker/host method interface.
    #[allow(clippy::needless_pass_by_ref_mut)]
    pub(super) fn branch_join(
        &mut self,
        state: &mut State,
        branch: Branch,
        mut no: State,
    ) -> Result<(CodeId, LocationId), Error> {
        if let Some([left, _]) = branch.start.binds {
            state.env.close(left).ok_or(Error::Slot)?;
        }
        let no_value = self.exact(&no.stack, &branch.remainder)?;
        let yes_value = self.exact(&state.stack, &branch.remainder)?;
        if !no.env.same(&self.layouts, &state.env)
            || !self
                .layouts
                .fits(&self.shapes, branch.start.shape, no_value)
            || !self
                .layouts
                .fits(&self.shapes, branch.start.shape, yes_value)
        {
            return Err(Error::Slot);
        }
        self.moves(&mut no, branch.start.branches[1], no_value, branch.dst)?;
        self.moves(state, branch.start.branches[0], yes_value, branch.dst)?;
        let next = no.generator.next.max(state.generator.next);
        let mut live = self.layouts.registers(branch.dst);
        for value in &branch.remainder {
            live.extend(self.layouts.registers(*value));
        }
        live.extend(no.env.registers(&self.layouts, false));
        state.generator.available(next, &live)?;
        let mut seq = branch.prefix;
        seq.push(marked(
            &branch.env,
            branch.start.at,
            Asm::Branch(branch.start.guard, branch.yes_label),
        ));
        seq.append(&mut no.seq);
        seq.push(marked(
            &no.env,
            branch.start.at,
            Asm::Goto(branch.end_label),
        ));
        seq.push(marked(
            &branch.env,
            branch.start.at,
            Asm::Place(branch.yes_label),
        ));
        seq.append(&mut state.seq);
        seq.push(marked(
            &no.env,
            branch.start.at,
            Asm::Place(branch.end_label),
        ));
        state.env = no.env;
        state.stack = branch.remainder;
        state.stack.push(branch.dst);
        state.seq = seq;
        Ok((branch.start.rest, branch.start.lrest))
    }
}
