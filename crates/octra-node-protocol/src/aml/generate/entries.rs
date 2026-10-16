// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Imperative and linked-form entry points with explicit call-evidence output.
use super::super::{call::Call, evidence::Evidence, forms::Linked};
use super::{
    check_interfaces, types, Arc, Ast, Error, Function, Generator, Name, Param, Refinement, Result,
    Syntax, Type, Visibility,
};
use crate::octb::Instruction as I;

#[derive(Clone, Debug)]
pub struct Generated {
    pub code: Vec<I>,
    pub seals: Vec<Call>,
}

/// Emission alone confers no authority. The source deployment path must still
/// independently reconstruct certificates, facts and the admitted byte stream.
pub fn imperative(ast: &mut Ast, syntax: Syntax, loops: bool) -> Result<Vec<I>> {
    if !ast.contract.forms.is_empty() {
        check_interfaces(ast)?;
        return Err(Error::Unavailable("compiler form linking is required"));
    }
    Ok(generate(ast, syntax, loops, vec![], &[])?.code)
}
/// Historical Oct_emit entry path. Compilation reports and Program admission
/// remain separate, and this does not select the frozen Prior compiler.
pub fn protocol(ast: &mut Ast, loops: bool, checked: bool) -> Result<Vec<I>> {
    check_interfaces(ast)?;
    let mut generator = Generator::protocol(ast, loops, checked);
    legacy_entries(&mut generator)?;
    Ok(generator.code.into_instructions())
}
pub fn prior(ast: &mut Ast) -> Result<Vec<I>> {
    check_interfaces(ast)?;
    let mut generator = Generator::prior(ast);
    legacy_entries(&mut generator)?;
    Ok(generator.code.into_instructions())
}
fn legacy_entries(generator: &mut Generator<'_>) -> Result<()> {
    generator.prepare_labels()?;
    let constructor = generator.contract.constructor.clone();
    generator.constructor(constructor.as_ref())?;
    generator.dispatcher()?;
    for (index, function) in generator.contract.functions.clone().iter().enumerate() {
        generator.function(function, entry_label(index)?)?;
    }
    Ok(())
}

pub fn linked(linked: &mut Linked, syntax: Syntax, loops: bool) -> Result<Generated> {
    generate(
        &mut linked.ast,
        syntax,
        loops,
        linked.direct.clone(),
        &linked.calls,
    )
}

/// As upstream, this returns call seals separately from instructions. Artifact
/// packaging must bind them to the final encoded image and verify that binding.
pub fn generate(
    ast: &mut Ast,
    syntax: Syntax,
    loops: bool,
    direct: Vec<Name>,
    calls: &[(Name, Evidence)],
) -> Result<Generated> {
    check_interfaces(ast)?;
    let mut generator = Generator::new(ast, syntax, loops, direct);
    generator.prepare_labels()?;
    let constructor = generator.contract.constructor.clone();
    generator.constructor(constructor.as_ref())?;
    generator.dispatcher()?;
    let functions = generator.contract.functions.clone();
    let mut seals = vec![];
    for (index, function) in functions.iter().enumerate() {
        let label = entry_label(index)?;
        if let Some((_, evidence)) = calls.iter().find(|(name, _)| name == &function.name) {
            let call = Call::make(
                i64::from(label),
                i64::from(generator.code.next_label),
                evidence.clone(),
            )
            .map_err(|failure| Error::Invalid {
                message: [function.name.as_slice(), b" ", &failure.text()].concat(),
                line: 0,
                column: 1,
            })?;
            generator.code.next_label = u32::try_from(call.next())
                .map_err(|_| Error::Unavailable("compiler call-label transport exhausted"))?;
            for instruction in call.wire_code() {
                generator.code.emit(instruction)?;
            }
            seals.push(call);
        } else {
            generator.function(function, label)?;
        }
    }
    if !generator.forms.is_empty() {
        generator.validate_depth(generator.code.instructions())?;
    }
    Ok(Generated {
        code: generator.code.into_instructions(),
        seals,
    })
}
pub(super) fn entry_label(index: usize) -> Result<u32> {
    u32::try_from(index)
        .ok()
        .and_then(|index| index.checked_mul(100))
        .and_then(|index| index.checked_add(200))
        .ok_or(Error::Unavailable(
            "compiler entry-label transport exhausted",
        ))
}
impl Generator<'_> {
    fn nonpayable(&self, function: &Function) -> bool {
        self.has_payable && !function.payable && function.visibility == Visibility::Public
    }
    pub(super) fn prepare_labels(&mut self) -> Result<()> {
        if !self.forms.is_empty() {
            self.code.next_label = self
                .code
                .next_label
                .max(entry_label(self.contract.functions.len())?);
        }
        for (index, function) in self.contract.functions.iter().enumerate() {
            let label = if self.is_direct(&function.name) && self.nonpayable(function) {
                self.code.alloc_label()?
            } else {
                entry_label(index)?
            };
            self.function_labels.insert(function.name.clone(), label);
        }
        Ok(())
    }
    fn constructor_gate(&mut self) -> Result<()> {
        self.code.base_reg = 1;
        self.code.next_reg = 1;
        let check = self.code.alloc_reg()?;
        let name = self.code.alloc_reg()?;
        let comparison = self.code.alloc_reg()?;
        self.code.emit(I::Mload(check, 999))?;
        self.code.string(name, b"constructor")?;
        self.code.emit(I::Neq(comparison, check, name))?;
        self.code.emit(I::Jif(comparison, 100))
    }
    pub(super) fn constructor(&mut self, constructor: Option<&Function>) -> Result<()> {
        let Some(constructor) = constructor else {
            self.constructor_gate()?;
            return self.code.emit(I::Stop());
        };
        let saved = (
            self.locals.clone(),
            self.code.base_reg,
            self.code.next_reg,
            self.function_return,
        );
        self.function_return = self.nodes.intern(Type::Void);
        self.locals = Arc::new(vec![]);
        self.constructor_gate()?;
        self.code.base_reg = 1;
        self.code.next_reg = 1;
        self.parameters(&constructor.params)?;
        self.block(&constructor.body)?;
        self.finish_entry()?;
        (
            self.locals,
            self.code.base_reg,
            self.code.next_reg,
            self.function_return,
        ) = saved;
        Ok(())
    }
    fn parameters(&mut self, params: &[Param]) -> Result<()> {
        for (index, param) in params.iter().enumerate() {
            let register = u8::try_from(self.code.base_reg).map_err(|_| {
                Error::Unavailable("compiler parameter-register transport exhausted")
            })?;
            let slot = u16::try_from(1001 + index)
                .map_err(|_| Error::Unavailable("compiler parameter-slot transport exhausted"))?;
            self.code.emit(I::Mload(register, slot))?;
            self.bind(param.name.clone(), register, param.typ);
            self.code.base_reg += 1;
        }
        self.code.next_reg = self.code.base_reg;
        for param in params {
            if let Some(register) = self.local(&param.name).map(|local| local.register) {
                self.code.type_check(register, self.nodes.typ(param.typ))?;
            }
        }
        Ok(())
    }
    pub(super) fn dispatcher(&mut self) -> Result<()> {
        self.code.base_reg = 1;
        self.code.next_reg = 1;
        self.code.emit(I::Jdest(100))?;
        let method = self.code.alloc_reg()?;
        self.code.emit(I::Mload(method, 1000))?;
        let name = self.code.alloc_reg()?;
        let comparison = self.code.alloc_reg()?;
        for (index, function) in self.contract.functions.iter().enumerate() {
            if function.visibility == Visibility::Public {
                self.code.string(name, &function.name)?;
                self.code.emit(I::Eq(comparison, method, name))?;
                self.code.emit(I::Jif(comparison, entry_label(index)?))?;
            }
        }
        self.code.emit(I::Revert())
    }
    fn refinements(&mut self, params: &[Param]) -> Result<()> {
        for param in params {
            let Some(refinement) = &param.refine else {
                continue;
            };
            if !self.code.is_protocol() && !types::numeric(self.nodes.typ(param.typ)) {
                return Err(self.code.error(
                    [
                        b"refinement type is not numeric parameter = ".as_slice(),
                        &param.name,
                    ]
                    .concat(),
                ));
            }
            let Some(register) = self.local(&param.name).map(|local| local.register) else {
                continue;
            };
            let value = self.code.alloc_reg()?;
            let comparison = self.code.alloc_reg()?;
            let ok = self.code.alloc_label()?;
            let bound = match refinement {
                Refinement::Gt(_, bound)
                | Refinement::Ge(_, bound)
                | Refinement::Lt(_, bound)
                | Refinement::Le(_, bound)
                | Refinement::Neq(_, bound) => *bound,
                Refinement::NonZero(_) => 0,
            };
            self.code.integer(value, bound)?;
            self.code.emit(match refinement {
                Refinement::Gt(..) | Refinement::Le(..) => I::Gt(comparison, register, value),
                Refinement::Ge(..) | Refinement::Lt(..) => I::Lt(comparison, register, value),
                Refinement::Neq(..) | Refinement::NonZero(_) => I::Eq(comparison, register, value),
            })?;
            if matches!(
                refinement,
                Refinement::Ge(..)
                    | Refinement::Le(..)
                    | Refinement::Neq(..)
                    | Refinement::NonZero(_)
            ) {
                let zero = self.code.alloc_reg()?;
                self.code.integer(zero, 0)?;
                self.code.emit(I::Eq(comparison, comparison, zero))?;
            }
            self.code.emit(I::Jif(comparison, ok))?;
            self.code.emit(I::Revert())?;
            self.code.emit(I::Jdest(ok))?;
        }
        Ok(())
    }
    pub(super) fn function(&mut self, function: &Function, label: u32) -> Result<()> {
        let saved = (
            self.locals.clone(),
            self.code.base_reg,
            self.code.next_reg,
            self.code.view,
            self.code.pure,
            self.function_direct,
            self.function_return,
        );
        if !self.code.is_protocol() {
            self.code.position.line = types::block_line(self.nodes, &function.body);
        }
        if !self.code.is_protocol()
            && self.nodes.typ(function.ret) != &Type::Void
            && !types::Returns::new(self.nodes).block(&function.body)
        {
            return Err(self.code.error(
                [
                    b"function return is not total function = ".as_slice(),
                    &function.name,
                    b" type = ",
                    self.nodes.typ(function.ret).name(),
                ]
                .concat(),
            ));
        }
        self.code.view = function.view;
        self.code.pure = function.pure;
        self.function_direct = self.is_direct(&function.name);
        self.function_return = function.ret;
        self.locals = Arc::new(vec![]);
        self.code.base_reg = 1;
        self.code.next_reg = 1;
        let call_label = self
            .function_labels
            .get(&function.name)
            .copied()
            .ok_or(Error::Unavailable("compiler function label is missing"))?;
        let split = !self.code.is_protocol() && call_label != label;
        self.code.emit(I::Jdest(label))?;
        if split {
            self.code.nonpayable_guard(call_label)?;
        }
        self.parameters(&function.params)?;
        self.refinements(&function.params)?;
        if self.nonpayable(function) && !split {
            let ok = self.code.alloc_label()?;
            self.code.nonpayable_guard(ok)?;
        }
        if function.nonreentrant {
            self.code.nonreentrant_enter()?;
        }
        self.in_nonreentrant = function.nonreentrant;
        self.block(&function.body)?;
        if function.nonreentrant {
            self.code.nonreentrant_exit()?;
        }
        self.finish_entry()?;
        self.in_nonreentrant = false;
        (
            self.locals,
            self.code.base_reg,
            self.code.next_reg,
            self.code.view,
            self.code.pure,
            self.function_direct,
            self.function_return,
        ) = saved;
        Ok(())
    }
    fn finish_entry(&mut self) -> Result<()> {
        // The adopted generator reverses its reverse-built code before this
        // check, so it inspects the first instruction, not the entry's tail.
        if !matches!(self.code.instructions().first(), Some(I::Stop())) {
            self.code.emit(I::Stop())?;
        }
        Ok(())
    }
}
