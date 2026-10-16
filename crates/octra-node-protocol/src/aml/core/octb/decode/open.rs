// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Independent recognition of scalar and schema-bearing open wrappers. Guards
//! are compared in full before the body is admitted to the machine profile.
use super::{
    profile, verify, BigInt, Context, DecodeError, Literal, Natural, Op, Result, Schema, Shapes,
    ToPrimitive, Type, TypeId, Zero, I, V,
};
const BODY_BASE: u32 = 10_000_000;
pub(super) struct Open {
    pub inputs: Vec<TypeId>,
    pub output: TypeId,
    pub results: Vec<u8>,
    pub entry: usize,
    pub code: Vec<Op>,
    pub guarded: bool,
}
fn header(code: &[I]) -> bool {
    if code.len() < 8 {
        return false;
    }
    matches!(&code[..7], [I::Jdest(100), I::Mload(61, 1000), I::Ldi(62, name), I::Eq(63, 61, 62), I::Jif(63, 200), I::Revert(), I::Jdest(200)] if matches!(name.as_ref(), V::Str(name) if name.as_ref() == b"main"))
}
fn target(pc: usize, count: usize, target: u32) -> Result<u32> {
    target
        .checked_sub(BODY_BASE)
        .filter(|index| (*index as usize) < count)
        .ok_or(DecodeError::JumpRef(pc, target))
}
fn result_regs(regs: &[u32]) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    regs.iter().all(|reg| *reg <= 60 && seen.insert(*reg))
}
impl Context<'_> {
    fn input_type(&mut self, code: &[I], pc: usize, index: usize) -> Option<(TypeId, usize)> {
        let reg = u8::try_from(index + 1).ok()?;
        let memory = u16::try_from(1001 + index).ok()?;
        let yes = 1000 + u32::try_from(index).ok()? * 2;
        let done = yes + 1;
        if let Some([I::Mload(dst, at), I::Ldi(61, zero), I::Sub(out, source, 61)]) =
            code.get(pc..pc + 3)
        {
            if *dst == reg
                && *at == memory
                && *out == reg
                && *source == reg
                && matches!(zero.as_ref(), V::Int(zero) if zero.is_zero())
            {
                return Some((self.types.intern(Type::Int), pc + 3));
            }
        }
        if let Some(
            [I::Mload(dst, at), I::Jif(guard, yes_at), I::Nop(), I::Jmp(done_jump), I::Jdest(yes_mark), I::Jmp(done_two), I::Jdest(done_mark)],
        ) = code.get(pc..pc + 7)
        {
            if *dst == reg
                && *at == memory
                && *guard == reg
                && *yes_at == yes
                && *yes_mark == yes
                && *done_jump == done
                && *done_two == done
                && *done_mark == done
            {
                return Some((self.types.intern(Type::Bool), pc + 7));
            }
        }
        if let Some(
            [I::Mload(dst, at), I::Ldi(61, empty), I::Eq(63, left, 61), I::Strlen(61, text), I::Ldi(62, length), I::Eq(63, 61, 62), I::Jif(63, jump), I::Revert(), I::Jdest(mark), I::Ldi(61, zero), I::Substr(out, source, 61, 62)],
        ) = code.get(pc..pc + 11)
        {
            if *dst == reg
                && *at == memory
                && *left == reg
                && *text == reg
                && *jump == yes
                && *mark == yes
                && *out == reg
                && *source == reg
                && matches!(empty.as_ref(), V::Bytes(empty) if empty.is_empty())
                && matches!(zero.as_ref(), V::Int(zero) if zero.is_zero())
            {
                if let V::Int(length) = length.as_ref() {
                    let length = Natural::new(length)?;
                    return Some((self.types.intern(Type::Bytes(length)), pc + 11));
                }
            }
        }
        None
    }
    fn body(&mut self, native: &[I], at: usize, count: usize, data: bool) -> Result<Vec<Op>> {
        if count == 0 {
            return Err(DecodeError::EmptyCode);
        }
        let mut code = Vec::with_capacity(count);
        for pc in 0..count {
            let absolute = at + pc;
            let value = &native[absolute];
            let op = if data && pc == count - 1 {
                match value {
                    I::Jdest(found) if *found == BODY_BASE + pc as u32 => Op::Stop,
                    _ => return Err(DecodeError::Opcode(absolute, i32::from(value.opcode()))),
                }
            } else {
                match value {
                    I::Jmp(found) => Op::Jump(target(absolute, count, *found)?),
                    I::Jif(guard, found) => {
                        let target = target(absolute, count, *found)?;
                        Op::JumpIf(profile::reg(absolute, *guard)?, target)
                    }
                    I::Jdest(found) if *found == BODY_BASE + pc as u32 => Op::Mark(pc as u32),
                    I::Jdest(found) => return Err(DecodeError::JumpRef(absolute, *found)),
                    I::Stop() if data => return Err(DecodeError::ResultHeader),
                    _ => self.profile(absolute, value)?,
                }
            };
            code.push(op);
        }
        verify(&code, true)?;
        Ok(code)
    }
    fn result_type(&mut self, code: &[Op]) -> Option<(TypeId, usize)> {
        let n = code.len();
        if n >= 3
            && matches!(&code[n - 3..], [Op::Load(61, Literal::Int(zero)), Op::Minus(0, 0, 61), Op::Stop] if zero.is_zero())
        {
            return Some((self.types.intern(Type::Int), n - 3));
        }
        if n >= 7 {
            if let [Op::JumpIf(0, yes), Op::Noop, Op::Jump(done), Op::Mark(yes_mark), Op::Jump(done_two), Op::Mark(done_mark), Op::Stop] =
                &code[n - 7..]
            {
                if *yes as usize == n - 4
                    && *yes_mark as usize == n - 4
                    && *done as usize == n - 2
                    && *done_two as usize == n - 2
                    && *done_mark as usize == n - 2
                {
                    return Some((self.types.intern(Type::Bool), n - 7));
                }
            }
        }
        if n >= 11 {
            if let [Op::Load(61, Literal::Bytes(empty)), Op::Same(63, 0, 61), Op::Size(61, 0), Op::Load(62, Literal::Int(length)), Op::Same(63, 61, 62), Op::JumpIf(63, yes), Op::Load(61, Literal::Int(one)), Op::Load(62, Literal::Int(zero)), Op::Quotient(61, 61, 62), Op::Mark(mark), Op::Stop] =
                &code[n - 11..]
            {
                if empty.is_empty()
                    && **one == BigInt::from(1)
                    && zero.is_zero()
                    && *yes as usize == n - 2
                    && *mark as usize == n - 2
                {
                    return Some((
                        self.types.intern(Type::Bytes(Natural::new(length)?)),
                        n - 11,
                    ));
                }
            }
        }
        None
    }
    fn data_claim(&mut self, native: &[I]) -> Result<Option<Open>> {
        if native.len() <= 8 {
            return Ok(None);
        }
        let I::Ldi(61, raw) = &native[7] else {
            return Ok(None);
        };
        let V::Str(raw) = raw.as_ref() else {
            return Ok(None);
        };
        let schema = Schema::read(self.types, raw).ok_or(DecodeError::SchemaInvalid)?;
        if schema.inputs().is_empty() {
            return Err(DecodeError::SchemaInvalid);
        }
        let mut shapes = Shapes::default();
        let mut width = BigInt::from(0);
        let mut cells = BigInt::from(0);
        for typ in schema.inputs() {
            let shape = shapes
                .from_type(self.types, *typ)
                .ok_or(DecodeError::SchemaInvalid)?;
            width += shapes.width(shape);
            cells += shapes.cells(shape);
        }
        if width > BigInt::from(60) {
            return Err(DecodeError::SchemaInvalid);
        }
        let output = shapes
            .from_type(self.types, schema.output())
            .ok_or(DecodeError::SchemaInvalid)?;
        let result_width = shapes.width(output);
        cells += shapes.cells(output);
        if cells > BigInt::from(4096) {
            return Err(DecodeError::SchemaInvalid);
        }
        let count = width.to_usize().expect("bounded machine width");
        let (checks, found) =
            super::super::guards::data_input_code(self.types, self.values, schema.inputs())
                .map_err(|_| DecodeError::SchemaInvalid)?;
        if found != count {
            return Err(DecodeError::SchemaInvalid);
        }
        let mut expected = (0..count)
            .map(|index| I::Mload((index + 1) as u8, (1001 + index) as u16))
            .collect::<Vec<_>>();
        expected.extend(checks);
        let mut at = 8;
        for op in expected {
            let found = native.get(at).ok_or(DecodeError::EmptyCode)?;
            if *found != op {
                return Err(DecodeError::Opcode(at, i32::from(found.opcode())));
            }
            at += 1;
        }
        if native.get(at) != Some(&I::Nop()) {
            return Err(DecodeError::ResultHeader);
        }
        if result_width != BigInt::from(schema.results().len()) || !result_regs(schema.results()) {
            return Err(DecodeError::SchemaInvalid);
        }
        let results = schema
            .results()
            .iter()
            .map(|reg| *reg as u8)
            .collect::<Vec<_>>();
        let mut suffix =
            super::super::guards::guard_code(self.types, self.values, schema.output(), &results)
                .map_err(|_| DecodeError::SchemaInvalid)?;
        suffix.push(I::Stop());
        let entry = at + 1;
        let count = native
            .len()
            .checked_sub(entry + suffix.len())
            .filter(|count| *count >= 1)
            .ok_or(DecodeError::ResultHeader)?;
        for (offset, op) in suffix.iter().enumerate() {
            let pc = entry + count + offset;
            if native.get(pc) != Some(op) {
                return Err(DecodeError::Opcode(
                    pc,
                    native.get(pc).map_or(-1, |op| i32::from(op.opcode())),
                ));
            }
        }
        let code = self.body(native, entry, count, true)?;
        Ok(Some(Open {
            inputs: schema.inputs().to_vec(),
            output: schema.output(),
            results,
            entry,
            code,
            guarded: true,
        }))
    }
    pub(super) fn open_claim(&mut self, native: &[I]) -> Result<Option<Open>> {
        if !header(native) {
            return Ok(None);
        }
        if let Some(open) = self.data_claim(native)? {
            return Ok(Some(open));
        }
        let mut at = 7;
        let mut inputs = vec![];
        loop {
            let op = native.get(at).ok_or(DecodeError::EmptyCode)?;
            if matches!(op, I::Nop()) {
                if inputs.is_empty() {
                    return Err(DecodeError::EmptyCode);
                }
                break;
            }
            if inputs.len() >= 60 {
                return Err(DecodeError::RegisterRef(at, inputs.len() as u32 + 1));
            }
            let (typ, next) = self
                .input_type(native, at, inputs.len())
                .ok_or(DecodeError::Opcode(at, i32::from(op.opcode())))?;
            inputs.push(typ);
            at = next;
        }
        let entry = at + 1;
        let code = self.body(native, entry, native.len() - entry, false)?;
        let (output, first) = self.result_type(&code).ok_or(DecodeError::ResultHeader)?;
        for op in code.iter().take(first) {
            if matches!(op, Op::Stop)
                || matches!(op, Op::Jump(target) | Op::JumpIf(_, target) if *target as usize >= first)
            {
                return Err(DecodeError::ResultHeader);
            }
        }
        Ok(Some(Open {
            inputs,
            output,
            results: vec![0],
            entry,
            code,
            guarded: false,
        }))
    }
}
