// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{work, Budget, Exec, Instruction as I, IntegerOp, Machine, Request, Trap, Value};
use num_traits::{ToPrimitive, Zero};
pub(super) fn fixed(op: &I) -> i64 {
    op.effort_cost()
}

impl Machine {
    // Positional operand names match the native instruction layout.
    #[allow(clippy::many_single_char_names)]
    fn strict(&self, op: &I) -> Exec<bool> {
        Ok(match op {
            I::Add(_, a, b) => self.get(*a)?.add_operand(self.get(*b)?),
            I::Sub(_, a, b)
            | I::Mul(_, a, b)
            | I::Div(_, a, b)
            | I::Mod(_, a, b)
            | I::Lt(_, a, b)
            | I::Gt(_, a, b)
            | I::Bitand(_, a, b)
            | I::Bitor(_, a, b)
            | I::Bitxor(_, a, b)
            | I::Bitshl(_, a, b)
            | I::Bitshr(_, a, b) => self.get(*a)?.numeric() && self.get(*b)?.numeric(),
            I::Neg(_, a) | I::Abs(_, a) | I::Mloadr(_, a) => self.get(*a)?.numeric(),
            I::Mstore(_, a) => !matches!(self.get(*a)?, Value::Capability(_)),
            I::Mstorer(a, b) => {
                self.get(*a)?.numeric() && !matches!(self.get(*b)?, Value::Capability(_))
            }
            I::Eq(_, a, b) | I::Neq(_, a, b) => self.get(*a)?.comparable(self.get(*b)?),
            I::Jif(a, _) | I::Assert(a) => matches!(self.get(*a)?, Value::Bool(_)),
            I::Balance(_, a)
            | I::Sloadk(_, a)
            | I::Sdelk(a)
            | I::Isaddr(_, a)
            | I::Ishex(_, a)
            | I::StatePathKey(_, a)
            | I::AssertAddr(a) => self.get(*a)?.is_address(),
            I::CapCheck(kind, reg) | I::CapClose(kind, reg) => {
                matches!(self.get(*reg)?,Value::Capability(cap) if cap.matches(kind))
            }
            I::Sstore(key, source) => {
                let value = self.get(*source)?;
                self.options
                    .storage_kinds
                    .get(key.as_ref())
                    .map_or_else(|| value.scalar(), |kind| value.matches_storage(*kind))
            }
            I::Sstorek(key, value) => self.get(*key)?.is_address() && self.get(*value)?.scalar(),
            I::ParseInts(_, text, base) | I::Skeys(_, text, base) => {
                self.get(*text)?.is_text() && self.get(*base)?.numeric()
            }
            I::ObjectMemberCount(_, object) => self.get(*object)?.is_text(),
            I::ObjectHasMember(_, object, member) => {
                self.get(*object)?.is_text() && self.get(*member)?.is_text()
            }
            I::ObjectMemberRefAt(_, object, index) => {
                self.get(*object)?.is_text() && self.get(*index)?.numeric()
            }
            I::ObjectTransitionApply(_, a, b, c, d, e, f, g, h, i, j) => {
                [a, b, c, d, e, f, g, h, i, j]
                    .into_iter()
                    .map(|reg| self.get(*reg).map(Value::is_text))
                    .collect::<Exec<Vec<_>>>()?
                    .into_iter()
                    .all(|v| v)
            }
            I::SkeysPage(_, _, prefix, after, base) => {
                self.get(*prefix)?.is_text()
                    && self.get(*after)?.is_text()
                    && self.get(*base)?.numeric()
            }
            I::ExpQ16(_, source) => self.get(*source)?.numeric(),
            I::SoftmaxQ16Inplace(base, count) | I::SiluQ16Inplace(base, count) => {
                self.get(*base)?.numeric() && self.get(*count)?.numeric()
            }
            I::LayernormQ16Inplace(a, b, c, d)
            | I::RopeApplyQ16(a, b, c, d)
            | I::AppendVecQ16(a, b, c, d) => [a, b, c, d]
                .into_iter()
                .map(|r| self.get(*r).map(Value::numeric))
                .collect::<Exec<Vec<_>>>()?
                .into_iter()
                .all(|v| v),
            I::RmsnormQ16Inplace(a, b, c)
            | I::ElemwiseMulQ16(a, b, c)
            | I::ResidualAddQ16(a, b, c)
            | I::ArgmaxQ16(a, b, c)
            | I::VecdotQ16(_, a, b, c) => {
                self.get(*a)?.numeric() && self.get(*b)?.numeric() && self.get(*c)?.numeric()
            }
            I::AttentionKvQ16(a, b, c, d, e, f, g, h) => [a, b, c, d, e, f, g, h]
                .into_iter()
                .map(|r| self.get(*r).map(Value::numeric))
                .collect::<Exec<Vec<_>>>()?
                .into_iter()
                .all(|v| v),
            I::LoadInt8BytesToMem(dest, source, off, count, scale)
            | I::LoadInt8B64ToMem(dest, source, off, count, scale)
            | I::LoadInt8Q16(dest, source, off, count, scale) => {
                self.get(*dest)?.numeric()
                    && self.get(*source)?.is_text()
                    && self.get(*off)?.numeric()
                    && self.get(*count)?.numeric()
                    && self.get(*scale)?.numeric()
            }
            I::Sloadn(key, value, count) | I::Sstoren(key, value, count) => {
                self.get(*key)?.numeric()
                    && self.get(*value)?.numeric()
                    && self.get(*count)?.numeric()
            }
            I::Ed25519Ok(_, key, message, signature)
            | I::Groth16VerifyBn254(_, key, message, signature) => {
                self.get(*key)?.is_text()
                    && self.get(*message)?.is_text()
                    && self.get(*signature)?.is_text()
            }
            I::FheLoadPk(_, source) => self.get(*source)?.is_address(),
            I::FheAdd(_, p, a, b) | I::FheSub(_, p, a, b) | I::FheMul(_, p, a, b) => {
                matches!(self.get(*p)?, Value::PublicKey(_))
                    && matches!(self.get(*a)?, Value::Cipher(_))
                    && matches!(self.get(*b)?, Value::Cipher(_))
            }
            I::FheScale(_, p, c, s)
            | I::FheDivConst(_, p, c, s)
            | I::FheAddConst(_, p, c, s)
            | I::FheSubConst(_, p, c, s) => {
                matches!(self.get(*p)?, Value::PublicKey(_))
                    && matches!(self.get(*c)?, Value::Cipher(_))
                    && self.get(*s)?.numeric()
            }
            I::FheVerifyZero(_, p, c, proof) | I::FheVerifyRange(_, p, c, proof) => {
                matches!(self.get(*p)?, Value::PublicKey(_))
                    && matches!(self.get(*c)?, Value::Cipher(_))
                    && self.get(*proof)?.is_text()
            }
            I::FheVerifyBound(_, p, c, proof, commit) => {
                matches!(self.get(*p)?, Value::PublicKey(_))
                    && matches!(self.get(*c)?, Value::Cipher(_))
                    && self.get(*proof)?.is_text()
                    && self.get(*commit)?.is_text()
            }
            I::FheCommit(_, p, c) => {
                matches!(self.get(*p)?, Value::PublicKey(_))
                    && matches!(self.get(*c)?, Value::Cipher(_))
            }
            I::FhePedersen(_, a, b) => self.get(*a)?.numeric() && self.get(*b)?.is_text(),
            I::FhePedersenAdd(_, a, b) | I::FhePedersenSub(_, a, b) => {
                self.get(*a)?.is_text() && self.get(*b)?.is_text()
            }
            I::FheSer(_, c) => matches!(self.get(*c)?, Value::Cipher(_)),
            I::FheDeser(_, r) | I::FheDeserPk(_, r) => self.get(*r)?.is_text(),
            I::FheSerPk(_, p) => matches!(self.get(*p)?, Value::PublicKey(_)),
            I::Substr(_, s, a, b) => {
                self.get(*s)?.is_text() && self.get(*a)?.numeric() && self.get(*b)?.numeric()
            }
            I::Indexof(_, s, p) => self.get(*s)?.is_text() && self.get(*p)?.is_text(),
            I::Sha256(_, s)
            | I::Keccak256(_, s)
            | I::Fstore(_, s)
            | I::Fload(_, s)
            | I::Strlen(_, s) => self.get(*s)?.is_text(),
            I::Concat(_, a, b) => {
                let a = self.get(*a)?;
                let b = self.get(*b)?;
                if self.options.typed_bytes {
                    matches!((a, b), (Value::Bytes(_), Value::Bytes(_)))
                } else {
                    a.scalar() && b.scalar()
                }
            }
            I::Transfer(_, a, b) => self.get(*a)?.is_address() && self.get(*b)?.numeric(),
            I::Spawn(_, source) => self.get(*source)?.is_text(),
            I::Spawn2(_, source, base, count) => {
                self.get(*source)?.is_text()
                    && u16::from(*base) + u16::from(*count) <= 64
                    && self.regs[usize::from(*base)..usize::from(*base) + usize::from(*count)]
                        .iter()
                        .all(|v| !matches!(v, Value::Capability(_)))
            }
            I::Xcall(_, target, method, base, count) => {
                self.get(*target)?.is_address()
                    && self.get(*method)?.is_text()
                    && u16::from(*base) + u16::from(*count) <= 64
                    && self.regs[usize::from(*base)..usize::from(*base) + usize::from(*count)]
                        .iter()
                        .all(|v| !matches!(v, Value::Capability(_)))
            }
            I::Emit(_, regs) => regs
                .iter()
                .map(|r| self.get(*r).map(|v| !matches!(v, Value::Capability(_))))
                .collect::<Exec<Vec<_>>>()?
                .iter()
                .all(|v| *v),
            _ => true,
        })
    }
    // Positional operand names match the native instruction layout.
    #[allow(clippy::many_single_char_names)]
    fn inputs(&self, op: &I) -> Vec<(u8, i64, bool)> {
        let numeric =
            |registers: &[u8], passes: i64| registers.iter().map(|r| (*r, passes, false)).collect();
        let indices = |registers: &[u8], passes: i64| {
            registers.iter().map(|r| (*r, passes + 1, true)).collect()
        };
        match op {
            I::Add(_, a, b) if self.options.strict => numeric(&[*a, *b], 3),
            I::Add(_, a, b)
            | I::Sub(_, a, b)
            | I::Mul(_, a, b)
            | I::Div(_, a, b)
            | I::Mod(_, a, b) => numeric(&[*a, *b], 2),
            I::Neg(_, a) | I::Abs(_, a) => numeric(&[*a], 2),
            I::Lt(_, a, b)
            | I::Gt(_, a, b)
            | I::Bitand(_, a, b)
            | I::Bitor(_, a, b)
            | I::Bitxor(_, a, b) => numeric(&[*a, *b], 1),
            I::Bitshl(_, a, b) | I::Bitshr(_, a, b) => vec![(*a, 1, false), (*b, 2, true)],
            I::Mloadr(_, a)
            | I::Mstorer(a, _)
            | I::ParseInts(_, _, a)
            | I::ObjectMemberRefAt(_, _, a)
            | I::Skeys(_, _, a)
            | I::SkeysPage(_, _, _, _, a) => indices(&[*a], 1),
            I::Sloadn(a, b, c)
            | I::Vecdot(_, a, b, c)
            | I::VecdotQ16(_, a, b, c)
            | I::RmsnormQ16Inplace(a, b, c)
            | I::ElemwiseMulInplace(a, b, c)
            | I::ElemwiseMulQ16(a, b, c)
            | I::ResidualAdd(a, b, c)
            | I::ResidualAddQ16(a, b, c)
            | I::ShiftRoundInplace(a, b, c) => indices(&[*a, *b, *c], 1),
            I::Sstoren(a, b, c) => indices(&[*a, *b, *c], 2),
            I::Matmul(a, b, c, d, e, f) | I::MatmulQ16(a, b, c, d, e, f) => {
                indices(&[*a, *b, *c, *d, *e, *f], 1)
            }
            I::SoftmaxQ16Inplace(a, b)
            | I::ReluInplace(a, b)
            | I::SiluQ16Inplace(a, b)
            | I::ArgmaxQ16(_, a, b) => indices(&[*a, *b], 1),
            I::LayernormQ16Inplace(a, b, c, d) | I::AppendVecQ16(a, b, c, d) => {
                indices(&[*a, *b, *c, *d], 1)
            }
            I::RopeApplyQ16(a, b, c, d) => {
                let mut values = indices(&[*a, *b, *c], 1);
                values.extend(numeric(&[*d], 1));
                values
            }
            I::LoadInt8BytesToMem(a, _, b, c, d)
            | I::LoadInt8B64ToMem(a, _, b, c, d)
            | I::LoadInt8Q16(a, _, b, c, d) => {
                let mut values = indices(
                    &[*a, *b, *c],
                    if matches!(op, I::LoadInt8BytesToMem(..)) {
                        1
                    } else {
                        2
                    },
                );
                values.extend(numeric(&[*d], 1));
                values
            }
            I::AttentionKvQ16(a, b, c, d, e, f, g, h) => {
                indices(&[*a, *b, *c, *d, *e, *f, *g, *h], 1)
            }
            I::ExpQ16(_, source)
            | I::FheScale(_, _, _, source)
            | I::FheDivConst(_, _, _, source)
            | I::FheAddConst(_, _, _, source)
            | I::FheSubConst(_, _, _, source)
            | I::FhePedersen(_, source, _) => numeric(&[*source], 1),
            I::Substr(_, _, a, b) => indices(&[*a, *b], 2),
            I::Transfer(_, _, a) => numeric(&[*a], 1),
            _ => vec![],
        }
    }
    fn reserve_numbers(&mut self, op: &I, budget: &mut Option<&mut Budget>) -> Exec {
        let Some(b) = budget else { return Ok(()) };
        let inputs = self.inputs(op);
        let mut base = 0;
        let mut requests = Vec::new();
        for (reg, passes, _) in &inputs {
            if let Value::String(raw) = self.get(*reg)? {
                let (cost, parts) = work::parsing(raw.len() as i64, 1).ok_or(Trap::Refused)?;
                base += passes * cost;
                // Native prepends each register's request group. Atomic planning
                // gives the same result, while preserving all repeated charges.
                for _ in 0..*passes {
                    requests.extend_from_slice(&parts);
                }
            }
        }
        if !requests.is_empty() {
            b.plan(self.effort, self.options.limit, base + fixed(op), &requests)
                .ok_or(Trap::Refused)?;
            self.effort = b
                .charge(self.effort, self.options.limit, base, &requests)
                .ok_or(Trap::Refused)?;
        }
        for (reg, _, machine) in inputs {
            if machine {
                self.index(reg).map_err(|_| Trap::Refused)?;
            }
        }
        Ok(())
    }
    fn reserve_text(&mut self, reg: u8, budget: &mut Budget) -> Exec {
        let value = self.get(reg)?.clone();
        self.reserve_value_text(&value, budget)
    }
    pub(super) fn text_fits(value: &Value, cap: i64) -> bool {
        !value.numeric() || u128::from(value.number().bits()) <= cap.max(0) as u128 * 4
    }
    pub(super) fn reserve_value_text(&mut self, value: &Value, budget: &mut Budget) -> Exec {
        if value.numeric() {
            let bits = value.number().bits();
            if u128::from(bits) > budget.text_limit() as u128 * 4 {
                return Err(Trap::Refused);
            }
            let size = (bits / 3 + 2).to_i64().ok_or(Trap::Refused)?;
            if size > budget.text_limit() {
                return Err(Trap::Refused);
            }
            self.effort = budget
                .charge(
                    self.effort,
                    self.options.limit,
                    0,
                    &[Request::Allocate(size)],
                )
                .ok_or(Trap::Refused)?;
        }
        Ok(())
    }
    fn byte_inputs(&mut self, op: &I, budget: &mut Option<&mut Budget>) -> Exec {
        let Some(b) = budget else { return Ok(()) };
        let regs: Vec<_> = match op {
            I::Sstorek(a, b) | I::Concat(_, a, b) | I::Indexof(_, a, b) => vec![*a, *b],
            I::Substr(_, a, start, len) => {
                let reg = *a;
                self.reserve_text(reg, b)?;
                self.index(*start).map_err(|_| Trap::Refused)?;
                self.index(*len).map_err(|_| Trap::Refused)?;
                return Ok(());
            }
            I::Sstore(_, a)
            | I::Fstore(_, a)
            | I::Spawn(_, a)
            | I::Spawn2(_, a, ..)
            | I::Strlen(_, a)
            | I::Sha256(_, a)
            | I::Keccak256(_, a)
            | I::Sdelk(a)
            | I::ParseInts(_, a, _)
            | I::Skeys(_, a, _) => vec![*a],
            I::SkeysPage(_, _, a, c, _) => vec![*a, *c],
            I::LoadInt8BytesToMem(dest, source, offset, count, _)
            | I::LoadInt8B64ToMem(dest, source, offset, count, _)
            | I::LoadInt8Q16(dest, source, offset, count, _) => {
                self.reserve_text(*source, b)?;
                for reg in [dest, offset, count] {
                    self.index(*reg).map_err(|_| Trap::Refused)?;
                }
                vec![]
            }
            I::Sstoren(keys, values, count) => {
                let count = self.index(*count)?;
                let keys = self.index(*keys)?;
                let values = self.index(*values)?;
                if !(0..=1000).contains(&count)
                    || !(0..=16_777_216).contains(&keys)
                    || !(0..=16_777_216).contains(&values)
                    || count > 16_777_216 - keys
                    || count > 16_777_216 - values
                {
                    return Err(Trap::Refused);
                }
                for index in 0..count {
                    for base in [keys, values] {
                        if self
                            .memory
                            .get(&(base + index))
                            .is_some_and(|v| !Self::text_fits(v, b.text_limit()))
                        {
                            return Err(Trap::Refused);
                        }
                    }
                }
                vec![]
            }
            _ => vec![],
        };
        for reg in regs {
            self.reserve_text(reg, b)?;
        }
        Ok(())
    }
    pub(super) fn prepare(&mut self, op: &I, budget: &mut Option<&mut Budget>) -> Exec {
        self.reserve_numbers(op, budget)?;
        let strict = !self.options.strict || self.strict(op)?;
        let active = self.options.integer_work || budget.is_some();
        let cost = if strict {
            match op {
                I::Add(_, a, b)
                | I::Sub(_, a, b)
                | I::Mul(_, a, b)
                | I::Div(_, a, b)
                | I::Mod(_, a, b) => {
                    let kind = match op {
                        I::Add(..) => IntegerOp::Add,
                        I::Sub(..) => IntegerOp::Sub,
                        I::Mul(..) => IntegerOp::Mul,
                        I::Div(..) => IntegerOp::Div,
                        _ => IntegerOp::Mod,
                    };
                    kind.cost(
                        active,
                        fixed(op),
                        &self.get(*a)?.number(),
                        &self.get(*b)?.number(),
                    )
                }
                I::Neg(_, a) | I::Abs(_, a) => {
                    let kind = if matches!(op, I::Neg(..)) {
                        IntegerOp::Neg
                    } else {
                        IntegerOp::Abs
                    };
                    kind.cost(
                        active,
                        fixed(op),
                        &self.get(*a)?.number(),
                        &num_bigint::BigInt::zero(),
                    )
                }
                _ => fixed(op).into(),
            }
        } else {
            fixed(op).into()
        };
        self.charge_integer(&cost)?;
        if !strict {
            return Err(Trap::Refused);
        }
        self.byte_inputs(op, budget)
    }
}
