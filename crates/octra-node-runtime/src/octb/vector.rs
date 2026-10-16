// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native integer and Q16 vector execution. Prior integer loops read live memory;
//! activated integer work snapshots operands before charging and mutating them.
use super::{
    data, work, BigInt, Budget, Exec, Instruction as I, IntegerOp, Machine, Request, Trap,
    Unavailable, Value,
};
use num_traits::{Signed, Zero};
use octra_node_protocol::{native_base64, octb::q16};

enum Operands {
    Live,
    Fixed(Vec<(BigInt, BigInt)>),
}
fn qspan(base: i64, count: i64) -> bool {
    base >= 0 && (1..=131_072).contains(&count) && base <= work::MAX_INT - count
}
fn array_words(length: i64) -> i128 {
    if length == 0 {
        0
    } else {
        i128::from(length) + 1
    }
}
impl Machine {
    fn vector_indices<const N: usize>(&self, regs: [u8; N]) -> Exec<[i64; N]> {
        let mut values = [0; N];
        for (value, reg) in values.iter_mut().zip(regs) {
            *value = self.index(reg)?;
        }
        Ok(values)
    }
    fn vector_span(base: i64, count: i64, sized: bool, budget: &Option<&mut Budget>) -> bool {
        budget.is_none()
            || base >= 0
                && count >= 0
                && if sized {
                    base <= work::MAX_INT - count
                } else {
                    count == 0 || base <= work::MAX_INT - (count - 1)
                }
    }
    fn vector_space(&mut self, words: i128, budget: &mut Option<&mut Budget>) -> Exec {
        if budget.is_some() {
            let size = words
                .checked_mul(8)
                .and_then(|v| i64::try_from(v).ok())
                .filter(|v| (0..=work::MAX_INT).contains(v))
                .ok_or(Trap::Refused)?;
            self.bytes(budget, 0, 0, &[Request::Allocate(size)])?;
        }
        Ok(())
    }
    fn vector_arrays(&mut self, count: i64, length: i64, budget: &mut Option<&mut Budget>) -> Exec {
        self.vector_space(i128::from(count) * array_words(length), budget)
    }
    fn vector_product(&mut self, factors: &[i64], divisor: i64) -> Exec {
        self.charge(work::scaled_product(factors, divisor).ok_or(Trap::Refused)?)
    }
    fn memory_number(&mut self, address: i64, budget: &mut Option<&mut Budget>) -> Exec<BigInt> {
        let value = self.memory.get(&address).cloned().unwrap_or_default();
        if let (Some(b), Value::String(raw)) = (budget, &value) {
            let (base, requests) = work::parsing(raw.len() as i64, 1).ok_or(Trap::Exception)?;
            self.effort = b
                .charge(self.effort, self.options.limit, base, &requests)
                .ok_or(Trap::Exception)?;
        }
        Ok(value.number().into_owned())
    }
    fn memory_pair(
        &mut self,
        pair: (i64, i64),
        budget: &mut Option<&mut Budget>,
    ) -> Exec<(BigInt, BigInt)> {
        let left = self.memory_number(pair.0, budget)?;
        let right = self.memory_number(pair.1, budget)?;
        Ok((left, right))
    }
    fn prepare_vectors(
        &mut self,
        kind: IntegerOp,
        count: i64,
        addresses: &impl Fn(i64) -> (i64, i64),
        budget: &mut Option<&mut Budget>,
    ) -> Exec<Operands> {
        if !self.options.integer_work {
            return Ok(Operands::Live);
        }
        let left = self.options.limit - self.effort;
        if !(0..=work::ITEM_CAP).contains(&count) || count > left {
            return Err(Trap::Refused);
        }
        self.vector_arrays(1, count, budget)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(count as usize)
            .map_err(|_| Unavailable("integer vector allocation unavailable".into()))?;
        let mut cost = BigInt::zero();
        for index in 0..count {
            let (a, b) = self.memory_pair(addresses(index), budget)?;
            cost += kind.variable(&a, &b);
            if cost > BigInt::from(left) {
                return Err(Trap::Refused);
            }
            values.push((a, b));
        }
        self.charge_integer(&cost)?;
        Ok(Operands::Fixed(values))
    }
    fn vector_pair(
        &mut self,
        kind: IntegerOp,
        saved: &Operands,
        index: i64,
        addresses: &impl Fn(i64) -> (i64, i64),
        budget: &mut Option<&mut Budget>,
    ) -> Exec<(BigInt, BigInt)> {
        match saved {
            Operands::Fixed(values) => Ok(values[index as usize].clone()),
            Operands::Live => {
                let (a, b) = self.memory_pair(addresses(index), budget)?;
                if budget.is_some() {
                    self.charge_integer(&kind.variable(&a, &b))?;
                }
                Ok((a, b))
            }
        }
    }
    fn read_q16(&self, base: i64, count: i64) -> Exec<Vec<BigInt>> {
        if !qspan(base, count) {
            return Err(Trap::Refused);
        }
        (0..count)
            .map(|index| match self.memory.get(&(base + index)) {
                None => Ok(BigInt::zero()),
                Some(value) if value.numeric() && q16::in_range(&value.number()) => {
                    Ok(value.number().into_owned())
                }
                Some(_) => Err(Trap::Refused),
            })
            .collect()
    }
    fn write_q16(&mut self, base: i64, values: Vec<BigInt>) {
        for (index, value) in values.into_iter().enumerate() {
            self.memory_set(base + index as i64, Value::int(value));
        }
    }
    // Positional operand names match the native instruction layout.
    #[allow(clippy::many_single_char_names)]
    fn integer_matrix(
        &mut self,
        dest: i64,
        left: i64,
        right: i64,
        m: i64,
        k: i64,
        n: i64,
        budget: &mut Option<&mut Budget>,
    ) -> Exec {
        if [m, k, n].iter().any(|v| !(1..=32_768).contains(v))
            || !Self::vector_span(dest, m * n, true, budget)
            || !Self::vector_span(left, m * k, false, budget)
            || !Self::vector_span(right, k * n, false, budget)
            || !Self::vector_span(0, m * n * k, false, budget)
        {
            return Err(Trap::Refused);
        }
        self.vector_product(&[m, n, k], 1024)?;
        let row_size = n * k;
        let addresses = |index| {
            let row = index / row_size;
            let offset = index % row_size;
            (
                data::add(left, row * k + offset % k),
                data::add(right, offset % k * n + offset / k),
            )
        };
        let saved = self.prepare_vectors(IntegerOp::Mul, m * row_size, &addresses, budget)?;
        for row in 0..m {
            for column in 0..n {
                let mut acc = BigInt::zero();
                for inner in 0..k {
                    let index = row * row_size + column * k + inner;
                    let (a, b) =
                        self.vector_pair(IntegerOp::Mul, &saved, index, &addresses, budget)?;
                    acc += a * b;
                }
                self.memory_set(data::add(dest, row * n + column), Value::int(acc));
            }
        }
        Ok(())
    }
    fn q16_matrix(
        &mut self,
        dest: i64,
        left: i64,
        right: i64,
        m: i64,
        k: i64,
        n: i64,
        budget: &mut Option<&mut Budget>,
    ) -> Exec {
        if [m, k, n].iter().any(|v| !(1..=32_768).contains(v))
            || !qspan(dest, m * n)
            || !qspan(left, m * k)
            || !qspan(right, k * n)
        {
            return Err(Trap::Refused);
        }
        self.vector_product(&[m, n, k], 1024)?;
        self.vector_space(
            2 * (array_words(m * k) + array_words(k * n)) + array_words(m * n),
            budget,
        )?;
        let left = self.read_q16(left, m * k)?;
        let right = self.read_q16(right, k * n)?;
        let mut result = Vec::with_capacity((m * n) as usize);
        for row in 0..m {
            for column in 0..n {
                let mut acc = BigInt::zero();
                for inner in 0..k {
                    acc +=
                        &left[(row * k + inner) as usize] * &right[(inner * n + column) as usize];
                }
                result.push(q16::round(&acc, 16).ok_or(Trap::Refused)?);
            }
        }
        if !result.iter().all(q16::in_range) {
            return Err(Trap::Refused);
        }
        self.write_q16(dest, result);
        Ok(())
    }
    fn load_work(&self, count: i64, scale: &BigInt, budgeted: bool) -> Exec<BigInt> {
        if !self.options.integer_work && !budgeted {
            return Ok(BigInt::zero());
        }
        if !(0..=work::ITEM_CAP).contains(&count) || count > self.options.limit - self.effort {
            return Err(Trap::Refused);
        }
        Ok(BigInt::from(count) * IntegerOp::Mul.variable(&BigInt::zero(), scale))
    }
    /// Reserve retained bytes while proving the following execution charge fits.
    fn vector_reserve_io(
        &mut self,
        base: i64,
        requests: &[Request],
        budget: &mut Option<&mut Budget>,
    ) -> Exec {
        if let Some(b) = budget {
            b.plan(self.effort, self.options.limit, base, requests)
                .ok_or(Trap::Refused)?;
            self.effort = b
                .charge(self.effort, self.options.limit, 0, requests)
                .ok_or(Trap::Refused)?;
        }
        Ok(())
    }
    // Positional operand names match the native instruction layout.
    #[allow(clippy::many_single_char_names)]
    fn load_int8(&mut self, op: &I, budget: &mut Option<&mut Budget>) -> Exec {
        let (dest, source, offset, count, scale, encoded, fixed) = match op {
            I::LoadInt8BytesToMem(a, b, c, d, e) => (*a, *b, *c, *d, *e, false, false),
            I::LoadInt8B64ToMem(a, b, c, d, e) => (*a, *b, *c, *d, *e, true, false),
            I::LoadInt8Q16(a, b, c, d, e) => (*a, *b, *c, *d, *e, true, true),
            _ => unreachable!("integer byte loaders are dispatched together"),
        };
        let dest = self.index(dest)?;
        let source = self.text(source)?;
        let offset = self.index(offset)?;
        let count = self.index(count)?;
        let scale = self.integer(scale)?;
        if !(1..=1_048_576).contains(&count)
            || fixed && (!qspan(dest, count) || !q16::in_range(&scale))
        {
            return Err(Trap::Refused);
        }
        if budget.is_some()
            && (!Self::vector_span(dest, count, encoded, budget)
                || encoded && (dest > 16_777_216 || count > 16_777_216 - dest || offset < 0))
        {
            return Err(Trap::Refused);
        }
        let budgeted = budget.is_some();
        let range = |size: usize| {
            if fixed || budgeted {
                offset >= 0 && offset <= size as i64 && count <= size as i64 - offset
            } else {
                offset >= 0 && data::add(offset, count) <= size as i64
            }
        };
        if !encoded && !range(source.len()) {
            return Err(Trap::Refused);
        }
        if budget.is_some() {
            let bits = if fixed {
                128
            } else {
                i64::try_from(scale.bits()).map_err(|_| Trap::Refused)? + 8
            };
            let (cost, requests) = if encoded {
                let plan =
                    work::decoding(source.len() as i64, count, bits, false).ok_or(Trap::Refused)?;
                (count + plan.max_bytes / 4, plan.requests)
            } else {
                (
                    count / 2,
                    vec![Request::Allocate(
                        work::cell_bytes(count, bits).ok_or(Trap::Refused)?,
                    )],
                )
            };
            let extra = if fixed {
                BigInt::zero()
            } else {
                self.load_work(count, &scale, true)?
            };
            let cost = num_traits::ToPrimitive::to_i64(&(BigInt::from(cost) + extra))
                .filter(|v| *v <= work::MAX_INT)
                .ok_or(Trap::Refused)?;
            self.vector_reserve_io(cost, &requests, budget)?;
        }
        let decoded = if encoded {
            native_base64::decode(&source).map_err(|_| Trap::Refused)?
        } else {
            source
        };
        if encoded && !range(decoded.len()) {
            return Err(Trap::Refused);
        }
        self.charge(if encoded {
            count + decoded.len() as i64 / 4
        } else {
            count / 2
        })?;
        if !fixed {
            self.charge_integer(&self.load_work(count, &scale, budget.is_some())?)?;
        }
        let mut values = if fixed {
            Some(Vec::with_capacity(count as usize))
        } else {
            None
        };
        for index in 0..count {
            let index_in_source =
                usize::try_from(data::add(offset, index)).map_err(|_| Trap::Exception)?;
            let byte = *decoded.get(index_in_source).ok_or(Trap::Exception)? as i8;
            let value = BigInt::from(byte) * &scale;
            if let Some(values) = &mut values {
                values.push(value);
            } else {
                self.memory
                    .insert(data::add(dest, index), Value::int(value));
            }
        }
        if let Some(values) = values {
            if !values.iter().all(q16::in_range) {
                return Err(Trap::Refused);
            }
            self.write_q16(dest, values);
        }
        Ok(())
    }
    fn q16_attention(&mut self, regs: [u8; 8], budget: &mut Option<&mut Budget>) -> Exec {
        let [q, k, v, dest, tokens, heads, keys, width] = self.vector_indices(regs)?;
        if !(1..=8192).contains(&tokens)
            || !(1..=256).contains(&heads)
            || !(1..=256).contains(&keys)
            || !(1..=1024).contains(&width)
            || heads % keys != 0
        {
            return Err(Trap::Refused);
        }
        let query_size = heads * width;
        let key_size = tokens * keys * width;
        if !qspan(q, query_size)
            || !qspan(k, key_size)
            || !qspan(v, key_size)
            || !qspan(dest, query_size)
        {
            return Err(Trap::Refused);
        }
        self.vector_product(&[heads, tokens, width, 4], 1)?;
        let words = 3 * array_words(query_size)
            + 4 * array_words(key_size)
            + i128::from(heads)
                * (i128::from(tokens) * array_words(width)
                    + 4 * array_words(tokens)
                    + array_words(width)
                    + i128::from(width) * array_words(tokens))
            + 2 * array_words(heads);
        self.vector_space(words, budget)?;
        let result = q16::attention(
            &self.read_q16(q, query_size)?,
            &self.read_q16(k, key_size)?,
            &self.read_q16(v, key_size)?,
            tokens as usize,
            heads as usize,
            keys as usize,
            width as usize,
        )
        .ok_or(Trap::Refused)?;
        self.write_q16(dest, result);
        Ok(())
    }
    // Positional operand names match the native instruction layout.
    #[allow(clippy::many_single_char_names)]
    pub(super) fn execute_vector(&mut self, op: &I, budget: &mut Option<&mut Budget>) -> Exec {
        match op {
            I::Matmul(dest, left, right, m, k, n) | I::MatmulQ16(dest, left, right, m, k, n) => {
                let [dest, left, right, m, k, n] =
                    self.vector_indices([*dest, *left, *right, *m, *k, *n])?;
                if matches!(op, I::Matmul(..)) {
                    self.integer_matrix(dest, left, right, m, k, n, budget)?;
                } else {
                    self.q16_matrix(dest, left, right, m, k, n, budget)?;
                }
            }
            I::LoadInt8BytesToMem(..) | I::LoadInt8B64ToMem(..) | I::LoadInt8Q16(..) => {
                self.load_int8(op, budget)?;
            }
            I::Vecdot(dest, left, right, count) | I::VecdotQ16(dest, left, right, count) => {
                let left = self.index(*left)?;
                let right = self.index(*right)?;
                let count = self.index(*count)?;
                let fixed = matches!(op, I::VecdotQ16(..));
                if !(1..=131_072).contains(&count)
                    || fixed && (!qspan(left, count) || !qspan(right, count))
                    || !Self::vector_span(left, count, false, budget)
                    || !Self::vector_span(right, count, false, budget)
                {
                    return Err(Trap::Refused);
                }
                self.charge(count / 16)?;
                let value = if fixed {
                    self.vector_arrays(5, count, budget)?;
                    let value =
                        q16::dot(&self.read_q16(left, count)?, &self.read_q16(right, count)?);
                    if !q16::in_range(&value) {
                        return Err(Trap::Refused);
                    }
                    value
                } else {
                    let addresses = |index| (data::add(left, index), data::add(right, index));
                    let saved = self.prepare_vectors(IntegerOp::Mul, count, &addresses, budget)?;
                    let mut value = BigInt::zero();
                    for index in 0..count {
                        let (a, b) =
                            self.vector_pair(IntegerOp::Mul, &saved, index, &addresses, budget)?;
                        value += a * b;
                    }
                    value
                };
                self.set(*dest, Value::int(value))?;
            }
            I::ElemwiseMulInplace(dest, source, count)
            | I::ResidualAdd(dest, source, count)
            | I::ElemwiseMulQ16(dest, source, count)
            | I::ResidualAddQ16(dest, source, count) => {
                let dest = self.index(*dest)?;
                let source = self.index(*source)?;
                let count = self.index(*count)?;
                let fixed = matches!(op, I::ElemwiseMulQ16(..) | I::ResidualAddQ16(..));
                let product = matches!(op, I::ElemwiseMulQ16(..) | I::ElemwiseMulInplace(..));
                if !(1..=1_048_576).contains(&count)
                    || fixed && (!qspan(dest, count) || !qspan(source, count))
                    || !Self::vector_span(dest, count, false, budget)
                    || !Self::vector_span(source, count, false, budget)
                {
                    return Err(Trap::Refused);
                }
                self.charge(count / if product { 2 } else { 4 })?;
                if fixed {
                    self.vector_arrays(5, count, budget)?;
                    let values = q16::pairwise(
                        &self.read_q16(dest, count)?,
                        &self.read_q16(source, count)?,
                        product,
                    )
                    .ok_or(Trap::Refused)?;
                    self.write_q16(dest, values);
                } else {
                    let addresses = |index| (data::add(dest, index), data::add(source, index));
                    let kind = if product {
                        IntegerOp::Mul
                    } else {
                        IntegerOp::Add
                    };
                    let saved = self.prepare_vectors(kind, count, &addresses, budget)?;
                    for index in 0..count {
                        let (a, b) = self.vector_pair(kind, &saved, index, &addresses, budget)?;
                        let value = if product { q16::mul(&a, &b) } else { a + b };
                        self.memory
                            .insert(data::add(dest, index), Value::int(value));
                    }
                }
            }
            I::ReluInplace(base, count) | I::ShiftRoundInplace(base, count, _) => {
                let base = self.index(*base)?;
                let count = self.index(*count)?;
                let bits = if let I::ShiftRoundInplace(_, _, bits) = op {
                    Some(self.index(*bits)?)
                } else {
                    None
                };
                if !(1..=1_048_576).contains(&count)
                    || bits.is_some_and(|v| !(1..=62).contains(&v))
                    || !Self::vector_span(base, count, false, budget)
                {
                    return Err(Trap::Refused);
                }
                self.charge(count / 4)?;
                for index in 0..count {
                    let address = data::add(base, index);
                    if let Some(bits) = bits {
                        let value = self.memory_number(address, budget)?;
                        self.memory.insert(
                            address,
                            Value::int(q16::round(&value, bits as u32).ok_or(Trap::Refused)?),
                        );
                    } else if self.memory.contains_key(&address)
                        && self.memory_number(address, budget)?.is_negative()
                    {
                        self.memory.insert(address, Value::int(0));
                    }
                }
            }
            I::ExpQ16(dest, source) => {
                let value = self.integer(*source)?;
                self.charge(8)?;
                self.set(*dest, Value::int(q16::exp(&value)))?;
            }
            I::SoftmaxQ16Inplace(base, count) | I::SiluQ16Inplace(base, count) => {
                let base = self.index(*base)?;
                let count = self.index(*count)?;
                if !qspan(base, count) {
                    return Err(Trap::Refused);
                }
                let softmax = matches!(op, I::SoftmaxQ16Inplace(..));
                self.vector_product(&[count, if softmax { 8 } else { 2 }], 1)?;
                self.vector_arrays(if softmax { 5 } else { 4 }, count, budget)?;
                let values = self.read_q16(base, count)?;
                let result = if softmax {
                    q16::softmax(&values)
                } else {
                    values.iter().map(q16::silu).collect()
                }
                .ok_or(Trap::Refused)?;
                self.write_q16(base, result);
            }
            I::LayernormQ16Inplace(base, count, gamma, beta) => {
                let base = self.index(*base)?;
                let count = self.index(*count)?;
                let gamma = self.index(*gamma)?;
                let beta = self.index(*beta)?;
                if !qspan(base, count) || !qspan(gamma, count) || !qspan(beta, count) {
                    return Err(Trap::Refused);
                }
                self.vector_product(&[count, 4], 1)?;
                self.vector_arrays(7, count, budget)?;
                let result = q16::layer(
                    &self.read_q16(base, count)?,
                    &self.read_q16(gamma, count)?,
                    &self.read_q16(beta, count)?,
                    self.options.math,
                )
                .ok_or(Trap::Refused)?;
                self.write_q16(base, result);
            }
            I::RmsnormQ16Inplace(base, count, gamma) => {
                let base = self.index(*base)?;
                let count = self.index(*count)?;
                let gamma = self.index(*gamma)?;
                if !qspan(base, count) || !qspan(gamma, count) {
                    return Err(Trap::Refused);
                }
                self.vector_product(&[count, 3], 1)?;
                self.vector_arrays(5, count, budget)?;
                let result = q16::rms(
                    &self.read_q16(base, count)?,
                    &self.read_q16(gamma, count)?,
                    self.options.math,
                )
                .ok_or(Trap::Refused)?;
                self.write_q16(base, result);
            }
            I::RopeApplyQ16(base, count, position, scale) => {
                let base = self.index(*base)?;
                let count = self.index(*count)?;
                let position = self.index(*position)?;
                if position < 0 || count % 2 != 0 || !qspan(base, count) {
                    return Err(Trap::Refused);
                }
                let scale = self.integer(*scale)?;
                self.vector_product(&[count, 4], 1)?;
                self.vector_space(3 * array_words(count) + array_words(count / 2), budget)?;
                let result = q16::rope(&self.read_q16(base, count)?, &scale, position)
                    .ok_or(Trap::Refused)?;
                self.write_q16(base, result);
            }
            I::AppendVecQ16(dest, position, source, count) => {
                let dest = self.index(*dest)?;
                let position = self.index(*position)?;
                let source = self.index(*source)?;
                let count = self.index(*count)?;
                if !(0..=16_777_216).contains(&position)
                    || !qspan(source, count)
                    || position > work::MAX_INT / count
                {
                    return Err(Trap::Refused);
                }
                let shift = position * count;
                if budget.is_some()
                    && (dest > work::MAX_INT - shift
                        || !Self::vector_span(data::add(dest, shift), count, false, budget))
                {
                    return Err(Trap::Refused);
                }
                let target = data::add(dest, shift);
                if target < dest || !qspan(target, count) {
                    return Err(Trap::Refused);
                }
                self.charge(count)?;
                self.vector_arrays(2, count, budget)?;
                let values = self.read_q16(source, count)?;
                self.write_q16(target, values);
            }
            I::ArgmaxQ16(dest, base, count) => {
                let base = self.index(*base)?;
                let count = self.index(*count)?;
                if !qspan(base, count) {
                    return Err(Trap::Refused);
                }
                self.charge(count / 2)?;
                self.vector_arrays(2, count, budget)?;
                let values = self.read_q16(base, count)?;
                let mut best = 0;
                for index in 1..values.len() {
                    if values[index] > values[best] {
                        best = index;
                    }
                }
                self.set(*dest, Value::int(best))?;
            }
            I::AttentionKvQ16(a, b, c, d, e, f, g, h) => {
                self.q16_attention([*a, *b, *c, *d, *e, *f, *g, *h], budget)?;
            }
            _ => unreachable!("integer and Q16 vectors are dispatched together"),
        }
        Ok(())
    }
}
