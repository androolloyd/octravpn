// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native fixed-point type-flow analysis. Worklist order is significant because
//! the first reachable typing failure is part of admission's diagnostic result.
use super::{Facts, Kind};
use crate::octb::{Instruction as I, Value};
use num_traits::Zero;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
type Result<T> = std::result::Result<T, String>;
#[derive(Clone, Debug, PartialEq, Eq)]
enum Constant {
    Text(Arc<[u8]>),
    Zero,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct State {
    regs: [Option<Kind>; 64],
    memory: BTreeMap<i64, Kind>,
    constants: [Option<Constant>; 64],
}
fn unsupported(pc: usize) -> String {
    format!("instruction at pc {pc} is outside the typed Program profile")
}
fn invalid_target(pc: usize, target: i64) -> String {
    format!("invalid target {target} at pc {pc}")
}
impl State {
    fn new(memory: &[(i64, Kind)]) -> Self {
        Self {
            regs: [None; 64],
            memory: memory.iter().copied().collect(),
            constants: std::array::from_fn(|_| None),
        }
    }
    fn read(&self, pc: usize, reg: u8) -> Result<Kind> {
        self.regs
            .get(reg as usize)
            .ok_or_else(|| format!("invalid register r{reg} at pc {pc}"))?
            .ok_or_else(|| format!("uninitialized register r{reg} at pc {pc}"))
    }
    fn expect(
        &self,
        pc: usize,
        reg: u8,
        predicate: impl FnOnce(Kind) -> bool,
        name: &str,
    ) -> Result<Kind> {
        let kind = self.read(pc, reg)?;
        if predicate(kind) {
            Ok(kind)
        } else {
            Err(format!(
                "expected {name} in r{reg} at pc {pc}, got {}",
                kind.name()
            ))
        }
    }
    fn number(&self, pc: usize, reg: u8) -> Result<Kind> {
        self.expect(pc, reg, Kind::numeric, "number")
    }
    fn text(&self, pc: usize, reg: u8) -> Result<Kind> {
        self.expect(pc, reg, Kind::text, "text")
    }
    fn address(&self, pc: usize, reg: u8) -> Result<Kind> {
        self.expect(pc, reg, Kind::address, "address")
    }
    fn kind(&self, pc: usize, reg: u8, kind: Kind) -> Result<Kind> {
        self.expect(pc, reg, |v| v == kind, kind.name())
    }
    fn numbers(&self, pc: usize, registers: &[u8]) -> Result<()> {
        for reg in registers {
            self.number(pc, *reg)?;
        }
        Ok(())
    }
    fn span(&self, pc: usize, base: u8, count: u8) -> Result<()> {
        if count > 64 || base > 64 - count {
            return Err(format!("invalid register r{base} at pc {pc}"));
        }
        for index in 0..count {
            self.read(pc, base + index)?;
        }
        Ok(())
    }
    fn write(&mut self, pc: usize, reg: u8, kind: Kind) -> Result<()> {
        let slot = self
            .regs
            .get_mut(reg as usize)
            .ok_or_else(|| format!("invalid register r{reg} at pc {pc}"))?;
        *slot = Some(kind);
        self.constants[reg as usize] = None;
        Ok(())
    }
    fn seed(mut self, facts: &Facts, target: usize) -> Self {
        if let Some(entry) = facts.entries.iter().find(|e| e.target == target as i64) {
            self.regs = [None; 64];
            self.constants = std::array::from_fn(|_| None);
            self.memory.extend(entry.memory.iter().copied());
        }
        self
    }
    fn join(&self, other: &Self) -> Self {
        let join = |left: Option<Kind>, right: Option<Kind>| match (left, right) {
            (Some(a), Some(b)) if a == b => Some(a),
            (Some(a), Some(b)) if a.numeric() && b.numeric() => Some(Kind::Int),
            _ => None,
        };
        let regs = std::array::from_fn(|i| join(self.regs[i], other.regs[i]));
        let constants = std::array::from_fn(|i| {
            self.constants[i]
                .clone()
                .filter(|v| other.constants[i].as_ref() == Some(v))
        });
        let memory = self
            .memory
            .keys()
            .chain(other.memory.keys())
            .map(|key| {
                (
                    *key,
                    join(
                        self.memory.get(key).copied(),
                        other.memory.get(key).copied(),
                    )
                    .unwrap_or(Kind::Unknown),
                )
            })
            .collect();
        Self {
            regs,
            memory,
            constants,
        }
    }
}
// Positional register names follow the native instruction operands.
#[allow(clippy::many_single_char_names)]
fn step(facts: &Facts, pc: usize, mut env: State, op: &I) -> Result<State> {
    use Kind as K;
    match op {
        I::Ldi(dest, value) => {
            let (kind, constant) = match value.as_ref() {
                Value::Int(v) => (K::Int, v.is_zero().then_some(Constant::Zero)),
                Value::Bool(_) => (K::Bool, None),
                Value::Str(v) => (K::String, Some(Constant::Text(v.clone()))),
                Value::Bytes(_) => (K::Bytes, None),
                Value::Addr(_) => (K::Addr, None),
            };
            env.write(pc, *dest, kind)?;
            env.constants[*dest as usize] = constant;
        }
        I::Mov(dest, source) => {
            let kind = env.read(pc, *source)?;
            let constant = env.constants[*source as usize].clone();
            env.write(pc, *dest, kind)?;
            env.constants[*dest as usize] = constant;
        }
        I::Add(dest, left, right) => {
            let a = env.read(pc, *left)?;
            let b = env.read(pc, *right)?;
            let valid = a.numeric() && b.numeric()
                || a.numeric()
                    && env.constants[*left as usize] == Some(Constant::Zero)
                    && b == K::String
                || a == K::String
                    && b.numeric()
                    && env.constants[*right as usize] == Some(Constant::Zero);
            if !valid {
                return Err(format!(
                    "expected {} in r{right} at pc {pc}, got {}",
                    a.name(),
                    b.name()
                ));
            }
            env.write(pc, *dest, K::Int)?;
        }
        I::Sub(d, a, b)
        | I::Mul(d, a, b)
        | I::Div(d, a, b)
        | I::Mod(d, a, b)
        | I::Bitand(d, a, b)
        | I::Bitor(d, a, b)
        | I::Bitxor(d, a, b)
        | I::Bitshl(d, a, b)
        | I::Bitshr(d, a, b) => {
            env.numbers(pc, &[*a, *b])?;
            env.write(pc, *d, K::Int)?;
        }
        I::Neg(d, s) | I::Abs(d, s) | I::ExpQ16(d, s) => {
            env.number(pc, *s)?;
            env.write(pc, *d, K::Int)?;
        }
        I::Eq(d, a, b) | I::Neq(d, a, b) => {
            let left = env.read(pc, *a)?;
            let right = env.read(pc, *b)?;
            if !left.same(right) {
                return Err(format!(
                    "expected {} in r{b} at pc {pc}, got {}",
                    left.name(),
                    right.name()
                ));
            }
            env.write(pc, *d, K::Bool)?;
        }
        I::Lt(d, a, b) | I::Gt(d, a, b) => {
            env.numbers(pc, &[*a, *b])?;
            env.write(pc, *d, K::Bool)?;
        }
        I::Concat(d, a, b) => {
            env.expect(pc, *a, Kind::scalar, "scalar value")?;
            env.expect(pc, *b, Kind::scalar, "scalar value")?;
            env.write(pc, *d, K::String)?;
        }
        I::Strlen(d, s) => {
            env.text(pc, *s)?;
            env.write(pc, *d, K::Int)?;
        }
        I::SoftmaxQ16Inplace(a, c) | I::SiluQ16Inplace(a, c) => env.numbers(pc, &[*a, *c])?,
        I::LayernormQ16Inplace(a, c, g, b) | I::RopeApplyQ16(a, c, g, b) => {
            env.numbers(pc, &[*a, *c, *g, *b])?;
        }
        I::RmsnormQ16Inplace(a, c, g) => env.numbers(pc, &[*a, *c, *g])?,
        I::AttentionKvQ16(q, k, v, c, t, qh, kh, hd) => {
            env.numbers(pc, &[*q, *k, *v, *c, *t, *qh, *kh, *hd])?;
        }
        I::LoadInt8Q16(d, s, o, c, scale) => {
            env.expect(pc, *s, Kind::text, "bytes")?;
            env.numbers(pc, &[*d, *o, *c, *scale])?;
        }
        I::AppendVecQ16(d, p, s, c) => env.numbers(pc, &[*d, *p, *s, *c])?,
        I::ArgmaxQ16(d, a, c) => {
            env.numbers(pc, &[*a, *c])?;
            env.write(pc, *d, K::Int)?;
        }
        I::VecdotQ16(d, a, b, c) => {
            env.numbers(pc, &[*a, *b, *c])?;
            env.write(pc, *d, K::Int)?;
        }
        I::ElemwiseMulQ16(d, s, c) | I::ResidualAddQ16(d, s, c) => {
            env.numbers(pc, &[*d, *s, *c])?;
        }
        I::Caller(d) | I::Origin(d) | I::SelfAddr(d) => env.write(pc, *d, K::Addr)?,
        I::Epoch(d) | I::EpochTime(d) | I::Value(d) | I::Effort(d) => env.write(pc, *d, K::Int)?,
        I::Balance(d, s) => {
            env.address(pc, *s)?;
            env.write(pc, *d, K::Int)?;
        }
        I::Sload(d, key) => env.write(
            pc,
            *d,
            facts
                .storage
                .iter()
                .find(|(k, _)| k == key.as_ref())
                .map_or(K::String, |(_, k)| *k),
        )?,
        I::Treehash(d) | I::Nodeid(d) | I::Txhash(d) | I::FhePedersenIdentity(d) => {
            env.write(pc, *d, K::String)?;
        }
        I::Sloadk(d, key) => {
            env.address(pc, *key)?;
            env.write(pc, *d, K::String)?;
        }
        I::Sstore(key, source) => {
            if let Some((_, expected)) = facts.storage.iter().find(|(k, _)| k == key.as_ref()) {
                let actual = env.read(pc, *source)?;
                if !expected.same(actual) {
                    return Err(format!(
                        "expected {} in r{source} at pc {pc}, got {}",
                        expected.name(),
                        actual.name()
                    ));
                }
            } else {
                env.expect(pc, *source, Kind::scalar, "scalar value")?;
            }
        }
        I::Sstorek(key, source) => {
            env.address(pc, *key)?;
            env.expect(pc, *source, Kind::scalar, "scalar value")?;
        }
        I::Sdelk(key) => {
            env.address(pc, *key)?;
        }
        I::Mload(dest, index) => {
            let kind = env.memory.get(&i64::from(*index)).copied().unwrap_or(
                if [999, 1000].contains(index) {
                    K::String
                } else {
                    K::Unknown
                },
            );
            env.write(pc, *dest, kind)?;
        }
        I::Mstore(index, source) => {
            let kind = env.read(pc, *source)?;
            env.memory.insert(i64::from(*index), kind);
        }
        I::Mloadr(dest, index) => {
            env.number(pc, *index)?;
            env.write(pc, *dest, K::Unknown)?;
        }
        I::Mstorer(index, source) => {
            env.number(pc, *index)?;
            env.read(pc, *source)?;
            env.memory.clear();
        }
        I::Xcall(dest, target, method, base, count) => {
            env.address(pc, *target)?;
            env.expect(pc, *method, |k| k == K::String, "method")?;
            env.span(pc, *base, *count)?;
            let kind = match facts.xcalls.iter().find(|c| c.pc == pc as i64) {
                None => K::Unknown,
                Some(abi) => {
                    let failure = |s| format!("external call ABI mismatch at pc {pc}: {s}");
                    match &env.constants[*method as usize] {
                        Some(Constant::Text(value)) if value.as_ref() == abi.method => (),
                        Some(_) => return Err(failure("method mismatch")),
                        None => return Err(failure("method is not constant")),
                    }
                    if abi.inputs.len() != *count as usize {
                        return Err(failure("argument count mismatch"));
                    }
                    for (i, expected) in abi.inputs.iter().enumerate() {
                        if !env.read(pc, *base + i as u8)?.same(*expected) {
                            return Err(failure("argument type mismatch"));
                        }
                    }
                    abi.output
                }
            };
            env.write(pc, *dest, kind)?;
        }
        I::CallInt(dest, _) => {
            env.write(
                pc,
                *dest,
                facts
                    .calls
                    .iter()
                    .find(|c| c.pc == pc as i64)
                    .map_or(K::Unknown, |c| c.kind),
            )?;
            env.memory.clear();
        }
        I::Spawn(dest, source) => {
            env.text(pc, *source)?;
            env.write(pc, *dest, K::Addr)?;
        }
        I::Spawn2(dest, source, base, count) => {
            env.text(pc, *source)?;
            env.span(pc, *base, *count)?;
            env.write(pc, *dest, K::Addr)?;
        }
        I::Transfer(dest, target, value) => {
            env.address(pc, *target)?;
            env.number(pc, *value)?;
            env.write(pc, *dest, K::Bool)?;
        }
        I::Emit(_, registers) => {
            for reg in registers {
                env.read(pc, *reg)?;
            }
        }
        I::Checkpoint()
        | I::Rollback()
        | I::Commit()
        | I::Jdest(_)
        | I::Jmp(_)
        | I::Stop()
        | I::Revert()
        | I::Nop() => (),
        I::Jif(source, _) | I::Assert(source) => {
            env.kind(pc, *source, K::Bool)?;
        }
        I::Isaddr(dest, source) | I::Ishex(dest, source) => {
            env.address(pc, *source)?;
            env.write(pc, *dest, K::Bool)?;
        }
        I::FheLoadPk(dest, source) => {
            env.address(pc, *source)?;
            env.write(pc, *dest, K::PubKey)?;
        }
        I::FheAdd(d, p, a, b) | I::FheSub(d, p, a, b) | I::FheMul(d, p, a, b) => {
            env.kind(pc, *p, K::PubKey)?;
            env.kind(pc, *a, K::Cipher)?;
            env.kind(pc, *b, K::Cipher)?;
            env.write(pc, *d, K::Cipher)?;
        }
        I::FheScale(d, p, c, s)
        | I::FheDivConst(d, p, c, s)
        | I::FheAddConst(d, p, c, s)
        | I::FheSubConst(d, p, c, s) => {
            env.kind(pc, *p, K::PubKey)?;
            env.kind(pc, *c, K::Cipher)?;
            env.number(pc, *s)?;
            env.write(pc, *d, K::Cipher)?;
        }
        I::FheVerifyZero(d, p, c, proof) | I::FheVerifyRange(d, p, c, proof) => {
            env.kind(pc, *p, K::PubKey)?;
            env.kind(pc, *c, K::Cipher)?;
            env.text(pc, *proof)?;
            env.write(pc, *d, K::Bool)?;
        }
        I::FheVerifyBound(d, p, c, proof, commit) => {
            env.kind(pc, *p, K::PubKey)?;
            env.kind(pc, *c, K::Cipher)?;
            env.text(pc, *proof)?;
            env.text(pc, *commit)?;
            env.write(pc, *d, K::Bool)?;
        }
        I::Groth16VerifyBn254(d, k, p, i) => {
            env.text(pc, *k)?;
            env.text(pc, *p)?;
            env.text(pc, *i)?;
            env.write(pc, *d, K::Bool)?;
        }
        I::FheCommit(d, p, c) => {
            env.kind(pc, *p, K::PubKey)?;
            env.kind(pc, *c, K::Cipher)?;
            env.write(pc, *d, K::String)?;
        }
        I::FhePedersen(d, a, b) => {
            env.number(pc, *a)?;
            env.text(pc, *b)?;
            env.write(pc, *d, K::String)?;
        }
        I::FhePedersenAdd(d, a, b) | I::FhePedersenSub(d, a, b) => {
            env.text(pc, *a)?;
            env.text(pc, *b)?;
            env.write(pc, *d, K::String)?;
        }
        I::FheSer(d, c) => {
            env.kind(pc, *c, K::Cipher)?;
            env.write(pc, *d, K::String)?;
        }
        I::FheDeser(d, b) => {
            env.text(pc, *b)?;
            env.write(pc, *d, K::Cipher)?;
        }
        I::FheSerPk(d, p) => {
            env.kind(pc, *p, K::PubKey)?;
            env.write(pc, *d, K::String)?;
        }
        I::FheDeserPk(d, b) => {
            env.text(pc, *b)?;
            env.write(pc, *d, K::PubKey)?;
        }
        I::AssertAddr(s) => {
            env.address(pc, *s)?;
        }
        I::Substr(d, s, a, b) => {
            env.text(pc, *s)?;
            env.numbers(pc, &[*a, *b])?;
            env.write(pc, *d, K::String)?;
        }
        I::Indexof(d, s, n) => {
            env.text(pc, *s)?;
            env.text(pc, *n)?;
            env.write(pc, *d, K::Int)?;
        }
        I::Sha256(d, s) | I::Keccak256(d, s) => {
            env.text(pc, *s)?;
            env.write(pc, *d, K::String)?;
        }
        _ => return Err(unsupported(pc)),
    }
    Ok(env)
}
fn unique<T: Ord>(values: impl IntoIterator<Item = T>) -> bool {
    let mut seen = BTreeSet::new();
    values.into_iter().all(|v| seen.insert(v))
}
fn valid(facts: &Facts, code: &[I], labels: &BTreeMap<u32, usize>) -> bool {
    let memory = |pairs: &[(i64, Kind)]| {
        pairs
            .iter()
            .all(|(slot, _)| (0..=16_777_216).contains(slot))
            && unique(pairs.iter().map(|(slot, _)| *slot))
    };
    let effect = |name: &Vec<u8>| {
        matches!(
            name.as_slice(),
            b"memory_read"
                | b"memory_write"
                | b"storage_read"
                | b"storage_write"
                | b"call"
                | b"deploy"
                | b"transfer"
                | b"emit"
                | b"fhe"
                | b"journal"
        )
    };
    let targets = facts
        .entries
        .iter()
        .map(|e| e.target)
        .collect::<BTreeSet<_>>();
    if code.len() > 65_536
        || facts.entries.len() > 256
        || facts.calls.len() > 4096
        || facts.xcalls.len() > 1024
        || facts.root.len() > 4096
        || facts.storage.len() > 4096
        || !memory(&facts.root)
        || !unique(facts.storage.iter().map(|(k, _)| k))
        || !unique(facts.entries.iter().map(|e| e.target))
        || !unique(facts.calls.iter().map(|c| c.pc))
        || !unique(facts.xcalls.iter().map(|c| c.pc))
    {
        return false;
    }
    if facts
        .storage
        .iter()
        .any(|(k, kind)| k.is_empty() || !kind.scalar())
    {
        return false;
    }
    for e in &facts.entries {
        if e.target < 0
            || e.target as usize >= code.len()
            || e.memory.len() > 4096
            || !memory(&e.memory)
            || !e.effects.iter().all(effect)
            || !unique(e.effects.iter())
            || !matches!(code[e.target as usize], I::Jdest(_))
        {
            return false;
        }
    }
    for c in &facts.calls {
        if c.owner < 0
            || c.owner as usize >= code.len()
            || c.pc < c.owner
            || c.pc as usize >= code.len()
            || c.target < 0
            || c.target as usize >= code.len()
            || !targets.contains(&c.owner)
            || !targets.contains(&c.target)
        {
            return false;
        }
        match code[c.pc as usize] {
            I::CallInt(_, label) if labels.get(&label) == Some(&(c.target as usize)) => (),
            _ => return false,
        }
    }
    let expected = code
        .iter()
        .enumerate()
        .filter_map(|(pc, op)| matches!(op, I::CallInt(..)).then_some(pc as i64))
        .collect::<BTreeSet<_>>();
    if expected != facts.calls.iter().map(|c| c.pc).collect() {
        return false;
    }
    for c in &facts.xcalls {
        if c.pc < 0
            || c.pc as usize >= code.len()
            || c.method.is_empty()
            || c.inputs.contains(&Kind::Unknown)
            || c.output == Kind::Unknown
            || !unique(c.capabilities.iter().map(|c| c.name()))
            || !matches!(code[c.pc as usize], I::Xcall(..))
        {
            return false;
        }
    }
    // Iterative DFS bounds hostile call graphs without using the Rust stack.
    let mut edges = BTreeMap::<i64, Vec<i64>>::new();
    for c in &facts.calls {
        edges.entry(c.owner).or_default().push(c.target);
    }
    let mut complete = BTreeMap::<i64, usize>::new();
    for root in edges.keys() {
        if complete.contains_key(root) {
            continue;
        }
        let mut active = BTreeSet::new();
        let mut pending = vec![(*root, false)];
        while let Some((node, exit)) = pending.pop() {
            if complete.contains_key(&node) {
                continue;
            }
            if exit {
                let depth = edges
                    .get(&node)
                    .into_iter()
                    .flatten()
                    .filter_map(|c| complete.get(c))
                    .max()
                    .copied()
                    .unwrap_or(0)
                    + 1;
                if depth > 64 {
                    return false;
                }
                complete.insert(node, depth);
                active.remove(&node);
            } else {
                if !active.insert(node) {
                    return false;
                }
                pending.push((node, true));
                if let Some(children) = edges.get(&node) {
                    for child in children.iter().rev() {
                        if !complete.contains_key(child) {
                            pending.push((*child, false));
                        }
                    }
                }
            }
        }
    }
    true
}
pub(super) fn check(code: &[I], facts: &Facts, max_steps: usize) -> Result<()> {
    if code.is_empty() {
        return Err(unsupported(0));
    }
    if max_steps == 0 {
        return Err(format!("Program type flow exceeds {max_steps} steps"));
    }
    let labels = code
        .iter()
        .enumerate()
        .filter_map(|(pc, op)| {
            if let I::Jdest(label) = op {
                Some((*label, pc))
            } else {
                None
            }
        })
        .collect::<BTreeMap<_, _>>();
    if !valid(facts, code, &labels) {
        return Err(unsupported(0));
    }
    let entry = code
        .iter()
        .position(|op| matches!(op, I::Jdest(100)))
        .unwrap_or(0);
    let mut states = vec![None; code.len()];
    states[entry] = Some(State::new(&facts.root));
    let mut pending = vec![entry];
    let mut steps = 0;
    while let Some(pc) = pending.pop() {
        if steps >= max_steps {
            return Err(format!("Program type flow exceeds {max_steps} steps"));
        }
        steps += 1;
        let Some(env) = states[pc].clone() else {
            continue;
        };
        let next = step(facts, pc, env, &code[pc])?;
        let label = |label: &u32| labels.get(label).copied().unwrap_or(*label as usize);
        let mut targets = if pc + 1 < code.len() {
            vec![pc + 1]
        } else {
            vec![]
        };
        match &code[pc] {
            I::Stop() | I::Revert() => targets.clear(),
            I::Jmp(target) => targets = vec![label(target)],
            I::Jif(_, target) | I::CallInt(_, target) => targets.insert(0, label(target)),
            _ => (),
        }
        for target in targets {
            if target >= code.len() {
                return Err(invalid_target(pc, target as i64));
            }
            let next = next.clone().seed(facts, target);
            let joined = states[target]
                .as_ref()
                .map_or_else(|| next.clone(), |old| old.join(&next));
            if states[target].as_ref() != Some(&joined) {
                states[target] = Some(joined);
                pending.push(target);
            }
        }
    }
    Ok(())
}
