// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::super::{
    core::{
        flow::{Flow, FlowId, Flows, Location, Origin, Site},
        Atom,
    },
    effects::{Charge, Entry, HostType, Rollback, Scalar},
};
use super::{bin, program_codec, Arc, Bits, Block, CodeId, Codes, Layout, Sealed, Types};
use crate::octb::{self as wire, Instruction as I, Value};
use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero};
use std::collections::BTreeMap;
fn tuple(codes: &mut Codes, tag: u32, fields: &[CodeId]) -> CodeId {
    let fields = codes.list(fields);
    codes.tag(tag, fields)
}
fn host_code(codes: &mut Codes, host: HostType) -> CodeId {
    codes.tag(
        match host {
            HostType::Int => 0,
            HostType::Bool => 1,
            HostType::Bytes32 => 2,
        },
        codes.nil(),
    )
}
fn host_get(codes: &Codes, id: CodeId) -> Option<HostType> {
    let bin::Code::Tag(tag, body) = codes.get(id) else {
        return None;
    };
    if !matches!(codes.get(*body), bin::Code::Nil) {
        return None;
    }
    Some(match tag.to_u32()? {
        0 => HostType::Int,
        1 => HostType::Bool,
        2 => HostType::Bytes32,
        _ => return None,
    })
}
fn entry_code(codes: &mut Codes, atom: Atom, entry: &Entry) -> CodeId {
    let atom = codes.atom_code(atom);
    match entry {
        Entry::State(name, typ) => {
            let name = codes.bytes_code(name);
            let typ = host_code(codes, *typ);
            tuple(codes, 0, &[atom, name, typ])
        }
        Entry::Event(name, types) => {
            let name = codes.bytes_code(name);
            let types = types
                .iter()
                .map(|typ| host_code(codes, *typ))
                .collect::<Vec<_>>();
            let types = codes.list(&types);
            tuple(codes, 1, &[atom, name, types])
        }
        Entry::Fault(name, code, message) => {
            let name = codes.bytes_code(name);
            let code = codes.integer(*code);
            let message = codes.bytes_code(message);
            tuple(codes, 2, &[atom, name, code, message])
        }
    }
}
fn entry_get(codes: &Codes, id: CodeId) -> Option<(Atom, Entry)> {
    let bin::Code::Tag(tag, body) = codes.get(id) else {
        return None;
    };
    Some(match tag.to_u32()? {
        0 => {
            let [atom, name, typ] = codes.fields::<3>(*body)?;
            (
                codes.atom_get(atom)?,
                Entry::State(codes.bytes_get(name)?, host_get(codes, typ)?),
            )
        }
        1 => {
            let [atom, name, types] = codes.fields::<3>(*body)?;
            let atom = codes.atom_get(atom)?;
            let name = codes.bytes_get(name)?;
            let types = codes
                .list_get(types)?
                .into_iter()
                .map(|typ| host_get(codes, typ))
                .collect::<Option<Vec<_>>>()?;
            (atom, Entry::Event(name, types))
        }
        2 => {
            let [atom, name, code, message] = codes.fields::<4>(*body)?;
            let atom = codes.atom_get(atom)?;
            let name = codes.bytes_get(name)?;
            let bin::Code::Int(value) = codes.get(code) else {
                return None;
            };
            let code = value.to_i64()?;
            // The adopted native compiler uses a signed 63-bit OCaml int here.
            if !(-(1_i64 << 62)..=(1_i64 << 62) - 1).contains(&code) {
                return None;
            }
            (atom, Entry::Fault(name, code, codes.bytes_get(message)?))
        }
        _ => return None,
    })
}
fn site_code(codes: &mut Codes, types: &Types, site: Site) -> CodeId {
    let atom = codes.atom_code(site.atom());
    let typ = codes.type_code(types, site.payload());
    let origin = match site.origin() {
        Origin::Direct => codes.tag(0, codes.nil()),
        Origin::Held(kind) => {
            let kind = codes.num(kind.get());
            codes.tag(1, kind)
        }
    };
    tuple(codes, 0, &[atom, typ, origin])
}
fn flow_code(codes: &mut Codes, types: &Types, flows: &Flows, root: FlowId) -> CodeId {
    let mut memo = BTreeMap::new();
    let mut pending = vec![(root, false)];
    while let Some((id, finish)) = pending.pop() {
        if memo.contains_key(&id) {
            continue;
        }
        if !finish {
            pending.push((id, true));
            match flows.get(id) {
                Flow::Seq(left, right) | Flow::Fork(left, right) => {
                    pending.push((*right, false));
                    pending.push((*left, false));
                }
                Flow::Loop(_, body) => pending.push((*body, false)),
                _ => (),
            }
            continue;
        }
        let code = match flows.get(id) {
            Flow::Pure => codes.tag(0, codes.nil()),
            Flow::Action(site) => {
                let site = site_code(codes, types, *site);
                codes.tag(1, site)
            }
            Flow::Seq(left, right) | Flow::Fork(left, right) => tuple(
                codes,
                if matches!(flows.get(id), Flow::Seq(..)) {
                    2
                } else {
                    3
                },
                &[memo[left], memo[right]],
            ),
            Flow::Loop(count, body) => {
                let count = codes.num(count.get());
                tuple(codes, 4, &[count, memo[body]])
            }
        };
        memo.insert(id, code);
    }
    memo[&root]
}
fn location_code(codes: &mut Codes, types: &Types, location: &Location) -> CodeId {
    let index = codes.num(location.index());
    let site = site_code(codes, types, location.site());
    let count = codes.integer(location.count().clone());
    tuple(codes, 0, &[index, site, count])
}
fn layout_code(codes: &mut Codes, layout: &Layout) -> Option<CodeId> {
    let regs = |codes: &mut Codes, values: &[u8]| -> Option<CodeId> {
        let values = values
            .iter()
            .map(|reg| (*reg < 64).then(|| codes.num(*reg)))
            .collect::<Option<Vec<_>>>()?;
        Some(codes.list(&values))
    };
    let payload = regs(codes, &layout.payload)?;
    let scratch = regs(codes, &layout.scratch)?;
    Some(tuple(codes, 0, &[payload, scratch]))
}
fn block_code(codes: &mut Codes, types: &Types, block: &Block) -> Option<CodeId> {
    let index = codes.num(block.index());
    let site = site_code(codes, types, block.site());
    let rollback = codes.tag(
        match block.rollback() {
            Rollback::Preserve => 0,
            Rollback::Journal => 1,
            Rollback::Record => 2,
            Rollback::Abort => 3,
        },
        codes.nil(),
    );
    let raw = wire::encode(block.ops(), &wire::Metadata::default(), false).ok()?;
    let ops = codes.bytes_code(&raw);
    let cost = codes.integer(block.cost().clone());
    let charge = codes.tag(
        match block.charge() {
            Charge::Exact => 0,
            Charge::Storage => 1,
        },
        codes.nil(),
    );
    Some(tuple(codes, 0, &[index, site, rollback, ops, cost, charge]))
}
fn cost_code(codes: &mut Codes) -> CodeId {
    let zero = Arc::new(Value::Int(Arc::new(BigInt::from(0))));
    let mut costs = vec![
        64_i64,
        wire::work::Limits::CONSENSUS.value_bytes,
        I::Ldi(0, zero).effort_cost(),
        I::Sload(0, Arc::from(b"x".as_slice())).effort_cost(),
        I::Eq(0, 1, 2).effort_cost(),
        I::Assert(0).effort_cost(),
        I::Sstore(Arc::from(b"x".as_slice()), 0).effort_cost(),
        I::Emit(Arc::from(b"x".as_slice()), vec![]).effort_cost(),
        I::Revert().effort_cost(),
    ];
    for value in [
        Scalar::Int(Arc::new(BigInt::from(0))),
        Scalar::Bool(false),
        Scalar::Bytes32(vec![0; 32].into()),
    ] {
        costs.push((value.text().len() / wire::work::Limits::CONSENSUS.unit_bytes as usize) as i64);
    }
    let values = costs
        .into_iter()
        .map(|value| codes.integer(value))
        .collect::<Vec<_>>();
    tuple(codes, 0, &values)
}
pub(super) fn encode(sealed: &Sealed, layouts: &[Layout], blocks: &[Block]) -> Option<Bits> {
    let mut types = sealed.types().clone();
    let mut codes = Codes::default();
    let program = program_codec::code(&mut codes, &mut types, sealed.terms(), sealed.program())?;
    let entries = sealed
        .registry()
        .entries()
        .iter()
        .map(|(atom, entry)| entry_code(&mut codes, *atom, entry))
        .collect::<Vec<_>>();
    let entries = codes.list(&entries);
    let typ = codes.type_code(&types, sealed.typ());
    let flow = flow_code(
        &mut codes,
        &types,
        sealed.checked().flows(),
        sealed.checked().info().flow(),
    );
    let locations = sealed
        .locations()
        .iter()
        .map(|location| location_code(&mut codes, &types, location))
        .collect::<Vec<_>>();
    let locations = codes.list(&locations);
    let layouts = layouts
        .iter()
        .map(|layout| layout_code(&mut codes, layout))
        .collect::<Option<Vec<_>>>()?;
    let layouts = codes.list(&layouts);
    let blocks = blocks
        .iter()
        .map(|block| block_code(&mut codes, &types, block))
        .collect::<Option<Vec<_>>>()?;
    let blocks = codes.list(&blocks);
    let cost = cost_code(&mut codes);
    let root = tuple(
        &mut codes,
        0,
        &[
            program, entries, typ, flow, locations, layouts, blocks, cost,
        ],
    );
    bin::encode(&codes, root)
}
pub(super) fn root(codes: &Codes, id: CodeId) -> Option<(CodeId, CodeId)> {
    let bin::Code::Tag(tag, body) = codes.get(id) else {
        return None;
    };
    if !tag.is_zero() {
        return None;
    }
    let [program, entries, _, _, _, _, _, _] = codes.fields::<8>(*body)?;
    Some((program, entries))
}
pub(super) fn entries_get(codes: &Codes, id: CodeId) -> Option<Vec<(Atom, Entry)>> {
    codes
        .list_get(id)?
        .into_iter()
        .map(|entry| entry_get(codes, entry))
        .collect()
}
