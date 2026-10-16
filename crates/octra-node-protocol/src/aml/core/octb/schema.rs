// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Canonical C_octb open-data schema. The schema grammar accepts natural result
//! IDs; runtime register bounds and uniqueness are separate image checks.
use super::super::{
    bin::{self, Code, Codes},
    rule::{Field, LOCAL},
    types::{TypeId, Types},
    Natural,
};
use num_traits::Zero;
use std::sync::Arc;
const PREFIX: &[u8] = b"\0OCTRA_AML_OPEN\0";
const MAX_BITS: usize = LOCAL.get(Field::TypeNodes) as usize * 128;
#[derive(Clone, Debug)]
pub struct Schema {
    inputs: Vec<TypeId>,
    output: TypeId,
    results: Vec<u32>,
    raw: Arc<[u8]>,
}
impl Schema {
    pub fn make(types: &Types, inputs: &[TypeId], output: TypeId, results: &[u32]) -> Option<Self> {
        let mut nodes = 0_usize;
        for typ in inputs.iter().copied().chain(std::iter::once(output)) {
            let found = types.nodes(typ)?;
            if found > LOCAL.get(Field::TypeNodes) as usize - nodes {
                return None;
            }
            nodes += found;
        }
        let mut codes = Codes::default();
        let input_codes = inputs
            .iter()
            .map(|typ| codes.type_code(types, *typ))
            .collect::<Vec<_>>();
        let input_code = codes.list(&input_codes);
        let output_code = codes.type_code(types, output);
        let results_code = results
            .iter()
            .map(|reg| Natural::from_u32(*reg).map(|reg| codes.num(reg.get())))
            .collect::<Option<Vec<_>>>()?;
        let result_code = codes.list(&results_code);
        let fields = codes.list(&[input_code, output_code, result_code]);
        let root = codes.tag(0, fields);
        let bits = bin::encode(&codes, root)?;
        if bits.len() > MAX_BITS {
            return None;
        }
        let mut raw = PREFIX.to_vec();
        raw.extend(bits.into_iter().map(|bit| if bit { b'1' } else { b'0' }));
        Some(Self {
            inputs: inputs.to_vec(),
            output,
            results: results.to_vec(),
            raw: raw.into(),
        })
    }
    pub fn read(types: &mut Types, raw: &[u8]) -> Option<Self> {
        if raw.len() <= PREFIX.len() || raw.len() > PREFIX.len() + MAX_BITS {
            return None;
        }
        let body = raw.strip_prefix(PREFIX)?;
        if !body.iter().all(|byte| matches!(byte, b'0' | b'1')) {
            return None;
        }
        let bits = body.iter().map(|byte| *byte == b'1').collect::<Vec<_>>();
        let decoded = bin::decode(&bits)?;
        let Code::Tag(tag, fields) = decoded.codes.get(decoded.root) else {
            return None;
        };
        if !tag.is_zero() {
            return None;
        }
        let fields = decoded.codes.list_get(*fields)?;
        let [inputs, output, results] = fields.as_slice() else {
            return None;
        };
        let inputs = decoded
            .codes
            .list_get(*inputs)?
            .into_iter()
            .map(|typ| decoded.codes.type_get(types, typ))
            .collect::<Option<Vec<_>>>()?;
        let output = decoded.codes.type_get(types, *output)?;
        let results = decoded
            .codes
            .list_get(*results)?
            .into_iter()
            .map(|id| {
                let Code::Num(value) = decoded.codes.get(id) else {
                    return None;
                };
                Some(Natural::new(value)?.get())
            })
            .collect::<Option<Vec<_>>>()?;
        let schema = Self::make(types, &inputs, output, &results)?;
        (schema.raw.as_ref() == raw).then_some(schema)
    }
    pub fn inputs(&self) -> &[TypeId] {
        &self.inputs
    }
    pub fn output(&self) -> TypeId {
        self.output
    }
    pub fn results(&self) -> &[u32] {
        &self.results
    }
    pub fn encode(&self) -> &[u8] {
        &self.raw
    }
}
