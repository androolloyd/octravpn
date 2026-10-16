// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_octb image construction. Source binding, proof generation and verification
//! remain separate; an emitted compiler image is not deployment authority.
use super::super::{
    eval::Values,
    machine::{self, Literal},
    maps::{LiveMap, SourceMap},
    term::Bind,
    types::{TypeId, Types},
    Atom,
};
use super::{decode, encode_open, encode_raw, lower, result_code, Error, Open, Operation};
use crate::octb::Veil;
#[derive(Clone, Debug)]
pub struct Image {
    machine: machine::Image,
    code: Vec<Operation>,
    raw: Vec<u8>,
    results: Vec<u8>,
    source: SourceMap,
    live: LiveMap,
}
impl Image {
    pub fn machine(&self) -> &machine::Image {
        &self.machine
    }
    pub fn inputs(&self) -> &[Bind] {
        self.machine.inputs()
    }
    pub fn code(&self) -> &[Operation] {
        &self.code
    }
    pub fn octb(&self) -> &[u8] {
        &self.raw
    }
    pub fn typ(&self) -> TypeId {
        self.machine.typ()
    }
    pub fn results(&self) -> &[u8] {
        &self.results
    }
    pub fn result(&self) -> Option<&Literal> {
        self.machine.result()
    }
    pub fn source_map(&self) -> &SourceMap {
        &self.source
    }
    pub fn live_map(&self) -> &LiveMap {
        &self.live
    }
}
pub fn finish(
    types: &mut Types,
    values: &mut Values,
    image: machine::Image,
) -> Result<Image, Error> {
    let effects = image.codes().effects(image.code());
    if effects
        .iter()
        .any(|effect| !matches!(effect, Atom::Close(_)))
    {
        return Err(Error::Mach(machine::Error::Effects(effects)));
    }
    let plan = lower(types, values, (&image).into())?;
    let assembly = plan.resolve()?;
    let source = SourceMap::make(&assembly.spans).map_err(Error::Smap)?;
    let live = LiveMap::make(&assembly.live).map_err(Error::Lmap)?;
    let veil = Veil {
        count: image.veils().into(),
        depth: image.veil_depth().get().into(),
    };
    let raw = if image.inputs().is_empty() {
        encode_raw(&assembly.code, Some(image.emission()), Some(veil))?
    } else {
        let raw = encode_open(
            types,
            values,
            Open {
                inputs: image.inputs(),
                regs: &plan.inputs,
                typ: image.typ(),
                results: &plan.results,
                code: &assembly.code,
                emission: image.emission(),
                veil,
            },
        )?;
        let scalar = image
            .inputs()
            .iter()
            .all(|bind| super::encode::scalar_type(types.get(bind.typ)))
            && super::encode::scalar_type(types.get(image.typ()));
        let expected = if scalar {
            result_code(types, image.typ(), &assembly.code).ok_or(Error::OutputCode)?
        } else {
            assembly.code.clone()
        };
        let decoded = decode(types, values, &raw).map_err(Error::Output)?;
        if decoded.code != expected
            || decoded.guarded == scalar
            || decoded.inputs
                != image
                    .inputs()
                    .iter()
                    .map(|bind| bind.typ)
                    .collect::<Vec<_>>()
            || decoded.output != Some(image.typ())
            || decoded.results != plan.results
            || decoded.emission != Some(image.emission())
            || decoded.veil != Some((image.veils(), image.veil_depth()))
        {
            return Err(Error::OutputCode);
        }
        raw
    };
    Ok(Image {
        machine: image,
        code: assembly.code,
        raw,
        results: plan.results,
        source,
        live,
    })
}
pub fn encode(
    types: &mut Types,
    values: &mut Values,
    code: &[Operation],
) -> Result<Vec<u8>, Error> {
    let raw = encode_raw(code, None, None)?;
    let image = decode(types, values, &raw).map_err(Error::Output)?;
    if !image.inputs.is_empty() || image.output.is_some() || image.code != code {
        return Err(Error::OutputCode);
    }
    Ok(raw)
}
