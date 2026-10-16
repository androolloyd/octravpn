// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_mach checked image construction over lowered core terms. The surface
//! parser, OCTB emitter and code-bound evidence admission are separate stages.
use super::super::{
    check,
    eval::{self, Output, ValueId, Values},
    feed::{self, Feed},
    lexer::Span,
    rule::{Field, LOCAL},
    term::{Bind, Program, TermId, Terms},
    types::{TypeId, Types},
    Atom, Effects, Natural,
};
use super::{
    literal, CodeId, Codes, Literal, LocationId, Locations, Operation, Shape, Shapes, Trees,
};
use num_bigint::BigInt;
use num_traits::Zero;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Emission {
    Lowered,
    Specialized,
}
impl Emission {
    pub fn text(self) -> &'static str {
        match self {
            Self::Lowered => "lowered",
            Self::Specialized => "specialized",
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Source<'a> {
    pub marks: &'a [Option<Span>],
    pub span: Span,
    pub veils: usize,
    pub veil_depth: Natural,
}
#[derive(Clone, Debug)]
pub struct Image {
    inputs: Vec<Bind>,
    codes: Codes,
    code: CodeId,
    shapes: Shapes,
    locations: Locations,
    location: LocationId,
    typ: TypeId,
    result: Option<Literal>,
    emission: Emission,
    veils: usize,
    veil_depth: Natural,
    span: Span,
}
impl Image {
    pub fn inputs(&self) -> &[Bind] {
        &self.inputs
    }
    pub fn codes(&self) -> &Codes {
        &self.codes
    }
    pub fn code(&self) -> CodeId {
        self.code
    }
    pub fn shapes(&self) -> &Shapes {
        &self.shapes
    }
    pub fn locations(&self) -> &Locations {
        &self.locations
    }
    pub fn location(&self) -> LocationId {
        self.location
    }
    pub fn typ(&self) -> TypeId {
        self.typ
    }
    pub fn result(&self) -> Option<&Literal> {
        self.result.as_ref()
    }
    pub fn emission(&self) -> Emission {
        self.emission
    }
    pub fn veils(&self) -> usize {
        self.veils
    }
    pub fn veil_depth(&self) -> Natural {
        self.veil_depth
    }
    pub fn span(&self) -> Span {
        self.span
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Source(super::super::parse::Error),
    Check(check::Error),
    Feed(feed::Error),
    Input(Natural, TypeId),
    Inputs(BigInt),
    Layout(BigInt),
    Types(BigInt),
    Effects(Effects),
    Term,
    Run(eval::Error),
    Plan(Vec<Atom>),
    Value(TypeId, ValueId),
    Replay,
    Map,
}
struct Builder<'a> {
    source: Source<'a>,
    codes: Codes,
    shapes: Shapes,
    locations: Locations,
}
impl<'a> Builder<'a> {
    fn new(source: Source<'a>) -> Self {
        Self {
            source,
            codes: Codes::default(),
            shapes: Shapes::default(),
            locations: Locations::default(),
        }
    }
    fn image(
        self,
        inputs: Vec<Bind>,
        typ: TypeId,
        code: CodeId,
        location: LocationId,
        result: Option<Literal>,
        emission: Emission,
    ) -> Image {
        Image {
            inputs,
            typ,
            code,
            location,
            result,
            emission,
            codes: self.codes,
            shapes: self.shapes,
            locations: self.locations,
            veils: self.source.veils,
            veil_depth: self.source.veil_depth,
            span: self.source.span,
        }
    }
    fn closed(mut self, typ: TypeId, result: Literal) -> Image {
        let done = self.codes.done();
        let code = self.codes.next(Operation::Push(result.clone()), done);
        let location = self.locations.locate(&self.codes, code, self.source.span);
        self.image(
            vec![],
            typ,
            code,
            location,
            Some(result),
            Emission::Specialized,
        )
    }
    fn map(
        &mut self,
        types: &Types,
        terms: &Terms,
        original: TermId,
        term: TermId,
        code: CodeId,
    ) -> Result<LocationId, Error> {
        let mut trees = Trees::default();
        let (mut tree, consumed) = trees
            .from_marks(terms, original, self.source.marks)
            .ok_or(Error::Map)?;
        if consumed != self.source.marks.len() {
            return Err(Error::Map);
        }
        if original != term {
            tree = trees
                .retree(terms, original, term, tree)
                .ok_or(Error::Map)?;
        }
        let location = self
            .locations
            .from_term(types, terms, &trees, term, tree)
            .ok_or(Error::Map)?;
        if !self.locations.same(&self.codes, code, location) {
            return Err(Error::Map);
        }
        Ok(location)
    }
    fn finish(
        mut self,
        types: &mut Types,
        terms: &Terms,
        values: &mut Values,
        original: TermId,
        term: TermId,
        info: &check::Info,
        out: &Output,
    ) -> Result<Image, Error> {
        let result = literal(types, values, info.typ(), out.value())
            .ok_or(Error::Value(info.typ(), out.value()))?;
        let Some(code) = self.codes.lower(&mut self.shapes, types, terms, &[], term) else {
            return if out.plan().is_empty() {
                Ok(self.closed(info.typ(), result))
            } else {
                Err(Error::Plan(out.plan().to_vec()))
            };
        };
        match self
            .codes
            .one_shape(&mut self.shapes, types, code)
            .map(|shape| self.shapes.get(shape).clone())
        {
            Some(Shape::Atom) => {
                let location = self.map(types, terms, original, term, code)?;
                let replay = self
                    .codes
                    .replay_actions_in(&mut self.shapes, types, values, code, &[])
                    .ok_or(Error::Replay)?;
                if !matches!(replay.literals.as_slice(), [actual] if actual.equal(&result))
                    || eval::atoms(&replay.actions).as_slice() != out.plan()
                {
                    return Err(Error::Replay);
                }
                Ok(self.image(
                    vec![],
                    info.typ(),
                    code,
                    location,
                    Some(result),
                    Emission::Lowered,
                ))
            }
            Some(_) if out.plan().is_empty() => Ok(self.closed(info.typ(), result)),
            Some(_) => Err(Error::Plan(out.plan().to_vec())),
            None => Err(Error::Term),
        }
    }
    fn open(
        mut self,
        types: &Types,
        terms: &Terms,
        program: &Program,
        info: &check::Info,
    ) -> Result<Image, Error> {
        let mut width = BigInt::zero();
        let mut cells = BigInt::zero();
        let mut nodes = BigInt::zero();
        for bind in &program.inputs {
            let shape = self
                .shapes
                .from_type(types, bind.typ)
                .ok_or(Error::Input(bind.id, bind.typ))?;
            let count = types
                .nodes(bind.typ)
                .ok_or(Error::Input(bind.id, bind.typ))?;
            width += self.shapes.width(shape);
            cells += self.shapes.cells(shape);
            nodes += count;
        }
        let output = self
            .shapes
            .from_type(types, info.typ())
            .ok_or(Error::Term)?;
        let out_nodes = types.nodes(info.typ()).ok_or(Error::Term)?;
        cells += self.shapes.cells(output);
        nodes += out_nodes;
        if width > BigInt::from(60) {
            return Err(Error::Inputs(width));
        }
        if cells > BigInt::from(LOCAL.get(Field::Inputs)) {
            return Err(Error::Layout(cells));
        }
        if nodes > BigInt::from(LOCAL.get(Field::TypeNodes)) {
            return Err(Error::Types(nodes));
        }
        let fuel = BigInt::from(LOCAL.get(Field::Fuel));
        if info.resources().steps > fuel {
            return Err(Error::Run(eval::Error::Fuel(
                fuel,
                info.resources().steps.clone(),
            )));
        }
        if info
            .effects()
            .iter()
            .any(|atom| !matches!(atom, Atom::Close(_)))
        {
            return Err(Error::Effects(info.effects().clone()));
        }
        let code = self
            .codes
            .lower(
                &mut self.shapes,
                types,
                terms,
                &program.inputs,
                program.term,
            )
            .ok_or(Error::Term)?;
        if self.codes.one_shape(&mut self.shapes, types, code) != Some(output) {
            return Err(Error::Term);
        }
        let location = self.map(types, terms, program.term, program.term, code)?;
        Ok(self.image(
            program.inputs.clone(),
            info.typ(),
            code,
            location,
            None,
            Emission::Lowered,
        ))
    }
}
pub fn compile(
    types: &mut Types,
    terms: &Terms,
    values: &mut Values,
    program: &Program,
    source: Source<'_>,
) -> Result<Image, Error> {
    let checked =
        check::check_in(types, terms, &program.inputs, program.term).map_err(Error::Check)?;
    compile_checked(types, terms, values, program, source, checked.info())
}
pub(super) fn compile_checked(
    types: &mut Types,
    terms: &Terms,
    values: &mut Values,
    program: &Program,
    source: Source<'_>,
    info: &check::Info,
) -> Result<Image, Error> {
    let builder = Builder::new(source);
    if program.inputs.is_empty() {
        let out = eval::run(types, terms, values, program.term, None).map_err(Error::Run)?;
        builder.finish(types, terms, values, program.term, program.term, info, &out)
    } else {
        builder.open(types, terms, program, info)
    }
}
pub fn compile_feed(
    types: &mut Types,
    terms: &mut Terms,
    values: &mut Values,
    program: &Program,
    source: Source<'_>,
    feed: &Feed,
) -> Result<Image, Error> {
    let checked =
        check::check_in(types, terms, &program.inputs, program.term).map_err(Error::Check)?;
    compile_feed_checked(types, terms, values, program, source, checked.info(), feed)
}
pub(super) fn compile_feed_checked(
    types: &mut Types,
    terms: &mut Terms,
    values: &mut Values,
    program: &Program,
    source: Source<'_>,
    info: &check::Info,
    feed: &Feed,
) -> Result<Image, Error> {
    let pairs = feed
        .attach(types, values, &program.inputs)
        .map_err(Error::Feed)?;
    let term = feed
        .close(types, values, terms, &program.inputs, program.term)
        .map_err(Error::Feed)?;
    let out = eval::run_in(types, terms, values, &pairs, program.term, None).map_err(Error::Run)?;
    Builder::new(source).finish(types, terms, values, program.term, term, info, &out)
}
impl Error {
    pub fn text(&self, types: &Types, values: &Values) -> Vec<u8> {
        match self {
            Self::Source(error) => error.text(),
            Self::Check(error) => error.text(types),
            Self::Feed(error) => error.text(types),
            Self::Input(id, typ) => [
                format!(
                    "machine input is outside the plain data profile id = {} type = ",
                    id.get()
                )
                .as_bytes(),
                &types.text(*typ),
            ]
            .concat(),
            Self::Inputs(count) => {
                format!("machine input count = {count} maximum = 60").into_bytes()
            }
            Self::Layout(cells) => {
                format!("machine layout cells = {cells} maximum = 4096").into_bytes()
            }
            Self::Types(nodes) => {
                format!("machine type nodes = {nodes} maximum = 4096").into_bytes()
            }
            Self::Effects(effects) => [
                b"machine effects are not representable effects = ".as_slice(),
                &super::super::effects_text(effects),
            ]
            .concat(),
            Self::Term => b"machine term is outside the runtime data profile".to_vec(),
            Self::Run(error) => error.text(types),
            Self::Plan(plan) => [
                b"machine execution plan is not empty effects = ".as_slice(),
                &super::super::effects_text(&plan.iter().copied().collect()),
            ]
            .concat(),
            Self::Value(typ, value) => [
                b"machine value is not representable type = ".as_slice(),
                &types.text(*typ),
                b" value = ",
                &values.text(*value),
            ]
            .concat(),
            Self::Replay => b"machine replay differs from checked evaluation".to_vec(),
            Self::Map => b"machine source position map differs from lowered term".to_vec(),
        }
    }
}
