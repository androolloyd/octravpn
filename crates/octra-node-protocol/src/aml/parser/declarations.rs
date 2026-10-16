// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native declaration ordering, duplicate checks and direct form syntax.
use super::{
    Atom, Const, Contract, Declaration, Enum, ErrorDef, Event, Form, FormMark, Function, Import,
    Interface, InterfaceMethod, Invariant, Limit, Name, Natural, Parser, Result, StateField,
    Struct, Type, TypeId, Visibility, S, T, W,
};
#[derive(Clone, Copy)]
struct Modifiers {
    visibility: Visibility,
    view: bool,
    pure: bool,
    payable: bool,
    nonreentrant: bool,
}
impl Default for Modifiers {
    fn default() -> Self {
        Self {
            visibility: Visibility::Public,
            view: false,
            pure: false,
            payable: false,
            nonreentrant: false,
        }
    }
}
impl Parser<'_> {
    fn fields(&mut self, state: bool) -> Result<Vec<(Name, TypeId)>> {
        self.expect(T::Symbol(S::LBrace))?;
        let mut out: Vec<(Name, TypeId)> = vec![];
        loop {
            if self.is(T::Symbol(S::RBrace))? {
                self.eat();
                return Ok(out);
            }
            let name = self.ident()?;
            if !self.prior && out.iter().any(|(prior, _)| *prior == name) {
                return Err(self.error(
                    [
                        if state {
                            b"duplicate state field name = ".as_slice()
                        } else {
                            b"duplicate struct field name = "
                        },
                        &name,
                    ]
                    .concat(),
                ));
            }
            self.expect(T::Symbol(S::Colon))?;
            out.push((name, self.typ()?));
            if self.is(T::Symbol(S::Comma))? {
                self.eat();
            }
        }
    }
    fn event(&mut self) -> Result<Event> {
        let name = self.ident()?;
        self.expect(T::Symbol(S::LParen))?;
        let mut fields: Vec<(Name, TypeId, bool)> = vec![];
        loop {
            if self.is(T::Symbol(S::RParen))? {
                self.eat();
                return Ok(Event { name, fields });
            }
            if !fields.is_empty() {
                self.expect(T::Symbol(S::Comma))?;
            }
            let field = self.ident()?;
            if !self.prior && fields.iter().any(|(name, _, _)| *name == field) {
                return Err(
                    self.error([b"duplicate event field name = ".as_slice(), &field].concat())
                );
            }
            self.expect(T::Symbol(S::Colon))?;
            let indexed = matches!(self.stream.peek()?, T::Ident(name) if name == b"indexed");
            if indexed {
                self.eat();
            }
            fields.push((field, self.typ()?, indexed));
        }
    }
    fn return_type(&mut self) -> Result<TypeId> {
        if self.is(T::Symbol(S::Colon))? {
            self.eat();
            self.typ()
        } else {
            Ok(self.nodes.intern(Type::Void))
        }
    }
    fn function(&mut self, modifiers: Modifiers) -> Result<Function> {
        self.eat();
        let name = self.ident()?;
        let params = self.params()?;
        let ret = self.return_type()?;
        let body = self.block()?;
        Ok(Function {
            name,
            params,
            ret,
            body,
            view: modifiers.view,
            pure: modifiers.pure,
            payable: modifiers.payable,
            nonreentrant: modifiers.nonreentrant,
            visibility: modifiers.visibility,
        })
    }
    fn modified_function(&mut self, mut modifiers: Modifiers) -> Result<Function> {
        loop {
            match self.token()? {
                T::Word(W::View) => modifiers.view = true,
                T::Word(W::Pure) => modifiers.pure = true,
                T::Word(W::Payable) => {
                    modifiers.view = false;
                    modifiers.pure = false;
                    modifiers.payable = true;
                }
                T::Ident(name) if name == b"nonreentrant" => modifiers.nonreentrant = true,
                T::Word(W::Fn) => return self.function(modifiers),
                _ => return Err(self.error("expected fn after modifiers")),
            }
            self.eat();
        }
    }
    fn constructor(&mut self) -> Result<Function> {
        let params = self.params()?;
        let body = self.block()?;
        Ok(Function {
            name: b"constructor".to_vec(),
            params,
            ret: self.nodes.intern(Type::Void),
            body,
            view: false,
            pure: false,
            payable: true,
            nonreentrant: false,
            visibility: Visibility::Public,
        })
    }
    fn form_axis(&mut self, name: &[u8]) -> Result<num_bigint::BigInt> {
        self.word(name)?;
        self.expect(T::Symbol(S::LBracket))?;
        let value = match self.stream.peek()? {
            T::Integer(value) => Natural::new(value),
            _ => return Err(self.error("expected direct form limit")),
        };
        self.eat();
        let value = value.ok_or_else(|| self.error("direct form limit is invalid"))?;
        self.expect(T::Symbol(S::RBracket))?;
        Ok(value.get().into())
    }
    fn form_limit(&mut self) -> Result<Option<Limit>> {
        if !matches!(self.stream.peek()?, T::Ident(name) if name == b"under") {
            return Ok(None);
        }
        self.eat();
        self.expect(T::Symbol(S::LBrace))?;
        let steps = self.form_axis(b"steps")?;
        self.expect(T::Symbol(S::Comma))?;
        let depth = self.form_axis(b"depth")?;
        self.expect(T::Symbol(S::Comma))?;
        let work = self.form_axis(b"work")?;
        self.expect(T::Symbol(S::RBrace))?;
        Ok(Some(Limit { steps, depth, work }))
    }
    fn form_marks(&mut self) -> Result<Vec<FormMark>> {
        self.expect(T::Symbol(S::LBrace))?;
        let mut marks = vec![];
        loop {
            if self.is(T::Symbol(S::RBrace))? {
                self.eat();
                return Ok(marks);
            }
            if !marks.is_empty() {
                self.expect(T::Symbol(S::Comma))?;
            }
            let make: fn(Natural) -> Atom = match self.stream.peek()? {
                T::Word(W::Emit) => Atom::Emit,
                T::Ident(name) if name == b"write" => Atom::Write,
                T::Ident(name) if name == b"read" => Atom::Read,
                T::Ident(name) if name == b"fail" => Atom::Fail,
                _ => return Err(self.error("direct form mark is unsupported")),
            };
            self.eat();
            self.expect(T::Symbol(S::LBracket))?;
            let kind = self.natural(b"expected effect atom")?;
            self.expect(T::Symbol(S::RBracket))?;
            self.expect(T::Symbol(S::Colon))?;
            let target = self.ident()?;
            marks.push(FormMark {
                atom: make(kind),
                target,
            });
        }
    }
    fn form(&mut self, public: bool) -> Result<Form> {
        let (line, column) = self.stream.location();
        self.eat();
        let name = if public {
            b"main".to_vec()
        } else {
            self.ident()?
        };
        let mut params = vec![];
        if !public {
            self.expect(T::Symbol(S::LBracket))?;
            loop {
                if self.is(T::Symbol(S::RBracket))? {
                    self.eat();
                    break;
                }
                if !params.is_empty() {
                    self.expect(T::Symbol(S::Comma))?;
                }
                params.push(self.binding()?);
            }
        }
        self.expect(T::Symbol(S::LParen))?;
        if public {
            let mut arguments = vec![];
            loop {
                if self.is(T::Symbol(S::RParen))? {
                    self.eat();
                    break;
                }
                if !arguments.is_empty() {
                    self.expect(T::Symbol(S::Comma))?;
                }
                arguments.push(self.binding()?);
            }
            params = arguments;
        } else {
            params.push(self.binding()?);
            self.expect(T::Symbol(S::RParen))?;
        }
        self.expect(T::Symbol(S::Minus))?;
        self.expect(T::Symbol(S::Gt))?;
        self.expect(T::Symbol(S::LBracket))?;
        let mult = self.multiplicity()?;
        self.expect(T::Symbol(S::RBracket))?;
        let ret = self.typ()?;
        self.word(b"marks")?;
        let marks = self.form_marks()?;
        let limit = self.form_limit()?;
        self.expect(T::Symbol(S::Eq))?;
        let body = self.expr()?;
        Ok(Form {
            name,
            params,
            ret,
            mult,
            marks,
            limit,
            body,
            public,
            line,
            column,
        })
    }
    fn constant(&mut self) -> Result<Const> {
        let name = self.ident()?;
        let typ = self.return_type()?;
        self.expect(T::Symbol(S::Eq))?;
        let value = self.expr()?;
        Ok(Const { name, typ, value })
    }
    fn error_def(&mut self) -> Result<ErrorDef> {
        let name = self.ident()?;
        self.expect(T::Symbol(S::LParen))?;
        let code = self.ast_int(b"expected error code (integer)")?;
        self.expect(T::Symbol(S::Comma))?;
        let message = match self.token()? {
            T::String(message) => {
                self.eat();
                message
            }
            _ => return Err(self.error("expected error message (string)")),
        };
        self.expect(T::Symbol(S::RParen))?;
        Ok(ErrorDef {
            name,
            code,
            message,
        })
    }
    fn enumeration(&mut self) -> Result<Enum> {
        let name = self.ident()?;
        self.expect(T::Symbol(S::LBrace))?;
        let mut variants = vec![];
        loop {
            if self.is(T::Symbol(S::RBrace))? {
                self.eat();
                return Ok(Enum { name, variants });
            }
            if !variants.is_empty() && self.is(T::Symbol(S::Comma))? {
                self.eat();
            }
            let variant = self.ident()?;
            if !self.prior && variants.contains(&variant) {
                return Err(
                    self.error([b"duplicate enum variant name = ".as_slice(), &variant].concat())
                );
            }
            variants.push(variant);
        }
    }
    fn interface(&mut self) -> Result<Interface> {
        self.eat();
        let name = self.ident()?;
        self.expect(T::Symbol(S::LBrace))?;
        let mut methods: Vec<InterfaceMethod> = vec![];
        loop {
            match self.token()? {
                T::Symbol(S::RBrace) => {
                    self.eat();
                    return Ok(Interface { name, methods });
                }
                T::Word(W::Fn) => {
                    self.eat();
                    let name = self.ident()?;
                    let params = self.params()?;
                    let ret = self.return_type()?;
                    if !self.prior && methods.iter().any(|prior| prior.name == name) {
                        return Err(self.error(
                            [b"duplicate interface method name = ".as_slice(), &name].concat(),
                        ));
                    }
                    methods.push(InterfaceMethod { name, params, ret });
                }
                _ => return Err(self.error("expected fn or } in interface")),
            }
        }
    }
    fn names(&mut self) -> Result<Vec<Name>> {
        let mut names = vec![];
        loop {
            names.push(self.ident()?);
            if self.is(T::Symbol(S::Comma))? {
                self.eat();
            } else {
                return Ok(names);
            }
        }
    }
    fn import(&mut self) -> Result<Import> {
        self.eat();
        let names = self.names()?;
        if !matches!(self.stream.peek()?, T::Ident(name) if name == b"from") {
            return Err(self.error("expected 'from' after import names"));
        }
        self.eat();
        let path = match self.token()? {
            T::String(path) => {
                self.eat();
                path
            }
            _ => return Err(self.error("expected string path after from")),
        };
        Ok(Import { names, path })
    }
    pub(super) fn contract(&mut self) -> Result<Contract> {
        let mut imports = vec![];
        while self.is(T::Word(W::Import))? {
            imports.push(self.import()?);
        }
        let mut interfaces = vec![];
        while self.is(T::Word(W::Interface))? {
            interfaces.push(self.interface()?);
        }
        let declaration = match self.token()? {
            T::Eof => Declaration::Interface,
            T::Word(W::Program) => {
                self.eat();
                Declaration::Program
            }
            T::Word(W::Contract) => {
                self.eat();
                Declaration::Contract
            }
            T::Ident(name) if name == b"Program" => {
                self.eat();
                Declaration::Program
            }
            T::Ident(name) if name == b"Contract" => {
                self.eat();
                Declaration::Contract
            }
            _ => return Err(self.error("expected program or contract")),
        };
        let mut contract = Contract {
            declaration,
            name: vec![],
            imports,
            interfaces,
            structs: vec![],
            enums: vec![],
            consts: vec![],
            invariants: vec![],
            state: vec![],
            events: vec![],
            errors: vec![],
            implements: vec![],
            constructor: None,
            functions: vec![],
            forms: vec![],
        };
        if declaration == Declaration::Interface {
            return Ok(contract);
        }
        contract.name = self.ident()?;
        if self.is(T::Word(W::Implements))? {
            self.eat();
            contract.implements = self.names()?;
        }
        self.expect(T::Symbol(S::LBrace))?;
        let mut state_seen = false;
        loop {
            match self.token()? {
                T::Symbol(S::RBrace) => {
                    self.eat();
                    return Ok(contract);
                }
                T::Word(W::Struct) => {
                    self.eat();
                    let name = self.ident()?;
                    let fields = self.fields(false)?;
                    if !self.prior
                        && (contract.structs.iter().any(|item| item.name == name)
                            || contract.enums.iter().any(|item| item.name == name))
                    {
                        return Err(
                            self.error([b"duplicate type name = ".as_slice(), &name].concat())
                        );
                    }
                    contract.structs.push(Struct { name, fields });
                }
                T::Word(W::Enum) => {
                    self.eat();
                    let item = self.enumeration()?;
                    if !self.prior
                        && (contract.structs.iter().any(|prior| prior.name == item.name)
                            || contract.enums.iter().any(|prior| prior.name == item.name))
                    {
                        return Err(
                            self.error([b"duplicate type name = ".as_slice(), &item.name].concat())
                        );
                    }
                    contract.enums.push(item);
                }
                T::Word(W::Const) => {
                    self.eat();
                    let item = self.constant()?;
                    if !self.prior && contract.consts.iter().any(|prior| prior.name == item.name) {
                        return Err(self.error(
                            [b"duplicate constant name = ".as_slice(), &item.name].concat(),
                        ));
                    }
                    contract.consts.push(item);
                }
                T::Ident(name) if name == b"invariant" => {
                    self.eat();
                    let name = self.ident()?;
                    self.expect(T::Symbol(S::Eq))?;
                    let expr = self.expr()?;
                    if !self.prior && contract.invariants.iter().any(|prior| prior.name == name) {
                        return Err(
                            self.error([b"duplicate invariant name = ".as_slice(), &name].concat())
                        );
                    }
                    contract.invariants.push(Invariant { name, expr });
                }
                T::Word(W::State) => {
                    self.eat();
                    if !self.prior && state_seen {
                        return Err(self.error("duplicate state declaration"));
                    }
                    state_seen = true;
                    contract.state = self
                        .fields(true)?
                        .into_iter()
                        .map(|(name, typ)| StateField { name, typ })
                        .collect();
                }
                T::Word(W::Error) => {
                    self.eat();
                    let item = self.error_def()?;
                    if !self.prior && contract.errors.iter().any(|prior| prior.name == item.name) {
                        return Err(self
                            .error([b"duplicate error name = ".as_slice(), &item.name].concat()));
                    }
                    contract.errors.push(item);
                }
                T::Word(W::Event) => {
                    self.eat();
                    let item = self.event()?;
                    if !self.prior && contract.events.iter().any(|prior| prior.name == item.name) {
                        return Err(self
                            .error([b"duplicate event name = ".as_slice(), &item.name].concat()));
                    }
                    contract.events.push(item);
                }
                T::Word(W::Constructor) => {
                    self.eat();
                    if !self.prior && contract.constructor.is_some() {
                        return Err(self.error("duplicate constructor"));
                    }
                    contract.constructor = Some(self.constructor()?);
                }
                T::Word(W::Public) => {
                    self.eat();
                    if !self.prior
                        && matches!(self.stream.peek()?, T::Ident(name) if name == b"main")
                    {
                        if declaration != Declaration::Program {
                            return Err(self.error("main declaration requires Program"));
                        }
                        if contract.forms.iter().any(|prior| prior.name == b"main")
                            || contract.functions.iter().any(|prior| prior.name == b"main")
                        {
                            return Err(self.error("duplicate main declaration"));
                        }
                        contract.forms.push(self.form(true)?);
                    } else {
                        self.add_function(&mut contract, Modifiers::default(), true)?;
                    }
                }
                T::Word(word @ (W::Private | W::Internal | W::View | W::Pure | W::Payable)) => {
                    self.eat();
                    let mut modifiers = Modifiers::default();
                    match word {
                        W::Private => modifiers.visibility = Visibility::Private,
                        W::Internal => modifiers.visibility = Visibility::Internal,
                        W::View => modifiers.view = true,
                        W::Pure => modifiers.pure = true,
                        W::Payable => modifiers.payable = true,
                        _ => unreachable!(),
                    }
                    self.add_function(&mut contract, modifiers, true)?;
                }
                T::Ident(name) if name == b"nonreentrant" => {
                    self.eat();
                    self.add_function(
                        &mut contract,
                        Modifiers {
                            nonreentrant: true,
                            ..Modifiers::default()
                        },
                        true,
                    )?;
                }
                T::Word(W::Fn) => self.add_function(&mut contract, Modifiers::default(), false)?,
                T::Ident(name) if !self.prior && name == b"form" => {
                    if declaration != Declaration::Program {
                        return Err(self.error("form declarations require Program"));
                    }
                    let form = self.form(false)?;
                    if contract.forms.iter().any(|prior| prior.name == form.name) {
                        return Err(
                            self.error([b"duplicate form name = ".as_slice(), &form.name].concat())
                        );
                    }
                    contract.forms.push(form);
                }
                T::Ident(name)
                    if !self.prior
                        && declaration == Declaration::Program
                        && matches!(name.as_slice(), b"input" | b"term") =>
                {
                    return Err(self.error("stateful or callable entry requires public main"))
                }
                _ => {
                    return Err(self.error(
                        "expected struct, enum, const, state, event, constructor, fn, or }",
                    ))
                }
            }
        }
    }
    fn add_function(
        &mut self,
        contract: &mut Contract,
        modifiers: Modifiers,
        modified: bool,
    ) -> Result<()> {
        let function = if modified {
            self.modified_function(modifiers)?
        } else {
            self.function(modifiers)?
        };
        if !self.prior
            && contract
                .functions
                .iter()
                .any(|prior| prior.name == function.name)
        {
            return Err(
                self.error([b"duplicate function name = ".as_slice(), &function.name].concat())
            );
        }
        contract.functions.push(function);
        Ok(())
    }
}
