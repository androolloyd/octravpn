// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Located standalone source before C_raw expansion and specialization.
use super::super::{
    declaration::{Declarations, Input, TypeId},
    index::{Env, IndexId, Indices, Relation as IndexRelation},
    lexer::Span,
    limit::Limit,
    syntax::{self, Name, Syntax},
    term::Relation,
    types::Multiplicity,
    Effects, Natural,
};
use num_bigint::BigInt;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExprId(pub(super) usize);
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BodyId(pub(super) usize);
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FheId(pub(super) usize);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bind {
    pub name: Name,
    pub multiplicity: Multiplicity,
    pub typ: TypeId,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quantifier {
    Every,
    Any,
    Count,
    Sum,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    Syn(syntax::TermId),
    Unit,
    Bool(bool),
    Int(BigInt),
    Bytes(Vec<u8>),
    Var(Name),
    Vec(TypeId, Vec<ExprId>),
    Seq(IndexId, TypeId, Vec<ExprId>),
    Let(Bind, ExprId, ExprId),
    If(ExprId, ExprId, ExprId),
    Pair(ExprId, ExprId),
    Unpair(ExprId, Bind, Bind, ExprId),
    Fst(ExprId),
    Snd(ExprId),
    Inl(ExprId, TypeId),
    Inr(TypeId, ExprId),
    Case(ExprId, Bind, ExprId, Bind, ExprId),
    Act(syntax::Atom, ExprId),
    Add(ExprId, ExprId),
    Sub(ExprId, ExprId),
    Mul(ExprId, ExprId),
    Div(ExprId, ExprId),
    Mod(ExprId, ExprId),
    Neg(ExprId),
    Abs(ExprId),
    Fit(TypeId, ExprId),
    Wide(ExprId),
    Length(ExprId),
    Eq(TypeId, ExprId, ExprId),
    Cmp(Relation, ExprId, ExprId),
    Cat(ExprId, ExprId),
    Take(BigInt, ExprId),
    Drop(BigInt, ExprId),
    Vcat(ExprId, ExprId),
    At(BigInt, ExprId),
    Uncons(ExprId),
    Fold(ExprId, ExprId, Bind, Bind, ExprId),
    Step(ExprId, ExprId),
    Close(ExprId),
    DataMake(usize, Name, ExprId),
    DataCase(usize, ExprId, Vec<(Name, Bind, ExprId)>),
    RecordMake(usize, Vec<(Name, ExprId)>),
    RecordSplit(usize, ExprId, Vec<(Name, Bind)>, ExprId),
    Quant(Quantifier, ExprId, Bind, ExprId),
    Weave(IndexId, TypeId, ExprId, Bind, ExprId),
    Braid(IndexId, TypeId, ExprId, ExprId, Bind, Bind, ExprId),
    Loom(IndexId, TypeId, Bind, ExprId),
    Orbit(IndexId, ExprId, Bind, ExprId),
    OrbitTo(IndexId, ExprId, ExprId, Bind, ExprId),
    Wake(IndexId, ExprId, Bind, ExprId),
    Rift(IndexId, IndexId, TypeId, ExprId),
    DirectCall(usize, Vec<ExprId>, Natural),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    Ret(ExprId),
    Let(Bind, ExprId, BodyId),
    If(ExprId, BodyId, BodyId),
    Use {
        name: Name,
        types: Vec<TypeId>,
        sizes: Vec<IndexId>,
        captures: Vec<ExprId>,
        argument: ExprId,
        result: Bind,
        rest: BodyId,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Located<T> {
    pub value: T,
    pub mark: Option<Span>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Law {
    pub relation: IndexRelation,
    pub left: IndexId,
    pub right: IndexId,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Data,
    Resource,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Form {
    pub name: Name,
    pub kinds: Vec<(Name, Kind)>,
    pub sizes: Vec<Name>,
    pub laws: Vec<Law>,
    pub captures: Vec<Bind>,
    pub argument: Bind,
    pub multiplicity: Multiplicity,
    pub output: TypeId,
    pub effects: Effects,
    pub limit: Option<Limit>,
    pub body: ExprId,
    pub body_span: Span,
    pub span: Span,
}
impl Form {
    pub fn specialized(&self) -> bool {
        !self.sizes.is_empty()
    }
    pub fn polymorphic(&self) -> bool {
        !self.kinds.is_empty()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Data {
    pub name: Name,
    pub code: BigInt,
    pub constructors: Vec<(Name, syntax::TypeId)>,
    pub typ: syntax::TypeId,
    pub span: Span,
    pub elaborated: super::super::data::Decl,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shape {
    pub name: Name,
    pub code: BigInt,
    pub fields: Vec<(Name, syntax::TypeId)>,
    pub typ: syntax::TypeId,
    pub span: Span,
    pub elaborated: super::super::record::Decl,
}
pub use super::super::perm::Permission;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fhe {
    Var(Name),
    Add(FheId, FheId),
    Mul(FheId, FheId),
    Renew(FheId),
    Trim(BigInt, FheId),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FheInput {
    pub name: Name,
    pub key: BigInt,
    pub remaining: BigInt,
    pub state: Option<(BigInt, BigInt, BigInt)>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Veil {
    pub name: Name,
    pub key: BigInt,
    pub depth: BigInt,
    pub add: BigInt,
    pub multiply: BigInt,
    pub renew: BigInt,
    pub staged: bool,
    pub parameters: Vec<(BigInt, BigInt)>,
    pub inputs: Vec<FheInput>,
    pub body: FheId,
    pub span: Span,
}
#[derive(Clone, Debug, Default)]
pub struct Ast {
    pub indices: Indices,
    pub declarations: Declarations,
    pub syntax: Syntax,
    pub(super) expressions: Vec<Located<Expr>>,
    pub(super) bodies: Vec<Located<Body>>,
    pub(super) private: Vec<Located<Fhe>>,
}
impl Ast {
    pub fn try_expression(&self, id: ExprId) -> Option<&Located<Expr>> {
        self.expressions.get(id.0)
    }
    pub fn try_body(&self, id: BodyId) -> Option<&Located<Body>> {
        self.bodies.get(id.0)
    }
    pub fn try_private(&self, id: FheId) -> Option<&Located<Fhe>> {
        self.private.get(id.0)
    }
    fn require_expr(&self, id: ExprId) -> Result<(), super::super::arena::Reference> {
        self.try_expression(id)
            .map(|_| ())
            .ok_or(super::super::arena::Reference {
                kind: super::super::arena::Kind::RawExpr,
                index: id.0,
                length: self.expressions.len(),
            })
    }
    fn require_body(&self, id: BodyId) -> Result<(), super::super::arena::Reference> {
        self.try_body(id)
            .map(|_| ())
            .ok_or(super::super::arena::Reference {
                kind: super::super::arena::Kind::RawBody,
                index: id.0,
                length: self.bodies.len(),
            })
    }
    /// Construct raw syntax without changing native elaboration checks. The
    /// only extra failure is a Rust arena reference absent from this arena.
    pub fn insert_expression(
        &mut self,
        value: Expr,
        mark: Option<Span>,
    ) -> Result<ExprId, super::super::arena::Reference> {
        for child in super::elaborate::children(&value) {
            self.require_expr(child)?;
        }
        let types = match &value {
            Expr::Syn(id) => {
                self.syntax.require_term(*id)?;
                Vec::new()
            }
            Expr::Vec(typ, _)
            | Expr::Seq(_, typ, _)
            | Expr::Inl(_, typ)
            | Expr::Inr(typ, _)
            | Expr::Fit(typ, _)
            | Expr::Eq(typ, _, _)
            | Expr::Rift(_, _, typ, _) => vec![*typ],
            Expr::Let(bind, _, _)
            | Expr::Quant(_, _, bind, _)
            | Expr::Orbit(_, _, bind, _)
            | Expr::OrbitTo(_, _, _, bind, _)
            | Expr::Wake(_, _, bind, _) => vec![bind.typ],
            Expr::Unpair(_, left, right, _)
            | Expr::Case(_, left, _, right, _)
            | Expr::Fold(_, _, left, right, _) => vec![left.typ, right.typ],
            Expr::Weave(_, typ, _, bind, _) | Expr::Loom(_, typ, bind, _) => vec![*typ, bind.typ],
            Expr::Braid(_, typ, _, _, left, right, _) => vec![*typ, left.typ, right.typ],
            Expr::DataCase(_, _, arms) => arms.iter().map(|(_, bind, _)| bind.typ).collect(),
            Expr::RecordSplit(_, _, picks, _) => picks.iter().map(|(_, bind)| bind.typ).collect(),
            _ => Vec::new(),
        };
        for typ in types {
            self.declarations.require(typ)?;
        }
        match &value {
            Expr::Seq(index, _, _)
            | Expr::Weave(index, _, _, _, _)
            | Expr::Braid(index, _, _, _, _, _, _)
            | Expr::Loom(index, _, _, _)
            | Expr::Orbit(index, _, _, _)
            | Expr::OrbitTo(index, _, _, _, _)
            | Expr::Wake(index, _, _, _) => self.indices.require(*index)?,
            Expr::Rift(first, second, _, _) => {
                self.indices.require(*first)?;
                self.indices.require(*second)?;
            }
            _ => (),
        }
        Ok(self.push_expr(value, mark))
    }
    pub fn insert_body(
        &mut self,
        value: Body,
        mark: Option<Span>,
    ) -> Result<BodyId, super::super::arena::Reference> {
        match &value {
            Body::Ret(expr) => self.require_expr(*expr)?,
            Body::Let(bind, expr, body) => {
                self.declarations.require(bind.typ)?;
                self.require_expr(*expr)?;
                self.require_body(*body)?;
            }
            Body::If(guard, yes, no) => {
                self.require_expr(*guard)?;
                self.require_body(*yes)?;
                self.require_body(*no)?;
            }
            Body::Use {
                types,
                sizes,
                captures,
                argument,
                result,
                rest,
                ..
            } => {
                for typ in types {
                    self.declarations.require(*typ)?;
                }
                for index in sizes {
                    self.indices.require(*index)?;
                }
                for expr in captures {
                    self.require_expr(*expr)?;
                }
                self.require_expr(*argument)?;
                self.declarations.require(result.typ)?;
                self.require_body(*rest)?;
            }
        }
        let id = BodyId(self.bodies.len());
        self.bodies.push(Located { value, mark });
        Ok(id)
    }
    pub fn insert_private(
        &mut self,
        value: Fhe,
        mark: Option<Span>,
    ) -> Result<FheId, super::super::arena::Reference> {
        let children = match &value {
            Fhe::Var(_) => Vec::new(),
            Fhe::Renew(body) | Fhe::Trim(_, body) => vec![*body],
            Fhe::Add(left, right) | Fhe::Mul(left, right) => vec![*left, *right],
        };
        for child in children {
            if self.try_private(child).is_none() {
                return Err(super::super::arena::Reference {
                    kind: super::super::arena::Kind::Fhe,
                    index: child.0,
                    length: self.private.len(),
                });
            }
        }
        let id = FheId(self.private.len());
        self.private.push(Located { value, mark });
        Ok(id)
    }
    pub(crate) fn push_expr(&mut self, value: Expr, mark: Option<Span>) -> ExprId {
        let id = ExprId(self.expressions.len());
        self.expressions.push(Located { value, mark });
        id
    }
    pub fn expression(&self, id: ExprId) -> &Located<Expr> {
        &self.expressions[id.0]
    }
    pub fn body(&self, id: BodyId) -> &Located<Body> {
        &self.bodies[id.0]
    }
    pub fn private(&self, id: FheId) -> &Located<Fhe> {
        &self.private[id.0]
    }
}
#[derive(Clone, Debug)]
pub struct Parsed {
    pub perms: super::super::perm::Set,
    pub name: Name,
    pub ast: Ast,
    pub sizes: Env,
    pub inputs: Vec<Input>,
    pub input_spans: Vec<Span>,
    pub forms: Vec<Form>,
    pub data: Vec<Data>,
    pub shapes: Vec<Shape>,
    pub permissions: Vec<(BigInt, Permission)>,
    pub veils: Vec<Veil>,
    pub body: BodyId,
    pub body_span: Span,
    pub span: Span,
}
