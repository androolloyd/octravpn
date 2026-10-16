// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Oct_lang syntax. Flat arenas keep long left-associated expressions and type
//! products from recursively cloning or dropping the host stack.
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use std::collections::BTreeMap;
mod merge;

pub type Name = Vec<u8>;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeId(usize);
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExprId(usize);
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StmtId(usize);
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Natural(u32);
impl Natural {
    pub fn new(value: &BigInt) -> Option<Self> {
        value
            .to_u32()
            .filter(|value| *value <= super::limits::NATURAL)
            .map(Self)
    }
    pub fn get(self) -> u32 {
        self.0
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Type {
    Int,
    Bool,
    String,
    Address,
    Bytes,
    Bytes32,
    U64,
    U128,
    U256,
    Cipher,
    PubKey,
    Map(TypeId, TypeId),
    List(TypeId),
    Struct(Name),
    Enum(Name),
    Option(TypeId),
    Tuple(Vec<TypeId>),
    Void,
}
impl Type {
    pub fn name(&self) -> &[u8] {
        match self {
            Self::Int => b"int",
            Self::Bool => b"bool",
            Self::String => b"string",
            Self::Address => b"address",
            Self::Bytes => b"bytes",
            Self::Bytes32 => b"bytes32",
            Self::U64 => b"u64",
            Self::U128 => b"u128",
            Self::U256 => b"u256",
            Self::Cipher => b"cipher",
            Self::PubKey => b"pubkey",
            Self::Map(..) => b"map",
            Self::List(_) => b"list",
            Self::Struct(name) | Self::Enum(name) => name,
            Self::Option(_) => b"option",
            Self::Tuple(_) => b"tuple",
            Self::Void => b"void",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Visibility {
    Public,
    Private,
    Internal,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Declaration {
    Program,
    Contract,
    Interface,
}
impl Declaration {
    pub fn name(self) -> &'static [u8] {
        match self {
            Self::Program => b"program",
            Self::Contract => b"contract",
            Self::Interface => b"interface",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Eq,
    Neq,
    Lt,
    Gt,
    Le,
    Ge,
    And,
    Or,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnOp {
    Neg,
    Not,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mult {
    Once,
    Many,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Atom {
    Read(Natural),
    Write(Natural),
    Emit(Natural),
    Fail(Natural),
    Close(Natural),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub name: Name,
    pub mult: Mult,
    pub typ: TypeId,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    Int(BigInt),
    Bool(bool),
    String(Vec<u8>),
    Var(Name),
    Field(Name),
    Index(Name, Vec<ExprId>),
    Binop(BinOp, ExprId, ExprId),
    Unop(UnOp, ExprId),
    Caller,
    Origin,
    SelfAddr,
    Epoch,
    EpochTime,
    Value,
    Balance(ExprId),
    TreeHash,
    NodeId,
    TxHash,
    Call(Name, Vec<ExprId>),
    Array(Vec<ExprId>),
    Tuple(Vec<ExprId>),
    StoragePath(Name, Vec<ExprId>, Vec<Name>),
    FieldProp(Name, Name),
    IndexField(Name, Vec<ExprId>, Name),
    EnumVariant(Name, Name),
    Ternary(ExprId, ExprId, ExprId),
    Equal(TypeId, ExprId, ExprId),
    Let(Binding, ExprId, ExprId),
    Split(ExprId, Binding, Binding, ExprId),
    Orbit(Natural, Option<ExprId>, ExprId, Binding, ExprId),
    Action(Atom, ExprId),
    Use(Use),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Use {
    pub name: Name,
    pub caps: Vec<ExprId>,
    pub arg: ExprId,
    pub binding: Binding,
    pub body: ExprId,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stmt {
    Located(usize, usize, StmtId),
    Let(Name, Option<TypeId>, ExprId),
    Assign(Name, ExprId),
    FieldSet(Name, ExprId),
    IndexSet(Name, Vec<ExprId>, ExprId),
    IndexUpdate(Name, Vec<ExprId>, BinOp, ExprId),
    Return(Option<ExprId>),
    Assert(ExprId),
    Require(ExprId, ExprId),
    Emit(Name, Vec<ExprId>),
    If(ExprId, Vec<StmtId>, Option<Vec<StmtId>>),
    While(ExprId, Vec<StmtId>),
    For(Name, ExprId, ExprId, Vec<StmtId>),
    FieldCall(Name, Name, Vec<ExprId>),
    StoragePathSet(Name, Vec<ExprId>, Vec<Name>, ExprId),
    StoragePathUpdate(Name, Vec<ExprId>, Vec<Name>, BinOp, ExprId),
    IndexFieldSet(Name, Vec<ExprId>, Name, ExprId),
    ForEach(Name, Name, Vec<StmtId>),
    Match(ExprId, Vec<(Name, Name, Vec<StmtId>)>),
    LetTuple(Vec<Name>, ExprId),
    Expr(ExprId),
    RevertError(Name, Vec<ExprId>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub name: Name,
    pub fields: Vec<(Name, TypeId, bool)>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorDef {
    pub name: Name,
    pub code: i64,
    pub message: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refinement {
    Gt(Name, i64),
    Ge(Name, i64),
    Lt(Name, i64),
    Le(Name, i64),
    Neq(Name, i64),
    NonZero(Name),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Param {
    pub name: Name,
    pub typ: TypeId,
    pub refine: Option<Refinement>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    StorageWrite,
    StorageRead,
    Emit,
    Transfer,
    Call,
    Revert,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Function {
    pub name: Name,
    pub params: Vec<Param>,
    pub ret: TypeId,
    pub view: bool,
    pub pure: bool,
    pub payable: bool,
    pub nonreentrant: bool,
    pub visibility: Visibility,
    pub body: Vec<StmtId>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormMark {
    pub atom: Atom,
    pub target: Name,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limit {
    pub steps: BigInt,
    pub depth: BigInt,
    pub work: BigInt,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Form {
    pub name: Name,
    pub params: Vec<Binding>,
    pub ret: TypeId,
    pub mult: Mult,
    pub marks: Vec<FormMark>,
    pub limit: Option<Limit>,
    pub body: ExprId,
    pub public: bool,
    pub line: usize,
    pub column: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateField {
    pub name: Name,
    pub typ: TypeId,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Const {
    pub name: Name,
    pub typ: TypeId,
    pub value: ExprId,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invariant {
    pub name: Name,
    pub expr: ExprId,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Struct {
    pub name: Name,
    pub fields: Vec<(Name, TypeId)>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enum {
    pub name: Name,
    pub variants: Vec<Name>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Import {
    pub names: Vec<Name>,
    pub path: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceMethod {
    pub name: Name,
    pub params: Vec<Param>,
    pub ret: TypeId,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    pub name: Name,
    pub methods: Vec<InterfaceMethod>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contract {
    pub declaration: Declaration,
    pub name: Name,
    pub imports: Vec<Import>,
    pub structs: Vec<Struct>,
    pub enums: Vec<Enum>,
    pub consts: Vec<Const>,
    pub invariants: Vec<Invariant>,
    pub state: Vec<StateField>,
    pub events: Vec<Event>,
    pub errors: Vec<ErrorDef>,
    pub interfaces: Vec<Interface>,
    pub implements: Vec<Name>,
    pub constructor: Option<Function>,
    pub functions: Vec<Function>,
    pub forms: Vec<Form>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Nodes {
    types: Vec<Type>,
    interned: BTreeMap<Type, TypeId>,
    expressions: Vec<Expr>,
    statements: Vec<Stmt>,
}
impl Nodes {
    pub(crate) fn type_arena(&self) -> Self {
        Self {
            types: self.types.clone(),
            interned: self.interned.clone(),
            expressions: vec![],
            statements: vec![],
        }
    }
    pub(crate) fn statements(&self) -> impl Iterator<Item = (StmtId, &Stmt)> {
        self.statements
            .iter()
            .enumerate()
            .map(|(index, stmt)| (StmtId(index), stmt))
    }
    pub fn typ(&self, id: TypeId) -> &Type {
        &self.types[id.0]
    }
    pub fn expression(&self, id: ExprId) -> &Expr {
        &self.expressions[id.0]
    }
    pub fn statement(&self, id: StmtId) -> &Stmt {
        &self.statements[id.0]
    }
    pub(crate) fn intern(&mut self, typ: Type) -> TypeId {
        if let Some(id) = self.interned.get(&typ) {
            return *id;
        }
        let id = TypeId(self.types.len());
        self.types.push(typ.clone());
        self.interned.insert(typ, id);
        id
    }
    pub(crate) fn expr(&mut self, expr: Expr) -> ExprId {
        let id = ExprId(self.expressions.len());
        self.expressions.push(expr);
        id
    }
    pub(crate) fn stmt(&mut self, stmt: Stmt) -> StmtId {
        let id = StmtId(self.statements.len());
        self.statements.push(stmt);
        id
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ast {
    pub contract: Contract,
    pub nodes: Nodes,
}

impl Expr {
    pub(crate) fn map_exprs(&mut self, map: &mut impl FnMut(ExprId) -> ExprId) {
        let mut one = |id: &mut ExprId| *id = map(*id);
        match self {
            Self::Index(_, items)
            | Self::Call(_, items)
            | Self::Array(items)
            | Self::Tuple(items)
            | Self::StoragePath(_, items, _)
            | Self::IndexField(_, items, _) => items.iter_mut().for_each(one),
            Self::Binop(_, left, right)
            | Self::Equal(_, left, right)
            | Self::Let(_, left, right) => {
                one(left);
                one(right);
            }
            Self::Unop(_, value) | Self::Balance(value) | Self::Action(_, value) => one(value),
            Self::Ternary(cond, yes, no) => {
                one(cond);
                one(yes);
                one(no);
            }
            Self::Split(value, _, _, body) => {
                one(value);
                one(body);
            }
            Self::Orbit(_, turns, seed, _, body) => {
                if let Some(turns) = turns {
                    one(turns);
                }
                one(seed);
                one(body);
            }
            Self::Use(value) => {
                value.caps.iter_mut().for_each(&mut one);
                one(&mut value.arg);
                one(&mut value.body);
            }
            _ => (),
        }
    }
    pub(crate) fn map_types(&mut self, map: &mut impl FnMut(TypeId) -> TypeId) {
        match self {
            Self::Equal(typ, ..) => *typ = map(*typ),
            Self::Let(binding, ..) | Self::Orbit(_, _, _, binding, _) => {
                binding.typ = map(binding.typ);
            }
            Self::Split(_, left, right, _) => {
                left.typ = map(left.typ);
                right.typ = map(right.typ);
            }
            Self::Use(value) => value.binding.typ = map(value.binding.typ),
            _ => (),
        }
    }
}
impl Stmt {
    pub(crate) fn map_exprs(&mut self, map: &mut impl FnMut(ExprId) -> ExprId) {
        let mut one = |id: &mut ExprId| *id = map(*id);
        match self {
            Self::IndexSet(_, keys, value)
            | Self::IndexUpdate(_, keys, _, value)
            | Self::StoragePathSet(_, keys, _, value)
            | Self::StoragePathUpdate(_, keys, _, _, value)
            | Self::IndexFieldSet(_, keys, _, value) => {
                keys.iter_mut().for_each(&mut one);
                one(value);
            }
            Self::Return(value) => {
                if let Some(value) = value {
                    one(value);
                }
            }
            Self::Require(cond, message) => {
                one(cond);
                one(message);
            }
            Self::Emit(_, values)
            | Self::FieldCall(_, _, values)
            | Self::RevertError(_, values) => values.iter_mut().for_each(one),
            Self::For(_, first, last, _) => {
                one(first);
                one(last);
            }
            Self::Let(_, _, value)
            | Self::Assign(_, value)
            | Self::FieldSet(_, value)
            | Self::Assert(value)
            | Self::Expr(value)
            | Self::Match(value, _)
            | Self::If(value, _, _)
            | Self::While(value, _)
            | Self::LetTuple(_, value) => one(value),
            Self::Located(..) | Self::ForEach(..) => (),
        }
    }
    pub(crate) fn blocks(&mut self, map: &mut impl FnMut(&mut Vec<StmtId>)) {
        match self {
            Self::If(_, yes, no) => {
                map(yes);
                if let Some(no) = no {
                    map(no);
                }
            }
            Self::While(_, body) | Self::For(_, _, _, body) | Self::ForEach(_, _, body) => {
                map(body);
            }
            Self::Match(_, arms) => {
                for (_, _, body) in arms {
                    map(body);
                }
            }
            _ => (),
        }
    }
}
