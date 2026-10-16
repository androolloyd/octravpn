// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_feed's typed value grammar; explicit tasks avoid recursive parsing stacks.
use super::super::{
    eval::Value,
    field::Field as Element,
    lexer::{self, Form, Item, Span, Symbol as S, Token, Word as W},
    types::Type,
};
use super::{Error, Feed, Natural, Result, Spec, TypeId, Types, ValueId, Values};
use num_bigint::BigInt;
struct Parser<'a> {
    items: Vec<Item>,
    at: usize,
    types: &'a Types,
    values: &'a mut Values,
}
struct Sequence {
    capacity: Natural,
    elem: TypeId,
    typ: TypeId,
    span: Span,
    items: Vec<ValueId>,
}
struct Vector {
    elem: TypeId,
    count: usize,
    items: Vec<ValueId>,
}
enum Task {
    Value(TypeId),
    Need(Form),
    Pair,
    Wrap(bool),
    Vector(Vector),
    VectorItem(Vector),
    Sequence(Sequence),
    SequenceItem(Sequence),
}
impl Parser<'_> {
    fn item(&self) -> &Item {
        &self.items[self.at]
    }
    fn need(&mut self, wanted: Form) -> Result<()> {
        let actual = self.item().token.form();
        if actual != wanted {
            return Err(Error::Need(wanted, actual, self.item().span));
        }
        self.at += 1;
        Ok(())
    }
    fn symbol(&mut self, symbol: S) -> Result<()> {
        self.need(Form::Symbol(symbol))
    }
    fn word(&mut self, wanted: &[u8]) -> Result<()> {
        if matches!(&self.item().token, Token::Ident(name) if name == wanted) {
            self.at += 1;
            Ok(())
        } else {
            Err(Error::Need(
                Form::Ident,
                self.item().token.form(),
                self.item().span,
            ))
        }
    }
    fn natural(&mut self) -> Result<Natural> {
        let Token::Natural(value) = &self.item().token else {
            return Err(Error::Need(
                Form::Natural,
                self.item().token.form(),
                self.item().span,
            ));
        };
        let value =
            Natural::new(value).ok_or_else(|| Error::Natural(value.clone(), self.item().span))?;
        self.at += 1;
        Ok(value)
    }
    fn integer(&mut self) -> Result<BigInt> {
        let negative = self.item().token == Token::Symbol(S::Minus);
        if negative {
            self.at += 1;
        }
        let Token::Natural(value) = &self.item().token else {
            return Err(Error::Need(
                Form::Natural,
                self.item().token.form(),
                self.item().span,
            ));
        };
        let value = if negative { -value } else { value.clone() };
        self.at += 1;
        Ok(value)
    }
    fn different(typ: TypeId, span: Span) -> Error {
        Error::Type(b"value".to_vec(), typ, span)
    }
    // Keep the native owned-input interface and its diagnostic/arena ownership.
    #[allow(clippy::needless_pass_by_value)]
    fn finish_sequence(&mut self, sequence: Sequence) -> Result<ValueId> {
        let empty = self
            .values
            .zero(self.types, sequence.elem)
            .ok_or_else(|| Self::different(sequence.typ, sequence.span))?;
        let count = sequence.items.len();
        let mut full = vec![empty; sequence.capacity.get() as usize];
        full[..count].copy_from_slice(&sequence.items);
        let length = self.values.integer(count);
        let vector = self.values.push(Value::Vec(full.into()));
        Ok(self.values.push(Value::Pair(length, vector)))
    }
    fn value(&mut self, root: TypeId) -> Result<ValueId> {
        let mut pending = vec![Task::Value(root)];
        let mut out: Vec<ValueId> = vec![];
        while let Some(task) = pending.pop() {
            match task {
                Task::Value(typ) => {
                    let span = self.item().span;
                    match self.types.get(typ).clone() {
                        Type::Unit => {
                            self.need(Form::Word(W::Unit))?;
                            out.push(self.values.push(Value::Unit));
                        }
                        Type::Bool => {
                            let value = match self.item().token {
                                Token::Word(W::True) => true,
                                Token::Word(W::False) => false,
                                _ => return Err(Self::different(typ, span)),
                            };
                            self.at += 1;
                            out.push(self.values.push(Value::Bool(value)));
                        }
                        Type::Int => {
                            let value = self.integer()?;
                            out.push(self.values.integer(value));
                        }
                        Type::Num(..) => {
                            let value = self.integer()?;
                            if !self.types.admits(typ, &value) {
                                return Err(Self::different(typ, span));
                            }
                            out.push(self.values.integer(value));
                        }
                        Type::Bytes(length) => {
                            let Token::Hex(raw) = &self.item().token else {
                                return Err(Self::different(typ, span));
                            };
                            if raw.len() != length.get() as usize {
                                return Err(Self::different(typ, span));
                            }
                            let raw = raw.as_slice().into();
                            let value = self.values.push(Value::Bytes(raw));
                            self.at += 1;
                            out.push(value);
                        }
                        Type::Vec(length, elem) => {
                            self.need(Form::Word(W::Vec))?;
                            self.symbol(S::Lparen)?;
                            pending.push(Task::Vector(Vector {
                                elem,
                                count: length.get() as usize,
                                items: vec![],
                            }));
                        }
                        Type::Seq(capacity, elem) => {
                            self.need(Form::Word(W::Seq))?;
                            self.symbol(S::Lparen)?;
                            pending.push(Task::Sequence(Sequence {
                                capacity,
                                elem,
                                typ,
                                span,
                                items: vec![],
                            }));
                        }
                        Type::Cap(kind) => {
                            self.need(Form::Word(W::Cap))?;
                            self.symbol(S::Lbrack)?;
                            let actual = self.natural()?;
                            if kind != actual {
                                return Err(Self::different(typ, span));
                            }
                            self.symbol(S::Rbrack)?;
                            self.symbol(S::Lparen)?;
                            let id = self.natural()?;
                            self.symbol(S::Rparen)?;
                            out.push(self.values.push(Value::Cap(kind, id)));
                        }
                        Type::Enc(key, remaining) => {
                            self.word(b"enc")?;
                            self.symbol(S::Lbrack)?;
                            let actual_key = self.natural()?;
                            self.symbol(S::Comma)?;
                            let actual_remaining = self.natural()?;
                            if key != actual_key || remaining != actual_remaining {
                                return Err(Self::different(typ, span));
                            }
                            self.symbol(S::Rbrack)?;
                            self.symbol(S::Lparen)?;
                            let value = self.integer()?;
                            let field =
                                Element::new(value).ok_or_else(|| Self::different(typ, span))?;
                            self.symbol(S::Rparen)?;
                            out.push(self.values.push(Value::Enc(key, remaining, field)));
                        }
                        Type::Pair(left, right) => {
                            self.symbol(S::Lparen)?;
                            pending.push(Task::Pair);
                            pending.push(Task::Need(Form::Symbol(S::Rparen)));
                            pending.push(Task::Value(right));
                            pending.push(Task::Need(Form::Symbol(S::Comma)));
                            pending.push(Task::Value(left));
                        }
                        Type::Sum(left, right) => {
                            let (typ, left) = match self.item().token {
                                Token::Word(W::Good) => (left, true),
                                Token::Word(W::Bad) => (right, false),
                                _ => return Err(Self::different(typ, span)),
                            };
                            self.at += 1;
                            self.symbol(S::Lparen)?;
                            pending.push(Task::Wrap(left));
                            pending.push(Task::Need(Form::Symbol(S::Rparen)));
                            pending.push(Task::Value(typ));
                        }
                    }
                }
                Task::Need(form) => self.need(form)?,
                Task::Pair => {
                    let right = out.pop().expect("feed pair right");
                    let left = out.pop().expect("feed pair left");
                    out.push(self.values.push(Value::Pair(left, right)));
                }
                Task::Wrap(left) => {
                    let value = out.pop().expect("feed sum payload");
                    out.push(self.values.push(if left {
                        Value::Inl(value)
                    } else {
                        Value::Inr(value)
                    }));
                }
                Task::Vector(vector) => {
                    if vector.items.len() == vector.count {
                        self.symbol(S::Rparen)?;
                        out.push(self.values.push(Value::Vec(vector.items.into())));
                    } else {
                        if !vector.items.is_empty() {
                            self.symbol(S::Comma)?;
                        }
                        let elem = vector.elem;
                        pending.push(Task::VectorItem(vector));
                        pending.push(Task::Value(elem));
                    }
                }
                Task::VectorItem(mut vector) => {
                    vector.items.push(out.pop().expect("feed vector item"));
                    pending.push(Task::Vector(vector));
                }
                Task::Sequence(sequence) => {
                    if self.item().token == Token::Symbol(S::Rparen) {
                        self.at += 1;
                        out.push(self.finish_sequence(sequence)?);
                    } else if sequence.items.len() == sequence.capacity.get() as usize {
                        return Err(Self::different(sequence.typ, sequence.span));
                    } else {
                        let elem = sequence.elem;
                        pending.push(Task::SequenceItem(sequence));
                        pending.push(Task::Value(elem));
                    }
                }
                Task::SequenceItem(mut sequence) => {
                    sequence.items.push(out.pop().expect("feed sequence item"));
                    match self.item().token {
                        Token::Symbol(S::Comma) => {
                            self.at += 1;
                            if self.item().token == Token::Symbol(S::Rparen) {
                                return Err(Self::different(sequence.typ, sequence.span));
                            }
                            pending.push(Task::Sequence(sequence));
                        }
                        Token::Symbol(S::Rparen) => {
                            self.at += 1;
                            out.push(self.finish_sequence(sequence)?);
                        }
                        _ => return Err(Self::different(sequence.typ, sequence.span)),
                    }
                }
            }
        }
        Ok(out.pop().expect("feed value root"))
    }
}
pub fn parse_value(
    types: &Types,
    values: &mut Values,
    typ: TypeId,
    source: &[u8],
) -> Result<ValueId> {
    let items = lexer::scan(source).map_err(Error::Lex)?;
    let mut parser = Parser {
        items,
        at: 0,
        types,
        values,
    };
    let value = parser.value(typ)?;
    parser.need(Form::Eof)?;
    parser.values.shape(&[value]).map_err(|_| Error::Form)?;
    Ok(value)
}
pub fn parse(types: &Types, values: &mut Values, specs: &[Spec], source: &[u8]) -> Result<Feed> {
    let items = lexer::scan(source).map_err(Error::Lex)?;
    let mut parser = Parser {
        items,
        at: 0,
        types,
        values,
    };
    parser.word(b"feed")?;
    parser.symbol(S::Lbrace)?;
    let mut out = Vec::with_capacity(specs.len());
    for (index, spec) in specs.iter().enumerate() {
        let Token::Ident(actual) = &parser.item().token else {
            return Err(Error::Need(
                Form::Ident,
                parser.item().token.form(),
                parser.item().span,
            ));
        };
        if actual != &spec.name {
            return Err(Error::Name(
                spec.name.clone(),
                actual.clone(),
                parser.item().span,
            ));
        }
        parser.at += 1;
        parser.symbol(S::Eq)?;
        out.push(parser.value(spec.typ)?);
        if index + 1 != specs.len() {
            parser.symbol(S::Comma)?;
        }
    }
    parser.symbol(S::Rbrace)?;
    parser.need(Form::Eof)?;
    Feed::make(parser.values, &out)
}
