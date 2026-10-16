// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Product association and native source ABI type syntax, using explicit frames.
use super::{Name, Parser, Result, Type, TypeId, S, T, W};
enum Task {
    Product,
    Base,
    Value(TypeId, bool),
}
enum Frame {
    Product,
    Right(TypeId),
    MapKey,
    MapValue(TypeId),
    Wrapped(W),
    ParenFirst,
    ParenMore(Vec<TypeId>),
    Invalid(Name),
}
impl Parser<'_> {
    pub(super) fn typ(&mut self) -> Result<TypeId> {
        let mut frames = vec![];
        let mut task = if self.prior {
            Task::Base
        } else {
            Task::Product
        };
        loop {
            task = match task {
                Task::Product => {
                    frames.push(Frame::Product);
                    Task::Base
                }
                Task::Base => match self.token()? {
                    T::Word(
                        word @ (W::Int
                        | W::Bool
                        | W::String
                        | W::Address
                        | W::Bytes32
                        | W::U64
                        | W::U128
                        | W::U256
                        | W::Cipher
                        | W::PubKey),
                    ) => {
                        self.eat();
                        let typ = match word {
                            W::Int => Type::Int,
                            W::Bool => Type::Bool,
                            W::String => Type::String,
                            W::Address => Type::Address,
                            W::Bytes32 => Type::Bytes32,
                            W::U64 => Type::U64,
                            W::U128 => Type::U128,
                            W::U256 => Type::U256,
                            W::Cipher => Type::Cipher,
                            W::PubKey => Type::PubKey,
                            _ => unreachable!(),
                        };
                        Task::Value(self.nodes.intern(typ), false)
                    }
                    T::Word(W::Bytes | W::Uint) => {
                        let bytes = self.is(T::Word(W::Bytes))?;
                        self.eat();
                        let typ = if !self.prior && self.is(T::Symbol(S::LBracket))? {
                            self.eat();
                            let width = self.natural(if bytes {
                                b"expected bytes width"
                            } else {
                                b"expected uint width"
                            })?;
                            self.expect(T::Symbol(S::RBracket))?;
                            match (bytes, width.get()) {
                                (true, 32) => Type::Bytes32,
                                (false, 64) => Type::U64,
                                (false, 128) => Type::U128,
                                (false, 256) => Type::U256,
                                (true, _) => {
                                    return Err(self.error("sized bytes type has no public ABI"))
                                }
                                _ => return Err(self.error("uint width has no public ABI")),
                            }
                        } else if bytes {
                            Type::Bytes
                        } else {
                            Type::U256
                        };
                        Task::Value(self.nodes.intern(typ), false)
                    }
                    T::Word(W::Map) => {
                        self.eat();
                        self.expect(T::Symbol(S::LBracket))?;
                        frames.push(Frame::MapKey);
                        if self.prior {
                            Task::Base
                        } else {
                            Task::Product
                        }
                    }
                    T::Word(word @ (W::List | W::Option)) => {
                        self.eat();
                        self.expect(T::Symbol(S::LBracket))?;
                        frames.push(Frame::Wrapped(word));
                        if self.prior {
                            Task::Base
                        } else {
                            Task::Product
                        }
                    }
                    T::Symbol(S::LParen) => {
                        self.eat();
                        frames.push(Frame::ParenFirst);
                        if self.prior {
                            Task::Base
                        } else {
                            Task::Product
                        }
                    }
                    T::Ident(name) => {
                        self.eat();
                        if !self.prior
                            && matches!(name.as_slice(), b"sint" | b"vec" | b"seq")
                            && self.is(T::Symbol(S::LBracket))?
                        {
                            self.eat();
                            self.natural(
                                &[
                                    b"expected ".as_slice(),
                                    &name,
                                    if name == b"sint" { b" width" } else { b" size" },
                                ]
                                .concat(),
                            )?;
                            if name == b"sint" {
                                self.expect(T::Symbol(S::RBracket))?;
                                return Err(self.error("sint type has no public ABI"));
                            }
                            self.expect(T::Symbol(S::Comma))?;
                            frames.push(Frame::Invalid(name));
                            if self.prior {
                                Task::Base
                            } else {
                                Task::Product
                            }
                        } else {
                            Task::Value(self.nodes.intern(Type::Struct(name)), false)
                        }
                    }
                    _ => return Err(self.error("expected type")),
                },
                Task::Value(value, paired) => match frames.pop() {
                    None => return Ok(value),
                    Some(Frame::Product) => {
                        if self.is(T::Symbol(S::Star))? {
                            self.eat();
                            frames.push(Frame::Right(value));
                            Task::Product
                        } else {
                            Task::Value(value, false)
                        }
                    }
                    Some(Frame::Right(left)) => {
                        Task::Value(self.nodes.intern(Type::Tuple(vec![left, value])), true)
                    }
                    Some(Frame::MapKey) => {
                        self.expect(T::Symbol(S::RBracket))?;
                        frames.push(Frame::MapValue(value));
                        Task::Base
                    }
                    Some(Frame::MapValue(key)) => {
                        Task::Value(self.nodes.intern(Type::Map(key, value)), false)
                    }
                    Some(Frame::Wrapped(word)) => {
                        self.expect(T::Symbol(S::RBracket))?;
                        Task::Value(
                            self.nodes.intern(if word == W::List {
                                Type::List(value)
                            } else {
                                Type::Option(value)
                            }),
                            false,
                        )
                    }
                    Some(Frame::ParenFirst) => match self.token()? {
                        T::Symbol(S::Comma) => {
                            self.eat();
                            frames.push(Frame::ParenMore(vec![value]));
                            if self.prior {
                                Task::Base
                            } else {
                                Task::Product
                            }
                        }
                        T::Symbol(S::RParen) => {
                            self.eat();
                            Task::Value(
                                if paired {
                                    value
                                } else {
                                    self.nodes.intern(Type::Tuple(vec![value]))
                                },
                                false,
                            )
                        }
                        _ => return Err(self.error("expected , or ) in tuple type")),
                    },
                    Some(Frame::ParenMore(mut items)) => {
                        items.push(value);
                        match self.token()? {
                            T::Symbol(S::Comma) => {
                                self.eat();
                                frames.push(Frame::ParenMore(items));
                                if self.prior {
                                    Task::Base
                                } else {
                                    Task::Product
                                }
                            }
                            T::Symbol(S::RParen) => {
                                self.eat();
                                Task::Value(self.nodes.intern(Type::Tuple(items)), false)
                            }
                            _ => return Err(self.error("expected , or ) in tuple type")),
                        }
                    }
                    Some(Frame::Invalid(name)) => {
                        self.expect(T::Symbol(S::RBracket))?;
                        return Err(
                            self.error([name.as_slice(), b" type has no public ABI"].concat())
                        );
                    }
                },
            };
        }
    }
}
