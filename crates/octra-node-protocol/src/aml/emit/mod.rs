// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Adopted Oct_gen emission primitives. Emission does not confer admission.
use super::{
    ast::{BinOp, Type},
    source::{self, Syntax},
};
use crate::octb::{Instruction as I, Value as V};
use num_bigint::BigInt;
use std::sync::Arc;
mod builtins;
mod circle_builtins;
mod compatibility;
mod guards;
mod options;
mod records;
mod storage;
mod text;
pub use records::{BindingKind, Flag, PolicyKind, RecordKind};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Backend {
    Current,
    Protocol { checked: bool },
    Prior,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Failure(Vec<u8>),
    Invalid {
        message: Vec<u8>,
        line: usize,
        column: usize,
    },
    Unavailable(&'static str),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failure(reason) => write!(
                f,
                "{}",
                String::from_utf8_lossy(&crate::native_exception::string_argument(
                    b"Failure", reason
                ))
            ),
            Self::Invalid {
                message,
                line,
                column,
            } => write!(
                f,
                "{}",
                String::from_utf8_lossy(&source::diagnostic(
                    None,
                    *line as i64,
                    (*column > 0).then_some(*column as i64),
                    message
                ))
            ),
            Self::Unavailable(message) => f.write_str(message),
        }
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Position {
    pub line: usize,
    pub column: usize,
}

pub struct Emitter {
    backend: Backend,
    pub syntax: Syntax,
    pub position: Position,
    pub pure: bool,
    pub view: bool,
    pub base_reg: u32,
    pub next_reg: u32,
    pub next_label: u32,
    code: Vec<I>,
}
impl Emitter {
    pub fn new(syntax: Syntax) -> Self {
        Self {
            backend: Backend::Current,
            syntax,
            position: Position::default(),
            pure: false,
            view: false,
            base_reg: 1,
            next_reg: 1,
            next_label: 10_000,
            code: vec![],
        }
    }
    pub(crate) fn protocol(checked: bool) -> Self {
        Self {
            backend: Backend::Protocol { checked },
            ..Self::new(Syntax::Forms)
        }
    }
    pub(crate) fn prior() -> Self {
        Self {
            backend: Backend::Prior,
            ..Self::new(Syntax::Forms)
        }
    }
    pub(crate) fn is_prior(&self) -> bool {
        self.backend == Backend::Prior
    }
    pub(crate) fn protocol_checked(&self) -> Option<bool> {
        match self.backend {
            Backend::Current => None,
            Backend::Protocol { checked } => Some(checked),
            Backend::Prior => Some(false),
        }
    }
    pub(crate) fn is_protocol(&self) -> bool {
        self.protocol_checked().is_some()
    }
    pub fn instructions(&self) -> &[I] {
        &self.code
    }
    pub fn into_instructions(self) -> Vec<I> {
        self.code
    }
    pub fn error(&self, message: impl AsRef<[u8]>) -> Error {
        Error::Invalid {
            message: message.as_ref().to_vec(),
            line: self.position.line,
            column: usize::from(!self.is_protocol()),
        }
    }
    pub fn located_error(&self, message: impl AsRef<[u8]>) -> Error {
        Error::Invalid {
            message: message.as_ref().to_vec(),
            line: self.position.line,
            column: if self.is_protocol() {
                0
            } else {
                self.position.column
            },
        }
    }
    pub fn alloc_reg(&mut self) -> Result<u8> {
        if self.next_reg > 63 {
            return Err(self.error(if self.is_protocol() {
                "too many local variables (max 63 registers)"
            } else {
                "register capacity exceeded maximum = 64"
            }));
        }
        let reg = self.next_reg as u8;
        self.next_reg += 1;
        Ok(reg)
    }
    pub fn reserve_local(&mut self) -> Result<u8> {
        if self.base_reg > 63 {
            return Err(self.error(if self.is_protocol() {
                "too many local variables (max 63 registers)"
            } else {
                "register capacity exceeded maximum = 64"
            }));
        }
        let reg = self.base_reg as u8;
        self.base_reg += 1;
        self.next_reg = self.base_reg;
        Ok(reg)
    }
    pub fn alloc_label(&mut self) -> Result<u32> {
        let label = self.next_label;
        self.next_label = label
            .checked_add(1)
            .ok_or(Error::Unavailable("compiler label transport exhausted"))?;
        Ok(label)
    }
    pub fn emit(&mut self, instruction: I) -> Result<()> {
        self.code
            .try_reserve(1)
            .map_err(|_| Error::Unavailable("compiler instruction allocation failed"))?;
        self.code.push(instruction);
        Ok(())
    }
    pub fn integer(&mut self, register: u8, value: impl Into<BigInt>) -> Result<()> {
        self.emit(I::Ldi(register, Arc::new(V::Int(Arc::new(value.into())))))
    }
    pub fn boolean(&mut self, register: u8, value: bool) -> Result<()> {
        self.emit(I::Ldi(register, Arc::new(V::Bool(value))))
    }
    pub fn string(&mut self, register: u8, value: impl AsRef<[u8]>) -> Result<()> {
        self.emit(I::Ldi(
            register,
            Arc::new(V::Str(Arc::from(value.as_ref()))),
        ))
    }
    pub fn storage_write(&self) -> Result<()> {
        if self.pure {
            Err(self.error("pure function cannot write storage"))
        } else if self.view {
            Err(self.error("view function cannot write storage"))
        } else {
            Ok(())
        }
    }
    pub fn event(&self) -> Result<()> {
        if self.pure {
            Err(self.error("pure function cannot emit events"))
        } else {
            Ok(())
        }
    }
    pub fn transfer(&self) -> Result<()> {
        if self.pure {
            Err(self.error("pure function cannot transfer"))
        } else if self.view {
            Err(self.error("view function cannot transfer"))
        } else {
            Ok(())
        }
    }
    pub fn external_call(&self) -> Result<()> {
        if self.pure {
            Err(self.error("pure function cannot call external contracts"))
        } else {
            Ok(())
        }
    }
    pub fn pure_while(&self) -> Result<()> {
        if self.pure {
            Err(self.error(if self.is_prior() {
                "pure function cannot use while loops (use for..in with bounded range)"
            } else {
                "pure function cannot use while loops (use for..in with finite range)"
            }))
        } else {
            Ok(())
        }
    }
}
pub fn internal_key(family: &[u8], name: &[u8]) -> Vec<u8> {
    [b"@aml/".as_slice(), family, b"/", name].concat()
}
pub fn list_length_key(field: &[u8]) -> Vec<u8> {
    [internal_key(b"list", field), b"/length".to_vec()].concat()
}
pub fn list_item_prefix(field: &[u8]) -> Vec<u8> {
    [internal_key(b"list", field), b"/item/".to_vec()].concat()
}
pub fn option_presence_key(field: &[u8]) -> Vec<u8> {
    [internal_key(b"option", field), b"/present".to_vec()].concat()
}
pub fn nonreentrant_key() -> Vec<u8> {
    internal_key(b"guard", b"nonreentrant")
}
