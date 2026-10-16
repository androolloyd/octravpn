// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Byte-string Oct_lex tokens, locations and lazy newline-skipping stream.
use num_bigint::BigInt;

pub use super::limits::PARSER_DEPTH as MAX_DEPTH;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Word {
    Program,
    Contract,
    State,
    Event,
    Constructor,
    Fn,
    View,
    Pure,
    Let,
    Return,
    Assert,
    Emit,
    If,
    Else,
    While,
    Self_,
    Caller,
    Origin,
    Epoch,
    EpochTime,
    Value,
    Balance,
    True,
    False,
    Int,
    Bool,
    String,
    Address,
    Bytes,
    Bytes32,
    U64,
    U128,
    U256,
    Uint,
    Cipher,
    PubKey,
    Map,
    TreeHash,
    NodeId,
    TxHash,
    For,
    In,
    List,
    Const,
    Require,
    Struct,
    Enum,
    Match,
    SelfAddr,
    Public,
    Private,
    Internal,
    Payable,
    Error,
    Revert,
    Where,
    Option,
    None_,
    Some_,
    Unwrap,
    IsSome,
    Interface,
    Implements,
    Import,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Symbol {
    LBrace,
    RBrace,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Colon,
    Comma,
    Dot,
    DotDot,
    Eq,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    EqEq,
    BangEq,
    Lt,
    Gt,
    LtEq,
    GtEq,
    And,
    Or,
    Bang,
    PlusEq,
    MinusEq,
    StarEq,
    SlashEq,
    FatArrow,
    Question,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    Word(Word),
    Symbol(Symbol),
    Ident(Vec<u8>),
    Integer(BigInt),
    String(Vec<u8>),
    Newline,
    Eof,
}
impl Token {
    pub fn identifier(&self) -> Option<&[u8]> {
        match self {
            Self::Ident(raw) => Some(raw),
            Self::Word(Word::Value) => Some(b"value"),
            Self::Word(Word::Epoch) => Some(b"epoch"),
            Self::Word(Word::EpochTime) => Some(b"epoch_time"),
            Self::Word(Word::Balance) => Some(b"balance"),
            _ => None,
        }
    }
    fn expected(&self) -> &[u8] {
        match self {
            Self::Symbol(Symbol::LBrace) => b"{",
            Self::Symbol(Symbol::RBrace) => b"}",
            Self::Symbol(Symbol::LParen) => b"(",
            Self::Symbol(Symbol::RParen) => b")",
            Self::Symbol(Symbol::LBracket) => b"[",
            Self::Symbol(Symbol::RBracket) => b"]",
            Self::Symbol(Symbol::Colon) => b":",
            Self::Symbol(Symbol::Comma) => b",",
            Self::Symbol(Symbol::Eq) => b"=",
            Self::Symbol(Symbol::Dot) => b".",
            Self::Symbol(Symbol::DotDot) => b"..",
            Self::Symbol(Symbol::FatArrow) => b"=>",
            Self::Word(Word::In) => b"in",
            _ => b"token",
        }
    }
    fn found(&self) -> Vec<u8> {
        match self {
            Self::Ident(raw) => raw.clone(),
            Self::Integer(number) => number.to_string().into_bytes(),
            Self::String(raw) => [b"\"".as_slice(), raw, b"\""].concat(),
            Self::Eof => b"EOF".to_vec(),
            Self::Newline => b"newline".to_vec(),
            _ => b"token".to_vec(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub message: Vec<u8>,
    pub line: usize,
    pub column: usize,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} at {}:{}",
            String::from_utf8_lossy(&self.message),
            self.line,
            self.column
        )
    }
}
impl std::error::Error for Error {}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Located {
    pub token: Token,
    pub line: usize,
    pub column: usize,
}
pub struct Lexer<'a> {
    prior: bool,
    source: &'a [u8],
    at: usize,
    line: usize,
    column: usize,
    depth: usize,
}
impl<'a> Lexer<'a> {
    pub fn new(source: &'a [u8]) -> Self {
        Self {
            prior: false,
            source,
            at: 0,
            line: 1,
            column: 1,
            depth: 0,
        }
    }
    fn peek(&self) -> Option<u8> {
        self.source.get(self.at).copied()
    }
    fn advance(&mut self) {
        if let Some(byte) = self.peek() {
            if byte == b'\n' {
                self.line += 1;
                self.column = 1;
            } else {
                self.column += 1;
            }
            self.at += 1;
        }
    }
    fn error(&self, message: impl AsRef<[u8]>) -> Error {
        Error {
            message: message.as_ref().to_vec(),
            line: self.line,
            column: self.column,
        }
    }
    fn paired(&mut self, next: u8, yes: Symbol, no: Symbol) -> Symbol {
        self.advance();
        if self.peek() == Some(next) {
            self.advance();
            yes
        } else {
            no
        }
    }
    fn comment(&mut self) -> Result<(), Error> {
        self.advance();
        self.advance();
        let mut depth = 1usize;
        while let Some(byte) = self.peek() {
            self.advance();
            match (byte, self.peek()) {
                (b'*', Some(b'/')) => {
                    self.advance();
                    depth -= 1;
                    if depth == 0 {
                        return Ok(());
                    }
                }
                (b'/', Some(b'*')) => {
                    self.advance();
                    depth += 1;
                }
                _ => (),
            }
        }
        Err(self.error(if self.prior {
            "unterminated block comment"
        } else {
            "comment is not closed"
        }))
    }
    fn string(&mut self) -> Result<Vec<u8>, Error> {
        self.advance();
        let mut out = Vec::new();
        loop {
            match self.peek() {
                None => return Err(self.error("unterminated string")),
                Some(b'"') => {
                    self.advance();
                    return Ok(out);
                }
                Some(0) if !self.prior => {
                    return Err(self.error("NUL byte is not allowed in string"))
                }
                Some(b'\\') => {
                    self.advance();
                    let byte = match self.peek() {
                        Some(b'n') => b'\n',
                        Some(b't') => b'\t',
                        Some(b'\\') => b'\\',
                        Some(b'"') => b'"',
                        _ => return Err(self.error("invalid escape")),
                    };
                    out.push(byte);
                    self.advance();
                }
                Some(byte) => {
                    out.push(byte);
                    self.advance();
                }
            }
        }
    }
    pub fn next_token(&mut self) -> Result<Located, Error> {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r')) {
            self.advance();
        }
        let (line, column) = (self.line, self.column);
        let token = match self.peek() {
            None => Token::Eof,
            Some(b'\n') => {
                self.advance();
                Token::Newline
            }
            Some(b'/') if self.source.get(self.at + 1) == Some(&b'/') => {
                while !matches!(self.peek(), None | Some(b'\n')) {
                    self.advance();
                }
                Token::Newline
            }
            Some(b'/') if self.source.get(self.at + 1) == Some(&b'*') => {
                self.comment()?;
                Token::Newline
            }
            Some(b'"') => Token::String(self.string()?),
            Some(byte) if byte.is_ascii_digit() => {
                let mut digits = Vec::new();
                while let Some(byte) = self
                    .peek()
                    .filter(|byte| byte.is_ascii_digit() || *byte == b'_')
                {
                    if byte != b'_' {
                        digits.push(byte);
                    }
                    self.advance();
                }
                Token::Integer(BigInt::parse_bytes(&digits, 10).expect("nonempty decimal digits"))
            }
            Some(byte) if alpha(byte) => {
                let start = self.at;
                while self
                    .peek()
                    .is_some_and(|byte| alpha(byte) || byte.is_ascii_digit())
                {
                    self.advance();
                }
                let raw = &self.source[start..self.at];
                let word = keyword(raw).map(|word| {
                    if self.prior && word == Word::Uint {
                        Word::U256
                    } else {
                        word
                    }
                });
                word.map_or_else(|| Token::Ident(raw.to_vec()), Token::Word)
            }
            Some(byte @ (b'{' | b'(' | b'[')) => {
                self.depth += 1;
                if self.depth > MAX_DEPTH {
                    return Err(self.error("syntax nesting exceeds limit"));
                }
                self.advance();
                Token::Symbol(match byte {
                    b'{' => Symbol::LBrace,
                    b'(' => Symbol::LParen,
                    _ => Symbol::LBracket,
                })
            }
            Some(byte @ (b'}' | b')' | b']')) => {
                self.depth = self.depth.saturating_sub(1);
                self.advance();
                Token::Symbol(match byte {
                    b'}' => Symbol::RBrace,
                    b')' => Symbol::RParen,
                    _ => Symbol::RBracket,
                })
            }
            Some(byte) => Token::Symbol(match byte {
                b':' => {
                    self.advance();
                    Symbol::Colon
                }
                b',' => {
                    self.advance();
                    Symbol::Comma
                }
                b'%' => {
                    self.advance();
                    Symbol::Percent
                }
                b'?' => {
                    self.advance();
                    Symbol::Question
                }
                b'.' => self.paired(b'.', Symbol::DotDot, Symbol::Dot),
                b'+' => self.paired(b'=', Symbol::PlusEq, Symbol::Plus),
                b'-' => self.paired(b'=', Symbol::MinusEq, Symbol::Minus),
                b'*' => self.paired(b'=', Symbol::StarEq, Symbol::Star),
                b'/' => self.paired(b'=', Symbol::SlashEq, Symbol::Slash),
                b'!' => self.paired(b'=', Symbol::BangEq, Symbol::Bang),
                b'<' => self.paired(b'=', Symbol::LtEq, Symbol::Lt),
                b'>' => self.paired(b'=', Symbol::GtEq, Symbol::Gt),
                b'=' => {
                    self.advance();
                    match self.peek() {
                        Some(b'=') => {
                            self.advance();
                            Symbol::EqEq
                        }
                        Some(b'>') => {
                            self.advance();
                            Symbol::FatArrow
                        }
                        _ => Symbol::Eq,
                    }
                }
                b'&' | b'|' => {
                    self.advance();
                    if self.peek() != Some(byte) {
                        return Err(self.error(if byte == b'&' {
                            "expected &&"
                        } else {
                            "expected ||"
                        }));
                    }
                    self.advance();
                    if byte == b'&' {
                        Symbol::And
                    } else {
                        Symbol::Or
                    }
                }
                byte if byte > 127 => {
                    if self.prior {
                        self.advance();
                    }
                    return Err(self.error(format!("unexpected character: 0x{byte:02X}")));
                }
                byte => {
                    return Err(self.error([b"unexpected character: ".as_slice(), &[byte]].concat()))
                }
            }),
        };
        Ok(Located {
            token,
            line,
            column,
        })
    }
}
fn alpha(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}
fn keyword(raw: &[u8]) -> Option<Word> {
    Some(match raw {
        b"program" => Word::Program,
        b"contract" => Word::Contract,
        b"state" => Word::State,
        b"event" => Word::Event,
        b"constructor" => Word::Constructor,
        b"fn" => Word::Fn,
        b"view" => Word::View,
        b"pure" => Word::Pure,
        b"let" => Word::Let,
        b"return" => Word::Return,
        b"assert" => Word::Assert,
        b"emit" => Word::Emit,
        b"if" => Word::If,
        b"else" => Word::Else,
        b"while" => Word::While,
        b"self" => Word::Self_,
        b"caller" => Word::Caller,
        b"origin" => Word::Origin,
        b"epoch" => Word::Epoch,
        b"epoch_time" => Word::EpochTime,
        b"value" => Word::Value,
        b"balance" => Word::Balance,
        b"true" => Word::True,
        b"false" => Word::False,
        b"int" => Word::Int,
        b"bool" => Word::Bool,
        b"string" => Word::String,
        b"address" => Word::Address,
        b"bytes" => Word::Bytes,
        b"bytes32" => Word::Bytes32,
        b"u64" => Word::U64,
        b"u128" => Word::U128,
        b"u256" => Word::U256,
        b"uint" => Word::Uint,
        b"cipher" => Word::Cipher,
        b"pubkey" => Word::PubKey,
        b"map" => Word::Map,
        b"tree_hash" => Word::TreeHash,
        b"node_id" => Word::NodeId,
        b"tx_hash" => Word::TxHash,
        b"for" => Word::For,
        b"in" => Word::In,
        b"list" => Word::List,
        b"const" => Word::Const,
        b"require" => Word::Require,
        b"struct" => Word::Struct,
        b"enum" => Word::Enum,
        b"match" => Word::Match,
        b"self_addr" => Word::SelfAddr,
        b"public" => Word::Public,
        b"private" => Word::Private,
        b"internal" => Word::Internal,
        b"payable" => Word::Payable,
        b"error" => Word::Error,
        b"revert" => Word::Revert,
        b"where" => Word::Where,
        b"Option" | b"option" => Word::Option,
        b"None" | b"none" => Word::None_,
        b"Some" | b"some" => Word::Some_,
        b"unwrap" => Word::Unwrap,
        b"is_some" => Word::IsSome,
        b"interface" => Word::Interface,
        b"implements" => Word::Implements,
        b"import" => Word::Import,
        _ => return None,
    })
}

pub struct Stream<'a> {
    lexer: Lexer<'a>,
    current: Option<Located>,
    location: (usize, usize),
}
impl<'a> Stream<'a> {
    pub(crate) fn prior(source: &'a [u8]) -> Self {
        let mut stream = Self::new(source);
        stream.lexer.prior = true;
        stream
    }
    pub fn new(source: &'a [u8]) -> Self {
        Self {
            lexer: Lexer::new(source),
            current: None,
            location: (1, 1),
        }
    }
    pub fn peek(&mut self) -> Result<&Token, Error> {
        if self.current.is_none() {
            loop {
                let next = self.lexer.next_token()?;
                if next.token != Token::Newline {
                    self.location = (next.line, next.column);
                    self.current = Some(next);
                    break;
                }
            }
        }
        Ok(&self.current.as_ref().expect("stream has a token").token)
    }
    pub fn eat(&mut self) {
        self.current = None;
    }
    pub fn location(&self) -> (usize, usize) {
        if self.lexer.prior {
            (self.lexer.line, self.lexer.column)
        } else {
            self.location
        }
    }
    pub fn expect(&mut self, token: &Token) -> Result<(), Error> {
        let got = self.peek()?;
        if got != token {
            let message = [
                b"expected ".as_slice(),
                token.expected(),
                b", got ",
                &got.found(),
            ]
            .concat();
            let (line, column) = self.location();
            return Err(Error {
                message,
                line,
                column,
            });
        }
        self.eat();
        Ok(())
    }
}
