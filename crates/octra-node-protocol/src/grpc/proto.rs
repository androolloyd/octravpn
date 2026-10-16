// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Hand-sized native unary protobuf schema; no JSON or UTF-8 normalization of
//! byte strings. Unknown fields are skipped and singular fields are last-wins.
use crate::{
    epoch_page,
    native_json::{Document, Value},
    transaction::json_string,
};

pub const HEALTH: &str = "/grpc.health.v1.Health/Check";
pub const STATUS: &str = "/octra.node.v1.Node/Status";
pub const ACCOUNT: &str = "/octra.node.v1.Node/Account";
pub const TRANSACTION: &str = "/octra.node.v1.Node/Transaction";
pub const EPOCH: &str = "/octra.node.v1.Node/Epoch";
pub const EPOCHS: &str = "/octra.node.v1.Node/Epochs";
pub const SUBMIT: &str = "/octra.node.v1.Node/Submit";
pub const PATHS: &[&str] = &[HEALTH, STATUS, ACCOUNT, TRANSACTION, EPOCH, EPOCHS, SUBMIT];
type Result<T> = std::result::Result<T, &'static str>;
const INVALID: &str = "protobuf message is invalid";

struct Reader<'a> {
    raw: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn new(raw: &'a [u8]) -> Self {
        Self { raw, at: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or(INVALID)?;
        let value = self.raw.get(self.at..end).ok_or(INVALID)?;
        self.at = end;
        Ok(value)
    }
    fn varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for shift in (0..70).step_by(7) {
            let byte = self.take(1)?[0];
            if shift == 63 && byte > 1 {
                return Err(INVALID);
            }
            value |= u64::from(byte & 127) << shift;
            if byte & 128 == 0 {
                return Ok(value);
            }
        }
        Err(INVALID)
    }
    fn key(&mut self) -> Result<Option<(u32, u8)>> {
        if self.at == self.raw.len() {
            return Ok(None);
        }
        let key = self.varint()?;
        let field = u32::try_from(key >> 3)
            .ok()
            .filter(|v| *v > 0 && *v < (1 << 29))
            .ok_or(INVALID)?;
        let wire = (key & 7) as u8;
        if !matches!(wire, 0 | 1 | 2 | 5) {
            return Err(INVALID);
        }
        Ok(Some((field, wire)))
    }
    fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = usize::try_from(self.varint()?).map_err(|_| INVALID)?;
        self.take(len)
    }
    fn skip(&mut self, wire: u8) -> Result<()> {
        match wire {
            0 => {
                self.varint()?;
            }
            1 => {
                self.take(8)?;
            }
            2 => {
                self.bytes()?;
            }
            5 => {
                self.take(4)?;
            }
            _ => return Err(INVALID),
        }
        Ok(())
    }
    fn integer(&mut self, max: u64) -> Result<i64> {
        let value = self.varint()?;
        if value > max {
            return Err(INVALID);
        }
        Ok(value as i64)
    }
}
fn varint(out: &mut Vec<u8>, mut n: u64) {
    while n >= 128 {
        out.push(n as u8 | 128);
        n >>= 7;
    }
    out.push(n as u8);
}
fn integer(out: &mut Vec<u8>, field: u64, n: u64) {
    varint(out, field << 3);
    varint(out, n);
}
fn bytes(out: &mut Vec<u8>, field: u64, raw: &[u8]) {
    varint(out, (field << 3) | 2);
    varint(out, raw.len() as u64);
    out.extend_from_slice(raw);
}
pub fn json(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    bytes(&mut out, 1, raw);
    out
}
pub fn serving() -> Vec<u8> {
    vec![8, 1]
}
pub enum Request {
    Health(Vec<u8>),
    Call {
        method: &'static [u8],
        params: Vec<u8>,
        page: bool,
    },
}
fn single(raw: &[u8], required: bool, strict: bool) -> Result<Vec<u8>> {
    let mut reader = Reader::new(raw);
    let mut value = vec![];
    while let Some((field, wire)) = reader.key()? {
        match (field, wire) {
            (1, 2) => value = reader.bytes()?.to_vec(),
            (1, _) if strict => return Err(INVALID),
            (_, wire) => reader.skip(wire)?,
        }
    }
    if required && value.is_empty() {
        return Err(INVALID);
    }
    Ok(value)
}
fn array_string(raw: &[u8]) -> Vec<u8> {
    let mut out = vec![b'['];
    json_string(&mut out, raw);
    out.push(b']');
    out
}
fn anchor(raw: &[u8], value: &mut epoch_page::Anchor) -> Result<()> {
    let mut reader = Reader::new(raw);
    while let Some((field, wire)) = reader.key()? {
        match (field, wire) {
            (1, 2) => value.chain = reader.bytes()?.to_vec(),
            (2, 0) => value.epoch = reader.integer(epoch_page::MAX_EPOCH as u64)?,
            (3, 2) => value.root = reader.bytes()?.to_vec(),
            (1..=3, _) => return Err(INVALID),
            (_, wire) => reader.skip(wire)?,
        }
    }
    Ok(())
}
fn page(raw: &[u8]) -> Result<Vec<u8>> {
    let mut reader = Reader::new(raw);
    let mut start = 0;
    let mut limit = 32;
    let mut pinned = None;
    let mut previous = vec![];
    while let Some((field, wire)) = reader.key()? {
        match (field, wire) {
            (1, 0) => start = reader.integer(epoch_page::MAX_EPOCH as u64)?,
            (2, 0) => limit = reader.integer(epoch_page::MAX_EPOCH as u64)?,
            (3, 2) => {
                let current = pinned.get_or_insert(epoch_page::Anchor {
                    chain: vec![],
                    epoch: 0,
                    root: vec![],
                });
                anchor(reader.bytes()?, current)?;
            }
            (4, 2) => previous = reader.bytes()?.to_vec(),
            (1..=4, _) => return Err(INVALID),
            (_, wire) => reader.skip(wire)?,
        }
    }
    let mut params = format!("{{\"start\":{start},\"limit\":{limit},\"anchor\":").into_bytes();
    params.extend(pinned.map_or_else(|| b"null".to_vec(), |value| value.encode()));
    params.extend_from_slice(b",\"previous_root\":");
    json_string(&mut params, &previous);
    params.push(b'}');
    let doc = Document::parse(&params).map_err(|_| INVALID)?;
    epoch_page::Request::parse(&doc, doc.root()).map_err(|_| "invalid params")?;
    Ok(params)
}
pub fn decode(path: &str, raw: &[u8]) -> Result<Request> {
    let (method, params, page) = match path {
        HEALTH => return Ok(Request::Health(single(raw, false, false)?)),
        STATUS => {
            let mut reader = Reader::new(raw);
            while let Some((_, wire)) = reader.key()? {
                reader.skip(wire)?;
            }
            (b"node_status".as_slice(), b"[]".to_vec(), false)
        }
        ACCOUNT => (
            b"octra_account".as_slice(),
            array_string(&single(raw, true, false)?),
            false,
        ),
        TRANSACTION => (
            b"octra_transaction".as_slice(),
            array_string(&single(raw, true, false)?),
            false,
        ),
        EPOCH => {
            let mut reader = Reader::new(raw);
            let mut epoch = 0u64;
            while let Some((field, wire)) = reader.key()? {
                if field == 1 && wire == 0 {
                    // Native singular fields are last-wins, including values
                    // outside the host int range that a later field replaces.
                    epoch = reader.varint()?;
                } else {
                    reader.skip(wire)?;
                }
            }
            if epoch > (1u64 << 62) - 1 {
                return Err(INVALID);
            }
            (
                b"epoch_get".as_slice(),
                format!("[{epoch}]").into_bytes(),
                false,
            )
        }
        EPOCHS => (b"octra_epochPage".as_slice(), page(raw)?, true),
        SUBMIT => {
            if raw.len() > 5_000_005 {
                return Err("transaction message exceeds limit");
            }
            let transaction = single(raw, true, true)?;
            if transaction.len() > 5_000_000 {
                return Err("transaction JSON exceeds limit");
            }
            let doc = Document::parse(&transaction).map_err(|_| "transaction JSON is invalid")?;
            if !matches!(doc.root(), Value::Object(_)) {
                return Err("transaction JSON must be an object");
            }
            let mut params = vec![b'['];
            params.extend(doc.write(doc.root(), false).map_err(|_| INVALID)?);
            params.push(b']');
            (b"octra_submit".as_slice(), params, false)
        }
        _ => return Err("gRPC method is not implemented"),
    };
    Ok(Request::Call {
        method,
        params,
        page,
    })
}
pub fn encode_page(raw: &[u8]) -> Result<Vec<u8>> {
    let doc = Document::parse(raw).map_err(|_| "epoch page response is invalid")?;
    let page =
        epoch_page::Page::parse(&doc, doc.root()).map_err(|_| "epoch page response is invalid")?;
    let pinned = page.anchor;
    let mut anchor_wire = vec![];
    bytes(&mut anchor_wire, 1, &pinned.chain);
    integer(&mut anchor_wire, 2, pinned.epoch as u64);
    bytes(&mut anchor_wire, 3, &pinned.root);
    let mut out = vec![];
    bytes(&mut out, 1, &anchor_wire);
    for row in page.rows {
        let mut wire = vec![];
        integer(&mut wire, 1, row.epoch as u64);
        bytes(&mut wire, 2, &row.root);
        bytes(&mut wire, 3, &row.previous);
        integer(&mut wire, 4, row.tx_start as u64);
        integer(&mut wire, 5, row.tx_count as u64);
        wire.push(49);
        wire.extend_from_slice(&row.time.to_le_bytes());
        bytes(&mut out, 2, &wire);
    }
    let stop = match page.stop {
        epoch_page::Stop::Complete => 1,
        epoch_page::Stop::More => 2,
        epoch_page::Stop::Gap => 3,
    };
    integer(&mut out, 3, page.next as u64);
    integer(&mut out, 4, stop);
    Ok(out)
}
