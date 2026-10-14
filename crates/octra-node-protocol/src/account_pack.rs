//! Native account data and content-defined ciphertext storage, including both
//! legacy JSON accounts and the activated account-parts layout.
use crate::{
    native_integer::parse_integer,
    native_json::{Document, Value},
    state::Account,
    transaction::{decode_base64, json_optional, json_string, Error, Nonce},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    Hfhe,
    Text,
}
impl Form {
    fn name(self) -> &'static [u8] {
        match self {
            Self::Hfhe => b"hfhe",
            Self::Text => b"text",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    pub id: Vec<u8>,
    pub raw: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Meta {
    pub form: Form,
    pub size: usize,
    pub id: Vec<u8>,
    pub blob: Vec<u8>,
    pub parts: Vec<Vec<u8>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Data {
    Old(Account),
    Parts(Account, Vec<u8>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image {
    pub data: Vec<u8>,
    pub meta: Option<Vec<u8>>,
    pub parts: Vec<Part>,
    pub id: Option<Vec<u8>>,
}
fn error(s: &str) -> Error {
    Error(s.into())
}
fn parse(raw: &[u8], label: &str) -> Result<Document, Error> {
    Document::parse(raw).map_err(|_| Error(format!("{label} is not json")))
}
fn exact(doc: &Document, expected: &[&[u8]]) -> bool {
    let Value::Object(fields) = doc.root() else {
        return false;
    };
    let names = fields
        .iter()
        .map(|(k, _)| k.as_slice())
        .collect::<std::collections::BTreeSet<_>>();
    fields.len() == expected.len()
        && names.len() == expected.len()
        && expected.iter().all(|k| names.contains(k))
}
fn field<'a>(doc: &'a Document, name: &str) -> Result<&'a Value, Error> {
    doc.field(doc.root(), name.as_bytes())
        .ok_or_else(|| Error(format!("account field is missing: {name}")))
}
fn text<'a>(doc: &'a Document, name: &str) -> Result<&'a [u8], Error> {
    match field(doc, name)? {
        Value::String(v) => Ok(v),
        _ => Err(Error(format!("account field is not text: {name}"))),
    }
}
fn int(doc: &Document, name: &str) -> Result<Nonce, Error> {
    match field(doc, name)? {
        Value::Int(v) => Ok(*v),
        _ => Err(Error(format!("account field is not integer: {name}"))),
    }
}
fn optional(doc: &Document, name: &str) -> Result<Option<Vec<u8>>, Error> {
    match field(doc, name)? {
        Value::Null => Ok(None),
        Value::String(v) => Ok(Some(v.clone())),
        _ => Err(Error(format!("account field is not optional text: {name}"))),
    }
}
fn integer(doc: &Document, name: &str) -> Result<num_bigint::BigInt, Error> {
    parse_integer(text(doc, name)?)
        .ok_or_else(|| Error(format!("account field is not natural text: {name}")))
}
pub fn data(raw: &[u8]) -> Result<Data, Error> {
    let doc = parse(raw, "account value")?;
    if !matches!(doc.root(), Value::Object(_)) {
        return Err(error("account value is not an object"));
    }
    if doc.field(doc.root(), b"layout").is_some() {
        if !exact(
            &doc,
            &[
                b"layout",
                b"balance",
                b"nonce",
                b"public_key",
                b"cipher_id",
                b"decrypt_allowance",
            ],
        ) {
            return Err(error("account part fields differ"));
        }
        if text(&doc, "layout")? != b"parts" {
            return Err(error("account layout differs"));
        }
        let balance = integer(&doc, "balance")?;
        let nonce = int(&doc, "nonce")?;
        let public_key = optional(&doc, "public_key")?;
        let id = text(&doc, "cipher_id")?.to_vec();
        let decrypt_allowance = integer(&doc, "decrypt_allowance")?;
        Ok(Data::Parts(
            Account {
                balance,
                nonce,
                public_key,
                encrypted_balance: None,
                decrypt_allowance,
            },
            id,
        ))
    } else {
        let decrypt = exact(
            &doc,
            &[
                b"balance",
                b"nonce",
                b"public_key",
                b"encrypted_balance",
                b"decrypt_allowance",
            ],
        );
        if !decrypt
            && !exact(
                &doc,
                &[b"balance", b"nonce", b"public_key", b"encrypted_balance"],
            )
        {
            return Err(error("account fields differ"));
        }
        let balance = integer(&doc, "balance")?;
        let nonce = int(&doc, "nonce")?;
        let public_key = optional(&doc, "public_key")?;
        let encrypted_balance = optional(&doc, "encrypted_balance")?;
        let decrypt_allowance = if decrypt {
            integer(&doc, "decrypt_allowance")?
        } else {
            0.into()
        };
        Ok(Data::Old(Account {
            balance,
            nonce,
            public_key,
            encrypted_balance,
            decrypt_allowance,
        }))
    }
}
fn hex_id(raw: &[u8]) -> bool {
    raw.len() == 64
        && raw
            .iter()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
pub fn count_ok(size: usize, count: usize) -> bool {
    if size == 0 {
        count == 0
    } else {
        count > 0 && count <= 1 + (size - 1) / 4096
    }
}
pub fn meta(raw: &[u8]) -> Result<Meta, Error> {
    let doc = parse(raw, "account cipher value")?;
    if !matches!(doc.root(), Value::Object(_)) {
        return Err(error("account cipher value is not an object"));
    }
    if !exact(&doc, &[b"form", b"size", b"id", b"blob", b"parts"]) {
        return Err(error("account cipher fields differ"));
    }
    let form = match text(&doc, "form")? {
        b"hfhe" => Form::Hfhe,
        b"text" => Form::Text,
        _ => return Err(error("account cipher form differs")),
    };
    let size = int(&doc, "size")?.get();
    let id = text(&doc, "id")?.to_vec();
    let blob = text(&doc, "blob")?.to_vec();
    let Value::List(values) = field(&doc, "parts")? else {
        return Err(error("account parts are not a list"));
    };
    let mut parts = Vec::with_capacity(values.len());
    for index in values {
        match doc.get(*index) {
            Some(Value::String(v)) if hex_id(v) => parts.push(v.clone()),
            _ => return Err(error("account part id differs")),
        }
    }
    if size < 0 {
        return Err(error("account cipher size is negative"));
    }
    if !hex_id(&id) {
        return Err(error("account cipher id differs"));
    }
    if !hex_id(&blob) {
        return Err(error("account blob id differs"));
    }
    let size = usize::try_from(size).map_err(|_| error("account cipher size unavailable"))?;
    if !count_ok(size, parts.len()) {
        return Err(error("account part count differs"));
    }
    Ok(Meta {
        form,
        size,
        id,
        blob,
        parts,
    })
}
fn hash(tag: &[u8], raw: &[u8]) -> Vec<u8> {
    let mut state = Sha256::new();
    state.update(tag);
    state.update([0]);
    state.update(raw);
    hex::encode(state.finalize()).into_bytes()
}
pub fn part_id(raw: &[u8]) -> Vec<u8> {
    hash(b"octra.account.part", raw)
}
pub fn blob_id(raw: &[u8]) -> Vec<u8> {
    hash(b"octra.account.blob", raw)
}
pub fn cipher_id(form: Form, raw: &[u8]) -> Vec<u8> {
    let mut state = Sha256::new();
    state.update(b"octra.account.cipher\0");
    state.update(form.name());
    state.update([0]);
    state.update(raw);
    hex::encode(state.finalize()).into_bytes()
}
fn source(cipher: &[u8]) -> (Form, Vec<u8>) {
    if let Some(encoded) = cipher.strip_prefix(b"hfhe_v1|").filter(|v| !v.is_empty()) {
        if let Ok(raw) = decode_base64(encoded) {
            if STANDARD.encode(&raw).as_bytes() == encoded {
                return (Form::Hfhe, raw);
            }
        }
    }
    (Form::Text, cipher.to_vec())
}
fn mix(byte: u8) -> u64 {
    let value = (u64::from(byte) + 1).wrapping_mul(0x5851_f42d_4c95_7f2d);
    value ^ (value >> 29)
}
fn stop(state: u64, size: usize) -> bool {
    size >= 4096 && (state.trailing_zeros() >= 14 || size >= 65536)
}
pub fn cut(raw: &[u8]) -> Vec<Part> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut state = 0u64;
    for (pos, &byte) in raw.iter().enumerate() {
        state = state.wrapping_shl(1).wrapping_add(mix(byte));
        if stop(state, pos - start + 1) {
            let part = &raw[start..=pos];
            parts.push(Part {
                id: part_id(part),
                raw: part.to_vec(),
            });
            start = pos + 1;
            state = 0;
        }
    }
    if start < raw.len() {
        let part = &raw[start..];
        parts.push(Part {
            id: part_id(part),
            raw: part.to_vec(),
        });
    }
    parts
}
fn piece_ok(raw: &[u8], final_piece: bool) -> bool {
    let mut state = 0u64;
    for (pos, &byte) in raw.iter().enumerate() {
        state = state.wrapping_shl(1).wrapping_add(mix(byte));
        if stop(state, pos + 1) {
            return pos + 1 == raw.len();
        }
        if pos + 1 == raw.len() {
            return final_piece;
        }
    }
    false
}
pub fn join(id: &[u8], size: usize, parts: &[Part]) -> Result<Vec<u8>, Error> {
    if !count_ok(size, parts.len()) {
        return Err(error("blob part count differs"));
    }
    let mut raw = Vec::new();
    for (index, part) in parts.iter().enumerate() {
        if part_id(&part.raw) != part.id {
            return Err(error("blob part id differs"));
        }
        if part.raw.len() > size - raw.len() {
            return Err(error("blob parts exceed size"));
        }
        let total = raw.len() + part.raw.len();
        if !piece_ok(&part.raw, index + 1 == parts.len() && total == size) {
            return Err(error("blob part split differs"));
        }
        raw.try_reserve(part.raw.len())
            .map_err(|_| error("account allocation unavailable"))?;
        raw.extend_from_slice(&part.raw);
    }
    if raw.len() != size {
        return Err(error("blob size differs"));
    }
    if blob_id(&raw) != id {
        return Err(error("blob id differs"));
    }
    Ok(raw)
}
fn data_json(account: &Account, id: &[u8]) -> Vec<u8> {
    let mut raw = b"{\"layout\":\"parts\",\"balance\":".to_vec();
    json_string(&mut raw, account.balance.to_string().as_bytes());
    raw.extend(b",\"nonce\":");
    raw.extend(account.nonce.get().to_string().as_bytes());
    raw.extend(b",\"public_key\":");
    json_optional(&mut raw, account.public_key.as_deref());
    raw.extend(b",\"cipher_id\":");
    json_string(&mut raw, id);
    raw.extend(b",\"decrypt_allowance\":");
    json_string(&mut raw, account.decrypt_allowance.to_string().as_bytes());
    raw.push(b'}');
    raw
}
impl Meta {
    pub fn to_json_bytes(&self) -> Vec<u8> {
        let mut raw = b"{\"form\":".to_vec();
        json_string(&mut raw, self.form.name());
        raw.extend(b",\"size\":");
        raw.extend(self.size.to_string().as_bytes());
        raw.extend(b",\"id\":");
        json_string(&mut raw, &self.id);
        raw.extend(b",\"blob\":");
        json_string(&mut raw, &self.blob);
        raw.extend(b",\"parts\":[");
        for (index, id) in self.parts.iter().enumerate() {
            if index > 0 {
                raw.push(b',');
            }
            json_string(&mut raw, id);
        }
        raw.extend(b"]}");
        raw
    }
    pub fn restore(&self, mut get: impl FnMut(&[u8]) -> Option<Vec<u8>>) -> Result<Vec<u8>, Error> {
        let parts = self
            .parts
            .iter()
            .map(|id| {
                Ok(Part {
                    id: id.clone(),
                    raw: get(id).ok_or_else(|| error("account cipher part is missing"))?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let raw = join(&self.blob, self.size, &parts)?;
        if cipher_id(self.form, &raw) != self.id {
            return Err(error("account cipher id differs"));
        }
        Ok(match self.form {
            Form::Hfhe => [b"hfhe_v1|".as_slice(), STANDARD.encode(raw).as_bytes()].concat(),
            Form::Text => raw,
        })
    }
}
pub fn head(account: &Account) -> Option<(Vec<u8>, Vec<u8>)> {
    account.encrypted_balance.as_deref().map(|cipher| {
        let (form, raw) = source(cipher);
        let id = cipher_id(form, &raw);
        (data_json(account, &id), id)
    })
}
pub fn image(account: &Account) -> Image {
    let Some(cipher) = account.encrypted_balance.as_deref() else {
        return Image {
            data: account.to_json_bytes(),
            meta: None,
            parts: Vec::new(),
            id: None,
        };
    };
    let (form, raw) = source(cipher);
    let parts = cut(&raw);
    let id = cipher_id(form, &raw);
    let meta = Meta {
        form,
        size: raw.len(),
        id: id.clone(),
        blob: blob_id(&raw),
        parts: parts.iter().map(|p| p.id.clone()).collect(),
    };
    Image {
        data: data_json(account, &id),
        meta: Some(meta.to_json_bytes()),
        parts,
        id: Some(id),
    }
}
pub fn read(
    data: Data,
    meta_raw: Option<&[u8]>,
    get: impl FnMut(&[u8]) -> Option<Vec<u8>>,
) -> Result<Account, Error> {
    match data {
        Data::Old(account) => Ok(account),
        Data::Parts(mut account, id) => {
            let meta = meta(meta_raw.ok_or_else(|| error("account cipher metadata is missing"))?)?;
            if meta.id != id {
                return Err(error("account cipher reference differs"));
            }
            account.encrypted_balance = Some(meta.restore(get)?);
            Ok(account)
        }
    }
}
