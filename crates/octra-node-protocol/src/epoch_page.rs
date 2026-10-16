//! Native bounded epoch-page request and response projection.
use crate::{
    epoch_journal::{array, number, object, string},
    native_integer::parse_int63,
    native_json::{Document, Value},
    rpc::Fault,
    transaction::native_float,
};
pub const MAX_EPOCH: i64 = i32::MAX as i64;
pub const MAX_COUNT: usize = 64;
pub const MAX_RECORD: usize = 262_144;
pub const MAX_BYTES: usize = 1_048_576;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub chain: Vec<u8>,
    pub epoch: i64,
    pub root: Vec<u8>,
}
impl Anchor {
    pub fn parse(doc: &Document, value: &Value) -> Result<Self, Fault> {
        fields(doc, value, &[b"chain_id", b"epoch", b"state_root"])?;
        let get = |name: &[u8]| {
            doc.field(value, name)
                .ok_or_else(|| Fault::invalid("epoch page parameters are invalid"))
        };
        let anchor = Self {
            chain: bytes(get(b"chain_id")?)?,
            epoch: integer(get(b"epoch")?)?,
            root: bytes(get(b"state_root")?)?,
        };
        if !anchor.valid() {
            return Err(Fault::invalid("anchor is invalid"));
        }
        Ok(anchor)
    }
    pub fn valid(&self) -> bool {
        self.epoch >= 0
            && self.epoch <= MAX_EPOCH
            && hex(&self.root)
            && !self.chain.is_empty()
            && self.chain.len() <= 128
            && self.chain.iter().all(|v| (b'!'..=b'~').contains(v))
    }
    pub fn encode(&self) -> Vec<u8> {
        object(&[
            ("chain_id", string(&self.chain)),
            ("epoch", number(self.epoch)),
            ("state_root", string(&self.root)),
        ])
    }
}
#[derive(Clone, Debug)]
pub struct Request {
    pub start: i64,
    pub limit: usize,
    pub anchor: Option<Anchor>,
    pub previous: Vec<u8>,
}
pub fn hex(value: &[u8]) -> bool {
    matches!(value.len(), 64 | 128)
        && value
            .iter()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(v))
}
fn fields(doc: &Document, value: &Value, names: &[&[u8]]) -> Result<(), Fault> {
    let Value::Object(rows) = value else {
        return Err(Fault::invalid("epoch page parameters are invalid"));
    };
    let mut seen = std::collections::BTreeSet::new();
    for (name, _) in rows {
        if !names.contains(&name.as_slice()) || !seen.insert(name) {
            return Err(Fault::invalid("epoch page parameters are invalid"));
        }
    }
    let _ = doc;
    Ok(())
}
fn integer(value: &Value) -> Result<i64, Fault> {
    let number = match value {
        Value::Int(value) => Some(value.get()),
        Value::String(raw) | Value::IntLiteral(raw)
            if !raw.is_empty() && raw.iter().all(u8::is_ascii_digit) =>
        {
            parse_int63(raw)
        }
        _ => None,
    };
    number.ok_or_else(|| Fault::invalid("epoch page parameters are invalid"))
}
fn bytes(value: &Value) -> Result<Vec<u8>, Fault> {
    match value {
        Value::String(raw) => Ok(raw.clone()),
        _ => Err(Fault::invalid("epoch page parameters are invalid")),
    }
}
impl Request {
    pub fn parse(doc: &Document, value: &Value) -> Result<Self, Fault> {
        fields(
            doc,
            value,
            &[b"start", b"limit", b"anchor", b"previous_root"],
        )?;
        let start = doc
            .field(value, b"start")
            .map(integer)
            .transpose()?
            .unwrap_or(0);
        let limit = doc
            .field(value, b"limit")
            .map(integer)
            .transpose()?
            .unwrap_or(32);
        let previous = doc
            .field(value, b"previous_root")
            .map(bytes)
            .transpose()?
            .unwrap_or_default();
        let anchor = match doc.field(value, b"anchor") {
            None | Some(Value::Null) => None,
            Some(value) => {
                fields(doc, value, &[b"chain_id", b"epoch", b"state_root"])?;
                let get = |name: &[u8]| {
                    doc.field(value, name)
                        .ok_or_else(|| Fault::invalid("epoch page parameters are invalid"))
                };
                Some(Anchor {
                    chain: bytes(get(b"chain_id")?)?,
                    epoch: integer(get(b"epoch")?)?,
                    root: bytes(get(b"state_root")?)?,
                })
            }
        };
        if !(0..=MAX_EPOCH).contains(&start) {
            return Err(Fault::invalid("start exceeds epoch range"));
        }
        if !(1..=MAX_COUNT as i64).contains(&limit) {
            return Err(Fault::invalid("limit must be between 1 and 64"));
        }
        if !previous.is_empty() && !hex(&previous) {
            return Err(Fault::invalid("previous root is invalid"));
        }
        if anchor.as_ref().is_some_and(|value| !value.valid()) {
            return Err(Fault::invalid("anchor is invalid"));
        }
        Ok(Self {
            start,
            limit: limit as usize,
            anchor,
            previous,
        })
    }
}
#[derive(Clone, Debug)]
pub struct Row {
    pub epoch: i64,
    pub root: Vec<u8>,
    pub previous: Vec<u8>,
    pub tx_start: i64,
    pub tx_count: i64,
    pub time: f64,
}
impl Row {
    // Match the native integer-to-float projection and rounding exactly.
    #[allow(clippy::cast_precision_loss)]
    pub fn parse(doc: &Document, value: &Value) -> Result<Self, Fault> {
        let get = |name: &[u8]| {
            doc.field(value, name)
                .ok_or_else(crate::epoch_journal::unavailable)
        };
        let time = match get(b"finalized_at")? {
            Value::Float(value) => *value,
            Value::Int(value) => value.get() as f64,
            _ => return Err(crate::epoch_journal::unavailable()),
        };
        let start = bytes(get(b"start_txid")?)?;
        let row = Self {
            epoch: integer(get(b"id")?)?,
            root: bytes(get(b"state_root")?)?,
            previous: bytes(get(b"prev_state_root")?)?,
            tx_start: crate::native_integer::parse_int64(&start)
                .ok_or_else(crate::epoch_journal::unavailable)?,
            tx_count: integer(get(b"tx_count")?)?,
            time,
        };
        row.encode()?;
        Ok(row)
    }
    pub fn encode(&self) -> Result<Vec<u8>, Fault> {
        if self.epoch < 0
            || self.epoch > MAX_EPOCH
            || !hex(&self.root)
            || !(hex(&self.previous) || self.epoch == 0 && self.previous.is_empty())
            || self.tx_start < 0
            || self.tx_count < 0
            || self.tx_start.checked_add(self.tx_count).is_none()
            || !self.time.is_finite()
            || self.time < 0.
        {
            return Err(crate::epoch_journal::unavailable());
        }
        Ok(object(&[
            ("id", number(self.epoch)),
            ("state_root", string(&self.root)),
            ("prev_state_root", string(&self.previous)),
            ("start_txid", string(self.tx_start.to_string().as_bytes())),
            ("tx_count", number(self.tx_count)),
            (
                "finalized_at",
                native_float(self.time)
                    .map_err(|_| crate::epoch_journal::unavailable())?
                    .into_bytes(),
            ),
        ]))
    }
}
#[derive(Clone, Debug)]
pub struct Page {
    pub anchor: Anchor,
    pub rows: Vec<Row>,
    pub next: i64,
    pub stop: Stop,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    Complete,
    More,
    Gap,
}
impl Stop {
    pub fn text(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::More => "more",
            Self::Gap => "gap",
        }
    }
}
impl Page {
    pub fn parse(doc: &Document, value: &Value) -> Result<Self, Fault> {
        let get = |name: &[u8]| {
            doc.field(value, name)
                .ok_or_else(crate::epoch_journal::unavailable)
        };
        let anchor = Anchor::parse(doc, get(b"anchor")?)?;
        let Value::List(values) = get(b"epochs")? else {
            return Err(crate::epoch_journal::unavailable());
        };
        if values.len() > MAX_COUNT {
            return Err(crate::epoch_journal::unavailable());
        }
        let rows = values
            .iter()
            .map(|id| {
                Row::parse(
                    doc,
                    doc.get(*id).ok_or_else(crate::epoch_journal::unavailable)?,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let next = integer(get(b"next_epoch")?)?;
        let stop = match bytes(get(b"stop")?)?.as_slice() {
            b"complete" => Stop::Complete,
            b"more" => Stop::More,
            b"gap" => Stop::Gap,
            _ => return Err(crate::epoch_journal::unavailable()),
        };
        let page = Self {
            anchor,
            rows,
            next,
            stop,
        };
        page.validate()?;
        Ok(page)
    }
    pub fn validate(&self) -> Result<(), Fault> {
        let valid = self.anchor.valid()
            && self.rows.len() <= MAX_COUNT
            && self.next >= 0
            && self.next <= self.anchor.epoch + 1
            && self.rows.windows(2).all(|w| {
                w[0].epoch + 1 == w[1].epoch
                    && w[0].root == w[1].previous
                    && w[0].tx_start.checked_add(w[0].tx_count) == Some(w[1].tx_start)
            })
            && self
                .rows
                .last()
                .is_none_or(|row| row.epoch + 1 == self.next)
            && match self.stop {
                Stop::Complete => {
                    self.next == self.anchor.epoch + 1
                        && self
                            .rows
                            .last()
                            .is_none_or(|row| row.root == self.anchor.root)
                }
                Stop::More => self.next <= self.anchor.epoch && !self.rows.is_empty(),
                Stop::Gap => self.next <= self.anchor.epoch,
            };
        if !valid {
            return Err(crate::epoch_journal::unavailable());
        }
        for row in &self.rows {
            row.encode()?;
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, Fault> {
        self.validate()?;
        encode(&self.anchor, &self.rows, self.next, self.stop.text())
    }
}
pub fn encode(anchor: &Anchor, rows: &[Row], next: i64, stop: &str) -> Result<Vec<u8>, Fault> {
    Ok(object(&[
        ("anchor", anchor.encode()),
        (
            "epochs",
            array(
                rows.iter()
                    .map(Row::encode)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        ),
        ("next_epoch", number(next)),
        ("stop", string(stop.as_bytes())),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requests_reject_duplicate_fields_and_unbounded_ranges() {
        for raw in [
            br#"{"start":0,"start":1}"#.as_slice(),
            br#"{"limit":65}"#,
            br#"{"start":"2147483648"}"#,
            br#"{"previous_root":"not-a-root"}"#,
        ] {
            let document = Document::parse(raw).unwrap();
            assert!(Request::parse(&document, document.root()).is_err());
        }
    }
    #[test]
    fn pages_bind_roots_transaction_spans_and_continuation() {
        let root = vec![b'a'; 64];
        let next_root = vec![b'b'; 64];
        let mut page = Page {
            anchor: Anchor {
                chain: b"test".to_vec(),
                epoch: 2,
                root: next_root.clone(),
            },
            rows: vec![
                Row {
                    epoch: 1,
                    root: root.clone(),
                    previous: vec![b'0'; 64],
                    tx_start: 7,
                    tx_count: 2,
                    time: 1.25,
                },
                Row {
                    epoch: 2,
                    root: next_root,
                    previous: root,
                    tx_start: 9,
                    tx_count: 0,
                    time: 2.5,
                },
            ],
            next: 3,
            stop: Stop::Complete,
        };
        let raw = page.encode().unwrap();
        let document = Document::parse(&raw).unwrap();
        assert_eq!(Page::parse(&document, document.root()).unwrap().next, 3);
        page.rows[1].tx_start = 8;
        assert!(page.validate().is_err());
        page.rows[1].tx_start = 9;
        page.rows[1].previous = vec![b'c'; 64];
        assert!(page.validate().is_err());
    }
}
