// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{Error, Final, Marks, Member, Phase, Pulse, State};
use crate::{
    native_integer::{parse_int63, parse_int64},
    native_json::{Document, Value},
    transaction::{decode_base64, json_string},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::BTreeSet;
fn name(out: &mut Vec<u8>, key: &[u8]) {
    out.push(b',');
    json_string(out, key);
    out.push(b':');
}
fn text(out: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    name(out, key);
    json_string(out, value);
}
fn epoch(out: &mut Vec<u8>, key: &[u8], value: i64) {
    text(out, key, value.to_string().as_bytes());
}
fn optional(out: &mut Vec<u8>, value: Option<i64>) {
    match value {
        Some(n) => json_string(out, n.to_string().as_bytes()),
        None => out.extend_from_slice(b"null"),
    }
}
impl State {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = b"{\"standard\":\"octra-validator-duty\"".to_vec();
        epoch(&mut out, b"safe_after", self.safe_after);
        name(&mut out, b"applied");
        optional(&mut out, self.applied);
        out.extend_from_slice(b",\"members\":[");
        let mut members: Vec<_> = self.members.iter().collect();
        members.sort_by(|l, r| {
            l.address.cmp(&r.address).then_with(|| {
                matches!(l.phase, Phase::Shadow(_)).cmp(&matches!(r.phase, Phase::Shadow(_)))
            })
        });
        for (i, m) in members.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            out.extend_from_slice(b"{\"address\":");
            json_string(&mut out, &m.address);
            name(&mut out, b"phase");
            match &m.phase {
                Phase::Live(since) => {
                    out.extend_from_slice(b"{\"kind\":\"live\"");
                    epoch(&mut out, b"since", *since);
                    out.push(b'}');
                }
                Phase::Shadow(p) => {
                    out.extend_from_slice(b"{\"kind\":\"shadow\"");
                    if let Some(p) = p {
                        out.extend_from_slice(b",\"pulse\":{\"first\":");
                        json_string(&mut out, p.first.to_string().as_bytes());
                        epoch(&mut out, b"last", p.last);
                        name(&mut out, b"count");
                        out.extend_from_slice(p.count.to_string().as_bytes());
                        out.push(b'}');
                    }
                    out.push(b'}');
                }
            }
            out.extend_from_slice(b",\"marks\":[");
            for (i, n) in m.marks.epochs.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                json_string(&mut out, n.to_string().as_bytes());
            }
            out.extend_from_slice(b"]}");
        }
        out.extend_from_slice(b"],\"finals\":[");
        let mut finals: Vec<_> = self.finals.iter().collect();
        finals.sort_by_key(|f| f.epoch);
        for (i, f) in finals.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            out.extend_from_slice(b"{\"epoch\":");
            json_string(&mut out, f.epoch.to_string().as_bytes());
            text(
                &mut out,
                b"proposal_id",
                STANDARD.encode(&f.proposal_id).as_bytes(),
            );
            text(
                &mut out,
                b"set_hash",
                STANDARD.encode(&f.set_hash).as_bytes(),
            );
            out.push(b'}');
        }
        out.push(b']');
        if let Some(seats) = self.seats {
            name(&mut out, b"seats");
            out.extend_from_slice(seats.to_string().as_bytes());
        }
        out.push(b'}');
        out
    }
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let doc = Document::parse(raw)
            .map_err(|_| Error::from("validator duty state encoding is invalid"))?;
        let root = object(doc.root(), "validator duty state")?;
        if !matches!(doc.field(root,b"standard"),Some(Value::String(v)) if v==b"octra-validator-duty")
        {
            return Err("validator duty standard is invalid".into());
        }
        let safe_after = integer(
            required(&doc, root, b"safe_after")?,
            "validator duty safe epoch",
            false,
        )?;
        let applied = match required(&doc, root, b"applied")? {
            Value::Null => None,
            v => Some(integer(v, "validator duty applied epoch", false)?),
        };
        let seats = match doc.field(root, b"seats") {
            None | Some(Value::Null) => None,
            Some(v) => {
                let n = integer(v, "validator duty seats", true)?;
                if !(4..=200).contains(&n) {
                    return Err("validator duty seats are outside limits".into());
                }
                Some(n)
            }
        };
        let mut members = list(required(&doc, root, b"members")?, "validator duty members")?
            .iter()
            .map(|i| member(&doc, doc.get(*i).expect("JSON child")))
            .collect::<Result<Vec<_>, _>>()?;
        let mut finals = list(required(&doc, root, b"finals")?, "validator duty finals")?
            .iter()
            .map(|i| finality(&doc, doc.get(*i).expect("JSON child")))
            .collect::<Result<Vec<_>, _>>()?;
        members.sort_by(|l, r| l.address.cmp(&r.address));
        finals.sort_by_key(|f| f.epoch);
        if members.windows(2).any(|p| p[0].address == p[1].address) {
            return Err("validator duty member is duplicated".into());
        }
        if finals.windows(2).any(|p| p[0].epoch == p[1].epoch) {
            return Err("validator duty final is duplicated".into());
        }
        Ok(Self {
            members,
            finals,
            safe_after,
            applied,
            seats,
        })
    }
}
fn object<'a>(v: &'a Value, label: &str) -> Result<&'a Value, Error> {
    if matches!(v, Value::Object(_)) {
        Ok(v)
    } else {
        Err(format!("{label} has wrong type").into())
    }
}
fn required<'a>(d: &'a Document, v: &Value, key: &[u8]) -> Result<&'a Value, Error> {
    d.field(v, key)
        .ok_or_else(|| format!("{} is missing", String::from_utf8_lossy(key)).into())
}
fn list<'a>(v: &'a Value, label: &str) -> Result<&'a [usize], Error> {
    match v {
        Value::List(v) => Ok(v),
        _ => Err(format!("{label} has wrong type").into()),
    }
}
fn integer(v: &Value, label: &str, machine: bool) -> Result<i64, Error> {
    match v {
        Value::Int(v) => Ok(v.get()),
        Value::String(raw) => (if machine {
            parse_int63(raw)
        } else {
            parse_int64(raw)
        })
        .ok_or_else(|| format!("{label} is invalid").into()),
        _ => Err(format!("{label} has wrong type").into()),
    }
}
fn hash(label: &str, value: &[u8]) -> Result<Vec<u8>, Error> {
    let raw = decode_base64(value).map_err(|_| Error::from(format!("{label} is not base64")))?;
    if STANDARD.encode(&raw).as_bytes() != value {
        return Err(format!("{label} is not exact").into());
    }
    if raw.len() != 32 {
        return Err(format!("{label} length is invalid").into());
    }
    Ok(raw)
}
fn pulse(d: &Document, v: &Value) -> Result<Pulse, Error> {
    let v = object(v, "validator duty pulse")?;
    let first = integer(
        required(d, v, b"first")?,
        "validator duty pulse first",
        false,
    )?;
    let last = integer(required(d, v, b"last")?, "validator duty pulse last", false)?;
    let count = integer(
        required(d, v, b"count")?,
        "validator duty pulse count",
        true,
    )?;
    if first < 0 || last < first || count < 1 {
        return Err("validator duty pulse is invalid".into());
    }
    Ok(Pulse { first, last, count })
}
fn phase(d: &Document, v: &Value) -> Result<Phase, Error> {
    let v = object(v, "validator duty phase")?;
    match d.field(v, b"kind") {
        Some(Value::String(k)) if k == b"live" => Ok(Phase::Live(integer(
            required(d, v, b"since")?,
            "validator duty live epoch",
            false,
        )?)),
        Some(Value::String(k)) if k == b"shadow" => Ok(Phase::Shadow(
            d.field(v, b"pulse").map(|v| pulse(d, v)).transpose()?,
        )),
        _ => Err("validator duty phase kind is invalid".into()),
    }
}
fn marks(d: &Document, v: &Value) -> Result<Marks, Error> {
    let values = list(v, "validator duty marks")?;
    let mut epochs = BTreeSet::new();
    for id in values {
        let n = integer(
            d.get(*id).expect("JSON child"),
            "validator duty mark",
            false,
        )?;
        if n < 0 {
            return Err("validator duty mark is negative".into());
        }
        if !epochs.insert(n) {
            return Err("validator duty mark is duplicated".into());
        }
    }
    let floor = epochs.first().copied().unwrap_or(0);
    if epochs
        .last()
        .is_some_and(|last| last.wrapping_sub(floor) > 255)
    {
        return Err("validator duty marks exceed range".into());
    }
    Ok(Marks { floor, epochs })
}
fn member(d: &Document, v: &Value) -> Result<Member, Error> {
    let v = object(v, "validator duty member")?;
    let Some(Value::String(address)) = d
        .field(v, b"address")
        .filter(|v| matches!(v,Value::String(v)if !v.is_empty()))
    else {
        return Err("validator duty member address is invalid".into());
    };
    let phase = phase(d, required(d, v, b"phase")?)?;
    let marks = marks(d, required(d, v, b"marks")?)?;
    Ok(Member {
        address: address.clone(),
        phase,
        marks,
    })
}
fn finality(d: &Document, v: &Value) -> Result<Final, Error> {
    let v = object(v, "validator duty final")?;
    let epoch = integer(
        required(d, v, b"epoch")?,
        "validator duty final epoch",
        false,
    )?;
    let (Some(Value::String(proposal)), Some(Value::String(set))) =
        (d.field(v, b"proposal_id"), d.field(v, b"set_hash"))
    else {
        return Err("validator duty final hash is missing".into());
    };
    let proposal_id = hash("validator duty proposal id", proposal)?;
    let set_hash = hash("validator duty set hash", set)?;
    if epoch < 0 {
        return Err("validator duty final epoch is negative".into());
    }
    Ok(Final {
        epoch,
        proposal_id,
        set_hash,
    })
}
