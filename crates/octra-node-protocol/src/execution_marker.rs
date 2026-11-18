// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! The per-epoch execution profile marker (`Epoch_exec.execution_marker`).
//! Under seatless voting every executed epoch records, in state meta
//! `execution_profile`, the consensus profile it was executed under; the next
//! epoch, and any restored state, must find the marker its rules expect.
use crate::native_json::{Document, ReadMode, Value};
use crate::transaction::Nonce;

pub const META_KEY: &[u8] = b"execution_profile";
/// OCaml `max_int` on the pinned host.
const MAX_INT: i64 = (1 << 62) - 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Marker {
    pub epoch: i64,
    pub profile: [u8; 32],
}

pub fn to_bytes(epoch: i64, profile: &[u8]) -> Result<Vec<u8>, String> {
    if !(0..MAX_INT).contains(&epoch) {
        return Err("execution profile epoch is invalid".into());
    }
    if profile.len() != 32 {
        return Err("execution profile hash is invalid".into());
    }
    Ok(format!(
        "{{\"epoch\":{epoch},\"profile\":\"{}\"}}",
        hex::encode(profile)
    )
    .into_bytes())
}

pub fn parse(raw: &[u8]) -> Result<Marker, String> {
    let invalid = || "execution profile marker is invalid".to_string();
    if raw.len() > 256 {
        return Err(invalid());
    }
    let doc = Document::parse_native(raw, ReadMode::Safe).map_err(|_| invalid())?;
    let Value::Object(fields) = doc.root() else {
        return Err(invalid());
    };
    let mut fields: Vec<_> = fields.iter().collect();
    fields.sort_by(|a, b| a.0.cmp(&b.0));
    let [(epoch_key, epoch), (profile_key, profile)] = fields.as_slice() else {
        return Err(invalid());
    };
    if epoch_key.as_slice() != b"epoch" || profile_key.as_slice() != b"profile" {
        return Err(invalid());
    }
    let (Some(Value::Int(epoch)), Some(Value::String(hex))) = (doc.get(*epoch), doc.get(*profile))
    else {
        return Err(invalid());
    };
    let epoch = nonce(*epoch);
    if !(0..MAX_INT).contains(&epoch)
        || hex.len() != 64
        || !hex
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(invalid());
    }
    let mut profile = [0; 32];
    hex::decode_to_slice(hex, &mut profile).map_err(|_| invalid())?;
    Ok(Marker { epoch, profile })
}

fn nonce(value: Nonce) -> i64 {
    value.get()
}

/// Native `check_execution`: the stored marker for `epoch` against the
/// profile its rules expect (`None` before seatless).
pub fn check(expected: Option<&[u8]>, epoch: i64, marker: Option<&[u8]>) -> Result<(), String> {
    match (expected, marker) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err("execution profile marker is unexpected".into()),
        (Some(expected), _) if expected.len() != 32 => {
            Err("execution profile hash is invalid".into())
        }
        (Some(_), None) => Err("execution profile marker is missing".into()),
        (Some(expected), Some(raw)) => {
            let marker = parse(raw)?;
            if marker.epoch != epoch {
                Err("execution profile epoch differs".into())
            } else if marker.profile.as_slice() != expected {
                Err("execution profile hash differs".into())
            } else {
                Ok(())
            }
        }
    }
}

/// Native `check_execution_epochs`: state committed after `epoch`.
pub fn check_epochs(epoch: i64, last: Option<&[u8]>, current: Option<&[u8]>) -> Result<(), String> {
    if epoch < 0 || epoch == MAX_INT {
        return Err("execution profile epoch is invalid".into());
    }
    if last != Some(epoch.to_string().as_bytes()) {
        return Err("execution profile last epoch differs".into());
    }
    if current != Some((epoch + 1).to_string().as_bytes()) {
        return Err("execution profile current epoch differs".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip_and_refusals() {
        let raw = to_bytes(7, &[0xab; 32]).unwrap();
        assert_eq!(
            parse(&raw).unwrap(),
            Marker {
                epoch: 7,
                profile: [0xab; 32]
            }
        );
        let swapped = format!("{{\"profile\":\"{}\",\"epoch\":7}}", "ab".repeat(32));
        assert_eq!(parse(swapped.as_bytes()).unwrap().epoch, 7);
        for bad in [
            "{\"epoch\":7,\"profile\":\"AB\"}".to_string(),
            format!("{{\"epoch\":7.0,\"profile\":\"{}\"}}", "ab".repeat(32)),
            format!("{{\"epoch\":-1,\"profile\":\"{}\"}}", "ab".repeat(32)),
            format!(
                "{{\"epoch\":7,\"epoch\":7,\"profile\":\"{}\"}}",
                "ab".repeat(32)
            ),
            format!("{{\"epoch\":7,\"profile\":\"{}\"}}", "AB".repeat(32)),
        ] {
            assert!(parse(bad.as_bytes()).is_err(), "{bad}");
        }
        assert_eq!(check(None, 1, None), Ok(()));
        assert!(check(Some(&[0; 32]), 1, None).is_err());
        assert_eq!(check_epochs(4, Some(b"4"), Some(b"5")), Ok(()));
    }
}
