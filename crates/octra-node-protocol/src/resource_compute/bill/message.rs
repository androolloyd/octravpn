// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{Error, Result, MAX_FUEL, MAX_WIRE, MODEL_LIMIT};
use crate::{oce1::Writer, transaction::decode_base64};
use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigInt;
pub struct PaymentRequest {
    pub fuel: i64,
    pub records: Vec<Vec<u8>>,
}
pub fn encode_request(fuel: i64, records: &[Vec<u8>]) -> Result<Vec<u8>> {
    if !(1..=MAX_FUEL).contains(&fuel) || records.is_empty() || records.len() > 64 {
        return Err(Error::rejected(b"compute payment limits"));
    }
    let mut out = Writer::new();
    out.put_u32(fuel as u32)?;
    out.put_u16(records.len() as u16)?;
    for record in records {
        out.put_bytes(record)?;
    }
    let raw = STANDARD.encode(out.into_bytes()).into_bytes();
    if raw.len() > MAX_WIRE {
        Err(Error::rejected(b"compute payment size"))
    } else {
        Ok(raw)
    }
}
pub fn decode_request(raw: &[u8]) -> Result<PaymentRequest> {
    if raw.len() > MAX_WIRE {
        return Err(Error::rejected(b"compute payment size"));
    }
    let bytes = decode_base64(raw).map_err(|_| Error::rejected(b"compute payment encoding"))?;
    super::super::frame(&bytes, b"compute payment encoding", |input| {
        let fuel = i64::from(input.get_u32()? as i32);
        let count = usize::from(input.get_u16()?);
        if !(1..=MAX_FUEL).contains(&fuel) || count == 0 || count > 64 {
            return Ok(Err(Error::rejected(b"compute payment limits")));
        }
        let mut records = Vec::new();
        for _ in 0..count {
            records.push(input.get_bytes_bounded(MAX_WIRE)?.to_vec());
        }
        Ok(Ok(PaymentRequest { fuel, records }))
    })
}
pub fn fee(raw: &[u8]) -> Result<BigInt> {
    match decode_request(raw) {
        Ok(request) => Ok(BigInt::from(MODEL_LIMIT / 16)
            + BigInt::from(10_000 + request.fuel)
            + BigInt::from(raw.len()) * 2),
        Err(error) if error.is_operational() => Err(error),
        Err(_) => Ok(BigInt::from(10_000_000)),
    }
}
