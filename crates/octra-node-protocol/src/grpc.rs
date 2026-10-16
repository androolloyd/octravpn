// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native optional unary gRPC policy. HTTP/2 I/O remains a host concern.
use crate::{native_integer::parse_int63, network::endpoint::native_trim, rpc::Fault};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{net::SocketAddr, time::Duration};
pub mod proto;

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub request_bytes: usize,
    pub submit_bytes: Option<usize>,
    pub response_bytes: usize,
    pub streams: u32,
    pub default_deadline: Duration,
    pub max_deadline: Duration,
}
impl Config {
    pub fn capture(get: impl Fn(&str) -> Option<Vec<u8>>) -> Result<Option<Self>, String> {
        let boolean = |name: &str, default| match get(name) {
            None => Ok(default),
            Some(raw) => match native_trim(&raw).to_ascii_lowercase().as_slice() {
                b"1" | b"true" | b"yes" => Ok(true),
                b"0" | b"false" | b"no" => Ok(false),
                _ => Err(format!("{name} is invalid")),
            },
        };
        if !boolean("OCTRA_GRPC_ENABLE", false)? {
            return Ok(None);
        }
        let parsed = |name: &str, default: i64| -> Result<i64, String> {
            match get(name) {
                None => Ok(default),
                Some(raw) => {
                    parse_int63(native_trim(&raw)).ok_or_else(|| format!("{name} is invalid"))
                }
            }
        };
        let bounded = |name: &str, value: i64, low: i64, high: i64| {
            if value < low || value > high {
                Err(format!("{name} is outside range {low}..{high}"))
            } else {
                Ok(value)
            }
        };
        let integer = |name: &str, default: i64, low: i64, high: i64| {
            bounded(name, parsed(name, default)?, low, high)
        };
        let host = get("OCTRA_GRPC_HOST").unwrap_or_else(|| b"127.0.0.1".to_vec());
        let host = std::str::from_utf8(&host)
            .ok()
            .and_then(|s| s.parse::<std::net::IpAddr>().ok())
            .ok_or("OCTRA_GRPC_HOST must be a numeric address")?;
        if !host.is_loopback() {
            return Err("OCTRA_GRPC_HOST must be a loopback address".into());
        }
        let port = integer("OCTRA_GRPC_PORT", 8081, 1, 65_535)? as u16;
        let request_bytes = integer("OCTRA_GRPC_MAX_REQUEST_BYTES", 65_536, 1, 1_048_576)? as usize;
        let response_bytes =
            integer("OCTRA_GRPC_MAX_RESPONSE_BYTES", 4_194_304, 1, 16_777_216)? as usize;
        let submit_bytes = if boolean("OCTRA_GRPC_SUBMIT_ENABLE", true)? {
            Some(integer("OCTRA_GRPC_MAX_SUBMIT_BYTES", 5_000_005, 1, 5_000_005)? as usize)
        } else {
            None
        };
        let streams = integer("OCTRA_GRPC_MAX_STREAMS", 32, 1, 128)? as u32;
        // Native parsing reads both values before checking the maximum range.
        let default = parsed("OCTRA_GRPC_DEADLINE_MS", 5_000)?;
        let maximum = parsed("OCTRA_GRPC_MAX_DEADLINE_MS", 10_000)?;
        let maximum = bounded("OCTRA_GRPC_MAX_DEADLINE_MS", maximum, 1, 60_000)? as u64;
        let default = bounded("OCTRA_GRPC_DEADLINE_MS", default, 1, maximum as i64)? as u64;
        Ok(Some(Self {
            listen: SocketAddr::new(host, port),
            request_bytes,
            submit_bytes,
            response_bytes,
            streams,
            default_deadline: Duration::from_millis(default),
            max_deadline: Duration::from_millis(maximum),
        }))
    }
    // Match the native integer-to-float projection and rounding exactly.
    #[allow(clippy::cast_precision_loss)]
    pub fn deadline(&self, raw: Option<&[u8]>) -> Result<Duration, Status> {
        let Some(raw) = raw else {
            return Ok(self.default_deadline.min(self.max_deadline));
        };
        let raw = native_trim(raw);
        if raw.len() < 2 {
            return Err(Status::new(3, b"grpc-timeout is invalid"));
        }
        let (digits, unit) = raw.split_at(raw.len() - 1);
        let scale = match unit[0] {
            b'H' => 3600.,
            b'M' => 60.,
            b'S' => 1.,
            b'm' => 0.001,
            b'u' => 0.000_001,
            b'n' => 0.000_000_001,
            _ => return Err(Status::new(3, b"grpc-timeout unit is invalid")),
        };
        if digits.is_empty() || digits.len() > 8 || !digits.iter().all(u8::is_ascii_digit) {
            return Err(Status::new(3, b"grpc-timeout is invalid"));
        }
        let count = digits
            .iter()
            .fold(0u64, |n, d| n * 10 + u64::from(d - b'0'));
        if count == 0 {
            return Err(Status::new(3, b"grpc-timeout is invalid"));
        }
        Ok(Duration::from_secs_f64(count as f64 * scale).min(self.max_deadline))
    }
}
#[derive(Clone, Debug)]
pub struct Status {
    pub code: u8,
    pub message: Vec<u8>,
    pub rpc: Option<Fault>,
}
impl Status {
    pub fn new(code: u8, message: impl AsRef<[u8]>) -> Self {
        Self {
            code,
            message: message.as_ref().to_vec(),
            rpc: None,
        }
    }
    pub fn from_rpc(error: Fault) -> Self {
        let code = match error.code {
            -32700 | -32600 | -32602 | 105 | 109 | 114 => 3,
            -32601 => 12,
            101 => 16,
            104 => 9,
            107 => 8,
            110 | -32005 | -32012 => 14,
            100 | 112 => 5,
            _ => 9,
        };
        Self {
            code,
            message: error.message.clone(),
            rpc: Some(error),
        }
    }
    pub fn trailers(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![("grpc-status", self.code.to_string())];
        if !self.message.is_empty() {
            let mut message = String::new();
            const HEX: &[u8] = b"0123456789ABCDEF";
            for &byte in &self.message {
                if (32..=126).contains(&byte) && byte != b'%' {
                    message.push(char::from(byte));
                } else {
                    message.push('%');
                    message.push(char::from(HEX[(byte >> 4) as usize]));
                    message.push(char::from(HEX[(byte & 15) as usize]));
                }
            }
            fields.push(("grpc-message", message));
        }
        if let Some(error) = &self.rpc {
            fields.push(("octra-rpc-code", error.code.to_string()));
            fields.push(("octra-rpc-error-bin", STANDARD.encode(error.encode())));
        }
        fields
    }
}
pub fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0];
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}
pub fn unframe(raw: &[u8], limit: usize) -> Result<&[u8], Status> {
    if raw.len() < 5 {
        return Err(Status::new(3, b"request frame is incomplete"));
    }
    if raw[0] != 0 {
        return Err(Status::new(12, b"message compression is not supported"));
    }
    let len = u32::from_be_bytes(raw[1..5].try_into().expect("frame header")) as usize;
    if len > limit {
        return Err(Status::new(8, b"request message exceeds limit"));
    }
    if raw.len() < len + 5 {
        return Err(Status::new(3, b"request frame is incomplete"));
    }
    if raw.len() > len + 5 {
        return Err(Status::new(3, b"unary request has extra data"));
    }
    Ok(&raw[5..])
}
