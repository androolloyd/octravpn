// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native endpoint parsing, without reading process-global environment variables.
use crate::native_integer::parse_int63;
use std::collections::BTreeSet;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub host: Vec<u8>,
    pub port: u16,
}
// OCaml String.trim excludes vertical tab (Rust trim_ascii includes it).
pub fn native_trim(mut bytes: &[u8]) -> &[u8] {
    fn whitespace(b: u8) -> bool {
        matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 12)
    }
    while bytes.first().is_some_and(|b| whitespace(*b)) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(|b| whitespace(*b)) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}
impl Endpoint {
    pub fn parse(raw: &[u8]) -> Option<Self> {
        let mut parts = native_trim(raw).split(|b| *b == b':');
        let host = native_trim(parts.next()?);
        let port = parse_int63(native_trim(parts.next()?))?;
        if parts.next().is_some() || host.is_empty() || !(1..=65535).contains(&port) {
            return None;
        }
        Some(Self {
            host: host.to_vec(),
            port: port as u16,
        })
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.host.clone();
        out.push(b':');
        out.extend(self.port.to_string().bytes());
        out
    }
}
pub fn dedupe(endpoints: impl IntoIterator<Item = Endpoint>) -> Vec<Endpoint> {
    let mut seen = BTreeSet::new();
    endpoints
        .into_iter()
        .filter(|e| seen.insert(e.encode()))
        .collect()
}
pub fn csv(raw: &[u8]) -> Vec<Endpoint> {
    dedupe(raw.split(|b| *b == b',').filter_map(Endpoint::parse))
}
pub fn bootstrap(configured: &[Vec<u8>], base: &[u8], extra: &[u8]) -> Vec<Endpoint> {
    dedupe(
        configured
            .iter()
            .filter_map(|s| Endpoint::parse(s))
            .chain(csv(base))
            .chain(csv(extra)),
    )
}
pub fn advertised(
    default_port: u16,
    endpoint: Option<&[u8]>,
    host: Option<&[u8]>,
    port: Option<&[u8]>,
) -> Endpoint {
    let fallback = || Endpoint {
        host: b"127.0.0.1".to_vec(),
        port: default_port,
    };
    if let Some(endpoint) = endpoint {
        return Endpoint::parse(endpoint).unwrap_or_else(fallback);
    }
    Endpoint {
        host: host
            .map(native_trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(b"127.0.0.1")
            .to_vec(),
        port: port
            .and_then(|s| parse_int63(native_trim(s)))
            .filter(|p| (1..=65535).contains(p))
            .map_or(default_port, |p| p as u16),
    }
}
