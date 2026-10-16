// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native Circle policy payloads and deterministic stable-storage snapshots.
pub(crate) mod fields;
pub mod hfhe;
pub mod key;
pub mod receipt;
pub mod transport;
pub(crate) mod view;
use crate::{circle_program::Refusal, transaction::json_string};
pub(crate) type Result<T> = std::result::Result<T, Refusal>;
pub(crate) fn malformed(reason: impl Into<Vec<u8>>) -> Refusal {
    Refusal::new("malformed_transaction", reason)
}
/// Ordered writes use native `Hashtbl.replace` / `Hashtbl.remove` semantics.
#[derive(Default)]
pub struct Snapshot(pub Vec<(Vec<u8>, Option<Vec<u8>>)>);
impl Snapshot {
    pub(crate) fn set(&mut self, prefix: &[u8], name: &[u8], value: Option<Vec<u8>>) {
        self.0.push(([prefix, b":", name].concat(), value));
    }
    pub(crate) fn nondefault(&mut self, prefix: &[u8], name: &[u8], raw: &[u8], default: &[u8]) {
        self.set(prefix, name, (raw != default).then(|| raw.to_vec()));
    }
}
pub(crate) fn string_list(values: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![b'['];
    for (i, value) in values.iter().enumerate() {
        if i != 0 {
            out.push(b',');
        }
        json_string(&mut out, value);
    }
    out.push(b']');
    out
}
macro_rules! native_enum {
    ($name:ident, $label:literal, {$($variant:ident => $raw:literal),+ $(,)?}) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum $name { $($variant),+ }
        impl $name {
            pub fn parse(raw: &[u8]) -> $crate::circle_policy::Result<Self> {
                match raw { $($raw => Ok(Self::$variant),)+ _ => Err($crate::circle_policy::malformed([$label.as_slice(), raw].concat())) }
            }
            pub const fn as_bytes(self) -> &'static [u8] { match self { $(Self::$variant => $raw,)+ } }
        }
    };
}
pub(crate) use native_enum;
