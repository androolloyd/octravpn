// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native token metadata, balance filtering and bounded public pages.
use crate::light_rpc::json::{array, boolean, null, number, object, string};
pub const MAX_SCAN_PROGRAMS: usize = 1024;
pub const MAX_PAGE_ROWS: usize = 128;
pub const MAX_PAGE_BYTES: usize = 131_072;
pub const PAGE_OVERHEAD_BYTES: usize = 512;
#[derive(Clone, Debug)]
pub struct Meta {
    pub address: Vec<u8>,
    pub owner: Vec<u8>,
    pub symbol: Vec<u8>,
    pub name: Vec<u8>,
    pub decimals: Vec<u8>,
    pub total_supply: Vec<u8>,
}
fn unsigned(value: &[u8], max_digits: usize, max: u128) -> bool {
    value.len() <= max_digits
        && !value.is_empty()
        && value.iter().all(u8::is_ascii_digit)
        && std::str::from_utf8(value)
            .ok()
            .and_then(|v| v.parse::<u128>().ok())
            .is_some_and(|v| v <= max)
}
pub fn u128(value: &[u8]) -> bool {
    unsigned(value, 39, u128::MAX)
}
pub fn decimal_places(value: &[u8]) -> bool {
    unsigned(value, 2, 18)
}
pub fn encrypted_balance(value: &[u8]) -> bool {
    !value.is_empty() && value.len() <= 96 * 1024 && crate::native_base64::decode(value).is_ok()
}
fn trim(value: &[u8], limit: usize) -> Vec<u8> {
    value[..value.len().min(limit)].to_vec()
}
impl Meta {
    pub fn new(
        address: &[u8],
        owner: &[u8],
        symbol: &[u8],
        name: Option<&[u8]>,
        decimals: Option<&[u8]>,
        total_supply: Option<&[u8]>,
    ) -> Option<Self> {
        let symbol = trim(symbol, 32);
        let name = trim(name.unwrap_or(&symbol), 64);
        let decimals = decimals.unwrap_or(b"0");
        let supply = total_supply.unwrap_or(b"0");
        if symbol.is_empty() || symbol == b"0" || !decimal_places(decimals) || !u128(supply) {
            return None;
        }
        Some(Self {
            address: address.to_vec(),
            owner: trim(owner, 64),
            symbol,
            name,
            decimals: decimals.to_vec(),
            total_supply: supply.to_vec(),
        })
    }
    pub fn row(&self, balance: &[u8]) -> Option<Vec<u8>> {
        let encrypted = if u128(balance) {
            if balance == b"0" {
                return None;
            }
            false
        } else if encrypted_balance(balance) {
            true
        } else {
            return None;
        };
        Some(object(&[
            ("address", string(&self.address)),
            ("name", string(&self.name)),
            ("symbol", string(&self.symbol)),
            ("total_supply", string(&self.total_supply)),
            ("balance", string(balance)),
            (
                "balance_kind",
                string(if encrypted {
                    b"encrypted".as_slice()
                } else {
                    b"plain"
                }),
            ),
            ("balance_is_encrypted", boolean(encrypted)),
            ("decimals", string(&self.decimals)),
            ("owner", string(&self.owner)),
        ]))
    }
}
pub struct Page {
    address: Vec<u8>,
    offset: usize,
    limit: usize,
    skip: usize,
    rows: Vec<Vec<u8>>,
    row_bytes: usize,
    limited: bool,
}
pub enum Added {
    Continue,
    Complete,
}
impl Page {
    pub fn new(address: Vec<u8>, offset: usize, limit: usize) -> Self {
        Self {
            address,
            offset,
            limit: limit.clamp(1, MAX_PAGE_ROWS),
            skip: offset,
            rows: vec![],
            row_bytes: 0,
            limited: false,
        }
    }
    pub fn add(&mut self, row: Vec<u8>) -> Added {
        if self.skip > 0 {
            self.skip -= 1;
            Added::Continue
        } else if self.rows.len() >= self.limit
            || self
                .row_bytes
                .saturating_add(row.len() + 1)
                .saturating_add(PAGE_OVERHEAD_BYTES)
                > MAX_PAGE_BYTES
        {
            self.limited = true;
            Added::Complete
        } else {
            self.row_bytes += row.len() + 1;
            self.rows.push(row);
            Added::Continue
        }
    }
    fn payload(&self, limited: bool) -> Vec<u8> {
        let limited = limited || self.limited;
        object(&[
            ("address", string(&self.address)),
            ("tokens", array(self.rows.iter().cloned())),
            ("count", number(self.rows.len())),
            ("offset", number(self.offset)),
            (
                "next_offset",
                if limited {
                    number(self.offset + self.rows.len())
                } else {
                    null()
                },
            ),
            ("limited", boolean(limited)),
        ])
    }
    pub fn finish(mut self, mut limited: bool) -> Vec<u8> {
        loop {
            let value = self.payload(limited);
            if value.len() <= MAX_PAGE_BYTES || self.rows.is_empty() {
                return value;
            }
            let row = self.rows.pop().expect("nonempty page");
            self.row_bytes = self.row_bytes.saturating_sub(row.len() + 1);
            limited = true;
        }
    }
}
