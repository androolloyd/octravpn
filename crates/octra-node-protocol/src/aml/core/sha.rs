// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_sha raw SHA-256 digest; this grants no artifact admission authority.
use sha2::{Digest, Sha256};
pub fn hash(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}
