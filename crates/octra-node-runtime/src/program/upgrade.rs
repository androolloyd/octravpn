// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! State-bound owner and code-hash checks before staging a binary upgrade.
use super::{journal, store, Error, Journal, Result};
use crate::state_batch::Snapshot;
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    aml::compiler::LANG_VERSION, octb::program, program_trust::Keys, program_upgrade::Upgrade,
};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Changed {
    pub old_code_hash: Vec<u8>,
    pub new_code_hash: Vec<u8>,
}
pub fn stage(
    journal: &mut Journal,
    state: &Snapshot,
    trusted: &Keys,
    point_ops: bool,
    address: &[u8],
    caller: &[u8],
    payload: &Upgrade,
) -> Result<Changed> {
    if journal.find_upgrade(address).is_some() {
        return Err(Error::rejected("program upgrade already staged"));
    }
    if journal.find_deploy(address).is_some() {
        return Err(Error::rejected("staged program cannot be upgraded"));
    }
    let mut meta =
        store::meta(state, address)?.ok_or_else(|| Error::rejected("program not found"))?;
    if meta.owner != caller {
        return Err(Error::rejected("only the program owner can upgrade"));
    }
    if meta.code_hash != payload.expected_code_hash {
        return Err(Error::rejected("program upgrade code hash mismatch"));
    }
    program::decode(&payload.bytecode, point_ops, trusted)?;
    let new_code_hash = hex::encode(Sha256::digest(&payload.bytecode)).into_bytes();
    if new_code_hash == meta.code_hash {
        return Err(Error::rejected("program upgrade bytecode unchanged"));
    }
    let old_code_hash = std::mem::replace(&mut meta.code_hash, new_code_hash.clone());
    // Native staging uses the requested address, even if old metadata carried
    // another address. Ownership and the expected hash were checked above.
    meta.address = address.to_vec();
    meta.admission = b"binary".to_vec();
    meta.version = LANG_VERSION.to_vec();
    journal.add_upgrade(journal::Upgrade {
        meta,
        expected_code_hash: payload.expected_code_hash.clone(),
        bytecode: STANDARD.encode(&payload.bytecode).into_bytes(),
    });
    Ok(Changed {
        old_code_hash,
        new_code_hash,
    })
}
