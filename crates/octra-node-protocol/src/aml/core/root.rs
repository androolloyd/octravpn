// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_root binds canonical program bits, a prior root and canonical session
//! state. This local artifact hash does not establish consensus finality.
use super::{program_codec, source_binary, term::Terms, types::Types};
use sha2::{Digest, Sha256};

/// Native root images use a big-endian 64-bit bit count and MSB-first packing,
/// without the generic binary transport header or its separate size profile.
pub fn image(input: &[bool]) -> Vec<u8> {
    let mut out = vec![0; 8 + input.len().div_ceil(8)];
    out[..8].copy_from_slice(&(input.len() as u64).to_be_bytes());
    for (index, bit) in input.iter().enumerate() {
        if *bit {
            out[8 + index / 8] |= 1 << (7 - index % 8);
        }
    }
    out
}
pub fn root(program: &[bool], prior: &[u8], state: &[bool]) -> Option<[u8; 32]> {
    let mut types = Types::default();
    let mut terms = Terms::default();
    program_codec::decode(&mut types, &mut terms, program)?;
    let decoded = source_binary::decode_state(state)?;
    let program_image = image(program);
    if prior.len() != 32
        || decoded.scope().program() != program_image
        || decoded.scope().root() != prior
    {
        return None;
    }
    let mut hash = Sha256::new();
    hash.update(b"AML2ROOT\x01");
    hash.update(program_image);
    hash.update(prior);
    hash.update(image(state));
    Some(hash.finalize().into())
}
