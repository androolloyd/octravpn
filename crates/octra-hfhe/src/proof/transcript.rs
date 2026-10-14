// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native Bulletproof transcript framing and profile-specific scalar reduction.
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::generators::Point;
use crate::scalar::{Scalar, ScalarRule};

#[derive(Clone)]
pub struct Transcript {
    state: [u8; 64],
    pub rule: ScalarRule,
}

impl Drop for Transcript {
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

fn label_bytes(label: &[u8]) -> &[u8] {
    let length = label
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(label.len());
    // Native strlen is narrowed to uint32 before hashing the label bytes.
    &label[..length as u32 as usize]
}

impl Transcript {
    pub fn new(domain: &[u8], rule: ScalarRule) -> Self {
        let domain = label_bytes(domain);
        let mut output = Self {
            state: [0; 64],
            rule,
        };
        let mut hash = Sha256::new();
        // Exactly 18 bytes: the upstream explicit length excludes NUL.
        hash.update(b"pvac.bp.transcript");
        hash.update((domain.len() as u32).to_le_bytes());
        hash.update(domain);
        hash.finalize_into((&mut output.state[..32]).into());
        output.extend_state(1);
        output
    }

    fn extend_state(&mut self, tweak: u8) {
        let mut hash = Sha256::new();
        hash.update(&self.state[..32]);
        hash.update([tweak]);
        hash.finalize_into((&mut self.state[32..]).into());
    }

    fn mix(&mut self, label: &[u8], bytes: &[u8], operation: u8) {
        let label = label_bytes(label);
        let mut hash = Sha256::new();
        hash.update(self.state.as_slice());
        hash.update([operation]);
        hash.update((label.len() as u32).to_le_bytes());
        hash.update(label);
        // Empty native messages omit the length field altogether.
        if !bytes.is_empty() {
            hash.update((bytes.len() as u32).to_le_bytes());
            hash.update(bytes);
        }
        hash.finalize_into((&mut self.state[..32]).into());
        self.extend_state(0xff);
    }

    pub fn append_message(&mut self, label: &[u8], bytes: &[u8]) {
        self.mix(label, bytes, b'A');
    }

    pub fn append_u64(&mut self, label: &[u8], value: u64) {
        self.append_message(label, &value.to_le_bytes());
    }

    pub fn append_point(&mut self, label: &[u8], point: &Point) {
        // The native transcript binds the supplied encoding without decoding.
        self.append_message(label, point);
    }

    pub fn append_scalar(&mut self, label: &[u8], scalar: &Scalar) {
        self.append_message(label, Zeroizing::new(scalar.to_bytes()).as_ref());
    }

    pub fn challenge_scalar(&mut self, label: &[u8]) -> Scalar {
        self.mix(label, &[], b'C');
        let scalar = self.rule.reduce_bytes(&self.state);
        self.mix(b"post_challenge", &[], b'A');
        scalar
    }
}
