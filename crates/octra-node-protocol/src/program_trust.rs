// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Configured program release keys and their native network fingerprint.
use crate::{
    native_base64,
    network::{self, endpoint::native_trim},
    oce1::Error,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
#[derive(Clone, Debug, Default)]
pub struct Keys(BTreeMap<Vec<u8>, Vec<u8>>);
impl Keys {
    pub fn parse(raw: Option<&[u8]>) -> Result<Self, Error> {
        let mut keys = BTreeMap::new();
        let Some(raw) = raw.filter(|v| !native_trim(v).is_empty()) else {
            return Ok(Self(keys));
        };
        for entry in raw.split(|b| *b == b',') {
            let pos = entry
                .iter()
                .position(|b| *b == b'=')
                .ok_or("invalid program release key entry")?;
            let id = native_trim(&entry[..pos]);
            let encoded = native_trim(&entry[pos + 1..]);
            if id.is_empty() || id.len() > 64 || !id.iter().all(|b| (33..=126).contains(b)) {
                return Err("invalid program release key id".into());
            }
            let public = native_base64::decode(encoded)
                .map_err(|_| Error::from("invalid program release public key"))?;
            if public.len() != 32 || !network::public_key_safe(&public) {
                return Err("invalid program release public key".into());
            }
            if keys.insert(id.to_vec(), public).is_some() {
                return Err("duplicate program release key id".into());
            }
        }
        Ok(Self(keys))
    }
    pub fn public_key(&self, id: &[u8]) -> Option<&[u8]> {
        self.0.get(id).map(Vec::as_slice)
    }
    pub fn fingerprint(&self) -> [u8; 32] {
        fn frame(hash: &mut Sha256, value: &[u8]) {
            hash.update(value.len().to_string().as_bytes());
            hash.update(b":");
            hash.update(value);
        }
        let mut hash = Sha256::new();
        frame(&mut hash, b"octra:program_trust:v1");
        for (id, key) in &self.0 {
            frame(&mut hash, id);
            frame(&mut hash, key);
        }
        hash.finalize().into()
    }
    pub fn config_hash(&self) -> Option<Vec<u8>> {
        (!self.0.is_empty()).then(|| self.fingerprint().to_vec())
    }
}
