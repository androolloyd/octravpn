// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{crypto, Error, Result};
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cipher {
    Empty,
    Proven,
    Legacy,
    Foreign,
    Malformed,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Key {
    Current,
    Historical,
    Missing,
    Malformed,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Route {
    Direct,
    Bound,
    History,
    Blocked,
}
pub(crate) struct Status {
    pub cipher: Cipher,
    pub key: Key,
    pub route: Route,
    pub reason: Vec<u8>,
}
impl Status {
    pub(crate) fn history(&self, active: bool) -> bool {
        self.route == Route::History
            || active && self.cipher == Cipher::Proven && self.key == Key::Missing
    }
}
pub(crate) fn cipher(raw: &[u8], cap: bool) -> Result<(Cipher, Vec<u8>)> {
    if raw.is_empty() || raw == b"0" {
        return Ok((Cipher::Empty, vec![]));
    }
    if !raw.starts_with(b"hfhe_v1|") || raw.len() <= 8 {
        return Ok((Cipher::Foreign, vec![]));
    }
    match crypto::decode_cipher(raw, false, cap) {
        Ok(value) => Ok((
            if value.has_key_bound_material() {
                Cipher::Proven
            } else {
                Cipher::Legacy
            },
            vec![],
        )),
        Err(crypto::Error::Rejected(reason)) => Ok((Cipher::Malformed, reason)),
        Err(crypto::Error::Unavailable(error)) => Err(Error::Unavailable(error.to_string())),
    }
}
pub(crate) fn status(raw: &[u8], public: Option<&[u8]>, cap: bool) -> Result<Status> {
    let (cipher, cipher_error) = cipher(raw, cap)?;
    let (key, key_error) = key(public)?;
    Ok(of_classes(cipher, cipher_error, key, key_error))
}
pub(crate) fn key(public: Option<&[u8]>) -> Result<(Key, Vec<u8>)> {
    Ok(match public {
        None => (Key::Missing, vec![]),
        Some(raw) => match crypto::load_pubkey(raw) {
            Ok(value) => (
                if value.supports_alias_rejection() {
                    Key::Current
                } else {
                    Key::Historical
                },
                vec![],
            ),
            Err(crypto::Error::Rejected(reason)) => (Key::Malformed, reason),
            Err(crypto::Error::Unavailable(error)) => {
                return Err(Error::Unavailable(error.to_string()))
            }
        },
    })
}
// Preserve the native owned-input and typed diagnostic interface.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn of_classes(
    cipher: Cipher,
    cipher_error: Vec<u8>,
    key: Key,
    key_error: Vec<u8>,
) -> Status {
    let (route, reason) = match (cipher, key) {
        (Cipher::Empty, _) => (Route::Direct, b"encrypted balance is empty".to_vec()),
        (Cipher::Proven, Key::Current) => (
            Route::Bound,
            b"key-bound encrypted balance can migrate with equality proofs".to_vec(),
        ),
        (Cipher::Proven, Key::Historical) => (
            Route::History,
            b"pvac pubkey proof circuit requires public or commitment history migration".to_vec(),
        ),
        (Cipher::Proven, Key::Missing) => (
            Route::Blocked,
            b"encrypted balance has no pvac pubkey".to_vec(),
        ),
        (Cipher::Proven, Key::Malformed) => (Route::Blocked, key_error),
        (Cipher::Legacy, _) => (
            Route::History,
            b"legacy hfhe balance needs public-history replay or ciphertext migration proof"
                .to_vec(),
        ),
        (Cipher::Foreign, _) => (Route::Blocked, b"encrypted balance is not hfhe".to_vec()),
        (Cipher::Malformed, _) => (
            Route::Blocked,
            [
                b"encrypted balance is malformed: ".as_slice(),
                &cipher_error,
            ]
            .concat(),
        ),
    };
    Status {
        cipher,
        key,
        route,
        reason,
    }
}
