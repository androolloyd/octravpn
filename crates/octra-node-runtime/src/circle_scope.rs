// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Host-owned HFHE context, matching the optional native execution fields.
//! This capability is deliberately not a deserializable transaction/RPC input.
use octra_hfhe::keys::{PublicKey, SecretKey};
use std::{fmt, sync::Arc};
#[derive(Clone, Default)]
pub struct Scope {
    pub(crate) key: Option<Vec<u8>>,
    pub(crate) intent: Option<Vec<u8>>,
    pub(crate) relay: Option<Vec<u8>>,
    pub(crate) pair: Option<KeyPair>,
}
#[derive(Clone)]
pub(crate) struct KeyPair {
    pub public: Arc<PublicKey>,
    pub secret: Arc<SecretKey>,
}
impl Scope {
    pub fn new(key: Option<Vec<u8>>, intent: Option<Vec<u8>>, relay: Option<Vec<u8>>) -> Self {
        Self {
            key,
            intent,
            relay,
            pair: None,
        }
    }
    /// Supplying material does not bypass the scoped key policy or HFHE modes.
    pub fn with_keypair(mut self, public: Arc<PublicKey>, secret: Arc<SecretKey>) -> Self {
        self.pair = Some(KeyPair { public, secret });
        self
    }
}
impl fmt::Debug for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scope")
            .field("key", &self.key)
            .field("intent", &self.intent)
            .field("relay", &self.relay)
            .field("keypair_present", &self.pair.is_some())
            .finish()
    }
}
