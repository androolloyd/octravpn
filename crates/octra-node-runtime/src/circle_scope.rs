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
    pub public: Arc<crate::crypto_worker::Key>,
    pub secret: Arc<zeroize::Zeroizing<Vec<u8>>>,
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
    /// Material is explicitly trusted, expanded host configuration. Serialize
    /// it once here, before an untrusted invocation starts its native deadline.
    /// Execution retains only immutable images; secret bytes are zeroizing and
    /// neither this capability nor its material is exposed through Debug.
    pub fn with_keypair(
        mut self,
        public: &PublicKey,
        secret: &SecretKey,
    ) -> Result<Self, octra_hfhe::Error> {
        let public = Arc::new(crate::crypto_worker::Key::from_public_key(public)?);
        let secret = Arc::new(secret.to_bytes());
        self.pair = Some(KeyPair { public, secret });
        Ok(self)
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
