//! Cheatcodes for wallets, signatures, address labeling.
//!
//! Foundry analogues:
//!   - `addr(privateKey)` → [`addr_from_secret`]
//!   - `createWallet(label)` → [`Wallet::create_labeled`]
//!   - `sign(privateKey, hash)` → [`sign`]
//!   - `label(addr, name)` / `getLabel(addr)` → [`ForgeCtx::label`]
//!
//! Labels are useful for trace output: a test that pranks
//! `"oct..."` and gets `Validator(0xabcd…)` in the trace is easier to
//! read when labels exist.

use std::collections::HashMap;

use octravpn_core::{
    address::Address,
    sig::{KeyPair, Signature},
};

/// Generate a fresh keypair labeled `name`.
#[derive(Clone, Debug)]
pub struct Wallet {
    pub label: String,
    pub address: Address,
    pub secret_hex: String,
    pub public_hex: String,
}

impl Wallet {
    /// Create a fresh wallet with the given label. The keypair is
    /// generated from OS entropy; the secret is exposed only here for
    /// the test's convenience.
    pub fn create_labeled(label: impl Into<String>) -> (Self, KeyPair) {
        let kp = KeyPair::generate();
        let address = Address::from_pubkey(&kp.public.0);
        let w = Self {
            label: label.into(),
            address,
            secret_hex: hex::encode(kp.secret_bytes()),
            public_hex: hex::encode(kp.public.0),
        };
        (w, kp)
    }
}

/// Sign an arbitrary message with the given keypair. Mirrors Foundry's
/// `vm.sign(privateKey, hash)`.
pub fn sign(kp: &KeyPair, message: &[u8]) -> Signature {
    kp.sign(message)
}

/// Recover the Octra address corresponding to an ed25519 public key.
/// Foundry analogue: `vm.addr(privateKey)` — but we take a public key
/// because the conversion is `Address::from_pubkey(pubkey)`.
pub fn addr_from_pubkey(public: &[u8; 32]) -> Address {
    Address::from_pubkey(public)
}

/// Convenience: keypair → address.
pub fn addr_from_keypair(kp: &KeyPair) -> Address {
    addr_from_pubkey(&kp.public.0)
}

/// Cheatcode-side address label registry. The `ForgeCtx` holds one of
/// these so test output can render `oct...XYZ` as `Alice` etc.
#[derive(Clone, Debug, Default)]
pub struct LabelTable {
    map: HashMap<String, String>,
}

impl LabelTable {
    pub fn label(&mut self, addr: impl Into<String>, name: impl Into<String>) {
        self.map.insert(addr.into(), name.into());
    }

    pub fn get(&self, addr: &str) -> Option<&str> {
        self.map.get(addr).map(String::as_str)
    }

    /// Format an address as `Label (oct...prefix…suffix)` if known,
    /// otherwise the bare address.
    pub fn pretty(&self, addr: &str) -> String {
        if let Some(name) = self.get(addr) {
            let short = if addr.len() > 12 {
                format!("{}…{}", &addr[..6], &addr[addr.len() - 4..])
            } else {
                addr.to_string()
            };
            format!("{name} ({short})")
        } else {
            addr.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_labeled_round_trip() {
        let (w, kp) = Wallet::create_labeled("alice");
        assert_eq!(w.label, "alice");
        let derived = Address::from_pubkey(&kp.public.0);
        assert_eq!(derived.display(), w.address.display());
    }

    #[test]
    fn sign_verify_round_trip() {
        let kp = KeyPair::generate();
        let msg = b"forge sign test";
        let sig = sign(&kp, msg);
        octravpn_core::sig::verify(&kp.public, msg, &sig).unwrap();
    }

    #[test]
    fn labels_pretty_print() {
        let mut t = LabelTable::default();
        let addr = Address::from_pubkey(&[1u8; 32]);
        t.label(addr.display().to_string(), "alice".to_string());
        let pretty = t.pretty(addr.display());
        assert!(pretty.contains("alice"));
    }
}
