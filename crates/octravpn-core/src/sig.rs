//! Ed25519 signing for ephemeral session keys and node receipt keys.
//!
//! These are *not* the user's main wallet key — that one stays untouched.
//! For each session we generate a fresh ephemeral keypair so the chain
//! never sees the wallet pubkey alongside session activity.

use ed25519_dalek::{Signature as DalekSig, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use zeroize::Zeroize;

use crate::{CoreError, CoreResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey(pub [u8; 32]);

#[serde_as]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(#[serde_as(as = "Bytes")] pub [u8; 64]);

/// Wrapper that zeroizes secret material on drop.
pub struct KeyPair {
    secret: SigningKey,
    pub public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let secret = SigningKey::generate(&mut OsRng);
        let public = PublicKey(secret.verifying_key().to_bytes());
        Self { secret, public }
    }

    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        let secret = SigningKey::from_bytes(bytes);
        let public = PublicKey(secret.verifying_key().to_bytes());
        Self { secret, public }
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.secret.sign(msg).to_bytes())
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        // SigningKey already zeroizes on drop in dalek 2.x; this is for
        // belt-and-suspenders in case we change backends.
        let mut bytes = self.secret.to_bytes();
        bytes.zeroize();
    }
}

/// Verify an ed25519 signature.
pub fn verify(pubkey: &PublicKey, msg: &[u8], sig: &Signature) -> CoreResult<()> {
    let vk = VerifyingKey::from_bytes(&pubkey.0)
        .map_err(|e| CoreError::Crypto(format!("bad pubkey: {e}")))?;
    let s = DalekSig::from_bytes(&sig.0);
    vk.verify(msg, &s)
        .map_err(|e| CoreError::Crypto(format!("verify: {e}")))
}
