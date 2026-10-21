//! Private local storage, separate from native payment and tunnel wire formats.
//! XChaCha20-Poly1305 seals the whole record with a fresh 192-bit nonce; the
//! caller's immutable scope is authenticated but never written as plaintext.
use anyhow::{ensure, Context, Result};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"OVPNSE01";
pub const OVERHEAD: usize = 8 + 24 + 16;
const MAX_RECORD: usize = 64 * 1024 * 1024;

/// Deliberately no Debug or generic serialization. Key custody belongs to the
/// host; do not save this key alongside exported encrypted wallet backups.
#[derive(Clone)]
pub struct Key(Zeroizing<[u8; 32]>);
impl Key {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
    pub fn random() -> Result<Self> {
        let mut bytes = Zeroizing::new([0; 32]);
        OsRng
            .try_fill_bytes(&mut *bytes)
            .context("private storage entropy unavailable")?;
        Ok(Self(bytes))
    }
    pub fn derive_bytes(&self, label: &[u8], context: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        ensure!(
            label.len() <= 256 && context.len() <= 4096,
            "private key context exceeds bound"
        );
        let mut info = b"Octranet private storage keys v1\0".to_vec();
        info.extend_from_slice(&(label.len() as u64).to_be_bytes());
        info.extend_from_slice(label);
        info.extend_from_slice(context);
        let mut key = Zeroizing::new([0; 32]);
        Hkdf::<Sha256>::new(None, self.0.as_ref())
            .expand(&info, &mut *key)
            .map_err(|_| anyhow::anyhow!("private key derivation failed"))?;
        Ok(key)
    }
    pub fn derive(&self, label: &[u8], context: &[u8]) -> Result<Self> {
        Ok(Self(self.derive_bytes(label, context)?))
    }
}

#[derive(Clone)]
pub struct Protection {
    key: Key,
    scope: [u8; 32],
}
impl Protection {
    pub fn new(key: Key, scope: [u8; 32]) -> Self {
        Self { key, scope }
    }
    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new((&*self.key.0).into())
    }
    fn aad(&self) -> Vec<u8> {
        [MAGIC.as_slice(), &self.scope].concat()
    }
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            plaintext.len() <= MAX_RECORD,
            "private record exceeds bound"
        );
        let mut nonce = [0; 24];
        OsRng
            .try_fill_bytes(&mut nonce)
            .context("private record entropy unavailable")?;
        let mut body = Zeroizing::new(plaintext.to_vec());
        self.cipher()
            .encrypt_in_place(XNonce::from_slice(&nonce), &self.aad(), &mut *body)
            .map_err(|_| anyhow::anyhow!("private record encryption failed"))?;
        Ok([MAGIC.as_slice(), &nonce, body.as_slice()].concat())
    }
    pub fn open(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            (OVERHEAD..=MAX_RECORD + OVERHEAD).contains(&ciphertext.len())
                && ciphertext.get(..8) == Some(MAGIC),
            "invalid private record format"
        );
        let mut body = Zeroizing::new(ciphertext[32..].to_vec());
        self.cipher()
            .decrypt_in_place(
                XNonce::from_slice(&ciphertext[8..32]),
                &self.aad(),
                &mut *body,
            )
            .map_err(|_| anyhow::anyhow!("private record authentication failed"))?;
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scope_key_and_every_ciphertext_byte_are_authenticated() {
        let key = Key::from_bytes([7; 32]);
        let protected = Protection::new(key.clone(), [8; 32]);
        let message = b"private receipt relationship and balance";
        let first = protected.seal(message).unwrap();
        assert_eq!(&*protected.open(&first).unwrap(), message);
        assert_ne!(first, protected.seal(message).unwrap());
        assert!(!first.windows(message.len()).any(|part| part == message));
        for offset in 0..first.len() {
            let mut changed = first.clone();
            changed[offset] ^= 1;
            assert!(protected.open(&changed).is_err());
        }
        assert!(Protection::new(key, [9; 32]).open(&first).is_err());
        assert!(Protection::new(Key::from_bytes([6; 32]), [8; 32])
            .open(&first)
            .is_err());
        for length in 0..OVERHEAD {
            assert!(protected.open(&first[..length]).is_err());
        }
    }
    #[test]
    fn child_keys_separate_labels_and_scope_without_exporting_the_master() {
        let key = Key::from_bytes([1; 32]);
        assert_eq!(
            key.derive_bytes(b"claimant", b"one").unwrap(),
            key.derive_bytes(b"claimant", b"one").unwrap()
        );
        assert_ne!(
            key.derive_bytes(b"claimant", b"one").unwrap(),
            key.derive_bytes(b"spend", b"one").unwrap()
        );
        assert_ne!(
            key.derive_bytes(b"claimant", b"one").unwrap(),
            key.derive_bytes(b"claimant", b"two").unwrap()
        );
    }
}
