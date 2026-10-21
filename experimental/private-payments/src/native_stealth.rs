//! Octra wallet V5 payload codec. This uses native AES-GCM, its direct ECDH
//! key, little-endian amount and native Ed25519-to-X25519 view derivation.
//! No payment is authenticated by decoding an encrypted amount alone.
use anyhow::{ensure, Context, Result};
use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const PAYLOAD_LEN: usize = 68;

/// Secret-bearing values deliberately have no Debug or serialization support.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Amount {
    value: u64,
    blinding: [u8; 32],
}
impl Amount {
    pub fn new(value: u64, blinding: [u8; 32]) -> Self {
        Self { value, blinding }
    }
    pub fn value(&self) -> u64 {
        self.value
    }
    pub fn blinding(&self) -> &[u8; 32] {
        &self.blinding
    }
}

/// Native wallet derivation from the 32-byte Ed25519 seed. The older VPN
/// view-key derivation has a different domain and is not substituted here.
pub fn view_secret(seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut hash = Sha512::digest(seed);
    let mut secret = Zeroizing::new([0_u8; 32]);
    secret.copy_from_slice(&hash[..32]);
    let hash_bytes: &mut [u8] = hash.as_mut();
    hash_bytes.zeroize();
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
    secret
}

pub fn view_public(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

/// Native shared-key bytes, with a stricter refusal of low-order peers.
pub fn shared(secret: &[u8; 32], peer: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let dh = StaticSecret::from(*secret).diffie_hellman(&PublicKey::from(*peer));
    ensure!(dh.was_contributory(), "non-contributory stealth peer");
    Ok(Zeroizing::new(Sha256::digest(dh.as_bytes()).into()))
}

pub fn tag(shared: &[u8; 32]) -> [u8; 16] {
    let hash = digest(shared, b"", b"OCTRA_STEALTH_TAG_V1");
    hash[..16].try_into().expect("fixed SHA256 prefix")
}

pub fn claim_secret(shared: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(digest(shared, b"", b"OCTRA_CLAIM_SECRET_V1"))
}

/// Address validity and the invoice recipient must be checked by admission.
pub fn claim_public(secret: &[u8; 32], recipient: &[u8]) -> [u8; 32] {
    digest(secret, recipient, b"OCTRA_CLAIM_BIND_V1")
}

fn digest(secret: &[u8; 32], middle: &[u8], domain: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(secret);
    hash.update(middle);
    hash.update(domain);
    hash.finalize().into()
}

fn key(shared: &[u8; 32]) -> Result<LessSafeKey> {
    Ok(LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, shared)
            .map_err(|_| anyhow::anyhow!("invalid stealth key"))?,
    ))
}

pub fn seal(shared: &[u8; 32], amount: &Amount) -> Result<String> {
    let mut nonce = [0_u8; 12];
    OsRng
        .try_fill_bytes(&mut nonce)
        .context("stealth nonce entropy unavailable")?;
    seal_with_nonce(shared, amount, nonce)
}

// Kept private: callers cannot supply or accidentally reuse an AES-GCM nonce.
fn seal_with_nonce(shared: &[u8; 32], amount: &Amount, nonce: [u8; 12]) -> Result<String> {
    let mut body = Zeroizing::new(Vec::with_capacity(56));
    body.extend_from_slice(&amount.value.to_le_bytes());
    body.extend_from_slice(&amount.blinding);
    key(shared)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::empty(),
            &mut *body,
        )
        .map_err(|_| anyhow::anyhow!("stealth encryption failed"))?;
    let mut output = Vec::with_capacity(PAYLOAD_LEN);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&body);
    Ok(STANDARD.encode(output))
}

pub fn open(shared: &[u8; 32], encoded: &str) -> Result<Amount> {
    // The canonical native encoding of 68 bytes occupies exactly 92 bytes.
    ensure!(encoded.len() == 92, "invalid stealth payload size");
    let raw = STANDARD
        .decode(encoded)
        .context("invalid stealth payload encoding")?;
    ensure!(raw.len() == PAYLOAD_LEN, "invalid stealth payload size");
    let nonce = raw[..12].try_into().expect("checked nonce length");
    let mut body = Zeroizing::new(raw[12..].to_vec());
    let key = key(shared)?;
    let plaintext = key
        .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut body)
        .map_err(|_| anyhow::anyhow!("stealth payload authentication failed"))?;
    ensure!(plaintext.len() == 40, "invalid stealth plaintext size");
    let value = u64::from_le_bytes(plaintext[..8].try_into().expect("checked amount length"));
    let blinding = plaintext[8..].try_into().expect("checked blinding length");
    Ok(Amount::new(value, blinding))
}

#[cfg(test)]
mod tests;
