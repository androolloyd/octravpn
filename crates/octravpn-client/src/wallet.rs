//! Wallet I/O — reads a 32-byte secret from disk (raw or hex) and exposes
//! the keypair. Wallet-level encryption is left to the user (the secret
//! file should be on disk only behind OS-level protections).

use std::fs;

use anyhow::{anyhow, Context, Result};
use octravpn_core::sig::KeyPair;

pub fn load_keypair(secret_path: &str) -> Result<KeyPair> {
    let raw = fs::read(secret_path)
        .with_context(|| format!("read wallet secret {secret_path}"))?;
    let bytes = if raw.len() == 32 {
        raw
    } else {
        let s = std::str::from_utf8(&raw)
            .map_err(|e| anyhow!("non-utf8 wallet secret: {e}"))?
            .trim()
            .to_string();
        hex::decode(&s).context("decode hex wallet secret")?
    };
    if bytes.len() != 32 {
        return Err(anyhow!("wallet secret must be 32 bytes"));
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes);
    Ok(KeyPair::from_secret_bytes(&k))
}
