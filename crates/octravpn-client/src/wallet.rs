//! Wallet I/O — reads a 32-byte secret from disk (raw or hex) and exposes
//! the keypair. Wallet-level encryption is left to the user (the secret
//! file should be on disk only behind OS-level protections).

use anyhow::{Context, Result};
use octravpn_core::{sig::KeyPair, util};

pub(crate) fn load_keypair(secret_path: &str) -> Result<KeyPair> {
    let bytes = util::read_secret_32(secret_path)
        .with_context(|| format!("load wallet secret {secret_path}"))?;
    Ok(KeyPair::from_secret_bytes(&bytes))
}
