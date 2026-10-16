//! Private node identities. Key generation is explicit and never replaces a key.
use anyhow::{ensure, Result};
use ed25519_dalek::SigningKey;
use std::path::Path;
#[allow(clippy::verbose_bit_mask)] // The octal mask directly expresses private Unix permission bits.
pub fn read(path: &Path) -> Result<SigningKey> {
    #[cfg(unix)]
    {
        use std::io::Read;
        use std::os::unix::fs::PermissionsExt;
        let mut file: std::fs::File = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )?
        .into();
        let meta = file.metadata()?;
        ensure!(
            meta.is_file() && meta.len() == 32 && meta.permissions().mode() & 0o077 == 0,
            "validator key must be a private 32-byte regular file"
        );
        let mut bytes = zeroize::Zeroizing::new([0; 32]);
        file.read_exact(bytes.as_mut())?;
        Ok(SigningKey::from_bytes(&bytes))
    }
    #[cfg(not(unix))]
    anyhow::bail!("node keys require Unix file permissions")
}

/// Write a fresh private key and return only its public identity.
pub fn create(path: &Path) -> Result<serde_json::Value> {
    use base64::Engine;
    use rand::RngCore;
    let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.try_fill_bytes(bytes.as_mut())?;
    let key = SigningKey::from_bytes(&bytes);
    crate::storage::publish(path, bytes.as_ref())?;
    let public = base64::engine::general_purpose::STANDARD.encode(key.verifying_key().as_bytes());
    let address = String::from_utf8(octra_node_protocol::transaction::address_from_public_key(
        public.as_bytes(),
    ))?;
    Ok(serde_json::json!({"address":address,"public_key":public,"key_path":path}))
}
