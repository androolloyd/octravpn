//! Small cross-crate utilities. Kept narrow on purpose — only things that
//! recur in three or more call sites belong here.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::{wallet_enc, CoreError, CoreResult};

/// HKDF-Expand a 32-byte master secret into a domain-separated 32-byte
/// child secret. The master should already be high-entropy (we don't
/// salt because the master is the wallet's root secret).
pub fn derive_subkey(master: &[u8; 32], domain: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut out = [0u8; 32];
    hk.expand(domain, &mut out)
        .expect("HKDF-Expand of 32 bytes always fits in one Sha256 block");
    out
}

pub const DOMAIN_RECEIPT_SIGN: &[u8] = b"octravpn-key-v1/receipt-sign-ed25519";
pub const DOMAIN_NOISE: &[u8] = b"octravpn-key-v1/noise-x25519";
pub const DOMAIN_VIEW: &[u8] = b"octravpn-key-v1/stealth-view";

/// Env var holding the passphrase for v1-encrypted wallet envelopes.
/// Honoured by `read_secret_32` when the file on disk has the v1 magic.
pub const WALLET_PASSPHRASE_ENV: &str = "OCTRAVPN_WALLET_PASSPHRASE";

/// Current wall-clock time as seconds since the Unix epoch.
/// Returns 0 if the system clock is before the epoch (impossible on a
/// correctly-configured machine, but we never want this to panic).
pub fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Decode a hex string into a fixed-size byte array. The input must be
/// exactly `2 * N` hex digits.
pub fn hex_to_array<const N: usize>(s: &str, what: &str) -> CoreResult<[u8; N]> {
    let bytes =
        hex::decode(s).map_err(|e| CoreError::InvalidEncoding(format!("{what} hex: {e}")))?;
    if bytes.len() != N {
        return Err(CoreError::InvalidLength {
            expected: N,
            actual: bytes.len(),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Read a 32-byte secret from disk. Accepts:
///   - a v1 encrypted envelope (passphrase from `WALLET_PASSPHRASE_ENV`)
///   - raw 32 bytes
///   - 64 hex digits (with optional trailing whitespace)
pub fn read_secret_32(path: &str) -> CoreResult<[u8; 32]> {
    let raw =
        std::fs::read(path).map_err(|e| CoreError::InvalidEncoding(format!("read {path}: {e}")))?;
    if wallet_enc::looks_like_envelope(&raw) {
        let pass = std::env::var(WALLET_PASSPHRASE_ENV).map_err(|_| {
            CoreError::InvalidEncoding(format!(
                "{path} is encrypted; set {WALLET_PASSPHRASE_ENV} to decrypt"
            ))
        })?;
        return wallet_enc::decrypt_secret(&raw, &pass);
    }
    if raw.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        return Ok(out);
    }
    let s = std::str::from_utf8(&raw)
        .map_err(|e| CoreError::InvalidEncoding(format!("non-utf8 secret: {e}")))?
        .trim();
    hex_to_array::<32>(s, "secret file")
}

/// Env var: set to `json` to emit JSON-formatted logs.
pub const LOG_FORMAT_ENV: &str = "OCTRAVPN_LOG_FORMAT";

/// Initialise `tracing` for a daemon binary writing to stdout. Honours
/// `RUST_LOG` (via `EnvFilter`) and `OCTRAVPN_LOG_FORMAT=json` for
/// structured output. Safe to call exactly once from `main`.
pub fn init_tracing(default_filter: &str) {
    let filter = build_env_filter(default_filter);
    if json_logs() {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

/// Same as `init_tracing` but writes to stderr — appropriate for CLI
/// tools where stdout is reserved for command output.
pub fn init_tracing_stderr(default_filter: &str) {
    let filter = build_env_filter(default_filter);
    if json_logs() {
        tracing_subscriber::fmt()
            .json()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .init();
    }
}

fn build_env_filter(default: &str) -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default))
}

fn json_logs() -> bool {
    std::env::var(LOG_FORMAT_ENV).as_deref() == Ok("json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_to_array_round_trip() {
        let bytes: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
        let arr: [u8; 4] = hex_to_array(&hex::encode(bytes), "test").unwrap();
        assert_eq!(arr, bytes);
    }

    #[test]
    fn hex_to_array_rejects_wrong_length() {
        let ok: CoreResult<[u8; 2]> = hex_to_array("dead", "test");
        assert!(ok.is_ok());
        let too_short: CoreResult<[u8; 8]> = hex_to_array("dead", "test");
        assert!(too_short.is_err());
        let too_long: CoreResult<[u8; 1]> = hex_to_array("dead", "test");
        assert!(too_long.is_err());
    }

    // Run both env-var paths in one test so they don't race over the
    // shared `OCTRAVPN_WALLET_PASSPHRASE` global. Cargo runs tests in
    // parallel by default.
    #[test]
    fn read_secret_32_envelope_paths() {
        let secret = [42u8; 32];
        let enc = wallet_enc::encrypt_secret_with_iters(&secret, "pw", 100);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.enc");
        std::fs::write(&path, &enc).unwrap();
        let path_str = path.to_str().unwrap();

        std::env::remove_var(WALLET_PASSPHRASE_ENV);
        assert!(read_secret_32(path_str).is_err());

        std::env::set_var(WALLET_PASSPHRASE_ENV, "pw");
        let got = read_secret_32(path_str).unwrap();
        std::env::remove_var(WALLET_PASSPHRASE_ENV);
        assert_eq!(got, secret);
    }
}
