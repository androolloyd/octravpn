//! `cast wallet ...` — keygen, signing, address derivation.
//!
//! Wallet files are 64-char hex on a single line. This keeps tooling
//! interop with `octra_pre_client` and the C++ wallet trivial and stays
//! human-readable; it's *not* the production wallet format and shouldn't
//! be used to hold real funds.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Subcommand;
use octravpn_core::{address::Address, sig::KeyPair};
use serde_json::json;

use crate::io::{dump_json, read_secret_hex, write_to};

#[derive(Subcommand, Debug)]
pub enum WalletCmd {
    /// Generate a fresh ed25519 keypair.
    New {
        /// Output path for the 32-byte hex secret. If omitted, prints
        /// the secret + address to stdout (the secret is on stderr).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Sign arbitrary bytes with a key file.
    Sign {
        #[arg(long, env = "OCTRA_KEY_FILE")]
        key: PathBuf,
        /// Message to sign. If it parses as hex (with or without `0x`),
        /// the decoded bytes are signed; otherwise the raw UTF-8 bytes.
        message: String,
    },
    /// Derive the `oct...` address from a key file.
    Addr {
        #[arg(long, env = "OCTRA_KEY_FILE")]
        key: PathBuf,
    },
}

pub fn dispatch(cmd: WalletCmd) -> Result<()> {
    match cmd {
        WalletCmd::New { out } => new_wallet(out.as_deref()),
        WalletCmd::Sign { key, message } => sign_message(&key, &message),
        WalletCmd::Addr { key } => print_address(&key),
    }
}

fn new_wallet(out: Option<&Path>) -> Result<()> {
    let kp = KeyPair::generate();
    let secret = hex::encode(kp.secret_bytes());
    let addr = Address::from_pubkey(&kp.public.0).display().to_string();
    let public = hex::encode(kp.public.0);
    if let Some(p) = out {
        write_to(p, &secret).context("write wallet")?;
        // Mode bits aren't enforced on Windows, but on Unix the file
        // contains a private key, so tighten read perms.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
        }
        // On disk we wrote only the secret; print summary as JSON for
        // pipeline-friendliness.
        dump_json(&json!({
            "path": p.display().to_string(),
            "address": addr,
            "public_key": public,
        }));
    } else {
        // Print to stdout in a wallet-friendly shape; the secret is
        // intentionally on stderr so naive `> wallet.json` redirection
        // doesn't leak it into a shared log file.
        eprintln!("{secret}");
        dump_json(&json!({
            "address": addr,
            "public_key": public,
        }));
    }
    Ok(())
}

fn sign_message(key: &Path, msg: &str) -> Result<()> {
    let secret = read_secret_hex(key)?;
    let kp = KeyPair::from_secret_bytes(&secret);
    let bytes = decode_hex_or_utf8(msg);
    let sig = kp.sign(&bytes);
    println!("{}", STANDARD.encode(sig.0));
    Ok(())
}

fn print_address(key: &Path) -> Result<()> {
    let secret = read_secret_hex(key)?;
    let kp = KeyPair::from_secret_bytes(&secret);
    let addr = Address::from_pubkey(&kp.public.0).display().to_string();
    println!("{addr}");
    Ok(())
}

fn decode_hex_or_utf8(s: &str) -> Vec<u8> {
    let stripped = s.trim().trim_start_matches("0x");
    if stripped.is_empty() {
        return Vec::new();
    }
    if stripped.len() % 2 == 0 && stripped.chars().all(|c| c.is_ascii_hexdigit()) {
        return hex::decode(stripped).unwrap_or_else(|_| s.as_bytes().to_vec());
    }
    s.as_bytes().to_vec()
}

/// Public re-export so tests can roundtrip without parsing CLI args.
pub fn derive_address(secret_hex: &str) -> Result<String> {
    let bytes = hex::decode(secret_hex.trim().trim_start_matches("0x"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("secret must be 32 bytes"));
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes);
    let kp = KeyPair::from_secret_bytes(&k);
    Ok(Address::from_pubkey(&kp.public.0).display().to_string())
}
