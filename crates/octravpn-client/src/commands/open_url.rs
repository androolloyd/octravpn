//! `octravpn open-url <oct-url>` — OS protocol handler for `oct://`.
//!
//! Stub. Does not yet wire up the actual fetch/decrypt; that lands in a
//! follow-up. See `docs/oct-url-handler.md` for the design and the
//! security model.
//!
//! ## Translation pipeline (target behaviour, not yet wired)
//!
//! `oct://<circle_id>/<canonical_path>` resolves to a sealed asset
//! inside an Octra circle. The Rust translation is already implemented
//! in this repo:
//!
//!   - `octravpn_core::circle::resource_key(circle_id, canonical_path)`
//!     — exactly mirrors the upstream `octra-labs/webcli`
//!     `static/circles.html` (commit `f9c73e1`) JS impl, per
//!     `octra-core/src/circle.rs:1-25`.
//!   - JSON-RPC `circle_asset_ciphertext_by_resource_key([circle, rkey])`
//!     returns `{ ciphertext_b64, plaintext_hash, key_id }`.
//!   - `octravpn_core::circle::decrypt_sealed_bytes(...)` reverses the
//!     `OCRS1` AES-256-GCM envelope (PBKDF2-HMAC-SHA256, 120 000 iters).
//!
//! See `crates/octravpn-client/src/discover_v2.rs:244-345` for the
//! exact RPC + decrypt call sequence we will re-use here.
//!
//! ## Security defaults (see design doc §"Security model")
//!
//! For the MVP and indefinitely until we explicitly relax it:
//!
//!   - Confirm with the user before any fetch (native dialog,
//!     terminal fallback).
//!   - Render the decrypted bytes in a sandboxed viewer; NEVER hand a
//!     raw blob to the OS "default app for this MIME type".
//!   - Refuse `oct://` URLs that are not well-formed
//!     (`oct://<circle>/<path>`, `circle` matches Octra address regex).
//!   - Default to **tunnel-required**: if no `utun*` interface bound
//!     to an OctraVPN tailnet IP exists, refuse and tell the user to
//!     run `octravpn connect-v3` first.

use anyhow::{anyhow, Result};
use clap::Parser;

/// Clap-facing subcommand for the OS protocol handler.
///
/// Wired in by `main.rs` as e.g.
///
/// ```ignore
/// Cmd::OpenUrl(args) => commands::open_url::run(args),
/// ```
///
/// The signature is intentionally tiny because OS protocol handlers
/// receive a single positional argument (the full URL, percent-encoded)
/// and nothing else.
#[derive(Parser, Debug, Clone)]
pub(crate) struct OpenUrlArgs {
    /// The full `oct://<circle>/<path>` URL passed by the OS.
    ///
    /// The OS may URL-encode this. We do **not** decode it here so the
    /// authoritative `Url::parse` (called by the resolver) sees the
    /// exact bytes the OS handed over.
    pub url: String,

    /// Skip the tunnel-up check and fetch over clearnet.
    ///
    /// Off by default. Leaking the user's IP to the chain RPC endpoint
    /// is the whole reason the default is on.
    #[arg(long, default_value_t = false)]
    pub offline: bool,

    /// Skip the user-confirmation prompt.
    ///
    /// Intended for tests and for `--no-confirm` flag added manually.
    /// Web pages cannot pass extra flags via the URL handler, so this
    /// can only be set when invoking `octravpn open-url` from a shell.
    #[arg(long, default_value_t = false)]
    pub no_confirm: bool,
}

/// Entry point used by the clap dispatcher.
pub(crate) fn run(args: &OpenUrlArgs) -> Result<()> {
    open_url(&args.url)
}

/// Open an `oct://<circle>/<path>` URL.
///
/// Stub: parses + prints, does not fetch. Returns Ok if the URL was
/// well-formed; Err otherwise.
///
/// Compiles and runs even when the VPN is not up — that's the whole
/// point of having a handler that can degrade gracefully.
//
// `pub` per the design spec — the followup that wires this into a
// future `octravpn-client` library target needs the wider visibility.
// Today the bin crate makes this lint as unreachable_pub; suppress
// only here, not crate-wide.
#[allow(unreachable_pub)]
pub fn open_url(url: &str) -> Result<()> {
    let (circle_id, canonical_path) = parse_oct_url(url)?;

    // Once wired up, the next step is:
    //
    //   let rkey = octravpn_core::circle::resource_key(&circle_id, &canonical_path);
    //   let env = rpc.raw_call("circle_asset_ciphertext_by_resource_key",
    //                          json!([&circle_id, &rkey])).await?;
    //   let plaintext = octravpn_core::circle::decrypt_sealed_bytes(...)?;
    //
    // followed by a sandboxed viewer dispatch. None of that is wired
    // yet; this stub just confirms the URL parses.
    //
    // Tunnel-up probe will fail-closed by default once it lands.

    println!(
        "would open oct://{circle_id}{canonical_path} \
         (stub; fetch not yet wired — see docs/oct-url-handler.md)"
    );
    Ok(())
}

/// Split `oct://<circle>/<path>` into `(circle, /path)`.
///
/// Rejects anything that does not start with `oct://`, that has an
/// empty circle id, or that is missing a path. We do **not** validate
/// the circle id beyond non-emptiness here — the chain RPC will reject
/// malformed addresses; surfacing the chain's error verbatim is more
/// useful than a parser that drifts out of sync with `Address::try_from_display`.
fn parse_oct_url(url: &str) -> Result<(String, String)> {
    let rest = url
        .strip_prefix("oct://")
        .ok_or_else(|| anyhow!("not an oct:// URL: {url}"))?;
    let (circle, path) = rest
        .split_once('/')
        .ok_or_else(|| anyhow!("oct:// URL missing path component: {url}"))?;
    if circle.is_empty() {
        return Err(anyhow!("oct:// URL has empty circle id: {url}"));
    }
    let canonical = format!("/{path}");
    Ok((circle.to_string(), canonical))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_well_formed_url() {
        let (c, p) =
            parse_oct_url("oct://octdeadbeef00000000000000000000000000000000/policy.json").unwrap();
        assert_eq!(c, "octdeadbeef00000000000000000000000000000000");
        assert_eq!(p, "/policy.json");
    }

    #[test]
    fn parses_nested_path() {
        let (c, p) =
            parse_oct_url("oct://octdeadbeef/tailnet-7/members.json").unwrap();
        assert_eq!(c, "octdeadbeef");
        assert_eq!(p, "/tailnet-7/members.json");
    }

    #[test]
    fn rejects_wrong_scheme() {
        assert!(parse_oct_url("https://example.com/").is_err());
    }

    #[test]
    fn rejects_missing_path() {
        assert!(parse_oct_url("oct://octdeadbeef").is_err());
    }

    #[test]
    fn rejects_empty_circle() {
        assert!(parse_oct_url("oct:///policy.json").is_err());
    }

    #[test]
    fn open_url_stub_is_ok_on_valid() {
        assert!(open_url("oct://octdeadbeef/policy.json").is_ok());
    }
}
