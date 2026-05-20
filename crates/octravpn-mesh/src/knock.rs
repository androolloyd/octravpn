//! Client-side helper for the PSK-gated wire-control handshake.
//!
//! Mirror of `headscale_api::tailscale_wire::knock` (server-side
//! verifier) — the math here must stay byte-for-byte identical to the
//! server's, otherwise the CLI / portal can't authenticate. The
//! `cross_repo_compat` integration test in `octravpn-node` pins a
//! known-answer triple `(psk, window, expected_knock)` against both
//! crates so a future divergence trips CI.
//!
//! ## Surface
//!
//! Two helpers:
//!
//!   * [`current_knock`] — compute the knock cookie for the wall-clock
//!     `now()`. Pass the result as either the `X-OctraVPN-Knock` HTTP
//!     header or as the `/k/<knock>/` URL prefix.
//!
//!   * [`parse_knock_psk_query`] — strip a `?knock_psk=<base64>` query
//!     from an `oct://` URL and return the decoded PSK. The portal
//!     uses this so dispatch-time handlers don't see the PSK leaked
//!     into other code paths.
//!
//! Both functions are deterministic + clock-independent except for
//! `current_knock`, which reads `SystemTime::now()`. The
//! `*_at_window` lower-level helpers exist for tests.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// HTTP header used by our own client to carry the knock cookie.
pub const KNOCK_HEADER: &str = "X-OctraVPN-Knock";

/// URI path prefix used for the path-embedded knock variant. Stock
/// `tailscale up` clients can't add custom HTTP headers, so the
/// operator's `--login-server` URL embeds the knock as a path prefix.
pub const KNOCK_PATH_PREFIX: &str = "/k/";

/// Default rounding window in seconds. Mirrors the server-side
/// [`headscale_api::tailscale_wire::knock::DEFAULT_WINDOW_SECS`].
pub const DEFAULT_WINDOW_SECS: u64 = 60;

/// Truncated tag length in *bytes*. 8 bytes = 16 hex chars, which
/// fits comfortably in a `--login-server` URL while still requiring
/// ≥ 2^63 probes per window to forge.
pub const KNOCK_TAG_BYTES: usize = 8;

/// `oct://...?knock_psk=<base64>` query parameter name. The portal
/// strips this before dispatching the remainder of the URL so the PSK
/// doesn't leak into chain / fetch handlers.
pub const KNOCK_PSK_QUERY: &str = "knock_psk";

/// Compute the current knock cookie for `psk`, using the wall clock
/// and the default rounding window.
///
/// Returns the 16-character hex tag. Pass this verbatim as the
/// `X-OctraVPN-Knock` header value, or insert into the URL as
/// `/k/<knock>/<rest>`.
#[must_use]
pub fn current_knock(psk: &[u8; 32], window_secs: u64) -> String {
    let window = now_unix() / window_secs.max(1);
    knock_at_window(psk, window)
}

/// Lower-level helper: compute the knock for a specific window
/// index. Used by tests to pin `now`; production callers want
/// [`current_knock`].
#[must_use]
pub fn knock_at_window(psk: &[u8; 32], window: u64) -> String {
    let mut mac = HmacSha256::new_from_slice(psk).expect("HMAC accepts any 32B key");
    mac.update(window.to_string().as_bytes());
    let tag = mac.finalize().into_bytes();
    hex::encode(&tag[..KNOCK_TAG_BYTES])
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Decode a base64-encoded PSK string into a 32-byte secret.
///
/// Accepts both standard and URL-safe base64 (`oct://` URLs may carry
/// either). Returns `Err` for any decoding / length mismatch.
pub fn decode_psk(b64: &str) -> Result<[u8; 32], KnockPskError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(b64))
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(b64))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64))
        .map_err(|_| KnockPskError::Base64)?;
    if raw.len() != 32 {
        return Err(KnockPskError::BadLength(raw.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Strip a `?knock_psk=<base64>` query parameter from `url` and return
/// `(cleaned_url, decoded_psk)`. Other query parameters are preserved
/// in their original order.
///
/// Returns `Ok(None)` if the URL carries no `knock_psk` parameter
/// (a normal `oct://` URL). Returns `Err` if the parameter is present
/// but malformed.
pub fn parse_knock_psk_query(url: &str) -> Result<Option<(String, [u8; 32])>, KnockPskError> {
    let Some(qmark) = url.find('?') else {
        return Ok(None);
    };
    let (head, query) = url.split_at(qmark);
    // Drop the leading '?'.
    let query = &query[1..];

    let mut kept = Vec::with_capacity(4);
    let mut found_psk: Option<&str> = None;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some(p) => p,
            None => (pair, ""),
        };
        if k == KNOCK_PSK_QUERY {
            if found_psk.is_some() {
                return Err(KnockPskError::Duplicate);
            }
            found_psk = Some(v);
        } else {
            kept.push(pair);
        }
    }
    let Some(b64) = found_psk else {
        return Ok(None);
    };
    let psk = decode_psk(b64)?;
    let cleaned = if kept.is_empty() {
        head.to_string()
    } else {
        format!("{head}?{}", kept.join("&"))
    };
    Ok(Some((cleaned, psk)))
}

/// Errors from parsing the `knock_psk` query parameter.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KnockPskError {
    /// Base64 decode failed.
    #[error("knock_psk: base64 decode failed")]
    Base64,
    /// Decoded length wasn't 32 bytes.
    #[error("knock_psk: expected 32 bytes after base64, got {0}")]
    BadLength(usize),
    /// The query string carried `knock_psk` more than once.
    #[error("knock_psk: parameter present more than once")]
    Duplicate,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_psk() -> [u8; 32] {
        let mut psk = [0u8; 32];
        for (i, b) in psk.iter_mut().enumerate() {
            *b = i as u8;
        }
        psk
    }

    #[test]
    fn knock_is_deterministic_for_same_window() {
        let psk = fixed_psk();
        let a = knock_at_window(&psk, 100);
        let b = knock_at_window(&psk, 100);
        assert_eq!(a, b);
        assert_eq!(a.len(), KNOCK_TAG_BYTES * 2);
    }

    #[test]
    fn knock_changes_per_window() {
        let psk = fixed_psk();
        let a = knock_at_window(&psk, 100);
        let b = knock_at_window(&psk, 101);
        assert_ne!(a, b);
    }

    /// Cross-repo compat: this triple must match the server-side
    /// verifier in `headscale-api`. The
    /// `tailscale_wire_knock_cross_repo` integration test in
    /// `octravpn-node` exercises both paths end-to-end.
    ///
    /// Triple: psk = 0x00..0x1f, window = 12345
    #[test]
    fn known_answer_test_window_12345() {
        let psk = fixed_psk();
        let knock = knock_at_window(&psk, 12345);
        assert_eq!(knock.len(), 16, "16 hex chars");
        // Recompute via the explicit underlying primitives so a
        // future change to the math (truncation length, window-string
        // formatting) must be deliberate.
        let mut mac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(&psk).unwrap();
        hmac::Mac::update(&mut mac, b"12345");
        let tag = hmac::Mac::finalize(mac).into_bytes();
        assert_eq!(knock, hex::encode(&tag[..8]));
    }

    #[test]
    fn parse_knock_psk_query_strips_param() {
        let mut psk_b64 = base64::engine::general_purpose::STANDARD.encode(fixed_psk());
        // Sanity: a 32-byte PSK encodes to a stable 44-char base64.
        assert_eq!(psk_b64.len(), 44);

        // No query at all.
        let r = parse_knock_psk_query("oct://circle/path").unwrap();
        assert_eq!(r, None);

        // Only `knock_psk`.
        let url = format!("oct://circle/path?knock_psk={psk_b64}");
        let (cleaned, recovered) = parse_knock_psk_query(&url).unwrap().unwrap();
        assert_eq!(cleaned, "oct://circle/path");
        assert_eq!(recovered, fixed_psk());

        // Mixed with other params, knock_psk in the middle.
        let url = format!("oct://circle/path?a=1&knock_psk={psk_b64}&b=2");
        let (cleaned, recovered) = parse_knock_psk_query(&url).unwrap().unwrap();
        assert_eq!(cleaned, "oct://circle/path?a=1&b=2");
        assert_eq!(recovered, fixed_psk());

        // URL-safe base64 also accepted.
        psk_b64 = psk_b64.replace('+', "-").replace('/', "_");
        let url = format!("oct://circle/path?knock_psk={psk_b64}");
        let (_, recovered) = parse_knock_psk_query(&url).unwrap().unwrap();
        assert_eq!(recovered, fixed_psk());

        // Duplicate rejected.
        let url = format!("oct://x/?knock_psk={psk_b64}&knock_psk={psk_b64}");
        assert_eq!(
            parse_knock_psk_query(&url).unwrap_err(),
            KnockPskError::Duplicate
        );

        // Malformed base64.
        let url = "oct://x/?knock_psk=!!!";
        assert!(matches!(
            parse_knock_psk_query(url).unwrap_err(),
            KnockPskError::Base64
        ));
    }

    #[test]
    fn decode_psk_rejects_short_input() {
        // Decodes but length wrong.
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        assert!(matches!(
            decode_psk(&short).unwrap_err(),
            KnockPskError::BadLength(16)
        ));
    }
}
