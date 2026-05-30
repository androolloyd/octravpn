//! Canonical base64 codecs for the workspace.
//!
//! One home for the STANDARD and URL-safe engines plus the lenient
//! any-alphabet decoder, replacing the ~20 per-call-site
//! `use base64::engine::general_purpose::{STANDARD, …}; use base64::Engine as _;`
//! declarations (under three competing aliases — `BASE64_STD`, `B64`,
//! `B64URL`) that were scattered across every crate.
//!
//! - [`encode`] / [`decode`] — padded **standard** alphabet. The default
//!   for wire fields, signatures, wg pubkeys, receipt blinding, etc.
//! - [`encode_url`] / [`decode_url`] — **URL-safe, no padding**. For
//!   bytes embedded in `oct://` URLs and query params.
//! - [`decode_any`] — lenient: accepts any of the four common alphabets
//!   (standard / URL-safe × padded / unpadded). For inputs whose origin
//!   is uncontrolled (PSK config, SPKI pin bundles).

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;

pub use base64::DecodeError;

/// Encode bytes as padded standard base64.
pub fn encode(bytes: impl AsRef<[u8]>) -> String {
    STANDARD.encode(bytes)
}

/// Decode padded standard base64.
pub fn decode(input: impl AsRef<[u8]>) -> Result<Vec<u8>, DecodeError> {
    STANDARD.decode(input)
}

/// Encode bytes as URL-safe base64 without padding — for `oct://` URLs
/// and query params, where `+`/`/`/`=` would need escaping.
pub fn encode_url(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode URL-safe base64 without padding.
pub fn decode_url(input: impl AsRef<[u8]>) -> Result<Vec<u8>, DecodeError> {
    URL_SAFE_NO_PAD.decode(input)
}

/// Lenient decode accepting any of the four common base64 alphabets
/// (standard / URL-safe × padded / unpadded). Returns `None` if the
/// input matches none. Use only where the encoding alphabet of the
/// input is not under our control — prefer [`decode`] / [`decode_url`]
/// when the producer is known.
pub fn decode_any(input: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    let input = input.as_ref();
    STANDARD
        .decode(input)
        .or_else(|_| URL_SAFE.decode(input))
        .or_else(|_| STANDARD_NO_PAD.decode(input))
        .or_else(|_| URL_SAFE_NO_PAD.decode(input))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_round_trips() {
        let raw = b"\x00\xff\x10octra\x7f";
        assert_eq!(decode(encode(raw)).unwrap(), raw);
    }

    #[test]
    fn url_safe_has_no_padding_or_unsafe_chars() {
        // 0xFF 0xFE 0xFD → standard "//79", url-safe-no-pad "__79".
        let enc = encode_url([0xff, 0xfe, 0xfd]);
        assert!(!enc.contains('+') && !enc.contains('/') && !enc.contains('='));
        assert_eq!(decode_url(&enc).unwrap(), vec![0xff, 0xfe, 0xfd]);
    }

    #[test]
    fn decode_any_accepts_every_alphabet() {
        let raw = [0xff, 0xfe, 0xfd, 0x00, 0x10];
        for variant in [
            encode(raw),                 // standard padded
            encode_url(raw),             // url-safe no pad
            STANDARD_NO_PAD.encode(raw), // standard no pad
            URL_SAFE.encode(raw),        // url-safe padded
        ] {
            assert_eq!(decode_any(&variant).as_deref(), Some(&raw[..]), "{variant}");
        }
        assert!(decode_any("not valid base64 !!!").is_none());
    }
}
