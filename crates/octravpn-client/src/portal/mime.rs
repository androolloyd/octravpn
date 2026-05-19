//! Minimal MIME sniffer for the portal's render-by-type dispatcher.
//!
//! We deliberately don't depend on `infer` or `mime_guess` — the portal
//! only needs to distinguish "render as image / JSON / sandboxed HTML /
//! plain text" from "Save-As". Bytes that don't match any signature
//! (including everything that looks encrypted) get
//! `application/octet-stream`, which the route handler maps to Save-As.
//!
//! **Decision log: sniff order.**
//! Binary magics first (PNG/JPEG/GIF/WebP/PDF) — these are unambiguous
//! and fast. Then JSON (leading `{` / `[` skipping whitespace) before
//! HTML, because `{"...html..."}` would otherwise be mis-classified as
//! HTML. Then HTML (`<!DOCTYPE` / `<html` / `<svg`). UTF-8-clean text
//! is the last positive identification; anything else is
//! `application/octet-stream`.

/// A small, fixed-vocabulary MIME enum. Avoids pulling in `mime` and
/// keeps the dispatch table inside `routes.rs` exhaustive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SniffedMime {
    Png,
    Jpeg,
    Gif,
    Webp,
    Svg,
    Pdf,
    Json,
    Html,
    PlainText,
    OctetStream,
}

impl SniffedMime {
    /// Canonical `Content-Type` header value.
    pub(crate) fn content_type(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Gif => "image/gif",
            Self::Webp => "image/webp",
            Self::Svg => "image/svg+xml",
            Self::Pdf => "application/pdf",
            Self::Json => "application/json",
            Self::Html => "text/html; charset=utf-8",
            Self::PlainText => "text/plain; charset=utf-8",
            Self::OctetStream => "application/octet-stream",
        }
    }

    /// True for types the portal can safely render inline. Anything
    /// `false` flips to Save-As.
    pub(crate) fn renderable(self) -> bool {
        !matches!(self, Self::OctetStream)
    }
}

/// Sniff the first 16 bytes (or fewer) of `bytes` and classify.
pub(crate) fn sniff(bytes: &[u8]) -> SniffedMime {
    let head = &bytes[..bytes.len().min(16)];

    // Binary magics (unambiguous).
    if head.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]) {
        return SniffedMime::Png;
    }
    if head.starts_with(&[0xff, 0xd8, 0xff]) {
        return SniffedMime::Jpeg;
    }
    if head.starts_with(b"GIF87a") || head.starts_with(b"GIF89a") {
        return SniffedMime::Gif;
    }
    // WebP: "RIFF....WEBP"
    if head.len() >= 12 && &head[0..4] == b"RIFF" && &head[8..12] == b"WEBP" {
        return SniffedMime::Webp;
    }
    if head.starts_with(b"%PDF-") {
        return SniffedMime::Pdf;
    }

    // Skip leading ASCII whitespace for the text classifiers.
    let trimmed = trim_ascii_ws(bytes);
    let trimmed_head = &trimmed[..trimmed.len().min(64)];

    // JSON before HTML so `{"html": "<b>"}` doesn't flip to HTML.
    if let Some(&first) = trimmed_head.first() {
        if first == b'{' || first == b'[' {
            // Verify the whole payload parses (cheap on small bodies;
            // for larger we still try — JSON parsers short-circuit on
            // syntax errors quickly).
            if serde_json::from_slice::<serde_json::Value>(bytes).is_ok() {
                return SniffedMime::Json;
            }
        }
    }

    // HTML / SVG (case-insensitive on the magic prefix).
    let ascii_lc: Vec<u8> = trimmed_head
        .iter()
        .map(u8::to_ascii_lowercase)
        .collect();
    if ascii_lc.starts_with(b"<!doctype html")
        || ascii_lc.starts_with(b"<html")
        || ascii_lc.starts_with(b"<head")
        || ascii_lc.starts_with(b"<body")
    {
        return SniffedMime::Html;
    }
    if ascii_lc.starts_with(b"<svg")
        || ascii_lc.starts_with(b"<?xml") && find_subslice_ci(trimmed_head, b"<svg").is_some()
    {
        return SniffedMime::Svg;
    }

    // UTF-8-clean text.
    if std::str::from_utf8(bytes).is_ok() {
        return SniffedMime::PlainText;
    }

    SniffedMime::OctetStream
}

fn trim_ascii_ws(b: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < b.len() && b[start].is_ascii_whitespace() {
        start += 1;
    }
    &b[start..]
}

fn find_subslice_ci(haystack: &[u8], needle_lc: &[u8]) -> Option<usize> {
    if needle_lc.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle_lc.len())
        .position(|w| w.iter().map(u8::to_ascii_lowercase).eq(needle_lc.iter().copied()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniff_png_magic() {
        let png = b"\x89PNG\r\n\x1a\nrest";
        assert_eq!(sniff(png), SniffedMime::Png);
    }

    #[test]
    fn sniff_jpeg_magic() {
        let jpg = b"\xff\xd8\xff\xe0junk";
        assert_eq!(sniff(jpg), SniffedMime::Jpeg);
    }

    #[test]
    fn sniff_json_before_html() {
        let mixed = br#"{"html": "<b>"}"#;
        assert_eq!(sniff(mixed), SniffedMime::Json);
    }

    #[test]
    fn sniff_html_doctype() {
        let h = b"<!DOCTYPE html><html><body>";
        assert_eq!(sniff(h), SniffedMime::Html);
    }

    #[test]
    fn sniff_plaintext_falls_through() {
        let t = b"plain text, no magic";
        assert_eq!(sniff(t), SniffedMime::PlainText);
    }

    #[test]
    fn sniff_encrypted_looking_bytes_are_octet_stream() {
        // Random-ish bytes with no valid UTF-8 / known magic — like an
        // AES-GCM ciphertext envelope. Must fall to octet-stream so the
        // portal's Save-As fallback engages.
        let mut bytes = vec![0u8; 256];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(173).wrapping_add(7);
        }
        // Stamp a non-UTF8 high bit to be safe.
        bytes[0] = 0xff;
        bytes[1] = 0xfe;
        bytes[2] = 0xfd;
        assert_eq!(sniff(&bytes), SniffedMime::OctetStream);
    }

    #[test]
    fn sniff_renderable_includes_image_and_text_excludes_octet() {
        assert!(SniffedMime::Png.renderable());
        assert!(SniffedMime::Html.renderable());
        assert!(!SniffedMime::OctetStream.renderable());
    }
}
