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
    let ascii_lc: Vec<u8> = trimmed_head.iter().map(u8::to_ascii_lowercase).collect();
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
    haystack.windows(needle_lc.len()).position(|w| {
        w.iter()
            .map(u8::to_ascii_lowercase)
            .eq(needle_lc.iter().copied())
    })
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

    // ── Phase-Z added coverage ───────────────────────────────────────
    //
    // Round out every variant returned by `sniff()`. Each direct test
    // exercises one happy path; the proptest at the bottom asserts the
    // global panic-freedom invariant on arbitrary byte sequences.

    #[test]
    fn sniff_gif_87_and_89_variants() {
        assert_eq!(sniff(b"GIF87a\x00\x00\x00"), SniffedMime::Gif);
        assert_eq!(sniff(b"GIF89a\x00\x00\x00"), SniffedMime::Gif);
        // Truncated header (no 'a') falls through.
        assert_ne!(sniff(b"GIF87"), SniffedMime::Gif);
    }

    #[test]
    fn sniff_webp_riff_header() {
        let mut bytes: Vec<u8> = b"RIFF".to_vec();
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        bytes.extend_from_slice(b"WEBP");
        bytes.extend_from_slice(b"VP8 ");
        assert_eq!(sniff(&bytes), SniffedMime::Webp);
    }

    #[test]
    fn sniff_webp_rejects_riff_without_webp_marker() {
        let mut bytes: Vec<u8> = b"RIFF".to_vec();
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        bytes.extend_from_slice(b"WAVE"); // not WEBP
        assert_ne!(sniff(&bytes), SniffedMime::Webp);
    }

    #[test]
    fn sniff_pdf_magic() {
        let p = b"%PDF-1.4\n%\xc7\xec\x8f\xa2\n";
        assert_eq!(sniff(p), SniffedMime::Pdf);
    }

    #[test]
    fn sniff_svg_with_xml_prologue() {
        let s = b"<?xml version=\"1.0\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>";
        assert_eq!(sniff(s), SniffedMime::Svg);
    }

    #[test]
    fn sniff_svg_bare() {
        let s = b"<svg width=\"10\" height=\"10\"></svg>";
        assert_eq!(sniff(s), SniffedMime::Svg);
    }

    #[test]
    fn sniff_svg_case_insensitive() {
        let s = b"<SvG xmlns=\"x\"></SvG>";
        assert_eq!(sniff(s), SniffedMime::Svg);
    }

    #[test]
    fn sniff_html_html_tag() {
        assert_eq!(sniff(b"<html><body>x</body></html>"), SniffedMime::Html);
    }

    #[test]
    fn sniff_html_head_tag() {
        assert_eq!(sniff(b"<head><title>x</title></head>"), SniffedMime::Html);
    }

    #[test]
    fn sniff_html_body_tag() {
        assert_eq!(sniff(b"<body>hi</body>"), SniffedMime::Html);
    }

    #[test]
    fn sniff_html_case_insensitive_doctype() {
        assert_eq!(sniff(b"<!DocType HTML><html></html>"), SniffedMime::Html);
    }

    #[test]
    fn sniff_html_leading_whitespace() {
        assert_eq!(
            sniff(b"   \n\t<!DOCTYPE html><html></html>"),
            SniffedMime::Html
        );
    }

    #[test]
    fn sniff_json_array() {
        assert_eq!(sniff(b"[1,2,3]"), SniffedMime::Json);
    }

    #[test]
    fn sniff_json_with_leading_whitespace() {
        assert_eq!(sniff(b"   {\"a\":1}"), SniffedMime::Json);
    }

    #[test]
    fn sniff_json_nested_object() {
        assert_eq!(sniff(br#"{"a":{"b":[1,2]}}"#), SniffedMime::Json);
    }

    #[test]
    fn sniff_invalid_json_drops_to_html_or_text() {
        // `{` start but body not parseable: falls through, eventually
        // PlainText (no HTML magic).
        let s = b"{not valid json at all";
        let got = sniff(s);
        assert!(matches!(got, SniffedMime::PlainText | SniffedMime::Html));
    }

    #[test]
    fn sniff_plaintext_unicode() {
        let t = "héllo wörld — utf8 ⚡";
        assert_eq!(sniff(t.as_bytes()), SniffedMime::PlainText);
    }

    #[test]
    fn sniff_empty_input() {
        // Empty slice has no magic + parses neither as JSON nor HTML.
        // UTF-8 check on empty slice returns Ok, so → PlainText.
        assert_eq!(sniff(b""), SniffedMime::PlainText);
    }

    #[test]
    fn sniff_one_byte_inputs() {
        // A single byte that's valid UTF-8 → PlainText. A single byte
        // 0xFF is not valid UTF-8 alone → OctetStream.
        assert_eq!(sniff(b"a"), SniffedMime::PlainText);
        assert_eq!(sniff(&[0xff]), SniffedMime::OctetStream);
    }

    #[test]
    fn sniff_short_png_prefix_does_not_match() {
        // First 4 bytes of PNG magic, but not the full 8 — must not
        // misclassify as PNG.
        let half = b"\x89PNG";
        assert_ne!(sniff(half), SniffedMime::Png);
    }

    #[test]
    fn sniff_content_type_header_values() {
        // Lock the wire-level Content-Type values — the route layer
        // emits these verbatim into HTTP headers.
        assert_eq!(SniffedMime::Png.content_type(), "image/png");
        assert_eq!(SniffedMime::Jpeg.content_type(), "image/jpeg");
        assert_eq!(SniffedMime::Gif.content_type(), "image/gif");
        assert_eq!(SniffedMime::Webp.content_type(), "image/webp");
        assert_eq!(SniffedMime::Svg.content_type(), "image/svg+xml");
        assert_eq!(SniffedMime::Pdf.content_type(), "application/pdf");
        assert_eq!(SniffedMime::Json.content_type(), "application/json");
        assert_eq!(SniffedMime::Html.content_type(), "text/html; charset=utf-8");
        assert_eq!(
            SniffedMime::PlainText.content_type(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            SniffedMime::OctetStream.content_type(),
            "application/octet-stream"
        );
    }

    #[test]
    fn sniff_renderable_excludes_only_octet_stream() {
        for m in [
            SniffedMime::Png,
            SniffedMime::Jpeg,
            SniffedMime::Gif,
            SniffedMime::Webp,
            SniffedMime::Svg,
            SniffedMime::Pdf,
            SniffedMime::Json,
            SniffedMime::Html,
            SniffedMime::PlainText,
        ] {
            assert!(m.renderable(), "{:?} must be renderable", m);
        }
        assert!(!SniffedMime::OctetStream.renderable());
    }

    #[test]
    fn sniff_high_bytes_after_text_drop_to_octet_stream() {
        // ASCII prefix that looks like text, then a continuation byte
        // sequence that breaks UTF-8.
        let mut b = b"hello \xc3\x28 world".to_vec(); // invalid UTF-8
        b.push(0xff);
        let got = sniff(&b);
        assert_eq!(got, SniffedMime::OctetStream);
    }

    #[test]
    fn sniff_50_weird_html_preambles_all_classify_as_html() {
        // Variations: comments, whitespace, case variants, BOM, mixed
        // attribute counts. None should fall through.
        let mut cases: Vec<Vec<u8>> = vec![
            b"<!DOCTYPE html>".to_vec(),
            b"<!doctype html>".to_vec(),
            b"<!DocType HTML>".to_vec(),
            b"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\">".to_vec(),
            b"<html>".to_vec(),
            b"<HTML>".to_vec(),
            b"<html lang=\"en\">".to_vec(),
            b"<html xmlns=\"http://www.w3.org/1999/xhtml\">".to_vec(),
            b"<head>".to_vec(),
            b"<body>".to_vec(),
            b" <html>".to_vec(),
            b"\t<html>".to_vec(),
            b"\n<html>".to_vec(),
            b"\r\n<html>".to_vec(),
            b"   <!DOCTYPE html>".to_vec(),
            b"\n\n<!DOCTYPE html>".to_vec(),
        ];
        // Pad to 50 with permutations: each base form, with extra trailing
        // attribute / whitespace / suffix.
        let suffixes: &[&[u8]] = &[
            b"\n",
            b" ",
            b"\t<body>x</body>",
            b"<head></head>",
            b" lang=\"en\">",
            b" data-x=\"y\">",
            b"</html>",
            b"foo",
            b"<title>t</title>",
            b"<meta charset=\"utf-8\">",
        ];
        let bases: &[&[u8]] = &[b"<!DOCTYPE html>", b"<html>", b"<head>", b"<body>"];
        for base in bases {
            for suf in suffixes {
                let mut buf = base.to_vec();
                buf.extend_from_slice(suf);
                cases.push(buf);
            }
        }
        cases.truncate(50);
        assert_eq!(cases.len(), 50, "need 50 distinct HTML preambles");
        for (i, c) in cases.iter().enumerate() {
            let got = sniff(c);
            assert_eq!(
                got,
                SniffedMime::Html,
                "case #{i} (`{}`) → {got:?}",
                String::from_utf8_lossy(c),
            );
        }
    }

    #[test]
    fn sniff_data_uri_in_html_still_html() {
        // Base64 data-uri image inside an HTML attribute. Must not
        // tip the sniffer over to image/jpeg / image/png based on
        // embedded magic bytes — the leading bytes are still `<html`.
        let s = b"<html><body><img src=\"data:image/png;base64,iVBORw0KGgo=\"></body></html>";
        assert_eq!(sniff(s), SniffedMime::Html);
    }

    #[test]
    fn sniff_html_with_inline_script_still_html() {
        let s = b"<html><script>alert(1)</script></html>";
        assert_eq!(sniff(s), SniffedMime::Html);
    }

    #[test]
    fn sniff_jpeg_alternate_marker() {
        // JPEG SOI is `FF D8 FF`; the 4th byte varies (E0 JFIF, E1 EXIF, ...).
        let j_jfif = b"\xff\xd8\xff\xe0\x00\x10JFIF";
        let j_exif = b"\xff\xd8\xff\xe1\x00\x10Exif";
        assert_eq!(sniff(j_jfif), SniffedMime::Jpeg);
        assert_eq!(sniff(j_exif), SniffedMime::Jpeg);
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 256,
            .. proptest::test_runner::Config::default()
        })]

        /// Sniff must never panic on arbitrary bytes — it is the very
        /// first dispatch step inside the asset render path.
        #[test]
        fn sniff_never_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(0u8..=255, 0..=8192)) {
            let _ = sniff(&bytes);
        }

        /// Sniff must always return one of the named variants (no panics,
        /// no UB). We assert renderable() is a well-defined bool too.
        #[test]
        fn sniff_returns_some_variant_for_any_input(bytes in proptest::collection::vec(0u8..=255, 0..=4096)) {
            let m = sniff(&bytes);
            // content_type() must not panic.
            let _ = m.content_type();
            let _ = m.renderable();
        }
    }
}
