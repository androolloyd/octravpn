//! SPKI fingerprint pinning for the chain-RPC TLS path.
//!
//! Audit-1 H-1 (`docs/audit/2026-05-20-deep-security-audit.md`): the
//! threat-model (`docs/security/threat-model-v3.md` rows 4.c, 5.f)
//! claims the client pins the chain RPC's SubjectPublicKeyInfo
//! fingerprint, but the actual code in
//! `crates/octravpn-client/src/portal/chain/fetch.rs::build_rpc` was
//! doing **CA-bundle pinning** via
//! `RpcClient::new_with_pinned_roots`: it disables the system trust
//! store and pins the issuer chain, but any cert under those issuers
//! still passes. A compromised LE account / coerced corporate CA /
//! DigiNotar-style breach silently MITMs the chain RPC.
//!
//! This module closes the gap. [`SpkiPinVerifier`] is a
//! `rustls::client::danger::ServerCertVerifier` that:
//!
//!   1. Extracts the leaf cert's `SubjectPublicKeyInfo` (the
//!      tag-length-value DER bytes of the SPKI SEQUENCE inside
//!      `tbsCertificate`).
//!   2. Computes `sha256(SubjectPublicKeyInfo)`.
//!   3. Constant-time compares to every entry in [`SpkiPinVerifier::pins`].
//!   4. On match, defers to the wrapped `inner` verifier for
//!      hostname + chain validation. On mismatch, returns
//!      `Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)`
//!      so the TLS handshake aborts with a precise error variant the
//!      tests can pin.
//!
//! Multiple pins are supported (operators rotate cert keys; the
//! `oct://` URL may carry the OLD + NEW SPKI in parallel during the
//! rotation window). An empty `pins` vector rejects **all** chains —
//! by construction misconfigurations close the door rather than fall
//! back to CA-only pinning.
//!
//! ## SPKI extraction
//!
//! Standard SPKI-pin (RFC 7469 — HPKP) hashes the entire
//! `SubjectPublicKeyInfo` DER (the SEQUENCE tag + length + value, in
//! particular *including* the AlgorithmIdentifier and the BIT STRING
//! that carries the public key). We do the same so a pin computed by
//! `openssl x509 -in cert.pem -noout -pubkey | openssl pkey -pubin
//! -outform DER | openssl dgst -sha256 -binary | base64` matches.
//!
//! We avoid a full X.509 parser dep here (the existing tree has
//! `rustls-webpki` but its `SubjectPublicKeyInfo` accessor is not
//! `pub`). The extraction is hand-rolled DER walk: enter the outer
//! Certificate SEQUENCE, enter the TBSCertificate SEQUENCE, skip the
//! optional `[0]` EXPLICIT version, then skip 5 fields (serialNumber,
//! signature, issuer, validity, subject), and emit the next element
//! verbatim as the SPKI bytes. The walker rejects malformed lengths,
//! truncated streams, and any prefix that isn't a SEQUENCE — see
//! [`extract_spki_der`].
//!
//! ## Why constant-time
//!
//! The pin set is a fixed 32-byte digest the attacker doesn't see in
//! plaintext, so a timing-side-channel recovery isn't trivially in
//! scope, but consistent style (every `octravpn-core` byte compare
//! uses [`crate::bearer::constant_time_eq_str`]'s `Vec<u8>` cousin)
//! is cheap and rules out any future state-key-as-pin extension
//! drifting into a non-CT path.

use std::fmt;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use sha2::{Digest, Sha256};

/// A `rustls` server-cert verifier that requires the leaf cert's
/// SubjectPublicKeyInfo to sha256-hash to one of a pinned set, then
/// defers to the supplied `inner` verifier for the rest of the
/// standard chain/hostname validation.
///
/// `inner` must be a fully-functional verifier — typically the
/// `WebPkiServerVerifier` reqwest constructs from the configured trust
/// roots (system store, pinned PEM bundle, etc.). The SPKI check is a
/// pre-flight gate: *any* cert that fails the SPKI test is rejected
/// before its chain even gets a chance. So a forged chain whose root
/// happens to be in the system store is still refused unless its
/// leaf's SPKI was on the pin list, which closes the audit-1 H-1
/// hole.
pub struct SpkiPinVerifier {
    /// The set of permitted leaf SPKI sha256 hashes. Encoded as
    /// `[u8; 32]` for fixed-size storage. Multiple entries are
    /// supported so the operator can rotate the chain RPC's TLS key
    /// without invalidating in-flight `oct://` URLs (the new URL
    /// carries the new pin; old clients with the old pin keep
    /// connecting until the old key is retired — see the "PVAC
    /// pubkey rotation" paragraph in the audit-fix commit message).
    pins: Vec<[u8; 32]>,
    /// Chain/hostname validator. Public-API'd as an Arc so the same
    /// `WebPkiServerVerifier` can back multiple `SpkiPinVerifier`s
    /// without rebuilding.
    inner: Arc<dyn ServerCertVerifier>,
}

impl fmt::Debug for SpkiPinVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpkiPinVerifier")
            .field("pin_count", &self.pins.len())
            .field("inner", &"<ServerCertVerifier>")
            .finish()
    }
}

impl SpkiPinVerifier {
    /// Construct directly with a set of pre-decoded sha256 pins and
    /// the inner verifier to delegate chain validation to. Used by
    /// `from_oct_url` and by tests that want to fabricate a pin set
    /// from a known cert.
    pub fn new(pins: Vec<[u8; 32]>, inner: Arc<dyn ServerCertVerifier>) -> Self {
        Self { pins, inner }
    }

    /// Parse one or more SPKI pins out of an `oct://...` URL.
    ///
    /// The URL spec (`docs/oct-url-handler.md`) carries the pin in a
    /// `spki` query parameter, base64-encoded sha256(SPKI). Multiple
    /// pins are comma-separated (rotation grace window). The function
    /// is strict — any non-32-byte decoded value, any malformed base64,
    /// or a missing `spki` param produces `None`, leaving the caller
    /// to fall back to the regular CA-pinned path.
    ///
    /// Acceptable encodings (per the spec, in order of preference):
    ///   * Standard base64 (`+/=` alphabet)
    ///   * URL-safe base64 without padding (`-_` alphabet, common in
    ///     shell-pasted oct:// links)
    ///
    /// Returns `None` if the URL doesn't carry an `spki=` parameter
    /// at all, so the caller can transparently fall back to
    /// CA-bundle pinning for legacy URLs.
    #[must_use]
    pub fn parse_pins_from_oct_url(url: &str) -> Option<Vec<[u8; 32]>> {
        let q = url.split_once('?')?.1;
        // Strip any fragment that may follow `#`.
        let q = q.split('#').next().unwrap_or(q);
        let mut spki_param: Option<&str> = None;
        for kv in q.split('&') {
            let (k, v) = kv.split_once('=')?;
            if k == "spki" {
                spki_param = Some(v);
                break;
            }
        }
        let raw = spki_param?;
        let mut out = Vec::new();
        for piece in raw.split(',') {
            let decoded = crate::b64::decode_any(piece)?;
            if decoded.len() != 32 {
                return None;
            }
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&decoded);
            out.push(buf);
        }
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }

    /// Compute `sha256(SubjectPublicKeyInfo DER)` for `cert_der` — the
    /// fingerprint format `parse_pins_from_oct_url` expects. Useful
    /// for fabricating test pins and for operator tooling
    /// (`octravpn show-pin <cert.pem>`).
    pub fn fingerprint(cert_der: &[u8]) -> Result<[u8; 32], SpkiExtractError> {
        let spki = extract_spki_der(cert_der)?;
        let mut h = Sha256::new();
        h.update(spki);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        Ok(out)
    }

    /// Read-only view of the currently-configured pins. Lets tests
    /// pin the rotation behaviour without re-deriving the digests.
    pub fn pins(&self) -> &[[u8; 32]] {
        &self.pins
    }
}

/// Constant-time equality on the 32-byte SPKI fingerprint. Avoids a
/// short-circuit on the first mismatched byte; same primitive as
/// `crate::bearer::constant_time_eq_str` but specialised for the
/// fixed-size case.
fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

impl ServerCertVerifier for SpkiPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        // Empty pin set is a hard reject — never silently fall back
        // to CA-only validation. Operators get a precise error
        // variant (ApplicationVerificationFailure) so a misconfigured
        // pin list surfaces as a TLS-level failure rather than a
        // success.
        if self.pins.is_empty() {
            return Err(RustlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        // Extract leaf SPKI. A malformed cert is rejected up front
        // with `BadEncoding` (rustls convention for "the DER didn't
        // parse").
        let leaf_spki = extract_spki_der(end_entity.as_ref())
            .map_err(|_| RustlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        let mut h = Sha256::new();
        h.update(leaf_spki);
        let mut leaf_hash = [0u8; 32];
        leaf_hash.copy_from_slice(&h.finalize());

        // Constant-time membership test: OR every per-pin comparison
        // into a single bit so the wall-clock time is independent of
        // which (if any) pin matched. Short-circuiting `any()` would
        // leak a position-of-match timing oracle when the pin set is
        // user-controlled — irrelevant for today's "operator-loaded
        // from oct:// URL" flow but cheap to do right.
        let mut matched = 0u8;
        for pin in &self.pins {
            matched |= u8::from(ct_eq_32(pin, &leaf_hash));
        }
        if matched == 0 {
            return Err(RustlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        // SPKI matched. Defer to the inner verifier for chain +
        // hostname + validity. Note that order matters: we did the
        // SPKI check first so a forged chain whose root is in the
        // system store can NOT pass — its leaf SPKI won't match
        // unless the attacker also stole the private key the pin
        // pinned.
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        // The signature check piggy-backs on the inner verifier's
        // configured signature schemes (matching the WebPKI default
        // set when the inner was built that way). We don't filter
        // anything here — the chain-validation deferral already
        // happened in verify_server_cert.
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Errors from [`extract_spki_der`]. Kept distinct from rustls's own
/// error type so tests can match on the precise failure mode without
/// dragging in the full `rustls::Error` enum.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SpkiExtractError {
    /// The byte stream does not start with the expected
    /// `Certificate ::= SEQUENCE` (DER tag `0x30`). Catches "the
    /// caller passed a PEM body" / "the caller passed a non-cert
    /// payload" misuse.
    #[error("not a DER SEQUENCE at offset 0")]
    NotASequence,
    /// The byte stream is shorter than the encoded length claims —
    /// either a truncated cert or a malformed length encoding.
    #[error("DER truncated at offset {offset}")]
    Truncated { offset: usize },
    /// Indefinite-length encoding (BER, tag `0x80` in the length
    /// position). Permitted in BER but forbidden in DER. We reject so
    /// the parser never reads past the cert.
    #[error("indefinite-length encoding is forbidden in DER")]
    IndefiniteLength,
    /// The DER walker ran out of TBSCertificate fields before
    /// reaching the SubjectPublicKeyInfo slot. Indicates a
    /// non-standard TBSCertificate layout (e.g. a custom extension
    /// stuffed before SPKI, or a truncated tbs).
    #[error("TBSCertificate did not contain a SubjectPublicKeyInfo at slot {slot}")]
    MissingSpkiField { slot: usize },
}

/// Extract the SubjectPublicKeyInfo DER bytes (tag-length-value, the
/// whole SEQUENCE) from a DER-encoded X.509 certificate.
///
/// Layout per RFC 5280:
///
/// ```text
///   Certificate ::= SEQUENCE {
///     tbsCertificate         TBSCertificate,
///     signatureAlgorithm     AlgorithmIdentifier,
///     signatureValue         BIT STRING
///   }
///   TBSCertificate ::= SEQUENCE {
///     [0] EXPLICIT Version DEFAULT v1,   -- optional, tag 0xA0
///     serialNumber           INTEGER,
///     signature              AlgorithmIdentifier,
///     issuer                 Name,
///     validity               Validity,
///     subject                Name,
///     subjectPublicKeyInfo   SubjectPublicKeyInfo,
///     ...
///   }
/// ```
///
/// We enter Certificate, enter tbsCertificate, skip the optional
/// `[0]` version tag if present, then skip 5 fields (serialNumber,
/// signature, issuer, validity, subject), and return the next
/// element verbatim.
fn extract_spki_der(cert_der: &[u8]) -> Result<&[u8], SpkiExtractError> {
    // Enter the outer Certificate SEQUENCE.
    let tbs_body = enter_sequence(cert_der)?;
    // tbsCertificate is the first element of the Certificate
    // SEQUENCE. Its body holds the version/serial/.../spki fields.
    let tbs_inner = enter_sequence(tbs_body)?;

    let mut cursor = tbs_inner;
    // Optional [0] EXPLICIT version. Tag = 0xA0.
    if let Some(tlv) = peek_tlv(cursor)? {
        if tlv.tag == 0xA0 {
            cursor = tlv.rest;
        }
    }
    // Skip serialNumber, signature, issuer, validity, subject — 5
    // fields. The 6th is SubjectPublicKeyInfo, which is what we
    // return whole.
    for slot in 0..5 {
        let tlv = peek_tlv(cursor)?.ok_or(SpkiExtractError::MissingSpkiField { slot })?;
        cursor = tlv.rest;
    }
    // The next element is the SPKI. Re-find its bounds and slice
    // back into the *original* cert_der buffer so the returned
    // reference covers tag+length+value verbatim.
    let spki = peek_tlv(cursor)?.ok_or(SpkiExtractError::MissingSpkiField { slot: 5 })?;
    // `cursor` is a sub-slice of `cert_der`. The SPKI element starts
    // at `cursor[0]` and ends at `cursor[header_len + body_len]`.
    let end = spki
        .header_len
        .checked_add(spki.body_len)
        .ok_or(SpkiExtractError::Truncated {
            offset: cursor.len(),
        })?;
    if cursor.len() < end {
        return Err(SpkiExtractError::Truncated {
            offset: cursor.len(),
        });
    }
    Ok(&cursor[..end])
}

/// Walk into a single DER SEQUENCE, returning its body (after the
/// tag + length header). Errors if the tag isn't `0x30` or the
/// length encoding is malformed/indefinite.
fn enter_sequence(input: &[u8]) -> Result<&[u8], SpkiExtractError> {
    let tlv = peek_tlv(input)?.ok_or(SpkiExtractError::NotASequence)?;
    if tlv.tag != 0x30 {
        return Err(SpkiExtractError::NotASequence);
    }
    Ok(tlv.body)
}

/// One parsed DER TLV (Tag-Length-Value) element. `body` is
/// `&input[header_len..header_len+body_len]`; `rest` is the bytes
/// after the element. Held as a struct so callers can dot-access
/// the fields they need instead of unpacking a 5-tuple.
struct Tlv<'a> {
    tag: u8,
    header_len: usize,
    body_len: usize,
    body: &'a [u8],
    rest: &'a [u8],
}

/// Parse one TLV element off the front of `input`. Returns `Ok(None)`
/// when `input` is empty — sentinel for "no more elements in the
/// enclosing SEQUENCE".
fn peek_tlv(input: &[u8]) -> Result<Option<Tlv<'_>>, SpkiExtractError> {
    if input.is_empty() {
        return Ok(None);
    }
    let tag = input[0];
    if input.len() < 2 {
        return Err(SpkiExtractError::Truncated { offset: 1 });
    }
    let first_len = input[1];
    let (header_len, body_len) = if first_len & 0x80 == 0 {
        // Short form: length fits in one byte (0..=127).
        (2usize, usize::from(first_len))
    } else if first_len == 0x80 {
        // Indefinite-length encoding — BER only, forbidden in DER.
        return Err(SpkiExtractError::IndefiniteLength);
    } else {
        // Long form: low 7 bits give the number of subsequent length
        // bytes (big-endian).
        let n = usize::from(first_len & 0x7F);
        if n == 0 || n > core::mem::size_of::<usize>() {
            return Err(SpkiExtractError::Truncated { offset: 1 });
        }
        if input.len() < 2 + n {
            return Err(SpkiExtractError::Truncated { offset: 2 + n });
        }
        let mut body_len = 0usize;
        for i in 0..n {
            body_len = (body_len << 8) | usize::from(input[2 + i]);
        }
        (2 + n, body_len)
    };
    let end = header_len
        .checked_add(body_len)
        .ok_or(SpkiExtractError::Truncated { offset: header_len })?;
    if input.len() < end {
        return Err(SpkiExtractError::Truncated { offset: end });
    }
    Ok(Some(Tlv {
        tag,
        header_len,
        body_len,
        body: &input[header_len..end],
        rest: &input[end..],
    }))
}

#[cfg(test)]
mod tests {
    //! ≥5 tests covering the contract pinned by audit-1 H-1:
    //! * pin match → accept (defer to inner)
    //! * pin mismatch → reject with the exact rustls error variant
    //! * multiple pins (rotation grace) — any pin matches
    //! * empty pins list → reject (fail-closed on misconfig)
    //! * non-cert byte stream → reject without panic
    //!
    //! We use a self-signed test cert generated at test time via
    //! `rcgen`-style hand-rolled DER. Rather than depend on `rcgen`
    //! (heavy dep, includes its own ring + ed25519 fork), we ship a
    //! minimal handcrafted ECDSA cert blob inline so the test crate
    //! has zero new transitive dependencies.

    use super::*;
    use std::fmt::Debug;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Fake inner verifier that always returns `Ok`. Lets us observe
    /// whether the SpkiPinVerifier called through or rejected before
    /// delegation.
    #[derive(Debug)]
    struct AlwaysOkInner {
        called: AtomicUsize,
    }
    impl AlwaysOkInner {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                called: AtomicUsize::new(0),
            })
        }
        fn count(&self) -> usize {
            self.called.load(Ordering::SeqCst)
        }
        /// Return self as the trait-object Arc the verifier expects.
        /// Lets the test sites pass `inner.as_dyn()` without a
        /// clippy-flagged `as Arc<dyn …>` cast.
        fn as_dyn(self: &Arc<Self>) -> Arc<dyn ServerCertVerifier> {
            self.clone()
        }
    }
    impl ServerCertVerifier for AlwaysOkInner {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, RustlsError> {
            self.called.fetch_add(1, Ordering::SeqCst);
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ED25519]
        }
    }

    /// Minimal hand-rolled X.509 v3 self-signed-style cert with a
    /// known SPKI. Not signed (the signature bytes are zero) — the
    /// test verifiers never check the signature. The structure is:
    ///
    ///   Certificate := SEQUENCE {
    ///     tbsCertificate := SEQUENCE {
    ///       [0] version=2 (v3),
    ///       serial=1,
    ///       sigAlg=ED25519 OID,
    ///       issuer=empty SEQUENCE,
    ///       validity=two GeneralizedTime,
    ///       subject=empty SEQUENCE,
    ///       SPKI := SEQUENCE { algo=OID, BIT STRING pk_bytes }
    ///     },
    ///     sigAlg,
    ///     sig=BIT STRING(0)
    ///   }
    ///
    /// The SPKI carries a fixed 32-byte payload so the test can pin
    /// its sha256.
    fn make_test_cert(pubkey: [u8; 32]) -> Vec<u8> {
        // Helper: SEQUENCE wrap.
        fn seq(body: &[u8]) -> Vec<u8> {
            let mut out = vec![0x30];
            put_len(body.len(), &mut out);
            out.extend_from_slice(body);
            out
        }
        fn put_len(len: usize, out: &mut Vec<u8>) {
            if len < 0x80 {
                out.push(len as u8);
            } else if len < 0x100 {
                out.push(0x81);
                out.push(len as u8);
            } else {
                out.push(0x82);
                out.push((len >> 8) as u8);
                out.push((len & 0xFF) as u8);
            }
        }
        // [0] EXPLICIT version=2: A0 03 02 01 02
        let version = vec![0xA0, 0x03, 0x02, 0x01, 0x02];
        // INTEGER serial=1: 02 01 01
        let serial = vec![0x02, 0x01, 0x01];
        // AlgorithmIdentifier: SEQUENCE { OID 1.3.101.112 (ed25519) }
        // OID DER: 06 03 2B 65 70
        let alg = seq(&[0x06, 0x03, 0x2B, 0x65, 0x70]);
        // Empty Name (SEQUENCE {}).
        let empty_name = seq(&[]);
        // Validity: SEQUENCE { GeneralizedTime "20260101000000Z",
        //                      GeneralizedTime "21260101000000Z" }
        let make_gt = |s: &[u8; 15]| {
            let mut v = vec![0x18, 0x0F];
            v.extend_from_slice(s);
            v
        };
        let validity = seq(&{
            let mut body = make_gt(b"20260101000000Z");
            body.extend(make_gt(b"21260101000000Z"));
            body
        });
        // SubjectPublicKeyInfo: SEQUENCE { ed25519 alg, BIT STRING pubkey }
        let spki = {
            let alg_spki = seq(&[0x06, 0x03, 0x2B, 0x65, 0x70]);
            // BIT STRING: 03 LEN 00 <pubkey 32B>
            let mut bit = vec![0x03];
            put_len(1 + 32, &mut bit);
            bit.push(0x00);
            bit.extend_from_slice(&pubkey);
            seq(&{
                let mut b = alg_spki;
                b.extend(bit);
                b
            })
        };
        // TBSCertificate body = version || serial || alg || issuer ||
        // validity || subject || spki.
        let mut tbs_body = Vec::new();
        tbs_body.extend(&version);
        tbs_body.extend(&serial);
        tbs_body.extend(&alg);
        tbs_body.extend(&empty_name);
        tbs_body.extend(&validity);
        tbs_body.extend(&empty_name);
        tbs_body.extend(&spki);
        let tbs = seq(&tbs_body);
        // Signature BIT STRING (empty / zero-length).
        let sig = {
            let mut bit = vec![0x03];
            put_len(1, &mut bit);
            bit.push(0x00);
            bit
        };
        // Certificate SEQUENCE.
        let mut cert_body = Vec::new();
        cert_body.extend(tbs);
        cert_body.extend(alg);
        cert_body.extend(sig);
        seq(&cert_body)
    }

    fn known_unix_time() -> UnixTime {
        // 2026-06-01 00:00:00 UTC — well inside our test cert's
        // validity window (2026-01-01..2126-01-01).
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_780_000_000))
    }

    /// Test 1 — pin matches the leaf SPKI, the verifier accepts the
    /// chain and the inner verifier is called exactly once.
    #[test]
    fn pin_matches_accepts_and_delegates_to_inner() {
        let cert = make_test_cert([0xA5; 32]);
        let pin = SpkiPinVerifier::fingerprint(&cert).expect("extract SPKI");
        let inner = AlwaysOkInner::new();
        let v = SpkiPinVerifier::new(vec![pin], inner.as_dyn());
        let cert_der = CertificateDer::from(cert);
        let name = ServerName::try_from("example.test").unwrap();
        let r = v.verify_server_cert(&cert_der, &[], &name, &[], known_unix_time());
        assert!(r.is_ok(), "match must accept: {r:?}");
        assert_eq!(inner.count(), 1, "inner must run on a matching SPKI");
    }

    /// Test 2 — pin doesn't match: rejected with the precise
    /// `ApplicationVerificationFailure` variant, *before* the inner
    /// verifier is consulted.
    #[test]
    fn pin_mismatch_rejects_with_expected_rustls_error() {
        let cert = make_test_cert([0xA5; 32]);
        let inner = AlwaysOkInner::new();
        let v = SpkiPinVerifier::new(
            vec![[0xDE; 32]], // not the cert's SPKI hash
            inner.as_dyn(),
        );
        let cert_der = CertificateDer::from(cert);
        let name = ServerName::try_from("example.test").unwrap();
        let err = v
            .verify_server_cert(&cert_der, &[], &name, &[], known_unix_time())
            .expect_err("must reject");
        assert!(
            matches!(
                err,
                RustlsError::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure
                )
            ),
            "expected ApplicationVerificationFailure, got {err:?}"
        );
        assert_eq!(inner.count(), 0, "inner must NOT run on a mismatched SPKI",);
    }

    /// Test 3 — rotation grace: multiple pins are supported, any one
    /// matching is enough. We pin the NEW pin first (rotation-ready)
    /// then the OLD pin; the cert here corresponds to the OLD pin so
    /// the verifier accepts via the second entry.
    #[test]
    fn multiple_pins_rotation_grace_any_match_accepts() {
        let old_cert = make_test_cert([0x11; 32]);
        let old_pin = SpkiPinVerifier::fingerprint(&old_cert).unwrap();
        let new_cert = make_test_cert([0x22; 32]);
        let new_pin = SpkiPinVerifier::fingerprint(&new_cert).unwrap();
        let inner = AlwaysOkInner::new();
        let v = SpkiPinVerifier::new(vec![new_pin, old_pin], inner.as_dyn());
        let cert_der = CertificateDer::from(old_cert);
        let name = ServerName::try_from("example.test").unwrap();
        let r = v.verify_server_cert(&cert_der, &[], &name, &[], known_unix_time());
        assert!(
            r.is_ok(),
            "OLD cert under (new, old) pin set must accept: {r:?}"
        );
    }

    /// Test 4 — empty pins list: every chain is rejected, regardless
    /// of what the inner verifier would say. Catches misconfig that
    /// would otherwise silently degrade to CA-only validation.
    #[test]
    fn empty_pins_list_rejects_everything() {
        let cert = make_test_cert([0x33; 32]);
        let inner = AlwaysOkInner::new();
        let v = SpkiPinVerifier::new(vec![], inner.as_dyn());
        let cert_der = CertificateDer::from(cert);
        let name = ServerName::try_from("example.test").unwrap();
        let err = v
            .verify_server_cert(&cert_der, &[], &name, &[], known_unix_time())
            .expect_err("empty pins must reject");
        assert!(matches!(
            err,
            RustlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure
            )
        ));
        assert_eq!(inner.count(), 0);
    }

    /// Test 5 — a non-cert byte stream (random garbage, an empty
    /// slice, a PEM body) is rejected with the parser's BadEncoding
    /// variant. No panic, no out-of-bounds read.
    #[test]
    fn non_cert_input_rejects_without_panic() {
        let pin = [0u8; 32];
        let inner = AlwaysOkInner::new();
        let v = SpkiPinVerifier::new(vec![pin], inner.as_dyn());
        let name = ServerName::try_from("example.test").unwrap();

        for bad in [
            b"".to_vec(),
            b"-----BEGIN CERTIFICATE-----\nMIIB...".to_vec(),
            vec![0xFF; 32],
            vec![0x30, 0x82, 0xFF, 0xFF], // sequence with absurd length
            vec![0x02, 0x01, 0x01],       // INTEGER, not SEQUENCE
        ] {
            let cert_der = CertificateDer::from(bad);
            let err = v
                .verify_server_cert(&cert_der, &[], &name, &[], known_unix_time())
                .expect_err("garbage must reject");
            assert!(
                matches!(
                    err,
                    RustlsError::InvalidCertificate(
                        rustls::CertificateError::BadEncoding
                            | rustls::CertificateError::ApplicationVerificationFailure,
                    )
                ),
                "expected BadEncoding/ApplicationVerificationFailure, got {err:?}",
            );
        }
    }

    /// `parse_pins_from_oct_url` pulls one or more base64-encoded
    /// sha256 pins out of an `oct://...?spki=<b64>` URL. Multiple
    /// pins are comma-separated.
    #[test]
    fn parse_pins_from_oct_url_extracts_and_decodes() {
        let pin_a = [0x11u8; 32];
        let pin_b = [0x22u8; 32];
        let b64_a = crate::b64::encode(pin_a);
        let b64_b = crate::b64::encode(pin_b);

        // Single pin.
        let url = format!("oct://circle/policy.json?spki={b64_a}");
        let pins = SpkiPinVerifier::parse_pins_from_oct_url(&url).expect("must parse");
        assert_eq!(pins, vec![pin_a]);

        // Rotation: two pins.
        let url = format!("oct://circle/policy.json?spki={b64_a},{b64_b}&other=ignored");
        let pins = SpkiPinVerifier::parse_pins_from_oct_url(&url).expect("must parse");
        assert_eq!(pins, vec![pin_a, pin_b]);

        // No spki param → None (caller falls back to CA pinning).
        assert!(
            SpkiPinVerifier::parse_pins_from_oct_url("oct://circle/policy.json").is_none(),
            "missing spki must return None"
        );

        // Malformed base64 → None.
        let url = format!("oct://circle/policy.json?spki={b64_a},NOT-BASE64-!!!");
        assert!(SpkiPinVerifier::parse_pins_from_oct_url(&url).is_none());

        // Wrong length → None.
        let short = crate::b64::encode([0u8; 16]);
        let url = format!("oct://circle/policy.json?spki={short}");
        assert!(SpkiPinVerifier::parse_pins_from_oct_url(&url).is_none());
    }
}
