//! Hardware-accelerated ChaCha20-Poly1305 AEAD shim.
//!
//! # Why this module exists
//!
//! Audit-8 §1 ("data plane") flagged that every per-packet seal/open on
//! the WireGuard relay path was bottlenecked by the portable Rust
//! ChaCha20-Poly1305 implementation in the `chacha20poly1305 = "0.10"`
//! crate. The criterion bench (`crates/octravpn-node/benches/wireguard_throughput.rs`)
//! pinned that path at 4.43 µs / 4.53 µs for a 1380-byte MTU payload —
//! about 2.49 Gbps single-core encap-only, ~1.23 Gbps per relay hop
//! once a decap + encap pair is accounted for. The portable backend does
//! not use AVX2 / AES-NI on x86_64 or NEON on aarch64 even when those
//! ISAs are available at runtime, so the data plane was leaving 30-50 %
//! of throughput on the floor on every CPU shipped after ~2013.
//!
//! This module is the Perf-5 fix: it wraps `aws-lc-rs` (the AWS
//! libcrypto Rust binding) and exposes the smallest possible AEAD
//! surface the hot path needs (`seal` / `open` against a fixed key, an
//! explicit 12-byte nonce, and an AAD slice). `aws-lc-rs` ships an
//! assembly-tuned ChaCha20-Poly1305 with AVX2 on x86_64 and NEON on
//! aarch64; the same algorithm constant covers both. The output bytes
//! are byte-identical to the portable backend (it is the same RFC 8439
//! standard); the `cross_impl_compatibility` test below proves it.
//!
//! # Why a new module rather than swap the dep wholesale
//!
//! Two reasons:
//!
//! 1. Several call sites (`stealth.rs` sealed-output blob,
//!    `wallet_enc.rs` passphrase envelope, occasional one-shot control
//!    -plane wraps) are not on the hot path and gain nothing from the
//!    switch — but each one is a small wire-format risk if we change
//!    impls under it. Leaving the old crate in place for those sites
//!    keeps Perf-5's blast radius to the call sites that actually win.
//! 2. The `aws-lc-rs` API takes an in-place buffer that is
//!    plaintext-on-write and ciphertext-on-return. The portable crate
//!    takes an owned slice and returns a new `Vec<u8>`. The shim
//!    bridges those shapes so call sites pick the API that fits each
//!    one's existing buffer story.
//!
//! # Where it gets wired
//!
//! - `crates/octravpn-core/src/onion.rs` — per-session onion seal/peel.
//! - `crates/octravpn-obfs4/src/frame.rs` — per-frame transport
//!   ChaCha20-Poly1305 wrap (the obfs4 sealer/opener pair).
//! - Bench: `crates/octravpn-node/benches/wireguard_throughput.rs`
//!   gains a `seal_hwaccel_1380B` + `open_hwaccel_1380B` group alongside
//!   the existing portable path so the regression-gate can compare
//!   apples-to-apples and the audit doc can quote a delta.
//!
//! # Threat-model implications
//!
//! `aws-lc-rs` is a FIPS-eligible crate (the underlying AWS-LC build is
//! FIPS 140-3 validated when compiled with `fips`; `default-features =
//! false` here disables the FIPS module but keeps the assembly backend).
//! The portable `chacha20poly1305` crate is not FIPS-eligible. See
//! `docs/security/threat-model-v3.md` §4 row "DERP MITM" for the
//! AEAD-selection note.
//!
//! # Supply chain
//!
//! `aws-lc-rs` and `aws-lc-sys` are already present in `Cargo.lock`
//! pulled transitively by `rcgen` (via `headscale-api`) and by
//! `tokio-rustls` (already feature-gated to `aws-lc-rs` in
//! `crates/octravpn-node/Cargo.toml`). No new transitive dependencies
//! enter the lock graph from this module.

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305, NONCE_LEN};

/// ChaCha20-Poly1305 key length in bytes (RFC 8439 §2.4: 256-bit key).
pub const KEY_LEN: usize = 32;
/// Poly1305 authentication tag length in bytes (RFC 8439 §2.5).
pub const TAG_LEN: usize = 16;
/// AEAD nonce length in bytes (RFC 8439 §2.3: 96-bit nonce).
pub const AEAD_NONCE_LEN: usize = NONCE_LEN;

/// AEAD operation outcome. The shim does not surface the underlying
/// crate's `Unspecified` opaque type because callers cannot do
/// anything useful with the distinction beyond "AEAD failed" — they
/// drop the frame.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AeadError {
    /// Seal/open call failed. For seal this is essentially unreachable
    /// (a 32-byte key + 12-byte nonce + non-overlong plaintext always
    /// seals); for open it is the authentication-tag mismatch the
    /// caller cares about.
    #[error("aead operation failed (tag mismatch or malformed input)")]
    Aead,
    /// Plaintext exceeded the RFC 8439 §2.8 limit of `2^32 - 1` blocks
    /// (~256 GiB) under a single key+nonce pair. No live call site
    /// approaches this — the WG MTU is 1500 B — but the shim still
    /// rejects rather than producing a silently-corrupt seal.
    #[error("plaintext too long: {0} bytes (RFC 8439 limit is 2^32-1 blocks)")]
    PlaintextTooLong(usize),
}

/// RFC 8439 §2.8 message-size cap, in bytes:
/// `(2^32 - 1) * 64`. Cast to `usize` is safe on 64-bit; on 32-bit it
/// is `usize::MAX` (the system runs out of address space before it
/// runs out of plaintext budget).
pub const MAX_PLAINTEXT_BYTES: u64 = ((1u64 << 32) - 1) * 64;

/// Allocate-then-seal: returns `ciphertext || tag` in a fresh `Vec`.
///
/// Mirrors the portable crate's `Aead::encrypt(nonce, plaintext)`
/// signature so the call-site swap is one line. Hot-path call sites
/// that already have an owned plaintext (e.g. `onion::wrap_layer`)
/// use this entry point.
///
/// Byte-identity with `chacha20poly1305::ChaCha20Poly1305::encrypt`
/// is guaranteed by RFC 8439 (the AEAD output is fully specified)
/// and verified by the `cross_impl_compatibility` test below.
pub fn aead_seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if (plaintext.len() as u64) > MAX_PLAINTEXT_BYTES {
        return Err(AeadError::PlaintextTooLong(plaintext.len()));
    }
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| AeadError::Aead)?;
    let sealing = LessSafeKey::new(unbound);
    let mut in_out: Vec<u8> = Vec::with_capacity(plaintext.len() + TAG_LEN);
    in_out.extend_from_slice(plaintext);
    sealing
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut in_out,
        )
        .map_err(|_| AeadError::Aead)?;
    Ok(in_out)
}

/// Allocate-then-open: takes `ciphertext || tag` and returns the
/// plaintext on success.
///
/// Mirrors the portable crate's `Aead::decrypt(nonce, ciphertext)`
/// signature. The shim still performs the in-place open under the
/// hood (the `aws-lc-rs` API requires it), but presents an owned
/// `Vec<u8>` plaintext so existing call sites don't have to change
/// their buffer story.
pub fn aead_open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if ciphertext_with_tag.len() < TAG_LEN {
        return Err(AeadError::Aead);
    }
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| AeadError::Aead)?;
    let opening = LessSafeKey::new(unbound);
    let mut in_out: Vec<u8> = ciphertext_with_tag.to_vec();
    let plaintext_len = {
        let pt = opening
            .open_in_place(
                Nonce::assume_unique_for_key(*nonce),
                Aad::from(aad),
                &mut in_out,
            )
            .map_err(|_| AeadError::Aead)?;
        pt.len()
    };
    in_out.truncate(plaintext_len);
    Ok(in_out)
}

/// A pre-expanded ChaCha20-Poly1305 key, suitable for amortising the
/// per-call `UnboundKey::new` cost across many frames under the same
/// session key.
///
/// The obfs4 sealer/opener pair (`crates/octravpn-obfs4/src/frame.rs`)
/// holds one of these for the lifetime of a session — every per-frame
/// seal/open hits [`AeadKey::seal`] / [`AeadKey::open`] directly. Onion
/// peel keys live for only one packet so they keep using the one-shot
/// [`aead_seal`] / [`aead_open`] helpers.
pub struct AeadKey {
    key: LessSafeKey,
}

impl AeadKey {
    /// Construct from a 32-byte key. Failure is impossible for a
    /// 32-byte key under `CHACHA20_POLY1305` in the current `aws-lc-rs`
    /// build; the `Result` is here so a future algorithm-change path
    /// (e.g. selecting AES-256-GCM under a key shorter than 32 bytes)
    /// surfaces an error rather than panicking.
    pub fn new(key: &[u8; KEY_LEN]) -> Result<Self, AeadError> {
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| AeadError::Aead)?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
        })
    }

    /// Seal `plaintext` into a fresh ciphertext-with-tag `Vec`. Same
    /// semantics as [`aead_seal`] but without the per-call key
    /// expansion.
    pub fn seal(
        &self,
        nonce: &[u8; AEAD_NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        if (plaintext.len() as u64) > MAX_PLAINTEXT_BYTES {
            return Err(AeadError::PlaintextTooLong(plaintext.len()));
        }
        let mut in_out: Vec<u8> = Vec::with_capacity(plaintext.len() + TAG_LEN);
        in_out.extend_from_slice(plaintext);
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(*nonce),
                Aad::from(aad),
                &mut in_out,
            )
            .map_err(|_| AeadError::Aead)?;
        Ok(in_out)
    }

    /// Open `ciphertext_with_tag`. Same semantics as [`aead_open`] but
    /// without the per-call key expansion.
    pub fn open(
        &self,
        nonce: &[u8; AEAD_NONCE_LEN],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        if ciphertext_with_tag.len() < TAG_LEN {
            return Err(AeadError::Aead);
        }
        let mut in_out: Vec<u8> = ciphertext_with_tag.to_vec();
        let plaintext_len = {
            let pt = self
                .key
                .open_in_place(
                    Nonce::assume_unique_for_key(*nonce),
                    Aad::from(aad),
                    &mut in_out,
                )
                .map_err(|_| AeadError::Aead)?;
            pt.len()
        };
        in_out.truncate(plaintext_len);
        Ok(in_out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 32-byte deterministic key for tests; avoids OsRng-dependence so
    /// the tests are reproducible.
    fn test_key() -> [u8; KEY_LEN] {
        let mut k = [0u8; KEY_LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(13);
        }
        k
    }

    fn test_nonce(counter: u64) -> [u8; AEAD_NONCE_LEN] {
        let mut n = [0u8; AEAD_NONCE_LEN];
        n[4..].copy_from_slice(&counter.to_be_bytes());
        n
    }

    #[test]
    fn round_trip_with_aad() {
        let key = test_key();
        let nonce = test_nonce(1);
        let aad = b"octravpn-aead-test-v1";
        let pt = b"the quick brown fox jumps over the lazy dog";
        let ct = aead_seal(&key, &nonce, aad, pt).unwrap();
        assert_eq!(ct.len(), pt.len() + TAG_LEN);
        let recovered = aead_open(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn aad_bind_rejects_mismatch() {
        let key = test_key();
        let nonce = test_nonce(2);
        let ct = aead_seal(&key, &nonce, b"correct-aad", b"payload").unwrap();
        // Opening with a different AAD must fail; this is the AEAD's
        // "associated data is bound to the ciphertext" property.
        let err = aead_open(&key, &nonce, b"wrong-aad", &ct);
        assert!(matches!(err, Err(AeadError::Aead)));
    }

    #[test]
    fn wrong_nonce_rejects_open() {
        // Per RFC 8439, opening with a different nonce than was used to
        // seal yields a tag mismatch. This stands in for the "nonce
        // uniqueness rejection" property: a replayed-frame attacker who
        // tries to open with a stale nonce against a rekeyed sealer's
        // ciphertext gets a hard failure.
        let key = test_key();
        let ct = aead_seal(&key, &test_nonce(10), b"", b"hello").unwrap();
        let err = aead_open(&key, &test_nonce(11), b"", &ct);
        assert!(matches!(err, Err(AeadError::Aead)));
    }

    #[test]
    fn malformed_tag_rejected() {
        let key = test_key();
        let nonce = test_nonce(3);
        let mut ct = aead_seal(&key, &nonce, b"", b"payload-x").unwrap();
        // Flip a bit in the tag (last 16 bytes are the Poly1305 tag).
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        let err = aead_open(&key, &nonce, b"", &ct);
        assert!(matches!(err, Err(AeadError::Aead)));
    }

    #[test]
    fn zero_length_plaintext_round_trips() {
        // An empty plaintext still seals to a 16-byte ciphertext (the
        // Poly1305 tag). This matches the portable crate's behaviour and
        // is required by call sites that send heartbeat-style "no
        // payload, just authenticated counter advance" frames.
        let key = test_key();
        let nonce = test_nonce(4);
        let ct = aead_seal(&key, &nonce, b"aad", b"").unwrap();
        assert_eq!(ct.len(), TAG_LEN);
        let recovered = aead_open(&key, &nonce, b"aad", &ct).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn truncated_ciphertext_rejected() {
        // A ciphertext shorter than the tag length cannot be authentic;
        // the shim rejects it without invoking the underlying crate.
        let key = test_key();
        let nonce = test_nonce(5);
        let err = aead_open(&key, &nonce, b"", &[0u8; TAG_LEN - 1]);
        assert!(matches!(err, Err(AeadError::Aead)));
    }

    #[test]
    fn near_max_plaintext_seal_succeeds() {
        // 64 KiB is well above the MTU but well below the RFC 8439
        // 256 GiB ceiling. The "max-length plaintext within RFC 8439
        // limits" test exercises the path without OOM-ing CI.
        let key = test_key();
        let nonce = test_nonce(6);
        let pt = vec![0xCDu8; 64 * 1024];
        let ct = aead_seal(&key, &nonce, b"", &pt).unwrap();
        let recovered = aead_open(&key, &nonce, b"", &ct).unwrap();
        assert_eq!(recovered, pt);
    }

    /// **Safety gate.** The whole point of the migration is that the
    /// AEAD output is the same standard. This test seals the same
    /// `(key, nonce, aad, plaintext)` tuple with both the old portable
    /// `chacha20poly1305 = "0.10"` crate and the new `aws-lc-rs` shim
    /// and asserts byte-identity, then cross-opens each impl's output
    /// with the other. Any divergence is a bug — either in the shim's
    /// nonce-/aad-handling, or (extremely unlikely) in one of the
    /// underlying crates. Either way Perf-5 cannot ship.
    #[test]
    fn cross_impl_compatibility() {
        use chacha20poly1305::{
            aead::{Aead, KeyInit, Payload},
            ChaCha20Poly1305, Key, Nonce as PortableNonce,
        };

        let key = test_key();
        let nonce = test_nonce(42);
        let aad = b"octravpn-aead-cross-impl-v1";

        for &plaintext_len in &[0usize, 1, 16, 64, 1380, 4096] {
            let mut pt = vec![0u8; plaintext_len];
            // Fill with a deterministic pattern so any byte-level
            // divergence shows up at a known offset.
            for (i, b) in pt.iter_mut().enumerate() {
                *b = ((i * 31) ^ 0xA5) as u8;
            }

            // New (aws-lc-rs) path.
            let new_ct = aead_seal(&key, &nonce, aad, &pt).unwrap();

            // Old (portable RustCrypto) path.
            let portable = ChaCha20Poly1305::new(Key::from_slice(&key));
            let old_ct = portable
                .encrypt(
                    PortableNonce::from_slice(&nonce),
                    Payload {
                        msg: &pt,
                        aad: aad.as_ref(),
                    },
                )
                .expect("portable seal");

            assert_eq!(
                new_ct, old_ct,
                "AEAD output diverged at len={plaintext_len}: aws-lc-rs vs portable RustCrypto"
            );

            // Cross-open: old ciphertext opens under new impl.
            let recovered_via_new = aead_open(&key, &nonce, aad, &old_ct).unwrap();
            assert_eq!(recovered_via_new, pt);

            // Cross-open: new ciphertext opens under old impl.
            let recovered_via_old = portable
                .decrypt(
                    PortableNonce::from_slice(&nonce),
                    Payload {
                        msg: &new_ct,
                        aad: aad.as_ref(),
                    },
                )
                .expect("portable open of aws-lc-rs ciphertext");
            assert_eq!(recovered_via_old, pt);
        }
    }
}
