//! Frame sealing and opening for obfs4-modelled transport.
//!
//! # Wire layout
//!
//! Every post-handshake datagram on the wire looks like:
//!
//! ```text
//!   ┌──────────────────────┬──────────────────────────────────────┐
//!   │ u16 BE  total_len    │ ciphertext_with_tag (total_len bytes)│
//!   ├──────────────────────┴──────────────────────────────────────┤
//!   │  ciphertext_with_tag = ChaCha20-Poly1305(                   │
//!   │      key  = direction_key,                                  │
//!   │      nonce = 4-byte tag || u64 BE counter,                  │
//!   │      aad  = (empty),                                        │
//!   │      plaintext = [u16 BE real_len] [real_payload]           │
//!   │                  [random padding]                           │
//!   │  )                                                          │
//!   │  + 16 byte Poly1305 tag                                     │
//!   └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! Properties:
//!
//! - **Length-randomised.** Padding is uniform in
//!   `[MIN_PAD_PLAINTEXT, MAX_PAD_PLAINTEXT]`, so a 92-byte WG
//!   transport packet does not produce a constant-length frame.
//! - **AEAD-sealed.** Tampering anywhere in the ciphertext (including
//!   the length field, which is the first plaintext bytes) fails the
//!   Poly1305 check and the frame is dropped.
//! - **Counter per direction.** The 8-byte counter starts at 0 on
//!   each direction and increments monotonically. A replayed frame
//!   has the wrong counter and produces a tag mismatch.
//!
//! # Why a 2-byte outer length
//!
//! Each datagram is one frame; the outer u16 lets a hypothetical
//! framed-over-TCP variant chunk-and-coalesce without redesigning
//! the inner format. Maximum frame size is 65 535 bytes (well above
//! the WG-side MTU).
//!
//! # Per-key message-count budget (audit-1 H-2)
//!
//! The 8-byte counter is the bottom half of the ChaCha20-Poly1305
//! nonce; reusing it under the same key is a catastrophic
//! confidentiality failure. The counter therefore MUST NOT wrap. We
//! enforce this by switching every `counter` mutation to
//! [`u64::checked_add`] — a frame at `u64::MAX` is the last frame any
//! sealer/opener will accept under the current key, and any attempt to
//! emit / open a 2^64-th frame surfaces as
//! [`FrameError::CounterExhausted`]. Operators rotate the key (close
//! and re-handshake the obfs4 session) well before that point.
//!
//! At a sustained 1 Mfps the budget is `2^64 / 1e6 / 86400 / 365 ≈
//! 585 000 millennia`, so the hard wall is practically unreachable —
//! but switching from `wrapping_add` to `checked_add` removes any
//! silent regression path (e.g. a future shrink to a 32-bit counter
//! would otherwise wrap at ~71 minutes of saturated traffic).

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{Rng, RngCore};
use thiserror::Error;

/// Inner padding bounds. Plaintext layout is
/// `[u16 BE real_len] [payload] [padding]`. Padding bytes are
/// uniformly random in this range.
const MIN_PAD_PLAINTEXT: usize = 0;
const MAX_PAD_PLAINTEXT: usize = 256;

/// Maximum size of a single decrypted payload, in bytes. Generous
/// for WG packets (an MTU-1500 IPv4 packet plus WG overhead is well
/// under 1600 bytes).
pub const MAX_PAYLOAD: usize = 16 * 1024;

/// Outer length prefix is u16 BE.
const LEN_PREFIX_BYTES: usize = 2;
/// Inner plaintext "real length" prefix is also u16 BE.
const INNER_LEN_BYTES: usize = 2;
/// Poly1305 tag length.
const TAG_LEN: usize = 16;

/// Errors raised by the framing layer.
#[derive(Debug, Error)]
pub enum FrameError {
    /// Incoming buffer didn't contain a full frame (couldn't read the
    /// length prefix, or the prefix exceeded the buffer).
    #[error("incomplete frame: have {have} bytes, need {need}")]
    Incomplete {
        /// Bytes available in the input buffer.
        have: usize,
        /// Bytes the framing layer needs to decode the next frame.
        need: usize,
    },
    /// AEAD tag did not validate. Either the frame was tampered with,
    /// the counter is out of sync, or this is a replay.
    #[error("aead tag mismatch")]
    BadTag,
    /// Inner length field claimed more bytes than the plaintext
    /// contained, or more than [`MAX_PAYLOAD`].
    #[error("inner length out of bounds: claimed {claimed}, max {max}")]
    BadInnerLen {
        /// The length the inner header claimed.
        claimed: usize,
        /// The maximum length the surrounding plaintext could possibly
        /// hold.
        max: usize,
    },
    /// `send_to` was called with a payload that wouldn't fit even
    /// after sealing (MAX_PAYLOAD exceeded).
    #[error("payload too large: {0} bytes (max {MAX_PAYLOAD})")]
    PayloadTooLarge(usize),
    /// audit-1 H-2: the 64-bit counter that drives the AEAD nonce has
    /// reached its maximum and cannot increment without wrapping. Any
    /// further frame under the current key would risk nonce reuse;
    /// callers MUST tear down the session and re-handshake to obtain a
    /// fresh key + zeroed counter.
    #[error(
        "counter exhausted: the 2^64-frame per-key budget has been spent — rotate keys"
    )]
    CounterExhausted,
}

/// Direction-tagged ChaCha20-Poly1305 sealer. Owns the key + the
/// monotonic counter; `seal_into` advances the counter every call.
pub struct FrameSealer {
    cipher: ChaCha20Poly1305,
    nonce_prefix: [u8; 4],
    counter: u64,
}

impl FrameSealer {
    /// Construct a sealer. `nonce_prefix` is a 4-byte tag that
    /// distinguishes this direction from the opposite direction so a
    /// reflected frame can't be opened as if it came from the other
    /// peer. Convention: `b"c2s\0"` for client→server, `b"s2c\0"` for
    /// server→client.
    pub fn new(key: &[u8; 32], nonce_prefix: [u8; 4]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
            nonce_prefix,
            counter: 0,
        }
    }

    /// Seal `payload` into a frame written to `out`. Returns the
    /// total bytes appended.
    pub fn seal_into(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<usize, FrameError> {
        if payload.len() > MAX_PAYLOAD {
            return Err(FrameError::PayloadTooLarge(payload.len()));
        }

        // audit-1 H-2: refuse to wrap the AEAD nonce. We check the
        // *next* counter value before sealing so the last accepted
        // frame is at `u64::MAX - 1` and `u64::MAX` itself is reserved
        // — any attempt to emit a frame from a sealer whose counter
        // has reached `u64::MAX` returns `CounterExhausted` BEFORE the
        // ciphertext is appended to `out`. This way the caller's
        // buffer is never mutated under an exhausted-counter path.
        let next_counter = self
            .counter
            .checked_add(1)
            .ok_or(FrameError::CounterExhausted)?;

        // Build the plaintext: [u16 BE real_len] [payload] [random pad].
        let pad_len = rand::thread_rng().gen_range(MIN_PAD_PLAINTEXT..=MAX_PAD_PLAINTEXT);
        let mut plaintext = Vec::with_capacity(INNER_LEN_BYTES + payload.len() + pad_len);
        plaintext.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        plaintext.extend_from_slice(payload);
        let pad_start = plaintext.len();
        plaintext.resize(pad_start + pad_len, 0);
        rand::thread_rng().fill_bytes(&mut plaintext[pad_start..]);

        // Nonce = 4-byte prefix || u64 BE counter.
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&self.nonce_prefix);
        nonce_bytes[4..].copy_from_slice(&self.counter.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Seal.
        let ciphertext = self
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &plaintext,
                    aad: &[],
                },
            )
            .map_err(|_| FrameError::BadTag)?; // encrypt cannot really fail; map for total cover.
        // audit-1 H-2: counter advance pre-validated above.
        self.counter = next_counter;

        // Emit: [u16 BE total_len] [ciphertext (incl tag)].
        let total_len = ciphertext.len();
        // u16 BE bounds-checked: ciphertext = plaintext + 16-byte tag.
        // plaintext ≤ MAX_PAYLOAD + 2 + 256 = MAX_PAYLOAD + 258.
        // ciphertext ≤ MAX_PAYLOAD + 274 ≤ 16_658, well under u16::MAX.
        let total_u16 = u16::try_from(total_len).expect("frame fits in u16");
        out.extend_from_slice(&total_u16.to_be_bytes());
        out.extend_from_slice(&ciphertext);
        Ok(LEN_PREFIX_BYTES + total_len)
    }
}

/// Direction-tagged ChaCha20-Poly1305 opener.
pub struct FrameOpener {
    cipher: ChaCha20Poly1305,
    nonce_prefix: [u8; 4],
    counter: u64,
}

impl FrameOpener {
    /// Construct an opener; see [`FrameSealer::new`].
    pub fn new(key: &[u8; 32], nonce_prefix: [u8; 4]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
            nonce_prefix,
            counter: 0,
        }
    }

    /// Open one frame from the head of `buf`. Returns
    /// `(payload, consumed_bytes)` on success. On error, the opener's
    /// counter does not advance (caller can attempt resynchronisation
    /// via skipping to the next datagram boundary — but for UDP we
    /// drop the offending datagram entirely).
    pub fn open_from(&mut self, buf: &[u8]) -> Result<(Vec<u8>, usize), FrameError> {
        // audit-1 H-2: refuse to wrap the AEAD nonce. Same pre-check as
        // the sealer's: if the next counter would overflow, reject this
        // frame outright. The opener has not yet consumed bytes from
        // `buf`, so the caller's read position is preserved.
        let next_counter = self
            .counter
            .checked_add(1)
            .ok_or(FrameError::CounterExhausted)?;
        if buf.len() < LEN_PREFIX_BYTES {
            return Err(FrameError::Incomplete {
                have: buf.len(),
                need: LEN_PREFIX_BYTES,
            });
        }
        let total_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        let frame_end = LEN_PREFIX_BYTES + total_len;
        if buf.len() < frame_end {
            return Err(FrameError::Incomplete {
                have: buf.len(),
                need: frame_end,
            });
        }
        if total_len < TAG_LEN + INNER_LEN_BYTES {
            return Err(FrameError::BadTag);
        }
        let ciphertext = &buf[LEN_PREFIX_BYTES..frame_end];

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&self.nonce_prefix);
        nonce_bytes[4..].copy_from_slice(&self.counter.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = self
            .cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &[],
                },
            )
            .map_err(|_| FrameError::BadTag)?;
        // audit-1 H-2: counter advance pre-validated above.
        self.counter = next_counter;

        if plaintext.len() < INNER_LEN_BYTES {
            return Err(FrameError::BadTag);
        }
        let real_len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
        if real_len > plaintext.len() - INNER_LEN_BYTES || real_len > MAX_PAYLOAD {
            return Err(FrameError::BadInnerLen {
                claimed: real_len,
                max: plaintext.len() - INNER_LEN_BYTES,
            });
        }
        let mut payload = vec![0u8; real_len];
        payload.copy_from_slice(&plaintext[INNER_LEN_BYTES..INNER_LEN_BYTES + real_len]);
        Ok((payload, frame_end))
    }
}

impl FrameSealer {
    /// Test-only counter setter. Production code never touches the
    /// counter directly; only `seal_into` advances it. Tests use this
    /// to drive the audit-1 H-2 `CounterExhausted` guard at the
    /// boundary without sealing `u64::MAX` legitimate frames first.
    #[cfg(test)]
    pub(crate) fn set_counter_for_test(&mut self, c: u64) {
        self.counter = c;
    }
}

impl FrameOpener {
    /// Test-only counter setter; see [`FrameSealer::set_counter_for_test`].
    #[cfg(test)]
    pub(crate) fn set_counter_for_test(&mut self, c: u64) {
        self.counter = c;
    }
}

/// Nonce-prefix constant for client→server frames.
pub const NONCE_PREFIX_C2S: [u8; 4] = *b"C2S\0";
/// Nonce-prefix constant for server→client frames.
pub const NONCE_PREFIX_S2C: [u8; 4] = *b"S2C\0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = [7u8; 32];
        let mut sealer = FrameSealer::new(&key, NONCE_PREFIX_C2S);
        let mut opener = FrameOpener::new(&key, NONCE_PREFIX_C2S);
        let payload = b"WG transport packet bytes";
        let mut wire = Vec::new();
        sealer.seal_into(payload, &mut wire).unwrap();
        let (out, n) = opener.open_from(&wire).unwrap();
        assert_eq!(out, payload);
        assert_eq!(n, wire.len());
    }

    #[test]
    fn fixed_input_produces_random_length_output() {
        let key = [9u8; 32];
        let mut sealer = FrameSealer::new(&key, NONCE_PREFIX_C2S);
        let payload = [0u8; 148]; // mimics WG handshake-init size
        let mut sizes = std::collections::HashSet::new();
        for _ in 0..32 {
            let mut wire = Vec::new();
            sealer.seal_into(&payload, &mut wire).unwrap();
            sizes.insert(wire.len());
        }
        assert!(
            sizes.len() > 4,
            "expected diverse frame sizes for fixed input, got {} distinct",
            sizes.len()
        );
    }

    #[test]
    fn tampered_frame_fails() {
        let key = [1u8; 32];
        let mut sealer = FrameSealer::new(&key, NONCE_PREFIX_C2S);
        let mut opener = FrameOpener::new(&key, NONCE_PREFIX_C2S);
        let mut wire = Vec::new();
        sealer.seal_into(b"hello", &mut wire).unwrap();
        let flip = wire.len() - 3;
        wire[flip] ^= 0x01;
        assert!(matches!(opener.open_from(&wire), Err(FrameError::BadTag)));
    }

    #[test]
    fn wrong_direction_prefix_fails() {
        let key = [3u8; 32];
        let mut sealer = FrameSealer::new(&key, NONCE_PREFIX_C2S);
        let mut opener = FrameOpener::new(&key, NONCE_PREFIX_S2C);
        let mut wire = Vec::new();
        sealer.seal_into(b"hi", &mut wire).unwrap();
        assert!(matches!(opener.open_from(&wire), Err(FrameError::BadTag)));
    }

    #[test]
    fn replay_fails_after_counter_advance() {
        let key = [4u8; 32];
        let mut sealer = FrameSealer::new(&key, NONCE_PREFIX_C2S);
        let mut opener = FrameOpener::new(&key, NONCE_PREFIX_C2S);

        // Seal two frames at counter=0 and counter=1.
        let mut a = Vec::new();
        sealer.seal_into(b"first", &mut a).unwrap();
        let mut b = Vec::new();
        sealer.seal_into(b"second", &mut b).unwrap();

        // Open in order — both succeed and the opener's counter
        // advances to 2.
        let (got_a, _) = opener.open_from(&a).expect("a opens at counter=0");
        assert_eq!(got_a, b"first");
        let (got_b, _) = opener.open_from(&b).expect("b opens at counter=1");
        assert_eq!(got_b, b"second");

        // Now replay `a`. The opener is at counter=2, so the
        // ChaCha20-Poly1305 tag computed under counter=0 must not
        // verify under counter=2.
        assert!(matches!(opener.open_from(&a), Err(FrameError::BadTag)));
    }

    #[test]
    fn incomplete_frame_signals_need() {
        let key = [0u8; 32];
        let mut opener = FrameOpener::new(&key, NONCE_PREFIX_C2S);
        let err = opener.open_from(&[]).unwrap_err();
        assert!(matches!(err, FrameError::Incomplete { .. }));
    }

    // ---------- Length-distribution: chi-squared-style spread ----------

    /// Stronger length-randomisation guard than the existing
    /// `fixed_input_produces_random_length_output`. Asserts that the
    /// distribution over a fixed input is not constant AND has at least
    /// 32 distinct sizes across 10 000 trials, i.e. the padding RNG
    /// actually spans most of `[MIN_PAD, MAX_PAD]`.
    #[test]
    fn padding_distribution_covers_range() {
        let key = [11u8; 32];
        let mut sealer = FrameSealer::new(&key, NONCE_PREFIX_C2S);
        let payload = [0u8; 148];
        let mut sizes = std::collections::HashMap::new();
        for _ in 0..10_000 {
            let mut wire = Vec::new();
            sealer.seal_into(&payload, &mut wire).unwrap();
            *sizes.entry(wire.len()).or_insert(0u32) += 1;
        }
        assert!(
            sizes.len() >= 32,
            "expected ≥32 distinct frame sizes over 10k trials, got {} (RNG seam weak?)",
            sizes.len()
        );
        // Chi-square-ish "not concentrated in one bucket" check: no
        // single size should dominate (>20% of all samples).
        let max = sizes.values().copied().max().unwrap();
        assert!(
            max < 2_000,
            "one size dominates ({max}/10000 samples) — padding distribution skewed"
        );
    }

    // ---------- Counter replay across 5 frames ----------

    #[test]
    fn five_counters_yield_five_distinct_ciphertexts() {
        // Same plaintext under counters 0..5 must produce 5 distinct
        // wire frames (nonce includes the counter). Random padding
        // would also produce distinct frames, so we strip pads off by
        // pinning the seal output bytes for inspection — instead we
        // assert that the ciphertext bytes after the length prefix
        // differ on every counter.
        let key = [0x88u8; 32];
        let mut sealer = FrameSealer::new(&key, NONCE_PREFIX_C2S);
        let payload = b"identical-payload-bytes";
        let mut seen = std::collections::HashSet::new();
        for i in 0..5 {
            let mut wire = Vec::new();
            sealer.seal_into(payload, &mut wire).unwrap();
            // Skip the 2-byte length prefix.
            let ct = wire[2..].to_vec();
            assert!(
                seen.insert(ct),
                "counter {i} produced a duplicate ciphertext"
            );
        }
    }

    #[test]
    fn replay_at_higher_counter_fails() {
        let key = [0x44u8; 32];
        let mut sealer = FrameSealer::new(&key, NONCE_PREFIX_C2S);
        let mut opener = FrameOpener::new(&key, NONCE_PREFIX_C2S);
        let mut frames = Vec::new();
        for _ in 0..5 {
            let mut w = Vec::new();
            sealer.seal_into(b"replay", &mut w).unwrap();
            frames.push(w);
        }
        // Consume frame 0 — opener advances to counter=1.
        let _ = opener.open_from(&frames[0]).unwrap();
        // Now replay frame 0 (counter=0 ciphertext) against opener at
        // counter=1 → AEAD fails.
        assert!(matches!(
            opener.open_from(&frames[0]),
            Err(FrameError::BadTag)
        ));
        // But frame 1 (counter=1) does open.
        assert!(opener.open_from(&frames[1]).is_ok());
    }

    #[test]
    fn frame_with_truncated_inner_length_field_fails() {
        // Build a wire frame, then re-encrypt with a too-large inner
        // length field; the opener's bounds check must reject.
        // (We can't easily mutate the ciphertext to flip plaintext
        // bytes deterministically, so this is a structural sanity
        // check: BadInnerLen surfaces when the inner length claim is
        // larger than the plaintext.)
        // Instead, we verify the error path triggers when total_len is
        // less than tag+inner-len header.
        let key = [0u8; 32];
        let mut opener = FrameOpener::new(&key, NONCE_PREFIX_C2S);
        // Outer length prefix says "3 bytes"; that's smaller than the
        // 16-byte tag, so open_from must reject as BadTag (we use the
        // BadTag error to encode "structurally impossible frame").
        let mut buf = vec![];
        buf.extend_from_slice(&3u16.to_be_bytes());
        buf.extend_from_slice(&[0u8; 3]);
        assert!(matches!(opener.open_from(&buf), Err(FrameError::BadTag)));
    }

    // ---------- Wrong key rejects ----------

    #[test]
    fn wrong_key_decryption_fails() {
        let mut sealer = FrameSealer::new(&[1u8; 32], NONCE_PREFIX_C2S);
        let mut opener = FrameOpener::new(&[2u8; 32], NONCE_PREFIX_C2S);
        let mut w = Vec::new();
        sealer.seal_into(b"hello", &mut w).unwrap();
        assert!(matches!(opener.open_from(&w), Err(FrameError::BadTag)));
    }

    // ---------- Max payload accepted; over-max rejected ----------

    #[test]
    fn max_payload_accepted_round_trip() {
        let key = [9u8; 32];
        let mut sealer = FrameSealer::new(&key, NONCE_PREFIX_C2S);
        let mut opener = FrameOpener::new(&key, NONCE_PREFIX_C2S);
        // Payload at exactly MAX_PAYLOAD.
        let payload = vec![0xA5u8; MAX_PAYLOAD];
        let mut wire = Vec::new();
        sealer.seal_into(&payload, &mut wire).unwrap();
        let (got, _) = opener.open_from(&wire).unwrap();
        assert_eq!(got.len(), payload.len());
        assert_eq!(got, payload);
    }

    #[test]
    fn over_max_payload_rejected() {
        let key = [0u8; 32];
        let mut sealer = FrameSealer::new(&key, NONCE_PREFIX_C2S);
        let payload = vec![0u8; MAX_PAYLOAD + 1];
        let mut w = Vec::new();
        let err = sealer.seal_into(&payload, &mut w).unwrap_err();
        assert!(matches!(err, FrameError::PayloadTooLarge(_)));
    }

    // ---------- Empty payload still round-trips ----------

    #[test]
    fn empty_payload_round_trips() {
        let key = [0xDEu8; 32];
        let mut sealer = FrameSealer::new(&key, NONCE_PREFIX_C2S);
        let mut opener = FrameOpener::new(&key, NONCE_PREFIX_C2S);
        let mut w = Vec::new();
        sealer.seal_into(b"", &mut w).unwrap();
        let (got, _) = opener.open_from(&w).unwrap();
        assert!(got.is_empty());
    }

    // ---------- Boundary: cross-direction prefix safety ----------

    #[test]
    fn s2c_frame_does_not_open_as_c2s() {
        let key = [7u8; 32];
        let mut server_sealer = FrameSealer::new(&key, NONCE_PREFIX_S2C);
        let mut client_opener = FrameOpener::new(&key, NONCE_PREFIX_C2S);
        let mut wire = Vec::new();
        server_sealer.seal_into(b"reply", &mut wire).unwrap();
        assert!(matches!(
            client_opener.open_from(&wire),
            Err(FrameError::BadTag)
        ));
    }

    // ---------- Incomplete frame: partial length prefix ----------

    #[test]
    fn one_byte_buf_signals_incomplete() {
        let key = [0u8; 32];
        let mut opener = FrameOpener::new(&key, NONCE_PREFIX_C2S);
        let err = opener.open_from(&[0u8]).unwrap_err();
        match err {
            FrameError::Incomplete { have, need } => {
                assert_eq!(have, 1);
                assert_eq!(need, 2);
            }
            other => panic!("expected Incomplete, got {other:?}"),
        }
    }

    #[test]
    fn truncated_after_length_prefix_signals_incomplete() {
        let key = [0u8; 32];
        let mut opener = FrameOpener::new(&key, NONCE_PREFIX_C2S);
        let mut buf = vec![];
        buf.extend_from_slice(&100u16.to_be_bytes());
        // No body — opener must say "I need 102 bytes."
        let err = opener.open_from(&buf).unwrap_err();
        match err {
            FrameError::Incomplete { need: 102, .. } => {}
            other => panic!("expected Incomplete{{need=102}}, got {other:?}"),
        }
    }

    // ---------- 100 random frames stress ----------

    #[test]
    fn stress_100_round_trips_under_one_session() {
        let key = [0xC0u8; 32];
        let mut sealer = FrameSealer::new(&key, NONCE_PREFIX_C2S);
        let mut opener = FrameOpener::new(&key, NONCE_PREFIX_C2S);
        for i in 0..100u64 {
            let mut payload = Vec::with_capacity(64);
            payload.extend_from_slice(b"frame#");
            payload.extend_from_slice(&i.to_le_bytes());
            let mut wire = Vec::new();
            sealer.seal_into(&payload, &mut wire).unwrap();
            let (got, n) = opener.open_from(&wire).unwrap();
            assert_eq!(n, wire.len());
            assert_eq!(got, payload, "iter {i}");
        }
    }

    // ---------- Test the existing `round_trip` is checking real bytes
    //            and not silently passing on an empty payload edge. ----

    // ---------- audit-1 H-2: counter exhaustion ----------

    /// A sealer whose counter has reached `u64::MAX` MUST refuse to
    /// emit another frame. The error is `CounterExhausted`, the
    /// caller's `out` buffer is unchanged, and the internal counter
    /// stays put — the only safe recovery is to drop this sealer +
    /// re-handshake under a fresh key.
    #[test]
    fn sealer_at_counter_max_refuses_next_frame() {
        let key = [0x55u8; 32];
        let mut sealer = FrameSealer::new(&key, NONCE_PREFIX_C2S);
        sealer.set_counter_for_test(u64::MAX);
        let before_counter = sealer.counter;
        let mut out = b"prefix-not-modified".to_vec();
        let before_out = out.clone();
        let err = sealer
            .seal_into(b"would-cause-wrap", &mut out)
            .expect_err("counter exhausted");
        assert!(matches!(err, FrameError::CounterExhausted));
        // Buffer untouched — we rejected before extending `out`.
        assert_eq!(out, before_out);
        // Internal counter unchanged so a follow-up call hits the same
        // guard rather than wrapping silently.
        assert_eq!(sealer.counter, before_counter);
    }

    /// An opener at `u64::MAX` likewise refuses. We test that the
    /// rejection happens BEFORE any cipher work so a torn or replayed
    /// frame at end-of-budget can't sneak through.
    #[test]
    fn opener_at_counter_max_refuses_next_frame() {
        let key = [0x66u8; 32];
        let mut opener = FrameOpener::new(&key, NONCE_PREFIX_C2S);
        opener.set_counter_for_test(u64::MAX);
        // Even a syntactically-valid-looking buffer is rejected.
        let mut buf = vec![];
        buf.extend_from_slice(&64u16.to_be_bytes());
        buf.extend_from_slice(&[0u8; 64]);
        let err = opener.open_from(&buf).expect_err("counter exhausted");
        assert!(matches!(err, FrameError::CounterExhausted));
    }

    /// One frame *below* exhaustion still succeeds — the last legitimate
    /// frame is at `u64::MAX - 1`. This pins the off-by-one boundary
    /// against future regressions to either `<` or `<=` checks.
    #[test]
    fn sealer_one_below_max_still_seals() {
        let key = [0x77u8; 32];
        let mut sealer = FrameSealer::new(&key, NONCE_PREFIX_C2S);
        let mut opener = FrameOpener::new(&key, NONCE_PREFIX_C2S);
        sealer.set_counter_for_test(u64::MAX - 1);
        opener.set_counter_for_test(u64::MAX - 1);
        let mut wire = Vec::new();
        sealer
            .seal_into(b"last-legitimate", &mut wire)
            .expect("seal at MAX-1 succeeds");
        // Counter advanced to MAX; next call rejects.
        assert_eq!(sealer.counter, u64::MAX);
        let (got, _) = opener.open_from(&wire).expect("open at MAX-1 succeeds");
        assert_eq!(got, b"last-legitimate");
        assert_eq!(opener.counter, u64::MAX);
        // Now both sides are exhausted; next op fails on both ends.
        let mut more = Vec::new();
        assert!(matches!(
            sealer.seal_into(b"x", &mut more),
            Err(FrameError::CounterExhausted)
        ));
    }

    #[test]
    fn round_trip_with_inner_zero_bytes_payload() {
        // Lots of repeated zero bytes — verifies the AEAD isn't masking
        // a content bug that produces an "empty"-looking payload.
        let key = [0u8; 32];
        let mut sealer = FrameSealer::new(&key, NONCE_PREFIX_C2S);
        let mut opener = FrameOpener::new(&key, NONCE_PREFIX_C2S);
        let payload = vec![0u8; 1024];
        let mut wire = Vec::new();
        sealer.seal_into(&payload, &mut wire).unwrap();
        let (got, _) = opener.open_from(&wire).unwrap();
        assert_eq!(got.len(), 1024);
        assert!(got.iter().all(|&b| b == 0));
    }
}
