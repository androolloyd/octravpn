//! Per-session encrypted byte counter.
//!
//! v1 uses a *mock* HFHE ciphertext: an opaque `hfhe_v1|<hex>` string
//! whose hex payload is just the plaintext byte count, big-endian.
//! Real PVAC arithmetic is deferred (`pvac_hfhe_cpp` PoC lacks the
//! proof primitives the AML needs; see `docs/v2-octra-questions.md`).
//!
//! The shape mirrors what real HFHE would look like:
//!   * `EncryptedCounter::seal(0)` — initial encrypt-of-zero.
//!   * `EncryptedCounter::add_const(n)` — homomorphic `ct + n`.
//!   * `EncryptedCounter::open(&secret)` — decrypt at settle time.
//!
//! When we wire real PVAC, the signatures stay the same; only the
//! body changes.

use serde::{Deserialize, Serialize};

const PREFIX: &str = "hfhe_v1|";

/// One operator's mock-encrypted byte counter for a session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedCounter {
    /// Wire-format ciphertext (`hfhe_v1|<hex>`). For v1 this is just
    /// the plaintext count, but we keep the prefix so the wire shape
    /// matches what `program/main.aml` already accepts via
    /// `fhe_deser` / `fhe_ser`.
    pub ct: String,
}

impl EncryptedCounter {
    /// Encrypt 0 (initial counter).
    pub fn seal_zero() -> Self {
        Self::from_plain(0)
    }

    /// Helper for tests: build a counter that decrypts to `n`.
    pub fn from_plain(n: u64) -> Self {
        let body = hex::encode(n.to_be_bytes());
        Self {
            ct: format!("{PREFIX}{body}"),
        }
    }

    /// Homomorphic add-constant. Returns the new ciphertext;
    /// `self` is unchanged.
    pub fn add_const(&self, k: u64) -> Self {
        let cur = self.peek_unsafe();
        Self::from_plain(cur.saturating_add(k))
    }

    /// "Decrypt" (mock — for tests + ledger reads). Real PVAC would
    /// require the operator's seckey; the mock just reads the
    /// plaintext we stashed.
    pub fn open(&self) -> u64 {
        self.peek_unsafe()
    }

    fn peek_unsafe(&self) -> u64 {
        let stripped = self.ct.strip_prefix(PREFIX).unwrap_or(&self.ct);
        let bytes = hex::decode(stripped).unwrap_or_default();
        if bytes.len() != 8 {
            return 0;
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&bytes);
        u64::from_be_bytes(b)
    }
}

/// Per-session metering surface used by the Circle. Wraps an
/// [`EncryptedCounter`] and exposes the operations a packet pipeline
/// actually needs.
#[derive(Clone, Debug)]
pub struct ByteMeter {
    counter: EncryptedCounter,
}

impl ByteMeter {
    pub fn new() -> Self {
        Self {
            counter: EncryptedCounter::seal_zero(),
        }
    }

    /// Increment by `n` bytes (one packet, one batch — whatever the
    /// caller wants).
    pub fn record(&mut self, n: u64) {
        self.counter = self.counter.add_const(n);
    }

    /// Wire-format ciphertext (what `settle_claim` / `claim_earnings`
    /// will eventually send to the chain).
    pub fn ciphertext(&self) -> &str {
        &self.counter.ct
    }

    /// Plaintext for settle: the operator must reveal `bytes_used`
    /// to the AML in v1's pattern (the AML doesn't yet compute
    /// `bytes * price` under HFHE). When v2 Path B
    /// ([`docs/v2-circles-design.md`] §4.4) ships, this changes to
    /// return only a transciphered ct.
    pub fn bytes_used(&self) -> u64 {
        self.counter.open()
    }
}

impl Default for ByteMeter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_meter_reads_zero() {
        let m = ByteMeter::new();
        assert_eq!(m.bytes_used(), 0);
        assert!(m.ciphertext().starts_with("hfhe_v1|"));
    }

    #[test]
    fn record_accumulates() {
        let mut m = ByteMeter::new();
        m.record(100);
        m.record(50);
        m.record(7);
        assert_eq!(m.bytes_used(), 157);
    }

    #[test]
    fn ciphertext_is_stable_for_same_total() {
        let mut a = ByteMeter::new();
        let mut b = ByteMeter::new();
        a.record(40);
        a.record(60);
        b.record(100);
        assert_eq!(a.ciphertext(), b.ciphertext());
    }
}
