//! `bound`, `sha256`, address-from-label utilities mirroring `StdUtils`.

use sha2::{Digest, Sha256};

/// `bound(x, min, max)` — clamp x into [min, max] inclusive. Useful
/// for proptest inputs.
pub fn bound(x: u64, min: u64, max: u64) -> u64 {
    assert!(min <= max, "bound: min > max");
    if max == min {
        return min;
    }
    let range = max - min + 1;
    min + (x % range)
}

/// `keccak`-equivalent: Octra uses SHA-256, so this is SHA-256.
/// (Aliased as `keccak` for muscle memory.)
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Alias for `sha256` so Solidity-trained users don't reach for the
/// wrong hash.
pub fn keccak(data: &[u8]) -> [u8; 32] {
    sha256(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_clamps() {
        // range = max - min + 1 = 6
        assert_eq!(bound(0, 5, 10), 5);    // 0 % 6 = 0 → 5
        assert_eq!(bound(5, 5, 10), 10);   // 5 % 6 = 5 → 10
        assert_eq!(bound(6, 5, 10), 5);    // 6 % 6 = 0 → 5
        assert_eq!(bound(11, 5, 10), 10);  // 11 % 6 = 5 → 10
    }

    #[test]
    fn sha256_known() {
        let h = sha256(b"abc");
        // Wikipedia known vector.
        assert_eq!(
            hex::encode(h),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
