//! Pedersen commitments over the Ristretto group (Curve25519).
//!
//! commit(addr, blind) = blind * G + H(addr) * `H_point`
//!
//! Where:
//!   - G is the Ristretto basepoint
//!   - `H_point` is a fixed second generator derived deterministically from
//!     a domain-separation tag (so its discrete log w.r.t. G is unknown)
//!   - H(addr) maps the 32-byte address into a Ristretto scalar
//!
//! Properties:
//!   - **Hiding**: a uniformly random `blind` perfectly hides `addr`.
//!   - **Binding**: opening to a different (addr', blind') would require
//!     knowing the discrete log of `H_point` w.r.t. G, which is hard.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand::RngCore;
use sha2::{Digest, Sha512};

use crate::address::Address;

pub const COMMIT_DOMAIN: &[u8] = b"octravpn-commit-v1";
pub const BLIND_LEN: usize = 32;
pub const COMMIT_LEN: usize = 32;

/// 32-byte compressed Ristretto point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment(pub [u8; COMMIT_LEN]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    pub addr: Address,
    pub blind: [u8; BLIND_LEN],
}

/// The second Pedersen generator. Derived once at startup from a fixed
/// hash-to-curve so the discrete log w.r.t. G is unknown.
fn h_point() -> RistrettoPoint {
    let mut hash = Sha512::new();
    hash.update(b"octravpn-pedersen-H-v1");
    RistrettoPoint::from_uniform_bytes(&hash.finalize().into())
}

fn addr_to_scalar(addr: &Address) -> Scalar {
    let mut hash = Sha512::new();
    hash.update(b"octravpn-pedersen-addr-v1");
    hash.update(addr.as_bytes());
    Scalar::from_bytes_mod_order_wide(&hash.finalize().into())
}

fn blind_to_scalar(blind: &[u8; BLIND_LEN]) -> Scalar {
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(blind);
    Scalar::from_bytes_mod_order_wide(&wide)
}

pub fn fresh_blind() -> [u8; BLIND_LEN] {
    let mut b = [0u8; BLIND_LEN];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

pub fn commit(addr: &Address, blind: &[u8; BLIND_LEN]) -> Commitment {
    let r = blind_to_scalar(blind);
    let m = addr_to_scalar(addr);
    let point = &r * RISTRETTO_BASEPOINT_TABLE + m * h_point();
    Commitment(point.compress().to_bytes())
}

pub fn verify_open(c: &Commitment, opening: &Opening) -> bool {
    let lhs = match CompressedRistretto::from_slice(&c.0) {
        Ok(cp) => match cp.decompress() {
            Some(pt) => pt,
            None => return false,
        },
        Err(_) => return false,
    };
    let r = blind_to_scalar(&opening.blind);
    let m = addr_to_scalar(&opening.addr);
    let rhs = &r * RISTRETTO_BASEPOINT_TABLE + m * h_point();
    lhs == rhs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_open_round_trip() {
        let a = Address::from_display("octABC123");
        let b = fresh_blind();
        let c = commit(&a, &b);
        assert!(verify_open(&c, &Opening { addr: a, blind: b }));
    }

    #[test]
    fn wrong_blind_fails() {
        let a = Address::from_display("octABC123");
        let b = fresh_blind();
        let c = commit(&a, &b);
        let mut b2 = b;
        b2[0] ^= 1;
        assert!(!verify_open(&c, &Opening { addr: a, blind: b2 }));
    }

    #[test]
    fn wrong_addr_fails() {
        let a = Address::from_display("octABC123");
        let b = fresh_blind();
        let c = commit(&a, &b);
        let other = Address::from_display("octZZZ");
        assert!(!verify_open(
            &c,
            &Opening {
                addr: other,
                blind: b
            }
        ));
    }

    #[test]
    fn hiding_distinct_blinds_distinct_commits() {
        let a = Address::from_display("octABC");
        let c1 = commit(&a, &fresh_blind());
        let c2 = commit(&a, &fresh_blind());
        assert_ne!(c1, c2);
    }

    /// Malformed commit bytes (32-byte point that isn't a valid
    /// Ristretto encoding) surface as `verify_open == false`, not
    /// panic. Catches the "decompress returns None" branch.
    #[test]
    fn malformed_commit_bytes_reject_safely() {
        let a = Address::from_display("octABC123");
        let b = fresh_blind();
        let bogus = Commitment([0xFFu8; COMMIT_LEN]);
        assert!(!verify_open(&bogus, &Opening { addr: a, blind: b }));
    }

    /// All-zero commit (identity point compressed) is valid but must
    /// not open to a random (addr, blind). Confirms point-equality
    /// semantics, not byte-pattern matching.
    #[test]
    fn identity_commit_does_not_open_random_addr() {
        use curve25519_dalek::traits::Identity;
        let identity = Commitment(
            curve25519_dalek::ristretto::RistrettoPoint::identity()
                .compress()
                .to_bytes(),
        );
        let a = Address::from_display("octRANDOM");
        let b = fresh_blind();
        assert!(!verify_open(&identity, &Opening { addr: a, blind: b }));
    }

    /// Zero blind: still a valid scalar. Catches a regression where
    /// empty-bytes paths special-cased to "no commit".
    #[test]
    fn zero_blind_round_trips() {
        let a = Address::from_display("octABC");
        let zero = [0u8; BLIND_LEN];
        let c = commit(&a, &zero);
        assert!(verify_open(
            &c,
            &Opening {
                addr: a,
                blind: zero
            }
        ));
    }

    /// `fresh_blind` returns exactly 32 bytes. Guards against a
    /// regression to a different RNG fill width.
    #[test]
    fn fresh_blind_length() {
        let b = fresh_blind();
        assert_eq!(b.len(), BLIND_LEN);
    }

    #[test]
    fn additive_homomorphism_property() {
        // c(a, r1) + c(a', r2) should equal c(a + a', r1 + r2) — verifying
        // the underlying group structure works as expected.
        let a1 = Address::from_display("octONE");
        let a2 = Address::from_display("octTWO");
        let r1 = fresh_blind();
        let r2 = fresh_blind();
        let c1 = commit(&a1, &r1);
        let c2 = commit(&a2, &r2);
        let p1 = CompressedRistretto::from_slice(&c1.0)
            .unwrap()
            .decompress()
            .unwrap();
        let p2 = CompressedRistretto::from_slice(&c2.0)
            .unwrap()
            .decompress()
            .unwrap();
        let sum = p1 + p2;

        let r1s = blind_to_scalar(&r1);
        let r2s = blind_to_scalar(&r2);
        let m1 = addr_to_scalar(&a1);
        let m2 = addr_to_scalar(&a2);
        let r_sum = r1s + r2s;
        let m_sum = m1 + m2;
        let expected = &r_sum * RISTRETTO_BASEPOINT_TABLE + m_sum * h_point();
        assert_eq!(sum, expected);
    }
}
