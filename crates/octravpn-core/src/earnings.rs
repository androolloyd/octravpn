//! Validator earnings ledger using Curve25519 Pedersen commitments.
//!
//! Each validator has an earnings ledger entry: a single Ristretto point
//!
//!   E_v = a_v * G + r_v * H
//!
//! where `a_v` is the cumulative earned OCT and `r_v` is the cumulative
//! blinding. Both `a_v` and `r_v` accumulate by simple curve-point
//! addition as settlements occur, which is exactly what the on-chain
//! program performs in `settle_session`.
//!
//! Privacy: observers see `E_v` (a 32-byte point) but cannot recover
//! `a_v` without solving the discrete log. At claim time, the validator
//! reveals `(a_v, r_v)` and the chain checks `E_v == a_v * G + r_v * H`,
//! then pays out `a_v` via a stealth output and zeroes the ledger.
//!
//! `r_v` is revealed at claim, but observing `r_v` doesn't help an
//! adversary: there's only one `(a, r)` pair satisfying the equation
//! for a given E, but extracting it still requires DLP. The validator
//! tracks `r_v` off-chain by accumulating each settlement's blind.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use rand::RngCore;
use sha2::{Digest, Sha512};

use crate::CoreError;

pub const POINT_LEN: usize = 32;

/// 32-byte compressed Ristretto point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedgerPoint(pub [u8; POINT_LEN]);

impl LedgerPoint {
    pub fn zero() -> Self {
        Self(RistrettoPoint::identity().compress().to_bytes())
    }

    pub fn from_point(p: RistrettoPoint) -> Self {
        Self(p.compress().to_bytes())
    }

    pub fn to_point(self) -> Result<RistrettoPoint, CoreError> {
        CompressedRistretto::from_slice(&self.0)
            .map_err(|e| CoreError::Crypto(format!("ristretto decode: {e}")))?
            .decompress()
            .ok_or_else(|| CoreError::Crypto("ristretto decompress failed".into()))
    }
}

/// Second Pedersen generator H, with unknown discrete log w.r.t. G.
/// Derived deterministically so client/node/chain agree.
pub fn h_generator() -> RistrettoPoint {
    let mut hash = Sha512::new();
    hash.update(b"octravpn-earnings-H-v1");
    RistrettoPoint::from_uniform_bytes(&hash.finalize().into())
}

/// Encode an unsigned 64-bit amount as a Curve25519 scalar.
pub fn amount_to_scalar(a: u64) -> Scalar {
    Scalar::from(a)
}

/// Generate a fresh blinding scalar.
pub fn fresh_blind() -> Scalar {
    let mut wide = [0u8; 64];
    rand::rngs::OsRng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Compute a Pedersen commitment `a*G + r*H`.
pub fn commit(amount: u64, blind: &Scalar) -> LedgerPoint {
    let a = amount_to_scalar(amount);
    let p = &a * RISTRETTO_BASEPOINT_TABLE + blind * h_generator();
    LedgerPoint::from_point(p)
}

/// Add two ledger points together. This is what `settle_session` does.
pub fn add(a: LedgerPoint, b: LedgerPoint) -> Result<LedgerPoint, CoreError> {
    Ok(LedgerPoint::from_point(a.to_point()? + b.to_point()?))
}

/// Verify that a claim `(amount, blind)` opens a ledger point.
pub fn verify_claim(point: LedgerPoint, amount: u64, blind: &Scalar) -> bool {
    match point.to_point() {
        Ok(p) => {
            let a = amount_to_scalar(amount);
            let recomputed = &a * RISTRETTO_BASEPOINT_TABLE + blind * h_generator();
            p == recomputed
        }
        Err(_) => false,
    }
}

/// Encode a scalar to its 32-byte canonical form for transport.
pub fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    s.to_bytes()
}

/// Decode a scalar from its 32-byte canonical form.
pub fn scalar_from_bytes(b: &[u8; 32]) -> Result<Scalar, CoreError> {
    let ct = Scalar::from_canonical_bytes(*b);
    if bool::from(ct.is_some()) {
        Ok(ct.unwrap())
    } else {
        Err(CoreError::Crypto("non-canonical scalar".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_identity() {
        let z = LedgerPoint::zero();
        let p = z.to_point().unwrap();
        assert_eq!(p, RistrettoPoint::identity());
    }

    #[test]
    fn commit_then_open() {
        let r = fresh_blind();
        let c = commit(12_345, &r);
        assert!(verify_claim(c, 12_345, &r));
    }

    #[test]
    fn wrong_amount_or_blind_rejects() {
        let r = fresh_blind();
        let c = commit(100, &r);
        assert!(!verify_claim(c, 101, &r));
        let mut wrong = r;
        wrong += Scalar::ONE;
        assert!(!verify_claim(c, 100, &wrong));
    }

    #[test]
    fn additive_homomorphism() {
        let r1 = fresh_blind();
        let r2 = fresh_blind();
        let c1 = commit(50, &r1);
        let c2 = commit(70, &r2);
        let sum = add(c1, c2).unwrap();
        assert!(verify_claim(sum, 120, &(r1 + r2)));
    }

    #[test]
    fn scalar_round_trip() {
        let r = fresh_blind();
        let bytes = scalar_to_bytes(&r);
        let r2 = scalar_from_bytes(&bytes).unwrap();
        assert_eq!(r, r2);
    }
}
