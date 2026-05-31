//! Wallet-native device enrollment — the "Octra login".
//!
//! A device proves it controls **both** an Octra wallet (ed25519) and a
//! WireGuard keypair (X25519), and the operator admits it into the
//! tailnet's member set (a sealed [`crate::v3_members::TailnetMembers`]
//! in the operator circle, anchored via `circle_state_root`). This is the
//! missing live protocol behind the v3 membership model: today the owner
//! hand-builds `members.json` out-of-band and the client takes its own
//! membership "on trust" (the #191 gap). Enrollment replaces that with a
//! verified, self-service join — the operator checks a wallet signature
//! before adding a [`crate::v3_members::Member`].
//!
//! Runs on the same HTTP control plane as `/session`
//! ([`crate::control`]):
//!
//! ```text
//! GET  /enroll/challenge?tailnet_id=<id>&wallet=<oct…>
//!        → EnrollChallenge { nonce, expires_at }      (replay guard)
//! POST /enroll   { EnrollRequest, signed by the wallet }
//!        → EnrollResponse { assigned_ip, peers, members_version }
//! ```
//!
//! The signature binds `{wallet_pubkey ↔ device_wg_pubkey ↔ tailnet_id ↔
//! circle ↔ nonce}`. The operator derives the `oct…` wallet **from
//! `wallet_pubkey`** (via [`crate::address::Address::from_pubkey`]) rather
//! than trusting a client-supplied string, so a device cannot enroll
//! under a wallet whose key it does not hold; and the nonce ties the
//! request to a short operator-issued window so a captured request cannot
//! be replayed.

use serde::{Deserialize, Serialize};

use crate::{
    address::Address,
    sig::{verify, PublicKey, Signature},
    CoreResult,
};

/// HTTP path for the enrollment challenge (nonce issuance).
pub const PATH_CHALLENGE: &str = "/enroll/challenge";

/// HTTP path for the enrollment submission.
pub const PATH_ENROLL: &str = "/enroll";

/// How long an issued challenge nonce stays valid. Short — the device
/// requests, signs, and submits in a single round trip.
pub const CHALLENGE_TTL_SECS: u64 = 120;

/// Length, in bytes, of the challenge nonce (hex-encoded on the wire, so
/// `2 * NONCE_LEN` characters).
pub const NONCE_LEN: usize = 32;

/// Domain-separation prefix for the enrollment signing payload. Distinct
/// from `octravpn:announce:v1` so a session-announce signature can never
/// be replayed as an enrollment (or vice versa).
const SIGN_DOMAIN: &[u8] = b"octravpn:enroll:v1";

/// Operator → device: a one-shot nonce binding an enrollment attempt to a
/// short time window. The device echoes `nonce` in the signed
/// [`EnrollRequest`]. Issued per `(tailnet_id, wallet)`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollChallenge {
    pub tailnet_id: u64,
    /// Operator circle the enrollment state is anchored in (`oct…`).
    pub circle: String,
    /// `2 * NONCE_LEN` lowercase-hex characters of random bytes.
    pub nonce: String,
    /// Operator wall-clock seconds when the nonce was minted.
    pub issued_at: u64,
    /// `issued_at + CHALLENGE_TTL_SECS`. The device must submit before
    /// this; the operator re-checks against its own clock.
    pub expires_at: u64,
}

/// Device → operator: a signed claim to join `tailnet_id`, binding the
/// device's WireGuard pubkey to its Octra wallet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub tailnet_id: u64,
    /// Operator circle, echoed from the challenge.
    pub circle: String,
    /// ed25519 wallet public key. The operator derives the `oct…`
    /// address from this — the device does **not** assert a wallet
    /// string independently (see [`EnrollRequest::wallet_address`]).
    pub wallet_pubkey: PublicKey,
    /// X25519 WireGuard public key the device will use in the tailnet.
    pub device_wg_pubkey: [u8; 32],
    /// Human label for the device (e.g. `"andrew-laptop"`). Informational
    /// only; not part of the signed payload.
    pub device_name: String,
    /// Echo of the issued challenge nonce (`2 * NONCE_LEN` hex chars).
    pub nonce: String,
    /// ed25519 signature over [`enroll_signing_payload`].
    pub wallet_sig: Signature,
}

impl EnrollRequest {
    /// The `oct…` wallet address derived from `wallet_pubkey`. This is the
    /// identity admitted to the member set — derived, never client-
    /// supplied — so a device cannot enroll under a wallet whose key it
    /// does not control.
    #[must_use]
    pub fn wallet_address(&self) -> String {
        Address::from_pubkey(&self.wallet_pubkey.0)
            .display()
            .to_string()
    }

    /// The deterministic bytes this request's signature must cover.
    #[must_use]
    pub fn signing_payload(&self) -> Vec<u8> {
        enroll_signing_payload(
            self.tailnet_id,
            &self.circle,
            &self.wallet_pubkey,
            &self.device_wg_pubkey,
            &self.nonce,
        )
    }

    /// Verify the wallet signature over this request's bound fields.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`crate::sig::verify`] error if the
    /// signature does not validate against `wallet_pubkey`. Note this
    /// proves key possession only — the caller still has to check the
    /// nonce freshness and the wallet's authorization to join.
    pub fn verify_signature(&self) -> CoreResult<()> {
        verify(
            &self.wallet_pubkey,
            &self.signing_payload(),
            &self.wallet_sig,
        )
    }
}

/// Operator → device: the result of a successful enrollment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub admitted: bool,
    /// The device's tailnet IP, deterministically derived from
    /// `(ip_salt, wallet)` (see [`crate::v3_members`]). Dotted-quad.
    pub assigned_ip: String,
    /// `circle_state_version` the post-enrollment `members.json` was
    /// anchored at — monotonic, lets the device detect later rotations.
    pub members_version: u64,
    /// Current peer set, so the device can bring up its mesh without a
    /// second round trip.
    pub peers: Vec<EnrollPeer>,
}

/// A tailnet peer the freshly-enrolled device can reach.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollPeer {
    pub wallet: String,
    pub wg_pubkey_b64: String,
    pub ip: String,
}

/// Deterministic bytes the wallet signs to authorize an enrollment.
///
/// Binds the wallet key to the device WG key, the target tailnet, the
/// operator circle, and the operator-issued nonce — so a captured request
/// cannot be replayed against another tailnet/circle, and a device cannot
/// swap in a different WG key after signing. Variable-length fields
/// (`circle`, `nonce`) are length-prefixed so no two distinct field
/// tuples can serialize to the same bytes.
#[must_use]
pub fn enroll_signing_payload(
    tailnet_id: u64,
    circle: &str,
    wallet_pubkey: &PublicKey,
    device_wg_pubkey: &[u8; 32],
    nonce: &str,
) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(SIGN_DOMAIN.len() + 8 + 4 + circle.len() + 32 + 32 + 4 + nonce.len());
    out.extend_from_slice(SIGN_DOMAIN);
    out.extend_from_slice(&tailnet_id.to_be_bytes());
    out.extend_from_slice(&(circle.len() as u32).to_be_bytes());
    out.extend_from_slice(circle.as_bytes());
    out.extend_from_slice(&wallet_pubkey.0);
    out.extend_from_slice(device_wg_pubkey);
    out.extend_from_slice(&(nonce.len() as u32).to_be_bytes());
    out.extend_from_slice(nonce.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sig::KeyPair;

    fn signed_request(kp: &KeyPair, tailnet_id: u64, circle: &str, nonce: &str) -> EnrollRequest {
        let device_wg_pubkey = [7u8; 32];
        let wallet_sig = kp.sign(&enroll_signing_payload(
            tailnet_id,
            circle,
            &kp.public,
            &device_wg_pubkey,
            nonce,
        ));
        EnrollRequest {
            tailnet_id,
            circle: circle.to_string(),
            wallet_pubkey: kp.public,
            device_wg_pubkey,
            device_name: "test-device".to_string(),
            nonce: nonce.to_string(),
            wallet_sig,
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = KeyPair::generate();
        let req = signed_request(&kp, 3, "octCircleAAA", "deadbeef");
        req.verify_signature().expect("valid signature verifies");
    }

    #[test]
    fn wallet_address_is_derived_from_pubkey_not_asserted() {
        let kp = KeyPair::generate();
        let req = signed_request(&kp, 3, "octCircleAAA", "deadbeef");
        // The admitted identity is exactly Address::from_pubkey — a device
        // cannot smuggle in a different wallet string.
        assert_eq!(
            req.wallet_address(),
            Address::from_pubkey(&kp.public.0).display()
        );
        assert!(req.wallet_address().starts_with("oct"));
    }

    #[test]
    fn tampered_wg_key_fails_verification() {
        let kp = KeyPair::generate();
        let mut req = signed_request(&kp, 3, "octCircleAAA", "deadbeef");
        // Swap the WG key after signing — the binding must break.
        req.device_wg_pubkey[0] ^= 1;
        assert!(req.verify_signature().is_err());
    }

    #[test]
    fn payload_binds_every_field() {
        let kp = KeyPair::generate();
        let base = enroll_signing_payload(3, "octC", &kp.public, &[7u8; 32], "n1");
        // Each field change must change the payload (no collisions).
        assert_ne!(
            base,
            enroll_signing_payload(4, "octC", &kp.public, &[7u8; 32], "n1")
        );
        assert_ne!(
            base,
            enroll_signing_payload(3, "octD", &kp.public, &[7u8; 32], "n1")
        );
        assert_ne!(
            base,
            enroll_signing_payload(3, "octC", &kp.public, &[8u8; 32], "n1")
        );
        assert_ne!(
            base,
            enroll_signing_payload(3, "octC", &kp.public, &[7u8; 32], "n2")
        );
        // Length-prefixing prevents the classic concat ambiguity:
        // ("oct","Cn1") must not collide with ("octC","n1").
        let a = enroll_signing_payload(3, "oct", &kp.public, &[7u8; 32], "Cn1");
        let b = enroll_signing_payload(3, "octC", &kp.public, &[7u8; 32], "n1");
        assert_ne!(a, b);
    }

    #[test]
    fn cross_tailnet_replay_is_rejected() {
        let kp = KeyPair::generate();
        // Sign for tailnet 3, then try to present it as tailnet 9.
        let mut req = signed_request(&kp, 3, "octCircleAAA", "deadbeef");
        req.tailnet_id = 9;
        assert!(req.verify_signature().is_err());
    }
}
