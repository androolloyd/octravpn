//! Property tests for dual-signed receipt sign/verify.

use octravpn_core::{
    receipt::{Receipt, SignedReceipt},
    session::{Blind, SessionId},
    sig::KeyPair,
};
use proptest::prelude::*;

proptest! {
    /// Build-then-verify round-trips for any well-formed receipt.
    #[test]
    fn build_verify_round_trip(
        session in any::<[u8; 32]>(),
        seq in any::<u64>(),
        bytes_used in any::<u64>(),
        blind in any::<[u8; 32]>(),
        client_secret in any::<[u8; 32]>(),
        node_secret in any::<[u8; 32]>(),
    ) {
        let client = KeyPair::from_secret_bytes(&client_secret);
        let node = KeyPair::from_secret_bytes(&node_secret);
        let r = Receipt {
            session_id: SessionId::new(session),
            seq,
            bytes_used,
            blind: Blind::new(blind),
        };
        let signed = SignedReceipt::build(r, &client, &node);
        prop_assert!(signed.verify().is_ok());
    }

    /// Tampering with bytes_used invalidates both sigs.
    #[test]
    fn tampered_bytes_breaks_verify(
        session in any::<[u8; 32]>(),
        seq in any::<u64>(),
        bytes_used in any::<u64>(),
        blind in any::<[u8; 32]>(),
        client_secret in any::<[u8; 32]>(),
        node_secret in any::<[u8; 32]>(),
        delta in 1u64..1_000_000,
    ) {
        let client = KeyPair::from_secret_bytes(&client_secret);
        let node = KeyPair::from_secret_bytes(&node_secret);
        let r = Receipt {
            session_id: SessionId::new(session),
            seq,
            bytes_used,
            blind: Blind::new(blind),
        };
        let mut signed = SignedReceipt::build(r, &client, &node);
        signed.receipt.bytes_used = signed.receipt.bytes_used.wrapping_add(delta);
        prop_assert!(signed.verify().is_err());
    }

    /// Monotonic check: accept iff strictly greater than prev.
    #[test]
    fn monotonic(prev in any::<u64>(), seq in any::<u64>(), session in any::<[u8; 32]>()) {
        let r = Receipt {
            session_id: SessionId::new(session),
            seq,
            bytes_used: 0,
            blind: Blind::new([0u8; 32]),
        };
        let signed = SignedReceipt::build(r, &KeyPair::generate(), &KeyPair::generate());
        let ok = signed.check_monotonic(prev).is_ok();
        prop_assert_eq!(ok, seq > prev);
    }
}
