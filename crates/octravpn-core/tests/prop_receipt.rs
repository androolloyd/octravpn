//! Property tests for dual-signed receipt sign/verify.

use octravpn_core::{
    address::Address,
    receipt::{Receipt, ReceiptContext, SignedReceipt, CHAIN_ID_TEST},
    session::{Blind, SessionId},
    sig::KeyPair,
};
use proptest::prelude::*;

fn fixture_ctx() -> ReceiptContext {
    // Stable v1.1 fixture used by every property below. Tests that need
    // to demonstrate cross-context behaviour build their own contexts
    // (see the v1.2 binder tests in `receipt::tests`).
    let prog = Address::from_pubkey(&[0xABu8; 32]);
    ReceiptContext::v1_1(prog, CHAIN_ID_TEST)
}

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
            context: fixture_ctx(),
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
            context: fixture_ctx(),
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
            context: fixture_ctx(),
            session_id: SessionId::new(session),
            seq,
            bytes_used: 0,
            blind: Blind::new([0u8; 32]),
        };
        let signed = SignedReceipt::build(r, &KeyPair::generate(), &KeyPair::generate());
        let ok = signed.check_monotonic(prev).is_ok();
        prop_assert_eq!(ok, seq > prev);
    }

    /// v1.2 domain binder: tampering with the program_addr (without
    /// re-signing) invalidates both sigs. Generalises the targeted
    /// cross-program test in `receipt::tests::cross_program_receipt_rejection`
    /// to arbitrary program-byte mutations.
    #[test]
    fn tampered_program_breaks_verify(
        session in any::<[u8; 32]>(),
        seq in any::<u64>(),
        bytes_used in any::<u64>(),
        blind in any::<[u8; 32]>(),
        prog_a in any::<[u8; 32]>(),
        prog_b in any::<[u8; 32]>(),
        client_secret in any::<[u8; 32]>(),
        node_secret in any::<[u8; 32]>(),
    ) {
        prop_assume!(prog_a != prog_b);
        let client = KeyPair::from_secret_bytes(&client_secret);
        let node = KeyPair::from_secret_bytes(&node_secret);
        let ctx_a = ReceiptContext::v1_1(Address::from_pubkey(&prog_a), CHAIN_ID_TEST);
        let ctx_b = ReceiptContext::v1_1(Address::from_pubkey(&prog_b), CHAIN_ID_TEST);
        let r = Receipt {
            context: ctx_a,
            session_id: SessionId::new(session),
            seq,
            bytes_used,
            blind: Blind::new(blind),
        };
        let mut signed = SignedReceipt::build(r, &client, &node);
        signed.receipt.context = ctx_b;
        prop_assert!(signed.verify().is_err());
    }

    /// v1.2 domain binder: tampering with chain_id invalidates both sigs.
    #[test]
    fn tampered_chain_id_breaks_verify(
        session in any::<[u8; 32]>(),
        seq in any::<u64>(),
        bytes_used in any::<u64>(),
        blind in any::<[u8; 32]>(),
        chain_a in any::<u32>(),
        chain_b in any::<u32>(),
        client_secret in any::<[u8; 32]>(),
        node_secret in any::<[u8; 32]>(),
    ) {
        prop_assume!(chain_a != chain_b);
        let client = KeyPair::from_secret_bytes(&client_secret);
        let node = KeyPair::from_secret_bytes(&node_secret);
        let prog = Address::from_pubkey(&[0xAB; 32]);
        let ctx_a = ReceiptContext::v1_1(prog.clone(), chain_a);
        let ctx_b = ReceiptContext::v1_1(prog, chain_b);
        let r = Receipt {
            context: ctx_a,
            session_id: SessionId::new(session),
            seq,
            bytes_used,
            blind: Blind::new(blind),
        };
        let mut signed = SignedReceipt::build(r, &client, &node);
        signed.receipt.context = ctx_b;
        prop_assert!(signed.verify().is_err());
    }
}
