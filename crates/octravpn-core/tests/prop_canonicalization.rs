//! Property tests: the on-chain program's `concat_receipt_v1` and the
//! Rust client's `canonical_payload` must produce identical bytes for
//! the same inputs.
//!
//! The on-chain side hashes
//! `tag || program_addr || chain_id_be || circle_id_canonical
//!     || sid || seq || bytes_used || blind`.
//!
//! v1.2 added the `(program_addr, chain_id, circle_id)` domain binders
//! per `docs/v2-threat-model.md` P1-5; the reference hasher below
//! mirrors that exactly so any future drift between the Rust and
//! on-chain sides is caught by a property failure.

use octravpn_core::{
    address::{Address, ADDRESS_LEN},
    receipt::{canonical_payload, ReceiptContext},
    session::{Blind, SessionId},
};
use proptest::prelude::*;
use sha2::{Digest, Sha256};

fn ref_payload(
    program_addr_bytes: &[u8; ADDRESS_LEN],
    chain_id: u32,
    circle_id_bytes: &[u8; ADDRESS_LEN],
    sid: &[u8; 32],
    seq: u64,
    bytes_used: u64,
    blind: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"octravpn-receipt-v1");
    h.update(program_addr_bytes);
    h.update(chain_id.to_be_bytes());
    h.update(circle_id_bytes);
    h.update(sid);
    h.update(seq.to_be_bytes());
    h.update(bytes_used.to_be_bytes());
    h.update(blind);
    h.finalize().into()
}

proptest! {
    /// v1.1-style receipt (circle_id = None) canonical_payload equals
    /// the reference hash with the all-zero canonical encoding for
    /// circle_id.
    #[test]
    fn matches_reference_v1_1(
        program_pubkey in any::<[u8; 32]>(),
        chain_id in any::<u32>(),
        sid in any::<[u8; 32]>(),
        seq in any::<u64>(),
        bytes_used in any::<u64>(),
        blind in any::<[u8; 32]>(),
    ) {
        let program_addr = Address::from_pubkey(&program_pubkey);
        let ctx = ReceiptContext::v1_1(program_addr.clone(), chain_id);
        let ours = canonical_payload(
            &ctx,
            &SessionId::new(sid),
            seq,
            bytes_used,
            &Blind::new(blind),
        )
        .unwrap();
        let theirs = ref_payload(
            program_addr.as_bytes(),
            chain_id,
            &[0u8; ADDRESS_LEN],
            &sid,
            seq,
            bytes_used,
            &blind,
        );
        prop_assert_eq!(ours, theirs);
    }

    /// v2 receipt (Some(circle)) canonical_payload equals the reference
    /// hash with circle_id.as_bytes() spliced into the domain.
    #[test]
    fn matches_reference_v2(
        program_pubkey in any::<[u8; 32]>(),
        circle_pubkey in any::<[u8; 32]>(),
        chain_id in any::<u32>(),
        sid in any::<[u8; 32]>(),
        seq in any::<u64>(),
        bytes_used in any::<u64>(),
        blind in any::<[u8; 32]>(),
    ) {
        let program_addr = Address::from_pubkey(&program_pubkey);
        let circle_addr = Address::from_pubkey(&circle_pubkey);
        let ctx = ReceiptContext::v2(program_addr.clone(), chain_id, circle_addr.clone());
        let ours = canonical_payload(
            &ctx,
            &SessionId::new(sid),
            seq,
            bytes_used,
            &Blind::new(blind),
        )
        .unwrap();
        let theirs = ref_payload(
            program_addr.as_bytes(),
            chain_id,
            circle_addr.as_bytes(),
            &sid,
            seq,
            bytes_used,
            &blind,
        );
        prop_assert_eq!(ours, theirs);
    }
}
