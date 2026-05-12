//! Property tests: the on-chain program's `concat_receipt_v1` and the
//! Rust client's `canonical_payload` must produce identical bytes for
//! the same inputs.
//!
//! The on-chain side hashes `tag || sid || seq || bytes_used || blind`.

use octravpn_core::{
    receipt::canonical_payload,
    session::{Blind, SessionId},
};
use proptest::prelude::*;
use sha2::{Digest, Sha256};

fn ref_payload(sid: &[u8; 32], seq: u64, bytes_used: u64, blind: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"octravpn-receipt-v1");
    h.update(sid);
    h.update(seq.to_be_bytes());
    h.update(bytes_used.to_be_bytes());
    h.update(blind);
    h.finalize().into()
}

proptest! {
    #[test]
    fn matches_reference(
        sid in any::<[u8; 32]>(),
        seq in any::<u64>(),
        bytes_used in any::<u64>(),
        blind in any::<[u8; 32]>(),
    ) {
        let ours =
            canonical_payload(&SessionId::new(sid), seq, bytes_used, &Blind::new(blind)).unwrap();
        let theirs = ref_payload(&sid, seq, bytes_used, &blind);
        prop_assert_eq!(ours, theirs);
    }
}
