//! Property tests for Pedersen-style commitments.

use octravpn_core::{
    address::Address,
    commit::{commit, fresh_blind, verify_open, Opening},
};
use proptest::prelude::*;

fn make_addr(seed: &[u8; 16]) -> Address {
    let mut s = String::from("oct");
    s.push_str(&hex::encode(seed));
    Address::from_display(s)
}

proptest! {
    /// Hiding: two fresh blinds for the same address yield different
    /// commitments with overwhelming probability (statistically).
    #[test]
    fn hiding(addr_seed in any::<[u8; 16]>()) {
        let addr = make_addr(&addr_seed);
        let c1 = commit(&addr, &fresh_blind());
        let c2 = commit(&addr, &fresh_blind());
        prop_assert_ne!(c1, c2);
    }

    /// Binding: opening must match address and blind exactly.
    #[test]
    fn binding(
        addr_seed in any::<[u8; 16]>(),
        wrong_seed in any::<[u8; 16]>(),
        blind in any::<[u8; 32]>(),
    ) {
        prop_assume!(addr_seed != wrong_seed);
        let addr = make_addr(&addr_seed);
        let wrong = make_addr(&wrong_seed);
        let c = commit(&addr, &blind);
        let ok_match = verify_open(&c, &Opening { addr: addr.clone(), blind });
        let ok_mismatch = verify_open(&c, &Opening { addr: wrong, blind });
        prop_assert!(ok_match);
        prop_assert!(!ok_mismatch);
    }
}
