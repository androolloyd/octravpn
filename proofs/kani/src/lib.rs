//! Bounded verification of production session codecs and relay epoch guards.
//! Cryptographic unforgeability is an assumption, not a Kani proof here.
#[cfg(kani)]
use octravpn_core::{relay_window::{claim_window_open, recovery_window_open}, session::SessionId};

#[cfg(kani)]
#[kani::proof]
#[kani::unwind(33)]
fn session_u64_round_trip() {
    let id: u64 = kani::any();
    assert_eq!(SessionId::from_u64(id).as_u64(), Some(id));
}

#[cfg(kani)]
#[kani::proof]
#[kani::unwind(33)]
fn session_nonzero_padding_rejected() {
    let bytes: [u8; 32] = kani::any();
    let has_padding = bytes[8..].iter().any(|b| *b != 0);
    assert_eq!(SessionId::new(bytes).as_u64().is_none(), has_padding);
}

#[cfg(kani)]
#[kani::proof]
fn claim_never_at_or_after_deadline() {
    let now: u64 = kani::any();
    let deadline: u64 = kani::any();
    let margin: u64 = kani::any();
    if claim_window_open(now, deadline, margin) { assert!(now < deadline); }
}

#[cfg(kani)]
#[kani::proof]
fn recovery_never_at_or_before_deadline() {
    let now: u64 = kani::any();
    let deadline: u64 = kani::any();
    let grace: u64 = kani::any();
    let margin: u64 = kani::any();
    if recovery_window_open(now, deadline, grace, margin) { assert!(now > deadline); }
}

#[cfg(kani)]
#[kani::proof]
fn claim_and_recovery_windows_disjoint() {
    let now: u64 = kani::any();
    let deadline: u64 = kani::any();
    let claim_margin: u64 = kani::any();
    let refund_margin: u64 = kani::any();
    let grace: u64 = kani::any();
    assert!(!(claim_window_open(now, deadline, claim_margin)
        && recovery_window_open(now, deadline, grace, refund_margin)));
}

pub fn build_marker() -> &'static str { "octravpn-kani" }
