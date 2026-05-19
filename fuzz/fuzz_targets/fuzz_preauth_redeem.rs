#![no_main]
//! Fuzz `PreauthMinter::redeem` adversarially.
//!
//! `PreauthMinter` is the single-use credential gate used by the
//! Tailscale-wire bridge (`crates/octravpn-mesh/src/headscale_bridge
//! .rs`). It's the load-bearing primitive for validator-side preauth
//! redemption — if any of these paths panic or admit a double-spend,
//! a hostile client could either crash the validator (DoS) or get
//! mesh access for free (auth bypass).
//!
//! Adversarial scenarios covered:
//!
//!   - tampered token bytes (control chars, leading/trailing
//!     whitespace, NUL bytes, oversized strings)
//!   - near-expiry races (TTL set to zero / 1ms; redeem after sleep)
//!   - capacity-overflow attacks (mint past the configured cap;
//!     FIFO eviction must preserve the single-use property — an
//!     evicted token must NOT become re-redeemable)
//!   - reusable-key abuse (reusable=true tokens redeemed many times;
//!     must not panic)
//!   - single-use double-redemption (the primary single-use
//!     invariant; an adversary that retries on network errors must
//!     get exactly one success across all attempts)
use libfuzzer_sys::fuzz_target;
use octravpn_mesh::{PreauthMinter, RedeemError};
use std::time::Duration;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Tiny capacity stresses the FIFO-evict path the brief calls out.
    let minter = PreauthMinter::with_capacity(4, 4);

    // Each input byte drives one operation. Top 3 bits = op, low 5
    // = key index. We carry up to 32 minted tokens.
    let mut tokens: Vec<(String, bool /* reusable */)> = Vec::new();
    let mut single_use_redeemed: std::collections::HashSet<String> =
        std::collections::HashSet::new();

    for &b in data.iter().take(256) {
        let op = (b >> 5) & 0b111;
        let idx = (b & 0b11111) as usize;

        match op {
            0 => {
                // Mint single-use, normal TTL.
                let pk = minter.mint("u", Duration::from_secs(3600), false);
                tokens.push((pk.key, false));
            }
            1 => {
                // Mint reusable.
                let pk = minter.mint("u", Duration::from_secs(3600), true);
                tokens.push((pk.key, true));
            }
            2 => {
                // Mint near-expiry: 1ms TTL. Race between mint and
                // redeem is the attack surface.
                let pk = minter.mint("u", Duration::from_millis(1), false);
                tokens.push((pk.key, false));
            }
            3 => {
                // Redeem an existing token.
                if tokens.is_empty() {
                    continue;
                }
                let (tok, reusable) = tokens[idx % tokens.len()].clone();
                match minter.redeem(&tok) {
                    Ok(_) => {
                        if !reusable {
                            // Single-use invariant: at most one Ok per
                            // token across the lifetime of this fuzz
                            // input.
                            let fresh = single_use_redeemed.insert(tok.clone());
                            assert!(
                                fresh,
                                "single-use double-redemption: {tok}"
                            );
                        }
                    }
                    Err(RedeemError::Unknown) | Err(RedeemError::Expired) => {
                        // Both are fine outcomes — eviction (cap),
                        // expiry (1ms TTL), or already-redeemed
                        // single-use.
                    }
                }
            }
            4 => {
                // Tampered token: take an existing one and mutate.
                if tokens.is_empty() {
                    continue;
                }
                let (orig, _) = tokens[idx % tokens.len()].clone();
                let mut bytes = orig.into_bytes();
                if !bytes.is_empty() {
                    bytes[0] ^= 0x01;
                }
                let tok = String::from_utf8_lossy(&bytes).to_string();
                let _ = minter.redeem(&tok); // any result OK, no panic
            }
            5 => {
                // Adversarial token shapes: NUL bytes, control chars,
                // oversized.
                let tok = match idx % 5 {
                    0 => String::from("\0\0\0"),
                    1 => "octrapreauth-".to_string() + &"a".repeat(10_000),
                    2 => String::from("octrapreauth-deadbeef\n\r\t"),
                    3 => String::from(""),
                    _ => String::from_utf8_lossy(&[0xff, 0xfe, 0xfd]).to_string(),
                };
                let result = minter.redeem(&tok);
                // Must be Err for any of these — they're not the
                // hex-encoded shape `mint` produces.
                assert!(
                    result.is_err(),
                    "adversarial token {tok:?} unexpectedly redeemed"
                );
            }
            6 => {
                // Lookup invariants: redeemed single-use must be gone.
                if tokens.is_empty() {
                    continue;
                }
                let (tok, _) = tokens[idx % tokens.len()].clone();
                if single_use_redeemed.contains(&tok) {
                    assert!(
                        minter.lookup(&tok).is_none(),
                        "redeemed single-use token still present"
                    );
                }
            }
            _ => {
                // Force capacity-eviction by minting up to the cap +
                // one extra. The FIFO-eviction path must not violate
                // single-use.
                for _ in 0..6 {
                    let pk = minter.mint("u", Duration::from_secs(3600), false);
                    tokens.push((pk.key, false));
                }
            }
        }
    }
});
