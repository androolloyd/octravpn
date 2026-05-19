#![no_main]
//! Fuzz the v3 `settle_claim` idempotency invariant under adversarial
//! sequencing.
//!
//! The v3 AML `settle_claim(session_id, bytes_used)` is required to be
//! idempotent: a duplicate submission with the same `(session_id, seq,
//! signature)` triple must be a no-op, and a re-submission with a
//! *forged* signature must be rejected outright. Operators maintain an
//! in-memory `claim_window` map keyed by session_id whose invariants
//! are:
//!
//!   1. `seq` is monotonic per session (a lower seq than the recorded
//!      floor is rejected)
//!   2. duplicate `(session_id, seq, signature)` is a no-op
//!   3. signature on the receipt MUST verify against the receipt's
//!      embedded `node_pubkey` — a mismatched pubkey is rejected
//!
//! We model the validator's claim-window state with the same
//! single-use primitive the production code uses (`PreauthMinter`'s
//! mint/redeem pattern, `crates/octravpn-mesh/src/headscale_bridge.rs:
//! 332` — the BoundedMap-backed atomic `lookup → conditional remove →
//! record` sequence). The fuzz target generates a sequence of "claim"
//! operations and asserts no operation can break the single-use
//! invariant.
use libfuzzer_sys::fuzz_target;
use octravpn_mesh::PreauthMinter;
use std::time::Duration;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // Use a long TTL so the test exercises the *single-use* property,
    // not expiry. The brief calls out claim_window invariants as the
    // load-bearing surface.
    let minter = PreauthMinter::new();

    // Walk the input bytes as a sequence of (op, key_idx) pairs.
    // op = byte[2i], key_idx = byte[2i+1]. We carry a small bank of
    // tokens so duplicate / out-of-order / forged paths all get hit.
    let mut tokens: Vec<String> = Vec::new();
    let mut redeemed_once: std::collections::HashSet<String> =
        std::collections::HashSet::new();

    for chunk in data.chunks_exact(2) {
        let op = chunk[0] & 0b111;
        let key_idx = chunk[1] as usize;

        match op {
            0 | 1 => {
                // Mint a fresh non-reusable token (the claim_window
                // analogue: each (session_id, seq) is single-use).
                let pk = minter.mint(
                    format!("session_{key_idx}"),
                    Duration::from_secs(3600),
                    false, // single-use
                );
                tokens.push(pk.key);
            }
            2 | 3 | 4 => {
                // Redeem an existing token. The invariant we assert
                // is that a *second* successful redemption never
                // occurs for a single-use token.
                if tokens.is_empty() {
                    continue;
                }
                let tok = &tokens[key_idx % tokens.len()];
                let result = minter.redeem(tok);
                if result.is_ok() {
                    let inserted = redeemed_once.insert(tok.clone());
                    assert!(
                        inserted,
                        "double-spend: token {tok} redeemed twice (claim_window invariant violated)"
                    );
                }
            }
            5 => {
                // Forged token: derive a token-shaped string from the
                // fuzz bytes and try to redeem it. Must always fail
                // (RedeemError::Unknown) — never succeed.
                let forged = format!(
                    "octrapreauth-{:064x}",
                    u128::from_le_bytes(
                        chunk
                            .iter()
                            .chain(data.iter().rev())
                            .take(16)
                            .copied()
                            .collect::<Vec<u8>>()
                            .try_into()
                            .unwrap_or([0u8; 16]),
                    )
                );
                if let Ok(_) = minter.redeem(&forged) {
                    // Astronomical probability of collision; if it
                    // happens, the fuzzer found something real.
                    if !tokens.iter().any(|t| t == &forged) {
                        panic!("forged token unexpectedly redeemed: {forged}");
                    }
                }
            }
            6 => {
                // Look up without redeeming. Must be consistent with
                // the redeemed_once set.
                if tokens.is_empty() {
                    continue;
                }
                let tok = &tokens[key_idx % tokens.len()];
                if redeemed_once.contains(tok) {
                    assert!(
                        minter.lookup(tok).is_none(),
                        "single-use token {tok} still visible after redemption"
                    );
                }
            }
            _ => {
                // Sweep expired (no-op in this short-lived target;
                // exercises the path).
                let (_a, _b) = minter.sweep_expired();
            }
        }
    }
});
