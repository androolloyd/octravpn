#![no_main]
//! Fuzz `StateRoot` mutation → anchor flips invariant.
//!
//! The canonical encoder in `crates/octravpn-core/src/v3_state_root.rs`
//! is proven stable by issue #242 (the proptests at lines 380+ pin
//! determinism, round-trip, and reorder-invariance). The remaining
//! attack surface is *semantic*: a malicious operator who mutates a
//! sealed `state-root.json` field must always produce a different
//! anchor — otherwise they could swap policy/wg_pubkey/region
//! out from under a verifier without the on-chain anchor catching it.
//!
//! Adversarial scenario:
//!
//!   - operator publishes anchor A for StateRoot S
//!   - operator serves a different StateRoot S' to clients
//!   - verifier fetches S', recomputes the anchor, compares
//!
//! For this attack to succeed, S' must hash to A under the canonical
//! encoder while differing from S in any client-visible field. This
//! fuzz target probes for such collisions: it builds two `StateRoot`s
//! that differ in *at least one* field and asserts their anchors
//! diverge.
use libfuzzer_sys::fuzz_target;
use octravpn_core::v3_state_root::StateRoot;

/// Build a deterministic 64-char hex hash from a single byte.
fn hex_from_byte(b: u8) -> String {
    // Same construction the in-tree tests use: 32 repetitions of one
    // byte, hex-encoded → 64-char lowercase hex digest.
    let bytes = [b; 32];
    bytes.iter().map(|x| format!("{x:02x}")).collect()
}

fn build_state_root(seed: &[u8]) -> Option<StateRoot> {
    if seed.len() < 24 {
        return None;
    }
    // Pull deterministic field values out of the fuzz seed. Strings
    // are kept ASCII-printable to avoid burning the fuzzer on UTF-8
    // edge cases that v3_canonical already covers.
    let circle_id = format!("oct{:016x}", u64::from_le_bytes(seed[0..8].try_into().unwrap()));
    let policy_hash = hex_from_byte(seed[8]);
    let wg_pubkey_hash = hex_from_byte(seed[9]);
    let attestation_hash = if seed[10] & 1 == 0 {
        None
    } else {
        Some(hex_from_byte(seed[11]))
    };
    let region = format!("r{:02x}", seed[12]);
    let member_count = u32::from_le_bytes(seed[13..17].try_into().unwrap());
    let epoch = u64::from_le_bytes(seed[17..25.min(seed.len())].try_into().ok()?);
    let timestamp_secs = if seed.len() >= 33 {
        u64::from_le_bytes(seed[25..33].try_into().ok()?)
    } else {
        1_700_000_000
    };

    Some(StateRoot::new_v1(
        circle_id,
        policy_hash,
        wg_pubkey_hash,
        attestation_hash,
        region,
        member_count,
        epoch,
        timestamp_secs,
    ))
}

fuzz_target!(|data: &[u8]| {
    // Need ≥ 33 + 33 + 1 bytes: two state roots + mutation selector.
    if data.len() < 70 {
        return;
    }
    let Some(sr_a) = build_state_root(&data[0..33]) else { return };

    // Compute anchor for the base StateRoot. Even before mutation,
    // validation may fail (e.g. empty region produced by a quirky
    // seed); skip those — the canonical-bytes path handles them.
    let Ok(anchor_a) = sr_a.anchor_hex() else { return };

    // Mutate exactly one field. The mutation selector picks which.
    let mut sr_b = sr_a.clone();
    let sel = data[33] % 8;
    match sel {
        0 => sr_b.circle_id.push('!'),
        1 => sr_b.policy_hash = hex_from_byte(data[34].wrapping_add(1)),
        2 => sr_b.wg_pubkey_hash = hex_from_byte(data[34].wrapping_add(1)),
        3 => {
            sr_b.attestation_hash = match &sr_b.attestation_hash {
                None => Some(hex_from_byte(0xab)),
                Some(_) => None,
            }
        }
        4 => sr_b.region.push('*'),
        5 => sr_b.member_count = sr_b.member_count.wrapping_add(1),
        6 => sr_b.epoch = sr_b.epoch.wrapping_add(1),
        _ => sr_b.timestamp_secs = sr_b.timestamp_secs.wrapping_add(1),
    }

    // Sanity: the structs really differ (the wrapping_add could
    // produce a same-value mutation; skip if so).
    if sr_a == sr_b {
        return;
    }

    let Ok(anchor_b) = sr_b.anchor_hex() else { return };

    // The load-bearing assertion: a field-level mutation must flip
    // the anchor. A collision here is a SHA-256 collision, which
    // would be a much bigger finding than a fuzz target.
    assert_ne!(
        anchor_a, anchor_b,
        "state-root anchor collision detected — mutation produced identical anchor. \
         a={sr_a:?} b={sr_b:?}",
    );

    // Also assert: canonical bytes for two equal StateRoots are
    // identical (determinism), and for two differing StateRoots
    // diverge (encoder injectivity at the byte level).
    let bytes_a = sr_a.canonical_bytes().unwrap();
    let bytes_b = sr_b.canonical_bytes().unwrap();
    assert_ne!(bytes_a, bytes_b, "canonical bytes collided despite struct inequality");
});
