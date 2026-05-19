#![no_main]
//! Fuzz the validator-health oracle's response-decoding path.
//!
//! Adversarial scenario: a hostile RPC endpoint (or compromised relay)
//! returns malformed `octra_listValidators` payloads. The
//! `ValidatorOracle` at `crates/octravpn-core/src/validator_oracle.rs`
//! decodes those responses into its in-memory bulk-cache set; any
//! panic here would let an adversary kill validator processes by
//! poisoning a single bulk-listing response.
//!
//! What we fuzz:
//!
//!   - The `serde_json::Value` shape the oracle's `refresh_bulk` path
//!     pulls out: an array of strings. We feed arbitrary bytes,
//!     attempt to decode, and ensure the membership-check path stays
//!     well-defined.
//!   - Mixed-type arrays (numbers + strings + nulls + nested arrays)
//!     — the production code does
//!     `arr.iter().filter_map(|x| x.as_str().map(String::from))`,
//!     which must drop non-strings rather than panic.
//!   - Wildly-out-of-band timestamps and freeform metadata blobs that
//!     might be folded into the per-validator record in future
//!     schemas (forward-compat: unknown keys must not panic the
//!     decoder).
//!
//! The slash-decision logic referenced in the threat brief lives on
//! chain (`slash_double_sign` in `program/main-v3.aml`), not in this
//! oracle — the oracle's role is purely set-membership lookup. This
//! target catches the off-chain panic surface; chain-side bounded-FP
//! analysis happens in `program/tests/` proofs.
use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use std::collections::HashSet;

fuzz_target!(|data: &[u8]| {
    // 1. Decode as a generic Value. Random bytes will mostly fail; the
    //    branches we care about are the borderline-valid ones.
    let v: Value = match serde_json::from_slice(data) {
        Ok(v) => v,
        Err(_) => return,
    };

    // 2. Mirror exactly what `ValidatorOracle::refresh_bulk` does:
    //    treat the top-level as an array, filter_map string entries,
    //    collect into a HashSet. The production code at
    //    crates/octravpn-core/src/validator_oracle.rs:154-160 must
    //    not panic on any of these shapes.
    if let Some(arr) = v.as_array() {
        let set: HashSet<String> = arr
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect();

        // 3. Membership-check invariant: every address in the set is
        //    well-defined UTF-8 (already true by construction from
        //    `as_str`), and the lookup function is total.
        for s in &set {
            let _ = set.contains(s);
            // Decode-shaped string must be safe to use as map key.
            assert!(!s.contains('\0'), "validator addr contains NUL: {s:?}");
        }

        // 4. Edge case the brief calls out: "wildly out-of-band
        //    timestamps". If the array contains numeric entries, they
        //    should be safely ignored by the as_str filter.
        for item in arr {
            // Must not panic on any type — covers number, null, bool,
            // nested array/object.
            let _ = item.as_str();
            let _ = item.as_i64();
            let _ = item.as_f64();
            let _ = item.as_bool();
            let _ = item.as_array();
            let _ = item.as_object();
        }
    }

    // 5. Some oracle deployments will eventually consume per-validator
    //    records (object shape). Pre-flight that path: any object
    //    must walk without panicking.
    if let Some(obj) = v.as_object() {
        for (k, val) in obj {
            assert!(!k.contains('\0'), "validator key contains NUL");
            let _ = val.as_str();
            let _ = val.as_array();
        }
    }
});
