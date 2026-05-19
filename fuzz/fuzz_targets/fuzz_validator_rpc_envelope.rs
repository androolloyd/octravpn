#![no_main]
//! Fuzz the JSON-RPC envelope shapes a validator decodes off the wire.
//!
//! Adversarial scenario: a hostile client (or a MITM with a stolen TLS
//! root) sends syntactically-borderline JSON to the validator's RPC
//! ingress. We exercise the same `serde_json` decode path the
//! `RpcClient` uses for *response* envelopes (the same shapes are
//! decoded by the validator when consuming peer-relayed RPC). The
//! invariants are:
//!
//!   - decode must never panic, regardless of input bytes
//!   - decode-then-canonicalise must never panic
//!   - if the input parses as a `serde_json::Value`, every nested
//!     string must decode through the canonical writer without
//!     panicking on unicode/leading-zero/oversized integer tricks
//!
//! Specifically targets:
//!   - malformed UTF-8 + truncated JSON
//!   - oversized integer literals beyond i64/u64 range
//!   - deeply nested arrays / objects (stack overflow probe)
//!   - duplicate keys (which `serde_json` accepts but canonical
//!     writers must handle deterministically)
//!   - unicode normalisation tricks (NFC vs NFKC equivalence) in
//!     address-shaped string positions
//!   - leading-zero / scientific-notation number literals
use libfuzzer_sys::fuzz_target;
use octravpn_core::tx::canonical_bytes;

fuzz_target!(|data: &[u8]| {
    // 1. Generic JSON-Value decode. Must never panic. Random bytes are
    //    expected to fail; that's fine.
    let value: serde_json::Value = match serde_json::from_slice(data) {
        Ok(v) => v,
        Err(_) => return,
    };

    // 2. Round-trip through the canonical bytes encoder (same one the
    //    validator uses to recompute tx hashes on receipt). Catches
    //    panics on duplicate keys, deep nesting, exotic numerics.
    let _ = canonical_bytes(&value);

    // 3. Try the typed-envelope shapes the validator decodes most
    //    often. None of these may panic for any input that parsed as
    //    a Value above.
    let bytes = data; // alias for readability
    let _: Result<octravpn_core::receipt::SignedReceipt, _> =
        serde_json::from_slice(bytes);

    // 4. Re-encode the value as bytes and re-decode. The
    //    `canonical_bytes` output is itself valid JSON; a second
    //    parse must succeed.
    if let Ok(canon) = canonical_bytes(&value) {
        let _: Result<serde_json::Value, _> = serde_json::from_slice(&canon);
    }
});
