#![no_main]
use libfuzzer_sys::fuzz_target;
use octravpn_core::tx::canonical_bytes;

fuzz_target!(|data: &[u8]| {
    // Treat input as JSON; canonicalize; must not panic for any value
    // serde_json accepts.
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = canonical_bytes(&v);
    }
});
