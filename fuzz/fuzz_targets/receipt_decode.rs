#![no_main]
use libfuzzer_sys::fuzz_target;
use octravpn_core::receipt::SignedReceipt;

fuzz_target!(|data: &[u8]| {
    // Decode arbitrary bytes as a SignedReceipt; must never panic.
    let _ = serde_json::from_slice::<SignedReceipt>(data);
});
