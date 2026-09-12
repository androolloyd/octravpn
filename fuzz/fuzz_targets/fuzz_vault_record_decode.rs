#![no_main]
use libfuzzer_sys::fuzz_target;
use octravpn_core::receipt_vault::decode_record;

fuzz_target!(|data: &[u8]| {
    // OCRV2 record decode must be total for arbitrary bytes: short
    // prefixes are torn tails, oversized lengths are rejected before
    // JSON decode, and malformed payloads return errors rather than
    // panicking.
    let _ = decode_record(data);
});
