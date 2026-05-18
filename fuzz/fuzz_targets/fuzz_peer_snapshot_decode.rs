#![no_main]
use libfuzzer_sys::fuzz_target;
use octravpn_mesh::SignedPeerSnapshot;

fuzz_target!(|data: &[u8]| {
    // Decode arbitrary bytes as a SignedPeerSnapshot (serde_json wire
    // form). Must never panic; Err is the expected outcome for
    // random input.
    let _ = serde_json::from_slice::<SignedPeerSnapshot>(data);
});
