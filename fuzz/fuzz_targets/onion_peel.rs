#![no_main]
use libfuzzer_sys::fuzz_target;
use octravpn_core::onion::peel_layer;
use x25519_dalek::StaticSecret;

fuzz_target!(|data: &[u8]| {
    // Random bytes against a fixed-but-arbitrary X25519 secret. Must
    // either return Ok(...) (valid for the secret) or Err(...) — never
    // panic.
    let sk = StaticSecret::from([7u8; 32]);
    let _ = peel_layer(&sk, data);
});
