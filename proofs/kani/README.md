# Kani harnesses

Bounded model checks for the Rust crypto/parsing surface.

## Harnesses

- **payload_deterministic** — `Receipt::signing_payload` is deterministic.
- **round_trip_signed_receipt** — sign-then-verify never panics and always
  succeeds for any 32-byte session id and 64-bit seq.
- **monotonic_iff_strictly_greater** — `check_monotonic(prev)` accepts iff
  the new seq is strictly greater than `prev`.

## Running

```
cargo install kani-verifier
cargo kani setup
cd proofs/kani
cargo kani
```

These harnesses are intentionally small so they verify in seconds. The
proptest suite (`cargo test -p octravpn-core --tests prop`) covers the
same properties at unbounded sizes for runtime confidence.
