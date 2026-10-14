# Native PVAC from Rust

Loads the BSD-3-Clause PVAC implementation from the pinned lite_node. The
cryptographic headers and serialization remain upstream. A small C ABI bridge
owns exception handling; Rust owns handles and releases native buffers with the
native allocator. No OCaml runtime or sidecar is needed for these operations.

Current surface: seeded key generation/encryption, imports/exports, signed
decryption, addition/subtraction, profile-aware scale/constant addition, and
commitments. Proof verification and its isolated worker remain separate node
integration work. Handles are thread-confined; no unchecked `Send`/`Sync` impls.

```sh
cargo test --locked -p octra-pvac
cargo run --locked --release -p octra-pvac --features benchmark --example boundary_bench
```

The benchmark alternates nine Rust and C++ samples using the same cached
key/cipher, native operation, allocation and release. It measures the call
boundary, not serialization, key loading, proof verification or node throughput.
No production credentials are used or printed.

`vendor/octra-pvac/PROVENANCE.json` pins all adopted source hashes. This tree is
separate from the older GPL `pvac-sidecar`; that sidecar's license and IPC
boundary remain intact.
