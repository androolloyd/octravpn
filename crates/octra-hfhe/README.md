# Pure Rust HFHE

The backend target is pure Rust after exact compatibility qualification.
Native PVAC remains the reference oracle; this crate is not yet a full backend.

Current ports:

- Mersenne field 2^127−1: canonical words/bytes, signed extraction, arithmetic,
  exponentiation and inverse. All 1,629 native differential cases match.
- Native AES-256 counter stream, bounded draws, seeded field/nonce generation,
  and PRF-key transcript: all 140 native cases match, including counter wrap.
- Seeded v5 key generation with both v6/v7 circuit commitments: 41 valid
  vectors and 12 parameter refusals match. Small vectors include every byte;
  one standard full-size public key matches length and SHA-256 over every raw
  and compressed byte. Secret-key bytes match in every valid vector.
- Public/secret v1–v5 imports and canonical v5 exports: all 848 native cases
  match, including 703 malformed-input refusals and legacy default fields.
- SHA matrix draw order and effort limits: all 44 cases match. Adaptive range
  compression: 14 encoding and 104 decoding/refusal cases match.
- Retained LPN PRF: all 18 vectors match complete output words and PRF fields,
  including standard LPN dimensions. Low-127-bit binary convolution matches
  native scalar and hardware implementations in all 130 cases.
- Active v6/v7 circuit masks, LPN-v2 noise, full Toeplitz windows and layer
  transcripts: 260 vectors match. Direct signed Pedersen commitments match
  2,178 field/sign/scalar-boundary and deterministic random vectors.
- Ciphertext v1–v5 imports and canonical v3 exports: 2,219 vectors match.
  Linear arithmetic, compaction, commitments and UBK permutation match 530
  vectors; seeded products and squares match 234 vectors under both math modes.
- Seeded encryption matches 54 complete ciphertext/refusal vectors, including
  full-size parameters and four encryption/arithmetic/UBK/decryption pipelines.
  Another 76 ciphertext cases check active, retained and native-local decryption
  policies, including refusal order.
- Noise planning: 326 floating-point boundary cases compare the current native
  target. The fixture contains ARM and translated x86 macOS outputs; 27 budgets
  differ between those native targets. Rust preserves each observed build's
  contraction behavior. Other hosts generate their own native fixture in CI.

Scalar, transcript, generator, inner-product and R1CS proof ports add 3,263
inputs: complete proofs, identical entropy consumption, scalar helpers and
refusals. Another 3,664 verifier outcomes compare acceptance and post-call
transcripts. There are 12,120 native fixture inputs in total. Resource-overflow diagnostics
are separate: uncapped legacy slots must return allocation errors without
panicking. The backend must classify these as operational unavailability.
The observed floating-point differences use nonstandard parameter boundaries;
they do not establish a reachable public-chain consensus bug. Network profile
admission and cross-platform execution remain qualification requirements.

Run `cargo test --locked -p octra-hfhe`. Fixture generators in
`scripts/node-port/hfhe-*-fixtures.py` use the real pinned C++ implementation.
The embedded budget evidence is macOS-specific. Other hosts must first generate
their own evidence from a pristine checkout of the adopted pin, using a fresh
output path:

```sh
python3 scripts/node-port/hfhe-budget-fixtures.py --mode native \
  --upstream /path/to/lite_node --out out/hfhe-budget-host.json
OCTRA_HFHE_BUDGET_FIXTURE="$PWD/out/hfhe-budget-host.json" \
  cargo test --locked -p octra-hfhe
```

The inherited workspace policy denies unsafe Rust in this crate.
Fixture seeds are public deterministic test material. Owned secret keys,
secret exports and AES schedules wipe on drop; exported buffers reserve their
complete size before writing secrets. Derived AES keys borrow secret inputs and
use protected output buffers. SHA-256/SHAKE state and compiler-generated copies
still need a full secret-lifetime and side-channel review.
Key-generation parameters are trusted local configuration. The full backend's
profile, input-size and worker resource policy is still an integration gate.

Switch-over still requires complete recryption and proofs; matching
verification acceptance/refusal and resource policy; every
retained execution profile; and native worker/node integration. Randomized
operations need the same entropy tape for a byte-for-byte comparison.
Primitive tests do not establish complete HFHE parity or side-channel safety.
