# octra-pvac-sidecar

A tiny JSON-over-stdio daemon that produces **chain-compatible** PVAC
(HFHE) pubkey, ciphertext and zero-proof blobs for Octra's v2 substrate.

The PVAC reference implementation lives in
[`octra-labs/webcli`](https://github.com/octra-labs/webcli) under
`pvac/` and is licensed **GPL-2+ (with OpenSSL exemption)**. Linking
that code into our MIT/Apache-licensed Rust workspace would
contaminate the workspace's license, so instead we vendor the same
sources here and ship them as a **separate process** with its own
license. The Rust side communicates with this binary over a JSON IPC
boundary; no GPL symbols cross into the Rust crates.

See [`LICENSE`](./LICENSE) (verbatim GPL from webcli) and
[`LICENSE.NOTICE.md`](./LICENSE.NOTICE.md) for the boundary statement.

## Why a separate binary

PVAC's pubkey, ciphertext, range-proof and zero-proof formats are
implementation-defined (`pvac_serialize.hpp` — `"PVAC"` magic + version
+ tag + body). The on-chain `fhe_*` opcodes in `program/main-v2.aml`
deserialize these blobs via the same code path. Anything **not**
produced by webcli's vendored fork (including the 2024 PoC
`pvac_hfhe_cpp`) is rejected at the chain-side magic/AES-KAT check.

So we have three options for producing chain-compatible blobs:

1. Re-implement PVAC in clean Rust — months of work, formal-verification
   gap, ongoing maintenance burden.
2. Link the C++ fork into our Rust crates via `cc` / `bindgen` — fast,
   but the resulting Rust binaries inherit the GPL.
3. **Run PVAC as a sidecar** and talk to it over JSON IPC — this repo.

This is option 3.

## Layout

```
pvac-sidecar/
├── LICENSE                  # GPL-2+ (verbatim from webcli/COPYING)
├── LICENSE.NOTICE.md        # IPC-boundary statement
├── README.md
├── Dockerfile               # builds octra-pvac-sidecar in isolation
├── Makefile
├── src/main.cpp             # JSON-over-stdio loop
└── vendor/
    ├── lib/
    │   ├── b64.hpp          # base64 (extracted from webcli/crypto_utils)
    │   └── json.hpp         # nlohmann/json (MIT) — small enough to vendor
    └── pvac/
        ├── pvac_c_api.{h,cpp}
        ├── pvac_serialize.hpp
        └── include/pvac/    # the full PVAC fork (header-only, header dir)
            ├── core/
            ├── crypto/
            ├── ops/
            └── utils/
```

The sidecar deliberately does **not** depend on OpenSSL or LevelDB,
unlike the parent `webcli` build. PVAC's own headers are self-contained
(SIMD intrinsics plus libstdc++); the only extra files we vendor are
base64 + nlohmann/json.

## Build

The Dockerfile produces a single binary at `/usr/local/bin/octra-pvac-sidecar`:

```bash
cd pvac-sidecar
docker build -t octra-pvac-sidecar .
```

You can also build natively if you have a C++17 toolchain:

```bash
make
```

## Invoke

The sidecar speaks **JSON-over-stdin/stdout**, one request per line,
one response per line. Run it interactively to smoke-test:

```bash
docker run -i --rm octra-pvac-sidecar
```

### Ops

#### `keygen`

```json
> {"op":"keygen","seed":"0101...32 bytes hex..."}
< {"pk":"hfhe_v1|<base64>","sk":"hfhe_v1|<base64>"}
```

Deterministic keygen from a 32-byte seed. The caller should derive the
seed however it wants (e.g. HKDF over the wallet ed25519 secret). The
secret key is returned to the caller for use in subsequent `encrypt_*`
or `make_zero_proof` calls — the sidecar itself is stateless.

#### `encrypt_zero`

```json
> {"op":"encrypt_zero","pk":"hfhe_v1|...","sk":"hfhe_v1|...","seed":"<32 hex>"}
< {"ct":"hfhe_v1|<base64>"}
```

Encrypts the value `0` under the supplied pubkey. The chain uses
`op_zero_ct` as the starting point for the encrypted-earnings ledger.

#### `encrypt_const`

```json
> {"op":"encrypt_const","pk":"hfhe_v1|...","sk":"hfhe_v1|...",
   "value":"1000000000","seed":"<32 hex>"}
< {"ct":"hfhe_v1|<base64>"}
```

Encrypts a u64 constant (passed as decimal string to avoid JavaScript's
53-bit number limit on the calling side).

#### `make_zero_proof`

```json
> {"op":"make_zero_proof","pk":"hfhe_v1|...","sk":"hfhe_v1|...",
   "ct":"hfhe_v1|...","amount":"1000000000",
   "blinding":"<base64 32 bytes>"}
< {"proof":"zkzp_v2|<base64>"}
```

Produces a zero-proof bound to an `(amount, blinding)` Pedersen
commitment. The chain's `claim_earnings` opcode requires this proof
to verify that the residual ciphertext after a claim is in fact a
fresh encryption of zero.

#### `add`

```json
> {"op":"add","pk":"hfhe_v1|...","a":"hfhe_v1|...","b":"hfhe_v1|..."}
< {"ct":"hfhe_v1|..."}
```

Homomorphic addition. Used for off-chain verification / mock harness;
the on-chain `fhe_add` is performed by the AML runtime itself.

#### `ping` / `version`

```json
> {"op":"ping"}
< {"pong":true}

> {"op":"version"}
< {"sidecar":"octra-pvac-sidecar/0.1"}
```

### Errors

Any failure returns a single field:

```json
{"error":"short description"}
```

The sidecar never logs secret material on stdout. Setting
`PVAC_SIDECAR_DEBUG=1` enables one-line **opaque** trace messages on
stderr (op name + output length, never key/cipher contents).

## Integration

The OctraVPN Rust workspace spawns this binary as a long-lived child
process and pipes JSON requests through stdin/stdout. The plumbing
lives in `crates/octravpn-node/.../pvac_sidecar.rs` (forthcoming);
the wire format is intentionally simple so a similar wrapper can be
written for the cast CLI, or for the operator-side test harness.

## What it does NOT do

- It does **not** decrypt other people's ciphertexts. Even though the
  C API exposes `pvac_dec_value`, this sidecar does not expose a
  `decrypt` op — the operator's secret key never leaves the operator's
  process (it's passed into the sidecar only for the duration of the
  call, and only for ops that the protocol genuinely requires the SK
  for).
- It does **not** generate range proofs or aggregated range proofs.
  The current chain code at `program/main-v2.aml` only verifies zero
  proofs against the encrypted-earnings ledger; range proofs become
  necessary when we add encrypted balances. Adding `make_range_proof`
  is a one-day change to `src/main.cpp` when needed.
- It does **not** ship a key/secret persistence layer. The caller is
  responsible for storing the operator's PVAC secret key alongside
  the wallet keypair, in the same encrypted vault.
