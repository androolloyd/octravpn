# OctraVPN v2 — release notes

> Status: **circle-keyed substrate live on devnet, end-to-end on chain
> through `open_session`, HFHE settlement gated on the devnet RPC body
> cap.** v2 runs alongside v1.1 (`program/main.aml`) — the two programs
> share no on-chain state and are selected per-deploy by the node and
> client `protocol_version` config flag. v1.1 remains the
> production-shippable thing; v2 is the new substrate.

Counterpart to [`docs/v1.1-release-notes.md`](v1.1-release-notes.md).

## Deployments

| Program | Address (devnet) | Source |
|---|---|---|
| Slim registry | `oct3fxjrzfqh65ATo31eau8xRFBPiXh2Uzwue56EYkfVSj7` | `program/main-v2.aml` |
| Operator circle (canonical sample) | `octE5x8WvhXB1FStpDmmfxkMmFKdnx5cL1Fr4gnry6aUdqA` | `program/operator-circle.aml` |

Canonical end-to-end on devnet (the first ever v2 session open against
a registered, sealed-policy-published operator circle):

- `register_circle` (atomic register + 1 OCT bond):
  `54d84c02d5a61bfade3122c1abd918f142cd54ace95b2c251aaf11cf49dbc74b`
- `circle_asset_put_encrypted` (sealed `/policy.json`, 4k AES-GCM):
  `5811465946323b04de530924825b87ad6c95953dce55b9bbb2416cf2aa1bc494`
- `open_session(class=0 shared, max_pay=200)`:
  `434ad40cf475dd4f509550daee36362655375d43c40d064b3e8c65aeae8ff7ae`

## What shipped, commit by commit

### v2 substrate — circles, sealed assets, slim registry

- **`162ee3d` v2: octra-circle-sim crate.** Rust simulator for an
  OctraVPN Circle. Lets the test harness drive `circle_*` RPCs without
  a real devnet.
- **`613cc94` v1.1 slash_double_sign + v2 main-v2.aml compiles +
  circle-sim RpcChain + v2 e2e.** First v2 AML that survived
  `octra_compileAml` against mainnet. Carries the v1.1
  cryptographic slash unchanged.
- **`d1d7eec` tx: real Octra wire envelope.** `octraforge create`
  produces a real `octra_submit` envelope and lands deploys on
  devnet for real. Unblocks every subsequent on-chain step.
- **`95bbcac` devnet e2e + harness wiring.** Live deploy of v1.1 on
  devnet, multi-step settlement, attack drill. The harness this added
  (`docker/devnet/e2e-*.sh`) is what carries the v2 work to
  completion.
- **`4f1fc3c` v1.1 hardening: 49-case adversarial drill, formal-verify
  uplift, pause-guard fix.** Pause-on-governance was reverted (see
  `d7aaa65`).
- **`d7aaa65` revert pause-gate on withdraw + set_params.** Governance
  bypasses pause; a compromised owner can `set_paused(0)` first anyway.
- **`6c3ce5a` v2: circle-native main + operator-circle programs (live
  on devnet).** First on-chain v2 deploy. `main-v2.aml` carries 28
  entrypoints; `register_circle` is `payable` (atomic register + bond)
  — surfaced by the chicken-and-egg the live e2e hit
  (`bond_endpoint requires owner` ↔ `register_circle requires bond`).
  Per-class price stamped at open time so live sessions are immune to
  mid-session price updates.
- **`beae338` v2 adversarial drill — 45 cases, all held.**
  `docker/devnet/e2e-adversarial-v2.sh` covers F-class (governance),
  S-class (slashing, re-slash idempotence), R-class (replay), E-class
  (escrow accounting), etc.
- **`a533f2c` docs/v2-circles-design: add §0 status snapshot.** §0 is
  the canonical "what shipped" reference; the rest of the doc is
  preserved as the original design.

### Client + node wiring

- **`029ff0e` client: v2 circle discovery + connect-v2.** Adds
  `octravpn discover v2 <tid>` and `octravpn connect-v2`
  (`crates/octravpn-client/src/discover_v2.rs`). Reads
  `authorized_circles[tid]`, fetches sealed `/policy.json` by
  `resource_key(circle_id, "/policy.json")`, decrypts with the shared
  tailnet passphrase, then `open_session`s with `class` +
  `max_pay`.
- **`5edd9b9` node: v2 circle deploy + sealed-asset upload +
  register_circle.** `octravpn-node` automates the v2 boot sequence
  (`chain_v2.rs`): predict `circle_id` → `circle_info` →
  `deploy_circle` if absent → `circle_asset_put_encrypted` →
  atomic `register_circle` with `MIN_CIRCLE_STAKE`.

### HFHE / PVAC

- **`6c9d15b` v2: route fhe_load_pk through circle.owner.** Octra's
  PVAC pubkey registry is per-wallet; circles are contracts with no
  keypair, so `fhe_load_pk(circle)` always fails. v2 routes through
  `circles[c].owner` (`main-v2.aml:790, :858`), unblocking
  `settle_confirm` and `claim_earnings`.
- **`9e16868` pvac-sidecar: GPL-isolated daemon — past the AES KAT
  wall on chain.** `pvac-sidecar/` (C++, GPL-2+ with OpenSSL
  exemption) vendors the upstream `octra-labs/webcli` PVAC sources
  and exposes them over JSON-over-stdio. The MIT/Apache Rust crates
  shell out to the binary; no GPL symbols cross the IPC boundary.
  Produces chain-compatible PVAC pubkey / ciphertext / zero-proof
  blobs that pass the AES KAT gate the on-chain `fhe_*` opcodes
  enforce.

### Formal verification — Lean, TLA+, proptest

- **`db6ad7d` proofs/v2: Lean+TLA port to circle-keyed registry.**
  - **Lean 4** v2 module (`proofs/lean/OctraVPN_V2/`) — 50+ new
    theorems covering atomic `register_circle`, per-class price
    stamping, slash carries-over, sealed-asset put/fetch, and member
    ACL acceptance. Combined v1.1 + v2 totals: **95 theorems / 0
    `sorry`**, clean `lake build`.
  - **TLA+** v2 spec (`proofs/tla/OctraVPN_V2.tla`) — 17 invariants
    including `Inv_CircleAtomicRegisterBond`,
    `Inv_AuthorizedCircleIsActive`, and
    `Inv_StampedPriceImmutableInOpenSession`. TLC last-run:
    **52,676,571 states / 3,805,681 distinct / depth 31 / 0
    violations** in ~39s. v1.1 spec carried over unchanged.
  - **Rust proptest** — 30 harnesses across `octravpn-core` +
    `octravpn-mesh` (canonicalization, monotonic seq, receipt
    context binding, sweep determinism, etc.).

### Threat-model audit + fixes

- **`374ba49` docs: v2 threat model + operator key hygiene.** New
  `docs/v2-threat-model.md` lays out 8 attack trees + 18-item
  prioritized fix queue + dependency risk register. New
  `docs/v2-operator-key-hygiene.md` codifies the fresh-wallet
  rule (`from=deployer → to_=circle_id` permanently binds the
  wallet to the circle on chain).
- **`b9aedf7` operator-circle: fix P0-3 meter_bytes auth.** Dropped a
  dead branch in `program/operator-circle.aml:229` that called
  `ed25519_ok(resource_key, ...)` (a hash arg, not a pubkey) — the
  branch always rejected, collapsing the auth to caller-only. Now
  the doc claim matches the code.
- **`f4f5e65` node: events_token gate on /events + sign_call log fix
  + leak audit.** Internal infra hardening; closed the unauthenticated
  `/events` channel.
- **`2d933fc` P0-2 cert pinning + P1-10 zeroize sealed passphrase.**
  - P0-2: pin `devnet.octrascan.io` leaf cert in
    `reqwest::Client::builder()` across `octravpn-core::rpc`,
    `octravpn-client::runner`, and `octra-cli::rpc_client`. Closes
    the corporate-MITM-CA exfil path.
  - P1-10: wrap the v2 `sealed_passphrase` config field with
    `secrecy::SecretString` / `zeroize::Zeroizing` so a core dump or
    page-fault swap doesn't leak it.
- **`f5b5a07` / `060903d` P1-5: bind program_addr + chain_id +
  circle_id into receipts.** Receipt v1.2 signing payload now folds
  in `(program_addr, chain_id, circle_id)` via a `ReceiptContext`
  field on `Receipt`. Cross-program, cross-chain, and cross-circle
  replay all fail signature verification. v1.1 receipts canonically
  encode `circle_id = None` as 32 zero bytes so the hash domain is
  fixed-width across both programs. New tests:
  `cross_program_receipt_rejection`, `cross_chain_receipt_rejection`,
  `cross_circle_receipt_rejection`; property-based variants in
  `tests/prop_receipt.rs`; chain-side reference parity in
  `tests/prop_canonicalization.rs`.
- **`8db1ad1` / `dfc016e` P1-6 sealed keys + P1-8/P1-9 receipt
  journal.**
  - P1-6: `octravpn-node seal-keys` / `unseal-keys` wrap wallet +
    WG keys under `OCTRA-WALLET-V1` (ChaCha20-Poly1305 +
    PBKDF2-SHA256-120k). Strict mode
    (`[chain].require_sealed_keys = true`) refuses to boot if any
    configured secret is still plaintext, surfacing
    `CoreError::PlaintextKeyOnDisk` with the `seal-keys` CLI quoted in
    the error. Passphrase: `OCTRAVPN_KEY_PASSPHRASE`.
  - P1-8 / P1-9: `crates/octravpn-core/src/receipt_journal.rs`
    persists `(session_id → last_signed_seq)` to `./state/receipts.bin`,
    fsync'd before any `Receipt` is signed. Daemon restarts reload
    the floor; `ControlSession.last_seq` is shadowed by
    `max(in_mem, journal_floor)` so an OOM / segfault / signal
    between two receipts can no longer trick the daemon into signing
    two distinct receipts at the same `(session_id, seq)`.

### Repo hygiene

- **`d6b3930` gitignore .claude/worktrees + drop embedded-repo refs.**
  Worktree directories no longer pollute `git status`.

## Threat-model fix queue — status

From `docs/v2-threat-model.md §3`:

| ID | Severity | Status |
|---|---|---|
| P0-1 (TLS on operator control plane) | P0 | open |
| **P0-2** (cert-pin OctraRPC) | P0 | **FIXED** (`2d933fc`) |
| **P0-3** (operator-circle `meter_bytes` auth) | P0 | **FIXED** (`b9aedf7`) |
| P1-2 (onion AEAD nonce hardening) | P1 | open |
| P1-3 (operator key hygiene doc) | P1 | done (`374ba49`) |
| P1-4 (passphrase entropy floor) | P1 | open |
| **P1-5** (receipt context binding) | P1 | **FIXED** (`f5b5a07` / `060903d`) |
| **P1-6** (sealed key envelope + strict mode) | P1 | **FIXED** (`8db1ad1` / `dfc016e`) |
| P1-7 (periodic WG static rotation) | P1 | open |
| **P1-8** (persistent receipt journal) | P1 | **FIXED** (`8db1ad1`) |
| **P1-9** (atomic last_seq bump) | P1 | **FIXED** (`8db1ad1`, joint with P1-8) |
| **P1-10** (zeroize sealed passphrase) | P1 | **FIXED** (`2d933fc`) |
| P2-11 → P3-18 | P2 / P3 | tracked |

## Backward compatibility

- v1.1 and v2 are **separate deployments**. The on-chain registry
  shape differs (`address`-keyed vs `circle_id`-keyed); there is no
  in-place migration inside one program instance.
- Operators may run both. The daemon selects per-tailnet by
  `protocol_version` config.
- A tailnet is single-version. Tailnets created against the v1.1
  program stay on v1.1.
- v1.1 receipts continue to verify (`circle_id_canonical = 32 zero
  bytes` keeps the v1.2 hash domain fixed-width across both).

## Test artifacts

- `program/main-v2.aml` — 890 lines, 28 entrypoints, compile-gated.
- `program/operator-circle.aml` — 289 lines, compile-gated.
- `docker/devnet/e2e-adversarial-v2.sh` — 45 cases, all hold.
- `proofs/lean/OctraVPN_V2/` + `proofs/tla/OctraVPN_V2.tla`.
- `crates/octra-circle-sim/tests/v2_e2e.rs` — in-process v2 e2e.
- `crates/octravpn-core/tests/prop_*.rs` — 30 proptest harnesses.
- `pvac-sidecar/` — GPL-isolated; past mainnet AES KAT.

## What's blocked

End-to-end HFHE settlement on devnet is blocked behind the devnet
RPC nginx `client_max_body_size` rejecting POSTs above 1 MiB. PVAC
pubkey registration is a ~4 MB tx, so `octra cast register-pvac`
returns 413 on devnet. Mainnet accepts. Filed upstream;
`pvac-sidecar/` is otherwise ready and the v2 program correctly
routes `fhe_load_pk(circles[c].owner)`.

## Runbooks

- Operator: [`docs/v2-operator-flow.md`](v2-operator-flow.md).
- Client: [`docs/v2-client-flow.md`](v2-client-flow.md).
- Key hygiene: [`docs/v2-operator-key-hygiene.md`](v2-operator-key-hygiene.md).
- Threat model: [`docs/v2-threat-model.md`](v2-threat-model.md).
- Architecture: [`docs/architecture.md`](architecture.md).
