# OctraVPN — open questions for the Octra dev team

This document collects empirical observations and open questions accumulated
while building OctraVPN ("hidden-exit" private VPN payments) against Octra
devnet (`https://devnet.octrascan.io/rpc`). All findings are reproducible
against the scripts referenced in each section. We are sharing this as a
single inquiry rather than scattered Discord pings so the dev team has the
full picture.

## Context

- We are building an AML-based settlement contract (`program/main-v3.aml`,
  deployed 2026-05-18 at
  `oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3`) that uses Octra
  circles as off-chain-addressable, sealed-asset namespaces, and the main
  contract as the on-chain enforcer of bonds, slash, and session escrow.
- Architecture write-up:
  [`docs/v3-circle-resident-architecture.md`](v3-circle-resident-architecture.md).
- Empirical evidence for every question below is a smoke test
  ([`docker/devnet/v3-smoke.sh`](../docker/devnet/v3-smoke.sh)) and a
  40-case adversarial drill
  ([`docker/devnet/e2e-adversarial-v3.sh`](../docker/devnet/e2e-adversarial-v3.sh))
  driven against devnet.
- The questions below are the ones that gate the full hidden-exit ship —
  not every minor quirk we've hit.

Each section follows the same shape:

- **Observed** — what we ran and what we got back.
- **Question** — what we'd like clarified.
- **Impact on v3** — one sentence on what this blocks or enables.

We're not assuming any of these are bugs; several may be intentional.
Where the answer is "this is by design", we'd appreciate a confirmation
plus a docs update so we can stop re-deriving the behavior.

---

## 1. AML → HFHE host-call bridge

### Observed

Every `fhe_*` AML host call reverts on newly-deployed contracts on devnet.
To rule out an AML authoring mistake on our side, we cloned
`octra-labs/program-examples/private_ml` verbatim and deployed it at
`octHCQv6URtBXKjvAUo4AtDuDAgNjPhfazGiLPJXHwB3gDt`. Calling its
`private_predict(0, pk_addr, ct0, ct1)` view function reverts with the
generic `execution reverted` at the first `fhe_load_pk`.

Eight probe shapes were tested (view vs state-change × caller-self vs
explicit-address × `string`-typed arg vs `address`-typed arg). All revert
identically. The caller wallet
(`oct8Tdgu4RLbSGah1fVoVHW4T4cLFDmsoKhTyVD8gCndNFm`) has a 4.1 MB PVAC
pubkey registered via `octra_registerPvacPubkey` (verified by
`octra_pvacPubkey` returning it). Probe contract reproducer:
`octaUNQtHpsmGrd4m4pftsjhE7zYwK4fVEgsDTKQ4BsXDRB`.

### Question

When are `fhe_*` AML host calls expected to run against newly-deployed
contracts on devnet? Is there a chain-side opt-in flag, deployer
allowlist, or version gate we should be passing? Is
`program-examples/private_ml` known-working from a specific historical
deploy address that we could compare against?

### Impact on v3

Currently the v3 settle/claim path uses a sha256 hash-chain commitment in
place of HFHE-encrypted running totals. The storage shape is designed to
swap in HFHE additively the moment the bridge runs (see
`docs/v3-circle-resident-architecture.md` §5.2). Until then, per-session
plaintext blindings live in operator circles and chain observers see
running plaintext totals.

---

## 2. Circle code execution

### Observed

`deploy_circle` accepts and persists a `code_b64` field and the chain
computes a real (non-zero) `code_hash`. However `contract_call` against
the resulting circle address returns `"bytecode not found"`.

Reproducer (run 2026-05-18):

- Compiled a 12-line `counter.aml` with `bump()`/`get()`/`state.n`.
- Built a `deploy_circle` payload with `code_b64 = base64(OCTB bytecode)`.
- Deployed at `octHXaof7eyQEess39BR3nuRg5k6oVsoVMa192Vo8htPoHT`. Tx
  confirmed. `circle_info` returned a non-zero
  `code_hash = 39861519b80ae5…` and the deployer-matching `owner`.
- `contract_call(<circle>, "get", [])` → `{"code": -32000, "message":
  "bytecode not found"}`.
- `cast send <circle> bump` → `{"type": "contract_call_failed",
  "reason": "bytecode not found"}`.
- Sealed-asset operations on the same circle (`circle_asset_put_encrypted`
  / fetch by `resource_key`) continued to work normally.

### Question

Is `deploy_circle.code_b64` execution scheduled for a future devnet
update? The field is in the wire format, the chain accepts and hashes
the bytecode — only dispatch from `contract_call` seems unwired. If
there's a separate entrypoint we should be using to invoke circle code,
we'd appreciate a pointer.

### Impact on v3

Until circles execute their bytecode, bonds and slash logic must remain
in the main-contract AML rather than living in a per-operator
`BondEscrow` circle. v3 §6 sketches the swap path; the shrink to a pure
OU-routing main contract is gated on circle execution.

---

## 3. Map value storage cap (`string` / `bytes`)

### Observed

`map[address]string` (and the equivalent `map[address]bytes`) values are
silently truncated to 4096 bytes when stored. Reproducer
(2026-05-18) on program
`octHiTZruUMFiBkAjt6EGYojYKAcn1mpiSHbaZn8Tfah5ss`:

- Local PVAC `enc_zero_seeded` ciphertext (compressed `hfhe_v1|` +
  base64): **56,032 bytes** measured before submission.
- Stored on chain via `register_circle` and read back via
  `contract_call`: **4,096 bytes** — silent truncation, no revert.
- Downstream `fhe_deser(self.enc_earnings[circle])` over the truncated
  value reverts at the PVAC magic/version/tag checks.

Tx body sizes much larger than 4 KiB (e.g. ~56 KB hashed into a sha256
commit) flow through the RPC and execute fine. The cap appears to be on
the persisted map value specifically, not on the request body.

### Question

1. Is the 4 KiB cap on `map[K]string` / `map[K]bytes` values intentional?
2. If so, is there a different storage class (`blob`, chunked, or
   per-key-prefix sealed asset) with a higher cap that AML code can read
   at runtime?
3. Is there a planned higher-cap blob primitive on the roadmap?

### Impact on v3

Forces v3 to store only sha256 commitments (64-char hex) inline and keep
all real bytes (policy bundles, ciphertexts, member lists, attestation
records) in circle-resident sealed assets where the 32 MiB cap applies.
Workable today, but every cross-circle proof becomes a four-step
fetch-and-rehash for off-chain verifiers. A larger inline cap (even
64 KiB) would let us hold PVAC ciphertexts inline and remove a hop.

---

## 4. `bytes` type semantics at the RPC boundary

### Observed

The AML runtime does not decode `bytes`-typed params at the RPC
boundary. `len(bytes_arg)` returns the JSON-string character count
verbatim — no hex or base64 decoding step. Concretely (discovered while
authoring `program/main-v3.aml`):

- `register_circle(circle, state_root: bytes, ...)` with
  `require(len(state_root) == 32)` rejected real sha256 digests passed
  as either 44-char base64 or 64-char hex.
- Only a 32-char ASCII string passed the constraint.
- AML's own `sha256()` builtin returns a 64-character hex string.
- v3 settled on `require(len(state_root) == 64)` and stores anchors as
  64-char hex digests verbatim. The header comments of
  [`program/main-v3.aml`](../program/main-v3.aml) (lines 8–15) note this.

Additionally, unset `map[K]bytes` entries read back as the literal
one-character string `"0"` rather than the empty string. This breaks
naive hash-chain replay: the genesis `prev_head` is `"0"` unless the
contract explicitly initializes it. v3 works around this by seeding
`circle_earnings_chain[circle]` with `sha256(state_root)` at
`register_circle` time.

### Question

1. Is the no-decode-at-RPC-boundary behavior for `bytes` intentional? If
   so, is there a separate `bytes`-decoding mode we can opt into per
   param, or should we treat `bytes` as a sized string for all on-chain
   length checks?
2. Is the `"0"` default for unset `bytes` map entries intentional? It
   reads as a value the user never set, which makes it easy to write
   contracts that silently misbehave on the first access of a key.
3. Either way, a docs note on these two behaviors would save future
   contract authors the same forensic dive.

### Impact on v3

v3 ships today by treating every `bytes` field as a length-checked hex
string and explicitly seeding any map entry before its first read.
Confirmation either way would let us stop hedging and would let
upstream AML examples (which we mine for patterns) follow the same
convention.

---

## 5. `circle_id` derivation stability

### Observed

The v3 redeploy story
([`docs/v3-circle-resident-architecture.md`](v3-circle-resident-architecture.md)
§4) hinges on `circle_id` being derived from the registering wallet (and
its nonce / salt) and being independent of the main contract that
references it. Concretely: when our main-v3 contract is redeployed at a
new address `R'`, every operator's `circle_id` must remain the same so
they can re-anchor their existing sealed-asset state with a single
`register_circle` call on `R'`.

We have not observed any failure here — circles created by the same
deployer wallet keep the same address across our test deploys. We just
want to confirm this is a stable contract of the chain and not an
implementation detail that might change.

### Question

Please confirm that `circle_id` derivation is, and will remain,
independent of the main contract that calls `octra_*Circle` or that
references the circle in its state. If `circle_id` derivation ever
becomes a function of the calling contract address (CREATE-style rather
than CREATE2-style), the redeploy migration in §4 of our architecture
doc breaks and we'd want to know early.

### Impact on v3

Confirmation lets us guarantee operators that "if main-v3 redeploys, you
re-anchor in one tx and lose nothing in your circle." Without that
guarantee we'd need a separately-deployed registry contract to map old
→ new identities, which is more centralization than v3 is willing to
introduce.

---

## 6. Sealed-asset observability

### Observed

`circle_asset_put_encrypted` and the read-side
`circle_asset_ciphertext_by_resource_key` work as documented. What we
have not been able to find is a chain-side signal that a sealed-asset
write occurred — we don't see events in the receipt for the tx, and we
don't see them in the block events feed. Today the only way for an
off-chain validator to notice that an operator updated their
`state-root.json` is either (a) the matching on-chain `update_circle_state`
that the operator submits afterwards, or (b) periodic RPC polling of
the resource key.

### Question

1. Are sealed-asset writes observable on chain via events or in
   transaction receipts? If yes, what's the event name / shape and
   which RPC method returns it?
2. If not currently, is there a planned event for sealed-asset
   create/update/delete that off-chain indexers can subscribe to?

### Impact on v3

Off-chain auditors that watch operator behavior (e.g. detecting
`state-root.json` drift relative to the on-chain anchor) currently must
poll. A chain event would let them subscribe and react in the same
block. Not a blocker for v3's correctness — the anchor catches
mismatches at the next on-chain rotation — but it adds detection
latency.

---

## 7. Devnet RPC body cap

### Observed

Before 2026-05-18, `https://devnet.octrascan.io/rpc` rejected POST
bodies > ~1 MiB at the nginx edge with HTTP 413, before the chain saw
the request. This blocked PVAC pubkey registration on devnet (the
base64-encoded pubkey is ~4.1 MB) while mainnet
(`https://octra.network/rpc`) accepted the same body. After raising the
limit, `octra_registerPvacPubkey` now confirms on devnet — thank you.

### Question

1. What is the current production body cap on `octra.network/rpc`?
2. Is there a stable upper bound we should target for end-user tx
   construction, so we don't accidentally build payloads that work on
   devnet today but get rejected on mainnet?

### Impact on v3

v3 itself only submits small bodies (no inline ciphertexts). However the
pvac-sidecar will eventually need to register PVAC pubkeys against
mainnet for production hidden-exit, and the sealed-asset write path
will need to accept multi-MB ciphertext blobs. Knowing the production
ceiling lets us size our client-side chunking strategy correctly.

---

## Appendix A. Reproducers

Each empirical claim above maps to a script or test we've run against
devnet. All scripts are in the OctraVPN repo at the paths shown:

| Question | Script / file | What it demonstrates |
| --- | --- | --- |
| 1 (HFHE bridge) | private_ml clone at `octHCQv6URtBXKjvAUo4AtDuDAgNjPhfazGiLPJXHwB3gDt` | `private_predict` reverts at `fhe_load_pk` |
| 2 (Circle exec) | counter circle at `octHXaof7eyQEess39BR3nuRg5k6oVsoVMa192Vo8htPoHT` | `contract_call` → `"bytecode not found"` |
| 3 (4 KiB cap) | program `octHiTZruUMFiBkAjt6EGYojYKAcn1mpiSHbaZn8Tfah5ss`; 56 KB ciphertext stored, 4096 B read back | Silent truncation |
| 4 (`bytes` semantics) | `program/main-v3.aml` lines 8–15; smoke test `docker/devnet/v3-smoke.sh` | `len()` returns char count; unset `bytes` reads as `"0"` |
| 5 (`circle_id` stability) | `docker/devnet/v3-smoke.sh` step 1 (`register_circle` reuses an existing circle owned by the deployer) | Same wallet → same circle_id across our deploys |
| 6 (Sealed-asset events) | `docker/devnet/e2e-adversarial-v3.sh` (anchor-rotation cases) | No chain event observed on `circle_asset_put_encrypted` |
| 7 (RPC body cap) | `octra_registerPvacPubkey` PVAC pubkey ~4.1 MB — failed pre-2026-05-18, passes now | nginx 413 wall raised |

End-to-end v3 lifecycle (deploy → register_circle → create_tailnet →
open_session → settle_claim → settle_confirm → claim_earnings) is
covered by [`docker/devnet/v3-smoke.sh`](../docker/devnet/v3-smoke.sh).
The 40-case adversarial drill covering replay, double-spend, slash,
overclaim, dispute, and anchor-rotation paths is in
[`docker/devnet/e2e-adversarial-v3.sh`](../docker/devnet/e2e-adversarial-v3.sh).

---

## Appendix B. What we are NOT asking

For completeness, here are behaviors we've previously verified empirically
and are not asking about:

- `ed25519_ok` takes base64-encoded signatures (not hex) — confirmed,
  used in `slash_double_sign`.
- Pause halts user flows only; governance bypasses pause — confirmed,
  matches v1.1 semantics and is the behavior we want.
- `sha256()` is a string-in / hex-string-out builtin — confirmed and
  documented in the v3 header comments.
- Tx bodies up to multi-MB execute fine when the per-map-value 4 KiB
  cap is respected — confirmed.
- `register_circle` is payable and the initial bond is atomic with
  registration — confirmed in v3 smoke.

Happy to walk through any of the above in more depth if useful. We can
be reached at `dev@octravpn.io` or on Discord as the OctraVPN team.
