# Questions for Octra dev team — OctraVPN v2 on Circles

> Compiled from `docs/v2-circles-design.md` §9. Send this verbatim (or close to it) to the dev team via the Discord development channel or `dev@octra.org`. Answers gated the v2 implementation work in tasks #141–#143.

## Status (2026-05-17)

The Octra dev team announced on **2026-05-14** that the AML compiler exposes:

- `ed25519_ok(pk, msg, sig) -> bool`
- `digest_sha256`, `digest_keccak256`
- `current_tx_hash`
- native `bool` type

Reference deployment: `octBDvZSiTqdEBAyFSp79CHeoLMR9MzHugX9YkHtuQ57MRB` (its AML is readable via `vm_contract` / `contract_source`).

This resolves the public-AML slice of the original §9. The cryptographic equivocation slash is now in `program/main.aml::slash_double_sign` and is compile-gated against mainnet. Earnings-claim / receipt-hashing primitives are confirmed.

On **2026-05-15** Octra published the **Circles** primitive end-to-end via `octra-labs/webcli` commit `f9c73e1` (clear deploy + sealed-asset wire format) and the AML modifiers (`payable`, `nonreentrant`) used in `octra-labs/program-examples`. This resolves five of the six original §9 questions (1–3, 5, 6 below) and partially resolves §9.4 (HFHE inside circles). A new operational ask has surfaced (§7, devnet RPC body cap). The questions below preserve the history and add the new ask.

We're building **OctraVPN**, a decentralized Tailscale-compatible mesh on Octra. v1 ships against current main-net primitives (AML + HFHE ledger + stealth payments + cryptographic equivocation slash, now that `ed25519_ok` is confirmed). For v2 you mentioned that Circles let us hide operators while still offering clear-internet egress — *"you can build a VPN on this."* We took that as a hint and designed a v2 architecture where each operator is a Circle, the slim registry on main-net is the public face, and the per-circle program gates membership / class / pricing.

Before we author any Circle-shaped code we needed to ground six things. Numbered for easy reply, with resolution status.

## 1. Circle SDK + DSL — current state of the art ~~[OPEN]~~ [RESOLVED 2026-05-15 via `octra-labs/webcli` `f9c73e1`]

The litepaper (§2.3, §4.2) says Circles run logic in Rust, C++, OCaml, or WASM. None of the public `octra-labs` repos shipped a Circle example until **2026-05-15**.

- ~~Is there an internal SDK we should request access to?~~
- ~~Which target (Rust? OCaml? WASM?) is the recommended path for new dApps?~~
- ~~Is the Circle bytecode (OCTB) the same format as smart-contract bytecode, or distinct?~~

**Resolution.** The public release exposes Circles as **AML programs deployed via a `deploy_circle` op-type**, *not* a separate DSL. Wire format (reverse-engineered from `octra-labs/webcli/static/circles.html`):

- `op_type = "deploy_circle"`
- `to_ = <predicted circle_id>` (CREATE2-style — see below)
- `message = canonical_json({ runtime, privacy_class, browser_mode, resource_mode, limits, code_b64, policy_hash, members_root, export_policy })`

Deterministic `circle_id`: `"oct" + base58(sha256(seed))[:44]` where `seed = h256("octra:circle_deploy_id:v1", [deployer_addr, u64be(nonce), payload_hash_hex])`. The id is computable BEFORE submitting the deploy tx, enabling main-net programs to assert ownership at registration without trusting deployer-disclosed metadata.

We mirror the reference impl in `octra-foundry/crates/octra-core/src/circle.rs`. Our `octra cast circle predict|deploy|info|asset|put-encrypted|...` subcommands are byte-identical to the webcli JS.

### How we discovered this

Watched the public **2026-05-15** webcli ship `circles.html`, diff'd it against the older commit, ported the JS to Rust. Verified by deploying a real circle on devnet (`octE5x8WvhXB1FStpDmmfxkMmFKdnx5cL1Fr4gnry6aUdqA`) and round-tripping a sealed `/policy.json` asset.

## 2. Proxy contract grammar ~~[OPEN]~~ [REFRAMED 2026-05-15 — no separate proxy contract needed]

§4.4.2 described the proxy contract as deployed with "a pre-allocated resource address for the backend" and as the bridge between Circle and main-net via "interaction actors."

- ~~Is the proxy authored in AML (with special pragmas), or its own DSL?~~
- ~~How is the *allowlist of predefined callers* declared?~~
- ~~Can the proxy receive callbacks from main-net AML programs, and how is that callback declared/dispatched?~~

**Resolution.** Real circles don't need a separate proxy contract. `circle_id` is structurally an address (47-char `oct…`); the chain treats it like any other addressable thing. Our slim registry (`program/main-v2.aml`) stores `circle: address` in its records and bonds OU keyed by circle_id; the operator's own program inside the circle (`program/operator-circle.aml`) is the "proxy" surface.

The "allowlist" is just normal AML — `members: map[address]int` inside the operator's circle program, gated by `require(self.members[caller] == 1, ...)`. Callbacks from main-net to circle are normal contract-to-contract calls under the existing AML model.

### How we discovered this

Got `register_circle` working as a `payable` entrypoint in `program/main-v2.aml`; the `circle_id` (computed via §1's deterministic derivation) flowed through as a plain `address`-typed argument. Compiled, deployed, registered + bonded in one atomic tx. No separate proxy DSL appeared anywhere in the public surface.

## 3. Access contract grammar ~~[OPEN]~~ [REFRAMED 2026-05-15 — no separate access contract DSL]

§4.2 said "access is defined during Circle deployment through an access contract, which includes the necessary functions for interface exchange."

- ~~Same question as 2: AML-with-pragmas or separate DSL?~~
- ~~Is the function table declared inline or in a separate manifest? Are there hooks for tag-based routing?~~

**Resolution.** Access control lives in normal AML. The operator-circle program at `program/operator-circle.aml` uses `caller == self.owner` for owner ops, `ed25519_ok(pk, canonical_msg, sig)` for member-signed acceptances. Tag-based routing is a plain `map[address]int` field (class tags). There is no separate access-contract DSL.

### How we discovered this

Wrote `operator-circle.aml` using the same primitives `program/main.aml` already uses — `caller`, `origin`, `require`, `ed25519_ok` — and `octra_compileAml` accepted it without complaint. The `payable` + `nonreentrant` modifiers (visible in `octra-labs/program-examples` after **2026-05-15**) are the only new things needed.

## 4. Circle-internal HFHE primitive availability ~~[OPEN]~~ [PARTIALLY RESOLVED 2026-05-17]

We currently use `fhe_add`, `fhe_sub`, `fhe_add_const`, `fhe_scale`, `fhe_verify_zero` inside `program/main.aml` (the public v1 AML). For v2, the natural place to compute `total_paid = bytes_used * price_per_mb` is in the circle (so byte counts stay encrypted), but the resulting amount has to escape to main-net for OU transfer.

- ~~Are the HFHE primitives available inside the Circle's logic, or only at the proxy boundary?~~
- What's the supported path for **decrypting a Circle-internal ciphertext into a main-net cleartext value** at settle time? Is `fhe_verify_zero` the right pattern, or is there a richer transcipher primitive?

**Resolution (partial).** The chain-side HFHE ops (`fhe_load_pk`, `fhe_deser`, `fhe_add_const`, `fhe_verify_zero`, etc.) are available in **any AML program**, circles included. We have not yet exercised them inside an operator circle — that's gated on the new finding below.

**CRITICAL new finding.** `fhe_load_pk(addr)` requires `addr` to have a **per-wallet PVAC pubkey** registered via the off-chain RPC `octra_registerPvacPubkey`. Circles have no keypair (they're addresses derived from a deploy seed, not signing accounts), so contracts deployed inside circles must route HFHE lookups through `circle.owner` (the wallet that submitted the deploy_circle tx) rather than `self_addr`. Our `program/main-v2.aml` does this; documented in saved memory `octra_hfhe_pubkey_per_wallet.md`.

The transcipher / decryption-into-cleartext path remains open: today we use the v1 pattern (`fhe_verify_zero` on `fhe_sub(ct, fhe_encrypt(claimed))`) which forces operators to claim the plaintext, after which they wrap in a native `op_type="stealth"` tx for unlinkable payout. **Ask remains open**: is there a primitive that lets the circle attest a plaintext amount to main-net without round-tripping through the operator wallet?

### How we discovered the pubkey-per-wallet constraint

Tried calling `fhe_load_pk(self_addr)` inside `program/main-v2.aml`. AML compiled fine, but at runtime the call returned "pubkey not registered." Cross-referenced with `octra-labs/pvac_hfhe_cpp` and found that `octra_registerPvacPubkey` takes `address + ed25519-signed registration` — so a contract address (no keypair) can never register one. The only workaround is to thread `circle.owner` through every HFHE call site.

## 5. Bond escrow at proxy deployment ~~[OPEN]~~ [REFRAMED 2026-05-17 — slim-registry-held bond]

- ~~Does proxy deployment support attaching a bond, escrowed by main-net?~~
- ~~If not yet, is there a recommended pattern?~~

**Resolution.** The slim registry (`program/main-v2.aml`) holds bonds in main-v2 storage (`circle_stake: map[address]int`). Registration + bond happens atomically in the `payable` `register_circle` entrypoint. There's no separate "proxy deployment bond" — the v2 model is **registry-mediated bonding**: a circle is deployed first (it has no on-chain capital obligation), then `register_circle(circle_id) payable` locks the bond keyed by `circle_id`. Slashing (carried over verbatim from v1.1's `slash_double_sign`) zeroes the bond and marks the entry permanently slashed.

### How we discovered this (the chicken-and-egg)

Original draft of `register_circle` was NOT payable and assumed the operator would call `bond_endpoint(circle_id, amount)` separately. Live e2e revealed `bond_endpoint requires owner` — and the owner can't deposit a bond they haven't registered yet. Fixed by making `register_circle` itself payable and atomic in commit `6c3ce5a`. Captured as a v2 design lesson in `docs/v2-circles-design.md` §0.

## 6. Operator discovery ~~[OPEN]~~ [RESOLVED 2026-05-17 via sealed-asset path]

- ~~Is there an Octra-blessed pattern for opt-in discovery?~~
- ~~Or are we expected to roll our own out-of-band channel?~~

**Resolution.** Operators publish a sealed `/policy.json` (AES-GCM-256 + PBKDF2-SHA256-120k key derivation + "OCRS1" magic + padded to 4k/16k/32k/128k bucket) via `circle_asset_put_encrypted`. Clients fetch the ciphertext by `resource_key(circle_id, "/policy.json")` — a hash derived from circle_id + path — so the path itself stays private from chain observers.

The discovery channel is two-step:
1. Public chain index: registered circles are queryable from the slim registry (`list_active_circles`-equivalent).
2. Per-circle policy: a tailnet owner who knows a circle_id fetches the sealed `/policy.json`, decrypts with the per-circle key the operator advertised out-of-band (e.g., via a public webpage or Twitter post — not on chain).

This composes "operators visible to authorized callers" without requiring a new directory primitive.

### How we discovered this

Studied the public webcli's `circle_asset_put_encrypted` flow and ported the envelope crypto. Verified by sealing a `/policy.json`, fetching by `resource_key`, decrypting in our client, and watching the chain trace show only opaque ciphertext + opaque resource_key.

## 7. Devnet RPC body cap [NEW OPEN — added 2026-05-17]

`https://devnet.octrascan.io/rpc` has `client_max_body_size ≈ 1 MiB` at the nginx edge. A PVAC pubkey blob (raw) is ~3.3 MB; base64-encoded for `octra_registerPvacPubkey` it's ~4.4 MB. **Result: PVAC pubkey registration is unreachable on devnet.** Mainnet RPC accepts the body (we tested with a 4 MB POST and got a proper RPC-layer rejection, not nginx 413).

This blocks any v2 work that exercises real HFHE on devnet — the operator's circle owner can't register a pubkey, so `fhe_load_pk(circle.owner)` fails at runtime, so settle / claim / encrypted-metering stay mock-only on devnet.

Documented in saved memory `octra_devnet_rpc_body_cap.md`.

**Ask:** raise the devnet RPC body cap to ≥8 MB to match mainnet behaviour, so v2 HFHE integration can be exercised end-to-end on devnet before mainnet bring-up.

---

## Why we cared (historical)

v1 ships today on main-net AML with public operator addresses. We could have kept extending v1 incrementally, but the privacy and ACL story is much cleaner on circles. We didn't want to ship a v1.5 with shared-exit / internal-subnet ACL just to throw it away in v2 — so we asked these six questions. Five resolved; §4 is partially resolved; §7 is the new operational ask.

8. **Timeline.** Public circles shipped on 2026-05-15. The HFHE transcipher / native-amount-attestation path (§4 remaining ask) timeline is still open.

We're happy to share our v2 design doc (`docs/v2-circles-design.md`) for sanity-check. Team contact: `andrew@golast.xyz`.

Thanks!
