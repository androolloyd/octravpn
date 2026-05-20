# OctraVPN architecture

This document is the long-form companion to the README. It walks
through each subsystem's responsibilities, the wire formats between
them, and the security argument tying them to the formal specs.

Three AML programs are live on devnet in parallel and selected by
the node/client `protocol_version` config flag:

- **v1.1** — `program/main.aml`, deployed at
  `oct2YehVLezCi2RCcSkURc3nyyYtzxmspwGHHALm6pjkUvJ`. Public operator
  registry, two-tx settle, cryptographic `slash_double_sign`.
- **v2** — `program/main-v2.aml`, deployed at
  `oct3fxjrzfqh65ATo31eau8xRFBPiXh2Uzwue56EYkfVSj7`. Slim registry
  keyed by `circle_id`; identity + ACL + policy live in each
  operator's Octra Circle.
- **v3** — `program/main-v3.aml`, deployed at
  `oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3` (2026-05-18).
  Chain-minimal: only OU custody, slash, and 32-byte SHA-256 anchors
  per role. Class + price moved off chain entirely; settle is
  `(bytes_used, net, settle_blinding)` against the operator's
  circle. HFHE earnings ledger replaced by a SHA-256 hash chain
  (swap-ready when `fhe_*` AML host calls unblock). **This is the
  substrate going to mainnet.**

§1 below covers v1.1 (production shape); §2 covers v2 (intermediate
shape that introduced circle-keyed identity); v3 has its own
canonical doc set at [`v3/`](v3/) — start with
[`v3/README.md`](v3/README.md) for reading order per audience and
[`v3/overview.md`](v3/overview.md) for the one-page narrative. §3-§5
of this document cover off-chain components, wire formats, and the
safety argument shared across all three versions.

## 1. v1.1 — public registry (`program/main.aml`)

OctraVPN v1.1's on-chain program holds:

- **Endpoint registry**: `endpoints: map[address]EndpointRecord`.
  Each record stores bond, endpoint URL, WG pubkey, HFHE pubkey,
  view pubkey, region, `price_per_mb`, attestation epoch, jail
  state, and (v1.1) `receipt_pubkey` for cryptographic slashing.
- **Sessions**: `sessions: map[u64]Session` — opener, exit, deposit,
  open epoch, status, two-tx claim/confirm slots.
- **Encrypted earnings ledger**: `enc_earnings: map[address]bytes`.
  Each operator's running balance is held as an HFHE ciphertext
  under *their own* pubkey, so only they can decrypt.

### 1.1 Endpoint lifecycle

```
bond_endpoint() (payable)
    requires value >= MIN_ENDPOINT_STAKE
    effects  endpoint_stake[caller] += value

register_endpoint(endpoint, wg_pk, fhe_pk, view_pk, region,
                  price_per_mb, receipt_pubkey)
    requires endpoint_stake[caller] >= MIN_ENDPOINT_STAKE
    effects  endpoints[caller] = EndpointRecord{...}

unbond_endpoint() / finalize_unbond()
    standard timer-based unbonding.
```

### 1.2 Session lifecycle — two-tx settle

The v1.1 AML uses a **two-tx settle**: operator submits `settle_claim`,
client submits `settle_confirm`. Settlement only applies when both
agree on `bytes_used`. Equivocation triggers an in-AML slash;
disagreement records a public `SettleDispute` event and leaves the
session open for governance.

```
open_session(tailnet_id, exit_addr, max_pay)
    requires is_member(tailnet_id, caller)
             endpoints[exit_addr].active == 1
             max_pay >= min_session_deposit
    effects  tailnet.treasury -= max_pay
             sessions[++session_count] = Session{tailnet, exit, opener, deposit, open}

settle_claim(session_id, bytes_used)        // operator first
    if operator_claims[s].set && claim.bytes_used != bytes_used:
        SLASH operator (in-AML equivocation)
    else: record claim

settle_confirm(session_id, bytes_used)      // client second
    if claim.bytes_used != bytes_used:
        emit SettleDispute  (session stays open)
    else:
        total = bytes_used * endpoints[exit].price_per_mb
        protocol_fee = total * fee_bps / 10000
        enc_earnings[exit] += (total - protocol_fee)   // HFHE add_const
        treasury += protocol_fee
        tailnet.treasury += deposit - total            // refund
        sessions[s].status = settled

claim_no_show / sweep_expired_session       // long-tail cleanup
```

#### Hash-precommit join tokens

Tailnet owners pre-publish `sha256(preimage)` via
`precommit_join_token`; anyone holding the preimage redeems via
`redeem_join_token`. No signature verification needed — the
preimage IS the capability.

### 1.3 Earnings claim

```
claim_earnings(amount_proof, claimed_amount, stealth_output)
    fhe_load_pk(caller) → operator's PVAC pubkey
    fhe_verify_decrypt(enc_earnings[caller], claimed_amount, proof, pk)
    enc_earnings[caller] = fhe_zero(pk)
    emit_private_transfer(stealth_output, claimed_amount)
```

### 1.4 Cryptographic equivocation slash — `slash_double_sign`

The 2026-05-14 Octra dev-team announcement confirmed
`ed25519_ok(pk, msg, sig) -> bool`. v1.1 stores the operator's
`receipt_pubkey` in `EndpointRecord` and exposes:

```
slash_double_sign(operator, session_id, payload_a, sig_a, payload_b, sig_b)
    requires endpoints[operator].active && !slashed
             payload_a != payload_b
             ed25519_ok(receipt_pubkey, payload_a, sig_a)
             ed25519_ok(receipt_pubkey, payload_b, sig_b)
    effects  burn = total_stake * slash_burn_bps / 10000     (90%)
             bounty = total_stake - burn                       (10%)
             zero stake, mark slashed, transfer bounty to caller
```

Two distinct signed payloads under one receipt key are evidence of
equivocation regardless of what the payloads encode, so the AML
doesn't have to parse them.

The Lean lemmas `slashDoubleSign_*` and the TLA `SlashDoubleSign`
action + `Inv_DoubleSignSlashable` invariant cover the chain-side
formal argument.

## 2. v2 — circle-keyed, slim registry (`program/main-v2.aml`)

v2 splits the operator's identity, policy, ACL, and metering into a
per-operator Octra **Circle** (an Isolated Execution Environment)
and keeps only money, sessions, and slashing on the main program.

### 2.1 Slim registry shape

`program/main-v2.aml` (28 entrypoints) keeps:

- `circles: map[address]CircleRecord` — owner wallet,
  `receipt_pubkey` (base64), region, `price_per_mb_shared`,
  `price_per_mb_internal`, `active`, registration epoch.
- `tailnets: map[u64]Tailnet` — owner, treasury, member count,
  ACL policy ref, `charge_internal_traffic` toggle.
- `authorized_circles: map[u64]map[address]int` — per-tailnet
  ACL of which circles can be `open_session`'d against.
- `sessions: map[u64]Session` — `circle: address` replaces the v1.1
  `exit: address`; stamp the per-class `price_per_mb` at open time
  so live sessions are immune to mid-session price changes.
- `enc_earnings: map[address]bytes` — keyed on `circle_id`,
  HFHE-accumulated.

It drops: `endpoints`, `update_endpoint`, `rotate_keys` — those
move into the circle, since redeploying a circle changes its
`circle_id` and the operator re-registers under the new id.

### 2.2 Operator boot sequence in v2

`octravpn-node` (`crates/octravpn-node/src/chain_v2.rs`) automates:

1. **Predict** `circle_id` deterministically via
   `octra_core::circle::circle_id_of_deploy(deployer, nonce, deploy_payload)`.
   Output is a 47-char `oct…` address (sha256 + base58 over
   `(deployer, nonce, payload)`).
2. **Check** the registry: `circle_info(circle_id)` — skip the rest
   if already deployed + registered.
3. `deploy_circle` (normal Octra tx, `from=deployer → to_=circle_id`).
4. `circle_asset_put_encrypted` — uploads the sealed
   `/policy.json` keyed on `resource_key(circle_id, "/policy.json")`.
   Envelope format below (§4.4).
5. `register_circle(circle, receipt_pubkey_b64, region, price_shared, price_internal)`
   carrying `value = MIN_CIRCLE_STAKE`. In v2 this entrypoint is
   declared `payable` (`main-v2.aml:488`) so registration and the
   initial bond are **atomic** in one tx — the chicken-and-egg
   that surfaced in the live e2e (`bond_endpoint` required an
   already-registered circle; `register_circle` required an
   already-bonded circle) is fixed by making register-with-bond
   the only entrypoint.

PVAC pubkey registration is a separate per-wallet step (run once
per deployer wallet, not per-circle) because Octra's PVAC registry
is wallet-keyed: `octra cast register-pvac` (foundry sibling)
signs `"register_pvac|<addr>|<sha256_hex(pk)>"` and submits
`octra_registerPvacPubkey`. v2 looks up the HFHE pubkey via
`fhe_load_pk(circles[c].owner)` rather than `fhe_load_pk(circle)`
because circles are contracts with no keypair.

### 2.3 Client discovery in v2

`octravpn discover v2 <tailnet_id>` and `octravpn connect-v2`
(`crates/octravpn-client/src/discover_v2.rs`):

1. List `authorized_circles[tailnet_id]` from the registry → set
   of `circle_id` values approved by the tailnet owner.
2. For each, fetch the sealed asset by
   `circle_asset_ciphertext_by_resource_key(circle_id, "/policy.json")`.
   This RPC is **path-private**: the chain only sees that some
   resource_key was fetched, not which logical path.
3. Decrypt with the shared tailnet passphrase (PBKDF2-SHA256-120k
   → AES-GCM-256). The plaintext carries the operator's WG endpoint,
   pubkey, region, and tariffs.
4. `open_session(tailnet_id, circle, class, max_pay)` —
   `class ∈ {CLASS_SHARED=0, CLASS_INTERNAL=1}`, tariff stamped from
   the registry at open time.

### 2.4 Receipt context binding (P1-5)

Every receipt now binds the deployment context, so a receipt minted
under v1.1 / circle X / chain A cannot be replayed against v2 /
circle Y / chain B. `crates/octravpn-core/src/receipt.rs` defines
the v1.2 signing payload as

```
sha256("octravpn-receipt-v1" ||
       program_addr (32B) ||
       chain_id (u32 BE) ||
       circle_id_canonical (32B) ||      // 32 zero bytes in v1.1
       session_id (u64 BE) ||
       seq (u64 BE) ||
       bytes_used (u64 BE) ||
       blind (32B))
```

Operators set `[chain].chain_id` in `node.toml` (defaults to
`CHAIN_ID_DEVNET = 0x6F637464`); clients mirror via
`[chain].chain_id` in `client.toml`. Tests
`cross_program_receipt_rejection`, `cross_chain_receipt_rejection`,
`cross_circle_receipt_rejection` in `receipt.rs` and proptest
variants in `tests/prop_receipt.rs` assert the binding.

### 2.5 Receipt journal (P1-8 / P1-9)

`crates/octravpn-core/src/receipt_journal.rs` persists
`(session_id → last_signed_seq)` to disk. The journal is fsync'd
(tempfile + persist + sync_all on both the file and the parent dir)
**before** any `Receipt` is signed. Daemon restarts reload the floor
and shadow `ControlSession.last_seq = max(in_mem, journal_floor)`,
so an OOM / segfault / signal between two receipts can no longer
trick the daemon into signing two distinct receipts at the same
`(session_id, seq)`. Default path `./state/receipts.bin`, overridable
via `[control].receipt_journal_path`.

### 2.6 Sealed key storage (P1-6)

`crates/octravpn-node/src/seal.rs` adds the
`octravpn-node seal-keys` / `unseal-keys` subcommands. They wrap
the configured wallet + WG keys under the
`OCTRA-WALLET-V1` passphrase envelope
(ChaCha20-Poly1305 + PBKDF2-SHA256-120k), atomic-write via tempfile
+ fsync, idempotent on re-runs. Strict mode
(`[chain].require_sealed_keys = true`) refuses to boot if any
configured secret is still plaintext, surfacing
`CoreError::PlaintextKeyOnDisk` with the suggested `seal-keys`
CLI quoted in the error. Passphrase comes from
`OCTRAVPN_KEY_PASSPHRASE`. Devnet keys remain plaintext by default
for back-compat with the existing `e2e.sh` harness.

### 2.7 HFHE settlement routing

The HFHE ledger in v2 stores ciphertexts under `circle_id`, but
PVAC pubkey registration is **per-wallet** (Octra's PVAC registry
shape). Both `settle_confirm` and `claim_earnings` route through
the circle's owner:

```
let pk = fhe_load_pk(circles[c].owner)   // design comment at main-v2.aml:176
```

The PVAC sidecar (`pvac-sidecar/`, GPL-2+, isolated as a separate
process) produces chain-compatible PVAC pubkey, ciphertext and
zero-proof blobs from the upstream `octra-labs/webcli` PVAC
reference. The Rust workspace talks to it over JSON-over-stdio; no
GPL symbols cross into the MIT/Apache crates.

### 2.8 Operator-circle (per-operator program)

`program/operator-circle.aml` is the in-circle program each operator
deploys. It compiles against the AML grammar (verified via
`octra_compileAml`) and carries:

- **Sealed policy resource_keys** — the encrypted `/policy.json`
  is stored by `resource_key` so non-members can't enumerate it.
- **Member ACL** — `commit_member(member, receipt_pk_b64, sig_b64)`
  verifies the acceptance signature via `ed25519_ok` and binds the
  member's wallet to the circle's ACL.
- **Per-session metering counters** — `meter_bytes` accepts deltas
  signed by the circle owner (P0-3 fixed in commit `b9aedf7` — the
  earlier broken `ed25519_ok` call used a resource_key hash as the
  pubkey arg; the dead branch was dropped, caller-auth is now the
  documented + enforced contract).

### 2.9 Pause semantics

`pause` halts USER flows only (`open_session`, `settle_*`,
`bond_endpoint`, etc.). Governance entrypoints
(`withdraw_program_treasury`, `set_params`, `transfer_ownership`,
`set_paused`) intentionally bypass pause — a compromised owner can
`set_paused(0)` first anyway, so gating governance on pause adds no
defense and breaks emergency-response (refunds, migrations). v1.1
had a brief detour gating these on pause; reverted in commit
`d7aaa65`.

## 3. Off-chain components (shared)

### 3.1 `octravpn-core`

Shared crate. Defines `Address`, `KeyPair`, `Receipt`, `SignedReceipt`,
`Commitment`, `Onion`, `SessionId`, `EndpointRecord` (v1.1) /
`CircleRecord` (v2), plus the `RpcClient` covering every Octra RPC
method the workspace touches. Critical invariants:

- Receipt canonical signing payload is the v1.2 hash described in §2.4.
  Identical Rust ↔ AML serialization is property-checked in
  `prop_canonicalization.rs`.
- `SignedReceipt::check_monotonic` rejects equal seqs; the receipt
  journal (§2.5) makes the check survive restart.
- Pedersen commitment is hiding under random blinds and binding by
  hash.

### 3.2 `octravpn-node`

Operator daemon. Subcommands:

- `register` (v1.1) — submit `register_endpoint`.
- `v2 register` — predict circle_id → deploy → asset_put → atomic
  `register_circle` (§2.2).
- `seal-keys` / `unseal-keys` — sealed-mode key envelope (§2.6).
- `attest` — push `refresh_attestation` (v1.1 only).
- `claim-earnings` — fetch ciphertext, decrypt via the PVAC sidecar,
  prove decryption, submit `claim_earnings`.
- `run` — the main loop: register if needed, schedule attestations
  (v1.1), run the boringtun server, accept WG traffic, sign receipts.

### 3.3 `octravpn-client`

End-user CLI. Subcommands include:

- `nodes` (v1.1) — list active endpoints.
- `discover v2 <tailnet_id>` — enumerate authorized circles + fetch
  sealed `/policy.json` for each.
- `connect-v2` — discover + decrypt + `open_session` + bring up the
  tunnel + settle.
- `connect --hops 3 --deposit 200` (v1.1) — same for the v1.1 path.
- `settle <id>` — settle a previously-opened session.
- `slash-evidence verify|build|submit` — landing a
  `slash_double_sign` on chain for a bounty.

### 3.4 `pvac-sidecar`

JSON-over-stdio C++ daemon producing chain-compatible PVAC blobs.
Past the AES KAT gate on mainnet (commit `9e16868`). The Rust crates
shell out to it; no GPL symbols are linked.

## 4. Wire formats

### 4.1 Receipt (v1.2)

```
Domain tag : "octravpn-receipt-v1"
Payload    : tag || program_addr (32B) || chain_id (u32 BE) ||
             circle_id_canonical (32B) ||
             session_id (u64 BE) || seq (u64 BE) ||
             bytes_used (u64 BE) || blind (32B)
Signing    : ed25519(receipt_secret_key, sha256(payload))
```

`circle_id_canonical = 32 zero bytes` for v1.1 receipts (no circle),
so the hash domain is fixed-width across v1.1 + v2.

### 4.2 Pedersen commitment

```
Domain tag : "octravpn-commit-v1"
Commit     : sha256(tag || addr_raw (32B) || blind (32B))
Open       : (addr, blind) — verified by recomputing
```

### 4.3 Onion header

```
HopHeader {
  wg_pubkey: [u8; 32],
  next: HopNext::Forward { endpoint, wg_pubkey } | HopNext::Egress,
  mac:  [u8; 16]
}
```

`Onion = { layers: [HopHeader; N], inner: bytes }`. Each hop's
symmetric session key is derived via Curve25519 ECDH between the
client session ephemeral and the hop's static WG pubkey.

### 4.4 Sealed asset envelope (`"OCRS1"`)

The format used by `circle_asset_put_encrypted` /
`circle_asset_ciphertext_by_resource_key`
(`octra-foundry/crates/octra-core/src/circle.rs`):

```
"OCRS1" (magic) || version (u8=1) || padding_class (u8) ||
salt (32B) || nonce (12B) || aes_gcm_ciphertext(plaintext_padded)

key   = PBKDF2-HMAC-SHA256(passphrase, salt, 120_000) → 32B AES key
salt  = "octra:circle:sealed_read:v1:" || circle_id || ":" || key_id
nonce = fresh random 12B per call (no AES-GCM nonce reuse)
pad   = plaintext zero-padded up to padding_class ∈ {4k, 16k, 32k, 128k}
```

Padding classes leak coarse plaintext size by design — most
`/policy.json` blobs fit in the 4k class so they're indistinguishable
from each other.

### 4.5 Sealed-key envelope (`OCTRA-WALLET-V1`)

Used by `octravpn-node seal-keys` (`crates/octravpn-node/src/seal.rs`):

```
"OCTRA-WALLET-V1" || version || salt (32B) || nonce (24B) ||
chacha20poly1305_ciphertext(secret_key_32B)

key = PBKDF2-HMAC-SHA256(passphrase, salt, 120_000)
```

## 5. Safety and verification arguments

| Property                            | Where it's argued / checked          |
| ----------------------------------- | ------------------------------------ |
| Receipt signatures unforgeable      | Tamarin `ReceiptUnforgeability`      |
| Cross-program / cross-chain / cross-circle replay rejected | `receipt.rs` tests `cross_*_receipt_rejection` (P1-5) |
| Restart-replay rejected             | `receipt_journal::tests::restart_replay_rejection` (P1-8/9) |
| Plaintext-on-disk rejected in strict mode | `seal.rs` returns `CoreError::PlaintextKeyOnDisk` (P1-6) |
| No double-settle, monotonic seq     | TLA+ `NoDoubleSettle`, `MonotonicSeq` (v1.1 + v2) |
| Conservation of funds               | TLA+ `ConservationOfFunds` (v1.1 + v2) |
| Atomic register-bond invariant      | TLA+ v2 `Inv_CircleAtomicRegisterBond` |
| Authorized circle is registered     | TLA+ v2 `Inv_AuthorizedCircleIsActive` |
| Stamped price immutable in open session | TLA+ v2 `Inv_StampedPriceImmutableInOpenSession` |
| Bond never negative                 | TLA+ `SlashLeBond`, Lean `slash_double_sign_zeros_bond` |
| `register; complete_unbond` returns full bond | Lean `completeUnbond_returns_full_bond` |
| Receipt round-trip is sound         | Kani `round_trip_signed_receipt`, proptest |
| 45 v2 adversarial cases (S/F/R/E/etc) | `docker/devnet/e2e-adversarial-v2.sh` |
| 49 v1.1 adversarial cases             | `docker/devnet/e2e-adversarial.sh`    |

TLC runs:

- v1.1: 2,756,874 states / 223,118 distinct / depth 26 / 0 violations.
- v2:  52,676,571 states / 3,805,681 distinct / depth 31 / 0 violations.

## 6. Operational notes

- v1.1 operators MUST refresh attestations within
  `attest_grace_epochs`. Reference daemon refreshes every 5 epochs.
- v2 operators have no per-epoch attestation — the circle's
  `active = 1` flag at registration is the liveness signal.
- Clients SHOULD maintain a local cache of in-flight session
  bookkeeping so `settle <id>` can reconstruct a session after
  process death.
- For mainnet deploys: `require_sealed_keys = true`, sealed
  `*.sealed` paths in TOML, and a fresh wallet for each circle
  deploy — see [`docs/v2-operator-key-hygiene.md`](v2-operator-key-hygiene.md).
- HFHE end-to-end settlement on devnet is partially unblocked: the
  RPC body cap was raised 2026-05-18 so PVAC pubkey registration
  confirms, but chain-side AML `fhe_load_pk` still reverts for our
  contracts — see README's "What's blocked" section and
  `memory/octra_aml_fhe_load_pk_blocked.md`.

## 7. Migration

v1.1 and v2 are separate deployments. There is no in-place
migration inside a program instance — the on-chain registry shape
is fundamentally different (`address`-keyed vs `circle_id`-keyed).
Operators may run both in parallel and clients pick by config flag.
Tailnets are single-version.
