# Validator hardening

How OctraVPN hardens the validator (a.k.a. operator / exit-node) side of
the network against adversarial clients, hostile peers, and a malicious
chain-RPC endpoint. This document is the index for the fuzz suite, the
chain-side slash conditions, the rate-limit boundary, and the HMAC
audit log that together pin a validator's exposed surface area.

## 1. Threat model

What a validator must defend against:

| Attack                                | Surface           | Defence                                            |
|---------------------------------------|-------------------|----------------------------------------------------|
| Malformed RPC envelope crashes daemon | HTTP control plane | `serde_json` strict-decode + `fuzz_validator_rpc_envelope` |
| Double-redemption of preauth key      | `/admin/preauth`   | `PreauthMinter` single-use BoundedMap + `fuzz_preauth_redeem` |
| Double-spend / out-of-order claims    | `settle_claim` RPC | `claim_window` monotonic-seq invariant + `fuzz_v3_settle_claim_double_spend` |
| Hostile chain-RPC returning trash     | `ValidatorOracle`  | `as_str`-filtered bulk decode + `fuzz_validator_health_oracle` |
| Operator publishes anchor A, serves S′| `state-root.json`  | Canonical-encoder injectivity + `fuzz_circle_state_root_replay` |
| Equivocation (two seqs, same session) | Receipt journal    | `slash_double_sign` (chain) + `receipt_journal` (off-chain durability) |
| RPC flood / DoS                       | `/session`, `/admin/preauth`, `/v3_calls` | Per-route token-bucket in `octravpn-node::rate_limit` |
| Audit log forgery                     | JSONL files        | HMAC-SHA256 chain across every line (`octravpn-node::audit`) |

What a malicious validator can do (and what we deliberately do NOT
defend against at the protocol layer):

- **Refuse service.** A validator can drop sessions or stop signing
  receipts. This is detectable but not punishable on-chain — the
  consumer's recourse is `claim_no_show` / `sweep_expired_session`
  (`crates/octravpn-core/src/v3_calls.rs:67-71`), which refunds the
  deposit.
- **Lie about region / latency.** `region` in `state-root.json` is
  freeform; verifiers treat divergence as advisory.
- **Underreport `bytes_used`.** Validators are *incentivised* to
  overreport, not underreport. Underreporting hurts only the validator.

What a malicious client can do:

- **Burn a deposit by opening a session and never connecting.** Yes,
  but that's their money.
- **Refuse to acknowledge a settle.** The validator settles unilaterally
  via `settle_claim`; the client cannot block it.

## 2. The 5 validator-side fuzz targets

All five live in `fuzz/fuzz_targets/`, are wired into
`fuzz/Cargo.toml`, and run nightly via `.github/workflows/fuzz.yml`
(5-minute budget per target, on-crash corpus + GitHub-issue dispatch).
Each target completes a `-runs=1000` smoke pass in under 60s.

### 2.1 `fuzz_validator_rpc_envelope`

**Catches:** panic-on-decode for any byte sequence arriving on the
validator's JSON-RPC surface.

Adversarial scenarios:

- malformed UTF-8 / truncated JSON
- oversized integer literals beyond `i64`/`u64` range
- deeply nested arrays / objects (stack-overflow probe)
- duplicate keys
- unicode normalisation tricks in address-shaped positions
- leading-zero / scientific-notation number literals

The same `canonical_bytes()` path the validator uses to recompute
tx hashes is invoked on every successful parse — so a panic in the
canonical encoder also surfaces here.

### 2.2 `fuzz_v3_settle_claim_double_spend`

**Catches:** any sequence of `(session_id, claim_seq, signature)` tuples
— valid, duplicate, out-of-order, or forged — that breaks the
single-use invariant of the v3 `settle_claim` handler.

Models the handler's `claim_window` map using the same primitive the
production code uses for single-use enforcement: `PreauthMinter`'s
`mints` BoundedMap with FIFO eviction and atomic
`lookup → conditional remove → record` (see
`crates/octravpn-mesh/src/headscale_bridge.rs:332`). The fuzz target
asserts: *for any single-use token, at most one `redeem()` call ever
returns `Ok`* across the entire fuzzed sequence.

### 2.3 `fuzz_validator_health_oracle`

**Catches:** panics in the validator-set decode path when the chain
RPC returns adversarial JSON.

Mirrors `ValidatorOracle::refresh_bulk`
(`crates/octravpn-core/src/validator_oracle.rs:154-160`):
`arr.iter().filter_map(|x| x.as_str().map(String::from)).collect()`.
The fuzz target feeds arbitrary bytes and asserts:

- decode never panics
- non-string entries are silently dropped (not coerced)
- resulting set contains no NUL bytes
- every `Value` accessor (`as_i64`, `as_array`, …) is safe to call on
  every input

The slash-decision logic for misbehaving validators lives **on chain**
(`slash_double_sign` in `program/main-v3.aml`); the oracle's
off-chain role is purely set-membership lookup, and that is what this
target covers.

### 2.4 `fuzz_circle_state_root_replay`

**Catches:** any field-level mutation of a `StateRoot` that fails to
flip the on-chain anchor.

Since #242 the canonical encoder is determinism-proven by proptest.
The remaining attack surface is *semantic*: an operator who mutates
`policy_hash`, `wg_pubkey_hash`, `region`, `member_count`, `epoch`,
`timestamp_secs`, `attestation_hash`, or `circle_id` and recomputes
the anchor must produce a *different* anchor than the original. The
fuzz target builds two `StateRoot`s, mutates exactly one field, and
asserts `sr_a.anchor_hex() != sr_b.anchor_hex()`. A collision
would be a SHA-256 collision — a finding much bigger than a fuzz bug.

### 2.5 `fuzz_preauth_redeem`

**Catches:** any input to `PreauthMinter::redeem` that panics, that
admits a double-redemption of a single-use token, or that accepts an
adversarial token shape (NUL bytes, oversized, empty, wrong prefix).

Specifically exercises:

- tampered token bytes (1-bit flip from a valid token)
- near-expiry races (1ms TTL on mint, immediate redeem)
- capacity-overflow attacks (cap=4, mint past it; FIFO-evicted
  tokens must NOT become re-redeemable)
- reusable-key abuse (many redeems on `reusable=true`)
- single-use double-redemption (the primary invariant)

## 3. Operational hardening

### 3.1 Rate limits

Per-route token-bucket limits are configured in `node.toml` under
`[control.rate_limit]` and wired in `octravpn-node::rate_limit`
(`crates/octravpn-node/src/rate_limit.rs`). The classifier at
`rate_limit.rs:85` recognises:

| Path prefix      | Class      | Defaults (per peer) |
|------------------|------------|---------------------|
| `/admin/preauth` | `Preauth`  | 60/min, burst 120   |
| `/session*`, `/receipt*` | `Receipt`  | (see config)        |
| `/v3_calls*`     | `V3Calls`  | 10/min, burst 30    |
| anything else    | `Other`    | default bucket      |

**Gaps as of 2026-05-19:**

- There is **no `/map` route classifier**. The Tailscale-compatible
  `/map` endpoint (added when the wire bridge lands — see
  `headscale-rs` PR thread) will need a new `RouteClass::Map` entry
  in `rate_limit.rs:85` with a conservative bucket; until then it
  falls into `RouteClass::Other` (the default bucket), which is fine
  for the current devnet load but should be tightened before
  mainnet.
- The `/admin/preauth/redeem` sub-path inherits the `Preauth` bucket.
  This is correct *only if* the mint-side bucket is sized to dominate
  redeem traffic; once headscale-rs is wired the redeem path will
  see >>> mint traffic and need its own classifier.

### 3.2 Bounded memory

Every long-lived map on the validator side is a `BoundedMap`
(`crates/octravpn-core/src/bounded.rs`) with a hard capacity cap and
idle-TTL sweep. Defaults:

- `PreauthMinter::mints` — 100k entries, 30-day TTL
- `PreauthMinter::redemptions` — 100k entries, 30-day TTL
- `ControlSession.last_seq` — bounded per-session

This means a flood of mints / redeems cannot exhaust memory; FIFO
eviction kicks in past the cap. Crucially, an evicted single-use
preauth key returns `RedeemError::Unknown` (NOT re-redeemable) —
`fuzz_preauth_redeem` exercises that exact path.

## 4. Slash conditions (v3 AML)

Three slash paths exist on chain (`program/main-v3.aml`):

1. **`slash_double_sign(circle, payload_a, sig_a, payload_b, sig_b)`**
   (`v3_calls.rs:49-50`). The dual-signed receipt scheme
   (`crates/octravpn-core/src/receipt.rs`) means any third party who
   observes two distinct `(seq, bytes_used)` pairs under the same
   session_id, both signed by the operator's receipt-signing key, can
   submit them and burn the bond. The receipt journal
   (`crates/octravpn-core/src/receipt_journal.rs`) keeps the operator
   from accidentally signing two payloads at the same seq across a
   restart — see P1-8 / P1-9 in `docs/v2-threat-model.md`.

2. **Settle griefing**: not a standalone slash, but `claim_no_show`
   and `sweep_expired_session` refund the consumer's deposit if the
   operator never settles within the session-grace window. This makes
   griefing economically pointless: the operator burned the chain
   fees to open the session but earns nothing.

3. **Claim-window violation**: an operator that submits two distinct
   `settle_claim` payloads for the same `(session_id, claim_seq)` is
   committing equivocation in the same shape as `slash_double_sign`.
   The `fuzz_v3_settle_claim_double_spend` target ensures the
   single-use invariant holds locally so the operator daemon does not
   *accidentally* equivocate.

## 5. Audit log emit points

The validator runs a JSONL audit log
(`crates/octravpn-node/src/audit.rs`) with an HMAC-SHA256 chain across
every line — `mac[N] = HMAC(key, prev_mac || record_json)`. A
verifier can detect any truncation, reordering, or in-place edit by
walking the chain (`audit_cli::verify_audit_files`,
`audit_cli.rs:485`).

Events the validator MUST emit:

| Kind             | Source                                              |
|------------------|-----------------------------------------------------|
| `announce`       | session-open                                        |
| `get_state`      | mid-session state pull                              |
| `receipt_signed` | every signed receipt — `audit.rs:388`               |
| `preauth_mint`   | `PreauthMinter::mint` (via `MetricsSink`)           |
| `preauth_redeem` | `PreauthMinter::redeem` (via `MetricsSink`)         |

Operators must run `octravpn-node verify-audit-log` periodically (or
on every shift change) — a missing `receipt_signed` row before a
`settle_claim` event is the signature of a tampered audit log, and the
verifier exits non-zero with the offending line.

### 5.1 HMAC chain integrity guarantees

- **Truncation detection**: removing trailing lines breaks the chain
  on the next append because `prev_mac` no longer matches.
- **In-place edit detection**: any byte change to `record_json`
  changes `mac`, which the next line's `prev_mac` references —
  cascade failure.
- **Reordering detection**: the chain is positional; swapping two
  lines breaks both their `mac`s.
- **What the chain does NOT prove**: that the validator *emitted*
  every event it should have. An operator who never logs a
  `receipt_signed` row will have a self-consistent (but incomplete)
  chain. That's why the verifier cross-checks against the on-chain
  `settle_claim` events: every chain-side claim must have a
  corresponding `receipt_signed` row in the audit log
  (`audit_cli.rs:501-513`).

## 6. Layer 1: AmneziaWG-style obfuscation

OctraVPN's WireGuard data plane runs on top of `boringtun`. Stock WG
packets carry a deterministic fingerprint that any DPI middlebox
(GFW, hotel captive-portal filter, hostile ISP) can match in O(1):

  - bytes 0..4 = msg_type as a little-endian u32, always one of
    `{1, 2, 3, 4}` followed by three NUL pad bytes;
  - canonical lengths — handshake-init is exactly 148 bytes,
    handshake-response is 92 bytes, cookie is 64 bytes;
  - the very first packet of a session matches the init signature
    every time.

The Layer-1 shield is an
[AmneziaWG](https://github.com/amnezia-vpn/amneziawg-go)-style
**wrapper** around UDP send/recv in `crates/octravpn-tun/src/amnezia.rs`.
We do not fork `boringtun`; we pre-process outbound packets after
`Tunn::encapsulate` and post-process inbound packets before
`Tunn::decapsulate`. The shield's three primitives:

| Primitive | Knob(s)               | Defeats                                           |
|-----------|-----------------------|---------------------------------------------------|
| Pre-handshake junk burst | `jc`, `jmin`, `jmax` | "first datagram is the init" fingerprint           |
| Random length-prefix     | `s1`, `s2`           | length-based matchers (148/92 vanish)              |
| Msg-type substitution    | `h1`..`h4`           | the `byte 0 ∈ {1..=4} && bytes 1..4 == 0` matcher  |

### Config

Add to `node.toml`:

```toml
[tunnel.amnezia]
enabled = true
jc      = 4           # 1..=128   pre-handshake junk packets
jmin    = 40          # 1..=1280  min junk-packet size
jmax    = 70          # 1..=1280  max junk-packet size (≥ jmin)
s1      = 24          # 0..=1280  bytes prepended to outgoing init
s2      = 17          # 0..=1280  bytes prepended to outgoing response
h1      = 0x21A1A1A1  # 5..=2_147_483_647   replaces msg-type 1
h2      = 0x22B2B2B2  # 5..=2_147_483_647   replaces msg-type 2
h3      = 0x23C3C3C3  # 5..=2_147_483_647   replaces msg-type 3
h4      = 0x24D4D4D4  # 5..=2_147_483_647   replaces msg-type 4
```

`enabled = false` (the default) makes the shield an identity
transform — zero allocations, zero substitutions, full stock-WG
compatibility.

### Interop

**Both ends must agree** on every value of all 9 knobs. The shield
is symmetric: when peer A applies `s1=24, h1=0x21A1A1A1`, peer B
strips 24 bytes of prefix and rewrites the header back to `0x01` —
if peer B is configured with `s1=0` or a different `h1`, B's
`wrap_recv` returns `None` and the packet is dropped as junk.

Stock-WireGuard peers **cannot** connect to a node with
`[tunnel.amnezia].enabled = true`. To bridge the two populations
run a second listener on a different UDP port with the shield
disabled. The shield-disabled path is config-gated:
`AmneziaCfg::to_wire()` returns the identity `AmneziaConfig`
whenever `enabled = false`, even if the operator left h-values set
from a previous experiment (defence in depth against typos).

### What this layer does NOT hide

  - **Timing.** Packet inter-arrival is unchanged. A traffic-analysis
    adversary who sees both sides of the link can still infer
    "this is a tunneled keepalive flow" from the periodic
    25-second WG keepalive cadence.
  - **Volume.** Total bytes per session are unchanged (plus the
    fixed `s1 + s2 + jc * avg(jmin, jmax)` per-session overhead).
  - **Endpoint addressing.** A passive observer still sees the
    source/destination IP + port tuple of every datagram.
  - **Active probing on the obfuscated port.** A probe that mints
    a candidate `h1`-prefixed packet of plausible length can only
    be told apart from a real init *after* `boringtun` rejects the
    noise handshake — this layer is **defence in depth, not
    steganography**. Subsequent layers (PSK-gated knock, decoy
    flow, hidden-exit v2) raise the cost of an active probe.

### Code refs

  - `crates/octravpn-tun/src/amnezia.rs` — wire-layer shield +
    11 unit/property/loopback tests.
  - `crates/octravpn-node/src/tunnel.rs` — `Server` integration.
    Public callers go through `Server::bind` (identity shield) or
    `Server::bind_with_shield` (explicit config). The egress UDP
    path (`Server::egress`) bypasses the shield because those
    bytes are plaintext destined for the public internet, not WG.
  - `crates/octravpn-node/src/config.rs` — `[tunnel.amnezia]`
    `AmneziaCfg` block.

## 7. Running the fuzz suite locally

```bash
cd fuzz
# Smoke (60s):
cargo +nightly fuzz run fuzz_validator_rpc_envelope -- -runs=1000
# Real run (5 min, matches nightly):
cargo +nightly fuzz run fuzz_preauth_redeem -- -max_total_time=300

# Build all targets without running:
cargo +nightly fuzz build
```

A crash drops a reproducer into `fuzz/artifacts/<target>/`; the
nightly workflow uploads it as a run artifact and opens an issue
labelled `fuzz-crash` + `target/<name>`.
