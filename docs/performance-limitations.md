# OctraVPN — performance limitations

This is the internal scorecard for where the v2 stack tops out today.
For each layer below we record the current ceiling, the specific
bottleneck (file + line where known), and whether anyone has actually
measured it. Numbers come from code, audits, or saved-memory notes;
when no measurement exists the entry says "not measured" rather than
guessing.

This is a limits doc, not a roadmap. It deliberately does not propose
fixes — that's the next ticket.

## At a glance

| # | Layer                  | Current ceiling                                 | Bottleneck                                                       | Measured?                |
|---|------------------------|-------------------------------------------------|------------------------------------------------------------------|--------------------------|
| 1 | Data plane (WireGuard) | userspace boringtun 0.7.1 + onion peel per pkt  | per-packet decap + onion peel (`tunnel.rs`, `onion.rs:163`)      | no — qualitative only    |
| 2 | Mesh control plane     | 300 s peer-TTL, 60 s upgrade tick               | `peer.rs:270` TTL, `conn.rs:76` upgrade period                   | concurrency stress only  |
| 3 | IP allocator           | O(1) SHA-256 per allocation, ~4.19 M hosts/tnet | `ip_alloc.rs:118` (`hashed_host`)                                | yes — unit + birthday   |
| 4 | Chain interactions     | one tx per ~10 s mainnet epoch per wallet       | nonce serialization through one wallet; epoch finality           | epoch length empirical   |
| 5 | Operator settle freq   | ≥1 epoch (~10 s) per session per wallet         | same as #4 + audit-log flush; sessions through one proxy wallet  | no                       |
| 6 | Client connect time    | ≥1 epoch (~10 s) for `SessionOpened` event      | `runner.rs:311` poll backoff (100 ms→2 s, ≤30 s budget)          | no — bounded by chain    |
| 7 | Cryptography costs     | ed25519 + sha256 + AES-GCM (per receipt/asset)  | none individually dominant                                       | bench harness exists; snapshot not committed |
| 8 | Storage                | journal fsync per receipt sign; 4 KiB AML cap   | `receipt_journal.rs:186` (`atomic_write`); AML string truncation | qualitative; cap verified |

## 1. Data plane (WireGuard)

The data plane is userspace boringtun 0.7.1 (`Cargo.toml:67`, pinned via
workspace). Each accepted client peer gets its own `Tunn` instance in
`crates/octravpn-node/src/tunnel.rs:20`; encapsulation is Noise IKpsk2
+ ChaCha20-Poly1305. The TUN MTU defaults to 1380 bytes
(`octravpn-tun/src/lib.rs:58`), which leaves headroom for the WG header
(80 B) plus our onion layer; on a 1500-byte path that's 1380 / 1500 ≈
92 % goodput before counting the onion-layer expansion.

The onion layer is non-trivial in the hot path: every inbound payload
on a relay hop runs `peel_layer` (`octravpn-core/src/onion.rs:163`),
which is X25519 ECDH + ChaCha20-Poly1305 over the wrapper. The threat
model (`docs/v2-threat-model.md:41`) and `docs/troubleshooting.md:308`
both call out the per-packet boringtun decap + onion peel as the
expected CPU cost.

**No throughput number is committed.** The bench in
`crates/octravpn-core/benches/core.rs` exists but covers crypto
primitives only — there is no end-to-end Mbps measurement, no `iperf3`
harness, and no committed snapshot under `bench-snapshots/`. The
gap-analysis doc (`docs/gap-analysis.md:215`) flags this explicitly:
"D1. No performance benchmarks" / "No `criterion` benches" — written
before the primitives bench landed and still accurate for end-to-end.

## 2. Mesh control plane

The mesh manager (`octravpn-mesh/src/manager.rs`) doesn't run a
heartbeat loop itself — its `tick(tailnet_id)` returns a `Vec<MeshAction>`
that the host daemon applies. The tick is cheap and lock-only: snapshot
the `PeerRegistry` (`manager.rs:135`), step the per-peer connection
FSM, emit at most one open/close per peer.

Two scalars set the implicit refresh rate:

- **Peer TTL: 300 s** (`crates/octravpn-mesh/src/peer.rs:270` —
  `pub const TTL: Duration = Duration::from_secs(300)`). Any snapshot
  older than this is treated as stale; we don't act on it.
- **Conn upgrade period: 60 s** (`crates/octravpn-mesh/src/conn.rs:76`).
  How often the FSM re-probes a relay-routed connection for a direct
  candidate.

Concurrency under load is exercised in `crates/octravpn-node/tests/stress.rs:96`:
200 publishers + a ticker thread, 50 ticks at 100 µs spacing, asserting
"no panic" only. That's a correctness test, not a throughput number.

The mesh layer hands `MeteringSnapshot` to the chain via
`headscale_bridge.rs:32` (the integration point with `headscale-rs`).
The bridge is the boundary; no per-snapshot publish rate is encoded
here — it's whatever cadence the host daemon picks.

**Not measured**: max peers per tailnet before tick latency degrades;
publish-snapshot bandwidth at the control-plane HTTP layer.

## 3. IP allocator

`crates/octravpn-mesh/src/ip_alloc.rs:118` allocates a tailnet IP with
a single SHA-256 hash of `(tailnet_id, member_addr, ip_salt)` and a
modulo into a 4,194,300-slot CGNAT host space. Cost is O(1) per
allocation; no scan, no collision detection at the allocator layer.

Capacity and birthday-collision bounds are documented in-module
(`ip_alloc.rs:23-32`) and asserted in three unit tests:
`birthday_probability_matches_documented_bound` (`ip_alloc.rs:229`),
`empirical_collisions_for_1000_members_is_small` (line 262), and
`regression_old_10bit_host_space_would_collide` (line 286). At 1000
members the analytic P(collision) is ~11.75 %; the empirical test
asserts ≤ 5 collisions for 1000 distinct members.

Collision recovery uses an on-chain `ip_salt: u32` bump
(`with_salt`, line 92). **Caveat noted in the module docstring at
line 39**: the `ip_salt` field is not yet added to the on-chain
`Tailnet` struct in `program/main-v2.aml`, so it currently defaults to
0 and collisions must be resolved out-of-band.

**Measured**: yes (unit tests + analytic bound).

## 4. Chain interactions

The chain is Octra mainnet at ~**10.0 s/epoch** empirically — see
`docs/octra-research.md:15` and `:264` ("Mainnet target epoch length —
committed value unstated; ~10 s empirically"), sampled across
`epoch_summaries(818841..818850)`. Each epoch is finalized by a single
validator (Octra Labs ecosystem-fund wallet today;
`docs/octra-research.md:20`). The litepaper claim is ~800 TPS across
24 nodes (`docs/octra-research.md:135`); we do not hit that ceiling.

Our practical chain ceiling is one tx per epoch per wallet:

- Every `contract_call` from a single wallet must serialize on its
  nonce. The fetch path (`runner.rs:202-208`,
  `octra-circle-sim/src/rpc_chain.rs:106-127`) reads
  `pending_nonce.max(nonce)` and submits, but two concurrent submissions
  from the same wallet collide.
- Finality is per-epoch, so a `settle_claim` submitted in epoch N is
  observable in epoch N+1.

Body-size cap on devnet was 1 MiB at the nginx edge (memory:
`octra_devnet_rpc_body_cap.md`, confirmed 2026-05-17). That has now
been **raised** by the Octra team (acknowledged in
`memory/octra_aml_fhe_load_pk_blocked.md` — "RAISED — thanks Octra
team"). Mainnet RPC has always accepted full-size bodies.

AML `fhe_*` host calls revert on devnet for newly-deployed contracts —
verified by deploying Octra's own `program-examples/private_ml`
verbatim and watching `fhe_load_pk` fail (memory:
`octra_aml_fhe_load_pk_blocked.md`). This is not a throughput limit;
it's a hard ceiling at zero for the HFHE path until Octra wires the
bridge. We work around with `sha256` commitments today.

**Measured**: epoch length yes (live RPC sampling). Per-wallet tx
throughput under load: no.

## 5. Operator settle frequency

`submit_settle_claim` (`crates/octra-circle-sim/src/rpc_chain.rs:106`)
is a normal `contract_call`. The minimum interval between two settles
from one operator wallet is therefore:

- **One epoch** (~10 s) of chain finality before the next nonce is
  safe to use, and
- The OU fee floor returned by `octra_recommendedFee` per call
  (`runner.rs:204`) — quoted dynamically; no committed floor in our
  config. Per `docs/economics.md:713`, "5 000 OU × handful of epochs"
  per-tailnet-policy change is the documented cost shape, not a
  per-settle one.

A second cost is the **audit-log write** that wraps every receipt
event. `crates/octravpn-node/src/audit.rs:111` uses `OpenOptions::new().append(true)`
+ `write_all` + `flush` (line 143). **`flush` is libc-level buffer
flush, not `fsync`** — durability across power loss is not guaranteed
by the audit log alone. The HMAC chain (line 127-131) sequentializes
writes through one `parking_lot::Mutex`, so concurrent receipt events
on the same node settle through that lock.

The **receipt journal** (`crates/octravpn-core/src/receipt_journal.rs`)
*does* fsync — `atomic_write` (line 269-286) calls `File::sync_all` on
the tempfile then best-effort `sync_all` on the parent directory after
the rename. Every receipt-sign decision goes through `bump` (line 164),
which holds the journal lock across disk I/O (acknowledged in the
module comment at line 179-185 as a deliberate serialization trade-off
on grounds that "a tailnet's worth of sessions per node" is low).

So the per-receipt-signing ceiling per node is roughly: one
journal-fsync round-trip per signed receipt. On a healthy SSD that is
sub-millisecond; on networked storage it is whatever fsync costs there.

**Not measured**: fsync rate, audit-log appended-line rate, max
sustained signed-receipts per second.

## 6. Client connect time

`crates/octravpn-client/src/runner.rs:266` (`Cmd::Connect`) is the
cold-open path. The sequence:

1. Discover candidates: `discover::list(self, 0, 200)` (line 138) — one
   RPC round-trip.
2. Build commitments + onion route (lines 154-170) — pure CPU,
   negligible.
3. Submit `open_session` `contract_call` (line 223-225) — one chain
   submit.
4. Poll for `SessionOpened` event: `poll_session_id`
   (`runner.rs:311-333`). **Exponential backoff: 100 ms → 200 ms →
   400 ms → 800 ms → 1.6 s, capped at 2 s, up to 20 iterations
   (~30 s budget total)**.
5. WG handshake (boringtun) against entry hop.
6. `announce_to_exit` (line 274) — one HTTP POST to the exit's
   `/session` endpoint.

The chain-finality wait at step 4 is the long pole: `SessionOpened`
won't be visible until the open-session tx lands in a finalized epoch,
which is **≥1 epoch (~10 s)** on mainnet (`docs/octra-research.md:15`).
Step 6 adds one HTTP RTT; steps 1, 5 add their own.

**Not measured end-to-end.** The poll backoff implies the client gives
up at ~30 s; we don't have an `iperf-style` wall-clock distribution.

## 7. Cryptography costs

Per-primitive criterion benches live in
`crates/octravpn-core/benches/core.rs`:

- `receipt_build_sign` / `receipt_verify_dual` (line 36, 44) — dual
  ed25519 sign + verify around a `SignedReceipt`.
- `pedersen_commit` / `pedersen_verify_open` (line 56, 59).
- `earnings_commit` / `earnings_verify_claim` (line 76, 79).
- `onion_build_3hop` / `onion_peel_layer` (line 96, 99) — X25519 ECDH
  + ChaCha20-Poly1305 per hop.
- `tx_canonical_bytes` / `tx_sign_call` (line 118, 121).
- `wallet_encrypt_1k_iters` / `wallet_decrypt_1k_iters` (line 136, 139)
  — runs PBKDF2-style KDF at 1 000 iterations to keep the bench
  sub-second; the docstring at line 135 notes "production uses 200k".

**No committed snapshot** — `bench-snapshots/core.json` is referenced
in the bench docstring at line 5 but is gitignored output. Numbers
exist only when someone runs `cargo bench -p octravpn-core --bench
core` locally. There's no CI run-tracker.

AES-GCM seal/unseal of sealed assets is not directly benched here;
the receipt path covers ed25519 + sha256, the wallet path covers PBKDF2
+ AES-GCM (via the `wallet_enc` symbol the bench imports). Sealed-asset
throughput per-circle is bounded by the 4 KiB AML cap (§8) before it
ever hits the cipher.

**Measured**: harness exists, snapshot not committed. Treat all
crypto-primitive numbers as "knowable on-demand but not recorded".

## 8. Storage

Three durable writes happen on the node:

1. **Receipt journal** (`crates/octravpn-core/src/receipt_journal.rs`).
   Rewritten in full on every `bump` via tempfile + `sync_all` +
   rename (`atomic_write`, line 269). The mutex is held across disk
   I/O (line 179-185). One round-trip per signed receipt, per node.
2. **Audit log** (`crates/octravpn-node/src/audit.rs:111`). Append +
   `flush` (line 143) — libc flush, not fsync. HMAC-chained line
   format (line 126-131) serializes through one mutex.
3. **Sealed-asset writes** to circles. Bounded by the AML map-value
   cap.

The AML cap is **4096 bytes per `map[address]string` entry**, silently
truncated (memory: `octra_aml_string_cap_4kb.md`, verified 2026-05-18
against devnet program `octHiTZruUMFiBkAjt6EGYojYKAcn1mpiSHbaZn8Tfah5ss`).
A PVAC ciphertext is 56,032 bytes; storing one inline gives back 4096
bytes and a downstream `fhe_deser` revert. **Implication**: anything
that needs to persist >4 KiB on chain must use the
sha256-commitment-on-chain + ciphertext-as-sealed-asset pattern. The
sealed-asset path itself has a 32 MiB cap (per the memory note).

**Measured**: 4 KiB cap empirically (memory file); receipt-journal
correctness is unit-tested (`receipt_journal.rs:310-450`) but fsync
rate is not benched.

## Suspected limits not yet measured

- WireGuard data-plane Mbps per peer, with and without onion overhead,
  on a representative box. No end-to-end harness exists.
- Max concurrent sessions a single operator can sign for before the
  receipt-journal mutex starves new sessions.
- Mesh `tick` latency at 1k+ peers in one tailnet.
- Mesh peer-publish HTTP bandwidth at the control-plane.
- Per-wallet chain-tx throughput under sustained submit (nonce
  serialization vs `pending_nonce` race).
- Audit-log lines/second sustained.
- Cold-open client connect time end-to-end (chain epoch dominates;
  WG + announce add an unknown tail).
- AES-GCM throughput on sealed-asset put/get.
- PBKDF2 wallet-decrypt latency at the production 200k iterations
  (bench only covers 1k for sub-second runs).

## What we know vs. what we assume

**Measured (code or memory backs the number):**
- IP allocator capacity + birthday bounds — `ip_alloc.rs` tests.
- TUN MTU default of 1380 B — `octravpn-tun/src/lib.rs:58`.
- Peer TTL 300 s, conn upgrade period 60 s — `peer.rs:270`,
  `conn.rs:76`.
- Mainnet epoch length ~10.0 s — `docs/octra-research.md:15` from
  live `epoch_summaries` sampling.
- AML map-string truncation at 4096 B — `memory/octra_aml_string_cap_4kb.md`.
- Devnet RPC body cap was 1 MiB, now raised — `memory/octra_devnet_rpc_body_cap.md`.
- Client poll backoff 100 ms→2 s, ~30 s ceiling — `runner.rs:311-333`.
- Audit log uses `flush` not `fsync`; journal uses `sync_all` —
  `audit.rs:143`, `receipt_journal.rs:276`.

**Extrapolated (number derives from a measured one plus an obvious
chain rule):**
- "≥1 epoch per settle per wallet" — follows from epoch length + nonce
  serialization, not benched.
- "~30 s connect-time ceiling" — that's the poll budget, not an
  observed median.
- Birthday bounds at exact member counts beyond the documented table
  rows.

**Assumed (we have a story but no number):**
- WireGuard data-plane Mbps.
- Crypto-primitive throughput (bench exists, no snapshot committed).
- Tick / publish-snapshot scaling beyond the correctness-only stress
  test in `octravpn-node/tests/stress.rs`.
- AML `fhe_*` runtime cost on chain — moot until the chain-side
  bridge is wired (`memory/octra_aml_fhe_load_pk_blocked.md`).
