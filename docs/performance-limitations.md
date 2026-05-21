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
| 1 | Data plane (WireGuard) | ~1.2 Gbps/core relay-hop (chacha+onion)         | per-packet decap + onion peel (`tunnel.rs`, `onion.rs:163`)      | yes — primitives, §1     |
| 2 | Mesh control plane     | ~2.3M publishes/s; tick ~1 µs/peer              | `peer.rs:270` TTL, `conn.rs:76` upgrade period                   | yes — §2                 |
| 3 | IP allocator           | O(1) SHA-256 per allocation, ~4.19 M hosts/tnet | `ip_alloc.rs:118` (`hashed_host`)                                | yes — unit + birthday    |
| 4 | Chain interactions     | one tx per ~10 s mainnet epoch per wallet       | nonce serialization through one wallet; epoch finality           | epoch length empirical   |
| 5 | Operator settle freq   | ~100 signed receipts/s/node (journal fsync)     | `receipt_journal.rs:186` fsync; audit log flush nearly free      | yes — §5                 |
| 6 | Client connect time    | epoch + ≤2 s poll-overhead tail                 | `runner.rs:311` poll backoff (100 ms→2 s, ≤30 s budget)          | yes — §6                 |
| 7 | Cryptography costs     | snapshot committed (`bench-snapshots/core.json`)| none individually dominant                                       | yes — §7                 |
| 8 | Storage                | journal fsync per receipt sign; 4 KiB AML cap   | `receipt_journal.rs:186` (`atomic_write`); AML string truncation | yes — §5 + cap verified  |

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

**Primitive-level numbers** (committed; end-to-end Mbps with two
real `Tunn` instances isn't reachable without expanding the node's
public API — see the bench docstring). Host: Darwin arm64 / Apple
M3 Max / macOS 26.1, `--release`. Bench:
`crates/octravpn-node/benches/wireguard_throughput.rs`.

| Primitive                                  | Mean      | Implied single-core ceiling |
|--------------------------------------------|-----------|------------------------------|
| ChaCha20-Poly1305 seal (1380 B, portable)  | 4.48 µs   | ~2.46 Gbps (encap only)      |
| ChaCha20-Poly1305 open (1380 B, portable)  | 4.46 µs   | ~2.47 Gbps (decap only)      |
| ChaCha20-Poly1305 seal (1380 B, aws-lc-rs) | 0.93 µs   | ~11.6 Gbps (encap only)      |
| ChaCha20-Poly1305 open (1380 B, aws-lc-rs) | 1.09 µs   | ~9.86 Gbps (decap only)      |
| X25519 ECDH (handshake)                    | 29.3 µs   | 34 k handshakes/s/core       |

Perf-5 (hardware-accelerated AEAD, `crates/octravpn-core/src/aead.rs`)
switched the WireGuard data-plane and obfs4 framing call sites from
the portable `chacha20poly1305 = "0.10"` crate to a `aws-lc-rs`-backed
shim that uses AVX2 on x86_64 and NEON on aarch64. The hwaccel rows
above are the post-switch numbers; the portable rows are kept as the
audit baseline. Seal speedup: −79 % wall-time, ~4.8×; open speedup:
−76 %, ~4.1×.

Extrapolated WG-relay-hop budget per core, **portable path**: one
decap + one encap per packet ≈ 8.94 µs/pkt → ~1.23 Gbps.
**Hardware-accelerated path**: ≈ 2.02 µs/pkt → ~**5.47 Gbps/core**.
Add one `onion_peel_layer` (31.7 µs from the older
`bench-snapshots/core.json`; onion is now also on the hwaccel path so
this will measure smaller on the next snapshot) and the relay-hop
budget for a 3-hop circuit moves from ~270 Mbps/core/hop to ~1 Gbps+
once the snapshot refreshes. Live tunnels run on real UDP sockets
with ~80 B header; these are upper-bound crypto-cost numbers, not
wire-rate.

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

**Measured** (`crates/octravpn-mesh/benches/peer_publish.rs`, same host
as §1, run with `--features test-helpers`):

| Scale         | publish_unverified | tick                 |
|---------------|--------------------|----------------------|
| 10 peers      | 432 ns / insert    | 8.96 µs / tick       |
| 100 peers     | 433 ns / insert    | 88.1 µs / tick       |
| 1 000 peers   | 446 ns / insert    | 936 µs / tick        |
| 10 000 peers  | 442 ns / insert    | 9.93 ms / tick       |

`publish_unverified` is HashMap-flat across the range (one RwLock
write + one alloc per snapshot). `tick` scales linearly: ~0.9 µs
per peer of registry walk + per-peer FSM step (the inner cost
matches the per-peer crypto-free path through `manager.rs:135`).
At 10 k peers in one tailnet, a tick is still under 10 ms — well
inside the 1 s cadence the host daemon currently runs at. The
control-plane HTTP publish rate isn't covered here (no public API
on the bridge layer); the **registry-side** rate is not the gate.

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

Two storage costs wrap every receipt: (a) **audit-log append +
`flush`** (`audit.rs:143`) — libc buffer flush, not fsync,
HMAC-chained through one mutex; (b) **receipt-journal `bump`**
(`receipt_journal.rs:164`) — full rewrite + tempfile + `sync_all`
+ rename + parent dir `sync_all`, lock held across disk I/O. The
per-receipt-signing ceiling is one journal-fsync round-trip.

**Measured** (`crates/octravpn-node/benches/settle_throughput.rs`,
same host, APFS-on-NVMe tempdir):

| Operation                                | Mean      | Implied rate                |
|------------------------------------------|-----------|------------------------------|
| `ReceiptJournal::bump` (1 session)       | 10.4 ms   | 96 signed receipts/s/node    |
| `ReceiptJournal::bump` (64 sessions)     | 9.88 ms   | 101 receipts/s/node          |
| `ReceiptJournal::bump` (1 024 sessions)  | 11.7 ms   | 85 receipts/s/node           |
| Audit append + `flush()` (libc)          | 2.41 µs   | 414 k lines/s (~143 MiB/s)   |
| Audit append + `sync_all()` (real fsync) | 4.89 ms   | 204 lines/s                  |

Two findings worth flagging:

- **Receipt-signing ceiling is ~100/s/node** on this storage,
  set by the journal's tempfile + rename + double fsync per call
  (`receipt_journal.rs:269-286`). The 1 024-session run is only
  ~15% slower than the 1-session run, so the per-bump-rewrite cost
  of the (small) journal is irrelevant — the fsync round-trip
  dominates. Networked storage will be worse.
- **Audit-log flush-vs-fsync gap is ~2 000×.** `audit.rs:143` calls
  `flush()` which is libc buffer flush, sub-3 µs per line. Upgrading
  to `sync_all` would cap audit-log lines at ~200/s and collapse
  signed-receipts/s by an order of magnitude on a busy operator.
  That's an intentional trade — the journal carries the
  fault-tolerance guarantee for the slashable invariant
  (receipt_journal.rs:1-36); the audit log is best-effort forensics.

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

**Measured** — *poll-overhead component only*. The full `connect`
path can't be cleanly benched (binary-crate `pub(crate)` API +
ctrl-c-driven shutdown). The bench reproduces the verbatim backoff
schedule from `runner.rs:311-336` against an in-process mock that
flips "ready" after a configurable target delay. Bench:
`crates/octravpn-client/benches/cold_connect.rs`, same host.

| Target chain-finality delay | Observed wall-clock | Poll overhead |
|------------------------------|---------------------|---------------|
| 0 ms (instant)               | 49.5 ns             | 0             |
| 1 000 ms                     | 1 510 ms            | +510 ms       |
| 5 000 ms                     | 5 130 ms            | +130 ms       |
| 10 000 ms (mainnet epoch)    | 11 140 ms           | +1 140 ms     |

Bounded overhead: at the steady-state cap of 2 s between polls, the
worst-case extra wait between "tx finalized" and "client observes
`SessionOpened`" is ≤ 2 s. The 0 ms case isolates the in-process
overhead at ~50 ns. The remaining wall-clock budget for a v2 connect
on mainnet is therefore approximately `epoch (~10 s) + ≤2 s poll +
HTTP RTT (announce) + WG handshake (29 µs ECDH, negligible)`.

## 7. Cryptography costs

Per-primitive criterion benches live in
`crates/octravpn-core/benches/core.rs` (covers receipt sign/verify,
pedersen + earnings commit/open, onion build/peel, tx canonical +
sign, wallet enc/dec at 1 k PBKDF2 iters — production uses 200 k).

**Committed snapshot**: `bench-snapshots/core.json` (host: Darwin
arm64 / Apple M3 Max / macOS 26.1, release build, criterion
`--sample-size 20 --warm-up-time 1 --measurement-time 2`):

| Primitive                  | Mean      |
|----------------------------|-----------|
| `receipt_build_sign`       | 22.3 µs   |
| `receipt_verify_dual`      | 58.0 µs   |
| `pedersen_commit`          | 41.8 µs   |
| `pedersen_verify_open`     | 42.0 µs   |
| `earnings_commit`          | 36.7 µs   |
| `earnings_verify_claim`    | 36.1 µs   |
| `onion_build_3hop`         | 125 µs    |
| `onion_peel_layer`         | 31.7 µs   |
| `tx_canonical_bytes`       | 1.81 µs   |
| `tx_sign_call`             | 14.7 µs   |
| `wallet_encrypt_1k_iters`  | 292 µs    |
| `wallet_decrypt_1k_iters`  | 299 µs    |

Re-run with `cargo bench -p octravpn-core --bench core --release`.
A CI diff against the committed JSON is a separate ticket. AES-GCM
on sealed assets isn't a standalone primitive here — the wallet
path covers PBKDF2 + AES-GCM; sealed-asset throughput per-circle is
bounded by the 4 KiB AML cap (§8) before it hits the cipher.

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
fsync rate ~100 ops/s (§5,
`crates/octravpn-node/benches/settle_throughput.rs`); audit-log
flush 414 k lines/s (same bench).

## Suspected limits not yet measured

- End-to-end WG Mbps with two real `Tunn` instances on loopback.
  Primitive ceilings are §1; live-tunnel numbers would require
  exposing `Tunn`-construction past `octravpn-node`'s private API.
- Per-wallet chain-tx throughput under sustained submit (nonce
  serialization vs `pending_nonce` race) — requires a real or
  mocked chain at scale; not in this bench batch.
- AES-GCM throughput on sealed-asset put/get (covered indirectly
  via the wallet-enc bench, not as a standalone primitive).
- PBKDF2 wallet-decrypt latency at the production 200 k iterations
  (bench only covers 1 k for sub-second runs; extrapolate × 200).
- Audit-log throughput against `AuditLog` itself (the type is
  `pub(crate)`; this PR benches the underlying primitive). Same
  shape applies to `connect`-path full wall-clock.

## What we know vs. what we assume

**Measured**: §§1–3, 5–7 (each section cites its bench file:line
above); plus epoch length (`docs/octra-research.md:15`), AML cap
(`memory/octra_aml_string_cap_4kb.md`), poll backoff
(`runner.rs:311-333`).

**Extrapolated** (number derives from a measured one plus chain rule):
- "≥1 epoch per settle per wallet" — epoch length + nonce serialization.
- WG relay-hop ~1.2 Gbps/core (~270 Mbps with onion) — §1 primitives
  × packet count, not a live tunnel.
- Birthday bounds at member counts beyond `ip_alloc.rs:229-294`.

**Assumed** (we have a story but no number):
- Real WG-over-UDP throughput (kernel scheduler, NIC offload, MTU).
- AML `fhe_*` runtime cost on chain — moot until the chain-side
  bridge is wired (`memory/octra_aml_fhe_load_pk_blocked.md`).
