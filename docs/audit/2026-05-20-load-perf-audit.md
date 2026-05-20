# Load + Performance Audit — Tier 2 Pre-Launch

> **Scope:** doc-only Tier 2 production-readiness audit. Needed before
> launch announcement, not strictly before code-freeze.
> **Commit:** `11f83a198b7b04e5a79ebc00a238d7326888337a`
> **Snapshot host:** Apple M3 Max / macOS 26.1 / arm64 / Darwin 25.1.0,
> `cargo --release`, APFS-on-NVMe tempdir.
> **Bench infra:** `crates/octravpn-{core,node,mesh,client}/benches/*.rs`
> (criterion) + `scripts/bench-regression.sh` (5% gate per #244).
> **Snapshot:** `bench-snapshots/core.json` (committed 2026-05-19).
> **Existing perf-limits doc:** `docs/performance-limitations.md`
> (referenced throughout; this audit adds attack-mode + capacity-planning
> + middleware-overhead views the limits doc does not cover).

This audit reads the existing bench data, code-side bounds, and the
prior concurrency audit (`2026-05-20-concurrency-error-config-audit.md`,
hereafter "Audit-2"); it does **not** spin up a live cluster. Every
extrapolation is flagged with the source bench and the multiplier.
Where a measurement requires a tool we don't ship (`wrk`, `hey`, full
`AuditLog` throughput), the gap is documented + the closest in-repo
proxy is named.

---

## 1. Executive summary

| Severity      | Count | Topic                                                                                       |
|---------------|-------|---------------------------------------------------------------------------------------------|
| BLOCK-LAUNCH  | **1** | Audit-log batched flusher uses unbounded `mpsc` (Audit-2 C-6 / OOM-3 below)                 |
| HIGH          | 2     | Receipt-journal `EveryWrite` policy caps signed-receipts at ~225/s/node; PVAC shadow path is +900 µs/receipt under HFHE-2 (vs the 0.35% headline) |
| MEDIUM        | 3     | `MachineRegistry` COW write is O(N) (rotation-storm ceiling ~6500/s @ 10k peers); HFHE-2 sidecar IPC adds 2× `encrypt_const` + 1× `make_zero_proof` per receipt; bench thresholds.json has 9 overrides already eating perf-regression headroom |
| LOW           | 3     | 23/37 orphan `tokio::spawn`s (Audit-2 C-10) prevent clean drain; rate-limit map allows 10k keys × 4 classes = 40k buckets; circle-sealed-asset cipher path bound by AML 4 KiB cap |

**One launch-blocker** (Audit-2 C-6 with attack-mode capacity sums in §7):
the audit flusher's unbounded mpsc grows without bound when the disk
stalls or under sustained burst. At the audit-append `flush()` rate of
414 k lines/s (`settle_throughput.rs`) and the 200–300 B per `FlusherCmd`
heap shape, a one-second flusher stall queues ~100 MB; a minute is
~6 GB; an attacker who pins the disk fills RAM in tens of minutes. No
LRU eviction, no back-pressure. Fix is one-line per Audit-2 ("bounded
4096 + sync-fallback").

---

## 2. Latency results (committed snapshot)

All numbers from `bench-snapshots/core.json` and the two perf benches
shipped in `crates/octravpn-node/benches/`. p50/p95/p99 columns are
**criterion mean ± CI** rather than full quantiles; criterion's
`--sample-size 20 --warm-up-time 1 --measurement-time 2` config does
not emit full p99 (a deliberate cap-noise trade — see
`scripts/bench-regression.sh:13`). The p95 column is approximated as
`ci_upper_ns`; p99 is **extrapolated** as `mean × 1.10` based on the
quick-mode variance overrides in `bench-snapshots/thresholds.json`
(median 10–15 %). Where the extrapolation matters (e.g. signed-receipts
under load), the §3 throughput ceiling is the authoritative bound.

| Critical path                              | p50 (mean) | p95 (ci_upper) | p99 (extrapolated, ×1.10) | Source |
|--------------------------------------------|------------|----------------|---------------------------|--------|
| `receipt_build_sign`                       | 22.25 µs   | 22.40 µs       | ~24.5 µs                  | core.json |
| `receipt_verify_dual`                      | 57.96 µs   | 58.11 µs       | ~63.8 µs                  | core.json |
| `pedersen_commit`                          | 41.98 µs   | 42.19 µs       | ~46.2 µs                  | core.json |
| `pedersen_verify_open`                     | 42.20 µs   | 42.38 µs       | ~46.4 µs                  | core.json |
| `earnings_commit`                          | 36.91 µs   | 37.04 µs       | ~40.6 µs                  | core.json |
| `earnings_verify_claim`                    | 36.20 µs   | 36.29 µs       | ~39.8 µs                  | core.json |
| `onion_build_3hop`                         | 125.5 µs   | 125.8 µs       | ~138 µs                   | core.json |
| `onion_peel_layer`                         | 31.74 µs   | 31.92 µs       | ~34.9 µs                  | core.json |
| `tx_canonical_bytes`                       | 1.81 µs    | 1.81 µs        | ~2.0 µs                   | core.json |
| `tx_sign_call`                             | 14.84 µs   | 14.96 µs       | ~16.3 µs                  | core.json |
| `wallet_encrypt_1k_iters` (×200 prod)      | 291.5 µs (1 k) → ~58.3 ms (prod) | — | ~64 ms | core.json + ×200 extrap |
| `wallet_decrypt_1k_iters` (×200 prod)      | 299.3 µs (1 k) → ~59.9 ms (prod) | — | ~66 ms | core.json + ×200 extrap |
| `ReceiptJournal::bump` EveryWrite, 1 sess  | 4.26 ms    | —              | —                         | settle_throughput.rs #235 numbers |
| `ReceiptJournal::bump` EveryWrite, 1024    | 4.44 ms    | —              | —                         | settle_throughput.rs |
| `ReceiptJournal::bump` Periodic, 1 sess    | 1.92 µs    | —              | —                         | settle_throughput.rs |
| Audit append + `flush()` (libc)            | 2.41 µs    | —              | —                         | settle_throughput.rs |
| Audit append + `sync_all()` (real fsync)   | 4.89 ms    | —              | —                         | settle_throughput.rs |

PVAC sidecar `encrypt_const` is documented at **~200 µs round-trip**
(`control.rs:1058-1069`); zero-proof is **~500 µs**. Both are
out-of-process IPC over the FIFO, not in the criterion suite. See §6
for the HFHE-2 finding.

---

## 3. Throughput ceilings (max RPS per endpoint)

The control plane runs `axum 0.7` over `tokio 1.x` on a per-Hub
runtime. None of the endpoints below have a live `wrk`/`hey` number
in-repo; the table below is **single-core analytic ceiling = 1 / handler
hot-path µs**, with the dominant cost cited. Real ceilings will be
lower by tokio scheduling, TLS, and the rate-limit middleware (see §6).

| Endpoint                       | Hot-path dominant cost      | Single-core analytic ceiling | Rate-limit class default (rps / burst) | Notes |
|--------------------------------|-----------------------------|------------------------------|----------------------------------------|-------|
| `POST /admin/preauth`          | bearer-check + minter mint (`headscale_bridge/preauth.rs:235`) — sub-µs | **>100 k RPS/core** (analytic) | preauth: 60 / 120 | **highest-RPS endpoint by analytic ceiling**. The per-IP token-bucket caps at 60 sustained / 120 burst per IP, so the realistic per-IP ceiling is the bucket itself. Cluster-wide it's gated by the in-memory `PreauthMinter` map which is `BoundedMap`-backed. |
| `POST /session` announce       | `receipt_build_sign` 22 µs + journal bump | EveryWrite: ~**225 RPS/node**; Periodic: ~**500 k RPS/node** | receipt: 60 / 120 per IP | Journal fsync dominates at default policy. Per `settle_throughput.rs:46-52`. |
| `GET /session/:id` state       | `BoundedMap::get` + serialize | ~**500 k RPS/core** (analytic) | receipt: 60 / 120 | Read-only; not a launch-gating ceiling. |
| `GET /events` (SSE)            | broadcast subscriber + serialize | bounded by `EventBus::new(256)` capacity (`control.rs:401`) | **bypassed** (`router.rs:73-75`) | One stuck consumer drops events at 257; no OOM risk. |
| `GET /health`                  | atomic-load + format         | ~**1 M RPS/core**             | **bypassed** (`rate_limit.rs:89`)      | Always responds under load. |
| `GET /metrics`                 | format the metric block      | ~**100 k RPS/core**           | **bypassed** + bearer-gated            | Scrape interval; never hot. |
| `POST /machine/.../map` (Tailscale-wire long-poll) | `MachineRegistry::snapshot` (1 Arc-clone) + `Notify::notified` wait | bounded by `keepalive_interval = 30 s` (`headscale-api/src/tailscale_wire/map.rs:27`) | (no class; `Other` defaults 60/120) | See §6 + OOM-2. Wake-up latency from `notify_waiters()` is <100 µs (Notify is a futex). |

**Sustained 1000 concurrent preauth-mint** (the scope's first scenario):
the analytic ceiling allows it on one core, but the **per-IP rate
limit caps 1000 distinct clients at 1000×60 = 60 k mints/s sustained**;
1000 mints from one IP collapses to 60 RPS sustained after the 120-burst
drains. **Closest available load gen:** `wrk -t 8 -c 1000 -d 60s
-H 'Authorization: Bearer …' --latency http://<node>:8080/admin/preauth`
or `hey -n 60000 -c 1000 -H …`. Neither is shipped; both are
`brew install`-grade. Bench substitute: the criterion suite has no
HTTP-layer bench because every route is on `pub(crate)` state.

**Sustained 1000 sessions × 10 receipts/sec = 10 k receipts/s**: the
EveryWrite ceiling is ~225/s per node, so a single node **cannot** sustain
this; the deployment shape assumes **44+ nodes** (10000/225) or
**`FsyncPolicy::Periodic`** mode (which collapses to ~2 µs/bump). The
`set_fsync_policy` knob is on the `ReceiptJournal` itself
(`receipt_journal.rs:346`); operators flip it via the config block, not
runtime. See §9 recommendation #2.

**Sustained 100 long-pollers on `/machine/map` with 1s updates**: the
`MachineRegistry::upsert` path is `RwLock<Arc<HashMap>>` (mod.rs:282)
— O(N) clone of the whole map per write. At 1000 peers each at ~512 B,
one clone is ~150 µs (Audit-2 C-9). With one writer/sec the wake-up
cost is 100 × `notify_waiters()` (which is a `Notify` notify-all, sub-µs)
+ 100 × snapshot-Arc-clone (sub-µs each). Total wake-up budget: <200 µs.
**Caveat:** Audit-2 C-9 notes this ceilings the registry at ~**6500
writes/s at 10 k peers** — a rotation-storm bound, not a steady-state
bound.

---

## 4. Memory profile

### 4.1 Steady-state

| Subsystem                         | Per-unit shape                          | Steady-state @ 1000 active sessions |
|-----------------------------------|-----------------------------------------|--------------------------------------|
| `BoundedMap<SessionId, ControlSession>` (`control.rs:80`) | 32 B key + ~256 B `ControlSession` | ~290 KB |
| `MachineRegistry` (1000 peers)    | ~512 B/record, 1 Arc holder + Notify    | ~512 KB                              |
| `ReceiptJournal` in-mem `BTreeMap<SessionId, u64>` | 32 B + 8 B + ~48 B overhead | ~88 KB |
| `RateLimiter` buckets (1000 IP × 4 classes) | ~64 B/bucket | ~256 KB                              |
| `PreauthMinter` (live + redeemed) | bounded by `with_capacity` (default 1024 entries) | ~256 KB |
| `EventBus` broadcast (capacity 256) | per-event payload | <1 MB                               |
| `AuditLog` flusher in-flight buffer | unbounded mpsc + `parking_lot::Mutex<Inner>` | **unbounded** (OOM-3) |
| Tokio runtime + axum + boringtun crypto state | per-tunnel `Tunn` ~16 KB | ~16 MB (1000 tunnels) |
| **Total RSS estimate (steady)**   |                                         | **~20–50 MB** without analytics |

### 4.2 24-hour run (extrapolated; no 24h real run shipped)

**Caveat — extrapolation method.** We have **no 24h soak number in
this repo.** The closest available signal is the `BoundedMap` TTL
(`CONTROL_SESSION_TTL = 3600s`) and `CONTROL_SWEEP_PERIOD = 60s`
(`control.rs:63-66`): every hour, stale `ControlSession` entries are
evicted. At 1000 sess/s churn the BoundedMap stays at cap (10 000),
~3 MB. Over 24 h the `AuditLog` on disk grows linearly with traffic
(no rotation in the current code path — `audit/inner.rs` opens a single
`audit-<ts>.jsonl` file at boot). At a sustained 100 receipts/s, the
disk is the long-pole, not memory: 100 × 86400 × ~300 B = ~2.5 GB/day.

**Recommended abbreviated form:** `docker-compose up -d` the testnet
profile (`docker-compose.testnet.yml`), drive with a 1 h Python driver
(no driver shipped — operator would write one against
`POST /admin/preauth` + `POST /session`), then extrapolate ×24 with the
following multipliers from the table above (each line is linear in
time at steady-state). Document the actual run in `docs/audit/runs/`.

### 4.3 Attack mode (the dangerous numbers)

| Attack                                              | Bound                                      | Time to OOM @ 1 GB / 16 GB |
|-----------------------------------------------------|--------------------------------------------|----------------------------|
| **Audit-flusher backpressure** (1M malformed audit emits queued during disk stall) | **unbounded mpsc** (Audit-2 C-6) | At 300 B/cmd, **3.5 M cmd → 1 GB**; at 414 k cmd/s sustainable audit rate (`settle_throughput.rs`) → **~8 s to 1 GB**, **~130 s to 16 GB** |
| 1M malformed preauth POSTs (1 KB body each)         | per-conn buffers ephemeral; rate-limiter LRU caps `(IP, class)` map at 10 000 keys (`rate_limit.rs:229`) — when full, oldest evicted | rate-limiter map: ~640 KB peak; per-conn axum bodies discarded post-decode → bounded by tokio's accept loop, not handler |
| 100 k receipts/s announce flood (forged sigs)       | sig verify cost (`receipt_verify_dual` 58 µs) on 1 core = ~17 k/s ceiling; flood is **CPU-bound** before it's RAM-bound | Steady RAM unchanged; CPU-pinned attacker = 100% one core per ~17 k req/s. |
| 1M long-poll connections on `/machine/map`          | each connection: 1 tokio task + 1 `Notify::notified` waiter | At ~4 KB per task + waker, **1M conns → ~4 GB**. Notify is O(1) on wake. **No per-conn cap exists** in `headscale-api/.../map.rs` — see OOM-4. |
| AML `fhe_load_pk` revert spam                       | n/a — handled on chain, not on node       | irrelevant for node RAM |

---

## 5. Cold-start breakdown

### 5.1 `cargo build --release` (fresh)

**Not measured in this audit.** The repo has **427 resolved crates**
(`docs/audit/dependency-audit.md:24`) and **542 packages in `Cargo.lock`**
(`grep -c '^\[\[package\]\]'`). Rough reference points from the
ecosystem:

- A 400-crate Rust workspace with `tokio` + `axum` + `rustls` + `boringtun`
  + a custom AML compiler (`crates/octra-circle-sim`) + curve25519-dalek
  + heavy proc-macros (`serde`, `clap`) typically takes **6–12 min on
  Apple M3 Max / 8C release**, **15–25 min on a 4-core x86 CI box**.
- Hot dep chains: `rustls`/`ring` (assembly), `curve25519-dalek`
  (multi-arch backends), `aws-lc-rs` (LLVM bitcode), and **most of
  all** `headscale-api` (sibling repo, pulled in via path dep at
  `crates/octravpn-mesh/Cargo.toml:23`). Any change to `headscale-api`
  invalidates the entire `octravpn-mesh + octravpn-node` build graph.
- `cargo deny check` + `cargo audit` (CI gate per
  `docs/audit/dependency-audit.md`): ~30 s after build.

**Recommended capture before launch:**
```sh
git clean -xfd && time cargo build --release -p octravpn-node 2>&1 | tee /tmp/build.log
cargo build --release --timings   # writes target/cargo-timings/cargo-timing-*.html
```
`--timings` is the right tool to identify the long-pole crates; commit
the HTML to `docs/audit/runs/` once captured.

### 5.2 `octravpn-node run` startup

Tracing `info!` markers on the boot path (`hub.rs`):

1. `tracing::info!("loading config from ...")` — TOML parse, <1 ms.
2. `tracing::info!("HFHE-2 shadow signer enabled (circle keys loaded)")`
   (`hub.rs:261`) — only if `[pvac].enabled = true`. Loads two on-disk
   keys + initializes the PVAC sidecar IPC pipe. ~10–50 ms (pvac
   subprocess spawn + FIFO open).
3. `tracing::info!("pvac sidecar spawned (HFHE path enabled)")` —
   sidecar handshake (`hub.rs:184`). One round-trip ~200 µs over the
   FIFO. Total sidecar spawn budget: ~30–80 ms (process fork + ld.so).
4. `tracing::info!(?listen, "tunnel listening")` (`hub/spawn.rs:63`) —
   bind UDP socket. Sub-ms.
5. `tracing::info!(files = scans.len(), "analytics: replayed audit log
   at boot")` (`hub/spawn.rs:224`) — replays last `audit-<ts>.jsonl`
   under HMAC verification. **Largest single contributor on a node
   with a long-running audit log:** verification re-runs HMAC-SHA256
   over every line. At 100 receipts/s × 86400 s/day × N days, the
   replay budget is ~1 ms per 100 lines. **A 30-day node with 100
   receipts/s of audit traffic replays ~260 M lines = ~26 s of
   HMAC-chain replay at boot.**
6. Final `info!` at `hub/spawn.rs:372` — the moment to treat as "control
   plane ready". Total cold-start budget on a fresh node: **<1 s**.
   On a 30-day-old node: **~30 s, dominated by audit-log replay**.

**Single biggest contributor:** audit-log replay at boot
(`hub/spawn.rs:224`). Recommendation #6 in §9 covers the rotation gap.

---

## 6. Hot-path overhead per middleware

Numbers below are µs-per-request added by each layer over the bare
handler. All from code inspection — no `axum` benchmark in-repo. The
overhead cost is the cost the request pays even on the happy path
(token available, bearer valid).

| Middleware / step                | Per-request overhead | Source              |
|----------------------------------|----------------------|---------------------|
| **Rate-limit layer** (per-IP token bucket) | ~150–300 ns (one `Mutex<HashMap>` lock + 4-element linear scan over policies + token math) | `rate_limit.rs:249-287` |
| **Bearer-token check** (`/admin/preauth`)  | ~100 ns (constant-time compare on hex string) | `preauth.rs:64` + `core/src/bearer.rs` |
| **Knock** (if `[knock].enabled = true`)    | ~200 µs — HMAC-SHA256 over the knock packet | `mesh/src/knock.rs` |
| **`tracing::info!` macro on cold path**    | ~100 ns at default filter (no allocation when filtered) | tokio-tracing 0.1.x semantics |
| **Audit `write_async` emit per receipt**   | ~1 µs (channel send) + amortized fsync (1/64 records = ~76 µs/record at 4.89 ms fsync) | `audit/batched.rs:68` + `settle_throughput.rs` |
| **HFHE-2 shadow-blob emission** (`[pvac].enabled = true`) | **~900 µs** per receipt = 2× `encrypt_const` (200 µs each) + 1× `make_zero_proof` (~500 µs) | `control.rs:1058-1123` |

**HFHE-2 verification of the "0.35%" claim.** The claim is in PR thread,
not in `control.rs`. Source-of-truth: receipt build-sign is **22 µs**
(core.json `receipt_build_sign`). HFHE-2 adds 2× `encrypt_const` (200 µs
each per docstring at `control.rs:1058`) + 1× `make_zero_proof` (~500 µs).
Total added on the **receipt-build hot path** is **~900 µs** — i.e.
**40× the bare-receipt cost, ~+4000% in absolute receipt latency**,
which is the opposite of 0.35%. The 0.35% headline is plausible
**only when measured against full session lifetime** (open-session
+ 10s epoch wait + WG handshake), where 900 µs is indeed ~0.0001× the
~10 s denominator. **Verify which denominator the headline used.**
If the answer is "full mainnet connect", 0.35% may be correct but
misleads for steady-state settle throughput.

**Fsyncs per second under steady-state.** With `DEFAULT_BATCH_SIZE = 64`
and `DEFAULT_BATCH_INTERVAL_MS = 100`, the audit flusher fsyncs
**`max(traffic/64, 10) fsync/s`** — at 100 receipts/s → batch fills
hit at ~1.5 fsync/s; at 100 k receipts/s → 1562 fsync/s, well above
the SSD's ~200 sync_all/s ceiling. The flusher pattern is correct;
**the SSD becomes the gate**, not the lock. **The interval-driven
floor is 10 fsync/s even with no traffic** — fine on local SSD,
noticeable on network FS.

---

## 7. OOM-bound register

| ID    | Collection                                            | Bound today                                | Worst-case RAM (attack)         | Source                         |
|-------|-------------------------------------------------------|--------------------------------------------|---------------------------------|--------------------------------|
| OOM-1 | `ReceiptJournal.by_session: BTreeMap<SessionId, u64>` | **none** (one entry per session ever seen) | 1M sess × 88 B = ~88 MB; 100M sess = ~8.8 GB | `receipt_journal.rs:204` |
| OOM-2 | `MachineRegistry inner: RwLock<Arc<HashMap>>`          | **none** at the type; bounded by registration auth | 100k machines × 512 B = ~50 MB; 10M = ~5 GB | `headscale-api/.../tailscale_wire/mod.rs:282` |
| OOM-3 | Audit flusher mpsc                                    | **unbounded**                              | At 414 k events/s and 300 B/cmd: **125 MB/s of queue growth when flusher stalls** → 1 GB in 8 s, 16 GB in 130 s | `audit/batched.rs:49`; Audit-2 C-6 |
| OOM-4 | `/machine/map` long-poller tokio tasks                | **no per-IP cap**                          | 1M conns × ~4 KB task = ~4 GB | `headscale-api/.../tailscale_wire/map.rs` (no per-conn limit) |
| OOM-5 | `RateLimiter inner: HashMap<(IP, class), Bucket>`     | `max_keys = 10 000` (LRU evict)            | ~640 KB — **bounded**           | `rate_limit.rs:229` |
| OOM-6 | `BoundedMap<SessionId, ControlSession>` (`/session`)  | `CONTROL_SESSIONS_CAP = 10 000`, TTL 1 h   | ~3 MB — **bounded**             | `control.rs:59-63` |
| OOM-7 | `EventBus broadcast::channel(256)`                    | cap 256 events                             | ~per-event payload — **bounded** | `control.rs:401` |
| OOM-8 | `PreauthMinter` (live + redeemed)                     | `with_capacity` (default 1024) + TTL       | ~256 KB — **bounded**           | `preauth.rs:193` |
| OOM-9 | Analytics tap `mpsc::UnboundedSender<AnalyticsEvent>` | **unbounded**                              | Same shape as OOM-3 but lower rate; minutes to GB | `audit/tap.rs:21` |

**Biggest memory hog under attack:** OOM-3 (audit flusher mpsc) — the
**only one** that can fill 16 GB in ~2 min from a single IP under flood,
because the flood path goes through unbounded channel send before any
token bucket. OOM-1 (receipt journal in-mem) is the next worst at
steady-state with no malicious driver: every session that ever opens
on the node lives in the BTreeMap until process restart.

---

## 8. Capacity-planning table

The expected mainnet shape (per `docs/economics.md` + cluster
assumptions): N operator nodes, each carrying 1–10 k client sessions.
Receipt cadence per session is **one per epoch (~10 s)** on the chain
hot path, not "one per 100 ms" as a control-plane unit test would
suggest. So a single node at 1 k sessions handles ~100 receipts/s —
**right at the EveryWrite ceiling** of 225/s/node.

| Expected mainnet load        | Recommended hardware (per node)                          | Gate                                         |
|------------------------------|----------------------------------------------------------|----------------------------------------------|
| **100 sess/node, ~10 rec/s** | 1 vCPU, 1 GB RAM, NVMe-backed disk                       | none — bench ceiling is 22×                  |
| **1k sess/node, ~100 rec/s** | **2 vCPU, 2 GB RAM, NVMe SSD** (~225 rec/s journal limit) | journal fsync                                |
| **10k sess/node, ~1k rec/s** | **4–8 vCPU, 4 GB RAM, NVMe + `Periodic(1s)`**            | journal fsync — **must** flip Periodic policy |
| **100k sess/node, ~10k rec/s** | **16 vCPU, 16 GB RAM, NVMe**, `Periodic`, +monitoring on OOM-3 channel depth | audit-flusher OOM-3 + CPU sig-verify         |

**Recommended mainnet hardware for a 10 k-session node (the realistic
operator default):** **4 vCPU, 4 GB RAM, NVMe SSD (≥3 k IOPS sustained)**,
with `[node.receipt_journal].fsync_policy = "periodic"` and audit
flusher's mpsc fixed (Audit-2 C-6).

**Network**: ≥100 Mbps symmetric per ~270 Mbps onion-peel-per-core; the
node is **not** the bottleneck below 1 Gbps (boringtun primitive ceiling
~1.2 Gbps/core, `docs/performance-limitations.md:53`).

---

## 9. Recommendations (ranked by perf-impact)

1. **[LAUNCH-BLOCK] Bound the audit-flusher mpsc.** Replace
   `mpsc::unbounded_channel()` at `audit/batched.rs:49` with
   `mpsc::channel(4096)`; add a sync-fallback write when send fails so
   audit records degrade to in-band fsync rather than vanish. Verbatim
   Audit-2 C-6 fix. **One-line code change; unblocks launch.** Same
   fix shape applies to OOM-9 (`audit/tap.rs:21`).

2. **[HIGH] Document + default `FsyncPolicy::Periodic(1s)` for
   non-financial operators.** The current `EveryWrite` default is
   correct for slashable-invariant nodes (the journal holds the
   receipts-monotonic invariant), but ceilings throughput at ~225/s/node
   regardless of disk. Add a `[node.receipt_journal].fsync_policy = "every_write"|"periodic"`
   config knob that operators flip explicitly. Document the loss-window
   trade in `docs/operators/`.

3. **[HIGH] Either fix the HFHE-2 0.35% headline or note the
   denominator.** ~900 µs per receipt is real and survivable, but the
   "0.35%" framing only holds if the denominator is "full mainnet
   `connect` wall-clock". If the launch announcement mentions HFHE
   without context, an auditor running `settle_throughput.rs` with the
   PVAC sidecar enabled will see receipts ~40× slower than the
   no-shadow path.

4. **[MEDIUM] Cap `/machine/map` long-pollers per IP.** Today there's
   no per-IP limit (`headscale-api/.../tailscale_wire/map.rs`). At ~4 KB
   tokio-task overhead per pending poll, 1M open polls is ~4 GB.
   Recommend a per-IP cap of ~16 in the wire-router layer (mirrors what
   real headscale ships).

5. **[MEDIUM] Refresh `bench-snapshots/core.json` against a quieter
   host and prune `thresholds.json` overrides.** Per the snapshot file's
   own `_audit_2026_05_19` note, 9 of 12 benches have permissive
   overrides eating headroom; once the recapture lands, the 5% global
   gate (#244) catches real regressions earlier. Three benches
   (`onion_peel_layer` at 30%, `receipt_verify_dual` at 25%,
   `pedersen_verify_open` at 20%) currently mask up to 30% perf loss.

6. **[MEDIUM] Add an audit-log rotation knob.** `hub/spawn.rs:224`
   replays the entire `audit-<ts>.jsonl` at boot — a 30-day node
   replays ~26 s of HMAC-chain at startup. Either rotate on size or
   ship a `replay_from_offset` flag that skips already-verified prefix
   (the chain root is preserved by `verify_file`).

7. **[LOW] Hard-cap `ReceiptJournal.by_session: BTreeMap` size.** Today
   any session ever opened on the node lives in the in-mem mirror
   forever. Either evict TTL-aged sessions when the on-disk file
   confirms last-seq, or document the **88 B/sess × lifetime** RSS
   floor. For a 1-year node with 10 M unique sessions: ~880 MB just
   for the mirror.

8. **[LOW] Inventory the 23/37 orphan `tokio::spawn`s** (Audit-2 C-10)
   and convert the top-3 RSS-impactful (`hub.rs` cluster of 6) to
   `JoinSet`. Doesn't move the perf needle on a happy path, but a
   `SIGTERM` today aborts mid-fsync — recoverable, but adds a torn-write
   risk that the `EveryWrite` policy is supposed to prevent.

9. **[LOW] Verify HFHE-2 batching opportunity.** The two `encrypt_const`
   calls per receipt (bytes_used + net) are serial-awaited in
   `control.rs:1077-1098`. Sidecar IPC supports batched requests in
   principle (the FIFO is line-delimited but the protocol has a `batch`
   verb in `pvac.rs`). Concurrent-await both would halve the per-receipt
   shadow-blob overhead from ~900 µs to ~500 µs.

---

## Notes on what this audit could **not** measure

- **Real `wrk`/`hey` against a live node.** The repo doesn't ship a
  load-gen tool; `docker-compose.testnet.yml` is suitable for an
  operator to drive, but no scripted runner. The closest in-repo
  proxy for HTTP throughput is the criterion suite + the analytic
  ceiling math in §3.
- **24h soak.** Replaced by §4.2's hour-with-multiplier-extrapolation
  recipe. The shape is linear enough at steady-state that the
  extrapolation is safer than a noisy 1-hour absolute number.
- **`cargo build --release` time.** Documented as a `--timings` run an
  operator should commit alongside this doc. The ~6–12 min range is
  ecosystem-typical for a 400-crate workspace with the deps listed.
- **PVAC sidecar IPC latency under contention.** The benches I reference
  are docstring numbers from `control.rs:1059` ("on the order of
  ~200 µs"); no microbench shipped. The right addition is a
  `pvac_bench.rs` in `crates/octravpn-node/benches/` that drives the
  sidecar through `encrypt_const` + `make_zero_proof` at 1, 10, 100, 1000
  concurrent. Out of scope for a doc-only audit.

---

## Report tags (machine-readable)

```
commit_hash:        11f83a198b7b04e5a79ebc00a238d7326888337a
highest_rps_endpoint: POST /admin/preauth (analytic >100k RPS/core; per-IP gated at 60 sustained)
biggest_memory_hog: audit-flusher unbounded mpsc (OOM-3)  — 125 MB/s queue growth on flusher stall
recommended_mainnet_hw: 4 vCPU / 4 GB RAM / NVMe SSD (≥3 k IOPS) per 10 k-session node, with FsyncPolicy::Periodic and OOM-3 fix
launch_blocker:     OOM-3 / Audit-2 C-6 — bound the audit-flusher mpsc; one-line fix
```
