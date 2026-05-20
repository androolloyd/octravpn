# OctraVPN — Concurrency / Error / Config Audit (2026-05-20)

> Auditor: concurrency-error-config audit subagent, read-only.
> Worktree `agent-ad3f9ad8e39e926b3`. HEAD `c1766fe`. Scope:
> `octra/`, `headscale-rs/`, `octra-foundry/`. Same shape as
> `2026-05-20-claims-audit.md`. NO code changes.

## Top-level summary

| Severity | Total | Concurrency | Error | Config |
| --- | ---: | ---: | ---: | ---: |
| BLOCKER | 2 | 0 | 1 | 1 |
| HIGH | 5 | 3 | 0 | 2 |
| MEDIUM | 10 | 3 | 3 | 4 |
| LOW | 7 | 3 | 2 | 2 |
| ADVISORY | 4 | 1 | 1 | 1 |
| **Total** | **28** | **10** | **7** | **10** |

Aggregate stats at HEAD: `Arc<Mutex<…>>` / `Arc<RwLock<…>>` —
`octra/crates` 24 sites, `headscale-rs` 20, `octra-foundry` 0.
`tokio::spawn` non-test in `octra/crates` 37 (23 drop JoinHandle).
`spawn_blocking` 6 (all on disk fsync — justified).
`#[non_exhaustive]` on any error enum across all 3 repos: **0**.
`#[serde(deny_unknown_fields)]` across all 3 repos: **0**.
`#[serde(default)]` in `octra/crates`: 121.

Three biggest themes: (1) lost-wake race in headscale-rs `/map`
long-poll — `Notify::notified()` only wakes already-registered
futures; the unfold loop re-registers AFTER work, the project's own
test side-steps with a 50 ms sleep. (2) Zero `deny_unknown_fields`:
typo'd fields silently get `#[serde(default)]` fallback. (3) Six
secret config fields are plain `Option<String>`, visible in `Debug`
and panic crash dumps.

---

## CONCURRENCY (11 findings)

### C-1 [HIGH] Lost-wake race in `/map` long-poll
- File: `headscale-rs/headscale-api/src/tailscale_wire/map.rs:395-419`.
- Impact: a peer registration / DNS extra-records push / policy edit
  arriving BETWEEN chunks of an in-flight `/map` long-poll is silently
  dropped — `notified()` is created AFTER the chunk processes, so
  `notify_waiters()` in that gap goes nowhere. Test at
  `map.rs:842-852` side-steps via `sleep(50ms); insert_peer`.
- Fix: arm-then-await — `let mut n = Box::pin(notify.notified());
  n.as_mut().enable();` BEFORE chunk-build, OR migrate to
  `tokio::sync::watch<u64>` (edge-triggered, race-free by design).

### C-2 [HIGH] Same lost-wake exposure on `PolicyStore` / `DnsStore`
- Files: `headscale-rs/headscale-api/src/policy/mod.rs:160-170`,
  `dns.rs:241,254,261`.
- Impact: `policy.notify().notified().await` and
  `dns.changed().await` have the same race shape as C-1. Every consumer
  (notably the `/map` poller) is exposed.
- Fix: same arm-then-await pattern, or switch to `watch<u64>`.

### C-3 [HIGH] Headscale-rs uses `std::sync::RwLock + .unwrap()` in 3 hot files
- Files: `headscale-rs/headscale-api/src/gateway/auth.rs:71,76,82,95,103`;
  `headscale-rs/headscale-api/src/control_auth.rs:4`;
  `headscale-rs/headscale-core/src/swarm_transport.rs:16,254,277,302,335`.
- Impact: `std::sync::RwLock::write().unwrap()` panics on `PoisonError`;
  a panic anywhere in the lock-holding path propagates and kills the
  process. The rest of the workspace uses poison-free `parking_lot`.
- Fix: convert these three files to `parking_lot::RwLock`. Drop-in
  replacement, no `.unwrap()` needed. Workspace already pulls in
  `parking_lot` via `octravpn-core`.

### C-4 [MEDIUM] `Arc<Mutex<HashMap>>` rate-limiter is one global lock
- File: `octra/crates/octravpn-node/src/rate_limit.rs:200`.
- Impact: every control-plane request takes the same
  `parking_lot::Mutex` to charge a token. Critical section ~100ns but
  the eviction path (`m.keys().next()` — O(n)) at line 265 amplifies
  the worst case under abuse.
- Fix: `dashmap::DashMap<BucketKey, Bucket>` — shards across N internal
  locks, preserves the `.entry().or_insert_with()` semantics. Or a
  fixed array of sharded `parking_lot::Mutex<HashMap<…>>` keyed by
  `hash(ip)`.

### C-5 [MEDIUM] 9 instances of `Arc<RwLock<HashMap>>` in older headscale-rs crates
- Files: `headscale-resources/src/{metering,registry}.rs`,
  `headscale-payments/src/{ledger,channels,escrow}.rs`,
  `headscale-core/src/{mesh,metering}.rs`,
  `headscale-api/src/{admin/users,gateway/inference}.rs`.
- Impact: legacy pattern that `MachineRegistry` (#238) replaced with
  the COW `RwLock<Arc<HashMap>>` shape. Each is a per-write contention
  hot-spot.
- Fix: convert to COW. The `update_with` helper at
  `tailscale_wire/mod.rs:351-364` is the template. For
  writes-dominant tables (ledger), `arc-swap::ArcSwap` lowers reads.

### C-6 [MEDIUM] Audit-log batched flusher uses unbounded mpsc
- File: `octra/crates/octravpn-node/src/audit.rs:179`.
- Impact: under sustained burst the channel grows without bound; a
  flusher stall (slow disk, IO error spam) → unbounded RSS. The
  flusher lock pattern itself is sound — `parking_lot::Mutex` held
  only across sync `write_inner_direct`, never across `.await`. The
  doc-comment (L131) argues for unbounded to preserve audit↔analytics
  correlation under burst; the OOM failure mode loses everything.
- Fix: `mpsc::channel(4096)` with degrade-to-sync-fallback on send
  error so audit records never silently vanish.

### C-7 [MEDIUM] PVAC sidecar IPC: partial-line recovery clean, drift handling silent
- File: `crates/octravpn-node/src/pvac.rs:698-706`.
- Impact: brief asked about partial JSON + crash. Verified clean —
  `BufReader::read_line` returns the partial line, `from_str` fails
  on the FIFO head, next read returns 0 → `stdout EOF` →
  `Incarnation::Crashed` → respawn. BUT the unsolicited-response path
  only logs `warn!`; a misbehaving sidecar surfaces as restart spam.
- Fix: log unsolicited-response at `error!` + bump a metric.

### C-8 [LOW] Receipt-journal rename atomicity is POSIX-safe, NOT overlayfs-safe
- File: `crates/octravpn-core/src/receipt_journal.rs:616`.
- Impact: `fs::rename` is atomic within a dir on ext4/xfs; the
  parent-dir fsync at 619-623 is correct. On aufs/overlayfs (some
  container runtimes), rename is NOT atomic. Operators running
  receipts.bin on a container overlay are exposed.
- Fix: doc-note "bind-mount to host ext4/xfs". Optional EBUSY retry.

### C-9 [LOW] `MachineRegistry` COW write cost is O(N) per upsert
- File: `headscale-rs/headscale-api/src/tailscale_wire/mod.rs:298-364`.
- Impact: every `upsert`/`update_with` clones the full HashMap. For
  10k machines @ 512B, a clone is ~150µs — caps registry at ~6500
  writes/s. Fine steady-state; matters during rotation storm.
- Fix: document the ceiling. If a future deploy needs more, switch to
  `arc-swap::ArcSwap<im::HashMap<…>>` (`im::HashMap` is persistent /
  structural-sharing — O(log N) clone).

### C-10 [LOW] 23 of 37 `tokio::spawn` sites drop the JoinHandle
- Clusters: `crates/octravpn-mesh/src/magic_dns.rs` (3),
  `crates/octravpn-client/src/portal/{routes,chain}.rs` (7),
  `crates/octravpn-node/src/hub.rs` (6).
- Impact: orphan tasks not cancelled on Hub shutdown. Runtime aborts
  them on `Runtime::drop` — fine for the "kill" path, precludes a
  clean drain-then-stop. SIGTERM today aborts in-flight HFHE
  encrypts / receipt-sign mid-future.
- Fix: `JoinSet` per top-level subsystem (Hub, Portal, Mesh). Spawn
  via `joinset.spawn(…)`; shutdown via `joinset.shutdown().await`
  (graceful budget) or `abort_all()`.

### C-11 [ADVISORY] `parking_lot::Mutex` across `.await` — clean
- Verification: scanned every `parking_lot::{lock,read,write}` call in
  `octra/crates` for a following `.await` within ~20 lines. Every
  suspicious site (`tunnel.rs:174,181`, `runner.rs:241-253`,
  `circle_update.rs:1451+`, `sim.rs:115`, `magic_dns.rs:93+`) drops
  the guard at end-of-statement OR the function is sync. Pattern is
  fragile though — one accidental `let g = …; expr.await;` edit
  deadlocks.
- Fix: enable `clippy::await_holding_lock` in `workspace.lints`.

---

## ERROR HANDLING (7 findings)

### E-1 [BLOCKER] Zero `#[non_exhaustive]` on any public error enum
- Files: every `thiserror::Error` enum:
  `octravpn-core/src/{onion,receipt,receipt_journal,v3_members,
  v3_policy,v3_state_root}.rs`,
  `octravpn-node/src/{pvac,circle_update}.rs`,
  `octravpn-mesh/src/{headscale_bridge,knock,lib,stun}.rs`.
- Impact: any external crate (or future workspace member) that pattern
  matches on these enums hits a compile error the moment a new variant
  lands — a breaking change to the public API. The audit-log
  `VerifyError` and journal `JournalError` are the most likely to grow
  variants (new corruption modes, format versions).
- Fix: add `#[non_exhaustive]` to every public error enum. One-line
  diff per file. Confirm no in-workspace exhaustive matches on a
  sibling crate's enum break (a couple of test sites do — they need
  wildcard arms).

### E-2 [MEDIUM] `anyhow::Error` crosses public API boundaries
- Files: `crates/octravpn-node/src/audit.rs` (every pub method);
  `crates/octravpn-mesh/src/serve.rs` (`pub fn serve(…) ->
  anyhow::Result`); `crates/octravpn-client/src/runner.rs` (`pub async
  fn run(…)`).
- Impact: external callers can't pattern-match — `anyhow::Error` erases
  the type. The audit-log surface is the most load-bearing: the CLI
  `audit verify` path needs to distinguish "file missing" from
  "chain corrupt", but today both surface as opaque `anyhow::Error`.
- Fix: expose a `thiserror`-enum at each library boundary; keep
  `anyhow::Result` only for internal helpers and CLI top-level.

### E-3 [MEDIUM] Panics inside `spawn_blocking` workers are swallowed
- File: `crates/octravpn-core/src/receipt_journal.rs:459-462,528,1282,1438`.
- Impact: `spawn_blocking` JoinHandles are dropped immediately
  (L461: `drop(handle)`). A panic in `compact_async_worker` (e.g. a
  non-provably-safe `expect()`) gets eaten silently. The
  `compaction_inflight` flag clears via `Drop` on the lock guard so
  the journal stays usable, but the operator sees nothing in logs.
- Fix: don't drop the handle — wrap in a small `tokio::spawn` that
  awaits and logs `JoinError::is_panic()`. Or: convert the worker to
  return `Result` so panic-via-`expect` cases get the same treatment
  as `Err`-via-`?` cases.

### E-4 [MEDIUM] Error `Display` impls may leak payload contents
- Files: `crates/octravpn-node/src/pvac.rs:115` (PvacError),
  `crates/octravpn-node/src/circle_update.rs:229` (BundleError),
  `crates/octravpn-mesh/src/knock.rs:153` (KnockError).
- Impact: I did not find a clear sensitive-leak (the structs carry ids
  / counts, not key material), but `BundleError::BlobPutFailed(String)`
  echoes the failing payload — if the chain RPC echoes the payload
  back, the operator log carries it.
- Fix: introduce a `Redacted<String>` newtype for any
  variant-carried `String` whose origin is untrusted. Add a unit test
  that asserts `format!("{e}")` does not match `[0-9a-f]{64}` (32+
  hex bytes — covers most secrets and the `code_hash`).

### E-5 [LOW] Lost `io::Error` context across `?` propagation
- Files: `receipt_journal.rs:549` (`fs::read(&path)?` — no `.with_context`),
  several similar in `seal.rs`. `audit.rs:329` does it right
  (`with_context(|| format!("open {}", path.display()))`).
- Impact: `ENOENT: No such file or directory` surfaces without the
  path the daemon was looking at; operator has to guess.
- Fix: every `?` on an `io::Error` should chain
  `.with_context(|| format!("…{path}…"))`. ~30 sites tightenable in
  `receipt_journal.rs` alone.

### E-6 [LOW] Production-side `unwrap`/`expect` audit — clean
- 1444 `.unwrap()`s in workspace, concentrated in `#[cfg(test)]` mods
  (`audit.rs` 82 unwraps, 0 outside test mod). Verified non-test
  panic sources: `main.rs:992` (`https_addr.unwrap()`, guarded by outer
  `if let Some(tls) = …` — implicit invariant; re-bind or document);
  every other `panic!`/`unreachable!` in `octra/crates/*/src/*.rs`
  falls inside test mods or provably-dead match arms (`main.rs:559`,
  `client/main.rs:414`).
- Fix: `main.rs:992` (3-line refactor); no other action needed.

### E-7 [ADVISORY] `anyhow` vs `thiserror` style mixing — convention good
- Internal helpers + CLI dispatch use `anyhow::Result + with_context`;
  library boundaries (`octravpn-core`, `octravpn-mesh`) use
  `thiserror` enums. Right shape.
- Fix: document the convention in `CONTRIBUTING.md`.

---

## CONFIGURATION (10 findings)

### CFG-1 [BLOCKER] Zero `#[serde(deny_unknown_fields)]` workspace-wide
- File: every `Deserialize` struct in
  `crates/octravpn-{node,client}/src/config.rs`.
- Impact: an operator who typos `metric_token` for `metrics_token`
  gets a silent `None` default → `/metrics` 503s with no diagnostic.
  With 121 `#[serde(default)]` annotations in the workspace, every
  typo'd field manifests as a silently-defaulted value.
- Fix: add `#[serde(deny_unknown_fields)]` to `NodeConfig`,
  `ChainCfg`, `TunnelCfg`, `PricingCfg`, `ControlCfg`,
  `AttestationCfg`, `AnalyticsCfg`, `PvacCfg`, `TunCfg`,
  `TransportCfg`, `Obfs4Cfg`, `AmneziaCfg`. Add a deliberate-typo
  TOML unit test.

### CFG-2 [HIGH] Six secret-bearing fields stored as plain `Option<String>`
- File: `crates/octravpn-node/src/config.rs`:
  L353 `chain.sealed_passphrase`, L253 `obfs4.bridge_identity_secret`,
  L283 `analytics.bearer_token`, L557 `control.events_token`,
  L567 `control.metrics_token`, L590 `control.admin_token`.
- Impact: plaintext secrets in heap as `String` for daemon lifetime;
  visible in `Debug` (`#[derive(Debug)]` at L68 prints them all);
  could land in panic-handler crash dump or stray
  `tracing::debug!(?cfg)` line.
- Fix: wrap each in `secrecy::SecretString` (min:
  `zeroize::Zeroizing<String>`). Audit `tracing::*` macros in
  `hub.rs`/`main.rs`/`pvac.rs` for `?cfg` emissions.

### CFG-3 [HIGH] Multiple env-var precedence chains for the same secret
- Files: `OCTRAVPN_SEALED_PASSPHRASE` read at `hub.rs:684`,
  `main.rs:815`, `client/discover_v2.rs:145` (3 chains).
  `OCTRAVPN_ADMIN_TOKEN` read at `hub.rs:1037` (config.OR(env)),
  `mesh_ops.rs:128` (arg.OR(env)), `main.rs:857` (admin_token.OR(env))
  — 3 different precedence rules for the same value.
- Impact: an operator who sets both config + env can get different
  authoriser values depending on which code path mints it.
- Fix: a single `fn resolve_admin_token(cfg: &NodeConfig) ->
  Option<SecretString>` in `crate::secrets`. Every consumer goes
  through it. The field docstring at `config.rs:580-594` documents
  precedence for `admin_token`; do the same for the other 4 vars.

### CFG-4 [MEDIUM] Path-typed fields are `String`, not `PathBuf`
- File: `config.rs` — 12 fields: `pvac.binary_path`, `pvac.circle_pubkey_path`,
  `pvac.circle_secret_path`, `analytics.listen_addr`,
  `chain.wallet_secret_path`, `chain.circle_state_path`,
  `chain.pinned_root_paths`, `chain.circle_v3_state_path`,
  `tunnel.wg_secret_path`, `control.audit_dir`,
  `control.receipt_journal_path`, `control.tailscale_wire_state_dir`.
- Impact: relative-path resolution differs by consumer. Some call
  `canonicalize()` early; others pass `&str` to `fs::read(path_str)`
  which resolves against `CWD` at syscall time — divergent if any
  task triggered `chdir`.
- Fix: type-change to `PathBuf` (or `ConfigPath(PathBuf)` newtype that
  canonicalises relative-to-the-node.toml's directory at load time).
  Loader `config.rs:651-657` already has the config-file path; a
  3-line change.

### CFG-5 [MEDIUM] `chain.chain_id` defaults to DEVNET — wrong direction
- File: `config.rs:340-341,413-418`.
- Impact: a mainnet operator who forgets the field gets devnet
  receipts that won't validate against the mainnet program. Observable
  only at settle time. Docstring 333-339 names the risk; the default
  itself points the wrong way (production should fail-closed on
  missing field).
- Fix: remove `#[serde(default = "default_chain_id")]` from
  `chain_id`; make it required-explicit. Categorise the rest of
  `#[serde(default)]` fields into "safe-default" (amnezia.enabled =
  false, pvac.enabled = false), "required-explicit"
  (`wallet_secret_path`, `wg_secret_path`, `chain_id`), and
  "operator-knob" (`restart_backoff_ms`, `poll_interval_secs`).
  Remove `default` from "required-explicit".

### CFG-6 [MEDIUM] Config block sprawl — 8 top-level + 3 nested today
- File: `config.rs:68-97`. Top-level: `[chain]`, `[tunnel]`,
  `[pricing]`, `[control]`, `[attestation]`, `[analytics]`, `[tun]`,
  `[pvac]`. Nested: `[tunnel.amnezia]`, `[tun.transport]`,
  `[tun.transport.obfs4]`. Brief's `[control.knock]`,
  `[control.rate_limit]`, `[tun.derp.front]`, `[dns]`, `[derp]` NOT
  yet in NodeConfig — planned / in-flight.
- Impact: 4 of 8 top-level blocks are singletons. Operator mental
  model exploding: where does `bearer_token` live?
- Mergeable: `[attestation]` (1 field) → `[control]`. `[tun]` →
  promote `[tun.transport]` to top-level `[transport]`.
  `[analytics.bearer_token]` + `[control.{metrics,events}_token]`
  unify under `[observability]`.
- Fix: `docs/operators/config-blocks.md` enumerating each block +
  dependencies. Consolidate in follow-up.

### CFG-7 [LOW] `chain.rpc_url` has no scheme validation
- File: `config.rs:325`. Typo'd `http://foo` slides through; defeats
  P0-2 (TLS pinning) silently if the RPC accepts plaintext.
- Fix: validate at load — `starts_with("https://") ||
  starts_with("http://localhost")`. Reject otherwise.

### CFG-8 [LOW] `obfs4.iat_mode` accepts any u8
- File: `config.rs:257`. Doc says 0/1/2 only; `iat_mode = 99` parses
  cleanly. The wire layer presumably validates but the config does
  not.
- Fix: `impl Obfs4Cfg { fn validate(&self) -> Result<…> }` rejects > 2.
  Call from `NodeConfig::load`.

### CFG-9 [LOW] `chain.attestation_url` not URL-parsed at boot
- File: `config.rs:410`. Typo'd URL goes into `policy.json` and the
  audit chain notices, but only at scrape time.
- Fix: `url::Url::parse` at config-load, clear error on bad URL.

### CFG-10 [ADVISORY] No per-block `validate()` API
- Pattern: `NodeConfig::load` parses TOML but does no semantic
  validation. Ad-hoc validation scattered across consumers.
- Fix: `impl ChainCfg { fn validate(&self) -> Result<(), CfgError> }`
  on each block; `NodeConfig::validate` chains them; `load` calls
  `validate` after parse. Combined with CFG-1 + CFG-7/8/9 this gives
  operators strong boot diagnostics.

---

## Concurrency model — overall verdict

The workspace is **moving in the right direction**. Recent merges
show three healthy patterns: `MachineRegistry` COW (#238) —
`RwLock<Arc<HashMap>>` benchmarked; audit-log supervisor
(`audit.rs:586-644`) — textbook tokio-mpsc-flusher, `parking_lot::
Mutex` held only across sync `write_inner_direct`, never across
`.await`; receipt-journal async compaction (`receipt_journal.rs:
485-645`) — slow tempfile write off-lock on `spawn_blocking`, lock
only for the bounded delta-replay, atomicity argument holds. Tech
debt is concentrated in `headscale-rs` `gateway/auth.rs` +
`swarm_transport.rs` (still `std::sync::RwLock + .unwrap()`) and in
older `headscale-{core,payments,resources}` crates not yet converted
to COW (C-5). The lost-wake race (C-1 / C-2) is the only real
correctness concern: latent since the long-poll landed, the project's
test code documents the workaround without fixing the primitive.
Configuration is the weakest area — zero `deny_unknown_fields`, zero
secret-wrapping, multiple env-var precedence chains for the same
value, 121 silent `#[serde(default)]` fallbacks. Fixing
CFG-1 + CFG-2 + CFG-3 is one focused PR with major operator-safety
upside and no architectural change.

## Top-3 highest-leverage findings

1. **CFG-1 (BLOCKER)** — `#[serde(deny_unknown_fields)]` on every
   `Deserialize` struct in `config.rs` is ~12 sites × 1 line plus one
   test, turns 121 silent typo-tolerant fields into 121 fail-fast
   operator diagnostics. Best safety-per-LOC change here.
2. **C-1 (HIGH)** — fixing the `Notify` lost-wake race in
   `tailscale_wire/map.rs:395-419` is ~15 lines (arm-then-await or
   `tokio::sync::watch`) and eliminates the "peer registered but the
   long-poll didn't notice" bug class. The test at `map.rs:842-852`
   already encodes the workaround so regression coverage is baked in.
3. **CFG-2 (HIGH)** — wrapping the 6 secret config fields in
   `secrecy::SecretString` removes them from `Debug`, scrubs panic
   crash dumps, blocks accidental `tracing::debug!(?cfg)` leaks.
   Paired with CFG-3 (single resolver per secret) the
   secret-handling surface becomes auditable in one file.

## Out-of-scope but noted

- `octra-foundry` is concurrency-free (0 locks, 0 spawn, 0 non-test
  panics). Pure sync compute. No findings.
- `octravpn-obfs4` uses `parking_lot::Mutex` correctly, never across
  `.await`, exercised by property tests. No findings.
- Brief's "9 new config blocks added this session" — at HEAD only
  8 top-level blocks exist (CFG-6). `[control.knock]`,
  `[control.rate_limit]`, `[tun.derp.front]`, `[dns]`, `[derp]` are
  planned / on other worktrees, not yet in `NodeConfig`.
