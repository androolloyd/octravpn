# Refactor plan — 2026-05-20

Targets modules that cause **agent collisions** and merge thrash when
multiple contributors (human or subagent) touch them in parallel.

> **Scope rule.** This document is a **plan, not a refactor**. No code
> changes are included. `crates/octravpn-tun/**` is explicitly excluded
> from every recommendation below — four agents are concurrently
> rewriting it for the shielding pack.
>
> **One missing target.** `headscale-rs/headscale-api/src/tailscale_wire/wire.rs`
> from the prompt **no longer exists in this tree** (the `headscale-rs`
> embedded repo was dropped — see `d6b3930 gitignore .claude/worktrees +
> drop embedded-repo refs`). It is omitted from the candidates list; the
> structural concern moves to `crates/octravpn-mesh/src/headscale_bridge.rs`
> instead.

---

## Metrics snapshot

Collected from this worktree's HEAD (`05d7c8b`). Churn = commits in the
30 days ending 2026-05-20. Test-block lines counted by the `#[cfg(test)]`
sentinel to EOF.

| File | LOC | fns | pub items | churn 30d | test-block | test-ratio |
|------|----:|----:|----------:|----------:|-----------:|-----------:|
| `crates/octravpn-node/src/control.rs` | 1690 | 33 | 0¹ | 12 | 1427 | 0.84 |
| `crates/octravpn-core/src/receipt_journal.rs` | 1653 | 56 | 18 | 6 | 1109 | 0.67 |
| `crates/octravpn-client/src/portal/routes.rs` | 1560 | 53 | 0 | 6 | n/a | — |
| `crates/octravpn-node/src/cli_ops.rs` | 1432 | 34 | 0 | 1 | n/a | — |
| `crates/octravpn-node/src/hub.rs` | 1321 | 26 | 0 | **24** | 44 | 0.03 |
| `crates/octravpn-node/src/audit_cli.rs` | 1270 | n/a | 0 | n/a | n/a | — |
| `crates/octravpn-client/src/portal/chain.rs` | 1215 | 30 | 0 | 4 | 961 | 0.79 |
| `crates/octravpn-node/src/audit.rs` | 1105 | 22 | 0 | 8 | 404 | 0.37 |
| `crates/octravpn-node/src/main.rs` | 830 | 9 | 0 | **19** | 0 | 0.00 |
| `crates/octravpn-mesh/src/headscale_bridge.rs` | 777 | 36 | 16 | 5 | 314 | 0.40 |

¹ `control.rs` declares its types as `pub(crate)`, not `pub`, so the
naive `^pub ` grep returns 0. Effective surface area: `ControlState`,
`NodeMetrics`, `ApiError`, plus eight axum handlers (`announce`,
`health`, `metrics`, `events_sse`, `get_state`, `mint_preauth`, …).

**Cross-cutting churn signal.** The five "agent-collision" files cited
in the prompt all appear in the top-10 by churn or by LOC. `hub.rs` is
the single biggest target by churn (24 commits in 30 days) — every new
subsystem at boot lands inside `Hub::spawn_control_plane`. `main.rs` is
second (19 commits) — every new subcommand lands in `enum Cmd`.

---

## Top-8 refactor candidates (ranked by collaboration pain)

### 1 — `crates/octravpn-node/src/hub.rs`

- **Churn metrics**: 24 commits / 30d (highest in tree). 1321 LOC.
  26 functions, 14 `pub` fields on `Hub`. Only **3 %** test code — most
  tests live in integration files, so any structural change here cannot
  be locally validated.
- **Why this hurts**: every feature that has to "wire itself in at
  boot" (analytics, audit batched flusher, tailscale-wire surface,
  preauth minter, sealed-key strict mode, v3 chain ctx, DERP map,
  policy store) appends another 20–80 lines to a single 200-line
  `spawn_control_plane` closure. The recent merges
  (`dfc016e P1-6 sealed keys + P1-8/9 receipt journal`,
  `2e1ad52 tailscale-interop`, `5d58c08 instrument metrics`,
  `8c89fbc switch audit log to batched fsync`) all collide here.
- **Structural problem**: **God object** (`Hub` has 14 pub fields and
  acts as a service-locator) + **module boundary doesn't match
  coupling** (spawning + wiring + key derivation + RPC building +
  policy-bundle build live in one file).
- **Proposed refactor**: split into
  - `hub/state.rs` — the `Hub` struct definition + accessor methods
    (no `new`, no spawns).
  - `hub/boot.rs` — `Hub::new` decomposed into
    `load_keys` → `build_chain_ctxs` → `build_state` (each ≤ 80 LOC).
  - `hub/registration.rs` — `register_endpoint_v1` / `v2` / `v3` (already
    cleanly separated; just move).
  - `hub/spawn.rs` — `spawn_validator_health_loop`, `spawn_tunnel`,
    `spawn_control_plane`.
  - `hub/control_plane_builder.rs` — extract the 200-LOC
    `spawn_control_plane` closure into a `ControlPlaneBuilder` struct
    whose methods (`with_wire_state`, `with_analytics`, `with_audit`)
    each own one subsystem.
  - `hub/accumulator.rs` — `Accumulator` + `AccumulatorStore` (currently
    lines 1113–1175, unrelated to Hub itself).
- **Risk**: medium. Hub is reached by `main.rs`, all `Cmd` variants
  that need a live daemon, and `tests/v3_boot_integration.rs`. Gates:
  `cargo test -p octravpn-node` and the v3 boot integration test.
  Rollback: revert is one PR (the moves are mechanical).
- **Negative counter-argument**: leave it alone if (a) we expect the
  pace of "new subsystem at boot" to slow once shielding+analytics are
  shipped, (b) the agents that touch it are already serialised by the
  upstream subagent dispatcher. Hub is structurally fine for a
  single-author project; it only hurts under concurrent agents.
- **Sequencing**: **staged in 3 PRs.**
  1. Mechanical moves (`Accumulator`, `register_endpoint_*`). No
     behavioral change.
  2. Introduce `ControlPlaneBuilder` and rewrite `spawn_control_plane`
     to call it. Behavior-preserving.
  3. Split `Hub::new` into `load_keys`/`build_chain_ctxs`/`build_state`.
  Total estimated LOC delta: **−250** (mostly comment + boilerplate
  collapse; some lines move to new files).

---

### 2 — `crates/octravpn-node/src/control.rs`

- **Churn metrics**: 12 commits / 30d, 1690 LOC, **84 % test code**
  (1427 / 1690), 33 functions, 6 axum routes registered in one `Router`
  builder. **Three independent bearer-auth handlers** roll their own
  Authorization parsing.
- **Why this hurts**: every new HTTP feature lands in the same file:
  metrics counters, /metrics handler, /preauth admin, /events SSE,
  /session, /session/:id, /health. Each new agent-PR adds another
  `with_<token>(…)` builder method and another inlined bearer check
  (lines 611, 764, 974). Most edits don't actually touch the same
  handler — they touch shared state — but the file's god-router pattern
  forces overlap. Tests interleave with production code: an
  `assert_eq!` block (lines 1006–1690) is six times the size of any
  individual handler.
- **Structural problem**: **Cross-cutting concern not extracted** (the
  bearer-auth pattern: `headers.get(AUTHORIZATION) → strip_prefix("Bearer ")
  → constant_time_eq_str(want)` is hand-rolled in three handlers) +
  **Test code mixed with prod code** (84 % test ratio is the canary —
  prod and test edits cannot be reviewed independently) + **Hot path
  tangled with cold path** (route registration + handlers + metrics
  rendering + state-builder fluent API in one file).
- **Proposed refactor**:
  - **Extract bearer middleware.** New file
    `crates/octravpn-node/src/control/auth.rs` exporting a
    `bearer_layer(token: Option<Arc<str>>, hide_404: bool) -> tower::Layer`.
    Apply via `.route_layer` per endpoint. Drops ~80 LOC across three
    handlers and unifies the "absent token ⇒ 404 vs 503" decision.
  - **Split handler files.** New tree:
    - `control/mod.rs` — `ControlState` + `serve` only.
    - `control/auth.rs` — bearer middleware.
    - `control/health.rs` — `/health`.
    - `control/metrics.rs` — `/metrics` handler + Prometheus
      rendering (currently 80+ lines of inline strings).
    - `control/session.rs` — `/session` POST + `/session/:id` GET.
    - `control/events.rs` — SSE.
    - `control/admin.rs` — `/admin/preauth`.
  - **Move tests** to a sibling `tests/control_*.rs` integration file
    where they belong (they already use `oneshot()` HTTP requests, so
    they're integration tests in disguise).
- **Risk**: low–medium. The Router builder is the only API any other
  module uses (`crate::control::serve` from hub). Gates: the entire
  `control::tests::*` module — 20+ tests covering every handler. The
  tests should pass byte-identically after the move.
- **Negative counter-argument**: skip if the bearer middleware is the
  *only* repeated pattern (one tower middleware for three uses might be
  more boilerplate than the three handlers it replaces). The test-split
  is the higher-leverage half — middleware can wait until a 4th
  bearer-gated route appears.
- **Sequencing**: **staged in 2 PRs.**
  1. Move `#[cfg(test)]` block to `tests/control_handlers.rs` (mechanical, ~−1400 LOC from `control.rs`, +1400 in tests). Establishes the new prod-only surface.
  2. Split handler files + introduce bearer middleware.
  Total estimated LOC delta: **−120** (middleware dedup) on prod side,
  zero on tests.

---

### 3 — `crates/octravpn-node/src/main.rs`

- **Churn metrics**: 19 commits / 30d (second-highest in tree),
  830 LOC, 12 top-level `Cmd` variants + 4 `MeshCmd` variants + nested
  `V3Cmd`, `AuditCmd`, `ConfigCmd` (33 `Cmd::Variant` references
  matched). The `enum Cmd` itself is **162 lines** (lines 56–217).
- **Why this hurts**: every new subcommand requires three coordinated
  edits — add an enum variant, add a `match` arm, add the actual
  handler. With 8+ parallel agents adding subcommands (`audit replay`,
  `audit verify`, `health`, `audit-tail`, `receipt-verify`, `config
  validate`, `mesh status`, `mesh policy`) the enum-match-handler triple
  is a guaranteed collision site. Recent example: PR series
  `00c274a v3 node CLI: 17 subcommands…` had to be staged because of
  conflict drift.
- **Structural problem**: **Wide trait equivalent** (a giant `enum` is
  the rust-pattern equivalent of a wide trait — every variant requires
  match-completeness in N places) + **Module boundary doesn't match
  coupling** (`v3_cli.rs`, `audit_cli.rs`, `mesh_ops.rs`, `cli_ops.rs`
  all exist already; `main.rs` just dispatches).
- **Proposed refactor**:
  - Per-subcommand-tree files for the enum **fragments**: move
    `enum MeshCmd` into `mesh_ops.rs` (where its handler already lives),
    `enum V3Cmd` into `v3_cli.rs`, `enum AuditCmd` into `audit_cli.rs`,
    `enum ConfigCmd` into `cli_ops.rs`. Each module re-exports its enum
    + a `dispatch(self, hub: Option<&Hub>) -> Result<()>`.
  - `main.rs` becomes ~150 LOC: top-level `enum Cmd` listing only
    `Run | Bond | Unbond | … | Mesh(MeshCmd) | V3(V3Cmd) | …` and a
    flat `match cmd { Cmd::Mesh(c) => mesh_ops::dispatch(c).await, … }`.
  - **Introduce a `Subcommand` trait** (only if the
    enum-fragment split alone doesn't suffice — keep the rule
    "one variant = one method call").
- **Risk**: low. Pure mechanical move; `clap` derive is variant-local.
  Gates: every `octravpn-node <subcommand>` invocation in CI
  (`scripts/devnet-smoke.sh`, the demo scripts, the docker
  testnet harness). Rollback: revert is trivial.
- **Negative counter-argument**: leave it alone if the
  *enum-discoverability* benefit (one place to grep `Cmd::`) matters
  more than the collision cost. clap's compile-time errors catch
  most mistakes anyway.
- **Sequencing**: **single PR**, mechanical. LOC delta: **−200** in
  `main.rs`, +50 spread across the four `*_cli.rs` files.

---

### 4 — `crates/octravpn-core/src/receipt_journal.rs`

- **Churn metrics**: 6 commits / 30d, 1653 LOC, **67 % test code**,
  56 functions across one file (18 pub items: 11 pub fn + 1 pub struct +
  2 pub enum + 4 pub const).
- **Why this hurts**: append-only journal + async compaction +
  fsync-policy + v0→v1 format migration + replay/recovery + watermark
  trigger + CRC32 vectors — six independent concerns in one file. The
  P1-8/9 subagent landed this as one PR; subsequent collisions on the
  compaction path (`01697d4 async compaction to keep bump() O(1)`,
  `5e56b5a clippy fix wave`) hit the same impl block.
- **Structural problem**: **Hot path tangled with cold path** (`bump()`
  is hot, called per receipt; `compact()` is cold, called at watermark;
  both live in one impl) + **Test code mixed with prod code** (67 %
  tests means any refactor of compaction tugs on 30+ tests in the same
  file).
- **Proposed refactor**:
  - `receipt_journal/mod.rs` — `ReceiptJournal` + `Inner` + `JournalError`
    + `FsyncPolicy` types only.
  - `receipt_journal/hot.rs` — `bump()`, `floor()`, `read_floor()`,
    `entries()`. The cache-line-tight in-memory path.
  - `receipt_journal/io.rs` — `open()`, `reload()`, `flush()`, the
    fsync-policy timer.
  - `receipt_journal/compact.rs` — `compact()`, `compact_async()`,
    `compact_locked()`, `compact_async_worker()`,
    `compacting_tempfile_path()`, `write_v1_snapshot_at()`.
  - `receipt_journal/codec.rs` — `encode_record`, `replay_v1`,
    `replay_any`, `decode_v0`, `write_v1_snapshot`, `ensure_v1_header`,
    `crc32_ieee`. Pure functions over `&[u8]` — easy to property-test.
  - `receipt_journal/tests.rs` — the 1100-line test block, unchanged.
- **Risk**: low. The pub API surface (`ReceiptJournal::{open, bump,
  floor, compact, …}`) is stable; only internal helpers move. Gates:
  the 30+ unit tests + `tests/v3_boot_integration.rs` (which exercises
  the journal at boot).
- **Negative counter-argument**: leave it alone if the file isn't yet
  causing actual merge conflicts — 6 commits/30d is not catastrophic.
  Splitting can wait until either format v2 lands (then `codec.rs` is
  forced anyway) or until two concurrent agents collide on compaction.
- **Sequencing**: **single PR**, all moves at once. The pure-functions
  test surface makes it easy to verify byte-identity. LOC delta:
  **0** (pure move).

---

### 5 — `crates/octravpn-node/src/audit.rs`

- **Churn metrics**: 8 commits / 30d, 1105 LOC, 22 fns, 37 % test ratio.
  The `AuditLog::open` vs `AuditLog::open_batched` split was added in
  one PR (`1782318 audit: batched fsync flusher + audit_cli reuses
  AuditLog::verify_file`) and immediately collided with two subsequent
  hub-side changes (`8c89fbc hub: switch audit log to batched fsync`,
  `5d58c08 receipt_signed audit emission`).
- **Why this hurts**: the file holds the sync writer, the async batched
  writer, the flusher loop, the analytics tap, the file-verify report,
  and the HMAC chain-step. Agents extending the analytics tap (`5d58c08`)
  and agents extending the flusher (`1782318`) cannot work in parallel.
- **Structural problem**: **God object** (one `AuditLog` impl owns
  sync writes, async writes, flusher cmd channel, verify-file, key
  loading, and analytics tap) + **Hot path tangled with cold path**
  (`tap_publish` runs per-receipt; `verify_file` is an offline operator
  command in the same file).
- **Proposed refactor**:
  - `audit/mod.rs` — `AuditLog`, `Inner`, the sync `write()` path.
  - `audit/batched.rs` — `open_batched`, `flusher_loop`, `FlusherCmd`,
    `fsync_now`, `write_async`, `flush_and_close`.
  - `audit/tap.rs` — `with_analytics_tap`, `tap_publish`. Tap channel
    lives behind a single `enum Tap { None, Analytics(Sender<…>) }`.
  - `audit/verify.rs` — `verify_file`, `FileVerifyReport`,
    `FileVerifyError`. Offline path; not linked into the hot daemon.
  - `audit/codec.rs` — `chain_step` + `write_inner_direct` + key
    loading + `ymd_utc` + `days_to_ymd`. Pure functions.
- **Risk**: medium. The hub calls `AuditLog::open_batched` →
  `with_analytics_tap` → `state.with_audit(audit)` as a 3-step
  builder; the refactor must preserve that fluent API. Gates: the
  audit unit tests + the `audit_cli` integration tests that call
  `verify_file`.
- **Negative counter-argument**: skip if the next 1–2 PRs touching
  audit are all already in flight (don't refactor a file that has
  pending agent work). Check `git log --since='7 days ago' --
  crates/octravpn-node/src/audit.rs` before scheduling.
- **Sequencing**: **single PR**, behavior-preserving. LOC delta: **−40**
  (small dedup in the verify path; mostly a move).

---

### 6 — `crates/octravpn-mesh/src/headscale_bridge.rs`

- **Churn metrics**: 5 commits / 30d, 777 LOC, 36 fns, **16 pub items**
  (the highest pub-item count of any candidate). Test ratio 40 %.
- **Why this hurts**: `PreauthMinter`, `PreauthKey`, `RedemptionRecord`,
  `MetricsSink` trait, `TailnetIpAllocator` impl, `IpAllocator` trait
  impl, `PreauthRedeemer` impl, the `test-helpers` feature gate — all
  in one file. Two concurrent collisions:
  `0f690dc bounded mints + redemptions` and
  `2e1ad52 tailscale-interop: real PreauthMinter + admin endpoint`
  both rewrote big chunks within a week.
- **Structural problem**: **Module boundary doesn't match coupling** —
  the `PreauthMinter` (a chain-agnostic LRU-with-TTL keyed by token)
  and the `TailnetIpAllocator` impl (Tailscale-specific IP allocation)
  share a file only because they were added in the same PR. **Wide
  trait emergent**: `MetricsSink` is used in three crates; it should
  not live next to the preauth minter.
- **Proposed refactor**:
  - `octravpn-mesh/src/preauth.rs` — `PreauthMinter`, `PreauthKey`,
    `RedemptionRecord`, `RedeemError`, `PreauthRedeemer` impl,
    `DEFAULT_*` constants.
  - `octravpn-mesh/src/metrics_sink.rs` — the `MetricsSink` trait
    (its callers cross 3 crates; promoting it to its own file makes
    re-exports cleaner).
  - `octravpn-mesh/src/ip_alloc.rs` (already exists) — receive the
    `IpAllocator for TailnetIpAllocator` impl that currently lives in
    `headscale_bridge`.
  - `octravpn-mesh/src/headscale_bridge.rs` — keep
    `ExpectedMeteringSnapshotShape` + the test-helpers feature gate,
    or delete it entirely once everything inside has migrated out.
- **Risk**: low. All exported types are re-exported through
  `octravpn_mesh::*` at the crate root; downstream code that uses
  `octravpn_mesh::PreauthMinter` keeps working.
- **Negative counter-argument**: leave it alone if the `headscale_bridge`
  name is intentional ("everything Headscale-adjacent lives here") and
  agents are expected to look here first. The split fragments
  discoverability. Counter: the file's churn is already moderate, so
  the optimization is small.
- **Sequencing**: **single PR**, mechanical move. LOC delta: **0**
  (pure split).

---

### 7 — `crates/octravpn-client/src/portal/chain.rs`

- **Churn metrics**: 4 commits / 30d, 1215 LOC, 30 fns, **79 % test
  code** (961 / 1215). Test ratio rivals `control.rs`.
- **Why this hurts**: `PortalChain` mixes (a) chain RPC fetch, (b)
  source-sniffing (oct:// vs https://), (c) sealed-asset decryption,
  (d) `AssetCache` (LRU+TTL) management, and (e) passphrase resolution
  through the `PassphraseSource` trait. New cache-aware features can't
  be added without touching the fetch path; new decrypt paths can't
  be added without touching the cache key.
- **Structural problem**: **God object** (`PortalChain` owns cache +
  RPC + passphrase + chain-id) + **Hot path tangled with cold path**
  (cache-hit returns in 1 µs; sealed decrypt is 100×; both share one
  function).
- **Proposed refactor**:
  - `portal/chain/cache.rs` — `AssetCache`, `AssetCacheEntry`,
    `AssetCacheKey`, eviction policy. ~150 LOC, fully testable in
    isolation. The portal's `/api/cache/stats` future endpoint binds
    here.
  - `portal/chain/fetch.rs` — `fetch_with_source`,
    `fetch_with_source_sniffed`, the RPC client wrap.
  - `portal/chain/decrypt.rs` — `try_decrypt`, `looks_sealed`, sealed
    envelope handling. Pure: `(bytes, passphrase) -> Result<bytes>`.
  - `portal/chain/passphrase.rs` — `PassphraseSource` trait +
    `ConfigPassphrase` impl. Currently 30 LOC in the middle of the file.
  - `portal/chain/mod.rs` — `PortalChain` itself, which composes the
    four above. ~200 LOC down from 1215.
- **Risk**: low. The pub-crate API (`PortalChain::{from_config,
  fetch_with_source, …}`) is stable; only internals reorganize.
  Gates: the test block in this file (~961 LOC of integration tests
  built around a mock RPC).
- **Negative counter-argument**: this file is **less collision-prone**
  than the top-5 (4 commits/30d). Pre-emptive split only pays off if
  we expect more decrypt schemes to land (PVAC-sidecar plaintexts,
  Octra HFHE re-encrypt) — which we do, per the AML wire-format memory.
- **Sequencing**: **single PR**. LOC delta: **0** (move).

---

### 8 — `crates/octravpn-client/src/portal/routes.rs`

- **Churn metrics**: 6 commits / 30d, 1560 LOC, **53 functions**, 11
  axum routes registered in one router.
- **Why this hurts**: every new HTTP endpoint on the *client* portal
  side (analogous to the *node* side in control.rs) lands here:
  `/`, `/healthz`, `/go`, `/api/resolve`, `/view`, `/confirm`,
  `/approve`, `/raw`, `/unseal`, plus 20+ HTML-rendering helpers
  (`render_bytes`, `render_image`, `render_json`,
  `render_sandboxed_html`, `error_page`, `confirm_interstitial`).
  Two agents touching different routes will both touch this file.
- **Structural problem**: same as `control.rs` — **god-router**
  pattern + handler/rendering/state-builder interleaved.
- **Proposed refactor**: mirror the `control.rs` split:
  - `portal/routes/mod.rs` — router + `PortalState` only.
  - `portal/routes/assets.rs` — `/view`, `/raw`, `/go`, `/api/resolve`.
  - `portal/routes/confirm.rs` — `/confirm`, `/approve`.
  - `portal/routes/unseal.rs` — `/unseal` + `unseal_form_page`.
  - `portal/routes/render.rs` — `render_bytes`, `render_image`,
    `render_json`, `render_sandboxed_html`, `render_plain_text`,
    `render_save_as`, `render_shell`, `error_page`,
    `confirm_interstitial`, `fetch_error_page`, `tunnel_error_page`.
  - `portal/routes/util.rs` — `last_path_component`,
    `urlencode_query_value`, `sanitize_next`, `raw_error_response`.
- **Risk**: low. Tests for these handlers already live in
  `tests/portal_integration.rs` and hit the router via
  `oneshot()`. Internal moves don't change observable behavior.
- **Negative counter-argument**: lower priority than `control.rs`
  because (a) client portal has fewer concurrent agents and (b)
  rendering helpers genuinely share boilerplate that benefits from
  co-location.
- **Sequencing**: **single PR** after `control.rs` split lands. LOC
  delta: **0** (move).

---

## Cross-cutting opportunities

Patterns observed in 3+ candidates above. These yield the biggest
maintenance dividend per LOC of refactor work.

### XC-1 — Bearer-auth middleware (extracted)

**Highest leverage.** Currently duplicated **four times** across the
tree:

- `crates/octravpn-node/src/control.rs:597–616` (metrics handler).
- `crates/octravpn-node/src/control.rs:751–800` (events SSE handler).
- `crates/octravpn-node/src/control.rs:961–1005` (admin/preauth).
- `crates/octravpn-analytics/src/http.rs:67–78` (analytics endpoints).

All four follow the same recipe:

```
let Some(want) = state.token.as_deref() else { return 503 or 404; };
let got = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok())
                 .and_then(|s| s.strip_prefix("Bearer "));
let authorized = got.is_some_and(|tok| constant_time_eq_str(tok, want));
if !authorized { return 401; }
```

with two policy axes (absent-token-action: `503` vs `404`) and one
constant-time helper. **Proposal**: a `tower::Layer` in
`crates/octravpn-core/src/bearer.rs` (core crate so both `node` and
`analytics` can use it):

- `BearerLayer::strict(token)` — token must be present + match;
  absent ⇒ 503.
- `BearerLayer::hidden(token)` — same as strict, but absent token ⇒
  404 (the "endpoint hidden" pattern used by `/events` and `/admin/preauth`).

Apply with `.route_layer(BearerLayer::hidden(state.admin_token.clone()))`.
**LOC delta: ~−100** across the four sites.

### XC-2 — Subcommand dispatch trait (`Subcommand::dispatch`)

**Second-highest leverage.** Currently four cli-module files each
define their own dispatcher fn (`run_mesh_cmd`, `run_v3_cmd`,
`run_audit_cmd`, `run_config_cmd`) with subtly different signatures.
**Proposal**: a `trait Subcommand` in
`crates/octravpn-node/src/cli/mod.rs`:

```text
trait Subcommand {
    async fn dispatch(self, ctx: &CliContext) -> Result<()>;
}
```

`CliContext` carries the optional `Arc<Hub>`, a logger handle, and
config-file path. Each `enum MeshCmd | V3Cmd | AuditCmd | ConfigCmd`
gets one `impl Subcommand`. `main.rs` becomes a flat dispatch:

```text
match cli.cmd { Cmd::Mesh(c) => c.dispatch(&ctx).await, … }
```

**LOC delta: ~−50** in `main.rs`, ~+30 spread across cli files. Net
**−20** but the real win is consistency: new subcommands stop hitting
`main.rs` at all. Pairs directly with refactor candidate #3.

### XC-3 (lower-priority) — RPC envelope encode/decode helper

Observed in `crates/octravpn-core/src/v3_calls.rs`,
`crates/octravpn-node/src/chain_v3.rs`,
`crates/octravpn-client/src/runner.rs` — each inlines
`serde_json::to_value` → `{"method":…, "params":[…]}` → `rpc.call(…)` →
decode. Not driving collisions today (different sub-trees), so this is
a "nice to have" rather than a "do it now."

---

## Anti-recommendations (do NOT refactor)

- **`crates/octravpn-core/src/v3_canonical.rs`** — 416 LOC, 4 functions,
  each single-responsibility (`sha256_hex`, `check_hash`,
  `canonical_write`, `write_json_string`). High LOC is doc + JSON
  edge-case tests; logical density is low. Leave it alone.
- **`crates/octravpn-node/src/rate_limit.rs`** — 622 LOC but cleanly
  bounded: token bucket + tower-layer integration. 3 commits/30d.
  Recently shipped; let it bake.
- **`crates/octravpn-core/src/receipt.rs`** — 695 LOC, but the API
  surface is the canonical receipt encoding and is intentionally
  fully owned by one file (changes here are versioned via
  `ReceiptContext`).
- **`proofs/lean/*`, `proofs/kani/*`, `proofs/tamarin/*`** — high LOC,
  near-zero logical density per line. Do not touch.
- **`crates/octravpn-tun/**`** — excluded per the constraint
  (four agents concurrently rewriting it).

---

## Sequencing for the next 10 PRs

Ordered to maximize unblocking — each PR creates space for the next:

| PR # | Candidate | Description | LOC delta | Unblocks |
|-----:|-----------|-------------|----------:|----------|
| 1 | #3 main.rs | Move `enum MeshCmd / V3Cmd / AuditCmd / ConfigCmd` into their existing `*_cli.rs` modules. Re-export from `main.rs`. | −200 | XC-2, future subcommand PRs |
| 2 | XC-1 | Introduce `octravpn-core::bearer::BearerLayer` with `strict` / `hidden` constructors + tests. No call-site changes yet. | +120 (new file) | PR 3, PR 5 |
| 3 | #2 (part A) | `control.rs` — move `#[cfg(test)]` block to `tests/control_handlers.rs`. Prod file drops from 1690 → ~260 LOC. | −1430 in prod, +1430 in tests | PR 4, PR 7 |
| 4 | #2 (part B) | `control.rs` — split handlers into `control/{auth,health,metrics,session,events,admin}.rs`. Apply `BearerLayer` from PR 2 to all three gated routes. | −80 net | PR 5 |
| 5 | XC-2 | Introduce `Subcommand` trait + `CliContext` in `cli/mod.rs`. Migrate `MeshCmd` first as the proof-of-concept. | −10 | PRs that add new subcommands |
| 6 | #6 headscale_bridge | Split `PreauthMinter`, `MetricsSink`, `TailnetIpAllocator` impl into separate files. | 0 (move) | parallel work on preauth + IP alloc |
| 7 | #1 (part A) | `hub.rs` — mechanical moves: `Accumulator{,Store}`, `register_endpoint_v{1,2,3}` into `hub/` directory. | 0 (move) | PR 8 |
| 8 | #1 (part B) | `hub.rs` — introduce `ControlPlaneBuilder` and replace the 200-LOC closure. | −150 | PR 9 |
| 9 | #5 audit.rs | Split into `audit/{mod,batched,tap,verify,codec}.rs`. Done after hub stabilizes (PR 8) since hub is the only async caller. | −40 | none |
| 10 | #4 receipt_journal.rs | Split into `receipt_journal/{mod,hot,io,compact,codec,tests}.rs`. Last because the file is the most stable. | 0 (move) | format-v2 work whenever it lands |

**Deferred to a later batch**: candidate #7 (`portal/chain.rs`) and
candidate #8 (`portal/routes.rs`). Both are client-side, lower-churn,
and the `control.rs` split (PRs 3–4) sets the template they will copy.

### Estimated cumulative LOC delta

Sum of the deltas above (prod side only, excluding test moves):

`-200 + 120 + (-1430 + 1430) + (-80) + (-10) + 0 + 0 + (-150) + (-40) + 0`

= **−360 LOC of prod code**, with **0 functional changes**. Net file
count grows by ~20 new small modules; net per-module LOC drops sharply
(target: no file > 600 LOC of prod code).

---

## Pattern: where churn concentrates

One sentence answer: **anywhere a new feature has to "wire itself into
the running daemon" — boot, HTTP routes, CLI subcommands — accumulates
churn linearly with feature count.** The top-3 by churn are exactly
the three "wiring" hubs:

1. `hub.rs` (24) — every subsystem-at-boot hangs off `spawn_control_plane`.
2. `main.rs` (19) — every subcommand hangs off `enum Cmd`.
3. `config.rs` (15) — every tunable hangs off `NodeConfig`. (Not in
   the top-8 candidates because it's mostly serde-derive boilerplate
   with low logical density — easy to merge.)

**Implication for agent dispatch.** When multiple agents work in
parallel, the dispatcher should treat `hub.rs`, `main.rs`,
`control.rs`, and (post-XC-1) `bearer.rs` as **serializing files** —
no two concurrent agent PRs may touch them. The refactors above
shrink the surface so this serialization rule applies to ~100 LOC of
"wiring index" per file, not ~1500.
