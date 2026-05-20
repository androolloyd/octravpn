# Test-quality audit — 2026-05-20

Scope: the OctraVPN workspace at `/Users/androolloyd/Development/octra`.
Commit: `11f83a198b7b04e5a79ebc00a238d7326888337a` (`merge: docs/maintenance/ — per-OS upgrades + rotation + recovery`).

The earlier session note "~3000+ tests" includes the sibling
`headscale-rs` repo (~9.4 k inline `#[test]` attributes there). The
*octra* workspace proper has **1,265 inline + 179 integration + 46
pvac-sidecar = 1,490 test functions** across `crates/`, `tests/e2e/`,
`pvac-sidecar/`. This audit focuses on the octra workspace; the
sibling repo is called out where modules cross the boundary (knock,
ACL).

## 1 · Executive summary

| Metric | Value | Note |
|---|---|---|
| Workspace inline test fns | 1,265 | `grep -cE '#\[(test\|tokio::test)\]'` in `crates/*/src` |
| Integration test fns | 179 | `crates/*/tests` |
| pvac-sidecar tests | 46 | GPL-isolated daemon |
| Branch coverage % | **not measured** | `cargo tarpaulin --branch` is "NOT IMPLEMENTED" upstream; `cargo-llvm-cov` available but a workspace run was not feasible in this session (see §8). Workspace line coverage is collected by CI today via tarpaulin (`.github/workflows/ci.yml:220`). |
| Mutation-catch % (octravpn-core) | **not measured** | `cargo install cargo-mutants --locked` failed to complete inside the audit window (two attempts, both stalled at `Compiling similar v2.1.0` under heavy concurrent cargo load and 83 %-full disk). Invocation pinned in §4 for follow-up. |
| Flakes confirmed | **1** | `octravpn_core::receipt_journal::tests::auto_compaction_does_not_block_bumps` failed 1/10 runs under contention (see §5). |
| Tests with shared static (env / `HOME`) | 6 fns | 2 already serialise with a `Mutex<()>` guard; 4 do not (see §6). |
| Test:source LOC ratio (workspace) | **0.79** | 11,160 inline-test + 8,064 integration LOC vs 35,313 production LOC. Healthy (<2 : 1). |

**Headline findings**

1. `auto_compaction_does_not_block_bumps` is a confirmed flake under
   parallel load (`p50 < 5 ms` assertion, see §5). This already had a
   comment acknowledging fsync-floor variance; the test is still
   gating CI.
2. `octravpn-tun` (1,089 production LOC, 1,692 test LOC including
   `amnezia.rs`) and `octravpn-obfs4` (1,322 LOC, 1,174 test LOC) have
   **zero integration tests** — all coverage is inline `#[cfg(test)]`.
   See §6 recommendation R4.
3. Branch coverage is not gated anywhere. Tarpaulin's line metric is
   posted to Codecov via CI but `--branch` is upstream-unsupported;
   neither `cargo-llvm-cov` nor `grcov` is wired in. R1.
4. There is no mutation-testing pipeline (no `cargo-mutants` config,
   no CI job). R2.
5. There are **zero `insta` snapshot tests** workspace-wide. There are
   pinned byte/hash assertions (e.g. `bearer::NGINX_404_BODY`,
   `receipt_journal::codec::MAGIC_V1`, `v3_state_root::*_anchor_is_stable`)
   but they are not snapshot-managed — review is per-PR. §7.

## 2 · Per-crate coverage table

LOC measured by walking `src/` and computing inline-test vs production
LOC with a brace-aware classifier (`#[cfg(test)]` block → test
bucket).

| Crate | Prod LOC | Inline-test LOC | Integ-test LOC | Test:src | Inline `#[test]` | Error variants |
|---|---:|---:|---:|---:|---:|---:|
| octravpn-core | 5,167 | 5,038 | 451 | 1.06 | 294 | 45 |
| octravpn-node | 14,391 | 6,590 | 2,893 | 0.66 | 356 | 14 |
| octravpn-client | 7,474 | 4,304 | 1,808 | 0.82 | 247 | 6 |
| octravpn-mesh | 2,599 | 1,467 | 1,304 | 1.07 | 92 | 24 |
| octravpn-tun | 1,089 | 1,692 | 0 | **1.55** | 82 | 0 |
| octravpn-obfs4 | 1,322 | 1,174 | 0 | 0.89 | 67 | 11 |
| octravpn-analytics | 1,265 | 500 | 1,359 | 1.47 | 31 | 0 |
| octra-circle-sim | 728 | 311 | 204 | 0.71 | 20 | 5 |
| octravpn-admin-ui | 662 | 84 | 45 | 0.19 | 5 | 0 |
| **TOTAL (octra workspace)** | **35,313** | **11,160** | **8,064** | **0.79** | **1,265** | **111** |

Reading the table:

- **`octravpn-tun`** has the highest test:src ratio (1.55) but zero
  integration tests — amnezia.rs alone has 44 inline tests covering
  proptest-driven shape oracles.
- **`octravpn-admin-ui`** (0.19) is the under-tested crate. It is
  mostly axum HTTP handlers + templates; if these are exercised at all
  it is via the broader `octravpn-client` portal tests (cross-crate).
- **`octravpn-node`** has the largest absolute production LOC (14k)
  and the second-lowest test:src (0.66). This is the integration
  surface — most behaviour is reached only through the integration
  tests in `crates/octravpn-node/tests/*`.

## 3 · Top-10 likely-uncovered branches (static analysis)

Branch coverage was not measured (see §1), so this list is the result
of a static-analysis proxy: high-fan-in `if let Err`, `match` with
explicit `_ =>` panics/log-and-drop arms, and `unwrap_or_*` defaults
in modules with the fewest tests-per-branch. Each row pairs an
*exists* fact (line) with a *likely-uncovered* hypothesis.

| # | Module : line | Branch | Why we suspect it's uncovered |
|---|---|---|---|
| 1 | `crates/octravpn-node/src/pvac.rs:~1200` | error arm where sidecar binary path is missing | only `/tmp/never-spawned` placeholder is asserted; no negative test runs the spawn-failure branch |
| 2 | `crates/octravpn-node/src/circle_update.rs` `apply_update` rollback | partial-fail rollback path on disk-write error | 84 branches in the file; 30 `#[test]` fns — error-path coverage is the obvious gap |
| 3 | `crates/octravpn-tun/src/amnezia.rs` `validate()` reject branches | s1/s2/H1..H4 conflict rejections | proptest `prop_assume!` filters out bad cases before they hit the negative arm |
| 4 | `crates/octravpn-tun/src/derp/front.rs` `auth_header` malformed | non-hex / wrong-length tag rejection | 8 top-level `if`; only the happy-path length is asserted |
| 5 | `crates/octravpn-mesh/src/knock.rs` `verify` wrong-PSK path | the explicit "bad base64 PSK falls back to None with a warning" path is tested in `mesh_ops`, but the byte-mismatch path inside `verify` itself is only checked structurally |
| 6 | `crates/octravpn-core/src/bearer.rs` strict policy 401 + `WWW-Authenticate` realm | the *body* shape on 401 (asserted empty) is pinned; the realm header value branch is not |
| 7 | `crates/octravpn-obfs4/src/handshake.rs` retry/abort | 16 inline tests but the explicit abort-on-bad-tag branch is not directly hit |
| 8 | `crates/octravpn-core/src/rpc.rs` retry-with-jitter exhausted | jitter sleep branch (`tokio::time::sleep(delay + jitter)`) — tested for one iteration only |
| 9 | `crates/octravpn-node/src/audit.rs` (newly split into `audit/` module) | the just-modularised path; tests still reference the old monolith file (status shows `audit.rs` deleted but `audit/` added — see `git status`) |
| 10 | `crates/octravpn-client/src/portal/routes.rs` 50 +-test surface | the 4xx -> 5xx escalation branches (axum error_handler) are reached by happy-path tests only |

Confirming any of these requires a real coverage run. The invocation
in §4 produces `lcov.info` from which `genhtml` shows the exact lines.

## 4 · Mutation-test results

Status: **not run.** `cargo install cargo-mutants --locked` was
attempted twice in this session; both attempts stalled during dep
compilation (last log line "Compiling similar v2.1.0") under heavy
concurrent cargo load from other agent worktrees and finished without
producing a binary in `~/.cargo/bin/`.

Documented invocation for follow-up (on a quiescent host):

```sh
# install (clean target dir helps; mutants is ~250 deps to compile)
CARGO_TARGET_DIR=/tmp/mutants-install \
  cargo install cargo-mutants --locked

# subset run (octravpn-core, octravpn-mesh, octravpn-node) per the
# audit request. --no-shuffle for deterministic ordering, --jobs=4
# to avoid swamping CI runners.
for pkg in octravpn-core octravpn-mesh octravpn-node; do
  cargo mutants -p "$pkg" --no-shuffle --jobs 4 \
    --output mutants-$pkg/ --timeout 300 \
    2>&1 | tee mutants-$pkg.log
done
```

Expected first targets given the static profile:

- `octravpn-core::receipt::sign` — flipping the `domain_separator` arm
  or swapping `verify_strict` for `verify` should kill at least one
  test; if it doesn't, the receipt-sign suite is signature-shape-only.
- `octravpn-core::receipt_journal::codec::MAGIC_V1` — changing the
  magic byte must fail `empty_file_decodes_to_empty_map` and
  `migrates_v0_to_v1_on_open`.
- `octravpn-mesh::knock::verify` — flipping `==` to `!=` on the tag
  comparison; constant-time vs early-return swap.
- `octravpn-node::pvac` — flipping the "registered" flag in the
  capability gate.

A useful CI guard: gate on mutation-score ≥ 80 % for `octravpn-core`
and `octravpn-mesh`; informational only for the larger node crate.

## 5 · Flake register

Ten consecutive runs of the pre-built debug test binary for
`octravpn-core` on this host (load avg ~7.4 during the run):

```
BIN=/Users/androolloyd/Development/octra/target/debug/deps/octravpn_core-d61ec11b08491ee0
for i in $(seq 1 10); do "$BIN" --test-threads=8 2>&1 | grep '^test result:'; done
```

Iteration results (270 tests per run):

```
iter=1  passed=269 failed=1 ignored=0 wall=8.44s
   test receipt_journal::tests::auto_compaction_does_not_block_bumps ... FAILED
iter=2  passed=270 failed=0 ignored=0 wall=9.24s
iter=3  passed=270 failed=0 ignored=0 wall=8.13s
iter=4  passed=270 failed=0 ignored=0 wall=7.89s
iter=5  passed=270 failed=0 ignored=0 wall=7.44s
iter=6  passed=270 failed=0 ignored=0 wall=8.30s
iter=7  passed=270 failed=0 ignored=0 wall=7.29s
iter=8  passed=270 failed=0 ignored=0 wall=6.94s
iter=9  passed=270 failed=0 ignored=0 wall=7.25s
iter=10 passed=270 failed=0 ignored=0 wall=6.83s
```

Net: **9 / 10 pass** → flake rate 10 % on this host under contention.
Wall p50 ~7.5 s; the failing iteration was the slowest (8.4 s wall),
consistent with the "kernel didn't give us a CPU slice in time"
failure mode.

**Flake #1 — confirmed**

- Test: `octravpn-core::receipt_journal::tests::auto_compaction_does_not_block_bumps`
  (`crates/octravpn-core/src/receipt_journal/compact.rs:390`).
- Failure mode: tight latency assertion. The test asserts:
  `p50 < 5 ms` for `j.bump()` under 4-task contention while the
  auto-compaction watermark fires. On a host with load >5 the p50
  crosses 5 ms because the kernel scheduler doesn't give the bump
  task a CPU slice for >5 ms, not because of the I/O the test is
  designed to catch.
- Author already documented this in the docstring ("we assert
  wall-clock + p50 smoke checks rather than a tight p99 (fsync floors
  on macOS/network FS hosts make a tight target unstable)"), but the
  margin is still too tight to survive shared-runner load.
- Recommended fix: bump the p50 budget to 15 ms (3× current) and
  guard the entire test behind `#[ignore]` on `target_os = "macos"`
  when running under `CI=true`, OR move it to a `--features perf-smoke`
  bench so it doesn't run by default. R3.

No other flakes were observed in the 10× run (iterations 2-10 all
passed cleanly within ±0.5 s of the 7-9 s baseline).

**Other latent flake risk (not triggered in this run)**

Static analysis surfaced:

- `crates/octravpn-core/src/bounded.rs:191` `ttl_sweeps_idle` uses a
  20 ms TTL + 40 ms `thread::sleep`. On a CPU-starved host the
  `sleep(40 ms)` may not actually elapse 40 ms wall — survivable, but
  thin.
- `crates/octravpn-core/src/bounded.rs:199` `get_refreshes_touch`
  uses a 50 ms TTL with two 30 ms sleeps. Same risk window.

Neither flaked in the 10× run. Loosening the TTL to 100 ms / sleeps
to 60 ms would buy a 2× safety margin essentially for free.

## 6 · Test isolation issues

### 6.1 Shared process-global state

Six tests mutate process-wide state:

| Test | File : line | Var | Guarded? |
|---|---|---|---|
| `bookmark_round_trip` | `crates/octravpn-client/src/tailnet.rs:854` | `HOME` | yes (`HOME_GUARD: Mutex<()>`) |
| `load_bookmark_accepts_raw_hex_id` | `:868` | `HOME` | yes (same mutex) |
| `passphrase_precedence_env_beats_cli_beats_config` | `crates/octravpn-client/src/discover_v2.rs:481` | `OCTRAVPN_SEALED_PASSPHRASE` | **no** |
| `resolve_token_prefers_explicit` | `crates/octravpn-node/src/mesh_ops.rs:631` | `OCTRAVPN_ADMIN_TOKEN` | **no** |
| `resolve_token_explicit_overrides_env` | `:870` | `OCTRAVPN_ADMIN_TOKEN` | **no** |
| `resolve_knock_psk_*` (3 fns) | `:877…894` | `OCTRAVPN_KNOCK_PSK` | **no** |

Risk: `cargo test` runs unit tests of the same binary in parallel by
default (8 threads on this host). The unguarded env-mutating tests
share the process global. They happen to pass today because they
each set + remove their own key, but two of them assert "env unset"
between operations and could race if another test sets the same key.

Fix: lift the `HOME_GUARD` pattern into a shared
`pub(crate) static ENV_GUARD: Mutex<()>` in each crate's test module
and acquire it in every env-mutating test. R5.

### 6.2 Filesystem-sensitive tests

`tempfile::TempDir` is used in 59 production-source test sites and
all integration tests in `crates/octravpn-node/tests/v3_boot_integration.rs`.
This is the correct pattern — each test gets its own tempdir, drop
cleans up. No tests use a fixed path under `/tmp/` for writes; the
`/tmp/x` and `/tmp/foo.toml` strings that appear in tests are
*config-parser inputs that are never opened* (asserted via
`PathBuf::from`).

### 6.3 Network-sensitive tests

43 sites bind a real port (`UdpSocket::bind("127.0.0.1:0")`,
`TcpListener::bind("127.0.0.1:0")`). All use port 0 — the kernel
allocates — so there is no fixed-port collision. The closest risk
is the DERP front test (`crates/octravpn-tun/src/derp/front.rs:545`)
which races a tiny echo server against a client; if the server
hasn't `accept()`ed by the time the client connects, the OS still
queues. Did not flake in 10 ×.

### 6.4 RNG-sensitive

Proptest is used in 9 source files (4 in `octravpn-core`, 2 in
`octravpn-tun/amnezia.rs`, plus client + node). Case counts are
explicitly low (32 / 64) and the failures regress to a stable shrink,
so `proptest-regressions/` files would normally accumulate. None
were touched in this audit run. Proptest seeding uses the default
`xorshift` PRNG which is reproducible per seed; no `cases::worker`
divergence expected.

## 7 · Snapshot / golden tests

**No `insta::assert_*` calls anywhere in the workspace.** The
following byte-pinning assertions act as ad-hoc golden tests:

| Pin | Where asserted |
|---|---|
| `MAGIC_V1 = b"OCRJ2\0\0\0"` | `receipt_journal::codec.rs:15`; verified by `migration::empty_file_decodes_to_empty_map` (`migration.rs:200`) and `migrates_v0_to_v1_on_open` (`migration.rs:227`). |
| `NGINX_404_BODY = b""` | `bearer.rs:62`; verified by `hidden_no_token_returns_404_with_nginx_body` (`bearer.rs:278`) — currently empty bytes, not a hashed body. Cross-repo contract with `headscale-api::tailscale_wire::knock::NGINX_404_BODY`. |
| `v3_state_root` "worked example" anchor | `crates/octravpn-core/src/v3_state_root.rs::tests::worked_example_anchor_is_stable` — a stability witness. |
| `auth.to_str().len() == 64` ("hex(SHA256)") | `derp/front.rs:428` — length is asserted, not value. |

These are robust *contracts* (a wire-format change must flip them),
but they're scattered, not centralised in a `snapshots/` directory,
and there is no `cargo insta review` workflow to make a "regenerate
all" obvious during refactors. R6.

The "knock nginx-404 SHA-256" pin called out in the task description
does not yet exist — `NGINX_404_BODY` is currently `b""`. If the
intent is to pin a non-empty body (e.g. real nginx 404 HTML so the
shape matches `nginx -v 1.x` on the wire), that's an explicit todo.

## 8 · Tooling state observed in this audit

- `cargo-tarpaulin` 0.35.2 installed; `--branch` is **NOT
  IMPLEMENTED** upstream. CI (`.github/workflows/ci.yml:220`) runs
  workspace line coverage to Codecov today.
- `cargo-llvm-cov` 0.8.5 installed locally. This supports branch
  coverage on nightly via `--branch`. A workspace run was not
  feasible inside this audit due to: (a) the cargo build lock being
  contended with 5+ concurrent agent worktrees building the same
  workspace, (b) disk at 83 % full (3.0 TiB of 3.6 TiB).
- `cargo-mutants` install attempted twice; both attempts stalled at
  dep-compile time. The recommended next step is to install on a
  quiescent host with `CARGO_TARGET_DIR=/tmp/mutants-install`.
- No `cargo-nextest` config in the workspace. Adopting it would give
  proper test-isolation (each test in its own process) and remove the
  shared-static risk in §6.1 essentially for free. R5b.

## 9 · Recommendations (ranked by leverage)

**R1 — Wire `cargo-llvm-cov --branch` into CI alongside (or replacing)
tarpaulin.** One CI job, ~1 hour of work, lets us answer "did this PR
move branch %?". Tarpaulin's line coverage stays useful but the
branch number is the harder one to keep up.

**R2 — Add a weekly `cargo mutants -p octravpn-core` CI job.** Not
per-PR (too slow), but a weekly run with a 7-day budget catches
test-effectiveness regressions early. Threshold: ≥ 80 % caught for
`octravpn-core`; informational for the rest.

**R3 — Soften `auto_compaction_does_not_block_bumps`.** Either widen
the p50 budget to 15 ms (already comments fsync-floor variance) or
move it to `--features perf-smoke`. Today it is the only confirmed
flake in `octravpn-core`'s suite.

**R4 — Add integration tests to `octravpn-tun` and `octravpn-obfs4`.**
Both crates have *zero* `tests/*.rs` files; all coverage is inline.
The new shielding work (amnezia + obfs4 frame layer) is exactly the
surface most likely to break with kernel-level upgrades; a real
integration test that wires the two together and pumps bytes through
would catch shape regressions immediately.

**R5 — Centralise env-mutating test guards.** Six tests mutate
`OCTRAVPN_ADMIN_TOKEN` / `OCTRAVPN_KNOCK_PSK` /
`OCTRAVPN_SEALED_PASSPHRASE` without serialisation. Promote the
`HOME_GUARD: Mutex<()>` pattern from `tailnet.rs:852` to a
`pub(crate) static ENV_GUARD: Mutex<()>` per crate, or — better —
**R5b** adopt `cargo-nextest` so each test gets its own process and
the problem disappears.

**R6 — Add snapshot tests for the canonical byte specs.** A
`snapshots/` directory with `insta::assert_snapshot!` for:
`canonical encoder bytes`, `receipt journal v1 magic + 32-byte
session-id + 8-byte sequence layout`, `state-root canonical
encoding`. The current "assert one constant equals one constant"
style is correct but invisible to refactor-time review tools.

**R7 — Pin a real nginx-404 body** if the indistinguishability claim
in `bearer.rs` ("externally indistinguishable from the disabled case
… `404` + `NGINX_404_BODY`") is to survive an `nginx` version bump.
`NGINX_404_BODY` is currently `b""`, not the literal nginx default
HTML; clarify which shape the wire contract pins.

**R8 — Loosen `bounded.rs` TTL tests.** Bump TTLs from 20-50 ms to
100 ms and sleeps to 60 ms. Free safety margin.

## 10 · Appendix — actual measurement scripts

Flake-detection invocation:

```sh
BIN=/Users/androolloyd/Development/octra/target/debug/deps/octravpn_core-d61ec11b08491ee0
for i in $(seq 1 10); do
  out=$("$BIN" --test-threads=8 2>&1)
  summary=$(echo "$out" | grep -E '^test result:' | tail -1)
  echo "iter=$i $summary"
  echo "$out" | grep -E '^test .* FAILED$'
done
```

Line-coverage invocation (workspace, on a quiescent host):

```sh
# avoid bus-locking the shared target dir
CARGO_TARGET_DIR=/tmp/octra-cov \
  cargo +nightly llvm-cov \
    --workspace \
    --branch \
    --lcov --output-path /tmp/octra-cov.lcov \
    -- --test-threads=4

# render
genhtml /tmp/octra-cov.lcov --branch-coverage -o /tmp/octra-cov-html
```

Mutation-testing invocation:

```sh
cargo install cargo-mutants --locked
cargo mutants -p octravpn-core --no-shuffle --jobs 4 \
  --output /tmp/mutants-core/ --timeout 300
```

End of audit.
