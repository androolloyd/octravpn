# OctraVPN v3 + headscale-rs + octra-foundry — Correctness + Info-Leak Audit

> Auditor: correctness + info-leak gap audit (Audit-3), read-only.
> Date: 2026-05-20.
> HEAD `octra/`        : `11f83a198b7b04e5a79ebc00a238d7326888337a`.
> HEAD `headscale-rs/` : `fd95f57f702a429126be8392624d8dda84885a7e`.
> HEAD `octra-foundry/`: `42f4b22e648b0b7726185f10252c98b8961e4765`.
> Scope: gaps left by Audit-1 (`2026-05-20-deep-security-audit.md`)
> and Audit-2 (`2026-05-20-concurrency-error-config-audit.md`).
> Tracing leaks, panic surface, error Display content, response-byte
> timing / size, padding / endian / nonce / TOCTOU / overflow
> correctness, the circle_update atomic-update swap protocol, the
> PreauthMinter redeem-then-evict order, and the CFG-1 / E-1 rollout
> prioritisation. No code changes. Doc-only.

## Top-level summary

| Severity | Total | Leaks | Correctness | Process |
| --- | ---: | ---: | ---: | ---: |
| BLOCKER  | 1 | 0 | 1 | 0 |
| HIGH     | 6 | 3 | 3 | 0 |
| MEDIUM   | 9 | 3 | 4 | 2 |
| LOW      | 7 | 4 | 2 | 1 |
| ADVISORY | 3 | 1 | 0 | 2 |
| **Total**| **26** | **11** | **10** | **5** |

Three biggest themes: (1) receipt-journal async-compaction **phase-3
crash window** drops bumps that landed during phase-2 — even on POSIX
FS — a slashable seq-regression (NEW BLOCKER, scope-extends prior
M-5). (2) `BearerCheck::Strict` returns a different *body size* for
"token unset" (503 + 67 bytes) vs "wrong bearer" (401 + 0 bytes) — a
configuration-state oracle visible to any unauthenticated scanner.
(3) Multiple `Debug`-deriving structs carry secret or plaintext bytes
(`BlobUpdate.plaintext`, `PreauthAdminKey.key`, six `Option<String>`
secret fields in `NodeConfig`); none is actively logged today, but
the derive is a footgun one `?cfg` / `?bundle` / `?row` edit away
from active.

---

## BLOCKER — count: 1

### B-1 [CORRECTNESS] Receipt-journal async-compaction phase-3 crash regresses seq floor

- **Status:** Fixed in commit `4eb9339` (single-tempfile single-rename
  commit; delta-replay now happens INTO the tempfile BEFORE the
  rename, so the rename atomically swaps in a complete journal). 6
  new crash-injection tests cover the three crash points (after
  phase-2 snapshot, after deltas before rename, after rename). See
  `crates/octravpn-core/src/receipt_journal/README.md` ("single-
  tempfile snapshot/swap protocol") for the post-fix atomicity
  contract.
- File: `crates/octravpn-core/src/receipt_journal/compact.rs:64-138`,
  `mod.rs:191-273`.
- Category: chain / slashable.
- Description: `compact_async_worker` is 3-phase:
  1. **P1** (under lock, in `bump`): snapshot `by_session` + mark
     `compaction_inflight`.
  2. **P2** (no lock): write `tmp_path` + fsync. Concurrent `bump`
     keeps appending records to the OLD inode + updating
     `by_session`.
  3. **P3** (under lock): drop handle to old inode → `fs::rename
     (tmp_path, path)` → reopen handle on new inode → **delta-
     replay**: for `seq > snapshot[id]`, append a record →
     `sync_data`.
  The window: rename at compact.rs:93 commits BEFORE delta-replay at
  108-119. SIGKILL / panic / power-fail in this window discards the
  bumps that landed in P2 — they were written only to the old inode
  (now unreferenced after rename; in-mem `by_session` lost with the
  process).
- Impact: slashable. On next boot, `replay_v1` of the new file
  yields a floor lower than what the daemon committed *before* P3.
  Daemon signs at `seq ≤ prev_committed_seq` → on-chain double-sign
  → `slash_double_sign` burns the operator bond.
- Why Audit-1 M-5 didn't cover this: M-5 only flagged non-POSIX FS
  (overlayfs / NFS) where `rename(2)` itself is non-atomic. This is
  POSIX where rename is atomic but the delta-replay is not durable.
- Proposed fix: either (a) extend the lock window — snapshot + delta
  + rename + fsync all under lock (loses lock-free P2 win, but
  eliminates the window); or (b) persist a `delta_pending.bin`
  sidecar before P3 rename; on boot replay-merge it.
- Test: integration test that hammers `bump` past the watermark and
  races a kill-9 in P3, asserts on reboot the floor equals the
  highest committed seq pre-kill.
- Lean coverage: `proofs/lean/OctraVPN_Rust/Lemmas.lean` proves
  monotonicity under "rename atomic" — that axiom does NOT entail
  "compaction durable". Add a Lean axiom that the delta is fsync'd
  before the journal lock releases.

---

## HIGH — count: 6

### H-1 [LEAK] `BearerCheck::Strict` body-size oracle leaks token-unset vs wrong-token

- File: `crates/octravpn-core/src/bearer.rs:170-187`,
  `crates/octravpn-node/src/control/state.rs:357-365`.
- Description: `/metrics` uses `BearerCheck::strict(token,
  "metrics endpoint disabled: set [control].metrics_token in
  node.toml")`. Three responses:
  - token unset: `(503, 67 bytes,` `b"metrics endpoint disabled:
    set [control].metrics_token in node.toml")`.
  - header missing OR wrong: `(401, 0 bytes, b"")`.
- Exact bytes leaked: an unauthenticated `GET /metrics` always
  yields either `(503, "metrics endpoint disabled…")` OR `(401,
  "")`. Passive scanner distinguishes "operator never configured"
  from "endpoint configured, no token". A *configuration state*
  oracle.
- Impact: aids enumeration. Combined with M-2 below, the 503 body
  literally tells the scanner which TOML key to set.
- Proposed fix: unify on `(503, "")` or `(401, "")`. Operator-side
  scrape failure surfaces via the configured-or-not check at scrape
  config time, not by HTTP-body content.
- **Fixed in commit `7d016618155c`** — `BearerCheck::Strict` and
  `BearerCheck::Hidden` now share one reject path: `(404,
  NGINX_404_BODY)` for every reject reason (token unset, header
  missing, wrong scheme, wrong token). The 503-with-text body became
  a boot-time `tracing::warn!` log line emitted by
  `BearerCheck::warn_if_unconfigured`, called by
  `Hub::spawn_control_plane` for every Strict-policy check.
  `crates/octravpn-core/src/bearer.rs::tests::bearer_failure_byte_identical_across_all_reject_reasons`
  pins the byte-stable wire shape across every reject reason
  (sha256 of body =
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`,
  the sha256 of the empty string — same as the knock-route 404 the
  nginx default-page emits).

### H-2 [LEAK] `Debug` derive on `UpdateBundle` / `BlobUpdate` exposes plaintext blob bytes

- File: `crates/octravpn-node/src/circle_update.rs:82-100, 203-211`.
- Description: `BlobUpdate` is `#[derive(Clone, Debug)]` and carries
  `pub plaintext: Vec<u8>`. `UpdateBundle` is `#[derive(Clone,
  Debug)]` with `pub blobs: Vec<BlobUpdate>`. Plaintext is the
  pre-encryption bytes of every sealed asset: `policy.json` (the
  tailnet's ACL), `wg.pub` (operator's WG pubkey — public),
  `state-root.json` (anchor + member count — public),
  `attestation.json` (operator's TEE quote — sensitive).
- Exact bytes that would leak: any `tracing::debug!(?bundle)` or
  `tracing::info!(?blob)` writes the **plaintext** policy.json /
  attestation.json bytes to the operator's log. `Vec<u8>`'s `Debug`
  emits every byte as the standard Rust slice format.
- Impact: zero today (no `?bundle` / `?blob` log site at this HEAD).
  One edit away from active.
- Proposed fix: hand-written `Debug` for `BlobUpdate` printing
  `plaintext_len` only. Wrap `plaintext` in `zeroize::Zeroizing<
  Vec<u8>>` for defense in depth.
- Test: `assert!(!format!("{:?}", bundle).contains("my-secret-
  policy"))`.

### H-3 [LEAK] HashMap-keyed bearer lookup in `InMemoryLeaseStore::validate_token` is timing-side-channel

- File: `headscale-rs/headscale-api/src/gateway/auth.rs:81-92`.
- Description: `tokens.get(token)` on `HashMap<String, …>`. Rust's
  string `PartialEq` short-circuits on first mismatched byte (NOT
  constant-time). An attacker who submits ~10^6 bearer guesses and
  measures latency recovers the token byte by byte.
- Exact bytes that leak: response latency reveals which leading
  bytes match an installed token; the standard CVE-2007-2454-style
  recovery.
- Impact: the impl is the "in-memory testing store" but
  `LeaseStore` is a `dyn`-trait — a production impl inheriting the
  same shape silently inherits the vulnerability.
- Proposed fix: production impls must index on a non-secret token
  id (first 16 bytes) then constant-time-compare the remaining
  bytes. Document the contract on the trait.
- Test: micro-benchmark that asserts latency variance between
  matching and non-matching first-byte tokens is below a noise
  floor.

### H-4 [CORRECTNESS] `circle_update::apply` writes /state-root.json AFTER the anchor flip

- File: `crates/octravpn-node/src/circle_update.rs:471-619`.
- Description: module docstring (13-37) declares "blobs first,
  anchor second". The actual flow:
  1. L518-560: write policy.json / wg.pub blobs.
  2. L563-569: submit anchor update tx.
  3. L571-612: NOW write `/state-root.json` (the meta-blob).
  Between (2) and (3) the anchor points to a state-root JSON hash
  whose bytes are NOT yet on chain. A verifier polling here sees
  the new anchor → fetches `/state-root.json` → gets the OLD bytes
  → anchor mismatch → rejects the circle.
- Impact: if the operator dies between (2) and (3), the meta-blob
  never lands. `retry_anchor` won't help (anchor already flipped).
  `list_orphaned_blobs` (L657) doesn't probe `/state-root.json`.
  No automated recovery — operator must reconstruct expected JSON
  bytes and re-submit `circle_asset_put_encrypted` manually.
- Comment at L571-574 says "same-block ordering covers it" but
  Octra doesn't enforce intra-block ordering between
  `contract_call` and `circle_asset_put_encrypted`.
- Proposed fix: promote the meta-blob to be the FIRST blob written
  (before policy.json / wg.pub). Order becomes meta-blob → other
  blobs → anchor. Anchor cannot land before all blobs are durable.
- Test: integration test that interrupts after step 2, asserts
  subsequent `list_orphaned_blobs` reports `/state-root.json` as
  orphaned + provides a recovery path.

### H-5 [CORRECTNESS] Receipt-journal `bump` panics on closed handle

- File: `crates/octravpn-core/src/receipt_journal/mod.rs:208-212`.
- Description:
  ```rust
  let handle = g.handle.as_mut()
      .expect("path is Some so handle must be Some");
  ```
  Invariant "path Some ⇒ handle Some" is enforced by `open()` and
  by the compaction routine on success. On a P3 compaction failure
  between `g.handle = None` (compact.rs:87) and the reopen attempt
  (compact.rs:102), the handle is left `None` while `path` stays
  `Some`. Concurrent `bump` in this window panics.
- Impact: process crash. Panic propagates up; the daemon exits.
  On restart `open()` re-creates the handle cleanly, but in-flight
  signatures are lost. Combined with B-1, panicking in the same
  window worsens the seq-regression probability.
- Proposed fix: replace `expect` with `ok_or_else(|| JournalError::
  HandleClosed { path: g.path.clone().unwrap().display().to_string()
  })?`. Add `HandleClosed` variant.
- Test: simulate P3 reopen failure (read-only parent), call `bump`
  during compaction, assert `JournalError::HandleClosed` rather
  than panic.

### H-6 [LEAK] Six secret `Option<String>` fields in `NodeConfig` are `Debug`-derived (Audit-2 CFG-2 cross-ref + exact-bytes detail)

- File: `crates/octravpn-node/src/config.rs:253, 283, 353, 557, 567, 590`.
  All `Deserialize` blocks (`NodeConfig`, `ChainCfg`, `AnalyticsCfg`,
  `Obfs4Cfg`, `ControlCfg`, `AttestationCfg`) derive `Debug`.
- Description: this is Audit-2 CFG-2 restated with the *exact-bytes*
  detail. A single `tracing::debug!(?cfg)` in `hub.rs` / `main.rs` /
  `pvac.rs` writes:
  - `obfs4.bridge_identity_secret: Some("a1b2c3…")` — 64-char hex.
  - `analytics.bearer_token: Some("…")` — operator's metrics bearer.
  - `chain.sealed_passphrase: Some("…")` — the MASTER passphrase
    that unseals every other key on the box.
  - `control.events_token: Some("…")`.
  - `control.metrics_token: Some("…")`.
  - `control.admin_token: Some("…")`.
- Active check: `grep -rEn 'tracing::(debug|info|warn|error)!
  .*\?cfg' crates/octravpn-node/src/` returns 0 hits. Dormant.
- Proposed fix: per Audit-2 CFG-2, wrap each in `secrecy::
  SecretString`. Defense in depth: add a test that asserts
  `format!("{:?}", cfg)` does not match `[0-9a-f]{40,}` or
  `r#"Bearer "#`.

---

## MEDIUM — count: 9

### M-1 [LEAK] `JournalError::ChecksumMismatch.path` echoes full FS path

`crates/octravpn-core/src/receipt_journal/codec.rs:49-53`. Error
carries `path: path.display().to_string()` →
`/var/lib/octravpn/receipts.bin, offset: 584`. Reveals deployment
layout to log consumers. Fix: hashed or relative path.

### M-2 [LEAK] `/metrics` 503 body contains the config knob name

`crates/octravpn-node/src/control/state.rs:361-364`. The 503 body
literally says `"set [control].metrics_token in node.toml"` —
direct hint at the next step for a scanner. Fix: `"endpoint not
configured"` or empty.

### M-3 [LEAK] `UpdateError::BlobPutFailed.source` echoes chain RPC payload

`crates/octravpn-node/src/circle_update.rs:230-250`. Audit-2 E-4
pattern; `source: anyhow::Error` carries echoed tx bytes (incl.
signature). Sig bytes alone aren't useful; the *pattern* of which
tx kinds fail does reveal state. Fix: `Redacted<String>` newtype +
scrub `0x[0-9a-f]{64,}`.

### M-4 [CORRECTNESS] `file_size += record.len()` not `saturating_add`

`crates/octravpn-core/src/receipt_journal/mod.rs:225`. u64 overflow
requires ~10^17 records — infeasible but a lint catches the next
record-size bump. Fix: `saturating_add`.

### M-5 [CORRECTNESS] `now_unix() == 0` on clock failure in preauth

`crates/octravpn-mesh/src/headscale_bridge/preauth.rs:352-357`.
Same shape as Audit-1 L-3 (knock). Clock-error → `now = 0` →
`expires_at = ttl_secs` → key instantly expired. Audit log surfaces
`created_at = 0` rows. Fix: `Err(ClockBroken)`, refuse mint.

### M-6 [CORRECTNESS / SAFE TODAY] `NonceStore::check_and_store` retain-sweep keyed on attacker timestamp

`headscale-rs/headscale-api/src/control_auth.rs:52-71`,
`gateway/auth.rs:98-114`. `oldest_allowed = timestamp_millis.
saturating_sub(SIGNATURE_WINDOW_MILLIS)`. The retain key is the
request's timestamp. In control_auth and gateway/auth the timestamp
is pre-validated at L216-219 / L231-236 — SAFE today. A future
refactor that moves `check_and_store` without pre-validation lets
an attacker grow the per-DID nonce map unboundedly via
`timestamp_millis = 0`. Fix: clamp inside via
`timestamp_millis.min(now_millis())`.

### M-7 [LEAK] Knock warn-line includes `KnockPskError::BadLength(N)`

`crates/octravpn-mesh/src/knock.rs:80-150` + middleware callers.
Rejected knocks return byte-identical 404 + NGINX body (Audit-1
L-5), but warn-level logs emit the PSK *length*. Combined over many
probes, attacker confirms parse-state via timing on the rate-
limited path. Fix: single "knock rejected" log; drop length.

### M-8 [PROCESS] `#[non_exhaustive]` missing on 12 public + 6 crate-private error enums (Audit-2 E-1 inventory)

- Files with `pub enum *Error` missing the attribute:
  - `octravpn-core/src/onion.rs:46 OnionError`
  - `octravpn-core/src/receipt.rs:186 ReceiptError`
  - `octravpn-core/src/receipt_journal/errors.rs:8 JournalError`
  - `octravpn-core/src/v3_state_root.rs:72 StateRootError`
  - `octravpn-core/src/v3_policy.rs:102 V3PolicyError`
  - `octravpn-core/src/v3_members.rs:120 V3MembersError`
  - `octravpn-mesh/src/stun.rs:37 StunError`
  - `octravpn-mesh/src/lib.rs:62 MeshError`
  - `octravpn-mesh/src/knock.rs:154 KnockPskError`
  - `octravpn-mesh/src/headscale_bridge/preauth.rs:342 RedeemError`
  - `octravpn-obfs4/src/frame.rs:68 FrameError`
  - `octravpn-obfs4/src/handshake.rs:104 HandshakeError`
  - `octra-circle-sim/src/chain.rs:39 ChainError`
  - `octravpn-client/src/portal/chain/errors.rs:21 FetchAssetError`
  Crate-private (P2): `pvac.rs:116 PvacError`,
  `circle_update.rs:230 UpdateError`, `audit_cli.rs`,
  `audit/verify.rs`.
- Land the `pub` cases first.

### M-9 [PROCESS] `#[serde(deny_unknown_fields)]` missing on 38 Deserialize files

- See A-2 rollout below. Workspace-wide grep: 38 `.rs` files with
  `Deserialize` derives and zero `deny_unknown_fields`.

---

## LOW — count: 7

- **L-1 [LEAK]** `crates/octravpn-node/src/seal.rs:250-254`. `tracing::
  info!(label, src, dst, "seal-keys: wrote sealed envelope")` tells a
  log-consumer exactly where the plaintext used to live before
  sealing.
- **L-2 [LEAK]** `crates/octravpn-node/src/circle_update.rs:641`.
  Anchor + tx hash logged on every flip. Public on chain, but
  combined with log timestamps reveals operator activity timing.
- **L-3 [LEAK]** `crates/octravpn-core/src/receipt_journal/errors.rs:
  8+`. `JournalError::SeqNotMonotonic` `Display` emits session id
  hex + floor + proposed — leaks state-machine internals.
- **L-4 [CORRECTNESS]** `crates/octravpn-node/src/seal.rs:214-238`.
  TOCTOU: `if target.dst.exists() { fs::read(...) }` then later
  `atomic_write`. Local FS write — out of threat-model scope.
- **L-5 [LEAK]** `headscale-rs/headscale-api/src/admin/preauth.rs:
  34-62`. `pub struct PreauthAdminKey { pub key: String, … }` with
  `#[derive(Debug)]`. Any `tracing::debug!(?row)` dumps the bearer
  plaintext. No active leak today. Fix: hand-written `Debug` →
  `key_prefix(self.key)` only.
- **L-6 [CORRECTNESS]** `crates/octravpn-obfs4/src/frame.rs:153,
  224`. obfs4 counter `wrapping_add` unchanged at this HEAD. Audit-1
  H-2 already covers; noted to confirm no in-flight fix landed.
- **L-7 [PROCESS]** Workspace `Cargo.toml` lacks
  `clippy::await_holding_lock`. Audit-2 C-11 noted parking_lot
  `Mutex` held across `.await` is a deadlock footgun across ~30
  sites. Add to `[workspace.lints.clippy]` as `warn`.

---

## ADVISORY — count: 3

### A-1 [PROCESS] CFG-1 deny_unknown_fields rollout — prioritized order

By blast-radius per misconfiguration:

| Order | Struct | File:line | Why first |
|------:|--------|-----------|-----------|
| 1 | `NodeConfig` | `config.rs:68` | Top-level; typo orphans an entire block |
| 2 | `ChainCfg` | `config.rs:323` | `chain_id` typo → wrong-network receipts (Audit-2 CFG-5) |
| 3 | `ControlCfg` | `config.rs:539` | All bearer-token fields; typo → silent 404 |
| 4 | `AnalyticsCfg` | `config.rs:264` | `bearer_token` typo → silent 503 |
| 5 | `Obfs4Cfg` | `config.rs:239` | `bridge_identity_secret` typo → handshake refuses |
| 6 | `AttestationCfg` | `config.rs:628` | Low blast radius (`poll_interval_secs` only) |
| 7 | `PvacCfg`, `TunCfg`, `TransportCfg`, `AmneziaCfg`, `PricingCfg` | various | P2 — operator knobs |

First 5 are the security-relevant config blocks. Land them in one
PR with one TOML-typo unit test per block (5 tests total).

### A-2 [PROCESS] Audit-3 confirms `PreauthMinter` redeem-then-evict order is correct

- File: `crates/octravpn-mesh/src/headscale_bridge/preauth.rs:277-308`.
- Redeem path line by line:
  1. lock `seq`.
  2. `mints.get(&key)` (immutable lookup).
  3. expiry check; on expired → remove + return `Expired`.
  4. on non-reusable → `mints.remove(&key)` BEFORE record-insert.
  5. insert into `redemptions` audit map.
  6. drop lock, emit metrics.
- A single-use replay after step 4 sees `mints.get` return None →
  `RedeemError::Unknown`, matching never-minted shape. Verified by
  tests at `preauth.rs:382-388` (single_use_redeem_consumes_key)
  and `mints_capacity_evicts_oldest:444+` (asserts evicted-key
  lookup returns None).

### A-3 [PROCESS] octra-foundry `wallet_enc` clean

- File: `octra-foundry/crates/octra-core/src/wallet_enc.rs`.
- ChaCha20-Poly1305 envelope + PBKDF2-200k KEK. Proptests cover
  encrypt/decrypt roundtrip, bit-flip rejection, truncated envelope
  rejection, wrong-passphrase rejection. `Zeroizing<[u8; 32]>` KEK,
  `plain.zeroize()` after decrypt. No findings.

---

## Top-3 highest-impact leaks (with exact bytes)

1. **H-2 — `Debug` derive on `BlobUpdate` / `UpdateBundle`** —
   `crates/octravpn-node/src/circle_update.rs:82-100, 203-211`. A
   future `tracing::debug!(?bundle)` line dumps the plaintext bytes
   of every sealed asset: `policy.json` (full tailnet ACL JSON),
   `wg.pub` (operator's WG public key — public), `state-root.json`
   (anchor + member count + region — public), AND
   `attestation.json` (operator's TEE quote — sensitive). Today
   dormant; one `?bundle` away from active. Mitigation: hand-write
   `Debug` to print `plaintext_len` only.

2. **H-1 — `BearerCheck::Strict` 503-body oracle** —
   `crates/octravpn-core/src/bearer.rs:170-177`. Unauthenticated
   `GET /metrics` returns either `(503, 67 bytes,` `b"metrics
   endpoint disabled: set [control].metrics_token in node.toml")`
   (token unset) OR `(401, 0 bytes, b"")` (token set, header
   missing/wrong). Body content + byte-count is a passive oracle
   for "is this operator misconfigured?". Mitigation: unify both
   on `(503, "")` or `(401, "")`.

3. **H-6 / CFG-2 — six secret `Option<String>` fields with `Debug`
   derive on `NodeConfig`** — `crates/octravpn-node/src/config.rs:
   253, 283, 353, 557, 567, 590`. A single `tracing::debug!(?cfg)`
   in `hub.rs` / `main.rs` dumps:
   `obfs4.bridge_identity_secret: Some("a1b2c3…")` (64-char hex),
   `analytics.bearer_token: Some("…")`, `chain.sealed_passphrase:
   Some("…")` (the master passphrase), `events_token`,
   `metrics_token`, `admin_token` — all in quoted-string form.
   Today no `?cfg` log exists; the derive is the live attack
   surface.

---

## Out of scope

Lean proof verification (CI), dependency CVE scan (see Audit-1
references), AML chain semantics beyond Audit-1 / Audit-2 coverage,
container/kernel surface, octra-foundry chain runtime beyond the
`wallet_enc` consumers (verified clean — see A-3).

## Reproduction

```
cd /Users/androolloyd/Development/octra && git rev-parse HEAD
# 11f83a198b7b04e5a79ebc00a238d7326888337a
grep -n 'fs::rename\|handle.sync_data' \
    crates/octravpn-core/src/receipt_journal/compact.rs   # B-1
grep -n 'disabled_body\|SERVICE_UNAVAILABLE' \
    crates/octravpn-core/src/bearer.rs                    # H-1
grep -n '#\[derive.*Debug' \
    crates/octravpn-node/src/circle_update.rs             # H-2
grep -n 'tokens.get\|validate_token' \
    ../headscale-rs/headscale-api/src/gateway/auth.rs     # H-3
sed -n '560,612p' crates/octravpn-node/src/circle_update.rs  # H-4
grep -n 'expect("path' \
    crates/octravpn-core/src/receipt_journal/mod.rs       # H-5
grep -rln 'pub enum.*Error' crates/ --include='*.rs' \
    | xargs grep -L 'non_exhaustive'                      # M-8
```
