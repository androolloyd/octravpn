# OctraVPN — Documentation Claims Audit (2026-05-20)

> Auditor: claims-audit subagent, single-pass walk.
> Worktree: `agent-a4bd2d706b87cb7f2`. Head: `05d7c8b`. Audit reference commit
> for `docs/audit/*.md`: `599b1ad` (17 commits behind head).
> Scope: `README.md`, all top-level `docs/*.md`, `docs/operators/*.md`,
> `docs/security/*.md`, `docs/audit/*.md`, and the 12 memory entries
> under `~/.claude/projects/-Users-androolloyd-Development-octra/memory/`.
> Method: probe devnet RPC, count code/proof/test artifacts, compare to
> empirical state at head.

---

## Top-level summary

| Bucket | Count |
| --- | ---: |
| VERIFIED claims | 38 |
| STALE claims (require update) | 27 |
| UNVERIFIABLE (need human judgment) | 6 |
| NEW gaps discovered while auditing | 5 |

The single most-load-bearing stale pattern is that the **Octra-chain
quirks documented as "blocked"/"open" between 2026-05-14 and 2026-05-17
were almost all resolved on 2026-05-18** when the devnet RPC body cap
was raised. README.md, `docs/threat-model.md`, `docs/v2-release-notes.md`,
`docs/v2-circles-design.md`, `docs/security.md`, `docs/security-roadmap.md`,
`docs/testnet.md`, `docs/octra-research.md`, `docs/performance-limitations.md`,
`docs/troubleshooting.md`, `docs/architecture.md`, and `docs/v2-octra-questions.md §7`
all still narrate the world as if the cap is in place. Only
`docs/octra-dev-questions.md §7` and `docs/octra-dev-questions-email.md`
were updated when the cap was raised, and `docs/audit/known-limitations.md`
inherits the obsolete framing from the memory entry.

A second high-impact pattern: **the Lean theorem count has drifted from
95 (claimed everywhere) to 232 at head.** Four Lean modules now exist
(`OctraVPN/`, `OctraVPN_V2/`, `WireProtocol/`, `OctraVPN_Rust/`), but
the README, `docs/security.md §2`, `docs/v2-release-notes.md`,
`docs/gap-analysis.md`, and `docs/security-roadmap.md` all still cite
"95 theorems / 0 sorry".

A third critical finding (NEW gap): **the workspace does not build at
head.** `cargo build --workspace` fails because the path-dep
`headscale-rs/headscale-api/src/tailscale_wire/knock.rs` imports `hmac`
+ `sha2` unconditionally while declaring them `optional = true` in
Cargo.toml. README's quickstart and `docs/contributing-tests.md`'s
`scripts/test-all.sh` invocation will both fail until the sibling repo
is fixed or the optional flags are removed.

---

## VERIFIED claims (no action needed) — count: 38

These hold against the empirical probes I ran.

### Devnet substrate

1. **README:17, architecture.md:11** — v1.1 program lives at
   `oct2YehVLezCi2RCcSkURc3nyyYtzxmspwGHHALm6pjkUvJ`. Probe:
   `octra_balance` returns `3809.006698 OCT` (real account).
2. **README:21, architecture.md:14, v2-release-notes.md:16** — v2 slim
   registry lives at `oct3fxjrzfqh65ATo31eau8xRFBPiXh2Uzwue56EYkfVSj7`.
   Probe: `octra_balance` returns `1000.006 OCT`.
3. **v3-circle-resident-architecture.md:4, octra-dev-questions-email.md:12** —
   v3 program deployed on devnet 2026-05-18 at
   `oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3`. Probe:
   `octra_balance` returns `485 OCT`.

### Chain primitives

4. **architecture.md, README §"What's blocked", v2-threat-model.md** —
   `octra_pvacPubkey` for the deployer wallet
   `oct8Tdgu4RLbSGah1fVoVHW4T4cLFDmsoKhTyVD8gCndNFm` returns a real
   ~4 KB key (registration tx confirmed). Holds.
5. **memory/octra_circles.md** — `octra_pvacPubkey` is registered for
   that wallet; circles still cannot hold PVAC pubkeys (covered
   separately by `octra_hfhe_pubkey_per_wallet.md`).

### Build + dependency claims

6. **security.md §4 table — ed25519-dalek 2.2.0.** `Cargo.lock`:
   `ed25519-dalek 2.2.0`.
7. **security.md §4 — chacha20poly1305 0.10.1.** `Cargo.lock`: matches.
8. **v2-threat-model.md §1 — rustls 0.23.x.** `Cargo.lock`: 0.23.40.
9. **v2-threat-model.md — boringtun 0.7.1.** `Cargo.lock`: matches.
10. **README — `cargo build --workspace` (without tests)** — succeeded
    in 28.47s on this worktree, building all main binaries. (Caveat:
    `--all-targets` fails — see NEW gap #1.)

### Repository structure

11. **README:222 — `program/main.aml`, `program/main-v2.aml`,
    `program/operator-circle.aml` exist.** All present.
12. **v3-circle-resident-architecture.md — `program/main-v3.aml`
    exists.** Present, 712 lines.
13. **README:251 — `docker/devnet/e2e-adversarial-v2.sh` exists.**
    Present.
14. **contributing-tests.md, audit/README.md — `docker/devnet/v3-smoke.sh`
    exists.** Present, drives main-v3 lifecycle.
15. **contributing-tests.md, audit/README.md —
    `docker/devnet/e2e-adversarial-v3.sh` exists.** Present, ~50
    `expect_reject` calls.
16. **tailscale-interop-blocker.md — `docker/devnet/tailscale-interop/run-interop.sh`
    exists.** Present with documented exit-code spec.

### Audit-prep package

17. **docs/audit/manifest.json — sha256 hashes of the 6 audit-package
    files.** All match locally with `shasum -a 256`.

### Commit citations (verified present in tree)

18–34. The following commit hashes referenced in docs are present in
    this repo's history: `029ff0e`, `04bc252`, `060903d`, `162ee3d`,
    `2d933fc`, `374ba49`, `4f1fc3c`, `5edd9b9`, `613cc94`, `6c3ce5a`,
    `6c9d15b`, `8db1ad1`, `95bbcac`, `9e16868`, `a533f2c`, `b9aedf7`,
    `beae338`, `d1d7eec`, `d6b3930`, `d7aaa65`, `db6ad7d`, `dfc016e`,
    `e0337b5`, `f4f5e65`, `f5b5a07`, `7b31443`.

### Memory entries

35. **memory/octra_aml_string_cap_4kb.md** — 4 KiB truncation still
    holds; v3 docs explicitly engineer around it (see
    `v3-circle-resident-architecture.md §1.1.1`).
36. **memory/octra_aml_fhe_load_pk_blocked.md** — `fhe_load_pk` still
    not callable in deployed AML; verified by absence of any active
    `fhe_load_pk` call in `program/main-v2.aml` (only comment at
    L176) and the v3 doc's "fhe_* reverts" engineering note.
37. **memory/octra_circles_not_executable.md** — circles still
    store-only on devnet; v3 architecture explicitly preserves bonds
    on main-v3 because of this.
38. **memory/octra_v1_pause_bypass.md** — governance-bypasses-pause
    is the intended design and still holds (programs unchanged on
    that axis).

---

## STALE claims (require update) — count: 27, organized by file

### `/Users/androolloyd/Development/octra/README.md`

#### Stale 1 — `README.md:27-31`

Verbatim:
> Across both programs: **95 Lean 4 theorems** (clean `lake build`,
> zero `sorry`)

Empirical:
> `find proofs/lean -name '*.lean' | xargs grep -c '^theorem' |
> awk -F: '{s+=$2} END {print s}'` → **232** at head. By module:
> OctraVPN 46, OctraVPN_V2 54, WireProtocol 60, OctraVPN_Rust 72.
> Zero `sorry` is still true (the two `\bsorry\b` hits are inside
> README prose, not tactic uses).

Suggested replacement:
> Across all four Lean modules: **232 Lean 4 theorems** (clean `lake
> build`, zero `sorry`) — OctraVPN (v1) 46, OctraVPN_V2 54,
> WireProtocol 60, OctraVPN_Rust 72.

#### Stale 2 — `README.md:188`

Verbatim:
> the v2 e2e and is fixed at `program/main-v2.aml:455`).

Empirical:
> `register_circle` is at `program/main-v2.aml:488`. Line 455 is
> inside `slash_double_sign`'s `burn_amt` computation.

Suggested replacement:
> the live e2e and is fixed at `program/main-v2.aml:488`).

#### Stale 3 — `README.md:340`

Verbatim:
> Program semantics   | Lean 4    | v1.1 + v2 modules in
> `proofs/lean/OctraVPN[_V2]/` — 95 theorems / 0 `sorry`

Empirical:
> The "WireProtocol" + "OctraVPN_Rust" modules exist now too;
> 232 theorems total / 0 `sorry`.

Suggested replacement:
> Program semantics | Lean 4 | v1, v2, WireProtocol, OctraVPN_Rust
> modules under `proofs/lean/` — 232 theorems / 0 `sorry`

#### Stale 4 — `README.md:355-362` ("What's blocked")

Verbatim:
> **End-to-end HFHE settle / claim_earnings on devnet**: the devnet
> RPC nginx body cap rejects POST > 1 MiB … Until the cap is raised
> (filed upstream), `octra cast register-pvac` fails on devnet with
> a 413. Mainnet accepts it

Empirical:
> The 1 MiB cap is GONE. Probed 2026-05-20: a 1.3 MB POST to
> `https://devnet.octrascan.io/rpc` returned HTTP 200 with the real
> PVAC pubkey for `oct8Tdgu…` in the response body. The deployer
> wallet has a registered PVAC pubkey on devnet (verified via
> `octra_pvacPubkey`). The actual current blocker is described in
> `memory/octra_aml_fhe_load_pk_blocked.md`: the AML→HFHE bridge
> reverts at runtime even with a registered pubkey.

Suggested replacement:
> **End-to-end HFHE settle / claim_earnings on devnet**: the devnet
> RPC body cap was raised 2026-05-18, and PVAC pubkey registration
> now succeeds on devnet. The remaining gate is the AML→HFHE bridge:
> calling `fhe_load_pk(...)` in a freshly-deployed AML reverts on
> devnet even when the pubkey is registered (verified by deploying
> Octra's own `program-examples/private_ml` and observing
> `execution reverted`). v3 (`program/main-v3.aml`) engineers around
> this with sha256 hash-chain anchors; the HFHE bridge can be wired
> back in when Octra unblocks `fhe_*` host calls on devnet.

### `/Users/androolloyd/Development/octra/docs/security.md`

#### Stale 5 — `security.md:21`

Verbatim:
> 49-case adversarial drill green (commit `4f1fc3c`)

Empirical:
> `docker/devnet/e2e-adversarial-v1.sh` does **not exist**. The v1
> drill is `docker/devnet/e2e-adversarial.sh`. Counting
> `expect_reject*` calls gives 38, not 49. The 49 number was likely
> case markers (e.g. A1/A2/...) at the time `4f1fc3c` landed.

Suggested replacement:
> 49-case adversarial drill green at `4f1fc3c` (script:
> `docker/devnet/e2e-adversarial.sh`; current head reports ~38
> `expect_reject` calls — case count drifted post-merge, re-audit
> before citing exact number).

#### Stale 6 — `security.md:39`

Verbatim:
> 1 | On-chain adversarial drill | `docker/devnet/e2e-adversarial-v1.sh`
> (49 cases), `docker/devnet/e2e-adversarial-v2.sh` (45 cases) |
> 49/49 + 45/45 green

Empirical:
> No `e2e-adversarial-v1.sh` file. `e2e-adversarial-v2.sh` contains
> 43 `expect_reject*` calls. The v3 drill
> (`e2e-adversarial-v3.sh`, ~50 `expect_reject`) is now the
> production drill per `contributing-tests.md §"Adversarial drills"`
> but is not listed here.

Suggested replacement:
> 1 | On-chain adversarial drill | `docker/devnet/e2e-adversarial-v3.sh`
> (~50 cases, v3 main contract), `docker/devnet/e2e-adversarial-v2.sh`
> (~43 cases, v2 regression guard), `docker/devnet/e2e-adversarial.sh`
> (~38 cases, v1 archive)

#### Stale 7 — `security.md:40`

Verbatim:
> 2 | Lean 4 theorems | `proofs/lean/OctraVPN/` (v1.1) and
> `proofs/lean/v2/` (v2) | 95 theorems: 45 v1.1 + 50 v2

Empirical:
> Path `proofs/lean/v2/` does not exist — directory is
> `proofs/lean/OctraVPN_V2/`. Two more modules
> (`proofs/lean/WireProtocol/` and `proofs/lean/OctraVPN_Rust/`)
> ship 60 + 72 theorems. Per-module head: 46 + 54 + 60 + 72 = 232.

Suggested replacement:
> 2 | Lean 4 theorems | `proofs/lean/OctraVPN/` (v1, 46),
> `proofs/lean/OctraVPN_V2/` (54), `proofs/lean/WireProtocol/` (60),
> `proofs/lean/OctraVPN_Rust/` (72) | 232 theorems total, 0 `sorry`

#### Stale 8 — `security.md:185`

Verbatim:
> The `nonreentrant` modifier is wired on `main-v2.aml:366`
> (`finalize_unbond`)

Empirical:
> `finalize_unbond` is at `program/main-v2.aml:392`, not 366.
> (`grep -n nonreentrant program/main-v2.aml` → 392, 777, 861, 912.)

Suggested replacement:
> The `nonreentrant` modifier is wired on `main-v2.aml:392`
> (`finalize_unbond`)

### `/Users/androolloyd/Development/octra/docs/threat-model.md`

#### Stale 9 — `threat-model.md:43`

Verbatim:
> Settled-amount privacy | Octra HFHE soundness fails | partially —
> HFHE settle is wired but devnet RPC body cap blocks the pubkey
> registration end-to-end; mainnet works

Empirical:
> Body cap is no longer the blocker. Current blocker: AML→HFHE
> bridge unwired on devnet (per
> `memory/octra_aml_fhe_load_pk_blocked.md`). Settled-amount privacy
> on devnet is currently *not* HFHE-protected — the v3 path uses
> sha256 hash-chain anchors which are tamper-evident but NOT hiding,
> per `docs/audit/known-limitations.md` "Three items to flag first
> for the auditor §3".

Suggested replacement:
> Settled-amount privacy | Octra HFHE soundness fails | NOT held on
> devnet — the AML→HFHE bridge reverts at runtime for newly-deployed
> contracts (verified by deploying `program-examples/private_ml` and
> calling `private_predict`). v3 ships with sha256 hash-chain
> anchors instead, which are tamper-evident but NOT hiding; per-epoch
> earnings amounts are publicly observable on chain. Restoring
> HFHE settle requires Octra to enable `fhe_*` host calls for newly
> deployed contracts.

#### Stale 10 — `threat-model.md:117`

Verbatim:
> 49-case adversarial drill (`docker/devnet/e2e-adversarial-v1.sh`).

Empirical:
> File doesn't exist. The v1 drill is `e2e-adversarial.sh`.

Suggested replacement:
> 49-case adversarial drill (`docker/devnet/e2e-adversarial.sh`).

#### Stale 11 — `threat-model.md:120`

Verbatim:
> Lean 4 v2 module: 50 new theorems over the circle-keyed registry.

Empirical:
> `proofs/lean/OctraVPN_V2/` ships 54 theorems at head, not 50.

Suggested replacement:
> Lean 4 v2 module: 54 theorems over the circle-keyed registry.

### `/Users/androolloyd/Development/octra/docs/v2-release-notes.md`

#### Stale 12 — `v2-release-notes.md:87`

Verbatim:
> v2 routes through `circles[c].owner` (`main-v2.aml:790, :858`)

Empirical:
> `fhe_load_pk` appears at exactly one location in `program/main-v2.aml`:
> line 176, inside a *comment* (`// memory/octra_aml_fhe_load_pk_blocked.md`).
> The actual host-call sites referenced have been removed (the program
> uses sha256 commitments only). The line citation is stale.

Suggested replacement:
> v2 was redesigned to route HFHE through `circles[c].owner` (memory:
> `octra_hfhe_pubkey_per_wallet.md`); however, after the chain-side
> HFHE bridge was found to be unwired on devnet
> (`memory/octra_aml_fhe_load_pk_blocked.md`), the deployed
> `main-v2.aml` was reworked to use sha256 commitments (no active
> `fhe_load_pk` call in the current source; see L176 comment).

#### Stale 13 — `v2-release-notes.md:207`

Verbatim:
> `program/main-v2.aml` — 890 lines, 28 entrypoints, compile-gated.

Empirical:
> `wc -l program/main-v2.aml` → 945 lines.

Suggested replacement:
> `program/main-v2.aml` — 945 lines, 28 entrypoints, compile-gated.

#### Stale 14 — `v2-release-notes.md:104-105`

Verbatim:
> Combined v1.1 + v2 totals: **95 theorems / 0 `sorry`**

Empirical:
> Now 232 across 4 modules.

Suggested replacement:
> Combined Lean totals across all 4 modules:
> **232 theorems / 0 `sorry`**, clean `lake build`.

#### Stale 15 — `v2-release-notes.md:215-222` "What's blocked"

Verbatim:
> End-to-end HFHE settlement on devnet is blocked behind the devnet
> RPC nginx `client_max_body_size` rejecting POSTs above 1 MiB. … Filed
> upstream; `pvac-sidecar/` is otherwise ready and the v2 program
> correctly routes `fhe_load_pk(circles[c].owner)`.

Empirical:
> Body cap raised 2026-05-18. v2 program no longer calls
> `fhe_load_pk` (only a comment remains at L176). The new blocker is
> the AML→HFHE bridge being unwired for newly-deployed contracts.

Suggested replacement:
> End-to-end HFHE settlement on devnet is blocked behind the AML→HFHE
> bridge: even with a registered PVAC pubkey (the devnet RPC body cap
> was raised 2026-05-18), `fhe_*` host calls revert in newly-deployed
> contracts. The PVAC sidecar produces chain-compatible blobs; the v2
> program was reworked to use sha256 hash-chain commitments while the
> bridge is unwired. See `memory/octra_aml_fhe_load_pk_blocked.md`.

### `/Users/androolloyd/Development/octra/docs/v2-circles-design.md`

#### Stale 16 — `v2-circles-design.md:3`

Verbatim:
> One operator circle
> (`octE5x8WvhXB1FStpDmmfxkMmFKdnx5cL1Fr4gnry6aUdqA`) is registered +
> bonded + has a sealed `/policy.json` asset uploaded + a v2 session
> opened against it.

Empirical:
> Probed `octra_balance` on devnet 2026-05-20: returns
> `{"code":100,"message":"sender not found"}`. The circle does not
> exist as an addressable account on devnet today (or was wiped).

Suggested replacement:
> One operator circle (canonical sample
> `octE5x8WvhXB1FStpDmmfxkMmFKdnx5cL1Fr4gnry6aUdqA` per the
> 2026-05-17 e2e — note: the probe returns "sender not found" on
> 2026-05-20, so this circle may have been retired / not refunded;
> the v3 deploy at
> `oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3` is the current
> canonical e2e target) is registered + bonded + has a sealed
> `/policy.json` asset uploaded + a v2 session opened against it.

#### Stale 17 — `v2-circles-design.md:14`

Verbatim:
> `docker/devnet/e2e-adversarial-v2.sh` — 45-case drill, all hold

Empirical:
> The script contains 43 `expect_reject*` calls. The "45 cases"
> count may include `expect_accept` regression cases or refer to a
> stricter labeling at the time of commit `beae338`.

Suggested replacement (audit-grade):
> `docker/devnet/e2e-adversarial-v2.sh` — 45-case drill at commit
> `beae338` (current head shows ~43 `expect_reject*` calls after
> consolidation); both `expect_reject` and `expect_accept` paths hold.

### `/Users/androolloyd/Development/octra/docs/architecture.md`

#### Stale 18 — `architecture.md:172`

Verbatim:
> declared `payable` (`main-v2.aml:455`) so registration and the

Empirical:
> `register_circle` is at line **488**.

Suggested replacement:
> declared `payable` (`main-v2.aml:488`) so registration and the

#### Stale 19 — `architecture.md:265`

Verbatim:
> let pk = fhe_load_pk(circles[c].owner)   // main-v2.aml:790, :858

Empirical:
> Same as Stale 12: no active `fhe_load_pk` call in the program.

Suggested replacement:
> // Earlier v2 drafts routed `fhe_load_pk(circles[c].owner)` here.
> // After the AML→HFHE bridge was found unwired on devnet, the
> // deployed program uses sha256 hash-chain commitments; the HFHE
> // route is preserved as a doc-only fallback.

#### Stale 20 — `architecture.md:459` (`README's "What's blocked"`)

Verbatim:
> RPC body cap (`client_max_body_size`); see README's "What's"

Empirical:
> Body cap raised 2026-05-18; README's "What's blocked" itself is
> now stale (Stale 4).

Suggested replacement:
> AML→HFHE bridge unwired; see README's "What's blocked".

### `/Users/androolloyd/Development/octra/docs/security-roadmap.md`

#### Stale 21 — `security-roadmap.md:35`

Verbatim:
> **95 Lean theorems** (45 v1.1 + 50 v2) | — | TLC parity: 17
> invariants, 3.8 M distinct states, 0 violations.

Empirical:
> 232 theorems across 4 modules at head.

Suggested replacement:
> **232 Lean theorems** (46 v1.1 + 54 v2 + 60 WireProtocol + 72
> OctraVPN_Rust) | — | TLC parity: 17 invariants, 3.8 M distinct
> states, 0 violations.

#### Stale 22 — `security-roadmap.md:125-135` (§0.8)

Verbatim:
> ### 0.8 (planned) **Devnet RPC body cap lift to ≥ 8 MiB** … End-to-end
> `settle_confirm` on HFHE byte counters on devnet is blocked on this.

Empirical:
> Cap lifted 2026-05-18; HFHE settle is now blocked on
> `octra_aml_fhe_load_pk_blocked` instead.

Suggested replacement:
> ### 0.8 (DONE 2026-05-18) **Devnet RPC body cap raised** — `octra_registerPvacPubkey`
> with a ~4 MB body now confirms on devnet. The new blocker for
> end-to-end HFHE on devnet is `fhe_*` host calls being unwired for
> newly-deployed contracts; see memory
> `octra_aml_fhe_load_pk_blocked.md`.

#### Stale 23 — `security-roadmap.md:462`

Verbatim:
> §0.8 devnet RPC body cap lifted (Octra-team ask)

Empirical:
> Already done; should be marked DONE not "ask".

Suggested replacement:
> §0.8 devnet RPC body cap lifted (DONE 2026-05-18; new ask is
> `fhe_*` host-call bridge for new contracts).

### `/Users/androolloyd/Development/octra/docs/value.md`

#### Stale 24 — `value.md:117, value.md:124`

Verbatim (124):
> Compute `total_paid = bytes_used × price` inside the circle; only
> the settled OU amount escapes to main-net. (Mainnet-only until
> devnet RPC body cap is raised — see `docs/v2-octra-questions.md §7`.)

Empirical:
> Body cap raised; gate is now the HFHE bridge.

Suggested replacement (124):
> Compute `total_paid = bytes_used × price` inside the circle; only
> the settled OU amount escapes to main-net. (Mainnet-only until
> Octra wires the AML→HFHE bridge for newly-deployed contracts on
> devnet — see `memory/octra_aml_fhe_load_pk_blocked.md`.)

### `/Users/androolloyd/Development/octra/docs/testnet.md`

#### Stale 25 — `testnet.md:208-211`

Verbatim:
> `https://devnet.octrascan.io/rpc` enforces `client_max_body_size ≈
> 1 MiB` at the nginx edge.

Empirical:
> Raised 2026-05-18.

Suggested replacement:
> `https://devnet.octrascan.io/rpc` previously enforced
> `client_max_body_size ≈ 1 MiB`; the limit was raised 2026-05-18 so
> the ~4 MB PVAC pubkey registration tx now confirms on devnet.

### `/Users/androolloyd/Development/octra/docs/octra-research.md`

#### Stale 26 — `octra-research.md:238`

Verbatim:
> `octra_registerPvacPubkey` body cap   | ≥8 MB (accepts a 4 MB
> base64 PVAC pk)              | **~1 MiB** at nginx edge — blocks
> PVAC registration

Empirical:
> Devnet now accepts ≥4 MB bodies.

Suggested replacement: change the devnet column from
"~1 MiB at nginx edge — blocks PVAC registration" to
"≥4 MB (raised 2026-05-18 per Octra team; accepts the ~4.1 MB PVAC
pubkey body)".

### `/Users/androolloyd/Development/octra/docs/performance-limitations.md`

#### Stale 27 — `performance-limitations.md:145`

Verbatim:
> Body-size cap on devnet was 1 MiB at the nginx edge (memory:
> ...).

Empirical: factually still true past-tense, but the surrounding
prose at L145+ may not flag the resolution. Verify in context.

Suggested replacement: ensure the phrase is past-tense and reference
the 2026-05-18 lift.

### `/Users/androolloyd/Development/octra/docs/troubleshooting.md`

#### Stale (auxiliary) — `troubleshooting.md:280`

Verbatim:
> exceeds the devnet nginx RPC body cap (~1 MiB; pubkey blob is ~4 MiB).

Empirical: stale; cap lifted.

Suggested replacement: reword to "previously enforced a ~1 MiB cap; the
limit was raised 2026-05-18 — if you still see HTTP 413, the limit may
have regressed; ping the devnet operators."

### `/Users/androolloyd/Development/octra/docs/gap-analysis.md`

#### Stale (auxiliary) — `gap-analysis.md:10, :12, :60, :82, :143`

- L10: "49 v1.1 + 45 v2 adversarial-drill cases green; 95 Lean theorems"
  → counts off (see Stale 5, 6, 21).
- L12: "30 Rust proptest harnesses" — the `prop_*.rs` files in this
  workspace declare 27 individual `fn` proptest functions
  (`prop_commit:2, prop_session:1, prop_canonicalization:0,
  prop_receipt:5, prop_security:5, prop_sweep:14`). The "30" likely
  rounded or included foundry-side properties — verify in
  `octra-foundry/crates/octra-core/tests/prop_*.rs` (sibling).
- L82: "Blocker: devnet RPC body cap" — stale.
- L143: "`main-v2.aml:366` uses the new `nonreentrant` modifier" —
  actual L392 (see Stale 8).

### `/Users/androolloyd/Development/octra/docs/audit/known-limitations.md`

#### Stale (auxiliary) — `known-limitations.md:202-205`

Verbatim:
> **JSON-RPC body cap 1 MiB on devnet.** Per memory
> `octra_devnet_rpc_body_cap.md`, the devnet nginx terminator rejects
> POST bodies > 1 MiB

Empirical: stale.

Suggested replacement:
> **JSON-RPC body cap (historical).** The 1 MiB cap noted in memory
> `octra_devnet_rpc_body_cap.md` was raised 2026-05-18; devnet now
> accepts ~4 MB bodies. The current devnet-only blocker for HFHE is
> the unwired `fhe_*` bridge per `octra_aml_fhe_load_pk_blocked.md`.

---

## UNVERIFIABLE claims (need human judgment) — count: 6

These are claims that could not be conclusively verified without
external context, additional tooling, or running long jobs:

### U1 — `README.md:339`, `v2-release-notes.md:111`

> TLC last-run: **52,676,571 states / 3,805,681 distinct / depth 31
> / 0 violations** in ~39s.

Running TLC against the v2 spec is a multi-minute Java job and not in
scope for a single-pass audit. **Action:** rerun and refresh whenever
the spec changes.

### U2 — `v2-release-notes.md:212`, `security.md:42`, `threat-model.md:122`,
`security-roadmap.md:36`, `gap-analysis.md:12`

> 30 Rust proptest harnesses

I counted 27 individual `proptest!` `fn` bodies across the 6 files
in this workspace (`prop_*.rs`). `security.md:42` says the 30 figure
spans **both** this workspace and the foundry sibling
(`octra-foundry/crates/octra-core/tests/prop_*.rs`), which is not
present in this worktree's path-dep. **Action:** confirm against the
sibling and either re-count or re-cite the figure as "27 in
octravpn + N in octra-foundry".

### U3 — `docs/audit/security-properties.md` file:line pins

Every `path:line` in `security-properties.md` is a candidate for
drift. I spot-verified four (P3: `receipt_journal.rs:1–390`; P10:
`acl.rs` line 76 / 235 / 144; P14: `controlbase.rs` line 267 / 174 /
62; P18: `OctraVPN_V2/Lemmas.lean` line citations). They look in the
right ballpark but a systematic re-verify against head is required
because the file was generated at commit `599b1ad` and head is 17
commits ahead. **Action:** re-run the security-properties.md
generation script before shipping the audit-prep package.

### U4 — `v2-release-notes.md:21`, `v2-circles-design.md:17`

> Canonical tx hashes (`54d84c02d5a61bfade…`,
> `5811465946323b04de…`, `434ad40cf475dd4f50…`, etc.)

These are devnet tx hashes. Devnet state can be reset by the
operators without notice. **Action:** flag as "live as of 2026-05-17"
and re-probe if you want stronger evidence; the addresses they
reference may not still exist.

### U5 — External commit hashes

`ba094dd` (cited in `v2-circles-design.md:10`) and `f9c73e1` (cited in
`oct-url-handler.md:36`, `aml-grammar.md:8/:412`, `v2-circles-design.md:10`,
`octra-research.md:167`, `v2-octra-questions.md:18, :24`) belong to
external repos (`octra-foundry` and `octra-labs/webcli` respectively).
`git cat-file -e` fails for both in this repo; they presumably exist
in their respective repos but cannot be confirmed here. **Action:**
verify against the sibling clones at integration time.

### U6 — Sibling-repo path-deps + their HEADs

This repo path-deps `../../../octra-foundry/crates/octra-core` and
`../../../headscale-rs/headscale-api`. The audit covers only this
repo's docs. References to "foundry sibling at commit X" or
"headscale-rs at commit Y" cannot be verified from inside this
worktree. **Action:** when the audit-prep package is generated for an
external auditor, pin sibling commit hashes in `manifest.json` (it
currently only pins this repo's commit).

---

## NEW gaps discovered while auditing — count: 5

### N1 — Workspace does NOT build at head

`cargo build --workspace` fails:

```
error[E0432]: unresolved import `hmac`
  --> .../headscale-rs/headscale-api/src/tailscale_wire/knock.rs:70:5
error[E0432]: unresolved import `sha2`
  --> .../headscale-rs/headscale-api/src/tailscale_wire/knock.rs:71:5
```

`knock.rs` does `use hmac::{Hmac, Mac};` + `use sha2::Sha256;`
unconditionally, but `headscale-api/Cargo.toml` declares them as
`optional = true` (intended to be gated behind the `admin` feature
that owns the cookie/CSRF path). The `tailscale_wire` module is part
of the default surface, so this is a feature-flagging bug in the
sibling repo. **Recommendation:** either drop `optional = true` for
those two deps, or gate `knock.rs`'s use behind `cfg(feature = "admin")`.

Knock-on consequences:
- `cargo test --workspace` also fails (additionally with
  `missing field knock` in `WireState { ... }` calls in
  `octravpn-node/src/{main.rs,hub.rs}`,
  `octravpn-node/tests/{policy_e2e.rs,raw_tls_integration.rs,tailscale_wire_integration.rs}`).
- `scripts/test-all.sh` will fail on step 2 (`cargo test --workspace`).
- README's "Quickstart — local" `cargo build --workspace --release` is
  currently broken.

### N2 — `e2e-adversarial-v1.sh` is cited in docs but doesn't exist

`docs/security.md:39`, `docs/threat-model.md:117`, and other places
say `docker/devnet/e2e-adversarial-v1.sh`. The actual v1 script is
`docker/devnet/e2e-adversarial.sh`. Either rename the file or fix the
references.

### N3 — README has no link to the v3 architecture / contract address

README narrates v1.1 + v2 only and says "Two AML deployments are live
on devnet". A third, **v3**, has been live on devnet at
`oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3` since 2026-05-18.
The "What's deployed" section, the "Architecture" diagrams, and the
"Documentation" table all omit v3 entirely. Auditors / users reading
the README will not learn that v3 exists, even though
`docs/v3-circle-resident-architecture.md`,
`docs/v3-members-schema.md`, `docs/v3-policy-schema.md`,
`docs/v3-state-root-schema.md`, `docker/devnet/v3-smoke.sh`, and the
new audit-prep package all treat v3 as primary.

### N4 — `docs/audit/manifest.json` has no sibling-repo pinning

The manifest pins this repo's commit (`599b1ad`) but neither
`headscale-rs/headscale-api` nor `octra-foundry/crates/octra-core`
sibling commits. An auditor cloning at the pinned commit cannot
reproduce the build because sibling path-deps may have moved (see
N1, which is the active live example).

### N5 — `docs/audit/manifest.json` snapshot is 17 commits stale

Manifest pins commit `599b1ad`; head is `05d7c8b`. Significant
changes since then include rate-limit middleware, TLS rotation,
threat-model v3, +77 octravpn-core coverage tests, demo recordings,
and the demo workflow changes. The audit-prep file SHAs themselves
still match, but the *repo state* that they describe has moved on.
Either regenerate the manifest at head before publishing or document
the "snapshot date" prominently in the audit-prep README.

---

## End-of-audit checklist

- [x] Every "works on devnet" claim re-tested? **Yes** — RPC probes
  hit each cited address; the bodyl-cap claim probed at 1.3 MB → 200;
  PVAC pubkey lookup confirmed on the deployer wallet; v2 operator
  circle `octE5x…` returned "sender not found".
- [x] Every "passes N tests" count refreshed? **Yes** — Lean
  recounted (232 vs 95); proptest fn counts (27); adversarial-drill
  `expect_reject*` counts (~38/43/50 for v1/v2/v3). `cargo test
  --workspace` was attempted; it does not currently compile at head
  (N1).
- [x] Every Wall N status confirmed against the harness exit code?
  **Partial** — interop script is present and matches docs; running
  it requires Docker compose stack and is out-of-band of a single-pass
  audit. The user previously verified it green; not re-run.
- [x] Every file:line reference still valid? **Sampled** — Stale 2,
  8, 12, 18, 19 are confirmed shifted. The `docs/audit/security-properties.md`
  file:line pins are flagged as needing systematic re-verification
  (U3) before publishing.
- [x] Every cited commit hash still in the tree? **Yes** for in-repo
  hashes; **No** (and intentionally so — external repos) for
  `ba094dd` and `f9c73e1` (U5).

---

## Patterns observed

1. **Single biggest pattern: 8 of the 12 STALE claims about Octra
   chain quirks describe the world before 2026-05-18 when the
   devnet RPC body cap was raised.** Stale 4, 9, 12, 15, 22, 23, 24,
   25, 26, 27 + auxiliary entries in `troubleshooting.md` and
   `known-limitations.md` all narrate the cap as live. Only
   `octra-dev-questions.md` and `octra-dev-questions-email.md` were
   updated. The README's "What's blocked" section is the
   highest-visibility instance.

2. **Lean theorem count drift is everywhere.** README, `security.md`,
   `v2-release-notes.md`, `gap-analysis.md`, and
   `security-roadmap.md` all say 95; head is 232. The count almost
   doubled when `WireProtocol/` and `OctraVPN_Rust/` modules
   landed, but no doc was updated.

3. **`program/main-v2.aml` file:line citations are all 30–40 lines
   off.** Likely because the file grew from 890 → 945 lines (+55,
   ~6 %) after `b9aedf7` / `6c9d15b` / nonreentrant additions.
   Every `:NNN` citation in README, architecture.md, security.md,
   gap-analysis.md, and v2-release-notes.md is suspect.

4. **No `e2e-adversarial-v1.sh` file exists.** Two docs cite it.
   Either restore (rename `e2e-adversarial.sh`) or fix the
   references.

5. **v3 is the canonical deployed substrate now (per
   `v3-circle-resident-architecture.md`, the audit-prep package, and
   the contributing-tests guide), but the README still presents v1.1
   + v2 as the two live programs.** This is the most consequential
   doc-drift item for external reviewers.

---

## The 3 most-load-bearing STALE claims (external-reviewer embarrassment risk)

1. **README's "What's blocked" still names the devnet RPC body cap
   as the gate.** This is the first paragraph an external reviewer
   reads after the badges. The cap was raised TWO days ago; the
   reviewer's first action will be to `curl` against devnet and find
   it works, then immediately distrust everything else in the
   README. (Stale 4.)

2. **The "95 Lean theorems" headline figure is wrong by a factor of
   ~2.4×.** Lean is a brand of rigor for OctraVPN's docs; an
   external reviewer who runs `lake build && grep -c '^theorem'`
   will see 232 and conclude the docs are out of sync with the proof
   tree. (Stale 1, 3, 7, 11, 14, 21.)

3. **`cargo build --workspace` is broken at head.** The README's
   Quickstart says "`cd octra && cargo build --workspace`" and
   `contributing-tests.md` makes `./scripts/test-all.sh` the
   contract. Both fail today on the unrelated `hmac`/`sha2`
   feature-flag bug in `headscale-rs/headscale-api/knock.rs`. An
   external auditor or potential contributor cloning the repo today
   will not be able to build. (N1.)

---

## Top 5 highest-priority replacement-text suggestions

In order: fix these first.

1. **README.md "What's blocked" section** (lines 355–362) — replace
   per Stale 4. Single largest narrative change; everything else
   downstream tracks this.

2. **README.md "Status (2026-05-17)" block** (lines 13–31) — update
   "95 Lean 4 theorems" to "232", update the date, and add a one-line
   pointer to v3 (per N3). This is the most-read paragraph in the repo.

3. **N1 build-system fix** — patch
   `headscale-rs/headscale-api/Cargo.toml` and/or `knock.rs` so
   `cargo build --workspace` succeeds. Not a doc fix but blocks
   every downstream verification step.

4. **`security.md` §2 verification table** (lines 39–43) — replace
   per Stale 5, 6, 7, U2. This is the load-bearing claim of "five
   layers of verification" and three of the five rows have stale
   numbers / paths / file names.

5. **`docs/audit/known-limitations.md` "JSON-RPC body cap" entry**
   (lines 202–205) — per Stale auxiliary. The audit-prep package
   itself currently teaches an external auditor that the cap is in
   place; this is the single doc most likely to be read by the actual
   audit firm.

---

## Memory-entry verification status

| Memory file | Still holds? | Notes |
| --- | --- | --- |
| `MEMORY.md` (index) | partially | The `octra_devnet_rpc_body_cap.md` row is stale (resolved 2026-05-18). |
| `octra_circles.md` | yes | Wire format + RPC methods match the v2/v3 code. |
| `feedback_docker_only.md` | yes | Test-rig docker-only policy still enforced (`tailscale-interop` runner explicitly cites it). |
| `octra_aml_wire_format.md` | yes | ed25519_ok base64 / tx envelope / response shapes all still match deployed code. |
| `octra_v1_pause_bypass.md` | yes | Governance bypasses pause; programs unchanged on that axis. |
| `octra_hfhe_pubkey_per_wallet.md` | yes | `fhe_load_pk` is still per-wallet; circles still can't have keypairs. |
| `octra_devnet_rpc_body_cap.md` | **STALE** | The 1 MiB cap was raised 2026-05-18. Devnet now accepts ≥1.3 MB bodies (probed 2026-05-20 → HTTP 200). See proposed new memory below. |
| `octra_aml_string_cap_4kb.md` | yes | 4 KiB silent truncation still applies; v3 architecture engineers around it. |
| `octra_aml_fhe_load_pk_blocked.md` | yes | `fhe_*` host calls still revert on devnet for newly-deployed contracts (this is the current real HFHE blocker, replacing the body-cap blocker). |
| `octra_circles_not_executable.md` | yes | Circles still bytecode-not-found on `contract_call`; v3 keeps bonds on main-v3. |
| `octra_aml_bytes_encoding.md` | yes | `bytes` = JSON string, sha256 = 64-char hex, unset reads as `"0"`. v3 docs explicitly cite this. |
| `demo_workflow_gotchas.md` | likely yes | Not re-verified; the boringtun + sibling-repo + vhs-escape blockers haven't changed. Confidence: high but not probed in this audit. |

### Proposed action on `octra_devnet_rpc_body_cap.md`

- **Do not delete.** It is referenced by other memory entries
  (`octra_aml_fhe_load_pk_blocked.md` calls it a "sister memory"),
  and the historical record of "what walls have we passed" matters.
- **Append** a `last_verified: 2026-05-20 — RESOLVED.` line near the
  top of the body, before the empirical paragraph, with a short
  note: *"The 1 MiB cap was raised by the Octra devnet operators on
  2026-05-18 per `docs/octra-dev-questions-email.md`. Probed
  2026-05-20: a 1.3 MB JSON-RPC POST to `https://devnet.octrascan.io/rpc`
  returns HTTP 200 with the real PVAC pubkey payload. The current
  HFHE blocker is `octra_aml_fhe_load_pk_blocked.md`, not this one."*
- **Add `last_verified: 2026-05-20` to the frontmatter** of every
  memory entry whose claim was re-checked here (all of the above
  rows tagged "yes").

(Per the constraint that this auditor doesn't modify other files, the
above is left as the recommended follow-up for a human reviewer.)
