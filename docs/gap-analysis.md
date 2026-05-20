# OctraVPN — Honest Gap Analysis

Current state (counted at the time of writing, post-v2 hardening pass):

- 2 deployed AML substrates (v1.1
  `oct2YehVLezCi2RCcSkURc3nyyYtzxmspwGHHALm6pjkUvJ`; v2
  `oct3fxjrzfqh65ATo31eau8xRFBPiXh2Uzwue56EYkfVSj7`)
- 11 workspace crates · ≈10.6k LOC Rust + new `pvac-sidecar` crate
- AML: `main-v1.aml`, `main-v2.aml`, `operator-circle.aml`
- 49 v1.1 + 45 v2 adversarial-drill cases green; 232 Lean theorems
  (OctraVPN 46 + OctraVPN_V2 54 + OctraVPN_Rust 72 + WireProtocol 60);
  TLC 17 invariants / 3.8 M states / 0 violations
- 30 Rust proptest harnesses (crypto / tx / wallet_enc / receipt)
- `cargo audit` clean (1090-advisory RustSec db, one informational
  unmaintained warning on `paste 1.0.15`)

The system has shipped scope across the protocol, off-chain libraries,
test harness, Foundry-equivalent tooling, formal verification, install
scripts, CI, deployment packaging, and the v2 hardening pass. What
follows is what is **still missing for production**, sorted by
blocking impact.

For the canonical fix queue see `docs/v2-threat-model.md §3`.
For the roadmap see `docs/security-roadmap.md`.

## Tier A — closed in the v2 hardening pass

These were the v1 Tier-A gaps; status as of `dfc016e`.

### A1. Data plane is not wired end-to-end (the big one)

The `octravpn-tun` / `octravpn-core::onion` / `octravpn-node::tunnel`
pieces still need to be connected for the *client* connect flow.
The v2 work focused on the **chain + key + receipt** path rather than
the TUN integration; the data plane status is unchanged from the v1
write-up. ≈500-800 lines of careful packet-pump code split between
client and node, plus per-OS routing configuration.

**Status**: still open.

### A2. ~~`reconcile` is missing~~

**Status**: still open as documented; the v2 work did not touch this.
Validators have no automated way to know what to claim beyond
manually invoking `accumulator-add` after each settlement.

### A3. ~~`octravpn connect` doesn't establish a tunnel~~

**Status**: still open (same root cause as A1).

### A4. ~~Health endpoint is a placeholder~~

**Status**: still open. `/health` is still uptime-based.

## Tier A.v2 — v2 substrate inventory (closed this pass)

| Item | Status | Reference |
| --- | --- | --- |
| **v2 slim registry deployed** | DONE | `oct3fxjrzfqh65ATo31eau8xRFBPiXh2Uzwue56EYkfVSj7` (commit `6c3ce5a`) |
| **v2 operator-circle compile-checked** | DONE — design + reference impl | `program/operator-circle.aml`; deployable but not yet hosting `code_b64` runtime in production (still a design doc for the operator-side circle program) |
| **v2 adversarial drill 45/45** | DONE | `docker/devnet/e2e-adversarial-v2.sh` (commit `beae338`) |
| **Lean v2 module** | DONE | `proofs/lean/v2/` (50 theorems; commit `db6ad7d`) |
| **TLC v2 invariants** | DONE | 17 invariants, 3.8 M distinct states, 0 violations |
| **Rust proptest + leak audit** | DONE | 30 properties; `docs/v2-rust-leak-audit.md` |
| **Receipt context binding** (P1-5) | DONE | `crates/octravpn-core/src/receipt.rs`; commit `060903d`; binds `(program_addr, chain_id, circle_id)` |
| **RPC cert pinning lib + config** (P0-2) | DONE | `[chain].pinned_root_paths`; commit `2d933fc`. *Operator-side enablement still on operators.* |
| **Sealed on-disk secrets** (P1-6) | DONE | `octravpn-node seal-keys` / `unseal-keys`; strict mode flag; commit `dfc016e` |
| **Sealed-passphrase zeroization** (P1-10) | DONE | `Zeroizing<String>`; commit `2d933fc` |
| **Receipt journal** (P1-8/P1-9) | DONE | `crates/octravpn-core/src/receipt_journal.rs`; fsync'd; commit `dfc016e` |
| **`/events` SSE auth gate** (P0-1) | DONE | events_token; commit `f4f5e65` |
| **`meter_bytes` auth fix** (P0-3) | DONE | commit `b9aedf7` |
| **PVAC sidecar built** | DONE | GPL-isolated; AES-KAT green on mainnet; commit `9e16868` |
| **`cast register-pvac`** | DONE | (part of `9e16868` toolchain) |

## Tier A.v2 — v2 substrate, still open

These do not block v2 from operating on chain today (the substrate is
live), but they block the privacy / hardening properties we claim
end-to-end.

### A.v2.1 End-to-end HFHE `settle_confirm` on devnet

**Blocker**: devnet RPC body cap. The PVAC sidecar's `fhe_load_pk`
transaction (~4 MB lattice key) is rejected with `413 Request Entity
Too Large` by the devnet nginx. Mainnet has no such cap and accepts.

**Tracked**: `docs/security-roadmap.md §0.8` (Octra-team ask); memory
note in `memory/octra_devnet_rpc_body_cap.md`.

**Workaround today**: the sidecar is exercisable on mainnet for the
registration leg; full settle-confirm cycle on devnet awaits the cap
lift.

### A.v2.2 Operator daemon ↔ PVAC sidecar subprocess wiring

**Status**: the JSON IPC contract is defined and the sidecar runs
under `octra cast` today. The **actual subprocess spawn from
`octravpn-node`** — startup, lifecycle, crash + backoff, metric
surface — is not yet wired. The daemon does not currently boot the
sidecar.

**Tracked**: `docs/security-roadmap.md §2.9`.

### A.v2.3 v2.1 redeploy gate

The v2 hardening pass shipped fixes that update the **off-chain Rust
stack** (P0-1, P0-2, P1-5, P1-6, P1-8, P1-9, P1-10). They do not
require a chain redeploy. The next redeploy bundles:
- Drill case 46 (re-entrancy on `nonreentrant` paths)
- §2.9 sidecar wiring
- Owner-routed `fhe_load_pk` (already shipped per
  `memory/octra_hfhe_pubkey_per_wallet.md`)

**Tracked**: `docs/security-roadmap.md` v2.1 milestone.

### A.v2.4 Per-member sealed wrap

**Defection fragility.** Today the sealed `/policy.json` passphrase
is shared OOB across every tailnet member; one leak = one full policy
plaintext, with no per-member revocation. The fix is per-member
X25519 wrap of a content key (`docs/security-roadmap.md §2.6`).

**Tracked**: v2.2 milestone.

### A.v2.5 AEAD primitive migration (AES-GCM + PBKDF2 → XChaCha20 + Argon2id)

PBKDF2-120k is GPU-cheap (~5k guesses/sec) — a 30-bit passphrase
falls in a year. AES-GCM's 96-bit random nonce is fragile to RNG
class advisories (RUSTSEC-2024-0376 / -0379 class). Both are
addressed by the v2.3 milestone.

**Tracked**: `docs/security-roadmap.md §2.7` and `§2.8`; v2.3 milestone.

### A.v2.6 Onion AEAD random nonce hardening (P1-2)

Onion uses constant-zero nonce; safe today by fresh-key-per-call
construction but fragile to refactor. Use random 12-byte nonce in
the wire packet.

**Tracked**: `docs/security-roadmap.md §4.5`; v1.x parallel track.

### A.v2.7 Drill case 46 — re-entrancy

`main-v2.aml:366` uses the new `nonreentrant` modifier on
`finalize_unbond`. The v2 drill has 45 cases; the 46th — an active
re-entrancy attempt — is the missing twin. Lean coverage of
re-entrant paths is also residual.

**Tracked**: `docs/security-roadmap.md §5.4`.

## Tier B — production-critical hardening

### B1. ~~Wallet at-rest encryption~~

**Status**: CLOSED for the v2 path (P1-6, commit `dfc016e`). v1.1
hosts still use plaintext keys; that's the back-compat path
`e2e.sh` requires.

### B2. No LICENSE files

`Cargo.toml` declares `MIT OR Apache-2.0` but the repo has no
`LICENSE`, `LICENSE-MIT`, or `LICENSE-APACHE` files. The new
`pvac-sidecar` crate adds a GPL component — its licence MUST be
called out explicitly to avoid contaminating the MIT/Apache surface
when downstream consumers vendor.

**Status**: open.

### B3. Per-validator receipt audit log

The new `receipt_journal.rs` is a *floor*, not an audit log. It
stores `(session_id, last_signed_seq)` so the daemon refuses to
re-sign at a stale seq across restarts. A full append-only audit log
keyed by `(session_id, seq)` with periodic disk-sync — useful for
defending against false equivocation claims — is still missing.

**Status**: partially addressed; full audit log open.

### B4. Rate limiting on control plane is in the doc but not in code

`docs/security.md` mentions `tower-http` rate limit; the actual axum
router doesn't apply one. The new `/events` token gate (P0-1) closes
the *information-leak* problem but not the *DoS* problem.

**Status**: open.

### B5. (NEW) Cargo audit + cargo deny CI wiring

`deny.toml` exists; no GitHub Actions wiring. Bumps could silently
regress.

**Status**: open; `docs/security-roadmap.md §5.6`.

## Tier C — community / community-readiness

### C1. Missing project docs

No `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`,
`CODE_OF_CONDUCT.md`, or `FAQ.md`. (Note: `docs/faq.md` exists for
end-user FAQ; we need a *security disclosure* `SECURITY.md` at the
repo root.) **Status**: open.

### C2. No tutorial docs

Have `docs/tutorial-client.md` and `docs/tutorial-validator.md` plus
`docs/troubleshooting.md`. **Status**: partially closed; v2 client +
operator tutorials need refresh.

### C3. No comparison docs

No comparison with adjacent dVPN projects (Mysterium, Sentinel,
Orchid). **Status**: open.

## Tier D — observability / dev-experience

### D1. No performance benchmarks

No `criterion` benches.

### D2. No code coverage report

### D3. No tracing spans on the hot paths

### D4. Structured JSON logging not configurable

## Tier E — release engineering

### E1. No container images for the daemon set

The v2 substrate is exercised via `docker/devnet/` compose stack;
operator-facing OCI image build isn't yet in CI.

### E2. No Helm chart

### E3. No Nix flake

## Tier F — protocol refinements (post-v1)

### F1. Dispute mechanism beyond double-sign / no-show

Partially addressed in v2 via `settle_confirm` mismatch (public
`SettleDispute` event). A *third-party arbitration* with adverse-witness
evidence is still open.

### F2. Pricing tiers / regional floors

### F3. Top-up running sessions

### F4. Reputation decay

### F5. Treasury withdrawal entrypoint

`treasury` accumulates but has no withdrawal path. Documented as
intentional in `governance.md` (governance-gated `withdraw` is now
exposed in v1.1 — note `docs/octra_v1_pause_bypass.md` carve-out).

## What's deliberately out of scope for now

- Mobile clients (iOS/Android). Add later.
- GUI client. CLI is the v1.
- HSM / YubiKey wallet signing. Operator-level addition; tracked as
  v1.x in `docs/security-roadmap.md §1.1` (P1-6 covers the
  passphrase-wrap version).
- IPv6 throughout. Most paths take SocketAddr already; egress format
  is IPv4-only.
- TCP fallback transport (for censored networks).
- Network Extension on macOS.

## Action plan for next sprint

Reset for post-v2-hardening:

1. **A.v2.2 sidecar subprocess wiring** — close the operator daemon
   ↔ PVAC sidecar gap; this unblocks shipping the privacy story.
2. **A.v2.7 + drill case 46** — re-entrancy attempt against
   `nonreentrant` paths; Lean parity.
3. **A.v2.4 per-member sealed wrap** — defection-fragility fix;
   biggest remaining hole in the tailnet model.
4. **B2 LICENSE files** — must clearly call out the GPL `pvac-sidecar`
   boundary.
5. **B4 rate-limit wiring** + **B5 cargo-audit CI** — small, mechanical.
6. **A1/A2/A3 data-plane wiring** — its own multi-week milestone.
7. **C1 SECURITY.md + CHANGELOG** — start tracking v2 versions
   formally.

Tier A data-plane wiring is committed as its own next milestone
because it deserves a focused sprint with multi-machine integration
tests.
