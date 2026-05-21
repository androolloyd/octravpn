# Doc + substrate changelog

A chronological log of **major beats only** — substrate upgrades,
audit drops, big consolidation passes, formal-verification
milestones. This is *not* a per-commit log; `git log` is the source
of truth for that. Use this file when someone asks "when did X
land" and you don't want to grep history.

Newest first.

---

## 2026-05-20 — Massive consolidation pass

A multi-agent landing day. The substrate didn't change but the
codebase got dramatically more navigable.

### Modularization sweep

Five large files were split into directory modules without behavior
change. Every commit message starts with `modularize-*` or `merge:
modularize *`:

- `hub.rs` (1537 LOC) → 6 submodules + `SUBSYSTEM_CHECKLIST`
  (`merge: modularize hub.rs (1537 → 6 submodules + SUBSYSTEM_CHECKLIST)`).
- `main.rs` (1631 LOC) → 53 LOC + `cli/` directory + `Subcommand`
  trait (`merge: modularize main.rs (1631→53 LOC) → cli/ +
  Subcommand trait`).
- `control.rs` → `control/` submodule; `BearerCheck` extracted
  into `octravpn-core` as a tower `Layer`
  (`merge: modularize control.rs → control/ + bearer Layer in
  octravpn-core`).
- `portal/chain.rs` (1818 LOC) → `chain/` submodule
  (`merge: modularize portal/chain.rs → chain/ submodule`).
- `receipt_journal.rs` → submodule with a v1 byte-spec README
  (`merge: modularize receipt_journal.rs → submodule with v1 byte-spec README`).

### Subsystems wired

- `audit/` module landed (file system) — `crates/octravpn-node/src/audit/`
  replaces `audit.rs`; on disk at the start of this commit (deleted
  `audit.rs` + new directory in the working tree).
- ACL consolidation pass — multiple feature-parity agents merged.
- Embedded `headscale` CLI shipped under `octravpn-node headscale …`
  — single-binary install; see
  [`operators/cli-migration.md`](operators/cli-migration.md).
- PVAC sidecar wired into the node IPC path (chain-compatible HFHE
  blobs; AML ↔ HFHE bridge still blocked, see "What's blocked" in
  the root README).
- Shadow blob emission for v2 sealed-asset path-privacy.

### Formal verification

- HFHE Lean module — **+35 theorems** (end-to-end composition, the
  headline settle theorem, resolved against Shielding+Wire).
- WireProtocol: Shielding + Wire Lean modules added — **+28 theorems**.
- AML proofs — **+55 theorems** across the v3 invariant set.
- Shielding proofs — **+28 theorems**.
- OctraVPN_V3 state-machine model landed — 53 invariants
  (`proofs/lean: add OctraVPN_V3 state-machine model (53 invariants)`).

Workspace total now: **373 Lean 4 theorems** across OctraVPN (46),
OctraVPN_V2 (54), OctraVPN_V3 (55), OctraVPN_Rust (109), and
WireProtocol (109) — clean `lake build`, zero `sorry`.

### Audits dropped

Three audit artifacts landed simultaneously under `docs/audit/`:

- [`audit/2026-05-20-deep-security-audit.md`](audit/2026-05-20-deep-security-audit.md)
  — deep security audit of OctraVPN v3 + headscale-rs +
  octra-foundry. **One critical (C-1) flagged.**
- [`audit/2026-05-20-concurrency-error-config-audit.md`](audit/2026-05-20-concurrency-error-config-audit.md)
  — concurrency / error / config audit: 2 blocker / 5 high / 10 med
  / 7 low / 4 advisory.
- [`audit/2026-05-20-claims-audit.md`](audit/2026-05-20-claims-audit.md)
  — documentation claims audit (every load-bearing assertion in
  the README/docs cross-checked against code).

### Docs information-architecture pass (this commit)

- [`README.md`](README.md) — "I am a..." audience selector
  landing page.
- [`READING_PATHS.md`](READING_PATHS.md) — per-time-budget reading
  guide (5 min → onboarding contributor).
- [`INDEX.md`](INDEX.md) — alphabetical file index.
- [`changelog.md`](changelog.md) — this file.
- Root [`../README.md`](../README.md) gained a 5-line
  "Documentation" section pointing here.

In parallel, sibling agents landed `docs/users/{README,linux,macos}.md`,
`docs/operators/tour-*.md`, `docs/maintenance/*`, and `demo/tapes/*`.

---

## 2026-05-19 — Wall 7 closed

Wall 7 (the headscale-parity wall) closed. Six feature-parity
agents merged in sequence:

- preauth keys (single-use + reusable).
- node lifecycle (register → online → expire → tombstone).
- ACL grammar parity (`group:`, `tag:`, `*`, port ranges).
- DNS (MagicDNS + split DNS).
- DERP (region map + relay selection).
- MapResponse (full v1 wire-format, delta + full snapshots).

In parallel, four coverage agents added **~+335 tests** across the
workspace — proptest harnesses, ACL fuzzers, MapResponse round-trip,
DERP fallback scenarios. See
[`headscale-gap-analysis.md`](headscale-gap-analysis.md) for the
property-by-property delta vs. upstream `headscale-go`.

The tailscale-interop drill landed a finding the same day —
[`tailscale-interop-finding.md`](tailscale-interop-finding.md) +
handoff in [`tailscale-interop-blocker.md`](tailscale-interop-blocker.md).

---

## 2026-05-18 — v3 deployed; devnet RPC body cap raised

- **v3 deployed** to Octra devnet at
  `oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3`. Chain-minimal
  successor — only OU custody + slash + 32-byte SHA-256 role
  anchors stay on chain; policy / members / per-session receipts
  move into sealed circle assets. Full design at
  [`v3/`](v3/) (overview, data-model, state-machine, call-flows,
  canonical-encoders, fee-model, security-model, deployment,
  v3-vs-v2).
- 40/40 v3 adversarial drill green; end-to-end smoke replays the
  earnings hash chain byte-for-byte.
- Devnet RPC body cap raised — `octra cast register-pvac` now
  confirms a ~4 MB PVAC pubkey. Chain-side `fhe_load_pk` still
  reverts; see [`octra-dev-questions.md`](octra-dev-questions.md) §1.

---

## Earlier — summary

- **2026-05 early** — v2 (slim registry + per-operator Octra Circle)
  deployed at `oct3fxjrzfqh65ATo31eau8xRFBPiXh2Uzwue56EYkfVSj7`. 45/45
  adversarial drill, end-to-end on devnet through `open_session`.
  Atomic `register_circle` fix (chicken-and-egg of "bond requires
  owner / owner requires bond"). See
  [`v2-release-notes.md`](v2-release-notes.md).
- **2026-04** — P1-6 sealed keys + P1-8/P1-9 receipt journal +
  P1-5 bind program_addr + chain_id + circle_id into receipts.
  See the root README "fix queue" status table.
- **2026-03** — PVAC sidecar past the AES KAT wall; GPL-isolated
  daemon producing chain-compatible HFHE blobs over JSON-over-stdio.
- **Earlier** — v1.1 (`oct2YehVLezCi2RCcSkURc3nyyYtzxmspwGHHALm6pjkUvJ`)
  shipped: public-registry operators, two-tx settle, cryptographic
  `slash_double_sign`. The 49-case adversarial drill landed clean.
  See [`v1.1-release-notes.md`](v1.1-release-notes.md).

For anything older, use `git log`.
