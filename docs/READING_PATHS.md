# Reading paths by time budget

Pick the row that matches the time you have. Each path is a finite,
ordered list of files — read them top-to-bottom, stop when you run
out of clock. Every link in this doc resolves to a file that exists
on `main` (or is being landed by a sibling agent — those are
flagged inline).

If you have no budget at all, the [`../README.md`](../README.md)
project pitch + the audience selector in [`README.md`](README.md) is
the absolute minimum.

---

## 5 minutes — "what is this thing"

Goal: leave with a one-paragraph mental model + visual confirmation
that the cold-start flow actually works.

1. [`../README.md`](../README.md) — the project pitch (top of file
   through "Architecture").
2. Inline GIF — `octravpn init` + keygen + identity:

   ![init / keygen demo](../demo/recordings/01-init-keygen.gif)

3. (Optional) skim [`value.md`](value.md) — "What OctraVPN provides"
   in plain English.

That's it. You now know the elevator pitch and have seen the cold
start.

---

## 30 minutes — "I want to understand the substrate"

Goal: understand what v3 is, what it replaced, and why.

1. [`../README.md`](../README.md) — full read, including the
   "What's shielded, by layer" table and the slashing table.
2. [`v3/overview.md`](v3/overview.md) — chain-minimal successor;
   what stayed on chain, what moved into circles.
3. [`v3/v3-vs-v2.md`](v3/v3-vs-v2.md) — per-entrypoint delta from v2.
4. Watch the master demo tour at
   [`../demo/recordings/00-master-tour.mp4`](../demo/recordings/00-master-tour.mp4)
   — cold-start operator flow end-to-end, ~6 minutes wall time.

You can now hold a coffee-break conversation about "why circles" and
"what the chain enforces" without bluffing.

---

## 2 hours — "I am going to operate or build on it"

Goal: leave able to read the code base without grep-fishing.

1. [`../README.md`](../README.md) — full read.
2. [`users/README.md`](users/README.md) — the user-facing model.
3. [`operators/tour-operator.md`](operators/tour-operator.md) —
   guided operator narrative (landed by sibling agent).
4. [`v3/README.md`](v3/README.md) — design-doc set, top-down:
   `overview.md` → `data-model.md` → `state-machine.md` →
   `call-flows.md` → `canonical-encoders.md` → `fee-model.md` →
   `security-model.md` → `deployment.md` → `v3-vs-v2.md`.
5. [`architecture.md`](architecture.md) — long-form system design
   (skim the v1.1 + v2 sections; the v3 section is the live one).
6. [`headscale-gap-analysis.md`](headscale-gap-analysis.md) — what
   the embedded headscale Rust port does / doesn't cover.
7. [`v3/security-model.md`](v3/security-model.md) — adversary
   model + what v3 defends and concedes.

After this you should be able to pattern-match new code against
"which subsystem owns this" without a tour guide.

---

## Half day (auditor) — "I will issue a finding"

Goal: enough surface to write a real audit report — claims, evidence,
gaps.

1. [`audit/README.md`](audit/README.md) — orientation + manifest.
2. [`audit/threat-model-summary.md`](audit/threat-model-summary.md).
3. [`audit/security-properties.md`](audit/security-properties.md) —
   property ↔ spec ↔ enforcement-point map.
4. [`audit/known-limitations.md`](audit/known-limitations.md).
5. [`audit/dependency-audit.md`](audit/dependency-audit.md).
6. [`audit/file-index.md`](audit/file-index.md) — in-scope code map.
7. [`audit/2026-05-20-deep-security-audit.md`](audit/2026-05-20-deep-security-audit.md)
   — C-1 critical flagged here; read it before the next two.
8. [`audit/2026-05-20-concurrency-error-config-audit.md`](audit/2026-05-20-concurrency-error-config-audit.md).
9. [`audit/2026-05-20-claims-audit.md`](audit/2026-05-20-claims-audit.md).
10. [`v3/security-model.md`](v3/security-model.md) — substrate-level
    adversary model + the exit-IP concession.
11. [`security/threat-model-v3.md`](security/threat-model-v3.md).
12. [`security/pentest-runbook.md`](security/pentest-runbook.md).
13. [`../proofs/lean/WireProtocol/Theorems.md`](../proofs/lean/WireProtocol/Theorems.md)
    — Lean theorems index (canonical entry point into the 232-theorem
    workspace, by module: BeNonce, Controlbase, HFHE, HmacToken,
    PortalCache, RpcEnvelope, Shielding, V3Canonical, V3Members,
    V3Policy, Wire).
14. [`v2-threat-model.md`](v2-threat-model.md) — the 18-item fix
    queue + current P0/P1 status (carry-over surface relevant to v3).
15. [`v2-rust-leak-audit.md`](v2-rust-leak-audit.md) — Rust-side
    leak audit (memory, key material, log surfaces).

Half-day = land on items 1–10 with notes; the rest is depth on
specific findings.

---

## Onboarding contributor — "I will land a PR this week"

Goal: be able to point at a subsystem, explain what owns what, and
write a clean PR that doesn't collide with concurrent agents.

1. [`architecture.md`](architecture.md) — long-form system design
   (full read, including the deployment + sibling-repo sections).
2. [`refactor-plan-2026-05-20.md`](refactor-plan-2026-05-20.md) —
   **read this before you touch anything.** It is the current source
   of truth for "module X is being refactored — do not touch."
   The scope rule explicitly excludes `crates/octravpn-tun/**`.
3. [`contributing-tests.md`](contributing-tests.md) — the full test
   surface, the one-command gate, the proptest + Kani + Lean + TLA+
   harnesses, how to add a new one.
4. [`../CONTRIBUTING.md`](../CONTRIBUTING.md) +
   [`../SECURITY.md`](../SECURITY.md) — workflow + disclosure rules.
5. [`v3/README.md`](v3/README.md) — the substrate you are building
   against.
6. [`headscale-gap-analysis.md`](headscale-gap-analysis.md) +
   [`architecture/headscale-dep-strategy.md`](architecture/headscale-dep-strategy.md)
   — the embedded coordination layer.
7. Check out the code: `cargo build --workspace --release` from the
   repo root, then `./scripts/test-all.sh` from the repo root, then
   open `crates/octravpn-node/src/` (start at `main.rs` →
   `cli/` → the subsystem you care about).
8. Skim [`changelog.md`](changelog.md) — the major doc + substrate
   beats from the last few weeks.

Cadence note: agents land in parallel on this repo. Before you
push, re-read item 2 — the refactor plan is updated when an agent
opens a new module collision.

---

## Cross-cutting: the absolute shortest path by question

| Question | One file |
| --- | --- |
| "Where do tokens flow?" | [`economics.md`](economics.md) |
| "What can be slashed?" | [`governance.md`](governance.md) |
| "Is it ready for mainnet?" | [`production-readiness.md`](production-readiness.md) |
| "How do I install it?" | [`install.md`](install.md) |
| "It's broken." | [`troubleshooting.md`](troubleshooting.md) |
| "What's the wire grammar?" | [`aml-grammar.md`](aml-grammar.md) |
| "What's the long-form pitch?" | [`whitepaper.md`](whitepaper.md) |
| "What did Octra dev confirm?" | [`octra-research.md`](octra-research.md) |
