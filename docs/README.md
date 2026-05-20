# OctraVPN documentation

This directory holds every long-form doc for OctraVPN — the
decentralized Tailscale-style mesh VPN coordinated by AppliedML
programs on Octra. The top-level [`../README.md`](../README.md) is
the project pitch + quickstart; this file is the **navigation hub**
for everything deeper.

If you are landing here cold, pick a path below.

---

## I am a...

### End-user (someone gave me a join key)

You want to put a laptop / phone on a tailnet that another person
runs. You will not run a validator, mint keys, or read AML.

1. [`users/README.md`](users/README.md) — what OctraVPN is for users.
2. Per-OS install — [`users/linux.md`](users/linux.md) ·
   [`users/macos.md`](users/macos.md) ·
   [`users/windows.md`](users/windows.md).
3. [`users/connect.md`](users/connect.md) — paste your preauth key,
   confirm the device shows up.
4. [`users/using.md`](users/using.md) — day-to-day flows (sharing,
   exit nodes, MagicDNS, tearing down).

Fallback (if `docs/users/` pages aren't live yet on your branch):
[`tailnet-user-guide.md`](tailnet-user-guide.md) ·
[`tutorial-client.md`](tutorial-client.md).

### Operator (I want to run a validator + earn OU)

You stake OU, run an exit/relay endpoint, and collect bandwidth
receipts that settle on-chain.

1. [`operators/tour-operator.md`](operators/tour-operator.md) — the
   guided narrative tour from cold host to first paid byte.
2. [`operators/mainnet-deployment.md`](operators/mainnet-deployment.md)
   — concrete runbook (Docker / systemd / bond / register).
3. [`operators/troubleshooting.md`](operators/troubleshooting.md) —
   "my node won't bond" / "settle is failing" / "DERP is hot".
4. [`maintenance/`](maintenance/) — long-running ops: rotation
   schedules, key hygiene, audit-log replay, upgrade gates.
5. Day-2 reference: [`operator-guide.md`](operator-guide.md) ·
   [`operators/pvac-rotation.md`](operators/pvac-rotation.md) ·
   [`operators/tls-rotation.md`](operators/tls-rotation.md) ·
   [`operators/derp-fronting.md`](operators/derp-fronting.md) ·
   [`operators/obfs4-bridge.md`](operators/obfs4-bridge.md) ·
   [`operators/cli-migration.md`](operators/cli-migration.md).

### Tailnet owner (I run the control plane + a treasury)

You hold the owner wallet, mint preauth keys, fund the treasury,
gate ACLs, and approve members.

1. [`tailnet-owners/tour-owner.md`](tailnet-owners/tour-owner.md) —
   guided tour: owner-wallet ceremony → first preauth → first joiner.
2. [`mainnet-ceremony.md`](mainnet-ceremony.md) — the v3 mainnet
   deploy + owner-wallet provisioning ceremony.
3. [`v3-members-schema.md`](v3-members-schema.md) +
   [`v3-policy-schema.md`](v3-policy-schema.md) — the sealed
   members.json / policy.json your circle holds.
4. [`governance.md`](governance.md) — roles, parameters, slash rules,
   decentralization roadmap.

### Auditor / external reviewer

You are reading the codebase to issue a security finding, a formal
audit report, or a third-party assurance opinion.

1. [`audit/README.md`](audit/README.md) — orientation + manifest for
   the audit-prep package.
2. [`audit/threat-model-summary.md`](audit/threat-model-summary.md) →
   [`audit/security-properties.md`](audit/security-properties.md) →
   [`audit/known-limitations.md`](audit/known-limitations.md).
3. [`audit/2026-05-20-deep-security-audit.md`](audit/2026-05-20-deep-security-audit.md)
   (C-1 flagged) +
   [`audit/2026-05-20-concurrency-error-config-audit.md`](audit/2026-05-20-concurrency-error-config-audit.md)
   + [`audit/2026-05-20-claims-audit.md`](audit/2026-05-20-claims-audit.md).
4. [`v3/`](v3/) — the deployed substrate's design-doc set
   ([`v3/overview.md`](v3/overview.md),
   [`v3/security-model.md`](v3/security-model.md),
   [`v3/state-machine.md`](v3/state-machine.md),
   [`v3/data-model.md`](v3/data-model.md),
   [`v3/canonical-encoders.md`](v3/canonical-encoders.md),
   [`v3/call-flows.md`](v3/call-flows.md),
   [`v3/fee-model.md`](v3/fee-model.md),
   [`v3/v3-vs-v2.md`](v3/v3-vs-v2.md)).
5. Lean theorems index — [`../proofs/lean/WireProtocol/Theorems.md`](../proofs/lean/WireProtocol/Theorems.md)
   (the canonical entry point into the 232-theorem Lean workspace).
6. [`security/threat-model-v3.md`](security/threat-model-v3.md) +
   [`security/pentest-runbook.md`](security/pentest-runbook.md) +
   [`security/validator-hardening.md`](security/validator-hardening.md).
7. [`audit/file-index.md`](audit/file-index.md) + the
   [`audit/dependency-audit.md`](audit/dependency-audit.md).

Time-budget version: see [`READING_PATHS.md`](READING_PATHS.md)
"Half day (auditor)".

### Contributor / integrator (I want to ship code against this)

You are adding a feature, fixing a bug, wiring an integration, or
forking the workspace.

1. [`architecture.md`](architecture.md) — long-form system design
   (v1.1 + v2 + v3, AML + Rust + sidecar layout).
2. [`headscale-gap-analysis.md`](headscale-gap-analysis.md) — what
   the embedded Tailscale-style control plane covers vs. upstream.
3. [`refactor-plan-2026-05-20.md`](refactor-plan-2026-05-20.md) —
   the active plan (module collisions, agent-safe boundaries, what
   *not* to touch).
4. [`contributing-tests.md`](contributing-tests.md) — the test
   surface, gate command, and how to add a new harness.
5. [`architecture/headscale-dep-strategy.md`](architecture/headscale-dep-strategy.md)
   — how `headscale-rs` is vendored vs. path-dep'd.
6. The repo's [`CONTRIBUTING.md`](../CONTRIBUTING.md) +
   [`SECURITY.md`](../SECURITY.md) at the workspace root.

---

## Watch first

If you'd rather see it than read it, start with the **master demo
tour** — a single recording that walks the cold-start operator
flow end-to-end (init → keygen → identity → mesh preauth → portal
fetch → audit replay → v3 smoke):

- [`../demo/recordings/00-master-tour.mp4`](../demo/recordings/00-master-tour.mp4)
  (master tour; lands alongside the sibling demo-recording pass).
- Inline preview of step 1 — `octravpn init` + keygen + identity:

  ![init / keygen demo](../demo/recordings/01-init-keygen.gif)

- Inline preview of step 4 — mesh preauth (single-use + reusable):

  ![mesh preauth demo](../demo/recordings/04-mesh-preauth.gif)

Source `.tape` files for every demo segment live in
[`../demo/tapes/`](../demo/tapes/). Regenerate everything with
`bash ../demo/run-demo.sh` from inside a Codespace.

---

## Status + verification

This project ships with a deliberate audit and verification surface
so reviewers can confirm claims without trusting prose:

- [`audit/README.md`](audit/README.md) — the external-review
  orientation package (read-only, deterministic regen).
- The proof-of-working-state CI workflow
  (`.github/workflows/proof.yml`) — the badge in the root README
  links to its summary tab (test counts, clippy gate, Lean count,
  signed `.deb`/`.rpm` hashes).
- Verification-coverage doc — a follow-up artifact that will live
  at `docs/audit/verification-coverage.md` once the next
  audit-prep pass lands; until then the closest existing map is
  [`audit/security-properties.md`](audit/security-properties.md)
  (property → spec → enforcement-point).
- Lean theorem index —
  [`../proofs/lean/WireProtocol/Theorems.md`](../proofs/lean/WireProtocol/Theorems.md).
- v2 threat-model fix queue — [`v2-threat-model.md`](v2-threat-model.md)
  (P0/P1 status table, current commit pointer).

---

## How docs are organized

```
docs/
├── README.md                # ← you are here (navigation hub)
├── READING_PATHS.md         # by time budget
├── INDEX.md                 # alphabetical, every .md, one-liner each
├── changelog.md             # major doc + substrate beats
│
├── users/                   # end-user join + day-2 flows
├── operators/               # validator runbooks (tour + per-task)
├── tailnet-owners/          # control-plane owner + treasury
├── maintenance/             # long-running ops: rotation, audits
├── audit/                   # external-review prep package
├── security/                # threat models + hardening + pentest
├── architecture/            # subsystem-specific design notes
└── v3/                      # the deployed substrate's design set
```

Top-level `.md` files in `docs/` are **per-topic deep dives** —
treat them as references the audience pages link into, not as a
reading order.

When in doubt:

- Need a known topic by name → [`INDEX.md`](INDEX.md).
- Have a time budget → [`READING_PATHS.md`](READING_PATHS.md).
- Want a chronology → [`changelog.md`](changelog.md).
