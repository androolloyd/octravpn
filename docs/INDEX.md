# Docs index — alphabetical

Every `.md` file under `docs/` with a one-line summary. Use this
when you know the topic by name and want to grep. For a curated
reading order, see [`README.md`](README.md) or
[`READING_PATHS.md`](READING_PATHS.md). For a chronology, see
[`changelog.md`](changelog.md).

Count: 90 files (regenerate with
`find docs -name "*.md" | wc -l` — if this number drifts, update
the table). Sibling agents are actively landing `docs/users/*`,
`docs/operators/tour-*`, `docs/maintenance/*`, and
`docs/tailnet-owners/*` pages; expect this count to grow.

---

## Top-level (`docs/`)

| File | Summary |
| --- | --- |
| [`INDEX.md`](INDEX.md) | This file — alphabetical index of every doc. |
| [`README.md`](README.md) | Navigation hub — "I am a..." audience selector. |
| [`READING_PATHS.md`](READING_PATHS.md) | Per-time-budget reading guide (5 min → half day). |
| [`aml-gap-analysis.md`](aml-gap-analysis.md) | AML gap analysis: OctraVPN vs. confirmed Octra primitives. |
| [`aml-grammar.md`](aml-grammar.md) | Real AML grammar — reverse-engineered reference. |
| [`architecture.md`](architecture.md) | Long-form system design (v1.1 + v2 + v3, AML + Rust + sidecar). |
| [`attack-cost.md`](attack-cost.md) | Attack-cost analysis — what an adversary pays per attack class. |
| [`changelog.md`](changelog.md) | Chronological log of major doc + substrate beats. |
| [`contributing-tests.md`](contributing-tests.md) | Test surface, gate command, how to add a new harness. |
| [`demo.md`](demo.md) | OctraVPN demo runbook. |
| [`deploy.md`](deploy.md) | Operator deployment guide (legacy long-form). |
| [`deployment-runbook.md`](deployment-runbook.md) | Concrete deployment runbook. |
| [`economics.md`](economics.md) | Economic design — OU-only token flow + operator P&L. |
| [`faq.md`](faq.md) | Frequently asked questions. |
| [`gap-analysis.md`](gap-analysis.md) | Honest gap analysis — what works / what doesn't. |
| [`governance.md`](governance.md) | Roles, parameters, slash rules, decentralization roadmap. |
| [`headscale-gap-analysis.md`](headscale-gap-analysis.md) | `headscale-go` → `headscale-rs` gap analysis. |
| [`install.md`](install.md) | Per-OS install guide (general / try-it-out). |
| [`keys.md`](keys.md) | Key management — what keys exist, where they live, rotation. |
| [`mainnet-ceremony.md`](mainnet-ceremony.md) | v3 mainnet deploy + owner-wallet ceremony. |
| [`observability.md`](observability.md) | Observability runbook — metrics, logs, traces. |
| [`oct-url-handler.md`](oct-url-handler.md) | `oct://` URL handler design. |
| [`octra-dev-questions-email.md`](octra-dev-questions-email.md) | Email-form of open questions to the Octra dev team. |
| [`octra-dev-questions.md`](octra-dev-questions.md) | Open questions to the Octra dev team (long form). |
| [`octra-research.md`](octra-research.md) | Public-info dossier on the Octra chain. |
| [`operator-guide.md`](operator-guide.md) | Validator / endpoint operator guide (day-2). |
| [`performance-limitations.md`](performance-limitations.md) | Performance limitations — measured ceilings and bottlenecks. |
| [`production-checklist.md`](production-checklist.md) | v1 production checklist. |
| [`production-readiness.md`](production-readiness.md) | Production readiness checklist (current). |
| [`refactor-plan-2026-05-20.md`](refactor-plan-2026-05-20.md) | Active refactor plan — agent collisions, what *not* to touch. |
| [`release.md`](release.md) | Release runbook. |
| [`security-roadmap.md`](security-roadmap.md) | Security + identity roadmap. |
| [`security.md`](security.md) | v1.1 threat model + formal-verification correspondence. |
| [`tailnet-user-guide.md`](tailnet-user-guide.md) | Tailnet user guide (legacy single-page). |
| [`tailscale-interop-blocker.md`](tailscale-interop-blocker.md) | Tailscale-interop blocker handoff. |
| [`tailscale-interop-finding.md`](tailscale-interop-finding.md) | Tailscale interop test finding (2026-05-19). |
| [`testnet.md`](testnet.md) | Testnet readiness. |
| [`threat-model.md`](threat-model.md) | v1 archive threat model. |
| [`troubleshooting.md`](troubleshooting.md) | Troubleshooting — symptom → fix. |
| [`tutorial-client.md`](tutorial-client.md) | "Your first OctraVPN session" (5 min). |
| [`tutorial-validator.md`](tutorial-validator.md) | "Your first OctraVPN validator-VPN node" (10 min). |
| [`v1.1-release-notes.md`](v1.1-release-notes.md) | v1.1 release notes (cryptographic `slash_double_sign`). |
| [`v2-circles-design.md`](v2-circles-design.md) | v2 Circle-native architecture (status snapshot in §0). |
| [`v2-client-flow.md`](v2-client-flow.md) | v2 client flow (discover + connect-v2). |
| [`v2-octra-questions.md`](v2-octra-questions.md) | v2-specific questions for the Octra dev team. |
| [`v2-operator-flow.md`](v2-operator-flow.md) | v2 operator boot sequence (deploy + register). |
| [`v2-operator-key-hygiene.md`](v2-operator-key-hygiene.md) | v2 operator key hygiene — fresh-wallet rule + sealed-key mode. |
| [`v2-release-notes.md`](v2-release-notes.md) | v2 release notes (substrate — what shipped, commit-by-commit). |
| [`v2-rust-leak-audit.md`](v2-rust-leak-audit.md) | Rust crypto + node-daemon leak audit (v2 hardening pass). |
| [`v2-threat-model.md`](v2-threat-model.md) | v2 cryptographic threat model + 18-item fix queue. |
| [`v3-circle-resident-architecture.md`](v3-circle-resident-architecture.md) | v3 circle-resident architecture (top-level overview). |
| [`v3-members-schema.md`](v3-members-schema.md) | v3 `members.json` schema. |
| [`v3-policy-schema.md`](v3-policy-schema.md) | v3 `policy.json` schema. |
| [`v3-state-root-schema.md`](v3-state-root-schema.md) | v3 `state-root.json` schema. |
| [`validator-hardening.md`](validator-hardening.md) | Validator (paid endpoint) hardening playbook. |
| [`value.md`](value.md) | "What OctraVPN provides" — plain-English value prop. |
| [`whitepaper.md`](whitepaper.md) | OctraVPN whitepaper — decentralized private mesh networking on Octra. |

## `architecture/`

| File | Summary |
| --- | --- |
| [`architecture/headscale-dep-strategy.md`](architecture/headscale-dep-strategy.md) | `headscale-rs` / `octra-foundry` dependency strategy. |

## `audit/`

| File | Summary |
| --- | --- |
| [`audit/2026-05-20-claims-audit.md`](audit/2026-05-20-claims-audit.md) | Documentation claims audit (2026-05-20). |
| [`audit/2026-05-20-concurrency-error-config-audit.md`](audit/2026-05-20-concurrency-error-config-audit.md) | Concurrency / error / config audit (2026-05-20). |
| [`audit/2026-05-20-deep-security-audit.md`](audit/2026-05-20-deep-security-audit.md) | Deep security audit — OctraVPN v3 + headscale-rs + octra-foundry (C-1 flagged). |
| [`audit/README.md`](audit/README.md) | External security audit orientation. |
| [`audit/dependency-audit.md`](audit/dependency-audit.md) | Dependency audit. |
| [`audit/file-index.md`](audit/file-index.md) | In-scope file index. |
| [`audit/known-limitations.md`](audit/known-limitations.md) | Known limitations / open TODOs. |
| [`audit/security-properties.md`](audit/security-properties.md) | Security properties (property ↔ spec ↔ enforcement-point). |
| [`audit/threat-model-summary.md`](audit/threat-model-summary.md) | Threat model — v3 executive summary. |

## `maintenance/`

| File | Summary |
| --- | --- |
| [`maintenance/README.md`](maintenance/README.md) | Maintenance index (long-running ops, rotation, audits) — landed by sibling agent. |

## `operators/`

| File | Summary |
| --- | --- |
| [`operators/cli-migration.md`](operators/cli-migration.md) | Operator CLI migration: `headscale` → `octravpn-node headscale`. |
| [`operators/derp-fronting.md`](operators/derp-fronting.md) | DERP domain-fronting (operators). |
| [`operators/mainnet-deployment.md`](operators/mainnet-deployment.md) | Mainnet deployment runbook — clean host → paid v3 node. |
| [`operators/obfs4-bridge.md`](operators/obfs4-bridge.md) | obfs4 bridge runbook. |
| [`operators/pvac-rotation.md`](operators/pvac-rotation.md) | PVAC pubkey rotation runbook. |
| [`operators/tls-rotation.md`](operators/tls-rotation.md) | TLS pin and rotation runbook. |

## `security/`

| File | Summary |
| --- | --- |
| [`security/pentest-runbook.md`](security/pentest-runbook.md) | OctraVPN pentest runbook. |
| [`security/threat-model-v3.md`](security/threat-model-v3.md) | v3 threat model. |
| [`security/validator-hardening.md`](security/validator-hardening.md) | Validator hardening. |

## `users/`

| File | Summary |
| --- | --- |
| [`users/README.md`](users/README.md) | End-user guide — joining a tailnet with a preauth key. |
| [`users/linux.md`](users/linux.md) | Linux install / connect / use — landed by sibling agent. |
| [`users/macos.md`](users/macos.md) | macOS install / connect / use — landed by sibling agent. |

## `v3/` (design-doc set for the deployed substrate)

| File | Summary |
| --- | --- |
| [`v3/README.md`](v3/README.md) | v3 design-doc set entry point + per-audience reading order. |
| [`v3/call-flows.md`](v3/call-flows.md) | v3 call flows (deploy / register / open-session / settle). |
| [`v3/canonical-encoders.md`](v3/canonical-encoders.md) | v3 canonical encoders (byte-for-byte). |
| [`v3/data-model.md`](v3/data-model.md) | v3 data model (on-chain + sealed-asset). |
| [`v3/deployment.md`](v3/deployment.md) | v3 deployment. |
| [`v3/fee-model.md`](v3/fee-model.md) | v3 fee model. |
| [`v3/overview.md`](v3/overview.md) | v3 overview — chain-minimal successor to v2. |
| [`v3/security-model.md`](v3/security-model.md) | v3 security model + adversary scope. |
| [`v3/state-machine.md`](v3/state-machine.md) | v3 state machine (TLA+-companion). |
| [`v3/v3-vs-v2.md`](v3/v3-vs-v2.md) | Per-entrypoint delta from v2. |
