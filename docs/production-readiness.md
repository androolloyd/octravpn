# OctraVPN — production readiness checklist

**Scope.** Single source of truth answering "how close are we to shipping
OctraVPN to a real paying operator on Octra mainnet?" Pulls together the
fragmented state from `production-checklist.md` (v1 gates),
`headscale-gap-analysis.md` (mesh control-plane parity),
`tailscale-interop-blocker.md` (Wall 5), and `octra-dev-questions.md`
(chain-side blockers).

**Last updated.** 2026-05-19.

**Operator persona.** A single operator: one wallet, one bonded circle on
Octra mainnet, one tailnet hosting 5–50 stock-`tailscale` clients, real
egress through their nodes, real OCT settled per session. They are
technical (can run `systemctl`, read a TOML config, hold a sealed
passphrase in a password manager) but they are NOT a Tailscale engineer
and NOT a Solidity auditor. They want one binary, one config, and a
runbook.

## Verdict at a glance

**Where we are today.** Substrate is real but not connected end-to-end.
v3 AML is deployed and exercised on devnet
(`oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3`, commit `04bc252`);
the full lifecycle clears smoke + a 40-case adversarial drill. The
client/node Rust stack compiles, has TLS-pinned cert validation,
sealed-key boot, and a signed receipt journal. The mesh control plane
ships `/key`, `/ts2021`, flat `/machine/{register,map}`, controlbase
framing, BE-nonce noise transport, and h2-over-Noise (commit `e0337b5`).
Where we are NOT: stock `tailscale up` against our control plane still
exits non-zero (Wall 5 — post-register the daemon never reaches "Up");
chain-side `fhe_*` host calls revert on every newly-deployed contract;
the v3 mainnet deploy + owner-wallet ceremony has not happened; no
independent audit has started.

**Smallest set that closes the gap to "one operator on mainnet."** Five
items (enumerated in P0 below): close Wall 5 so a stock client actually
joins, finish operator CLI surface for the day-2 ops a node operator
needs (preauth keys, policy reload, node lifecycle), deploy v3 AML to
mainnet behind an owner-wallet ceremony, replace devnet-only smoke
harness with one mainnet-runnable smoke, and ship a v0 operator runbook
that covers the keys, the bond, the receipts journal, and the recovery
paths. None of these depend on Octra dev-team action; all four of the
chain-side asks in `octra-dev-questions.md` improve v3 but do not block
the first mainnet operator.

**What we are NOT doing for v0.1.** Multi-tenant control plane,
DERP-relay hosting, OIDC SSO, MagicDNS, delta `MapResponse` updates,
HFHE-encrypted ledger, circle-resident bonds. All deferred to v1.0
(see "broadly" section below).

## Inventory

### 1. Wire protocol (interop test)

| Area | Item | State | Blocker | Exit criteria for production |
|---|---|---|---|---|
| Mesh | `GET /key` + persistent X25519 server key | shipped (`e0337b5`) | — | shipped |
| Mesh | TS2021 / controlbase + Noise IK + EarlyNoise | shipped — Wall 4 closed (`e0337b5`) | — | shipped |
| Mesh | Flat `/machine/{register,map}` + TLS-on-443 | shipped (`2654663`) | — | shipped |
| Mesh | `MapResponse` per-chunk streaming | partial — single-shot + 30s keepalives, no per-chunk writer | task #215 (Wall 5) | per-chunk ndjson; stock client reaches "Up" + survives a peer change |
| Mesh | Stock `tailscale up` joins mesh — exit 0 on `docker/devnet/tailscale-interop/run-interop.sh` | **failing** — Wall 5 | task #215 | `run-interop.sh` exits 0 in CI for 5 consecutive nights |
| Mesh | EarlyNoise validated against real client bytes | unverified — daemon never reaches `/ts2021` cleanly in stock-client flow | task #215 | tcpdump shows our challenge accepted |
| Mesh | `MapResponse.PacketFilters` populated from ACL | missing | headscale-rs P1 (gap-analysis §4) | ACL deny rules enforced client-side on real `tailscale ping` denials |

### 2. Chain integration (v3 substrate)

| Area | Item | State | Blocker | Exit criteria for production |
|---|---|---|---|---|
| Chain | v3 AML deployed on devnet, lifecycle smoke passes | shipped (`04bc252`) | — | shipped |
| Chain | 40-case adversarial drill on devnet | shipped (`7b31443`) | — | shipped |
| Chain | Hash-chain commit ledger (plaintext running total) | shipped (`c1a5997`) | — | shipped — interim until HFHE bridge lands |
| Chain | v3 AML deployed on mainnet | not started | owner-wallet ceremony (§7) | deployed under cold-storage multisig; full smoke runs against mainnet |
| Chain | HFHE-encrypted running totals (replaces plaintext) | blocked | `octra-dev-questions.md` §1 (AML→HFHE bridge) | `fhe_*` host calls executable; v3 §5.2 swap-in complete |
| Chain | Bonds + slash live in `BondEscrow` circle (not main contract) | blocked | `octra-dev-questions.md` §2 (circle execution) | `contract_call` against circle returns expected output; v3 §6 swap path executed |
| Chain | Inline PVAC ciphertexts in map values | blocked | `octra-dev-questions.md` §3 (4 KiB cap) | inline ≥64 KiB cap, or chunked-blob primitive |
| Chain | `circle_id` derivation stability across main-contract redeploys | verified empirically, confirmation pending | `octra-dev-questions.md` §5 | written confirmation from Octra team |
| Chain | Receipt-anchor binding (program_addr + chain_id + circle_id) | shipped (`060903d`, P1-5) | — | shipped |
| Chain | Receipt journal — fsync floor before signing | shipped (`8db1ad1`, P1-8/9) | — | shipped |
| Chain | Cert pinning on RPC client | shipped (`2d933fc`, P0-2) | — | shipped |
| Chain | Sealed keys on disk + zeroized passphrase | shipped (`8db1ad1` / `2d933fc`, P1-6/P1-10) | — | shipped |

### 3. Node operator surface (CLI, admin HTTP, packaging)

| Area | Item | State | Blocker | Exit criteria for production |
|---|---|---|---|---|
| CLI | `octravpn-node` v3 subcommand surface (17 cmds) | shipped (`00c274a`) | — | shipped |
| CLI | Operator audit CLI (`octravpn audit …` for ledger + receipt diffs) | not started | task #217 | covers session/settle/claim diff against chain state; flags drift |
| CLI | Operator CLI v0 — production-runbook subset (bond, register-circle, rotate keys, dump receipts, mirror state-root) | partial — subcommands exist; not consolidated under one operator-facing UX | task #216 | one binary, one `--config`, ten verbs an operator needs in a runbook |
| CLI | Headscale-side operator CLI: `users`, `preauthkeys`, `policy`, `apikeys` | missing | headscale-gap-analysis.md §11 | preauth keys are CLI-manageable; HTTP `/admin/preauth` shim no longer load-bearing |
| Admin | `/admin/preauth` token-gated minter | shipped (`2e1ad52`, `f4f5e65`) | — | shipped |
| Admin | `/events` SSE gated by `events_token` | shipped (`f4f5e65`) | — | shipped |
| Packaging | Reproducible builds for node + client | not started | F-row of `production-checklist.md` | cosign-signed artefact; bit-for-bit reproducible from a clean checkout |
| Packaging | Cosign-signed releases + SBOM | not started | — | release artefacts attested in Sigstore + CycloneDX SBOM attached |
| Packaging | Multi-arch OCI images | not started | — | linux/amd64 + linux/arm64 + macOS/arm64 |

### 4. Client UX (portal, fetch, OS handlers)

| Area | Item | State | Blocker | Exit criteria for production |
|---|---|---|---|---|
| Portal | `oct://` URL handler — macOS + Linux + Windows assets | shipped (`a78efb6`, `0c749fd`) | — | shipped |
| Portal | `oct://` portal decrypts sealed v2 assets, renders | shipped (`5dc31cd`) | — | shipped |
| Client | `octravpn-client` fetch CLI + interactive unseal + `/raw` | shipped (`366cb25`) | — | shipped |
| Client | Two-step claim flow (AML transfer + native-tx stealth wrap) | not started | C-row of `production-checklist.md`; depends on stealth-tx primitives | a claimer can withdraw without linking the receiving address to the claim |
| Client | Sealed passphrase rotation flow | partial | — | documented + drilled in operator runbook |

### 5. Observability + ops

| Area | Item | State | Blocker | Exit criteria for production |
|---|---|---|---|---|
| Metrics | `/metrics` Prometheus + mesh counters | shipped | — | shipped |
| Metrics | Grafana dashboards + alerting rules | shipped | — | shipped |
| Metrics | Per-bench regression gate in CI | shipped (`c2d5553`) | — | shipped |
| Ops | systemd hardening profile | shipped | — | shipped |
| Ops | Incident-response oncall rotation | not started | G-row of `production-checklist.md` | named oncall + escalation tree + a paged drill |
| Ops | Owner-wallet ceremony | not started | task #216 dependency | cold-storage multisig holds the program-deployer key; ceremony recorded |
| Ops | Bug-bounty program | not started | — | live on Immunefi or HackerOne with scope + payouts |

### 6. Documentation

| Area | Item | State | Blocker | Exit criteria for production |
|---|---|---|---|---|
| Docs | v3 architecture + circle-resident design | shipped (`6db7785`) | — | shipped |
| Docs | Performance-limitations / measured ceilings | shipped (`4182499`, `cf163c5`) | — | shipped |
| Docs | Headscale gap analysis | shipped (`d547b41`) | — | shipped |
| Docs | Octra dev-team open questions | shipped (`a1a1000`) | — | shipped (this rev) |
| Docs | Operator runbook v0 — mainnet flavour | partial (`docs/deployment-runbook.md` is v1 / devnet) | task #216 | covers mainnet deploy, mainnet bond, mainnet recovery, mainnet rotation |
| Docs | End-user FAQ / getting-started | partial — `docs/tutorial-client.md` exists, not refreshed for v3 | — | one page each for client install and "what is this VPN" |

### 7. Security audit gates

| Area | Item | State | Blocker | Exit criteria for production |
|---|---|---|---|---|
| Audit | Lean state machine + 54-theorem extension | shipped (`42183d3`) | — | shipped |
| Audit | TLA+ spec + invariants | shipped; TLC end-to-end run still pending | B-row of `production-checklist.md` | TLC clears in CI on the v3 spec |
| Audit | Kani harnesses on crypto primitives | partial | — | parity with the Lean theorems |
| Audit | Foundry clippy sweep (full workspace) | in progress | task #218 (parallel) | zero clippy warnings on `--workspace --all-targets` for `octra-foundry/` |
| Audit | Independent third-party audit of `program/main-v3.aml` + node Rust | not started | G-row of `production-checklist.md` | clean report from one of TOB / Spearbit / Zellic / Trail of Bits |
| Audit | Annual re-audit cadence | not started | — | scheduled |

### 8. External dependencies

| Area | Item | State | Blocker | Exit criteria for production |
|---|---|---|---|---|
| Octra | AML → HFHE bridge runs on newly-deployed contracts | open ask | `octra-dev-questions.md` §1 | `fhe_*` doesn't revert in a fresh deploy |
| Octra | Circle code execution from `contract_call` | open ask | `octra-dev-questions.md` §2 | `bump()` on the counter circle returns `1` |
| Octra | 4 KiB map-value cap raised (or chunked-blob primitive) | open ask | `octra-dev-questions.md` §3 | ≥64 KiB inline, OR a documented chunking primitive |
| Octra | `circle_id` stability — written confirmation | open ask | `octra-dev-questions.md` §5 | a sentence from the Octra dev team in writing |
| Octra | Sealed-asset write events | open ask | `octra-dev-questions.md` §6 | event emitted on `circle_asset_put_encrypted`; subscribable |
| Octra | Mainnet RPC body cap documented | open ask | `octra-dev-questions.md` §7 | a number we can target for client-side chunking |
| headscale-rs | Wire-surface drift fixes (P0 batch from gap analysis) | in progress | task #214 (drift), task #215 (Wall 5) | headscale-rs at parity with `tailscale_wire` PRs we landed locally |
| headscale-rs | Persistent `preauth_keys` + `machines` + `users` tables | not started | headscale-gap-analysis.md §10 | nodes survive a control-plane restart |
| headscale-rs | Embedded DERP server | not started | headscale-gap-analysis.md §5 | only required for WAN multi-tenant; not v0.1 |

## P0 (blocks the first mainnet deploy)

The minimum five that, when green, mean we can ship one paying operator
on mainnet today.

1. **Close Wall 5 — stock `tailscale up` joins mesh** (task #215). What:
   close the post-register stall described in
   `tailscale-interop-blocker.md` so `docker/devnet/tailscale-interop/run-interop.sh`
   exits 0 with the stock `tailscale/tailscale:latest` image (v1.78+).
   Why P0: without this, the operator has no usable mesh; they can run
   nodes but no real client joins. Current state: Walls 1–4 closed,
   wire surface present, post-register handshake unverified
   end-to-end. Size: large (1–1.5 person-weeks per the blocker doc's
   own estimate plus EarlyNoise validation against real client bytes).

2. **v3 AML mainnet deploy + owner-wallet ceremony** (G-row of
   `production-checklist.md`). What: deploy `program/main-v3.aml` to
   mainnet under a cold-storage multisig, run the smoke + adversarial
   drills against the mainnet program. Why P0: devnet wipes (memory
   `octra_devnet_rpc_body_cap.md`, `octra_aml_fhe_load_pk_blocked.md`)
   make devnet unsuitable for real money. State: deploy script exists
   (`docker/devnet/v3-smoke.sh`); the ceremony, the keys, and the
   mainnet-flavoured runbook do not. Size: medium.

3. **Operator CLI v0 — production runbook subset** (task #216,
   running in parallel). What: consolidate the 17 v3 subcommands
   (`00c274a`) into a single operator-facing UX with a documented set
   of verbs an operator runs from a mainnet runbook: `bond`,
   `register-circle`, `mirror-state`, `dump-receipts`, `rotate-keys`,
   `claim`, plus chain-state diagnostic commands. Why P0: the day-2
   ops surface is what an operator pages on; today it is a pile of
   developer-facing subcommands. State: subcommands exist; UX and
   runbook do not. Size: medium.

4. **Operator audit CLI** (task #217, running in parallel). What:
   `octravpn audit` subcommand that diffs the operator's local ledger
   + receipt journal against on-chain state and flags drift (sessions
   marked settled locally but not on-chain, hash-chain divergence,
   bond underflow, claim shortfall). Why P0: this is the operator's
   own canary for whether they're being silently overcharged or
   under-credited; on mainnet, with real money, they need it. State:
   not started. Size: medium.

5. **Mainnet-flavoured deployment runbook** (consolidates §6 in
   inventory). What: a single doc that walks one operator from a
   clean Ubuntu box to "running a mainnet OctraVPN node, serving one
   tailnet, claiming earnings." Must include the owner-wallet
   ceremony, sealed-passphrase generation rules
   (`memory:octra_aml_fhe_load_pk_blocked.md`'s warnings on devnet
   defaults), the receipt-journal recovery flow (`8db1ad1`), the
   chain_id pin (`f5b5a07`), and the operator-audit drill. Why P0:
   shipping a binary without a runbook means the operator fails on
   first contact. State: `docs/deployment-runbook.md` is v1 / devnet.
   Size: medium.

## P1 (blocks multi-tenant deployment)

What we need before a second operator can self-serve onto the network
without our handholding.

- **headscale-rs persistence layer.** Today `MachineRegistry` and
  `PreauthMinter` are in-process; a restart loses every joined node.
  Schema is straightforward (see `headscale-gap-analysis.md` §10), the
  work is wiring sqlx migrations + handlers. Size: medium.
- **AML→HFHE bridge runs on new deploys** (`octra-dev-questions.md`
  §1). Without this, v3 settle/claim leaks plaintext running totals to
  any chain observer. v0.1 ships with this leak documented; v1.0 does
  not. External dependency.
- **Circle code execution** (`octra-dev-questions.md` §2). Lets
  `BondEscrow` move into the per-operator circle; shrinks the main
  contract's surface area; unblocks v3 §6's "pure OU-routing main
  contract" target. External dependency.
- **`MapResponse.PacketFilters` populated from ACL.** Without this the
  client enforces no L3 policy; we currently gate at the node. Required
  for any deployment with ACL-sensitive resources. Size: medium.
- **Delta `MapResponse` updates.** Full snapshots are O(n²) per peer
  change. Fine for 2 peers; not fine for 50. Size: large (upstream's
  batcher is six files).
- **Machine lifecycle: logout / expire / renew / ephemeral GC.**
  Currently a node registers once and lives forever in RAM. Size:
  medium (couples to persistence).
- **Foundry clippy sweep** (task #218). Hygiene; not a correctness
  blocker but blocks the audit. Size: small (parallelisable).
- **TLC end-to-end on the v3 spec.** The spec exists; CI run does not.
  Size: small.
- **Two-step claim flow** with native-tx stealth wrap. Currently the
  claim links the claimer's receiving address. v0.1 acceptable as
  long as it's documented in the threat model; v1.0 needs the
  unlinkable path.
- **Bug-bounty program live.** Mainnet without an external incentive
  for researchers is a research-debt accumulation problem. Size:
  small (process, not code).

## P2 (operator polish, nice-to-have for v0)

- **Sealed-asset write events** (`octra-dev-questions.md` §6). Lets
  off-chain auditors subscribe rather than poll. Latency improvement,
  not correctness.
- **HuJSON ACL parser**, autogroups beyond `internet`, NodeAttr
  resolution. Upstream parity polish.
- **DERP map URL/file loaders.** Lets operators point at external
  relays without restart.
- **MagicDNS / SplitDNS.** Mesh names today resolve through the
  hard-coded `octra.test` domain with no responder.
- **gRPC admin API completeness.** `headscale-api/src/grpc.rs` exists;
  per-RPC handler coverage was not enumerated.
- **`/version`, `/robots.txt`** routes.
- **Annual re-audit cadence.** Worth scheduling once item 1 of the
  audit gate lands; not blocking v0.

## What changes "shippable to one operator" to "shippable broadly"

v0.1 — one operator, one tailnet, manual onboarding, mainnet money,
plaintext earnings totals on chain — is roughly the P0 list above. The
gap between v0.1 and v1.0 — "any technically-literate user can spin up
an operator without us in the loop" — is the P1 list, with three items
load-bearing:

**Persistence in headscale-rs.** A control plane whose state lives in
RAM is a control plane that re-onboards every node after every
deployment. We can keep five operators in a spreadsheet; we cannot keep
five hundred. The work is well-scoped (4 migrations exist; need ~5
more) but the change touches every handler that today reads from a
HashMap.

**HFHE-encrypted earnings ledger.** Today the chain sees per-circle
running plaintext OCT totals (`c1a5997`). For v0.1 with one operator
this is a privacy footgun for the operator's competitors, not a
solvency risk. For v1.0 it's structurally wrong — the whole point of
the v3 substrate is that operators don't expose per-session revenue to
the chain. External dependency on Octra's `fhe_*` bridge.

**OIDC SSO + interactive registration.** Today every joining node needs
a preauth key minted by the operator. For a five-user operator that's
fine; for a five-hundred-user operator that's a help-desk job. P2 in
the gap-analysis priority list but it is the single largest UX cliff
between v0.1 and v1.0.

Beyond those three: embedded DERP server (for WAN deployments where
NAT-traversal fails), reusable/ephemeral/tagged preauth keys, the
delta `MapResponse` plumbing, and key-rotation history. None
individually blocks broadening; all together they are the difference
between "an early-access mainnet pilot" and "a public service."

## Risks not captured by tasks

Risks too vague to land in a task tracker but real enough to call out:

- **Octra chain stability.** Devnet has wiped before; the 4 KiB cap and
  the AES KAT path both required forensic reverse-engineering rather
  than docs. We assume mainnet is more conservative but have no SLA.
  Mitigation: the receipt journal + sealed keys mean we can re-anchor
  state from operator-local artefacts; we do not assume the chain is
  the source of truth for *anything* an operator needs to recover.
- **Tailscale wire protocol drift.** v1.78+ already surprised us
  (Wall 5: forced-443 dial, flat `/machine/{register,map}` paths).
  Future client versions can and will move. Mitigation: pin to
  `tailscale/tailscale:1.78` in CI, gate v0.1 on a specific tested
  client version, and accept that "interop with stock latest" is a
  rolling commitment.
- **WireGuard kernel module compatibility.** Operators on older
  kernels (RHEL 7-era, custom-built) may not have `wireguard` as a
  loadable module. `wireguard-go` is a fallback but not what we
  test. Mitigation: a `doctor` subcommand that checks kernel module
  + module signing posture; document the supported kernels.
- **Bandwidth metering legal posture.** Operators relay traffic for
  paying users. Depending on jurisdiction (US common-carrier
  questions, EU GDPR data-controller status, AU metadata-retention
  rules) the operator may or may not be the lawful operator of a
  telecommunications service. This is a documentation + legal-counsel
  problem, not a code problem. We don't ship until we have a
  jurisdictional disclaimer in the operator runbook.
- **KYC for paid relays.** OCT settlement on chain is pseudonymous;
  operator earnings are real money. Tax-residency reporting is the
  operator's problem in v0.1, but we should ensure our docs don't
  imply otherwise. Out of scope for code; in scope for docs.
- **Headscale-rs upstream coupling.** Wall-5 fixes land in
  `headscale-rs`, not in this repo (task #214). Release-coupling
  between two repos that both ship to production is a known fragility;
  cargo-vendor + version pinning is the operational workaround.

## How to update this doc

Refresh on every batch of commits that closes one or more P0/P1 items,
and on every reply from the Octra dev team to
`octra-dev-questions.md`. An item moves from "in inventory" to
"shipped" when (a) the commit is on `main`, (b) the exit criteria are
demonstrated in a CI signal or a smoke script that runs unattended,
and (c) the operator runbook references the new behaviour. An item
moves from P1 to P0 when its absence becomes load-bearing for an
operator we have an actual conversation with — not before.
