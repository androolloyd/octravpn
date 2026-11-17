# System analysis — 2026-11-17

Scope: the whole workspace at `fab663b` (main), CI history, the public
deployment, and upstream lite_node. Every number below was measured today; where
something is only *recorded* in our own docs rather than observed, it says so.

**Verdict.** The design got better since September — prepaid purchase-before-forward
removed the hardest problems the old settlement rails had. The implementation is
now limited by three things that are not design: the shared gate is red, the
public deployment is down, and upstream moves faster than we adopt it. After
those, the largest improvement available is subtraction: one payment model is the
product, and five retired ones still shape the build, the docs and the proofs.

## What the system is now

| | |
| --- | --- |
| Rust in `crates/` | 450k lines, 1,509 files (1,471 of them under 1k lines) |
| Rust Octra node (`octra-node`, `-runtime`, `-protocol`) | 302k lines — AML compiler/VM alone is 51k |
| VPN crates (`octravpn-*`) | 126k lines; `octravpn-node` 53k, `octravpn-client` 32k |
| Tests | 2,927 test functions; `cargo test (release)` takes 88 min in CI |
| Dependencies | 682 crates in `Cargo.lock` |
| Docs | 206 Markdown files, 56.6k lines; 228 qualification checkpoint files |
| Proofs | Lean 432 theorems / 118 axioms, TLA+ 3 specs, Tamarin, 5 Kani harnesses |
| Upstream pin | lite_node `c49de45` (upstream date Oct 24, adopted Nov 12) |

## Findings, most important first

### 1. `main` has been red for a month

The last 15 CI runs on `main` (Oct 17 → Nov 12): 14 failed, 1 cancelled, none
passed. The Nov 12 run fails five jobs, none of them deep:

| Job | Cause |
| --- | --- |
| `cargo fmt` | 3 files under `octra-node/src/vpn/payments/shielded/` |
| `cargo clippy` | one lint, `octra-node-protocol/tests/network_swarm/scope.rs:117` |
| `cargo audit + deny` | 6 advisories (zstd / zstd-safe / zstd-sys, pulldown-cmark) + 11 denied warnings (rustix unsound) |
| `docker-compose e2e` | image build fails at `Dockerfile.builder:48` (`cargo build`) |
| `cargo tarpaulin` | link failure building `octra-node-runtime` tests |

Scheduled jobs over the last 31 runs: `demo` failed 30, `octra release canary`
failed 22, `v4-relay-devnet-e2e` failed 5 of 5. Fuzz and the `fhe_load_pk` probe
are healthy.

The Nov 12 checkpoint says strict Clippy and formatting pass — locally, on
changed files. A gate that is always red cannot tell a new regression from an old
one, and pushes go to `main` regardless.

### 2. The public deployment is down, and its record stops on Oct 21

- `https://octra.to` returns **HTTP 502** today. It is the README's front door.
- Devnet is live at epoch 1,861,844. Our last *recorded* observer admission is
  epoch 1,727,415 on Oct 21.
- `rust-node/status.md` records that day: the observer was OOM-killed (exit 137)
  while test matrices ran on the same host; then the relay activation command
  timed out and SSH and HTTPS became unreachable. Nothing later is recorded.
- No funded public canary has ever run (recorded: "No public canary transaction
  has been signed or funded").

Local qualification is thorough. Public service — the thing alpha testers touch —
has one relay, one observer, manual restarts, and no external probe.

### 3. Upstream changed consensus the day after we adopted it, and nothing told us

- `c49de45` is dated Oct 24; we adopted it Nov 12 (19 days).
- Upstream has 4 newer commits (Nov 13–14). The first is *"weighted quorum,
  execution time slices and store gc"* — a quorum rule, which an observer must
  implement to verify finality, not only a validator.
- The release canary compares the release marker with a baseline last set in
  September (sequence 12, `e984d401`). It has therefore been red 22 of 31 days
  and its status file's `last_check` is 2026-09-13. A detector that is always
  firing detects nothing.
- The status RPC reports a hard-coded `consensus_rules_id`.

The parity *method* is good — independent oracles in `scripts/node-port/`, 1,192
upstream files inventoried, captured fixtures. What is missing is the pipeline
around it: adoption is a manual, weeks-long event against a weekly upstream.

### 4. Several settlement generations share one tree, and two of them are live

Two rails are in use by the native node: prepaid Octranet channels
(`octranet-payments.aml`) and receipt settlement on `main-v5.aml` — v4's
settlement with proof-authorized administration — which
`octra-node/src/vpn/settlement.rs` submits and the runtime's
`vpn_settlement_security` and `groth16_parity` tests exercise. The older
generations are all still wired in rather than dead:

- **Programs:** `main.aml` (v1.1), `operator-circle.aml` (v2), `main-v4.aml` +
  `v4-relay-htlc.aml` (superseded by v5), and `operator-circle-v3.aml`, which no
  code, test or script references (only docs and checkpoint records do).
- **Standalone operator:** the Hub selects `protocol_version = v1.1 | v2 | v3`
  and drives `chain.rs`, `chain_v2.rs` and `chain_v3.rs` (2,479 lines — the
  largest file in the repo), plus the relay claimer/sweeper, PVAC and onion.
  CI's docker e2e and most demo tapes run this binary.
- **Client:** `discover.rs`, `discover_v2.rs`, `v2_cache`, `v2_runner`,
  `v3_runner`, `chain_v3`, `settler`, `settle_state` beside the prepaid modules.
- **Around them:** 55 `allow(dead_code)` in `octravpn-node` and 34 in the client;
  a weekly v4 devnet job that cannot pass (its secret is not configured); v2/v3
  adversarial drills in `test-all.sh`; Lean libraries for V1–V4 and a TLA+ spec
  for relay settlement.

Each generation was right when written. v1.1 and v2 are the clear candidates
for removal, but they are reachable through the Hub's version switch, so
removing them is a decision about what the standalone operator still supports,
not a dead-code cleanup.

*Corrected after first writing:* an earlier draft said `chain_v2.rs` had no
callers and that the launch used none of these generations. Both were wrong —
the first was a search that missed nested imports, the second overlooked v5 in
the native node.

### 5. Dependencies point the wrong way

- `octra-node` depends on **`octravpn-node`** — the whole 53k-line legacy
  operator, with `headscale-cli`/`-db` — to reach seven modules (`embedded`,
  `admission`, `payments`, `payment_meter`, `mesh_control`, `mesh_store`,
  `stock`; 77 references).
- The other two cross-edges are already confined to tests: `octravpn-client` →
  `octravpn-node` and `octra-node-runtime` → `octravpn-core` are both
  dev-dependencies. (An earlier draft of this document listed them as normal
  dependencies; that was wrong.)
- Module-level reachability inside `octravpn-node` shows how entangled the one
  real edge is: from the seven modules `octra-node` imports, 26 of the crate's
  33 top-level modules (38k of 48k lines) are reachable, because `control`
  reaches `hub`, `chain_v3`, `pvac` and `audit`, and `mesh_control` reaches
  `members_policy`, which reaches `hub` and `v3_cli`. That count is a lower
  bound (it does not see nested imports). Extracting a service crate is
  therefore an interface redesign, not a file move.
- `octra-foundry` is a sibling **path** dependency pinned only by a commit hash
  in README prose, while `headscale-rs` is a git dependency with a `rev`. A clean
  clone does not build without it. (The Docker e2e failure turned out to be a
  different missing input: the builder image never copied `experimental/`.)
- Two config dialects (JSON for `octra-node`, TOML for the other two binaries).

### 6. Qualification is narrated, and the reference docs describe the old system

- `rust-node/status.md` is 1,250 lines of reverse-chronological prose. The
  machine-readable checkpoint JSON it summarises already exists.
- `docs/security.md` was last changed May 21 and never mentions prepaid; it
  specifies registration, liveness slashing and settlement for the retired rails.
- `production-readiness.md` was last touched Oct 14; `vpn-design-improvements.md`
  (September) is superseded by the prepaid model.

### 7. Repository weight

- `.git` is 1.2 GB. 125 `ci(demo): refresh recordings` commits put 137 MB of
  recordings in history — from a job that has now failed for 30 days.
- Eight fixture files are 11–31 MB each; the two fixture trees total ~438 MB.
- 42 worktrees and 73 local branches.

### 8. Proof effort is spread across retired models

Lean axioms are concentrated in `WireProtocol/Shielding` (31), `HFHE` (17) and
the `OctraVPN_Rust` spec (23) — experimental or legacy areas. The current model's
file, `OctranetPayments.lean`, has 48 theorems and **zero axioms**. The best proof
artefact we have is for the thing we ship; most of the rest is for things we don't.

### 9. What is in good shape — leave it alone

- **The prepaid design.** Forwarding waits for a canonically settled purchase, so
  there is no operator credit risk and no mesh/money join to get wrong; rates,
  unstake and the double-receipt slash are specified precisely.
- **New-node code discipline.** `unsafe_code = "deny"`; 46 `unsafe` mentions,
  mostly PVAC/registry FFI; in files without test modules, 38 panic/index sites in
  `protocol/network`, 33 in `consensus`, 4 in `rpc`; 7 TODO/FIXME in the workspace.
- **Shielded payments** (18.8k of the 25.3k lines in `vpn/payments/`) are behind
  `private-payments-experimental`, off by default.
- **The registration gate** from September is in use: the native node's mesh
  refuses registration while the host is not serving authenticated state, and
  refuses the operator's own virtual key. The chain-anchored *member set*,
  though, is consulted only by the standalone operator — the native node passes
  no members policy, because there registration is an identity and a canonical
  purchase is what admits traffic. (An earlier draft said membership admission
  was "still wired in" without that distinction.)

## Proposed order of work

1. **Make `main` green and keep it green.** Fix the five jobs (four are an hour
   each; the zstd/pulldown/rustix bumps need a test pass). Then require checks
   before merge. Delete or repair the three dead schedules. Split the 88-minute
   test job by crate so it stays usable as a merge gate.
2. **Bring the public observer back and make it boring.** External uptime probe
   on `octra.to` and the RPC; a memory ceiling the node respects rather than one
   the kernel enforces; supervised restart; never share its host with test
   matrices. Define the alpha bar as something measurable — e.g. 7 days at head.
3. **Turn upstream adoption into a pipeline.** The canary opens an issue (or a PR
   with regenerated oracle fixtures) when the marker moves, and re-baselines when
   that merges. Add a "rule ahead" check: the upstream chain config's scheduled
   rule IDs versus the set this build implements, with the activation epoch. The
   node should stop paid admission, not guess, when a rule it lacks activates.
4. **Subtract.** Stop `octra-node` linking the standalone operator (Hub, CLI,
   v1.1/v2 chain layers, relay keepers) — first behind a feature, later as a
   separate crate. Decide whether the standalone operator still supports v1.1
   and v2; if not, remove them with their programs, drills and proofs at a tag.
   v5 stays: the native node settles on it. Make `octra-foundry` a pinned git
   dependency.
5. **Generate the status page; rewrite `security.md` for prepaid.** One table —
   gate × candidate × result × date — built from the checkpoint JSON, with the
   narrative left in the checkpoints.
6. **Stop growing the repository.** Publish recordings as release assets or CI
   artifacts; compress or externalise the large fixtures; prune worktrees.

## Decisions that are yours

1. **The node's role for alpha.** Observer-only (it verifies finality and executes
   but does not vote) or validator-capable. The README already says operating an
   exit does not require voting, and the public node has only ever run non-voting.
   Declaring observer-only for alpha lets parity work target verification paths
   first. Recommended.
2. **Which generations the standalone operator still supports.** v5 is live in
   the native node and stays. v1.1 and v2 are reachable only through the Hub's
   `protocol_version` switch, and CI's docker e2e registers endpoints through
   the v1.1 path. Dropping them means deciding the standalone operator is
   v3/v5-only (or retiring it in favour of `octra-node`) and rewriting that e2e.
3. **Whether to pause feature work** until steps 1–2 hold. The last month added
   capability on top of a red gate and a down deployment; I would pause.
