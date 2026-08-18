# Octra upstream delta — 2026-05-23 → 2026-08-17

> What the Octra core team shipped while our picture of the chain was frozen, what it
> changes for OctraVPN, and what to do about it.
>
> Produced by two multi-agent analyses (21 agents, ~2.7M tokens) reading the now-public
> OCaml node source, with adversarial verification passes on the high-impact claims.
> Every chain-behavior claim below cites `octra-labs/lite_node` source. Claims that
> source does not settle are marked `[unverified]` with the experiment that settles them.

---

## 0. The one-paragraph version

Octra published the **full validator node as public source** (`octra-labs/lite_node`,
BSD-3, OCaml + C++ + Rust, shipping near-daily with mandatory epoch-gated releases).
Reading it retires or reframes **all six** of our long-standing blockers — and four of
them turned out to be **our own bugs**, not chain limitations. The most consequential
finding is negative: the native relay rail moves no money and has no hashlock, so our
v4 AML HTLC is the **permanent** settlement design rather than a stopgap. The second
most consequential is uncomfortable: our test mock has **0% response-shape parity** with
the real chain on every method it implements, has **never executed a byte of our AML**,
and one of our Lean theorems proves a property the chain does not have.

**Do now:** push the 19 unpushed commits. Then run the reality probe (§6a).

---

## 1. What shipped

| Repo | Last push | What it is now |
|---|---|---|
| `octra-labs/lite_node` | 2026-08-16 (73 commits since 05-23) | Full validator node: `node_runtime/` (302 files), `circle_runtime/`, `contracts/`, `pvac/`, `pvac_ffi/`, `zk_ffi/`, `mcl/`, `net/`, `controls/`, `formal/`, `bin/` |
| `octra-labs/webcli` | 2026-08-07 | Reference client. New circle policy rules, PVAC component work, "reject noncanonical ristretto encodings" |
| `octra-labs/pvac_hfhe_cpp` | 2026-07-09 | HFHE/PVAC C++ reference: native recrypt, public matrix sampling, keygen root-exponent fix, encoding hardening |
| `octra-labs/hfhe-challenge` | 2026-07-11 | Public **1M-oct bounty to break HFHE** (v2; v1 cancelled over a real R_com oracle) |
| `octra-labs/circle_examples` | 2026-05-23 | Unchanged |

Public git history for `lite_node` starts **2026-06-25**. May-era devnet behavior is
permanently uninspectable from source, so "the node does X today" never dates our older
observations.

**The release treadmill.** Mandatory releases landed 2026-08-09, -10, -12, each with an
activation epoch (circle execution 1,299,000; wasm-compute/private bundle 1,330,000;
participation set-fold 1,334,000). Nodes that don't update get rejected by the network. A
signed release JSON at `https://releases.octra.network/v1/devnet/latest.json` (ed25519 key
in `controls/lib/release.py:20-49`) marks the required `source_commit` and
`consensus_rules_id`, ~72h expiry.

**Method change:** every chain question we used to escalate is now answerable by reading
their source. Default to reading `lite_node` before writing a question.

---

## 2. Blocker ledger

| # | Blocker | Status | Evidence |
|---|---|---|---|
| 1 | Executable circles ("bytecode not found") | **WAS OUR BUG** | `contract_call` only consults `["contracts";addr;"bytecode"]` (`store_irmin.ml:883`); circle code lives at `["circles";id;"program"]` (`store_irmin.ml:1418-1423`). Right code, wrong lookup table. |
| 2 | `circle_call` tx construction / signing | **RETIRED** | Full preimage at `transaction.ml:309-326`, read off the *verifier* (`tx_view.ml:1135-1148`), not inferred from a struct. Reference impl `webcli/lib/tx_builder.hpp:78-106`. |
| 3 | Native relay settlement ops | **RETIRED as blocker — premise dead** | No hashlock (`circle_transport_verify.ml:42-47`); no money, `fee_budget` inert (`epoch_exec.ml:931-934`). "amount must be positive" was our envelope silently falling back to Standard op_type. |
| 4 | 4 KiB string truncation | **WAS OUR BUG (read-side)** | VM cap is 4 MiB and **reverts**, never truncates (`contract_vm.ml:265, 1057-1113`). 4096 is a display slice on `contract_call` responses (`rpc_view.ml:385-406`, with an explicit `truncated:true` flag). `octra_contractStorage [addr, key, "full"]` returns everything. |
| 5 | `fhe_load_pk` reverts | **RETIRED in old form; 3 new constraints** | Wired for AML (`contract_vm.ml:2573-2581`, `consensus_epoch_vm_shell.ml:425-478`) with two revert sites. New: `fhe_verify_*` is view-only (`contract_vm.ml:2667-2671`); PVAC registration is dead for our sidecar keys (`registration_rpc.ml:63-71`, `pvac_registry.ml:85-90`); HFHE is under an active break bounty. |
| 6 | RPC quirks | **STILL REAL, source-confirmed** | nonce+1 (`ledger.ml:241`), float timestamps (`transaction.ml:292-296`), ±300s drift → 105 (`tx_view.ml:1121-1129`), base64 ed25519 (`transaction.ml:334-340`), genuinely no events (`tx_view.ml:93-136`). But `contract_receipt` now carries `{success, events, effort, error}` and `octra_transaction` returns rejected/dropped **with reasons**. |
| 7 | *(new)* ValidatorOracle | **SILENTLY BROKEN** | `octra_isValidator` / `octra_listValidators` exist nowhere in the node. Our fallback caches an empty set and returns `Ok(false)` for everyone — [`validator_oracle.rs:149-176`](../crates/octravpn-core/src/validator_oracle.rs:149). Replace with `octra_validatorSetProof` (`status_read_rpc.ml:102-119`). |
| 8 | *(new)* Sealed-asset write observability | **UNKNOWN** | Receipts exist for deploy/circle_save/program_save (`consensus_epoch_vm_shell.ml:945-996`); whether `CircleAssetPut` gets one was not established. One probe. |

### 2.1 The canonical signing preimage

Compact Yojson, **this exact order**:

```
from (string), to_ (string), amount (string), nonce (int),
ou (string), timestamp (float), op_type (string)
```

then `encrypted_data`, then `message` — each appended **only when present**. ed25519 over
the JSON *text*; signature encoded **base64**. **No `chain_id`.**

Landmines:
- Wire key is **`to_`**, with the trailing underscore.
- `timestamp` must byte-match yojson float rendering (trailing `.0` on integral values). One
  formatting difference = code 101. Property-test the Rust formatter against a live round-trip.
- `amount` and `ou` are strings; `nonce` is an int.
- The tx *hash* is a different, 11-field JSON — don't reuse the signing preimage.
- An unrecognized `op_type` is a hard error; a **missing** one silently falls back to
  Standard, which produced our bogus "amount must be positive" on relay ops.

---

## 3. The native relay rail is attestation, not payment

We assumed `circle_outbox_open` / `relay_claim` / `ingress_commit` were a native paid-relay
rail we couldn't sign onto, and built the v4 AML HTLC as an interim substitute. Source
inverts that:

- **No hashlock.** The only cryptographic check on a relay claim is an ed25519 signature over
  `"octra_circle_relay_claim|circle|intent|relay|epoch|expiry"` (`circle_transport_verify.ml:42-47`).
  No `sha256(preimage) == committed_hash` exists on that path.
- **No money.** `fee_budget` is inert; only `ou` is debited (`epoch_exec.ml:931-934`).
- **`fhe_verify_*` is view-only** (`contract_vm.ml:2667-2671`), one use per view, 5M effort —
  HFHE can never gate a settle/claim *mutation*.

What it actually is: delivery **attestation** — Open→Claimed→Fulfilled with lazy keeper-less
expiry (`circle_transport_state.ml:83-156`), owner-only allowlist/quorum/topology policy
(`epoch_exec.ml:1647-1691`). Active quorum-ready claims unlock scoped HFHE rights per
`intent_id` (`circle_cell_transition.ml:168-192`) — a real composition hook for hidden-exit v2.

**Consequences:**
- **Do not pause the v4 default-on push.** The AML HTLC *is* the rail, permanently. Reframe
  the v4 spec; mechanics unchanged.
- Adopt the native outbox **additively**, keyed by the same `intent_id`.
- **`swap-ready-hfhe` (1,693 lines, parked) cannot ship as designed** — its chain-side verify
  gate on `settle_confirm`/`claim_earnings` is structurally impossible. Salvage the storage
  schema; move verification into auditor views.
- **"Bonds/slash into circles" (v3 §6) is dead, not deferred** — circle execution disables
  transfers and cross-contract calls (`circle_exec.ml:625-631`). Custody stays in AML.

---

## 4. The local-chain story: our anvil can become real

### 4.1 The real node runs anvil-shaped out of the box

- Unset `OCTRA_CONSENSUS_MODE` → `Single` role (`c_role.ml:12-22`, `consensus_enabled Single = false`).
- Tick loop applies an epoch every 10s from staged txs — **no peers, quorum, or stake**
  (`consensus_tick_plan.ml:115-123`).
- Genesis auto-mints 100M OCT across `OCTRA_VALIDATORS` addr:pubkey pairs on an empty ledger
  (`startup_account_shell.ml:40-87`, `validators.ml:63-66`). **Pre-funded dev accounts are an
  env var** — anvil's mnemonic accounts, already built in.
- Address format specified: `"oct" + base58(sha256(pub)).rjust(44,'1')` (`validator_common.py:184-189`).
- All pm2/systemd/sudo lives only in `controls/`; the binary is 12-factor
  (`startup_process_shell.ml:105`). Two hard requirements: `octra_pvac_worker.exe` as a sibling
  (`octra_node.ml:87-95`), and a writable data dir.

**Cost:** no release binaries exist (all 4 GitHub releases have `assets:[]`), so a 35–55 min
cold source build — paid once per pin bump in a registry image, never in CI jobs.

**The irreducible limit:** epoch interval is hardcoded `interval_ms = 10_000L`
(`epoch_time.ml:10-11`). No test RPCs, no faucet, no instant mining, no `octra_test_*`
namespace anywhere in `rpc_dispatch.ml`. **The real node is the integration/e2e tier, not the
sub-second tier.**

### 4.2 Forking devnet is probably real — mechanism confirmed, composition unverified

State sync is a **full content-addressed state dump**: manifest requires `HEAD.json`,
`state_root`, `ledger.dat` (full account + contract KV including circle sealed assets,
`ledger_image.ml:23-40`), chaindata, and PVAC blobs (`state_sync_manifest.ml:500-518`).
`octra_state_sync_client.exe` downloads, verifies against checkpoint quorum + exporter
signatures, and produces a **bootable data dir** (`state_sync_client.ml:609-632, 837-899`).
Fetch is anonymous HTTP; devnet publishes sources at
`devnet.octrascan.io/state-sync/{primary,secondary}` (`config/network.env:29-30`).

Critically: **boot checks only `chain_id` + `config_hash`, with no liveness tether to devnet**
(`octra_node.ml:243-271`). So import + Single-mode boot = a fork that mints local epochs on
real devnet state.

Constraints: forks land at exporter-published **epoch boundaries within a ~24h retention
window** (`sync_lease.ml:12`), not arbitrary heights. "Leases" are GC markers, not permission
gates (`sync_lease.ml:4-68`).

`[unverified]` — nobody has run import → Single-boot → diverge end-to-end. **The experiment:**
run `octra_state_sync_client.exe` against devnet with `network.env` anchors, boot Single with
devnet's `OCTRA_CHAIN_ID`/`OCTRA_CONSENSUS_CONFIG_HASH`, submit one tx, watch epochs advance.
Half a day.

The disclaimer at [`octra-foundry/crates/octra-cli/src/anvil.rs:1-9`](../../octra-foundry/crates/octra-cli/src/anvil.rs) —
"a real fork mode … would need the upstream node to expose a state-dump method, which it
doesn't today" — **is now false**.

---

## 5. How wrong our test harness is

This is the uncomfortable section.

**Coverage:** the mock implements **13 of ~108 real handlers (~12%)** (`rpc_dispatch.ml:115-202`,
`node_rpc_server.ml:431-480`).

**Shape drift on all 13**, three of them structural lies:

1. **`octra_submit` instant-confirms** with `{hash, status:"confirmed"}`. The real chain returns
   `{tx_hash, status:"accepted", nonce, ou_cost}` and only **stages** — confirmation happens at
   epoch apply (`rpc_view.ml:706-712`).
2. **`octra_transaction` returns an `events` array the chain provably never emits**
   (`tx_view.ml:93-136`). Execution results live in `contract_receipt` (`contract_rpc.ml:765-780`),
   which the mock doesn't implement.
3. **`contract_call` returns a bare value** instead of `{"result":...}`, **ignores the contract
   address entirely**, and pattern-matches hardcoded OctraVPN method names.

Plus: `octra_balance` wrong keys and **invents a 1e9 balance for unknown accounts**;
`compileAml` returns a sha256 masquerading as bytecode; `registerPvacPubkey` **inverts key
custody** (the server mints the key — real chains never do).

**Pure fiction** (zero grep hits upstream): the 7 `octra_fhe*` RPCs, `octra_isValidator`, the 4
`octra_test_*` backdoors, and **the chain_id envelope gate** — the real tx envelope has no
`chain_id` field at all (`transaction.ml:273-325`).

**The mock executes zero AML.** It is ~3,000 LOC of hand-written Rust reimplementations of our
program's per-method semantics. Deploying a different program changes nothing. Therefore:
`aml_coverage.rs` measures branches of *the mock*, not the AML. The fuzzer fuzzes our
reimplementation. `tool_parity.rs` proves three doors into the same fiction agree.

### 5.1 Two findings that need action beyond testing

- **The Lean axiom `chain_id_binding_rejects_replay` is unsound.** We formally proved a property
  of a replay-protection mechanism the chain does not have. Real replay resistance is nonce+1
  plus the signed timestamp. This needs flagging in the proof set and in any README claim that
  counts it.
- **`expect_emit` / `expect_emit_fields` / `expect_no_emit` / `record_logs` die in all tiers** —
  the chain has no events. Any v4 arm/claim/refund assertion resting on events rather than state
  reads has been verifying fiction. ~1,624 test LOC of call sites.

### 5.2 Suites most likely hiding a real bug

1. Every octraforge test asserting via `expect_emit` / `SubmitResult.events`.
2. Any submit-then-read sequence whose hand-rolled mock confirms instantly — the exact failure
   mode of the devnet premature-balance-read incident, still latent wherever the client lacks
   staged-tx await logic.
3. The P1-5b cross-chain-replay tests — passing against a property the chain doesn't enforce.
4. Anything calling `octra_isValidator` or `octra_fhe*` — hard `method_not_found` on a real node.
5. `claim_earnings_v2`'s plaintext `balance != claimed` fallback — a proof-verification bypass
   that exists only in the mock.
6. Every client that has never seen `-32012` (committed-state-changed retry) or `-32005`
   (single-flight busy).

---

## 6. Plan

### 6a. Do now (this week)

1. **Push.** 19 commits — the back half of the v4 money loop — exist only on this machine.
   `git push origin codex/octra-headscale-router-adaptation-20260602`
2. **Reality probe** (one script, `docker/devnet/experiments/upstream-reality-probe.sh`):
   current epoch vs the three gates; `op_type: "call"` vs `"program_exec"` acceptance; write
   >4096 bytes and read back via `octra_contractStorage [.., "full"]`; `contract_receipt` for a
   known tx; confirm `octra_isValidator` is missing; `octra_pvacStatus` for our May wallet.
3. **chain_id guard** — assert-empty in the [`chain_tx_queue.rs`](../crates/octravpn-core/src/chain_tx_queue.rs:195) sign path; audit configs. Five minutes.
4. **Fix `_oplib.sh`** per the now-known preimage and re-run the parked P2.1/P2.2 probes — they
   were tooling bad-sig, one fix re-arms both.
5. **`fhe_load_pk` re-probe as a live tx** — read the receipt's Require event; view calls return a
   bare "execution reverted" and tell you nothing. Update `docs/audit/fhe-load-pk-status.json`.
6. **Release canary** — poll the signed release JSON; alert on `consensus_rules_id` change.
7. **Flag the unsound Lean axiom.**

### 6b. Next, in dependency order

1. **Rust canonical `TxSigner`** ported from `transaction.ml:309-326`, with yojson-float property
   tests. *Everything else depends on this.* (~300–500 LOC)
2. **Receipt-based confirm loop** — `octra_transaction` terminal statuses + `contract_receipt`;
   delete the string-matched error heuristics; add `-32012` retry, `octra_nonce`, `staging_remove`
   recovery. (net-negative ~400 LOC)
3. **ValidatorOracle rewrite** on `octra_validatorSetProof`. (~150 LOC)
4. **Re-capture `devnet_rpc_contract.rs` fixtures** against current devnet. Re-capture, never
   hand-edit.
5. **Local real-node harness** — `octra-foundry/docker/octra-node/Dockerfile`, two-stage, Single
   mode, dev keys via `OCTRA_VALIDATORS`. Then the **fork spike** (§4.2).
6. Finish Step 9 (Tamarin `relay_receipt_ack.spthy`, Kani epoch-gate) and **flip `[v3.relay]`
   default-on**. Upstream changes nothing the proofs model — the HTLC is the rail.
7. **Native outbox adoption (additive)** — mirror WireState relays into
   `circle_transport_policy_put` allowlists; chain-attested delivery composed with the HTLC via
   shared `intent_id`. (~1–2 weeks)

### 6c. Test-harness plan

Three architectures were proposed and judged. Ranking: **Pyramid > Iron Anvil > Conformance**.

The spine is **tiered, behind one `ChainBackend` trait**, because two facts are both true: the
node can never be sub-second (hardcoded `10_000L`), and the mock can never be trusted alone (no
interpreter). Tier membership becomes one-line configuration, with the policy: **nothing
money-shaped may have the mock tier as its only coverage.**

Grafted in: a devkeys crate and `:stock`/`:turbo` dual-image discipline (from Iron Anvil); RPC
registry codegen scraped from `rpc_dispatch.ml`, a recording-proxy corpus, and nightly
fuzz-differential (from Conformance — its verification machinery was the best-designed component
anyone proposed).

Mock fate: **stays, repaired, under a parity contract** — the method registry and error codes get
regenerated from node source; `events`, the `octra_fhe*` wrappers, `octra_isValidator`, the
chain_id gate, and `host_fhe.rs` (732 LOC) get deleted.

`octra-circle-sim` fate: **keep separate**, in this repo — it simulates the operator side (ACL,
byte meter, proxy surface), which is OctraVPN domain, not generic tooling.

Rough total: ~5–6 engineer-weeks; steady state ~2–4 hrs/week of drift triage paid on our schedule
via pin-bump PRs.

### 6d. Stop doing

1. Counting mock-green as evidence for anything money-shaped.
2. Reporting "AML branch coverage" — retract it from any dashboard until re-targeted.
3. Citing `tool_parity.rs` as a parity guarantee.
4. Maintaining three mutually incompatible fake-HFHE layers.
5. Using shared public devnet as the default real-chain check.

---

## 7. What might silently break us

Ranked by likelihood × blast radius.

1. **`op_type: "call"` vs `"program_exec"`** — webcli renamed it 2026-06-08. Our foundry
   `sign_call` emits `"call"`; an unrecognized op_type is a hard error. Blast radius: every
   v3/v4 submission. `[unverified]` — probe first.
2. **Non-empty `chain_id` in the preimage** → guaranteed 101.
3. **Epoch-gated mandatory rule changes.** Fixtures froze 2026-07-04, before all three gates and
   three mandatory releases.
4. **ValidatorOracle deny-all** — already broken.
5. **PVAC registration dead for new sidecar keys** — any HFHE re-attempt fails at key_switch.
6. **Yojson float timestamp formatting** in the Rust signer.
7. **Latent decode breaks** — `octra_stealthOutputs` now returns a pagination object vs our
   `Vec<Value>`; `octra_viewPubkey` returns `{view_pubkey: null, reason}`; `-32012` isn't in
   `is_retryable()`.
8. **circle read-auth `frame_v2`** (2026-07-24) — May-era pipe-concat auth fails all
   `octra_circle*Auth` reads.
9. **Private-payload strictness at epoch 1,330,000** — re-validate the AML wire format before the
   client data plane relies on it.

---

## 8. Questions genuinely left for the core team

`docs/octra-team-post.md` should be rewritten before posting. **Drop Q1–Q4** — executable
circles, the signing preimage, relay op construction + the preimage check, and storage caps are
all now self-answered from source. Q5 is diagnosable rather than askable.

What remains:

1. **Devnet binary provenance** — is running devnet exactly `source_commit 75d9ed1d…`? Everything
   above presumes it.
2. **Legacy `op_type: "call"`** — still accepted, or must all clients emit `"program_exec"`?
3. **Historical PVAC keys** — intended path for a Historical-profile key with no encrypted
   balance: `key_switch` now, or wait for the 1,330,000 migration machinery? Is `key_switch`
   itself epoch-gated?
4. **Sealed-asset / `CircleAssetPut` observability** — any receipt or event, or is polling the
   only auditor signal?
5. **Mainnet RPC body cap** — does it match devnet's 5,065,536 bytes (`rpc_http.ml:10`)?
6. **Effort/gas activation** — is ou-metering beyond floors planned for devnet? It would
   invalidate zero-cost keeper economics.
7. **Native relay payment** — is a value-bearing settlement layer planned for the outbox rail, or
   is attestation-only the long-term design? Determines whether our HTLC eventually composes with
   or migrates to something native.

---

## 9. In-flight work

| Item | Recommendation |
|---|---|
| Active branch (52 ahead of main, **19 unpushed**) | **Push today**, PR into main after fixture re-capture |
| Step-9 fork (Kani epoch-gate / Tamarin ACK-precedes-arm) | **Resume both.** Tamarin first — it models the ACK the composition invariant depends on |
| `swap-ready-hfhe` (1,693 lines) | **Do not ship as designed** — chain-side verify gate is structurally impossible. Keep for the storage schema; file a redesign issue |
| `feat/wallet-enroll-circles` (1,398 lines) | **Rebase + review now** — gains a lot from executable circles + native key policy |
| ~24 patch-equivalent branches + 12 locked agent worktrees | Prune |
| `perf-4-pvac-batched-rpc` | Hold until the sidecar re-vendor decision — its IPC target may disappear |
| Stranded 75-line router test (stock-control-router-hook worktree) | Cherry-pick, delete worktree |
| `docs/octra-team-post.md` (untracked) | Rewrite per §8 |
| `out/` (untracked) | Add to `.gitignore` |

---

*Sources: `octra-labs/lite_node` @ `dd342e7` (2026-08-17), `octra-labs/webcli` @ `b4ae091`,
`octra-labs/pvac_hfhe_cpp` @ `071b0e9`, `octra-labs/hfhe-challenge` @ `019380c`.*
