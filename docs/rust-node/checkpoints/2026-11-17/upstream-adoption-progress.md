# Following lite_node 8f785a93 — progress

Target: `8f785a93a4e7392a0f3e65674f9de89854d33dbc`, the release devnet
requires (sequence 42, `consensus_recovery`). Previous candidate:
`c49de45c`. Branch: `adopt/upstream-release-20261117`.

**`candidate.json` still names `c49de45c`.** It moves only when the node
implements the release; until then the release canary correctly reports
drift. `source-map-candidate.json` already inventories the new commit, so
every candidate-bound test must be regenerated against it to pass.

## Method

Each stage ports one upstream area and is checked against output captured
from the unchanged upstream sources at the new commit
(`scripts/node-port/candidate-*-oracle.py`, built with the local OCaml 4.14
switch). Re-running an oracle and comparing with the previous capture shows
exactly which observable behaviour changed.

```
python3 scripts/node-port/candidate-<name>-oracle.py \
  --upstream <lite_node checkout> --out <scratch dir> \
  --fixture <fixture path> --ocaml-bin ~/.opam/4.14.2/bin
```

## Done and checked against upstream output

| Area | Upstream | Rust | Evidence at 8f785a93 |
| --- | --- | --- | --- |
| Quorum measure, seatless policy | `c_measure`, `c_quorum_policy` | `consensus/measure.rs`, `policy.rs` | 120 measure grids, 132 policy cases |
| Validator-set shape, seat cap, eviction plan, pending choice | `c_types` | `consensus/validators.rs` | 336 set cases; 1,272 historical vectors replayed, unchanged |
| Certificates | `c_qc` | `consensus/qc.rs` | covered by the set and engine traces |
| Relief overlap and restore | `c_relief` | `consensus/relief.rs` | historical vectors; one now past seatless activation |
| Rule graph: ScalarWork, SourceCreate, ProgramResult, Seatless | `rule_graph` | `rules.rs` | 536 graph cases, 450 activation inputs |
| Engine evidence requests, voting-set checks | `c_engine` | `consensus/engine.rs` | 512 signed traces / 9,670 transitions |
| Profile commitments | `consensus_profile` | `consensus/profile.rs` | 96 inputs, 1,656 epoch hashes |
| Epoch rule selection order | `set_rule` | `validator_epoch/mod.rs` | 978 preview inputs |
| Local vote persistence | `c_driver` (vote log) | unchanged | 184 traces / 2,718 steps, unchanged upstream |
| Compiler and publication, VM roots | `lib/vm` | unchanged | 101 + 22 + 56 cases, unchanged upstream for these inputs |
| Eviction witness on validator updates | `validator_set_update` | `control_payload.rs`, `validator/update.rs` | 80 constructions, 540 stored forms |
| Sync anchor steps with an eviction; checkpoint voting-set check | `sync_anchor`, `state_sync_checkpoint` | `state_sync/anchor.rs`, `checkpoint.rs` | historical state-sync vectors pass; the eviction step's parts are captured, its composition is not |
| VM integer width and numeric text work (`scalar_work`) | `scalar_work`, `contract_vm` | `octb/scalar_work.rs`; runtime `octb/{mod,meter,vector,data}.rs` | 13,528 historical VM cases unchanged without the rule; with it 11,020 change and Rust matches all; 7,280 new cases at the limits (`candidate-octb-scalar-oracle`) |

## What devnet runs

Of 18,900 transactions in the ~1,400 epochs before 1,866,522: 18,882
`validator_ready`, 9 program calls, 5 transfers, and one each of
`stealth`, `encrypt`, `key_switch` and `validator_bond`. Epoch execution
(execution marker, penalties, reward exclusions, pending-set promotion,
eviction scheduling, the weight check on `validator_ready`) therefore
decides every state root and comes first; the program-call pricing of
`scalar_work` next.

## Native build at the candidate

The VM and runtime oracles need the full upstream tree. The image
`octra-candidate-native:8f785a93` holds it built with upstream's own
storage wrapper (`controls/lib/gc_build.py`, which installs its patched
irmin), `mcl` and a Rust toolchain for the Circle WASM host:
`scripts/node-port/candidate-native-image.sh <lite_node clone>`.
`scripts/node-port/candidate_native.py` runs an oracle against it after
checking every source file against `source-map-candidate.json`.
Execution time slices (`exec_resource`) only shape the proposer's
preview; replaying a committed epoch still executes every transaction.

## Not ported yet

In the order an observer needs them to follow devnet past epoch 1,845,000:

1. **Bootstrap, remainder.** A restored state must carry the execution
   marker for its epoch (`state_sync_verify`), which execution writes —
   see 2. The validator source set at the durable head
   (`consensus_parent_commit.set_at_head`) belongs with the driver.
2. **Execution** — everything that changes a state root:
   scalar-work pricing outside the VM (`contract` call/deploy/view,
   `code_check`, `bytecode`, `program_package`, `call_plan`, circle code
   admission, `circle_exec`, `wasm_call`; the VM itself is done);
   recorded results for failed programs and circle calls
   (`program_result`); child programs from signed source
   (`program_spawn`); validator eviction, slashing and the per-epoch
   execution profile in `epoch_exec` (+657); reward attribution under
   seatless voting; `tx_payload`, `tx_envelope`, `tx_savepoint`,
   receipts with charged rejections; `private_ledger`,
   `private_transition`, `fhe_calc`; `circle_exec`, `wasm_call`, the
   Circle WASM host and worker. `SOURCE_STAMP` already names the new
   `lib/vm` sources; the compiler and VM are not yet shown equal to them
   beyond the 179 captured cases above.
3. **Network.** `p2p_conn` (+80), `p2p_swarm`, tx gossip, round requests
   (`c_round_request`, new), root queries, `sync_chain`, `sync_probe`.
4. **Driver.** `c_driver` (+518): eviction handling, pending-set choice at
   activation, source and promise thresholds through the measure.
5. **Transaction intake.** Byte-accounted staging queue, preview holds
   with backoff, payload-account check (`tx_staging` +204, `tx_view`,
   `node_rest_facade`). The oracle is adapted and its capture differs in
   107 of 178 traces; `staging_intake_parity` fails its pin check until
   this lands.
6. **RPC and status.** `status_read_rpc` (+278), `rpc_http` (+191),
   `rest_read_rpc`, `tx_view` rendering.
7. **Vendored PVAC.** Bulletproofs generator, inner-product, prover and
   verifier changes plus the new ready-points table; `vendor/octra-pvac`
   must match the candidate again.
8. Not applicable to this node: Irmin store GC, the proof worker
   processes and their C stubs (our store is SQLite and proofs run in
   process). To be confirmed when the execution stage is read.

## Then

Regenerate the remaining candidate captures (`circle-engine`,
`hfhe-key-binding`), run `./scripts/test-all.sh`, move `candidate.json`,
and only then redeploy the public observer under supervision.
