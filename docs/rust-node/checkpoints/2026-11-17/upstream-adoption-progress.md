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

## Not ported yet

In the order an observer needs them to follow devnet past epoch 1,845,000:

1. **Bootstrap.** Sync anchor eviction witness and size limits
   (`sync_anchor` +158), state-sync verification and checkpoint
   (`state_sync_verify`, `state_sync_checkpoint`), parent-commit check
   (`consensus_parent_commit`). Depends on the eviction record in
   `validator_set_update` (+197) and `validator_entry`.
2. **Execution** — everything that changes a state root:
   scalar-work metering (`scalar_work`, `contract_vm` +208, `contract`,
   `code_check`, `program_type_flow`, `bytecode`, `program_package`);
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
