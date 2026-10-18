# Native interfaces and operator tooling

This is the 2026-10-18 successor implementation map, pending its final combined
qualification round. The adopted reference remains lite_node
`7f9be4489870645cfcc95439638cde40f5da9f50`. Existing checkpoints keep their
original source, binary, profile and execution scope; their counts are not
extended by this source review. Full Rust node parity remains incomplete.

The [compact interface map](interface-scope.json) links seven caller families to
Rust and adopted native sources. The [1,158-file native inventory](source-map.json)
remains unchanged and is an inventory, not a completeness or behavior proof.

| Interface | Successor boundary |
| --- | --- |
| RPC/gRPC and HTTP reads | Known reads wait for owned publication to finish and retry a changed generation twice. Writes, unknown methods and compute are not replayed. |
| BFT transaction intake | Shape, signature, profile, resource, nonce and lease checks precede durable staging. Bounded speculative proof warmup starts afterward and cannot authorize execution. Ordered proposal proofs/receipts remain authoritative; Single keeps its own policy. |
| Validator transactions | `validator-tx` prepares/signs/submits native-format transactions and wallet intents alongside the existing local `validator-control` API. Offline preparation is not admission, selection, a receipt or finalized state. |
| Snapshot administration | Seal/build, detached signatures, assembly and verification reuse existing body/hash/finality/content primitives. Canonical signing requires a trusted supplied finalized Anchor matching the exact retained wire and active validator authority. |
| Store maintenance | `check-store`, `fhe-audit` and `vote-floor` have explicit canonical/native forms and stopped-store ownership. Read-only diagnostics do not manufacture external QC authority. |

Warmup has bounded private/KeySwitch lanes, captured concurrency, queued-work
retention and owned shutdown. Required work can promote queued jobs or join
running proof jobs. Completed opaque local artifacts survive unrelated heads,
but each reuse rechecks the current transaction, ciphertext, public key, Claim
output and policy before creating a fresh receipt. Ordered application still
checks current nonce, debit, claim state and limits. History-based KeySwitch
migration retains its separate authenticated entitlement path.
The source-backed intake cost repair keeps authentication before the full account
fold and retains complete ledger semantics inside the bounded owned worker.
Neither optimization changes consensus admission or transaction transitions.

Native physical Irmin/chaindata forms deliberately reuse the unchanged pinned
native executable through an explicit artifact/source/build binding. The adapter
freezes the executable, clears its child environment, bounds output/time and
retains ownership through cancellation and reaping. This is disclosed native
backend reuse, not a new all-Rust physical store implementation. Rust canonical
diagnostics use a typed read-only/query-only interface without DDL or index
backfill. Follow the selected command's help for its artifact binding and inputs.

The original standalone snapshot tool's encoded-role quorum body and finalized
raw-consensus validator-set body remain distinct. Legacy quorum verification is
an offline interchange; it does not replace finalized reference authority in
bootstrap. Wallet signing emits public transaction/signature data, never private
wallet material. Native-compatible preparation can sign negative amount/OU
fields, but transaction parsing/admission still refuses those values. Nonce,
finite timestamp and signed-intent checks are not relaxed.

## Configuration and qualification limits

Public startup captures one profile before constructing its CLI-owned proof
runtime. Proposal grace, epoch-tag retention and worker resource limits use that
capture, including configured absence, instead of rereading process settings.
Recovery preserves the captured grace. Existing embedded runtimes and standalone
constructors retain their explicit capabilities and convenience behavior.

Profile/settings/hash comparisons exercise the public configuration API. A mixed
fixture exercises its explicitly selected genesis, rules and actual workload.
Those are separate checks. In particular, an explicit trusted legacy private
genesis is a disclosed fixture authority, not derived entitlement for a public
chain or proof that a similarly named profile passes stock full-release startup.
No consensus rule, activation or chain authority is inferred from a fixture name.

Active KeySwitch/private-proof transitions and Circle HFHE calls are distinguished
from uncalled experimental library functions. Private/Recrypt and aggregate range
verification remain refused where the adopted native implementation refuses
them. A finite mixed workload does not cover historical/cipher migration forms,
every schedule, every private cell or end-user view-key discovery/encryption.

The new combined qualification must bind the final source, normal artifact,
unchanged-native differentials and fresh workload results before any completion
flag changes. Native dispatch coverage is not every-handler/error equivalence.
The recorded observer's catch-up/restart progress does not establish sustained
public availability or peer retention. Public paid service and Mainnet remain
unqualified; see [status.md](status.md) and the separately scoped checkpoints.
