# OctraVPN deployment candidate review — 2026-10-11

**Status: unsigned candidate preparation; mainnet launch is blocked.** The target
network, genesis, RPC and owner remain undecided. This review records local
verification and its limits; it is not an independent audit or launch approval.

## Changes requiring review

- Session admission checks the live program, confirmed opening transaction,
  opener, session bounds/status and funded exit identity. Receipt submission
  requires a current admitted session; an evicted session must announce again.
- Standalone client settlement binds its configured v3 circle before replaying
  journals. Client WireGuard identities derive X25519 keys from private signing
  material; published signing keys cannot reconstruct them. Existing peers must
  reannounce the corrected identity.
- Wallet-file decryption rejects zero or excessive PBKDF2 work factors before
  deriving a key. The file-controlled maximum is 1,000,000 rounds; ordinary
  200,000-round wallets retain their format. A corruption property test reproduced
  the previous CPU denial of service. Deliberately higher-work-factor envelopes
  require a reviewed migration rather than automatic unbounded work.
- Relay claim/recovery arithmetic uses checked sums, a nonzero margin and
  disjoint windows. Membership synchronization retries a failed epoch fetch.
- v3/v4 governance approves a verified native circle owner before registration.
  The contract cannot query native circle ownership itself. Circle registration
  is permanent: retirement does not release its identity to another operator.
- Retirement precedes unbonding; every funded session must reach a terminal state
  before principal can leave. Outstanding-session counts cover ordinary and
  relay settlement/refund paths. Accrued earnings remain withdrawable after slash.
- Opaque permissionless `slash_double_sign` fails closed in all contract variants.
  Two arbitrary signed hashes do not prove the same receipt slot equivocated.
  The retained ABI cannot safely authorize a burn. Governance slashing remains;
  this candidate is a governed pilot. A public permissionless policy requires
  structured VM-verifiable evidence, specification, tests and independent review.
- Foundry uses the real pinned AML compiler by default. Synthetic artifacts
  require `--mock`. HTTP compilation failures never produce fallback artifacts.
  Native deployment success requires a successful execution receipt and actual
  program address; `--no-wait` explicitly reports an unconfirmed prediction.
  Automatic nonces account for pending transactions, and native HTTP signing
  refuses the model-only chain-ID envelope extension.
- Headscale changes retain the existing wire surface and close reviewed ACL/
  compatibility failures. Protobuf generation now writes Cargo's output directory
  instead of modifying tracked source files or requiring a writable dependency checkout. Passing mock or legacy slash tests does not establish
  equivalence with the revised AML contract.

## Verification evidence

The final `out/mainnet-evidence-20261011` directory contains logs and machine-readable
results. Native runtime provenance is supplemented by the local Docker image and
patch hashes because its self-reported source/binary fields are null. Local checks:

| Check | Result and scope |
| --- | --- |
| Octra Rust workspace, all targets/features | 1,678 passed; 4 ignored; strict Clippy passed with all targets/features and in default/test-helper configurations |
| Headscale API | Minimal: 782 passed; full: 879 passed; each 1 ignored; strict Clippy passed in both configurations; focused ACL tests 13 passed |
| AML v4 tests | 18 actual compiler/VM tests passed; three deliberately failing fixtures and an empty selection correctly failed |
| Native v4 money tests | Passed actual native transfers, ordinary settlement/earnings withdrawal, relay claim/refund, no-show recovery, and retirement/unbonding with negative controls |
| TLA+ | v1: 223,118 distinct states; v2: 3,805,681; relay: 71; invariants held; zero-margin control produced the expected violation |
| Kani | Five production-code harnesses passed, including session ID encoding and disjoint checked relay windows |
| Tamarin | Six exact symbolic authentication/durable-ack lemmas verified, including reachable honest/crash-recovery traces |
| Lean | Libraries build, including six new v4 stake-lifecycle properties |
| ExEx | 12 tests passed for ordered replay, failure/crash handling and durable namespaced checkpoint CAS |
| Foundry workspace | 350 passed; strict Clippy passed; deployment confirmation negative controls passed |
| Native daemon receipt/arm/autonomous claim | Passed with plaintext and sealed-only operator keys; real native earnings increased by 2,985 OU for the 3,000 OU claim |
| Stock Tailscale mesh and restart | Tailscale 1.96.5: two clients joined; encrypted TSMP/ICMP probes passed; registrations hydrated from SQLite and encrypted TSMP passed after restart |

Native money evidence binds production `main-v4.aml` by SHA256 and identifies the
private runtime. A single owner-only fixture method seeds elapsed unbond grace;
production method bodies are unchanged. **That fixture contract is never a launch
artifact.** Standalone tests cannot execute host transfer operations, so financial
claims rely on the native test in addition to local compiler tests.

Formal models prove their stated abstractions and assumptions. Historical v1–v3
Lean models have not been refined against the revised AML; symbolic crypto,
finite model bounds and abstract transitions do not prove the compiler, node,
AML implementation or complete VPN correct.

## Upstream constraint and reproduced bug

Upstream source is pinned to public commit
`7264d6d016091358fae071c332a0c6aeeb90f2e4`; standalone AML compiler to
`3a183bc8892b1795f2e1059848f1f331ce1a3a51`.

The isolated native mode opts in to a private `octra-local-*` chain, disables
peer services and requires Single mode with consensus disabled. The existing
rule graph, VM, activation schedule and consensus algorithms remain unchanged.
Its private chain executes the prior profile, so it cannot certify a selected
public chain's activated execution rules.

A reproduced upstream Single-mode bug passed insertion-order staging directly
into a validator requiring canonical order. Two independent senders in reverse
canonical order caused `outcome_order_invalid` and terminated epoch processing.
The patch sorts this input with the existing `Transaction.consensus_order`.
BFT and override validation stay strict. The Docker build requires the same
regression to fail before the patch and pass after it, including duplicate and
invalid override rejection. This is the user's explicit bug exception; no new
consensus feature was introduced. Patches and test are reviewable under sibling
`octra-foundry/docker/octra-node/patches/`.

The signed release canary verified sequence 30, public commit above, internal
source `103dfe528e38328fee7e9ffaa6e63dfba2dc06a7`, profile 16 and rules
`finalized_rejection_commitment`. It returned the expected drift exit code 10
against accepted sequence 12. The baseline was not silently advanced. The
marker expires at `2026-10-11T13:59:19Z`; refetch and reverify for launch.

## Remaining launch prerequisites

1. Select and independently verify the target network/genesis, RPC, chain
   execution profile, activation epoch and fresh signed release provenance.
   Recompile and rerun native/daemon checks under those exact rules.
2. Select the owner and supported authorization/recovery scheme. The previous
   ceremony described CLI multisig features that do not exist. It now refuses
   execution; native multisig support is not assumed. No transaction is signed
   or broadcast by candidate preparation.
3. Approve economics in **six-decimal native balance units**: 1 OCT = 1,000,000
   OU. The historical worksheet used nine-decimal annotations incorrectly.
   Carried-forward numbers currently imply 1,000 OCT minimum session escrow and
   10,000 OCT tailnet deposit/stake. Those amounts have not been approved. The
   contract's stake floor is 100 OCT.
4. Independently review the revised contract, receipt/HTLC protocol, onboarding
   trust, governance slash policy and historical-key evidence retention. Run
   deployment, backup/restore, pause/recovery and operator failure rehearsals on
   the target environment; define operational ownership and monitoring.
5. Publish compatible cross-repository changes and pin CI checkouts before
   relying on remote gates. Local Octra, Foundry and Headscale changes are
   uncommitted; a source fingerprint records the actual dirty trees.

## Unsigned candidate and verification

```sh
python3 scripts/ceremony/prepare-candidate.py prepare \
  --amlc /absolute/path/to/pinned/amlc \
  --out out/mainnet-candidate-20261011
python3 scripts/ceremony/prepare-candidate.py verify \
  --out out/mainnet-candidate-20261011
python3 scripts/ceremony/prepare-candidate.py verify \
  --out out/mainnet-candidate-20261011 --require-ready
```

The first command bundles exact production v4 source, real OCTB and ABI, compiler
identity, constructor intent and source fingerprints. `intent.json` is a review
intent, not an unsigned wire transaction: target fields and nonce are unset.
Integrity verification can pass while `--require-ready` fails. The compiler's
local preview is not a target-profile deployment package. Artifact hashes do not
authenticate an owner or approve launch prerequisites.

After a separately authorized deployment, verify its actual execution-package
code hash and current `get_owner` against independently reviewed target values:

```sh
scripts/ceremony/verify-deploy.sh octPROGRAM \
  --rpc-url https://VERIFIED-TARGET/rpc \
  --expected-code-hash REVIEWED_TARGET_PACKAGE_SHA256 \
  --expected-owner octREVIEWED_OWNER
```

This read-only check verifies only code hash and current owner. A standalone
OCTB hash or predicted address must not substitute for the deployed package.

## Rust node and ExEx scope

`crates/octra-exex` provides immutable committed-epoch delivery, ordered callbacks,
at-least-once replay and SQLite checkpoint persistence with namespaces and CAS.
2026-10-12 update: It now also has a transactional SQLite epoch source for a future host that keeps
canonical chain state in the same database; rollback and restart are tested.
The host must still supply authenticated finalized epochs. This is not yet connected to
an Octra consensus commit hook or the VPN daemon. A Rust Octra consensus node,
protocol parity and the requested single-process chain/VPN integration remain
implementation work. The native test setup currently runs the upstream OCaml
chain node and Rust VPN daemon as separate processes.
