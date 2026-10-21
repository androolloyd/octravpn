# Private payment experiment

This package is outside the released node/client workspace. It provides an
experimental shielded OCT pool as an immutable Circle app, plus the native
wallet's stealth wire codec, operator/claimant signed invoices, encrypted
purchase proposals and HFHE amount-opening checks.
The codec is checked against unchanged upstream
wallet code at `549536d6fbe265a4aace02bc9b85b5313ebb4868`. It does not fund a VPN
plan, mint traffic capacity, or enable `shielded_required` in the released node.

The native format uses AES-256-GCM with the ECDH shared digest directly as its key,
12 nonce bytes, an eight-byte little-endian amount, 32 blinding bytes and a 16-byte
tag, encoded as base64. Native view keys derive from the Ed25519 seed through
SHA-512 and clamping. The existing VPN helper's private ChaCha format and view-key
domain remain separate; its ciphertext must never be sent as a native payment.

Generate test vectors using the actual pinned wallet checkout and OpenSSL:

```sh
python3 tools/native-stealth-fixtures.py --upstream /path/to/pristine/webcli --out /path/to/fresh/output
```

Copy that output's `native-stealth.json` into `tests/`, then run `cargo test
--locked` in this package. The oracle links a deterministic test-only RNG callback
to make nonce vectors reproducible; it does not change the upstream codec. The
seeds and openings in these fixtures are public test constants and must never
receive funds.

Version 2 invoices bind the chain, directory Circle, operator bond generation, exact offer
and tariff, payer receipt key, one-time claimant, class, finite bytes, rounded
price, expiry, settlement type, pool Circle and private note owner. Acceptance
also enforces the rate-notice cutoff. Both the operator and claimant sign their
domain-separated statements. Verification checks independently accepted offer
facts and price caps at authenticated chain time; it returns a quote ID and
grants no traffic capacity. Recipient view keys and addresses match native
wallet vectors. Invoice types have no Debug or generic serialization support.

Proposals use fresh ECDH keys, authenticate the native amount envelope, and
keep the invoice ID outside chain fields. Amount openings are checked with the
existing HFHE port against native Pedersen generator vectors. These operations
authenticate proposed terms and a price opening; they do not prove payment.

Each invoice currently covers one traffic class. A live route needs an
explicitly accepted bundle for every paid class. Expiry closes new purchases;
a later claim must preserve a payment made at its authenticated creation time
within the quote window. It must not expire already-purchased bytes.

The standalone native-claim proposal remains an interoperability experiment.
Its transfer cannot atomically reject an expired quote and refund its sender;
the pool is the intended settlement path. Native-claim and pool invoices cannot
be substituted for one another. No consensus change is included.

## Shielded Circle pool

`src/pool` implements two-input/two-output note transitions with full-depth
Groth16 BN254 proofs. A note commits to the pool/chain domain, private owner,
random rho, value and call context. A spend proves membership, key ownership,
non-use of its nullifier and conservation of value. Every enabled amount is
positive and fits native int64; bounded sums cannot wrap the scalar field.

The note append tree has depth 32. A sparse spent tree uses all 254 canonical
nullifier bits, so no ever-growing nullifier map occupies Circle stable storage.
Both roots remain constant-size on chain. Full withdrawal needs no new output
and remains possible at append-tree capacity. Public nullifiers/commitments let
independent indexers reconstruct the trees without knowing owners or amounts.
`PoolIndex::observe` only checks index consistency; the caller must authenticate
the actual canonical Circle event first.
`Membership` additionally checks a note path against an independently accepted
root and count. The node's experimental funding adapter uses authenticated
historical roots and the newly appended index interval, rather than VM receipt
text, to establish receipt of an actual private purchase.

Hashes use the exact BN254 x^5/t=3 parameters from
[light-poseidon 0.4.0](https://docs.rs/light-poseidon/0.4.0/light_poseidon/).
The native and constraint implementations are checked against that independent
implementation and its published vector. Domain tags distinguish owners, notes,
nullifiers, authorization and every tree level.

`program/shielded-pool.aml.in` constructs its own 17 public scalars from current
state and typed call data; a relayer cannot supply trusted verifier inputs.
Expiry is checked before roots/custody change. Deposits, withdrawals, encrypted
boxes, payout and relayer are proof-bound. Version 2 call context also includes
native value flows inside each note commitment, preventing public deposits from
being presented as internal shielded purchases. An expired or invalid call rolls back
its native value and stable state. Only the ordinary transaction fee remains.
There is no protocol commission or privileged withdrawal function. The separate
factory spawns parent-owned code and exposes no upgrade entrypoint.
Permissionless initialization is a later finalized call with source-pinned terms.

An operator receives spendable notes and can pay another operator from those
earnings. The local Circle test exercises deposit, private purchase, an onward
earned-note payment, and three full withdrawals. It also checks expired calls at
a monotonically advancing clock, replay, every public scalar, altered payout,
inactive native custody, public-index recovery and zero remaining custody.
The proof setup uses the real 32/254 depths, including disabled input slots.

```sh
OCTRA_PRIVATE_POOL_EVIDENCE=/absolute/fresh/public-report.json RAYON_NUM_THREADS=8 \
  cargo test --release --locked -- --nocapture
cargo clippy --release --locked --all-targets -- -D warnings
python3 tools/pool-native-fixtures.py --upstream /path/to/pristine/lite_node \
  --builder-image your-local-native-builder --input /absolute/fresh/public-report.json \
  --out /absolute/fresh/native-report.json
```

The last command compares both AML emitters and real proof vectors with the
unchanged, source-inventoried upstream VM and worker, offline. This is distinct
from full upstream epoch or public-network qualification.

`proofs/Pool.lean` proves six abstract backing, withdrawal, expiry and zero-fee
lemmas. Run it from the repository's `proofs/lean` directory with its pinned
Lean 4.10 toolchain. These lemmas assume sound conservation and membership
verification; they do not prove the circuit, cryptography or compiler correct.

The node now has an opt-in experimental historical funding adapter, documented
in [shielded Circle payments](../../docs/architecture/shielded-circle-payments.md).
The node's encrypted wallet reserves unique claimant/spend slots, retains private
invoice and funding proofs, and consumes each note credit once before adding
per-class purchased bytes. Its shared prepaid meter supports encrypted journals.
The wallet now supplies the shared service's canonical packet guards and
prepaid acknowledgements; private status uses its own accounting/signature
domain. Node binding requires the browser and wallet to share one publication.
The local node payer now reserves canonical notes before proving, persists
encrypted intents/change keys, and reconciles final note inclusion. Its local
prover and native calldata builder expose no witness or spend key. Rebase and
retry retain the same input notes; canonical confirmation remains mandatory.
The node also provides opt-in signed private purchase RPC, atomic retry records,
an encrypted payer outbox and a CA/SPKI-pinned HTTPS control client. Responses are
not funding authority; receipts must pass the canonical note verifier.
The node payer now also shares note reservations across native purchase
submission, consolidation and partial/full withdrawals. Signed attempts and
conservative native fee budgets survive restart. Confirmed transactions and
historical note-prefix paths reconcile later appends without trusting an RPC
success flag. The encrypted relayer journal uses individual records and supports
explicit budgets up to 65,536 attempts, with atomic original-journal migration.
Earned operator notes can join one local payer book through an exclusive durable
assignment. Price consent varies by operator while notes, keys, reservations and
relayer journals stay shared. The original income wallet must be unlocked and
reattached after restart; this is not a key transfer to another person.
The node also reconstructs public pool trees from canonical history with an
encrypted cursor/update journal. Untrusted nested-call events supply hints only;
actual canonical roots and counts must agree before returning a current view.
Public leaf seeds can bootstrap the index at a nonempty authenticated checkpoint;
canonical roots/count authenticate the result. Encrypted reanchoring preserves
local resource limits and consumed updates. Existing directly owned payer notes
can recover spending authority after checkpoint import through their original
encrypted journal, keys and authenticated current membership. This preserves
reservations/signatures and establishes no new traffic credit. The floor clock
comes from its verified finalized QC, without changing checkpoint acceptance.
Original operator wallets can also recover earned notes through current
membership, preserving one-book assignments and keeping their keys local.
Mixed-key consolidation and withdrawals leave customer-credit records unchanged.
The node can now retain bounded encrypted historical execution witnesses before
pruning. Exact node-authenticated certificates and existing signed parent links
authenticate old customer credit, new receipt imports and pending purchase or
full-withdrawal reconciliation after checkpoint import. Missing witness chunks
refuse; explicit verified imports repair them without changing financial rows.
Successor extensions preserve the original execution and reject anchor regression.
See the [portable history checkpoint](../../docs/rust-node/checkpoints/2026-10-19/private-history.json).
The format has a 4,096-certificate/32 MiB limit and cannot bridge a legacy child
without a signed parent commitment. It requires the original journals and keys.
The isolated BFT launcher now reconstructs and authenticates original genesis
before carrying its opt-in proof into execution and views. Explicit checkpoint
trust and ordinary private-store snapshot export support native Circle execution
and ExEx after import/restart. See the
[private launcher checkpoint](../../docs/rust-node/checkpoints/2026-10-19/private-launcher.json).
The isolated experimental launcher can explicitly initialize and resume an
encrypted operator wallet, then bind its canonical private purchase and meter
services. Missing wallets refuse at ordinary startup; initialization is a
separate offline command. See the
[operator startup checkpoint](../../docs/rust-node/checkpoints/2026-10-19/private-operator-startup.json).
The native payer now has a finite encrypted purchase runner connected to the
canonical index and pinned HTTPS exchange interface. It fixes local consent
before requests, recovers exact native attempts before buying again and confirms
original inclusion before asking for operator credit. Lost replies, staged
retransmission and offline confirmation recover through the same job ID. See the
[payer runner checkpoint](../../docs/rust-node/checkpoints/2026-10-19/private-payer-runner.json).
The caller retains that ID; automatic discovery and routed client admission are
not provided by this service.
The standalone client now has a private preparation/admission path using pinned
HTTPS and a fully sealed transport journal. It reuses conservative packet
handoffs, refuses a missing purchased floor before UDP/TUN startup and preserves
private accounting floors on reconnect. The native canonical fixture exercises
admission before/after genuine funding and encrypted resume; 617 node/client
tests pass. See the
[private client checkpoint](../../docs/rust-node/checkpoints/2026-10-19/private-client.json).
Private payload/kernel and routed per-hop qualification remain unfinished.
Release integration still needs general long-history recovery, operator key-custody/backup tooling,
automatic routed client recovery,
zero-price grants, private service-equivocation claims and
funded route qualification. Test setup entropy
is not a production proving-key ceremony; no test key should back real funds.
Proofs currently bind exact prior roots, so concurrent submissions need retries
and a scheduling/batching design before high-throughput use. Internal values and
owner links are hidden; native deposit/withdrawal amounts, relayer addresses and
timing remain public. Tunnel encryption does not conceal all network metadata or
protect plaintext beyond the exit. This experiment makes no anonymity claim.
