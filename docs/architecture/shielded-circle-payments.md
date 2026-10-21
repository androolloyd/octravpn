# Shielded Circle payments

The experimental node adapter is compiled with
`--features private-payments-experimental`. It uses the existing Circle/BN254
host and changes no consensus rule. Released clients still reject
`shielded_required`; routed-traffic client integration remains unfinished.
The experimental purchase RPC and HTTPS control client are
described below.
The protocol takes no commission.

The public directory remains the source of operator bonds, immutable tariff
hashes, class rates, rate notice and bond generations. `Payments::offer` reads
those facts without a public payer plan. Public plans use the same projection.
The returned offer carries a revocable publication lease; suspension, a new
publication or an operator stop prevents issuing a new quote from old facts.

An operator and one-time claimant sign the private invoice. It binds the full
chain origin, directory, pool, private note owner, receipt key, traffic class,
finite bytes, rounded price and purchase window. The wallet must accept the
actual directory facts and its own price/byte limits. The pool checks the call
deadline atomically with its root/custody update. Call context includes native
deposit and withdrawal amounts: a publicly funded note cannot be reinterpreted
as a shielded internal payment.

`shielded::Pool::confirm` treats all caller-supplied inclusion material as
untrusted. It obtains retained before/after trees from the node's canonical
reader, authenticates the epoch through the node's historical QC service, and
checks the original execution epoch's anchored value/proof rules. The pool and
factory must match the source-derived code and accepted verification-key pins,
with parent ownership, initialized storage and sufficient real native custody.

The note's position must be at least the prior count and below the resulting
count. A 32-level path must bind the privately opened note to the resulting
canonical root. Its owner, value, context and signed quote must agree with the
accepted operator generation and tariff. This works for notes created through
nested Circle calls. An RPC success flag, mempool proof, raw VM receipt or local
index is never funding authority. VM receipt text is deliberately not part of
the adapter's inputs.

The resulting funding record has one credit identity derived from the full
chain, pool and note commitment. Re-reading it, using another inclusion proof,
spending the operator's note or advancing beyond quote expiry cannot create a
different credit. The encrypted wallet journal durably consumes that identity
once before increasing purchased capacity. Actual service handoff must check
the same current publication lease through a nonblocking callback. Disk IO,
proof work and awaits must happen outside that callback.

The canonical test deploys the pool, funds a private payer note, publishes a
private purchase and withdraws the operator's income through the real node
executor and signed QCs. It checks forged paths, wrong creation epochs,
ownership/receipt limits, code/key pins, expiry, suspension, unstake and reopened
canonical/ExEx stores. It recovers the same credit and original purchase time
after reopening. The wallet extension also recovers encrypted quote reservations,
single-use credits and metered capacity against that canonical history.

`shielded::wallet::Wallet` accepts a separately held master key and a Node-minted
pool source. It reserves each claimant/spend-key slot before returning the signed
invoice. Derivation separates wallet identity, invoice nonce, claimant, spend,
database and meter keys. The encrypted channel ceiling limits accepted quotes;
it is not a public on-chain balance. An unpaid quote grants no capacity.

SQLite receives authenticated ciphertext and scoped pseudorandom lookup tags,
including in its WAL. Financial updates use one FULL-synchronous transaction;
an exclusive writer lease and existing-only recovery prevent accidental resets.
A wrong key, deployment, row identity or altered ciphertext refuses recovery.
Credits retain the original private inclusion material. On reopening, the wallet
rechecks actual canonical funding before exposing purchased-byte floors.
Concurrent retries of one note are idempotent. Another genuine payment to the
same invoice is retained as an owned note but grants no second entitlement.

The shared packet meter can encrypt its entire atomic journal with a derived
key while retaining prepaid floors, connection replay watermarks and uncertain
packet reservations. It refuses plaintext fallback, wrong-key recovery and
regressing purchase floors. `Service::bind_private` selects this encrypted meter
storage for a host-supplied authority; it does not turn a public authority into
shielded settlement.

`Wallet` implements the shared traffic authority and prepaid acknowledgement
interfaces. It revalidates received credits against canonical history, then
reads the pool, operator bond, generation and retained tariff from one current
publication. The current epoch, pool count and clock must cover the verified
funding floor even when purchase validation was cached. Each packet handoff
holds that exact publication guard. New publications, suspension, stale heads
and operator retirement prevent an old guard from forwarding.

`Funds::Channel` carries public channel OCT; `Funds::Shielded` carries the private
quote ceiling and credited purchase price. The shared registry refuses a mode
mismatch before opening a meter or connection. A private acknowledgement only
checks already purchased capacity; it cannot buy more bytes from a signature or
submit a public purchase transaction.

`Node::bind_shielded` binds the Circle browser and private VPN in one process,
requiring the wallet to belong to that node's exact publication. It uses the
ordinary WireGuard transport and encrypted per-class meter. `Wallet::bind_service`
also provides the standalone VPN service. Keep one stable transport directory
per wallet; changing directories or restoring old counters is not recovery.
An exit supplies `Some(IpTunnelConfig)`; `None` opens control/transport sockets
without a kernel internet forwarding path.

The private service binds HTTP only on loopback, behind the host's authenticated
TLS transport. It mounts `/shielded/connect`, `/shielded/status`,
`/shielded/stock/connect` and `/shielded/usage`; public `/payments` routes are
absent. `SignedShieldedStatus` has its own signature domain and explicit
purchased, delivered and held counters. It carries no withdrawable channel
balance. Its durable service sequence pins committed counters, while funding,
held bytes and clock can change within that slot. Clients must independently
match connection identity, accepted terms, purchased amounts and freshness.
The private status is not yet a Circle-verifiable service-equivocation claim.

`Node::bind_shielded_purchases` adds `/shielded/purchase` to the same-node service;
`Wallet::bind_purchase_service` exposes the standalone equivalent. Operators
must supply explicit channel/request count, quote ceiling and invoice lifetime
limits. The route is absent without this opt-in. These limits bound local
allocations; the quote ceiling is not deposited or withdrawable OCT.

The receipt key signs a versioned request binding its random ID, full origin,
pool/domain, directory, operator, method/arguments and canonical-time window.
Open creates an empty channel; quote and receipt operations require that
channel's receipt key. Reusing an ID with different terms is refused. Creating
a channel or reserving a quote and recording its response happen in the same
encrypted SQLite transaction. Concurrent retries return the original response,
including the exact claimant/invoice, without allocating another key or ceiling.
Receipt retries recheck/deduplicate actual canonical note placement; a crash
between credit and response recording cannot buy the same bytes twice.

Responses bind the exact signed request digest and are signed by the pinned
operator. They are private control data, not evidence of payment or admission.
A replayed historical quote does not override expiry, current directory consent
or canonical pool checks. Exact requests can be retried only during their signed
canonical-time window; after that, explicit fresh requests are required.

`Payer::record_request` persists the signed envelope in an encrypted, bounded
outbox before transmission. It refuses changed terms under the same ID and
`saved_request` recovers the original envelope after restart. The reusable
`octravpn_client::PrivateControl` accepts a bare HTTPS origin, an independently
pinned target, exactly one accepted CA and one to four accepted TLS SPKI pins.
It requires the leaf key pin as well as chain and hostname verification before
sending private data. It disables ambient proxies, redirects and system roots,
bounds response bodies, and verifies both request
identity and operator signature. It sends no spend keys or proof witnesses.
Callers must still validate signed invoice terms through the canonical payer
before building or submitting a purchase. An authenticated reply cannot fund a
meter.

Allocation caps bound local disk use; self-authenticated receipt keys do not
provide Sybil resistance. Public onboarding abuse controls and funded route
qualification are still required before opening this experimental service to
unrestricted Internet clients.

`shielded::payer::Payer` holds local receiving keys, canonical owned notes and
finite purchase intents in a separately scoped encrypted database. Receiving
addresses reserve their key slot before returning it. A supplied public
`PoolIndex` must match the current canonical note root, spent root and count;
it cannot establish funds by itself. Incoming notes use the same historical
code, proof-rule, custody, QC and membership checks as operator receipts.

`shielded::index::Index` reconstructs the public note and nullifier trees from
retained canonical history. It finds the deployed pool's empty baseline, advances
in bounded epoch batches and keeps an encrypted, atomic cursor/update journal.
Direct successful exchanges use canonical calldata; nested Circle executions
supply auxiliary event hints. Every epoch's rebuilt roots and count must match
that epoch's authenticated state. Event names, receipt checksums and success
flags establish no funding or finality by themselves.

Incomplete sync cannot return a current `View`. A view retains the node's
revocable publication lease, and wallet operations independently check its roots.
Reopening replays bounded encrypted segments and authenticates the saved cursor;
missing records, wrong keys or inconsistent roots refuse recovery. Resource
limits are fixed in the journal. Closing an index drains its SQLite pool before
releasing the writer lease. A source lacking the pool's retained empty baseline
can bootstrap from a public `Seed`. Its scope, epoch and native state root must match a retained
canonical snapshot, and rebuilding all leaves must reproduce both pool roots
and the note count. The seed carries no amounts, owners, private keys or secret
witnesses; a peer signature is not funding authority.
History providers must retain nested-call hints or replay those executions;
missing hints never authorize skipping a changed root.

`View::seed` exports public commitments in append order and sorted nullifiers.
The binary codec bounds counts and exact length before allocating leaf lists.
`Index::bootstrap` verifies the reconstructed trees before creating the local
journal. Version 2 journals store encrypted seed segments alongside later
updates. Existing version 1 journals keep their original format and remain
readable. Explicit `reanchor` can repair public index data against another
verified snapshot, including a checkpoint with a different local sequence or
Irmin commit. It preserves the accepted resource limits and consumed update
counter; it never modifies a payer or operator financial journal.

Private application fixtures can carry an Irmin proof of their original genesis
opt-in across checkpoint import. The proof must bind the configured full genesis
commitment and the exact profile/chain metadata. A current mutable flag cannot
replace it. The checkpoint history reader can return that independently
configured genesis root without inventing an epoch record, snapshot or transaction.
Production consensus rules and public-network activation plans are unchanged.
The [bootstrap checkpoint](../rust-node/checkpoints/2026-10-19/private-bootstrap.json)
records the genuine imported-floor qualification. Recovery of payer/operator
journals and private CLI/config wiring are separate from public-tree recovery.

The later [payer recovery checkpoint](../rust-node/checkpoints/2026-10-19/private-payer-floor.json)
adds spending from directly owned notes already accepted into an encrypted
payer journal. When creation is at or below the imported history floor, the
wallet checks its original key and envelope against the recorded commitment
and position in the current canonical tree. Current code/factory/custody pins,
active value/math rules, exact roots and a live publication lease remain
mandatory. Reservations and spent nullifiers still control available value.
Retained creation histories keep their original verification path. New receipt
imports and operator traffic-credit checks still require historical evidence;
current membership establishes no invoice timing or new capacity.

The imported floor's clock comes from its independently verified finalized QC,
including after store reopen. Clock reads authenticate the captured head and
use the ordinary native timestamp conversion. Conversion happens on read,
preserving checkpoint acceptance. Commit dates and wall clocks provide no
substitute. Genesis without a finalized certificate still provides no clock.
Traffic-credit journals and pending confirmations older than the retained floor
require the original execution evidence described below.

The [operator recovery checkpoint](../rust-node/checkpoints/2026-10-19/private-income-floor.json)
extends owned-note recovery to original encrypted operator wallets. Payer and
operator credentials share the same canonical pool/index checks. Opening income
requires current membership, the original encrypted credit and its receiving key.
Retained creation history also keeps its original placement check. A missing
creation epoch below an imported floor does not confiscate an owned note.

Durable assignments still bind each operator note to one payer book. Previously
unassigned income can join that book once after pruning. Reopen requires every
unspent income provider to be unlocked and reattached; its keys stay in the
original wallet. The saved historical path remains unchanged even when later
appends require another current path. This allows mixed payer/operator inputs,
exact earned-note withdrawal and signature/reservation recovery. Recovery writes
no new customer credit or purchased bytes. Channel recovery still independently
authenticates the original invoice, funding and timing; missing unarchived history
refuses.

The [portable history checkpoint](../rust-node/checkpoints/2026-10-19/private-history.json)
adds bounded witnesses for that original execution. The exact native certificate
retained by this node anchors the witness. Existing v4 signed parent commitments
link back to the payment epoch; a self-consistent quorum on another header with
the same state root is insufficient. Fixed-path Irmin proofs authenticate complete
before/after subtrees for metadata, both custody accounts and the four relevant
Circles. Restoring those subtrees creates a projection, never canonical snapshot
authority. Original code, factory, custody, rule, invoice, signature and timing
checks still apply. Transaction and receipt commitments authenticate successful
execution, including a full withdrawal with no output note.

Before pruning, select the exact epoch to be exported as the checkpoint. Call
`Wallet::prepare_recovery(anchor, maximum)` in batches of at most eight epochs
until `remaining` is zero. `Wallet::retain_epoch` also preserves an execution
whose receipt has not arrived yet. Call `Payer::retain_native` for each confirmed
native attempt that may need later reconciliation. Preserve these encrypted
journals alongside their original keys, the authenticated checkpoint and the
public tree seed. After import, `Wallet::channel` and receipt import reauthenticate
historical funding; `confirmed_native` and `reconcile_native` recover exact
purchases, change and movements even when transaction lookup returns no retained
record. A saved locator alone proves nothing.

Witness descriptors and 48 KiB chunks commit atomically outside financial rows.
Missing chunks refuse after reopen; an explicit authenticated import can repair
them without rewriting credits. Channel validation releases its bounded database
read before loading witnesses, then rechecks the channel before caching its
result. Original invoice associations remain encrypted even though witness data
comes from public history. Existing witnesses can extend to a later retained
certificate before the next pruning operation; anchor regression refuses.

This format permits at most 4,096 ancestry certificates, 32 MiB encoded evidence
and 8 MiB per certificate or subtree. Credit preparation scans at most 16,384
records, and channel verification has the same per-channel credit bound. Every
backward hop needs an existing signed parent commitment, so a legacy child
without it cannot form a bridge. Rule anchors and private genesis opt-in still
need independently authenticated coverage. Lost keys, journals or unarchived
history are not recreated. General long-history production recovery and another
full checkpoint import of extended witnesses remain qualification work.

Index bootstrap starts at the first authenticated initialized empty pool state,
with pinned code and parent ownership. A metadata-only spawn has no initialized
stable storage and cannot serve as the baseline. Funding also requires an
initialized prior pool. The adopted resource lanes admit one Circle call per
epoch, so initialization and the first deposit remain separate native epochs.
Nested calls use zero native value; shielded internal payments and withdrawals
can use that path. The
[index checkpoint](../rust-node/checkpoints/2026-10-19/private-index.json)
records the local qualification.

The payer independently accepts the directory, receipt key, traffic class and
byte/OCT limits. It reserves at most two notes and a change key before local
proving. The proving key must match the accepted verification key, and each
generated proof is checked locally. Only native public calldata leaves the
wallet; witnesses and spend keys are not sent to an operator or RPC. Operator
eligibility and pool roots are rechecked against one current publication before
returning a proposal. A proposal is not a payment or forwarding capability.

An unchanged-root retry returns the same saved calldata after restart. Rebasing
after a competing pool update retains the exact inputs and change key, so the
shared nullifiers prevent two payments. Canonical note inclusion finalizes the
purchase, rather than a submission or operator acknowledgement. Change can be
imported before finalization and spent by another intent; finalizing the earlier
purchase preserves that later reservation. Exact two-note purchases need no
change output.

Available payer OCT excludes reserved or canonically spent notes. Cancellation
can release a reservation only before any proof was exposed, or after canonical
roots invalidate the exposed proof and its inputs remain unspent. Expiry also
requires obsolete roots, rather than relying on a local timeout. Settled
purchases remain final. `for_operator` creates a price-consent view over the
same pool and node. Notes, receiving keys, reservations, proof capacity and
relayer nonces remain shared; another operator cannot create a second balance.
A different pool, custody configuration or node refuses a shared view. Preserve
the original wallet and transport state; restoring old copies is not supported
rollback recovery.

`Wallet::income_ids` enumerates encrypted local credits; the IDs authorize no
spend. `Payer::claim_income` authenticates the actual owned note against its
creation epoch and assigns it durably to one payer identity in the operator
wallet before importing it. `attach_income` recovers an interrupted import and
reattaches the unlocked operator wallet after restart. Repeated imports preserve
spent and reserved state; another payer book cannot claim the same assignment.
The original operator wallet retains the keys and supplies them only inside the
local proof path. This is local custody assignment for one owner, not an
on-chain transfer to another person.

Earned notes can pay another operator or join the ordinary withdrawal and
consolidation paths. Spending them never reduces a customer's purchased-byte
floor. Operator retirement stops new service purchases, but does not confiscate
already earned notes. After reopening the payer, remaining imported income
requires its original wallet to be unlocked and attached; balance and spending
operations refuse while that credential provider is missing.
The [income checkpoint](../rust-node/checkpoints/2026-10-19/private-income.json)
records the local canonical two-operator and recovery qualification.

The shared payer ledger selects and durably reserves notes for purchases,
withdrawals and consolidation. `prepare_withdrawal` returns native calldata for
a partial or full withdrawal; a full withdrawal creates no dust note.
`consolidate` combines two explicit available notes into one fresh owned note.
Both retain their input reservation and output slot across retries/rebasing.
Changed terms under the same movement ID refuse. Cancellation requires either
an unexposed proof or canonical root invalidation with unspent inputs.

`sign_native` binds a prepared operation to its explicit relayer key and a
fixed lifetime fee/attempt budget. It durably records the exact signed native
transaction before returning it. A live retry reuses its nonce, timestamp,
signature and fee reservation. Replacement requires nonce consumption or native
timestamp expiry, a different canonical head and remaining budget. Use a
dedicated relayer: one live attempt serializes that key's nonce. Declared native
fees are conservatively reserved even after failure; they are not protocol
commission. Attempts are stored as individually encrypted records under a
compact versioned counter. The caller may choose up to 65,536 attempts, with a
65,536-record storage ceiling across the wallet; fee and attempt limits remain
fixed after creation. The original inline journal migrates atomically while
preserving its accepted limits, signatures and reserved fees. Missing entries
or missing metadata refuse recovery rather than reset a budget.

`native_attempt` recovers a historical signed transaction by relayer and sequence
without allocating a nonce or fee. Signing and broadcasting check that the
prepared proof's roots/count still match the authenticated current pool; callers
must rebase a stale proof. One unconsumed live transaction still prevents another
operation on the same relayer. Expired native attempts can be replaced only
after another canonical head, preserving both conservative fee reservations.

`broadcast` uses the same node's actual bounded native intake and peer
announcement. Staging cannot fund a channel or retire a reservation.
`confirmed_native` checks the exact transaction envelope and arguments in
authenticated retained finality. `complete_movement` confirms a direct successful
pool exchange, its historical code/value/proof rules and spent inputs. Rejected
calls carried separately in the epoch cannot satisfy it; auxiliary VM receipt
text is not payment authority. This also handles a full withdrawal with no
output membership proof.

`reconcile_native` completes purchases or movements from confirmed execution.
The current public index can reconstruct note paths at an earlier append count
through `membership_at`; every reconstructed path still has to verify against
the actual creation epoch's canonical root. Later appends therefore do not force
the caller to retain an old index snapshot. Reconciliation preserves any later
reservation or spend on an early-imported change note.

Shutdown revokes packet admission before draining HTTP. It signals idle
keep-alive connections and cancels incomplete bodies/handlers, with a bounded
drain and control deadline. Caller cancellation sends the same stop signal;
clients do not have to disconnect to release the old service's wallet lease.
Already-started durable meter writes retain their own ownership until finished.

Keep the master key outside the database and backups. Losing it loses the
one-time spend keys. Automatic keyfile custody/backup tooling remains unfinished. Encryption cannot detect
a privileged rollback or concurrent cloned copies of the entire wallet and
meter history; do not restore an old backup as a fresh live writer. File sizes,
record counts and IO timing are observable, and encryption at rest does not
protect an unlocked process.

The [private launcher checkpoint](../rust-node/checkpoints/2026-10-19/private-launcher.json)
connects original genesis proofs to the isolated BFT launcher's execution and view
graphs. Its explicit `checkpoint_trust` reopens authenticated imports without
creating a substitute ordinary store. Private offline snapshot export also uses
the existing prepare/assemble APIs.

The [operator startup checkpoint](../rust-node/checkpoints/2026-10-19/private-operator-startup.json)
adds a separate `shielded` configuration to the isolated experimental launcher.
`init-private-wallet` explicitly creates a new encrypted book while offline;
normal startup resumes it and refuses a missing or incompatible wallet. The
same native operator key signs private replies, while a separate private master
key protects the book and meter recovery. Startup binds the existing private
purchase, admission and metering services to this node's publication. It neither
submits funding transactions nor turns a quote into purchased bytes. Public
payment routes and alternate payment/stock-exit modes remain absent.

The [private payer runner](../rust-node/checkpoints/2026-10-19/private-payer-runner.json)
adds a caller-driven finite purchase job in the encrypted payer book. Accepted
source/generation/tariff pins, class, bytes, maximum cost, expiry and relayer fee
budget remain immutable across retries. Its per-job receipt key is derived
locally; operators receive no witness or native signing secret. The shared
`PrivateExchange` interface uses the existing CA/SPKI-pinned HTTPS client.

Each step syncs the canonical index and recovers prior native attempts before
preparing another payment. Requests and signatures persist before transmission.
Exact queued transactions are reannounced through the healthy owned staging
pool, preserving ordinary admission rules. Canonical inclusion and change
reconciliation precede the receipt exchange; signed operator data alone does not
establish funding. `Credited` acknowledges that exact note and grants no packet
authority. Applications retain the original job ID for resume, respect finite
request expiry, and retain/extend witnesses before pruning. Automatic job
discovery and routed client admission remain unfinished.

The [private transport client](../rust-node/checkpoints/2026-10-19/private-client.json)
now supplies standalone private admission/status and encrypted transport
recovery. `PreparedPrivateClient` persists its connection watermark, authenticates
the operator over accepted CA/SPKI-pinned HTTPS and refuses a missing purchased
floor before UDP/TUN startup. `PrivatePaymentClient` rechecks that floor before
opening the shared WireGuard/TUN driver. It holds only the job's receipt key and
cannot initiate a native purchase. Per-hop orchestration remains separate.

The private transport journal seals the complete record under a receipt-secret
key with immutable financial/source scope. It preserves the existing exclusive
writer, atomic durability, poisoning and uncertain-handoff rules. Signed status
pins funding, purchase, delivery-slot, connection and canonical-clock floors
across reconnect; it never raises local caps. Its quote ceiling is not channel
OCT. The canonical preparation/restart path and all public client regressions
pass, while private kernel forwarding and combined route recovery remain open.

Remaining integration includes long-history witness coverage and private
operator key-custody/backup tooling, automatic routed-client scheduling and recovery,
zero-price grants without dummy paid notes, private service-equivocation
claims, and a funded private route using the live per-class meter.
Concurrent roots need scheduling/retries and funded multi-node/kernel
qualification before enabling the released mode. A production circuit-specific
ceremony and adversarial cryptographic review also remain required.

Internal values and ownership links are hidden under the proof/hash assumptions.
Native deposits/withdrawals, relayer identity and timing remain public. Payment
does not prove physical traffic delivery. Tunnel encryption does not conceal all
network metadata or protect plaintext beyond the final exit.
