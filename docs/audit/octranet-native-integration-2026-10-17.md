# Native integration adversarial review — 2026-10-17

This review covers the baseline-compatible Circle custody variant, explicit
stock Tailscale transport, fixed unpaid portal and paid Circle HTTPS route,
legacy native reward metadata, and nested prepaid clients. Three agents worked
on implementation and independent source reviews. Final execution results belong
to the qualification checkpoint; source inspection alone is not an end-to-end
result or a proof of complete behavioral equivalence.

## Corrections made before final validation

| Trigger | Correction |
| --- | --- |
| A public stock connection request is replayed through the native framed endpoint before its first durable admission. | Stock authorization uses a distinct signing domain. Neither endpoint accepts the other transport's signature. The journal also binds transport and registration identity. |
| A valid existing framed prepaid journal has no new transport field. | Strict v2 decoding validates the original checksum transcript and rejects injected fields, converts only to framed mode, and durably writes v3 before publication. All consumed, purchased, pending, uncertain and connection-watermark state survives. |
| Both a v2 legacy reward row and its version row are removed. | Existing outbox rows require a version marker. Only the first atomic schema installation can label pre-feature bound native history as v1; reopen cannot heal deleted markers. Modern canonical reward evidence remains mandatory. |
| A virtual operator is marked online when mesh configuration binds, before its paid transport runs. | Its presence guard belongs to the live native DERP/transport task and drops with that task. A stale offline callback cannot override a newer presence generation. |
| An operator chooses a CGNAT address that the deterministic member allocator can later allocate. | The stock operator uses the allocator's actually reserved router address, `100.64.0.1`. Other choices fail configuration validation. |
| A general Circle gateway shares the registration-only portal route. | The portal retains one Circle and exact asset allowlist. General Circle HTTPS uses a separate reserved VIP and TLS listener and consumes canonical purchased bytes. |
| A higher-precedence foreign routing rule could bypass a nested client's fallback blackholes. | The composite lease uses priority 1 after the standard local rule, refuses conflicting earlier policy, and retains specific downstream endpoint blackholes beneath each carrier route. Foreign policies are never flushed. |

## Findings during final validation

The unchanged native Circle oracle reports `charged = false` for Circle-call
rejections even when OU and the nonce are consumed. That marker is reserved for
three compute money operations. The generator's initial blanket expectation was
incorrect; the corrected reference retains actual native fees, accounts, receipts
and roots. No runtime fee rule changed.

The new signed-QC Circle fixture initially required a VM receipt for every
transaction. Native `CircleDeploy` installs code without invoking the VM. The
fixture now requires absence for that operation and retains its strict receipt
and success checks for calls, alongside full proposal and finality verification.
The failing diagnostic and interrupted broad run remain recorded.

Independent legacy-wrapper validation also found three tests returning early
because macOS provides `true` at `/usr/bin/true` rather than `/bin/true`. Their
old reported count of 24 represented 21 executions and three skips. The test
helper now resolves the fixed system paths and fails if neither exists; the
final wrapper gate rejects skip markers and uses the freshly built C++ helper.
This changes test fixtures only. Broad qualification and Linux image runs are
restarted after those corrections rather than presented as passing old runs.

The subsequent broad run also detected that the registry's strict native golden
still pinned the previous `Cargo.lock`. Its refusal occurs while checking input
provenance, before comparing execution outputs. The golden must be regenerated
by the pristine adopted native host for the new dependency pin; manually changing
its expected hash would not establish native compatibility. The broad failure
remains recorded separately from the complete corrected target rerun.

The first stock-client kernel run also exposed a fixture socket collision:
wildcard control HTTPS on port 443 overlaps the fixed portal listener in the
same operator network namespace. The fixture must bind control HTTPS to its
specific underlay address. Public configuration examples use a distinct control
port, avoiding both portal port 443 and the paid Circle listener on port 8443.
The failed run and its cleanup remain separate evidence; this correction changes
the test listener configuration, not production admission or consensus rules.

The real stock-client run then found a production transport bug: switching an
existing WireGuard session from its direct UDP endpoint to DERP lost its peer
state. Endpoint sharding treated the relay's loopback source as a new peer, while
every stock session used the same receiver index. Restarting the disposable
Tailscale daemon established a fresh DERP session and isolated the fault, but
that diagnostic does not satisfy the ordinary connection-switching test.

Stock cryptographic state now belongs to the exact registered node key, with
unique receiver indices and one replay window across direct and relayed paths.
Only authenticated Noise handshake or data results can update its return
endpoint. Invalid packets, cookie replies and replayed packets cannot move it.
An unregistered or forged handshake cannot allocate the bounded peer table.
Registration replacement, expiration and stale completion tokens retire the old
identity, including pending TUN handoffs and replies. The repaired candidate
requires a new image and the original direct-to-DERP test; results from the
previous executable are retained with their original success or failure.

The repaired roaming test passed before the next run exposed a separate restart
failure. An operator restart discards ephemeral WireGuard sessions, while the
unchanged stock client can continue sending its old receiver index. An unknown
index now triggers a fresh native Noise handshake only when the enclosing DERP
source authenticates the exact current registered node key. Direct UDP packets
cannot allocate this recovery state. A separate candidate endpoint permits only
handshake initiation and native timer retries; it cannot carry transport data
or become the authenticated return endpoint. Final sends recheck canonical
admission, registration, identity and the DERP source association. A valid Noise
response is still required before forwarding. Repeated old packets retain the
pending handshake, and registration replacement retires its retries. The
original failed restart run remains failed; the production fix requires fresh
stock-client and combined transport qualification.

A separate header-only diagnostic retained the same Tailscale process, key and
purchases. The old build eventually recovered through the client's own rekey,
but its first ten-second TCP attempt still failed. That diagnostic stays
unqualified; the correction supplies prompt authenticated server-side recovery
without restarting the client or relaxing the original traffic check.

The fresh Circle-custody fixture later stopped after its factory was confirmed:
the next `octra_submit` returned RPC 110, `service unavailable`, before client
onboarding. The fixture had not waited for canonical Serving admission before
that Circle call. A diagnostic fixture added the existing read-only Serving and
HTTP 200 check before submitting once. It failed at the same call despite
Serving being true. Neither run establishes transaction absence; both failures
and their cleanup remain recorded. The diagnostic fixture is not promoted.

The repeat exposed the actual admission defect. Rust queue intake sent
`CircleCall` through its private proof dispatcher, which always returned
`private_preverify_pending`. Native queue admission starts only private and
key-switch proof jobs; Circle execution and bindings belong to ordered proposal
processing. Rust now defers Circle calls and Circle cell puts at queue intake,
retaining signature, payload, profile, resource, nonce, durable staging and
current-generation checks. It supplies no execution receipt at admission.
Proposal execution, Circle receipt capture and imported receipt validation stay
unchanged. Regression tests must traverse the actual Native/RPC boundary: the
earlier service fixture mocked intake and therefore missed this defect. A fresh
production image and the original Circle fixture are required for qualification.

The new HTTP regressions retain their initial lint and test failures. Their
first executed run passed the real Circle submission/finalized spawn and the
signature/profile/resource/nonce/lease controls. The cell negative incorrectly
expected a `Built` result from direct `build_proposal`; that API rejects the
whole supplied candidate before producing a stage when cell proof verification
fails. The corrected assertion requires exactly
`ProposalError::Invalid("local_preverify_mismatch")`, plus unchanged canonical
head, root, account and absent VM receipt. It still requires both cell operations
to enter through the real HTTP queue first. No runtime rejection rule changed.

The complete admin API comparison also exposed a fixture clock race: its two
otherwise identical records could receive different creation seconds. Both
fixtures now use the same nonzero UTC timestamp. The comparison retains every
field, including `last_seen`, rejects malformed JSON and requires HTTP 200.
The complete six-case target passes on Linux; no production clock or API
response changed.

The first two-hop crash-recovery run stopped before deleting routes because
iproute2 renders numeric protocol 186 as `bgp`. Its IPv6 blackholes also report
`dev: lo` and `pref: medium`. The production route manager filters the kernel
with numeric `proto 186`; it does not compare that display name. This was a
fixture decoder failure after canonical purchases and bidirectional MTU/MSS
checks, before completing recovery, exhaustion or withdrawal.

The fixture accepts only the two exact protocol renderings. It permits the
medium preference only on the two expected IPv6 blackholes, rejects blocker
gateways or unexpected devices, and retains numeric per-row deletion and all
other ownership checks. A disposable namespace on the same image verified six
numeric deletions while preserving a foreign protocol-187 route. The failed
run remains failed. Both corrected two-hop scenarios and the three-hop scenario
require fresh execution. Native binaries and their original source manifest
remain unchanged; a separate helper context records the exact fixture repair.

The corrected two-hop run passed route recovery, both operator restarts,
carrier-loss blocking and entry exhaustion. It then failed while purchasing
against newly accepted plans after withdrawal. The second operator's class-one
purchase finalized successfully in all four canonical/ExEx archives at epoch
52, about 30 milliseconds before the client reported a non-success HTTP reply.
Its meter had reconciled the purchased floor but had not persisted the matching
authorization. This excludes a lost purchase and the 45-second confirmation
timeout; it does not identify the exact HTTP status or refusal branch.
Publication revokes Serving before commit and restores it after ExEx notification,
so the waiting confirmation can encounter that interval. The failed run remains
failed. One diagnostic stopped earlier on the read-only getter's documented RPC
`-32005`, `program snapshot unavailable`. A second completed all seven traffic
and economic stages with eight successful receipt replies and no observed
refusal. Neither establishes the original refusal's exact cause.

The client now retries only HTTP 503, at most three times, using the identical
already signed receipt bytes. Other failures remain terminal. The existing
signed-status, tariff, membership, freshness and canonical-purchase guards still
authorize traffic; an HTTP success alone does not. The qualification fixture
separately retries only the two documented read-only snapshot-busy responses,
using the same arguments and a fixed ten-call limit. Writes and purchases are
not retried by that helper. These are bounded resilience changes, not a claim
that the historical refusal was reproduced or its cause confirmed.

Read-only public observation found another concrete source parity gap. The old
observer advanced two epochs while the official head advanced seven in the
sampled interval; its lag widened from 98 to 103 even though Serving became true.
The adopted native HTTP fallback requests a bounded 16-record chunk even when
its target is the next verified successor. Rust instead limited the request to
the target distance, importing one epoch before another retained-prefix audit.
The correction preserves the independently proved target, rejects malformed
payloads before import, truncates only a QC-invalid suffix, and keeps valid-QC
execution failures fatal. A real-service regression imports all sixteen epochs
before one audited resume. Its first run reached that point but failed because
the fixture compared the entire vote directory against its initial bytes while
also expecting the safety floor to advance from one to seventeen. The corrected
check verifies that exact floor advance while requiring every other journal
byte to remain unchanged; the fresh regression passes. Strict lint subsequently
found a redundant test import and required a `let ... else` expression. Those
syntax/import corrections change no QC, execution or payment behavior. Their
failed run and the stopped runtime build remain recorded separately from fresh
qualification. Serving alone is not proof of synchronization to tip.

A later read-only sample of that unchanged old build reached epoch 1,711,144,
33 epochs behind the RPC head and 34 behind the secondary HTTP head. The earlier
87-second lag-growth observation therefore does not establish a permanent stall
or the batching correction's performance effect. Those HTTP hints are sampled
separately and do not supply finality authority.

The additional production-worker check initially ran a fault-enabled harness
against a normal release. That binary deliberately omits the test-only `Fault`
decoder, so five lifecycle cases failed before the later targets ran. The failed
attempt remains recorded. A corrected supplement separates ordinary operations
from all eight helper-only cases, including a cancellation case that happened to
pass before dispatching its fault command. Fault-enabled execution retains its
own artifact and feature scope; it cannot establish support for test commands
in the production binary. The corrected macOS production supplement passes
14 ordinary named cases across six executables, with no remaining owned child
processes. The Linux image's process-test layer explicitly enables test helpers;
a later default-feature build supplies its separately hashed production node.
Those repeated cases do not increase the logical Rust test total.

The image manifest binds six executable byte strings. Its node and
administration tool use default-feature release builds; Foundry, the paid
client and the standalone operator use debug builds. The Single initializer
is a debug test executable. Both actual mixed Rust validators use the release
node. Equality of the six manifest entries establishes artifact identity;
release-built paid-client end-to-end behavior remains a separate qualification.

The next fresh Linux run passed the framed, stock-Program and stock-Circle
scenarios. Its first nested scenario then stopped while reading the packet
target's JSON snapshot, after the route, purchase, MTU/MSS, restart and
carrier-loss controls. The reader checked that the path existed before opening
it; the subsequent open returned `FileNotFoundError`. The target's final
snapshot contained traffic counters and no recorded target errors. Its writer
uses a temporary file and atomic replacement and does not unlink the target.
The failed open is observed; a cross-container filesystem visibility race is
an inference, not a demonstrated gap in ordinary POSIX rename semantics.

The fixture now shares one bounded snapshot reader. It retries only
`FileNotFoundError`, for at most ten reads separated by 100 milliseconds. It
rejects oversize files, malformed JSON, duplicate keys, non-finite numbers,
wrong top-level types and other I/O errors immediately. An exhausted read
remains an error; missing or corrupt counters never become zero, stale or empty
snapshots. Every traffic and economic assertion remains in place, including
the nonempty MSS observations after actual TCP traffic. All 21 Python
regressions pass. The seven-path correction changes fixture readers and their
image packaging; Rust, native source, dependencies and payment rules remain
byte-identical to the preceding implementation. The fresh image subsequently
passed all seven scenarios: framed prepaid traffic, stock Program and Circle
custody, both two-hop exhaustion directions, legacy-v5 private Single, and the
three-hop Program route. The actual completed collector records 35 passing
local gates. Repeated executions do not increase the logical test count.

After those runtime results, Root's pre-copy check stopped publication before
copying any files. Eight sealed public-code helpers had mode `0400`, while the
packaging verifier had assumed `0444`; the existing repository copies were
`0644`. Their bytes were identical. The five new harness files also had mode
`0400` and retain exact byte-and-mode identity on publication. Neither test
results nor sealed evidence permissions were changed. The successor verifier
checks the eight exact names and hashes in both preparation and verification,
with owner read preserved, no execute bits, and only the recorded public-code
source-access difference. This metadata correction grants no exception for
private inputs, production binaries or other source changes.

The first post-pack evidence reader also refused the original workspace log
because a synthetic attestation fixture wrote binary stderr outside the Circle
test section. Its successor authenticates the entire unchanged raw log and
extracts only the unique, complete Cargo section for `circle_code_parity` before
strict UTF-8 decoding. All thirteen named results, their complete summary,
source and executable predicates remain required. Every other text and JSON
read remains strict. The original broad workspace failure is still recorded as
failed; selecting its independently passing whole target does not erase it or
add test executions.

The added mixed-consensus fixture uses two production Rust validators and two
hosts around the unchanged native consensus and execution libraries. Its first
executed network finalized eight epochs, including a Standard transfer, before
the independent cold-store checker misread ExEx events as byte arrays. Actual
events are `NativeTransaction` objects carrying an exact transaction identity,
transaction bytes, hash, global transaction ID and optional receipt. The
corrected checker requires those bindings and normalizes only the three absent
optional JSON fields omitted by native `Transaction.to_yojson`.

A subsequent checker assertion exposed a second fixture error. The active
proposal and engine header use `octra:tx_list:v1` over concatenated lowercase
hex transaction hashes. The checker had used the separate generic
`octra:tx_list_hash:v1` API over a counted binary list. The corrected independent
checker follows the active header domain in both its native-history and Rust
ExEx paths, retaining exact transaction order and identity checks. Both failed
attempts remain failed. Neither established a production Rust/native mismatch;
the subsequent [mixed-validator checkpoint](../rust-node/checkpoints/2026-10-17/mixed-validators.md)
records sixteen finalized epochs, a clean four-process retained-state restart,
and one Standard transfer on each side of that restart. An independent
read-only supplement checks the captured phase histories because the original
report's pre-restart transfer-list field shared the mutable final list. The
original report remains unchanged and discloses that presentation limitation.
The test uses a shared private genesis and hosts around unchanged native
libraries; its certificate mutation controls run in the independent verifier.
It does not establish stock-launcher or mixed Circle/private-proof parity.

## Reviewed boundaries

Circle initialization is permissionless, idempotent and restricted to code-pinned
terms. All other public methods guard initialization before state/value effects.
Native spawn is deferred: deployment and initialization are separate finalized
transactions. The payment reader requires the exact Circle/factory/code/storage
bindings and active authenticated execution rules. Circle and Program receipt
origins and signed claim opcodes are distinct.

Stock billing occurs on validated decrypted IPv4 packets using the original
remote endpoint and byte length before local address/port translation. Canonical
publication and current machine membership stay guarded through the final
nonblocking handoff. DERP authenticates its source independently of WireGuard;
encrypted relay bytes do not become tariff or delivery evidence. The fixed free
portal cannot expose RPC, wallet execution or arbitrary Circle assets.

The nested client binds all accepted plans, keys, journals, resolved endpoints,
order and MTUs before purchasing. Its hop tasks share an owned route lease.
Cancellation and errors retain blocking routes; deliberate clean shutdown joins
all hops before restoring routes. Purchases are independent and final: a later
hop failure does not refund an earlier purchase.

The final source census rechecked all 1,158 adopted native file hashes. All 940
tracked OCaml sources and interfaces in the active families are inventoried;
all 167 current network/consensus mapping rows match their native hashes and
name existing Rust paths. Historical missing/partial labels were reconciled
against the current implementation rather than counted as new omissions. That
source review did not expose the queue-intake defect subsequently found by the
real Circle RPC run. An inventory and selected control-flow review do not
establish behavioral equivalence for every input, profile or schedule.

## Limits

These are bounded source reviews. The legacy importer trusts an independently
selected local historical authority; it is not a peer-finality verifier or a
protection against an administrator replacing an entire database/schema.

Nested routing is Linux-only. Management endpoint IPs have explicit direct
routes, rather than a per-socket firewall guarantee. The supported no-fragment
profile uses conservative final MTUs of 1075 and 867 bytes for two and three hops;
oversized UDP returns are refused. IPv6 exit delivery, arbitrary Internet
delivery proofs, automated non-delivery slashing, production load, public TLS
provisioning, public paid onboarding and Mainnet launch are separate concerns.
