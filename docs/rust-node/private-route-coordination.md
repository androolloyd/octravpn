# Private route coordination boundary

This integration is required and is not implemented by the pre-funded
`MultiPrivatePaymentClient` API. The ordered controller candidate now composes
the native purchase runner with the shared route supervisor. Its experimental
node, protocol and client all-targets build and strict checks pass. Combined
kernel execution and cold restart recovery remain unqualified.

1. Persist every hop's finite purchase consent before making an operator request.
   Bind its target pool/directory, tariff, cap, operator generation, receipt key,
   lifetime and fee policy. Each pool remains independently accepted. Mark the
   purchases as route-owned before any channel binding exists, so restarting
   the standalone scheduler cannot start a partially prepared route.
2. Confirm the entry purchase before arming the global route blockers. This
   bootstrap may use the local node's ordinary authenticated chain access.
3. Open the entry and route downstream control through it. Run each downstream
   native purchase only after its preceding paid carrier is ready. A signed
   operator reply cannot substitute for canonical payment confirmation.
4. Keep the client's local node syncing during that process. Its trusted chain
   sockets need a separate owned routing policy through the paid entry; ordinary
   application traffic must stay blocked until the complete route is ready.
   Operator control sockets must follow the ordered paid prefix. The candidate
   binds native P2P sockets to the entry interface and uses a separate Linux
   routing table for those sockets. Bound mode accepts literal IPv4 peers or
   explicit hostname pins without host DNS or direct fallback. A scope change
   acknowledges only after old owned sessions stop. Kernel qualification of
   this policy is still required.
5. Persist the authenticated channel binding once returned by each operator.
   Commit the child journal's creation phase before network admission. Resume
   must distinguish a journal never created from missing previously admitted
   state; it must never reset connection counters or buy again.
6. Activate general traffic only after all hops are funded and live. Cancellation
   retains blockers, signed envelopes and finite consent for exact recovery.

One custody book can use its existing operator views and shared nonce/fee
journal. Independent pools cannot silently share a relayer without a common
durable nonce reservation authority; separate relayers or that authority must
be explicit. Operator income attachment must retain exclusive note assignment
and cannot create new purchase consent.

The native [payer scheduler candidate](private-payer-routing.md) now provides
paused same-book operator groups, complete-target discovery, pinned control and
explicit operator-income attachment. It supplies primitives for this coordinator;
it does not yet own the ordered route or its phase journal.

The native purchase/client bridge now exposes a nonfinancial `Purchase::open`.
After its authenticated binding is available, `prepare_client(Transport)` creates
the encrypted child journal offline and commits its immutable transport to the
payer book before the first quote. It derives the receipt identity from that
purchase and checks the accepted target, tariff and exact finite byte caps.
Resume uses only the recorded path, interface, TLS trust and optional hop pins;
missing or incomplete state is refused. Preparation creates no UDP socket, TUN,
route or payment. A partial first creation can leave an unadmitted orphan that
must be investigated, rather than adopted or reset automatically.

The returned prepared purchase checks its held child journal before advancing
native payment. Its admission needs a canonical credited step in this process
and a fresh private meter check. Standalone `Purchase::step`, including the payer
scheduler, refuses a client-owned phase so it cannot bypass those checks after
restart. These per-purchase phases alone do not implement the global route
intent, ordered supervisor or chain routing policy, and do not qualify funded
private multihop transport.

`payer::runner::route::Route::{create,resume}` now records the complete finite
route intent in the entry custody book. It validates every accepted endpoint,
TLS key, tariff, cap, interface and journal path before writing. Each new job
and its route ownership are committed atomically in its own book. Ownership is
also embedded in the encrypted job, so a missing marker cannot turn that job
into standalone consent. Separate books require distinct relayers; shared
custody retains one relayer and the same fee policy.

Single-hop client preparation likewise commits the client-phase digest into
the original purchase in the same transaction as its phase record. A missing
phase cannot become an unmanaged purchase or a fresh client journal. Existing
complete phases can acquire this digest only after their original encrypted
child journal resumes successfully.

Creation requires fresh job identities. Resume requires the existing complete
intent and exact original inputs. Interrupted first initialization may finish
only its never-started missing jobs. Once initialization is complete, missing
intent, ownership or job records are errors and are not reconstructed. The
returned record holds the original custody leases and offers an explicit
consistency check. Initialization itself makes no purchase or connection.

The controller reserves and checks the route namespace before entry funding.
After canonical entry credit, it records the armed phase, pauses existing chain
sockets, installs blockers and opens the entry. The local node then resumes P2P
through that paid entry while downstream native purchases and transport follow
their preceding carrier. General traffic activates only after all hops are live.
Existing credit revalidation checks the exact confirmed native quote and output;
it cannot quote, sign or submit another purchase. Ordinary revalidation retains
the existing node freshness and quarantine requirements.

The [startup and recovery candidate](private-route-recovery.md) now restores the
armed phase as paused before P2P starts and runs its controller alongside node
initialization. An entry-only retained execution proof can reauthenticate
already settled capacity without publishing a fresh chain view; new spending
still requires fresh canonical state. Cold process recovery and the retained
kernel plan still need combined qualification. Neither behavior is qualified by
compilation or the earlier consent tests.

The [phase checkpoint](checkpoints/2026-10-20/private-route-phases.json) records
69 release payment tests, 378 client tests, four benchmark checks and strict
checks. Both exact Linux private-payment/tunnel regression cases passed with
verified cleanup. The new phase is exercised through canonical payment and
authenticated admission for the second purchase; the existing first-purchase
client carries the kernel payload. Full coordinator and chain-policy execution
remain separate acceptance gates.

Acceptance needs actual native execution and signed QCs, not fabricated private
status. The multi-operator kernel fixture must observe downstream purchase,
quote, credit and transport connections only through their paid predecessor;
keep authenticated node sync alive with ordinary traffic blocked; then exercise
traffic, exhaustion, carrier loss and restart. Native payments, private wallet
and route journals, operator counters, canonical history and ExEx must agree
after recovery. The pre-funded single-hop result and the public-payment route
matrix qualify their own paths and do not replace this gate.

The current native purchase job selects one traffic class. A route offering
several priced classes on one hop also needs coordinated class purchases for
that same channel and receipt identity; separate independently opened channels
do not establish that behavior.
