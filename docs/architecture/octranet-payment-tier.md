# Octranet onboarding and payment tier

This is the prepaid implementation target revised on 2026-10-17. It supersedes the
assumption that joining a stock Tailscale mesh opens a paid traffic session.
The existing v5 deployments and their recorded tests remain separate.

## Access and pricing

An unfunded device can reach a bounded Circle portal for joining, funding,
balances, connection status and operator offers. The portal exemption does not
grant a general proxy, arbitrary DNS forwarding, arbitrary Circle hosting,
an exit route or unrestricted DERP carriage. Stock Tailscale enrollment is a
device identity, not a payment authorization.

Operators choose their prices, including zero. Offers contain a default rate
and named traffic classes; for example, a premium class for a specified set of
Hyperliquid destinations. The selected offer, selectors, counting rules and
rates are immutable for an opened plan. A replacement rate becomes available
after a full 24-hour notice period and requires another accepted purchase.
All traffic payments go to the operator; the
protocol has no commission. Ordinary Octra transaction fees are separate.

Classification must use facts the forwarding path can enforce: destination
prefixes and ports, or an explicit service proxy/egress capability. A label such
as "Hyperliquid" does not prove which application generated encrypted traffic.
Shared CDN addresses, encrypted DNS, ECH and nested VPNs prevent reliable
arbitrary application detection. Do not decrypt HTTPS or promise otherwise.
Unmatched traffic uses the advertised default class, never the portal exemption.

The client and operator count the same forwarded IP octets in both directions.
Class counters are cumulative, checked for overflow and bound to the accepted
offer. Charge is cumulative per class, rounded up once to the smallest OCT unit;
small packets or reconnects must not create a fresh free MiB. A packet that
cannot be classified safely is refused. The funding budget is checked before
forwarding, including return traffic.

## Custody and claims

The channel holds OCT that can pay for traffic or be withdrawn. Its balance is
the account's remaining funds plus its exit earnings; operator stake is separate.
Opening a plan automatically reuses enough earned OCT to cover any funding
shortfall, without an external withdrawal and deposit. This is internal balance
netting, not a protocol commission or an operator credit line. Every purchase
still records its full charge and payee.

Payment accounts reserve explicit budgets for operator plans. Opening another
plan cannot spend an already reserved budget. The payer signs an explicit
cumulative byte purchase per class before any traffic. An ordinary `claim`
settles that purchase on chain, moving only the new tariff increment from held
funds to operator earnings. The forwarding path then consumes the canonically
purchased byte allowance. Funding escrow, signing an authorization or submitting
a transaction is insufficient by itself. With no purchase there is no paid
traffic, and exhaustion pauses traffic without increasing the purchase.

For each class the cumulative price is `ceil(bytes * rate_ou_per_mib / 1048576)`
in the smallest OCT unit. Only the difference from the previous cumulative
price is charged. Claims bind the deployment domain, program, payer generation,
plan, immutable offer/manifest, class, sequence and cumulative purchased bytes.
The new signature tag is `Octranet prepaid v1`; old postpaid signatures cannot
buy bytes under this revision. Replays and over-budget claims move no value.

`withdraw_remaining` immediately returns the channel's available OCT and closes
the account; no prior exit request or payer withdrawal delay is required.
`withdraw_channel(amount)` withdraws part of the balance and keeps the account
open. It advances the payer generation and clears all old reservations, so
old plans and held purchase signatures cannot claim against the remainder.
Previously reserved but unspent OCT is withdrawable through these operations.
Both operations stop the old plan connections; any unused purchased allowance
on those plans is not refunded.
An optional `request_exit` stops admission immediately and imposes no hold.

The canonical transaction order decides a purchase/withdrawal race. A purchase
that settles first remains final and reduces the withdrawable balance. A
withdrawal that settles first invalidates the old purchase authorization.
Forwarding waits for canonical purchase settlement, so the operator never
extends credit against a signature that the payer can later invalidate.
Rejoining uses another generation. A chain halt still prevents withdrawals and
other chain transactions; immediate means no application waiting period.

Operator stake has a separate fixed seven-day unstake period: 604,800,000
canonical milliseconds from the operator's first unstake request. That request
immediately stops new plans and paid admission for the operator. Repeated
requests leave the original deadline intact; top-ups cannot bypass an ongoing
unstake. New purchases stop immediately, including held signatures. The payer
can release an unused stopped-plan reservation immediately.
Offers bind an operator
generation, so rebonding cannot revive old plans or claim windows. At the
seven-day boundary the operator can withdraw its
stake. Traffic earnings are available to their owner for withdrawal or traffic
purchases; no account can spend another account's balance. The custody cap
includes operator stake.
This application does not invent an unverified automatic slashing mechanism.

## Rate changes

An initial offer is usable when sealed. `create_rate_change(parent, manifest)`
creates an immutable replacement in that offer's lineage. Sealing the replacement
publishes its full manifest and rates and sets activation to canonical
`epoch_time + 86400000`. Before that boundary only the parent sells new bytes;
at the boundary only the replacement does. Already purchased bytes retain their
original price and allowance after the old quote retires.

Replacing a pending change restarts the full notice period and permanently
cancels the superseded quote. An operator may also cancel a pending change
before activation. Neither operation can reactivate an old quote later or
apply a price change retroactively. Independent offers remain separate products
that require their own explicit payer consent.

The native service's configured offer identifies the lineage root. Each actual
plan still binds its precise offer, tariff hash and generation. A new price
cannot silently replace those facts or create another client authorization.
The current client accepts finite purchase targets; it does not auto-renew,
automatically accept future rates or implement a collateral-backed PAYG mode.

Custody logic belongs in the application. The adopted AML runtime already
offers signature verification and Program `epoch_time`; Circle compilation
currently refuses `epoch_time`. Use that existing Program capability for the
timed payment application and Circles for portal and offer assets. Any future
Circle clock capability needs a separately specified experimental fork; do not
change the adopted consensus rules to make this application compile.

The adopted typed Program flow profile does not accept Ed25519 instructions.
The local `compile-legacy` tool therefore emits this Program source as raw OCTB
for the factory's existing binary child path. Source syntax enables canonical
time emission; it does not grant typed Program admission. The v1 build
certificate is reproducibility evidence only. Binary execution has embedded
integer guards but lacks typed ABI/storage enforcement; native plan admission
independently validates canonical state. No consensus/compiler rule is changed.

## Native boundaries

`octravpn-core::payments` defines the exact receipt message, immutable Circle
tariff and aggregate class budget. Classification uses observable remote IP,
protocol and port; it does not identify encrypted applications. The packet
helper currently accepts validated IPv4 traffic.

`octra-node::vpn::payments` checks application and factory bytecode pins,
network origin, actual custody, generations, the authenticated epoch clock and
the canonical Circle tariff. Its returned plan has immutable bound facts and a
revocable lease. A stopped node cannot renew that lease indefinitely from the
same retained head. The local lease clock limits service availability; it never
advances an on-chain rate activation or operator unstake deadline.

`octravpn-node::payment_meter` reserves a shared lifetime budget durably before
forwarding. Confirmed sends become committed counters. An unresolved send holds
uncertain capacity without becoming billable; only explicit cancellation of a
definitely unsent packet releases its reservation. The host must keep one meter
per plan and preserve its journal across reconnects and restarts. Packet-level
fsync is a correctness baseline, with no throughput qualification yet.

The opt-in `payments` node has no credit configuration or unlimited fallback.
Its meter separates actual consumed/pending/uncertain bytes from canonical
purchased capacity. Each packet reservation must fit the purchased allowance
of its own class, including zero-rate classes. Same-price rounding does not
permit an unrecorded extra purchase: the exact canonical byte floor is required.
A fully spent monetary budget can still have purchased bytes left to consume.
A separate immutable lifetime claim-fee budget bounds transaction spending,
including failed or ambiguous attempts. Larger prepaid batches amortize fees.
Old postpaid journals are rejected instead of reinterpreted.

Receipt-key-signed connection requests bind the complete plan and a monotonic
connection sequence to the client's WireGuard key. Rotation suspends the old
capability before its durable watermark changes. The current native publication
guard encloses the actual nonblocking kernel or UDP handoff. Confirmed raw IP
bytes consume prepaid capacity. Paid payloads never enter boringtun's opaque rekey queue:
an absent current session starts only the control handshake and drops the
unsent raw packet without charging it. Ambiguous sends retain uncertain
capacity. This favors custody safety when delivery cannot be established.

The client `payments` command consumes a locally accepted plan file, an explicit
receipt-key file and a persistent journal. It verifies the offer operator's
status signature, manifest, budget, connection sequence and both WireGuard
keys. That signature authenticates the operator, not chain finality. The plan
file must be obtained from confirmed state by the onboarding flow. Automatic
funding, route installation and stock Tailscale payment signing are not implied
by this command. The client requires explicit finite `prepaid_bytes` targets by class and persists
their exact purchase signatures before submission. Its traffic interface opens
only after purchase confirmation. Operator counters cannot cause another
purchase. Its immutable targets, original budget and consumed/uncertain bytes
survive reconnects; resume refuses missing, corrupt or old postpaid state.

The gateway's [portal capability](../operators/unpaid-portal.md) limits unpaid
reads to explicitly selected passive assets in one Circle. It does not confer
device enrollment, general DNS/DERP access or paid forwarding. The new native
payment path still requires combined kernel, recovery and public qualification
before the application can accept alpha traffic.

## Trustless delivery boundary

A prepaid signature proves spending consent, not delivery. An operator that
drops a packet and an operator that forwards correctly before the client,
router or destination drops the reply can leave identical chain evidence.
Payer-controlled timeouts or withheld acknowledgments cannot distinguish them.
No arbitrary Web non-delivery proof or slashing state machine exists here.

A successful purchase immediately credits operator earnings, available for
withdrawal or further traffic purchases. Payer withdrawal returns only OCT
still in the channel; settled byte purchases are final, including unused
purchased bytes. Seven-day operator unstaking does not insure future delivery.
This prepaid product does not implement refundable delivery insurance.

Signed conflicting obligations or a missed on-chain response deadline could
support narrower objective penalties after that service obligation is specified.
A chain-response promise does not itself prove general Internet availability.
There is no trusted arbiter or witness voting fallback. A launch advertised as
trustless non-delivery protection is blocked on a verifiable service predicate.

## Qualification

Before an alpha launch, exercise the actual compiled AML, node admission,
client metering and kernel forwarding together. Include unfunded portal use,
denied unpaid web access, distinct class rates, agreement before repricing,
budget exhaustion, claim replay, concurrent claims, just-before/at/after the
24-hour rate boundary, immediate full/partial withdrawal, withdrawal/claim races,
earnings reuse, rejoin, crash recovery and a suspended
canonical node. Formal accounting and deadline models must identify their link
to the AML source and their limits; model proofs alone do not qualify the VM.

An LLM must be able to follow repository instructions and machine-readable CLI
results from a clean checkout through a real connection. It must distinguish
device enrollment, portal availability, funding and paid forwarding. Private
keys stay in private local files. A Mainnet alpha uses an explicit capped
deployment candidate and verified network identity; local fixtures and public
RPC compilation are not substitutes for stateful qualification.
