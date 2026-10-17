# Octranet onboarding and payment tier

This is the implementation target agreed on 2026-10-17. It supersedes the
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
rates are immutable for an opened plan. Repricing creates another offer and
requires another accepted plan. All traffic payments go to the operator; the
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

Payment accounts reserve explicit budgets for operator plans. Opening another
plan cannot spend an already reserved budget. Operators submit client-authorized
cumulative receipts against their own plan and its immutable tariff. A
successful claim transfers only the new increment from the payer's held
balance to that operator's earnings. Pending, malformed, replayed or excessive
claims transfer nothing. Claims bind the deployment domain, program, account
generation, plan, class, sequence and cumulative usage.

Disconnecting is immediate. Requesting exit from the payment tier stops new
paid admission and starts exactly 86,400,000 milliseconds of settlement time,
measured by the canonical epoch timestamp. Authorized claims may succeed
strictly before that deadline. Neither a claim nor a retry extends it. At and
after the deadline claims are refused, and the user can withdraw the remaining
balance. Successful claims reduce that balance; unresolved claims do not keep
it locked. Rejoining starts another generation, so old authorizations cannot
consume new funds. A chain halt still prevents all chain transactions.

Operator stake has a separate fixed seven-day unstake period: 604,800,000
canonical milliseconds from the operator's first unstake request. That request
immediately stops new plans and paid admission for the operator. Repeated
requests leave the original deadline intact; top-ups cannot bypass an ongoing
unstake. Already authorized usage claims remain redeemable strictly before the
earlier of the payer's exit deadline and 24 hours after the operator stopped.
The payer can then release any unused plan reservation. Offers bind an operator
generation, so rebonding cannot revive old plans or claim windows. At the
seven-day boundary the operator can withdraw its
stake. Operator earnings and payer balances are separate liabilities; neither
withdrawal spends the other's funds. The custody cap includes operator stake.
This application does not invent an unverified automatic slashing mechanism.

Custody logic belongs in the application. The adopted AML runtime already
offers signature verification and Program `epoch_time`; Circle compilation
currently refuses `epoch_time`. Use that existing Program capability for the
timed payment application and Circles for portal and offer assets. Any future
Circle clock capability needs a separately specified experimental fork; do not
change the adopted consensus rules to make this application compile.

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
advances an on-chain withdrawal deadline.

`octravpn-node::payment_meter` reserves a shared lifetime budget durably before
forwarding. Confirmed sends become committed counters. An unresolved send holds
uncertain capacity without becoming billable; only explicit cancellation of a
definitely unsent packet releases its reservation. The host must keep one meter
per plan and preserve its journal across reconnects and restarts. Packet-level
fsync is a correctness baseline, with no throughput qualification yet.

The gateway's [portal capability](../operators/unpaid-portal.md) limits unpaid
reads to explicitly selected passive assets in one Circle. It does not confer
device enrollment, general DNS/DERP access or paid forwarding. These components
still need a connected native admission, client and settlement path before the
new application can accept alpha traffic.

## Qualification

Before an alpha launch, exercise the actual compiled AML, node admission,
client metering and kernel forwarding together. Include unfunded portal use,
denied unpaid web access, distinct class rates, agreement before repricing,
budget exhaustion, claim replay, concurrent claims, just-before/at/after the
24-hour boundary, remainder withdrawal, rejoin, crash recovery and a suspended
canonical node. Formal accounting and deadline models must identify their link
to the AML source and their limits; model proofs alone do not qualify the VM.

An LLM must be able to follow repository instructions and machine-readable CLI
results from a clean checkout through a real connection. It must distinguish
device enrollment, portal availability, funding and paid forwarding. Private
keys stay in private local files. A Mainnet alpha uses an explicit capped
deployment candidate and verified network identity; local fixtures and public
RPC compilation are not substitutes for stateful qualification.
