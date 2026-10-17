# Native prepaid payment plans

The staged `program/octranet-payments.aml` revision sells byte allowances before
traffic is carried. Its new qualification record must be checked separately
from earlier postpaid evidence. Existing v5 deployments and stock Tailscale
enrollment do not become prepaid plans by enabling this configuration.

Build the application locally:

```sh
octra-node compile-legacy --source program/octranet-payments.aml --loops --point-ops > payments.build.json
```

This uses the existing Legacy binary VM. The adopted typed Program profile
excludes Ed25519, while this source needs Program `epoch_time`. The certificate
pins source and OCTB hashes; it grants no typed Program admission. Deploy its
`bytecode` through the deployment-only factory and verify the exact stored hash.
The flags select local emitter capabilities, not public network activation.
No public compiler or consensus change is needed.

An operator's BFT node selects `payments` instead of `vpn`:

```json
{
  "payments": {
    "application": {
      "program": "CONFIRMED_PAYMENT_PROGRAM",
      "code_hash": "SHA256_OF_DECODED_PROGRAM_BYTECODE",
      "factory": "CONFIRMED_DEPLOYMENT_FACTORY",
      "factory_code_hash": "SHA256_OF_DECODED_FACTORY_BYTECODE",
      "domain": "FULL_CHAIN_ORIGIN_PAYMENT_DOMAIN",
      "operator_circle": "PUBLIC_OFFER_CIRCLE",
      "offer": 0
    },
    "ip_tunnel": { "name": "octrapay0" },
    "max_claim_fees_ou": 25000
  }
}
```

These placeholders must come from one confirmed deployment. The domain is
`vpn::payments::network_domain` over the full chain origin; an RPC hostname does
not establish identity. Operator identity is the actual node wallet. Its stake
must be active and its exact public Circle tariff available at the serving head.

There is no operator credit window. Escrow and a purchase signature alone grant
no traffic. The native service waits for the exact cumulative byte purchase in
authenticated canonical state, then forwards within each class's allowance.
Even a zero-rate class requires an explicit finite purchase. Exhaustion pauses
traffic; operator reports never trigger automatic extra purchases.

`max_claim_fees_ou` caps lifetime relayer spending for the claim directory,
including signed attempts with ambiguous outcomes. Restarting cannot reset it;
zero disables new fee spending. Choose package sizes and rates with transaction
fees and confirmation latency in mind. The protocol takes no commission.

Keep `octranet-payments/transport`, its address book and
`octranet-payments/claims` private and durable. Missing journals or writer leases
fail closed. Do not discard counters to regain allowance. The host controls
canonical admission; an RPC response or operator status signature cannot replace
that state. The claim journal retains the exact authenticated tariff for retries
after its Circle asset expires; this never grants forwarding from an expired
asset. Program pins, keys, budgets, classes and deadlines are rechecked.

After registering the receipt key and opening a funded, confirmed plan,
construct a JSON accepted plan with these six fields. A plan can use existing
exit earnings directly; no withdrawal/deposit round trip is needed:

```text
binding: deployment {domain, program}, payer, generation, plan, offer, manifest_hash
tariff: exact canonical tariff JSON (version, operator, classes, selectors)
original_budget_ou: original allocation, including already purchased amounts
prepaid_bytes: explicit cumulative byte purchase target for each tariff class
control_url: operator HTTPS origin, or loopback HTTP for local tests
wireguard_endpoint: operator host:port
```

`prepaid_bytes` has exactly one entry per class; their cumulative tariff cost
must fit the original budget. For example, `[1048576, 0]` buys one MiB of the
first class and none of the second. The targets are fixed for this journal and
run. No implicit top-up or postpaid plan fallback exists. Use canonical native
address strings and keep the receipt key in its own private file:

```sh
octravpn payments --plan accepted-plan.json --receipt-key /private/path/receipt.key \
  --journal /private/path/plan-journal --tun-name octrapay0
```

A fresh invocation refuses an existing journal. `--resume` requires the original
intact journal, binding budget, tariff, key, plan and purchase targets. The client
persists exact purchase signatures before sending them and retries those same
authorizations after lost responses. It waits for purchase confirmation before
opening the traffic interface. Old postpaid journals are rejected.

Packet reservations are durable before handoff. Confirmed, pending and uncertain
bytes consume the prepaid allowance; neither reconnect nor process death resets
it. An uncertain handoff does not prove destination delivery or authorize another
purchase. The operator's signed status authenticates its assertions, not public
chain finality. Independently authenticated deployment and plan facts remain
necessary; fully trustless onboarding/finality still requires qualification.

TUN access requires host privileges. The command prints the actual interface
and address. Provision routes and NAT explicitly, keeping control and WireGuard
endpoints outside their own tunnel. The client installs no default route and
does not modify an existing Tailscale connection.

`get_channel_balance(account)` reports remaining channel funds plus exit
earnings, excluding operator stake. Opening a plan automatically moves only the
needed earnings into its funding allocation. Earned OCT can therefore pay for
your own traffic in the same application.

`withdraw_remaining()` returns all available channel OCT immediately and closes
the account. It needs no prior exit request or payer waiting period.
`withdraw_channel(amount)` withdraws part of the balance, advances the account
generation and cancels all its old plan reservations. Both operations invalidate
unsettled old purchase authorizations before transferring funds. Construct a
fresh accepted plan after a partial withdrawal; do not reuse its old journal.
Full or partial channel withdrawal stops all old paid connections, including
their unused purchased allowance; it does not refund those final purchases.
An optional `request_exit()` stops paid admission immediately without imposing
a withdrawal hold. Settled purchases remain final whichever operation is used.

An operator seals a replacement created with
`create_rate_change(parent_offer, manifest_hash)`. Its rates activate after a
full 24-hour notice period. Old-rate purchases stop at that boundary; existing
paid bytes retain their original allowance. A superseded pending quote is
cancelled permanently. The configured native `application.offer` is the lineage
root, while each accepted plan names its exact actual offer and manifest.
The client never accepts replacement rates automatically.

Operator unstaking stops forwarding and holds stake for seven days from the
first request. Retries cannot extend that deadline. Releasing a stopped plan's
unspent reservation needs no 24-hour hold.

Use the existing signed-transaction CLI for a withdrawal, selecting the verified
deployment, RPC, private wallet file and transaction OU limit explicitly:

```sh
octra cast send "$PAYMENTS_PROGRAM" withdraw_remaining \
  --key "$WALLET_KEY_FILE" --rpc-url "$OCTRA_RPC" --fee "$TRANSACTION_OU_LIMIT"
```

For a partial withdrawal, call `withdraw_channel` with an integer amount in the
application's smallest OCT units. Verify the confirmed receipt and new payer
generation before creating another plan. Never print wallet-file contents or
infer a confirmed withdrawal from transaction intake alone.

A successful purchase credits withdrawable operator earnings immediately. It is
not a refundable escrow for unused purchased bytes. No trustless proof or slash
for arbitrary Internet non-delivery is implemented. Seven-day unstaking alone
cannot insure outstanding delivery obligations. A product promising insured
delivery would additionally need an objectively verifiable breach predicate and
compensation rules. See the
[payment specification](../architecture/octranet-payment-tier.md).

## Embedded clients

`octravpn-client` exposes the same flow as `PaymentClient::open(PaymentOptions)`.
`AcceptedPlan::load` validates the bounded JSON; `client.interface()` reports its
actual name, assigned IPv4 and MTU. `client.run(shutdown).await` accepts a
caller-owned shutdown future and installs no global signal handler or tracing
subscriber. Graceful shutdown stops packet/control tasks and waits for journal
writes. Confirmed counters describe local IO; purchased capacity describes paid
authority. Neither is a proof of destination delivery.
