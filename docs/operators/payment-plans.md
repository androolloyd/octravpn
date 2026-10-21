# Native prepaid payment plans

The `program/octranet-payments.aml` application sells byte allowances before
traffic is carried. Check the [current qualification record](../rust-node/status.md)
separately from earlier postpaid evidence. Existing v5 deployments and stock
Tailscale enrollment do not become prepaid plans by enabling this configuration.

For a new Circle-first deployment, build the custody Circle from the exact
network configuration:

```sh
octra-node compile-circle-payments --config network.json \
  --custody-cap 200000000 --minimum-stake 100000000 > payments-circle.build.json
```

The CLI derives the Circle-specific receipt domain from the configured chain
origin and emits the Circle child and factory bytecode. Deploy through that
factory, wait for finality, call the child's `initialize`, wait for finality
again, then verify both code hashes and terms before accepting value. The
certificate pins source and OCTB hashes; it grants no typed Program admission.
No public compiler or consensus change is needed.

The [Circle custody details](../architecture/circle-prepaid.md) describe its
separate application kind and signed operation domain. Existing Program
deployments remain supported through `compile-legacy` and their own pins.

An operator's BFT node selects `payments` instead of `vpn`:

```json
{
  "payments": {
    "application": {
      "application": "circle",
      "program": "CONFIRMED_PAYMENT_PROGRAM",
      "code_hash": "SHA256_OF_DECODED_PROGRAM_BYTECODE",
      "factory": "CONFIRMED_DEPLOYMENT_FACTORY",
      "factory_code_hash": "SHA256_OF_DECODED_FACTORY_BYTECODE",
      "domain": "CIRCLE_KIND_FULL_CHAIN_ORIGIN_DOMAIN",
      "operator_circle": "PUBLIC_OFFER_CIRCLE",
      "offer": 0
    },
    "ip_tunnel": { "name": "octrapay0" },
    "max_claim_fees_ou": 25000
  }
}
```

A nonvoting observer serving paid VPN traffic adds
`"claim_rpc_url": "https://.../rpc"` under `payments`. It is required for
observer deployments because local observer admission is read-only. The node
signs each exact claim once per durable attempt and sends that signed
transaction to the configured RPC for intake. A successful intake response
does not buy bytes: only the observer's own authenticated canonical state can
advance the purchased-byte floor and permit forwarding. Voting nodes submit
locally and omit this field. The URL must use HTTPS, with loopback HTTP allowed
for isolated tests.

These placeholders must come from one confirmed deployment. The domain is
`vpn::payments::network_domain` over the full chain origin; an RPC hostname does
not establish identity. Operator identity is the actual node wallet. Its stake
must be active and its exact public Circle tariff available at the serving head.
Before creating an offer, the operator must call
`register_operator_receipt_key` with a base64 Ed25519 public key and its
signature over `Octranet operator key v1|DOMAIN|PAYMENT_CIRCLE|OPERATOR|GENERATION`.
The Rust node requires this key to derive the operator wallet address used in
the tariff and signed status. The contract pins it for the whole bond
generation. Retain it durably;
after unstaking or slashing, rebonding requires another registration. Offers
without a pinned key are rejected.

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
construct a JSON accepted plan with these seven fields. A plan can use existing
exit earnings directly; no withdrawal/deposit round trip is needed:

```text
binding: deployment {domain, program}, payer, generation, plan, offer, manifest_hash
tariff: exact canonical tariff JSON (version, operator, classes, selectors)
operator_generation: canonical bond generation pinned by the offer
original_budget_ou: original allocation, including already purchased amounts
prepaid_bytes: explicit cumulative byte purchase target for each tariff class
control_url: operator HTTPS origin, or loopback HTTP for local tests
wireguard_endpoint: operator host:port
```

A private control service may also supply `control_ca_pem`, the PEM-encoded
root certificate explicitly accepted for that HTTPS origin. The client then
trusts only that root for this control connection and still verifies the server
hostname. An invalid, oversized or HTTP-only CA configuration is refused before
journal creation. Omit the field to use the built-in public certificate roots.

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

For a continuously managed single-exit client, add `--reconnect` (and
`--resume` after the first process restart). A transient HTTP refusal or
connection timeout closes the TUN and packet driver, then retries the same
durable plan with a one-to-30-second backoff. Reconnection cannot enlarge the
prepaid byte target or sign a new purchase. A withdrawn plan keeps refusing
traffic; stop the command with Ctrl-C and create a new accepted plan.

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

Stock Tailscale uses the separate [registration-bound payment path](../architecture/stock-paid-exit.md).
Its fixed onboarding portal remains available before a purchase. General Circle
HTTPS and Internet exit traffic require canonical purchased allowance. DNS names
and trusted TLS certificates must be provisioned for the intended deployment.

For two or three paid exits, use [`multi-payments`](../architecture/nested-paid-exits.md).
Every hop has an independently accepted plan, signature, key and journal.
Purchases remain final if a later hop fails. The composite client owns Linux
routing; its MTU and recovery rules differ from the single-interface command.

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

Use the signed Circle-call CLI for a withdrawal, selecting the verified
Circle, RPC, private wallet file and transaction OU limit explicitly:

```sh
octra cast circle send "$PAYMENTS_CIRCLE" withdraw_remaining \
  --key "$WALLET_KEY_FILE" --rpc-url "$OCTRA_RPC" --ou "$TRANSACTION_OU_LIMIT"
```

For a partial withdrawal, call `withdraw_channel` with an integer amount in the
application's smallest OCT units. Verify the confirmed receipt and new payer
generation before creating another plan. Never print wallet-file contents or
infer a confirmed withdrawal from transaction intake alone.
Legacy Program deployments use `octra cast send` with their own deployment and
receipt domain.

A successful payer-signed byte purchase moves its exact charge from the payer's
funds to the offer owner's earnings inside the payment Circle. Merely opening a
connection or viewing a content Circle does not pay that Circle's owner. The
operator can leave earnings in its channel to buy traffic itself, or withdraw
them to its wallet:

```sh
octra cast circle send "$PAYMENTS_CIRCLE" withdraw_earnings "$EARNED_OU" \
  --key "$OPERATOR_KEY_FILE" --rpc-url "$OCTRA_RPC" --ou "$TRANSACTION_OU_LIMIT"
```

Verify the confirmed receipt and new `get_earnings(operator)` value before
accounting for the withdrawal. Purchased bytes are final even if unused; the
protocol takes no commission. The payment Circle now
verifies two contradictory, operator-signed service byte statements for the
same plan/class/sequence and reserves the operator bond for that plan's payer.
The payer calls `withdraw_slash_award(operator, generation)` only after the
original unstake deadline or seven days from a pre-unstake slash.
`octravpn-core::payments::SignedServiceReceipt::slash_params` constructs the
call arguments from verified statements. The paid transport now emits one
statement per class with a durable sequence, and the client retains the latest
verified statement in its private payment journal. If it sees conflicting
totals in one slot, the journal retains both statements in `service_conflict`
and the client stops; extract the pair and verify `slash_params` before calling
`slash_double_service_receipt`. Stop the client, then run
`octravpn service-evidence --journal /private/path/payment-journal` to print
the verified deployment, operator generation and exact Circle call parameters.
This read-only command requires the journal writer lease to be free. The
[public devnet Circle](../rust-node/checkpoints/2026-10-18/devnet-circle-deployment.json)
has a bonded offer and a bounded accounting canary with confirmed operator
earnings withdrawal and payer exit. It has no combined public paid-traffic
qualification. No trustless
proof or slash for arbitrary Internet non-delivery is implemented. Seven-day
unstaking alone cannot insure outstanding delivery obligations. See the
[payment specification](../architecture/octranet-payment-tier.md).

## Embedded clients

`octravpn-client` exposes the same flow as `PaymentClient::open(PaymentOptions)`.
`AcceptedPlan::load` validates the bounded JSON; `client.interface()` reports its
actual name, assigned IPv4 and MTU. `client.run(shutdown).await` accepts a
caller-owned shutdown future and installs no global signal handler or tracing
subscriber. Graceful shutdown stops packet/control tasks and waits for journal
writes. Confirmed counters describe local IO; purchased capacity describes paid
authority. Neither is a proof of destination delivery.
