# Native payment-plan candidate

This opt-in path uses `program/octranet-payments.aml`. It has not passed the
combined kernel/public-network launch gates. Existing v5 deployments and stock
Tailscale enrollment do not become paid plans by enabling this configuration.

An operator's BFT node configuration selects `payments` instead of `vpn`:

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
    "credit": {
      "max_unacknowledged_bytes": 262144,
      "max_unacknowledged_ou": 100000
    },
    "max_claim_fees_ou": 25000
  }
}
```

These are placeholders, not a deployable network configuration. Obtain the
application addresses, bytecode pins, domain and offer from the same confirmed
deployment. Domain derivation is `vpn::payments::network_domain` over the full
chain origin; an RPC hostname does not establish identity. Retain a stable
checkpoint origin for all nodes using that deployment. Operator identity is the
node's actual wallet key. Program stake must be active, and its public Circle
tariff must resolve at the serving canonical head.

The credit values above illustrate operator risk limits, not recommended prices.
Both limits are mandatory and immutable for the transport directory. They bound
unacknowledged traffic across classes, connections and restart. A client can
refuse its final receipt; escrow alone cannot force a signature. Zero credit
denies traffic. This path waits for canonical charge coverage before restoring
credit; an already paid rounding interval or zero-rate class needs no redundant
transaction. The separate `max_claim_fees_ou` bounds lifetime relayer spending
for this claim directory, including signed attempts with ambiguous outcomes.
Restarting cannot reset it; zero disables new fee spending. Consider transaction
fees and confirmation latency when choosing prices and credit. The protocol
takes no commission.

Keep `octranet-payments/transport`, its address book, and
`octranet-payments/claims` private and durable. Do not delete or replace them to
recover a failed session. Missing journals or writer leases fail closed.
The native host controls admission; an RPC, discovery entry or signed operator
status cannot substitute for its canonical state.

After the payer has registered its receipt key, funded its account and opened a
confirmed plan, construct an accepted plan file from those confirmed facts:

```text
binding: deployment {domain, program}, payer, generation, plan, offer, manifest_hash
tariff: the exact accepted canonical tariff JSON (version, operator, classes, selectors)
original_budget_ou: the original allocation, including already redeemed amounts
control_url: the operator's HTTPS origin, or loopback HTTP during local tests
wireguard_endpoint: the operator's host:port
```

The file is a JSON object with those five fields. Use canonical native address
strings. It contains no secret material. The receipt key remains in a separate
private file:

```sh
octravpn payments --plan accepted-plan.json --receipt-key /private/path/receipt.key \
  --journal /private/path/plan-journal --tun-name octrapay0
```

`--resume` requires the original intact journal. A fresh invocation refuses an
existing directory. The journal binds the original budget, tariff, key and plan;
reconnecting cannot reset usage or change price. The client authenticates the
operator status and signs only cumulative counts bounded by its own confirmed
handoffs. The status signature authenticates the operator; it is not a finality
proof. A trusted confirmed-state onboarding flow must supply the plan file.

TUN access requires host privileges. This command prints the assigned interface
and address; explicit routing/NAT provisioning remains a host task. Do not route
the operator's own control or WireGuard endpoint into its tunnel. The command
does not change an existing Tailscale connection or install a default route.

Requesting payer exit stops forwarding and starts a fixed 24-hour claim window.
Requesting operator unstake stops forwarding and starts a separate fixed
seven-day stake hold. Retrying either request cannot extend its deadline.
The full [payment specification](../architecture/octranet-payment-tier.md)
records the canonical time, generation and recovery boundaries.
