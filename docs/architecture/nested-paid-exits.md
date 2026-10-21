# Nested prepaid exits

The client can carry one paid connection through another operator's paid exit.
Every operator has its own accepted plan, receipt key, finite purchase and durable
journal. The entry operator charges for encrypted UDP carriage to the next
operator; the final operator charges for traffic to its destination. The protocol
takes no commission. This composes existing sessions without changing consensus
or enabling unauthenticated raw forwarding.

## Accept and start a route

Use Linux with `/dev/net/tun`, `iproute2` and the privileges needed to manage TUN
interfaces and routes. Obtain and independently verify each accepted plan using
the [payment guide](../operators/payment-plans.md). For the entry's tariff, check
the class and price covering the next operator's WireGuard endpoint. Accept a
finite byte limit at every hop. Purchases are final; a later hop failing does not
refund an earlier purchase.

Create a route JSON file with these fields:

```text
{
  "journal": "route-journal",
  "payment_privacy": "public",
  "bootstrap_privacy": "pinned_ips",
  "hops": [
    {
      "plan": <complete accepted entry-plan JSON object>,
      "journal": "entry-journal",
      "receipt_key": "/private/path/entry-receipt.key",
      "wireguard_pin": "ENTRY_PUBLIC_IPV4:WG_PORT",
      "control_pin": "ENTRY_PUBLIC_IPV4:HTTPS_PORT",
      "interface_name": "octra-entry"
    },
    {
      "plan": <complete accepted exit-plan JSON object>,
      "journal": "exit-journal",
      "receipt_key": "/private/path/exit-receipt.key",
      "wireguard_pin": "EXIT_PUBLIC_IPV4:WG_PORT",
      "control_pin": "EXIT_PUBLIC_IPV4:HTTPS_PORT",
      "interface_name": "octra-exit"
    }
  ]
}
```

Embed each plan object rather than its filename. Relative journal and key paths
resolve against the route file's directory; existing parent directories must be
present. Keys, sessions, journal directories and interface names must be distinct.
The same format accepts a third hop. Start with fresh journals:

```sh
octravpn multi-payments --route /absolute/path/accepted-route.json
```

The client pins control and WireGuard addresses, rejects overlapping endpoints
and incompatible host policy, installs blockers and prepares every journal before
requesting purchases. It then authenticates hops in order. Keep the process
running. Ctrl-C requests a clean shutdown that joins every hop before removing
its owned route lease. The Rust library exposes the same lifecycle through
`MultiPaymentClient`, `MultiPaymentOptions` and `MultiRoutePlan`.

The current Circle records payer, plan, and purchase data publicly. The optional
`payment_privacy` field defaults to `public` for older files. Setting it to
`shielded_required` refuses the route before loading a key or opening a journal;
it never silently downgrades to public payment. Shielded settlement is a future
chain/Circle integration, not a property of this prepaid route.
`bootstrap_privacy: "pinned_ips"` requires both accepted IP:port pins for every
hop, skips operator hostname DNS lookups, and checks the ports and literal-IP
origins against their accepted plans. Obtain the pins through an authenticated
source; the later TLS and WireGuard handshakes still authenticate the operator.
The default `system_dns` resolves operator names before arming the route.

## Recovery and limits

An error, cancelled future or process death retains blocking routes. Preserve the
route file, all keys and every journal. Resume uses the exact original consent:

```sh
octravpn multi-payments --route /absolute/path/accepted-route.json --resume
```

Before a crash resume, deliberately recover the retained host lease. Confirm no
client owns `/run/octravpn-paid-exit.lock`; inspect both address families with
`ip -j rule show`, `ip -j route show table 186` and `ip -j route show proto 186`.
Remove only the rules and routes verified against this exact interrupted route,
including its priority-1 policy rules. Do not flush a routing table or numeric
protocol tag. Foreign policy, interfaces or retained leases cause refusal.

Only entry peer and control IPs are direct-route exceptions. The downstream
peer and non-loopback control IPs are blackholed until the preceding paid tunnel
is ready, then both follow that tunnel. Control requests use HTTPS outside local
tests. This is not a per-socket firewall guarantee; resolving a hostname before
the route is armed can still disclose that operator hostname to the configured
DNS resolver. Personal `100.64.0.0/10` traffic follows existing host policy.
Downstream endpoint blackholes prevent a broken carrier from falling back to the
ordinary Internet route. IPv6 exit traffic is captured and refused.
The no-fragment profile uses final MTUs of 1075 bytes for two hops and 867 for
three, allowing standard WireGuard padding. Oversized UDP is refused; arbitrary
path-MTU recovery or delivery is not promised. Exhaustion never triggers a top-up.

The final qualification checkpoint records executed combinations. Support for a
three-hop route in source does not establish a three-hop kernel test result, and
local testing does not qualify public paid onboarding or Mainnet.

## Routed private-control qualification

The two-hop gate accepts `--application circle --private-control`. This deploys
real Circle custody on four local validators and uses separate operator TLS
identities under a fresh offline CA. Each accepted plan carries its root in
`control_ca_pem`; all operator hostnames end in `.invalid` and resolve only via
the route's accepted IP pins. The client firewall rejects physical downstream
traffic and DNS. A direct-connect negative control must increment that firewall,
then all counters must remain zero during the real run. A wrong server hostname
must fail before any purchase. The exit's TLS listener must see only the entry
carrier's source address. Existing traffic, MTU, restart, exhaustion, withdrawal
and four-sink ExEx checks still apply.

```sh
python3 docker/native-vpn/multi_run.py \
  --node-image <source-bound-native-vpn-image> \
  --context /absolute/path/to/frozen/context \
  --headscale-commit <exact-root-lock-commit> \
  --application circle --private-control --exhaust-hop 1 \
  --out /absolute/path/to/fresh-evidence
```

Run each exhaustion direction separately. These checks exercise encrypted
control transport and public prepaid payments; they do not establish shielded
payments, public TLS availability or resistance to global timing correlation.

## Three-hop qualification

The additional kernel gate uses three independent native operators, four
validators, a separate client and a separate target. Run it against the same
frozen image used by the five primary gates: framed prepaid traffic,
stock Program custody, stock Circle custody, entry exhaustion and exit
exhaustion. Their completed qualification bundle must retain `summary.json`,
`framed.json` and its native build context. The summary must record all five
passing gates; `framed.json` binds the verified production image and executable
manifest. A cold checkout without that prior bundle is insufficient.

The runner accepts a separate helper context when a test fixture changes after
the production image was built. `--context` still identifies the original native
build inputs; `--helper-context` supplies the eight source-checked base helpers used
by the derived test image. Retain both contexts and the exact source transition.
The parent directory of the supplied native-context path must contain the
completed five-gate summary. A symlink can keep that bundle layout without
copying or changing the native inputs. This does not assign a new source hash to
the original production image.

```sh
python3 docker/native-vpn/triple_run.py \
  --node-image <local-tag-for-same-qualified-native-vpn-image> \
  --context /absolute/path/to/completed-five-gate-bundle/native-context \
  --helper-context /absolute/path/to/verified-helper-context \
  --headscale-commit <exact-root-lock-commit> \
  --exhaust-hop 1 --out /absolute/path/to/fresh-three-hop-evidence
```

Use a local image tag that resolves to the qualified immutable image ID; Docker
builds consume this argument in `FROM`. Qualification also verifies the actual
derived image's native manifest and all executable hashes, so a retained parent
layer alone cannot establish binary identity.

The harness checks independent canonical purchases before activating the final
route, kernel traffic in both directions, MTU 867 and TCP MSS at most 827,
operator and client restart, carrier loss without route fallback, middle-hop
exhaustion, immediate withdrawal and claims in all four ExEx archives. This is
a Program custody gate; it does not establish nested Circle custody. Generated
keys and command mailboxes stay under `private/`; publish only the public
evidence and redacted logs.
