# Native private route startup and recovery

The experimental supervisor supports the isolated BFT application profile and
explicitly configured public devnet with `private-payments-experimental`.
Public deployment qualification is separate from the local funded matrices;
see the [private alpha guide](../operators/devnet-private-alpha.md). Mainnet and
public multi-operator routes remain unqualified.

Set `private_route` in the isolated node configuration. It contains an existing
route `id`, two or three `hops` using the existing private payer configuration,
and optional `chain_dns` IPv4 pins. Each hop specifies its original wallet,
index and key paths, accepted deployment and pinned TLS control endpoint.
Runtime configuration contains no fresh purchase terms. Select the route owner
instead of the standalone `payer` scheduler.

Import finite consent while the node is stopped:

```sh
octra-node private-route-consent --config node.json --requests route-consent.json
```

The private request file is a JSON array. Each entry contains `purchase_id`,
`terms`, `tariff`, `endpoint`, `journal` and `interface_name`, matching
`payer::startup::route::Consent`. The existing books and public pool index must
already exist. The command uses the same private-file permission, size,
single-link and symlink checks as payer consent. It records the complete route
before any operator request. `--resume` can finish interrupted initialization
with the exact original input; it cannot adopt unrelated jobs or repair missing
previously committed records.

Startup restores the original sealed intent and books before the P2P actor
starts. Shared custody reuses one book, relayer and index handle; another pool
requires a separate book and relayer. Recorded endpoint trust must match the
configuration. A previously armed route configures native P2P as paused. The
controller starts alongside node initialization, so entry recovery can precede
the peer catch-up gate. Index opening waits for a fresh canonical publication. If that publication is
revoked while the original index is being reopened, the complete reopen attempt
waits and retries. Only a successfully authenticated index enters the shared
cache. A root quarantine, corrupted history or custody error remains fatal.

A successful native purchase now retains its exact signed envelope locator and
portable execution proof before client admission. An armed entry can verify that
already settled purchase against the node's authenticated retained certificate
while serving is suspended. The proof still checks ancestry, signed finality,
historical rules, state commitments, the exact transaction, invoice identity and
operator output. A quarantine invalidates the recovery permit, including after
the quarantine is cleared. The operator's fresh meter and original encrypted
client journal remain necessary for transport admission.

Historical verification creates no serving publication, note reconciliation,
new signature, fee reservation or purchase. New entry funding and downstream
purchases continue through the existing fresh canonical payment path. Missing
credit, proof, channel or client state fails without another purchase or a direct
network fallback.

`spend_operator_income` can be set per hop. The launcher attaches its existing
operator wallet after that service unlocks it. A fresh, fully synchronized index
and the existing exclusive note-assignment checks precede income import. The
finite route terms and fee allowance still bound spending; earnings create no
new consent and the protocol takes no commission.

The retained network-plan candidate now seals the accepted endpoint/interface
binding, Linux boot/network namespace and physical entry device identities in
the same encrypted transaction as the armed flag. Reservation checks this plan
under the host lease without changing kernel state. A missing previously armed
plan, live tunnel, changed namespace/device, foreign rule or unexpected route is
an error. Root and `CAP_NET_ADMIN` are checked before entry funding.

After the recorded plan is armed and P2P paused, recovery completes any missing
base blockers, retains both global blocking policies and removes only the
validated detached entry rule. It then reopens the original paid carriers.
Recovery does not flush tables, infer ownership from a protocol tag, reset
counters or purchase another entry. A fresh empty namespace can acquire a new
host plan from the original accepted pins; existing unknown state is refused.
The encrypted-book checks now pass within the 69-test release payment suite.
Native chain sockets also require the recorded privileged socket mark, and
restart accepts the complete original interface, mark and DNS pin scope.
The route-only candidate failed a real Linux test: forcing an output interface
could evade its blockers, including with a terminal unreachable policy. The
[packet guard](private-packet-guard.md) now enforces exact accepted paths in
local OUTPUT, and the final kernel test rejects the real UID-1000 packets
without transmitting them. It also restores the sealed route/filter plan,
repairs a missing family, and refuses foreign or shadowed state. This is
bounded composite qualification, not a full funded multihop result. See the
[current checkpoint](checkpoints/2026-10-20/private-packet-guard.json).
The [combined funded two-hop checkpoint](checkpoints/2026-10-21/private-funded-multihop.json)
now passes ordered downstream payment, full process restart, finite exhaustion,
carrier loss and ExEx agreement in isolated Linux kernels. Public multi-operator
qualification remains separate.
