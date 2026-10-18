This gate starts four fresh Rust validator processes inside a network-disabled
Linux container, opts their new genesis into the fixed application VM profile,
and deploys the unchanged private-admin factory and VPN AML through signed
ordinary transactions. It uses a newly generated development proving setup,
native operator registration, immutable discovery, canonical `Pinned` admission,
the real client and WireGuard, on-chain operator claim and opener settlement,
and committed Circle asset/ExEx checks. After the paid UDP gate, two actual OS
TUNs carry TCP, UDP and ICMP through kernel SNAT to a second network-disabled
Linux container. A bounded raw-IP Unix socket hop replaces its physical link;
the target uses ordinary kernel TCP/UDP sockets and kernel ICMP replies.
Policy routes prevent direct application-stack bypass; the target must observe
the translated source, and both paid sessions must settle and appear in ExEx.
Each live session also survives an operator process restart: the client pauses,
revalidates its original canonical opening and policy, reannounces the same
identities, completes a fresh WireGuard handshake, then resumes traffic. The
gate checks retained receipt floors and that no extra escrow was funded.
Existing host networks and stores are never mounted. Both containers have only
loopback and explicitly opened TUNs, with no external interface or default route.
A fresh private Docker-managed volume carries the packet-hop sockets and is
removed at exit. A separate volume retains public logs and manifests
until they are copied into the requested evidence directory, then is removed.
All wallet and proving secrets stay in disposable `/tmp` tmpfs.
The container receives `/dev/net/tun`, NET_ADMIN and NET_RAW. Forwarding, reverse
path and local-address acceptance sysctls apply only to its disposable network
namespace; local-address acceptance is needed because both test hosts share it.
Early TCP demultiplexing is disabled in the main fixture so its explicit receive
routes carry replies through both VPN TUNs before reaching the local socket.

Run `bash docker/native-vpn/run.sh /absolute/path/to/new-evidence-directory`.
Set `OCTRA_NATIVE_VPN_CONTEXT` to a staged directory containing `octra/`,
`octra-foundry/`, and the pinned `headscale-rs/` when qualifying a specific
sibling revision without replacing the developer's working checkout.
The builder image must supply the pinned Rust toolchain and sibling source
dependencies. Source and executable hashes are retained. Keys and proving
material remain in disposable container tmpfs and are excluded from evidence.

The application profile is an explicit local qualification policy anchored to
its committed genesis. Public `Graph::new`, validator membership, quorum and
epoch timing remain unchanged. Raw OCTB binary deployment uses the existing
Legacy path; the 64-epoch ProgramSource overlap applies to source packages,
not these raw binaries. This is not a public-chain activation or
Mainnet parity claim. The development trusted setup is not production ceremony
evidence. HTTPS gateway backend checks do not qualify external Tailscale/TLS.


The separate `single-run.sh` uses the same image, isolated kernel target and
unchanged four-validator gate inputs. It runs `single_qualify.py` instead of
`qualify.py`. Its controlled test initializer writes a new private Single
ledger image containing funded accounts and the original application opt-in;
all factories, programs, Circles, administrative changes and escrow operations
are subsequently ordinary signed RPC transactions. The node uses the shared
native RPC/application facade and authenticates local history with its retained
Single journal key. It does not create a BFT certificate or serve BFT catch-up.

This gate requires the actual `octra-single-fixture` test executable captured in
the source/binary manifest. It retains the original initial UDP timeout/loss and
usage criteria, the real two-kernel TUN/NAT/TCP/ICMP checks, private administrator
handoff/rotation/replay controls, exact claim/refund checks and same-opening
restart recovery. Its ExEx assertion covers one actual Single producer. The
four-validator agreement/quorum assertions belong to `run.sh` independently.
Both gates must be run and reported separately; source preparation alone is not
qualification. External HTTPS/Tailscale and public-network deployment remain
separate gates.

The payment-plan candidate has its own gate:

```sh
OCTRA_NATIVE_VPN_GATE=payments bash docker/native-vpn/run.sh /absolute/path/to/fresh-evidence
```

It deploys `octranet-payments.aml` and its factory on four fresh validators,
publishes the hash-pinned tariff in a real Circle, registers and funds the payer,
and bonds the operator. The `payments` client and native service then carry
actual kernel TCP, UDP and ICMP through the same isolated two-kernel fixture.
It checks differential traffic rates, operator-selected free traffic, native
canonical claims, matching ExEx, crash recovery with `--resume`, retained
budgets, immediate channel withdrawal, earnings reuse and early operator-stake
withdrawal refusal. It uses the normal native
clock; exact 24-hour rate activation and seven-day unstake boundaries have separate compiled
AML and native canonical tests. Passing this gate does not qualify stock
Tailscale paid exits, portal onboarding, public DNS/TLS or Mainnet deployment.

The prepaid gate holds initial purchase authorizations and requires zero
delivery, zero earnings and no client traffic interface before their canonical
settlement, including client/operator crash recovery. Once released, exact
finite byte purchases precede real traffic. The same purchase survives restart;
consumption cannot trigger top-ups. Exhausting a class must stop its packets,
while a still-funded class provides a positive control before exit revocation.
UDP retries remain bounded and journal/packet evidence is retained on failure.
These checks do not prove arbitrary Internet delivery or implement non-delivery
slashing, refunds of unused purchased bytes or future-obligation insurance.

The application requires canonical `epoch_time` and Ed25519 receipt checks.
The adopted typed Program profile excludes Ed25519; the gate uses the explicit
local `octra-node compile-legacy --source ... --loops --point-ops` build and
unchanged binary factory admission. Its v1 source certificate pins the emitted
OCTB but grants no typed ABI/storage authority. No source is sent to a public
compiler, and no compiler, VM or consensus admission rule is changed.

The stock-client integration gate is a separate, fresh qualification after the
native image has been built from the frozen context. Its source is prepared;
execution results must be retained before describing this path as qualified:

```sh
python3 docker/native-vpn/stock_run.py \
  --node-image <fresh-native-vpn-image> --context <frozen-context> \
  --headscale-commit <exact-root-lock-commit> --application program \
  --out <fresh-program-evidence-directory>
python3 docker/native-vpn/stock_run.py \
  --node-image <same-fresh-native-vpn-image> --context <same-frozen-context> \
  --headscale-commit <same-exact-root-lock-commit> --application circle \
  --out <fresh-circle-evidence-directory>
```

Each invocation verifies the image's complete source manifest against the frozen
`octra`, `octra-foundry` and `headscale-rs` context. It copies the digest-pinned
Tailscale image and requires version 1.104.1. A fresh internal Docker network
contains the actual stock kernel client and four Rust validators; a third
network-disabled container supplies the independent application target kernel.
The existing bounded Unix packet link carries only the fixture's public target.
An exact container-only UDP DNAT rule and namespace `route_localnet` connect
the internal underlay to the unchanged devnet's loopback listener, preserving
the real peer source and native WireGuard/Disco authentication. No cryptography
or admission is terminated by this fixture forwarding rule.
Neither the host network nor the host VPN is used.

The gate requires genuine canonical prepaid purchases, a fixed Circle asset
portal over trusted TLS/MagicDNS, separately paid general Circle HTTPS, direct
and forced native TLS DERP carriage, TCP/UDP/ICMP, restart, registration rotation,
class exhaustion, instant channel revocation and matching claims in all four
ExEx archives. The payment controller uses only the payer key and public stock
node key; stock WireGuard secrets stay inside tailscaled. Generated TLS keys,
preauth values and the private command mailbox are under `private/`; publish
only the public evidence and redacted logs. Each application mode uses a fresh
chain and genuinely executes its own Program or Circle custody application.
This gate does not establish public-network availability, Web delivery proofs,
non-delivery slashing, or a mainnet deployment.

The nested route gate uses two actual native operators in different network
namespaces, a separate kernel client and a separate kernel application target.
Run both independently selected exhaustion/revocation cases with fresh outputs:

```sh
python3 docker/native-vpn/multi_run.py \
  --node-image <fresh-native-vpn-image> --context <frozen-context> \
  --headscale-commit <exact-root-lock-commit> --exhaust-hop 0 \
  --out <fresh-entry-hop-evidence-directory>
python3 docker/native-vpn/multi_run.py \
  --node-image <same-fresh-native-vpn-image> --context <same-frozen-context> \
  --headscale-commit <same-exact-root-lock-commit> --exhaust-hop 1 \
  --out <fresh-exit-hop-evidence-directory>
```

This gate genuinely stops and relocates validator1's existing canonical store,
key, signing history and ExEx archive; it verifies their complete stopped-file
hashes before starting the second namespace. Bounded opaque TCP links preserve
the native isolated launcher's loopback endpoints while the native peers still
authenticate their own frames, roots, bundles and finality. Exact namespace UDP
DNAT rules expose the two public fixture aliases to their native loopback
WireGuard listeners. The entry forwards only encrypted UDP to the next operator;
the exit carries the target web traffic. Each has its own operator key, payer
key, quote, plan, journal, canonical purchase and durable packet meter.

The entry UDP IP and accepted control IPs are explicit physical management
exceptions. In this isolated fixture the accepted loopback HTTP controls use
opaque TCP links through the entry IP to the two actual native control services.
These are IP exceptions, not a per-socket firewall or public TLS qualification.
The gate checks the all-hop purchase barrier, both directions of kernel traffic,
the conservative1075-byte final profile and TCP MSS, oversized profile refusal,
operator/client restarts, specific downstream blackholes after carrier loss,
foreign priority1 rule refusal, each hop's finite exhaustion and canonical
withdrawal, and identical claims in four ExEx archives. Crash resume deliberately
verifies and removes only the exact fixture-owned routes after the writer and
TUNs have stopped; it never flushes a routing table or silently repairs host
policy. Both invocations are two-hop Program custody qualifications; three-hop
and Circle custody paths require their own gates. The harness source alone is
not a passing result.
