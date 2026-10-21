# OctraVPN

**Peer-to-peer bandwidth, paid in OCT.**

OctraVPN combines a Rust Octra node, WireGuard networking and Circle-hosted
applications. Operators offer connectivity at their own prices. Users fund a
channel, buy traffic, and pay operators directly. The protocol takes **zero
commission**.

[Documentation](docs/README.md) · [Node status](docs/rust-node/status.md) ·
[Payment model](docs/architecture/circle-prepaid.md) · [octra.to](https://octra.to)

> **Development preview.** The payment and portal Circles are published on
> public devnet. Sustained public VPN service, funded private multi-hop recovery
> and accounting are still being qualified. The alpha is not open to testers
> yet; Mainnet deployment is not qualified.

## What it does

- **Run an Octra node.** Transaction execution, authenticated peers, consensus,
  canonical state, ExEx and embedded VPN services share one node lifecycle.
- **Create an Octranet.** Coordinate a private mesh with embedded `headscale-rs`
  and supported Tailscale clients. Internet exit service is an explicit opt-in.
- **Sell connectivity.** Publish an offer, choose rates for different traffic
  classes, and enforce purchased allowances before forwarding packets.
- **Use Circles.** Host tariffs, management pages and onboarding assets in
  Circles. Resolve published public Circle resources through the node's HTTPS
  gateway.
- **Route through operators.** Nested routes carry downstream control and data
  through preceding tunnels. Shielded payments and funded private routes remain
  experimental and require their own qualification.

The integrated node follows the adopted upstream Octra protocol. Full behavioral
parity is still being checked; implementation and qualification evidence are
recorded in the [node status](docs/rust-node/status.md).

## How payment works

Users buy finite byte allowances before traffic flows. Operators set their own
prices, including different rates for different traffic classes. The unpaid
onboarding portal provides the basics needed to join and fund an account.

| Rule | Behavior |
| --- | --- |
| Protocol commission | Zero. Payments go directly to operators. |
| Available channel OCT | Withdrawable immediately. Settled byte purchases stay final. |
| Operator earnings | Can fund outgoing traffic without a withdrawal and redeposit. |
| Rate changes | Activate after 24 hours. Purchased bytes keep their accepted price. |
| Operator unstaking | Seven-day delay. |
| Transaction fees | Ordinary Octra transaction fees apply separately. |

There are no automatic top-ups or operator credit lines. Buying bytes does not
prove delivery of arbitrary Internet traffic. The exact custody, allowance and
withdrawal rules are in the [payment design](docs/architecture/octranet-payment-tier.md)
and [operator guide](docs/operators/payment-plans.md).

WireGuard encrypts tunnel traffic. An exit operator can still observe
destinations, and applications need HTTPS or equivalent protection beyond the
exit. Standard prepaid settlement exposes payment metadata; experimental
shielded settlement has separate setup and security requirements. See the
[security documentation](docs/security.md) for the trust assumptions.

## Build from source

Install Rust through [rustup](https://rustup.rs), a C/C++ build toolchain and
`protoc`. The repository selects Rust **1.96.0**. Clone Foundry beside this
checkout at the revision used by CI:

```sh
mkdir octravpn-workspace
cd octravpn-workspace
git clone https://github.com/androolloyd/octravpn.git octra
git clone https://github.com/androolloyd/octra-foundry.git
git -C octra-foundry checkout c9011f1f4dfeee3c7c726feb4b4cd337477f866a
cd octra
cargo build --locked --release -p octra-node -p octravpn-client -p octravpn-node
```

This builds `octra-node`, the `octravpn` client and the standalone
`octravpn-node` operator. Cargo fetches `headscale-rs` at its pinned revision;
a separate Headscale checkout is optional. See
[dependency strategy](docs/architecture/headscale-dep-strategy.md).

Start an isolated four-validator development chain:

```sh
target/release/octra-node init-devnet --directory out/native-devnet
python3 scripts/devnet/native.py start --binary target/release/octra-node
python3 scripts/devnet/native.py status
```

Initialization requires a new directory. This chain is local; joining public
devnet requires independently configured network trust and an authenticated
bootstrap. Follow the [node guide](docs/rust-node/devnet.md) for public startup,
Circle browsing and retained-state restart. Stop the local chain with
`python3 scripts/devnet/native.py stop`.

## Circles and octra.to

[octra.to](https://octra.to) is the front door for onboarding and public Circle
browsing. Its portal assets are published in a Circle; the Rust gateway reads
canonical state and serves them over HTTPS. Public service availability remains
a launch gate.

An `oct://<CircleAddress>/path` identifies a Circle resource. A client handler or
HTTPS gateway resolves it. DNS alone cannot make arbitrary applications
understand the `oct://` scheme. Circle addresses stay in URL paths because their
case is significant. See the [gateway guide](docs/rust-node/devnet.md#https-access-through-tailscale)
and [site bundle](sites/octra-to/README.md).

## Development and verification

```sh
./scripts/test-all.sh
```

The required gate builds and tests the workspace, runs strict Clippy and checks
benchmark regressions. Public-chain drills and Docker smoke tests are explicit
opt-ins. Privileged kernel transport, private payments and public deployment
have additional gates; a green unit suite does not qualify a launch.

Formal models and executable tests cover specific payment and protocol
properties. Their scope and assumptions are recorded with the evidence; they do
not establish complete implementation correctness or prove Internet delivery.

| Start here | Guide |
| --- | --- |
| Run a node | [Local and public devnet](docs/rust-node/devnet.md) |
| Operate a paid exit | [Payment plans](docs/operators/payment-plans.md) |
| Use Tailscale clients | [Stock paid exits](docs/architecture/stock-paid-exit.md) |
| Build nested routes | [Multi-hop design](docs/architecture/nested-paid-exits.md) |
| Inspect verification | [Formal models](proofs/lean/README.md) and [qualification status](docs/rust-node/status.md) |
| Watch recorded flows | [Demos and recordings](demo/README.md) |
| Report a vulnerability | [Security policy](SECURITY.md) |
| Explore the project | [Documentation index](docs/README.md) |

## License

The workspace is licensed under [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE). Bundled components retain their own licenses;
see the [PVAC sidecar documentation](pvac-sidecar/README.md).
