# Private kernel qualification

Run the funded private transport fixture in disposable Linux containers:

```sh
bash docker/native-vpn/private-kernel.sh /absolute/path/new-evidence
```

It requires local builder and native VPN runtime images. Set
`OCTRA_PRIVATE_KERNEL_BUILDER` and `OCTRA_PRIVATE_KERNEL_RUNTIME` to use other
local tags; see [native VPN setup](../../docker/native-vpn/README.md). The builder
must contain the locked dependency cache and Python. The runtime supplies
Python, iproute2 and iptables. Both base image identities are recorded. Image
construction and execution use disabled networking.

The script freezes explicit source inputs, compiles a release test executable
with `private-kernel-qualification`, verifies its hash, then explicitly selects
the ignored kernel test. Ordinary tests, including `--all-features`, keep this
privileged case ignored and retain the ordinary canonical private test.

The fixture exercises the actual canonical executor and four-validator
signed QCs, native funding, private note purchases, CA/SPKI-pinned HTTPS control,
WireGuard and client/operator TUN devices. A second container owns the target
TCP/UDP/IP stack. A bounded Unix packet link joins the kernels; policy routing
and NAT force application packets through the paid tunnel.

It checks TCP, ICMP and near-MTU UDP replies without retries. It closes and
reopens the encrypted client journal, operator wallet and operator service,
then repeats traffic and checks that purchased capacity and paid amounts stay
fixed while committed counters advance. This is an in-process canonical
fixture, not public-network or multihop qualification.

The same run registers the production `octra_node::archive::Archive` through
`Node::register`. It compares archived epochs with the canonical source, checks
the two actual paid native transactions and the persisted SQLite checkpoint,
then reopens the canonical/extension stores and checks that sink files agree.
The archive keeps its existing `devnet-archive` checkpoint name. VM receipts are
local execution output; they do not independently establish finality.

The ordinary canonical private test also runs from the same executable. Both
cases must finish successfully, and their owned tunnel interfaces must be gone.

`qualification.json` is authoritative only when `qualified` is true and both
container exits are zero. `native-test.log`, `private-kernel.json`, the packet
link/target metrics, source hashes and executable hash retain the evidence.
Proof and wallet keys are ephemeral test material; no real funds are used.

The [local checkpoint](checkpoints/2026-10-19/private-kernel.json) records a
successful run of both cases on the same frozen executable. The target observed
9,340 UDP and 9,728 TCP payload bytes across the two traffic phases, with no
packet-link errors or rejections. Canonical/ExEx recovery preserved 83 archive
files, including both paid transactions. Only these two exact tests were rerun
in this stage; the earlier full suite is separate evidence.

This qualifies one private paid hop in the isolated fixture. Broader
consensus/network parity, private multihop, production key ceremony and
independent cryptographic review remain separate requirements.
