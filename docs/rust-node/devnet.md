# Rust node local devnet

The `octra-node` executable runs the canonical Rust node, native validator driver,
authenticated peer services, transaction queue, ExEx, Circle browser and embedded
VPN sockets in one process. `scripts/devnet/native.py` manages four independent
validator processes on loopback. This is an isolated development chain.

## Run

From this repository, with the existing sibling dependencies available:

```sh
cargo build --locked -p octra-node --bin octra-node
python3 scripts/devnet/native.py init
python3 scripts/devnet/native.py start
python3 scripts/devnet/native.py status
```

Initialization requires a new directory. It generates fresh validator and faucet
keys, a shared genesis commitment, and four configurations under
`out/native-devnet`. That directory is ignored by Git. Keys are private regular
files; startup rejects permissive or symlinked key files. Genesis binds the local
validator list, timestamp and activation settings. Changing those settings
requires a new chain.

The default endpoints are:

| Validator | Peer TCP | RPC HTTP | Browser HTTP | VPN control HTTP | WireGuard UDP |
| --- | --- | --- | --- | --- | --- |
| 0 | 19870 | 19871 | 19872 | 19873 | 19874 |
| 1 | 19880 | 19881 | 19882 | 19883 | 19884 |
| 2 | 19890 | 19891 | 19892 | 19893 | 19894 |
| 3 | 19900 | 19901 | 19902 | 19903 | 19904 |

The Circle address is in `genesis.json`; each node log prints its browser URL.
Use `http://127.0.0.1:19872/open?u=oct://<circle>/index.html`. The browser resolves
assets from a committed snapshot; a new commit invalidates URLs tied to the old
snapshot. This launcher does not install an OS-wide `oct://` handler.

Stop and restart without deleting state:

```sh
python3 scripts/devnet/native.py stop
python3 scripts/devnet/native.py start
```

The supervisor retains keys, canonical databases, vote and pending journals,
receipt journals, evidence and ExEx checkpoints. It never force-kills a validator.
`node-N/node.log` contains diagnostics. A service failure stops the node and
revokes service admission. Startup reauthenticates retained history, catches up
from peers with certificate and execution verification, and restores a pending
precommit lock only after local replay. Unresolved legacy locks stop startup.

## Development RPC

- `GET /status`: chain, committed epoch/root, serving state, peers and queue size.
- `GET /account/<address>`: committed balance and nonce, with the captured epoch.
- `POST /transactions`: native signed transaction JSON. A `202` response means
  queue acceptance. Inclusion must be checked in canonical history/ExEx.

Transactions undergo signature, payload, fee, nonce, proof and active-rule
admission. Peer gossip uses the same queue admission. Queue state is currently
volatile; clients must retain signed pending transactions for resubmission after
restart. RPC is a small local operator API, not the complete upstream REST API.
The faucet key signs transactions client-side; no endpoint exposes or signs with
that key.

`node-N/exex/<sequence>.json` contains immutable canonical execution events. The
archive extension uses atomic durable writes and durable checkpoints. Replayed
writes must match existing bytes.

## Qualification boundary

The launcher uses the adopted native protocol and execution components. Its
local genesis explicitly starts the current proposal format at epoch two,
turns on preverification receipts from genesis, uses `devnet_full_v1`, static
genesis validators and no issuance. These are isolated-chain startup settings;
this is not a public-devnet or mainnet joining configuration.

VPN sockets run with canonical admission, but the launcher has no configured
settlement Circle: every funded session request is denied. It never fabricates
escrow. Circle HFHE host calls report unavailable. Managed private operations
without an implemented verifier also remain unavailable. Complete VM/HFHE parity,
funded VPN settlement, public network qualification and OS protocol registration
remain separate work.

The end-to-end regression is:

```sh
cargo test --locked -p octra-node --test devnet -- --nocapture
```

It starts four real validators, submits a signed transfer, reads a committed
Circle asset, stops one validator while the other three progress, restarts it
through peer catch-up, compares ExEx output, and shuts down cleanly. Consult the
checkpoint report for the actual result of a particular run.
