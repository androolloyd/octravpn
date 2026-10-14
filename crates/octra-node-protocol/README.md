# Octra node protocol

Ports of pinned lite_node protocol boundaries: commitments, transaction
identity and admission, account journals, Circle storage, epoch outcomes and
rewards, consensus codecs/state machines, and authenticated peer transport.
Byte strings, native numeric rules and rejection order are preserved.

`tests/fixtures/epoch-index.json` contains outputs from the real pinned OCaml
implementation. It includes invalid inputs, duplicate IDs, signed boundaries,
raw and textual roots, and deterministic randomized cases. Regenerate with:

```sh
python3 scripts/node-port/epoch-index-fixtures.py --upstream /path/to/lite_node \
  --builder-image <pinned-upstream-builder> --out /tmp/epoch-index.json
cargo test --locked -p octra-node-protocol
```

The peer swarm owns authenticated full-duplex connections, signed discovery,
peer roles and limits, duplicate selection, profile changes, bans and reconnects.
Connection cancellation drops both stream halves. Per-peer outgoing queues hold
one frame; a queue timeout never interrupts an in-progress frame. Inbound
handshakes have a separate 512-task resource ceiling.

Tests include native fixtures, three-node TCP meshes, replacement connections,
restart, observer limits and identity bans. A localhost-only Docker harness also
runs the unmodified OCaml swarm against Rust:

```sh
python3 scripts/node-port/test-native-peer.py --upstream /path/to/lite_node \
  --builder-image <pinned-upstream-builder> --out /tmp/native-peer.json
```

The live harness checks challenge authentication, signed discovery/profile
messages, ping/pong and transaction inventory/request framing. The host still
needs to connect peer messages to the full consensus driver, transaction queue
and sync/recovery services. These boundaries do not establish full node parity
or Mainnet readiness. Upstream-derived code retains its BSD-3-Clause license.
