# Validator duty and local controls

The Rust node integrates the adopted native `Set_actor`, `Set_post`,
`Set_control` and `Set_delivery` flow. The workspace all-targets type check
passed, and the intent codec has 20 native fixture cases. The default isolated
devnet and paid VPN fixture use static validators; they do not qualify a live
bonded validator's full duty/exit lifecycle. The broader runtime suite and
public-network duty integration retain separate gates; see [status.md](status.md).

Automatic duty starts only for an explicitly configured voting operator with
the bonded validator lifecycle enabled. An operator awaiting selection follows
certified history and may submit its own `validator_ready` pulses. Engine
voting and proposal gates still require active validator membership. A
configured identity mismatch prevents startup.

Duty decisions read the committed validator registry and duty receipt from one
canonical snapshot. Inactive bonded operators pulse at half the native pulse
gap. Active operators submit appeals only for a real precommit recovered from
their durable local vote journal and omitted from a finalized parent
certificate. Appealing never creates or replaces a vote. Receipts acknowledge
included proofs; expired proofs and bounded queue pressure have explicit
observations.

Delivery uses the normal authenticated and persisted transaction queue, with
the native exact-hash retry shortcut for already staged duty. A pending next
account nonce blocks a new duty transaction. Retained transactions preserve
their signed bytes and proposal reference across retries; committed nonces,
expired delivery windows and changed bonded incarnations retire them.
`OCTRA_OPERATOR_RPC_URL`, when explicitly configured, adds the native bounded
five-second `octra_submit` delivery in addition to peer gossip. It receives
only the signed public duty transaction.

To pause automatic duty before an on-chain exit, use the same key and data
directory as `run-network`, and the exact `bonded_epoch` reported by
`octra_validatorEnrollment`:

```sh
octra-node validator-control --key /path/to/node.key --data /path/to/data \
  --chain-id CHAIN --bonded-epoch EPOCH request
octra-node validator-control --key /path/to/node.key --data /path/to/data \
  --chain-id CHAIN --bonded-epoch EPOCH status
octra-node validator-control --key /path/to/node.key --data /path/to/data \
  --chain-id CHAIN --bonded-epoch EPOCH cancel
```

These commands authenticate a local intent; they do not submit an exit or
withdrawal transaction. Intent files use the native signed format, private
permissions, POSIX advisory lock, atomic rename and directory fsync. A duty
admission holds that lock until owned queue workers finish, including when its
awaiting task is cancelled. Restart reads the persisted intent. A stale intent
does not apply to a later bonded incarnation.

Source mapping:

| Adopted native source | Rust source |
| --- | --- |
| `node_runtime/set_actor.ml` | `octra-node-runtime/src/validator_duty.rs` |
| `node_runtime/set_post.ml` | `octra-node-runtime/src/validator_duty/post.rs` |
| `node_runtime/set_control.ml` | `octra-node-runtime/src/validator_duty/control.rs` |
| `node_runtime/set_delivery.ml` and node wiring | `octra-node/src/duty.rs`, `executor/pending.rs`, `launch.rs` |
| `C_driver.fold_event`, `notify_fold` | `octra-node-runtime/src/consensus_driver/outputs.rs` |
| `bft_control_tx --exit-intent` | `octra-node/src/validator_cli.rs` |
