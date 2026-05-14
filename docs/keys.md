# Key management

OctraVPN uses three classes of keys per role:

## Operator (node)

| Key                      | Purpose                                          | Where it lives          |
| ------------------------ | ------------------------------------------------ | ----------------------- |
| `wallet_secret`          | Octra account key; signs `bond_endpoint`, `register_endpoint`, `settle_claim`, `claim_earnings`, `unbond_endpoint`, `finalize_unbond` | `node.toml.chain.wallet_secret_path` |
| `wg_secret`              | WireGuard noise IK static key; node side of every tunnel; receipt signer | `node.toml.tunnel.wg_secret_path` |
| `fhe_secret`             | HFHE secret for the validator's encrypted earnings ledger | `node.toml.fhe.secret_path` |
| `view_pubkey` (derived)  | Stealth view key; published on chain; clients use it to derive payment outputs | derived from wallet pubkey |

Key files contain either 32 raw bytes or a hex-encoded form. The node
loader auto-detects.

**Compromise impact**:
- `wallet_secret` lost → adversary controls the operator account; can
  unbond, submit `settle_claim` for arbitrary bytes, or claim earnings.
  Equivocation (two different `settle_claim` per session) is slashable
  in-AML — adversary risks 90% bond loss on the first bad claim.
- `wg_secret` lost → adversary can serve traffic and sign receipts.
  Off-chain dispute resolution still relies on the dual-signed receipt
  (client + node) — see the off-chain dispute flow in `architecture.md`.
- `fhe_secret` lost → adversary can decrypt encrypted earnings ledger.
  Earnings are still paid via stealth output, so adversary learns
  amounts but not the recipient.

## Client

| Key                      | Purpose                                          | Where it lives          |
| ------------------------ | ------------------------------------------------ | ----------------------- |
| `wallet_secret`          | Octra account key; signs the `open_session` and `settle_confirm` outer txs | `client.toml.wallet.secret_path` |
| Session ephemeral        | Generated fresh per `connect`; signs receipts;   | in-memory only          |

The session ephemeral is **never** the wallet key. It's generated at
`connect`, used for the lifetime of the session, and discarded on
clean shutdown. The on-chain program never sees the wallet pubkey
during session activity.

## Generating keys

For tests, hex-encoded 32-byte secrets are sufficient (see
`docker/conf/*/wallet.key`). For production, generate from `/dev/urandom`:

```sh
head -c 32 /dev/urandom | xxd -p -c 64 > wallet.key
chmod 600 wallet.key
```

A future helper subcommand (`octravpn keygen`) will encapsulate this.
