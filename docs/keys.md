# Key management

OctraVPN uses three classes of keys per role:

## Validator (node)

| Key                      | Purpose                                          | Where it lives          |
| ------------------------ | ------------------------------------------------ | ----------------------- |
| `wallet_secret`          | Octra account key; signs `register_validator`, `refresh_attestation`, `claim_earnings` | `node.toml.chain.wallet_secret_path` |
| `wg_secret`              | WireGuard noise IK static key; node side of every tunnel; receipt signer | `node.toml.tunnel.wg_secret_path` |
| `fhe_secret`             | HFHE secret for the validator's encrypted earnings ledger | `node.toml.fhe.secret_path` |
| `view_pubkey` (derived)  | Stealth view key; published on chain; clients use it to derive payment outputs | derived from wallet pubkey |

Key files contain either 32 raw bytes or a hex-encoded form. The node
loader auto-detects.

**Compromise impact**:
- `wallet_secret` lost → adversary controls the validator account; can
  request_unbond, falsely refresh, or move bond out. Slashable: no.
- `wg_secret` lost → adversary can sign receipts for sessions that
  routed through this node. Mitigated by the `slash_double_sign`
  evidence path: any honest node who signed differently has the
  evidence to slash.
- `fhe_secret` lost → adversary can decrypt encrypted earnings ledger.
  Earnings are still paid via stealth output, so adversary learns
  amounts but not the recipient.

## Client

| Key                      | Purpose                                          | Where it lives          |
| ------------------------ | ------------------------------------------------ | ----------------------- |
| `wallet_secret`          | Octra account key; signs the `open_session` and `settle_session` outer txs | `client.toml.wallet.secret_path` |
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
