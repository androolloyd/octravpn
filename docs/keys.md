# Key management

OctraVPN uses several classes of keys; the set depends on whether
you're running v1.1 or the v2 substrate. This doc covers both. For
v2, see also
[`docs/v2-operator-key-hygiene.md`](v2-operator-key-hygiene.md) for
the fresh-wallet hygiene rule and
[`docs/v2-threat-model.md`](v2-threat-model.md) §8 for the on-disk
storage threat model.

## v2 key types at a glance

In v2 every active session involves four distinct key types:

| Key | Algorithm | Encoding on the wire | Purpose | Compromise → |
| --- | --- | --- | --- | --- |
| **Wallet secret** | Ed25519 (Octra account) | base64 in tx envelopes; raw/hex in config | Signs every on-chain tx — `open_session`, `settle_confirm`, `redeem_join_token`, operator-side `register_circle`, `bond_endpoint`, `update_circle`, etc. | Adversary owns your account: drains balance, posts arbitrary slashable receipts, controls the operator circle if you're the owner. |
| **WG static (tunnel)** | Curve25519 (Noise IKpsk2) | base64 (matches webcli) | Operator side of every WireGuard tunnel; client side per session. Client side is regenerated per `connect`/`connect-v2`. | Adversary can serve / sign tunnel traffic for that endpoint. Off-chain dispute resolution still pivots on dual-signed receipts. |
| **Receipt key** | Ed25519 (separate from wallet) | **base64** (NOT hex — AML `ed25519_ok` decodes via base64) | Signs per-session receipts that gate slash-defense (`slash_double_sign`, `claim_no_show`). | Adversary can sign rogue receipts attributed to you; if they sign two different `bytes_used` for the same `(session, seq)` they self-slash. |
| **Sealed-policy passphrase** | PBKDF2-HMAC-SHA256 (120k) → AES-256-GCM | passphrase string | Per-tailnet shared secret. Encrypts every authorized circle's `/policy.json` (endpoint, WG pubkey, region, tariff, version). | Adversary can decrypt the sealed policy for every authorized circle in this tailnet. Per-tailnet, not per-member — see FAQ. |

Wire-format gotcha for the receipt key: AML's `ed25519_ok` expects
**base64** for both pubkey and signature. Hex round-trips correctly
through the rest of the stack but reverts at chain verification with
`sig_a invalid`. `octra cast wallet sign` outputs base64 already;
`octra cast wallet pubkey` currently outputs hex, pipe through
`xxd -r -p | base64` until `--format=base64` lands.

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

## Sealing on-disk keys (v2 operators)

The default on-disk encoding is raw hex (back-compat with devnet and
v1). v2 operators should switch to sealed envelopes:

```sh
export OCTRAVPN_KEY_PASSPHRASE="$(openssl rand -base64 24)"
octravpn-node --config /etc/octravpn/node.toml seal-keys
# After verifying the sealed daemon boots:
octravpn-node --config /etc/octravpn/node.toml seal-keys --remove-plaintext
```

`seal-keys` wraps each configured secret (wallet + WG) under the
`OCTRA-WALLET-V1` envelope (PBKDF2 → ChaCha20-Poly1305), writes a
parallel `*.sealed` file atomically, and is idempotent across re-runs.
Set `[chain].require_sealed_keys = true` and point the TOML at the
`*.sealed` paths; the daemon will refuse to boot if any configured
secret is still plaintext-on-disk (surfaced as
`CoreError::PlaintextKeyOnDisk`). The full procedure, including
`unseal-keys` for emergency recovery, lives at
[`docs/v2-operator-key-hygiene.md`](v2-operator-key-hygiene.md)
§ "the `seal-keys` subcommand".

## Fresh-deploy-wallet hygiene (v2 operators)

In v2, the `deploy_circle` tx that creates an operator circle has
`from = <deployer_wallet>` and `to_ = <circle_id>`. That binding is
permanent on chain and re-stated by every subsequent owner action
(`register_circle`, `bond_endpoint`, `update_circle`,
`finalize_unbond`, every governance slash). Anyone scraping octrascan
can pin `circle_id ↔ deploy_wallet` retroactively.

**Operating rule**: every operator circle must be deployed from a
brand-new wallet that has **zero prior chain history** — no faucet
visit from your main wallet, no transfers, no contract calls. Fund it
via the public faucet directly (devnet) or via a stealth output from
another single-purpose wallet (mainnet). Don't reuse a deploy wallet
across circles you don't want publicly linked together. See
[`docs/v2-operator-key-hygiene.md`](v2-operator-key-hygiene.md) §§ 1–3
for the full funding patterns.

## Rotation

| Key | Rotate when | How |
| --- | --- | --- |
| Wallet secret | Suspected compromise | Generate fresh wallet, move balance via stealth send. For operators: `unbond_endpoint` from old, `register_circle` from new (creates a new circle_id; can't preserve the old identity). |
| WG static | Quarterly, or on compromise | Operator: rotate the static key, re-`circle_asset_put_encrypted /policy.json` with the new pubkey and bumped `policy_version` — clients auto-bust their cache on `plaintext_hash` change. |
| Receipt key | Suspected compromise of a session-signer host | Operator: `octravpn-node rotate-keys`. The new pubkey is announced at the next `register_endpoint` / policy seal. |
| Sealed-policy passphrase | Quarterly, on any member compromise, or after `remove_member` if you want the removal to bite retroactively | Tailnet owner picks new passphrase, asks each operator to re-seal `/policy.json` under it via `cast circle put-encrypted`, distributes the new passphrase out-of-band to remaining members. |
