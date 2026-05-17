# v2 Operator Boot Sequence

> Status: **shipped**. The `octravpn-node` binary picks v1.1 (default) or
> v2 (Circle-native) at startup based on a single config toggle. This
> doc walks a new operator through the v2 boot path: which keys come
> from where, what flags toggle v2 vs v1, where the sealed-passphrase
> comes from, and what tx hashes get logged.

## TL;DR

```toml
[chain]
rpc_url             = "https://devnet.octrascan.io/rpc"
program_addr        = "oct3fxjrzfqh65ATo31eau8xRFBPiXh2Uzwue56EYkfVSj7"
validator_addr      = "octYOURWALLET..."
wallet_secret_path  = "/etc/octravpn/wallet.key"
protocol_version    = "v2"
sealed_passphrase   = "shared-with-tailnet-members"
circle_state_path   = "/var/lib/octravpn/circle.toml"

[tunnel]
public_endpoint     = "node1.example.com:51820"
listen              = "0.0.0.0:51820"
wg_secret_path      = "/etc/octravpn/wg.key"

[pricing]
price_per_mb        = 100              # used by v1.1 — left in for back-compat
price_per_mb_shared = 100              # v2 shared (public-internet) tariff
price_per_mb_internal = 0              # v2 intra-tailnet (free by default)
region              = "eu-west"
```

Run:

```sh
octravpn-node --config /etc/octravpn/node.toml run
```

…and the daemon walks the four steps below. v1.1 operators leave
`protocol_version` unset (defaults to `"v1.1"`) and the legacy
`bond → register_endpoint` path runs unchanged.

## The four-step boot

The v2 register flow is implemented in
`crates/octravpn-node/src/hub.rs::register_endpoint_v2`. It chains
four chain interactions, persisting state to
`circle_state_path` (default `./state/circle.toml`) after each so a
crash mid-flow resumes cleanly on restart.

### 1. Predict the `circle_id`

A circle's on-chain id is fully deterministic:

```
circle_id = "oct" + base58(sha256(
    "octra:circle_deploy_id:v1"
    || deployer_address
    || u64be(deploy_nonce)
    || hex(sha256("octra:circle_deploy_payload:v1" || canonical_payload_json))
))
```

…cycled to 44 base58 chars. The code lives in
`octra_core::circle::circle_id_of_deploy` (re-exported via
`octravpn_core::circle`). The operator fetches the wallet's current
nonce from `octra_balance`, derives the would-be `circle_id`, and
saves the triple `(circle_id, deploy_nonce, …)` to
`state/circle.toml`. Subsequent restarts load the cache instead of
re-deriving (the deploy nonce changes every time the wallet sends a
tx, so a fresh derivation would NOT predict the same circle).

If the cache file already has a `circle_id` from a prior run, the
boot loads it and skips re-derivation. To force re-derivation
(e.g. the operator wants to deploy a fresh circle), delete
`state/circle.toml` and restart.

### 2. `deploy_circle` (if needed)

We then check the chain via the `circle_info` RPC. If the chain
already knows the circle, this step short-circuits.

Otherwise we submit a tx with `op_type = "deploy_circle"`,
`to_ = <predicted circle_id>`, `nonce = deploy_nonce`, and `message
= canonical_payload_json(default_deploy_payload())`. The payload is
the webcli default: `runtime=octb`, `privacy_class=sealed`,
`browser_mode=native_sealed`, `resource_mode=sealed_read`, no
overrides. The chain verifies the predicted `to_` matches what it
computes from `(from, nonce, payload)` — that's how circles get
content-addressed.

Logged at info level:

```text
v2 circle predicted (no prior state on disk) circle_id=oct… deploy_nonce=N
v2 deploy_circle submitted hash=… circle_id=oct…
```

The submitted tx hash is persisted to `state/circle.toml` so the
next step can run idempotently.

### 3. `circle_asset_put_encrypted /policy.json`

The operator's runtime policy (endpoint URL, WG pubkey, region,
tariffs, attestation timestamp, receipt pubkey) is bundled into a
JSON object (`PolicyBundle` in `chain_v2.rs`), encrypted under the
sealed-asset scheme, and uploaded into the circle at the canonical
path `/policy.json`.

Encryption uses
`octra_core::circle::encrypt_sealed_bytes(circle_id, "default",
passphrase, plaintext, PaddingClass::None)`. The passphrase comes
from one of two places, checked in order:

1. **`[chain].sealed_passphrase`** in the operator's TOML.
2. **`OCTRAVPN_SEALED_PASSPHRASE`** env var.

If neither is set, the operator's daemon refuses to start v2. The
passphrase is a **per-tailnet shared secret** the operator receives
at provisioning time from whichever party runs the tailnet (typically
the same person who runs `cast circle put-encrypted` on the client
side). Clients that join the tailnet receive the same passphrase via
the tailnet's join-token flow.

The chain sees only:
- The opaque AES-GCM ciphertext (with PBKDF2-SHA256 PBKDF salt + 12-byte
  random nonce + standard sealed-envelope magic).
- A `key_id` (`"default"` for now) so the operator can rotate
  passphrases without breaking historical assets.
- A `plaintext_hash` (sha256 of the unencrypted bundle) so clients can
  detect tampering after decrypt.
- A `path` (`/policy.json`) and `content_type` (`application/json`).

Clients fetch this by the **resource key** —
`resource_key(circle_id, "/policy.json")` — via the
`circle_asset_ciphertext_by_resource_key` RPC, which keeps even the
*path* private from chain observers.

Logged at info level:

```text
v2 policy bundle uploaded (sealed) hash=… circle_id=oct… resource_key=<hex>
```

The plaintext sha256 hash is also cached in `state/circle.toml`; on a
later restart, if the on-disk policy still hashes to the same value,
we skip the re-upload.

### 4. `register_circle` (atomic register + bond)

Finally, the operator calls `register_circle(circle, region,
price_shared, price_internal, receipt_pubkey_b64, op_pk_hfhe,
op_zero_ct_hfhe)` on the v2 program (`program/main-v2.aml`, deployed
at `oct3fxjrzfqh65ATo31eau8xRFBPiXh2Uzwue56EYkfVSj7`) with `value =
MIN_CIRCLE_STAKE` (default 1_000_000_000 OU = 1000 OCT).

`register_circle` is **payable**, so this single tx both registers the
circle in the slim registry AND deposits the initial bond. v2 lifted
the v1.1 chicken-and-egg where `bond_endpoint` required an owner that
only `register` set.

The wire form is the standard `op_type=call` envelope; `caller`
becomes `circles[circle].owner`, so the operator's wallet has to be
the same address that deployed the circle in step 2.

`receipt_pubkey` is base64-encoded here (not hex like v1.1) because
the v2 AML's `ed25519_ok` host call decodes base64 natively. The same
underlying Ed25519 key, just a different on-chain encoding.

Logged at info level:

```text
v2 register_circle submitted (atomic register+bond) hash=… circle_id=oct… stake=1000000000
```

After this point the registry shows
`circles[circle].active == 1` and the operator is open for business.
The existing health-check loop continues to verify the operator's
stake every `poll_interval_secs`.

## What keys come from where

| Key | Where it lives | Used for |
|---|---|---|
| Wallet secret (32B) | `wallet_secret_path` (chmod 0600) | Signs every tx the operator submits |
| WG master secret (32B) | `wg_secret_path` (chmod 0600) | HKDF-Expand'd into two subkeys (see below) |
| Receipt signing key | HKDF(`wg_secret`, `DOMAIN_RECEIPT_SIGN`) | Off-chain receipt signatures; pubkey published on chain |
| Noise static secret | HKDF(`wg_secret`, `DOMAIN_NOISE`) | WireGuard data plane handshake |
| Sealed-asset passphrase | `sealed_passphrase` / env var | PBKDF2 input for sealed-asset AES-GCM read key |

The wallet secret is the only key whose pubkey appears as an address
on chain (`circles[circle].owner`). The receipt pubkey appears on
chain too, but as a string field; only the wallet can deploy a circle
and call `register_circle`.

## What tx hashes get logged

Every step logs the submitted tx hash at info level, prefixed with
`v2 <step> submitted`. The same hashes are also persisted to
`circle_state_path`:

```toml
# state/circle.toml after a successful boot
circle_id = "oct…44chars"
deploy_nonce = 7
deploy_tx_hash = "…"
policy_tx_hash = "…"
register_tx_hash = "…"
policy_plaintext_hash = "<hex>"
```

Operators can dump the current state with `octravpn-node identity` —
this prints the protocol version, the predicted/derived circle id,
and any cached tx hashes without touching the chain.

## What stays the same as v1.1

- The wallet key, the WG master key, and their derivation are
  unchanged. v2 operators can keep using the same key files they
  used for v1.1.
- The control-plane HTTP server, audit log, and tunnel server are
  identical. They don't know which protocol version is running.
- `settle_claim` is wired against the v2 program in v2 mode (same
  wire shape — only `caller == circle.owner` enforcement differs).
- The HFHE pubkey + zero ciphertext stored on chain are still
  placeholders until `libpvac` lands. v2 doesn't unblock real
  HFHE — that's a separate axis.

## What to do if v2 boot fails

Each step is idempotent and resumable. Common cases:

- **"v2 sealed-asset passphrase required"** — set
  `[chain].sealed_passphrase` in the TOML or export
  `OCTRAVPN_SEALED_PASSPHRASE`.
- **"circle … is permanently slashed"** — the operator's prior
  circle was slashed by `slash_double_sign` or `gov_slash_operator`.
  Delete `state/circle.toml`; the next boot derives a fresh
  `circle_id` (which won't be slashed because it's brand new) and
  redeploys.
- **register_circle reverted with "initial stake below minimum"** —
  the wallet's OU balance is below `MIN_CIRCLE_STAKE` (1000 OCT by
  default). Fund the wallet via the faucet (devnet) or buy more
  OCT (mainnet) and rerun.
- **deploy_circle was submitted but never confirmed** — wait for the
  chain to catch up; the local cache records the in-flight hash so
  a restart resumes without re-deploying.

## Implementation pointers

- v2 chain helpers: `crates/octravpn-node/src/chain_v2.rs`
- v2 register orchestration: `crates/octravpn-node/src/hub.rs`
  (`register_endpoint_v2`)
- Config flag: `[chain].protocol_version = "v2"` —
  `crates/octravpn-node/src/config.rs::ProtocolVersion`
- Foundry reference impl: `octra-foundry/crates/octra-cli/src/cast/circle.rs`
  (`predict`, `deploy`, `put_encrypted`)
- v2 AML: `program/main-v2.aml`
- Inner operator circle (design-only): `program/operator-circle.aml`
