# OctraVPN v2 — client flow

This document walks through the v2 (circle-native) tailnet flow from a
member's perspective. The v1.1 flow is preserved; v2 is gated on a
config switch so older clients keep working.

For the chain-side substrate see [`program/main-v2.aml`](../program/main-v2.aml)
and [`program/operator-circle.aml`](../program/operator-circle.aml). For
the design narrative see [`docs/v2-circles-design.md`](v2-circles-design.md).

## TL;DR diff vs v1.1

|                          | v1.1                                                | v2                                                            |
|--------------------------|-----------------------------------------------------|---------------------------------------------------------------|
| Operator discovery       | `list_active_endpoints` → public `endpoints[op]`    | `authorized_circles[tid]` → per-tailnet circle set            |
| Endpoint URL + WG pubkey | Plaintext on chain                                  | AES-GCM sealed under `/policy.json` inside the circle         |
| Auth shape               | Open registry; anyone can list every operator       | Only tailnet members can decrypt the policy                   |
| Session call             | `open_session(tailnet_id, exit_addr, max_pay)`      | `open_session(tailnet_id, circle, class, max_pay)`            |
| Tariff axes              | One `price_per_mb` per endpoint                     | `price_per_mb_shared` + `price_per_mb_internal` per circle    |

The split is unchanged in spirit: **main-net handles money, the Circle
handles identity + policy + metering**.

## 1. Joining a v2 tailnet

A v2 member needs three things provisioned out-of-band:

1. **Wallet keypair** — same as v1.1; stored under `[wallet].secret_path`.
2. **Tailnet membership** — they were either `add_member`-ed by the
   tailnet owner, or they `redeem_join_token` themselves against a
   token the owner published.
3. **Sealed-policy passphrase** — a shared per-tailnet secret. The
   tailnet owner picked it at deploy time when running
   `cast circle put-encrypted --passphrase <…> --key-id default`
   against each authorized circle's `/policy.json`. The same secret is
   shared with every member off-chain (PGP, vault, signal, whatever).

The passphrase resolves from any of these, in precedence order:

```
$OCTRAVPN_SEALED_PASSPHRASE         (env)         > 
--secret <…>                        (CLI flag)    >
[v2].sealed_passphrase              (client.toml)
```

The CLI never *prompts* for the passphrase — set the env, pass `--secret`,
or store it in `client.toml`. (If you store it on disk, ensure the file
is chmod 0600; running `octravpn init` already does that for the wallet.)

A minimal v2-flavored `client.toml`:

```toml
[chain]
rpc_url          = "https://octra.network/rpc"
program_addr     = "oct3fxjrzfqh65ATo31eau8xRFBPiXh2Uzwue56EYkfVSj7"   # v2 program
protocol_version = "v2"

[wallet]
addr        = "octABC…"
secret_path = "/var/lib/octravpn/wallet.key"

[v2]
# Optional — env is the recommended channel for production. The field
# is here for dev / single-user setups.
sealed_passphrase = "correct horse battery staple"
key_id            = "default"
cache_dir         = ""           # empty → $XDG_CACHE_HOME/octravpn/policies
```

If `[chain].protocol_version` is omitted or set to `"v1.1"`, the v2
commands return a clear error and the v1.1 flow keeps working
unchanged.

## 2. Discovery in a normal run

Day-to-day, a member runs:

```
octravpn discover v2 <tailnet_id>
```

What happens:

1. The client reads the v2 program's `authorized_circles[tid]` map.
   It does this by calling `get_tailnet(tid)` with the raw RPC envelope
   and scraping storage keys of the shape
   `authorized_circles:<tid>:<circle_addr>` with value `"1"`.
   *(Yes, this is a workaround until the AML exposes a proper view.
   When that lands the client will switch over without breaking the
   on-disk surface.)*
2. For each circle, the client computes
   `resource_key(circle_id, "/policy.json")` locally and calls
   `circle_asset_ciphertext_by_resource_key(circle_id, resource_key)`.
   The resource key is path-private — chain observers can't tell which
   asset path you asked for.
3. The client attempts `decrypt_sealed_bytes(circle_id, key_id,
   passphrase, ciphertext_b64, plaintext_hash)`. Three outcomes:
   - **Open** — decrypt succeeds, JSON parses. Row prints region +
     shared/internal tariffs + policy version.
   - **Opaque** — decrypt fails (wrong passphrase / not a member of
     this tailnet). Row prints `[opaque]` with a friendly message.
   - **Unpublished** — operator hasn't sealed a policy yet. Row prints
     `[no policy yet]`.
4. Successful decrypts are written to `<cache_dir>/<circle_id>.json`
   keyed on the plaintext_hash. Next run, if the chain returns the same
   plaintext_hash, the cached copy is reused without re-decrypting.

The decrypted policy carries:

```json
{
  "endpoint": "vpn-us-east.example:51820",
  "wg_pubkey_b64": "AAAA...",
  "region": "us-east",
  "price_per_mb_shared": 10,
  "price_per_mb_internal": 0,
  "policy_version": 7,
  "attestation_ts": 1700000000
}
```

To connect against the first decryptable circle:

```
octravpn connect-v2 \
  --tailnet-id 0 \
  --class shared \
  --deposit 1000000
```

To pin a specific circle (the operator menu output prints these):

```
octravpn connect-v2 \
  --tailnet-id 0 \
  --circle-id oct…SomeCircleAddr \
  --class internal \
  --deposit 1000000
```

The client submits `open_session(tid, circle, class, max_pay)` against
the v2 program, polls for the `SessionOpened` event, and prints the
decrypted WG handoff (PublicKey + Endpoint + AllowedIPs) so an external
WG implementation can dial. *(Bringing the boringtun side up against
the decrypted endpoint is parallel work in `octravpn-node`.)*

## 3. Cache invalidation

Cached policies live at `<cache_dir>/<circle_id>.json`. The cache is
**correctness-preserving**, not security-preserving — treat the
plaintext on disk the same as the passphrase that decrypted it. Default
location: `$XDG_CACHE_HOME/octravpn/policies/` or
`~/.cache/octravpn/policies/`.

The cache invalidates automatically when the operator publishes a new
sealed asset (the chain's `plaintext_hash` changes ⇒ cache miss ⇒
re-decrypt). Two manual escape hatches:

```
# Drop one circle's cached policy.
octravpn discover invalidate --circle-id oct…SomeCircleAddr

# Drop every cached entry.
octravpn discover invalidate --all

# Force a fresh fetch + decrypt without dropping the cache first.
octravpn discover v2 <tailnet_id> --refresh
```

Reasons to invalidate manually:

- Operator rotated the sealed asset out-of-band and the cached
  plaintext_hash check hasn't caught up yet (e.g. CDN caching).
- You changed the tailnet passphrase (cached plaintext still decrypts
  under the old key; force-refresh re-derives the read key).
- You're switching between key ids and the cached entry was sealed
  under a different one.

## 4. Failure modes

| Symptom                                                                | Likely cause                                                                              | Fix                                                                              |
|------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| `v2 subcommands require [chain].protocol_version = "v2"`               | Config still says v1.1                                                                    | Edit `client.toml`, set `protocol_version = "v2"`                                |
| All circles show `[opaque]`                                            | Wrong passphrase / wrong key_id, or you're not a member                                   | Re-check the secret with the tailnet owner; confirm `add_member`                 |
| `no authorized circles found for tailnet <id>`                         | Owner hasn't called `authorize_circle(tid, circle_addr)` yet                              | Ask the owner to authorize; or you have the wrong tailnet_id                     |
| `no sealed-policy passphrase available`                                | Env unset, no `--secret`, config field empty                                              | Set `OCTRAVPN_SEALED_PASSPHRASE`, pass `--secret`, or fill the config            |
| One circle shows `[no policy yet]`                                     | Operator registered but hasn't `circle_asset_put_encrypted`-ed `/policy.json`             | Ask the operator to publish policy; benign for newly-registered exits           |
| `circle <id> fetch error: …`                                           | RPC error or non-decryptable response shape (mock RPC, unsupported method)                | Check `octravpn doctor`; verify the RPC endpoint speaks v2                       |

## 5. Backwards compatibility

The v1.1 flow is **untouched**. Specifically:

- `octravpn nodes`, `octravpn connect`, `octravpn settle`, `octravpn reclaim`
  all behave exactly as before and target the v1.1 program when
  `protocol_version` is `"v1.1"` (the default).
- The v2 commands (`discover v2`, `connect-v2`) are additive. They
  refuse to run unless the config explicitly opts into v2, so an old
  config never accidentally hits the v2 RPC.

To run both v1.1 and v2 client configs side-by-side, keep two
`client.toml` files and pass `--config <path>` (or set
`OCTRAVPN_CONFIG`).

## 6. Operator-side context

The operator daemon is parallel work in `octravpn-node`. From the
client's perspective the contract is:

- Operator deploys their own circle (v2 program already has a
  reference operator circle in `program/operator-circle.aml`).
- Tailnet owner runs `register_circle` (main-v2) and
  `authorize_circle(tid, circle_addr)`.
- Operator runs `cast circle put-encrypted <circle_id> /policy.json
  ./policy.json --passphrase <tailnet-secret>` to seal the JSON.
- Operator periodically re-seals to bump `policy_version` and rotate
  WG keys; cache invalidates on each plaintext_hash change.

When the operator side lands, the integration test will exercise:

1. `cast circle deploy` an operator circle.
2. `cast circle put-encrypted /policy.json` with a fixed passphrase.
3. v2 program: `create_tailnet`, `add_member`, `authorize_circle`.
4. `octravpn discover v2 <tid>` — assert decrypted policy matches input.
5. `octravpn connect-v2 --circle-id …` — assert `SessionOpened`
   event surfaces, `session_id` is returned, WG handoff matches the
   sealed policy.

That test lives under `docker/devnet/e2e-v2-client.sh` (planned;
keep the harness docker-only per the project convention).
