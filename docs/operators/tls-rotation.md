# TLS pin and rotation runbook

This runbook covers TLS material for two distinct surfaces that an
OctraVPN operator runs:

1. **Validator / control-plane HTTPS** — the `mesh serve` `https_addr`
   listener (`crates/octravpn-node/src/main.rs:566-573`). Stock
   Tailscale clients dial the `:443` endpoint over rustls; the cert is
   minted by `tls::SanConfig::with_hostname` and persisted under
   `[control].tailscale_wire_state_dir` (see
   `crates/octravpn-node/src/config.rs:294-302`).
2. **DERP relay** — the sidecar referenced by the Tailscale-interop
   harness. The cert is minted by `run-interop.sh` step 1b (see
   `docker/devnet/tailscale-interop/run-interop.sh:157-180`) into
   `docker/devnet/tailscale-interop/derp-certs/{derp-1.crt,derp-1.key}`
   and consumed by `cmd/derper --certmode=manual` (see
   `docker/devnet/tailscale-interop/Dockerfile.derper:36-46`).

The chain RPC TLS trust roots are a separate concern (pinned via
`[chain].pinned_root_paths` in `node.toml`, plumbed through
`octravpn_core::rpc::RpcClient::new_with_pinned_roots` at
`crates/octravpn-core/src/rpc.rs:93`). Rotating those means updating
the *remote* CA bundle the operator pins, not minting new material on
this host — see the "Chain RPC roots" section at the end.

## Where TLS material lives

| Surface | Cert path | Key path | Owner | Trust |
|---------|-----------|----------|-------|-------|
| `mesh serve` HTTPS | `${state_dir}/tls/cert.pem` | `${state_dir}/tls/key.pem` | `octravpn-node` (root-owned, 0600 key) | self-signed; clients pin via `oct://` URL fingerprint (see `crates/octravpn-client/src/portal/chain.rs:609`) |
| DERP sidecar | `${SCRIPT_DIR}/derp-certs/derp-1.crt` | `${SCRIPT_DIR}/derp-certs/derp-1.key` | host operator | self-signed, SAN `DNS:derp-1`; peers install via `update-ca-certificates` in their container |
| Chain RPC (devnet) | `${chain.pinned_root_paths[i]}` | (none — read-only) | operator | PEM bundle pinned in `node.toml`; trust applies to outgoing RPC calls |

`state_dir` is `[control].tailscale_wire_state_dir` from `node.toml`;
defaults to `./state/tailscale-wire` (see
`crates/octravpn-node/src/config.rs:294-302`).

## How `oct://` clients pin the cert

The Tailscale-wire HTTPS cert is self-signed by default. Stock
Tailscale clients verify it against the system trust store; OctraVPN
clients verify against the SPKI fingerprint embedded in the `oct://`
URL the operator publishes. The fingerprint check happens at the rustls
layer before any HTTP traffic flows — a swapped cert without a matching
fingerprint surfaces as a TLS handshake failure, never a soft-warn.

When the cert is rotated, the SPKI fingerprint *changes if and only if
the public key changes*. The rotation script below preserves the key
across rotations by default; new fingerprints only get published when
the operator passes `--rekey` (see "Recovering from a compromised key"
below).

## How preauth flows handle a cert change mid-session

The preauth-key minter (`POST /admin/preauth` at
`crates/octravpn-node/src/control.rs:381`) is bearer-token-gated, and
the token is sent over the same TLS session that delivers the minted
key. Cert rotation mid-flow has three sub-cases:

1. **Drain-then-swap (the default).** The script below stops accepting
   new connections, waits for in-flight `/admin/preauth` requests to
   complete (they take <50 ms), then rebinds with the new cert. Open
   `/events` SSE streams reconnect on their own — they tolerate up to
   the default `EventSource` retry of ~3 s (browser-driven; the daemon
   does not control the retry interval).
2. **Hot-reload (TODO).** Not yet implemented. The current binary does
   not watch the cert files for changes; a `SIGHUP` is treated as
   "exit". A hot-reload path is tracked in
   `docs/security-roadmap.md` under "live cert rotation".
3. **Hard rotate (compromised material).** The operator first revokes
   the old key (see below), then runs the rotation script with
   `--rekey`. Every in-flight preauth response is dropped — the client
   re-mints on a fresh TLS session.

The minted preauth keys themselves do NOT carry a TLS fingerprint;
they are short-lived (`DEFAULT_PREAUTH_TTL` from `octravpn-mesh`) and
the redemption check is at the wire-noise layer, not the TLS layer.
A mid-flight cert change therefore does not invalidate any
already-minted preauth that has not been redeemed yet.

## Without-downtime rotation (the common path)

The rotation script `scripts/operators/rotate-tls.sh` automates the
five-step dance:

1. **Back up** the current cert+key to
   `${state_dir}/tls/backup/<timestamp>/`.
2. **Mint** new material with the same SAN list as the current cert.
   When `--rekey` is absent, the existing private key is reused so the
   SPKI fingerprint is preserved and pinned `oct://` URLs keep working.
3. **Validate** the new cert: it parses, the SAN matches, the
   not-before/not-after window covers `now + 24h` to `now + min_days`,
   and the cert+key pair are mathematically consistent
   (`openssl x509 -modulus` vs. `openssl rsa -modulus`).
4. **Atomic swap**: `mv` the new files into place (same filesystem ⇒
   `rename(2)` is atomic) and send `systemctl reload` (which the node's
   systemd unit translates to "graceful reopen"). Daemons that don't
   support `reload` get a `restart` with `--no-block`.
5. **Observe**: poll `/health` for `tls_cert_not_before` to advance
   past the timestamp of the backed-up cert (the metric is exported by
   `metrics()` at `crates/octravpn-node/src/control.rs:567`; if absent,
   the script falls back to comparing `openssl s_client -showcerts`
   output against the backup).

The script is idempotent: re-running with the same args is a no-op
when the on-disk cert already matches what step 2 would produce.

## Recovering from a compromised key

If the private key is leaked or suspected to be:

1. Revoke external trust first. For DERP, push a new `DerpMap` with
   the compromised region disabled; for the validator HTTPS surface,
   pull the operator's listing from the public node directory (or
   coordinate via the chain-side `slash` if the operator opted into
   on-chain attestation — see `docs/security-roadmap.md`).
2. Run `scripts/operators/rotate-tls.sh --rekey`. This forces a fresh
   keypair, so the SPKI fingerprint changes. Any pinned `oct://` URL
   pointing at this operator is now invalid; clients see a TLS pin
   mismatch and refuse to connect, which is the desired behaviour —
   they fall back to the operator's other endpoints (if listed) or
   surface a hard error to the user.
3. Publish a fresh `oct://` URL carrying the new fingerprint. The
   `oct-url-handler` flow at `docs/oct-url-handler.md` documents how
   the URL is constructed; the fingerprint is the SPKI sha256.
4. Audit the audit log for any preauth mints between the suspected
   compromise time and the rotation. The journal is at
   `[control].receipt_journal_path` (default `./state/receipts.bin`,
   see `crates/octravpn-node/src/config.rs:271-282`); decode with
   `octravpn-node audit dump` (see
   `crates/octravpn-node/src/audit_cli.rs`).

## Verifying the rotation took effect

```
# 1. New cert is served
openssl s_client -connect <host>:443 -servername <san> </dev/null 2>/dev/null \
  | openssl x509 -noout -dates -fingerprint -sha256

# 2. Old SPKI is gone (if --rekey was passed)
openssl s_client -connect <host>:443 -servername <san> </dev/null 2>/dev/null \
  | openssl x509 -noout -pubkey \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256

# 3. Daemon is healthy
curl -sf https://<host>:443/health
```

The `/health` endpoint bypasses the rate-limit layer
(`crates/octravpn-node/src/rate_limit.rs::classify`) and is unauth, so
it is safe to poll from a deploy pipeline.

## Chain RPC roots

`[chain].pinned_root_paths` in `node.toml` (see
`crates/octravpn-node/src/config.rs:148-157`) pins the trust roots
for *outgoing* RPC to the Octra chain endpoint. Rotation here is
operator-driven and asynchronous from the daemon process:

1. Obtain the new PEM bundle from the chain endpoint operator.
2. Place it at the same path the daemon already reads (so the daemon
   sees an in-place update at next restart).
3. Restart the daemon (`systemctl restart octravpn-node`). There is no
   hot-reload for `pinned_root_paths`; the file is read once at
   `Hub::new` (see `crates/octravpn-node/src/hub.rs:1155-1171`).

If multiple bundles are listed, the daemon ORs them — useful during a
cutover window where both the old and new roots should be trusted.
Remove the old bundle after the cutover.

## Calendar

- Rotate `mesh serve` HTTPS material every **90 days** under normal
  conditions, every **30 days** when the cert chain depth is >1 (i.e.
  not a self-signed leaf).
- Rotate DERP material every **30 days** — the `gen-derp-cert.sh` step
  in the harness mints with `-days 30`, so anything older than that is
  already a misconfiguration.
- Rotate the chain RPC pinned bundle when the chain endpoint operator
  publishes a new root — there is no fixed schedule; subscribe to
  their announcement channel.

## Failure modes and recovery

| Symptom | Likely cause | Recovery |
|---------|--------------|----------|
| `tls handshake failed: pin mismatch` on every client | `--rekey` was run but the new fingerprint was not published | publish the new `oct://` URL OR restore from backup at `${state_dir}/tls/backup/<latest>` |
| `/health` returns 200 but `s_client` shows old cert | listener was not reloaded | `systemctl reload octravpn-node` then re-poll |
| DERP peer `failed to dial relay 1: x509: certificate has expired` | DERP cert past its 30-day window | re-run `run-interop.sh` step 1b; restart `derp-1` container |
| Daemon refuses to start: `tls: private key does not match public key` | partial swap (cert from one mint, key from another) | restore from `${state_dir}/tls/backup/<latest>` and re-run the script |

## PSK-gated control plane

> Optional. Default-off. Operators running on a network where active
> probing of the wire surface is plausible (state-level censors that
> sweep candidate IPs for the "Tailscale fingerprint" — observed in
> 2024–2026 GFW reports) should enable this. Operators on plain LAN
> deployments don't need it.

The Tailscale-wire control plane (`/key`, `/ts2021`,
`/machine/register`, `/machine/map`) speaks the same shapes as
upstream Tailscale, which means a probe that completes the Noise IK
handshake against our endpoint gets the same positive signal it
would from any tailnet — useful to a censor who wants to enumerate
control planes to block. The PSK-gated handshake layer prevents that
by requiring an out-of-band shared secret before the wire surface
will even respond.

When the gate is enabled, every request must carry one of:

  * **`X-OctraVPN-Knock: <hmac16>`** header — used by our own
    `octravpn` CLI (`mesh status`, `mesh policy …` per `#232`). Stock
    Tailscale clients cannot add custom HTTP headers and use the path
    variant below.
  * **`/k/<hmac16>/<rest-of-path>` URL prefix** — the
    operator-distributed `--login-server` URL embeds the knock as a
    path segment, e.g.
    `tailscale up --login-server https://node.example.org/k/abcdef0123456789 --authkey octrapreauth-…`.

The `hmac16` is the first **8 bytes** of
`HMAC-SHA256(psk, floor(unix_seconds / window_secs).to_string())`,
hex-encoded → 16 ASCII chars. Default `window_secs = 60`. A knock is
valid for both the current window and the next window (forward
clock-skew tolerance), so the effective TTL is between 60 and 120
seconds depending on when the client mints it.

Any request that fails the gate — missing knock, wrong knock, expired
window, malformed prefix — gets the canonical nginx 1.18 "404 Not
Found" page (byte-for-byte identical across attempts; see
`tailscale_wire::knock::NGINX_404_BODY`). To a probe, the wire surface
is indistinguishable from a stock nginx that has nothing mounted at
the requested path.

### Generating the PSK

The PSK is 32 raw bytes, distributed as a base64 string. Mint with:

```bash
openssl rand 32 | base64 > /etc/octravpn/knock.psk
chmod 0600 /etc/octravpn/knock.psk
```

Or, for the inline-in-`oct://`-URL variant:

```bash
openssl rand 32 | base64
# Embed the output as `?knock_psk=<base64>` in the URL you publish to
# peers. The portal in `crates/octravpn-client/src/portal/` strips this
# query parameter before dispatching the rest of the URL (see
# `octravpn_mesh::knock::parse_knock_psk_query`), so the PSK is never
# leaked into chain/fetch handlers.
```

### Distributing the PSK

The PSK travels alongside the preauth key in the same out-of-band
channel the operator already uses (Signal, Keybase, a printed
QR-code at a tradeshow booth — pick whatever channel you trust). It
is NOT secret in the cryptographic sense — knowing it lets a probe
complete the knock, but the underlying Noise IK handshake still
needs a valid preauth key, an authorised `mkey:` identity, etc. The
knock layer is a *prefilter*, not the only line of defence.

That said, treat the PSK with the same care as the preauth key. A
state-level adversary that scrapes the PSK from a public forum will
be able to detect-and-block the endpoint just like any other
operator's deployment.

### Enabling the gate on the node

Wire it up via three environment variables read by `mesh serve` at
startup (see `crates/octravpn-node/src/main.rs::load_knock_cfg_from_env`):

```bash
export OCTRAVPN_KNOCK_ENABLED=1
export OCTRAVPN_KNOCK_PSK="$(cat /etc/octravpn/knock.psk)"
# Optional — defaults to 60s. Wider windows tolerate more clock skew
# but increase the replay window.
export OCTRAVPN_KNOCK_WINDOW_SECS=60

octravpn-node mesh serve --listen 0.0.0.0:51821 --https-listen 0.0.0.0:443 \
    --state-dir /var/lib/octravpn/wire --tailnet-id tnt-prod
```

Startup logs `mesh serve: PSK-gated handshake ENABLED (window=60s)`
when the gate is live. A non-empty `OCTRAVPN_KNOCK_ENABLED` with a
missing or unparseable `OCTRAVPN_KNOCK_PSK` logs a warning and
disables the gate (rather than rejecting every connection).

### CLI tools

`octravpn-node mesh status` / `mesh policy {get,set,validate}` wrap
the admin routes (`#232`). They read `OCTRAVPN_KNOCK_PSK` from the
environment and prepend the `X-OctraVPN-Knock` header on every
request — set the env var in the same shell session before invoking
them:

```bash
export OCTRAVPN_KNOCK_PSK="$(cat /etc/octravpn/knock.psk)"
export OCTRAVPN_ADMIN_TOKEN="op-bearer-token"
octravpn-node mesh status --remote https://node.example.org
```

Without the env var, the CLI sends no knock and gets a generic 404
back from a knock-enabled node.

### Stock-tailscale-client interop

Stock `tailscale up` can't add HTTP headers. Use the path-prefix
variant: publish per-peer `--login-server` URLs that already embed
the current knock:

```bash
# On the operator's side, when minting a preauth key + URL bundle
# for the peer:
WIN=$(( $(date +%s) / 60 ))
KNOCK=$(printf %s "$WIN" | openssl dgst -sha256 -hmac "$(cat /etc/octravpn/knock.psk | base64 -d)" -binary | head -c 8 | xxd -p)
echo "tailscale up --login-server https://node.example.org/k/$KNOCK --authkey $PREAUTH_KEY"
```

Because the knock rolls every 60 seconds, the URL has the same
short-lived character as the preauth key itself: mint it for the
peer, expect them to use it inside the window. If they don't, mint
another. The intent matches how preauth-key flows already work in
production — operators mint a fresh URL per peer onboarding.

For peers running our `octravpn` client, the PSK can be embedded
directly in the `oct://` URL via `?knock_psk=<base64>`; the portal
strips and applies the knock automatically without any environment
plumbing.

### Rotating the PSK

The PSK is a 32-byte secret with the same lifetime expectations as a
TLS root cert: rotate when (a) you suspect a peer has been
compromised and may have leaked it, or (b) on a calendar cadence of
your choice (no fixed maximum lifetime — the per-window HMAC means
a leaked PSK can be revoked instantly by minting a new one, no
on-chain coordination needed).

To rotate:

1. Mint a new PSK (`openssl rand 32 | base64 > /etc/octravpn/knock.psk.new`).
2. Restart `octravpn-node mesh serve` with `OCTRAVPN_KNOCK_PSK`
   pointing at the new file. The next minute, every peer carrying
   the old PSK starts seeing nginx-404s.
3. Distribute the new PSK alongside a fresh preauth key to each
   peer through the same out-of-band channel.
4. `mv /etc/octravpn/knock.psk.new /etc/octravpn/knock.psk` on the
   node host so the new PSK is the persisted default.

No grace period is built in — the gate is intentionally binary, the
way `Server-Authorization` would be. Operators who want to coordinate
a smooth cutover can run two listeners on different ports with
different PSKs and migrate peers between them.

### Constraints

- DO NOT change the Noise IK handshake bytes; the knock is a
  pre-handshake check that fires before the upgrade hijack.
- DO NOT enable the gate without a working out-of-band channel; a
  PSK shipped over insecure email is worth no more than a missing
  gate.
- The path-prefix variant has the PSK derivative visible in HTTP
  access logs along the wire path — for sensitive deployments,
  pair it with the existing rate-limit + audit log scrubbing.
