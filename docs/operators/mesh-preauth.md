# Operator guide: minting mesh preauth keys

`octravpn-node mesh mint-preauth` is the operator surface for emitting
Tailscale-style preauth keys (`octrapreauth-…`) that a joining
`tailscale up --authkey "$KEY"` redeems against the daemon's wire
control plane. The same command has **two modes** — the only
difference is whether the key is bound to the running daemon's
persistent minter or not.

## Mode 1 — local mint (default)

```sh
KEY=$(octravpn-node mesh mint-preauth --user alice)
echo "$KEY"   # octrapreauth-…
```

The key is generated **in-process inside the CLI** with no daemon
contact. Useful for:

  * Shell scripting where you only need the key shape (e.g. the
    Tailscale-interop "reachable surface" probe).
  * Offline / smoke-test paths where no daemon is running.

**Limitation.** The running daemon does **not** know about this key.
A real `tailscale up --authkey "$KEY"` join against a live mesh
control plane will be rejected — the daemon's `register` handler
looks the key up against its `PreauthMinter` instance and finds
nothing.

## Mode 2 — daemon-bound mint (recommended for joins)

```sh
KEY=$(octravpn-node mesh mint-preauth \
    --user alice \
    --remote http://127.0.0.1:51821 \
    --admin-token "$ADMIN_TOKEN")
tailscale up --login-server http://mesh-control:51821 --authkey "$KEY"
```

The CLI POSTs `{user, reusable, ttl_secs}` to `<remote>/admin/preauth`
with `Authorization: Bearer <admin-token>`. The daemon's persistent
`PreauthMinter` materialises the key so it survives across process
boundaries — and is honoured by a real `tailscale up` join.

Both `--remote` and `--admin-token` are clap-`requires`-linked:
supplying one without the other prints a clear parse error rather
than failing later with a 401.

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--user` | string | `default` | User label bound into the key. |
| `--reusable` | bool | off | Off = single-use (safer Tailscale default). |
| `--ttl-secs` | u64 | `DEFAULT_PREAUTH_TTL` (3600) | Best-effort: current daemon hard-codes the TTL. |
| `--remote` | URL | _unset_ | Switches to daemon-bound mode. |
| `--admin-token` | string | _unset_ | Bearer token; required when `--remote` is set. |

### Where the admin token comes from

The bearer is the value of `[control].admin_token` in the daemon's
`node.toml`:

```toml
[control]
listen = "0.0.0.0:51821"
admin_token = "rotate-me-via-1password"
```

When the field is unset, the daemon's `BearerCheck::Hidden` gate
returns `404` for **every** request to `/admin/preauth` (including
authenticated ones) — the endpoint is effectively disabled. The CLI
maps that 404 to a clear "admin surface disabled" message so the
operator knows to set `admin_token` rather than chase a phantom auth
bug.

When the operator sets `admin_token` but supplies the wrong bearer,
the same `BearerCheck::Hidden` posture returns `404` (so external
scanners can't fingerprint the endpoint). For interactive ops use,
swap to `BearerCheck::Strict` (config: `admin_hidden = false`) and
the CLI will surface a real `401` mapped to:

```
admin token rejected (check [control].admin_token in node.toml on the daemon at http://…)
```

### Error mapping reference

| Daemon response | CLI message |
|---|---|
| connect refused | `daemon at <remote> not reachable` |
| `401` / `403` | `admin token rejected (check [control].admin_token …)` |
| `404` (Hidden mode) | `… either the admin surface is disabled or the bearer was rejected …` |
| `503` | `admin surface disabled — daemon started without [control].admin_token` |
| any other non-2xx | full `<method> <url>: <status>: <body>` for debugging |

## Mode 3 (escape hatch) — raw HTTP

Operators who already speak HTTP and don't want `octravpn-node` as a
build dep can call the same endpoint directly:

```sh
curl -fsS \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    --data '{"user":"alice","reusable":false}' \
    http://127.0.0.1:51821/admin/preauth
```

The response envelope is `{"key": "octrapreauth-…", "user": "alice",
"reusable": false, "expires_at": <unix-secs>}` — same shape Mode 2's
CLI parses.

## stdout / stderr contract

In both Mode 1 and Mode 2 the **key alone goes to stdout** (a single
line, no trailing whitespace beyond the newline). The diagnostic
preamble (`minted preauth: user=… reusable=… expires_at=…`) goes to
stderr. This keeps the `KEY=$(...)` shell-capture idiom working
byte-identically across modes.

```sh
# This shell pattern works in either mode.
KEY=$(octravpn-node mesh mint-preauth --user alice [--remote … --admin-token …])
```

## See also

  * `docs/reference/cli-octravpn-node.md` § `mesh mint-preauth` —
    flag reference (the docs/reference page is the auto-generated
    surface; this page is the operator playbook).
  * `crates/octravpn-node/src/control/handlers/preauth.rs` — the
    server-side handler.
  * `crates/octravpn-mesh/src/headscale_bridge/preauth.rs` — the
    persistent `PreauthMinter` that survives across process
    boundaries.
