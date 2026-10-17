# Mesh admin surface

The mesh admin surface is the HTTP control plane the operator uses to
inspect and mutate a running mesh. It is mounted by:

- the **full Hub daemon** (`octravpn-node` with `[control]` + `[chain]`
  configured), and
- the **Hub-free `mesh serve`** shell
  (`octravpn-node mesh serve --admin-token <T>`) used in the
  `mesh-demo` and `tailscale-interop` docker stacks; and
- the native `octra-node` process when its `mesh` service is configured.

The hosts call the same `octravpn_mesh::build_admin_router` builder
over an `AdminState`, so the on-wire shape never drifts between them.
The Hub mounts it when its Tailscale wire state directory is configured.
The listeners share persistent users, machine registrations, preauth
credentials, API keys and ACL policy with their wire registration path. Minting, single-use redemption,
expiry and revocation use the same `machines.sqlite` database.

## Auth posture

The bootstrap bearer enables the admin surface. JSON API routes also accept
persisted Headscale API keys; revocation is checked on every request. HTML
routes and the legacy `/admin/preauth` shim require the bootstrap bearer.
Missing, invalid, expired or revoked credentials receive the same empty 404.
Browser cookies cannot authorize the API, and ambiguous Authorization headers
are rejected before routing.

To call the surface successfully:

```
curl -H "Authorization: Bearer ${OCTRAVPN_ADMIN_TOKEN}" \
     http://mesh-control:51821/api/v1/machines
```

The token is configured via:

| Shell | Source |
|-|-|
| Full Hub | `[control].admin_token` in `node.toml` (or the `OCTRAVPN_ADMIN_TOKEN` env var as fallback) |
| `mesh serve` | `--admin-token <T>` CLI flag (or the `OCTRAVPN_ADMIN_TOKEN` env var) |
| `octra-node` | `mesh.admin_token_file`; owner-only permissions on Unix |

If the token is unset, all admin routes remain hidden behind empty 404
responses, including on the public wire listener with its blank-200 fallback. Operators MUST set a long random
token in production.

## Native node configuration

Add `mesh` to the public-network or isolated devnet JSON configuration. Private
Single uses the same object under `single.services.mesh`:

```json
{
  "mesh": {
    "state_dir": "mesh",
    "tailnet_id": "personal-octranet",
    "http_addr": "127.0.0.1:51821",
    "https_addr": "0.0.0.0:443",
    "hostname": "control.example.com",
    "control_url": "https://control.example.com",
    "admin_token_file": "secrets/mesh-admin.token",
    "tls": {"certificate": "tls/fullchain.pem", "key": "tls/key.pem"},
    "dns": {
      "base_domain": "mesh.example.com",
      "override_local_dns": false,
      "extra_records": [
        {"name": "circles.example.com", "type": "A", "value": "100.64.0.1"}
      ]
    },
    "serve_derp": true
  }
}
```

File paths resolve against the node configuration's directory. The mesh service
owns its state directory exclusively and runs within the node's supervised
lifecycle. It retains its Noise identity, enrollment, API keys and ACL across
restarts. Omit `tls` only for development with explicitly trusted self-signed
certificates. Use HTTPS for remote administration; plaintext HTTP is intended
for a loopback reverse-proxy backend or an isolated test network.

The same service can run separately with `octravpn-node mesh run --service-config
mesh.json`; that JSON contains the mesh object itself. This supports a control
endpoint reachable over an existing VPN IP. Stock Tailscale needs to reach its
selected control endpoint before establishing a new tunnel, so first enrollment
needs an existing route, an optional reachable operator bootstrap, or a local
compatibility adapter. A deployment is not required to share a central bootstrap.

DNS configuration is distributed through client netmaps. An extra record directs
clients to a reachable service address; it does not create the gateway, a route,
a certificate or an `oct://` handler. The Circle gateway retains its separate
`gateway` configuration and requires an HTTPS reverse proxy. This configuration
does not enroll the local OS client or establish its VPN connection.

The gateway's `sites` map binds HTTPS DNS hostnames to published Circle assets:

```json
{
  "gateway": {
    "listen": "127.0.0.1:20803",
    "origin": "https://circles.octra.to",
    "sites": {"octra.to": "<published-Circle-address>"}
  }
}
```

For example, `/index.html` on `octra.to` resolves that Circle's `/index.html`.
HTML, CSS and subresources retain canonical snapshot checks and Circle isolation.
Missing assets return an error; there is no local website directory fallback.
Only configured hosts are accepted. The `sites` map creates no DNS records,
certificates or VPN routes. The HTTPS proxy must route native Tailscale control
and DERP paths to the mesh service; website paths go to the Circle gateway.

## Durable policy and API keys

Successful ACL updates commit to `machines.sqlite` before becoming live. A
failed write leaves the previous policy in place. Startup loads the persisted
policy before opening listeners; unreadable or malformed stored policy aborts
startup. An explicit empty ACL remains deny-all after a restart. A fresh store
with no ACL retains Headscale's existing default policy behavior.

Native DERP forwarding requires an explicit loaded ACL, live registered keys
and unexpired registrations for both peers. An empty ACL denies forwarding.
The relay rechecks both endpoints and peer adjacency on each incoming packet
and before writing queued packets. Circle-managed membership is checked from
the current verified member set even when registration-only enforcement is
disabled. Native node and Single launchers additionally gate new registration
and relay frames on their current canonical Serving publication; standalone
`mesh serve` remains controlled by its operator.

DERP carries encrypted packets. Its peer-adjacency check cannot enforce inner
destination ports, portal paths, tariffs or prepaid balances. Direct WireGuard
links remain subject to the endpoint's packet policy. These relay checks do not
establish paid stock-client enrollment or the bounded unpaid portal service.
Membership or Serving revocation is checked on the next frame or keepalive;
pair ACL changes are checked on each relayed packet. Already completed IO
cannot be recalled.

When Circle membership controls the Hub or `mesh serve` policy, admin policy
replacement returns 403. The verified Circle source owns those ACL updates.

`POST /api/v1/apikey` mints a key once. `GET /api/v1/apikey` returns metadata,
`POST /api/v1/apikey/expire` revokes by `id` or `prefix`, and
`DELETE /api/v1/apikey/:prefix` removes it. Stored keys are hashed. Turning off
the bootstrap token disables the whole admin surface, including stored keys.

## Routes mounted in each host

| Method + path | Purpose | Source |
|-|-|-|
| `GET  /api/v1/machines` | tailnet roster (used by `mesh status --remote …`) | `headscale_api::admin::api_machines_list` |
| `GET  /api/v1/machines/:id` | machine detail | `headscale_api::admin` |
| `POST /api/v1/machines/:id/{expire,logout,rename,tags}` | machine lifecycle | `headscale_api::admin` |
| `DELETE /api/v1/machines/:id` | remove from tailnet | `headscale_api::admin` |
| `GET  /api/v1/policy` | live hujson ACL doc (used by `mesh policy get --remote …`) | `headscale_api::admin::api_policy_get` |
| `PUT  /api/v1/policy` | replace ACL doc; wakes `/map` long-pollers within ~1 ms | `headscale_api::admin::api_policy_put` |
| `POST /api/v1/policy/validate` | parse-only validation | `headscale_api::admin::api_policy_validate` |
| `GET  /api/v1/preauthkeys` | list outstanding preauth keys | `headscale_api::admin::api_preauth_list` |
| `POST /api/v1/preauthkeys` | mint a new preauth key (JSON API) | `headscale_api::admin::api_preauth_mint` |
| `POST /api/v1/preauthkeys/:prefix/expire` | revoke a preauth key | `headscale_api::admin` |
| `GET  /api/v1/users` / `POST /api/v1/users` / `DELETE /api/v1/users/:name` | user CRUD | `headscale_api::admin::api_users_*` |
| `GET  /api/v1/tailnet` | tailnet summary | `headscale_api::admin::api_tailnet` |
| `GET  /admin/...` | operator HTML UI (login, dashboard, peers, policy, sessions) | `headscale_api::admin::page_*` |
| `POST /admin/preauth` | legacy in-process preauth mint shim (separate from `/api/v1/preauthkeys`); used by the interop test's `run-interop.sh` reachability probe | `octravpn-node` `mesh serve` + `octravpn-node` `ControlState` |

## Routes that stay Hub-only

Some routes have implementations that require the full Hub assembly
(chain RPC client, PVAC sidecar handle, wallet keypair). They are NOT
mounted by `mesh serve`, by design:

| Route | Why Hub-only |
|-|-|
| `POST /session`, `GET /session/:id` | Needs the wallet keypair to sign receipts AND the chain RPC client to verify the announce's `open_tx_hash`. |
| `GET  /events` (SSE) | Backed by the Hub's in-process `EventBus`, fed by the audit log + tunnel-side counters. `mesh serve` has no audit log writer. |
| `GET  /metrics` | Exposes Hub-internal `NodeMetrics` counters (tunnel bytes, receipt-sign latency, attestation freshness, etc.). |
| Tailscale-wire surface: `GET /key`, `POST /ts2021`, `POST /machine/:node_key/{register,map}` | Mounted by both shells but via `tailscale_wire_router(state)` — NOT through the admin router. Documented here only so operators don't expect it under `/api/v1/`. |

If a future release closes one of these gaps (e.g. wires an audit-log
writer into `mesh serve`), the corresponding route migrates into the
unified router and this table shrinks.

## Demo tapes that exercise the surface

- `demo/tapes/04-mesh-preauth.tape` — `mesh mint-preauth --remote …`
  hits `POST /admin/preauth`.
- `demo/tapes/08-3node-mesh.tape` — `mesh status --remote …` hits
  `GET /api/v1/machines`.
- `demo/tapes/09-traffic-patterns.tape` — `mesh policy get --remote …`
  hits `GET /api/v1/policy`.

The `mesh-demo` stack at the repo root
(`docker-compose.mesh-demo.yml`) sets `OCTRAVPN_ADMIN_TOKEN=mesh-demo-token`
in the `mesh-control` container so the tapes succeed against a local
bring-up of the stack.
