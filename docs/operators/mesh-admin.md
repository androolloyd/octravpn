# Mesh admin surface

The mesh admin surface is the HTTP control plane the operator uses to
inspect and mutate a running mesh. It is mounted by BOTH:

- the **full Hub daemon** (`octravpn-node` with `[control]` + `[chain]`
  configured), and
- the **Hub-free `mesh serve`** shell
  (`octravpn-node mesh serve --admin-token <T>`) used in the
  `mesh-demo` and `tailscale-interop` docker stacks.

Both shells call the same `octravpn_mesh::build_admin_router` builder
over an `AdminState`, so the on-wire shape never drifts between them.

## Auth posture

The whole admin router is wrapped in
`octravpn_core::bearer::BearerCheck::hidden`. Every reject reason
(no token configured, missing header, wrong bearer) returns the
byte-stable `(404, NGINX_404_BODY)` shape — same Audit-3 H-1 invariant
`/events` and `/admin/preauth` already enforce. An external probe can
NOT tell whether the surface exists.

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

If the token is unset, the surface is not mounted at all — requests fall
through to the outer axum 404 fallback, which emits the same on-wire
bytes as the Hidden-mode rejection. Operators MUST set a long random
token in production.

## Routes mounted in BOTH shells

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
