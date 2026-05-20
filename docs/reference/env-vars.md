<!-- captured from source at SHA 2ffead7 (2026-05-20) -->

# Environment variables

Every environment variable the OctraVPN binaries honour. Discovered by
grep-ing for `std::env::var` and `env = "…"` clap attributes across the
workspace.

## Audit-2 CFG-7 finding (precedence collisions)

The 2026-05-20 config audit flagged that several settings have **three
independent sources** (CLI flag, env var, TOML field) and the precedence
isn't uniform across them. The table below documents the actual order
each binary uses; where it differs from "CLI > env > config" the row is
marked with **(CFG-7)** so the next audit-fix pass can normalise the
precedence.

## Variable index

| Variable | Consumed by | Type | Notes |
|---|---|---|---|
| `OCTRAVPN_NODE_CONFIG` | `octravpn-node` | path | Path to `node.toml`. |
| `OCTRAVPN_CONFIG` | `octravpn` | path | Path to `client.toml`. |
| `OCTRAVPN_KEY_PASSPHRASE` | `octravpn-node`, `octravpn` | string | Passphrase for sealed wallet / WG keys. |
| `OCTRAVPN_SEALED_PASSPHRASE` | `octravpn-node`, `octravpn` | string | Passphrase for sealed circle assets. |
| `OCTRAVPN_ADMIN_TOKEN` | `octravpn-node mesh serve`, `mesh status` | string | Bearer token for the `POST /admin/preauth` and admin surfaces. |
| `OCTRAVPN_DERP_MAP_PATH` | `octravpn-node mesh serve` | path | Override DERP map file. |
| `OCTRAVPN_KNOCK_ENABLED` | `octravpn-node mesh serve` | any | Any non-empty value enables the knock layer. |
| `OCTRAVPN_KNOCK_PSK` | `octravpn-node mesh serve` | base64 | 32-byte secret. |
| `OCTRAVPN_KNOCK_WINDOW_SECS` | `octravpn-node mesh serve` | u64 | Knock validity window. Default 60. |
| `OCTRAVPN_MESH_INSECURE_TLS` | `octravpn-node mesh_ops` | any | Disable TLS verification (devnet/testing only). |
| `OCTRAVPN_CACHE_DIR` | `octravpn` | path | Override client cache directory. |
| `OCTRAVPN_SERVE_DIR` | `octravpn serve` | path | Override `serve.toml` location. |
| `HEADSCALE_URL` | `octravpn-node headscale …` | URL | Admin server URL. Equivalent to `--server`. |
| `HEADSCALE_ADMIN_TOKEN` | `octravpn-node headscale …` | string | Admin bearer. Equivalent to `--token`. |
| `PVAC_SIDECAR_BIN` | `octravpn-node` (when `[pvac].enabled`) | path | Override `[pvac].binary_path`. |
| `RUST_LOG` | every binary | tracing-env-filter | `info`, `info,octravpn=debug`, etc. Honoured via `tracing-subscriber`'s `EnvFilter`. |
| `HOME` | `octravpn` (tailnet.rs, v2_cache.rs) | path | Used to locate `~/.octravpn/tailnets/*.toml`. |
| `XDG_CACHE_HOME` | `octravpn` | path | Override default cache root before `HOME`. |
| `HOST` / `HOSTNAME` | `octravpn` (tailnet.rs) | string | Fallback hostname for MagicDNS. |

Total unique env vars: **19** (12 OctraVPN-namespaced, 2 headscale, 1 PVAC, 4 standard).

---

## Per-variable details

### `OCTRAVPN_NODE_CONFIG`

* **Binary.** `octravpn-node`.
* **Type.** Path to TOML config file.
* **Default.** `node.toml` (relative to cwd).
* **Precedence.** `--config` flag > this env var > built-in default.
  (Clap `env = "OCTRAVPN_NODE_CONFIG"`.)
* **Source.** `crates/octravpn-node/src/cli/mod.rs:69`.

### `OCTRAVPN_CONFIG`

* **Binary.** `octravpn`.
* **Type.** Path to client TOML.
* **Default.** `client.toml`.
* **Precedence.** `--config` flag > env > default.
* **Source.** `crates/octravpn-client/src/main.rs:29`.

### `OCTRAVPN_KEY_PASSPHRASE`

* **Binary.** `octravpn-node` (seal/unseal/run), `octravpn` (when
  reading sealed wallet/WG keys).
* **Type.** Free-form passphrase string.
* **Fallback.** If unset, the seal subcommands fall through to a TTY
  prompt; the daemon's `run` subcommand fails to boot with a clear
  error pointing the operator at `seal-keys`.
* **Precedence (seal-keys / unseal-keys).** `--passphrase` >
  `--passphrase-file` > `--passphrase-stdin` > this env > TTY prompt.
  See `crates/octravpn-node/src/seal.rs:52`.
* **Precedence (daemon `run`).** This env > none (no other source
  exists for the running daemon).

### `OCTRAVPN_SEALED_PASSPHRASE`

* **Binary.** `octravpn-node circle update / list-orphans`,
  `octravpn fetch`, `octravpn open-url`, `octravpn portal`, `octravpn discover`,
  `octravpn connect-v2`.
* **Type.** Passphrase for sealed circle assets (AES-GCM read key).
* **Precedence (`octravpn-node`).** `--passphrase` flag > this env >
  config field `[chain].sealed_passphrase` > error.
  (`cli/circle.rs:268` and `crates/octravpn-client/src/discover_v2.rs:145`.)
* **Precedence (`octravpn fetch`).** env > `--secret` > config > `-i`.
  **(CFG-7: env > flag, opposite of the rest of the surface.)**
* **Source.** Multiple call sites — see the discover_v2.rs comment at
  `:23` for the precedence note.

### `OCTRAVPN_ADMIN_TOKEN`

* **Binary.** `octravpn-node mesh serve` (`POST /admin/preauth`),
  `octravpn-node mesh status` (admin client), and the hub's spawn path
  for the Tailscale-wire bridge.
* **Type.** Bearer token string.
* **Fallback.** When unset AND `[control].admin_token` is unset, the
  `POST /admin/preauth` endpoint returns 404 (not 401 — the surface is
  hidden so scanners can't fingerprint it).
* **Precedence.** `--admin-token` flag > `[control].admin_token` field
  > this env. **(CFG-7: field > env, opposite of most others.)**
* **Source.** `cli/mesh.rs:239`, `hub/spawn.rs:91`, `config.rs:590`.

### `OCTRAVPN_DERP_MAP_PATH`

* **Binary.** `octravpn-node mesh serve`, hub spawn.
* **Type.** Path to a DERP map JSON file.
* **Default.** When unset, the embedded DERP map is used.
* **Source.** `cli/mesh.rs:251`, `hub/spawn.rs:143`.

### `OCTRAVPN_KNOCK_*` (knock-layer trio)

The "port-knocking" layer in front of `mesh serve`. All three opt-in
together:

* `OCTRAVPN_KNOCK_ENABLED` — any non-empty string enables the layer.
* `OCTRAVPN_KNOCK_PSK` — base64-encoded 32-byte secret. Required when
  enabled; if missing or undecodable, the layer is disabled with a
  stderr warning (`cli/mesh.rs:422`).
* `OCTRAVPN_KNOCK_WINDOW_SECS` — knock validity window. Default
  `DEFAULT_WINDOW_SECS` (60).

Source: `crates/octravpn-node/src/cli/mesh.rs:408-440`.

### `OCTRAVPN_MESH_INSECURE_TLS`

* **Binary.** `octravpn-node mesh_ops` (the admin client).
* **Type.** Any non-empty string disables TLS verification.
* **Use.** Devnet harnesses + self-signed mesh control planes. Never
  set in production.
* **Source.** `crates/octravpn-node/src/mesh_ops.rs:178`.

### `OCTRAVPN_CACHE_DIR`

* **Binary.** `octravpn`.
* **Type.** Path to a cache directory.
* **Precedence.** This env > `$XDG_CACHE_HOME/octravpn` > `$HOME/.cache/octravpn`.
* **Source.** `crates/octravpn-client/src/v2_cache.rs:148`.

### `OCTRAVPN_SERVE_DIR`

* **Binary.** `octravpn serve`.
* **Type.** Path containing `serve.toml`.
* **Fallback.** `$HOME/.octravpn/serve` when unset.
* **Source.** `crates/octravpn-client/src/commands/serve.rs:39` (const
  `SERVE_DIR_ENV`).

### `HEADSCALE_URL`

* **Binary.** `octravpn-node headscale …` (and the standalone
  `headscale` binary).
* **Type.** Admin server URL. Trailing `/` allowed.
* **Precedence.** `--server` flag > this env > error.
* **Source.** `headscale-rs/headscale-cli/src/admin/mod.rs:101`.

### `HEADSCALE_ADMIN_TOKEN`

* **Binary.** `octravpn-node headscale …`.
* **Type.** Bearer token string. Empty allowed.
* **Precedence.** `--token` flag > this env.
* **Source.** `headscale-rs/headscale-cli/src/admin/mod.rs:104`.

### `PVAC_SIDECAR_BIN`

* **Binary.** `octravpn-node` (only when `[pvac].enabled = true`).
* **Type.** Path to the PVAC sidecar binary.
* **Precedence.** This env > `[pvac].binary_path` > default
  `./pvac-sidecar/octra-pvac-sidecar`. **(CFG-7: env > field, opposite
  of the `OCTRAVPN_ADMIN_TOKEN` posture.)**
* **Source.** `crates/octravpn-node/src/pvac.rs:811`.

### `RUST_LOG`

* **Binary.** Every binary.
* **Type.** `tracing-subscriber`'s `EnvFilter` syntax.
* **Default.** `info` from the global subscriber init in each binary's
  `main`.
* **Examples.**

  ```
  RUST_LOG=info
  RUST_LOG=info,octravpn_node::hub=debug,octravpn_core::receipt=trace
  RUST_LOG=warn,octravpn=info
  ```

### `HOME`, `HOSTNAME`, `HOST`, `XDG_CACHE_HOME`

Standard. Their use sites:

* `HOME` — locating `~/.octravpn/tailnets/<name>.toml`
  (`crates/octravpn-client/src/tailnet.rs:155`) and the default cache
  root (`v2_cache.rs:158`).
* `HOST` / `HOSTNAME` — MagicDNS fallback hostname when `--hostname` is
  unset (`tailnet.rs:768`).
* `XDG_CACHE_HOME` — preferred cache root when set
  (`v2_cache.rs:153`).

---

## Precedence cheat sheet

Per the CFG-7 finding, there are **three patterns** in the wild:

| Pattern | Where | Settings |
|---|---|---|
| CLI > env > config (the intent) | Most subcommand flags with `env = "…"` clap attrs | `--config` / `OCTRAVPN_NODE_CONFIG`, `--server` / `HEADSCALE_URL`, `--token` / `HEADSCALE_ADMIN_TOKEN`, `--admin-token` / `OCTRAVPN_ADMIN_TOKEN` (CLI side) |
| Env > field > error | `OCTRAVPN_SEALED_PASSPHRASE` for circle subcommands | `cli/circle.rs:268` |
| Field > env | `[control].admin_token` for the hub's spawn path | `hub/spawn.rs:91`, `config.rs:585` |
| Env > flag > field > prompt | `octravpn fetch` (CFG-7) | `commands/fetch.rs` |

A future PR will normalise to "CLI > env > config" everywhere. Track in
the audit-fix worktree's checklist.

---

## Cross-references

* Config file fields these env vars override: [config.md](./config.md).
* CLI flags that participate in precedence: [cli-octravpn-node.md](./cli-octravpn-node.md), [cli-octravpn-client.md](./cli-octravpn-client.md), [cli-headscale-embedded.md](./cli-headscale-embedded.md).
* Sealed-keys workflow: `docs/v2-operator-key-hygiene.md`.
