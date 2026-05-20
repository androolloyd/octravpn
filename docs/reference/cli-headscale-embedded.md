<!-- captured from binary at SHA 2ffead7 (debug build, 2026-05-20) -->

# `octravpn-node headscale …` — embedded headscale admin CLI

The OctraVPN node binary includes the full `headscale_cli` admin surface
as a sub-CLI. Every invocation under `octravpn-node headscale …` is
**byte-identical** to the standalone `headscale` binary's admin command
of the same shape — same flags, same stdout, same `error:` envelope,
same exit-code contract. The fold-in exists so operators don't have to
juggle two binaries to manage a tailnet.

## Architecture and source

* Embedding entry: `crates/octravpn-node/src/cli/headscale.rs`
  (just a clap-flatten + a single `headscale_cli::dispatch` call).
* Dispatcher: `headscale-rs/headscale-cli/src/lib.rs::dispatch`.
* Subcommand definitions: `headscale-rs/headscale-cli/src/admin/mod.rs`
  (the `AdminCmd` clap enum).
* Per-command implementations:
  `headscale-rs/headscale-cli/src/admin/{users,nodes,preauthkeys,policy,tailnet}.rs`.
* Standalone equivalent binary: `headscale` (cargo target
  `headscale-rs/headscale-cli/src/main.rs`).
* Passthrough byte-diff test: `crates/octravpn-node/tests/headscale_cli_passthrough.rs`.

## Global options (apply to every subcommand)

```
Usage: octravpn-node headscale [OPTIONS] <COMMAND>
```

| Flag | Type | Default | Env override | Source |
|---|---|---|---|---|
| `--server <SERVER>` | URL | required | `HEADSCALE_URL` | `admin/mod.rs:101` |
| `--token <TOKEN>` | string | required | `HEADSCALE_ADMIN_TOKEN` | `admin/mod.rs:104` |
| `--json` | bool | off | — | `admin/mod.rs:107` |
| `-h, --help` | bool | — | — | clap derived |

`--server` accepts a trailing `/`. `--token` empty is allowed (some
admin builds disable bearer auth in tests) — the server returns 401 if
it's required.

## Exit-code contract

From `headscale-rs/headscale-cli/src/admin/mod.rs:75-81`:

| Code | Variant | Meaning |
|---|---|---|
| 0 | `Success` | Operation completed. |
| 3 | `Connection` | DNS / TCP / TLS / handshake failed — anything pre-status. |
| 4 | `Auth` | HTTP 401 / 403. Wrong or missing bearer. |
| 5 | `NotFound` | HTTP 404. User / node / preauth key not found. |
| 6 | `Server` | HTTP 5xx, or any other 4xx, or response-decode failure, or local file IO. |

The `octravpn-node headscale …` invocation forwards this code via
`std::process::exit` (`cli/headscale.rs:31`). Operators can cron-pipe
the subcommands and rely on the codes without parsing stderr.

## Subcommand index

| Subcommand | Section |
|---|---|
| `users create` / `list` / `delete` | [users](#users) |
| `nodes list` / `show` / `expire` / `logout` / `rename` / `tags` / `delete` | [nodes](#nodes) |
| `preauthkeys create` / `list` / `expire` | [preauthkeys](#preauthkeys) |
| `policy get` / `set` / `check` | [policy](#policy) |
| `tailnet status` | [tailnet](#tailnet) |

## `users`

Manage users on the admin surface. Source:
`headscale-rs/headscale-cli/src/admin/users.rs`.

### `users create <NAME>`

```
Usage: octravpn-node headscale users create [OPTIONS] <NAME>
```

Create a new user. `<NAME>` is the user label (a free-form string —
headscale uses it as the namespace key).

### `users list`

```
Usage: octravpn-node headscale users list [OPTIONS]
```

List all users. With `--json`, emits the raw JSON array of `{ id, name,
created_at }` records.

### `users delete <NAME>`

```
Usage: octravpn-node headscale users delete [OPTIONS] <NAME>
```

Delete a user by name. Returns exit code 5 if the user does not exist.

## `nodes`

Manage registered nodes. Source: `admin/nodes.rs`.

### `nodes list`

```
Usage: octravpn-node headscale nodes list [OPTIONS]
```

| Flag | Type | Notes |
|---|---|---|
| `--user <USER>` | string | Restrict to a single user. |

List registered nodes. The default table view shows `id`, `name`,
`user`, `last_seen`. `--json` emits the full record.

### `nodes show <ID_OR_NAME>`

```
Usage: octravpn-node headscale nodes show [OPTIONS] <ID_OR_NAME>
```

Show one node by node_key hex or hostname.

### `nodes expire <ID>`

```
Usage: octravpn-node headscale nodes expire [OPTIONS] <ID>
```

| Flag | Type | Notes |
|---|---|---|
| `--at <ISO8601>` | string | Schedule expiry at the given timestamp. Defaults to "now". |

Without `--at`, expires immediately (forces re-register on the node's
next `/map`). With `--at`, schedules expiry for the supplied ISO-8601
timestamp.

### `nodes logout <ID>`

```
Usage: octravpn-node headscale nodes logout [OPTIONS] <ID>
```

Force-logout a node — clears Noise/disco keys + stamps `expiry=now` so
the next `/map` round-trip returns a logout response. Mirrors upstream
`headscale nodes logout`.

### `nodes rename <ID> <HOSTNAME>`

```
Usage: octravpn-node headscale nodes rename [OPTIONS] <ID> <HOSTNAME>
```

Operator-driven hostname rewrite.

### `nodes tags <ID> [TAGS]...`

```
Usage: octravpn-node headscale nodes tags [OPTIONS] <ID> [TAGS]...
```

| Argument | Type | Notes |
|---|---|---|
| `[TAGS]...` | comma-separated | e.g. `tag:prod,tag:web`. Empty list clears the override. |

Replace the node's forced-tags list. Tags are matched by exact string
against the policy.

### `nodes delete <ID>`

```
Usage: octravpn-node headscale nodes delete [OPTIONS] <ID>
```

Delete a node. Exit code 5 if not found.

## `preauthkeys`

Manage pre-auth keys. Source: `admin/preauthkeys.rs`.

### `preauthkeys create`

```
Usage: octravpn-node headscale preauthkeys create [OPTIONS] --user <USER>
```

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--user <USER>` | string | required | User the key belongs to. |
| `--reusable` | bool | off | Allow more than one redemption. |
| `--ephemeral` | bool | off | Mark resulting device ephemeral (auto-clean). |
| `--tags <TAGS>` | comma-separated | (none) | `tag:foo,tag:bar`. |
| `--expires-in <DUR>` | duration | `24h` | e.g. `24h`, `7d`, `30m`. |

Mint a fresh preauth key.

### `preauthkeys list`

```
Usage: octravpn-node headscale preauthkeys list [OPTIONS]
```

| Flag | Type | Notes |
|---|---|---|
| `--user <USER>` | string | Restrict to a single user. |

### `preauthkeys expire <PREFIX>`

```
Usage: octravpn-node headscale preauthkeys expire [OPTIONS] <PREFIX>
```

Expire a key identified by its visible prefix.

## `policy`

Inspect or update the network policy. Source: `admin/policy.rs`.

### `policy get`

```
Usage: octravpn-node headscale policy get [OPTIONS]
```

Fetch the policy currently loaded on the server. Default output is the
hujson document; `--json` wraps it in a transport envelope.

### `policy set <FILE>`

```
Usage: octravpn-node headscale policy set [OPTIONS] <FILE>
```

Push a policy file to the server. The change takes effect within ~1ms —
the policy store's `Notify` wakes parked `/map` long-pollers.

### `policy check <FILE>`

```
Usage: octravpn-node headscale policy check [OPTIONS] <FILE>
```

Validate a policy file locally without touching the server. Honours
`--server` only when the local validator wants to cross-check against
known nodes.

## `tailnet`

Inspect tailnet-wide state. Source: `admin/tailnet.rs`.

### `tailnet status`

```
Usage: octravpn-node headscale tailnet status [OPTIONS]
```

Show tailnet-wide status (DERP regions, DNS, policy). The default table
view is operator-friendly; `--json` emits the raw status envelope.

## Migration from deprecated `mesh` arms

The two `mesh` arms in
[`cli-octravpn-node.md` § mesh](./cli-octravpn-node.md#mesh) (`mesh status`,
`mesh policy`) duplicate functionality here. Operators should prefer:

| Deprecated | Replacement |
|---|---|
| `octravpn-node mesh status --remote URL --admin-token T` | `octravpn-node headscale nodes list --server URL --token T` |
| `octravpn-node mesh policy get` | `octravpn-node headscale policy get` |
| `octravpn-node mesh policy set --file F` | `octravpn-node headscale policy set F` |
| `octravpn-node mesh policy validate --file F` | `octravpn-node headscale policy check F` |

See `docs/operators/cli-migration.md` for the deprecation timeline.

## Upstream parity

This surface is intentionally a thin wrapper. To compare behaviour
against the standalone `headscale` binary, the passthrough test at
`crates/octravpn-node/tests/headscale_cli_passthrough.rs` shells out to
both binaries for every subcommand and asserts byte-equal stdout. If a
documented flag here ever drifts from the standalone `headscale` binary,
that test fails CI.

Upstream reference docs:

* `headscale-rs/headscale-cli/README.md` — module overview.
* `headscale-rs/headscale-cli/src/admin/mod.rs` — clap definitions.
* `headscale-rs/headscale-api/src/admin/*` — server-side schemas.

## Cross-references

* Env vars (`HEADSCALE_URL`, `HEADSCALE_ADMIN_TOKEN`): [env-vars.md](./env-vars.md).
* Error variants (`AdminError`): [error-codes.md](./error-codes.md#adminerror).
* Operator tour: `docs/operators/tour-*.md` (the headscale section).
