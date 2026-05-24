<!-- refreshed against headscale-rs 201fc8c (debug build, 2026-05-24) -->

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
* Subcommand definitions: `headscale-rs/headscale-cli/src/lib.rs`
  (`AdminCmd`) plus `headscale-rs/headscale-cli/src/admin/mod.rs`
  (per-group clap enums and dispatchers).
* Per-command implementations:
  `headscale-rs/headscale-cli/src/admin/{users,nodes,preauthkeys,auth,apikeys,policy,tailnet,debug}.rs`.
* Standalone equivalent binary: `headscale` (cargo target
  `headscale-rs/headscale-cli/src/main.rs`).
* Passthrough byte-diff test: `crates/octravpn-node/tests/headscale_cli_passthrough.rs`.

## Global options (apply to every subcommand)

```
Usage: octravpn-node headscale [OPTIONS] <COMMAND>
```

| Flag | Type | Default | Env override | Notes |
|---|---|---|---|---|
| `--address <ADDR>` | URL | unset | `HEADSCALE_CLI_ADDRESS` | Upstream-compatible gRPC admin endpoint. |
| `--api-key <KEY>` | string | unset | `HEADSCALE_CLI_API_KEY` | API key for remote gRPC. |
| `--unix-socket <PATH>` | path | local default | `HEADSCALE_UNIX_SOCKET` | Used when `--address` is unset. |
| `--insecure` | bool | off | `HEADSCALE_CLI_INSECURE` | Disable TLS certificate verification for remote gRPC. |
| `--server <SERVER>` | URL | unset | `HEADSCALE_URL` | Legacy HTTP admin endpoint; selecting it keeps migrated groups on `/api/v1/*`. |
| `--token <TOKEN>` | string | empty | `HEADSCALE_ADMIN_TOKEN` | Legacy HTTP bearer. |
| `--json` | bool | off | — | Raw JSON output alias. |
| `-o, --output <FMT>` | `json`, `json-line`, `yaml` | table | — | Structured output selector. |
| `--force` | bool | off | — | Disable prompts where the upstream command requires confirmation. |
| `-h, --help` | bool | — | — | clap derived |

Current admin groups are gRPC-first. With no explicit `--address`,
commands try the local Unix socket. Supplying `--server` without an
explicit gRPC endpoint selects the legacy HTTP path for command groups
that still keep one.

## Exit-code contract

From the stable `ExitCode` enum in
`headscale-rs/headscale-cli/src/admin/mod.rs`:

| Code | Variant | Meaning |
|---|---|---|
| 0 | `Success` | Operation completed. |
| 1 | `Usage` | Cobra-style runtime usage error returned by a handler. |
| 3 | `Connection` | DNS / TCP / TLS / handshake failed — anything pre-status. |
| 4 | `Auth` | HTTP 401 / 403. Wrong or missing bearer. |
| 5 | `NotFound` | HTTP 404. User / node / preauth key not found. |
| 6 | `Server` | HTTP 5xx, or any other 4xx, or response-decode failure, or local file IO. |

Clap parser errors still exit 2 before dispatch, matching the standalone
binary.

The `octravpn-node headscale …` invocation forwards this code via
`std::process::exit` (`cli/headscale.rs:31`). Operators can cron-pipe
the subcommands and rely on the codes without parsing stderr.

## Subcommand index

| Subcommand | Section |
|---|---|
| `users create` / `list` / `delete` | [users](#users) |
| `nodes list` / `list-routes` / `register` / `expire` / `rename` / `tag` / `approve-routes` / `delete` / `backfillips` | [nodes](#nodes) |
| `preauthkeys create` / `list` / `expire` / `delete` | [preauthkeys](#preauthkeys) |
| `auth register` / `approve` / `reject` | [auth](#auth) |
| `apikeys create` / `list` / `expire` / `delete` | [apikeys](#apikeys) |
| `policy get` / `set` / `check` | [policy](#policy) |
| `tailnet status` | [tailnet](#tailnet) |
| `debug create-node` | [debug](#debug) |

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

### `users destroy`

```
Usage: octravpn-node headscale users destroy [OPTIONS]
```

Delete a user by `--identifier` or `--name`. Alias: `delete`.

### `users rename`

```
Usage: octravpn-node headscale users rename [OPTIONS] --new-name <NEW_NAME>
```

Rename a user selected by `--identifier` or `--name`.

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

### `nodes list-routes`

```
Usage: octravpn-node headscale nodes list-routes [OPTIONS]
```

List advertised, approved, and serving routes. Alias: `routes`.

### `nodes register`

```
Usage: octravpn-node headscale nodes register --user <USER> --key <KEY>
```

Register a node by auth key over the gRPC admin path.

### `nodes expire`

```
Usage: octravpn-node headscale nodes expire [OPTIONS]
```

| Flag | Type | Notes |
|---|---|---|
| `-i, --identifier <ID>` | string | Node ID. Positional ID is also accepted. |
| `-e, --expiry <RFC3339>` | string | Schedule expiry at the given timestamp. Defaults to "now". Alias: `--at`. |
| `--disable` | bool | Clear key expiry. |

Alias: `logout`.

### `nodes rename`

```
Usage: octravpn-node headscale nodes rename [OPTIONS] <NEW_NAME>
```

Operator-driven hostname rewrite.

### `nodes tag`

```
Usage: octravpn-node headscale nodes tag [OPTIONS] [ID] [TAGS]...
```

Replace the node's forced-tags list. Aliases: `tags`, `t`.

### `nodes approve-routes`

```
Usage: octravpn-node headscale nodes approve-routes --identifier <ID> --routes <ROUTES>
```

Replace the approved routes for a node.

### `nodes delete`

```
Usage: octravpn-node headscale nodes delete [OPTIONS] [ID]
```

Delete a node. Exit code 5 if not found.

### `nodes backfillips`

```
Usage: octravpn-node headscale nodes backfillips [OPTIONS]
```

Backfill missing node IP addresses. Requires `--confirm` or global
`--force`.

## `preauthkeys`

Manage pre-auth keys. Source: `admin/preauthkeys.rs`.

### `preauthkeys create`

```
Usage: octravpn-node headscale preauthkeys create [OPTIONS]
```

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--user <ID>` | integer | optional | User ID the key belongs to. |
| `--reusable` | bool | off | Allow more than one redemption. |
| `--ephemeral` | bool | off | Mark resulting device ephemeral (auto-clean). |
| `--tags <TAGS>` | comma-separated | (none) | `tag:foo,tag:bar`. |
| `--expiration <DUR>` | duration | `1h` | e.g. `24h`, `7d`, `30m`. Alias: `--expires-in`. |

Mint a fresh preauth key.

### `preauthkeys list`

```
Usage: octravpn-node headscale preauthkeys list [OPTIONS]
```

| Flag | Type | Notes |
|---|---|---|
| `--user <USER>` | string | Restrict to a single user. |

### `preauthkeys expire`

```
Usage: octravpn-node headscale preauthkeys expire --id <ID>
```

Expire a key identified by numeric ID. Aliases: `revoke`, `exp`, `e`.

### `preauthkeys delete`

```
Usage: octravpn-node headscale preauthkeys delete --id <ID>
```

Delete a key by numeric ID. Aliases: `del`, `rm`, `d`.

## `auth`

Manage node authentication and approval over the upstream gRPC admin API.
Source: `admin/auth.rs`.

| Command | Usage |
|---|---|
| `auth register` | `octravpn-node headscale auth register --user <USER> --auth-id <AUTH_ID>` |
| `auth approve` | `octravpn-node headscale auth approve --auth-id <AUTH_ID>` |
| `auth reject` | `octravpn-node headscale auth reject --auth-id <AUTH_ID>` |

## `apikeys`

Manage API keys. Source: `admin/apikeys.rs`.

| Command | Usage |
|---|---|
| `apikeys create` | `octravpn-node headscale apikeys create [--expiration 90d]` |
| `apikeys list` | `octravpn-node headscale apikeys list` |
| `apikeys expire` | `octravpn-node headscale apikeys expire (--id <ID> \| --prefix <PREFIX>)` |
| `apikeys delete` | `octravpn-node headscale apikeys delete (--id <ID> \| --prefix <PREFIX>)` |

## `policy`

Inspect or update the network policy. Source: `admin/policy.rs`.

### `policy get`

```
Usage: octravpn-node headscale policy get [OPTIONS]
```

Fetch the policy currently loaded on the server. Default output is the
hujson document; `--json` wraps it in a transport envelope.

### `policy set`

```
Usage: octravpn-node headscale policy set --file <FILE>
```

Push a HuJSON policy file to the server. The change takes effect within
~1ms — the policy store's `Notify` wakes parked `/map` long-pollers.

### `policy check`

```
Usage: octravpn-node headscale policy check --file <FILE>
```

Validate a policy file. The direct-database bypass flag is available for
the standalone `headscale` binary when it has loaded a headscale config;
the embedded Octra dispatch path does not load that config, so Octra
operators should use the gRPC/default path here.

## `tailnet`

Inspect tailnet-wide state. Source: `admin/tailnet.rs`.

### `tailnet status`

```
Usage: octravpn-node headscale tailnet status [OPTIONS]
```

Show tailnet-wide status (DERP regions, DNS, policy). The default table
view is operator-friendly; `--json` emits the raw status envelope.

## `debug`

Debug and test helpers. Source: `admin/mod.rs::DebugCmd`.

### `debug create-node`

```
Usage: octravpn-node headscale debug create-node --user <USER> --key <KEY> --name <NAME> [--route <CIDR>...]
```

Create a node that can be registered with `nodes register`.

## Migration from deprecated `mesh` arms

The two `mesh` arms in
[`cli-octravpn-node.md` § mesh](./cli-octravpn-node.md#mesh) (`mesh status`,
`mesh policy`) duplicate functionality here. Operators should prefer:

| Deprecated | Replacement |
|---|---|
| `octravpn-node mesh status --remote URL --admin-token T` | `octravpn-node headscale nodes list --server URL --token T` |
| `octravpn-node mesh policy get` | `octravpn-node headscale policy get` |
| `octravpn-node mesh policy set --file F` | `octravpn-node headscale policy set --file F` |
| `octravpn-node mesh policy validate --file F` | `octravpn-node headscale policy check --file F` |

See `docs/operators/cli-migration.md` for the deprecation timeline.

## Upstream parity

This surface is intentionally a thin wrapper. To compare behaviour
against the standalone `headscale` binary, the passthrough test at
`crates/octravpn-node/tests/headscale_cli_passthrough.rs` shells out to
both binaries across representative gRPC-default and legacy-HTTP paths
and asserts byte-equal stdout, stderr, and exit code. If the embedded
surface drifts from the standalone `headscale` binary, that test fails
CI.

Upstream reference docs:

* `headscale-rs/headscale-cli/README.md` — module overview.
* `headscale-rs/headscale-cli/src/admin/mod.rs` — clap definitions.
* `headscale-rs/headscale-api/src/admin/*` — server-side schemas.

## Cross-references

* Env vars (`HEADSCALE_URL`, `HEADSCALE_ADMIN_TOKEN`,
  `HEADSCALE_CLI_ADDRESS`, `HEADSCALE_CLI_API_KEY`,
  `HEADSCALE_UNIX_SOCKET`, `HEADSCALE_CLI_INSECURE`):
  [env-vars.md](./env-vars.md).
* Error variants (`AdminError`): [error-codes.md](./error-codes.md#adminerror).
* Operator tour: `docs/operators/tour-*.md` (the headscale section).
