# Operator CLI migration: `headscale` → `octravpn-node headscale`

Status: **active** — `mesh status` + `mesh policy` are deprecated in
favour of the embedded `octravpn-node headscale …` surface.
Removal scheduled **2026-Q3**.

## Why we embedded headscale-cli

Before this change, operators needed **two binaries** on every
endpoint host:

  * `octravpn-node` — the validator-VPN daemon (chain registration,
    WireGuard data plane, receipt journal, …).
  * `headscale` — the admin CLI for the headscale-rs control plane
    (users / nodes / preauthkeys / auth / apikeys / policy / debug).

They share admin connection state (local gRPC Unix socket by default,
or remote gRPC address + API key; legacy HTTP `--server`/`--token`
remains available where the command group keeps a fallback) and
operators routinely flipped between them. The standalone `headscale`
binary was also required for shell scripts driving the admin surface —
increasing the install footprint and the per-host attack surface.

`octravpn-node` now links `headscale-cli` as a library and re-exposes
the entire admin surface under a single subcommand:

```sh
octravpn-node headscale [users|nodes|preauthkeys|auth|apikeys|policy|debug] …
```

The output is **byte-identical** to the standalone binary. Both paths
call the same `admin::run_*` dispatchers, and the embedded wrapper now
mirrors the standalone binary's pre-dispatch setup, so stdout, stderr,
and exit codes track upstream. That includes the current default-config
local gRPC failure shape: a `WRN no config file found, using defaults`
line, an `Error: connecting to headscale: ...` envelope, and exit code
`1`. Legacy explicit `--server http://...` failures continue to follow
whatever the standalone binary emits for that command group.

## Migration table

Every operator-facing invocation has a 1:1 replacement. Arguments are
unchanged.

| Standalone                                               | Embedded                                                       |
|----------------------------------------------------------|----------------------------------------------------------------|
| `headscale users list`                                   | `octravpn-node headscale users list`                           |
| `headscale users create <NAME>`                          | `octravpn-node headscale users create <NAME>`                  |
| `headscale users destroy --name <NAME>`                   | `octravpn-node headscale users destroy --name <NAME>`          |
| `headscale users rename --name <OLD> --new-name <NEW>`    | `octravpn-node headscale users rename --name <OLD> --new-name <NEW>` |
| `headscale nodes list [--user <U>]`                      | `octravpn-node headscale nodes list [--user <U>]`              |
| `headscale nodes list-routes [--identifier <ID>]`         | `octravpn-node headscale nodes list-routes [--identifier <ID>]` |
| `headscale nodes register --user <U> --key <KEY>`         | `octravpn-node headscale nodes register --user <U> --key <KEY>` |
| `headscale nodes expire --identifier <ID> [--expiry <ISO>]` | `octravpn-node headscale nodes expire --identifier <ID> [--expiry <ISO>]` |
| `headscale nodes rename --identifier <ID> <HOST>`         | `octravpn-node headscale nodes rename --identifier <ID> <HOST>` |
| `headscale nodes tag --identifier <ID> --tags <TAGS>`     | `octravpn-node headscale nodes tag --identifier <ID> --tags <TAGS>` |
| `headscale nodes approve-routes --identifier <ID> --routes <CIDRS>` | `octravpn-node headscale nodes approve-routes --identifier <ID> --routes <CIDRS>` |
| `headscale nodes delete <ID>`                            | `octravpn-node headscale nodes delete <ID>`                    |
| `headscale nodes backfillips --confirm`                   | `octravpn-node headscale nodes backfillips --confirm`          |
| `headscale preauthkeys create --user <ID> [--reusable …]` | `octravpn-node headscale preauthkeys create --user <ID> [...]` |
| `headscale preauthkeys list [--user <U>]`                | `octravpn-node headscale preauthkeys list [--user <U>]`        |
| `headscale preauthkeys expire --id <ID>`                  | `octravpn-node headscale preauthkeys expire --id <ID>`         |
| `headscale preauthkeys delete --id <ID>`                  | `octravpn-node headscale preauthkeys delete --id <ID>`         |
| `headscale auth approve --auth-id <ID>`                   | `octravpn-node headscale auth approve --auth-id <ID>`          |
| `headscale auth reject --auth-id <ID>`                    | `octravpn-node headscale auth reject --auth-id <ID>`           |
| `headscale apikeys create [--expiration 90d]`             | `octravpn-node headscale apikeys create [--expiration 90d]`    |
| `headscale apikeys list`                                  | `octravpn-node headscale apikeys list`                         |
| `headscale apikeys expire (--id <ID> \| --prefix <P>)`    | `octravpn-node headscale apikeys expire (--id <ID> \| --prefix <P>)` |
| `headscale policy get`                                   | `octravpn-node headscale policy get`                           |
| `headscale policy set --file <FILE>`                      | `octravpn-node headscale policy set --file <FILE>`             |
| `headscale policy check --file <FILE>`                    | `octravpn-node headscale policy check --file <FILE>`           |
| `headscale debug create-node …`                           | `octravpn-node headscale debug create-node …`                  |

Connection flags behave identically on either binary. Migrated admin
groups default to upstream-compatible gRPC (`--address` /
`HEADSCALE_CLI_ADDRESS`, `--api-key` / `HEADSCALE_CLI_API_KEY`, or
`--unix-socket` / `HEADSCALE_UNIX_SOCKET`). Supplying `--server` /
`HEADSCALE_URL` without an explicit gRPC endpoint selects the legacy
HTTP path for groups that keep one.

## Deprecated subcommands + timeline

The two octravpn-node-specific subcommands that wrapped the same
admin routes are deprecated. They keep working — they print a stderr
warning and continue — until 2026-Q3, when they are removed entirely.

| Deprecated                                | Replacement                                       |
|-------------------------------------------|---------------------------------------------------|
| `octravpn-node mesh status`               | `octravpn-node headscale nodes list`              |
| `octravpn-node mesh policy get`           | `octravpn-node headscale policy get`              |
| `octravpn-node mesh policy set --file F`  | `octravpn-node headscale policy set --file F`     |
| `octravpn-node mesh policy validate F`    | `octravpn-node headscale policy check --file F`   |

The deprecation warning is printed to stderr (so byte-diff harnesses
captured on stdout are unaffected). It does **not** affect the exit
code. Scripts written against the deprecated commands continue
working unchanged through 2026-Q3.

Operator action: update scripts + runbooks before 2026-Q3 by either
running the migration command:

```sh
sed -i 's/octravpn-node mesh status/octravpn-node headscale nodes list/g' …
sed -i 's/octravpn-node mesh policy get/octravpn-node headscale policy get/g' …
```

or by running this skill check (zero output ⇒ clean):

```sh
git grep -nE 'octravpn-node mesh (status|policy)' -- ':!docs/operators/cli-migration.md' || true
```

## When the standalone `headscale` binary is still useful

The standalone binary is still built + published by the `headscale-rs`
workspace. Keep installing it when:

  * You're driving the headscale-rs control plane from a host that
    isn't running `octravpn-node` (e.g. a CI runner, a packet-shop
    operator using only the Tailscale-compat surface, a one-shot
    diagnostic console).
  * You need the **serve**, **mesh-node**, **identity**, **generate**,
    **mockoidc**, **health**, **version**, **completion**,
    **configtest**, **dumpConfig**, **status**, or **init-config**
    subcommands. The embedded surface intentionally
    only re-exposes the admin verbs — the `headscale server` /
    `headscale node` paths touch local on-disk keypair state and stay
    in the standalone binary.

Otherwise, `octravpn-node headscale …` is the one to use.

## Implementation notes

Crate wiring: `octravpn-node`'s `Cargo.toml` adds
`headscale-cli = { path = "../../../headscale-rs/headscale-cli" }`.
The library exports an `AdminCmd` clap subcommand enum + a
`dispatch(connect, cmd) -> i32` async function. The bin's top-level
`Cmd::Headscale { connect, cmd }` variant flattens
`headscale_cli::ConnectArgs` (so gRPC flags, legacy HTTP flags, output
flags, and their env-var fallbacks all appear at the same level as the
standalone binary), applies the same default-config gRPC warning and
`connecting to headscale:` wrapping flags that upstream `main()` applies,
and delegates to `dispatch`. Exit code is propagated via
`std::process::exit`.

Pass-through tests live in
`crates/octravpn-node/tests/headscale_cli_passthrough.rs`. They build
the standalone `headscale` binary via `escargot`, run both binaries
side-by-side against an unreachable local endpoint or explicit
`127.0.0.1:1` legacy HTTP endpoint, and `diff` stdout + stderr + exit
code. The pass-through contract is a test-time invariant — a divergence
in either binary breaks CI.

## Changelog

  * 2026-05-20 — embedded `headscale-cli` as a library dep; added
    `octravpn-node headscale …` surface; deprecated `mesh status` +
    `mesh policy` with a 2026-Q3 removal target.
  * 2026-05-24 — refreshed for the gRPC-first admin surface and new
    `auth` / `apikeys` / `debug` coverage.
  * 2026-07-02 — refreshed after the headscale-rs `origin/main` bump:
    removed stale `tailnet` migration guidance and aligned the embedded
    wrapper with upstream's default-config warning, connection-error
    envelope, and exit-1 usage contract.
