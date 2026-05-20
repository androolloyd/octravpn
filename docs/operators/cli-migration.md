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
    (users / nodes / preauthkeys / policy / tailnet).

They share auth (bearer token + admin URL) and operators routinely
flipped between them. The standalone `headscale` binary was also
required for shell scripts driving the admin surface — increasing the
install footprint and the per-host attack surface.

`octravpn-node` now links `headscale-cli` as a library and re-exposes
the entire admin surface under a single subcommand:

```sh
octravpn-node headscale [users|nodes|preauthkeys|policy|tailnet] …
```

The output is **byte-identical** to the standalone binary. Both paths
call the same `admin::run_*` dispatchers, so stdout, the stderr
`error: …` envelope, and the exit-code contract all match.

## Migration table

Every operator-facing invocation has a 1:1 replacement. Arguments are
unchanged.

| Standalone                                               | Embedded                                                       |
|----------------------------------------------------------|----------------------------------------------------------------|
| `headscale users list`                                   | `octravpn-node headscale users list`                           |
| `headscale users create <NAME>`                          | `octravpn-node headscale users create <NAME>`                  |
| `headscale users delete <NAME>`                          | `octravpn-node headscale users delete <NAME>`                  |
| `headscale nodes list [--user <U>]`                      | `octravpn-node headscale nodes list [--user <U>]`              |
| `headscale nodes show <ID>`                              | `octravpn-node headscale nodes show <ID>`                      |
| `headscale nodes expire <ID> [--at <ISO>]`               | `octravpn-node headscale nodes expire <ID> [--at <ISO>]`       |
| `headscale nodes logout <ID>`                            | `octravpn-node headscale nodes logout <ID>`                    |
| `headscale nodes rename <ID> <HOST>`                     | `octravpn-node headscale nodes rename <ID> <HOST>`             |
| `headscale nodes tags <ID> <TAGS>`                       | `octravpn-node headscale nodes tags <ID> <TAGS>`               |
| `headscale nodes delete <ID>`                            | `octravpn-node headscale nodes delete <ID>`                    |
| `headscale preauthkeys create --user <U> [--reusable …]` | `octravpn-node headscale preauthkeys create --user <U> [...]`  |
| `headscale preauthkeys list [--user <U>]`                | `octravpn-node headscale preauthkeys list [--user <U>]`        |
| `headscale preauthkeys expire <PREFIX>`                  | `octravpn-node headscale preauthkeys expire <PREFIX>`          |
| `headscale policy get`                                   | `octravpn-node headscale policy get`                           |
| `headscale policy set <FILE>`                            | `octravpn-node headscale policy set <FILE>`                    |
| `headscale policy check <FILE>`                          | `octravpn-node headscale policy check <FILE>`                  |
| `headscale tailnet status`                               | `octravpn-node headscale tailnet status`                       |

Connection flags (`--server`, `--token`, `--json`) plus their
`HEADSCALE_URL` / `HEADSCALE_ADMIN_TOKEN` env-var fallbacks behave
identically on either binary.

## Deprecated subcommands + timeline

The two octravpn-node-specific subcommands that wrapped the same
admin routes are deprecated. They keep working — they print a stderr
warning and continue — until 2026-Q3, when they are removed entirely.

| Deprecated                                | Replacement                                       |
|-------------------------------------------|---------------------------------------------------|
| `octravpn-node mesh status`               | `octravpn-node headscale nodes list`              |
| `octravpn-node mesh policy get`           | `octravpn-node headscale policy get`              |
| `octravpn-node mesh policy set --file F`  | `octravpn-node headscale policy set F`            |
| `octravpn-node mesh policy validate F`    | `octravpn-node headscale policy check F`          |

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
  * You need the **server**, **node**, **identity**, or
    **init-config** subcommands. The embedded surface intentionally
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
`headscale_cli::ConnectArgs` (so `--server` / `--token` / `--json` /
their env-var fallbacks all appear at the same level as the
standalone binary) and delegates to `dispatch`. Exit code is
propagated via `std::process::exit`.

Pass-through tests live in
`crates/octravpn-node/tests/headscale_cli_passthrough.rs`. They build
the standalone `headscale` binary via `escargot`, run both binaries
side-by-side against an unreachable address (`127.0.0.1:1`), and
`diff` stdout + stderr + exit code. The pass-through contract is a
test-time invariant — a divergence in either binary breaks CI.

## Changelog

  * 2026-05-20 — embedded `headscale-cli` as a library dep; added
    `octravpn-node headscale …` surface; deprecated `mesh status` +
    `mesh policy` with a 2026-Q3 removal target.
