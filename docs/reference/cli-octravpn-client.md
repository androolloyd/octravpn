<!-- captured from binary at SHA 2ffead7 (debug build, 2026-05-20) -->

# `octravpn` — client CLI

The end-user / device-side binary (binary name: `octravpn`; cargo target:
`crates/octravpn-client`). One process, many subcommands. Builds with
`cargo build -p octravpn-client`. Entry point:
`crates/octravpn-client/src/main.rs`; clap surface defined in
`crates/octravpn-client/src/commands.rs` and dispatched through
`crates/octravpn-client/src/runner.rs` (v1/v2) and `v3_runner.rs` (v3).

## Top-level synopsis

```
OctraVPN client

Usage: octravpn [OPTIONS] <COMMAND>
```

### Global options

| Flag | Type | Default | Env override | Source |
|---|---|---|---|---|
| `--config <CONFIG>` | path | `client.toml` | `OCTRAVPN_CONFIG` | `main.rs:29` |
| `-h, --help` | bool | — | — | clap derived |
| `-V, --version` | bool | — | — | clap derived |

### Subcommand index

| Subcommand | Source | Section |
|---|---|---|
| `identity` | `commands.rs` | [identity](#identity) |
| `nodes` | `runner.rs` | [nodes](#nodes) |
| `connect` | `runner.rs` | [connect](#connect) |
| `settle` | `settler.rs` | [settle](#settle) |
| `reclaim` | `settler.rs` | [reclaim](#reclaim) |
| `init` | `commands.rs` | [init](#init) |
| `keygen` | `commands.rs` | [keygen](#keygen) |
| `doctor` | `commands.rs` | [doctor](#doctor) |
| `bug-report` | `commands/bugreport.rs` | [bug-report](#bug-report) |
| `tailnet` | `tailnet.rs` | [tailnet (subcommands)](#tailnet) |
| `slash-evidence` | `commands/slash.rs` | [slash-evidence (subcommands)](#slash-evidence) |
| `serve` | `commands/serve.rs` | [serve (subcommands)](#serve) |
| `funnel` | `commands/funnel.rs` | [funnel (subcommands)](#funnel) |
| `discover` | `discover.rs`, `discover_v2.rs` | [discover (subcommands)](#discover) |
| `connect-v3` | `v3_runner.rs` | [connect-v3](#connect-v3) |
| `connect-v2` | `v2_runner.rs` | [connect-v2](#connect-v2) |
| `open-url` | `commands/open_url.rs` | [open-url](#open-url) |
| `fetch` | `commands/fetch.rs` | [fetch](#fetch) |
| `portal` | `commands/serve.rs`, `portal/*` | [portal](#portal) |

---

## `identity`

**Synopsis.** Print derived addresses/pubkeys for the current wallet.

```
Usage: octravpn identity
```

Reads the wallet at `[wallet].secret_path`, derives the `oct…` address,
and prints it along with the WG pubkey. No flags. Source:
`commands::run_identity`.

---

## `nodes`

**Synopsis.** List active validator-VPN nodes from the on-chain
registry.

```
Usage: octravpn nodes [OPTIONS]
```

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--offset` | u32 | 0 | Pagination offset. |
| `--limit` | u32 | 50 | Page size. |

Calls `octra_listContracts` (see [rpc-methods.md](./rpc-methods.md)) and
filters for active operator endpoints.

---

## `connect`

**Synopsis.** Open a 1..3 hop session and run the tunnel until ctrl-c.
The v1.1 path — `connect-v2` and `connect-v3` are the protocol-version
specific subcommands.

```
Usage: octravpn connect [OPTIONS] --deposit <DEPOSIT>
```

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--hops` | 1..=3 | 3 | Onion route length. |
| `--region` | string | (any) | Preferred operator region. |
| `--deposit` | u64 (raw OU) | required | Pre-paid OU credit on the session. |

Source: `runner::run_connect`.

---

## `settle`

**Synopsis.** Settle a session opened earlier.

```
Usage: octravpn settle <SESSION_ID>
```

Calls `settle_confirm(session_id, bytes_used, net, settle_blinding)` on
the operator's program (`settler.rs:146`). The bytes_used comes from the
client's local session counter.

---

## `reclaim`

**Synopsis.** Trigger no-show refund for a session past grace.

```
Usage: octravpn reclaim <SESSION_ID>
```

Calls `claim_no_show(session_id)`. The chain enforces the grace window
(`session_grace`) — the call reverts if the operator already settled or
the grace has not elapsed. Source: `settler::reclaim` (`settler.rs:114`).

---

## `init`

**Synopsis.** Write a fresh client config + key files into a directory.

```
Usage: octravpn init [OPTIONS]
```

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--dir` | path | `.` | Target directory. |
| `--rpc-url` | URL | (devnet) | Chain RPC URL. |
| `--program-addr` | `oct…` | (devnet program) | OctraVPN program address. |
| `--force` | bool | off | Overwrite existing files. |

Generates `client.toml`, `wallet.key`, and `wg.key`. Mode 0600.

---

## `keygen`

**Synopsis.** Generate a new wallet keypair and write to disk.

```
Usage: octravpn keygen --out <OUT>
```

| Flag | Type | Notes |
|---|---|---|
| `--out` | path | Required. The file gets the secret; mode 0600. |

---

## `doctor`

**Synopsis.** Run preflight checks: config readable, key valid, RPC
reachable, TUN openable, system capabilities present.

```
Usage: octravpn doctor
```

No flags. Exits 0 if all probes pass; non-zero with the first failing
probe printed. Source: `commands::run_doctor`.

---

## `bug-report`

**Synopsis.** Collect a redacted diagnostic bundle (tar.gz) for support
reports.

```
Usage: octravpn bug-report [OPTIONS]
```

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--out` | path | `./octravpn-bugreport-<ts>.tar.gz` | |

Bundles: redacted `client.toml`, last 1 MiB of structured logs, `doctor`
output, system info. Secrets are scrubbed by
`commands::bugreport::sanitise_*` before archiving. Source:
`crates/octravpn-client/src/commands/bugreport.rs`.

---

## `tailnet`

**Synopsis.** Tailnet operations (create / membership / mesh-up /
discovery).

```
Usage: octravpn tailnet <COMMAND>
```

Source: `crates/octravpn-client/src/tailnet.rs`. Sub-commands:

### `tailnet create`

```
Usage: octravpn tailnet create --treasury <TREASURY> --acl <ACL> --name <NAME>
```

| Flag | Type | Notes |
|---|---|---|
| `--treasury` | u64 (raw OU) | Initial treasury. |
| `--acl` | path | TOML ACL doc. Canonical hash goes on chain. |
| `--name` | string | Saved to `~/.octravpn/tailnets/<name>.toml`. |

Underlying RPC: `create_tailnet` (`tailnet.rs:397`).

### `tailnet add-member`

```
Usage: octravpn tailnet add-member --tailnet <TAILNET> --addr <ADDR>
```

Owner-only. RPC: `add_member` (`tailnet.rs:435`).

### `tailnet remove-member`

```
Usage: octravpn tailnet remove-member --tailnet <TAILNET> --addr <ADDR>
```

Owner-only; can't remove the owner. RPC: `remove_member`.

### `tailnet top-up`

```
Usage: octravpn tailnet top-up --tailnet <TAILNET> --amount <AMOUNT>
```

Deposit OU into a tailnet treasury. RPC: `deposit_to_tailnet`.

### `tailnet set-acl`

```
Usage: octravpn tailnet set-acl --tailnet <TAILNET> --file <FILE>
```

Replace the ACL hash on chain. RPC: `update_acl`.

### `tailnet configure-exit`

```
Usage: octravpn tailnet configure-exit --tailnet <TAILNET> --validator <OCT_ADDR>
```

Owner-only. RPC: `configure_tailnet_exit`.

### `tailnet info`

```
Usage: octravpn tailnet info --tailnet <TAILNET>
```

Print tailnet metadata.

### `tailnet up`

```
Usage: octravpn tailnet up [OPTIONS] --tailnet <TAILNET>
```

Bring this device online inside the tailnet. Long-running.

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--tailnet` | id | required | |
| `--hostname` | string | OS hostname | MagicDNS hostname. |
| `--stun` | host:port | `stun.l.google.com:19302` | |
| `--dns-upstream` | host:port | `1.1.1.1:53` | |
| `--refresh-secs` | u64 | 60 | STUN + peer snapshot refresh interval. |

### `tailnet list`

```
Usage: octravpn tailnet list
```

List tailnet IDs discovered on chain.

### `tailnet peers`

```
Usage: octravpn tailnet peers --tailnet <TAILNET>
```

Per-peer connection state (Direct / Relay / Probing).

### `tailnet advertise-subnet`

```
Usage: octravpn tailnet advertise-subnet --tailnet <TAILNET> --cidr <CIDR>
```

Advertise a private subnet so members can route through this device.

### `tailnet register-device`

```
Usage: octravpn tailnet register-device --device <OCT_ADDR>
```

Attach a new device address. RPC: `register_device` (`tailnet.rs:331`).

### `tailnet revoke-device`

```
Usage: octravpn tailnet revoke-device --device <OCT_ADDR>
```

RPC: `revoke_device`.

### `tailnet issue-token`

```
Usage: octravpn tailnet issue-token [OPTIONS] --tailnet <TAILNET>
```

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--hours` | u64 | 24 | Token validity. |

Owner-only. Token printed to stdout.

### `tailnet redeem-token`

```
Usage: octravpn tailnet redeem-token --token <TOKEN>
```

The chain adds the caller without bothering the owner. RPC:
`redeem_join_token` (`tailnet.rs:299`).

---

## `slash-evidence`

**Synopsis.** Build or verify equivocation evidence against an endpoint.

```
Usage: octravpn slash-evidence <COMMAND>
```

Source: `crates/octravpn-client/src/commands/slash.rs`.

### `slash-evidence build`

```
Usage: octravpn slash-evidence build [OPTIONS] \
   --endpoint-addr <…> --receipt-pubkey <…> --session-id <…> --seq <…> \
   --bytes-a <…> --blind-a <…> --sig-a <…> \
   --bytes-b <…> --blind-b <…> --sig-b <…> \
   --out <OUT>
```

| Flag | Notes |
|---|---|
| `--endpoint-addr` | The operator's chain address. |
| `--receipt-pubkey` | Ed25519 pubkey used to sign the receipts. |
| `--session-id` | Common session id (hex64 or u64). |
| `--seq` | Common receipt seq. |
| `--bytes-a`, `--bytes-b` | The two conflicting `bytes_used` values. |
| `--blind-a`, `--blind-b` | Matching blinding factors. |
| `--sig-a`, `--sig-b` | Base64-encoded ed25519 signatures. |
| `--program-addr` | v1.2 binder: program address that hosts the session. |
| `--chain-id` | v1.2 binder: chain id (devnet/mainnet/shard). |
| `--circle-id` | v2 binder: hex circle id (required for v2 receipts). |
| `--out` | Path to write the evidence JSON. |

### `slash-evidence verify`

```
Usage: octravpn slash-evidence verify <BLOB>
```

Load the evidence file, verify both signatures + distinctness, and
exit 0 on a valid blob.

### `slash-evidence submit`

```
Usage: octravpn slash-evidence submit <BLOB>
```

Verify and submit `slash_double_sign` on chain. The caller receives the
`slash_bounty_bps` bounty (10% by default). RPC builders:
`crates/octravpn-client/src/commands/slash.rs:324`.

---

## `serve`

**Synopsis.** Expose a local TCP service to tailnet members at
`<host>.<tailnet>.octra:<port><path>`.

```
Usage: octravpn serve <COMMAND>

Commands:
  add      Register a local port to advertise
  remove   Remove a previously-registered port
  list     List currently-registered entries
```

Honours the `OCTRAVPN_SERVE_DIR` env var for `serve.toml` location
(`commands/serve.rs:39`).

---

## `funnel`

**Synopsis.** Same as `serve`, but additionally publish the service
through a paid validator exit node to the public internet.

```
Usage: octravpn funnel <COMMAND>

Commands:
  add      Register a local port to advertise
  remove   Remove a previously-registered port
  list     List currently-registered entries
```

---

## `discover`

**Synopsis.** v2 substrate: list authorized circles for a tailnet and
decrypt their sealed `/policy.json`. Members see endpoint/region/price;
non-members see `[opaque]` and an explanatory message. Gated on
`[chain].protocol_version = "v2"`.

```
Usage: octravpn discover <COMMAND>

Commands:
  v2          List authorized circles for a tailnet and decrypt their sealed `/policy.json`
  invalidate  Drop one circle's cached policy
```

Source: `crates/octravpn-client/src/discover_v2.rs` (RPC builder at
`:390` calls `open_session` to enumerate the tailnet's circle set).

---

## `connect-v3`

**Synopsis.** v3 substrate: open a session against the configured
operator circle (`[v3].circle_id`) on the v3 chain-minimal program.

```
Usage: octravpn connect-v3 [OPTIONS]
```

| Flag | Type | Notes |
|---|---|---|
| `--tailnet-id` | int | Override `[v3].tailnet_id`. |
| `--circle-id` | `oct…` | Override `[v3].circle_id`. |
| `--max-pay` | u64 OU | Override `[v3].max_pay`. |
| `--no-show` | bool | Skip `settle_confirm` and submit `claim_no_show` instead. |
| `--bytes-used` | u64 | Test-only deterministic `bytes_used`. |

Source: `crates/octravpn-client/src/v3_runner.rs`. RPC builder:
`crates/octravpn-client/src/runner.rs:213` (`open_session`).

---

## `connect-v2`

**Synopsis.** v2 substrate: open a session against an authorized circle
and print the WG handoff. The v1.1 `connect` path is preserved.

```
Usage: octravpn connect-v2 [OPTIONS] --tailnet-id <TAILNET_ID> --deposit <DEPOSIT>
```

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--tailnet-id` | int | required | Looked up against the v2 program. |
| `--circle-id` | `oct…` | (auto) | First decryptable circle if unset. |
| `--class` | `shared` \| `internal` | `shared` | Session class. |
| `--deposit` | u64 OU | required | Must be ≥ chain `min_session_deposit`. |
| `--secret` | string | env > this > config | Sealed-policy passphrase override. |
| `--refresh` | bool | off | Force refresh of cached policy. |

Source: `crates/octravpn-client/src/v2_runner.rs`.

---

## `open-url`

**Synopsis.** Resolve an `oct://<circle>/<path>` URL — either render in
the local browser portal (default), save to disk, or stream to stdout.
The OS protocol handler (see `dist/`) dispatches here.

```
Usage: octravpn open-url [OPTIONS] <URL>
```

| Flag | Type | Notes |
|---|---|---|
| `--save <SAVE>` | path | Write fetched bytes to file. Mutually exclusive with the other modes. |
| `--stdout` | bool | Stream to stdout. |
| `--portal` | bool | Hand off to local portal (default if no mode set). Spawns the portal if needed. |
| `--portal-bind` | host:port | Override portal loopback. Default `127.0.0.1:51823`. |

Source: `crates/octravpn-client/src/commands/open_url.rs`. See
`docs/oct-url-handler.md` for the OS-level protocol-handler install.

---

## `fetch`

**Synopsis.** `oct://` fetch surface for shell pipelines: raw bytes to
stdout or `--output <path>`, optional interactive passphrase prompt for
sealed assets. Bypasses the HTTP portal entirely.

```
Usage: octravpn fetch [OPTIONS] <URL>
```

| Flag | Type | Notes |
|---|---|---|
| `-o, --output <OUTPUT>` | path | Write to file instead of stdout. Containing dir must exist. |
| `--secret <SECRET>` | string | One-shot sealed-asset passphrase. |
| `-i, --interactive` | bool | Prompt on TTY when asset is sealed and no other passphrase source resolved. 3 attempts, then exit 5. |
| `--headers` | bool | Emit `Content-Type:` lines to stderr (curl `-i` style). |

**Passphrase precedence.** `OCTRAVPN_SEALED_PASSPHRASE` env > `--secret`
flag > `[v2].sealed_passphrase` config > `-i` interactive prompt
(if stdin is a TTY).

**Exit codes (from `commands/fetch.rs`).**

| Code | Meaning |
|---|---|
| 0 | Success, body written to stdout/file. |
| 2 | URL parse error or invalid `-o` path. |
| 3 | Chain RPC failure. |
| 4 | Asset not published (RPC returned null). |
| 5 | Sealed asset, no passphrase available (or 3 wrong attempts in `-i`). |
| 6 | Sealed asset, decrypt failed (wrong passphrase / key_id / corrupt envelope). |

---

## `portal`

**Synopsis.** Run the local `oct://` browser portal. Long-running.

```
Usage: octravpn portal [OPTIONS]
```

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--bind <BIND>` | host:port | `127.0.0.1:51823` | Loopback bind. |

Serves HTML/JSON fetched over the active VPN session, sandboxes HTML
inside an iframe, gates first-time circles on an explicit confirm.
Source: `crates/octravpn-client/src/portal/mod.rs` (routes in
`portal/routes.rs`).

---

## Exit-code summary

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Generic failure |
| 2 | clap usage error / URL parse |
| 3 | Chain RPC failure (where surfaced) |
| 4 | Asset not published (`fetch`) |
| 5 | Sealed asset, no passphrase (`fetch`) |
| 6 | Sealed asset, decrypt failed (`fetch`) |

---

## Cross-references

* User how-to: `docs/users/*.md`.
* Portal architecture: `docs/oct-url-handler.md`,
  `crates/octravpn-client/src/portal/README.md` (if present).
* v2 substrate semantics: `docs/v2-client-flow.md`.
* v3 substrate semantics: `docs/v3-state-root-schema.md`.
