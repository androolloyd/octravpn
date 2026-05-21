<!-- captured from binary at SHA 2ffead7 (debug build, 2026-05-20) -->
<!-- Refresh command:
       cargo build -p octravpn-node
       BIN=./target/debug/octravpn-node
       $BIN --help; for c in run bond unbond finalize-unbond register \
            claim-earnings settle-claim identity accumulator-add \
            verify-audit-log audit seal-keys unseal-keys v3 circle \
            mesh headscale config health audit-tail receipt-verify; \
         do $BIN $c --help; done
-->

# `octravpn-node` — operator daemon CLI

The operator-facing binary. One process, many subcommands. Build with
`cargo build -p octravpn-node`; install via `target/debian/*.deb` or
copy the binary into `$PATH`. The daemon entrypoint is
`crates/octravpn-node/src/main.rs`; the subcommand dispatcher is
`crates/octravpn-node/src/cli/mod.rs` — every variant in `Cmd` cites
the file backing it.

## Top-level synopsis

```
OctraVPN node daemon: WireGuard + chain registration + onion forwarding.

Usage: octravpn-node [OPTIONS] <COMMAND>
```

### Global options

| Flag | Type | Default | Env override | Source |
|---|---|---|---|---|
| `--config <CONFIG>` | path | `node.toml` | `OCTRAVPN_NODE_CONFIG` | `cli/mod.rs:69` |
| `-h, --help` | bool | — | — | clap derived |
| `-V, --version` | bool | — | — | clap derived |

The global `--config` is consumed before subcommand dispatch; subcommands
that need a `NodeConfig` resolve it via `CliContext::load_config()`
(`cli/mod.rs:131`).

### Subcommand index

| Subcommand | Implementing file | Needs Hub? | Section |
|---|---|---|---|
| `run` | `cli/runtime.rs` | yes | [run](#run) |
| `bond` | `cli/bond.rs` | yes | [bond](#bond) |
| `unbond` | `cli/bond.rs` | yes | [unbond](#unbond) |
| `finalize-unbond` | `cli/bond.rs` | yes | [finalize-unbond](#finalize-unbond) |
| `register` | `cli/bond.rs` | yes | [register](#register) |
| `claim-earnings` | `cli/bond.rs` | yes | [claim-earnings](#claim-earnings) |
| `settle-claim` | `cli/bond.rs` | yes | [settle-claim](#settle-claim) |
| `identity` | `cli/identity.rs` | yes | [identity](#identity) |
| `accumulator-add` | `cli/identity.rs` | yes | [accumulator-add](#accumulator-add) |
| `verify-audit-log` | `cli/audit.rs` | no | [verify-audit-log](#verify-audit-log) |
| `audit` | `cli/audit.rs` | no | [audit (replay/verify)](#audit) |
| `seal-keys` | `cli/seal.rs` | no | [seal-keys](#seal-keys) |
| `unseal-keys` | `cli/seal.rs` | no | [unseal-keys](#unseal-keys) |
| `v3` | `cli/v3.rs` → `v3_cli.rs` | yes | [v3 (subcommands)](#v3) |
| `circle` | `cli/circle.rs` → `circle_update.rs` | yes | [circle (subcommands)](#circle) |
| `mesh` | `cli/mesh.rs` → `mesh_ops.rs` | varies | [mesh (subcommands)](#mesh) |
| `headscale` | `cli/headscale.rs` → `headscale_cli` crate | no | see [cli-headscale-embedded.md](./cli-headscale-embedded.md) |
| `config` | `cli/ops.rs` | no | [config](#config) |
| `health` | `cli/ops.rs` | no | [health](#health) |
| `audit-tail` | `cli/ops.rs` | no | [audit-tail](#audit-tail) |
| `receipt-verify` | `cli/ops.rs` | no | [receipt-verify](#receipt-verify) |

Total subcommands (top + nested): **72**. See the tour doc for which to
hit during a typical bring-up.

---

## `run`

**Synopsis.** Run the daemon in long-lived mode.

```
Usage: octravpn-node run
```

This is the entrypoint your systemd unit invokes. Subcommand arguments
are intentionally empty — every operating-mode knob lives in `node.toml`.
The boot sequence (chain attestation → WG tunnel → control plane →
audit log → analytics indexer → optional Tailscale-wire bridge) is
orchestrated by `Hub::new(cfg).await` in `crates/octravpn-node/src/hub/mod.rs`.

**Exit codes.** Daemon runs until SIGTERM. Returns 0 on a clean shutdown
via `Hub::shutdown`. Any unrecoverable boot failure surfaces as
`anyhow::Error` and exits with code 1; check stderr for the chain.

**Example.**

```bash
sudo OCTRAVPN_KEY_PASSPHRASE=$(cat /run/secrets/key.pp) \
  octravpn-node --config /etc/octravpn/node.toml run
```

**See also.** Operator tour for the boot-time sequence; `[chain].protocol_version`
in [config.md](./config.md) for which boot flow runs.

---

## `bond`

**Synopsis.** Deposit OU as operator stake. Required before `register`.

```
Usage: octravpn-node bond --amount <AMOUNT>
```

Implemented by `BondArgs::dispatch` in `crates/octravpn-node/src/cli/bond.rs`.
The protocol-version switch decides which on-chain method runs:

* v1.1 → `bond_endpoint()` on `program/main.aml`
* v2   → `bond_endpoint(circle)` on `program/main-v2.aml`
* v3   → use `octravpn-node v3 bond --circle … --amount …` instead

**Options.**

| Flag | Type | Required | Notes |
|---|---|---|---|
| `--amount <AMOUNT>` | u64 (raw OU) | yes | Minimum is `MIN_ENDPOINT_STAKE` (1000 OCT = 10^9 OU in defaults). |

**Exit codes.** 0 on submit; non-zero on chain rejection. The error
message is the AML revert string verbatim.

**Example.**

```bash
octravpn-node bond --amount 1000000000   # 1000 OCT
```

---

## `unbond`

**Synopsis.** Begin unbonding the operator stake. Starts the grace
timer; the endpoint becomes inactive immediately.

```
Usage: octravpn-node unbond
```

No flags. The grace period is `unbond_grace_epochs` on chain (default 7
epochs). After it elapses, run `finalize-unbond` to actually claim the
OU back. The endpoint flips `endpoint_active = 0` synchronously so
clients stop opening new sessions; in-flight sessions still need to
settle.

Source: `cli/bond.rs::UnbondArgs::dispatch`.

---

## `finalize-unbond`

**Synopsis.** After the unbond grace elapses, claim the stake back.

```
Usage: octravpn-node finalize-unbond
```

No flags. Reverts with `unbond grace not elapsed` if called too early.
Source: `cli/bond.rs::FinalizeUnbondArgs::dispatch`.

---

## `register`

**Synopsis.** Register endpoint on chain (idempotent). Caller must have
at least `MIN_ENDPOINT_STAKE` bonded — run `bond` first.

```
Usage: octravpn-node register
```

Idempotent — re-running while already registered is a no-op (the daemon
checks `endpoint_active` first). For v2/v3 operators, this is normally
done automatically inside `run` at boot via `Hub::new`. The standalone
subcommand exists for the v1.1 manual-flow operators and for
post-`unbond` re-registration.

Source: `cli/bond.rs::RegisterArgs::dispatch` + `crates/octravpn-node/src/chain.rs:138`.

---

## `claim-earnings`

**Synopsis.** Claim accumulated earnings. Two-step: AML verifies an FHE
zero-proof and transfers plaintext OU; the operator's wallet then wraps
it in a native stealth tx for unlinkable payout.

```
Usage: octravpn-node claim-earnings
```

No flags. The amount to claim is read from the local earnings
accumulator (which is fed by `accumulator-add`). The on-chain side calls
`claim_earnings()` (v1.1 / v2) or `claim_earnings(circle, amount)` (v3 —
prefer the `v3 claim-earnings` subcommand for v3). Implementation:
`cli/bond.rs::ClaimEarningsArgs::dispatch` + `chain.rs:210`.

---

## `settle-claim`

**Synopsis.** Submit `settle_claim(session_id, bytes_used)` for a closed
session.

```
Usage: octravpn-node settle-claim --session-id <SESSION_ID> --bytes-used <BYTES_USED>
```

| Flag | Type | Notes |
|---|---|---|
| `--session-id` | 64-char hex (v2+) or u64 decimal (v1) | The session you are settling. |
| `--bytes-used` | u64 | The monotonic high-watermark of bytes delivered. |

**WARNING.** The operator MUST submit the same `bytes_used` per
`session_id` for life — equivocation is detected on-chain by the v3
state machine and triggers an immediate `slash_double_sign`. The local
receipt journal at `state/receipts.bin` prevents the daemon from
double-signing across restarts (see [state-files.md](./state-files.md)).

Source: `cli/bond.rs::SettleClaimArgs::dispatch` + `chain.rs:235`.

---

## `identity`

**Synopsis.** Print derived addresses / pubkeys without changing
on-chain state.

```
Usage: octravpn-node identity
```

Reads the config, loads the wallet secret, and prints:

* `validator_addr` — the `oct…` address derived from the wallet key.
* `wg_pubkey_b64` — the base64 of the WG static pubkey.
* (v2+) `circle_id` — the predicted/deployed circle id.
* (v3) `receipt_pubkey_b64` — the ed25519 pubkey published in
  `register_circle`.

Source: `cli/identity.rs::IdentityArgs::dispatch`.

---

## `accumulator-add`

**Synopsis.** Add `(delta_amount, delta_blind)` to the local earnings
accumulator. Used by reconciliation tooling that watches
`SessionSettled` events and tells the node which contributions are
theirs.

```
Usage: octravpn-node accumulator-add --delta-amount <DELTA_AMOUNT> --delta-blind-hex <DELTA_BLIND_HEX>
```

| Flag | Type | Notes |
|---|---|---|
| `--delta-amount` | u64 (raw OU) | OU to add to the local pending-earnings counter. |
| `--delta-blind-hex` | 64-char hex | Blinding factor used in the FHE proof. |

Source: `cli/identity.rs::AccumulatorAddArgs::dispatch`.

---

## `verify-audit-log`

**Synopsis.** Verify the HMAC chain of an audit log file. Exits 0 on a
clean chain; non-zero with the first broken line index otherwise.

```
Usage: octravpn-node verify-audit-log <PATH>
```

Deprecated alias for `audit verify --audit-path <path>`. Kept so
existing operator runbooks keep working.

| Argument | Type | Notes |
|---|---|---|
| `<PATH>` | path | The audit JSONL file (NOT directory). |

Source: `cli/audit.rs::VerifyAuditLogArgs::dispatch`.

---

## `audit`

**Synopsis.** Operator-facing audit tooling: pretty-print the audit log
+ receipt journal as a timeline, or run a full crypto verification.

```
Usage: octravpn-node audit <COMMAND>

Commands:
  replay  Pretty-print every entry in the audit log + receipt journal
  verify  Cryptographically verify the HMAC chain + receipt-seq monotonicity
```

Source: `cli/audit.rs::AuditArgs::dispatch` → `audit_cli.rs`.

### `audit replay`

```
Usage: octravpn-node audit replay [OPTIONS]
```

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--audit-path` | path | `./state/audit.log` | File or directory. Directory form (one file per UTC day) is auto-detected. |
| `--journal-path` | path | `./state/receipts.bin` | The P1-8/9 receipt journal. |
| `--session` | hex64 or u64 | (none) | Filter to one session id. |
| `--since` | u64 | (none) | Lower bound on Unix timestamp (inclusive). |
| `--until` | u64 | (none) | Upper bound on Unix timestamp (inclusive). |
| `--format` | `human` \| `json` | `human` | NDJSON output for downstream tooling. |

**Example.**

```bash
octravpn-node audit replay \
  --audit-path /var/lib/octravpn/audit \
  --since 1715000000 --until 1715100000 \
  --format json | jq 'select(.kind=="receipt_signed")'
```

Implementing function: `audit_cli::run_replay`.

### `audit verify`

```
Usage: octravpn-node audit verify [OPTIONS]
```

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--audit-path` | path | `./state/audit.log` | Same semantics as `replay --audit-path`. |
| `--journal-path` | path | `./state/receipts.bin` | The receipt journal to monotonicity-check. |
| `--hmac-key` | path | (auto) | 32-byte HMAC key. Defaults to `<audit_path>.key` (file) or `<audit_path>/.audit.key` (dir). |

Exits 0 on full verification; non-zero with the specific check that
failed. The structured report is also printed to stdout.

Implementing function: `audit_cli::run_verify` →
`octravpn_core::audit::AuditLog::verify_file`.

---

## `seal-keys`

**Synopsis.** P1-6: wrap the operator's on-disk wallet + WG keys under
the `octra_core::wallet_enc` passphrase envelope (ChaCha20-Poly1305 over
a PBKDF2-derived KEK).

```
Usage: octravpn-node seal-keys [OPTIONS]
```

| Flag | Type | Notes |
|---|---|---|
| `--passphrase <PASSPHRASE>` | string | Inline passphrase. Warns about shell history. |
| `--passphrase-file <PATH>` | path | First line of the file is the passphrase. |
| `--passphrase-stdin` | bool | Read passphrase as one line from stdin. |
| `--remove-plaintext` | bool | Delete the plaintext source after a successful seal. |

**Passphrase precedence.** `--passphrase` > `--passphrase-file` >
`--passphrase-stdin` > `OCTRAVPN_KEY_PASSPHRASE` env > TTY prompt
(if stdin is a tty). See `crates/octravpn-node/src/seal.rs:52`.

Idempotent: re-running on already-sealed destinations is a no-op so an
operator can safely include this in a post-deploy script.

**Example.**

```bash
echo -n "$(systemd-creds cat octravpn-key-pp)" | \
  octravpn-node seal-keys --passphrase-stdin --remove-plaintext
```

Cross-link: operator tour §sealed-keys for the recommended OS-by-OS
passphrase storage workflow.

Source: `crates/octravpn-node/src/cli/seal.rs::SealKeysArgs::dispatch`.

---

## `unseal-keys`

**Synopsis.** P1-6: reverse `seal-keys` onto a tmpfs/ramfs path for
emergency rotation or one-shot recovery.

```
Usage: octravpn-node unseal-keys [OPTIONS] --tmpdir <TMPDIR>
```

| Flag | Type | Required | Notes |
|---|---|---|---|
| `--tmpdir <TMPDIR>` | path | yes | Must live on tmpfs/ramfs/devtmpfs (Linux) or `/private/tmp` (macOS). |
| `--passphrase` | string | one-of | See seal-keys precedence. |
| `--passphrase-file` | path | one-of | |
| `--passphrase-stdin` | bool | one-of | |

The command refuses to write to non-volatile filesystems — the
`statfs(2)` check in `seal.rs::is_volatile_fs` fails fast with a clear
error if the target isn't recognised as tmpfs.

Source: `crates/octravpn-node/src/cli/seal.rs::UnsealKeysArgs::dispatch`.

---

## `v3`

**Synopsis.** v3 chain-minimal entrypoints. Every non-boot v3 method
exposed by `program/main-v3.aml` is reachable here as a subcommand.

```
Usage: octravpn-node v3 <COMMAND>
```

Implemented by `cli/v3.rs::V3Args` → `crates/octravpn-node/src/v3_cli.rs`.
The boot flow (`register_circle` + `update_circle_state`) still goes
through `register` / `run`; this subcommand surface is the operator's
manual-control plane.

### `v3 bond`

```
Usage: octravpn-node v3 bond --circle <CIRCLE> --amount <AMOUNT>
```

`payable bond_endpoint(circle)`. Top up the operator's existing bond.

| Flag | Notes |
|---|---|
| `--circle` | Circle id receiving the additional bond. |
| `--amount` | OU added to `circle_bond[circle]`. Sent as the tx `value`. |

### `v3 unbond`

```
Usage: octravpn-node v3 unbond --circle <CIRCLE>
```

`unbond_endpoint(circle)` — start the unbond grace period.

### `v3 finalize-unbond`

```
Usage: octravpn-node v3 finalize-unbond --circle <CIRCLE>
```

`finalize_unbond(circle)` — claim the stake back once `epoch >=
circle_unbond_unlock_epoch[circle]`.

### `v3 slash`

```
Usage: octravpn-node v3 slash --circle <CIRCLE> --receipt-key <RECEIPT_KEY> \
       --payload-a <PAYLOAD_A> --payload-b <PAYLOAD_B>
```

`slash_double_sign(circle, payload_a, sig_a, payload_b, sig_b)`. The CLI
signs both payloads inline with the supplied receipt private key file —
operators don't compute base64 sigs by hand. The corresponding pubkey
must match `circle_receipt_pk[circle]` on chain or the slash reverts.

| Flag | Notes |
|---|---|
| `--circle` | Circle being slashed. |
| `--receipt-key` | Path to a 32-byte ed25519 secret (raw or hex). |
| `--payload-a`, `--payload-b` | The two conflicting receipt payloads. Must be byte-distinct. |

### `v3 rotate-receipt-pubkey`

```
Usage: octravpn-node v3 rotate-receipt-pubkey --circle <CIRCLE> --new-pubkey-b64 <NEW_PUBKEY_B64>
```

`rotate_receipt_pubkey(circle, new_pubkey)`. Swap the on-chain ed25519
pubkey used for `slash_double_sign` going forward.

`--new-pubkey-b64` is a base64-encoded ed25519 pubkey (44 chars
including padding).

### `v3 retire`

```
Usage: octravpn-node v3 retire --circle <CIRCLE>
```

`retire_circle(circle)`. Flips `circle_active[circle] = 0`. Stake
remains bonded until a subsequent `finalize_unbond`.

### `v3 create-tailnet`

```
Usage: octravpn-node v3 create-tailnet --members-root <MEMBERS_ROOT> --deposit <DEPOSIT>
```

`payable create_tailnet(members_root)`. Register a new tailnet.

| Flag | Notes |
|---|---|
| `--members-root` | 64-char lowercase hex sha256 of the canonical `members.json`. Anchor only — the chain does not decode the JSON. |
| `--deposit` | Initial OU deposit into the tailnet treasury. |

The assigned `tailnet_id` is fetched best-effort post-submit via
`octra_transaction(hash)` and logged.

### `v3 update-members-root`

```
Usage: octravpn-node v3 update-members-root --tailnet-id <TAILNET_ID> --new-members-root <NEW_MEMBERS_ROOT>
```

`update_members_root(tailnet_id, new_members_root)`. Bump the
members-root anchor for an existing tailnet.

### `v3 retire-tailnet`

```
Usage: octravpn-node v3 retire-tailnet --tailnet-id <TAILNET_ID>
```

`retire_tailnet(tailnet_id)`. Flips `tailnet_retired = 1`.

### `v3 deposit-tailnet`

```
Usage: octravpn-node v3 deposit-tailnet --tailnet-id <TAILNET_ID> --amount <AMOUNT>
```

`payable deposit_to_tailnet(tailnet_id)`. Top up the tailnet treasury.
Anyone can call; membership is enforced off-chain.

### `v3 withdraw-tailnet`

```
Usage: octravpn-node v3 withdraw-tailnet --tailnet-id <TAILNET_ID> --amount <AMOUNT>
```

`withdraw_tailnet_treasury(tailnet_id, amount)`. Owner-only withdrawal
after `retire_tailnet`. NOTE: built inline (no `chain_v3` builder exists
yet — see `v3_calls.rs` module doc).

### `v3 open-session`

```
Usage: octravpn-node v3 open-session --tailnet-id <TAILNET_ID> --circle <CIRCLE> --max-pay <MAX_PAY>
```

`open_session(tailnet_id, circle, max_pay) -> int`. Open a paid session.

| Flag | Notes |
|---|---|
| `--tailnet-id` | The tailnet the session is opened under. |
| `--circle` | Exit circle the session pays out to. |
| `--max-pay` | Pre-agreed max OU the opener will spend on this session. |

The assigned `session_id` is best-effort fetched from
`octra_transaction(hash)` and logged.

### `v3 settle-claim`

```
Usage: octravpn-node v3 settle-claim --session-id <SESSION_ID> --bytes-used <BYTES_USED>
```

`settle_claim(session_id, bytes_used)`. Operator-side first half of the
two-tx settle. Equivocation on `bytes_used` per `session_id` triggers an
AML-side slash.

### `v3 settle-confirm`

```
Usage: octravpn-node v3 settle-confirm --session-id <SESSION_ID> --bytes-used <BYTES_USED> \
       --net <NET> --settle-blinding <SETTLE_BLINDING>
```

`settle_confirm(session_id, bytes_used, net, settle_blinding) -> bool`.
Opener-side second half. Returns `accepted` vs `disputed`.

| Flag | Notes |
|---|---|
| `--net` | Pre-agreed plaintext credit (`price * bytes` after class rules). |
| `--settle-blinding` | Per-session blinding fed into the earnings hash chain. |

### `v3 claim-no-show`

```
Usage: octravpn-node v3 claim-no-show --session-id <SESSION_ID>
```

`claim_no_show(session_id)`. Opener-side abort path when the operator
never called `settle_claim`.

### `v3 sweep-session`

```
Usage: octravpn-node v3 sweep-session --session-id <SESSION_ID>
```

`sweep_expired_session(session_id)`. Any caller can sweep an OPEN
session past `opened_at + session_grace * sweep_multiplier` for a
`sweep_bounty_bps` bounty.

### `v3 claim-earnings`

```
Usage: octravpn-node v3 claim-earnings --circle <CIRCLE> --amount <AMOUNT>
```

`claim_earnings(circle, amount)`. Pull `amount` OU from the v3 earnings
ledger (`circle_earnings_total - circle_earnings_claimed`) to the circle
owner.

**v3 subcommand source.** `crates/octravpn-node/src/v3_cli.rs`; builders
live in `crates/octravpn-core/src/v3_calls.rs` (one Rust fn per `method`
string).

---

## `circle`

**Synopsis.** Circle-asset CRUD: atomic update primitive for sealed
circle assets.

```
Usage: octravpn-node circle <COMMAND>

Commands:
  update         Atomic update of one or more sealed circle assets + state-root anchor
  list-orphans   Diagnostic: probe sealed-asset paths and report any unbound by current anchor
  retry-anchor   Re-submit only the `update_circle_state` tx with a pre-computed anchor
```

Source: `cli/circle.rs::CircleArgs` → `crates/octravpn-node/src/circle_update.rs`.

### `circle update`

```
Usage: octravpn-node circle update [OPTIONS] --circle <CIRCLE>
```

| Flag | Type | Notes |
|---|---|---|
| `--circle` | string | Operator-circle id this update targets. Required. |
| `--passphrase` | string | Sealed-asset passphrase. Falls back to `OCTRAVPN_SEALED_PASSPHRASE`. |
| `--blob` | spec, repeatable | `<asset_path>:<file>:<key_id>:<padding>` — `padding` is one of `none\|4k\|16k\|32k\|128k`. |
| `--set-region` | string | Override `state_root.region`. |
| `--set-member-count` | u64 | Override `state_root.member_count`. |
| `--set-policy-hash` | hex64 | Force `state_root.policy_hash`. |
| `--set-wg-pubkey-hash` | hex64 | Force `state_root.wg_pubkey_hash`. |
| `--set-attestation-hash` | hex64 | Force `state_root.attestation_hash`. Empty string clears it. |
| `--dry-run` | bool | **Default ON.** Describes txs without broadcasting. |
| `--commit` | bool | Explicit opposite of `--dry-run`. Required to actually submit. |

**Atomicity contract.** Blobs are written first; the anchor flip is the
last tx. A failure between the two leaves chain state on the OLD anchor
(old blobs still bound, new blobs are orphans recoverable via
`retry-anchor`). See `circle_update.rs::UpdateError` in
[error-codes.md](./error-codes.md).

**Example.**

```bash
octravpn-node circle update --circle oct… \
  --blob /policy.json:./policy.json:default:4k \
  --set-region eu-west --commit
```

### `circle list-orphans`

```
Usage: octravpn-node circle list-orphans [OPTIONS] --circle <CIRCLE>
```

| Flag | Type | Notes |
|---|---|---|
| `--circle` | string | Required. |
| `--passphrase` | string | For decrypting sealed assets to verify their plaintext hash. |

Probes known sealed-asset paths and reports any whose plaintext hash is
not bound by the current on-chain anchor. Used after an interrupted
`update`.

### `circle retry-anchor`

```
Usage: octravpn-node circle retry-anchor --circle <CIRCLE> --anchor <ANCHOR>
```

Re-submit only the `update_circle_state` tx with a pre-computed anchor.

| Flag | Type | Notes |
|---|---|---|
| `--circle` | string | Required. |
| `--anchor` | hex64 | 64-char hex anchor to commit. |

---

## `mesh`

**Synopsis.** Mesh / Tailscale-interop control surface.

```
Usage: octravpn-node mesh <COMMAND>

Commands:
  mint-preauth   Mint a fresh preauth key (stdout)
  serve          Run a minimal Tailscale-wire control plane (no chain/wallet deps)
  status         Wrap `GET /api/v1/machines` on the remote mesh-control admin surface (deprecated — see headscale)
  policy         Wrap the `/api/v1/policy` CRUD surface (deprecated — see headscale)
```

Source: `cli/mesh.rs` → `crates/octravpn-node/src/mesh_ops.rs`. Used by
`docker/devnet/tailscale-interop/run-interop.sh`.

The `status` and `policy` arms are deprecated in favour of
`octravpn-node headscale {nodes list, policy ...}` (see
[cli-headscale-embedded.md](./cli-headscale-embedded.md)).

### `mesh mint-preauth`

```
Usage: octravpn-node mesh mint-preauth [OPTIONS]
```

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--user` | string | `default` | User label to bind the minted key to. |
| `--reusable` | bool | off | Off matches Tailscale's safer single-use default. |
| `--ttl-secs` | u64 | `DEFAULT_PREAUTH_TTL` (3600 = 1h) | |
| `--remote` | URL | _unset_ | When set, switches to the daemon-bound mint path: POST to `<URL>/admin/preauth` instead of minting locally. Requires `--admin-token`. |
| `--admin-token` | string | _unset_ | Bearer token for the daemon's admin surface. Required when `--remote` is set (clap-`requires`). Maps to `[control].admin_token` in the daemon's `node.toml`. |

Two modes:

  * **Local mint (default)** — `mesh mint-preauth --user alice` generates
    a key in-process with no daemon contact and prints it to stdout.
    Suitable for shell scripting and reachability probes but NOT
    honoured by a real `tailscale up` join because the running daemon
    doesn't know about the key.
  * **Daemon-bound mint** — `mesh mint-preauth --user alice --remote
    http://127.0.0.1:51821 --admin-token <TOKEN>` POSTs to
    `<remote>/admin/preauth`; the daemon's persistent `PreauthMinter`
    materialises the key so it survives across process boundaries and
    IS honoured by a real `tailscale up --authkey "$KEY"`.

Stdout format is identical in both modes (single line, `octrapreauth-…`),
so the `KEY=$(octravpn-node mesh mint-preauth …)` shell idiom works
byte-identically. See [`docs/operators/mesh-preauth.md`](../operators/mesh-preauth.md)
for the full operator playbook, error-mapping reference, and the
`[control].admin_token` cross-reference.

### `mesh serve`

```
Usage: octravpn-node mesh serve [OPTIONS]
```

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--listen` | host:port | `127.0.0.1:51821` | Plain HTTP listener. Set an explicit public address for docker interop harnesses. |
| `--https-listen` | host:port | `""` (disabled) | rustls-terminated HTTPS listener. Required for stock `tailscale up` v1.78+. |
| `--cert-hostname` | string | `localhost` | SAN hostname embedded in the self-signed cert. |
| `--state-dir` | path | `./state/tailscale-wire` | Directory for the Noise long-term static key. |
| `--tailnet-id` | string | `octravpn-interop` | Drives the IP allocator. |
| `--admin-token` | string | env `OCTRAVPN_ADMIN_TOKEN` | Bearer token for `POST /admin/preauth`. |

Mounts in one process: the Tailscale-wire surface (`GET /key`,
`POST /machine/.../register`, `POST /machine/.../map`) and
`POST /admin/preauth`. Both surfaces share one `PreauthMinter`. Honours
the optional `OCTRAVPN_KNOCK_*` env vars (see [env-vars.md](./env-vars.md)).

### `mesh status` (deprecated)

```
Usage: octravpn-node mesh status [OPTIONS]
```

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--remote` | URL | `http://127.0.0.1:51821` | Mesh-control admin URL. |
| `--admin-token` | string | env `OCTRAVPN_ADMIN_TOKEN` | |
| `--json` | bool | off | Raw JSON body when set. |

Prefer `octravpn-node headscale nodes list`.

### `mesh policy` (deprecated)

```
Usage: octravpn-node mesh policy <COMMAND>

Commands:
  get        Fetch the currently-loaded policy document
  set        Replace the policy document with the contents of `--file`
  validate   Parse-only validation — never mutates the live store
```

Prefer `octravpn-node headscale policy {get,set,check}`.

---

## `headscale`

The embedded `headscale` admin CLI surface. Documented in its own file:
[cli-headscale-embedded.md](./cli-headscale-embedded.md). Exit-code
contract: 0/3/4/5/6 (matches `headscale_cli::admin::ExitCode`). Source:
`cli/headscale.rs` (passthrough) → `headscale-rs/headscale-cli/src/admin/mod.rs`.

---

## `config`

**Synopsis.** Schema-check + key + RPC + program reachability against a
`node.toml`. Replaces the manual `octra cast rpc node_status` +
`octra cast call $PROG get_params` smoke probe (#232).

```
Usage: octravpn-node config <COMMAND>

Commands:
  validate   Schema-check, key load, RPC reachability, program view-call
```

### `config validate`

Source: `cli/ops.rs::ConfigArgs::dispatch` → `cli_ops.rs::run_validate`.
Exits 0 on a clean validation; 1 with the first failure surfaced.

The validator runs in this order:

1. Parse `node.toml` as `NodeConfig` — surfaces unknown-field errors
   from `serde`.
2. Load wallet + WG keys (decrypting sealed envelopes if needed).
3. RPC ping (`node_status`) against `[chain].rpc_url`.
4. Program view (no-side-effects contract call) against
   `[chain].program_addr`.

---

## `health`

**Synopsis.** One-shot operator health probe (#232).

```
Usage: octravpn-node health [OPTIONS]
```

| Flag | Type | Default | Env override | Notes |
|---|---|---|---|---|
| `--config` | path | `node.toml` | `OCTRAVPN_NODE_CONFIG` | |
| `--remote` | URL | (none) | — | Hits `GET /health` at this URL if set. |
| `--json` | bool | off | — | Machine-readable report. |

Reads on-chain stake / slashed / unbonding state, validates local audit
log + receipt journal are openable, and (when `--remote` is set) hits
the running daemon's `GET /health`. Source:
`cli/ops.rs::HealthArgs::dispatch` → `cli_ops.rs::run_health`.

**Exit codes.**

| Code | Meaning |
|---|---|
| 0 | All checks green. |
| 1 | Any check failed; details in stderr / JSON `failures` field. |

---

## `audit-tail`

**Synopsis.** Live-tail the audit log with per-line HMAC verification (#232).

```
Usage: octravpn-node audit-tail [OPTIONS]
```

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--audit-path` | path | `./state/audit.log` | File OR directory (auto-detected). |
| `--hmac-key` | path | (auto) | Same discovery as `audit verify`. |
| `--follow` | bool | off | `tail -F`-style. Without it the command prints existing lines then exits. |
| `--poll-ms` | u64 | `250` | Poll interval in ms when `--follow` is set. |

A chain break interrupts output with a clear marker and non-zero exit
code so cron pipelines surface tampering immediately. Source:
`cli/ops.rs::AuditTailArgs::dispatch` → `cli_ops.rs::run_audit_tail`.

---

## `receipt-verify`

**Synopsis.** Report the receipt-journal floor for a session id plus
every audit-log entry that names the same session. Cross-checks the
P1-8/9 invariant (no signed seq above the journal floor).

```
Usage: octravpn-node receipt-verify [OPTIONS] <SESSION_ID>
```

| Argument | Type | Notes |
|---|---|---|
| `<SESSION_ID>` | hex64 or u64 | Session to look up. |

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--journal-path` | path | `./state/receipts.bin` | |
| `--audit-path` | path | (none) | Optional cross-check. |
| `--json` | bool | off | |

Useful as a quick forensic probe after a `slash_double_sign` alert.
Source: `cli/ops.rs::ReceiptVerifyArgs::dispatch` → `cli_ops.rs::run_receipt_verify`.

---

## Exit-code summary (all subcommands)

| Code | Meaning |
|---|---|
| 0 | Success (or `audit verify` on a clean chain, or `config validate` schema-clean) |
| 1 | Generic failure (anyhow chain printed to stderr) |
| 2 | (reserved by clap for usage errors) |
| 3 | Headscale: connection / DNS / TLS pre-status |
| 4 | Headscale: auth (401/403) |
| 5 | Headscale: 404 |
| 6 | Headscale: any other 4xx/5xx / decode |

The 0/3/4/5/6 contract comes from `headscale_cli::admin::ExitCode`
(`headscale-rs/headscale-cli/src/admin/mod.rs:75-81`); the other codes
are the standard clap/anyhow contract from `cli/mod.rs::run`.

---

## Cross-references

* Operator tour: `docs/operators/tour-*.md` for the narrative
  bring-up walkthrough.
* v3 call flows: `docs/v3/*.md` for the on-chain semantics every
  `v3 *` subcommand triggers.
* Config field reference: [config.md](./config.md).
* Env-var fallbacks: [env-vars.md](./env-vars.md).
* On-disk artifacts each subcommand touches: [state-files.md](./state-files.md).
