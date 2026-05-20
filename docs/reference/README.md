<!-- captured from binaries at SHA 2ffead7 (debug build, 2026-05-20) -->

# OctraVPN reference manual

This directory is the **exhaustive** reference for every operator-visible
surface of OctraVPN. It is intentionally machine-augmentable: every CLI
section was generated from a recursive `--help` walk against the current
debug binary and then annotated with implementing file paths and prose.

If you want a **guided walk-through** instead, head to
`docs/operators/tour-*.md` (operator-flow tour) or
`docs/users/*` (end-user how-to). This directory is the lookup table you
return to once you know what to grep for.

## How to read this directory

* **Every flag, field, env-var, RPC method, and audit-event kind that
  exists in the v2026-05-20 build is documented here.** If you find one
  that isn't, file a doc bug — the reference is supposed to be the
  union of `--help`, `Cargo.toml`, `config.rs`, and the `thiserror`
  enums in the workspace.
* **Each entry cites a file:line** where the behaviour lives. The
  `2ffead7` SHA at the top of each captured `--help` block is the
  commit the snapshot was taken from; re-capture (with the script in
  `scripts/refresh-reference-help.sh` if it exists, otherwise the
  one-liner at the top of `cli-octravpn-node.md`) when bumping master.
* **Defaults shown are the in-code defaults**, not the runbook
  recommendations. The runbook in `docs/operator-guide.md` is the
  source of truth for "what value should I actually use."

## Index

| File | Scope | Approximate size |
|---|---|---|
| [`cli-octravpn-node.md`](./cli-octravpn-node.md) | Every `octravpn-node` subcommand and flag, recursive. 21 top-level subcommands, 51 nested. | ~800 lines |
| [`cli-octravpn-client.md`](./cli-octravpn-client.md) | The `octravpn` (client) binary: identity / connect / portal / fetch / tailnet / slash-evidence. | ~400 lines |
| [`cli-headscale-embedded.md`](./cli-headscale-embedded.md) | The embedded `octravpn-node headscale …` surface (users / nodes / preauthkeys / policy / tailnet / api-keys). Byte-identical to the standalone `headscale` binary. | ~300 lines |
| [`config.md`](./config.md) | Every `node.toml` block and field, alphabetized — `[chain]`, `[control]`, `[tunnel]`, `[tun]`, `[pricing]`, `[dns]`, `[derp]`, `[pvac]`, `[analytics]`, `[attestation]`. Calls out the CFG-1 audit BLOCKER. | ~600 lines |
| [`env-vars.md`](./env-vars.md) | Every environment variable the binaries honour. Includes precedence and the AUDIT-2 CFG-7 collision finding. | ~150 lines |
| [`state-files.md`](./state-files.md) | Every on-disk artifact: `state/receipts.bin`, `audit/audit-YYYY-MM-DD.jsonl`, sealed keys, DERP map, Noise static. | ~250 lines |
| [`audit-events.md`](./audit-events.md) | Every audit-event `kind` the daemon emits. Cross-referenced to the analytics indexer mapping. | ~200 lines |
| [`rpc-methods.md`](./rpc-methods.md) | Every Octra JSON-RPC method we consume + emit. v1.1 + v2 + v3 method tables, request/response shapes, mock-rpc handlers. | ~400 lines |
| [`error-codes.md`](./error-codes.md) | Every `thiserror::Error` enum variant in the workspace + every documented exit code. | ~300 lines |
| [`metrics.md`](./metrics.md) | Every Prometheus metric emitted by `/metrics` and `/analytics/series`. Type, labels, healthy range, alert rule template. | ~250 lines |
| (this file) | `README.md` — index. | ~80 lines |

## Cross-cutting conventions

* **`oct…` addresses** are 50-character base58 Octra wallet
  addresses. The reference always uses the lowercase `oct` prefix
  even though the chain accepts mixed case in some places.
* **`OU`** is the smallest indivisible unit of OCT; 1 OCT = 1_000_000
  OU. Every `--amount` flag and on-chain `value:` field is in raw OU
  unless otherwise noted.
* **`v1.1`, `v2`, `v3`** are protocol-version selectors. `v1.1` is the
  legacy operator-wallet-as-identity flow; `v2` is circle-keyed with
  sealed policy; `v3` is the chain-minimal flow with circle-resident
  `state-root.json`. The selector lives in `[chain].protocol_version`.
* **Section numbers like `§7.1`** refer to `docs/deployment-runbook.md`
  unless otherwise qualified.

## Refreshing this directory

To re-capture `--help` snapshots after a CLI flag drift:

```bash
cargo build -p octravpn-node -p octravpn-client
# then run the help-walk script at the top of cli-octravpn-node.md
```

If you bump a config field, add an audit kind, or wire a new env var,
search the relevant reference file by the symbol name and update both
the table row and the prose paragraph beneath it.

## Sibling docs (NOT part of this reference)

* `docs/operators/tour-*.md` — narrative operator walkthrough.
* `docs/users/*.md` — client-side how-to.
* `docs/maintenance/*.md` — release runbook, ceremony scripts.
* `docs/INDEX.md`, `docs/README.md`, `docs/READING_PATHS.md` — top-level navigation.
* `docs/changelog.md` — release notes.
