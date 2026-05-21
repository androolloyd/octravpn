<!-- captured from source at SHA 2ffead7 (2026-05-20) -->

# `node.toml` — operator daemon configuration reference

This is the field-by-field reference for the file `octravpn-node`
consumes. Schema is defined in
`crates/octravpn-node/src/config.rs`. The deserializer is
`serde`-`Deserialize` with `toml`; the loader is `NodeConfig::load` at
`config.rs:651`.

## CFG-1 / CFG-2 / H-2 / H-6 — fixed (2026-05-20)

Two audit findings against this schema are now closed:

* **CFG-1 (was BLOCKER)** — every config-shaped struct in
  `crates/octravpn-node/src/config.rs` carries
  `#[serde(deny_unknown_fields)]`. A typo in `node.toml` — e.g.
  `metric_token` instead of `metrics_token` — now hard-fails
  `NodeConfig::load` with an error that names the unknown field, so
  the daemon refuses to boot rather than silently defaulting the
  block. Twelve structs flipped: `NodeConfig`, `ChainCfg`,
  `TunnelCfg`, `AmneziaCfg`, `PricingCfg`, `ControlCfg`,
  `AttestationCfg`, `AnalyticsCfg`, `TunCfg`, `TransportCfg`,
  `Obfs4Cfg`, `PvacCfg`. See the typo-rejection unit tests at the
  bottom of `config.rs`.
* **CFG-2 / Audit-3 H-6 (was HIGH)** — six secret-bearing fields are
  now wrapped in `secrecy::SecretString`:
  * `chain.sealed_passphrase` (the master tailnet passphrase)
  * `control.admin_token`
  * `control.events_token`
  * `control.metrics_token`
  * `analytics.bearer_token`
  * `tun.transport.obfs4.bridge_identity_secret`

  Each parent struct ships a hand-written `Debug` impl that prints
  `<redacted>` in place of the wrapped bytes; `tracing::debug!(?cfg)`
  is no longer a foot-gun. The runtime accessors are explicit and
  redaction-free at the call site so an `expose_secret` is greppable:

  ```rust
  cfg.chain.sealed_passphrase_expose()         // Option<&str>
  cfg.tun.transport.obfs4.bridge_identity_secret_expose()
  cfg.control.admin_token_string()             // Option<String>
  cfg.control.metrics_token_string()
  cfg.control.events_token_string()
  cfg.analytics.bearer_token_string()
  ```

  The `*_string()` flavours return an owned `String` for the
  downstream consumers that build `ControlState` / `HttpState` (those
  re-wrap in `Arc<str>` for constant-time compare).
* **Audit-3 H-2 (was LEAK)** — `BlobUpdate.plaintext` in
  `circle_update.rs` is now `zeroize::Zeroizing<Vec<u8>>` and both
  `BlobUpdate` and `UpdateBundle` have hand-written `Debug` impls
  that print only `plaintext_len` (never the bytes). The
  Zeroizing wrap scrubs the heap buffer on drop.

If you're adding a new config field with secret semantics: wrap it in
`SecretString`, extend the parent `Debug` impl to redact it via the
`redact_opt_secret` helper, and add a sentinel-bytes line to the
`debug_format_does_not_leak_secret_bytes` test in `config.rs`.

## Top-level structure

```toml
[chain]        # On-chain endpoints, wallet, protocol version
[tunnel]       # WG datapath
  [tunnel.amnezia]   # Optional AmneziaWG obfuscation
[pricing]      # Per-MB tariffs
[control]      # HTTP control plane + audit
[attestation]  # Validator-stake poll loop
[analytics]    # Optional #231 historical indexer
[tun]          # Optional pluggable-transport datapath wrapper
  [tun.transport]
    [tun.transport.obfs4]  # Required when kind="obfs4"
[pvac]         # Optional managed octra-pvac-sidecar subprocess
```

Optional blocks (`#[serde(default)]` at the block level) are:
`[control]`, `[attestation]`, `[analytics]`, `[tun]`, `[pvac]`,
`[tunnel.amnezia]`. They can be omitted in their entirety.

---

## `[chain]` — chain endpoint, wallet, protocol version

Source: `config.rs::ChainCfg` at `:323-411`.

| Field | Type | Default | Source | Notes |
|---|---|---|---|---|
| `rpc_url` | URL | **required** | `:325` | Octra chain JSON-RPC endpoint. Devnet: `https://devnet-rpc.octra.network`. Pinned with `pinned_root_paths`. |
| `program_addr` | `oct…` | **required** | `:326` | The OctraVPN program address (v1.1 main / v2 main-v2 / v3 main-v3). |
| `validator_addr` | `oct…` | **required** | `:327` | This node's wallet address. Cross-checked against `octra_isValidator` at boot. |
| `wallet_secret_path` | path | **required** | `:328` | Used to sign transactions. Plaintext OR sealed envelope (auto-detected). |
| `protocol_version` | `"v1.1"` \| `"v2"` \| `"v3"` | `"v1.1"` | `:331` | Selects which boot flow runs. CFG-1: typos silently default to v1.1. |
| `chain_id` | u32 | `CHAIN_ID_DEVNET` (`0x6F637464` = 1869832804) | `:340` | Bound into every signed receipt (v1.2). Mainnet: `CHAIN_ID_MAINNET`. |
| `sealed_passphrase` | string | (none) | `:352` | v2-only. AES-GCM read-key passphrase for sealed assets. Precedence: `OCTRAVPN_SEALED_PASSPHRASE` env > this field. |
| `circle_state_path` | path | `./state/circle.toml` | `:357` | v2-only. Cached circle id so the operator doesn't re-derive on every restart. |
| `pinned_root_paths` | array&lt;path&gt; | (none) — system trust store | `:367` | TLS pin PEM bundles for `rpc_url`. Defeats CA-compromise MITM (P0-2). Each path is a PEM cert (bundle full chain). |
| `circle_id` | `oct…` | (none) | `:376` | **v3-only.** Required when `protocol_version = "v3"`. The circle that commits its `state-root.json` under `register_circle`. |
| `circle_v3_state_path` | path | `./state/circle-v3.toml` | `:383` | v3-only. Cached v3 boot anchor + tx hashes. |
| `v3_initial_stake` | u64 OU | `1_000_000_000` | `:389` | v3-only. Initial stake submitted with the first `register_circle`. Must clear `min_circle_stake` (default 100_000_000 OU). |
| `require_sealed_keys` | bool | `false` | `:399` | P1-6 strict mode. Refuse to boot if any configured secret file is plaintext on disk. Recommended `true` in production. |
| `attestation_url` | URL | (none) | `:409` | v3-only. URL pointing at a remote-attestation bundle. SHA-256 lands in `state_root.attestation_hash`. |

**CFG-1 fallback risks in `[chain]`.** Of these 14 fields, **10** are
`#[serde(default)]`. If you mistype any of them, the daemon boots with
the default value and only a behavioural symptom (e.g. wrong chain id
on a receipt → slash risk) surfaces the typo. The required four (`rpc_url`,
`program_addr`, `validator_addr`, `wallet_secret_path`) WILL hard-fail
the parse if missing — they have no default.

**Example.**

```toml
[chain]
rpc_url             = "https://devnet-rpc.octra.network"
program_addr        = "octuKpaB...VWR"
validator_addr      = "oct7MoFanQ...4eX"
wallet_secret_path  = "/etc/octravpn/wallet.key.sealed"
protocol_version    = "v3"
chain_id            = 1869832804
circle_id           = "octCxaA...j2"
require_sealed_keys = true
pinned_root_paths   = ["/etc/octravpn/pins/devnet-rpc.pem"]
```

---

## `[tunnel]` — WireGuard datapath

Source: `config.rs::TunnelCfg` at `:420-433`.

| Field | Type | Default | Source | Notes |
|---|---|---|---|---|
| `public_endpoint` | `host:port` | **required** | `:422` | What clients dial. Usually the public IP plus 51820. |
| `listen` | `host:port` | **required** | `:423` | What the daemon binds. `0.0.0.0:51820` for IPv4, `[::]:51820` for dual-stack. |
| `wg_secret_path` | path | **required** | `:424` | Master from which WG + receipt keys derive. Plaintext OR sealed. |

### `[tunnel.amnezia]` — AmneziaWG obfuscation (optional)

Source: `config.rs::AmneziaCfg` at `:440-474`. Maps onto
`octravpn_tun::amnezia::AmneziaConfig`. When omitted or `enabled = false`,
the WG datapath runs unmodified (zero-overhead identity transform).

| Field | Type | Default | Validation | Notes |
|---|---|---|---|---|
| `enabled` | bool | `false` | — | Master toggle. Both peers MUST agree on every field or the handshake silently drops. |
| `jc` | u8 | `0` | `0..=128` | Pre-handshake junk packet count. |
| `jmin` | u16 | `0` | `1..=1280` (when enabled) | Junk packet min size. |
| `jmax` | u16 | `0` | `jmin..=1280` (when enabled) | Junk packet max size. |
| `s1` | u16 | `0` | `0..=1280` | Random prefix bytes on outgoing handshake-init. |
| `s2` | u16 | `0` | `0..=1280` | Random prefix bytes on outgoing handshake-response. |
| `h1` | u32 | `1` | `1` (stock) or `5..=2_147_483_647` | Replacement msg-type for WG init. |
| `h2` | u32 | `2` | `2` (stock) or `5..=2_147_483_647` | Replacement msg-type for WG response. |
| `h3` | u32 | `3` | `3` (stock) or `5..=2_147_483_647` | Replacement msg-type for WG cookie. |
| `h4` | u32 | `4` | `4` (stock) or `5..=2_147_483_647` | Replacement msg-type for WG transport. |

See `docs/security/validator-hardening.md § Layer 1` for the threat
model.

---

## `[pricing]` — per-MB tariffs

Source: `config.rs::PricingCfg` at `:513-525`.

| Field | Type | Default | Source | Notes |
|---|---|---|---|---|
| `price_per_mb` | u64 OU | **required** | `:515` | Tariff in raw OU per MB. v1.1 setting. |
| `region` | string | **required** | `:516` | Region label (e.g. `"eu-west"`). Surfaced in discovery. |
| `price_per_mb_shared` | u64 OU | `price_per_mb` | `:520` | v2-only. Shared (public-internet exit) tariff. |
| `price_per_mb_internal` | u64 OU | `0` | `:524` | v2-only. Internal (intra-tailnet) tariff. |

The `PricingCfg::shared_price()` / `internal_price()` accessors at
`:527-537` materialise the v2 defaults.

---

## `[control]` — HTTP control plane + audit

Source: `config.rs::ControlCfg` at `:539-622`.

| Field | Type | Default | Source | Notes |
|---|---|---|---|---|
| `listen` | `host:port` | `127.0.0.1:51821` | `:542` | HTTP listen for the receipt control plane. Set `0.0.0.0` explicitly when exposing. |
| `audit_dir` | path | (none → `./audit`) | `:547` | Daily JSONL files. See [state-files.md](./state-files.md). |
| `events_token` | string | (none — endpoint 404s) | `:557` | Bearer for `GET /events` SSE. v2 hardening fix (P0-1). |
| `metrics_token` | string | (none — endpoint 503s) | `:567` | Bearer for `GET /metrics`. Must set in production. Pick ≥32-byte random. |
| `receipt_journal_path` | path | `./state/receipts.bin` | `:579` | P1-8/9 persistent seq journal. See [state-files.md](./state-files.md). |
| `fsync_policy` | `"periodic"` \| `"every_write"` | `"periodic"` (Perf-1) | `config.rs::FsyncPolicyCfg` | Receipt-journal durability policy. `"periodic"` ⇒ `Periodic(1s)`, ~500 k receipts/s ceiling, ≤1 s loss window on hard crash (recoverable via `journal rebuild --from-audit`). `"every_write"` ⇒ `EveryWrite`, ~225 RPS/node ceiling, instantly durable per bump — pick for financial-invariant exit nodes. See [operators/performance.md](../operators/performance.md) and audit-8 §3. |
| `admin_token` | string | (none — `POST /admin/preauth` 404s) | `:590` | Falls back to `OCTRAVPN_ADMIN_TOKEN`. |
| `tailscale_wire_state_dir` | path | `./state/tailscale-wire` | `:599` | Noise long-term static + future wire state. Must survive restarts. |
| `tailscale_tailnet_id` | string | `"octravpn-interop"` | `:606` | IP allocator key. Set per-deployment in production. |

**CFG-1 fallback risk:** `metrics_token` defaulting to `None` → `503`
is intentional; an operator who forgets to set it gets a clear failure
mode instead of an open metrics endpoint. Same posture for `events_token`
and `admin_token` (`404` rather than `401` so a scanner can't fingerprint).

---

## `[attestation]` — validator-stake poll loop

Source: `config.rs::AttestationCfg` at `:628-636`.

| Field | Type | Default | Source | Notes |
|---|---|---|---|---|
| `poll_interval_secs` | u64 | `30` | `:635` | How often to re-check the wallet is still an Octra protocol validator. |

---

## `[analytics]` — historical-analytics indexer (#231)

Source: `config.rs::AnalyticsCfg` at `:264-284`. Off by default.
Spawned in-process when enabled.

| Field | Type | Default | Source | Notes |
|---|---|---|---|---|
| `enabled` | bool | `false` | `:269` | Master toggle. |
| `listen_addr` | `host:port` | `127.0.0.1:51823` | `:275` | Indexer's HTTP listen (`/metrics`, `/analytics/series`, `/analytics/health`). Loopback by default. |
| `bearer_token` | string | (none — endpoints 503) | `:282` | Bearer gating `/metrics` and `/analytics/series`. Pick ≥32 bytes random; reuse in the Prometheus scrape's `authorization.credentials`. |

---

## `[tun]` — pluggable-transport datapath wrapper

Source: `config.rs::TunCfg` at `:189-194`. Carries only the
`[tun.transport]` selector.

### `[tun.transport]`

Source: `config.rs::TransportCfg` at `:217-224`.

| Field | Type | Default | Source | Notes |
|---|---|---|---|---|
| `kind` | `"direct"` \| `"obfs4"` | `"direct"` | `:219` | Pass-through vs obfs4-wrapped. |
| `obfs4` | sub-table | (none) | `:222` | Required when `kind = "obfs4"`. |

### `[tun.transport.obfs4]`

Source: `config.rs::Obfs4Cfg` at `:239-258`. Required when
`kind = "obfs4"`.

| Field | Type | Default | Source | Notes |
|---|---|---|---|---|
| `bridge_node_id` | 40-char hex | **required** | `:242` | 20-byte bridge node_id. Distributed out of band. |
| `bridge_pubkey` | 64-char hex | **required** | `:246` | 32-byte X25519 bridge identity pubkey. |
| `bridge_identity_secret` | 64-char hex | (none) | `:253` | Set only on the bridge node; clients leave unset. |
| `iat_mode` | u8 | `0` | `:257` | `0` = off, `1` = uniform 0..25ms, `2` = Pareto 0..200ms. |

See `docs/operators/obfs4-bridge.md` (if present) for the operational
runbook.

---

## `[pvac]` — managed PVAC (HFHE) sidecar

Source: `config.rs::PvacCfg` at `:110-148`. Off by default; opt in by
setting `enabled = true`.

| Field | Type | Default | Source | Notes |
|---|---|---|---|---|
| `enabled` | bool | `false` | `:114` | Master toggle. `false` → `Hub::pvac()` returns `None`. |
| `binary_path` | path | `./pvac-sidecar/octra-pvac-sidecar` | `:122` | Path to the C++ sidecar binary. |
| `restart_backoff_ms` | u64 | `250` | `:126` | Initial back-off after a crash; supervisor doubles per consecutive crash up to 60s. |
| `request_timeout_secs` | u64 | `30` | `:130` | Per-request timeout; returned as `PvacError::Timeout`. |
| `circle_pubkey_path` | path | (none) | `:141` | HFHE-2: on-disk envelope holding the circle PVAC pubkey blob (`hfhe_v1\|<base64>`). |
| `circle_secret_path` | path | (none) | `:147` | HFHE-2: matching circle PVAC secret. Loaded once at boot. Never leaves the operator process. |

When `enabled = true` AND both `circle_*_path` resolve to readable
files, the receipt-signing path homomorphically encrypts `bytes_used`
and `net` under the pubkey and attaches the ciphertext to each emitted
receipt. When either path is unset OR the file does not exist, the
shadow blob is `None` on the wire — wire-compatible with pre-HFHE-2
operators.

`PVAC_SIDECAR_BIN` env var (read by `pvac.rs:811`) overrides
`binary_path` at runtime.

---

## `[dns]` and `[derp]` — placeholders

These blocks do **not** exist in the current schema. They are future
work tracked by:

* `[dns]` — MagicDNS extra-record hot-reload (target: `state/extra_records.json`).
* `[derp]` — DERP map override (target: `state/derp-map.json`, env-var
  workaround `OCTRAVPN_DERP_MAP_PATH` available today; see
  [env-vars.md](./env-vars.md)).

When they land they will follow the `#[serde(default)]` pattern of the
existing blocks. Track via the operator changelog.

---

## Sample minimal valid config

```toml
# v1.1 devnet operator, no analytics, no obfs4
[chain]
rpc_url            = "https://devnet-rpc.octra.network"
program_addr       = "octuKpaB...VWR"
validator_addr     = "oct7MoFa...4eX"
wallet_secret_path = "./keys/wallet.key"

[tunnel]
public_endpoint = "203.0.113.10:51820"
listen          = "0.0.0.0:51820"
wg_secret_path  = "./keys/wg.key"

[pricing]
price_per_mb = 100
region       = "eu-west"
```

## Sample full v3 production config

```toml
[chain]
rpc_url             = "https://mainnet-rpc.octra.network"
program_addr        = "oct…v3"
validator_addr      = "oct…operator"
wallet_secret_path  = "/etc/octravpn/wallet.key.sealed"
protocol_version    = "v3"
chain_id            = 0x6F637462   # CHAIN_ID_MAINNET (illustrative)
circle_id           = "oct…circle"
v3_initial_stake    = 1_000_000_000
require_sealed_keys = true
pinned_root_paths   = ["/etc/octravpn/pins/mainnet-rpc.pem"]
attestation_url     = "https://attestation.example.com/octravpn/o1.json"

[tunnel]
public_endpoint = "203.0.113.10:51820"
listen          = "[::]:51820"
wg_secret_path  = "/etc/octravpn/wg.key.sealed"

  [tunnel.amnezia]
  enabled = true
  jc      = 4
  jmin    = 50
  jmax    = 1000
  s1      = 25
  s2      = 25
  h1      = 1731927040
  h2      = 1862593847
  h3      = 1995040128
  h4      = 2127486591

[pricing]
price_per_mb           = 100
region                 = "eu-west"
price_per_mb_shared    = 150
price_per_mb_internal  = 0

[control]
listen               = "127.0.0.1:51821"
audit_dir            = "/var/lib/octravpn/audit"
metrics_token        = "${random ≥32 bytes}"
admin_token          = "${random ≥32 bytes}"
receipt_journal_path = "/var/lib/octravpn/receipts.bin"
# Perf-1: receipt-journal fsync policy. "periodic" (default) trades
# a ≤1 s loss window on hard crash for ~500 k receipts/s/node;
# "every_write" is the financial-invariant override.
# See docs/operators/performance.md.
fsync_policy             = "periodic"
tailscale_wire_state_dir = "/var/lib/octravpn/tailscale-wire"
tailscale_tailnet_id     = "acme-prod"

[attestation]
poll_interval_secs = 30

[analytics]
enabled       = true
listen_addr   = "127.0.0.1:51823"
bearer_token  = "${random ≥32 bytes}"

[pvac]
enabled              = true
binary_path          = "/usr/local/bin/octra-pvac-sidecar"
circle_pubkey_path   = "/etc/octravpn/circle.pvac.pub"
circle_secret_path   = "/etc/octravpn/circle.pvac.key.sealed"
restart_backoff_ms   = 250
request_timeout_secs = 30
```

## Cross-references

* Env var fallbacks: [env-vars.md](./env-vars.md).
* On-disk state files referenced from `[control]`,
  `[chain]`, etc.: [state-files.md](./state-files.md).
* Validating a `node.toml`: the `octravpn-node config validate`
  subcommand (see [cli-octravpn-node.md § config](./cli-octravpn-node.md#config)).
* CFG-1 audit context: `docs/refactor-plan-2026-05-20.md` (the
  audit-fix worktree's main checklist).
